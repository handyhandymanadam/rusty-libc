//! Signal handlers that only set flags or bump counters (feature `libc-services`): the signal-hook `flag::register`
//! model (signal-hook-registry 1.4 / signal-hook 0.3, MIT OR Apache-2.0: its design was studied, no code copied).
//!
//! # State rule
//!
//! A signal's handler is process state the C library also manages (glibc and rusty-libc keep SIGCANCEL/SIGSETXID for
//! themselves, set the `sa_restorer` trampoline, and C code in the process installs handlers through them), so the
//! handler is installed through the running C library's `sigaction(2)`, never by a raw rt_sigaction beside it.
//!
//! # Design
//!
//! - One fixed static table: per signal 1..=64, [`SLOTS`] flag slots (`AtomicPtr<AtomicBool>`) and [`SLOTS`] counter
//!   slots (`AtomicPtr<AtomicUsize>`), an in-flight count, and the previous handler to chain to. No allocation, lock or
//!   C call happens in the handler.
//! - The handler (one `extern "C"` function for every signal) increments the in-flight count, does `store(true)` on
//!   each non-null flag and `fetch_add(1)` on each non-null counter, decrements the in-flight count, then calls the
//!   handler that was installed before (if it was a function, not SIG_DFL/SIG_IGN), with the same arguments.
//! - Registration and unregistration are serialised by a mutex (never touched by the handler). The first registration
//!   for a signal installs the handler (SA_SIGINFO | SA_RESTART, as signal-hook) and saves the previous `sigaction`;
//!   the last unregistration puts that previous action back if the handler is still ours (if other code replaced it
//!   meanwhile, ours stays reachable through that code's chaining and keeps forwarding to the saved one).
//!
//! # Why the handler is async-signal-safe
//!
//! POSIX (SUSv5 XSH 2.4.3 "Signal Actions", librarian: V2_chap02 block 20): a handler may refer to objects of static
//! storage duration only if they are lock-free atomic objects (or `volatile sig_atomic_t` assignments, Kerrisk, The
//! Linux Programming Interface p. 428 (PDF p. 472): "set it within the signal handler, and check it in the main
//! program"), and may call only async-signal-safe functions. The handler touches only lock-free atomics (x86-64
//! `AtomicUsize`/`AtomicBool`/`AtomicPtr` are lock-free) in the static table and in the `Arc`ed atomics the table
//! holds a strong count of; it calls no function except the chained previous handler, which is what would have run
//! without us. It does not change errno (atomics do not touch it).
//!
//! # Why freeing a registration is sound
//!
//! A slot owns one strong count of its `Arc` (`Arc::into_raw`). Unregistering swaps the slot to null, then waits
//! until the in-flight count is 0, then drops that count. All four operations are SeqCst: a handler that loaded the
//! non-null pointer did its increment before that load, so before the swap in the single SeqCst order, and before the
//! waiter's loads; the waiter can only read 0 after that handler's decrement, which comes after its last use of the
//! pointer (and the decrement's release / the load's acquire order that use before the drop). A handler that starts
//! after the swap reads null. The chained call happens after the decrement, so a previous handler that never returns
//! (siglongjmp) cannot block an unregistration.
//!
//! Known limit: if other code installs its own handler over ours, chains to ours, and all our registrations for that
//! signal end and then a new one starts, the new one chains to that code's handler, which chains back: a loop. Code
//! that mixes this registry with its own chaining sigaction handlers on the same signal should not do that.
//!
//! Refused (EINVAL): numbers outside 1..=64, glibc's internal 32 and 33, SIGKILL and SIGSTOP (cannot be caught), and
//! SIGSEGV, SIGBUS, SIGILL and SIGFPE (a flag handler returning from a fault re-executes the faulting instruction
//! forever; signal-hook refuses the same set, its FORBIDDEN list).

use crate::errno::Errno;
use crate::syscall::nr;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

/// Flag registrations and, separately, counter registrations per signal (ENOSPC beyond that).
pub const SLOTS: usize = 8;

/// glibc's / rusty-libc's `struct sigaction` (x86-64): handler, 1024-bit mask, flags, restorer.
#[repr(C)]
#[derive(Clone, Copy)]
struct CSigaction {
    handler: usize,
    mask: [u64; 16],
    flags: c_int,
    restorer: usize,
}

const _: () = assert!(core::mem::size_of::<CSigaction>() == 152);

impl CSigaction {
    const ZERO: CSigaction = CSigaction { handler: 0, mask: [0; 16], flags: 0, restorer: 0 };
}

unsafe extern "C" {
    fn sigaction(sig: c_int, act: *const CSigaction, old: *mut CSigaction) -> c_int;
}

const SA_SIGINFO: c_int = 4;
const SA_RESTART: c_int = 0x1000_0000;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;

struct SigSlots {
    flags: [AtomicPtr<AtomicBool>; SLOTS],
    counters: [AtomicPtr<AtomicUsize>; SLOTS],
    inflight: AtomicUsize,
    /// The handler to chain to (0: none).
    prev: AtomicUsize,
    /// Does `prev` take (sig, info, context)?
    prev_siginfo: AtomicBool,
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY: SigSlots = SigSlots {
    flags: [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS],
    counters: [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS],
    inflight: AtomicUsize::new(0),
    prev: AtomicUsize::new(0),
    prev_siginfo: AtomicBool::new(false),
};

/// Index = signal number (0 unused).
static TABLE: [SigSlots; 65] = [EMPTY; 65];

/// Per signal: the number of live registrations and the action that was in place before ours.
struct Saved {
    count: usize,
    old: CSigaction,
}

static REGISTRY: Mutex<[Saved; 65]> = Mutex::new([const { Saved { count: 0, old: CSigaction::ZERO } }; 65]);

/// The one handler for every registered signal (see the module documentation for why it is async-signal-safe).
extern "C" fn handler(sig: c_int, info: *mut c_void, ctx: *mut c_void) {
    let Some(t) = usize::try_from(sig).ok().and_then(|i| TABLE.get(i)) else { return };
    t.inflight.fetch_add(1, SeqCst);
    for s in &t.flags {
        let p = s.load(SeqCst);
        if !p.is_null() {
            // SAFETY: a non-null slot pointer came from `Arc::into_raw` and the table still holds that strong count:
            // it is released only after the slot is nulled and the in-flight count (incremented above, before this
            // load) has dropped back to 0.
            unsafe { &*p }.store(true, SeqCst);
        }
    }
    for s in &t.counters {
        let p = s.load(SeqCst);
        if !p.is_null() {
            // SAFETY: as for the flags.
            unsafe { &*p }.fetch_add(1, SeqCst);
        }
    }
    t.inflight.fetch_sub(1, SeqCst);
    let prev = t.prev.load(SeqCst);
    if prev != 0 {
        if t.prev_siginfo.load(SeqCst) {
            // SAFETY: `prev` is the address of the function the C library reported as this signal's SA_SIGINFO handler
            // before ours (not SIG_DFL/SIG_IGN); calling it with the kernel's arguments is what would have happened
            // without our handler.
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn(c_int, *mut c_void, *mut c_void)>(prev as *const ()) };
            f(sig, info, ctx);
        } else {
            // SAFETY: as above, for a plain `void (*)(int)` handler.
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn(c_int)>(prev as *const ()) };
            f(sig);
        }
    }
}

/// The address of `handler`, as `sa_handler` holds it.
fn ours() -> usize {
    handler as *const () as usize
}

/// Can `sig` get a flag/counter handler?
fn check(sig: i32) -> Result<usize, Errno> {
    match sig {
        1..=64 if !matches!(sig, 4 | 7 | 8 | 9 | 11 | 19 | 32 | 33) => Ok(sig as usize),
        _ => Err(Errno::EINVAL),
    }
}

fn c_sigaction(sig: usize, new: Option<&CSigaction>, old: Option<&mut CSigaction>) -> Result<(), Errno> {
    let n = new.map_or(core::ptr::null(), |n| n as *const CSigaction);
    let o = old.map_or(core::ptr::null_mut(), |o| o as *mut CSigaction);
    // SAFETY: `n` is NULL or a live `struct sigaction` the library reads; `o` is NULL or a live one it writes. The only
    // handler ever passed in `n` is `handler` above (async-signal-safe) or an action the library itself reported.
    if unsafe { sigaction(sig as c_int, n, o) } == 0 {
        Ok(())
    } else {
        Err(Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(Errno::EINVAL.0)))
    }
}

fn is_function(h: usize) -> bool {
    h != SIG_DFL && h != SIG_IGN
}

fn set_prev(t: &SigSlots, old: &CSigaction) {
    if is_function(old.handler) && old.handler != ours() {
        t.prev_siginfo.store(old.flags & SA_SIGINFO != 0, SeqCst);
        t.prev.store(old.handler, SeqCst);
    } else {
        t.prev.store(0, SeqCst);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Flag,
    Counter,
}

/// A live registration; dropping it unregisters (the flag or counter is no longer touched by the signal, and the last
/// registration of a signal puts the previous disposition back). [`Registration::keep`] leaves it registered for the
/// rest of the process.
#[derive(Debug)]
#[must_use = "dropping a Registration unregisters it at once; call .keep() to keep it for the life of the process"]
pub struct Registration {
    sig: usize,
    kind: Kind,
    slot: usize,
}

impl Registration {
    /// The signal number.
    pub fn signal(&self) -> i32 {
        self.sig as i32
    }

    /// Keep the registration for the rest of the process (the handler and the `Arc` it holds are never released).
    pub fn keep(self) {
        core::mem::forget(self);
    }
}

fn register(sig: i32, kind: Kind, ptr: *mut u8) -> Result<Registration, (Errno, *mut u8)> {
    let sig = check(sig).map_err(|e| (e, ptr))?;
    let mut reg = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
    let t = &TABLE[sig];
    let slot = match kind {
        Kind::Flag => t.flags.iter().position(|s| s.load(SeqCst).is_null()),
        Kind::Counter => t.counters.iter().position(|s| s.load(SeqCst).is_null()),
    };
    let Some(slot) = slot else { return Err((Errno(28), ptr)) }; // ENOSPC
    // publish first, so a signal arriving right after the handler is installed already sees it
    match kind {
        Kind::Flag => t.flags[slot].store(ptr.cast(), SeqCst),
        Kind::Counter => t.counters[slot].store(ptr.cast(), SeqCst),
    }
    let saved = &mut reg[sig];
    if saved.count == 0 {
        let mut old = CSigaction::ZERO;
        let installed = c_sigaction(sig, None, Some(&mut old)).and_then(|()| {
            set_prev(t, &old);
            let new = CSigaction { handler: ours(), mask: [0; 16], flags: SA_SIGINFO | SA_RESTART, restorer: 0 };
            let mut replaced = CSigaction::ZERO;
            c_sigaction(sig, Some(&new), Some(&mut replaced))?;
            // (changed between the two calls by code not using this registry: chain to what was really replaced)
            if replaced.handler != old.handler || replaced.flags != old.flags {
                set_prev(t, &replaced);
            }
            Ok(replaced)
        });
        match installed {
            Ok(replaced) => saved.old = replaced,
            Err(e) => {
                let p = match kind {
                    Kind::Flag => t.flags[slot].swap(core::ptr::null_mut(), SeqCst).cast::<u8>(),
                    Kind::Counter => t.counters[slot].swap(core::ptr::null_mut(), SeqCst).cast::<u8>(),
                };
                wait_idle(t);
                t.prev.store(0, SeqCst);
                return Err((e, p));
            }
        }
    }
    saved.count += 1;
    Ok(Registration { sig, kind, slot })
}

/// Wait until no handler is between its in-flight increment and decrement for this signal.
fn wait_idle(t: &SigSlots) {
    while t.inflight.load(SeqCst) != 0 {
        let _ = plain!(nr::SCHED_YIELD);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut reg = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
        let t = &TABLE[self.sig];
        let p = match self.kind {
            Kind::Flag => t.flags[self.slot].swap(core::ptr::null_mut(), SeqCst).cast::<u8>(),
            Kind::Counter => t.counters[self.slot].swap(core::ptr::null_mut(), SeqCst).cast::<u8>(),
        };
        wait_idle(t);
        release(self.kind, p);
        let saved = &mut reg[self.sig];
        saved.count -= 1;
        if saved.count == 0 {
            let mut cur = CSigaction::ZERO;
            if c_sigaction(self.sig, None, Some(&mut cur)).is_ok() && cur.handler == ours() {
                let old = saved.old;
                if c_sigaction(self.sig, Some(&old), None).is_ok() {
                    t.prev.store(0, SeqCst);
                }
            }
            // otherwise other code replaced our handler after us; it may chain to ours, which keeps forwarding to `prev`
        }
    }
}

/// Drop the strong count a slot held.
fn release(kind: Kind, p: *mut u8) {
    if p.is_null() {
        return;
    }
    match kind {
        // SAFETY: `p` came from `Arc::<AtomicBool>::into_raw` in `register_flag`; the slot that held it is null and no
        // handler is using it (wait_idle), so this strong count is ours to give back, once.
        Kind::Flag => drop(unsafe { Arc::from_raw(p.cast::<AtomicBool>()) }),
        // SAFETY: as above, for `Arc<AtomicUsize>` from `register_counter`.
        Kind::Counter => drop(unsafe { Arc::from_raw(p.cast::<AtomicUsize>()) }),
    }
}

/// When `sig` arrives, set `flag` to true (signal-hook's `flag::register`). The handler is installed through the C
/// library's sigaction on the first registration for `sig`; up to [`SLOTS`] flags per signal (ENOSPC beyond).
/// EINVAL: see the module documentation for the refused signals.
pub fn register_flag(sig: i32, flag: Arc<AtomicBool>) -> Result<Registration, Errno> {
    register(sig, Kind::Flag, Arc::into_raw(flag).cast_mut().cast()).map_err(|(e, p)| {
        release(Kind::Flag, p);
        e
    })
}

/// When `sig` arrives, add 1 to `counter` (wrapping). As [`register_flag`] otherwise; the counter slots are separate
/// from the flag slots.
pub fn register_counter(sig: i32, counter: Arc<AtomicUsize>) -> Result<Registration, Errno> {
    register(sig, Kind::Counter, Arc::into_raw(counter).cast_mut().cast()).map_err(|(e, p)| {
        release(Kind::Counter, p);
        e
    })
}

/// The current handler address of `sig` as the C library reports it (tests: is ours installed?).
#[doc(hidden)]
pub fn handler_is_ours(sig: i32) -> bool {
    let mut cur = CSigaction::ZERO;
    sig > 0 && c_sigaction(sig as usize, None, Some(&mut cur)).is_ok() && cur.handler == ours()
}
