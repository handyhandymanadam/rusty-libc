//! pthread_cond_t (48 bytes, glibc's x86-64 layout) and pthread_condattr_t.
//!
//! The algorithm is glibc's group-based condition variable (glibc 2.25 and later), ported to Rust
//! (derived from glibc's nptl/pthread_cond_*.c, LGPL-2.1; see LICENSES.md): waiters take a ticket from
//! a 64-bit sequence, split into two groups G1 and G2 so that a signal can be handed to the
//! oldest waiters (wake-up in arrival order) and never to a waiter that arrived after the signal; no
//! wake-up is lost when a waiter is cancelled or times out (it hands its signal on), and
//! pthread_cond_destroy waits until the last woken waiter has finished touching the variable.
//! Layout: wseq 0 (u64), g1_start 8 (u64), g_size[2] 16, g1_orig_size 24 (low 2 bits are the
//! signalers' lock), wrefs 28 (bit 0 shared, bit 1 monotonic clock, bit 2 destroy waits, waiter
//! count << 3), g_signals[2] 32. All zero is the static initializer.
//!
//! Safe core: every field of a `Cond` is an atomic, so signal, broadcast and destroy work on `&Cond`; the wait keeps the
//! mutex as a raw pointer (mutex.rs) and registers its cancellation handler with a pointer to a stack record.
use crate::mutex::{Mutex, mutex_cond_lock, mutex_unlock_usercnt};
use crate::sys::*;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const MAX_GROUP_SIZE: u32 = 1 << 29;
const SHARED_MASK: u32 = 1;
const CLOCK_MONOTONIC_MASK: u32 = 2;

#[repr(C)]
pub struct Cond {
    wseq: AtomicU64,
    g1_start: AtomicU64,
    g_size: [AtomicU32; 2],
    g1_orig_size: AtomicU32,
    wrefs: AtomicU32,
    g_signals: [AtomicU32; 2],
    unused: [u32; 2],
}

const _: () = assert!(core::mem::size_of::<Cond>() == 48);

#[repr(C)]
pub struct CondAttr {
    pub value: c_int,
}

#[inline]
fn is_private(flags: u32) -> bool {
    flags & SHARED_MASK == 0
}

fn acquire_lock(c: &Cond, private: bool) {
    let mut s = c.g1_orig_size.load(Ordering::Relaxed);
    while s & 3 == 0 {
        match c.g1_orig_size.compare_exchange_weak(s, s | 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return,
            Err(x) => s = x,
        }
    }
    loop {
        while s & 3 != 2 {
            match c.g1_orig_size.compare_exchange_weak(s, (s & !3) | 2, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => {
                    if s & 3 == 0 {
                        return;
                    }
                    break;
                }
                Err(x) => s = x,
            }
        }
        futex_wait(&c.g1_orig_size, (s & !3) | 2, private);
        s = c.g1_orig_size.load(Ordering::Relaxed);
    }
}

fn release_lock(c: &Cond, private: bool) {
    if c.g1_orig_size.fetch_and(!3, Ordering::Release) & 3 == 2 {
        futex_wake(&c.g1_orig_size, 1, private);
    }
}

fn get_orig_size(c: &Cond) -> u32 {
    c.g1_orig_size.load(Ordering::Relaxed) >> 2
}

fn set_orig_size(c: &Cond, size: u32) {
    let s = (c.g1_orig_size.load(Ordering::Relaxed) & 3) | (size << 2);
    if c.g1_orig_size.swap(s, Ordering::Relaxed) & 3 != s & 3 {
        c.g1_orig_size.store((size << 2) | 2, Ordering::Relaxed);
    }
}

/// Close G1, make G2 the new G1. False when the groups were not switched because G2 is empty.
fn switch_g1(c: &Cond, wseq_in: u64, g1index: &mut u32) -> bool {
    let mut g1 = *g1index as usize;
    let old_orig_size = get_orig_size(c);
    let old_g1_start = c.g1_start.load(Ordering::Relaxed);
    let new_g1_start = old_g1_start + old_orig_size as u64;
    let g2size = c.g_size[g1 ^ 1].load(Ordering::Relaxed);
    if (wseq_in.wrapping_sub(new_g1_start) as u32).wrapping_add(g2size) == 0 {
        return false;
    }
    c.g1_start.fetch_add(old_orig_size as u64, Ordering::Relaxed);
    let wseq = c.wseq.fetch_xor(1, Ordering::Release) >> 1;
    g1 ^= 1;
    *g1index ^= 1;
    c.g_signals[g1].store(new_g1_start as u32, Ordering::Release);
    let orig_size = wseq.wrapping_sub(new_g1_start) as u32;
    set_orig_size(c, orig_size);
    let cur = c.g_size[g1].load(Ordering::Relaxed);
    c.g_size[g1].store(cur.wrapping_add(orig_size), Ordering::Relaxed);
    c.g_size[g1].load(Ordering::Relaxed) != 0
}

/// The exported functions convert the condition pointer once: glibc uses it without a NULL check. Every field of a
/// `Cond` is an atomic, so a shared reference is enough while other threads use it.
macro_rules! cond_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_cond_t that stays valid for the call; all its fields are atomics.
        unsafe { arg($p as *const Cond) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut Cond) -> c_int {
    signal(cond_ref!(cond))
}

/// `pthread_cond_signal`.
#[inline(always)]
pub fn signal(c: &Cond) -> c_int {
    let wrefs = c.wrefs.load(Ordering::Relaxed);
    // no waiters: one load and return (the rest lives out of line so this path saves no registers)
    if wrefs >> 3 == 0 {
        return 0;
    }
    signal_waiters(c, wrefs)
}

#[cold]
#[inline(never)]
fn signal_waiters(c: &Cond, wrefs: u32) -> c_int {
    let private = is_private(wrefs);
    acquire_lock(c, private);
    let wseq_full = c.wseq.load(Ordering::Relaxed);
    let mut g1 = ((wseq_full & 1) ^ 1) as u32;
    let wseq = wseq_full >> 1;
    let mut do_wake = false;
    if c.g_size[g1 as usize].load(Ordering::Relaxed) != 0 || switch_g1(c, wseq, &mut g1) {
        c.g_signals[g1 as usize].fetch_add(1, Ordering::Relaxed);
        let s = c.g_size[g1 as usize].load(Ordering::Relaxed);
        c.g_size[g1 as usize].store(s.wrapping_sub(1), Ordering::Relaxed);
        do_wake = true;
    }
    release_lock(c, private);
    if do_wake {
        futex_wake(&c.g_signals[g1 as usize], 1, private);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut Cond) -> c_int {
    broadcast(cond_ref!(cond))
}

/// `pthread_cond_broadcast`.
#[inline(always)]
pub fn broadcast(c: &Cond) -> c_int {
    let wrefs = c.wrefs.load(Ordering::Relaxed);
    // no waiters: one load and return (the rest lives out of line so this path saves no registers)
    if wrefs >> 3 == 0 {
        return 0;
    }
    broadcast_waiters(c, wrefs)
}

#[cold]
#[inline(never)]
fn broadcast_waiters(c: &Cond, wrefs: u32) -> c_int {
    let private = is_private(wrefs);
    acquire_lock(c, private);
    let wseq_full = c.wseq.load(Ordering::Relaxed);
    let g2 = (wseq_full & 1) as u32;
    let mut g1 = g2 ^ 1;
    let wseq = wseq_full >> 1;
    let mut do_wake = false;
    let sz = c.g_size[g1 as usize].load(Ordering::Relaxed);
    if sz != 0 {
        c.g_signals[g1 as usize].fetch_add(sz, Ordering::Relaxed);
        c.g_size[g1 as usize].store(0, Ordering::Relaxed);
        futex_wake(&c.g_signals[g1 as usize], i32::MAX, private);
    }
    if switch_g1(c, wseq, &mut g1) {
        let sz = c.g_size[g1 as usize].load(Ordering::Relaxed);
        c.g_signals[g1 as usize].fetch_add(sz, Ordering::Relaxed);
        c.g_size[g1 as usize].store(0, Ordering::Relaxed);
        do_wake = true;
    }
    release_lock(c, private);
    if do_wake {
        futex_wake(&c.g_signals[g1 as usize], i32::MAX, private);
    }
    0
}

fn confirm_wakeup(c: &Cond, private: bool) {
    if c.wrefs.fetch_add(0u32.wrapping_sub(8), Ordering::Release) >> 2 == 3 {
        futex_wake(&c.wrefs, i32::MAX, private);
    }
}

/// A waiter gives up (cancelled or timed out): shrink its group if it still can, or send on the
/// signal it consumed.
fn cancel_waiting(c: &Cond, seq: u64, g: usize, private: bool) {
    let mut consumed_signal = false;
    acquire_lock(c, private);
    let g1_start = c.g1_start.load(Ordering::Relaxed);
    if g1_start > seq {
        consumed_signal = true;
    } else if g1_start + get_orig_size(c) as u64 <= seq {
        // current G2: not signaled, make it smaller
        let sz = c.g_size[g].load(Ordering::Relaxed);
        if sz.wrapping_add(MAX_GROUP_SIZE) > 0 {
            c.g_size[g].store(sz.wrapping_sub(1), Ordering::Relaxed);
        } else {
            release_lock(c, private);
            broadcast(c);
            return;
        }
    } else {
        // current G1
        let sz = c.g_size[g].load(Ordering::Relaxed);
        if sz == 0 {
            consumed_signal = true;
        } else {
            c.g_size[g].store(sz - 1, Ordering::Relaxed);
        }
    }
    release_lock(c, private);
    if consumed_signal {
        signal(c);
    }
}

struct CleanupArg {
    wseq: u64,
    cond: *const Cond,
    mutex: *mut Mutex,
    private: bool,
}

/// The cancellation handler of a waiting thread (registered by `wait_common` with a pointer to its `CleanupArg`).
unsafe extern "C" fn cleanup_waiting(arg: *mut c_void) {
    // SAFETY: `arg` is the CleanupArg on the cancelled waiter's stack (wait_common), still live while handlers run.
    let a = unsafe { &*(arg as *const CleanupArg) };
    // SAFETY: the condition variable the thread waits on stays valid while it waits (POSIX: no destroy with waiters).
    let c = unsafe { &*a.cond };
    let g = (a.wseq & 1) as usize;
    cancel_waiting(c, a.wseq >> 1, g, a.private);
    // a cancelled thread may have consumed a futex wake-up another waiter needed
    futex_wake(&c.g_signals[g], 1, a.private);
    confirm_wakeup(c, a.private);
    // SAFETY: the mutex the waiter released (still valid: the caller of pthread_cond_wait owns it).
    unsafe { mutex_cond_lock(a.mutex) };
}

/// Wait on `c` with `mutex` (held by the caller), until `abs` on `clock` at most (None: no timeout).
///
/// # Safety
/// `mutex` is the initialised mutex the caller holds; it stays valid for the call.
pub unsafe fn wait_common(c: &Cond, mutex: *mut Mutex, clock: c_int, abs: Option<&Timespec>) -> c_int {
    let mut result = 0;
    let wseq = c.wseq.fetch_add(2, Ordering::Acquire);
    let g = (wseq & 1) as usize;
    let seq = wseq >> 1;
    let flags = c.wrefs.fetch_add(8, Ordering::Relaxed);
    let private = is_private(flags);
    // SAFETY: `mutex` is valid and held (caller's contract).
    let err = unsafe { mutex_unlock_usercnt(mutex, false) };
    if err != 0 {
        cancel_waiting(c, seq, g, private);
        confirm_wakeup(c, private);
        return err;
    }
    loop {
        let signals = c.g_signals[g].load(Ordering::Acquire);
        let g1_start = c.g1_start.load(Ordering::Relaxed);
        if seq < g1_start {
            break;
        }
        if (signals.wrapping_sub(g1_start as u32)) as i32 > 0 {
            if c.g_signals[g].compare_exchange_weak(signals, signals - 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            continue;
        }
        let mut arg = CleanupArg { wseq, cond: c, mutex, private };
        // SAFETY: the handler gets a pointer to `arg`, which lives until with_cleanup returns (the handler only runs inside it).
        let e = unsafe {
            crate::cancel::with_cleanup(cleanup_waiting, &mut arg as *mut CleanupArg as *mut c_void, || match abs {
                None => futex_wait_cp(&c.g_signals[g], signals, private),
                Some(_) => futex_wait_abs_cp(&c.g_signals[g], signals, clock, abs, private),
            })
        };
        if e == ETIMEDOUT || e == EOVERFLOW {
            cancel_waiting(c, seq, g, private);
            result = e;
            break;
        }
    }
    confirm_wakeup(c, private);
    // SAFETY: as above: the caller's mutex, relocked before returning.
    let err = unsafe { mutex_cond_lock(mutex) };
    if err != 0 { err } else { result }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_wait(cond: *mut Cond, mutex: *mut Mutex) -> c_int {
    let c = cond_ref!(cond);
    // SAFETY: `mutex` is the caller's held mutex (C contract).
    unsafe { wait_common(c, mutex, 0, None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_timedwait(cond: *mut Cond, mutex: *mut Mutex, abstime: *const Timespec) -> c_int {
    // SAFETY: `abstime` is a valid struct timespec (C contract; read without a NULL check, as glibc).
    let abs = unsafe { arg(abstime) };
    if !valid_nsec(abs) {
        return EINVAL;
    }
    let c = cond_ref!(cond);
    let flags = c.wrefs.load(Ordering::Relaxed);
    let clock = if flags & CLOCK_MONOTONIC_MASK != 0 { CLOCK_MONOTONIC } else { CLOCK_REALTIME };
    // SAFETY: `mutex` is the caller's held mutex (C contract).
    unsafe { wait_common(c, mutex, clock, Some(abs)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_clockwait(cond: *mut Cond, mutex: *mut Mutex, clockid: c_int, abstime: *const Timespec) -> c_int {
    // SAFETY: `abstime` is a valid struct timespec (C contract; read without a NULL check, as glibc).
    let abs = unsafe { arg(abstime) };
    if !valid_nsec(abs) {
        return EINVAL;
    }
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }
    let c = cond_ref!(cond);
    // SAFETY: `mutex` is the caller's held mutex (C contract).
    unsafe { wait_common(c, mutex, clockid, Some(abs)) }
}

impl Cond {
    /// What `pthread_cond_init` makes from an attribute value (bit 0 process-shared, bit 1 CLOCK_MONOTONIC); all zero
    /// (`with_attr(0)`) is the static initializer.
    pub const fn with_attr(value: c_int) -> Cond {
        let mut w = 0u32;
        if value & 1 != 0 {
            w |= SHARED_MASK;
        }
        if (value >> 1) & 1 != CLOCK_REALTIME {
            w |= CLOCK_MONOTONIC_MASK;
        }
        Cond {
            wseq: AtomicU64::new(0),
            g1_start: AtomicU64::new(0),
            g_size: [AtomicU32::new(0), AtomicU32::new(0)],
            g1_orig_size: AtomicU32::new(0),
            wrefs: AtomicU32::new(w),
            g_signals: [AtomicU32::new(0), AtomicU32::new(0)],
            unused: [0; 2],
        }
    }
}

/// `pthread_cond_destroy`: wait until the woken waiters have stopped touching `c`.
pub fn destroy(c: &Cond) -> c_int {
    let mut wrefs = c.wrefs.fetch_or(4, Ordering::Acquire);
    let private = is_private(wrefs);
    while wrefs >> 3 != 0 {
        futex_wait(&c.wrefs, wrefs, private);
        wrefs = c.wrefs.load(Ordering::Acquire);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_init(cond: *mut Cond, attr: *const CondAttr) -> c_int {
    // SAFETY: `attr` is NULL or an initialised pthread_condattr_t (C contract).
    let v = unsafe { attr.as_ref() }.map_or(0, |a| a.value);
    // SAFETY: `cond` is writable memory for one pthread_cond_t that no other thread uses during the init (C contract).
    unsafe { core::ptr::write(cond, Cond::with_attr(v)) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut Cond) -> c_int {
    destroy(cond_ref!(cond))
}

impl CondAttr {
    pub fn set_pshared(&mut self, pshared: c_int) -> c_int {
        if pshared != 0 && pshared != 1 {
            return EINVAL;
        }
        self.value = (self.value & !1) | pshared;
        0
    }

    pub fn set_clock(&mut self, clock: c_int) -> c_int {
        if clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC {
            return EINVAL;
        }
        self.value = (self.value & !(1 << 1)) | (clock << 1);
        0
    }
}

macro_rules! attr_mut {
    ($p:expr) => {{
        // SAFETY: the C caller passes a valid pthread_condattr_t that no other thread uses during the call.
        unsafe { arg_mut($p) }
    }};
}
macro_rules! attr_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_condattr_t.
        unsafe { arg($p) }
    }};
}
macro_rules! out {
    ($p:expr) => {{
        // SAFETY: the C caller passes a writable int (written without a NULL check, as glibc).
        unsafe { arg_mut($p) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(a: *mut CondAttr) -> c_int {
    // SAFETY: `a` is writable memory for one pthread_condattr_t (C contract); the old contents are not read.
    unsafe { core::ptr::write(a, CondAttr { value: 0 }) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_destroy(_a: *mut CondAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getpshared(a: *const CondAttr, pshared: *mut c_int) -> c_int {
    *out!(pshared) = attr_ref!(a).value & 1;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setpshared(a: *mut CondAttr, pshared: c_int) -> c_int {
    attr_mut!(a).set_pshared(pshared)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getclock(a: *const CondAttr, clock: *mut c_int) -> c_int {
    *out!(clock) = (attr_ref!(a).value >> 1) & 1;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setclock(a: *mut CondAttr, clock: c_int) -> c_int {
    attr_mut!(a).set_clock(clock)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::mutex::*;

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<Cond>(), 48);
        assert_eq!(core::mem::offset_of!(Cond, g1_orig_size), 24);
        assert_eq!(core::mem::offset_of!(Cond, wrefs), 28);
        assert_eq!(core::mem::offset_of!(Cond, g_signals), 32);
    }

    #[test]
    fn timedwait_times_out() {
        unsafe {
            let mut m: Mutex = core::mem::zeroed();
            let mut c: Cond = core::mem::zeroed();
            pthread_mutex_init(&mut m, core::ptr::null());
            pthread_mutex_lock(&mut m);
            let mut now = Timespec::default();
            clock_gettime(CLOCK_REALTIME, &mut now);
            timespec_add_ns(&mut now, 20_000_000);
            assert_eq!(pthread_cond_timedwait(&mut c, &mut m, &now), ETIMEDOUT);
            // the mutex is held again
            assert_eq!(pthread_mutex_trylock(&mut m), EBUSY);
            let bad = Timespec { tv_sec: 0, tv_nsec: -1 };
            assert_eq!(pthread_cond_timedwait(&mut c, &mut m, &bad), EINVAL);
            assert_eq!(pthread_cond_clockwait(&mut c, &mut m, 5, &now), EINVAL);
            pthread_mutex_unlock(&mut m);
        }
    }

    #[test]
    fn ping_pong_with_std_threads() {
        use std::sync::Arc;
        struct S {
            m: core::cell::UnsafeCell<Mutex>,
            c: core::cell::UnsafeCell<Cond>,
            turn: core::cell::UnsafeCell<u32>,
        }
        unsafe impl Sync for S {}
        unsafe impl Send for S {}
        let s = Arc::new(S { m: core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }), c: core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }), turn: core::cell::UnsafeCell::new(0) });
        let rounds = 2000;
        let hs: Vec<_> = (0..2u32)
            .map(|me| {
                let s = s.clone();
                std::thread::spawn(move || unsafe {
                    for _ in 0..rounds {
                        pthread_mutex_lock(s.m.get());
                        while *s.turn.get() != me {
                            pthread_cond_wait(s.c.get(), s.m.get());
                        }
                        *s.turn.get() = 1 - me;
                        pthread_cond_broadcast(s.c.get());
                        pthread_mutex_unlock(s.m.get());
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(unsafe { pthread_cond_destroy(s.c.get()) }, 0);
        // the waits must leave the user count balanced: destroy used to fail with EBUSY (nslookup aborted on it)
        assert_eq!(unsafe { crate::mutex::pthread_mutex_destroy(s.m.get()) }, 0);
    }

    #[test]
    fn signal_wakes_exactly_one_at_a_time() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32 as A, Ordering::SeqCst};
        struct S {
            m: core::cell::UnsafeCell<Mutex>,
            c: core::cell::UnsafeCell<Cond>,
            go: A,
            woke: A,
            waiting: A,
        }
        unsafe impl Sync for S {}
        unsafe impl Send for S {}
        let s = Arc::new(S { m: core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }), c: core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }), go: A::new(0), woke: A::new(0), waiting: A::new(0) });
        let n = 6;
        let hs: Vec<_> = (0..n)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || unsafe {
                    pthread_mutex_lock(s.m.get());
                    s.waiting.fetch_add(1, SeqCst);
                    while s.go.load(SeqCst) == 0 {
                        pthread_cond_wait(s.c.get(), s.m.get());
                    }
                    s.go.fetch_sub(1, SeqCst);
                    s.woke.fetch_add(1, SeqCst);
                    pthread_mutex_unlock(s.m.get());
                })
            })
            .collect();
        while s.waiting.load(SeqCst) < n {
            std::thread::yield_now();
        }
        for i in 1..=n {
            unsafe {
                pthread_mutex_lock(s.m.get());
                s.go.fetch_add(1, SeqCst);
                pthread_cond_signal(s.c.get());
                pthread_mutex_unlock(s.m.get());
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while s.woke.load(SeqCst) < i {
                assert!(std::time::Instant::now() < deadline, "signal {i} did not wake anyone");
                std::thread::yield_now();
            }
        }
        for h in hs {
            h.join().unwrap();
        }
    }
}
