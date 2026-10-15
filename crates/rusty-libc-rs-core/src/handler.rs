use crate::errno::Errno;
use crate::syscall::nr;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

pub const SLOTS: usize = 8;

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
    prev: AtomicUsize,
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

static TABLE: [SigSlots; 65] = [EMPTY; 65];

struct Saved {
    count: usize,
    old: CSigaction,
}

static REGISTRY: Mutex<[Saved; 65]> = Mutex::new([const { Saved { count: 0, old: CSigaction::ZERO } }; 65]);

extern "C" fn handler(sig: c_int, info: *mut c_void, ctx: *mut c_void) {
    let Some(t) = usize::try_from(sig).ok().and_then(|i| TABLE.get(i)) else { return };
    t.inflight.fetch_add(1, SeqCst);
    for s in &t.flags {
        let p = s.load(SeqCst);
        if !p.is_null() {
            unsafe { &*p }.store(true, SeqCst);
        }
    }
    for s in &t.counters {
        let p = s.load(SeqCst);
        if !p.is_null() {
            unsafe { &*p }.fetch_add(1, SeqCst);
        }
    }
    t.inflight.fetch_sub(1, SeqCst);
    let prev = t.prev.load(SeqCst);
    if prev != 0 {
        if t.prev_siginfo.load(SeqCst) {
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn(c_int, *mut c_void, *mut c_void)>(prev as *const ()) };
            f(sig, info, ctx);
        } else {
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn(c_int)>(prev as *const ()) };
            f(sig);
        }
    }
}

fn ours() -> usize {
    handler as *const () as usize
}

fn check(sig: i32) -> Result<usize, Errno> {
    match sig {
        1..=64 if !matches!(sig, 4 | 7 | 8 | 9 | 11 | 19 | 32 | 33) => Ok(sig as usize),
        _ => Err(Errno::EINVAL),
    }
}

fn c_sigaction(sig: usize, new: Option<&CSigaction>, old: Option<&mut CSigaction>) -> Result<(), Errno> {
    let n = new.map_or(core::ptr::null(), |n| n as *const CSigaction);
    let o = old.map_or(core::ptr::null_mut(), |o| o as *mut CSigaction);
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

#[derive(Debug)]
#[must_use = "dropping a Registration unregisters it at once; call .keep() to keep it for the life of the process"]
pub struct Registration {
    sig: usize,
    kind: Kind,
    slot: usize,
}

impl Registration {
    pub fn signal(&self) -> i32 {
        self.sig as i32
    }

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
    let Some(slot) = slot else { return Err((Errno(28), ptr)) };
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
        }
    }
}

fn release(kind: Kind, p: *mut u8) {
    if p.is_null() {
        return;
    }
    match kind {
        Kind::Flag => drop(unsafe { Arc::from_raw(p.cast::<AtomicBool>()) }),
        Kind::Counter => drop(unsafe { Arc::from_raw(p.cast::<AtomicUsize>()) }),
    }
}

pub fn register_flag(sig: i32, flag: Arc<AtomicBool>) -> Result<Registration, Errno> {
    register(sig, Kind::Flag, Arc::into_raw(flag).cast_mut().cast()).map_err(|(e, p)| {
        release(Kind::Flag, p);
        e
    })
}

pub fn register_counter(sig: i32, counter: Arc<AtomicUsize>) -> Result<Registration, Errno> {
    register(sig, Kind::Counter, Arc::into_raw(counter).cast_mut().cast()).map_err(|(e, p)| {
        release(Kind::Counter, p);
        e
    })
}

pub fn handler_is_ours(sig: i32) -> bool {
    let mut cur = CSigaction::ZERO;
    sig > 0 && c_sigaction(sig as usize, None, Some(&mut cur)).is_ok() && cur.handler == ours()
}
