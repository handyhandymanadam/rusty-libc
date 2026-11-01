//! pthread_barrier_t (32 bytes), pthread_barrierattr_t, pthread_spinlock_t (int), pthread_once_t
//! (int). The barrier and once algorithms are glibc's, ported to Rust (derived from glibc's
//! nptl/pthread_barrier_*.c and pthread_once.c, LGPL-2.1; see LICENSES.md).
//!
//! Safe core: the words these objects share are atomics, so the algorithms work on references; the exported functions
//! convert the pointer once. Unsafe left: those conversions and the call of the program's once initialiser.
use crate::cancel;
use crate::{pthread_once_t, pthread_spinlock_t};
use crate::sys::*;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering, fence};

pub const PTHREAD_BARRIER_SERIAL_THREAD: c_int = -1;
const BARRIER_IN_THRESHOLD: u32 = u32::MAX / 2;

/// glibc's `struct pthread_barrier` inside the 32 bytes of `pthread_barrier_t`.
#[repr(C)]
pub struct Barrier {
    in_: AtomicU32,
    current_round: AtomicU32,
    count: u32,
    /// glibc's encoding (nptl FUTEX_PRIVATE = 0, FUTEX_SHARED = 128): 0 for a process-private barrier, 128 for a
    /// process-shared one. Another process may run glibc on the same barrier, so the value must mean the same there.
    shared: i32,
    out: AtomicU32,
    pad: [u32; 3],
}

const _: () = assert!(core::mem::size_of::<Barrier>() == 32);

#[repr(C)]
pub struct BarrierAttr {
    pub pshared: c_int,
}

fn bar_private(b: &Barrier) -> bool {
    b.shared == 0
}

impl Barrier {
    /// A barrier for `count` threads (process-shared when `pshared`), as `pthread_barrier_init` makes it.
    pub const fn new(count: u32, pshared: bool) -> Barrier {
        Barrier { in_: AtomicU32::new(0), current_round: AtomicU32::new(0), count, shared: if pshared { 128 } else { 0 }, out: AtomicU32::new(0), pad: [0; 3] }
    }
}

/// The exported functions convert the barrier pointer once (glibc uses it without a NULL check). The fields other threads
/// change are atomics; `count` and `shared` are written only by pthread_barrier_init.
macro_rules! barrier_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_barrier_t that stays valid for the call.
        unsafe { arg($p as *const Barrier) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_init(b: *mut Barrier, attr: *const BarrierAttr, count: u32) -> c_int {
    if count == 0 || count >= BARRIER_IN_THRESHOLD {
        return EINVAL;
    }
    // SAFETY: `attr` is NULL or an initialised pthread_barrierattr_t (C contract).
    let pshared = unsafe { attr.as_ref() }.map_or(0, |a| a.pshared);
    // SAFETY: `b` is writable memory for one pthread_barrier_t that no other thread uses during the init (C contract).
    unsafe { core::ptr::write(b, Barrier::new(count, pshared != 0)) };
    0
}

/// `pthread_barrier_destroy`: wait until the threads of the last round have left.
pub fn barrier_destroy(b: &Barrier) -> c_int {
    let count = b.count;
    let max_in_before_reset = BARRIER_IN_THRESHOLD - BARRIER_IN_THRESHOLD % count;
    let mut inn = b.in_.load(Ordering::Relaxed);
    if b.out.fetch_add(max_in_before_reset.wrapping_sub(inn), Ordering::Relaxed) < inn {
        while inn != 0 {
            futex_wait(&b.in_, inn, bar_private(b));
            inn = b.in_.load(Ordering::Relaxed);
        }
    }
    fence(Ordering::Acquire);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_destroy(b: *mut Barrier) -> c_int {
    barrier_destroy(barrier_ref!(b))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_wait(b: *mut Barrier) -> c_int {
    barrier_wait(barrier_ref!(b))
}

/// `pthread_barrier_wait`: PTHREAD_BARRIER_SERIAL_THREAD for one thread of each round, 0 for the others.
#[inline]
pub fn barrier_wait(b: &Barrier) -> c_int {
    let private = bar_private(b);
    loop {
        // reset_restart:
        let mut i = b.in_.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        let count = b.count;
        let max_in_before_reset = BARRIER_IN_THRESHOLD - BARRIER_IN_THRESHOLD % count;
        if i > max_in_before_reset {
            while i > max_in_before_reset {
                futex_wait(&b.in_, i, private);
                i = b.in_.load(Ordering::Relaxed);
            }
            continue;
        }
        let mut cr = b.current_round.load(Ordering::Relaxed);
        let mut ready_to_leave = false;
        while cr + count <= i {
            let newcr = i - i % count;
            match b.current_round.compare_exchange_weak(cr, newcr, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => {
                    cr = newcr;
                    futex_wake(&b.current_round, i32::MAX, private);
                    if i <= cr {
                        ready_to_leave = true;
                    }
                    break;
                }
                Err(x) => cr = x,
            }
        }
        if !ready_to_leave {
            while i > cr {
                futex_wait(&b.current_round, cr, private);
                cr = b.current_round.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
        }
        let o = b.out.fetch_add(1, Ordering::Release).wrapping_add(1);
        if o == max_in_before_reset {
            fence(Ordering::Acquire);
            b.current_round.store(0, Ordering::Relaxed);
            b.out.store(0, Ordering::Relaxed);
            let shared_private = bar_private(b);
            b.in_.store(0, Ordering::Release);
            futex_wake(&b.in_, i32::MAX, shared_private);
        }
        return if i.is_multiple_of(count) { PTHREAD_BARRIER_SERIAL_THREAD } else { 0 };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_init(a: *mut BarrierAttr) -> c_int {
    // SAFETY: `a` is writable memory for one pthread_barrierattr_t (C contract); the old contents are not read.
    unsafe { core::ptr::write(a, BarrierAttr { pshared: 0 }) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_destroy(_a: *mut BarrierAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(a: *const BarrierAttr, p: *mut c_int) -> c_int {
    // SAFETY: `a` is an initialised pthread_barrierattr_t (C contract).
    let v = unsafe { arg(a) }.pshared;
    // SAFETY: `p` is a writable int (C contract; written without a NULL check, as glibc).
    unsafe { *p = v };
    0
}

impl BarrierAttr {
    pub fn set_pshared(&mut self, p: c_int) -> c_int {
        if p != 0 && p != 1 {
            return EINVAL;
        }
        self.pshared = p;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(a: *mut BarrierAttr, p: c_int) -> c_int {
    // SAFETY: `a` is a valid pthread_barrierattr_t that no other thread uses during the call (C contract).
    unsafe { arg_mut(a) }.set_pshared(p)
}

// ---- spin locks -------------------------------------------------------------------------------
// glibc's x86_64 encoding (sysdeps/x86_64/nptl/pthread_spin_*.S): 1 is free, 0 or less is held. Lock is an atomic decrement
// that took the lock when it gave 0, otherwise wait until the word is positive and decrement again; unlock (and init) store
// 1; trylock swaps in 0 and took the lock when it got 1. A spin lock in memory shared with a program linked to glibc, and code
// that reads the word, see the same values.

/// The atomic view of a C spin lock word (an `int`).
///
/// # Safety
/// `l` points to a valid, aligned `int` that stays valid for `'a` and is only accessed atomically meanwhile.
#[inline(always)]
unsafe fn spin_word<'a>(l: *mut pthread_spinlock_t) -> &'a AtomicI32 {
    // SAFETY: forwarded contract; AtomicI32 has the size and alignment of int.
    unsafe { &*(l as *const AtomicI32) }
}

/// `pthread_spin_lock` on the lock word.
#[inline(always)]
pub fn spin_lock(l: &AtomicI32) {
    while l.fetch_sub(1, Ordering::Acquire) != 1 {
        while l.load(Ordering::Relaxed) <= 0 {
            core::hint::spin_loop();
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_init(l: *mut pthread_spinlock_t, _pshared: c_int) -> c_int {
    // SAFETY: `l` is a valid int (C contract).
    unsafe { spin_word(l) }.store(1, Ordering::Release);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_destroy(_l: *mut pthread_spinlock_t) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_lock(l: *mut pthread_spinlock_t) -> c_int {
    // SAFETY: `l` is an initialised spin lock (C contract).
    spin_lock(unsafe { spin_word(l) });
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_trylock(l: *mut pthread_spinlock_t) -> c_int {
    // SAFETY: `l` is an initialised spin lock (C contract).
    let l = unsafe { spin_word(l) };
    if l.swap(0, Ordering::Acquire) == 1 { 0 } else { EBUSY }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_unlock(l: *mut pthread_spinlock_t) -> c_int {
    // SAFETY: `l` is an initialised spin lock (C contract).
    unsafe { spin_word(l) }.store(1, Ordering::Release);
    0
}

// ---- once ---------------------------------------------------------------------------------------

const ONCE_INPROGRESS: u32 = 1;
const ONCE_DONE: u32 = 2;
const ONCE_FORK_GEN_INCR: u32 = 4;

static FORK_GENERATION: AtomicU32 = AtomicU32::new(0);

/// Called in the child after fork: once-initializations that were running in threads that no longer
/// exist can be restarted.
pub fn once_fork_child() {
    FORK_GENERATION.fetch_add(ONCE_FORK_GEN_INCR, Ordering::Relaxed);
}

unsafe extern "C" fn clear_once(arg: *mut c_void) {
    // SAFETY: `arg` is the once word registered by once_slow, valid while its initialiser runs.
    let o = unsafe { &*(arg as *const AtomicU32) };
    o.store(0, Ordering::Relaxed);
    futex_wake(o, i32::MAX, true);
}

/// # Safety
/// `f` may be called (the program's initialiser).
#[cold]
unsafe fn once_slow(o: &AtomicU32, f: unsafe extern "C" fn()) -> c_int {
    loop {
        let mut val = o.load(Ordering::Acquire);
        let newval = FORK_GENERATION.load(Ordering::Relaxed) | ONCE_INPROGRESS;
        loop {
            if val & ONCE_DONE != 0 {
                return 0;
            }
            match o.compare_exchange_weak(val, newval, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(x) => val = x,
            }
        }
        if val & ONCE_INPROGRESS != 0 && val == newval {
            futex_wait(o, newval, true);
            continue;
        }
        let body = || {
            // SAFETY: the caller vouches for `f`.
            unsafe { f() }
        };
        // SAFETY: the handler gets `o`, which outlives the call (the handler only runs inside it).
        unsafe { cancel::with_cleanup(clear_once, o as *const AtomicU32 as *mut c_void, body) };
        o.store(ONCE_DONE, Ordering::Release);
        futex_wake(o, i32::MAX, true);
        return 0;
    }
}

/// `pthread_once` on a once word.
///
/// # Safety
/// `f` may be called (the program's initialiser).
#[inline(always)]
pub unsafe fn once_call(o: &AtomicU32, f: unsafe extern "C" fn()) -> c_int {
    if o.load(Ordering::Acquire) & ONCE_DONE != 0 {
        return 0;
    }
    // SAFETY: forwarded contract.
    unsafe { once_slow(o, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_once(once: *mut pthread_once_t, f: unsafe extern "C" fn()) -> c_int {
    // SAFETY: `once` is a valid pthread_once_t (an int, used only atomically: C contract).
    let o = unsafe { au32(once as *const u32) };
    // SAFETY: `f` is the caller's initialiser.
    unsafe { once_call(o, f) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn barrier_round_trip() {
        use std::sync::Arc;
        let b: Arc<core::cell::UnsafeCell<Barrier>> = Arc::new(core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }));
        struct P(*mut Barrier);
        unsafe impl Send for P {}
        unsafe { assert_eq!(pthread_barrier_init(b.get(), core::ptr::null(), 4), 0) };
        let serial = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let p = P(b.get());
                let serial = serial.clone();
                std::thread::spawn(move || {
                    let p = p;
                    for _ in 0..200 {
                        if unsafe { pthread_barrier_wait(p.0) } == PTHREAD_BARRIER_SERIAL_THREAD {
                            serial.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(serial.load(Ordering::Relaxed), 200);
        unsafe { assert_eq!(pthread_barrier_destroy(b.get()), 0) };
    }

    #[test]
    fn barrier_init_errors() {
        unsafe {
            let mut b: Barrier = core::mem::zeroed();
            assert_eq!(pthread_barrier_init(&mut b, core::ptr::null(), 0), EINVAL);
            assert_eq!(pthread_barrier_init(&mut b, core::ptr::null(), u32::MAX), EINVAL);
            let mut a = BarrierAttr { pshared: 0 };
            assert_eq!(pthread_barrierattr_setpshared(&mut a, 2), EINVAL);
        }
    }

    #[test]
    fn once_runs_once() {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        unsafe extern "C" fn init() {
            COUNT.fetch_add(1, Ordering::SeqCst);
        }
        let once = AtomicU32::new(0);
        let p = &once as *const AtomicU32 as usize;
        let hs: Vec<_> = (0..6).map(|_| std::thread::spawn(move || unsafe { pthread_once(p as *mut c_int, init) })).collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn spin() {
        unsafe {
            let l = AtomicU32::new(7);
            assert_eq!(pthread_spin_init(&l as *const AtomicU32 as *mut c_int, 0), 0);
            assert_eq!(pthread_spin_lock(&l as *const AtomicU32 as *mut c_int), 0);
            assert_eq!(pthread_spin_trylock(&l as *const AtomicU32 as *mut c_int), EBUSY);
            assert_eq!(pthread_spin_unlock(&l as *const AtomicU32 as *mut c_int), 0);
            assert_eq!(pthread_spin_trylock(&l as *const AtomicU32 as *mut c_int), 0);
        }
    }
}
