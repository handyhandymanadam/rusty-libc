use crate::cancel;
use crate::{pthread_once_t, pthread_spinlock_t};
use crate::sys::*;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, Ordering, fence};

pub const PTHREAD_BARRIER_SERIAL_THREAD: c_int = -1;
const BARRIER_IN_THRESHOLD: u32 = u32::MAX / 2;

#[repr(C)]
pub struct Barrier {
    in_: AtomicU32,
    current_round: AtomicU32,
    count: u32,
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_init(b: *mut Barrier, attr: *const BarrierAttr, count: u32) -> c_int {
    unsafe {
        if count == 0 || count >= BARRIER_IN_THRESHOLD {
            return EINVAL;
        }
        let pshared = if attr.is_null() { 0 } else { (*attr).pshared };
        core::ptr::write_bytes(b as *mut u8, 0, 32);
        (*b).count = count;
        (*b).shared = if pshared == 0 { 0 } else { 128 };
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_destroy(b: *mut Barrier) -> c_int {
    let b = unsafe { &*b };
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
pub unsafe extern "C" fn pthread_barrier_wait(b: *mut Barrier) -> c_int {
    let b = unsafe { &*b };
    let private = bar_private(b);
    loop {
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
        return if i % count == 0 { PTHREAD_BARRIER_SERIAL_THREAD } else { 0 };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_init(a: *mut BarrierAttr) -> c_int {
    unsafe {
        (*a).pshared = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_destroy(_a: *mut BarrierAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(a: *const BarrierAttr, p: *mut c_int) -> c_int {
    unsafe {
        *p = (*a).pshared;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(a: *mut BarrierAttr, p: c_int) -> c_int {
    unsafe {
        if p != 0 && p != 1 {
            return EINVAL;
        }
        (*a).pshared = p;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_init(l: *mut pthread_spinlock_t, _pshared: c_int) -> c_int {
    unsafe {
        (*(l as *mut AtomicU32)).store(0, Ordering::Release);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_destroy(_l: *mut pthread_spinlock_t) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_lock(l: *mut pthread_spinlock_t) -> c_int {
    let l = unsafe { &*(l as *mut AtomicU32) };
    while l.swap(1, Ordering::Acquire) != 0 {
        while l.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_trylock(l: *mut pthread_spinlock_t) -> c_int {
    let l = unsafe { &*(l as *mut AtomicU32) };
    if l.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() { 0 } else { EBUSY }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_unlock(l: *mut pthread_spinlock_t) -> c_int {
    unsafe { (*(l as *mut AtomicU32)).store(0, Ordering::Release) };
    0
}

const ONCE_INPROGRESS: u32 = 1;
const ONCE_DONE: u32 = 2;
const ONCE_FORK_GEN_INCR: u32 = 4;

static FORK_GENERATION: AtomicU32 = AtomicU32::new(0);

pub fn once_fork_child() {
    FORK_GENERATION.fetch_add(ONCE_FORK_GEN_INCR, Ordering::Relaxed);
}

unsafe extern "C" fn clear_once(arg: *mut c_void) {
    let o = unsafe { &*(arg as *const AtomicU32) };
    o.store(0, Ordering::Relaxed);
    futex_wake(o, i32::MAX, true);
}

#[cold]
unsafe fn once_slow(o: &AtomicU32, f: unsafe extern "C" fn()) -> c_int {
    unsafe {
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
            cancel::with_cleanup(clear_once, o as *const AtomicU32 as *mut c_void, || f());
            o.store(ONCE_DONE, Ordering::Release);
            futex_wake(o, i32::MAX, true);
            return 0;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_once(once: *mut pthread_once_t, f: unsafe extern "C" fn()) -> c_int {
    unsafe {
        let o = &*(once as *mut AtomicU32);
        if o.load(Ordering::Acquire) & ONCE_DONE != 0 {
            return 0;
        }
        once_slow(o, f)
    }
}

