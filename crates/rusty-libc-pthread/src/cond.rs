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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut Cond) -> c_int {
    let c = unsafe { &*cond };
    let wrefs = c.wrefs.load(Ordering::Relaxed);
    if wrefs >> 3 == 0 {
        return 0;
    }
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
    let c = unsafe { &*cond };
    let wrefs = c.wrefs.load(Ordering::Relaxed);
    if wrefs >> 3 == 0 {
        return 0;
    }
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

fn cancel_waiting(cond: *mut Cond, seq: u64, g: usize, private: bool) {
    let c = unsafe { &*cond };
    let mut consumed_signal = false;
    acquire_lock(c, private);
    let g1_start = c.g1_start.load(Ordering::Relaxed);
    if g1_start > seq {
        consumed_signal = true;
    } else if g1_start + get_orig_size(c) as u64 <= seq {
        let sz = c.g_size[g].load(Ordering::Relaxed);
        if sz.wrapping_add(MAX_GROUP_SIZE) > 0 {
            c.g_size[g].store(sz.wrapping_sub(1), Ordering::Relaxed);
        } else {
            release_lock(c, private);
            unsafe { pthread_cond_broadcast(cond) };
            return;
        }
    } else {
        let sz = c.g_size[g].load(Ordering::Relaxed);
        if sz == 0 {
            consumed_signal = true;
        } else {
            c.g_size[g].store(sz - 1, Ordering::Relaxed);
        }
    }
    release_lock(c, private);
    if consumed_signal {
        unsafe { pthread_cond_signal(cond) };
    }
}

struct CleanupArg {
    wseq: u64,
    cond: *mut Cond,
    mutex: *mut Mutex,
    private: bool,
}

unsafe extern "C" fn cleanup_waiting(arg: *mut c_void) {
    unsafe {
        let a = &*(arg as *const CleanupArg);
        let g = (a.wseq & 1) as usize;
        cancel_waiting(a.cond, a.wseq >> 1, g, a.private);
        futex_wake(&(*a.cond).g_signals[g], 1, a.private);
        confirm_wakeup(&*a.cond, a.private);
        mutex_cond_lock(a.mutex);
    }
}

unsafe fn wait_common(cond: *mut Cond, mutex: *mut Mutex, clock: c_int, abs: *const Timespec) -> c_int {
    unsafe {
        let c = &*cond;
        let mut result = 0;
        let wseq = c.wseq.fetch_add(2, Ordering::Acquire);
        let g = (wseq & 1) as usize;
        let seq = wseq >> 1;
        let flags = c.wrefs.fetch_add(8, Ordering::Relaxed);
        let private = is_private(flags);
        let err = mutex_unlock_usercnt(mutex, false);
        if err != 0 {
            cancel_waiting(cond, seq, g, private);
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
            let mut arg = CleanupArg { wseq, cond, mutex, private };
            let e = crate::cancel::with_cleanup(cleanup_waiting, &mut arg as *mut CleanupArg as *mut c_void, || {
                if abs.is_null() { futex_wait_cp(&c.g_signals[g], signals, private) } else { futex_wait_abs_cp(&c.g_signals[g], signals, clock, abs, private) }
            });
            if e == ETIMEDOUT || e == EOVERFLOW {
                cancel_waiting(cond, seq, g, private);
                result = e;
                break;
            }
        }
        confirm_wakeup(c, private);
        let err = mutex_cond_lock(mutex);
        if err != 0 { err } else { result }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_wait(cond: *mut Cond, mutex: *mut Mutex) -> c_int {
    unsafe { wait_common(cond, mutex, 0, core::ptr::null()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_timedwait(cond: *mut Cond, mutex: *mut Mutex, abstime: *const Timespec) -> c_int {
    unsafe {
        if !valid_nsec(&*abstime) {
            return EINVAL;
        }
        let flags = (*cond).wrefs.load(Ordering::Relaxed);
        let clock = if flags & CLOCK_MONOTONIC_MASK != 0 { CLOCK_MONOTONIC } else { CLOCK_REALTIME };
        wait_common(cond, mutex, clock, abstime)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_clockwait(cond: *mut Cond, mutex: *mut Mutex, clockid: c_int, abstime: *const Timespec) -> c_int {
    unsafe {
        if !valid_nsec(&*abstime) {
            return EINVAL;
        }
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }
        wait_common(cond, mutex, clockid, abstime)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_init(cond: *mut Cond, attr: *const CondAttr) -> c_int {
    unsafe {
        core::ptr::write_bytes(cond as *mut u8, 0, core::mem::size_of::<Cond>());
        if !attr.is_null() {
            let v = (*attr).value;
            let mut w = 0u32;
            if v & 1 != 0 {
                w |= SHARED_MASK;
            }
            if (v >> 1) & 1 != CLOCK_REALTIME {
                w |= CLOCK_MONOTONIC_MASK;
            }
            (*cond).wrefs = AtomicU32::new(w);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut Cond) -> c_int {
    let c = unsafe { &*cond };
    let mut wrefs = c.wrefs.fetch_or(4, Ordering::Acquire);
    let private = is_private(wrefs);
    while wrefs >> 3 != 0 {
        futex_wait(&c.wrefs, wrefs, private);
        wrefs = c.wrefs.load(Ordering::Acquire);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(a: *mut CondAttr) -> c_int {
    unsafe {
        (*a).value = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_destroy(_a: *mut CondAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getpshared(a: *const CondAttr, pshared: *mut c_int) -> c_int {
    unsafe {
        *pshared = (*a).value & 1;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setpshared(a: *mut CondAttr, pshared: c_int) -> c_int {
    unsafe {
        if pshared != 0 && pshared != 1 {
            return EINVAL;
        }
        (*a).value = ((*a).value & !1) | pshared;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getclock(a: *const CondAttr, clock: *mut c_int) -> c_int {
    unsafe {
        *clock = ((*a).value >> 1) & 1;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setclock(a: *mut CondAttr, clock: c_int) -> c_int {
    unsafe {
        if clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC {
            return EINVAL;
        }
        (*a).value = ((*a).value & !(1 << 1)) | (clock << 1);
        0
    }
}

