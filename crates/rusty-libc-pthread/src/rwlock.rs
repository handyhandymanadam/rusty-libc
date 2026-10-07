use crate::sys::*;
use core::ffi::c_int;
use core::sync::atomic::{AtomicU32, Ordering, fence};

pub const PTHREAD_RWLOCK_PREFER_READER_NP: u32 = 0;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: u32 = 1;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: u32 = 2;

const WRPHASE: u32 = 1;
const WRLOCKED: u32 = 2;
const RWAITING: u32 = 4;
const READER_SHIFT: u32 = 3;
const READER_OVERFLOW: u32 = 1 << 31;
const WRHANDOVER: u32 = 1 << 31;
const FUTEX_USED: u32 = 2;

#[repr(C)]
pub struct RwLock {
    readers: AtomicU32,
    writers: AtomicU32,
    wrphase_futex: AtomicU32,
    writers_futex: AtomicU32,
    pad3: u32,
    pad4: u32,
    cur_writer: AtomicU32,
    shared: u32,
    pad1: u64,
    pad2: u64,
    flags: u32,
    pad5: u32,
}

const _: () = assert!(core::mem::size_of::<RwLock>() == 56);
const _: () = assert!(core::mem::offset_of!(RwLock, flags) == 48);

#[repr(C)]
pub struct RwLockAttr {
    pub lockkind: c_int,
    pub pshared: c_int,
}

#[inline]
fn private_of(l: &RwLock) -> bool {
    l.shared == 0
}

fn tid() -> u32 {
    gettid() as u32
}

fn rdunlock(l: &RwLock) {
    let private = private_of(l);
    let mut r = l.readers.load(Ordering::Relaxed);
    let mut rnew;
    loop {
        rnew = r.wrapping_sub(1 << READER_SHIFT);
        if rnew >> READER_SHIFT == 0 {
            if rnew & WRLOCKED != 0 {
                rnew |= WRPHASE;
            }
            rnew &= !RWAITING;
        }
        match l.readers.compare_exchange_weak(r, rnew, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => r = x,
        }
    }
    if rnew & WRPHASE != 0 {
        fence(Ordering::Acquire);
        if l.wrphase_futex.swap(1, Ordering::Relaxed) & FUTEX_USED != 0 {
            futex_wake(&l.wrphase_futex, i32::MAX, private);
        }
    }
    if r & RWAITING != rnew & RWAITING {
        futex_wake(&l.readers, i32::MAX, private);
    }
}

fn is_timeout(e: c_int) -> bool {
    e == ETIMEDOUT || e == EOVERFLOW
}

fn rdlock_full(l: &RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    if !abs.is_null() && ((clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) || !valid_nsec(unsafe { &*abs })) {
        return EINVAL;
    }
    if l.cur_writer.load(Ordering::Relaxed) == tid() {
        return EDEADLK;
    }
    let private = private_of(l);
    let mut r;
    if l.flags == PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP {
        r = l.readers.load(Ordering::Relaxed);
        while r & WRPHASE == 0 && r & WRLOCKED != 0 && r >> READER_SHIFT > 0 {
            if l.readers.compare_exchange_weak(r, r | RWAITING, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                loop {
                    r = l.readers.load(Ordering::Relaxed);
                    if r & RWAITING == 0 {
                        break;
                    }
                    let err = futex_wait_abs(&l.readers, r, clock, abs, private);
                    if is_timeout(err) {
                        return err;
                    }
                }
            } else {
                r = l.readers.load(Ordering::Relaxed);
            }
        }
    }
    r = l.readers.fetch_add(1 << READER_SHIFT, Ordering::Acquire).wrapping_add(1 << READER_SHIFT);
    while r >= READER_OVERFLOW {
        match l.readers.compare_exchange_weak(r, r - (1 << READER_SHIFT), Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return EAGAIN,
            Err(x) => r = x,
        }
    }
    if r & WRPHASE == 0 {
        return 0;
    }
    while r & WRPHASE != 0 && r & WRLOCKED == 0 {
        match l.readers.compare_exchange_weak(r, r ^ WRPHASE, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                if l.wrphase_futex.swap(0, Ordering::Relaxed) & FUTEX_USED != 0 {
                    futex_wake(&l.wrphase_futex, i32::MAX, private);
                }
                return 0;
            }
            Err(x) => r = x,
        }
    }
    let mut ready = false;
    loop {
        loop {
            let mut wpf = l.wrphase_futex.load(Ordering::Relaxed);
            if wpf | FUTEX_USED != 1 | FUTEX_USED {
                break;
            }
            if wpf & FUTEX_USED == 0 {
                match l.wrphase_futex.compare_exchange_weak(wpf, wpf | FUTEX_USED, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => wpf |= FUTEX_USED,
                    Err(_) => continue,
                }
            }
            let _ = wpf;
            let err = futex_wait_abs(&l.wrphase_futex, 1 | FUTEX_USED, clock, abs, private);
            if is_timeout(err) {
                let mut r = l.readers.load(Ordering::Relaxed);
                while r & WRPHASE != 0 {
                    match l.readers.compare_exchange_weak(r, r - (1 << READER_SHIFT), Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => return err,
                        Err(x) => r = x,
                    }
                }
                fence(Ordering::Acquire);
                while l.wrphase_futex.load(Ordering::Relaxed) | FUTEX_USED == 1 | FUTEX_USED {
                    core::hint::spin_loop();
                }
                ready = true;
                break;
            }
        }
        if ready {
            break;
        }
        if l.readers.load(Ordering::Acquire) & WRPHASE == 0 {
            ready = true;
        }
    }
    0
}

fn wrunlock(l: &RwLock) {
    let private = private_of(l);
    l.cur_writer.store(0, Ordering::Relaxed);
    let wake_writers = l.writers_futex.swap(0, Ordering::Relaxed) & FUTEX_USED != 0;
    'done: {
        if l.flags != PTHREAD_RWLOCK_PREFER_READER_NP {
            let mut w = l.writers.load(Ordering::Relaxed);
            while w != 0 {
                match l.writers.compare_exchange_weak(w, w | WRHANDOVER, Ordering::Release, Ordering::Relaxed) {
                    Ok(_) => break 'done,
                    Err(x) => w = x,
                }
            }
        }
        let mut r = l.readers.load(Ordering::Relaxed);
        loop {
            let new = (r ^ WRLOCKED) ^ (if r >> READER_SHIFT == 0 { 0 } else { WRPHASE });
            match l.readers.compare_exchange_weak(r, new, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => break,
                Err(x) => r = x,
            }
        }
        if r >> READER_SHIFT != 0 && l.wrphase_futex.swap(0, Ordering::Relaxed) & FUTEX_USED != 0 {
            futex_wake(&l.wrphase_futex, i32::MAX, private);
        }
    }
    if wake_writers {
        futex_wake(&l.writers_futex, 1, private);
    }
}

fn wrlock_full(l: &RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    if !abs.is_null() && ((clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) || !valid_nsec(unsafe { &*abs })) {
        return EINVAL;
    }
    if l.cur_writer.load(Ordering::Relaxed) == tid() {
        return EDEADLK;
    }
    let private = private_of(l);
    let mut may_share_futex_used_flag = false;
    let mut r = l.readers.fetch_or(WRLOCKED, Ordering::Acquire);
    if r & WRLOCKED != 0 {
        let prefer_writer = l.flags != PTHREAD_RWLOCK_PREFER_READER_NP;
        if prefer_writer {
            l.writers.fetch_add(1, Ordering::Relaxed);
        }
        loop {
            if r & WRLOCKED == 0 {
                match l.readers.compare_exchange_weak(r, r | WRLOCKED, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => {
                        if prefer_writer {
                            l.writers.fetch_sub(1, Ordering::Relaxed);
                        }
                        break;
                    }
                    Err(x) => {
                        r = x;
                        continue;
                    }
                }
            }
            if prefer_writer {
                let w = l.writers.load(Ordering::Relaxed);
                if w & WRHANDOVER != 0 {
                    if l.writers.compare_exchange_weak(w, w - WRHANDOVER - 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                        r = l.readers.load(Ordering::Relaxed);
                        break;
                    }
                    continue;
                }
            }
            let wf = l.writers_futex.load(Ordering::Relaxed);
            if (wf & !FUTEX_USED) != 1 || (wf != (1 | FUTEX_USED) && l.writers_futex.compare_exchange_weak(wf, 1 | FUTEX_USED, Ordering::Relaxed, Ordering::Relaxed).is_err()) {
                r = l.readers.load(Ordering::Relaxed);
                continue;
            }
            may_share_futex_used_flag = true;
            let err = futex_wait_abs(&l.writers_futex, 1 | FUTEX_USED, clock, abs, private);
            if is_timeout(err) {
                if prefer_writer {
                    let mut w = l.writers.load(Ordering::Relaxed);
                    loop {
                        let nw = if w == WRHANDOVER + 1 { 0 } else { w - 1 };
                        match l.writers.compare_exchange_weak(w, nw, Ordering::Acquire, Ordering::Relaxed) {
                            Ok(_) => break,
                            Err(x) => w = x,
                        }
                    }
                    if w == WRHANDOVER + 1 {
                        r = l.readers.load(Ordering::Relaxed);
                        break;
                    }
                }
                return err;
            }
            r = l.readers.load(Ordering::Relaxed);
        }
        r |= WRLOCKED;
    }
    l.writers_futex.store(1 | if may_share_futex_used_flag { FUTEX_USED } else { 0 }, Ordering::Relaxed);
    'done: {
        if r & WRPHASE != 0 {
            break 'done;
        }
        while r & WRPHASE == 0 && r >> READER_SHIFT == 0 {
            match l.readers.compare_exchange_weak(r, r | WRPHASE, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => {
                    l.wrphase_futex.store(1, Ordering::Relaxed);
                    break 'done;
                }
                Err(x) => r = x,
            }
        }
        let mut ready = false;
        loop {
            loop {
                let mut wpf = l.wrphase_futex.load(Ordering::Relaxed);
                if wpf | FUTEX_USED != FUTEX_USED {
                    break;
                }
                if wpf & FUTEX_USED == 0 {
                    match l.wrphase_futex.compare_exchange_weak(wpf, FUTEX_USED, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => wpf = FUTEX_USED,
                        Err(_) => continue,
                    }
                }
                let _ = wpf;
                let err = futex_wait_abs(&l.wrphase_futex, FUTEX_USED, clock, abs, private);
                if is_timeout(err) {
                    if l.flags != PTHREAD_RWLOCK_PREFER_READER_NP {
                        let mut w = l.writers.load(Ordering::Relaxed);
                        if w != 0 {
                            let wf = l.writers_futex.swap(0, Ordering::Relaxed);
                            while w != 0 {
                                match l.writers.compare_exchange_weak(w, w | WRHANDOVER, Ordering::Release, Ordering::Relaxed) {
                                    Ok(_) => {
                                        if wf & FUTEX_USED != 0 {
                                            futex_wake(&l.writers_futex, 1, private);
                                        }
                                        return err;
                                    }
                                    Err(x) => w = x,
                                }
                            }
                            l.writers_futex.store(wf, Ordering::Relaxed);
                        }
                    }
                    let mut r = l.readers.load(Ordering::Relaxed);
                    if r & WRPHASE == 0 {
                        let wf = l.writers_futex.swap(0, Ordering::Relaxed);
                        while r & WRPHASE == 0 {
                            match l.readers.compare_exchange_weak(r, (r ^ WRLOCKED) & !RWAITING, Ordering::Release, Ordering::Relaxed) {
                                Ok(_) => {
                                    if wf & FUTEX_USED != 0 {
                                        futex_wake(&l.writers_futex, 1, private);
                                    }
                                    if r & RWAITING != 0 {
                                        futex_wake(&l.readers, i32::MAX, private);
                                    }
                                    return ETIMEDOUT;
                                }
                                Err(x) => r = x,
                            }
                        }
                        l.writers_futex.store(wf, Ordering::Relaxed);
                    }
                    fence(Ordering::Acquire);
                    while l.wrphase_futex.load(Ordering::Relaxed) | FUTEX_USED == FUTEX_USED {
                        core::hint::spin_loop();
                    }
                    ready = true;
                    break;
                }
            }
            if ready {
                break;
            }
            if l.readers.load(Ordering::Acquire) & WRPHASE != 0 {
                ready = true;
            }
        }
    }
    l.cur_writer.store(tid(), Ordering::Relaxed);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_init(l: *mut RwLock, attr: *const RwLockAttr) -> c_int {
    unsafe {
        core::ptr::write_bytes(l as *mut u8, 0, core::mem::size_of::<RwLock>());
        let (kind, pshared) = if attr.is_null() { (0, 0) } else { ((*attr).lockkind, (*attr).pshared) };
        (*l).flags = kind as u32;
        (*l).shared = (pshared != 0) as u32;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_destroy(_l: *mut RwLock) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_rdlock(l: *mut RwLock) -> c_int {
    rdlock_full(unsafe { &*l }, 0, core::ptr::null())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(l: *mut RwLock, abs: *const Timespec) -> c_int {
    rdlock_full(unsafe { &*l }, CLOCK_REALTIME, abs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockrdlock(l: *mut RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    rdlock_full(unsafe { &*l }, clock, abs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_wrlock(l: *mut RwLock) -> c_int {
    wrlock_full(unsafe { &*l }, 0, core::ptr::null())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(l: *mut RwLock, abs: *const Timespec) -> c_int {
    wrlock_full(unsafe { &*l }, CLOCK_REALTIME, abs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockwrlock(l: *mut RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    wrlock_full(unsafe { &*l }, clock, abs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(l: *mut RwLock) -> c_int {
    let l = unsafe { &*l };
    let mut r = l.readers.load(Ordering::Relaxed);
    let mut rnew;
    loop {
        if r & WRPHASE == 0 {
            if r & WRLOCKED != 0 && l.flags == PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP {
                return EBUSY;
            }
            rnew = r.wrapping_add(1 << READER_SHIFT);
        } else {
            if r & WRLOCKED != 0 {
                return EBUSY;
            }
            rnew = r.wrapping_add(1 << READER_SHIFT) ^ WRPHASE;
        }
        if rnew >= READER_OVERFLOW {
            return EAGAIN;
        }
        match l.readers.compare_exchange_weak(r, rnew, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => r = x,
        }
    }
    if r & WRPHASE != 0 && l.wrphase_futex.swap(0, Ordering::Relaxed) & FUTEX_USED != 0 {
        futex_wake(&l.wrphase_futex, i32::MAX, private_of(l));
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(l: *mut RwLock) -> c_int {
    let l = unsafe { &*l };
    let mut r = l.readers.load(Ordering::Relaxed);
    let prefer_writer = l.flags != PTHREAD_RWLOCK_PREFER_READER_NP;
    while r & WRLOCKED == 0 && (r >> READER_SHIFT == 0 || (prefer_writer && r & WRPHASE != 0)) {
        match l.readers.compare_exchange_weak(r, r | WRPHASE | WRLOCKED, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                l.writers_futex.store(1, Ordering::Relaxed);
                if r & WRPHASE == 0 {
                    l.wrphase_futex.store(1, Ordering::Relaxed);
                }
                l.cur_writer.store(tid(), Ordering::Relaxed);
                return 0;
            }
            Err(x) => r = x,
        }
    }
    EBUSY
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_unlock(l: *mut RwLock) -> c_int {
    let l = unsafe { &*l };
    if l.cur_writer.load(Ordering::Relaxed) == tid() {
        wrunlock(l);
    } else {
        rdunlock(l);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_init(a: *mut RwLockAttr) -> c_int {
    unsafe {
        (*a).lockkind = 0;
        (*a).pshared = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(_a: *mut RwLockAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(a: *const RwLockAttr, p: *mut c_int) -> c_int {
    unsafe {
        *p = (*a).pshared;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(a: *mut RwLockAttr, p: c_int) -> c_int {
    unsafe {
        if p != 0 && p != 1 {
            return EINVAL;
        }
        (*a).pshared = p;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getkind_np(a: *const RwLockAttr, k: *mut c_int) -> c_int {
    unsafe {
        *k = (*a).lockkind;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setkind_np(a: *mut RwLockAttr, k: c_int) -> c_int {
    unsafe {
        if k as u32 > PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP {
            return EINVAL;
        }
        (*a).lockkind = k;
        0
    }
}

