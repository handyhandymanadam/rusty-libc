//! pthread_rwlock_t (56 bytes, glibc's x86-64 layout) and pthread_rwlockattr_t (8 bytes).
//!
//! The algorithm is glibc's (2.25 and later), ported to Rust (derived from glibc's
//! nptl/pthread_rwlock_*.c, LGPL-2.1; see LICENSES.md): a primary-writer bit, a write-phase bit and a
//! reader count in `readers`, explicit hand-over between read and write phases through the
//! `wrphase_futex`, writer-writer hand-over for the writer-preferring kinds, and the same
//! reader/writer preference kinds. Lock operations are not cancellation points.
//! Layout: readers 0, writers 4, wrphase_futex 8, writers_futex 12, cur_writer 24, shared 28,
//! flags 48.
//!
//! Safe core: every field the lock operations change is an atomic, so they work on `&RwLock`; the exported functions
//! convert the pointer (and the timeout) once. No unsafe is left but those conversions.
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

/// Read-lock `l`, waiting until `abs` on `clock` at most (None: no timeout). 0, EDEADLK, EAGAIN, EINVAL, ETIMEDOUT.
pub fn rdlock_full(l: &RwLock, clock: c_int, abs: Option<&Timespec>) -> c_int {
    if abs.is_some_and(|a| (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) || !valid_nsec(a)) {
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

/// Write-lock `l`, waiting until `abs` on `clock` at most (None: no timeout). 0, EDEADLK, EINVAL, ETIMEDOUT.
pub fn wrlock_full(l: &RwLock, clock: c_int, abs: Option<&Timespec>) -> c_int {
    if abs.is_some_and(|a| (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) || !valid_nsec(a)) {
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

impl RwLock {
    /// An unlocked rwlock of kind `flags` (process-shared when `shared`): what `pthread_rwlock_init` makes. All zero (kind 0,
    /// private) is the static initializer.
    pub const fn with_kind(flags: u32, shared: bool) -> RwLock {
        RwLock {
            readers: AtomicU32::new(0),
            writers: AtomicU32::new(0),
            wrphase_futex: AtomicU32::new(0),
            writers_futex: AtomicU32::new(0),
            pad3: 0,
            pad4: 0,
            cur_writer: AtomicU32::new(0),
            shared: shared as u32,
            pad1: 0,
            pad2: 0,
            flags,
            pad5: 0,
        }
    }
}

/// `pthread_rwlock_tryrdlock`: 0, EBUSY, EAGAIN.
#[inline(always)]
pub fn tryrdlock(l: &RwLock) -> c_int {
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

/// `pthread_rwlock_trywrlock`: 0 or EBUSY.
#[inline(always)]
pub fn trywrlock(l: &RwLock) -> c_int {
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

/// `pthread_rwlock_unlock` (inlined into the exported function, as its body was before).
#[inline(always)]
pub fn unlock(l: &RwLock) -> c_int {
    if l.cur_writer.load(Ordering::Relaxed) == tid() {
        wrunlock(l);
    } else {
        rdunlock(l);
    }
    0
}

/// The exported functions convert the rwlock pointer once: glibc uses it without a NULL check. Every field the lock
/// operations change is an atomic, so a shared reference is enough while other threads use the same lock.
macro_rules! lock_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_rwlock_t that stays valid for the call; the fields that change
        // while it is shared are atomics (`flags` and `shared` are written only by pthread_rwlock_init).
        unsafe { arg($p as *const RwLock) }
    }};
}

/// A timeout argument: NULL means none (glibc reads it only when it is not NULL).
macro_rules! timeout {
    ($p:expr) => {{
        // SAFETY: the C caller passes NULL or a valid struct timespec.
        unsafe { $p.as_ref() }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_init(l: *mut RwLock, attr: *const RwLockAttr) -> c_int {
    // SAFETY: `attr` is NULL or an initialised pthread_rwlockattr_t (C contract).
    let (kind, pshared) = match unsafe { attr.as_ref() } {
        None => (0, 0),
        Some(a) => (a.lockkind, a.pshared),
    };
    // SAFETY: `l` is writable memory for one pthread_rwlock_t that no other thread uses during the init (C contract).
    unsafe { core::ptr::write(l, RwLock::with_kind(kind as u32, pshared != 0)) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_destroy(_l: *mut RwLock) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_rdlock(l: *mut RwLock) -> c_int {
    rdlock_full(lock_ref!(l), 0, None)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(l: *mut RwLock, abs: *const Timespec) -> c_int {
    rdlock_full(lock_ref!(l), CLOCK_REALTIME, timeout!(abs))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockrdlock(l: *mut RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    rdlock_full(lock_ref!(l), clock, timeout!(abs))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_wrlock(l: *mut RwLock) -> c_int {
    wrlock_full(lock_ref!(l), 0, None)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(l: *mut RwLock, abs: *const Timespec) -> c_int {
    wrlock_full(lock_ref!(l), CLOCK_REALTIME, timeout!(abs))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockwrlock(l: *mut RwLock, clock: c_int, abs: *const Timespec) -> c_int {
    wrlock_full(lock_ref!(l), clock, timeout!(abs))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(l: *mut RwLock) -> c_int {
    tryrdlock(lock_ref!(l))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(l: *mut RwLock) -> c_int {
    trywrlock(lock_ref!(l))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_unlock(l: *mut RwLock) -> c_int {
    unlock(lock_ref!(l))
}

impl RwLockAttr {
    pub fn set_pshared(&mut self, p: c_int) -> c_int {
        if p != 0 && p != 1 {
            return EINVAL;
        }
        self.pshared = p;
        0
    }

    pub fn set_kind(&mut self, k: c_int) -> c_int {
        if k as u32 > PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP {
            return EINVAL;
        }
        self.lockkind = k;
        0
    }
}

macro_rules! attr_mut {
    ($p:expr) => {{
        // SAFETY: the C caller passes a valid pthread_rwlockattr_t that no other thread uses during the call.
        unsafe { arg_mut($p) }
    }};
}
macro_rules! attr_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised pthread_rwlockattr_t.
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
pub unsafe extern "C" fn pthread_rwlockattr_init(a: *mut RwLockAttr) -> c_int {
    // SAFETY: `a` is writable memory for one pthread_rwlockattr_t (C contract); the old contents are not read.
    unsafe { core::ptr::write(a, RwLockAttr { lockkind: 0, pshared: 0 }) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(_a: *mut RwLockAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(a: *const RwLockAttr, p: *mut c_int) -> c_int {
    *out!(p) = attr_ref!(a).pshared;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(a: *mut RwLockAttr, p: c_int) -> c_int {
    attr_mut!(a).set_pshared(p)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getkind_np(a: *const RwLockAttr, k: *mut c_int) -> c_int {
    *out!(k) = attr_ref!(a).lockkind;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setkind_np(a: *mut RwLockAttr, k: c_int) -> c_int {
    attr_mut!(a).set_kind(k)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use std::sync::Arc;

    struct S(core::cell::UnsafeCell<RwLock>, core::cell::UnsafeCell<u64>);
    unsafe impl Sync for S {}
    unsafe impl Send for S {}

    #[test]
    fn basic_states() {
        unsafe {
            let mut l: RwLock = core::mem::zeroed();
            pthread_rwlock_init(&mut l, core::ptr::null());
            assert_eq!(pthread_rwlock_rdlock(&mut l), 0);
            assert_eq!(pthread_rwlock_rdlock(&mut l), 0);
            assert_eq!(pthread_rwlock_trywrlock(&mut l), EBUSY);
            assert_eq!(pthread_rwlock_unlock(&mut l), 0);
            assert_eq!(pthread_rwlock_unlock(&mut l), 0);
            assert_eq!(pthread_rwlock_trywrlock(&mut l), 0);
            assert_eq!(pthread_rwlock_tryrdlock(&mut l), EBUSY);
            assert_eq!(pthread_rwlock_wrlock(&mut l), EDEADLK);
            assert_eq!(pthread_rwlock_rdlock(&mut l), EDEADLK);
            assert_eq!(pthread_rwlock_unlock(&mut l), 0);
        }
    }

    #[test]
    fn timed_errors_match_host() {
        unsafe {
            let mut l: RwLock = core::mem::zeroed();
            pthread_rwlock_init(&mut l, core::ptr::null());
            let mut h: libc::pthread_rwlock_t = core::mem::zeroed();
            libc::pthread_rwlock_init(&mut h, core::ptr::null());
            let bad = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
            let hbad = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
            assert_eq!(pthread_rwlock_timedrdlock(&mut l, &bad), host_timedrdlock(&mut h, &hbad));
            assert_eq!(pthread_rwlock_timedwrlock(&mut l, &bad), host_timedwrlock(&mut h, &hbad));
            assert_eq!(pthread_rwlock_clockrdlock(&mut l, 5, &bad), EINVAL);
            // write-locked: another thread times out
            assert_eq!(pthread_rwlock_wrlock(&mut l), 0);
            let lp = &mut l as *mut RwLock as usize;
            let r = std::thread::spawn(move || {
                let mut now = Timespec::default();
                clock_gettime(CLOCK_REALTIME, &mut now);
                timespec_add_ns(&mut now, 20_000_000);
                (pthread_rwlock_timedrdlock(lp as *mut RwLock, &now), pthread_rwlock_timedwrlock(lp as *mut RwLock, &now))
            })
            .join()
            .unwrap();
            assert_eq!(r, (ETIMEDOUT, ETIMEDOUT));
            assert_eq!(pthread_rwlock_unlock(&mut l), 0);
        }
    }

    unsafe extern "C" {
        #[link_name = "pthread_rwlock_timedrdlock"]
        fn host_timedrdlock(l: *mut libc::pthread_rwlock_t, t: *const libc::timespec) -> c_int;
        #[link_name = "pthread_rwlock_timedwrlock"]
        fn host_timedwrlock(l: *mut libc::pthread_rwlock_t, t: *const libc::timespec) -> c_int;
    }

    fn stress(kind: i32) {
        let s = Arc::new(S(core::cell::UnsafeCell::new(unsafe { core::mem::zeroed() }), core::cell::UnsafeCell::new(0)));
        let mut a = RwLockAttr { lockkind: 0, pshared: 0 };
        unsafe {
            pthread_rwlockattr_setkind_np(&mut a, kind);
            pthread_rwlock_init(s.0.get(), &a);
        }
        let mut hs = vec![];
        for t in 0..6 {
            let s = s.clone();
            hs.push(std::thread::spawn(move || unsafe {
                let mut seen = 0u64;
                for i in 0..5000 {
                    if (i + t) % 5 == 0 {
                        pthread_rwlock_wrlock(s.0.get());
                        let v = *s.1.get();
                        *s.1.get() = v + 1;
                        assert_eq!(*s.1.get(), v + 1);
                        pthread_rwlock_unlock(s.0.get());
                    } else {
                        pthread_rwlock_rdlock(s.0.get());
                        let v = *s.1.get();
                        assert!(v >= seen);
                        seen = v;
                        pthread_rwlock_unlock(s.0.get());
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        // each thread wrote 1000 times
        assert_eq!(unsafe { *s.1.get() }, 6000);
    }

    #[test]
    fn stress_prefer_reader() {
        stress(0);
    }
    #[test]
    fn stress_prefer_writer() {
        stress(2);
    }
}
