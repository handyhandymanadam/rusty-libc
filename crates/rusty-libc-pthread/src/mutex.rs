use crate::sys::*;
use crate::thread::RobustHead;
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use rusty_libc_core::syscall::syscall4;

pub const PTHREAD_MUTEX_TIMED_NP: i32 = 0;
pub const PTHREAD_MUTEX_RECURSIVE_NP: i32 = 1;
pub const PTHREAD_MUTEX_ERRORCHECK_NP: i32 = 2;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: i32 = 3;
const KIND_MASK: i32 = 3;
const ROBUST: i32 = 16;
const PRIO_INHERIT: i32 = 32;
const PRIO_PROTECT: i32 = 64;
const PSHARED_BIT: i32 = 128;
const PRIO_CEILING_SHIFT: u32 = 19;
const PRIO_CEILING_MASK: u32 = 0xfff8_0000;

pub const MUTEX_INCONSISTENT: i32 = i32::MAX;
pub const MUTEX_NOTRECOVERABLE: i32 = i32::MAX - 1;

const ATTR_PROTOCOL_SHIFT: u32 = 28;
const ATTR_PROTOCOL_MASK: i32 = 0x3000_0000;
const ATTR_PRIO_CEILING_SHIFT: u32 = 12;
const ATTR_PRIO_CEILING_MASK: i32 = 0x00ff_f000;
const ATTR_ROBUST: i32 = 0x4000_0000;
const ATTR_PSHARED: i32 = i32::MIN;
const ATTR_FLAG_BITS: i32 = ATTR_ROBUST | ATTR_PSHARED | ATTR_PROTOCOL_MASK | ATTR_PRIO_CEILING_MASK;

#[repr(C)]
pub struct Mutex {
    pub lock: AtomicU32,
    pub count: u32,
    pub owner: i32,
    pub nusers: u32,
    pub kind: i32,
    pub spins: i16,
    pub unused: i16,
    pub list_prev: *mut u8,
    pub list_next: *mut u8,
}

const _: () = assert!(core::mem::size_of::<Mutex>() == 40);
const _: () = assert!(core::mem::offset_of!(Mutex, kind) == 16);
const _: () = assert!(core::mem::offset_of!(Mutex, list_next) == 32);

#[repr(C)]
pub struct MutexAttr {
    pub kind: i32,
}

#[inline(always)]
fn private_of(kind: i32) -> bool {
    kind & (PSHARED_BIT | ROBUST) == 0
}

#[inline]
fn lll_trylock(f: &AtomicU32) -> bool {
    f.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}

#[inline(always)]
fn lll_trylock_p(f: &AtomicU32, private: bool) -> bool {
    if private && !rusty_libc_core::lock::multithreaded() {
        return unsafe { rusty_libc_core::lock::take01_single_thread(f) };
    }
    lll_trylock(f)
}

#[inline]
fn lll_lock(f: &AtomicU32, private: bool) {
    if !lll_trylock_p(f, private) {
        lll_lock_wait(f, private);
    }
}

#[cold]
fn lll_lock_wait(f: &AtomicU32, private: bool) {
    if f.load(Ordering::Relaxed) != 2 {
        if f.swap(2, Ordering::Acquire) == 0 {
            return;
        }
    }
    loop {
        futex_wait(f, 2, private);
        if f.swap(2, Ordering::Acquire) == 0 {
            return;
        }
    }
}

#[inline]
fn lll_unlock(f: &AtomicU32, private: bool) {
    let old = if private && !rusty_libc_core::lock::multithreaded() {
        unsafe { rusty_libc_core::lock::release_single_thread(f) }
    } else {
        f.swap(0, Ordering::Release)
    };
    if old > 1 {
        futex_wake(f, 1, private);
    }
}

fn lll_clocklock_wait(f: &AtomicU32, clock: c_int, abs: &Timespec, private: bool) -> c_int {
    if !valid_nsec(abs) {
        return EINVAL;
    }
    while f.swap(2, Ordering::Acquire) != 0 {
        let e = futex_wait_abs(f, 2, clock, Some(abs), private);
        if e == ETIMEDOUT || e == EINVAL || e == EOVERFLOW {
            return e;
        }
    }
    0
}

fn robust_head() -> *mut RobustHead {
    crate::thread::field_of!(crate::thread::current_thread(), tcb.robust: RobustHead)
}

const QUEUE_PTR_ADJUST: usize = 8;

macro_rules! field {
    ($m:expr, $f:ident: $t:ty) => {
        ($m).cast::<u8>().wrapping_add(core::mem::offset_of!(Mutex, $f)).cast::<$t>()
    };
}

macro_rules! head_field {
    ($h:expr, $f:ident) => {
        ($h).cast::<u8>().wrapping_add(core::mem::offset_of!(RobustHead, $f)).cast::<*mut u8>()
    };
}

fn entry_prev(entry: *mut u8) -> *mut *mut u8 {
    ((entry as usize & !1) - QUEUE_PTR_ADJUST) as *mut *mut u8
}

unsafe fn enqueue(m: *mut Mutex, head: *mut RobustHead, pi: usize) {
    let list = head_field!(head, list);
    let first = unsafe { *list };
    unsafe { *entry_prev(first) = field!(m, list_prev: u8) };
    unsafe { *field!(m, list_next: *mut u8) = first };
    unsafe { *field!(m, list_prev: *mut u8) = head as *mut u8 };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { *list = (field!(m, list_next: u8) as usize | pi) as *mut u8 };
}

unsafe fn dequeue(m: *mut Mutex) {
    let next = unsafe { *field!(m, list_next: *mut u8) };
    let prev = unsafe { *field!(m, list_prev: *mut u8) };
    unsafe { *entry_prev(next) = prev };
    unsafe { *entry_prev(prev).wrapping_add(1) = next };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { *field!(m, list_prev: *mut u8) = core::ptr::null_mut() };
    unsafe { *field!(m, list_next: *mut u8) = core::ptr::null_mut() };
}

#[inline]
unsafe fn set_pending(head: *mut RobustHead, m: *mut Mutex, pi: usize) {
    unsafe { *head_field!(head, list_op_pending) = (field!(m, list_next: u8) as usize | pi) as *mut u8 };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn clear_pending(head: *mut RobustHead) {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe { *head_field!(head, list_op_pending) = core::ptr::null_mut() };
}

#[inline(always)]
unsafe fn lockw<'a>(m: *mut Mutex) -> &'a AtomicU32 {
    unsafe { &*field!(m, lock: AtomicU32) }
}

#[inline(always)]
unsafe fn kind_of(m: *const Mutex) -> i32 {
    unsafe { (*field!(m, kind: AtomicI32)).load(Ordering::Relaxed) }
}

fn max_spin() -> i32 {
    100
}

#[derive(Clone, Copy)]
pub struct Wait<'a> {
    pub clock: c_int,
    pub abs: Option<&'a Timespec>,
}

impl Wait<'static> {
    pub const NONE: Wait<'static> = Wait { clock: CLOCK_REALTIME, abs: None };
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe fn mutex_lock_common(m: *mut Mutex, w: Wait<'_>) -> c_int {
    unsafe {
        let kind = kind_of(m);
        let id = gettid();
        let timed = w.abs.is_some();
        if kind & !(KIND_MASK | PSHARED_BIT) == 0 {
            let private = private_of(kind);
            let ty = kind & KIND_MASK;
            match ty {
                PTHREAD_MUTEX_RECURSIVE_NP => {
                    if (*m).owner == id {
                        if (*m).count.wrapping_add(1) == 0 {
                            return EAGAIN;
                        }
                        (*m).count += 1;
                        return 0;
                    }
                }
                PTHREAD_MUTEX_ERRORCHECK_NP => {
                    if (*m).owner == id {
                        return EDEADLK;
                    }
                }
                _ => {}
            }
            if ty == PTHREAD_MUTEX_ADAPTIVE_NP && !timed {
                if !lll_trylock_p(lockw(m), private) {
                    let mut spins = 0;
                    let max = max_spin().min((*m).spins as i32 * 2 + 10);
                    loop {
                        if spins >= max {
                            lll_lock(lockw(m), private);
                            break;
                        }
                        core::hint::spin_loop();
                        spins += 1;
                        if lockw(m).load(Ordering::Relaxed) == 0 && lll_trylock(lockw(m)) {
                            break;
                        }
                    }
                    (*m).spins += ((spins - (*m).spins as i32) / 8) as i16;
                }
            } else if let Some(abs) = w.abs {
                if !lll_trylock_p(lockw(m), private) {
                    let r = lll_clocklock_wait(lockw(m), w.clock, abs, private);
                    if r != 0 {
                        return r;
                    }
                }
            } else {
                lll_lock(lockw(m), private);
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                (*m).count = 1;
            }
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
        }
        lock_full(m, w, id, kind)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn lock_full(m: *mut Mutex, w: Wait<'_>, id: i32, kind: i32) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let timed = w.abs.is_some();
        let known = kind & !(KIND_MASK | ROBUST | PRIO_INHERIT | PRIO_PROTECT | PSHARED_BIT) == 0;
        if !known || (kind & PRIO_INHERIT != 0 && kind & PRIO_PROTECT != 0) {
            return EINVAL;
        }
        let private = private_of(kind);
        let robust = kind & ROBUST != 0;
        if kind & PRIO_INHERIT != 0 {
            return lock_pi(m, w, id, kind);
        }
        if kind & PRIO_PROTECT != 0 {
            if robust {
                return EINVAL;
            }
            return lock_pp(m, w, id, kind, false);
        }
        if !robust {
            return EINVAL;
        }
        let head = robust_head();
        set_pending(head, m, 0);
        let f = lockw(m);
        let mut oldval = f.load(Ordering::Relaxed);
        let mut assume_waiters = 0u32;
        loop {
            if oldval == 0 {
                match f.compare_exchange(0, id as u32 | assume_waiters, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(x) => oldval = x,
                }
                if oldval == 0 {
                    continue;
                }
            }
            if oldval & FUTEX_OWNER_DIED != 0 {
                let newval = id as u32 | (oldval & FUTEX_WAITERS) | assume_waiters;
                match f.compare_exchange(oldval, newval, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => {}
                    Err(x) => {
                        oldval = x;
                        continue;
                    }
                }
                (*m).count = 1;
                (*m).owner = MUTEX_INCONSISTENT;
                enqueue(m, head, 0);
                clear_pending(head);
                return EOWNERDEAD;
            }
            if oldval & FUTEX_TID_MASK == id as u32 {
                if ty == PTHREAD_MUTEX_ERRORCHECK_NP {
                    clear_pending(head);
                    return EDEADLK;
                }
                if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                    clear_pending(head);
                    if (*m).count.wrapping_add(1) == 0 {
                        return EAGAIN;
                    }
                    (*m).count += 1;
                    return 0;
                }
            }
            if oldval & FUTEX_WAITERS == 0 {
                match f.compare_exchange(oldval, oldval | FUTEX_WAITERS, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => oldval |= FUTEX_WAITERS,
                    Err(x) => {
                        oldval = x;
                        continue;
                    }
                }
            }
            assume_waiters |= FUTEX_WAITERS;
            let e = if timed { futex_wait_abs(f, oldval, w.clock, w.abs, private) } else { futex_wait(f, oldval, private) };
            if timed && (e == ETIMEDOUT || e == EINVAL || e == EOVERFLOW) {
                clear_pending(head);
                return e;
            }
            oldval = f.load(Ordering::Relaxed);
        }
        if (*m).owner == MUTEX_NOTRECOVERABLE {
            (*m).count = 0;
            lll_robust_unlock(f, private);
            clear_pending(head);
            return ENOTRECOVERABLE;
        }
        (*m).count = 1;
        enqueue(m, head, 0);
        clear_pending(head);
        (*m).owner = id;
        (*m).nusers += 1;
        0
    }
}

#[inline]
fn lll_robust_unlock(f: &AtomicU32, private: bool) {
    if f.swap(0, Ordering::Release) & FUTEX_WAITERS != 0 {
        futex_wake(f, 1, private);
    }
}

fn futex_lock_pi(f: &AtomicU32, w: Wait<'_>, private: bool) -> c_int {
    loop {
        let e = match w.abs {
            None => errno_of(unsafe { syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, FUTEX_LOCK_PI | pflag(private), 0, 0) }),
            Some(abs) => {
                if !valid_nsec(abs) || (w.clock != CLOCK_REALTIME && w.clock != CLOCK_MONOTONIC) {
                    return EINVAL;
                }
                let mut op = FUTEX_LOCK_PI2 | pflag(private);
                if w.clock == CLOCK_REALTIME {
                    op |= FUTEX_CLOCK_REALTIME;
                }
                errno_of(unsafe { syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, op, 0, abs as *const Timespec as usize) })
            }
        };
        if e != EINTR && e != EAGAIN {
            return e;
        }
    }
}

#[inline]
fn pflag(private: bool) -> usize {
    if private { FUTEX_PRIVATE_FLAG } else { 0 }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn lock_pi(m: *mut Mutex, w: Wait<'_>, id: i32, kind: i32) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let robust = kind & ROBUST != 0;
        let private = private_of(kind);
        let head = if robust { robust_head() } else { core::ptr::null_mut() };
        if robust {
            set_pending(head, m, 1);
        }
        let f = lockw(m);
        let mut oldval = f.load(Ordering::Relaxed);
        if oldval & FUTEX_TID_MASK == id as u32 {
            if ty == PTHREAD_MUTEX_ERRORCHECK_NP {
                if robust {
                    clear_pending(head);
                }
                return EDEADLK;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                if robust {
                    clear_pending(head);
                }
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
        }
        match f.compare_exchange(0, id as u32, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {}
            Err(x) => {
                oldval = x;
                let _ = oldval;
                let e = futex_lock_pi(f, w, private);
                if e == ESRCH || e == EDEADLK {
                    let z = AtomicU32::new(0);
                    if w.abs.is_none() {
                        loop {
                            futex_wait(&z, 0, private);
                        }
                    }
                    loop {
                        let r = crate::sys::futex_wait_abs(&z, 0, w.clock, w.abs, private);
                        if r == ETIMEDOUT || r == EINVAL {
                            if robust {
                                clear_pending(head);
                            }
                            return r;
                        }
                    }
                }
                if e != 0 {
                    if robust {
                        clear_pending(head);
                    }
                    return e;
                }
                oldval = f.load(Ordering::Relaxed);
            }
        }
        if oldval & FUTEX_OWNER_DIED != 0 {
            f.fetch_and(!FUTEX_OWNER_DIED, Ordering::Acquire);
            (*m).count = 1;
            (*m).owner = MUTEX_INCONSISTENT;
            enqueue(m, head, 1);
            clear_pending(head);
            return EOWNERDEAD;
        }
        if robust && (*m).owner == MUTEX_NOTRECOVERABLE {
            (*m).count = 0;
            futex_unlock_pi(f, private);
            clear_pending(head);
            return ENOTRECOVERABLE;
        }
        (*m).count = 1;
        if robust {
            enqueue(m, head, 1);
            clear_pending(head);
        }
        (*m).owner = id;
        (*m).nusers += 1;
        0
    }
}

fn futex_unlock_pi(f: &AtomicU32, private: bool) {
    unsafe { syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, FUTEX_UNLOCK_PI | pflag(private), 0, 0) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut Mutex) -> c_int {
    unsafe {
        let kind = kind_of(m);
        if kind == PTHREAD_MUTEX_TIMED_NP {
            lll_lock(lockw(m), true);
            (*m).owner = gettid();
            (*m).nusers += 1;
            return 0;
        }
        if kind == PTHREAD_MUTEX_RECURSIVE_NP {
            let id = gettid();
            if (*m).owner == id {
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
            lll_lock(lockw(m), true);
            (*m).count = 1;
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
        }
        mutex_lock_common(m, Wait::NONE)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_timedlock(m: *mut Mutex, abstime: *const Timespec) -> c_int {
    let abs = unsafe { abstime.as_ref() };
    unsafe { mutex_lock_common(m, Wait { clock: CLOCK_REALTIME, abs }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_clocklock(m: *mut Mutex, clockid: c_int, abstime: *const Timespec) -> c_int {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }
    let abs = unsafe { abstime.as_ref() };
    unsafe { mutex_lock_common(m, Wait { clock: clockid, abs }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe extern "C" fn pthread_mutex_trylock(m: *mut Mutex) -> c_int {
    unsafe {
        let kind = kind_of(m);
        let id = gettid();
        let ty = kind & KIND_MASK;
        if kind & !(KIND_MASK | PSHARED_BIT) == 0 {
            match ty {
                PTHREAD_MUTEX_RECURSIVE_NP => {
                    if (*m).owner == id {
                        if (*m).count.wrapping_add(1) == 0 {
                            return EAGAIN;
                        }
                        (*m).count += 1;
                        return 0;
                    }
                    if lll_trylock_p(lockw(m), private_of(kind)) {
                        (*m).owner = id;
                        (*m).nusers += 1;
                        (*m).count = 1;
                        return 0;
                    }
                    return EBUSY;
                }
                _ => {
                    if lll_trylock_p(lockw(m), private_of(kind)) {
                        (*m).owner = id;
                        (*m).nusers += 1;
                        return 0;
                    }
                    return EBUSY;
                }
            }
        }
        trylock_full(m, id, kind)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn trylock_full(m: *mut Mutex, id: i32, kind: i32) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let known = kind & !(KIND_MASK | ROBUST | PRIO_INHERIT | PRIO_PROTECT | PSHARED_BIT) == 0;
        if !known || (kind & PRIO_INHERIT != 0 && kind & PRIO_PROTECT != 0) {
            return EINVAL;
        }
        let private = private_of(kind);
        let robust = kind & ROBUST != 0;
        let f = lockw(m);
        if kind & PRIO_INHERIT != 0 {
            let head = if robust { robust_head() } else { core::ptr::null_mut() };
            if robust {
                set_pending(head, m, 1);
            }
            let mut oldval = f.load(Ordering::Relaxed);
            if oldval & FUTEX_TID_MASK == id as u32 {
                if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                    if robust {
                        clear_pending(head);
                    }
                    if (*m).count.wrapping_add(1) == 0 {
                        return EAGAIN;
                    }
                    (*m).count += 1;
                    return 0;
                }
                if robust {
                    clear_pending(head);
                }
                return if ty == PTHREAD_MUTEX_ERRORCHECK_NP { EDEADLK } else { EBUSY };
            }
            match f.compare_exchange(0, id as u32, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => {}
                Err(_) => {
                    let e = errno_of(syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, FUTEX_TRYLOCK_PI | pflag(private), 0, 0));
                    if e != 0 {
                        if robust {
                            clear_pending(head);
                        }
                        return if e == EAGAIN { EBUSY } else { e };
                    }
                }
            }
            oldval = f.load(Ordering::Relaxed);
            if oldval & FUTEX_OWNER_DIED != 0 {
                f.fetch_and(!FUTEX_OWNER_DIED, Ordering::Acquire);
                (*m).count = 1;
                (*m).owner = MUTEX_INCONSISTENT;
                enqueue(m, head, 1);
                clear_pending(head);
                return EOWNERDEAD;
            }
            if robust && (*m).owner == MUTEX_NOTRECOVERABLE {
                (*m).count = 0;
                futex_unlock_pi(f, private);
                clear_pending(head);
                return ENOTRECOVERABLE;
            }
            (*m).count = 1;
            if robust {
                enqueue(m, head, 1);
                clear_pending(head);
            }
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
        }
        if kind & PRIO_PROTECT != 0 {
            if robust {
                return EINVAL;
            }
            return trylock_pp(m, id, ty);
        }
        if !robust {
            return EINVAL;
        }
        let head = robust_head();
        set_pending(head, m, 0);
        let mut oldval = f.load(Ordering::Relaxed);
        if oldval == 0 {
            match f.compare_exchange(0, id as u32, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => oldval = 0,
                Err(x) => oldval = x,
            }
        } else {
        }
        let acquired = oldval == 0 && (f.load(Ordering::Relaxed) & FUTEX_TID_MASK) == id as u32;
        if acquired {
            if (*m).owner == MUTEX_NOTRECOVERABLE {
                (*m).count = 0;
                lll_robust_unlock(f, private);
                clear_pending(head);
                return ENOTRECOVERABLE;
            }
            (*m).count = 1;
            enqueue(m, head, 0);
            clear_pending(head);
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
        }
        if oldval & FUTEX_OWNER_DIED != 0 {
            let newval = id as u32 | (oldval & FUTEX_WAITERS);
            if f.compare_exchange(oldval, newval, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                (*m).count = 1;
                (*m).owner = MUTEX_INCONSISTENT;
                enqueue(m, head, 0);
                clear_pending(head);
                return EOWNERDEAD;
            }
            clear_pending(head);
            return EBUSY;
        }
        if oldval & FUTEX_TID_MASK == id as u32 && ty == PTHREAD_MUTEX_RECURSIVE_NP {
            clear_pending(head);
            if (*m).count.wrapping_add(1) == 0 {
                return EAGAIN;
            }
            (*m).count += 1;
            return 0;
        }
        clear_pending(head);
        EBUSY
    }
}

#[inline]
fn cas_val(f: &AtomicU32, expected: u32, new: u32) -> u32 {
    match f.compare_exchange(expected, new, Ordering::Acquire, Ordering::Relaxed) {
        Ok(v) | Err(v) => v,
    }
}

#[inline]
fn ceiling_of(word: u32) -> c_int {
    ((word & PRIO_CEILING_MASK) >> PRIO_CEILING_SHIFT) as c_int
}

#[cold]
#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn lock_pp(m: *mut Mutex, w: Wait<'_>, id: i32, kind: i32, cond: bool) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let private = private_of(kind);
        let f = lockw(m);
        let mut oldval = f.load(Ordering::Relaxed);
        if (*m).owner == id {
            if ty == PTHREAD_MUTEX_ERRORCHECK_NP {
                return EDEADLK;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
        }
        let mut oldprio = -1;
        loop {
            let ceiling = ceiling_of(oldval);
            if crate::tpp::current_priority() > ceiling {
                if oldprio != -1 {
                    crate::tpp::change_priority(oldprio, -1);
                }
                return EINVAL;
            }
            let r = crate::tpp::change_priority(oldprio, ceiling);
            if r != 0 {
                return r;
            }
            let ceilval = (ceiling as u32) << PRIO_CEILING_SHIFT;
            oldprio = ceiling;
            oldval = cas_val(f, ceilval, ceilval | if cond { 2 } else { 1 });
            if oldval == ceilval {
                break;
            }
            loop {
                oldval = cas_val(f, ceilval | 1, ceilval | 2);
                if oldval & PRIO_CEILING_MASK != ceilval {
                    break;
                }
                if oldval != ceilval {
                    match w.abs {
                        None => {
                            futex_wait(f, ceilval | 2, private);
                        }
                        Some(abs) => {
                            if !valid_nsec(abs) {
                                crate::tpp::change_priority(oldprio, -1);
                                return EINVAL;
                            }
                            let e = futex_wait_abs(f, ceilval | 2, w.clock, Some(abs), private);
                            if e == ETIMEDOUT || e == EOVERFLOW {
                                return e;
                            }
                        }
                    }
                }
                if cas_val(f, ceilval, ceilval | 2) == ceilval {
                    break;
                }
            }
            if oldval & PRIO_CEILING_MASK == ceilval {
                break;
            }
        }
        (*m).count = 1;
        (*m).owner = id;
        if !cond {
            (*m).nusers += 1;
        }
        0
    }
}

#[cold]
#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn trylock_pp(m: *mut Mutex, id: i32, ty: i32) -> c_int {
    unsafe {
        let f = lockw(m);
        let mut oldval = f.load(Ordering::Relaxed);
        if (*m).owner == id {
            if ty == PTHREAD_MUTEX_ERRORCHECK_NP {
                return EDEADLK;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
        }
        let mut oldprio = -1;
        let mut ceilval;
        loop {
            let ceiling = ceiling_of(oldval);
            if crate::tpp::current_priority() > ceiling {
                if oldprio != -1 {
                    crate::tpp::change_priority(oldprio, -1);
                }
                return EINVAL;
            }
            let r = crate::tpp::change_priority(oldprio, ceiling);
            if r != 0 {
                return r;
            }
            ceilval = (ceiling as u32) << PRIO_CEILING_SHIFT;
            oldprio = ceiling;
            oldval = cas_val(f, ceilval, ceilval | 1);
            if oldval == ceilval || oldval & PRIO_CEILING_MASK == ceilval {
                break;
            }
        }
        if oldval != ceilval {
            crate::tpp::change_priority(oldprio, -1);
            return EBUSY;
        }
        (*m).owner = id;
        (*m).nusers += 1;
        (*m).count = 1;
        0
    }
}

#[cold]
#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn unlock_pp(m: *mut Mutex, decr: bool, id: i32, ty: i32, private: bool) -> c_int {
    unsafe {
        let f = lockw(m);
        if ty == PTHREAD_MUTEX_RECURSIVE_NP {
            if (*m).owner != id {
                return EPERM;
            }
            (*m).count -= 1;
            if (*m).count != 0 {
                return 0;
            }
        } else if ty == PTHREAD_MUTEX_ERRORCHECK_NP && ((*m).owner != id || f.load(Ordering::Relaxed) & !PRIO_CEILING_MASK == 0) {
            return EPERM;
        }
        (*m).owner = 0;
        if decr {
            (*m).nusers = (*m).nusers.wrapping_sub(1);
        }
        let mut oldval = f.load(Ordering::Relaxed);
        let mut newval;
        loop {
            newval = oldval & PRIO_CEILING_MASK;
            match f.compare_exchange_weak(oldval, newval, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => break,
                Err(v) => oldval = v,
            }
        }
        if oldval & !PRIO_CEILING_MASK > 1 {
            futex_wake(f, 1, private);
        }
        crate::tpp::change_priority((newval >> PRIO_CEILING_SHIFT) as c_int, -1)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe fn mutex_unlock_usercnt(m: *mut Mutex, decr: bool) -> c_int {
    unsafe {
        let kind = kind_of(m);
        let id = gettid();
        if kind & !(KIND_MASK | PSHARED_BIT) == 0 {
            let ty = kind & KIND_MASK;
            match ty {
                PTHREAD_MUTEX_RECURSIVE_NP => {
                    if (*m).owner != id {
                        return EPERM;
                    }
                    (*m).count -= 1;
                    if (*m).count != 0 {
                        return 0;
                    }
                }
                PTHREAD_MUTEX_ERRORCHECK_NP => {
                    if (*m).owner != id || lockw(m).load(Ordering::Relaxed) == 0 {
                        return EPERM;
                    }
                }
                _ => {}
            }
            (*m).owner = 0;
            if decr {
                (*m).nusers = (*m).nusers.wrapping_sub(1);
            }
            lll_unlock(lockw(m), private_of(kind));
            return 0;
        }
        unlock_full(m, decr, id, kind)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe fn unlock_full(m: *mut Mutex, decr: bool, id: i32, kind: i32) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let known = kind & !(KIND_MASK | ROBUST | PRIO_INHERIT | PRIO_PROTECT | PSHARED_BIT) == 0;
        if !known || (kind & PRIO_INHERIT != 0 && kind & PRIO_PROTECT != 0) {
            return EINVAL;
        }
        let private = private_of(kind);
        let robust = kind & ROBUST != 0;
        let f = lockw(m);
        if kind & PRIO_PROTECT != 0 {
            if robust {
                return EINVAL;
            }
            return unlock_pp(m, decr, id, ty, private);
        }
        if kind & PRIO_INHERIT != 0 {
            let held = if robust {
                lockw(m).load(Ordering::Relaxed) & FUTEX_TID_MASK == id as u32 && (*m).owner != 0
            } else {
                (*m).owner == id
            };
            if !held {
                return EPERM;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                (*m).count -= 1;
                if (*m).count != 0 {
                    return 0;
                }
            }
            let mut newowner = 0;
            if robust && (*m).owner == MUTEX_INCONSISTENT {
                newowner = MUTEX_NOTRECOVERABLE;
            }
            if robust {
            }
            let head = if robust { robust_head() } else { core::ptr::null_mut() };
            if robust {
                set_pending(head, m, 1);
                dequeue(m);
            }
            (*m).owner = newowner;
            if decr {
                (*m).nusers = (*m).nusers.wrapping_sub(1);
            }
            if f.load(Ordering::Relaxed) & FUTEX_WAITERS != 0 || f.compare_exchange(id as u32, 0, Ordering::Release, Ordering::Relaxed).is_err() {
                futex_unlock_pi(f, private);
            }
            if robust {
                clear_pending(head);
            }
            return 0;
        }
        if robust {
            let l = f.load(Ordering::Relaxed);
            if l & FUTEX_TID_MASK != id as u32 || l == 0 {
                return EPERM;
            }
            if (*m).owner == MUTEX_INCONSISTENT {
                (*m).owner = MUTEX_NOTRECOVERABLE;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                (*m).count -= 1;
                if (*m).count != 0 {
                    return 0;
                }
            }
            if (*m).owner != MUTEX_NOTRECOVERABLE {
                (*m).owner = 0;
            }
            if decr {
                (*m).nusers = (*m).nusers.wrapping_sub(1);
            }
            let head = robust_head();
            set_pending(head, m, 0);
            dequeue(m);
            lll_robust_unlock(f, private);
            clear_pending(head);
            return 0;
        }
        EINVAL
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut Mutex) -> c_int {
    unsafe {
        let kind = kind_of(m);
        if kind == PTHREAD_MUTEX_TIMED_NP {
            (*m).owner = 0;
            (*m).nusers = (*m).nusers.wrapping_sub(1);
            lll_unlock(lockw(m), true);
            return 0;
        }
        if kind == PTHREAD_MUTEX_RECURSIVE_NP {
            if (*m).owner != gettid() {
                return EPERM;
            }
            (*m).count -= 1;
            if (*m).count != 0 {
                return 0;
            }
            (*m).owner = 0;
            (*m).nusers = (*m).nusers.wrapping_sub(1);
            lll_unlock(lockw(m), true);
            return 0;
        }
        mutex_unlock_usercnt(m, true)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe fn mutex_cond_lock(m: *mut Mutex) -> c_int {
    unsafe {
        let kind = kind_of(m);
        if kind & PRIO_PROTECT != 0 && kind & !(KIND_MASK | PRIO_PROTECT | PSHARED_BIT) == 0 {
            return lock_pp(m, Wait::NONE, gettid(), kind, true);
        }
        let r = mutex_lock_common(m, Wait::NONE);
        if r == 0 {
            (*m).nusers = (*m).nusers.wrapping_sub(1);
        }
        r
    }
}

impl MutexAttr {
    fn mutex_words(&self) -> Result<(i32, u32), c_int> {
        let ak = self.kind;
        let protocol = (ak & ATTR_PROTOCOL_MASK) >> ATTR_PROTOCOL_SHIFT;
        if protocol >= 2 && ak & ATTR_ROBUST != 0 {
            return Err(ENOTSUP);
        }
        let mut kind = ak & !ATTR_FLAG_BITS;
        let mut lock = 0u32;
        match protocol {
            1 => kind |= PRIO_INHERIT,
            2 => {
                kind |= PRIO_PROTECT;
                let mut ceiling = (ak & ATTR_PRIO_CEILING_MASK) >> ATTR_PRIO_CEILING_SHIFT;
                if ceiling == 0 {
                    ceiling = ceiling.max(crate::tpp::fifo_min());
                }
                lock = (ceiling as u32) << PRIO_CEILING_SHIFT;
            }
            _ => {}
        }
        if ak & ATTR_ROBUST != 0 {
            kind |= ROBUST;
        }
        if ak & (ATTR_PSHARED | ATTR_ROBUST) != 0 {
            kind |= PSHARED_BIT;
        }
        Ok((kind, lock))
    }

    pub fn kind_type(&self) -> c_int {
        self.kind & !ATTR_FLAG_BITS
    }

    pub fn set_type(&mut self, kind: c_int) -> c_int {
        if !(PTHREAD_MUTEX_TIMED_NP..=PTHREAD_MUTEX_ADAPTIVE_NP).contains(&kind) {
            return EINVAL;
        }
        self.kind = (self.kind & ATTR_FLAG_BITS) | kind;
        0
    }

    pub fn pshared(&self) -> c_int {
        (self.kind & ATTR_PSHARED != 0) as c_int
    }

    pub fn set_pshared(&mut self, pshared: c_int) -> c_int {
        match pshared {
            0 => self.kind &= !ATTR_PSHARED,
            1 => self.kind |= ATTR_PSHARED,
            _ => return EINVAL,
        }
        0
    }

    pub fn robust(&self) -> c_int {
        (self.kind & ATTR_ROBUST != 0) as c_int
    }

    pub fn set_robust(&mut self, robust: c_int) -> c_int {
        match robust {
            0 => self.kind &= !ATTR_ROBUST,
            1 => self.kind |= ATTR_ROBUST,
            _ => return EINVAL,
        }
        0
    }

    pub fn protocol(&self) -> c_int {
        (self.kind & ATTR_PROTOCOL_MASK) >> ATTR_PROTOCOL_SHIFT
    }

    pub fn set_protocol(&mut self, protocol: c_int) -> c_int {
        if !(0..=2).contains(&protocol) {
            return EINVAL;
        }
        self.kind = (self.kind & !ATTR_PROTOCOL_MASK) | (protocol << ATTR_PROTOCOL_SHIFT);
        0
    }

    pub fn prioceiling(&self) -> c_int {
        let c = (self.kind & ATTR_PRIO_CEILING_MASK) >> ATTR_PRIO_CEILING_SHIFT;
        if c == 0 { c.max(crate::tpp::fifo_min()) } else { c }
    }

    pub fn set_prioceiling(&mut self, ceiling: c_int) -> c_int {
        let (min, max) = crate::tpp::fifo_range();
        if ceiling < min || ceiling > max || ceiling & (ATTR_PRIO_CEILING_MASK >> ATTR_PRIO_CEILING_SHIFT) != ceiling {
            return EINVAL;
        }
        self.kind = (self.kind & !ATTR_PRIO_CEILING_MASK) | (ceiling << ATTR_PRIO_CEILING_SHIFT);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut Mutex, attr: *const MutexAttr) -> c_int {
    let (kind, lock) = match unsafe { attr.as_ref() } {
        None => (0, 0),
        Some(a) => match a.mutex_words() {
            Ok(w) => w,
            Err(e) => return e,
        },
    };
    let new = Mutex { lock: AtomicU32::new(lock), count: 0, owner: 0, nusers: 0, kind, spins: 0, unused: 0, list_prev: core::ptr::null_mut(), list_next: core::ptr::null_mut() };
    unsafe { core::ptr::write(m, new) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(m: *mut Mutex) -> c_int {
    let kind = unsafe { *field!(m, kind: i32) };
    if kind & ROBUST == 0 && unsafe { *field!(m, nusers: u32) } != 0 {
        return EBUSY;
    }
    unsafe { *field!(m, kind: i32) = -1 };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent(m: *mut Mutex) -> c_int {
    let kind = unsafe { *field!(m, kind: i32) };
    if kind & ROBUST == 0 {
        return EINVAL;
    }
    if unsafe { *field!(m, owner: i32) } != MUTEX_INCONSISTENT {
        return EINVAL;
    }
    unsafe { *field!(m, owner: i32) = gettid() };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(m: *const Mutex, ceiling: *mut c_int) -> c_int {
    let kind = unsafe { *field!(m, kind: i32) };
    if kind & PRIO_PROTECT == 0 {
        return EINVAL;
    }
    let word = unsafe { &*field!(m, lock: AtomicU32) }.load(Ordering::Relaxed);
    unsafe { *ceiling = ((word & PRIO_CEILING_MASK) >> PRIO_CEILING_SHIFT) as c_int };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(clippy::multiple_unsafe_ops_per_block)]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(m: *mut Mutex, ceiling: c_int, old: *mut c_int) -> c_int {
    unsafe {
        let kind = kind_of(m);
        if kind & PRIO_PROTECT == 0 {
            return EINVAL;
        }
        let (min, max) = crate::tpp::fifo_range();
        if ceiling < min || ceiling > max || ceiling & (ATTR_PRIO_CEILING_MASK >> ATTR_PRIO_CEILING_SHIFT) != ceiling {
            return EINVAL;
        }
        let ty = kind & 127;
        let mut locked = false;
        if (*m).owner == gettid() {
            if ty == PRIO_PROTECT | PTHREAD_MUTEX_ERRORCHECK_NP {
                return EDEADLK;
            }
            if ty == PRIO_PROTECT | PTHREAD_MUTEX_RECURSIVE_NP {
                locked = true;
            }
        }
        let f = lockw(m);
        let mut oldval = f.load(Ordering::Relaxed);
        if !locked {
            let ceilval = oldval & PRIO_CEILING_MASK;
            oldval = cas_val(f, ceilval, ceilval | 1);
            if oldval != ceilval {
                loop {
                    oldval = cas_val(f, ceilval | 1, ceilval | 2);
                    if oldval & PRIO_CEILING_MASK != ceilval {
                        break;
                    }
                    if oldval != ceilval {
                        futex_wait(f, ceilval | 2, private_of(kind));
                    }
                    if cas_val(f, ceilval, ceilval | 2) == ceilval {
                        break;
                    }
                }
            }
        }
        let oldprio = ceiling_of(oldval);
        if locked {
            let r = crate::tpp::change_priority(oldprio, ceiling);
            if r != 0 {
                return r;
            }
        }
        if !old.is_null() {
            *old = oldprio;
        }
        let newlock = if locked { f.load(Ordering::Relaxed) & !PRIO_CEILING_MASK } else { 0 };
        f.store(newlock | ((ceiling as u32) << PRIO_CEILING_SHIFT), Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::SeqCst);
        futex_wake(f, i32::MAX, private_of(kind));
        0
    }
}

macro_rules! attr_mut {
    ($p:expr) => {{
        unsafe { arg_mut($p) }
    }};
}
macro_rules! attr_ref {
    ($p:expr) => {{
        unsafe { arg($p) }
    }};
}
macro_rules! out {
    ($p:expr) => {{
        unsafe { arg_mut($p) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(a: *mut MutexAttr) -> c_int {
    unsafe { core::ptr::write(a, MutexAttr { kind: 0 }) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_a: *mut MutexAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const MutexAttr, kind: *mut c_int) -> c_int {
    *out!(kind) = attr_ref!(a).kind_type();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut MutexAttr, kind: c_int) -> c_int {
    attr_mut!(a).set_type(kind)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getkind_np(a: *const MutexAttr, kind: *mut c_int) -> c_int {
    *out!(kind) = attr_ref!(a).kind_type();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setkind_np(a: *mut MutexAttr, kind: c_int) -> c_int {
    attr_mut!(a).set_type(kind)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pthread_kill_other_threads_np() {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(a: *const MutexAttr, pshared: *mut c_int) -> c_int {
    *out!(pshared) = attr_ref!(a).pshared();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(a: *mut MutexAttr, pshared: c_int) -> c_int {
    attr_mut!(a).set_pshared(pshared)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent_np(m: *mut Mutex) -> c_int {
    unsafe { pthread_mutex_consistent(m) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust_np(a: *const MutexAttr, robust: *mut c_int) -> c_int {
    *out!(robust) = attr_ref!(a).robust();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust_np(a: *mut MutexAttr, robust: c_int) -> c_int {
    attr_mut!(a).set_robust(robust)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(a: *const MutexAttr, robust: *mut c_int) -> c_int {
    *out!(robust) = attr_ref!(a).robust();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(a: *mut MutexAttr, robust: c_int) -> c_int {
    attr_mut!(a).set_robust(robust)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprotocol(a: *const MutexAttr, protocol: *mut c_int) -> c_int {
    *out!(protocol) = attr_ref!(a).protocol();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprotocol(a: *mut MutexAttr, protocol: c_int) -> c_int {
    attr_mut!(a).set_protocol(protocol)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprioceiling(a: *const MutexAttr, ceiling: *mut c_int) -> c_int {
    let c = attr_ref!(a).prioceiling();
    *out!(ceiling) = c;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprioceiling(a: *mut MutexAttr, ceiling: c_int) -> c_int {
    attr_mut!(a).set_prioceiling(ceiling)
}

