use crate::sys::*;
use crate::thread::RobustHead;
use crate::thread::ensure_robust_registered;
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
const PRIO_CEILING_MASK: u32 = 0x7ff8_0000;

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

#[inline]
fn lll_lock(f: &AtomicU32, private: bool) {
    if !lll_trylock(f) {
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
    if f.swap(0, Ordering::Release) > 1 {
        futex_wake(f, 1, private);
    }
}

fn lll_clocklock_wait(f: &AtomicU32, clock: c_int, abs: *const Timespec, private: bool) -> c_int {
    if !valid_nsec(unsafe { &*abs }) {
        return EINVAL;
    }
    while f.swap(2, Ordering::Acquire) != 0 {
        let e = futex_wait_abs(f, 2, clock, abs, private);
        if e == ETIMEDOUT || e == EINVAL || e == EOVERFLOW {
            return e;
        }
    }
    0
}

fn robust_head() -> *mut RobustHead {
    unsafe {
        let t = crate::thread::current_thread();
        ensure_robust_registered(t);
        &raw mut (*t).robust
    }
}

const QUEUE_PTR_ADJUST: usize = 8;

unsafe fn enqueue(m: *mut Mutex, head: *mut RobustHead, pi: usize) {
    unsafe {
        let nextp = (((*head).list as usize & !1) - QUEUE_PTR_ADJUST) as *mut *mut u8;
        *nextp = &raw mut (*m).list_prev as *mut u8;
        (*m).list_next = (*head).list;
        (*m).list_prev = head as *mut u8;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        (*head).list = ((&raw mut (*m).list_next) as usize | pi) as *mut u8;
    }
}

unsafe fn dequeue(m: *mut Mutex) {
    unsafe {
        let next = (((*m).list_next as usize & !1) - QUEUE_PTR_ADJUST) as *mut *mut u8;
        *next = (*m).list_prev;
        let prev = (((*m).list_prev as usize & !1) - QUEUE_PTR_ADJUST) as *mut *mut u8;
        *prev.add(1) = (*m).list_next;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        (*m).list_prev = core::ptr::null_mut();
        (*m).list_next = core::ptr::null_mut();
    }
}

#[inline]
unsafe fn set_pending(head: *mut RobustHead, m: *mut Mutex, pi: usize) {
    unsafe {
        (*head).list_op_pending = ((&raw mut (*m).list_next) as usize | pi) as *mut u8;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

#[inline]
unsafe fn clear_pending(head: *mut RobustHead) {
    unsafe {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        (*head).list_op_pending = core::ptr::null_mut();
    }
}

#[inline(always)]
unsafe fn lockw<'a>(m: *mut Mutex) -> &'a AtomicU32 {
    unsafe { &(*m).lock }
}

#[inline(always)]
unsafe fn kind_of(m: *const Mutex) -> i32 {
    unsafe { (*(&raw const (*m).kind as *const AtomicI32)).load(Ordering::Relaxed) }
}

fn max_spin() -> i32 {
    100
}

#[derive(Clone, Copy)]
pub struct Wait {
    pub clock: c_int,
    pub abs: *const Timespec,
}

impl Wait {
    pub const NONE: Wait = Wait { clock: CLOCK_REALTIME, abs: core::ptr::null() };
}

pub unsafe fn mutex_lock_common(m: *mut Mutex, w: Wait) -> c_int {
    unsafe {
        let kind = kind_of(m);
        let id = gettid();
        let timed = !w.abs.is_null();
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
                if !lll_trylock(lockw(m)) {
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
            } else if timed {
                if !lll_trylock(lockw(m)) {
                    let r = lll_clocklock_wait(lockw(m), w.clock, w.abs, private);
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

unsafe fn lock_full(m: *mut Mutex, w: Wait, id: i32, kind: i32) -> c_int {
    unsafe {
        let ty = kind & KIND_MASK;
        let timed = !w.abs.is_null();
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
            let ceiling = ((lockw(m).load(Ordering::Relaxed) & PRIO_CEILING_MASK) >> PRIO_CEILING_SHIFT) as i32;
            let mut sp = SchedParam::default();
            rusty_libc_core::syscall::syscall2(SYS_SCHED_GETPARAM, 0, &mut sp as *mut SchedParam as usize);
            if sp.sched_priority > ceiling {
                return EINVAL;
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP && (*m).owner == id {
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
            if ty == PTHREAD_MUTEX_ERRORCHECK_NP && (*m).owner == id {
                return EDEADLK;
            }
            let f = lockw(m);
            loop {
                let old = f.load(Ordering::Relaxed);
                let cbits = old & PRIO_CEILING_MASK;
                let state = old & !(PRIO_CEILING_MASK);
                if state == 0 {
                    if f.compare_exchange(old, cbits | 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                        break;
                    }
                    continue;
                }
                if state != 2 && f.compare_exchange(old, cbits | 2, Ordering::Relaxed, Ordering::Relaxed).is_err() {
                    continue;
                }
                let e = if timed { futex_wait_abs(f, cbits | 2, w.clock, w.abs, private) } else { futex_wait(f, cbits | 2, private) };
                if e == ETIMEDOUT || (timed && (e == EINVAL || e == EOVERFLOW)) {
                    return e;
                }
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                (*m).count = 1;
            }
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
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

fn futex_lock_pi(f: &AtomicU32, w: Wait, private: bool) -> c_int {
    loop {
        let e = if w.abs.is_null() {
            errno_of(unsafe { syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, FUTEX_LOCK_PI | pflag(private), 0, 0) })
        } else {
            if !valid_nsec(unsafe { &*w.abs }) || (w.clock != CLOCK_REALTIME && w.clock != CLOCK_MONOTONIC) {
                return EINVAL;
            }
            let mut op = FUTEX_LOCK_PI2 | pflag(private);
            if w.clock == CLOCK_REALTIME {
                op |= FUTEX_CLOCK_REALTIME;
            }
            errno_of(unsafe { syscall4(SYS_FUTEX, f as *const AtomicU32 as usize, op, 0, w.abs as usize) })
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

unsafe fn lock_pi(m: *mut Mutex, w: Wait, id: i32, kind: i32) -> c_int {
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
                    if w.abs.is_null() {
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
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut Mutex) -> c_int {
    unsafe {
        if kind_of(m) == PTHREAD_MUTEX_TIMED_NP {
            lll_lock(lockw(m), true);
            (*m).owner = gettid();
            (*m).nusers += 1;
            return 0;
        }
        mutex_lock_common(m, Wait::NONE)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_timedlock(m: *mut Mutex, abstime: *const Timespec) -> c_int {
    unsafe { mutex_lock_common(m, Wait { clock: CLOCK_REALTIME, abs: abstime }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_clocklock(m: *mut Mutex, clockid: c_int, abstime: *const Timespec) -> c_int {
    unsafe {
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }
        mutex_lock_common(m, Wait { clock: clockid, abs: abstime })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
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
                    if lll_trylock(lockw(m)) {
                        (*m).owner = id;
                        (*m).nusers += 1;
                        (*m).count = 1;
                        return 0;
                    }
                    return EBUSY;
                }
                _ => {
                    if lll_trylock(lockw(m)) {
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
                return EBUSY;
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
            if ty == PTHREAD_MUTEX_RECURSIVE_NP && (*m).owner == id {
                if (*m).count.wrapping_add(1) == 0 {
                    return EAGAIN;
                }
                (*m).count += 1;
                return 0;
            }
            let old = f.load(Ordering::Relaxed);
            let cbits = old & PRIO_CEILING_MASK;
            if old & !PRIO_CEILING_MASK != 0 || f.compare_exchange(old, cbits | 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
                return EBUSY;
            }
            (*m).count = 1;
            (*m).owner = id;
            (*m).nusers += 1;
            return 0;
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
            if ty != PTHREAD_MUTEX_TIMED_NP && ty != PTHREAD_MUTEX_ADAPTIVE_NP && (*m).owner != id {
                return EPERM;
            }
            if ty == PTHREAD_MUTEX_TIMED_NP || ty == PTHREAD_MUTEX_ADAPTIVE_NP {
            }
            if ty == PTHREAD_MUTEX_RECURSIVE_NP {
                (*m).count -= 1;
                if (*m).count != 0 {
                    return 0;
                }
            }
            (*m).owner = 0;
            if decr {
                (*m).nusers = (*m).nusers.wrapping_sub(1);
            }
            let old = f.load(Ordering::Relaxed);
            let cbits = old & PRIO_CEILING_MASK;
            let prev = f.swap(cbits, Ordering::Release);
            if prev & !PRIO_CEILING_MASK == 2 {
                futex_wake(f, 1, private);
            }
            return 0;
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
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut Mutex) -> c_int {
    unsafe {
        if kind_of(m) == PTHREAD_MUTEX_TIMED_NP {
            (*m).owner = 0;
            (*m).nusers = (*m).nusers.wrapping_sub(1);
            lll_unlock(lockw(m), true);
            return 0;
        }
        mutex_unlock_usercnt(m, true)
    }
}

pub unsafe fn mutex_cond_lock(m: *mut Mutex) -> c_int {
    unsafe {
        let r = mutex_lock_common(m, Wait::NONE);
        if r == 0 {
            (*m).nusers = (*m).nusers.wrapping_sub(1);
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut Mutex, attr: *const MutexAttr) -> c_int {
    unsafe {
        let ak = if attr.is_null() { 0 } else { (*attr).kind };
        core::ptr::write_bytes(m as *mut u8, 0, core::mem::size_of::<Mutex>());
        let mut kind = ak & !ATTR_FLAG_BITS;
        let protocol = (ak & ATTR_PROTOCOL_MASK) >> ATTR_PROTOCOL_SHIFT;
        match protocol {
            0 => {}
            1 => kind |= PRIO_INHERIT,
            2 => {
                kind |= PRIO_PROTECT;
                let mut ceiling = ((ak & ATTR_PRIO_CEILING_MASK) >> ATTR_PRIO_CEILING_SHIFT) as u32;
                if ceiling == 0 {
                    ceiling = 1;
                }
                (*m).lock = AtomicU32::new(ceiling << PRIO_CEILING_SHIFT);
            }
            _ => return ENOTSUP,
        }
        if ak & ATTR_ROBUST != 0 {
            kind |= ROBUST;
        }
        if ak & ATTR_PSHARED != 0 {
            kind |= PSHARED_BIT;
        }
        (*m).kind = kind;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(m: *mut Mutex) -> c_int {
    unsafe {
        if (*m).kind & ROBUST == 0 && (*m).nusers != 0 {
            return EBUSY;
        }
        (*m).kind = -1;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent(m: *mut Mutex) -> c_int {
    unsafe {
        let kind = (*m).kind;
        if kind & ROBUST == 0 {
            return EINVAL;
        }
        if (*m).owner != MUTEX_INCONSISTENT {
            return EINVAL;
        }
        (*m).owner = gettid();
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(m: *const Mutex, ceiling: *mut c_int) -> c_int {
    unsafe {
        if (*m).kind & PRIO_PROTECT == 0 {
            return EINVAL;
        }
        *ceiling = ((((*m).lock.load(Ordering::Relaxed)) & PRIO_CEILING_MASK) >> PRIO_CEILING_SHIFT) as c_int;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(m: *mut Mutex, ceiling: c_int, old: *mut c_int) -> c_int {
    unsafe {
        if (*m).kind & PRIO_PROTECT == 0 {
            return EINVAL;
        }
        let min = rusty_libc_core::syscall::syscall1(147, 1) as c_int;
        let max = rusty_libc_core::syscall::syscall1(146, 1) as c_int;
        if ceiling < min || ceiling > max {
            return EINVAL;
        }
        let r = pthread_mutex_lock(m);
        if r != 0 {
            return r;
        }
        let f = &(*m).lock;
        let cur = f.load(Ordering::Relaxed);
        if !old.is_null() {
            *old = ((cur & PRIO_CEILING_MASK) >> PRIO_CEILING_SHIFT) as c_int;
        }
        f.store((cur & !PRIO_CEILING_MASK) | ((ceiling as u32) << PRIO_CEILING_SHIFT), Ordering::Relaxed);
        pthread_mutex_unlock(m)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(a: *mut MutexAttr) -> c_int {
    unsafe {
        (*a).kind = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_a: *mut MutexAttr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const MutexAttr, kind: *mut c_int) -> c_int {
    unsafe {
        *kind = (*a).kind & !ATTR_FLAG_BITS;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut MutexAttr, kind: c_int) -> c_int {
    unsafe {
        if !(PTHREAD_MUTEX_TIMED_NP..=PTHREAD_MUTEX_ADAPTIVE_NP).contains(&kind) {
            return EINVAL;
        }
        (*a).kind = ((*a).kind & ATTR_FLAG_BITS) | kind;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getkind_np(a: *const MutexAttr, kind: *mut c_int) -> c_int {
    unsafe { pthread_mutexattr_gettype(a, kind) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setkind_np(a: *mut MutexAttr, kind: c_int) -> c_int {
    unsafe { pthread_mutexattr_settype(a, kind) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pthread_kill_other_threads_np() {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(a: *const MutexAttr, pshared: *mut c_int) -> c_int {
    unsafe {
        *pshared = ((*a).kind & ATTR_PSHARED != 0) as c_int;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(a: *mut MutexAttr, pshared: c_int) -> c_int {
    unsafe {
        match pshared {
            0 => (*a).kind &= !ATTR_PSHARED,
            1 => (*a).kind |= ATTR_PSHARED,
            _ => return EINVAL,
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent_np(m: *mut Mutex) -> c_int {
    unsafe { pthread_mutex_consistent(m) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust_np(a: *const MutexAttr, robust: *mut c_int) -> c_int {
    unsafe { pthread_mutexattr_getrobust(a, robust) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust_np(a: *mut MutexAttr, robust: c_int) -> c_int {
    unsafe { pthread_mutexattr_setrobust(a, robust) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(a: *const MutexAttr, robust: *mut c_int) -> c_int {
    unsafe {
        *robust = ((*a).kind & ATTR_ROBUST != 0) as c_int;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(a: *mut MutexAttr, robust: c_int) -> c_int {
    unsafe {
        match robust {
            0 => (*a).kind &= !ATTR_ROBUST,
            1 => (*a).kind |= ATTR_ROBUST,
            _ => return EINVAL,
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprotocol(a: *const MutexAttr, protocol: *mut c_int) -> c_int {
    unsafe {
        *protocol = ((*a).kind & ATTR_PROTOCOL_MASK) >> ATTR_PROTOCOL_SHIFT;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprotocol(a: *mut MutexAttr, protocol: c_int) -> c_int {
    unsafe {
        if !(0..=2).contains(&protocol) {
            return EINVAL;
        }
        (*a).kind = ((*a).kind & !ATTR_PROTOCOL_MASK) | (protocol << ATTR_PROTOCOL_SHIFT);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprioceiling(a: *const MutexAttr, ceiling: *mut c_int) -> c_int {
    unsafe {
        let c = ((*a).kind & ATTR_PRIO_CEILING_MASK) >> ATTR_PRIO_CEILING_SHIFT;
        *ceiling = if c == 0 { rusty_libc_core::syscall::syscall1(147, 1) as c_int } else { c };
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprioceiling(a: *mut MutexAttr, ceiling: c_int) -> c_int {
    unsafe {
        let min = rusty_libc_core::syscall::syscall1(147, 1) as c_int;
        let max = rusty_libc_core::syscall::syscall1(146, 1) as c_int;
        if ceiling < min || ceiling > max {
            return EINVAL;
        }
        (*a).kind = ((*a).kind & !ATTR_PRIO_CEILING_MASK) | (ceiling << ATTR_PRIO_CEILING_SHIFT);
        0
    }
}

