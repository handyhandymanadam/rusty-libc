use crate::cancel::INTERNAL_SIGNALS;
use crate::sys::*;
use crate::thread::{Thread, current_thread};
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_core::syscall::{syscall1, syscall2, syscall3, syscall4};

fn tid_of(t: PthreadT) -> i32 {
    let t = t as *mut Thread;
    if t == current_thread() { gettid() } else { unsafe { (*t).tcb.tid } }
}

fn is_internal(sig: c_int) -> bool {
    sig == crate::cancel::SIGCANCEL || sig == crate::cancel::SIGSETXID
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_kill(th: PthreadT, sig: c_int) -> c_int {
    if is_internal(sig) {
        return EINVAL;
    }
    let tid = tid_of(th);
    if th as *mut Thread != current_thread() {
        if tid == 0 {
            return 0;
        }
        if tid < 0 {
            return ESRCH;
        }
    }
    let r = tgkill(getpid(), tid, sig);
    if r == ESRCH && th as *mut Thread != current_thread() { 0 } else { r }
}

#[repr(C)]
struct SigInfo {
    si_signo: c_int,
    si_errno: c_int,
    si_code: c_int,
    pad0: c_int,
    si_pid: c_int,
    si_uid: c_int,
    si_value: usize,
    rest: [u64; 12],
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigqueue(th: PthreadT, sig: c_int, value: usize) -> c_int {
    unsafe {
        if is_internal(sig) {
            return EINVAL;
        }
        let tid = tid_of(th);
        if tid <= 0 && th as *mut Thread != current_thread() {
            return ESRCH;
        }
        let mut info: SigInfo = core::mem::zeroed();
        info.si_signo = sig;
        info.si_code = -1;
        info.si_pid = getpid();
        info.si_uid = syscall1(102, 0) as c_int;
        info.si_value = value;
        errno_of(syscall4(SYS_RT_TGSIGQUEUEINFO, getpid() as usize, tid as usize, sig as usize, &info as *const SigInfo as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const SigsetT, old: *mut SigsetT) -> c_int {
    unsafe {
        let new;
        let mut setp = 0;
        if !set.is_null() {
            new = (*set).val[0] & !INTERNAL_SIGNALS;
            setp = &new as *const u64 as usize;
        }
        let mut oldmask = 0u64;
        let r = syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how as usize, setp, if old.is_null() { 0 } else { &mut oldmask as *mut u64 as usize }, 8);
        let e = errno_of(r);
        if e != 0 {
            return e;
        }
        if !old.is_null() {
            (*old).val[0] = oldmask & !INTERNAL_SIGNALS;
        }
        0
    }
}

const TASK_COMM_LEN: usize = 16;

fn comm_path(tid: i32, buf: &mut [u8; 48]) -> usize {
    let pre = b"/proc/self/task/";
    buf[..pre.len()].copy_from_slice(pre);
    let mut i = pre.len();
    let mut digits = [0u8; 10];
    let mut k = 0;
    let mut v = tid as u32;
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        v /= 10;
        k += 1;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        buf[i] = digits[k];
        i += 1;
    }
    let post = b"/comm\0";
    buf[i..i + post.len()].copy_from_slice(post);
    i + post.len() - 1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setname_np(th: PthreadT, name: *const c_char) -> c_int {
    unsafe {
        let mut len = 0;
        while *name.add(len) != 0 {
            len += 1;
        }
        if len > TASK_COMM_LEN - 1 {
            return ERANGE;
        }
        let tid = tid_of(th);
        let mut path = [0u8; 48];
        comm_path(tid, &mut path);
        let fd = syscall3(rusty_libc_core::syscall::SYS_OPEN, path.as_ptr() as usize, 1  | 0o2000000, 0);
        let e = errno_of(fd);
        if e != 0 {
            return if e == ENOENT { ESRCH } else { e };
        }
        let w = syscall3(rusty_libc_core::syscall::SYS_WRITE, fd, name as usize, len);
        syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd);
        let e = errno_of(w);
        if e != 0 { e } else { 0 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getname_np(th: PthreadT, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        if buflen < TASK_COMM_LEN {
            return ERANGE;
        }
        let tid = tid_of(th);
        let mut path = [0u8; 48];
        comm_path(tid, &mut path);
        let fd = syscall3(rusty_libc_core::syscall::SYS_OPEN, path.as_ptr() as usize, 0o2000000, 0);
        let e = errno_of(fd);
        if e != 0 {
            return if e == ENOENT { ESRCH } else { e };
        }
        let r = syscall3(rusty_libc_core::syscall::SYS_READ, fd, buf as usize, buflen);
        syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd);
        let e = errno_of(r);
        if e != 0 {
            return e;
        }
        let mut n = r;
        if n > 0 && *buf.add(n - 1) as u8 == b'\n' {
            n -= 1;
        }
        *buf.add(n) = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedparam(th: PthreadT, policy: c_int, param: *const SchedParam) -> c_int {
    unsafe {
        let tid = tid_of(th);
        if tid <= 0 {
            return ESRCH;
        }
        crate::attr::sched_setscheduler(tid, policy, &*param)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getschedparam(th: PthreadT, policy: *mut c_int, param: *mut SchedParam) -> c_int {
    unsafe {
        let tid = tid_of(th);
        if tid <= 0 {
            return ESRCH;
        }
        let p = syscall1(SYS_SCHED_GETSCHEDULER, tid as usize);
        let e = errno_of(p);
        if e != 0 {
            return e;
        }
        let r = syscall2(SYS_SCHED_GETPARAM, tid as usize, param as usize);
        let e = errno_of(r);
        if e != 0 {
            return e;
        }
        *policy = p as c_int;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedprio(th: PthreadT, prio: c_int) -> c_int {
    let tid = tid_of(th);
    if tid <= 0 {
        return ESRCH;
    }
    crate::attr::sched_setparam(tid, &SchedParam { sched_priority: prio })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setaffinity_np(th: PthreadT, size: usize, set: *const CpuSet) -> c_int {
    let tid = tid_of(th);
    if tid <= 0 {
        return ESRCH;
    }
    crate::attr::sched_setaffinity(tid, size, set as *const u8)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getaffinity_np(th: PthreadT, size: usize, set: *mut CpuSet) -> c_int {
    unsafe {
        let tid = tid_of(th);
        if tid <= 0 {
            return ESRCH;
        }
        let r = crate::attr::sched_getaffinity(tid, size, set as *mut u8);
        if r < 0 {
            return (-r) as c_int;
        }
        core::ptr::write_bytes((set as *mut u8).add(r as usize), 0, size - r as usize);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getcpuclockid(th: PthreadT, clockid: *mut c_int) -> c_int {
    unsafe {
        let tid = tid_of(th);
        if tid <= 0 {
            return ESRCH;
        }
        *clockid = ((!(tid as c_int)) << 3) | 6;
        0
    }
}

static CONCURRENCY: AtomicI32 = AtomicI32::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setconcurrency(level: c_int) -> c_int {
    if level < 0 {
        return EINVAL;
    }
    CONCURRENCY.store(level, Ordering::Relaxed);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getconcurrency() -> c_int {
    CONCURRENCY.load(Ordering::Relaxed)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_yield() -> c_int {
    sched_yield();
    0
}

macro_rules! alias {
    ($($name:ident => $target:path : fn($($arg:ident : $ty:ty),*) -> $ret:ty;)*) => {
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
                unsafe { $target($($arg),*) }
            }
        )*
    };
}

alias! {
    __pthread_key_create => crate::key::pthread_key_create : fn(key: *mut u32, d: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    __pthread_mutex_lock => crate::mutex::pthread_mutex_lock : fn(m: *mut crate::mutex::Mutex) -> c_int;
    __pthread_mutex_unlock => crate::mutex::pthread_mutex_unlock : fn(m: *mut crate::mutex::Mutex) -> c_int;
    __pthread_mutex_trylock => crate::mutex::pthread_mutex_trylock : fn(m: *mut crate::mutex::Mutex) -> c_int;
    __pthread_mutex_init => crate::mutex::pthread_mutex_init : fn(m: *mut crate::mutex::Mutex, a: *const crate::mutex::MutexAttr) -> c_int;
    __pthread_mutex_destroy => crate::mutex::pthread_mutex_destroy : fn(m: *mut crate::mutex::Mutex) -> c_int;
    __pthread_once => crate::sync::pthread_once : fn(o: *mut c_int, f: unsafe extern "C" fn()) -> c_int;
    __pthread_getspecific => crate::key::pthread_getspecific : fn(k: u32) -> *mut c_void;
    __pthread_setspecific => crate::key::pthread_setspecific : fn(k: u32, v: *const c_void) -> c_int;
}
