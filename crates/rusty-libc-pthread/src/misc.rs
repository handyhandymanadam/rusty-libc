use crate::cancel::INTERNAL_SIGNALS;
use crate::sys::*;
use crate::thread::{Thread, current_thread, tid_word, with_sched_locked};
use core::ffi::{CStr, c_char, c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_core::syscall::{syscall3, syscall4};

unsafe fn tid_of(th: PthreadT) -> i32 {
    let t = th as *mut Thread;
    if t == current_thread() { gettid() } else { unsafe { tid_word(t) }.load(Ordering::Relaxed) }
}

fn is_internal(sig: c_int) -> bool {
    sig == crate::cancel::SIGCANCEL || sig == crate::cancel::SIGSETXID
}

pub fn kill_tid(is_self: bool, tid: i32, sig: c_int) -> c_int {
    if !is_self {
        if tid == 0 {
            return 0;
        }
        if tid < 0 {
            return ESRCH;
        }
    }
    let r = tgkill(getpid(), tid, sig);
    if r == ESRCH && !is_self { 0 } else { r }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_kill(th: PthreadT, sig: c_int) -> c_int {
    if is_internal(sig) {
        return EINVAL;
    }
    let tid = unsafe { tid_of(th) };
    kill_tid(th as *mut Thread == current_thread(), tid, sig)
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

pub fn sigqueue_tid(is_self: bool, tid: i32, sig: c_int, value: usize) -> c_int {
    if tid <= 0 && !is_self {
        return ESRCH;
    }
    let info = SigInfo {
        si_signo: sig,
        si_errno: 0,
        si_code: -1,
        pad0: 0,
        si_pid: getpid(),
        si_uid: rusty_libc_core::unistd::getuid() as c_int,
        si_value: value,
        rest: [0; 12],
    };
    errno_of(unsafe { syscall4(SYS_RT_TGSIGQUEUEINFO, getpid() as usize, tid as usize, sig as usize, &info as *const SigInfo as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigqueue(th: PthreadT, sig: c_int, value: usize) -> c_int {
    if is_internal(sig) {
        return EINVAL;
    }
    let tid = unsafe { tid_of(th) };
    sigqueue_tid(th as *mut Thread == current_thread(), tid, sig, value)
}

pub fn sigmask(how: c_int, set: Option<&SigsetT>, old: Option<&mut SigsetT>) -> c_int {
    let new = set.map(|s| s.val[0] & !INTERNAL_SIGNALS);
    let setp = new.as_ref().map_or(0, |n| n as *const u64 as usize);
    let mut oldmask = 0u64;
    let oldp = if old.is_none() { 0 } else { &mut oldmask as *mut u64 as usize };
    let r = unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how as usize, setp, oldp, 8) };
    let e = errno_of(r);
    if e != 0 {
        return e;
    }
    if let Some(o) = old {
        o.val[0] = oldmask & !INTERNAL_SIGNALS;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const SigsetT, old: *mut SigsetT) -> c_int {
    let set = unsafe { set.as_ref() };
    let old = unsafe { old.as_mut() };
    sigmask(how, set, old)
}

const TASK_COMM_LEN: usize = 16;

fn comm_path(tid: i32, buf: &mut [u8; 48]) -> &CStr {
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
    CStr::from_bytes_with_nul(&buf[..i + post.len()]).unwrap_or(c"")
}

fn open_comm(tid: i32, flags: usize) -> Result<usize, c_int> {
    let mut path = [0u8; 48];
    let path = comm_path(tid, &mut path);
    let fd = unsafe { rusty_libc_core::syscall::sys_open(path.as_ptr() as usize, flags | 0o2000000, 0) };
    match errno_of(fd) {
        0 => Ok(fd),
        ENOENT => Err(ESRCH),
        e => Err(e),
    }
}

fn close_fd(fd: usize) {
    let _ = rusty_libc_core::unistd::close(fd as i32);
}

pub fn setname(is_self: bool, tid: impl FnOnce() -> i32, name: &CStr) -> c_int {
    let len = name.to_bytes().len();
    if len > TASK_COMM_LEN - 1 {
        return ERANGE;
    }
    if is_self {
        return errno_of(unsafe { syscall3(SYS_PRCTL, 15 , name.as_ptr() as usize, 0) });
    }
    let fd = match open_comm(tid(), 1 ) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let w = rusty_libc_core::unistd::write_nocancel(fd as i32, name.to_bytes());
    close_fd(fd);
    match w {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setname_np(th: PthreadT, name: *const c_char) -> c_int {
    let name = unsafe { rusty_libc_core::ffi::cstr_nonnull(name) };
    setname(th as *mut Thread == current_thread(), || unsafe { tid_of(th) }, name)
}

pub fn getname(is_self: bool, tid: impl FnOnce() -> i32, buf: &mut [u8]) -> c_int {
    if buf.len() < TASK_COMM_LEN {
        return ERANGE;
    }
    if is_self {
        return errno_of(unsafe { syscall3(SYS_PRCTL, 16 , buf.as_mut_ptr() as usize, 0) });
    }
    let fd = match open_comm(tid(), 0) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let r = rusty_libc_core::unistd::read_nocancel(fd as i32, buf);
    close_fd(fd);
    let mut n = match r {
        Ok(n) => n,
        Err(e) => return e.0,
    };
    if n > 0 && buf[n - 1] == b'\n' {
        n -= 1;
    }
    if let Some(b) = buf.get_mut(n) {
        *b = 0;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getname_np(th: PthreadT, buf: *mut c_char, buflen: usize) -> c_int {
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    getname(th as *mut Thread == current_thread(), || unsafe { tid_of(th) }, out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedparam(th: PthreadT, policy: c_int, param: *const SchedParam) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let t = th as *mut Thread;
    let prio = unsafe { arg(param) }.sched_priority;
    let body = |sched: &mut crate::thread::Sched| {
        let p = SchedParam { sched_priority: unsafe { crate::tpp::boosted(t, prio) } };
        let r = crate::attr::sched_setscheduler(tid, policy, &p);
        if r == 0 {
            sched.policy = policy;
            sched.prio = prio;
            sched.flags |= crate::attr::ATTR_FLAG_SCHED_SET | crate::attr::ATTR_FLAG_POLICY_SET;
        }
        r
    };
    unsafe { with_sched_locked(t, body) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getschedparam(th: PthreadT, policy: *mut c_int, param: *mut SchedParam) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let got = unsafe { with_sched_locked(th as *mut Thread, |sched| if sched.fill(tid) != 0 { None } else { Some((sched.policy, sched.prio)) }) };
    match got {
        None => 1,
        Some((pol, prio)) => {
            unsafe { *policy = pol };
            unsafe { (*param).sched_priority = prio };
            0
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedprio(th: PthreadT, prio: c_int) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let t = th as *mut Thread;
    let body = |sched: &mut crate::thread::Sched| {
        let r = crate::attr::sched_setparam(tid, &SchedParam { sched_priority: unsafe { crate::tpp::boosted(t, prio) } });
        if r == 0 {
            sched.prio = prio;
            sched.flags |= crate::attr::ATTR_FLAG_SCHED_SET;
        }
        r
    };
    unsafe { with_sched_locked(t, body) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setaffinity_np(th: PthreadT, size: usize, set: *const CpuSet) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let mask = unsafe { rusty_libc_core::ffi::bytes(set.cast::<u8>(), size) };
    crate::attr::sched_setaffinity(tid, mask)
}

pub fn getaffinity(tid: i32, set: &mut [u8]) -> c_int {
    let r = crate::attr::sched_getaffinity(tid, set);
    if r < 0 {
        return (-r) as c_int;
    }
    set[r as usize..].fill(0);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getaffinity_np(th: PthreadT, size: usize, set: *mut CpuSet) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    getaffinity(tid, unsafe { rusty_libc_core::ffi::bytes_mut(set.cast::<u8>(), size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getcpuclockid(th: PthreadT, clockid: *mut c_int) -> c_int {
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    unsafe { *clockid = ((!(tid as c_int)) << 3) | 6 };
    0
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
