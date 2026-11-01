//! The smaller pthread functions: pthread_kill, sigqueue, sigmask, thread names, scheduling and CPU
//! affinity of a thread, the thread's CPU clock, concurrency level, yield.
//!
//! Safe core: the logic works on thread ids, slices, `&CStr` and the locked scheduling cache (`with_sched_locked`); the
//! exported functions convert their arguments once. Unsafe left: reading another thread's id from its descriptor
//! (`tid_of`), the system calls with pointer arguments, the boundary conversions.
use crate::cancel::INTERNAL_SIGNALS;
use crate::sys::*;
use crate::thread::{Thread, current_thread, tid_word, with_sched_locked};
use core::ffi::{CStr, c_char, c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_core::syscall::{syscall3, syscall4};

/// The kernel thread id of thread `th` (the calling thread's from its TCB).
///
/// # Safety
/// `th` is a thread handle of this process that was not reaped (C contract of the pthread functions).
unsafe fn tid_of(th: PthreadT) -> i32 {
    let t = th as *mut Thread;
    // SAFETY: forwarded contract.
    if t == current_thread() { gettid() } else { unsafe { tid_word(t) }.load(Ordering::Relaxed) }
}

fn is_internal(sig: c_int) -> bool {
    sig == crate::cancel::SIGCANCEL || sig == crate::cancel::SIGSETXID
}

/// `pthread_kill` for a thread whose id is `tid` (`is_self`: the caller).
pub fn kill_tid(is_self: bool, tid: i32, sig: c_int) -> c_int {
    if !is_self {
        if tid == 0 {
            // a thread that has ended but was not joined yet: not an error in glibc 2.34 and later (the thread handle is
            // still valid); the signal is simply not sent. (tst-pthread_kill-exiting)
            return 0;
        }
        if tid < 0 {
            return ESRCH;
        }
    }
    let r = tgkill(getpid(), tid, sig);
    // the thread ended between reading its tid and the kill: its handle was valid, so this is not an error (glibc 2.34+)
    if r == ESRCH && !is_self { 0 } else { r }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_kill(th: PthreadT, sig: c_int) -> c_int {
    if is_internal(sig) {
        return EINVAL;
    }
    // SAFETY: `th` is a live thread handle (C contract).
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

/// `pthread_sigqueue` to thread `tid` (`is_self`: the caller).
pub fn sigqueue_tid(is_self: bool, tid: i32, sig: c_int, value: usize) -> c_int {
    if tid <= 0 && !is_self {
        return ESRCH;
    }
    let info = SigInfo {
        si_signo: sig,
        si_errno: 0,
        si_code: -1, // SI_QUEUE
        pad0: 0,
        si_pid: getpid(),
        si_uid: rusty_libc_core::unistd::getuid() as c_int,
        si_value: value,
        rest: [0; 12],
    };
    // SAFETY: the kernel reads the borrowed siginfo (128 bytes, the size of SigInfo).
    errno_of(unsafe { syscall4(SYS_RT_TGSIGQUEUEINFO, getpid() as usize, tid as usize, sig as usize, &info as *const SigInfo as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigqueue(th: PthreadT, sig: c_int, value: usize) -> c_int {
    if is_internal(sig) {
        return EINVAL;
    }
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    sigqueue_tid(th as *mut Thread == current_thread(), tid, sig, value)
}

/// `pthread_sigmask` on the first 64 bits of glibc's 128-byte sigset_t. The signals the thread layer keeps for itself
/// (32 and 33) never show up in, or change, the mask.
pub fn sigmask(how: c_int, set: Option<&SigsetT>, old: Option<&mut SigsetT>) -> c_int {
    let new = set.map(|s| s.val[0] & !INTERNAL_SIGNALS);
    let setp = new.as_ref().map_or(0, |n| n as *const u64 as usize);
    let mut oldmask = 0u64;
    let oldp = if old.is_none() { 0 } else { &mut oldmask as *mut u64 as usize };
    // SAFETY: the kernel reads the borrowed new mask and writes the borrowed old one (8 bytes each), or takes NULL.
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

/// pthread_sigmask: `set` and `old` are glibc's 128-byte sigset_t; only the first 64 bits are used.
/// The signals the thread layer keeps for itself (32 and 33) never show up in, or change, the mask.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const SigsetT, old: *mut SigsetT) -> c_int {
    // SAFETY: `set` is NULL or a valid sigset_t (C contract).
    let set = unsafe { set.as_ref() };
    // SAFETY: `old` is NULL or a writable sigset_t (C contract).
    let old = unsafe { old.as_mut() };
    sigmask(how, set, old)
}

const TASK_COMM_LEN: usize = 16;

/// "/proc/self/task/TID/comm" with its NUL, in `buf`.
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
    // (digits and fixed text only before the one NUL)
    CStr::from_bytes_with_nul(&buf[..i + post.len()]).unwrap_or(c"")
}

/// Open thread `tid`'s comm file with `flags` (O_CLOEXEC added): the fd, or the errno (ENOENT reads as ESRCH, as glibc).
fn open_comm(tid: i32, flags: usize) -> Result<usize, c_int> {
    let mut path = [0u8; 48];
    let path = comm_path(tid, &mut path);
    // SAFETY: the kernel reads the borrowed NUL-terminated path.
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

/// `pthread_setname_np`: the caller's name with prctl, another thread's through /proc.
pub fn setname(is_self: bool, tid: impl FnOnce() -> i32, name: &CStr) -> c_int {
    let len = name.to_bytes().len();
    if len > TASK_COMM_LEN - 1 {
        return ERANGE;
    }
    if is_self {
        // SAFETY: the kernel reads the borrowed NUL-terminated name.
        return errno_of(unsafe { syscall3(SYS_PRCTL, 15 /* PR_SET_NAME */, name.as_ptr() as usize, 0) });
    }
    let fd = match open_comm(tid(), 1 /* O_WRONLY */) {
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
    // SAFETY: `name` is a NUL-terminated string (C contract; read without a NULL check, as glibc).
    let name = unsafe { rusty_libc_core::ffi::cstr_nonnull(name) };
    // SAFETY: `th` is a live thread handle (C contract).
    setname(th as *mut Thread == current_thread(), || unsafe { tid_of(th) }, name)
}

/// `pthread_getname_np` into `buf` (NUL-terminated on success).
pub fn getname(is_self: bool, tid: impl FnOnce() -> i32, buf: &mut [u8]) -> c_int {
    if buf.len() < TASK_COMM_LEN {
        return ERANGE;
    }
    // the calling thread's own name: prctl(PR_GET_NAME) as glibc, no /proc (16 bytes, NUL-terminated)
    if is_self {
        // SAFETY: the kernel writes 16 bytes into the borrowed buffer, which holds at least 16.
        return errno_of(unsafe { syscall3(SYS_PRCTL, 16 /* PR_GET_NAME */, buf.as_mut_ptr() as usize, 0) });
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
    // (n < buf.len(): the comm file holds at most 15 characters and a newline)
    if let Some(b) = buf.get_mut(n) {
        *b = 0;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getname_np(th: PthreadT, buf: *mut c_char, buflen: usize) -> c_int {
    // SAFETY: `buf` holds `buflen` writable bytes (C contract).
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    // SAFETY: `th` is a live thread handle (C contract).
    getname(th as *mut Thread == current_thread(), || unsafe { tid_of(th) }, out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedparam(th: PthreadT, policy: c_int, param: *const SchedParam) -> c_int {
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let t = th as *mut Thread;
    // SAFETY: `param` is a valid struct sched_param (C contract).
    let prio = unsafe { arg(param) }.sched_priority;
    // the thread's lock, as glibc's pd->lock: its own PP lock/unlock cannot change the boost in between
    let body = |sched: &mut crate::thread::Sched| {
        // never below the highest ceiling of the PTHREAD_PRIO_PROTECT mutexes the thread holds; the cache keeps the base value
        // SAFETY: `t` is live and its lock is held (boosted's contract).
        let p = SchedParam { sched_priority: unsafe { crate::tpp::boosted(t, prio) } };
        let r = crate::attr::sched_setscheduler(tid, policy, &p);
        if r == 0 {
            sched.policy = policy;
            sched.prio = prio;
            sched.flags |= crate::attr::ATTR_FLAG_SCHED_SET | crate::attr::ATTR_FLAG_POLICY_SET;
        }
        r
    };
    // SAFETY: `t` is live (checked handle); the closure does not take its lock.
    unsafe { with_sched_locked(t, body) }
}

/// The cached values (glibc: "the library is responsible for maintaining the values"), asking the kernel only for what is
/// not known yet; so a thread boosted by a PTHREAD_PRIO_PROTECT mutex reports its base priority. A failing call gives 1, as
/// glibc's does.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getschedparam(th: PthreadT, policy: *mut c_int, param: *mut SchedParam) -> c_int {
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    // SAFETY: `th` is live; the closure does not take its lock.
    let got = unsafe { with_sched_locked(th as *mut Thread, |sched| if sched.fill(tid) != 0 { None } else { Some((sched.policy, sched.prio)) }) };
    match got {
        None => 1,
        Some((pol, prio)) => {
            // SAFETY: `policy` is a writable int (C contract).
            unsafe { *policy = pol };
            // SAFETY: `param` is a writable struct sched_param (C contract).
            unsafe { (*param).sched_priority = prio };
            0
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedprio(th: PthreadT, prio: c_int) -> c_int {
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    let t = th as *mut Thread;
    let body = |sched: &mut crate::thread::Sched| {
        // SAFETY: `t` is live and its lock is held.
        let r = crate::attr::sched_setparam(tid, &SchedParam { sched_priority: unsafe { crate::tpp::boosted(t, prio) } });
        if r == 0 {
            sched.prio = prio;
            sched.flags |= crate::attr::ATTR_FLAG_SCHED_SET;
        }
        r
    };
    // SAFETY: `t` is live; the closure does not take its lock.
    unsafe { with_sched_locked(t, body) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setaffinity_np(th: PthreadT, size: usize, set: *const CpuSet) -> c_int {
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    // SAFETY: `set` holds `size` readable bytes (C contract).
    let mask = unsafe { rusty_libc_core::ffi::bytes(set.cast::<u8>(), size) };
    crate::attr::sched_setaffinity(tid, mask)
}

/// `pthread_getaffinity_np` of thread `tid` into `set` (the bytes past the kernel's mask are cleared).
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
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    // SAFETY: `set` holds `size` writable bytes (C contract).
    getaffinity(tid, unsafe { rusty_libc_core::ffi::bytes_mut(set.cast::<u8>(), size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getcpuclockid(th: PthreadT, clockid: *mut c_int) -> c_int {
    // SAFETY: `th` is a live thread handle (C contract).
    let tid = unsafe { tid_of(th) };
    if tid <= 0 {
        return ESRCH;
    }
    // SAFETY: `clockid` is a writable clockid_t (C contract).
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

/// The names libgcc and libstdc++ probe to see whether threads are linked in.
macro_rules! alias {
    ($($name:ident => $target:path : fn($($arg:ident : $ty:ty),*) -> $ret:ty;)*) => {
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
                // SAFETY: the same C contract as the function it forwards to.
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
