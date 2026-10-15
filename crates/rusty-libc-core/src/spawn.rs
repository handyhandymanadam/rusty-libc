#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::signal::{self, SIG_SETMASK};
use crate::syscall::{syscall1, syscall2, syscall3, syscall4, syscall5};
use core::ffi::{CStr, c_char, c_int, c_short, c_void};
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_rs_core::signal::Action;
use rusty_libc_rs_core::spawn::flags::{CLONE_CLEAR_SIGHAND, CLONE_INTO_CGROUP, CLONE_PIDFD, CLONE_VFORK, CLONE_VM, SIGCHLD};
use rusty_libc_rs_core::spawn::{CVec, CloneArgs, CloneCall, Stack, clone_vfork};

const EPERM: c_int = 1;
const ENOEXEC: c_int = 8;
const ECHILD: c_int = 10;
const EINVAL: c_int = 22;
const ENOSYS: c_int = 38;
const ENOTSUP: c_int = 95;
const SYS_CHDIR: usize = 80;
const SYS_FCHDIR: usize = 81;
const SYS_SETPGID: usize = 109;
const SYS_SETSID_NR: usize = 112;
const SYS_SETRESUID: usize = 117;
const SYS_SETRESGID: usize = 119;
const SYS_SCHED_SETPARAM: usize = 142;
const SYS_SCHED_SETSCHEDULER: usize = 144;
const SYS_WAITID: usize = 247;
const SYS_PRLIMIT64: usize = 302;
const SYS_CLOSE_RANGE: usize = 436;

pub const POSIX_SPAWN_RESETIDS: c_int = 0x01;
pub const POSIX_SPAWN_SETPGROUP: c_int = 0x02;
pub const POSIX_SPAWN_SETSIGDEF: c_int = 0x04;
pub const POSIX_SPAWN_SETSIGMASK: c_int = 0x08;
pub const POSIX_SPAWN_SETSCHEDPARAM: c_int = 0x10;
pub const POSIX_SPAWN_SETSCHEDULER: c_int = 0x20;
pub const POSIX_SPAWN_USEVFORK: c_int = 0x40;
pub const POSIX_SPAWN_SETSID: c_int = 0x80;
pub const POSIX_SPAWN_SETCGROUP: c_int = 0x100;
pub const ALL_FLAGS: c_int = 0x1ff;

pub const SCHED_OTHER: c_int = 0;
pub const SCHED_FIFO: c_int = 1;
pub const SCHED_RR: c_int = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigsetT {
    pub val: [u64; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedParam {
    pub sched_priority: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PosixSpawnattr {
    pub flags: c_short,
    pub pgrp: c_int,
    pub sd: SigsetT,
    pub ss: SigsetT,
    pub sp: SchedParam,
    pub policy: c_int,
    pub cgroup: c_int,
    pub pad: [c_int; 15],
}

pub const ZERO_ATTR: PosixSpawnattr = PosixSpawnattr { flags: 0, pgrp: 0, sd: SigsetT { val: [0; 16] }, ss: SigsetT { val: [0; 16] }, sp: SchedParam { sched_priority: 0 }, policy: 0, cgroup: 0, pad: [0; 15] };

pub const A_CLOSE: c_int = 0;
pub const A_OPEN: c_int = 1;
pub const A_DUP2: c_int = 2;
pub const A_CHDIR: c_int = 3;
pub const A_FCHDIR: c_int = 4;
pub const A_CLOSEFROM: c_int = 5;
pub const A_TCSETPGRP: c_int = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SpawnAction {
    pub tag: c_int,
    pub fd: c_int,
    pub arg: c_int,
    pub mode: c_int,
    pub path: *mut c_char,
}

#[repr(C)]
pub struct PosixSpawnFileActions {
    pub allocated: c_int,
    pub used: c_int,
    pub actions: *mut SpawnAction,
    pub pad: [c_int; 16],
}

pub fn open_max() -> i64 {
    let mut rl = [0u64; 2];
    let r = unsafe { syscall4(SYS_PRLIMIT64, 0, 7, 0, rl.as_mut_ptr() as usize) };
    if r > usize::MAX - 4095 || rl[0] == u64::MAX { -1 } else { rl[0] as i64 }
}

#[repr(C)]
struct Args {
    err: c_int,
    file: *const c_char,
    use_path: bool,
    try_shell: bool,
    use_clone3: bool,
    fa: *const PosixSpawnFileActions,
    attr: *const PosixSpawnattr,
    argv: *const *const c_char,
    envp: *const *const c_char,
    oldmask: u64,
    pidfd: c_int,
}

#[inline(always)]
pub fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

#[inline(always)]
fn res_err<T>(r: Result<T, crate::Errno>) -> c_int {
    match r {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}

unsafe fn execvpex(file: *const c_char, argv: CVec<'_>, envp: CVec<'_>) -> c_int {
    let f = unsafe { CStr::from_ptr(file) };
    let path: &[u8] = match unsafe { crate::env::getenv(b"PATH") } {
        p if p.is_null() => b"/usr/bin",
        p => unsafe { crate::ffi::cstr_bytes(p) },
    };
    rusty_libc_rs_core::spawn::exec_search(f, path, argv, envp).0
}

unsafe fn child_setup(args: &Args) -> c_int {
    let attr = unsafe { &*args.attr };
    let flags = attr.flags as c_int;
    let setdef = flags & POSIX_SPAWN_SETSIGDEF != 0;
    if setdef || !args.use_clone3 {
        for sig in 1..=64i32 {
            let in_default = setdef && attr.sd.val[0] & signal::bit(sig) != 0;
            if in_default {
                let _ = rusty_libc_rs_core::signal::set_action_raw(sig, Action::Default);
            } else if !args.use_clone3 {
                if sig == 32 || sig == 33 {
                    let _ = rusty_libc_rs_core::signal::set_action_raw(sig, Action::Ignore);
                    continue;
                }
                rusty_libc_rs_core::signal::clear_handler(sig);
            }
        }
    }
    if flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER) == POSIX_SPAWN_SETSCHEDPARAM {
        let e = sys_err(unsafe { syscall2(SYS_SCHED_SETPARAM, 0, &attr.sp as *const SchedParam as usize) });
        if e != 0 {
            return e;
        }
    } else if flags & POSIX_SPAWN_SETSCHEDULER != 0 {
        let e = sys_err(unsafe { syscall3(SYS_SCHED_SETSCHEDULER, 0, attr.policy as usize, &attr.sp as *const SchedParam as usize) });
        if e != 0 {
            return e;
        }
    }
    if flags & POSIX_SPAWN_SETSID != 0 {
        let e = sys_err(unsafe { syscall1(SYS_SETSID_NR, 0) });
        if e != 0 {
            return e;
        }
    }
    if flags & POSIX_SPAWN_SETPGROUP != 0 {
        let e = sys_err(unsafe { syscall2(SYS_SETPGID, 0, attr.pgrp as usize) });
        if e != 0 {
            return e;
        }
    }
    if flags & POSIX_SPAWN_RESETIDS != 0 {
        let uid = crate::unistd::getuid() as usize;
        let e = sys_err(unsafe { syscall3(SYS_SETRESUID, usize::MAX, uid, usize::MAX) });
        if e != 0 {
            return e;
        }
        let gid = crate::unistd::getgid() as usize;
        let e = sys_err(unsafe { syscall3(SYS_SETRESGID, usize::MAX, gid, usize::MAX) });
        if e != 0 {
            return e;
        }
    }
    if !args.fa.is_null() {
        let fa = unsafe { &*args.fa };
        let actions = unsafe { crate::ffi::slice(fa.actions, fa.used.max(0) as usize) };
        let mut fd_limit: Option<i64> = None;
        for a in actions {
            match a.tag {
                A_CLOSE => {
                    let e = res_err(crate::unistd::close(a.fd));
                    if e != 0 {
                        let lim = *fd_limit.get_or_insert_with(open_max);
                        if a.fd < 0 || (lim >= 0 && a.fd as i64 >= lim) {
                            return e;
                        }
                    }
                }
                A_OPEN => {
                    let _ = crate::unistd::close(a.fd);
                    let r = unsafe { crate::syscall::sys_open(a.path as usize, a.arg as usize, a.mode as usize) };
                    let e = sys_err(r);
                    if e != 0 {
                        return e;
                    }
                    let new_fd = r as c_int;
                    if new_fd != a.fd {
                        let e = res_err(crate::unistd::dup2(new_fd, a.fd));
                        if e != 0 {
                            return e;
                        }
                        let e = res_err(crate::unistd::close(new_fd));
                        if e != 0 {
                            return e;
                        }
                    }
                }
                A_DUP2 => {
                    if a.fd == a.arg {
                        let r = match crate::unistd::fcntl_int(a.arg, crate::unistd::F_GETFD, 0) {
                            Ok(r) => r,
                            Err(e) => return e.0,
                        };
                        let e = res_err(crate::unistd::fcntl_int(a.arg, crate::unistd::F_SETFD, r & !1));
                        if e != 0 {
                            return e;
                        }
                    } else {
                        let e = res_err(crate::unistd::dup2(a.fd, a.arg));
                        if e != 0 {
                            return e;
                        }
                    }
                }
                A_CHDIR => {
                    let e = sys_err(unsafe { syscall1(SYS_CHDIR, a.path as usize) });
                    if e != 0 {
                        return e;
                    }
                }
                A_FCHDIR => {
                    let e = sys_err(unsafe { syscall1(SYS_FCHDIR, a.fd as usize) });
                    if e != 0 {
                        return e;
                    }
                }
                A_CLOSEFROM => {
                    let e = sys_err(unsafe { syscall3(SYS_CLOSE_RANGE, a.fd as usize, u32::MAX as usize, 0) });
                    if e != 0 && !closefrom_fallback(a.fd) {
                        return e;
                    }
                }
                A_TCSETPGRP => {
                    let pgrp = if flags & POSIX_SPAWN_SETPGROUP != 0 && attr.pgrp != 0 { Some(attr.pgrp) } else { None };
                    if let Err(e) = unsafe { rusty_libc_rs_core::spawn::child_tcsetpgrp(a.fd, pgrp) } {
                        return e.0;
                    }
                }
                _ => {}
            }
        }
    }
    let mask = if flags & POSIX_SPAWN_SETSIGMASK != 0 { attr.ss.val[0] } else { args.oldmask };
    let _ = signal::sigprocmask(SIG_SETMASK, Some(mask));
    let argv = unsafe { CVec::from_raw(args.argv) };
    let envp = unsafe { CVec::from_raw(args.envp) };
    let mut e = if args.use_path {
        unsafe { execvpex(args.file, argv, envp) }
    } else {
        rusty_libc_rs_core::spawn::execve(unsafe { CStr::from_ptr(args.file) }, argv, envp).0
    };
    if e == ENOEXEC && args.try_shell {
        let mut argc = 0usize;
        loop {
            let p = unsafe { args.argv.add(argc) };
            if unsafe { *p }.is_null() {
                break;
            }
            argc += 1;
        }
        let mut new_argv = [core::ptr::null::<c_char>(); 130];
        if argc + 2 < new_argv.len() {
            new_argv[0] = c"/bin/sh".as_ptr();
            new_argv[1] = args.file;
            let old = unsafe { crate::ffi::slice(args.argv, argc) };
            if argc > 1 {
                new_argv[2..argc + 1].copy_from_slice(&old[1..]);
            }
            let sh_argv = unsafe { CVec::from_raw(new_argv.as_ptr()) };
            e = rusty_libc_rs_core::spawn::execve(c"/bin/sh", sh_argv, envp).0;
        }
    }
    if e != 0 { e } else { ECHILD }
}

fn closefrom_fallback(low: c_int) -> bool {
    let lim = open_max();
    let top = if !(0..=(1 << 20)).contains(&lim) { 1 << 20 } else { lim } as c_int;
    let mut fd = low.max(0);
    while fd < top {
        let _ = crate::unistd::close(fd);
        fd += 1;
    }
    true
}

unsafe extern "C" fn spawn_child(args: *mut c_void) -> ! {
    let args = args.cast::<Args>();
    let a = unsafe { &*args };
    let e = unsafe { child_setup(a) };
    let err = unsafe { &raw mut (*args).err };
    unsafe { core::ptr::write_volatile(err, if e == 0 { ECHILD } else { e }) };
    rusty_libc_rs_core::spawn::exit_group(SPAWN_ERROR)
}

const SPAWN_ERROR: c_int = 127;

pub static FORCE_CLONE_FALLBACK: AtomicBool = AtomicBool::new(false);
const CHILD_STACK: usize = 96 * 1024;

#[allow(clippy::too_many_arguments)]
pub unsafe fn spawnix(pid: *mut c_int, file: *const c_char, fa: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *const c_char, envp: *const *const c_char, use_path: bool, use_pidfd: bool) -> c_int {
    unsafe { spawnix_x(pid, file, fa, attrp, argv, envp, use_path, use_pidfd, false) }
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn spawnix_x(pid: *mut c_int, file: *const c_char, fa: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *const c_char, envp: *const *const c_char, use_path: bool, use_pidfd: bool, try_shell: bool) -> c_int {
    let stack = match Stack::new(CHILD_STACK, 0) {
        Ok(s) => s,
        Err(e) => return e.0,
    };
    static ZERO: PosixSpawnattr = ZERO_ATTR;
    let attr = if attrp.is_null() { &raw const ZERO } else { attrp };
    let attr_ref = unsafe { &*attr };
    let oldmask = signal::sigprocmask(SIG_SETMASK, Some(u64::MAX)).unwrap_or(0);
    let mut args = Args { err: 0, file, use_path, try_shell, use_clone3: true, fa, attr, argv, envp, oldmask, pidfd: 0 };
    let set_cgroup = attr_ref.flags as c_int & POSIX_SPAWN_SETCGROUP != 0;
    let ca = CloneArgs {
        flags: (if set_cgroup { CLONE_INTO_CGROUP } else { 0 }) | (if use_pidfd { CLONE_PIDFD } else { 0 }) | CLONE_CLEAR_SIGHAND | CLONE_VM | CLONE_VFORK,
        pidfd: if use_pidfd { &raw mut args.pidfd as u64 } else { 0 },
        child_tid: 0,
        parent_tid: if use_pidfd { &raw mut args.pidfd as u64 } else { 0 },
        exit_signal: SIGCHLD,
        stack: stack.low() as u64,
        stack_size: stack.size() as u64,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: if set_cgroup { attr_ref.cgroup as u32 as u64 } else { 0 },
    };
    let mut new_pid = if FORCE_CLONE_FALLBACK.load(Ordering::Relaxed) {
        -(ENOSYS as isize)
    } else {
        unsafe { clone_vfork(CloneCall::Clone3(&ca), spawn_child, (&raw mut args).cast()) }
    };
    let mut failure = sys_err(new_pid as usize);
    if new_pid < 0 && (failure == ENOSYS || failure == EINVAL || failure == EPERM) {
        args.use_clone3 = false;
        if use_pidfd {
            failure = ENOSYS;
            new_pid = -1;
        } else if !set_cgroup {
            new_pid = unsafe { clone_vfork(CloneCall::Clone { flags: CLONE_VM | CLONE_VFORK | SIGCHLD, stack_top: stack.top() }, spawn_child, (&raw mut args).cast()) };
            failure = sys_err(new_pid as usize);
        } else {
            failure = if failure == ENOSYS { ENOTSUP } else { failure };
            new_pid = -1;
        }
    }
    let ec;
    if new_pid > 0 {
        ec = unsafe { core::ptr::read_volatile(&raw const args.err) };
        if ec > 0 {
            if use_pidfd {
                unsafe { syscall5(SYS_WAITID, 3, args.pidfd as usize, 0, 4, 0) };
                let _ = crate::unistd::close(args.pidfd);
            } else {
                unsafe { syscall5(SYS_WAITID, 1, new_pid as usize, 0, 4, 0) };
            }
        }
    } else {
        ec = failure;
    }
    drop(stack);
    let _ = signal::sigprocmask(SIG_SETMASK, Some(oldmask));
    if ec == 0 && !pid.is_null() {
        unsafe { *pid = if use_pidfd { args.pidfd } else { new_pid as c_int } };
    }
    ec
}
