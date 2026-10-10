use crate::signal::{self, KSigaction, SIG_SETMASK};
use crate::syscall::{self, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use core::ffi::{c_char, c_int, c_short};
use core::sync::atomic::{AtomicBool, Ordering};

const EPERM: c_int = 1;
const ENOENT: c_int = 2;
const ENOEXEC: c_int = 8;
const ECHILD: c_int = 10;
const EACCES: c_int = 13;
const ENODEV: c_int = 19;
const ENOTDIR: c_int = 20;
const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;
const ENOSYS: c_int = 38;
const ENOTSUP: c_int = 95;
const ETIMEDOUT: c_int = 110;
const ESTALE: c_int = 116;
const SYS_CHDIR: usize = 80;
const SYS_FCHDIR: usize = 81;
const SYS_GETUID_NR: usize = 102;
const SYS_GETGID_NR: usize = 104;
const SYS_SETPGID: usize = 109;
const SYS_SETSID_NR: usize = 112;
const SYS_SETRESUID: usize = 117;
const SYS_SETRESGID: usize = 119;
const SYS_GETPGID: usize = 121;
const SYS_SCHED_SETPARAM: usize = 142;
const SYS_SCHED_SETSCHEDULER: usize = 144;
const SYS_WAITID: usize = 247;
const SYS_PRLIMIT64: usize = 302;
const SYS_CLOSE_RANGE: usize = 436;
const TIOCSPGRP: usize = 0x5410;

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

const CLONE_VM: u64 = 0x100;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
const CLONE_INTO_CGROUP: u64 = 1 << 33;
const SIGCHLD: u64 = 17;

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

core::arch::global_asm!(
    ".text",
    ".globl rl_spawn_clone3",
    ".type rl_spawn_clone3, @function",
    "rl_spawn_clone3:",
    "mov r9, rdx",
    "mov r8, rcx",
    "mov eax, 435",
    "syscall",
    "test rax, rax",
    "jnz 2f",
    "xor ebp, ebp",
    "mov rdi, r8",
    "call r9",
    "mov edi, eax",
    "mov eax, 231",
    "syscall",
    "ud2",
    "2:",
    "ret",
    ".size rl_spawn_clone3, . - rl_spawn_clone3",
    ".globl rl_spawn_clone",
    ".type rl_spawn_clone, @function",
    "rl_spawn_clone:",
    "and rsi, -16",
    "sub rsi, 16",
    "mov qword ptr [rsi], rdx",
    "mov qword ptr [rsi + 8], rcx",
    "xor edx, edx",
    "xor r10d, r10d",
    "xor r8d, r8d",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jnz 3f",
    "xor ebp, ebp",
    "pop rax",
    "pop rdi",
    "call rax",
    "mov edi, eax",
    "mov eax, 231",
    "syscall",
    "ud2",
    "3:",
    "ret",
    ".size rl_spawn_clone, . - rl_spawn_clone",
);

unsafe extern "C" {
    fn rl_spawn_clone3(args: *const CloneArgs, size: usize, f: unsafe extern "C" fn(*mut Args) -> c_int, arg: *mut Args) -> isize;
    fn rl_spawn_clone(flags: usize, stack_top: *mut u8, f: unsafe extern "C" fn(*mut Args) -> c_int, arg: *mut Args) -> isize;
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

unsafe fn execve_raw(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    let r = unsafe { syscall3(syscall::SYS_EXECVE, file as usize, argv as usize, envp as usize) };
    sys_err(r)
}

const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

unsafe fn cstrnlen(s: *const c_char, max: usize) -> usize {
    let mut n = 0;
    while n < max && unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

unsafe fn execvpex(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe {
        if *file == 0 {
            return ENOENT;
        }
        let mut slash = false;
        let mut i = 0;
        while *file.add(i) != 0 {
            if *file.add(i) == b'/' as c_char {
                slash = true;
                break;
            }
            i += 1;
        }
        if slash {
            return execve_raw(file, argv, envp);
        }
        let mut path = crate::env::getenv(b"PATH") as *const c_char;
        if path.is_null() {
            path = c"/bin:/usr/bin".as_ptr();
        }
        let file_len = cstrnlen(file, NAME_MAX) + 1;
        let path_len = cstrnlen(path, PATH_MAX - 1) + 1;
        if (file_len - 1 == NAME_MAX && *file.add(NAME_MAX) != 0) || path_len + file_len + 1 > PATH_MAX + NAME_MAX + 3 {
            return ENAMETOOLONG;
        }
        let mut buffer = [0 as c_char; PATH_MAX + NAME_MAX + 3];
        let mut got_eacces = false;
        let mut last = ENOENT;
        let mut pp = path;
        loop {
            let mut subp = pp;
            while *subp != 0 && *subp != b':' as c_char {
                subp = subp.add(1);
            }
            let seg = subp.offset_from(pp) as usize;
            if seg >= path_len {
                if *subp == 0 {
                    break;
                }
                pp = subp;
                continue;
            }
            core::ptr::copy_nonoverlapping(pp, buffer.as_mut_ptr(), seg);
            buffer[seg] = b'/' as c_char;
            let skip = (seg > 0) as usize;
            core::ptr::copy_nonoverlapping(file, buffer.as_mut_ptr().add(seg + skip), file_len);
            let e = execve_raw(buffer.as_ptr(), argv, envp);
            last = e;
            match e {
                EACCES => got_eacces = true,
                ENOENT | ESTALE | ENOTDIR | ENODEV | ETIMEDOUT => {}
                _ => return e,
            }
            let end = *subp == 0;
            pp = subp.add(1);
            if end {
                break;
            }
        }
        if got_eacces { EACCES } else { last }
    }
}

unsafe fn child_setup(args: &Args) -> c_int {
    unsafe {
        let attr = &*args.attr;
        let flags = attr.flags as c_int;
        let setdef = flags & POSIX_SPAWN_SETSIGDEF != 0;
        if setdef || !args.use_clone3 {
            for sig in 1..=64i32 {
                let in_default = setdef && attr.sd.val[0] & signal::bit(sig) != 0;
                if in_default {
                    let _ = signal::sigaction(sig, Some(&KSigaction::DEFAULT));
                } else if !args.use_clone3 {
                    if sig == 32 || sig == 33 {
                        let _ = signal::sigaction(sig, Some(&KSigaction::IGNORE));
                        continue;
                    }
                    match signal::sigaction(sig, None) {
                        Ok(old) if old.handler == signal::SIG_IGN || old.handler == signal::SIG_DFL => {}
                        Ok(_) => {
                            let _ = signal::sigaction(sig, Some(&KSigaction::DEFAULT));
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        if flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER) == POSIX_SPAWN_SETSCHEDPARAM {
            let e = sys_err(syscall2(SYS_SCHED_SETPARAM, 0, &attr.sp as *const SchedParam as usize));
            if e != 0 {
                return e;
            }
        } else if flags & POSIX_SPAWN_SETSCHEDULER != 0 {
            let e = sys_err(syscall3(SYS_SCHED_SETSCHEDULER, 0, attr.policy as usize, &attr.sp as *const SchedParam as usize));
            if e != 0 {
                return e;
            }
        }
        if flags & POSIX_SPAWN_SETSID != 0 {
            let e = sys_err(syscall1(SYS_SETSID_NR, 0));
            if e != 0 {
                return e;
            }
        }
        if flags & POSIX_SPAWN_SETPGROUP != 0 {
            let e = sys_err(syscall2(SYS_SETPGID, 0, attr.pgrp as usize));
            if e != 0 {
                return e;
            }
        }
        if flags & POSIX_SPAWN_RESETIDS != 0 {
            let uid = syscall1(SYS_GETUID_NR, 0);
            let e = sys_err(syscall3(SYS_SETRESUID, usize::MAX, uid, usize::MAX));
            if e != 0 {
                return e;
            }
            let gid = syscall1(SYS_GETGID_NR, 0);
            let e = sys_err(syscall3(SYS_SETRESGID, usize::MAX, gid, usize::MAX));
            if e != 0 {
                return e;
            }
        }
        if !args.fa.is_null() {
            let fa = &*args.fa;
            let mut fd_limit: Option<i64> = None;
            for i in 0..fa.used.max(0) as usize {
                let a = &*fa.actions.add(i);
                match a.tag {
                    A_CLOSE => {
                        let e = sys_err(syscall1(syscall::SYS_CLOSE, a.fd as usize));
                        if e != 0 {
                            let lim = *fd_limit.get_or_insert_with(open_max);
                            if a.fd < 0 || (lim >= 0 && a.fd as i64 >= lim) {
                                return e;
                            }
                        }
                    }
                    A_OPEN => {
                        let _ = syscall1(syscall::SYS_CLOSE, a.fd as usize);
                        let r = syscall3(syscall::SYS_OPEN, a.path as usize, a.arg as usize, a.mode as usize);
                        let e = sys_err(r);
                        if e != 0 {
                            return e;
                        }
                        let new_fd = r as c_int;
                        if new_fd != a.fd {
                            let r2 = syscall2(syscall::SYS_DUP2, new_fd as usize, a.fd as usize);
                            let e = sys_err(r2);
                            if e != 0 {
                                return e;
                            }
                            let e = sys_err(syscall1(syscall::SYS_CLOSE, new_fd as usize));
                            if e != 0 {
                                return e;
                            }
                        }
                    }
                    A_DUP2 => {
                        if a.fd == a.arg {
                            let r = syscall3(syscall::SYS_FCNTL, a.arg as usize, 1, 0);
                            let e = sys_err(r);
                            if e != 0 {
                                return e;
                            }
                            let e = sys_err(syscall3(syscall::SYS_FCNTL, a.arg as usize, 2, r & !1));
                            if e != 0 {
                                return e;
                            }
                        } else {
                            let e = sys_err(syscall2(syscall::SYS_DUP2, a.fd as usize, a.arg as usize));
                            if e != 0 {
                                return e;
                            }
                        }
                    }
                    A_CHDIR => {
                        let e = sys_err(syscall1(SYS_CHDIR, a.path as usize));
                        if e != 0 {
                            return e;
                        }
                    }
                    A_FCHDIR => {
                        let e = sys_err(syscall1(SYS_FCHDIR, a.fd as usize));
                        if e != 0 {
                            return e;
                        }
                    }
                    A_CLOSEFROM => {
                        let e = sys_err(syscall3(SYS_CLOSE_RANGE, a.fd as usize, u32::MAX as usize, 0));
                        if e != 0 && !closefrom_fallback(a.fd) {
                            return e;
                        }
                    }
                    A_TCSETPGRP => {
                        let pgrp = if flags & POSIX_SPAWN_SETPGROUP != 0 && attr.pgrp != 0 {
                            attr.pgrp
                        } else {
                            syscall1(SYS_GETPGID, 0) as c_int
                        };
                        let e = sys_err(syscall3(syscall::SYS_IOCTL, a.fd as usize, TIOCSPGRP, &pgrp as *const c_int as usize));
                        if e != 0 {
                            return e;
                        }
                    }
                    _ => {}
                }
            }
        }
        let mask = if flags & POSIX_SPAWN_SETSIGMASK != 0 { attr.ss.val[0] } else { args.oldmask };
        let _ = signal::sigprocmask(SIG_SETMASK, Some(mask));
        let mut e = if args.use_path { execvpex(args.file, args.argv, args.envp) } else { execve_raw(args.file, args.argv, args.envp) };
        if e == ENOEXEC && args.try_shell {
            let mut argc = 0usize;
            while !(*args.argv.add(argc)).is_null() {
                argc += 1;
            }
            let mut new_argv = [core::ptr::null::<c_char>(); 130];
            if argc + 2 < new_argv.len() {
                new_argv[0] = c"/bin/sh".as_ptr();
                new_argv[1] = args.file;
                for i in 1..argc {
                    new_argv[1 + i] = *args.argv.add(i);
                }
                e = execve_raw(new_argv[0], new_argv.as_ptr(), args.envp);
            }
        }
        if e != 0 { e } else { ECHILD }
    }
}

unsafe fn closefrom_fallback(low: c_int) -> bool {
    let lim = open_max();
    let top = if !(0..=(1 << 20)).contains(&lim) { 1 << 20 } else { lim } as c_int;
    let mut fd = low.max(0);
    while fd < top {
        unsafe { syscall1(syscall::SYS_CLOSE, fd as usize) };
        fd += 1;
    }
    true
}

unsafe extern "C" fn spawn_child(args: *mut Args) -> c_int {
    unsafe {
        let e = child_setup(&*args);
        core::ptr::write_volatile(&raw mut (*args).err, if e == 0 { ECHILD } else { e });
    }
    SPAWN_ERROR
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
    unsafe {
        let stack = syscall6(syscall::SYS_MMAP, 0, CHILD_STACK, 3, 0x2 | 0x20 | 0x20000, usize::MAX, 0);
        let e = sys_err(stack);
        if e != 0 {
            return e;
        }
        static ZERO: PosixSpawnattr = ZERO_ATTR;
        let attr = if attrp.is_null() { &raw const ZERO } else { attrp };
        let oldmask = signal::sigprocmask(SIG_SETMASK, Some(u64::MAX)).unwrap_or(0);
        let mut args = Args { err: 0, file, use_path, try_shell, use_clone3: true, fa, attr, argv, envp, oldmask, pidfd: 0 };
        let set_cgroup = (*attr).flags as c_int & POSIX_SPAWN_SETCGROUP != 0;
        let ca = CloneArgs {
            flags: (if set_cgroup { CLONE_INTO_CGROUP } else { 0 }) | (if use_pidfd { CLONE_PIDFD } else { 0 }) | CLONE_CLEAR_SIGHAND | CLONE_VM | CLONE_VFORK,
            pidfd: if use_pidfd { &raw mut args.pidfd as u64 } else { 0 },
            child_tid: 0,
            parent_tid: if use_pidfd { &raw mut args.pidfd as u64 } else { 0 },
            exit_signal: SIGCHLD,
            stack: stack as u64,
            stack_size: CHILD_STACK as u64,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: if set_cgroup { (*attr).cgroup as u32 as u64 } else { 0 },
        };
        let mut new_pid = if FORCE_CLONE_FALLBACK.load(Ordering::Relaxed) { -(ENOSYS as isize) } else { rl_spawn_clone3(&ca, size_of::<CloneArgs>(), spawn_child, &mut args) };
        let mut failure = sys_err(new_pid as usize);
        if new_pid < 0 && (failure == ENOSYS || failure == EINVAL || failure == EPERM) {
            args.use_clone3 = false;
            if use_pidfd {
                failure = ENOSYS;
                new_pid = -1;
            } else if !set_cgroup {
                new_pid = rl_spawn_clone((CLONE_VM | CLONE_VFORK | SIGCHLD) as usize, (stack + CHILD_STACK) as *mut u8, spawn_child, &mut args);
                failure = sys_err(new_pid as usize);
            } else {
                failure = if failure == ENOSYS { ENOTSUP } else { failure };
                new_pid = -1;
            }
        }
        let ec;
        if new_pid > 0 {
            ec = core::ptr::read_volatile(&raw const args.err);
            if ec > 0 {
                if use_pidfd {
                    syscall5(SYS_WAITID, 3, args.pidfd as usize, 0, 4, 0);
                    syscall1(syscall::SYS_CLOSE, args.pidfd as usize);
                } else {
                    syscall5(SYS_WAITID, 1, new_pid as usize, 0, 4, 0);
                }
            }
        } else {
            ec = failure;
        }
        syscall2(syscall::SYS_MUNMAP, stack, CHILD_STACK);
        let _ = signal::sigprocmask(SIG_SETMASK, Some(oldmask));
        if ec == 0 && !pid.is_null() {
            *pid = if use_pidfd { args.pidfd } else { new_pid as c_int };
        }
        ec
    }
}
