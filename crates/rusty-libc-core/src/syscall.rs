//! Raw Linux x86_64 system calls.
//!
//! The entry itself is the one unsafe thing here: `syscallN` puts the number in `rax` and the arguments in `rdi`, `rsi`,
//! `rdx`, `r10`, `r8`, `r9`, executes `syscall` and returns `rax` (the kernel's result, `-errno` in -4095..=-1); the kernel
//! clobbers `rcx` (return address) and `r11` (flags) and nothing else. Whether a call is memory-safe depends on what the
//! kernel does with the arguments (a pointer it writes through, a mapping it removes), which only the caller knows: hence
//! `unsafe fn` with the contract "arguments valid for system call `n`". Safe wrappers for calls with plain-value arguments
//! live in `unistd` and `signal`.
//!
//! The asm blocks do not say `nomem`: the kernel may read or write memory the arguments point to, so the compiler must
//! not keep values in registers across the call (Rust RFC Book p.3363: without `nomem`/`readonly` the block may read and
//! write any memory it can reach). `nostack`: the `syscall` instruction does not touch the user stack.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::arch::asm;

pub const SYS_READ: usize = 0;
/// Kernel numbers of the legacy calls glibc 2.43 never makes (the library uses openat, newfstatat and clone instead, so
/// that seccomp filters written for glibc allow it); kept for the Rust API's users and test programs.
pub const SYS_OPEN: usize = 2;
pub const SYS_STAT: usize = 4;
pub const SYS_LSTAT: usize = 6;
pub const SYS_FORK: usize = 57;
pub const SYS_WRITE: usize = 1;
pub const SYS_CLOSE: usize = 3;
pub const SYS_FSTAT: usize = 5;
pub const SYS_LSEEK: usize = 8;
pub const SYS_IOCTL: usize = 16;
pub const SYS_PIPE2: usize = 293;
pub const SYS_DUP: usize = 32;
pub const SYS_DUP3: usize = 292;
pub const SYS_ACCESS: usize = 21;
pub const SYS_NEWFSTATAT: usize = 262;
pub const SYS_RENAMEAT: usize = 264;
pub const SYS_RENAMEAT2: usize = 316;
pub const SYS_GETPPID: usize = 110;
pub const SYS_GETUID: usize = 102;
pub const SYS_GETEUID: usize = 107;
pub const SYS_GETGID: usize = 104;
pub const SYS_GETEGID: usize = 108;
pub const SYS_KILL: usize = 62;
pub const SYS_RENAME: usize = 82;
pub const SYS_UNLINK: usize = 87;
pub const SYS_RMDIR: usize = 84;
pub const SYS_FTRUNCATE: usize = 77;
pub const SYS_FCNTL: usize = 72;
pub const SYS_DUP2: usize = 33;
pub const SYS_OPENAT: usize = 257;
pub const SYS_CLONE: usize = 56;
pub const SYS_EXECVE: usize = 59;
pub const SYS_WAIT4: usize = 61;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_BRK: usize = 12;
pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGPROCMASK: usize = 14;
pub const SYS_MREMAP: usize = 25;
pub const SYS_MADVISE: usize = 28;
pub const SYS_GETPID: usize = 39;
pub const SYS_GETTID: usize = 186;
pub const SYS_TGKILL: usize = 234;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_GETRANDOM: usize = 318;
/// AT_FDCWD as a system-call argument.
pub const AT_FDCWD: usize = -100isize as usize;

/// open(path, flags, mode) made the way glibc makes it: `openat(AT_FDCWD, ...)`. glibc never uses the
/// legacy `open` call (number 2), so seccomp filters built from glibc's behaviour (Chromium, glycin,
/// systemd SystemCallFilter, flatpak) may not allow it. Raw kernel return value.
///
/// # Safety
/// `path` must be a NUL-terminated string (or a pointer the kernel may fault on, giving EFAULT).
#[inline(always)]
pub unsafe fn sys_open(path: usize, flags: usize, mode: usize) -> usize {
    // SAFETY: openat only reads the NUL-terminated `path` (caller's contract); the rest are plain values.
    unsafe { syscall4(SYS_OPENAT, AT_FDCWD, path, flags, mode) }
}

/// stat(path, buf) made the way glibc makes it: `newfstatat(AT_FDCWD, path, buf, 0)` (glibc's stat never uses the legacy
/// `stat` call; only its pre-2.33 `__xstat` compatibility symbols do). Raw kernel return value.
///
/// # Safety
/// `path` must be a NUL-terminated string and `buf` room for a kernel `struct stat` (144 bytes).
#[inline(always)]
pub unsafe fn sys_stat(path: usize, buf: usize) -> usize {
    // SAFETY: newfstatat reads `path` and writes one struct stat to `buf` (caller's contract).
    unsafe { syscall4(SYS_NEWFSTATAT, AT_FDCWD, path, buf, 0) }
}

/// lstat(path, buf) as glibc makes it: `newfstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW)`. Raw kernel return value.
///
/// # Safety
/// As [`sys_stat`].
#[inline(always)]
pub unsafe fn sys_lstat(path: usize, buf: usize) -> usize {
    // SAFETY: as in `sys_stat`.
    unsafe { syscall4(SYS_NEWFSTATAT, AT_FDCWD, path, buf, 0x100 /* AT_SYMLINK_NOFOLLOW */) }
}

/// Turn a raw kernel return value into `Ok(value)` or `Err(errno)`.
/// The kernel returns `-errno` in the range -4095..=-1.
pub fn check(ret: usize) -> Result<usize, crate::Errno> {
    if ret > usize::MAX - 4095 {
        Err(crate::Errno((ret as isize).wrapping_neg() as i32))
    } else {
        Ok(ret)
    }
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall0(n: usize) -> usize {
    let ret;
    // SAFETY: the `syscall` instruction with the registers the kernel ABI names; it clobbers only rcx and r11 (declared).
    // What the kernel does with the arguments is covered by the caller's contract.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall1(n: usize, a: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall3(n: usize, a: usize, b: usize, c: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall2(n: usize, a: usize, b: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall4(n: usize, a: usize, b: usize, c: usize, d: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall5(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// # Safety
/// The caller must pass arguments valid for system call `n`.
pub unsafe fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> usize {
    let ret;
    // SAFETY: as in `syscall0`; the arguments are valid for `n` (caller's contract).
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, in("r9") f,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}
