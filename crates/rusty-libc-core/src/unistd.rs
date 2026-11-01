//! unistd.h, Rust side: safe wrappers over the system calls (BRIEF-UNSAFE.md U1). Each wrapper makes one system call with
//! plain values (or pointers to its own locals and the slices it was given) and turns the raw result into a `Result` with
//! `syscall::check`; the system call itself is the only unsafe operation.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::{Errno, syscall};

/// write(2): write bytes to a file descriptor; returns how many were written.
pub fn write(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `buf.len()` bytes of `buf`.
    let ret = unsafe {
        crate::tls::syscall_cp(syscall::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0)
    };
    syscall::check(ret)
}

/// read(2) that is not a cancellation point (a stream opened with the glibc "c" mode flag).
pub fn read_nocancel(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    let ret = unsafe { syscall::syscall3(syscall::SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
    syscall::check(ret)
}

/// write(2) that is not a cancellation point.
pub fn write_nocancel(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `buf.len()` bytes of `buf`.
    let ret = unsafe { syscall::syscall3(syscall::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) };
    syscall::check(ret)
}

use core::ffi::c_char;

/// read(2): read into a buffer; returns how many bytes were read (0 at end of file).
pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    let ret = unsafe { crate::tls::syscall_cp(syscall::SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0) };
    syscall::check(ret)
}

/// open(2). `path` must be NUL-terminated.
///
/// # Safety
/// `path` must point to a NUL-terminated string.
pub unsafe fn open(path: *const c_char, flags: i32, mode: u32) -> Result<i32, Errno> {
    // SAFETY: `path` is a C string (caller's contract).
    let ret = unsafe { crate::syscall::sys_open(path as usize, flags as usize, mode as usize) };
    syscall::check(ret).map(|v| v as i32)
}

/// close(2).
pub fn close(fd: i32) -> Result<(), Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall1(syscall::SYS_CLOSE, fd as usize) };
    syscall::check(ret).map(|_| ())
}

/// lseek(2); returns the new offset.
pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall3(syscall::SYS_LSEEK, fd as usize, offset as usize, whence as usize) };
    syscall::check(ret).map(|v| v as i64)
}

/// The fields of `struct stat` that stdio needs: (mode, block size, size), via fstat(2).
pub fn fstat_basic(fd: i32) -> Result<(u32, i64, i64), Errno> {
    let mut st = [0u64; 18]; // struct stat on x86-64 is 144 bytes
    // SAFETY: `st` has room for the kernel's struct stat.
    let ret = unsafe { syscall::syscall2(syscall::SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize) };
    syscall::check(ret)?;
    // layout (in 8-byte words): dev, ino, nlink, mode+uid, gid+pad, rdev, size, blksize, blocks
    let mode = (st[3] & 0xffff_ffff) as u32;
    Ok((mode, st[7] as i64, st[6] as i64))
}

/// The `TCGETS2` ioctl request (`struct termios2`, 44 bytes): glibc 2.43's isatty, tcgetattr and stdio's terminal check
/// use it, never `TCGETS` (seccomp filters may check the request number).
pub const TCGETS2: usize = 0x802C_542A;

/// True if `fd` refers to a terminal (the TCGETS2 ioctl succeeds, as in glibc).
pub fn isatty(fd: i32) -> bool {
    let mut termios = [0u8; 64];
    // SAFETY: `termios` has room for the 44-byte struct termios2.
    let ret = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, TCGETS2, termios.as_mut_ptr() as usize) };
    ret == 0
}

/// dup3(2): duplicate `old` onto `new` (closing `new` first), with `flags` (O_CLOEXEC).
pub fn dup3(old: i32, new: i32, flags: i32) -> Result<i32, Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall3(syscall::SYS_DUP3, old as usize, new as usize, flags as usize) };
    syscall::check(ret).map(|v| v as i32)
}

/// dup(2).
pub fn dup(fd: i32) -> Result<i32, Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall1(syscall::SYS_DUP, fd as usize) };
    syscall::check(ret).map(|v| v as i32)
}

/// pipe2(2): (read end, write end).
pub fn pipe2(flags: i32) -> Result<(i32, i32), Errno> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` has room for the two descriptors.
    let ret = unsafe { syscall::syscall2(syscall::SYS_PIPE2, fds.as_mut_ptr() as usize, flags as usize) };
    syscall::check(ret)?;
    Ok((fds[0], fds[1]))
}

/// fork(2): 0 in the child, the child's pid in the parent.
///
/// # Safety
/// The child shares no threads with the parent; only async-signal-safe work is allowed there until
/// it executes another program.
///
/// Made as glibc's `_Fork` makes it: `clone(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0, NULL, &tid, 0)`, never
/// the legacy `fork` call (seccomp filters built from glibc's behaviour may not allow it). The kernel stores the child's
/// thread id in the TCB and clears it when the child ends (no gettid or set_tid_address needed); the child registers an
/// empty robust mutex list, as glibc's does.
pub unsafe fn fork() -> Result<i32, Errno> {
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const SIGCHLD: usize = 17;
    let tp = crate::tls::current();
    let ret = if tp.is_null() {
        // SAFETY: no pointers; the caller accepts fork's rules for the child.
        unsafe { syscall::syscall5(syscall::SYS_CLONE, SIGCHLD, 0, 0, 0, 0) }
    } else {
        // SAFETY: `tp` is this thread's TCB (not NULL); only the field's address is taken.
        let tid = unsafe { &raw mut (*tp).tid };
        // SAFETY: the kernel stores the child's tid at `tid`, in the child's copy of the TCB.
        unsafe { syscall::syscall5(syscall::SYS_CLONE, CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0, 0, tid as usize, 0) }
    };
    if ret == 0 && !tp.is_null() {
        // SAFETY: in the child, `tp` is its own (only) thread's TCB.
        unsafe { crate::tls::robust_register(tp) };
    }
    syscall::check(ret).map(|v| v as i32)
}

/// execve(2); only returns on failure.
///
/// # Safety
/// `path`, `argv` and `envp` must be valid, NULL-terminated as the kernel requires.
pub unsafe fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> Errno {
    // SAFETY: the arguments are valid as the kernel requires (caller's contract).
    let ret = unsafe { syscall::syscall3(syscall::SYS_EXECVE, path as usize, argv as usize, envp as usize) };
    syscall::check(ret).err().unwrap_or(Errno(0))
}

/// wait4(2) for one child; returns (pid, wait status).
pub fn waitpid(pid: i32, options: i32) -> Result<(i32, i32), Errno> {
    let mut status = 0i32;
    // SAFETY: the kernel writes the status into the local `status`; no rusage pointer.
    let ret = unsafe { crate::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, 0, 0, 0) };
    syscall::check(ret).map(|v| (v as i32, status))
}

/// access(2).
///
/// # Safety
/// `path` must be NUL-terminated.
pub unsafe fn access(path: *const c_char, mode: i32) -> Result<(), Errno> {
    // SAFETY: `path` is a C string (caller's contract).
    let ret = unsafe { syscall::syscall2(syscall::SYS_ACCESS, path as usize, mode as usize) };
    syscall::check(ret).map(|_| ())
}

/// Hook rusty-libc-pthread sets at its first `pthread_create`: `unsafe extern "C" fn(nr, a1, a2, a3) -> usize` makes a
/// set*id system call on every thread of the process (glibc's `__nptl_setxid`); 0 while the process has never had a
/// second thread.
pub static SETXID_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// A set*id system call (setuid, setgid, setreuid, setregid, setresuid, setresgid, setgroups) for the whole process, as
/// glibc's `INLINE_SETXID_SYSCALL`: Linux keeps credentials per thread, so once threads have existed the call goes through
/// rusty-libc-pthread, which has every thread make it; before that it is the plain system call. Returns the raw kernel
/// result (-errno on error).
///
/// # Safety
/// The arguments must be valid for system call `nr` (setgroups: a readable list).
#[inline]
pub unsafe fn setxid_syscall(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let hook = SETXID_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only rusty-libc-pthread stores here, always this signature.
        let f: unsafe extern "C" fn(usize, usize, usize, usize) -> usize = unsafe { core::mem::transmute(hook) };
        // SAFETY: the arguments are valid for `nr` (caller's contract), which is what the hook needs.
        return unsafe { f(nr, a1, a2, a3) };
    }
    // SAFETY: the arguments are valid for `nr` (caller's contract).
    unsafe { syscall::syscall3(nr, a1, a2, a3) }
}

// ---------------------------------------------------------------- plain-value system calls (U1)

/// getpid(2).
#[inline]
pub fn getpid() -> i32 {
    // SAFETY: no arguments; getpid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETPID) as i32 }
}

/// gettid(2): the calling thread's kernel id.
#[inline]
pub fn gettid() -> i32 {
    // SAFETY: no arguments; gettid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETTID) as i32 }
}

/// getppid(2).
#[inline]
pub fn getppid() -> i32 {
    // SAFETY: no arguments; getppid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETPPID) as i32 }
}

/// getuid(2).
#[inline]
pub fn getuid() -> u32 {
    // SAFETY: no arguments; getuid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETUID) as u32 }
}

/// geteuid(2).
#[inline]
pub fn geteuid() -> u32 {
    // SAFETY: no arguments; geteuid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETEUID) as u32 }
}

/// getgid(2).
#[inline]
pub fn getgid() -> u32 {
    // SAFETY: no arguments; getgid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETGID) as u32 }
}

/// getegid(2).
#[inline]
pub fn getegid() -> u32 {
    // SAFETY: no arguments; getegid cannot fail.
    unsafe { syscall::syscall0(syscall::SYS_GETEGID) as u32 }
}

/// dup2(2): duplicate `old` onto `new` (the dup2 system call, as glibc's dup2 on x86-64).
#[inline]
pub fn dup2(old: i32, new: i32) -> Result<i32, Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall2(syscall::SYS_DUP2, old as usize, new as usize) };
    syscall::check(ret).map(|v| v as i32)
}

/// ftruncate(2).
#[inline]
pub fn ftruncate(fd: i32, len: i64) -> Result<(), Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall2(syscall::SYS_FTRUNCATE, fd as usize, len as usize) };
    syscall::check(ret).map(|_| ())
}

pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_SETOWN: i32 = 8;
pub const F_SETSIG: i32 = 10;
pub const F_GETSIG: i32 = 11;
pub const F_SETLEASE: i32 = 1024;
pub const F_GETLEASE: i32 = 1025;
pub const F_NOTIFY: i32 = 1026;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const F_SETPIPE_SZ: i32 = 1031;
pub const F_GETPIPE_SZ: i32 = 1032;
pub const F_ADD_SEALS: i32 = 1033;
pub const F_GET_SEALS: i32 = 1034;
pub const FD_CLOEXEC: i32 = 1;

/// fcntl(2) for the commands whose argument is an `int` (or unused): F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL,
/// F_SETFL, F_SETOWN, F_GETSIG, F_SETSIG, F_GETLEASE, F_SETLEASE, F_NOTIFY, F_GETPIPE_SZ, F_SETPIPE_SZ, F_ADD_SEALS,
/// F_GET_SEALS. Any other command is refused with EINVAL without a system call: the lock and owner-ex commands take a
/// pointer (the kernel would write through `arg`, so they cannot be offered safely), and F_GETOWN can return a negative
/// process group that looks like an error (Kerrisk, The Linux Programming Interface p.89).
#[inline]
pub fn fcntl_int(fd: i32, cmd: i32, arg: i32) -> Result<i32, Errno> {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL | F_SETFL | F_SETOWN | F_GETSIG | F_SETSIG | F_GETLEASE
        | F_SETLEASE | F_NOTIFY | F_GETPIPE_SZ | F_SETPIPE_SZ | F_ADD_SEALS | F_GET_SEALS => {}
        _ => return Err(Errno(crate::errno::EINVAL)),
    }
    // SAFETY: every command allowed above reads `arg` as an int (or ignores it); none dereferences it.
    let ret = unsafe { syscall::syscall3(syscall::SYS_FCNTL, fd as usize, cmd as usize, arg as isize as usize) };
    syscall::check(ret).map(|v| v as i32)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn ids() {
        assert!(getpid() > 0);
        assert!(gettid() > 0);
        assert!(getppid() >= 0);
        let _ = (getuid(), geteuid(), getgid(), getegid());
    }

    #[test]
    fn fcntl_int_allowed_and_refused() {
        let (r, w) = pipe2(0).unwrap();
        assert_eq!(fcntl_int(r, F_GETFD, 0), Ok(0));
        assert_eq!(fcntl_int(r, F_SETFD, FD_CLOEXEC), Ok(0));
        assert_eq!(fcntl_int(r, F_GETFD, 0), Ok(FD_CLOEXEC));
        // F_GETLK (5) takes a pointer and F_GETOWN (9) is ambiguous: refused, no system call
        assert_eq!(fcntl_int(r, 5, 0x1000), Err(Errno(crate::errno::EINVAL)));
        assert_eq!(fcntl_int(r, 9, 0), Err(Errno(crate::errno::EINVAL)));
        let d = fcntl_int(r, F_DUPFD_CLOEXEC, 700).unwrap();
        assert!(d >= 700);
        assert_eq!(dup2(w, d), Ok(d));
        assert_eq!(write(d, b"z"), Ok(1));
        let mut b = [0u8; 1];
        assert_eq!(read(r, &mut b), Ok(1));
        assert_eq!(&b, b"z");
        for fd in [r, w, d] {
            close(fd).unwrap();
        }
        assert_eq!(fcntl_int(d, F_GETFD, 0), Err(Errno(crate::errno::EBADF)));
        assert_eq!(ftruncate(-1, 0), Err(Errno(crate::errno::EBADF)));
    }
}
