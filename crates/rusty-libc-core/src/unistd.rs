#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::{Errno, syscall};

pub fn write(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    let ret = unsafe {
        crate::tls::syscall_cp(syscall::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0)
    };
    syscall::check(ret)
}

pub fn read_nocancel(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    let ret = unsafe { syscall::syscall3(syscall::SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
    syscall::check(ret)
}

pub fn write_nocancel(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    let ret = unsafe { syscall::syscall3(syscall::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) };
    syscall::check(ret)
}

use core::ffi::c_char;

pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    let ret = unsafe { crate::tls::syscall_cp(syscall::SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0) };
    syscall::check(ret)
}

pub unsafe fn open(path: *const c_char, flags: i32, mode: u32) -> Result<i32, Errno> {
    let ret = unsafe { crate::syscall::sys_open(path as usize, flags as usize, mode as usize) };
    syscall::check(ret).map(|v| v as i32)
}

pub fn close(fd: i32) -> Result<(), Errno> {
    let ret = unsafe { syscall::syscall1(syscall::SYS_CLOSE, fd as usize) };
    syscall::check(ret).map(|_| ())
}

pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, Errno> {
    let ret = unsafe { syscall::syscall3(syscall::SYS_LSEEK, fd as usize, offset as usize, whence as usize) };
    syscall::check(ret).map(|v| v as i64)
}

pub fn fstat_basic(fd: i32) -> Result<(u32, i64, i64), Errno> {
    let mut st = [0u64; 18];
    let ret = unsafe { syscall::syscall2(syscall::SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize) };
    syscall::check(ret)?;
    let mode = (st[3] & 0xffff_ffff) as u32;
    Ok((mode, st[7] as i64, st[6] as i64))
}

pub const TCGETS2: usize = 0x802C_542A;

pub fn isatty(fd: i32) -> bool {
    let mut termios = [0u8; 64];
    let ret = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, TCGETS2, termios.as_mut_ptr() as usize) };
    ret == 0
}

pub fn dup3(old: i32, new: i32, flags: i32) -> Result<i32, Errno> {
    let ret = unsafe { syscall::syscall3(syscall::SYS_DUP3, old as usize, new as usize, flags as usize) };
    syscall::check(ret).map(|v| v as i32)
}

pub fn dup(fd: i32) -> Result<i32, Errno> {
    let ret = unsafe { syscall::syscall1(syscall::SYS_DUP, fd as usize) };
    syscall::check(ret).map(|v| v as i32)
}

pub fn pipe2(flags: i32) -> Result<(i32, i32), Errno> {
    let mut fds = [0i32; 2];
    let ret = unsafe { syscall::syscall2(syscall::SYS_PIPE2, fds.as_mut_ptr() as usize, flags as usize) };
    syscall::check(ret)?;
    Ok((fds[0], fds[1]))
}

pub unsafe fn fork() -> Result<i32, Errno> {
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const SIGCHLD: usize = 17;
    let tp = crate::tls::current();
    let ret = if tp.is_null() {
        unsafe { syscall::syscall5(syscall::SYS_CLONE, SIGCHLD, 0, 0, 0, 0) }
    } else {
        let tid = unsafe { &raw mut (*tp).tid };
        unsafe { syscall::syscall5(syscall::SYS_CLONE, CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, 0, 0, tid as usize, 0) }
    };
    if ret == 0 && !tp.is_null() {
        unsafe { crate::tls::robust_register(tp) };
    }
    syscall::check(ret).map(|v| v as i32)
}

pub unsafe fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> Errno {
    let ret = unsafe { syscall::syscall3(syscall::SYS_EXECVE, path as usize, argv as usize, envp as usize) };
    syscall::check(ret).err().unwrap_or(Errno(0))
}

pub fn waitpid(pid: i32, options: i32) -> Result<(i32, i32), Errno> {
    let mut status = 0i32;
    let ret = unsafe { crate::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, 0, 0, 0) };
    syscall::check(ret).map(|v| (v as i32, status))
}

pub unsafe fn access(path: *const c_char, mode: i32) -> Result<(), Errno> {
    let ret = unsafe { syscall::syscall2(syscall::SYS_ACCESS, path as usize, mode as usize) };
    syscall::check(ret).map(|_| ())
}

pub static SETXID_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[inline]
pub unsafe fn setxid_syscall(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let hook = SETXID_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        let f: unsafe extern "C" fn(usize, usize, usize, usize) -> usize = unsafe { core::mem::transmute(hook) };
        return unsafe { f(nr, a1, a2, a3) };
    }
    unsafe { syscall::syscall3(nr, a1, a2, a3) }
}

#[inline]
pub fn getpid() -> i32 {
    unsafe { syscall::syscall0(syscall::SYS_GETPID) as i32 }
}

#[inline]
pub fn gettid() -> i32 {
    unsafe { syscall::syscall0(syscall::SYS_GETTID) as i32 }
}

#[inline]
pub fn getppid() -> i32 {
    unsafe { syscall::syscall0(syscall::SYS_GETPPID) as i32 }
}

#[inline]
pub fn getuid() -> u32 {
    unsafe { syscall::syscall0(syscall::SYS_GETUID) as u32 }
}

#[inline]
pub fn geteuid() -> u32 {
    unsafe { syscall::syscall0(syscall::SYS_GETEUID) as u32 }
}

#[inline]
pub fn getgid() -> u32 {
    unsafe { syscall::syscall0(syscall::SYS_GETGID) as u32 }
}

#[inline]
pub fn getegid() -> u32 {
    unsafe { syscall::syscall0(syscall::SYS_GETEGID) as u32 }
}

#[inline]
pub fn dup2(old: i32, new: i32) -> Result<i32, Errno> {
    let ret = unsafe { syscall::syscall2(syscall::SYS_DUP2, old as usize, new as usize) };
    syscall::check(ret).map(|v| v as i32)
}

#[inline]
pub fn ftruncate(fd: i32, len: i64) -> Result<(), Errno> {
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

#[inline]
pub fn fcntl_int(fd: i32, cmd: i32, arg: i32) -> Result<i32, Errno> {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL | F_SETFL | F_SETOWN | F_GETSIG | F_SETSIG | F_GETLEASE
        | F_SETLEASE | F_NOTIFY | F_GETPIPE_SZ | F_SETPIPE_SZ | F_ADD_SEALS | F_GET_SEALS => {}
        _ => return Err(Errno(crate::errno::EINVAL)),
    }
    let ret = unsafe { syscall::syscall3(syscall::SYS_FCNTL, fd as usize, cmd as usize, arg as isize as usize) };
    syscall::check(ret).map(|v| v as i32)
}

