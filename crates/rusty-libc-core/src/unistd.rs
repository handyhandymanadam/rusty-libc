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
    let ret = unsafe { syscall::syscall3(syscall::SYS_OPEN, path as usize, flags as usize, mode as usize) };
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

pub fn isatty(fd: i32) -> bool {
    let mut termios = [0u8; 64];
    let ret = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, 0x5401, termios.as_mut_ptr() as usize) };
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
    let ret = unsafe { syscall::syscall0(syscall::SYS_FORK) };
    if ret == 0 {
        crate::tls::refresh_tid_after_fork();
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
