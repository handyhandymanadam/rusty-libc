#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use rusty_libc_core::{Errno, syscall};

const SYS_MKDIR: usize = 83;
const SYS_READLINK: usize = 89;
const SYS_GETCWD: usize = 79;
const SYS_SYSINFO: usize = 99;
const SYS_KILL: usize = 62;
const SYS_FACCESSAT: usize = 269;
const SYS_FACCESSAT2: usize = 439;
const AT_FDCWD: usize = -100isize as usize;

#[inline]
pub(crate) fn getrandom(buf: &mut [u8], flags: usize) -> usize {
    unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), flags) }
}

#[inline]
pub(crate) fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline]
pub(crate) fn open(path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
    unsafe { rusty_libc_core::unistd::open(path.as_ptr(), flags, mode) }
}

#[inline]
pub(crate) fn mkdir(path: &CStr, mode: usize) -> usize {
    unsafe { syscall::syscall2(SYS_MKDIR, path.as_ptr() as usize, mode) }
}

#[inline]
pub(crate) fn lstat(path: &CStr, st: &mut [u64; 18]) -> usize {
    unsafe { syscall::sys_lstat(path.as_ptr() as usize, st.as_mut_ptr() as usize) }
}

#[inline]
pub(crate) fn stat_at(path: &CStr, st: &mut [u64; 18]) -> usize {
    unsafe { syscall::syscall4(syscall::SYS_NEWFSTATAT, AT_FDCWD, path.as_ptr() as usize, st.as_mut_ptr() as usize, 0) }
}

#[inline]
pub(crate) fn faccessat2(path: &CStr, mode: usize, flags: usize) -> usize {
    unsafe { syscall::syscall4(SYS_FACCESSAT2, AT_FDCWD, path.as_ptr() as usize, mode, flags) }
}

#[inline]
pub(crate) fn faccessat(path: &CStr, mode: usize) -> usize {
    unsafe { syscall::syscall3(SYS_FACCESSAT, AT_FDCWD, path.as_ptr() as usize, mode) }
}

#[inline]
pub(crate) fn getcwd(buf: &mut [u8]) -> usize {
    unsafe { syscall::syscall2(SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len()) }
}

#[inline]
pub(crate) fn readlink(path: &CStr, buf: &mut [u8]) -> usize {
    unsafe { syscall::syscall3(SYS_READLINK, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len()) }
}

#[inline]
pub(crate) fn sysinfo(info: &mut [u64; 14]) -> usize {
    unsafe { syscall::syscall1(SYS_SYSINFO, info.as_mut_ptr() as usize) }
}

#[inline]
pub(crate) fn ioctl_int(fd: i32, req: usize, v: &mut i32) -> usize {
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, req, v as *mut i32 as usize) }
}

#[inline]
pub(crate) fn kill(pid: i32, sig: i32) -> usize {
    unsafe { syscall::syscall2(SYS_KILL, pid as usize, sig as usize) }
}
