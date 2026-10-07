use crate::misc::sc;
use core::ffi::{c_int, c_ulong};
use rusty_libc_core::syscall::{SYS_IOCTL, check, syscall3};
use rusty_libc_core::Errno;

pub unsafe fn ioctl_r(fd: i32, request: u64, arg: usize) -> Result<usize, Errno> {
    unsafe { check(syscall3(SYS_IOCTL, fd as usize, request as usize, arg)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, mut args: ...) -> c_int {
    unsafe {
        let arg = args.next_arg::<usize>();
        sc(syscall3(SYS_IOCTL, fd as usize, request as usize, arg)) as c_int
    }
}

