use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, syscall};

#[allow(non_camel_case_types)]
pub type ssize_t = isize;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> ssize_t {
    let ret = unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WRITE, fd as usize, buf as usize, count, 0, 0, 0) };
    match syscall::check(ret) {
        Ok(n) => n as ssize_t,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __write(fd: c_int, buf: *const c_void, count: usize) -> ssize_t {
    unsafe { write(fd, buf, count) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(status: c_int) -> ! {
    rusty_libc_core::process::exit_now(status)
}
