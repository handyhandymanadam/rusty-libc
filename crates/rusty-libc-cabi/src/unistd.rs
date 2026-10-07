use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, unistd};

#[allow(non_camel_case_types)]
pub type ssize_t = isize;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> ssize_t {
    let slice = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), count) };
    match unistd::write(fd, slice) {
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
