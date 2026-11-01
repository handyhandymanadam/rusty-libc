//! unistd.h
use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, syscall};

#[allow(non_camel_case_types)]
pub type ssize_t = isize;

/// write(2).
///
/// # Safety
/// `buf` must be valid for reading `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> ssize_t {
    // SAFETY: write(2) reads `count` bytes at `buf`, which are readable (the contract; the kernel checks the pointer, and C
    // allows NULL with a count of 0); a cancellation point, as core's `unistd::write`. The pointer goes to the kernel as the
    // caller gave it (no slice: a NULL slice would be undefined behaviour in Rust).
    let ret = unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WRITE, fd as usize, buf as usize, count, 0, 0, 0) };
    match syscall::check(ret) {
        Ok(n) => n as ssize_t,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

/// glibc's internal name for `write`.
///
/// # Safety
/// As `write`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __write(fd: c_int, buf: *const c_void, count: usize) -> ssize_t {
    // SAFETY: the same contract.
    unsafe { write(fd, buf, count) }
}

/// _exit(2): terminate the process at once.
#[unsafe(no_mangle)]
pub extern "C" fn _exit(status: c_int) -> ! {
    rusty_libc_core::process::exit_now(status)
}
