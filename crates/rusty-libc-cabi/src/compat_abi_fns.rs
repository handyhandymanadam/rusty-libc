use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::{errno, syscall};

const EINVAL: i32 = 22;
const SYS_STAT: usize = 4;
const SYS_FSTAT: usize = 5;
const SYS_LSTAT: usize = 6;
const SYS_NEWFSTATAT: usize = 262;
const SYS_MKNOD: usize = 133;
const SYS_MKNODAT: usize = 259;
const SYS_GETPGID: usize = 121;

fn ver_ok(vers: c_int) -> bool {
    vers == 0 || vers == 1
}

unsafe fn call(nr: usize, a: usize, b: usize, c: usize, d: usize) -> c_int {
    unsafe {
        let r = syscall::syscall4(nr, a, b, c, d);
        if r > usize::MAX - 4095 {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        } else {
            r as c_int
        }
    }
}

fn einval() -> c_int {
    errno::set(EINVAL);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xstat(vers: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
    if !ver_ok(vers) {
        return einval();
    }
    unsafe { call(SYS_STAT, path as usize, buf as usize, 0, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xstat64(vers: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { __xstat(vers, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __lxstat(vers: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
    if !ver_ok(vers) {
        return einval();
    }
    unsafe { call(SYS_LSTAT, path as usize, buf as usize, 0, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __lxstat64(vers: c_int, path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { __lxstat(vers, path, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstat(vers: c_int, fd: c_int, buf: *mut c_void) -> c_int {
    if !ver_ok(vers) {
        return einval();
    }
    unsafe { call(SYS_FSTAT, fd as usize, buf as usize, 0, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstat64(vers: c_int, fd: c_int, buf: *mut c_void) -> c_int {
    unsafe { __fxstat(vers, fd, buf) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstatat(vers: c_int, dirfd: c_int, path: *const c_char, buf: *mut c_void, flags: c_int) -> c_int {
    if !ver_ok(vers) {
        return einval();
    }
    unsafe { call(SYS_NEWFSTATAT, dirfd as isize as usize, path as usize, buf as usize, flags as isize as usize) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fxstatat64(vers: c_int, dirfd: c_int, path: *const c_char, buf: *mut c_void, flags: c_int) -> c_int {
    unsafe { __fxstatat(vers, dirfd, path, buf, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xmknod(vers: c_int, path: *const c_char, mode: u32, dev: *const u64) -> c_int {
    if vers != 0 {
        return einval();
    }
    unsafe { call(SYS_MKNOD, path as usize, mode as usize, *dev as usize, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xmknodat(vers: c_int, dirfd: c_int, path: *const c_char, mode: u32, dev: *const u64) -> c_int {
    if vers != 0 {
        return einval();
    }
    unsafe { call(SYS_MKNODAT, dirfd as isize as usize, path as usize, mode as usize, *dev as usize) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_freeres() {
    unsafe { rusty_libc_stdio::file::freeres() }
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_init_first(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_sa_len(family: u16) -> c_int {
    match family {
        1 => 110,
        2 => 16,
        10 => 28,
        16 => 12,
        17 => 20,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __bsd_getpgrp(pid: c_int) -> c_int {
    unsafe { call(SYS_GETPGID, pid as usize, 0, 0, 0) }
}
