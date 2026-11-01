//! `__isctype` and the data symbol `__fpu_control`. (glibc's other internal-looking aliases such as
//! `__stpcpy`, `__sysconf`, `__isalnum_l`, `__memcmpeq`, `__strcoll_l`, `__newlocale` live next to their real functions, so that
//! using one does not pull unrelated crates into a program.)
use core::ffi::{c_int, c_ushort};
use rusty_libc_core::messages;

/// `__isctype(c, mask)`: the class bits of `c` ANDed with `mask` (what the ctype macros expand to).
#[unsafe(no_mangle)]
pub extern "C" fn __isctype(c: c_int, mask: c_int) -> c_int {
    c_int::from(rusty_libc_ctype::class_of(c)) & mask
}

/// The x87/SSE control word glibc's `fpu_control.h` reads (round to nearest, extended precision, all
/// exceptions masked).
#[unsafe(no_mangle)]
pub static __fpu_control: c_ushort = 0x037f;

// The old error-message table (GLIBC_2.2.5 .. 2.12 versions of these symbols, exported by glibc 2.43
// for old binaries; the newest version has 135 entries, NULL for numbers glibc does not know).
// `sys_errlist` and `_sys_errlist` are two copies of one array. Static libc.a only: libc.so.6 exports the versioned ones
// (compat_symver.rs) and no default version, so these would be two unused tables of 135 load-time relocations.
/// `_sys_errlist`: the messages by errno.
#[allow(non_upper_case_globals)]
#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
pub static _sys_errlist: messages::ErrPtrs = messages::err_ptrs();
/// `sys_errlist`: the same table.
#[allow(non_upper_case_globals)]
#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
pub static sys_errlist: messages::ErrPtrs = messages::err_ptrs();
/// `_sys_nerr`: the number of entries of `_sys_errlist`.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static _sys_nerr: c_int = 135;
/// `sys_nerr`: the same count.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static sys_nerr: c_int = 135;

/// `__cxa_at_quick_exit(func, dso)`: libc_nonshared.a's `at_quick_exit` (the one programs built against glibc call) forwards here.
/// The handler is tied to `dso`: `__cxa_finalize(dso)` (dlclose of that object) drops it without running it, as glibc does.
#[unsafe(no_mangle)]
pub extern "C" fn __cxa_at_quick_exit(func: Option<extern "C" fn()>, dso: *mut core::ffi::c_void) -> c_int {
    rusty_libc_stdlib::misc::at_quick_exit_dso(func, dso as usize)
}

