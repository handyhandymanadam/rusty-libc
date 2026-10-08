use core::ffi::{c_int, c_ushort};
use rusty_libc_core::messages;

#[unsafe(no_mangle)]
pub extern "C" fn __isctype(c: c_int, mask: c_int) -> c_int {
    c_int::from(rusty_libc_ctype::class_of(c)) & mask
}

#[unsafe(no_mangle)]
pub static __fpu_control: c_ushort = 0x037f;

#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static _sys_errlist: messages::ErrPtrs = messages::err_ptrs();
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static sys_errlist: messages::ErrPtrs = messages::err_ptrs();
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static _sys_nerr: c_int = 135;
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static sys_nerr: c_int = 135;

#[unsafe(no_mangle)]
pub extern "C" fn __cxa_at_quick_exit(func: Option<extern "C" fn()>, _dso: *mut core::ffi::c_void) -> c_int {
    rusty_libc_stdlib::misc::at_quick_exit(func)
}

