use core::ffi::{c_int, c_void};

#[unsafe(no_mangle)]
#[allow(suspicious_runtime_symbol_definitions)]
pub extern "C" fn exit(status: c_int) -> ! {
    rusty_libc_core::process::exit(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn atexit(function: Option<extern "C" fn()>) -> c_int {
    let Some(function) = function else { rusty_libc_core::process::exit_func_is_null() };
    if rusty_libc_core::process::atexit(function) { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    rusty_libc_core::process::abort()
}

#[unsafe(no_mangle)]
pub extern "C" fn _Exit(status: c_int) -> ! {
    rusty_libc_core::process::exit_now(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"*** stack smashing detected ***: terminated\n";
    unsafe { rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, 2, msg.as_ptr() as usize, msg.len()) };
    rusty_libc_core::process::abort()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(f: Option<unsafe extern "C" fn(*mut c_void)>, arg: *mut c_void, dso: *mut c_void) -> c_int {
    let Some(f) = f else { rusty_libc_core::process::exit_func_is_null() };
    if rusty_libc_core::process::register(rusty_libc_core::process::ExitFn::Cxa(f, arg, dso as usize)) { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub extern "C" fn __cxa_finalize(dso: *mut c_void) {
    rusty_libc_core::process::finalize(dso as usize);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit_impl(f: Option<unsafe extern "C" fn(*mut c_void)>, obj: *mut c_void, _dso: *mut c_void) -> c_int {
    let Some(f) = f else { return -1 };
    if rusty_libc_core::tls::register_thread_dtor(f, obj) { 0 } else { -1 }
}
