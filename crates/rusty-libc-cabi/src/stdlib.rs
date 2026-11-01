//! stdlib.h
use core::ffi::{c_int, c_void};

/// exit(3): run the atexit handlers (last registered first), flush every stdio stream, terminate.
#[unsafe(no_mangle)]
#[allow(suspicious_runtime_symbol_definitions)]
pub extern "C" fn exit(status: c_int) -> ! {
    rusty_libc_core::process::exit(status)
}

/// atexit(3): returns 0 on success, nonzero if the table is full.
#[unsafe(no_mangle)]
pub extern "C" fn atexit(function: Option<extern "C" fn()>) -> c_int {
    let Some(function) = function else { rusty_libc_core::process::exit_func_is_null() };
    if rusty_libc_core::process::atexit(function) { 0 } else { -1 }
}

/// abort(3): raise SIGABRT; never returns.
#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    rusty_libc_core::process::abort()
}

/// _Exit(3): terminate at once, like `_exit`.
#[unsafe(no_mangle)]
pub extern "C" fn _Exit(status: c_int) -> ! {
    rusty_libc_core::process::exit_now(status)
}

/// Called by compiler-generated code when a stack canary was overwritten (gcc `-fstack-protector`):
/// print glibc's message on standard error and abort.
#[unsafe(no_mangle)]
pub extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"*** stack smashing detected ***: terminated\n";
    let _ = rusty_libc_core::unistd::write_nocancel(2, msg);
    rusty_libc_core::process::abort()
}

/// `__cxa_atexit(f, arg, dso_handle)`: what C++ (and Rust's std on glibc) use to register static
/// destructors; `exit` runs them with `atexit` handlers, last registered first, as `f(arg, status)` like glibc (a
/// destructor declared with one parameter ignores the second).
///
/// # Safety
/// `f` must be callable with `arg`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(f: Option<unsafe extern "C" fn(*mut c_void)>, arg: *mut c_void, dso: *mut c_void) -> c_int {
    let Some(f) = f else { rusty_libc_core::process::exit_func_is_null() };
    if rusty_libc_core::process::register(rusty_libc_core::process::ExitFn::Cxa(f, arg, dso as usize)) { 0 } else { -1 }
}

/// `__cxa_finalize(dso)`: run and remove the `__cxa_atexit` handlers registered with `dso` (every `atexit` and
/// `__cxa_atexit` handler when `dso` is NULL) and drop its `at_quick_exit` handlers, as glibc 2.43.
#[unsafe(no_mangle)]
pub extern "C" fn __cxa_finalize(dso: *mut c_void) {
    rusty_libc_core::process::finalize(dso as usize);
}

/// `__cxa_thread_atexit_impl(f, obj, dso)`: run `f(obj)` when the calling thread exits (C++
/// `thread_local` destructors); the object `dso` points into stays loaded until then (dlclose keeps it, as glibc).
///
/// # Safety
/// `f` must be callable with `obj`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit_impl(f: Option<unsafe extern "C" fn(*mut c_void)>, obj: *mut c_void, dso: *mut c_void) -> c_int {
    let Some(f) = f else { return -1 };
    if rusty_libc_core::tls::register_thread_dtor(f, obj, dso as usize) { 0 } else { -1 }
}
