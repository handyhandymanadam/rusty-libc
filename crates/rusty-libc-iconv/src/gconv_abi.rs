//! The layouts a gconv plug-in module sees, as `<gconv.h>` declares them: `struct __gconv_step`, `struct __gconv_step_data`,
//! the status codes and flags, and glibc's `struct __gconv_loaded_object` (the module's handle and entry points), plus the
//! pointer guard that glibc applies to the function pointers a loaded module's step holds.
// (the module interface is used by the shared build only; the static library shares the layouts and `__gconv_transliterate`)
#![cfg_attr(not(any(feature = "shared", test)), allow(dead_code))]
use core::ffi::{c_char, c_int, c_void};

/// `__GCONV_*` status codes.
pub(crate) const OK: c_int = 0;
pub(crate) const NOCONV: c_int = 1;
pub(crate) const NODB: c_int = 2;
pub(crate) const EMPTY_INPUT: c_int = 4;
pub(crate) const FULL_OUTPUT: c_int = 5;
pub(crate) const ILLEGAL_INPUT: c_int = 6;
pub(crate) const INCOMPLETE_INPUT: c_int = 7;
pub(crate) const ILLEGAL_DESCRIPTOR: c_int = 8;

/// `__GCONV_IS_LAST` and the other flags of a step's data.
pub(crate) const IS_LAST: c_int = 0x0001;
pub(crate) const IGNORE_ERRORS: c_int = 0x0002;
pub(crate) const TRANSLIT: c_int = 0x0008;
/// `__GCONV_ENCOUNTERED_ILLEGAL_INPUT` (iconv/gconv_int.h): set in a step's flags when it met illegal input.
pub(crate) const ENCOUNTERED_ILLEGAL_INPUT: c_int = 1 << 30;

/// How many characters one conversion call should produce (glibc's `GCONV_NCHAR_GOAL`): the size of the buffer between steps.
pub(crate) const NCHAR_GOAL: usize = 8160;

/// `__gconv_fct`: the conversion function of a step.
pub(crate) type GconvFn = unsafe extern "C" fn(
    step: *mut Step,
    data: *mut StepData,
    inptrp: *mut *const u8,
    inend: *const u8,
    outbufstart: *mut *mut u8,
    irreversible: *mut usize,
    do_flush: c_int,
    consume_incomplete: c_int,
) -> c_int;

/// `__gconv_init_fct`.
pub(crate) type InitFn = unsafe extern "C" fn(step: *mut Step) -> c_int;
/// `__gconv_end_fct`.
pub(crate) type EndFn = unsafe extern "C" fn(step: *mut Step);

/// glibc's `struct __gconv_loaded_object` (iconv/gconv_int.h): one loaded module. `fct`, `init_fct` and `end_fct` are
/// the module's `gconv`, `gconv_init` and `gconv_end`, pointer-guarded as glibc keeps them.
#[repr(C)]
pub struct LoadedObject {
    pub name: *const c_char,
    pub counter: c_int,
    pub handle: *mut c_void,
    pub fct: usize,
    pub init_fct: usize,
    pub end_fct: usize,
}

/// `struct __gconv_step`.
#[repr(C)]
pub struct Step {
    pub shlib_handle: *mut LoadedObject,
    pub modname: *const c_char,
    pub counter: c_int,
    pub from_name: *mut c_char,
    pub to_name: *mut c_char,
    pub fct: usize,
    pub btowc_fct: usize,
    pub init_fct: usize,
    pub end_fct: usize,
    pub min_needed_from: c_int,
    pub max_needed_from: c_int,
    pub min_needed_to: c_int,
    pub max_needed_to: c_int,
    pub stateful: c_int,
    pub data: *mut c_void,
}

/// `struct __gconv_step_data`.
#[repr(C)]
pub struct StepData {
    pub outbuf: *mut u8,
    pub outbufend: *mut u8,
    pub flags: c_int,
    pub invocation_counter: c_int,
    pub internal_use: c_int,
    pub statep: *mut c_void,
    pub state: [c_int; 2],
}

/// The head of `struct __gconv_info` (`__gconv_t`): the step count and the steps, followed in memory by `nsteps` step data.
#[repr(C)]
pub(crate) struct InfoHead {
    pub nsteps: usize,
    pub steps: *mut Step,
}

/// glibc's `PTR_MANGLE` of the pointer guard in the thread control block (`%fs:0x30`): xor with the guard, then rotate left
/// by 17 bits on x86-64.
#[cfg(not(test))]
fn pointer_guard() -> usize {
    // SAFETY: the calling thread's control block is set up by the startup code before any C function runs.
    unsafe { (*rusty_libc_core::tls::current()).pointer_guard }
}

/// Test builds run on the host's libc, whose thread control block is not ours: use a fixed guard (nothing outside the
/// test reads the mangled pointers).
#[cfg(test)]
fn pointer_guard() -> usize {
    0x5a5a_1234
}

/// `PTR_MANGLE`.
pub(crate) fn mangle(p: usize) -> usize {
    (p ^ pointer_guard()).rotate_left(0x11)
}

/// `PTR_DEMANGLE`.
pub(crate) fn demangle(p: usize) -> usize {
    p.rotate_right(0x11) ^ pointer_guard()
}

/// The conversion function of `step`: modules keep theirs mangled, built-in steps (no shared object) do not.
///
/// # Safety
/// `step` points to a step whose `fct` is a real conversion function (mangled if `shlib_handle` is set), or NULL.
pub(crate) unsafe fn step_fct(step: *const Step) -> Option<GconvFn> {
    // SAFETY: `step` is a valid step (the caller's contract), only read.
    let fct = unsafe { (*step).fct };
    // SAFETY: as above.
    let module = unsafe { !(*step).shlib_handle.is_null() };
    let addr = if module { demangle(fct) } else { fct };
    if addr == 0 {
        return None;
    }
    // SAFETY: a non-NULL `fct` is the address of a function with this signature (the caller's contract).
    Some(unsafe { core::mem::transmute::<usize, GconvFn>(addr) })
}
