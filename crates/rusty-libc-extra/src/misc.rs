//! Small glibc interfaces: `ffs`, `ffsl`, `ffsll` (strings.h), `gnu_get_libc_version` and
//! `gnu_get_libc_release` (gnu/libc-version.h), `__isascii_l` and `__toascii_l` (ctype.h).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use rusty_libc_core::sync_cell::SyncCell;
use core::ffi::{c_char, c_int, c_long, c_longlong, c_void};

/// `ffs (i)`: the position (1 is the least significant bit) of the first bit set in `i`, 0 if none.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffs(i: c_int) -> c_int {
    if i == 0 { 0 } else { i.trailing_zeros() as c_int + 1 }
}

/// `ffsl (l)`: `ffs` of a long.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffsl(__l: c_long) -> c_int {
    if __l == 0 { 0 } else { __l.trailing_zeros() as c_int + 1 }
}

/// `ffsll (ll)`: `ffs` of a long long.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffsll(ll: c_longlong) -> c_int {
    if ll == 0 { 0 } else { ll.trailing_zeros() as c_int + 1 }
}

/// The version of the glibc this library follows (what the programs here see on the host).
pub const LIBC_VERSION: &core::ffi::CStr = c"2.43";
/// The release name: "stable" for a released glibc.
pub const LIBC_RELEASE: &core::ffi::CStr = c"stable";

/// `gnu_get_libc_version ()`: "2.43".
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_get_libc_version() -> *const c_char {
    LIBC_VERSION.as_ptr()
}

/// `gnu_get_libc_release ()`: "stable".
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_get_libc_release() -> *const c_char {
    LIBC_RELEASE.as_ptr()
}

/// `__isascii_l (c, locale)`: `c` fits in seven bits; the locale does not matter.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isascii_l(c: c_int, _locale: *mut c_void) -> c_int {
    ((c & !0x7f) == 0) as c_int
}

/// `__toascii_l (c, locale)`: the low seven bits of `c`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __toascii_l(c: c_int, _locale: *mut c_void) -> c_int {
    c & 0x7f
}

// ---- mcheck.h: in glibc 2.43 the checking heap lives in libc_malloc_debug.so (loaded with LD_PRELOAD); the
// functions in libc itself only answer "not enabled" (measured on the host: mcheck and mcheck_pedantic return -1
// before and after the first allocation, mprobe returns MCHECK_DISABLED for every pointer). Same here.

/// `mcheck (abortfunc)`: -1, consistency checking is not available in the library itself.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    -1
}

/// `mcheck_pedantic (abortfunc)`: -1.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck_pedantic(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    -1
}

/// `mcheck_check_all ()`: does nothing.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck_check_all() {}

/// `mprobe (ptr)`: `MCHECK_DISABLED` (-1).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mprobe(_ptr: *mut c_void) -> c_int {
    -1
}

/// `mtrace ()`: does nothing (allocation tracing is part of libc_malloc_debug in glibc 2.43).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mtrace() {}

/// `tr_break ()`: the empty function of mtrace's break point (a place for a debugger to stop at).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tr_break() {}

/// `mallwatch`: mtrace's address to watch (unused, as there is no tracing). A C data symbol (the same 8 bytes as a plain
/// pointer: `SyncCell` is `repr(transparent)`); the library never reads or writes it, so only the program's own accesses
/// (its rule) apply.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mallwatch: SyncCell<*mut c_void> = SyncCell::new(core::ptr::null_mut());

/// `muntrace ()`: does nothing.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn muntrace() {}
