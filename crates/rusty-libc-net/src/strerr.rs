//! gai_strerror, hstrerror, herror and `h_errno`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::cell::Cell;
use core::ffi::{c_char, c_int};

/// The message for a `getaddrinfo` error code (glibc 2.43's texts).
pub fn gai_message(code: c_int) -> &'static [u8] {
    match code {
        EAI_BADFLAGS => b"Bad value for ai_flags\0",
        EAI_NONAME => b"Name or service not known\0",
        EAI_AGAIN => b"Temporary failure in name resolution\0",
        EAI_FAIL => b"Non-recoverable failure in name resolution\0",
        EAI_NODATA => b"No address associated with hostname\0",
        EAI_FAMILY => b"ai_family not supported\0",
        EAI_SOCKTYPE => b"ai_socktype not supported\0",
        EAI_SERVICE => b"Servname not supported for ai_socktype\0",
        EAI_ADDRFAMILY => b"Address family for hostname not supported\0",
        EAI_MEMORY => b"Memory allocation failure\0",
        EAI_SYSTEM => b"System error\0",
        EAI_OVERFLOW => b"Result too large for supplied buffer\0",
        EAI_INPROGRESS => b"Processing request in progress\0",
        EAI_CANCELED => b"Request canceled\0",
        EAI_NOTCANCELED => b"Request not canceled\0",
        EAI_ALLDONE => b"All requests done\0",
        EAI_INTR => b"Interrupted by a signal\0",
        EAI_IDN_ENCODE => b"Parameter string not correctly encoded\0",
        0 => b"Success\0",
        _ => b"Unknown error\0",
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gai_strerror(code: c_int) -> *const c_char {
    // glibc: `_(result)`, translated in the calling thread's LC_MESSAGES locale
    tr(gai_message(code))
}

/// `_()` of one of the NUL-terminated message literals above.
fn tr(m: &'static [u8]) -> *const c_char {
    // SAFETY: every message here ends with its NUL.
    unsafe { rusty_libc_core::i18n::tr_ptr(m.as_ptr() as *const c_char) }
}

/// The message for a resolver (`h_errno`) code.
pub fn h_message(err: c_int) -> &'static [u8] {
    match err {
        e if e < 0 => b"Resolver internal error\0",
        NETDB_SUCCESS => b"Resolver Error 0 (no error)\0",
        HOST_NOT_FOUND => b"Unknown host\0",
        TRY_AGAIN => b"Host name lookup failure\0",
        NO_RECOVERY => b"Unknown server error\0",
        NO_DATA => b"No address associated with name\0",
        _ => b"Unknown resolver error\0",
    }
}

/// `h_errlist`: the old table of resolver error texts (indexes 0 to 4; deprecated, still exported by glibc).
#[repr(transparent)]
pub struct HErrList(pub [*const c_char; 5]);
// SAFETY: the pointers point at immutable string literals.
unsafe impl Sync for HErrList {}
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static h_errlist: HErrList = HErrList([
    c"Resolver Error 0 (no error)".as_ptr(),
    c"Unknown host".as_ptr(),
    c"Host name lookup failure".as_ptr(),
    c"Unknown server error".as_ptr(),
    c"No address associated with name".as_ptr(),
]);
/// `h_nerr`: the number of entries of `h_errlist`.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static h_nerr: c_int = 5;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hstrerror(err: c_int) -> *const c_char {
    // glibc: `_(h_errlist[err])` and the other texts through `_()`
    tr(h_message(err))
}

// the thread-local symbol `__h_errno` (GLIBC_PRIVATE in glibc) is this storage
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[thread_local]
pub static __h_errno: Cell<c_int> = Cell::new(0);

/// Current resolver error of this thread (`h_errno`).
pub fn h_errno() -> c_int {
    __h_errno.get()
}

/// Set `h_errno` of this thread.
pub fn set_h_errno(v: c_int) {
    __h_errno.set(v);
}

/// `&h_errno` (the C header defines `h_errno` as `(*__h_errno_location ())`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __h_errno_location() -> *mut c_int {
    __h_errno.as_ptr()
}

/// `herror`: "<s>: <message>\n" on standard error (the prefix and ": " only when `s` is non-empty).
///
/// # Safety
/// `s` is null or a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn herror(s: *const c_char) {
    // SAFETY: `s` is NULL or a C string (the caller's contract).
    let prefix = unsafe { rusty_libc_core::ffi::cstr(s) }.map(core::ffi::CStr::to_bytes);
    herror_bytes(prefix);
}

/// [`herror`] with the prefix as bytes (None for a NULL prefix).
pub fn herror_bytes(prefix: Option<&[u8]>) {
    let hp = hstrerror(h_errno());
    // SAFETY: hstrerror returns a NUL-terminated message (a literal or its translation, both kept for the process).
    let msg = unsafe { crate::util::cbytes(hp) };
    let mut out = crate::util::Buf::<512>::new();
    if let Some(p) = prefix {
        if !p.is_empty() {
            out.push_all(&p[..p.len().min(400)]);
            out.push_all(b": ");
        }
    }
    out.push_all(msg);
    out.push(b'\n');
    let _ = rusty_libc_core::unistd::write(2, out.as_bytes());
}
