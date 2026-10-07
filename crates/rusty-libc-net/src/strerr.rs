use crate::types::*;
use core::cell::Cell;
use core::ffi::{c_char, c_int};

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
    gai_message(code).as_ptr() as *const c_char
}

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

#[repr(transparent)]
pub struct HErrList(pub [*const c_char; 5]);
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
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static h_nerr: c_int = 5;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hstrerror(err: c_int) -> *const c_char {
    h_message(err).as_ptr() as *const c_char
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[thread_local]
pub static __h_errno: Cell<c_int> = Cell::new(0);

pub fn h_errno() -> c_int {
    __h_errno.get()
}

pub fn set_h_errno(v: c_int) {
    __h_errno.set(v);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __h_errno_location() -> *mut c_int {
    __h_errno.as_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn herror(s: *const c_char) {
    let msg = h_message(h_errno());
    let msg = &msg[..msg.len() - 1];
    let mut out = crate::util::Buf::<512>::new();
    if !s.is_null() {
        let p = unsafe { crate::util::cbytes(s) };
        if !p.is_empty() {
            out.push_all(&p[..p.len().min(400)]);
            out.push_all(b": ");
        }
    }
    out.push_all(msg);
    out.push(b'\n');
    let _ = rusty_libc_core::unistd::write(2, out.as_bytes());
}
