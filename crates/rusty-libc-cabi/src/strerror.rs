use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::messages;

unsafe fn unknown_error_text(errnum: c_int) -> *mut c_char {
    unsafe {
        let slot = messages::strerror_buf_slot();
        rusty_libc_malloc::free((*slot).cast());
        *slot = core::ptr::null_mut();
        let mut tmp = [0u8; 40];
        let n = messages::write_unknown(&mut tmp, b"Unknown error ", errnum);
        let p = rusty_libc_malloc::malloc(n + 1) as *mut u8;
        if p.is_null() {
            return c"Unknown error".as_ptr() as *mut c_char;
        }
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), p, n + 1);
        *slot = p;
        p.cast()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    unsafe {
        match messages::error_message(errnum) {
            Some(m) => m.as_ptr() as *mut c_char,
            None => {
                let saved = rusty_libc_core::errno::get();
                let p = unknown_error_text(errnum);
                rusty_libc_core::errno::set(saved);
                p
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_l(errnum: c_int, _locale: *mut c_void) -> *mut c_char {
    unsafe { strerror(errnum) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char {
    unsafe {
        if let Some(m) = messages::error_message(errnum) {
            return m.as_ptr() as *mut c_char;
        }
        if buflen == 0 {
            return buf;
        }
        let mut tmp = [0u8; 40];
        let n = messages::write_unknown(&mut tmp, b"Unknown error ", errnum);
        let k = n.min(buflen - 1);
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf as *mut u8, k);
        *buf.add(k) = 0;
        buf
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let mut tmp = [0u8; 40];
        let (text, ret): (&[u8], c_int) = match messages::error_message(errnum) {
            Some(m) => (m.to_bytes(), 0),
            None => {
                let n = messages::write_unknown(&mut tmp, b"Unknown error ", errnum);
                (&tmp[..n], 22)
            }
        };
        if buflen == 0 {
            return 34;
        }
        let k = text.len().min(buflen - 1);
        core::ptr::copy_nonoverlapping(text.as_ptr(), buf as *mut u8, k);
        *buf.add(k) = 0;
        if k < text.len() { 34 } else { ret }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrorname_np(errnum: c_int) -> *const c_char {
    messages::error_name(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrordesc_np(errnum: c_int) -> *const c_char {
    messages::error_message(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

static mut UNKNOWN: [u8; 40] = [0; 40];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    unsafe {
        match messages::signal_message(sig) {
            Some(m) => m.as_ptr() as *mut c_char,
            None => {
                let buf = &mut *core::ptr::addr_of_mut!(UNKNOWN);
                messages::write_unknown(buf, b"Unknown signal ", sig);
                buf.as_mut_ptr().cast()
            }
        }
    }
}
