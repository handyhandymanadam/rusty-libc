use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::{i18n, messages};

#[cold]
#[inline(never)]
unsafe fn unknown_error_text(errnum: c_int, loc: usize) -> *mut c_char {
    let slot = messages::strerror_buf_slot();
    let old = unsafe { slot.read() };
    unsafe { rusty_libc_malloc::free(old.cast()) };
    unsafe { slot.write(core::ptr::null_mut()) };
    let prefix = unsafe { i18n::tr_l(c"Unknown error ", loc) }.to_bytes();
    let n = prefix.len() + 12;
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) } as *mut u8;
    if p.is_null() {
        return unsafe { i18n::tr_l(c"Unknown error", loc) }.as_ptr() as *mut c_char;
    }
    messages::write_prefixed_number(unsafe { rusty_libc_core::ffi::bytes_mut(p, n + 1) }, prefix, errnum);
    unsafe { slot.write(p) };
    p.cast()
}

#[inline(always)]
unsafe fn strerror_in(errnum: c_int, loc: usize) -> *mut c_char {
    match messages::error_message(errnum) {
        Some(m) => unsafe { i18n::tr_l(m, loc) }.as_ptr() as *mut c_char,
        None => {
            let saved = rusty_libc_core::errno::get();
            let p = unsafe { unknown_error_text(errnum, loc) };
            rusty_libc_core::errno::set(saved);
            p
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    unsafe { strerror_in(errnum, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_l(errnum: c_int, locale: *mut c_void) -> *mut c_char {
    unsafe { strerror_in(errnum, locale as usize) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char {
    if let Some(m) = messages::error_message_tr(errnum) {
        return m.as_ptr() as *mut c_char;
    }
    if buflen == 0 {
        return buf;
    }
    let b = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    messages::write_prefixed_number(b, i18n::tr(c"Unknown error ").to_bytes(), errnum);
    buf
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let buf = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    xpg_strerror_r(errnum, buf)
}

fn xpg_strerror_r(errnum: c_int, buf: &mut [u8]) -> c_int {
    let Some(m) = messages::error_message_tr(errnum) else {
        if !buf.is_empty() {
            messages::write_prefixed_number(buf, i18n::tr(c"Unknown error ").to_bytes(), errnum);
        }
        return 22;
    };
    let text = m.to_bytes();
    if buf.is_empty() {
        return 34;
    }
    let k = text.len().min(buf.len() - 1);
    buf[..k].copy_from_slice(&text[..k]);
    buf[k] = 0;
    if k < text.len() { 34 } else { 0 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrorname_np(errnum: c_int) -> *const c_char {
    messages::error_name(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrordesc_np(errnum: c_int) -> *const c_char {
    messages::error_message(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

fn strsignal_unknown(sig: c_int) -> *mut c_char {
    let slot = messages::strsignal_buf_slot();
    let old = unsafe { slot.read() };
    unsafe { rusty_libc_malloc::free(old.cast()) };
    unsafe { slot.write(core::ptr::null_mut()) };
    let rtmin = rusty_libc_signal::rt::__libc_current_sigrtmin();
    let rtmax = rusty_libc_signal::rt::__libc_current_sigrtmax();
    let (fmt, arg) = if sig >= rtmin && sig <= rtmax { (c"Real-time signal %d", sig - rtmin) } else { (c"Unknown signal %d", sig) };
    let mut tmp = [0u8; 256];
    let mut n = 0usize;
    let translated = i18n::tr_format(fmt, &[arg as u32 as u64], &mut |b: &[u8]| {
        let k = b.len().min(tmp.len() - 1 - n);
        tmp[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    });
    if !translated {
        let prefix: &[u8] = if fmt == c"Real-time signal %d" { b"Real-time signal " } else { b"Unknown signal " };
        n = messages::write_prefixed_number(&mut tmp, prefix, arg);
    }
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) } as *mut u8;
    if p.is_null() {
        return i18n::tr(c"Unknown signal").as_ptr() as *mut c_char;
    }
    let b = unsafe { rusty_libc_core::ffi::bytes_mut(p, n + 1) };
    b[..n].copy_from_slice(&tmp[..n]);
    b[n] = 0;
    unsafe { slot.write(p) };
    p.cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    match rusty_libc_signal::names::sigdescr_text(sig) {
        Some(m) => i18n::tr(m).as_ptr() as *mut c_char,
        None => strsignal_unknown(sig),
    }
}
