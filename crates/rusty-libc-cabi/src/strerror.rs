//! string.h: error and signal messages (`strerror` and friends, `strsignal`).
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::{i18n, messages};

/// "Unknown error N" as glibc makes it (`__strerror_l`): `_("Unknown error ")` in the locale `loc` and the number, in a
/// malloc'd buffer owned by the calling thread (the previous one is freed first); when malloc fails the text is
/// `_("Unknown error")` alone (glibc's tst-strerror-fail interposes malloc to check it).
///
/// # Safety
/// `loc` is 0, LC_GLOBAL_LOCALE or a locale object.
#[cold]
#[inline(never)]
unsafe fn unknown_error_text(errnum: c_int, loc: usize) -> *mut c_char {
    let slot = messages::strerror_buf_slot();
    // SAFETY: `slot` is the calling thread's buffer slot (a thread-local cell only this thread uses).
    let old = unsafe { slot.read() };
    // SAFETY: NULL or the buffer the previous call malloc'd; the slot is cleared next, so nothing refers to it after this.
    unsafe { rusty_libc_malloc::free(old.cast()) };
    // SAFETY: as above.
    unsafe { slot.write(core::ptr::null_mut()) };
    // SAFETY: forwarded contract.
    let prefix = unsafe { i18n::tr_l(c"Unknown error ", loc) }.to_bytes();
    let n = prefix.len() + 12;
    // SAFETY: malloc has no precondition.
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) } as *mut u8;
    if p.is_null() {
        // SAFETY: forwarded contract.
        return unsafe { i18n::tr_l(c"Unknown error", loc) }.as_ptr() as *mut c_char;
    }
    // SAFETY: `p` is a fresh block of `n + 1` bytes, ours alone.
    messages::write_prefixed_number(unsafe { rusty_libc_core::ffi::bytes_mut(p, n + 1) }, prefix, errnum);
    // SAFETY: the calling thread's slot, as above.
    unsafe { slot.write(p) };
    p.cast()
}

/// glibc's `__strerror_l`: the message in the LC_MESSAGES locale of `loc` (0: the calling thread's), errno kept.
///
/// # Safety
/// `loc` is 0, LC_GLOBAL_LOCALE or a locale object.
#[inline(always)]
unsafe fn strerror_in(errnum: c_int, loc: usize) -> *mut c_char {
    match messages::error_message(errnum) {
        // SAFETY: forwarded contract.
        Some(m) => unsafe { i18n::tr_l(m, loc) }.as_ptr() as *mut c_char,
        None => {
            let saved = rusty_libc_core::errno::get();
            // SAFETY: forwarded contract.
            let p = unsafe { unknown_error_text(errnum, loc) };
            rusty_libc_core::errno::set(saved);
            p
        }
    }
}

/// The message for an error number ("No such file or directory"), translated in the calling thread's LC_MESSAGES
/// locale; an unknown number gives "Unknown error N" in a buffer that the next call overwrites.
///
/// # Safety
/// The result must not be written to or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    // SAFETY: 0 is the calling thread's locale.
    unsafe { strerror_in(errnum, 0) }
}

/// `strerror` in the LC_MESSAGES locale of `locale` (glibc switches to it with `uselocale` for the lookup).
///
/// # Safety
/// As `strerror`; `locale` is a locale object or LC_GLOBAL_LOCALE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_l(errnum: c_int, locale: *mut c_void) -> *mut c_char {
    // SAFETY: `locale` is a locale object or LC_GLOBAL_LOCALE (the contract).
    unsafe { strerror_in(errnum, locale as usize) }
}

/// GNU `strerror_r`: the (translated) message, in static storage when the number is known, else
/// `_("Unknown error ")` and the number in `buf` (glibc's `snprintf(buf, buflen, "%s%d", ...)`).
///
/// # Safety
/// `buf` must be valid for `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char {
    if let Some(m) = messages::error_message_tr(errnum) {
        return m.as_ptr() as *mut c_char;
    }
    if buflen == 0 {
        return buf;
    }
    // SAFETY: `buf` is writable for `buflen` bytes (the contract).
    let b = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    messages::write_prefixed_number(b, i18n::tr(c"Unknown error ").to_bytes(), errnum);
    buf
}

/// POSIX `strerror_r`: copy the message into `buf`; 0, or ERANGE if it was cut, or EINVAL for an
/// unknown number (the "Unknown error N" text is still stored).
///
/// # Safety
/// `buf` must be valid for `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    // SAFETY: `buf` is writable for `buflen` bytes (the contract; nothing is written when `buflen` is 0).
    let buf = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), buflen) };
    xpg_strerror_r(errnum, buf)
}

/// [`__xpg_strerror_r`] on the buffer.
fn xpg_strerror_r(errnum: c_int, buf: &mut [u8]) -> c_int {
    // glibc: an unknown number is EINVAL whatever the buffer size (its text, cut to the buffer, is still written); a known
    // one that does not fit is ERANGE
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

/// The macro name of an error number ("ENOENT"), or NULL.
///
/// # Safety
/// The result must not be written to or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrorname_np(errnum: c_int) -> *const c_char {
    messages::error_name(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

/// The message of an error number without any "Unknown error" fallback: NULL for an unknown one.
///
/// # Safety
/// The result must not be written to or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerrordesc_np(errnum: c_int) -> *const c_char {
    messages::error_message(errnum).map_or(core::ptr::null(), |n| n.as_ptr())
}

/// "Real-time signal N" / "Unknown signal N" (glibc's `strsignal`): the translated format run with the number, in a
/// malloc'd buffer of the calling thread that the next such call frees; `_("Unknown signal")` when malloc fails.
fn strsignal_unknown(sig: c_int) -> *mut c_char {
    let slot = messages::strsignal_buf_slot();
    // SAFETY: `slot` is the calling thread's buffer slot (a thread-local cell only this thread uses).
    let old = unsafe { slot.read() };
    // SAFETY: NULL or the buffer the previous call malloc'd; the slot is cleared next, so nothing refers to it after this.
    unsafe { rusty_libc_malloc::free(old.cast()) };
    // SAFETY: as above.
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
    // SAFETY: malloc has no precondition.
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) } as *mut u8;
    if p.is_null() {
        return i18n::tr(c"Unknown signal").as_ptr() as *mut c_char;
    }
    // SAFETY: `p` is a fresh block of `n + 1` bytes, ours alone.
    let b = unsafe { rusty_libc_core::ffi::bytes_mut(p, n + 1) };
    b[..n].copy_from_slice(&tmp[..n]);
    b[n] = 0;
    // SAFETY: the calling thread's slot, as above.
    unsafe { slot.write(p) };
    p.cast()
}

/// The description of a signal ("Interrupt"), translated in the calling thread's LC_MESSAGES locale; a real-time
/// signal gives "Real-time signal N" (N counted from SIGRTMIN), anything else "Unknown signal N", in a buffer of the
/// calling thread that the next such call overwrites.
///
/// # Safety
/// The result must not be written to or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    match rusty_libc_signal::names::sigdescr_text(sig) {
        Some(m) => i18n::tr(m).as_ptr() as *mut c_char,
        None => strsignal_unknown(sig),
    }
}
