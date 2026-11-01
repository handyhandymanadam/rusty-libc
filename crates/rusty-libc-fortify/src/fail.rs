//! The failure path: write "*** <what> ***: terminated" to standard error and abort, like glibc's
//! `__fortify_fail` over `__libc_message`.
use core::ffi::c_char;

/// Write the pieces to descriptor 2 in one buffer (resuming after a short write), then abort.
#[cold]
#[inline(never)]
pub fn message_abort(parts: &[&[u8]]) -> ! {
    let mut buf = [0u8; 512];
    let mut n = 0;
    for p in parts {
        let k = p.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    let mut off = 0;
    while off < n {
        match rusty_libc_core::unistd::write(2, &buf[off..n]) {
            Ok(k) => off += k,
            Err(e) if e.0 == 4 => {}
            Err(_) => break,
        }
    }
    rusty_libc_core::process::abort()
}

/// "*** <msg> ***: terminated\n" then abort.
#[cold]
#[inline(never)]
pub fn fortify_fail(msg: &[u8]) -> ! {
    message_abort(&[b"*** ", msg, b" ***: terminated\n"])
}

/// A fortified call would overflow its destination.
#[cold]
#[inline(never)]
pub fn chk_fail() -> ! {
    fortify_fail(b"buffer overflow detected")
}

/// # Safety
/// `msg` must be a NUL-terminated string.
#[cold]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fortify_fail(msg: *const c_char) -> ! {
    // SAFETY: `msg` is a NUL-terminated string (the caller's contract) that lives until the abort.
    fortify_fail(unsafe { rusty_libc_core::ffi::cstr_bytes(msg) })
}

#[cold]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __chk_fail() -> ! {
    chk_fail()
}
