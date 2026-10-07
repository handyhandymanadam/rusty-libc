use core::ffi::c_char;

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

#[cold]
#[inline(never)]
pub fn fortify_fail(msg: &[u8]) -> ! {
    message_abort(&[b"*** ", msg, b" ***: terminated\n"])
}

#[cold]
#[inline(never)]
pub fn chk_fail() -> ! {
    fortify_fail(b"buffer overflow detected")
}

#[cold]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fortify_fail(msg: *const c_char) -> ! {
    unsafe {
        let n = rusty_libc_mem::strlen(msg);
        fortify_fail(core::slice::from_raw_parts(msg.cast::<u8>(), n))
    }
}

#[cold]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __chk_fail() -> ! {
    chk_fail()
}
