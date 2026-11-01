//! The registered conversions through the Rust API (typed argument slices instead of a C va_list).
use core::ffi::{c_int, c_void};
use rusty_libc_stdio::printf_ext::{self, PrintfInfo};
use rusty_libc_stdio::rust_api::{Arg, snprintf};

unsafe extern "C" fn z_handler(fp: *mut rusty_libc_stdio::file::File, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
    unsafe {
        let v = **(args as *const *const c_int);
        let mut b = *b"<   >\0";
        b[1] = b'0' + (v % 10) as u8;
        b[2] = if (*info).width > 0 { b'w' } else { b'-' };
        b[3] = if (*info).prec >= 0 { b'p' } else { b'-' };
        rusty_libc_stdio::fputs(b.as_ptr().cast(), fp)
    }
}

unsafe extern "C" fn z_info(_i: *const PrintfInfo, n: usize, t: *mut c_int, _s: *mut c_int) -> c_int {
    unsafe {
        if n >= 1 {
            *t = printf_ext::PA_INT;
        }
    }
    1
}

#[test]
fn rust_api_with_registry() {
    let mut buf = [0u8; 200];
    let n = snprintf(&mut buf, c"[%d|%s|%5.1f]", &[Arg::Int(5), Arg::Str(c"str"), Arg::Double(2.25)]);
    assert_eq!(&buf[..n as usize], b"[5|str|  2.2]");
    assert_eq!(printf_ext::register_printf_specifier(i32::from(b'N'), Some(z_handler), Some(z_info)), 0);
    let n = snprintf(&mut buf, c"[%d|%s|%5.1f]", &[Arg::Int(5), Arg::Str(c"str"), Arg::Double(2.25)]);
    assert_eq!(&buf[..n as usize], b"[5|str|  2.2]");
    let n = snprintf(&mut buf, c"[%5.2N|%d|%s]", &[Arg::Int(7), Arg::Int(-3), Arg::Str(c"str")]);
    assert_eq!(&buf[..n as usize], b"[<7wp>|-3|str]");
}
