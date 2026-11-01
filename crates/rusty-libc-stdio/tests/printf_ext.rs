#![allow(clippy::approx_constant, clippy::byte_char_slices)]
//! printf.h extensions (register_printf_specifier, _modifier, _type, parse_printf_format, printf_size):
//! the same handlers are registered with our library and with the host glibc, and the same formats and
//! arguments go through both; bytes, return value and errno must agree. This is an integration test so
//! that the registrations (global, permanent) stay in a process of their own.
#![allow(clippy::type_complexity)]
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_stdio::printf_ext::PrintfInfo;
use std::ffi::CString;

type OurFile = rusty_libc_stdio::file::File;
type HostFile = c_void;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn snprintf(buf: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
        pub fn fprintf(f: *mut HostFile, fmt: *const c_char, ...) -> c_int;
        pub fn fputs(s: *const c_char, f: *mut HostFile) -> c_int;
        pub fn register_printf_specifier(spec: c_int, f: Option<unsafe extern "C" fn(*mut HostFile, *const PrintfInfo, *const *const c_void) -> c_int>, a: Option<unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int, *mut c_int) -> c_int>) -> c_int;
        pub fn register_printf_function(spec: c_int, f: Option<unsafe extern "C" fn(*mut HostFile, *const PrintfInfo, *const *const c_void) -> c_int>, a: Option<unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int) -> c_int>) -> c_int;
        pub fn register_printf_modifier(s: *const i32) -> c_int;
        pub fn register_printf_type(f: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>) -> c_int;
        pub fn parse_printf_format(fmt: *const c_char, n: usize, types: *mut c_int) -> usize;
        pub fn printf_size(f: *mut HostFile, i: *const PrintfInfo, a: *const *const c_void) -> c_int;
        pub fn printf_size_info(i: *const PrintfInfo, n: usize, t: *mut c_int) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}

// ---- the handlers, written once for each library's stream functions

macro_rules! handlers {
    ($m:ident, $file:ty, $fprintf:path, $fputs:path, $user_va:ty) => {
        mod $m {
            use super::*;
            const USER_TYPE_SLOT: usize = 0;
            pub static USER_TYPE: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
            #[repr(C)]
            struct Pair {
                i: c_long,
                d: f64,
            }

            /// %N: one int; prints what the handler is told.
            pub unsafe extern "C" fn z(fp: *mut $file, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let i = &*info;
                    let v = **(args as *const *const c_int);
                    $fprintf(fp, c"<N w=%d p=%d f=%x u=%x pad=%d s=%c v=%d>".as_ptr(), i.width, i.prec, c_int::from(i.flags & 0x1fff), c_int::from(i.user), i.pad, i.spec, v)
                }
            }
            pub unsafe extern "C" fn z_info(_i: *const PrintfInfo, n: usize, t: *mut c_int, s: *mut c_int) -> c_int {
                unsafe {
                    if n >= 1 {
                        *t = 0; // PA_INT
                        *s = -1;
                    }
                    1
                }
            }
            /// %Y: an int and a double.
            pub unsafe extern "C" fn y(fp: *mut $file, _info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let a = **(args as *const *const c_int);
                    let b = **(args.add(1) as *const *const f64);
                    $fprintf(fp, c"<Y a=%d b=%g>".as_ptr(), a, b)
                }
            }
            pub unsafe extern "C" fn y_info(_i: *const PrintfInfo, n: usize, t: *mut c_int, _s: *mut c_int) -> c_int {
                unsafe {
                    if n >= 1 {
                        *t = 0;
                    }
                    if n >= 2 {
                        *t.add(1) = 7; // PA_DOUBLE
                    }
                    2
                }
            }
            /// %W: declines odd numbers (-2: the built-in conversion, here "unknown", prints it), prints even ones.
            pub unsafe extern "C" fn w(fp: *mut $file, _info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let v = **(args as *const *const c_int);
                    if v % 2 != 0 {
                        return -2;
                    }
                    $fprintf(fp, c"even(%d)".as_ptr(), v)
                }
            }
            /// %V: writes something, then fails for negative numbers.
            pub unsafe extern "C" fn v(fp: *mut $file, _info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let v = **(args as *const *const c_int);
                    $fputs(c"partial".as_ptr(), fp);
                    if v < 0 { -1 } else { $fprintf(fp, c"ok%d".as_ptr(), v) }
                }
            }
            /// %x overridden: prints "X<value>" for positive numbers and leaves negative ones to the built-in.
            pub unsafe extern "C" fn xo(fp: *mut $file, _info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let v = **(args as *const *const c_int);
                    if v < 0 { -2 } else { $fprintf(fp, c"X<%d>".as_ptr(), v) }
                }
            }
            /// %P: a user type: pairs (long, double), precision = number of pairs.
            pub unsafe extern "C" fn p(fp: *mut $file, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
                unsafe {
                    let i = &*info;
                    let nargs = if i.prec >= 0 { i.prec as usize } else { 1 };
                    let mut printed = 0;
                    for k in 0..nargs {
                        if k > 0 {
                            $fputs(c",".as_ptr(), fp);
                            printed += 1;
                        }
                        // triple indirection: args[k] points at a slot that holds the pointer to the memory
                        let pair = *(*args.add(k) as *const *const Pair);
                        let r = $fprintf(fp, c"(%ld, %f)".as_ptr(), (*pair).i, (*pair).d);
                        if r < 0 {
                            return -1;
                        }
                        printed += r;
                    }
                    printed
                }
            }
            pub unsafe extern "C" fn p_info(info: *const PrintfInfo, n: usize, t: *mut c_int, s: *mut c_int) -> c_int {
                unsafe {
                    let i = &*info;
                    if i.spec != c_int::from(b'P') {
                        return -1;
                    }
                    let nargs = if i.prec >= 0 { i.prec as usize } else { 1 };
                    for k in 0..nargs.min(n) {
                        *t.add(k) = USER_TYPE.load(core::sync::atomic::Ordering::SeqCst);
                        *s.add(k) = size_of::<Pair>() as c_int;
                    }
                    nargs as c_int
                }
            }
            pub unsafe extern "C" fn p_va(mem: *mut c_void, ap: *mut c_void) {
                unsafe {
                    let _ = USER_TYPE_SLOT;
                    // `ap` is a `va_list *`: take a long and a double the way va_arg does on x86-64
                    let rec = ap as *mut VaRec;
                    let pair = mem as *mut Pair;
                    (*pair).i = take_gp(rec) as c_long;
                    (*pair).d = take_fp(rec);
                }
            }
            #[allow(dead_code)]
            pub type Unused = $user_va;
        }
    };
}

/// The System V x86-64 `va_list` record, to take arguments in the user type function.
#[repr(C)]
struct VaRec {
    gp_offset: u32,
    fp_offset: u32,
    overflow: *mut u8,
    reg_save: *mut u8,
}

unsafe fn take_gp(r: *mut VaRec) -> u64 {
    unsafe {
        if (*r).gp_offset < 48 {
            let v = *((*r).reg_save.add((*r).gp_offset as usize) as *const u64);
            (*r).gp_offset += 8;
            v
        } else {
            let v = *((*r).overflow as *const u64);
            (*r).overflow = (*r).overflow.add(8);
            v
        }
    }
}

unsafe fn take_fp(r: *mut VaRec) -> f64 {
    unsafe {
        if (*r).fp_offset < 176 {
            let v = *((*r).reg_save.add((*r).fp_offset as usize) as *const f64);
            (*r).fp_offset += 16;
            v
        } else {
            let v = *((*r).overflow as *const f64);
            (*r).overflow = (*r).overflow.add(8);
            v
        }
    }
}

handlers!(ours_h, OurFile, rusty_libc_stdio::fprintf, rusty_libc_stdio::fputs, ());
handlers!(host_h, HostFile, host::fprintf, host::fputs, ());

type Out = (Vec<u8>, c_int, c_int);

fn ours(f: impl FnOnce(*mut c_char, usize) -> c_int) -> Out {
    let mut buf = vec![0xAAu8; 4200];
    rusty_libc_core::errno::set(0);
    let r = f(buf.as_mut_ptr().cast(), 4096);
    let e = rusty_libc_core::errno::get();
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    (buf, r, if r < 0 { e } else { 0 })
}

fn host_(f: impl FnOnce(*mut c_char, usize) -> c_int) -> Out {
    let mut buf = vec![0xAAu8; 4200];
    unsafe { *host::__errno_location() = 0 };
    let r = f(buf.as_mut_ptr().cast(), 4096);
    let e = unsafe { *host::__errno_location() };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    (buf, r, if r < 0 { e } else { 0 })
}

macro_rules! both {
    ($fmt:expr $(, $a:expr)*) => {{
        let f = CString::new($fmt).unwrap();
        let o = ours(|b, n| rusty_libc_stdio::snprintf(b, n, f.as_ptr() $(, $a)*));
        let h = host_(|b, n| host::snprintf(b, n, f.as_ptr() $(, $a)*));
        assert_eq!(o, h, "format {:?}: ours {:?} host {:?}", $fmt, String::from_utf8_lossy(&o.0), String::from_utf8_lossy(&h.0));
        o
    }};
}

#[test]
fn registered_conversions_match_glibc() {
    assert!(!rusty_libc_stdio::printf_ext::active(), "nothing is registered yet");
    unsafe {
        // before registration both do the ordinary thing
        both!("[%d %s %5.2f]", 42 as c_int, c"x".as_ptr(), 3.14159f64);

        // register the same set with both libraries
        assert_eq!(rusty_libc_stdio::register_printf_specifier(i32::from(b'N'), Some(ours_h::z), Some(ours_h::z_info)), 0);
        assert_eq!(host::register_printf_specifier(i32::from(b'N'), Some(host_h::z), Some(host_h::z_info)), 0);
        assert!(rusty_libc_stdio::printf_ext::active());
        assert_eq!(rusty_libc_stdio::register_printf_specifier(i32::from(b'Y'), Some(ours_h::y), Some(ours_h::y_info)), 0);
        assert_eq!(host::register_printf_specifier(i32::from(b'Y'), Some(host_h::y), Some(host_h::y_info)), 0);
        for (spec, o, h, io, ih) in [
            (b'W', ours_h::w as unsafe extern "C" fn(_, _, _) -> c_int, host_h::w as unsafe extern "C" fn(_, _, _) -> c_int, ours_h::z_info as unsafe extern "C" fn(_, _, _, _) -> c_int, host_h::z_info as unsafe extern "C" fn(_, _, _, _) -> c_int),
            (b'V', ours_h::v, host_h::v, ours_h::z_info, host_h::z_info),
            (b'x', ours_h::xo, host_h::xo, ours_h::z_info, host_h::z_info),
        ] {
            assert_eq!(rusty_libc_stdio::register_printf_specifier(i32::from(spec), Some(o), Some(io)), 0);
            assert_eq!(host::register_printf_specifier(i32::from(spec), Some(h), Some(ih)), 0);
        }
        // the old registration function
        unsafe extern "C" fn old_info_ours(_i: *const PrintfInfo, n: usize, t: *mut c_int) -> c_int {
            unsafe {
                if n >= 1 {
                    *t = 0;
                }
            }
            1
        }
        assert_eq!(rusty_libc_stdio::register_printf_function(i32::from(b'O'), Some(ours_h::z), Some(old_info_ours)), 0);
        assert_eq!(host::register_printf_function(i32::from(b'O'), Some(host_h::z), Some(old_info_ours)), 0);
        // a user type
        let ot = rusty_libc_stdio::register_printf_type(Some(ours_h::p_va));
        let ht = host::register_printf_type(Some(host_h::p_va));
        assert!(ot >= 8 && ot == ht, "{ot} {ht}");
        ours_h::USER_TYPE.store(ot, core::sync::atomic::Ordering::SeqCst);
        host_h::USER_TYPE.store(ht, core::sync::atomic::Ordering::SeqCst);
        assert_eq!(rusty_libc_stdio::register_printf_specifier(i32::from(b'P'), Some(ours_h::p), Some(ours_h::p_info)), 0);
        assert_eq!(host::register_printf_specifier(i32::from(b'P'), Some(host_h::p), Some(host_h::p_info)), 0);
        // printf_size
        for c in [b'b', b'B'] {
            assert_eq!(rusty_libc_stdio::register_printf_function(i32::from(c), Some(rusty_libc_stdio::printf_size), Some(rusty_libc_stdio::printf_size_info)), 0);
            assert_eq!(host::register_printf_function(i32::from(c), Some(host::printf_size), Some(host::printf_size_info)), 0);
        }
        // modifiers
        let q = [i32::from(b'Q'), 0];
        let qq = [i32::from(b'Q'), i32::from(b'Q'), 0];
        let rr = [i32::from(b'R'), i32::from(b'S'), i32::from(b'T'), 0];
        for m in [&q[..], &qq[..], &rr[..]] {
            let a = rusty_libc_stdio::register_printf_modifier(m.as_ptr());
            let h = host::register_printf_modifier(m.as_ptr());
            assert!(a > 0 && a == h, "{a} {h}");
        }
        // errors
        let empty = [0i32];
        let wide = [0x100i32, 0];
        let neg = [-1i32, 0];
        for bad in [&empty[..], &wide[..], &neg[..]] {
            rusty_libc_core::errno::set(0);
            *host::__errno_location() = 0;
            assert_eq!(rusty_libc_stdio::register_printf_modifier(bad.as_ptr()), -1);
            assert_eq!(host::register_printf_modifier(bad.as_ptr()), -1);
            assert_eq!(rusty_libc_core::errno::get(), *host::__errno_location());
        }
        assert_eq!(rusty_libc_stdio::register_printf_specifier(256, Some(ours_h::z), None), -1);
        assert_eq!(rusty_libc_core::errno::get(), 22);
        assert_eq!(rusty_libc_stdio::register_printf_specifier(-1, Some(ours_h::z), None), -1);
    }

    // ---- the registered conversions
    unsafe {
        let i = 7 as c_int;
        for fmt in ["%N", "%5N", "%-5N", "%05N", "%+N", "% N", "%#N", "%'N", "%IN", "%.3N", "%.N", "%8.3N", "%-+ #0'I8.2N", "%hN", "%hhN", "%lN", "%llN", "%LN", "%qN", "%zN", "%jN", "%tN", "%ON", "%O", "%5O", "%QN", "%QQN", "%RSTN", "%RN", "%QQQN", "%QRN", "a%Nb%Nc"] {
            if fmt.matches('N').count() == 2 {
                both!(fmt, i, i + 1);
            } else if fmt.contains('O') && !fmt.contains('N') {
                both!(fmt, i);
            } else {
                both!(fmt, i);
            }
        }
        both!("%*N|%-*N", 6 as c_int, i, 6 as c_int, i);
        both!("%*N|%-*N", -6 as c_int, i, -6 as c_int, i);
        both!("%.*N|%*.*N", 4 as c_int, i, 9 as c_int, -3 as c_int, i);
        both!("%2$N %1$N", i, 99 as c_int);
        both!("%1$N %1$N", i);
        both!("%3$*1$.*2$N", 10 as c_int, 4 as c_int, i);
        both!("%Y", 3 as c_int, 2.5f64);
        both!("[%Y][%Y]", 3 as c_int, 2.5f64, 4 as c_int, -0.125f64);
        both!("%d %Y %s", 1 as c_int, 3 as c_int, 2.5f64, c"str".as_ptr());
        // declining and failing handlers
        for v in [2 as c_int, 3, 0, -4, -5] {
            both!("<%W>", v);
            both!("<%5W>", v);
            both!("<%V>", v);
            both!("[%d%V%d]", 1 as c_int, v, 2 as c_int);
        }
        // an overridden built-in
        for v in [5 as c_int, 0, -1, 255] {
            both!("%x|%08x|%#x|%X", v, v, v, v);
        }
        // user type
        both!("[[%P]]", 123 as c_long, 456.0f64);
        both!("[[%.2P]]", 1 as c_long, 2.5f64, 3 as c_long, 4.5f64);
        both!("%1$P %1$P", 123 as c_long, 457.0f64);
        both!("%.0P|%d", 5 as c_int);
        both!("%P %Y %P", 1 as c_long, 1.5f64, 7 as c_int, 2.5f64, 2 as c_long, 2.5f64);
        // printf_size, with the strings of glibc's test and more
        let v = 11774.75614f64 * 1024.0 * 1024.0;
        both!("%g %b %B %.0b %.0B %.1b %.1B %8.0b %08.0B", 12345678.9f64, 1025.0f64, v, v, v, v, v, v, v);
        both!("%b|%B|%-20.2b|%-10.0b|%-10.8b|%-10.2B|", v, v, v, v, v, v);
        both!("%#.0B %*.0b %10.*b %*.*B %10.2B", v, 2 as c_int, v, 2 as c_int, v, 10 as c_int, 2 as c_int, v, v);
        both!("%6B %6.1B %b %B %b %B", v, v, 1000.0f64, 1000.0f64, 1024.0f64, 1024.0f64);
        for x in [0.0f64, 1.0, 1023.0, 1024.0, 1e10, 1e30, 1e300, -5.0, -1e9, f64::INFINITY, -f64::INFINITY, f64::NAN] {
            both!("%b|%B|%10b|%-10B|%+b|% B|%.0b|%#b|%010b", x, x, x, x, x, x, x, x, x);
        }
        // built-ins keep working
        let s = c"text".as_ptr();
        both!("%d|%5d|%-5d|%05d|%+d|%x|%o|%u|%c|%s|%10s|%.2s|%f|%e|%g|%a|%p|%%|%5%", -5 as c_int, 5 as c_int, 5 as c_int, 5 as c_int, 5 as c_int, 255 as c_int, 8 as c_int, 3 as c_int, 65 as c_int, s, s, s, 1.5f64, 1.5f64, 1.5f64, 1.5f64, core::ptr::null::<c_void>());
        both!("%ld %lld %hd %hhd %zd %jd %td %lu", 1 as c_long, 2 as c_long, 3 as c_int, 4 as c_int, 5 as c_long, 6 as c_long, 7 as c_long, 8 as c_long);
        both!("%3$s %1$d %2$s", 1 as c_int, s, s);
        both!("%*d|%-*d|%.*f", 5 as c_int, 3 as c_int, 5 as c_int, 3 as c_int, 2 as c_int, 3.14159f64);
        both!("%m");
        both!("%5m|");
        both!("%Q");
        both!("%k %K %y");
        both!("%5.3k|");
        both!("%-+ #0'Ik|");
        both!("%");
        both!("abc%");
        both!("%5");
        both!("%5.");
        both!("%.*", 3 as c_int);
        both!("%w8d %w16d %w32d %w64d %wf8d %wf16d %wf32d %wf64d", 1 as c_int, 2 as c_int, 3 as c_int, 4 as c_long, 5 as c_int, 6 as c_long, 7 as c_long, 8 as c_long);
        both!("%w9d", 1 as c_int);
        both!("%w0d", 1 as c_int);
        both!("plain text only");
        both!("");
        // %n counts through user conversions
        let (mut n1, mut n2) = (-1 as c_int, -1 as c_int);
        let f = c"ab%Nc%n d";
        let o = ours(|b, n| rusty_libc_stdio::snprintf(b, n, f.as_ptr(), i, &mut n1 as *mut c_int));
        let h = host_(|b, n| host::snprintf(b, n, f.as_ptr(), i, &mut n2 as *mut c_int));
        assert_eq!(o, h);
        assert_eq!(n1, n2, "%n value");
        let (mut s1, mut s2) = (-1i16, -1i16);
        let f = c"%hn xyz";
        rusty_libc_stdio::snprintf(vec![0u8; 100].as_mut_ptr().cast(), 100, f.as_ptr(), &mut s1 as *mut i16);
        host::snprintf(vec![0u8; 100].as_mut_ptr().cast(), 100, f.as_ptr(), &mut s2 as *mut i16);
        assert_eq!(s1, s2);
        // errno is visible to %m
        rusty_libc_core::errno::set(2);
        *host::__errno_location() = 2;
        let o = ours(|b, n| {
            rusty_libc_core::errno::set(2);
            rusty_libc_stdio::snprintf(b, n, c"%m".as_ptr())
        });
        let h = host_(|b, n| {
            *host::__errno_location() = 2;
            host::snprintf(b, n, c"%m".as_ptr())
        });
        assert_eq!(o, h);
        // many conversions of one argument (positional)
        let mut o = vec![0u8; 20000];
        let mut h = vec![0u8; 20000];
        // 300 int arguments through a pointer-free path: use the positional form instead
        let mut posfmt = String::new();
        for k in 0..300 {
            posfmt.push_str(&format!("t{k}[%1$N]"));
        }
        let pf = CString::new(posfmt).unwrap();
        let ro = rusty_libc_stdio::snprintf(o.as_mut_ptr().cast(), o.len(), pf.as_ptr(), 5 as c_int);
        let rh = host::snprintf(h.as_mut_ptr().cast(), h.len(), pf.as_ptr(), 5 as c_int);
        assert_eq!((ro, &o[..ro as usize]), (rh, &h[..rh as usize]));
    }

    // ---- parse_printf_format
    unsafe {
        for fmt in [
            "", "plain", "%d", "%s %d %f", "%ld %lld %hd %hhd %Lf %lf %c %C %S %p %n", "%*d", "%.*f", "%*.*f", "%2$d %1$s", "%3$*1$.*2$f", "%N", "%Y", "%P", "%b %B", "%Q", "%QN", "%%", "%5%",
            "%zd %td %jd %qd", "%w8d", "%w9d", "%m", "%1$N %1$Y %2$d", "%hN %lN %LN", "%e %E %g %G %a %A %F", "%u %o %x %X %i", "%O %5O", "%k",
        ] {
            let cf = CString::new(fmt).unwrap();
            for n in [0usize, 1, 2, 3, 8, 20] {
                let mut a = vec![-77 as c_int; 24];
                let mut b = vec![-77 as c_int; 24];
                let ra = rusty_libc_stdio::parse_printf_format(cf.as_ptr(), n, a.as_mut_ptr());
                let rb = host::parse_printf_format(cf.as_ptr(), n, b.as_mut_ptr());
                assert_eq!((ra, &a), (rb, &b), "parse_printf_format({fmt:?}, {n})");
            }
        }
    }

    // a user conversion that takes several arguments (glibc's own parse_printf_format hands such an arginfo
    // function one int for all the sizes and overflows it, so only ours is run)
    unsafe {
        let mut a = vec![-77 as c_int; 6];
        let r = rusty_libc_stdio::parse_printf_format(c"%.3P".as_ptr(), 2, a.as_mut_ptr());
        let t = ours_h::USER_TYPE.load(core::sync::atomic::Ordering::SeqCst);
        assert_eq!((r, &a[..3]), (3, &[t, t, -77][..]));
    }

    // ---- calling the printf_size functions directly
    unsafe {
        let info = PrintfInfo { prec: 2, width: 12, spec: i32::from(b'b'), flags: 0, user: 0, pad: i32::from(b' ') };
        let mut t = [0 as c_int; 2];
        assert_eq!(rusty_libc_stdio::printf_size_info(&info, 1, t.as_mut_ptr()), 1);
        assert_eq!(t[0], 7);
        let info2 = PrintfInfo { flags: 1, ..info };
        assert_eq!(rusty_libc_stdio::printf_size_info(&info2, 1, t.as_mut_ptr()), 1);
        assert_eq!(t[0], 7 | 256);
        assert_eq!(rusty_libc_stdio::printf_size_info(&info2, 0, t.as_mut_ptr()), 1);
    }
}
