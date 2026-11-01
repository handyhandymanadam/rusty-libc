//! The resolver debugging helpers (resdebug.rs) against the host's libresolv: names, symbols, LOC text, message printing with
//! every `pfcode`, `inet_net_*`, `inet_neta`, host aliases and the answer parser of the old host lookups.
use crate::resdebug::{self, Sink};
use crate::resolv::{ResState, __res_state};
use core::ffi::{c_char, c_int, c_ulong, c_void};
use std::ffi::{CStr, CString};

mod host {
    use super::*;
    #[link(name = "resolv")]
    unsafe extern "C" {
        pub fn __p_type(t: c_int) -> *const c_char;
        pub fn __p_class(t: c_int) -> *const c_char;
        pub fn __p_rcode(t: c_int) -> *const c_char;
        pub fn __p_option(o: c_ulong) -> *const c_char;
        pub fn __p_time(v: u32) -> *const c_char;
        pub fn __dn_count_labels(n: *const c_char) -> c_int;
        pub fn __loc_aton(a: *const c_char, b: *mut u8) -> c_int;
        pub fn __fp_nquery(m: *const u8, len: c_int, f: *mut c_void);
        pub fn __fp_resstat(st: *const ResState, f: *mut c_void);
        pub fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int;
        pub fn inet_net_ntop(af: c_int, src: *const c_void, bits: c_int, dst: *mut c_char, size: usize) -> *const c_char;
        pub fn inet_neta(src: u32, dst: *mut c_char, size: usize) -> *const c_char;
        pub fn __res_state() -> *mut ResState;
        pub fn open_memstream(buf: *mut *mut c_char, size: *mut usize) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn free(p: *mut c_void);
    }
}

struct VecSink(Vec<u8>);
impl Sink for VecSink {
    fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

/// `__p_secstodate@GLIBC_2.2.5` is a compat symbol of libresolv: found at run time.
fn host_secstodate(v: c_ulong) -> String {
    unsafe {
        let h = libc::dlopen(c"libresolv.so.2".as_ptr(), libc::RTLD_NOW);
        assert!(!h.is_null());
        let f = libc::dlvsym(h, c"__p_secstodate".as_ptr(), c"GLIBC_2.2.5".as_ptr());
        assert!(!f.is_null());
        let f: extern "C" fn(c_ulong) -> *const c_char = core::mem::transmute(f);
        cs(f(v))
    }
}

fn cs(p: *const c_char) -> String {
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

fn host_capture(f: impl FnOnce(*mut c_void)) -> Vec<u8> {
    unsafe {
        let mut buf: *mut c_char = core::ptr::null_mut();
        let mut size = 0usize;
        let fp = host::open_memstream(&mut buf, &mut size);
        f(fp);
        host::fclose(fp);
        let v = if buf.is_null() { Vec::new() } else { core::slice::from_raw_parts(buf as *const u8, size).to_vec() };
        host::free(buf as *mut c_void);
        v
    }
}

fn build(opcode: u16, rcode: u16, flags: u16) -> Vec<u8> {
    let mut m = Vec::new();
    let put16 = |m: &mut Vec<u8>, v: u16| m.extend_from_slice(&v.to_be_bytes());
    let name = |m: &mut Vec<u8>, s: &str| {
        for l in s.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
    };
    let rr = |m: &mut Vec<u8>, ty: u16, class: u16, ttl: u32, rd: &[u8]| {
        m.extend_from_slice(&[0xc0, 12]);
        m.extend_from_slice(&ty.to_be_bytes());
        m.extend_from_slice(&class.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(rd);
    };
    put16(&mut m, 0x1234);
    put16(&mut m, 0x8000 | (opcode << 11) | flags | rcode);
    for c in [1u16, 6, 1, 1] {
        put16(&mut m, c);
    }
    name(&mut m, "example.com");
    put16(&mut m, 1);
    put16(&mut m, 1);
    rr(&mut m, 1, 1, 3600, &[1, 2, 3, 4]);
    rr(&mut m, 5, 1, 86400 * 8 + 5, &[3, b'w', b'w', b'w', 0xc0, 12]);
    rr(&mut m, 15, 1, 300, &[0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]);
    rr(&mut m, 16, 1, 60, b"\x05hello\x03\"x\\");
    rr(&mut m, 28, 1, 0, &[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    rr(&mut m, 999, 3, 7, &[0xde, 0xad]);
    m
}

#[test]
fn names_match_host() {
    unsafe {
        for t in 0..300 {
            assert_eq!(resdebug::type_str(t).as_bytes(), cs(host::__p_type(t)).as_bytes(), "type {t}");
            assert_eq!(resdebug::class_str(t).as_bytes(), cs(host::__p_class(t)).as_bytes(), "class {t}");
        }
        for r in 0..30 {
            assert_eq!(resdebug::rcode_str(r).as_bytes(), cs(host::__p_rcode(r)).as_bytes(), "rcode {r}");
        }
        for b in 0..40 {
            assert_eq!(resdebug::option_str(1 << b).as_bytes(), cs(host::__p_option(1 << b)).as_bytes(), "option bit {b}");
        }
        for v in [0u32, 1, 59, 60, 61, 3600, 86401, 604801, 0x7fffffff, u32::MAX] {
            assert_eq!(resdebug::time_str(v).as_bytes(), cs(host::__p_time(v)).as_bytes(), "ttl {v}");
        }
        for n in ["", ".", "a", "a.", "a.b.", "*.a.b", "*", "*.", "..", "www.example.com", "\\.a.b"] {
            let c = CString::new(n).unwrap();
            assert_eq!(resdebug::count_labels(n.as_bytes()), host::__dn_count_labels(c.as_ptr()), "labels {n:?}");
        }
        for s in [0u64, 1, 86399, 951782400, 1700000000, 2147483647] {
            assert_eq!(&resdebug::secstodate(s).unwrap()[..], host_secstodate(s).as_bytes(), "date {s}");
        }
        assert!(resdebug::secstodate(2147483648).is_err());
        assert_eq!(host_secstodate(2147483648), "<overflow>");
    }
}

#[test]
fn loc_aton_matches_host() {
    let texts = [
        "42 21 54 N 71 06 18 W -24m 30m",
        "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        "1 1 1 N 2 2 2 W 0m",
        "bogus",
        "42 N 71 W 1.5m 2.3m 4.4m 0.55m",
        "N 12",
        "10 S 20 E 5",
        "90 0 0.001 n 180 0 0 w 100000000m 1m 1m 1m",
        "42 21 54 N 71 06 18 W -24",
        "71 06 18 W 42 21 54 N 7m 3.14m",
        "",
        "42 21 54.5 N 71 06 18.25 W 123456789.99m 2m 2.5m 12345678m",
    ];
    for t in texts {
        let c = CString::new(t).unwrap();
        let mut hb = [0xaau8; 16];
        let hr = unsafe { host::__loc_aton(c.as_ptr(), hb.as_mut_ptr()) };
        match resdebug::loc_aton(t.as_bytes()) {
            Some(b) => {
                assert_eq!(hr, 16, "{t}");
                assert_eq!(b, hb, "{t}");
            }
            None => assert_eq!(hr, 0, "{t}"),
        }
    }
}

#[test]
fn message_printer_matches_host() {
    let _g = crate::LOCK.lock().unwrap();
    for (opcode, rcode, flags) in [(0, 0, 0x0180), (0, 3, 0x0180), (5, 0, 0x0180), (0, 0, 0x0780)] {
        let m = build(opcode, rcode, flags);
        for pf in [0u64, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x800, 0x1f0, 0xbf0, 0x30] {
            unsafe {
                (*host::__res_state()).pfcode = pf;
            }
            let want = host_capture(|f| unsafe { host::__fp_nquery(m.as_ptr(), m.len() as c_int, f) });
            let mut sink = VecSink(Vec::new());
            resdebug::render_fp_nquery(&m, pf, &mut sink);
            assert_eq!(String::from_utf8_lossy(&sink.0), String::from_utf8_lossy(&want), "opcode {opcode} rcode {rcode} pfcode {pf:#x}");
        }
        unsafe { (*host::__res_state()).pfcode = 0 };
        for cut in (0..=m.len()).step_by(5) {
            let want = host_capture(|f| unsafe { host::__fp_nquery(m.as_ptr(), cut as c_int, f) });
            let mut sink = VecSink(Vec::new());
            resdebug::render_fp_nquery(&m[..cut], 0, &mut sink);
            assert_eq!(String::from_utf8_lossy(&sink.0), String::from_utf8_lossy(&want), "cut {cut}");
        }
    }
}

#[test]
fn resstat_matches_host() {
    let _g = crate::LOCK.lock().unwrap();
    for o in [0u64, 1, 3, 8, 0x2a1, 0x1000, 0x4000, 0xffff_ffff, 0x1fff_ffff, 0x80_0000] {
        let mut st = ResState::zero();
        st.options = o;
        let want = host_capture(|f| unsafe { host::__fp_resstat(&st, f) });
        let mut sink = VecSink(Vec::new());
        resdebug::render_resstat(o, &mut sink);
        assert_eq!(sink.0, want, "options {o:#x}");
    }
    let _ = __res_state();
}

#[test]
fn inet_net_matches_host() {
    let strs = [
        "10", "10.1", "10.1.2", "10.1.2.3", "10.1.2.3/24", "10/8", "10.1/16", "192.168.1.0/24", "0x0a", "0x0a0102", "0xA0B0C0D0", "0x", "0xg",
        "1.2.3.4.5", "256.1.1.1", "1.2.3.4/33", "1.2.3.4/", "/8", "1.2.3.", "1..2", "224", "224.1", "192", "128", "240", "0", "0/0", "0.0.0.0/0", "1.2.3.4/32",
        "1.2.3.4/x", "1.2.3.4 ", " 1.2.3.4", "0x01/8", "0x0102/12", "1.2.3.4/032", "+1", "", "10.1.2.3/24junk", "0X1F", "99999999999",
    ];
    for s in strs {
        for size in [1usize, 3, 5, 8] {
            let c = CString::new(s).unwrap();
            let mut hb = [0x55u8; 8];
            let hr = unsafe { host::inet_net_pton(2, c.as_ptr(), hb.as_mut_ptr() as *mut c_void, size) };
            let mut ob = [0x55u8; 8];
            let or = resdebug::net_pton_ipv4(s.as_bytes(), &mut ob[..size]);
            match or {
                Ok(bits) => {
                    assert_eq!(hr, bits, "pton {s:?} size {size}");
                    assert_eq!(hb, ob, "pton bytes {s:?} size {size}");
                }
                Err(_) => assert_eq!(hr, -1, "pton {s:?} size {size}"),
            }
        }
    }
    for a in [0x0a010203u32, 0xc0a80100, 0xff000000, 0, 0xffffffff, 0x80000001] {
        for bits in -1..=33 {
            for size in [0usize, 7, 14] {
                let b = a.to_be_bytes();
                let mut buf = [b'q' as c_char; 64];
                let hr = unsafe { host::inet_net_ntop(2, b.as_ptr() as *const c_void, bits, buf.as_mut_ptr(), size) };
                let or = resdebug::net_ntop_ipv4(&b, bits, size);
                match or {
                    Ok(t) => {
                        assert!(!hr.is_null(), "ntop {a:#x}/{bits} size {size}");
                        assert_eq!(cs(hr).as_bytes(), t.as_bytes());
                    }
                    Err(_) => assert!(hr.is_null(), "ntop {a:#x}/{bits} size {size}"),
                }
            }
        }
    }
    for n in [0u32, 0x0a000000, 0x0a010000, 0x0a010200, 0x0a010203, 0xc0a80000, 0x00010000, 0x000000ff, 0xffffffff, 0x01000001] {
        for size in (0usize..20).step_by(3) {
            let mut buf = [b'q' as c_char; 64];
            let hr = unsafe { host::inet_neta(n, buf.as_mut_ptr(), size) };
            match resdebug::neta(n, size) {
                Some(t) => {
                    assert!(!hr.is_null(), "neta {n:#x} size {size}");
                    assert_eq!(cs(hr).as_bytes(), t.as_bytes());
                }
                None => assert!(hr.is_null(), "neta {n:#x} size {size}"),
            }
        }
    }
}
