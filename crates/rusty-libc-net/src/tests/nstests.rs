//! nsparse against the host's libresolv: the same messages (a hand-built one, its truncations and random
//! mutations) through both, every result, errno and printed text compared.
use super::*;
use crate::nsparse::*;
use core::ffi::{c_char, c_int, c_ulong};

mod host {
    use super::*;
    #[link(name = "resolv")]
    unsafe extern "C" {
        pub fn ns_initparse(msg: *const u8, len: c_int, h: *mut ns_msg) -> c_int;
        pub fn ns_parserr(h: *mut ns_msg, section: c_int, rrnum: c_int, rr: *mut ns_rr) -> c_int;
        pub fn ns_skiprr(ptr: *const u8, eom: *const u8, section: c_int, count: c_int) -> c_int;
        pub fn ns_sprintrr(h: *const ns_msg, rr: *const ns_rr, ctx: *const c_char, origin: *const c_char, buf: *mut c_char, len: usize) -> c_int;
        pub fn ns_sprintrrf(msg: *const u8, msglen: usize, name: *const c_char, class: c_int, ty: c_int, ttl: c_ulong, rdata: *const u8, rdlen: usize, ctx: *const c_char, origin: *const c_char, buf: *mut c_char, len: usize) -> c_int;
        pub fn ns_msg_getflag(h: ns_msg, flag: c_int) -> c_int;
        pub fn ns_format_ttl(v: c_ulong, dst: *mut c_char, len: usize) -> c_int;
        pub fn ns_parse_ttl(src: *const c_char, dst: *mut c_ulong) -> c_int;
        pub fn ns_datetosecs(cp: *const c_char, errp: *mut c_int) -> u32;
        pub fn ns_samedomain(a: *const c_char, b: *const c_char) -> c_int;
        pub fn ns_subdomain(a: *const c_char, b: *const c_char) -> c_int;
        pub fn ns_samename(a: *const c_char, b: *const c_char) -> c_int;
        pub fn ns_makecanon(src: *const c_char, dst: *mut c_char, size: usize) -> c_int;
        pub fn ns_name_ntol(src: *const u8, dst: *mut u8, size: usize) -> c_int;
        pub fn __loc_ntoa(bin: *const u8, ascii: *mut c_char) -> *const c_char;
    }
}

fn herrno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn set_herrno(v: i32) {
    unsafe { *libc::__errno_location() = v };
}

const MSG: [u8; 182] = [
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22, 0x03, 0x77, 0x77, 0x77, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x06, 0x03, 0x77, 0x65, 0x62, 0xc0, 0x0c, 0xc0, 0x0c, 0x00,
    0x0f, 0x00, 0x01, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x09, 0x00, 0x0a, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x0b, 0x06, 0x76, 0x3d, 0x73, 0x70,
    0x66, 0x31, 0x03, 0x61, 0x22, 0x62, 0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x4d, 0x00, 0x27, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72,
    0xc0, 0x0c, 0x78, 0xa3, 0xf1, 0x75, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x03,
    0xe8, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
];

const ORIGINS: [Option<&std::ffi::CStr>; 4] = [None, Some(c"example.com."), Some(c"."), Some(c"com")];
const CTXS: [Option<&std::ffi::CStr>; 3] = [None, Some(c"example.com"), Some(c"other.org.")];

fn opt(c: Option<&std::ffi::CStr>) -> *const c_char {
    c.map_or(core::ptr::null(), |c| c.as_ptr())
}

/// Parse `m` with both libraries and compare every step; returns the number of records that parsed.
fn compare_message(m: &[u8]) -> usize {
    let mut a = ns_msg::zero();
    let mut b = ns_msg::zero();
    rusty_libc_core::errno::set(0);
    let ra = unsafe { ns_initparse(m.as_ptr(), m.len() as c_int, &mut a) };
    let ea = rusty_libc_core::errno::get();
    set_herrno(0);
    let rb = unsafe { host::ns_initparse(m.as_ptr(), m.len() as c_int, &mut b) };
    let eb = herrno();
    assert_eq!(ra, rb, "initparse rc for {m:02x?}");
    if ra < 0 {
        assert_eq!(ea, eb, "initparse errno for {m:02x?}");
    }
    // the handle, including what a failed call leaves in it
    assert_eq!((a._id, a._flags, a._counts, a._sect, a._rrnum), (b._id, b._flags, b._counts, b._sect, b._rrnum), "handle for {m:02x?}");
    if ra < 0 {
        return 0;
    }
    for f in 0..16 {
        assert_eq!(ns_msg_getflag(a, f), unsafe { host::ns_msg_getflag(b, f) }, "flag {f}");
    }
    let mut parsed = 0;
    for s in 0..4 {
        for i in 0..a._counts[s as usize] as c_int {
            let mut ra_ = ns_rr::zero();
            let mut rb_ = ns_rr::zero();
            rusty_libc_core::errno::set(0);
            let x = unsafe { ns_parserr(&mut a, s, i, &mut ra_) };
            let ex = rusty_libc_core::errno::get();
            set_herrno(0);
            let y = unsafe { host::ns_parserr(&mut b, s, i, &mut rb_) };
            let ey = herrno();
            assert_eq!(x, y, "parserr rc {s}/{i} for {m:02x?}");
            assert_eq!((a._sect, a._rrnum), (b._sect, b._rrnum), "handle after parserr");
            if x < 0 {
                assert_eq!(ex, ey, "parserr errno {s}/{i}");
                continue;
            }
            parsed += 1;
            assert_eq!((ra_.name, ra_.type_, ra_.rr_class, ra_.ttl, ra_.rdlength), (rb_.name, rb_.type_, rb_.rr_class, rb_.ttl, rb_.rdlength), "rr fields {s}/{i}");
            for origin in ORIGINS {
                for ctx in CTXS {
                    for size in [0usize, 7, 40, 300, 2000] {
                        let mut oa = vec![0x55 as c_char; size.max(1)];
                        let mut ob = vec![0x55 as c_char; size.max(1)];
                        rusty_libc_core::errno::set(0);
                        let p = unsafe { ns_sprintrr(&a, &ra_, opt(ctx), opt(origin), oa.as_mut_ptr(), size) };
                        let ep = rusty_libc_core::errno::get();
                        set_herrno(0);
                        let q = unsafe { host::ns_sprintrr(&b, &rb_, opt(ctx), opt(origin), ob.as_mut_ptr(), size) };
                        let eq = herrno();
                        assert_eq!(p, q, "sprintrr rc {s}/{i} {origin:?} {ctx:?} {size}");
                        assert_eq!(ep, eq, "sprintrr errno {s}/{i} {origin:?} {ctx:?} {size}");
                        assert_eq!(oa, ob, "sprintrr buffer {s}/{i} {origin:?} {ctx:?} {size}");
                    }
                }
            }
        }
    }
    parsed
}

#[test]
fn messages_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(compare_message(&MSG), 1 + 4 + 1 + 1);
    // every truncation
    for n in 0..=MSG.len() {
        compare_message(&MSG[..n]);
    }
    // random mutations
    let mut r = Rng(0x5eed);
    let mut whole = 0;
    for _ in 0..1500 {
        let mut m = MSG.to_vec();
        for _ in 0..1 + r.below(3) {
            let pos = r.below(m.len());
            m[pos] = match r.below(4) {
                0 => r.next() as u8,
                1 => 0xc0,
                2 => 0,
                _ => 0xff,
            };
        }
        let keep = if r.below(8) == 0 { m.len() - r.below(10) } else { m.len() };
        if compare_message(&m[..keep]) > 0 {
            whole += 1;
        }
    }
    assert!(whole > 500, "only {whole} mutations parsed");
}

#[test]
fn sprintrrf_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xfeed);
    let types = [1, 2, 5, 6, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 26, 28, 29, 33, 35, 38, 39, 41, 46, 99, 250, 4242];
    for _ in 0..4000 {
        let ty = types[r.below(types.len())];
        let class = [1, 3, 4, 255, 7, 4096][r.below(6)];
        let rdlen = r.below(40);
        let mut msg = vec![0u8; 12];
        let rd: Vec<u8> = (0..rdlen)
            .map(|_| match r.below(6) {
                0 => 0,
                1 => 3,
                2 => b'a' + r.below(26) as u8,
                3 => 0xc0,
                _ => r.next() as u8,
            })
            .collect();
        msg.extend_from_slice(&rd);
        let ttl = [0u64, 59, 3600, 90061, 694861, 4294967295][r.below(6)];
        let name = [c"", c".", c"a.example.com.", c"example.com", c"x\\.y."][r.below(5)];
        let (origin, ctx) = (ORIGINS[r.below(4)], CTXS[r.below(3)]);
        for size in [0usize, 5, 30, 100, 600] {
            let mut oa = vec![0 as c_char; size.max(1)];
            let mut ob = vec![0 as c_char; size.max(1)];
            rusty_libc_core::errno::set(0);
            let p = unsafe { ns_sprintrrf(msg.as_ptr(), msg.len(), name.as_ptr(), class, ty, ttl as c_ulong, msg.as_ptr().add(12), rdlen, opt(ctx), opt(origin), oa.as_mut_ptr(), size) };
            let ep = rusty_libc_core::errno::get();
            set_herrno(0);
            let q = unsafe { host::ns_sprintrrf(msg.as_ptr(), msg.len(), name.as_ptr(), class, ty, ttl as c_ulong, msg.as_ptr().add(12), rdlen, opt(ctx), opt(origin), ob.as_mut_ptr(), size) };
            let eq = herrno();
            assert_eq!((p, ep, &oa), (q, eq, &ob), "sprintrrf type {ty} class {class} rdata {rd:02x?} origin {origin:?} ctx {ctx:?} size {size}");
        }
    }
}

#[test]
fn loc_text_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x10c);
    for i in 0..5000 {
        let mut b = [0u8; 16];
        for x in &mut b {
            *x = r.next() as u8;
        }
        b[0] = if i % 7 == 0 { 1 } else { 0 };
        if i % 3 == 0 {
            b[4] = [0x00, 0x7f, 0x80, 0xff][r.below(4)];
            b[8] = [0x00, 0x7f, 0x80, 0xff][r.below(4)];
        }
        let mut oa = [0 as c_char; 128];
        let mut ob = [0 as c_char; 128];
        unsafe {
            __loc_ntoa(b.as_ptr(), oa.as_mut_ptr());
            host::__loc_ntoa(b.as_ptr(), ob.as_mut_ptr());
        }
        assert_eq!(oa, ob, "loc {b:02x?}");
    }
}

#[test]
fn ttl_date_names_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x771);
    let mut vals: Vec<u64> = vec![0, 1, 59, 60, 61, 3600, 86400, 604800, 694861, u32::MAX as u64, 1 << 32, 1 << 40, u64::MAX, 2147483648 * 604800, 4294967296 * 604800];
    for _ in 0..3000 {
        vals.push(r.next() >> r.below(60));
    }
    for v in vals {
        for size in [0usize, 1, 3, 5, 10, 11, 64] {
            let mut oa = [b'Z' as c_char; 80];
            let mut ob = [b'Z' as c_char; 80];
            let p = unsafe { ns_format_ttl(v as c_ulong, oa.as_mut_ptr(), size) };
            let q = unsafe { host::ns_format_ttl(v as c_ulong, ob.as_mut_ptr(), size) };
            assert_eq!((p, oa), (q, ob), "format_ttl({v}, {size})");
        }
    }
    let texts = ["1w2d3h4m5s", "1W", "3600", "0", "", "w", "1x", "5s5", " 1", "1d1d", "99999999999999999999", "18446744073709551616", "1h30", "1h30m", "2H2h", "00s", "1\u{7f}", "-1", "s1", "1ss", "12345678901234567890s"];
    for t in texts {
        let c = CString::new(t).unwrap();
        let (mut a, mut b) = (0x1234 as c_ulong, 0x1234 as c_ulong);
        rusty_libc_core::errno::set(0);
        let p = unsafe { ns_parse_ttl(c.as_ptr(), &mut a) };
        let ep = rusty_libc_core::errno::get();
        set_herrno(0);
        let q = unsafe { host::ns_parse_ttl(c.as_ptr(), &mut b) };
        assert_eq!((p, a), (q, b), "parse_ttl({t:?})");
        if p < 0 {
            assert_eq!(ep, herrno(), "parse_ttl errno {t:?}");
        }
    }
    let dates = ["19900101000000", "19700101000000", "20240229123456", "20230229123456", "21000229000000", "99991231235959", "20241301000000", "2024010100000", "2024010100000a", "20240231000000", "20991231235959", ""];
    for t in dates {
        let c = CString::new(t).unwrap();
        let (mut ea, mut eb) = (77, 77);
        let p = unsafe { ns_datetosecs(c.as_ptr(), &mut ea) };
        let q = unsafe { host::ns_datetosecs(c.as_ptr(), &mut eb) };
        assert_eq!((p, ea), (q, eb), "datetosecs({t:?})");
    }
    let names = ["", ".", "a", "a.", "a..", "A.B", "www.example.com", "www.example.com.", "WWW.EXAMPLE.COM", "example.com", "com", "foo\\.", "foo\\\\.", "x.foo\\.bar.com", "bar.com", "foobar.com", "\\.", "a\\.b", "b", "a.b\\", "e.f", "a.b.c.d.e.f"];
    for a in names {
        for b in names {
            let (ca, cb) = (CString::new(a).unwrap(), CString::new(b).unwrap());
            unsafe {
                assert_eq!(ns_samedomain(ca.as_ptr(), cb.as_ptr()), host::ns_samedomain(ca.as_ptr(), cb.as_ptr()), "samedomain({a:?}, {b:?})");
                assert_eq!(ns_subdomain(ca.as_ptr(), cb.as_ptr()), host::ns_subdomain(ca.as_ptr(), cb.as_ptr()), "subdomain({a:?}, {b:?})");
                assert_eq!(ns_samename(ca.as_ptr(), cb.as_ptr()), host::ns_samename(ca.as_ptr(), cb.as_ptr()), "samename({a:?}, {b:?})");
            }
        }
        let ca = CString::new(a).unwrap();
        for size in [0usize, 1, 2, 3, 5, 16] {
            let mut oa = [b'Q' as c_char; 32];
            let mut ob = [b'Q' as c_char; 32];
            rusty_libc_core::errno::set(0);
            let p = unsafe { ns_makecanon(ca.as_ptr(), oa.as_mut_ptr(), size) };
            let ep = rusty_libc_core::errno::get();
            set_herrno(0);
            let q = unsafe { host::ns_makecanon(ca.as_ptr(), ob.as_mut_ptr(), size) };
            assert_eq!((p, oa), (q, ob), "makecanon({a:?}, {size})");
            if p < 0 {
                assert_eq!(ep, herrno(), "makecanon errno");
            }
        }
    }
    // ns_name_ntol over random wire names
    for _ in 0..3000 {
        let mut w = vec![];
        for _ in 0..r.below(4) {
            let l = match r.below(10) {
                0 => 64 + r.below(130),
                1 => 192 + r.below(60),
                _ => r.below(8),
            };
            w.push(l as u8);
            for _ in 0..l.min(8) {
                w.push([b'A', b'z', b'-', 0xc3, b'.'][r.below(5)]);
            }
        }
        w.push(0);
        w.extend_from_slice(&[0xaa; 4]);
        for size in [0usize, 1, 5, 12, 40] {
            let mut oa = [0xaau8; 48];
            let mut ob = [0xaau8; 48];
            rusty_libc_core::errno::set(0);
            let p = unsafe { ns_name_ntol(w.as_ptr(), oa.as_mut_ptr(), size) };
            let ep = rusty_libc_core::errno::get();
            set_herrno(0);
            let q = unsafe { host::ns_name_ntol(w.as_ptr(), ob.as_mut_ptr(), size) };
            assert_eq!((p, oa), (q, ob), "ntol {w:02x?} {size}");
            if p < 0 {
                assert_eq!(ep, herrno(), "ntol errno {w:02x?} {size}");
            }
        }
    }
}

#[test]
fn skiprr_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for sect in 0..4 {
        for count in 0..6 {
            for start in [12usize, 29, 45, 100] {
                for end in [60usize, 150, 182] {
                    let ptr = MSG.as_ptr().wrapping_add(start);
                    let eom = MSG.as_ptr().wrapping_add(end);
                    rusty_libc_core::errno::set(0);
                    let a = unsafe { ns_skiprr(ptr, eom, sect, count) };
                    let ea = rusty_libc_core::errno::get();
                    set_herrno(0);
                    let b = unsafe { host::ns_skiprr(ptr, eom, sect, count) };
                    assert_eq!(a, b, "skiprr {sect} {count} {start} {end}");
                    if a < 0 {
                        assert_eq!(ea, herrno());
                    }
                }
            }
        }
    }
}
