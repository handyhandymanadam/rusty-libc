//! Differential tests of the deterministic functions against the host's glibc.
use super::*;
use crate::types::*;
use crate::util::cbytes;
use crate::{ether, inet, misc, netdb, strerr};

fn edge_ipv4() -> Vec<&'static str> {
    vec![
        "", ".", "1", "1.2", "1.2.3", "1.2.3.4", "1.2.3.4.5", "0", "00", "0x", "0x1", "0X1F", "0xff.0xff.0xff.0xff", "0377.0377.0377.0377", "0400", "08", "09", "0.0.0.0", "255.255.255.255", "256.1.1.1", "1.256.1.1", "1.1.1.256", "4294967295", "4294967296", "0xffffffff", "0x100000000", "1.2.3.", ".1.2.3", "1..2", "1.2.3.4 ", "1.2.3.4 junk", "1.2.3.4\t5", "1.2.3.4x", " 1.2.3.4", "-1", "+1", "1.2.3.-4", "010.010.010.010", "0x7f.1", "127.1", "127.0.1", "1.2.65535", "1.2.65536", "1.16777215", "1.16777216", "00x1", "0x0", "0xg", "0x.1", "1.0x", "999999999999999999999", "18446744073709551616", "1,2,3,4", "a.b.c.d", "0xA.0xb.0xC.0xd", "1.2.3.4\n", "1.2.3.4\r", "1.2.3.0x1ffffff", "128.0", "0.0.0.0.0", "07.07.07.07", "08.1", "1.0x1f.2.3", "\u{e9}1.2.3.4",
    ]
}

fn rand_text(r: &mut Rng, alphabet: &[u8], maxlen: usize) -> String {
    let n = r.below(maxlen + 1);
    (0..n).map(|_| alphabet[r.below(alphabet.len())] as char).collect()
}

#[test]
fn aton_addr_network_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cases: Vec<String> = edge_ipv4().into_iter().map(String::from).collect();
    let mut r = Rng(0x1234_5678_9abc_def1);
    for _ in 0..40000 {
        cases.push(rand_text(&mut r, b"0123456789.xX ab\tFf", 20));
    }
    // structured: four parts each in a random base
    for _ in 0..20000 {
        let parts = 1 + r.below(4);
        let mut s = String::new();
        for i in 0..parts {
            if i > 0 {
                s.push('.');
            }
            let v = r.next() as u32 >> r.below(32);
            match r.below(3) {
                0 => s += &format!("{}", v),
                1 => s += &format!("0x{:x}", v),
                _ => s += &format!("0{:o}", v),
            }
        }
        cases.push(s);
    }
    for s in &cases {
        let c = match CString::new(s.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut a = 0u32;
        let mut b = 0u32;
        let ra = unsafe { inet::inet_aton(c.as_ptr(), &mut a as *mut u32 as *mut in_addr) };
        let rb = unsafe { host::inet_aton(c.as_ptr(), &mut b) };
        assert_eq!((ra, if ra == 1 { a } else { 0 }), (rb, if rb == 1 { b } else { 0 }), "inet_aton({s:?})");
        assert_eq!(unsafe { inet::inet_addr(c.as_ptr()) }, unsafe { host::inet_addr(c.as_ptr()) }, "inet_addr({s:?})");
        assert_eq!(unsafe { inet::inet_network(c.as_ptr()) }, unsafe { host::inet_network(c.as_ptr()) }, "inet_network({s:?})");
    }
}

#[test]
fn byte_order_and_class_functions() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(77);
    for _ in 0..2000 {
        let x = r.next();
        assert_eq!(inet::htons(x as u16), unsafe { host::htons(x as u16) });
        assert_eq!(inet::ntohs(x as u16), unsafe { host::ntohs(x as u16) });
        assert_eq!(inet::htonl(x as u32), unsafe { host::htonl(x as u32) });
        assert_eq!(inet::ntohl(x as u32), unsafe { host::ntohl(x as u32) });
        let (n, h) = (r.next() as u32 >> r.below(32), r.next() as u32);
        assert_eq!(inet::inet_makeaddr(n, h).s_addr, unsafe { host::inet_makeaddr(n, h) }, "makeaddr {n:x} {h:x}");
        let a = r.next() as u32;
        assert_eq!(inet::inet_lnaof(in_addr { s_addr: a }), unsafe { host::inet_lnaof(a) });
        assert_eq!(inet::inet_netof(in_addr { s_addr: a }), unsafe { host::inet_netof(a) });
        let p = inet::inet_ntoa(in_addr { s_addr: a });
        let q = unsafe { host::inet_ntoa(a) };
        assert_eq!(cstr_opt(p), cstr_opt(q));
    }
}

fn pton_both(af: c_int, s: &str) -> (c_int, Vec<u8>, c_int, Vec<u8>) {
    let c = match CString::new(s) {
        Ok(c) => c,
        Err(_) => return (0, vec![], 0, vec![]),
    };
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    let ra = unsafe { inet::inet_pton(af, c.as_ptr(), a.as_mut_ptr() as *mut c_void) };
    let rb = unsafe { host::inet_pton(af, c.as_ptr(), b.as_mut_ptr() as *mut c_void) };
    let n = if af == AF_INET { 4 } else { 16 };
    (ra, if ra == 1 { a[..n].to_vec() } else { vec![] }, rb, if rb == 1 { b[..n].to_vec() } else { vec![] })
}

#[test]
fn pton_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixed = [
        "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1::8", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", ":1", "1:", "::1:", ":::", "1:::2", "1::2::3", "::ffff:1.2.3.4", "::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:1.2.3.4", "::1.2.3", "::1.2.3.4.5", "::01.2.3.4", "::256.1.1.1", "1.2.3.4", "fe80::1%eth0", "fe80::1%", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "0000:0000:0000:0000:0000:0000:0000:0000", "00001::", "12345::", "g::", "::g", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "0:0:0:0:0:0:0:0", "::0", "1::1.2.3.4", "1:2:3:4:5:6::1.2.3.4", "::.1", "1.2.3.4::", "::1.2.3.4:1", "1:1.2.3.4", "::ffff:255.255.255.255", "::ffff:0.0.0.0", " ::1", "::1 ", "",
        "0.0.0.0", "255.255.255.255", "01.2.3.4", "1.2.3.04", "1.2.3", "1.2.3.4.5", "1.2.3.256", "1..3.4", ".1.2.3", "1.2.3.", "a.b.c.d", "1.2.3.4 ", "0x1.2.3.4",
    ];
    let mut cases: Vec<String> = fixed.iter().map(|s| s.to_string()).collect();
    let mut r = Rng(0xdead_beef_0bad_f00d);
    for _ in 0..60000 {
        cases.push(rand_text(&mut r, b"0123456789abcdefABCDEF:.:::..", 42));
    }
    // random structured v6: groups with a :: somewhere and an optional embedded v4
    for _ in 0..30000 {
        let n = r.below(9);
        let mut parts: Vec<String> = (0..n).map(|_| format!("{:x}", r.next() as u16 >> r.below(16))).collect();
        if r.below(4) == 0 {
            parts.push(format!("{}.{}.{}.{}", r.below(256), r.below(256), r.below(256), r.below(256)));
        }
        let mut s = parts.join(":");
        if r.below(2) == 0 && !s.is_empty() {
            let pos = r.below(s.len());
            s.insert_str(pos, "::");
        }
        cases.push(s);
    }
    for s in &cases {
        for af in [AF_INET, AF_INET6] {
            let (ra, a, rb, b) = pton_both(af, s);
            assert_eq!((ra, a), (rb, b), "inet_pton(af={af}, {s:?})");
        }
    }
    // unknown family
    let c = cs("1.2.3.4");
    let mut buf = [0u8; 16];
    rusty_libc_core::errno::set(0);
    let ra = unsafe { inet::inet_pton(99, c.as_ptr(), buf.as_mut_ptr() as *mut c_void) };
    let ea = rusty_libc_core::errno::get();
    unsafe { *libc::__errno_location() = 0 };
    let rb = unsafe { host::inet_pton(99, c.as_ptr(), buf.as_mut_ptr() as *mut c_void) };
    assert_eq!((ra, ea), (rb, unsafe { *libc::__errno_location() }));
}

#[test]
fn ntop_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x0ff1ce);
    let mut addrs: Vec<[u8; 16]> = vec![[0; 16], {
        let mut a = [0; 16];
        a[15] = 1;
        a
    }];
    for _ in 0..50000 {
        let mut a = [0u8; 16];
        // few distinct values so runs of zeros are common
        for i in 0..8 {
            let v = match r.below(4) {
                0 | 1 => 0u16,
                2 => 0xffff,
                _ => r.next() as u16,
            };
            a[2 * i] = (v >> 8) as u8;
            a[2 * i + 1] = v as u8;
        }
        match r.below(6) {
            0 => {
                a[..10].fill(0);
                a[10] = 0xff;
                a[11] = 0xff;
            }
            1 => a[..12].fill(0),
            2 => {
                a[..8].fill(0);
                a[8..10].fill(0);
                a[10] = 0xff;
                a[11] = 0xff;
                a[12..].fill(0);
            }
            _ => {}
        }
        addrs.push(a);
    }
    for a in &addrs {
        for size in [0u32, 1, 7, 8, 15, 16, 17, 20, 39, 45, 46, 47, 64] {
            for af in [AF_INET, AF_INET6] {
                let mut x = [0x55 as c_char; 64];
                let mut y = [0x55 as c_char; 64];
                unsafe { *libc::__errno_location() = 0 };
                rusty_libc_core::errno::set(0);
                let ra = unsafe { inet::inet_ntop(af, a.as_ptr() as *const c_void, x.as_mut_ptr(), size) };
                let ea = rusty_libc_core::errno::get();
                unsafe { *libc::__errno_location() = 0 };
                let rb = unsafe { host::inet_ntop(af, a.as_ptr() as *const c_void, y.as_mut_ptr(), size) };
                let eb = unsafe { *libc::__errno_location() };
                assert_eq!(ra.is_null(), rb.is_null(), "ntop null af={af} size={size} {a:02x?}");
                assert_eq!(ea, eb, "ntop errno af={af} size={size}");
                if !ra.is_null() {
                    assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) }, "ntop {a:02x?}");
                }
            }
        }
    }
    unsafe { *libc::__errno_location() = 0 };
    rusty_libc_core::errno::set(0);
    let mut buf = [0 as c_char; 64];
    assert!(unsafe { inet::inet_ntop(99, [0u8; 16].as_ptr() as *const c_void, buf.as_mut_ptr(), 64) }.is_null());
    assert_eq!(rusty_libc_core::errno::get(), EAFNOSUPPORT);
}

#[test]
fn nsap_and_ether_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(5);
    for _ in 0..20000 {
        let s = rand_text(&mut r, b"0123456789abcdefABCDEF./+g", 24);
        let c = CString::new(s.as_str()).unwrap();
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let (la, lb) = unsafe { (inet::inet_nsap_addr(c.as_ptr(), a.as_mut_ptr(), 12), host::inet_nsap_addr(c.as_ptr(), b.as_mut_ptr(), 12)) };
        assert_eq!(la, lb, "nsap_addr {s:?}");
        assert_eq!(a[..la as usize], b[..lb as usize]);
        let bin: Vec<u8> = (0..r.below(20)).map(|_| r.next() as u8).collect();
        let (mut x, mut y) = ([0 as c_char; 600], [0 as c_char; 600]);
        let _ = unsafe { inet::inet_nsap_ntoa(bin.len() as c_int, bin.as_ptr(), x.as_mut_ptr()) };
        let _ = unsafe { host::inet_nsap_ntoa(bin.len() as c_int, bin.as_ptr(), y.as_mut_ptr()) };
        assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) });
    }
    for _ in 0..60000 {
        let s = match r.below(3) {
            0 => rand_text(&mut r, b"0123456789abcdefABCDEF:: ", 20),
            _ => {
                let v: Vec<String> = (0..6 + r.below(2)).map(|_| format!("{:x}", (r.next() as u8 as u32) >> r.below(9))).collect();
                let mut s = v.join(":");
                if r.below(5) == 0 {
                    s.push(' ');
                    s.push('x');
                }
                s
            }
        };
        let c = CString::new(s.as_str()).unwrap();
        let (mut a, mut b) = (ether_addr::default(), [0u8; 6]);
        let ra = unsafe { ether::ether_aton_r(c.as_ptr(), &mut a) };
        let rb = unsafe { host::ether_aton_r(c.as_ptr(), b.as_mut_ptr()) };
        assert_eq!(ra.is_null(), rb.is_null(), "ether_aton {s:?}");
        if !ra.is_null() {
            assert_eq!(a.ether_addr_octet, b, "ether_aton {s:?}");
            let (mut x, mut y) = ([0 as c_char; 32], [0 as c_char; 32]);
            unsafe {
                ether::ether_ntoa_r(&a, x.as_mut_ptr());
                host::ether_ntoa_r(b.as_ptr(), y.as_mut_ptr());
            }
            assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) });
        }
    }
    for line in ["00:11:22:33:44:55 host", "0:1:2:3:4:5\thost  # c", "1:2:3:4:5 h", "1:2:3:4:5:6", "ff:ff:ff:ff:ff:100 h", "1:2:3:4:5:6 #x", "aa:bb:cc:dd:ee:ff   foo.bar"] {
        let c = cs(line);
        let (mut a, mut b) = (ether_addr::default(), [0u8; 6]);
        let (mut h1, mut h2) = ([0 as c_char; 100], [0 as c_char; 100]);
        let ra = unsafe { ether::ether_line(c.as_ptr(), &mut a, h1.as_mut_ptr()) };
        let rb = unsafe { host::ether_line(c.as_ptr(), b.as_mut_ptr(), h2.as_mut_ptr()) };
        assert_eq!(ra, rb, "ether_line {line:?}");
        if ra == 0 {
            assert_eq!(a.ether_addr_octet, b);
            assert_eq!(unsafe { CStr::from_ptr(h1.as_ptr()) }, unsafe { CStr::from_ptr(h2.as_ptr()) });
        }
    }
}

#[test]
fn error_texts_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for c in -300..=300 {
        assert_eq!(cstr_opt(strerr::gai_strerror(c)), cstr_opt(unsafe { host::gai_strerror(c) }), "gai_strerror({c})");
        assert_eq!(cstr_opt(strerr::hstrerror(c)), cstr_opt(unsafe { host::hstrerror(c) }), "hstrerror({c})");
    }
}

// ---------------------------------------------------------------- dn_* and ns_name_*

#[test]
fn dns_names_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xabc);
    let names = ["", ".", "a", "a.", "www.example.com", "www.example.com.", "a..b", ".a", "a\\.b.c", "a\\065b.c", "a\\256.c", "a\\", "\\", "a\\0.b", "x\\046y.z", "a.b.c.d.e.f.g.h.i.j.k", "\u{e9}.com", "a b.c", "UPPER.Case.COM", "foo;bar.com", "$x.(y).@z", "-a.com", "a_b.com"];
    let mut cases: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    for _ in 0..30000 {
        let nl = r.below(6);
        let mut parts = vec![];
        for _ in 0..nl {
            let l = r.below(70);
            let p: String = (0..l)
                .map(|_| match r.below(10) {
                    0 => '.',
                    1 => '\\',
                    2 => '9',
                    3 => ';',
                    _ => (b'a' + r.below(26) as u8) as char,
                })
                .collect();
            parts.push(p);
        }
        let mut s = parts.join(".");
        if r.below(3) == 0 {
            s.push('.');
        }
        cases.push(s);
    }
    for s in &cases {
        let Ok(c) = CString::new(s.as_str()) else { continue };
        for siz in [255usize, 256, 10, 3] {
            let (mut a, mut b) = ([0u8; 300], [0u8; 300]);
            let ra = unsafe { crate::resolv::ns_name_pton(c.as_ptr(), a.as_mut_ptr(), siz) };
            let rb = unsafe { host::ns_name_pton(c.as_ptr(), b.as_mut_ptr(), siz) };
            assert_eq!(ra, rb, "ns_name_pton({s:?}, {siz})");
            if ra >= 0 {
                let n = a.iter().position(|_| true).unwrap();
                let _ = n;
                assert_eq!(a[..siz.min(255)], b[..siz.min(255)], "ns_name_pton bytes {s:?}");
                // and back to text
                for tsz in [1025usize, 20, 4] {
                    let (mut x, mut y) = ([0 as c_char; 1100], [0 as c_char; 1100]);
                    let ta = unsafe { crate::resolv::ns_name_ntop(a.as_ptr(), x.as_mut_ptr(), tsz) };
                    let tb = unsafe { host::ns_name_ntop(b.as_ptr(), y.as_mut_ptr(), tsz) };
                    assert_eq!(ta, tb, "ns_name_ntop({s:?}, {tsz})");
                    if ta >= 0 {
                        assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) });
                    }
                }
            }
        }
        // name checks
        assert_eq!(unsafe { crate::resolv::res_hnok(c.as_ptr()) }, unsafe { host::res_hnok(c.as_ptr()) }, "res_hnok {s:?}");
        assert_eq!(unsafe { crate::resolv::res_dnok(c.as_ptr()) }, unsafe { host::res_dnok(c.as_ptr()) }, "res_dnok {s:?}");
        assert_eq!(unsafe { crate::resolv::res_ownok(c.as_ptr()) }, unsafe { host::res_ownok(c.as_ptr()) }, "res_ownok {s:?}");
        assert_eq!(unsafe { crate::resolv::res_mailok(c.as_ptr()) }, unsafe { host::res_mailok(c.as_ptr()) }, "res_mailok {s:?}");
    }
}

#[test]
fn dn_comp_expand_skipname_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(99);
    let pool = ["example.com", "www.example.com", "mail.example.com", "example.org", "a.b.c.example.com", "x", "WWW.EXAMPLE.COM", "com", "."];
    for _ in 0..2000 {
        // build a message of several compressed names with both implementations
        let k = 1 + r.below(6);
        let picks: Vec<&str> = (0..k).map(|_| pool[r.below(pool.len())]).collect();
        let (mut ma, mut mb) = ([0u8; 600], [0u8; 600]);
        let mut pa: [*mut u8; 20] = [core::ptr::null_mut(); 20];
        let mut pb: [*mut u8; 20] = [core::ptr::null_mut(); 20];
        pa[0] = ma.as_mut_ptr();
        pb[0] = mb.as_mut_ptr();
        let (mut oa, mut ob) = (12usize, 12usize);
        for p in &picks {
            let c = cs(p);
            let la = unsafe { crate::resolv::dn_comp(c.as_ptr(), ma.as_mut_ptr().add(oa), (ma.len() - oa) as c_int, pa.as_mut_ptr(), pa.as_mut_ptr().add(19)) };
            let lb = unsafe { host::dn_comp(c.as_ptr(), mb.as_mut_ptr().add(ob), (mb.len() - ob) as c_int, pb.as_mut_ptr(), pb.as_mut_ptr().add(19)) };
            assert_eq!(la, lb, "dn_comp {p}");
            if la < 0 {
                break;
            }
            oa += la as usize;
            ob += lb as usize;
        }
        assert_eq!(oa, ob);
        assert_eq!(ma[..oa], mb[..ob], "dn_comp message {picks:?}");
        // expand each name from the message with both
        let mut off = 12;
        while off < oa {
            let (mut x, mut y) = ([0 as c_char; 300], [0 as c_char; 300]);
            let ea = unsafe { crate::resolv::dn_expand(ma.as_ptr(), ma.as_ptr().add(oa), ma.as_ptr().add(off), x.as_mut_ptr(), 300) };
            let eb = unsafe { host::dn_expand(ma.as_ptr(), ma.as_ptr().add(oa), ma.as_ptr().add(off), y.as_mut_ptr(), 300) };
            assert_eq!(ea, eb);
            assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) });
            let sa = unsafe { crate::resolv::dn_skipname(ma.as_ptr().add(off), ma.as_ptr().add(oa)) };
            let sb = unsafe { host::dn_skipname(ma.as_ptr().add(off), ma.as_ptr().add(oa)) };
            assert_eq!(sa, sb);
            off += sa as usize;
        }
    }
    // corrupt messages: random bytes must be rejected or accepted identically
    for _ in 0..30000 {
        let n = 1 + r.below(40);
        let m: Vec<u8> = (0..n).map(|_| if r.below(3) == 0 { 0xc0 | r.below(8) as u8 } else { r.below(70) as u8 }).collect();
        let off = r.below(n);
        let (mut x, mut y) = ([0 as c_char; 300], [0 as c_char; 300]);
        let ea = unsafe { crate::resolv::dn_expand(m.as_ptr(), m.as_ptr().add(n), m.as_ptr().add(off), x.as_mut_ptr(), 300) };
        let eb = unsafe { host::dn_expand(m.as_ptr(), m.as_ptr().add(n), m.as_ptr().add(off), y.as_mut_ptr(), 300) };
        assert_eq!(ea, eb, "dn_expand {m:02x?} @{off}");
        if ea >= 0 {
            assert_eq!(unsafe { CStr::from_ptr(x.as_ptr()) }, unsafe { CStr::from_ptr(y.as_ptr()) });
        }
        let sa = unsafe { crate::resolv::dn_skipname(m.as_ptr().add(off), m.as_ptr().add(n)) };
        let sb = unsafe { host::dn_skipname(m.as_ptr().add(off), m.as_ptr().add(n)) };
        assert_eq!(sa, sb, "dn_skipname {m:02x?} @{off}");
    }
}

#[test]
fn inet6_option_functions_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // sizes and offsets of the RFC 3542 helpers
    for l in [0u32, 8, 16, 24, 2048, 2056, 7] {
        let (mut a, mut b) = ([0u8; 2100], [0u8; 2100]);
        let ra = unsafe { misc::inet6_opt_init(a.as_mut_ptr() as *mut c_void, l) };
        let rb = unsafe { host::inet6_opt_init(b.as_mut_ptr() as *mut c_void, l) };
        assert_eq!(ra, rb);
        assert_eq!(a[..4], b[..4]);
    }
    for (ty, len, al, off) in [(5u8, 4u32, 4u8, 2), (7, 8, 8, 2), (0, 4, 4, 2), (9, 300, 1, 2), (9, 4, 3, 2), (9, 4, 8, 2), (9, 2, 2, 5), (11, 12, 8, 14)] {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let (mut da, mut db) = (core::ptr::null_mut(), core::ptr::null_mut());
        let ra = unsafe { misc::inet6_opt_append(a.as_mut_ptr() as *mut c_void, 64, off, ty, len, al, &mut da) };
        let rb = unsafe { host::inet6_opt_append(b.as_mut_ptr() as *mut c_void, 64, off, ty, len, al, &mut db) };
        assert_eq!(ra, rb, "append {ty} {len} {al} {off}");
        assert_eq!(a, b);
        let ra = unsafe { misc::inet6_opt_append(core::ptr::null_mut(), 0, off, ty, len, al, &mut da) };
        let rb = unsafe { host::inet6_opt_append(core::ptr::null_mut(), 0, off, ty, len, al, &mut db) };
        assert_eq!(ra, rb);
    }
    for off in [0, 1, 2, 3, 7, 8, 9, 15] {
        let (mut a, mut b) = ([0xffu8; 32], [0xffu8; 32]);
        let ra = unsafe { misc::inet6_opt_finish(a.as_mut_ptr() as *mut c_void, 32, off) };
        let rb = unsafe { host::inet6_opt_finish(b.as_mut_ptr() as *mut c_void, 32, off) };
        assert_eq!(ra, rb);
        assert_eq!(a, b);
    }
    for t in [0, 1, 2] {
        for s in [-1, 0, 1, 127, 128] {
            assert_eq!(misc::inet6_rth_space(t, s), unsafe { host::inet6_rth_space(t, s) });
        }
    }
}

#[test]
fn services_and_protocols_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // names from /etc/services and /etc/protocols
    let services = std::fs::read_to_string("/etc/services").unwrap_or_default();
    let mut names: Vec<(String, String)> = vec![];
    for (i, line) in services.lines().enumerate() {
        let l = line.split('#').next().unwrap();
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2 && (i % 7 == 0 || names.len() < 40) {
            let (port, proto) = f[1].split_once('/').unwrap_or((f[1], ""));
            let _ = port;
            names.push((f[0].to_string(), proto.to_string()));
            if f.len() > 2 {
                names.push((f[2].to_string(), proto.to_string()));
            }
        }
    }
    names.push(("nonexistent-service".into(), "tcp".into()));
    names.push(("http".into(), "nonexistent".into()));
    for (n, p) in &names {
        for proto in [Some(p.as_str()), None, Some("tcp"), Some("udp")] {
            let cn = cs(n);
            let cp = proto.map(cs);
            let pp = cp.as_ref().map(|c| c.as_ptr()).unwrap_or(core::ptr::null());
            let mut ours = servent_zero();
            let mut buf = vec![0 as c_char; 4096];
            let mut out: *mut servent = core::ptr::null_mut();
            let ra = unsafe { netdb::getservbyname_r(cn.as_ptr(), pp, &mut ours, buf.as_mut_ptr(), buf.len(), &mut out) };
            let mut theirs = [0u8; 64];
            let mut buf2 = vec![0 as c_char; 4096];
            let mut out2: *mut u8 = core::ptr::null_mut();
            let rb = unsafe { host::getservbyname_r(cn.as_ptr(), pp, theirs.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2) };
            assert_eq!(ra, rb, "getservbyname_r({n}, {proto:?})");
            assert_eq!(out.is_null(), out2.is_null());
            if !out.is_null() {
                assert_eq!(dump_servent(out as *const u8), dump_servent(out2));
                // by port
                let port = unsafe { (*out).s_port };
                let mut o3 = servent_zero();
                let mut out3: *mut servent = core::ptr::null_mut();
                let r3 = unsafe { netdb::getservbyport_r(port, pp, &mut o3, buf.as_mut_ptr(), buf.len(), &mut out3) };
                let mut t4 = [0u8; 64];
                let mut out4: *mut u8 = core::ptr::null_mut();
                let r4 = unsafe { host::getservbyport_r(port, pp, t4.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out4) };
                assert_eq!(r3, r4);
                assert_eq!(dump_servent(out3 as *const u8), dump_servent(out4));
            }
        }
    }
    // small buffers: both fail with ERANGE or both succeed
    let cn = cs("http");
    let cp = cs("tcp");
    for len in [0usize, 8, 16, 32, 64, 128] {
        let mut ours = servent_zero();
        let mut buf = vec![0 as c_char; len.max(1)];
        let mut out: *mut servent = core::ptr::null_mut();
        let ra = unsafe { netdb::getservbyname_r(cn.as_ptr(), cp.as_ptr(), &mut ours, buf.as_mut_ptr(), len, &mut out) };
        assert!(ra == 0 || ra == ERANGE, "len {len}: {ra}");
        assert_eq!(ra == 0, !out.is_null());
    }
    // protocols
    let protos = std::fs::read_to_string("/etc/protocols").unwrap_or_default();
    let mut pn: Vec<(String, i32)> = vec![("nosuchproto".into(), 9999)];
    for line in protos.lines() {
        let l = line.split('#').next().unwrap();
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2 {
            pn.push((f[0].to_string(), f[1].parse().unwrap()));
            for a in &f[2..] {
                pn.push((a.to_string(), f[1].parse().unwrap()));
            }
        }
    }
    for (n, num) in &pn {
        let cn = cs(n);
        let mut ours = unsafe { core::mem::zeroed::<protoent>() };
        let mut buf = vec![0 as c_char; 2048];
        let mut out: *mut protoent = core::ptr::null_mut();
        let ra = unsafe { netdb::getprotobyname_r(cn.as_ptr(), &mut ours, buf.as_mut_ptr(), buf.len(), &mut out) };
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 2048];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let rb = unsafe { host::getprotobyname_r(cn.as_ptr(), t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2) };
        assert_eq!(ra, rb, "getprotobyname_r({n})");
        assert_eq!(dump_protoent(out as *const u8), dump_protoent(out2), "protoent {n}");
        let mut o3 = unsafe { core::mem::zeroed::<protoent>() };
        let mut out3: *mut protoent = core::ptr::null_mut();
        let r3 = unsafe { netdb::getprotobynumber_r(*num, &mut o3, buf.as_mut_ptr(), buf.len(), &mut out3) };
        let mut t4 = [0u8; 64];
        let mut out4: *mut u8 = core::ptr::null_mut();
        let r4 = unsafe { host::getprotobynumber_r(*num, t4.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out4) };
        assert_eq!(r3, r4);
        assert_eq!(dump_protoent(out3 as *const u8), dump_protoent(out4));
    }
}

pub(crate) fn servent_zero() -> servent {
    servent { s_name: core::ptr::null_mut(), s_aliases: core::ptr::null_mut(), s_port: 0, s_proto: core::ptr::null_mut() }
}

unsafe fn strs(mut p: *const *const c_char) -> Vec<String> {
    let mut v = vec![];
    unsafe {
        while !p.is_null() && !(*p).is_null() {
            v.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
            p = p.add(1);
        }
    }
    v
}

/// (name, aliases, port, proto) of a `struct servent` at `p` (any layout-compatible owner).
pub(crate) fn dump_servent(p: *const u8) -> Option<(String, Vec<String>, i32, String)> {
    if p.is_null() {
        return None;
    }
    unsafe {
        let s = p as *const servent;
        Some((cstr_opt((*s).s_name)?, strs((*s).s_aliases as *const *const c_char), (*s).s_port, cstr_opt((*s).s_proto)?))
    }
}

pub(crate) fn dump_protoent(p: *const u8) -> Option<(String, Vec<String>, i32)> {
    if p.is_null() {
        return None;
    }
    unsafe {
        let s = p as *const protoent;
        Some((cstr_opt((*s).p_name)?, strs((*s).p_aliases as *const *const c_char), (*s).p_proto))
    }
}

/// (name, aliases, type, length, addresses as bytes) of a `struct hostent`.
pub(crate) fn dump_hostent(p: *const u8) -> Option<(String, Vec<String>, i32, i32, Vec<Vec<u8>>)> {
    if p.is_null() {
        return None;
    }
    unsafe {
        let h = p as *const hostent;
        let mut addrs = vec![];
        let mut a = (*h).h_addr_list;
        while !a.is_null() && !(*a).is_null() {
            addrs.push(core::slice::from_raw_parts(*a as *const u8, (*h).h_length as usize).to_vec());
            a = a.add(1);
        }
        Some((cstr_opt((*h).h_name)?, strs((*h).h_aliases as *const *const c_char), (*h).h_addrtype, (*h).h_length, addrs))
    }
}

#[test]
fn hosts_lookups_match_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = super::EtcGuard::files_only();
    let names = ["localhost", "LOCALHOST", "localhost.localdomain", "localhost4", "localhost6", "nonexistent-host-for-test.invalid", "127.0.0.1", "1.2.3.4", "::1", "::ffff:1.2.3.4", "0x7f.1", "1.2.3", "fe80::1", ""];
    for n in names {
        let c = cs(n);
        for af in [AF_INET, AF_INET6] {
            let mut ours = unsafe { core::mem::zeroed::<hostent>() };
            let mut buf = vec![0 as c_char; 4096];
            let mut out: *mut hostent = core::ptr::null_mut();
            let mut h1 = 0;
            let ra = unsafe { netdb::gethostbyname2_r(c.as_ptr(), af, &mut ours, buf.as_mut_ptr(), buf.len(), &mut out, &mut h1) };
            if n.contains("nonexistent") || n.is_empty() {
                assert!(out.is_null(), "{n} af={af}");
                continue; // the host would ask DNS: not from a test
            }
            let mut t = [0u8; 64];
            let mut buf2 = vec![0 as c_char; 4096];
            let mut out2: *mut u8 = core::ptr::null_mut();
            let mut h2 = 0;
            let rb = unsafe { host::gethostbyname2_r(c.as_ptr(), af, t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2, &mut h2) };
            // (mdns4_minimal in the host's nsswitch.conf turns "not found" into NO_DATA for IPv6 queries)
            let h1 = if out.is_null() && h1 == HOST_NOT_FOUND && h2 == NO_DATA { h2 } else { h1 };
            assert_eq!((ra, out.is_null(), if out.is_null() { h1 } else { 0 }), (rb, out2.is_null(), if out2.is_null() { h2 } else { 0 }), "gethostbyname2_r({n:?}, {af}): ours {ra}/{h1} theirs {rb}/{h2}");
            assert_eq!(dump_hostent(out as *const u8), dump_hostent(out2), "gethostbyname2_r({n:?}, {af})");
        }
        let mut ours = unsafe { core::mem::zeroed::<hostent>() };
        let mut buf = vec![0 as c_char; 4096];
        let mut out: *mut hostent = core::ptr::null_mut();
        let mut h1 = 0;
        let ra = unsafe { netdb::gethostbyname_r(c.as_ptr(), &mut ours, buf.as_mut_ptr(), buf.len(), &mut out, &mut h1) };
        if !(n.contains("nonexistent") || n.is_empty()) {
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 4096];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let mut h2 = 0;
        let rb = unsafe { host::gethostbyname_r(c.as_ptr(), t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2, &mut h2) };
            assert_eq!((ra, out.is_null(), if out.is_null() { h1 } else { 0 }), (rb, out2.is_null(), if out2.is_null() { h2 } else { 0 }), "gethostbyname_r({n:?})");
            assert_eq!(dump_hostent(out as *const u8), dump_hostent(out2), "gethostbyname_r({n:?})");
        }
    }
    // by address
    for (af, a) in [(AF_INET, vec![127u8, 0, 0, 1]), (AF_INET6, { let mut v = vec![0u8; 16]; v[15] = 1; v }), (AF_INET, vec![1, 2, 3, 4])] {
        let mut ours = unsafe { core::mem::zeroed::<hostent>() };
        let mut buf = vec![0 as c_char; 4096];
        let mut out: *mut hostent = core::ptr::null_mut();
        let mut h1 = 0;
        let ra = unsafe { netdb::gethostbyaddr_r(a.as_ptr() as *const c_void, a.len() as u32, af, &mut ours, buf.as_mut_ptr(), buf.len(), &mut out, &mut h1) };
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 4096];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let mut h2 = 0;
        let rb = unsafe { host::gethostbyaddr_r(a.as_ptr() as *const c_void, a.len() as u32, af, t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2, &mut h2) };
        if a == [1, 2, 3, 4] {
            continue; // needs reverse DNS
        }
        assert_eq!((ra, out.is_null(), if out.is_null() { h1 } else { 0 }), (rb, out2.is_null(), if out2.is_null() { h2 } else { 0 }), "gethostbyaddr_r({a:?})");
        assert_eq!(dump_hostent(out as *const u8), dump_hostent(out2), "gethostbyaddr_r({a:?})");
    }
    // errors of gethostbyaddr_r
    for (af, len) in [(99, 4u32), (AF_INET, 5), (AF_INET6, 4), (AF_INET, 16), (AF_INET, 3), (AF_INET6, 15), (AF_INET6, 17), (1, 4)] {
        let a = [0u8; 16];
        let mut ours = unsafe { core::mem::zeroed::<hostent>() };
        let mut buf = vec![0 as c_char; 4096];
        let mut out: *mut hostent = core::ptr::null_mut();
        let mut h1 = 0;
        rusty_libc_core::errno::set(0);
        let ra = unsafe { netdb::gethostbyaddr_r(a.as_ptr() as *const c_void, len, af, &mut ours, buf.as_mut_ptr(), buf.len(), &mut out, &mut h1) };
        let ea = rusty_libc_core::errno::get();
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 4096];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let mut h2 = 0;
        unsafe { *libc::__errno_location() = 0 };
        let rb = unsafe { host::gethostbyaddr_r(a.as_ptr() as *const c_void, len, af, t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2, &mut h2) };
        let eb = unsafe { *libc::__errno_location() };
        // not found is rc 0 here; the host's nss-myhostname/resolve modules make it ENOENT for some addresses
        let norm = |rc: c_int, out_null: bool| if out_null && rc == ENOENT { 0 } else { rc };
        assert_eq!((norm(ra, out.is_null()), h1, ea), (norm(rb, out2.is_null()), h2, eb), "gethostbyaddr_r bad args af={af} len={len}");
    }
}

#[test]
fn rpc_and_networks_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let rpc = std::fs::read_to_string("/etc/rpc").unwrap_or_default();
    for line in rpc.lines() {
        let l = line.split('#').next().unwrap();
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let c = cs(f[0]);
        let mut ours = unsafe { core::mem::zeroed::<rpcent>() };
        let mut buf = vec![0 as c_char; 2048];
        let mut out: *mut rpcent = core::ptr::null_mut();
        let ra = unsafe { netdb::getrpcbyname_r(c.as_ptr(), &mut ours, buf.as_mut_ptr(), buf.len(), &mut out) };
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 2048];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let rb = unsafe { host::getrpcbyname_r(c.as_ptr(), t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2) };
        assert_eq!(ra, rb);
        let d = |p: *const u8| -> Option<(String, Vec<String>, i32)> {
            if p.is_null() {
                return None;
            }
            unsafe {
                let r = p as *const rpcent;
                Some((cstr_opt((*r).r_name)?, strs((*r).r_aliases as *const *const c_char), (*r).r_number))
            }
        };
        assert_eq!(d(out as *const u8), d(out2));
        let n: i32 = f[1].parse().unwrap();
        let mut o3 = unsafe { core::mem::zeroed::<rpcent>() };
        let mut out3: *mut rpcent = core::ptr::null_mut();
        unsafe { netdb::getrpcbynumber_r(n, &mut o3, buf.as_mut_ptr(), buf.len(), &mut out3) };
        let mut out4: *mut u8 = core::ptr::null_mut();
        unsafe { host::getrpcbynumber_r(n, t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out4) };
        assert_eq!(d(out3 as *const u8), d(out4));
    }
    // networks: names from the file (the host also consults DNS for unknown names: only known ones)
    let nets = std::fs::read_to_string("/etc/networks").unwrap_or_default();
    for line in nets.lines() {
        let l = line.split('#').next().unwrap();
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let c = cs(f[0]);
        let mut ours = unsafe { core::mem::zeroed::<netent>() };
        let mut buf = vec![0 as c_char; 2048];
        let mut out: *mut netent = core::ptr::null_mut();
        let mut h = 0;
        let ra = unsafe { netdb::getnetbyname_r(c.as_ptr(), &mut ours, buf.as_mut_ptr(), buf.len(), &mut out, &mut h) };
        let mut t = [0u8; 64];
        let mut buf2 = vec![0 as c_char; 2048];
        let mut out2: *mut u8 = core::ptr::null_mut();
        let mut h2 = 0;
        let rb = unsafe { host::getnetbyname_r(c.as_ptr(), t.as_mut_ptr(), buf2.as_mut_ptr(), buf2.len(), &mut out2, &mut h2) };
        assert_eq!(ra, rb, "getnetbyname_r({})", f[0]);
        let d = |p: *const u8| -> Option<(String, Vec<String>, i32, u32)> {
            if p.is_null() {
                return None;
            }
            unsafe {
                let r = p as *const netent;
                Some((cstr_opt((*r).n_name)?, strs((*r).n_aliases as *const *const c_char), (*r).n_addrtype, (*r).n_net))
            }
        };
        assert_eq!(d(out as *const u8), d(out2));
    }
    let _ = cbytes::<core::ffi::c_char>;
}

/// FIXLIST #132: gethostid's wiring (file, node name, lookup, rotation) against our own gethostbyname_r. Not against the
/// host's glibc: test builds load no NSS modules (myhostname, resolve: the `shared` feature), so the host name can resolve
/// differently here; tests/dyn (c-hostid, sys-hostid, hostid-ns) compare the built library with glibc.
#[test]
fn gethostid_uses_first_address() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if std::path::Path::new("/etc/hostid").exists() {
        return;
    }
    let node = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let name = cs(node.trim_end());
    let mut res = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
    let mut buf = vec![0u8; 65536];
    let (mut out, mut h) = (core::ptr::null_mut(), 0);
    let r = unsafe { netdb::gethostbyname_r(name.as_ptr(), &mut res, buf.as_mut_ptr().cast(), buf.len(), &mut out, &mut h) };
    let want = if r == 0 && !out.is_null() {
        let a = unsafe { core::slice::from_raw_parts((*res.h_addr_list).cast::<u8>(), 4) };
        rusty_libc_rs_core::hostid::from_address(a.try_into().unwrap()) as core::ffi::c_long
    } else {
        0
    };
    rusty_libc_core::errno::set(-1);
    assert_eq!(crate::hostid::gethostid(), want);
    if want != 0 {
        assert_eq!(rusty_libc_core::errno::get(), 0, "glibc: errno is the lookup's result");
    }
}
