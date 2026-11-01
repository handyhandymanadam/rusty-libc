//! The nine exported `_nss_dns_*` functions against the host glibc's own, with the same fake name server behind both:
//! same status, same errno and h_errno, same result, and the same smallest buffer that does not give ERANGE.
use super::dnstest::{Fake, Rec, Reply, a, aaaa, cname, ptr, response};
use crate::nssdns_abi as ours;
use crate::resolv::{ResState, __res_ninit, __res_state};
use crate::types::*;
use crate::wire;
use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};

type Hostent = hostent;

struct HostFns {
    gethostbyname3_r: unsafe extern "C" fn(*const c_char, c_int, *mut Hostent, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32, *mut *mut c_char) -> c_int,
    gethostbyname2_r: unsafe extern "C" fn(*const c_char, c_int, *mut Hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
    gethostbyname_r: unsafe extern "C" fn(*const c_char, *mut Hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
    gethostbyname4_r: unsafe extern "C" fn(*const c_char, *mut *mut c_void, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32) -> c_int,
    gethostbyaddr2_r: unsafe extern "C" fn(*const c_void, u32, c_int, *mut Hostent, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32) -> c_int,
    gethostbyaddr_r: unsafe extern "C" fn(*const c_void, u32, c_int, *mut Hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
    getcanonname_r: unsafe extern "C" fn(*const c_char, *mut c_char, usize, *mut *mut c_char, *mut c_int, *mut c_int) -> c_int,
    getnetbyname_r: unsafe extern "C" fn(*const c_char, *mut netent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
    getnetbyaddr_r: unsafe extern "C" fn(u32, c_int, *mut netent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
}

unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    #[link_name = "__res_init"]
    fn host_res_init() -> c_int;
    fn __res_iclose(st: *mut ResState, free_addr: c_int);
    #[link_name = "__res_state"]
    fn host_res_state() -> *mut ResState;
    fn __h_errno_location() -> *mut c_int;
}

/// The thread's h_errno of both libraries (the host's and ours are two variables) set to one value, so that what a
/// function leaves in it can be compared.
fn set_both_h_errno(v: c_int) {
    unsafe { *__h_errno_location() = v };
    crate::strerr::set_h_errno(v);
}

/// The host glibc's functions (GLIBC_PRIVATE in its libc.so.6, found by name).
#[allow(clippy::missing_transmute_annotations)] // each target type is the field's
fn host_fns() -> Option<HostFns> {
    unsafe {
        let get = |n: &str| -> *mut c_void {
            let c = CString::new(n).unwrap();
            dlsym(core::ptr::null_mut(), c.as_ptr())
        };
        macro_rules! f {
            ($n:literal) => {{
                let p = get($n);
                if p.is_null() {
                    return None;
                }
                core::mem::transmute(p)
            }};
        }
        Some(HostFns {
            gethostbyname3_r: f!("_nss_dns_gethostbyname3_r"),
            gethostbyname2_r: f!("_nss_dns_gethostbyname2_r"),
            gethostbyname_r: f!("_nss_dns_gethostbyname_r"),
            gethostbyname4_r: f!("_nss_dns_gethostbyname4_r"),
            gethostbyaddr2_r: f!("_nss_dns_gethostbyaddr2_r"),
            gethostbyaddr_r: f!("_nss_dns_gethostbyaddr_r"),
            getcanonname_r: f!("_nss_dns_getcanonname_r"),
            getnetbyname_r: f!("_nss_dns_getnetbyname_r"),
            getnetbyaddr_r: f!("_nss_dns_getnetbyaddr_r"),
        })
    }
}

#[allow(clippy::missing_transmute_annotations)] // the target type is the field's
fn ours_fns() -> HostFns {
    HostFns {
        gethostbyname3_r: ours::_nss_dns_gethostbyname3_r,
        gethostbyname2_r: ours::_nss_dns_gethostbyname2_r,
        gethostbyname_r: ours::_nss_dns_gethostbyname_r,
        gethostbyname4_r: unsafe { core::mem::transmute(ours::_nss_dns_gethostbyname4_r as *const ()) },
        gethostbyaddr2_r: ours::_nss_dns_gethostbyaddr2_r,
        gethostbyaddr_r: ours::_nss_dns_gethostbyaddr_r,
        getcanonname_r: ours::_nss_dns_getcanonname_r,
        getnetbyname_r: ours::_nss_dns_getnetbyname_r,
        getnetbyaddr_r: ours::_nss_dns_getnetbyaddr_r,
    }
}

/// Point the resolver state of this thread, in both libraries, at the fake server: DNS over UDP, one try.
fn point_both_at(f: &Fake) {
    unsafe {
        // ours
        let st = __res_state();
        __res_ninit(st);
        let s = &mut *st;
        s.nscount = 1;
        s.nsaddr_list[0].sin_family = AF_INET as u16;
        s.nsaddr_list[0].sin_port = f.port.to_be();
        s.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        s.retrans = 1;
        s.retry = 1;
        s.options = (s.options & !(crate::dns::RES_DNSRCH as u64)) | crate::dns::RES_INIT as u64;
        s.bits = (s.bits & !0xf) | 1;
        // the host's
        host_res_init();
        let h = host_res_state();
        __res_iclose(h, 1);
        let hs = &mut *h;
        hs.u.nscount = 0;
        hs.nscount = 1;
        hs.nsaddr_list[0] = s.nsaddr_list[0];
        hs.retrans = 1;
        hs.retry = 1;
        hs.options = s.options;
        hs.bits = s.bits;
    }
}

fn zone(s: &super::dnstest::Seen, q: &[u8]) -> Vec<Reply> {
    let recs: Vec<Rec> = match (s.name.as_str(), s.qtype) {
        ("www.example.test", t) if t == wire::T_A => vec![cname("www.example.test", "web.example.test"), a("web.example.test", [192, 0, 2, 1]), a("web.example.test", [192, 0, 2, 2])],
        ("www.example.test", t) if t == wire::T_AAAA => vec![cname("www.example.test", "web.example.test"), aaaa("web.example.test", "2001:db8::1")],
        ("plain.example.test", t) if t == wire::T_A => vec![a("plain.example.test", [10, 1, 2, 3])],
        ("plain.example.test", t) if t == wire::T_AAAA => vec![aaaa("plain.example.test", "2001:db8::3")],
        ("only4.example.test", t) if t == wire::T_A => vec![a("only4.example.test", [10, 4, 4, 4])],
        ("only4.example.test", _) => vec![],
        ("cnameonly.example.test", _) => vec![cname("cnameonly.example.test", "elsewhere.example.test")],
        ("servfail.example.test", _) => return vec![Reply::Raw(response(q, wire::SERVFAIL, false, &[]))],
        ("4.3.2.1.in-addr.arpa", wire::T_PTR) => vec![ptr("4.3.2.1.in-addr.arpa", "host1234.example.test")],
        ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", wire::T_PTR) => vec![ptr(s.name.clone().leak(), "six.example.test")],
        ("code1.example.test", wire::T_PTR) => vec![ptr("code1.example.test", "1.in-addr.arpa")],
        ("code4.example.test", wire::T_PTR) => vec![ptr("code4.example.test", "4.3.2.1.in-addr.arpa"), ptr("code4.example.test", "alias.in-addr.arpa")],
        ("0.0.0.127.in-addr.arpa", wire::T_PTR) => vec![ptr("0.0.0.127.in-addr.arpa", "loopback.example.test")],
        ("0.0.2.1.in-addr.arpa", wire::T_PTR) => vec![ptr("0.0.2.1.in-addr.arpa", "net21.example.test"), ptr("0.0.2.1.in-addr.arpa", "second.example.test")],
        _ => return vec![Reply::Raw(response(q, wire::NXDOMAIN, false, &[]))],
    };
    vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))]
}

/// A readable dump of a hostent that does not depend on addresses of the buffer.
unsafe fn dump_host(h: &Hostent, buf: *const c_char, buflen: usize) -> String {
    unsafe {
        let mut s = String::new();
        let inside = |p: *const c_char| (p as usize) >= buf as usize && (p as usize) < buf as usize + buflen;
        s += &format!("name={:?} type={} len={}\n", CStr::from_ptr(h.h_name), h.h_addrtype, h.h_length);
        assert!(inside(h.h_name));
        let mut i = 0;
        while !(*h.h_aliases.add(i)).is_null() {
            s += &format!("alias={:?}\n", CStr::from_ptr(*h.h_aliases.add(i)));
            i += 1;
        }
        let mut i = 0;
        while !(*h.h_addr_list.add(i)).is_null() {
            let a = core::slice::from_raw_parts(*h.h_addr_list.add(i) as *const u8, h.h_length as usize);
            s += &format!("addr={a:?} aligned4={}\n", (*h.h_addr_list.add(i) as usize).is_multiple_of(4));
            i += 1;
        }
        s
    }
}

#[derive(Debug, PartialEq)]
struct Res {
    status: c_int,
    errno: c_int,
    h_errno: c_int,
    dump: String,
    ttl: i32,
}

/// Run one host lookup function with a buffer of `buflen` bytes (8-aligned) and sentinel errno/h_errno values.
unsafe fn run_name3(fns: &HostFns, name: &str, af: c_int, buflen: usize) -> Res {
    unsafe {
        let n = CString::new(name).unwrap();
        let mut buf = vec![0u64; buflen / 8 + 2];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut h: Hostent = core::mem::zeroed();
        let (mut en, mut hen, mut ttl) = (-7, -7, i32::MAX);
        let mut canon: *mut c_char = core::ptr::null_mut();
        let st = (fns.gethostbyname3_r)(n.as_ptr(), af, &mut h, bp, buflen, &mut en, &mut hen, &mut ttl, &mut canon);
        let dump = if st == 1 {
            let mut d = dump_host(&h, bp, buflen);
            d += &format!("canon_is_name={}\n", canon == h.h_name);
            d
        } else {
            String::new()
        };
        Res { status: st, errno: en, h_errno: hen, dump, ttl }
    }
}

unsafe fn run_name2(fns: &HostFns, name: &str, af: c_int, buflen: usize, plain: bool) -> Res {
    unsafe {
        let n = CString::new(name).unwrap();
        let mut buf = vec![0u64; buflen / 8 + 2];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut h: Hostent = core::mem::zeroed();
        let (mut en, mut hen) = (-7, -7);
        let st = if plain { (fns.gethostbyname_r)(n.as_ptr(), &mut h, bp, buflen, &mut en, &mut hen) } else { (fns.gethostbyname2_r)(n.as_ptr(), af, &mut h, bp, buflen, &mut en, &mut hen) };
        let dump = if st == 1 { dump_host(&h, bp, buflen) } else { String::new() };
        Res { status: st, errno: en, h_errno: hen, dump, ttl: 0 }
    }
}

unsafe fn run_name4(fns: &HostFns, name: &str, buflen: usize) -> Res {
    unsafe {
        let n = CString::new(name).unwrap();
        let mut buf = vec![0u64; buflen / 8 + 2];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut pat: *mut c_void = core::ptr::null_mut();
        let (mut en, mut hen, mut ttl) = (-7, -7, i32::MAX);
        let st = (fns.gethostbyname4_r)(n.as_ptr(), &mut pat, bp, buflen, &mut en, &mut hen, &mut ttl);
        // struct gaih_addrtuple { next, name, family, addr[4] (u32), scopeid }
        let mut dump = String::new();
        // (on ERANGE glibc has already linked the tuples that fit; the caller must not look at them)
        let mut p = if st == 1 { pat as *const usize } else { core::ptr::null() };
        while !p.is_null() {
            let next = *p as *const usize;
            let namep = *p.add(1) as *const c_char;
            let family = *(p.add(2) as *const c_int);
            let addr = core::slice::from_raw_parts((p as *const u8).add(20), 16).to_vec();
            let scope = *((p as *const u8).add(36) as *const u32);
            dump += &format!("tuple family={family} addr={addr:?} scope={scope} name={:?} inside={}\n", if namep.is_null() { None } else { Some(CStr::from_ptr(namep).to_owned()) }, (p as usize) >= bp as usize && (p as usize) < bp as usize + buflen);
            p = next;
        }
        Res { status: st, errno: en, h_errno: hen, dump, ttl }
    }
}

unsafe fn run_addr2(fns: &HostFns, addr: &[u8], af: c_int, buflen: usize, two: bool) -> Res {
    unsafe {
        let mut buf = vec![0u64; buflen / 8 + 2];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut h: Hostent = core::mem::zeroed();
        let (mut en, mut hen, mut ttl) = (-7, -7, i32::MAX);
        let st = if two {
            (fns.gethostbyaddr2_r)(addr.as_ptr() as *const c_void, addr.len() as u32, af, &mut h, bp, buflen, &mut en, &mut hen, &mut ttl)
        } else {
            (fns.gethostbyaddr_r)(addr.as_ptr() as *const c_void, addr.len() as u32, af, &mut h, bp, buflen, &mut en, &mut hen)
        };
        let dump = if st == 1 { dump_host(&h, bp, buflen) } else { String::new() };
        Res { status: st, errno: en, h_errno: hen, dump, ttl: if two { ttl } else { 0 } }
    }
}

unsafe fn run_canon(fns: &HostFns, name: &str, buflen: usize) -> Res {
    unsafe {
        let n = CString::new(name).unwrap();
        let mut buf = vec![0u8; buflen + 8];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut res: *mut c_char = core::ptr::null_mut();
        let (mut en, mut hen) = (-7, -7);
        set_both_h_errno(0x5a);
        let st = (fns.getcanonname_r)(n.as_ptr(), bp, buflen, &mut res, &mut en, &mut hen);
        let dump = if st == 1 { format!("canon={:?} is_buffer={}", CStr::from_ptr(res), res == bp) } else { String::new() };
        Res { status: st, errno: en, h_errno: hen, dump, ttl: 0 }
    }
}

unsafe fn dump_net(n: &netent, buf: *const c_char, buflen: usize) -> String {
    unsafe {
        let mut s = format!("name={:?} type={} net={:#x}\n", if n.n_name.is_null() { None } else { Some(CStr::from_ptr(n.n_name).to_owned()) }, n.n_addrtype, n.n_net);
        let mut i = 0;
        while !(*n.n_aliases.add(i)).is_null() {
            let p = *n.n_aliases.add(i);
            s += &format!("alias={:?} inside={}\n", CStr::from_ptr(p), (p as usize) >= buf as usize && (p as usize) < buf as usize + buflen);
            i += 1;
        }
        s
    }
}

unsafe fn run_net(fns: &HostFns, by_name: Option<&str>, num: u32, buflen: usize) -> Res {
    unsafe {
        let mut buf = vec![0u64; buflen / 8 + 2];
        let bp = buf.as_mut_ptr() as *mut c_char;
        let mut nt: netent = core::mem::zeroed();
        let (mut en, mut hen) = (-7, -7);
        set_both_h_errno(-9);
        let st = match by_name {
            Some(n) => {
                let c = CString::new(n).unwrap();
                (fns.getnetbyname_r)(c.as_ptr(), &mut nt, bp, buflen, &mut en, &mut hen)
            }
            None => (fns.getnetbyaddr_r)(num, AF_INET, &mut nt, bp, buflen, &mut en, &mut hen),
        };
        let dump = if st == 1 { dump_net(&nt, bp, buflen) } else { String::new() };
        Res { status: st, errno: en, h_errno: hen, dump, ttl: 0 }
    }
}

#[test]
fn nine_functions_match_the_host() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(host) = host_fns() else {
        eprintln!("host libc has no _nss_dns_* symbols: skipped");
        return;
    };
    let mine = ours_fns();
    let f = Fake::start(zone);
    point_both_at(&f);
    let names = ["www.example.test", "plain.example.test", "only4.example.test", "cnameonly.example.test", "servfail.example.test", "nosuch.example.test", "bad name.example.test"];
    for name in names {
        for af in [AF_INET, AF_INET6] {
            let mut first_ok = None;
            for buflen in 0..300 {
                let (h, o) = unsafe { (run_name3(&host, name, af, buflen), run_name3(&mine, name, af, buflen)) };
                assert_eq!(h, o, "gethostbyname3_r {name} af={af} buflen={buflen}");
                if h.status == 1 && first_ok.is_none() {
                    first_ok = Some(buflen);
                }
                let (h, o) = unsafe { (run_name2(&host, name, af, buflen, false), run_name2(&mine, name, af, buflen, false)) };
                assert_eq!(h, o, "gethostbyname2_r {name} af={af} buflen={buflen}");
            }
            eprintln!("gethostbyname3_r {name} af={af}: smallest buffer {first_ok:?}");
        }
        for buflen in 0..300 {
            let (h, o) = unsafe { (run_name2(&host, name, AF_INET, buflen, true), run_name2(&mine, name, AF_INET, buflen, true)) };
            assert_eq!(h, o, "gethostbyname_r {name} buflen={buflen}");
            let (h, o) = unsafe { (run_name4(&host, name, buflen), run_name4(&mine, name, buflen)) };
            assert_eq!(h, o, "gethostbyname4_r {name} buflen={buflen}");
        }
        for buflen in [0, 5, 20, 40, 64, 200] {
            let (h, o) = unsafe { (run_canon(&host, name, buflen), run_canon(&mine, name, buflen)) };
            assert_eq!(h, o, "getcanonname_r {name} buflen={buflen}");
        }
    }
    // bad family
    unsafe {
        assert_eq!(run_name3(&host, "www.example.test", 99, 200), run_name3(&mine, "www.example.test", 99, 200));
    }
    // by address: v4, v6, mapped, compatible, unknown, short length, wrong family
    let v6 = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let mapped = "::ffff:1.2.3.4".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let compat = "::1.2.3.4".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let loop6 = "::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let cases: Vec<(&str, Vec<u8>, c_int)> = vec![
        ("v4", vec![1, 2, 3, 4], AF_INET),
        ("v4 unknown", vec![9, 9, 9, 9], AF_INET),
        ("v6", v6.to_vec(), AF_INET6),
        ("mapped", mapped.to_vec(), AF_INET6),
        ("compat", compat.to_vec(), AF_INET6),
        ("::1", loop6.to_vec(), AF_INET6),
        ("v4 too short", vec![1, 2, 3], AF_INET),
        ("bad family", vec![1, 2, 3, 4], 99),
        ("v4 longer", vec![1, 2, 3, 4, 5, 6], AF_INET),
    ];
    for (what, addr, af) in &cases {
        for buflen in 0..260 {
            let (h, o) = unsafe { (run_addr2(&host, addr, *af, buflen, true), run_addr2(&mine, addr, *af, buflen, true)) };
            assert_eq!(h, o, "gethostbyaddr2_r {what} buflen={buflen}");
            let (h, o) = unsafe { (run_addr2(&host, addr, *af, buflen, false), run_addr2(&mine, addr, *af, buflen, false)) };
            assert_eq!(h, o, "gethostbyaddr_r {what} buflen={buflen}");
        }
    }
    // networks
    for name in ["code1.example.test", "code4.example.test", "nosuch.example.test", "servfail.example.test"] {
        for buflen in (0..520).step_by(1) {
            let (h, o) = unsafe { (run_net(&host, Some(name), 0, buflen), run_net(&mine, Some(name), 0, buflen)) };
            assert_eq!(h, o, "getnetbyname_r {name} buflen={buflen}");
        }
    }
    for net in [0x7f_u32, 0x0102, 0x010203, 0x01020304, 0] {
        for buflen in (0..520).step_by(1) {
            let (h, o) = unsafe { (run_net(&host, None, net, buflen), run_net(&mine, None, net, buflen)) };
            assert_eq!(h, o, "getnetbyaddr_r {net:#x} buflen={buflen}");
        }
    }
    // an IPv6 network lookup is not supported
    unsafe {
        let mut buf = [0u64; 64];
        let mut nt: netent = core::mem::zeroed();
        let (mut e1, mut h1, mut e2, mut h2) = (0, 0, 0, 0);
        let a = (host.getnetbyaddr_r)(1, AF_INET6, &mut nt, buf.as_mut_ptr() as *mut c_char, 512, &mut e1, &mut h1);
        let b = (mine.getnetbyaddr_r)(1, AF_INET6, &mut nt, buf.as_mut_ptr() as *mut c_char, 512, &mut e2, &mut h2);
        assert_eq!(a, b);
    }
}
