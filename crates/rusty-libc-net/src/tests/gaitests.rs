//! getaddrinfo, getnameinfo, ifaddrs and enumerations against the host's glibc.
use super::*;
use crate::types::*;
use crate::{gai, netdb};
use crate::ifaddrs as ifa;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
struct Item {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addr: Vec<u8>,
    flags: c_int,
}

fn collect_ours(mut p: *const addrinfo) -> (Vec<Item>, Option<String>) {
    let mut v = vec![];
    let canon = if p.is_null() { None } else { cstr_opt(unsafe { (*p).ai_canonname }) };
    unsafe {
        while !p.is_null() {
            let a = &*p;
            v.push(Item { family: a.ai_family, socktype: a.ai_socktype, protocol: a.ai_protocol, addr: core::slice::from_raw_parts(a.ai_addr as *const u8, a.ai_addrlen as usize).to_vec(), flags: a.ai_flags });
            p = a.ai_next;
        }
    }
    (v, canon)
}

fn collect_host(mut p: *const libc::addrinfo) -> (Vec<Item>, Option<String>) {
    let mut v = vec![];
    let canon = if p.is_null() { None } else { cstr_opt(unsafe { (*p).ai_canonname }) };
    unsafe {
        while !p.is_null() {
            let a = &*p;
            v.push(Item { family: a.ai_family, socktype: a.ai_socktype, protocol: a.ai_protocol, addr: core::slice::from_raw_parts(a.ai_addr as *const u8, a.ai_addrlen as usize).to_vec(), flags: a.ai_flags });
            p = a.ai_next;
        }
    }
    (v, canon)
}

fn run_both(node: Option<&str>, serv: Option<&str>, hints: Option<(c_int, c_int, c_int, c_int)>) -> ((c_int, Vec<Item>, Option<String>), (c_int, Vec<Item>, Option<String>)) {
    let cn = node.map(cs);
    let csv = serv.map(cs);
    let np = cn.as_ref().map(|c| c.as_ptr()).unwrap_or(core::ptr::null());
    let sp = csv.as_ref().map(|c| c.as_ptr()).unwrap_or(core::ptr::null());
    let mut ours: *mut addrinfo = core::ptr::null_mut();
    let hi = hints.map(|(f, fam, st, pr)| addrinfo { ai_flags: f, ai_family: fam, ai_socktype: st, ai_protocol: pr, ..addrinfo::default() });
    let rc = unsafe { gai::getaddrinfo(np, sp, hi.as_ref().map(|h| h as *const addrinfo).unwrap_or(core::ptr::null()), &mut ours) };
    let (items, canon) = if rc == 0 { collect_ours(ours) } else { (vec![], None) };
    if rc == 0 {
        unsafe { gai::freeaddrinfo(ours) };
    }
    let mut theirs: *mut libc::addrinfo = core::ptr::null_mut();
    let hh = hints.map(|(f, fam, st, pr)| {
        let mut h: libc::addrinfo = unsafe { core::mem::zeroed() };
        h.ai_flags = f;
        h.ai_family = fam;
        h.ai_socktype = st;
        h.ai_protocol = pr;
        h
    });
    let rc2 = unsafe { libc::getaddrinfo(np, sp, hh.as_ref().map(|h| h as *const libc::addrinfo).unwrap_or(core::ptr::null()), &mut theirs) };
    let (items2, canon2) = if rc2 == 0 { collect_host(theirs) } else { (vec![], None) };
    if rc2 == 0 {
        unsafe { libc::freeaddrinfo(theirs) };
    }
    ((rc, items, canon), (rc2, items2, canon2))
}

#[test]
fn getaddrinfo_matches_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::files_only();
    let nodes: [Option<&str>; 16] = [None, Some("*"), Some("localhost"), Some("LocalHost"), Some("localhost4"), Some("localhost6"), Some("127.0.0.1"), Some("::1"), Some("::ffff:1.2.3.4"), Some("1.2.3.4"), Some("1.2.3"), Some("0x7f.1"), Some("fe80::1%lo"), Some("fe80::1%1"), Some("fe80::1%nosuchif"), Some("2001:db8::1")];
    let servs: [Option<&str>; 12] = [None, Some("80"), Some("http"), Some("domain"), Some("0"), Some(""), Some("99999"), Some("*"), Some("nosuchservice"), Some("  80"), Some("80abc"), Some("ntp")];
    let mut r = Rng(0x600d_cafe);
    let mut compared = 0usize;
    let mut order_diff = 0usize;
    for round in 0..6000 {
        let node = nodes[r.below(nodes.len())];
        let serv = servs[r.below(servs.len())];
        let hints = if r.below(8) == 0 {
            None
        } else {
            let flags = {
                let mut f = 0;
                for bit in [AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST, AI_NUMERICSERV, AI_V4MAPPED, AI_ALL, AI_ADDRCONFIG] {
                    if r.below(3) == 0 {
                        f |= bit;
                    }
                }
                if r.below(50) == 0 {
                    f |= 0x1000;
                }
                f
            };
            let fam = [0, 0, AF_INET, AF_INET6, 3][r.below(5)];
            let st = [0, 0, 1, 2, 3, 5, 99][r.below(7)];
            let pr = [0, 0, 6, 17, 132, 255, 1][r.below(7)];
            Some((flags, fam, st, pr))
        };
        // the host asks DNS for names its files do not know; keep to names the hosts file answers
        let ((rc, items, canon), (rc2, items2, canon2)) = run_both(node, serv, hints);
        let sets_equal = {
            let (mut a, mut b) = (items.clone(), items2.clone());
            a.sort();
            b.sort();
            a == b
        };
        // for names that need DNS on the host the answers can legitimately differ: not in the node list
        // The host's nsswitch.conf lists mdns4_minimal, which answers NO_DATA (not "not found") for an
        // IPv6 query of a name that only has IPv4 addresses; with `files dns` the answer is "not found".
        if rc == EAI_NONAME && rc2 == EAI_NODATA && node.map(|n| n.starts_with("localhost")).unwrap_or(false) {
            continue;
        }
        assert_eq!(rc, rc2, "round {round}: getaddrinfo({node:?}, {serv:?}, {hints:?}): ours {rc} theirs {rc2}");
        assert!(sets_equal, "round {round}: getaddrinfo({node:?}, {serv:?}, {hints:?}):\nours   {items:?}\ntheirs {items2:?}");
        assert_eq!(canon, canon2, "round {round}: canonname of getaddrinfo({node:?}, {serv:?}, {hints:?})");
        if items != items2 {
            order_diff += 1;
            if order_diff <= 5 {
                eprintln!("order differs for ({node:?}, {serv:?}, {hints:?}):\n  ours   {:?}\n  theirs {:?}", items.iter().map(|i| (i.family, i.socktype)).collect::<Vec<_>>(), items2.iter().map(|i| (i.family, i.socktype)).collect::<Vec<_>>());
            }
        }
        compared += 1;
    }
    eprintln!("getaddrinfo: {compared} combinations compared, {order_diff} with a different result order");
    assert_eq!(order_diff, 0, "result order must equal glibc's for the loopback cases");
}

#[test]
fn getnameinfo_matches_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::files_only();
    let mut socks: Vec<(String, Vec<u8>)> = vec![];
    for (name, ip) in [("lo4", [127u8, 0, 0, 1]), ("lo4b", [127, 0, 0, 2])] {
        for port in [80u16, 53, 0, 65535, 9, 22, 12345] {
            let (ss, len) = crate::rustapi::SockAddr::V4 { addr: ip, port }.to_raw();
            socks.push((format!("{name}:{port}"), unsafe { core::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) }.to_vec()));
        }
    }
    let mut lo6 = [0u8; 16];
    lo6[15] = 1;
    for port in [80u16, 123, 0] {
        for scope in [0u32, 1, 12345] {
            let (ss, len) = crate::rustapi::SockAddr::V6 { addr: lo6, port, flowinfo: 0, scope_id: scope }.to_raw();
            socks.push((format!("lo6:{port}%{scope}"), unsafe { core::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) }.to_vec()));
        }
    }
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    for scope in [0u32, 1, 99999] {
        let (ss, len) = crate::rustapi::SockAddr::V6 { addr: ll, port: 80, flowinfo: 0, scope_id: scope }.to_raw();
        socks.push((format!("ll6%{scope}"), unsafe { core::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) }.to_vec()));
    }
    let mut other = [0u8; 16];
    other[0] = 0x20;
    other[1] = 1;
    other[2] = 0xd;
    other[3] = 0xb8;
    other[15] = 9;
    let (ss, len) = crate::rustapi::SockAddr::V6 { addr: other, port: 443, flowinfo: 0, scope_id: 0 }.to_raw();
    socks.push(("db8".into(), unsafe { core::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) }.to_vec()));
    let (ss, len) = crate::rustapi::SockAddr::V4 { addr: [1, 2, 3, 4], port: 80 }.to_raw();
    socks.push(("1.2.3.4".into(), unsafe { core::slice::from_raw_parts(&ss as *const _ as *const u8, len as usize) }.to_vec()));
    let un = crate::rustapi::SockAddr::unix(b"/tmp/x.sock").unwrap().to_raw();
    socks.push(("unix".into(), unsafe { core::slice::from_raw_parts(&un.0 as *const _ as *const u8, un.1 as usize) }.to_vec()));
    // a family that is not supported, and truncated lengths
    let mut bad = vec![0u8; 16];
    bad[0] = 99;
    socks.push(("fam99".into(), bad));
    for flags in 0..64 {
        for (name, sa) in &socks {
            let needs_dns = (name.starts_with("db8") || name.starts_with("1.2.3.4") || name.starts_with("ll6") || name.starts_with("lo4b")) && flags & NI_NUMERICHOST == 0;
            if needs_dns {
                continue;
            }
            for (hl, sl) in [(1025u32, 32u32), (3, 3), (0, 0), (10, 1), (1025, 0)] {
                for lenmod in [0usize, 1] {
                    let salen = if lenmod == 1 { sa.len().saturating_sub(4) } else { sa.len() } as u32;
                    let mut ha = vec![0x55 as c_char; 1025];
                    let mut sa_ = vec![0x55 as c_char; 33];
                    let mut hb = ha.clone();
                    let mut sb = sa_.clone();
                    let ra = unsafe { gai::getnameinfo(sa.as_ptr() as *const sockaddr, salen, if hl == 0 { core::ptr::null_mut() } else { ha.as_mut_ptr() }, hl, if sl == 0 { core::ptr::null_mut() } else { sa_.as_mut_ptr() }, sl, flags) };
                    let rb = unsafe { libc::getnameinfo(sa.as_ptr() as *const libc::sockaddr, salen, if hl == 0 { core::ptr::null_mut() } else { hb.as_mut_ptr() }, hl, if sl == 0 { core::ptr::null_mut() } else { sb.as_mut_ptr() }, sl, flags) };
                    assert_eq!(ra, rb, "getnameinfo({name}, flags={flags}, hl={hl}, sl={sl}, len={salen}): ours {ra} theirs {rb}");
                    if ra == 0 {
                        if hl > 0 {
                            assert_eq!(unsafe { CStr::from_ptr(ha.as_ptr()) }, unsafe { CStr::from_ptr(hb.as_ptr()) }, "host of {name} flags={flags}");
                        }
                        if sl > 0 {
                            assert_eq!(unsafe { CStr::from_ptr(sa_.as_ptr()) }, unsafe { CStr::from_ptr(sb.as_ptr()) }, "serv of {name} flags={flags}");
                        }
                    }
                }
            }
        }
    }
    // null address
    assert_eq!(unsafe { gai::getnameinfo(core::ptr::null(), 16, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0, 0) }, unsafe { libc::getnameinfo(core::ptr::null(), 16, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0, 0) });
}

// ---------------------------------------------------------------- interfaces

fn ifname(p: *const c_char) -> String {
    cstr_opt(p).unwrap_or_default()
}

fn sa_text(p: *const sockaddr) -> String {
    if p.is_null() {
        return "-".into();
    }
    unsafe {
        let fam = (*p).sa_family as c_int;
        match fam {
            AF_INET => {
                let s = p as *const sockaddr_in;
                format!("4:{:?}", (*s).sin_addr.s_addr.to_ne_bytes())
            }
            AF_INET6 => {
                let s = p as *const sockaddr_in6;
                format!("6:{:?}%{}", (*s).sin6_addr.s6_addr, (*s).sin6_scope_id)
            }
            AF_PACKET => {
                let s = p as *const sockaddr_ll;
                format!("p:{}:{}:{}:{:?}", (*s).sll_ifindex, (*s).sll_hatype, (*s).sll_halen, (*s).sll_addr)
            }
            f => format!("?{f}"),
        }
    }
}

#[test]
fn getifaddrs_matches_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut a: *mut crate::types::ifaddrs = core::ptr::null_mut();
    assert_eq!(unsafe { ifa::getifaddrs(&mut a) }, 0);
    let mut ours = vec![];
    let mut p = a;
    while !p.is_null() {
        unsafe {
            let e = &*p;
            let b = sa_text(e.ifa_ifu.ifu_broadaddr);
            ours.push((ifname(e.ifa_name), sa_text(e.ifa_addr), sa_text(e.ifa_netmask), e.ifa_flags, b, !e.ifa_data.is_null()));
            p = e.ifa_next;
        }
    }
    unsafe { ifa::freeifaddrs(a) };
    let mut h: *mut libc::ifaddrs = core::ptr::null_mut();
    assert_eq!(unsafe { libc::getifaddrs(&mut h) }, 0);
    let mut theirs = vec![];
    let mut p = h;
    while !p.is_null() {
        unsafe {
            let e = &*p;
            theirs.push((ifname(e.ifa_name), sa_text(e.ifa_addr as *const sockaddr), sa_text(e.ifa_netmask as *const sockaddr), e.ifa_flags, sa_text(e.ifa_ifu as *const sockaddr), !e.ifa_data.is_null()));
            p = e.ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(h) };
    assert!(!ours.is_empty());
    let mut o = ours.clone();
    let mut t = theirs.clone();
    o.sort();
    t.sort();
    assert_eq!(o, t, "getifaddrs sets differ");
    assert_eq!(ours, theirs, "getifaddrs order differs");
}

#[test]
fn interface_names_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ni = unsafe { ifa::if_nameindex() };
    let hi = unsafe { libc::if_nameindex() };
    let list = |mut p: *const (c_int, *const c_char)| {
        let mut v = vec![];
        unsafe {
            while (*p).0 != 0 {
                v.push(((*p).0, ifname((*p).1)));
                p = p.add(1);
            }
        }
        v
    };
    let ours = list(ni as *const _);
    let theirs = list(hi as *const _);
    unsafe {
        ifa::if_freenameindex(ni);
        libc::if_freenameindex(hi);
    }
    assert_eq!(ours, theirs);
    assert!(ours.iter().any(|(_, n)| n == "lo"));
    for (idx, name) in &ours {
        let c = cs(name);
        assert_eq!(unsafe { ifa::if_nametoindex(c.as_ptr()) }, *idx as u32);
        let mut buf = [0 as c_char; 16];
        let r = unsafe { ifa::if_indextoname(*idx as u32, buf.as_mut_ptr()) };
        assert!(!r.is_null());
        assert_eq!(ifname(buf.as_ptr()), *name);
    }
    for bad in ["", "nosuchif0", "a-very-long-interface-name-over-15"] {
        let c = cs(bad);
        rusty_libc_core::errno::set(0);
        let ra = unsafe { ifa::if_nametoindex(c.as_ptr()) };
        let ea = rusty_libc_core::errno::get();
        unsafe { *libc::__errno_location() = 0 };
        let rb = unsafe { libc::if_nametoindex(c.as_ptr()) };
        assert_eq!((ra, ea), (rb, unsafe { *libc::__errno_location() }), "if_nametoindex({bad:?})");
    }
    for bad in [0u32, 99999] {
        let mut b1 = [0 as c_char; 16];
        let mut b2 = [0 as c_char; 16];
        rusty_libc_core::errno::set(0);
        let ra = unsafe { ifa::if_indextoname(bad, b1.as_mut_ptr()) };
        let ea = rusty_libc_core::errno::get();
        unsafe { *libc::__errno_location() = 0 };
        let rb = unsafe { libc::if_indextoname(bad, b2.as_mut_ptr()) };
        assert_eq!((ra.is_null(), ea), (rb.is_null(), unsafe { *libc::__errno_location() }), "if_indextoname({bad})");
    }
}

// ---------------------------------------------------------------- enumerations

#[test]
fn enumerations_match_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // services
    let mut ours = vec![];
    unsafe {
        netdb::setservent(0);
        let mut res = servent_zero();
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut servent = core::ptr::null_mut();
            let rc = netdb::getservent_r(&mut res, buf.as_mut_ptr(), buf.len(), &mut out);
            if out.is_null() {
                ours.push((rc, None));
                break;
            }
            ours.push((rc, dump_servent(out as *const u8)));
        }
        netdb::endservent();
    }
    let mut theirs = vec![];
    unsafe {
        host::setservent(0);
        let mut res = [0u8; 64];
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut u8 = core::ptr::null_mut();
            let rc = host::getservent_r(res.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut out);
            if out.is_null() {
                theirs.push((rc, None));
                break;
            }
            theirs.push((rc, dump_servent(out as *const u8)));
        }
        host::endservent();
    }
    assert_eq!(ours.len(), theirs.len());
    assert_eq!(ours, theirs);
    // protocols
    let mut ours = vec![];
    unsafe {
        netdb::setprotoent(1);
        let mut res = core::mem::zeroed::<protoent>();
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut protoent = core::ptr::null_mut();
            let rc = netdb::getprotoent_r(&mut res, buf.as_mut_ptr(), buf.len(), &mut out);
            if out.is_null() {
                ours.push((rc, None));
                break;
            }
            ours.push((rc, dump_protoent(out as *const u8)));
        }
        netdb::endprotoent();
    }
    let mut theirs = vec![];
    unsafe {
        host::setprotoent(1);
        let mut res = [0u8; 64];
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut u8 = core::ptr::null_mut();
            let rc = host::getprotoent_r(res.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut out);
            if out.is_null() {
                theirs.push((rc, None));
                break;
            }
            theirs.push((rc, dump_protoent(out as *const u8)));
        }
        host::endprotoent();
    }
    assert_eq!(ours, theirs);
    // hosts (the whole /etc/hosts as a list)
    let _etc = EtcGuard::files_only();
    let mut ours = vec![];
    unsafe {
        netdb::sethostent(0);
        let mut res = core::mem::zeroed::<hostent>();
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut hostent = core::ptr::null_mut();
            let mut h = 0;
            let rc = netdb::gethostent_r(&mut res, buf.as_mut_ptr(), buf.len(), &mut out, &mut h);
            if out.is_null() {
                ours.push((rc, None));
                break;
            }
            ours.push((rc, dump_hostent(out as *const u8)));
        }
        netdb::endhostent();
    }
    let mut theirs = vec![];
    unsafe {
        host::sethostent(0);
        let mut res = [0u8; 64];
        let mut buf = vec![0 as c_char; 4096];
        loop {
            let mut out: *mut u8 = core::ptr::null_mut();
            let mut h = 0;
            let rc = host::gethostent_r(res.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut out, &mut h);
            if out.is_null() {
                theirs.push((rc, None));
                break;
            }
            theirs.push((rc, dump_hostent(out as *const u8)));
        }
        host::endhostent();
    }
    assert_eq!(ours, theirs);
}

#[test]
fn static_buffer_functions_match_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::files_only();
    for (n, p) in [("http", "tcp"), ("domain", "udp"), ("nosuch", "tcp")] {
        let (cn, cp) = (cs(n), cs(p));
        rusty_libc_core::errno::set(0);
        let a = unsafe { netdb::getservbyname(cn.as_ptr(), cp.as_ptr()) };
        let ea = rusty_libc_core::errno::get();
        unsafe { *libc::__errno_location() = 0 };
        let b = unsafe { host::getservbyname(cn.as_ptr(), cp.as_ptr()) };
        let eb = unsafe { *libc::__errno_location() };
        assert_eq!((dump_servent(a as *const u8), ea), (dump_servent(b as *const u8), eb), "getservbyname({n},{p})");
    }
    for n in ["tcp", "udp", "nosuch"] {
        let cn = cs(n);
        let a = unsafe { netdb::getprotobyname(cn.as_ptr()) };
        let b = unsafe { host::getprotobyname(cn.as_ptr()) };
        assert_eq!(dump_protoent(a as *const u8), dump_protoent(b as *const u8));
    }
    let a = netdb::getprotobynumber(17);
    let b = unsafe { host::getprotobynumber(17) };
    assert_eq!(dump_protoent(a as *const u8), dump_protoent(b as *const u8));
    // gethostbyname family with errno / h_errno
    let cn = cs("localhost");
    let a = unsafe { netdb::gethostbyname(cn.as_ptr()) };
    let b = unsafe { host::gethostbyname(cn.as_ptr()) };
    assert_eq!(dump_hostent(a as *const u8), dump_hostent(b as *const u8));
    let a = unsafe { netdb::gethostbyname2(cn.as_ptr(), AF_INET6) };
    let b = unsafe { host::gethostbyname2(cn.as_ptr(), AF_INET6) };
    assert_eq!(dump_hostent(a as *const u8), dump_hostent(b as *const u8));
    let ip = [127u8, 0, 0, 1];
    let a = unsafe { netdb::gethostbyaddr(ip.as_ptr() as *const c_void, 4, AF_INET) };
    let b = unsafe { host::gethostbyaddr(ip.as_ptr() as *const c_void, 4, AF_INET) };
    assert_eq!(dump_hostent(a as *const u8), dump_hostent(b as *const u8));
    // h_errno
    let nx = cs("nonexistent-host-for-test.invalid");
    let a = unsafe { netdb::gethostbyname(nx.as_ptr()) };
    assert!(a.is_null());
    assert_eq!(crate::strerr::h_errno(), HOST_NOT_FOUND);
}

/// Speed against the host's glibc (run with `cargo test -p rusty-libc-net --release -- --ignored --nocapture speed`).
#[test]
#[ignore]
fn speed_vs_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::time::Instant;
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::files_only();
    fn time(n: u32, mut f: impl FnMut()) -> f64 {
        for _ in 0..n / 10 + 1 {
            f();
        }
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        t.elapsed().as_nanos() as f64 / n as f64
    }
    let host = cs("localhost");
    let serv = cs("80");
    let s_http = cs("http");
    let tcp = cs("tcp");
    let rows: Vec<(&str, f64, f64)> = vec![
        ("inet_pton v6", time(200000, || unsafe {
            let mut b = [0u8; 16];
            crate::inet::inet_pton(AF_INET6, c"2001:db8::ff00:42:8329".as_ptr(), b.as_mut_ptr() as *mut c_void);
            core::hint::black_box(&b);
        }), time(200000, || unsafe {
            let mut b = [0u8; 16];
            host::inet_pton(AF_INET6, c"2001:db8::ff00:42:8329".as_ptr(), b.as_mut_ptr() as *mut c_void);
            core::hint::black_box(&b);
        })),
        ("inet_ntop v6", time(200000, || unsafe {
            let a = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut o = [0 as c_char; 64];
            crate::inet::inet_ntop(AF_INET6, a.as_ptr() as *const c_void, o.as_mut_ptr(), 64);
            core::hint::black_box(&o);
        }), time(200000, || unsafe {
            let a = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            let mut o = [0 as c_char; 64];
            host::inet_ntop(AF_INET6, a.as_ptr() as *const c_void, o.as_mut_ptr(), 64);
            core::hint::black_box(&o);
        })),
        ("getservbyname(http)", time(5000, || unsafe {
            core::hint::black_box(crate::netdb::getservbyname(s_http.as_ptr(), tcp.as_ptr()));
        }), time(5000, || unsafe {
            core::hint::black_box(host::getservbyname(s_http.as_ptr(), tcp.as_ptr()));
        })),
        ("gethostbyname(localhost)", time(5000, || unsafe {
            core::hint::black_box(crate::netdb::gethostbyname(host.as_ptr()));
        }), time(5000, || unsafe {
            core::hint::black_box(host::gethostbyname(host.as_ptr()));
        })),
        ("getaddrinfo(localhost,80) default hints", time(2000, || unsafe {
            let mut r: *mut addrinfo = core::ptr::null_mut();
            crate::gai::getaddrinfo(host.as_ptr(), serv.as_ptr(), core::ptr::null(), &mut r);
            crate::gai::freeaddrinfo(r);
        }), time(2000, || unsafe {
            let mut r: *mut libc::addrinfo = core::ptr::null_mut();
            libc::getaddrinfo(host.as_ptr(), serv.as_ptr(), core::ptr::null(), &mut r);
            libc::freeaddrinfo(r);
        })),
        ("getaddrinfo(127.0.0.1,80) numeric", time(20000, || unsafe {
            let mut r: *mut addrinfo = core::ptr::null_mut();
            let h = addrinfo { ai_flags: AI_NUMERICHOST | AI_NUMERICSERV, ai_socktype: SOCK_STREAM, ..addrinfo::default() };
            crate::gai::getaddrinfo(c"127.0.0.1".as_ptr(), serv.as_ptr(), &h, &mut r);
            crate::gai::freeaddrinfo(r);
        }), time(20000, || unsafe {
            let mut r: *mut libc::addrinfo = core::ptr::null_mut();
            let mut h: libc::addrinfo = core::mem::zeroed();
            h.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
            h.ai_socktype = SOCK_STREAM;
            libc::getaddrinfo(c"127.0.0.1".as_ptr(), serv.as_ptr(), &h, &mut r);
            libc::freeaddrinfo(r);
        })),
        ("getifaddrs+free", time(2000, || unsafe {
            let mut l: *mut crate::types::ifaddrs = core::ptr::null_mut();
            crate::ifaddrs::getifaddrs(&mut l);
            crate::ifaddrs::freeifaddrs(l);
        }), time(2000, || unsafe {
            let mut l: *mut libc::ifaddrs = core::ptr::null_mut();
            libc::getifaddrs(&mut l);
            libc::freeifaddrs(l);
        })),
        ("if_nametoindex(lo)", time(20000, || unsafe {
            core::hint::black_box(crate::ifaddrs::if_nametoindex(c"lo".as_ptr()));
        }), time(20000, || unsafe {
            core::hint::black_box(libc::if_nametoindex(c"lo".as_ptr()));
        })),
    ];
    eprintln!("{:<42} {:>10} {:>10} {:>7}", "operation", "ours ns", "glibc ns", "ratio");
    for (n, a, b) in rows {
        eprintln!("{:<42} {:>10.0} {:>10.0} {:>7.2}", n, a, b, a / b);
    }
}
