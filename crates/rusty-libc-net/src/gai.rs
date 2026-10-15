#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::dns::{Addr, HostData};
use crate::inet;
use crate::netdb;
use crate::nss::{self, Action, Source, Status};
use crate::strerr::set_h_errno;
use crate::types::*;
use crate::util::{Buf, HeapVec, cbytes};
use core::ffi::{CStr, c_char, c_int, c_void};
use crate::netdb::{Bytes, CIn, OptBytesMut, OptRef, OptStr, Out};
use rusty_libc_core::errno;

const DEPRECATED_AI_IDN: c_int = 0x300;
const AI_DEFAULT: c_int = AI_V4MAPPED | AI_ADDRCONFIG;
const IPPROTO_SCTP: c_int = 132;
const IPPROTO_UDPLITE: c_int = 136;
const IPPROTO_DCCP: c_int = 33;
const IPPROTO_MPTCP: c_int = 262;
const SOCK_DCCP: c_int = 6;

struct TypeProto {
    socktype: c_int,
    protocol: c_int,
    protoany: bool,
    noservice: bool,
    default: bool,
    name: &'static [u8],
}

const TP: &[TypeProto] = &[
    TypeProto { socktype: 0, protocol: 0, protoany: false, noservice: false, default: false, name: b"" },
    TypeProto { socktype: SOCK_STREAM, protocol: IPPROTO_TCP, protoany: false, noservice: false, default: true, name: b"tcp" },
    TypeProto { socktype: SOCK_DGRAM, protocol: IPPROTO_UDP, protoany: false, noservice: false, default: true, name: b"udp" },
    TypeProto { socktype: SOCK_DCCP, protocol: IPPROTO_DCCP, protoany: false, noservice: false, default: false, name: b"dccp" },
    TypeProto { socktype: SOCK_DGRAM, protocol: IPPROTO_UDPLITE, protoany: false, noservice: false, default: false, name: b"udplite" },
    TypeProto { socktype: SOCK_STREAM, protocol: IPPROTO_SCTP, protoany: false, noservice: false, default: false, name: b"sctp" },
    TypeProto { socktype: SOCK_SEQPACKET, protocol: IPPROTO_SCTP, protoany: false, noservice: false, default: false, name: b"sctp" },
    TypeProto { socktype: SOCK_STREAM, protocol: IPPROTO_MPTCP, protoany: false, noservice: false, default: false, name: b"mptcp" },
    TypeProto { socktype: SOCK_RAW, protocol: 0, protoany: true, noservice: true, default: true, name: b"raw" },
];

#[derive(Clone, Copy, Default)]
struct ServTuple {
    socktype: c_int,
    protocol: c_int,
    port: u16,
    set: bool,
}

const MAX_ST: usize = 12;

enum Service<'a> {
    Num(i32),
    Name(&'a [u8]),
}

fn serv_by_name(name: &[u8], proto: &[u8]) -> Option<u16> {
    let mut n = Buf::<256>::from(name)?;
    n.push(0);
    let mut p = Buf::<16>::from(proto)?;
    p.push(0);
    let n = CStr::from_bytes_until_nul(n.as_bytes()).ok()?;
    let p = CStr::from_bytes_until_nul(p.as_bytes()).ok()?;
    let mut res = SERVENT_ZERO;
    let mut buf = [0u8; 1024];
    with_growing(&mut buf, |b| match netdb::servbyname_r(n, Some(p), &mut res, b) {
        (ERANGE, _) => None,
        (0, true) => Some(Some(res.s_port as u16)),
        _ => Some(None),
    })
    .flatten()
}

fn with_growing<R>(first: &mut [u8], mut f: impl FnMut(&mut [u8]) -> Option<R>) -> Option<R> {
    if let Some(r) = f(first) {
        return Some(r);
    }
    let mut cap = first.len();
    let mut heap = crate::nss::ZBuf::new();
    loop {
        cap *= 2;
        if !heap.grow(cap) {
            return None;
        }
        if let Some(r) = f(heap.as_mut_slice()) {
            return Some(r);
        }
    }
}

const SERVENT_ZERO: servent = servent { s_name: core::ptr::null_mut(), s_aliases: core::ptr::null_mut(), s_port: 0, s_proto: core::ptr::null_mut() };

fn get_servtuples(service: &Option<Service>, req_socktype: c_int, req_protocol: c_int, st: &mut [ServTuple; MAX_ST]) -> Result<(), c_int> {
    let mut ti = 0usize;
    if req_protocol != 0 || req_socktype != 0 {
        ti = 1;
        while !TP[ti..].is_empty() && ti < TP.len() && !TP[ti].name.is_empty() && ((req_socktype != 0 && req_socktype != TP[ti].socktype) || (req_protocol != 0 && !TP[ti].protoany && req_protocol != TP[ti].protocol)) {
            ti += 1;
        }
        if ti >= TP.len() || TP[ti].name.is_empty() {
            return Err(if req_socktype != 0 { EAI_SOCKTYPE } else { EAI_SERVICE });
        }
    }
    if service.is_some() && TP[ti].noservice {
        return Err(EAI_SERVICE);
    }
    match service {
        None | Some(Service::Num(_)) => {
            let port = match service {
                Some(Service::Num(n)) => (*n as u16).to_be(),
                _ => 0,
            };
            if req_socktype != 0 || req_protocol != 0 {
                st[0] = ServTuple { socktype: TP[ti].socktype, protocol: if TP[ti].protoany { req_protocol } else { TP[ti].protocol }, port, set: true };
                return Ok(());
            }
            let mut i = 0;
            for t in &TP[1..] {
                if t.name.is_empty() {
                    break;
                }
                if t.default {
                    st[i] = ServTuple { socktype: t.socktype, protocol: t.protocol, port, set: true };
                    i += 1;
                }
            }
            Ok(())
        }
        Some(Service::Name(sn)) => {
            let one = |t: &TypeProto, req_protocol: c_int| -> Result<ServTuple, c_int> {
                match serv_by_name(sn, t.name) {
                    Some(port) => Ok(ServTuple { socktype: t.socktype, protocol: if t.protoany { req_protocol } else { t.protocol }, port, set: true }),
                    None => Err(EAI_SERVICE),
                }
            };
            if !TP[ti].name.is_empty() {
                st[0] = one(&TP[ti], req_protocol)?;
                return Ok(());
            }
            let mut i = 0;
            for t in &TP[1..] {
                if t.name.is_empty() {
                    break;
                }
                if t.noservice {
                    continue;
                }
                if req_socktype != 0 && req_socktype != t.socktype {
                    continue;
                }
                if req_protocol != 0 && !t.protoany && req_protocol != t.protocol {
                    continue;
                }
                if let Ok(x) = one(t, req_protocol) {
                    if i < MAX_ST {
                        st[i] = x;
                        i += 1;
                    }
                }
            }
            if !st[0].set { Err(EAI_SERVICE) } else { Ok(()) }
        }
    }
}

#[derive(Clone, Copy)]
struct At {
    family: c_int,
    addr: [u8; 16],
    scope: u32,
}

struct Found {
    at: HeapVec<At>,
    oom: bool,
    canon: Option<Buf<256>>,
    got_ipv6: bool,
}

impl Found {
    fn new() -> Found {
        Found { at: HeapVec::new(), oom: false, canon: None, got_ipv6: false }
    }
    fn push(&mut self, a: At) {
        if !self.at.push(a) {
            self.oom = true;
        }
    }
}

fn map_v4(a: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[10] = 0xff;
    o[11] = 0xff;
    o[12..].copy_from_slice(&a[..4]);
    o
}

fn text_to_binary(name: &[u8], fam: c_int, flags: c_int, found: &mut Found) -> Result<bool, c_int> {
    if let Some((v, end)) = inet::parse_aton(name) {
        if end == name.len() {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&v);
            if fam == AF_UNSPEC || fam == AF_INET {
                found.push(At { family: AF_INET, addr: a, scope: 0 });
            } else if fam == AF_INET6 && flags & AI_V4MAPPED != 0 {
                found.push(At { family: AF_INET6, addr: map_v4(&a), scope: 0 });
            } else {
                return Err(EAI_ADDRFAMILY);
            }
            if flags & AI_CANONNAME != 0 {
                found.canon = Buf::from(&name[..name.len().min(256)]);
            }
            return Ok(true);
        }
    }
    let (host, scope) = match name.iter().position(|&c| c == b'%') {
        Some(p) => (&name[..p], Some(&name[p + 1..])),
        None => (name, None),
    };
    if let Some(v6) = inet::parse_ipv6(host) {
        let mut at = At { family: AF_INET6, addr: v6, scope: 0 };
        if fam == AF_UNSPEC || fam == AF_INET6 {
        } else if fam == AF_INET && v6[..10] == [0; 10] && v6[10] == 0xff && v6[11] == 0xff {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&v6[12..]);
            at = At { family: AF_INET, addr: a, scope: 0 };
        } else {
            return Err(EAI_ADDRFAMILY);
        }
        if let Some(s) = scope {
            match crate::ifaddrs::scopeid_pton(&v6, s) {
                Some(id) => at.scope = id,
                None => return Err(EAI_NONAME),
            }
        }
        found.push(at);
        if flags & AI_CANONNAME != 0 {
            found.canon = Buf::from(&name[..name.len().min(256)]);
        }
        return Ok(true);
    }
    if flags & AI_NUMERICHOST != 0 {
        return Err(EAI_NONAME);
    }
    Ok(false)
}

fn convert(found: &mut Found, fam: c_int, req_family: c_int, d: &HostData) {
    for a in &d.addrs[..d.n] {
        if fam == AF_INET && req_family == AF_INET6 {
            found.push(At { family: AF_INET6, addr: map_v4(&a.bytes), scope: 0 });
        } else {
            found.push(At { family: fam, addr: a.bytes, scope: a.scope });
        }
    }
    found.got_ipv6 = fam == AF_INET6;
}

fn module_has_lookup(e: &nss::Entry, req_family: c_int, flags: c_int) -> bool {
    use rusty_libc_core::nssmod::function;
    let m = e.module_name();
    (req_family == AF_UNSPEC && function(m, b"gethostbyname4_r") != 0) || (flags & AI_CANONNAME != 0 && function(m, b"gethostbyname3_r") != 0) || function(m, b"gethostbyname2_r") != 0
}

fn get_nss_addresses(name: &[u8], req_family: c_int, flags: c_int, found: &mut Found) -> Result<(), c_int> {
    nss::hconf_init();
    let order = nss::hosts_order();
    let mut no_data = 0;
    let mut no_inet6_data = 0;
    let mut status = Status::Unavail;
    let mut inet6_status = Status::Unavail;
    let nd = |st: Status, h: c_int| -> c_int {
        let _ = st;
        if h == TRY_AGAIN {
            EAI_AGAIN
        } else {
            (h == NO_DATA) as c_int
        }
    };
    let mut do_merge = false;
    let mut h_internal = false;
    for e in &order.e[..order.n] {
        found.at.clear();
        found.canon = None;
        found.got_ipv6 = false;
        if do_merge {
            errno::set(EBUSY);
            break;
        }
        no_data = 0;
        let mut hd = HostData::new();
        if e.src == Source::Module && !module_has_lookup(e, req_family, flags) {
            status = Status::Unavail;
            h_internal = true;
            errno::set(EBUSY);
        } else if req_family == AF_UNSPEC {
            let (st, h) = netdb::src_lookup(e, name, AF_UNSPEC, false, &mut hd);
            h_internal = h == NETDB_INTERNAL;
            status = st;
            if st == Status::Success {
                no_data = 1;
                if flags & AI_CANONNAME != 0 && hd.have_canon {
                    found.canon = Some(hd.canon);
                }
                for a in &hd.addrs[..hd.n] {
                    found.push(At { family: a.family, addr: a.bytes, scope: a.scope });
                    no_data = 0;
                }
                if hd.addrs[..hd.n].iter().any(|a| a.family == AF_INET6) && req_family == AF_INET6 {
                    found.got_ipv6 = true;
                }
            } else {
                no_data = nd(st, h);
            }
            no_inet6_data = no_data;
        } else {
            if req_family == AF_INET6 {
                let mut d6 = HostData::new();
                let (st, h) = netdb::src_lookup(e, name, AF_INET6, false, &mut d6);
                h_internal = h == NETDB_INTERNAL;
                if st == Status::Success {
                    convert(found, AF_INET6, req_family, &d6);
                    if flags & AI_CANONNAME != 0 && found.canon.is_none() && d6.have_canon {
                        found.canon = Some(d6.canon);
                    }
                    no_data = 0;
                } else {
                    no_data = nd(st, h);
                }
                no_inet6_data = no_data;
                inet6_status = st;
            }
            let need4 = req_family == AF_INET || (req_family == AF_INET6 && flags & AI_V4MAPPED != 0 && (flags & AI_ALL != 0 || !found.got_ipv6));
            if need4 {
                let mut d4 = HostData::new();
                let (st, h) = netdb::src_lookup(e, name, AF_INET, false, &mut d4);
                h_internal = h == NETDB_INTERNAL;
                status = st;
                if st == Status::Success {
                    convert(found, AF_INET, req_family, &d4);
                    if flags & AI_CANONNAME != 0 && found.canon.is_none() && d4.have_canon {
                        found.canon = Some(d4.canon);
                    }
                    no_data = 0;
                } else {
                    no_data = nd(st, h);
                }
                if req_family == AF_INET {
                    no_inet6_data = no_data;
                    inet6_status = st;
                }
            }
            if inet6_status == Status::Success || status == Status::Success {
                status = Status::Success;
            } else if inet6_status == Status::TryAgain {
                status = Status::TryAgain;
            } else if status == Status::Unavail && inet6_status != Status::Unavail {
                status = inet6_status;
            }
        }
        if e.action(status) == Action::Return {
            break;
        }
        if e.action(status) == Action::Merge {
            do_merge = true;
        }
    }
    if matches!(status, Status::TryAgain | Status::Unavail) && h_internal {
        return Err(EAI_SYSTEM);
    }
    if !found.at.is_empty() {
        return Ok(());
    }
    if no_data != 0 && no_inet6_data != 0 {
        if no_data == EAI_AGAIN && no_inet6_data == EAI_AGAIN {
            return Err(EAI_AGAIN);
        }
        return Err(EAI_NODATA);
    }
    Err(EAI_NONAME)
}

struct Prefix {
    prefix: [u8; 16],
    bits: u32,
    val: i32,
}

const fn pfx(head: &[u8], bits: u32, val: i32) -> Prefix {
    let mut p = [0u8; 16];
    let mut i = 0;
    while i < head.len() {
        p[i] = head[i];
        i += 1;
    }
    Prefix { prefix: p, bits, val }
}

const LOOP: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

static LABELS: [Prefix; 8] = [
    Prefix { prefix: LOOP, bits: 128, val: 0 },
    pfx(&[0x20, 0x02], 16, 2),
    pfx(&[], 96, 3),
    pfx(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96, 4),
    pfx(&[0xfe, 0xc0], 10, 5),
    pfx(&[0xfc], 7, 6),
    pfx(&[0x20, 0x01], 32, 7),
    pfx(&[], 0, 1),
];

static PRECEDENCE: [Prefix; 5] = [Prefix { prefix: LOOP, bits: 128, val: 50 }, pfx(&[0x20, 0x02], 16, 30), pfx(&[], 96, 20), pfx(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96, 10), pfx(&[], 0, 40)];

fn label_prec_init() {}

fn match_prefix(family: c_int, addr: &[u8; 16], list: &[Prefix], default: i32, last_nonempty: usize) -> i32 {
    let mut a = *addr;
    if family == AF_INET {
        a = map_v4(addr);
    } else if family != AF_INET6 {
        return default;
    }
    for p in &list[..last_nonempty] {
        let mut bits = p.bits as usize;
        let mut i = 0;
        let mut ok = true;
        while bits >= 8 {
            if p.prefix[i] != a[i] {
                ok = false;
                break;
            }
            i += 1;
            bits -= 8;
        }
        if ok && bits < 8 {
            if i >= 16 {
                return p.val;
            }
            let m = (0xff00u32 >> bits) as u8;
            if p.prefix[i] & m == a[i] & m {
                return p.val;
            }
        }
    }
    list[last_nonempty - 1].val
}

fn get_label(family: c_int, a: &[u8; 16]) -> i32 {
    match_prefix(family, a, &LABELS, i32::MAX, LABELS.len())
}

fn get_precedence(family: c_int, a: &[u8; 16]) -> i32 {
    match_prefix(family, a, &PRECEDENCE, 0, 5)
}

fn get_scope(family: c_int, a: &[u8; 16]) -> i32 {
    if family == AF_INET6 {
        let multicast = a[0] == 0xff;
        if !multicast {
            let ll = a[0] == 0xfe && a[1] & 0xc0 == 0x80;
            let lo = a[..15] == [0; 15] && a[15] == 1;
            if ll || lo {
                2
            } else if a[0] == 0xfe && a[1] & 0xc0 == 0xc0 {
                5
            } else {
                14
            }
        } else {
            (a[1] & 0xf) as i32
        }
    } else if family == AF_INET {
        if a[0] == 169 && a[1] == 254 || a[0] == 127 {
            2
        } else {
            14
        }
    } else {
        15
    }
}

#[derive(Clone, Copy)]
struct SortInfo {
    got_source: bool,
    src_family: c_int,
    src: [u8; 16],
    flags: u32,
    prefixlen: u8,
    index: u32,
}

fn source_for(at: &At, locals: &[crate::ifaddrs::LocalAddr]) -> SortInfo {
    let mut si = SortInfo { got_source: false, src_family: 0, src: [0; 16], flags: 0, prefixlen: 0, index: u32::MAX };
    let fd = crate::dns::sock_open(at.family, SOCK_DGRAM | SOCK_CLOEXEC);
    if fd < 0 {
        return si;
    }
    let mut ss = sockaddr_storage::default();
    let len = crate::dns::sockaddr_from(at.family, &at.addr, 0, at.scope, &mut ss);
    let mut out = sockaddr_storage::default();
    let ok = crate::dns::sock_connect(fd, &ss, len) == 0 && crate::dns::sock_name(fd, &mut out) == 0;
    let _ = rusty_libc_core::unistd::close(fd);
    if !ok {
        return si;
    }
    si.got_source = true;
    si.src_family = at.family;
    if at.family == AF_INET {
        si.src[..4].copy_from_slice(&out.__ss_padding[2..6]);
    } else {
        si.src.copy_from_slice(&out.__ss_padding[6..22]);
    }
    let mut key = si.src;
    if at.family == AF_INET && key[0] == 127 {
        key[..4].copy_from_slice(&[127, 0, 0, 1]);
    }
    for l in locals {
        if l.family == at.family && l.addr[..(if at.family == AF_INET { 4 } else { 16 })] == key[..(if at.family == AF_INET { 4 } else { 16 })] {
            si.flags = l.flags;
            si.prefixlen = l.prefixlen;
            si.index = l.index;
            break;
        }
    }
    si
}

fn lead_zeros32(x: u32) -> i32 {
    x.leading_zeros() as i32
}

fn cmp_addr(a1: &At, s1: &SortInfo, a2: &At, s2: &SortInfo) -> core::cmp::Ordering {
    use core::cmp::Ordering::*;
    if s1.got_source && !s2.got_source {
        return Less;
    }
    if !s1.got_source && s2.got_source {
        return Greater;
    }
    let d1 = get_scope(a1.family, &a1.addr);
    let d2 = get_scope(a2.family, &a2.addr);
    if s1.got_source {
        let sc1 = get_scope(s1.src_family, &s1.src);
        let sc2 = get_scope(s2.src_family, &s2.src);
        if d1 == sc1 && d2 != sc2 {
            return Less;
        }
        if d1 != sc1 && d2 == sc2 {
            return Greater;
        }
        let dep = |s: &SortInfo| s.flags & crate::ifaddrs::IFA_F_DEPRECATED != 0;
        if !dep(s1) && dep(s2) {
            return Less;
        }
        if dep(s1) && !dep(s2) {
            return Greater;
        }
        let home = |s: &SortInfo| s.flags & 0x10 != 0;
        if !home(s1) && home(s2) {
            return Greater;
        }
        if home(s1) && !home(s2) {
            return Less;
        }
        let l1d = get_label(a1.family, &a1.addr);
        let l1s = get_label(s1.src_family, &s1.src);
        let l2d = get_label(a2.family, &a2.addr);
        let l2s = get_label(s2.src_family, &s2.src);
        if l1d == l1s && l2d != l2s {
            return Less;
        }
        if l1d != l1s && l2d == l2s {
            return Greater;
        }
    }
    let p1 = get_precedence(a1.family, &a1.addr);
    let p2 = get_precedence(a2.family, &a2.addr);
    if p1 > p2 {
        return Less;
    }
    if p1 < p2 {
        return Greater;
    }
    if d1 < d2 {
        return Less;
    }
    if d1 > d2 {
        return Greater;
    }
    if s1.got_source && a1.family == a2.family {
        let (mut b1, mut b2) = (0, 0);
        if a1.family == AF_INET {
            let w = |b: &[u8; 16]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let (d1a, s1a) = (w(&a1.addr), w(&s1.src));
            let nm1 = 0xffff_ffffu32.wrapping_shl(32 - s1.prefixlen as u32);
            if s1a & nm1 == d1a & nm1 {
                b1 = lead_zeros32(d1a ^ s1a);
            }
            let (d2a, s2a) = (w(&a2.addr), w(&s2.src));
            let nm2 = 0xffff_ffffu32.wrapping_shl(32 - s2.prefixlen as u32);
            if s2a & nm2 == d2a & nm2 {
                b2 = lead_zeros32(d2a ^ s2a);
            }
        } else if a1.family == AF_INET6 {
            let w = |b: &[u8; 16], i: usize| u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
            let mut i = 0;
            while i < 4 {
                if w(&a1.addr, i) != w(&s1.src, i) || w(&a2.addr, i) != w(&s2.src, i) {
                    break;
                }
                i += 1;
            }
            if i < 4 {
                b1 = lead_zeros32(w(&a1.addr, i) ^ w(&s1.src, i));
                b2 = lead_zeros32(w(&a2.addr, i) ^ w(&s2.src, i));
            }
        }
        if b1 > b2 {
            return Less;
        }
        if b1 < b2 {
            return Greater;
        }
    }
    Equal
}

fn sort_addresses(at: &mut [At]) -> bool {
    let mut locals = [crate::ifaddrs::LocalAddr { family: 0, addr: [0; 16], prefixlen: 0, index: 0, flags: 0, scope: 0 }; 64];
    let nl = crate::ifaddrs::local_addrs(&mut locals).unwrap_or(0);
    let n = at.len();
    let (mut info, mut idx, mut tmp, mut copy) = (HeapVec::<SortInfo>::new(), HeapVec::<usize>::new(), HeapVec::<usize>::new(), HeapVec::<At>::new());
    for (i, a) in at.iter().enumerate() {
        let si = match at[..i].iter().position(|b| b.family == a.family && b.addr == a.addr && b.scope == a.scope) {
            Some(j) => info[j],
            None => source_for(a, &locals[..nl]),
        };
        if !info.push(si) || !idx.push(i) || !tmp.push(i) {
            return false;
        }
    }
    if !copy.extend_from(at) {
        return false;
    }
    let greater = |a: usize, b: usize| cmp_addr(&copy[a], &info[a], &copy[b], &info[b]) == core::cmp::Ordering::Greater;
    let (mut src, mut dst) = (idx.as_mut_slice(), tmp.as_mut_slice());
    let mut width = 1;
    while width < n {
        let mut lo = 0;
        while lo < n {
            let mid = (lo + width).min(n);
            let hi = (lo + 2 * width).min(n);
            let (mut i, mut j) = (lo, mid);
            for d in dst[lo..hi].iter_mut() {
                if i < mid && (j >= hi || !greater(src[i], src[j])) {
                    *d = src[i];
                    i += 1;
                } else {
                    *d = src[j];
                    j += 1;
                }
            }
            lo = hi;
        }
        core::mem::swap(&mut src, &mut dst);
        width *= 2;
    }
    for (i, a) in at.iter_mut().enumerate() {
        *a = copy[src[i]];
    }
    true
}

fn alloc_ai(flags: c_int, at: &At, st: &ServTuple) -> *mut addrinfo {
    let socklen = if at.family == AF_INET6 { 28 } else { 16 };
    let p = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<addrinfo>() + socklen) } as *mut addrinfo;
    if p.is_null() {
        return p;
    }
    let sa = p.wrapping_add(1) as *mut u8;
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&(at.family as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&st.port.to_ne_bytes());
    if at.family == AF_INET6 {
        b[8..24].copy_from_slice(&at.addr);
        b[24..28].copy_from_slice(&at.scope.to_ne_bytes());
    } else {
        b[4..8].copy_from_slice(&at.addr[..4]);
    }
    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), sa, socklen) };
    let node = addrinfo { ai_flags: flags, ai_family: at.family, ai_socktype: st.socktype, ai_protocol: st.protocol, ai_addrlen: socklen as u32, ai_addr: sa as *mut sockaddr, ai_canonname: core::ptr::null_mut(), ai_next: core::ptr::null_mut() };
    unsafe { p.write(node) };
    p
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo(name: *const c_char, service: *const c_char, hints: *const addrinfo, pai: *mut *mut addrinfo) -> c_int {
    let ((name, service), (hints, pai)) = unsafe { ((OptStr(name), OptStr(service)), (OptRef(hints), Out(pai))).conv() };
    match addrinfo_list(name.map(CStr::to_bytes), service.map(CStr::to_bytes), hints) {
        Ok(head) => {
            *pai = head;
            0
        }
        Err(e) => e,
    }
}

pub fn addrinfo_list(name: Option<&[u8]>, service: Option<&[u8]>, hints: Option<&addrinfo>) -> Result<*mut addrinfo, c_int> {
    {
        let mut name = name;
        let mut service = service;
        if name == Some(b"*") {
            name = None;
        }
        if service == Some(b"*") {
            service = None;
        }
        if name.is_none() && service.is_none() {
            return Err(EAI_NONAME);
        }
        let default_hints = addrinfo { ai_flags: AI_DEFAULT, ..addrinfo::default() };
        let mut h = hints.copied().unwrap_or(default_hints);
        if h.ai_flags & !(AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_ADDRCONFIG | AI_V4MAPPED | AI_IDN | AI_CANONIDN | DEPRECATED_AI_IDN | AI_NUMERICSERV | AI_ALL) != 0 {
            return Err(EAI_BADFLAGS);
        }
        if h.ai_flags & AI_CANONNAME != 0 && name.is_none() {
            return Err(EAI_BADFLAGS);
        }
        if h.ai_family != AF_UNSPEC && h.ai_family != AF_INET && h.ai_family != AF_INET6 {
            return Err(EAI_FAMILY);
        }
        if h.ai_flags & AI_ADDRCONFIG != 0 {
            let (s4, s6) = crate::ifaddrs::check_pf();
            if h.ai_family == AF_UNSPEC && (s4 || s6) {
                if s4 != s6 {
                    h.ai_family = if s4 { AF_INET } else { AF_INET6 };
                }
            } else if (h.ai_family == AF_INET && !s4) || (h.ai_family == AF_INET6 && !s6) {
                return Err(EAI_NONAME);
            }
        }
        let svc: Option<Service> = match service {
            Some(s) if !s.is_empty() => {
                let mut i = 0;
                while i < s.len() && crate::util::is_space(s[i]) {
                    i += 1;
                }
                let mut neg = false;
                if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
                    neg = s[i] == b'-';
                    i += 1;
                }
                let st = i;
                let mut v: u64 = 0;
                while i < s.len() && s[i].is_ascii_digit() {
                    v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as u64);
                    i += 1;
                }
                let end = if i == st { 0 } else { i };
                if end != s.len() {
                    if h.ai_flags & AI_NUMERICSERV != 0 {
                        return Err(EAI_NONAME);
                    }
                    Some(Service::Name(s))
                } else {
                    let v = if neg { v.wrapping_neg() } else { v };
                    Some(Service::Num(v as i32))
                }
            }
            _ => None,
        };
        let mut st = [ServTuple::default(); MAX_ST];
        get_servtuples(&svc, h.ai_socktype, h.ai_protocol, &mut st)?;
        let orig = name;
        let idn_name;
        if h.ai_flags & AI_IDN != 0 {
            if let Some(n) = name {
                idn_name = crate::idna::to_dns(n)?;
                if let Some(e) = &idn_name {
                    name = Some(e.as_bytes());
                }
            }
        }
        let mut found = Found::new();
        match name {
            None => {
                if h.ai_family == AF_UNSPEC || h.ai_family == AF_INET6 {
                    let mut a = [0u8; 16];
                    if h.ai_flags & AI_PASSIVE == 0 {
                        a[15] = 1;
                    }
                    found.push(At { family: AF_INET6, addr: a, scope: 0 });
                }
                if h.ai_family == AF_UNSPEC || h.ai_family == AF_INET {
                    let mut a = [0u8; 16];
                    if h.ai_flags & AI_PASSIVE == 0 {
                        a[..4].copy_from_slice(&[127, 0, 0, 1]);
                    }
                    found.push(At { family: AF_INET, addr: a, scope: 0 });
                }
            }
            Some(nm) => match text_to_binary(nm, h.ai_family, h.ai_flags, &mut found) {
                Err(e) => return Err(e),
                Ok(true) => {}
                Ok(false) => {
                    get_nss_addresses(nm, h.ai_family, h.ai_flags, &mut found)?;
                }
            },
        }
        let mut canon: Option<Buf<256>> = None;
        if h.ai_flags & AI_CANONNAME != 0 {
            canon = found.canon.or_else(|| orig.and_then(|n| Buf::from(&n[..n.len().min(256)])));
            if h.ai_flags & AI_CANONIDN != 0 {
                if let Some(c) = &canon {
                    match crate::idna::from_dns(c.as_bytes()) {
                        Ok(Some(u)) => canon = Buf::from(&u.as_bytes()[..u.as_bytes().len().min(256)]),
                        Ok(None) | Err(EAI_IDN_ENCODE) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if found.oom {
            return Err(EAI_MEMORY);
        }
        let mut list = HeapVec::<At>::new();
        for a in found.at.iter() {
            if a.family == AF_INET6 && found.got_ipv6 && h.ai_flags & (AI_V4MAPPED | AI_ALL) == AI_V4MAPPED && a.addr[..10] == [0; 10] && a.addr[10] == 0xff && a.addr[11] == 0xff {
                continue;
            }
            if !list.push(*a) {
                return Err(EAI_MEMORY);
            }
        }
        if list.len() > 1 && !sort_addresses(&mut list) {
            return Err(EAI_MEMORY);
        }
        let mut nodes = AiList { head: core::ptr::null_mut(), tail: core::ptr::null_mut() };
        for a in list.iter() {
            for s in st.iter().take_while(|s| s.set) {
                let ai = alloc_ai(h.ai_flags, a, s);
                if ai.is_null() {
                    return Err(EAI_MEMORY);
                }
                nodes.push(ai);
            }
        }
        if nodes.head.is_null() {
            return Err(EAI_NONAME);
        }
        if let Some(c) = canon {
            let p = crate::nss::c_dup(c.as_bytes());
            if p.is_null() {
                return Err(EAI_MEMORY);
            }
            nodes.set_canon(p as *mut c_char);
        }
        Ok(nodes.finish())
    }
}

struct AiList {
    head: *mut addrinfo,
    tail: *mut addrinfo,
}

impl AiList {
    fn push(&mut self, ai: *mut addrinfo) {
        if self.tail.is_null() {
            self.head = ai;
        } else {
            unsafe { (*self.tail).ai_next = ai };
        }
        self.tail = ai;
    }
    fn set_canon(&mut self, p: *mut c_char) {
        unsafe { (*self.head).ai_canonname = p };
    }
    fn finish(mut self) -> *mut addrinfo {
        core::mem::replace(&mut self.head, core::ptr::null_mut())
    }
}

impl Drop for AiList {
    #[inline]
    fn drop(&mut self) {
        if self.head.is_null() {
            return;
        }
        unsafe { freeaddrinfo(self.head) };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freeaddrinfo(mut ai: *mut addrinfo) {
    while !ai.is_null() {
        let node = unsafe { &*ai };
        let next = node.ai_next;
        if !node.ai_canonname.is_null() {
            unsafe { rusty_libc_malloc::free(node.ai_canonname as *mut c_void) };
        }
        unsafe { rusty_libc_malloc::free(ai as *mut c_void) };
        ai = next;
    }
}

fn domain_name() -> Option<Buf<256>> {
    let mut hd = HostData::new();
    if netdb::lookup_name(b"localhost", AF_INET, false, &mut hd).is_ok() {
        if let Some(d) = hd.canon.as_bytes().iter().position(|&c| c == b'.') {
            return Buf::from(&hd.canon.as_bytes()[d + 1..]);
        }
    }
    let mut un = [0u8; 390];
    crate::dns::uname(&mut un);
    let nn = &un[65..130];
    let l = nn.iter().position(|&c| c == 0).unwrap_or(65);
    if let Some(d) = nn[..l].iter().position(|&c| c == b'.') {
        return Buf::from(&nn[d + 1..l]);
    }
    let mut hd = HostData::new();
    if netdb::lookup_name(&nn[..l], AF_INET, false, &mut hd).is_ok() {
        if let Some(d) = hd.canon.as_bytes().iter().position(|&c| c == b'.') {
            return Buf::from(&hd.canon.as_bytes()[d + 1..]);
        }
    }
    None
}

fn copy_out(dst: &mut [u8], s: &[u8]) -> c_int {
    if s.len() + 1 > dst.len() {
        return EAI_OVERFLOW;
    }
    dst[..s.len()].copy_from_slice(s);
    dst[s.len()] = 0;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnameinfo(sa: *const sockaddr, addrlen: socklen_t, host: *mut c_char, hostlen: socklen_t, serv: *mut c_char, servlen: socklen_t, flags: c_int) -> c_int {
    if flags & !(NI_NUMERICHOST | NI_NUMERICSERV | NI_NOFQDN | NI_NAMEREQD | NI_DGRAM | NI_IDN | 0xc0) != 0 {
        return EAI_BADFLAGS;
    }
    if sa.is_null() || (addrlen as usize) < 2 {
        return EAI_FAMILY;
    }
    if flags & NI_NAMEREQD != 0 && host.is_null() && serv.is_null() {
        return EAI_NONAME;
    }
    let fam = unsafe { Bytes(sa as *const u8, 2).conv() };
    let fam = c_int::from(u16::from_ne_bytes([fam[0], fam[1]]));
    let need = match fam {
        AF_UNIX => 110,
        AF_INET if (addrlen as usize) < 16 => return EAI_FAMILY,
        AF_INET6 if (addrlen as usize) < 28 => return EAI_FAMILY,
        AF_INET => 16,
        AF_INET6 => 28,
        _ => return EAI_FAMILY,
    };
    let (sab, (host, serv)) = unsafe { (Bytes(sa as *const u8, need), (OptBytesMut(host as *mut u8, hostlen as usize), OptBytesMut(serv as *mut u8, servlen as usize))).conv() };
    nameinfo(sab, host, serv, flags)
}

pub fn nameinfo(sa: &[u8], host: Option<&mut [u8]>, serv: Option<&mut [u8]>, flags: c_int) -> c_int {
    if let Some(h) = host {
        let r = gni_host(sa, h, flags);
        if r != 0 {
            return r;
        }
    }
    if let Some(sv) = serv {
        let r = gni_serv(sa, sv, flags);
        if r != 0 {
            return r;
        }
    }
    0
}

fn gni_host(sa: &[u8], host: &mut [u8], flags: c_int) -> c_int {
    let fam = c_int::from(u16::from_ne_bytes([sa[0], sa[1]]));
    if fam == AF_UNIX {
        if flags & NI_NUMERICHOST == 0 {
            let mut un = [0u8; 390];
            if crate::dns::uname(&mut un) {
                let nn = &un[65..130];
                let l = nn.iter().position(|&c| c == 0).unwrap_or(65);
                return copy_out(host, &nn[..l]);
            }
        }
        if flags & NI_NAMEREQD != 0 {
            return EAI_NONAME;
        }
        return copy_out(host, b"localhost");
    }
    let (addr, alen): ([u8; 16], usize) = if fam == AF_INET6 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&sa[8..24]);
        (a, 16)
    } else {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&sa[4..8]);
        (a, 4)
    };
    if flags & NI_NUMERICHOST == 0 {
        let mut res = HOSTENT0;
        let mut buf = [0u8; 2048];
        let mut herr = 0;
        let found = with_growing(&mut buf, |b| {
            let (rc, ok) = netdb::hostbyaddr_r(&addr[..alen], alen as u32, fam, &mut res, b, &mut herr);
            if rc == ERANGE && herr == NETDB_INTERNAL {
                return None;
            }
            if !ok {
                return Some(None);
            }
            let mut nm = unsafe { cbytes(res.h_name) };
            let dom;
            if flags & NI_NOFQDN != 0 {
                dom = domain_name();
                if let Some(d) = &dom {
                    let db = d.as_bytes();
                    if !db.is_empty() {
                        if let Some(pos) = nm.windows(db.len()).position(|w| w == db) {
                            if pos > 0 && nm[pos - 1] == b'.' {
                                nm = &nm[..pos - 1];
                            }
                        }
                    }
                }
            }
            let idn = if flags & NI_IDN != 0 { crate::idna::from_dns(nm) } else { Ok(None) };
            Some(Some(match &idn {
                Ok(Some(u)) => copy_out(host, u.as_bytes()),
                Ok(None) | Err(EAI_IDN_ENCODE) => copy_out(host, nm),
                Err(e) => *e,
            }))
        });
        match found {
            None => return EAI_MEMORY,
            Some(Some(r)) => return r,
            Some(None) => {
                if herr == NETDB_INTERNAL {
                    set_h_errno(herr);
                    return EAI_SYSTEM;
                }
                if herr == TRY_AGAIN {
                    set_h_errno(herr);
                    return EAI_AGAIN;
                }
            }
        }
    }
    if flags & NI_NAMEREQD != 0 {
        return EAI_NONAME;
    }
    let mut t = if fam == AF_INET6 { inet::format_ipv6(&addr) } else { inet::format_ipv4(&[addr[0], addr[1], addr[2], addr[3]]) };
    if fam == AF_INET6 {
        let scope = u32::from_ne_bytes([sa[24], sa[25], sa[26], sa[27]]);
        if scope != 0 {
            t.push(b'%');
            let ll = addr[0] == 0xfe && addr[1] & 0xc0 == 0x80;
            let mc_ll = addr[0] == 0xff && addr[1] & 0xf == 2;
            let mut named = false;
            if ll || mc_ll {
                let mut nb = [0u8; 16];
                if !unsafe { crate::ifaddrs::if_indextoname(scope, nb.as_mut_ptr() as *mut c_char) }.is_null() {
                    let l = nb.iter().position(|&c| c == 0).unwrap_or(16);
                    t.push_all(&nb[..l]);
                    named = true;
                }
            }
            if !named {
                t.push_u32(scope);
            }
        }
    }
    copy_out(host, t.as_bytes())
}

const HOSTENT0: hostent = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };

fn gni_serv(sa: &[u8], serv: &mut [u8], flags: c_int) -> c_int {
    let fam = c_int::from(u16::from_ne_bytes([sa[0], sa[1]]));
    if fam == AF_UNIX {
        let path = &sa[2..110];
        let l = path.iter().position(|&c| c == 0).unwrap_or(108);
        return copy_out(serv, &path[..l]);
    }
    let port = u16::from_ne_bytes([sa[2], sa[3]]);
    if flags & NI_NUMERICSERV == 0 {
        let mut res = SERVENT_ZERO;
        let mut buf = [0u8; 1024];
        let proto = if flags & NI_DGRAM != 0 { c"udp" } else { c"tcp" };
        let r = with_growing(&mut buf, |b| match netdb::servbyport_r(port as c_int, Some(proto), &mut res, b) {
            (ERANGE, _) => None,
            (_, true) => Some(Some(copy_out(serv, unsafe { cbytes(res.s_name) }))),
            _ => Some(None),
        });
        match r {
            None => return EAI_MEMORY,
            Some(Some(r)) => return r,
            Some(None) => {}
        }
    }
    let mut t = Buf::<8>::new();
    t.push_u32(u16::from_be(port) as u32);
    copy_out(serv, t.as_bytes())
}

#[allow(dead_code)]
fn _unused(_: Source, _: Addr) {
    let _ = errno::get();
    label_prec_init();
}
