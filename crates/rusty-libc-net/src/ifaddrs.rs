use crate::types::*;
use crate::util::cstrlen;
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::syscall::{check, syscall3};

const NETLINK_ROUTE: c_int = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_STATS: u16 = 7;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_FLAGS: u16 = 8;
const IFF_POINTOPOINT: u32 = 0x10;
pub const IFA_F_DEPRECATED: u32 = 0x20;
const SIOCGIFINDEX: usize = 0x8933;
const SIOCGIFNAME: usize = 0x8910;
const IFNAMSIZ: usize = 16;
const STATS_SIZE: usize = 92;

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

struct Heap {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl Heap {
    fn new() -> Heap {
        Heap { p: core::ptr::null_mut(), len: 0, cap: 0 }
    }
    fn reserve(&mut self, extra: usize) -> bool {
        if self.len + extra <= self.cap {
            return true;
        }
        let ncap = (self.len + extra).max(self.cap * 2).max(16384);
        let np = unsafe { rusty_libc_malloc::realloc(self.p as *mut c_void, ncap) } as *mut u8;
        if np.is_null() {
            return false;
        }
        self.p = np;
        self.cap = ncap;
        true
    }
    fn bytes(&self) -> &[u8] {
        if self.p.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.p, self.len) } }
    }
}

impl Drop for Heap {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe { rusty_libc_malloc::free(self.p as *mut c_void) };
        }
    }
}

fn netlink_dump(typ: u16) -> Result<Heap, i32> {
    let fd = unsafe { crate::sock::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(errno::get());
    }
    let r = (|| {
        let sa = sockaddr_nl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
        if unsafe { crate::sock::bind(fd, &sa as *const _ as *const sockaddr, 12) } < 0 {
            return Err(errno::get());
        }
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&typ.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        req[16] = AF_UNSPEC as u8;
        req[0..4].copy_from_slice(&17u32.to_ne_bytes());
        let mut dst = sockaddr_nl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
        if unsafe { crate::sock::sendto(fd, req.as_ptr() as *const c_void, 20, 0, &mut dst as *mut _ as *const sockaddr, 12) } < 0 {
            return Err(errno::get());
        }
        let mut heap = Heap::new();
        let mut buf = [0u8; 16384];
        loop {
            let n = unsafe { crate::sock::recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                let e = errno::get();
                if e == EINTR {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            if n == 0 {
                return Err(EINVAL);
            }
            let mut off = 0;
            let mut done = false;
            while off + 16 <= n {
                let len = rd32(&buf, off) as usize;
                let ty = rd16(&buf, off + 4);
                if len < 16 || off + len > n {
                    return Err(EINVAL);
                }
                if ty == NLMSG_DONE {
                    done = true;
                    break;
                }
                if ty == NLMSG_ERROR {
                    return Err(EINVAL);
                }
                if !heap.reserve(len) {
                    return Err(ENOMEM);
                }
                unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr().add(off), heap.p.add(heap.len), len) };
                heap.len += len;
                off += (len + 3) & !3;
            }
            if done {
                return Ok(heap);
            }
        }
    })();
    unsafe { rusty_libc_core::syscall::syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd as usize) };
    r
}

fn messages(d: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut off = 0;
    core::iter::from_fn(move || {
        if off + 16 > d.len() {
            return None;
        }
        let len = rd32(d, off) as usize;
        let ty = rd16(d, off + 4);
        let m = &d[off + 16..off + len];
        off += (len + 3) & !3;
        Some((ty, m))
    })
}

fn attrs(m: &[u8], skip: usize) -> impl Iterator<Item = (u16, &[u8])> {
    let mut off = skip;
    core::iter::from_fn(move || {
        if off + 4 > m.len() {
            return None;
        }
        let len = rd16(m, off) as usize;
        let ty = rd16(m, off + 2) & 0x3fff;
        if len < 4 || off + len > m.len() {
            return None;
        }
        let d = &m[off + 4..off + len];
        off += (len + 3) & !3;
        Some((ty, d))
    })
}

#[derive(Clone, Copy, Debug)]
pub struct LocalAddr {
    pub family: c_int,
    pub addr: [u8; 16],
    pub prefixlen: u8,
    pub index: u32,
    pub flags: u32,
    pub scope: u8,
}

pub fn local_addrs(out: &mut [LocalAddr]) -> Result<usize, i32> {
    let d = netlink_dump(RTM_GETADDR)?;
    let mut n = 0;
    for (ty, m) in messages(d.bytes()) {
        if ty != RTM_NEWADDR || m.len() < 8 {
            continue;
        }
        let fam = m[0] as c_int;
        if fam != AF_INET && fam != AF_INET6 {
            continue;
        }
        let mut la = LocalAddr { family: fam, addr: [0; 16], prefixlen: m[1], index: rd32(m, 4), flags: m[2] as u32, scope: m[3] };
        let want = if fam == AF_INET { 4 } else { 16 };
        let mut got = false;
        for (t, v) in attrs(m, 8) {
            if t == IFA_ADDRESS && v.len() == want && !got {
                la.addr[..want].copy_from_slice(v);
                got = true;
            } else if t == IFA_LOCAL && v.len() == want {
                la.addr[..want].copy_from_slice(v);
                got = true;
            } else if t == IFA_FLAGS && v.len() == 4 {
                la.flags = rd32(v, 0);
            }
        }
        if !got {
            continue;
        }
        if n < out.len() {
            out[n] = la;
        }
        n += 1;
    }
    Ok(n.min(out.len()))
}

pub fn check_pf() -> (bool, bool) {
    let mut v = [LocalAddr { family: 0, addr: [0; 16], prefixlen: 0, index: 0, flags: 0, scope: 0 }; 64];
    let Ok(n) = local_addrs(&mut v) else { return (true, true) };
    let (mut s4, mut s6) = (false, false);
    for a in &v[..n] {
        if a.family == AF_INET {
            if a.addr[..4] != [127, 0, 0, 1] {
                s4 = true;
            }
        } else if a.addr[..15] != [0; 15] || a.addr[15] != 1 {
            s6 = true;
        }
    }
    (s4, s6)
}

fn ifreq_call(req: usize, ifr: &mut [u8; 40]) -> c_int {
    let fd = unsafe { crate::sock::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    let fd = if fd < 0 { unsafe { crate::sock::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0) } } else { fd };
    if fd < 0 {
        return -1;
    }
    let r = unsafe { syscall3(rusty_libc_core::syscall::SYS_IOCTL, fd as usize, req, ifr.as_mut_ptr() as usize) };
    let ok = check(r);
    let saved = match ok {
        Ok(_) => 0,
        Err(e) => e.0,
    };
    unsafe { rusty_libc_core::syscall::syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd as usize) };
    if saved != 0 {
        errno::set(saved);
        -1
    } else {
        0
    }
}

pub fn name_to_index(name: &[u8]) -> Option<u32> {
    if name.len() >= IFNAMSIZ {
        errno::set(ENODEV);
        return None;
    }
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    if ifreq_call(SIOCGIFINDEX, &mut ifr) < 0 {
        return None;
    }
    Some(rd32(&ifr, 16))
}

pub fn scope_id_from_text(s: &[u8]) -> Option<u32> {
    if let Some(i) = name_to_index(s) {
        return Some(i);
    }
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
        if v > u32::MAX as u64 {
            return None;
        }
    }
    Some(v as u32)
}

pub fn scopeid_pton(addr: &[u8; 16], s: &[u8]) -> Option<u32> {
    let ll = addr[0] == 0xfe && addr[1] & 0xc0 == 0x80;
    let mc_ll = addr[0] == 0xff && addr[1] & 0xf == 2;
    if ll || mc_ll {
        if let Some(i) = name_to_index(s) {
            return Some(i);
        }
    }
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
        if v > u32::MAX as u64 {
            return None;
        }
    }
    Some(v as u32)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn if_nametoindex(name: *const c_char) -> c_uint {
    let s = unsafe { core::slice::from_raw_parts(name as *const u8, cstrlen(name)) };
    name_to_index(s).unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn if_indextoname(index: c_uint, buf: *mut c_char) -> *mut c_char {
    let mut ifr = [0u8; 40];
    ifr[16..20].copy_from_slice(&index.to_ne_bytes());
    if ifreq_call(SIOCGIFNAME, &mut ifr) < 0 {
        if errno::get() == ENODEV {
            errno::set(ENXIO);
        }
        return core::ptr::null_mut();
    }
    unsafe {
        core::ptr::copy_nonoverlapping(ifr.as_ptr(), buf as *mut u8, IFNAMSIZ);
        *buf.add(IFNAMSIZ - 1) = 0;
    }
    buf
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn if_nameindex() -> *mut if_nameindex {
    let d = match netlink_dump(RTM_GETLINK) {
        Ok(d) => d,
        Err(e) => {
            errno::set(if e == ENOMEM { ENOMEM } else { e });
            return core::ptr::null_mut();
        }
    };
    let mut n = 0usize;
    for (ty, m) in messages(d.bytes()) {
        if ty == RTM_NEWLINK && m.len() >= 16 {
            n += 1;
        }
    }
    let esz = core::mem::size_of::<if_nameindex>();
    let total = (n + 1) * esz + n * IFNAMSIZ;
    let blk = unsafe { rusty_libc_malloc::malloc(total) } as *mut u8;
    if blk.is_null() {
        errno::set(ENOMEM);
        return core::ptr::null_mut();
    }
    let arr = blk as *mut if_nameindex;
    let mut names = unsafe { blk.add((n + 1) * esz) };
    let mut i = 0usize;
    for (ty, m) in messages(d.bytes()) {
        if ty != RTM_NEWLINK || m.len() < 16 {
            continue;
        }
        let idx = rd32(m, 4);
        unsafe {
            (*arr.add(i)).if_index = idx;
            (*arr.add(i)).if_name = names as *mut c_char;
            core::ptr::write_bytes(names, 0, IFNAMSIZ);
        }
        for (t, v) in attrs(m, 16) {
            if t == IFLA_IFNAME {
                let l = v.iter().position(|&c| c == 0).unwrap_or(v.len()).min(IFNAMSIZ - 1);
                unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), names, l) };
            }
        }
        names = unsafe { names.add(IFNAMSIZ) };
        i += 1;
    }
    unsafe {
        (*arr.add(i)).if_index = 0;
        (*arr.add(i)).if_name = core::ptr::null_mut();
    }
    arr
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn if_freenameindex(p: *mut if_nameindex) {
    if !p.is_null() {
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
    }
}

const SLOT: usize = 256;


#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int {
    let links = match netlink_dump(RTM_GETLINK) {
        Ok(d) => d,
        Err(e) => {
            errno::set(e);
            return -1;
        }
    };
    let addrs = match netlink_dump(RTM_GETADDR) {
        Ok(d) => d,
        Err(e) => {
            errno::set(e);
            return -1;
        }
    };
    let mut count = 0usize;
    for (ty, m) in messages(links.bytes()) {
        if ty == RTM_NEWLINK && m.len() >= 16 {
            count += 1;
        }
    }
    for (ty, m) in messages(addrs.bytes()) {
        if ty == RTM_NEWADDR && m.len() >= 8 && (m[0] as c_int == AF_INET || m[0] as c_int == AF_INET6) {
            count += 1;
        }
    }
    if count == 0 {
        unsafe { *ifap = core::ptr::null_mut() };
        return 0;
    }
    let blk = unsafe { rusty_libc_malloc::calloc(count, SLOT) } as *mut u8;
    if blk.is_null() {
        errno::set(ENOMEM);
        return -1;
    }
    let mut slot = 0usize;
    let mut prev: *mut ifaddrs = core::ptr::null_mut();
    let mut first: *mut ifaddrs = core::ptr::null_mut();
    let setup = |slot: usize| -> (*mut ifaddrs, *mut u8, *mut u8, *mut u8, *mut u8, *mut u8) {
        let base = unsafe { blk.add(slot * SLOT) };
        let ia = base as *mut ifaddrs;
        let name = unsafe { base.add(56) };
        let a = unsafe { base.add(72) };
        let mk = unsafe { base.add(100) };
        let bc = unsafe { base.add(128) };
        let data = unsafe { base.add(156) };
        (ia, name, a, mk, bc, data)
    };
    let link_tab = |idx: u32| -> Option<([u8; IFNAMSIZ], u32)> {
        for (ty, m) in messages(links.bytes()) {
            if ty == RTM_NEWLINK && m.len() >= 16 && rd32(m, 4) == idx {
                let mut name = [0u8; IFNAMSIZ];
                for (t, v) in attrs(m, 16) {
                    if t == IFLA_IFNAME {
                        let l = v.iter().position(|&c| c == 0).unwrap_or(v.len()).min(IFNAMSIZ - 1);
                        name[..l].copy_from_slice(&v[..l]);
                    }
                }
                return Some((name, rd32(m, 8)));
            }
        }
        None
    };
    let mut link = |ia: *mut ifaddrs| {
        if prev.is_null() {
            first = ia;
        } else {
            unsafe { (*prev).ifa_next = ia };
        }
        prev = ia;
    };
    for (ty, m) in messages(links.bytes()) {
        if ty != RTM_NEWLINK || m.len() < 16 {
            continue;
        }
        let (ia, name, a, _mk, bc, data) = setup(slot);
        slot += 1;
        let hatype = rd16(m, 2);
        let index = rd32(m, 4);
        let flags = rd32(m, 8);
        unsafe {
            (*ia).ifa_name = name as *mut c_char;
            (*ia).ifa_flags = flags;
        }
        for (t, v) in attrs(m, 16) {
            match t {
                IFLA_IFNAME => {
                    let l = v.iter().position(|&c| c == 0).unwrap_or(v.len()).min(IFNAMSIZ - 1);
                    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), name, l) };
                }
                IFLA_ADDRESS => unsafe {
                    let l = v.len().min(8);
                    *(a as *mut sockaddr_ll) = sockaddr_ll { sll_family: AF_PACKET as u16, sll_protocol: 0, sll_ifindex: index as c_int, sll_hatype: hatype, sll_pkttype: 0, sll_halen: 0, sll_addr: [0; 8] };
                    (*ia).ifa_addr = a as *mut sockaddr;
                    (*(a as *mut sockaddr_ll)).sll_halen = l as u8;
                    core::ptr::copy_nonoverlapping(v.as_ptr(), (&raw mut (*(a as *mut sockaddr_ll)).sll_addr) as *mut u8, l);
                },
                IFLA_BROADCAST => unsafe {
                    let l = v.len().min(8);
                    let b = bc as *mut sockaddr_ll;
                    *b = sockaddr_ll { sll_family: AF_PACKET as u16, sll_protocol: 0, sll_ifindex: index as c_int, sll_hatype: hatype, sll_pkttype: 0, sll_halen: l as u8, sll_addr: [0; 8] };
                    core::ptr::copy_nonoverlapping(v.as_ptr(), (&raw mut (*b).sll_addr) as *mut u8, l);
                    if flags & IFF_POINTOPOINT != 0 {
                        (*ia).ifa_ifu.ifu_dstaddr = b as *mut sockaddr;
                    } else {
                        (*ia).ifa_ifu.ifu_broadaddr = b as *mut sockaddr;
                    }
                },
                IFLA_STATS if v.len() >= STATS_SIZE => unsafe {
                    core::ptr::copy_nonoverlapping(v.as_ptr(), data, STATS_SIZE);
                    (*ia).ifa_data = data as *mut c_void;
                },
                _ => {}
            }
        }
        link(ia);
    }
    for (ty, m) in messages(addrs.bytes()) {
        if ty != RTM_NEWADDR || m.len() < 8 {
            continue;
        }
        let fam = m[0] as c_int;
        if fam != AF_INET && fam != AF_INET6 {
            continue;
        }
        let (ia, name, a, mk, bc, _data) = setup(slot);
        slot += 1;
        let prefix = m[1] as usize;
        let index = rd32(m, 4);
        let (lname, lflags) = link_tab(index).unwrap_or(([0; IFNAMSIZ], 0));
        unsafe {
            core::ptr::copy_nonoverlapping(lname.as_ptr(), name, IFNAMSIZ);
            (*ia).ifa_name = name as *mut c_char;
            (*ia).ifa_flags = lflags;
        }
        let want = if fam == AF_INET { 4 } else { 16 };
        let mut addr: Option<[u8; 16]> = None;
        let mut dst: Option<[u8; 16]> = None;
        let pad = |v: &[u8]| -> [u8; 16] {
            let mut x = [0u8; 16];
            if v.len() == want {
                x[..want].copy_from_slice(v);
            }
            x
        };
        for (t, v) in attrs(m, 8) {
            match t {
                IFA_ADDRESS => {
                    if addr.is_some() {
                        dst = Some(pad(v));
                    } else {
                        addr = Some(pad(v));
                    }
                }
                IFA_LOCAL => {
                    if addr.is_some() {
                        dst = addr;
                    }
                    addr = Some(pad(v));
                }
                IFA_BROADCAST => dst = Some(pad(v)),
                IFA_LABEL => unsafe {
                    let l = v.iter().position(|&c| c == 0).unwrap_or(v.len()).min(IFNAMSIZ - 1);
                    core::ptr::write_bytes(name, 0, IFNAMSIZ);
                    core::ptr::copy_nonoverlapping(v.as_ptr(), name, l);
                },
                _ => {}
            }
        }
        let scope_for = |b: &[u8; 16]| -> u32 {
            if fam == AF_INET6 && ((b[0] == 0xfe && b[1] & 0xc0 == 0x80) || (b[0] == 0xff && b[1] & 0xf == 2)) { index } else { 0 }
        };
        let fill = |p: *mut u8, b: &[u8; 16]| unsafe {
            if fam == AF_INET {
                let s = p as *mut sockaddr_in;
                *s = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) }, sin_zero: [0; 8] };
            } else {
                let s = p as *mut sockaddr_in6;
                *s = sockaddr_in6 { sin6_family: AF_INET6 as u16, sin6_port: 0, sin6_flowinfo: 0, sin6_addr: in6_addr { s6_addr: *b }, sin6_scope_id: scope_for(b) };
            }
        };
        unsafe {
            if let Some(ad) = addr {
                fill(a, &ad);
                (*ia).ifa_addr = a as *mut sockaddr;
                let mut mask = [0u8; 16];
                for i in 0..prefix.min(want * 8) {
                    mask[i / 8] |= 0x80 >> (i % 8);
                }
                if fam == AF_INET {
                    fill(mk, &mask);
                } else {
                    let s = mk as *mut sockaddr_in6;
                    *s = sockaddr_in6 { sin6_family: AF_INET6 as u16, sin6_port: 0, sin6_flowinfo: 0, sin6_addr: in6_addr { s6_addr: mask }, sin6_scope_id: 0 };
                }
                (*ia).ifa_netmask = mk as *mut sockaddr;
            }
            if let Some(d) = dst {
                fill(bc, &d);
                (*ia).ifa_ifu.ifu_broadaddr = bc as *mut sockaddr;
            }
        }
        link(ia);
    }
    unsafe { *ifap = first };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freeifaddrs(ifa: *mut ifaddrs) {
    if !ifa.is_null() {
        unsafe { rusty_libc_malloc::free(ifa as *mut c_void) };
    }
}
