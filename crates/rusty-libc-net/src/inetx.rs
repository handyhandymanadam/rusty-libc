#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, ffi};

const IP6OPT_PAD1: u8 = 0;
const IP6OPT_PADN: u8 = 1;
const IPV6_HOPOPTS: c_int = 54;
const IPV6_DSTOPTS: c_int = 59;
const CMSG_HDR: usize = 16;

#[inline]
fn cmsg_len(n: usize) -> usize {
    CMSG_HDR + n
}

#[inline]
fn data_ptr(c: *const cmsghdr, off: usize) -> *mut u8 {
    c.cast::<u8>().cast_mut().wrapping_add(CMSG_HDR).wrapping_add(off)
}

fn pad_bytes(p: &mut [u8]) {
    match p.len() {
        0 => {}
        1 => p[0] = IP6OPT_PAD1,
        n => {
            p[0] = IP6OPT_PADN;
            p[1] = (n - 2) as u8;
            p[2..].fill(0);
        }
    }
}

unsafe fn pad_at(cmsg: *mut cmsghdr, off: usize, len: usize) {
    pad_bytes(unsafe { ffi::bytes_mut(data_ptr(cmsg, off), len) });
}

fn opt_end(b: &[u8], start: usize) -> Option<usize> {
    if start >= b.len() {
        return None;
    }
    if b[start] == IP6OPT_PAD1 {
        return Some(start + 1);
    }
    if start + 2 > b.len() || start + b[start + 1] as usize + 2 > b.len() {
        return None;
    }
    Some(start + b[start + 1] as usize + 2)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet6_option_space(nbytes: c_int) -> c_int {
    let n = nbytes.wrapping_add(2);
    let rounded = n.wrapping_add(7) & !7;
    (CMSG_HDR as c_int).wrapping_add(rounded.wrapping_add(7) & !7)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_init(bp: *mut c_void, cmsgp: *mut *mut cmsghdr, ty: c_int) -> c_int {
    if ty != IPV6_HOPOPTS && ty != IPV6_DSTOPTS {
        return -1;
    }
    let newp = bp as *mut cmsghdr;
    unsafe { newp.write(cmsghdr { cmsg_len: cmsg_len(0), cmsg_level: IPPROTO_IPV6, cmsg_type: ty }) };
    unsafe { cmsgp.write(newp) };
    0
}

unsafe fn option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    if !matches!(multx, 1 | 2 | 4 | 8) || !(0..=7).contains(&plusy) {
        return core::ptr::null_mut();
    }
    let mut len = unsafe { (*cmsg).cmsg_len };
    let mut dsize = (len - CMSG_HDR) as c_int;
    if dsize == 0 {
        len += 2;
        dsize = 2;
    }
    let pad = (((multx - (dsize & (multx - 1))) & (multx - 1)) + plusy) as usize;
    unsafe { pad_at(cmsg, len - CMSG_HDR, pad) };
    len += pad;
    let result = data_ptr(cmsg, len - CMSG_HDR);
    len = len.wrapping_add(datalen as usize);
    dsize = (len - CMSG_HDR) as c_int;
    let pad = ((8 - (dsize & 7)) & 7) as usize;
    unsafe { pad_at(cmsg, len - CMSG_HDR, pad) };
    len += pad;
    unsafe { (*cmsg).cmsg_len = len };
    let len8b = (len - CMSG_HDR) / 8 - 1;
    if len8b >= 256 {
        return core::ptr::null_mut();
    }
    unsafe { data_ptr(cmsg, 1).write(len8b as u8) };
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_append(cmsg: *mut cmsghdr, typep: *const u8, multx: c_int, plusy: c_int) -> c_int {
    let len = if unsafe { *typep } == IP6OPT_PAD1 {
        1
    } else {
        unsafe { *typep.wrapping_add(1) as c_int + 2 }
    };
    let ptr = unsafe { option_alloc(cmsg, len, multx, plusy) };
    if ptr.is_null() {
        return -1;
    }
    let src = unsafe { ffi::bytes(typep, len as usize) };
    unsafe { ffi::bytes_mut(ptr, len as usize) }.copy_from_slice(src);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    unsafe { option_alloc(cmsg, datalen, multx, plusy) }
}

unsafe fn option_bounds<'a>(cmsg: *const cmsghdr) -> Option<&'a [u8]> {
    let c = unsafe { &*cmsg };
    if c.cmsg_level != IPPROTO_IPV6 || (c.cmsg_type != IPV6_HOPOPTS && c.cmsg_type != IPV6_DSTOPTS) {
        return None;
    }
    if c.cmsg_len < cmsg_len(2) {
        return None;
    }
    let data = unsafe { ffi::bytes(data_ptr(cmsg, 0), c.cmsg_len - CMSG_HDR) };
    let n = (data[1] as usize + 1) * 8;
    if c.cmsg_len < cmsg_len(n) {
        return None;
    }
    Some(&data[..n])
}

fn option_start(ext: &[u8], tptr: *const u8) -> Option<usize> {
    let first = ext.as_ptr() as usize + 2;
    if tptr.is_null() {
        return Some(2);
    }
    if (tptr as usize) < first {
        return None;
    }
    opt_end(ext, tptr as usize - ext.as_ptr() as usize)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_next(cmsg: *const cmsghdr, tptrp: *mut *mut u8) -> c_int {
    let Some(ext) = (unsafe { option_bounds(cmsg) }) else { return -1 };
    let tptr = unsafe { &mut *tptrp };
    let Some(result) = option_start(ext, *tptr) else { return -1 };
    *tptr = data_ptr(cmsg, result);
    if opt_end(ext, result).is_some() { 0 } else { -1 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_find(cmsg: *const cmsghdr, tptrp: *mut *mut u8, ty: c_int) -> c_int {
    let Some(ext) = (unsafe { option_bounds(cmsg) }) else { return -1 };
    let tptr = unsafe { &mut *tptrp };
    let Some(mut next) = option_start(ext, *tptr) else { return -1 };
    let mut result;
    loop {
        result = next;
        match opt_end(ext, result) {
            Some(n) => next = n,
            None => return -1,
        }
        if c_int::from(ext[result]) == ty {
            break;
        }
    }
    *tptr = data_ptr(cmsg, result);
    0
}

fn get_sol(af: c_int, len: socklen_t) -> c_int {
    const MAP: [(c_int, c_int, socklen_t); 7] = [(0, 2, 16), (41, 10, 28), (257, 3, 16), (256, 4, 16), (258, 5, 16), (260, 11, 28), (263, 17, 20)];
    let mut first_size = -1;
    for (sol, fam, size) in MAP {
        if len == size {
            if af == fam {
                return sol;
            }
            if first_size == -1 {
                first_size = sol;
            }
        }
    }
    first_size
}

const MCAST_MSFILTER: c_int = 48;
const IP_MSFILTER: c_int = 41;
const GF_HEADER: usize = 144;
const SS: usize = 128;
const IMSF_HEADER: usize = 16;

struct Scratch(*mut u8, usize);

impl Scratch {
    fn new(n: usize) -> Option<Scratch> {
        let p = unsafe { rusty_libc_malloc::calloc(1, n.max(1)) } as *mut u8;
        if p.is_null() { None } else { Some(Scratch(p, n)) }
    }
    fn bytes(&mut self) -> &mut [u8] {
        unsafe { ffi::bytes_mut(self.0, self.1) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

unsafe fn filter_outs<'a>(fmode: *mut u32, numsrc: *mut u32) -> (&'a mut u32, &'a mut u32) {
    let f = unsafe { &mut *fmode };
    let n = unsafe { &mut *numsrc };
    (f, n)
}

unsafe fn group_addr<'a>(group: *const sockaddr, grouplen: socklen_t) -> (c_int, &'a [u8]) {
    let gl = (grouplen as usize).min(SS);
    let b = unsafe { ffi::bytes(group.cast::<u8>(), gl.max(2)) };
    (u16::from_ne_bytes([b[0], b[1]]) as c_int, &b[..gl])
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: *mut u32, numsrc: *mut u32, slist: *mut sockaddr_storage) -> c_int {
    let (fmode, numsrc) = unsafe { filter_outs(fmode, numsrc) };
    let want = *numsrc;
    let mut needed = (GF_HEADER as u64 + u64::from(want) * SS as u64) as socklen_t;
    let Some(mut gf) = Scratch::new(needed as usize) else { return -1 };
    let g = gf.bytes();
    g[..4].copy_from_slice(&interface.to_ne_bytes());
    let (family, ga) = unsafe { group_addr(group, grouplen) };
    g[8..8 + ga.len()].copy_from_slice(ga);
    g[140..144].copy_from_slice(&want.to_ne_bytes());
    let sol = get_sol(family, grouplen);
    if sol == -1 {
        errno::set(22);
        return -1;
    }
    let result = unsafe { crate::sock::getsockopt(s, sol, MCAST_MSFILTER, g.as_mut_ptr().cast(), &mut needed) };
    if result == 0 {
        let ns = u32::from_ne_bytes(g[140..144].try_into().unwrap());
        *fmode = u32::from_ne_bytes(g[136..140].try_into().unwrap());
        let n = want.min(ns) as usize * SS;
        unsafe { ffi::bytes_mut(slist.cast::<u8>(), n) }.copy_from_slice(&g[GF_HEADER..GF_HEADER + n]);
        *numsrc = ns;
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: u32, numsrc: u32, slist: *const sockaddr_storage) -> c_int {
    let needed = (GF_HEADER as u64 + u64::from(numsrc) * SS as u64) as usize;
    let Some(mut gf) = Scratch::new(needed) else { return -1 };
    let g = gf.bytes();
    g[..4].copy_from_slice(&interface.to_ne_bytes());
    let (family, ga) = unsafe { group_addr(group, grouplen) };
    g[8..8 + ga.len()].copy_from_slice(ga);
    g[136..140].copy_from_slice(&fmode.to_ne_bytes());
    g[140..144].copy_from_slice(&numsrc.to_ne_bytes());
    let n = numsrc as usize * SS;
    g[GF_HEADER..GF_HEADER + n].copy_from_slice(unsafe { ffi::bytes(slist.cast::<u8>(), n) });
    let sol = get_sol(family, grouplen);
    if sol == -1 {
        errno::set(22);
        return -1;
    }
    unsafe { crate::sock::setsockopt(s, sol, MCAST_MSFILTER, g.as_ptr().cast(), needed as socklen_t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getipv4sourcefilter(s: c_int, interface: in_addr, group: in_addr, fmode: *mut u32, numsrc: *mut u32, slist: *mut in_addr) -> c_int {
    let (fmode, numsrc) = unsafe { filter_outs(fmode, numsrc) };
    let want = *numsrc;
    let mut needed = (IMSF_HEADER as u64 + u64::from(want) * 4) as socklen_t;
    let Some(mut imsf) = Scratch::new(needed as usize) else { return -1 };
    let m = imsf.bytes();
    m[..4].copy_from_slice(&group.s_addr.to_ne_bytes());
    m[4..8].copy_from_slice(&interface.s_addr.to_ne_bytes());
    m[12..16].copy_from_slice(&want.to_ne_bytes());
    let result = unsafe { crate::sock::getsockopt(s, 0, IP_MSFILTER, m.as_mut_ptr().cast(), &mut needed) };
    if result == 0 {
        let ns = u32::from_ne_bytes(m[12..16].try_into().unwrap());
        *fmode = u32::from_ne_bytes(m[8..12].try_into().unwrap());
        let n = want.min(ns) as usize * 4;
        unsafe { ffi::bytes_mut(slist.cast::<u8>(), n) }.copy_from_slice(&m[IMSF_HEADER..IMSF_HEADER + n]);
        *numsrc = ns;
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setipv4sourcefilter(s: c_int, interface: in_addr, group: in_addr, fmode: u32, numsrc: u32, slist: *const in_addr) -> c_int {
    let needed = (IMSF_HEADER as u64 + u64::from(numsrc) * 4) as usize;
    let Some(mut imsf) = Scratch::new(needed) else { return -1 };
    let m = imsf.bytes();
    m[..4].copy_from_slice(&group.s_addr.to_ne_bytes());
    m[4..8].copy_from_slice(&interface.s_addr.to_ne_bytes());
    m[8..12].copy_from_slice(&fmode.to_ne_bytes());
    m[12..16].copy_from_slice(&numsrc.to_ne_bytes());
    let n = numsrc as usize * 4;
    m[IMSF_HEADER..IMSF_HEADER + n].copy_from_slice(unsafe { ffi::bytes(slist.cast::<u8>(), n) });
    unsafe { crate::sock::setsockopt(s, 0, IP_MSFILTER, m.as_ptr().cast(), needed as socklen_t) }
}
