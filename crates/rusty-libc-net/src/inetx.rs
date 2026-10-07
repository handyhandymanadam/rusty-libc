use crate::types::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::errno;

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
unsafe fn cmsg_data(c: *const cmsghdr) -> *mut u8 {
    unsafe { (c as *mut u8).add(CMSG_HDR) }
}

unsafe fn add_pad(cmsg: *mut cmsghdr, len: usize) {
    unsafe {
        let mut p = cmsg_data(cmsg).add((*cmsg).cmsg_len - CMSG_HDR);
        if len == 1 {
            *p = IP6OPT_PAD1;
        } else if len != 0 {
            *p = IP6OPT_PADN;
            p = p.add(1);
            *p = (len - 2) as u8;
            p = p.add(1);
            core::ptr::write_bytes(p, 0, len - 2);
        }
        (*cmsg).cmsg_len += len;
    }
}

unsafe fn get_opt_end(start: *const u8, end: *const u8) -> Option<*const u8> {
    unsafe {
        if start >= end {
            return None;
        }
        if *start == IP6OPT_PAD1 {
            return Some(start.add(1));
        }
        if start.add(2) > end || start.add(*start.add(1) as usize + 2) > end {
            return None;
        }
        Some(start.add(*start.add(1) as usize + 2))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet6_option_space(nbytes: c_int) -> c_int {
    let n = nbytes.wrapping_add(2);
    let rounded = n.wrapping_add(7) & !7;
    (CMSG_HDR as c_int).wrapping_add(rounded.wrapping_add(7) & !7)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_init(bp: *mut c_void, cmsgp: *mut *mut cmsghdr, ty: c_int) -> c_int {
    unsafe {
        if ty != IPV6_HOPOPTS && ty != IPV6_DSTOPTS {
            return -1;
        }
        let newp = bp as *mut cmsghdr;
        (*newp).cmsg_len = cmsg_len(0);
        (*newp).cmsg_level = IPPROTO_IPV6;
        (*newp).cmsg_type = ty;
        *cmsgp = newp;
        0
    }
}

unsafe fn option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    unsafe {
        if !matches!(multx, 1 | 2 | 4 | 8) || !(0..=7).contains(&plusy) {
            return core::ptr::null_mut();
        }
        let mut dsize = ((*cmsg).cmsg_len - CMSG_HDR) as c_int;
        if dsize == 0 {
            (*cmsg).cmsg_len += 2;
            dsize = 2;
        }
        add_pad(cmsg, (((multx - (dsize & (multx - 1))) & (multx - 1)) + plusy) as usize);
        let result = cmsg_data(cmsg).add((*cmsg).cmsg_len - CMSG_HDR);
        (*cmsg).cmsg_len = (*cmsg).cmsg_len.wrapping_add(datalen as usize);
        dsize = ((*cmsg).cmsg_len - CMSG_HDR) as c_int;
        add_pad(cmsg, ((8 - (dsize & 7)) & 7) as usize);
        let len8b = ((*cmsg).cmsg_len - CMSG_HDR) / 8 - 1;
        if len8b >= 256 {
            return core::ptr::null_mut();
        }
        *cmsg_data(cmsg).add(1) = len8b as u8;
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_append(cmsg: *mut cmsghdr, typep: *const u8, multx: c_int, plusy: c_int) -> c_int {
    unsafe {
        let len = if *typep == IP6OPT_PAD1 { 1 } else { *typep.add(1) as c_int + 2 };
        let ptr = option_alloc(cmsg, len, multx, plusy);
        if ptr.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping(typep, ptr, len as usize);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    unsafe { option_alloc(cmsg, datalen, multx, plusy) }
}

unsafe fn option_bounds(cmsg: *const cmsghdr) -> Option<*const u8> {
    unsafe {
        if (*cmsg).cmsg_level != IPPROTO_IPV6 || ((*cmsg).cmsg_type != IPV6_HOPOPTS && (*cmsg).cmsg_type != IPV6_DSTOPTS) {
            return None;
        }
        let ext = cmsg_data(cmsg);
        if (*cmsg).cmsg_len < cmsg_len(2) || (*cmsg).cmsg_len < cmsg_len((*ext.add(1) as usize + 1) * 8) {
            return None;
        }
        Some(ext.add((*ext.add(1) as usize + 1) * 8))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_next(cmsg: *const cmsghdr, tptrp: *mut *mut u8) -> c_int {
    unsafe {
        let Some(endp) = option_bounds(cmsg) else { return -1 };
        let first = cmsg_data(cmsg).add(2) as *const u8;
        let result: *const u8 = if (*tptrp).is_null() {
            first
        } else {
            if (*tptrp as *const u8) < first {
                return -1;
            }
            match get_opt_end(*tptrp, endp) {
                Some(r) => r,
                None => return -1,
            }
        };
        *tptrp = result as *mut u8;
        if get_opt_end(result, endp).is_some() { 0 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_find(cmsg: *const cmsghdr, tptrp: *mut *mut u8, ty: c_int) -> c_int {
    unsafe {
        let Some(endp) = option_bounds(cmsg) else { return -1 };
        let first = cmsg_data(cmsg).add(2) as *const u8;
        let mut next: *const u8 = if (*tptrp).is_null() {
            first
        } else {
            if (*tptrp as *const u8) < first {
                return -1;
            }
            match get_opt_end(*tptrp, endp) {
                Some(r) => r,
                None => return -1,
            }
        };
        let mut result;
        loop {
            result = next;
            match get_opt_end(result, endp) {
                Some(n) => next = n,
                None => return -1,
            }
            if c_int::from(*result) == ty {
                break;
            }
        }
        *tptrp = result as *mut u8;
        0
    }
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

unsafe fn scratch(n: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::calloc(1, n.max(1)) as *mut u8 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: *mut u32, numsrc: *mut u32, slist: *mut sockaddr_storage) -> c_int {
    unsafe {
        let mut needed = (GF_HEADER as u64 + u64::from(*numsrc) * SS as u64) as socklen_t;
        let gf = scratch(needed as usize);
        if gf.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping(&interface as *const u32 as *const u8, gf, 4);
        core::ptr::copy_nonoverlapping(group as *const u8, gf.add(8), (grouplen as usize).min(SS));
        core::ptr::copy_nonoverlapping(numsrc as *const u8, gf.add(140), 4);
        let sol = get_sol((*group).sa_family as c_int, grouplen);
        let result;
        if sol == -1 {
            errno::set(22);
            result = -1;
        } else {
            result = crate::sock::getsockopt(s, sol, MCAST_MSFILTER, gf.cast(), &mut needed);
            if result == 0 {
                let fm = *(gf.add(136) as *const u32);
                let ns = *(gf.add(140) as *const u32);
                *fmode = fm;
                core::ptr::copy_nonoverlapping(gf.add(GF_HEADER), slist as *mut u8, (*numsrc).min(ns) as usize * SS);
                *numsrc = ns;
            }
        }
        rusty_libc_malloc::free(gf.cast());
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: u32, numsrc: u32, slist: *const sockaddr_storage) -> c_int {
    unsafe {
        let needed = (GF_HEADER as u64 + u64::from(numsrc) * SS as u64) as usize;
        let gf = scratch(needed);
        if gf.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping(&interface as *const u32 as *const u8, gf, 4);
        core::ptr::copy_nonoverlapping(group as *const u8, gf.add(8), (grouplen as usize).min(SS));
        core::ptr::copy_nonoverlapping(&fmode as *const u32 as *const u8, gf.add(136), 4);
        core::ptr::copy_nonoverlapping(&numsrc as *const u32 as *const u8, gf.add(140), 4);
        core::ptr::copy_nonoverlapping(slist as *const u8, gf.add(GF_HEADER), numsrc as usize * SS);
        let sol = get_sol((*group).sa_family as c_int, grouplen);
        let result;
        if sol == -1 {
            errno::set(22);
            result = -1;
        } else {
            result = crate::sock::setsockopt(s, sol, MCAST_MSFILTER, gf.cast(), needed as socklen_t);
        }
        rusty_libc_malloc::free(gf.cast());
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getipv4sourcefilter(s: c_int, interface: in_addr, group: in_addr, fmode: *mut u32, numsrc: *mut u32, slist: *mut in_addr) -> c_int {
    unsafe {
        let mut needed = (IMSF_HEADER as u64 + u64::from(*numsrc) * 4) as socklen_t;
        let imsf = scratch(needed as usize);
        if imsf.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping(&group as *const in_addr as *const u8, imsf, 4);
        core::ptr::copy_nonoverlapping(&interface as *const in_addr as *const u8, imsf.add(4), 4);
        core::ptr::copy_nonoverlapping(numsrc as *const u8, imsf.add(12), 4);
        let result = crate::sock::getsockopt(s, 0, IP_MSFILTER, imsf.cast(), &mut needed);
        if result == 0 {
            let fm = *(imsf.add(8) as *const u32);
            let ns = *(imsf.add(12) as *const u32);
            *fmode = fm;
            core::ptr::copy_nonoverlapping(imsf.add(IMSF_HEADER), slist as *mut u8, (*numsrc).min(ns) as usize * 4);
            *numsrc = ns;
        }
        rusty_libc_malloc::free(imsf.cast());
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setipv4sourcefilter(s: c_int, interface: in_addr, group: in_addr, fmode: u32, numsrc: u32, slist: *const in_addr) -> c_int {
    unsafe {
        let needed = (IMSF_HEADER as u64 + u64::from(numsrc) * 4) as usize;
        let imsf = scratch(needed);
        if imsf.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping(&group as *const in_addr as *const u8, imsf, 4);
        core::ptr::copy_nonoverlapping(&interface as *const in_addr as *const u8, imsf.add(4), 4);
        core::ptr::copy_nonoverlapping(&fmode as *const u32 as *const u8, imsf.add(8), 4);
        core::ptr::copy_nonoverlapping(&numsrc as *const u32 as *const u8, imsf.add(12), 4);
        core::ptr::copy_nonoverlapping(slist as *const u8, imsf.add(IMSF_HEADER), numsrc as usize * 4);
        let result = crate::sock::setsockopt(s, 0, IP_MSFILTER, imsf.cast(), needed as socklen_t);
        rusty_libc_malloc::free(imsf.cast());
        result
    }
}
