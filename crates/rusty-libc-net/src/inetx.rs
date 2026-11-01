//! netinet/in.h extras: the obsolete RFC 2292 hop-by-hop and destination option functions (`inet6_option_*`:
//! options kept in ancillary data objects) and the multicast source filter functions (`getsourcefilter`,
//! `setsourcefilter`, `getipv4sourcefilter`, `setipv4sourcefilter`). The structure follows glibc 2.43
//! inet/inet6_option.c and inet/getsourcefilter.c with its neighbours (read as reference; written in Rust).
//! glibc marks the option functions deprecated with a link-time warning, which a static library cannot do.
//!
//! The RFC 2292 objects have no length argument (the caller promises room), so the shells reach their data bytes by address
//! one small unsafe step at a time; the option walks run on a slice of the extension header the object says it holds.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, ffi};

const IP6OPT_PAD1: u8 = 0;
const IP6OPT_PADN: u8 = 1;
const IPV6_HOPOPTS: c_int = 54;
const IPV6_DSTOPTS: c_int = 59;
const CMSG_HDR: usize = 16; // CMSG_LEN (0): sizeof (struct cmsghdr)

#[inline]
fn cmsg_len(n: usize) -> usize {
    CMSG_HDR + n
}

/// The address of data byte `off` of the ancillary data object `c` (address arithmetic only).
#[inline]
fn data_ptr(c: *const cmsghdr, off: usize) -> *mut u8 {
    c.cast::<u8>().cast_mut().wrapping_add(CMSG_HDR).wrapping_add(off)
}

/// Padding of `p.len()` bytes: nothing, a Pad1 option, or a PadN option of zeros.
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

/// Write `len` bytes of padding at data offset `off` of `cmsg`.
///
/// # Safety
/// The object's buffer has room for `len` bytes there (the contract of the `inet6_option_*` callers).
unsafe fn pad_at(cmsg: *mut cmsghdr, off: usize, len: usize) {
    // SAFETY: the caller's contract; the bytes lie after the header, which nothing borrows meanwhile.
    pad_bytes(unsafe { ffi::bytes_mut(data_ptr(cmsg, off), len) });
}

/// The end of the option starting at `start` in the options `b`; None when it does not fit.
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

/// `inet6_option_space (nbytes)`: the bytes an option of `nbytes` takes as ancillary data (header and padding
/// to a multiple of 8 included).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet6_option_space(nbytes: c_int) -> c_int {
    let n = nbytes.wrapping_add(2); // the extension header
    // CMSG_SPACE (roundup (n, 8)): the header and the data aligned to 8
    let rounded = n.wrapping_add(7) & !7;
    (CMSG_HDR as c_int).wrapping_add(rounded.wrapping_add(7) & !7)
}

/// `inet6_option_init (bp, cmsgp, type)`: start an ancillary data object for hop-by-hop or destination options
/// in the buffer `bp`.
///
/// # Safety
/// `bp` has room for a `cmsghdr`; `cmsgp` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_init(bp: *mut c_void, cmsgp: *mut *mut cmsghdr, ty: c_int) -> c_int {
    if ty != IPV6_HOPOPTS && ty != IPV6_DSTOPTS {
        return -1;
    }
    let newp = bp as *mut cmsghdr;
    // SAFETY: `bp` has room for a cmsghdr (the caller's contract).
    unsafe { newp.write(cmsghdr { cmsg_len: cmsg_len(0), cmsg_level: IPPROTO_IPV6, cmsg_type: ty }) };
    // SAFETY: `cmsgp` is writable (the caller's contract).
    unsafe { cmsgp.write(newp) };
    0
}

/// Reserve `datalen` bytes aligned as `multx * n + plusy` in the object; their address, or NULL.
///
/// # Safety
/// `cmsg` is an object set up by `inet6_option_init` with room in its buffer for the padding and data.
unsafe fn option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    if !matches!(multx, 1 | 2 | 4 | 8) || !(0..=7).contains(&plusy) {
        return core::ptr::null_mut();
    }
    // SAFETY: `cmsg` points to a valid header (the caller's contract).
    let mut len = unsafe { (*cmsg).cmsg_len };
    let mut dsize = (len - CMSG_HDR) as c_int;
    if dsize == 0 {
        len += 2;
        dsize = 2;
    }
    let pad = (((multx - (dsize & (multx - 1))) & (multx - 1)) + plusy) as usize;
    // SAFETY: room for the padding (the caller's contract).
    unsafe { pad_at(cmsg, len - CMSG_HDR, pad) };
    len += pad;
    let result = data_ptr(cmsg, len - CMSG_HDR);
    len = len.wrapping_add(datalen as usize);
    dsize = (len - CMSG_HDR) as c_int;
    let pad = ((8 - (dsize & 7)) & 7) as usize;
    // SAFETY: room for the padding (the caller's contract).
    unsafe { pad_at(cmsg, len - CMSG_HDR, pad) };
    len += pad;
    // SAFETY: as above; the length is stored before the size check, as glibc's stepwise updates leave it.
    unsafe { (*cmsg).cmsg_len = len };
    let len8b = (len - CMSG_HDR) / 8 - 1;
    if len8b >= 256 {
        return core::ptr::null_mut();
    }
    // SAFETY: the object holds at least 8 data bytes now, so data byte 1 (the extension header's length) is in it.
    unsafe { data_ptr(cmsg, 1).write(len8b as u8) };
    result
}

/// `inet6_option_append (cmsg, typep, multx, plusy)`: append the option at `typep` (type, length, data) with the
/// alignment `multx * n + plusy`.
///
/// # Safety
/// `cmsg` was set up by `inet6_option_init` with room in its buffer; `typep` points at a whole option.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_append(cmsg: *mut cmsghdr, typep: *const u8, multx: c_int, plusy: c_int) -> c_int {
    // SAFETY: `typep` points at an option, so its type byte is readable.
    let len = if unsafe { *typep } == IP6OPT_PAD1 {
        1
    } else {
        // SAFETY: an option other than Pad1 has a length byte after its type.
        unsafe { *typep.wrapping_add(1) as c_int + 2 }
    };
    // SAFETY: forwarded contract.
    let ptr = unsafe { option_alloc(cmsg, len, multx, plusy) };
    if ptr.is_null() {
        return -1;
    }
    // SAFETY: the whole option, `len` bytes, is readable at `typep`.
    let src = unsafe { ffi::bytes(typep, len as usize) };
    // SAFETY: option_alloc reserved `len` bytes at `ptr` in the object, which does not overlap the caller's option.
    unsafe { ffi::bytes_mut(ptr, len as usize) }.copy_from_slice(src);
    0
}

/// `inet6_option_alloc (cmsg, datalen, multx, plusy)`: room for an option of `datalen` bytes; the address of its
/// type byte, or NULL.
///
/// # Safety
/// As `inet6_option_append`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_alloc(cmsg: *mut cmsghdr, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8 {
    // SAFETY: forwarded contract.
    unsafe { option_alloc(cmsg, datalen, multx, plusy) }
}

/// Check `cmsg` is a hop-by-hop or destination options object that holds all it says; its extension header (data bytes
/// from 0 to the end of the options).
///
/// # Safety
/// `cmsg` is a valid ancillary data object whose `cmsg_len` bytes are readable, unchanged for `'a`.
unsafe fn option_bounds<'a>(cmsg: *const cmsghdr) -> Option<&'a [u8]> {
    // SAFETY: `cmsg` points to a valid header (the caller's contract).
    let c = unsafe { &*cmsg };
    if c.cmsg_level != IPPROTO_IPV6 || (c.cmsg_type != IPV6_HOPOPTS && c.cmsg_type != IPV6_DSTOPTS) {
        return None;
    }
    if c.cmsg_len < cmsg_len(2) {
        return None;
    }
    // SAFETY: the object's `cmsg_len` bytes, the data after the header among them, are readable for `'a` (the caller's
    // contract).
    let data = unsafe { ffi::bytes(data_ptr(cmsg, 0), c.cmsg_len - CMSG_HDR) };
    let n = (data[1] as usize + 1) * 8;
    if c.cmsg_len < cmsg_len(n) {
        return None;
    }
    Some(&data[..n])
}

/// The option after `*tptrp` (or the first one when it is NULL) in the object's options `ext`, as an offset into `ext`;
/// None on an error.
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

/// `inet6_option_next (cmsg, tptrp)`: the next option of the object: 0 with `*tptrp` at its type byte; -1 with
/// `*tptrp` NULL when there are no more; -1 with `*tptrp` unchanged on an error.
///
/// # Safety
/// `cmsg` is a valid ancillary data object; `tptrp` is valid (`*tptrp` NULL or a pointer into the object).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_next(cmsg: *const cmsghdr, tptrp: *mut *mut u8) -> c_int {
    // SAFETY: `cmsg` is a valid object (the caller's contract).
    let Some(ext) = (unsafe { option_bounds(cmsg) }) else { return -1 };
    // SAFETY: `tptrp` is valid (the caller's contract).
    let tptr = unsafe { &mut *tptrp };
    let Some(result) = option_start(ext, *tptr) else { return -1 };
    *tptr = data_ptr(cmsg, result);
    if opt_end(ext, result).is_some() { 0 } else { -1 }
}

/// `inet6_option_find (cmsg, tptrp, type)`: the next option of the object that has the given type.
///
/// # Safety
/// As `inet6_option_next`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_find(cmsg: *const cmsghdr, tptrp: *mut *mut u8, ty: c_int) -> c_int {
    // SAFETY: `cmsg` is a valid object (the caller's contract).
    let Some(ext) = (unsafe { option_bounds(cmsg) }) else { return -1 };
    // SAFETY: `tptrp` is valid (the caller's contract).
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

// ---------------------------------------------------------------------------------------------
// Multicast source filters: socket options with variable size arguments.

/// The socket level for an address of family `af` and size `len` (family and size agree; failing that the first
/// protocol whose address has this size).
fn get_sol(af: c_int, len: socklen_t) -> c_int {
    // (level, family, address size): IP, IPv6, AX.25, IPX, AppleTalk, ROSE, packet
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
const GF_HEADER: usize = 144; // sizeof (struct group_filter) - sizeof (struct sockaddr_storage)
const SS: usize = 128; // sizeof (struct sockaddr_storage)
const IMSF_HEADER: usize = 16; // sizeof (struct ip_msfilter) - sizeof (struct in_addr)

/// A zeroed scratch buffer of `n` bytes from the library's heap (calloc, as glibc's code uses), freed on drop.
struct Scratch(*mut u8, usize);

impl Scratch {
    fn new(n: usize) -> Option<Scratch> {
        // SAFETY: calloc has no preconditions.
        let p = unsafe { rusty_libc_malloc::calloc(1, n.max(1)) } as *mut u8;
        if p.is_null() { None } else { Some(Scratch(p, n)) }
    }
    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: the block holds `self.1` zeroed (initialised) bytes owned by this value alone.
        unsafe { ffi::bytes_mut(self.0, self.1) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // SAFETY: the block came from calloc and is owned by this value alone.
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

/// The out-parameters of the get*sourcefilter functions as references.
///
/// # Safety
/// `fmode` and `numsrc` are valid, distinct pointers.
unsafe fn filter_outs<'a>(fmode: *mut u32, numsrc: *mut u32) -> (&'a mut u32, &'a mut u32) {
    // SAFETY: the caller's contract.
    let f = unsafe { &mut *fmode };
    // SAFETY: the caller's contract.
    let n = unsafe { &mut *numsrc };
    (f, n)
}

/// The group address of a source-filter call: its family and its first `min(grouplen, 128)` bytes.
///
/// # Safety
/// `group` points to `grouplen` readable bytes, at least the 2-byte family (read whatever `grouplen` says, as glibc does).
unsafe fn group_addr<'a>(group: *const sockaddr, grouplen: socklen_t) -> (c_int, &'a [u8]) {
    let gl = (grouplen as usize).min(SS);
    // SAFETY: the caller's contract.
    let b = unsafe { ffi::bytes(group.cast::<u8>(), gl.max(2)) };
    (u16::from_ne_bytes([b[0], b[1]]) as c_int, &b[..gl])
}

/// `getsourcefilter (s, interface, group, grouplen, fmode, numsrc, slist)`: the source filter of a multicast
/// group on the socket: the filter mode, and up to `*numsrc` sources (`*numsrc` is the number there are).
///
/// # Safety
/// The pointers are valid; `slist` has room for `*numsrc` addresses.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: *mut u32, numsrc: *mut u32, slist: *mut sockaddr_storage) -> c_int {
    // SAFETY: valid, distinct pointers (the caller's contract).
    let (fmode, numsrc) = unsafe { filter_outs(fmode, numsrc) };
    let want = *numsrc;
    let mut needed = (GF_HEADER as u64 + u64::from(want) * SS as u64) as socklen_t;
    let Some(mut gf) = Scratch::new(needed as usize) else { return -1 };
    let g = gf.bytes();
    g[..4].copy_from_slice(&interface.to_ne_bytes());
    // SAFETY: `group` points to a socket address of `grouplen` bytes (the caller's contract).
    let (family, ga) = unsafe { group_addr(group, grouplen) };
    g[8..8 + ga.len()].copy_from_slice(ga);
    g[140..144].copy_from_slice(&want.to_ne_bytes());
    let sol = get_sol(family, grouplen);
    if sol == -1 {
        errno::set(22);
        return -1;
    }
    // SAFETY: the buffer and `needed` are ours, the buffer `needed` bytes long.
    let result = unsafe { crate::sock::getsockopt(s, sol, MCAST_MSFILTER, g.as_mut_ptr().cast(), &mut needed) };
    if result == 0 {
        let ns = u32::from_ne_bytes(g[140..144].try_into().unwrap());
        *fmode = u32::from_ne_bytes(g[136..140].try_into().unwrap());
        let n = want.min(ns) as usize * SS;
        // SAFETY: `slist` has room for `*numsrc` addresses (the caller's contract), at least `n` bytes.
        unsafe { ffi::bytes_mut(slist.cast::<u8>(), n) }.copy_from_slice(&g[GF_HEADER..GF_HEADER + n]);
        *numsrc = ns;
    }
    result
}

/// `setsourcefilter (s, interface, group, grouplen, fmode, numsrc, slist)`: set the source filter.
///
/// # Safety
/// The pointers are valid; `slist` holds `numsrc` addresses.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsourcefilter(s: c_int, interface: u32, group: *const sockaddr, grouplen: socklen_t, fmode: u32, numsrc: u32, slist: *const sockaddr_storage) -> c_int {
    let needed = (GF_HEADER as u64 + u64::from(numsrc) * SS as u64) as usize;
    let Some(mut gf) = Scratch::new(needed) else { return -1 };
    let g = gf.bytes();
    g[..4].copy_from_slice(&interface.to_ne_bytes());
    // SAFETY: `group` points to a socket address of `grouplen` bytes (the caller's contract).
    let (family, ga) = unsafe { group_addr(group, grouplen) };
    g[8..8 + ga.len()].copy_from_slice(ga);
    g[136..140].copy_from_slice(&fmode.to_ne_bytes());
    g[140..144].copy_from_slice(&numsrc.to_ne_bytes());
    let n = numsrc as usize * SS;
    // SAFETY: `slist` holds `numsrc` addresses (the caller's contract).
    g[GF_HEADER..GF_HEADER + n].copy_from_slice(unsafe { ffi::bytes(slist.cast::<u8>(), n) });
    let sol = get_sol(family, grouplen);
    if sol == -1 {
        errno::set(22);
        return -1;
    }
    // SAFETY: the buffer is ours and `needed` bytes long.
    unsafe { crate::sock::setsockopt(s, sol, MCAST_MSFILTER, g.as_ptr().cast(), needed as socklen_t) }
}

/// `getipv4sourcefilter (s, interface, group, fmode, numsrc, slist)`: as `getsourcefilter` for IPv4.
///
/// # Safety
/// The pointers are valid; `slist` has room for `*numsrc` addresses.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getipv4sourcefilter(s: c_int, interface: in_addr, group: in_addr, fmode: *mut u32, numsrc: *mut u32, slist: *mut in_addr) -> c_int {
    // SAFETY: valid, distinct pointers (the caller's contract).
    let (fmode, numsrc) = unsafe { filter_outs(fmode, numsrc) };
    let want = *numsrc;
    let mut needed = (IMSF_HEADER as u64 + u64::from(want) * 4) as socklen_t;
    let Some(mut imsf) = Scratch::new(needed as usize) else { return -1 };
    let m = imsf.bytes();
    m[..4].copy_from_slice(&group.s_addr.to_ne_bytes());
    m[4..8].copy_from_slice(&interface.s_addr.to_ne_bytes());
    m[12..16].copy_from_slice(&want.to_ne_bytes());
    // SAFETY: the buffer and `needed` are ours, the buffer `needed` bytes long.
    let result = unsafe { crate::sock::getsockopt(s, 0, IP_MSFILTER, m.as_mut_ptr().cast(), &mut needed) };
    if result == 0 {
        let ns = u32::from_ne_bytes(m[12..16].try_into().unwrap());
        *fmode = u32::from_ne_bytes(m[8..12].try_into().unwrap());
        let n = want.min(ns) as usize * 4;
        // SAFETY: `slist` has room for `*numsrc` addresses (the caller's contract), at least `n` bytes.
        unsafe { ffi::bytes_mut(slist.cast::<u8>(), n) }.copy_from_slice(&m[IMSF_HEADER..IMSF_HEADER + n]);
        *numsrc = ns;
    }
    result
}

/// `setipv4sourcefilter (s, interface, group, fmode, numsrc, slist)`: as `setsourcefilter` for IPv4.
///
/// # Safety
/// The pointers are valid; `slist` holds `numsrc` addresses.
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
    // SAFETY: `slist` holds `numsrc` addresses (the caller's contract).
    m[IMSF_HEADER..IMSF_HEADER + n].copy_from_slice(unsafe { ffi::bytes(slist.cast::<u8>(), n) });
    // SAFETY: the buffer is ours and `needed` bytes long.
    unsafe { crate::sock::setsockopt(s, 0, IP_MSFILTER, m.as_ptr().cast(), needed as socklen_t) }
}
