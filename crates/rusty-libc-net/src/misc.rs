//! netinet/in.h helpers: `bindresvport` and the RFC 3542 option and routing header functions
//! (`inet6_opt_*`, `inet6_rth_*`). The obsolete RFC 2292 `inet6_option_*` functions and the multicast source
//! filter functions are in `inetx`.
//!
//! The C shells view the caller's extension-header buffer as a slice of the length it passes (`extlen`, `bp_len`, or the
//! length the header's own length byte gives) and the work is done on that slice.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::{errno, ffi};

const HBH: usize = 2; // sizeof(struct ip6_hbh) and of struct ip6_opt
const IP6OPT_PAD1: u8 = 0;
const IP6OPT_PADN: u8 = 1;
const IPV6_RTHDR_TYPE_0: c_int = 0;

#[inline]
fn a8(x: socklen_t) -> bool {
    x.is_multiple_of(8)
}

/// # Safety
/// `extbuf` is null or points to `extlen` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_init(extbuf: *mut c_void, extlen: socklen_t) -> c_int {
    if !extbuf.is_null() {
        if extlen == 0 || !a8(extlen) || extlen > 256 * 8 {
            return -1;
        }
        // SAFETY: `extbuf` points to `extlen` (at least 8) writable bytes (the caller's contract).
        let b = unsafe { ffi::bytes_mut(extbuf.cast::<u8>(), extlen as usize) };
        b[1] = (extlen / 8 - 1) as u8;
    }
    HBH as c_int
}

/// Padding of `npad` bytes at `b[offset..]`: a Pad1 option or a PadN option of zeros.
fn add_padding(b: &mut [u8], offset: usize, npad: usize) {
    if npad == 1 {
        b[offset] = IP6OPT_PAD1;
    } else if npad > 0 {
        b[offset] = IP6OPT_PADN;
        b[offset + 1] = (npad - 2) as u8;
        b[offset + 2..offset + npad].fill(0);
    }
}

/// # Safety
/// glibc's contract for `inet6_opt_append`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_append(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, ty: u8, len: socklen_t, align: u8, databufp: *mut *mut c_void) -> c_int {
    if (offset as usize) < HBH || offset < 0 {
        return -1;
    }
    if ty == IP6OPT_PAD1 || ty == IP6OPT_PADN || len > 255 {
        return -1;
    }
    if align == 0 || align > 8 || (align & (align - 1)) != 0 || align as u32 > len {
        return -1;
    }
    let data_offset = offset as usize + HBH;
    let npad = (align as usize - data_offset % align as usize) & (align as usize - 1);
    let mut offset = offset as usize;
    if !extbuf.is_null() {
        if data_offset + npad + len as usize > extlen as usize {
            return -1;
        }
        // SAFETY: `extbuf` points to `extlen` writable bytes (the caller's contract).
        let b = unsafe { ffi::bytes_mut(extbuf.cast::<u8>(), extlen as usize) };
        add_padding(b, offset, npad);
        offset += npad;
        b[offset] = ty;
        b[offset + 1] = len as u8;
        let data = b[offset + HBH..].as_mut_ptr().cast::<c_void>();
        // SAFETY: `databufp` is writable (the caller's contract; glibc stores through it unchecked too).
        unsafe { databufp.write(data) };
    } else {
        offset += npad;
    }
    (offset + HBH + len as usize) as c_int
}

/// # Safety
/// glibc's contract for `inet6_opt_finish`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_finish(extbuf: *mut c_void, extlen: socklen_t, offset: c_int) -> c_int {
    if (offset as usize) < HBH || offset < 0 {
        return -1;
    }
    let npad = (8 - (offset as usize & 7)) & 7;
    if !extbuf.is_null() {
        if offset as usize + npad > extlen as usize {
            return -1;
        }
        // SAFETY: `extbuf` points to `extlen` writable bytes (the caller's contract).
        add_padding(unsafe { ffi::bytes_mut(extbuf.cast::<u8>(), extlen as usize) }, offset as usize, npad);
    }
    (offset as usize + npad) as c_int
}

/// # Safety
/// `databuf + offset` has room for `vallen` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_set_val(databuf: *mut c_void, offset: c_int, val: *mut c_void, vallen: socklen_t) -> c_int {
    // SAFETY: `val` has `vallen` readable bytes (the caller's contract).
    let src = unsafe { ffi::bytes(val.cast::<u8>(), vallen as usize) };
    // SAFETY: `databuf + offset` has room for `vallen` bytes, not overlapping `val` (memcpy's contract, as glibc's).
    let dst = unsafe { ffi::bytes_mut(databuf.cast::<u8>().wrapping_offset(offset as isize), vallen as usize) };
    dst.copy_from_slice(src);
    offset + vallen as c_int
}

/// The option walk of `inet6_opt_next` (`want` None) and `inet6_opt_find` (`want` Some(type)) over the extension header
/// `b`: (offset after the option, its type, its data offset, its data length), or None (-1).
fn opt_walk(b: &[u8], offset: c_int, want: Option<u8>) -> Option<(usize, u8, usize, u8)> {
    let mut offset = offset as i64;
    if offset == 0 {
        offset = HBH as i64;
    } else if offset < HBH as i64 {
        return None;
    }
    let extlen = b.len() as i64;
    let mut off = offset as usize;
    while (off as i64) < extlen {
        let t = b[off];
        if t == IP6OPT_PAD1 {
            off += 1;
            if want == Some(IP6OPT_PAD1) {
                return Some((off, t, off, 0));
            }
        } else {
            // glibc reads the length byte even when it is past the end; any value then takes the walk past `extlen`, which
            // ends it with -1, so a missing byte gives the same result
            let l = *b.get(off + 1)?;
            let start = off;
            off += HBH + l as usize;
            // next skips PadN options, find every option of another type (PadN too unless it is the one wanted)
            let skip = match want {
                None => t == IP6OPT_PADN,
                Some(w) => w != t,
            };
            if skip {
                continue;
            }
            if off as i64 > extlen {
                return None;
            }
            return Some((off, t, start + HBH, l));
        }
    }
    None
}

/// # Safety
/// glibc's contract for `inet6_opt_next`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_next(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, typep: *mut u8, lenp: *mut socklen_t, databufp: *mut *mut c_void) -> c_int {
    // SAFETY: `extbuf` points to `extlen` bytes (the caller's contract).
    let b = unsafe { ffi::bytes_mut(extbuf.cast::<u8>(), extlen as usize) };
    match opt_walk(b, offset, None) {
        Some((next, ty, data, l)) => {
            // SAFETY: `typep` is writable (the caller's contract).
            unsafe { typep.write(ty) };
            // SAFETY: `lenp` and `databufp` are writable (the caller's contract).
            unsafe { opt_found(lenp, databufp, l, b[data..].as_mut_ptr()) };
            next as c_int
        }
        None => -1,
    }
}

/// Store a found option's data length and data pointer.
///
/// # Safety
/// `lenp` and `databufp` are writable (glibc stores through them unchecked too).
unsafe fn opt_found(lenp: *mut socklen_t, databufp: *mut *mut c_void, l: u8, data: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe { lenp.write(l as socklen_t) };
    // SAFETY: the caller's contract.
    unsafe { databufp.write(data.cast::<c_void>()) };
}

/// # Safety
/// glibc's contract for `inet6_opt_find`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_find(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, ty: u8, lenp: *mut socklen_t, databufp: *mut *mut c_void) -> c_int {
    // SAFETY: `extbuf` points to `extlen` bytes (the caller's contract).
    let b = unsafe { ffi::bytes_mut(extbuf.cast::<u8>(), extlen as usize) };
    match opt_walk(b, offset, Some(ty)) {
        Some((next, _, data, l)) => {
            // SAFETY: `lenp` and `databufp` are writable (the caller's contract).
            unsafe { opt_found(lenp, databufp, l, b[data..].as_mut_ptr()) };
            next as c_int
        }
        None => -1,
    }
}

/// # Safety
/// `databuf + offset` has `vallen` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_get_val(databuf: *mut c_void, offset: c_int, val: *mut c_void, vallen: socklen_t) -> c_int {
    // SAFETY: `databuf + offset` has `vallen` readable bytes (the caller's contract).
    let src = unsafe { ffi::bytes(databuf.cast::<u8>().wrapping_offset(offset as isize), vallen as usize) };
    // SAFETY: `val` has room for `vallen` bytes, not overlapping the source (memcpy's contract, as glibc's).
    let dst = unsafe { ffi::bytes_mut(val.cast::<u8>(), vallen as usize) };
    dst.copy_from_slice(src);
    offset + vallen as c_int
}

// ---- routing header type 0: nxt, len, type, segleft, reserved, slmap[3], then the addresses

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet6_rth_space(ty: c_int, segments: c_int) -> socklen_t {
    if ty == IPV6_RTHDR_TYPE_0 && (0..=127).contains(&segments) { (8 + segments * 16) as socklen_t } else { 0 }
}

/// # Safety
/// `bp` points to `bp_len` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_init(bp: *mut c_void, bp_len: socklen_t, ty: c_int, segments: c_int) -> *mut c_void {
    if ty == IPV6_RTHDR_TYPE_0 && (0..=127).contains(&segments) {
        let len = 8 + segments as usize * 16;
        if len > bp_len as usize {
            return core::ptr::null_mut();
        }
        // SAFETY: `bp` points to `bp_len` writable bytes, at least `len` (the caller's contract).
        let b = unsafe { ffi::bytes_mut(bp.cast::<u8>(), len) };
        b.fill(0);
        b[1] = (segments as usize * 16 / 8) as u8;
        b[2] = IPV6_RTHDR_TYPE_0 as u8;
        return bp;
    }
    core::ptr::null_mut()
}

/// The fixed part of a routing header: (header length byte, type, segments left).
///
/// # Safety
/// `bp` points to a routing header (at least its 8 fixed bytes).
unsafe fn rth_fixed(bp: *const c_void) -> (u8, u8, u8) {
    // SAFETY: the caller's contract; only the first four bytes are read.
    let h = unsafe { ffi::bytes(bp.cast::<u8>(), 4) };
    (h[1], h[2], h[3])
}

/// # Safety
/// `bp` is a header made by `inet6_rth_init`; `addr` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_add(bp: *mut c_void, addr: *const in6_addr) -> c_int {
    // SAFETY: `bp` is a routing header (the caller's contract).
    let (len, ty, segleft) = unsafe { rth_fixed(bp) };
    if ty as c_int != IPV6_RTHDR_TYPE_0 {
        return -1;
    }
    if len as i32 * 8 / 16 - (segleft as i32) < 1 {
        return -1;
    }
    // SAFETY: a type 0 header made by inet6_rth_init is `8 + len * 8` bytes, all writable (the caller's contract).
    let b = unsafe { ffi::bytes_mut(bp.cast::<u8>(), 8 + len as usize * 8) };
    // SAFETY: `addr` points to a valid address (the caller's contract).
    let a = unsafe { &(*addr).s6_addr };
    let at = 8 + segleft as usize * 16;
    b[at..at + 16].copy_from_slice(a);
    b[3] = segleft + 1;
    0
}

/// # Safety
/// `in_` and `out` are routing headers (they may be the same).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_reverse(in_: *const c_void, out: *mut c_void) -> c_int {
    // SAFETY: `in_` is a routing header (the caller's contract).
    let (len, ty, _) = unsafe { rth_fixed(in_) };
    if ty as c_int != IPV6_RTHDR_TYPE_0 {
        return -1;
    }
    let total = (len as usize) * 8 / 16;
    let size = 8 + total * 16;
    // `in_` and `out` may be the same header: read all of the input first, then write the output
    let mut copy = [0u8; 8 + 127 * 16];
    // SAFETY: `in_` holds `size` bytes (its fixed part and `total` addresses); the view ends before `out` is written.
    copy[..size].copy_from_slice(unsafe { ffi::bytes(in_.cast::<u8>(), size) });
    // SAFETY: `out` has room for a header of the same size (the caller's contract); `copy` holds the input now.
    let o = unsafe { ffi::bytes_mut(out.cast::<u8>(), size) };
    o[..8].copy_from_slice(&copy[..8]);
    for k in 0..total {
        o[8 + k * 16..8 + (k + 1) * 16].copy_from_slice(&copy[8 + (total - 1 - k) * 16..8 + (total - k) * 16]);
    }
    o[3] = total as u8;
    0
}

/// # Safety
/// `bp` is a routing header.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_segments(bp: *const c_void) -> c_int {
    // SAFETY: `bp` is a routing header (the caller's contract).
    let (len, ty, _) = unsafe { rth_fixed(bp) };
    if ty as c_int == IPV6_RTHDR_TYPE_0 { (len as c_int) * 8 / 16 } else { -1 }
}

/// # Safety
/// `bp` is a routing header.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_getaddr(bp: *const c_void, index: c_int) -> *mut in6_addr {
    // SAFETY: `bp` is a routing header (the caller's contract).
    let (len, ty, _) = unsafe { rth_fixed(bp) };
    if ty as c_int == IPV6_RTHDR_TYPE_0 && index < (len as c_int) * 8 / 16 {
        // glibc's address arithmetic, unchecked for a negative index as there
        return bp.cast::<u8>().cast_mut().wrapping_offset(8 + index as isize * 16).cast::<in6_addr>();
    }
    core::ptr::null_mut()
}

// ---- bindresvport

static LAST_PORT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static START_PORT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(600);

/// Bind `fd` to a reserved port, as glibc's inet/bindresvport.c: ports 600 to 1023 from where the last call stopped (the first
/// call starts at 600 + pid % 424), then 512 to 599 once all of those were in use. `sin` may be null (an AF_INET address of
/// 0.0.0.0); otherwise it must be an AF_INET `sockaddr_in` (else EAFNOSUPPORT), whose port is set. The first error other
/// than EADDRINUSE ends the search.
///
/// # Safety
/// `sin` is null or points to a `sockaddr_in`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport(fd: c_int, sin: *mut sockaddr_in) -> c_int {
    use core::sync::atomic::Ordering;
    const LOW: u32 = 512;
    const START: u32 = 600;
    const END: u32 = 1023;
    let mut local = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: 0 }, sin_zero: [0; 8] };
    let sin = if sin.is_null() {
        &mut local as *mut sockaddr_in
    } else {
        // SAFETY: `sin` points to a sockaddr_in (the caller's contract).
        if unsafe { (*sin).sin_family } as c_int != AF_INET {
            errno::set(EAFNOSUPPORT);
            return -1;
        }
        sin
    };
    let mut port = LAST_PORT.load(Ordering::Relaxed);
    if port == 0 {
        port = (rusty_libc_core::unistd::getpid() as u32) % (END - START + 1) + START;
    }
    let mut startport = START_PORT.load(Ordering::Relaxed);
    let mut endport = END;
    let mut nports = END - startport + 1;
    let mut res;
    loop {
        let mut i = 0;
        res = -1;
        while i < nports {
            // SAFETY: `sin` is the caller's sockaddr_in or our local one, writable either way.
            unsafe { (*sin).sin_port = (port as u16).to_be() };
            port += 1;
            if port > endport {
                port = startport;
            }
            // SAFETY: `sin` points to a 16-byte sockaddr_in.
            res = unsafe { crate::sock::bind(fd, sin as *const sockaddr, 16) };
            if res >= 0 || errno::get() != EADDRINUSE {
                break;
            }
            i += 1;
        }
        if i == nports && startport != LOW {
            startport = LOW;
            endport = START - 1;
            nports = START - LOW;
            port = LOW + port % (START - LOW);
            START_PORT.store(LOW, Ordering::Relaxed);
            continue;
        }
        break;
    }
    LAST_PORT.store(port, Ordering::Relaxed);
    res
}

