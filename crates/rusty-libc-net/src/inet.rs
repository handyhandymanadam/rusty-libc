//! arpa/inet.h and the functions of netinet/in.h: byte order, `inet_aton` and friends, `inet_pton`,
//! `inet_ntop`, `in6addr_any`, `in6addr_loopback`. The text forms accepted and produced are glibc 2.43's
//! (checked against the host's glibc on random and edge-case inputs by the unit tests).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use crate::util::{Buf, is_space};
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

// ---------------------------------------------------------------- byte order

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn htons(x: u16) -> u16 {
    x.to_be()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn htonl(x: u32) -> u32 {
    x.to_be()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

// ---------------------------------------------------------------- in6addr_*

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static in6addr_any: in6_addr = in6_addr { s6_addr: [0; 16] };
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static in6addr_loopback: in6_addr = in6_addr { s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };

// ---------------------------------------------------------------- IPv4 text to binary (BSD forms)

/// `strtoul(s, &end, 0)` for a string that starts with a digit: (value, bytes used), or None on overflow of
/// 64 bits (glibc's `ERANGE` case).
fn strtoul0(s: &[u8]) -> Option<(u64, usize)> {
    let (base, mut i) = if s.len() >= 3 && s[0] == b'0' && (s[1] | 0x20) == b'x' && s[2].is_ascii_hexdigit() {
        (16u64, 2)
    } else if s[0] == b'0' {
        (8, 1)
    } else {
        (10, 0)
    };
    let mut v: u64 = 0;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if d >= base {
            break;
        }
        v = v.checked_mul(base)?.checked_add(d)?;
        i += 1;
    }
    Some((v, i))
}

/// Parse the BSD address forms (`a`, `a.b`, `a.b.c`, `a.b.c.d`, each number decimal, octal or hex).
/// Returns the address (network order bytes) and the index of the first character not used, or None.
/// Trailing white space, and anything after it, is left for the caller (glibc's `inet_aton` accepts it).
pub fn parse_aton(s: &[u8]) -> Option<([u8; 4], usize)> {
    const MAX: [u64; 4] = [0xffff_ffff, 0xff_ffff, 0xffff, 0xff];
    let mut res = [0u8; 4];
    let mut np = 0usize;
    let mut pos = 0usize;
    loop {
        let c = *s.get(pos)?;
        if !c.is_ascii_digit() {
            return None;
        }
        let (val, used) = strtoul0(&s[pos..])?;
        if val > 0xffff_ffff {
            return None;
        }
        pos += used;
        let c = s.get(pos).copied().unwrap_or(0);
        if c == b'.' {
            if np > 2 || val > 0xff {
                return None;
            }
            res[np] = val as u8;
            np += 1;
            pos += 1;
        } else {
            if c != 0 && !(c < 128 && is_space(c)) {
                return None;
            }
            if val > MAX[np] {
                return None;
            }
            let w = u32::from_ne_bytes(res) | (val as u32).to_be();
            return Some((w.to_ne_bytes(), pos));
        }
    }
}

/// glibc's `inet_aton` on a C string.
///
/// # Safety
/// `cp` is a C string; `addr` is null or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_aton(cp: *const c_char, addr: *mut in_addr) -> c_int {
    // SAFETY: `cp` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(cp) };
    match parse_aton(s) {
        Some((a, _)) => {
            // SAFETY: `addr` is NULL or writable (the caller's contract).
            if let Some(addr) = unsafe { ffi::out(addr) } {
                addr.s_addr = u32::from_ne_bytes(a);
            }
            1
        }
        None => 0,
    }
}

/// # Safety
/// `cp` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_addr(cp: *const c_char) -> in_addr_t {
    // SAFETY: `cp` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(cp) };
    match parse_aton(s) {
        Some((a, _)) => u32::from_ne_bytes(a),
        None => INADDR_NONE,
    }
}

/// `inet_network`: the address as a host-order number, with each part a single byte (so "1.2" is 0x0102).
///
/// # Safety
/// `cp` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_network(cp: *const c_char) -> in_addr_t {
    // SAFETY: `cp` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(cp) };
    network_parse(s).unwrap_or(INADDR_NONE)
}

pub(crate) fn network_parse(s: &[u8]) -> Option<u32> {
    let mut parts = [0u32; 4];
    let mut np = 0usize;
    let mut i = 0usize;
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    loop {
        let mut val: u32 = 0;
        let mut base: u32 = 10;
        let mut digit = false;
        if at(i) == b'0' {
            digit = true;
            base = 8;
            i += 1;
        }
        if at(i) == b'x' || at(i) == b'X' {
            digit = false;
            base = 16;
            i += 1;
        }
        while at(i) != 0 {
            if val > 0xff {
                return None;
            }
            let c = at(i);
            if c.is_ascii_digit() {
                if base == 8 && (c == b'8' || c == b'9') {
                    return None;
                }
                val = val * base + (c - b'0') as u32;
                i += 1;
                digit = true;
                continue;
            }
            if base == 16 && c.is_ascii_hexdigit() {
                val = (val << 4) + ((c | 0x20) - b'a' + 10) as u32;
                i += 1;
                digit = true;
                continue;
            }
            break;
        }
        if !digit {
            return None;
        }
        if np >= 4 || val > 0xff {
            return None;
        }
        if at(i) == b'.' {
            parts[np] = val;
            np += 1;
            i += 1;
            continue;
        }
        while is_space(at(i)) {
            i += 1;
        }
        if at(i) != 0 {
            return None;
        }
        parts[np] = val;
        np += 1;
        let mut r = 0u32;
        for p in &parts[..np] {
            r = (r << 8) | (p & 0xff);
        }
        return Some(r);
    }
}

fn in_class_a(a: u32) -> bool {
    a & 0x8000_0000 == 0
}
fn in_class_b(a: u32) -> bool {
    a & 0xc000_0000 == 0x8000_0000
}

/// # Safety
/// Plain function.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet_lnaof(i: in_addr) -> in_addr_t {
    let a = u32::from_be(i.s_addr);
    if in_class_a(a) {
        a & 0x00ff_ffff
    } else if in_class_b(a) {
        a & 0xffff
    } else {
        a & 0xff
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet_netof(i: in_addr) -> in_addr_t {
    let a = u32::from_be(i.s_addr);
    if in_class_a(a) {
        (a & 0xff00_0000) >> 24
    } else if in_class_b(a) {
        (a & 0xffff_0000) >> 16
    } else {
        (a & 0xffff_ff00) >> 8
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet_makeaddr(net: in_addr_t, host: in_addr_t) -> in_addr {
    let v = if net < 128 {
        (net << 24) | (host & 0x00ff_ffff)
    } else if net < 65536 {
        (net << 16) | (host & 0xffff)
    } else if net < 16_777_216 {
        (net << 8) | (host & 0xff)
    } else {
        net | host
    };
    in_addr { s_addr: v.to_be() }
}

// ---------------------------------------------------------------- inet_pton / inet_ntop

/// Strict dotted quad (no leading zeros, exactly four parts, no trailing text).
pub fn parse_ipv4(s: &[u8]) -> Option<[u8; 4]> {
    let mut tmp = [0u8; 4];
    let mut idx = 0usize;
    let mut cur = 0u32; // the octet being read (kept in a register, stored when its dot or the end comes)
    let mut saw_digit = false;
    let mut octets = 0;
    for &ch in s {
        let d = ch.wrapping_sub(b'0');
        if d < 10 {
            if saw_digit && cur == 0 {
                return None;
            }
            cur = cur * 10 + d as u32;
            if cur > 255 {
                return None;
            }
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if ch == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            tmp[idx] = cur as u8;
            idx += 1;
            cur = 0;
            saw_digit = false;
        } else {
            return None;
        }
    }
    if saw_digit {
        tmp[idx] = cur as u8;
    }
    if octets < 4 { None } else { Some(tmp) }
}

fn hexval(c: u8) -> Option<u32> {
    // table lookup: 0xff marks a byte that is no hex digit
    const T: [u8; 256] = {
        let mut t = [0xffu8; 256];
        let mut i = 0;
        while i < 10 {
            t[b'0' as usize + i] = i as u8;
            i += 1;
        }
        i = 0;
        while i < 6 {
            t[b'a' as usize + i] = 10 + i as u8;
            t[b'A' as usize + i] = 10 + i as u8;
            i += 1;
        }
        t
    };
    let v = T[c as usize];
    if v == 0xff { None } else { Some(v as u32) }
}

/// IPv6 text form (RFC 4291 2.2, with an embedded dotted quad at the end).
pub fn parse_ipv6(s: &[u8]) -> Option<[u8; 16]> {
    let mut tmp = [0u8; 16];
    let mut tp = 0usize;
    let mut colonp: Option<usize> = None;
    if s.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    if s[0] == b':' {
        pos = 1;
        if pos >= s.len() || s[pos] != b':' {
            return None;
        }
    }
    let mut curtok = pos;
    let mut xdigits = 0usize;
    let mut val: u32 = 0;
    while pos < s.len() {
        let ch = s[pos];
        pos += 1;
        if let Some(d) = hexval(ch) {
            if xdigits == 4 {
                return None;
            }
            val = (val << 4) | d;
            if val > 0xffff {
                return None;
            }
            xdigits += 1;
            continue;
        }
        if ch == b':' {
            curtok = pos;
            if xdigits == 0 {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            } else if pos == s.len() {
                return None;
            }
            if tp + 2 > 16 {
                return None;
            }
            tmp[tp] = (val >> 8) as u8;
            tmp[tp + 1] = val as u8;
            tp += 2;
            xdigits = 0;
            val = 0;
            continue;
        }
        if ch == b'.' && tp + 4 <= 16 {
            if let Some(v4) = parse_ipv4(&s[curtok..]) {
                tmp[tp..tp + 4].copy_from_slice(&v4);
                tp += 4;
                xdigits = 0;
                break;
            }
        }
        return None;
    }
    if xdigits > 0 {
        if tp + 2 > 16 {
            return None;
        }
        tmp[tp] = (val >> 8) as u8;
        tmp[tp + 1] = val as u8;
        tp += 2;
    }
    if let Some(cp) = colonp {
        if tp == 16 {
            return None;
        }
        let n = tp - cp;
        // move the tail to the end, zero the gap
        for k in 0..n {
            tmp[16 - 1 - k] = tmp[tp - 1 - k];
        }
        for b in &mut tmp[cp..16 - n] {
            *b = 0;
        }
        tp = 16;
    }
    if tp != 16 { None } else { Some(tmp) }
}

/// Dotted-quad text of `a` into `out` (at most 15 characters); the length.
#[inline]
pub(crate) fn ipv4_text(a: &[u8; 4], out: &mut [u8; 16]) -> usize {
    let mut n = 0;
    for (i, &v) in a.iter().enumerate() {
        if i > 0 {
            out[n] = b'.';
            n += 1;
        }
        if v >= 100 {
            out[n] = b'0' + v / 100;
            out[n + 1] = b'0' + (v / 10) % 10;
            out[n + 2] = b'0' + v % 10;
            n += 3;
        } else if v >= 10 {
            out[n] = b'0' + v / 10;
            out[n + 1] = b'0' + v % 10;
            n += 2;
        } else {
            out[n] = b'0' + v;
            n += 1;
        }
    }
    n
}

/// Dotted-quad text.
pub fn format_ipv4(a: &[u8; 4]) -> Buf<48> {
    let mut t = [0u8; 16];
    let n = ipv4_text(a, &mut t);
    let mut o = Buf::<48>::new();
    o.push_all(&t[..n]);
    o
}

/// IPv6 text in glibc's form: lower case, longest run of zero groups (at least two) as `::` (the first
/// longest), `::a.b.c.d` for IPv4-compatible and `::ffff:a.b.c.d` for IPv4-mapped addresses.
pub fn format_ipv6(a: &[u8; 16]) -> Buf<48> {
    let mut t = [0u8; 64];
    let n = ipv6_text(a, &mut t);
    let mut o = Buf::<48>::new();
    o.push_all(&t[..n]);
    o
}

/// The text of `format_ipv6` into `out` (at most 45 characters); the length. Every single-byte store indexes with `n & 63`:
/// `n` never exceeds 45, so the mask changes nothing, but it lets the compiler drop the bounds checks of this hot loop.
#[inline]
fn ipv6_text(a: &[u8; 16], out: &mut [u8; 64]) -> usize {
    const D: &[u8; 16] = b"0123456789abcdef";
    let w = |i: usize| ((a[2 * i] as u16) << 8) | a[2 * i + 1] as u16;
    let (mut best_base, mut best_len) = (-1i32, 0i32);
    let (mut cur_base, mut cur_len) = (-1i32, 0i32);
    for i in 0..8 {
        if w(i) == 0 {
            if cur_base == -1 {
                cur_base = i as i32;
                cur_len = 1;
            } else {
                cur_len += 1;
            }
        } else if cur_base != -1 {
            if best_base == -1 || cur_len > best_len {
                best_base = cur_base;
                best_len = cur_len;
            }
            cur_base = -1;
        }
    }
    if cur_base != -1 && (best_base == -1 || cur_len > best_len) {
        best_base = cur_base;
        best_len = cur_len;
    }
    if best_base != -1 && best_len < 2 {
        best_base = -1;
    }
    let mut n = 0usize;
    let mut i = 0i32;
    // 8 groups of at most 4 digits and 7 colons are at most 39 bytes; the dotted tail replaces the last two groups
    while i < 8 {
        if best_base != -1 && i >= best_base && i < best_base + best_len {
            if i == best_base {
                out[n & 63] = b':';
                n += 1;
            }
            i += 1;
            continue;
        }
        if i != 0 {
            out[n & 63] = b':';
            n += 1;
        }
        if i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && w(5) == 0xffff)) {
            let mut t = [0u8; 16];
            let m = ipv4_text(&[a[12], a[13], a[14], a[15]], &mut t);
            out[n..n + m].copy_from_slice(&t[..m]);
            n += m;
            break;
        }
        let v = w(i as usize);
        if v >= 0x1000 {
            out[n & 63] = D[(v >> 12) as usize & 15];
            n += 1;
        }
        if v >= 0x100 {
            out[n & 63] = D[(v >> 8) as usize & 15];
            n += 1;
        }
        if v >= 0x10 {
            out[n & 63] = D[(v >> 4) as usize & 15];
            n += 1;
        }
        out[n & 63] = D[v as usize & 15];
        n += 1;
        i += 1;
    }
    if best_base != -1 && best_base + best_len == 8 {
        out[n & 63] = b':';
        n += 1;
    }
    n
}

/// `inet_ntop` on Rust types: the text of the address in `src` (4 bytes for `AF_INET`, 16 for `AF_INET6`) into `dst` with a
/// NUL; the text length, or `EAFNOSUPPORT` / `ENOSPC` (nothing written then).
pub fn ntop(af: c_int, src: &[u8], dst: &mut [u8]) -> Result<usize, c_int> {
    let mut t = [0u8; 64];
    let n = match af {
        AF_INET => {
            let a: &[u8; 4] = src.try_into().map_err(|_| EAFNOSUPPORT)?;
            if let Some(d) = dst.first_chunk_mut::<16>() {
                return Ok(ntop4_in_place(a, d));
            }
            ipv4_text(a, t.first_chunk_mut::<16>().unwrap())
        }
        AF_INET6 => ipv6_text(src.try_into().map_err(|_| EAFNOSUPPORT)?, &mut t),
        _ => return Err(EAFNOSUPPORT),
    };
    copy_text(&t[..n], dst)
}

/// The dotted quad of `a` and a NUL into `d`, which has room for the longest text; the length.
#[inline]
fn ntop4_in_place(a: &[u8; 4], d: &mut [u8; 16]) -> usize {
    let n = ipv4_text(a, d);
    d[n & 15] = 0; // n <= 15: the mask only drops the bounds check
    n
}

/// `text` and a NUL into `dst`, or ENOSPC (nothing written).
#[inline]
fn copy_text(text: &[u8], dst: &mut [u8]) -> Result<usize, c_int> {
    let n = text.len();
    if n + 1 > dst.len() {
        return Err(ENOSPC);
    }
    dst[..n].copy_from_slice(text);
    dst[n] = 0;
    Ok(n)
}

/// # Safety
/// `src` points to an address of family `af`; `dst` to `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t) -> *const c_char {
    // The text goes to a local buffer only when `dst` may be too small: the buffer is declared on those paths alone, so the
    // in-place paths do not zero it first.
    let finish = |text: &[u8]| {
        // The longest text is 45 bytes and a NUL, so a view of at most 64 bytes decides ENOSPC as the full `size` would.
        // SAFETY: the caller passes `size` writable bytes at `dst` that nothing else uses during the call.
        let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), (size as usize).min(64)) };
        match copy_text(text, d) {
            Ok(_) => dst.cast_const(),
            Err(e) => {
                errno::set(e);
                core::ptr::null()
            }
        }
    };
    match af {
        AF_INET => {
            // SAFETY: the caller passes an IPv4 address (4 bytes) at `src`.
            let a = unsafe { &*src.cast::<[u8; 4]>() };
            if size >= 16 {
                // room for the longest text: write it in place
                // SAFETY: the caller passes `size` (at least 16) writable bytes at `dst`, unused by others during the call.
                ntop4_in_place(a, unsafe { &mut *dst.cast::<[u8; 16]>() });
                return dst;
            }
            let mut t = [0u8; 16];
            let n = ipv4_text(a, &mut t);
            finish(&t[..n])
        }
        AF_INET6 => {
            // SAFETY: the caller passes an IPv6 address (16 bytes) at `src`.
            let a = unsafe { &*src.cast::<[u8; 16]>() };
            if size >= 64 {
                // room for anything ipv6_text writes: write it in place (it stores only the text, then the NUL below)
                // SAFETY: the caller passes `size` (at least 64) writable bytes at `dst`, unused by others during the call.
                let d = unsafe { &mut *dst.cast::<[u8; 64]>() };
                let n = ipv6_text(a, d);
                d[n & 63] = 0;
                return dst;
            }
            let mut t = [0u8; 64];
            let n = ipv6_text(a, &mut t);
            finish(&t[..n])
        }
        _ => {
            errno::set(EAFNOSUPPORT);
            core::ptr::null()
        }
    }
}

/// # Safety
/// `src` is a C string; `dst` points to a writable address of family `af` (4 or 16 bytes).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    // SAFETY: `src` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(src) };
    // SAFETY: as for `__inet_pton_length`; `s` is `src`'s bytes.
    unsafe { pton_raw(af, s, dst) }
}

/// `inet_pton` on Rust types: the binary address (4 or 16 bytes used) or None when `s` is not one, or `EAFNOSUPPORT`.
pub fn pton(af: c_int, s: &[u8]) -> Result<Option<([u8; 16], usize)>, c_int> {
    match af {
        AF_INET => Ok(parse_ipv4(s).map(|a| {
            let mut r = [0u8; 16];
            r[..4].copy_from_slice(&a);
            (r, 4)
        })),
        AF_INET6 => Ok(parse_ipv6(s).map(|a| (a, 16))),
        _ => Err(EAFNOSUPPORT),
    }
}

/// The C shell of `inet_pton`: parse `s`, store into `dst`, return 1, 0 or -1 with errno.
///
/// # Safety
/// `dst` points to 4 (`AF_INET`) or 16 (`AF_INET6`) writable bytes.
unsafe fn pton_raw(af: c_int, s: &[u8], dst: *mut c_void) -> c_int {
    match af {
        AF_INET => match parse_ipv4(s) {
            Some(a) => {
                // SAFETY: `dst` has room for an IPv4 address (the caller's contract).
                unsafe { dst.cast::<[u8; 4]>().write_unaligned(a) };
                1
            }
            None => 0,
        },
        AF_INET6 => match parse_ipv6(s) {
            Some(a) => {
                // SAFETY: `dst` has room for an IPv6 address (the caller's contract).
                unsafe { dst.cast::<[u8; 16]>().write_unaligned(a) };
                1
            }
            None => 0,
        },
        _ => {
            errno::set(EAFNOSUPPORT);
            -1
        }
    }
}

/// `inet_pton` on a counted string.
///
/// # Safety
/// `src` points to `len` readable bytes; `dst` as for `inet_pton`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_pton_length(af: c_int, src: *const c_char, len: usize, dst: *mut c_void) -> c_int {
    // SAFETY: the caller passes `len` readable bytes at `src`.
    let s = unsafe { ffi::bytes(src.cast::<u8>(), len) };
    // SAFETY: forwarded contract for `dst`.
    unsafe { pton_raw(af, s, dst) }
}

/// Per thread (`#[thread_local]`, so no other thread can reach it); the pointer handed to C is valid until the thread's next
/// `inet_ntoa`.
#[thread_local]
static NTOA_BUF: SyncCell<[u8; 16]> = SyncCell::new([0; 16]);

/// `inet_ntoa`: dotted quad in a per-thread static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet_ntoa(i: in_addr) -> *mut c_char {
    let a = i.s_addr.to_ne_bytes();
    // SAFETY: the buffer is this thread's own and no reference to it outlives this call (C only gets the raw pointer, and
    // its contract ends at the thread's next call, which is this one).
    unsafe {
        NTOA_BUF.with_unsync(|b| {
            let n = ipv4_text(&a, b.first_chunk_mut::<16>().unwrap());
            b[n] = 0;
        })
    };
    NTOA_BUF.as_ptr().cast::<c_char>()
}

// ---------------------------------------------------------------- inet_nsap_*

fn xtob(c: u8) -> u8 {
    c - if c.is_ascii_digit() { b'0' } else { b'7' }
}

/// # Safety
/// `ascii` is a C string; `binary` has room for `maxlen` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_addr(ascii: *const c_char, binary: *mut u8, maxlen: c_int) -> u32 {
    // SAFETY: `ascii` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(ascii) };
    // At most one byte per two characters is written, so a limit above `s.len() / 2 + 1` (a negative `maxlen` is a huge
    // unsigned one, as glibc compares it) never stops the loop before the string's end does.
    let n = (maxlen as u32 as usize).min(s.len() / 2 + 1);
    // SAFETY: `binary` has room for `maxlen` bytes, at least `n`; nothing else uses them meanwhile (the caller's contract).
    let out = unsafe { ffi::bytes_mut(binary, n) };
    nsap_addr(s, out) as u32
}

/// `inet_nsap_addr` on Rust types: hex pairs of `s` (with `.`, `+`, `/` skipped) into `out`; the bytes written, or 0 on a
/// bad character (bytes before it may have been written, as in glibc).
pub fn nsap_addr(s: &[u8], out: &mut [u8]) -> usize {
    let mut len = 0usize;
    let mut i = 0usize;
    while i < s.len() && len < out.len() {
        let c = s[i];
        i += 1;
        if c == b'.' || c == b'+' || c == b'/' {
            continue;
        }
        if c >= 128 {
            return 0;
        }
        let c = c.to_ascii_uppercase();
        if !c.is_ascii_hexdigit() {
            return 0;
        }
        let nib = xtob(c);
        let Some(&c2) = s.get(i) else { return 0 };
        i += 1;
        let c2 = c2.to_ascii_uppercase();
        if c2 >= 128 || !c2.is_ascii_hexdigit() {
            return 0;
        }
        out[len] = (nib << 4) | xtob(c2);
        len += 1;
    }
    len
}

static NSAP_BUF: crate::util::Spin<[u8; 255 * 2 + 128]> = crate::util::Spin::new([0; 255 * 2 + 128]);

/// # Safety
/// `binary` points to `binlen` bytes; `ascii` is null or has room for `2 * binlen + binlen / 2 + 1` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_ntoa(binlen: c_int, binary: *const u8, ascii: *mut c_char) -> *mut c_char {
    let n = binlen.clamp(0, 255) as usize;
    // SAFETY: `binary` points to `binlen` bytes (the caller's contract; a negative length reads nothing).
    let bin = unsafe { ffi::bytes(binary, n) };
    let need = nsap_ntoa_len(n);
    if ascii.is_null() {
        let mut guard = NSAP_BUF.lock();
        nsap_ntoa(bin, &mut guard[..need]);
        // the static buffer, as glibc returns it (valid until the next call with NULL)
        guard.as_mut_ptr().cast::<c_char>()
    } else {
        // SAFETY: `ascii` has room for `2 * binlen + binlen / 2 + 1` bytes (the caller's contract), which is `need`.
        nsap_ntoa(bin, unsafe { ffi::bytes_mut(ascii.cast::<u8>(), need) });
        ascii
    }
}

/// Text length of `inet_nsap_ntoa` for `n` bytes, the NUL included.
fn nsap_ntoa_len(n: usize) -> usize {
    2 * n + n / 2 + 1
}

/// `inet_nsap_ntoa` on Rust types: upper-case hex of `bin` with a `.` after every second byte but the last, then a NUL, into
/// `out` (at least [`nsap_ntoa_len`] bytes).
pub fn nsap_ntoa(bin: &[u8], out: &mut [u8]) {
    let hexd = |n: u8| n + if n < 10 { b'0' } else { b'7' };
    let mut o = 0usize;
    for (i, &b) in bin.iter().enumerate() {
        out[o] = hexd(b >> 4);
        out[o + 1] = hexd(b & 15);
        o += 2;
        if i % 2 == 0 && i + 1 < bin.len() {
            out[o] = b'.';
            o += 1;
        }
    }
    out[o] = 0;
}
