use crate::types::*;
use crate::util::{Buf, is_space};
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static in6addr_any: in6_addr = in6_addr { s6_addr: [0; 16] };
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static in6addr_loopback: in6_addr = in6_addr { s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_aton(cp: *const c_char, addr: *mut in_addr) -> c_int {
    let s = unsafe { crate::util::cbytes(cp) };
    match parse_aton(s) {
        Some((a, _)) => {
            if !addr.is_null() {
                unsafe { (*addr).s_addr = u32::from_ne_bytes(a) };
            }
            1
        }
        None => 0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_addr(cp: *const c_char) -> in_addr_t {
    let s = unsafe { crate::util::cbytes(cp) };
    match parse_aton(s) {
        Some((a, _)) => u32::from_ne_bytes(a),
        None => INADDR_NONE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_network(cp: *const c_char) -> in_addr_t {
    let s = unsafe { crate::util::cbytes(cp) };
    network_parse(s).unwrap_or(INADDR_NONE)
}

fn network_parse(s: &[u8]) -> Option<u32> {
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

pub fn parse_ipv4(s: &[u8]) -> Option<[u8; 4]> {
    let mut tmp = [0u8; 4];
    let mut idx = 0usize;
    let mut cur = 0u32;
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

#[inline]
fn ipv4_text(a: &[u8; 4], out: &mut [u8; 16]) -> usize {
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

pub fn format_ipv4(a: &[u8; 4]) -> Buf<48> {
    let mut t = [0u8; 16];
    let n = ipv4_text(a, &mut t);
    let mut o = Buf::<48>::new();
    o.push_all(&t[..n]);
    o
}

pub fn format_ipv6(a: &[u8; 16]) -> Buf<48> {
    let mut t = [0u8; 48];
    let n = ipv6_text(a, &mut t);
    let mut o = Buf::<48>::new();
    o.push_all(&t[..n]);
    o
}

fn ipv6_text(a: &[u8; 16], out: &mut [u8; 48]) -> usize {
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
    let o = out.as_mut_ptr();
    let mut n = 0usize;
    unsafe {
        let mut i = 0i32;
        while i < 8 {
            if best_base != -1 && i >= best_base && i < best_base + best_len {
                if i == best_base {
                    *o.add(n) = b':';
                    n += 1;
                }
                i += 1;
                continue;
            }
            if i != 0 {
                *o.add(n) = b':';
                n += 1;
            }
            if i == 6 && best_base == 0 && (best_len == 6 || (best_len == 5 && w(5) == 0xffff)) {
                let mut t = [0u8; 16];
                let m = ipv4_text(&[a[12], a[13], a[14], a[15]], &mut t);
                core::ptr::copy_nonoverlapping(t.as_ptr(), o.add(n), m);
                n += m;
                break;
            }
            let v = w(i as usize);
            if v >= 0x1000 {
                *o.add(n) = D[(v >> 12) as usize & 15];
                n += 1;
            }
            if v >= 0x100 {
                *o.add(n) = D[(v >> 8) as usize & 15];
                n += 1;
            }
            if v >= 0x10 {
                *o.add(n) = D[(v >> 4) as usize & 15];
                n += 1;
            }
            *o.add(n) = D[v as usize & 15];
            n += 1;
            i += 1;
        }
        if best_base != -1 && best_base + best_len == 8 {
            *o.add(n) = b':';
            n += 1;
        }
    }
    n
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t) -> *const c_char {
    unsafe {
        let mut t = [0u8; 48];
        let n = match af {
            AF_INET => {
                if size >= 16 {
                    let n = ipv4_text(&*(src as *const [u8; 4]), &mut *(dst as *mut [u8; 16]));
                    *dst.add(n) = 0;
                    return dst;
                }
                ipv4_text(&*(src as *const [u8; 4]), (&mut t[..16]).try_into().unwrap())
            }
            AF_INET6 => ipv6_text(&*(src as *const [u8; 16]), &mut t),
            _ => {
                errno::set(EAFNOSUPPORT);
                return core::ptr::null();
            }
        };
        if n + 1 > size as usize {
            errno::set(ENOSPC);
            return core::ptr::null();
        }
        core::ptr::copy_nonoverlapping(t.as_ptr(), dst as *mut u8, n);
        *dst.add(n) = 0;
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    unsafe { __inet_pton_length(af, src, crate::util::cstrlen(src), dst) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_pton_length(af: c_int, src: *const c_char, len: usize, dst: *mut c_void) -> c_int {
    let s = unsafe { core::slice::from_raw_parts(src as *const u8, len) };
    match af {
        AF_INET => match parse_ipv4(s) {
            Some(a) => {
                unsafe { core::ptr::copy_nonoverlapping(a.as_ptr(), dst as *mut u8, 4) };
                1
            }
            None => 0,
        },
        AF_INET6 => match parse_ipv6(s) {
            Some(a) => {
                unsafe { core::ptr::copy_nonoverlapping(a.as_ptr(), dst as *mut u8, 16) };
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

#[thread_local]
static mut NTOA_BUF: [u8; 16] = [0; 16];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet_ntoa(i: in_addr) -> *mut c_char {
    let t = format_ipv4(&i.s_addr.to_ne_bytes());
    unsafe {
        let b = &mut *(&raw mut NTOA_BUF);
        b[..t.len].copy_from_slice(t.as_bytes());
        b[t.len] = 0;
        b.as_mut_ptr() as *mut c_char
    }
}

fn xtob(c: u8) -> u8 {
    c - if c.is_ascii_digit() { b'0' } else { b'7' }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_addr(ascii: *const c_char, binary: *mut u8, maxlen: c_int) -> u32 {
    let s = unsafe { crate::util::cbytes(ascii) };
    let mut len = 0u32;
    let mut i = 0usize;
    while i < s.len() && (len as i64) < maxlen as u32 as i64 {
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
        unsafe { *binary.add(len as usize) = (nib << 4) | xtob(c2) };
        len += 1;
    }
    len
}

static NSAP_BUF: crate::util::Spin<[u8; 255 * 2 + 128]> = crate::util::Spin::new([0; 255 * 2 + 128]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_ntoa(binlen: c_int, binary: *const u8, ascii: *mut c_char) -> *mut c_char {
    let mut guard = NSAP_BUF.lock();
    let start: *mut u8 = if ascii.is_null() { guard.as_mut_ptr() } else { ascii as *mut u8 };
    let binlen = binlen.min(255);
    let mut o = 0usize;
    let hexd = |n: u8| n + if n < 10 { b'0' } else { b'7' };
    for i in 0..binlen.max(0) as usize {
        let b = unsafe { *binary.add(i) };
        unsafe {
            *start.add(o) = hexd(b >> 4);
            *start.add(o + 1) = hexd(b & 15);
        }
        o += 2;
        if i % 2 == 0 && (i as c_int + 1) < binlen {
            unsafe { *start.add(o) = b'.' };
            o += 1;
        }
    }
    unsafe { *start.add(o) = 0 };
    start as *mut c_char
}
