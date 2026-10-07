use crate::nss::{self, Db};
use crate::types::*;
use crate::util::{Buf, cbytes};
use core::ffi::{c_char, c_int};

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn parse_ether_prefix(s: &[u8]) -> Option<([u8; 6], usize)> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut out = [0u8; 6];
    let mut i = 0usize;
    for cnt in 0..6 {
        let mut number = hexv(at(i))?;
        i += 1;
        let ch = at(i);
        let lower = ch.to_ascii_lowercase();
        let mut ch_now = ch;
        if (cnt < 5 && lower != b':') || (cnt == 5 && lower != 0 && !crate::util::is_space(lower)) {
            i += 1;
            number = (number << 4) | hexv(lower)?;
            ch_now = at(i);
            if cnt < 5 && ch_now != b':' {
                return None;
            }
        }
        out[cnt] = number;
        if ch_now != 0 {
            i += 1;
        }
    }
    Some((out, i))
}

pub fn parse_ether(s: &[u8]) -> Option<[u8; 6]> {
    parse_ether_prefix(s).map(|r| r.0)
}

pub fn format_ether(a: &[u8; 6]) -> Buf<24> {
    let mut b = Buf::<24>::new();
    for (i, x) in a.iter().enumerate() {
        if i > 0 {
            b.push(b':');
        }
        const D: &[u8; 16] = b"0123456789abcdef";
        if *x >= 16 {
            b.push(D[(x >> 4) as usize]);
        }
        b.push(D[(x & 15) as usize]);
    }
    b
}

#[thread_local]
static mut ATON_BUF: ether_addr = ether_addr { ether_addr_octet: [0; 6] };
#[thread_local]
static mut NTOA_BUF: [u8; 18] = [0; 18];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton_r(asc: *const c_char, addr: *mut ether_addr) -> *mut ether_addr {
    match parse_ether(unsafe { cbytes(asc) }) {
        Some(a) => {
            unsafe { (*addr).ether_addr_octet = a };
            addr
        }
        None => core::ptr::null_mut(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut ether_addr {
    unsafe { ether_aton_r(asc, &raw mut ATON_BUF) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa_r(addr: *const ether_addr, buf: *mut c_char) -> *mut c_char {
    let t = format_ether(unsafe { &(*addr).ether_addr_octet });
    unsafe {
        core::ptr::copy_nonoverlapping(t.b.as_ptr(), buf as *mut u8, t.len);
        *buf.add(t.len) = 0;
    }
    buf
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa(addr: *const ether_addr) -> *mut c_char {
    unsafe { ether_ntoa_r(addr, (&raw mut NTOA_BUF) as *mut c_char) }
}

fn parse_line(line: &[u8]) -> Option<([u8; 6], &[u8])> {
    let (a, mut i) = parse_ether_prefix(line)?;
    while i < line.len() && crate::util::is_space(line[i]) {
        i += 1;
    }
    if i >= line.len() || line[i] == b'#' {
        return None;
    }
    let st = i;
    while i < line.len() && !crate::util::is_space(line[i]) && line[i] != b'#' {
        i += 1;
    }
    Some((a, &line[st..i]))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_line(line: *const c_char, addr: *mut ether_addr, hostname: *mut c_char) -> c_int {
    let s = unsafe { cbytes(line) };
    match parse_line(s) {
        Some((a, h)) => unsafe {
            (*addr).ether_addr_octet = a;
            core::ptr::copy_nonoverlapping(h.as_ptr(), hostname as *mut u8, h.len());
            *hostname.add(h.len()) = 0;
            0
        },
        None => -1,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_hostton(hostname: *const c_char, addr: *mut ether_addr) -> c_int {
    let h = unsafe { cbytes(hostname) };
    let Ok(mut r) = nss::open_db(Db::Ethers) else { return -1 };
    while let Some(l) = r.next_entry() {
        if let Some((a, n)) = parse_line(l) {
            if n == h {
                unsafe { (*addr).ether_addr_octet = a };
                return 0;
            }
        }
    }
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntohost(hostname: *mut c_char, addr: *const ether_addr) -> c_int {
    let want = unsafe { (*addr).ether_addr_octet };
    let Ok(mut r) = nss::open_db(Db::Ethers) else { return -1 };
    while let Some(l) = r.next_entry() {
        if let Some((a, n)) = parse_line(l) {
            if a == want {
                unsafe {
                    core::ptr::copy_nonoverlapping(n.as_ptr(), hostname as *mut u8, n.len());
                    *hostname.add(n.len()) = 0;
                }
                return 0;
            }
        }
    }
    -1
}
