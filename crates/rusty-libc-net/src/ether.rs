//! netinet/ether.h: Ethernet address text forms and the /etc/ethers lookups.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::nss::{self, Db};
use crate::types::*;
use crate::util::Buf;
use core::ffi::{c_char, c_int};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

/// `s` and a NUL into the C buffer `dst`.
///
/// # Safety
/// `dst` has room for `s.len() + 1` bytes that nothing else uses during the call.
unsafe fn put_cstr(dst: *mut c_char, s: &[u8]) {
    // SAFETY: the caller's contract.
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), s.len() + 1) };
    d[..s.len()].copy_from_slice(s);
    d[s.len()] = 0;
}

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The text rules of glibc's `ether_aton_r` and `ether_line`: six numbers of one or two hex digits
/// separated by `:`; after the last number only a NUL or white space may follow a single digit (anything
/// after two digits is ignored). Returns the address and the index after it.
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

/// `%x:%x:%x:%x:%x:%x` (no zero padding, as glibc).
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

// Per thread (`#[thread_local]`): only this thread's ether_aton / ether_ntoa write them, and C gets raw pointers that stay
// valid until the thread's next call.
#[thread_local]
static ATON_BUF: SyncCell<ether_addr> = SyncCell::new(ether_addr { ether_addr_octet: [0; 6] });
#[thread_local]
static NTOA_BUF: SyncCell<[u8; 18]> = SyncCell::new([0; 18]);

/// # Safety
/// `asc` is a C string; `addr` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton_r(asc: *const c_char, addr: *mut ether_addr) -> *mut ether_addr {
    // SAFETY: `asc` is a C string (the caller's contract).
    match parse_ether(unsafe { ffi::cstr_bytes(asc) }) {
        Some(a) => {
            // SAFETY: `addr` is writable (the caller's contract); a NULL one faults in glibc and is stored to here too.
            unsafe { addr.write(ether_addr { ether_addr_octet: a }) };
            addr
        }
        None => core::ptr::null_mut(),
    }
}

/// # Safety
/// `asc` is a C string. The result is a per-thread buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut ether_addr {
    // SAFETY: `asc` as the caller promised; the buffer is this thread's own and writable.
    unsafe { ether_aton_r(asc, ATON_BUF.as_ptr()) }
}

/// # Safety
/// `buf` has room for 18 bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa_r(addr: *const ether_addr, buf: *mut c_char) -> *mut c_char {
    // SAFETY: `addr` points to a valid address (the caller's contract).
    let t = format_ether(unsafe { &(*addr).ether_addr_octet });
    // SAFETY: `buf` has room for 18 bytes (the caller's contract); the text is at most 17.
    unsafe { put_cstr(buf, t.as_bytes()) };
    buf
}

/// # Safety
/// `addr` is valid. The result is a per-thread buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa(addr: *const ether_addr) -> *mut c_char {
    // SAFETY: `addr` as the caller promised; the 18-byte buffer is this thread's own.
    unsafe { ether_ntoa_r(addr, NTOA_BUF.as_ptr().cast::<c_char>()) }
}

/// One line of /etc/ethers: the address and the host name after it.
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

/// # Safety
/// `line` is a C string; `addr` and `hostname` are writable (hostname: as long as `line`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_line(line: *const c_char, addr: *mut ether_addr, hostname: *mut c_char) -> c_int {
    // SAFETY: `line` is a C string (the caller's contract).
    let s = unsafe { ffi::cstr_bytes(line) };
    match parse_line(s) {
        Some((a, h)) => {
            // SAFETY: `addr` is writable (the caller's contract).
            unsafe { addr.write(ether_addr { ether_addr_octet: a }) };
            // SAFETY: `hostname` has room for as many bytes as `line`, more than the name and its NUL.
            unsafe { put_cstr(hostname, h) };
            0
        }
        None => -1,
    }
}

/// `struct etherent` as the plug-in modules fill it.
#[repr(C)]
struct EtherEnt {
    e_name: *const c_char,
    e_addr: ether_addr,
}

/// glibc's ether_hostton/ether_ntohost loop (nss/ether_hton.c): ask each source of `ethers` that has `func` in turn, as the
/// `[STATUS=ACTION]` lists allow (a `merge` action counts as `continue` here, as there). `files` is the built-in reader
/// `files()`, any other name the plug-in function `_nss_NAME_<func>` that `call` runs; `dns` has none and is skipped.
/// The status of the last source asked is the result (UNAVAIL when none could be asked).
fn ethers_dispatch(func: &[u8], files: &mut dyn FnMut() -> i32, call: &mut dyn FnMut(usize) -> i32) -> i32 {
    use rusty_libc_core::nssmod::{self as m, ACT_CONTINUE, ACT_RETURN};
    let order = m::order(b"ethers");
    let mut status = m::NSS_UNAVAIL;
    for src in &order.e[..order.n] {
        if rusty_libc_core::nssent::is_files(src) {
            status = files();
        } else {
            let f = if src.is(b"dns") { 0 } else { m::function(src.name(), func) };
            if f == 0 {
                if src.action(m::NSS_UNAVAIL) != ACT_CONTINUE {
                    break;
                }
                continue;
            }
            status = call(f);
            if !(-2..=1).contains(&status) {
                status = m::NSS_UNAVAIL;
            }
        }
        if src.action(status) == ACT_RETURN {
            break;
        }
    }
    status
}

/// # Safety
/// `hostname` is a C string; `addr` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_hostton(hostname: *const c_char, addr: *mut ether_addr) -> c_int {
    // SAFETY: `hostname` is a C string (the caller's contract).
    let h = unsafe { ffi::cstr_bytes(hostname) };
    let found = core::cell::Cell::new(None::<[u8; 6]>);
    let status = ethers_dispatch(
        b"gethostton_r",
        &mut || {
            let mut r = match nss::open_db(Db::Ethers) {
                Ok(r) => r,
                Err(e) => {
                    // the files module leaves the reason in errno (ENOENT for a missing file)
                    rusty_libc_core::errno::set(e);
                    return -1;
                }
            };
            while let Some(l) = r.next_entry() {
                if let Some((a, n)) = parse_line(l) {
                    if n == h {
                        found.set(Some(a));
                        return 1;
                    }
                }
            }
            0
        },
        &mut |f| {
            // SAFETY: `f` is the address of the module's `_nss_NAME_gethostton_r`, which has this C signature.
            let f: unsafe extern "C" fn(*const c_char, *mut EtherEnt, *mut c_char, c_int, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
            let mut ent = EtherEnt { e_name: core::ptr::null(), e_addr: ether_addr { ether_addr_octet: [0; 6] } };
            let mut buf = [0u8; 1024];
            let mut e: c_int = 0;
            // SAFETY: a C string, a writable entry, a 1024-byte buffer and an errno slot, all live for the call.
            let st = unsafe { f(hostname, &mut ent, buf.as_mut_ptr().cast(), 1024, &mut e) };
            if st == 1 {
                found.set(Some(ent.e_addr.ether_addr_octet));
            }
            st
        },
    );
    match (status, found.get()) {
        (1, Some(a)) => {
            // SAFETY: `addr` is writable (the caller's contract).
            unsafe { addr.write(ether_addr { ether_addr_octet: a }) };
            0
        }
        _ => -1,
    }
}

/// # Safety
/// `addr` is valid; `hostname` has room for the name (glibc assumes `MAXHOSTNAMELEN`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntohost(hostname: *mut c_char, addr: *const ether_addr) -> c_int {
    // SAFETY: `addr` points to a valid address (the caller's contract).
    let want = unsafe { (*addr).ether_addr_octet };
    let name = core::cell::RefCell::new(None::<([u8; 1024], usize)>);
    let keep = |n: &[u8]| {
        let mut b = [0u8; 1024];
        let l = n.len().min(1023);
        b[..l].copy_from_slice(&n[..l]);
        *name.borrow_mut() = Some((b, l));
    };
    let status = ethers_dispatch(
        b"getntohost_r",
        &mut || {
            let mut r = match nss::open_db(Db::Ethers) {
                Ok(r) => r,
                Err(e) => {
                    // the files module leaves the reason in errno (ENOENT for a missing file)
                    rusty_libc_core::errno::set(e);
                    return -1;
                }
            };
            while let Some(l) = r.next_entry() {
                if let Some((a, n)) = parse_line(l) {
                    if a == want {
                        keep(n);
                        return 1;
                    }
                }
            }
            0
        },
        &mut |f| {
            // SAFETY: `f` is the address of the module's `_nss_NAME_getntohost_r`, which has this C signature.
            let f: unsafe extern "C" fn(*const ether_addr, *mut EtherEnt, *mut c_char, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
            let mut ent = EtherEnt { e_name: core::ptr::null(), e_addr: ether_addr { ether_addr_octet: [0; 6] } };
            let mut buf = [0u8; 1024];
            let mut e: c_int = 0;
            // SAFETY: a valid address, a writable entry, a 1024-byte buffer and an errno slot, all live for the call.
            let st = unsafe { f(addr, &mut ent, buf.as_mut_ptr().cast(), 1024, &mut e) };
            if st == 1 {
                // SAFETY: on success the module left `e_name` NULL or pointing to a C string in `buf`.
                if let Some(n) = unsafe { ffi::cstr(ent.e_name) } {
                    keep(n.to_bytes());
                }
            }
            st
        },
    );
    match (status, name.into_inner()) {
        (1, Some((b, l))) => {
            // SAFETY: `hostname` has room for the name (the caller's contract, glibc's MAXHOSTNAMELEN assumption).
            unsafe { put_cstr(hostname, &b[..l]) };
            0
        }
        _ => -1,
    }
}
