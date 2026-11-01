//! The nine functions of the `dns` name service module, exported (GLIBC_PRIVATE) with glibc's signatures:
//! `_nss_dns_gethostbyname3_r`, `..2_r`, `..name_r`, `..4_r`, `_nss_dns_gethostbyaddr2_r`, `..addr_r`,
//! `_nss_dns_getcanonname_r`, `_nss_dns_getnetbyname_r` and `_nss_dns_getnetbyaddr_r`.
//!
//! Thin layers over the parsers in [`crate::nssdns`] and the query code in [`crate::dns`]: they build what the caller's
//! buffer has to hold in the order and with the alignment glibc uses (so that "buffer too small" happens at the same size:
//! TRYAGAIN with errno ERANGE and h_errno NETDB_INTERNAL), and report the status as `enum nss_status` (SUCCESS 1, NOTFOUND 0,
//! UNAVAIL -1, TRYAGAIN -2). The buffer is laid out in two passes over the answer (the first only counts, the second
//! writes), so no heap is needed and nothing is written when the buffer turns out too small.
//!
//! Unsafe (U2): only the C shells, which turn the caller's pointers into references and the buffer into a slice once. The
//! pointers stored into the buffer (and into the result structures) are computed from the caller's own buffer pointer, so
//! they stay valid for whoever reads them after the call; the two typed stores into the slice (a pointer, a tuple) are the
//! only unsafe operations of the layout code.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::dns::{self, HErr};
use crate::netdb;
use crate::nss::Status;
use crate::nssdns::{self, HostSink, Outcome, TupleSink};
use crate::strerr;
use crate::types::*;
use crate::wire;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::{errno, ffi};

const SUCCESS: c_int = 1;
const NOTFOUND: c_int = 0;
const UNAVAIL: c_int = -1;
const TRYAGAIN: c_int = -2;

fn code(s: Status) -> c_int {
    match s {
        Status::Success => SUCCESS,
        Status::NotFound => NOTFOUND,
        Status::Unavail => UNAVAIL,
        Status::TryAgain => TRYAGAIN,
    }
}

const EPFNOSUPPORT: c_int = 96;

/// `struct gaih_addrtuple` (nss/nss.h), the element of the list `_nss_dns_gethostbyname4_r` builds.
#[repr(C)]
pub struct Tuple {
    pub next: *mut Tuple,
    pub name: *mut c_char,
    pub family: c_int,
    pub addr: [u32; 4],
    pub scopeid: u32,
}

/// The caller's buffer: its pointer (the stored pointers are computed from it) and the same bytes as a slice (for writing).
struct CBuf<'a> {
    base: *mut c_char,
    bytes: &'a mut [u8],
}

impl CBuf<'_> {
    /// The buffer at `buffer`, `buflen` bytes.
    ///
    /// # Safety
    /// `buffer` points to `buflen` writable bytes that nothing else uses during the call (the caller's contract).
    unsafe fn new<'a>(buffer: *mut c_char, buflen: usize) -> CBuf<'a> {
        // SAFETY: forwarded contract.
        CBuf { base: buffer, bytes: unsafe { ffi::bytes_mut(buffer.cast::<u8>(), buflen) } }
    }
}

/// glibc's `alloc_buffer`: sequential allocation from the caller's buffer. A request that does not fit makes the whole
/// buffer "failed" for good. With `dry` nothing is written, only the layout is followed. Positions are addresses (the
/// alignment is of the address); the writes go to the slice at `address - base`.
struct AllocBuf<'a> {
    base: *mut c_char,
    bytes: &'a mut [u8],
    cur: usize,
    end: usize,
    failed: bool,
    dry: bool,
}

impl<'a> AllocBuf<'a> {
    fn new(buf: &'a mut CBuf<'_>, dry: bool) -> AllocBuf<'a> {
        let cur = buf.base as usize;
        AllocBuf { base: buf.base, end: cur.wrapping_add(buf.bytes.len()), bytes: &mut *buf.bytes, cur, failed: false, dry }
    }

    /// Reserve `size` bytes at `align`; the address, or `None` (and failed) when it does not fit.
    fn alloc(&mut self, size: usize, align: usize) -> Option<usize> {
        if self.failed {
            return None;
        }
        let a = (self.cur + align - 1) & !(align - 1);
        if a < self.cur || a > self.end || size > self.end - a {
            self.failed = true;
            return None;
        }
        self.cur = a + size;
        Some(a)
    }

    /// Align the position (nothing is reserved); the address.
    fn next(&mut self, align: usize) -> Option<usize> {
        if self.failed {
            return None;
        }
        let a = (self.cur + align - 1) & !(align - 1);
        if a < self.cur || a > self.end {
            self.failed = true;
            return None;
        }
        self.cur = a;
        Some(a)
    }

    /// The bytes at address `a` (reserved by `alloc`).
    fn at(&mut self, a: usize, n: usize) -> &mut [u8] {
        let o = a - self.base as usize;
        &mut self.bytes[o..o + n]
    }

    /// The pointer C gets for address `a` (NULL for None), computed from the caller's buffer pointer.
    fn ptr<T>(&self, a: Option<usize>) -> *mut T {
        match a {
            Some(a) => self.base.wrapping_byte_add(a - self.base as usize).cast::<T>(),
            None => core::ptr::null_mut(),
        }
    }

    /// Store the pointer `p` at address `a` (a slot reserved by `alloc`).
    fn put_ptr<T>(&mut self, a: usize, p: *mut T) {
        let slot = self.at(a, core::mem::size_of::<*mut T>());
        // SAFETY: `slot` is a borrowed part of the buffer exactly one pointer long; the store is unaligned-safe.
        unsafe { slot.as_mut_ptr().cast::<*mut T>().write_unaligned(p) };
    }

    fn copy_bytes(&mut self, src: &[u8]) -> Option<usize> {
        let a = self.alloc(src.len(), 1)?;
        if !self.dry {
            self.at(a, src.len()).copy_from_slice(src);
        }
        Some(a)
    }

    fn copy_string(&mut self, s: &[u8]) -> Option<usize> {
        let a = self.alloc(s.len() + 1, 1)?;
        if !self.dry {
            let d = self.at(a, s.len() + 1);
            d[..s.len()].copy_from_slice(s);
            d[s.len()] = 0;
        }
        Some(a)
    }
}

/// Apply what a parser reports: `h_errno` through the caller's pointer, `errno` through the caller's pointer.
fn report(o: &Outcome, errnop: &mut c_int, h_errnop: &mut c_int) {
    if let Some(h) = o.h_errno {
        *h_errnop = h;
    }
    if let Some(e) = o.errno {
        *errnop = e;
    }
}

/// The failure of a query (the `n < 0` case): status and `h_errno` as [`nssdns::query_failure`], errno EAGAIN for TRY_AGAIN,
/// otherwise the thread's errno as it was (`olderr`).
fn query_failed(e: &HErr, olderr: c_int, errnop: &mut c_int, h_errnop: &mut c_int) -> c_int {
    outcome_failed(&nssdns::query_failure(e), olderr, errnop, h_errnop)
}

fn outcome_failed(o: &Outcome, olderr: c_int, errnop: &mut c_int, h_errnop: &mut c_int) -> c_int {
    *h_errnop = o.h_errno.unwrap_or(NETDB_SUCCESS);
    match o.errno {
        Some(e) => *errnop = e,
        None => errno::set(olderr),
    }
    code(o.status)
}

/// What every function of the module converts: the result (a structure, or the caller's list head or string pointer), the
/// buffer, `errnop` and `h_errnop`.
struct Nss<'a, T> {
    result: &'a mut T,
    buf: CBuf<'a>,
    errnop: &'a mut c_int,
    h_errnop: &'a mut c_int,
}

/// The conversions of [`Nss`].
///
/// # Safety
/// The NSS contract: `result`, `errnop` and `h_errnop` are valid, distinct pointers; `buffer` points to `buflen` writable
/// bytes; none of them is used by anyone else during the call.
unsafe fn nss<'a, T>(result: *mut T, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> Nss<'a, T> {
    // SAFETY: valid and not otherwise used (the caller's contract).
    let result = unsafe { &mut *result };
    // SAFETY: as above.
    let buf = unsafe { CBuf::new(buffer, buflen) };
    // SAFETY: as above; distinct from `h_errnop`.
    let errnop = unsafe { &mut *errnop };
    // SAFETY: as above.
    let h_errnop = unsafe { &mut *h_errnop };
    Nss { result, buf, errnop, h_errnop }
}

/// [`nss`] for the functions that take a name first.
///
/// # Safety
/// As [`nss`], and `name` is a C string.
unsafe fn named<'a, T>(name: *const c_char, result: *mut T, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> (&'a [u8], Nss<'a, T>) {
    // SAFETY: a C string (the caller's contract).
    let name = unsafe { ffi::cstr_bytes(name) };
    // SAFETY: forwarded contract.
    (name, unsafe { nss(result, buffer, buflen, errnop, h_errnop) })
}

// ---------------------------------------------------------------- hosts by name

/// Lays a host answer out in the caller's buffer: alias strings and addresses in answer order, then the address pointer
/// array, then the alias pointer array.
struct HostLayout<'a> {
    ab: AllocBuf<'a>,
    naddr: usize,
    nalias: usize,
    /// Known from the first pass; None in the first pass.
    addr_arr: Option<usize>,
    alias_arr: Option<usize>,
    /// The pointer stored for the last alias (the host name).
    last_alias: *mut c_char,
}

impl HostSink for HostLayout<'_> {
    fn alias(&mut self, name: &[u8]) {
        let a = self.ab.copy_string(name);
        let p = self.ab.ptr::<c_char>(a);
        if let Some(arr) = self.alias_arr {
            self.ab.put_ptr(arr + 8 * self.nalias, p);
        }
        self.last_alias = p;
        self.nalias += 1;
    }
    fn addr(&mut self, a: &[u8]) {
        // alignment 4, in case programs expect at least that of an address
        let _ = self.ab.next(4);
        let at = self.ab.copy_bytes(a);
        let p = self.ab.ptr::<c_char>(at);
        if let Some(arr) = self.addr_arr {
            self.ab.put_ptr(arr + 8 * self.naddr, p);
        }
        self.naddr += 1;
    }
}

fn host_by_name3(name: &[u8], af: c_int, result: &mut hostent, buf: &mut CBuf<'_>, errnop: &mut c_int, h_errnop: &mut c_int, ttlp: Option<&mut i32>, canonp: Option<&mut *mut c_char>) -> c_int {
    let (size, qtype) = match af {
        AF_INET => (4usize, wire::T_A),
        AF_INET6 => (16usize, wire::T_AAAA),
        _ => {
            *h_errnop = NO_DATA;
            *errnop = EAFNOSUPPORT;
            return UNAVAIL;
        }
    };
    result.h_addrtype = af;
    result.h_length = size as c_int;
    let cfg = crate::resolv::current_config();
    let olderr = errno::get();
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    let n = match dns::search_in(&cfg, name, wire::C_IN, qtype, &mut ans) {
        Ok(n) => n,
        Err(e) => return query_failed(&e, olderr, errnop, h_errnop),
    };
    let mut ttl = ttlp.as_deref().copied().unwrap_or(i32::MAX);
    // first pass: the layout, without writing
    let mut lay = HostLayout { ab: AllocBuf::new(buf, true), naddr: 0, nalias: 0, addr_arr: None, alias_arr: None, last_alias: core::ptr::null_mut() };
    let o = nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl);
    if let Some(t) = ttlp {
        *t = ttl;
    }
    if o.status != Status::Success {
        report(&o, errnop, h_errnop);
        return code(o.status);
    }
    // the pointer arrays follow the strings and addresses; the alias array has room for the official name too (it takes
    // the place of the terminating NULL)
    let addr_at = lay.ab.alloc(8 * (lay.naddr + 1), 8);
    let alias_at = lay.ab.alloc(8 * lay.nalias, 8);
    if lay.ab.failed {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    let (addr_arr, alias_arr) = (addr_at.unwrap(), alias_at.unwrap());
    // second pass: write
    let (naddr, nalias) = (lay.naddr, lay.nalias);
    let mut lay = HostLayout { ab: AllocBuf::new(buf, false), naddr: 0, nalias: 0, addr_arr: Some(addr_arr), alias_arr: Some(alias_arr), last_alias: core::ptr::null_mut() };
    let mut ttl2 = i32::MAX;
    nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl2);
    lay.ab.put_ptr::<c_char>(addr_arr + 8 * naddr, core::ptr::null_mut());
    // the last alias is the host name, and also the canonical name
    let hname = lay.last_alias;
    lay.ab.put_ptr::<c_char>(alias_arr + 8 * (nalias - 1), core::ptr::null_mut());
    result.h_addr_list = lay.ab.ptr(Some(addr_arr));
    result.h_aliases = lay.ab.ptr(Some(alias_arr));
    result.h_name = hname;
    if let Some(c) = canonp {
        *c = hname;
    }
    *h_errnop = NETDB_SUCCESS;
    SUCCESS
}

fn check_name(name: &[u8], h_errnop: &mut c_int) -> bool {
    if crate::resolv::hostname_ok(name) {
        return true;
    }
    *h_errnop = HOST_NOT_FOUND;
    false
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyname3_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname3_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char) -> c_int {
    // SAFETY: the NSS contract: `name` is a C string, `result` and the error pointers are valid, `buffer` has `buflen` bytes,
    // `ttlp` and `canonp` are NULL or valid.
    unsafe { gethostbyname3_shell(name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp, false) }
}

/// The shell of the three gethostbyname*_r functions (`check` = the host-name check of the 2 and 1 forms).
///
/// # Safety
/// glibc's contract for `_nss_dns_gethostbyname3_r`.
unsafe fn gethostbyname3_shell(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char, check: bool) -> c_int {
    // SAFETY: the caller's contract.
    let (name, a) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    if check && !check_name(name, a.h_errnop) {
        return NOTFOUND;
    }
    // SAFETY: NULL or valid (the caller's contract).
    let ttlp = unsafe { ffi::out(ttlp) };
    // SAFETY: NULL or valid (the caller's contract).
    let canonp = unsafe { ffi::out(canonp) };
    let Nss { result, mut buf, errnop, h_errnop } = a;
    host_by_name3(name, af, result, &mut buf, errnop, h_errnop, ttlp, canonp)
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyname2_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname2_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // SAFETY: the NSS contract, as for gethostbyname3_r without ttlp and canonp.
    unsafe { gethostbyname3_shell(name, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut(), true) }
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname_r(name: *const c_char, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // SAFETY: the NSS contract, as for gethostbyname3_r without ttlp and canonp.
    unsafe { gethostbyname3_shell(name, AF_INET, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut(), true) }
}

// ---------------------------------------------------------------- hosts by name for getaddrinfo

/// Where the pointer to the next tuple goes.
enum Tail<'p> {
    /// The caller's `*pat`.
    Caller(&'p mut *mut Tuple),
    /// The `next` field of the tuple at this address in the buffer.
    In(usize),
    /// Nowhere (the first, layout-only pass).
    None,
}

/// Lays the address tuples out in the caller's buffer and links them from `*head`.
struct TupleLayout<'a, 'p> {
    ab: AllocBuf<'a>,
    tail: Tail<'p>,
}

impl TupleSink for TupleLayout<'_, '_> {
    fn tuple(&mut self, family: c_int, addr: &[u8], canon: Option<&[u8]>) {
        let Some(t) = self.ab.alloc(core::mem::size_of::<Tuple>(), core::mem::align_of::<Tuple>()) else { return };
        let name = match canon {
            Some(c) => self.ab.copy_string(c),
            None => None,
        };
        if self.ab.dry {
            return;
        }
        let mut b = [0u8; 16];
        b[..addr.len()].copy_from_slice(addr);
        let a = core::array::from_fn(|i| u32::from_ne_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]));
        let tuple = Tuple { next: core::ptr::null_mut(), name: self.ab.ptr(name), family, addr: a, scopeid: 0 };
        let slot = self.ab.at(t, core::mem::size_of::<Tuple>());
        // SAFETY: `slot` is a borrowed part of the buffer exactly one Tuple long; the store is unaligned-safe.
        unsafe { slot.as_mut_ptr().cast::<Tuple>().write_unaligned(tuple) };
        let tp = self.ab.ptr::<Tuple>(Some(t));
        match core::mem::replace(&mut self.tail, Tail::In(t + core::mem::offset_of!(Tuple, next))) {
            Tail::Caller(p) => *p = tp,
            Tail::In(at) => self.ab.put_ptr(at, tp),
            Tail::None => {}
        }
    }
    fn failed(&self) -> bool {
        self.ab.failed
    }
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyname4_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname4_r(name: *const c_char, pat: *mut *mut Tuple, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    // SAFETY: the NSS contract (`pat` is the result pointer).
    let (name, a) = unsafe { named(name, pat, buffer, buflen, errnop, h_errnop) };
    if !check_name(name, a.h_errnop) {
        return NOTFOUND;
    }
    // SAFETY: NULL or valid (the caller's contract).
    let ttlp = unsafe { ffi::out(ttlp) };
    let Nss { result, mut buf, errnop, h_errnop } = a;
    host_by_name4(name, result, &mut buf, errnop, h_errnop, ttlp)
}

fn host_by_name4(name: &[u8], pat: &mut *mut Tuple, buf: &mut CBuf<'_>, errnop: &mut c_int, h_errnop: &mut c_int, ttlp: Option<&mut i32>) -> c_int {
    let cfg = crate::resolv::current_config();
    let olderr = errno::get();
    let (mut f4, mut f6) = ([0u8; 4096], [0u8; 4096]);
    let (mut a4, mut a6) = (dns::Answer::growable(&mut f4), dns::Answer::growable(&mut f6));
    let (n1, n2) = match netdb::query_a_aaaa(&cfg, name, &mut a4, &mut a6) {
        Ok(l) => l,
        Err(o) => return outcome_failed(&o, olderr, errnop, h_errnop),
    };
    let mut ttl = ttlp.as_deref().copied().unwrap_or(i32::MAX);
    // first pass: layout only (nothing is linked)
    let mut lay = TupleLayout { ab: AllocBuf::new(buf, true), tail: Tail::None };
    let o = nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut lay, &mut ttl);
    if let Some(t) = ttlp {
        *t = ttl;
    }
    if lay.ab.failed {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    // second pass: write and link
    let mut lay = TupleLayout { ab: AllocBuf::new(buf, false), tail: Tail::Caller(pat) };
    let mut ttl2 = i32::MAX;
    nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut lay, &mut ttl2);
    report(&o, errnop, h_errnop);
    code(o.status)
}

// ---------------------------------------------------------------- hosts by address

fn host_by_addr2(addr: &[u8], af: c_int, result: &mut hostent, buf: &mut CBuf<'_>, errnop: &mut c_int, h_errnop: &mut c_int, ttlp: Option<&mut i32>) -> c_int {
    let olderr = errno::get();
    // the pointer pair comes first, to benefit from the alignment of the buffer
    let mut ab = AllocBuf::new(buf, false);
    let Some(arr) = ab.alloc(16, 8) else {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    };
    let (mut af, mut uaddr) = (af, addr);
    // v4-mapped, and v4-compatible addresses other than ::1 (and :: itself unmapped to 0.0.0.0), are looked up as IPv4
    if af == AF_INET6 && uaddr.len() == 16 {
        let a16 = uaddr;
        let mapped = a16[..10] == [0; 10] && a16[10] == 0xff && a16[11] == 0xff;
        let tunnelled = a16[..12] == [0; 12] && a16[12..16] != [0, 0, 0, 1];
        if mapped || tunnelled {
            uaddr = &uaddr[12..];
            af = AF_INET;
        }
    }
    let size = match af {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => {
            *errnop = EAFNOSUPPORT;
            *h_errnop = NETDB_INTERNAL;
            return UNAVAIL;
        }
    };
    if size > uaddr.len() {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NETDB_INTERNAL;
        return UNAVAIL;
    }
    let cfg = crate::resolv::current_config();
    let rn = dns::reverse_name(af, &uaddr[..size]);
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    let n = match dns::query_in(&cfg, rn.as_bytes(), wire::C_IN, wire::T_PTR, &mut ans) {
        Ok(n) => n,
        Err(e) => {
            *h_errnop = e.h;
            errno::set(olderr);
            // (the errno was put back first, so only an earlier ECONNREFUSED makes this UNAVAIL)
            return if errno::get() == ECONNREFUSED { UNAVAIL } else { NOTFOUND };
        }
    };
    let mut ttl = ttlp.as_deref().copied().unwrap_or(i32::MAX);
    let mut nm = crate::util::Buf::<{ nssdns::MAXHOST + 1 }>::new();
    let o = nssdns::parse_ptr(ans.kept(n), &mut ttl, &mut nm);
    if let Some(t) = ttlp {
        *t = ttl;
    }
    if o.status != Status::Success {
        report(&o, errnop, h_errnop);
        return code(o.status);
    }
    let hname = ab.copy_string(nm.as_bytes());
    result.h_name = ab.ptr(hname);
    result.h_addrtype = af;
    result.h_length = uaddr.len() as c_int;
    let _ = ab.next(4);
    let p = ab.copy_bytes(uaddr);
    let pp = ab.ptr::<c_char>(p);
    ab.put_ptr(arr, pp);
    ab.put_ptr::<c_char>(arr + 8, core::ptr::null_mut());
    if ab.failed {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    result.h_addr_list = ab.ptr(Some(arr));
    result.h_aliases = ab.ptr(Some(arr + 8));
    *h_errnop = NETDB_SUCCESS;
    SUCCESS
}

/// The shell of the two gethostbyaddr*_r functions.
///
/// # Safety
/// glibc's contract for `_nss_dns_gethostbyaddr2_r` (`addr` has `len` bytes; `ttlp` NULL or valid).
unsafe fn gethostbyaddr2_shell(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    // SAFETY: `addr` points to `len` bytes (the caller's contract).
    let addr = unsafe { ffi::bytes(addr.cast::<u8>(), len as usize) };
    // SAFETY: the NSS contract.
    let Nss { result, mut buf, errnop, h_errnop } = unsafe { nss(result, buffer, buflen, errnop, h_errnop) };
    // SAFETY: NULL or valid (the caller's contract).
    let ttlp = unsafe { ffi::out(ttlp) };
    host_by_addr2(addr, af, result, &mut buf, errnop, h_errnop, ttlp)
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyaddr2_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr2_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { gethostbyaddr2_shell(addr, len, af, result, buffer, buflen, errnop, h_errnop, ttlp) }
}

/// # Safety
/// glibc's contract for `_nss_dns_gethostbyaddr_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // SAFETY: forwarded contract, without ttlp.
    unsafe { gethostbyaddr2_shell(addr, len, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut()) }
}

// ---------------------------------------------------------------- canonical name

/// # Safety
/// glibc's contract for `_nss_dns_getcanonname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getcanonname_r(name: *const c_char, buffer: *mut c_char, buflen: usize, result: *mut *mut c_char, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // SAFETY: the NSS contract.
    let (name, a) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    canonname(name, a.buf, a.result, a.errnop, a.h_errnop)
}

fn canonname(name: &[u8], buf: CBuf<'_>, result: &mut *mut c_char, errnop: &mut c_int, h_errnop: &mut c_int) -> c_int {
    let cfg = crate::resolv::current_config();
    let mut status = UNAVAIL;
    // h_errno as the resolver leaves it: the failure of the last query, else what it was
    let mut h = strerr::h_errno();
    for qtype in [wire::T_A, wire::T_AAAA] {
        let mut first = [0u8; 4096];
        let mut ans = dns::Answer::growable(&mut first);
        let n = match dns::query_in(&cfg, name, wire::C_IN, qtype, &mut ans) {
            Ok(n) => n,
            Err(e) => {
                h = e.h;
                continue;
            }
        };
        match nssdns::canon_walk(ans.kept(n), qtype) {
            nssdns::Canon::Next => continue,
            nssdns::Canon::Unavail => {
                status = UNAVAIL;
                break;
            }
            nssdns::Canon::Found(at) => {
                let text = wire::name_expand::<{ dns::MAXDNAME }>(ans.kept(n), at);
                match text {
                    Some((t, _)) if t.len < buf.bytes.len() => {
                        buf.bytes[..t.len].copy_from_slice(t.as_bytes());
                        buf.bytes[t.len] = 0;
                        *result = buf.base;
                        status = SUCCESS;
                    }
                    Some(_) => {
                        // the buffer is too small
                        *errnop = ERANGE;
                        status = TRYAGAIN;
                        h = NETDB_INTERNAL;
                    }
                    None => {
                        status = UNAVAIL;
                    }
                }
                break;
            }
        }
    }
    *h_errnop = h;
    status
}

// ---------------------------------------------------------------- networks

/// Lays a network answer out as glibc does: a table of 48 name pointers at the start of the (8-aligned) buffer, then the
/// names, one after the other.
fn net_answer(pkt: &[u8], by_name: bool, result: &mut netent, buf: &mut CBuf<'_>, errnop: &mut c_int, h_errnop: &mut c_int) -> c_int {
    const TABLE: usize = 48 * 8;
    let buflen = buf.bytes.len();
    let pad = (buf.base as usize).wrapping_neg() & 7;
    if buflen < TABLE + pad {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    let room = buflen - pad - TABLE;
    // the table and the names, as separate borrows of the buffer; pointers for C are computed from the buffer's pointer
    let (table, texts) = buf.bytes[pad..].split_at_mut(TABLE);
    let text_base = buf.base.wrapping_add(pad + TABLE);
    let table_base = buf.base.wrapping_add(pad).cast::<*mut c_char>();
    let mut count = 0usize;
    let mut next_text = 0usize;
    // the (offset, length) of each name, to read them back below
    let mut names = [(0usize, 0usize); nssdns::MAX_NET_NAMES];
    let put = |table: &mut [u8], i: usize, p: *mut c_char| {
        let slot = &mut table[8 * i..8 * i + 8];
        // SAFETY: `slot` is a borrowed part of the buffer exactly one pointer long; the store is unaligned-safe.
        unsafe { slot.as_mut_ptr().cast::<*mut c_char>().write_unaligned(p) };
    };
    let o = nssdns::parse_net(pkt, room, &mut |n: &[u8]| {
        // parse_net keeps to `room` and to MAX_NET_NAMES names (fewer than the 48 slots)
        texts[next_text..next_text + n.len()].copy_from_slice(n);
        texts[next_text + n.len()] = 0;
        put(table, count, text_base.wrapping_add(next_text));
        names[count] = (next_text, n.len());
        next_text += n.len() + 1;
        count += 1;
    });
    // these parsers set the thread's h_errno, not the caller's pointer, except for the buffer protocol
    if o.status == Status::TryAgain && o.errno == Some(ERANGE) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    if let Some(h) = o.h_errno {
        strerr::set_h_errno(h);
    }
    if o.status != Status::Success {
        return code(o.status);
    }
    put(table, count, core::ptr::null_mut());
    result.n_aliases = table_base;
    result.n_addrtype = AF_INET;
    if !by_name {
        // by address: the first name is the network's name, the rest are aliases
        result.n_name = if count > 0 { text_base } else { core::ptr::null_mut() };
        result.n_aliases = table_base.wrapping_add(1);
        result.n_net = 0;
        return SUCCESS;
    }
    // by name: the network number is written in one of the names
    for &(off, len) in &names[..count] {
        if let Some(net) = nssdns::net_from_name(&texts[off..off + len]) {
            result.n_net = net;
            return SUCCESS;
        }
    }
    strerr::set_h_errno(TRY_AGAIN);
    TRYAGAIN
}

/// How the lookups by network map a failed query: nothing listening and unsupported families are UNAVAIL, the rest NOTFOUND.
fn net_query_failed(errno_seen: c_int) -> c_int {
    if errno_seen == ECONNREFUSED || errno_seen == EPFNOSUPPORT || errno_seen == EAFNOSUPPORT { UNAVAIL } else { NOTFOUND }
}

/// # Safety
/// glibc's contract for `_nss_dns_getnetbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyname_r(name: *const c_char, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // SAFETY: the NSS contract.
    let (name, Nss { result, mut buf, errnop, h_errnop }) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    let cfg = crate::resolv::current_config();
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    match dns::search_in(&cfg, name, wire::C_IN, wire::T_PTR, &mut ans) {
        Ok(n) => net_answer(ans.kept(n), true, result, &mut buf, errnop, h_errnop),
        Err(e) => {
            // nothing found: h_errno as the search leaves it (glibc's __res_context_search sets it), and the errno it left (the
            // old one when the servers answered)
            strerr::set_h_errno(e.h);
            let seen = if e.errno != 0 { e.errno } else { errno::get() };
            *errnop = seen;
            net_query_failed(seen)
        }
    }
}

/// # Safety
/// glibc's contract for `_nss_dns_getnetbyaddr_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyaddr_r(net: u32, type_: c_int, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    // no address lookup for IPv6 networks
    if type_ != AF_INET {
        return UNAVAIL;
    }
    // SAFETY: the NSS contract.
    let Nss { result, mut buf, errnop, h_errnop } = unsafe { nss(result, buffer, buflen, errnop, h_errnop) };
    let olderr = errno::get();
    let cfg = crate::resolv::current_config();
    let q = nssdns::net_query_name(net);
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    match dns::query_in(&cfg, q.as_bytes(), wire::C_IN, wire::T_PTR, &mut ans) {
        Ok(n) => {
            let st = net_answer(ans.kept(n), false, result, &mut buf, errnop, h_errnop);
            if st == SUCCESS {
                // the network number without its trailing zero bytes
                let mut u = net;
                while u & 0xff == 0 && u != 0 {
                    u >>= 8;
                }
                result.n_net = u;
            }
            st
        }
        Err(e) => {
            // h_errno as glibc's __res_context_query leaves it
            strerr::set_h_errno(e.h);
            let seen = if e.errno != 0 { e.errno } else { olderr };
            errno::set(olderr);
            net_query_failed(seen)
        }
    }
}
