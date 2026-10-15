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

#[repr(C)]
pub struct Tuple {
    pub next: *mut Tuple,
    pub name: *mut c_char,
    pub family: c_int,
    pub addr: [u32; 4],
    pub scopeid: u32,
}

struct CBuf<'a> {
    base: *mut c_char,
    bytes: &'a mut [u8],
}

impl CBuf<'_> {
    unsafe fn new<'a>(buffer: *mut c_char, buflen: usize) -> CBuf<'a> {
        CBuf { base: buffer, bytes: unsafe { ffi::bytes_mut(buffer.cast::<u8>(), buflen) } }
    }
}

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

    fn at(&mut self, a: usize, n: usize) -> &mut [u8] {
        let o = a - self.base as usize;
        &mut self.bytes[o..o + n]
    }

    fn ptr<T>(&self, a: Option<usize>) -> *mut T {
        match a {
            Some(a) => self.base.wrapping_byte_add(a - self.base as usize).cast::<T>(),
            None => core::ptr::null_mut(),
        }
    }

    fn put_ptr<T>(&mut self, a: usize, p: *mut T) {
        let slot = self.at(a, core::mem::size_of::<*mut T>());
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

fn report(o: &Outcome, errnop: &mut c_int, h_errnop: &mut c_int) {
    if let Some(h) = o.h_errno {
        *h_errnop = h;
    }
    if let Some(e) = o.errno {
        *errnop = e;
    }
}

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

struct Nss<'a, T> {
    result: &'a mut T,
    buf: CBuf<'a>,
    errnop: &'a mut c_int,
    h_errnop: &'a mut c_int,
}

unsafe fn nss<'a, T>(result: *mut T, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> Nss<'a, T> {
    let result = unsafe { &mut *result };
    let buf = unsafe { CBuf::new(buffer, buflen) };
    let errnop = unsafe { &mut *errnop };
    let h_errnop = unsafe { &mut *h_errnop };
    Nss { result, buf, errnop, h_errnop }
}

unsafe fn named<'a, T>(name: *const c_char, result: *mut T, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> (&'a [u8], Nss<'a, T>) {
    let name = unsafe { ffi::cstr_bytes(name) };
    (name, unsafe { nss(result, buffer, buflen, errnop, h_errnop) })
}

struct HostLayout<'a> {
    ab: AllocBuf<'a>,
    naddr: usize,
    nalias: usize,
    addr_arr: Option<usize>,
    alias_arr: Option<usize>,
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
    let mut lay = HostLayout { ab: AllocBuf::new(buf, true), naddr: 0, nalias: 0, addr_arr: None, alias_arr: None, last_alias: core::ptr::null_mut() };
    let o = nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl);
    if let Some(t) = ttlp {
        *t = ttl;
    }
    if o.status != Status::Success {
        report(&o, errnop, h_errnop);
        return code(o.status);
    }
    let addr_at = lay.ab.alloc(8 * (lay.naddr + 1), 8);
    let alias_at = lay.ab.alloc(8 * lay.nalias, 8);
    if lay.ab.failed {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    }
    let (addr_arr, alias_arr) = (addr_at.unwrap(), alias_at.unwrap());
    let (naddr, nalias) = (lay.naddr, lay.nalias);
    let mut lay = HostLayout { ab: AllocBuf::new(buf, false), naddr: 0, nalias: 0, addr_arr: Some(addr_arr), alias_arr: Some(alias_arr), last_alias: core::ptr::null_mut() };
    let mut ttl2 = i32::MAX;
    nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl2);
    lay.ab.put_ptr::<c_char>(addr_arr + 8 * naddr, core::ptr::null_mut());
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname3_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char) -> c_int {
    unsafe { gethostbyname3_shell(name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp, false) }
}

unsafe fn gethostbyname3_shell(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char, check: bool) -> c_int {
    let (name, a) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    if check && !check_name(name, a.h_errnop) {
        return NOTFOUND;
    }
    let ttlp = unsafe { ffi::out(ttlp) };
    let canonp = unsafe { ffi::out(canonp) };
    let Nss { result, mut buf, errnop, h_errnop } = a;
    host_by_name3(name, af, result, &mut buf, errnop, h_errnop, ttlp, canonp)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname2_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe { gethostbyname3_shell(name, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut(), true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname_r(name: *const c_char, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe { gethostbyname3_shell(name, AF_INET, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut(), true) }
}

enum Tail<'p> {
    Caller(&'p mut *mut Tuple),
    In(usize),
    None,
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname4_r(name: *const c_char, pat: *mut *mut Tuple, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    let (name, a) = unsafe { named(name, pat, buffer, buflen, errnop, h_errnop) };
    if !check_name(name, a.h_errnop) {
        return NOTFOUND;
    }
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
    let mut lay = TupleLayout { ab: AllocBuf::new(buf, false), tail: Tail::Caller(pat) };
    let mut ttl2 = i32::MAX;
    nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut lay, &mut ttl2);
    report(&o, errnop, h_errnop);
    code(o.status)
}

fn host_by_addr2(addr: &[u8], af: c_int, result: &mut hostent, buf: &mut CBuf<'_>, errnop: &mut c_int, h_errnop: &mut c_int, ttlp: Option<&mut i32>) -> c_int {
    let olderr = errno::get();
    let mut ab = AllocBuf::new(buf, false);
    let Some(arr) = ab.alloc(16, 8) else {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return TRYAGAIN;
    };
    let (mut af, mut uaddr) = (af, addr);
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

unsafe fn gethostbyaddr2_shell(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    let addr = unsafe { ffi::bytes(addr.cast::<u8>(), len as usize) };
    let Nss { result, mut buf, errnop, h_errnop } = unsafe { nss(result, buffer, buflen, errnop, h_errnop) };
    let ttlp = unsafe { ffi::out(ttlp) };
    host_by_addr2(addr, af, result, &mut buf, errnop, h_errnop, ttlp)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr2_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    unsafe { gethostbyaddr2_shell(addr, len, af, result, buffer, buflen, errnop, h_errnop, ttlp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe { gethostbyaddr2_shell(addr, len, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getcanonname_r(name: *const c_char, buffer: *mut c_char, buflen: usize, result: *mut *mut c_char, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    let (name, a) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    canonname(name, a.buf, a.result, a.errnop, a.h_errnop)
}

fn canonname(name: &[u8], buf: CBuf<'_>, result: &mut *mut c_char, errnop: &mut c_int, h_errnop: &mut c_int) -> c_int {
    let cfg = crate::resolv::current_config();
    let mut status = UNAVAIL;
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
    let (table, texts) = buf.bytes[pad..].split_at_mut(TABLE);
    let text_base = buf.base.wrapping_add(pad + TABLE);
    let table_base = buf.base.wrapping_add(pad).cast::<*mut c_char>();
    let mut count = 0usize;
    let mut next_text = 0usize;
    let mut names = [(0usize, 0usize); nssdns::MAX_NET_NAMES];
    let put = |table: &mut [u8], i: usize, p: *mut c_char| {
        let slot = &mut table[8 * i..8 * i + 8];
        unsafe { slot.as_mut_ptr().cast::<*mut c_char>().write_unaligned(p) };
    };
    let o = nssdns::parse_net(pkt, room, &mut |n: &[u8]| {
        texts[next_text..next_text + n.len()].copy_from_slice(n);
        texts[next_text + n.len()] = 0;
        put(table, count, text_base.wrapping_add(next_text));
        names[count] = (next_text, n.len());
        next_text += n.len() + 1;
        count += 1;
    });
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
        result.n_name = if count > 0 { text_base } else { core::ptr::null_mut() };
        result.n_aliases = table_base.wrapping_add(1);
        result.n_net = 0;
        return SUCCESS;
    }
    for &(off, len) in &names[..count] {
        if let Some(net) = nssdns::net_from_name(&texts[off..off + len]) {
            result.n_net = net;
            return SUCCESS;
        }
    }
    strerr::set_h_errno(TRY_AGAIN);
    TRYAGAIN
}

fn net_query_failed(errno_seen: c_int) -> c_int {
    if errno_seen == ECONNREFUSED || errno_seen == EPFNOSUPPORT || errno_seen == EAFNOSUPPORT { UNAVAIL } else { NOTFOUND }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyname_r(name: *const c_char, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    let (name, Nss { result, mut buf, errnop, h_errnop }) = unsafe { named(name, result, buffer, buflen, errnop, h_errnop) };
    let cfg = crate::resolv::current_config();
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    match dns::search_in(&cfg, name, wire::C_IN, wire::T_PTR, &mut ans) {
        Ok(n) => net_answer(ans.kept(n), true, result, &mut buf, errnop, h_errnop),
        Err(e) => {
            strerr::set_h_errno(e.h);
            let seen = if e.errno != 0 { e.errno } else { errno::get() };
            *errnop = seen;
            net_query_failed(seen)
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyaddr_r(net: u32, type_: c_int, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    if type_ != AF_INET {
        return UNAVAIL;
    }
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
                let mut u = net;
                while u & 0xff == 0 && u != 0 {
                    u >>= 8;
                }
                result.n_net = u;
            }
            st
        }
        Err(e) => {
            strerr::set_h_errno(e.h);
            let seen = if e.errno != 0 { e.errno } else { olderr };
            errno::set(olderr);
            net_query_failed(seen)
        }
    }
}
