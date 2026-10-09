use crate::dns::{self, HErr};
use crate::netdb;
use crate::nss::Status;
use crate::nssdns::{self, HostSink, Outcome, TupleSink};
use crate::strerr;
use crate::types::*;
use crate::util::cbytes;
use crate::wire;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;

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

struct AllocBuf {
    cur: usize,
    end: usize,
    failed: bool,
    dry: bool,
}

impl AllocBuf {
    fn new(buffer: *mut c_char, buflen: usize, dry: bool) -> AllocBuf {
        let cur = buffer as usize;
        AllocBuf { cur, end: cur.wrapping_add(buflen), failed: false, dry }
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

    fn copy_bytes(&mut self, src: &[u8]) -> Option<usize> {
        let a = self.alloc(src.len(), 1)?;
        if !self.dry {
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), a as *mut u8, src.len()) };
        }
        Some(a)
    }

    fn copy_string(&mut self, s: &[u8]) -> Option<usize> {
        let a = self.alloc(s.len() + 1, 1)?;
        if !self.dry {
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), a as *mut u8, s.len());
                *(a as *mut u8).add(s.len()) = 0;
            }
        }
        Some(a)
    }
}

unsafe fn report(o: &Outcome, errnop: *mut c_int, h_errnop: *mut c_int) {
    unsafe {
        if let Some(h) = o.h_errno {
            *h_errnop = h;
        }
        if let Some(e) = o.errno {
            *errnop = e;
        }
    }
}

unsafe fn query_failed(e: &HErr, olderr: c_int, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe { outcome_failed(&nssdns::query_failure(e), olderr, errnop, h_errnop) }
}

unsafe fn outcome_failed(o: &Outcome, olderr: c_int, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        *h_errnop = o.h_errno.unwrap_or(NETDB_SUCCESS);
        match o.errno {
            Some(e) => *errnop = e,
            None => errno::set(olderr),
        }
        code(o.status)
    }
}

struct HostLayout {
    ab: AllocBuf,
    naddr: usize,
    nalias: usize,
    addr_arr: *mut *mut c_char,
    alias_arr: *mut *mut c_char,
}

impl HostSink for HostLayout {
    fn alias(&mut self, name: &[u8]) {
        let p = self.ab.copy_string(name);
        if !self.alias_arr.is_null() {
            unsafe { *self.alias_arr.add(self.nalias) = p.unwrap_or(0) as *mut c_char };
        }
        self.nalias += 1;
    }
    fn addr(&mut self, a: &[u8]) {
        let _ = self.ab.next(4);
        let p = self.ab.copy_bytes(a);
        if !self.addr_arr.is_null() {
            unsafe { *self.addr_arr.add(self.naddr) = p.unwrap_or(0) as *mut c_char };
        }
        self.naddr += 1;
    }
}

unsafe fn host_by_name3(name: &[u8], af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char) -> c_int {
    unsafe {
        let (size, qtype) = match af {
            AF_INET => (4usize, wire::T_A),
            AF_INET6 => (16usize, wire::T_AAAA),
            _ => {
                *h_errnop = NO_DATA;
                *errnop = EAFNOSUPPORT;
                return UNAVAIL;
            }
        };
        (*result).h_addrtype = af;
        (*result).h_length = size as c_int;
        let cfg = crate::resolv::current_config();
        let olderr = errno::get();
        let mut first = [0u8; 4096];
        let mut ans = dns::Answer::growable(&mut first);
        let n = match dns::search_in(&cfg, name, wire::C_IN, qtype, &mut ans) {
            Ok(n) => n,
            Err(e) => return query_failed(&e, olderr, errnop, h_errnop),
        };
        let mut ttl = if ttlp.is_null() { i32::MAX } else { *ttlp };
        let mut lay = HostLayout { ab: AllocBuf::new(buffer, buflen, true), naddr: 0, nalias: 0, addr_arr: core::ptr::null_mut(), alias_arr: core::ptr::null_mut() };
        let o = nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl);
        if !ttlp.is_null() {
            *ttlp = ttl;
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
        let (addr_arr, alias_arr) = (addr_at.unwrap() as *mut *mut c_char, alias_at.unwrap() as *mut *mut c_char);
        let (naddr, nalias) = (lay.naddr, lay.nalias);
        let mut lay = HostLayout { ab: AllocBuf::new(buffer, buflen, false), naddr: 0, nalias: 0, addr_arr, alias_arr };
        let mut ttl2 = i32::MAX;
        nssdns::parse_host(ans.kept(n), qtype, &mut lay, &mut ttl2);
        *addr_arr.add(naddr) = core::ptr::null_mut();
        let hname = *alias_arr.add(nalias - 1);
        *alias_arr.add(nalias - 1) = core::ptr::null_mut();
        (*result).h_addr_list = addr_arr;
        (*result).h_aliases = alias_arr;
        (*result).h_name = hname;
        if !canonp.is_null() {
            *canonp = hname;
        }
        *h_errnop = NETDB_SUCCESS;
        SUCCESS
    }
}

fn check_name(name: &[u8], h_errnop: *mut c_int) -> bool {
    if crate::resolv::hostname_ok(name) {
        return true;
    }
    unsafe { *h_errnop = HOST_NOT_FOUND };
    false
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname3_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32, canonp: *mut *mut c_char) -> c_int {
    unsafe { host_by_name3(cbytes(name), af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname2_r(name: *const c_char, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        if !check_name(cbytes(name), h_errnop) {
            return NOTFOUND;
        }
        host_by_name3(cbytes(name), af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname_r(name: *const c_char, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        if !check_name(cbytes(name), h_errnop) {
            return NOTFOUND;
        }
        host_by_name3(cbytes(name), AF_INET, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut(), core::ptr::null_mut())
    }
}

struct TupleLayout {
    ab: AllocBuf,
    tail: *mut *mut Tuple,
}

impl TupleSink for TupleLayout {
    fn tuple(&mut self, family: c_int, addr: &[u8], canon: Option<&[u8]>) {
        let Some(t) = self.ab.alloc(core::mem::size_of::<Tuple>(), core::mem::align_of::<Tuple>()) else { return };
        let name = match canon {
            Some(c) => self.ab.copy_string(c),
            None => None,
        };
        if self.ab.dry {
            return;
        }
        unsafe {
            let tp = t as *mut Tuple;
            let mut a = [0u32; 4];
            core::ptr::copy_nonoverlapping(addr.as_ptr(), a.as_mut_ptr() as *mut u8, addr.len());
            tp.write(Tuple { next: core::ptr::null_mut(), name: name.unwrap_or(0) as *mut c_char, family, addr: a, scopeid: 0 });
            *self.tail = tp;
            self.tail = &raw mut (*tp).next;
        }
    }
    fn failed(&self) -> bool {
        self.ab.failed
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname4_r(name: *const c_char, pat: *mut *mut Tuple, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    unsafe {
        if !check_name(cbytes(name), h_errnop) {
            return NOTFOUND;
        }
        let cfg = crate::resolv::current_config();
        let olderr = errno::get();
        let (mut f4, mut f6) = ([0u8; 4096], [0u8; 4096]);
        let (mut a4, mut a6) = (dns::Answer::growable(&mut f4), dns::Answer::growable(&mut f6));
        let (n1, n2) = match netdb::query_a_aaaa(&cfg, cbytes(name), &mut a4, &mut a6) {
            Ok(l) => l,
            Err(o) => return outcome_failed(&o, olderr, errnop, h_errnop),
        };
        let mut ttl = if ttlp.is_null() { i32::MAX } else { *ttlp };
        let mut scratch: *mut Tuple = core::ptr::null_mut();
        let mut lay = TupleLayout { ab: AllocBuf::new(buffer, buflen, true), tail: &raw mut scratch };
        let o = nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut lay, &mut ttl);
        if !ttlp.is_null() {
            *ttlp = ttl;
        }
        if lay.ab.failed {
            *errnop = ERANGE;
            *h_errnop = NETDB_INTERNAL;
            return TRYAGAIN;
        }
        let mut lay = TupleLayout { ab: AllocBuf::new(buffer, buflen, false), tail: pat };
        let mut ttl2 = i32::MAX;
        nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut lay, &mut ttl2);
        report(&o, errnop, h_errnop);
        code(o.status)
    }
}

unsafe fn host_by_addr2(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    unsafe {
        let olderr = errno::get();
        let mut ab = AllocBuf::new(buffer, buflen, false);
        let Some(arr) = ab.alloc(16, 8) else {
            *errnop = ERANGE;
            *h_errnop = NETDB_INTERNAL;
            return TRYAGAIN;
        };
        let address_array = arr as *mut *mut c_char;
        let (mut af, mut len, mut uaddr) = (af, len, addr as *const u8);
        if af == AF_INET6 && len == 16 {
            let a16 = core::slice::from_raw_parts(uaddr, 16);
            let mapped = a16[..10] == [0; 10] && a16[10] == 0xff && a16[11] == 0xff;
            let tunnelled = a16[..12] == [0; 12] && a16[12..16] != [0, 0, 0, 1];
            if mapped || tunnelled {
                uaddr = uaddr.add(12);
                af = AF_INET;
                len = 4;
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
        if size > len {
            *errnop = EAFNOSUPPORT;
            *h_errnop = NETDB_INTERNAL;
            return UNAVAIL;
        }
        let cfg = crate::resolv::current_config();
        let a = core::slice::from_raw_parts(uaddr, size as usize);
        let rn = dns::reverse_name(af, a);
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
        let mut ttl = if ttlp.is_null() { i32::MAX } else { *ttlp };
        let mut nm = crate::util::Buf::<{ nssdns::MAXHOST + 1 }>::new();
        let o = nssdns::parse_ptr(ans.kept(n), &mut ttl, &mut nm);
        if !ttlp.is_null() {
            *ttlp = ttl;
        }
        if o.status != Status::Success {
            report(&o, errnop, h_errnop);
            return code(o.status);
        }
        let hname = ab.copy_string(nm.as_bytes());
        (*result).h_name = hname.unwrap_or(0) as *mut c_char;
        (*result).h_addrtype = af;
        (*result).h_length = len as c_int;
        let _ = ab.next(4);
        let p = ab.copy_bytes(core::slice::from_raw_parts(uaddr, len as usize));
        *address_array = p.unwrap_or(0) as *mut c_char;
        *address_array.add(1) = core::ptr::null_mut();
        if ab.failed {
            *errnop = ERANGE;
            *h_errnop = NETDB_INTERNAL;
            return TRYAGAIN;
        }
        (*result).h_addr_list = address_array;
        (*result).h_aliases = address_array.add(1);
        *h_errnop = NETDB_SUCCESS;
        SUCCESS
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr2_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int, ttlp: *mut i32) -> c_int {
    unsafe { host_by_addr2(addr, len, af, result, buffer, buflen, errnop, h_errnop, ttlp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr_r(addr: *const c_void, len: socklen_t, af: c_int, result: *mut hostent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe { host_by_addr2(addr, len, af, result, buffer, buflen, errnop, h_errnop, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getcanonname_r(name: *const c_char, buffer: *mut c_char, buflen: usize, result: *mut *mut c_char, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        let cfg = crate::resolv::current_config();
        let name = cbytes(name);
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
                        Some((t, _)) if t.len < buflen => {
                            core::ptr::copy_nonoverlapping(t.as_bytes().as_ptr(), buffer as *mut u8, t.len);
                            *(buffer as *mut u8).add(t.len) = 0;
                            *result = buffer;
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
}

struct NetLayout {
    next_text: *mut u8,
    table: *mut *mut c_char,
    count: usize,
}

unsafe fn net_answer(pkt: &[u8], by_name: bool, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        const TABLE: usize = 48 * 8;
        let pad = (buffer as usize).wrapping_neg() & 7;
        if buflen < TABLE + pad {
            *errnop = ERANGE;
            *h_errnop = NETDB_INTERNAL;
            return TRYAGAIN;
        }
        let base = (buffer as *mut u8).add(pad);
        let room = buflen - pad - TABLE;
        let mut lay = NetLayout { next_text: base.add(TABLE), table: base as *mut *mut c_char, count: 0 };
        let o = nssdns::parse_net(pkt, room, &mut |n: &[u8]| {
            core::ptr::copy_nonoverlapping(n.as_ptr(), lay.next_text, n.len());
            *lay.next_text.add(n.len()) = 0;
            *lay.table.add(lay.count) = lay.next_text as *mut c_char;
            lay.next_text = lay.next_text.add(n.len() + 1);
            lay.count += 1;
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
        *lay.table.add(lay.count) = core::ptr::null_mut();
        (*result).n_aliases = lay.table;
        (*result).n_addrtype = AF_INET;
        if !by_name {
            (*result).n_name = *lay.table;
            (*result).n_aliases = lay.table.add(1);
            (*result).n_net = 0;
            return SUCCESS;
        }
        for i in 0..lay.count {
            if let Some(net) = nssdns::net_from_name(cbytes(*lay.table.add(i))) {
                (*result).n_net = net;
                return SUCCESS;
            }
        }
        strerr::set_h_errno(TRY_AGAIN);
        TRYAGAIN
    }
}

fn net_query_failed(errno_seen: c_int) -> c_int {
    if errno_seen == ECONNREFUSED || errno_seen == EPFNOSUPPORT || errno_seen == EAFNOSUPPORT { UNAVAIL } else { NOTFOUND }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyname_r(name: *const c_char, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        let cfg = crate::resolv::current_config();
        let mut first = [0u8; 4096];
        let mut ans = dns::Answer::growable(&mut first);
        match dns::search_in(&cfg, cbytes(name), wire::C_IN, wire::T_PTR, &mut ans) {
            Ok(n) => net_answer(ans.kept(n), true, result, buffer, buflen, errnop, h_errnop),
            Err(e) => {
                strerr::set_h_errno(e.h);
                let seen = if e.errno != 0 { e.errno } else { errno::get() };
                *errnop = seen;
                net_query_failed(seen)
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyaddr_r(net: u32, type_: c_int, result: *mut netent, buffer: *mut c_char, buflen: usize, errnop: *mut c_int, h_errnop: *mut c_int) -> c_int {
    unsafe {
        if type_ != AF_INET {
            return UNAVAIL;
        }
        let olderr = errno::get();
        let cfg = crate::resolv::current_config();
        let q = nssdns::net_query_name(net);
        let mut first = [0u8; 4096];
        let mut ans = dns::Answer::growable(&mut first);
        match dns::query_in(&cfg, q.as_bytes(), wire::C_IN, wire::T_PTR, &mut ans) {
            Ok(n) => {
                let st = net_answer(ans.kept(n), false, result, buffer, buflen, errnop, h_errnop);
                if st == SUCCESS {
                    let mut u = net;
                    while u & 0xff == 0 && u != 0 {
                        u >>= 8;
                    }
                    (*result).n_net = u;
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
}
