use crate::dns::{self, Addr, HostData};
use crate::inet;
use crate::nss::{self, Action, Db, Entry, LineReader, Source, Status};
use crate::strerr::set_h_errno;
use crate::types::*;
use crate::util::{Buf, Spin, align_up, cbytes, eq_nocase};
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;

struct Fill {
    base: *mut u8,
    len: usize,
    off: usize,
}

impl Fill {
    unsafe fn new(buf: *mut c_char, buflen: usize) -> Fill {
        let pad = (buf as usize).wrapping_neg() & 7;
        if buflen < pad {
            return Fill { base: buf as *mut u8, len: 0, off: 0 };
        }
        Fill { base: unsafe { (buf as *mut u8).add(pad) }, len: buflen - pad, off: 0 }
    }
    fn ptr_array(&mut self, n: usize) -> Option<*mut *mut c_char> {
        self.off = align_up(self.off, 8);
        let need = n * 8;
        if self.off + need > self.len {
            return None;
        }
        let p = unsafe { self.base.add(self.off) } as *mut *mut c_char;
        self.off += need;
        Some(p)
    }
    fn bytes(&mut self, b: &[u8]) -> Option<*mut u8> {
        if self.off + b.len() > self.len {
            return None;
        }
        let p = unsafe { self.base.add(self.off) };
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len()) };
        self.off += b.len();
        Some(p)
    }
    fn string(&mut self, s: &[u8]) -> Option<*mut c_char> {
        if self.off + s.len() + 1 > self.len {
            return None;
        }
        let p = unsafe { self.base.add(self.off) };
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
            *p.add(s.len()) = 0;
        }
        self.off += s.len() + 1;
        Some(p as *mut c_char)
    }
    fn word_list(&mut self, rest: &[u8]) -> Option<*mut *mut c_char> {
        let n = nss::words(rest).count();
        let arr = self.ptr_array(n + 1)?;
        for (i, w) in nss::words(rest).enumerate() {
            unsafe { *arr.add(i) = self.string(w)? };
        }
        unsafe { *arr.add(n) = core::ptr::null_mut() };
        Some(arr)
    }
}

fn fill_servent(res: &mut servent, buf: *mut c_char, buflen: usize, l: &nss::ServLine) -> Result<(), i32> {
    let mut f = unsafe { Fill::new(buf, buflen) };
    let r = (|| {
        res.s_aliases = f.word_list(l.rest)?;
        res.s_name = f.string(l.name)?;
        res.s_proto = f.string(l.proto)?;
        res.s_port = l.port.to_be() as c_int;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_protoent(res: &mut protoent, buf: *mut c_char, buflen: usize, l: &nss::NumLine) -> Result<(), i32> {
    let mut f = unsafe { Fill::new(buf, buflen) };
    let r = (|| {
        res.p_aliases = f.word_list(l.rest)?;
        res.p_name = f.string(l.name)?;
        res.p_proto = l.num;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_rpcent(res: &mut rpcent, buf: *mut c_char, buflen: usize, l: &nss::NumLine) -> Result<(), i32> {
    let mut f = unsafe { Fill::new(buf, buflen) };
    let r = (|| {
        res.r_aliases = f.word_list(l.rest)?;
        res.r_name = f.string(l.name)?;
        res.r_number = l.num;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_netent(res: &mut netent, buf: *mut c_char, buflen: usize, l: &nss::NetLine) -> Result<(), i32> {
    let mut f = unsafe { Fill::new(buf, buflen) };
    let r = (|| {
        res.n_aliases = f.word_list(l.rest)?;
        res.n_name = f.string(l.name)?;
        res.n_addrtype = AF_INET;
        res.n_net = l.net;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_hostent(res: &mut hostent, buf: *mut c_char, buflen: usize, name: &[u8], aliases: &[u8], family: c_int, addrs: &[Addr]) -> Result<(), i32> {
    let mut f = unsafe { Fill::new(buf, buflen) };
    let alen = if family == AF_INET { 4 } else { 16 };
    let r = (|| {
        let na = aliases.split(|&c| c == 0 || c == b' ').filter(|w| !w.is_empty()).count();
        let alist = f.ptr_array(na + 1)?;
        let addr_list = f.ptr_array(addrs.len() + 1)?;
        for (i, a) in addrs.iter().enumerate() {
            let p = f.bytes(&a.bytes[..alen])?;
            unsafe { *addr_list.add(i) = p as *mut c_char };
        }
        unsafe { *addr_list.add(addrs.len()) = core::ptr::null_mut() };
        res.h_name = f.string(name)?;
        for (i, w) in aliases.split(|&c| c == 0 || c == b' ').filter(|w| !w.is_empty()).enumerate() {
            unsafe { *alist.add(i) = f.string(w)? };
        }
        unsafe { *alist.add(na) = core::ptr::null_mut() };
        res.h_aliases = alist;
        res.h_addr_list = addr_list;
        res.h_addrtype = family;
        res.h_length = alen as c_int;
        Some(())
    })();
    r.ok_or(ERANGE)
}

#[derive(Clone, Copy)]
struct Fit {
    base: usize,
    addr: usize,
    len: usize,
}

impl Fit {
    fn new(base: usize, buf: *mut c_char, len: usize) -> Fit {
        Fit { base, addr: buf as usize, len }
    }
    fn pre_ok(&self) -> bool {
        self.len >= self.base + 3
    }
    fn read_ok(&self, rawlen: usize) -> bool {
        rawlen + 2 <= self.len - self.base
    }
    fn list_ok(&self, rawlen: usize, k: usize) -> bool {
        let start = (self.addr + self.base + rawlen + 1 + 7) & !7;
        start - self.addr + 8 * (k + 2) <= self.len
    }
}

enum Scan {
    Unavail(i32),
    NotFound,
    Hit(Result<(), i32>),
}

fn scan(db: Db, fit: Fit, mut f: impl FnMut(&[u8], &mut usize) -> Option<Result<(), i32>>) -> Scan {
    let mut r = match nss::open_db(db) {
        Ok(r) => r,
        Err(e) => return Scan::Unavail(e),
    };
    if !fit.pre_ok() {
        return Scan::Hit(Err(ERANGE));
    }
    while let Some((line, rawlen)) = r.next_raw() {
        let line = unsafe { core::slice::from_raw_parts(line.as_ptr(), line.len()) };
        if !fit.read_ok(rawlen) {
            return Scan::Hit(Err(ERANGE));
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let mut k = usize::MAX;
        let res = f(body, &mut k);
        if k != usize::MAX && !fit.list_ok(rawlen, k) {
            return Scan::Hit(Err(ERANGE));
        }
        if let Some(x) = res {
            return Scan::Hit(x);
        }
    }
    Scan::NotFound
}

const NSS_TRYAGAIN: i32 = -2;
const NSS_UNAVAIL: i32 = -1;
const NSS_NOTFOUND: i32 = 0;
const NSS_SUCCESS: i32 = 1;

fn scan_status(h: *mut c_int, r: Scan) -> i32 {
    match r {
        Scan::Unavail(e) => {
            errno::set(e);
            if e == EAGAIN { NSS_TRYAGAIN } else { NSS_UNAVAIL }
        }
        Scan::NotFound => {
            if !h.is_null() {
                unsafe { *h = HOST_NOT_FOUND };
            }
            NSS_NOTFOUND
        }
        Scan::Hit(Ok(())) => NSS_SUCCESS,
        Scan::Hit(Err(e)) => {
            errno::set(e);
            if !h.is_null() {
                unsafe { *h = NETDB_INTERNAL };
            }
            if e == ERANGE { NSS_TRYAGAIN } else { NSS_UNAVAIL }
        }
    }
}

unsafe fn by_key<T>(db: &[u8], func: &[u8], res: *mut T, result: *mut *mut T, h_errnop: *mut c_int, files: &dyn Fn() -> i32, call: &dyn Fn(usize, *mut c_int) -> i32) -> c_int {
    unsafe { by_key_dns(db, func, res, result, h_errnop, files, call, None) }
}

unsafe fn by_key_dns<T>(db: &[u8], func: &[u8], res: *mut T, result: *mut *mut T, h_errnop: *mut c_int, files: &dyn Fn() -> i32, call: &dyn Fn(usize, *mut c_int) -> i32, dns: Option<&dyn Fn(*mut c_int) -> i32>) -> c_int {
    unsafe {
        let any = core::cell::Cell::new(false);
        let dns_any = |e: *mut c_int| {
            any.set(true);
            match dns {
                Some(d) => d(e),
                None => NSS_UNAVAIL,
            }
        };
        let status = rusty_libc_core::nssent::dispatch_dns(
            db,
            func,
            &|| {
                any.set(true);
                files()
            },
            &|f, en| {
                any.set(true);
                call(f, en)
            },
            None,
            if dns.is_some() { Some(&dns_any) } else { None },
        );
        *result = if status == NSS_SUCCESS { res } else { core::ptr::null_mut() };
        if !h_errnop.is_null() && status != NSS_SUCCESS && !any.get() {
            *h_errnop = if status == NSS_UNAVAIL && errno::get() != ENOENT { NETDB_INTERNAL } else { NO_RECOVERY };
        }
        let rc = if status == NSS_SUCCESS || status == NSS_NOTFOUND {
            0
        } else if errno::get() == ERANGE && status != NSS_TRYAGAIN {
            EINVAL
        } else if !h_errnop.is_null() && status == NSS_TRYAGAIN && *h_errnop != NETDB_INTERNAL {
            EAGAIN
        } else {
            return errno::get();
        };
        errno::set(rc);
        rc
    }
}

type SrcResult = (Status, c_int);

struct OutBuf {
    cur: usize,
    end: usize,
    ok: bool,
}

impl OutBuf {
    fn alloc(&mut self, size: usize, align: usize) {
        if !self.ok {
            return;
        }
        let a = (self.cur + align - 1) & !(align - 1);
        if a + size > self.end {
            self.ok = false;
        } else {
            self.cur = a + size;
        }
    }
}

fn files_hosts(name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> SrcResult {
    let multi = nss::host_conf_multi();
    let mut r = match nss::open_db(Db::Hosts) {
        Ok(r) => r,
        Err(e) => {
            errno::set(e);
            return (if e == EAGAIN { Status::TryAgain } else { Status::Unavail }, out.h);
        }
    };
    let fit = out.fit.map(|(addr, len)| {
        let pad = (8 - addr % 8) % 8;
        Fit { base: 32, addr: addr + pad, len: len.saturating_sub(pad) }
    });
    let erange = |out: &mut HostData| {
        out.erange = true;
        (Status::TryAgain, NETDB_INTERNAL)
    };
    if let Some(f) = fit {
        if !f.pre_ok() {
            return erange(out);
        }
    }
    let mut found = false;
    let mut ob = OutBuf { cur: 0, end: 0, ok: true };
    let (mut naddr, mut nalias) = (0usize, 0usize);
    while let Some((line, rawlen)) = r.next_raw() {
        let line = unsafe { core::slice::from_raw_parts(line.as_ptr(), line.len()) };
        if !found {
            if let Some(f) = fit {
                if !f.read_ok(rawlen) {
                    return erange(out);
                }
            }
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let Some(h) = nss::parse_host_line(body, af, v4mapped) else { continue };
        let k = nss::words(h.rest).count();
        if !found {
            if let Some(f) = fit {
                if !f.list_ok(rawlen, k) {
                    return erange(out);
                }
            }
        }
        let hit = eq_nocase(h.name, name) || nss::words(h.rest).any(|w| eq_nocase(w, name));
        if !hit {
            continue;
        }
        if !found {
            out.canon = Buf::from(h.name).unwrap_or_default();
            out.have_canon = true;
            if let Some(f) = fit {
                let list = (f.addr + f.base + rawlen + 1 + 7) & !7;
                ob = OutBuf { cur: list, end: f.addr + f.len, ok: true };
                naddr = 1;
                nalias = k;
            }
        } else {
            if !eq_nocase(out.canon.as_bytes(), h.name) {
                out.add_alias(h.name);
            }
            if fit.is_some() {
                ob.alloc(if h.family == AF_INET { 4 } else { 16 }, 4);
                naddr += 1;
                for w in nss::words(h.rest) {
                    ob.alloc(w.len() + 1, 1);
                    nalias += 1;
                }
                if h.name != out.canon.as_bytes() {
                    ob.alloc(h.name.len() + 1, 1);
                    nalias += 1;
                }
                if !ob.ok {
                    return erange(out);
                }
            }
        }
        out.push(Addr { family: h.family, bytes: h.addr, scope: 0 });
        for w in nss::words(h.rest) {
            out.add_alias(w);
        }
        found = true;
        if !multi {
            break;
        }
    }
    if !found || multi {
        out.h = HOST_NOT_FOUND;
    }
    if found && multi && fit.is_some() {
        ob.alloc(8 * (naddr + 1), 8);
        ob.alloc(8 * (nalias + 1), 8);
        if !ob.ok {
            return erange(out);
        }
    }
    if found { (Status::Success, NETDB_SUCCESS) } else { (Status::NotFound, HOST_NOT_FOUND) }
}

fn dns_hosts(cfg: &dns::Config, name: &[u8], af: c_int, out: &mut HostData) -> SrcResult {
    if !crate::resolv::hostname_ok(name) {
        out.h = HOST_NOT_FOUND;
        return (Status::NotFound, HOST_NOT_FOUND);
    }
    let mut best: Option<c_int> = None;
    let mut any = false;
    let fams: &[c_int] = match af {
        AF_UNSPEC => &[AF_INET, AF_INET6],
        AF_INET => &[AF_INET],
        _ => &[AF_INET6],
    };
    for &fam in fams {
        if fam == AF_INET6 && cfg.options & dns::RES_NOAAAA != 0 {
            continue;
        }
        match dns::lookup_host(cfg, name, fam, out) {
            Ok(()) => any = true,
            Err(e) => {
                let rank = |h: c_int| match h {
                    TRY_AGAIN => 3,
                    NO_RECOVERY => 2,
                    NO_DATA => 1,
                    _ => 0,
                };
                if best.map(|b| rank(e.h) > rank(b)).unwrap_or(true) {
                    best = Some(e.h);
                }
            }
        }
    }
    if any {
        return (Status::Success, NETDB_SUCCESS);
    }
    let h = best.unwrap_or(HOST_NOT_FOUND);
    out.h = h;
    match h {
        TRY_AGAIN => (Status::TryAgain, TRY_AGAIN),
        h => (Status::NotFound, h),
    }
}

pub(crate) fn src_lookup(e: &Entry, name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> (Status, c_int) {
    match e.src {
        Source::Files => files_hosts(name, af, v4mapped, out),
        Source::Dns => dns_hosts(&crate::resolv::current_config(), name, af, out),
        Source::Module => module_hosts(e.module_name(), name, af, out),
    }
}

fn module_status(st: c_int) -> Status {
    match st {
        1 => Status::Success,
        0 => Status::NotFound,
        -2 => Status::TryAgain,
        _ => Status::Unavail,
    }
}

#[repr(C)]
struct AddrTuple {
    next: *mut AddrTuple,
    name: *mut c_char,
    family: c_int,
    addr: [u32; 4],
    scopeid: u32,
}

unsafe fn with_scratch<R>(mut f: impl FnMut(*mut c_char, usize) -> (R, bool)) -> R {
    unsafe {
        let mut stack = [0u8; 2048];
        let (r, retry) = f(stack.as_mut_ptr() as *mut c_char, stack.len());
        if !retry {
            return r;
        }
        let mut size = 8192usize;
        loop {
            let heap = rusty_libc_malloc::malloc(size) as *mut c_char;
            if heap.is_null() {
                return r;
            }
            let (r, retry) = f(heap, size);
            rusty_libc_malloc::free(heap.cast());
            if !retry || size >= (1 << 20) {
                return r;
            }
            size *= 2;
        }
    }
}

unsafe fn hostent_into(h: &hostent, out: &mut HostData, canon: *const c_char) {
    unsafe {
        if !h.h_name.is_null() && !out.have_canon {
            out.canon = Buf::from(cbytes(h.h_name)).unwrap_or_default();
            out.have_canon = true;
        }
        if !canon.is_null() {
            out.canon = Buf::from(cbytes(canon)).unwrap_or_default();
            out.have_canon = true;
        }
        if !h.h_aliases.is_null() {
            let mut i = 0;
            while !(*h.h_aliases.add(i)).is_null() {
                out.add_alias(cbytes(*h.h_aliases.add(i)));
                i += 1;
            }
        }
        if !h.h_addr_list.is_null() {
            let len = (h.h_length.max(0) as usize).min(16);
            let mut i = 0;
            while !(*h.h_addr_list.add(i)).is_null() {
                let mut a = Addr { family: h.h_addrtype, bytes: [0; 16], scope: 0 };
                core::ptr::copy_nonoverlapping(*h.h_addr_list.add(i) as *const u8, a.bytes.as_mut_ptr(), len);
                out.push(a);
                i += 1;
            }
        }
    }
}

fn module_hosts(module: &[u8], name: &[u8], af: c_int, out: &mut HostData) -> SrcResult {
    use rusty_libc_core::nssmod;
    unsafe {
        let Some(cname) = Buf::<256>::from(name).filter(|b| b.len < 255) else { return (Status::Unavail, NO_DATA) };
        let mut cname = cname;
        cname.push(0);
        let cname_ptr = cname.b.as_ptr() as *const c_char;
        if af == AF_UNSPEC {
            let f4 = nssmod::function(module, b"gethostbyname4_r");
            if f4 != 0 {
                type F4 = unsafe extern "C" fn(*const c_char, *mut *mut AddrTuple, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32) -> c_int;
                let f: F4 = core::mem::transmute(f4);
                let mut result: (c_int, c_int) = (-1, NO_DATA);
                let mut tmp = HostData::new();
                with_scratch(|buf, len| {
                    let mut pat: *mut AddrTuple = core::ptr::null_mut();
                    let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, NETDB_SUCCESS, 0);
                    tmp = HostData::new();
                    let st = f(cname_ptr, &mut pat, buf, len, &mut en, &mut he, &mut ttl);
                    let retry = st == -2 && en == ERANGE;
                    if st == 1 {
                        let mut first = true;
                        let mut p = pat;
                        while !p.is_null() {
                            let t = &*p;
                            if first && !t.name.is_null() {
                                tmp.canon = Buf::from(cbytes(t.name)).unwrap_or_default();
                                tmp.have_canon = true;
                            }
                            first = false;
                            let mut a = Addr { family: t.family, bytes: [0; 16], scope: if t.family == AF_INET6 { t.scopeid } else { 0 } };
                            let n = if t.family == AF_INET { 4 } else { 16 };
                            core::ptr::copy_nonoverlapping(t.addr.as_ptr() as *const u8, a.bytes.as_mut_ptr(), n);
                            tmp.push(a);
                            p = t.next;
                        }
                    }
                    result = (st, he);
                    ((), retry)
                });
                let st = module_status(result.0);
                if st == Status::Success {
                    *out = tmp;
                    return (Status::Success, NETDB_SUCCESS);
                }
                return (st, if result.1 == NETDB_SUCCESS { HOST_NOT_FOUND } else { result.1 });
            }
        }
        let fams: &[c_int] = match af {
            AF_UNSPEC => &[AF_INET6, AF_INET],
            AF_INET => &[AF_INET],
            _ => &[AF_INET6],
        };
        let mut best = (Status::Unavail, HOST_NOT_FOUND);
        let mut any = false;
        let (f3, f2, f1) = match out.func {
            1 => (0, 0, nssmod::function(module, b"gethostbyname_r")),
            2 => (0, nssmod::function(module, b"gethostbyname2_r"), 0),
            _ => (nssmod::function(module, b"gethostbyname3_r"), nssmod::function(module, b"gethostbyname2_r"), 0),
        };
        if f3 == 0 && f2 == 0 && f1 == 0 {
            return (Status::Unavail, NO_DATA);
        }
        out.called = true;
        let h_in = out.h;
        for &fam in fams {
            let mut hd = HostData::new();
            let mut r: (c_int, c_int) = (-1, NO_DATA);
            with_scratch(|buf, len| {
                let mut host = HOSTENT0;
                let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, h_in, 0);
                let mut canon: *mut c_char = core::ptr::null_mut();
                hd = HostData::new();
                let st = if f1 != 0 {
                    type F1 = unsafe extern "C" fn(*const c_char, *mut hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int;
                    let f: F1 = core::mem::transmute(f1);
                    f(cname_ptr, &mut host, buf, len, &mut en, &mut he)
                } else if f3 != 0 {
                    type F3 = unsafe extern "C" fn(*const c_char, c_int, *mut hostent, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32, *mut *mut c_char) -> c_int;
                    let f: F3 = core::mem::transmute(f3);
                    f(cname_ptr, fam, &mut host, buf, len, &mut en, &mut he, &mut ttl, &mut canon)
                } else {
                    type F2 = unsafe extern "C" fn(*const c_char, c_int, *mut hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int;
                    let f: F2 = core::mem::transmute(f2);
                    f(cname_ptr, fam, &mut host, buf, len, &mut en, &mut he)
                };
                let retry = st == -2 && en == ERANGE;
                if st == 1 {
                    hostent_into(&host, &mut hd, canon);
                }
                r = (st, he);
                ((), retry)
            });
            let st = module_status(r.0);
            out.h = r.1;
            if st == Status::Success {
                any = true;
                if !out.have_canon && hd.have_canon {
                    out.canon = hd.canon;
                    out.have_canon = true;
                }
                for a in &hd.addrs[..hd.n] {
                    out.push(*a);
                }
                for w in hd.aliases.as_bytes().split(|&c| c == 0).filter(|w| !w.is_empty()) {
                    out.add_alias(w);
                }
            } else if best.0 == Status::Unavail || (st == Status::TryAgain) {
                best = (st, if r.1 == NETDB_SUCCESS { HOST_NOT_FOUND } else { r.1 });
            }
        }
        if any { (Status::Success, NETDB_SUCCESS) } else { best }
    }
}

fn module_addr(module: &[u8], af: c_int, addr: &[u8], h_in: c_int, name: &mut Option<Buf<256>>, aliases: &mut Buf<1024>) -> (Status, c_int, bool) {
    use rusty_libc_core::nssmod;
    unsafe {
        let f2 = nssmod::function(module, b"gethostbyaddr2_r");
        let f1 = nssmod::function(module, b"gethostbyaddr_r");
        if f2 == 0 && f1 == 0 {
            return (Status::Unavail, h_in, false);
        }
        let mut r: (c_int, c_int) = (-1, h_in);
        let mut got: Option<(Buf<256>, Buf<1024>)> = None;
        with_scratch(|buf, len| {
            let mut host = HOSTENT0;
            let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, h_in, 0);
            let st = if f2 != 0 {
                type F = unsafe extern "C" fn(*const c_void, u32, c_int, *mut hostent, *mut c_char, usize, *mut c_int, *mut c_int, *mut i32) -> c_int;
                let f: F = core::mem::transmute(f2);
                f(addr.as_ptr() as *const c_void, addr.len() as u32, af, &mut host, buf, len, &mut en, &mut he, &mut ttl)
            } else {
                type F = unsafe extern "C" fn(*const c_void, u32, c_int, *mut hostent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int;
                let f: F = core::mem::transmute(f1);
                f(addr.as_ptr() as *const c_void, addr.len() as u32, af, &mut host, buf, len, &mut en, &mut he)
            };
            let retry = st == -2 && en == ERANGE;
            if st == 1 && !host.h_name.is_null() {
                let mut al = Buf::<1024>::new();
                if !host.h_aliases.is_null() {
                    let mut i = 0;
                    while !(*host.h_aliases.add(i)).is_null() {
                        al.push_all(cbytes(*host.h_aliases.add(i)));
                        al.push(0);
                        i += 1;
                    }
                }
                got = Some((Buf::from(cbytes(host.h_name)).unwrap_or_default(), al));
            }
            r = (st, he);
            ((), retry)
        });
        let st = module_status(r.0);
        if st == Status::Success {
            if let Some((n, al)) = got {
                *name = Some(n);
                *aliases = al;
                return (Status::Success, r.1, true);
            }
            return (Status::NotFound, r.1, true);
        }
        (st, r.1, true)
    }
}

pub fn lookup_name(name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> Result<(), c_int> {
    let order = nss::hosts_order();
    let mut status = Status::Unavail;
    let mut any = false;
    for e in &order.e[..order.n] {
        let saved = if status == Status::Success { Some(*out) } else { None };
        if status == Status::Success {
            let keep = (out.fit, out.func, out.h);
            *out = HostData::new();
            (out.fit, out.func, out.h) = keep;
        }
        out.called = e.src != Source::Module;
        let r = src_lookup(e, name, af, v4mapped, out);
        if !out.called {
            if let Some(sv) = saved {
                *out = sv;
            }
            if e.action(Status::Unavail) == Action::Return {
                break;
            }
            continue;
        }
        any = true;
        status = r.0;
        if status == Status::Success && e.action(Status::Success) == Action::Merge {
            errno::set(EINVAL);
            out.einval = true;
            break;
        }
        if out.erange {
            break;
        }
        if e.action(r.0) == Action::Return {
            break;
        }
    }
    out.any = any;
    out.unavail = any && status == Status::Unavail;
    if out.einval {
        Err(out.h)
    } else if status == Status::Success {
        Ok(())
    } else if any {
        Err(out.h)
    } else {
        Err(NO_DATA)
    }
}

fn digits_dots(name: &[u8], af: c_int, use_inet6: bool) -> Result<Option<(Addr, c_int)>, c_int> {
    if name.is_empty() {
        return Ok(None);
    }
    let c0 = name[0];
    if !(c0.is_ascii_digit() || c0.is_ascii_hexdigit() || c0 == b':') {
        return Ok(None);
    }
    let mut af = af;
    if af != AF_INET && af != AF_INET6 {
        af = if use_inet6 { AF_INET6 } else { AF_INET };
    }
    if c0.is_ascii_digit() {
        if name.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
            if *name.last().unwrap() == b'.' {
                return Ok(None);
            }
            let mut a = Addr { family: af, bytes: [0; 16], scope: 0 };
            if af == AF_INET {
                let mut t = Buf::<64>::from(name).ok_or(HOST_NOT_FOUND)?;
                t.push(0);
                let mut ia = in_addr::default();
                match inet::parse_aton(name) {
                    Some((v, end)) if end == name.len() => {
                        ia.s_addr = u32::from_ne_bytes(v);
                    }
                    _ => return Err(HOST_NOT_FOUND),
                }
                a.bytes[..4].copy_from_slice(&ia.s_addr.to_ne_bytes());
            } else {
                match inet::parse_ipv6(name) {
                    Some(v) => a.bytes = v,
                    None => return Err(HOST_NOT_FOUND),
                }
            }
            if af == AF_INET && use_inet6 {
                let v4 = [a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]];
                a.bytes = [0; 16];
                a.bytes[10] = 0xff;
                a.bytes[11] = 0xff;
                a.bytes[12..].copy_from_slice(&v4);
                a.family = AF_INET6;
            }
            return Ok(Some((a, a.family)));
        }
    }
    if (c0.is_ascii_hexdigit() && name.contains(&b':')) || c0 == b':' {
        let af6 = match af {
            AF_INET6 => true,
            _ => return Err(HOST_NOT_FOUND),
        };
        let _ = af6;
        if name.iter().all(|&c| c.is_ascii_hexdigit() || c == b':' || c == b'.') {
            if *name.last().unwrap() == b'.' {
                return Ok(None);
            }
            return match inet::parse_ipv6(name) {
                Some(v) => Ok(Some((Addr { family: AF_INET6, bytes: v, scope: 0 }, AF_INET6))),
                None => Err(HOST_NOT_FOUND),
            };
        }
    }
    Ok(None)
}

fn use_inet6() -> bool {
    crate::resolv::current_config().options & dns::RES_USE_INET6 != 0
}

unsafe fn no_sources(h_errnop: *mut c_int) -> c_int {
    unsafe {
        let e = errno::get();
        *h_errnop = if e != ENOENT { NETDB_INTERNAL } else { NO_RECOVERY };
        if e == ERANGE {
            errno::set(EINVAL);
            return EINVAL;
        }
        e
    }
}

unsafe fn hostbyname_r(func: u8, name: *const c_char, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        let rc = hostbyname_r_body(func, name, af, res, buf, buflen, result, h_errnop);
        errno::set(rc);
        rc
    }
}

unsafe fn hostbyname_r_body(func: u8, name: *const c_char, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        nss::hconf_init();
        *result = core::ptr::null_mut();
        if name.is_null() {
            *h_errnop = HOST_NOT_FOUND;
            return EINVAL;
        }
        let nm = cbytes(name);
        let (mut name_buf, mut data) = (Buf::<1025>::from(nm).unwrap_or_default(), HostData::new());
        let _ = &mut name_buf;
        match digits_dots(nm, af, use_inet6()) {
            Err(h) => {
                *h_errnop = h;
                return 0;
            }
            Ok(Some((a, fam))) => {
                if buflen < 16 + 16 + 8 + nm.len() + 1 {
                    *h_errnop = NETDB_INTERNAL;
                    errno::set(ERANGE);
                    return ERANGE;
                }
                let r = fill_hostent(&mut *res, buf, buflen, nm, b"", fam, &[a]);
                return match r {
                    Ok(()) => {
                        *h_errnop = NETDB_SUCCESS;
                        *result = res;
                        0
                    }
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        e
                    }
                };
            }
            Ok(None) => {}
        }
        if nss::hosts_order().n == 0 {
            return no_sources(h_errnop);
        }
        let want_af = if af == AF_INET || af == AF_INET6 { af } else { AF_INET };
        let v4m = want_af == AF_INET6 && use_inet6();
        data.fit = Some((buf as usize, buflen));
        data.func = func;
        data.h = *h_errnop;
        match lookup_name(nm, want_af, v4m, &mut data) {
            Ok(()) => {
                let fam = if want_af == AF_INET6 { AF_INET6 } else { AF_INET };
                let addrs = &data.addrs[..data.n];
                let r = fill_hostent(&mut *res, buf, buflen, data.canon.as_bytes(), data.aliases.as_bytes(), fam, addrs);
                match r {
                    Ok(()) => {
                        *h_errnop = data.h;
                        *result = res;
                        0
                    }
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        e
                    }
                }
            }
            Err(h) => {
                if data.erange {
                    *h_errnop = NETDB_INTERNAL;
                    errno::set(ERANGE);
                    return ERANGE;
                }
                if data.einval {
                    *h_errnop = data.h;
                    return EINVAL;
                }
                if !data.any {
                    return no_sources(h_errnop);
                }
                *h_errnop = h;
                if h == TRY_AGAIN {
                    EAGAIN
                } else if data.unavail {
                    errno::get()
                } else {
                    0
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname_r(name: *const c_char, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe { hostbyname_r(1, name, if use_inet6() { AF_INET6 } else { AF_INET }, res, buf, buflen, result, h_errnop) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2_r(name: *const c_char, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe { hostbyname_r(2, name, af, res, buf, buflen, result, h_errnop) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr_r(addr: *const c_void, len: u32, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        let rc = hostbyaddr_r_body(addr, len, af, res, buf, buflen, result, h_errnop);
        errno::set(rc);
        rc
    }
}

unsafe fn hostbyaddr_r_body(addr: *const c_void, len: u32, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        nss::hconf_init();
        *result = core::ptr::null_mut();
        let af = if af == AF_UNSPEC { AF_INET } else { af };
        if !((af == AF_INET6 && len >= 16) || (af == AF_INET && len >= 4)) {
            *h_errnop = NETDB_INTERNAL;
            errno::set(EAFNOSUPPORT);
            return EAFNOSUPPORT;
        }
        let len = if af == AF_INET { 4 } else { 16 };
        let a = core::slice::from_raw_parts(addr as *const u8, len as usize);
        let (mut af, mut a) = (af, a);
        if af == AF_INET6 && a[..10] == [0; 10] && ((a[10] == 0xff && a[11] == 0xff) || (a[10] == 0 && a[11] == 0 && (a[12] != 0 || a[13] != 0 || a[14] != 0 || a[15] > 1))) {
            a = &a[12..];
            af = AF_INET;
        }
        let order = nss::hosts_order();
        if order.n == 0 {
            return no_sources(h_errnop);
        }
        let mut name: Option<Buf<256>> = None;
        let mut aliases = Buf::<1024>::new();
        let mut h_out = *h_errnop;
        let mut range_err = false;
        let mut status = Status::Unavail;
        let mut any = false;
        for e in &order.e[..order.n] {
            let saved = if status == Status::Success { Some((name, aliases)) } else { None };
            if status == Status::Success {
                name = None;
                aliases = Buf::<1024>::new();
            }
            let st = match e.src {
                Source::Files => {
                    let mut found = Status::NotFound;
                    let fit = Fit::new(32, buf, buflen);
                    let opened = nss::open_db(Db::Hosts);
                    if let Err(e) = &opened {
                        errno::set(*e);
                    }
                    if let Ok(mut r) = opened {
                        if !fit.pre_ok() {
                            range_err = true;
                        }
                        let mut matched = false;
                        while !range_err {
                            let Some((line, rawlen)) = r.next_raw() else { break };
                            let line = core::slice::from_raw_parts(line.as_ptr(), line.len());
                            if !fit.read_ok(rawlen) {
                                range_err = true;
                                break;
                            }
                            let Some(body) = nss::entry_body(line) else { continue };
                            let Some(h) = nss::parse_host_line(body, af, len == 16) else { continue };
                            if !fit.list_ok(rawlen, nss::words(h.rest).count()) {
                                range_err = true;
                                break;
                            }
                            let alen = if af == AF_INET { 4 } else { 16 };
                            if h.addr[..alen] == a[..alen] {
                                name = Buf::from(h.name);
                                for w in nss::words(h.rest) {
                                    aliases.push_all(w);
                                    aliases.push(0);
                                }
                                found = Status::Success;
                                matched = true;
                                break;
                            }
                        }
                        if !range_err && !matched {
                            h_out = HOST_NOT_FOUND;
                        }
                    } else {
                        found = Status::Unavail;
                    }
                    any = true;
                    found
                }
                Source::Dns => {
                    any = true;
                    match dns::lookup_addr(&crate::resolv::current_config(), af, a) {
                        Ok(n) => {
                            name = Some(n);
                            Status::Success
                        }
                        Err(he) => {
                            h_out = he.h;
                            Status::NotFound
                        }
                    }
                }
                Source::Module => {
                    let (st, h, asked) = module_addr(e.module_name(), af, a, h_out, &mut name, &mut aliases);
                    if !asked {
                        if let Some((n, al)) = saved {
                            name = n;
                            aliases = al;
                        }
                        if e.action(Status::Unavail) == Action::Return {
                            break;
                        }
                        continue;
                    }
                    any = true;
                    h_out = h;
                    st
                }
            };
            if range_err {
                *h_errnop = NETDB_INTERNAL;
                errno::set(ERANGE);
                return ERANGE;
            }
            status = st;
            if st == Status::Success && e.action(Status::Success) == Action::Merge {
                errno::set(EINVAL);
                *h_errnop = h_out;
                return EINVAL;
            }
            if e.action(st) == Action::Return {
                break;
            }
        }
        if !any {
            return no_sources(h_errnop);
        }
        match name {
            Some(n) if status == Status::Success => {
                *h_errnop = h_out;
                let ad = Addr { family: af, bytes: { let mut b = [0u8; 16]; b[..a.len()].copy_from_slice(a); b }, scope: 0 };
                match fill_hostent(&mut *res, buf, buflen, n.as_bytes(), aliases.as_bytes(), af, &[ad]) {
                    Ok(()) => {
                        *result = res;
                        0
                    }
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        e
                    }
                }
            }
            _ => {
                *h_errnop = h_out;
                if status == Status::TryAgain && h_out != NETDB_INTERNAL {
                    EAGAIN
                } else if status == Status::Unavail {
                    errno::get()
                } else {
                    0
                }
            }
        }
    }
}

struct Static<T> {
    res: T,
    buf: *mut c_char,
    cap: usize,
}

unsafe impl<T> Send for Static<T> {}

const BUF0: usize = 1024;

macro_rules! statics {
    ($name:ident, $ty:ty, $zero:expr) => {
        static $name: Spin<Static<$ty>> = Spin::new(Static { res: $zero, buf: core::ptr::null_mut(), cap: 0 });
    };
}

const HOSTENT0: hostent = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
const SERVENT0: servent = servent { s_name: core::ptr::null_mut(), s_aliases: core::ptr::null_mut(), s_port: 0, s_proto: core::ptr::null_mut() };
const PROTOENT0: protoent = protoent { p_name: core::ptr::null_mut(), p_aliases: core::ptr::null_mut(), p_proto: 0 };
const NETENT0: netent = netent { n_name: core::ptr::null_mut(), n_aliases: core::ptr::null_mut(), n_addrtype: 0, n_net: 0 };
const RPCENT0: rpcent = rpcent { r_name: core::ptr::null_mut(), r_aliases: core::ptr::null_mut(), r_number: 0 };
const ALIASENT0: aliasent = aliasent { alias_name: core::ptr::null_mut(), alias_members_len: 0, alias_members: core::ptr::null_mut(), alias_local: 0 };

statics!(HOSTENT_S, hostent, HOSTENT0);
statics!(SERVENT_S, servent, SERVENT0);
statics!(PROTOENT_S, protoent, PROTOENT0);
statics!(NETENT_S, netent, NETENT0);
statics!(RPCENT_S, rpcent, RPCENT0);
statics!(ALIASENT_S, aliasent, ALIASENT0);

fn with_static<T: Copy>(s: &Spin<Static<T>>, mut f: impl FnMut(*mut T, *mut c_char, usize, *mut *mut T) -> c_int) -> *mut T {
    let mut g = s.lock();
    if g.buf.is_null() {
        g.buf = unsafe { rusty_libc_malloc::malloc(BUF0) } as *mut c_char;
        if g.buf.is_null() {
            errno::set(ENOMEM);
            return core::ptr::null_mut();
        }
        g.cap = BUF0;
    }
    loop {
        let (res, buf, cap) = (&mut g.res as *mut T, g.buf, g.cap);
        let mut out: *mut T = core::ptr::null_mut();
        let r = f(res, buf, cap, &mut out);
        if r == ERANGE {
            let ncap = g.cap * 2;
            let nb = unsafe { rusty_libc_malloc::realloc(g.buf as *mut c_void, ncap) } as *mut c_char;
            if nb.is_null() {
                errno::set(ENOMEM);
                return core::ptr::null_mut();
            }
            g.buf = nb;
            g.cap = ncap;
            continue;
        }
        if r == 0 {
            return out;
        }
        errno::set(r);
        return core::ptr::null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut hostent {
    let mut h = 0;
    let r = with_static(&HOSTENT_S, |res, buf, cap, out| unsafe { gethostbyname_r(name, res, buf, cap, out, &mut h) });
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut hostent {
    let mut h = 0;
    let r = with_static(&HOSTENT_S, |res, buf, cap, out| unsafe { gethostbyname2_r(name, af, res, buf, cap, out, &mut h) });
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr(addr: *const c_void, len: u32, af: c_int) -> *mut hostent {
    let mut h = 0;
    let r = with_static(&HOSTENT_S, |res, buf, cap, out| unsafe { gethostbyaddr_r(addr, len, af, res, buf, cap, out, &mut h) });
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname_r(name: *const c_char, proto: *const c_char, res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    unsafe {
        let nm = cbytes(name);
        let pr = if proto.is_null() { None } else { Some(cbytes(proto)) };
        by_key(
            b"services",
            b"getservbyname_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Services, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_serv_line(line)?;
                    *k = nss::words(l.rest).count();
                    if let Some(p) = pr {
                        if l.proto != p {
                            return None;
                        }
                    }
                    if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                        return Some(fill_servent(&mut *res, buf, buflen, &l));
                    }
                    None
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *const c_char, *mut servent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, proto, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport_r(port: c_int, proto: *const c_char, res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    unsafe {
        let pr = if proto.is_null() { None } else { Some(cbytes(proto)) };
        by_key(
            b"services",
            b"getservbyport_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Services, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_serv_line(line)?;
                    *k = nss::words(l.rest).count();
                    if (l.port.to_be() as c_int) != port {
                        return None;
                    }
                    if let Some(p) = pr {
                        if l.proto != p {
                            return None;
                        }
                    }
                    Some(fill_servent(&mut *res, buf, buflen, &l))
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(c_int, *const c_char, *mut servent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(port, proto, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname_r(name: *const c_char, res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    unsafe {
        let nm = cbytes(name);
        by_key(
            b"protocols",
            b"getprotobyname_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Protocols, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_num_line(line)?;
                    *k = nss::words(l.rest).count();
                    if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                        return Some(fill_protoent(&mut *res, buf, buflen, &l));
                    }
                    None
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut protoent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber_r(proto: c_int, res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    unsafe {
        by_key(
            b"protocols",
            b"getprotobynumber_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Protocols, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_num_line(line)?;
                    *k = nss::words(l.rest).count();
                    if l.num == proto { Some(fill_protoent(&mut *res, buf, buflen, &l)) } else { None }
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(c_int, *mut protoent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(proto, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname_r(name: *const c_char, res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        let nm = cbytes(name);
        by_key_dns(
            b"networks",
            b"getnetbyname_r",
            res,
            result,
            h_errnop,
            &|| {
                scan_status(h_errnop, scan(Db::Networks, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_net_line(line)?;
                    *k = nss::words(l.rest).count();
                    if eq_nocase(l.name, nm) || nss::words(l.rest).any(|w| eq_nocase(w, nm)) {
                        return Some(fill_netent(&mut *res, buf, buflen, &l));
                    }
                    None
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut netent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, res, buf, buflen, en, h_errnop)
            },
            Some(&|en| {
                if dns::net_name_query_refused(&crate::resolv::current_config(), nm) {
                    *en = ECONNREFUSED;
                    NSS_UNAVAIL
                } else {
                    NSS_NOTFOUND
                }
            }),
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr_r(net: u32, ty: c_int, res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, h_errnop: *mut c_int) -> c_int {
    unsafe {
        by_key_dns(
            b"networks",
            b"getnetbyaddr_r",
            res,
            result,
            h_errnop,
            &|| {
                scan_status(h_errnop, scan(Db::Networks, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_net_line(line)?;
                    *k = nss::words(l.rest).count();
                    if (ty == AF_UNSPEC || ty == AF_INET) && l.net == net { Some(fill_netent(&mut *res, buf, buflen, &l)) } else { None }
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(u32, c_int, *mut netent, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int = core::mem::transmute(f);
                f(net, ty, res, buf, buflen, en, h_errnop)
            },
            Some(&|_en| {
                if ty != AF_INET {
                    return NSS_UNAVAIL;
                }
                let olderr = errno::get();
                let refused = dns::net_addr_query_refused(&crate::resolv::current_config(), net);
                errno::set(olderr);
                if refused { NSS_UNAVAIL } else { NSS_NOTFOUND }
            }),
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname_r(name: *const c_char, res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    unsafe {
        let nm = cbytes(name);
        by_key(
            b"rpc",
            b"getrpcbyname_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Rpc, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_num_line(line)?;
                    *k = nss::words(l.rest).count();
                    if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                        return Some(fill_rpcent(&mut *res, buf, buflen, &l));
                    }
                    None
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut rpcent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber_r(number: c_int, res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    unsafe {
        by_key(
            b"rpc",
            b"getrpcbynumber_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                scan_status(core::ptr::null_mut(), scan(Db::Rpc, Fit::new(0, buf, buflen), |line, k| {
                    let l = nss::parse_num_line(line)?;
                    *k = nss::words(l.rest).count();
                    if l.num == number { Some(fill_rpcent(&mut *res, buf, buflen, &l)) } else { None }
                }))
            },
            &|f, en| {
                let f: unsafe extern "C" fn(c_int, *mut rpcent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(number, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut servent {
    with_static(&SERVENT_S, |res, buf, cap, out| unsafe { getservbyname_r(name, proto, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport(port: c_int, proto: *const c_char) -> *mut servent {
    with_static(&SERVENT_S, |res, buf, cap, out| unsafe { getservbyport_r(port, proto, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut protoent {
    with_static(&PROTOENT_S, |res, buf, cap, out| unsafe { getprotobyname_r(name, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber(proto: c_int) -> *mut protoent {
    with_static(&PROTOENT_S, |res, buf, cap, out| unsafe { getprotobynumber_r(proto, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname(name: *const c_char) -> *mut rpcent {
    with_static(&RPCENT_S, |res, buf, cap, out| unsafe { getrpcbyname_r(name, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber(number: c_int) -> *mut rpcent {
    with_static(&RPCENT_S, |res, buf, cap, out| unsafe { getrpcbynumber_r(number, res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname(name: *const c_char) -> *mut netent {
    let mut h = 0;
    let r = with_static(&NETENT_S, |res, buf, cap, out| unsafe { getnetbyname_r(name, res, buf, cap, out, &mut h) });
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr(net: u32, ty: c_int) -> *mut netent {
    let mut h = 0;
    let r = with_static(&NETENT_S, |res, buf, cap, out| unsafe { getnetbyaddr_r(net, ty, res, buf, cap, out, &mut h) });
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

use rusty_libc_core::nssent::{self, EntOps, Fn3};
use rusty_libc_core::nssmod;

const ST_TRYAGAIN: i32 = -2;
const ST_UNAVAIL: i32 = -1;
const ST_NOTFOUND: i32 = 0;
const ST_SUCCESS: i32 = 1;

struct FileEnt {
    r: LineReader,
}

struct NetDb {
    st: nssent::EntState,
    f: FileEnt,
}

impl NetDb {
    const fn new() -> NetDb {
        NetDb { st: nssent::EntState::new(), f: FileEnt { r: LineReader::closed() } }
    }
}

static mut HOST_DB: NetDb = NetDb::new();
static mut SERV_DB: NetDb = NetDb::new();
static mut PROTO_DB: NetDb = NetDb::new();
static mut NET_DB: NetDb = NetDb::new();
static mut RPC_DB: NetDb = NetDb::new();
static mut ALIAS_DB: NetDb = NetDb::new();

struct Names {
    db: &'static [u8],
    dbid: Db,
    set: &'static [u8],
    get: &'static [u8],
    end: &'static [u8],
    stay: bool,
    h: bool,
}

const HOST_NAMES: Names = Names { db: b"hosts", dbid: Db::Hosts, set: b"sethostent", get: b"gethostent_r", end: b"endhostent", stay: true, h: true };
const SERV_NAMES: Names = Names { db: b"services", dbid: Db::Services, set: b"setservent", get: b"getservent_r", end: b"endservent", stay: true, h: false };
const PROTO_NAMES: Names = Names { db: b"protocols", dbid: Db::Protocols, set: b"setprotoent", get: b"getprotoent_r", end: b"endprotoent", stay: true, h: false };
const NET_NAMES: Names = Names { db: b"networks", dbid: Db::Networks, set: b"setnetent", get: b"getnetent_r", end: b"endnetent", stay: true, h: true };
const RPC_NAMES: Names = Names { db: b"rpc", dbid: Db::Rpc, set: b"setrpcent", get: b"getrpcent_r", end: b"endrpcent", stay: true, h: false };
const ALIAS_NAMES: Names = Names { db: b"aliases", dbid: Db::Aliases, set: b"setaliasent", get: b"getaliasent_r", end: b"endaliasent", stay: false, h: false };

type ReadFn<T> = unsafe fn(&mut FileEnt, *mut T, *mut c_char, usize) -> i32;

struct NetOps<'a, T> {
    f: &'a mut FileEnt,
    names: &'static Names,
    res: *mut T,
    buf: *mut c_char,
    len: usize,
    read: Option<ReadFn<T>>,
    h: *mut c_int,
}

fn is_files(src: &nssmod::Source) -> bool {
    nssent::is_files(src)
}

impl<T> EntOps for NetOps<'_, T> {
    fn has(&mut self, src: &nssmod::Source, f: Fn3) -> bool {
        if is_files(src) {
            return true;
        }
        if src.is(b"dns") {
            return false;
        }
        let n = match f {
            Fn3::Set => self.names.set,
            Fn3::Get => self.names.get,
            Fn3::End => self.names.end,
        };
        nssmod::function(src.name(), n) != 0
    }
    fn call_set(&mut self, src: &nssmod::Source, stay: i32) -> i32 {
        unsafe {
            if is_files(src) {
                return file_set(self.f, self.names.dbid);
            }
            let f = nssmod::function(src.name(), self.names.set);
            if f == 0 {
                return ST_UNAVAIL;
            }
            if self.names.stay {
                let f: unsafe extern "C" fn(c_int) -> c_int = core::mem::transmute(f);
                f(stay)
            } else {
                let f: unsafe extern "C" fn() -> c_int = core::mem::transmute(f);
                f()
            }
        }
    }
    fn call_get(&mut self, src: &nssmod::Source) -> i32 {
        unsafe {
            if is_files(src) {
                if !self.f.r.is_open() {
                    let saved = errno::get();
                    let st = file_set(self.f, self.names.dbid);
                    errno::set(saved);
                    if st != ST_SUCCESS {
                        return st;
                    }
                }
                return (self.read.unwrap())(self.f, self.res, self.buf, self.len);
            }
            let f = nssmod::function(src.name(), self.names.get);
            if f == 0 {
                return ST_UNAVAIL;
            }
            let f: unsafe extern "C" fn(*mut T, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int = core::mem::transmute(f);
            let st = f(self.res, self.buf, self.len, errno::location(), self.h);
            if (-2..=1).contains(&st) { st } else { ST_UNAVAIL }
        }
    }
    fn call_end(&mut self, src: &nssmod::Source) {
        unsafe {
            if is_files(src) {
                self.f.r.close();
                return;
            }
            let f = nssmod::function(src.name(), self.names.end);
            if f != 0 {
                let f: unsafe extern "C" fn() -> c_int = core::mem::transmute(f);
                f();
            }
        }
    }
}

fn file_set(f: &mut FileEnt, db: Db) -> i32 {
    if f.r.is_open() {
        f.r.rewind();
        return ST_SUCCESS;
    }
    match nss::open_db(db) {
        Ok(r) => {
            f.r = r;
            ST_SUCCESS
        }
        Err(e) => {
            errno::set(e);
            if e == EAGAIN { ST_TRYAGAIN } else { ST_UNAVAIL }
        }
    }
}

unsafe fn db_set<T>(db: *mut NetDb, names: &'static Names, stay: c_int) {
    unsafe {
        let db = &mut *db;
        db.st.lock.lock_always();
        let mut ops = NetOps::<T> { f: &mut db.f, names, res: core::ptr::null_mut(), buf: core::ptr::null_mut(), len: 0, read: None, h: core::ptr::null_mut() };
        db.st.setent(names.db, stay, &mut ops, names.stay);
        db.st.lock.unlock_always();
    }
}

unsafe fn db_end<T>(db: *mut NetDb, names: &'static Names) {
    unsafe {
        let db = &mut *db;
        if !db.st.is_started() {
            return;
        }
        db.st.lock.lock_always();
        let mut ops = NetOps::<T> { f: &mut db.f, names, res: core::ptr::null_mut(), buf: core::ptr::null_mut(), len: 0, read: None, h: core::ptr::null_mut() };
        db.st.endent(names.db, &mut ops);
        db.st.lock.unlock_always();
    }
}

unsafe fn db_get<T>(db: *mut NetDb, names: &'static Names, read: ReadFn<T>, res: *mut T, buf: *mut c_char, len: usize, result: *mut *mut T) -> c_int {
    unsafe {
        let db = &mut *db;
        db.st.lock.lock_always();
        let hp: *mut c_int = if names.h { crate::strerr::__h_errno.as_ptr() } else { core::ptr::null_mut() };
        let mut ops = NetOps::<T> { f: &mut db.f, names, res, buf, len, read: Some(read), h: hp };
        let rc = db.st.getent(names.db, &mut ops, names.stay, &|| hp.is_null() || *hp == NETDB_INTERNAL);
        db.st.lock.unlock_always();
        *result = if rc == 0 { res } else { core::ptr::null_mut() };
        rc
    }
}

unsafe fn read_ent(f: &mut FileEnt, fit: Fit, h: bool, mut parse: impl FnMut(&[u8], &mut usize) -> Option<Result<(), i32>>) -> i32 {
    let erange = |f: &mut FileEnt, unread: bool| {
        if unread {
            f.r.unread();
        }
        errno::set(ERANGE);
        if h {
            crate::strerr::set_h_errno(NETDB_INTERNAL);
        }
        ST_TRYAGAIN
    };
    if !fit.pre_ok() {
        return erange(f, false);
    }
    loop {
        let Some((line, rawlen)) = f.r.next_raw() else {
            if h {
                crate::strerr::set_h_errno(HOST_NOT_FOUND);
            }
            return ST_NOTFOUND;
        };
        let line = unsafe { core::slice::from_raw_parts(line.as_ptr(), line.len()) };
        if !fit.read_ok(rawlen) {
            return erange(f, true);
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let mut k = usize::MAX;
        let r = parse(body, &mut k);
        if k != usize::MAX && !fit.list_ok(rawlen, k) {
            return erange(f, true);
        }
        match r {
            None => continue,
            Some(Ok(())) => return ST_SUCCESS,
            Some(Err(e)) => {
                f.r.unread();
                errno::set(e);
                if h {
                    crate::strerr::set_h_errno(NETDB_INTERNAL);
                }
                return if e == ERANGE { ST_TRYAGAIN } else { ST_UNAVAIL };
            }
        }
    }
}

unsafe fn read_serv(f: &mut FileEnt, res: *mut servent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        read_ent(f, Fit::new(0, buf, len), false, |line, k| {
            let l = nss::parse_serv_line(line)?;
            *k = nss::words(l.rest).count();
            Some(fill_servent(&mut *res, buf, len, &l))
        })
    }
}
unsafe fn read_proto(f: &mut FileEnt, res: *mut protoent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        read_ent(f, Fit::new(0, buf, len), false, |line, k| {
            let l = nss::parse_num_line(line)?;
            *k = nss::words(l.rest).count();
            Some(fill_protoent(&mut *res, buf, len, &l))
        })
    }
}
unsafe fn read_net(f: &mut FileEnt, res: *mut netent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        read_ent(f, Fit::new(0, buf, len), true, |line, k| {
            let l = nss::parse_net_line(line)?;
            *k = nss::words(l.rest).count();
            Some(fill_netent(&mut *res, buf, len, &l))
        })
    }
}
unsafe fn read_rpc(f: &mut FileEnt, res: *mut rpcent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        read_ent(f, Fit::new(0, buf, len), false, |line, k| {
            let l = nss::parse_num_line(line)?;
            *k = nss::words(l.rest).count();
            Some(fill_rpcent(&mut *res, buf, len, &l))
        })
    }
}
unsafe fn read_host(f: &mut FileEnt, res: *mut hostent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        read_ent(f, Fit::new(32, buf, len), true, |line, k| {
            let h = nss::parse_host_line(line, AF_INET, false)?;
            *k = nss::words(h.rest).count();
            let a = Addr { family: h.family, bytes: h.addr, scope: 0 };
            Some(fill_hostent(&mut *res, buf, len, h.name, h.rest, h.family, &[a]))
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setservent(stay: c_int) {
    unsafe { db_set::<servent>(&raw mut SERV_DB, &SERV_NAMES, stay) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endservent() {
    unsafe { db_end::<servent>(&raw mut SERV_DB, &SERV_NAMES) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setprotoent(stay: c_int) {
    unsafe { db_set::<protoent>(&raw mut PROTO_DB, &PROTO_NAMES, stay) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endprotoent() {
    unsafe { db_end::<protoent>(&raw mut PROTO_DB, &PROTO_NAMES) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setnetent(stay: c_int) {
    unsafe { db_set::<netent>(&raw mut NET_DB, &NET_NAMES, stay) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endnetent() {
    unsafe { db_end::<netent>(&raw mut NET_DB, &NET_NAMES) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setrpcent(stay: c_int) {
    unsafe { db_set::<rpcent>(&raw mut RPC_DB, &RPC_NAMES, stay) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endrpcent() {
    unsafe { db_end::<rpcent>(&raw mut RPC_DB, &RPC_NAMES) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sethostent(stay: c_int) {
    unsafe { db_set::<hostent>(&raw mut HOST_DB, &HOST_NAMES, stay) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endhostent() {
    unsafe { db_end::<hostent>(&raw mut HOST_DB, &HOST_NAMES) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setaliasent() {
    unsafe { db_set::<aliasent>(&raw mut ALIAS_DB, &ALIAS_NAMES, 0) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endaliasent() {
    unsafe { db_end::<aliasent>(&raw mut ALIAS_DB, &ALIAS_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservent_r(res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    unsafe { db_get::<servent>(&raw mut SERV_DB, &SERV_NAMES, read_serv, res, buf, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent_r(res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    unsafe { db_get::<protoent>(&raw mut PROTO_DB, &PROTO_NAMES, read_proto, res, buf, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent_r(res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, _h_errnop: *mut c_int) -> c_int {
    unsafe {
        db_get::<netent>(&raw mut NET_DB, &NET_NAMES, read_net, res, buf, buflen, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcent_r(res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    unsafe { db_get::<rpcent>(&raw mut RPC_DB, &RPC_NAMES, read_rpc, res, buf, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent_r(res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, _h_errnop: *mut c_int) -> c_int {
    unsafe {
        db_get::<hostent>(&raw mut HOST_DB, &HOST_NAMES, read_host, res, buf, buflen, result)
    }
}

fn with_static_ent<T: Copy>(s: &Spin<Static<T>>, mut f: impl FnMut(*mut T, *mut c_char, usize, *mut *mut T) -> c_int) -> *mut T {
    let mut g = s.lock();
    if g.buf.is_null() {
        g.buf = unsafe { rusty_libc_malloc::malloc(BUF0) } as *mut c_char;
        if g.buf.is_null() {
            errno::set(ENOMEM);
            return core::ptr::null_mut();
        }
        g.cap = BUF0;
    }
    loop {
        let (res, buf, cap) = (&mut g.res as *mut T, g.buf, g.cap);
        let mut out: *mut T = core::ptr::null_mut();
        let r = f(res, buf, cap, &mut out);
        if r == ERANGE {
            let ncap = g.cap * 2;
            let nb = unsafe { rusty_libc_malloc::realloc(g.buf as *mut c_void, ncap) } as *mut c_char;
            if nb.is_null() {
                errno::set(ENOMEM);
                return core::ptr::null_mut();
            }
            g.buf = nb;
            g.cap = ncap;
            continue;
        }
        return if r == 0 { out } else { core::ptr::null_mut() };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservent() -> *mut servent {
    with_static_ent(&SERVENT_S, |res, buf, cap, out| unsafe { getservent_r(res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent() -> *mut protoent {
    with_static_ent(&PROTOENT_S, |res, buf, cap, out| unsafe { getprotoent_r(res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent() -> *mut netent {
    let mut h = 0;
    with_static_ent(&NETENT_S, |res, buf, cap, out| unsafe { getnetent_r(res, buf, cap, out, &mut h) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcent() -> *mut rpcent {
    with_static_ent(&RPCENT_S, |res, buf, cap, out| unsafe { getrpcent_r(res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent() -> *mut hostent {
    let mut h = 0;
    with_static_ent(&HOSTENT_S, |res, buf, cap, out| unsafe { gethostent_r(res, buf, cap, out, &mut h) })
}

const ST_RETURN: i32 = 2;

fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | 9..=13)
}

unsafe fn cut_at_comment_or_newline(p: *mut u8) {
    unsafe {
        let mut q = p;
        while *q != 0 {
            if *q == b'#' || *q == b'\n' {
                *q = 0;
                return;
            }
            q = q.add(1);
        }
    }
}

unsafe fn c_strlen(p: *const u8) -> usize {
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        n
    }
}

unsafe fn get_next_alias(st: &mut LineReader, matchname: Option<&[u8]>, result: *mut aliasent, buffer: *mut u8, buflen: usize) -> i32 {
    unsafe {
        let mut status = ST_NOTFOUND;
        let mut ignore = false;
        (*result).alias_members_len = 0;
        let no_room = || {
            errno::set(ERANGE);
            ST_TRYAGAIN
        };
        loop {
            let mut first_unused = buffer;
            let mut room_left = buflen - (buflen % 8);
            if room_left < 2 {
                return no_room();
            }
            *first_unused.add(room_left - 1) = 0xff;
            if !st.fgets(first_unused, room_left) {
                break;
            }
            if *first_unused.add(room_left - 1) != 0xff {
                return no_room();
            }
            let mut line = first_unused;
            if ignore && c_isspace(*first_unused) {
                continue;
            }
            cut_at_comment_or_newline(first_unused);
            while c_isspace(*line) {
                line = line.add(1);
            }
            let name_at = first_unused;
            (*result).alias_name = first_unused as *mut c_char;
            while *line != 0 && *line != b':' {
                *first_unused = *line;
                first_unused = first_unused.add(1);
                line = line.add(1);
            }
            if *line == 0 || name_at == first_unused {
                continue;
            }
            *first_unused = 0;
            first_unused = first_unused.add(1);
            let used = first_unused.offset_from(name_at) as usize;
            if room_left < used {
                return no_room();
            }
            room_left -= used;
            line = line.add(1);
            ignore = match matchname {
                Some(m) => !eq_nocase(core::slice::from_raw_parts(name_at, c_strlen(name_at)), m),
                None => false,
            };
            if !ignore {
              loop {
                while c_isspace(*line) {
                    line = line.add(1);
                }
                let mut cp = first_unused;
                while *line != 0 && *line != b',' {
                    *first_unused = *line;
                    first_unused = first_unused.add(1);
                    line = line.add(1);
                }
                if first_unused != cp {
                    if *line != 0 {
                        line = line.add(1);
                    }
                    *first_unused = 0;
                    first_unused = first_unused.add(1);
                    let is_include = core::slice::from_raw_parts(cp, 9.min(first_unused.offset_from(cp) as usize)) == b":include:";
                    if !is_include {
                        let n = first_unused.offset_from(cp) as usize;
                        if room_left < n + 8 {
                            return no_room();
                        }
                        room_left -= n + 8;
                        (*result).alias_members_len += 1;
                    } else {
                        first_unused = cp;
                        let mut path = Buf::<320>::new();
                        path.push_all(core::slice::from_raw_parts(cp.add(9), c_strlen(cp.add(9))));
                        path.push(0);
                        let listfile = LineReader::open(&path).ok();
                        let old_line = if listfile.is_some() {
                            let n = c_strlen(line);
                            let o = rusty_libc_malloc::malloc(n + 1) as *mut u8;
                            if !o.is_null() {
                                core::ptr::copy_nonoverlapping(line, o, n + 1);
                            }
                            o
                        } else {
                            core::ptr::null_mut()
                        };
                        if let (Some(mut lf), false) = (listfile, old_line.is_null()) {
                            while !lf.at_eof() {
                                if room_left < 2 {
                                    rusty_libc_malloc::free(old_line as *mut c_void);
                                    return no_room();
                                }
                                *first_unused.add(room_left - 1) = 0xff;
                                if !lf.fgets(first_unused, room_left) {
                                    break;
                                }
                                line = first_unused;
                                if *first_unused.add(room_left - 1) != 0xff {
                                    rusty_libc_malloc::free(old_line as *mut c_void);
                                    return no_room();
                                }
                                cut_at_comment_or_newline(line);
                                loop {
                                    while c_isspace(*line) {
                                        line = line.add(1);
                                    }
                                    cp = first_unused;
                                    while *line != 0 && *line != b',' {
                                        *first_unused = *line;
                                        first_unused = first_unused.add(1);
                                        line = line.add(1);
                                    }
                                    if *line != 0 {
                                        line = line.add(1);
                                    }
                                    if first_unused != cp {
                                        *first_unused = 0;
                                        first_unused = first_unused.add(1);
                                        let n = first_unused.offset_from(cp) as usize;
                                        if room_left < n + 8 {
                                            rusty_libc_malloc::free(old_line as *mut c_void);
                                            return no_room();
                                        }
                                        room_left -= n + 8;
                                        (*result).alias_members_len += 1;
                                    }
                                    if *line == 0 {
                                        break;
                                    }
                                }
                            }
                            drop(lf);
                            *first_unused.add(room_left - 1) = 0;
                            let n = c_strlen(old_line).min(room_left);
                            core::ptr::copy_nonoverlapping(old_line, first_unused, n);
                            core::ptr::write_bytes(first_unused.add(n), 0, room_left - n);
                            rusty_libc_malloc::free(old_line as *mut c_void);
                            line = first_unused;
                            if *first_unused.add(room_left - 1) != 0 {
                                return no_room();
                            }
                        } else if !old_line.is_null() {
                            rusty_libc_malloc::free(old_line as *mut c_void);
                        }
                    }
                }
                if *line == 0 {
                    let ch = st.getc();
                    if ch == -1 || ch == b'\n' as i32 || !c_isspace(ch as u8) {
                        if ch != -1 {
                            st.ungetc();
                        }
                        let a = (first_unused as usize + 7) & !7;
                        first_unused = a as *mut u8;
                        let members = first_unused as *mut *mut c_char;
                        (*result).alias_members = members;
                        let mut c = (*result).alias_name as *mut u8;
                        for cnt in 0..(*result).alias_members_len {
                            c = c.add(c_strlen(c) + 1);
                            *members.add(cnt) = c as *mut c_char;
                        }
                        status = if (*result).alias_members_len == 0 { ST_RETURN } else { ST_SUCCESS };
                        break;
                    }
                    *first_unused.add(room_left - 1) = 0xff;
                    if !st.fgets(first_unused, room_left) {
                        line = first_unused;
                        *line = 0;
                        continue;
                    }
                    line = first_unused;
                    if *first_unused.add(room_left - 1) != 0xff {
                        return no_room();
                    }
                    cut_at_comment_or_newline(line);
                }
            }
            }
            if status != ST_NOTFOUND {
                break;
            }
        }
        status
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent_r(res: *mut aliasent, buf: *mut c_char, buflen: usize, result: *mut *mut aliasent) -> c_int {
    unsafe { db_get::<aliasent>(&raw mut ALIAS_DB, &ALIAS_NAMES, read_aliasf, res, buf, buflen, result) }
}

unsafe fn read_aliasf(f: &mut FileEnt, res: *mut aliasent, buf: *mut c_char, len: usize) -> i32 {
    unsafe {
        (*res).alias_local = 1;
        loop {
            let st = get_next_alias(&mut f.r, None, res, buf as *mut u8, len);
            if st != ST_RETURN {
                return st;
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname_r(name: *const c_char, res: *mut aliasent, buf: *mut c_char, buflen: usize, result: *mut *mut aliasent) -> c_int {
    unsafe {
        by_key(
            b"aliases",
            b"getaliasbyname_r",
            res,
            result,
            core::ptr::null_mut(),
            &|| {
                let mut r = match nss::open_db(Db::Aliases) {
                    Ok(r) => r,
                    Err(e) => return scan_status(core::ptr::null_mut(), Scan::Unavail(e)),
                };
                (*res).alias_local = 1;
                loop {
                    let st = get_next_alias(&mut r, Some(cbytes(name)), res, buf as *mut u8, buflen);
                    if st != ST_RETURN {
                        return st;
                    }
                }
            },
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut aliasent, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, res, buf, buflen, en)
            },
        )
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent() -> *mut aliasent {
    with_static_ent(&ALIASENT_S, |res, buf, cap, out| unsafe { getaliasent_r(res, buf, cap, out) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname(name: *const c_char) -> *mut aliasent {
    with_static(&ALIASENT_S, |res, buf, cap, out| unsafe { getaliasbyname_r(name, res, buf, cap, out) })
}

