use crate::inet;
use crate::types::*;
use crate::util::{Buf, Spin, eq_nocase};
use crate::wire::*;
use core::ffi::c_int;
use rusty_libc_core::syscall::{check, syscall1, syscall2, syscall3};

pub const MAXNS: usize = 3;
pub const MAXDNSRCH: usize = 6;
pub const MAXDNAME: usize = 1025;

pub const RES_INIT: u32 = 0x1;
pub const RES_DEBUG: u32 = 0x2;
pub const RES_USEVC: u32 = 0x8;
pub const RES_IGNTC: u32 = 0x20;
pub const RES_RECURSE: u32 = 0x40;
pub const RES_DEFNAMES: u32 = 0x80;
pub const RES_STAYOPEN: u32 = 0x100;
pub const RES_DNSRCH: u32 = 0x200;
pub const RES_NOALIASES: u32 = 0x1000;
pub const RES_USE_INET6: u32 = 0x2000;
pub const RES_ROTATE: u32 = 0x4000;
pub const RES_NOCHECKNAME: u32 = 0x8000;
pub const RES_USE_EDNS0: u32 = 0x100000;
pub const RES_SNGLKUP: u32 = 0x200000;
pub const RES_SNGLKUPREOP: u32 = 0x400000;
pub const RES_NOTLDQUERY: u32 = 0x1000000;
pub const RES_NORELOAD: u32 = 0x2000000;
pub const RES_TRUSTAD: u32 = 0x4000000;
pub const RES_NOAAAA: u32 = 0x8000000;
pub const RES_DEFAULT: u32 = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    pub family: c_int,
    pub addr: [u8; 16],
    pub port: u16,
    pub scope: u32,
}

impl Server {
    pub fn v4(a: [u8; 4], port: u16) -> Server {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&a);
        Server { family: AF_INET, addr, port, scope: 0 }
    }
    pub fn v6(addr: [u8; 16], port: u16, scope: u32) -> Server {
        Server { family: AF_INET6, addr, port, scope }
    }
}

#[derive(Clone, Copy)]
pub struct Config {
    pub servers: [Server; MAXNS],
    pub nservers: usize,
    pub search: [Buf<256>; MAXDNSRCH],
    pub nsearch: usize,
    pub ndots: u32,
    pub timeout_ms: u32,
    pub attempts: u32,
    pub options: u32,
}

impl Config {
    pub fn defaults() -> Config {
        let mut c = Config {
            servers: [Server::v4([127, 0, 0, 1], 53); MAXNS],
            nservers: 0,
            search: [Buf::new(); MAXDNSRCH],
            nsearch: 0,
            ndots: 1,
            timeout_ms: 5000,
            attempts: 2,
            options: RES_DEFAULT,
        };
        c.nservers = 0;
        c
    }

    pub fn with_servers(servers: &[Server]) -> Config {
        let mut c = Config::defaults();
        for (i, s) in servers.iter().take(MAXNS).enumerate() {
            c.servers[i] = *s;
            c.nservers = i + 1;
        }
        c
    }

    fn set_search_from_domain(&mut self, d: &[u8]) {
        if let Some(b) = Buf::<256>::from(d) {
            self.search[0] = b;
            self.nsearch = 1;
        }
    }

    pub fn parse(text: &[u8]) -> Config {
        let mut c = Config::defaults();
        let mut have_search = false;
        for raw in text.split(|&b| b == b'\n') {
            let mut f = crate::nss::fields(raw);
            let Some(key) = f.next() else { continue };
            if key[0] == b';' || key[0] == b'#' {
                continue;
            }
            if key == b"nameserver" {
                if c.nservers >= MAXNS {
                    continue;
                }
                if let Some(a) = f.next() {
                    if let Some(s) = parse_server(a) {
                        c.servers[c.nservers] = s;
                        c.nservers += 1;
                    }
                }
            } else if key == b"domain" {
                if let Some(d) = f.next() {
                    c.nsearch = 0;
                    c.set_search_from_domain(d);
                    have_search = true;
                }
            } else if key == b"search" {
                c.nsearch = 0;
                for d in f {
                    if c.nsearch >= MAXDNSRCH {
                        break;
                    }
                    if let Some(b) = Buf::<256>::from(d) {
                        c.search[c.nsearch] = b;
                        c.nsearch += 1;
                    }
                }
                have_search = true;
            } else if key == b"options" {
                for o in f {
                    c.apply_option(o);
                }
            }
        }
        if !have_search {
            c.default_domain();
        }
        c
    }

    fn default_domain(&mut self) {
        let mut un = [0u8; 390];
        if check(unsafe { syscall1(63, un.as_mut_ptr() as usize) }).is_err() {
            return;
        }
        let nodename = &un[65..130];
        let n = nodename.iter().position(|&b| b == 0).unwrap_or(65);
        if let Some(dot) = nodename[..n].iter().position(|&b| b == b'.') {
            let d = &nodename[dot + 1..n];
            if !d.is_empty() {
                self.set_search_from_domain(d);
            }
        }
    }

    pub fn apply_option(&mut self, o: &[u8]) {
        let num = |p: &[u8]| -> Option<u32> {
            let (v, used) = crate::nss::strtou32(p);
            if used == 0 { None } else { Some(v) }
        };
        if let Some(v) = o.strip_prefix(b"ndots:") {
            if let Some(n) = num(v) {
                self.ndots = n.min(15);
            }
        } else if let Some(v) = o.strip_prefix(b"timeout:") {
            if let Some(n) = num(v) {
                self.timeout_ms = n.min(30) * 1000;
            }
        } else if let Some(v) = o.strip_prefix(b"attempts:") {
            if let Some(n) = num(v) {
                self.attempts = n.min(5);
            }
        } else if o == b"rotate" {
            self.options |= RES_ROTATE;
        } else if o == b"use-vc" {
            self.options |= RES_USEVC;
        } else if o == b"edns0" {
            self.options |= RES_USE_EDNS0;
        } else if o == b"single-request" {
            self.options |= RES_SNGLKUP;
        } else if o == b"single-request-reopen" {
            self.options |= RES_SNGLKUPREOP;
        } else if o == b"no-aaaa" {
            self.options |= RES_NOAAAA;
        } else if o == b"no-check-names" {
            self.options |= RES_NOCHECKNAME;
        } else if o == b"no-tld-query" {
            self.options |= RES_NOTLDQUERY;
        } else if o == b"trust-ad" {
            self.options |= RES_TRUSTAD;
        } else if o == b"inet6" {
            self.options |= RES_USE_INET6;
        } else if o == b"debug" {
            self.options |= RES_DEBUG;
        } else if o == b"no-reload" {
            self.options |= RES_NORELOAD;
        }
    }

    pub fn finish(&mut self) {
        if self.nservers == 0 {
            self.servers[0] = Server::v4([127, 0, 0, 1], 53);
            self.nservers = 1;
        }
    }

    pub fn load(path: &Buf<320>) -> Config {
        let mut text = [0u8; 8192];
        let mut n = 0;
        if let Ok(mut r) = crate::nss::LineReader::open(path) {
            while let Some(l) = r.next_line() {
                if n + l.len() + 1 > text.len() {
                    break;
                }
                text[n..n + l.len()].copy_from_slice(l);
                text[n + l.len()] = b'\n';
                n += l.len() + 1;
            }
        }
        let mut c = Config::parse(&text[..n]);
        if let Some(ld) = crate::util::getenv(b"LOCALDOMAIN") {
            c.nsearch = 0;
            for d in crate::nss::fields(ld) {
                if c.nsearch >= MAXDNSRCH {
                    break;
                }
                if let Some(b) = Buf::<256>::from(d) {
                    c.search[c.nsearch] = b;
                    c.nsearch += 1;
                }
            }
        }
        if let Some(ro) = crate::util::getenv(b"RES_OPTIONS") {
            for o in crate::nss::fields(ro) {
                c.apply_option(o);
            }
        }
        c.finish();
        c
    }
}

fn parse_server(a: &[u8]) -> Option<Server> {
    if let Some(v) = inet::parse_ipv4(a) {
        return Some(Server::v4(v, 53));
    }
    let (addr_text, scope_text) = match a.iter().position(|&c| c == b'%') {
        Some(p) => (&a[..p], Some(&a[p + 1..])),
        None => (a, None),
    };
    let v = inet::parse_ipv6(addr_text)?;
    let scope = match scope_text {
        Some(s) => crate::ifaddrs::scope_id_from_text(s).unwrap_or(0),
        None => 0,
    };
    Some(Server::v6(v, 53, scope))
}

struct Cached {
    cfg: Option<Config>,
    sig: [u64; 3],
}

static DEFAULT: Spin<Cached> = Spin::new(Cached { cfg: None, sig: [0; 3] });

pub fn default_config() -> Config {
    let path = crate::nss::etc_path(b"/resolv.conf");
    let sig = crate::nss::file_sig(&path);
    let mut g = DEFAULT.lock();
    let stale = match &g.cfg {
        None => true,
        Some(c) => c.options & RES_NORELOAD == 0 && g.sig != sig,
    };
    if stale {
        g.cfg = Some(Config::load(&path));
        g.sig = sig;
    }
    g.cfg.unwrap_or_else(Config::defaults)
}

pub fn reset_default() {
    DEFAULT.lock().cfg = None;
}

pub fn set_default_config(c: Config) {
    let mut g = DEFAULT.lock();
    g.cfg = Some(c);
    if let Some(cfg) = g.cfg.as_mut() {
        cfg.options |= RES_NORELOAD;
    }
}

fn now_ms() -> u64 {
    let mut ts = [0i64; 2];
    unsafe { syscall2(228, 1, ts.as_mut_ptr() as usize) };
    ts[0] as u64 * 1000 + ts[1] as u64 / 1_000_000
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    let r = unsafe { rusty_libc_core::syscall::syscall3(318, b.as_mut_ptr() as usize, 2, 0) };
    if check(r).is_err() {
        let t = now_ms() as u16;
        return t ^ 0x5a5a;
    }
    u16::from_ne_bytes(b)
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

fn poll1(fd: c_int, events: i16, ms: u64) -> Result<i16, i32> {
    let mut p = PollFd { fd, events, revents: 0 };
    let r = unsafe { syscall3(7, &mut p as *mut PollFd as usize, 1, ms.min(i32::MAX as u64) as usize) };
    match check(r) {
        Ok(0) => Ok(0),
        Ok(_) => Ok(p.revents),
        Err(e) if e.0 == EINTR => Ok(0),
        Err(e) => Err(e.0),
    }
}

fn close(fd: c_int) {
    let _ = rusty_libc_core::unistd::close(fd);
}

fn sockaddr_of(s: &Server, out: &mut sockaddr_storage) -> socklen_t {
    *out = sockaddr_storage::default();
    unsafe {
        if s.family == AF_INET {
            let p = out as *mut sockaddr_storage as *mut sockaddr_in;
            (*p).sin_family = AF_INET as u16;
            (*p).sin_port = s.port.to_be();
            (*p).sin_addr.s_addr = u32::from_ne_bytes([s.addr[0], s.addr[1], s.addr[2], s.addr[3]]);
            16
        } else {
            let p = out as *mut sockaddr_storage as *mut sockaddr_in6;
            (*p).sin6_family = AF_INET6 as u16;
            (*p).sin6_port = s.port.to_be();
            (*p).sin6_addr.s6_addr = s.addr;
            (*p).sin6_scope_id = s.scope;
            28
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendErr {
    Timeout,
    Refused,
    Other(i32),
}

fn question_matches(q: &[u8], a: &[u8]) -> bool {
    match (first_question::<256>(q), first_question::<256>(a)) {
        (Some((qn, qt, qc)), Some((an, at, ac))) => qt == at && qc == ac && same_name(qn.as_bytes(), an.as_bytes()),
        _ => false,
    }
}

fn udp_exchange(s: &Server, q: &[u8], ans: &mut [u8], ms: u64) -> Result<usize, SendErr> {
    let fd = unsafe { crate::sock::socket(s.family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(SendErr::Other(rusty_libc_core::errno::get()));
    }
    let mut ss = sockaddr_storage::default();
    let len = sockaddr_of(s, &mut ss);
    if unsafe { crate::sock::connect(fd, &ss as *const _ as *const sockaddr, len) } < 0 {
        let e = rusty_libc_core::errno::get();
        close(fd);
        return Err(if e == ECONNREFUSED { SendErr::Refused } else { SendErr::Other(e) });
    }
    let r = (|| {
        if unsafe { crate::sock::send(fd, q.as_ptr() as *const _, q.len(), 0) } < 0 {
            let e = rusty_libc_core::errno::get();
            return Err(if e == ECONNREFUSED { SendErr::Refused } else { SendErr::Other(e) });
        }
        let qid = get16(q, 0).unwrap_or(0);
        let deadline = now_ms() + ms;
        loop {
            let now = now_ms();
            if now >= deadline {
                return Err(SendErr::Timeout);
            }
            match poll1(fd, 1, deadline - now) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(e) => return Err(SendErr::Other(e)),
            }
            let n = unsafe { crate::sock::recv(fd, ans.as_mut_ptr() as *mut _, ans.len(), 0) };
            if n < 0 {
                let e = rusty_libc_core::errno::get();
                if e == EAGAIN {
                    continue;
                }
                return Err(if e == ECONNREFUSED { SendErr::Refused } else { SendErr::Other(e) });
            }
            let n = n as usize;
            if n < HFIXEDSZ || get16(ans, 0) != Some(qid) || ans[2] & 0x80 == 0 || !question_matches(q, &ans[..n]) {
                continue;
            }
            return Ok(n);
        }
    })();
    close(fd);
    r
}

fn tcp_exchange(s: &Server, q: &[u8], ans: &mut [u8], ms: u64) -> Result<usize, SendErr> {
    let fd = unsafe { crate::sock::socket(s.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(SendErr::Other(rusty_libc_core::errno::get()));
    }
    let deadline = now_ms() + ms;
    let r = (|| {
        let mut ss = sockaddr_storage::default();
        let len = sockaddr_of(s, &mut ss);
        if unsafe { crate::sock::connect(fd, &ss as *const _ as *const sockaddr, len) } < 0 {
            let e = rusty_libc_core::errno::get();
            if e != EINPROGRESS {
                return Err(if e == ECONNREFUSED { SendErr::Refused } else { SendErr::Other(e) });
            }
            let now = now_ms();
            if now >= deadline || poll1(fd, 4, deadline - now).map_err(SendErr::Other)? == 0 {
                return Err(SendErr::Timeout);
            }
            let mut err: c_int = 0;
            let mut l: socklen_t = 4;
            unsafe { crate::sock::getsockopt(fd, SOL_SOCKET, SO_ERROR, &mut err as *mut c_int as *mut _, &mut l) };
            if err != 0 {
                return Err(if err == ECONNREFUSED { SendErr::Refused } else { SendErr::Other(err) });
            }
        }
        let mut msg = [0u8; 2 + 1232 + 512];
        if q.len() + 2 > msg.len() {
            return Err(SendErr::Other(EMSGSIZE));
        }
        put16(&mut msg, 0, q.len() as u16);
        msg[2..2 + q.len()].copy_from_slice(q);
        let mut off = 0;
        while off < q.len() + 2 {
            let now = now_ms();
            if now >= deadline {
                return Err(SendErr::Timeout);
            }
            poll1(fd, 4, deadline - now).map_err(SendErr::Other)?;
            let n = unsafe { crate::sock::send(fd, msg[off..].as_ptr() as *const _, q.len() + 2 - off, MSG_NOSIGNAL) };
            if n < 0 {
                let e = rusty_libc_core::errno::get();
                if e == EAGAIN {
                    continue;
                }
                return Err(SendErr::Other(e));
            }
            off += n as usize;
        }
        let recv_exact = |buf: &mut [u8]| -> Result<(), SendErr> {
            let mut got = 0;
            while got < buf.len() {
                let now = now_ms();
                if now >= deadline {
                    return Err(SendErr::Timeout);
                }
                poll1(fd, 1, deadline - now).map_err(SendErr::Other)?;
                let n = unsafe { crate::sock::recv(fd, buf[got..].as_mut_ptr() as *mut _, buf.len() - got, 0) };
                if n < 0 {
                    let e = rusty_libc_core::errno::get();
                    if e == EAGAIN {
                        continue;
                    }
                    return Err(SendErr::Other(e));
                }
                if n == 0 {
                    return Err(SendErr::Other(ECONNREFUSED));
                }
                got += n as usize;
            }
            Ok(())
        };
        let mut lb = [0u8; 2];
        recv_exact(&mut lb)?;
        let n = ((lb[0] as usize) << 8) | lb[1] as usize;
        if n < HFIXEDSZ {
            return Err(SendErr::Other(EMSGSIZE));
        }
        let keep = n.min(ans.len());
        recv_exact(&mut ans[..keep])?;
        if n > keep {
            let mut skip = [0u8; 256];
            let mut left = n - keep;
            while left > 0 {
                let c = left.min(skip.len());
                recv_exact(&mut skip[..c])?;
                left -= c;
            }
        }
        Ok(keep)
    })();
    close(fd);
    r
}

pub fn send_query(cfg: &Config, q: &[u8], ans: &mut [u8]) -> Result<usize, SendErr> {
    let ns = cfg.nservers.max(1);
    let mut last_err = SendErr::Timeout;
    let mut bad = [0u8; 4096];
    let mut bad_len = 0usize;
    let start = if cfg.options & RES_ROTATE != 0 { random_id() as usize % ns } else { 0 };
    for attempt in 0..cfg.attempts.max(1) {
        for k in 0..ns {
            let s = &cfg.servers[(start + k) % ns];
            let mut ms = (cfg.timeout_ms as u64) << attempt;
            if attempt > 0 {
                ms /= ns as u64;
            }
            let ms = ms.max(1);
            let r = if cfg.options & RES_USEVC != 0 { tcp_exchange(s, q, ans, ms) } else { udp_exchange(s, q, ans, ms) };
            let mut r = r;
            if let Ok(n) = r {
                if Header::parse(&ans[..n]).map(|h| h.truncated()).unwrap_or(false) && cfg.options & RES_IGNTC == 0 && cfg.options & RES_USEVC == 0 {
                    r = tcp_exchange(s, q, ans, ms.max(cfg.timeout_ms as u64));
                }
            }
            match r {
                Ok(n) => {
                    if cfg.options & RES_TRUSTAD == 0 && n >= 4 {
                        ans[3] &= !0x20;
                    }
                    let rc = Header::parse(&ans[..n]).map(|h| h.rcode()).unwrap_or(FORMERR);
                    if rc == SERVFAIL || rc == NOTIMP || rc == REFUSED {
                        bad[..n].copy_from_slice(&ans[..n]);
                        bad_len = n;
                        continue;
                    }
                    return Ok(n);
                }
                Err(e) => last_err = e,
            }
        }
    }
    if bad_len > 0 {
        ans[..bad_len].copy_from_slice(&bad[..bad_len]);
        return Ok(bad_len);
    }
    Err(last_err)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HErr {
    pub h: c_int,
    pub rcode: u8,
    pub refused_conn: bool,
}

pub fn query(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    let mut q = [0u8; 1500];
    let edns = cfg.options & RES_USE_EDNS0 != 0;
    let Some(ql) = build_query(random_id(), name, qtype, qclass, cfg.options & RES_RECURSE != 0, edns, &mut q) else {
        return Err(HErr { h: NO_RECOVERY, rcode: 0, refused_conn: false });
    };
    if cfg.options & RES_TRUSTAD != 0 {
        q[3] |= 0x20;
    }
    match send_query(cfg, &q[..ql], ans) {
        Ok(n) => classify(&ans[..n]).map(|_| n),
        Err(SendErr::Refused) => Err(HErr { h: TRY_AGAIN, rcode: 0, refused_conn: true }),
        Err(_) => Err(HErr { h: TRY_AGAIN, rcode: 0, refused_conn: false }),
    }
}

pub fn classify(ans: &[u8]) -> Result<(), HErr> {
    let Some(h) = Header::parse(ans) else {
        return Err(HErr { h: NO_RECOVERY, rcode: 0, refused_conn: false });
    };
    if h.rcode() != NOERROR || h.ancount == 0 {
        let herr = match h.rcode() {
            NXDOMAIN => HOST_NOT_FOUND,
            SERVFAIL => TRY_AGAIN,
            NOERROR => NO_DATA,
            _ => NO_RECOVERY,
        };
        return Err(HErr { h: herr, rcode: h.rcode(), refused_conn: false });
    }
    Ok(())
}

fn query_domain(cfg: &Config, name: &[u8], domain: Option<&[u8]>, qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    match domain {
        None => {
            query(cfg, name, qclass, qtype, ans)
        }
        Some(d) => {
            let mut full = Buf::<MAXDNAME>::new();
            let n = name.strip_suffix(b".").unwrap_or(name);
            let ok = full.push_all(n) && full.push(b'.') && full.push_all(d.strip_prefix(b".").unwrap_or(d));
            if !ok {
                return Err(HErr { h: NO_RECOVERY, rcode: 0, refused_conn: false });
            }
            query(cfg, full.as_bytes(), qclass, qtype, ans)
        }
    }
}

pub fn search(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    let dots = name.iter().filter(|&&c| c == b'.').count();
    let trailing = name.last() == Some(&b'.');
    if dots == 0 {
        if let Some(a) = crate::resdebug::host_alias(cfg.options as core::ffi::c_ulong, name) {
            return query(cfg, a.as_bytes(), qclass, qtype, ans);
        }
    }
    let mut saved: Option<HErr> = None;
    let mut got_nodata = false;
    let mut got_servfail = false;
    let mut tried_as_is = false;
    let mut searched = false;
    let mut last = HErr { h: HOST_NOT_FOUND, rcode: 0, refused_conn: false };
    if dots as u32 >= cfg.ndots || trailing {
        match query_domain(cfg, name, None, qclass, qtype, ans) {
            Ok(n) => return Ok(n),
            Err(e) => {
                if trailing {
                    return Err(e);
                }
                saved = Some(e);
                tried_as_is = true;
            }
        }
    }
    if (dots == 0 && cfg.options & RES_DEFNAMES != 0) || (dots > 0 && !trailing && cfg.options & RES_DNSRCH != 0) {
        let mut done = false;
        for i in 0..cfg.nsearch {
            if done {
                break;
            }
            searched = true;
            match query_domain(cfg, name, Some(cfg.search[i].as_bytes()), qclass, qtype, ans) {
                Ok(n) => return Ok(n),
                Err(e) => {
                    last = e;
                    if e.refused_conn {
                        return Err(HErr { h: TRY_AGAIN, ..e });
                    }
                    match e.h {
                        NO_DATA => got_nodata = true,
                        HOST_NOT_FOUND => {}
                        TRY_AGAIN if e.rcode == SERVFAIL => got_servfail = true,
                        _ => done = true,
                    }
                }
            }
            if cfg.options & RES_DNSRCH == 0 {
                done = true;
            }
        }
    }
    if (dots > 0 || !searched || cfg.options & RES_NOTLDQUERY == 0) && !tried_as_is {
        match query_domain(cfg, name, None, qclass, qtype, ans) {
            Ok(n) => return Ok(n),
            Err(e) => last = e,
        }
    }
    if let Some(s) = saved {
        return Err(s);
    }
    if got_nodata {
        return Err(HErr { h: NO_DATA, ..last });
    }
    if got_servfail {
        return Err(HErr { h: TRY_AGAIN, ..last });
    }
    Err(last)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub family: c_int,
    pub bytes: [u8; 16],
    pub scope: u32,
}

pub const MAX_ADDRS: usize = 64;

#[derive(Clone, Copy)]
pub struct HostData {
    pub n: usize,
    pub addrs: [Addr; MAX_ADDRS],
    pub canon: Buf<256>,
    pub have_canon: bool,
    pub aliases: Buf<1024>,
    pub naliases: usize,
    pub ttl: u32,
    pub fit: Option<(usize, usize)>,
    pub erange: bool,
    pub func: u8,
    pub h: i32,
    pub called: bool,
    pub any: bool,
    pub einval: bool,
    pub unavail: bool,
}

impl HostData {
    pub fn new() -> HostData {
        HostData {
            n: 0,
            addrs: [Addr { family: 0, bytes: [0; 16], scope: 0 }; MAX_ADDRS],
            canon: Buf::new(),
            have_canon: false,
            aliases: Buf::new(),
            naliases: 0,
            ttl: u32::MAX,
            fit: None,
            erange: false,
            func: 0,
            h: 0,
            called: false,
            any: false,
            einval: false,
            unavail: false,
        }
    }
    pub fn push(&mut self, a: Addr) {
        if self.n < MAX_ADDRS {
            self.addrs[self.n] = a;
            self.n += 1;
        }
    }
    pub fn add_alias(&mut self, name: &[u8]) {
        if self.aliases.push_all(name) && self.aliases.push(0) {
            self.naliases += 1;
        }
    }
}

impl Default for HostData {
    fn default() -> Self {
        Self::new()
    }
}

pub fn collect_addrs(ans: &[u8], qname: &[u8], qtype: u16, out: &mut HostData) {
    let Some((h, cur)) = Cursor::answers(ans) else { return };
    let mut cur = cur;
    let mut current = Buf::<256>::from(&qname[..qname.len().min(256)]).unwrap_or_default();
    for _ in 0..h.ancount {
        let Some(Some(rr)) = cur.next() else { break };
        let Some((owner, _)) = name_expand::<256>(ans, rr.name_off) else { continue };
        if rr.class != C_IN || !same_name(owner.as_bytes(), current.as_bytes()) {
            continue;
        }
        if rr.rtype == T_CNAME {
            if let Some((target, _)) = name_expand::<256>(ans, rr.rdata) {
                if !out.have_canon || !same_name(out.canon.as_bytes(), owner.as_bytes()) {
                }
                out.add_alias(owner.as_bytes());
                current = target;
                out.canon = target;
                out.have_canon = true;
            }
        } else if rr.rtype == qtype {
            let want = if qtype == T_A { 4 } else { 16 };
            if rr.rdlen == want {
                let mut b = [0u8; 16];
                b[..want].copy_from_slice(&ans[rr.rdata..rr.rdata + want]);
                out.push(Addr { family: if qtype == T_A { AF_INET } else { AF_INET6 }, bytes: b, scope: 0 });
                out.ttl = out.ttl.min(rr.ttl);
                if !out.have_canon {
                    out.canon = current;
                    out.have_canon = true;
                }
            }
        }
    }
}

pub fn collect_ptr(ans: &[u8], qname: &[u8]) -> Option<Buf<256>> {
    let (h, mut cur) = Cursor::answers(ans)?;
    let mut current = Buf::<256>::from(&qname[..qname.len().min(256)])?;
    for _ in 0..h.ancount {
        let Some(Some(rr)) = cur.next() else { break };
        let (owner, _) = name_expand::<256>(ans, rr.name_off)?;
        if rr.class != C_IN || !same_name(owner.as_bytes(), current.as_bytes()) {
            continue;
        }
        if rr.rtype == T_CNAME {
            current = name_expand::<256>(ans, rr.rdata)?.0;
        } else if rr.rtype == T_PTR {
            return Some(name_expand::<256>(ans, rr.rdata)?.0);
        }
    }
    None
}

pub fn lookup_host(cfg: &Config, name: &[u8], af: c_int, out: &mut HostData) -> Result<(), HErr> {
    let qtype = if af == AF_INET { T_A } else { T_AAAA };
    let mut ans = [0u8; 4096];
    let n = search(cfg, name, C_IN, qtype, &mut ans)?;
    let qn = first_question::<256>(&ans[..n]).map(|q| q.0).unwrap_or_default();
    let before = out.n;
    collect_addrs(&ans[..n], qn.as_bytes(), qtype, out);
    if out.n == before {
        return Err(HErr { h: NO_DATA, rcode: 0, refused_conn: false });
    }
    if !out.have_canon {
        out.canon = qn;
        out.have_canon = true;
    }
    Ok(())
}

pub fn reverse_name(family: c_int, addr: &[u8]) -> Buf<80> {
    let mut b = Buf::<80>::new();
    if family == AF_INET {
        for i in (0..4).rev() {
            b.push_u32(addr[i] as u32);
            b.push(b'.');
        }
        b.push_all(b"in-addr.arpa");
    } else {
        const D: &[u8; 16] = b"0123456789abcdef";
        for i in (0..16).rev() {
            b.push(D[(addr[i] & 15) as usize]);
            b.push(b'.');
            b.push(D[(addr[i] >> 4) as usize]);
            b.push(b'.');
        }
        b.push_all(b"ip6.arpa");
    }
    b
}

pub fn lookup_addr(cfg: &Config, family: c_int, addr: &[u8]) -> Result<Buf<256>, HErr> {
    let rn = reverse_name(family, addr);
    let mut ans = [0u8; 4096];
    let n = query(cfg, rn.as_bytes(), C_IN, T_PTR, &mut ans)?;
    collect_ptr(&ans[..n], rn.as_bytes()).ok_or(HErr { h: NO_DATA, rcode: 0, refused_conn: false })
}

pub fn net_name_query_refused(cfg: &Config, name: &[u8]) -> bool {
    let mut ans = [0u8; 1024];
    matches!(search(cfg, name, C_IN, T_PTR, &mut ans), Err(HErr { refused_conn: true, .. }))
}

pub fn net_addr_query_refused(cfg: &Config, net: u32) -> bool {
    let b = net.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(4);
    let mut q = Buf::<80>::new();
    match first {
        4 => {
            q.push_all(b"0.0.0.0");
        }
        _ => {
            for _ in 0..first {
                q.push_all(b"0.");
            }
            for i in (first..4).rev() {
                q.push_u32(b[i] as u32);
                if i != first {
                    q.push(b'.');
                }
            }
        }
    }
    q.push_all(b".in-addr.arpa");
    let mut ans = [0u8; 1024];
    matches!(query(cfg, q.as_bytes(), C_IN, T_PTR, &mut ans), Err(HErr { refused_conn: true, .. }))
}

#[allow(dead_code)]
fn _eq(a: &[u8], b: &[u8]) -> bool {
    eq_nocase(a, b)
}
