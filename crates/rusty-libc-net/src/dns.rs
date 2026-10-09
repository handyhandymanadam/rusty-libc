use crate::inet;
use crate::types::*;
use crate::util::{Buf, HeapVec, Spin, eq_nocase};
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
pub const RES_USE_DNSSEC: u32 = 0x800000;
pub const RES_NOTLDQUERY: u32 = 0x1000000;
pub const RES_NORELOAD: u32 = 0x2000000;
pub const RES_TRUSTAD: u32 = 0x4000000;
pub const RES_NOAAAA: u32 = 0x8000000;
pub const RES_STRICTERR: u32 = 0x10000000;
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
    match (Header::parse(q), Header::parse(a)) {
        (Some(hq), Some(ha)) if hq.qdcount == ha.qdcount => {}
        _ => return false,
    }
    match (first_question::<256>(q), first_question::<256>(a)) {
        (Some((qn, qt, qc)), Some((an, at, ac))) => qt == at && qc == ac && same_name(qn.as_bytes(), an.as_bytes()),
        (Some(_), None) => true,
        _ => false,
    }
}

pub const MAXPACKET: usize = 65536;

pub struct Answer<'a> {
    first: &'a mut [u8],
    heap: *mut u8,
    can_grow: bool,
}

impl<'a> Answer<'a> {
    pub fn fixed(b: &'a mut [u8]) -> Answer<'a> {
        Answer { first: b, heap: core::ptr::null_mut(), can_grow: false }
    }

    pub fn growable(b: &'a mut [u8]) -> Answer<'a> {
        Answer { first: b, heap: core::ptr::null_mut(), can_grow: true }
    }

    pub fn buf(&mut self) -> &mut [u8] {
        if self.heap.is_null() { self.first } else { unsafe { core::slice::from_raw_parts_mut(self.heap, MAXPACKET) } }
    }

    pub fn bytes(&self) -> &[u8] {
        if self.heap.is_null() { self.first } else { unsafe { core::slice::from_raw_parts(self.heap, MAXPACKET) } }
    }

    pub fn kept(&self, n: usize) -> &[u8] {
        let b = self.bytes();
        &b[..n.min(b.len())]
    }

    fn may_grow(&self) -> bool {
        self.can_grow && self.heap.is_null() && self.first.len() < MAXPACKET
    }

    fn room_for(&mut self, need: usize) -> bool {
        if need <= self.bytes().len() {
            return true;
        }
        if !self.may_grow() {
            return false;
        }
        let p = unsafe { rusty_libc_malloc::malloc(MAXPACKET) } as *mut u8;
        if p.is_null() {
            return false;
        }
        self.heap = p;
        need <= MAXPACKET
    }
}

impl Drop for Answer<'_> {
    fn drop(&mut self) {
        if !self.heap.is_null() {
            unsafe { rusty_libc_malloc::free(self.heap as *mut core::ffi::c_void) };
        }
    }
}

pub const RES_F_SNGLKUP: u32 = 0x0020_0000;
pub const RES_F_SNGLKUPREOP: u32 = 0x0040_0000;

const ECONNRESET: c_int = 104;
const EPIPE: c_int = 32;

const PACKETSZ: usize = 512;

pub(crate) fn server_ms(cfg: &Config, ns: usize) -> u64 {
    let n = cfg.nservers.max(1) as u64;
    let t = cfg.timeout_ms as u64;
    if t.is_multiple_of(1000) {
        let mut secs = (t / 1000) << ns;
        if ns > 0 {
            secs /= n;
        }
        secs.max(1) * 1000
    } else {
        let mut ms = t << ns;
        if ns > 0 {
            ms /= n;
        }
        ms.max(1)
    }
}

fn last_errno() -> c_int {
    rusty_libc_core::errno::get()
}

struct Socks {
    fd: [c_int; MAXNS],
}

impl Socks {
    fn new() -> Socks {
        Socks { fd: [-1; MAXNS] }
    }

    fn open(&mut self, s: &Server, ns: usize) -> Result<c_int, Option<c_int>> {
        if self.fd[ns] >= 0 {
            return Ok(self.fd[ns]);
        }
        let fd = unsafe { crate::sock::socket(s.family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(Some(last_errno()));
        }
        let mut ss = sockaddr_storage::default();
        let len = sockaddr_of(s, &mut ss);
        if unsafe { crate::sock::connect(fd, &ss as *const _ as *const sockaddr, len) } < 0 {
            close(fd);
            return Err(None);
        }
        self.fd[ns] = fd;
        Ok(fd)
    }

    fn close_all(&mut self) {
        for fd in self.fd.iter_mut() {
            if *fd >= 0 {
                close(*fd);
                *fd = -1;
            }
        }
    }
}

impl Drop for Socks {
    fn drop(&mut self) {
        self.close_all();
    }
}

struct Send<'s, 'a> {
    cfg: &'s Config,
    q1: &'s [u8],
    q2: Option<&'s [u8]>,
    a1: &'s mut Answer<'a>,
    a2: &'s mut Answer<'a>,
    flags: &'s mut u32,
    socks: Socks,
    gotsomewhere: bool,
    terrno: c_int,
    bad: usize,
}

enum Try {
    Got(usize, usize),
    Next,
    Tcp,
    Fatal(c_int),
}

fn reply_to(q: &[u8], rid: u16, buf: &[u8], skip_match: bool) -> bool {
    get16(q, 0) == Some(rid) && (skip_match || question_matches(q, buf))
}

impl Send<'_, '_> {
    fn dg(&mut self, ns: usize) -> Try {
        let s = self.cfg.servers[ns];
        let ms = server_ms(self.cfg, ns);
        let opts = self.cfg.options;
        let mut single_reopen = opts & RES_SNGLKUPREOP != 0 || *self.flags & RES_F_SNGLKUPREOP != 0;
        let mut single = opts & RES_SNGLKUP != 0 || *self.flags & RES_F_SNGLKUP != 0 || single_reopen;
        let save_got = self.gotsomewhere;
        let (q1, q2) = (self.q1, self.q2);
        let pair = q2.is_some();
        let mut fd = match self.socks.open(&s, ns) {
            Ok(fd) => fd,
            Err(Some(e)) => return Try::Fatal(e),
            Err(None) => return Try::Next,
        };
        'round: loop {
            let deadline = now_ms() + ms;
            let mut nwritten = 0;
            let (mut recv1, mut recv2) = (false, !pair);
            let (mut n1, mut n2) = (0usize, 0usize);
            let mut want_out = true;
            loop {
                if want_out {
                    let q = if nwritten == 0 { q1 } else { q2.unwrap_or(&[]) };
                    let r = unsafe { crate::sock::send(fd, q.as_ptr() as *const _, q.len(), MSG_NOSIGNAL) };
                    if r == q.len() as isize {
                        nwritten += 1;
                        want_out = nwritten == 1 && pair && !single;
                        continue;
                    }
                    let e = last_errno();
                    if r >= 0 || (e != EINTR && e != EAGAIN) {
                        self.socks.close_all();
                        return Try::Next;
                    }
                }
                let now = now_ms();
                let rev = if now >= deadline { Ok(0) } else { poll1(fd, if want_out { 4 } else { 1 }, deadline - now) };
                let rev = match rev {
                    Ok(r) => r,
                    Err(_) => {
                        self.socks.close_all();
                        return Try::Next;
                    }
                };
                if rev == 0 {
                    if now_ms() < deadline {
                        continue;
                    }
                    if n1 > 1 && (recv1 || (pair && recv2)) {
                        if !single {
                            *self.flags |= RES_F_SNGLKUP;
                            single = true;
                            self.gotsomewhere = save_got;
                            continue 'round;
                        } else if !single_reopen {
                            *self.flags |= RES_F_SNGLKUPREOP;
                            single_reopen = true;
                            self.gotsomewhere = save_got;
                            self.socks.close_all();
                            fd = match self.socks.open(&s, ns) {
                                Ok(fd) => fd,
                                Err(Some(e)) => return Try::Fatal(e),
                                Err(None) => return Try::Next,
                            };
                            continue 'round;
                        }
                        return Try::Got(n1, 1);
                    }
                    self.gotsomewhere = true;
                    return Try::Next;
                }
                if rev & 4 != 0 && want_out {
                    continue;
                }
                if rev & 1 != 0 {
                    let first = !(recv1 || recv2) || !pair;
                    let ans: &mut Answer = if first { &mut *self.a1 } else { &mut *self.a2 };
                    if ans.may_grow() {
                        let mut b = [0u8; 1];
                        let n = unsafe { crate::sock::recv(fd, b.as_mut_ptr() as *mut _, 0, MSG_PEEK | MSG_TRUNC) };
                        if n > 0 {
                            ans.room_for(n as usize);
                        }
                    }
                    let buf = ans.buf();
                    let r = unsafe { crate::sock::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                    if r <= 0 {
                        let e = last_errno();
                        if r < 0 && (e == EINTR || e == EAGAIN) {
                            continue;
                        }
                        self.socks.close_all();
                        return Try::Next;
                    }
                    let n = r as usize;
                    self.gotsomewhere = true;
                    if n < HFIXEDSZ {
                        self.socks.close_all();
                        return Try::Next;
                    }
                    let got = &buf[..n];
                    let h = Header::parse(got).unwrap();
                    let rid = h.id;
                    let error = matches!(h.rcode(), SERVFAIL | NOTIMP | REFUSED);
                    let skip_match = n == HFIXEDSZ && h.qdcount == 0 && error;
                    let mut which = 0u8;
                    if !recv1 && reply_to(q1, rid, got, skip_match) {
                        which = 1;
                    }
                    if !recv2 && pair && reply_to(q2.unwrap_or(&[]), rid, got, skip_match) {
                        which = 2;
                    }
                    if which == 0 {
                        continue;
                    }
                    let useless = h.rcode() == NOERROR && h.ancount == 0 && h.flags & 0x0400 == 0 && h.flags & 0x0080 == 0 && h.arcount == 0;
                    if error || useless {
                        if first && error {
                            self.bad = n;
                        }
                        if opts & RES_STRICTERR == 0 {
                            if recv1 || (pair && recv2) {
                                return Try::Got(n1, 0);
                            }
                            if pair && !single {
                                n1 = 0;
                                if which == 1 {
                                    recv1 = true;
                                } else {
                                    recv2 = true;
                                }
                                continue;
                            }
                        }
                        self.socks.close_all();
                        return Try::Next;
                    }
                    if opts & RES_IGNTC == 0 && h.truncated() {
                        self.socks.close_all();
                        return Try::Tcp;
                    }
                    if first {
                        n1 = n;
                    } else {
                        n2 = n;
                    }
                    if which == 1 {
                        recv1 = true;
                    } else {
                        recv2 = true;
                    }
                    if recv1 && recv2 {
                        return Try::Got(n1, n2);
                    }
                    if single {
                        want_out = true;
                        if single_reopen {
                            self.socks.close_all();
                            fd = match self.socks.open(&s, ns) {
                                Ok(fd) => fd,
                                Err(Some(e)) => return Try::Fatal(e),
                                Err(None) => return Try::Next,
                            };
                        }
                    }
                    continue;
                }
                self.socks.close_all();
                return Try::Next;
            }
        }
    }

    fn vc(&mut self, ns: usize) -> Try {
        let s = self.cfg.servers[ns];
        let ms = server_ms(self.cfg, ns).max(self.cfg.timeout_ms as u64);
        let pair = self.q2.is_some();
        let mut connreset = false;
        'conn: loop {
            let fd = unsafe { crate::sock::socket(s.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
            if fd < 0 {
                let e = last_errno();
                self.terrno = e;
                return Try::Fatal(e);
            }
            let r = self.vc_on(fd, &s, ms, pair);
            close(fd);
            match r {
                Err(e) => {
                    self.terrno = e;
                    if e == ECONNRESET && !connreset {
                        connreset = true;
                        continue 'conn;
                    }
                    return Try::Next;
                }
                Ok((n1, n2)) => return Try::Got(n1, n2),
            }
        }
    }

    fn vc_on(&mut self, fd: c_int, s: &Server, ms: u64, pair: bool) -> Result<(usize, usize), c_int> {
        let deadline = now_ms() + ms;
        let wait = |ev: i16| -> Result<(), c_int> {
            let now = now_ms();
            if now >= deadline {
                return Err(ETIMEDOUT);
            }
            poll1(fd, ev, deadline - now).map(|_| ())
        };
        let mut ss = sockaddr_storage::default();
        let len = sockaddr_of(s, &mut ss);
        if unsafe { crate::sock::connect(fd, &ss as *const _ as *const sockaddr, len) } < 0 {
            let e = last_errno();
            if e != EINPROGRESS {
                return Err(e);
            }
            wait(4)?;
            let mut err: c_int = 0;
            let mut l: socklen_t = 4;
            unsafe { crate::sock::getsockopt(fd, SOL_SOCKET, SO_ERROR, &mut err as *mut c_int as *mut _, &mut l) };
            if err != 0 {
                return Err(err);
            }
            if now_ms() >= deadline {
                return Err(ETIMEDOUT);
            }
        }
        let mut msg = HeapVec::<u8>::new();
        for q in [Some(self.q1), self.q2].into_iter().flatten() {
            if !msg.extend_from(&(q.len() as u16).to_be_bytes()) || !msg.extend_from(q) {
                return Err(ENOMEM);
            }
        }
        let mut off = 0;
        while off < msg.len() {
            let n = unsafe { crate::sock::send(fd, msg[off..].as_ptr() as *const _, msg.len() - off, MSG_NOSIGNAL) };
            if n < 0 {
                let e = last_errno();
                if e == EAGAIN || e == EINTR {
                    wait(4)?;
                    continue;
                }
                return Err(e);
            }
            off += n as usize;
        }
        let read_exact = |buf: &mut [u8]| -> Result<(), c_int> {
            let mut got = 0;
            while got < buf.len() {
                let n = unsafe { crate::sock::recv(fd, buf[got..].as_mut_ptr() as *mut _, buf.len() - got, 0) };
                if n < 0 {
                    let e = last_errno();
                    if e == EAGAIN || e == EINTR {
                        wait(1)?;
                        continue;
                    }
                    return Err(e);
                }
                if n == 0 {
                    return Err(EPIPE);
                }
                got += n as usize;
            }
            Ok(())
        };
        let (id1, id2) = (get16(self.q1, 0), self.q2.and_then(|q| get16(q, 0)));
        let (mut recv1, mut recv2) = (false, !pair);
        let (mut n1, mut n2) = (0usize, 0usize);
        loop {
            let mut lb = [0u8; 2];
            read_exact(&mut lb)?;
            let rlen = u16::from_be_bytes(lb) as usize;
            let first = !(recv1 || recv2) || !pair;
            let ans: &mut Answer = if first { &mut *self.a1 } else { &mut *self.a2 };
            ans.room_for(rlen);
            let buf = ans.buf();
            let keep = rlen.min(buf.len());
            if keep < HFIXEDSZ {
                return Err(EMSGSIZE);
            }
            read_exact(&mut buf[..keep])?;
            if rlen > keep {
                buf[2] |= 0x02;
                let mut junk = [0u8; PACKETSZ];
                let mut left = rlen - keep;
                while left > 0 {
                    let c = left.min(junk.len());
                    if read_exact(&mut junk[..c]).is_err() {
                        break;
                    }
                    left -= c;
                }
            }
            let rid = get16(buf, 0);
            if first {
                n1 = rlen;
            } else {
                n2 = rlen;
            }
            if (recv1 || rid != id1) && (recv2 || rid != id2) {
                continue;
            }
            if !recv1 && rid == id1 {
                recv1 = true;
            } else {
                recv2 = true;
            }
            if recv1 && recv2 {
                return Ok((n1, n2));
            }
        }
    }

    fn run(&mut self) -> Result<(usize, usize), SendErr> {
        let ns_count = self.cfg.nservers.max(1);
        let opts = self.cfg.options;
        let mut v_circuit = opts & RES_USEVC != 0 || self.q1.len() > PACKETSZ || self.q2.is_some_and(|q| q.len() > PACKETSZ);
        self.terrno = ETIMEDOUT;
        let start = if opts & RES_ROTATE != 0 { random_id() as usize % ns_count } else { 0 };
        let tries = self.cfg.attempts.max(1);
        let mut t = 0;
        while t < tries {
            for shift in 0..ns_count {
                let ns = (start + shift) % ns_count;
                let got = loop {
                    if v_circuit {
                        t = tries;
                        match self.vc(ns) {
                            Try::Fatal(e) => return Err(SendErr::Other(e)),
                            Try::Got(n1, n2) if n1 != 0 || (self.q2.is_some() && n2 != 0) => break Some((n1, n2)),
                            _ => break None,
                        }
                    }
                    match self.dg(ns) {
                        Try::Fatal(e) => return Err(SendErr::Other(e)),
                        Try::Tcp => v_circuit = true,
                        Try::Got(n1, n2) if n1 != 0 || (self.q2.is_some() && n2 != 0) => break Some((n1, n2)),
                        _ => break None,
                    }
                };
                if let Some((n1, n2)) = got {
                    if opts & RES_TRUSTAD == 0 {
                        if n1 > HFIXEDSZ {
                            self.a1.buf()[3] &= !0x20;
                        }
                        if n2 > HFIXEDSZ {
                            self.a2.buf()[3] &= !0x20;
                        }
                    }
                    return Ok((n1, n2));
                }
            }
            t += 1;
        }
        Err(if v_circuit {
            match self.terrno {
                ECONNREFUSED => SendErr::Refused,
                ETIMEDOUT => SendErr::Timeout,
                e => SendErr::Other(e),
            }
        } else if self.gotsomewhere {
            SendErr::Timeout
        } else {
            SendErr::Refused
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFail {
    pub err: SendErr,
    pub bad: usize,
}

pub fn send_queries<'a>(cfg: &Config, q1: &[u8], q2: Option<&[u8]>, a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), SendFail> {
    let mut s = Send { cfg, q1, q2, a1, a2, flags, socks: Socks::new(), gotsomewhere: false, terrno: ETIMEDOUT, bad: 0 };
    let r = s.run();
    let bad = s.bad;
    r.map_err(|err| SendFail { err, bad })
}

pub fn send_query(cfg: &Config, q: &[u8], ans: &mut [u8]) -> Result<usize, SendErr> {
    send_query_ans(cfg, q, &mut Answer::fixed(ans))
}

pub fn send_query_ans(cfg: &Config, q: &[u8], ans: &mut Answer) -> Result<usize, SendErr> {
    let mut flags = 0u32;
    match send_queries(cfg, q, None, ans, &mut Answer::fixed(&mut []), &mut flags) {
        Ok((n, _)) => Ok(n),
        Err(f) if f.bad > 0 => Ok(f.bad),
        Err(f) => Err(f.err),
    }
}

pub fn send_query_noaaaa(cfg: &Config, q: &[u8], ans: &mut Answer) -> Option<Result<usize, SendErr>> {
    if cfg.options & RES_NOAAAA == 0 || q.len() <= HFIXEDSZ {
        return None;
    }
    let h = Header::parse(q)?;
    if h.is_response() || h.opcode() != 0 || h.rcode() != 0 || h.qdcount != 1 || h.ancount != 0 || h.nscount != 0 {
        return None;
    }
    const MAXCDNAME: usize = 255;
    let mut rep = [0u8; HFIXEDSZ + MAXCDNAME + 4];
    rep[..HFIXEDSZ].copy_from_slice(&q[..HFIXEDSZ]);
    put16(&mut rep, 10, 0);
    let used = name_unpack(q, HFIXEDSZ, &mut rep[HFIXEDSZ..HFIXEDSZ + MAXCDNAME])?;
    let after = HFIXEDSZ + used;
    if q.len() < after + 4 || q[after..after + 4] != [0, T_AAAA as u8, 0, C_IN as u8] {
        return None;
    }
    let qend = name_skip(&rep, HFIXEDSZ)?;
    rep[qend..qend + 4].copy_from_slice(&[0, T_A as u8, 0, C_IN as u8]);
    ans.buf().fill(0);
    let r = send_query_ans(cfg, &rep[..qend + 4], ans);
    let b = ans.buf();
    if let Some(a) = name_skip(b, HFIXEDSZ) {
        if b.len() >= a + 4 && b[a..a + 4] == [0, T_A as u8, 0, C_IN as u8] {
            b[a + 1] = T_AAAA as u8;
            put16(b, 6, 0);
            put16(b, 8, 0);
            put16(b, 10, 0);
            return Some(r.map(|_| a + 4));
        }
    }
    Some(r)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HErr {
    pub h: c_int,
    pub rcode: u8,
    pub errno: c_int,
}

impl HErr {
    pub fn refused(&self) -> bool {
        self.errno == ECONNREFUSED
    }
}

pub fn query(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    query_adv(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

pub fn query_in(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer) -> Result<usize, HErr> {
    query_ans(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

pub fn search_in(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer) -> Result<usize, HErr> {
    search_ans(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

pub fn query_adv(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8], advertise: usize) -> Result<usize, HErr> {
    query_ans(cfg, name, qclass, qtype, &mut Answer::fixed(ans), advertise)
}

pub fn query_ans(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer, advertise: usize) -> Result<usize, HErr> {
    let mut q = [0u8; 1500];
    let opt = if cfg.options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0 {
        Some(Opt { payload: edns_payload(advertise), dnssec_ok: cfg.options & RES_USE_DNSSEC != 0 })
    } else {
        None
    };
    let Some(ql) = build_query(random_id(), name, qtype, qclass, cfg.options & RES_RECURSE != 0, opt, &mut q) else {
        return Err(HErr { h: NO_RECOVERY, rcode: 0, errno: 0 });
    };
    if cfg.options & RES_TRUSTAD != 0 {
        q[3] |= 0x20;
    }
    let sent = match send_query_noaaaa(cfg, &q[..ql], ans) {
        Some(r) => r,
        None => send_query_ans(cfg, &q[..ql], ans),
    };
    match sent {
        Ok(n) => classify(ans.kept(n)).map(|_| n),
        Err(SendErr::Refused) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: ECONNREFUSED }),
        Err(SendErr::Other(e)) if e == EMFILE || e == ENFILE => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: e }),
        Err(_) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: ETIMEDOUT }),
    }
}

pub fn query_pair<'a>(cfg: &Config, name: &[u8], a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), HErr> {
    let opt = if cfg.options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0 {
        Some(Opt { payload: edns_payload(RESOLV_EDNS_BUFFER_SIZE), dnssec_ok: cfg.options & RES_USE_DNSSEC != 0 })
    } else {
        None
    };
    let (mut q1, mut q2) = ([0u8; 1500], [0u8; 1500]);
    let rd = cfg.options & RES_RECURSE != 0;
    let (Some(l1), Some(l2)) = (build_query(random_id(), name, T_A, C_IN, rd, opt, &mut q1), build_query(random_id(), name, T_AAAA, C_IN, rd, opt, &mut q2)) else {
        return Err(HErr { h: NO_RECOVERY, rcode: 0, errno: 0 });
    };
    if cfg.options & RES_TRUSTAD != 0 {
        q1[3] |= 0x20;
        q2[3] |= 0x20;
    }
    let (n1, n2) = match send_queries(cfg, &q1[..l1], Some(&q2[..l2]), a1, a2, flags) {
        Ok(n) => n,
        Err(f) => {
            let rcode = if f.bad > 0 { Header::parse(a1.kept(f.bad)).map(|h| h.rcode()).unwrap_or(0) } else { 0 };
            let errno = match f.err {
                SendErr::Refused => ECONNREFUSED,
                SendErr::Other(e) if e == EMFILE || e == ENFILE => e,
                _ => ETIMEDOUT,
            };
            return Err(HErr { h: TRY_AGAIN, rcode, errno });
        }
    };
    let h1 = if n1 >= HFIXEDSZ { Header::parse(a1.kept(n1)) } else { None };
    let h2 = if n2 >= HFIXEDSZ { Header::parse(a2.kept(n2)) } else { None };
    let (hp, hp2) = match (h1, h2) {
        (Some(x), Some(y)) => (x, y),
        (Some(x), None) | (None, Some(x)) => (x, x),
        (None, None) => return Err(HErr { h: NO_RECOVERY, rcode: 0, errno: 0 }),
    };
    let has_data = |h: &Header| h.rcode() == NOERROR && h.ancount != 0;
    if has_data(&hp) || has_data(&hp2) {
        return Ok((n1, n2));
    }
    let rcode = if hp.rcode() == NOERROR { hp2.rcode() } else { hp.rcode() };
    let h = match rcode {
        NXDOMAIN => HOST_NOT_FOUND,
        SERVFAIL => TRY_AGAIN,
        NOERROR => NO_DATA,
        _ => NO_RECOVERY,
    };
    Err(HErr { h, rcode, errno: 0 })
}

pub fn classify(ans: &[u8]) -> Result<(), HErr> {
    let Some(h) = Header::parse(ans) else {
        return Err(HErr { h: NO_RECOVERY, rcode: 0, errno: 0 });
    };
    if h.rcode() != NOERROR || h.ancount == 0 {
        let (herr, errno) = match h.rcode() {
            NXDOMAIN => (HOST_NOT_FOUND, 0),
            SERVFAIL | NOTIMP | REFUSED => (TRY_AGAIN, ETIMEDOUT),
            NOERROR => (NO_DATA, 0),
            _ => (NO_RECOVERY, 0),
        };
        return Err(HErr { h: herr, rcode: h.rcode(), errno });
    }
    Ok(())
}

fn query_domain<T>(name: &[u8], domain: Option<&[u8]>, q: &mut impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    match domain {
        None => {
            q(name)
        }
        Some(d) => {
            let mut full = Buf::<MAXDNAME>::new();
            let n = name.strip_suffix(b".").unwrap_or(name);
            let ok = full.push_all(n) && full.push(b'.') && full.push_all(d.strip_prefix(b".").unwrap_or(d));
            if !ok {
                return Err(HErr { h: NO_RECOVERY, rcode: 0, errno: 0 });
            }
            q(full.as_bytes())
        }
    }
}

pub fn search(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    search_adv(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

pub fn search_adv(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8], adv: usize) -> Result<usize, HErr> {
    search_ans(cfg, name, qclass, qtype, &mut Answer::fixed(ans), adv)
}

pub fn search_ans(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer, adv: usize) -> Result<usize, HErr> {
    search_with(cfg, name, |n: &[u8]| query_ans(cfg, n, qclass, qtype, ans, adv))
}

pub fn search_pair<'a>(cfg: &Config, name: &[u8], a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), HErr> {
    search_with(cfg, name, |n: &[u8]| query_pair(cfg, n, a1, a2, flags))
}

fn search_with<T>(cfg: &Config, name: &[u8], mut q: impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    let dots = name.iter().filter(|&&c| c == b'.').count();
    let trailing = name.last() == Some(&b'.');
    if dots == 0 {
        if let Some(a) = crate::resdebug::host_alias(cfg.options as core::ffi::c_ulong, name) {
            return q(a.as_bytes());
        }
    }
    let mut saved: Option<HErr> = None;
    let mut got_nodata = false;
    let mut got_servfail = false;
    let mut tried_as_is = false;
    let mut searched = false;
    let mut last = HErr { h: HOST_NOT_FOUND, rcode: 0, errno: 0 };
    if dots as u32 >= cfg.ndots || trailing {
        match query_domain(name, None, &mut q) {
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
            match query_domain(name, Some(cfg.search[i].as_bytes()), &mut q) {
                Ok(n) => return Ok(n),
                Err(e) => {
                    last = e;
                    if e.refused() {
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
        match query_domain(name, None, &mut q) {
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
        return Err(HErr { h: TRY_AGAIN, errno: ETIMEDOUT, ..last });
    }
    Err(last)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub family: c_int,
    pub bytes: [u8; 16],
    pub scope: u32,
}

pub struct HostData {
    pub n: usize,
    pub addrs: HeapVec<Addr>,
    pub canon: Buf<256>,
    pub have_canon: bool,
    pub aliases: HeapVec<u8>,
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
            addrs: HeapVec::new(),
            canon: Buf::new(),
            have_canon: false,
            aliases: HeapVec::new(),
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
        if self.addrs.push(a) {
            self.n += 1;
        }
    }
    pub fn add_alias(&mut self, name: &[u8]) {
        if self.aliases.extend_from(name) && self.aliases.push(0) {
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
    let n = search(cfg, name, C_IN, qtype, &mut ans)?.min(ans.len());
    let qn = first_question::<256>(&ans[..n]).map(|q| q.0).unwrap_or_default();
    let before = out.n;
    collect_addrs(&ans[..n], qn.as_bytes(), qtype, out);
    if out.n == before {
        return Err(HErr { h: NO_DATA, rcode: 0, errno: 0 });
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
    let n = query(cfg, rn.as_bytes(), C_IN, T_PTR, &mut ans)?.min(ans.len());
    collect_ptr(&ans[..n], rn.as_bytes()).ok_or(HErr { h: NO_DATA, rcode: 0, errno: 0 })
}

#[allow(dead_code)]
fn _eq(a: &[u8], b: &[u8]) -> bool {
    eq_nocase(a, b)
}
