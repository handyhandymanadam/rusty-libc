#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::inet;
use crate::types::*;
use crate::util::{Buf, HeapVec, Spin, eq_nocase};
use crate::wire::*;
use core::ffi::c_int;
use rusty_libc_core::syscall::{check, syscall1, syscall3};

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
    pub fn other(family: c_int, bytes: [u8; 12], port: u16) -> Server {
        let mut addr = [0u8; 16];
        addr[..12].copy_from_slice(&bytes);
        Server { family, addr, port, scope: 0 }
    }
    pub fn usable(&self) -> bool {
        self.family == AF_INET || self.family == AF_INET6
    }
}

pub const MAXRESOLVSORT: usize = 10;

#[derive(Clone, Copy)]
pub struct Config {
    pub servers: [Server; MAXNS],
    pub nservers: usize,
    pub search: [Buf<256>; MAXDNSRCH],
    pub nsearch: usize,
    pub ndots: u32,
    pub timeout_ms: i64,
    pub attempts: i32,
    pub options: u32,
    pub sort: [(u32, u32); MAXRESOLVSORT],
    pub nsort: usize,
}

fn strtol_int(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && crate::util::is_space(s[i]) {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        i += 1;
    }
    let mut acc: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match acc.checked_mul(10).and_then(|v| v.checked_add((s[i] - b'0') as u64)) {
            Some(v) if v <= 1 << 63 => acc = v,
            _ => over = true,
        }
        i += 1;
    }
    let l: i64 = if neg {
        if over { i64::MIN } else { (acc as i64).wrapping_neg() }
    } else if over || acc > i64::MAX as u64 {
        i64::MAX
    } else {
        acc as i64
    };
    l as i32
}

fn glibc_words(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let first = s.iter().position(blank).unwrap_or(s.len());
    core::iter::once(&s[..first]).chain(s[first..].split(blank).filter(|w| !w.is_empty()))
}

const OPTION_TABLE: [(&[u8], u32); 11] = [
    (b"rotate", RES_ROTATE),
    (b"edns0", RES_USE_EDNS0),
    (b"single-request-reopen", RES_SNGLKUPREOP),
    (b"single-request", RES_SNGLKUP),
    (b"no_tld_query", RES_NOTLDQUERY),
    (b"no-tld-query", RES_NOTLDQUERY),
    (b"no-reload", RES_NORELOAD),
    (b"use-vc", RES_USEVC),
    (b"trust-ad", RES_TRUSTAD),
    (b"no-aaaa", RES_NOAAAA),
    (b"strict-error", RES_STRICTERR),
];

fn net_mask(addr_ne: u32) -> u32 {
    let i = u32::from_be(addr_ne);
    let m: u32 = if i & 0x8000_0000 == 0 {
        0xff00_0000
    } else if i & 0xc000_0000 == 0x8000_0000 {
        0xffff_0000
    } else {
        0xffff_ff00
    };
    m.to_be()
}

fn aton_exact(s: &[u8]) -> Option<u32> {
    match inet::parse_aton(s) {
        Some((a, used)) if used == s.len() => Some(u32::from_ne_bytes(a)),
        _ => None,
    }
}

struct Reader {
    c: Config,
    haveenv: bool,
    have_search: bool,
}

impl Reader {
    fn new(localdomain: Option<&[u8]>) -> Reader {
        let mut r = Reader { c: Config::defaults(), haveenv: false, have_search: false };
        if let Some(ld) = localdomain {
            let ld = &ld[..ld.iter().position(|&c| c == b'\n').unwrap_or(ld.len())];
            r.c.set_search(glibc_words(ld));
            r.haveenv = true;
            r.have_search = true;
        }
        r
    }

    fn line(&mut self, l: &[u8]) {
        let l = &l[..l.iter().position(|&c| c == 0).unwrap_or(l.len())];
        let l = l.strip_suffix(b"\n").unwrap_or(l);
        if l.first().is_some_and(|&c| c == b';' || c == b'#') {
            return;
        }
        let rest = |kw: &[u8]| -> Option<&[u8]> {
            let r = l.strip_prefix(kw)?;
            if matches!(r.first(), Some(b' ' | b'\t')) { Some(r) } else { None }
        };
        let skip_blanks = |s: &[u8]| -> usize { s.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(s.len()) };
        if let Some(r) = rest(b"domain") {
            let r = &r[skip_blanks(r)..];
            if self.haveenv || r.is_empty() {
                return;
            }
            let end = r.iter().position(|&c| c == b' ' || c == b'\t').unwrap_or(r.len());
            self.c.set_search(core::iter::once(&r[..end]));
            self.have_search = true;
        } else if let Some(r) = rest(b"search") {
            let r = &r[skip_blanks(r)..];
            if self.haveenv || r.is_empty() {
                return;
            }
            self.c.set_search(glibc_words(r));
            self.have_search = true;
        } else if let Some(r) = rest(b"nameserver") {
            let r = &r[skip_blanks(r)..];
            let a = &r[..r.iter().position(|&c| c == b' ' || c == b'\t').unwrap_or(r.len())];
            if self.c.nservers < MAXNS
                && let Some(s) = parse_server(a)
            {
                self.c.servers[self.c.nservers] = s;
                self.c.nservers += 1;
            }
        } else if let Some(r) = rest(b"sortlist") {
            self.sortlist(r);
        } else if let Some(r) = rest(b"options") {
            self.c.set_options(r);
        }
    }

    fn sortlist(&mut self, s: &[u8]) {
        let at = |i: usize| s.get(i).copied().unwrap_or(0);
        let word = |c: u8| c != 0 && c != b';' && c.is_ascii() && !crate::util::is_space(c);
        let mut i = 0;
        loop {
            while at(i) == b' ' || at(i) == b'\t' {
                i += 1;
            }
            if matches!(at(i), 0 | b'\n' | b';') {
                break;
            }
            let st = i;
            while word(at(i)) && at(i) != b'/' && at(i) != b'&' {
                i += 1;
            }
            let net = &s[st..i];
            if let Some(addr) = aton_exact(net) {
                let mut mask = net_mask(addr);
                if matches!(at(i), b'/' | b'&') {
                    i += 1;
                    let ms = i;
                    while word(at(i)) {
                        i += 1;
                    }
                    if let Some(m) = aton_exact(&s[ms..i]) {
                        mask = m;
                    }
                }
                if self.c.nsort < MAXRESOLVSORT {
                    self.c.sort[self.c.nsort] = (addr, mask);
                    self.c.nsort += 1;
                }
            }
            if !matches!(at(i), b' ' | b'\t' | 0 | b'\n' | b';') {
                break;
            }
        }
    }

    fn finish(mut self, res_options: Option<&[u8]>) -> Config {
        self.c.finish();
        if !self.have_search {
            self.c.default_domain();
        }
        if let Some(ro) = res_options {
            self.c.set_options(ro);
        }
        self.c
    }
}

impl Config {
    pub fn defaults() -> Config {
        Config {
            servers: [Server::v4([127, 0, 0, 1], 53); MAXNS],
            nservers: 0,
            search: [Buf::new(); MAXDNSRCH],
            nsearch: 0,
            ndots: 1,
            timeout_ms: 5000,
            attempts: 2,
            options: RES_DEFAULT,
            sort: [(0, 0); MAXRESOLVSORT],
            nsort: 0,
        }
    }

    pub fn with_servers(servers: &[Server]) -> Config {
        let mut c = Config::defaults();
        for (i, s) in servers.iter().take(MAXNS).enumerate() {
            c.servers[i] = *s;
            c.nservers = i + 1;
        }
        c
    }

    fn set_search<'a>(&mut self, words: impl Iterator<Item = &'a [u8]>) {
        self.nsearch = 0;
        let mut used = 0;
        for w in words {
            if self.nsearch >= MAXDNSRCH || used + w.len() + 1 > 256 {
                break;
            }
            let Some(b) = Buf::<256>::from(w) else { break };
            self.search[self.nsearch] = b;
            self.nsearch += 1;
            used += w.len() + 1;
        }
    }

    pub fn parse(text: &[u8]) -> Config {
        Config::parse_env(text, None, None)
    }

    pub fn parse_env(text: &[u8], localdomain: Option<&[u8]>, res_options: Option<&[u8]>) -> Config {
        let mut r = Reader::new(localdomain);
        for l in text.split(|&b| b == b'\n') {
            r.line(l);
        }
        r.finish(res_options)
    }

    fn default_domain(&mut self) {
        let mut un = [0u8; 390];
        if !uname(&mut un) {
            return;
        }
        let nodename = &un[65..130];
        let n = nodename.iter().position(|&b| b == 0).unwrap_or(65);
        if let Some(dot) = nodename[..n].iter().position(|&b| b == b'.') {
            let d = &nodename[dot + 1..n];
            self.set_search(core::iter::once(d));
        }
    }

    pub fn set_options(&mut self, s: &[u8]) {
        let blank = |c: u8| c == b' ' || c == b'\t';
        let mut i = 0;
        while i < s.len() {
            while i < s.len() && blank(s[i]) {
                i += 1;
            }
            let cp = &s[i..];
            if let Some(v) = cp.strip_prefix(b"ndots:") {
                let v = strtol_int(v);
                self.ndots = if v <= 15 { (v as u32) & 0xf } else { 15 };
            } else if let Some(v) = cp.strip_prefix(b"timeout:") {
                let v = strtol_int(v);
                self.timeout_ms = if v <= 30 { v as i64 * 1000 } else { 30_000 };
            } else if let Some(v) = cp.strip_prefix(b"attempts:") {
                let v = strtol_int(v);
                self.attempts = if v <= 5 { v } else { 5 };
            } else {
                let negate = cp.first() == Some(&b'-');
                if negate {
                    i += 1;
                }
                let cp = &s[i..];
                if let Some(&(_, flag)) = OPTION_TABLE.iter().find(|(name, _)| cp.starts_with(name)) {
                    if negate {
                        self.options &= !flag;
                    } else {
                        self.options |= flag;
                    }
                }
            }
            while i < s.len() && !blank(s[i]) {
                i += 1;
            }
        }
    }

    pub fn finish(&mut self) {
        if self.nservers == 0 {
            self.servers[0] = Server::v4([127, 0, 0, 1], 53);
            self.nservers = 1;
        }
    }

    pub fn load(path: &Buf<320>) -> Config {
        Config::load_from(path, None)
    }

    pub fn load_preinit(path: &Buf<320>, retrans: i32, retry: i32, options: u32) -> Config {
        Config::load_from(path, Some((retrans, retry, options)))
    }

    fn load_from(path: &Buf<320>, preinit: Option<(i32, i32, u32)>) -> Config {
        let mut r = Reader::new(crate::util::getenv(b"LOCALDOMAIN"));
        if let Some((retrans, retry, options)) = preinit {
            r.c.timeout_ms = retrans as i64 * 1000;
            r.c.attempts = retry;
            r.c.options = options & !RES_INIT;
        }
        if let Ok(mut lr) = crate::nss::LineReader::open(path) {
            while let Some(l) = lr.next_line() {
                r.line(l);
            }
        }
        r.finish(crate::util::getenv(b"RES_OPTIONS"))
    }
}

fn parse_server(a: &[u8]) -> Option<Server> {
    if a.is_empty() {
        return None;
    }
    if let Some(v) = aton_exact(a) {
        return Some(Server::v4(v.to_ne_bytes(), 53));
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
    generation: u64,
}

static DEFAULT: Spin<Cached> = Spin::new(Cached { cfg: None, sig: [0; 3], generation: 1 });

pub fn default_config() -> Config {
    default_config_gen().0
}

pub fn default_config_gen() -> (Config, u64) {
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
        g.generation += 1;
    }
    (g.cfg.unwrap_or_else(Config::defaults), g.generation)
}

pub fn reset_default() {
    let mut g = DEFAULT.lock();
    g.cfg = None;
    g.generation += 1;
}

pub fn set_default_config(c: Config) {
    let mut g = DEFAULT.lock();
    g.cfg = Some(c);
    g.generation += 1;
    if let Some(cfg) = g.cfg.as_mut() {
        cfg.options |= RES_NORELOAD;
    }
}

pub(crate) fn monotonic() -> [i64; 2] {
    let mut ts = [0i64; 2];
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(1, ts.as_mut_ptr().cast()) };
    ts
}

fn now_ms() -> u64 {
    let ts = monotonic();
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

pub(crate) fn uname(un: &mut [u8; 390]) -> bool {
    check(unsafe { syscall1(63, un.as_mut_ptr() as usize) }).is_ok()
}

fn sockaddr_of(s: &Server, out: &mut sockaddr_storage) -> socklen_t {
    if !s.usable() {
        *out = sockaddr_storage::default();
        out.ss_family = s.family as u16;
        out.__ss_padding[0..2].copy_from_slice(&s.port.to_be().to_ne_bytes());
        out.__ss_padding[2..14].copy_from_slice(&s.addr[..12]);
        return 28;
    }
    sockaddr_from(s.family, &s.addr, s.port.to_be(), s.scope, out)
}

pub(crate) fn sockaddr_from(family: c_int, addr: &[u8; 16], port_be: u16, scope: u32, out: &mut sockaddr_storage) -> socklen_t {
    *out = sockaddr_storage::default();
    let pad = &mut out.__ss_padding;
    pad[0..2].copy_from_slice(&port_be.to_ne_bytes());
    if family == AF_INET {
        out.ss_family = AF_INET as u16;
        pad[2..6].copy_from_slice(&addr[..4]);
        16
    } else {
        out.ss_family = AF_INET6 as u16;
        pad[6..22].copy_from_slice(addr);
        pad[22..26].copy_from_slice(&scope.to_ne_bytes());
        28
    }
}

pub(crate) fn sock_name(fd: c_int, out: &mut sockaddr_storage) -> c_int {
    sock_addr(fd, out, false)
}

fn sock_peer(fd: c_int, out: &mut sockaddr_storage) -> c_int {
    sock_addr(fd, out, true)
}

fn sock_addr(fd: c_int, out: &mut sockaddr_storage, peer: bool) -> c_int {
    let mut sl: socklen_t = core::mem::size_of::<sockaddr_storage>() as u32;
    let f: unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int = if peer { crate::sock::getpeername } else { crate::sock::getsockname };
    unsafe { f(fd, out as *mut sockaddr_storage as *mut sockaddr, &mut sl) }
}

pub(crate) fn sock_open(family: c_int, ty: c_int) -> c_int {
    crate::sock::socket(family, ty, 0)
}

pub(crate) fn sock_connect(fd: c_int, ss: &sockaddr_storage, len: socklen_t) -> c_int {
    debug_assert!(len as usize <= core::mem::size_of::<sockaddr_storage>());
    unsafe { crate::sock::connect(fd, ss as *const sockaddr_storage as *const sockaddr, len) }
}

fn sock_send(fd: c_int, b: &[u8], flags: c_int) -> isize {
    unsafe { crate::sock::send(fd, b.as_ptr() as *const _, b.len(), flags) }
}

fn sock_recv(fd: c_int, b: &mut [u8], flags: c_int) -> isize {
    unsafe { crate::sock::recv(fd, b.as_mut_ptr() as *mut _, b.len(), flags) }
}

fn so_error(fd: c_int) -> c_int {
    let mut err: c_int = 0;
    let mut l: socklen_t = 4;
    unsafe { crate::sock::getsockopt(fd, SOL_SOCKET, SO_ERROR, &mut err as *mut c_int as *mut _, &mut l) };
    err
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
    heap: crate::nss::ZBuf,
    can_grow: bool,
}

impl<'a> Answer<'a> {
    pub fn fixed(b: &'a mut [u8]) -> Answer<'a> {
        Answer { first: b, heap: crate::nss::ZBuf::new(), can_grow: false }
    }

    pub fn growable(b: &'a mut [u8]) -> Answer<'a> {
        Answer { first: b, heap: crate::nss::ZBuf::new(), can_grow: true }
    }

    pub fn buf(&mut self) -> &mut [u8] {
        if self.heap.is_empty() { self.first } else { self.heap.as_mut_slice() }
    }

    pub fn bytes(&self) -> &[u8] {
        if self.heap.is_empty() { self.first } else { self.heap.as_slice() }
    }

    pub fn kept(&self, n: usize) -> &[u8] {
        let b = self.bytes();
        &b[..n.min(b.len())]
    }

    fn may_grow(&self) -> bool {
        self.can_grow && self.heap.is_empty() && self.first.len() < MAXPACKET
    }

    fn room_for(&mut self, need: usize) -> bool {
        if need <= self.bytes().len() {
            return true;
        }
        if !self.may_grow() {
            return false;
        }
        if !self.heap.grow(MAXPACKET) {
            return false;
        }
        need <= MAXPACKET
    }
}

pub const RES_F_SNGLKUP: u32 = 0x0020_0000;
pub const RES_F_SNGLKUPREOP: u32 = 0x0040_0000;

const ECONNRESET: c_int = 104;
const EPIPE: c_int = 32;

const PACKETSZ: usize = 512;

pub(crate) fn server_ms(cfg: &Config, ns: usize) -> u64 {
    let t = cfg.timeout_ms;
    if t % 1000 == 0 {
        let mut secs = ((t / 1000) as i32).wrapping_shl(ns as u32);
        if ns > 0 {
            secs /= cfg.nservers.max(1) as i32;
        }
        secs.max(1) as u64 * 1000
    } else {
        let mut ms = (t.max(0) as u64) << ns;
        if ns > 0 {
            ms /= cfg.nservers.max(1) as u64;
        }
        ms.max(1)
    }
}

fn last_errno() -> c_int {
    rusty_libc_core::errno::get()
}

pub const RES_F_VC: u32 = 0x1;
pub const RES_F_CONN: u32 = 0x2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSocks {
    pub udp: [c_int; MAXNS],
    pub vc: c_int,
    pub vc_flags: u32,
    pub nscount: usize,
    pub has_ext: [bool; MAXNS],
    pub presend: Option<PreSend>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreSend {
    pub needclose: bool,
    pub fresh: bool,
    pub has_ext: [bool; MAXNS],
}

#[thread_local]
static LENT_SOCKS: core::cell::Cell<Option<StateSocks>> = core::cell::Cell::new(None);

pub fn lend_state_socks(k: StateSocks) -> Option<StateSocks> {
    LENT_SOCKS.replace(Some(k))
}

pub fn take_state_socks() -> Option<StateSocks> {
    LENT_SOCKS.take()
}

pub fn restore_state_socks(prev: Option<StateSocks>) {
    LENT_SOCKS.set(prev);
}

struct Socks {
    fd: [c_int; MAXNS],
    vc: c_int,
    vc_flags: u32,
    nscount: usize,
    has_ext: [bool; MAXNS],
    home: bool,
}

impl Socks {
    fn idle() -> Socks {
        Socks { fd: [-1; MAXNS], vc: -1, vc_flags: 0, nscount: 0, has_ext: [false; MAXNS], home: false }
    }

    fn begin(nscount: usize) -> Socks {
        let Some(mut k) = LENT_SOCKS.take() else {
            return Socks { fd: [-1; MAXNS], vc: -1, vc_flags: 0, nscount: nscount.min(MAXNS), has_ext: [true; MAXNS], home: false };
        };
        let mut s = Socks { fd: k.udp, vc: k.vc, vc_flags: k.vc_flags, nscount: k.nscount.min(MAXNS), has_ext: k.has_ext, home: true };
        if let Some(p) = k.presend.take() {
            if p.needclose {
                s.iclose();
            }
            if p.fresh {
                for fd in s.fd.iter_mut().take(s.nscount) {
                    *fd = -1;
                }
            }
            s.has_ext = p.has_ext;
        }
        s
    }

    fn open(&mut self, s: &Server, ns: usize) -> Result<c_int, Option<c_int>> {
        if self.fd[ns] != -1 {
            return Ok(self.fd[ns]);
        }
        if !s.usable() {
            return Err(Some(last_errno()));
        }
        let fd = sock_open(s.family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK);
        if fd < 0 {
            return Err(Some(last_errno()));
        }
        self.fd[ns] = fd;
        let mut ss = sockaddr_storage::default();
        let len = sockaddr_of(s, &mut ss);
        if sock_connect(fd, &ss, len) < 0 {
            self.iclose();
            return Err(None);
        }
        Ok(fd)
    }

    fn iclose(&mut self) {
        if self.vc >= 0 {
            close(self.vc);
            self.vc = -1;
            self.vc_flags &= !(RES_F_VC | RES_F_CONN);
        }
        for ns in 0..self.nscount {
            if self.has_ext[ns] && self.fd[ns] != -1 {
                close(self.fd[ns]);
                self.fd[ns] = -1;
            }
        }
    }
}

impl Drop for Socks {
    fn drop(&mut self) {
        if self.home {
            if self.vc >= 0 {
                set_nonblock(self.vc, false);
            }
            LENT_SOCKS.set(Some(StateSocks { udp: self.fd, vc: self.vc, vc_flags: self.vc_flags, nscount: self.nscount, has_ext: self.has_ext, presend: None }));
        } else {
            self.nscount = MAXNS;
            self.has_ext = [true; MAXNS];
            self.iclose();
            for fd in self.fd.iter_mut() {
                if *fd >= 0 {
                    close(*fd);
                    *fd = -1;
                }
            }
        }
    }
}

fn set_nonblock(fd: c_int, on: bool) {
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0o4000;
    let _ = rusty_libc_core::unistd::fcntl_int(fd, F_SETFL, if on { O_NONBLOCK } else { 0 });
}

fn peer_is(fd: c_int, s: &Server) -> bool {
    let mut peer = sockaddr_storage::default();
    if sock_peer(fd, &mut peer) < 0 {
        return false;
    }
    let mut want = sockaddr_storage::default();
    sockaddr_of(s, &mut want);
    let p = &peer.__ss_padding;
    let w = &want.__ss_padding;
    let mapped = |six: &[u8], four: &[u8]| six[6..18] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && six[18..22] == four[2..6];
    match (peer.ss_family as c_int, want.ss_family as c_int) {
        (a, b) if a == b => p[0..2] == w[0..2] && if a == AF_INET { p[2..6] == w[2..6] } else { p[6..22] == w[6..22] },
        (AF_INET6, AF_INET) => p[0..2] == w[0..2] && mapped(p, w),
        (AF_INET, _) => p[0..2] == w[0..2] && mapped(w, p),
        _ => false,
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
                    let r = sock_send(fd, q, MSG_NOSIGNAL);
                    if r == q.len() as isize {
                        nwritten += 1;
                        want_out = nwritten == 1 && pair && !single;
                        continue;
                    }
                    let e = last_errno();
                    if r >= 0 || (e != EINTR && e != EAGAIN) {
                        self.socks.iclose();
                        return Try::Next;
                    }
                }
                let now = now_ms();
                let rev = if now >= deadline { Ok(0) } else { poll1(fd, if want_out { 4 } else { 1 }, deadline - now) };
                let rev = match rev {
                    Ok(r) => r,
                    Err(_) => {
                        self.socks.iclose();
                        return Try::Next;
                    }
                };
                if rev != 0 {
                    rusty_libc_core::errno::set(0);
                }
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
                            self.socks.iclose();
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
                        let n = sock_recv(fd, &mut b[..0], MSG_PEEK | MSG_TRUNC);
                        if n > 0 {
                            ans.room_for(n as usize);
                        }
                    }
                    let buf = ans.buf();
                    let r = sock_recv(fd, buf, 0);
                    if r <= 0 {
                        let e = last_errno();
                        if r < 0 && (e == EINTR || e == EAGAIN) {
                            continue;
                        }
                        self.socks.iclose();
                        return Try::Next;
                    }
                    let n = r as usize;
                    self.gotsomewhere = true;
                    if n < HFIXEDSZ {
                        self.socks.iclose();
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
                        self.socks.iclose();
                        return Try::Next;
                    }
                    if opts & RES_IGNTC == 0 && h.truncated() {
                        self.socks.iclose();
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
                            self.socks.iclose();
                            fd = match self.socks.open(&s, ns) {
                                Ok(fd) => fd,
                                Err(Some(e)) => return Try::Fatal(e),
                                Err(None) => return Try::Next,
                            };
                        }
                    }
                    continue;
                }
                self.socks.iclose();
                return Try::Next;
            }
        }
    }

    fn vc(&mut self, ns: usize) -> Try {
        let s = self.cfg.servers[ns];
        let ms = server_ms(self.cfg, ns).max(self.cfg.timeout_ms.max(0) as u64);
        let pair = self.q2.is_some();
        let mut connreset = false;
        loop {
            if self.socks.vc >= 0 && self.socks.vc_flags & RES_F_VC != 0 && !peer_is(self.socks.vc, &s) {
                self.socks.iclose();
                self.socks.vc_flags &= !RES_F_VC;
            }
            let fresh = self.socks.vc < 0 || self.socks.vc_flags & RES_F_VC == 0;
            if fresh {
                if self.socks.vc >= 0 {
                    self.socks.iclose();
                }
                let fd = sock_open(s.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK);
                self.socks.vc = fd;
                if fd < 0 {
                    let e = last_errno();
                    self.terrno = e;
                    return Try::Fatal(e);
                }
            } else {
                set_nonblock(self.socks.vc, true);
            }
            let fd = self.socks.vc;
            let keep = if fresh { 0 } else { last_errno() };
            match self.vc_on(fd, &s, ms, pair, fresh) {
                Err(e) => {
                    self.terrno = e;
                    self.socks.iclose();
                    if e == ECONNRESET && !connreset {
                        connreset = true;
                        continue;
                    }
                    return Try::Next;
                }
                Ok((n1, n2)) => {
                    rusty_libc_core::errno::set(keep);
                    self.socks.vc_flags |= RES_F_VC;
                    return Try::Got(n1, n2);
                }
            }
        }
    }

    fn vc_on(&mut self, fd: c_int, s: &Server, ms: u64, pair: bool, connect: bool) -> Result<(usize, usize), c_int> {
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
        if connect {
            rusty_libc_core::errno::set(0);
        }
        if connect && sock_connect(fd, &ss, len) < 0 {
            let e = last_errno();
            if e != EINPROGRESS {
                return Err(e);
            }
            wait(4)?;
            let err = so_error(fd);
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
            let n = sock_send(fd, &msg[off..], MSG_NOSIGNAL);
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
                let n = sock_recv(fd, &mut buf[got..], 0);
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
        if self.cfg.nservers == 0 {
            return Err(SendErr::Other(ESRCH));
        }
        SEND_REACHED.set(true);
        let ns_count = self.cfg.nservers;
        self.socks = Socks::begin(ns_count);
        let opts = self.cfg.options;
        let mut v_circuit = opts & RES_USEVC != 0 || self.q1.len() > PACKETSZ || self.q2.is_some_and(|q| q.len() > PACKETSZ);
        self.terrno = ETIMEDOUT;
        let start = if opts & RES_ROTATE != 0 { random_id() as usize % ns_count } else { 0 };
        let tries = self.cfg.attempts;
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
                    if (v_circuit && opts & RES_USEVC == 0) || opts & RES_STAYOPEN == 0 {
                        self.socks.iclose();
                    }
                    return Ok((n1, n2));
                }
            }
            t += 1;
        }
        self.socks.iclose();
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

#[thread_local]
static SEND_REACHED: core::cell::Cell<bool> = core::cell::Cell::new(false);

pub fn reset_send_marks() {
    SEND_REACHED.set(false);
}

pub fn take_send_reached() -> bool {
    SEND_REACHED.replace(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFail {
    pub err: SendErr,
    pub bad: usize,
}

pub fn send_queries<'a>(cfg: &Config, q1: &[u8], q2: Option<&[u8]>, a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), SendFail> {
    let mut s = Send { cfg, q1, q2, a1, a2, flags, socks: Socks::idle(), gotsomewhere: false, terrno: ETIMEDOUT, bad: 0 };
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

pub fn mkquery_errno(q: &[u8]) {
    if q.get(HFIXEDSZ).is_some_and(|&l| l != 0) {
        rusty_libc_core::errno::set(ENOENT);
    }
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
    mkquery_errno(&q[..ql]);
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
        Err(SendErr::Other(e)) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: e }),
        Err(SendErr::Timeout) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: ETIMEDOUT }),
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
    mkquery_errno(&q1[..l1]);
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
                SendErr::Other(e) => e,
                SendErr::Timeout => ETIMEDOUT,
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
    let r = query_domain_1(name, domain, q);
    if let Err(e) = &r {
        set_search_herr(e.h);
    }
    r
}

#[thread_local]
static SEARCH_HERR: core::cell::Cell<c_int> = core::cell::Cell::new(0);

fn set_search_herr(h: c_int) {
    SEARCH_HERR.set(h);
    crate::strerr::set_h_errno(h);
}

pub fn search_herr() -> c_int {
    SEARCH_HERR.get()
}

fn query_domain_1<T>(name: &[u8], domain: Option<&[u8]>, q: &mut impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
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
    set_search_herr(HOST_NOT_FOUND);
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
    let mut root_on_list = false;
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
            let d = cfg.search[i].as_bytes();
            if d.strip_prefix(b".").unwrap_or(d).is_empty() {
                root_on_list = true;
            }
            match query_domain(name, Some(d), &mut q) {
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
    if (dots > 0 || !searched || cfg.options & RES_NOTLDQUERY == 0) && !(tried_as_is || root_on_list) {
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
    pub tryagain: bool,
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
            tryagain: false,
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
