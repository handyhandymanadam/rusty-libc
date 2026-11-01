//! The DNS client behind `res_query`, `gethostbyname` and `getaddrinfo`.
//!
//! A [`Config`] holds the name servers, search list and options; the process-wide default is read from
//! `/etc/resolv.conf` (reloaded when the file changes) with `LOCALDOMAIN` and `RES_OPTIONS` applied, and
//! any code can build a `Config` explicitly and use it with [`query`] or [`search`] (the unit tests point
//! one at a fake server on 127.0.0.1).
//!
//! Queries go out over UDP (one connected socket per server, the A and AAAA queries of a lookup as one pair, each try
//! timed by glibc's rule), fall back to TCP when the answer is truncated, and treat SERVFAIL, NOTIMP and
//! REFUSED as "try the next server" (see [`send_queries`]). Only plain DNS is spoken (A, AAAA, PTR, CNAME chains in answers);
//! no DNSSEC validation, no EDNS client subnet; an EDNS0 OPT record goes into a query only with the `edns0` option or
//! `RES_USE_DNSSEC` (which also sets the DO bit), advertising the answer buffer length clamped to 512..=1200.
//! Answers of the name service lookups may be up to 64 KiB ([`Answer`] grows onto the heap); `res_query` and friends use the
//! caller's buffer, cutting a longer answer as glibc does.
//!
//! Unsafe that stays: the system calls (uname, getrandom, poll, the vDSO clock, and the socket calls of [`crate::sock`]
//! wrapped below in small safe functions on slices) and the heap block of a grown [`Answer`].
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

// option bits (the values of glibc's RES_* flags, so res_state.options maps one to one)
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

/// One name server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    pub family: c_int,
    pub addr: [u8; 16],
    /// Port in host order.
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
    /// A resolver-state server slot of another family (0 with no IPv6 address, or a family glibc cannot use): `bytes` are
    /// the 12 bytes after family and port of its `sockaddr_in` (address and `sin_zero`), kept for a TCP connect.
    pub fn other(family: c_int, bytes: [u8; 12], port: u16) -> Server {
        let mut addr = [0u8; 16];
        addr[..12].copy_from_slice(&bytes);
        Server { family, addr, port, scope: 0 }
    }
    /// A family glibc's res_send can open a socket for.
    pub fn usable(&self) -> bool {
        self.family == AF_INET || self.family == AF_INET6
    }
}

/// Most `sortlist` entries the resolver state holds (MAXRESOLVSORT).
pub const MAXRESOLVSORT: usize = 10;

/// Resolver configuration.
#[derive(Clone, Copy)]
pub struct Config {
    pub servers: [Server; MAXNS],
    pub nservers: usize,
    pub search: [Buf<256>; MAXDNSRCH],
    pub nsearch: usize,
    /// As in `struct __res_state`: four bits (glibc stores `options ndots:N` there, so a negative N wraps).
    pub ndots: u32,
    /// Timeout of the first attempt per server, in milliseconds (`options timeout:N` is N seconds; glibc keeps N as an
    /// `int`, so it can be zero or negative: each try then waits one second, as glibc's send_dg does).
    pub timeout_ms: i64,
    /// Tries per server (`options attempts:N`; zero or negative: no query is sent, as with glibc).
    pub attempts: i32,
    pub options: u32,
    /// The `sortlist` (address, mask), both in network byte order; only copied into `_res` (glibc 2.43 uses it nowhere
    /// else outside its compatibility symbols).
    pub sort: [(u32, u32); MAXRESOLVSORT],
    pub nsort: usize,
}

/// glibc's `(int) strtol (s, NULL, 10)` in the C locale: leading white space, a sign, decimal digits (none: 0); a value
/// past `long` saturates and the cast keeps its low 32 bits.
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

/// The words of a `search` line or of `LOCALDOMAIN` as glibc splits them: the first word starts at the first byte (empty
/// when that is a blank), each later one at a non-blank after blanks; only space and tab separate.
fn glibc_words(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let first = s.iter().position(blank).unwrap_or(s.len());
    core::iter::once(&s[..first]).chain(s[first..].split(blank).filter(|w| !w.is_empty()))
}

/// glibc's option table of res_setoptions, in its order (the first name the option text starts with wins).
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

/// The classful mask of a `sortlist` address without one (glibc's net_mask), network byte order.
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

/// `inet_aton` that must use the whole text (glibc's `__inet_aton_exact`).
fn aton_exact(s: &[u8]) -> Option<u32> {
    match inet::parse_aton(s) {
        Some((a, used)) if used == s.len() => Some(u32::from_ne_bytes(a)),
        _ => None,
    }
}

/// glibc's res_vinit_1 state while reading resolv.conf: `LOCALDOMAIN` first (it makes the file's `domain` and `search`
/// lines ignored), the lines in order (`options` lines applied where they stand), then the local host as the server when
/// none was given, the host name's domain when there is no search list, and `RES_OPTIONS` last.
struct Reader {
    c: Config,
    /// LOCALDOMAIN was set.
    haveenv: bool,
    /// glibc's search list is not empty (it can be although nothing fit into `search`, see [`Config::set_search`]).
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

    /// One line of the file (with or without its newline).
    fn line(&mut self, l: &[u8]) {
        // glibc works on C strings
        let l = &l[..l.iter().position(|&c| c == 0).unwrap_or(l.len())];
        let l = l.strip_suffix(b"\n").unwrap_or(l);
        if l.first().is_some_and(|&c| c == b';' || c == b'#') {
            return;
        }
        // MATCH: the keyword, then a space or a tab
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

    /// The entries of a `sortlist` line: `addr[/mask]` or `addr[&mask]`, up to a `;`; an entry whose address does not
    /// parse is skipped, a mask that does not parse becomes the classful one.
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
                // nothing consumes this byte ('/' or '&' after an address that does not parse, a non-ASCII byte, or
                // \r \v \f): glibc 2.43 loops forever here; stop reading the line instead
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
    /// What glibc uses without a resolv.conf: the server on the local host, default options.
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

    /// Replace the search list with `words`, keeping what glibc's `_res` keeps: at most MAXDNSRCH names, stopping at
    /// the first that no longer fits (with its NUL) into the 256 bytes of `defdname`.
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

    /// Parse the text of a resolv.conf over the defaults (no environment), with the local host as the server when the
    /// text names none.
    pub fn parse(text: &[u8]) -> Config {
        Config::parse_env(text, None, None)
    }

    /// [`Config::parse`] with the values of `LOCALDOMAIN` and `RES_OPTIONS` given, in glibc's order (see [`Reader`]).
    pub fn parse_env(text: &[u8], localdomain: Option<&[u8]>, res_options: Option<&[u8]>) -> Config {
        let mut r = Reader::new(localdomain);
        for l in text.split(|&b| b == b'\n') {
            r.line(l);
        }
        r.finish(res_options)
    }

    /// The search list a missing `search`/`domain` gets: what follows the first dot of the host name (glibc keeps it even
    /// when empty).
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

    /// glibc 2.43's res_setoptions over `s` (an `options` line after the keyword, or `RES_OPTIONS`): words separated by
    /// spaces and tabs; `ndots:`, `timeout:` and `attempts:` take `strtol` of what follows (white space first allowed,
    /// so `ndots: 3` is 3) capped at 15, 30 and 5 but not raised (a negative value is kept as glibc keeps it); any other
    /// word is matched by prefix against glibc's table, a leading `-` clearing the flag instead of setting it; words
    /// glibc does not know (`debug`, `inet6`, `no-check-names`, ...) do nothing.
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

    /// Fill in the local host as the server when none was configured.
    pub fn finish(&mut self) {
        if self.nservers == 0 {
            self.servers[0] = Server::v4([127, 0, 0, 1], 53);
            self.nservers = 1;
        }
    }

    /// resolv.conf at `path` (NUL-terminated), with `LOCALDOMAIN` and `RES_OPTIONS` applied, as glibc's res_vinit_1.
    pub fn load(path: &Buf<320>) -> Config {
        Config::load_from(path, None)
    }

    /// [`Config::load`] starting from the values a program set in its state before `res_init` instead of the defaults
    /// (glibc 2.43 `resolv_conf_parser_init` with a preinit state): `retrans` seconds, `retry` tries and `options` (without
    /// `RES_INIT`); the file and `RES_OPTIONS` then apply over them as usual.
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

// ---------------------------------------------------------------- the process-wide default

struct Cached {
    cfg: Option<Config>,
    sig: [u64; 3], // inode, mtime sec, mtime nsec + size mix
    /// Bumped each time `cfg` is replaced: tells a state set up from an older (or a preinit) configuration that the
    /// process-wide one is another object now (glibc compares its `resolv_conf` pointers).
    generation: u64,
}

static DEFAULT: Spin<Cached> = Spin::new(Cached { cfg: None, sig: [0; 3], generation: 1 });

/// The process-wide configuration: resolv.conf read once and re-read when the file changes.
pub fn default_config() -> Config {
    default_config_gen().0
}

/// [`default_config`] and its generation (never 0, which marks a configuration that is not the process-wide one).
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

/// Drop the cached default (for `res_init` and tests).
pub fn reset_default() {
    let mut g = DEFAULT.lock();
    g.cfg = None;
    g.generation += 1;
}

/// Replace the process-wide default (the Rust API for programs that configure resolution themselves).
pub fn set_default_config(c: Config) {
    let mut g = DEFAULT.lock();
    g.cfg = Some(c);
    g.generation += 1;
    // a signature that never matches the file would reload it; pin the value by marking NORELOAD
    if let Some(cfg) = g.cfg.as_mut() {
        cfg.options |= RES_NORELOAD;
    }
}

// ---------------------------------------------------------------- sockets and time

/// CLOCK_MONOTONIC as (seconds, nanoseconds).
pub(crate) fn monotonic() -> [i64; 2] {
    let mut ts = [0i64; 2];
    // SAFETY: `ts` is a `struct timespec` (two 64-bit words) for the clock to write.
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(1, ts.as_mut_ptr().cast()) };
    ts
}

fn now_ms() -> u64 {
    let ts = monotonic();
    ts[0] as u64 * 1000 + ts[1] as u64 / 1_000_000
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    if getrandom2(&mut b).is_err() {
        let t = now_ms() as u16;
        return t ^ 0x5a5a;
    }
    u16::from_ne_bytes(b)
}

/// getrandom(2) into `b` (flags 0); on failure `b` may be partly written.
pub(crate) fn getrandom2(b: &mut [u8; 2]) -> Result<usize, rusty_libc_core::Errno> {
    // SAFETY: getrandom writes at most 2 bytes into `b`, which is 2 bytes long.
    check(unsafe { rusty_libc_core::syscall::syscall3(318, b.as_mut_ptr() as usize, 2, 0) })
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

/// Wait up to `ms` for `events`; returns revents (0 on timeout).
fn poll1(fd: c_int, events: i16, ms: u64) -> Result<i16, i32> {
    let mut p = PollFd { fd, events, revents: 0 };
    // SAFETY: `p` is one `struct pollfd` (layout matched by PollFd), and the count passed is 1.
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

/// `uname` into `un` (one `struct utsname`: six 65-byte fields; the node name is `un[65..130]`). False on failure.
pub(crate) fn uname(un: &mut [u8; 390]) -> bool {
    // SAFETY: uname writes one `struct utsname` (6 x 65 = 390 bytes) into `un`, which is that long.
    check(unsafe { syscall1(63, un.as_mut_ptr() as usize) }).is_ok()
}

fn sockaddr_of(s: &Server, out: &mut sockaddr_storage) -> socklen_t {
    if !s.usable() {
        // glibc's send_vc connects to the slot as it is, with the length of a sockaddr_in6 (family, port, then the slot's
        // address and sin_zero; glibc's last 12 bytes are whatever follows the slot in the state, zeros here)
        *out = sockaddr_storage::default();
        out.ss_family = s.family as u16;
        out.__ss_padding[0..2].copy_from_slice(&s.port.to_be().to_ne_bytes());
        out.__ss_padding[2..14].copy_from_slice(&s.addr[..12]);
        return 28;
    }
    sockaddr_from(s.family, &s.addr, s.port.to_be(), s.scope, out)
}

/// Fill `out` with the sockaddr_in (AF_INET: the first 4 bytes of `addr`) or sockaddr_in6 of an address; `port_be` is in
/// network order (as stored). Returns the length of that sockaddr.
pub(crate) fn sockaddr_from(family: c_int, addr: &[u8; 16], port_be: u16, scope: u32, out: &mut sockaddr_storage) -> socklen_t {
    *out = sockaddr_storage::default();
    // `__ss_padding` starts at byte 2 of the structure, right after the family: the offsets below are those of
    // sockaddr_in (port 2, address 4) and sockaddr_in6 (port 2, flow info 4, address 8, scope 24) minus 2.
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

/// `getsockname(fd, out)` with the whole of `out`: 0, or -1 with errno set.
pub(crate) fn sock_name(fd: c_int, out: &mut sockaddr_storage) -> c_int {
    sock_addr(fd, out, false)
}

/// `getpeername(fd, out)` with the whole of `out`: 0, or -1 with errno set.
fn sock_peer(fd: c_int, out: &mut sockaddr_storage) -> c_int {
    sock_addr(fd, out, true)
}

fn sock_addr(fd: c_int, out: &mut sockaddr_storage, peer: bool) -> c_int {
    let mut sl: socklen_t = core::mem::size_of::<sockaddr_storage>() as u32;
    let f: unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int = if peer { crate::sock::getpeername } else { crate::sock::getsockname };
    // SAFETY: `out` is writable for `sl` bytes (its size), `sl` is our local (getsockname and getpeername take the same).
    unsafe { f(fd, out as *mut sockaddr_storage as *mut sockaddr, &mut sl) }
}

/// `socket(family, ty, 0)`: the descriptor, or -1 with errno set.
pub(crate) fn sock_open(family: c_int, ty: c_int) -> c_int {
    crate::sock::socket(family, ty, 0)
}

/// `connect(fd, ss, len)` (len at most the size of `ss`): 0, or -1 with errno set.
pub(crate) fn sock_connect(fd: c_int, ss: &sockaddr_storage, len: socklen_t) -> c_int {
    debug_assert!(len as usize <= core::mem::size_of::<sockaddr_storage>());
    // SAFETY: `ss` is readable for `len` bytes (at most its size).
    unsafe { crate::sock::connect(fd, ss as *const sockaddr_storage as *const sockaddr, len) }
}

/// glibc's `__res_enable_icmp`: IP_RECVERR (AF_INET) or IPV6_RECVERR (AF_INET6) on `fd`; -1 with errno set on failure
/// (EAFNOSUPPORT for any other family).
fn enable_icmp(family: c_int, fd: c_int) -> c_int {
    const SOL_IP: c_int = 0;
    const IP_RECVERR: c_int = 11;
    const SOL_IPV6: c_int = 41;
    const IPV6_RECVERR: c_int = 25;
    const EAFNOSUPPORT: c_int = 97;
    let (level, name) = match family {
        AF_INET => (SOL_IP, IP_RECVERR),
        AF_INET6 => (SOL_IPV6, IPV6_RECVERR),
        _ => {
            rusty_libc_core::errno::set(EAFNOSUPPORT);
            return -1;
        }
    };
    let one: c_int = 1;
    // SAFETY: `one` is a readable 4-byte int and the length says 4.
    unsafe { crate::sock::setsockopt(fd, level, name, &one as *const c_int as *const _, 4) }
}

/// `send(fd, b, flags)`: bytes sent, or -1 with errno set.
fn sock_send(fd: c_int, b: &[u8], flags: c_int) -> isize {
    // SAFETY: `b` is readable for its length.
    unsafe { crate::sock::send(fd, b.as_ptr() as *const _, b.len(), flags) }
}

/// `recv(fd, b, flags)` into all of `b`: bytes received, or -1 with errno set.
fn sock_recv(fd: c_int, b: &mut [u8], flags: c_int) -> isize {
    // SAFETY: `b` is writable for its length.
    unsafe { crate::sock::recv(fd, b.as_mut_ptr() as *mut _, b.len(), flags) }
}

/// The pending SO_ERROR of `fd` (0 when there is none or it cannot be read).
fn so_error(fd: c_int) -> c_int {
    let mut err: c_int = 0;
    let mut l: socklen_t = 4;
    // SAFETY: `err` is a 4-byte int and `l` says 4.
    unsafe { crate::sock::getsockopt(fd, SOL_SOCKET, SO_ERROR, &mut err as *mut c_int as *mut _, &mut l) };
    err
}

/// Why a send failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendErr {
    Timeout,
    Refused,
    Other(i32),
}

/// Is `a` the answer to `q`? The question counts must agree; a question in the answer that cannot be read (an answer cut
/// to a small caller buffer) counts as matching, as in glibc's check.
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

/// glibc's largest answer (MAXPACKET): the size a growable answer buffer grows to.
pub const MAXPACKET: usize = 65536;

/// The buffer an answer is received into. Fixed: the caller's, and a longer answer is cut to it (`res_nquery` and the other
/// functions with a caller's buffer). Growable: the caller's to begin with, replaced by a heap block of [`MAXPACKET`] bytes
/// when an answer does not fit (the name service lookups, as glibc's nss_dns module lets `res_send` grow its buffer). The
/// heap block is freed with the `Answer`.
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

    /// The whole buffer (its length is the room for an answer).
    pub fn buf(&mut self) -> &mut [u8] {
        if self.heap.is_empty() { self.first } else { self.heap.as_mut_slice() }
    }

    /// The whole buffer, to read an answer of a known length from.
    pub fn bytes(&self) -> &[u8] {
        if self.heap.is_empty() { self.first } else { self.heap.as_slice() }
    }

    /// The part of an answer of length `n` (as [`send_query`] reports it) that the buffer holds.
    pub fn kept(&self, n: usize) -> &[u8] {
        let b = self.bytes();
        &b[..n.min(b.len())]
    }

    /// Will the next answer go to a buffer that is still to grow?
    fn may_grow(&self) -> bool {
        self.can_grow && self.heap.is_empty() && self.first.len() < MAXPACKET
    }

    /// Make room for an answer of `need` bytes (the contents are not kept); true if it now fits whole.
    fn room_for(&mut self, need: usize) -> bool {
        if need <= self.bytes().len() {
            return true;
        }
        if !self.may_grow() {
            return false;
        }
        // the heap block (zeroed, freed with the Answer)
        if !self.heap.grow(MAXPACKET) {
            return false;
        }
        need <= MAXPACKET
    }
}

/// glibc's private copies of RES_SNGLKUP and RES_SNGLKUPREOP in the resolver state's `_flags`: set when a server let a
/// pair of queries time out after answering one, so that later lookups of the thread send one query at a time.
pub const RES_F_SNGLKUP: u32 = 0x0020_0000;
pub const RES_F_SNGLKUPREOP: u32 = 0x0040_0000;

const ECONNRESET: c_int = 104;
const EPIPE: c_int = 32;

/// The largest query sent over UDP; a longer one goes over TCP (PACKETSZ).
const PACKETSZ: usize = 512;

/// How long one server gets for one try (glibc's rule: `retrans << ns`, divided by the number of servers for the servers
/// after the first, at least one second). With a timeout in whole seconds (any configuration from resolv.conf or the
/// resolver state) it is glibc's arithmetic exactly; a finer timeout (tests) follows the same rule in milliseconds.
pub(crate) fn server_ms(cfg: &Config, ns: usize) -> u64 {
    let t = cfg.timeout_ms;
    if t % 1000 == 0 {
        // glibc's `int seconds = retrans << ns` (wrapping, as its x86-64 code does), the division, then at least 1
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

/// glibc's private `_flags` bits for the TCP connection in a resolver state (resolv/resolv-internal.h): RES_F_VC set while
/// `_vcsock` is connected to a server, RES_F_CONN (cleared with it).
pub const RES_F_VC: u32 = 0x1;
pub const RES_F_CONN: u32 = 0x2;

/// The sockets glibc keeps in a resolver state (`_u._ext.nssocks`, `_vcsock` and its `_flags` bits), lent to the sends of
/// one lookup on that state ([`lend_state_socks`], [`take_state_socks`]): a send uses and leaves them as glibc's res_send
/// does (kept after an answer under RES_STAYOPEN, closed by its `__res_iclose` otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSocks {
    /// `_u._ext.nssocks`
    pub udp: [c_int; MAXNS],
    /// `_vcsock`
    pub vc: c_int,
    /// The RES_F_VC and RES_F_CONN bits of `_flags`.
    pub vc_flags: u32,
    /// `nscount` (at most MAXNS): `__res_iclose` looks at the server slots below it.
    pub nscount: usize,
    /// Which of those slots have an `_u._ext.nsaddrs` address (`__res_iclose` closes only their sockets).
    pub has_ext: [bool; MAXNS],
    /// What glibc's res_send does to the state before its first socket, still to do (None once a send of the lookup got
    /// past the "no name server" check and made its copy of the servers).
    pub presend: Option<PreSend>,
    /// The blocks the sends got for the `_ext` copies of the servers (see [`PreSend::alloc`]), for `resolv::sync_ext`.
    pub ext: [*mut sockaddr_in6; MAXNS],
}

/// The start of glibc 2.43's `__res_context_send` on the state's sockets (computed from the state when it is lent, done by
/// the first send of the lookup that gets that far): `needclose` (its copy of the servers is stale: `__res_iclose`),
/// `fresh` (a new copy is made: every slot's `nssocks` entry is set to -1 without a close), `has_ext` (the slots with an
/// `nsaddrs` address after that copy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreSend {
    pub needclose: bool,
    pub fresh: bool,
    pub has_ext: [bool; MAXNS],
    /// The slots whose copy needs a new block (`nsaddrs` NULL): glibc's res_send mallocs it, in slot order, and fails
    /// (-1, errno ENOMEM) when it gets none, leaving the copy unfinished, so the next send tries again.
    pub alloc: [bool; MAXNS],
}

/// The sockets of the state the current lookup runs on (None: no state, the sockets of a send are closed when it ends).
#[thread_local]
static LENT_SOCKS: core::cell::Cell<Option<StateSocks>> = core::cell::Cell::new(None);

/// Lend the sockets of the state a lookup is about to run on to its sends; returns what was lent before (a lookup on
/// another state that this one runs inside), to give back to [`restore_state_socks`] after [`take_state_socks`].
pub fn lend_state_socks(k: StateSocks) -> Option<StateSocks> {
    LENT_SOCKS.replace(Some(k))
}

/// The sockets lent by [`lend_state_socks`] as the lookup's sends left them (to be written back into the state).
pub fn take_state_socks() -> Option<StateSocks> {
    LENT_SOCKS.take()
}

/// Put back what [`lend_state_socks`] returned.
pub fn restore_state_socks(prev: Option<StateSocks>) {
    LENT_SOCKS.set(prev);
}

/// The sockets of one send: one UDP socket per server and the TCP connection, opened when first needed. A send on a
/// resolver state's sockets (lent, see [`StateSocks`]) leaves them to the state when it ends; any other send closes them.
struct Socks {
    fd: [c_int; MAXNS],
    vc: c_int,
    vc_flags: u32,
    nscount: usize,
    has_ext: [bool; MAXNS],
    /// The sockets are a state's (given back when the send ends).
    home: bool,
    /// The state's copy of the servers is still to be made by the next send (a block could not be allocated).
    presend: Option<PreSend>,
    ext: [*mut sockaddr_in6; MAXNS],
}

impl Socks {
    /// No sockets (a send that has not started).
    fn idle() -> Socks {
        Socks { fd: [-1; MAXNS], vc: -1, vc_flags: 0, nscount: 0, has_ext: [false; MAXNS], home: false, presend: None, ext: [core::ptr::null_mut(); MAXNS] }
    }

    /// The sockets of a send to `nscount` servers: the lent state's, after glibc's start of res_send ([`PreSend`]), or none.
    /// False with them when a block for the state's copy of the servers could not be allocated (the send fails with
    /// ENOMEM, errno set).
    fn begin(nscount: usize) -> (Socks, bool) {
        let Some(mut k) = LENT_SOCKS.take() else {
            let s = Socks { fd: [-1; MAXNS], vc: -1, vc_flags: 0, nscount: nscount.min(MAXNS), has_ext: [true; MAXNS], home: false, presend: None, ext: [core::ptr::null_mut(); MAXNS] };
            return (s, true);
        };
        let mut s = Socks { fd: k.udp, vc: k.vc, vc_flags: k.vc_flags, nscount: k.nscount.min(MAXNS), has_ext: k.has_ext, home: true, presend: None, ext: k.ext };
        if let Some(p) = k.presend.take() {
            if p.needclose {
                s.iclose();
            }
            // glibc's copy loop: each slot's nssocks entry -1, then its block (malloc when NULL); no block ends the send
            for ns in 0..s.nscount {
                if p.fresh {
                    s.fd[ns] = -1;
                }
                if p.alloc[ns] && s.ext[ns].is_null() {
                    s.ext[ns] = crate::resolv::ext_block();
                    if s.ext[ns].is_null() {
                        s.has_ext = core::array::from_fn(|i| k.has_ext[i] || !s.ext[i].is_null());
                        // the next send of the lookup starts the copy again (its copy count is still 0: no close)
                        s.presend = Some(PreSend { needclose: false, ..p });
                        rusty_libc_core::errno::set(ENOMEM);
                        return (s, false);
                    }
                }
            }
            s.has_ext = p.has_ext;
        }
        (s, true)
    }

    /// The server's socket: Ok(fd), Err(None) when it cannot be connected (try the next server), Err(Some(errno)) when no
    /// socket can be made (the send fails). glibc's reopen: a slot whose `nssocks` entry is not -1 is used as it is.
    fn open(&mut self, s: &Server, ns: usize) -> Result<c_int, Option<c_int>> {
        if self.fd[ns] != -1 {
            return Ok(self.fd[ns]);
        }
        // glibc's reopen: a family other than AF_INET and AF_INET6 gets no socket call, and the send fails with the errno left
        // from before (`*terrno = errno; return -1`): whatever the last failed call of this lookup, or the caller, left there
        if !s.usable() {
            return Err(Some(last_errno()));
        }
        let fd = sock_open(s.family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK);
        if fd < 0 {
            return Err(Some(last_errno()));
        }
        self.fd[ns] = fd;
        // glibc 2.43 (__res_enable_icmp): full ICMP error reporting on the socket, so every ICMP error the kernel gets
        // (host and network unreachable too, not only port unreachable) ends the wait on this server with POLLERR; the
        // error queue itself is never read. If the option cannot be set the sockets are closed and the send fails.
        if enable_icmp(s.family, fd) < 0 {
            let e = last_errno();
            self.iclose();
            rusty_libc_core::errno::set(e);
            return Err(Some(e));
        }
        let mut ss = sockaddr_storage::default();
        let len = sockaddr_of(s, &mut ss);
        if sock_connect(fd, &ss, len) < 0 {
            // glibc: `__res_iclose (statp, false); return 0`, which closes every socket of the state
            self.iclose();
            return Err(None);
        }
        Ok(fd)
    }

    /// glibc's `__res_iclose(statp, false)`: close the TCP connection (RES_F_VC and RES_F_CONN cleared) and the UDP socket
    /// of each server slot below `nscount` that has an `_ext` address.
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
            // glibc's connection is a blocking socket (ours is non-blocking while a send uses it)
            if self.vc >= 0 {
                set_nonblock(self.vc, false);
            }
            LENT_SOCKS.set(Some(StateSocks { udp: self.fd, vc: self.vc, vc_flags: self.vc_flags, nscount: self.nscount, has_ext: self.has_ext, presend: self.presend.take(), ext: self.ext }));
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

/// Set or clear O_NONBLOCK on a socket of ours (its other status flags are 0).
fn set_nonblock(fd: c_int, on: bool) {
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0o4000;
    let _ = rusty_libc_core::unistd::fcntl_int(fd, F_SETFL, if on { O_NONBLOCK } else { 0 });
}

/// Is the TCP socket `fd` still connected to `s` (glibc's send_vc: getpeername and `sock_eq`)?
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
        // same family: port and address (IPv4: 4 bytes at offset 2 of the padding; otherwise the IPv6 address at 6)
        (a, b) if a == b => p[0..2] == w[0..2] && if a == AF_INET { p[2..6] == w[2..6] } else { p[6..22] == w[6..22] },
        (AF_INET6, AF_INET) => p[0..2] == w[0..2] && mapped(p, w),
        (AF_INET, _) => p[0..2] == w[0..2] && mapped(w, p),
        _ => false,
    }
}

/// The state of one send of one or two queries: the replies go to `a1` and `a2` in the order they arrive.
struct Send<'s, 'a> {
    cfg: &'s Config,
    q1: &'s [u8],
    q2: Option<&'s [u8]>,
    a1: &'s mut Answer<'a>,
    a2: &'s mut Answer<'a>,
    /// The thread's sticky single-request flags (RES_F_SNGLKUP, RES_F_SNGLKUPREOP).
    flags: &'s mut u32,
    socks: Socks,
    /// Some server answered (a send that fails then says ETIMEDOUT, not ECONNREFUSED).
    gotsomewhere: bool,
    /// The errno of the last TCP failure.
    terrno: c_int,
    /// Length of the last SERVFAIL, NOTIMP or REFUSED reply left in `a1` (0: none).
    bad: usize,
}

/// What one try with one server gave.
enum Try {
    /// The replies: `n1` bytes in the first buffer, `n2` in the second (under HFIXEDSZ: no reply there).
    Got(usize, usize),
    /// Nothing usable: the next server.
    Next,
    /// A truncated reply: the same server over TCP.
    Tcp,
    /// No socket could be made: the send fails with this errno.
    Fatal(c_int),
}

/// Is the reply `buf` (id `rid`) the one to the query `q`?
fn reply_to(q: &[u8], rid: u16, buf: &[u8], skip_match: bool) -> bool {
    get16(q, 0) == Some(rid) && (skip_match || question_matches(q, buf))
}

impl Send<'_, '_> {
    /// One try over UDP with the server `ns` (glibc's send_dg).
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
        // a new round: everything sent again, both replies awaited again (after a switch to single-request mode)
        'round: loop {
            let deadline = now_ms() + ms;
            let mut nwritten = 0;
            let (mut recv1, mut recv2) = (false, !pair);
            let (mut n1, mut n2) = (0usize, 0usize);
            // waiting to send (POLLOUT) or to receive (POLLIN)
            let mut want_out = true;
            loop {
                if want_out {
                    // a connected UDP socket can nearly always take the query at once: send first, wait only if it cannot
                    let q = if nwritten == 0 { q1 } else { q2.unwrap_or(&[]) };
                    let r = sock_send(fd, q, MSG_NOSIGNAL);
                    if r == q.len() as isize {
                        nwritten += 1;
                        // the second query goes out right after the first, unless one at a time
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
                    // glibc's send_dg: `__set_errno (0)` after every poll that saw an event
                    rusty_libc_core::errno::set(0);
                }
                if rev == 0 {
                    if now_ms() < deadline {
                        continue; // interrupted
                    }
                    if n1 > 1 && (recv1 || (pair && recv2)) {
                        // one reply came and the other did not: servers and firewalls that cannot take two queries at
                        // once; ask again one query at a time, then also on a fresh socket for the second one
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
                    continue; // writable again: send at the top
                }
                if rev & 1 != 0 {
                    // the first reply to arrive goes to the first buffer, the other to the second
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
                    // some resolvers send an error without the question: a bare header
                    let skip_match = n == HFIXEDSZ && h.qdcount == 0 && error;
                    let mut which = 0u8;
                    if !recv1 && reply_to(q1, rid, got, skip_match) {
                        which = 1;
                    }
                    if !recv2 && pair && reply_to(q2.unwrap_or(&[]), rid, got, skip_match) {
                        which = 2;
                    }
                    if which == 0 {
                        continue; // not ours
                    }
                    // an error, or an empty answer from a server that is neither authoritative nor recursive
                    let useless = h.rcode() == NOERROR && h.ancount == 0 && h.flags & 0x0400 == 0 && h.flags & 0x0080 == 0 && h.arcount == 0;
                    if error || useless {
                        if first && error {
                            self.bad = n;
                        }
                        if opts & RES_STRICTERR == 0 {
                            // the reply that did come is used even when the other one is an error
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
                        // now the second query
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
                // POLLERR, POLLHUP, POLLNVAL
                self.socks.iclose();
                return Try::Next;
            }
        }
    }

    /// One try over TCP with the server `ns` (glibc's send_vc): both queries on one connection, the replies read in the
    /// order they come. The state's connection is used again while it is still connected to this server (else it is closed
    /// with the other sockets, `__res_iclose`); every failure closes them all. Unlike glibc, connecting, writing and reading
    /// are bounded by the server's timeout.
    fn vc(&mut self, ns: usize) -> Try {
        let s = self.cfg.servers[ns];
        let ms = server_ms(self.cfg, ns).max(self.cfg.timeout_ms.max(0) as u64);
        let pair = self.q2.is_some();
        let mut connreset = false;
        loop {
            // still talking to the server we want?
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
            // glibc's blocking calls leave errno as the connect step set it (0) or, on a connection used again, as it was;
            // ours may meet EAGAIN and EINPROGRESS on the way
            let keep = if fresh { 0 } else { last_errno() };
            match self.vc_on(fd, &s, ms, pair, fresh) {
                Err(e) => {
                    self.terrno = e;
                    self.socks.iclose();
                    if e == ECONNRESET && !connreset {
                        // a long-lived connection reset by a restarted server: once more, same server
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

    /// The exchange on the connection `fd`, connected first when `connect` (a new socket).
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
        // glibc's send_vc: `__set_errno (0)` before the connect (a connection used again keeps errno as it was)
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
        // both queries, each behind its length, in one write
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
                    // closed by the server (glibc keeps errno as it was: no reset, so no second try)
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
                // cut to the caller's buffer: marked truncated, and the length reported is the whole answer's (glibc's
                // res_send does both; res_query callers retry with a bigger buffer when the result exceeds theirs)
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
            // a reply to an earlier, abandoned query on this connection: skip it
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

    /// glibc's res_send over all servers and tries.
    fn run(&mut self) -> Result<(usize, usize), SendErr> {
        // glibc 2.43 __res_context_send: a state with no name server (a program that set `nscount` to 0 in an initialised
        // state) fails at once with ESRCH, before any socket
        if self.cfg.nservers == 0 {
            return Err(SendErr::Other(ESRCH));
        }
        SEND_REACHED.set(true);
        let ns_count = self.cfg.nservers;
        // the state's sockets, after res_send's check of its copy of the servers
        let (socks, ok) = Socks::begin(ns_count);
        self.socks = socks;
        if !ok {
            return Err(SendErr::Other(ENOMEM));
        }
        let opts = self.cfg.options;
        let mut v_circuit = opts & RES_USEVC != 0 || self.q1.len() > PACKETSZ || self.q2.is_some_and(|q| q.len() > PACKETSZ);
        self.terrno = ETIMEDOUT;
        let start = if opts & RES_ROTATE != 0 { random_id() as usize % ns_count } else { 0 };
        // glibc: `for (try = 0; try < statp->retry; try++)`, so no try at all when the setting is 0 or negative
        let tries = self.cfg.attempts;
        let mut t = 0;
        while t < tries {
            for shift in 0..ns_count {
                let ns = (start + shift) % ns_count;
                let got = loop {
                    if v_circuit {
                        // over TCP every server gets one try
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
                    // like glibc's mask_ad_bit: an answer's AD bit is only passed on when the trust-ad option is set
                    if opts & RES_TRUSTAD == 0 {
                        if n1 > HFIXEDSZ {
                            self.a1.buf()[3] &= !0x20;
                        }
                        if n2 > HFIXEDSZ {
                            self.a2.buf()[3] &= !0x20;
                        }
                    }
                    // glibc closes the state's sockets (__res_iclose) after an answer over a TCP connection it opened for a
                    // truncated reply, or unless RES_STAYOPEN
                    if (v_circuit && opts & RES_USEVC == 0) || opts & RES_STAYOPEN == 0 {
                        self.socks.iclose();
                    }
                    return Ok((n1, n2));
                }
            }
            t += 1;
        }
        // every server and try failed: glibc's __res_iclose, then the errno
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

/// Set when a send got past the "no name server" check, where glibc's res_send copies the server list into the state
/// (`resolv::sync_ext`); read and cleared with [`take_send_reached`].
#[thread_local]
static SEND_REACHED: core::cell::Cell<bool> = core::cell::Cell::new(false);

/// Clear the marks before a lookup (also [`RES_HERR`]).
pub fn reset_send_marks() {
    SEND_REACHED.set(false);
    RES_HERR.set(None);
}

/// Did a send get past the "no name server" check since [`reset_send_marks`]? (Clears the mark.)
pub fn take_send_reached() -> bool {
    SEND_REACHED.replace(false)
}

/// Why a send of one or two queries failed, and the length of a SERVFAIL, NOTIMP or REFUSED reply left in the first buffer
/// (0: none), whose response code glibc's search still looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFail {
    pub err: SendErr,
    pub bad: usize,
}

/// glibc's res_send for one query (`q2` None) or the A+AAAA pair: both queries go to a server at once and the replies are
/// taken in the order they come (`a1` gets the first, `a2` the second; a length under HFIXEDSZ means none). A reply that
/// says SERVFAIL, NOTIMP or REFUSED, or an empty answer from a server that is neither authoritative nor recursive, makes the
/// next server run unless the other reply of the pair has come (outside RES_STRICTERR); a truncated reply makes the pair go
/// over TCP to the same server. When a server answers only one query of a pair in time, the thread switches to one query at
/// a time (RES_F_SNGLKUP in `flags`), then also to a fresh socket for the second (RES_F_SNGLKUPREOP), as RES_SNGLKUP and
/// RES_SNGLKUPREOP ask from the start. A TCP answer longer than a fixed buffer is cut to it, marked truncated, and the
/// length returned is the whole answer's: read it with [`Answer::kept`].
pub fn send_queries<'a>(cfg: &Config, q1: &[u8], q2: Option<&[u8]>, a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), SendFail> {
    let mut s = Send { cfg, q1, q2, a1, a2, flags, socks: Socks::idle(), gotsomewhere: false, terrno: ETIMEDOUT, bad: 0 };
    let r = s.run();
    let bad = s.bad;
    r.map_err(|err| SendFail { err, bad })
}

/// Send one query to the configured servers and return the answer length (see [`send_queries`]). If every server answered
/// SERVFAIL, NOTIMP or REFUSED, the last such answer is returned.
pub fn send_query(cfg: &Config, q: &[u8], ans: &mut [u8]) -> Result<usize, SendErr> {
    send_query_ans(cfg, q, &mut Answer::fixed(ans))
}

/// [`send_query`] into an [`Answer`].
pub fn send_query_ans(cfg: &Config, q: &[u8], ans: &mut Answer) -> Result<usize, SendErr> {
    let mut flags = 0u32;
    match send_queries(cfg, q, None, ans, &mut Answer::fixed(&mut []), &mut flags) {
        Ok((n, _)) => Ok(n),
        Err(f) if f.bad > 0 => Ok(f.bad),
        Err(f) => Err(f.err),
    }
}

/// glibc's RES_NOAAAA handling of one query (__res_handle_no_aaaa): when the option is on and `q` is a well-formed AAAA/IN
/// question, an A/IN question for the same name (no EDNS record) is sent instead, so that a name that does not exist still gets
/// its NXDOMAIN, and the reply is turned back into an answer to the AAAA question with no records (header counts zeroed and the
/// reply cut after the question). `None` when the query is not one to rewrite: send it as it is.
pub fn send_query_noaaaa(cfg: &Config, q: &[u8], ans: &mut Answer) -> Option<Result<usize, SendErr>> {
    if cfg.options & RES_NOAAAA == 0 || q.len() <= HFIXEDSZ {
        return None;
    }
    let h = Header::parse(q)?;
    if h.is_response() || h.opcode() != 0 || h.rcode() != 0 || h.qdcount != 1 || h.ancount != 0 || h.nscount != 0 {
        return None;
    }
    const MAXCDNAME: usize = 255; // NS_MAXCDNAME
    let mut rep = [0u8; HFIXEDSZ + MAXCDNAME + 4];
    rep[..HFIXEDSZ].copy_from_slice(&q[..HFIXEDSZ]);
    // no EDNS record in the replacement
    put16(&mut rep, 10, 0);
    let used = name_unpack(q, HFIXEDSZ, &mut rep[HFIXEDSZ..HFIXEDSZ + MAXCDNAME])?;
    let after = HFIXEDSZ + used;
    if q.len() < after + 4 || q[after..after + 4] != [0, T_AAAA as u8, 0, C_IN as u8] {
        return None;
    }
    let qend = name_skip(&rep, HFIXEDSZ)?;
    rep[qend..qend + 4].copy_from_slice(&[0, T_A as u8, 0, C_IN as u8]);
    // a clean buffer: a failed send leaves no old bytes to be read as a question
    ans.buf().fill(0);
    let r = send_query_ans(cfg, &rep[..qend + 4], ans);
    let b = ans.buf();
    if let Some(a) = name_skip(b, HFIXEDSZ) {
        if b.len() >= a + 4 && b[a..a + 4] == [0, T_A as u8, 0, C_IN as u8] {
            b[a + 1] = T_AAAA as u8;
            // the question stays, the records go: a positive answer becomes "no data", the response code is kept
            put16(b, 6, 0);
            put16(b, 8, 0);
            put16(b, 10, 0);
            return Some(r.map(|_| a + 4));
        }
    }
    Some(r)
}

/// The errno glibc's res_mkquery leaves after building the query `q`: its name compression (ns_name_pack) asks dn_find for
/// each label to point to, finds nothing in a fresh message and sets ENOENT; a root name has no label to look up. A send
/// that later fails on a server slot glibc cannot use (Socks::open) returns that errno.
pub fn mkquery_errno(q: &[u8]) {
    if q.get(HFIXEDSZ).is_some_and(|&l| l != 0) {
        rusty_libc_core::errno::set(ENOENT);
    }
}

/// Resolver failure in `h_errno` terms, with the response code that caused it (0 if none) and the `errno` glibc's
/// `res_nquery`/`res_nsearch` leaves behind when the failure is that no server gave a usable answer: ECONNREFUSED
/// (nothing listening), ETIMEDOUT (no answer, or only SERVFAIL, REFUSED and NOTIMP answers), EMFILE/ENFILE (no socket).
/// 0 when the servers answered and the answer itself says no (NXDOMAIN, no data, FORMERR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HErr {
    pub h: c_int,
    pub rcode: u8,
    pub errno: c_int,
}

impl HErr {
    /// The resolver could not be reached (connection refused).
    pub fn refused(&self) -> bool {
        self.errno == ECONNREFUSED
    }
}

/// `res_nquery`: build the query for `name` (used as is), send it, and map the answer. On success the
/// answer is in `ans` and its length returned. An EDNS0 option is advertised as [`RESOLV_EDNS_BUFFER_SIZE`] (the answer
/// buffer of the name service lookups can grow); [`query_adv`] takes the size of the caller's answer buffer instead.
pub fn query(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    query_adv(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

/// [`query`] into an [`Answer`] (the name service lookups give a growable one).
pub fn query_in(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer) -> Result<usize, HErr> {
    query_ans(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

/// [`search`] into an [`Answer`] (the name service lookups give a growable one).
pub fn search_in(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer) -> Result<usize, HErr> {
    search_ans(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

/// [`query`] with the size to advertise in the OPT record: the caller's answer buffer length (`res_nquery`), which
/// is clamped to 512..=1200 like glibc's `__res_nopt`.
pub fn query_adv(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8], advertise: usize) -> Result<usize, HErr> {
    query_ans(cfg, name, qclass, qtype, &mut Answer::fixed(ans), advertise)
}

/// [`query_adv`] into an [`Answer`]: the name service lookups give a growable one.
pub fn query_ans(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer, advertise: usize) -> Result<usize, HErr> {
    noted(query_ans_1(cfg, name, qclass, qtype, ans, advertise))
}

fn query_ans_1(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer, advertise: usize) -> Result<usize, HErr> {
    let mut q = [0u8; 1500];
    // an OPT record goes into the query with EDNS0, and also with DNSSEC (which adds the DO bit)
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
        q[3] |= 0x20; // AD bit: ask the server to tell us about validation
    }
    // RES_NOAAAA: an AAAA query is asked as A and answered with no data (glibc's res_query)
    let sent = match send_query_noaaaa(cfg, &q[..ql], ans) {
        Some(r) => r,
        None => send_query_ans(cfg, &q[..ql], ans),
    };
    match sent {
        Ok(n) => classify(ans.kept(n)).map(|_| n),
        Err(SendErr::Refused) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: ECONNREFUSED }),
        // a send that failed with an errno of its own (no server ESRCH, no socket, a server slot of another family) leaves it,
        // as glibc's __res_context_send returns -1 with errno set; no server reached is ECONNREFUSED, no answer ETIMEDOUT
        Err(SendErr::Other(e)) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: e }),
        Err(SendErr::Timeout) => Err(HErr { h: TRY_AGAIN, rcode: 0, errno: ETIMEDOUT }),
    }
}

/// glibc's res_query for the A and AAAA queries of a name as one pair (T_QUERY_A_AND_AAAA, what getaddrinfo's lookup
/// asks): the replies in `a1` and `a2` in the order they came (see [`send_queries`]). A success when either reply has
/// data; otherwise the first reply's response code decides, or the second's when the first is NOERROR: NXDOMAIN
/// HOST_NOT_FOUND, SERVFAIL TRY_AGAIN, no data NO_DATA, anything else NO_RECOVERY.
pub fn query_pair<'a>(cfg: &Config, name: &[u8], a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), HErr> {
    noted(query_pair_1(cfg, name, a1, a2, flags))
}

fn query_pair_1<'a>(cfg: &Config, name: &[u8], a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), HErr> {
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
            // a SERVFAIL left in the first buffer is seen by the search (it goes on to the next domain)
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

/// Answer to h_errno: NXDOMAIN HOST_NOT_FOUND, no records NO_DATA, FORMERR NO_RECOVERY. SERVFAIL, NOTIMP and REFUSED are
/// what [`send_query`] hands back when every server answered like that: glibc's send then fails (TRY_AGAIN, errno ETIMEDOUT),
/// so those three are TRY_AGAIN too, keeping the response code (the search loop looks at SERVFAIL).
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

/// Ask `q` for `name`, or for `name` in `domain`.
fn query_domain<T>(name: &[u8], domain: Option<&[u8]>, q: &mut impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    let r = query_domain_1(name, domain, q);
    // glibc's res_querydomain/res_query set h_errno (and the state's res_h_errno) when they fail
    if let Err(e) = &r {
        set_search_herr(e.h);
    }
    r
}

/// The h_errno glibc's res_search leaves behind when it succeeds: HOST_NOT_FOUND, set when it starts, or what the last name
/// that failed during the search set. Kept per thread; read with [`search_herr`].
#[thread_local]
static SEARCH_HERR: core::cell::Cell<c_int> = core::cell::Cell::new(0);

fn set_search_herr(h: c_int) {
    SEARCH_HERR.set(h);
    RES_HERR.set(Some(h));
    crate::strerr::set_h_errno(h);
}

/// The value glibc's `RES_SET_H_ERRNO(statp, ...)` last wrote into the state's `res_h_errno` during the current lookup of
/// this thread (None when nothing wrote it): res_query when it fails, res_search when it starts, after each failed name
/// and when it fails. Cleared by [`reset_send_marks`] when a lookup starts; [`take_res_herr`] hands it to the state when
/// the lookup ends (the name service lookups on the thread's `_res` as well as the `res_n*` functions).
#[thread_local]
static RES_HERR: core::cell::Cell<Option<c_int>> = core::cell::Cell::new(None);

/// Note the h_errno of a failed query or search in [`RES_HERR`]; `r` passes through.
fn noted<T>(r: Result<T, HErr>) -> Result<T, HErr> {
    if let Err(e) = &r {
        RES_HERR.set(Some(e.h));
    }
    r
}

/// What the current lookup wrote into the state's `res_h_errno` (see [`RES_HERR`]), if anything.
pub fn take_res_herr() -> Option<c_int> {
    RES_HERR.take()
}

/// The h_errno the last search of this thread left (see [`SEARCH_HERR`]): glibc's res_search, and the name service
/// lookups built on it (gethostbyname, getaddrinfo), succeed with it still set.
pub fn search_herr() -> c_int {
    SEARCH_HERR.get()
}

fn query_domain_1<T>(name: &[u8], domain: Option<&[u8]>, q: &mut impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    match domain {
        None => {
            // a trailing dot is allowed; the wire encoder takes both forms
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

/// `res_nsearch`: try `name` with the search list as the options and the number of dots direct.
pub fn search(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8]) -> Result<usize, HErr> {
    search_adv(cfg, name, qclass, qtype, ans, RESOLV_EDNS_BUFFER_SIZE)
}

/// [`search`] advertising `adv` (the caller's answer buffer length, clamped) in an EDNS0 OPT record.
pub fn search_adv(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut [u8], adv: usize) -> Result<usize, HErr> {
    search_ans(cfg, name, qclass, qtype, &mut Answer::fixed(ans), adv)
}

/// [`search_adv`] into an [`Answer`]: the name service lookups give a growable one.
pub fn search_ans(cfg: &Config, name: &[u8], qclass: u16, qtype: u16, ans: &mut Answer, adv: usize) -> Result<usize, HErr> {
    search_with(cfg, name, |n: &[u8]| query_ans(cfg, n, qclass, qtype, ans, adv))
}

/// [`search`] for the A+AAAA pair ([`query_pair`]): the search stops at the first name where either query has data.
pub fn search_pair<'a>(cfg: &Config, name: &[u8], a1: &mut Answer<'a>, a2: &mut Answer<'a>, flags: &mut u32) -> Result<(usize, usize), HErr> {
    search_with(cfg, name, |n: &[u8]| query_pair(cfg, n, a1, a2, flags))
}

/// glibc's res_search over the names to try, asking `q` for each.
fn search_with<T>(cfg: &Config, name: &[u8], q: impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    // glibc's res_search ends a failed search with RES_SET_H_ERRNO of the value it returns with
    noted(search_with_1(cfg, name, q))
}

fn search_with_1<T>(cfg: &Config, name: &[u8], mut q: impl FnMut(&[u8]) -> Result<T, HErr>) -> Result<T, HErr> {
    // glibc: `RES_SET_H_ERRNO(statp, HOST_NOT_FOUND)` before anything ("true if we never query"), and a success leaves the
    // value of the last failure
    set_search_herr(HOST_NOT_FOUND);
    let dots = name.iter().filter(|&&c| c == b'.').count();
    let trailing = name.last() == Some(&b'.');
    if dots == 0 {
        // glibc's res_context_search: a name without dots is first looked up in the $HOSTALIASES file (`alias real.name`)
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
            // glibc: a search entry that is the root ("" or ".") means the name as is was tried, so it is not tried again
            // at the end
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
        // (glibc leaves the errno of the failed send behind)
        return Err(HErr { h: TRY_AGAIN, errno: ETIMEDOUT, ..last });
    }
    Err(last)
}

// ---------------------------------------------------------------- reading answers

/// One address from an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub family: c_int,
    pub bytes: [u8; 16],
    /// The scope id of a link-local IPv6 address (from a plug-in module such as myhostname); 0 otherwise.
    pub scope: u32,
}

/// A list of addresses, a canonical name and the alias chain. The addresses and aliases live in memory from the library's
/// allocator, so an answer can carry as many as the message holds.
pub struct HostData {
    /// The number of addresses (the length of `addrs`).
    pub n: usize,
    pub addrs: HeapVec<Addr>,
    pub canon: Buf<256>,
    pub have_canon: bool,
    /// Alias names, NUL-separated (the query name first when the answer went through CNAMEs, then the CNAME targets but the last,
    /// which is the canonical name).
    pub aliases: HeapVec<u8>,
    pub naliases: usize,
    pub ttl: u32,
    /// The caller's buffer (address, length) of a `gethostbyname*_r` call: the `files` source then applies glibc's rules for
    /// when that buffer is too small, and sets `erange` instead of answering.
    pub fit: Option<(usize, usize)>,
    pub erange: bool,
    /// Which module function a plug-in source is asked for: 0 getaddrinfo's (gethostbyname4_r, then 3_r, then 2_r),
    /// 1 `gethostbyname_r`, 2 `gethostbyname2_r` (what those two functions of the C library ask).
    pub func: u8,
    /// `h_errno` as the sources of a `gethostby*_r` call leave it: the caller's value to begin with, then what each source
    /// wrote (glibc hands the caller's pointer to the sources; the files source sets HOST_NOT_FOUND at the end of the file).
    pub h: i32,
    /// The plug-in source just asked had its function (false: it was skipped).
    pub called: bool,
    /// Some source could be asked (set by `lookup_name`).
    pub any: bool,
    /// A SUCCESS whose action is `merge` (hosts cannot merge: EINVAL).
    pub einval: bool,
    /// The last source asked answered UNAVAIL (the reason is in errno): glibc's `getXXbyYY_r` returns that errno.
    pub unavail: bool,
    /// The last source asked said TRYAGAIN (glibc's getXXbyYY_r then returns EAGAIN unless h_errno is NETDB_INTERNAL).
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

/// Collect the address records of type `qtype` (A or AAAA) that answer `qname`, following CNAMEs in
/// the answer section. The final name becomes `canon`, the names passed on the way become aliases.
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
                    // the name queried first is the host name; later owners are aliases
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

/// The PTR targets in an answer for `qname` (following CNAMEs): first name only.
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

/// Look `name` up over DNS for one address family with the search rules; the result for `getaddrinfo`
/// and `gethostbyname`.
pub fn lookup_host(cfg: &Config, name: &[u8], af: c_int, out: &mut HostData) -> Result<(), HErr> {
    let qtype = if af == AF_INET { T_A } else { T_AAAA };
    let mut ans = [0u8; 4096];
    let n = search(cfg, name, C_IN, qtype, &mut ans)?.min(ans.len());
    // the name that finally answered is the first question
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

/// Reverse lookup name for an address (`d.c.b.a.in-addr.arpa` or nibbles under `ip6.arpa`).
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

/// PTR lookup. Returns the name.
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
