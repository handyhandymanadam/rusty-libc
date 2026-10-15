#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::inet;
use crate::types::*;
use crate::util::{Buf, Spin, eq_nocase, is_space};
use core::ffi::{c_char, c_int};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::syscall;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Db {
    Hosts,
    Services,
    Protocols,
    Networks,
    Rpc,
    Aliases,
    Ethers,
    Netgroup,
}

impl Db {
    fn file(self) -> &'static [u8] {
        match self {
            Db::Hosts => b"/hosts",
            Db::Services => b"/services",
            Db::Protocols => b"/protocols",
            Db::Networks => b"/networks",
            Db::Rpc => b"/rpc",
            Db::Aliases => b"/aliases",
            Db::Ethers => b"/ethers",
            Db::Netgroup => b"/netgroup",
        }
    }
}

static ETC: Spin<Buf<200>> = Spin::new(Buf::new());

pub fn set_etc_dir(dir: &[u8]) -> bool {
    match Buf::<200>::from(dir) {
        Some(b) => {
            *ETC.lock() = b;
            if dir.is_empty() {
                rusty_libc_core::nssmod::set_conf_path(b"");
            } else {
                let mut p = Buf::<320>::new();
                p.push_all(dir);
                p.push_all(b"/nsswitch.conf");
                rusty_libc_core::nssmod::set_conf_path(p.as_bytes());
            }
            true
        }
        None => false,
    }
}

pub fn etc_path(name: &[u8]) -> Buf<320> {
    let mut p = Buf::<320>::new();
    let e = ETC.lock();
    if e.len == 0 {
        p.push_all(b"/etc");
    } else {
        p.push_all(e.as_bytes());
    }
    drop(e);
    p.push_all(name);
    p.push(0);
    p
}

fn db_path(db: Db) -> Buf<320> {
    etc_path(db.file())
}

pub(crate) struct ZBuf {
    p: *mut u8,
    cap: usize,
}

unsafe impl Send for ZBuf {}

impl ZBuf {
    pub(crate) const fn new() -> ZBuf {
        ZBuf { p: core::ptr::null_mut(), cap: 0 }
    }
    pub(crate) fn cap(&self) -> usize {
        self.cap
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.p.is_null()
    }
    pub(crate) fn grow(&mut self, ncap: usize) -> bool {
        let nb = unsafe { rusty_libc_malloc::realloc(self.p as *mut core::ffi::c_void, ncap) } as *mut u8;
        if nb.is_null() {
            return false;
        }
        if ncap > self.cap {
            unsafe { nb.wrapping_add(self.cap).write_bytes(0, ncap - self.cap) };
        }
        self.p = nb;
        self.cap = ncap;
        true
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        unsafe { rusty_libc_core::ffi::bytes(self.p, self.cap) }
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { rusty_libc_core::ffi::bytes_mut(self.p, self.cap) }
    }
}

impl Drop for ZBuf {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe { rusty_libc_malloc::free(self.p as *mut core::ffi::c_void) };
        }
    }
}

pub(crate) fn c_dup(s: &[u8]) -> *mut u8 {
    let p = unsafe { rusty_libc_malloc::malloc(s.len() + 1) } as *mut u8;
    if !p.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
        unsafe { p.wrapping_add(s.len()).write(0) };
    }
    p
}

pub(crate) fn heap_new<T>(v: T) -> *mut T {
    let p = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<T>()) } as *mut T;
    if !p.is_null() {
        unsafe { p.write(v) };
    }
    p
}

pub struct LineReader {
    fd: c_int,
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    eof: bool,
    big: ZBuf,
    last_big: Option<usize>,
    last_start: usize,
    last_nl: bool,
    held: Option<usize>,
}

#[derive(Clone, Copy)]
enum Span {
    Buf(usize, usize),
    Big(usize),
}


impl LineReader {
    pub const fn closed() -> LineReader {
        LineReader { fd: -1, buf: [0; 4096], pos: 0, len: 0, eof: false, big: ZBuf::new(), last_big: None, last_start: 0, last_nl: true, held: None }
    }

    pub fn open(path: &Buf<320>) -> Result<LineReader, i32> {
        let mut r = LineReader::closed();
        let path = path.as_bytes();
        debug_assert!(path.last() == Some(&0));
        let fd = unsafe { rusty_libc_core::unistd::open(path.as_ptr() as *const c_char, 0o2000000, 0) };
        match fd {
            Ok(fd) => {
                r.fd = fd;
                Ok(r)
            }
            Err(e) => Err(e.0),
        }
    }

    pub fn is_open(&self) -> bool {
        self.fd >= 0
    }

    pub fn close(&mut self) {
        if self.fd >= 0 {
            let _ = rusty_libc_core::unistd::close(self.fd);
            self.fd = -1;
        }
        if !self.big.is_empty() {
            self.big = ZBuf::new();
        }
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        self.held = None;
    }

    pub fn rewind(&mut self) {
        if self.fd >= 0 {
            let _ = rusty_libc_core::unistd::lseek(self.fd, 0, 0);
        }
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        self.held = None;
    }

    pub fn unread(&mut self) {
        match self.last_big {
            Some(n) => self.held = Some(n),
            None => self.pos = self.last_start,
        }
    }

    fn fill(&mut self) -> bool {
        if self.eof || self.fd < 0 {
            return false;
        }
        loop {
            match rusty_libc_core::unistd::read(self.fd, &mut self.buf) {
                Ok(0) => {
                    self.eof = true;
                    return false;
                }
                Ok(n) => {
                    self.pos = 0;
                    self.len = n;
                    return true;
                }
                Err(e) if e.0 == EINTR => continue,
                Err(_) => {
                    self.eof = true;
                    return false;
                }
            }
        }
    }

    fn big(&self, n: usize) -> &[u8] {
        &self.big.as_slice()[..n]
    }

    fn span(&self, sp: Span) -> &[u8] {
        match sp {
            Span::Buf(s, e) => &self.buf[s..e],
            Span::Big(n) => self.big(n),
        }
    }

    pub fn next_line(&mut self) -> Option<&[u8]> {
        let sp = self.next_span()?;
        Some(self.span(sp))
    }

    fn next_span(&mut self) -> Option<Span> {
        if let Some(n) = self.held.take() {
            self.last_big = Some(n);
            return Some(Span::Big(n));
        }
        if self.pos >= self.len && !self.fill() {
            return None;
        }
        if let Some(i) = self.buf[self.pos..self.len].iter().position(|&c| c == b'\n') {
            let s = self.pos;
            self.pos += i + 1;
            self.last_big = None;
            self.last_start = s;
            self.last_nl = true;
            return Some(Span::Buf(s, s + i));
        }
        let mut used = 0usize;
        let mut ended_by_newline = false;
        loop {
            let chunk_start = self.pos;
            let chunk_end = self.len;
            let nl = self.buf[chunk_start..chunk_end].iter().position(|&c| c == b'\n');
            let take = nl.unwrap_or(chunk_end - chunk_start);
            if used + take > self.big.cap() {
                let ncap = (used + take).max(self.big.cap() * 2).max(8192);
                if !self.big.grow(ncap) {
                    self.pos = chunk_end;
                    if nl.is_some() || !self.fill() {
                        return Some(Span::Buf(0, 0));
                    }
                    continue;
                }
            }
            self.big.as_mut_slice()[used..used + take].copy_from_slice(&self.buf[chunk_start..chunk_start + take]);
            used += take;
            if nl.is_some() {
                self.pos = chunk_start + take + 1;
                ended_by_newline = true;
                break;
            }
            self.pos = chunk_end;
            if !self.fill() {
                break;
            }
        }
        self.last_nl = ended_by_newline;
        self.last_big = Some(used);
        Some(Span::Big(used))
    }

    pub fn next_raw(&mut self) -> Option<(&[u8], usize)> {
        let sp = self.next_span()?;
        let nl = self.last_nl as usize;
        let line = self.span(sp);
        Some((line, line.len() + nl))
    }

    pub fn next_entry(&mut self) -> Option<&[u8]> {
        let (sp, s, e) = loop {
            let sp = self.next_span()?;
            let line = self.span(sp);
            let mut s = 0;
            while s < line.len() && is_space(line[s]) {
                s += 1;
            }
            if s == line.len() || line[s] == b'#' {
                continue;
            }
            let mut e = line.len();
            if let Some(h) = line[s..].iter().position(|&c| c == b'#') {
                e = s + h;
            }
            break (sp, s, e);
        };
        Some(&self.span(sp)[s..e])
    }
}

pub fn entry_body(line: &[u8]) -> Option<&[u8]> {
    let mut s = 0;
    while s < line.len() && is_space(line[s]) {
        s += 1;
    }
    if s == line.len() || line[s] == b'#' {
        return None;
    }
    let mut e = line.len();
    if let Some(h) = line[s..].iter().position(|&c| c == b'#') {
        e = s + h;
    }
    Some(&line[s..e])
}

impl LineReader {
    pub fn fgets(&mut self, dst: &mut [u8]) -> bool {
        let n = dst.len();
        if n == 0 {
            return false;
        }
        let mut got = 0usize;
        while got + 1 < n {
            if self.pos >= self.len && !self.fill() {
                break;
            }
            let avail = &self.buf[self.pos..self.len];
            let room = n - 1 - got;
            let take = avail.len().min(room);
            let (chunk, nl) = match avail[..take].iter().position(|&c| c == b'\n') {
                Some(i) => (i + 1, true),
                None => (take, false),
            };
            dst[got..got + chunk].copy_from_slice(&avail[..chunk]);
            got += chunk;
            self.pos += chunk;
            if nl {
                break;
            }
        }
        dst[got] = 0;
        got > 0
    }

    pub fn getc(&mut self) -> i32 {
        if self.pos >= self.len && !self.fill() {
            return -1;
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        c as i32
    }

    pub fn ungetc(&mut self) {
        if self.pos > 0 {
            self.pos -= 1;
        }
    }

    pub fn at_eof(&self) -> bool {
        self.eof && self.pos >= self.len
    }
}

impl Drop for LineReader {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone)]
pub struct Fields<'a> {
    s: &'a [u8],
}

pub fn fields(s: &[u8]) -> Fields<'_> {
    Fields { s }
}

impl<'a> Iterator for Fields<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let mut i = 0;
        while i < self.s.len() && is_space(self.s[i]) {
            i += 1;
        }
        if i == self.s.len() {
            self.s = &[];
            return None;
        }
        let st = i;
        while i < self.s.len() && !is_space(self.s[i]) {
            i += 1;
        }
        let f = &self.s[st..i];
        self.s = &self.s[i..];
        Some(f)
    }
}

pub fn strtou32(s: &[u8]) -> (u32, usize) {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let st = i;
    let mut v: u64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((s[i] - b'0') as u64);
        i += 1;
    }
    if i == st {
        return (0, 0);
    }
    let v = if neg { v.wrapping_neg() } else { v };
    (if v > 0xffff_ffff { 0xffff_ffff } else { v as u32 }, i)
}

pub struct HostLine<'a> {
    pub family: c_int,
    pub addr: [u8; 16],
    pub name: &'a [u8],
    pub rest: &'a [u8],
}

pub fn parse_host_line(line: &[u8], af: c_int, v4mapped: bool) -> Option<HostLine<'_>> {
    let mut f = fields(line);
    let a = f.next()?;
    let mut addr = [0u8; 16];
    let mut family;
    let try4 = |addr: &mut [u8; 16]| inet::parse_ipv4(a).map(|v| addr[..4].copy_from_slice(&v)).is_some();
    let try6 = |addr: &mut [u8; 16]| inet::parse_ipv6(a).map(|v| *addr = v).is_some();
    let want = if af == AF_UNSPEC { AF_INET } else { af };
    let ok = if want == AF_INET { try4(&mut addr) } else { try6(&mut addr) };
    if ok {
        family = want;
    } else if af == AF_INET6 && v4mapped && try4(&mut addr) {
        let v4 = [addr[0], addr[1], addr[2], addr[3]];
        addr = [0; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12..].copy_from_slice(&v4);
        family = AF_INET6;
    } else if af == AF_INET && try6(&mut addr) {
        if addr[..10] == [0; 10] && addr[10] == 0xff && addr[11] == 0xff {
            let v4 = [addr[12], addr[13], addr[14], addr[15]];
            addr = [0; 16];
            addr[..4].copy_from_slice(&v4);
        } else if addr[..15] == [0; 15] && addr[15] == 1 {
            addr = [0; 16];
            addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        } else {
            return None;
        }
        family = AF_INET;
    } else if af == AF_UNSPEC && try6(&mut addr) {
        family = AF_INET6;
    } else {
        return None;
    }
    let _ = &mut family;
    let name = f.next()?;
    let off = name.as_ptr() as usize - line.as_ptr() as usize + name.len();
    Some(HostLine { family, addr, name, rest: &line[off..] })
}

pub struct ServLine<'a> {
    pub name: &'a [u8],
    pub port: u16,
    pub proto: &'a [u8],
    pub rest: &'a [u8],
}

pub fn parse_serv_line(line: &[u8]) -> Option<ServLine<'_>> {
    let mut i = 0;
    while i < line.len() && !is_space(line[i]) {
        i += 1;
    }
    let name = &line[..i];
    while i < line.len() && is_space(line[i]) {
        i += 1;
    }
    let (v, used) = strtou32(&line[i..]);
    if used == 0 {
        return None;
    }
    i += used;
    if i < line.len() {
        if line[i] == b'/' {
            i += 1;
        } else {
            return None;
        }
    }
    let ps = i;
    while i < line.len() && !is_space(line[i]) {
        i += 1;
    }
    let proto = &line[ps..i];
    Some(ServLine { name, port: v as u16, proto, rest: &line[i..] })
}

pub struct NumLine<'a> {
    pub name: &'a [u8],
    pub num: i32,
    pub rest: &'a [u8],
}

pub fn parse_num_line(line: &[u8]) -> Option<NumLine<'_>> {
    let mut i = 0;
    while i < line.len() && !is_space(line[i]) {
        i += 1;
    }
    let name = &line[..i];
    while i < line.len() && is_space(line[i]) {
        i += 1;
    }
    let (v, used) = strtou32(&line[i..]);
    if used == 0 {
        return None;
    }
    i += used;
    if i < line.len() && !is_space(line[i]) {
        return None;
    }
    while i < line.len() && is_space(line[i]) {
        i += 1;
    }
    Some(NumLine { name, num: v as i32, rest: &line[i..] })
}

pub struct NetLine<'a> {
    pub name: &'a [u8],
    pub net: u32,
    pub rest: &'a [u8],
}

pub fn parse_net_line(line: &[u8]) -> Option<NetLine<'_>> {
    let mut f = fields(line);
    let name = f.next()?;
    let addr = f.next()?;
    let dots = addr.iter().filter(|&&c| c == b'.').count();
    let n = (dots + 1).min(4) as u32;
    if addr.len() > 64 {
        return None;
    }
    let cs = &addr[..addr.iter().position(|&c| c == 0).unwrap_or(addr.len())];
    let mut net = inet::network_parse(cs).unwrap_or(INADDR_NONE);
    if net == INADDR_NONE {
        return None;
    }
    if n < 4 {
        net <<= 8 * (4 - n);
    }
    let off = addr.as_ptr() as usize - line.as_ptr() as usize + addr.len();
    Some(NetLine { name, net, rest: &line[off..] })
}

pub fn words(rest: &[u8]) -> Fields<'_> {
    fields(rest)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Files,
    Dns,
    Module,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Success,
    NotFound,
    Unavail,
    TryAgain,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Return,
    Continue,
    Merge,
}

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub src: Source,
    pub act: [Action; 4],
    pub name: [u8; 24],
    pub nlen: u8,
}

impl Entry {
    pub const fn new(src: Source, act: [Action; 4]) -> Entry {
        Entry { src, act, name: [0; 24], nlen: 0 }
    }
    pub fn module_name(&self) -> &[u8] {
        &self.name[..self.nlen as usize]
    }
    pub fn action(&self, st: Status) -> Action {
        self.act[st as usize]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Order {
    pub e: [Entry; 8],
    pub n: usize,
}

fn default_actions() -> [Action; 4] {
    [Action::Return, Action::Continue, Action::Continue, Action::Continue]
}

impl Order {
    pub fn files_only() -> Order {
        Order { e: [Entry::new(Source::Files, default_actions()); 8], n: 1 }
    }
    pub fn default_hosts() -> Order {
        let mut o = Order { e: [Entry::new(Source::Dns, default_actions()); 8], n: 2 };
        o.e[0].act = [Action::Return, Action::Return, Action::Continue, Action::Return];
        o.e[1] = Entry::new(Source::Files, default_actions());
        o
    }
}

fn convert(o: &rusty_libc_core::nssmod::Order, keep_unloadable: bool) -> Order {
    use rusty_libc_core::nssmod::{self as m, ACT_RETURN};
    let mut r = Order { e: [Entry::new(Source::Files, default_actions()); 8], n: 0 };
    for s in &o.e[..o.n] {
        let src = if s.is(b"files") || s.is(b"compat") {
            Some(Source::Files)
        } else if s.is(b"dns") {
            Some(Source::Dns)
        } else if s.len > 0 && (keep_unloadable || m::supported()) {
            Some(Source::Module)
        } else {
            None
        };
        let Some(src) = src else { continue };
        let a = |st: i32| match s.action(st) {
            ACT_RETURN => Action::Return,
            m::ACT_MERGE => Action::Merge,
            _ => Action::Continue,
        };
        let mut e = Entry::new(src, [a(m::NSS_SUCCESS), a(m::NSS_NOTFOUND), a(m::NSS_UNAVAIL), a(m::NSS_TRYAGAIN)]);
        if src == Source::Module {
            e.name[..s.len as usize].copy_from_slice(s.name());
            e.nlen = s.len;
        }
        r.e[r.n] = e;
        r.n += 1;
    }
    r
}

pub fn parse_order(spec: &[u8]) -> Option<Order> {
    let o = convert(&rusty_libc_core::nssmod::parse_sources(spec)?, false);
    if o.n == 0 { None } else { Some(o) }
}

pub fn order_for(name: &[u8]) -> Option<Order> {
    let o = convert(&rusty_libc_core::nssmod::order(name), true);
    if o.n == 0 { None } else { Some(o) }
}

pub(crate) fn file_sig(path: &Buf<320>) -> [u64; 3] {
    let mut st = [0u64; 18];
    debug_assert!(path.as_bytes().last() == Some(&0));
    let r = unsafe { rusty_libc_core::syscall::sys_stat(path.b.as_ptr() as usize, st.as_mut_ptr() as usize) };
    if syscall::check(r).is_err() {
        return [u64::MAX; 3];
    }
    [st[1], st[11] ^ (st[6] << 32), st[12]]
}

static HCONF_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn hconf_init() {
    if HCONF_DONE.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let mut path = etc_path(b"/host.conf");
    if let Some(p) = crate::util::getenv(b"RESOLV_HOST_CONF") {
        path = Buf::new();
        path.push_all(p);
        path.push(0);
    }
    unsafe { _res_hconf.with_unsync(|h| hconf_fill(h, &path)) };
    let init = _res_hconf.as_ptr().cast::<core::sync::atomic::AtomicI32>();
    unsafe { &*init }.store(1, core::sync::atomic::Ordering::Release);
}

fn hconf_fill(h: &mut Hconf, path: &Buf<320>) {
    *h = Hconf::ZERO;
    let fname = &path.as_bytes()[..path.as_bytes().len() - 1];
    match LineReader::open(path) {
        Ok(mut r) => {
            let mut buf = [0u8; 256];
            let mut line_num = 0;
            while r.fgets(&mut buf) {
                line_num += 1;
                let n = buf.iter().position(|&c| c == 0 || c == b'\n').unwrap_or(buf.len());
                hconf_line(h, fname, line_num, &buf[..n]);
            }
        }
        Err(e) => rusty_libc_core::errno::set(e),
    }
    if let Some(v) = crate::util::getenv(b"RESOLV_MULTI") {
        hconf_bool(h, b"RESOLV_MULTI", 1, v, HCONF_FLAG_MULTI);
    }
    if let Some(v) = crate::util::getenv(b"RESOLV_REORDER") {
        hconf_bool(h, b"RESOLV_REORDER", 1, v, HCONF_FLAG_REORDER);
    }
    if let Some(v) = crate::util::getenv(b"RESOLV_ADD_TRIM_DOMAINS") {
        hconf_trim(h, b"RESOLV_ADD_TRIM_DOMAINS", 1, v);
    }
    if let Some(v) = crate::util::getenv(b"RESOLV_OVERRIDE_TRIM_DOMAINS") {
        h.num_trimdomains = 0;
        hconf_trim(h, b"RESOLV_OVERRIDE_TRIM_DOMAINS", 1, v);
    }
}

#[repr(C)]
pub struct Hconf {
    pub initialized: c_int,
    unused1: c_int,
    unused2: [c_int; 4],
    pub num_trimdomains: c_int,
    pub trimdomain: [*const c_char; 4],
    pub flags: u32,
}

impl Hconf {
    const ZERO: Hconf = Hconf { initialized: 0, unused1: 0, unused2: [0; 4], num_trimdomains: 0, trimdomain: [core::ptr::null(); 4], flags: 0 };
}

const HCONF_FLAG_REORDER: u32 = 1 << 3;
const HCONF_FLAG_MULTI: u32 = 1 << 4;

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _res_hconf: SyncCell<Hconf> = SyncCell::new(Hconf::ZERO);

fn hconf() -> &'static Hconf {
    hconf_init();
    unsafe { &*_res_hconf.as_ptr() }
}

fn hconf_word(s: &[u8]) -> usize {
    s.iter().position(|&c| is_space(c) || c == b'#' || c == b',').unwrap_or(s.len())
}

fn hconf_ws(s: &[u8]) -> &[u8] {
    &s[s.iter().position(|&c| !is_space(c)).unwrap_or(s.len())..]
}

fn hconf_warn(fmt: &'static core::ffi::CStr, args: &[HcArg]) {
    let mut words = [0u64; 4];
    for (i, a) in args.iter().enumerate() {
        words[i] = match a {
            HcArg::S(s) => s.as_ptr() as u64,
            HcArg::D(d) => *d as u64,
        };
    }
    let mut out = [0u8; 1024];
    let mut n = 0;
    let mut put = |b: &[u8]| {
        let k = b.len().min(out.len() - n);
        out[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    };
    if !rusty_libc_core::i18n::tr_format(fmt, &words[..args.len()], &mut put) {
        let mut ai = 0;
        let f = fmt.to_bytes();
        let mut i = 0;
        while i < f.len() {
            if f[i] == b'%' && i + 1 < f.len() && (f[i + 1] == b's' || f[i + 1] == b'd') {
                match args.get(ai) {
                    Some(HcArg::S(s)) => put(&s[..s.len() - 1]),
                    Some(HcArg::D(d)) => {
                        let mut b = [0u8; 12];
                        let mut k = b.len();
                        let mut v = *d as u32;
                        loop {
                            k -= 1;
                            b[k] = b'0' + (v % 10) as u8;
                            v /= 10;
                            if v == 0 {
                                break;
                            }
                        }
                        put(&b[k..]);
                    }
                    None => {}
                }
                ai += 1;
                i += 2;
            } else {
                put(&f[i..i + 1]);
                i += 1;
            }
        }
    }
    let _ = rusty_libc_sys_write(&out[..n]);
}

fn rusty_libc_sys_write(b: &[u8]) -> isize {
    unsafe { syscall::syscall3(syscall::SYS_WRITE, 2, b.as_ptr() as usize, b.len()) as isize }
}

enum HcArg<'a> {
    S(&'a [u8]),
    D(c_int),
}

fn hc_cstr(s: &[u8]) -> Buf<320> {
    let mut b = Buf::<320>::new();
    b.push_all(&s[..s.len().min(300)]);
    b.push(0);
    b
}

fn hconf_bool<'a>(h: &mut Hconf, fname: &[u8], line: c_int, v: &'a [u8], flag: u32) -> Option<&'a [u8]> {
    if v.len() >= 2 && eq_nocase(&v[..2], b"on") {
        h.flags |= flag;
        Some(&v[2..])
    } else if v.len() >= 3 && eq_nocase(&v[..3], b"off") {
        h.flags &= !flag;
        Some(&v[3..])
    } else {
        let (f, a) = (hc_cstr(fname), hc_cstr(v));
        hconf_warn(c"%s: line %d: expected `on' or `off', found `%s'\n", &[HcArg::S(f.as_bytes()), HcArg::D(line), HcArg::S(a.as_bytes())]);
        None
    }
}

fn hconf_trim<'a>(h: &mut Hconf, fname: &[u8], line: c_int, mut a: &'a [u8]) -> Option<&'a [u8]> {
    loop {
        let n = hconf_word(a);
        if h.num_trimdomains >= 4 {
            let f = hc_cstr(fname);
            hconf_warn(c"%s: line %d: cannot specify more than %d trim domains", &[HcArg::S(f.as_bytes()), HcArg::D(line), HcArg::D(4)]);
            return None;
        }
        let p = c_dup(&a[..n]);
        h.trimdomain[h.num_trimdomains as usize] = p as *const c_char;
        h.num_trimdomains += 1;
        a = hconf_ws(&a[n..]);
        if let Some(&(b',' | b';' | b':')) = a.first() {
            a = hconf_ws(&a[1..]);
            if a.is_empty() || a[0] == b'#' {
                let f = hc_cstr(fname);
                hconf_warn(c"%s: line %d: list delimiter not followed by domain", &[HcArg::S(f.as_bytes()), HcArg::D(line)]);
                return None;
            }
        }
        if a.is_empty() || a[0] == b'#' {
            return Some(a);
        }
    }
}

fn hconf_line(h: &mut Hconf, fname: &[u8], line: c_int, text: &[u8]) {
    let l = hconf_ws(text);
    if l.is_empty() || l[0] == b'#' {
        return;
    }
    let n = hconf_word(l);
    let (cmd, rest) = (&l[..n], hconf_ws(&l[n..]));
    let after = if eq_nocase(cmd, b"order") {
        return;
    } else if eq_nocase(cmd, b"trim") {
        hconf_trim(h, fname, line, rest)
    } else if eq_nocase(cmd, b"multi") {
        hconf_bool(h, fname, line, rest, HCONF_FLAG_MULTI)
    } else if eq_nocase(cmd, b"reorder") {
        hconf_bool(h, fname, line, rest, HCONF_FLAG_REORDER)
    } else {
        let (f, a) = (hc_cstr(fname), hc_cstr(l));
        hconf_warn(c"%s: line %d: bad command `%s'\n", &[HcArg::S(f.as_bytes()), HcArg::D(line), HcArg::S(a.as_bytes())]);
        return;
    };
    if let Some(r) = after {
        let r = hconf_ws(r);
        if !r.is_empty() && r[0] != b'#' {
            let (f, a) = (hc_cstr(fname), hc_cstr(r));
            hconf_warn(c"%s: line %d: ignoring trailing garbage `%s'\n", &[HcArg::S(f.as_bytes()), HcArg::D(line), HcArg::S(a.as_bytes())]);
        }
    }
}

pub fn host_conf_multi() -> bool {
    hconf().flags & HCONF_FLAG_MULTI != 0
}

pub unsafe fn trim_domains(hp: *mut crate::types::hostent) {
    let h = hconf();
    if h.num_trimdomains == 0 {
        return;
    }
    let trims = &h.trimdomain[..h.num_trimdomains as usize];
    let he = unsafe { &*hp };
    trim_name(unsafe { cstr_mut(he.h_name) }, trims);
    let mut a = he.h_aliases;
    loop {
        let p = unsafe { *a };
        if p.is_null() {
            break;
        }
        trim_name(unsafe { cstr_mut(p) }, trims);
        a = a.wrapping_add(1);
    }
}

unsafe fn cstr_mut<'a>(p: *mut c_char) -> &'a mut [u8] {
    let n = unsafe { crate::util::cstrlen(p) };
    unsafe { core::slice::from_raw_parts_mut(p as *mut u8, n + 1) }
}

fn trim_name(name: &mut [u8], trims: &[*const c_char]) {
    let len = name.len() - 1;
    for &t in trims {
        let Some(t) = (unsafe { rusty_libc_core::ffi::cstr(t) }) else { continue };
        let t = t.to_bytes();
        if len > t.len() && eq_nocase(&name[len - t.len()..len], t) {
            name[len - t.len()] = 0;
            break;
        }
    }
}

pub unsafe fn reorder_addrs(hp: *mut crate::types::hostent) {
    if hconf().flags & HCONF_FLAG_REORDER == 0 {
        return;
    }
    let he = unsafe { &*hp };
    if he.h_addrtype != crate::types::AF_INET {
        return;
    }
    let mut ifs = [(0u32, 0u32); 64];
    let n = local_ipv4_nets(&mut ifs);
    if n == 0 {
        return;
    }
    let list = he.h_addr_list;
    let mut count = 0;
    while !unsafe { *list.wrapping_add(count) }.is_null() {
        count += 1;
    }
    let addrs = unsafe { core::slice::from_raw_parts_mut(list, count) };
    for i in 0..count {
        let a = u32::from_ne_bytes(unsafe { *(addrs[i] as *const [u8; 4]) });
        if ifs[..n].iter().any(|&(addr, mask)| (a ^ addr) & mask == 0) {
            addrs.swap(0, i);
            return;
        }
    }
}

fn local_ipv4_nets(out: &mut [(u32, u32); 64]) -> usize {
    static NETS: Spin<([(u32, u32); 64], usize)> = Spin::new(([(0, 0); 64], 0));
    let mut g = NETS.lock();
    if g.1 == 0 {
        let save = rusty_libc_core::errno::get();
        let sd = unsafe { syscall::syscall3(41 , 2 , 2 | 0o2000000 , 0) } as isize;
        if sd >= 0 {
            let mut reqs = [0u8; 40 * 64];
            let mut ifc = [0u64; 2];
            ifc[0] = reqs.len() as u64;
            ifc[1] = reqs.as_mut_ptr() as u64;
            if unsafe { syscall::syscall3(syscall::SYS_IOCTL, sd as usize, 0x8912 , ifc.as_mut_ptr() as usize) } as isize >= 0 {
                let count = (ifc[0] as u32 as usize) / 40;
                let mut k = 0;
                for i in 0..count.min(64) {
                    let r = &mut reqs[i * 40..i * 40 + 40];
                    if u16::from_ne_bytes([r[16], r[17]]) != 2 {
                        continue;
                    }
                    let addr = u32::from_ne_bytes([r[20], r[21], r[22], r[23]]);
                    if (unsafe { syscall::syscall3(syscall::SYS_IOCTL, sd as usize, 0x891b , r.as_mut_ptr() as usize) } as isize) < 0 {
                        continue;
                    }
                    let mask = u32::from_ne_bytes([r[20], r[21], r[22], r[23]]);
                    g.0[k] = (addr, mask);
                    k += 1;
                }
                g.1 = k;
            }
            unsafe { syscall::syscall1(syscall::SYS_CLOSE, sd as usize) };
        }
        rusty_libc_core::errno::set(save);
    }
    *out = g.0;
    g.1
}

pub fn validate_service_line(spec: &[u8]) -> bool {
    rusty_libc_core::nssmod::parse_sources(spec).is_some()
}

const NSS_DATABASES: [&[u8]; 17] = [
    b"aliases", b"ethers", b"group", b"group_compat", b"gshadow", b"hosts", b"initgroups", b"netgroup", b"networks", b"passwd", b"passwd_compat", b"protocols", b"publickey", b"rpc", b"services", b"shadow", b"shadow_compat",
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_configure_lookup(dbname: *const c_char, string: *const c_char) -> c_int {
    use crate::netdb::{CIn, Str};
    let (db, line) = unsafe { (Str(dbname), Str(string)).conv() };
    configure_lookup(db.to_bytes(), line.to_bytes())
}

pub fn configure_lookup(db: &[u8], line: &[u8]) -> c_int {
    if !NSS_DATABASES.contains(&db) {
        return -1;
    }
    if !validate_service_line(line) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    if !rusty_libc_core::nssent::configure(db, line) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    0
}

pub fn hosts_order() -> Order {
    convert(&rusty_libc_core::nssmod::order(b"hosts"), true)
}

pub fn open_db(db: Db) -> Result<LineReader, i32> {
    LineReader::open(&db_path(db))
}

#[allow(dead_code)]
pub(crate) fn _unused(_: i64) -> i64 {
    syscall::SYS_READ as i64
}

