use crate::inet;
use crate::types::*;
use crate::util::{Buf, Spin, eq_nocase, is_space};
use core::ffi::{c_char, c_int};
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

pub struct LineReader {
    fd: c_int,
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    eof: bool,
    big: *mut u8,
    big_cap: usize,
    last_big: Option<usize>,
    last_start: usize,
    last_nl: bool,
    held: Option<usize>,
}

unsafe impl Send for LineReader {}

impl LineReader {
    pub const fn closed() -> LineReader {
        LineReader { fd: -1, buf: [0; 4096], pos: 0, len: 0, eof: false, big: core::ptr::null_mut(), big_cap: 0, last_big: None, last_start: 0, last_nl: true, held: None }
    }

    pub fn open(path: &Buf<320>) -> Result<LineReader, i32> {
        let mut r = LineReader::closed();
        let fd = unsafe { rusty_libc_core::unistd::open(path.b.as_ptr() as *const c_char, 0o2000000, 0) };
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
        if !self.big.is_null() {
            unsafe { rusty_libc_malloc::free(self.big as *mut core::ffi::c_void) };
            self.big = core::ptr::null_mut();
            self.big_cap = 0;
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

    pub fn next_line(&mut self) -> Option<&[u8]> {
        if let Some(n) = self.held.take() {
            self.last_big = Some(n);
            return Some(unsafe { core::slice::from_raw_parts(self.big, n) });
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
            return Some(&self.buf[s..s + i]);
        }
        let mut used = 0usize;
        let mut ended_by_newline = false;
        loop {
            let chunk_start = self.pos;
            let chunk_end = self.len;
            let nl = self.buf[chunk_start..chunk_end].iter().position(|&c| c == b'\n');
            let take = nl.unwrap_or(chunk_end - chunk_start);
            if used + take > self.big_cap {
                let ncap = (used + take).max(self.big_cap * 2).max(8192);
                let nb = unsafe { rusty_libc_malloc::realloc(self.big as *mut core::ffi::c_void, ncap) } as *mut u8;
                if nb.is_null() {
                    self.pos = chunk_end;
                    if nl.is_some() || !self.fill() {
                        return Some(&[]);
                    }
                    continue;
                }
                self.big = nb;
                self.big_cap = ncap;
            }
            unsafe { core::ptr::copy_nonoverlapping(self.buf.as_ptr().add(chunk_start), self.big.add(used), take) };
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
        Some(unsafe { core::slice::from_raw_parts(self.big, used) })
    }

    pub fn next_raw(&mut self) -> Option<(&[u8], usize)> {
        let line = self.next_line()?;
        let (p, n) = (line.as_ptr(), line.len());
        let line = unsafe { core::slice::from_raw_parts(p, n) };
        Some((line, n + self.last_nl as usize))
    }

    pub fn next_entry(&mut self) -> Option<&[u8]> {
        loop {
            let line = self.next_line()?;
            let (p, n) = (line.as_ptr(), line.len());
            let line = unsafe { core::slice::from_raw_parts(p, n) };
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
            return Some(&line[s..e]);
        }
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
    pub unsafe fn fgets(&mut self, dst: *mut u8, n: usize) -> bool {
        unsafe {
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
                core::ptr::copy_nonoverlapping(avail.as_ptr(), dst.add(got), chunk);
                got += chunk;
                self.pos += chunk;
                if nl {
                    break;
                }
            }
            *dst.add(got) = 0;
            got > 0
        }
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
    let mut tmp = Buf::<64>::from(addr)?;
    tmp.push(0);
    let mut net = unsafe { inet::inet_network(tmp.b.as_ptr() as *const c_char) };
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

fn convert(o: &rusty_libc_core::nssmod::Order) -> Order {
    use rusty_libc_core::nssmod::{self as m, ACT_RETURN};
    let mut r = Order { e: [Entry::new(Source::Files, default_actions()); 8], n: 0 };
    for s in &o.e[..o.n] {
        let src = if s.is(b"files") || s.is(b"compat") {
            Some(Source::Files)
        } else if s.is(b"dns") {
            Some(Source::Dns)
        } else if m::supported() && s.len > 0 {
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
    let o = convert(&rusty_libc_core::nssmod::parse_sources(spec)?);
    if o.n == 0 { None } else { Some(o) }
}

pub fn order_for(name: &[u8]) -> Option<Order> {
    let o = convert(&rusty_libc_core::nssmod::order(name));
    if o.n == 0 { None } else { Some(o) }
}

pub(crate) fn file_sig(path: &Buf<320>) -> [u64; 3] {
    let mut st = [0u64; 18];
    let r = unsafe { syscall::syscall2(syscall::SYS_STAT, path.b.as_ptr() as usize, st.as_mut_ptr() as usize) };
    if syscall::check(r).is_err() {
        return [u64::MAX; 3];
    }
    [st[1], st[11] ^ (st[6] << 32), st[12]]
}

struct Cached<T: Copy> {
    path: Buf<320>,
    sig: [u64; 3],
    val: T,
    valid: bool,
}

impl<T: Copy> Cached<T> {
    fn get(&mut self, path: &Buf<320>, load: impl FnOnce() -> T) -> T {
        let sig = file_sig(path);
        if !self.valid || self.path.as_bytes() != path.as_bytes() || self.sig != sig {
            self.val = load();
            self.path = *path;
            self.sig = sig;
            self.valid = true;
        }
        self.val
    }
}

static HOST_MULTI: Spin<Cached<bool>> = Spin::new(Cached { path: Buf::new(), sig: [0; 3], val: false, valid: false });

pub fn validate_service_line(spec: &[u8]) -> bool {
    rusty_libc_core::nssmod::parse_sources(spec).is_some()
}

const NSS_DATABASES: [&[u8]; 17] = [
    b"aliases", b"ethers", b"group", b"group_compat", b"gshadow", b"hosts", b"initgroups", b"netgroup", b"networks", b"passwd", b"passwd_compat", b"protocols", b"publickey", b"rpc", b"services", b"shadow", b"shadow_compat",
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_configure_lookup(dbname: *const c_char, string: *const c_char) -> c_int {
    let (db, line) = unsafe { (core::slice::from_raw_parts(dbname as *const u8, crate::util::cstrlen(dbname)), core::slice::from_raw_parts(string as *const u8, crate::util::cstrlen(string))) };
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
    convert(&rusty_libc_core::nssmod::order(b"hosts"))
}

pub fn host_conf_multi() -> bool {
    let path = etc_path(b"/host.conf");
    let mut multi = HOST_MULTI.lock().get(&path, || {
        let mut multi = false;
        if let Ok(mut r) = LineReader::open(&path) {
            while let Some(line) = r.next_entry() {
                let mut f = fields(line);
                if let (Some(k), Some(v)) = (f.next(), f.next()) {
                    if eq_nocase(k, b"multi") {
                        multi = bool_word(v).unwrap_or(multi);
                    }
                }
            }
        }
        multi
    });
    if let Some(v) = crate::util::getenv(b"RESOLV_MULTI") {
        multi = bool_word(v).unwrap_or(multi);
    }
    multi
}

fn bool_word(v: &[u8]) -> Option<bool> {
    if eq_nocase(v, b"on") || eq_nocase(v, b"yes") || eq_nocase(v, b"true") || v == b"1" {
        Some(true)
    } else if eq_nocase(v, b"off") || eq_nocase(v, b"no") || eq_nocase(v, b"false") || v == b"0" {
        Some(false)
    } else {
        None
    }
}

pub fn open_db(db: Db) -> Result<LineReader, i32> {
    LineReader::open(&db_path(db))
}

#[allow(dead_code)]
pub(crate) fn _unused(_: i64) -> i64 {
    syscall::SYS_READ as i64
}

