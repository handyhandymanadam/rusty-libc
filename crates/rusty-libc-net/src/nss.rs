//! The name service switch, reduced to what exists here: the `files` backend for hosts, services,
//! protocols, networks, rpc, aliases and ethers (`/etc/<db>`), the `dns` backend (see [`crate::dns`]), and
//! `/etc/nsswitch.conf` (only the order of `files` and `dns` is honoured; every other source name, such as
//! `myhostname`, `resolve`, `mdns4_minimal`, `systemd`, `nis`, is ignored, including its `[STATUS=action]`
//! list), plus `/etc/host.conf` (`multi on`).
//!
//! The file formats follow glibc's `nss_files`: leading white space is dropped, empty lines and lines that
//! start with `#` are skipped, `#` anywhere ends a line, fields are separated by white space, a line that
//! does not parse is skipped silently.
//!
//! Unsafe that stays: the system calls with pointer arguments (open, stat, the interface ioctls), the heap block of
//! [`LineReader`]'s long lines, the exported `_res_hconf` (C may read it), and walking the C `hostent` arrays in
//! [`trim_domains`] / [`reorder_addrs`].
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::inet;
use crate::types::*;
use crate::util::{Buf, Spin, eq_nocase, is_space};
use core::ffi::{c_char, c_int};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::syscall;

/// The databases that have a files backend.
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

/// Directory that holds the databases (default `/etc`). Tests and the Rust API can point it elsewhere.
static ETC: Spin<Buf<200>> = Spin::new(Buf::new());

/// Use `dir` instead of `/etc` for hosts, services, protocols, networks, rpc, aliases, ethers, netgroup,
/// nsswitch.conf, host.conf and resolv.conf. An empty `dir` restores `/etc`.
pub fn set_etc_dir(dir: &[u8]) -> bool {
    match Buf::<200>::from(dir) {
        Some(b) => {
            *ETC.lock() = b;
            // nsswitch.conf is read by rusty-libc-core: point it there too
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

/// `<etc>/<name>` as a NUL-terminated string.
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

// ---------------------------------------------------------------- heap helpers (shared by the crate's modules)

/// A block from the library's allocator whose `cap` bytes are all initialised (zeroed when obtained), freed on drop: a
/// growable buffer that can be handed out as a slice.
pub(crate) struct ZBuf {
    p: *mut u8,
    cap: usize,
}

// SAFETY: the block is owned by the ZBuf alone (no other pointer to it is kept), so it may move to another thread with it.
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
    /// Resize to `ncap` bytes (realloc: the first `min(cap, ncap)` bytes are kept, new bytes are zero). False, with the old
    /// block kept, when memory is short.
    pub(crate) fn grow(&mut self, ncap: usize) -> bool {
        // SAFETY: `p` is NULL or our own block from the same allocator.
        let nb = unsafe { rusty_libc_malloc::realloc(self.p as *mut core::ffi::c_void, ncap) } as *mut u8;
        if nb.is_null() {
            return false;
        }
        if ncap > self.cap {
            // SAFETY: bytes `cap..ncap` lie inside the new block of `ncap` bytes, ours alone.
            unsafe { nb.wrapping_add(self.cap).write_bytes(0, ncap - self.cap) };
        }
        self.p = nb;
        self.cap = ncap;
        true
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `cap` initialised bytes owned by this value (or none).
        unsafe { rusty_libc_core::ffi::bytes(self.p, self.cap) }
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above; `&mut self` makes the slice the only access.
        unsafe { rusty_libc_core::ffi::bytes_mut(self.p, self.cap) }
    }
}

/// A reply from the name service cache daemon of a size known only from its header lands in a `ZBuf`.
impl rusty_libc_core::nscd::Sink for ZBuf {
    fn reserve(&mut self, bytes: usize) -> bool {
        bytes <= self.cap || self.grow(bytes)
    }
    fn bytes(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for ZBuf {
    fn drop(&mut self) {
        if !self.p.is_null() {
            // SAFETY: our own block, freed once.
            unsafe { rusty_libc_malloc::free(self.p as *mut core::ffi::c_void) };
        }
    }
}

/// `s` and a NUL in a fresh block from the library's allocator (`malloc(len + 1)`, glibc's strndup), or NULL. The caller
/// owns the block.
pub(crate) fn c_dup(s: &[u8]) -> *mut u8 {
    // SAFETY: malloc has no precondition.
    let p = unsafe { rusty_libc_malloc::malloc(s.len() + 1) } as *mut u8;
    if !p.is_null() {
        // SAFETY: `p` has room for `s.len() + 1` bytes and is not `s`'s memory (fresh).
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
        // SAFETY: the last byte of the block.
        unsafe { p.wrapping_add(s.len()).write(0) };
    }
    p
}

/// `v` in a fresh block from the library's allocator (malloc of its size), or NULL. The caller owns the block.
pub(crate) fn heap_new<T>(v: T) -> *mut T {
    // SAFETY: malloc has no precondition.
    let p = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<T>()) } as *mut T;
    if !p.is_null() {
        // SAFETY: a fresh block of the size of `T`, aligned to 16 (malloc) which covers the library's types.
        unsafe { p.write(v) };
    }
    p
}

// ---------------------------------------------------------------- reading lines

/// Reads text files line by line from a descriptor (any line length).
pub struct LineReader {
    fd: c_int,
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    eof: bool,
    big: ZBuf,
    /// The last line came from the heap buffer (length) rather than `buf` (start offset).
    last_big: Option<usize>,
    last_start: usize,
    /// The last line returned by `next_line` ended with a newline (false: the end of the file cut it).
    last_nl: bool,
    held: Option<usize>,
}

/// Where the last line lies: in `buf` (start, end) or at the start of the heap block (length).
#[derive(Clone, Copy)]
enum Span {
    Buf(usize, usize),
    Big(usize),
}


impl LineReader {
    pub const fn closed() -> LineReader {
        LineReader { fd: -1, buf: [0; 4096], pos: 0, len: 0, eof: false, big: ZBuf::new(), last_big: None, last_start: 0, last_nl: true, held: None }
    }

    /// Open `path` (NUL-terminated) for reading.
    pub fn open(path: &Buf<320>) -> Result<LineReader, i32> {
        let mut r = LineReader::closed();
        let path = path.as_bytes();
        debug_assert!(path.last() == Some(&0));
        // SAFETY: `path` is NUL-terminated (the callers' Buf ends with the NUL), so open reads inside it.
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

    /// Back to the start of the file.
    pub fn rewind(&mut self) {
        if self.fd >= 0 {
            let _ = rusty_libc_core::unistd::lseek(self.fd, 0, 0);
        }
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        self.held = None;
    }

    /// The file offset of the next byte `getc` or `fgets` returns (`None` when the descriptor is not seekable).
    pub fn tell(&self) -> Option<i64> {
        let end = rusty_libc_core::unistd::lseek(self.fd, 0, 1).ok()?;
        Some(end - (self.len - self.pos) as i64)
    }

    /// Go back to a file offset `tell` returned.
    pub fn seek(&mut self, offset: i64) {
        let _ = rusty_libc_core::unistd::lseek(self.fd, offset, 0);
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        self.held = None;
    }

    /// Give the line last returned by `next_line` back (the next call returns it again).
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

    /// The first `n` bytes of the heap block.
    fn big(&self, n: usize) -> &[u8] {
        &self.big.as_slice()[..n]
    }

    fn span(&self, sp: Span) -> &[u8] {
        match sp {
            Span::Buf(s, e) => &self.buf[s..e],
            Span::Big(n) => self.big(n),
        }
    }

    /// The next line without its newline, or None at the end of the file.
    pub fn next_line(&mut self) -> Option<&[u8]> {
        let sp = self.next_span()?;
        Some(self.span(sp))
    }

    fn next_span(&mut self) -> Option<Span> {
        if let Some(n) = self.held.take() {
            self.last_big = Some(n);
            return Some(Span::Big(n));
        }
        // fast path: the whole line is in the buffer
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
        // slow path: assemble the line in the heap block
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
                    // out of memory: drop the rest of the line
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

    /// The next line like `next_line` plus the length glibc's `fgets` would have read for it: the newline counts.
    pub fn next_raw(&mut self) -> Option<(&[u8], usize)> {
        let sp = self.next_span()?;
        let nl = self.last_nl as usize;
        let line = self.span(sp);
        Some((line, line.len() + nl))
    }

    /// The next line that is neither empty nor a comment, with leading white space removed, and cut at
    /// the first `#` (what glibc's `__nss_readline` plus the line parsers do together).
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

/// The part of a line a parser sees: leading white space removed, cut at the first `#`; None for an empty line or a comment
/// (what `next_entry` does for each line).
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
    /// stdio's `fgets` on the descriptor: reads at most `dst.len() - 1` bytes into `dst`, stopping after a newline, and
    /// NUL-terminates. False when nothing could be read (end of file). The aliases parser works on the raw stream like glibc's.
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

    /// stdio's `getc`: -1 at the end of the file.
    pub fn getc(&mut self) -> i32 {
        if self.pos >= self.len && !self.fill() {
            return -1;
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        c as i32
    }

    /// Push back the byte `getc` just returned.
    pub fn ungetc(&mut self) {
        if self.pos > 0 {
            self.pos -= 1;
        }
    }

    /// stdio's `feof`: a read has hit the end of the file.
    pub fn at_eof(&self) -> bool {
        self.eof && self.pos >= self.len
    }
}

impl Drop for LineReader {
    fn drop(&mut self) {
        self.close();
    }
}

/// White space separated fields of a line.
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

/// `strtoul(s, &end, 10)` clamped to 32 bits, as glibc's `strtou32`: (value, bytes used) with 0 bytes used
/// when there is no number.
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

// ---------------------------------------------------------------- parsed lines

/// One line of /etc/hosts. Addresses are converted for the requested family like glibc does.
pub struct HostLine<'a> {
    pub family: c_int,
    pub addr: [u8; 16],
    pub name: &'a [u8],
    pub rest: &'a [u8],
}

/// Parse a hosts line for family `af` (AF_UNSPEC, AF_INET, AF_INET6). `v4mapped` is `AI_V4MAPPED`.
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
    // the aliases are the text after the name
    let off = name.as_ptr() as usize - line.as_ptr() as usize + name.len();
    Some(HostLine { family, addr, name, rest: &line[off..] })
}

/// A services line: name, port (host order), protocol, aliases text.
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

/// "name number aliases" (protocols, rpc).
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

/// "name network aliases" (networks): the number is `inet_network` shifted to a full address.
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
    // (glibc copies the field into a 64-byte buffer first: a longer one is no entry)
    if addr.len() > 64 {
        return None;
    }
    // inet_network on the field as a C string (it ends at a NUL, if one is in it)
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

/// Number of whitespace separated words in `rest` and an iterator over them.
pub fn words(rest: &[u8]) -> Fields<'_> {
    fields(rest)
}

// ---------------------------------------------------------------- nsswitch.conf and host.conf

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Files,
    Dns,
    /// A plug-in module (`libnss_NAME.so.2`, shared libc only): the name is in the entry.
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
    /// `merge`: only the group database can merge two answers; for the hosts a SUCCESS with this action fails with EINVAL.
    Merge,
}

/// A source with what to do after each outcome of a lookup in it.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub src: Source,
    pub act: [Action; 4], // indexed by Status
    /// The module's name when `src` is `Module`.
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
    /// glibc's built-in default for a missing `hosts:` line.
    pub fn default_hosts() -> Order {
        // "dns [!UNAVAIL=return] files"
        let mut o = Order { e: [Entry::new(Source::Dns, default_actions()); 8], n: 2 };
        o.e[0].act = [Action::Return, Action::Return, Action::Continue, Action::Return];
        o.e[1] = Entry::new(Source::Files, default_actions());
        o
    }
}

/// The hosts-style view of a list of sources parsed by rusty-libc-core (glibc's own parser, `nssmod::parse_sources`): `files` and
/// `compat` are the files, `dns` the resolver, any other name a plug-in module (where modules cannot be loaded such a source is dropped, or with `keep_unloadable` is one
/// that fails to load). `merge` counts as `continue` here.
fn convert(o: &rusty_libc_core::nssmod::Order, keep_unloadable: bool) -> Order {
    use rusty_libc_core::nssmod::{self as m, ACT_RETURN};
    let mut r = Order { e: [Entry::new(Source::Files, default_actions()); 8], n: 0 };
    for s in &o.e[..o.n] {
        let src = if s.is(b"files") || s.is(b"compat") {
            Some(Source::Files)
        } else if s.is(b"dns") {
            Some(Source::Dns)
        } else if s.len > 0 && (keep_unloadable || m::supported()) {
            // (for lookups, where modules cannot be loaded, a static program, this is a module that fails to load: UNAVAIL,
            // as for a missing library in glibc)
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

/// Parse the right hand side of one `db: ...` line (None for a line glibc rejects, or one that names no usable source).
pub fn parse_order(spec: &[u8]) -> Option<Order> {
    let o = convert(&rusty_libc_core::nssmod::parse_sources(spec)?, false);
    if o.n == 0 { None } else { Some(o) }
}

/// The lookup order for database `name` (`hosts`, `networks`, ...): what `__nss_configure_lookup` set, else nsswitch.conf,
/// else glibc's default for the database; None when that leaves no usable source.
pub fn order_for(name: &[u8]) -> Option<Order> {
    let o = convert(&rusty_libc_core::nssmod::order(name), true);
    if o.n == 0 { None } else { Some(o) }
}

/// Change signature of a file (inode, size and modification time; all ones when it does not exist).
pub(crate) fn file_sig(path: &Buf<320>) -> [u64; 3] {
    let mut st = [0u64; 18];
    debug_assert!(path.as_bytes().last() == Some(&0));
    // SAFETY: `path` is NUL-terminated; stat writes one 144-byte `struct stat` into `st` (144 bytes).
    let r = unsafe { rusty_libc_core::syscall::sys_stat(path.b.as_ptr() as usize, st.as_mut_ptr() as usize) };
    if syscall::check(r).is_err() {
        return [u64::MAX; 3];
    }
    // x86-64 struct stat: ino at word 1, size at word 6, mtime at words 11 and 12
    [st[1], st[11] ^ (st[6] << 32), st[12]]
}

static HCONF_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// glibc reads `/etc/host.conf` once, when the first hosts lookup makes its resolver context (`_res_hconf_init`): when the file
/// is missing, errno is ENOENT from then on until something sets it again. A failing lookup returns that errno.
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
    // SAFETY: once (HCONF_DONE), before any reader of _res_hconf in this library; glibc fills it the same way (no lock,
    // `initialized` last).
    unsafe { _res_hconf.with_unsync(|h| hconf_fill(h, &path)) };
    let init = _res_hconf.as_ptr().cast::<core::sync::atomic::AtomicI32>();
    // SAFETY: `initialized` is the first field of the repr(C) Hconf, an aligned c_int, so it can be viewed as an AtomicI32
    // (same size and alignment); the store publishes the filled structure.
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

/// glibc's `struct hconf` (resolv/res_hconf.h): what `/etc/host.conf` and the RESOLV_* variables said, read once at the first
/// hosts lookup. Exported as `_res_hconf` (GLIBC_2.2.5) for old programs and NSS modules that look at `flags`; this library's
/// own lookups read it through `host_conf_multi`, `trim_domains` and `reorder_addrs`.
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

/// Written once by [`hconf_init`] (the first caller, guarded by HCONF_DONE), read after that: the rule glibc has for it.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _res_hconf: SyncCell<Hconf> = SyncCell::new(Hconf::ZERO);

/// The host.conf settings, after hconf_init has filled them.
fn hconf() -> &'static Hconf {
    hconf_init();
    // SAFETY: hconf_init has run (in this or another thread, which wrote before setting HCONF_DONE); the structure is not
    // written again (a program writing `_res_hconf` itself takes glibc's risk).
    unsafe { &*_res_hconf.as_ptr() }
}

/// glibc's `skip_string`: up to white space, a comment, a comma or the end.
fn hconf_word(s: &[u8]) -> usize {
    s.iter().position(|&c| is_space(c) || c == b'#' || c == b',').unwrap_or(s.len())
}

fn hconf_ws(s: &[u8]) -> &[u8] {
    &s[s.iter().position(|&c| !is_space(c)).unwrap_or(s.len())..]
}

/// One of glibc's host.conf warnings on standard error (`__fxprintf (NULL, "%s", buf)` of an `_()` message): `fmt` is the
/// English printf format, `args` its arguments (strings as NUL-terminated byte strings, numbers as such).
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
        // the English text: the format with its %s and %d filled in
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
    // SAFETY: a plain write(2) of a buffer we own.
    unsafe { syscall::syscall3(syscall::SYS_WRITE, 2, b.as_ptr() as usize, b.len()) as isize }
}

/// An argument of a host.conf warning: a NUL-terminated string or a number.
enum HcArg<'a> {
    S(&'a [u8]),
    D(c_int),
}

/// `s` with a NUL after it, for a warning (cut to 300 bytes; host.conf lines have at most 255).
fn hc_cstr(s: &[u8]) -> Buf<320> {
    let mut b = Buf::<320>::new();
    b.push_all(&s[..s.len().min(300)]);
    b.push(0);
    b
}

/// glibc's `arg_bool`: a leading "on" or "off" (any case) sets or clears `flag`; anything else is warned about. Returns the
/// rest of the text (None after a warning).
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

/// glibc's `arg_trimdomain_list`: up to four domains, separated by white space or `,` `;` `:`, each kept as a malloc'd copy.
/// Returns the rest of the line (None after a warning).
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

/// glibc's `parse_line` for host.conf: `order` (ignored), `trim`, `multi`, `reorder` (the whole word, any case); another
/// word, or text after the arguments other than white space and a comment, is warned about.
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
    // the rest of the line must be white space or a comment
    if let Some(r) = after {
        let r = hconf_ws(r);
        if !r.is_empty() && r[0] != b'#' {
            let (f, a) = (hc_cstr(fname), hc_cstr(r));
            hconf_warn(c"%s: line %d: ignoring trailing garbage `%s'\n", &[HcArg::S(f.as_bytes()), HcArg::D(line), HcArg::S(a.as_bytes())]);
        }
    }
}

/// `multi on` (host.conf or RESOLV_MULTI): the files backend's gethostbyname merges every line of a name, getaddrinfo takes
/// every line (glibc's `_res_hconf.flags & HCONF_FLAG_MULTI`).
pub fn host_conf_multi() -> bool {
    hconf().flags & HCONF_FLAG_MULTI != 0
}

/// glibc's `_res_hconf_trim_domains`: cut the first trim domain that ends a name (any case, and only when the name is
/// longer) off the name and every alias, in place.
///
/// # Safety
/// `hp` is a valid hostent whose strings are writable.
pub unsafe fn trim_domains(hp: *mut crate::types::hostent) {
    let h = hconf();
    if h.num_trimdomains == 0 {
        return;
    }
    let trims = &h.trimdomain[..h.num_trimdomains as usize];
    // SAFETY: `hp` is a valid hostent (caller).
    let he = unsafe { &*hp };
    // SAFETY: h_name is a writable C string in the caller's buffer.
    trim_name(unsafe { cstr_mut(he.h_name) }, trims);
    let mut a = he.h_aliases;
    loop {
        // SAFETY: h_aliases is a NULL-terminated array (caller); `a` has not passed its NULL.
        let p = unsafe { *a };
        if p.is_null() {
            break;
        }
        // SAFETY: each alias is a writable C string.
        trim_name(unsafe { cstr_mut(p) }, trims);
        a = a.wrapping_add(1);
    }
}

/// The bytes of the writable C string at `p`, with its NUL.
///
/// # Safety
/// `p` is a non-NULL NUL-terminated string nothing else accesses for `'a`.
unsafe fn cstr_mut<'a>(p: *mut c_char) -> &'a mut [u8] {
    // SAFETY: forwarded contract.
    let n = unsafe { crate::util::cstrlen(p) };
    // SAFETY: the `n` bytes and the NUL are the string's (forwarded contract).
    unsafe { core::slice::from_raw_parts_mut(p as *mut u8, n + 1) }
}

/// Cut the first trim domain that ends `name` (with its NUL; longer than the domain, any case) by writing a NUL over it.
fn trim_name(name: &mut [u8], trims: &[*const c_char]) {
    let len = name.len() - 1;
    for &t in trims {
        // SAFETY: the trim domains are NULL or the NUL-terminated copies hconf_trim made, never freed.
        let Some(t) = (unsafe { rusty_libc_core::ffi::cstr(t) }) else { continue };
        let t = t.to_bytes();
        if len > t.len() && eq_nocase(&name[len - t.len()..len], t) {
            name[len - t.len()] = 0;
            break;
        }
    }
}

/// glibc's `_res_hconf_reorder_addrs` (`reorder on`): for an IPv4 result, the first address that is on the subnet of one of
/// the machine's interfaces (SIOCGIFCONF, SIOCGIFNETMASK) changes places with the first address.
///
/// # Safety
/// `hp` is a valid hostent.
pub unsafe fn reorder_addrs(hp: *mut crate::types::hostent) {
    if hconf().flags & HCONF_FLAG_REORDER == 0 {
        return;
    }
    // SAFETY: `hp` is a valid hostent (caller).
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
    // SAFETY: h_addr_list is a NULL-terminated array (caller); the loop stops at its NULL.
    while !unsafe { *list.wrapping_add(count) }.is_null() {
        count += 1;
    }
    // SAFETY: the `count` entries before the NULL are the caller's pointer array, writable, not otherwise borrowed.
    let addrs = unsafe { core::slice::from_raw_parts_mut(list, count) };
    for i in 0..count {
        // SAFETY: every entry of an AF_INET list points to a 4-byte address.
        let a = u32::from_ne_bytes(unsafe { *(addrs[i] as *const [u8; 4]) });
        if ifs[..n].iter().any(|&(addr, mask)| (a ^ addr) & mask == 0) {
            addrs.swap(0, i);
            return;
        }
    }
}

/// The IPv4 interfaces and their netmasks (address and mask in network order), as glibc's `__ifreq` + SIOCGIFNETMASK; read
/// once, kept when there is at least one (glibc's `num_ifs`). errno is kept.
fn local_ipv4_nets(out: &mut [(u32, u32); 64]) -> usize {
    static NETS: Spin<([(u32, u32); 64], usize)> = Spin::new(([(0, 0); 64], 0));
    let mut g = NETS.lock();
    if g.1 == 0 {
        let save = rusty_libc_core::errno::get();
        // SAFETY: plain values only.
        let sd = unsafe { syscall::syscall3(41 /* socket */, 2 /* AF_INET */, 2 | 0o2000000 /* SOCK_DGRAM | SOCK_CLOEXEC */, 0) } as isize;
        if sd >= 0 {
            // struct ifconf { int len; char *buf; } over struct ifreq[64] (40 bytes each)
            let mut reqs = [0u8; 40 * 64];
            let mut ifc = [0u64; 2];
            ifc[0] = reqs.len() as u64;
            ifc[1] = reqs.as_mut_ptr() as u64;
            // SAFETY: `ifc` is a struct ifconf whose buffer `reqs` is writable for the length it states.
            if unsafe { syscall::syscall3(syscall::SYS_IOCTL, sd as usize, 0x8912 /* SIOCGIFCONF */, ifc.as_mut_ptr() as usize) } as isize >= 0 {
                let count = (ifc[0] as u32 as usize) / 40;
                let mut k = 0;
                for i in 0..count.min(64) {
                    let r = &mut reqs[i * 40..i * 40 + 40];
                    // ifr_addr at 16: sa_family (2 bytes), port, then the address
                    if u16::from_ne_bytes([r[16], r[17]]) != 2 {
                        continue;
                    }
                    let addr = u32::from_ne_bytes([r[20], r[21], r[22], r[23]]);
                    // SAFETY: `r` is one 40-byte struct ifreq, read and written by the ioctl.
                    if (unsafe { syscall::syscall3(syscall::SYS_IOCTL, sd as usize, 0x891b /* SIOCGIFNETMASK */, r.as_mut_ptr() as usize) } as isize) < 0 {
                        continue;
                    }
                    let mask = u32::from_ne_bytes([r[20], r[21], r[22], r[23]]);
                    g.0[k] = (addr, mask);
                    k += 1;
                }
                g.1 = k;
            }
            // SAFETY: plain values only.
            unsafe { syscall::syscall1(syscall::SYS_CLOSE, sd as usize) };
        }
        rusty_libc_core::errno::set(save);
    }
    *out = g.0;
    g.1
}

/// Is `spec` a service line glibc's parser accepts (`nss_action_parse`)? See rusty-libc-core's `nssmod::parse_sources`.
pub fn validate_service_line(spec: &[u8]) -> bool {
    rusty_libc_core::nssmod::parse_sources(spec).is_some()
}

/// The databases `__nss_configure_lookup` knows.
const NSS_DATABASES: [&[u8]; 17] = [
    b"aliases", b"ethers", b"group", b"group_compat", b"gshadow", b"hosts", b"initgroups", b"netgroup", b"networks", b"passwd", b"passwd_compat", b"protocols", b"publickey", b"rpc", b"services", b"shadow", b"shadow_compat",
];

/// `__nss_configure_lookup (dbname, string)`: replace the source list of database `dbname` with the
/// nsswitch line `string`. 0 on success; -1 for an unknown database (errno untouched) or, with
/// EINVAL, a malformed line. Every database takes the new source list (lookups, enumeration, netgroups and
/// the plug-in module loader read it through rusty_libc_core::nssent), like glibc.
///
/// # Safety
/// Both arguments are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_configure_lookup(dbname: *const c_char, string: *const c_char) -> c_int {
    use crate::netdb::{CIn, Str};
    // SAFETY: both are C strings (the caller's contract).
    let (db, line) = unsafe { (Str(dbname), Str(string)).conv() };
    configure_lookup(db.to_bytes(), line.to_bytes())
}

/// [`__nss_configure_lookup`] on byte strings.
pub fn configure_lookup(db: &[u8], line: &[u8]) -> c_int {
    if !NSS_DATABASES.contains(&db) {
        return -1;
    }
    if !validate_service_line(line) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    // every database (hosts included): lookups, enumeration, netgroups and the module loader read the sources from here
    if !rusty_libc_core::nssent::configure(db, line) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    0
}

/// Order of sources for hosts lookups (nsswitch.conf is re-read when it changes); `n == 0` is no source at all.
pub fn hosts_order() -> Order {
    convert(&rusty_libc_core::nssmod::order(b"hosts"), true)
}

/// Open `db`'s file for a one-shot scan.
pub fn open_db(db: Db) -> Result<LineReader, i32> {
    LineReader::open(&db_path(db))
}

#[allow(dead_code)]
pub(crate) fn _unused(_: i64) -> i64 {
    syscall::SYS_READ as i64
}

#[cfg(test)]
#[path = "nss_configure_tests.rs"]
mod configure_tests;
