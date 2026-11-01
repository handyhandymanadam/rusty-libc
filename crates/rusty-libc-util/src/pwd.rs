//! pwd.h, grp.h, shadow.h with the "files" backend only (`/etc/passwd`, `/etc/group`,
//! `/etc/shadow`), plus `getlogin`, `getusershell` and the password-file lock.
//!
//! Behaviour follows glibc 2.43's files backend:
//! * Lines are read like `fgets` into the caller's buffer (the `_r` functions) and parsed in place,
//!   so every string of the result points into that buffer. A line needs `len + 2` bytes (the line
//!   with its newline, a NUL, and one more); a group line also needs room for the member pointer
//!   vector after it (aligned, with the NULL and one spare slot). A line that does not fit gives
//!   `ERANGE` and the stream is moved back so the next call reads the same line again.
//! * Blank lines and `#` comments are skipped (after leading white space); malformed lines are
//!   skipped silently; `+` and `-` (NIS) entries are parsed and returned by the `*ent` functions but
//!   never match a lookup by name or id.
//! * `getpwnam`-style functions keep one static buffer each (1024 bytes, doubled on `ERANGE`); the
//!   `_r` lookups clear `errno` on success and on "not found" and return 0 with `*result == NULL`
//!   for a missing name; `get*ent_r` returns `ENOENT` at the end.
//!
//! The by-name and by-id lookups and the group list ask the name service cache daemon first (rusty_libc_core::nscd), then
//! the sources of nsswitch.conf: the files backend and plug-in modules. A missing database file makes lookups fail with the
//! error from `open` (glibc would try the next module).
//!
//! Unsafe code (BRIEF-UNSAFE U2): the line readers and parsers are safe code on the caller's buffer as a slice (the
//! results' string pointers are computed from it, never followed); the C entry points convert their pointers once. What
//! stays unsafe: following the C strings and pointer vectors a caller or a plug-in module hands over ([`CList`],
//! `name_is`), calling the plug-in modules' functions through their addresses (`call_*`), the stdio stream calls
//! ([`FileSrc`]), the heap blocks of the static buffers and line builders, and a few raw system calls (alarm, fcntl lock,
//! readlink, setgroups).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem;
use crate::cmem::CVec;
use core::cell::RefCell;
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::nscd::reply::{GroupLayout, PasswdLayout};
use rusty_libc_core::nscd::{self, GidList, Res};
use rusty_libc_core::{errno, ffi, nssent, nssmod, syscall, unistd};
use rusty_libc_stdio::file::File;

pub mod ent;
pub mod sgrp;
pub(crate) use ent::*;
pub use sgrp::*;

pub type Uid = u32;
pub type Gid = u32;

const ENOENT: i32 = 2;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const ESPIPE: i32 = 29;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;

const O_RDONLY: i32 = 0;
const O_CLOEXEC: i32 = 0o2000000;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0o100;

/// `struct passwd`.
#[repr(C)]
pub struct Passwd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: Uid,
    pub pw_gid: Gid,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

/// `struct group`.
#[repr(C)]
pub struct Group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: Gid,
    pub gr_mem: *mut *mut c_char,
}

/// `struct spwd`.
#[repr(C)]
pub struct Spwd {
    pub sp_namp: *mut c_char,
    pub sp_pwdp: *mut c_char,
    pub sp_lstchg: i64,
    pub sp_min: i64,
    pub sp_max: i64,
    pub sp_warn: i64,
    pub sp_inact: i64,
    pub sp_expire: i64,
    pub sp_flag: u64,
}

impl Passwd {
    const fn zero() -> Passwd {
        Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() }
    }
}
impl Group {
    const fn zero() -> Group {
        Group { gr_name: null_mut(), gr_passwd: null_mut(), gr_gid: 0, gr_mem: null_mut() }
    }
}
impl Spwd {
    const fn zero() -> Spwd {
        Spwd { sp_namp: null_mut(), sp_pwdp: null_mut(), sp_lstchg: 0, sp_min: 0, sp_max: 0, sp_warn: 0, sp_inact: 0, sp_expire: 0, sp_flag: 0 }
    }
}

// ------------------------------------------------------------------------------ C data handed over

/// The bytes of the C string at `p`; NULL reads as "".
///
/// # Safety
/// `p` is NULL or a C string that stays valid and unchanged for `'a`.
unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: forwarded contract.
    unsafe { ffi::cstr(p) }.map_or(b"", CStr::to_bytes)
}

/// A NULL-terminated vector of C strings (`gr_mem`, `sg_adm`, `sg_mem`), read in place; NULL is an empty list.
#[derive(Clone, Copy)]
pub(crate) struct CList<'a> {
    p: *const *mut c_char,
    _l: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> CList<'a> {
    /// # Safety
    /// `p` is NULL or a NULL-terminated vector of C strings, all valid and unchanged for `'a`.
    pub(crate) unsafe fn new(p: *const *mut c_char) -> CList<'a> {
        CList { p, _l: core::marker::PhantomData }
    }
    /// The string pointers, in order.
    pub(crate) fn ptrs(self) -> impl Iterator<Item = *mut c_char> + 'a {
        let mut i = 0;
        core::iter::from_fn(move || {
            if self.p.is_null() {
                return None;
            }
            // SAFETY: the vector is readable up to its NULL (`new`'s contract) and iteration stops there.
            let q = unsafe { *self.p.wrapping_add(i) };
            if q.is_null() {
                return None;
            }
            i += 1;
            Some(q)
        })
    }
    /// The strings, in order.
    pub(crate) fn iter(self) -> impl Iterator<Item = &'a [u8]> + 'a {
        // SAFETY: every entry before the NULL is a C string valid for `'a` (`new`'s contract).
        self.ptrs().map(|q| unsafe { cbytes(q) })
    }
}

/// Does the C string `field` (a string of a parsed entry) equal `name`?
fn name_is(name: Option<&[u8]>, field: *const c_char) -> bool {
    // SAFETY: the strings of an entry just parsed or returned by a module are C strings in the caller's buffer (or the
    // module's memory), valid until that buffer is reused.
    name.is_some_and(|n| unsafe { cbytes(field) } == n)
}

/// A `+`/`-` (NIS) name.
fn is_nis(p: *const c_char) -> bool {
    // SAFETY: NULL or the first byte of a C string (a name given by the caller or parsed into an entry).
    !p.is_null() && matches!(unsafe { *p } as u8, b'+' | b'-')
}

// ------------------------------------------------------------------------------ line sources

/// Where lines come from: a raw descriptor (the lookup functions) or a stdio stream (`fgetpwent`).
pub(crate) trait Src {
    /// `fgets(buf, buf.len())`: false means NULL (end of file, or error with errno set).
    fn gets(&mut self, buf: &mut [u8]) -> bool;
    fn at_eof(&self) -> bool;
    fn tell(&mut self) -> i64;
    fn seek(&mut self, off: i64) -> bool;
}

/// A minimal buffered reader on a file descriptor.
pub(crate) struct FdStream {
    fd: c_int,
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    /// File offset of `buf[0]`.
    base: i64,
    eof: bool,
}

impl FdStream {
    /// `fopen(path, "rce")`; Err(errno).
    pub(crate) fn open(path: &CStr) -> Result<FdStream, i32> {
        match cmem::open(path, O_RDONLY | O_CLOEXEC, 0) {
            Ok(fd) => Ok(FdStream { fd, buf: [0; 4096], pos: 0, len: 0, base: 0, eof: false }),
            Err(e) => Err(e.0),
        }
    }
    pub(crate) fn close(&mut self) {
        let _ = unistd::close(self.fd);
        self.fd = -1;
    }
    pub(crate) fn rewind(&mut self) {
        self.seek(0);
        self.eof = false;
    }
    /// Refill the buffer; false at end of file or error.
    fn fill(&mut self) -> bool {
        loop {
            self.base += self.len as i64;
            self.pos = 0;
            self.len = 0;
            match unistd::read_nocancel(self.fd, &mut self.buf) {
                Ok(0) => {
                    self.eof = true;
                    return false;
                }
                Ok(n) => {
                    self.len = n;
                    return true;
                }
                Err(e) if e.0 == EINTR => continue,
                Err(e) => {
                    errno::set(e.0);
                    return false;
                }
            }
        }
    }
}

impl FdStream {
    /// `fgets` into `buf` (NUL-terminated): the number of bytes read (0 at the end of the file or on an error).
    #[inline]
    fn gets_n(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len();
        if n == 0 {
            return 0;
        }
        let max = n - 1;
        let mut i = 0usize;
        while i < max {
            if self.pos >= self.len && !self.fill() {
                break;
            }
            let avail = &self.buf[self.pos..self.len];
            let take = avail.len().min(max - i);
            // (the dispatched memchr: a byte loop cost more for lines of more than a few bytes)
            let k = match rusty_libc_core::string::memchr(&avail[..take], b'\n') {
                Some(p) => p + 1,
                None => take,
            };
            buf[i..i + k].copy_from_slice(&avail[..k]);
            self.pos += k;
            i += k;
            if buf[i - 1] == b'\n' {
                break;
            }
        }
        if i == 0 {
            return 0;
        }
        buf[i] = 0;
        i
    }
}

impl Src for FdStream {
    fn gets(&mut self, buf: &mut [u8]) -> bool {
        self.gets_n(buf) > 0
    }
    fn at_eof(&self) -> bool {
        self.eof
    }
    fn tell(&mut self) -> i64 {
        self.base + self.pos as i64
    }
    fn seek(&mut self, off: i64) -> bool {
        if unistd::lseek(self.fd, off, 0).is_err() {
            return false;
        }
        self.base = off;
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        true
    }
}

/// A stdio stream (for `fgetpwent` and friends).
pub(crate) struct FileSrc(*mut File);

impl FileSrc {
    /// # Safety
    /// `f` is an open stdio stream that stays open while this value is used.
    pub(crate) unsafe fn new(f: *mut File) -> FileSrc {
        FileSrc(f)
    }
}

impl Src for FileSrc {
    fn gets(&mut self, buf: &mut [u8]) -> bool {
        // SAFETY: an open stream (`new`'s contract); `buf` is writable for its length.
        unsafe { !rusty_libc_stdio::fgets(buf.as_mut_ptr().cast(), buf.len() as c_int, self.0).is_null() }
    }
    fn at_eof(&self) -> bool {
        // SAFETY: an open stream (`new`'s contract).
        unsafe { rusty_libc_stdio::feof(self.0) != 0 }
    }
    fn tell(&mut self) -> i64 {
        // SAFETY: an open stream (`new`'s contract).
        rusty_libc_stdio::file::tell(unsafe { rusty_libc_stdio::file::stream(self.0) })
    }
    fn seek(&mut self, off: i64) -> bool {
        // SAFETY: an open stream (`new`'s contract).
        rusty_libc_stdio::file::seek(unsafe { rusty_libc_stdio::file::stream(self.0) }, off, 0) == 0
    }
}

impl FileSrc {
    /// `fwrite` the bytes in one call; true when all were written.
    fn write(&mut self, b: &[u8]) -> bool {
        // SAFETY: an open stream (`new`'s contract).
        rusty_libc_stdio::file::write_bytes(unsafe { rusty_libc_stdio::file::stream(self.0) }, b) == b.len()
    }
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

/// `strlen` of the bytes in `buf` (up to the first NUL, or all of it).
fn clen(buf: &[u8]) -> usize {
    // the dispatched memchr (a byte loop cost more than the strlen the code before the safe rewrite called)
    rusty_libc_core::string::memchr(buf, 0).unwrap_or(buf.len())
}

/// `__nss_readline`: the next non-blank, non-comment line (leading white space removed) in `buf`.
/// 0 = got one, ENOENT = end of file, ERANGE = the line did not fit (stream repositioned), other =
/// an errno.
fn readline<S: Src>(s: &mut S, buf: &mut [u8], poffset: &mut i64) -> i32 {
    let len = buf.len();
    if len < 3 {
        *poffset = -1;
        errno::set(ERANGE);
        return ERANGE;
    }
    loop {
        *poffset = s.tell();
        buf[len - 1] = 0xff;
        if !s.gets(buf) {
            if s.at_eof() {
                errno::set(ENOENT);
                return ENOENT;
            }
            let e = errno::get();
            if e == ERANGE {
                errno::set(EINVAL);
            }
            return errno::get();
        } else if buf[len - 1] != 0xff {
            // the buffer was too small: arrange to read the same line again
            return readline_seek(s, *poffset);
        }
        let mut p = 0;
        while isspace(buf[p]) {
            p += 1;
        }
        if buf[p] == 0 || buf[p] == b'#' {
            continue;
        }
        if p != 0 {
            // glibc moves strlen(p) bytes, not strlen(p) + 1: the NUL is not moved, so the
            // text that was after the shifted part stays (the parsers cut at the newline)
            let n = clen(&buf[p..]);
            buf.copy_within(p..p + n, 0);
        }
        return 0;
    }
}

fn readline_seek<S: Src>(s: &mut S, offset: i64) -> i32 {
    if offset < 0 || !s.seek(offset) {
        errno::set(ESPIPE);
        ESPIPE
    } else {
        errno::set(ERANGE);
        ERANGE
    }
}

/// `__nss_parse_line_result`: 1 -> 0, 0 -> EINVAL, -1 -> seek back and ERANGE.
fn parse_line_result<S: Src>(s: &mut S, offset: i64, r: i32) -> i32 {
    match r {
        1 => 0,
        0 => {
            errno::set(EINVAL);
            EINVAL
        }
        _ => readline_seek(s, offset),
    }
}

// ------------------------------------------------------------------------------ parsing

/// A line being parsed in place: its bytes up to its NUL (the slice ends there; a NUL written into it ends a field),
/// and the cursor. The string pointers stored in results are addresses inside `line`.
pub(crate) struct Cur<'a> {
    line: &'a mut [u8],
    i: usize,
}

impl Cur<'_> {
    /// The byte at the cursor, 0 at the end (the line's NUL).
    fn peek(&self) -> u8 {
        self.line.get(self.i).copied().unwrap_or(0)
    }
    fn at_end(&self) -> bool {
        self.i >= self.line.len()
    }
    /// The address of byte `k` of the line (`k` may be its length: the NUL after it).
    fn ptr(&mut self, k: usize) -> *mut c_char {
        self.line.as_mut_ptr().wrapping_add(k).cast()
    }
    /// Cut the line at its first newline (a NUL is written there).
    fn chop_newline(&mut self) {
        // (the newline is usually the last byte: the dispatched memchr, not a byte loop over the whole line)
        if let Some(k) = rusty_libc_core::string::memchr(self.line, b'\n') {
            self.line[k] = 0;
            let line = core::mem::take(&mut self.line);
            self.line = &mut line[..k];
        }
    }
    fn skip_space(&mut self) {
        while !self.at_end() && isspace(self.line[self.i]) {
            self.i += 1;
        }
    }
    /// STRING_FIELD with a colon terminator, not swallowing repeated colons.
    fn string_field(&mut self) -> *mut c_char {
        let start = self.i;
        let rest = self.line.get(start..).unwrap_or_default();
        match rest.iter().position(|&b| b == b':') {
            Some(k) => {
                self.i = start + k;
                self.line[self.i] = 0;
                self.i += 1;
            }
            None => self.i = start.max(self.line.len()),
        }
        self.ptr(start)
    }
    /// `strtoul(cursor, &endp, 10)` clamped to 32 bits like glibc's `strtou32`; the end is the cursor itself when there
    /// are no digits.
    #[inline(always)]
    fn strtou32(&self) -> (u32, usize) {
        let mut p = self.i;
        let at = |k: usize| self.line.get(k).copied().unwrap_or(0);
        while isspace(at(p)) {
            p += 1;
        }
        let mut neg = false;
        if at(p) == b'-' {
            neg = true;
            p += 1;
        } else if at(p) == b'+' {
            p += 1;
        }
        let start = p;
        let mut v: u64 = 0;
        let mut over = false;
        while at(p).is_ascii_digit() {
            let d = (at(p) - b'0') as u64;
            match v.checked_mul(10).and_then(|x| x.checked_add(d)) {
                Some(n) => v = n,
                None => over = true,
            }
            p += 1;
        }
        if p == start {
            return (0, self.i);
        }
        let val = if over {
            u64::MAX
        } else if neg {
            v.wrapping_neg()
        } else {
            v
        };
        (if val > 0xffff_ffff { 0xffff_ffff } else { val as u32 }, p)
    }
    /// Past the number ending at `e`: a colon is skipped, anything but the end is an error.
    #[inline(always)]
    fn field_end(&mut self, e: usize) -> bool {
        let c = self.line.get(e).copied().unwrap_or(0);
        if c == b':' {
            self.i = e + 1;
        } else if c != 0 {
            return false;
        } else {
            self.i = e;
        }
        true
    }
    /// INT_FIELD: false = parse error.
    #[inline(always)]
    fn int_field(&mut self, out: &mut u32) -> bool {
        let (v, e) = self.strtou32();
        *out = v;
        if e == self.i {
            return false;
        }
        self.field_end(e)
    }
    /// INT_FIELD_MAYBE_NULL: an empty field takes `default`; false = parse error.
    #[inline(always)]
    fn int_field_maybe_null(&mut self, out: &mut u32, default: u32) -> bool {
        if self.at_end() {
            return false;
        }
        let (v, e) = self.strtou32();
        *out = if e == self.i { default } else { v };
        self.field_end(e)
    }
    /// Is the first byte of the line (after fields were cut) `+` or `-`?
    fn first_is_nis(&self) -> bool {
        matches!(self.line.first(), Some(b'+' | b'-'))
    }
}

/// Room for a pointer vector after a line (`area`, possibly empty), filled at 8-byte aligned addresses.
pub(crate) struct Vec8<'a> {
    area: &'a mut [u8],
    /// Offset of the first slot (aligned) and the number of slots used.
    off: usize,
    n: usize,
}

impl<'a> Vec8<'a> {
    /// A vector starting at the first aligned address at or after `area[from..]`.
    fn new(area: &'a mut [u8], from: usize) -> Vec8<'a> {
        let a = (area.as_ptr() as usize).wrapping_add(from);
        let off = from + (a.wrapping_add(7) & !7).wrapping_sub(a);
        Vec8 { area, off, n: 0 }
    }
    /// Is there room for one more pointer and the terminating NULL? (glibc: `p + 2 > buf_end` fails)
    fn room(&self) -> bool {
        self.off + 8 * (self.n + 2) <= self.area.len()
    }
    fn push(&mut self, p: *mut c_char) {
        let o = self.off + 8 * self.n;
        self.area[o..o + 8].copy_from_slice(&(p as usize).to_ne_bytes());
        self.n += 1;
    }
    /// Store the terminating NULL; the vector's address and the offset just past the NULL.
    fn finish(mut self) -> (*mut *mut c_char, usize) {
        self.push(null_mut());
        (self.area.as_mut_ptr().wrapping_add(self.off).cast(), self.off + 8 * self.n)
    }
}

/// Split the caller's buffer, which holds the line at its start, into the line (up to its NUL) and the room after
/// that NUL (where the member vectors go: glibc's `buf_start = line + strlen(line) + 1`).
pub(crate) fn split_line(buf: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let n = clen(buf);
    let (line, rest) = buf.split_at_mut(n);
    let room = if rest.is_empty() { rest } else { &mut rest[1..] };
    (line, room)
}

/// One database: how to parse a line into its structure (returns 1 = ok, 0 = malformed,
/// -1 = out of buffer space). `line` is the line up to its NUL, `area` the room for pointer vectors.
pub(crate) trait Entry: Sized {
    const PATH: &'static CStr;
    fn parse(line: &mut [u8], area: &mut [u8], res: &mut Self) -> i32;
}

impl Entry for Passwd {
    const PATH: &'static CStr = c"/etc/passwd";
    fn parse(line: &mut [u8], _area: &mut [u8], r: &mut Passwd) -> i32 {
        let mut c = Cur { line, i: 0 };
        c.chop_newline();
        r.pw_name = c.string_field();
        let nis = c.first_is_nis();
        if c.at_end() && nis {
            r.pw_passwd = null_mut();
            r.pw_uid = 0;
            r.pw_gid = 0;
            r.pw_gecos = null_mut();
            r.pw_dir = null_mut();
            r.pw_shell = null_mut();
        } else {
            r.pw_passwd = c.string_field();
            if nis {
                if !c.int_field_maybe_null(&mut r.pw_uid, 0) || !c.int_field_maybe_null(&mut r.pw_gid, 0) {
                    return 0;
                }
            } else if !c.int_field(&mut r.pw_uid) || !c.int_field(&mut r.pw_gid) {
                return 0;
            }
            r.pw_gecos = c.string_field();
            r.pw_dir = c.string_field();
            let i = c.i;
            r.pw_shell = c.ptr(i);
        }
        1
    }
}

impl Entry for Group {
    const PATH: &'static CStr = c"/etc/group";
    fn parse(line: &mut [u8], area: &mut [u8], r: &mut Group) -> i32 {
        let mut c = Cur { line, i: 0 };
        c.chop_newline();
        r.gr_name = c.string_field();
        let nis = c.first_is_nis();
        if c.at_end() && nis {
            r.gr_passwd = null_mut();
            r.gr_gid = 0;
        } else {
            r.gr_passwd = c.string_field();
            if nis {
                if !c.int_field_maybe_null(&mut r.gr_gid, 0) {
                    return 0;
                }
            } else if !c.int_field(&mut r.gr_gid) {
                return 0;
            }
        }
        // member list: comma separated, white space skipped, empty items dropped
        match parse_list(&mut c, Vec8::new(area, 0)) {
            None => {
                errno::set(ERANGE);
                -1
            }
            Some(list) => {
                r.gr_mem = list;
                1
            }
        }
    }
}

/// `parse_list` of glibc's files parser: the vector of pointers goes into `v`; None when it does not fit.
fn parse_list(c: &mut Cur, mut v: Vec8) -> Option<*mut *mut c_char> {
    loop {
        if !v.room() {
            return None;
        }
        if c.at_end() {
            break;
        }
        c.skip_space();
        let elt = c.i;
        loop {
            if c.at_end() || c.line[c.i] == b',' {
                if c.i > elt {
                    let p = c.ptr(elt);
                    v.push(p);
                }
                if !c.at_end() {
                    c.line[c.i] = 0;
                    c.i += 1;
                }
                break;
            }
            c.i += 1;
        }
    }
    Some(v.finish().0)
}

impl Entry for Spwd {
    const PATH: &'static CStr = c"/etc/shadow";
    fn parse(line: &mut [u8], _area: &mut [u8], r: &mut Spwd) -> i32 {
        let mut c = Cur { line, i: 0 };
        c.chop_newline();
        r.sp_namp = c.string_field();
        if c.at_end() && c.first_is_nis() {
            r.sp_pwdp = null_mut();
            r.sp_lstchg = 0;
            r.sp_min = 0;
            r.sp_max = 0;
            r.sp_warn = -1;
            r.sp_inact = -1;
            r.sp_expire = -1;
            r.sp_flag = !0;
            return 1;
        }
        r.sp_pwdp = c.string_field();
        let mut v = 0u32;
        // each field is converted like `(long) (int) value`, defaulting to -1
        macro_rules! sfield {
            ($dst:expr) => {{
                if !c.int_field_maybe_null(&mut v, u32::MAX) {
                    return 0;
                }
                $dst = i64::from(v as i32);
            }};
        }
        sfield!(r.sp_lstchg);
        sfield!(r.sp_min);
        sfield!(r.sp_max);
        c.skip_space();
        if c.at_end() {
            r.sp_warn = -1;
            r.sp_inact = -1;
            r.sp_expire = -1;
            r.sp_flag = !0;
        } else {
            sfield!(r.sp_warn);
            sfield!(r.sp_inact);
            sfield!(r.sp_expire);
            if !c.at_end() {
                // INT_FIELD_MAYBE_NULL with no terminator characters
                let (val, e) = c.strtou32();
                r.sp_flag = if e == c.i { !0 } else { u64::from(val) };
                if c.line.get(e).copied().unwrap_or(0) != 0 {
                    return 0;
                }
            } else {
                r.sp_flag = !0;
            }
        }
        1
    }
}

// ------------------------------------------------------------------------------ for the compat source

/// The files the `compat` source reads (rusty-libc-net nsscompat.rs).
pub const PASSWD_FILE: &[u8] = Passwd::PATH.to_bytes_with_nul();
pub const GROUP_FILE: &[u8] = Group::PATH.to_bytes_with_nul();
pub const SHADOW_FILE: &[u8] = Spwd::PATH.to_bytes_with_nul();

/// One of /etc/passwd, /etc/group, /etc/shadow read line by line through the files parsers (which accept the `+name`, `-name`,
/// `+@netgroup` and `+` lines of the compat format, like glibc's), for the `compat` source.
pub struct CompatFile(FdStream);

impl CompatFile {
    /// Open `path` (one of the constants above); Err(errno).
    ///
    /// # Safety
    /// `path` is NUL-terminated.
    pub unsafe fn open(path: &[u8]) -> Result<CompatFile, i32> {
        let path = CStr::from_bytes_until_nul(path).map_err(|_| EINVAL)?;
        FdStream::open(path).map(CompatFile)
    }
    pub fn rewind(&mut self) {
        self.0.rewind();
    }
    pub fn close(mut self) {
        self.0.close();
    }
    /// Where the next line starts (for [`CompatFile::seek`]).
    pub fn tell(&mut self) -> i64 {
        self.0.tell()
    }
    pub fn seek(&mut self, off: i64) {
        self.0.seek(off);
    }
    /// The next entry into `res` and `buf`: SUCCESS (1), NOTFOUND (0) at the end, TRYAGAIN (-2) with errno ERANGE when
    /// `buf` is too small (the same line comes again), UNAVAIL (-1) on a read error. Blank, comment and invalid lines are skipped.
    pub fn next_entry<E: CompatEntry>(&mut self, res: &mut E, buf: &mut [u8]) -> i32 {
        internal_getent::<E, _>(&mut self.0, res, buf)
    }
    /// As [`CompatFile::next_entry`] for C pointers.
    ///
    /// # Safety
    /// `res` and `buf` are writable (`len` bytes).
    pub unsafe fn next_passwd(&mut self, res: *mut Passwd, buf: *mut u8, len: usize) -> i32 {
        // SAFETY: forwarded contract (no result pointer).
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
    /// As [`CompatFile::next_passwd`] for /etc/group.
    ///
    /// # Safety
    /// As `next_passwd`.
    pub unsafe fn next_group(&mut self, res: *mut Group, buf: *mut u8, len: usize) -> i32 {
        // SAFETY: forwarded contract (no result pointer).
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
    /// As [`CompatFile::next_passwd`] for /etc/shadow.
    ///
    /// # Safety
    /// As `next_passwd`.
    pub unsafe fn next_spwd(&mut self, res: *mut Spwd, buf: *mut u8, len: usize) -> i32 {
        // SAFETY: forwarded contract (no result pointer).
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
}

/// The entry types [`CompatFile::next_entry`] reads.
#[allow(private_bounds)]
pub trait CompatEntry: Entry {}
impl CompatEntry for Passwd {}
impl CompatEntry for Group {}
impl CompatEntry for Spwd {}

/// The `files` source's `initgroups_dyn` (glibc's `_nss_files_initgroups_dyn`), for a `group_compat: files` line.
///
/// # Safety
/// `user` is a C string; `groups` points to a malloc'd array of `*size` entries.
pub unsafe fn files_initgroups_dyn(user: *const c_char, group: Gid, start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64) {
    // SAFETY: forwarded contract.
    let user = unsafe { ffi::cstr_bytes(user) };
    // SAFETY: forwarded contract.
    let mut g = unsafe { GidArray::from_raw(*groups, *size) };
    files_groups(user, group, &mut g, limit, start);
    (*groups, *size) = g.into_raw();
}

// ------------------------------------------------------------------------------ files backend

const ST_TRYAGAIN: i32 = -2;
const ST_UNAVAIL: i32 = -1;
const ST_NOTFOUND: i32 = 0;
const ST_SUCCESS: i32 = 1;

/// `internal_getent`: the next entry of the stream, in `buffer`.
fn internal_getent<E: Entry, S: Src>(s: &mut S, result: &mut E, buffer: &mut [u8]) -> i32 {
    let saved = errno::get();
    if buffer.len() < 2 {
        errno::set(ERANGE);
        return ST_TRYAGAIN;
    }
    loop {
        let mut off = 0i64;
        let mut ret = readline(s, buffer, &mut off);
        if ret == ENOENT {
            errno::set(saved);
            return ST_NOTFOUND;
        } else if ret == 0 {
            let (line, area) = split_line(buffer);
            let pr = E::parse(line, area, result);
            ret = parse_line_result(s, off, pr);
            if ret == 0 {
                errno::set(saved);
                return ST_SUCCESS;
            } else if ret == EINVAL {
                continue;
            }
        }
        errno::set(ret);
        return if ret == ERANGE { ST_TRYAGAIN } else { ST_UNAVAIL };
    }
}

/// A by-key lookup: open the file afresh, read entries until `matches`.
fn db_lookup<E: Entry>(result: &mut E, buffer: &mut [u8], matches: impl Fn(&E) -> bool) -> i32 {
    let mut st = match FdStream::open(E::PATH) {
        Ok(s) => s,
        Err(e) => {
            errno::set(e);
            return if e == EAGAIN { ST_TRYAGAIN } else { ST_UNAVAIL };
        }
    };
    let status = loop {
        let s = internal_getent::<E, _>(&mut st, result, buffer);
        if s != ST_SUCCESS {
            break s;
        }
        if matches(result) {
            break s;
        }
    };
    st.close();
    status
}

/// Run a by-key lookup over the sources `nsswitch.conf` names for database `db`, like glibc's `__nss_lookup`/`__nss_next` loop:
/// `files` (and `compat`) is the built-in reader (`files`), every other name a plug-in module (`libnss_NAME.so.2`) whose
/// `_nss_NAME_<func>` is called through `call` (it gets the function address and a place for the module's errno). The status
/// of each source decides, through its [STATUS=ACTION] list, whether the next one is asked (`merge` after SUCCESS is treated
/// as `return`). A source whose module cannot be loaded, or lacks the function, is skipped as far as its UNAVAIL action allows
/// and leaves the status of the one before it (glibc's `__nss_lookup`). No line for the database means `files`.
fn nss_dispatch(db: &[u8], func: &[u8], files: &impl Fn() -> i32, call: &impl Fn(usize, *mut c_int) -> i32) -> i32 {
    nssent::dispatch_compat(db, func, files, call, None, compat_fn(func))
}

/// The address of `_nss_compat_<func>`: rusty-libc-net's nsscompat.rs answers the `compat` source of passwd, group, shadow and
/// initgroups with `+`/`-` entries and netgroups, like glibc's libnss_compat. 0 for a function it does not have (the source then
/// reads the files like `files`), and always 0 in the host tests, where that crate is not linked.
pub(crate) fn compat_fn(func: &[u8]) -> usize {
    #[cfg(feature = "export")]
    unsafe extern "C" {
        fn __rl_nss_compat_function(name: *const u8, len: usize) -> usize;
    }
    #[cfg(feature = "export")]
    // SAFETY: a plain lookup in a table.
    return unsafe { __rl_nss_compat_function(func.as_ptr(), func.len()) };
    #[cfg(not(feature = "export"))]
    {
        let _ = func;
        0
    }
}

/// Call a module's `_nss_*_get*nam_r(name, result, buffer, buflen, errnop)` at address `f`.
fn call_by_name<E>(f: usize, name: *const c_char, res: *mut E, buf: *mut c_char, len: usize, en: *mut c_int) -> c_int {
    // SAFETY: `f` is the address nssmod (or the compat table) resolved for a function of this name, whose C type is this one.
    let f: unsafe extern "C" fn(*const c_char, *mut E, *mut c_char, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
    // SAFETY: the arguments are the caller's (valid by the lookup's contract) and the dispatcher's errno place.
    unsafe { f(name, res, buf, len, en) }
}

/// Call a module's `_nss_*_get*id_r(id, result, buffer, buflen, errnop)` at address `f`.
fn call_by_id<E>(f: usize, id: u32, res: *mut E, buf: *mut c_char, len: usize, en: *mut c_int) -> c_int {
    // SAFETY: as in `call_by_name`.
    let f: unsafe extern "C" fn(u32, *mut E, *mut c_char, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
    // SAFETY: as in `call_by_name`.
    unsafe { f(id, res, buf, len, en) }
}

/// Write a pointer-sized word at `off` of `buf`.
fn put_word(buf: &mut [u8], off: usize, v: usize) {
    buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

/// The pointer-sized word at `off` of `buf`.
fn get_word(buf: &[u8], off: usize) -> usize {
    usize::from_ne_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]))
}

/// The strings of a group, read where they are.
pub(crate) struct GroupView<'a> {
    name: &'a [u8],
    passwd: &'a [u8],
    gid: Gid,
    mem: CList<'a>,
}

impl GroupView<'_> {
    /// # Safety
    /// The strings and member vector of `g` are NULL or valid C data (as a lookup leaves them) for `'a`, and not in
    /// memory that the caller writes while the view is used.
    unsafe fn of<'a>(g: &Group) -> GroupView<'a> {
        // SAFETY: forwarded contract.
        let s = |p: *mut c_char| unsafe { cbytes(p) };
        // SAFETY: forwarded contract.
        GroupView { name: s(g.gr_name), passwd: s(g.gr_passwd), gid: g.gr_gid, mem: unsafe { CList::new(g.gr_mem) } }
    }
}

/// glibc's `__copy_grp` (nss/grp-merge.c): copy `src` into `destbuf` (name, password, members, the pointer vector and, after
/// it, the member count); ERANGE when it does not fit. `Ok` gives the end of what was written.
fn copy_grp(src: &GroupView, dest: &mut Group, destbuf: &mut [u8]) -> Result<usize, c_int> {
    let buflen = destbuf.len();
    dest.gr_gid = src.gid;
    let mut c = 0usize;
    let put = |buf: &mut [u8], s: &[u8], c: &mut usize| -> Option<*mut c_char> {
        let len = s.len() + 1;
        if *c + len > buflen {
            return None;
        }
        buf[*c..*c + s.len()].copy_from_slice(s);
        buf[*c + s.len()] = 0;
        let p = buf.as_mut_ptr().wrapping_add(*c).cast();
        *c += len;
        Some(p)
    };
    dest.gr_name = put(destbuf, src.name, &mut c).ok_or(ERANGE)?;
    dest.gr_passwd = put(destbuf, src.passwd, &mut c).ok_or(ERANGE)?;
    let memcount = src.mem.ptrs().count();
    let mut members: CVec<usize> = CVec::new();
    if !members.resize(memcount + 1, 0) {
        return Err(ENOMEM);
    }
    for (i, m) in src.mem.iter().enumerate() {
        members.as_mut_slice()[i] = put(destbuf, m, &mut c).ok_or(ERANGE)? as usize;
    }
    let mis = (destbuf.as_ptr() as usize + c) & 7;
    if mis != 0 {
        c += 8 - mis;
    }
    dest.gr_mem = destbuf.as_mut_ptr().wrapping_add(c).cast();
    let len = 8 * (memcount + 1);
    if c + len > buflen {
        return Err(ERANGE);
    }
    for (k, &w) in members.as_slice().iter().enumerate() {
        put_word(destbuf, c + 8 * k, w);
    }
    c += len;
    drop(members);
    if c + 8 > buflen {
        return Err(ERANGE);
    }
    put_word(destbuf, c, memcount);
    c += 8;
    Ok(c)
}

/// glibc's `__merge_grp`: add the members of `merge` (the group just found, strings in the caller's buffer or a module's
/// memory) to the saved group (in `savedbuf`, from `copy_grp`, ending at `savedend`) when name and gid agree, and leave
/// the result in `merge`/`mergebuf`; otherwise the saved group simply replaces it.
fn merge_grp(saved: &mut Group, savedbuf: &mut CVec<u8>, savedend: usize, merge: &mut Group, mergebuf: &mut [u8]) -> c_int {
    let to_merge = |saved: &Group, merge: &mut Group, mergebuf: &mut [u8]| -> c_int {
        // SAFETY: the saved group's strings are in the saved buffer, which is not written while the view is used.
        let sv = unsafe { GroupView::of(saved) };
        match copy_grp(&sv, merge, mergebuf) {
            Ok(_) => 0,
            Err(e) => e,
        }
    };
    // SAFETY: as above, for the comparison.
    let sv = unsafe { GroupView::of(saved) };
    // SAFETY: the merged group's strings are the caller's, as a lookup left them; not in the saved buffer.
    let mv = unsafe { GroupView::of(merge) };
    if mv.gid != sv.gid || mv.name != sv.name {
        return to_merge(saved, merge, mergebuf);
    }
    let base = savedbuf.as_mut_ptr() as usize;
    let sb = savedbuf.as_mut_slice();
    let buflen = sb.len();
    let savedmemcount = get_word(sb, savedend - 8);
    let memcount = mv.mem.ptrs().count();
    let membersize = savedmemcount + memcount + 1;
    let mut members: CVec<usize> = CVec::new();
    if !members.resize(membersize, 0) {
        return ENOMEM;
    }
    let gm_off = (saved.gr_mem as usize).wrapping_sub(base);
    for i in 0..savedmemcount {
        members.as_mut_slice()[i] = get_word(sb, gm_off + 8 * i);
    }
    let mut c = savedend - 8 - 8 * (savedmemcount + 1);
    for (i, m) in mv.mem.iter().enumerate() {
        let len = m.len() + 1;
        if c + len > buflen {
            return ERANGE;
        }
        sb[c..c + m.len()].copy_from_slice(m);
        sb[c + m.len()] = 0;
        members.as_mut_slice()[savedmemcount + i] = sb.as_mut_ptr().wrapping_add(c) as usize;
        c += len;
    }
    let mis = (base + c) & 7;
    if mis != 0 {
        c += 8 - mis;
    }
    saved.gr_mem = sb.as_mut_ptr().wrapping_add(c).cast();
    let len = 8 * membersize;
    if c + len > buflen {
        return ERANGE;
    }
    for (k, &w) in members.as_slice().iter().enumerate() {
        put_word(sb, c + 8 * k, w);
    }
    to_merge(saved, merge, mergebuf)
}

/// The merging of two sources' answers for a group (what `[SUCCESS=merge]` asks for), on the lookup's result through
/// the shared cell (the dispatcher calls these hooks between module calls, never during one).
struct GrMerge<'c, 'b, 'a> {
    out: &'c RefCell<&'b mut Out<'a, Group>>,
    saved_buf: CVec<u8>,
    saved: Group,
    end: usize,
}

impl nssent::MergeOps for GrMerge<'_, '_, '_> {
    fn save(&mut self) -> i32 {
        let mut o = self.out.borrow_mut();
        let o = &mut **o;
        if self.saved_buf.len() == 0 && !self.saved_buf.resize(o.buf.len(), 0) {
            return ENOMEM;
        }
        // SAFETY: filled by the source just asked; its strings are in the caller's buffer (or the module's memory), not
        // in our saved buffer.
        let src = unsafe { GroupView::of(o.res) };
        match copy_grp(&src, &mut self.saved, self.saved_buf.as_mut_slice()) {
            Ok(end) => {
                self.end = end;
                0
            }
            Err(e) => e,
        }
    }
    fn merge(&mut self) -> i32 {
        let mut o = self.out.borrow_mut();
        let o = &mut **o;
        merge_grp(&mut self.saved, &mut self.saved_buf, self.end, o.res, o.buf)
    }
    fn restore(&mut self) -> i32 {
        let mut o = self.out.borrow_mut();
        let o = &mut **o;
        // SAFETY: the saved group's strings are in our saved buffer, which is not written here.
        let src = unsafe { GroupView::of(&self.saved) };
        match copy_grp(&src, o.res, o.buf) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }
}

/// The wrapper every `get*_r` lookup goes through (glibc's `getXXbyYY_r`): maps the backend status to the return value
/// and `errno`.
fn finish_r(status: i32) -> c_int {
    let res = if status == ST_SUCCESS || status == ST_NOTFOUND {
        0
    } else if errno::get() == ERANGE && status != ST_TRYAGAIN {
        EINVAL
    } else {
        return errno::get();
    };
    errno::set(res);
    res
}

/// Where a `_r` function puts its answer: the result structure, the buffer for its strings, and the caller's result
/// pointer (glibc's `*result`), which gets the structure's address on success and NULL otherwise.
pub(crate) struct Out<'a, E> {
    pub(crate) res: &'a mut E,
    pub(crate) buf: &'a mut [u8],
    result: *mut *mut E,
    /// set by `finish`: the entry was found
    found: bool,
}

impl<'a, E> Out<'a, E> {
    /// The caller's pointers.
    ///
    /// # Safety
    /// `res` points to a writable `E` and `buf` to `len` writable bytes, disjoint, used by nothing else for `'a`; `result`
    /// is NULL or a writable `E *` outside both.
    pub(crate) unsafe fn from_c(res: *mut E, buf: *mut c_char, len: usize, result: *mut *mut E) -> Out<'a, E> {
        // SAFETY: forwarded contract.
        let r = unsafe { &mut *res };
        // SAFETY: forwarded contract.
        let b = unsafe { ffi::bytes_mut(buf.cast(), len) };
        Out { res: r, buf: b, result, found: false }
    }
    /// A result structure and buffer of our own (no result pointer).
    pub(crate) fn new(res: &'a mut E, buf: &'a mut [u8]) -> Out<'a, E> {
        Out { res, buf, result: null_mut(), found: false }
    }
    /// The C pointers a module function gets.
    fn ptrs(&mut self) -> (*mut E, *mut c_char, usize) {
        (&raw mut *self.res, self.buf.as_mut_ptr().cast(), self.buf.len())
    }
    /// Store the answer in the result pointer (the structure on success, else NULL).
    pub(crate) fn finish(&mut self, ok: bool) {
        self.found = ok;
        if !self.result.is_null() {
            let r = if ok { &raw mut *self.res } else { null_mut() };
            // SAFETY: a non-NULL result pointer is writable (`from_c`'s contract).
            unsafe { *self.result = r };
        }
    }
}

/// The name a lookup asks for: the C pointer (for modules) and its bytes (None for NULL: then no entry matches).
#[derive(Clone, Copy)]
struct Key<'a> {
    p: *const c_char,
    b: Option<&'a [u8]>,
}

impl<'a> Key<'a> {
    /// # Safety
    /// `name` is NULL or a C string valid for `'a`.
    unsafe fn new(name: *const c_char) -> Key<'a> {
        // SAFETY: forwarded contract.
        Key { p: name, b: unsafe { ffi::cstr(name) }.map(CStr::to_bytes) }
    }
    fn nis(&self) -> bool {
        self.b.is_some_and(|b| matches!(b.first(), Some(b'+' | b'-')))
    }
}

/// A by-key lookup through the sources of database `db`: `matches` picks the entry in the files source, `call` asks a
/// module (`f`, the result, the buffer, its length, the errno place).
fn lookup<E: Entry>(db: &[u8], func: &[u8], out: &mut Out<E>, matches: impl Fn(&E) -> bool, call: impl Fn(usize, *mut E, *mut c_char, usize, *mut c_int) -> c_int) -> c_int {
    let cell = RefCell::new(out);
    let files = || {
        let mut o = cell.borrow_mut();
        let o = &mut **o;
        db_lookup(o.res, o.buf, &matches)
    };
    let module = |f: usize, en: *mut c_int| {
        let (r, b, l) = cell.borrow_mut().ptrs();
        call(f, r, b, l, en)
    };
    let status = nss_dispatch(db, func, &files, &module);
    cell.into_inner().finish(status == ST_SUCCESS);
    finish_r(status)
}

/// `lookup` for the group database, with the merging hooks.
fn lookup_group(func: &[u8], out: &mut Out<Group>, matches: impl Fn(&Group) -> bool, call: impl Fn(usize, *mut Group, *mut c_char, usize, *mut c_int) -> c_int) -> c_int {
    let cell = RefCell::new(out);
    let files = || {
        let mut o = cell.borrow_mut();
        let o = &mut **o;
        db_lookup(o.res, o.buf, &matches)
    };
    let module = |f: usize, en: *mut c_int| {
        let (r, b, l) = cell.borrow_mut().ptrs();
        call(f, r, b, l, en)
    };
    let mut gm = GrMerge { out: &cell, saved_buf: CVec::new(), saved: Group::zero(), end: 0 };
    let status = nssent::dispatch_compat(b"group", func, &files, &module, Some(&mut gm), compat_fn(func));
    drop(gm);
    cell.into_inner().finish(status == ST_SUCCESS);
    finish_r(status)
}

/// The lookup functions' C arguments.
///
/// # Safety
/// `name` is NULL or a C string; `resbuf`, `buffer` (`buflen` bytes) and `result` are valid, writable and disjoint, for
/// `'a`.
unsafe fn r_args<'a, E>(name: *const c_char, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> (Key<'a>, Out<'a, E>) {
    // SAFETY: forwarded contract.
    let k = unsafe { Key::new(name) };
    // SAFETY: forwarded contract.
    (k, unsafe { Out::from_c(resbuf, buffer, buflen, result) })
}

/// The answer of the name service cache daemon as `getpwnam_r` returns it (glibc's `nscd_getpw_r`): the strings are
/// already in the buffer, `errno` is left alone when the entry is found and cleared when the daemon says there is none.
/// None: use the NSS sources.
fn nscd_passwd(out: &mut Out<Passwd>, answer: Res<PasswdLayout>) -> Option<c_int> {
    match answer {
        Res::Fallback => None,
        Res::Found(l) => {
            let base = out.buf.as_mut_ptr();
            let at = |off: usize| base.wrapping_add(off).cast::<c_char>();
            out.res.pw_name = at(l.name);
            out.res.pw_passwd = at(l.passwd);
            out.res.pw_uid = l.uid;
            out.res.pw_gid = l.gid;
            out.res.pw_gecos = at(l.gecos);
            out.res.pw_dir = at(l.dir);
            out.res.pw_shell = at(l.shell);
            out.finish(true);
            Some(0)
        }
        other => Some(nscd_miss(out, other)),
    }
}

/// The answers of the daemon that return no entry: not found (0, errno cleared), `ERANGE`, `ENOENT` (a record cut short).
fn nscd_miss<E, T>(out: &mut Out<E>, answer: Res<T>) -> c_int {
    out.finish(false);
    let code = match answer {
        Res::Erange => ERANGE,
        Res::Enoent => ENOENT,
        _ => 0,
    };
    errno::set(code);
    code
}

/// `getpwnam_r` on Rust values.
fn pwnam_r(k: Key, out: &mut Out<Passwd>) -> c_int {
    if let Some(name) = k.b {
        let answer = nscd::passwd_by_name(name, out.buf);
        if let Some(rc) = nscd_passwd(out, answer) {
            return rc;
        }
    }
    lookup(b"passwd", b"getpwnam_r", out, |r: &Passwd| !k.nis() && name_is(k.b, r.pw_name), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

/// `getpwuid_r` on Rust values.
fn pwuid_r(uid: Uid, out: &mut Out<Passwd>) -> c_int {
    let answer = nscd::passwd_by_uid(uid, out.buf);
    if let Some(rc) = nscd_passwd(out, answer) {
        return rc;
    }
    lookup(b"passwd", b"getpwuid_r", out, |r: &Passwd| r.pw_uid == uid && !is_nis(r.pw_name), |f, r, b, l, en| call_by_id(f, uid, r, b, l, en))
}

/// # Safety
/// `name` is a C string; `resbuf`, `buffer`, `result` valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam_r(name: *const c_char, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    pwnam_r(k, &mut out)
}

/// # Safety
/// As `getpwnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid_r(uid: Uid, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    pwuid_r(uid, &mut out)
}

/// A static result buffer that grows by `step` (doubling for the by-key lookups, adding for the
/// stream readers, like glibc's two families).
pub(crate) struct StaticBuf<E> {
    buf: CVec<u8>,
    res: E,
}

// SAFETY: `buf` is a heap block owned by this value and the pointers in `res` point into it (or into a module's memory);
// nothing in it is tied to a thread. The statics wrap it in a lock.
unsafe impl<E> Send for StaticBuf<E> {}

impl<E> StaticBuf<E> {
    pub(crate) const fn new(res: E) -> StaticBuf<E> {
        StaticBuf { buf: CVec::new(), res }
    }
}

const NSS_BUFLEN: usize = 1024;

/// The static buffers of the non-reentrant functions, each under its own lock (as glibc's `getXXbyYY.c` locks around its
/// static buffer); the returned pointer stays valid until the next call of the same function, as in glibc.
static PWNAM: Locked<StaticBuf<Passwd>> = Locked::new(StaticBuf::new(Passwd::zero()));
static PWUID: Locked<StaticBuf<Passwd>> = Locked::new(StaticBuf::new(Passwd::zero()));
static GRNAM: Locked<StaticBuf<Group>> = Locked::new(StaticBuf::new(Group::zero()));
static GRGID: Locked<StaticBuf<Group>> = Locked::new(StaticBuf::new(Group::zero()));
static SPNAM: Locked<StaticBuf<Spwd>> = Locked::new(StaticBuf::new(Spwd::zero()));
static PWENT: Locked<StaticBuf<Passwd>> = Locked::new(StaticBuf::new(Passwd::zero()));
static GRENT: Locked<StaticBuf<Group>> = Locked::new(StaticBuf::new(Group::zero()));
static SPENT: Locked<StaticBuf<Spwd>> = Locked::new(StaticBuf::new(Spwd::zero()));
static FGETPW: Locked<StaticBuf<Passwd>> = Locked::new(StaticBuf::new(Passwd::zero()));
static FGETGR: Locked<StaticBuf<Group>> = Locked::new(StaticBuf::new(Group::zero()));
static FGETSP: Locked<StaticBuf<Spwd>> = Locked::new(StaticBuf::new(Spwd::zero()));
static SGETSP: Locked<StaticBuf<Spwd>> = Locked::new(StaticBuf::new(Spwd::zero()));

/// The non-reentrant functions: the `_r` form on the static buffer, grown while it says ERANGE (`step_add`: by 1024,
/// like `fgetpwent`; else doubling, like the by-key lookups and `__nss_getent`); the structure's address when an entry
/// came back, else NULL. When memory runs out the buffer is freed (errno ENOMEM for the doubling kind, kept for the
/// adding kind, as glibc's two families do).
fn by_buf<E>(sb: &Locked<StaticBuf<E>>, step_add: bool, keep_errno: bool, mut call: impl FnMut(&mut Out<E>) -> c_int) -> *mut E {
    sb.with(|sb| {
        if sb.buf.len() == 0 && !sb.buf.resize(NSS_BUFLEN, 0) {
            return null_mut();
        }
        loop {
            let mut out = Out::new(&mut sb.res, sb.buf.as_mut_slice());
            let rc = call(&mut out);
            let found = out.found;
            if rc != ERANGE {
                return if found { &raw mut sb.res } else { null_mut() };
            }
            let size = sb.buf.len();
            let new = if step_add { size + NSS_BUFLEN } else { size * 2 };
            if !sb.buf.resize(new, 0) {
                let save = errno::get();
                sb.buf = CVec::new();
                errno::set(if keep_errno { save } else { ENOMEM });
                return null_mut();
            }
        }
    })
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    // SAFETY: a C string (caller's contract).
    let k = unsafe { Key::new(name) };
    by_buf(&PWNAM, false, false, |out| pwnam_r(k, out))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid(uid: Uid) -> *mut Passwd {
    by_buf(&PWUID, false, false, |out| pwuid_r(uid, out))
}

// ---- passwd enumeration (the engine is in ent.rs)

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpwent() {
    db_setent::<Passwd>(&PW_DB, &PW_NAMES)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    db_endent::<Passwd>(&PW_DB, &PW_NAMES)
}

/// # Safety
/// `resbuf`, `buffer`, `result` valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent_r(resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Passwd>(&PW_DB, &PW_NAMES, &mut out)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    by_buf(&PWENT, false, true, |out| db_getent::<Passwd>(&PW_DB, &PW_NAMES, out))
}

// ---- passwd from a stream

/// `__nss_fgetent_r` + the `fgetXXent_r` wrapper: 0 with the entry in `out`, or an errno.
fn fget_core<E: Entry>(src: &mut FileSrc, out: &mut Out<E>) -> c_int {
    let ret = loop {
        let mut off = 0i64;
        let mut ret = readline(src, out.buf, &mut off);
        if ret == 0 {
            let (line, area) = split_line(out.buf);
            let pr = E::parse(line, area, out.res);
            ret = parse_line_result(src, off, pr);
            if ret == EINVAL {
                continue;
            }
        }
        break ret;
    };
    out.finish(ret == 0);
    ret
}

/// The C side of `fgetXXent_r`.
///
/// # Safety
/// `stream` is an open stream; `resbuf`, `buffer` (`buflen` bytes) and `result` writable and disjoint.
unsafe fn fget_r<E: Entry>(stream: *mut File, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> c_int {
    // SAFETY: an open stream (caller's contract).
    let mut src = unsafe { FileSrc::new(stream) };
    // SAFETY: the caller's result and buffer (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    fget_core(&mut src, &mut out)
}

/// # Safety
/// `stream` is an open stdio stream; the rest valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent_r(stream: *mut File, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { fget_r::<Passwd>(stream, resbuf, buffer, buflen, result) }
}

/// `fgetpwent`-style: static buffer grown by 1024 on ERANGE, the stream repositioned each time.
///
/// # Safety
/// `stream` is an open stdio stream.
unsafe fn fget<E: Entry>(stream: *mut File, sb: &Locked<StaticBuf<E>>) -> *mut E {
    // SAFETY: an open stream (caller's contract).
    let mut src = unsafe { FileSrc::new(stream) };
    let pos = src.tell();
    if pos < 0 {
        return null_mut();
    }
    by_buf(sb, true, true, |out| {
        let rc = fget_core(&mut src, out);
        if rc == ERANGE {
            src.seek(pos);
        }
        rc
    })
}

/// # Safety
/// `stream` is an open stdio stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent(stream: *mut File) -> *mut Passwd {
    // SAFETY: forwarded contract.
    unsafe { fget::<Passwd>(stream, &FGETPW) }
}

// ---- writing entries

/// Characters that cannot appear in a field of the databases (glibc's NSS_INVALID_FIELD_CHARACTERS).
fn invalid_field_char(c: u8) -> bool {
    c == b':' || c == b'\n'
}

/// A field that may be written (NULL, None, is fine).
fn valid_field(s: Option<&[u8]>) -> bool {
    s.is_none_or(|s| !s.iter().any(|&c| invalid_field_char(c)))
}

/// A member list that may be written: no member with an invalid character or a comma.
fn valid_list_field(list: CList) -> bool {
    list.iter().all(|s| !s.iter().any(|&c| invalid_field_char(c) || c == b','))
}

/// Small append-only heap buffer for building a line before writing it with one `fwrite`.
struct Line {
    buf: CVec<u8>,
    ok: bool,
}

impl Line {
    fn new() -> Line {
        Line { buf: CVec::new(), ok: true }
    }
    fn put(&mut self, b: &[u8]) {
        let need = self.buf.len() + b.len();
        if need > self.buf.capacity() && !self.buf.reserve_total(need.max(self.buf.capacity() * 2).max(128)) {
            self.ok = false;
            return;
        }
        self.buf.extend(b);
    }
    fn num(&mut self, v: i128) {
        let mut tmp = [0u8; 44];
        let mut i = tmp.len();
        let neg = v < 0;
        let mut x = v.unsigned_abs();
        loop {
            i -= 1;
            tmp[i] = b'0' + (x % 10) as u8;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        if neg {
            i -= 1;
            tmp[i] = b'-';
        }
        self.put(&tmp[i..]);
    }
    /// The bytes built so far.
    fn bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
    /// Write it to the stream; false on failure.
    fn write_to(&self, f: &mut FileSrc) -> bool {
        self.ok && f.write(self.bytes())
    }
}

/// The text of `field` with every invalid character replaced by a space (`__nss_rewrite_field`).
fn put_rewritten(line: &mut Line, s: &[u8]) {
    for &c in s {
        line.put(&[if invalid_field_char(c) { b' ' } else { c }]);
    }
}

/// The C string at `p` as bytes, None for NULL.
///
/// # Safety
/// `p` is NULL or a C string valid for `'a`.
unsafe fn opt<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: forwarded contract.
    unsafe { ffi::cstr(p) }.map(CStr::to_bytes)
}

/// The strings of a passwd entry (None for NULL).
struct PwFields<'a> {
    name: Option<&'a [u8]>,
    passwd: Option<&'a [u8]>,
    gecos: Option<&'a [u8]>,
    dir: Option<&'a [u8]>,
    shell: Option<&'a [u8]>,
}

impl PwFields<'_> {
    /// # Safety
    /// The string fields of `p` are NULL or C strings valid for `'a`.
    unsafe fn of<'a>(p: &Passwd) -> PwFields<'a> {
        // SAFETY: forwarded contract.
        let f = |q: *mut c_char| unsafe { opt(q) };
        PwFields { name: f(p.pw_name), passwd: f(p.pw_passwd), gecos: f(p.pw_gecos), dir: f(p.pw_dir), shell: f(p.pw_shell) }
    }
}

/// `putpwent`'s line for `p` (None when a field cannot be written: EINVAL).
fn passwd_line(p: &Passwd, f: &PwFields) -> Option<Line> {
    if f.name.is_none() || !valid_field(f.name) || !valid_field(f.passwd) || !valid_field(f.dir) || !valid_field(f.shell) {
        return None;
    }
    let mut l = Line::new();
    l.put(f.name.unwrap_or(b""));
    l.put(b":");
    l.put(f.passwd.unwrap_or(b""));
    if is_nis(p.pw_name) {
        l.put(b":::");
    } else {
        l.put(b":");
        l.num(p.pw_uid as i128);
        l.put(b":");
        l.num(p.pw_gid as i128);
        l.put(b":");
    }
    put_rewritten(&mut l, f.gecos.unwrap_or(b""));
    l.put(b":");
    l.put(f.dir.unwrap_or(b""));
    l.put(b":");
    l.put(f.shell.unwrap_or(b""));
    l.put(b"\n");
    Some(l)
}

/// The arguments of a `putXXent`: the entry (None for NULL) and the stream (None for NULL).
///
/// # Safety
/// `p` is NULL or a valid entry for `'a`; `stream` is NULL or an open stream.
unsafe fn put_args<'a, E>(p: *const E, stream: *mut File) -> (Option<&'a E>, Option<FileSrc>) {
    // SAFETY: forwarded contract.
    let e = unsafe { p.as_ref() };
    // SAFETY: forwarded contract.
    (e, if stream.is_null() { None } else { Some(unsafe { FileSrc::new(stream) }) })
}

/// # Safety
/// `p` is a valid entry, `stream` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putpwent(p: *const Passwd, stream: *mut File) -> c_int {
    // SAFETY: the caller's entry and stream (caller's contract).
    let (Some(p), Some(mut f)) = (unsafe { put_args(p, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    // SAFETY: the entry's strings are NULL or C strings (caller's contract).
    let fields = unsafe { PwFields::of(p) };
    let Some(l) = passwd_line(p, &fields) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

/// `getpwuid_r` into Rust references: `Ok(true)` with the entry in `res` (strings in `buf`, or a module's memory),
/// `Ok(false)` when there is none, `Err(errno)`.
pub(crate) fn pwuid_into(uid: Uid, res: &mut Passwd, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = pwuid_r(uid, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

/// `getpwnam_r` into Rust references; see [`pwuid_into`].
pub(crate) fn pwnam_into(name: &CStr, res: &mut Passwd, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = pwnam_r(Key { p: name.as_ptr(), b: Some(name.to_bytes()) }, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

/// `getgrnam_r` into Rust references; see [`pwuid_into`].
fn grnam_into(name: &CStr, res: &mut Group, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = grnam_r(Key { p: name.as_ptr(), b: Some(name.to_bytes()) }, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

/// `getgrgid_r` into Rust references; see [`pwuid_into`].
fn grgid_into(gid: Gid, res: &mut Group, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = grgid_r(gid, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

/// `getpw`: rebuild the password-file line for `uid` in `buf` (dangerous: no length limit).
///
/// # Safety
/// `buf` is writable for the whole line.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpw(uid: Uid, buf: *mut c_char) -> c_int {
    if buf.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let mut tmp = [0u8; 1024];
    let mut res = Passwd::zero();
    if pwuid_into(uid, &mut res, &mut tmp) != Ok(true) {
        return -1;
    }
    // SAFETY: the entry's strings are NULL or C strings (in `tmp`, not written any more, or a module's memory).
    let f = unsafe { PwFields::of(&res) };
    let mut l = Line::new();
    l.put(f.name.unwrap_or(b""));
    l.put(b":");
    l.put(f.passwd.unwrap_or(b""));
    l.put(b":");
    l.num(res.pw_uid as i128);
    l.put(b":");
    l.num(res.pw_gid as i128);
    l.put(b":");
    l.put(f.gecos.unwrap_or(b""));
    l.put(b":");
    l.put(f.dir.unwrap_or(b""));
    l.put(b":");
    l.put(f.shell.unwrap_or(b""));
    if !l.ok {
        return -1;
    }
    let b = l.bytes();
    // SAFETY: `buf` has room for the whole line and its NUL (caller's contract).
    let out = unsafe { ffi::bytes_mut(buf.cast(), b.len() + 1) };
    out[..b.len()].copy_from_slice(b);
    out[b.len()] = 0;
    0
}

// ------------------------------------------------------------------------------ groups

/// The answer of the name service cache daemon as `getgrnam_r` returns it; see [`nscd_passwd`].
fn nscd_group(out: &mut Out<Group>, answer: Res<GroupLayout>) -> Option<c_int> {
    match answer {
        Res::Fallback => None,
        Res::Found(l) => {
            let base = out.buf.as_mut_ptr();
            let at = |off: usize| base.wrapping_add(off).cast::<c_char>();
            out.res.gr_name = at(l.name);
            out.res.gr_passwd = at(l.passwd);
            out.res.gr_gid = l.gid;
            out.res.gr_mem = at(l.members).cast::<*mut c_char>();
            out.finish(true);
            Some(0)
        }
        other => Some(nscd_miss(out, other)),
    }
}

/// `getgrnam_r` on Rust values.
fn grnam_r(k: Key, out: &mut Out<Group>) -> c_int {
    if let Some(name) = k.b {
        let answer = nscd::group_by_name(name, out.buf);
        if let Some(rc) = nscd_group(out, answer) {
            return rc;
        }
    }
    lookup_group(b"getgrnam_r", out, |r: &Group| !k.nis() && name_is(k.b, r.gr_name), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

/// `getgrgid_r` on Rust values.
fn grgid_r(gid: Gid, out: &mut Out<Group>) -> c_int {
    let answer = nscd::group_by_gid(gid, out.buf);
    if let Some(rc) = nscd_group(out, answer) {
        return rc;
    }
    lookup_group(b"getgrgid_r", out, |r: &Group| r.gr_gid == gid && !is_nis(r.gr_name), |f, r, b, l, en| call_by_id(f, gid, r, b, l, en))
}

/// # Safety
/// As `getpwnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam_r(name: *const c_char, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    grnam_r(k, &mut out)
}

/// # Safety
/// As `getpwnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid_r(gid: Gid, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    grgid_r(gid, &mut out)
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    // SAFETY: a C string (caller's contract).
    let k = unsafe { Key::new(name) };
    by_buf(&GRNAM, false, false, |out| grnam_r(k, out))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid(gid: Gid) -> *mut Group {
    by_buf(&GRGID, false, false, |out| grgid_r(gid, out))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setgrent() {
    db_setent::<Group>(&GR_DB, &GR_NAMES)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endgrent() {
    db_endent::<Group>(&GR_DB, &GR_NAMES)
}

/// # Safety
/// As `getpwent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent_r(resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Group>(&GR_DB, &GR_NAMES, &mut out)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    by_buf(&GRENT, false, true, |out| db_getent::<Group>(&GR_DB, &GR_NAMES, out))
}

/// # Safety
/// As `fgetpwent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent_r(stream: *mut File, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { fget_r::<Group>(stream, resbuf, buffer, buflen, result) }
}

/// # Safety
/// `stream` is an open stdio stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent(stream: *mut File) -> *mut Group {
    // SAFETY: forwarded contract.
    unsafe { fget::<Group>(stream, &FGETGR) }
}

/// `putgrent`'s line for `g` (None when a field cannot be written: EINVAL).
fn group_line(g: &Group, v: &GroupView) -> Option<Line> {
    // (an unset password counts as valid, like glibc's NULL check; its text is "")
    if g.gr_name.is_null() || !valid_field(Some(v.name)) || !valid_field(Some(v.passwd)) || !valid_list_field(v.mem) {
        return None;
    }
    let mut l = Line::new();
    l.put(v.name);
    l.put(b":");
    l.put(v.passwd);
    if is_nis(g.gr_name) {
        l.put(b"::");
    } else {
        l.put(b":");
        l.num(g.gr_gid as i128);
        l.put(b":");
    }
    for (i, m) in v.mem.iter().enumerate() {
        if i > 0 {
            l.put(b",");
        }
        l.put(m);
    }
    l.put(b"\n");
    Some(l)
}

/// # Safety
/// `gr` is a valid entry, `stream` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putgrent(gr: *const Group, stream: *mut File) -> c_int {
    // SAFETY: the caller's entry and stream (caller's contract).
    let (Some(g), Some(mut f)) = (unsafe { put_args(gr, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    // SAFETY: its strings and member vector are NULL or valid C data (caller's contract).
    let v = unsafe { GroupView::of(g) };
    let Some(l) = group_line(g, &v) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

/// `getline` on the stream: the next line (with its newline) at the start of `line` (grown as needed), NUL-terminated;
/// its length, 0 at the end of the file, or usize::MAX when memory ran out.
#[inline(always)]
fn getline_alloc(st: &mut FdStream, line: &mut CVec<u8>) -> usize {
    let mut n = 0usize;
    loop {
        if line.len() < n + 2 && !line.resize((line.len() * 2).max(128), 0) {
            return usize::MAX;
        }
        let b = line.as_mut_slice();
        let got = st.gets_n(&mut b[n..]);
        if got == 0 {
            return n;
        }
        // the length up to the first NUL, as strlen gives (a NUL read from the file ends the line early)
        n += clen(&b[n..n + got]);
        if n > 0 && b[n - 1] == b'\n' {
            return n;
        }
    }
}

/// A malloc'd array of group ids with its size in entries (glibc's `groups`/`size` pair of initgroups_dyn, which modules
/// may realloc): `p` holds `size` entries, the first `start` of them set.
pub(crate) struct GidArray {
    p: *mut Gid,
    size: i64,
}

impl GidArray {
    /// # Safety
    /// `p` is a heap block of at least `size` entries (or NULL with size 0), owned by the new value until `into_raw`.
    pub(crate) unsafe fn from_raw(p: *mut Gid, size: i64) -> GidArray {
        GidArray { p, size }
    }
    fn alloc(size: i64) -> Option<GidArray> {
        let p = cmem::malloc(size as usize * 4).cast::<Gid>();
        if p.is_null() { None } else { Some(GidArray { p, size }) }
    }
    pub(crate) fn into_raw(self) -> (*mut Gid, i64) {
        let r = (self.p, self.size);
        core::mem::forget(self);
        r
    }
    fn set(&mut self, i: i64, v: Gid) {
        assert!(i >= 0 && i < self.size);
        // SAFETY: an entry inside the block (checked above).
        unsafe { *self.p.wrapping_add(i as usize) = v };
    }
    /// Entry `i`, which was written before.
    fn get(&self, i: i64) -> Gid {
        assert!(i >= 0 && i < self.size);
        // SAFETY: an entry inside the block (checked above), written before (callers only read entries below `start`).
        unsafe { *self.p.wrapping_add(i as usize) }
    }
    /// Grow to `newsize` entries; false (unchanged) when memory ran out.
    fn grow(&mut self, newsize: i64) -> bool {
        // SAFETY: our heap block; on success the old pointer is not used again.
        let ng = unsafe { cmem::realloc(self.p, newsize as usize * 4) };
        if ng.is_null() {
            return false;
        }
        self.p = ng;
        self.size = newsize;
        true
    }
}

impl GidList for GidArray {
    fn ensure(&mut self, entries: usize) -> bool {
        i64::try_from(entries).is_ok_and(|n| n <= self.size || self.grow(n))
    }
    fn gids(&mut self) -> &mut [u32] {
        // SAFETY: `p` is a heap block of `size` entries (the type's invariant), held exclusively through `&mut self`.
        unsafe { ffi::slice_mut(self.p, self.size as usize) }
    }
}

impl Drop for GidArray {
    fn drop(&mut self) {
        // SAFETY: our heap block, given up here.
        unsafe { cmem::free(self.p) }
    }
}

/// The files part of glibc's `internal_getgrouplist`: append to `groups`, from index `*start`, the gid of every group of the group
/// file whose member list names `user` (every line is read raw, no comment skipping, parsed, and its member list searched; the
/// array grows through realloc up to `limit` entries when `limit` is positive).
fn files_groups(user: &[u8], group: Gid, groups: &mut GidArray, limit: i64, start: &mut i64) {
    let Ok(mut st) = FdStream::open(Group::PATH) else { return };
    let mut tmp: CVec<u8> = CVec::new();
    let _ = tmp.resize(1024, 0);
    let mut line: CVec<u8> = CVec::new();
    'lines: loop {
        let pos = st.tell();
        let mut n = getline_alloc(&mut st, &mut line);
        if n == 0 || n == usize::MAX {
            break;
        }
        let mut grp = Group::zero();
        loop {
            let res = Group::parse(&mut line.as_mut_slice()[..n], tmp.as_mut_slice(), &mut grp);
            if res == -1 {
                // no room for the member vector: bigger buffer, reread the clobbered line
                if !tmp.resize((tmp.len() * 2).max(2048), 0) {
                    break 'lines;
                }
                st.seek(pos);
                n = getline_alloc(&mut st, &mut line);
                if n == 0 || n == usize::MAX {
                    break 'lines;
                }
                continue;
            }
            if res > 0 && grp.gr_gid != group {
                // SAFETY: the member vector is in `tmp` and its strings in `line`, both unchanged until the next line.
                let mem = unsafe { CList::new(grp.gr_mem) };
                if mem.iter().any(|m| m == user) {
                    if *start == groups.size {
                        if limit > 0 && groups.size == limit {
                            break 'lines;
                        }
                        let newsize = if limit <= 0 { 2 * groups.size } else { limit.min(2 * groups.size) };
                        if !groups.grow(newsize) {
                            break 'lines;
                        }
                    }
                    groups.set(*start, grp.gr_gid);
                    *start += 1;
                }
            }
            break;
        }
    }
    st.close();
}

/// Remove from `groups[prev_start..*start]` the entries equal to an earlier one (before `prev_start`): an added entry equal to an
/// earlier one is replaced by the last one.
fn dedupe_groups(groups: &mut GidArray, start: &mut i64, prev_start: i64) {
    let mut cnt = prev_start;
    while cnt < *start {
        let mut inner = 0;
        while inner < prev_start {
            if groups.get(inner) == groups.get(cnt) {
                break;
            }
            inner += 1;
        }
        if inner < prev_start {
            *start -= 1;
            let last = groups.get(*start);
            groups.set(cnt, last);
        } else {
            cnt += 1;
        }
    }
}

/// Collect the groups of `user` through the sources nsswitch.conf names for `group` (glibc's `internal_getgrouplist`): the
/// files reader and every module's `_nss_NAME_initgroups_dyn`. `groups` starts with `group` at index 0; returns the total
/// count (the array grows through realloc up to `limit` entries when `limit` is positive).
fn internal_getgrouplist(user: Key, group: Gid, groups: &mut GidArray, limit: i64) -> i64 {
    // the name service cache daemon first (glibc: no `limit` applies to its answer, and `group` comes last)
    if let Some(n) = user.b.and_then(|u| nscd::init_groups(u, group, groups)) {
        return n as i64;
    }
    groups.set(0, group);
    let mut start: i64 = 1;
    // (no source at all, an empty list or an unparsable configuration: just the primary group)
    let order = nssmod::order(b"group");
    let mut prev_start: i64 = 1;
    for src in &order.e[..order.n] {
        let mut status = ST_UNAVAIL;
        let compat = if src.is(b"compat") { compat_fn(b"initgroups_dyn") } else { 0 };
        if (src.is(b"files") || src.is(b"compat")) && compat == 0 {
            files_groups(user.b.unwrap_or(b""), group, groups, limit, &mut start);
            status = ST_SUCCESS;
        } else if !src.is(b"dns") {
            let f = if compat != 0 { compat } else { nssmod::function(src.name(), b"initgroups_dyn") };
            if f == 0 {
                if src.action(ST_UNAVAIL) != nssmod::ACT_CONTINUE {
                    break;
                }
                continue;
            }
            // SAFETY: `f` is a module's `_nss_*_initgroups_dyn`, whose C type is this one.
            let f: unsafe extern "C" fn(*const c_char, Gid, *mut i64, *mut i64, *mut *mut Gid, i64, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
            let mut e: c_int = 0;
            // SAFETY: the module may realloc the array and update its size, which is what `groups` holds.
            status = unsafe { f(user.p, group, &mut start, &mut groups.size, &mut groups.p, limit, &mut e) };
            if !(-2..=1).contains(&status) {
                status = ST_UNAVAIL;
            }
        }
        dedupe_groups(groups, &mut start, prev_start);
        prev_start = start;
        // (in glibc's __nss_next2 only `return` stops here: `merge` continues, and initgroups keeps every source's groups)
        if src.action(status) == nssmod::ACT_RETURN {
            break;
        }
    }
    start
}

/// The safe core of `getgrouplist`: the groups of `user` into `groups` (as many as fit); the total count in `ngroups`;
/// -1 when they did not all fit.
fn getgrouplist_into(user: Key, group: Gid, groups: &mut [Gid], ngroups: &mut c_int) -> c_int {
    let Some(mut g) = GidArray::alloc(i64::from((*ngroups).max(1))) else { return -1 };
    let total = internal_getgrouplist(user, group, &mut g, -1);
    let n = i64::from(*ngroups).min(total).max(0) as usize;
    for (i, o) in groups[..n].iter_mut().enumerate() {
        *o = g.get(i as i64);
    }
    drop(g);
    let retval = if total > i64::from(*ngroups) { -1 } else { total as c_int };
    *ngroups = total as c_int;
    retval
}

/// # Safety
/// `user` is a C string; `groups` has room for `*ngroups` entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrouplist(user: *const c_char, group: Gid, groups: *mut Gid, ngroups: *mut c_int) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let (k, g, ng) = unsafe { gl_args(user, groups, ngroups) };
    getgrouplist_into(k, group, g, ng)
}

/// `getgrouplist`'s C arguments.
///
/// # Safety
/// As `getgrouplist`.
unsafe fn gl_args<'a>(user: *const c_char, groups: *mut Gid, ngroups: *mut c_int) -> (Key<'a>, &'a mut [Gid], &'a mut c_int) {
    // SAFETY: forwarded contract.
    let k = unsafe { Key::new(user) };
    // SAFETY: forwarded contract.
    let ng = unsafe { &mut *ngroups };
    // SAFETY: forwarded contract (room for `*ngroups` entries).
    let g = unsafe { ffi::slice_mut(groups, (*ng).max(0) as usize) };
    (k, g, ng)
}

const SYS_SETGROUPS: usize = 116;
/// `sysconf(_SC_NGROUPS_MAX)` on Linux.
const NGROUPS_MAX: i64 = 65536;

/// The safe core of `initgroups`.
fn initgroups_key(user: Key, group: Gid) -> c_int {
    let limit = NGROUPS_MAX;
    let Some(mut groups) = GidArray::alloc(limit.min(64)) else { return -1 };
    let mut ngroups = internal_getgrouplist(user, group, &mut groups, limit);
    loop {
        // glibc's initgroups calls setgroups, which every thread applies
        // SAFETY: the kernel reads `ngroups` (<= the array's size) ids from our array.
        let r = unsafe { unistd::setxid_syscall(SYS_SETGROUPS, ngroups as usize, groups.p as usize, 0) };
        match syscall::check(r) {
            Ok(_) => return 0,
            Err(e) => {
                errno::set(e.0);
                if e.0 == EINVAL {
                    ngroups -= 1;
                    if ngroups > 0 {
                        continue;
                    }
                }
                return -1;
            }
        }
    }
}

/// # Safety
/// `user` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: Gid) -> c_int {
    // SAFETY: a C string (caller's contract).
    initgroups_key(unsafe { Key::new(user) }, group)
}

// ------------------------------------------------------------------------------ shadow

/// `getspnam_r` on Rust values.
fn spnam_r(k: Key, out: &mut Out<Spwd>) -> c_int {
    lookup(b"shadow", b"getspnam_r", out, |r: &Spwd| !k.nis() && name_is(k.b, r.sp_namp), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

/// # Safety
/// As `getpwnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam_r(name: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    spnam_r(k, &mut out)
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut Spwd {
    // SAFETY: a C string (caller's contract).
    let k = unsafe { Key::new(name) };
    by_buf(&SPNAM, false, false, |out| spnam_r(k, out))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setspent() {
    db_setent::<Spwd>(&SP_DB, &SP_NAMES)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endspent() {
    db_endent::<Spwd>(&SP_DB, &SP_NAMES)
}

/// # Safety
/// As `getpwent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent_r(resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Spwd>(&SP_DB, &SP_NAMES, &mut out)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent() -> *mut Spwd {
    by_buf(&SPENT, false, true, |out| db_getent::<Spwd>(&SP_DB, &SP_NAMES, out))
}

/// # Safety
/// As `fgetpwent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent_r(stream: *mut File, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { fget_r::<Spwd>(stream, resbuf, buffer, buflen, result) }
}

/// # Safety
/// `stream` is an open stdio stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent(stream: *mut File) -> *mut Spwd {
    // SAFETY: forwarded contract.
    unsafe { fget::<Spwd>(stream, &FGETSP) }
}

/// The string an `sgetXXent` parses: its address and, when it lies outside `buf`, its bytes (None: it is inside `buf`,
/// at that offset).
#[derive(Clone, Copy)]
pub(crate) struct SrcStr<'a> {
    addr: usize,
    bytes: &'a [u8],
}

impl<'a> SrcStr<'a> {
    /// # Safety
    /// `s` is a C string valid for `'a`.
    pub(crate) unsafe fn new(s: *const c_char) -> SrcStr<'a> {
        // SAFETY: forwarded contract.
        SrcStr { addr: s as usize, bytes: unsafe { ffi::cstr_nonnull(s) }.to_bytes() }
    }
}

/// `strncpy(buf, src, buf.len())` (the string may lie inside `buf`: then it is read through `buf`), then the check of
/// sgetspent_r/sgetsgent_r: true when it fit (the last byte is NUL).
pub(crate) fn strncpy_fits(src: SrcStr, buf: &mut [u8]) -> bool {
    let n = buf.len();
    let base = buf.as_ptr() as usize;
    buf[n - 1] = 0;
    if src.addr >= base && src.addr < base + n {
        // the string is inside the buffer: copy byte by byte like the C loop
        let o = src.addr - base;
        let mut i = 0;
        while i < n {
            let c = if o + i < n { buf[o + i] } else { 0 };
            buf[i] = c;
            if c == 0 {
                buf[i + 1..].fill(0);
                break;
            }
            i += 1;
        }
    } else {
        let k = src.bytes.len().min(n);
        buf[..k].copy_from_slice(&src.bytes[..k]);
        buf[k..].fill(0);
    }
    buf[n - 1] == 0
}

/// `sgetspent_r` on Rust values.
fn sgetsp_r(s: SrcStr, out: &mut Out<Spwd>) -> c_int {
    if out.buf.is_empty() || !strncpy_fits(s, out.buf) {
        return ERANGE;
    }
    let (line, area) = split_line(out.buf);
    let pr = Spwd::parse(line, area, out.res);
    out.finish(pr > 0);
    if pr > 0 { 0 } else { errno::get() }
}

/// `sgetspent_r`'s C arguments.
///
/// # Safety
/// `string` is a C string; the rest as for `getpwnam_r`.
unsafe fn sget_args<'a, E>(string: *const c_char, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> (SrcStr<'a>, Out<'a, E>) {
    // SAFETY: forwarded contract.
    let s = unsafe { SrcStr::new(string) };
    // SAFETY: forwarded contract.
    (s, unsafe { Out::from_c(resbuf, buffer, buflen, result) })
}

/// # Safety
/// `string` is a C string; the rest valid. Returns ERANGE when the line does not fit in `buffer`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent_r(string: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    // SAFETY: the caller's arguments (caller's contract).
    let (s, mut out) = unsafe { sget_args(string, resbuf, buffer, buflen, result) };
    sgetsp_r(s, &mut out)
}

/// # Safety
/// `string` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent(string: *const c_char) -> *mut Spwd {
    // SAFETY: a C string (caller's contract).
    let s = unsafe { SrcStr::new(string) };
    by_buf(&SGETSP, true, true, |out| sgetsp_r(s, out))
}

/// `putspent`'s line for `p` (None when a field cannot be written: EINVAL).
fn shadow_line(p: &Spwd, name: Option<&[u8]>, pwdp: Option<&[u8]>) -> Option<Line> {
    if name.is_none() || !valid_field(name) || !valid_field(pwdp) {
        return None;
    }
    let mut l = Line::new();
    l.put(name.unwrap_or(b""));
    l.put(b":");
    l.put(pwdp.unwrap_or(b""));
    l.put(b":");
    for v in [p.sp_lstchg, p.sp_min, p.sp_max, p.sp_warn, p.sp_inact, p.sp_expire] {
        if v != -1 {
            l.num(v as i128);
        }
        l.put(b":");
    }
    if p.sp_flag != !0 {
        // glibc prints the flag with "%ld"
        l.num(i128::from(p.sp_flag as i64));
    }
    l.put(b"\n");
    Some(l)
}

/// # Safety
/// `p` is a valid entry, `stream` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putspent(p: *const Spwd, stream: *mut File) -> c_int {
    // SAFETY: the caller's entry and stream (caller's contract; glibc does not check either for NULL).
    let (Some(p), Some(mut f)) = (unsafe { put_args(p, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    // SAFETY: its strings are NULL or C strings (caller's contract).
    let f2 = |q: *mut c_char| unsafe { opt(q) };
    let Some(l) = shadow_line(p, f2(p.sp_namp), f2(p.sp_pwdp)) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

/// The descriptor of `/etc/.pwd.lock` while `lckpwdf` holds it (-1 otherwise), under the lock glibc also takes around
/// lckpwdf/ulckpwdf.
static LOCK_FD: Locked<c_int> = Locked::new(-1);

extern "C" fn noop_handler(_sig: c_int) {}

#[unsafe(naked)]
unsafe extern "C" fn restore_rt() {
    core::arch::naked_asm!("mov eax, 15", "syscall");
}

const SYS_ALARM: usize = 37;
const SIGALRM: i32 = 14;
const F_SETLKW: usize = 7;

/// alarm(2).
fn alarm(secs: usize) {
    // SAFETY: plain values only.
    unsafe { syscall::syscall1(SYS_ALARM, secs) };
}

/// lckpwdf: lock `/etc/.pwd.lock` for writing, waiting at most 15 seconds.
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    LOCK_FD.with(|lock_fd| {
        if *lock_fd != -1 {
            return -1;
        }
        match cmem::open(c"/etc/.pwd.lock", O_WRONLY | O_CREAT | O_CLOEXEC, 0o600) {
            Ok(fd) => *lock_fd = fd,
            Err(e) => {
                errno::set(e.0);
                return -1;
            }
        }
        let close_fd = |lock_fd: &mut c_int, code: c_int| -> c_int {
            if code < 0 && *lock_fd >= 0 {
                let _ = unistd::close(*lock_fd);
                *lock_fd = -1;
            }
            code
        };
        // handle SIGALRM with a no-op so that the blocked fcntl is interrupted after the timeout
        let new_act = rusty_libc_core::signal::KSigaction { handler: noop_handler as *const () as usize, flags: rusty_libc_core::signal::SA_RESTORER, restorer: restore_rt as *const () as usize, mask: !0 };
        let saved_act = match rusty_libc_core::signal::sigaction(SIGALRM, Some(&new_act)) {
            Ok(a) => a,
            Err(e) => {
                errno::set(e.0);
                return close_fd(lock_fd, -1);
            }
        };
        let saved_set = match rusty_libc_core::signal::sigprocmask(rusty_libc_core::signal::SIG_UNBLOCK, Some(rusty_libc_core::signal::bit(SIGALRM))) {
            Ok(s) => s,
            Err(e) => {
                errno::set(e.0);
                let _ = rusty_libc_core::signal::sigaction(SIGALRM, Some(&saved_act));
                return close_fd(lock_fd, -1);
            }
        };
        alarm(15);
        // struct flock { short l_type; short l_whence; off_t l_start; off_t l_len; pid_t l_pid; }
        let fl: [u64; 4] = [1 /* F_WRLCK */, 0, 0, 0];
        // SAFETY: the kernel reads a `struct flock` (32 bytes) from `fl`.
        let r = unsafe { syscall::syscall3(syscall::SYS_FCNTL, *lock_fd as usize, F_SETLKW, fl.as_ptr() as usize) };
        let result = match syscall::check(r) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        };
        alarm(0);
        let _ = rusty_libc_core::signal::sigprocmask(rusty_libc_core::signal::SIG_SETMASK, Some(saved_set));
        let _ = rusty_libc_core::signal::sigaction(SIGALRM, Some(&saved_act));
        close_fd(lock_fd, result)
    })
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    LOCK_FD.with(|lock_fd| {
        if *lock_fd == -1 {
            return -1;
        }
        let r = unistd::close(*lock_fd);
        *lock_fd = -1;
        match r {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        }
    })
}

// ------------------------------------------------------------------------------ login name

const UT_NAMESIZE: usize = 32;
const UT_LINESIZE: usize = 32;
/// `sizeof(struct utmp)` on x86-64 Linux.
const UTMP_SIZE: usize = 384;
const NAME_MAX2: usize = 2 + 2 * 255;

/// Copy the C string `s` with its NUL into `name`; ERANGE (errno set) when it does not fit.
fn put_name(s: &[u8], name: &mut [u8]) -> c_int {
    if s.len() + 1 > name.len() {
        errno::set(ERANGE);
        return ERANGE;
    }
    name[..s.len()].copy_from_slice(s);
    name[s.len()] = 0;
    0
}

/// `/proc/self/loginuid` -> user name. 0 = found, -1 = not available (use the utmp route), else an
/// errno (ERANGE when `name` is too small).
fn getlogin_r_loginuid(name: &mut [u8]) -> c_int {
    let Ok(fd) = cmem::open(c"/proc/self/loginuid", O_RDONLY | O_CLOEXEC, 0) else { return -1 };
    let mut uidbuf = [0u8; 12];
    let n = loop {
        match unistd::read_nocancel(fd, &mut uidbuf) {
            Err(e) if e.0 == EINTR => continue,
            Err(_) => break -1isize,
            Ok(n) => break n as isize,
        }
    };
    let _ = unistd::close(fd);
    if n <= 0 || n as usize == uidbuf.len() {
        return -1;
    }
    let n = n as usize;
    uidbuf[n] = 0;
    let (uid, endp) = strtoul_plain(&uidbuf[..=n]);
    if endp == 0 || uidbuf[endp] != 0 {
        return -1;
    }
    // stored in a 32-bit uid_t; (uid_t) -1 means "no login uid"
    let uid = uid as Uid;
    if uid == Uid::MAX {
        return -1;
    }
    let mut tmp = [0u8; 1024];
    let mut heap: CVec<u8> = CVec::new();
    let mut pwd = Passwd::zero();
    let found = loop {
        let buf: &mut [u8] = if heap.len() == 0 { &mut tmp } else { heap.as_mut_slice() };
        let buflen = buf.len();
        match pwuid_into(uid, &mut pwd, buf) {
            Err(ERANGE) => {}
            r => break r,
        }
        if !heap.resize(buflen * 2, 0) {
            return ENOMEM;
        }
    };
    match found {
        // SAFETY: the entry's name is a C string in the buffer just filled (not written any more) or a module's memory.
        Ok(true) => put_name(unsafe { cbytes(pwd.pw_name) }, name),
        _ => -1,
    }
}

/// strtoul base 10 on a NUL-terminated slice: (value, end index; 0 when no digits).
fn strtoul_plain(s: &[u8]) -> (u64, usize) {
    let mut i = 0;
    while i < s.len() && isspace(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        neg = s[i] == b'-';
        i += 1;
    }
    let st = i;
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(n) => v = n,
            None => over = true,
        }
        i += 1;
    }
    if i == st {
        return (0, 0);
    }
    (if over { u64::MAX } else if neg { v.wrapping_neg() } else { v }, i)
}

/// `ttyname_r(0)` the way getlogin needs it: the path of the terminal on standard input
/// ("/dev/...") in `buf` with a NUL, or an errno.
fn ttyname0(buf: &mut [u8]) -> c_int {
    // isatty: the TCGETS2 ioctl (glibc's tcgetattr)
    let mut t = [0u8; 64];
    // SAFETY: the kernel writes a `struct termios2` (44 bytes) into `t`.
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, 0, unistd::TCGETS2, t.as_mut_ptr() as usize) };
    if let Err(e) = syscall::check(r) {
        return e.0;
    }
    let len = buf.len();
    // SAFETY: a NUL-terminated literal; the kernel writes at most `len` bytes into `buf`.
    let r = unsafe { syscall::syscall3(89 /* readlink */, c"/proc/self/fd/0".as_ptr() as usize, buf.as_mut_ptr() as usize, len) };
    match syscall::check(r) {
        Err(e) => e.0,
        Ok(n) if n >= len => ERANGE,
        Ok(n) => {
            buf[n] = 0;
            let s = &buf[..n];
            if s.first() != Some(&b'/') {
                return ENOENT;
            }
            // a removed terminal shows as "<path> (deleted)"
            if s.ends_with(b" (deleted)") {
                buf[n - 10] = 0;
            }
            0
        }
    }
}

/// utmp entry types that name a login session.
fn utmp_is_login(t: i16) -> bool {
    matches!(t, 5..=7) // INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS
}

/// Search the utmp file at `path` for the entry whose line is `line` (glibc's `getutline_r`:
/// only USER_PROCESS and LOGIN_PROCESS entries qualify) and copy its user name to `name`.
/// 0 = found, ENOENT = no such entry (or the file cannot be read: glibc returns the open error),
/// ERANGE = `name` too small.
pub(crate) fn utmp_user_for_line(path: &CStr, line: &[u8], name: &mut [u8]) -> c_int {
    let fd = match cmem::open(path, O_RDONLY | O_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => return e.0,
    };
    let mut rec = [0u8; UTMP_SIZE];
    let mut found = ENOENT;
    'recs: loop {
        let mut got = 0;
        while got < UTMP_SIZE {
            match unistd::read_nocancel(fd, &mut rec[got..]) {
                Ok(0) => break 'recs,
                Ok(n) => got += n,
                Err(e) if e.0 == EINTR => {}
                Err(_) => break 'recs,
            }
        }
        let ut_type = i16::from_le_bytes([rec[0], rec[1]]);
        if !utmp_is_login(ut_type) {
            continue;
        }
        // ut_line at offset 8, ut_user at offset 44 (after type, pid, line, id)
        let ut_line = &rec[8..8 + UT_LINESIZE];
        let want = &line[..line.len().min(UT_LINESIZE)];
        let mut a = [0u8; UT_LINESIZE];
        a[..want.len()].copy_from_slice(want);
        let mut eq = true;
        for i in 0..UT_LINESIZE {
            if ut_line[i] != a[i] {
                eq = false;
                break;
            }
            if a[i] == 0 {
                break;
            }
        }
        if !eq {
            continue;
        }
        let user = &rec[44..44 + UT_NAMESIZE];
        let ulen = user.iter().position(|&b| b == 0).unwrap_or(UT_NAMESIZE);
        found = put_name(&user[..ulen], name);
        break;
    }
    let _ = unistd::close(fd);
    found
}

fn getlogin_r_fd0(name: &mut [u8]) -> c_int {
    let mut tty = [0u8; NAME_MAX2 + 1];
    let r = ttyname0(&mut tty);
    if r != 0 {
        return r;
    }
    let path = &tty[..clen(&tty)];
    let line = if path.starts_with(b"/dev/") { &path[5..] } else { &path[5.min(path.len())..] };
    utmp_user_for_line(c"/var/run/utmp", line, name)
}

/// The safe core of `getlogin_r`: the login name into `name` (with its NUL); 0 or an errno.
pub fn getlogin_into(name: &mut [u8]) -> c_int {
    let res = getlogin_r_loginuid(name);
    if res >= 0 {
        return res;
    }
    getlogin_r_fd0(name)
}

/// # Safety
/// `name` is writable for `namesize` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin_r(name: *mut c_char, namesize: usize) -> c_int {
    // SAFETY: `name` is writable for `namesize` bytes (caller's contract).
    getlogin_into(unsafe { ffi::bytes_mut(name.cast(), namesize) })
}

/// `getlogin`'s result. Rule: getlogin is MT-Unsafe (glibc: race:getlogin), so one call at a time.
static LOGIN_NAME: SyncCell<[u8; UT_NAMESIZE + 1]> = SyncCell::new([0; UT_NAMESIZE + 1]);

/// # Safety
/// Always safe to call; the result lives until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    // SAFETY: one getlogin call at a time (the rule of LOGIN_NAME).
    let name = unsafe { &mut *LOGIN_NAME.as_ptr() };
    let res = getlogin_r_loginuid(name);
    if res >= 0 {
        return if res == 0 { name.as_mut_ptr().cast() } else { null_mut() };
    }
    let r = getlogin_r_fd0(name);
    if r != 0 {
        errno::set(r);
        return null_mut();
    }
    name.as_mut_ptr().cast()
}

/// `L_cuserid`: room for a name in `cuserid`'s buffer.
pub const L_CUSERID: usize = 9;
/// `cuserid(NULL)`'s result. Rule: cuserid is MT-Unsafe (glibc: race:cuserid/!string), so one such call at a time.
static CUSERID_NAME: SyncCell<[u8; L_CUSERID]> = SyncCell::new([0; L_CUSERID]);

/// cuserid (stdio.h): the login name of the effective user id, from the password database (at most
/// `L_cuserid` bytes copied, as `strncpy` does); into `string`, or a static buffer if NULL. NULL
/// (with an empty string) if the user has no entry.
///
/// # Safety
/// `string` is NULL or has room for `L_cuserid` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cuserid(string: *mut c_char) -> *mut c_char {
    let euid = unistd::geteuid();
    let mut pwent = Passwd::zero();
    let mut buf = [0u8; 1024];
    let dest: &mut [u8] = if string.is_null() {
        // SAFETY: one cuserid(NULL) call at a time (the rule of CUSERID_NAME).
        unsafe { &mut *CUSERID_NAME.as_ptr() }
    } else {
        // SAFETY: `string` has room for `L_cuserid` bytes (caller's contract).
        unsafe { ffi::bytes_mut(string.cast(), L_CUSERID) }
    };
    if pwuid_into(euid, &mut pwent, &mut buf) != Ok(true) {
        // glibc: no entry (an empty /etc/passwd, say): the caller's buffer comes back holding "", NULL comes back NULL
        if !string.is_null() {
            dest[0] = 0;
        }
        return string;
    }
    // SAFETY: the entry's name is a C string in `buf` (not written any more) or a module's memory.
    let name = unsafe { cbytes(pwent.pw_name) };
    let k = name.len().min(L_CUSERID);
    dest[..k].copy_from_slice(&name[..k]);
    dest[k..].fill(0);
    dest.as_mut_ptr().cast()
}

// ------------------------------------------------------------------------------ shells

/// The state of getusershell: the list (pointers into `strings`), the cursor (an index into the list in use), and
/// whether the fallback list is in use.
struct Shells {
    cur: Option<usize>,
    fallback: bool,
    shells: CVec<*mut c_char>,
    strings: CVec<u8>,
    ok: [*mut c_char; 3],
}

/// Rule: getusershell/setusershell/endusershell are MT-Unsafe (glibc keeps the same unguarded statics), so one call at
/// a time.
static SHELLS: SyncCell<Shells> = SyncCell::new(Shells { cur: None, fallback: false, shells: CVec::new(), strings: CVec::new(), ok: [null_mut(); 3] });

/// The shell state (one call at a time: the rule of SHELLS).
fn shells_state() -> &'static mut Shells {
    // SAFETY: the rule of SHELLS: no two shell calls run at once, and each exported function takes this once.
    unsafe { &mut *SHELLS.as_ptr() }
}

/// Read /etc/shells into the list (glibc's `initshells`); the fallback list ("/bin/sh", "/bin/csh") when it cannot be read.
fn initshells(st: &mut Shells) {
    st.shells = CVec::new();
    st.strings = CVec::new();
    st.fallback = true;
    st.ok = [c"/bin/sh".as_ptr() as *mut c_char, c"/bin/csh".as_ptr() as *mut c_char, null_mut()];
    let Ok(fd) = cmem::open(c"/etc/shells", O_RDONLY | O_CLOEXEC, 0) else { return };
    // fstat for the size
    let size = match unistd::fstat_basic(fd) {
        Ok((_, _, size)) => size as usize,
        Err(_) => {
            let _ = unistd::close(fd);
            return;
        }
    };
    let flen = size + 3;
    let nshells = (size / 3).max(1);
    if !st.strings.resize(flen, 0) || !st.shells.reserve_total(nshells) {
        st.strings = CVec::new();
        st.shells = CVec::new();
        let _ = unistd::close(fd);
        return;
    }
    // read the whole file, then walk it line by line like the fgets loop
    let mut data: CVec<u8> = CVec::new();
    let mut have = 0usize;
    if data.resize(size + 1, 0) {
        loop {
            if have >= size && !data.resize(have + 4096, 0) {
                // grow in case the file grew
                break;
            }
            let want = if have >= size { 4096 } else { size - have };
            match unistd::read_nocancel(fd, &mut data.as_mut_slice()[have..have + want]) {
                Ok(0) => break,
                Ok(n) => have += n,
                Err(e) if e.0 == EINTR => {}
                Err(_) => break,
            }
        }
    }
    let _ = unistd::close(fd);
    st.fallback = false;
    let data_b = &data.as_slice()[..have];
    let strs = st.strings.as_mut_slice();
    let base = strs.as_mut_ptr();
    let mut cp = 0usize;
    let mut pos = 0usize;
    while pos < have {
        // fgets(cp, flen - cp): at most that many minus one bytes of one line
        let room = flen - cp;
        if room < 2 {
            break;
        }
        let mut n = 0usize;
        while pos + n < have && n < room - 1 {
            let b = data_b[pos + n];
            strs[cp + n] = b;
            n += 1;
            if b == b'\n' {
                break;
            }
        }
        strs[cp + n] = 0;
        pos += n;
        while strs[cp] != b'#' && strs[cp] != b'/' && strs[cp] != 0 {
            cp += 1;
        }
        if strs[cp] == b'#' || strs[cp] == 0 || strs[cp + 1] == 0 {
            continue;
        }
        if !st.shells.push(base.wrapping_add(cp).cast()) {
            break;
        }
        while !isspace(strs[cp]) && strs[cp] != b'#' && strs[cp] != 0 {
            cp += 1;
        }
        strs[cp] = 0;
        cp += 1;
    }
    st.shells.push(null_mut());
}

/// The entry at the cursor of the list in use.
fn shell_at(st: &Shells, i: usize) -> *mut c_char {
    if st.fallback { st.ok.get(i).copied().unwrap_or(null_mut()) } else { st.shells.as_slice().get(i).copied().unwrap_or(null_mut()) }
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getusershell() -> *mut c_char {
    let st = shells_state();
    if st.cur.is_none() {
        initshells(st);
        st.cur = Some(0);
    }
    let i = st.cur.unwrap_or(0);
    let ret = shell_at(st, i);
    if !ret.is_null() {
        st.cur = Some(i + 1);
    }
    ret
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endusershell() {
    let st = shells_state();
    st.shells = CVec::new();
    st.strings = CVec::new();
    st.cur = None;
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setusershell() {
    let st = shells_state();
    initshells(st);
    st.cur = Some(0);
}

// ------------------------------------------------------------------------------ Rust API

/// A passwd record borrowed from a caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct PasswdRef<'a> {
    pub name: &'a [u8],
    pub passwd: &'a [u8],
    pub uid: Uid,
    pub gid: Gid,
    pub gecos: &'a [u8],
    pub dir: &'a [u8],
    pub shell: &'a [u8],
}

/// A group record borrowed from a caller's buffer.
#[derive(Clone, Copy)]
pub struct GroupRef<'a> {
    pub name: &'a [u8],
    pub passwd: &'a [u8],
    pub gid: Gid,
    members: CList<'a>,
}

impl<'a> GroupRef<'a> {
    /// The member names.
    pub fn members(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.members.iter()
    }
}

/// # Safety
/// The strings of `p` are NULL or C strings valid for `'a`.
unsafe fn pwref<'a>(p: &Passwd) -> PasswdRef<'a> {
    // SAFETY: forwarded contract.
    let f = unsafe { PwFields::of(p) };
    PasswdRef { name: f.name.unwrap_or(b""), passwd: f.passwd.unwrap_or(b""), uid: p.pw_uid, gid: p.pw_gid, gecos: f.gecos.unwrap_or(b""), dir: f.dir.unwrap_or(b""), shell: f.shell.unwrap_or(b"") }
}

/// The name as a C string in `cname`, or None when it is too long or has a NUL.
fn c_name<'a>(name: &[u8], cname: &'a mut [u8; 256]) -> Option<&'a CStr> {
    if name.len() >= cname.len() || name.contains(&0) {
        return None;
    }
    cname[..name.len()].copy_from_slice(name);
    cname[name.len()] = 0;
    CStr::from_bytes_until_nul(&cname[..]).ok()
}

/// Look up a user by name; the strings live in `buf`. `Ok(None)` = no such user, `Err(errno)`
/// (`ERANGE` when `buf` is too small). `name` must not contain a NUL.
pub fn getpwnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<PasswdRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    let Some(cn) = c_name(name, &mut cname) else { return Ok(None) };
    let mut res = Passwd::zero();
    if !pwnam_into(cn, &mut res, buf)? {
        return Ok(None);
    }
    // SAFETY: the entry's strings are C strings in `buf`, which stays borrowed for `'a`.
    Ok(Some(unsafe { pwref(&res) }))
}

/// Look up a user by id; see [`getpwnam_buf`].
pub fn getpwuid_buf(uid: Uid, buf: &mut [u8]) -> Result<Option<PasswdRef<'_>>, i32> {
    let mut res = Passwd::zero();
    if !pwuid_into(uid, &mut res, buf)? {
        return Ok(None);
    }
    // SAFETY: as in getpwnam_buf.
    Ok(Some(unsafe { pwref(&res) }))
}

/// # Safety
/// The strings and member vector of `g` are C data valid for `'a`.
unsafe fn grref<'a>(g: &Group) -> GroupRef<'a> {
    // SAFETY: forwarded contract.
    let v = unsafe { GroupView::of(g) };
    GroupRef { name: v.name, passwd: v.passwd, gid: g.gr_gid, members: v.mem }
}

/// Look up a group by name; see [`getpwnam_buf`].
pub fn getgrnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<GroupRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    let Some(cn) = c_name(name, &mut cname) else { return Ok(None) };
    let mut res = Group::zero();
    if !grnam_into(cn, &mut res, buf)? {
        return Ok(None);
    }
    // SAFETY: the entry's strings and member vector are in `buf`, which stays borrowed for `'a`.
    Ok(Some(unsafe { grref(&res) }))
}

/// Look up a group by id; see [`getpwnam_buf`].
pub fn getgrgid_buf(gid: Gid, buf: &mut [u8]) -> Result<Option<GroupRef<'_>>, i32> {
    let mut res = Group::zero();
    if !grgid_into(gid, &mut res, buf)? {
        return Ok(None);
    }
    // SAFETY: as in getgrnam_buf.
    Ok(Some(unsafe { grref(&res) }))
}
