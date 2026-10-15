#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem;
use crate::cmem::CVec;
use core::cell::RefCell;
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::sync_cell::SyncCell;
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

#[repr(C)]
pub struct Group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: Gid,
    pub gr_mem: *mut *mut c_char,
}

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

unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { ffi::cstr(p) }.map_or(b"", CStr::to_bytes)
}

#[derive(Clone, Copy)]
pub(crate) struct CList<'a> {
    p: *const *mut c_char,
    _l: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> CList<'a> {
    pub(crate) unsafe fn new(p: *const *mut c_char) -> CList<'a> {
        CList { p, _l: core::marker::PhantomData }
    }
    pub(crate) fn ptrs(self) -> impl Iterator<Item = *mut c_char> + 'a {
        let mut i = 0;
        core::iter::from_fn(move || {
            if self.p.is_null() {
                return None;
            }
            let q = unsafe { *self.p.wrapping_add(i) };
            if q.is_null() {
                return None;
            }
            i += 1;
            Some(q)
        })
    }
    pub(crate) fn iter(self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.ptrs().map(|q| unsafe { cbytes(q) })
    }
}

fn name_is(name: Option<&[u8]>, field: *const c_char) -> bool {
    name.is_some_and(|n| unsafe { cbytes(field) } == n)
}

fn is_nis(p: *const c_char) -> bool {
    !p.is_null() && matches!(unsafe { *p } as u8, b'+' | b'-')
}

pub(crate) trait Src {
    fn gets(&mut self, buf: &mut [u8]) -> bool;
    fn at_eof(&self) -> bool;
    fn tell(&mut self) -> i64;
    fn seek(&mut self, off: i64) -> bool;
}

pub(crate) struct FdStream {
    fd: c_int,
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    base: i64,
    eof: bool,
}

impl FdStream {
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

pub(crate) struct FileSrc(*mut File);

impl FileSrc {
    pub(crate) unsafe fn new(f: *mut File) -> FileSrc {
        FileSrc(f)
    }
}

impl Src for FileSrc {
    fn gets(&mut self, buf: &mut [u8]) -> bool {
        unsafe { !rusty_libc_stdio::fgets(buf.as_mut_ptr().cast(), buf.len() as c_int, self.0).is_null() }
    }
    fn at_eof(&self) -> bool {
        unsafe { rusty_libc_stdio::feof(self.0) != 0 }
    }
    fn tell(&mut self) -> i64 {
        rusty_libc_stdio::file::tell(unsafe { rusty_libc_stdio::file::stream(self.0) })
    }
    fn seek(&mut self, off: i64) -> bool {
        rusty_libc_stdio::file::seek(unsafe { rusty_libc_stdio::file::stream(self.0) }, off, 0) == 0
    }
}

impl FileSrc {
    fn write(&mut self, b: &[u8]) -> bool {
        rusty_libc_stdio::file::write_bytes(unsafe { rusty_libc_stdio::file::stream(self.0) }, b) == b.len()
    }
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

fn clen(buf: &[u8]) -> usize {
    rusty_libc_core::string::memchr(buf, 0).unwrap_or(buf.len())
}

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

pub(crate) struct Cur<'a> {
    line: &'a mut [u8],
    i: usize,
}

impl Cur<'_> {
    fn peek(&self) -> u8 {
        self.line.get(self.i).copied().unwrap_or(0)
    }
    fn at_end(&self) -> bool {
        self.i >= self.line.len()
    }
    fn ptr(&mut self, k: usize) -> *mut c_char {
        self.line.as_mut_ptr().wrapping_add(k).cast()
    }
    fn chop_newline(&mut self) {
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
    #[inline(always)]
    fn int_field(&mut self, out: &mut u32) -> bool {
        let (v, e) = self.strtou32();
        *out = v;
        if e == self.i {
            return false;
        }
        self.field_end(e)
    }
    #[inline(always)]
    fn int_field_maybe_null(&mut self, out: &mut u32, default: u32) -> bool {
        if self.at_end() {
            return false;
        }
        let (v, e) = self.strtou32();
        *out = if e == self.i { default } else { v };
        self.field_end(e)
    }
    fn first_is_nis(&self) -> bool {
        matches!(self.line.first(), Some(b'+' | b'-'))
    }
}

pub(crate) struct Vec8<'a> {
    area: &'a mut [u8],
    off: usize,
    n: usize,
}

impl<'a> Vec8<'a> {
    fn new(area: &'a mut [u8], from: usize) -> Vec8<'a> {
        let a = (area.as_ptr() as usize).wrapping_add(from);
        let off = from + (a.wrapping_add(7) & !7).wrapping_sub(a);
        Vec8 { area, off, n: 0 }
    }
    fn room(&self) -> bool {
        self.off + 8 * (self.n + 2) <= self.area.len()
    }
    fn push(&mut self, p: *mut c_char) {
        let o = self.off + 8 * self.n;
        self.area[o..o + 8].copy_from_slice(&(p as usize).to_ne_bytes());
        self.n += 1;
    }
    fn finish(mut self) -> (*mut *mut c_char, usize) {
        self.push(null_mut());
        (self.area.as_mut_ptr().wrapping_add(self.off).cast(), self.off + 8 * self.n)
    }
}

pub(crate) fn split_line(buf: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let n = clen(buf);
    let (line, rest) = buf.split_at_mut(n);
    let room = if rest.is_empty() { rest } else { &mut rest[1..] };
    (line, room)
}

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

pub const PASSWD_FILE: &[u8] = Passwd::PATH.to_bytes_with_nul();
pub const GROUP_FILE: &[u8] = Group::PATH.to_bytes_with_nul();
pub const SHADOW_FILE: &[u8] = Spwd::PATH.to_bytes_with_nul();

pub struct CompatFile(FdStream);

impl CompatFile {
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
    pub fn tell(&mut self) -> i64 {
        self.0.tell()
    }
    pub fn seek(&mut self, off: i64) {
        self.0.seek(off);
    }
    pub fn next_entry<E: CompatEntry>(&mut self, res: &mut E, buf: &mut [u8]) -> i32 {
        internal_getent::<E, _>(&mut self.0, res, buf)
    }
    pub unsafe fn next_passwd(&mut self, res: *mut Passwd, buf: *mut u8, len: usize) -> i32 {
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
    pub unsafe fn next_group(&mut self, res: *mut Group, buf: *mut u8, len: usize) -> i32 {
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
    pub unsafe fn next_spwd(&mut self, res: *mut Spwd, buf: *mut u8, len: usize) -> i32 {
        let o = unsafe { Out::from_c(res, buf.cast(), len, null_mut()) };
        self.next_entry(o.res, o.buf)
    }
}

#[allow(private_bounds)]
pub trait CompatEntry: Entry {}
impl CompatEntry for Passwd {}
impl CompatEntry for Group {}
impl CompatEntry for Spwd {}

pub unsafe fn files_initgroups_dyn(user: *const c_char, group: Gid, start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64) {
    let user = unsafe { ffi::cstr_bytes(user) };
    let mut g = unsafe { GidArray::from_raw(*groups, *size) };
    files_groups(user, group, &mut g, limit, start);
    (*groups, *size) = g.into_raw();
}

const ST_TRYAGAIN: i32 = -2;
const ST_UNAVAIL: i32 = -1;
const ST_NOTFOUND: i32 = 0;
const ST_SUCCESS: i32 = 1;

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

fn nss_dispatch(db: &[u8], func: &[u8], files: &dyn Fn() -> i32, call: &dyn Fn(usize, *mut c_int) -> i32) -> i32 {
    nssent::dispatch_compat(db, func, files, call, None, compat_fn(func))
}

pub(crate) fn compat_fn(func: &[u8]) -> usize {
    #[cfg(feature = "export")]
    unsafe extern "C" {
        fn __rl_nss_compat_function(name: *const u8, len: usize) -> usize;
    }
    #[cfg(feature = "export")]
    return unsafe { __rl_nss_compat_function(func.as_ptr(), func.len()) };
    #[cfg(not(feature = "export"))]
    {
        let _ = func;
        0
    }
}

fn call_by_name<E>(f: usize, name: *const c_char, res: *mut E, buf: *mut c_char, len: usize, en: *mut c_int) -> c_int {
    let f: unsafe extern "C" fn(*const c_char, *mut E, *mut c_char, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
    unsafe { f(name, res, buf, len, en) }
}

fn call_by_id<E>(f: usize, id: u32, res: *mut E, buf: *mut c_char, len: usize, en: *mut c_int) -> c_int {
    let f: unsafe extern "C" fn(u32, *mut E, *mut c_char, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
    unsafe { f(id, res, buf, len, en) }
}

fn put_word(buf: &mut [u8], off: usize, v: usize) {
    buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

fn get_word(buf: &[u8], off: usize) -> usize {
    usize::from_ne_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]))
}

pub(crate) struct GroupView<'a> {
    name: &'a [u8],
    passwd: &'a [u8],
    gid: Gid,
    mem: CList<'a>,
}

impl GroupView<'_> {
    unsafe fn of<'a>(g: &Group) -> GroupView<'a> {
        let s = |p: *mut c_char| unsafe { cbytes(p) };
        GroupView { name: s(g.gr_name), passwd: s(g.gr_passwd), gid: g.gr_gid, mem: unsafe { CList::new(g.gr_mem) } }
    }
}

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

fn merge_grp(saved: &mut Group, savedbuf: &mut CVec<u8>, savedend: usize, merge: &mut Group, mergebuf: &mut [u8]) -> c_int {
    let to_merge = |saved: &Group, merge: &mut Group, mergebuf: &mut [u8]| -> c_int {
        let sv = unsafe { GroupView::of(saved) };
        match copy_grp(&sv, merge, mergebuf) {
            Ok(_) => 0,
            Err(e) => e,
        }
    };
    let sv = unsafe { GroupView::of(saved) };
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
        let src = unsafe { GroupView::of(&self.saved) };
        match copy_grp(&src, o.res, o.buf) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }
}

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

pub(crate) struct Out<'a, E> {
    pub(crate) res: &'a mut E,
    pub(crate) buf: &'a mut [u8],
    result: *mut *mut E,
    found: bool,
}

impl<'a, E> Out<'a, E> {
    pub(crate) unsafe fn from_c(res: *mut E, buf: *mut c_char, len: usize, result: *mut *mut E) -> Out<'a, E> {
        let r = unsafe { &mut *res };
        let b = unsafe { ffi::bytes_mut(buf.cast(), len) };
        Out { res: r, buf: b, result, found: false }
    }
    pub(crate) fn new(res: &'a mut E, buf: &'a mut [u8]) -> Out<'a, E> {
        Out { res, buf, result: null_mut(), found: false }
    }
    fn ptrs(&mut self) -> (*mut E, *mut c_char, usize) {
        (&raw mut *self.res, self.buf.as_mut_ptr().cast(), self.buf.len())
    }
    pub(crate) fn finish(&mut self, ok: bool) {
        self.found = ok;
        if !self.result.is_null() {
            let r = if ok { &raw mut *self.res } else { null_mut() };
            unsafe { *self.result = r };
        }
    }
}

#[derive(Clone, Copy)]
struct Key<'a> {
    p: *const c_char,
    b: Option<&'a [u8]>,
}

impl<'a> Key<'a> {
    unsafe fn new(name: *const c_char) -> Key<'a> {
        Key { p: name, b: unsafe { ffi::cstr(name) }.map(CStr::to_bytes) }
    }
    fn nis(&self) -> bool {
        self.b.is_some_and(|b| matches!(b.first(), Some(b'+' | b'-')))
    }
}

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

unsafe fn r_args<'a, E>(name: *const c_char, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> (Key<'a>, Out<'a, E>) {
    let k = unsafe { Key::new(name) };
    (k, unsafe { Out::from_c(resbuf, buffer, buflen, result) })
}

fn pwnam_r(k: Key, out: &mut Out<Passwd>) -> c_int {
    lookup(b"passwd", b"getpwnam_r", out, |r: &Passwd| !k.nis() && name_is(k.b, r.pw_name), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

fn pwuid_r(uid: Uid, out: &mut Out<Passwd>) -> c_int {
    lookup(b"passwd", b"getpwuid_r", out, |r: &Passwd| r.pw_uid == uid && !is_nis(r.pw_name), |f, r, b, l, en| call_by_id(f, uid, r, b, l, en))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam_r(name: *const c_char, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    pwnam_r(k, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid_r(uid: Uid, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    pwuid_r(uid, &mut out)
}

pub(crate) struct StaticBuf<E> {
    buf: CVec<u8>,
    res: E,
}

unsafe impl<E> Send for StaticBuf<E> {}

impl<E> StaticBuf<E> {
    pub(crate) const fn new(res: E) -> StaticBuf<E> {
        StaticBuf { buf: CVec::new(), res }
    }
}

const NSS_BUFLEN: usize = 1024;

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    let k = unsafe { Key::new(name) };
    by_buf(&PWNAM, false, false, |out| pwnam_r(k, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid(uid: Uid) -> *mut Passwd {
    by_buf(&PWUID, false, false, |out| pwuid_r(uid, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpwent() {
    db_setent::<Passwd>(&PW_DB, &PW_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    db_endent::<Passwd>(&PW_DB, &PW_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent_r(resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Passwd>(&PW_DB, &PW_NAMES, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    by_buf(&PWENT, false, true, |out| db_getent::<Passwd>(&PW_DB, &PW_NAMES, out))
}

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

unsafe fn fget_r<E: Entry>(stream: *mut File, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> c_int {
    let mut src = unsafe { FileSrc::new(stream) };
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    fget_core(&mut src, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent_r(stream: *mut File, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    unsafe { fget_r::<Passwd>(stream, resbuf, buffer, buflen, result) }
}

unsafe fn fget<E: Entry>(stream: *mut File, sb: &Locked<StaticBuf<E>>) -> *mut E {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent(stream: *mut File) -> *mut Passwd {
    unsafe { fget::<Passwd>(stream, &FGETPW) }
}

fn invalid_field_char(c: u8) -> bool {
    c == b':' || c == b'\n'
}

fn valid_field(s: Option<&[u8]>) -> bool {
    s.is_none_or(|s| !s.iter().any(|&c| invalid_field_char(c)))
}

fn valid_list_field(list: CList) -> bool {
    list.iter().all(|s| !s.iter().any(|&c| invalid_field_char(c) || c == b','))
}

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
    fn bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
    fn write_to(&self, f: &mut FileSrc) -> bool {
        self.ok && f.write(self.bytes())
    }
}

fn put_rewritten(line: &mut Line, s: &[u8]) {
    for &c in s {
        line.put(&[if invalid_field_char(c) { b' ' } else { c }]);
    }
}

unsafe fn opt<'a>(p: *const c_char) -> Option<&'a [u8]> {
    unsafe { ffi::cstr(p) }.map(CStr::to_bytes)
}

struct PwFields<'a> {
    name: Option<&'a [u8]>,
    passwd: Option<&'a [u8]>,
    gecos: Option<&'a [u8]>,
    dir: Option<&'a [u8]>,
    shell: Option<&'a [u8]>,
}

impl PwFields<'_> {
    unsafe fn of<'a>(p: &Passwd) -> PwFields<'a> {
        let f = |q: *mut c_char| unsafe { opt(q) };
        PwFields { name: f(p.pw_name), passwd: f(p.pw_passwd), gecos: f(p.pw_gecos), dir: f(p.pw_dir), shell: f(p.pw_shell) }
    }
}

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

unsafe fn put_args<'a, E>(p: *const E, stream: *mut File) -> (Option<&'a E>, Option<FileSrc>) {
    let e = unsafe { p.as_ref() };
    (e, if stream.is_null() { None } else { Some(unsafe { FileSrc::new(stream) }) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putpwent(p: *const Passwd, stream: *mut File) -> c_int {
    let (Some(p), Some(mut f)) = (unsafe { put_args(p, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let fields = unsafe { PwFields::of(p) };
    let Some(l) = passwd_line(p, &fields) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

pub(crate) fn pwuid_into(uid: Uid, res: &mut Passwd, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = pwuid_r(uid, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

pub(crate) fn pwnam_into(name: &CStr, res: &mut Passwd, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = pwnam_r(Key { p: name.as_ptr(), b: Some(name.to_bytes()) }, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

fn grnam_into(name: &CStr, res: &mut Group, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = grnam_r(Key { p: name.as_ptr(), b: Some(name.to_bytes()) }, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

fn grgid_into(gid: Gid, res: &mut Group, buf: &mut [u8]) -> Result<bool, c_int> {
    let mut out = Out::new(res, buf);
    let rc = grgid_r(gid, &mut out);
    if rc != 0 { Err(rc) } else { Ok(out.found) }
}

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
    let out = unsafe { ffi::bytes_mut(buf.cast(), b.len() + 1) };
    out[..b.len()].copy_from_slice(b);
    out[b.len()] = 0;
    0
}

fn grnam_r(k: Key, out: &mut Out<Group>) -> c_int {
    lookup_group(b"getgrnam_r", out, |r: &Group| !k.nis() && name_is(k.b, r.gr_name), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

fn grgid_r(gid: Gid, out: &mut Out<Group>) -> c_int {
    lookup_group(b"getgrgid_r", out, |r: &Group| r.gr_gid == gid && !is_nis(r.gr_name), |f, r, b, l, en| call_by_id(f, gid, r, b, l, en))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam_r(name: *const c_char, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    grnam_r(k, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid_r(gid: Gid, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    grgid_r(gid, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    let k = unsafe { Key::new(name) };
    by_buf(&GRNAM, false, false, |out| grnam_r(k, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid(gid: Gid) -> *mut Group {
    by_buf(&GRGID, false, false, |out| grgid_r(gid, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setgrent() {
    db_setent::<Group>(&GR_DB, &GR_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endgrent() {
    db_endent::<Group>(&GR_DB, &GR_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent_r(resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Group>(&GR_DB, &GR_NAMES, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    by_buf(&GRENT, false, true, |out| db_getent::<Group>(&GR_DB, &GR_NAMES, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent_r(stream: *mut File, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    unsafe { fget_r::<Group>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent(stream: *mut File) -> *mut Group {
    unsafe { fget::<Group>(stream, &FGETGR) }
}

fn group_line(g: &Group, v: &GroupView) -> Option<Line> {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putgrent(gr: *const Group, stream: *mut File) -> c_int {
    let (Some(g), Some(mut f)) = (unsafe { put_args(gr, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let v = unsafe { GroupView::of(g) };
    let Some(l) = group_line(g, &v) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

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
        n += clen(&b[n..n + got]);
        if n > 0 && b[n - 1] == b'\n' {
            return n;
        }
    }
}

pub(crate) struct GidArray {
    p: *mut Gid,
    size: i64,
}

impl GidArray {
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
        unsafe { *self.p.wrapping_add(i as usize) = v };
    }
    fn get(&self, i: i64) -> Gid {
        assert!(i >= 0 && i < self.size);
        unsafe { *self.p.wrapping_add(i as usize) }
    }
    fn grow(&mut self, newsize: i64) -> bool {
        let ng = unsafe { cmem::realloc(self.p, newsize as usize * 4) };
        if ng.is_null() {
            return false;
        }
        self.p = ng;
        self.size = newsize;
        true
    }
}

impl Drop for GidArray {
    fn drop(&mut self) {
        unsafe { cmem::free(self.p) }
    }
}

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

fn internal_getgrouplist(user: Key, group: Gid, groups: &mut GidArray, limit: i64) -> i64 {
    groups.set(0, group);
    let mut start: i64 = 1;
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
            let f: unsafe extern "C" fn(*const c_char, Gid, *mut i64, *mut i64, *mut *mut Gid, i64, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
            let mut e: c_int = 0;
            status = unsafe { f(user.p, group, &mut start, &mut groups.size, &mut groups.p, limit, &mut e) };
            if !(-2..=1).contains(&status) {
                status = ST_UNAVAIL;
            }
        }
        dedupe_groups(groups, &mut start, prev_start);
        prev_start = start;
        if src.action(status) == nssmod::ACT_RETURN {
            break;
        }
    }
    start
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrouplist(user: *const c_char, group: Gid, groups: *mut Gid, ngroups: *mut c_int) -> c_int {
    let (k, g, ng) = unsafe { gl_args(user, groups, ngroups) };
    getgrouplist_into(k, group, g, ng)
}

unsafe fn gl_args<'a>(user: *const c_char, groups: *mut Gid, ngroups: *mut c_int) -> (Key<'a>, &'a mut [Gid], &'a mut c_int) {
    let k = unsafe { Key::new(user) };
    let ng = unsafe { &mut *ngroups };
    let g = unsafe { ffi::slice_mut(groups, (*ng).max(0) as usize) };
    (k, g, ng)
}

const SYS_SETGROUPS: usize = 116;
const NGROUPS_MAX: i64 = 65536;

fn initgroups_key(user: Key, group: Gid) -> c_int {
    let limit = NGROUPS_MAX;
    let Some(mut groups) = GidArray::alloc(limit.min(64)) else { return -1 };
    let mut ngroups = internal_getgrouplist(user, group, &mut groups, limit);
    loop {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: Gid) -> c_int {
    initgroups_key(unsafe { Key::new(user) }, group)
}

fn spnam_r(k: Key, out: &mut Out<Spwd>) -> c_int {
    lookup(b"shadow", b"getspnam_r", out, |r: &Spwd| !k.nis() && name_is(k.b, r.sp_namp), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam_r(name: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    spnam_r(k, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut Spwd {
    let k = unsafe { Key::new(name) };
    by_buf(&SPNAM, false, false, |out| spnam_r(k, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setspent() {
    db_setent::<Spwd>(&SP_DB, &SP_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endspent() {
    db_endent::<Spwd>(&SP_DB, &SP_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent_r(resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Spwd>(&SP_DB, &SP_NAMES, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent() -> *mut Spwd {
    by_buf(&SPENT, false, true, |out| db_getent::<Spwd>(&SP_DB, &SP_NAMES, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent_r(stream: *mut File, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    unsafe { fget_r::<Spwd>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent(stream: *mut File) -> *mut Spwd {
    unsafe { fget::<Spwd>(stream, &FGETSP) }
}

#[derive(Clone, Copy)]
pub(crate) struct SrcStr<'a> {
    addr: usize,
    bytes: &'a [u8],
}

impl<'a> SrcStr<'a> {
    pub(crate) unsafe fn new(s: *const c_char) -> SrcStr<'a> {
        SrcStr { addr: s as usize, bytes: unsafe { ffi::cstr_nonnull(s) }.to_bytes() }
    }
}

pub(crate) fn strncpy_fits(src: SrcStr, buf: &mut [u8]) -> bool {
    let n = buf.len();
    let base = buf.as_ptr() as usize;
    buf[n - 1] = 0;
    if src.addr >= base && src.addr < base + n {
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

fn sgetsp_r(s: SrcStr, out: &mut Out<Spwd>) -> c_int {
    if out.buf.is_empty() || !strncpy_fits(s, out.buf) {
        return ERANGE;
    }
    let (line, area) = split_line(out.buf);
    let pr = Spwd::parse(line, area, out.res);
    out.finish(pr > 0);
    if pr > 0 { 0 } else { errno::get() }
}

unsafe fn sget_args<'a, E>(string: *const c_char, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> (SrcStr<'a>, Out<'a, E>) {
    let s = unsafe { SrcStr::new(string) };
    (s, unsafe { Out::from_c(resbuf, buffer, buflen, result) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent_r(string: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    let (s, mut out) = unsafe { sget_args(string, resbuf, buffer, buflen, result) };
    sgetsp_r(s, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent(string: *const c_char) -> *mut Spwd {
    let s = unsafe { SrcStr::new(string) };
    by_buf(&SGETSP, true, true, |out| sgetsp_r(s, out))
}

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
        l.num(i128::from(p.sp_flag as i64));
    }
    l.put(b"\n");
    Some(l)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putspent(p: *const Spwd, stream: *mut File) -> c_int {
    let (Some(p), Some(mut f)) = (unsafe { put_args(p, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let f2 = |q: *mut c_char| unsafe { opt(q) };
    let Some(l) = shadow_line(p, f2(p.sp_namp), f2(p.sp_pwdp)) else {
        errno::set(EINVAL);
        return -1;
    };
    if l.write_to(&mut f) { 0 } else { -1 }
}

static LOCK_FD: Locked<c_int> = Locked::new(-1);

extern "C" fn noop_handler(_sig: c_int) {}

#[unsafe(naked)]
unsafe extern "C" fn restore_rt() {
    core::arch::naked_asm!("mov eax, 15", "syscall");
}

const SYS_ALARM: usize = 37;
const SIGALRM: i32 = 14;
const F_SETLKW: usize = 7;

fn alarm(secs: usize) {
    unsafe { syscall::syscall1(SYS_ALARM, secs) };
}

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
        let fl: [u64; 4] = [1 , 0, 0, 0];
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

const UT_NAMESIZE: usize = 32;
const UT_LINESIZE: usize = 32;
const UTMP_SIZE: usize = 384;
const NAME_MAX2: usize = 2 + 2 * 255;

fn put_name(s: &[u8], name: &mut [u8]) -> c_int {
    if s.len() + 1 > name.len() {
        errno::set(ERANGE);
        return ERANGE;
    }
    name[..s.len()].copy_from_slice(s);
    name[s.len()] = 0;
    0
}

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
        Ok(true) => put_name(unsafe { cbytes(pwd.pw_name) }, name),
        _ => -1,
    }
}

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

fn ttyname0(buf: &mut [u8]) -> c_int {
    let mut t = [0u8; 64];
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, 0, unistd::TCGETS2, t.as_mut_ptr() as usize) };
    if let Err(e) = syscall::check(r) {
        return e.0;
    }
    let len = buf.len();
    let r = unsafe { syscall::syscall3(89 , c"/proc/self/fd/0".as_ptr() as usize, buf.as_mut_ptr() as usize, len) };
    match syscall::check(r) {
        Err(e) => e.0,
        Ok(n) if n >= len => ERANGE,
        Ok(n) => {
            buf[n] = 0;
            let s = &buf[..n];
            if s.first() != Some(&b'/') {
                return ENOENT;
            }
            if s.ends_with(b" (deleted)") {
                buf[n - 10] = 0;
            }
            0
        }
    }
}

fn utmp_is_login(t: i16) -> bool {
    matches!(t, 5..=7)
}

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

pub fn getlogin_into(name: &mut [u8]) -> c_int {
    let res = getlogin_r_loginuid(name);
    if res >= 0 {
        return res;
    }
    getlogin_r_fd0(name)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin_r(name: *mut c_char, namesize: usize) -> c_int {
    getlogin_into(unsafe { ffi::bytes_mut(name.cast(), namesize) })
}

static LOGIN_NAME: SyncCell<[u8; UT_NAMESIZE + 1]> = SyncCell::new([0; UT_NAMESIZE + 1]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
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

pub const L_CUSERID: usize = 9;
static CUSERID_NAME: SyncCell<[u8; L_CUSERID]> = SyncCell::new([0; L_CUSERID]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cuserid(string: *mut c_char) -> *mut c_char {
    let euid = unistd::geteuid();
    let mut pwent = Passwd::zero();
    let mut buf = [0u8; 1024];
    let dest: &mut [u8] = if string.is_null() {
        unsafe { &mut *CUSERID_NAME.as_ptr() }
    } else {
        unsafe { ffi::bytes_mut(string.cast(), L_CUSERID) }
    };
    if pwuid_into(euid, &mut pwent, &mut buf) != Ok(true) {
        if !string.is_null() {
            dest[0] = 0;
        }
        return string;
    }
    let name = unsafe { cbytes(pwent.pw_name) };
    let k = name.len().min(L_CUSERID);
    dest[..k].copy_from_slice(&name[..k]);
    dest[k..].fill(0);
    dest.as_mut_ptr().cast()
}

struct Shells {
    cur: Option<usize>,
    fallback: bool,
    shells: CVec<*mut c_char>,
    strings: CVec<u8>,
    ok: [*mut c_char; 3],
}

static SHELLS: SyncCell<Shells> = SyncCell::new(Shells { cur: None, fallback: false, shells: CVec::new(), strings: CVec::new(), ok: [null_mut(); 3] });

fn shells_state() -> &'static mut Shells {
    unsafe { &mut *SHELLS.as_ptr() }
}

fn initshells(st: &mut Shells) {
    st.shells = CVec::new();
    st.strings = CVec::new();
    st.fallback = true;
    st.ok = [c"/bin/sh".as_ptr() as *mut c_char, c"/bin/csh".as_ptr() as *mut c_char, null_mut()];
    let Ok(fd) = cmem::open(c"/etc/shells", O_RDONLY | O_CLOEXEC, 0) else { return };
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
    let mut data: CVec<u8> = CVec::new();
    let mut have = 0usize;
    if data.resize(size + 1, 0) {
        loop {
            if have >= size && !data.resize(have + 4096, 0) {
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

fn shell_at(st: &Shells, i: usize) -> *mut c_char {
    if st.fallback { st.ok.get(i).copied().unwrap_or(null_mut()) } else { st.shells.as_slice().get(i).copied().unwrap_or(null_mut()) }
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endusershell() {
    let st = shells_state();
    st.shells = CVec::new();
    st.strings = CVec::new();
    st.cur = None;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setusershell() {
    let st = shells_state();
    initshells(st);
    st.cur = Some(0);
}

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

#[derive(Clone, Copy)]
pub struct GroupRef<'a> {
    pub name: &'a [u8],
    pub passwd: &'a [u8],
    pub gid: Gid,
    members: CList<'a>,
}

impl<'a> GroupRef<'a> {
    pub fn members(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.members.iter()
    }
}

unsafe fn pwref<'a>(p: &Passwd) -> PasswdRef<'a> {
    let f = unsafe { PwFields::of(p) };
    PasswdRef { name: f.name.unwrap_or(b""), passwd: f.passwd.unwrap_or(b""), uid: p.pw_uid, gid: p.pw_gid, gecos: f.gecos.unwrap_or(b""), dir: f.dir.unwrap_or(b""), shell: f.shell.unwrap_or(b"") }
}

fn c_name<'a>(name: &[u8], cname: &'a mut [u8; 256]) -> Option<&'a CStr> {
    if name.len() >= cname.len() || name.contains(&0) {
        return None;
    }
    cname[..name.len()].copy_from_slice(name);
    cname[name.len()] = 0;
    CStr::from_bytes_until_nul(&cname[..]).ok()
}

pub fn getpwnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<PasswdRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    let Some(cn) = c_name(name, &mut cname) else { return Ok(None) };
    let mut res = Passwd::zero();
    if !pwnam_into(cn, &mut res, buf)? {
        return Ok(None);
    }
    Ok(Some(unsafe { pwref(&res) }))
}

pub fn getpwuid_buf(uid: Uid, buf: &mut [u8]) -> Result<Option<PasswdRef<'_>>, i32> {
    let mut res = Passwd::zero();
    if !pwuid_into(uid, &mut res, buf)? {
        return Ok(None);
    }
    Ok(Some(unsafe { pwref(&res) }))
}

unsafe fn grref<'a>(g: &Group) -> GroupRef<'a> {
    let v = unsafe { GroupView::of(g) };
    GroupRef { name: v.name, passwd: v.passwd, gid: g.gr_gid, members: v.mem }
}

pub fn getgrnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<GroupRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    let Some(cn) = c_name(name, &mut cname) else { return Ok(None) };
    let mut res = Group::zero();
    if !grnam_into(cn, &mut res, buf)? {
        return Ok(None);
    }
    Ok(Some(unsafe { grref(&res) }))
}

pub fn getgrgid_buf(gid: Gid, buf: &mut [u8]) -> Result<Option<GroupRef<'_>>, i32> {
    let mut res = Group::zero();
    if !grgid_into(gid, &mut res, buf)? {
        return Ok(None);
    }
    Ok(Some(unsafe { grref(&res) }))
}
