#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem::CVec;
use crate::fnmatch::{FNM_NOESCAPE, FNM_PERIOD, fnmatch_bytes};
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, ffi, syscall, unistd};

pub const GLOB_ERR: c_int = 1 << 0;
pub const GLOB_MARK: c_int = 1 << 1;
pub const GLOB_NOSORT: c_int = 1 << 2;
pub const GLOB_DOOFFS: c_int = 1 << 3;
pub const GLOB_NOCHECK: c_int = 1 << 4;
pub const GLOB_APPEND: c_int = 1 << 5;
pub const GLOB_NOESCAPE: c_int = 1 << 6;
pub const GLOB_PERIOD: c_int = 1 << 7;
pub const GLOB_MAGCHAR: c_int = 1 << 8;
pub const GLOB_ALTDIRFUNC: c_int = 1 << 9;
pub const GLOB_BRACE: c_int = 1 << 10;
pub const GLOB_NOMAGIC: c_int = 1 << 11;
pub const GLOB_TILDE: c_int = 1 << 12;
pub const GLOB_ONLYDIR: c_int = 1 << 13;
pub const GLOB_TILDE_CHECK: c_int = 1 << 14;

pub const GLOB_NOSPACE: c_int = 1;
pub const GLOB_ABORTED: c_int = 2;
pub const GLOB_NOMATCH: c_int = 3;

const ALL_FLAGS: c_int = GLOB_ERR | GLOB_MARK | GLOB_NOSORT | GLOB_DOOFFS | GLOB_NOESCAPE | GLOB_NOCHECK | GLOB_APPEND | GLOB_PERIOD | GLOB_ALTDIRFUNC | GLOB_BRACE | GLOB_NOMAGIC | GLOB_TILDE | GLOB_ONLYDIR | GLOB_TILDE_CHECK;

const ENOMEM: i32 = 12;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const EOVERFLOW: i32 = 75;
const ERANGE: i32 = 34;

const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;

#[repr(C)]
pub struct Dirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [c_char; 256],
}

pub type ErrFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;

#[repr(C)]
pub struct Glob {
    pub gl_pathc: usize,
    pub gl_pathv: *mut *mut c_char,
    pub gl_offs: usize,
    pub gl_flags: c_int,
    pub gl_closedir: Option<unsafe extern "C" fn(*mut c_void)>,
    pub gl_readdir: Option<unsafe extern "C" fn(*mut c_void) -> *mut Dirent>,
    pub gl_opendir: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
    pub gl_lstat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
    pub gl_stat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
}

impl Glob {
    pub const fn new() -> Glob {
        Glob { gl_pathc: 0, gl_pathv: null_mut(), gl_offs: 0, gl_flags: 0, gl_closedir: None, gl_readdir: None, gl_opendir: None, gl_lstat: None, gl_stat: None }
    }

    pub unsafe fn paths(&self) -> impl Iterator<Item = &core::ffi::CStr> + '_ {
        (0..self.gl_pathc).map(move |i| {
            let p = unsafe { *self.gl_pathv.wrapping_add(self.gl_offs + i) };
            unsafe { core::ffi::CStr::from_ptr(p) }
        })
    }
}

impl Default for Glob {
    fn default() -> Self {
        Glob::new()
    }
}

fn clen(s: &[u8]) -> usize {
    rusty_libc_core::string::memchr(s, 0).unwrap_or(s.len())
}

struct CBuf(CVec<u8>);

impl CBuf {
    fn of(parts: &[&[u8]]) -> Option<CBuf> {
        let mut v = CVec::new();
        let n: usize = parts.iter().map(|p| p.len()).sum();
        if !v.reserve_total(n + 1) {
            return None;
        }
        for p in parts {
            if !v.extend(p) {
                return None;
            }
        }
        v.push(0).then_some(CBuf(v))
    }
    fn bytes(&self) -> &[u8] {
        let s = self.0.as_slice();
        &s[..clen(s)]
    }
    fn cstr(&self) -> &[u8] {
        let s = self.0.as_slice();
        &s[..=clen(s).min(s.len() - 1)]
    }
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
    fn into_raw(self) -> *mut c_char {
        self.0.into_raw().0.cast()
    }
}

struct Names(CVec<*mut c_char>);

impl Names {
    fn push(&mut self, s: CBuf) -> bool {
        let raw = s.into_raw();
        if self.0.push(raw) {
            return true;
        }
        unsafe { crate::cmem::free(raw) };
        false
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Names {
    fn drop(&mut self) {
        for &p in self.0.as_slice() {
            unsafe { crate::cmem::free(p) };
        }
    }
}

const PAT_NONE: i32 = 0;
const PAT_SPECIAL: i32 = 1;
const PAT_BACKSLASH: i32 = 2;
const PAT_BRACKET: i32 = 4;

fn pattern_type(pattern: &[u8], quote: bool) -> i32 {
    let mut ret = PAT_NONE;
    let mut p = 0;
    let at = |i: usize| pattern.get(i).copied().unwrap_or(0);
    while at(p) != 0 {
        match at(p) {
            b'?' | b'*' => return PAT_SPECIAL,
            b'\\' if quote => {
                if at(p + 1) != 0 {
                    p += 1;
                }
                ret |= PAT_BACKSLASH;
            }
            b'[' => ret |= PAT_BRACKET,
            b']' if ret & 4 != 0 => return PAT_SPECIAL,
            _ => {}
        }
        p += 1;
    }
    ret
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob_pattern_p(pattern: *const c_char, quote: c_int) -> c_int {
    let p = unsafe { ffi::cstr_bytes(pattern) };
    (pattern_type(p, quote != 0) == PAT_SPECIAL) as c_int
}

struct PathV<'a> {
    g: &'a mut Glob,
    cap: usize,
}

impl<'a> PathV<'a> {
    unsafe fn new(g: &'a mut Glob) -> PathV<'a> {
        let cap = if g.gl_pathv.is_null() { 0 } else { g.gl_offs.wrapping_add(g.gl_pathc).wrapping_add(1) };
        PathV { g, cap }
    }
    fn count(&self) -> usize {
        self.g.gl_offs + self.g.gl_pathc
    }
    fn resize(&mut self, n: usize) -> bool {
        let nv = unsafe { crate::cmem::realloc(self.g.gl_pathv, n * core::mem::size_of::<*mut c_char>()) };
        if nv.is_null() {
            return false;
        }
        self.g.gl_pathv = nv;
        self.cap = n;
        true
    }
    fn fresh(&mut self, n: usize) -> bool {
        let v = crate::cmem::malloc(n * core::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
        if v.is_null() {
            return false;
        }
        self.g.gl_pathv = v;
        self.cap = n;
        for i in 0..n {
            self.set(i, null_mut());
        }
        true
    }
    fn set(&mut self, i: usize, p: *mut c_char) {
        assert!(i < self.cap);
        unsafe { *self.g.gl_pathv.wrapping_add(i) = p };
    }
    fn get(&self, i: usize) -> *mut c_char {
        assert!(i < self.cap);
        unsafe { *self.g.gl_pathv.wrapping_add(i) }
    }
    fn path(&self, i: usize) -> &[u8] {
        let p = self.get(i);
        unsafe { ffi::cstr_nonnull(p) }.to_bytes_with_nul()
    }
    fn replace(&mut self, i: usize, s: *mut c_char) {
        let old = self.get(i);
        unsafe { crate::cmem::free(old) };
        self.set(i, s);
    }
    fn sort(&mut self, from: usize) {
        let to = self.count();
        if from >= to {
            return;
        }
        let s = unsafe { ffi::slice_mut(self.g.gl_pathv.wrapping_add(from), to - from) };
        s.sort_unstable_by(|a, b| unsafe { rusty_libc_mem::strcmp(*a, *b) }.cmp(&0));
    }
    fn free(&mut self) {
        if !self.g.gl_pathv.is_null() {
            for i in 0..self.g.gl_pathc {
                let p = self.get(self.g.gl_offs + i);
                unsafe { crate::cmem::free(p) };
            }
            unsafe { crate::cmem::free(self.g.gl_pathv) };
            self.g.gl_pathv = null_mut();
            self.cap = 0;
        }
    }
    fn opendir(&self, dir: &[u8]) -> *mut c_void {
        self.g.gl_opendir.map_or(null_mut(), |f| unsafe { f(dir.as_ptr().cast()) })
    }
    fn readdir<'s>(&self, stream: *mut c_void) -> Option<(&'s [u8], u8)> {
        let d = self.g.gl_readdir.map_or(null_mut(), |f| unsafe { f(stream) });
        if d.is_null() {
            return None;
        }
        let d = unsafe { &*d };
        Some((unsafe { ffi::cstr_nonnull(d.d_name.as_ptr()) }.to_bytes_with_nul(), d.d_type))
    }
    fn closedir(&self, stream: *mut c_void) {
        if let Some(f) = self.g.gl_closedir {
            unsafe { f(stream) };
        }
    }
    fn alt_stat(&self, lstat: bool, path: &[u8], st: &mut StatBuf) -> c_int {
        let f = if lstat { self.g.gl_lstat } else { self.g.gl_stat };
        f.map_or(-1, |f| unsafe { f(path.as_ptr().cast(), st.as_mut_ptr().cast()) })
    }
}

#[derive(Clone, Copy)]
struct ErrCb(Option<ErrFn>);

impl ErrCb {
    unsafe fn new(f: Option<ErrFn>) -> ErrCb {
        ErrCb(f)
    }
    fn stop(self, path: &[u8], e: i32) -> bool {
        self.0.is_some_and(|f| unsafe { f(path.as_ptr().cast(), e) } != 0)
    }
}

const AT_FDCWD: usize = (-100isize) as usize;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const SYS_NEWFSTATAT: usize = 262;
const SYS_GETDENTS64: usize = 217;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

type StatBuf = [u64; 18];

fn stat_mode(st: &StatBuf) -> u32 {
    (st[3] & 0xffff_ffff) as u32
}

fn fstatat(dirfd: usize, path: &[u8], st: &mut StatBuf, flags: usize) -> Result<(), i32> {
    debug_assert!(path.last() == Some(&0));
    let r = unsafe { syscall::syscall4(SYS_NEWFSTATAT, dirfd, path.as_ptr() as usize, st.as_mut_ptr() as usize, flags) };
    match syscall::check(r) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.0),
    }
}

fn glob_lstat(pglob: &PathV, flags: c_int, fullname: &[u8]) -> Result<(), i32> {
    let mut st: StatBuf = [0; 18];
    let compat = STAT_FOR_LSTAT.get();
    if flags & GLOB_ALTDIRFUNC != 0 {
        let r = pglob.alt_stat(!compat, fullname, &mut st);
        if r == 0 { Ok(()) } else { Err(errno::get()) }
    } else {
        fstatat(AT_FDCWD, fullname, &mut st, AT_SYMLINK_NOFOLLOW)
    }
}

#[thread_local]
static STAT_FOR_LSTAT: core::cell::Cell<bool> = core::cell::Cell::new(false);

pub unsafe fn glob_compat(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    let saved = STAT_FOR_LSTAT.replace(true);
    let r = unsafe { glob(pattern, flags, errfunc, pglob) };
    STAT_FOR_LSTAT.set(saved);
    r
}

fn is_dir(filename: &[u8], flags: c_int, pglob: &PathV) -> bool {
    let mut st: StatBuf = [0; 18];
    if flags & GLOB_ALTDIRFUNC != 0 {
        pglob.alt_stat(false, filename, &mut st) == 0 && stat_mode(&st) & S_IFMT == S_IFDIR
    } else {
        fstatat(AT_FDCWD, filename, &mut st, 0).is_ok() && stat_mode(&st) & S_IFMT == S_IFDIR
    }
}

struct Dir {
    fd: c_int,
    buf: CVec<u8>,
    pos: usize,
}

const DIR_BUF: usize = 32768;

const O_RDONLY_DIR_CLOEXEC: i32 = 0o2000000 | 0o200000 | 0o4000;

impl Dir {
    fn open(path: &[u8]) -> Result<Dir, i32> {
        debug_assert!(path.last() == Some(&0));
            let Ok(cpath) = CStr::from_bytes_with_nul(path) else { return Err(EINVAL) };
        match crate::cmem::open(cpath, O_RDONLY_DIR_CLOEXEC, 0) {
            Ok(fd) => {
                let mut buf = CVec::new();
                if !buf.reserve_total(DIR_BUF) {
                    let _ = unistd::close(fd);
                    return Err(ENOMEM);
                }
                Ok(Dir { fd, buf, pos: 0 })
            }
            Err(e) => Err(e.0),
        }
    }
    fn next(&mut self) -> Option<(&[u8], u8)> {
        loop {
            if self.pos >= self.buf.len() {
                let fd = self.fd as usize;
                let mut err = 0;
                let getdents = |p: *mut u8, cap: usize| {
                    match syscall::check(unsafe { syscall::syscall3(SYS_GETDENTS64, fd, p as usize, cap) }) {
                        Ok(n) => n,
                        Err(e) => {
                            err = e.0;
                            0
                        }
                    }
                };
                let n = unsafe { self.buf.fill_raw(DIR_BUF, getdents) };
                if n == 0 {
                    if err != 0 {
                        errno::set(err);
                    }
                    return None;
                }
                self.pos = 0;
            }
            let b = self.buf.as_slice();
            let h: &[u8; 19] = b[self.pos..].first_chunk().unwrap_or_else(|| panic!("short directory record"));
            let ino = u64::from_le_bytes(*h.first_chunk().unwrap_or(&[0; 8]));
            let reclen = u16::from_le_bytes([h[16], h[17]]) as usize;
            let d_type = h[18];
            let start = self.pos + 19;
            let end = (self.pos + reclen).min(b.len()).max(start);
            self.pos += reclen.max(1);
            if ino == 0 {
                continue;
            }
            let area = &b[start..end];
            let in_tail = match area.last_chunk::<8>() {
                Some(t) => {
                    let w = u64::from_le_bytes(*t);
                    let z = w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080;
                    (z != 0).then(|| area.len() - 8 + (z.trailing_zeros() / 8) as usize)
                }
                None => area.iter().position(|&c| c == 0),
            };
            let k = match in_tail {
                Some(k) => k,
                None => {
                    let name = &b[start..];
                    clen(name).min(name.len() - 1)
                }
            };
            return Some((&b[start..=start + k], d_type));
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let save = errno::get();
        let _ = unistd::close(self.fd);
        errno::set(save);
    }
}

fn next_brace_sub(s: &[u8], mut cp: usize, flags: c_int) -> Option<usize> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut depth = 0usize;
    while at(cp) != 0 {
        if flags & GLOB_NOESCAPE == 0 && at(cp) == b'\\' {
            cp += 1;
            if at(cp) == 0 {
                break;
            }
            cp += 1;
        } else {
            if (at(cp) == b'}' && depth == 0) || (at(cp) == b',' && depth == 0) {
                break;
            }
            if at(cp) == b'}' {
                depth = depth.wrapping_sub(1);
            }
            let c = at(cp);
            cp += 1;
            if c == b'{' {
                depth += 1;
            }
        }
    }
    if at(cp) != 0 { Some(cp) } else { None }
}

fn prefix_array(dirname: &[u8], pv: &mut PathV, from: usize, n: usize) -> bool {
    let mut dirlen = clen(dirname);
    if dirlen == 1 && dirname[0] == b'/' {
        dirlen = 0;
    }
    for i in 0..n {
        let elt = pv.path(from + i);
        let new = CBuf::of(&[&dirname[..dirlen], b"/", &elt[..elt.len() - 1]]);
        let Some(new) = new else {
            for j in (0..i).rev() {
                pv.replace(from + j, null_mut());
            }
            return true;
        };
        pv.replace(from + i, new.into_raw());
    }
    false
}

fn block_order(n: usize) -> impl Iterator<Item = (usize, usize)> {
    let mut k = 0u32;
    while k < usize::BITS - 7 && 64usize.saturating_mul((1usize << k) - 1) < n {
        k += 1;
    }
    (0..k).rev().map(move |i| {
        let start = 64 * ((1usize << i) - 1);
        (start, (start + (64usize << i)).min(n))
    })
}

fn glob_in_dir(pattern: &[u8], directory: &[u8], mut flags: c_int, errfunc: ErrCb, pglob: &mut PathV) -> c_int {
    let dirlen = directory.len() - 1;
    let mut names = Names(CVec::new());
    let _ = names.0.reserve_total(64);
    let meta = pattern_type(pattern, flags & GLOB_NOESCAPE == 0);
    let mut alt_stream: *mut c_void = null_mut();
    let mut own_dir: Option<Dir> = None;
    let mut opened = false;
    if meta == PAT_NONE && flags & (GLOB_NOCHECK | GLOB_NOMAGIC) != 0 {
        flags |= GLOB_NOCHECK;
    } else if meta == PAT_NONE {
        let Some(fullname) = CBuf::of(&[&directory[..dirlen], b"/", pattern]) else { return GLOB_NOSPACE };
        let r = glob_lstat(pglob, flags, fullname.cstr());
        let e = errno::get();
        drop(fullname);
        if r.is_ok() || (r.is_err() && e == EOVERFLOW) {
            flags |= GLOB_NOCHECK;
        }
    } else {
        let alt = flags & GLOB_ALTDIRFUNC != 0;
        let mut failed: Option<i32> = None;
        if alt {
            alt_stream = pglob.opendir(directory);
            if alt_stream.is_null() {
                failed = Some(errno::get());
            }
        } else {
            match Dir::open(directory) {
                Ok(d) => own_dir = Some(d),
                Err(e) => {
                    errno::set(e);
                    failed = Some(e);
                }
            }
        }
        if let Some(e) = failed {
            if e != ENOTDIR && (errfunc.stop(directory, e) || flags & GLOB_ERR != 0) {
                return GLOB_ABORTED;
            }
        } else {
            opened = true;
            let fnm_flags = (if flags & GLOB_PERIOD == 0 { FNM_PERIOD } else { 0 }) | (if flags & GLOB_NOESCAPE != 0 { FNM_NOESCAPE } else { 0 });
            flags |= GLOB_MAGCHAR;
            loop {
                let dfd = own_dir.as_ref().map(|d| d.fd as usize);
                let (name, d_type): (&[u8], u8) = if alt {
                    match pglob.readdir(alt_stream) {
                        Some(x) => x,
                        None => break,
                    }
                } else {
                    match own_dir.as_mut().and_then(|d| d.next()) {
                        Some(x) => x,
                        None => break,
                    }
                };
                if flags & GLOB_ONLYDIR != 0 {
                    match d_type {
                        DT_DIR => {}
                        DT_LNK | DT_UNKNOWN => {
                            if let (false, Some(dfd)) = (alt, dfd) {
                                let mut st: StatBuf = [0; 18];
                                if !(fstatat(dfd, name, &mut st, 0).is_ok() && stat_mode(&st) & S_IFMT == S_IFDIR) {
                                    continue;
                                }
                            } else {
                                let sep: &[u8] = if dirlen > 0 && directory[dirlen - 1] == b'/' { b"" } else { b"/" };
                                let Some(s) = CBuf::of(&[&directory[..dirlen], sep, name]) else { return GLOB_NOSPACE };
                                if !is_dir(s.cstr(), flags, pglob) {
                                    continue;
                                }
                            }
                        }
                        _ => continue,
                    }
                }
                if fnmatch_bytes(pattern, name, fnm_flags) == 0 {
                    let Some(copy) = CBuf::of(&[name]) else { return GLOB_NOSPACE };
                    if !names.push(copy) {
                        return GLOB_NOSPACE;
                    }
                }
            }
        }
    }

    if names.len() == 0 && flags & GLOB_NOCHECK != 0 {
        let Some(copy) = CBuf::of(&[pattern]) else { return GLOB_NOSPACE };
        if !names.push(copy) {
            return GLOB_NOSPACE;
        }
    }

    let mut result = GLOB_NOMATCH;
    if names.len() != 0 {
        result = 0;
        let total = pglob.count() + names.len() + 1;
        if !pglob.resize(total) {
            drop(names);
            result = GLOB_NOSPACE;
        } else {
            let all = names.0.as_slice();
            for (start, end) in block_order(all.len()) {
                for &s in &all[start..end] {
                    let at = pglob.count();
                    pglob.set(at, s);
                    pglob.g.gl_pathc += 1;
                }
            }
            names.0.clear();
            let at = pglob.count();
            pglob.set(at, null_mut());
            pglob.g.gl_flags = flags;
        }
    }

    if opened && flags & GLOB_ALTDIRFUNC != 0 {
        let save = errno::get();
        pglob.closedir(alt_stream);
        errno::set(save);
    }
    drop(own_dir);
    result
}

enum DirName<'p> {
    Lit(&'static [u8]),
    Pat(&'p [u8]),
    Own(CBuf),
}

impl DirName<'_> {
    fn cstr(&self) -> &[u8] {
        match self {
            DirName::Lit(s) | DirName::Pat(s) => s,
            DirName::Own(b) => b.cstr(),
        }
    }
    fn at(&self, i: usize) -> u8 {
        self.cstr().get(i).copied().unwrap_or(0)
    }
    fn own(&mut self) -> Option<&mut CBuf> {
        if !matches!(self, DirName::Own(_)) {
            let c = CBuf::of(&[&self.cstr()[..self.cstr().len() - 1]])?;
            *self = DirName::Own(c);
        }
        match self {
            DirName::Own(b) => Some(b),
            _ => None,
        }
    }
}

fn home_dir() -> Result<Option<CBuf>, ()> {
    if let Some(h) = crate::cmem::getenv(b"HOME")
        && !h.is_empty()
    {
        return CBuf::of(&[h]).map(Some).ok_or(());
    }
    let mut name = [0u8; 4096];
    let mut pwbuf = [0u8; 4096];
    if crate::pwd::getlogin_into(&mut name) == 0 {
        let mut pw = crate::pwd::Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() };
        let Ok(n) = CStr::from_bytes_until_nul(&name) else { return Ok(None) };
        if crate::pwd::pwnam_into(n, &mut pw, &mut pwbuf) == Ok(true) {
            let d = unsafe { ffi::cstr(pw.pw_dir) }.map_or(&b""[..], CStr::to_bytes);
            let c = CBuf::of(&[d]).ok_or(())?;
            return Ok(if c.bytes().is_empty() { None } else { Some(c) });
        }
    }
    Ok(None)
}

fn user_home(user: &[u8]) -> Result<Option<CBuf>, ()> {
    let Ok(u) = CStr::from_bytes_until_nul(user) else { return Ok(None) };
    let mut pw = crate::pwd::Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() };
    let mut buf: CVec<u8> = CVec::new();
    let mut sz = 1024usize;
    loop {
        if !buf.resize(sz, 0) {
            return Err(());
        }
        match crate::pwd::pwnam_into(u, &mut pw, buf.as_mut_slice()) {
            Err(ERANGE) => sz *= 2,
            Ok(true) => break,
            _ => return Ok(None),
        }
    }
    let d = unsafe { ffi::cstr(pw.pw_dir) }.map_or(&b""[..], CStr::to_bytes);
    CBuf::of(&[d]).map(Some).ok_or(())
}

fn glob_run(pat: &[u8], flags_in: c_int, errfunc: ErrCb, pglob: &mut PathV) -> c_int {
    let mut flags = flags_in;
    if flags & !ALL_FLAGS != 0 {
        errno::set(EINVAL);
        return -1;
    }
    let patlen = pat.len() - 1;
    let at = |i: usize| pat.get(i).copied().unwrap_or(0);
    if patlen > 0 && pat[patlen - 1] == b'/' {
        flags |= GLOB_ONLYDIR;
    }
    if flags & GLOB_DOOFFS == 0 {
        pglob.g.gl_offs = 0;
    }
    if flags & GLOB_APPEND == 0 {
        pglob.g.gl_pathc = 0;
        if flags & GLOB_DOOFFS == 0 {
            pglob.g.gl_pathv = null_mut();
            pglob.cap = 0;
        } else {
            if pglob.g.gl_offs >= usize::MAX / core::mem::size_of::<*mut c_char>() {
                return GLOB_NOSPACE;
            }
            if !pglob.fresh(pglob.g.gl_offs + 1) {
                return GLOB_NOSPACE;
            }
        }
    }

    if flags & GLOB_BRACE != 0 {
        let begin = if flags & GLOB_NOESCAPE != 0 {
            pat[..patlen].iter().position(|&c| c == b'{')
        } else {
            let mut b = 0;
            loop {
                if at(b) == 0 {
                    break None;
                }
                if at(b) == b'\\' && at(b + 1) != 0 {
                    b += 1;
                } else if at(b) == b'{' {
                    break Some(b);
                }
                b += 1;
            }
        };
        if let Some(begin) = begin {
            let mut next = next_brace_sub(pat, begin + 1, flags);
            let mut rest = next;
            if let Some(mut r) = rest {
                while at(r) != b'}' {
                    match next_brace_sub(pat, r + 1, flags) {
                        Some(x) => r = x,
                        None => {
                            rest = None;
                            break;
                        }
                    }
                }
                if rest.is_some() {
                    rest = Some(r);
                }
            }
            match (next, rest) {
                (Some(_), Some(rest)) => {
                    let rest = &pat[rest + 1..];
                    let firstc = pglob.g.gl_pathc;
                    let mut p = begin + 1;
                    loop {
                        let n = next.unwrap_or(patlen);
                        let Some(onealt) = CBuf::of(&[&pat[..begin], &pat[p..n], &rest[..rest.len() - 1]]) else { return GLOB_NOSPACE };
                        let result = glob_run(onealt.cstr(), (flags & !(GLOB_NOCHECK | GLOB_NOMAGIC)) | GLOB_APPEND, errfunc, pglob);
                        if result != 0 && result != GLOB_NOMATCH {
                            if flags & GLOB_APPEND == 0 {
                                pglob.free();
                                pglob.g.gl_pathc = 0;
                            }
                            return result;
                        }
                        if at(n) == b'}' {
                            break;
                        }
                        p = n + 1;
                        next = next_brace_sub(pat, p, flags);
                    }
                    if pglob.g.gl_pathc != firstc {
                        return 0;
                    } else if flags & (GLOB_NOCHECK | GLOB_NOMAGIC) == 0 {
                        return GLOB_NOMATCH;
                    }
                }
                _ => flags &= !GLOB_BRACE,
            }
        }
    }

    let mut oldcount = pglob.count();
    let mut dirs = Glob::new();
    let mut retval = 0;
    let mut dirname: DirName;
    let mut dirlen: usize;
    let mut dirname_modified = false;
    let filename: Option<&[u8]>;

    let slash = pat[..patlen].iter().rposition(|&c| c == b'/');
    'out: {
        'to_d: {
            'nm: {
                match slash {
                    None => {
                        if flags & (GLOB_TILDE | GLOB_TILDE_CHECK) != 0 && at(0) == b'~' {
                            dirname = DirName::Pat(pat);
                            dirlen = patlen;
                            filename = None;
                        } else {
                            if at(0) == 0 {
                                break 'nm;
                            }
                            filename = Some(pat);
                            dirname = DirName::Lit(b".\0");
                            dirlen = 0;
                        }
                    }
                    Some(s) if s == 0 || (s == 1 && at(0) == b'\\' && flags & GLOB_NOESCAPE == 0) => {
                        dirname = DirName::Lit(b"/\0");
                        dirlen = 1;
                        filename = Some(&pat[s + 1..]);
                    }
                    Some(s) => {
                        dirlen = s;
                        let Some(newp) = CBuf::of(&[&pat[..dirlen]]) else { return GLOB_NOSPACE };
                        dirname = DirName::Own(newp);
                        let fname = &pat[s + 1..];
                        filename = Some(fname);
                        if fname[0] == 0 && dirlen > 1 {
                            let orig_flags = flags;
                            let DirName::Own(dn) = &mut dirname else { unreachable!() };
                            let dnb = dn.as_mut();
                            if flags & GLOB_NOESCAPE == 0 && dnb[dirlen - 1] == b'\\' {
                                let mut p = dirlen - 1;
                                while p > 0 && dnb[p - 1] == b'\\' {
                                    p -= 1;
                                }
                                if (dirlen - p) & 1 != 0 {
                                    dirlen -= 1;
                                    dnb[dirlen] = 0;
                                    flags &= !(GLOB_NOCHECK | GLOB_NOMAGIC);
                                }
                            }
                            let mut p = dirlen - 1;
                            while p > 0 && dnb[p] == b'/' && dnb[p - 1] == b'/' {
                                dnb[p] = 0;
                                p -= 1;
                            }
                            let val = glob_run(dn.cstr(), flags | GLOB_MARK, errfunc, pglob);
                            if val == 0 {
                                pglob.g.gl_flags = (pglob.g.gl_flags & !GLOB_MARK) | (flags & GLOB_MARK);
                            } else if val == GLOB_NOMATCH && flags != orig_flags {
                                dirs.gl_pathv = null_mut();
                                flags = orig_flags;
                                oldcount = pglob.count();
                                break 'nm;
                            }
                            retval = val;
                            break 'out;
                        }
                    }
                }

                if flags & (GLOB_TILDE | GLOB_TILDE_CHECK) != 0 && dirname.at(0) == b'~' {
                    if dirname.at(1) == 0 || dirname.at(1) == b'/' || (flags & GLOB_NOESCAPE == 0 && dirname.at(1) == b'\\' && (dirname.at(2) == 0 || dirname.at(2) == b'/')) {
                        let home = match home_dir() {
                            Ok(h) => h,
                            Err(()) => {
                                retval = GLOB_NOSPACE;
                                break 'out;
                            }
                        };
                        let home = match home {
                            Some(h) => h,
                            None => {
                                if flags & GLOB_TILDE_CHECK != 0 {
                                    retval = GLOB_NOMATCH;
                                    break 'out;
                                }
                                let Some(t) = CBuf::of(&[b"~"]) else {
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                };
                                t
                            }
                        };
                        if dirname.at(1) == 0 {
                            dirlen = home.bytes().len();
                            dirname = DirName::Own(home);
                        } else {
                            let d = dirname.cstr();
                            let Some(newp) = CBuf::of(&[home.bytes(), &d[1..dirlen.min(d.len() - 1)]]) else {
                                retval = GLOB_NOSPACE;
                                break 'out;
                            };
                            dirlen = dirlen + home.bytes().len() - 1;
                            dirname = DirName::Own(newp);
                        }
                        dirname_modified = true;
                    } else {
                        let d = dirname.cstr();
                        let dl = d.len() - 1;
                        let mut end_name = d[..dl].iter().position(|&c| c == b'/');
                        let mut unescape: Option<usize> = None;
                        if flags & GLOB_NOESCAPE == 0 {
                            if end_name.is_none() {
                                unescape = d[..dl].iter().position(|&c| c == b'\\');
                                if unescape.is_some() {
                                    end_name = Some(dl);
                                }
                            } else {
                                unescape = d[..end_name.unwrap_or(dl)].iter().position(|&c| c == b'\\');
                            }
                        }
                        let user_name: Option<CBuf> = match end_name {
                            None => CBuf::of(&[&d[1..dl]]),
                            Some(end) => match unescape {
                                Some(u) => {
                                    let mut v: CVec<u8> = CVec::new();
                                    let mut ok = v.extend(&d[1..u]);
                                    let mut q = u;
                                    while ok && q != end {
                                        if d[q] == b'\\' {
                                            if q + 1 == end {
                                                if filename.is_none() {
                                                    ok = v.push(b'\\');
                                                }
                                                break;
                                            }
                                            q += 1;
                                        }
                                        ok = ok && v.push(d[q]);
                                        q += 1;
                                    }
                                    if ok { CBuf::of(&[v.as_slice()]) } else { None }
                                }
                                None => CBuf::of(&[&d[1..end]]),
                            },
                        };
                        let Some(user_name) = user_name else {
                            retval = GLOB_NOSPACE;
                            break 'out;
                        };
                        match user_home(user_name.cstr()) {
                            Err(()) => {
                                retval = GLOB_NOSPACE;
                                break 'out;
                            }
                            Ok(Some(home)) => {
                                let rest: &[u8] = match end_name {
                                    Some(e) => &d[e..dl],
                                    None => b"",
                                };
                                let Some(nd) = CBuf::of(&[home.bytes(), rest]) else {
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                };
                                dirlen = home.bytes().len() + rest.len();
                                dirname = DirName::Own(nd);
                                dirname_modified = true;
                            }
                            Ok(None) => {
                                if flags & GLOB_TILDE_CHECK != 0 {
                                    retval = GLOB_NOMATCH;
                                    break 'out;
                                }
                            }
                        }
                    }
                }

                let Some(filename) = filename else {
                    let newcount = pglob.count();
                    if !pglob.resize(newcount + 2) {
                        pglob.free();
                        pglob.g.gl_pathc = 0;
                        retval = GLOB_NOSPACE;
                        break 'out;
                    }
                    let d = dirname.cstr();
                    let s = if flags & GLOB_MARK != 0 && is_dir(d, flags, pglob) { CBuf::of(&[&d[..dirlen.min(d.len() - 1)], b"/"]) } else { CBuf::of(&[&d[..d.len() - 1]]) };
                    let Some(s) = s else {
                        pglob.free();
                        pglob.g.gl_pathc = 0;
                        retval = GLOB_NOSPACE;
                        break 'out;
                    };
                    pglob.set(newcount, s.into_raw());
                    pglob.set(newcount + 1, null_mut());
                    pglob.g.gl_pathc += 1;
                    pglob.g.gl_flags = flags;
                    return 0;
                };

                let meta = pattern_type(dirname.cstr(), flags & GLOB_NOESCAPE == 0);
                if meta & (PAT_SPECIAL | PAT_BRACKET) != 0 {
                    if flags & GLOB_NOESCAPE == 0 && dirlen > 0 && dirname.at(dirlen - 1) == b'\\' {
                        let Some(dn) = dirname.own() else {
                            retval = GLOB_NOSPACE;
                            break 'out;
                        };
                        let dnb = dn.as_mut();
                        let mut p = dirlen - 1;
                        while p > 0 && dnb[p - 1] == b'\\' {
                            p -= 1;
                        }
                        if (dirlen - p) & 1 != 0 {
                            dirlen -= 1;
                            dnb[dirlen] = 0;
                        }
                    }
                    if flags & GLOB_ALTDIRFUNC != 0 {
                        dirs.gl_opendir = pglob.g.gl_opendir;
                        dirs.gl_readdir = pglob.g.gl_readdir;
                        dirs.gl_closedir = pglob.g.gl_closedir;
                        dirs.gl_stat = pglob.g.gl_stat;
                        dirs.gl_lstat = pglob.g.gl_lstat;
                    }
                    let mut dv = unsafe { PathV::new(&mut dirs) };
                    let status = glob_run(dirname.cstr(), (flags & (GLOB_ERR | GLOB_NOESCAPE | GLOB_ALTDIRFUNC)) | GLOB_NOSORT | GLOB_ONLYDIR, errfunc, &mut dv);
                    if status != 0 {
                        if flags & GLOB_NOCHECK == 0 || status != GLOB_NOMATCH {
                            retval = status;
                            break 'out;
                        }
                        break 'nm;
                    }
                    for i in 0..dv.g.gl_pathc {
                        let old_pathc = pglob.g.gl_pathc;
                        let dir = dv.path(dv.g.gl_offs + i);
                        let status = glob_in_dir(filename, dir, (flags | GLOB_APPEND) & !(GLOB_NOCHECK | GLOB_NOMAGIC), errfunc, pglob);
                        if status == GLOB_NOMATCH {
                            continue;
                        }
                        if status != 0 {
                            dv.free();
                            pglob.free();
                            pglob.g.gl_pathc = 0;
                            retval = status;
                            break 'out;
                        }
                        let from = old_pathc + pglob.g.gl_offs;
                        let n = pglob.g.gl_pathc - old_pathc;
                        if prefix_array(dir, pglob, from, n) {
                            dv.free();
                            pglob.free();
                            pglob.g.gl_pathc = 0;
                            retval = GLOB_NOSPACE;
                            break 'out;
                        }
                    }
                    flags |= GLOB_MAGCHAR;
                    if pglob.count() == oldcount {
                        break 'nm;
                    }
                    dv.free();
                    break 'to_d;
                } else {
                    let old_pathc = pglob.g.gl_pathc;
                    let orig_flags = flags;
                    if meta & PAT_BACKSLASH != 0 {
                        let Some(dn) = dirname.own() else {
                            retval = GLOB_NOSPACE;
                            break 'out;
                        };
                        let dnb = dn.as_mut();
                        let mut p = clen(dnb);
                        if let Some(first) = dnb[..p].iter().position(|&c| c == b'\\') {
                            p = first;
                            let mut q = p;
                            loop {
                                if dnb[p] == b'\\' {
                                    p += 1;
                                    dnb[q] = dnb[p];
                                    dirlen -= 1;
                                } else {
                                    dnb[q] = dnb[p];
                                }
                                q += 1;
                                let last = dnb[p] == 0;
                                p += 1;
                                if last {
                                    break;
                                }
                            }
                        }
                        dirname_modified = true;
                    }
                    if dirname_modified {
                        flags &= !(GLOB_NOCHECK | GLOB_NOMAGIC);
                    }
                    let status = glob_in_dir(filename, dirname.cstr(), flags, errfunc, pglob);
                    if status != 0 {
                        if status == GLOB_NOMATCH && flags != orig_flags && pglob.count() == oldcount {
                            dirs.gl_pathv = null_mut();
                            flags = orig_flags;
                            break 'nm;
                        }
                        retval = status;
                        break 'out;
                    }
                    let from = old_pathc + pglob.g.gl_offs;
                    let n = pglob.g.gl_pathc - old_pathc;
                    if dirlen > 0 && prefix_array(dirname.cstr(), pglob, from, n) {
                        pglob.free();
                        pglob.g.gl_pathc = 0;
                        retval = GLOB_NOSPACE;
                        break 'out;
                    }
                    break 'to_d;
                }
            }
            let mut dv = unsafe { PathV::new(&mut dirs) };
            if flags & GLOB_NOCHECK != 0 {
                let newcount = pglob.count();
                if !pglob.resize(newcount + 2) {
                    dv.free();
                    retval = GLOB_NOSPACE;
                    break 'out;
                }
                let Some(c) = CBuf::of(&[&pat[..patlen]]) else {
                    dv.free();
                    pglob.free();
                    pglob.g.gl_pathc = 0;
                    retval = GLOB_NOSPACE;
                    break 'out;
                };
                pglob.set(newcount, c.into_raw());
                pglob.g.gl_pathc += 1;
                pglob.set(newcount + 1, null_mut());
                pglob.g.gl_flags = flags;
            } else {
                dv.free();
                retval = GLOB_NOMATCH;
                break 'out;
            }
            dv.free();
        }
        if flags & GLOB_MARK != 0 {
            for i in oldcount..pglob.count() {
                if is_dir(pglob.path(i), flags, pglob) {
                    let Some(ns) = CBuf::of(&[&pglob.path(i)[..pglob.path(i).len() - 1], b"/"]) else {
                        pglob.free();
                        pglob.g.gl_pathc = 0;
                        retval = GLOB_NOSPACE;
                        break 'out;
                    };
                    pglob.replace(i, ns.into_raw());
                }
            }
        }
        if flags & GLOB_NOSORT == 0 {
            pglob.sort(oldcount);
        }
    }
    retval
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    let p = unsafe { ffi::cstr(pattern) };
    let g = unsafe { ffi::out(pglob) };
    let (Some(p), Some(g)) = (p, g) else {
        errno::set(EINVAL);
        return -1;
    };
    if flags & !ALL_FLAGS != 0 {
        errno::set(EINVAL);
        return -1;
    }
    let mut pv = unsafe { PathV::new(g) };
    let cb = unsafe { ErrCb::new(errfunc) };
    glob_run(p.to_bytes_with_nul(), flags, cb, &mut pv)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob64(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe { glob(pattern, flags, errfunc, pglob) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn globfree(pglob: *mut Glob) {
    let g = unsafe { &mut *pglob };
    unsafe { PathV::new(g) }.free();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn globfree64(pglob: *mut Glob) {
    unsafe { globfree(pglob) }
}
