#![allow(clippy::deref_addrof)]
use crate::fnmatch::{FNM_NOESCAPE, FNM_PERIOD, fnmatch};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, syscall};

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
        (0..self.gl_pathc).map(move |i| unsafe { core::ffi::CStr::from_ptr(*self.gl_pathv.add(self.gl_offs + i)) })
    }
}

impl Default for Glob {
    fn default() -> Self {
        Glob::new()
    }
}

unsafe fn slen(p: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(p.cast()) }
}

unsafe fn byte(p: *const c_char, i: usize) -> u8 {
    unsafe { *(p as *const u8).add(i) }
}

struct Owned(*mut c_char);

impl Owned {
    unsafe fn copy(src: *const c_char, n: usize) -> Option<Owned> {
        unsafe {
            let p = rusty_libc_malloc::malloc(n + 1) as *mut c_char;
            if p.is_null() {
                return None;
            }
            core::ptr::copy_nonoverlapping(src, p, n);
            *p.add(n) = 0;
            Some(Owned(p))
        }
    }
    unsafe fn dup(src: *const c_char) -> Option<Owned> {
        unsafe { Owned::copy(src, slen(src)) }
    }
    fn into_raw(self) -> *mut c_char {
        let p = self.0;
        core::mem::forget(self);
        p
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.0.cast()) }
    }
}

const PAT_NONE: i32 = 0;
const PAT_SPECIAL: i32 = 1;
const PAT_BACKSLASH: i32 = 2;
const PAT_BRACKET: i32 = 4;

unsafe fn pattern_type(pattern: *const c_char, quote: bool) -> i32 {
    unsafe {
        let mut ret = PAT_NONE;
        let mut p = pattern as *const u8;
        while *p != 0 {
            match *p {
                b'?' | b'*' => return PAT_SPECIAL,
                b'\\' if quote => {
                    if *p.add(1) != 0 {
                        p = p.add(1);
                    }
                    ret |= PAT_BACKSLASH;
                }
                b'[' => ret |= PAT_BRACKET,
                b']' if ret & 4 != 0 => return PAT_SPECIAL,
                _ => {}
            }
            p = p.add(1);
        }
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob_pattern_p(pattern: *const c_char, quote: c_int) -> c_int {
    unsafe { (pattern_type(pattern, quote != 0) == PAT_SPECIAL) as c_int }
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

unsafe fn fstatat(dirfd: usize, path: *const c_char, st: &mut StatBuf, flags: usize) -> Result<(), i32> {
    unsafe {
        let r = syscall::syscall4(SYS_NEWFSTATAT, dirfd, path as usize, st.as_mut_ptr() as usize, flags);
        match syscall::check(r) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.0),
        }
    }
}

unsafe fn glob_lstat(pglob: *mut Glob, flags: c_int, fullname: *const c_char) -> Result<(), i32> {
    unsafe {
        let mut st: StatBuf = [0; 18];
        let compat = STAT_FOR_LSTAT.get();
        if flags & GLOB_ALTDIRFUNC != 0 {
            let f = if compat { (*pglob).gl_stat } else { (*pglob).gl_lstat };
            let r = f.map_or(-1, |f| f(fullname, st.as_mut_ptr().cast()));
            if r == 0 { Ok(()) } else { Err(errno::get()) }
        } else {
            fstatat(AT_FDCWD, fullname, &mut st, AT_SYMLINK_NOFOLLOW)
        }
    }
}

#[thread_local]
static STAT_FOR_LSTAT: core::cell::Cell<bool> = core::cell::Cell::new(false);

pub unsafe fn glob_compat(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe {
        let saved = STAT_FOR_LSTAT.replace(true);
        let r = glob_run(pattern, flags, errfunc, pglob);
        STAT_FOR_LSTAT.set(saved);
        r
    }
}

unsafe fn is_dir(filename: *const c_char, flags: c_int, pglob: *const Glob) -> bool {
    unsafe {
        let mut st: StatBuf = [0; 18];
        if flags & GLOB_ALTDIRFUNC != 0 {
            let r = (*pglob).gl_stat.map_or(-1, |f| f(filename, st.as_mut_ptr().cast()));
            r == 0 && stat_mode(&st) & S_IFMT == S_IFDIR
        } else {
            fstatat(AT_FDCWD, filename, &mut st, 0).is_ok() && stat_mode(&st) & S_IFMT == S_IFDIR
        }
    }
}

struct Dir {
    fd: c_int,
    buf: *mut u8,
    pos: usize,
    len: usize,
}

const DIR_BUF: usize = 32768;

const O_RDONLY_DIR_CLOEXEC: usize = 0o2000000 | 0o200000 | 0o4000;

impl Dir {
    unsafe fn open(path: *const c_char) -> Result<Dir, i32> {
        unsafe {
            let r = syscall::syscall3(syscall::SYS_OPEN, path as usize, O_RDONLY_DIR_CLOEXEC, 0);
            match syscall::check(r) {
                Ok(fd) => {
                    let buf = rusty_libc_malloc::malloc(DIR_BUF) as *mut u8;
                    if buf.is_null() {
                        syscall::syscall1(syscall::SYS_CLOSE, fd);
                        return Err(ENOMEM);
                    }
                    Ok(Dir { fd: fd as c_int, buf, pos: 0, len: 0 })
                }
                Err(e) => Err(e.0),
            }
        }
    }
    unsafe fn next(&mut self) -> Option<(*const c_char, u8)> {
        unsafe {
            loop {
                if self.pos >= self.len {
                    let r = syscall::syscall3(SYS_GETDENTS64, self.fd as usize, self.buf as usize, DIR_BUF);
                    match syscall::check(r) {
                        Ok(0) => return None,
                        Ok(n) => {
                            self.len = n;
                            self.pos = 0;
                        }
                        Err(e) => {
                            errno::set(e.0);
                            return None;
                        }
                    }
                }
                let rec = self.buf.add(self.pos) as *const u8;
                let ino = u64::from_le_bytes(*(rec as *const [u8; 8]));
                let reclen = u16::from_le_bytes(*(rec.add(16) as *const [u8; 2])) as usize;
                let d_type = *rec.add(18);
                self.pos += reclen;
                if ino == 0 {
                    continue;
                }
                return Some((rec.add(19) as *const c_char, d_type));
            }
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let save = errno::get();
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, self.fd as usize);
            rusty_libc_malloc::free(self.buf.cast());
        }
        errno::set(save);
    }
}

unsafe fn next_brace_sub(mut cp: *const c_char, flags: c_int) -> *const c_char {
    unsafe {
        let mut depth = 0usize;
        while byte(cp, 0) != 0 {
            if flags & GLOB_NOESCAPE == 0 && byte(cp, 0) == b'\\' {
                cp = cp.add(1);
                if byte(cp, 0) == 0 {
                    break;
                }
                cp = cp.add(1);
            } else {
                if (byte(cp, 0) == b'}' && depth == 0) || (byte(cp, 0) == b',' && depth == 0) {
                    break;
                }
                if byte(cp, 0) == b'}' {
                    depth = depth.wrapping_sub(1);
                }
                let c = byte(cp, 0);
                cp = cp.add(1);
                if c == b'{' {
                    depth += 1;
                }
            }
        }
        if byte(cp, 0) != 0 { cp } else { core::ptr::null() }
    }
}

unsafe fn prefix_array(dirname: *const c_char, array: *mut *mut c_char, n: usize) -> bool {
    unsafe {
        let mut dirlen = slen(dirname);
        if dirlen == 1 && byte(dirname, 0) == b'/' {
            dirlen = 0;
        }
        for i in 0..n {
            let elt = *array.add(i);
            let eltlen = slen(elt) + 1;
            let new = rusty_libc_malloc::malloc(dirlen + 1 + eltlen) as *mut c_char;
            if new.is_null() {
                let mut j = i;
                while j > 0 {
                    j -= 1;
                    rusty_libc_malloc::free((*array.add(j)).cast());
                }
                return true;
            }
            core::ptr::copy_nonoverlapping(dirname, new, dirlen);
            *new.add(dirlen) = b'/' as c_char;
            core::ptr::copy_nonoverlapping(elt, new.add(dirlen + 1), eltlen);
            rusty_libc_malloc::free(elt.cast());
            *array.add(i) = new;
        }
        false
    }
}

unsafe extern "C" fn collated_compare(a: *const c_void, b: *const c_void) -> c_int {
    unsafe {
        let s1 = *(a as *const *const c_char);
        let s2 = *(b as *const *const c_char);
        if s1 == s2 {
            return 0;
        }
        if s1.is_null() {
            return 1;
        }
        if s2.is_null() {
            return -1;
        }
        rusty_libc_mem::strcmp(s1.cast(), s2.cast())
    }
}

struct Names {
    items: *mut *mut c_char,
    len: usize,
    cap: usize,
}

impl Names {
    fn new() -> Names {
        Names { items: null_mut(), len: 0, cap: 0 }
    }
    unsafe fn push(&mut self, s: *mut c_char) -> bool {
        unsafe {
            if self.len == self.cap {
                let ncap = if self.cap == 0 { 64 } else { self.cap * 2 };
                let np = rusty_libc_malloc::realloc(self.items.cast(), ncap * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
                if np.is_null() {
                    return false;
                }
                self.items = np;
                self.cap = ncap;
            }
            *self.items.add(self.len) = s;
            self.len += 1;
            true
        }
    }
    unsafe fn free_all(&mut self) {
        unsafe {
            for i in 0..self.len {
                rusty_libc_malloc::free((*self.items.add(i)).cast());
            }
            rusty_libc_malloc::free(self.items.cast());
            self.items = null_mut();
            self.len = 0;
        }
    }
}

unsafe fn glob_in_dir(pattern: *const c_char, directory: *const c_char, mut flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe {
        let dirlen = slen(directory);
        let mut names = Names::new();
        let meta = pattern_type(pattern, flags & GLOB_NOESCAPE == 0);
        let mut alt_stream: *mut c_void = null_mut();
        let mut own_dir: Option<Dir> = None;
        let mut opened = false;
        if meta == PAT_NONE && flags & (GLOB_NOCHECK | GLOB_NOMAGIC) != 0 {
            flags |= GLOB_NOCHECK;
        } else if meta == PAT_NONE {
            let patlen = slen(pattern);
            let fullname = rusty_libc_malloc::malloc(dirlen + 1 + patlen + 1) as *mut c_char;
            if fullname.is_null() {
                return GLOB_NOSPACE;
            }
            core::ptr::copy_nonoverlapping(directory, fullname, dirlen);
            *fullname.add(dirlen) = b'/' as c_char;
            core::ptr::copy_nonoverlapping(pattern, fullname.add(dirlen + 1), patlen + 1);
            let r = glob_lstat(pglob, flags, fullname);
            let e = errno::get();
            rusty_libc_malloc::free(fullname.cast());
            if r.is_ok() || (r.is_err() && e == EOVERFLOW) {
                flags |= GLOB_NOCHECK;
            }
        } else {
            let alt = flags & GLOB_ALTDIRFUNC != 0;
            let mut failed: Option<i32> = None;
            if alt {
                alt_stream = (*pglob).gl_opendir.map_or(null_mut(), |f| f(directory));
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
                if e != ENOTDIR && (errfunc.is_some_and(|f| f(directory, e) != 0) || flags & GLOB_ERR != 0) {
                    return GLOB_ABORTED;
                }
            } else {
                opened = true;
                let fnm_flags = (if flags & GLOB_PERIOD == 0 { FNM_PERIOD } else { 0 }) | (if flags & GLOB_NOESCAPE != 0 { FNM_NOESCAPE } else { 0 });
                flags |= GLOB_MAGCHAR;
                loop {
                    let (name, d_type): (*const c_char, u8) = if alt {
                        let d = (*pglob).gl_readdir.map_or(null_mut(), |f| f(alt_stream));
                        if d.is_null() {
                            break;
                        }
                        ((*d).d_name.as_ptr(), (*d).d_type)
                    } else {
                        match own_dir.as_mut().unwrap().next() {
                            Some(x) => x,
                            None => break,
                        }
                    };
                    if flags & GLOB_ONLYDIR != 0 {
                        match d_type {
                            DT_DIR => {}
                            DT_LNK | DT_UNKNOWN => {
                                if alt || own_dir.as_ref().is_none() {
                                    let namelen = slen(name);
                                    let need = dirlen + 1 + namelen + 1;
                                    let s = rusty_libc_malloc::malloc(need) as *mut c_char;
                                    if s.is_null() {
                                        names.free_all();
                                        return GLOB_NOSPACE;
                                    }
                                    core::ptr::copy_nonoverlapping(directory, s, dirlen);
                                    *s.add(dirlen) = b'/' as c_char;
                                    let p = if dirlen > 0 && byte(s, dirlen - 1) == b'/' { dirlen } else { dirlen + 1 };
                                    core::ptr::copy_nonoverlapping(name, s.add(p), namelen + 1);
                                    let d = is_dir(s, flags, pglob);
                                    rusty_libc_malloc::free(s.cast());
                                    if !d {
                                        continue;
                                    }
                                } else {
                                    let dfd = own_dir.as_ref().unwrap().fd as usize;
                                    let mut st: StatBuf = [0; 18];
                                    if !(fstatat(dfd, name, &mut st, 0).is_ok() && stat_mode(&st) & S_IFMT == S_IFDIR) {
                                        continue;
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                    if fnmatch(pattern, name, fnm_flags) == 0 {
                        let Some(copy) = Owned::dup(name) else {
                            names.free_all();
                            return GLOB_NOSPACE;
                        };
                        if !names.push(copy.0) {
                            names.free_all();
                            return GLOB_NOSPACE;
                        }
                        core::mem::forget(copy);
                    }
                }
            }
        }

        if names.len == 0 && flags & GLOB_NOCHECK != 0 {
            let Some(copy) = Owned::dup(pattern) else {
                names.free_all();
                return GLOB_NOSPACE;
            };
            if !names.push(copy.0) {
                names.free_all();
                return GLOB_NOSPACE;
            }
            core::mem::forget(copy);
        }

        let mut result = GLOB_NOMATCH;
        if names.len != 0 {
            result = 0;
            let total = (*pglob).gl_pathc + (*pglob).gl_offs + names.len + 1;
            let new_pathv = rusty_libc_malloc::realloc((*pglob).gl_pathv.cast(), total * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
            if new_pathv.is_null() {
                names.free_all();
                result = GLOB_NOSPACE;
            } else {
                for i in 0..names.len {
                    *new_pathv.add((*pglob).gl_offs + (*pglob).gl_pathc) = *names.items.add(i);
                    (*pglob).gl_pathc += 1;
                }
                rusty_libc_malloc::free(names.items.cast());
                (*pglob).gl_pathv = new_pathv;
                *new_pathv.add((*pglob).gl_offs + (*pglob).gl_pathc) = null_mut();
                (*pglob).gl_flags = flags;
            }
        } else {
            rusty_libc_malloc::free(names.items.cast());
        }

        if opened && flags & GLOB_ALTDIRFUNC != 0 {
            let save = errno::get();
            if let Some(f) = (*pglob).gl_closedir {
                f(alt_stream);
            }
            errno::set(save);
        }
        let _ = own_dir;
        result
    }
}

unsafe fn glob_run(pattern: *const c_char, flags_in: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe {
        let mut flags = flags_in;
        if pattern.is_null() || pglob.is_null() || flags & !ALL_FLAGS != 0 {
            errno::set(EINVAL);
            return -1;
        }
        let patlen = slen(pattern);
        if patlen > 0 && byte(pattern, patlen - 1) == b'/' {
            flags |= GLOB_ONLYDIR;
        }
        if flags & GLOB_DOOFFS == 0 {
            (*pglob).gl_offs = 0;
        }
        if flags & GLOB_APPEND == 0 {
            (*pglob).gl_pathc = 0;
            if flags & GLOB_DOOFFS == 0 {
                (*pglob).gl_pathv = null_mut();
            } else {
                if (*pglob).gl_offs >= usize::MAX / core::mem::size_of::<*mut c_char>() {
                    return GLOB_NOSPACE;
                }
                let v = rusty_libc_malloc::malloc(((*pglob).gl_offs + 1) * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
                if v.is_null() {
                    return GLOB_NOSPACE;
                }
                for i in 0..=(*pglob).gl_offs {
                    *v.add(i) = null_mut();
                }
                (*pglob).gl_pathv = v;
            }
        }

        if flags & GLOB_BRACE != 0 {
            let mut begin: *const c_char = pattern;
            if flags & GLOB_NOESCAPE != 0 {
                begin = rusty_libc_mem::strchr(pattern.cast(), b'{' as c_int) as *const c_char;
            } else {
                loop {
                    if byte(begin, 0) == 0 {
                        begin = core::ptr::null();
                        break;
                    }
                    if byte(begin, 0) == b'\\' && byte(begin, 1) != 0 {
                        begin = begin.add(1);
                    } else if byte(begin, 0) == b'{' {
                        break;
                    }
                    begin = begin.add(1);
                }
            }
            if !begin.is_null() {
                let pattern_len = patlen - 1;
                let onealt = rusty_libc_malloc::malloc(pattern_len.max(1)) as *mut c_char;
                if onealt.is_null() {
                    return GLOB_NOSPACE;
                }
                let alt_start = onealt.add(begin as usize - pattern as usize);
                core::ptr::copy_nonoverlapping(pattern, onealt, begin as usize - pattern as usize);
                let mut next = next_brace_sub(begin.add(1), flags);
                let mut valid = !next.is_null();
                let mut rest = next;
                if valid {
                    while byte(rest, 0) != b'}' {
                        rest = next_brace_sub(rest.add(1), flags);
                        if rest.is_null() {
                            valid = false;
                            break;
                        }
                    }
                }
                if !valid {
                    rusty_libc_malloc::free(onealt.cast());
                    flags &= !GLOB_BRACE;
                } else {
                    rest = rest.add(1);
                    let rest_len = slen(rest) + 1;
                    let firstc = (*pglob).gl_pathc;
                    let mut p = begin.add(1);
                    loop {
                        let seg = next as usize - p as usize;
                        core::ptr::copy_nonoverlapping(p, alt_start, seg);
                        core::ptr::copy_nonoverlapping(rest, alt_start.add(seg), rest_len);
                        let result = glob_run(onealt, (flags & !(GLOB_NOCHECK | GLOB_NOMAGIC)) | GLOB_APPEND, errfunc, pglob);
                        if result != 0 && result != GLOB_NOMATCH {
                            rusty_libc_malloc::free(onealt.cast());
                            if flags & GLOB_APPEND == 0 {
                                globfree(pglob);
                                (*pglob).gl_pathc = 0;
                            }
                            return result;
                        }
                        if byte(next, 0) == b'}' {
                            break;
                        }
                        p = next.add(1);
                        next = next_brace_sub(p, flags);
                    }
                    rusty_libc_malloc::free(onealt.cast());
                    if (*pglob).gl_pathc != firstc {
                        return 0;
                    } else if flags & (GLOB_NOCHECK | GLOB_NOMAGIC) == 0 {
                        return GLOB_NOMATCH;
                    }
                }
            }
        }

        let mut oldcount = (*pglob).gl_pathc + (*pglob).gl_offs;
        let mut dirs = Glob::new();
        let mut retval = 0;
        let mut dirname_owned: Option<Owned> = None;
        let mut dirname: *const c_char;
        let mut dirlen: usize;
        let mut dirname_modified = false;
        let mut filename: *const c_char;

        let slash = rusty_libc_mem::strrchr(pattern.cast(), b'/' as c_int) as *const c_char;
        filename = slash;
        'out: {
            'to_d: {
                'nm: {
                    if filename.is_null() {
                        if flags & (GLOB_TILDE | GLOB_TILDE_CHECK) != 0 && byte(pattern, 0) == b'~' {
                            dirname = pattern;
                            dirlen = patlen;
                            filename = core::ptr::null();
                        } else {
                            if byte(pattern, 0) == 0 {
                                break 'nm;
                            }
                            filename = pattern;
                            dirname = c".".as_ptr();
                            dirlen = 0;
                        }
                    } else if filename == pattern || (filename == pattern.add(1) && byte(pattern, 0) == b'\\' && flags & GLOB_NOESCAPE == 0) {
                        dirname = c"/".as_ptr();
                        dirlen = 1;
                        filename = filename.add(1);
                    } else {
                        dirlen = filename as usize - pattern as usize;
                        let Some(newp) = Owned::copy(pattern, dirlen) else {
                            return GLOB_NOSPACE;
                        };
                        dirname = newp.0;
                        dirname_owned = Some(newp);
                        filename = filename.add(1);
                        if byte(filename, 0) == 0 && dirlen > 1 {
                            let orig_flags = flags;
                            let dn = dirname_owned.as_ref().unwrap().0;
                            if flags & GLOB_NOESCAPE == 0 && byte(dn, dirlen - 1) == b'\\' {
                                let mut p = dirlen - 1;
                                while p > 0 && byte(dn, p - 1) == b'\\' {
                                    p -= 1;
                                }
                                if (dirlen - p) & 1 != 0 {
                                    dirlen -= 1;
                                    *dn.add(dirlen) = 0;
                                    flags &= !(GLOB_NOCHECK | GLOB_NOMAGIC);
                                }
                            }
                            let mut p = dirlen - 1;
                            while p > 0 && byte(dn, p) == b'/' && byte(dn, p - 1) == b'/' {
                                *dn.add(p) = 0;
                                p -= 1;
                            }
                            let val = glob_run(dn, flags | GLOB_MARK, errfunc, pglob);
                            if val == 0 {
                                (*pglob).gl_flags = ((*pglob).gl_flags & !GLOB_MARK) | (flags & GLOB_MARK);
                            } else if val == GLOB_NOMATCH && flags != orig_flags {
                                dirs.gl_pathv = null_mut();
                                flags = orig_flags;
                                oldcount = (*pglob).gl_pathc + (*pglob).gl_offs;
                                break 'nm;
                            }
                            retval = val;
                            break 'out;
                        }
                    }

                    if flags & (GLOB_TILDE | GLOB_TILDE_CHECK) != 0 && byte(dirname, 0) == b'~' {
                        if byte(dirname, 1) == 0 || byte(dirname, 1) == b'/' || (flags & GLOB_NOESCAPE == 0 && byte(dirname, 1) == b'\\' && (byte(dirname, 2) == 0 || byte(dirname, 2) == b'/')) {
                            let mut home_owned: Option<Owned> = None;
                            let mut home_dir: *const c_char = rusty_libc_core::env::getenv(b"HOME") as *const c_char;
                            if home_dir.is_null() || byte(home_dir, 0) == 0 {
                                home_dir = core::ptr::null();
                                let mut name = [0u8; 4096];
                                let mut pwbuf = [0u8; 4096];
                                let mut err = crate::pwd::getlogin_r(name.as_mut_ptr().cast(), name.len());
                                if err == 0 {
                                    let mut pw: crate::pwd::Passwd = core::mem::zeroed();
                                    let mut pp: *mut crate::pwd::Passwd = null_mut();
                                    err = crate::pwd::getpwnam_r(name.as_ptr().cast(), &mut pw, pwbuf.as_mut_ptr().cast(), pwbuf.len(), &mut pp);
                                    if err == 0 && !pp.is_null() {
                                        match Owned::dup(pw.pw_dir) {
                                            Some(o) => {
                                                home_dir = o.0;
                                                home_owned = Some(o);
                                            }
                                            None => {
                                                retval = GLOB_NOSPACE;
                                                break 'out;
                                            }
                                        }
                                    }
                                }
                            }
                            if home_dir.is_null() || byte(home_dir, 0) == 0 {
                                if flags & GLOB_TILDE_CHECK != 0 {
                                    retval = GLOB_NOMATCH;
                                    break 'out;
                                }
                                home_dir = c"~".as_ptr();
                                home_owned = None;
                            }
                            if byte(dirname, 1) == 0 {
                                match home_owned.take() {
                                    Some(o) => {
                                        dirname_owned = Some(o);
                                        dirname = dirname_owned.as_ref().unwrap().0;
                                    }
                                    None => {
                                        let Some(c) = Owned::dup(home_dir) else {
                                            retval = GLOB_NOSPACE;
                                            break 'out;
                                        };
                                        dirname = c.0;
                                        dirname_owned = Some(c);
                                    }
                                }
                                dirlen = slen(dirname);
                            } else {
                                let home_len = slen(home_dir);
                                let newp = rusty_libc_malloc::malloc(home_len + dirlen + 1) as *mut c_char;
                                if newp.is_null() {
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                }
                                core::ptr::copy_nonoverlapping(home_dir, newp, home_len);
                                core::ptr::copy_nonoverlapping(dirname.add(1), newp.add(home_len), dirlen);
                                dirname_owned = Some(Owned(newp));
                                dirname = newp;
                                dirlen = dirlen + home_len - 1;
                            }
                            dirname_modified = true;
                        } else {
                            let mut end_name = rusty_libc_mem::strchr(dirname.cast(), b'/' as c_int) as *const c_char;
                            let mut unescape: *const c_char = core::ptr::null();
                            if flags & GLOB_NOESCAPE == 0 {
                                if end_name.is_null() {
                                    unescape = rusty_libc_mem::strchr(dirname.cast(), b'\\' as c_int) as *const c_char;
                                    if !unescape.is_null() {
                                        end_name = unescape.add(slen(unescape));
                                    }
                                } else {
                                    unescape = rusty_libc_mem::memchr(dirname.cast(), b'\\' as c_int, end_name as usize - dirname as usize) as *const c_char;
                                }
                            }
                            let user_owned: Option<Owned>;
                            let user_name: *const c_char;
                            if end_name.is_null() {
                                user_name = dirname.add(1);
                                user_owned = None;
                            } else {
                                let cap = end_name as usize - dirname as usize;
                                let newp = rusty_libc_malloc::malloc(cap + 1) as *mut c_char;
                                if newp.is_null() {
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                }
                                if !unescape.is_null() {
                                    let pre = unescape as usize - dirname as usize - 1;
                                    core::ptr::copy_nonoverlapping(dirname.add(1), newp, pre);
                                    let mut pw_ = pre;
                                    let mut q = unescape;
                                    while q != end_name {
                                        if byte(q, 0) == b'\\' {
                                            if q.add(1) == end_name {
                                                if filename.is_null() {
                                                    *newp.add(pw_) = b'\\' as c_char;
                                                    pw_ += 1;
                                                }
                                                break;
                                            }
                                            q = q.add(1);
                                        }
                                        *newp.add(pw_) = *q;
                                        pw_ += 1;
                                        q = q.add(1);
                                    }
                                    *newp.add(pw_) = 0;
                                } else {
                                    core::ptr::copy_nonoverlapping(dirname.add(1), newp, cap - 1);
                                    *newp.add(cap - 1) = 0;
                                }
                                user_name = newp;
                                user_owned = Some(Owned(newp));
                            }
                            let mut pw: crate::pwd::Passwd = core::mem::zeroed();
                            let mut pp: *mut crate::pwd::Passwd = null_mut();
                            let mut sz = 1024usize;
                            let mut pbuf = rusty_libc_malloc::malloc(sz) as *mut c_char;
                            loop {
                                if pbuf.is_null() {
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                }
                                if crate::pwd::getpwnam_r(user_name, &mut pw, pbuf, sz, &mut pp) != 34 {
                                    break;
                                }
                                sz *= 2;
                                pbuf = rusty_libc_malloc::realloc(pbuf.cast(), sz) as *mut c_char;
                            }
                            drop(user_owned);
                            if !pp.is_null() {
                                let home_len = slen(pw.pw_dir);
                                let rest_len = if end_name.is_null() { 0 } else { slen(end_name) };
                                let nd = rusty_libc_malloc::malloc(home_len + rest_len + 1) as *mut c_char;
                                if nd.is_null() {
                                    rusty_libc_malloc::free(pbuf.cast());
                                    retval = GLOB_NOSPACE;
                                    break 'out;
                                }
                                core::ptr::copy_nonoverlapping(pw.pw_dir, nd, home_len);
                                if !end_name.is_null() {
                                    core::ptr::copy_nonoverlapping(end_name, nd.add(home_len), rest_len);
                                }
                                *nd.add(home_len + rest_len) = 0;
                                rusty_libc_malloc::free(pbuf.cast());
                                dirname_owned = Some(Owned(nd));
                                dirname = nd;
                                dirlen = home_len + rest_len;
                                dirname_modified = true;
                            } else {
                                rusty_libc_malloc::free(pbuf.cast());
                                if flags & GLOB_TILDE_CHECK != 0 {
                                    retval = GLOB_NOMATCH;
                                    break 'out;
                                }
                            }
                        }
                    }

                    if filename.is_null() {
                        let newcount = (*pglob).gl_pathc + (*pglob).gl_offs;
                        let nv = rusty_libc_malloc::realloc((*pglob).gl_pathv.cast(), (newcount + 2) * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
                        if nv.is_null() {
                            rusty_libc_malloc::free((*pglob).gl_pathv.cast());
                            (*pglob).gl_pathv = null_mut();
                            (*pglob).gl_pathc = 0;
                            retval = GLOB_NOSPACE;
                            break 'out;
                        }
                        (*pglob).gl_pathv = nv;
                        if flags & GLOB_MARK != 0 && is_dir(dirname, flags, pglob) {
                            let s = rusty_libc_malloc::malloc(dirlen + 2) as *mut c_char;
                            if s.is_null() {
                                rusty_libc_malloc::free((*pglob).gl_pathv.cast());
                                (*pglob).gl_pathv = null_mut();
                                (*pglob).gl_pathc = 0;
                                retval = GLOB_NOSPACE;
                                break 'out;
                            }
                            core::ptr::copy_nonoverlapping(dirname, s, dirlen);
                            *s.add(dirlen) = b'/' as c_char;
                            *s.add(dirlen + 1) = 0;
                            *nv.add(newcount) = s;
                        } else {
                            let Some(c) = Owned::dup(dirname) else {
                                rusty_libc_malloc::free((*pglob).gl_pathv.cast());
                                (*pglob).gl_pathv = null_mut();
                                (*pglob).gl_pathc = 0;
                                retval = GLOB_NOSPACE;
                                break 'out;
                            };
                            *nv.add(newcount) = c.into_raw();
                        }
                        *nv.add(newcount + 1) = null_mut();
                        (*pglob).gl_pathc += 1;
                        (*pglob).gl_flags = flags;
                        return 0;
                    }

                    let meta = pattern_type(dirname, flags & GLOB_NOESCAPE == 0);
                    if meta & (PAT_SPECIAL | PAT_BRACKET) != 0 {
                        if flags & GLOB_NOESCAPE == 0 && dirlen > 0 && byte(dirname, dirlen - 1) == b'\\' {
                            let dn = match dirname_owned.as_ref() {
                                Some(o) => o.0,
                                None => dirname as *mut c_char,
                            };
                            let mut p = dirlen - 1;
                            while p > 0 && byte(dn, p - 1) == b'\\' {
                                p -= 1;
                            }
                            if (dirlen - p) & 1 != 0 {
                                dirlen -= 1;
                                *dn.add(dirlen) = 0;
                            }
                        }
                        if flags & GLOB_ALTDIRFUNC != 0 {
                            dirs.gl_opendir = (*pglob).gl_opendir;
                            dirs.gl_readdir = (*pglob).gl_readdir;
                            dirs.gl_closedir = (*pglob).gl_closedir;
                            dirs.gl_stat = (*pglob).gl_stat;
                            dirs.gl_lstat = (*pglob).gl_lstat;
                        }
                        let status = glob_run(dirname, (flags & (GLOB_ERR | GLOB_NOESCAPE | GLOB_ALTDIRFUNC)) | GLOB_NOSORT | GLOB_ONLYDIR, errfunc, &mut dirs);
                        if status != 0 {
                            if flags & GLOB_NOCHECK == 0 || status != GLOB_NOMATCH {
                                retval = status;
                                break 'out;
                            }
                            break 'nm;
                        }
                        for i in 0..dirs.gl_pathc {
                            let old_pathc = (*pglob).gl_pathc;
                            let status = glob_in_dir(filename, *dirs.gl_pathv.add(i), (flags | GLOB_APPEND) & !(GLOB_NOCHECK | GLOB_NOMAGIC), errfunc, pglob);
                            if status == GLOB_NOMATCH {
                                continue;
                            }
                            if status != 0 {
                                globfree(&mut dirs);
                                globfree(pglob);
                                (*pglob).gl_pathc = 0;
                                retval = status;
                                break 'out;
                            }
                            if prefix_array(*dirs.gl_pathv.add(i), (*pglob).gl_pathv.add(old_pathc + (*pglob).gl_offs), (*pglob).gl_pathc - old_pathc) {
                                globfree(&mut dirs);
                                globfree(pglob);
                                (*pglob).gl_pathc = 0;
                                retval = GLOB_NOSPACE;
                                break 'out;
                            }
                        }
                        flags |= GLOB_MAGCHAR;
                        if (*pglob).gl_pathc + (*pglob).gl_offs == oldcount {
                            break 'nm;
                        }
                        globfree(&mut dirs);
                        break 'to_d;
                    } else {
                        let old_pathc = (*pglob).gl_pathc;
                        let orig_flags = flags;
                        if meta & PAT_BACKSLASH != 0 {
                            let dn = match dirname_owned.as_ref() {
                                Some(o) => o.0,
                                None => {
                                    let Some(c) = Owned::dup(dirname) else {
                                        retval = GLOB_NOSPACE;
                                        break 'out;
                                    };
                                    let r = c.0;
                                    dirname_owned = Some(c);
                                    dirname = r;
                                    r
                                }
                            };
                            let mut p = rusty_libc_mem::strchr(dn.cast(), b'\\' as c_int) as *mut c_char;
                            let mut q = p;
                            loop {
                                if *p as u8 == b'\\' {
                                    p = p.add(1);
                                    *q = *p;
                                    dirlen -= 1;
                                } else {
                                    *q = *p;
                                }
                                q = q.add(1);
                                let last = *p == 0;
                                p = p.add(1);
                                if last {
                                    break;
                                }
                            }
                            dirname_modified = true;
                        }
                        if dirname_modified {
                            flags &= !(GLOB_NOCHECK | GLOB_NOMAGIC);
                        }
                        let status = glob_in_dir(filename, dirname, flags, errfunc, pglob);
                        if status != 0 {
                            if status == GLOB_NOMATCH && flags != orig_flags && (*pglob).gl_pathc + (*pglob).gl_offs == oldcount {
                                dirs.gl_pathv = null_mut();
                                flags = orig_flags;
                                break 'nm;
                            }
                            retval = status;
                            break 'out;
                        }
                        if dirlen > 0 && prefix_array(dirname, (*pglob).gl_pathv.add(old_pathc + (*pglob).gl_offs), (*pglob).gl_pathc - old_pathc) {
                            globfree(pglob);
                            (*pglob).gl_pathc = 0;
                            retval = GLOB_NOSPACE;
                            break 'out;
                        }
                        break 'to_d;
                    }
                }
                if flags & GLOB_NOCHECK != 0 {
                    let newcount = (*pglob).gl_pathc + (*pglob).gl_offs;
                    let nv = rusty_libc_malloc::realloc((*pglob).gl_pathv.cast(), (newcount + 2) * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
                    if nv.is_null() {
                        globfree(&mut dirs);
                        retval = GLOB_NOSPACE;
                        break 'out;
                    }
                    (*pglob).gl_pathv = nv;
                    let Some(c) = Owned::dup(pattern) else {
                        globfree(&mut dirs);
                        globfree(pglob);
                        (*pglob).gl_pathc = 0;
                        retval = GLOB_NOSPACE;
                        break 'out;
                    };
                    *nv.add(newcount) = c.into_raw();
                    (*pglob).gl_pathc += 1;
                    *nv.add(newcount + 1) = null_mut();
                    (*pglob).gl_flags = flags;
                } else {
                    globfree(&mut dirs);
                    retval = GLOB_NOMATCH;
                    break 'out;
                }
                globfree(&mut dirs);
            }
            if flags & GLOB_MARK != 0 {
                for i in oldcount..(*pglob).gl_pathc + (*pglob).gl_offs {
                    let s = *(*pglob).gl_pathv.add(i);
                    if is_dir(s, flags, pglob) {
                        let len = slen(s) + 2;
                        let ns = rusty_libc_malloc::realloc(s.cast(), len) as *mut c_char;
                        if ns.is_null() {
                            globfree(pglob);
                            (*pglob).gl_pathc = 0;
                            retval = GLOB_NOSPACE;
                            break 'out;
                        }
                        *ns.add(len - 2) = b'/' as c_char;
                        *ns.add(len - 1) = 0;
                        *(*pglob).gl_pathv.add(i) = ns;
                    }
                }
            }
            if flags & GLOB_NOSORT == 0 {
                rusty_libc_stdlib::sort::qsort((*pglob).gl_pathv.add(oldcount).cast(), (*pglob).gl_pathc + (*pglob).gl_offs - oldcount, core::mem::size_of::<*mut c_char>(), collated_compare);
            }
        }
        let _ = &dirname_owned;
        retval
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe { glob_run(pattern, flags, errfunc, pglob) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn glob64(pattern: *const c_char, flags: c_int, errfunc: Option<ErrFn>, pglob: *mut Glob) -> c_int {
    unsafe { glob_run(pattern, flags, errfunc, pglob) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn globfree(pglob: *mut Glob) {
    unsafe {
        if !(*pglob).gl_pathv.is_null() {
            for i in 0..(*pglob).gl_pathc {
                rusty_libc_malloc::free((*(*pglob).gl_pathv.add((*pglob).gl_offs + i)).cast());
            }
            rusty_libc_malloc::free((*pglob).gl_pathv.cast());
            (*pglob).gl_pathv = null_mut();
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn globfree64(pglob: *mut Glob) {
    unsafe { globfree(pglob) }
}
