use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::{errno, nssent, nssmod, syscall};
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

const O_RDONLY: usize = 0;
const O_CLOEXEC: usize = 0o2000000;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0o100;

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

pub(crate) trait Src {
    unsafe fn gets(&mut self, buf: *mut u8, n: usize) -> bool;
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
    pub(crate) unsafe fn open(path: *const u8) -> Result<FdStream, i32> {
        unsafe {
            let r = syscall::syscall3(syscall::SYS_OPEN, path as usize, O_RDONLY | O_CLOEXEC, 0);
            match syscall::check(r) {
                Ok(fd) => Ok(FdStream { fd: fd as c_int, buf: [0; 4096], pos: 0, len: 0, base: 0, eof: false }),
                Err(e) => Err(e.0),
            }
        }
    }
    pub(crate) fn close(&mut self) {
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, self.fd as usize);
        }
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
            let r = unsafe { syscall::syscall3(syscall::SYS_READ, self.fd as usize, self.buf.as_mut_ptr() as usize, self.buf.len()) };
            match syscall::check(r) {
                Ok(0) => {
                    self.eof = true;
                    return false;
                }
                Ok(n) => {
                    self.len = n;
                    return true;
                }
                Err(e) if e.0 == EINTR => {
                    self.base -= 0;
                    continue;
                }
                Err(e) => {
                    errno::set(e.0);
                    return false;
                }
            }
        }
    }
}

impl Src for FdStream {
    unsafe fn gets(&mut self, buf: *mut u8, n: usize) -> bool {
        unsafe {
            if n == 0 {
                return false;
            }
            let max = n - 1;
            let mut i = 0usize;
            while i < max {
                if self.pos >= self.len && !self.fill() {
                    break;
                }
                let avail = &self.buf[self.pos..self.len];
                let take = avail.len().min(max - i);
                let k = match avail[..take].iter().position(|&b| b == b'\n') {
                    Some(p) => p + 1,
                    None => take,
                };
                core::ptr::copy_nonoverlapping(avail.as_ptr(), buf.add(i), k);
                self.pos += k;
                i += k;
                if *buf.add(i - 1) == b'\n' {
                    break;
                }
            }
            if i == 0 {
                return false;
            }
            *buf.add(i) = 0;
            true
        }
    }
    fn at_eof(&self) -> bool {
        self.eof
    }
    fn tell(&mut self) -> i64 {
        self.base + self.pos as i64
    }
    fn seek(&mut self, off: i64) -> bool {
        let r = unsafe { syscall::syscall3(syscall::SYS_LSEEK, self.fd as usize, off as usize, 0) };
        if syscall::check(r).is_err() {
            return false;
        }
        self.base = off;
        self.pos = 0;
        self.len = 0;
        self.eof = false;
        true
    }
}

pub(crate) struct FileSrc(pub *mut File);

impl Src for FileSrc {
    unsafe fn gets(&mut self, buf: *mut u8, n: usize) -> bool {
        unsafe { !rusty_libc_stdio::fgets(buf.cast(), n as c_int, self.0).is_null() }
    }
    fn at_eof(&self) -> bool {
        unsafe { rusty_libc_stdio::feof(self.0) != 0 }
    }
    fn tell(&mut self) -> i64 {
        unsafe { rusty_libc_stdio::file::tell(self.0) }
    }
    fn seek(&mut self, off: i64) -> bool {
        unsafe { rusty_libc_stdio::file::seek(self.0, off, 0) == 0 }
    }
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

unsafe fn readline<S: Src>(s: &mut S, buf: *mut u8, len: usize, poffset: &mut i64) -> i32 {
    unsafe {
        if len < 3 {
            *poffset = -1;
            errno::set(ERANGE);
            return ERANGE;
        }
        loop {
            *poffset = s.tell();
            *buf.add(len - 1) = 0xff;
            if !s.gets(buf, len) {
                if s.at_eof() {
                    errno::set(ENOENT);
                    return ENOENT;
                }
                let e = errno::get();
                if e == ERANGE {
                    errno::set(EINVAL);
                }
                return errno::get();
            } else if *buf.add(len - 1) != 0xff {
                return readline_seek(s, *poffset);
            }
            let mut p = buf;
            while isspace(*p) {
                p = p.add(1);
            }
            if *p == 0 || *p == b'#' {
                continue;
            }
            if p != buf {
                let n = rusty_libc_mem::strlen(p.cast());
                core::ptr::copy(p, buf, n);
            }
            return 0;
        }
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

unsafe fn strtou32(line: *mut u8) -> (u32, *mut u8) {
    unsafe {
        let mut p = line;
        while isspace(*p) {
            p = p.add(1);
        }
        let mut neg = false;
        if *p == b'-' {
            neg = true;
            p = p.add(1);
        } else if *p == b'+' {
            p = p.add(1);
        }
        let start = p;
        let mut v: u64 = 0;
        let mut over = false;
        while (*p).is_ascii_digit() {
            let d = (*p - b'0') as u64;
            match v.checked_mul(10).and_then(|x| x.checked_add(d)) {
                Some(n) => v = n,
                None => over = true,
            }
            p = p.add(1);
        }
        if p == start {
            return (0, line);
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
}

unsafe fn string_field(line: &mut *mut u8) -> *mut u8 {
    unsafe {
        let var = *line;
        let mut l = *line;
        while *l != 0 && *l != b':' {
            l = l.add(1);
        }
        if *l != 0 {
            *l = 0;
            l = l.add(1);
        }
        *line = l;
        var
    }
}

unsafe fn int_field(line: &mut *mut u8, out: &mut u32) -> bool {
    unsafe {
        let (v, endp) = strtou32(*line);
        *out = v;
        if endp == *line {
            return false;
        }
        let mut e = endp;
        if *e == b':' {
            e = e.add(1);
        } else if *e != 0 {
            return false;
        }
        *line = e;
        true
    }
}

unsafe fn int_field_maybe_null(line: &mut *mut u8, out: &mut u32, default: u32) -> bool {
    unsafe {
        if **line == 0 {
            return false;
        }
        let (v, endp) = strtou32(*line);
        *out = if endp == *line { default } else { v };
        let mut e = endp;
        if *e == b':' {
            e = e.add(1);
        } else if *e != 0 {
            return false;
        }
        *line = e;
        true
    }
}

unsafe fn chop_newline(line: *mut u8) {
    unsafe {
        let mut p = line;
        while *p != 0 {
            if *p == b'\n' {
                *p = 0;
                return;
            }
            p = p.add(1);
        }
    }
}

pub(crate) trait Entry: Sized {
    const PATH: &'static [u8];
    unsafe fn parse(line: *mut u8, res: *mut Self, data: *mut u8, datalen: usize) -> i32;
}

impl Entry for Passwd {
    const PATH: &'static [u8] = b"/etc/passwd\0";
    unsafe fn parse(line: *mut u8, res: *mut Passwd, _data: *mut u8, _datalen: usize) -> i32 {
        unsafe {
            let mut line = line;
            chop_newline(line);
            let r = &mut *res;
            r.pw_name = string_field(&mut line).cast();
            let nis = matches!(*r.pw_name as u8, b'+' | b'-');
            if *line == 0 && nis {
                r.pw_passwd = null_mut();
                r.pw_uid = 0;
                r.pw_gid = 0;
                r.pw_gecos = null_mut();
                r.pw_dir = null_mut();
                r.pw_shell = null_mut();
            } else {
                r.pw_passwd = string_field(&mut line).cast();
                if nis {
                    if !int_field_maybe_null(&mut line, &mut r.pw_uid, 0) || !int_field_maybe_null(&mut line, &mut r.pw_gid, 0) {
                        return 0;
                    }
                } else if !int_field(&mut line, &mut r.pw_uid) || !int_field(&mut line, &mut r.pw_gid) {
                    return 0;
                }
                r.pw_gecos = string_field(&mut line).cast();
                r.pw_dir = string_field(&mut line).cast();
                r.pw_shell = line.cast();
            }
            1
        }
    }
}

impl Entry for Group {
    const PATH: &'static [u8] = b"/etc/group\0";
    unsafe fn parse(line: *mut u8, res: *mut Group, data: *mut u8, datalen: usize) -> i32 {
        unsafe {
            let buf_end = data.add(datalen);
            let buf_start: *mut u8 = if line >= data && line < buf_end { line.add(rusty_libc_mem::strlen(line.cast()) + 1) } else { data };
            let mut line = line;
            chop_newline(line);
            let r = &mut *res;
            r.gr_name = string_field(&mut line).cast();
            let nis = matches!(*r.gr_name as u8, b'+' | b'-');
            if *line == 0 && nis {
                r.gr_passwd = null_mut();
                r.gr_gid = 0;
            } else {
                r.gr_passwd = string_field(&mut line).cast();
                if nis {
                    if !int_field_maybe_null(&mut line, &mut r.gr_gid, 0) {
                        return 0;
                    }
                } else if !int_field(&mut line, &mut r.gr_gid) {
                    return 0;
                }
            }
            let list = parse_list(&mut line, buf_start, buf_end);
            if list.is_null() {
                errno::set(ERANGE);
                return -1;
            }
            r.gr_mem = list;
            1
        }
    }
}

unsafe fn parse_list(linep: &mut *mut u8, eol: *mut u8, buf_end: *mut u8) -> *mut *mut c_char {
    unsafe {
        let mut line = *linep;
        let mut e = eol as usize;
        e += 7;
        e -= e % 8;
        let list = e as *mut *mut c_char;
        let mut p = list;
        loop {
            if (p.add(2) as usize) > buf_end as usize {
                return null_mut();
            }
            if *line == 0 {
                break;
            }
            while isspace(*line) {
                line = line.add(1);
            }
            let elt = line;
            loop {
                if *line == 0 || *line == b',' {
                    if line > elt {
                        *p = elt.cast();
                        p = p.add(1);
                    }
                    if *line != 0 {
                        *line = 0;
                        line = line.add(1);
                    }
                    break;
                }
                line = line.add(1);
            }
        }
        *p = null_mut();
        *linep = line;
        list
    }
}

impl Entry for Spwd {
    const PATH: &'static [u8] = b"/etc/shadow\0";
    unsafe fn parse(line: *mut u8, res: *mut Spwd, _data: *mut u8, _datalen: usize) -> i32 {
        unsafe {
            let mut line = line;
            chop_newline(line);
            let r = &mut *res;
            r.sp_namp = string_field(&mut line).cast();
            let nis = matches!(*r.sp_namp as u8, b'+' | b'-');
            if *line == 0 && nis {
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
            r.sp_pwdp = string_field(&mut line).cast();
            let mut v = 0u32;
            macro_rules! sfield {
                ($dst:expr) => {{
                    if !int_field_maybe_null(&mut line, &mut v, u32::MAX) {
                        return 0;
                    }
                    $dst = i64::from(v as i32);
                }};
            }
            sfield!(r.sp_lstchg);
            sfield!(r.sp_min);
            sfield!(r.sp_max);
            while isspace(*line) {
                line = line.add(1);
            }
            if *line == 0 {
                r.sp_warn = -1;
                r.sp_inact = -1;
                r.sp_expire = -1;
                r.sp_flag = !0;
            } else {
                sfield!(r.sp_warn);
                sfield!(r.sp_inact);
                sfield!(r.sp_expire);
                if *line != 0 {
                    let (val, endp) = strtou32(line);
                    r.sp_flag = if endp == line { !0 } else { u64::from(val) };
                    if *endp != 0 {
                        return 0;
                    }
                    line = endp;
                } else {
                    r.sp_flag = !0;
                }
            }
            let _ = line;
            1
        }
    }
}

const ST_TRYAGAIN: i32 = -2;
const ST_UNAVAIL: i32 = -1;
const ST_NOTFOUND: i32 = 0;
const ST_SUCCESS: i32 = 1;

unsafe fn internal_getent<E: Entry, S: Src>(s: &mut S, result: *mut E, buffer: *mut u8, buflen: usize) -> i32 {
    unsafe {
        let saved = errno::get();
        if buflen < 2 {
            errno::set(ERANGE);
            return ST_TRYAGAIN;
        }
        loop {
            let mut off = 0i64;
            let mut ret = readline(s, buffer, buflen, &mut off);
            if ret == ENOENT {
                errno::set(saved);
                return ST_NOTFOUND;
            } else if ret == 0 {
                let pr = E::parse(buffer, result, buffer, buflen);
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
}

unsafe fn db_lookup<E: Entry>(result: *mut E, buffer: *mut u8, buflen: usize, matches: &dyn Fn(&E) -> bool) -> i32 {
    unsafe {
        let mut st = match FdStream::open(E::PATH.as_ptr()) {
            Ok(s) => s,
            Err(e) => {
                errno::set(e);
                return if e == EAGAIN { ST_TRYAGAIN } else { ST_UNAVAIL };
            }
        };
        let status = loop {
            let s = internal_getent::<E, _>(&mut st, result, buffer, buflen);
            if s != ST_SUCCESS {
                break s;
            }
            if matches(&*result) {
                break s;
            }
        };
        st.close();
        status
    }
}

fn nss_dispatch(db: &[u8], func: &[u8], files: &dyn Fn() -> i32, call: &dyn Fn(usize, *mut c_int) -> i32) -> i32 {
    nssent::dispatch(db, func, files, call, None)
}

unsafe fn copy_grp(src: &Group, buflen: usize, dest: *mut Group, destbuf: *mut u8, end: Option<&mut *mut u8>) -> c_int {
    unsafe {
        (*dest).gr_gid = src.gr_gid;
        let mut c = 0usize;
        let put = |s: *const u8, c: &mut usize| -> Option<*mut u8> {
            let len = rusty_libc_mem::strlen(s.cast()) + 1;
            if *c + len > buflen {
                return None;
            }
            core::ptr::copy_nonoverlapping(s, destbuf.add(*c), len);
            let p = destbuf.add(*c);
            *c += len;
            Some(p)
        };
        let Some(n) = put(src.gr_name.cast(), &mut c) else { return ERANGE };
        (*dest).gr_name = n.cast();
        let Some(pw) = put(src.gr_passwd.cast(), &mut c) else { return ERANGE };
        (*dest).gr_passwd = pw.cast();
        let mut memcount = 0usize;
        while !(*src.gr_mem.add(memcount)).is_null() {
            memcount += 1;
        }
        let members = rusty_libc_malloc::malloc(8 * (memcount + 1)) as *mut *mut u8;
        if members.is_null() {
            return ENOMEM;
        }
        for i in 0..memcount {
            match put((*src.gr_mem.add(i)).cast(), &mut c) {
                Some(p) => *members.add(i) = p,
                None => {
                    rusty_libc_malloc::free(members.cast());
                    return ERANGE;
                }
            }
        }
        *members.add(memcount) = null_mut();
        let mis = (destbuf as usize + c) & 7;
        if mis != 0 {
            c += 8 - mis;
        }
        (*dest).gr_mem = destbuf.add(c).cast();
        let len = 8 * (memcount + 1);
        if c + len > buflen {
            rusty_libc_malloc::free(members.cast());
            return ERANGE;
        }
        core::ptr::copy_nonoverlapping(members as *const u8, destbuf.add(c), len);
        c += len;
        rusty_libc_malloc::free(members.cast());
        if c + 8 > buflen {
            return ERANGE;
        }
        core::ptr::copy_nonoverlapping(&memcount as *const usize as *const u8, destbuf.add(c), 8);
        c += 8;
        if let Some(e) = end {
            *e = destbuf.add(c);
        }
        0
    }
}

unsafe fn merge_grp(saved: &mut Group, savedbuf: *mut u8, savedend: *mut u8, buflen: usize, merge: *mut Group, mergebuf: *mut u8) -> c_int {
    unsafe {
        if (*merge).gr_gid != saved.gr_gid || rusty_libc_mem::strcmp((*merge).gr_name.cast(), saved.gr_name.cast()) != 0 {
            return copy_grp(saved, buflen, merge, mergebuf, None);
        }
        let mut savedmemcount = 0usize;
        core::ptr::copy_nonoverlapping(savedend.sub(8), &mut savedmemcount as *mut usize as *mut u8, 8);
        let mut memcount = 0usize;
        while !(*(*merge).gr_mem.add(memcount)).is_null() {
            memcount += 1;
        }
        let membersize = savedmemcount + memcount + 1;
        let members = rusty_libc_malloc::malloc(8 * membersize) as *mut *mut u8;
        if members.is_null() {
            return ENOMEM;
        }
        core::ptr::copy_nonoverlapping(saved.gr_mem as *const *mut u8, members, savedmemcount);
        let mut c = savedend.offset_from(savedbuf) as usize - 8 - 8 * (savedmemcount + 1);
        for i in 0..memcount {
            let m = (*(*merge).gr_mem.add(i)) as *const u8;
            let len = rusty_libc_mem::strlen(m.cast()) + 1;
            if c + len > buflen {
                rusty_libc_malloc::free(members.cast());
                return ERANGE;
            }
            core::ptr::copy_nonoverlapping(m, savedbuf.add(c), len);
            *members.add(savedmemcount + i) = savedbuf.add(c);
            c += len;
        }
        *members.add(savedmemcount + memcount) = null_mut();
        let mis = (savedbuf as usize + c) & 7;
        if mis != 0 {
            c += 8 - mis;
        }
        saved.gr_mem = savedbuf.add(c).cast();
        let len = 8 * membersize;
        if c + len > buflen {
            rusty_libc_malloc::free(members.cast());
            return ERANGE;
        }
        core::ptr::copy_nonoverlapping(members as *const u8, savedbuf.add(c), len);
        rusty_libc_malloc::free(members.cast());
        copy_grp(saved, buflen, merge, mergebuf, None)
    }
}

struct GrMerge {
    res: *mut Group,
    buf: *mut u8,
    buflen: usize,
    saved_buf: *mut u8,
    saved: Group,
    end: *mut u8,
}

impl nssent::MergeOps for GrMerge {
    fn save(&mut self) -> i32 {
        unsafe {
            if self.saved_buf.is_null() {
                self.saved_buf = rusty_libc_malloc::malloc(self.buflen) as *mut u8;
                if self.saved_buf.is_null() {
                    return ENOMEM;
                }
            }
            copy_grp(&*self.res, self.buflen, &mut self.saved, self.saved_buf, Some(&mut self.end))
        }
    }
    fn merge(&mut self) -> i32 {
        unsafe { merge_grp(&mut self.saved, self.saved_buf, self.end, self.buflen, self.res, self.buf) }
    }
    fn restore(&mut self) -> i32 {
        unsafe { copy_grp(&self.saved, self.buflen, self.res, self.buf, None) }
    }
}

impl Drop for GrMerge {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.saved_buf.cast()) }
    }
}

impl GrMerge {
    fn new(res: *mut Group, buf: *mut u8, buflen: usize) -> GrMerge {
        GrMerge { res, buf, buflen, saved_buf: null_mut(), saved: Group { gr_name: null_mut(), gr_passwd: null_mut(), gr_gid: 0, gr_mem: null_mut() }, end: null_mut() }
    }
}

unsafe fn finish_r<E>(status: i32, resbuf: *mut E, result: *mut *mut E) -> c_int {
    unsafe {
        *result = if status == ST_SUCCESS { resbuf } else { null_mut() };
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
}

unsafe fn cstr_eq(a: *const c_char, b: *const c_char) -> bool {
    unsafe { rusty_libc_mem::strcmp(a.cast(), b.cast()) == 0 }
}

fn is_nis(p: *const c_char) -> bool {
    unsafe { !p.is_null() && matches!(*p as u8, b'+' | b'-') }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam_r(name: *const c_char, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    unsafe {
        let status = nss_dispatch(
            b"passwd",
            b"getpwnam_r",
            &|| db_lookup::<Passwd>(resbuf, buffer.cast(), buflen, &|r| !is_nis(name) && cstr_eq(name, r.pw_name)),
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut Passwd, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, resbuf, buffer, buflen, en)
            },
        );
        finish_r(status, resbuf, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid_r(uid: Uid, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    unsafe {
        let status = nss_dispatch(
            b"passwd",
            b"getpwuid_r",
            &|| db_lookup::<Passwd>(resbuf, buffer.cast(), buflen, &|r| r.pw_uid == uid && !is_nis(r.pw_name)),
            &|f, en| {
                let f: unsafe extern "C" fn(Uid, *mut Passwd, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(uid, resbuf, buffer, buflen, en)
            },
        );
        finish_r(status, resbuf, result)
    }
}

struct StaticBuf<E> {
    buf: *mut u8,
    size: usize,
    res: E,
}

const NSS_BUFLEN: usize = 1024;

static mut PWNAM: StaticBuf<Passwd> = StaticBuf { buf: null_mut(), size: 0, res: Passwd::zero() };
static mut PWUID: StaticBuf<Passwd> = StaticBuf { buf: null_mut(), size: 0, res: Passwd::zero() };
static mut GRNAM: StaticBuf<Group> = StaticBuf { buf: null_mut(), size: 0, res: Group::zero() };
static mut GRGID: StaticBuf<Group> = StaticBuf { buf: null_mut(), size: 0, res: Group::zero() };
static mut SPNAM: StaticBuf<Spwd> = StaticBuf { buf: null_mut(), size: 0, res: Spwd::zero() };
static mut PWENT: StaticBuf<Passwd> = StaticBuf { buf: null_mut(), size: 0, res: Passwd::zero() };
static mut GRENT: StaticBuf<Group> = StaticBuf { buf: null_mut(), size: 0, res: Group::zero() };
static mut SPENT: StaticBuf<Spwd> = StaticBuf { buf: null_mut(), size: 0, res: Spwd::zero() };
static mut FGETPW: StaticBuf<Passwd> = StaticBuf { buf: null_mut(), size: 0, res: Passwd::zero() };
static mut FGETGR: StaticBuf<Group> = StaticBuf { buf: null_mut(), size: 0, res: Group::zero() };
static mut FGETSP: StaticBuf<Spwd> = StaticBuf { buf: null_mut(), size: 0, res: Spwd::zero() };
static mut SGETSP: StaticBuf<Spwd> = StaticBuf { buf: null_mut(), size: 0, res: Spwd::zero() };

unsafe fn by_key<E>(sb: &mut StaticBuf<E>, mut call: impl FnMut(*mut E, *mut u8, usize, *mut *mut E) -> c_int) -> *mut E {
    unsafe {
        if sb.buf.is_null() {
            sb.size = NSS_BUFLEN;
            sb.buf = rusty_libc_malloc::malloc(sb.size) as *mut u8;
        }
        let mut result: *mut E = null_mut();
        while !sb.buf.is_null() && call(&raw mut sb.res, sb.buf, sb.size, &mut result) == ERANGE {
            sb.size *= 2;
            let nb = rusty_libc_malloc::realloc(sb.buf.cast(), sb.size) as *mut u8;
            if nb.is_null() {
                rusty_libc_malloc::free(sb.buf.cast());
                errno::set(ENOMEM);
            }
            sb.buf = nb;
        }
        if sb.buf.is_null() {
            result = null_mut();
        }
        result
    }
}

unsafe fn by_stream<E>(sb: &mut StaticBuf<E>, step_add: bool, mut call: impl FnMut(*mut E, *mut u8, usize, *mut *mut E) -> c_int) -> *mut E {
    unsafe {
        if sb.buf.is_null() {
            sb.size = NSS_BUFLEN;
            sb.buf = rusty_libc_malloc::malloc(sb.size) as *mut u8;
        }
        let mut result: *mut E = null_mut();
        while !sb.buf.is_null() && call(&raw mut sb.res, sb.buf, sb.size, &mut result) == ERANGE {
            sb.size = if step_add { sb.size + NSS_BUFLEN } else { sb.size * 2 };
            let nb = rusty_libc_malloc::realloc(sb.buf.cast(), sb.size) as *mut u8;
            if nb.is_null() {
                let save = errno::get();
                rusty_libc_malloc::free(sb.buf.cast());
                errno::set(save);
            }
            sb.buf = nb;
        }
        if sb.buf.is_null() {
            result = null_mut();
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    unsafe { by_key(&mut *(&raw mut PWNAM), |r, b, n, res| getpwnam_r(name, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid(uid: Uid) -> *mut Passwd {
    unsafe { by_key(&mut *(&raw mut PWUID), |r, b, n, res| getpwuid_r(uid, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpwent() {
    unsafe { db_setent::<Passwd>(&raw mut PW_DB, &PW_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    unsafe { db_endent::<Passwd>(&raw mut PW_DB, &PW_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent_r(resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    unsafe { db_getent_r::<Passwd>(&raw mut PW_DB, &PW_NAMES, resbuf, buffer.cast(), buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    unsafe { by_stream(&mut *(&raw mut PWENT), false, |r, b, n, res| getpwent_r(r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent_r(stream: *mut File, resbuf: *mut Passwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Passwd) -> c_int {
    unsafe { fget_r::<Passwd>(stream, resbuf, buffer, buflen, result) }
}

unsafe fn fget_r<E: Entry>(stream: *mut File, resbuf: *mut E, buffer: *mut c_char, buflen: usize, result: *mut *mut E) -> c_int {
    unsafe {
        let mut src = FileSrc(stream);
        let mut ret;
        loop {
            let mut off = 0i64;
            ret = readline(&mut src, buffer.cast(), buflen, &mut off);
            if ret == 0 {
                let pr = E::parse(buffer.cast(), resbuf, buffer.cast(), buflen);
                ret = parse_line_result(&mut src, off, pr);
                if ret == EINVAL {
                    continue;
                }
            }
            break;
        }
        *result = if ret == 0 { resbuf } else { null_mut() };
        ret
    }
}

unsafe fn fget<E: Entry>(stream: *mut File, sb: &mut StaticBuf<E>) -> *mut E {
    unsafe {
        let pos = rusty_libc_stdio::file::tell(stream);
        if pos < 0 {
            return null_mut();
        }
        by_stream(sb, true, |r, b, n, res| {
            let rc = fget_r::<E>(stream, r, b.cast(), n, res);
            if rc == ERANGE {
                rusty_libc_stdio::file::seek(stream, pos, 0);
            }
            rc
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent(stream: *mut File) -> *mut Passwd {
    unsafe { fget::<Passwd>(stream, &mut *(&raw mut FGETPW)) }
}

fn invalid_field_char(c: u8) -> bool {
    c == b':' || c == b'\n'
}

unsafe fn valid_field(p: *const c_char) -> bool {
    unsafe {
        if p.is_null() {
            return true;
        }
        let mut q = p as *const u8;
        while *q != 0 {
            if invalid_field_char(*q) {
                return false;
            }
            q = q.add(1);
        }
        true
    }
}

unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe {
        if p.is_null() { b"" } else { core::slice::from_raw_parts(p as *const u8, rusty_libc_mem::strlen(p.cast())) }
    }
}

struct Line {
    buf: *mut u8,
    len: usize,
    cap: usize,
    ok: bool,
}

impl Line {
    fn new() -> Line {
        Line { buf: null_mut(), len: 0, cap: 0, ok: true }
    }
    fn put(&mut self, b: &[u8]) {
        unsafe {
            if self.len + b.len() > self.cap {
                let ncap = (self.len + b.len()).max(self.cap * 2).max(128);
                let nb = rusty_libc_malloc::realloc(self.buf.cast(), ncap) as *mut u8;
                if nb.is_null() {
                    self.ok = false;
                    return;
                }
                self.buf = nb;
                self.cap = ncap;
            }
            core::ptr::copy_nonoverlapping(b.as_ptr(), self.buf.add(self.len), b.len());
            self.len += b.len();
        }
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
    unsafe fn write_to(&mut self, f: *mut File) -> bool {
        unsafe {
            let ok = self.ok && rusty_libc_stdio::file::write_bytes(f, self.buf, self.len) == self.len;
            rusty_libc_malloc::free(self.buf.cast());
            self.buf = null_mut();
            ok
        }
    }
}

unsafe fn put_rewritten(line: &mut Line, p: *const c_char) {
    unsafe {
        for &c in bytes(p) {
            line.put(&[if invalid_field_char(c) { b' ' } else { c }]);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putpwent(p: *const Passwd, stream: *mut File) -> c_int {
    unsafe {
        if p.is_null() || stream.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let p = &*p;
        if p.pw_name.is_null() || !valid_field(p.pw_name) || !valid_field(p.pw_passwd) || !valid_field(p.pw_dir) || !valid_field(p.pw_shell) {
            errno::set(EINVAL);
            return -1;
        }
        let mut l = Line::new();
        l.put(bytes(p.pw_name));
        l.put(b":");
        l.put(bytes(p.pw_passwd));
        if is_nis(p.pw_name) {
            l.put(b":::");
        } else {
            l.put(b":");
            l.num(p.pw_uid as i128);
            l.put(b":");
            l.num(p.pw_gid as i128);
            l.put(b":");
        }
        put_rewritten(&mut l, p.pw_gecos);
        l.put(b":");
        l.put(bytes(p.pw_dir));
        l.put(b":");
        l.put(bytes(p.pw_shell));
        l.put(b"\n");
        if l.write_to(stream) { 0 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpw(uid: Uid, buf: *mut c_char) -> c_int {
    unsafe {
        if buf.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let mut tmp = [0u8; 1024];
        let mut res = Passwd::zero();
        let mut p: *mut Passwd = null_mut();
        if getpwuid_r(uid, &mut res, tmp.as_mut_ptr().cast(), tmp.len(), &mut p) != 0 || p.is_null() {
            return -1;
        }
        let mut l = Line::new();
        l.put(bytes(res.pw_name));
        l.put(b":");
        l.put(bytes(res.pw_passwd));
        l.put(b":");
        l.num(res.pw_uid as i128);
        l.put(b":");
        l.num(res.pw_gid as i128);
        l.put(b":");
        l.put(bytes(res.pw_gecos));
        l.put(b":");
        l.put(bytes(res.pw_dir));
        l.put(b":");
        l.put(bytes(res.pw_shell));
        if !l.ok {
            return -1;
        }
        core::ptr::copy_nonoverlapping(l.buf, buf as *mut u8, l.len);
        *buf.add(l.len) = 0;
        rusty_libc_malloc::free(l.buf.cast());
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam_r(name: *const c_char, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    unsafe {
        let mut gm = GrMerge::new(resbuf, buffer.cast(), buflen);
        let status = nssent::dispatch(
            b"group",
            b"getgrnam_r",
            &|| db_lookup::<Group>(resbuf, buffer.cast(), buflen, &|r| !is_nis(name) && cstr_eq(name, r.gr_name)),
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut Group, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, resbuf, buffer, buflen, en)
            },
            Some(&mut gm),
        );
        finish_r(status, resbuf, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid_r(gid: Gid, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    unsafe {
        let mut gm = GrMerge::new(resbuf, buffer.cast(), buflen);
        let status = nssent::dispatch(
            b"group",
            b"getgrgid_r",
            &|| db_lookup::<Group>(resbuf, buffer.cast(), buflen, &|r| r.gr_gid == gid && !is_nis(r.gr_name)),
            &|f, en| {
                let f: unsafe extern "C" fn(Gid, *mut Group, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(gid, resbuf, buffer, buflen, en)
            },
            Some(&mut gm),
        );
        finish_r(status, resbuf, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    unsafe { by_key(&mut *(&raw mut GRNAM), |r, b, n, res| getgrnam_r(name, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid(gid: Gid) -> *mut Group {
    unsafe { by_key(&mut *(&raw mut GRGID), |r, b, n, res| getgrgid_r(gid, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setgrent() {
    unsafe { db_setent::<Group>(&raw mut GR_DB, &GR_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endgrent() {
    unsafe { db_endent::<Group>(&raw mut GR_DB, &GR_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent_r(resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    unsafe { db_getent_r::<Group>(&raw mut GR_DB, &GR_NAMES, resbuf, buffer.cast(), buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    unsafe { by_stream(&mut *(&raw mut GRENT), false, |r, b, n, res| getgrent_r(r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent_r(stream: *mut File, resbuf: *mut Group, buffer: *mut c_char, buflen: usize, result: *mut *mut Group) -> c_int {
    unsafe { fget_r::<Group>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent(stream: *mut File) -> *mut Group {
    unsafe { fget::<Group>(stream, &mut *(&raw mut FGETGR)) }
}

unsafe fn valid_list_field(list: *mut *mut c_char) -> bool {
    unsafe {
        if list.is_null() {
            return true;
        }
        let mut i = 0;
        while !(*list.add(i)).is_null() {
            let s = bytes(*list.add(i));
            if s.iter().any(|&c| invalid_field_char(c) || c == b',') {
                return false;
            }
            i += 1;
        }
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putgrent(gr: *const Group, stream: *mut File) -> c_int {
    unsafe {
        if gr.is_null() || stream.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let g = &*gr;
        if g.gr_name.is_null() || !valid_field(g.gr_name) || !valid_field(g.gr_passwd) || !valid_list_field(g.gr_mem) {
            errno::set(EINVAL);
            return -1;
        }
        let mut l = Line::new();
        l.put(bytes(g.gr_name));
        l.put(b":");
        l.put(bytes(g.gr_passwd));
        if is_nis(g.gr_name) {
            l.put(b"::");
        } else {
            l.put(b":");
            l.num(g.gr_gid as i128);
            l.put(b":");
        }
        if !g.gr_mem.is_null() {
            let mut i = 0;
            while !(*g.gr_mem.add(i)).is_null() {
                if i > 0 {
                    l.put(b",");
                }
                l.put(bytes(*g.gr_mem.add(i)));
                i += 1;
            }
        }
        l.put(b"\n");
        if l.write_to(stream) { 0 } else { -1 }
    }
}

unsafe fn getline_alloc(st: &mut FdStream, line: &mut *mut u8, cap: &mut usize) -> usize {
    unsafe {
        let mut n = 0usize;
        loop {
            if *cap < n + 2 {
                let nc = (*cap * 2).max(128);
                let nl = rusty_libc_malloc::realloc((*line).cast(), nc) as *mut u8;
                if nl.is_null() {
                    return usize::MAX;
                }
                *line = nl;
                *cap = nc;
            }
            if !st.gets((*line).add(n), *cap - n) {
                return n;
            }
            n += rusty_libc_mem::strlen((*line).add(n).cast());
            if n > 0 && *(*line).add(n - 1) == b'\n' {
                return n;
            }
        }
    }
}

unsafe fn files_groups(user: *const c_char, group: Gid, size: &mut i64, groups: &mut *mut Gid, limit: i64, start: &mut i64) {
    unsafe {
        if let Ok(mut st) = FdStream::open(Group::PATH.as_ptr()) {
            let mut tmp_len = 1024usize;
            let mut tmp = rusty_libc_malloc::malloc(tmp_len) as *mut u8;
            let mut line: *mut u8 = null_mut();
            let mut line_cap = 0usize;
            'lines: loop {
                let pos = st.tell();
                let mut n = getline_alloc(&mut st, &mut line, &mut line_cap);
                if n == 0 || n == usize::MAX {
                    break;
                }
                let mut grp = Group::zero();
                loop {
                    let res = Group::parse(line, &mut grp, tmp, tmp_len);
                    if res == -1 {
                        tmp_len *= 2;
                        let nt = rusty_libc_malloc::realloc(tmp.cast(), tmp_len) as *mut u8;
                        if nt.is_null() {
                            break 'lines;
                        }
                        tmp = nt;
                        st.seek(pos);
                        n = getline_alloc(&mut st, &mut line, &mut line_cap);
                        if n == 0 || n == usize::MAX {
                            break 'lines;
                        }
                        continue;
                    }
                    if res > 0 && grp.gr_gid != group {
                        let mut m = grp.gr_mem;
                        while !(*m).is_null() {
                            if cstr_eq(*m, user) {
                                if *start == *size {
                                    if limit > 0 && *size == limit {
                                        break 'lines;
                                    }
                                    let newsize = if limit <= 0 { 2 * *size } else { limit.min(2 * *size) };
                                    let ng = rusty_libc_malloc::realloc((*groups).cast(), newsize as usize * 4) as *mut Gid;
                                    if ng.is_null() {
                                        break 'lines;
                                    }
                                    *groups = ng;
                                    *size = newsize;
                                }
                                *(*groups).add(*start as usize) = grp.gr_gid;
                                *start += 1;
                                break;
                            }
                            m = m.add(1);
                        }
                    }
                    break;
                }
            }
            rusty_libc_malloc::free(line.cast());
            rusty_libc_malloc::free(tmp.cast());
            st.close();
        }
    }
}

unsafe fn dedupe_groups(groups: *mut Gid, start: &mut i64, prev_start: i64) {
    unsafe {
        let mut cnt = prev_start;
        while cnt < *start {
            let mut inner = 0;
            while inner < prev_start {
                if *groups.add(inner as usize) == *groups.add(cnt as usize) {
                    break;
                }
                inner += 1;
            }
            if inner < prev_start {
                *start -= 1;
                *groups.add(cnt as usize) = *groups.add(*start as usize);
            } else {
                cnt += 1;
            }
        }
    }
}

unsafe fn internal_getgrouplist(user: *const c_char, group: Gid, size: &mut i64, groups: &mut *mut Gid, limit: i64) -> i64 {
    unsafe {
        **groups = group;
        let mut start: i64 = 1;
        let order = nssmod::order(b"group");
        let mut prev_start: i64 = 1;
        for src in &order.e[..order.n] {
            let mut status = ST_UNAVAIL;
            if src.is(b"files") || src.is(b"compat") {
                files_groups(user, group, size, groups, limit, &mut start);
                status = ST_SUCCESS;
            } else if !src.is(b"dns") {
                let f = nssmod::function(src.name(), b"initgroups_dyn");
                if f == 0 {
                    if src.action(ST_UNAVAIL) != nssmod::ACT_CONTINUE {
                        break;
                    }
                    continue;
                }
                let f: unsafe extern "C" fn(*const c_char, Gid, *mut i64, *mut i64, *mut *mut Gid, i64, *mut c_int) -> c_int = core::mem::transmute(f);
                let mut e: c_int = 0;
                status = f(user, group, &mut start, size, groups, limit, &mut e);
                if !(-2..=1).contains(&status) {
                    status = ST_UNAVAIL;
                }
            }
            dedupe_groups(*groups, &mut start, prev_start);
            prev_start = start;
            if src.action(status) == nssmod::ACT_RETURN {
                break;
            }
        }
        start
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgrouplist(user: *const c_char, group: Gid, groups: *mut Gid, ngroups: *mut c_int) -> c_int {
    unsafe {
        let mut size = i64::from((*ngroups).max(1));
        let mut newgroups = rusty_libc_malloc::malloc(size as usize * 4) as *mut Gid;
        if newgroups.is_null() {
            return -1;
        }
        let total = internal_getgrouplist(user, group, &mut size, &mut newgroups, -1);
        let n = i64::from(*ngroups).min(total).max(0) as usize;
        core::ptr::copy_nonoverlapping(newgroups, groups, n);
        rusty_libc_malloc::free(newgroups.cast());
        let retval = if total > i64::from(*ngroups) { -1 } else { total as c_int };
        *ngroups = total as c_int;
        retval
    }
}

const SYS_SETGROUPS: usize = 116;
const NGROUPS_MAX: i64 = 65536;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: Gid) -> c_int {
    unsafe {
        let limit = NGROUPS_MAX;
        let mut size = limit.min(64);
        let mut groups = rusty_libc_malloc::malloc(size as usize * 4) as *mut Gid;
        if groups.is_null() {
            return -1;
        }
        let mut ngroups = internal_getgrouplist(user, group, &mut size, &mut groups, limit);
        let mut result;
        loop {
            let r = syscall::syscall2(SYS_SETGROUPS, ngroups as usize, groups as usize);
            match syscall::check(r) {
                Ok(_) => {
                    result = 0;
                    break;
                }
                Err(e) => {
                    errno::set(e.0);
                    result = -1;
                    if e.0 == EINVAL {
                        ngroups -= 1;
                        if ngroups > 0 {
                            continue;
                        }
                    }
                    break;
                }
            }
        }
        rusty_libc_malloc::free(groups.cast());
        let _ = &mut result;
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam_r(name: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    unsafe {
        let status = nss_dispatch(
            b"shadow",
            b"getspnam_r",
            &|| db_lookup::<Spwd>(resbuf, buffer.cast(), buflen, &|r| !is_nis(name) && cstr_eq(name, r.sp_namp)),
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut Spwd, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, resbuf, buffer, buflen, en)
            },
        );
        finish_r(status, resbuf, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut Spwd {
    unsafe { by_key(&mut *(&raw mut SPNAM), |r, b, n, res| getspnam_r(name, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setspent() {
    unsafe { db_setent::<Spwd>(&raw mut SP_DB, &SP_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endspent() {
    unsafe { db_endent::<Spwd>(&raw mut SP_DB, &SP_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent_r(resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    unsafe { db_getent_r::<Spwd>(&raw mut SP_DB, &SP_NAMES, resbuf, buffer.cast(), buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getspent() -> *mut Spwd {
    unsafe { by_stream(&mut *(&raw mut SPENT), false, |r, b, n, res| getspent_r(r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent_r(stream: *mut File, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    unsafe { fget_r::<Spwd>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent(stream: *mut File) -> *mut Spwd {
    unsafe { fget::<Spwd>(stream, &mut *(&raw mut FGETSP)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent_r(string: *const c_char, resbuf: *mut Spwd, buffer: *mut c_char, buflen: usize, result: *mut *mut Spwd) -> c_int {
    unsafe {
        *buffer.add(buflen - 1) = 0;
        let mut i = 0;
        while i < buflen {
            let c = *string.add(i);
            *buffer.add(i) = c;
            if c == 0 {
                for j in i + 1..buflen {
                    *buffer.add(j) = 0;
                }
                break;
            }
            i += 1;
        }
        if *buffer.add(buflen - 1) != 0 {
            return ERANGE;
        }
        let pr = Spwd::parse(buffer.cast(), resbuf, core::ptr::null_mut(), 0);
        *result = if pr > 0 { resbuf } else { null_mut() };
        if (*result).is_null() { errno::get() } else { 0 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent(string: *const c_char) -> *mut Spwd {
    unsafe { by_stream(&mut *(&raw mut SGETSP), true, |r, b, n, res| sgetspent_r(string, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putspent(p: *const Spwd, stream: *mut File) -> c_int {
    unsafe {
        let p = &*p;
        if p.sp_namp.is_null() || !valid_field(p.sp_namp) || !valid_field(p.sp_pwdp) {
            errno::set(EINVAL);
            return -1;
        }
        let mut l = Line::new();
        l.put(bytes(p.sp_namp));
        l.put(b":");
        l.put(bytes(p.sp_pwdp));
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
        if l.write_to(stream) { 0 } else { -1 }
    }
}

static mut LOCK_FD: c_int = -1;

extern "C" fn noop_handler(_sig: c_int) {}

#[unsafe(naked)]
unsafe extern "C" fn restore_rt() {
    core::arch::naked_asm!("mov eax, 15", "syscall");
}

const SYS_ALARM: usize = 37;
const SIGALRM: i32 = 14;
const F_SETLKW: usize = 7;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    unsafe {
        if LOCK_FD != -1 {
            return -1;
        }
        let path = b"/etc/.pwd.lock\0";
        let r = syscall::syscall3(syscall::SYS_OPEN, path.as_ptr() as usize, O_WRONLY | O_CREAT | O_CLOEXEC, 0o600);
        match syscall::check(r) {
            Ok(fd) => LOCK_FD = fd as c_int,
            Err(e) => {
                errno::set(e.0);
                return -1;
            }
        }
        let close_fd = |code: c_int| -> c_int {
            if code < 0 && LOCK_FD >= 0 {
                syscall::syscall1(syscall::SYS_CLOSE, LOCK_FD as usize);
                LOCK_FD = -1;
            }
            code
        };
        let new_act = rusty_libc_core::signal::KSigaction { handler: noop_handler as *const () as usize, flags: rusty_libc_core::signal::SA_RESTORER, restorer: restore_rt as *const () as usize, mask: !0 };
        let saved_act = match rusty_libc_core::signal::sigaction(SIGALRM, Some(&new_act)) {
            Ok(a) => a,
            Err(e) => {
                errno::set(e.0);
                return close_fd(-1);
            }
        };
        let saved_set = match rusty_libc_core::signal::sigprocmask(rusty_libc_core::signal::SIG_UNBLOCK, Some(rusty_libc_core::signal::bit(SIGALRM))) {
            Ok(s) => s,
            Err(e) => {
                errno::set(e.0);
                let _ = rusty_libc_core::signal::sigaction(SIGALRM, Some(&saved_act));
                return close_fd(-1);
            }
        };
        syscall::syscall1(SYS_ALARM, 15);
        let fl: [u64; 4] = [1 , 0, 0, 0];
        let r = syscall::syscall3(syscall::SYS_FCNTL, LOCK_FD as usize, F_SETLKW, fl.as_ptr() as usize);
        let result = match syscall::check(r) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        };
        syscall::syscall1(SYS_ALARM, 0);
        let _ = rusty_libc_core::signal::sigprocmask(rusty_libc_core::signal::SIG_SETMASK, Some(saved_set));
        let _ = rusty_libc_core::signal::sigaction(SIGALRM, Some(&saved_act));
        close_fd(result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    unsafe {
        if LOCK_FD == -1 {
            return -1;
        }
        let r = syscall::syscall1(syscall::SYS_CLOSE, LOCK_FD as usize);
        LOCK_FD = -1;
        match syscall::check(r) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        }
    }
}

const UT_NAMESIZE: usize = 32;
const UT_LINESIZE: usize = 32;
const UTMP_SIZE: usize = 384;
const NAME_MAX2: usize = 2 + 2 * 255;

unsafe fn getlogin_r_loginuid(name: *mut u8, namesize: usize) -> c_int {
    unsafe {
        let path = b"/proc/self/loginuid\0";
        let r = syscall::syscall3(syscall::SYS_OPEN, path.as_ptr() as usize, O_RDONLY | O_CLOEXEC, 0);
        let Ok(fd) = syscall::check(r) else { return -1 };
        let mut uidbuf = [0u8; 12];
        let n = loop {
            let r = syscall::syscall3(syscall::SYS_READ, fd, uidbuf.as_mut_ptr() as usize, uidbuf.len());
            match syscall::check(r) {
                Err(e) if e.0 == EINTR => continue,
                Err(_) => break -1isize,
                Ok(n) => break n as isize,
            }
        };
        syscall::syscall1(syscall::SYS_CLOSE, fd);
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
        let mut buflen = 1024usize;
        let mut heap: *mut u8 = null_mut();
        let mut pwd = Passwd::zero();
        let mut tp: *mut Passwd = null_mut();
        let mut bufp = tmp.as_mut_ptr();
        let res = loop {
            let res = getpwuid_r(uid, &mut pwd, bufp.cast(), buflen, &mut tp);
            if res != ERANGE {
                break res;
            }
            buflen *= 2;
            let nb = rusty_libc_malloc::realloc(heap.cast(), buflen) as *mut u8;
            if nb.is_null() {
                return ENOMEM;
            }
            heap = nb;
            bufp = nb;
        };
        let mut result = 0;
        if res != 0 || tp.is_null() {
            result = -1;
        } else {
            let needed = rusty_libc_mem::strlen(pwd.pw_name.cast()) + 1;
            if needed > namesize {
                errno::set(ERANGE);
                result = ERANGE;
            } else {
                core::ptr::copy_nonoverlapping(pwd.pw_name as *const u8, name, needed);
            }
        }
        rusty_libc_malloc::free(heap.cast());
        result
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

unsafe fn ttyname0(buf: *mut u8, len: usize) -> c_int {
    unsafe {
        let mut t = [0u8; 64];
        let r = syscall::syscall3(syscall::SYS_IOCTL, 0, 0x5401, t.as_mut_ptr() as usize);
        if let Err(e) = syscall::check(r) {
            return e.0;
        }
        let link = b"/proc/self/fd/0\0";
        let r = syscall::syscall3(89 , link.as_ptr() as usize, buf as usize, len);
        match syscall::check(r) {
            Err(e) => e.0,
            Ok(n) if n >= len => ERANGE,
            Ok(n) => {
                *buf.add(n) = 0;
                let s = core::slice::from_raw_parts(buf, n);
                if s.first() != Some(&b'/') {
                    return ENOENT;
                }
                if s.ends_with(b" (deleted)") {
                    *buf.add(n - 10) = 0;
                }
                0
            }
        }
    }
}

fn utmp_is_login(t: i16) -> bool {
    matches!(t, 5..=7)
}

pub(crate) unsafe fn utmp_user_for_line(path: *const u8, line: &[u8], name: *mut u8, namesize: usize) -> c_int {
    unsafe {
        let r = syscall::syscall3(syscall::SYS_OPEN, path as usize, O_RDONLY | O_CLOEXEC, 0);
        let fd = match syscall::check(r) {
            Ok(fd) => fd,
            Err(e) => return e.0,
        };
        let mut rec = [0u8; UTMP_SIZE];
        let mut found = ENOENT;
        'recs: loop {
            let mut got = 0;
            while got < UTMP_SIZE {
                let r = syscall::syscall3(syscall::SYS_READ, fd, rec.as_mut_ptr().add(got) as usize, UTMP_SIZE - got);
                match syscall::check(r) {
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
            let cmp_len = UT_LINESIZE;
            let mut a = [0u8; UT_LINESIZE];
            a[..want.len()].copy_from_slice(want);
            let mut eq = true;
            for i in 0..cmp_len {
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
            if ulen + 1 > namesize {
                errno::set(ERANGE);
                found = ERANGE;
            } else {
                core::ptr::copy_nonoverlapping(user.as_ptr(), name, ulen);
                *name.add(ulen) = 0;
                found = 0;
            }
            break;
        }
        syscall::syscall1(syscall::SYS_CLOSE, fd);
        found
    }
}

unsafe fn getlogin_r_fd0(name: *mut u8, namesize: usize) -> c_int {
    unsafe {
        let mut tty = [0u8; NAME_MAX2 + 1];
        let r = ttyname0(tty.as_mut_ptr(), tty.len());
        if r != 0 {
            return r;
        }
        let path = &tty[..tty.iter().position(|&b| b == 0).unwrap_or(tty.len())];
        let line = if path.starts_with(b"/dev/") { &path[5..] } else { &path[5.min(path.len())..] };
        utmp_user_for_line(c"/var/run/utmp".as_ptr().cast(), line, name, namesize)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin_r(name: *mut c_char, namesize: usize) -> c_int {
    unsafe {
        let res = getlogin_r_loginuid(name.cast(), namesize);
        if res >= 0 {
            return res;
        }
        getlogin_r_fd0(name.cast(), namesize)
    }
}

static mut LOGIN_NAME: [u8; UT_NAMESIZE + 1] = [0; UT_NAMESIZE + 1];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    unsafe {
        let name = (&raw mut LOGIN_NAME) as *mut u8;
        let res = getlogin_r_loginuid(name, UT_NAMESIZE + 1);
        if res >= 0 {
            return if res == 0 { name.cast() } else { null_mut() };
        }
        let r = getlogin_r_fd0(name, UT_NAMESIZE + 1);
        if r != 0 {
            errno::set(r);
            return null_mut();
        }
        name.cast()
    }
}

pub const L_CUSERID: usize = 9;
static mut CUSERID_NAME: [u8; L_CUSERID] = [0; L_CUSERID];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cuserid(string: *mut c_char) -> *mut c_char {
    unsafe {
        let string: *mut u8 = if string.is_null() { (&raw mut CUSERID_NAME) as *mut u8 } else { string.cast() };
        let euid = rusty_libc_core::syscall::syscall0(107) as Uid;
        let mut pwent = core::mem::MaybeUninit::<Passwd>::uninit();
        let mut buf = [0u8; 1024];
        let mut res: *mut Passwd = null_mut();
        if getpwuid_r(euid, pwent.as_mut_ptr(), buf.as_mut_ptr().cast(), buf.len(), &mut res) != 0 || res.is_null() {
            *string = 0;
            return null_mut();
        }
        let name = (*res).pw_name as *const u8;
        let mut i = 0;
        while i < L_CUSERID && *name.add(i) != 0 {
            *string.add(i) = *name.add(i);
            i += 1;
        }
        while i < L_CUSERID {
            *string.add(i) = 0;
            i += 1;
        }
        string.cast()
    }
}

static mut CURSHELL: *mut *mut c_char = null_mut();
static mut SHELLS: *mut *mut c_char = null_mut();
static mut STRINGS: *mut u8 = null_mut();
static mut OKSHELLS: [*mut c_char; 3] = [null_mut(); 3];

unsafe fn initshells() -> *mut *mut c_char {
    unsafe {
        rusty_libc_malloc::free(SHELLS.cast());
        SHELLS = null_mut();
        rusty_libc_malloc::free(STRINGS.cast());
        STRINGS = null_mut();
        let ok = || {
            OKSHELLS[0] = c"/bin/sh".as_ptr() as *mut c_char;
            OKSHELLS[1] = c"/bin/csh".as_ptr() as *mut c_char;
            OKSHELLS[2] = null_mut();
            (&raw mut OKSHELLS) as *mut *mut c_char
        };
        let r = syscall::syscall3(syscall::SYS_OPEN, c"/etc/shells".as_ptr() as usize, O_RDONLY | O_CLOEXEC, 0);
        let Ok(fd) = syscall::check(r) else { return ok() };
        let mut st = [0u64; 18];
        let r = syscall::syscall2(syscall::SYS_FSTAT, fd, st.as_mut_ptr() as usize);
        if syscall::check(r).is_err() {
            syscall::syscall1(syscall::SYS_CLOSE, fd);
            return ok();
        }
        let size = st[6] as usize;
        let flen = size + 3;
        STRINGS = rusty_libc_malloc::malloc(flen) as *mut u8;
        if STRINGS.is_null() {
            syscall::syscall1(syscall::SYS_CLOSE, fd);
            return ok();
        }
        SHELLS = rusty_libc_malloc::malloc((size / 3).max(1) * core::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
        if SHELLS.is_null() {
            rusty_libc_malloc::free(STRINGS.cast());
            STRINGS = null_mut();
            syscall::syscall1(syscall::SYS_CLOSE, fd);
            return ok();
        }
        let mut data = rusty_libc_malloc::malloc(size + 1) as *mut u8;
        let mut have = 0usize;
        loop {
            if have == size {
                data = rusty_libc_malloc::realloc(data.cast(), have + 4096) as *mut u8;
            }
            let cap = if have == size { 4096 } else { size - have };
            let r = syscall::syscall3(syscall::SYS_READ, fd, data.add(have) as usize, cap);
            match syscall::check(r) {
                Ok(0) => break,
                Ok(n) => have += n,
                Err(e) if e.0 == EINTR => {}
                Err(_) => break,
            }
        }
        syscall::syscall1(syscall::SYS_CLOSE, fd);
        let mut sp = SHELLS;
        let mut cp = STRINGS;
        let mut pos = 0usize;
        while pos < have {
            let room = flen - (cp as usize - STRINGS as usize);
            if room < 2 {
                break;
            }
            let mut n = 0usize;
            while pos + n < have && n < room - 1 {
                let b = *data.add(pos + n);
                *cp.add(n) = b;
                n += 1;
                if b == b'\n' {
                    break;
                }
            }
            *cp.add(n) = 0;
            pos += n;
            while *cp != b'#' && *cp != b'/' && *cp != 0 {
                cp = cp.add(1);
            }
            if *cp == b'#' || *cp == 0 || *cp.add(1) == 0 {
                continue;
            }
            *sp = cp.cast();
            sp = sp.add(1);
            while !isspace(*cp) && *cp != b'#' && *cp != 0 {
                cp = cp.add(1);
            }
            *cp = 0;
            cp = cp.add(1);
        }
        *sp = null_mut();
        rusty_libc_malloc::free(data.cast());
        SHELLS
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getusershell() -> *mut c_char {
    unsafe {
        if CURSHELL.is_null() {
            CURSHELL = initshells();
        }
        let ret = *CURSHELL;
        if !ret.is_null() {
            CURSHELL = CURSHELL.add(1);
        }
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endusershell() {
    unsafe {
        rusty_libc_malloc::free(SHELLS.cast());
        SHELLS = null_mut();
        rusty_libc_malloc::free(STRINGS.cast());
        STRINGS = null_mut();
        CURSHELL = null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setusershell() {
    unsafe {
        CURSHELL = initshells();
    }
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
    members: *mut *mut c_char,
    _buf: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> GroupRef<'a> {
    pub fn members(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        let mut i = 0usize;
        core::iter::from_fn(move || unsafe {
            if self.members.is_null() || (*self.members.add(i)).is_null() {
                None
            } else {
                let s = bytes(*self.members.add(i));
                i += 1;
                Some(s)
            }
        })
    }
}

unsafe fn pwref<'a>(p: &Passwd) -> PasswdRef<'a> {
    unsafe {
        PasswdRef { name: bytes(p.pw_name), passwd: bytes(p.pw_passwd), uid: p.pw_uid, gid: p.pw_gid, gecos: bytes(p.pw_gecos), dir: bytes(p.pw_dir), shell: bytes(p.pw_shell) }
    }
}

pub fn getpwnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<PasswdRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    if name.len() >= cname.len() || name.contains(&0) {
        return Ok(None);
    }
    cname[..name.len()].copy_from_slice(name);
    unsafe {
        let mut res = Passwd::zero();
        let mut out: *mut Passwd = null_mut();
        let rc = getpwnam_r(cname.as_ptr().cast(), &mut res, buf.as_mut_ptr().cast(), buf.len(), &mut out);
        if rc != 0 {
            Err(rc)
        } else if out.is_null() {
            Ok(None)
        } else {
            Ok(Some(pwref(&res)))
        }
    }
}

pub fn getpwuid_buf(uid: Uid, buf: &mut [u8]) -> Result<Option<PasswdRef<'_>>, i32> {
    unsafe {
        let mut res = Passwd::zero();
        let mut out: *mut Passwd = null_mut();
        let rc = getpwuid_r(uid, &mut res, buf.as_mut_ptr().cast(), buf.len(), &mut out);
        if rc != 0 {
            Err(rc)
        } else if out.is_null() {
            Ok(None)
        } else {
            Ok(Some(pwref(&res)))
        }
    }
}

fn grref<'a>(g: &Group) -> GroupRef<'a> {
    unsafe { GroupRef { name: bytes(g.gr_name), passwd: bytes(g.gr_passwd), gid: g.gr_gid, members: g.gr_mem, _buf: core::marker::PhantomData } }
}

pub fn getgrnam_buf<'a>(name: &[u8], buf: &'a mut [u8]) -> Result<Option<GroupRef<'a>>, i32> {
    let mut cname = [0u8; 256];
    if name.len() >= cname.len() || name.contains(&0) {
        return Ok(None);
    }
    cname[..name.len()].copy_from_slice(name);
    unsafe {
        let mut res = Group::zero();
        let mut out: *mut Group = null_mut();
        let rc = getgrnam_r(cname.as_ptr().cast(), &mut res, buf.as_mut_ptr().cast(), buf.len(), &mut out);
        if rc != 0 {
            Err(rc)
        } else if out.is_null() {
            Ok(None)
        } else {
            Ok(Some(grref(&res)))
        }
    }
}

pub fn getgrgid_buf(gid: Gid, buf: &mut [u8]) -> Result<Option<GroupRef<'_>>, i32> {
    unsafe {
        let mut res = Group::zero();
        let mut out: *mut Group = null_mut();
        let rc = getgrgid_r(gid, &mut res, buf.as_mut_ptr().cast(), buf.len(), &mut out);
        if rc != 0 {
            Err(rc)
        } else if out.is_null() {
            Ok(None)
        } else {
            Ok(Some(grref(&res)))
        }
    }
}
