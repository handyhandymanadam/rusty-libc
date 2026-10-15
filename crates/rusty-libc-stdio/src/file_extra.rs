use crate::file::{self, EOF, F_APPEND, F_MEM, F_READ, F_WRITE, File as FILE};
use crate::file_api::{fpos_t, off_t};
use crate::flock::locked;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi, syscall, unistd};

macro_rules! alias {
    ($(#[$m:meta])* $name:ident($($a:ident: $t:ty),*) -> $r:ty = $target:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name($($a: $t),*) -> $r {
            unsafe { $target($($a),*) }
        }
    };
}

unsafe fn getc_u(f: *mut FILE) -> c_int {
    file::getc(unsafe { file::stream(f) })
}
unsafe fn getchar_u() -> c_int {
    file::getc(unsafe { file::stream(file::stdin_ptr()) })
}
unsafe fn putc_u(c: c_int, f: *mut FILE) -> c_int {
    file::putc(c, unsafe { file::stream(f) })
}
unsafe fn putchar_u(c: c_int) -> c_int {
    file::putc(c, unsafe { file::stream(file::stdout_ptr()) })
}
unsafe fn feof_u(f: *mut FILE) -> c_int {
    c_int::from(unsafe { file::stream(f) }.flags & file::F_EOF != 0)
}
unsafe fn ferror_u(f: *mut FILE) -> c_int {
    c_int::from(unsafe { file::stream(f) }.flags & file::F_ERR != 0)
}
unsafe fn clearerr_u(f: *mut FILE) {
    unsafe { file::stream(f) }.flags &= !(file::F_EOF | file::F_ERR)
}
unsafe fn fflush_u(f: *mut FILE) -> c_int {
    if f.is_null() {
        return if file::flush_all() { 0 } else { EOF };
    }
    file::fflush(unsafe { file::stream(f) })
}

alias!(fgetc_unlocked(f: *mut FILE) -> c_int = getc_u);
alias!(getc_unlocked(f: *mut FILE) -> c_int = getc_u);
alias!(getchar_unlocked() -> c_int = getchar_u);
alias!(fputc_unlocked(c: c_int, f: *mut FILE) -> c_int = putc_u);
alias!(putc_unlocked(c: c_int, f: *mut FILE) -> c_int = putc_u);
alias!(putchar_unlocked(c: c_int) -> c_int = putchar_u);
alias!(fgets_unlocked(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char = crate::file_api::fgets_u);
alias!(fputs_unlocked(s: *const c_char, f: *mut FILE) -> c_int = crate::file_api::fputs_u);
alias!(fread_unlocked(p: *mut c_void, size: usize, n: usize, f: *mut FILE) -> usize = crate::file_api::fread_u);
alias!(fwrite_unlocked(p: *const c_void, size: usize, n: usize, f: *mut FILE) -> usize = crate::file_api::fwrite_u);
alias!(feof_unlocked(f: *mut FILE) -> c_int = feof_u);
alias!(ferror_unlocked(f: *mut FILE) -> c_int = ferror_u);
alias!(clearerr_unlocked(f: *mut FILE) -> () = clearerr_u);
alias!(fflush_unlocked(f: *mut FILE) -> c_int = fflush_u);
alias!(fileno_unlocked(f: *mut FILE) -> c_int = crate::file_api::fileno_u);
alias!(fopen64(path: *const c_char, mode: *const c_char) -> *mut FILE = crate::file_api::fopen);
alias!(fseeko64(f: *mut FILE, off: off_t, whence: c_int) -> c_int = crate::file_api::fseeko);
alias!(ftello64(f: *mut FILE) -> off_t = crate::file_api::ftello);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos64(f: *mut FILE, pos: *mut fpos_t) -> c_int {
    unsafe { crate::file_api::fgetpos(f, pos) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos64(f: *mut FILE, pos: *const fpos_t) -> c_int {
    unsafe { crate::file_api::fsetpos(f, pos) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tmpfile64() -> *mut FILE {
    crate::file_api::tmpfile()
}
alias!(__getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize = crate::file_api::getdelim);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __uflow(f: *mut FILE) -> c_int {
    file::getc(unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __underflow(f: *mut FILE) -> c_int {
    file::peekc(unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __overflow(f: *mut FILE, c: c_int) -> c_int {
    file::putc(c, unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getw(f: *mut FILE) -> c_int {
    locked!(f, |s| {
        let mut w = [0u8; 4];
        if file::read_bytes(s, &mut w) != 4 { EOF } else { i32::from_ne_bytes(w) }
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putw(w: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| if file::write_bytes(s, &w.to_ne_bytes()) == 4 { 0 } else { -1 })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gets(s: *mut c_char) -> *mut c_char {
    locked!(file::stdin_ptr(), |f| {
        let mut i = 0usize;
        loop {
            let c = file::getc(f);
            if c == EOF {
                if i == 0 {
                    return null_mut();
                }
                break;
            }
            if c == c_int::from(b'\n') {
                break;
            }
            unsafe { *s.wrapping_add(i) = c as c_char };
            i += 1;
        }
        unsafe { *s.wrapping_add(i) = 0 };
        s
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fcloseall() -> c_int {
    file::close_all();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctermid(s: *mut c_char) -> *mut c_char {
    static BUF: SyncCell<[u8; 9]> = SyncCell::new(*b"/dev/tty\0");
    let dst = if s.is_null() { BUF.as_ptr() as *mut c_char } else { s };
    unsafe { rusty_libc_mem::memcpy(dst.cast(), c"/dev/tty".as_ptr().cast(), 9) };
    dst
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freopen(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE {
    let path = unsafe { rusty_libc_core::ffi::cstr(path) };
    let mode = unsafe { rusty_libc_core::ffi::cstr_bytes(mode) };
    let r = locked!(f, |s| {
        let keep = s.flags & (file::F_STATIC | F_MEM) != 0;
        match freopen_s(path, mode, s) {
            true => Reopen::Done,
            false if keep => Reopen::Failed,
            false => Reopen::Discard,
        }
    });
    match r {
        Reopen::Done => f,
        Reopen::Failed => null_mut(),
        Reopen::Discard => {
            let e = errno::get();
            unsafe { file::fclose(f) };
            errno::set(e);
            null_mut()
        }
    }
}

enum Reopen {
    Done,
    Failed,
    Discard,
}

fn freopen_s(path: Option<&core::ffi::CStr>, m: &[u8], f: &mut FILE) -> bool {
    let parsed = file::parse_mode(m);
    let oldfd = f.fd;
    let mut procname = [0u8; 40];
    let mut dupfd = -1;
    let mut path: *const c_char = path.map_or(core::ptr::null(), |p| p.as_ptr());
    if path.is_null()
        && oldfd >= 0
        && f.flags & F_MEM == 0
        && let Ok(d) = unistd::dup(oldfd)
    {
        dupfd = d;
        let prefix = b"/proc/self/fd/";
        procname[..prefix.len()].copy_from_slice(prefix);
        let mut tmp = [0u8; 12];
        let mut k = 12;
        let mut v = d as u32;
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        procname[prefix.len()..prefix.len() + 12 - k].copy_from_slice(&tmp[k..]);
        path = procname.as_ptr().cast();
    }
    file::close_keep(f);
    let Some((flags, oflags)) = parsed else {
        if dupfd >= 0 {
            let _ = unistd::close(dupfd);
        }
        errno::set(22);
        return false;
    };
    if path.is_null() {
        errno::set(9);
        return false;
    }
    let fd = match unsafe { unistd::open(path, oflags, 0o666) } {
        Ok(fd) => fd,
        Err(e) => {
            if dupfd >= 0 {
                let _ = unistd::close(dupfd);
            }
            errno::set(e.0);
            return false;
        }
    };
    if dupfd >= 0 {
        let _ = unistd::close(dupfd);
    }
    let mut fd = fd;
    if oldfd >= 0 && fd != oldfd {
        let cloexec = if oflags & 0o2000000 != 0 { 0o2000000 } else { 0 };
        if unistd::dup3(fd, oldfd, cloexec).is_ok() {
            let _ = unistd::close(fd);
            fd = oldfd;
        }
    }
    let mut start = 0i64;
    if flags & F_APPEND != 0 && flags & F_READ == 0 {
        start = unistd::lseek(fd, 0, 2).unwrap_or(-1);
    }
    file::reopen_as(f, flags, fd, start);
    if let Some(name) = file::mode_ccs(m)
        && !crate::wfile::set_ccs(f, name)
    {
        let e = errno::get();
        file::close_keep(f);
        errno::set(e);
        return false;
    }
    true
}
alias!(freopen64(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE = freopen);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn popen(command: *const c_char, ty: *const c_char) -> *mut FILE {
    let t = unsafe { ffi::cstr_bytes(ty) };
    let (mut reading, mut writing, mut cloexec) = (false, false, false);
    for &c in t {
        match c {
            b'r' => reading = true,
            b'w' => writing = true,
            b'e' => cloexec = true,
            _ => {
                errno::set(22);
                return null_mut();
            }
        }
    }
    if reading == writing {
        errno::set(22);
        return null_mut();
    }
    let (rd, wr) = match unistd::pipe2(0o2000000) {
        Ok(p) => p,
        Err(e) => {
            errno::set(e.0);
            return null_mut();
        }
    };
    let (parent_end, mut child_end) = if reading { (rd, wr) } else { (wr, rd) };
    let target = if reading { 1 } else { 0 };
    if child_end == target {
        match unistd::fcntl_int(child_end, 1030 , 0) {
            Ok(tmp) => {
                let _ = unistd::close(child_end);
                child_end = tmp;
            }
            Err(e) => {
                let _ = unistd::close(rd);
                let _ = unistd::close(wr);
                errno::set(e.0);
                return null_mut();
            }
        }
    }
    let flags = if reading { F_READ } else { F_WRITE };
    let f = file::alloc_file(flags, parent_end);
    if f.is_null() {
        let _ = unistd::close(parent_end);
        let _ = unistd::close(child_end);
        errno::set(12);
        return null_mut();
    }
    let s = unsafe { file::stream(f) };
    s.cookie_pos = -1;
    s.flags |= file::F_BYTE;
    let err = unsafe { file::popen_spawn(s, command, child_end, target, parent_end, cloexec) };
    if err != 0 {
        let _ = unistd::close(child_end);
        unsafe { crate::file_api::fclose(f) };
        errno::set(err);
        return null_mut();
    }
    f
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pclose(f: *mut FILE) -> c_int {
    if unsafe { (*f).pid } <= 0 {
        errno::set(10);
        return -1;
    }
    unsafe { file::fclose(f) }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cookie_io_functions_t {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut off_t, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

fn make_cookie_stream(cookie: *mut c_void, mode: &[u8], io: file::CookieIo) -> *mut FILE {
    let Some((flags, _)) = file::parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    let f = file::alloc_file(flags | F_MEM | file::F_BYTE, -1);
    if f.is_null() {
        errno::set(12);
        return f;
    }
    let s = unsafe { file::stream(f) };
    s.cookie = cookie;
    s.io = io;
    s.cookie_pos = 0;
    if flags & F_APPEND != 0
        && let Some(seek) = io.seek
    {
        let mut pos = 0i64;
        if unsafe { seek(cookie, &mut pos, 2) } == 0 {
            s.cookie_pos = pos;
        }
    }
    f
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopencookie(cookie: *mut c_void, mode: *const c_char, io: cookie_io_functions_t) -> *mut FILE {
    let m = unsafe { ffi::cstr_bytes(mode) };
    make_cookie_stream(cookie, m, file::CookieIo { read: io.read, write: io.write, seek: io.seek, close: io.close, sync: None })
}

#[inline(always)]
unsafe fn cookie<'a, T>(c: *mut c_void) -> &'a mut T {
    unsafe { &mut *c.cast::<T>() }
}

#[inline(always)]
unsafe fn io_out<'a>(b: *mut c_char, n: usize) -> &'a mut [u8] {
    unsafe { ffi::bytes_mut(b.cast(), n) }
}

#[inline(always)]
unsafe fn io_in<'a>(b: *const c_char, n: usize) -> &'a [u8] {
    unsafe { ffi::bytes(b.cast(), n) }
}

struct MemBuf {
    buf: *mut u8,
    own: bool,
    append: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

impl MemBuf {
    fn mem(&mut self) -> &mut [u8] {
        unsafe { ffi::bytes_mut(self.buf, self.size) }
    }

    fn read(&mut self, b: &mut [u8]) -> isize {
        let mut n = b.len();
        if self.pos as usize > self.maxpos || self.pos < 0 {
            n = 0;
        } else if self.pos as usize + n > self.maxpos {
            n = self.maxpos - self.pos as usize;
        }
        let pos = if n == 0 { 0 } else { self.pos as usize };
        file::copy_bytes(&mut b[..n], &self.mem()[pos..pos + n]);
        self.pos += n as i64;
        n as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let pos = if self.append { self.maxpos as i64 } else { self.pos };
        let addnul = b.last().is_none_or(|&c| c != 0);
        let mut n = b.len();
        if pos as usize + n > self.size {
            if (self.pos as usize + usize::from(addnul)) >= self.size {
                errno::set(28);
                return 0;
            }
            n = self.size - pos as usize;
        }
        file::copy_bytes(&mut self.mem()[pos as usize..pos as usize + n], &b[..n]);
        self.pos = pos + n as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
            if self.maxpos < self.size && addnul {
                let at = self.maxpos;
                self.mem()[at] = 0;
            } else if !self.append && addnul {
                let at = self.size - 1;
                self.mem()[at] = 0;
            }
        }
        n as isize
    }

    fn seek(&mut self, p: &mut i64, whence: c_int) -> c_int {
        let np = match whence {
            0 => *p,
            1 => self.pos + *p,
            2 => self.maxpos as i64 + *p,
            _ => return -1,
        };
        if np < 0 || np as usize > self.size {
            errno::set(22);
            return -1;
        }
        self.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn fm_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    unsafe { cookie::<MemBuf>(c) }.read(unsafe { io_out(b, n) })
}

unsafe extern "C" fn fm_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    unsafe { cookie::<MemBuf>(c) }.write(unsafe { io_in(b, n) })
}

unsafe extern "C" fn fm_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    unsafe { cookie::<MemBuf>(c) }.seek(unsafe { &mut *p }, whence)
}

unsafe extern "C" fn fm_close(c: *mut c_void) -> c_int {
    let m = unsafe { cookie::<MemBuf>(c) };
    if m.own {
        unsafe { file::free(m.buf) };
    }
    unsafe { file::free(c.cast()) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmemopen(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    let m = unsafe { ffi::cstr_bytes(mode) };
    let c = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<MemBuf>()) } as *mut MemBuf;
    if c.is_null() {
        return null_mut();
    }
    let cb = unsafe { &mut *c };
    cb.own = buf.is_null();
    if cb.own {
        cb.buf = file::alloc(len);
        if cb.buf.is_null() {
            unsafe { file::free(c.cast()) };
            return null_mut();
        }
        unsafe { *cb.buf = 0 };
    } else {
        if len > (0usize.wrapping_sub(buf as usize)) {
            unsafe { file::free(c.cast()) };
            errno::set(22);
            return null_mut();
        }
        cb.buf = buf as *mut u8;
        if m.first() == Some(&b'w') && m.get(1) == Some(&b'+') {
            unsafe { *cb.buf = 0 };
        }
        if m.first() == Some(&b'a') {
            cb.maxpos = unsafe { rusty_libc_mem::strnlen(cb.buf.cast(), len) };
        }
    }
    cb.size = len;
    if m.first() == Some(&b'r') {
        cb.maxpos = len;
    }
    cb.append = m.first() == Some(&b'a');
    cb.pos = if cb.append { cb.maxpos as i64 } else { 0 };
    let io = file::CookieIo { read: Some(fm_read), write: Some(fm_write), seek: Some(fm_seek), close: Some(fm_close), sync: None };
    let pos = cb.pos;
    let own = cb.own;
    let mb = cb.buf;
    let f = make_cookie_stream(c.cast(), m, io);
    if f.is_null() {
        if own {
            unsafe { file::free(mb) };
        }
        unsafe { file::free(c.cast()) };
    } else {
        unsafe { file::stream(f) }.cookie_pos = pos;
    }
    f
}


struct OldMemBuf {
    buffer: *mut u8,
    mybuffer: bool,
    binmode: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

impl OldMemBuf {
    fn mem(&mut self) -> &mut [u8] {
        unsafe { ffi::bytes_mut(self.buffer, self.size) }
    }

    fn read(&mut self, b: &mut [u8]) -> isize {
        let mut s = b.len();
        if self.pos as usize + s > self.size {
            if self.pos as usize == self.size {
                return 0;
            }
            s = self.size - self.pos as usize;
        }
        let pos = self.pos as usize;
        b[..s].copy_from_slice(&self.mem()[pos..pos + s]);
        self.pos += s as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
        }
        s as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let mut s = b.len();
        let addnullc = usize::from(!self.binmode && b.last().is_none_or(|&c| c != 0));
        if self.pos as usize + s + addnullc > self.size {
            if (self.pos as usize + addnullc) >= self.size {
                errno::set(28);
                return 0;
            }
            s = self.size - self.pos as usize - addnullc;
        }
        let pos = self.pos as usize;
        self.mem()[pos..pos + s].copy_from_slice(&b[..s]);
        self.pos += s as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
            if addnullc != 0 {
                let at = self.maxpos;
                self.mem()[at] = 0;
            }
        }
        s as isize
    }

    fn seek(&mut self, p: &mut i64, w: c_int) -> c_int {
        let np = match w {
            0 => *p,
            1 => self.pos + *p,
            2 => (if self.binmode { self.size } else { self.maxpos }) as i64 - *p,
            _ => return -1,
        };
        if np < 0 || np as usize > self.size {
            return -1;
        }
        self.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn ofm_read(c: *mut c_void, b: *mut c_char, s: usize) -> isize {
    unsafe { cookie::<OldMemBuf>(c) }.read(unsafe { io_out(b, s) })
}

unsafe extern "C" fn ofm_write(c: *mut c_void, b: *const c_char, s: usize) -> isize {
    unsafe { cookie::<OldMemBuf>(c) }.write(unsafe { io_in(b, s) })
}

unsafe extern "C" fn ofm_seek(c: *mut c_void, p: *mut off_t, w: c_int) -> c_int {
    unsafe { cookie::<OldMemBuf>(c) }.seek(unsafe { &mut *p }, w)
}

unsafe extern "C" fn ofm_close(c: *mut c_void) -> c_int {
    let m = unsafe { cookie::<OldMemBuf>(c) };
    if m.mybuffer {
        unsafe { file::free(m.buffer) };
    }
    unsafe { file::free(c.cast()) };
    0
}

pub unsafe fn fmemopen_old(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    let m = unsafe { ffi::cstr_bytes(mode) };
    if len == 0 {
        errno::set(22);
        return null_mut();
    }
    let c: *mut OldMemBuf = file::alloc(core::mem::size_of::<OldMemBuf>()).cast();
    if c.is_null() {
        return null_mut();
    }
    let mybuffer = buf.is_null();
    let (buffer, maxpos) = if mybuffer {
        let b = file::alloc(len);
        if b.is_null() {
            unsafe { file::free(c.cast()) };
            return null_mut();
        }
        unsafe { *b = 0 };
        (b, 0)
    } else {
        if len > (0usize.wrapping_sub(buf as usize)) {
            unsafe { file::free(c.cast()) };
            errno::set(22);
            return null_mut();
        }
        let b = buf as *mut u8;
        if m.first() == Some(&b'w') {
            unsafe { *b = 0 };
        }
        (b, unsafe { rusty_libc_mem::strnlen(b.cast(), len) })
    };
    let pos = if m.first() == Some(&b'a') { maxpos as i64 } else { 0 };
    let binmode = !m.is_empty() && m.get(1) == Some(&b'b');
    unsafe { c.write(OldMemBuf { buffer, mybuffer, binmode, size: len, pos, maxpos }) };
    let io = file::CookieIo { read: Some(ofm_read), write: Some(ofm_write), seek: Some(ofm_seek), close: Some(ofm_close), sync: None };
    let f = make_cookie_stream(c.cast(), m, io);
    if f.is_null() {
        if mybuffer {
            unsafe { file::free(buffer) };
        }
        unsafe { file::free(c.cast()) };
    } else {
        let s = unsafe { file::stream(f) };
        s.flags |= file::F_OLDMEM;
        s.cookie_pos = pos;
    }
    f
}

struct MemStream {
    bufloc: *mut *mut c_char,
    sizeloc: *mut usize,
    buf: *mut u8,
    cap: usize,
    pos: usize,
    re: usize,
    unit: usize,
}

impl MemStream {
    fn mem(&mut self) -> &mut [u8] {
        unsafe { ffi::bytes_mut(self.buf, self.cap) }
    }

    fn reserve(&mut self, need: usize) -> bool {
        if need < self.cap {
            return true;
        }
        let newcap = (2 * self.cap + 100).max(need + 1);
        let nb = unsafe { rusty_libc_malloc::realloc(self.buf.cast(), newcap) } as *mut u8;
        if nb.is_null() {
            return false;
        }
        let old = self.cap;
        self.buf = nb;
        self.cap = newcap;
        self.mem()[old..].fill(0);
        true
    }

    fn publish(&self) {
        unsafe { *self.bufloc = self.buf.cast() };
        unsafe { *self.sizeloc = self.pos / self.unit };
    }

    fn read(&mut self, b: &mut [u8]) -> isize {
        let avail = self.pos.max(self.re).saturating_sub(self.pos);
        let k = b.len().min(avail);
        let pos = self.pos;
        file::copy_bytes(&mut b[..k], &self.mem()[pos..pos + k]);
        self.pos += k;
        k as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let n = b.len();
        if !self.reserve(self.pos + n + self.unit - 1) {
            errno::set(12);
            return -1;
        }
        let pos = self.pos;
        file::copy_bytes(&mut self.mem()[pos..pos + n], b);
        self.pos += n;
        n as isize
    }

    fn seek(&mut self, p: &mut i64, whence: c_int) -> c_int {
        if self.pos > 0 {
            self.re = self.pos;
        }
        let cur_size = self.pos.max(self.re);
        let base = match whence {
            0 => 0,
            1 => self.pos as i64,
            2 => cur_size as i64,
            _ => return -1,
        };
        let np = base.saturating_add(*p);
        if !(0..=i64::MAX / 2).contains(&np) {
            errno::set(22);
            return -1;
        }
        if np as usize > cur_size && !self.reserve(np as usize + self.unit - 1) {
            errno::set(12);
            return -1;
        }
        self.re = cur_size;
        self.pos = np as usize;
        *p = np;
        0
    }
}

unsafe extern "C" fn ms_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    unsafe { cookie::<MemStream>(c) }.read(unsafe { io_out(b, n) })
}

unsafe extern "C" fn ms_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    unsafe { cookie::<MemStream>(c) }.write(unsafe { io_in(b, n) })
}

unsafe extern "C" fn ms_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    unsafe { cookie::<MemStream>(c) }.seek(unsafe { &mut *p }, whence)
}

unsafe extern "C" fn ms_sync(c: *mut c_void) {
    unsafe { cookie::<MemStream>(c) }.publish()
}

unsafe extern "C" fn ms_close(c: *mut c_void) -> c_int {
    let m = unsafe { cookie::<MemStream>(c) };
    let nb = unsafe { rusty_libc_malloc::realloc(m.buf.cast(), m.pos + m.unit) } as *mut u8;
    if !nb.is_null() {
        m.buf = nb;
        m.cap = m.pos + m.unit;
        let (pos, unit) = (m.pos, m.unit);
        m.mem()[pos..pos + unit].fill(0);
        m.publish();
    }
    unsafe { file::free(c.cast()) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_memstream(bufloc: *mut *mut c_char, sizeloc: *mut usize) -> *mut FILE {
    unsafe { open_memstream_unit(bufloc, sizeloc, 1) }
}

pub(crate) unsafe fn open_memstream_unit(bufloc: *mut *mut c_char, sizeloc: *mut usize, unit: usize) -> *mut FILE {
    let m = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<MemStream>()) } as *mut MemStream;
    if m.is_null() {
        return null_mut();
    }
    let buf = unsafe { rusty_libc_malloc::calloc(1, 8192) } as *mut u8;
    if buf.is_null() {
        unsafe { file::free(m.cast()) };
        return null_mut();
    }
    unsafe { m.write(MemStream { bufloc, sizeloc, buf, cap: 8192, pos: 0, re: 0, unit }) };
    let io = file::CookieIo { read: Some(ms_read), write: Some(ms_write), seek: Some(ms_seek), close: Some(ms_close), sync: Some(ms_sync) };
    let f = make_cookie_stream(m.cast(), b"w+", io);
    if f.is_null() {
        unsafe { file::free(buf) };
        unsafe { file::free(m.cast()) };
    } else {
        let s = unsafe { file::stream(f) };
        s.flags |= file::F_NOEOF | file::F_NOCACHE | file::F_UNBUF | file::F_DECIDED;
        if unit == 4 {
            s.flags &= !file::F_BYTE;
            s.flags |= file::F_W32;
            if !crate::wfile::make_raw_wide(s) {
                unsafe { file::fclose(f) };
                return null_mut();
            }
        }
    }
    f
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char) -> c_int {
    let r = unsafe { syscall::syscall4(syscall::SYS_RENAMEAT, oldfd as usize, old as usize, newfd as usize, new as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat2(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: core::ffi::c_uint) -> c_int {
    let r = unsafe { syscall::syscall5(syscall::SYS_RENAMEAT2, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn random6() -> [u8; 6] {
    let mut r = [0u8; 6];
    let got = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, r.as_mut_ptr() as usize, 6, 0) };
    if got != 6 {
        let mut t = unsafe { core::arch::x86_64::_rdtsc() };
        for b in r.iter_mut() {
            *b = (t & 0xff) as u8;
            t = t.rotate_right(7) ^ 0x9e37_79b9_7f4a_7c15;
        }
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = ALPHABET[r[i] as usize % 62];
    }
    out
}

fn gen_name(dir: &[u8], prefix: &[u8], buf: &mut [u8]) -> bool {
    let total = dir.len() + 1 + prefix.len() + 6 + 1;
    if total > buf.len() {
        errno::set(36);
        return false;
    }
    for _ in 0..238_328 {
        let mut k = 0;
        buf[..dir.len()].copy_from_slice(dir);
        k += dir.len();
        buf[k] = b'/';
        k += 1;
        buf[k..k + prefix.len()].copy_from_slice(prefix);
        k += prefix.len();
        buf[k..k + 6].copy_from_slice(&random6());
        k += 6;
        buf[k] = 0;
        let r = unsafe { rusty_libc_core::syscall::sys_lstat(buf.as_ptr() as usize, [0u64; 18].as_mut_ptr() as usize) };
        if r == (-2isize) as usize {
            return true;
        }
        if let Err(e) = syscall::check(r) {
            errno::set(e.0);
            return false;
        }
    }
    errno::set(17);
    false
}

static TMPNAM_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
    let mut local = [0u8; 20];
    if !gen_name(b"/tmp", b"file", &mut local) {
        return null_mut();
    }
    let dst: *mut u8 = if s.is_null() { TMPNAM_BUF.as_ptr().cast() } else { s as *mut u8 };
    unsafe { rusty_libc_mem::memcpy(dst.cast(), local.as_ptr().cast(), 20) };
    dst as *mut c_char
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam_r(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return null_mut();
    }
    unsafe { tmpnam(s) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    let dir = unsafe { ffi::cstr(dir) };
    let pfx = unsafe { ffi::cstr(pfx) }.map(|p| &p.to_bytes()[..p.to_bytes().len().min(5)]);
    tempnam_s(dir, pfx)
}

pub fn tempnam_s(dir: Option<&core::ffi::CStr>, pfx: Option<&[u8]>) -> *mut c_char {
    let usable = |d: Option<&core::ffi::CStr>| -> bool {
        let Some(d) = d else { return false };
        let mut st = [0u64; 18];
        if syscall::check(unsafe { rusty_libc_core::syscall::sys_stat(d.as_ptr() as usize, st.as_mut_ptr() as usize) }).is_err() {
            return false;
        }
        let mode = (st[3] & 0xffff_ffff) as u32;
        mode & 0o170000 == 0o040000
    };
    let tmpdir = if rusty_libc_core::lock::secure() { null_mut() } else { unsafe { rusty_libc_core::env::getenv(b"TMPDIR") } };
    let tmpdir = unsafe { ffi::cstr(tmpdir) };
    let chosen: &core::ffi::CStr = if usable(tmpdir) {
        tmpdir.unwrap_or(c"")
    } else if usable(dir) {
        dir.unwrap_or(c"")
    } else if usable(Some(c"/tmp")) {
        c"/tmp"
    } else {
        errno::set(2);
        return null_mut();
    };
    let p: &[u8] = match pfx {
        Some(p) if !p.is_empty() => p,
        _ => b"file",
    };
    let mut name = [0u8; 4096];
    if !gen_name(chosen.to_bytes(), p, &mut name) {
        return null_mut();
    }
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let out = file::alloc(len + 1);
    if out.is_null() {
        errno::set(12);
        return out.cast();
    }
    let dst = unsafe { ffi::bytes_mut(out, len + 1) };
    file::copy_bytes(dst, &name[..len + 1]);
    out.cast()
}
