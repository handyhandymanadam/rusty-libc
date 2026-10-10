use crate::file::{self, EOF, F_APPEND, F_MEM, F_READ, F_WRITE, File as FILE};
use crate::file_api::{fpos_t, off_t};
use crate::flock::locked;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, syscall, unistd};

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
    unsafe { file::getc(f) }
}
unsafe fn getchar_u() -> c_int {
    unsafe { file::getc(file::stdin_ptr()) }
}
unsafe fn putc_u(c: c_int, f: *mut FILE) -> c_int {
    unsafe { file::putc(c, f) }
}
unsafe fn putchar_u(c: c_int) -> c_int {
    unsafe { file::putc(c, file::stdout_ptr()) }
}
unsafe fn feof_u(f: *mut FILE) -> c_int {
    unsafe { c_int::from((*f).flags & file::F_EOF != 0) }
}
unsafe fn ferror_u(f: *mut FILE) -> c_int {
    unsafe { c_int::from((*f).flags & file::F_ERR != 0) }
}
unsafe fn clearerr_u(f: *mut FILE) {
    unsafe { (*f).flags &= !(file::F_EOF | file::F_ERR) }
}
unsafe fn fflush_u(f: *mut FILE) -> c_int {
    unsafe { file::fflush(f) }
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
alias!(tmpfile64() -> *mut FILE = crate::file_api::tmpfile);
alias!(__getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize = crate::file_api::getdelim);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __uflow(f: *mut FILE) -> c_int {
    unsafe { file::getc(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __underflow(f: *mut FILE) -> c_int {
    unsafe { file::peekc(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __overflow(f: *mut FILE, c: c_int) -> c_int {
    unsafe { file::putc(c, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getw(f: *mut FILE) -> c_int {
    unsafe {
        locked!(f, move || {
            let mut w = 0i32;
            if file::read_bytes(f, (&mut w as *mut i32).cast(), 4) != 4 { EOF } else { w }
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putw(w: c_int, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || if file::write_bytes(f, (&w as *const i32).cast(), 4) == 4 { 0 } else { -1 }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gets(s: *mut c_char) -> *mut c_char {
    unsafe {
        let f = file::stdin_ptr();
        locked!(f, move || {
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
                *s.add(i) = c as c_char;
                i += 1;
            }
            *s.add(i) = 0;
            s
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcloseall() -> c_int {
    unsafe {
        file::close_all();
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctermid(s: *mut c_char) -> *mut c_char {
    unsafe {
        static mut BUF: [u8; 9] = *b"/dev/tty\0";
        let dst = if s.is_null() { core::ptr::addr_of_mut!(BUF) as *mut c_char } else { s };
        rusty_libc_mem::memcpy(dst.cast(), c"/dev/tty".as_ptr().cast(), 9);
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freopen(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE {
    unsafe { locked!(f, move || freopen_u(path, mode, f)) }
}

unsafe fn freopen_u(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        let parsed = file::parse_mode(m);
        let oldfd = (*f).fd;
        let mut procname = [0u8; 40];
        let mut dupfd = -1;
        let mut path = path;
        if path.is_null()
            && oldfd >= 0
            && (*f).flags & F_MEM == 0
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
            return null_mut();
        };
        if path.is_null() {
            errno::set(9);
            return null_mut();
        }
        let fd = match unistd::open(path, oflags, 0o666) {
            Ok(fd) => fd,
            Err(e) => {
                if dupfd >= 0 {
                    let _ = unistd::close(dupfd);
                }
                errno::set(e.0);
                return null_mut();
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
            crate::file_api::fclose(f);
            errno::set(e);
            return null_mut();
        }
        f
    }
}
alias!(freopen64(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE = freopen);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn popen(command: *const c_char, ty: *const c_char) -> *mut FILE {
    unsafe {
        let t = core::slice::from_raw_parts(ty as *const u8, rusty_libc_mem::strlen(ty));
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
            let tmp = syscall::syscall3(syscall::SYS_FCNTL, child_end as usize, 1030 , 0) as isize;
            if tmp < 0 {
                let _ = unistd::close(rd);
                let _ = unistd::close(wr);
                errno::set(-tmp as c_int);
                return null_mut();
            }
            let _ = unistd::close(child_end);
            child_end = tmp as c_int;
        }
        let flags = if reading { F_READ } else { F_WRITE };
        let f = file::alloc_file(flags, parent_end);
        if f.is_null() {
            let _ = unistd::close(parent_end);
            let _ = unistd::close(child_end);
            errno::set(12);
            return null_mut();
        }
        (*f).cookie_pos = -1;
        (*f).flags |= file::F_BYTE;
        let err = file::popen_spawn(f, command, child_end, target, parent_end, cloexec);
        if err != 0 {
            let _ = unistd::close(child_end);
            crate::file_api::fclose(f);
            errno::set(err);
            return null_mut();
        }
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pclose(f: *mut FILE) -> c_int {
    unsafe {
        if (*f).pid <= 0 {
            errno::set(10);
            return -1;
        }
        file::fclose(f)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cookie_io_functions_t {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut off_t, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

unsafe fn make_cookie_stream(cookie: *mut c_void, mode: &[u8], io: file::CookieIo) -> *mut FILE {
    unsafe {
        let Some((flags, _)) = file::parse_mode(mode) else {
            errno::set(22);
            return null_mut();
        };
        let f = file::alloc_file(flags | F_MEM | file::F_BYTE, -1);
        if f.is_null() {
            errno::set(12);
            return f;
        }
        (*f).cookie = cookie;
        (*f).io = io;
        (*f).cookie_pos = 0;
        if flags & F_APPEND != 0
            && let Some(seek) = io.seek
        {
            let mut pos = 0i64;
            if seek(cookie, &mut pos, 2) == 0 {
                (*f).cookie_pos = pos;
            }
        }
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopencookie(cookie: *mut c_void, mode: *const c_char, io: cookie_io_functions_t) -> *mut FILE {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        make_cookie_stream(cookie, m, file::CookieIo { read: io.read, write: io.write, seek: io.seek, close: io.close, sync: None })
    }
}

struct MemBuf {
    buf: *mut u8,
    own: bool,
    append: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

unsafe extern "C" fn fm_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    unsafe {
        let c = &mut *(c as *mut MemBuf);
        let mut n = n;
        if c.pos as usize > c.maxpos || c.pos < 0 {
            n = 0;
        } else if c.pos as usize + n > c.maxpos {
            n = c.maxpos - c.pos as usize;
        }
        rusty_libc_mem::memcpy(b.cast(), c.buf.add(c.pos as usize).cast(), n);
        c.pos += n as i64;
        n as isize
    }
}

unsafe extern "C" fn fm_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    unsafe {
        let c = &mut *(c as *mut MemBuf);
        let pos = if c.append { c.maxpos as i64 } else { c.pos };
        let addnul = n == 0 || *b.add(n - 1) != 0;
        let mut n = n;
        if pos as usize + n > c.size {
            if (c.pos as usize + usize::from(addnul)) >= c.size {
                errno::set(28);
                return 0;
            }
            n = c.size - pos as usize;
        }
        rusty_libc_mem::memcpy(c.buf.add(pos as usize).cast(), b.cast(), n);
        c.pos = pos + n as i64;
        if c.pos as usize > c.maxpos {
            c.maxpos = c.pos as usize;
            if c.maxpos < c.size && addnul {
                *c.buf.add(c.maxpos) = 0;
            } else if !c.append && addnul {
                *c.buf.add(c.size - 1) = 0;
            }
        }
        n as isize
    }
}

unsafe extern "C" fn fm_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    unsafe {
        let c = &mut *(c as *mut MemBuf);
        let np = match whence {
            0 => *p,
            1 => c.pos + *p,
            2 => c.maxpos as i64 + *p,
            _ => return -1,
        };
        if np < 0 || np as usize > c.size {
            errno::set(22);
            return -1;
        }
        c.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn fm_close(c: *mut c_void) -> c_int {
    unsafe {
        let m = c as *mut MemBuf;
        if (*m).own {
            rusty_libc_malloc::free((*m).buf.cast());
        }
        rusty_libc_malloc::free(c.cast());
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmemopen(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        let c = rusty_libc_malloc::calloc(1, core::mem::size_of::<MemBuf>()) as *mut MemBuf;
        if c.is_null() {
            return null_mut();
        }
        (*c).own = buf.is_null();
        if (*c).own {
            (*c).buf = rusty_libc_malloc::malloc(len) as *mut u8;
            if (*c).buf.is_null() {
                rusty_libc_malloc::free(c.cast());
                return null_mut();
            }
            *(*c).buf = 0;
        } else {
            if len > (0usize.wrapping_sub(buf as usize)) {
                rusty_libc_malloc::free(c.cast());
                errno::set(22);
                return null_mut();
            }
            (*c).buf = buf as *mut u8;
            if m.first() == Some(&b'w') && m.get(1) == Some(&b'+') {
                *(*c).buf = 0;
            }
            if m.first() == Some(&b'a') {
                (*c).maxpos = rusty_libc_mem::strnlen((*c).buf.cast(), len);
            }
        }
        (*c).size = len;
        if m.first() == Some(&b'r') {
            (*c).maxpos = len;
        }
        (*c).append = m.first() == Some(&b'a');
        (*c).pos = if (*c).append { (*c).maxpos as i64 } else { 0 };
        let io = file::CookieIo { read: Some(fm_read), write: Some(fm_write), seek: Some(fm_seek), close: Some(fm_close), sync: None };
        let f = make_cookie_stream(c.cast(), m, io);
        if f.is_null() {
            if (*c).own {
                rusty_libc_malloc::free((*c).buf.cast());
            }
            rusty_libc_malloc::free(c.cast());
        } else {
            (*f).cookie_pos = (*c).pos;
        }
        f
    }
}


struct OldMemBuf {
    buffer: *mut u8,
    mybuffer: bool,
    binmode: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

unsafe extern "C" fn ofm_read(cookie: *mut c_void, b: *mut c_char, mut s: usize) -> isize {
    unsafe {
        let c = &mut *(cookie as *mut OldMemBuf);
        if c.pos as usize + s > c.size {
            if c.pos as usize == c.size {
                return 0;
            }
            s = c.size - c.pos as usize;
        }
        core::ptr::copy_nonoverlapping(c.buffer.add(c.pos as usize), b as *mut u8, s);
        c.pos += s as i64;
        if c.pos as usize > c.maxpos {
            c.maxpos = c.pos as usize;
        }
        s as isize
    }
}

unsafe extern "C" fn ofm_write(cookie: *mut c_void, b: *const c_char, mut s: usize) -> isize {
    unsafe {
        let c = &mut *(cookie as *mut OldMemBuf);
        let addnullc = usize::from(!c.binmode && (s == 0 || *b.add(s - 1) != 0));
        if c.pos as usize + s + addnullc > c.size {
            if (c.pos as usize + addnullc) >= c.size {
                errno::set(28);
                return 0;
            }
            s = c.size - c.pos as usize - addnullc;
        }
        core::ptr::copy_nonoverlapping(b as *const u8, c.buffer.add(c.pos as usize), s);
        c.pos += s as i64;
        if c.pos as usize > c.maxpos {
            c.maxpos = c.pos as usize;
            if addnullc != 0 {
                *c.buffer.add(c.maxpos) = 0;
            }
        }
        s as isize
    }
}

unsafe extern "C" fn ofm_seek(cookie: *mut c_void, p: *mut off_t, w: c_int) -> c_int {
    unsafe {
        let c = &mut *(cookie as *mut OldMemBuf);
        let np = match w {
            0 => *p,
            1 => c.pos + *p,
            2 => (if c.binmode { c.size } else { c.maxpos }) as i64 - *p,
            _ => return -1,
        };
        if np < 0 || np as usize > c.size {
            return -1;
        }
        c.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn ofm_close(cookie: *mut c_void) -> c_int {
    unsafe {
        let c = cookie as *mut OldMemBuf;
        if (*c).mybuffer {
            rusty_libc_malloc::free((*c).buffer.cast());
        }
        rusty_libc_malloc::free(c.cast());
        0
    }
}

pub unsafe fn fmemopen_old(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        if len == 0 {
            errno::set(22);
            return null_mut();
        }
        let c = rusty_libc_malloc::malloc(core::mem::size_of::<OldMemBuf>()) as *mut OldMemBuf;
        if c.is_null() {
            return null_mut();
        }
        (*c).mybuffer = buf.is_null();
        if (*c).mybuffer {
            (*c).buffer = rusty_libc_malloc::malloc(len) as *mut u8;
            if (*c).buffer.is_null() {
                rusty_libc_malloc::free(c.cast());
                return null_mut();
            }
            *(*c).buffer = 0;
            (*c).maxpos = 0;
        } else {
            if len > (0usize.wrapping_sub(buf as usize)) {
                rusty_libc_malloc::free(c.cast());
                errno::set(22);
                return null_mut();
            }
            (*c).buffer = buf as *mut u8;
            if m.first() == Some(&b'w') {
                *(*c).buffer = 0;
            }
            (*c).maxpos = rusty_libc_mem::strnlen((*c).buffer.cast(), len);
        }
        (*c).size = len;
        (*c).pos = if m.first() == Some(&b'a') { (*c).maxpos as i64 } else { 0 };
        (*c).binmode = !m.is_empty() && m.get(1) == Some(&b'b');
        let io = file::CookieIo { read: Some(ofm_read), write: Some(ofm_write), seek: Some(ofm_seek), close: Some(ofm_close), sync: None };
        let f = make_cookie_stream(c.cast(), m, io);
        if !f.is_null() {
            (*f).flags |= file::F_OLDMEM;
        }
        if f.is_null() {
            if (*c).mybuffer {
                rusty_libc_malloc::free((*c).buffer.cast());
            }
            rusty_libc_malloc::free(c.cast());
        } else {
            (*f).cookie_pos = (*c).pos;
        }
        f
    }
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
    unsafe fn reserve(&mut self, need: usize) -> bool {
        unsafe {
            if need < self.cap {
                return true;
            }
            let newcap = (2 * self.cap + 100).max(need + 1);
            let nb = rusty_libc_malloc::realloc(self.buf.cast(), newcap) as *mut u8;
            if nb.is_null() {
                return false;
            }
            core::ptr::write_bytes(nb.add(self.cap), 0, newcap - self.cap);
            self.buf = nb;
            self.cap = newcap;
            true
        }
    }
    unsafe fn publish(&self) {
        unsafe {
            *self.bufloc = self.buf.cast();
            *self.sizeloc = self.pos / self.unit;
        }
    }
}

unsafe extern "C" fn ms_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    unsafe {
        let m = &mut *(c as *mut MemStream);
        let avail = m.pos.max(m.re).saturating_sub(m.pos);
        let k = n.min(avail);
        rusty_libc_mem::memcpy(b.cast(), m.buf.add(m.pos).cast(), k);
        m.pos += k;
        k as isize
    }
}

unsafe extern "C" fn ms_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    unsafe {
        let m = &mut *(c as *mut MemStream);
        if !m.reserve(m.pos + n + m.unit - 1) {
            errno::set(12);
            return -1;
        }
        rusty_libc_mem::memcpy(m.buf.add(m.pos).cast(), b.cast(), n);
        m.pos += n;
        n as isize
    }
}

unsafe extern "C" fn ms_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    unsafe {
        let m = &mut *(c as *mut MemStream);
        if m.pos > 0 {
            m.re = m.pos;
        }
        let cur_size = m.pos.max(m.re);
        let base = match whence {
            0 => 0,
            1 => m.pos as i64,
            2 => cur_size as i64,
            _ => return -1,
        };
        let np = base.saturating_add(*p);
        if !(0..=i64::MAX / 2).contains(&np) {
            errno::set(22);
            return -1;
        }
        if np as usize > cur_size && !m.reserve(np as usize + m.unit - 1) {
            errno::set(12);
            return -1;
        }
        m.re = cur_size;
        m.pos = np as usize;
        *p = np;
        0
    }
}

unsafe extern "C" fn ms_sync(c: *mut c_void) {
    unsafe { (*(c as *mut MemStream)).publish() }
}

unsafe extern "C" fn ms_close(c: *mut c_void) -> c_int {
    unsafe {
        let m = c as *mut MemStream;
        let nb = rusty_libc_malloc::realloc((*m).buf.cast(), (*m).pos + (*m).unit) as *mut u8;
        if !nb.is_null() {
            core::ptr::write_bytes(nb.add((*m).pos), 0, (*m).unit);
            *(*m).bufloc = nb.cast();
            *(*m).sizeloc = (*m).pos / (*m).unit;
        }
        rusty_libc_malloc::free(c.cast());
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_memstream(bufloc: *mut *mut c_char, sizeloc: *mut usize) -> *mut FILE {
    unsafe { open_memstream_unit(bufloc, sizeloc, 1) }
}

pub(crate) unsafe fn open_memstream_unit(bufloc: *mut *mut c_char, sizeloc: *mut usize, unit: usize) -> *mut FILE {
    unsafe {
        let m = rusty_libc_malloc::calloc(1, core::mem::size_of::<MemStream>()) as *mut MemStream;
        if m.is_null() {
            return null_mut();
        }
        (*m).bufloc = bufloc;
        (*m).unit = unit;
        (*m).sizeloc = sizeloc;
        (*m).buf = rusty_libc_malloc::calloc(1, 8192) as *mut u8;
        if (*m).buf.is_null() {
            rusty_libc_malloc::free(m.cast());
            return null_mut();
        }
        (*m).cap = 8192;
        let io = file::CookieIo { read: Some(ms_read), write: Some(ms_write), seek: Some(ms_seek), close: Some(ms_close), sync: Some(ms_sync) };
        let f = make_cookie_stream(m.cast(), b"w+", io);
        if f.is_null() {
            rusty_libc_malloc::free((*m).buf.cast());
            rusty_libc_malloc::free(m.cast());
        } else {
            (*f).flags |= file::F_NOEOF | file::F_NOCACHE | file::F_UNBUF | file::F_DECIDED;
            if unit == 4 {
                (*f).flags &= !file::F_BYTE;
                (*f).flags |= file::F_W32;
                if !crate::wfile::make_raw_wide(f) {
                    file::fclose(f);
                    return null_mut();
                }
            }
        }
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char) -> c_int {
    unsafe {
        let r = syscall::syscall4(syscall::SYS_RENAMEAT, oldfd as usize, old as usize, newfd as usize, new as usize);
        if r <= usize::MAX - 4095 {
            0
        } else {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat2(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: core::ffi::c_uint) -> c_int {
    unsafe {
        let r = syscall::syscall5(syscall::SYS_RENAMEAT2, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize);
        if r <= usize::MAX - 4095 {
            0
        } else {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        }
    }
}

const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

unsafe fn random6() -> [u8; 6] {
    unsafe {
        let mut r = [0u8; 6];
        let got = syscall::syscall3(syscall::SYS_GETRANDOM, r.as_mut_ptr() as usize, 6, 0);
        if got != 6 {
            let mut t = core::arch::x86_64::_rdtsc();
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
}

unsafe fn gen_name(dir: &[u8], prefix: &[u8], buf: &mut [u8]) -> bool {
    unsafe {
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
            let r = syscall::syscall2(syscall::SYS_LSTAT, buf.as_ptr() as usize, [0u64; 18].as_mut_ptr() as usize);
            if r == (-2isize) as usize {
                return true;
            }
            if r > usize::MAX - 4095 {
                errno::set((r as isize).wrapping_neg() as i32);
                return false;
            }
        }
        errno::set(17);
        false
    }
}

static mut TMPNAM_BUF: [u8; 20] = [0; 20];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
    unsafe {
        let mut local = [0u8; 20];
        if !gen_name(b"/tmp", b"file", &mut local) {
            return null_mut();
        }
        let dst: *mut u8 = if s.is_null() { core::ptr::addr_of_mut!(TMPNAM_BUF) as *mut u8 } else { s as *mut u8 };
        rusty_libc_mem::memcpy(dst.cast(), local.as_ptr().cast(), 20);
        dst as *mut c_char
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam_r(s: *mut c_char) -> *mut c_char {
    unsafe {
        if s.is_null() {
            return null_mut();
        }
        tmpnam(s)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    unsafe {
        let usable = |d: *const c_char| -> bool {
            if d.is_null() {
                return false;
            }
            let mut st = [0u64; 18];
            if syscall::syscall2(syscall::SYS_STAT, d as usize, st.as_mut_ptr() as usize) > usize::MAX - 4095 {
                return false;
            }
            let mode = (st[3] & 0xffff_ffff) as u32;
            mode & 0o170000 == 0o040000 && unistd::access(d, 3).is_ok()
        };
        let tmpdir = rusty_libc_core::env::getenv(b"TMPDIR");
        let chosen: *const c_char = if usable(tmpdir) {
            tmpdir
        } else if usable(dir) {
            dir
        } else if usable(c"/tmp".as_ptr()) {
            c"/tmp".as_ptr()
        } else {
            errno::set(2);
            return null_mut();
        };
        let d = core::slice::from_raw_parts(chosen as *const u8, rusty_libc_mem::strlen(chosen));
        let mut p: &[u8] = b"file";
        if !pfx.is_null() {
            let l = rusty_libc_mem::strnlen(pfx, 5);
            p = core::slice::from_raw_parts(pfx as *const u8, l);
        }
        let mut name = [0u8; 4096];
        if !gen_name(d, p, &mut name) {
            return null_mut();
        }
        let len = rusty_libc_mem::strlen(name.as_ptr().cast());
        let out = rusty_libc_malloc::malloc(len + 1) as *mut c_char;
        if out.is_null() {
            errno::set(12);
            return out;
        }
        rusty_libc_mem::memcpy(out.cast(), name.as_ptr().cast(), len + 1);
        out
    }
}
