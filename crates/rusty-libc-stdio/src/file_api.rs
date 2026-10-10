use crate::file::{self, EOF, F_ERR, F_EOF, F_MEM, F_NOSEEK, F_WRITE, F_READ, File as FILE};
use crate::flock::locked;
use crate::fmt::Sink;
use crate::printf_api::run;
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, syscall};

#[allow(non_camel_case_types)]
pub type off_t = i64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fpos_t {
    pub pos: c_long,
    pub state: [c_int; 2],
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stdin: *mut FILE = core::ptr::addr_of_mut!(file::STDIN_FILE);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stdout: *mut FILE = core::ptr::addr_of_mut!(file::STDOUT_FILE);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stderr: *mut FILE = core::ptr::addr_of_mut!(file::STDERR_FILE);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    unsafe { file::fopen(path, mode) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut FILE {
    unsafe { file::fdopen(fd, mode) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> c_int {
    unsafe { file::fclose(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(f: *mut FILE) -> c_int {
    unsafe {
        if f.is_null() {
            return file::fflush(f);
        }
        locked!(f, move || file::fflush(f))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc(f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || file::getc(f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getc(f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || file::getc(f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getchar() -> c_int {
    unsafe {
        let f = file::stdin_ptr();
        locked!(f, move || file::getc(f))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || file::putc(c, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putc(c: c_int, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || file::putc(c, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    unsafe {
        let f = file::stdout_ptr();
        locked!(f, move || file::putc(c, f))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || file::ungetc(c, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fread(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    unsafe { locked!(f, move || fread_u(ptr, size, nmemb, f)) }
}

#[inline(always)]
pub(crate) unsafe fn fread_u(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    unsafe {
        if size == 0 || nmemb == 0 {
            return 0;
        }
        let Some(total) = size.checked_mul(nmemb) else {
            errno::set(75);
            return 0;
        };
        file::read_bytes(f, ptr.cast(), total) / size
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    unsafe { locked!(f, move || fwrite_u(ptr, size, nmemb, f)) }
}

#[inline(always)]
pub(crate) unsafe fn fwrite_u(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    unsafe {
        if size == 0 || nmemb == 0 {
            return 0;
        }
        let Some(total) = size.checked_mul(nmemb) else {
            errno::set(75);
            return 0;
        };
        file::write_bytes(f, ptr.cast(), total) / size
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgets(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    unsafe { locked!(f, move || fgets_u(s, n, f)) }
}

#[inline(always)]
pub(crate) unsafe fn fgets_u(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    unsafe {
        if n <= 0 {
            errno::set(22);
            return null_mut();
        }
        if n == 1 {
            *s = 0;
            return s;
        }
        let mut i = 0usize;
        let max = (n - 1) as usize;
        'line: while i < max {
            let Some((p, avail)) = file::fill_buf(f) else { break };
            let take = avail.min(max - i);
            let nl = rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) as *const u8;
            let k = if nl.is_null() { take } else { nl.offset_from(p) as usize + 1 };
            rusty_libc_mem::memcpy(s.add(i).cast(), p.cast(), k);
            file::consume(f, k);
            i += k;
            if !nl.is_null() {
                break 'line;
            }
        }
        if i == 0 || (*f).flags & F_ERR != 0 && i == 0 {
            return null_mut();
        }
        *s.add(i) = 0;
        s
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || fputs_u(s, f)) }
}

#[inline(always)]
pub(crate) unsafe fn fputs_u(s: *const c_char, f: *mut FILE) -> c_int {
    unsafe {
        let n = rusty_libc_mem::strlen(s);
        if file::write_bytes(f, s.cast(), n) == n { 1 } else { EOF }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    unsafe {
        let out = file::stdout_ptr();
        locked!(out, move || {
            let n = rusty_libc_mem::strlen(s);
            if file::write_bytes(out, s.cast(), n) == n && file::write_bytes(out, b"\n".as_ptr(), 1) == 1 { 1 } else { EOF }
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(f: *mut FILE, offset: c_long, whence: c_int) -> c_int {
    unsafe { locked!(f, move || file::seek(f, offset, whence)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko(f: *mut FILE, offset: off_t, whence: c_int) -> c_int {
    unsafe { locked!(f, move || file::seek(f, offset, whence)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(f: *mut FILE) -> c_long {
    unsafe { locked!(f, move || file::tell(f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftello(f: *mut FILE) -> off_t {
    unsafe { locked!(f, move || file::tell(f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewind(f: *mut FILE) {
    unsafe {
        locked!(f, move || {
            file::seek(f, 0, 0);
            (*f).flags &= !(F_ERR | F_EOF);
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos(f: *mut FILE, pos: *mut fpos_t) -> c_int {
    unsafe {
        locked!(f, move || {
            let p = file::tell(f);
            if p < 0 {
                return -1;
            }
            *pos = fpos_t { pos: p, state: [0; 2] };
            0
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos(f: *mut FILE, pos: *const fpos_t) -> c_int {
    unsafe { locked!(f, move || file::seek(f, (*pos).pos, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feof(f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || c_int::from((*f).flags & F_EOF != 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || c_int::from((*f).flags & F_ERR != 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr(f: *mut FILE) {
    unsafe { locked!(f, move || (*f).flags &= !(F_EOF | F_ERR)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || fileno_u(f)) }
}

#[inline(always)]
pub(crate) unsafe fn fileno_u(f: *mut FILE) -> c_int {
    unsafe {
        if (*f).flags & F_MEM != 0 || (*f).fd < 0 {
            errno::set(9);
            -1
        } else {
            (*f).fd
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setvbuf(f: *mut FILE, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    unsafe { locked!(f, move || file::setvbuf(f, buf, mode, size)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuf(f: *mut FILE, buf: *mut c_char) {
    unsafe {
        locked!(f, move || file::setvbuf(f, buf, if buf.is_null() { 2 } else { 0 }, file::BUFSIZ));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuffer(f: *mut FILE, buf: *mut c_char, size: usize) {
    unsafe {
        locked!(f, move || file::setvbuf(f, buf, if buf.is_null() { 2 } else { 0 }, size));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlinebuf(f: *mut FILE) {
    unsafe {
        locked!(f, move || file::setvbuf(f, null_mut(), 1, 0));
    }
}

struct FileSink(*mut FILE);

impl Sink for FileSink {
    const DIRECT: bool = true;
    fn direct(&mut self, n: usize) -> *mut u8 {
        unsafe {
            let f = &mut *self.0;
            if f.flags & (file::F_WRMODE | file::F_UNBUF | file::F_LBF | file::F_WIDE | file::F_BYTE) == (file::F_WRMODE | file::F_BYTE) && n <= f.wend as usize - f.wptr as usize {
                let p = f.wptr;
                f.wptr = p.add(n);
                p
            } else {
                core::ptr::null_mut()
            }
        }
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            let p = self.direct(bytes.len());
            if !p.is_null() {
                crate::fmt::small_copy(p, bytes.as_ptr(), bytes.len());
                return true;
            }
            file::write_bytes(self.0, bytes.as_ptr(), bytes.len()) == bytes.len()
        }
    }
    fn partial_output_on_error(&self) -> bool {
        false
    }
}

struct UnbufferedSink {
    f: *mut FILE,
    n: usize,
    ok: bool,
    buf: core::mem::MaybeUninit<[u8; file::BUFSIZ]>,
}

impl UnbufferedSink {
    fn flush(&mut self) -> bool {
        if self.n > 0 {
            if unsafe { file::write_bytes(self.f, self.buf.as_ptr().cast::<u8>(), self.n) } != self.n {
                self.ok = false;
            }
            self.n = 0;
        }
        self.ok
    }
}

impl Sink for UnbufferedSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > file::BUFSIZ - self.n && !self.flush() {
            return false;
        }
        if bytes.len() >= file::BUFSIZ {
            self.ok = unsafe { file::write_bytes(self.f, bytes.as_ptr(), bytes.len()) } == bytes.len();
            return self.ok;
        }
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buf.as_mut_ptr().cast::<u8>().add(self.n), bytes.len()) };
        self.n += bytes.len();
        true
    }
    fn partial_output_on_error(&self) -> bool {
        false
    }
}

unsafe fn stream_printf(f: *mut FILE, format: *const c_char, va: &mut VaList) -> c_int {
    unsafe {
        locked!(f, move || {
            if (*f).flags & file::F_UNBUF != 0 {
                let mut sink = UnbufferedSink { f, n: 0, ok: true, buf: core::mem::MaybeUninit::uninit() };
                let r = run(&mut sink, format, va);
                let written = sink.flush();
                return if r >= 0 && !written { -1 } else { r };
            }
            let mut sink = FileSink(f);
            run(&mut sink, format, va)
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vfprintf(f: *mut FILE, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { stream_printf(f, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { stream_printf(file::stdout_ptr(), format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fprintf(f: *mut FILE, format: *const c_char, mut args: ...) -> c_int {
    unsafe { stream_printf(f, format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf(format: *const c_char, mut args: ...) -> c_int {
    unsafe { stream_printf(file::stdout_ptr(), format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn perror(s: *const c_char) {
    unsafe {
        let err = errno::get();
        let mut tmp = [0u8; 40];
        let msg = crate::fmt::strerror_text(err, &mut tmp);
        let mut line = [0u8; 1100];
        let mut n = 0;
        if !s.is_null() && *s != 0 {
            let l = rusty_libc_mem::strlen(s).min(900);
            core::ptr::copy_nonoverlapping(s.cast::<u8>(), line.as_mut_ptr(), l);
            n = l;
            line[n] = b':';
            line[n + 1] = b' ';
            n += 2;
        }
        let m = msg.len().min(line.len() - n - 2);
        line[n..n + m].copy_from_slice(&msg[..m]);
        n += m;
        line[n] = b'\n';
        n += 1;
        let e = file::stderr_ptr();
        let oriented = (*e).flags & (file::F_WIDE | file::F_BYTE) != 0;
        let fd = if oriented { -1 } else { fileno(e) };
        if fd != -1 {
            let d = syscall::syscall1(syscall::SYS_DUP, fd as usize) as isize;
            if d >= 0 {
                let fp = fdopen(d as c_int, c"w+".as_ptr());
                if !fp.is_null() {
                    locked!(fp, move || file::write_bytes(fp, line.as_ptr(), n));
                    if (*fp).flags & file::F_ERR != 0 {
                        (*e).flags |= file::F_ERR;
                    }
                    fclose(fp);
                    return;
                }
                syscall::syscall1(syscall::SYS_CLOSE, d as usize);
            }
        }
        locked!(e, move || {
            if (*e).flags & file::F_WIDE != 0 {
                let mut wide = [0 as rusty_libc_wchar::wchar_t; 1100];
                line[n] = 0;
                let w = rusty_libc_wchar::mbyte::mbstowcs(wide.as_mut_ptr(), line.as_ptr() as *const c_char, wide.len() - 1);
                if w != usize::MAX {
                    for &c in &wide[..w] {
                        crate::wfile::putwc_raw(e, c as rusty_libc_wchar::wint_t);
                    }
                }
            } else {
                file::write_bytes(e, line.as_ptr(), n);
            }
        })
    }
}

unsafe fn grow(lineptr: *mut *mut c_char, n: *mut usize, needed: usize) -> bool {
    unsafe {
        let newn = needed.max(*n * 2);
        let p = rusty_libc_malloc::realloc((*lineptr).cast(), newn) as *mut c_char;
        if p.is_null() {
            return false;
        }
        *lineptr = p;
        *n = newn;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize {
    unsafe { locked!(f, move || getdelim_u(lineptr, n, delim, f)) }
}

#[inline(always)]
unsafe fn getdelim_u(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize {
    unsafe {
        if (*f).flags & F_ERR != 0 {
            return -1;
        }
        if lineptr.is_null() || n.is_null() {
            (*f).flags |= F_ERR;
            errno::set(22);
            return -1;
        }
        if (*lineptr).is_null() || *n == 0 {
            let p = rusty_libc_malloc::malloc(120) as *mut c_char;
            if p.is_null() {
                (*f).flags |= F_ERR;
                return -1;
            }
            *lineptr = p;
            *n = 120;
            *p = 0;
        }
        let mut len = 0usize;
        'outer: loop {
            if (*f).nunget() > 0 {
                let c = file::getc(f);
                if len + 2 > *n && !grow(lineptr, n, len + 2) {
                    (*f).flags |= F_ERR;
                    return -1;
                }
                *(*lineptr).add(len) = c as c_char;
                len += 1;
                if c == delim {
                    break;
                }
                continue;
            }
            let Some((p, avail)) = file::fill_buf(f) else {
                if len == 0 {
                    return -1;
                }
                break 'outer;
            };
            let dp = rusty_libc_mem::memchr(p.cast(), delim, avail) as *const u8;
            let k = if dp.is_null() { avail } else { dp.offset_from(p) as usize + 1 };
            if len + k + 1 > *n && !grow(lineptr, n, len + k + 1) {
                (*f).flags |= F_ERR;
                return -1;
            }
            rusty_libc_mem::memcpy((*lineptr).add(len).cast(), p.cast(), k);
            file::consume(f, k);
            len += k;
            if !dp.is_null() {
                break 'outer;
            }
        }
        *(*lineptr).add(len) = 0;
        len as isize
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getline(lineptr: *mut *mut c_char, n: *mut usize, f: *mut FILE) -> isize {
    unsafe { getdelim(lineptr, n, c_int::from(b'\n'), f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    unsafe {
        let r = syscall::syscall1(syscall::SYS_UNLINK, path as usize);
        if r <= usize::MAX - 4095 {
            return 0;
        }
        let e = (r as isize).wrapping_neg() as i32;
        if e == 21 {
            let r = syscall::syscall1(syscall::SYS_RMDIR, path as usize);
            if r <= usize::MAX - 4095 {
                return 0;
            }
            errno::set((r as isize).wrapping_neg() as i32);
            return -1;
        }
        errno::set(e);
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    unsafe {
        let r = syscall::syscall2(syscall::SYS_RENAME, old as usize, new as usize);
        if r <= usize::MAX - 4095 {
            0
        } else {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpfile() -> *mut FILE {
    unsafe {
        const O_TMPFILE_RDWR: c_int = 0o20200000 | 2;
        let fd = rusty_libc_core::unistd::open(c"/tmp".as_ptr(), O_TMPFILE_RDWR, 0o600);
        let fd = match fd {
            Ok(fd) => fd,
            Err(_) => {
                let mut name = *b"/tmp/tmpf_XXXXXX\0";
                let t = core::arch::x86_64::_rdtsc();
                for i in 0..6 {
                    name[10 + i] = b"abcdefghijklmnopqrstuvwxyz012345"[((t >> (5 * i)) & 31) as usize];
                }
                match rusty_libc_core::unistd::open(name.as_ptr().cast(), 2 | 0o100 | 0o200, 0o600) {
                    Ok(fd) => {
                        syscall::syscall1(syscall::SYS_UNLINK, name.as_ptr() as usize);
                        fd
                    }
                    Err(e) => {
                        errno::set(e.0);
                        return null_mut();
                    }
                }
            }
        };
        let f = file::alloc_file(F_READ | F_WRITE, fd);
        if f.is_null() {
            let _ = rusty_libc_core::unistd::close(fd);
        }
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn flockfile(f: *mut FILE) {
    unsafe {
        file::note_locking();
        (*f).lock.lock();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftrylockfile(f: *mut FILE) -> c_int {
    unsafe {
        file::note_locking();
        if (*f).lock.try_lock() { 0 } else { 1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn funlockfile(f: *mut FILE) {
    unsafe {
        (*f).lock.unlock();
    }
}

#[allow(dead_code)]
const _: u32 = F_WRITE | F_NOSEEK;

