use crate::file::{self, EOF, F_ERR, F_EOF, F_MEM, F_NOSEEK, F_WRITE, F_READ, File as FILE};
use crate::flock::locked;
use crate::fmt::Sink;
use crate::printf_api::run;
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi, syscall};

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
pub static stdin: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDIN_FILE));
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stdout: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDOUT_FILE));
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stderr: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDERR_FILE));

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    let path = unsafe { ffi::cstr(path) };
    let mode = unsafe { ffi::cstr_bytes(mode) };
    file::fopen(path, mode)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut FILE {
    file::fdopen(fd, unsafe { ffi::cstr_bytes(mode) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> c_int {
    unsafe { file::fclose(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(f: *mut FILE) -> c_int {
    if f.is_null() {
        return if file::flush_all() { 0 } else { EOF };
    }
    locked!(f, |s| file::fflush(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc(f: *mut FILE) -> c_int {
    locked!(f, |s| file::getc(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getc(f: *mut FILE) -> c_int {
    locked!(f, |s| file::getc(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getchar() -> c_int {
    locked!(file::stdin_ptr(), |s| file::getc(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::putc(c, s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::putc(c, s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn putchar(c: c_int) -> c_int {
    locked!(file::stdout_ptr(), |s| file::putc(c, s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::ungetc(c, s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fread(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    locked!(f, |s| unsafe { fread_s(ptr, size, nmemb, s) })
}

#[inline(always)]
pub(crate) unsafe fn fread_u(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    let s = unsafe { file::stream(f) };
    unsafe { fread_s(ptr, size, nmemb, s) }
}

#[inline(always)]
unsafe fn fread_s(ptr: *mut c_void, size: usize, nmemb: usize, f: &mut FILE) -> usize {
    if size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else {
        errno::set(75);
        return 0;
    };
    file::read_bytes(f, unsafe { core::slice::from_raw_parts_mut(ptr.cast(), total) }) / size
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    locked!(f, |s| unsafe { fwrite_s(ptr, size, nmemb, s) })
}

#[inline(always)]
pub(crate) unsafe fn fwrite_u(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    let s = unsafe { file::stream(f) };
    unsafe { fwrite_s(ptr, size, nmemb, s) }
}

#[inline(always)]
unsafe fn fwrite_s(ptr: *const c_void, size: usize, nmemb: usize, f: &mut FILE) -> usize {
    if size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else {
        errno::set(75);
        return 0;
    };
    file::write_bytes(f, unsafe { core::slice::from_raw_parts(ptr.cast(), total) }) / size
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgets(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    locked!(f, |st| unsafe { fgets_s(s, n, st) })
}

#[inline(always)]
pub(crate) unsafe fn fgets_u(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    let st = unsafe { file::stream(f) };
    unsafe { fgets_s(s, n, st) }
}

#[inline(always)]
unsafe fn fgets_s(s: *mut c_char, n: c_int, f: &mut FILE) -> *mut c_char {
    if n <= 0 {
        errno::set(22);
        return null_mut();
    }
    let buf = unsafe { ffi::bytes_mut(s.cast(), n as usize) };
    if read_line(buf, f) { s } else { null_mut() }
}

#[inline(always)]
pub fn read_line(buf: &mut [u8], f: &mut FILE) -> bool {
    let max = buf.len() - 1;
    if max == 0 {
        buf[0] = 0;
        return true;
    }
    let dst = buf.as_mut_ptr();
    let mut out = dst;
    let mut room = max;
    while room > 0 {
        let win = if file::window_ready(f) {
            f.window()
        } else {
            match file::fill_buf_slow(f) {
                Some(w) => w,
                None => break,
            }
        };
        let p = win.as_ptr();
        let take = win.len().min(room);
        let nl = unsafe { rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) } as *const u8;
        let k = if nl.is_null() { take } else { nl as usize - p as usize + 1 };
        unsafe { file::copy_raw(out, p, k) };
        file::consume(f, k);
        out = out.wrapping_add(k);
        room -= k;
        if !nl.is_null() {
            break;
        }
    }
    let i = max - room;
    if i == 0 {
        return false;
    }
    buf[i.min(max)] = 0;
    true
}

#[inline(always)]
pub(crate) fn find_byte(hay: &[u8], b: u8) -> Option<usize> {
    let p = unsafe { rusty_libc_mem::memchr(hay.as_ptr().cast(), c_int::from(b), hay.len()) } as *const u8;
    if p.is_null() { None } else { Some(p as usize - hay.as_ptr() as usize) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut FILE) -> c_int {
    let text = unsafe { ffi::cstr_bytes(s) };
    locked!(f, |st| put_text(text, st))
}

#[inline(always)]
pub(crate) unsafe fn fputs_u(s: *const c_char, f: *mut FILE) -> c_int {
    let text = unsafe { ffi::cstr_bytes(s) };
    put_text(text, unsafe { file::stream(f) })
}

#[inline(always)]
pub fn put_text(text: &[u8], f: &mut FILE) -> c_int {
    if file::write_bytes(f, text) == text.len() { 1 } else { EOF }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    let text = unsafe { ffi::cstr_bytes(s) };
    locked!(file::stdout_ptr(), |out| if file::write_bytes(out, text) == text.len() && file::write_bytes(out, b"\n") == 1 { 1 } else { EOF })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(f: *mut FILE, offset: c_long, whence: c_int) -> c_int {
    locked!(f, |s| file::seek(s, offset, whence))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko(f: *mut FILE, offset: off_t, whence: c_int) -> c_int {
    locked!(f, |s| file::seek(s, offset, whence))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(f: *mut FILE) -> c_long {
    locked!(f, |s| file::tell(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftello(f: *mut FILE) -> off_t {
    locked!(f, |s| file::tell(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewind(f: *mut FILE) {
    locked!(f, |s| {
        file::seek(s, 0, 0);
        s.flags &= !(F_ERR | F_EOF);
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos(f: *mut FILE, pos: *mut fpos_t) -> c_int {
    locked!(f, |s| {
        let p = file::tell(s);
        if p < 0 {
            return -1;
        }
        unsafe { pos.write(fpos_t { pos: p, state: [0; 2] }) };
        0
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos(f: *mut FILE, pos: *const fpos_t) -> c_int {
    locked!(f, |s| file::seek(s, unsafe { (*pos).pos }, 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feof(f: *mut FILE) -> c_int {
    locked!(f, |s| c_int::from(s.flags & F_EOF != 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(f: *mut FILE) -> c_int {
    locked!(f, |s| c_int::from(s.flags & F_ERR != 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr(f: *mut FILE) {
    locked!(f, |s| s.flags &= !(F_EOF | F_ERR))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(f: *mut FILE) -> c_int {
    locked!(f, |s| fileno_s(s))
}

#[inline(always)]
pub(crate) unsafe fn fileno_u(f: *mut FILE) -> c_int {
    fileno_s(unsafe { file::stream(f) })
}

#[inline(always)]
pub fn fileno_s(f: &FILE) -> c_int {
    if f.flags & F_MEM != 0 || f.fd < 0 {
        errno::set(9);
        -1
    } else {
        f.fd
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setvbuf(f: *mut FILE, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    locked!(f, |s| unsafe { file::setvbuf(s, buf, mode, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuf(f: *mut FILE, buf: *mut c_char) {
    locked!(f, |s| unsafe { file::setvbuf(s, buf, if buf.is_null() { 2 } else { 0 }, file::BUFSIZ) });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuffer(f: *mut FILE, buf: *mut c_char, size: usize) {
    locked!(f, |s| unsafe { file::setvbuf(s, buf, if buf.is_null() { 2 } else { 0 }, size) });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlinebuf(f: *mut FILE) {
    locked!(f, |s| unsafe { file::setvbuf(s, null_mut(), 1, 0) });
}

struct FileSink(*mut FILE);

impl FileSink {
    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        unsafe { file::stream(self.0) }
    }
}

impl Sink for FileSink {
    const DIRECT: bool = true;
    fn direct(&mut self, n: usize) -> *mut u8 {
        let f = self.stream();
        if f.flags & (file::F_WRMODE | file::F_UNBUF | file::F_LBF | file::F_WIDE | file::F_BYTE) == (file::F_WRMODE | file::F_BYTE) && n <= f.wend as usize - f.wptr as usize {
            let p = f.wptr;
            f.wptr = p.wrapping_add(n);
            p
        } else {
            core::ptr::null_mut()
        }
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        let p = self.direct(bytes.len());
        if !p.is_null() {
            unsafe { crate::fmt::small_copy(p, bytes.as_ptr(), bytes.len()) };
            return true;
        }
        file::write_bytes(self.stream(), bytes) == bytes.len()
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
    #[inline(always)]
    fn filled(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast::<u8>(), self.n) }
    }

    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        unsafe { file::stream(self.f) }
    }

    #[cold]
    #[inline(never)]
    fn put_slow(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > file::BUFSIZ - self.n && !self.flush() {
            return false;
        }
        if bytes.len() >= file::BUFSIZ {
            self.ok = file::write_bytes(self.stream(), bytes) == bytes.len();
            return false;
        }
        true
    }

    fn flush(&mut self) -> bool {
        if self.n > 0 {
            let st = unsafe { file::stream(self.f) };
            if file::write_bytes(st, self.filled()) != self.n {
                self.ok = false;
            }
            self.n = 0;
        }
        self.ok
    }
}

impl Sink for UnbufferedSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if (bytes.len() > file::BUFSIZ - self.n || bytes.len() >= file::BUFSIZ) && !self.put_slow(bytes) {
            return self.ok;
        }
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buf.as_mut_ptr().cast::<u8>().wrapping_add(self.n), bytes.len()) };
        self.n += bytes.len();
        true
    }
    fn partial_output_on_error(&self) -> bool {
        false
    }
}

unsafe fn stream_printf(f: *mut FILE, format: *const c_char, va: &mut VaList) -> c_int {
    locked!(f, |s| {
        let unbuffered = s.flags & file::F_UNBUF != 0;
        if unbuffered {
            let mut sink = UnbufferedSink { f, n: 0, ok: true, buf: core::mem::MaybeUninit::uninit() };
            let r = unsafe { run(&mut sink, format, va) };
            let written = sink.flush();
            return if r >= 0 && !written { -1 } else { r };
        }
        let mut sink = FileSink(f);
        unsafe { run(&mut sink, format, va) }
    })
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
    let prefix = unsafe { ffi::cstr(s) }.map_or(&[][..], |c| c.to_bytes());
    perror_text(prefix);
}

pub fn perror_text(prefix: &[u8]) {
    let err = errno::get();
    let mut tmp;
    let msg = match rusty_libc_core::messages::error_message_tr(err) {
        Some(m) => m.to_bytes(),
        None => {
            tmp = [0u8; 128];
            crate::fmt::strerror_text(err, &mut tmp)
        }
    };
    let mut line = [0u8; 1100];
    let mut n = 0;
    if !prefix.is_empty() {
        let l = prefix.len().min(900);
        line[..l].copy_from_slice(&prefix[..l]);
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
    let oriented = unsafe { (*e).flags } & (file::F_WIDE | file::F_BYTE) != 0;
    let fd = if oriented { -1 } else { unsafe { fileno(e) } };
    if fd != -1
        && let Ok(d) = rusty_libc_core::unistd::dup(fd)
    {
        let fp = file::fdopen(d, b"w+");
        if !fp.is_null() {
            let failed = locked!(fp, |s| {
                file::write_bytes(s, &line[..n]);
                s.flags & file::F_ERR != 0
            });
            if failed {
                unsafe { (*e).flags |= file::F_ERR };
            }
            unsafe { fclose(fp) };
            return;
        }
        let _ = rusty_libc_core::unistd::close(d);
    }
    locked!(e, |s| {
        if s.flags & file::F_WIDE != 0 {
            let mut wide = [0 as rusty_libc_wchar::wchar_t; 1100];
            line[n] = 0;
            let w = unsafe { rusty_libc_wchar::mbyte::mbstowcs(wide.as_mut_ptr(), line.as_ptr() as *const c_char, wide.len() - 1) };
            if w != usize::MAX {
                for &c in &wide[..w] {
                    crate::wfile::putwc_raw(s, c as rusty_libc_wchar::wint_t);
                }
            }
        } else {
            file::write_bytes(s, &line[..n]);
        }
    })
}

struct LineBuf<'a> {
    ptr: &'a mut *mut c_char,
    cap: &'a mut usize,
}

impl LineBuf<'_> {
    fn grow(&mut self, needed: usize) -> bool {
        let newn = needed.max(*self.cap * 2);
        let p = unsafe { rusty_libc_malloc::realloc((*self.ptr).cast(), newn) } as *mut c_char;
        if p.is_null() {
            return false;
        }
        *self.ptr = p;
        *self.cap = newn;
        true
    }

    fn bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut((*self.ptr).cast(), *self.cap) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize {
    locked!(f, |s| {
        if s.flags & F_ERR != 0 {
            return -1;
        }
        let (Some(ptr), Some(cap)) = (unsafe { ffi::out(lineptr) }, unsafe { ffi::out(n) }) else {
            s.flags |= F_ERR;
            errno::set(22);
            return -1;
        };
        getdelim_s(LineBuf { ptr, cap }, delim, s)
    })
}

#[inline(always)]
fn getdelim_s(mut line: LineBuf, delim: c_int, f: &mut FILE) -> isize {
    if (*line.ptr).is_null() || *line.cap == 0 {
        let p = file::alloc(120);
        if p.is_null() {
            f.flags |= F_ERR;
            return -1;
        }
        *line.ptr = p.cast();
        *line.cap = 120;
        line.bytes()[0] = 0;
    }
    let mut len = 0usize;
    loop {
        if f.nunget() > 0 {
            let c = file::getc(f);
            if len + 2 > *line.cap && !line.grow(len + 2) {
                f.flags |= F_ERR;
                return -1;
            }
            line.bytes()[len] = c as u8;
            len += 1;
            if c == delim {
                break;
            }
            continue;
        }
        let win = if file::window_ready(f) {
            f.window()
        } else {
            match file::fill_buf_slow(f) {
                Some(w) => w,
                None => {
                    if len == 0 {
                        return -1;
                    }
                    break;
                }
            }
        };
        let dp = find_byte(win, delim as u8);
        let k = dp.map_or(win.len(), |j| j + 1);
        if len + k + 1 > *line.cap && !line.grow(len + k + 1) {
            f.flags |= F_ERR;
            return -1;
        }
        unsafe { file::copy_raw((*line.ptr).cast::<u8>().wrapping_add(len), f.rptr, k) };
        file::consume(f, k);
        len += k;
        if dp.is_some() {
            break;
        }
    }
    line.bytes()[len] = 0;
    len as isize
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getline(lineptr: *mut *mut c_char, n: *mut usize, f: *mut FILE) -> isize {
    unsafe { getdelim(lineptr, n, c_int::from(b'\n'), f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    let r = unsafe { syscall::syscall1(syscall::SYS_UNLINK, path as usize) };
    let e = match syscall::check(r) {
        Ok(_) => return 0,
        Err(e) => e.0,
    };
    if e == 21 {
        let r = unsafe { syscall::syscall1(syscall::SYS_RMDIR, path as usize) };
        return match syscall::check(r) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        };
    }
    errno::set(e);
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    let r = unsafe { syscall::syscall2(syscall::SYS_RENAME, old as usize, new as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tmpfile() -> *mut FILE {
    tmpfile_s()
}

pub fn tmpfile_s() -> *mut FILE {
    const O_TMPFILE_RDWR: c_int = 0o20200000 | 2;
    let fd = unsafe { rusty_libc_core::unistd::open(c"/tmp".as_ptr(), O_TMPFILE_RDWR, 0o600) };
    let fd = match fd {
        Ok(fd) => fd,
        Err(_) => {
            let mut name = *b"/tmp/tmpf_XXXXXX\0";
            let t = unsafe { core::arch::x86_64::_rdtsc() };
            for i in 0..6 {
                name[10 + i] = b"abcdefghijklmnopqrstuvwxyz012345"[((t >> (5 * i)) & 31) as usize];
            }
            match unsafe { rusty_libc_core::unistd::open(name.as_ptr().cast(), 2 | 0o100 | 0o200, 0o600) } {
                Ok(fd) => {
                    unsafe { syscall::syscall1(syscall::SYS_UNLINK, name.as_ptr() as usize) };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn flockfile(f: *mut FILE) {
    file::note_locking();
    unsafe { file::lock_of(f) }.lock();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftrylockfile(f: *mut FILE) -> c_int {
    file::note_locking();
    if unsafe { file::lock_of(f) }.try_lock() { 0 } else { 1 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn funlockfile(f: *mut FILE) {
    unsafe { file::lock_of(f) }.unlock();
}

#[allow(dead_code)]
const _: u32 = F_WRITE | F_NOSEEK;

