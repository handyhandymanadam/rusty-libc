#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, VaList, c_char, c_int};
#[cfg(not(feature = "export"))]
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, process, syscall};
use rusty_libc_stdio::file;
use rusty_libc_stdio::fmt::Sink;
use rusty_libc_stdio::printf_api::run;
use rusty_libc_stdio::rust_api::{Arg, format_to};

#[cfg(feature = "export")]
core::arch::global_asm!(
    ".data",
    ".balign 8",
    ".globl program_invocation_name",
    ".globl __progname_full",
    "program_invocation_name:",
    "__progname_full:",
    ".quad 0",
    ".type program_invocation_name, @object",
    ".size program_invocation_name, 8",
    ".type __progname_full, @object",
    ".size __progname_full, 8",
    ".globl program_invocation_short_name",
    ".globl __progname",
    "program_invocation_short_name:",
    "__progname:",
    ".quad 0",
    ".type program_invocation_short_name, @object",
    ".size program_invocation_short_name, 8",
    ".type __progname, @object",
    ".size __progname, 8",
    ".globl __libc_argc",
    "__libc_argc:",
    ".long 0",
    ".long 0",
    ".type __libc_argc, @object",
    ".size __libc_argc, 8",
    ".globl __libc_argv",
    "__libc_argv:",
    ".quad 0",
    ".type __libc_argv, @object",
    ".size __libc_argv, 8",
    ".text",
    ".globl __init_misc",
    ".type __init_misc, @function",
    "__init_misc:",
    "    jmp {init}",
    init = sym __init_misc,
);

#[cfg(feature = "export")]
unsafe extern "C" {
    static mut program_invocation_name: *mut c_char;
    static mut program_invocation_short_name: *mut c_char;
    static mut __progname: *mut c_char;
    static mut __progname_full: *mut c_char;
    static mut __libc_argc: c_int;
    static mut __libc_argv: *mut *mut c_char;
}

#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut __libc_argc: c_int = 0;
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut __libc_argv: *mut *mut c_char = null_mut();

pub unsafe fn set_args(argc: c_int, argv: *mut *mut c_char) {
    unsafe { __libc_argc = argc };
    unsafe { __libc_argv = argv };
}

pub(crate) fn args() -> (c_int, *mut *mut c_char) {
    let argc = unsafe { __libc_argc };
    (argc, unsafe { __libc_argv })
}

fn short_name() -> *const c_char {
    unsafe { program_invocation_short_name }
}

fn full_name() -> *const c_char {
    unsafe { program_invocation_name }
}

fn prog_bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { name_bytes(p) }
}

#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_name: *mut c_char = null_mut();
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_short_name: *mut c_char = null_mut();

pub unsafe fn set_program_name(argv0: *mut c_char) {
    let Some(s) = (unsafe { rusty_libc_core::ffi::cstr(argv0) }) else { return };
    let short = match s.to_bytes().iter().rposition(|&c| c == b'/') {
        Some(i) => argv0.wrapping_add(i + 1),
        None => argv0,
    };
    unsafe { program_invocation_name = argv0 };
    unsafe { program_invocation_short_name = short };
    #[cfg(feature = "export")]
    {
        unsafe { __progname_full = argv0 };
        unsafe { __progname = short };
    }
}

pub unsafe extern "C" fn __init_misc(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    unsafe { set_args(argc, argv) };
    if !argv.is_null() {
        let argv0 = unsafe { *argv };
        unsafe { set_program_name(argv0) };
    }
}

pub(crate) unsafe fn name_bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { rusty_libc_core::ffi::cstr(p) }.map_or(b"(null)", core::ffi::CStr::to_bytes)
}

fn stderr() -> *mut file::File {
    file::stderr_ptr()
}

fn lock_stderr(g: &mut rusty_libc_stdio::flock::StreamGuard) {
    let e = stderr();
    unsafe { g.lock(e) };
}

fn write_stderr(src: &[u8]) -> usize {
    let e = stderr();
    if unsafe { (*e).flags } & file::F_WIDE == 0 {
        return file::write_bytes(unsafe { file::stream(e) }, src);
    }
    let n = src.len();
    let mut st = rusty_libc_wchar::mbstate_t::default();
    let mut done = 0;
    while done < n {
        let mut wc: rusty_libc_wchar::wchar_t = 0;
        let rest = &src[done..];
        let k = unsafe { rusty_libc_wchar::mbyte::mbrtowc(&mut wc, rest.as_ptr().cast(), rest.len(), &mut st) };
        let k = match k {
            k if k >= usize::MAX - 1 => return done,
            0 => 1,
            k => k,
        };
        if rusty_libc_stdio::wfile::putwc_raw(unsafe { file::stream(e) }, wc as rusty_libc_wchar::wint_t) == rusty_libc_wchar::WEOF {
            return done;
        }
        done += k;
    }
    n
}

pub(crate) struct Out {
    buf: [u8; 1024],
    n: usize,
    ok: bool,
}

impl Out {
    pub(crate) fn new() -> Out {
        Out { buf: [0; 1024], n: 0, ok: true }
    }
    pub(crate) fn flush(&mut self) {
        if self.n > 0 {
            let n = write_stderr(&self.buf[..self.n]);
            if n != self.n {
                self.ok = false;
            }
            self.n = 0;
        }
    }
    #[inline]
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        let _ = self.put(b);
    }
}

impl Sink for Out {
    #[inline]
    fn put(&mut self, bytes: &[u8]) -> bool {
        let end = self.n + bytes.len();
        if end <= self.buf.len() && bytes.len() < self.buf.len() {
            self.buf[self.n..end].copy_from_slice(bytes);
            self.n = end;
            return self.ok;
        }
        self.put_slow(bytes)
    }
}

impl Out {
    #[cold]
    #[inline(never)]
    fn put_slow(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.buf.len() - self.n {
            self.flush();
        }
        if bytes.len() >= self.buf.len() {
            let n = write_stderr(bytes);
            if n != bytes.len() {
                self.ok = false;
            }
        } else {
            self.buf[self.n..self.n + bytes.len()].copy_from_slice(bytes);
            self.n += bytes.len();
        }
        self.ok
    }
}

fn strerror_text(code: i32, buf: &mut [u8; 128]) -> &[u8] {
    rusty_libc_core::messages::strerror_r_text(code, buf)
}

type Body<'a> = &'a mut dyn FnMut(&mut Out);

fn vwarn_with(has_format: bool, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    let saved = errno::get();
    let mut o = Out::new();
    let prog = prog_bytes(short_name());
    if has_format {
        o.bytes(prog);
        o.bytes(b": ");
        body(&mut o);
        errno::set(saved);
        o.bytes(b": ");
    } else {
        errno::set(saved);
        o.bytes(prog);
        o.bytes(b": ");
    }
    let mut tmp = [0u8; 128];
    o.bytes(strerror_text(saved, &mut tmp));
    o.bytes(b"\n");
    o.flush();
    errno::set(saved);
}

fn vwarnx_with(has_format: bool, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    let mut o = Out::new();
    o.bytes(prog_bytes(short_name()));
    o.bytes(b": ");
    if has_format {
        body(&mut o);
    }
    o.bytes(b"\n");
    o.flush();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarn(format: *const c_char, mut ap: VaList) {
    vwarn_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut ap) };
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnx(format: *const c_char, mut ap: VaList) {
    vwarnx_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut ap) };
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verr(status: c_int, format: *const c_char, ap: VaList) -> ! {
    unsafe { vwarn(format, ap) };
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verrx(status: c_int, format: *const c_char, ap: VaList) -> ! {
    unsafe { vwarnx(format, ap) };
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warn(format: *const c_char, mut args: ...) {
    vwarn_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut args) };
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warnx(format: *const c_char, mut args: ...) {
    vwarnx_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut args) };
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn err(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarn_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut args) };
    });
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn errx(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarnx_with(!format.is_null(), &mut |o| {
        unsafe { run(o, format, &mut args) };
    });
    process::exit(status)
}

pub fn warn_args(format: Option<&CStr>, args: &[Arg]) {
    vwarn_with(format.is_some(), &mut |o| {
        if let Some(f) = format {
            format_to(o, f, args);
        }
    });
}

pub fn warnx_args(format: Option<&CStr>, args: &[Arg]) {
    vwarnx_with(format.is_some(), &mut |o| {
        if let Some(f) = format {
            format_to(o, f, args);
        }
    });
}

pub fn err_args(status: i32, format: Option<&CStr>, args: &[Arg]) -> ! {
    warn_args(format, args);
    process::exit(status)
}

pub fn errx_args(status: i32, format: Option<&CStr>, args: &[Arg]) -> ! {
    warnx_args(format, args);
    process::exit(status)
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_print_progname: Option<unsafe extern "C" fn()> = None;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_message_count: u32 = 0;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_one_per_line: c_int = 0;

fn flush_stdout() {
    let out = file::stdout_ptr();
    unsafe { rusty_libc_stdio::fflush(out) };
}

fn error_tail(o: &mut Out, status: c_int, errnum: c_int, body: Body) {
    body(o);
    let count = unsafe { error_message_count };
    unsafe { error_message_count = count.wrapping_add(1) };
    if errnum != 0 {
        o.bytes(b": ");
        let mut tmp = [0u8; 128];
        o.bytes(strerror_text(errnum, &mut tmp));
    }
    o.bytes(b"\n");
    o.flush();
    let e = stderr();
    file::fflush(unsafe { file::stream(e) });
    if status != 0 {
        process::exit(status);
    }
}

fn print_progname_fn() -> Option<unsafe extern "C" fn()> {
    unsafe { error_print_progname }
}

#[inline(always)]
fn progname_part(o: &mut Out, sep: &[u8]) {
    if let Some(f) = print_progname_fn() {
        o.flush();
        unsafe { f() };
    } else {
        o.bytes(prog_bytes(full_name()));
        o.bytes(sep);
    }
}

fn error_with(status: c_int, errnum: c_int, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    flush_stdout();
    let mut o = Out::new();
    progname_part(&mut o, b": ");
    error_tail(&mut o, status, errnum, body);
}

static OLD: SyncCell<(*const c_char, u32)> = SyncCell::new((core::ptr::null(), 0));

fn error_at_line_with(status: c_int, errnum: c_int, file_name: *const c_char, line: u32, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    if unsafe { error_one_per_line } != 0 {
        let (old_file, old_line) = unsafe { OLD.read() };
        if old_line == line && (file_name == old_file || (!old_file.is_null() && !file_name.is_null() && unsafe { rusty_libc_core::ffi::cstr_eq(old_file, file_name) })) {
            return;
        }
        unsafe { OLD.write((file_name, line)) };
    }
    flush_stdout();
    let mut o = Out::new();
    progname_part(&mut o, b":");
    if file_name.is_null() {
        o.bytes(b" ");
    } else {
        o.bytes(unsafe { name_bytes(file_name) });
        o.bytes(b":");
        let mut tmp = [0u8; 12];
        o.bytes(fmt_i32(line as i32, &mut tmp));
        o.bytes(b": ");
    }
    error_tail(&mut o, status, errnum, body);
}

fn fmt_i32(v: i32, buf: &mut [u8; 12]) -> &[u8] {
    let mut i = 12;
    let mut x = i64::from(v).unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    if v < 0 {
        i -= 1;
        buf[i] = b'-';
    }
    &buf[i..]
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn error(status: c_int, errnum: c_int, message: *const c_char, mut args: ...) {
    error_with(status, errnum, &mut |o| {
        unsafe { run(o, message, &mut args) };
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn error_at_line(status: c_int, errnum: c_int, file_name: *const c_char, line_number: u32, message: *const c_char, mut args: ...) {
    error_at_line_with(status, errnum, file_name, line_number, &mut |o| {
        unsafe { run(o, message, &mut args) };
    });
}

pub fn error_args(status: i32, errnum: i32, format: &CStr, args: &[Arg]) {
    error_with(status, errnum, &mut |o| {
        format_to(o, format, args);
    });
}

pub fn error_at_line_args(status: i32, errnum: i32, file_name: Option<&CStr>, line: u32, format: &CStr, args: &[Arg]) {
    let f = file_name.map_or(core::ptr::null(), |c| c.as_ptr());
    error_at_line_with(status, errnum, f, line, &mut |o| {
        format_to(o, format, args);
    });
}

const SYS_WRITEV: usize = 20;

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

fn write_pieces(pieces: &[&[u8]]) {
    let mut iov = [const { IoVec { base: core::ptr::null(), len: 0 } }; 16];
    let mut n = 0;
    let mut total = 0usize;
    for p in pieces {
        if !p.is_empty() && n < iov.len() {
            iov[n] = IoVec { base: p.as_ptr(), len: p.len() };
            n += 1;
            total += p.len();
        }
    }
    let mut start = 0;
    let mut left = total;
    while left > 0 {
        let r = unsafe { syscall::syscall3(SYS_WRITEV, 2, iov[start..].as_ptr() as usize, n - start) };
        match syscall::check(r) {
            Ok(mut w) => {
                left -= w;
                while start < n && w >= iov[start].len {
                    w -= iov[start].len;
                    start += 1;
                }
                if start < n && w > 0 {
                    iov[start].base = iov[start].base.wrapping_add(w);
                    iov[start].len -= w;
                }
            }
            Err(e) if e.0 == errno::EINTR => {}
            Err(_) => break,
        }
    }
}

fn fmt_u32(mut x: u32, buf: &mut [u8; 12]) -> &[u8] {
    let mut i = 12;
    loop {
        i -= 1;
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    &buf[i..]
}

fn assert_prog<'a>() -> &'a [u8] {
    let p = short_name();
    if p.is_null() { b"" } else { prog_bytes(p) }
}

fn assert_message(label: &[u8], text: &[u8], suffix: &[u8], file: &[u8], line: u32, function: Option<&[u8]>) {
    let prog = assert_prog();
    let mut lb = [0u8; 12];
    write_pieces(&[
        prog,
        if prog.is_empty() { b"" } else { b": " },
        file,
        b":",
        fmt_u32(line, &mut lb),
        b": ",
        function.unwrap_or(b""),
        if function.is_none() { b"" } else { b": " },
        label,
        text,
        suffix,
    ]);
}

fn assert_translated(msgid: &'static core::ffi::CStr, text: &[u8], file: &[u8], line: u32, function: Option<&[u8]>) -> bool {
    let t = rusty_libc_core::i18n::tr(msgid);
    if core::ptr::eq(t.as_ptr(), msgid.as_ptr()) {
        return false;
    }
    let prog = assert_prog();
    let mut lb = [0u8; 12];
    let args: [&[u8]; 7] = [prog, if prog.is_empty() { b"" } else { b": " }, file, fmt_u32(line, &mut lb), function.unwrap_or(b""), if function.is_none() { b"" } else { b": " }, text];
    let mut pieces: [&[u8]; 15] = [b""; 15];
    let mut n = 0;
    let mut too_many = false;
    rusty_libc_core::i18n::libc_message_pieces(t.to_bytes(), &args, &mut |p| {
        if n < pieces.len() {
            pieces[n] = p;
            n += 1;
        } else {
            too_many = true;
        }
    });
    if too_many {
        write_pieces(&[b"Fatal glibc error: Internal __libc_message error. Too many arguments.\n"]);
    } else {
        write_pieces(&pieces[..n]);
    }
    true
}

unsafe fn assert_where<'a>(file: *const c_char, function: *const c_char) -> (&'a [u8], Option<&'a [u8]>) {
    let f = unsafe { name_bytes(file) };
    (f, unsafe { rusty_libc_core::ffi::cstr(function) }.map(CStr::to_bytes))
}

pub fn assert_fail_message(assertion: &[u8], file: &[u8], line: u32, function: Option<&[u8]>) {
    if !assert_translated(c"%s%s%s:%s: %s%sAssertion `%s' failed.\n", assertion, file, line, function) {
        assert_message(b"Assertion `", assertion, b"' failed.\n", file, line, function);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_fail(assertion: *const c_char, file: *const c_char, line: u32, function: *const c_char) -> ! {
    let (f, func) = unsafe { assert_where(file, function) };
    let a = unsafe { name_bytes(assertion) };
    assert_fail_message(a, f, line, func);
    process::abort()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_perror_fail(errnum: c_int, file: *const c_char, line: u32, function: *const c_char) -> ! {
    let (f, func) = unsafe { assert_where(file, function) };
    let mut tmp = [0u8; 128];
    let e = strerror_text(errnum, &mut tmp);
    if !assert_translated(c"%s%s%s:%s: %s%sUnexpected error: %s.\n", e, f, line, func) {
        assert_message(b"Unexpected error: ", e, b".\n", f, line, func);
    }
    process::abort()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert(assertion: *const c_char, file: *const c_char, line: c_int) -> ! {
    unsafe { __assert_fail(assertion, file, line as u32, core::ptr::null()) }
}
