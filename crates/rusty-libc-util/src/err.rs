use core::ffi::{CStr, VaList, c_char, c_int};
#[cfg(not(feature = "export"))]
use core::ptr::null_mut;
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
    unsafe {
        __libc_argc = argc;
        __libc_argv = argv;
    }
}

pub(crate) fn args() -> (c_int, *mut *mut c_char) {
    unsafe { (__libc_argc, __libc_argv) }
}

#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_name: *mut c_char = null_mut();
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_short_name: *mut c_char = null_mut();

pub unsafe fn set_program_name(argv0: *mut c_char) {
    unsafe {
        if argv0.is_null() {
            return;
        }
        let n = rusty_libc_mem::strlen(argv0.cast());
        let s = core::slice::from_raw_parts(argv0 as *const u8, n);
        let short = match s.iter().rposition(|&c| c == b'/') {
            Some(i) => argv0.add(i + 1),
            None => argv0,
        };
        program_invocation_name = argv0;
        program_invocation_short_name = short;
        #[cfg(feature = "export")]
        {
            __progname_full = argv0;
            __progname = short;
        }
    }
}

pub unsafe extern "C" fn __init_misc(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    unsafe {
        set_args(argc, argv);
        if !argv.is_null() {
            set_program_name(*argv);
        }
    }
}

pub(crate) unsafe fn name_bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe {
        if p.is_null() {
            b"(null)"
        } else {
            core::slice::from_raw_parts(p as *const u8, rusty_libc_mem::strlen(p.cast()))
        }
    }
}

unsafe fn write_stderr(src: *const u8, n: usize) -> usize {
    unsafe {
        let e = file::stderr_ptr();
        if (*e).flags & file::F_WIDE == 0 {
            return file::write_bytes(e, src, n);
        }
        let mut st: rusty_libc_wchar::mbstate_t = core::mem::zeroed();
        let mut done = 0;
        while done < n {
            let mut wc: rusty_libc_wchar::wchar_t = 0;
            let k = rusty_libc_wchar::mbyte::mbrtowc(&mut wc, src.add(done).cast(), n - done, &mut st);
            let k = match k {
                k if k >= usize::MAX - 1 => return done,
                0 => 1,
                k => k,
            };
            if rusty_libc_stdio::wfile::putwc_raw(e, wc as rusty_libc_wchar::wint_t) == rusty_libc_wchar::WEOF {
                return done;
            }
            done += k;
        }
        n
    }
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
            let n = unsafe { write_stderr(self.buf.as_ptr(), self.n) };
            if n != self.n {
                self.ok = false;
            }
            self.n = 0;
        }
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        let _ = self.put(b);
    }
}

impl Sink for Out {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.buf.len() - self.n {
            self.flush();
        }
        if bytes.len() >= self.buf.len() {
            let n = unsafe { write_stderr(bytes.as_ptr(), bytes.len()) };
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

fn strerror_text(code: i32, buf: &mut [u8; 48]) -> &[u8] {
    match rusty_libc_core::messages::error_message(code) {
        Some(m) => m.to_bytes(),
        None => {
            let n = rusty_libc_core::messages::write_unknown(buf, b"Unknown error ", code);
            &buf[..n]
        }
    }
}

type Body<'a> = &'a mut dyn FnMut(&mut Out);

fn vwarn_with(has_format: bool, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    unsafe { _g.lock(file::stderr_ptr()) };
    let saved = errno::get();
    let mut o = Out::new();
    let prog = unsafe { name_bytes(program_invocation_short_name) };
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
    let mut tmp = [0u8; 48];
    o.bytes(strerror_text(saved, &mut tmp));
    o.bytes(b"\n");
    o.flush();
    errno::set(saved);
}

fn vwarnx_with(has_format: bool, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    unsafe { _g.lock(file::stderr_ptr()) };
    let mut o = Out::new();
    o.bytes(unsafe { name_bytes(program_invocation_short_name) });
    o.bytes(b": ");
    if has_format {
        body(&mut o);
    }
    o.bytes(b"\n");
    o.flush();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarn(format: *const c_char, mut ap: VaList) {
    vwarn_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut ap);
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnx(format: *const c_char, mut ap: VaList) {
    vwarnx_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut ap);
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verr(status: c_int, format: *const c_char, ap: VaList) -> ! {
    unsafe {
        vwarn(format, ap);
    }
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verrx(status: c_int, format: *const c_char, ap: VaList) -> ! {
    unsafe {
        vwarnx(format, ap);
    }
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warn(format: *const c_char, mut args: ...) {
    vwarn_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut args);
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warnx(format: *const c_char, mut args: ...) {
    vwarnx_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut args);
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn err(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarn_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut args);
    });
    process::exit(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn errx(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarnx_with(!format.is_null(), &mut |o| unsafe {
        run(o, format, &mut args);
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
    unsafe {
        file::fflush(file::stdout_ptr());
    }
}

fn error_tail(o: &mut Out, status: c_int, errnum: c_int, body: Body) {
    body(o);
    unsafe {
        error_message_count = error_message_count.wrapping_add(1);
    }
    if errnum != 0 {
        o.bytes(b": ");
        let mut tmp = [0u8; 48];
        o.bytes(strerror_text(errnum, &mut tmp));
    }
    o.bytes(b"\n");
    o.flush();
    unsafe {
        file::fflush(file::stderr_ptr());
    }
    if status != 0 {
        process::exit(status);
    }
}

fn error_with(status: c_int, errnum: c_int, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    unsafe { _g.lock(file::stderr_ptr()) };
    flush_stdout();
    let mut o = Out::new();
    unsafe {
        if let Some(f) = error_print_progname {
            o.flush();
            f();
        } else {
            o.bytes(name_bytes(program_invocation_name));
            o.bytes(b": ");
        }
    }
    error_tail(&mut o, status, errnum, body);
}

static mut OLD_FILE: *const c_char = core::ptr::null();
static mut OLD_LINE: u32 = 0;

fn error_at_line_with(status: c_int, errnum: c_int, file_name: *const c_char, line: u32, body: Body) {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    unsafe { _g.lock(file::stderr_ptr()) };
    unsafe {
        if error_one_per_line != 0 {
            if OLD_LINE == line
                && (file_name == OLD_FILE
                    || (!OLD_FILE.is_null() && !file_name.is_null() && rusty_libc_mem::strcmp(OLD_FILE.cast(), file_name.cast()) == 0))
            {
                return;
            }
            OLD_FILE = file_name;
            OLD_LINE = line;
        }
        flush_stdout();
        let mut o = Out::new();
        if let Some(f) = error_print_progname {
            o.flush();
            f();
        } else {
            o.bytes(name_bytes(program_invocation_name));
            o.bytes(b":");
        }
        if file_name.is_null() {
            o.bytes(b" ");
        } else {
            o.bytes(name_bytes(file_name));
            o.bytes(b":");
            let mut tmp = [0u8; 12];
            o.bytes(fmt_i32(line as i32, &mut tmp));
            o.bytes(b": ");
        }
        error_tail(&mut o, status, errnum, body);
    }
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
    error_with(status, errnum, &mut |o| unsafe {
        run(o, message, &mut args);
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn error_at_line(status: c_int, errnum: c_int, file_name: *const c_char, line_number: u32, message: *const c_char, mut args: ...) {
    error_at_line_with(status, errnum, file_name, line_number, &mut |o| unsafe {
        run(o, message, &mut args);
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
    let mut iov = [const { IoVec { base: core::ptr::null(), len: 0 } }; 12];
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
        let r = unsafe { syscall::syscall3(SYS_WRITEV, 2, iov.as_ptr().add(start) as usize, n - start) };
        match syscall::check(r) {
            Ok(mut w) => {
                left -= w;
                while start < n && w >= iov[start].len {
                    w -= iov[start].len;
                    start += 1;
                }
                if start < n && w > 0 {
                    iov[start].base = unsafe { iov[start].base.add(w) };
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

unsafe fn assert_message(label: &[u8], text: &[u8], suffix: &[u8], file: *const c_char, line: u32, function: *const c_char) {
    unsafe {
        let prog: &[u8] = if program_invocation_short_name.is_null() { b"" } else { name_bytes(program_invocation_short_name) };
        let mut lb = [0u8; 12];
        let func: &[u8] = if function.is_null() { b"" } else { name_bytes(function) };
        write_pieces(&[
            prog,
            if prog.is_empty() { b"" } else { b": " },
            name_bytes(file),
            b":",
            fmt_u32(line, &mut lb),
            b": ",
            func,
            if function.is_null() { b"" } else { b": " },
            label,
            text,
            suffix,
        ]);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_fail(assertion: *const c_char, file: *const c_char, line: u32, function: *const c_char) -> ! {
    unsafe {
        assert_message(b"Assertion `", name_bytes(assertion), b"' failed.\n", file, line, function);
    }
    process::abort()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_perror_fail(errnum: c_int, file: *const c_char, line: u32, function: *const c_char) -> ! {
    unsafe {
        let mut tmp = [0u8; 48];
        let e = strerror_text(errnum, &mut tmp);
        assert_message(b"Unexpected error: ", e, b".\n", file, line, function);
    }
    process::abort()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert(assertion: *const c_char, file: *const c_char, line: c_int) -> ! {
    unsafe { __assert_fail(assertion, file, line as u32, core::ptr::null()) }
}
