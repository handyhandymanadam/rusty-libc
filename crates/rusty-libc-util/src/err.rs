//! err.h, error.h and assert: `err`, `errx`, `warn`, `warnx` (and the `v` forms), `error`,
//! `error_at_line`, `__assert_fail`, `__assert_perror_fail`, `__assert`.
//!
//! The program name comes from `program_invocation_name` (`error`) and `program_invocation_short_name`
//! (`err`, `warn`, `assert`), which the startup code must set from `argv[0]` (see [`set_program_name`]);
//! they stay NULL until then, and a NULL name prints as `(null)` exactly as glibc does when its
//! startup did not run. Messages go through the stdio stream `stderr` in one write when they are
//! short; the assert messages go straight to file descriptor 2 with one `writev`, then abort, as
//! glibc's `__libc_message` does.
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

// ------------------------------------------------------------------ program name variables

// With the export feature the four names glibc exports are real symbols: `program_invocation_name`
// and `__progname_full` are one variable, `program_invocation_short_name` and `__progname` another.
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
    // glibc's hidden `__libc_argc` / `__libc_argv` (wordexp reads `$#`, `$1`, `$*` from them)
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
    // `__init_misc` is a stub in this same block, so one object holds the variables and the
    // function that sets them: any program that can read the names also gets it, and the startup
    // code may reference it weakly (a weak reference does not pull an archive member out of libc.a).
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

/// The program's `argc` (glibc's `__libc_argc`); 0 until the startup code or [`set_args`] set it.
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut __libc_argc: c_int = 0;
/// The program's `argv` (glibc's `__libc_argv`).
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut __libc_argv: *mut *mut c_char = null_mut();

/// Remember the program arguments for `wordexp` (`$#`, `$1`, `$*`, `$@`). The C startup does this
/// through `__init_misc`; a Rust program that starts without it can call this itself.
///
/// # Safety
/// `argv` must stay valid for the life of the program (NULL-terminated, `argc` entries).
pub unsafe fn set_args(argc: c_int, argv: *mut *mut c_char) {
    // SAFETY: plain stores to the two variables; the start-up code (or a Rust program before its threads) is the writer.
    unsafe { __libc_argc = argc };
    // SAFETY: as above.
    unsafe { __libc_argv = argv };
}

/// The recorded `(argc, argv)`.
pub(crate) fn args() -> (c_int, *mut *mut c_char) {
    // SAFETY: plain loads; the variables are written once at start-up (`set_args`), before anything reads them.
    let argc = unsafe { __libc_argc };
    // SAFETY: as above.
    (argc, unsafe { __libc_argv })
}

/// `program_invocation_short_name` (NULL until the start-up code sets it).
fn short_name() -> *const c_char {
    // SAFETY: a plain load of a pointer variable that the start-up code sets before `main` (a program may assign it too,
    // as with glibc; it is never written concurrently with a message being printed in a correct program).
    unsafe { program_invocation_short_name }
}

/// `program_invocation_name` (NULL until the start-up code sets it).
fn full_name() -> *const c_char {
    // SAFETY: as in `short_name`.
    unsafe { program_invocation_name }
}

/// The bytes of a program name for `%s`: "(null)" for NULL.
fn prog_bytes<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: the name variables are NULL or point to `argv[0]` (or a string the program assigned), which lives for the
    // whole program.
    unsafe { name_bytes(p) }
}

/// `program_invocation_name` (the full `argv[0]`).
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_name: *mut c_char = null_mut();
/// `program_invocation_short_name` (`argv[0]` after the last slash).
#[cfg(not(feature = "export"))]
#[allow(non_upper_case_globals)]
pub static mut program_invocation_short_name: *mut c_char = null_mut();

/// Set both program name variables from `argv[0]`, like glibc's startup (`__init_misc`); does
/// nothing when `argv0` is NULL.
///
/// # Safety
/// `argv0` must stay valid for the life of the program.
pub unsafe fn set_program_name(argv0: *mut c_char) {
    // SAFETY: a NULL check, then `argv0` is a C string (caller's contract).
    let Some(s) = (unsafe { rusty_libc_core::ffi::cstr(argv0) }) else { return };
    let short = match s.to_bytes().iter().rposition(|&c| c == b'/') {
        Some(i) => argv0.wrapping_add(i + 1),
        None => argv0,
    };
    // SAFETY: plain stores; the start-up code calls this before the program's threads exist.
    unsafe { program_invocation_name = argv0 };
    // SAFETY: as above.
    unsafe { program_invocation_short_name = short };
    // The four names are aliases of two variables inside libc. A program linked against glibc may have copy-relocated
    // any one of them into its own .bss (a PIE like pstree does it for __progname): each name is looked up on its own,
    // so write all four, and whichever copy the program reads has the value.
    #[cfg(feature = "export")]
    {
        // SAFETY: as above.
        unsafe { __progname_full = argv0 };
        // SAFETY: as above.
        unsafe { __progname = short };
    }
}

/// C name of [`set_program_name`] for the startup code (glibc's `__init_misc`): sets both program
/// name variables from `argv[0]`. rusty-libc-core's `_start` should call it before `main`.
///
/// # Safety
/// `argv` must be NULL or point to the program's argument vector.
pub unsafe extern "C" fn __init_misc(argc: c_int, argv: *mut *mut c_char, _envp: *mut *mut c_char) {
    // SAFETY: the program's argument vector lives for the whole program (caller's contract).
    unsafe { set_args(argc, argv) };
    if !argv.is_null() {
        // SAFETY: a non-NULL `argv` has at least its terminating NULL; argv[0] is NULL or a C string.
        let argv0 = unsafe { *argv };
        // SAFETY: as above.
        unsafe { set_program_name(argv0) };
    }
}

/// The program name as bytes: the empty-or-text of a C string, or "(null)" for NULL (what `%s` prints).
pub(crate) unsafe fn name_bytes<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: a non-NULL `p` is a C string (caller's contract).
    unsafe { rusty_libc_core::ffi::cstr(p) }.map_or(b"(null)", core::ffi::CStr::to_bytes)
}

// ------------------------------------------------------------------ output

/// The current `stderr` stream.
fn stderr() -> *mut file::File {
    // (a volatile load of the `stderr` variable: a program may assign it, as with glibc)
    file::stderr_ptr()
}

/// Take `stderr`'s lock for the guard's life (the guard is in its final place).
fn lock_stderr(g: &mut rusty_libc_stdio::flock::StreamGuard) {
    let e = stderr();
    // SAFETY: `e` is the program's stderr stream, which outlives the guard (a local of the caller, not moved after).
    unsafe { g.lock(e) };
}

/// Writes message text to `stderr`; returns how many bytes were accepted. A wide-oriented `stderr` gets the text
/// converted to wide characters (glibc's `__fxprintf` does the same; a byte write would be refused there).
fn write_stderr(src: &[u8]) -> usize {
    let e = stderr();
    // SAFETY: `e` is a valid stream (stdio keeps stderr valid); reading its flags word.
    if unsafe { (*e).flags } & file::F_WIDE == 0 {
        // SAFETY: `e` is a valid stream (the caller holds its lock).
        return file::write_bytes(unsafe { file::stream(e) }, src);
    }
    let n = src.len();
    let mut st = rusty_libc_wchar::mbstate_t::default();
    let mut done = 0;
    while done < n {
        let mut wc: rusty_libc_wchar::wchar_t = 0;
        let rest = &src[done..];
        // SAFETY: `rest` is readable for its length, `wc` and `st` are writable locals.
        let k = unsafe { rusty_libc_wchar::mbyte::mbrtowc(&mut wc, rest.as_ptr().cast(), rest.len(), &mut st) };
        // an invalid or cut-off sequence ends the message; a NUL character is one byte
        let k = match k {
            k if k >= usize::MAX - 1 => return done,
            0 => 1,
            k => k,
        };
        // SAFETY: `e` is a valid wide-oriented stream (the caller holds its lock).
        if rusty_libc_stdio::wfile::putwc_raw(unsafe { file::stream(e) }, wc as rusty_libc_wchar::wint_t) == rusty_libc_wchar::WEOF {
            return done;
        }
        done += k;
    }
    n
}

/// Collects output in a stack buffer and writes it to `stderr` in as few writes as possible.
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
    // (in line in the formatter, as before the safe rewrite: a call per piece cost more than the copy)
    // The copy into the buffer stays small enough to be inlined; the flush and the direct write of a long piece are
    // `put_slow` (with them inlined, `put` became a call per piece again).
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

/// The text of glibc's `__strerror_r(code)`: the message translated in the calling thread's LC_MESSAGES locale, or
/// `_("Unknown error ")` and the number.
fn strerror_text(code: i32, buf: &mut [u8; 128]) -> &[u8] {
    rusty_libc_core::messages::strerror_r_text(code, buf)
}

// ------------------------------------------------------------------ err.h

/// What the formatter callbacks do: write the message body into an `Out`.
type Body<'a> = &'a mut dyn FnMut(&mut Out);

fn vwarn_with(has_format: bool, body: Body) {
    // like glibc: the whole message is one critical section on stderr
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
    // like glibc: the whole message is one critical section on stderr
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

/// # Safety
/// `format` is NULL or a printf format matching the arguments in `ap`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarn(format: *const c_char, mut ap: VaList) {
    vwarn_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the arguments in `ap` (caller's contract).
        unsafe { run(o, format, &mut ap) };
    });
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnx(format: *const c_char, mut ap: VaList) {
    vwarnx_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the arguments in `ap` (caller's contract).
        unsafe { run(o, format, &mut ap) };
    });
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verr(status: c_int, format: *const c_char, ap: VaList) -> ! {
    // SAFETY: forwarded contract.
    unsafe { vwarn(format, ap) };
    process::exit(status)
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn verrx(status: c_int, format: *const c_char, ap: VaList) -> ! {
    // SAFETY: forwarded contract.
    unsafe { vwarnx(format, ap) };
    process::exit(status)
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warn(format: *const c_char, mut args: ...) {
    vwarn_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, format, &mut args) };
    });
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn warnx(format: *const c_char, mut args: ...) {
    vwarnx_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, format, &mut args) };
    });
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn err(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarn_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, format, &mut args) };
    });
    process::exit(status)
}

/// # Safety
/// As `vwarn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn errx(status: c_int, format: *const c_char, mut args: ...) -> ! {
    vwarnx_with(!format.is_null(), &mut |o| {
        // SAFETY: `format` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, format, &mut args) };
    });
    process::exit(status)
}

// Rust API: the same output with typed arguments instead of a `va_list`.

/// `warn(format, args...)` from Rust: `format` is a printf format (None prints only `prog: strerror`).
pub fn warn_args(format: Option<&CStr>, args: &[Arg]) {
    vwarn_with(format.is_some(), &mut |o| {
        if let Some(f) = format {
            format_to(o, f, args);
        }
    });
}

/// `warnx(format, args...)` from Rust.
pub fn warnx_args(format: Option<&CStr>, args: &[Arg]) {
    vwarnx_with(format.is_some(), &mut |o| {
        if let Some(f) = format {
            format_to(o, f, args);
        }
    });
}

/// `err(status, format, args...)` from Rust.
pub fn err_args(status: i32, format: Option<&CStr>, args: &[Arg]) -> ! {
    warn_args(format, args);
    process::exit(status)
}

/// `errx(status, format, args...)` from Rust.
pub fn errx_args(status: i32, format: Option<&CStr>, args: &[Arg]) -> ! {
    warnx_args(format, args);
    process::exit(status)
}

// ------------------------------------------------------------------ error.h

/// `error_print_progname`: when set, `error` calls it instead of printing the program name.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_print_progname: Option<unsafe extern "C" fn()> = None;
/// `error_message_count`: incremented by every call of `error` and `error_at_line` that prints.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_message_count: u32 = 0;
/// `error_one_per_line`: when non-zero, `error_at_line` skips a message for the same file and line.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut error_one_per_line: c_int = 0;

fn flush_stdout() {
    // (a volatile load of the `stdout` variable)
    let out = file::stdout_ptr();
    // SAFETY: `stdout` is NULL-free and valid (stdio keeps it so, or the program assigned another valid stream).
    unsafe { rusty_libc_stdio::fflush(out) };
}

fn error_tail(o: &mut Out, status: c_int, errnum: c_int, body: Body) {
    body(o);
    // SAFETY: a plain load of the counter; the caller holds stderr's lock, which every writer of it here holds (a program
    // that writes the variable itself meanwhile races as it would with glibc).
    let count = unsafe { error_message_count };
    // SAFETY: as above, the store.
    unsafe { error_message_count = count.wrapping_add(1) };
    if errnum != 0 {
        o.bytes(b": ");
        let mut tmp = [0u8; 128];
        o.bytes(strerror_text(errnum, &mut tmp));
    }
    o.bytes(b"\n");
    o.flush();
    let e = stderr();
    // (the stream's own flush: the caller holds stderr's lock, so the locking `fflush` would only take it again)
    // SAFETY: `e` is the program's stderr stream, valid, and its lock is held by this thread (error_with,
    // error_at_line_with).
    file::fflush(unsafe { file::stream(e) });
    if status != 0 {
        process::exit(status);
    }
}

/// `error_print_progname` (the program may set it at any time before a message).
fn print_progname_fn() -> Option<unsafe extern "C" fn()> {
    // SAFETY: a plain load of the variable.
    unsafe { error_print_progname }
}

/// The program name part of an `error`/`error_at_line` message: the program's own function, or the name and `sep`.
/// (In line: `sep` is a constant, so its copy is a store, not a memcpy call.)
#[inline(always)]
fn progname_part(o: &mut Out, sep: &[u8]) {
    if let Some(f) = print_progname_fn() {
        o.flush();
        // SAFETY: the program installed this function to be called here (error.h's contract).
        unsafe { f() };
    } else {
        o.bytes(prog_bytes(full_name()));
        o.bytes(sep);
    }
}

fn error_with(status: c_int, errnum: c_int, body: Body) {
    // like glibc: the whole message is one critical section on stderr
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    flush_stdout();
    let mut o = Out::new();
    progname_part(&mut o, b": ");
    error_tail(&mut o, status, errnum, body);
}

/// The file and line of the last `error_at_line` message (for `error_one_per_line`). Rule: only touched with stderr's
/// lock held (error_at_line_with takes it first), so one thread at a time.
static OLD: SyncCell<(*const c_char, u32)> = SyncCell::new((core::ptr::null(), 0));

fn error_at_line_with(status: c_int, errnum: c_int, file_name: *const c_char, line: u32, body: Body) {
    // like glibc: the whole message is one critical section on stderr
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    lock_stderr(&mut _g);
    // SAFETY: a plain load of the variable.
    if unsafe { error_one_per_line } != 0 {
        // SAFETY: stderr's lock is held (OLD's rule).
        let (old_file, old_line) = unsafe { OLD.read() };
        // SAFETY: both are C strings: `file_name` by error_at_line's contract, `old_file` because it was such a
        // `file_name` before (glibc compares them the same way).
        if old_line == line && (file_name == old_file || (!old_file.is_null() && !file_name.is_null() && unsafe { rusty_libc_core::ffi::cstr_eq(old_file, file_name) })) {
            return;
        }
        // SAFETY: as above.
        unsafe { OLD.write((file_name, line)) };
    }
    flush_stdout();
    let mut o = Out::new();
    progname_part(&mut o, b":");
    if file_name.is_null() {
        o.bytes(b" ");
    } else {
        // SAFETY: a non-NULL `file_name` is a C string (error_at_line's contract).
        o.bytes(unsafe { name_bytes(file_name) });
        o.bytes(b":");
        let mut tmp = [0u8; 12];
        o.bytes(fmt_i32(line as i32, &mut tmp));
        o.bytes(b": ");
    }
    error_tail(&mut o, status, errnum, body);
}

/// Decimal text of `v` (what `%d` prints) in `buf`.
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

/// # Safety
/// `message` is a printf format matching the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn error(status: c_int, errnum: c_int, message: *const c_char, mut args: ...) {
    error_with(status, errnum, &mut |o| {
        // SAFETY: `message` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, message, &mut args) };
    });
}

/// # Safety
/// As `error`; `file_name` is NULL or a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn error_at_line(status: c_int, errnum: c_int, file_name: *const c_char, line_number: u32, message: *const c_char, mut args: ...) {
    error_at_line_with(status, errnum, file_name, line_number, &mut |o| {
        // SAFETY: `message` is a printf format matching the variadic arguments (caller's contract).
        unsafe { run(o, message, &mut args) };
    });
}

/// `error(status, errnum, format, args...)` from Rust.
pub fn error_args(status: i32, errnum: i32, format: &CStr, args: &[Arg]) {
    error_with(status, errnum, &mut |o| {
        format_to(o, format, args);
    });
}

/// `error_at_line(...)` from Rust.
pub fn error_at_line_args(status: i32, errnum: i32, file_name: Option<&CStr>, line: u32, format: &CStr, args: &[Arg]) {
    let f = file_name.map_or(core::ptr::null(), |c| c.as_ptr());
    error_at_line_with(status, errnum, f, line, &mut |o| {
        format_to(o, format, args);
    });
}

// ------------------------------------------------------------------ assert

const SYS_WRITEV: usize = 20;

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

/// Write the pieces to fd 2 with one writev (resuming after a short write), like `__libc_message`.
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
        // SAFETY: entries `start..n` of `iov` describe readable slices of `pieces` (or their unwritten tails).
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

/// Decimal text of an unsigned 32-bit number.
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

/// The program name for the assert messages: empty when it is NULL (the name and its colon are left out then).
fn assert_prog<'a>() -> &'a [u8] {
    let p = short_name();
    if p.is_null() { b"" } else { prog_bytes(p) }
}

/// Write "prog: file:line: func: <label><text><suffix>" to fd 2 (the program name and its colon are
/// left out when the name is empty, the function part when `function` is None).
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

/// The assertion messages in a locale that translates them: glibc runs `_(format)` through `__libc_message`, which
/// knows only `%s` (the line number is passed as text). False when there is no translation.
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

/// The C strings of an assertion failure as bytes: `file` as `%s` prints it ("(null)" for NULL), `function` None for NULL.
///
/// # Safety
/// `file` and `function` are NULL or C strings that stay valid for `'a`.
unsafe fn assert_where<'a>(file: *const c_char, function: *const c_char) -> (&'a [u8], Option<&'a [u8]>) {
    // SAFETY: forwarded contract.
    let f = unsafe { name_bytes(file) };
    // SAFETY: forwarded contract.
    (f, unsafe { rusty_libc_core::ffi::cstr(function) }.map(CStr::to_bytes))
}

/// The `assert` failure message (glibc's `__assert_fail_base`) for the safe core: `assertion` text, where it failed.
pub fn assert_fail_message(assertion: &[u8], file: &[u8], line: u32, function: Option<&[u8]>) {
    if !assert_translated(c"%s%s%s:%s: %s%sAssertion `%s' failed.\n", assertion, file, line, function) {
        assert_message(b"Assertion `", assertion, b"' failed.\n", file, line, function);
    }
}

/// # Safety
/// The strings are C strings (`function` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_fail(assertion: *const c_char, file: *const c_char, line: u32, function: *const c_char) -> ! {
    // SAFETY: C strings or NULL (caller's contract).
    let (f, func) = unsafe { assert_where(file, function) };
    // SAFETY: `assertion` is NULL or a C string (caller's contract).
    let a = unsafe { name_bytes(assertion) };
    assert_fail_message(a, f, line, func);
    process::abort()
}

/// # Safety
/// As `__assert_fail`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_perror_fail(errnum: c_int, file: *const c_char, line: u32, function: *const c_char) -> ! {
    // SAFETY: C strings or NULL (caller's contract).
    let (f, func) = unsafe { assert_where(file, function) };
    let mut tmp = [0u8; 128];
    let e = strerror_text(errnum, &mut tmp);
    if !assert_translated(c"%s%s%s:%s: %s%sUnexpected error: %s.\n", e, f, line, func) {
        assert_message(b"Unexpected error: ", e, b".\n", f, line, func);
    }
    process::abort()
}

/// The old three-argument form.
///
/// # Safety
/// As `__assert_fail`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert(assertion: *const c_char, file: *const c_char, line: c_int) -> ! {
    // SAFETY: forwarded contract.
    unsafe { __assert_fail(assertion, file, line as u32, core::ptr::null()) }
}
