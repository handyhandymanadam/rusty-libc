//! Tests for err.rs: each function runs in a forked child with stderr (and stdout) redirected to a
//! file, once with the host glibc and once with ours; the bytes written and the wait status must
//! be identical.
use core::ffi::{c_char, c_int};
use std::ffi::CString;

mod host {
    use super::*;
    unsafe extern "C" {
        pub static mut program_invocation_name: *mut c_char;
        pub static mut program_invocation_short_name: *mut c_char;
        pub static mut error_print_progname: Option<unsafe extern "C" fn()>;
        pub static mut error_message_count: u32;
        pub static mut error_one_per_line: c_int;
        pub fn warn(f: *const c_char, ...);
        pub fn warnx(f: *const c_char, ...);
        pub fn err(s: c_int, f: *const c_char, ...) -> !;
        pub fn errx(s: c_int, f: *const c_char, ...) -> !;
        pub fn error(s: c_int, e: c_int, f: *const c_char, ...);
        pub fn error_at_line(s: c_int, e: c_int, file: *const c_char, line: u32, f: *const c_char, ...);
        pub fn __assert_fail(a: *const c_char, f: *const c_char, l: u32, func: *const c_char) -> !;
        pub fn __assert_perror_fail(e: c_int, f: *const c_char, l: u32, func: *const c_char) -> !;
        pub fn __assert(a: *const c_char, f: *const c_char, l: c_int) -> !;
        pub fn printf(f: *const c_char, ...) -> c_int;
        pub static mut _IO_2_1_stdin_: [u8; 1];
        pub static mut _IO_2_1_stdout_: [u8; 1];
        pub static mut _IO_2_1_stderr_: [u8; 1];
    }
}

/// rusty-libc-stdio exports the data symbols `stdin`, `stdout`, `stderr` even without its `export` feature,
/// so glibc, inside this test process, would read OUR variables. Point them at glibc's own streams
/// while host code runs (our code reaches its streams through `file::stderr_ptr()`, not the variable).
fn with_host_streams(f: &dyn Fn()) {
    unsafe {
        rusty_libc_stdio::stdin.write(core::ptr::addr_of_mut!(host::_IO_2_1_stdin_) as *mut _);
        rusty_libc_stdio::stdout.write(core::ptr::addr_of_mut!(host::_IO_2_1_stdout_) as *mut _);
        rusty_libc_stdio::stderr.write(core::ptr::addr_of_mut!(host::_IO_2_1_stderr_) as *mut _);
    }
    f();
}

/// Run `f` in a forked child with fds 1 and 2 pointing at a temp file; return (bytes, wait status).
fn capture(f: &dyn Fn()) -> (Vec<u8>, i32) {
    let path = format!("/tmp/rusty-libc-err-test-{}-{}", std::process::id(), {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    });
    let cpath = CString::new(path.clone()).unwrap();
    unsafe {
        let fd = libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600);
        assert!(fd >= 0);
        let pid = libc::fork();
        if pid == 0 {
            let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &lim);
            libc::prctl(libc::PR_SET_DUMPABLE, 0); // no core-dump handler run for an abort on purpose
            libc::dup2(fd, 2);
            libc::dup2(fd, 1);
            f();
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        libc::close(fd);
        let out = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        (out, st)
    }
}

/// Set our program name variables to the host's.
fn same_names() {
    unsafe {
        crate::err::program_invocation_name = host::program_invocation_name;
        crate::err::program_invocation_short_name = host::program_invocation_short_name;
    }
}

fn pair(label: &str, h: &dyn Fn(), o: &dyn Fn()) {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    same_names();
    let (hb, hs) = capture(&|| with_host_streams(h));
    let (ob, os) = capture(&|| {
        crate::testutil::ours_streams();
        o()
    });
    assert_eq!(String::from_utf8_lossy(&ob), String::from_utf8_lossy(&hb), "{label}: output (host status {hs:#x}, ours {os:#x})");
    assert_eq!(os, hs, "{label}: wait status");
    assert!(!hb.is_empty() || label.contains("silent"), "{label}: host wrote nothing");
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn warn_family() {
    use crate::err::*;
    let f = c("value %d and %s");
    let s = c("text");
    let plain = c("plain message");
    pair(
        "warn",
        &|| unsafe {
            *libc::__errno_location() = 2;
            host::warn(f.as_ptr(), 5 as c_int, s.as_ptr());
        },
        &|| unsafe {
            rusty_libc_core::errno::set(2);
            warn(f.as_ptr(), 5 as c_int, s.as_ptr());
        },
    );
    pair(
        "warn null format",
        &|| unsafe {
            *libc::__errno_location() = 13;
            host::warn(core::ptr::null());
        },
        &|| unsafe {
            rusty_libc_core::errno::set(13);
            warn(core::ptr::null());
        },
    );
    pair(
        "warn unknown errno",
        &|| unsafe {
            *libc::__errno_location() = 4000;
            host::warn(plain.as_ptr());
        },
        &|| unsafe {
            rusty_libc_core::errno::set(4000);
            warn(plain.as_ptr());
        },
    );
    pair(
        "warnx",
        &|| unsafe { host::warnx(f.as_ptr(), -7 as c_int, s.as_ptr()) },
        &|| unsafe { warnx(f.as_ptr(), -7 as c_int, s.as_ptr()) },
    );
    pair("warnx null", &|| unsafe { host::warnx(core::ptr::null()) }, &|| unsafe { warnx(core::ptr::null()) });
    pair(
        "warn %m inside",
        &|| unsafe {
            *libc::__errno_location() = 22;
            host::warn(c"err is %m here".as_ptr());
        },
        &|| unsafe {
            rusty_libc_core::errno::set(22);
            warn(c"err is %m here".as_ptr());
        },
    );
    let long = c(&"x".repeat(3000));
    pair(
        "warnx long",
        &|| unsafe { host::warnx(c"%s".as_ptr(), long.as_ptr()) },
        &|| unsafe { warnx(c"%s".as_ptr(), long.as_ptr()) },
    );
}

#[test]
fn err_family_exit() {
    use crate::err::*;
    let f = c("failed: %s");
    let s = c("thing");
    pair(
        "err",
        &|| unsafe {
            *libc::__errno_location() = 2;
            host::err(3, f.as_ptr(), s.as_ptr())
        },
        &|| unsafe {
            rusty_libc_core::errno::set(2);
            err(3, f.as_ptr(), s.as_ptr())
        },
    );
    pair("errx", &|| unsafe { host::errx(9, f.as_ptr(), s.as_ptr()) }, &|| unsafe { errx(9, f.as_ptr(), s.as_ptr()) });
    pair("errx 0", &|| unsafe { host::errx(0, c"zero".as_ptr()) }, &|| unsafe { errx(0, c"zero".as_ptr()) });
}

#[test]
fn error_family() {
    use crate::err::*;
    let f = c("cannot open %s (%d)");
    let s = c("file.txt");
    pair(
        "error with errnum",
        &|| unsafe {
            host::error(0, 2, f.as_ptr(), s.as_ptr(), 4 as c_int);
            host::error(0, 0, c"second".as_ptr());
            host::error(0, 999, c"unknown".as_ptr());
            host::error(5, 13, c"fatal".as_ptr());
        },
        &|| unsafe {
            error(0, 2, f.as_ptr(), s.as_ptr(), 4 as c_int);
            error(0, 0, c"second".as_ptr());
            error(0, 999, c"unknown".as_ptr());
            error(5, 13, c"fatal".as_ptr());
        },
    );
    // stdout is flushed before the message
    pair(
        "error flushes stdout",
        &|| unsafe {
            host::printf(c"out-line".as_ptr());
            host::error(0, 0, c"msg".as_ptr());
        },
        &|| unsafe {
            // our stdout stream is separate from the host's: write through ours
            rusty_libc_stdio::fprintf(rusty_libc_stdio::file::stdout_ptr(), c"out-line".as_ptr());
            error(0, 0, c"msg".as_ptr());
        },
    );
    pair(
        "error_at_line",
        &|| unsafe {
            host::error_at_line(0, 2, c"src.c".as_ptr(), 10, c"bad %d".as_ptr(), 1 as c_int);
            host::error_at_line(0, 0, core::ptr::null(), 11, c"no file".as_ptr());
            host::error_at_line(0, 0, c"src.c".as_ptr(), u32::MAX, c"big line".as_ptr());
        },
        &|| unsafe {
            error_at_line(0, 2, c"src.c".as_ptr(), 10, c"bad %d".as_ptr(), 1 as c_int);
            error_at_line(0, 0, core::ptr::null(), 11, c"no file".as_ptr());
            error_at_line(0, 0, c"src.c".as_ptr(), u32::MAX, c"big line".as_ptr());
        },
    );
    pair(
        "error_one_per_line",
        &|| unsafe {
            host::error_one_per_line = 1;
            host::error_at_line(0, 0, c"a.c".as_ptr(), 1, c"one".as_ptr());
            host::error_at_line(0, 0, c"a.c".as_ptr(), 1, c"dup".as_ptr());
            host::error_at_line(0, 0, c"a.c".as_ptr(), 2, c"two".as_ptr());
            host::error_at_line(0, 0, c"b.c".as_ptr(), 2, c"three".as_ptr());
            host::error_at_line(0, 0, c"b.c".as_ptr(), 2, c"dup".as_ptr());
            host::error(0, 0, c"count %d".as_ptr(), host::error_message_count as c_int);
        },
        &|| unsafe {
            error_one_per_line = 1;
            error_at_line(0, 0, c"a.c".as_ptr(), 1, c"one".as_ptr());
            error_at_line(0, 0, c"a.c".as_ptr(), 1, c"dup".as_ptr());
            error_at_line(0, 0, c"a.c".as_ptr(), 2, c"two".as_ptr());
            error_at_line(0, 0, c"b.c".as_ptr(), 2, c"three".as_ptr());
            error_at_line(0, 0, c"b.c".as_ptr(), 2, c"dup".as_ptr());
            error(0, 0, c"count %d".as_ptr(), error_message_count as c_int);
        },
    );
    unsafe extern "C" fn hook_host() {
        unsafe { host::printf(c"HOOK: ".as_ptr()) };
        unsafe { libc::fflush(core::ptr::null_mut()) };
    }
    unsafe extern "C" fn hook_ours() {
        unsafe { rusty_libc_stdio::fprintf(rusty_libc_stdio::file::stderr_ptr(), c"HOOK: ".as_ptr()) };
    }
    pair(
        "error_print_progname",
        &|| unsafe {
            host::error_print_progname = Some(hook_host);
            host::error(0, 1, c"via hook".as_ptr());
        },
        &|| unsafe {
            error_print_progname = Some(hook_ours);
            error(0, 1, c"via hook".as_ptr());
        },
    );
}

#[test]
fn error_count_increments() {
    use crate::err::*;
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let before = unsafe { error_message_count };
    // not through capture: stderr output of the test goes to the test's stderr, which is fine
    let (_, st) = capture(&|| unsafe {
        error(0, 0, c"x".as_ptr());
        if error_message_count != before + 1 {
            libc::_exit(7);
        }
    });
    assert_eq!(st, 0);
}

#[test]
fn assert_family() {
    use crate::err::*;
    pair(
        "__assert_fail",
        &|| unsafe { host::__assert_fail(c"x > 0".as_ptr(), c"foo.c".as_ptr(), 42, c"main".as_ptr()) },
        &|| unsafe { __assert_fail(c"x > 0".as_ptr(), c"foo.c".as_ptr(), 42, c"main".as_ptr()) },
    );
    pair(
        "__assert_fail no function",
        &|| unsafe { host::__assert_fail(c"a".as_ptr(), c"foo.c".as_ptr(), 4_000_000_000, core::ptr::null()) },
        &|| unsafe { __assert_fail(c"a".as_ptr(), c"foo.c".as_ptr(), 4_000_000_000, core::ptr::null()) },
    );
    pair(
        "__assert_perror_fail",
        &|| unsafe { host::__assert_perror_fail(2, c"bar.c".as_ptr(), 7, c"fn".as_ptr()) },
        &|| unsafe { __assert_perror_fail(2, c"bar.c".as_ptr(), 7, c"fn".as_ptr()) },
    );
    pair(
        "__assert_perror_fail unknown",
        &|| unsafe { host::__assert_perror_fail(999, c"bar.c".as_ptr(), 7, core::ptr::null()) },
        &|| unsafe { __assert_perror_fail(999, c"bar.c".as_ptr(), 7, core::ptr::null()) },
    );
    pair(
        "__assert",
        // the host's own `__assert` symbol crashes in glibc 2.43 (checked with a C program), so the
        // reference is what it is documented to do: __assert_fail with a NULL function
        &|| unsafe { host::__assert_fail(c"y".as_ptr(), c"baz.c".as_ptr(), 3, core::ptr::null()) },
        &|| unsafe { __assert(c"y".as_ptr(), c"baz.c".as_ptr(), 3) },
    );
}

#[test]
fn rust_api_matches_c() {
    use crate::err::*;
    use rusty_libc_stdio::rust_api::Arg;
    pair(
        "warn_args",
        &|| unsafe {
            *libc::__errno_location() = 2;
            host::warn(c"n=%d s=%s".as_ptr(), 12 as c_int, c"abc".as_ptr());
        },
        &|| {
            rusty_libc_core::errno::set(2);
            warn_args(Some(c"n=%d s=%s"), &[Arg::Int(12), Arg::Str(c"abc")]);
        },
    );
    pair(
        "error_args",
        &|| unsafe { host::error(0, 2, c"v=%u".as_ptr(), 9 as c_int) },
        &|| error_args(0, 2, c"v=%u", &[Arg::Uint(9)]),
    );
}

#[test]
fn set_program_name_splits_at_last_slash() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = unsafe { (crate::err::program_invocation_name, crate::err::program_invocation_short_name) };
    let p = c("/usr/bin/tool");
    let q = c("plain");
    unsafe {
        crate::err::set_program_name(p.as_ptr() as *mut c_char);
        assert_eq!(std::ffi::CStr::from_ptr(crate::err::program_invocation_short_name).to_bytes(), b"tool");
        assert_eq!(std::ffi::CStr::from_ptr(crate::err::program_invocation_name).to_bytes(), b"/usr/bin/tool");
        crate::err::set_program_name(q.as_ptr() as *mut c_char);
        assert_eq!(std::ffi::CStr::from_ptr(crate::err::program_invocation_short_name).to_bytes(), b"plain");
        crate::err::program_invocation_name = saved.0;
        crate::err::program_invocation_short_name = saved.1;
    }
}
