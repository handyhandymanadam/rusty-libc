#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
//! Tests: every non-overflow call is compared with the host glibc's function of the same name
//! (return value and every byte of the buffers); every overflow call runs in a forked child that must
//! die of SIGABRT with glibc's exact message on standard error.
use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

/// glibc's own functions, reached by their names (ours are Rust paths).
mod host {
    use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
    unsafe extern "C" {
        pub fn __memcpy_chk(d: *mut c_void, s: *const c_void, n: usize, dl: usize) -> *mut c_void;
        pub fn __memmove_chk(d: *mut c_void, s: *const c_void, n: usize, dl: usize) -> *mut c_void;
        pub fn __mempcpy_chk(d: *mut c_void, s: *const c_void, n: usize, dl: usize) -> *mut c_void;
        pub fn __memset_chk(d: *mut c_void, c: c_int, n: usize, dl: usize) -> *mut c_void;
        pub fn __strcpy_chk(d: *mut c_char, s: *const c_char, dl: usize) -> *mut c_char;
        pub fn __stpcpy_chk(d: *mut c_char, s: *const c_char, dl: usize) -> *mut c_char;
        pub fn __strncpy_chk(d: *mut c_char, s: *const c_char, n: usize, dl: usize) -> *mut c_char;
        pub fn __stpncpy_chk(d: *mut c_char, s: *const c_char, n: usize, dl: usize) -> *mut c_char;
        pub fn __strcat_chk(d: *mut c_char, s: *const c_char, dl: usize) -> *mut c_char;
        pub fn __strncat_chk(d: *mut c_char, s: *const c_char, n: usize, dl: usize) -> *mut c_char;
        pub fn __strlcpy_chk(d: *mut c_char, s: *const c_char, n: usize, dl: usize) -> usize;
        pub fn __strlcat_chk(d: *mut c_char, s: *const c_char, n: usize, dl: usize) -> usize;
        pub fn __explicit_bzero_chk(d: *mut c_void, n: usize, dl: usize);
        pub fn __memset_explicit_chk(d: *mut c_void, c: c_int, n: usize, dl: usize) -> *mut c_void;
        pub fn __sprintf_chk(s: *mut c_char, flag: c_int, slen: usize, fmt: *const c_char, ...) -> c_int;
        pub fn __snprintf_chk(s: *mut c_char, n: usize, flag: c_int, slen: usize, fmt: *const c_char, ...) -> c_int;
        pub fn __asprintf_chk(r: *mut *mut c_char, flag: c_int, fmt: *const c_char, ...) -> c_int;
        pub fn __dprintf_chk(fd: c_int, flag: c_int, fmt: *const c_char, ...) -> c_int;
        pub fn __read_chk(fd: c_int, b: *mut c_void, n: usize, bl: usize) -> isize;
        pub fn __pread_chk(fd: c_int, b: *mut c_void, n: usize, off: i64, bl: usize) -> isize;
        pub fn __pread64_chk(fd: c_int, b: *mut c_void, n: usize, off: i64, bl: usize) -> isize;
        pub fn __readlink_chk(p: *const c_char, b: *mut c_char, n: usize, bl: usize) -> isize;
        pub fn __readlinkat_chk(fd: c_int, p: *const c_char, b: *mut c_char, n: usize, bl: usize) -> isize;
        pub fn __getcwd_chk(b: *mut c_char, n: usize, bl: usize) -> *mut c_char;
        pub fn __realpath_chk(p: *const c_char, r: *mut c_char, rl: usize) -> *mut c_char;
        pub fn __ttyname_r_chk(fd: c_int, b: *mut c_char, n: usize, nr: usize) -> c_int;
        pub fn __ptsname_r_chk(fd: c_int, b: *mut c_char, n: usize, nr: usize) -> c_int;
        pub fn __getlogin_r_chk(b: *mut c_char, n: usize, nr: usize) -> c_int;
        pub fn __gethostname_chk(b: *mut c_char, n: usize, nr: usize) -> c_int;
        pub fn __getdomainname_chk(b: *mut c_char, n: usize, nr: usize) -> c_int;
        pub fn __getgroups_chk(size: c_int, l: *mut u32, ll: usize) -> c_int;
        pub fn __confstr_chk(name: c_int, b: *mut c_char, n: usize, bl: usize) -> usize;
        pub fn __poll_chk(f: *mut libc::pollfd, n: c_ulong, t: c_int, fl: usize) -> c_int;
        pub fn __recv_chk(fd: c_int, b: *mut c_void, n: usize, bl: usize, flags: c_int) -> isize;
        pub fn __inet_ntop_chk(af: c_int, s: *const c_void, d: *mut c_char, size: u32, ds: usize) -> *const c_char;
        pub fn __inet_pton_chk(af: c_int, s: *const c_char, d: *mut c_void, ds: usize) -> c_int;
        pub fn __fdelt_chk(d: c_long) -> c_long;
        pub fn __wmemcpy_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wmemmove_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wmempcpy_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wmemset_chk(d: *mut i32, c: i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wcscpy_chk(d: *mut i32, s: *const i32, dl: usize) -> *mut i32;
        pub fn __wcpcpy_chk(d: *mut i32, s: *const i32, dl: usize) -> *mut i32;
        pub fn __wcsncpy_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wcpncpy_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wcscat_chk(d: *mut i32, s: *const i32, dl: usize) -> *mut i32;
        pub fn __wcsncat_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> *mut i32;
        pub fn __wcslcpy_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> usize;
        pub fn __wcslcat_chk(d: *mut i32, s: *const i32, n: usize, dl: usize) -> usize;
        pub fn __mbstowcs_chk(d: *mut i32, s: *const c_char, n: usize, dl: usize) -> usize;
        pub fn __wcstombs_chk(d: *mut c_char, s: *const i32, n: usize, dl: usize) -> usize;
        pub fn __wctomb_chk(d: *mut c_char, c: i32, dl: usize) -> c_int;
        pub fn __swprintf_chk(s: *mut i32, n: usize, flag: c_int, slen: usize, fmt: *const i32, ...) -> c_int;
        pub fn __fgetws_chk(b: *mut i32, size: usize, n: c_int, f: *mut c_void) -> *mut i32;
    }
}

const ABORT: i32 = 6;
const OVERFLOW: &[u8] = b"*** buffer overflow detected ***: terminated\n";

/// Run `f` in a forked child with stderr on a pipe: (terminating signal or 0, what it wrote).
fn dies(f: impl FnOnce()) -> (i32, Vec<u8>) {
    unsafe {
        let mut fds = [0; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        if pid == 0 {
            // the child aborts on purpose: not dumpable, so the system's core-dump handler is never started (a core limit of 0 does not stop it)
            libc::prctl(libc::PR_SET_DUMPABLE, 0);
            libc::dup2(fds[1], 2);
            libc::close(fds[0]);
            f();
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        (if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { 0 }, out)
    }
}

fn aborts_with(msg: &[u8], f: impl FnOnce()) {
    let (sig, out) = dies(f);
    assert_eq!(sig, ABORT, "child did not abort (stderr {:?})", String::from_utf8_lossy(&out));
    assert_eq!(String::from_utf8_lossy(&out), String::from_utf8_lossy(msg));
}

fn overflows(f: impl FnOnce()) {
    aborts_with(OVERFLOW, f);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn cs(b: &[u8]) -> *const c_char {
    b.as_ptr().cast()
}

#[test]
fn mem_functions_match_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x1234_5678_9abc_def1);
    for _ in 0..2000 {
        let n = r.below(200);
        let extra = r.below(3) * r.below(5);
        let dl = n + extra;
        let src: Vec<u8> = (0..n + 8).map(|_| r.next() as u8).collect();
        let base: Vec<u8> = (0..dl + 16).map(|_| r.next() as u8).collect();
        let c = r.next() as c_int;
        unsafe {
            for k in 0..5 {
                let (mut a, mut b) = (base.clone(), base.clone());
                let (ra, rb): (usize, usize) = match k {
                    0 => (
                        crate::mem::__memcpy_chk(a.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - a.as_ptr() as usize,
                        host::__memcpy_chk(b.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - b.as_ptr() as usize,
                    ),
                    1 => (
                        crate::mem::__memmove_chk(a.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - a.as_ptr() as usize,
                        host::__memmove_chk(b.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - b.as_ptr() as usize,
                    ),
                    2 => (
                        crate::mem::__mempcpy_chk(a.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - a.as_ptr() as usize,
                        host::__mempcpy_chk(b.as_mut_ptr().cast(), src.as_ptr().cast(), n, dl) as usize - b.as_ptr() as usize,
                    ),
                    3 => (
                        crate::mem::__memset_chk(a.as_mut_ptr().cast(), c, n, dl) as usize - a.as_ptr() as usize,
                        host::__memset_chk(b.as_mut_ptr().cast(), c, n, dl) as usize - b.as_ptr() as usize,
                    ),
                    _ => {
                        crate::mem::__explicit_bzero_chk(a.as_mut_ptr().cast(), n, dl);
                        host::__explicit_bzero_chk(b.as_mut_ptr().cast(), n, dl);
                        (0, 0)
                    }
                };
                assert_eq!((ra, &a), (rb, &b), "mem kind {k} n {n}");
            }
            let (mut a, mut b) = (base.clone(), base.clone());
            let pa = crate::mem::__memset_explicit_chk(a.as_mut_ptr().cast(), c, n, dl);
            let pb = host::__memset_explicit_chk(b.as_mut_ptr().cast(), c, n, dl);
            assert_eq!((pa as usize - a.as_ptr() as usize, &a), (pb as usize - b.as_ptr() as usize, &b));
        }
    }
}

/// A random NUL-terminated string of length < max (letters), padded to `pad` extra bytes of junk.
fn rstr(r: &mut Rng, max: usize) -> Vec<u8> {
    let n = r.below(max);
    let mut v: Vec<u8> = (0..n).map(|_| b'a' + r.below(26) as u8).collect();
    v.push(0);
    v
}

#[test]
fn string_functions_match_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xfeed_beef_1234_0001);
    for _ in 0..4000 {
        let src = rstr(&mut r, 40);
        let pre = rstr(&mut r, 20); // existing destination text for cat/lcat
        let n = r.below(50);
        let dl = 8 + r.below(80);
        let mut base: Vec<u8> = (0..dl + 8).map(|_| 0xAA).collect();
        // the destination text only when it fits (else the call would abort, tested elsewhere)
        if pre.len() <= dl {
            base[..pre.len()].copy_from_slice(&pre);
        }
        let sl = src.len() - 1;
        let pl = if pre.len() <= dl { pre.len() - 1 } else { 0 };
        let pre_fits = pre.len() <= dl;
        macro_rules! both {
            ($ours:expr, $theirs:expr, $conv:expr) => {{
                let (mut a, mut b) = (base.clone(), base.clone());
                let ra = $conv($ours(a.as_mut_ptr().cast::<c_char>()), a.as_ptr());
                let rb = $conv($theirs(b.as_mut_ptr().cast::<c_char>()), b.as_ptr());
                assert_eq!((ra, &a), (rb, &b));
            }};
        }
        let off = |p: *mut c_char, base: *const u8| p as usize - base as usize;
        unsafe {
            if sl < dl {
                both!(|d| crate::mem::__strcpy_chk(d, cs(&src), dl), |d| host::__strcpy_chk(d, cs(&src), dl), off);
                both!(|d| crate::mem::__stpcpy_chk(d, cs(&src), dl), |d| host::__stpcpy_chk(d, cs(&src), dl), off);
            }
            if n <= dl {
                both!(|d| crate::mem::__strncpy_chk(d, cs(&src), n, dl), |d| host::__strncpy_chk(d, cs(&src), n, dl), off);
                both!(|d| crate::mem::__stpncpy_chk(d, cs(&src), n, dl), |d| host::__stpncpy_chk(d, cs(&src), n, dl), off);
                both!(|d| crate::mem::__strlcpy_chk(d, cs(&src), n, dl) as isize as *mut c_char, |d| host::__strlcpy_chk(d, cs(&src), n, dl) as isize as *mut c_char, |p: *mut c_char, _| p as usize);
            }
            if pre_fits && pl + sl < dl {
                both!(|d| crate::mem::__strcat_chk(d, cs(&src), dl), |d| host::__strcat_chk(d, cs(&src), dl), off);
            }
            if pre_fits && pl + n.min(sl) < dl {
                both!(|d| crate::mem::__strncat_chk(d, cs(&src), n, dl), |d| host::__strncat_chk(d, cs(&src), n, dl), off);
            }
            if pre_fits && n <= dl {
                both!(|d| crate::mem::__strlcat_chk(d, cs(&src), n, dl) as isize as *mut c_char, |d| host::__strlcat_chk(d, cs(&src), n, dl) as isize as *mut c_char, |p: *mut c_char, _| p as usize);
            }
        }
    }
}

#[test]
fn string_overflows_abort() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = [b'x'; 16];
    let p = buf.as_mut_ptr();
    unsafe {
        overflows(|| {
            crate::mem::__memcpy_chk(p.cast(), c"abcdefgh".as_ptr().cast(), 9, 8);
        });
        overflows(|| {
            crate::mem::__memmove_chk(p.cast(), c"abcdefgh".as_ptr().cast(), 9, 8);
        });
        overflows(|| {
            crate::mem::__mempcpy_chk(p.cast(), c"abcdefgh".as_ptr().cast(), 9, 8);
        });
        overflows(|| {
            crate::mem::__memset_chk(p.cast(), 0, 9, 8);
        });
        overflows(|| {
            crate::mem::__strcpy_chk(p.cast(), c"abcdefgh".as_ptr(), 8);
        });
        overflows(|| {
            crate::mem::__stpcpy_chk(p.cast(), c"abcdefgh".as_ptr(), 8);
        });
        overflows(|| {
            crate::mem::__strncpy_chk(p.cast(), c"abc".as_ptr(), 9, 8);
        });
        overflows(|| {
            crate::mem::__stpncpy_chk(p.cast(), c"abc".as_ptr(), 9, 8);
        });
        overflows(|| {
            let mut d = *b"abcd\0xxxxxxxxxxx";
            crate::mem::__strcat_chk(d.as_mut_ptr().cast(), c"efgh".as_ptr(), 8);
        });
        overflows(|| {
            // no NUL inside the destination object at all
            let mut d = [b'a'; 8];
            crate::mem::__strcat_chk(d.as_mut_ptr().cast(), c"".as_ptr(), 8);
        });
        overflows(|| {
            let mut d = *b"abcd\0xxxxxxxxxxx";
            crate::mem::__strncat_chk(d.as_mut_ptr().cast(), c"efghij".as_ptr(), 4, 8);
        });
        overflows(|| {
            crate::mem::__strlcpy_chk(p.cast(), c"abc".as_ptr(), 9, 8);
        });
        overflows(|| {
            crate::mem::__strlcat_chk(p.cast(), c"abc".as_ptr(), 9, 8);
        });
        overflows(|| crate::mem::__explicit_bzero_chk(p.cast(), 9, 8));
        overflows(|| {
            crate::mem::__memset_explicit_chk(p.cast(), 0, 9, 8);
        });
        // boundary: exactly fitting calls do not abort
        let (sig, out) = dies(|| {
            let mut d = *b"abcd\0xxxxxxxxxxx";
            crate::mem::__strcat_chk(d.as_mut_ptr().cast(), c"efg".as_ptr(), 8);
            crate::mem::__strncat_chk(d.as_mut_ptr().cast(), c"".as_ptr(), 100, 8);
            crate::mem::__strcpy_chk(d.as_mut_ptr().cast(), c"1234567".as_ptr(), 8);
        });
        assert_eq!((sig, out.len()), (0, 0));
    }
}

#[test]
fn fail_message_and_exports() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    aborts_with(b"*** something bad ***: terminated\n", || unsafe { crate::fail::__fortify_fail(c"something bad".as_ptr()) });
    aborts_with(OVERFLOW, || crate::fail::__chk_fail());
    // fd_set index
    for d in [0, 1, 63, 64, 100, 1023] {
        assert_eq!(crate::io::__fdelt_chk(d), unsafe { host::__fdelt_chk(d) });
        assert_eq!(crate::io::__fdelt_warn(d), d / 64);
    }
    for d in [-1, 1024, 5000, c_long::MAX] {
        aborts_with(b"*** bit out of range 0 - FD_SETSIZE on fd_set ***: terminated\n", || {
            crate::io::__fdelt_chk(d);
        });
        aborts_with(b"*** bit out of range 0 - FD_SETSIZE on fd_set ***: terminated\n", || {
            crate::io::__fdelt_warn(d);
        });
    }
}

fn text(buf: &[u8]) -> String {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[test]
fn sprintf_family_matches_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        for flag in [0, 1, 2] {
            for slen in [64usize, 38, usize::MAX] {
                let (mut a, mut b) = ([0xAAu8; 80], [0xAAu8; 80]);
                let ra = crate::printf::__sprintf_chk(a.as_mut_ptr().cast(), flag, slen, c"%d|%s|%5.2f|%#x|%-4c|%ld".as_ptr(), -42, c"str".as_ptr(), 7.125f64, 255u32, b'z' as c_int, 1234567890123i64);
                let rb = host::__sprintf_chk(b.as_mut_ptr().cast(), flag, slen, c"%d|%s|%5.2f|%#x|%-4c|%ld".as_ptr(), -42, c"str".as_ptr(), 7.125f64, 255u32, b'z' as c_int, 1234567890123i64);
                assert_eq!((ra, text(&a)), (rb, text(&b)));
                // glibc clears the first byte first and writes the NUL: bytes beyond are untouched in both
                assert_eq!(&a[ra as usize + 1..], &b[rb as usize + 1..]);
            }
            for (n, slen) in [(0usize, 10usize), (1, 1), (5, 40), (40, 40), (10, 100)] {
                let (mut a, mut b) = ([0xAAu8; 64], [0xAAu8; 64]);
                let ra = crate::printf::__snprintf_chk(a.as_mut_ptr().cast(), n, flag, slen, c"hello %s and %d".as_ptr(), c"world".as_ptr(), 77);
                let rb = host::__snprintf_chk(b.as_mut_ptr().cast(), n, flag, slen, c"hello %s and %d".as_ptr(), c"world".as_ptr(), 77);
                assert_eq!((ra, a), (rb, b), "snprintf n={n}");
            }
            // %N$ forms
            let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
            let ra = crate::printf::__sprintf_chk(a.as_mut_ptr().cast(), flag, 64, c"%2$s-%1$d-%2$s".as_ptr(), 5, c"p".as_ptr());
            let rb = host::__sprintf_chk(b.as_mut_ptr().cast(), flag, 64, c"%2$s-%1$d-%2$s".as_ptr(), 5, c"p".as_ptr());
            assert_eq!((ra, text(&a)), (rb, text(&b)));
        }
        // asprintf and dprintf
        let (mut pa, mut pb): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
        let ra = crate::printf::__asprintf_chk(&mut pa, 1, c"%s=%d".as_ptr(), c"k".as_ptr(), 9);
        let rb = host::__asprintf_chk(&mut pb, 1, c"%s=%d".as_ptr(), c"k".as_ptr(), 9);
        assert_eq!((ra, CStr::from_ptr(pa).to_bytes()), (rb, CStr::from_ptr(pb).to_bytes()));
        rusty_libc_malloc::free(pa.cast());
        libc::free(pb.cast());
        let mut fds = [0; 2];
        libc::pipe(fds.as_mut_ptr());
        let ra = crate::printf::__dprintf_chk(fds[1], 1, c"fd %d %s\n".as_ptr(), 3, c"x".as_ptr());
        let rb = host::__dprintf_chk(fds[1], 1, c"fd %d %s\n".as_ptr(), 3, c"x".as_ptr());
        assert_eq!(ra, rb);
        let mut got = [0u8; 64];
        let n = libc::read(fds[0], got.as_mut_ptr().cast(), 64);
        assert_eq!(&got[..n as usize], b"fd 3 x\nfd 3 x\n");
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn printf_family_overflow_and_percent_n() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = [0u8; 64];
    let p = buf.as_mut_ptr() as *mut c_char;
    unsafe {
        // sprintf: output plus NUL must fit
        overflows(|| {
            crate::printf::__sprintf_chk(p, 0, 5, c"hello".as_ptr());
        });
        overflows(|| {
            crate::printf::__sprintf_chk(p, 0, 5, c"%s".as_ptr(), c"toolong".as_ptr());
        });
        overflows(|| {
            crate::printf::__sprintf_chk(p, 0, 0, c"".as_ptr());
        });
        let (sig, out) = dies(|| {
            let mut b = [0u8; 6];
            let r = crate::printf::__sprintf_chk(b.as_mut_ptr().cast(), 0, 6, c"hello".as_ptr());
            libc::_exit(if r == 5 && &b == b"hello\0" { 0 } else { 3 });
        });
        assert_eq!((sig, out.len()), (0, 0));
        // snprintf: size given larger than the object
        overflows(|| {
            crate::printf::__snprintf_chk(p, 10, 0, 5, c"x".as_ptr());
        });
        // %n: allowed (and written) in a read-only format with flag 1, aborts from writable memory
        let mut cnt: c_int = -1;
        let n = crate::printf::__sprintf_chk(p, 1, 64, c"abc%n".as_ptr(), &mut cnt as *mut c_int);
        assert_eq!((n, cnt), (3, 3));
        let wmsg = b"*** %n in writable segments detected ***\n";
        aborts_with(wmsg, || {
            let mut fmt = *b"abc%n\0";
            let mut c: c_int = 0;
            crate::printf::__sprintf_chk(p, 1, 64, fmt.as_mut_ptr().cast(), &mut c as *mut c_int);
        });
        aborts_with(wmsg, || {
            let mut fmt = *b"abc%hhn\0";
            let mut c: i8 = 0;
            crate::printf::__snprintf_chk(p, 10, 2, 64, fmt.as_mut_ptr().cast(), &mut c as *mut i8);
        });
        // flag 0: %n from writable memory is not checked
        let (sig, out) = dies(|| {
            let mut fmt = *b"abc%n\0";
            let mut c: c_int = 0;
            crate::printf::__sprintf_chk(p, 0, 64, fmt.as_mut_ptr().cast(), &mut c as *mut c_int);
        });
        assert_eq!((sig, out.len()), (0, 0));
        // "%%n" is a literal
        let (sig, out) = dies(|| {
            let mut fmt = *b"100%%n\0";
            crate::printf::__sprintf_chk(p, 1, 64, fmt.as_mut_ptr().cast());
        });
        assert_eq!((sig, out.len()), (0, 0));
        // %N$ with an unused position
        aborts_with(b"*** invalid %N$ use detected ***\n", || {
            crate::printf::__sprintf_chk(p, 1, 64, c"%2$d".as_ptr(), 1, 2);
        });
        let (sig, _) = dies(|| {
            crate::printf::__sprintf_chk(p, 0, 64, c"%2$d".as_ptr(), 1, 2);
        });
        assert_eq!(sig, 0);
        // the same checks reach the fd and allocating forms
        aborts_with(wmsg, || {
            let mut fmt = *b"%n\0";
            let mut c: c_int = 0;
            crate::printf::__dprintf_chk(2, 1, fmt.as_mut_ptr().cast(), &mut c as *mut c_int);
        });
        aborts_with(wmsg, || {
            let mut fmt = *b"%n\0";
            let mut c: c_int = 0;
            let mut out: *mut c_char = core::ptr::null_mut();
            crate::printf::__asprintf_chk(&mut out, 1, fmt.as_mut_ptr().cast(), &mut c as *mut c_int);
        });
    }
}

#[test]
fn readonly_area_walk() {
    use crate::readonly::{Area, readonly_area};
    static RO: [u8; 8] = *b"literal\0";
    static mut RW: [u8; 8] = *b"writabl\0";
    let local = [0u8; 8];
    assert_eq!(readonly_area(RO.as_ptr(), 8), Area::ReadOnly);
    assert_eq!(readonly_area(c"in rodata".as_ptr().cast(), 10), Area::ReadOnly);
    assert_eq!(readonly_area((&raw const RW).cast(), 8), Area::Writable);
    assert_eq!(readonly_area(local.as_ptr(), 8), Area::Writable);
    assert_eq!(readonly_area(core::ptr::null(), 8), Area::Writable);
}

#[test]
fn readonly_area_needs_no_file_descriptor() {
    use crate::readonly::{Area, readonly_area};
    static RO: [u8; 8] = *b"literal\0";
    static mut RW: [u8; 8] = *b"writabl\0";
    // every descriptor below the limit taken: the segments of the program decide, /proc/self/maps cannot be opened
    let mut old = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut old), 0) };
    let used = unsafe { libc::dup(0) };
    assert!(used >= 0);
    let low = libc::rlimit { rlim_cur: used as libc::rlim_t + 1, rlim_max: old.rlim_max };
    unsafe { assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &low), 0) };
    let (ro, rw) = (readonly_area(RO.as_ptr(), 8), readonly_area((&raw const RW).cast(), 8));
    unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &old);
        libc::close(used);
    }
    assert_eq!(ro, Area::ReadOnly);
    assert_eq!(rw, Area::Writable);
}

fn tmpfile_with(data: &[u8]) -> (c_int, std::ffi::CString) {
    let path = std::ffi::CString::new(format!("{}/fortify-test-{}-{}", std::env::var("TMPDIR").unwrap_or("/tmp".into()), std::process::id(), data.len())).unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600);
        assert!(fd >= 0);
        assert_eq!(libc::write(fd, data.as_ptr().cast(), data.len()), data.len() as isize);
        (fd, path)
    }
}

#[test]
fn io_functions_match_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        let (fd, path) = tmpfile_with(&data);
        // read
        libc::lseek(fd, 0, 0);
        let (mut a, mut b) = ([0u8; 100], [0u8; 100]);
        let ra = crate::io::__read_chk(fd, a.as_mut_ptr().cast(), 100, 100);
        libc::lseek(fd, 0, 0);
        let rb = host::__read_chk(fd, b.as_mut_ptr().cast(), 100, 100);
        assert_eq!((ra, a), (rb, b));
        // pread and pread64
        for off in [0i64, 17, 250, 400] {
            let (mut a, mut b, mut c, mut d) = ([0u8; 64], [0u8; 64], [0u8; 64], [0u8; 64]);
            let ra = crate::io::__pread_chk(fd, a.as_mut_ptr().cast(), 64, off, 64);
            let rb = host::__pread_chk(fd, b.as_mut_ptr().cast(), 64, off, 64);
            let rc = crate::io::__pread64_chk(fd, c.as_mut_ptr().cast(), 64, off, 64);
            let rd = host::__pread64_chk(fd, d.as_mut_ptr().cast(), 64, off, 64);
            assert_eq!((ra, a, rc, c), (rb, b, rd, d));
        }
        libc::close(fd);
        libc::unlink(path.as_ptr());
        // readlink / readlinkat
        let (mut a, mut b, mut c, mut d) = ([0u8; 4096], [0u8; 4096], [0u8; 4096], [0u8; 4096]);
        let ra = crate::io::__readlink_chk(c"/proc/self/exe".as_ptr(), a.as_mut_ptr().cast(), 4096, 4096);
        let rb = host::__readlink_chk(c"/proc/self/exe".as_ptr(), b.as_mut_ptr().cast(), 4096, 4096);
        let rc = crate::io::__readlinkat_chk(libc::AT_FDCWD, c"/proc/self/exe".as_ptr(), c.as_mut_ptr().cast(), 4096, 4096);
        let rd = host::__readlinkat_chk(libc::AT_FDCWD, c"/proc/self/exe".as_ptr(), d.as_mut_ptr().cast(), 4096, 4096);
        assert!(ra > 0);
        assert_eq!((ra, &a[..], rc, &c[..]), (rb, &b[..], rd, &d[..]));
        // getcwd, getwd
        let (mut a, mut b) = ([0u8; 4096], [0u8; 4096]);
        let pa = crate::io::__getcwd_chk(a.as_mut_ptr().cast(), 4096, 4096);
        let pb = host::__getcwd_chk(b.as_mut_ptr().cast(), 4096, 4096);
        assert!(!pa.is_null() && !pb.is_null());
        assert_eq!(text(&a), text(&b));
        let mut c = [0u8; 4096];
        let pc = crate::io::__getwd_chk(c.as_mut_ptr().cast(), 4096);
        assert!(!pc.is_null());
        assert_eq!(text(&c), text(&b));
        // realpath
        let (mut a, mut b) = ([0u8; 4096], [0u8; 4096]);
        let pa = crate::io::__realpath_chk(c"/proc/self/../self/cwd".as_ptr(), a.as_mut_ptr().cast(), 4096);
        let pb = host::__realpath_chk(c"/proc/self/../self/cwd".as_ptr(), b.as_mut_ptr().cast(), 4096);
        assert_eq!((pa.is_null(), text(&a)), (pb.is_null(), text(&b)));
        // gethostname, getdomainname, confstr, getgroups, getlogin_r, ttyname_r, ptsname_r
        let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
        assert_eq!(crate::io::__gethostname_chk(a.as_mut_ptr().cast(), 256, 256), host::__gethostname_chk(b.as_mut_ptr().cast(), 256, 256));
        assert_eq!(a, b);
        let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
        assert_eq!(crate::io::__getdomainname_chk(a.as_mut_ptr().cast(), 256, 256), host::__getdomainname_chk(b.as_mut_ptr().cast(), 256, 256));
        assert_eq!(a, b);
        let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
        let ra = crate::io::__confstr_chk(libc::_CS_PATH, a.as_mut_ptr().cast(), 256, 256);
        let rb = host::__confstr_chk(libc::_CS_PATH, b.as_mut_ptr().cast(), 256, 256);
        assert_eq!((ra, a), (rb, b));
        let (mut a, mut b) = ([0u32; 64], [0u32; 64]);
        let ra = crate::io::__getgroups_chk(64, a.as_mut_ptr(), 256);
        let rb = host::__getgroups_chk(64, b.as_mut_ptr(), 256);
        assert_eq!((ra, a), (rb, b));
        assert_eq!(crate::io::__getgroups_chk(-1, a.as_mut_ptr(), 256), -1);
        assert_eq!(rusty_libc_core::errno::get(), 22);
        assert_eq!(host::__getgroups_chk(-1, b.as_mut_ptr(), 256), -1);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let ra = crate::io::__getlogin_r_chk(a.as_mut_ptr().cast(), 64, 64);
        let rb = host::__getlogin_r_chk(b.as_mut_ptr().cast(), 64, 64);
        assert_eq!(ra == 0, rb == 0);
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let ra = crate::io::__ttyname_r_chk(0, a.as_mut_ptr().cast(), 64, 64);
        let rb = host::__ttyname_r_chk(0, b.as_mut_ptr().cast(), 64, 64);
        assert_eq!((ra, a), (rb, b));
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        let ra = crate::io::__ptsname_r_chk(-1, a.as_mut_ptr().cast(), 64, 64);
        let rb = host::__ptsname_r_chk(-1, b.as_mut_ptr().cast(), 64, 64);
        assert_eq!(ra, rb);
        // poll and recv (a socket pair)
        let mut sv = [0; 2];
        assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()), 0);
        assert_eq!(libc::write(sv[0], b"ping".as_ptr().cast(), 4), 4);
        let mut p1 = libc::pollfd { fd: sv[1], events: libc::POLLIN, revents: 0 };
        let mut p2 = p1;
        let ra = crate::io::__poll_chk((&raw mut p1).cast(), 1, 1000, 8);
        let rb = host::__poll_chk(&mut p2, 1, 1000, 8);
        assert_eq!((ra, p1.revents), (rb, p2.revents));
        let mut a = [0u8; 16];
        let ra = crate::io::__recv_chk(sv[1], a.as_mut_ptr().cast(), 4, 16, 0);
        assert_eq!((ra, &a[..4]), (4, &b"ping"[..]));
        assert_eq!(libc::write(sv[0], b"pong".as_ptr().cast(), 4), 4);
        let mut b = [0u8; 16];
        let rb = host::__recv_chk(sv[1], b.as_mut_ptr().cast(), 4, 16, 0);
        assert_eq!((rb, &b[..4]), (4, &b"pong"[..]));
        let ra = crate::io::__recvfrom_chk(sv[1], a.as_mut_ptr().cast(), 4, 16, libc::MSG_DONTWAIT, core::ptr::null_mut(), core::ptr::null_mut());
        assert_eq!(ra, -1);
        libc::close(sv[0]);
        libc::close(sv[1]);
        // inet_ntop / inet_pton
        let addr4 = [127u8, 0, 0, 1];
        let (mut a, mut b) = ([0u8; 46], [0u8; 46]);
        let pa = crate::io::__inet_ntop_chk(libc::AF_INET, addr4.as_ptr().cast(), a.as_mut_ptr().cast(), 46, 46);
        let pb = host::__inet_ntop_chk(libc::AF_INET, addr4.as_ptr().cast(), b.as_mut_ptr().cast(), 46, 46);
        assert!(!pa.is_null() && !pb.is_null());
        assert_eq!(text(&a), text(&b));
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        let ra = crate::io::__inet_pton_chk(libc::AF_INET6, c"::1".as_ptr(), a.as_mut_ptr().cast(), 16);
        let rb = host::__inet_pton_chk(libc::AF_INET6, c"::1".as_ptr(), b.as_mut_ptr().cast(), 16);
        assert_eq!((ra, a), (rb, b));
        let (mut a, mut b) = ([0u8; 4], [0u8; 4]);
        let ra = crate::io::__inet_pton_chk(libc::AF_INET, c"10.1.2.3".as_ptr(), a.as_mut_ptr().cast(), 4);
        let rb = host::__inet_pton_chk(libc::AF_INET, c"10.1.2.3".as_ptr(), b.as_mut_ptr().cast(), 4);
        assert_eq!((ra, a), (rb, b));
        // open forms without a mode (no O_CREAT) just open
        for f in [crate::io::__open_2, crate::io::__open64_2] {
            let fd = f(c"/proc/self/exe".as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0);
            libc::close(fd);
        }
        for f in [crate::io::__openat_2, crate::io::__openat64_2] {
            let fd = f(libc::AT_FDCWD, c"/proc/self/exe".as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0);
            libc::close(fd);
        }
    }
}

#[test]
fn io_overflows_abort() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = [0u8; 64];
    let p = buf.as_mut_ptr() as *mut c_char;
    unsafe {
        overflows(|| {
            crate::io::__read_chk(0, p.cast(), 9, 8);
        });
        overflows(|| {
            crate::io::__pread_chk(0, p.cast(), 9, 0, 8);
        });
        overflows(|| {
            crate::io::__pread64_chk(0, p.cast(), 9, 0, 8);
        });
        overflows(|| {
            crate::io::__readlink_chk(c"/".as_ptr(), p, 9, 8);
        });
        overflows(|| {
            crate::io::__readlinkat_chk(-100, c"/".as_ptr(), p, 9, 8);
        });
        overflows(|| {
            crate::io::__getcwd_chk(p, 9, 8);
        });
        overflows(|| {
            // a buffer too small for the directory: getwd must not be called with it
            let mut tiny = [0u8; 1];
            crate::io::__getwd_chk(tiny.as_mut_ptr().cast(), 1);
        });
        overflows(|| {
            crate::io::__realpath_chk(c"/".as_ptr(), p, 100);
        });
        overflows(|| {
            crate::io::__ttyname_r_chk(0, p, 9, 8);
        });
        overflows(|| {
            crate::io::__ptsname_r_chk(0, p, 9, 8);
        });
        overflows(|| {
            crate::io::__getlogin_r_chk(p, 9, 8);
        });
        overflows(|| {
            crate::io::__gethostname_chk(p, 9, 8);
        });
        overflows(|| {
            crate::io::__getdomainname_chk(p, 9, 8);
        });
        overflows(|| {
            crate::io::__getgroups_chk(3, p.cast(), 8);
        });
        overflows(|| {
            crate::io::__confstr_chk(0, p, 9, 8);
        });
        overflows(|| {
            crate::io::__poll_chk(p.cast(), 2, 0, 8);
        });
        overflows(|| {
            crate::io::__ppoll_chk(p.cast(), 2, core::ptr::null(), core::ptr::null(), 15);
        });
        overflows(|| {
            crate::io::__recv_chk(0, p.cast(), 9, 8, 0);
        });
        overflows(|| {
            crate::io::__recvfrom_chk(0, p.cast(), 9, 8, 0, core::ptr::null_mut(), core::ptr::null_mut());
        });
        overflows(|| {
            crate::io::__inet_ntop_chk(2, p.cast(), p, 16, 8);
        });
        overflows(|| {
            crate::io::__inet_pton_chk(2, c"1.2.3.4".as_ptr(), p.cast(), 3);
        });
        overflows(|| {
            crate::io::__inet_pton_chk(10, c"::1".as_ptr(), p.cast(), 15);
        });
        // open forms that need a mode
        for (name, f) in [(&b"open"[..], 0), (b"open64", 1), (b"openat", 2), (b"openat64", 3)] {
            for flags in [libc::O_CREAT, libc::O_TMPFILE | libc::O_RDWR] {
                let msg = format!("*** invalid {} call: O_CREAT or O_TMPFILE without mode ***: terminated\n", String::from_utf8_lossy(name));
                aborts_with(msg.as_bytes(), || {
                    match f {
                        0 => crate::io::__open_2(c"/tmp/x".as_ptr(), flags),
                        1 => crate::io::__open64_2(c"/tmp/x".as_ptr(), flags),
                        2 => crate::io::__openat_2(-100, c"/tmp/x".as_ptr(), flags),
                        _ => crate::io::__openat64_2(-100, c"/tmp/x".as_ptr(), flags),
                    };
                });
            }
        }
        // `getcwd` with a buffer of exactly the right size is fine; `poll` with fewer entries than room too
        let (sig, out) = dies(|| {
            let mut fds = [libc::pollfd { fd: -1, events: 0, revents: 0 }; 2];
            let r = crate::io::__poll_chk(fds.as_mut_ptr().cast(), 2, 0, 16);
            libc::_exit(if r == 0 { 0 } else { 3 });
        });
        assert_eq!((sig, out.len()), (0, 0));
    }
}

#[test]
fn stream_functions() {
    use rusty_libc_stdio as io;
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let (fd, path) = tmpfile_with(b"line one\nsecond line is longer\nthird\n0123456789");
        libc::close(fd);
        let f = io::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        let mut b = [0xAAu8; 32];
        // plain line
        let r = crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, 32, f);
        assert_eq!((r.is_null(), text(&b)), (false, "line one\n".to_string()));
        // n limits the read: "second li"
        let r = crate::stream::__fgets_unlocked_chk(b.as_mut_ptr().cast(), 32, 10, f);
        assert_eq!((r.is_null(), text(&b)), (false, "second li".to_string()));
        // the rest of the line fits
        let r = crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, 32, f);
        assert_eq!((r.is_null(), text(&b)), (false, "ne is longer\n".to_string()));
        // n <= 0 gives NULL and reads nothing
        assert!(crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, 0, f).is_null());
        assert!(crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, -3, f).is_null());
        // fread
        let mut c = [0u8; 16];
        let n = crate::stream::__fread_chk(c.as_mut_ptr().cast(), 16, 2, 3, f);
        assert_eq!((n, &c[..6]), (3, &b"third\n"[..]));
        let n = crate::stream::__fread_unlocked_chk(c.as_mut_ptr().cast(), 16, 3, 5, f);
        assert_eq!((n, &c[..3]), (3, &b"012"[..])); // 10 bytes left: 3 items of 3
        assert_eq!(crate::stream::__fread_chk(c.as_mut_ptr().cast(), 16, 0, 5, f), 0);
        assert_eq!(crate::stream::__fread_chk(c.as_mut_ptr().cast(), 16, 5, 0, f), 0);
        // end of file: NULL
        io::fseek(f, 0, 2);
        assert!(crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, 32, f).is_null());
        io::fseek(f, -10, 2);
        let r = crate::stream::__fgets_chk(b.as_mut_ptr().cast(), 32, 32, f);
        assert_eq!((r.is_null(), text(&b)), (false, "0123456789".to_string()));
        io::fclose(f);
        libc::unlink(path.as_ptr());
    }
}

#[test]
fn stream_overflows_abort() {
    use rusty_libc_stdio as io;
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let (fd, path) = tmpfile_with(b"abcdefghijklmnop\n");
        libc::close(fd);
        let mut buf = [0u8; 64];
        let p = buf.as_mut_ptr() as *mut c_char;
        let ph = path.as_ptr() as usize;
        // a line longer than the object
        overflows(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fgets_chk(p, 8, 64, f);
        });
        overflows(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fgets_unlocked_chk(p, 8, 64, f);
        });
        // size exactly the line (with NUL it would not fit)
        overflows(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fgets_chk(p, 17, 64, f);
        });
        overflows(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fread_chk(p.cast(), 8, 3, 3, f);
        });
        overflows(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fread_unlocked_chk(p.cast(), 8, 1, 9, f);
        });
        overflows(|| {
            // size * n wraps around
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            crate::stream::__fread_chk(p.cast(), 8, 1 << 33, 1 << 33, f);
        });
        // a line that fits with its NUL does not abort
        let (sig, out) = dies(|| {
            let f = io::fopen(ph as *const c_char, c"r".as_ptr());
            let r = crate::stream::__fgets_chk(p, 18, 64, f);
            libc::_exit(if !r.is_null() { 0 } else { 3 });
        });
        assert_eq!((sig, out.len()), (0, 0));
        // gets from standard input (a pipe in the child)
        let gets_in = |data: &'static [u8], size: usize| {
            dies(move || {
                let mut fds = [0; 2];
                libc::pipe(fds.as_mut_ptr());
                libc::write(fds[1], data.as_ptr().cast(), data.len());
                libc::close(fds[1]);
                libc::dup2(fds[0], 0);
                let mut b = [0u8; 16];
                let r = crate::stream::__gets_chk(b.as_mut_ptr().cast(), size);
                let s = if r.is_null() { None } else { Some(CStr::from_ptr(r).to_bytes().to_vec()) };
                libc::_exit(match s.as_deref() {
                    Some(b"hello") => 0,
                    None => 4,
                    _ => 3,
                });
            })
        };
        assert_eq!(gets_in(b"hello\nrest\n", 6).0, 0); // 5 chars + NUL
        assert_eq!(gets_in(b"hello", 6).0, 0); // end of file ends the line too
        assert_eq!(gets_in(b"", 6).0, 0); // exit code 4 is not a signal
        let (sig, out) = gets_in(b"hello!\n", 6);
        assert_eq!((sig, out.as_slice()), (ABORT, OVERFLOW));
        let (sig, out) = gets_in(b"hello\n", 5);
        assert_eq!((sig, out.as_slice()), (ABORT, OVERFLOW));
        overflows(|| {
            crate::stream::__gets_chk(p, 0);
        });
        libc::unlink(path.as_ptr());
    }
}

fn w(s: &str) -> Vec<i32> {
    let mut v: Vec<i32> = s.chars().map(|c| c as i32).collect();
    v.push(0);
    v
}

fn wtext(b: &[i32]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..n].iter().map(|&c| char::from_u32(c as u32).unwrap_or('?')).collect()
}

#[test]
fn wide_functions_match_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xabcd_ef01_2345_6789);
    for _ in 0..3000 {
        let src = {
            let n = r.below(30);
            let mut v: Vec<i32> = (0..n).map(|_| 'a' as i32 + r.below(26) as i32).collect();
            v.push(0);
            v
        };
        let pre = {
            let n = r.below(15);
            let mut v: Vec<i32> = (0..n).map(|_| 'A' as i32 + r.below(26) as i32).collect();
            v.push(0);
            v
        };
        let sl = src.len() - 1;
        let pl = pre.len() - 1;
        let n = r.below(40);
        let dl = 4 + r.below(60);
        let mut base = vec![0x7777i32; dl + 4];
        if pre.len() <= dl {
            base[..pre.len()].copy_from_slice(&pre);
        }
        let pre_fits = pre.len() <= dl;
        let c = 'q' as i32;
        macro_rules! same {
            ($ours:expr, $theirs:expr) => {{
                let (mut a, mut b) = (base.clone(), base.clone());
                let (ra, rb) = unsafe { ($ours(a.as_mut_ptr()), $theirs(b.as_mut_ptr())) };
                let (oa, ob) = (ra as isize - a.as_ptr() as isize, rb as isize - b.as_ptr() as isize);
                assert_eq!((oa, &a), (ob, &b));
            }};
        }
        macro_rules! same_n {
            ($ours:expr, $theirs:expr) => {{
                let (mut a, mut b) = (base.clone(), base.clone());
                let (ra, rb) = unsafe { ($ours(a.as_mut_ptr()), $theirs(b.as_mut_ptr())) };
                assert_eq!((ra, &a), (rb, &b));
            }};
        }
        let s = src.as_ptr();
        {
            if n <= dl {
                same!(|d| crate::wide::__wmemcpy_chk(d, s, n.min(src.len()), dl), |d| host::__wmemcpy_chk(d, s, n.min(src.len()), dl));
                same!(|d| crate::wide::__wmemmove_chk(d, s, n.min(src.len()), dl), |d| host::__wmemmove_chk(d, s, n.min(src.len()), dl));
                same!(|d| crate::wide::__wmempcpy_chk(d, s, n.min(src.len()), dl), |d| host::__wmempcpy_chk(d, s, n.min(src.len()), dl));
                same!(|d| crate::wide::__wmemset_chk(d, c, n, dl), |d| host::__wmemset_chk(d, c, n, dl));
                same!(|d| crate::wide::__wcsncpy_chk(d, s, n, dl), |d| host::__wcsncpy_chk(d, s, n, dl));
                same!(|d| crate::wide::__wcpncpy_chk(d, s, n, dl), |d| host::__wcpncpy_chk(d, s, n, dl));
                same_n!(|d| crate::wide::__wcslcpy_chk(d, s, n, dl), |d| host::__wcslcpy_chk(d, s, n, dl));
            }
            if sl < dl {
                same!(|d| crate::wide::__wcscpy_chk(d, s, dl), |d| host::__wcscpy_chk(d, s, dl));
                same!(|d| crate::wide::__wcpcpy_chk(d, s, dl), |d| host::__wcpcpy_chk(d, s, dl));
            }
            if pre_fits && pl + sl < dl {
                same!(|d| crate::wide::__wcscat_chk(d, s, dl), |d| host::__wcscat_chk(d, s, dl));
            }
            if pre_fits && pl + n.min(sl) < dl {
                same!(|d| crate::wide::__wcsncat_chk(d, s, n, dl), |d| host::__wcsncat_chk(d, s, n, dl));
            }
            if pre_fits && n <= dl {
                same_n!(|d| crate::wide::__wcslcat_chk(d, s, n, dl), |d| host::__wcslcat_chk(d, s, n, dl));
            }
        }
    }
}

#[test]
fn multibyte_functions_match_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let text_in = b"hello world\0";
        let (mut a, mut b) = ([0x55i32; 32], [0x55i32; 32]);
        let ra = crate::wide::__mbstowcs_chk(a.as_mut_ptr(), cs(text_in), 20, 32);
        let rb = host::__mbstowcs_chk(b.as_mut_ptr(), cs(text_in), 20, 32);
        assert_eq!((ra, a), (rb, b));
        let wide = w("wide text");
        let (mut a, mut b) = ([0x55u8; 32], [0x55u8; 32]);
        let ra = crate::wide::__wcstombs_chk(a.as_mut_ptr().cast(), wide.as_ptr(), 20, 32);
        let rb = host::__wcstombs_chk(b.as_mut_ptr().cast(), wide.as_ptr(), 20, 32);
        assert_eq!((ra, a), (rb, b));
        let (mut a, mut b) = ([0x55u8; 16], [0x55u8; 16]);
        let ra = crate::wide::__wctomb_chk(a.as_mut_ptr().cast(), 'x' as i32, 16);
        let rb = host::__wctomb_chk(b.as_mut_ptr().cast(), 'x' as i32, 16);
        assert_eq!((ra, a), (rb, b));
        // wcrtomb with a small exact buffer
        let mut st: rusty_libc_wchar::mbstate_t = core::mem::zeroed();
        let mut a = [0x55u8; 1];
        assert_eq!(crate::wide::__wcrtomb_chk(a.as_mut_ptr().cast(), 'y' as i32, &mut st, 1), 1);
        assert_eq!(a[0], b'y');
        assert_eq!(crate::wide::__wcrtomb_chk(core::ptr::null_mut(), 0, &mut st, 0), 1);
        // mbsrtowcs / mbsnrtowcs / wcsrtombs / wcsnrtombs round trip
        let mut src = cs(b"abcdef\0");
        let mut wb = [0i32; 16];
        let mut st: rusty_libc_wchar::mbstate_t = core::mem::zeroed();
        assert_eq!(crate::wide::__mbsrtowcs_chk(wb.as_mut_ptr(), &mut src, 16, &mut st, 16), 6);
        assert_eq!(wtext(&wb), "abcdef");
        assert!(src.is_null());
        let mut src = cs(b"abcdef\0");
        let mut wb = [0i32; 16];
        assert_eq!(crate::wide::__mbsnrtowcs_chk(wb.as_mut_ptr(), &mut src, 3, 16, &mut st, 16), 3);
        assert_eq!(wtext(&wb), "abc");
        let ws = w("xyz");
        let mut psrc = ws.as_ptr();
        let mut cb = [0u8; 8];
        assert_eq!(crate::wide::__wcsrtombs_chk(cb.as_mut_ptr().cast(), &mut psrc, 8, &mut st, 8), 3);
        assert_eq!(&cb[..4], b"xyz\0");
        let mut psrc = ws.as_ptr();
        let mut cb = [0u8; 8];
        assert_eq!(crate::wide::__wcsnrtombs_chk(cb.as_mut_ptr().cast(), &mut psrc, 2, 8, &mut st, 8), 2);
        assert_eq!(&cb[..2], b"xy");
    }
}

#[test]
fn wide_overflows_abort() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = [0i32; 32];
    let p = buf.as_mut_ptr();
    let src = w("abcdefgh");
    let s = src.as_ptr();
    let sp = s as usize;
    let pp = p as usize;
    unsafe {
        overflows(|| {
            crate::wide::__wmemcpy_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__wmemmove_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__wmempcpy_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__wmemset_chk(pp as *mut i32, 1, 9, 8);
        });
        overflows(|| {
            crate::wide::__wcscpy_chk(pp as *mut i32, sp as *const i32, 8);
        });
        overflows(|| {
            crate::wide::__wcpcpy_chk(pp as *mut i32, sp as *const i32, 8);
        });
        overflows(|| {
            crate::wide::__wcsncpy_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__wcpncpy_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            let mut d = w("abcd");
            d.resize(16, 0);
            crate::wide::__wcscat_chk(d.as_mut_ptr(), sp as *const i32, 8);
        });
        overflows(|| {
            let mut d = w("abcd");
            d.resize(16, 0);
            crate::wide::__wcsncat_chk(d.as_mut_ptr(), sp as *const i32, 4, 8);
        });
        overflows(|| {
            let mut d = vec![7i32; 8]; // no terminator inside the object
            crate::wide::__wcscat_chk(d.as_mut_ptr(), sp as *const i32, 8);
        });
        overflows(|| {
            crate::wide::__wcslcpy_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__wcslcat_chk(pp as *mut i32, sp as *const i32, 9, 8);
        });
        overflows(|| {
            crate::wide::__mbstowcs_chk(pp as *mut i32, c"abc".as_ptr(), 9, 8);
        });
        overflows(|| {
            crate::wide::__wcstombs_chk(pp as *mut c_char, sp as *const i32, 9, 8);
        });
        overflows(|| {
            let mut s: *const c_char = c"abc".as_ptr();
            crate::wide::__mbsrtowcs_chk(pp as *mut i32, &mut s, 9, core::ptr::null_mut(), 8);
        });
        overflows(|| {
            let mut s: *const c_char = c"abc".as_ptr();
            crate::wide::__mbsnrtowcs_chk(pp as *mut i32, &mut s, 3, 9, core::ptr::null_mut(), 8);
        });
        overflows(|| {
            let mut s = sp as *const i32;
            crate::wide::__wcsrtombs_chk(pp as *mut c_char, &mut s, 9, core::ptr::null_mut(), 8);
        });
        overflows(|| {
            let mut s = sp as *const i32;
            crate::wide::__wcsnrtombs_chk(pp as *mut c_char, &mut s, 3, 9, core::ptr::null_mut(), 8);
        });
        overflows(|| {
            crate::wide::__wctomb_chk(pp as *mut c_char, 'x' as i32, 0);
        });
        overflows(|| {
            // 'é' needs 2 bytes in UTF-8 and the buffer has 1
            let mut st: rusty_libc_wchar::mbstate_t = core::mem::zeroed();
            rusty_libc_wchar::set_charset(rusty_libc_wchar::Charset::Utf8);
            crate::wide::__wcrtomb_chk(pp as *mut c_char, 0xe9, &mut st, 1);
        });
    }
}

fn wz(s: &str) -> Vec<i32> {
    s.chars().map(|c| c as i32).chain([0]).collect()
}

#[test]
fn wide_printf_checks_match_host_and_abort() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // ordinary calls: same result and bytes as the host's __swprintf_chk
        for (fmt, n, slen) in [("abc", 8usize, 8usize), ("%d-%d", 16, 16), ("%x|%o|", 20, 32), ("%5.2f", 10, 10), ("", 4, 4), ("toolongtext", 5, 5), ("x", 0, 3)] {
            let f = wz(fmt);
            let mut a = vec![0x55i32; 40];
            let mut b = a.clone();
            let ra = crate::widestdio::__swprintf_chk(a.as_mut_ptr(), n, 0, slen, f.as_ptr(), 42i32, 7i32);
            let rb = host::__swprintf_chk(b.as_mut_ptr(), n, 0, slen, f.as_ptr(), 42i32, 7i32);
            assert_eq!(ra, rb, "{fmt:?} return");
            assert_eq!(a, b, "{fmt:?} buffer");
        }
        // the object is smaller than the size the caller gives
        overflows(|| {
            let mut b = [0i32; 4];
            crate::widestdio::__swprintf_chk(b.as_mut_ptr(), 8, 0, 4, wz("x").as_ptr());
        });
        let host_dies = dies(|| {
            let mut b = [0i32; 4];
            host::__swprintf_chk(b.as_mut_ptr(), 8, 0, 4, wz("x").as_ptr());
        });
        assert_eq!(host_dies.0, ABORT);
        // %n from a writable wide format with flag 1
        let wmsg = b"*** %n in writable segments detected ***\n";
        aborts_with(wmsg, || {
            let mut b = [0i32; 16];
            let fmt = wz("abc%n");
            let mut c: c_int = 0;
            crate::widestdio::__swprintf_chk(b.as_mut_ptr(), 16, 1, 16, fmt.as_ptr(), &mut c as *mut c_int);
        });
        let (sig, out) = dies(|| {
            let mut b = [0i32; 16];
            let fmt = wz("abc%n");
            let mut c: c_int = 0;
            crate::widestdio::__swprintf_chk(b.as_mut_ptr(), 16, 0, 16, fmt.as_ptr(), &mut c as *mut c_int);
        });
        assert_eq!((sig, out.len()), (0, 0), "flag 0: no %n check");
        aborts_with(b"*** invalid %N$ use detected ***\n", || {
            let mut b = [0i32; 16];
            crate::widestdio::__swprintf_chk(b.as_mut_ptr(), 16, 1, 16, wz("%2$d").as_ptr(), 1, 2);
        });
        // fgetws: reads up to min(n-1, size) wide characters, aborts when that many were stored
        let (fd, path) = tmpfile_with(b"abcdefgh\nxyz\n");
        libc::close(fd);
        for (size, n) in [(16usize, 16 as c_int), (4, 16), (9, 9), (3, 3), (4, 5), (2, 2), (1, 1), (8, 0)] {
            let mut r = [(0u8, vec![], 0u8, vec![]); 1];
            let hf = libc::fopen(path.as_ptr(), c"r".as_ptr());
            let (hs, hout) = dies(|| {
                let mut b = [0x55i32; 20];
                let p = host::__fgetws_chk(b.as_mut_ptr(), size, n, hf.cast());
                let mut o = format!("{} ", p.is_null());
                for c in &b[..size.min(20)] {
                    o.push_str(&format!("{c:x} "));
                }
                libc::write(2, o.as_ptr().cast(), o.len());
                libc::_exit(0);
            });
            libc::fclose(hf);
            let of = rusty_libc_stdio::fopen(path.as_ptr(), c"r".as_ptr());
            let (os, oout) = dies(|| {
                let mut b = [0x55i32; 20];
                let p = crate::widestdio::__fgetws_chk(b.as_mut_ptr(), size, n, of);
                let mut o = format!("{} ", p.is_null());
                for c in &b[..size.min(20)] {
                    o.push_str(&format!("{c:x} "));
                }
                libc::write(2, o.as_ptr().cast(), o.len());
                libc::_exit(0);
            });
            rusty_libc_stdio::fclose(of);
            r[0] = (hs as u8, hout.clone(), os as u8, oout.clone());
            assert_eq!((hs, &hout), (os, &oout), "fgetws_chk(size {size}, n {n})");
        }
        libc::unlink(path.as_ptr());
    }
}

// keep unused imports honest
#[allow(dead_code)]
fn _types(_: c_ulong, _: *const c_void) {}

#[test]
fn readonly_area_program_headers_without_dl_iterate_phdr() {
    // the path a program takes when the runtime has no dl_iterate_phdr: its own headers, found through __ehdr_start
    use crate::readonly::{Query, Seg, program_object};
    static RO: [u8; 8] = *b"literal\0";
    static mut RW: [u8; 8] = *b"writabl\0";
    let local = [0u8; 8];
    let ask = |p: *const u8| {
        let mut q = Query { ptr: p as usize, end: p as usize + 8, verdict: Seg::NoVerdict };
        program_object(&mut q);
        q.verdict
    };
    assert!(ask(RO.as_ptr()) == Seg::ReadOnly);
    assert!(ask((&raw const RW).cast()) == Seg::Writable);
    assert!(ask(local.as_ptr()) == Seg::NoVerdict); // the stack is in no object: /proc/self/maps decides
}
