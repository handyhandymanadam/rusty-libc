//! popen, freopen, cookies, temporary names, getw/putw and stdio_ext against glibc.
use crate::LOCK;
use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};

mod g {
    use core::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn freopen(p: *const c_char, m: *const c_char, f: *mut c_void) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fwrite(p: *const c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fread(p: *mut c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn ftell(f: *mut c_void) -> i64;
        pub fn popen(c: *const c_char, t: *const c_char) -> *mut c_void;
        pub fn pclose(f: *mut c_void) -> c_int;
        pub fn getw(f: *mut c_void) -> c_int;
        pub fn putw(w: c_int, f: *mut c_void) -> c_int;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn fwide(f: *mut c_void, mode: c_int) -> c_int;
        pub fn fopencookie(c: *mut c_void, m: *const c_char, io: super::CookieFns) -> *mut c_void;
        pub fn __fbufsize(f: *mut c_void) -> usize;
        pub fn __fpending(f: *mut c_void) -> usize;
        pub fn __flbf(f: *mut c_void) -> c_int;
        pub fn __freadable(f: *mut c_void) -> c_int;
        pub fn __fwritable(f: *mut c_void) -> c_int;
        pub fn __freading(f: *mut c_void) -> c_int;
        pub fn __fwriting(f: *mut c_void) -> c_int;
    }
}

use crate::file_extra::cookie_io_functions_t as CookieFns;

fn tmp(name: &str) -> String {
    format!("{}/rusty-libc-extra-{}-{name}", std::env::temp_dir().display(), std::process::id())
}

#[test]
fn popen_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // reading: the command's output and its exit status
    for cmd in ["echo hello; echo world", "printf 'no newline'", "exit 3", "echo out; echo err 1>&2; exit 1", "kill -9 $$", "true", "cat /proc/self/status | head -c 200 | wc -c"] {
        let c = CString::new(cmd).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let (ra, rb);
        unsafe {
            let f = crate::file_extra::popen(c.as_ptr(), c"r".as_ptr());
            assert!(!f.is_null(), "{cmd}");
            let mut buf = [0u8; 4096];
            loop {
                let n = crate::file::read_bytes(&mut *(f), &mut buf[..]);
                if n == 0 {
                    break;
                }
                a.extend_from_slice(&buf[..n]);
            }
            ra = crate::file_extra::pclose(f);
            let f = g::popen(c.as_ptr(), c"r".as_ptr());
            loop {
                let n = g::fread(buf.as_mut_ptr().cast(), 1, buf.len(), f);
                if n == 0 {
                    break;
                }
                b.extend_from_slice(&buf[..n]);
            }
            rb = g::pclose(f);
        }
        assert_eq!(a, b, "{cmd}");
        assert_eq!(ra, rb, "{cmd}: wait status");
    }
    // writing: a command that copies its input into a file
    let (pa, pb) = (tmp("popen-a"), tmp("popen-b"));
    let data = b"line one\nline two\nline three\n";
    unsafe {
        let ca = CString::new(format!("cat > {pa}")).unwrap();
        let f = crate::file_extra::popen(ca.as_ptr(), c"w".as_ptr());
        assert_eq!(crate::file::write_bytes(&mut *(f), &data[..data.len()]), data.len());
        assert_eq!(crate::file_extra::pclose(f), 0);
        let cb = CString::new(format!("cat > {pb}")).unwrap();
        let f = g::popen(cb.as_ptr(), c"w".as_ptr());
        g::fwrite(data.as_ptr().cast(), 1, data.len(), f);
        assert_eq!(g::pclose(f), 0);
    }
    assert_eq!(std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
    assert_eq!(std::fs::read(&pa).unwrap(), data);
    // a bad mode
    unsafe {
        crate::file_extra::popen(c"true".as_ptr(), c"x".as_ptr());
    }
    let _ = (std::fs::remove_file(&pa), std::fs::remove_file(&pb));
}

#[test]
fn freopen_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (p1, p2, q1, q2) = (tmp("fr-a1"), tmp("fr-a2"), tmp("fr-b1"), tmp("fr-b2"));
    std::fs::write(&p1, b"first file contents\n").unwrap();
    std::fs::write(&q1, b"first file contents\n").unwrap();
    unsafe {
        // ours
        let (c1, c2) = (CString::new(p1.clone()).unwrap(), CString::new(p2.clone()).unwrap());
        let f = crate::file::fopen(Some(&c1), c"r+".to_bytes());
        let mut buf = [0u8; 8];
        crate::file::read_bytes(&mut *(f), &mut buf[..5]);
        let fd1 = (*f).fd;
        let f2 = crate::file_extra::freopen(c2.as_ptr(), c"w+".as_ptr(), f);
        assert_eq!(f2, f);
        assert_eq!((*f).fd, fd1, "the descriptor number is kept");
        crate::file::write_bytes(&mut *(f), &b"second"[..6]);
        crate::file::seek(&mut *f, 0, 0);
        let n = crate::file::read_bytes(&mut *(f), &mut buf[..8]);
        assert_eq!(&buf[..n], b"second");
        // no path: the same file, new mode
        let f3 = crate::file_extra::freopen(core::ptr::null(), c"r".as_ptr(), f);
        assert_eq!(f3, f);
        let n = crate::file::read_bytes(&mut *(f), &mut buf[..8]);
        assert_eq!(&buf[..n], b"second", "reopened without a path reads the same file from the start");
        // failure closes the stream and returns NULL
        let missing = c"/nonexistent/dir/x";
        assert!(crate::file_extra::freopen(missing.as_ptr(), c"r".as_ptr(), f).is_null());
        // glibc, same steps
        let (d1, d2) = (CString::new(q1.clone()).unwrap(), CString::new(q2.clone()).unwrap());
        let h = g::fopen(d1.as_ptr(), c"r+".as_ptr());
        g::fread(buf.as_mut_ptr().cast(), 1, 5, h);
        let h2 = g::freopen(d2.as_ptr(), c"w+".as_ptr(), h);
        assert_eq!(h2, h);
        g::fwrite(b"second".as_ptr().cast(), 1, 6, h);
        g::fclose(h);
    }
    assert_eq!(std::fs::read(&p2).unwrap(), std::fs::read(&q2).unwrap());
    assert_eq!(std::fs::read(&p1).unwrap(), std::fs::read(&q1).unwrap());
    for p in [&p1, &p2, &q1, &q2] {
        let _ = std::fs::remove_file(p);
    }
}

/// FIXLIST #102: freopen with a `,ccs=` charset that cannot be set up while another thread exists (the stream's lock is
/// taken): NULL and EINVAL as glibc, the stream closed and freed only after its lock is released (it used to be freed
/// first and then unlocked); the list of streams stays usable.
#[test]
fn freopen_bad_ccs_with_threads_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (pa, pb) = (tmp("frccs-a"), tmp("frccs-b"));
    std::fs::write(&pa, b"contents of a\n").unwrap();
    std::fs::write(&pb, b"contents of b\n").unwrap();
    let (ca, cb) = (CString::new(pa.clone()).unwrap(), CString::new(pb.clone()).unwrap());
    let mode = CString::new(format!("r,ccs={}", "X".repeat(300))).unwrap();
    // a second thread alive during the calls, so stdio takes the stream locks
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let t = std::thread::spawn(move || rx.recv().ok());
    assert!(rusty_libc_core::lock::multithreaded(), "the locking path is taken");
    for _ in 0..3 {
        unsafe {
            let f = crate::file::fopen(Some(&ca), c"r".to_bytes());
            assert!(!f.is_null());
            rusty_libc_core::errno::set(0);
            let r = crate::file_extra::freopen(cb.as_ptr(), mode.as_ptr(), f);
            assert!(r.is_null());
            assert_eq!(rusty_libc_core::errno::get(), 22);
            assert_eq!(crate::file_api::fflush(core::ptr::null_mut()), 0);
            let g2 = crate::file::fopen(Some(&ca), c"r".to_bytes());
            let mut buf = [0u8; 16];
            let n = crate::file::read_bytes(&mut *g2, &mut buf);
            assert_eq!(&buf[..n], b"contents of a\n");
            assert_eq!(crate::file_api::fclose(g2), 0);
            // glibc, same call
            let h = g::fopen(ca.as_ptr(), c"r".as_ptr());
            let hr = g::freopen(cb.as_ptr(), mode.as_ptr(), h);
            let ge = std::io::Error::last_os_error().raw_os_error();
            assert!(hr.is_null());
            assert_eq!(ge, Some(22));
        }
    }
    tx.send(()).unwrap();
    t.join().unwrap();
    for p in [&pa, &pb] {
        let _ = std::fs::remove_file(p);
    }
}

/// FIXLIST #109: which `,ccs=` names and mode strings fopen accepts, against the host glibc (NULL and errno, orientation).
#[test]
fn fopen_ccs_names_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let p = tmp("ccs-names");
    std::fs::write(&p, b"text\n").unwrap();
    let cp = CString::new(p.clone()).unwrap();
    let names = [
        "UTF-8", "utf8", "Utf-8", " UTF-8 ", "UTF@8", "utf_8", "UTF-8/", "UTF-8///", "UTF-8//TRANSLIT", "UTF-8//IGNORE", "/UTF-8", "latin1",
        "8859_1", "+ISO-8859-1", "UCS-4", "UTF-16", "WCHAR_T", "wchar_t", "INTERNAL", "ISO-10646/UTF8/", "ISO-10646/UCS4/X", "", "//",
        "@@", "NO-SUCH", "C", "POSIX", "LOCALE",
    ];
    let mut modes: Vec<String> = names.iter().map(|n| format!("r,ccs={n}")).collect();
    for m in ["r,CCS=UTF-8", "r,x,ccs=UTF-8", "r,ccs=UTF-8 junk", "r,ccs=UTF-8,ccs=NOPE", "r,ccs=NOPE,ccs=UTF-8", "rbbbbbbb,ccs=NOPE", "rccs=UTF-8"] {
        modes.push(m.to_string());
    }
    modes.push(format!("r,ccs=U{}TF-8", " ".repeat(300)));
    modes.push(format!("r,ccs={}", "X".repeat(300)));
    for m in &modes {
        let cm = CString::new(m.clone()).unwrap();
        unsafe {
            rusty_libc_core::errno::set(0);
            let f = crate::file::fopen(Some(&cp), cm.as_bytes());
            let ours = (f.is_null(), if f.is_null() { rusty_libc_core::errno::get() } else { 0 }, !f.is_null() && (*f).wide.is_null());
            if !f.is_null() {
                crate::file_api::fclose(f);
            }
            let h = g::fopen(cp.as_ptr(), cm.as_ptr());
            let ge = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let glibc = (h.is_null(), if h.is_null() { ge } else { 0 }, !h.is_null() && g::fwide(h, 0) == 0);
            if !h.is_null() {
                g::fclose(h);
            }
            assert_eq!(ours, glibc, "mode {m:?}: (NULL, errno, byte stream)");
        }
    }
    let _ = std::fs::remove_file(&p);
}

/// FIXLIST #109: a stream that freopen could not reopen is freed (as glibc's), whatever the failure; the list stays usable.
#[test]
fn freopen_failures_free_the_stream() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let p = tmp("frfail");
    std::fs::write(&p, b"text\n").unwrap();
    let cp = CString::new(p.clone()).unwrap();
    let cases: [(Option<&CStr>, &CStr, c_int); 4] =
        [(Some(&cp), c"q", 22), (Some(c"/nonexistent/dir/x"), c"r", 2), (Some(&cp), c"r,ccs=NO-SUCH", 22), (Some(&cp), c"r,ccs=", 22)];
    for (path, mode, want) in cases {
        unsafe {
            let f = crate::file::fopen(Some(&cp), c"r".to_bytes());
            assert!(!f.is_null());
            rusty_libc_core::errno::set(0);
            let r = crate::file_extra::freopen(path.map_or(core::ptr::null(), |p| p.as_ptr()), mode.as_ptr(), f);
            assert!(r.is_null(), "{mode:?}");
            assert_eq!(rusty_libc_core::errno::get(), want, "{mode:?}");
            assert_eq!(crate::file_api::fflush(core::ptr::null_mut()), 0);
        }
    }
    let _ = std::fs::remove_file(&p);
}

// A cookie stream over a Vec: both implementations call the same functions.
struct Mem {
    data: Vec<u8>,
    pos: usize,
    log: Vec<String>,
}

unsafe extern "C" fn c_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    unsafe {
        let m = &mut *(c as *mut Mem);
        let k = n.min(m.data.len().saturating_sub(m.pos));
        core::ptr::copy_nonoverlapping(m.data.as_ptr().add(m.pos), b as *mut u8, k);
        m.pos += k;
        m.log.push(format!("read {n} -> {k}"));
        k as isize
    }
}
unsafe extern "C" fn c_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    unsafe {
        let m = &mut *(c as *mut Mem);
        if m.pos + n > m.data.len() {
            m.data.resize(m.pos + n, 0);
        }
        core::ptr::copy_nonoverlapping(b as *const u8, m.data.as_mut_ptr().add(m.pos), n);
        m.pos += n;
        m.log.push(format!("write {n}"));
        n as isize
    }
}
unsafe extern "C" fn c_seek(c: *mut c_void, p: *mut i64, w: c_int) -> c_int {
    unsafe {
        let m = &mut *(c as *mut Mem);
        let base = match w {
            0 => 0,
            1 => m.pos as i64,
            _ => m.data.len() as i64,
        };
        let np = base + *p;
        if np < 0 {
            return -1;
        }
        m.pos = np as usize;
        *p = np;
        m.log.push(format!("seek {np}"));
        0
    }
}
unsafe extern "C" fn c_close(c: *mut c_void) -> c_int {
    unsafe { (*(c as *mut Mem)).log.push("close".into()) };
    0
}

#[test]
fn fopencookie_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let io = CookieFns { read: Some(c_read), write: Some(c_write), seek: Some(c_seek), close: Some(c_close) };
    let run = |ours: bool| -> (Vec<String>, Vec<u8>, Vec<String>) {
        let mut m = Box::new(Mem { data: b"0123456789abcdefghij".to_vec(), pos: 0, log: Vec::new() });
        let mut out = Vec::new();
        unsafe {
            let cookie = &mut *m as *mut Mem as *mut c_void;
            let f = if ours { crate::file_extra::fopencookie(cookie, c"r+".as_ptr(), io) as *mut c_void } else { g::fopencookie(cookie, c"r+".as_ptr(), io) };
            assert!(!f.is_null());
            let mut buf = [0u8; 32];
            let rd = |f: *mut c_void, n: usize, buf: &mut [u8; 32]| if ours { crate::file::read_bytes(&mut *(f as *mut crate::file::File), &mut buf[..n]) } else { g::fread(buf.as_mut_ptr().cast(), 1, n, f) };
            let wr = |f: *mut c_void, s: &[u8]| if ours { crate::file::write_bytes(&mut *(f as *mut crate::file::File), &s[..s.len()]) } else { g::fwrite(s.as_ptr().cast(), 1, s.len(), f) };
            let sk = |f: *mut c_void, o: i64, w: c_int| if ours { crate::file::seek(&mut *(f as *mut crate::file::File), o, w) } else { crate::file_api::fseek_glibc(f, o, w) };
            let tl = |f: *mut c_void| if ours { crate::file::tell(&mut *(f as *mut crate::file::File)) } else { g::ftell(f) };
            let n = rd(f, 5, &mut buf);
            out.push(format!("read5 {n} {:?} tell {}", String::from_utf8_lossy(&buf[..n]), tl(f)));
            sk(f, 2, 0);
            out.push(format!("write {}", wr(f, b"XYZ")));
            sk(f, 0, 0);
            let n = rd(f, 32, &mut buf);
            out.push(format!("all {n} {:?}", String::from_utf8_lossy(&buf[..n])));
            out.push(format!("seek end {} tell {}", sk(f, -3, 2), tl(f)));
            out.push(format!("close {}", if ours { crate::file::fclose(f as _) } else { g::fclose(f) }));
        }
        (out, m.data.clone(), m.log.clone())
    };
    let (a, b) = (run(true), run(false));
    assert_eq!(a.0, b.0);
    assert_eq!(a.1, b.1);
    // (the sequence of calls glibc makes on the cookie is not copied: it re-seeks more often)
    assert!(a.2.contains(&"write 3".to_string()) && a.2.last().map(String::as_str) == Some("close"));
}

#[test]
fn getw_putw_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (pa, pb) = (tmp("w-a"), tmp("w-b"));
    let (ca, cb) = (CString::new(pa.clone()).unwrap(), CString::new(pb.clone()).unwrap());
    unsafe {
        let f = crate::file::fopen(Some(&ca), c"w+".to_bytes());
        let h = g::fopen(cb.as_ptr(), c"w+".as_ptr());
        for w in [0, 1, -1, 305419896, i32::MIN, i32::MAX] {
            assert_eq!(crate::file_extra::putw(w, f as _), g::putw(w, h));
        }
        crate::file::seek(&mut *f, 0, 0);
        crate::file_extra::__uflow(f);
        crate::file::seek(&mut *f, 0, 0);
        g::fflush(h);
        crate::file::fclose(f);
        assert_eq!(std::fs::read(&pa).unwrap(), {
            g::fclose(h);
            std::fs::read(&pb).unwrap()
        });
        let f = crate::file::fopen(Some(&ca), c"r".to_bytes());
        let h = g::fopen(cb.as_ptr(), c"r".as_ptr());
        for _ in 0..8 {
            assert_eq!(crate::file_extra::getw(f as _), g::getw(h));
        }
        crate::file::fclose(f);
        g::fclose(h);
    }
    let _ = (std::fs::remove_file(&pa), std::fs::remove_file(&pb));
}

#[test]
fn stdio_ext_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (pa, pb) = (tmp("ext-a"), tmp("ext-b"));
    std::fs::write(&pa, vec![b'x'; 10000]).unwrap();
    std::fs::write(&pb, vec![b'x'; 10000]).unwrap();
    let (ca, cb) = (CString::new(pa.clone()).unwrap(), CString::new(pb.clone()).unwrap());
    for mode in [c"r", c"r+", c"w", c"a+"] {
        unsafe {
            let f = crate::file::fopen(Some(&ca), mode.to_bytes());
            let h = g::fopen(cb.as_ptr(), mode.as_ptr());
            let snap = move |ours: bool| {
                let (f, h) = (f as *mut c_void, h);
                let p = if ours { f } else { h };
                if ours {
                    (crate::stdio_ext::__freadable(f as _), crate::stdio_ext::__fwritable(f as _), crate::stdio_ext::__freading(f as _), crate::stdio_ext::__fwriting(f as _), crate::stdio_ext::__flbf(f as _), crate::stdio_ext::__fpending(f as _), crate::stdio_ext::__fbufsize(f as _))
                } else {
                    (g::__freadable(p), g::__fwritable(p), g::__freading(p), g::__fwriting(p), g::__flbf(p), g::__fpending(p), g::__fbufsize(p))
                }
            };
            let norm = |t: (c_int, c_int, c_int, c_int, c_int, usize, usize)| (t.0 != 0, t.1 != 0, t.2 != 0, t.3 != 0, t.4 != 0, t.5);
            assert_eq!(norm(snap(true)), norm(snap(false)), "{mode:?} fresh");
            let mut buf = [0u8; 16];
            if mode.to_bytes().contains(&b'r') || mode.to_bytes().contains(&b'+') {
                crate::file::read_bytes(&mut *(f), &mut buf[..4]);
                g::fread(buf.as_mut_ptr().cast(), 1, 4, h);
                assert_eq!(norm(snap(true)), norm(snap(false)), "{mode:?} after a read");
                assert_eq!(snap(true).6, snap(false).6, "{mode:?} buffer size after a read");
            }
            if mode.to_bytes().contains(&b'w') || mode.to_bytes().contains(&b'+') {
                crate::file::seek(&mut *f, 0, 0);
                g::fflush(h);
                crate::file::write_bytes(&mut *(f), &b"hello"[..5]);
                g::fwrite(b"hello".as_ptr().cast(), 1, 5, h);
                assert_eq!(norm(snap(true)), norm(snap(false)), "{mode:?} after a write");
            }
            crate::file::fclose(f);
            g::fclose(h);
        }
    }
    let _ = (std::fs::remove_file(&pa), std::fs::remove_file(&pb));
}

#[test]
fn temporary_names_have_the_right_shape() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let a = crate::file_extra::tmpnam(core::ptr::null_mut());
        let s = CStr::from_ptr(a).to_str().unwrap().to_string();
        assert!(s.starts_with("/tmp/file") && s.len() == 15, "{s}");
        assert!(!std::path::Path::new(&s).exists());
        let mut buf = [0 as c_char; 20];
        assert!(crate::file_extra::tmpnam_r(core::ptr::null_mut()).is_null());
        let r = crate::file_extra::tmpnam_r(buf.as_mut_ptr());
        assert_eq!(r, buf.as_mut_ptr());
        let t = crate::file_extra::tempnam(c"/tmp".as_ptr(), c"pre".as_ptr());
        let ts = CStr::from_ptr(t).to_str().unwrap().to_string();
        // tempnam prefers $TMPDIR (the build scripts set it) to the directory given
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let want = format!("{}/pre", base.trim_end_matches('/'));
        assert!(ts.starts_with(&want) && ts.len() == want.len() + 6, "{ts}");
        rusty_libc_malloc::free(t.cast());
        // a prefix longer than five characters is cut
        let t = crate::file_extra::tempnam(core::ptr::null(), c"longprefix".as_ptr());
        let ts = CStr::from_ptr(t).to_str().unwrap().to_string();
        let leaf = ts.rsplit('/').next().unwrap(); // "longp" + 6 random characters (which may by chance continue "longpr...")
        assert!(leaf.starts_with("longp") && leaf.len() == 11, "{ts}");
        rusty_libc_malloc::free(t.cast());
        // an unusable directory falls back to /tmp
        let t = crate::file_extra::tempnam(c"/nonexistent".as_ptr(), c"x".as_ptr());
        assert!(CStr::from_ptr(t).to_str().unwrap().starts_with("/tmp/x") || std::env::var("TMPDIR").is_ok());
        rusty_libc_malloc::free(t.cast());
    }
}

#[allow(dead_code)]
fn _unused(_: *mut c_void, _: c_char) {}
