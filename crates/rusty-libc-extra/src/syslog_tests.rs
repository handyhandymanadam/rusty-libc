//! Host tests for syslog.rs. glibc's syslog always writes to /dev/log, so these tests give our logger a
//! socket of its own (`Syslog::with_path`) and check what arrives against the documented format and
//! against the host's own local-time formatting; the comparison with glibc's bytes is the C diff test
//! (tests/c/syslog_diff.c), which runs both libraries against the same replaced /dev/log.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::syslog::*;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::sync::Mutex;
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());

/// Also holds the lock of the tests that switch the process locale (the time stamps are C-locale text).
fn guard() -> (std::sync::MutexGuard<'static, ()>, std::sync::MutexGuard<'static, ()>) {
    (LOCK.lock().unwrap_or_else(|e| e.into_inner()), crate::misc_tests::MON_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
}

fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("extra-syslog-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn dgram_server(name: &str) -> (UnixDatagram, std::path::PathBuf) {
    let p = dir().join(name);
    let _ = std::fs::remove_file(&p);
    let s = UnixDatagram::bind(&p).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    (s, p)
}

fn recv(s: &UnixDatagram) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 16384];
    s.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
}

unsafe extern "C" {
    static program_invocation_short_name: *const c_char;
}

fn local_stamp(t: i64) -> String {
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let mut buf = [0 as c_char; 32];
        let n = libc::strftime(buf.as_mut_ptr(), 32, c"%h %e %T ".as_ptr(), &tm);
        CStr::from_ptr(buf.as_ptr()).to_str().unwrap()[..n].to_owned()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Split a datagram into (priority field, time stamp ok, rest).
fn parse(msg: &[u8], before: i64, after: i64) -> (String, bool, String) {
    let text = String::from_utf8_lossy(msg).into_owned();
    let close = text.find('>').unwrap();
    let pri = text[..=close].to_owned();
    let rest = &text[close + 1..];
    let ts = (before - 2..=after + 2).any(|t| rest.starts_with(&local_stamp(t)));
    (pri, ts, if ts { rest[16..].to_owned() } else { rest.to_owned() })
}

#[test]
fn datagram_format() {
    let _g = guard();
    let (srv, path) = dgram_server("fmt");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("tid").unwrap();
    unsafe { s.openlog(ident.as_ptr(), LOG_PID, 19 << 3) };
    let (b, pid) = (now(), std::process::id());
    s.log_text(LOG_WARNING, b"hello");
    let m = recv(&srv).expect("a datagram");
    let (pri, ts, rest) = parse(&m, b, now());
    assert_eq!(pri, "<156>");
    assert!(ts, "time stamp of {:?}", String::from_utf8_lossy(&m));
    assert_eq!(rest, format!("tid[{pid}]: hello"));
    // a message that carries its own facility; no LOG_PID
    unsafe { s.openlog(std::ptr::null(), 0, 19 << 3) };
    s.log_text((2 << 3) | LOG_ERR, b"mail");
    let (pri, _, rest) = parse(&recv(&srv).unwrap(), b, now());
    assert_eq!((pri.as_str(), rest.as_str()), ("<19>", "tid: mail"));
    // closelog forgets the identifier (the program name is the tag again) and keeps the facility
    s.closelog();
    s.log_text(LOG_INFO, b"x");
    let (pri, _, rest) = parse(&recv(&srv).unwrap(), b, now());
    let prog = unsafe { CStr::from_ptr(program_invocation_short_name) }.to_str().unwrap().to_owned();
    assert_eq!((pri.as_str(), rest), ("<158>", format!("{prog}: x")));
    // facility 0 given to openlog is a real facility
    unsafe { s.openlog(ident.as_ptr(), 0, 0) };
    s.log_text(LOG_NOTICE, b"k");
    assert_eq!(parse(&recv(&srv).unwrap(), b, now()).0, "<5>");
    // a facility with stray bits in openlog is ignored (the old one stays)
    unsafe { s.openlog(ident.as_ptr(), 0, 5 << 3) };
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_FACMASK + 1) };
    s.log_text(LOG_NOTICE, b"k");
    assert_eq!(parse(&recv(&srv).unwrap(), b, now()).0, "<45>");
    s.closelog();
}

#[test]
fn mask_and_stray_bits() {
    let _g = guard();
    let (srv, path) = dgram_server("mask");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("m").unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    assert_eq!(s.setlogmask(0), 0xff);
    assert_eq!(s.setlogmask(log_upto(LOG_ERR)), 0xff);
    s.log_text(LOG_INFO, b"masked");
    assert!(recv(&srv).is_none());
    s.log_text(LOG_ERR, b"shown");
    assert!(recv(&srv).is_some());
    assert_eq!(s.setlogmask(log_mask(LOG_DEBUG)), 0xf);
    s.log_text(LOG_INFO, b"no");
    assert!(recv(&srv).is_none());
    s.log_text(LOG_DEBUG, b"yes");
    assert!(recv(&srv).is_some());
    assert_eq!(s.setlogmask(0xff), 0x80);
    assert_eq!(s.setlogmask(0), 0xff);
    // stray bits: a complaint at priority 35 (LOG_ERR with the auth facility), then the message
    let b = now();
    s.log_text(0x400 | LOG_ERR, b"text");
    let (p1, _, r1) = parse(&recv(&srv).unwrap(), b, now());
    let (p2, _, r2) = parse(&recv(&srv).unwrap(), b, now());
    assert_eq!((p1.as_str(), r1.as_str()), ("<35>", "m: syslog: unknown facility/priority: 403"));
    assert_eq!((p2.as_str(), r2.as_str()), ("<11>", "m: text"));
    s.closelog();
}

#[test]
fn long_and_odd_messages() {
    let _g = guard();
    let (srv, path) = dgram_server("long");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("l").unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    for len in [0usize, 1, 500, 1000, 1010, 1020, 1030, 3000, 6000] {
        let text = "x".repeat(len);
        s.log_text(LOG_INFO, text.as_bytes());
        let m = recv(&srv).unwrap();
        let (_, _, rest) = parse(&m, now() - 5, now());
        assert_eq!(rest, format!("l: {text}"), "length {len}");
    }
    s.log_text(LOG_INFO, b"a\nb\n");
    assert_eq!(parse(&recv(&srv).unwrap(), now() - 5, now()).2, "l: a\nb\n");
}

#[test]
fn stream_fallback_and_reconnect() {
    let _g = guard();
    let p = dir().join("stream");
    let _ = std::fs::remove_file(&p);
    let l = UnixListener::bind(&p).unwrap();
    let mut s = Syslog::with_path(p.to_str().unwrap().as_bytes());
    let ident = CString::new("st").unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    s.log_text(LOG_INFO, b"one");
    s.log_text(LOG_INFO, b"two");
    let (mut c, _) = l.accept().unwrap();
    c.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    use std::io::Read;
    let mut buf = [0u8; 256];
    let n = c.read(&mut buf).unwrap();
    let records: Vec<&[u8]> = buf[..n].split(|&b| b == 0).collect();
    // two records, each ended by a NUL: the split leaves an empty tail
    assert_eq!(records.len(), 3);
    assert!(records[2].is_empty());
    assert!(String::from_utf8_lossy(records[0]).ends_with("st: one"));
    assert!(String::from_utf8_lossy(records[1]).ends_with("st: two"));
    // the server drops the connection: the next message opens a new one
    drop(c);
    s.log_text(LOG_INFO, b"three");
    let (mut c2, _) = l.accept().unwrap();
    c2.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let n = c2.read(&mut buf).unwrap();
    assert!(buf[..n].ends_with(b"st: three\0"));
    // closelog goes back to datagrams
    s.closelog();
    drop(l);
    drop(c2);
    let _ = std::fs::remove_file(&p);
    let srv = UnixDatagram::bind(&p).unwrap();
    srv.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    s.log_text(LOG_INFO, b"dgram");
    assert!(recv(&srv).unwrap().ends_with(b"st: dgram"));
}

#[test]
fn server_goes_away_and_returns() {
    let _g = guard();
    let (srv, path) = dgram_server("gone");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("g").unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    s.log_text(LOG_INFO, b"one");
    assert!(recv(&srv).is_some());
    drop(srv);
    let _ = std::fs::remove_file(&path);
    // the send fails, the reopen fails: the message is dropped, nothing panics
    s.log_text(LOG_INFO, b"lost");
    let srv = UnixDatagram::bind(&path).unwrap();
    srv.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    s.log_text(LOG_INFO, b"two");
    assert!(recv(&srv).unwrap().ends_with(b"g: two"));
}

unsafe extern "C" fn logf(s: *mut Syslog, pri: c_int, fmt: *const c_char, mut args: ...) {
    unsafe { (*s).vsyslog(pri, fmt, &mut args, None) }
}

#[test]
fn formatted_messages() {
    let _g = guard();
    let (srv, path) = dgram_server("printf");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("f").unwrap();
    unsafe { s.openlog(ident.as_ptr(), 0, LOG_USER) };
    unsafe {
        logf(&mut s, LOG_INFO, c"%d %s %5.2f %05d %-4s|".as_ptr(), 5 as c_int, c"w".as_ptr(), 1.23456f64, 42 as c_int, c"ab".as_ptr());
        assert_eq!(parse(&recv(&srv).unwrap(), now() - 5, now()).2, "f: 5 w  1.23 00042 ab  |");
        rusty_libc_core::errno::set(2);
        logf(&mut s, LOG_INFO, c"error: %m".as_ptr());
        assert_eq!(parse(&recv(&srv).unwrap(), now() - 5, now()).2, "f: error: No such file or directory");
        rusty_libc_core::errno::set(0);
        // stray priority bits through the formatting path
        logf(&mut s, 0x400 | LOG_ERR, c"v %d".as_ptr(), 9 as c_int);
        assert_eq!(parse(&recv(&srv).unwrap(), now() - 5, now()).2, "f: syslog: unknown facility/priority: 403");
        assert_eq!(parse(&recv(&srv).unwrap(), now() - 5, now()).2, "f: v 9");
        // a masked message is not formatted at all
        s.setlogmask(log_upto(LOG_ERR));
        logf(&mut s, LOG_DEBUG, c"%s".as_ptr(), std::ptr::null::<c_char>());
        assert!(recv(&srv).is_none());
    }
}

#[test]
fn perror_and_pid() {
    let _g = guard();
    let (srv, path) = dgram_server("perror");
    let mut s = Syslog::with_path(path.to_str().unwrap().as_bytes());
    let ident = CString::new("pe").unwrap();
    unsafe { s.openlog(ident.as_ptr(), LOG_PERROR | LOG_PID, LOG_USER) };
    unsafe {
        let mut fds = [0 as c_int; 2];
        libc::pipe(fds.as_mut_ptr());
        let saved = libc::dup(2);
        libc::dup2(fds[1], 2);
        s.log_text(LOG_INFO, b"to stderr");
        s.log_text(LOG_INFO, b"with newline\n");
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(fds[1]);
        let mut buf = [0u8; 200];
        let n = libc::read(fds[0], buf.as_mut_ptr().cast(), 200);
        libc::close(fds[0]);
        let pid = std::process::id();
        assert_eq!(&buf[..n as usize], format!("pe[{pid}]: to stderr\npe[{pid}]: with newline\n").as_bytes());
    }
    assert!(recv(&srv).is_some() && recv(&srv).is_some());
}

#[test]
fn macros() {
    assert_eq!(log_mask(5), 0x20);
    assert_eq!(log_upto(5), 0x3f);
    assert_eq!(log_upto(0), 1);
    assert_eq!(log_upto(7), 0xff);
}
