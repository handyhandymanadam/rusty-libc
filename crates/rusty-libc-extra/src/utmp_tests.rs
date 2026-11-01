//! Host tests for utmp.rs: random operation sequences (pututline, setutent, getutent, getutid,
//! getutline and their reentrant forms) run through our functions and through the host glibc's on two
//! copies of a temporary file; every result, errno and the final file bytes must be equal.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::utmp::{self, Utmp, Utmpx};
use std::ffi::{CString, c_char, c_int};
use std::sync::Mutex;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn utmpname(file: *const c_char) -> c_int;
        pub fn setutent();
        pub fn endutent();
        pub fn getutent() -> *mut Utmp;
        pub fn getutid(id: *const Utmp) -> *mut Utmp;
        pub fn getutline(line: *const Utmp) -> *mut Utmp;
        pub fn pututline(u: *const Utmp) -> *mut Utmp;
        pub fn getutent_r(buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
        pub fn getutid_r(id: *const Utmp, buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
        pub fn getutline_r(id: *const Utmp, buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
        pub fn updwtmp(file: *const c_char, u: *const Utmp);
        pub fn getutmp(x: *const Utmpx, u: *mut Utmp);
        pub fn getutmpx(u: *const Utmp, x: *mut Utmpx);
    }
}

// both libraries keep process-wide state: one test at a time
static LOCK: Mutex<()> = Mutex::new(());

fn guard() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("extra-utmp-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn record(rng: &mut Rng) -> Utmp {
    let mut u = Utmp::ZERO;
    u.ut_type = [0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 8, 9, 10, -1][rng.below(14) as usize];
    u.ut_pid = rng.below(1000) as i32;
    let lines = ["tty1", "tty2", "pts/0", "pts/1", "", "console"];
    let ids = ["", "t1", "t2", "p0", "p1", "abcd"];
    let users = ["", "root", "alice", "bob"];
    let (l, i, n) = (lines[rng.below(6) as usize], ids[rng.below(6) as usize], users[rng.below(4) as usize]);
    u.ut_line[..l.len()].copy_from_slice(l.as_bytes());
    u.ut_id[..i.len()].copy_from_slice(i.as_bytes());
    u.ut_user[..n.len()].copy_from_slice(n.as_bytes());
    u.tv_sec = rng.below(100000) as u32;
    u
}

fn bytes(u: &Utmp) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((u as *const Utmp).cast::<u8>(), 384).to_vec() }
}

#[derive(Debug, PartialEq)]
enum Res {
    Rec(Vec<u8>),
    Null(i32),
    Code(i32, Option<Vec<u8>>, i32),
}

fn host_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_host_errno(v: i32) {
    unsafe { *libc::__errno_location() = v };
}

fn ptr_res(p: *mut Utmp, errno: i32) -> Res {
    if p.is_null() { Res::Null(errno) } else { Res::Rec(bytes(unsafe { &*p })) }
}

fn step_host(op: u64, u: &Utmp) -> Res {
    unsafe {
        set_host_errno(0);
        let mut buf = Utmp::ZERO;
        let mut res: *mut Utmp = std::ptr::null_mut();
        match op {
            0 => {
                host::setutent();
                Res::Code(0, None, host_errno())
            }
            1 => {
                let p = host::getutent();
                ptr_res(p, host_errno())
            }
            2 => {
                let p = host::getutid(u);
                ptr_res(p, host_errno())
            }
            3 => {
                let p = host::getutline(u);
                ptr_res(p, host_errno())
            }
            4 => {
                let p = host::pututline(u);
                ptr_res(p, host_errno())
            }
            5 => {
                let rc = host::getutent_r(&mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, host_errno())
            }
            6 => {
                let rc = host::getutid_r(u, &mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, host_errno())
            }
            _ => {
                let rc = host::getutline_r(u, &mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, host_errno())
            }
        }
    }
}

fn step_ours(op: u64, u: &Utmp) -> Res {
    unsafe {
        rusty_libc_core::errno::set(0);
        let mut buf = Utmp::ZERO;
        let mut res: *mut Utmp = std::ptr::null_mut();
        let e = rusty_libc_core::errno::get;
        match op {
            0 => {
                utmp::setutent();
                Res::Code(0, None, e())
            }
            1 => {
                let p = utmp::getutent();
                ptr_res(p, e())
            }
            2 => {
                let p = utmp::getutid(u);
                ptr_res(p, e())
            }
            3 => {
                let p = utmp::getutline(u);
                ptr_res(p, e())
            }
            4 => {
                let p = utmp::pututline(u);
                ptr_res(p, e())
            }
            5 => {
                let rc = utmp::getutent_r(&mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, e())
            }
            6 => {
                let rc = utmp::getutid_r(u, &mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, e())
            }
            _ => {
                let rc = utmp::getutline_r(u, &mut buf, &mut res);
                Res::Code(rc, if res.is_null() { None } else { Some(bytes(&buf)) }, e())
            }
        }
    }
}

fn run_sequences(seed: u64, ops: usize, initial: &[u8]) {
    let (hp, op) = (tmp(&format!("host-{seed}")), tmp(&format!("ours-{seed}")));
    std::fs::write(&hp, initial).unwrap();
    std::fs::write(&op, initial).unwrap();
    let (hc, oc) = (CString::new(hp.to_str().unwrap()).unwrap(), CString::new(op.to_str().unwrap()).unwrap());
    unsafe {
        assert_eq!(host::utmpname(hc.as_ptr()), 0);
        assert_eq!(utmp::utmpname(oc.as_ptr()), 0);
    }
    let mut rng = Rng(seed * 7919 + 1);
    let mut pool: Vec<Utmp> = (0..12).map(|_| record(&mut rng)).collect();
    for i in 0..ops {
        // mostly operations with entries from the pool, so that searches and overwrites hit
        let op = rng.below(8);
        let u = if rng.below(5) == 0 { record(&mut rng) } else { pool[rng.below(pool.len() as u64) as usize] };
        let a = step_host(op, &u);
        let b = step_ours(op, &u);
        assert_eq!(a, b, "seed {seed} step {i} op {op} entry type {} line {:?} id {:?}", u.ut_type, &u.ut_line[..6], u.ut_id);
        if op == 4 && rng.below(3) == 0 {
            let k = rng.below(pool.len() as u64) as usize;
            pool[k] = record(&mut rng);
        }
    }
    unsafe {
        host::endutent();
        utmp::endutent();
    }
    assert_eq!(std::fs::read(&hp).unwrap(), std::fs::read(&op).unwrap(), "seed {seed}: final file");
}

#[test]
fn layout() {
    assert_eq!(size_of::<Utmp>(), size_of::<libc::utmpx>());
    assert_eq!(size_of::<Utmpx>(), 384);
    assert_eq!(core::mem::offset_of!(Utmp, ut_pid), core::mem::offset_of!(libc::utmpx, ut_pid));
    assert_eq!(core::mem::offset_of!(Utmp, ut_line), core::mem::offset_of!(libc::utmpx, ut_line));
    assert_eq!(core::mem::offset_of!(Utmp, ut_id), core::mem::offset_of!(libc::utmpx, ut_id));
    assert_eq!(core::mem::offset_of!(Utmp, ut_user), core::mem::offset_of!(libc::utmpx, ut_user));
    assert_eq!(core::mem::offset_of!(Utmp, ut_host), core::mem::offset_of!(libc::utmpx, ut_host));
    assert_eq!(core::mem::offset_of!(Utmp, ut_session), core::mem::offset_of!(libc::utmpx, ut_session));
    assert_eq!(core::mem::offset_of!(Utmp, tv_sec), core::mem::offset_of!(libc::utmpx, ut_tv));
    assert_eq!(core::mem::offset_of!(Utmp, ut_addr_v6), core::mem::offset_of!(libc::utmpx, ut_addr_v6));
}

#[test]
fn random_sequences_on_an_empty_file() {
    let _g = guard();
    for seed in 1..=12 {
        run_sequences(seed, 400, b"");
    }
}

#[test]
fn random_sequences_on_a_filled_file() {
    let _g = guard();
    let mut rng = Rng(99);
    let mut data = Vec::new();
    for _ in 0..10 {
        data.extend_from_slice(&bytes(&record(&mut rng)));
    }
    for seed in 20..30 {
        run_sequences(seed, 400, &data);
    }
    // with a partial record at the end
    data.extend_from_slice(&[7u8; 100]);
    for seed in 40..45 {
        run_sequences(seed, 300, &data);
    }
}

#[test]
fn missing_file_and_bad_types() {
    let _g = guard();
    unsafe {
        let name = c"/nonexistent-dir/utmp";
        assert_eq!(host::utmpname(name.as_ptr()), utmp::utmpname(name.as_ptr()));
    }
    let mut rng = Rng(5);
    for op in 0..8 {
        let u = record(&mut rng);
        assert_eq!(step_host(op, &u), step_ours(op, &u), "op {op} on a missing file");
    }
    unsafe {
        host::endutent();
        utmp::endutent();
    }
}

#[test]
fn updwtmp_matches() {
    let _g = guard();
    let mut rng = Rng(7);
    let (hp, op) = (tmp("w-host"), tmp("w-ours"));
    let mut init = Vec::new();
    for _ in 0..3 {
        init.extend_from_slice(&bytes(&record(&mut rng)));
    }
    for partial in [0usize, 1, 100, 383] {
        let mut data = init.clone();
        data.extend(std::iter::repeat_n(9u8, partial));
        std::fs::write(&hp, &data).unwrap();
        std::fs::write(&op, &data).unwrap();
        let (hc, oc) = (CString::new(hp.to_str().unwrap()).unwrap(), CString::new(op.to_str().unwrap()).unwrap());
        let u = record(&mut rng);
        unsafe {
            host::updwtmp(hc.as_ptr(), &u);
            utmp::updwtmp(oc.as_ptr(), &u);
        }
        assert_eq!(std::fs::read(&hp).unwrap(), std::fs::read(&op).unwrap(), "partial {partial}");
    }
    // a missing file is not created
    unsafe {
        host::updwtmp(c"/nonexistent-dir/w".as_ptr(), &Utmp::ZERO);
        utmp::updwtmp(c"/nonexistent-dir/w".as_ptr(), &Utmp::ZERO);
    }
}

#[test]
fn getutmp_copies_everything() {
    let mut rng = Rng(3);
    let u = record(&mut rng);
    let mut x1 = Utmpx(Utmp::ZERO);
    let mut x2 = Utmpx(Utmp::ZERO);
    let mut b1 = Utmp::ZERO;
    let mut b2 = Utmp::ZERO;
    unsafe {
        host::getutmpx(&u, &mut x1);
        utmp::getutmpx(&u, &mut x2);
        host::getutmp(&x1, &mut b1);
        utmp::getutmp(&x2, &mut b2);
    }
    assert_eq!(bytes(&x1.0), bytes(&x2.0));
    assert_eq!(bytes(&b1), bytes(&b2));
    assert_eq!(bytes(&b1), bytes(&u));
}

#[test]
fn rust_api_and_wtmp_helpers() {
    let _g = guard();
    let path = tmp("api");
    std::fs::write(&path, b"").unwrap();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let mut db = utmp::UtmpDb::new();
    assert!(db.set_name(&cpath));
    let mut u = Utmp::ZERO;
    u.ut_type = utmp::USER_PROCESS;
    u.ut_line[..4].copy_from_slice(b"tty1");
    u.ut_user[..5].copy_from_slice(b"alice");
    assert!(db.pututline(&u));
    assert!(db.setutent());
    let got = db.getutent().unwrap().unwrap();
    assert_eq!(&got.ut_user[..5], b"alice");
    assert!(db.getutent().unwrap().is_none());
    assert!(db.getutid(&Utmp { ut_type: 99, ..Utmp::ZERO }).is_err());
    // logout marks the line dead and clears who and where
    assert!(utmp::logout_in(&cpath, c"tty1"));
    db.setutent();
    let got = db.getutent().unwrap().unwrap();
    assert_eq!(got.ut_type, utmp::DEAD_PROCESS);
    assert_eq!(got.ut_user[0], 0);
    assert!(!utmp::logout_in(&cpath, c"tty1"));
    // logwtmp appends login and logout records
    let w = tmp("api-wtmp");
    std::fs::write(&w, b"").unwrap();
    let cw = CString::new(w.to_str().unwrap()).unwrap();
    utmp::logwtmp_to(&cw, c"tty2", c"bob", c"host");
    utmp::logwtmp_to(&cw, c"tty2", c"", c"");
    let data = std::fs::read(&w).unwrap();
    assert_eq!(data.len(), 768);
    assert_eq!(i16::from_ne_bytes([data[0], data[1]]), utmp::USER_PROCESS);
    assert_eq!(i16::from_ne_bytes([data[384], data[385]]), utmp::DEAD_PROCESS);
}

/// A lock held by another process makes a read fail with EINTR after the timeout (glibc: 10 s; ours is
/// shortened to 1 s for the test). The alarm that ends the wait is a process signal and any thread may
/// take it, so each library is called from a forked single-threaded child.
#[test]
fn lock_timeout() {
    let _g = guard();
    let path = tmp("locked");
    let mut rng = Rng(1);
    std::fs::write(&path, bytes(&record(&mut rng))).unwrap();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    // a process that holds a write lock on the file for 13 seconds
    let holder = unsafe { libc::fork() };
    if holder == 0 {
        unsafe {
            let fd = libc::open(cpath.as_ptr(), libc::O_RDWR);
            let fl = libc::flock { l_type: libc::F_WRLCK as i16, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
            libc::fcntl(fd, libc::F_SETLK, &fl);
            libc::sleep(13);
            libc::_exit(0);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    unsafe {
        utmp::LOCK_TIMEOUT.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(utmp::utmpname(cpath.as_ptr()), 0);
        assert_eq!(host::utmpname(cpath.as_ptr()), 0);
        let mut times = [0u128; 2];
        for (which, t) in times.iter_mut().enumerate() {
            let start = std::time::Instant::now();
            let child = libc::fork();
            if child == 0 {
                let mut buf = Utmp::ZERO;
                let mut res: *mut Utmp = std::ptr::null_mut();
                let (rc, e) = if which == 0 {
                    rusty_libc_core::errno::set(0);
                    let rc = utmp::getutent_r(&mut buf, &mut res);
                    (rc, rusty_libc_core::errno::get())
                } else {
                    set_host_errno(0);
                    let rc = host::getutent_r(&mut buf, &mut res);
                    (rc, host_errno())
                };
                libc::_exit(if rc == -1 && res.is_null() && e == libc::EINTR { 0 } else { 1 });
            }
            let mut st = 0;
            libc::waitpid(child, &mut st, 0);
            *t = start.elapsed().as_millis();
            assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{} did not fail with EINTR", ["ours", "glibc"][which]);
        }
        assert!((900..4000).contains(&times[0]), "ours took {} ms", times[0]);
        assert!(times[1] >= 9000, "glibc took {} ms", times[1]);
        utmp::LOCK_TIMEOUT.store(10, std::sync::atomic::Ordering::SeqCst);
        libc::kill(holder, libc::SIGKILL);
        libc::waitpid(holder, std::ptr::null_mut(), 0);
    }
}
