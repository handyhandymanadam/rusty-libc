use super::{errno, host_errno, lock};
use crate::mq::*;
use crate::notify::*;
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use rusty_libc_core::Errno;
use std::ffi::CString;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A unique queue name that is removed (with every other name made from the same guard) on drop.
struct Name {
    s: CString,
}
impl Name {
    fn new() -> Name {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        Name { s: CString::new(format!("/rlibc-mq-{}-{}", std::process::id(), n)).unwrap() }
    }
    fn p(&self) -> *const c_char {
        self.s.as_ptr()
    }
}
impl Drop for Name {
    fn drop(&mut self) {
        unsafe { libc::mq_unlink(self.s.as_ptr()) };
    }
}

fn attr(max: i64, size: i64) -> MqAttr {
    MqAttr { flags: 0, maxmsg: max, msgsize: size, curmsgs: 0, reserved: [0; 4] }
}

fn mk(n: &Name, oflag: c_int, a: Option<&MqAttr>) -> mqd_t {
    unsafe { mq_open(n.p(), oflag | O_CREAT | O_EXCL, 0o600 as c_uint, a.map_or(core::ptr::null(), |a| a as *const MqAttr)) }
}

fn now_plus(ms: i64) -> Timespec {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let ns = ts.tv_nsec + (ms % 1000) * 1_000_000;
    Timespec { tv_sec: ts.tv_sec + ms / 1000 + ns / 1_000_000_000, tv_nsec: ns % 1_000_000_000 }
}

fn send(q: mqd_t, m: &[u8], prio: u32) -> c_int {
    unsafe { mq_send(q, m.as_ptr() as *const c_char, m.len(), prio) }
}

fn recv(q: mqd_t, buf: &mut [u8]) -> (isize, u32) {
    let mut p = 0;
    let n = unsafe { mq_receive(q, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut p) };
    (n, p)
}

#[test]
fn layout_and_constants_equal_glibc() {
    assert_eq!(core::mem::size_of::<MqAttr>(), core::mem::size_of::<libc::mq_attr>());
    assert_eq!(core::mem::size_of::<SigEvent>(), core::mem::size_of::<libc::sigevent>());
    assert_eq!((SIGEV_SIGNAL, SIGEV_NONE, SIGEV_THREAD, SIGEV_THREAD_ID), (libc::SIGEV_SIGNAL, libc::SIGEV_NONE, libc::SIGEV_THREAD, libc::SIGEV_THREAD_ID));
    assert_eq!((O_CREAT, O_EXCL, O_NONBLOCK, O_CLOEXEC), (libc::O_CREAT, libc::O_EXCL, libc::O_NONBLOCK, libc::O_CLOEXEC));
}

#[test]
fn open_errors_equal_host() {
    let _l = lock();
    let a = attr(4, 64);
    let long = CString::new(format!("/{}", "x".repeat(300))).unwrap();
    let bad_a = attr(0, 64);
    let bad_b = attr(4, 0);
    let big_a = attr(1_000_000, 64);
    let big_b = attr(4, 1 << 30);
    let cases: Vec<(&str, CString, c_int, Option<MqAttr>)> = vec![
        ("no slash", CString::new("rlibc-noslash").unwrap(), libc::O_RDONLY, None),
        ("empty", CString::new("").unwrap_or_default(), libc::O_RDONLY, None),
        ("slash only", CString::new("/").unwrap(), libc::O_RDONLY, None),
        ("inner slash", CString::new("/a/b").unwrap(), libc::O_RDONLY, None),
        ("nonexistent", CString::new("/rlibc-does-not-exist").unwrap(), libc::O_RDONLY, None),
        ("too long", long, libc::O_RDONLY, None),
        ("dot", CString::new("/.").unwrap(), libc::O_RDONLY, None),
        ("dotdot", CString::new("/..").unwrap(), libc::O_RDONLY, None),
        ("create attr maxmsg 0", CString::new("/rlibc-bad1").unwrap(), libc::O_CREAT | libc::O_RDWR, Some(bad_a)),
        ("create attr msgsize 0", CString::new("/rlibc-bad2").unwrap(), libc::O_CREAT | libc::O_RDWR, Some(bad_b)),
        ("create attr maxmsg huge", CString::new("/rlibc-bad3").unwrap(), libc::O_CREAT | libc::O_RDWR, Some(big_a)),
        ("create attr msgsize huge", CString::new("/rlibc-bad4").unwrap(), libc::O_CREAT | libc::O_RDWR, Some(big_b)),
        ("create ok", CString::new("/rlibc-ok").unwrap(), libc::O_CREAT | libc::O_RDWR, Some(a)),
    ];
    for (what, name, oflag, at) in cases {
        let ap = at.as_ref().map_or(core::ptr::null(), |a| a as *const MqAttr);
        let r1 = unsafe { mq_open(name.as_ptr(), oflag, 0o600 as c_uint, ap) };
        let e1 = errno();
        let r2 = unsafe { libc::mq_open(name.as_ptr(), oflag, 0o600 as libc::mode_t, ap as *const libc::mq_attr) };
        let e2 = host_errno();
        assert_eq!(r1 < 0, r2 < 0, "{}: ours {} host {}", what, r1, r2);
        if r1 < 0 {
            assert_eq!(e1, e2, "{}: errno", what);
        }
        if r1 >= 0 {
            unsafe {
                mq_close(r1);
                libc::mq_close(r2);
            }
            // both succeeded on the same name: unlink once, then ENOENT for the second
            assert_eq!(unsafe { mq_unlink(name.as_ptr()) }, 0);
            assert_eq!(unsafe { libc::mq_unlink(name.as_ptr()) }, -1);
        }
    }
    // O_EXCL on an existing queue, unlink errors
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&a));
    assert!(q >= 0, "errno {}", errno());
    assert_eq!(mk(&n, O_RDWR, Some(&a)), -1);
    assert_eq!(errno(), 17);
    assert_eq!(unsafe { libc::mq_open(n.p(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600, &a as *const MqAttr as *const libc::mq_attr) }, -1);
    assert_eq!(host_errno(), 17);
    // unlink: bad names
    let ns = CString::new("noslash").unwrap();
    assert_eq!(unsafe { mq_unlink(ns.as_ptr()) }, -1);
    let e1 = errno();
    assert_eq!(unsafe { libc::mq_unlink(ns.as_ptr()) }, -1);
    assert_eq!(e1, host_errno());
    let gone = CString::new("/rlibc-gone").unwrap();
    assert_eq!(unsafe { mq_unlink(gone.as_ptr()) }, -1);
    assert_eq!(errno(), 2);
    assert_eq!(unsafe { mq_unlink(n.p()) }, 0);
    // the open descriptor still works after the name is gone
    assert_eq!(send(q, b"x", 1), 0);
    assert_eq!(mq_close(q), 0);
    assert_eq!(mq_close(q), -1);
    assert_eq!(errno(), 9);
}

#[test]
fn priorities_and_order() {
    let _l = lock();
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&attr(8, 32)));
    assert!(q >= 0);
    for (m, p) in [(&b"low1"[..], 1u32), (b"high1", 5), (b"low2", 1), (b"top", 32767), (b"high2", 5), (b"zero", 0)] {
        assert_eq!(send(q, m, p), 0);
    }
    let mut a = MqAttr::default();
    assert_eq!(unsafe { mq_getattr(q, &mut a) }, 0);
    assert_eq!((a.curmsgs, a.maxmsg, a.msgsize, a.flags), (6, 8, 32, 0));
    let mut buf = [0u8; 32];
    let mut got = vec![];
    loop {
        let (r, p) = recv_nb(q, &mut buf);
        if r < 0 {
            assert_eq!(errno(), 11, "EAGAIN on empty");
            break;
        }
        got.push((String::from_utf8_lossy(&buf[..r as usize]).to_string(), p));
    }
    assert_eq!(
        got,
        vec![("top".into(), 32767), ("high1".into(), 5), ("high2".into(), 5), ("low1".into(), 1), ("low2".into(), 1), ("zero".into(), 0)]
    );
    // priority limit, size limits, zero length
    assert_eq!(send(q, b"x", 32768), -1);
    assert_eq!(errno(), 22);
    assert_eq!(send(q, &[0u8; 33], 0), -1);
    assert_eq!(errno(), 90);
    assert_eq!(send(q, b"", 3), 0);
    assert_eq!(recv(q, &mut buf), (0, 3));
    // receive buffer smaller than mq_msgsize: EMSGSIZE and the message stays
    assert_eq!(send(q, b"abc", 0), 0);
    let mut small = [0u8; 8];
    assert_eq!(recv(q, &mut small).0, -1);
    assert_eq!(errno(), 90);
    assert_eq!(recv(q, &mut buf), (3, 0));
    // null priority pointer
    assert_eq!(send(q, b"np", 7), 0);
    let r = unsafe { mq_receive(q, buf.as_mut_ptr() as *mut c_char, 32, core::ptr::null_mut()) };
    assert_eq!(r, 2);
    mq_close(q);
}

fn recv_nb(q: mqd_t, buf: &mut [u8]) -> (isize, u32) {
    // O_NONBLOCK is set on the descriptor by the caller of `set_nb`; reuse mq_timedreceive with a past time
    let ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut p = 0;
    let mut a = MqAttr::default();
    unsafe { mq_getattr(q, &mut a) };
    let n = if a.curmsgs == 0 {
        rusty_libc_core::errno::set(11);
        -1
    } else {
        unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut p, &ts) }
    };
    (n, p)
}

#[test]
fn nonblocking_full_and_empty() {
    let _l = lock();
    let n = Name::new();
    let a = attr(2, 16);
    let q = unsafe { mq_open(n.p(), O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0o600 as c_uint, &a as *const MqAttr) };
    assert!(q >= 0);
    let mut buf = [0u8; 16];
    assert_eq!(recv(q, &mut buf).0, -1);
    assert_eq!(errno(), 11);
    assert_eq!(send(q, b"1", 0), 0);
    assert_eq!(send(q, b"2", 0), 0);
    assert_eq!(send(q, b"3", 0), -1);
    assert_eq!(errno(), 11);
    let mut g = MqAttr::default();
    assert_eq!(unsafe { mq_getattr(q, &mut g) }, 0);
    assert_eq!((g.flags, g.curmsgs), (O_NONBLOCK as i64, 2));
    // mq_setattr: clear O_NONBLOCK; old attributes returned; other fields ignored
    let new = MqAttr { flags: 0, maxmsg: 99, msgsize: 99, curmsgs: 99, reserved: [0; 4] };
    let mut old = MqAttr::default();
    assert_eq!(unsafe { mq_setattr(q, &new, &mut old) }, 0);
    assert_eq!((old.flags, old.maxmsg, old.msgsize, old.curmsgs), (O_NONBLOCK as i64, 2, 16, 2));
    assert_eq!(unsafe { mq_getattr(q, &mut g) }, 0);
    assert_eq!((g.flags, g.maxmsg, g.msgsize), (0, 2, 16));
    // null mqstat: acts as getattr (as in glibc)
    let mut o2 = MqAttr::default();
    assert_eq!(unsafe { mq_setattr(q, core::ptr::null(), &mut o2) }, 0);
    assert_eq!(o2.curmsgs, 2);
    let mut h = unsafe { core::mem::zeroed::<libc::mq_attr>() };
    assert_eq!(unsafe { libc::mq_setattr(q, core::ptr::null(), &mut h) }, 0);
    assert_eq!(h.mq_curmsgs, 2);
    // bad descriptor and wrong access mode
    assert_eq!(send(-1, b"x", 0), -1);
    assert_eq!(errno(), 9);
    assert_eq!(unsafe { mq_getattr(-1, &mut g) }, -1);
    assert_eq!(errno(), 9);
    let ro = unsafe { mq_open(n.p(), O_RDONLY) };
    assert!(ro >= 0);
    assert_eq!(send(ro, b"x", 0), -1);
    assert_eq!(errno(), 9);
    let wo = unsafe { mq_open(n.p(), O_WRONLY) };
    assert_eq!(recv(wo, &mut buf).0, -1);
    assert_eq!(errno(), 9);
    for d in [q, ro, wo] {
        mq_close(d);
    }
}

#[test]
fn timed_send_and_receive() {
    let _l = lock();
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&attr(1, 16)));
    assert!(q >= 0);
    let mut buf = [0u8; 16];
    // receive from empty queue: ETIMEDOUT after about 100 ms
    let t0 = std::time::Instant::now();
    let ts = now_plus(100);
    let r = unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, 16, core::ptr::null_mut(), &ts) };
    assert_eq!((r, errno()), (-1, 110));
    let dt = t0.elapsed().as_millis();
    assert!((90..1500).contains(&dt), "{} ms", dt);
    // a time in the past: immediate ETIMEDOUT (also with an empty queue)
    let past = Timespec { tv_sec: 1, tv_nsec: 0 };
    let r = unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, 16, core::ptr::null_mut(), &past) };
    assert_eq!((r, errno()), (-1, 110));
    // invalid nanoseconds
    let bad = Timespec { tv_sec: 5, tv_nsec: 1_000_000_000 };
    let r = unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, 16, core::ptr::null_mut(), &bad) };
    assert_eq!((r, errno()), (-1, 22));
    let neg = Timespec { tv_sec: 5, tv_nsec: -1 };
    // the kernel checks the time first, even when the queue has room
    assert_eq!(unsafe { mq_timedsend(q, b"x".as_ptr() as *const c_char, 1, 0, &neg) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { libc::mq_timedsend(q, b"x".as_ptr() as *const c_char, 1, 0, &neg as *const Timespec as *const libc::timespec) }, -1);
    assert_eq!(host_errno(), 22);
    assert_eq!(send(q, b"x", 0), 0);
    // full queue: timedsend times out
    let ts = now_plus(50);
    assert_eq!(unsafe { mq_timedsend(q, b"y".as_ptr() as *const c_char, 1, 0, &ts) }, -1);
    assert_eq!(errno(), 110);
    let r = unsafe { mq_timedsend(q, b"y".as_ptr() as *const c_char, 1, 0, &bad) };
    assert_eq!((r, errno()), (-1, 22));
    // timed receive with a message ready returns at once
    let ts = now_plus(5000);
    let mut p = 99;
    let r = unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, 16, &mut p, &ts) };
    assert_eq!((r, p, buf[0]), (1, 0, b'x'));
    mq_close(q);
}

#[test]
fn blocking_send_and_receive_wake_each_other() {
    let _l = lock();
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&attr(1, 16)));
    assert!(q >= 0);
    // a blocked receiver is woken by a send from another thread
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 16];
        let (r, p) = recv(q, &mut buf);
        (r, p, buf[0])
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(send(q, b"Z", 9), 0);
    assert_eq!(t.join().unwrap(), (1, 9, b'Z'));
    // a blocked sender (queue full) is woken by a receive
    assert_eq!(send(q, b"a", 0), 0);
    let t = std::thread::spawn(move || send(q, b"b", 0));
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut buf = [0u8; 16];
    assert_eq!(recv(q, &mut buf), (1, 0));
    assert_eq!(t.join().unwrap(), 0);
    assert_eq!(recv(q, &mut buf), (1, 0));
    assert_eq!(buf[0], b'b');
    mq_close(q);
}

static SIG_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIG_VALUE: AtomicUsize = AtomicUsize::new(0);
static SIG_CODE: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(_sig: c_int, info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    unsafe {
        SIG_VALUE.store((*info).si_value().sival_ptr as usize, Ordering::SeqCst);
        SIG_CODE.store((*info).si_code, Ordering::SeqCst);
    }
    SIG_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn notify_signal_none_busy_and_removal() {
    let _l = lock();
    let sig = libc::SIGRTMIN() + 2;
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(sig, &sa, core::ptr::null_mut()), 0);
    }
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&attr(4, 16)));
    assert!(q >= 0);
    let mut ev = SigEvent::none();
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = sig;
    ev.sigev_value = SigVal { sival_ptr: 0x1234 as *mut c_void };
    SIG_COUNT.store(0, Ordering::SeqCst);
    assert_eq!(unsafe { mq_notify(q, &ev) }, 0);
    // second registration on the same queue: EBUSY
    assert_eq!(unsafe { mq_notify(q, &ev) }, -1);
    assert_eq!(errno(), 16);
    assert_eq!(send(q, b"1", 0), 0);
    for _ in 0..100 {
        if SIG_COUNT.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(SIG_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(SIG_VALUE.load(Ordering::SeqCst), 0x1234);
    assert_eq!(SIG_CODE.load(Ordering::SeqCst), -3, "SI_MESGQ");
    // one-shot: the next message does not signal; registration was removed
    assert_eq!(send(q, b"2", 0), 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(SIG_COUNT.load(Ordering::SeqCst), 1);
    // removal with null; a message on a non-empty queue never notifies
    assert_eq!(unsafe { mq_notify(q, &ev) }, 0);
    assert_eq!(unsafe { mq_notify(q, core::ptr::null()) }, 0);
    let mut buf = [0u8; 16];
    while recv_count(q, &mut buf) > 0 {}
    assert_eq!(send(q, b"3", 0), 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(SIG_COUNT.load(Ordering::SeqCst), 1);
    // SIGEV_NONE reserves the notification (EBUSY for the second) without any signal
    let mut none = SigEvent::none();
    none.sigev_notify = SIGEV_NONE;
    while recv_count(q, &mut buf) > 0 {}
    assert_eq!(unsafe { mq_notify(q, &none) }, 0);
    assert_eq!(unsafe { mq_notify(q, &ev) }, -1);
    assert_eq!(errno(), 16);
    assert_eq!(send(q, b"4", 0), 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(SIG_COUNT.load(Ordering::SeqCst), 1);
    // bad descriptor and bad notification kind
    assert_eq!(unsafe { mq_notify(-1, &ev) }, -1);
    assert_eq!(errno(), 9);
    let mut badev = SigEvent::none();
    badev.sigev_notify = 77;
    assert_eq!(unsafe { mq_notify(q, &badev) }, -1);
    assert_eq!(errno(), 22);
    mq_close(q);
}

fn recv_count(q: mqd_t, buf: &mut [u8]) -> isize {
    let ts = Timespec { tv_sec: 1, tv_nsec: 0 };
    let mut a = MqAttr::default();
    unsafe { mq_getattr(q, &mut a) };
    if a.curmsgs == 0 {
        return 0;
    }
    unsafe { mq_timedreceive(q, buf.as_mut_ptr() as *mut c_char, buf.len(), core::ptr::null_mut(), &ts) }
}

static THREAD_CALLS: AtomicUsize = AtomicUsize::new(0);
static THREAD_VALUE: AtomicUsize = AtomicUsize::new(0);
static THREAD_ID: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn on_thread(v: SigVal) {
    unsafe {
        THREAD_VALUE.store(v.sival_ptr as usize, Ordering::SeqCst);
        THREAD_ID.store(libc::gettid() as usize, Ordering::SeqCst);
    }
    THREAD_CALLS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn notify_thread() {
    let _l = lock();
    let n = Name::new();
    let q = mk(&n, O_RDWR, Some(&attr(4, 16)));
    assert!(q >= 0);
    let mut ev = SigEvent::none();
    ev.sigev_notify = SIGEV_THREAD;
    ev.sigev_notify_function = Some(on_thread);
    ev.sigev_value = SigVal { sival_ptr: 0xbeef as *mut c_void };
    THREAD_CALLS.store(0, Ordering::SeqCst);
    for round in 1..=3usize {
        assert_eq!(unsafe { mq_notify(q, &ev) }, 0, "errno {}", errno());
        if round == 1 {
            assert_eq!(unsafe { mq_notify(q, &ev) }, -1);
            assert_eq!(errno(), 16);
        }
        assert_eq!(send(q, b"x", 0), 0);
        for _ in 0..200 {
            if THREAD_CALLS.load(Ordering::SeqCst) >= round {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(THREAD_CALLS.load(Ordering::SeqCst), round);
        assert_eq!(THREAD_VALUE.load(Ordering::SeqCst), 0xbeef);
        assert_ne!(THREAD_ID.load(Ordering::SeqCst) as i32, unsafe { libc::gettid() });
        let mut buf = [0u8; 16];
        assert_eq!(recv(q, &mut buf).0, 1);
    }
    // with attributes (a detached thread with a small stack) and removal: no call
    let mut at: libc::pthread_attr_t = unsafe { core::mem::zeroed() };
    unsafe {
        libc::pthread_attr_init(&mut at);
        libc::pthread_attr_setdetachstate(&mut at, libc::PTHREAD_CREATE_DETACHED);
        libc::pthread_attr_setstacksize(&mut at, 256 * 1024);
    }
    ev.sigev_notify_attributes = &mut at as *mut libc::pthread_attr_t as *mut c_void;
    assert_eq!(unsafe { mq_notify(q, &ev) }, 0);
    assert_eq!(unsafe { mq_notify(q, core::ptr::null()) }, 0);
    assert_eq!(send(q, b"x", 0), 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(THREAD_CALLS.load(Ordering::SeqCst), 3);
    let mut buf = [0u8; 16];
    assert_eq!(recv(q, &mut buf).0, 1);
    assert_eq!(unsafe { mq_notify(q, &ev) }, 0);
    assert_eq!(send(q, b"x", 0), 0);
    for _ in 0..200 {
        if THREAD_CALLS.load(Ordering::SeqCst) >= 4 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(THREAD_CALLS.load(Ordering::SeqCst), 4);
    unsafe { libc::pthread_attr_destroy(&mut at) };
    mq_close(q);
}

#[test]
fn open_2_and_rust_api() {
    let _l = lock();
    let n = Name::new();
    // __mq_open_2 without O_CREAT is mq_open
    let a = attr(2, 8);
    let q = mk(&n, O_RDWR, Some(&a));
    assert!(q >= 0);
    let q2 = unsafe { __mq_open_2(n.p(), O_RDONLY) };
    assert!(q2 >= 0);
    mq_close(q2);
    mq_close(q);
    // with O_CREAT the process aborts (like glibc's __fortify_fail)
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            __mq_open_2(n.p(), O_CREAT | O_RDWR);
            libc::_exit(0);
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    assert!(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGABRT, "status {:#x}", st);
}

#[test]
fn rust_api() {
    let _l = lock();
    let n = Name::new();
    let a = attr(3, 32);
    assert_eq!(Queue::open(&n.s, O_RDWR).err(), Some(Errno(2)));
    let q = Queue::create(&n.s, O_RDWR | O_EXCL, 0o600, Some(&a)).unwrap();
    assert_eq!(Queue::create(&n.s, O_RDWR | O_EXCL, 0o600, None).err(), Some(Errno(17)));
    assert_eq!(Queue::open(c"no-slash", O_RDONLY).err(), Some(Errno(22)));
    assert_eq!(Queue::unlink(c"no-slash"), Err(Errno(22)));
    let at = q.attr().unwrap();
    assert_eq!((at.maxmsg, at.msgsize, at.curmsgs, at.flags), (3, 32, 0, 0));
    q.send(b"low", 1).unwrap();
    q.send(b"high", 9).unwrap();
    q.send(b"mid", 5).unwrap();
    assert_eq!(q.send(b"x", 40000), Err(Errno(22)));
    let mut buf = [0u8; 32];
    assert_eq!(q.receive(&mut buf), Ok((4, 9)));
    assert_eq!(&buf[..4], b"high");
    assert_eq!(q.receive(&mut buf), Ok((3, 5)));
    let old = q.set_nonblocking(true).unwrap();
    assert_eq!(old.flags, 0);
    assert_eq!(q.receive(&mut buf), Ok((3, 1)));
    assert_eq!(q.receive(&mut buf), Err(Errno(11)));
    assert_eq!(q.receive(&mut [0u8; 4]), Err(Errno(90)));
    for _ in 0..3 {
        q.send(b"f", 0).unwrap();
    }
    assert_eq!(q.send(b"f", 0), Err(Errno(11)));
    let t = now_plus(30);
    q.set_nonblocking(false).unwrap();
    assert_eq!(q.send_timed(b"f", 0, &t), Err(Errno(110)));
    let mut b2 = [0u8; 32];
    for _ in 0..3 {
        q.receive_timed(&mut b2, &now_plus(1000)).unwrap();
    }
    assert_eq!(q.receive_timed(&mut b2, &now_plus(30)), Err(Errno(110)));
    // notify through the wrapper: SIGEV_NONE then removal
    let mut ev = SigEvent::none();
    ev.sigev_notify = SIGEV_NONE;
    q.notify(Some(&ev)).unwrap();
    assert_eq!(q.notify(Some(&ev)), Err(Errno(16)));
    q.notify(None).unwrap();
    Queue::unlink(&n.s).unwrap();
    assert_eq!(Queue::unlink(&n.s), Err(Errno(2)));
}
