//! POSIX AIO against the host glibc: every scenario runs once through our functions and once through
//! glibc's (the same `Aiocb` memory layout is passed to both) and must log the same observations.
use super::{errno, host_errno, lock};
use crate::aio::*;
use crate::notify::*;
use crate::sysv::Timespec;
use core::ffi::{c_int, c_void};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

struct Api {
    name: &'static str,
    read: unsafe extern "C" fn(*mut Aiocb) -> c_int,
    write: unsafe extern "C" fn(*mut Aiocb) -> c_int,
    fsync: unsafe extern "C" fn(c_int, *mut Aiocb) -> c_int,
    error: unsafe extern "C" fn(*const Aiocb) -> c_int,
    ret: unsafe extern "C" fn(*mut Aiocb) -> isize,
    cancel: unsafe extern "C" fn(c_int, *mut Aiocb) -> c_int,
    suspend: unsafe extern "C" fn(*const *const Aiocb, c_int, *const Timespec) -> c_int,
    lio: unsafe extern "C" fn(c_int, *const *mut Aiocb, c_int, *mut SigEvent) -> c_int,
    errno: fn() -> c_int,
}

unsafe extern "C" fn h_read(c: *mut Aiocb) -> c_int {
    unsafe { libc::aio_read(c as *mut libc::aiocb) }
}
unsafe extern "C" fn h_write(c: *mut Aiocb) -> c_int {
    unsafe { libc::aio_write(c as *mut libc::aiocb) }
}
unsafe extern "C" fn h_fsync(op: c_int, c: *mut Aiocb) -> c_int {
    unsafe { libc::aio_fsync(op, c as *mut libc::aiocb) }
}
unsafe extern "C" fn h_error(c: *const Aiocb) -> c_int {
    unsafe { libc::aio_error(c as *const libc::aiocb) }
}
unsafe extern "C" fn h_ret(c: *mut Aiocb) -> isize {
    unsafe { libc::aio_return(c as *mut libc::aiocb) }
}
unsafe extern "C" fn h_cancel(fd: c_int, c: *mut Aiocb) -> c_int {
    unsafe { libc::aio_cancel(fd, c as *mut libc::aiocb) }
}
unsafe extern "C" fn h_suspend(l: *const *const Aiocb, n: c_int, t: *const Timespec) -> c_int {
    unsafe { libc::aio_suspend(l as *const *const libc::aiocb, n, t as *const libc::timespec) }
}
unsafe extern "C" fn h_lio(mode: c_int, l: *const *mut Aiocb, n: c_int, s: *mut SigEvent) -> c_int {
    unsafe { libc::lio_listio(mode, l as *const *mut libc::aiocb, n, s as *mut libc::sigevent) }
}

static OURS: Api = Api {
    name: "ours",
    read: aio_read,
    write: aio_write,
    fsync: aio_fsync,
    error: aio_error,
    ret: aio_return,
    cancel: aio_cancel,
    suspend: aio_suspend,
    lio: lio_listio,
    errno,
};

static HOST: Api = Api {
    name: "glibc",
    read: h_read,
    write: h_write,
    fsync: h_fsync,
    error: h_error,
    ret: h_ret,
    cancel: h_cancel,
    suspend: h_suspend,
    lio: h_lio,
    errno: host_errno,
};

fn zero_cb() -> Aiocb {
    unsafe { core::mem::zeroed() }
}

fn cb(fd: c_int, buf: *mut u8, n: usize, off: i64) -> Aiocb {
    let mut c = zero_cb();
    c.aio_fildes = fd;
    c.aio_buf = buf as *mut c_void;
    c.aio_nbytes = n;
    c.aio_offset = off;
    c.aio_sigevent.sigev_notify = SIGEV_NONE;
    c
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempFile {
    path: std::path::PathBuf,
    fd: c_int,
}
impl TempFile {
    fn new() -> TempFile {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("rlibc-aio-{}-{}", std::process::id(), n));
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) };
        assert!(fd >= 0);
        TempFile { path, fd }
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        let _ = std::fs::remove_file(&self.path);
    }
}

struct Pipe {
    r: c_int,
    w: c_int,
}
impl Pipe {
    fn new() -> Pipe {
        let mut f = [0; 2];
        assert_eq!(unsafe { libc::pipe(f.as_mut_ptr()) }, 0);
        Pipe { r: f[0], w: f[1] }
    }
    fn put(&self, b: &[u8]) {
        assert_eq!(unsafe { libc::write(self.w, b.as_ptr() as *const c_void, b.len()) }, b.len() as isize);
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.r);
            libc::close(self.w);
        }
    }
}

/// Wait (polling aio_error) until the request is no longer in progress; false if it never finishes.
fn done(api: &Api, c: &mut Aiocb) -> bool {
    for _ in 0..3000 {
        if unsafe { (api.error)(c) } != 115 {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    false
}

fn pause(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

fn ts(sec: i64, nsec: i64) -> Timespec {
    Timespec { tv_sec: sec, tv_nsec: nsec }
}

macro_rules! logln {
    ($log:expr, $($arg:tt)*) => { writeln!($log, $($arg)*).unwrap() };
}

/// Run a scenario through both implementations and compare the logs.
fn both(f: fn(&Api) -> String) -> String {
    let _l = lock();
    let a = f(&OURS);
    let b = f(&HOST);
    assert_eq!(a, b, "{} and {} differ:\n--- {}\n{}\n--- {}\n{}", OURS.name, HOST.name, OURS.name, a, HOST.name, b);
    a
}

#[test]
fn layout_and_constants_equal_glibc() {
    use core::mem::size_of;
    assert_eq!(size_of::<Aiocb>(), size_of::<libc::aiocb>());
    assert_eq!(size_of::<AioInit>(), 32);
    assert_eq!((LIO_READ, LIO_WRITE, LIO_NOP, LIO_WAIT, LIO_NOWAIT), (libc::LIO_READ, libc::LIO_WRITE, libc::LIO_NOP, libc::LIO_WAIT, libc::LIO_NOWAIT));
    assert_eq!((AIO_CANCELED, AIO_NOTCANCELED, AIO_ALLDONE), (libc::AIO_CANCELED, libc::AIO_NOTCANCELED, libc::AIO_ALLDONE));
    assert_eq!((O_SYNC, O_DSYNC), (libc::O_SYNC, libc::O_DSYNC));
}

fn s_roundtrip(api: &Api) -> String {
    let mut log = String::new();
    let f = TempFile::new();
    let mut w = *b"hello, asynchronous world";
    let mut c = cb(f.fd, w.as_mut_ptr(), w.len(), 0);
    logln!(log, "write submit {}", unsafe { (api.write)(&mut c) });
    logln!(log, "write finished {}", done(api, &mut c));
    logln!(log, "write error {} return {}", unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    logln!(log, "opcode now {}", c.aio_lio_opcode);
    let mut r = [0u8; 5];
    let mut c2 = cb(f.fd, r.as_mut_ptr(), 5, 7);
    logln!(log, "read submit {}", unsafe { (api.read)(&mut c2) });
    logln!(log, "read finished {}", done(api, &mut c2));
    logln!(log, "read error {} return {} data {:?}", unsafe { (api.error)(&c2) }, unsafe { (api.ret)(&mut c2) }, std::str::from_utf8(&r));
    // a read past the end returns 0, a read crossing it returns the rest
    let mut big = [0u8; 64];
    let mut c3 = cb(f.fd, big.as_mut_ptr(), 64, 20);
    unsafe { (api.read)(&mut c3) };
    done(api, &mut c3);
    logln!(log, "read crossing end return {}", unsafe { (api.ret)(&mut c3) });
    let mut c4 = cb(f.fd, big.as_mut_ptr(), 64, 1000);
    unsafe { (api.read)(&mut c4) };
    done(api, &mut c4);
    logln!(log, "read past end return {} error {}", unsafe { (api.ret)(&mut c4) }, unsafe { (api.error)(&c4) });
    // zero-length requests
    let mut c5 = cb(f.fd, big.as_mut_ptr(), 0, 0);
    unsafe { (api.write)(&mut c5) };
    done(api, &mut c5);
    logln!(log, "zero write return {} error {}", unsafe { (api.ret)(&mut c5) }, unsafe { (api.error)(&c5) });
    let content = std::fs::read(&f.path).unwrap();
    logln!(log, "file {:?}", std::str::from_utf8(&content));
    log
}

#[test]
fn write_then_read_back() {
    let log = both(s_roundtrip);
    assert!(log.contains("file Ok(\"hello, asynchronous world\")"), "{}", log);
    assert!(log.contains("read error 0 return 5 data Ok(\"async\")"), "{}", log);
}

fn s_errors(api: &Api) -> String {
    let mut log = String::new();
    let f = TempFile::new();
    let mut b = [0u8; 8];
    // a bad descriptor is not noticed when queuing: aio_error says EBADF afterwards
    let mut c = cb(9999, b.as_mut_ptr(), 8, 0);
    logln!(log, "read bad fd submit {}", unsafe { (api.read)(&mut c) });
    logln!(log, "finished {} error {} return {}", done(api, &mut c), unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    // a negative request priority is refused at once, with EINVAL in the aiocb too
    let mut c = cb(f.fd, b.as_mut_ptr(), 8, 0);
    c.aio_reqprio = -1;
    let r = unsafe { (api.read)(&mut c) };
    logln!(log, "reqprio -1 -> {} errno {} error {} return {}", r, (api.errno)(), unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    // a read-only descriptor refuses to write
    let ro = {
        let cpath = std::ffi::CString::new(f.path.to_str().unwrap()).unwrap();
        unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) }
    };
    let mut c = cb(ro, b.as_mut_ptr(), 8, 0);
    logln!(log, "write on O_RDONLY submit {}", unsafe { (api.write)(&mut c) });
    logln!(log, "finished {} error {} return {}", done(api, &mut c), unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    // aio_fsync argument checks
    let mut c = cb(f.fd, b.as_mut_ptr(), 0, 0);
    let r = unsafe { (api.fsync)(0, &mut c) };
    logln!(log, "fsync op 0 -> {} errno {}", r, (api.errno)());
    let mut c = cb(9999, b.as_mut_ptr(), 0, 0);
    let r = unsafe { (api.fsync)(libc::O_SYNC, &mut c) };
    logln!(log, "fsync bad fd -> {} errno {}", r, (api.errno)());
    // aio_cancel checks
    let r = unsafe { (api.cancel)(9999, core::ptr::null_mut()) };
    logln!(log, "cancel bad fd -> {} errno {}", r, (api.errno)());
    let mut c = cb(f.fd, b.as_mut_ptr(), 8, 0);
    let r = unsafe { (api.cancel)(f.fd + 1, &mut c) };
    logln!(log, "cancel fd mismatch -> {} errno {}", r, (api.errno)());
    // cancel on a descriptor with nothing pending
    logln!(log, "cancel idle fd all -> {}", unsafe { (api.cancel)(f.fd, core::ptr::null_mut()) });
    // a finished request: ALLDONE
    unsafe { (api.read)(&mut c) };
    done(api, &mut c);
    logln!(log, "cancel finished -> {}", unsafe { (api.cancel)(f.fd, &mut c) });
    // an aiocb that claims to be in progress but is unknown: EINVAL
    let mut ghost = cb(f.fd, b.as_mut_ptr(), 8, 0);
    ghost.error_code = 115;
    let r = unsafe { (api.cancel)(f.fd, &mut ghost) };
    logln!(log, "cancel unknown in-progress -> {} errno {}", r, (api.errno)());
    // aio_suspend and lio_listio argument checks
    let r = unsafe { (api.suspend)(core::ptr::null(), -1, core::ptr::null()) };
    logln!(log, "suspend nent -1 -> {} errno {}", r, (api.errno)());
    let r = unsafe { (api.suspend)(core::ptr::null(), 0, core::ptr::null()) };
    logln!(log, "suspend nent 0 -> {}", r);
    let nul: [*const Aiocb; 2] = [core::ptr::null(), core::ptr::null()];
    logln!(log, "suspend all null -> {}", unsafe { (api.suspend)(nul.as_ptr(), 2, core::ptr::null()) });
    let r = unsafe { (api.lio)(7, core::ptr::null(), 0, core::ptr::null_mut()) };
    logln!(log, "lio bad mode -> {} errno {}", r, (api.errno)());
    unsafe { libc::close(ro) };
    log
}

#[test]
fn error_cases() {
    let log = both(s_errors);
    assert!(log.contains("read bad fd submit 0"), "{}", log);
    assert!(log.contains("error 9 return -1"), "{}", log);
}

fn s_pipe_states(api: &Api) -> String {
    let mut log = String::new();
    let p = Pipe::new();
    let mut b = [0u8; 16];
    let mut c = cb(p.r, b.as_mut_ptr(), 16, 0);
    logln!(log, "submit {}", unsafe { (api.read)(&mut c) });
    pause(100);
    logln!(log, "in progress: error {} return {}", unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    // suspend with a timeout: EAGAIN
    let list = [&c as *const Aiocb];
    let t0 = std::time::Instant::now();
    let r = unsafe { (api.suspend)(list.as_ptr(), 1, &ts(0, 100_000_000)) };
    let dt = t0.elapsed().as_millis();
    logln!(log, "suspend timeout -> {} errno {} waited {}", r, (api.errno)(), (90..1500).contains(&dt));
    // (an invalid timeout makes glibc 2.43 abort in an assertion: only ours is tested, below)
    p.put(b"abc");
    let r = unsafe { (api.suspend)(list.as_ptr(), 1, &ts(5, 0)) };
    logln!(log, "suspend after data -> {}", r);
    logln!(log, "done {} error {} return {} data {:?}", done(api, &mut c), unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) }, &b[..3]);
    // suspend on an already finished request returns at once
    let t0 = std::time::Instant::now();
    let r = unsafe { (api.suspend)(list.as_ptr(), 1, core::ptr::null()) };
    logln!(log, "suspend finished -> {} quick {}", r, t0.elapsed().as_millis() < 100);
    // a null entry beside an in-progress one
    let mut c2 = cb(p.r, b.as_mut_ptr(), 16, 0);
    unsafe { (api.read)(&mut c2) };
    pause(50);
    let list2 = [core::ptr::null(), &c2 as *const Aiocb];
    let r = unsafe { (api.suspend)(list2.as_ptr(), 2, &ts(0, 50_000_000)) };
    logln!(log, "suspend null + pending -> {} errno {}", r, (api.errno)());
    p.put(b"z");
    done(api, &mut c2);
    logln!(log, "second read return {}", unsafe { (api.ret)(&mut c2) });
    log
}

#[test]
fn pipe_states_and_suspend() {
    let log = both(s_pipe_states);
    assert!(log.contains("in progress: error 115 return -1"), "{}", log);
    assert!(log.contains("suspend timeout -> -1 errno 11 waited true"), "{}", log);
}

#[test]
fn suspend_with_an_invalid_timeout_is_einval() {
    let _l = lock();
    let p = Pipe::new();
    let mut b = [0u8; 4];
    let mut c = cb(p.r, b.as_mut_ptr(), 4, 0);
    assert_eq!(unsafe { aio_read(&mut c) }, 0);
    pause(50);
    let list = [&c as *const Aiocb];
    assert_eq!(unsafe { aio_suspend(list.as_ptr(), 1, &ts(0, 2_000_000_000)) }, -1);
    assert_eq!(errno(), 22);
    p.put(b"abcd");
    assert!(done(&OURS, &mut c));
}

extern "C" fn on_usr2(_s: c_int) {}

fn s_interrupted(api: &Api) -> String {
    let mut log = String::new();
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_usr2 as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR2, &sa, core::ptr::null_mut());
    }
    let p = Pipe::new();
    let mut b = [0u8; 4];
    let mut c = cb(p.r, b.as_mut_ptr(), 4, 0);
    unsafe { (api.read)(&mut c) };
    pause(50);
    let me = unsafe { libc::pthread_self() };
    // a signal while blocked in aio_suspend ends it with EINTR
    let k = std::thread::spawn(move || {
        pause(100);
        unsafe { libc::pthread_kill(me, libc::SIGUSR2) };
    });
    let list = [&c as *const Aiocb];
    let r = unsafe { (api.suspend)(list.as_ptr(), 1, core::ptr::null()) };
    logln!(log, "suspend interrupted -> {} errno {}", r, (api.errno)());
    k.join().unwrap();
    // finish the read
    p.put(b"abcd");
    done(api, &mut c);
    logln!(log, "finished: {}", unsafe { (api.ret)(&mut c) });
    log
}

#[test]
fn signals_interrupt_the_waiting_calls() {
    let log = both(s_interrupted);
    assert!(log.contains("suspend interrupted -> -1 errno 4"), "{}", log);
}

/// lio_listio(LIO_WAIT) interrupted by a signal returns EINTR and leaves the requests running. (glibc
/// leaves its on-stack waiters linked to them, and crashes when they finish: ours is tested alone.)
#[test]
fn lio_wait_interrupted_leaves_no_dangling_waiter() {
    let _l = lock();
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_usr2 as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR2, &sa, core::ptr::null_mut());
    }
    let p = Pipe::new();
    let mut b = [0u8; 4];
    let mut c2 = cb(p.r, b.as_mut_ptr(), 4, 0);
    c2.aio_lio_opcode = LIO_READ;
    let me = unsafe { libc::pthread_self() };
    let k = std::thread::spawn(move || {
        pause(100);
        unsafe { libc::pthread_kill(me, libc::SIGUSR2) };
    });
    let l2 = [&mut c2 as *mut Aiocb];
    let r = unsafe { aio_lio_wait(l2.as_ptr()) };
    assert_eq!((r, errno()), (-1, 4));
    k.join().unwrap();
    p.put(b"abcd");
    assert!(done(&OURS, &mut c2));
    assert_eq!(unsafe { aio_return(&mut c2) }, 4);
    // the pool still works afterwards
    let f = TempFile::new();
    let mut w = *b"ok";
    let mut c3 = cb(f.fd, w.as_mut_ptr(), 2, 0);
    assert_eq!(unsafe { aio_write(&mut c3) }, 0);
    assert!(done(&OURS, &mut c3));
}

unsafe fn aio_lio_wait(l: *const *mut Aiocb) -> c_int {
    unsafe { lio_listio(LIO_WAIT, l, 1, core::ptr::null_mut()) }
}

fn s_cancel(api: &Api) -> String {
    let mut log = String::new();
    let p = Pipe::new();
    let mut bufs = [[0u8; 8]; 4];
    let mut cbs: Vec<Aiocb> = (0..4).map(|i| cb(p.r, bufs[i].as_mut_ptr(), 8, 0)).collect();
    for i in 0..4 {
        logln!(log, "submit {} -> {}", i, unsafe { (api.read)(&mut cbs[i]) });
    }
    pause(100);
    // the first read is running (blocked in the pipe), the others queue behind it
    logln!(log, "cancel running -> {}", unsafe { (api.cancel)(p.r, &mut cbs[0]) });
    logln!(log, "cancel queued 2 -> {}", unsafe { (api.cancel)(p.r, &mut cbs[2]) });
    logln!(log, "errors after: {} {} {} {}", unsafe { (api.error)(&cbs[0]) }, unsafe { (api.error)(&cbs[1]) }, unsafe { (api.error)(&cbs[2]) }, unsafe { (api.error)(&cbs[3]) });
    logln!(log, "return of cancelled 2: {}", unsafe { (api.ret)(&mut cbs[2]) });
    logln!(log, "cancel queued 2 again -> {}", unsafe { (api.cancel)(p.r, &mut cbs[2]) });
    logln!(log, "cancel all -> {}", unsafe { (api.cancel)(p.r, core::ptr::null_mut()) });
    logln!(log, "errors after: {} {} {} {}", unsafe { (api.error)(&cbs[0]) }, unsafe { (api.error)(&cbs[1]) }, unsafe { (api.error)(&cbs[2]) }, unsafe { (api.error)(&cbs[3]) });
    logln!(log, "return of cancelled 1 and 3: {} {}", unsafe { (api.ret)(&mut cbs[1]) }, unsafe { (api.ret)(&mut cbs[3]) });
    p.put(b"12345678");
    logln!(log, "running one finished {} error {} return {}", done(api, &mut cbs[0]), unsafe { (api.error)(&cbs[0]) }, unsafe { (api.ret)(&mut cbs[0]) });
    logln!(log, "cancel all when idle -> {}", unsafe { (api.cancel)(p.r, core::ptr::null_mut()) });
    // all requests of one descriptor cancelled while the head was only waiting for a worker is covered by the thread-limit test
    log
}

#[test]
fn cancel_pending_reads_on_a_pipe() {
    let log = both(s_cancel);
    assert!(log.contains("cancel running -> 1"), "{}", log);
    assert!(log.contains("cancel queued 2 -> 0"), "{}", log);
    assert!(log.contains("errors after: 115 115 125 115"), "{}", log);
    assert!(log.contains("cancel all -> 1"), "{}", log);
    assert!(log.contains("errors after: 115 125 125 125"), "{}", log);
}

fn s_cancel_by_thread_limit(api: &Api) -> String {
    let mut log = String::new();
    // 24 pipes, one blocking read each: the first 20 are taken by workers, the other 4 wait for a worker
    let pipes: Vec<Pipe> = (0..24).map(|_| Pipe::new()).collect();
    let mut bufs = [[0u8; 8]; 24];
    let mut cbs: Vec<Aiocb> = (0..24).map(|i| cb(pipes[i].r, bufs[i].as_mut_ptr(), 8, 0)).collect();
    for i in 0..24 {
        assert_eq!(unsafe { (api.read)(&mut cbs[i]) }, 0);
    }
    pause(300);
    let mut res = Vec::new();
    for i in 0..24 {
        res.push(unsafe { (api.cancel)(pipes[i].r, &mut cbs[i]) });
    }
    logln!(log, "cancel results: running {} not cancelled, waiting {} cancelled", res.iter().filter(|&&r| r == 1).count(), res.iter().filter(|&&r| r == 0).count());
    for p in &pipes {
        p.put(b"x");
    }
    let mut finished = 0;
    for i in 0..24 {
        if done(api, &mut cbs[i]) {
            finished += 1;
        }
    }
    logln!(log, "all settled {}", finished);
    let ok = cbs.iter().filter(|c| unsafe { (api.error)(*c) } == 0).count();
    let canc = cbs.iter().filter(|c| unsafe { (api.error)(*c) } == 125).count();
    logln!(log, "completed {} cancelled {}", ok, canc);
    log
}

#[test]
fn worker_thread_limit_decides_what_can_be_cancelled() {
    let log = both(s_cancel_by_thread_limit);
    assert!(log.contains("running 20 not cancelled, waiting 4 cancelled"), "{}", log);
    assert!(log.contains("completed 20 cancelled 4"), "{}", log);
}

static SIG_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIG_VAL: AtomicUsize = AtomicUsize::new(0);
static SIG_CODE: AtomicI32 = AtomicI32::new(0);
static SIG_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(_s: c_int, info: *mut libc::siginfo_t, _c: *mut c_void) {
    unsafe {
        SIG_VAL.store((*info).si_value().sival_ptr as usize, Ordering::SeqCst);
        SIG_CODE.store((*info).si_code, Ordering::SeqCst);
        SIG_PID.store((*info).si_pid(), Ordering::SeqCst);
    }
    SIG_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install(sig: c_int) {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(sig, &sa, core::ptr::null_mut()), 0);
    }
}

fn wait_count(c: &AtomicUsize, n: usize) {
    for _ in 0..500 {
        if c.load(Ordering::SeqCst) >= n {
            return;
        }
        pause(10);
    }
}

fn s_signal(api: &Api) -> String {
    let mut log = String::new();
    let sig = libc::SIGRTMIN() + 3;
    install(sig);
    let f = TempFile::new();
    let mut b = *b"signal";
    let mut c = cb(f.fd, b.as_mut_ptr(), 6, 0);
    c.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    c.aio_sigevent.sigev_signo = sig;
    c.aio_sigevent.sigev_value = SigVal { sival_ptr: 0x5151 as *mut c_void };
    SIG_COUNT.store(0, Ordering::SeqCst);
    logln!(log, "submit {}", unsafe { (api.write)(&mut c) });
    wait_count(&SIG_COUNT, 1);
    pause(30);
    logln!(log, "signals {} value {:#x} code {} pid_is_me {}", SIG_COUNT.load(Ordering::SeqCst), SIG_VAL.load(Ordering::SeqCst), SIG_CODE.load(Ordering::SeqCst), SIG_PID.load(Ordering::SeqCst) == std::process::id() as i32);
    // by the time the signal is delivered the request is finished
    logln!(log, "error {} return {}", unsafe { (api.error)(&c) }, unsafe { (api.ret)(&mut c) });
    // a cancelled request notifies too
    let p = Pipe::new();
    let mut rb = [0u8; 4];
    let mut c1 = cb(p.r, rb.as_mut_ptr(), 4, 0);
    let mut c2 = cb(p.r, rb.as_mut_ptr(), 4, 0);
    c2.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    c2.aio_sigevent.sigev_signo = sig;
    c2.aio_sigevent.sigev_value = SigVal { sival_ptr: 0x77 as *mut c_void };
    unsafe {
        (api.read)(&mut c1);
        pause(50);
        (api.read)(&mut c2);
    }
    SIG_COUNT.store(0, Ordering::SeqCst);
    logln!(log, "cancel queued -> {}", unsafe { (api.cancel)(p.r, &mut c2) });
    wait_count(&SIG_COUNT, 1);
    logln!(log, "cancel signals {} value {:#x}", SIG_COUNT.load(Ordering::SeqCst), SIG_VAL.load(Ordering::SeqCst));
    p.put(b"abcd");
    done(api, &mut c1);
    log
}

#[test]
fn completion_by_signal() {
    let log = both(s_signal);
    assert!(log.contains("signals 1 value 0x5151 code -4 pid_is_me true"), "{}", log);
    assert!(log.contains("cancel signals 1 value 0x77"), "{}", log);
}

static THREAD_CALLS: AtomicUsize = AtomicUsize::new(0);
static THREAD_SUM: AtomicUsize = AtomicUsize::new(0);
static THREAD_ON_MAIN: AtomicUsize = AtomicUsize::new(0);
static MAIN_TID: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn on_thread(v: SigVal) {
    THREAD_SUM.fetch_add(unsafe { v.sival_int } as usize, Ordering::SeqCst);
    if unsafe { libc::gettid() } == MAIN_TID.load(Ordering::SeqCst) {
        THREAD_ON_MAIN.fetch_add(1, Ordering::SeqCst);
    }
    THREAD_CALLS.fetch_add(1, Ordering::SeqCst);
}

fn s_thread_notify(api: &Api) -> String {
    let mut log = String::new();
    MAIN_TID.store(unsafe { libc::gettid() }, Ordering::SeqCst);
    THREAD_CALLS.store(0, Ordering::SeqCst);
    THREAD_SUM.store(0, Ordering::SeqCst);
    THREAD_ON_MAIN.store(0, Ordering::SeqCst);
    let f = TempFile::new();
    let mut data = [7u8; 32];
    let mut cbs: Vec<Aiocb> = (0..40).map(|i| cb(f.fd, data.as_mut_ptr(), 4, (i * 4) as i64)).collect();
    for (i, c) in cbs.iter_mut().enumerate() {
        c.aio_sigevent.sigev_notify = SIGEV_THREAD;
        c.aio_sigevent.sigev_notify_function = Some(on_thread);
        c.aio_sigevent.sigev_value = SigVal { sival_int: (i + 1) as c_int };
        assert_eq!(unsafe { (api.write)(c) }, 0);
    }
    wait_count(&THREAD_CALLS, 40);
    pause(30);
    logln!(log, "calls {} sum {} on main {}", THREAD_CALLS.load(Ordering::SeqCst), THREAD_SUM.load(Ordering::SeqCst), THREAD_ON_MAIN.load(Ordering::SeqCst));
    logln!(log, "all done {}", cbs.iter().all(|c| unsafe { (api.error)(c) } == 0));
    log
}

#[test]
fn completion_by_thread_counts_every_request() {
    let log = both(s_thread_notify);
    assert!(log.contains("calls 40 sum 820 on main 0"), "{}", log);
}

fn s_lio(api: &Api) -> String {
    let mut log = String::new();
    let f = TempFile::new();
    let mut w1 = *b"AAAA";
    let mut w2 = *b"BBBB";
    let mut r1 = [0u8; 4];
    let mut cs = [cb(f.fd, w1.as_mut_ptr(), 4, 0), cb(f.fd, w2.as_mut_ptr(), 4, 4), cb(f.fd, r1.as_mut_ptr(), 4, 2), zero_cb()];
    cs[0].aio_lio_opcode = LIO_WRITE;
    cs[1].aio_lio_opcode = LIO_WRITE;
    cs[2].aio_lio_opcode = LIO_READ;
    cs[3].aio_lio_opcode = LIO_NOP;
    let list: Vec<*mut Aiocb> = vec![&mut cs[0], &mut cs[1], &mut cs[2], &mut cs[3], core::ptr::null_mut()];
    let r = unsafe { (api.lio)(LIO_WAIT, list.as_ptr(), 5, core::ptr::null_mut()) };
    logln!(log, "lio wait -> {} errno {}", r, if r == -1 { (api.errno)() } else { 0 });
    logln!(log, "returns {} {} {} (read gets {:?})", unsafe { (api.ret)(&mut cs[0]) }, unsafe { (api.ret)(&mut cs[1]) }, unsafe { (api.ret)(&mut cs[2]) }, std::str::from_utf8(&r1));
    logln!(log, "errors {} {} {} nop error {}", unsafe { (api.error)(&cs[0]) }, unsafe { (api.error)(&cs[1]) }, unsafe { (api.error)(&cs[2]) }, cs[3].error_code);
    // one failing request: -1 and EIO
    let mut bad = cb(9999, r1.as_mut_ptr(), 4, 0);
    bad.aio_lio_opcode = LIO_READ;
    let list2: Vec<*mut Aiocb> = vec![&mut cs[2], &mut bad];
    let r = unsafe { (api.lio)(LIO_WAIT, list2.as_ptr(), 2, core::ptr::null_mut()) };
    logln!(log, "lio wait with a bad fd -> {} errno {}", r, (api.errno)());
    // a bad opcode
    let mut weird = cb(f.fd, r1.as_mut_ptr(), 4, 0);
    weird.aio_lio_opcode = 9;
    let list3: Vec<*mut Aiocb> = vec![&mut weird];
    let r = unsafe { (api.lio)(LIO_WAIT, list3.as_ptr(), 1, core::ptr::null_mut()) };
    logln!(log, "lio wait with opcode 9 -> {} errno {} error {}", r, (api.errno)(), unsafe { (api.error)(&weird) });
    // negative priority fails to queue
    let mut neg = cb(f.fd, r1.as_mut_ptr(), 4, 0);
    neg.aio_lio_opcode = LIO_READ;
    neg.aio_reqprio = -3;
    let list4: Vec<*mut Aiocb> = vec![&mut neg];
    let r = unsafe { (api.lio)(LIO_WAIT, list4.as_ptr(), 1, core::ptr::null_mut()) };
    logln!(log, "lio wait with reqprio -3 -> {} errno {}", r, (api.errno)());
    let r = unsafe { (api.lio)(LIO_NOWAIT, list4.as_ptr(), 1, core::ptr::null_mut()) };
    logln!(log, "lio nowait with reqprio -3 -> {} errno {}", r, (api.errno)());
    log
}

#[test]
fn lio_listio_wait() {
    let log = both(s_lio);
    assert!(log.contains("lio wait -> 0"), "{}", log);
    assert!(log.contains("returns 4 4 4 (read gets Ok(\"AABB\"))"), "{}", log);
    assert!(log.contains("lio wait with a bad fd -> -1 errno 5"), "{}", log);
}

fn s_lio_nowait_signal(api: &Api) -> String {
    let mut log = String::new();
    let sig = libc::SIGRTMIN() + 4;
    install(sig);
    let f = TempFile::new();
    let mut w = *b"0123456789ab";
    let mut cs: Vec<Aiocb> = (0..3).map(|i| cb(f.fd, unsafe { w.as_mut_ptr().add(i * 4) }, 4, (i * 4) as i64)).collect();
    for c in cs.iter_mut() {
        c.aio_lio_opcode = LIO_WRITE;
        c.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
        c.aio_sigevent.sigev_signo = sig;
        c.aio_sigevent.sigev_value = SigVal { sival_ptr: 0x10 as *mut c_void };
    }
    let list: Vec<*mut Aiocb> = cs.iter_mut().map(|c| c as *mut Aiocb).collect();
    let mut ev = SigEvent::none();
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = sig;
    ev.sigev_value = SigVal { sival_ptr: 0x99 as *mut c_void };
    SIG_COUNT.store(0, Ordering::SeqCst);
    let r = unsafe { (api.lio)(LIO_NOWAIT, list.as_ptr(), 3, &mut ev) };
    logln!(log, "lio nowait -> {}", r);
    // three individual signals and the final one (4 in all); the final one comes after the others
    wait_count(&SIG_COUNT, 4);
    pause(50);
    logln!(log, "signals {}", SIG_COUNT.load(Ordering::SeqCst));
    logln!(log, "all done {}", cs.iter().all(|c| unsafe { (api.error)(c) } == 0));
    // nothing to do (all NOP): the notification is still sent
    let mut nop = zero_cb();
    nop.aio_lio_opcode = LIO_NOP;
    let l2: Vec<*mut Aiocb> = vec![&mut nop];
    SIG_COUNT.store(0, Ordering::SeqCst);
    let r = unsafe { (api.lio)(LIO_NOWAIT, l2.as_ptr(), 1, &mut ev) };
    wait_count(&SIG_COUNT, 1);
    logln!(log, "nop only -> {} signals {} value {:#x}", r, SIG_COUNT.load(Ordering::SeqCst), SIG_VAL.load(Ordering::SeqCst));
    // nothing at all, no sigevent
    let r = unsafe { (api.lio)(LIO_NOWAIT, l2.as_ptr(), 0, core::ptr::null_mut()) };
    logln!(log, "empty list -> {}", r);
    log
}

#[test]
fn lio_listio_nowait_notifies_once_at_the_end() {
    let log = both(s_lio_nowait_signal);
    assert!(log.contains("signals 4"), "{}", log);
    assert!(log.contains("nop only -> 0 signals 1 value 0x99"), "{}", log);
}

fn s_order(api: &Api) -> String {
    let mut log = String::new();
    // two writes to the same offset of one descriptor: the later one wins, every time
    let mut wins = 0;
    let rounds = 200;
    for round in 0..rounds {
        let f = TempFile::new();
        let mut a = [b'a'; 64];
        let mut b = [b'b'; 64];
        let mut c1 = cb(f.fd, a.as_mut_ptr(), 64, 0);
        let mut c2 = cb(f.fd, b.as_mut_ptr(), 64, 0);
        unsafe {
            (api.write)(&mut c1);
            (api.write)(&mut c2);
        }
        done(api, &mut c1);
        done(api, &mut c2);
        let mut got = [0u8; 64];
        unsafe { libc::pread(f.fd, got.as_mut_ptr() as *mut c_void, 64, 0) };
        if got == b {
            wins += 1;
        } else {
            logln!(log, "round {} lost the order", round);
        }
    }
    logln!(log, "later write won {} of {}", wins, rounds);
    // write, fsync, write: the fsync request runs between them
    let f = TempFile::new();
    let mut a = *b"first";
    let mut c1 = cb(f.fd, a.as_mut_ptr(), 5, 0);
    let mut cs = cb(f.fd, a.as_mut_ptr(), 0, 0);
    let mut b = *b"second";
    let mut c2 = cb(f.fd, b.as_mut_ptr(), 6, 5);
    unsafe {
        (api.write)(&mut c1);
        logln!(log, "fsync submit {}", (api.fsync)(libc::O_SYNC, &mut cs));
        (api.write)(&mut c2);
    }
    for c in [&mut c1, &mut cs, &mut c2] {
        done(api, c);
    }
    let (e, r) = unsafe { ((api.error)(&cs), (api.ret)(&mut cs)) };
    logln!(log, "fsync opcode {} error {} return {}", cs.aio_lio_opcode, e, r);
    let mut cd = cb(f.fd, a.as_mut_ptr(), 0, 0);
    unsafe { (api.fsync)(libc::O_DSYNC, &mut cd) };
    done(api, &mut cd);
    let (e, r) = unsafe { ((api.error)(&cd), (api.ret)(&mut cd)) };
    logln!(log, "fdatasync opcode {} error {} return {}", cd.aio_lio_opcode, e, r);
    logln!(log, "file {:?}", std::str::from_utf8(&std::fs::read(&f.path).unwrap()).map(|s| s.to_string()));
    log
}

#[test]
fn request_order_per_descriptor_and_fsync() {
    let log = both(s_order);
    assert!(log.contains("later write won 200 of 200"), "{}", log);
    assert!(log.contains("fsync opcode 4 error 0 return 0"), "{}", log);
    assert!(log.contains("fdatasync opcode 3 error 0 return 0"), "{}", log);
    assert!(log.contains("file Ok(\"firstsecond\")"), "{}", log);
}

fn s_many(api: &Api) -> String {
    let mut log = String::new();
    let f = TempFile::new();
    let n = 1000;
    let mut data: Vec<[u8; 4]> = (0..n).map(|i| (i as u32).to_le_bytes()).collect();
    let mut cbs: Vec<Aiocb> = (0..n).map(|i| cb(f.fd, data[i].as_mut_ptr(), 4, (i * 4) as i64)).collect();
    let mut failed = 0;
    for c in cbs.iter_mut() {
        if unsafe { (api.write)(c) } != 0 {
            failed += 1;
        }
    }
    logln!(log, "submit failures {}", failed);
    // wait for all through aio_suspend on the last one, then check each
    let last = [&cbs[n - 1] as *const Aiocb];
    while unsafe { (api.error)(last[0]) } == 115 {
        unsafe { (api.suspend)(last.as_ptr(), 1, &ts(1, 0)) };
    }
    let mut ok = 0;
    for c in cbs.iter_mut() {
        done(api, c);
        if unsafe { (api.error)(c) } == 0 && unsafe { (api.ret)(c) } == 4 {
            ok += 1;
        }
    }
    logln!(log, "completed {}", ok);
    let file = std::fs::read(&f.path).unwrap();
    let mut good = file.len() == n * 4;
    for i in 0..n {
        good &= file[i * 4..i * 4 + 4] == (i as u32).to_le_bytes();
    }
    logln!(log, "file correct {} len {}", good, file.len());
    // read them all back through lio_listio in one call
    let mut out: Vec<[u8; 4]> = vec![[0; 4]; n];
    let mut rcbs: Vec<Aiocb> = (0..n).map(|i| cb(f.fd, out[i].as_mut_ptr(), 4, (i * 4) as i64)).collect();
    for c in rcbs.iter_mut() {
        c.aio_lio_opcode = LIO_READ;
    }
    let list: Vec<*mut Aiocb> = rcbs.iter_mut().map(|c| c as *mut Aiocb).collect();
    let r = unsafe { (api.lio)(LIO_WAIT, list.as_ptr(), n as c_int, core::ptr::null_mut()) };
    logln!(log, "lio wait of {} reads -> {}", n, r);
    logln!(log, "read back correct {}", (0..n).all(|i| out[i] == (i as u32).to_le_bytes()));
    log
}

#[test]
fn a_thousand_small_requests() {
    let log = both(s_many);
    assert!(log.contains("completed 1000"), "{}", log);
    assert!(log.contains("file correct true len 4000"), "{}", log);
    assert!(log.contains("read back correct true"), "{}", log);
}

fn s_many_files(api: &Api) -> String {
    let mut log = String::new();
    // 30 files in parallel, 20 writes each: ordering holds per file and the workers are shared
    let files: Vec<TempFile> = (0..30).map(|_| TempFile::new()).collect();
    let mut data: Vec<Vec<[u8; 8]>> = (0..30).map(|f| (0..20).map(|i| ((f * 100 + i) as u64).to_le_bytes()).collect()).collect();
    let mut cbs: Vec<Vec<Aiocb>> = Vec::new();
    for f in 0..30 {
        cbs.push((0..20).map(|i| cb(files[f].fd, data[f][i].as_mut_ptr(), 8, (i * 8) as i64)).collect());
    }
    for f in 0..30 {
        for i in 0..20 {
            assert_eq!(unsafe { (api.write)(&mut cbs[f][i]) }, 0);
        }
    }
    let mut ok = 0;
    for f in 0..30 {
        for i in 0..20 {
            done(api, &mut cbs[f][i]);
            if unsafe { (api.error)(&cbs[f][i]) } == 0 {
                ok += 1;
            }
        }
    }
    logln!(log, "completed {}", ok);
    let mut good = true;
    for f in 0..30 {
        let file = std::fs::read(&files[f].path).unwrap();
        good &= file.len() == 160;
        for i in 0..20 {
            good &= file.get(i * 8..i * 8 + 8) == Some(&((f * 100 + i) as u64).to_le_bytes()[..]);
        }
    }
    logln!(log, "all files correct {}", good);
    log
}

#[test]
fn many_descriptors_share_the_workers() {
    let log = both(s_many_files);
    assert!(log.contains("completed 600"), "{}", log);
    assert!(log.contains("all files correct true"), "{}", log);
}

#[test]
fn aio_init_accepts_settings() {
    let _l = lock();
    // the idle time can always be changed; the thread count only before the first request (which
    // other tests may have made): either way the call must not disturb later requests
    let init = AioInit { aio_threads: 20, aio_num: 64, aio_idle_time: 1, ..AioInit::default() };
    unsafe { aio_init(&init) };
    let f = TempFile::new();
    let mut w = *b"init";
    let mut c = cb(f.fd, w.as_mut_ptr(), 4, 0);
    assert_eq!(unsafe { aio_write(&mut c) }, 0);
    assert!(done(&OURS, &mut c));
    assert_eq!(unsafe { aio_return(&mut c) }, 4);
}

#[test]
fn sixty_four_bit_names_are_the_same_functions() {
    let _l = lock();
    let f = TempFile::new();
    let mut w = *b"sixty-four";
    let mut c = cb(f.fd, w.as_mut_ptr(), 10, 0);
    let c64 = &mut c as *mut Aiocb as *mut Aiocb64;
    assert_eq!(unsafe { aio_write64(c64) }, 0);
    let l = [c64 as *const Aiocb64];
    assert_eq!(unsafe { aio_suspend64(l.as_ptr(), 1, &ts(5, 0)) }, 0);
    assert_eq!(unsafe { aio_error64(c64) }, 0);
    assert_eq!(unsafe { aio_return64(c64) }, 10);
    assert_eq!(unsafe { aio_cancel64(f.fd, c64) }, AIO_ALLDONE);
    let mut r = [0u8; 10];
    let mut c2 = cb(f.fd, r.as_mut_ptr(), 10, 0);
    let c264 = &mut c2 as *mut Aiocb as *mut Aiocb64;
    c2.aio_lio_opcode = LIO_READ;
    let list = [c264];
    assert_eq!(unsafe { lio_listio64(LIO_WAIT, list.as_ptr(), 1, core::ptr::null_mut()) }, 0);
    assert_eq!(&r, b"sixty-four");
    assert_eq!(unsafe { aio_fsync64(libc::O_SYNC, c264) }, 0);
    assert!(done(&OURS, &mut c2));
    assert_eq!(unsafe { aio_read64(c264) }, 0);
    assert!(done(&OURS, &mut c2));
}
