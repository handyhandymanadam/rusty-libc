use crate::notify::*;
use crate::sysv::Timespec;
use crate::kernel;
use crate::util::*;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::{RawMutex, futex_wake};
use rusty_libc_core::syscall::*;

#[allow(non_camel_case_types)]
pub type ssize_t = isize;

pub const LIO_READ: c_int = 0;
pub const LIO_WRITE: c_int = 1;
pub const LIO_NOP: c_int = 2;
pub const LIO_DSYNC: c_int = 3;
pub const LIO_SYNC: c_int = 4;
pub const LIO_WAIT: c_int = 0;
pub const LIO_NOWAIT: c_int = 1;
pub const AIO_CANCELED: c_int = 0;
pub const AIO_NOTCANCELED: c_int = 1;
pub const AIO_ALLDONE: c_int = 2;
pub const O_DSYNC: c_int = 0o10000;
pub const O_SYNC: c_int = 0o4010000;

const SYS_PREAD64: usize = 17;
const SYS_PWRITE64: usize = 18;
const SYS_FUTEX: usize = 202;
const SYS_RT_SIGQUEUEINFO: usize = 129;
const FUTEX_WAIT_BITSET_PRIVATE: usize = 9 | 128;
const SI_ASYNCIO: i32 = -4;
const WORKER_STACK: usize = 128 * 1024;
const ENTRIES_PER_ROW: usize = 32;

#[repr(C)]
pub struct Aiocb {
    pub aio_fildes: c_int,
    pub aio_lio_opcode: c_int,
    pub aio_reqprio: c_int,
    pub aio_buf: *mut c_void,
    pub aio_nbytes: usize,
    pub aio_sigevent: SigEvent,
    pub next_prio: *mut Aiocb,
    pub abs_prio: c_int,
    pub policy: c_int,
    pub error_code: c_int,
    pub return_value: isize,
    pub aio_offset: i64,
    pub glibc_reserved: [u8; 32],
}

#[repr(C)]
pub struct Aiocb64 {
    pub aio_fildes: c_int,
    pub aio_lio_opcode: c_int,
    pub aio_reqprio: c_int,
    pub aio_buf: *mut c_void,
    pub aio_nbytes: usize,
    pub aio_sigevent: SigEvent,
    pub next_prio: *mut Aiocb,
    pub abs_prio: c_int,
    pub policy: c_int,
    pub error_code: c_int,
    pub return_value: isize,
    pub aio_offset: i64,
    pub glibc_reserved: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AioInit {
    pub aio_threads: c_int,
    pub aio_num: c_int,
    pub aio_locks: c_int,
    pub aio_usedba: c_int,
    pub aio_debug: c_int,
    pub aio_numusers: c_int,
    pub aio_idle_time: c_int,
    pub aio_reserved: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<Aiocb>() == 168);
    assert!(core::mem::size_of::<Aiocb64>() == 168);
    assert!(core::mem::offset_of!(Aiocb, aio_buf) == 16);
    assert!(core::mem::offset_of!(Aiocb, aio_sigevent) == 32);
    assert!(core::mem::offset_of!(Aiocb, next_prio) == 96);
    assert!(core::mem::offset_of!(Aiocb, error_code) == 112);
    assert!(core::mem::offset_of!(Aiocb, return_value) == 120);
    assert!(core::mem::offset_of!(Aiocb, aio_offset) == 128);
    assert!(core::mem::size_of::<AioInit>() == 32);
};


#[derive(Clone, Copy, PartialEq, Eq)]
struct Cb(*mut Aiocb);

#[repr(transparent)]
#[derive(Clone, Copy)]
struct CbSlot(*const Aiocb);

impl CbSlot {
    #[inline(always)]
    fn get(self) -> Option<Cb> {
        (!self.0.is_null()).then_some(Cb(self.0.cast_mut()))
    }
}

macro_rules! cb_fields {
    ($($get:ident, $set:ident: $t:ty;)*) => {
        impl Cb {
            $(
                #[inline(always)]
                #[allow(dead_code)]
                fn $get(self) -> $t {
                    unsafe { (*self.0).$get }
                }
                #[inline(always)]
                #[allow(dead_code)]
                fn $set(self, v: $t) {
                    unsafe { (*self.0).$get = v }
                }
            )*
        }
    };
}

cb_fields! {
    aio_fildes, set_aio_fildes: c_int;
    aio_lio_opcode, set_aio_lio_opcode: c_int;
    aio_reqprio, set_aio_reqprio: c_int;
    aio_buf, set_aio_buf: *mut c_void;
    aio_nbytes, set_aio_nbytes: usize;
    aio_sigevent, set_aio_sigevent: SigEvent;
    abs_prio, set_abs_prio: c_int;
    policy, set_policy: c_int;
    aio_offset, set_aio_offset: i64;
}

impl Cb {
    #[inline(always)]
    unsafe fn new(p: *mut Aiocb) -> Cb {
        Cb(p)
    }

    #[inline(always)]
    fn error_ptr(self) -> *mut c_int {
        self.0.wrapping_byte_add(core::mem::offset_of!(Aiocb, error_code)).cast()
    }

    #[inline(always)]
    fn ret_ptr(self) -> *mut isize {
        self.0.wrapping_byte_add(core::mem::offset_of!(Aiocb, return_value)).cast()
    }

    #[inline(always)]
    fn error(self) -> c_int {
        unsafe { self.error_ptr().read_volatile() }
    }

    #[inline(always)]
    fn set_error(self, e: c_int) {
        unsafe { self.error_ptr().write_volatile(e) }
    }

    #[inline(always)]
    fn ret(self) -> isize {
        unsafe { self.ret_ptr().read_volatile() }
    }

    #[inline(always)]
    fn set_ret(self, v: isize) {
        unsafe { self.ret_ptr().write_volatile(v) }
    }

    #[inline(always)]
    fn finish(self, ret: isize, err: c_int) {
        self.set_ret(ret);
        self.set_error(err);
    }
}

const FREE: u8 = 0;
const READY: u8 = 1;
const RUNNING: u8 = 2;
const QUEUED: u8 = 3;

mod tables {
    use super::{AtomicI32, AtomicU32, Cb, ENTRIES_PER_ROW, FREE, Ordering, READY, RawMutex, SigEvent, c_int, c_void};
    use core::marker::PhantomData;
    use core::ptr::NonNull;
    use rusty_libc_core::sync_cell::SyncCell;

    static LOCK: RawMutex = RawMutex::new();

    pub(super) struct Req {
        job: Job,
        state: u8,
        prio: c_int,
        next: Option<ReqRef>,
        fd_next: Option<ReqRef>,
        fd_prev: Option<ReqRef>,
        run_next: Option<ReqRef>,
        waiters: Option<WaitRef>,
    }

    impl Req {
        const EMPTY: Req = Req {
            job: Job { cb: Cb(core::ptr::null_mut()), fd: 0, op: 0 },
            state: FREE,
            prio: 0,
            next: None,
            fd_next: None,
            fd_prev: None,
            run_next: None,
            waiters: None,
        };
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct ReqRef(NonNull<Req>);

    #[derive(Clone, Copy)]
    pub(super) struct Job {
        pub(super) cb: Cb,
        pub(super) fd: c_int,
        pub(super) op: c_int,
    }

    impl ReqRef {
        pub(super) unsafe fn job(self) -> Job {
            unsafe { (*self.0.as_ptr()).job }
        }

        pub(super) fn as_arg(self) -> *mut c_void {
            self.0.as_ptr().cast()
        }

        pub(super) fn from_arg(arg: *mut c_void) -> Option<ReqRef> {
            NonNull::new(arg.cast::<Req>()).map(ReqRef)
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Wait {
        next: Option<WaitRef>,
        counter: *const AtomicU32,
        seq: *const AtomicU32,
        result: *const AtomicI32,
        sigev: *const SigEvent,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct WaitRef(NonNull<Wait>);

    #[repr(C)]
    pub(super) struct AsyncList {
        counter: AtomicU32,
        sigev: SigEvent,
    }

    pub(super) struct State {
        fds: Option<ReqRef>,
        run_head: Option<ReqRef>,
        run_tail: Option<ReqRef>,
        freelist: Option<ReqRef>,
        pub(super) nthreads: c_int,
        pub(super) idle: c_int,
        pub(super) max_threads: c_int,
        pub(super) idle_time: c_int,
        pub(super) num: c_int,
        pub(super) pool_used: bool,
    }

    static ST: SyncCell<State> = SyncCell::new(State {
        fds: None,
        run_head: None,
        run_tail: None,
        freelist: None,
        nthreads: 0,
        idle: 0,
        max_threads: 20,
        idle_time: 1,
        num: 64,
        pool_used: false,
    });

    pub(super) struct Tables(PhantomData<*const ()>);

    impl Tables {
        #[inline]
        pub(super) fn lock() -> Tables {
            LOCK.lock_always();
            Tables(PhantomData)
        }

        #[inline(always)]
        pub(super) fn st(&mut self) -> &mut State {
            unsafe { &mut *ST.as_ptr() }
        }

        #[inline]
        pub(super) fn unlocked<R>(&mut self, f: impl FnOnce() -> R) -> R {
            LOCK.unlock_always();
            let r = f();
            LOCK.lock_always();
            r
        }
    }

    impl Drop for Tables {
        #[inline]
        fn drop(&mut self) {
            LOCK.unlock_always();
        }
    }

    pub(super) unsafe extern "C" fn fork_prepare() {
        LOCK.lock_always();
    }
    pub(super) unsafe extern "C" fn fork_parent() {
        LOCK.unlock_always();
    }
    pub(super) unsafe extern "C" fn fork_child() {
        unsafe {
            ST.with_unsync(|s| {
                s.nthreads = 0;
                s.idle = 0;
                s.fds = None;
                s.run_head = None;
                s.run_tail = None;
            })
        };
        LOCK.unlock_always();
    }

    macro_rules! req_fields {
        ($($get:ident, $set:ident: $t:ty;)*) => {
            impl State {
                $(
                    #[inline(always)]
                    #[allow(dead_code)]
                    pub(super) fn $get(&self, r: ReqRef) -> $t {
                        unsafe { (*r.0.as_ptr()).$get }
                    }
                    #[inline(always)]
                    #[allow(dead_code)]
                    pub(super) fn $set(&mut self, r: ReqRef, v: $t) {
                        unsafe { (*r.0.as_ptr()).$get = v }
                    }
                )*
            }
        };
    }

    req_fields! {
        job, set_job: Job;
        state, set_state: u8;
        prio, set_prio: c_int;
        next, set_next: Option<ReqRef>;
        fd_next, set_fd_next: Option<ReqRef>;
        fd_prev, set_fd_prev: Option<ReqRef>;
        run_next, set_run_next: Option<ReqRef>;
        waiters, set_waiters: Option<WaitRef>;
    }

    impl State {
        pub(super) fn get_elem(&mut self) -> Option<ReqRef> {
            if self.freelist.is_none() {
                let n = if self.pool_used { ENTRIES_PER_ROW } else { self.num.max(ENTRIES_PER_ROW as c_int) as usize };
                let row = crate::util::malloc(n * core::mem::size_of::<Req>()).cast::<Req>();
                if row.is_null() {
                    return None;
                }
                self.pool_used = true;
                for i in 0..n {
                    let e = row.wrapping_add(i);
                    unsafe { e.write(Req { next: self.freelist, ..Req::EMPTY }) };
                    self.freelist = NonNull::new(e).map(ReqRef);
                }
            }
            let r = self.freelist?;
            self.freelist = self.next(r);
            unsafe { r.0.as_ptr().write(Req::EMPTY) };
            Some(r)
        }

        pub(super) fn free_req(&mut self, r: ReqRef) {
            self.set_state(r, FREE);
            self.set_waiters(r, None);
            self.set_next(r, self.freelist);
            self.freelist = Some(r);
        }

        pub(super) fn find_head(&self, fd: c_int) -> Option<ReqRef> {
            let mut r = self.fds;
            while let Some(x) = r {
                if self.job(x).fd == fd {
                    break;
                }
                r = self.fd_next(x);
            }
            r
        }

        pub(super) fn find_req(&self, cb: Cb) -> Option<ReqRef> {
            let mut r = self.find_head(cb.aio_fildes());
            while let Some(x) = r {
                if self.job(x).cb == cb {
                    break;
                }
                r = self.next(x);
            }
            r
        }

        pub(super) fn push_fd(&mut self, r: ReqRef) {
            self.set_fd_prev(r, None);
            self.set_fd_next(r, self.fds);
            if let Some(f) = self.fds {
                self.set_fd_prev(f, Some(r));
            }
            self.fds = Some(r);
        }

        pub(super) fn push_run(&mut self, r: ReqRef) {
            self.set_run_next(r, None);
            match self.run_tail {
                None => self.run_head = Some(r),
                Some(t) => self.set_run_next(t, Some(r)),
            }
            self.run_tail = Some(r);
        }

        pub(super) fn pop_run(&mut self) -> Option<ReqRef> {
            let r = self.run_head;
            if let Some(x) = r {
                self.run_head = self.run_next(x);
                if self.run_head.is_none() {
                    self.run_tail = None;
                }
            }
            r
        }

        pub(super) fn run_list_empty(&self) -> bool {
            self.run_head.is_none()
        }

        pub(super) fn remove_run(&mut self, r: ReqRef) {
            let mut prev = None;
            let mut p = self.run_head;
            while let Some(x) = p {
                if x == r {
                    break;
                }
                prev = p;
                p = self.run_next(x);
            }
            if p.is_none() {
                return;
            }
            match prev {
                None => self.run_head = self.run_next(r),
                Some(q) => self.set_run_next(q, self.run_next(r)),
            }
            if self.run_tail == Some(r) {
                self.run_tail = prev;
            }
        }

        pub(super) fn unlink_head(&mut self, r: ReqRef, promote: bool) {
            let n = if promote { self.next(r) } else { None };
            let (prev, next) = (self.fd_prev(r), self.fd_next(r));
            let repl = if let Some(n) = n {
                self.set_fd_prev(n, prev);
                self.set_fd_next(n, next);
                Some(n)
            } else {
                next
            };
            match prev {
                None => self.fds = repl,
                Some(p) => self.set_fd_next(p, repl),
            }
            if let Some(x) = next {
                self.set_fd_prev(x, if n.is_some() { n } else { prev });
            }
            if let Some(n) = n {
                self.set_state(n, READY);
                self.push_run(n);
            }
        }

        #[inline(always)]
        fn wait(&self, w: WaitRef) -> Wait {
            unsafe { w.0.as_ptr().read() }
        }

        #[inline(always)]
        fn set_wait_next(&mut self, w: WaitRef, v: Option<WaitRef>) {
            unsafe { (*w.0.as_ptr()).next = v }
        }

        unsafe fn register(&mut self, r: ReqRef, w: WaitRef, counter: &AtomicU32, seq: Option<&AtomicU32>, result: Option<&AtomicI32>, sigev: *const SigEvent) {
            let rec = Wait {
                next: self.waiters(r),
                counter,
                seq: seq.map_or(core::ptr::null(), |s| s as *const AtomicU32),
                result: result.map_or(core::ptr::null(), |s| s as *const AtomicI32),
                sigev,
            };
            unsafe { w.0.as_ptr().write(rec) };
            self.set_waiters(r, Some(w));
        }

        pub(super) fn complete_waiters(&mut self, r: ReqRef, failed: bool, notify_only: fn(&SigEvent) -> c_int) {
            let mut w = self.waiters(r);
            self.set_waiters(r, None);
            while let Some(wr) = w {
                let rec = self.wait(wr);
                let counter = unsafe { &*rec.counter };
                if rec.sigev.is_null() {
                    if failed && !rec.result.is_null() {
                        unsafe { (*rec.result).store(-1, Ordering::Relaxed) };
                    }
                    counter.store(counter.load(Ordering::Relaxed).wrapping_sub(1), Ordering::Relaxed);
                    if !rec.seq.is_null() {
                        let seq = unsafe { &*rec.seq };
                        seq.fetch_add(1, Ordering::SeqCst);
                        rusty_libc_core::lock::futex_wake(seq, 1);
                    }
                } else {
                    let left = counter.load(Ordering::Relaxed).wrapping_sub(1);
                    counter.store(left, Ordering::Relaxed);
                    if left == 0 {
                        notify_only(unsafe { &*rec.sigev });
                        unsafe { rusty_libc_malloc::free(rec.counter.cast_mut().cast()) };
                    }
                }
                w = rec.next;
            }
        }

        pub(super) fn unregister(&mut self, blk: &WaitBlock, cbs: &[super::CbSlot]) {
            for i in 0..blk.n {
                let Some(req) = blk.reg(i) else { continue };
                let Some(cb) = cbs[i].get() else { continue };
                if cb.error() != super::EINPROGRESS {
                    continue;
                }
                let me = blk.wait(i);
                let mut prev: Option<WaitRef> = None;
                let mut cur = self.waiters(req);
                while let Some(c) = cur {
                    if c == me {
                        break;
                    }
                    prev = cur;
                    cur = self.wait(c).next;
                }
                if let Some(c) = cur {
                    let nx = self.wait(c).next;
                    match prev {
                        None => self.set_waiters(req, nx),
                        Some(p) => self.set_wait_next(p, nx),
                    }
                }
            }
        }

        pub(super) unsafe fn register_waiter(&mut self, r: ReqRef, blk: &mut WaitBlock, i: usize, counter: &AtomicU32, seq: &AtomicU32, result: Option<&AtomicI32>) {
            blk.set_reg(i, Some(r));
            let w = blk.wait(i);
            unsafe { self.register(r, w, counter, Some(seq), result, core::ptr::null()) };
        }

        pub(super) fn register_async(&mut self, reqs: &WaitBlock, sig: &SigEvent) -> bool {
            let n = reqs.n;
            let al = crate::util::malloc(core::mem::size_of::<AsyncList>() + n * core::mem::size_of::<Wait>()).cast::<AsyncList>();
            if al.is_null() {
                return false;
            }
            unsafe { al.write(AsyncList { counter: AtomicU32::new(0), sigev: *sig }) };
            let list = unsafe { &*al };
            let aw = al.wrapping_add(1).cast::<Wait>();
            let mut cnt = 0;
            for i in 0..n {
                if let Some(r) = reqs.reg(i) {
                    let w = WaitRef(NonNull::new(aw.wrapping_add(i)).expect("record in block"));
                    unsafe { self.register(r, w, &list.counter, None, None, &raw const list.sigev) };
                    cnt += 1;
                }
            }
            list.counter.store(cnt, Ordering::Relaxed);
            true
        }
    }

    pub(super) struct WaitBlock {
        mem: NonNull<u8>,
        n: usize,
    }

    impl WaitBlock {
        pub(super) fn new(n: usize) -> Option<WaitBlock> {
            let size = n.max(1) * (core::mem::size_of::<Wait>() + core::mem::size_of::<Option<ReqRef>>());
            let mem = NonNull::new(crate::util::malloc(size).cast::<u8>())?;
            let b = WaitBlock { mem, n };
            for i in 0..n {
                b.write_reg(i, None);
            }
            Some(b)
        }

        pub(super) fn len(&self) -> usize {
            self.n
        }

        fn wait(&self, i: usize) -> WaitRef {
            assert!(i < self.n);
            WaitRef(NonNull::new(self.mem.as_ptr().cast::<Wait>().wrapping_add(i)).expect("record in block"))
        }

        fn reg_ptr(&self, i: usize) -> *mut Option<ReqRef> {
            assert!(i < self.n);
            self.mem.as_ptr().cast::<Wait>().wrapping_add(self.n).cast::<Option<ReqRef>>().wrapping_add(i)
        }

        fn write_reg(&self, i: usize, v: Option<ReqRef>) {
            unsafe { self.reg_ptr(i).write(v) }
        }

        pub(super) fn reg(&self, i: usize) -> Option<ReqRef> {
            unsafe { self.reg_ptr(i).read() }
        }

        pub(super) fn set_reg(&mut self, i: usize, v: Option<ReqRef>) {
            self.write_reg(i, v);
        }

        pub(super) fn as_raw(&self) -> *mut c_void {
            self.mem.as_ptr().cast()
        }

        pub(super) fn release(self) {
            unsafe { rusty_libc_malloc::free(self.as_raw()) };
        }

        pub(super) unsafe fn release_raw(p: *mut c_void) {
            unsafe { rusty_libc_malloc::free(p) };
        }
    }
}

use tables::{Job, ReqRef, State, Tables, WaitBlock};

static IDLE_SEQ: AtomicU32 = AtomicU32::new(0);
static HOOKED: AtomicBool = AtomicBool::new(false);

fn wake_idle() {
    IDLE_SEQ.fetch_add(1, Ordering::SeqCst);
    futex_wake(&IDLE_SEQ, 1);
}

struct NotifyJob {
    func: Option<unsafe extern "C" fn(SigVal)>,
    value: SigVal,
}

unsafe extern "C" fn notify_wrapper(arg: *mut c_void) -> *mut c_void {
    unblock_all();
    let j = unsafe { heap_take(arg.cast::<NotifyJob>()) };
    if let Some(f) = j.func {
        unsafe { f(j.value) };
    }
    core::ptr::null_mut()
}

fn notify_only(ev: &SigEvent) -> c_int {
    if ev.sigev_notify == SIGEV_THREAD {
        let nf = heap_box(NotifyJob { func: ev.sigev_notify_function, value: ev.sigev_value });
        if nf.is_null() {
            errno::set(ENOMEM);
            return -1;
        }
        let r = unsafe { spawn(notify_wrapper, nf.cast(), ev.sigev_notify_attributes, 0) };
        if r != 0 {
            unsafe { heap_free(nf) };
            errno::set(r);
            return -1;
        }
        0
    } else if ev.sigev_notify == SIGEV_SIGNAL {
        let pid = rusty_libc_core::unistd::getpid();
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&ev.sigev_signo.to_ne_bytes());
        info[8..12].copy_from_slice(&SI_ASYNCIO.to_ne_bytes());
        info[16..20].copy_from_slice(&pid.to_ne_bytes());
        let uid = rusty_libc_core::unistd::getuid();
        info[20..24].copy_from_slice(&uid.to_ne_bytes());
        let v = unsafe { ev.sigev_value.sival_ptr } as usize;
        info[24..32].copy_from_slice(&v.to_ne_bytes());
        sci(unsafe { syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, ev.sigev_signo as usize, info.as_ptr() as usize) })
    } else {
        0
    }
}

fn notify(s: &mut State, r: ReqRef) {
    let cb = s.job(r).cb;
    if notify_only(&cb.aio_sigevent()) != 0 {
        cb.set_error(errno::get());
        cb.set_ret(-1);
    }
    s.complete_waiters(r, cb.ret() == -1, notify_only);
}

fn do_io(job: Job) -> (isize, c_int) {
    let cb = job.cb;
    let fd = job.fd as usize;
    loop {
        let ret = match job.op {
            LIO_READ | LIO_WRITE => {
                let (pnr, nr) = if job.op == LIO_READ { (SYS_PREAD64, SYS_READ) } else { (SYS_PWRITE64, SYS_WRITE) };
                let (buf, n) = (cb.aio_buf() as usize, cb.aio_nbytes());
                let mut x = unsafe { syscall4(pnr, fd, buf, n, cb.aio_offset() as usize) };
                if x as isize == -(ESPIPE as isize) {
                    cb.set_ret(-1);
                    x = unsafe { syscall3(nr, fd, buf, n) };
                }
                x
            }
            LIO_DSYNC => kernel::fdatasync(fd),
            LIO_SYNC => kernel::fsync(fd),
            _ => return (-1, EINVAL),
        };
        if ret > usize::MAX - 4095 {
            let e = (ret as isize).wrapping_neg() as c_int;
            if e == EINTR {
                continue;
            }
            return (-1, e);
        }
        return (ret as isize, 0);
    }
}

fn spawn_worker(first: Option<ReqRef>) -> c_int {
    let arg = first.map_or(core::ptr::null_mut(), ReqRef::as_arg);
    with_signals_blocked(|| unsafe { spawn(worker, arg, core::ptr::null(), WORKER_STACK) })
}

unsafe extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    let mut r = ReqRef::from_arg(arg);
    loop {
        let mut t = match r {
            Some(rr) => {
                let job = unsafe { rr.job() };
                let (ret, err) = do_io(job);
                let mut t = Tables::lock();
                let s = t.st();
                job.cb.finish(ret, if ret == -1 { err } else { 0 });
                notify(s, rr);
                s.unlink_head(rr, true);
                s.free_req(rr);
                t
            }
            None => Tables::lock(),
        };
        let s = t.st();
        let mut next = s.pop_run();
        if next.is_none() && s.idle_time >= 0 {
            s.idle += 1;
            let seq = IDLE_SEQ.load(Ordering::SeqCst);
            let ns = s.idle_time as u64 * 1_000_000_000;
            t.unlocked(|| rusty_libc_core::lock::futex_wait_timeout(&IDLE_SEQ, seq, ns));
            let s = t.st();
            s.idle -= 1;
            next = s.pop_run();
        }
        let s = t.st();
        let Some(n) = next else {
            s.nthreads -= 1;
            drop(t);
            return core::ptr::null_mut();
        };
        s.set_state(n, RUNNING);
        if !s.run_list_empty() {
            if s.idle > 0 {
                wake_idle();
            } else if s.nthreads < s.max_threads && spawn_worker(None) == 0 {
                s.nthreads += 1;
            }
        }
        drop(t);
        r = next;
    }
}

fn enqueue_locked(s: &mut State, cb: Cb, op: c_int) -> Option<ReqRef> {
    if op == LIO_SYNC || op == LIO_DSYNC {
        cb.set_aio_reqprio(0);
    } else if cb.aio_reqprio() < 0 {
        cb.set_error(EINVAL);
        cb.set_ret(-1);
        errno::set(EINVAL);
        return None;
    }
    let prio = -cb.aio_reqprio();
    if !HOOKED.swap(true, Ordering::AcqRel) {
        rusty_libc_core::process::register_fork_handlers(tables::fork_prepare, tables::fork_parent, tables::fork_child);
    }
    let Some(newp) = s.get_elem() else {
        errno::set(EAGAIN);
        return None;
    };
    s.set_job(newp, Job { cb, fd: cb.aio_fildes(), op });
    s.set_prio(newp, prio);
    cb.set_abs_prio(prio);
    cb.set_policy(0);
    cb.set_aio_lio_opcode(op);
    cb.set_error(EINPROGRESS);
    cb.set_ret(0);
    if let Some(head) = s.find_head(s.job(newp).fd) {
        let mut p = head;
        while let Some(q) = s.next(p) {
            if s.prio(q) < prio {
                break;
            }
            p = q;
        }
        s.set_next(newp, s.next(p));
        s.set_next(p, Some(newp));
        s.set_state(newp, QUEUED);
        return Some(newp);
    }
    s.push_fd(newp);
    if s.nthreads < s.max_threads && s.idle == 0 {
        s.set_state(newp, RUNNING);
        let r = spawn_worker(Some(newp));
        if r == 0 {
            s.nthreads += 1;
            return Some(newp);
        }
        s.set_state(newp, READY);
        if s.nthreads == 0 {
            s.unlink_head(newp, false);
            s.free_req(newp);
            cb.set_error(r);
            errno::set(r);
            return None;
        }
    } else {
        s.set_state(newp, READY);
    }
    s.push_run(newp);
    if s.idle > 0 {
        wake_idle();
    }
    Some(newp)
}

fn enqueue(cb: Cb, op: c_int) -> c_int {
    let mut t = Tables::lock();
    let r = enqueue_locked(t.st(), cb, op);
    drop(t);
    if r.is_none() { -1 } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read(cb: *mut Aiocb) -> c_int {
    enqueue(unsafe { Cb::new(cb) }, LIO_READ)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read64(cb: *mut Aiocb64) -> c_int {
    enqueue(unsafe { Cb::new(cb.cast()) }, LIO_READ)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write(cb: *mut Aiocb) -> c_int {
    enqueue(unsafe { Cb::new(cb) }, LIO_WRITE)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write64(cb: *mut Aiocb64) -> c_int {
    enqueue(unsafe { Cb::new(cb.cast()) }, LIO_WRITE)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync(op: c_int, cb: *mut Aiocb) -> c_int {
    if op != O_DSYNC && op != O_SYNC {
        return fail(EINVAL);
    }
    let cb = unsafe { Cb::new(cb) };
    if sci(kernel::fcntl_getfl(cb.aio_fildes() as usize)) == -1 {
        return fail(EBADF);
    }
    enqueue(cb, if op == O_SYNC { LIO_SYNC } else { LIO_DSYNC })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync64(op: c_int, cb: *mut Aiocb64) -> c_int {
    unsafe { aio_fsync(op, cb.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error(cb: *const Aiocb) -> c_int {
    let cb = unsafe { Cb::new(cb.cast_mut()) };
    let t = Tables::lock();
    let e = cb.error();
    drop(t);
    e
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error64(cb: *const Aiocb64) -> c_int {
    unsafe { aio_error(cb.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return(cb: *mut Aiocb) -> ssize_t {
    unsafe { Cb::new(cb) }.ret()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return64(cb: *mut Aiocb64) -> ssize_t {
    unsafe { aio_return(cb.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel(fildes: c_int, cb: *mut Aiocb) -> c_int {
    if sci(kernel::fcntl_getfl(fildes as usize)) == -1 {
        return fail(EBADF);
    }
    let cb = (!cb.is_null()).then(|| unsafe { Cb::new(cb) });
    let mut t = Tables::lock();
    match cancel_locked(t.st(), fildes, cb) {
        Ok(r) => r,
        Err(e) => {
            drop(t);
            fail(e)
        }
    }
}

fn cancel_locked(s: &mut State, fildes: c_int, cb: Option<Cb>) -> Result<c_int, c_int> {
    let mut result = AIO_ALLDONE;
    let mut dead: Option<ReqRef> = None;
    if let Some(cb) = cb {
        if cb.aio_fildes() != fildes {
            return Err(EINVAL);
        } else if cb.error() == EINPROGRESS {
            let head = s.find_head(fildes).ok_or(EINVAL)?;
            let mut prev: Option<ReqRef> = None;
            let mut req = head;
            while s.job(req).cb != cb {
                prev = Some(req);
                req = s.next(req).ok_or(EINVAL)?;
            }
            if s.state(req) == RUNNING {
                result = AIO_NOTCANCELED;
            } else {
                match prev {
                    None => {
                        s.remove_run(req);
                        s.unlink_head(req, true);
                    }
                    Some(p) => s.set_next(p, s.next(req)),
                }
                s.set_next(req, None);
                result = AIO_CANCELED;
                dead = Some(req);
            }
        }
    } else if let Some(head) = s.find_head(fildes) {
        if s.state(head) == RUNNING {
            result = AIO_NOTCANCELED;
            dead = s.next(head);
            s.set_next(head, None);
        } else {
            result = AIO_CANCELED;
            s.remove_run(head);
            s.unlink_head(head, false);
            dead = Some(head);
        }
    }
    while let Some(r) = dead {
        dead = s.next(r);
        let c = s.job(r).cb;
        c.set_error(ECANCELED);
        c.set_ret(-1);
        notify(s, r);
        s.free_req(r);
    }
    Ok(result)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel64(fildes: c_int, cb: *mut Aiocb64) -> c_int {
    unsafe { aio_cancel(fildes, cb.cast()) }
}

fn mono_now() -> Timespec {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(1, (&raw mut ts).cast()) };
    ts
}

struct SuspendCtx<'a> {
    cbs: &'a [CbSlot],
    blk: &'a WaitBlock,
}

unsafe extern "C" fn suspend_cleanup(arg: *mut c_void) {
    let c = unsafe { &*arg.cast::<SuspendCtx>() };
    let mut t = Tables::lock();
    t.st().unregister(c.blk, c.cbs);
    drop(t);
    unsafe { WaitBlock::release_raw(c.blk.as_raw()) };
}

fn suspend_wait(seq: &AtomicU32, s: u32, abs: Option<&Timespec>) -> c_int {
    let tp = abs.map_or(0, |a| a as *const Timespec as usize);
    let r = unsafe { rusty_libc_core::tls::syscall_cp(SYS_FUTEX, seq as *const AtomicU32 as usize, FUTEX_WAIT_BITSET_PRIVATE, s as usize, tp, 0, 0xffff_ffff) };
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend(list: *const *const Aiocb, nent: c_int, timeout: *const Timespec) -> c_int {
    if nent < 0 {
        return fail(EINVAL);
    }
    let n = nent as usize;
    if n == 0 {
        return 0;
    }
    let cbs = unsafe { rusty_libc_core::ffi::slice(list.cast::<CbSlot>(), n) };
    let timeout = unsafe { timeout.as_ref() };
    match suspend(cbs, timeout) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

fn suspend(cbs: &[CbSlot], timeout: Option<&Timespec>) -> Result<(), c_int> {
    let n = cbs.len();
    let Some(mut blk) = WaitBlock::new(n) else { return Err(EAGAIN) };
    let seq = AtomicU32::new(0);
    let counter = AtomicU32::new(1);
    let mut result = 0;
    let mut t = Tables::lock();
    let s = t.st();
    let mut stop = false;
    let mut any = false;
    for (i, slot) in cbs.iter().enumerate() {
        let Some(cb) = slot.get() else { continue };
        if cb.error() != EINPROGRESS {
            stop = true;
            break;
        }
        let Some(req) = s.find_req(cb) else {
            stop = true;
            break;
        };
        unsafe { s.register_waiter(req, &mut blk, i, &counter, &seq, None) };
        any = true;
    }
    if !stop && any {
        let mut abs = Timespec { tv_sec: 0, tv_nsec: 0 };
        if let Some(to) = timeout {
            abs = mono_now();
            abs.tv_sec += to.tv_sec;
            abs.tv_nsec += to.tv_nsec;
            if abs.tv_nsec >= 1_000_000_000 {
                abs.tv_nsec -= 1_000_000_000;
                abs.tv_sec += 1;
            }
        }
        let sv = seq.load(Ordering::SeqCst);
        let ctx = SuspendCtx { cbs, blk: &blk };
        let r = t.unlocked(|| {
            run_cancellable(&ctx, || {
                if timeout.is_some() && abs.tv_sec < 0 {
                    return ETIMEDOUT;
                }
                suspend_wait(&seq, sv, timeout.is_some().then_some(&abs))
            })
        });
        result = match r {
            ETIMEDOUT => EAGAIN,
            EINVAL => EINVAL,
            EINTR => EINTR,
            _ => 0,
        };
    }
    t.st().unregister(&blk, cbs);
    drop(t);
    blk.release();
    if result != 0 { Err(result) } else { Ok(()) }
}

fn run_cancellable(ctx: &SuspendCtx, body: impl FnOnce() -> c_int) -> c_int {
    unsafe { rusty_libc_pthread::cancel::with_cleanup(suspend_cleanup, (ctx as *const SuspendCtx).cast_mut().cast(), body) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend64(list: *const *const Aiocb64, nent: c_int, timeout: *const Timespec) -> c_int {
    unsafe { aio_suspend(list.cast(), nent, timeout) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe { lio_listio_impl(mode, list, nent, sig) }
}

pub unsafe fn lio_listio_old(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        return fail(EINVAL);
    }
    unsafe { lio_listio_impl(LIO_NOWAIT, list, nent, sig) }
}

unsafe fn lio_listio_impl(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        return fail(EINVAL);
    }
    let n = if nent < 0 { 0 } else { nent as usize };
    let cbs = unsafe { rusty_libc_core::ffi::slice(list.cast::<CbSlot>(), n) };
    let sig = unsafe { sig.as_ref() }.copied().unwrap_or(SigEvent::none());
    listio(mode, cbs, &sig)
}

fn listio(mode: c_int, cbs: &[CbSlot], sig: &SigEvent) -> c_int {
    let n = cbs.len();
    let Some(mut blk) = WaitBlock::new(n) else { return fail(EAGAIN) };
    let result = AtomicI32::new(0);
    let mut total: u32 = 0;
    let mut t = Tables::lock();
    let s = t.st();
    for (i, slot) in cbs.iter().enumerate() {
        let Some(cb) = slot.get() else { continue };
        if cb.aio_lio_opcode() != LIO_NOP {
            match enqueue_locked(s, cb, cb.aio_lio_opcode()) {
                None => result.store(-1, Ordering::Relaxed),
                Some(r) => {
                    blk.set_reg(i, Some(r));
                    total += 1;
                }
            }
        }
    }
    if total == 0 {
        drop(t);
        if mode == LIO_NOWAIT {
            notify_only(sig);
        }
        blk.release();
        return result.load(Ordering::Relaxed);
    }
    if mode == LIO_WAIT {
        let seq = AtomicU32::new(0);
        let total = AtomicU32::new(0);
        for i in 0..blk.len() {
            if let Some(r) = blk.reg(i) {
                unsafe { s.register_waiter(r, &mut blk, i, &total, &seq, Some(&result)) };
                total.store(total.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
            }
        }
        let mut interrupted = false;
        while total.load(Ordering::Relaxed) > 0 {
            let sv = seq.load(Ordering::SeqCst);
            let r = t.unlocked(|| kernel::futex_wait(&seq, sv));
            if r as isize == -(EINTR as isize) {
                interrupted = true;
                break;
            }
        }
        if interrupted {
            t.st().unregister(&blk, cbs);
            errno::set(EINTR);
            result.store(-1, Ordering::Relaxed);
        } else if result.load(Ordering::Relaxed) != 0 {
            errno::set(EIO);
            result.store(-1, Ordering::Relaxed);
        }
    } else if !s.register_async(&blk, sig) {
        errno::set(EAGAIN);
        result.store(-1, Ordering::Relaxed);
    }
    drop(t);
    blk.release();
    result.load(Ordering::Relaxed)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio64(mode: c_int, list: *const *mut Aiocb64, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe { lio_listio(mode, list.cast(), nent, sig) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_init(init: *const AioInit) {
    let init = unsafe { *init };
    let mut t = Tables::lock();
    let s = t.st();
    if !s.pool_used {
        s.max_threads = if init.aio_threads < 1 { 1 } else { init.aio_threads };
        s.num = if (init.aio_num as usize) < ENTRIES_PER_ROW { ENTRIES_PER_ROW as c_int } else { init.aio_num & !(ENTRIES_PER_ROW as c_int - 1) };
    }
    if init.aio_idle_time != 0 {
        s.idle_time = init.aio_idle_time;
    }
}
