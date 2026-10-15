#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::gai::getaddrinfo;
use crate::types::*;
use core::cell::Cell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
use rusty_libc_core::errno;
use crate::netdb::{CIn, OptRef, Slice};
use rusty_libc_core::ffi;
use rusty_libc_core::syscall::{syscall3, syscall4};
use rusty_libc_ipc::notify::{SigEvent, SigVal, spawn, unblock_all};

pub const GAI_WAIT: c_int = 0;
pub const GAI_NOWAIT: c_int = 1;
const SIGEV_SIGNAL: c_int = 0;
const SIGEV_THREAD: c_int = 2;
const SI_ASYNCNL: i32 = -60;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const ETIMEDOUT: i32 = 110;

#[repr(C)]
pub struct Gaicb {
    pub ar_name: *const c_char,
    pub ar_service: *const c_char,
    pub ar_request: *const addrinfo,
    pub ar_result: *mut addrinfo,
    pub __return: c_int,
    pub __glibc_reserved: [c_int; 5],
}
const _: () = assert!(size_of::<Gaicb>() == 56);

struct Requestlist {
    running: Cell<bool>,
    next: Cell<*mut Requestlist>,
    gaicbp: *mut Gaicb,
    waiting: Cell<*mut Waitlist>,
}

#[repr(C)]
struct AsyncWaitlist {
    counter: u32,
    sigev: SigEvent,
}

const MAX_THREADS: i32 = 20;
const IDLE_SECONDS: i64 = 1;

static OWNER: AtomicI32 = AtomicI32::new(0);
static DEPTH: AtomicU32 = AtomicU32::new(0);
static REQUESTS: AtomicPtr<Requestlist> = AtomicPtr::new(null_mut());
static REQUESTS_TAIL: AtomicPtr<Requestlist> = AtomicPtr::new(null_mut());
static NTHREADS: AtomicI32 = AtomicI32::new(0);
static IDLE_THREADS: AtomicI32 = AtomicI32::new(0);
static NEW_REQUEST: AtomicU32 = AtomicU32::new(0);

static MUTEX: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

fn lock() {
    let me = rusty_libc_core::tls::current_tid();
    if OWNER.load(Ordering::Relaxed) == me {
        DEPTH.store(DEPTH.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        return;
    }
    MUTEX.lock_always();
    OWNER.store(me, Ordering::Relaxed);
    DEPTH.store(1, Ordering::Relaxed);
}

fn unlock() {
    let d = DEPTH.load(Ordering::Relaxed) - 1;
    DEPTH.store(d, Ordering::Relaxed);
    if d == 0 {
        OWNER.store(0, Ordering::Relaxed);
        MUTEX.unlock_always();
    }
}

fn get(a: &AtomicPtr<Requestlist>) -> Req {
    Req(a.load(Ordering::Relaxed))
}
fn put(a: &AtomicPtr<Requestlist>, r: Req) {
    a.store(r.0, Ordering::Relaxed);
}
fn add(a: &AtomicI32, d: i32) {
    a.store(a.load(Ordering::Relaxed) + d, Ordering::Relaxed);
}

const FUTEX_WAIT_PRIVATE: usize = 128;

fn futex_wake(addr: &AtomicU32, n: u32) {
    rusty_libc_core::lock::futex_wake(addr, n);
}

fn futex_wait(addr: &AtomicU32, val: u32, timeout: Option<[i64; 2]>) -> i32 {
    let ts = timeout.as_ref().map_or(0, |t| t.as_ptr() as usize);
    let r = unsafe { syscall4(202, addr.as_ptr() as usize, FUTEX_WAIT_PRIVATE, val as usize, ts) };
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as i32 } else { 0 }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Req(*mut Requestlist);

impl Req {
    const NULL: Req = Req(null_mut());
    fn is_null(self) -> bool {
        self.0.is_null()
    }
    fn node(self) -> &'static Requestlist {
        debug_assert!(!self.0.is_null());
        unsafe { &*self.0 }
    }
    fn next(self) -> Req {
        Req(self.node().next.get())
    }
    fn set_next(self, n: Req) {
        self.node().next.set(n.0);
    }
    fn running(self) -> bool {
        self.node().running.get()
    }
    fn set_running(self, v: bool) {
        self.node().running.set(v);
    }
    fn gaicbp(self) -> *mut Gaicb {
        self.node().gaicbp
    }
    fn waiting(self) -> Waiter {
        Waiter(self.node().waiting.get())
    }
    fn set_waiting(self, w: Waiter) {
        self.node().waiting.set(w.0);
    }
    fn free(self) {
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Waiter(*mut Waitlist);

impl Waiter {
    unsafe fn init(p: *mut Waitlist, w: Waitlist) -> Waiter {
        unsafe { p.write(w) };
        Waiter(p)
    }
    fn is_null(self) -> bool {
        self.0.is_null()
    }
    fn node(self) -> &'static Waitlist {
        debug_assert!(!self.0.is_null());
        unsafe { &*self.0 }
    }
    fn next(self) -> Waiter {
        Waiter(self.node().next.get())
    }
    fn set_next(self, n: Waiter) {
        self.node().next.set(n.0);
    }
}

unsafe fn link_waiters(reqs: &[Req], entries: *mut Waitlist, counterp: *mut u32, sigevp: *mut SigEvent, caller_pid: c_int) -> u32 {
    let mut total = 0;
    for (cnt, &r) in reqs.iter().enumerate() {
        if !r.is_null() {
            let w = unsafe { Waiter::init(entries.wrapping_add(cnt), Waitlist { next: Cell::new(r.waiting().0), counterp, sigevp, caller_pid }) };
            r.set_waiting(w);
            total += 1;
        }
    }
    total
}

struct Waitlist {
    next: Cell<*mut Waitlist>,
    counterp: *mut u32,
    sigevp: *mut SigEvent,
    caller_pid: c_int,
}

struct CArray<T> {
    p: *mut T,
    n: usize,
}

impl<T> CArray<T> {
    fn new(n: usize) -> Option<CArray<T>> {
        let p = unsafe { rusty_libc_malloc::calloc(n.max(1), size_of::<T>()) } as *mut T;
        if p.is_null() { None } else { Some(CArray { p, n }) }
    }
    fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { ffi::slice_mut(self.p, self.n) }
    }
}

impl<T> Drop for CArray<T> {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.cast()) };
    }
}

fn find_request(gaicbp: *const Gaicb) -> Req {
    let mut runp = get(&REQUESTS);
    while !runp.is_null() {
        if runp.gaicbp() as *const Gaicb == gaicbp {
            return runp;
        }
        runp = runp.next();
    }
    Req::NULL
}

fn remove_request(gaicbp: *mut Gaicb) -> c_int {
    let mut runp = get(&REQUESTS);
    let mut lastp = Req::NULL;
    while !runp.is_null() {
        if runp.gaicbp() == gaicbp {
            break;
        }
        lastp = runp;
        runp = runp.next();
    }
    if runp.is_null() {
        return -1;
    }
    if runp.running() {
        return 1;
    }
    if lastp.is_null() {
        put(&REQUESTS, runp.next());
    } else {
        lastp.set_next(runp.next());
    }
    if runp == get(&REQUESTS_TAIL) {
        put(&REQUESTS_TAIL, lastp);
    }
    runp.free();
    0
}

unsafe fn enqueue_request(gaicbp: *mut Gaicb) -> Req {
    lock();
    let p = crate::nss::heap_new(Requestlist { running: Cell::new(false), next: Cell::new(null_mut()), gaicbp, waiting: Cell::new(null_mut()) });
    if p.is_null() {
        unlock();
        errno::set(EAGAIN);
        return Req::NULL;
    }
    let mut newp = Req(p);
    let lastp = get(&REQUESTS_TAIL);
    if lastp.is_null() {
        put(&REQUESTS, newp);
    } else {
        lastp.set_next(newp);
    }
    put(&REQUESTS_TAIL, newp);
    unsafe { (*gaicbp).__return = EAI_INPROGRESS };
    if NTHREADS.load(Ordering::Relaxed) < MAX_THREADS && IDLE_THREADS.load(Ordering::Relaxed) == 0 {
        newp.set_running(true);
        if unsafe { spawn(handle_requests, p.cast(), null_mut(), 0) } == 0 {
            add(&NTHREADS, 1);
        } else if NTHREADS.load(Ordering::Relaxed) == 0 {
            if lastp.is_null() {
                put(&REQUESTS, Req::NULL);
            } else {
                lastp.set_next(Req::NULL);
            }
            put(&REQUESTS_TAIL, lastp);
            newp.free();
            newp = Req::NULL;
        } else {
            newp.set_running(false);
        }
    }
    if !newp.is_null() && IDLE_THREADS.load(Ordering::Relaxed) > 0 {
        NEW_REQUEST.fetch_add(1, Ordering::SeqCst);
        futex_wake(&NEW_REQUEST, 1);
    }
    unlock();
    newp
}

use rusty_libc_core::unistd::getpid;

fn gai_sigqueue(sig: c_int, val: SigVal, caller_pid: c_int) -> c_int {
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&sig.to_ne_bytes());
    info[8..12].copy_from_slice(&SI_ASYNCNL.to_ne_bytes());
    info[16..20].copy_from_slice(&caller_pid.to_ne_bytes());
    let uid = rusty_libc_core::unistd::getuid();
    info[20..24].copy_from_slice(&uid.to_ne_bytes());
    let v = unsafe { val.sival_ptr } as usize;
    info[24..32].copy_from_slice(&v.to_ne_bytes());
    let r = unsafe { syscall3(129, caller_pid as usize, sig as usize, info.as_ptr() as usize) };
    if r > usize::MAX - 4095 {
        errno::set((r as isize).wrapping_neg() as i32);
        -1
    } else {
        0
    }
}

struct NotifyFunc {
    func: Option<unsafe extern "C" fn(SigVal)>,
    value: SigVal,
}

unsafe extern "C" fn notify_func_wrapper(arg: *mut c_void) -> *mut c_void {
    unblock_all();
    let NotifyFunc { func, value } = unsafe { (arg as *mut NotifyFunc).read() };
    unsafe { rusty_libc_malloc::free(arg) };
    if let Some(f) = func {
        unsafe { f(value) };
    }
    null_mut()
}

fn notify_only(ev: &SigEvent, caller_pid: c_int) -> c_int {
    if ev.sigev_notify == SIGEV_THREAD {
        let nf = crate::nss::heap_new(NotifyFunc { func: ev.sigev_notify_function, value: ev.sigev_value });
        if nf.is_null() {
            return -1;
        }
        if unsafe { spawn(notify_func_wrapper, nf.cast(), ev.sigev_notify_attributes, 0) } != 0 {
            unsafe { rusty_libc_malloc::free(nf.cast()) };
            return -1;
        }
        0
    } else if ev.sigev_notify == SIGEV_SIGNAL {
        gai_sigqueue(ev.sigev_signo, ev.sigev_value, caller_pid)
    } else {
        0
    }
}

fn notify(req: Req) {
    let mut w = req.waiting();
    while !w.is_null() {
        let e = w.node();
        let next = e.next.get();
        let c = unsafe { AtomicU32::from_ptr(e.counterp) };
        if e.sigevp.is_null() {
            if c.load(Ordering::SeqCst) > 0 && c.fetch_sub(1, Ordering::SeqCst) == 1 {
                futex_wake(c, 1);
            }
        } else {
            let left = c.load(Ordering::Relaxed) - 1;
            c.store(left, Ordering::Relaxed);
            if left == 0 {
                notify_only(unsafe { &*e.sigevp }, e.caller_pid);
                unsafe { rusty_libc_malloc::free(e.counterp.cast()) };
            }
        }
        w = Waiter(next);
    }
}

unsafe extern "C" fn handle_requests(arg: *mut c_void) -> *mut c_void {
    let mut runp = Req(arg as *mut Requestlist);
    loop {
        if runp.is_null() {
            lock();
        } else {
            let req = runp.gaicbp();
            let g = unsafe { req.read() };
            let result_slot = (req as *mut u8).wrapping_add(core::mem::offset_of!(Gaicb, ar_result)) as *mut *mut addrinfo;
            let r = unsafe { getaddrinfo(g.ar_name, g.ar_service, g.ar_request, result_slot) };
            unsafe { core::ptr::write_volatile(return_of(req) as *mut c_int, r) };
            lock();
            notify(runp);
            let mut lastp = Req::NULL;
            let mut srchp = get(&REQUESTS);
            while srchp != runp {
                lastp = srchp;
                srchp = srchp.next();
            }
            if get(&REQUESTS_TAIL) == runp {
                put(&REQUESTS_TAIL, lastp);
            }
            if lastp.is_null() {
                put(&REQUESTS, get(&REQUESTS).next());
            } else {
                lastp.set_next(runp.next());
            }
            runp.free();
        }
        runp = get(&REQUESTS);
        while !runp.is_null() && runp.running() {
            runp = runp.next();
        }
        if runp.is_null() {
            add(&IDLE_THREADS, 1);
            let seq = NEW_REQUEST.load(Ordering::SeqCst);
            unlock();
            futex_wait(&NEW_REQUEST, seq, Some([IDLE_SECONDS, 0]));
            lock();
            add(&IDLE_THREADS, -1);
            runp = get(&REQUESTS);
            while !runp.is_null() && runp.running() {
                runp = runp.next();
            }
        }
        if runp.is_null() {
            add(&NTHREADS, -1);
        } else {
            runp.set_running(true);
            if !get(&REQUESTS).is_null() {
                if IDLE_THREADS.load(Ordering::Relaxed) > 0 {
                    NEW_REQUEST.fetch_add(1, Ordering::SeqCst);
                    futex_wake(&NEW_REQUEST, 1);
                } else if NTHREADS.load(Ordering::Relaxed) < MAX_THREADS && {
                    unsafe { spawn(handle_requests, null_mut(), null_mut(), 0) }
                } == 0
                {
                    add(&NTHREADS, 1);
                }
            }
        }
        unlock();
        if runp.is_null() {
            break;
        }
    }
    null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo_a(mode: c_int, list: *mut *mut Gaicb, ent: c_int, sig: *mut SigEvent) -> c_int {
    if mode != GAI_WAIT && mode != GAI_NOWAIT {
        errno::set(EINVAL);
        return EAI_SYSTEM;
    }
    let defsigev = SigEvent::none();
    let ent_n = ent.max(0) as usize;
    let (list, sig) = unsafe { (Slice(list as *const *mut Gaicb, ent_n), OptRef(sig as *const SigEvent)).conv() };
    let sig: &SigEvent = sig.unwrap_or(&defsigev);
    let Some(mut requests) = CArray::<Req>::new(ent_n) else { return EAI_AGAIN };
    let reqs = requests.as_mut_slice();
    let mut total: u32 = 0;
    let mut result = 0;
    lock();
    for (slot, &g) in reqs.iter_mut().zip(list) {
        if !g.is_null() {
            let r = unsafe { enqueue_request(g) };
            *slot = r;
            if !r.is_null() {
                total += 1;
            } else {
                result = EAI_SYSTEM;
            }
        } else {
            *slot = Req::NULL;
        }
    }
    if total == 0 {
        unlock();
        if mode == GAI_NOWAIT {
            notify_only(sig, if sig.sigev_notify == SIGEV_SIGNAL { getpid() } else { 0 });
        }
        drop(requests);
        return result;
    } else if mode == GAI_WAIT {
        let Some(mut waitlist) = CArray::<Waitlist>::new(ent_n) else {
            unlock();
            drop(requests);
            return EAI_AGAIN;
        };
        let counter = AtomicU32::new(0);
        let total = unsafe { link_waiters(reqs, waitlist.as_mut_slice().as_mut_ptr(), counter.as_ptr(), null_mut(), 0) };
        counter.store(total, Ordering::SeqCst);
        let mut oldval = counter.load(Ordering::SeqCst);
        if oldval != 0 {
            unlock();
            loop {
                futex_wait(&counter, oldval, None);
                oldval = counter.load(Ordering::SeqCst);
                if oldval == 0 {
                    break;
                }
            }
            lock();
        }
        drop(waitlist);
    } else {
        let aw = unsafe { rusty_libc_malloc::malloc(size_of::<AsyncWaitlist>() + ent_n * size_of::<Waitlist>()) } as *mut AsyncWaitlist;
        if aw.is_null() {
            result = EAI_AGAIN;
        } else {
            let caller_pid = if sig.sigev_notify == SIGEV_SIGNAL { getpid() } else { 0 };
            let wl = (aw as *mut u8).wrapping_add(size_of::<AsyncWaitlist>()) as *mut Waitlist;
            let counterp = (aw as *mut u8).wrapping_add(core::mem::offset_of!(AsyncWaitlist, counter)) as *mut u32;
            let sigevp = (aw as *mut u8).wrapping_add(core::mem::offset_of!(AsyncWaitlist, sigev)) as *mut SigEvent;
            let total = unsafe { link_waiters(reqs, wl, counterp, sigevp, caller_pid) };
            unsafe { aw.write(AsyncWaitlist { counter: total, sigev: *sig }) };
        }
    }
    unlock();
    drop(requests);
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gai_suspend(list: *const *const Gaicb, ent: c_int, timeout: *const timespec) -> c_int {
    let ent_n = ent.max(0) as usize;
    let (list, timeout) = unsafe { (Slice(list, ent_n), OptRef(timeout)).conv() };
    let wl = CArray::<Waitlist>::new(ent_n);
    let rl = CArray::<Req>::new(ent_n);
    let (Some(mut wl), Some(mut rl)) = (wl, rl) else {
        return EAI_SYSTEM;
    };
    let waitlist = wl.as_mut_slice().as_mut_ptr();
    let reqs = rl.as_mut_slice();
    let cntr = AtomicU32::new(1);
    let mut none = true;
    lock();
    for (cnt, &g) in list.iter().enumerate() {
        if g.is_null() {
            continue;
        }
        if unsafe { core::ptr::read_volatile(return_of(g)) } == EAI_INPROGRESS {
            let r = find_request(g);
            reqs[cnt] = r;
            if !r.is_null() {
                let w = unsafe { Waiter::init(waitlist.wrapping_add(cnt), Waitlist { next: Cell::new(r.waiting().0), counterp: cntr.as_ptr(), sigevp: null_mut(), caller_pid: 0 }) };
                r.set_waiting(w);
                none = false;
            }
        }
    }
    let result;
    if none {
        result = EAI_ALLDONE;
    } else {
        let mut status = 0;
        let deadline: Option<[i64; 2]> = timeout.map(|t| [t.tv_sec, t.tv_nsec]);
        let start = now();
        let oldval = cntr.load(Ordering::SeqCst);
        if oldval != 0 {
            unlock();
            let mut ov = oldval;
            loop {
                let remaining = match deadline {
                    None => None,
                    Some(d) => {
                        let now = now();
                        let mut s = d[0] - (now[0] - start[0]);
                        let mut n = d[1] - (now[1] - start[1]);
                        if n < 0 {
                            n += 1_000_000_000;
                            s -= 1;
                        }
                        if s < 0 {
                            status = ETIMEDOUT;
                            break;
                        }
                        Some([s, n])
                    }
                };
                let st = futex_wait(&cntr, ov, remaining);
                if st == EAGAIN || st == 0 {
                    ov = cntr.load(Ordering::SeqCst);
                    if ov == 0 {
                        break;
                    }
                    continue;
                }
                status = st;
                break;
            }
            lock();
        }
        for (cnt, &g) in list.iter().enumerate() {
            let r = reqs[cnt];
            if !g.is_null() && !r.is_null() && find_request(g) == r {
                let mine = Waiter(waitlist.wrapping_add(cnt));
                let first = r.waiting();
                if first == mine {
                    r.set_waiting(mine.next());
                } else {
                    let mut w = first;
                    while !w.is_null() {
                        let n = w.next();
                        if n == mine {
                            w.set_next(mine.next());
                            break;
                        }
                        w = n;
                    }
                }
            }
        }
        result = match status {
            0 => 0,
            ETIMEDOUT => EAI_SYSTEM,
            EINTR => EAI_INTR,
            _ => EAI_SYSTEM,
        };
    }
    unlock();
    drop(wl);
    drop(rl);
    result
}

use crate::dns::monotonic as now;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gai_error(req: *mut Gaicb) -> c_int {
    unsafe { core::ptr::read_volatile(return_of(req)) }
}

fn return_of(g: *const Gaicb) -> *const c_int {
    (g as *const u8).wrapping_add(core::mem::offset_of!(Gaicb, __return)) as *const c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gai_cancel(gaicbp: *mut Gaicb) -> c_int {
    lock();
    let status = remove_request(gaicbp);
    let result = if status == 0 {
        EAI_CANCELED
    } else if status > 0 {
        EAI_NOTCANCELED
    } else {
        EAI_ALLDONE
    };
    unlock();
    result
}
