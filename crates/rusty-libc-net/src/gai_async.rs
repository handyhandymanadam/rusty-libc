use crate::gai::getaddrinfo;
use crate::types::*;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::syscall::{self, syscall0, syscall3, syscall4};
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

struct Waitlist {
    next: *mut Waitlist,
    counterp: *mut u32,
    sigevp: *mut SigEvent,
    caller_pid: c_int,
}

struct Requestlist {
    running: bool,
    next: *mut Requestlist,
    gaicbp: *mut Gaicb,
    waiting: *mut Waitlist,
}

#[repr(C)]
struct AsyncWaitlist {
    counter: u32,
    sigev: SigEvent,
}

const MAX_THREADS: i32 = 20;
const IDLE_SECONDS: i64 = 1;

static OWNER: AtomicI32 = AtomicI32::new(0);
static mut DEPTH: u32 = 0;
static mut REQUESTS: *mut Requestlist = null_mut();
static mut REQUESTS_TAIL: *mut Requestlist = null_mut();
static mut NTHREADS: i32 = 0;
static mut IDLE_THREADS: i32 = 0;
static NEW_REQUEST: AtomicU32 = AtomicU32::new(0);

fn gettid() -> i32 {
    unsafe { syscall0(syscall::SYS_GETTID) as i32 }
}

fn lock() {
    let me = gettid();
    if OWNER.load(Ordering::Relaxed) == me {
        unsafe { DEPTH += 1 };
        return;
    }
    while OWNER.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
        unsafe { syscall0(24) };
    }
    unsafe { DEPTH = 1 };
}

fn unlock() {
    unsafe {
        DEPTH -= 1;
        if DEPTH == 0 {
            OWNER.store(0, Ordering::Release);
        }
    }
}

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;

fn futex_wake(addr: *const u32, n: usize) {
    unsafe { syscall3(202, addr as usize, FUTEX_WAKE_PRIVATE, n) };
}

fn futex_wait(addr: *const u32, val: u32, timeout: Option<[i64; 2]>) -> i32 {
    unsafe {
        let r = match timeout {
            Some(ts) => syscall4(202, addr as usize, FUTEX_WAIT_PRIVATE, val as usize, ts.as_ptr() as usize),
            None => syscall4(202, addr as usize, FUTEX_WAIT_PRIVATE, val as usize, 0),
        };
        if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as i32 } else { 0 }
    }
}

unsafe fn find_request(gaicbp: *const Gaicb) -> *mut Requestlist {
    unsafe {
        let mut runp = REQUESTS;
        while !runp.is_null() {
            if (*runp).gaicbp as *const Gaicb == gaicbp {
                return runp;
            }
            runp = (*runp).next;
        }
        null_mut()
    }
}

unsafe fn remove_request(gaicbp: *mut Gaicb) -> c_int {
    unsafe {
        let mut runp = REQUESTS;
        let mut lastp: *mut Requestlist = null_mut();
        while !runp.is_null() {
            if (*runp).gaicbp == gaicbp {
                break;
            }
            lastp = runp;
            runp = (*runp).next;
        }
        if runp.is_null() {
            return -1;
        }
        if (*runp).running {
            return 1;
        }
        if lastp.is_null() {
            REQUESTS = (*runp).next;
        } else {
            (*lastp).next = (*runp).next;
        }
        if runp == REQUESTS_TAIL {
            REQUESTS_TAIL = lastp;
        }
        rusty_libc_malloc::free(runp.cast());
        0
    }
}

unsafe fn enqueue_request(gaicbp: *mut Gaicb) -> *mut Requestlist {
    unsafe {
        lock();
        let mut newp = rusty_libc_malloc::malloc(size_of::<Requestlist>()) as *mut Requestlist;
        if newp.is_null() {
            unlock();
            errno::set(EAGAIN);
            return null_mut();
        }
        *newp = Requestlist { running: false, next: null_mut(), gaicbp, waiting: null_mut() };
        let lastp = REQUESTS_TAIL;
        if REQUESTS_TAIL.is_null() {
            REQUESTS = newp;
            REQUESTS_TAIL = newp;
        } else {
            (*REQUESTS_TAIL).next = newp;
            REQUESTS_TAIL = newp;
        }
        (*gaicbp).__return = EAI_INPROGRESS;
        if NTHREADS < MAX_THREADS && IDLE_THREADS == 0 {
            (*newp).running = true;
            if spawn(handle_requests, newp.cast(), null_mut(), 0) == 0 {
                NTHREADS += 1;
            } else if NTHREADS == 0 {
                if lastp.is_null() {
                    REQUESTS = null_mut();
                } else {
                    (*lastp).next = null_mut();
                }
                REQUESTS_TAIL = lastp;
                rusty_libc_malloc::free(newp.cast());
                newp = null_mut();
            } else {
                (*newp).running = false;
            }
        }
        if !newp.is_null() && IDLE_THREADS > 0 {
            NEW_REQUEST.fetch_add(1, Ordering::SeqCst);
            futex_wake(NEW_REQUEST.as_ptr(), 1);
        }
        unlock();
        newp
    }
}

fn getpid() -> c_int {
    unsafe { syscall0(syscall::SYS_GETPID) as c_int }
}

unsafe fn gai_sigqueue(sig: c_int, val: SigVal, caller_pid: c_int) -> c_int {
    unsafe {
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&sig.to_ne_bytes());
        info[8..12].copy_from_slice(&SI_ASYNCNL.to_ne_bytes());
        info[16..20].copy_from_slice(&caller_pid.to_ne_bytes());
        let uid = syscall0(102) as u32;
        info[20..24].copy_from_slice(&uid.to_ne_bytes());
        info[24..32].copy_from_slice(&(val.sival_ptr as usize).to_ne_bytes());
        let r = syscall3(129, caller_pid as usize, sig as usize, info.as_ptr() as usize);
        if r > usize::MAX - 4095 {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        } else {
            0
        }
    }
}

struct NotifyFunc {
    func: Option<unsafe extern "C" fn(SigVal)>,
    value: SigVal,
}

unsafe extern "C" fn notify_func_wrapper(arg: *mut c_void) -> *mut c_void {
    unsafe {
        unblock_all();
        let n = arg as *mut NotifyFunc;
        let func = (*n).func;
        let value = (*n).value;
        rusty_libc_malloc::free(arg);
        if let Some(f) = func {
            f(value);
        }
        null_mut()
    }
}

unsafe fn notify_only(sigev: *const SigEvent, caller_pid: c_int) -> c_int {
    unsafe {
        let ev = &*sigev;
        if ev.sigev_notify == SIGEV_THREAD {
            let nf = rusty_libc_malloc::malloc(size_of::<NotifyFunc>()) as *mut NotifyFunc;
            if nf.is_null() {
                return -1;
            }
            (*nf).func = ev.sigev_notify_function;
            (*nf).value = ev.sigev_value;
            if spawn(notify_func_wrapper, nf.cast(), ev.sigev_notify_attributes, 0) != 0 {
                rusty_libc_malloc::free(nf.cast());
                return -1;
            }
            0
        } else if ev.sigev_notify == SIGEV_SIGNAL {
            gai_sigqueue(ev.sigev_signo, ev.sigev_value, caller_pid)
        } else {
            0
        }
    }
}

unsafe fn notify(req: *mut Requestlist) {
    unsafe {
        let mut w = (*req).waiting;
        while !w.is_null() {
            let next = (*w).next;
            let counter = (*w).counterp;
            if (*w).sigevp.is_null() {
                let c = core::sync::atomic::AtomicU32::from_ptr(counter);
                if c.load(Ordering::SeqCst) > 0 && c.fetch_sub(1, Ordering::SeqCst) == 1 {
                    futex_wake(counter, 1);
                }
            } else {
                *counter -= 1;
                if *counter == 0 {
                    notify_only((*w).sigevp, (*w).caller_pid);
                    rusty_libc_malloc::free(counter.cast());
                }
            }
            w = next;
        }
    }
}

unsafe extern "C" fn handle_requests(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let mut runp = arg as *mut Requestlist;
        loop {
            if runp.is_null() {
                lock();
            } else {
                let req = (*runp).gaicbp;
                let r = getaddrinfo((*req).ar_name, (*req).ar_service, (*req).ar_request, &mut (*req).ar_result);
                core::ptr::write_volatile(&mut (*req).__return, r);
                lock();
                notify(runp);
                let mut lastp: *mut Requestlist = null_mut();
                let mut srchp = REQUESTS;
                while srchp != runp {
                    lastp = srchp;
                    srchp = (*srchp).next;
                }
                if REQUESTS_TAIL == runp {
                    REQUESTS_TAIL = lastp;
                }
                if lastp.is_null() {
                    REQUESTS = (*REQUESTS).next;
                } else {
                    (*lastp).next = (*runp).next;
                }
                rusty_libc_malloc::free(runp.cast());
            }
            runp = REQUESTS;
            while !runp.is_null() && (*runp).running {
                runp = (*runp).next;
            }
            if runp.is_null() {
                IDLE_THREADS += 1;
                let seq = NEW_REQUEST.load(Ordering::SeqCst);
                unlock();
                futex_wait(NEW_REQUEST.as_ptr(), seq, Some([IDLE_SECONDS, 0]));
                lock();
                IDLE_THREADS -= 1;
                runp = REQUESTS;
                while !runp.is_null() && (*runp).running {
                    runp = (*runp).next;
                }
            }
            if runp.is_null() {
                NTHREADS -= 1;
            } else {
                (*runp).running = true;
                if !REQUESTS.is_null() {
                    if IDLE_THREADS > 0 {
                        NEW_REQUEST.fetch_add(1, Ordering::SeqCst);
                        futex_wake(NEW_REQUEST.as_ptr(), 1);
                    } else if NTHREADS < MAX_THREADS && spawn(handle_requests, null_mut(), null_mut(), 0) == 0 {
                        NTHREADS += 1;
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
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo_a(mode: c_int, list: *mut *mut Gaicb, ent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe {
        if mode != GAI_WAIT && mode != GAI_NOWAIT {
            errno::set(EINVAL);
            return EAI_SYSTEM;
        }
        let mut defsigev = SigEvent::none();
        let sig: *mut SigEvent = if sig.is_null() { &mut defsigev } else { sig };
        let ent_n = ent.max(0) as usize;
        let requests = rusty_libc_malloc::calloc(ent_n.max(1), size_of::<*mut Requestlist>()) as *mut *mut Requestlist;
        if requests.is_null() {
            return EAI_AGAIN;
        }
        let mut total: u32 = 0;
        let mut result = 0;
        lock();
        for cnt in 0..ent_n {
            let g = *list.add(cnt);
            if !g.is_null() {
                let r = enqueue_request(g);
                *requests.add(cnt) = r;
                if !r.is_null() {
                    total += 1;
                } else {
                    result = EAI_SYSTEM;
                }
            } else {
                *requests.add(cnt) = null_mut();
            }
        }
        if total == 0 {
            unlock();
            if mode == GAI_NOWAIT {
                notify_only(sig, if (*sig).sigev_notify == SIGEV_SIGNAL { getpid() } else { 0 });
            }
            rusty_libc_malloc::free(requests.cast());
            return result;
        } else if mode == GAI_WAIT {
            let waitlist = rusty_libc_malloc::calloc(ent_n, size_of::<Waitlist>()) as *mut Waitlist;
            if waitlist.is_null() {
                unlock();
                rusty_libc_malloc::free(requests.cast());
                return EAI_AGAIN;
            }
            let counter = AtomicU32::new(0);
            total = 0;
            for cnt in 0..ent_n {
                let r = *requests.add(cnt);
                if !r.is_null() {
                    let w = waitlist.add(cnt);
                    (*w).next = (*r).waiting;
                    (*w).counterp = counter.as_ptr();
                    (*w).sigevp = null_mut();
                    (*w).caller_pid = 0;
                    (*r).waiting = w;
                    total += 1;
                }
            }
            counter.store(total, Ordering::SeqCst);
            let mut oldval = counter.load(Ordering::SeqCst);
            if oldval != 0 {
                unlock();
                loop {
                    let status = futex_wait(counter.as_ptr(), oldval, None);
                    if status != EAGAIN && status != EINTR {
                    }
                    oldval = counter.load(Ordering::SeqCst);
                    if oldval == 0 {
                        break;
                    }
                }
                lock();
            }
            rusty_libc_malloc::free(waitlist.cast());
        } else {
            let aw = rusty_libc_malloc::malloc(size_of::<AsyncWaitlist>() + ent_n * size_of::<Waitlist>()) as *mut AsyncWaitlist;
            if aw.is_null() {
                result = EAI_AGAIN;
            } else {
                let caller_pid = if (*sig).sigev_notify == SIGEV_SIGNAL { getpid() } else { 0 };
                total = 0;
                let wl = (aw as *mut u8).add(size_of::<AsyncWaitlist>()) as *mut Waitlist;
                for cnt in 0..ent_n {
                    let r = *requests.add(cnt);
                    if !r.is_null() {
                        let w = wl.add(cnt);
                        (*w).next = (*r).waiting;
                        (*w).counterp = &raw mut (*aw).counter;
                        (*w).sigevp = &raw mut (*aw).sigev;
                        (*w).caller_pid = caller_pid;
                        (*r).waiting = w;
                        total += 1;
                    }
                }
                (*aw).counter = total;
                (*aw).sigev = *sig;
            }
        }
        unlock();
        rusty_libc_malloc::free(requests.cast());
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gai_suspend(list: *const *const Gaicb, ent: c_int, timeout: *const timespec) -> c_int {
    unsafe {
        let ent_n = ent.max(0) as usize;
        let waitlist = rusty_libc_malloc::calloc(ent_n.max(1), size_of::<Waitlist>()) as *mut Waitlist;
        let requestlist = rusty_libc_malloc::calloc(ent_n.max(1), size_of::<*mut Requestlist>()) as *mut *mut Requestlist;
        if waitlist.is_null() || requestlist.is_null() {
            rusty_libc_malloc::free(waitlist.cast());
            rusty_libc_malloc::free(requestlist.cast());
            return EAI_SYSTEM;
        }
        let cntr = AtomicU32::new(1);
        let mut none = true;
        lock();
        for cnt in 0..ent_n {
            let g = *list.add(cnt);
            if g.is_null() {
                continue;
            }
            if core::ptr::read_volatile(&(*g).__return) == EAI_INPROGRESS {
                let r = find_request(g);
                *requestlist.add(cnt) = r;
                if !r.is_null() {
                    let w = waitlist.add(cnt);
                    (*w).next = (*r).waiting;
                    (*w).counterp = cntr.as_ptr();
                    (*w).sigevp = null_mut();
                    (*w).caller_pid = 0;
                    (*r).waiting = w;
                    none = false;
                }
            }
        }
        let result;
        if none {
            result = EAI_ALLDONE;
        } else {
            let mut status = 0;
            let deadline: Option<[i64; 2]> = if timeout.is_null() { None } else { Some([(*timeout).tv_sec, (*timeout).tv_nsec]) };
            let start = {
                let mut ts = [0i64; 2];
                syscall::syscall2(228, 1, ts.as_mut_ptr() as usize);
                ts
            };
            let oldval = cntr.load(Ordering::SeqCst);
            if oldval != 0 {
                unlock();
                let mut ov = oldval;
                loop {
                    let remaining = match deadline {
                        None => None,
                        Some(d) => {
                            let mut now = [0i64; 2];
                            syscall::syscall2(228, 1, now.as_mut_ptr() as usize);
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
                    let st = futex_wait(cntr.as_ptr(), ov, remaining);
                    if st == EAGAIN {
                        ov = cntr.load(Ordering::SeqCst);
                        if ov == 0 {
                            break;
                        }
                        continue;
                    }
                    if st == 0 {
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
            for cnt in 0..ent_n {
                let g = *list.add(cnt);
                if !g.is_null() && !(*requestlist.add(cnt)).is_null() && find_request(g) == *requestlist.add(cnt) {
                    let mut listp: *mut *mut Waitlist = &raw mut (**requestlist.add(cnt)).waiting;
                    let mine = waitlist.add(cnt);
                    while !(*listp).is_null() && *listp != mine {
                        listp = &raw mut (**listp).next;
                    }
                    if !(*listp).is_null() {
                        *listp = (**listp).next;
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
        rusty_libc_malloc::free(waitlist.cast());
        rusty_libc_malloc::free(requestlist.cast());
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gai_error(req: *mut Gaicb) -> c_int {
    unsafe { core::ptr::read_volatile(&(*req).__return) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gai_cancel(gaicbp: *mut Gaicb) -> c_int {
    unsafe {
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
}
