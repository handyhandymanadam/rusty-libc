use crate::notify::*;
use crate::sysv::Timespec;
use crate::util::*;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
const SYS_FSYNC: usize = 74;
const SYS_FDATASYNC: usize = 75;
const SYS_FCNTL: usize = 72;
const SYS_FUTEX: usize = 202;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_RT_SIGQUEUEINFO: usize = 129;
const F_GETFL: usize = 3;
const FUTEX_WAIT_PRIVATE: usize = 128;
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

const FREE: u8 = 0;
const READY: u8 = 1;
const RUNNING: u8 = 2;
const QUEUED: u8 = 3;

struct Req {
    cb: *mut Aiocb,
    fd: c_int,
    op: c_int,
    state: u8,
    prio: c_int,
    next: *mut Req,
    fd_next: *mut Req,
    fd_prev: *mut Req,
    run_next: *mut Req,
    waiters: *mut Wait,
}

struct Wait {
    next: *mut Wait,
    counter: *mut u32,
    seq: *const AtomicU32,
    result: *mut c_int,
    sigev: *mut SigEvent,
}

#[repr(C)]
struct AsyncList {
    counter: u32,
    sigev: SigEvent,
}

struct State {
    fds: *mut Req,
    run_head: *mut Req,
    run_tail: *mut Req,
    freelist: *mut Req,
    nthreads: c_int,
    idle: c_int,
    max_threads: c_int,
    idle_time: c_int,
    num: c_int,
    pool_used: bool,
}

static LOCK: RawMutex = RawMutex::new();
static IDLE_SEQ: AtomicU32 = AtomicU32::new(0);
static HOOKED: AtomicBool = AtomicBool::new(false);
static mut ST: State = State {
    fds: core::ptr::null_mut(),
    run_head: core::ptr::null_mut(),
    run_tail: core::ptr::null_mut(),
    freelist: core::ptr::null_mut(),
    nthreads: 0,
    idle: 0,
    max_threads: 20,
    idle_time: 1,
    num: 64,
    pool_used: false,
};

#[inline]
fn st() -> &'static mut State {
    unsafe { &mut *(&raw mut ST) }
}

unsafe fn get_elem() -> *mut Req {
    unsafe {
        let s = st();
        if s.freelist.is_null() {
            let n = if s.pool_used { ENTRIES_PER_ROW } else { s.num.max(ENTRIES_PER_ROW as c_int) as usize };
            let row = rusty_libc_malloc::malloc(n * core::mem::size_of::<Req>()) as *mut Req;
            if row.is_null() {
                return core::ptr::null_mut();
            }
            s.pool_used = true;
            for i in 0..n {
                let e = row.add(i);
                core::ptr::write_bytes(e, 0, 1);
                (*e).next = s.freelist;
                s.freelist = e;
            }
        }
        let r = s.freelist;
        s.freelist = (*r).next;
        core::ptr::write_bytes(r, 0, 1);
        r
    }
}

unsafe fn free_req(r: *mut Req) {
    unsafe {
        (*r).state = FREE;
        (*r).waiters = core::ptr::null_mut();
        (*r).next = st().freelist;
        st().freelist = r;
    }
}

unsafe fn find_head(fd: c_int) -> *mut Req {
    unsafe {
        let mut r = st().fds;
        while !r.is_null() && (*r).fd != fd {
            r = (*r).fd_next;
        }
        r
    }
}

unsafe fn push_run(r: *mut Req) {
    unsafe {
        let s = st();
        (*r).run_next = core::ptr::null_mut();
        if s.run_tail.is_null() {
            s.run_head = r;
        } else {
            (*s.run_tail).run_next = r;
        }
        s.run_tail = r;
    }
}

unsafe fn pop_run() -> *mut Req {
    unsafe {
        let s = st();
        let r = s.run_head;
        if !r.is_null() {
            s.run_head = (*r).run_next;
            if s.run_head.is_null() {
                s.run_tail = core::ptr::null_mut();
            }
        }
        r
    }
}

unsafe fn remove_run(r: *mut Req) {
    unsafe {
        let s = st();
        let mut prev: *mut Req = core::ptr::null_mut();
        let mut p = s.run_head;
        while !p.is_null() && p != r {
            prev = p;
            p = (*p).run_next;
        }
        if p.is_null() {
            return;
        }
        if prev.is_null() {
            s.run_head = (*r).run_next;
        } else {
            (*prev).run_next = (*r).run_next;
        }
        if s.run_tail == r {
            s.run_tail = prev;
        }
    }
}

unsafe fn unlink_head(r: *mut Req, promote: bool) {
    unsafe {
        let s = st();
        let n = if promote { (*r).next } else { core::ptr::null_mut() };
        if !n.is_null() {
            (*n).fd_prev = (*r).fd_prev;
            (*n).fd_next = (*r).fd_next;
            if (*r).fd_prev.is_null() {
                s.fds = n;
            } else {
                (*(*r).fd_prev).fd_next = n;
            }
            if !(*r).fd_next.is_null() {
                (*(*r).fd_next).fd_prev = n;
            }
            (*n).state = READY;
            push_run(n);
        } else {
            if (*r).fd_prev.is_null() {
                s.fds = (*r).fd_next;
            } else {
                (*(*r).fd_prev).fd_next = (*r).fd_next;
            }
            if !(*r).fd_next.is_null() {
                (*(*r).fd_next).fd_prev = (*r).fd_prev;
            }
        }
    }
}

unsafe fn wake_idle() {
    IDLE_SEQ.fetch_add(1, Ordering::SeqCst);
    futex_wake(&IDLE_SEQ, 1);
}

struct NotifyJob {
    func: Option<unsafe extern "C" fn(SigVal)>,
    value: SigVal,
}

unsafe extern "C" fn notify_wrapper(arg: *mut c_void) -> *mut c_void {
    unsafe {
        unblock_all();
        let j = arg as *mut NotifyJob;
        let f = (*j).func;
        let v = (*j).value;
        rusty_libc_malloc::free(arg);
        if let Some(f) = f {
            f(v);
        }
        core::ptr::null_mut()
    }
}

unsafe fn notify_only(sigev: *const SigEvent) -> c_int {
    unsafe {
        let ev = &*sigev;
        if ev.sigev_notify == SIGEV_THREAD {
            let nf = rusty_libc_malloc::malloc(core::mem::size_of::<NotifyJob>()) as *mut NotifyJob;
            if nf.is_null() {
                errno::set(ENOMEM);
                return -1;
            }
            (*nf).func = ev.sigev_notify_function;
            (*nf).value = ev.sigev_value;
            let r = spawn(notify_wrapper, nf as *mut c_void, ev.sigev_notify_attributes, 0);
            if r != 0 {
                rusty_libc_malloc::free(nf as *mut c_void);
                errno::set(r);
                return -1;
            }
            0
        } else if ev.sigev_notify == SIGEV_SIGNAL {
            let pid = syscall0(SYS_GETPID) as c_int;
            let mut info = [0u8; 128];
            info[0..4].copy_from_slice(&ev.sigev_signo.to_ne_bytes());
            info[8..12].copy_from_slice(&SI_ASYNCIO.to_ne_bytes());
            info[16..20].copy_from_slice(&pid.to_ne_bytes());
            let uid = syscall0(SYS_GETUID) as u32;
            info[20..24].copy_from_slice(&uid.to_ne_bytes());
            let v = ev.sigev_value.sival_ptr as usize;
            info[24..32].copy_from_slice(&v.to_ne_bytes());
            sci(syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, ev.sigev_signo as usize, info.as_ptr() as usize))
        } else {
            0
        }
    }
}

unsafe fn notify(r: *mut Req) {
    unsafe {
        let cb = (*r).cb;
        if notify_only(&(*cb).aio_sigevent) != 0 {
            core::ptr::write_volatile(&mut (*cb).error_code, errno::get());
            core::ptr::write_volatile(&mut (*cb).return_value, -1);
        }
        let mut w = (*r).waiters;
        (*r).waiters = core::ptr::null_mut();
        while !w.is_null() {
            let next = (*w).next;
            if (*w).sigev.is_null() {
                if !(*w).result.is_null() && core::ptr::read_volatile(&(*cb).return_value) == -1 {
                    *(*w).result = -1;
                }
                *(*w).counter -= 1;
                let seq = (*w).seq;
                if !seq.is_null() {
                    (*seq).fetch_add(1, Ordering::SeqCst);
                    futex_wake(&*seq, 1);
                }
            } else {
                *(*w).counter -= 1;
                if *(*w).counter == 0 {
                    notify_only((*w).sigev);
                    rusty_libc_malloc::free((*w).counter as *mut c_void);
                }
            }
            w = next;
        }
    }
}

unsafe fn do_io(r: *mut Req) -> (isize, c_int) {
    unsafe {
        let cb = (*r).cb;
        let fd = (*r).fd as usize;
        loop {
            let ret = match (*r).op {
                LIO_READ => {
                    let mut x = syscall4(SYS_PREAD64, fd, (*cb).aio_buf as usize, (*cb).aio_nbytes, (*cb).aio_offset as usize);
                    if x as isize == -(ESPIPE as isize) {
                        core::ptr::write_volatile(&mut (*cb).return_value, -1);
                        x = syscall3(SYS_READ, fd, (*cb).aio_buf as usize, (*cb).aio_nbytes);
                    }
                    x
                }
                LIO_WRITE => {
                    let mut x = syscall4(SYS_PWRITE64, fd, (*cb).aio_buf as usize, (*cb).aio_nbytes, (*cb).aio_offset as usize);
                    if x as isize == -(ESPIPE as isize) {
                        core::ptr::write_volatile(&mut (*cb).return_value, -1);
                        x = syscall3(SYS_WRITE, fd, (*cb).aio_buf as usize, (*cb).aio_nbytes);
                    }
                    x
                }
                LIO_DSYNC => syscall1(SYS_FDATASYNC, fd),
                LIO_SYNC => syscall1(SYS_FSYNC, fd),
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
}

unsafe fn spawn_worker(first: *mut Req) -> c_int {
    with_signals_blocked(|| unsafe { spawn(worker, first as *mut c_void, core::ptr::null(), WORKER_STACK) })
}

unsafe extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let mut r = arg as *mut Req;
        loop {
            if !r.is_null() {
                let (ret, err) = do_io(r);
                LOCK.lock_always();
                let cb = (*r).cb;
                core::ptr::write_volatile(&mut (*cb).return_value, ret);
                core::ptr::write_volatile(&mut (*cb).error_code, if ret == -1 { err } else { 0 });
                notify(r);
                unlink_head(r, true);
                free_req(r);
            } else {
                LOCK.lock_always();
            }
            let s = st();
            let mut next = pop_run();
            if next.is_null() && s.idle_time >= 0 {
                s.idle += 1;
                let seq = IDLE_SEQ.load(Ordering::SeqCst);
                let ts = Timespec { tv_sec: s.idle_time as i64, tv_nsec: 0 };
                LOCK.unlock_always();
                syscall4(SYS_FUTEX, &IDLE_SEQ as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, seq as usize, &ts as *const Timespec as usize);
                LOCK.lock_always();
                s.idle -= 1;
                next = pop_run();
            }
            if next.is_null() {
                s.nthreads -= 1;
                LOCK.unlock_always();
                return core::ptr::null_mut();
            }
            (*next).state = RUNNING;
            if !s.run_head.is_null() {
                if s.idle > 0 {
                    wake_idle();
                } else if s.nthreads < s.max_threads && spawn_worker(core::ptr::null_mut()) == 0 {
                    s.nthreads += 1;
                }
            }
            LOCK.unlock_always();
            r = next;
        }
    }
}

unsafe extern "C" fn fork_prepare() {
    LOCK.lock_always();
}
unsafe extern "C" fn fork_parent() {
    LOCK.unlock_always();
}
unsafe extern "C" fn fork_child() {
    let s = st();
    s.nthreads = 0;
    s.idle = 0;
    s.fds = core::ptr::null_mut();
    s.run_head = core::ptr::null_mut();
    s.run_tail = core::ptr::null_mut();
    LOCK.unlock_always();
}

unsafe fn enqueue_locked(cb: *mut Aiocb, op: c_int) -> *mut Req {
    unsafe {
        if op == LIO_SYNC || op == LIO_DSYNC {
            (*cb).aio_reqprio = 0;
        } else if (*cb).aio_reqprio < 0 {
            core::ptr::write_volatile(&mut (*cb).error_code, EINVAL);
            core::ptr::write_volatile(&mut (*cb).return_value, -1);
            errno::set(EINVAL);
            return core::ptr::null_mut();
        }
        let prio = -(*cb).aio_reqprio;
        let s = st();
        if !HOOKED.swap(true, Ordering::AcqRel) {
            rusty_libc_core::process::register_fork_handlers(fork_prepare, fork_parent, fork_child);
        }
        let newp = get_elem();
        if newp.is_null() {
            errno::set(EAGAIN);
            return core::ptr::null_mut();
        }
        (*newp).cb = cb;
        (*newp).fd = (*cb).aio_fildes;
        (*newp).op = op;
        (*newp).prio = prio;
        (*cb).abs_prio = prio;
        (*cb).policy = 0;
        (*cb).aio_lio_opcode = op;
        core::ptr::write_volatile(&mut (*cb).error_code, EINPROGRESS);
        core::ptr::write_volatile(&mut (*cb).return_value, 0);
        let head = find_head((*newp).fd);
        if !head.is_null() {
            let mut p = head;
            while !(*p).next.is_null() && (*(*p).next).prio >= prio {
                p = (*p).next;
            }
            (*newp).next = (*p).next;
            (*p).next = newp;
            (*newp).state = QUEUED;
            return newp;
        }
        (*newp).fd_prev = core::ptr::null_mut();
        (*newp).fd_next = s.fds;
        if !s.fds.is_null() {
            (*s.fds).fd_prev = newp;
        }
        s.fds = newp;
        if s.nthreads < s.max_threads && s.idle == 0 {
            (*newp).state = RUNNING;
            let r = spawn_worker(newp);
            if r == 0 {
                s.nthreads += 1;
                return newp;
            }
            (*newp).state = READY;
            if s.nthreads == 0 {
                unlink_head(newp, false);
                free_req(newp);
                core::ptr::write_volatile(&mut (*cb).error_code, r);
                errno::set(r);
                return core::ptr::null_mut();
            }
        } else {
            (*newp).state = READY;
        }
        push_run(newp);
        if s.idle > 0 {
            wake_idle();
        }
        newp
    }
}

unsafe fn enqueue(cb: *mut Aiocb, op: c_int) -> c_int {
    unsafe {
        LOCK.lock_always();
        let r = enqueue_locked(cb, op);
        LOCK.unlock_always();
        if r.is_null() { -1 } else { 0 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read(cb: *mut Aiocb) -> c_int {
    unsafe { enqueue(cb, LIO_READ) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read64(cb: *mut Aiocb64) -> c_int {
    unsafe { enqueue(cb as *mut Aiocb, LIO_READ) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write(cb: *mut Aiocb) -> c_int {
    unsafe { enqueue(cb, LIO_WRITE) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write64(cb: *mut Aiocb64) -> c_int {
    unsafe { enqueue(cb as *mut Aiocb, LIO_WRITE) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync(op: c_int, cb: *mut Aiocb) -> c_int {
    unsafe {
        if op != O_DSYNC && op != O_SYNC {
            return fail(EINVAL);
        }
        if sci(syscall2(SYS_FCNTL, (*cb).aio_fildes as usize, F_GETFL)) == -1 {
            return fail(EBADF);
        }
        enqueue(cb, if op == O_SYNC { LIO_SYNC } else { LIO_DSYNC })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync64(op: c_int, cb: *mut Aiocb64) -> c_int {
    unsafe { aio_fsync(op, cb as *mut Aiocb) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error(cb: *const Aiocb) -> c_int {
    unsafe {
        LOCK.lock_always();
        let e = core::ptr::read_volatile(&(*cb).error_code);
        LOCK.unlock_always();
        e
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error64(cb: *const Aiocb64) -> c_int {
    unsafe { aio_error(cb as *const Aiocb) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return(cb: *mut Aiocb) -> ssize_t {
    unsafe { core::ptr::read_volatile(&(*cb).return_value) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return64(cb: *mut Aiocb64) -> ssize_t {
    unsafe { aio_return(cb as *mut Aiocb) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel(fildes: c_int, cb: *mut Aiocb) -> c_int {
    unsafe {
        if sci(syscall2(SYS_FCNTL, fildes as usize, F_GETFL)) == -1 {
            return fail(EBADF);
        }
        LOCK.lock_always();
        let mut result = AIO_ALLDONE;
        let mut dead: *mut Req = core::ptr::null_mut();
        if !cb.is_null() {
            if (*cb).aio_fildes != fildes {
                LOCK.unlock_always();
                return fail(EINVAL);
            } else if core::ptr::read_volatile(&(*cb).error_code) == EINPROGRESS {
                let head = find_head(fildes);
                if head.is_null() {
                    LOCK.unlock_always();
                    return fail(EINVAL);
                }
                let mut prev: *mut Req = core::ptr::null_mut();
                let mut req = head;
                while (*req).cb != cb {
                    prev = req;
                    req = (*req).next;
                    if req.is_null() {
                        LOCK.unlock_always();
                        return fail(EINVAL);
                    }
                }
                if (*req).state == RUNNING {
                    result = AIO_NOTCANCELED;
                } else {
                    if prev.is_null() {
                        remove_run(req);
                        unlink_head(req, true);
                    } else {
                        (*prev).next = (*req).next;
                    }
                    (*req).next = core::ptr::null_mut();
                    result = AIO_CANCELED;
                    dead = req;
                }
            }
        } else {
            let head = find_head(fildes);
            if !head.is_null() {
                if (*head).state == RUNNING {
                    result = AIO_NOTCANCELED;
                    dead = (*head).next;
                    (*head).next = core::ptr::null_mut();
                } else {
                    result = AIO_CANCELED;
                    remove_run(head);
                    unlink_head(head, false);
                    dead = head;
                }
            }
        }
        while !dead.is_null() {
            let r = dead;
            dead = (*r).next;
            let c = (*r).cb;
            core::ptr::write_volatile(&mut (*c).error_code, ECANCELED);
            core::ptr::write_volatile(&mut (*c).return_value, -1);
            notify(r);
            free_req(r);
        }
        LOCK.unlock_always();
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel64(fildes: c_int, cb: *mut Aiocb64) -> c_int {
    unsafe { aio_cancel(fildes, cb as *mut Aiocb) }
}

fn mono_now() -> Timespec {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { syscall2(SYS_CLOCK_GETTIME, 1, &mut ts as *mut Timespec as usize) };
    ts
}

struct SuspendCtx {
    list: *const *const Aiocb,
    n: usize,
    waits: *mut Wait,
    regs: *mut *mut Req,
    mem: *mut c_void,
}

unsafe fn unregister(c: &SuspendCtx) {
    unsafe {
        for i in 0..c.n {
            let req = *c.regs.add(i);
            if req.is_null() {
                continue;
            }
            let cb = *c.list.add(i);
            if core::ptr::read_volatile(&(*cb).error_code) != EINPROGRESS {
                continue;
            }
            let mut link: *mut *mut Wait = &mut (*req).waiters;
            while !(*link).is_null() && *link != c.waits.add(i) {
                link = &mut (**link).next;
            }
            if !(*link).is_null() {
                *link = (**link).next;
            }
        }
    }
}

unsafe extern "C" fn suspend_cleanup(arg: *mut c_void) {
    unsafe {
        let c = &*(arg as *const SuspendCtx);
        LOCK.lock_always();
        unregister(c);
        LOCK.unlock_always();
        rusty_libc_malloc::free(c.mem);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend(list: *const *const Aiocb, nent: c_int, timeout: *const Timespec) -> c_int {
    unsafe {
        if nent < 0 {
            return fail(EINVAL);
        }
        let n = nent as usize;
        if n == 0 {
            return 0;
        }
        let mem = rusty_libc_malloc::malloc(n * (core::mem::size_of::<Wait>() + core::mem::size_of::<*mut Req>()));
        if mem.is_null() {
            return fail(EAGAIN);
        }
        let waits = mem as *mut Wait;
        let regs = waits.add(n) as *mut *mut Req;
        for i in 0..n {
            *regs.add(i) = core::ptr::null_mut();
        }
        let ctx = SuspendCtx { list, n, waits, regs, mem };
        let seq = AtomicU32::new(0);
        let mut counter: u32 = 1;
        let mut result = 0;
        LOCK.lock_always();
        let mut stop = false;
        let mut any = false;
        for i in 0..n {
            let cb = *list.add(i);
            if cb.is_null() {
                continue;
            }
            if core::ptr::read_volatile(&(*cb).error_code) != EINPROGRESS {
                stop = true;
                break;
            }
            let req = find_req(cb as *mut Aiocb);
            if req.is_null() {
                stop = true;
                break;
            }
            let w = waits.add(i);
            *w = Wait { next: (*req).waiters, counter: &mut counter, seq: &seq, result: core::ptr::null_mut(), sigev: core::ptr::null_mut() };
            (*req).waiters = w;
            *regs.add(i) = req;
            any = true;
        }
        if !stop && any {
            let mut abs = Timespec { tv_sec: 0, tv_nsec: 0 };
            if !timeout.is_null() {
                abs = mono_now();
                abs.tv_sec += (*timeout).tv_sec;
                abs.tv_nsec += (*timeout).tv_nsec;
                if abs.tv_nsec >= 1_000_000_000 {
                    abs.tv_nsec -= 1_000_000_000;
                    abs.tv_sec += 1;
                }
            }
            let s = seq.load(Ordering::SeqCst);
            LOCK.unlock_always();
            let r = run_cancellable(&ctx, || {
                if !timeout.is_null() && abs.tv_sec < 0 {
                    return ETIMEDOUT;
                }
                let tp = if timeout.is_null() { 0 } else { &abs as *const Timespec as usize };
                let r = rusty_libc_core::tls::syscall_cp(SYS_FUTEX, &seq as *const AtomicU32 as usize, FUTEX_WAIT_BITSET_PRIVATE, s as usize, tp, 0, 0xffff_ffff);
                if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
            });
            LOCK.lock_always();
            result = match r {
                ETIMEDOUT => EAGAIN,
                EINVAL => EINVAL,
                EINTR => EINTR,
                _ => 0,
            };
        }
        unregister(&ctx);
        LOCK.unlock_always();
        rusty_libc_malloc::free(mem);
        if result != 0 {
            errno::set(result);
            return -1;
        }
        0
    }
}

unsafe fn run_cancellable(ctx: &SuspendCtx, body: impl FnOnce() -> c_int) -> c_int {
    unsafe { rusty_libc_pthread::cancel::with_cleanup(suspend_cleanup, ctx as *const SuspendCtx as *mut c_void, body) }
}

unsafe fn find_req(cb: *mut Aiocb) -> *mut Req {
    unsafe {
        let mut r = find_head((*cb).aio_fildes);
        while !r.is_null() && (*r).cb != cb {
            r = (*r).next;
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend64(list: *const *const Aiocb64, nent: c_int, timeout: *const Timespec) -> c_int {
    unsafe { aio_suspend(list as *const *const Aiocb, nent, timeout) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe { lio_listio_impl(mode, list, nent, sig) }
}

pub unsafe fn lio_listio_old(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe {
        if mode != LIO_WAIT && mode != LIO_NOWAIT {
            return fail(EINVAL);
        }
        lio_listio_impl(LIO_NOWAIT, list, nent, sig)
    }
}

unsafe fn lio_listio_impl(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe {
        if mode != LIO_WAIT && mode != LIO_NOWAIT {
            return fail(EINVAL);
        }
        let n = if nent < 0 { 0 } else { nent as usize };
        let defsig = SigEvent::none();
        let sig: *const SigEvent = if sig.is_null() { &defsig } else { sig };
        let mem = rusty_libc_malloc::malloc(n.max(1) * (core::mem::size_of::<*mut Req>() + core::mem::size_of::<Wait>()));
        if mem.is_null() {
            return fail(EAGAIN);
        }
        let reqs = mem as *mut *mut Req;
        let waits = reqs.add(n) as *mut Wait;
        let mut total: u32 = 0;
        let mut result: c_int = 0;
        LOCK.lock_always();
        for i in 0..n {
            let cb = *list.add(i);
            *reqs.add(i) = core::ptr::null_mut();
            if !cb.is_null() && (*cb).aio_lio_opcode != LIO_NOP {
                let r = enqueue_locked(cb, (*cb).aio_lio_opcode);
                if r.is_null() {
                    result = -1;
                } else {
                    *reqs.add(i) = r;
                    total += 1;
                }
            }
        }
        if total == 0 {
            LOCK.unlock_always();
            if mode == LIO_NOWAIT {
                notify_only(sig);
            }
            rusty_libc_malloc::free(mem);
            return result;
        }
        if mode == LIO_WAIT {
            let seq = AtomicU32::new(0);
            total = 0;
            for i in 0..n {
                let r = *reqs.add(i);
                if !r.is_null() {
                    *waits.add(i) = Wait { next: (*r).waiters, counter: &mut total, seq: &seq, result: &mut result, sigev: core::ptr::null_mut() };
                    (*r).waiters = waits.add(i);
                    total += 1;
                }
            }
            let mut interrupted = false;
            while core::ptr::read_volatile(&total) > 0 {
                let s = seq.load(Ordering::SeqCst);
                LOCK.unlock_always();
                let r = syscall4(SYS_FUTEX, &seq as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, s as usize, 0);
                LOCK.lock_always();
                if r as isize == -(EINTR as isize) {
                    interrupted = true;
                    break;
                }
            }
            if interrupted {
                let c = SuspendCtx { list: list as *const *const Aiocb, n, waits, regs: reqs, mem };
                unregister(&c);
                errno::set(EINTR);
                result = -1;
            } else if result != 0 {
                errno::set(EIO);
                result = -1;
            }
        } else {
            let al = rusty_libc_malloc::malloc(core::mem::size_of::<AsyncList>() + n * core::mem::size_of::<Wait>()) as *mut AsyncList;
            if al.is_null() {
                errno::set(EAGAIN);
                result = -1;
            } else {
                let aw = (al as *mut u8).add(core::mem::size_of::<AsyncList>()) as *mut Wait;
                (*al).sigev = *sig;
                let mut cnt = 0;
                for i in 0..n {
                    let r = *reqs.add(i);
                    if !r.is_null() {
                        *aw.add(i) = Wait { next: (*r).waiters, counter: &mut (*al).counter, seq: core::ptr::null(), result: core::ptr::null_mut(), sigev: &mut (*al).sigev };
                        (*r).waiters = aw.add(i);
                        cnt += 1;
                    }
                }
                (*al).counter = cnt;
            }
        }
        LOCK.unlock_always();
        rusty_libc_malloc::free(mem);
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio64(mode: c_int, list: *const *mut Aiocb64, nent: c_int, sig: *mut SigEvent) -> c_int {
    unsafe { lio_listio(mode, list as *const *mut Aiocb, nent, sig) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_init(init: *const AioInit) {
    unsafe {
        LOCK.lock_always();
        let s = st();
        if !s.pool_used {
            s.max_threads = if (*init).aio_threads < 1 { 1 } else { (*init).aio_threads };
            s.num = if ((*init).aio_num as usize) < ENTRIES_PER_ROW { ENTRIES_PER_ROW as c_int } else { (*init).aio_num & !(ENTRIES_PER_ROW as c_int - 1) };
        }
        if (*init).aio_idle_time != 0 {
            s.idle_time = (*init).aio_idle_time;
        }
        LOCK.unlock_always();
    }
}
