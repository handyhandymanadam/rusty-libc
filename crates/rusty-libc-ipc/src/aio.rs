//! POSIX asynchronous I/O (aio.h): aio_read, aio_write, aio_fsync, aio_error, aio_return, aio_cancel,
//! aio_suspend, lio_listio, aio_init and the 64-bit names. Built the way glibc's librt does it, with
//! the same observable behaviour: a pool of worker threads (at most `aio_threads`, 20 by default)
//! does the I/O with pread/pwrite/fsync/fdatasync; requests for one descriptor run one at a time in
//! submission order (a later request may overtake queued ones only through a larger priority, i.e. a
//! smaller `aio_reqprio`); an idle worker waits `aio_idle_time` seconds (1) before it exits.
//!
//! One global lock protects the request tables and `aio_error`; the error code of a request is
//! EINPROGRESS until the worker has stored the result. Completion notification: SIGEV_SIGNAL (a
//! queued signal to the process with si_code SI_ASYNCIO), SIGEV_THREAD (a new thread runs the user's
//! function), SIGEV_NONE. aio_suspend and lio_listio(LIO_WAIT) sleep on futexes.
//!
//! Differences from glibc (all logged in STATE.md by the owner): the worker threads do not take over
//! the scheduling priority of the request (`aio_reqprio` only orders the queue); a failure to start a
//! notification thread is reported through aio_error/aio_return like a failed signal (glibc ignores it);
//! the worker stack is 128 KiB.
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
/// Internal opcodes of aio_fsync requests (what glibc stores in `aio_lio_opcode`).
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

/// `struct aiocb` (168 bytes; the last fields are glibc's internal ones).
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

/// `struct aiocb64`: the same layout on x86-64.
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

/// `struct aioinit`.
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


// ---- the program's aiocb ----

/// A request's `struct aiocb`, owned by the program.
///
/// Invariant: the pointer is valid for reads and writes of the fields whenever a method is called. [`Cb::new`] is the only
/// constructor; its caller vouches for the exported call it is in, and the aio_read/aio_write/lio_listio contract keeps a
/// queued `aiocb` valid until its request has finished (a request record keeps a `Cb` only that long; a finished record's
/// `Cb` is only compared, never used). `error_code` and `return_value` are read by the program without the lock
/// (aio_return, its own polling), so they are accessed with volatile reads and writes, as glibc's C does.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cb(*mut Aiocb);

/// An entry of an aio_suspend or lio_listio list: null, or a `Cb` (same layout as the C `struct aiocb *`). Slices of them
/// are made only from the program's list at the exported function, whose contract gives each non-null entry `Cb`'s
/// invariant.
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
                    // SAFETY: the pointer is valid (the invariant of `Cb`).
                    unsafe { (*self.0).$get }
                }
                #[inline(always)]
                #[allow(dead_code)]
                fn $set(self, v: $t) {
                    // SAFETY: as in the getter.
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
    /// # Safety
    /// `p` points to an `aiocb` that stays valid while this handle (or a copy) is used: for the exported call that makes it,
    /// and once queued until its request has finished.
    #[inline(always)]
    unsafe fn new(p: *mut Aiocb) -> Cb {
        Cb(p)
    }

    /// The address of `error_code` (computed without dereferencing).
    #[inline(always)]
    fn error_ptr(self) -> *mut c_int {
        self.0.wrapping_byte_add(core::mem::offset_of!(Aiocb, error_code)).cast()
    }

    /// The address of `return_value`.
    #[inline(always)]
    fn ret_ptr(self) -> *mut isize {
        self.0.wrapping_byte_add(core::mem::offset_of!(Aiocb, return_value)).cast()
    }

    #[inline(always)]
    fn error(self) -> c_int {
        // SAFETY: a field of a valid aiocb (the invariant); volatile because other threads write it under the lock while
        // the program polls it.
        unsafe { self.error_ptr().read_volatile() }
    }

    #[inline(always)]
    fn set_error(self, e: c_int) {
        // SAFETY: as in `error`.
        unsafe { self.error_ptr().write_volatile(e) }
    }

    #[inline(always)]
    fn ret(self) -> isize {
        // SAFETY: as in `error`.
        unsafe { self.ret_ptr().read_volatile() }
    }

    #[inline(always)]
    fn set_ret(self, v: isize) {
        // SAFETY: as in `error`.
        unsafe { self.ret_ptr().write_volatile(v) }
    }

    /// Store a finished request's result: the return value, then the error code (a program polling without the lock sees
    /// the error code change last).
    #[inline(always)]
    fn finish(self, ret: isize, err: c_int) {
        self.set_ret(ret);
        self.set_error(err);
    }
}

// ---- request tables (all under LOCK) ----

const FREE: u8 = 0;
/// first request of its descriptor, waiting in the run list for a worker
const READY: u8 = 1;
/// a worker is doing its I/O (cannot be cancelled)
const RUNNING: u8 = 2;
/// behind an earlier request of the same descriptor
const QUEUED: u8 = 3;

/// The request tables, their lock and the waiter records, behind a privacy boundary: everything outside this module works
/// with the safe handles and methods below (Rust for Rustaceans p.233: soundness is checked at the privacy boundary).
mod tables {
    use super::{AtomicI32, AtomicU32, Cb, ENTRIES_PER_ROW, FREE, Ordering, READY, RawMutex, SigEvent, c_int, c_void};
    use core::marker::PhantomData;
    use core::ptr::NonNull;
    use rusty_libc_core::sync_cell::SyncCell;

    static LOCK: RawMutex = RawMutex::new();

    /// A request record. Rows of records come from malloc and are never freed, so a `ReqRef` (made only by
    /// [`State::get_elem`]) always points to a valid record. Every field is read and written with LOCK held, through
    /// `State`'s methods (an `&State` exists only under the lock), except `job`: it is written while the record is not yet
    /// running and read without the lock by the worker that runs it ([`ReqRef::job`]). No reference to a
    /// record is ever made: the methods copy single fields in and out, so a worker reading those three fields never
    /// overlaps a reference held elsewhere.
    pub(super) struct Req {
        job: Job,
        state: u8,
        prio: c_int,
        /// the next request of the same descriptor (valid on every request of a descriptor's chain)
        next: Option<ReqRef>,
        /// links of the descriptor list (valid on chain heads)
        fd_next: Option<ReqRef>,
        fd_prev: Option<ReqRef>,
        /// run list link
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

    /// What a worker needs to run a request.
    #[derive(Clone, Copy)]
    pub(super) struct Job {
        pub(super) cb: Cb,
        pub(super) fd: c_int,
        pub(super) op: c_int,
    }

    impl ReqRef {
        /// The request's job, read without the lock.
        ///
        /// # Safety
        /// The calling worker runs this request (its state is RUNNING and it was handed to this worker), so nothing writes
        /// `cb`, `fd` or `op` until the worker frees the record.
        pub(super) unsafe fn job(self) -> Job {
            // SAFETY: the record is valid (rows are never freed) and, by the caller's contract, its job is not written
            // meanwhile; a raw read of a copy, no reference.
            unsafe { (*self.0.as_ptr()).job }
        }

        /// The record as the worker's start argument.
        pub(super) fn as_arg(self) -> *mut c_void {
            self.0.as_ptr().cast()
        }

        /// The record a worker was started with (`as_arg`), or None for null.
        pub(super) fn from_arg(arg: *mut c_void) -> Option<ReqRef> {
            NonNull::new(arg.cast::<Req>()).map(ReqRef)
        }
    }

    /// Someone waiting for a request to finish: an `aio_suspend` or `lio_listio(LIO_WAIT)` caller (it sleeps on `seq`), or
    /// the final notification of an asynchronous `lio_listio` (`sigev` set).
    ///
    /// Records live in their owner's memory ([`WaitBlock`], or the block after an [`AsyncList`]); their targets
    /// (`counter`, `seq`, `result`, `sigev`) on the owner's stack or in that block. A record is reached only with LOCK held
    /// and only while it is registered on a request: the owner removes it under the lock before its memory goes away
    /// ([`State::unregister`]), or the request's completion takes it off the list.
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

    /// The block an asynchronous `lio_listio` leaves behind (its waiter records follow it); freed by the last completing
    /// request.
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

    /// The tables. Reached through [`Tables::st`] (LOCK held) or, in the child after fork, [`fork_child_reset`].
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

    /// Proof that this thread holds LOCK (Mara Bos, Rust Atomics and Locks ch. 4: a guard whose existence means the lock is
    /// held, with a private field so `lock` is the only way to get one). Dropping it releases the lock.
    pub(super) struct Tables(PhantomData<*const ()>);

    impl Tables {
        #[inline]
        pub(super) fn lock() -> Tables {
            LOCK.lock_always();
            Tables(PhantomData)
        }

        /// The tables, exclusively.
        #[inline(always)]
        pub(super) fn st(&mut self) -> &mut State {
            // SAFETY: LOCK is held while `self` exists, and a thread has at most one usable `Tables` (taking LOCK again
            // would deadlock; while `unlocked` runs, `self` is borrowed), so this is the only reference to the state.
            unsafe { &mut *ST.as_ptr() }
        }

        /// Run `f` with LOCK released, then take it again.
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

    /// The fork handlers: hold LOCK across fork; the child forgets the workers and the requests (it does not inherit the
    /// operations, POSIX) and releases the lock.
    pub(super) unsafe extern "C" fn fork_prepare() {
        LOCK.lock_always();
    }
    pub(super) unsafe extern "C" fn fork_parent() {
        LOCK.unlock_always();
    }
    pub(super) unsafe extern "C" fn fork_child() {
        // SAFETY: the child of fork has one thread, and LOCK (taken in fork_prepare) is still held: nothing else can reach
        // the state.
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
                        // SAFETY: `r` points into a request row, which is never freed (see `Req`); LOCK is held while an
                        // `&State` exists, so no other thread writes this field. A copy, no reference.
                        unsafe { (*r.0.as_ptr()).$get }
                    }
                    #[inline(always)]
                    #[allow(dead_code)]
                    pub(super) fn $set(&mut self, r: ReqRef, v: $t) {
                        // SAFETY: as in the getter; `&mut State` also excludes other accesses in this thread.
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
        /// A cleared record from the free list (a new row of records when it is empty), or None when malloc fails.
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
                    // SAFETY: `e` is record `i` of the new row (malloc's block is aligned for `Req`); the row is never freed.
                    unsafe { e.write(Req { next: self.freelist, ..Req::EMPTY }) };
                    self.freelist = NonNull::new(e).map(ReqRef);
                }
            }
            let r = self.freelist?;
            self.freelist = self.next(r);
            // SAFETY: a record of a row (see `Req`), off the free list now, so nothing else refers to it.
            unsafe { r.0.as_ptr().write(Req::EMPTY) };
            Some(r)
        }

        pub(super) fn free_req(&mut self, r: ReqRef) {
            self.set_state(r, FREE);
            self.set_waiters(r, None);
            self.set_next(r, self.freelist);
            self.freelist = Some(r);
        }

        /// The chain head of descriptor `fd`.
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

        /// The request for `cb`, if it is queued or running.
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

        /// Put new chain head `r` at the front of the descriptor list.
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

        /// Take head `r` out of the descriptor list. With `promote`, its successor becomes the head (ready to run);
        /// without, the successors are dropped from the list too (the caller owns the chain).
        pub(super) fn unlink_head(&mut self, r: ReqRef, promote: bool) {
            let n = if promote { self.next(r) } else { None };
            let (prev, next) = (self.fd_prev(r), self.fd_next(r));
            // the node that takes `r`'s place in the list: its successor, or nothing
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

        // ---- waiters ----

        /// A copy of a registered record.
        #[inline(always)]
        fn wait(&self, w: WaitRef) -> Wait {
            // SAFETY: a registered record is valid while LOCK is held (see `Wait`); a copy, no reference.
            unsafe { w.0.as_ptr().read() }
        }

        #[inline(always)]
        fn set_wait_next(&mut self, w: WaitRef, v: Option<WaitRef>) {
            // SAFETY: as in `wait`.
            unsafe { (*w.0.as_ptr()).next = v }
        }

        /// Fill record `w` and put it at the front of `r`'s waiters.
        ///
        /// # Safety
        /// `w` points to writable memory for a `Wait` and its targets are valid, both until the record is taken off the
        /// list again: by the request's completion ([`State::complete_waiters`]) or by the owner ([`State::unregister`])
        /// before the memory goes away.
        unsafe fn register(&mut self, r: ReqRef, w: WaitRef, counter: &AtomicU32, seq: Option<&AtomicU32>, result: Option<&AtomicI32>, sigev: *const SigEvent) {
            let rec = Wait {
                next: self.waiters(r),
                counter,
                seq: seq.map_or(core::ptr::null(), |s| s as *const AtomicU32),
                result: result.map_or(core::ptr::null(), |s| s as *const AtomicI32),
                sigev,
            };
            // SAFETY: writable memory for a record (the caller's contract).
            unsafe { w.0.as_ptr().write(rec) };
            self.set_waiters(r, Some(w));
        }

        /// Take the waiters of request `r` (whose result is stored, `failed` when its return value is -1) off its list and
        /// tell each one: a waiting caller's counter goes down and it is woken; an asynchronous lio_listio's counter goes
        /// down and its notification (`notify_only`) is sent, and its block freed, when it reaches zero.
        pub(super) fn complete_waiters(&mut self, r: ReqRef, failed: bool, notify_only: fn(&SigEvent) -> c_int) {
            let mut w = self.waiters(r);
            self.set_waiters(r, None);
            while let Some(wr) = w {
                let rec = self.wait(wr);
                // SAFETY (for the target accesses below): `rec` was registered until this moment and LOCK is held, so its
                // owner has not removed it and its targets are alive (see `Wait`).
                // SAFETY: see above (for an asynchronous lio_listio the counter is in its AsyncList block).
                let counter = unsafe { &*rec.counter };
                if rec.sigev.is_null() {
                    if failed && !rec.result.is_null() {
                        // SAFETY: see above.
                        unsafe { (*rec.result).store(-1, Ordering::Relaxed) };
                    }
                    counter.store(counter.load(Ordering::Relaxed).wrapping_sub(1), Ordering::Relaxed);
                    if !rec.seq.is_null() {
                        // SAFETY: see above. The waiter may go on and free `rec`'s memory as soon as it has the lock
                        // after this wake-up: nothing of it is used afterwards (`next` was copied).
                        let seq = unsafe { &*rec.seq };
                        seq.fetch_add(1, Ordering::SeqCst);
                        rusty_libc_core::lock::futex_wake(seq, 1);
                    }
                } else {
                    let left = counter.load(Ordering::Relaxed).wrapping_sub(1);
                    counter.store(left, Ordering::Relaxed);
                    if left == 0 {
                        // SAFETY: see above.
                        notify_only(unsafe { &*rec.sigev });
                        // SAFETY: the counter is the first field of the AsyncList block from malloc; this was its last
                        // registered record, so nothing refers to the block any more.
                        unsafe { rusty_libc_malloc::free(rec.counter.cast_mut().cast()) };
                    }
                }
                w = rec.next;
            }
        }

        /// Take the records of `blk` off the requests that are still in progress (`cbs[i]` is the aiocb of `blk`'s
        /// request `i`).
        pub(super) fn unregister(&mut self, blk: &WaitBlock, cbs: &[super::CbSlot]) {
            for i in 0..blk.n {
                let Some(req) = blk.reg(i) else { continue };
                // a slot with a registered request is not null
                let Some(cb) = cbs[i].get() else { continue };
                if cb.error() != super::EINPROGRESS {
                    continue;
                }
                // a request that finished and was started again no longer has our entry: nothing found
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

        /// Register `blk`'s record `i` on request `r`, for a caller that waits for it: it wakes on `seq` and counts down
        /// `counter`; `result` (if any) becomes -1 when the request fails.
        ///
        /// # Safety
        /// The caller removes the record ([`State::unregister`], under the lock) before `blk`, `counter`, `seq` or
        /// `result` go away, unless the request's completion has taken it off already.
        pub(super) unsafe fn register_waiter(&mut self, r: ReqRef, blk: &mut WaitBlock, i: usize, counter: &AtomicU32, seq: &AtomicU32, result: Option<&AtomicI32>) {
            blk.set_reg(i, Some(r));
            let w = blk.wait(i);
            // SAFETY: `w` is record `i` of `blk` (writable); the lifetimes are the caller's contract.
            unsafe { self.register(r, w, counter, Some(seq), result, core::ptr::null()) };
        }

        /// The block an asynchronous lio_listio leaves behind: an `AsyncList` with room for `n` records after it, and each
        /// request of `reqs` registered on it. The last completing request sends `sig` and frees the block. False when
        /// malloc fails (nothing registered).
        pub(super) fn register_async(&mut self, reqs: &WaitBlock, sig: &SigEvent) -> bool {
            let n = reqs.n;
            let al = crate::util::malloc(core::mem::size_of::<AsyncList>() + n * core::mem::size_of::<Wait>()).cast::<AsyncList>();
            if al.is_null() {
                return false;
            }
            // SAFETY: a fresh block with room for the AsyncList (malloc aligns for it).
            unsafe { al.write(AsyncList { counter: AtomicU32::new(0), sigev: *sig }) };
            // SAFETY: initialised just above; the block lives until the last registered request completes, and only shared
            // references to it are made (the counter is an atomic).
            let list = unsafe { &*al };
            let aw = al.wrapping_add(1).cast::<Wait>();
            let mut cnt = 0;
            for i in 0..n {
                if let Some(r) = reqs.reg(i) {
                    let w = WaitRef(NonNull::new(aw.wrapping_add(i)).expect("record in block"));
                    // SAFETY: record `i` of the block's room for `n`; the block is freed only when its counter reaches zero,
                    // after every record has been taken off by its request's completion.
                    unsafe { self.register(r, w, &list.counter, None, None, &raw const list.sigev) };
                    cnt += 1;
                }
            }
            list.counter.store(cnt, Ordering::Relaxed);
            true
        }
    }

    /// `n` waiter records and `n` request slots in one malloc block (an aio_suspend's or lio_listio's), freed by
    /// [`WaitBlock::release`] or, for a cancelled aio_suspend, by [`WaitBlock::release_raw`] in its cleanup handler.
    pub(super) struct WaitBlock {
        mem: NonNull<u8>,
        n: usize,
    }

    impl WaitBlock {
        /// A block for `n` entries (`n.max(1)` bytes' worth of room), slots empty. None when malloc fails.
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
            // SAFETY: slot `i` (< n, checked) lies inside the block, aligned (after `n` records of 8-byte fields), and only
            // this thread touches the slots.
            unsafe { self.reg_ptr(i).write(v) }
        }

        pub(super) fn reg(&self, i: usize) -> Option<ReqRef> {
            // SAFETY: as in `write_reg`; every slot was written by `new`.
            unsafe { self.reg_ptr(i).read() }
        }

        pub(super) fn set_reg(&mut self, i: usize, v: Option<ReqRef>) {
            self.write_reg(i, v);
        }

        /// The block's address, for a cleanup handler ([`WaitBlock::release_raw`]).
        pub(super) fn as_raw(&self) -> *mut c_void {
            self.mem.as_ptr().cast()
        }

        pub(super) fn release(self) {
            // SAFETY: our own block from malloc, not used again.
            unsafe { rusty_libc_malloc::free(self.as_raw()) };
        }

        /// Free a block by its address (a cancelled aio_suspend's cleanup handler: the frame that owns the block never
        /// resumes).
        ///
        /// # Safety
        /// `p` came from `as_raw` of a block that is not used again.
        pub(super) unsafe fn release_raw(p: *mut c_void) {
            // SAFETY: the caller's contract.
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

// ---- notification ----

struct NotifyJob {
    func: Option<unsafe extern "C" fn(SigVal)>,
    value: SigVal,
}

unsafe extern "C" fn notify_wrapper(arg: *mut c_void) -> *mut c_void {
    unblock_all();
    // SAFETY: `notify_only` made `arg` with heap_box(NotifyJob) and gave it to this thread alone.
    let j = unsafe { heap_take(arg.cast::<NotifyJob>()) };
    if let Some(f) = j.func {
        // SAFETY: the function and value the program put in its sigevent (the SIGEV_THREAD contract).
        unsafe { f(j.value) };
    }
    core::ptr::null_mut()
}

/// Send the completion notification described by `ev`; -1 with errno set if it cannot be sent.
fn notify_only(ev: &SigEvent) -> c_int {
    if ev.sigev_notify == SIGEV_THREAD {
        let nf = heap_box(NotifyJob { func: ev.sigev_notify_function, value: ev.sigev_value });
        if nf.is_null() {
            errno::set(ENOMEM);
            return -1;
        }
        // SAFETY: `sigev_notify_attributes` is null or an initialised attribute object (the SIGEV_THREAD contract the
        // program accepted when it queued the request).
        let r = unsafe { spawn(notify_wrapper, nf.cast(), ev.sigev_notify_attributes, 0) };
        if r != 0 {
            // SAFETY: the thread was not created, so `nf` is still ours.
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
        // SAFETY: reading the pointer member of the union reads its 8 bytes whatever the program stored (an int or a
        // pointer); glibc copies the same 8 bytes.
        let v = unsafe { ev.sigev_value.sival_ptr } as usize;
        info[24..32].copy_from_slice(&v.to_ne_bytes());
        // SAFETY: the kernel reads the local 128-byte siginfo.
        sci(unsafe { syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, ev.sigev_signo as usize, info.as_ptr() as usize) })
    } else {
        0
    }
}

/// Completion of request `r` (its result is stored): its own notification, then the waiters.
fn notify(s: &mut State, r: ReqRef) {
    let cb = s.job(r).cb;
    if notify_only(&cb.aio_sigevent()) != 0 {
        cb.set_error(errno::get());
        cb.set_ret(-1);
    }
    s.complete_waiters(r, cb.ret() == -1, notify_only);
}

// ---- workers ----

/// Do the I/O of a job without the lock: (return value, error number).
fn do_io(job: Job) -> (isize, c_int) {
    let cb = job.cb;
    let fd = job.fd as usize;
    loop {
        let ret = match job.op {
            LIO_READ | LIO_WRITE => {
                let (pnr, nr) = if job.op == LIO_READ { (SYS_PREAD64, SYS_READ) } else { (SYS_PWRITE64, SYS_WRITE) };
                let (buf, n) = (cb.aio_buf() as usize, cb.aio_nbytes());
                // SAFETY: the program's buffer of `aio_nbytes` bytes, valid until the request finishes (aio_read's
                // contract), goes to the kernel untouched.
                let mut x = unsafe { syscall4(pnr, fd, buf, n, cb.aio_offset() as usize) };
                if x as isize == -(ESPIPE as isize) {
                    // sockets and pipes: the kernel refuses an offset; behave like read. (glibc has stored the failed
                    // pread's -1 as the return value by now, so aio_return of a read still waiting on a pipe says -1:
                    // the same here.)
                    cb.set_ret(-1);
                    // SAFETY: as above.
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

/// Start a worker (with all signals blocked while it is created); `first` is the request it starts with (running) or None
/// (it takes work from the run list).
fn spawn_worker(first: Option<ReqRef>) -> c_int {
    let arg = first.map_or(core::ptr::null_mut(), ReqRef::as_arg);
    // SAFETY: no attribute (null): a detached thread with WORKER_STACK bytes of stack running `worker`.
    with_signals_blocked(|| unsafe { spawn(worker, arg, core::ptr::null(), WORKER_STACK) })
}

unsafe extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    let mut r = ReqRef::from_arg(arg);
    loop {
        let mut t = match r {
            Some(rr) => {
                // SAFETY: this worker runs `rr`: enqueue set it RUNNING and handed it over, or the loop below took it off
                // the run list and set it RUNNING; only this worker frees it.
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
            // more work waits: wake an idle worker or start another one
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

/// Queue request `cb` with operation `op` (lock held). None with errno set on failure.
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
        // behind the running or waiting requests of this descriptor, by priority
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
            // cannot start a thread and none is running: give up on this request
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

// ---- the C functions ----

/// Queue a read of `aio_nbytes` at `aio_offset` (or at the current position for a pipe or socket).
///
/// # Safety
/// `cb` points to an `aiocb` that stays valid, with its buffer, until the request has finished.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read(cb: *mut Aiocb) -> c_int {
    // SAFETY: the caller's contract is `Cb`'s.
    enqueue(unsafe { Cb::new(cb) }, LIO_READ)
}

/// # Safety
/// As [`aio_read`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read64(cb: *mut Aiocb64) -> c_int {
    // SAFETY: the same layout; the caller's contract is `Cb`'s.
    enqueue(unsafe { Cb::new(cb.cast()) }, LIO_READ)
}

/// # Safety
/// As [`aio_read`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write(cb: *mut Aiocb) -> c_int {
    // SAFETY: the caller's contract is `Cb`'s.
    enqueue(unsafe { Cb::new(cb) }, LIO_WRITE)
}

/// # Safety
/// As [`aio_read`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write64(cb: *mut Aiocb64) -> c_int {
    // SAFETY: the same layout; the caller's contract is `Cb`'s.
    enqueue(unsafe { Cb::new(cb.cast()) }, LIO_WRITE)
}

/// Queue an fsync (`op` O_SYNC) or fdatasync (O_DSYNC) of the descriptor; it runs after the earlier
/// requests for that descriptor.
///
/// # Safety
/// As [`aio_read`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync(op: c_int, cb: *mut Aiocb) -> c_int {
    if op != O_DSYNC && op != O_SYNC {
        return fail(EINVAL);
    }
    // SAFETY: the caller's contract is `Cb`'s.
    let cb = unsafe { Cb::new(cb) };
    if sci(kernel::fcntl_getfl(cb.aio_fildes() as usize)) == -1 {
        return fail(EBADF);
    }
    enqueue(cb, if op == O_SYNC { LIO_SYNC } else { LIO_DSYNC })
}

/// # Safety
/// As [`aio_read`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync64(op: c_int, cb: *mut Aiocb64) -> c_int {
    // SAFETY: the same layout; forwarded contract.
    unsafe { aio_fsync(op, cb.cast()) }
}

/// EINPROGRESS while the request runs, else 0 or the error number of the I/O.
///
/// # Safety
/// `cb` points to an `aiocb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error(cb: *const Aiocb) -> c_int {
    // SAFETY: the caller's contract (only read here).
    let cb = unsafe { Cb::new(cb.cast_mut()) };
    // taking the lock makes sure the worker has finished all its bookkeeping for the request
    let t = Tables::lock();
    let e = cb.error();
    drop(t);
    e
}

/// # Safety
/// As [`aio_error`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error64(cb: *const Aiocb64) -> c_int {
    // SAFETY: the same layout; forwarded contract.
    unsafe { aio_error(cb.cast()) }
}

/// The result of the operation (what read/write/fsync returned): meaningful once aio_error is not
/// EINPROGRESS. (Like glibc, nothing stops a second call from returning the same value.)
///
/// # Safety
/// `cb` points to an `aiocb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return(cb: *mut Aiocb) -> ssize_t {
    // SAFETY: the caller's contract.
    unsafe { Cb::new(cb) }.ret()
}

/// # Safety
/// As [`aio_return`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return64(cb: *mut Aiocb64) -> ssize_t {
    // SAFETY: the same layout; forwarded contract.
    unsafe { aio_return(cb.cast()) }
}

/// Cancel the request `cb`, or all requests of `fildes` when `cb` is null. Requests whose I/O is
/// already running cannot be cancelled (AIO_NOTCANCELED); cancelled ones finish with ECANCELED.
///
/// # Safety
/// `cb` is null or points to an `aiocb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel(fildes: c_int, cb: *mut Aiocb) -> c_int {
    if sci(kernel::fcntl_getfl(fildes as usize)) == -1 {
        return fail(EBADF);
    }
    // SAFETY: null (checked before any use) or an aiocb (the caller's contract).
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

/// aio_cancel with the lock held: the result, or the error number (EINVAL).
fn cancel_locked(s: &mut State, fildes: c_int, cb: Option<Cb>) -> Result<c_int, c_int> {
    let mut result = AIO_ALLDONE;
    // the chain of cancelled requests, linked through `next`
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

/// # Safety
/// As [`aio_cancel`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel64(fildes: c_int, cb: *mut Aiocb64) -> c_int {
    // SAFETY: the same layout; forwarded contract.
    unsafe { aio_cancel(fildes, cb.cast()) }
}

fn mono_now() -> Timespec {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: the clock writes one timespec into the local `ts`.
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(1, (&raw mut ts).cast()) };
    ts
}

/// What a cancelled aio_suspend's cleanup handler needs: its list and its waiter block.
struct SuspendCtx<'a> {
    cbs: &'a [CbSlot],
    blk: &'a WaitBlock,
}

unsafe extern "C" fn suspend_cleanup(arg: *mut c_void) {
    // SAFETY: `arg` is the `SuspendCtx` on the cancelled aio_suspend's stack, registered by `run_cancellable`; the frame
    // is still there while the cleanup handlers run.
    let c = unsafe { &*arg.cast::<SuspendCtx>() };
    let mut t = Tables::lock();
    t.st().unregister(c.blk, c.cbs);
    drop(t);
    // SAFETY: the block is not used again: the aio_suspend frame that owns it never resumes.
    unsafe { WaitBlock::release_raw(c.blk.as_raw()) };
}

/// Wait on aio_suspend's word `seq` while it holds `s`, until the absolute CLOCK_MONOTONIC time `abs` (None: no limit);
/// a cancellation point. The kernel's error number, or 0.
fn suspend_wait(seq: &AtomicU32, s: u32, abs: Option<&Timespec>) -> c_int {
    let tp = abs.map_or(0, |a| a as *const Timespec as usize);
    // SAFETY: the kernel reads the borrowed word and the borrowed timeout (or none).
    let r = unsafe { rusty_libc_core::tls::syscall_cp(SYS_FUTEX, seq as *const AtomicU32 as usize, FUTEX_WAIT_BITSET_PRIVATE, s as usize, tp, 0, 0xffff_ffff) };
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

/// Wait until one of the requests in `list` (null entries are skipped) has finished, or the timeout
/// (relative, as glibc measures it on CLOCK_MONOTONIC) is over: -1 with EAGAIN. Returns 0 at once when
/// a listed request is already done. Cancellation point (the waiters are removed on cancel).
///
/// # Safety
/// `list` points to `nent` pointers to `aiocb`s; `timeout` is null or a timespec.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend(list: *const *const Aiocb, nent: c_int, timeout: *const Timespec) -> c_int {
    if nent < 0 {
        return fail(EINVAL);
    }
    let n = nent as usize;
    if n == 0 {
        return 0;
    }
    // SAFETY: `list` points to `nent` pointers, each null or an aiocb (the caller's contract, which is `CbSlot`'s), unchanged
    // during the call; `CbSlot` has the pointer's layout.
    let cbs = unsafe { rusty_libc_core::ffi::slice(list.cast::<CbSlot>(), n) };
    // SAFETY: null or a timespec (the caller's contract); read only when the call waits, as before.
    let timeout = unsafe { timeout.as_ref() };
    match suspend(cbs, timeout) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

/// aio_suspend on the list `cbs`: Ok, or the error number.
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
        // SAFETY: the records are removed by `unregister` below (or by the cleanup handler on cancellation) before `blk`,
        // `counter` and `seq` go away.
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
        // a changed word (EAGAIN) is a completion; a signal gives EINTR (glibc's futex wait does too);
        // glibc aborts on an invalid timeout where the kernel says EINVAL: we return it
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

/// Run `body` with the waiters removed if the thread is cancelled inside it (our cancellation runs the
/// registered cleanup handlers; it does not unwind). Host unit tests have no thread descriptor of ours
/// behind %fs, so there it just runs `body`.
#[cfg(not(test))]
fn run_cancellable(ctx: &SuspendCtx, body: impl FnOnce() -> c_int) -> c_int {
    // SAFETY: `suspend_cleanup(ctx)` may run if the thread ends inside `body`: `ctx` is alive for the whole call, and the
    // handler only takes the lock (not held while `body` runs), removes the records and frees the block.
    unsafe { rusty_libc_pthread::cancel::with_cleanup(suspend_cleanup, (ctx as *const SuspendCtx).cast_mut().cast(), body) }
}

#[cfg(test)]
fn run_cancellable(_ctx: &SuspendCtx, body: impl FnOnce() -> c_int) -> c_int {
    let _ = suspend_cleanup;
    body()
}

/// # Safety
/// As [`aio_suspend`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend64(list: *const *const Aiocb64, nent: c_int, timeout: *const Timespec) -> c_int {
    // SAFETY: the same layout; forwarded contract.
    unsafe { aio_suspend(list.cast(), nent, timeout) }
}

/// Start the operations in `list` (each has its own `aio_lio_opcode`: LIO_READ, LIO_WRITE or LIO_NOP).
/// LIO_WAIT returns when all are done (-1 with EIO if one failed); LIO_NOWAIT returns at once and
/// sends the notification `sig` (if any) when the last one is done, besides each request's own.
///
/// # Safety
/// `list` points to `nent` pointers to `aiocb`s (null entries are skipped); `sig` is null or a sigevent.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { lio_listio_impl(mode, list, nent, sig) }
}

/// `lio_listio@GLIBC_2.2.5`: what glibc 2.43 does on x86-64 for the old version. It adds the internal flag
/// LIO_NO_INDIVIDUAL_EVENT (128) to the mode, but the code that would act on the flag is not compiled in (it needs
/// the compat range from glibc 2.1, which this architecture never had), so the flag only makes the mode differ from
/// LIO_WAIT: the list is then handled as with LIO_NOWAIT. `lio_listio(LIO_WAIT, ...)` of the old version returns
/// before the requests are done; the individual `aio_sigevent`s still fire. rusty-libc-cabi exports it under the old version.
///
/// # Safety
/// As [`lio_listio`].
pub unsafe fn lio_listio_old(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        return fail(EINVAL);
    }
    // SAFETY: forwarded contract.
    unsafe { lio_listio_impl(LIO_NOWAIT, list, nent, sig) }
}

/// # Safety
/// As [`lio_listio`].
unsafe fn lio_listio_impl(mode: c_int, list: *const *mut Aiocb, nent: c_int, sig: *mut SigEvent) -> c_int {
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        return fail(EINVAL);
    }
    let n = if nent < 0 { 0 } else { nent as usize };
    // SAFETY: `list` points to `nent` pointers, each null or an aiocb that stays valid until its request has finished (the
    // caller's contract, which is `CbSlot`'s); with no entries nothing is read.
    let cbs = unsafe { rusty_libc_core::ffi::slice(list.cast::<CbSlot>(), n) };
    // SAFETY: null or a sigevent (the caller's contract), read while the call runs.
    let sig = unsafe { sig.as_ref() }.copied().unwrap_or(SigEvent::none());
    listio(mode, cbs, &sig)
}

/// lio_listio on the list `cbs`.
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
                // SAFETY: the records are taken off by their requests' completions (the loop below waits for all of them)
                // or, after a signal, by `unregister` before `blk`, `total`, `seq` and `result` go away.
                unsafe { s.register_waiter(r, &mut blk, i, &total, &seq, Some(&result)) };
                total.store(total.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
            }
        }
        // cancellation is deferred for the whole wait (as in glibc): plain system calls. A signal
        // ends the wait with EINTR (the requests go on); the waiters must then be taken out of the
        // requests, because they live in this call's memory.
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

/// # Safety
/// As [`lio_listio`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio64(mode: c_int, list: *const *mut Aiocb64, nent: c_int, sig: *mut SigEvent) -> c_int {
    // SAFETY: the same layout; forwarded contract.
    unsafe { lio_listio(mode, list.cast(), nent, sig) }
}

/// Tune the implementation: the maximum number of worker threads, the size of the first request pool
/// (both only before the first request), and the idle time of a worker in seconds.
///
/// # Safety
/// `init` points to a `struct aioinit`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn aio_init(init: *const AioInit) {
    // SAFETY: the caller's contract (read once; the structure is plain integers).
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
