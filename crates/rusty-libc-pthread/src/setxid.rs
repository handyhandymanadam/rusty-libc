//! set*id for every thread (glibc 2.43's `__nptl_setxid`, nptl/nptl_setxid.c; behaviour reference only, own code).
//!
//! Linux keeps credentials per thread, but POSIX says setuid and friends change the process. Once the process has had a
//! second thread, rusty-libc-sys's set*id functions come here (through `rusty_libc_core::unistd::SETXID_HOOK`):
//! * with the thread list lock held, every other thread that is not exiting is marked (`XID_SET` in `Thread::xid`); a
//!   thread still being created is waited for until it runs (`setxid_futex`: -1 until the new thread starts, -2 while a
//!   caller waits for that);
//! * each marked thread is sent SIGSETXID (33) with tgkill; its handler makes the same system call, records the result,
//!   clears its mark and counts down. The caller waits for the count to reach 0 and repeats until no thread was signalled;
//! * the marks are cleared, then the caller makes the call itself last (it may lose the right to signal the others);
//! * every thread must get the same result (all succeed or all fail with the same errno), otherwise the process aborts:
//!   the credentials would differ between threads.
//!
//! An exiting thread that was marked waits until its handler has run or the mark is cleared, so that a signal already
//! counted is always answered. Exiting threads (`XID_EXITING`, set where glibc sets EXITING_BITMASK) are skipped.
//!
//! Safe core: mark, unmark and signal work on the threads' atomic words; unsafe is left for reaching those words from a
//! descriptor pointer, the signal handler's siginfo and command pointer, and the system calls.
use crate::sys::*;
use crate::thread::{Thread, current_thread, field_of, shared_field, tid_word};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
use rusty_libc_core::signal::{KSigaction, SA_RESTORER};

/// `Thread::xid`: a set*id call wants this thread to answer (glibc's SETXID_BITMASK).
pub const XID_SET: u32 = 1;
/// `Thread::xid`: the thread is exiting; set*id calls leave it alone (glibc's EXITING_BITMASK as setxid reads it).
pub const XID_EXITING: u32 = 2;

/// `Thread::setxid_futex` of a thread that has not started running yet.
pub const FUTEX_NOT_STARTED: u32 = -1i32 as u32;
/// ... and of one a set*id caller is waiting on to start.
const FUTEX_START_WAITED: u32 = -2i32 as u32;

const SIGSETXID: c_int = crate::cancel::SIGSETXID;
const SI_TKILL: i32 = -6;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;

/// glibc's struct xid_command.
#[repr(C)]
struct XidCmd {
    nr: usize,
    id: [usize; 3],
    cntr: AtomicU32,
    error: AtomicI32,
}

/// The command in progress (only read by the handler while a caller holds the thread list lock).
static XIDCMD: AtomicPtr<XidCmd> = AtomicPtr::new(core::ptr::null_mut());

/// Install the SIGSETXID handler and route rusty-libc-sys's set*id calls here (once, at the first pthread_create, as
/// glibc's late_init).
pub fn init() {
    static DONE: AtomicU32 = AtomicU32::new(0);
    if DONE.load(Ordering::Acquire) != 0 || DONE.swap(1, Ordering::AcqRel) != 0 {
        return;
    }
    let act = KSigaction {
        handler: handler as *const () as usize,
        flags: SA_ONSTACK | SA_SIGINFO | SA_RESTART | SA_RESTORER,
        restorer: crate::cancel::restorer(),
        mask: 0,
    };
    // rt_sigaction(SIGSETXID, &act, NULL) as glibc's late_init (no old action asked for)
    // SAFETY: the kernel reads the borrowed sigaction; the handler and restorer are this module's functions.
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGACTION, SIGSETXID as usize, &act as *const KSigaction as usize, 0, 8) };
    // the parent process may have left the internal signals blocked: unblock them (as glibc), or a set*id call would wait
    // forever for threads that never take SIGSETXID
    let set: u64 = crate::cancel::INTERNAL_SIGNALS;
    // SAFETY: the kernel reads the borrowed 8-byte mask; no old mask is asked for.
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 1, &set as *const u64 as usize, 0, 8) };
    rusty_libc_core::unistd::SETXID_HOOK.store(setxid as unsafe extern "C" fn(usize, usize, usize, usize) -> usize as usize, Ordering::Release);
}

#[inline]
fn errno_raw(r: usize) -> i32 {
    errno_of(r)
}

/// glibc's setxid_error: all results must agree; a mismatch aborts.
fn record_error(cmd: &XidCmd, error: i32) {
    loop {
        let old = cmd.error.load(Ordering::Acquire);
        if old == error {
            return;
        }
        if old != -1 {
            let _keep = core::hint::black_box(error);
            rusty_libc_core::process::abort();
        }
        if cmd.error.compare_exchange(-1, error, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
}

/// The set*id system call of a command (a credential call with three plain-value arguments).
fn xid_call(nr: usize, id: [usize; 3]) -> usize {
    // SAFETY: `nr` is one of the set*id system calls rusty-libc-sys routes here; their arguments are plain ids (setgroups
    // passes a pointer to the caller's array, which stays valid while the command runs: the caller waits for every thread).
    unsafe { rusty_libc_core::syscall::syscall3(nr, id[0], id[1], id[2]) }
}

/// The calling thread's `xid` and `setxid_futex` words.
fn my_words() -> (&'static AtomicU32, &'static AtomicU32) {
    let me = current_thread();
    // SAFETY: the calling thread's own descriptor lives as long as the thread; both fields are atomics.
    let x = unsafe { shared_field(field_of!(me, xid: AtomicU32)) };
    // SAFETY: as above.
    let f = unsafe { shared_field(field_of!(me, setxid_futex: AtomicU32)) };
    (x, f)
}

extern "C" fn handler(sig: c_int, info: *const u8, _uc: *mut u8) {
    // only the tgkill of a set*id call in this process (as glibc's checks)
    // SAFETY: the kernel passes a valid siginfo_t (SA_SIGINFO): si_code at offset 8, si_pid at 16.
    let si_code = unsafe { *(info.wrapping_add(8) as *const i32) };
    // SAFETY: as above.
    let si_pid = unsafe { *(info.wrapping_add(16) as *const i32) };
    if sig != SIGSETXID || si_pid != getpid() || si_code != SI_TKILL {
        return;
    }
    // SAFETY: XIDCMD points to the command on the stack of the set*id caller, which holds the thread list lock and waits
    // for this handler's count-down before it returns (so the command outlives this use).
    let cmd = unsafe { &*XIDCMD.load(Ordering::Acquire) };
    let r = xid_call(cmd.nr, cmd.id);
    record_error(cmd, errno_raw(r));
    let (x, f) = my_words();
    x.fetch_and(!XID_SET, Ordering::AcqRel);
    f.store(1, Ordering::Release);
    futex_wake(f, 1, true);
    if cmd.cntr.fetch_sub(1, Ordering::AcqRel) == 1 {
        futex_wake(&cmd.cntr, 1, true);
    }
}

/// The `xid` and `setxid_futex` words of thread `t`.
///
/// # Safety
/// `t` is a thread of the list (the caller holds the thread list lock, so it is not reclaimed meanwhile).
unsafe fn words<'a>(t: *mut Thread) -> (&'a AtomicU32, &'a AtomicU32) {
    // SAFETY: forwarded contract; both fields are atomics.
    let x = unsafe { shared_field(field_of!(t, xid: AtomicU32)) };
    // SAFETY: as above.
    let f = unsafe { shared_field(field_of!(t, setxid_futex: AtomicU32)) };
    (x, f)
}

/// glibc's setxid_mark_thread.
fn mark(x: &AtomicU32, f: &AtomicU32) {
    // wait until the thread runs
    if f.load(Ordering::Acquire) == FUTEX_NOT_STARTED && f.compare_exchange(FUTEX_NOT_STARTED, FUTEX_START_WAITED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        while f.load(Ordering::Acquire) == FUTEX_START_WAITED {
            futex_wait(f, FUTEX_START_WAITED, true);
        }
    }
    // the thread may not exit before its handler has run
    f.store(0, Ordering::Release);
    let mut cur = x.load(Ordering::Acquire);
    loop {
        if cur & XID_EXITING != 0 {
            if cur & XID_SET == 0 {
                f.store(1, Ordering::Release);
                futex_wake(f, 1, true);
            }
            return;
        }
        match x.compare_exchange(cur, cur | XID_SET, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(v) => cur = v,
        }
    }
}

/// glibc's setxid_unmark_thread.
fn unmark(x: &AtomicU32, f: &AtomicU32) {
    let mut cur = x.load(Ordering::Acquire);
    loop {
        if cur & XID_SET == 0 {
            return;
        }
        match x.compare_exchange(cur, cur & !XID_SET, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
    f.store(1, Ordering::Release);
    futex_wake(f, 1, true);
}

/// glibc's setxid_signal_thread: 1 if the thread was sent the signal.
fn signal(cmd: &XidCmd, x: &AtomicU32, tid: &AtomicI32) -> u32 {
    if x.load(Ordering::Acquire) & XID_SET == 0 {
        return 0;
    }
    // (a thread that has not started or has already ended makes tgkill fail)
    if tgkill(getpid(), tid.load(Ordering::Acquire), SIGSETXID) == 0 {
        cmd.cntr.fetch_add(1, Ordering::AcqRel);
        1
    } else {
        0
    }
}

/// The hook: the call on every thread, the caller last. Raw kernel result of the caller's call.
unsafe extern "C" fn setxid(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let cmd = XidCmd { nr, id: [a1, a2, a3], cntr: AtomicU32::new(0), error: AtomicI32::new(-1) };
    let body = |for_each: crate::thread::Walker<'_>| {
        XIDCMD.store(&cmd as *const XidCmd as *mut XidCmd, Ordering::Release);
        // SAFETY (each closure below): the walker hands out threads of the list while the list lock is held.
        for_each(&mut |t| {
            // SAFETY: see above.
            let (x, f) = unsafe { words(t) };
            mark(x, f)
        });
        loop {
            let mut signalled = 0;
            for_each(&mut |t| {
                // SAFETY: see above.
                let (x, _) = unsafe { words(t) };
                // SAFETY: see above.
                signalled += signal(&cmd, x, unsafe { tid_word(t) })
            });
            let mut cur = cmd.cntr.load(Ordering::Acquire);
            while cur != 0 {
                futex_wait(&cmd.cntr, cur, true);
                cur = cmd.cntr.load(Ordering::Acquire);
            }
            if signalled == 0 {
                break;
            }
        }
        for_each(&mut |t| {
            // SAFETY: see above.
            let (x, f) = unsafe { words(t) };
            unmark(x, f)
        });
        let r = xid_call(nr, [a1, a2, a3]);
        record_error(&cmd, errno_raw(r));
        r
    };
    crate::thread::with_thread_list(body)
}

/// An exiting thread that a set*id call has marked waits until it has answered (glibc's start_thread does this before
/// its last steps). `t` is the calling thread.
///
/// # Safety
/// `t` is the calling thread's descriptor.
pub unsafe fn exit_wait(t: *mut Thread) {
    // SAFETY: forwarded contract (a live descriptor).
    let (x, f) = unsafe { words(t) };
    if x.load(Ordering::Acquire) & XID_SET != 0 {
        loop {
            futex_wait(f, 0, true);
            if x.load(Ordering::Acquire) & XID_SET == 0 {
                break;
            }
        }
        f.store(0, Ordering::Release);
    }
}

/// The calling thread is exiting from here on: set*id calls skip it.
///
/// # Safety
/// `t` is a live thread descriptor.
#[inline]
pub unsafe fn set_exiting(t: *mut Thread) {
    // SAFETY: forwarded contract; `xid` is an atomic.
    unsafe { shared_field(field_of!(t, xid: AtomicU32)) }.fetch_or(XID_EXITING, Ordering::AcqRel);
}

/// A new thread starts running: set*id calls may mark it from now on (wakes a caller waiting for that).
///
/// # Safety
/// `t` is a live thread descriptor.
#[inline]
pub unsafe fn thread_started(t: *mut Thread) {
    // SAFETY: forwarded contract; `setxid_futex` is an atomic.
    let f = unsafe { shared_field(field_of!(t, setxid_futex: AtomicU32)) };
    if f.swap(0, Ordering::AcqRel) == FUTEX_START_WAITED {
        futex_wake(f, 1, true);
    }
}
