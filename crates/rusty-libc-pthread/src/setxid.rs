use crate::sys::*;
use crate::thread::{Thread, current_thread, field_of, shared_field, tid_word};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};
use rusty_libc_core::signal::{KSigaction, SA_RESTORER};

pub const XID_SET: u32 = 1;
pub const XID_EXITING: u32 = 2;

pub const FUTEX_NOT_STARTED: u32 = -1i32 as u32;
const FUTEX_START_WAITED: u32 = -2i32 as u32;

const SIGSETXID: c_int = crate::cancel::SIGSETXID;
const SI_TKILL: i32 = -6;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;

#[repr(C)]
struct XidCmd {
    nr: usize,
    id: [usize; 3],
    cntr: AtomicU32,
    error: AtomicI32,
}

static XIDCMD: AtomicPtr<XidCmd> = AtomicPtr::new(core::ptr::null_mut());

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
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGACTION, SIGSETXID as usize, &act as *const KSigaction as usize, 0, 8) };
    let set: u64 = crate::cancel::INTERNAL_SIGNALS;
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 1, &set as *const u64 as usize, 0, 8) };
    rusty_libc_core::unistd::SETXID_HOOK.store(setxid as unsafe extern "C" fn(usize, usize, usize, usize) -> usize as usize, Ordering::Release);
}

#[inline]
fn errno_raw(r: usize) -> i32 {
    errno_of(r)
}

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

fn xid_call(nr: usize, id: [usize; 3]) -> usize {
    unsafe { rusty_libc_core::syscall::syscall3(nr, id[0], id[1], id[2]) }
}

fn my_words() -> (&'static AtomicU32, &'static AtomicU32) {
    let me = current_thread();
    let x = unsafe { shared_field(field_of!(me, xid: AtomicU32)) };
    let f = unsafe { shared_field(field_of!(me, setxid_futex: AtomicU32)) };
    (x, f)
}

extern "C" fn handler(sig: c_int, info: *const u8, _uc: *mut u8) {
    let si_code = unsafe { *(info.wrapping_add(8) as *const i32) };
    let si_pid = unsafe { *(info.wrapping_add(16) as *const i32) };
    if sig != SIGSETXID || si_pid != getpid() || si_code != SI_TKILL {
        return;
    }
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

unsafe fn words<'a>(t: *mut Thread) -> (&'a AtomicU32, &'a AtomicU32) {
    let x = unsafe { shared_field(field_of!(t, xid: AtomicU32)) };
    let f = unsafe { shared_field(field_of!(t, setxid_futex: AtomicU32)) };
    (x, f)
}

fn mark(x: &AtomicU32, f: &AtomicU32) {
    if f.load(Ordering::Acquire) == FUTEX_NOT_STARTED && f.compare_exchange(FUTEX_NOT_STARTED, FUTEX_START_WAITED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        while f.load(Ordering::Acquire) == FUTEX_START_WAITED {
            futex_wait(f, FUTEX_START_WAITED, true);
        }
    }
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

fn signal(cmd: &XidCmd, x: &AtomicU32, tid: &AtomicI32) -> u32 {
    if x.load(Ordering::Acquire) & XID_SET == 0 {
        return 0;
    }
    if tgkill(getpid(), tid.load(Ordering::Acquire), SIGSETXID) == 0 {
        cmd.cntr.fetch_add(1, Ordering::AcqRel);
        1
    } else {
        0
    }
}

unsafe extern "C" fn setxid(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let cmd = XidCmd { nr, id: [a1, a2, a3], cntr: AtomicU32::new(0), error: AtomicI32::new(-1) };
    let body = |for_each: crate::thread::Walker<'_>| {
        XIDCMD.store(&cmd as *const XidCmd as *mut XidCmd, Ordering::Release);
        for_each(&mut |t| {
            let (x, f) = unsafe { words(t) };
            mark(x, f)
        });
        loop {
            let mut signalled = 0;
            for_each(&mut |t| {
                let (x, _) = unsafe { words(t) };
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
            let (x, f) = unsafe { words(t) };
            unmark(x, f)
        });
        let r = xid_call(nr, [a1, a2, a3]);
        record_error(&cmd, errno_raw(r));
        r
    };
    crate::thread::with_thread_list(body)
}

pub unsafe fn exit_wait(t: *mut Thread) {
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

#[inline]
pub unsafe fn set_exiting(t: *mut Thread) {
    unsafe { shared_field(field_of!(t, xid: AtomicU32)) }.fetch_or(XID_EXITING, Ordering::AcqRel);
}

#[inline]
pub unsafe fn thread_started(t: *mut Thread) {
    let f = unsafe { shared_field(field_of!(t, setxid_futex: AtomicU32)) };
    if f.swap(0, Ordering::AcqRel) == FUTEX_START_WAITED {
        futex_wake(f, 1, true);
    }
}
