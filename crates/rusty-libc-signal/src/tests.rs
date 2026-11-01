#![allow(clippy::manual_dangling_ptr, clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
//! Host tests: our functions against the host glibc (the `h` module declares the host's symbols
//! with our types). The signal dispositions are process wide, so every test that installs a
//! handler or blocks a signal takes `lock()` and puts everything back. Signals are sent with
//! `raise` (thread directed) wherever the test needs to know which thread runs the handler.
//! `setjmp`/`longjmp` cannot be called safely from Rust test code; they are tested in the Rust
//! runtime program (tests/rust-signal) and the C differential test.
use crate::action::*;
use crate::consts::*;
use crate::context::*;
use crate::names::*;
use crate::rt::*;
use crate::send::*;
use crate::sigset::*;
use crate::stack::*;
use crate::types::*;
use crate::wait::*;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::{size_of, zeroed};
use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};

mod h {
    use super::*;
    unsafe extern "C" {
        pub fn sigemptyset(set: *mut Sigset) -> c_int;
        pub fn sigfillset(set: *mut Sigset) -> c_int;
        pub fn sigaddset(set: *mut Sigset, signo: c_int) -> c_int;
        pub fn sigdelset(set: *mut Sigset, signo: c_int) -> c_int;
        pub fn sigismember(set: *const Sigset, signo: c_int) -> c_int;
        pub fn sigisemptyset(set: *const Sigset) -> c_int;
        pub fn sigandset(d: *mut Sigset, l: *const Sigset, r: *const Sigset) -> c_int;
        pub fn sigorset(d: *mut Sigset, l: *const Sigset, r: *const Sigset) -> c_int;
        pub fn sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int;
        pub fn __sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int;
        pub fn signal(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn bsd_signal(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn ssignal(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn sysv_signal(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn __sysv_signal(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn siginterrupt(sig: c_int, i: c_int) -> c_int;
        pub fn sigset(sig: c_int, h: Sighandler) -> Sighandler;
        pub fn sighold(sig: c_int) -> c_int;
        pub fn sigrelse(sig: c_int) -> c_int;
        pub fn sigignore(sig: c_int) -> c_int;
        pub fn sigblock(m: c_int) -> c_int;
        pub fn sigsetmask(m: c_int) -> c_int;
        pub fn siggetmask() -> c_int;
        pub fn __sigpause(m: c_int, is_sig: c_int) -> c_int;
        pub fn sigpause(m: c_int) -> c_int;
        pub fn __xpg_sigpause(m: c_int) -> c_int;
        pub fn sigreturn(p: *mut Sigcontext) -> c_int;
        pub fn sigprocmask(how: c_int, set: *const Sigset, old: *mut Sigset) -> c_int;
        pub fn sigpending(set: *mut Sigset) -> c_int;
        pub fn sigsuspend(set: *const Sigset) -> c_int;
        pub fn sigwait(set: *const Sigset, sig: *mut c_int) -> c_int;
        pub fn sigtimedwait(set: *const Sigset, info: *mut Siginfo, t: *const Timespec) -> c_int;
        pub fn sigqueue(pid: c_int, sig: c_int, v: Sigval) -> c_int;
        pub fn kill(pid: c_int, sig: c_int) -> c_int;
        pub fn killpg(pg: c_int, sig: c_int) -> c_int;
        pub fn raise(sig: c_int) -> c_int;
        pub fn gsignal(sig: c_int) -> c_int;
        pub fn tgkill(tgid: c_int, tid: c_int, sig: c_int) -> c_int;
        pub fn sigaltstack(ss: *const StackT, old: *mut StackT) -> c_int;
        pub fn sigstack(ss: *const Sigstack, old: *mut Sigstack) -> c_int;
        pub fn sigabbrev_np(sig: c_int) -> *const c_char;
        pub fn sigdescr_np(sig: c_int) -> *const c_char;
        pub fn psignal(sig: c_int, s: *const c_char);
        pub fn psiginfo(i: *const Siginfo, s: *const c_char);
        pub fn __libc_current_sigrtmin() -> c_int;
        pub fn __libc_current_sigrtmax() -> c_int;
        pub fn getcontext(u: *mut UContext) -> c_int;
        pub fn makecontext(u: *mut UContext, f: extern "C" fn(), argc: c_int, ...);
        pub fn __errno_location() -> *mut c_int;
        pub fn getpid() -> c_int;
        pub fn getuid() -> u32;
        pub fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
        pub fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
        pub fn pipe(fds: *mut c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn dup(fd: c_int) -> c_int;
        pub fn dup2(a: c_int, b: c_int) -> c_int;
        pub fn usleep(us: u32) -> c_int;
    }
}

static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn host_errno() -> c_int {
    unsafe { *h::__errno_location() }
}

fn gettid() -> c_int {
    unsafe { rusty_libc_core::syscall::syscall0(186) as c_int }
}

/// Run `f` in a forked child with a single thread (signals sent to the process then reach that
/// thread, and no other test sees its dispositions or masks); a failure inside is reported by the
/// parent. The child leaves with `_exit`, never running the test harness's cleanup.
fn in_child(f: impl FnOnce()) {
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(h::pipe(fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            h::close(fds[0]);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            if let Err(e) = r {
                let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                h::write(fds[1], msg.as_ptr().cast(), msg.len());
                libc::_exit(1);
            }
            libc::_exit(0);
        }
        h::close(fds[1]);
        let mut out = vec![];
        let mut buf = [0u8; 1024];
        loop {
            let n = h::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        h::close(fds[0]);
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child failed (status {status:#x}): {}", String::from_utf8_lossy(&out));
    }
}

/// The result of a call and the errno it left (each side reads its own errno variable).
type Out = (i64, c_int);

macro_rules! ours {
    ($e:expr) => {{
        rusty_libc_core::errno::set(0);
        let r = $e;
        (r as i64, rusty_libc_core::errno::get())
    }};
}
macro_rules! host {
    ($e:expr) => {{
        unsafe { *h::__errno_location() = 0 };
        let r = $e;
        (r as i64, host_errno())
    }};
}

/// Compare a failing call exactly, a succeeding one by result only (errno is garbage after success).
fn same(a: Out, b: Out, what: &str) {
    assert_eq!(a.0, b.0, "{what}: result ours {a:?} host {b:?}");
    if a.0 == -1 || a.0 == SIG_ERR as i64 {
        assert_eq!(a.1, b.1, "{what}: errno ours {a:?} host {b:?}");
    }
}

fn filled(pattern: u8) -> Sigset {
    let mut s: Sigset = unsafe { zeroed() };
    unsafe { core::ptr::write_bytes(&mut s as *mut Sigset as *mut u8, pattern, size_of::<Sigset>()) };
    s
}

// ---------------------------------------------------------------------------------- layouts

#[test]
fn layouts_match_the_host() {
    assert_eq!(size_of::<Sigaction>(), size_of::<libc::sigaction>());
    assert_eq!(size_of::<Sigset>(), size_of::<libc::sigset_t>());
    assert_eq!(size_of::<Siginfo>(), size_of::<libc::siginfo_t>());
    assert_eq!(size_of::<StackT>(), size_of::<libc::stack_t>());
    assert_eq!(size_of::<UContext>(), size_of::<libc::ucontext_t>());
    assert_eq!(core::mem::offset_of!(Sigaction, sa_flags), core::mem::offset_of!(libc::sigaction, sa_flags));
    assert_eq!(core::mem::offset_of!(Sigaction, sa_restorer), core::mem::offset_of!(libc::sigaction, sa_restorer));
    assert_eq!(core::mem::offset_of!(UContext, uc_sigmask), core::mem::offset_of!(libc::ucontext_t, uc_sigmask));
    assert_eq!(core::mem::offset_of!(UContext, uc_stack), core::mem::offset_of!(libc::ucontext_t, uc_stack));
    assert_eq!(NGREG, 23);
    for (a, b) in [(REG_RIP, libc::REG_RIP), (REG_RSP, libc::REG_RSP), (REG_RBX, libc::REG_RBX), (REG_R8, libc::REG_R8), (REG_CR2, libc::REG_CR2)] {
        assert_eq!(a as i32, b);
    }
    // constants
    assert_eq!(SIGRTMIN_KERNEL, libc::SIGRTMIN() - 2);
    assert_eq!(SIGRTMAX_KERNEL, libc::SIGRTMAX());
    assert_eq!(SA_RESTART, libc::SA_RESTART);
    assert_eq!(SA_ONSTACK, libc::SA_ONSTACK);
    assert_eq!(SA_SIGINFO, libc::SA_SIGINFO);
    assert_eq!(SA_NODEFER, libc::SA_NODEFER);
    assert_eq!(SA_RESETHAND, libc::SA_RESETHAND);
    assert_eq!(SA_NOCLDSTOP, libc::SA_NOCLDSTOP);
    assert_eq!(SA_NOCLDWAIT, libc::SA_NOCLDWAIT);
    assert_eq!(SIGSTKSZ, libc::SIGSTKSZ);
    assert_eq!(MINSIGSTKSZ, libc::MINSIGSTKSZ);
    assert_eq!(SS_ONSTACK, libc::SS_ONSTACK);
    assert_eq!(SS_DISABLE, libc::SS_DISABLE);
    assert_eq!(SI_QUEUE, libc::SI_QUEUE);
    assert_eq!(SI_TKILL, libc::SI_TKILL);
    assert_eq!(SI_USER, libc::SI_USER);
    for (a, b) in [
        (SIGHUP, libc::SIGHUP),
        (SIGBUS, libc::SIGBUS),
        (SIGUSR1, libc::SIGUSR1),
        (SIGSTKFLT, libc::SIGSTKFLT),
        (SIGCHLD, libc::SIGCHLD),
        (SIGPOLL, libc::SIGPOLL),
        (SIGPWR, libc::SIGPWR),
        (SIGSYS, libc::SIGSYS),
        (SIGWINCH, libc::SIGWINCH),
    ] {
        assert_eq!(a, b);
    }
}

// ---------------------------------------------------------------------------------- sets

#[test]
fn sigset_operations_exhaustive() {
    for sig in -2..=67 {
        for start in [0u8, 0xff, 0x55] {
            let (mut a, mut b) = (filled(start), filled(start));
            // add
            let (x, y) = (ours!(unsafe { sigaddset(&mut a, sig) }), host!(unsafe { h::sigaddset(&mut b, sig) }));
            same(x, y, &format!("sigaddset {sig}"));
            assert_eq!(a, b, "sigaddset {sig} set contents");
            // member
            let (x, y) = (ours!(unsafe { sigismember(&a, sig) }), host!(unsafe { h::sigismember(&b, sig) }));
            same(x, y, &format!("sigismember {sig}"));
            let (x, y) = (ours!(unsafe { sigdelset(&mut a, sig) }), host!(unsafe { h::sigdelset(&mut b, sig) }));
            same(x, y, &format!("sigdelset {sig}"));
            assert_eq!(a, b, "sigdelset {sig} set contents");
            let (x, y) = (ours!(unsafe { sigismember(&a, sig) }), host!(unsafe { h::sigismember(&b, sig) }));
            same(x, y, &format!("sigismember after delete {sig}"));
            // the unchecked compat helpers (the host only has them as old symbol versions, which
            // cannot be linked): same effect as the host's checked calls for signals 1..=64
            if (1..=64).contains(&sig) && !is_internal_signal(sig) {
                let (mut c, mut d) = (filled(start), filled(start));
                assert_eq!(unsafe { __sigaddset(&mut c, sig) }, 0);
                unsafe { h::sigaddset(&mut d, sig) };
                assert_eq!(c, d);
                assert_eq!(unsafe { __sigismember(&c, sig) }, unsafe { h::sigismember(&d, sig) });
                assert_eq!(unsafe { __sigdelset(&mut c, sig) }, 0);
                unsafe { h::sigdelset(&mut d, sig) };
                assert_eq!(c, d);
                assert_eq!(unsafe { __sigismember(&c, sig) }, 0);
            }
        }
    }
    // empty, fill, isempty, and, or
    for start in [0u8, 0xff, 0x55, 0xaa] {
        let (mut a, mut b) = (filled(start), filled(start));
        same(ours!(unsafe { sigfillset(&mut a) }), host!(unsafe { h::sigfillset(&mut b) }), "sigfillset");
        assert_eq!(a, b, "sigfillset contents (start {start:#x})");
        same(ours!(unsafe { sigisemptyset(&a) }), host!(unsafe { h::sigisemptyset(&b) }), "sigisemptyset full");
        same(ours!(unsafe { sigemptyset(&mut a) }), host!(unsafe { h::sigemptyset(&mut b) }), "sigemptyset");
        assert_eq!(a, b, "sigemptyset contents (start {start:#x})");
        same(ours!(unsafe { sigisemptyset(&a) }), host!(unsafe { h::sigisemptyset(&b) }), "sigisemptyset empty");
    }
    let null = core::ptr::null_mut::<Sigset>();
    same(ours!(unsafe { sigemptyset(null) }), host!(unsafe { h::sigemptyset(null) }), "sigemptyset NULL");
    same(ours!(unsafe { sigfillset(null) }), host!(unsafe { h::sigfillset(null) }), "sigfillset NULL");
    same(ours!(unsafe { sigaddset(null, 2) }), host!(unsafe { h::sigaddset(null, 2) }), "sigaddset NULL");
    same(ours!(unsafe { sigdelset(null, 2) }), host!(unsafe { h::sigdelset(null, 2) }), "sigdelset NULL");
    same(ours!(unsafe { sigismember(null, 2) }), host!(unsafe { h::sigismember(null, 2) }), "sigismember NULL");
    same(ours!(unsafe { sigisemptyset(null) }), host!(unsafe { h::sigisemptyset(null) }), "sigisemptyset NULL");
    let mut x = filled(0x11);
    let mut y = filled(0x11);
    let (mut l, mut r) = (filled(0), filled(0));
    l.val[0] = 0xf0f0_f0f0_1234_5678;
    r.val[0] = 0x0ff0_0ff0_ffff_0000;
    r.val[3] = 7;
    for (dst_null, l_null, r_null) in [(false, false, false), (true, false, false), (false, true, false), (false, false, true)] {
        let d = |p: &mut Sigset, n: bool| if n { null } else { p as *mut Sigset };
        let lp = |p: &Sigset, n: bool| if n { core::ptr::null() } else { p as *const Sigset };
        let (o, hs) = (
            ours!(unsafe { sigandset(d(&mut x, dst_null), lp(&l, l_null), lp(&r, r_null)) }),
            host!(unsafe { h::sigandset(d(&mut y, dst_null), lp(&l, l_null), lp(&r, r_null)) }),
        );
        same(o, hs, "sigandset");
        assert_eq!(x, y);
        let (o, hs) = (
            ours!(unsafe { sigorset(d(&mut x, dst_null), lp(&l, l_null), lp(&r, r_null)) }),
            host!(unsafe { h::sigorset(d(&mut y, dst_null), lp(&l, l_null), lp(&r, r_null)) }),
        );
        same(o, hs, "sigorset");
        assert_eq!(x, y);
    }
    // the clear/fill pair leaves exactly 32 and 33 out
    let mut s = filled(0);
    unsafe { sigfillset(&mut s) };
    assert_eq!(s.val[0], !(1u64 << 31 | 1u64 << 32));
    assert_eq!(unsafe { sigismember(&s, 31) } + unsafe { sigismember(&s, 34) }, 2);
    assert_eq!(unsafe { sigismember(&s, SIGCANCEL) }, 0);
}

// ---------------------------------------------------------------------------------- sigaction

static HITS: AtomicI32 = AtomicI32::new(0);
static LAST_SIG: AtomicI32 = AtomicI32::new(0);

extern "C" fn count_handler(sig: c_int) {
    HITS.fetch_add(1, Ordering::SeqCst);
    LAST_SIG.store(sig, Ordering::SeqCst);
}
extern "C" fn other_handler(_sig: c_int) {}

fn handler_addr(f: extern "C" fn(c_int)) -> usize {
    f as usize
}

/// Read an action through the host's sigaction.
fn host_get(sig: c_int) -> Sigaction {
    let mut o = Sigaction::ZERO;
    assert_eq!(unsafe { h::sigaction(sig, core::ptr::null(), &mut o) }, 0);
    o
}

fn reset(sig: c_int) {
    let d = Sigaction::ZERO;
    unsafe { h::sigaction(sig, &d, core::ptr::null_mut()) };
}

#[test]
fn sigaction_round_trip_and_errors() {
    let _g = lock();
    let mut mask = Sigset::EMPTY;
    unsafe {
        sigaddset(&mut mask, SIGUSR2);
        sigaddset(&mut mask, SIGINT);
        sigaddset(&mut mask, 50);
    }
    for flags in [0, SA_RESTART, SA_SIGINFO | SA_NODEFER, SA_RESETHAND | SA_ONSTACK | SA_NOCLDSTOP, SA_RESTART | SA_SIGINFO | SA_RESETHAND] {
        let act = Sigaction { sa_handler: handler_addr(other_handler), sa_mask: mask, sa_flags: flags, sa_restorer: 0 };
        let mut old = Sigaction::ZERO;
        // install with ours, read with the host, then the other way round
        assert_eq!(unsafe { sigaction(SIGUSR1, &act, &mut old) }, 0);
        assert_eq!(old.sa_handler, SIG_DFL);
        let seen = host_get(SIGUSR1);
        assert_eq!(seen.sa_handler, act.sa_handler);
        assert_eq!(seen.sa_mask.val[0], mask.val[0]);
        assert_eq!(seen.sa_flags, flags | SA_RESTORER, "flags {flags:#x}");
        assert_ne!(seen.sa_restorer, 0);
        let mut old2 = Sigaction::ZERO;
        assert_eq!(unsafe { sigaction(SIGUSR1, core::ptr::null(), &mut old2) }, 0);
        assert_eq!((old2.sa_handler, old2.sa_mask.val[0], old2.sa_flags, old2.sa_restorer), (seen.sa_handler, seen.sa_mask.val[0], seen.sa_flags, seen.sa_restorer));
        // the host installs the same thing; the old action it hands back equals what we read
        let mut hold = Sigaction::ZERO;
        assert_eq!(unsafe { h::sigaction(SIGUSR1, &act, &mut hold) }, 0);
        assert_eq!((hold.sa_handler, hold.sa_mask.val[0], hold.sa_flags), (old2.sa_handler, old2.sa_mask.val[0], old2.sa_flags));
        let seen2 = host_get(SIGUSR1);
        assert_eq!((seen2.sa_handler, seen2.sa_mask.val[0], seen2.sa_flags), (seen.sa_handler, seen.sa_mask.val[0], seen.sa_flags));
        reset(SIGUSR1);
    }
    // errors
    let act = Sigaction { sa_handler: handler_addr(other_handler), ..Sigaction::ZERO };
    let mut old = Sigaction::ZERO;
    for sig in [-1, 0, 32, 33, 65, 66, 1000, SIGKILL, SIGSTOP] {
        for (a, o) in [(true, true), (true, false), (false, true), (false, false)] {
            let (ap, op) = (if a { &act as *const Sigaction } else { core::ptr::null() }, if o { &mut old as *mut Sigaction } else { core::ptr::null_mut() });
            same(ours!(unsafe { sigaction(sig, ap, op) }), host!(unsafe { h::sigaction(sig, ap, op) }), &format!("sigaction {sig} act={a} old={o}"));
            same(ours!(unsafe { __sigaction(sig, ap, op) }), host!(unsafe { h::__sigaction(sig, ap, op) }), &format!("__sigaction {sig}"));
        }
    }
    // SIGKILL: reading is fine, installing is EINVAL
    assert_eq!(unsafe { sigaction(SIGKILL, core::ptr::null(), &mut old) }, 0);
    assert_eq!(old.sa_handler, SIG_DFL);
}

#[test]
fn signal_family_return_values_and_flags() {
    let _g = lock();
    type Sig = unsafe fn(c_int, Sighandler) -> Sighandler;
    unsafe fn o_signal(s: c_int, f: Sighandler) -> Sighandler {
        signal(s, f)
    }
    unsafe fn o_bsd(s: c_int, f: Sighandler) -> Sighandler {
        bsd_signal(s, f)
    }
    unsafe fn o_ssignal(s: c_int, f: Sighandler) -> Sighandler {
        ssignal(s, f)
    }
    unsafe fn o_sysv(s: c_int, f: Sighandler) -> Sighandler {
        sysv_signal(s, f)
    }
    unsafe fn o_sysv2(s: c_int, f: Sighandler) -> Sighandler {
        __sysv_signal(s, f)
    }
    unsafe fn h_signal(s: c_int, f: Sighandler) -> Sighandler {
        unsafe { h::signal(s, f) }
    }
    unsafe fn h_bsd(s: c_int, f: Sighandler) -> Sighandler {
        unsafe { h::bsd_signal(s, f) }
    }
    unsafe fn h_ssignal(s: c_int, f: Sighandler) -> Sighandler {
        unsafe { h::ssignal(s, f) }
    }
    unsafe fn h_sysv(s: c_int, f: Sighandler) -> Sighandler {
        unsafe { h::sysv_signal(s, f) }
    }
    unsafe fn h_sysv2(s: c_int, f: Sighandler) -> Sighandler {
        unsafe { h::__sysv_signal(s, f) }
    }
    let pairs: [(&str, Sig, Sig); 5] = [("signal", o_signal, h_signal), ("bsd_signal", o_bsd, h_bsd), ("ssignal", o_ssignal, h_ssignal), ("sysv_signal", o_sysv, h_sysv), ("__sysv_signal", o_sysv2, h_sysv2)];
    for (name, o, hs) in pairs {
        for sig in [SIGUSR1, SIGUSR2, 50, SIGURG] {
            let mut log = vec![];
            for f in [o, hs] {
                let mut seq = vec![];
                unsafe {
                    seq.push(f(sig, handler_addr(count_handler)));
                    let a = host_get(sig);
                    seq.push(a.sa_flags as usize);
                    seq.push(a.sa_mask.val[0] as usize);
                    seq.push(a.sa_handler);
                    seq.push(f(sig, handler_addr(other_handler)));
                    seq.push(f(sig, SIG_IGN));
                    seq.push(f(sig, SIG_DFL));
                    seq.push(f(sig, SIG_DFL));
                }
                log.push(seq);
                reset(sig);
            }
            assert_eq!(log[0], log[1], "{name} sig {sig}");
            assert_eq!(log[0][0], SIG_DFL);
            assert_eq!(log[0][4], handler_addr(count_handler));
        }
        for sig in [-1, 0, 32, 33, 65, 99, SIGKILL, SIGSTOP] {
            for handler in [handler_addr(other_handler), SIG_ERR, SIG_DFL] {
                same(ours!(unsafe { o(sig, handler) }), host!(unsafe { hs(sig, handler) }), &format!("{name}({sig}, {handler:#x})"));
            }
        }
    }
}

extern "C" fn resethand_probe(_s: c_int) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn sysv_signal_resets_the_handler() {
    let _g = lock();
    HITS.store(0, Ordering::SeqCst);
    sysv_signal(SIGUSR1, handler_addr(resethand_probe));
    assert_eq!(raise(SIGUSR1), 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 1);
    // the first delivery put the default action back
    assert_eq!(host_get(SIGUSR1).sa_handler, SIG_DFL);
    // BSD signal(): stays installed and blocks the signal while running
    signal(SIGUSR1, handler_addr(resethand_probe));
    assert_eq!(raise(SIGUSR1), 0);
    assert_eq!(raise(SIGUSR1), 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 3);
    assert_eq!(host_get(SIGUSR1).sa_handler, handler_addr(resethand_probe));
    reset(SIGUSR1);
}

// A read() on a pipe interrupted by a signal: restarts under BSD signal() (SA_RESTART), fails with
// EINTR under sysv_signal().
fn interrupted_read(install: impl Fn(Sighandler)) -> (isize, c_int) {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { h::pipe(fds.as_mut_ptr()) }, 0);
    install(handler_addr(other_handler));
    let tid = gettid();
    let pid = unsafe { h::getpid() };
    let (w, restart_data) = (fds[1], true);
    let t = std::thread::spawn(move || {
        unsafe { h::usleep(60_000) };
        unsafe { h::tgkill(pid, tid, SIGUSR1) };
        unsafe { h::usleep(60_000) };
        if restart_data {
            unsafe { h::write(w, b"x".as_ptr().cast(), 1) };
        }
    });
    let mut b = [0u8; 4];
    host_errno_clear();
    let r = unsafe { h::read(fds[0], b.as_mut_ptr().cast(), 4) };
    let e = host_errno();
    t.join().unwrap();
    unsafe {
        h::close(fds[0]);
        h::close(fds[1]);
    }
    reset(SIGUSR1);
    (r, if r < 0 { e } else { 0 })
}

fn host_errno_clear() {
    unsafe { *h::__errno_location() = 0 };
}

#[test]
fn sa_restart_semantics_differ_between_signal_and_sysv_signal() {
    let _g = lock();
    let bsd_ours = interrupted_read(|f| {
        signal(SIGUSR1, f);
    });
    let bsd_host = interrupted_read(|f| {
        unsafe { h::signal(SIGUSR1, f) };
    });
    let sysv_ours = interrupted_read(|f| {
        sysv_signal(SIGUSR1, f);
    });
    let sysv_host = interrupted_read(|f| {
        unsafe { h::sysv_signal(SIGUSR1, f) };
    });
    assert_eq!(bsd_ours, (1, 0), "restarted read gets the byte");
    assert_eq!(bsd_ours, bsd_host);
    assert_eq!(sysv_ours, (-1, libc::EINTR));
    assert_eq!(sysv_ours, sysv_host);
}

#[test]
fn siginterrupt_and_signal_agree_with_glibc() {
    let _g = lock();
    let mut logs: Vec<Vec<i64>> = vec![];
    for use_host in [false, true] {
        let mut seq = vec![];
        let sig = SIGUSR2;
        unsafe {
            let call = |f: &dyn Fn() -> i64| f();
            let sigint = |i| if use_host { h::siginterrupt(sig, i) as i64 } else { siginterrupt(sig, i) as i64 };
            let sig_set = |f| if use_host { h::signal(sig, f) as i64 } else { signal(sig, f) as i64 };
            // no handler yet: siginterrupt works on the default action
            seq.push(call(&|| sigint(1)));
            seq.push(host_get(sig).sa_flags as i64);
            seq.push(call(&|| sigint(0)));
            seq.push(host_get(sig).sa_flags as i64);
            seq.push(call(&|| sigint(1)));
            seq.push(call(&|| sig_set(handler_addr(other_handler)))); // SA_RESTART stays off after siginterrupt(1)
            seq.push(host_get(sig).sa_flags as i64);
            seq.push(call(&|| sigint(0)));
            seq.push(call(&|| sig_set(handler_addr(other_handler))));
            seq.push(host_get(sig).sa_flags as i64);
            // errors
            for bad in [0, 32, 33, 65, SIGKILL.max(0)] {
                let r = if use_host {
                    *h::__errno_location() = 0;
                    let r = h::siginterrupt(bad, 1);
                    r as i64 * 1000 + i64::from(host_errno())
                } else {
                    rusty_libc_core::errno::set(0);
                    let r = siginterrupt(bad, 1);
                    r as i64 * 1000 + i64::from(rusty_libc_core::errno::get())
                };
                seq.push(r);
            }
        }
        reset(sig);
        // clear the remembered state of the other implementation too
        unsafe {
            h::siginterrupt(sig, 0);
            siginterrupt(sig, 0);
        }
        reset(sig);
        logs.push(seq);
    }
    assert_eq!(logs[0], logs[1]);
}

// ---------------------------------------------------------------------------------- masks

fn cur_mask() -> Sigset {
    let mut s = Sigset::EMPTY;
    assert_eq!(unsafe { h::sigprocmask(SIG_BLOCK, core::ptr::null(), &mut s) }, 0);
    s
}

fn set_mask(m: u64) {
    let s = Sigset::from_mask(m);
    assert_eq!(unsafe { h::sigprocmask(SIG_SETMASK, &s, core::ptr::null_mut()) }, 0);
}

#[test]
fn sigprocmask_and_sigpending() {
    let _g = lock();
    set_mask(0);
    let all_bits = Sigset::from_mask(!0);
    // internal signals cannot be blocked: both implementations drop bits 32 and 33
    for how in [SIG_SETMASK, SIG_BLOCK, SIG_UNBLOCK] {
        for (o, hs) in [(true, false), (false, true)] {
            set_mask(0);
            let mut old = filled(0x77);
            let r = if o { ours!(unsafe { sigprocmask(how, &all_bits, &mut old) }) } else { host!(unsafe { h::sigprocmask(how, &all_bits, &mut old) }) };
            assert_eq!(r.0, 0);
            let after = cur_mask().val[0];
            let expect = if how == SIG_UNBLOCK { 0 } else { !(1u64 << 31 | 1u64 << 32) & !(1 << 8 | 1 << 18) };
            // SIGKILL (9) and SIGSTOP (19) are never blocked either
            assert_eq!(after & !(1 << 8 | 1 << 18), expect & !(1 << 8 | 1 << 18), "how {how} ours={o} host={hs}");
            assert_eq!(old.val[0], 0);
            assert_eq!(old.val[1], 0x7777_7777_7777_7777, "only the first word is written");
        }
    }
    set_mask(0);
    // errors
    let one = Sigset::from_mask(2);
    for how in [-1, 3, 77] {
        same(ours!(unsafe { sigprocmask(how, &one, core::ptr::null_mut()) }), host!(unsafe { h::sigprocmask(how, &one, core::ptr::null_mut()) }), "bad how");
        // without a set the kernel ignores `how`
        same(ours!(unsafe { sigprocmask(how, core::ptr::null(), core::ptr::null_mut()) }), host!(unsafe { h::sigprocmask(how, core::ptr::null(), core::ptr::null_mut()) }), "bad how, no set");
    }
    let bad = 8 as *mut Sigset;
    same(ours!(unsafe { sigprocmask(SIG_BLOCK, core::ptr::null(), bad) }), host!(unsafe { h::sigprocmask(SIG_BLOCK, core::ptr::null(), bad) }), "EFAULT old");
    same(ours!(unsafe { sigprocmask(SIG_BLOCK, core::ptr::null(), bad) }), (-1, libc::EFAULT), "EFAULT value");
    same(ours!(unsafe { sigpending(bad) }), host!(unsafe { h::sigpending(bad) }), "sigpending EFAULT");
    same(ours!(unsafe { sigsuspend(bad) }), host!(unsafe { h::sigsuspend(bad) }), "sigsuspend EFAULT");
    // pending signals
    HITS.store(0, Ordering::SeqCst);
    signal(SIGUSR1, handler_addr(count_handler));
    let usr1 = Sigset::from_mask(1 << (SIGUSR1 - 1));
    assert_eq!(unsafe { sigprocmask(SIG_BLOCK, &usr1, core::ptr::null_mut()) }, 0);
    assert_eq!(raise(SIGUSR1), 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 0, "blocked: not delivered");
    let (mut p, mut q) = (filled(0x33), filled(0x33));
    assert_eq!(unsafe { sigpending(&mut p) }, 0);
    assert_eq!(unsafe { h::sigpending(&mut q) }, 0);
    assert_eq!(p, q);
    assert_eq!(p.val[0], 1 << (SIGUSR1 - 1));
    assert_eq!(p.val[1], 0x3333_3333_3333_3333);
    assert_eq!(sigpending_rs(), Ok(1 << (SIGUSR1 - 1)));
    assert_eq!(unsafe { sigprocmask(SIG_UNBLOCK, &usr1, core::ptr::null_mut()) }, 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 1, "delivered on unblock");
    let mut p = filled(1);
    unsafe { sigpending(&mut p) };
    assert_eq!(p.val[0], 0);
    // Rust form
    assert_eq!(sigprocmask_rs(SIG_BLOCK, Some(1 << (SIGUSR1 - 1))), Ok(0));
    assert_eq!(sigprocmask_rs(SIG_SETMASK, None), Ok(1 << (SIGUSR1 - 1)));
    assert_eq!(sigprocmask_rs(SIG_SETMASK, Some(0)), Ok(1 << (SIGUSR1 - 1)));
    reset(SIGUSR1);
    set_mask(0);
}

#[test]
fn sigsuspend_wakes_for_a_handled_signal() {
    let _g = lock();
    set_mask(0);
    for use_host in [false, true] {
        HITS.store(0, Ordering::SeqCst);
        signal(SIGUSR2, handler_addr(count_handler));
        let usr2 = Sigset::from_mask(1 << (SIGUSR2 - 1));
        unsafe { h::sigprocmask(SIG_BLOCK, &usr2, core::ptr::null_mut()) };
        assert_eq!(raise(SIGUSR2), 0);
        let empty = Sigset::EMPTY;
        let r = if use_host { host!(unsafe { h::sigsuspend(&empty) }) } else { ours!(unsafe { sigsuspend(&empty) }) };
        assert_eq!(r, (-1, libc::EINTR));
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        // the mask is back to blocking SIGUSR2
        assert_eq!(cur_mask().val[0], usr2.val[0]);
        set_mask(0);
        reset(SIGUSR2);
    }
    // Rust form and __sigsuspend
    signal(SIGUSR2, handler_addr(count_handler));
    HITS.store(0, Ordering::SeqCst);
    set_mask(1 << (SIGUSR2 - 1));
    raise(SIGUSR2);
    assert_eq!(sigsuspend_rs(0), Errno(libc::EINTR));
    raise(SIGUSR2);
    let e = Sigset::EMPTY;
    assert_eq!(unsafe { __sigsuspend(&e) }, -1);
    assert_eq!(HITS.load(Ordering::SeqCst), 2);
    set_mask(0);
    reset(SIGUSR2);
}

use rusty_libc_core::Errno;

#[test]
fn sigtimedwait_family() {
    in_child(sigtimedwait_family_body);
}

fn sigtimedwait_family_body() {
    set_mask(0);
    let usr1 = Sigset::from_mask(1 << (SIGUSR1 - 1));
    unsafe { h::sigprocmask(SIG_BLOCK, &usr1, core::ptr::null_mut()) };
    let ms = Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
    let mut info = Siginfo::ZERO;
    // nothing pending: EAGAIN after 1 ms
    same(ours!(unsafe { sigtimedwait(&usr1, &mut info, &ms) }), host!(unsafe { h::sigtimedwait(&usr1, &mut info, &ms) }), "timeout");
    assert_eq!(ours!(unsafe { sigtimedwait(&usr1, &mut info, &ms) }), (-1, libc::EAGAIN));
    // invalid timeouts
    for t in [Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 }, Timespec { tv_sec: -1, tv_nsec: 0 }, Timespec { tv_sec: 0, tv_nsec: -1 }] {
        same(ours!(unsafe { sigtimedwait(&usr1, &mut info, &t) }), host!(unsafe { h::sigtimedwait(&usr1, &mut info, &t) }), "bad timeout");
    }
    same(ours!(unsafe { sigtimedwait(&usr1, &mut info, 8 as *const Timespec) }), host!(unsafe { h::sigtimedwait(&usr1, &mut info, 8 as *const Timespec) }), "EFAULT timeout");
    // a pending signal comes back with its info; tkill's code is folded into SI_USER
    for (use_host, via_kill) in [(false, false), (true, false), (false, true), (true, true)] {
        assert_eq!(if via_kill { kill(unsafe { h::getpid() }, SIGUSR1) } else { raise(SIGUSR1) }, 0);
        let mut i = Siginfo { si_signo: -1, ..Siginfo::ZERO };
        let r = if use_host { unsafe { h::sigtimedwait(&usr1, &mut i, &ms) } } else { unsafe { sigtimedwait(&usr1, &mut i, &ms) } };
        assert_eq!(r, SIGUSR1);
        assert_eq!(i.si_signo, SIGUSR1);
        assert_eq!(i.si_code, SI_USER, "use_host={use_host} via_kill={via_kill}");
        assert_eq!(i.si_pid(), unsafe { h::getpid() });
        assert_eq!(i.si_uid(), unsafe { h::getuid() });
    }
    // no info pointer; sigwaitinfo and sigwait with the signal already pending
    raise(SIGUSR1);
    assert_eq!(unsafe { sigtimedwait(&usr1, core::ptr::null_mut(), &ms) }, SIGUSR1);
    raise(SIGUSR1);
    let mut i = Siginfo::ZERO;
    assert_eq!(unsafe { sigwaitinfo(&usr1, &mut i) }, SIGUSR1);
    assert_eq!(i.si_code, SI_USER);
    raise(SIGUSR1);
    let mut s = 0;
    assert_eq!(unsafe { sigwait(&usr1, &mut s) }, 0);
    assert_eq!(s, SIGUSR1);
    raise(SIGUSR1);
    s = 0;
    assert_eq!(unsafe { h::sigwait(&usr1, &mut s) }, 0);
    assert_eq!(s, SIGUSR1);
    // sigwait returns the error number itself
    let bad = 8 as *const Sigset;
    let mut s2 = 0;
    assert_eq!(unsafe { sigwait(bad, &mut s2) }, unsafe { h::sigwait(bad, &mut s2) });
    assert_eq!(unsafe { sigwait(bad, &mut s2) }, libc::EFAULT);
    // Rust form
    raise(SIGUSR1);
    let (sig, si) = sigtimedwait_rs(1 << (SIGUSR1 - 1), Some(Timespec { tv_sec: 1, tv_nsec: 0 })).unwrap();
    assert_eq!((sig, si.si_signo), (SIGUSR1, SIGUSR1));
    assert_eq!(sigtimedwait_rs(1 << (SIGUSR1 - 1), Some(Timespec { tv_sec: 0, tv_nsec: 1000 })).unwrap_err(), Errno(libc::EAGAIN));
    // a wait from another thread's signal: sigwait blocks until the signal comes
    let pid = unsafe { h::getpid() };
    let t = std::thread::spawn(move || {
        unsafe { h::usleep(30_000) };
        unsafe { h::kill(pid, SIGUSR1) };
    });
    let mut s3 = 0;
    assert_eq!(unsafe { sigwait(&usr1, &mut s3) }, 0);
    assert_eq!(s3, SIGUSR1);
    t.join().unwrap();
    set_mask(0);
}

// ---------------------------------------------------------------------------------- kill, raise

#[test]
fn kill_killpg_raise_errors_and_success() {
    let _g = lock();
    set_mask(0);
    let me = unsafe { h::getpid() };
    for (pid, sig) in [(0, 0), (me, 0), (me, 65), (me, -1), (me, 1000), (i32::MAX, 0), (999_999_999, 9), (-me, 0), (-1, 65)] {
        same(ours!(kill(pid, sig)), host!(unsafe { h::kill(pid, sig) }), &format!("kill({pid}, {sig})"));
    }
    for pg in [0, -1, -5, 999_999_999] {
        same(ours!(killpg(pg, 0)), host!(unsafe { h::killpg(pg, 0) }), &format!("killpg({pg}, 0)"));
        same(ours!(killpg(pg, 65)), host!(unsafe { h::killpg(pg, 65) }), &format!("killpg({pg}, 65)"));
    }
    assert_eq!(ours!(killpg(-3, 0)), (-1, libc::EINVAL));
    assert_eq!(kill_rs(me, 0), Ok(()));
    assert_eq!(kill_rs(me, 65), Err(Errno(libc::EINVAL)));
    let tid = gettid();
    for (a, b, sig) in [(me, tid, 0), (me, tid, 65), (me, 999_999_999, 0), (999_999_999, tid, 0), (-1, tid, 0), (me, -1, 0)] {
        same(ours!(tgkill(a, b, sig)), host!(unsafe { h::tgkill(a, b, sig) }), &format!("tgkill({a}, {b}, {sig})"));
    }
    // raise: handler count, blocked signals stay pending, errors
    HITS.store(0, Ordering::SeqCst);
    signal(SIGUSR1, handler_addr(count_handler));
    for _ in 0..5 {
        assert_eq!(raise(SIGUSR1), 0);
    }
    assert_eq!(HITS.load(Ordering::SeqCst), 5);
    assert_eq!(gsignal(SIGUSR1), 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 6);
    assert_eq!(raise_rs(SIGUSR1), Ok(()));
    assert_eq!(HITS.load(Ordering::SeqCst), 7);
    assert_eq!(unsafe { h::raise(SIGUSR1) }, 0);
    assert_eq!(unsafe { h::gsignal(SIGUSR1) }, 0);
    assert_eq!(HITS.load(Ordering::SeqCst), 9);
    reset(SIGUSR1);
    for sig in [0, 32, 33, 65, 66, -1, 1000] {
        same(ours!(raise(sig)), host!(unsafe { h::raise(sig) }), &format!("raise({sig})"));
        same(ours!(gsignal(sig)), host!(unsafe { h::gsignal(sig) }), &format!("gsignal({sig})"));
    }
    // ignored signal: raise succeeds and nothing happens
    signal(SIGUSR2, SIG_IGN);
    assert_eq!(raise(SIGUSR2), 0);
    reset(SIGUSR2);
}

type QRec = (i32, i32, i32, i32, u32, usize);
static QINFO: Mutex<Option<QRec>> = Mutex::new(None);
static QGOT: AtomicI32 = AtomicI32::new(0);

extern "C" fn q_handler(sig: c_int, info: *mut Siginfo, _uc: *mut c_void) {
    let i = unsafe { &*info };
    let v = unsafe { i.si_value().sival_ptr } as usize;
    // try_lock: never block inside a signal handler
    if let Ok(mut g) = QINFO.try_lock() {
        *g = Some((sig, i.si_signo, i.si_code, i.si_pid(), i.si_uid(), v));
    }
    QGOT.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn sigqueue_carries_the_value() {
    in_child(sigqueue_body);
}

fn sigqueue_body() {
    set_mask(0);
    let act = Sigaction { sa_handler: q_handler as *const () as usize, sa_mask: Sigset::EMPTY, sa_flags: SA_SIGINFO, sa_restorer: 0 };
    let sig = 40;
    assert_eq!(unsafe { sigaction(sig, &act, core::ptr::null_mut()) }, 0);
    let me = unsafe { h::getpid() };
    let mut seen = vec![];
    for (use_host, payload) in [(false, 0x1234_5678usize), (true, 0x1234_5678), (false, 0xdead_beef_cafe), (true, 0xdead_beef_cafe), (false, 0), (true, 0)] {
        // block, queue, then take it in this thread (process-directed signals may go to any thread)
        let m = Sigset::from_mask(1 << (sig - 1));
        unsafe { h::sigprocmask(SIG_BLOCK, &m, core::ptr::null_mut()) };
        QGOT.store(0, Ordering::SeqCst);
        let v = Sigval { sival_ptr: payload as *mut c_void };
        let r = if use_host { unsafe { h::sigqueue(me, sig, v) } } else { sigqueue(me, sig, v) };
        assert_eq!(r, 0);
        // unblocking delivers it at once, in this (the only) thread
        unsafe { h::sigprocmask(SIG_UNBLOCK, &m, core::ptr::null_mut()) };
        assert_eq!(QGOT.load(Ordering::SeqCst), 1);
        seen.push(QINFO.lock().unwrap().take().unwrap());
        let _ = use_host;
    }
    let uid = unsafe { h::getuid() };
    for (n, s) in seen.iter().enumerate() {
        assert_eq!(s.0, sig);
        assert_eq!(s.1, sig);
        assert_eq!(s.2, SI_QUEUE, "{n}");
        assert_eq!(s.3, me);
        assert_eq!(s.4, uid);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[2], seen[3]);
    assert_eq!(seen[4], seen[5]);
    assert_eq!(seen[0].5, 0x1234_5678);
    assert_eq!(seen[2].5, 0xdead_beef_cafe);
    // the int member: the low 32 bits of the value
    for use_host in [false, true] {
        let m = Sigset::from_mask(1 << (sig - 1));
        unsafe { h::sigprocmask(SIG_BLOCK, &m, core::ptr::null_mut()) };
        QGOT.store(0, Ordering::SeqCst);
        let mut vi = Sigval { sival_ptr: core::ptr::null_mut() };
        vi.sival_int = -7;
        let r = if use_host { unsafe { h::sigqueue(me, sig, vi) } } else { sigqueue(me, sig, vi) };
        assert_eq!(r, 0);
        unsafe { h::sigprocmask(SIG_UNBLOCK, &m, core::ptr::null_mut()) };
        assert_eq!(QGOT.load(Ordering::SeqCst), 1);
        let got = QINFO.lock().unwrap().take().unwrap();
        assert_eq!(got.5 as u32 as i32, -7);
        assert_eq!(got.2, SI_QUEUE);
    }
    // errors
    for (pid, s) in [(me, 65), (me, -1), (999_999_999, 40), (me, 0), (-1, 65)] {
        same(ours!(sigqueue(pid, s, Sigval { sival_int: 1 })), host!(unsafe { h::sigqueue(pid, s, Sigval { sival_int: 1 }) }), &format!("sigqueue({pid}, {s})"));
    }
}

// ---------------------------------------------------------------------------------- alt stack

static ALT_INFO: Mutex<Option<(usize, c_int)>> = Mutex::new(None);

extern "C" fn alt_handler(_s: c_int) {
    let local = 0u8;
    let mut ss = StackT::ZERO;
    unsafe { sigaltstack(core::ptr::null(), &mut ss) };
    if let Ok(mut g) = ALT_INFO.try_lock() {
        *g = Some((&local as *const u8 as usize, ss.ss_flags));
    }
}

#[test]
fn sigaltstack_set_query_and_run_a_handler_on_it() {
    let _g = lock();
    let mut mem = vec![0u8; 64 * 1024];
    let st = StackT { ss_sp: mem.as_mut_ptr().cast(), ss_flags: 0, ss_size: mem.len() };
    // start from "no stack" (this thread may have none)
    let off = StackT { ss_sp: core::ptr::null_mut(), ss_flags: SS_DISABLE, ss_size: 0 };
    assert_eq!(unsafe { h::sigaltstack(&off, core::ptr::null_mut()) }, 0);
    let (mut a, mut b) = (StackT::ZERO, StackT::ZERO);
    assert_eq!(unsafe { sigaltstack(core::ptr::null(), &mut a) }, 0);
    assert_eq!(unsafe { h::sigaltstack(core::ptr::null(), &mut b) }, 0);
    assert_eq!(a, b);
    assert_eq!(a.ss_flags, SS_DISABLE);
    // install with ours, read with the host and the Rust form
    assert_eq!(unsafe { sigaltstack(&st, &mut a) }, 0);
    assert_eq!(a.ss_flags, SS_DISABLE);
    assert_eq!(unsafe { h::sigaltstack(core::ptr::null(), &mut b) }, 0);
    assert_eq!(b, st);
    assert_eq!(sigaltstack_rs(None), Ok(st));
    // errors, compared one after the other on the same start state
    let small = StackT { ss_sp: mem.as_mut_ptr().cast(), ss_flags: 0, ss_size: 100 };
    let badflag = StackT { ss_sp: mem.as_mut_ptr().cast(), ss_flags: 77, ss_size: 70000 };
    for s in [&small, &badflag, &off, &st] {
        let (x, y) = (ours!(unsafe { sigaltstack(s, core::ptr::null_mut()) }), host!(unsafe { h::sigaltstack(s, core::ptr::null_mut()) }));
        same(x, y, "sigaltstack");
    }
    same(ours!(unsafe { sigaltstack(8 as *const StackT, core::ptr::null_mut()) }), host!(unsafe { h::sigaltstack(8 as *const StackT, core::ptr::null_mut()) }), "EFAULT");
    same(ours!(unsafe { sigaltstack(core::ptr::null(), 8 as *mut StackT) }), host!(unsafe { h::sigaltstack(core::ptr::null(), 8 as *mut StackT) }), "EFAULT old");
    assert_eq!(unsafe { sigaltstack(&st, core::ptr::null_mut()) }, 0);
    // a handler with SA_ONSTACK runs inside the stack and sees SS_ONSTACK
    let act = Sigaction { sa_handler: handler_addr(alt_handler), sa_mask: Sigset::EMPTY, sa_flags: SA_ONSTACK, sa_restorer: 0 };
    assert_eq!(unsafe { sigaction(SIGUSR1, &act, core::ptr::null_mut()) }, 0);
    assert_eq!(raise(SIGUSR1), 0);
    let (addr, flags) = ALT_INFO.lock().unwrap().take().unwrap();
    let base = mem.as_ptr() as usize;
    assert!(addr >= base && addr < base + mem.len(), "handler ran on the alternate stack");
    assert_eq!(flags, SS_ONSTACK);
    // inside normal code the flag is clear again
    let mut now = StackT::ZERO;
    unsafe { sigaltstack(core::ptr::null(), &mut now) };
    assert_eq!(now.ss_flags, 0);
    reset(SIGUSR1);
    // sigstack: same results as the host (each in a fresh thread: a thread cannot change its
    // alternate stack while it is "on" it, and the made-up size covers the thread's own stack)
    let base = mem.as_mut_ptr() as usize;
    let mut afters = vec![];
    for use_host in [false, true] {
        let after = std::thread::spawn(move || {
            let mut old = Sigstack { ss_sp: 1 as *mut c_void, ss_onstack: 9 };
            let new = Sigstack { ss_sp: (base + 60_000) as *mut c_void, ss_onstack: 0 };
            let r1 = if use_host { host!(unsafe { h::sigstack(&new, &mut old) }) } else { ours!(unsafe { sigstack(&new, &mut old) }) };
            let mut q = Sigstack { ss_sp: 1 as *mut c_void, ss_onstack: 9 };
            let r = unsafe { sigstack(core::ptr::null(), &mut q) };
            let mut st2 = StackT::ZERO;
            unsafe { h::sigaltstack(core::ptr::null(), &mut st2) };
            // the kernel reports our made-up size: everything from address 0 up to the pointer
            assert_eq!(st2.ss_size, new.ss_sp as usize);
            assert_eq!((r1.0, old.ss_onstack), (0, 0));
            assert_eq!((r, q.ss_sp as usize), (0, new.ss_sp as usize));
            q.ss_onstack
        })
        .join()
        .unwrap();
        afters.push(after);
    }
    assert_eq!(afters[0], afters[1]);
    assert_eq!(unsafe { h::sigaltstack(&off, core::ptr::null_mut()) }, 0);
}

// ---------------------------------------------------------------------------------- old APIs

#[test]
fn bsd_mask_functions_and_sysv_hold_release_ignore_set() {
    let _g = lock();
    set_mask(0);
    // sigblock / sigsetmask / siggetmask
    let mut logs: Vec<Vec<i64>> = vec![];
    for use_host in [false, true] {
        let mut seq = vec![];
        set_mask(0);
        unsafe {
            macro_rules! c {
                ($o:expr, $h:expr) => {
                    if use_host { $h as i64 } else { $o as i64 }
                };
            }
            seq.push(c!(sigblock(0b101), h::sigblock(0b101)));
            seq.push(c!(siggetmask(), h::siggetmask()));
            seq.push(c!(sigblock(0b1000), h::sigblock(0b1000)));
            seq.push(c!(sigsetmask(0b10), h::sigsetmask(0b10)));
            seq.push(c!(siggetmask(), h::siggetmask()));
            seq.push(c!(sigsetmask(-1), h::sigsetmask(-1)));
            seq.push(cur_mask().val[0] as i64);
            seq.push(c!(sigsetmask(0), h::sigsetmask(0)));
            seq.push(cur_mask().val[0] as i64);
            // sighold / sigrelse
            seq.push(c!(sighold(SIGUSR1), h::sighold(SIGUSR1)));
            seq.push(cur_mask().val[0] as i64);
            seq.push(c!(sigrelse(SIGUSR1), h::sigrelse(SIGUSR1)));
            seq.push(cur_mask().val[0] as i64);
            for bad in [0, 32, 33, 65, -1] {
                for which in 0..2 {
                    let r = if use_host {
                        *h::__errno_location() = 0;
                        let r = if which == 0 { h::sighold(bad) } else { h::sigrelse(bad) };
                        r as i64 * 1000 + i64::from(host_errno())
                    } else {
                        rusty_libc_core::errno::set(0);
                        let r = if which == 0 { sighold(bad) } else { sigrelse(bad) };
                        r as i64 * 1000 + i64::from(rusty_libc_core::errno::get())
                    };
                    seq.push(r);
                }
            }
            // sigignore
            seq.push(c!(sigignore(SIGUSR2), h::sigignore(SIGUSR2)));
            seq.push(host_get(SIGUSR2).sa_handler as i64);
            reset(SIGUSR2);
            // sigset
            seq.push(c!(sigset(SIGUSR2, handler_addr(count_handler)), h::sigset(SIGUSR2, handler_addr(count_handler))));
            seq.push(c!(sigset(SIGUSR2, SIG_HOLD), h::sigset(SIGUSR2, SIG_HOLD)));
            seq.push(cur_mask().val[0] as i64);
            seq.push(c!(sigset(SIGUSR2, SIG_HOLD), h::sigset(SIGUSR2, SIG_HOLD)));
            seq.push(c!(sigset(SIGUSR2, handler_addr(other_handler)), h::sigset(SIGUSR2, handler_addr(other_handler))));
            seq.push(cur_mask().val[0] as i64);
            seq.push(host_get(SIGUSR2).sa_flags as i64);
            seq.push(c!(sigset(SIGUSR2, SIG_DFL), h::sigset(SIGUSR2, SIG_DFL)));
            seq.push(c!(sigset(0, SIG_DFL), h::sigset(0, SIG_DFL)));
            seq.push(c!(sigset(SIGKILL, handler_addr(count_handler)), h::sigset(SIGKILL, handler_addr(count_handler))));
        }
        set_mask(0);
        reset(SIGUSR2);
        logs.push(seq);
    }
    assert_eq!(logs[0], logs[1]);
}

#[test]
fn sigpause_family() {
    let _g = lock();
    set_mask(0);
    for which in 0..3 {
        let mut res = vec![];
        for use_host in [false, true] {
            HITS.store(0, Ordering::SeqCst);
            signal(SIGUSR1, handler_addr(count_handler));
            // block SIGUSR1, make it pending, then the pause variants wait with it unblocked
            set_mask(1 << (SIGUSR1 - 1));
            raise(SIGUSR1);
            let r = unsafe {
                rusty_libc_core::errno::set(0);
                *h::__errno_location() = 0;
                match (which, use_host) {
                    // BSD sigpause(mask): the mask is the whole new mask (0: nothing blocked)
                    (0, false) => (sigpause(0) as i64, rusty_libc_core::errno::get()),
                    (0, true) => (h::sigpause(0) as i64, host_errno()),
                    // POSIX sigpause(sig) = __xpg_sigpause: remove sig from the current mask
                    (1, false) => (__xpg_sigpause(SIGUSR1) as i64, rusty_libc_core::errno::get()),
                    (1, true) => (h::__xpg_sigpause(SIGUSR1) as i64, host_errno()),
                    (_, false) => (__sigpause(SIGUSR1, 1) as i64, rusty_libc_core::errno::get()),
                    (_, true) => (h::__sigpause(SIGUSR1, 1) as i64, host_errno()),
                }
            };
            res.push((r, HITS.load(Ordering::SeqCst), cur_mask().val[0]));
            set_mask(0);
            reset(SIGUSR1);
        }
        assert_eq!(res[0], res[1], "variant {which}");
        assert_eq!(res[0].0, (-1, libc::EINTR));
        assert_eq!(res[0].1, 1);
    }
    // a bad signal for the XPG form
    for bad in [0, 32, 65] {
        same(ours!(__xpg_sigpause(bad)), host!(unsafe { h::__xpg_sigpause(bad) }), "xpg_sigpause bad");
    }
    // sigreturn cannot work on Linux
    same(ours!(sigreturn(core::ptr::null_mut())), host!(unsafe { h::sigreturn(core::ptr::null_mut()) }), "sigreturn");
    assert_eq!(ours!(sigreturn(core::ptr::null_mut())), (-1, libc::ENOSYS));
}

// ---------------------------------------------------------------------------------- names

fn cs(p: *const c_char) -> Option<String> {
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
}

#[test]
fn signal_names_match_glibc() {
    for sig in -3..=70 {
        assert_eq!(cs(sigabbrev_np(sig)), cs(unsafe { h::sigabbrev_np(sig) }), "sigabbrev_np({sig})");
        assert_eq!(cs(sigdescr_np(sig)), cs(unsafe { h::sigdescr_np(sig) }), "sigdescr_np({sig})");
    }
    assert_eq!(cs(sigabbrev_np(2)).as_deref(), Some("INT"));
    assert_eq!(cs(sigdescr_np(SIGSEGV)).as_deref(), Some("Segmentation fault"));
}

/// Run `f` with standard error redirected into a pipe; return what was written.
fn capture_stderr(f: impl FnOnce()) -> Vec<u8> {
    unsafe {
        let mut fds = [0 as c_int; 2];
        assert_eq!(h::pipe(fds.as_mut_ptr()), 0);
        let saved = h::dup(2);
        h::dup2(fds[1], 2);
        f();
        h::dup2(saved, 2);
        h::close(saved);
        h::close(fds[1]);
        let mut out = vec![];
        let mut buf = [0u8; 4096];
        // the writer end is closed: read until EOF
        loop {
            let n = h::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        h::close(fds[0]);
        out
    }
}

#[test]
fn psignal_matches_glibc() {
    let _g = lock();
    for sig in -3..=70 {
        for prefix in [None, Some(""), Some("prog"), Some("a longer prefix: with a colon")] {
            let c = prefix.map(|p| std::ffi::CString::new(p).unwrap());
            let p = c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
            let a = capture_stderr(|| unsafe { psignal(sig, p) });
            let b = capture_stderr(|| unsafe { h::psignal(sig, p) });
            assert_eq!(String::from_utf8_lossy(&a), String::from_utf8_lossy(&b), "psignal({sig}, {prefix:?})");
            assert!(!a.is_empty());
        }
    }
}

#[test]
fn psiginfo_matches_glibc() {
    let _g = lock();
    let rtmin = unsafe { h::__libc_current_sigrtmin() };
    let rtmax = unsafe { h::__libc_current_sigrtmax() };
    assert_eq!((rtmin, rtmax), (__libc_current_sigrtmin(), __libc_current_sigrtmax()));
    let codes = [-70, -60, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 0x80, 1000];
    let mut checked = 0;
    for sig in (-1..=70).chain([100, i32::MAX]) {
        for code in codes {
            for prefix in [None, Some("x")] {
                let mut i = Siginfo::ZERO;
                i.si_signo = sig;
                i.si_code = code;
                i.fields[0] = 0x0000_03e8_0000_1234; // pid 0x1234, uid 1000; also the fault address
                i.fields[1] = 0x1_0000_0007;
                i.fields[2] = 3;
                let c = prefix.map(|p| std::ffi::CString::new(p).unwrap());
                let p = c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
                let a = capture_stderr(|| unsafe { psiginfo(&i, p) });
                let b = capture_stderr(|| unsafe { h::psiginfo(&i, p) });
                assert_eq!(String::from_utf8_lossy(&a), String::from_utf8_lossy(&b), "psiginfo(sig {sig}, code {code}, {prefix:?})");
                checked += 1;
            }
        }
    }
    assert!(checked > 1500);
    // a null fault address prints "(nil)", a negative band prints signed
    for (sig, f0) in [(SIGSEGV, 0u64), (SIGPOLL, (-5i64) as u64), (SIGCHLD, 0xffff_ffff_ffff_ffff), (SIGUSR1, 0xffff_ffff_ffff_ffff)] {
        let mut i = Siginfo::ZERO;
        i.si_signo = sig;
        i.si_code = 1;
        i.fields[0] = f0;
        let a = capture_stderr(|| unsafe { psiginfo(&i, core::ptr::null()) });
        let b = capture_stderr(|| unsafe { h::psiginfo(&i, core::ptr::null()) });
        assert_eq!(String::from_utf8_lossy(&a), String::from_utf8_lossy(&b), "special {sig}");
    }
    // a prefix long enough to cut the line like glibc's 512-byte buffer
    let long = std::ffi::CString::new("p".repeat(600)).unwrap();
    let mut i = Siginfo::ZERO;
    i.si_signo = SIGUSR1;
    let a = capture_stderr(|| unsafe { psiginfo(&i, long.as_ptr()) });
    let b = capture_stderr(|| unsafe { h::psiginfo(&i, long.as_ptr()) });
    assert_eq!(a, b);
}

#[test]
fn realtime_signal_numbers() {
    let _g = lock();
    assert_eq!(__libc_current_sigrtmin(), 34);
    assert_eq!(__libc_current_sigrtmax(), 64);
    // do not call the host's __libc_allocate_rtsig here: it would move the host's own range; the C
    // test (tests/c/signal_diff.c) compares the allocation sequence in a separate process
    assert_eq!(unsafe { h::__libc_current_sigrtmin() }, 34);
    let first = __libc_allocate_rtsig(1);
    let last = __libc_allocate_rtsig(0);
    // other tests may have allocated too: only check the shape
    assert!(first >= 34 && last <= 64 && first < last);
    assert_eq!(__libc_current_sigrtmin(), first + 1);
    assert_eq!(__libc_current_sigrtmax(), last - 1);
    // put the range back for the other tests
    crate::rt::reset_for_tests();
}

// ---------------------------------------------------------------------------------- contexts

/// Run a 100%-Rust coroutine ping-pong on `makecontext` / `swapcontext` stacks.
mod coroutine {
    use super::*;

    pub static mut MAIN: UContext = unsafe { zeroed() };
    pub static mut CO: UContext = unsafe { zeroed() };
    pub static TRACE: Mutex<Vec<i64>> = Mutex::new(vec![]);
    pub static SUM: AtomicI32 = AtomicI32::new(0);

    pub extern "C" fn body(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, hh: i64) {
        TRACE.lock().unwrap().extend([a, b, c, d, e, f, g, hh]);
        for i in 0..3 {
            SUM.fetch_add(i + 1, Ordering::SeqCst);
            // hand control back to main; main resumes us again
            unsafe { swapcontext(&raw mut CO, &raw const MAIN) };
        }
        // returning resumes uc_link (main)
    }
    pub extern "C" fn no_args() {
        SUM.fetch_add(100, Ordering::SeqCst);
    }
}

#[test]
fn makecontext_swapcontext_coroutine() {
    let _g = lock();
    use coroutine::*;
    SUM.store(0, Ordering::SeqCst);
    TRACE.lock().unwrap().clear();
    let mut stack = vec![0u8; 128 * 1024];
    unsafe {
        let co = &raw mut CO;
        assert_eq!(getcontext(co), 0);
        (*co).uc_stack.ss_sp = stack.as_mut_ptr().cast();
        (*co).uc_stack.ss_size = stack.len();
        (*co).uc_link = &raw mut MAIN;
        // 8 integer arguments: six in registers, two on the stack
        makecontext(co, core::mem::transmute::<extern "C" fn(i64, i64, i64, i64, i64, i64, i64, i64), extern "C" fn()>(body), 8, 1i64, 2i64, 3i64, 4i64, 5i64, 6i64, 7i64, -8i64);
        for round in 1..=3 {
            assert_eq!(swapcontext(&raw mut MAIN, co), 0);
            assert_eq!(SUM.load(Ordering::SeqCst), (1..=round).sum::<i32>(), "round {round}");
        }
        // the last swap lets the body finish and return into MAIN through uc_link
        assert_eq!(swapcontext(&raw mut MAIN, co), 0);
        assert_eq!(SUM.load(Ordering::SeqCst), 6);
        assert_eq!(*TRACE.lock().unwrap(), vec![1, 2, 3, 4, 5, 6, 7, -8]);
        // a second context, no arguments, on the same stack, linked to MAIN; setcontext into it
        // would not come back, so use swapcontext again
        assert_eq!(getcontext(co), 0);
        (*co).uc_stack.ss_sp = stack.as_mut_ptr().cast();
        (*co).uc_stack.ss_size = stack.len();
        (*co).uc_link = &raw mut MAIN;
        makecontext(co, no_args, 0);
        assert_eq!(swapcontext(&raw mut MAIN, co), 0);
        assert_eq!(SUM.load(Ordering::SeqCst), 106);
    }
}

#[test]
fn getcontext_and_makecontext_fill_the_same_fields_as_glibc() {
    let _g = lock();
    set_mask(1 << (SIGUSR2 - 1));
    unsafe {
        let mut a: UContext = zeroed();
        let mut b: UContext = zeroed();
        assert_eq!(getcontext(&mut a), 0);
        assert_eq!(h::getcontext(&mut b), 0);
        assert_eq!(a.uc_sigmask.val[0], b.uc_sigmask.val[0]);
        assert_eq!(a.uc_sigmask.val[0], 1 << (SIGUSR2 - 1));
        assert_eq!(a.fpregs_mem.mxcsr, b.fpregs_mem.mxcsr);
        assert_eq!(a.fpregs_mem.cwd, b.fpregs_mem.cwd);
        assert_eq!(a.uc_mcontext.fpregs as usize, &a.fpregs_mem as *const FpState as usize);
        assert_eq!(b.uc_mcontext.fpregs as usize, &b.fpregs_mem as *const FpState as usize);
        // the saved callee-saved registers and the stack pointer of this call
        assert_ne!(a.uc_mcontext.gregs[REG_RSP], 0);
        assert_ne!(a.uc_mcontext.gregs[REG_RIP], 0);
        assert_eq!(a.uc_mcontext.gregs[REG_RDI], &a as *const UContext as i64, "rdi holds ucp, as in glibc");
        assert_eq!(b.uc_mcontext.gregs[REG_RDI], &b as *const UContext as i64);
        // makecontext: compare the registers and stack words with the host's for 0..=10 arguments
        extern "C" fn f() {}
        for argc in 0..=10i32 {
            let mut st_a = vec![0u64; 512];
            let mut st_b = vec![0u64; 512];
            let (mut ua, mut ub): (UContext, UContext) = (zeroed(), zeroed());
            let (mut link_a, mut link_b): (UContext, UContext) = (zeroed(), zeroed());
            // identical stack placement relative to a 16-byte aligned top
            let top_a = (st_a.as_mut_ptr() as usize + 4096 - 16) & !15;
            let top_b = (st_b.as_mut_ptr() as usize + 4096 - 16) & !15;
            for (u, top, link) in [(&mut ua, top_a, &mut link_a as *mut UContext), (&mut ub, top_b, &mut link_b as *mut UContext)] {
                u.uc_stack.ss_sp = (top - 2048) as *mut c_void;
                u.uc_stack.ss_size = 2048;
                u.uc_link = link;
            }
            let args: [i64; 10] = [11, 22, 33, 44, 55, 66, 77, 88, 99, 110];
            macro_rules! call {
                ($mk:expr, $u:expr) => {
                    match argc {
                        0 => $mk($u, f, 0),
                        1 => $mk($u, f, 1, args[0]),
                        2 => $mk($u, f, 2, args[0], args[1]),
                        3 => $mk($u, f, 3, args[0], args[1], args[2]),
                        4 => $mk($u, f, 4, args[0], args[1], args[2], args[3]),
                        5 => $mk($u, f, 5, args[0], args[1], args[2], args[3], args[4]),
                        6 => $mk($u, f, 6, args[0], args[1], args[2], args[3], args[4], args[5]),
                        7 => $mk($u, f, 7, args[0], args[1], args[2], args[3], args[4], args[5], args[6]),
                        8 => $mk($u, f, 8, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]),
                        9 => $mk($u, f, 9, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]),
                        _ => $mk($u, f, 10, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]),
                    }
                };
            }
            call!(makecontext, &mut ua);
            call!(h::makecontext, &mut ub);
            let (ga, gb) = (&ua.uc_mcontext.gregs, &ub.uc_mcontext.gregs);
            for r in [REG_RIP, REG_RDI, REG_RSI, REG_RDX, REG_RCX, REG_R8, REG_R9] {
                assert_eq!(ga[r], gb[r], "argc {argc} register {r}");
            }
            // stack pointer and rbx relative to the top
            assert_eq!(top_a as i64 - ga[REG_RSP], top_b as i64 - gb[REG_RSP], "argc {argc} rsp");
            assert_eq!(top_a as i64 - ga[REG_RBX], top_b as i64 - gb[REG_RBX], "argc {argc} rbx");
            // the words on the stack: slot 0 is the (different) start routine, the rest equal;
            // uc_link slot holds the link context's address
            let words = (top_a as i64 - ga[REG_RSP]) as usize / 8;
            let sa = ga[REG_RSP] as *const u64;
            let sb = gb[REG_RSP] as *const u64;
            assert_ne!(*sa, 0);
            for i in 1..words {
                let (x, y) = (*sa.add(i), *sb.add(i));
                if x == &link_a as *const UContext as u64 {
                    assert_eq!(y, &link_b as *const UContext as u64, "argc {argc} uc_link slot {i}");
                } else {
                    assert_eq!(x, y, "argc {argc} stack word {i}");
                }
            }
        }
    }
    set_mask(0);
}
