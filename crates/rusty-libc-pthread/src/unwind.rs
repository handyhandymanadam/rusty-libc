//! Cancellation and `pthread_exit` by a forced unwind, as glibc does it (nptl/unwind.c): when an unwinder is there
//! (`_Unwind_ForcedUnwind` of libgcc), the frames of the thread are unwound one by one under a stop function; the landing
//! pads of the frames run (C++ destructors, `__attribute__((cleanup))` of code built with `-fexceptions`, which includes the
//! `pthread_cleanup_push` of glibc's header in C++ and with `-fexceptions`, and Rust `Drop`), the handlers registered by
//! `pthread_cleanup_push` run as their frames are left, and at the end of the stack (the thread's start or `main`) the
//! thread ends. Without an unwinder, or if it fails, `cancel::unwind_continue` does what it did before: the registered
//! handlers in one go and the thread ends.
//!
//! * The static runtime (`feature = "unwind"`) finds the unwinder as a weak symbol: it is there when the program uses
//!   exceptions (libgcc_eh's unwind-dw2 defines `_Unwind_ForcedUnwind` next to `_Unwind_Resume`).
//! * The shared library (`feature = "unwind-dl"`) looks for it in the process and else loads `libgcc_s.so.1`, as glibc's
//!   `pthread_cancel_init` does.
//!
//! What glibc does with Rust (checked on this machine): the `Drop` of the cancelled thread's values runs up to the
//! catch of Rust's thread start, which does not rethrow, so the unwinder's `exception_cleanup` runs and glibc prints
//! "FATAL: exception not rethrown" and aborts. The same happens here, for the same reason.
#![cfg(feature = "unwind")]
use crate::cancel::{UnwindBuf, UnwindException, rl_unwind_longjmp};
use crate::thread::{current_thread, field_of};
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};
use rusty_libc_core::cleanup;

type StopFn = unsafe extern "C" fn(c_int, c_int, u64, *mut UnwindException, *mut c_void, *mut c_void) -> c_int;
type ForcedUnwind = unsafe extern "C" fn(*mut UnwindException, StopFn, *mut c_void) -> c_int;
type GetCfa = unsafe extern "C" fn(*mut c_void) -> usize;

/// `_UA_END_OF_STACK`
const UA_END_OF_STACK: c_int = 16;
const URC_NO_REASON: c_int = 0;

static FORCED: AtomicUsize = AtomicUsize::new(0);
static CFA: AtomicUsize = AtomicUsize::new(0);
/// 0 not looked for yet, 1 looking, 2 done (FORCED and CFA are 0 when there is no unwinder).
static STATE: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(feature = "unwind-dl"))]
fn find() -> (usize, usize) {
    macro_rules! weak_addr {
        ($sym:literal) => {{
            let a: usize;
            // SAFETY: only reads a symbol address
            unsafe { core::arch::asm!(concat!(".weak ", $sym), concat!("lea {0}, [rip + ", $sym, "]"), out(reg) a, options(nomem, nostack, preserves_flags)) };
            a
        }};
    }
    (weak_addr!("_Unwind_ForcedUnwind"), weak_addr!("_Unwind_GetCFA"))
}

#[cfg(feature = "unwind-dl")]
fn find() -> (usize, usize) {
    unsafe extern "C" {
        fn dlopen(file: *const core::ffi::c_char, mode: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, name: *const core::ffi::c_char) -> *mut c_void;
    }
    let sym = |h: *mut c_void, name: &core::ffi::CStr| {
        // SAFETY: the loader's dlsym with a handle it gave (or RTLD_DEFAULT) and a NUL-terminated name.
        unsafe { dlsym(h, name.as_ptr()) as usize }
    };
    let mut f = sym(core::ptr::null_mut(), c"_Unwind_ForcedUnwind");
    let mut c = sym(core::ptr::null_mut(), c"_Unwind_GetCFA");
    if f == 0 || c == 0 {
        // RTLD_NOW
        // SAFETY: the loader's dlopen with a NUL-terminated name.
        let h = unsafe { dlopen(c"libgcc_s.so.1".as_ptr(), 2) };
        if !h.is_null() {
            f = sym(h, c"_Unwind_ForcedUnwind");
            c = sym(h, c"_Unwind_GetCFA");
        }
    }
    if f == 0 || c == 0 { (0, 0) } else { (f, c) }
}

/// The unwinder's two entry points, found on first use.
pub(crate) fn resolve() -> Option<(ForcedUnwind, GetCfa)> {
    loop {
        match STATE.load(Ordering::Acquire) {
            2 => break,
            0 => {
                if STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    let (f, c) = find();
                    FORCED.store(f, Ordering::Release);
                    CFA.store(c, Ordering::Release);
                    STATE.store(2, Ordering::Release);
                    break;
                }
            }
            _ => core::hint::spin_loop(),
        }
    }
    let (f, c) = (FORCED.load(Ordering::Acquire), CFA.load(Ordering::Acquire));
    if f == 0 || c == 0 {
        return None;
    }
    // SAFETY: the address of libgcc's _Unwind_ForcedUnwind, which has this signature.
    let forced = unsafe { core::mem::transmute::<usize, ForcedUnwind>(f) };
    // SAFETY: the address of libgcc's _Unwind_GetCFA, which has this signature.
    let cfa = unsafe { core::mem::transmute::<usize, GetCfa>(c) };
    Some((forced, cfa))
}

/// A C++ `catch (...)` that does not rethrow: glibc's `unwind_cleanup` aborts with this text.
unsafe extern "C" fn exception_cleanup(_reason: c_int, _exc: *mut UnwindException) {
    let msg = b"FATAL: exception not rethrown\n";
    let _ = rusty_libc_core::unistd::write(2, msg);
    rusty_libc_core::process::abort();
}

/// The stack pointer saved in a glibc-style cancellation buffer (`__sigsetjmp_cancel`'s buffer keeps it mangled).
///
/// # Safety
/// `b` is a live buffer registered by the calling thread.
unsafe fn buf_rsp(b: *const UnwindBuf) -> usize {
    let guard: usize;
    // SAFETY: reads the calling thread's pointer guard from its TCB (%fs:0x30); no memory is written.
    unsafe { core::arch::asm!("mov {0}, qword ptr fs:[0x30]", out(reg) guard, options(nostack, preserves_flags, readonly)) };
    // SAFETY: forwarded contract.
    let saved = unsafe { (*b).jmp[6] };
    (saved as usize).rotate_right(0x11) ^ guard
}

/// glibc's `unwind_stop`: called for every frame the unwinder is about to unwind (and once at the end of the stack).
unsafe extern "C" fn stop(_version: c_int, actions: c_int, _class: u64, _exc: *mut UnwindException, context: *mut c_void, _arg: *mut c_void) -> c_int {
    let t = current_thread();
    // SAFETY: CFA holds libgcc's _Unwind_GetCFA (resolve ran before the unwind started).
    let get_cfa: GetCfa = unsafe { core::mem::transmute::<usize, GetCfa>(CFA.load(Ordering::Acquire)) };
    let end = actions & UA_END_OF_STACK != 0;
    // at the end of the stack there is no frame to ask (code without unwind tables, built with -fno-exceptions
    // -fno-asynchronous-unwind-tables, ends the walk early): every remaining buffer counts as reached
    // SAFETY: `context` is the unwinder's context for the frame being unwound.
    let cfa = if end { usize::MAX } else { unsafe { get_cfa(context) } };
    // a glibc-style buffer (code built with the non-exception cleanup macros) whose frame the unwinder has reached:
    // control goes to it (its code runs its handler and calls __pthread_unwind_next, which unwinds on from there)
    let unwind = field_of!(t, unwind: *mut UnwindBuf);
    // SAFETY: the calling thread's own descriptor; only this thread changes its buffer list.
    let top = unsafe { *unwind };
    // SAFETY: a non-NULL `top` is a live buffer of this thread (its frame is not unwound yet).
    let reached = !top.is_null() && (end || cfa >= unsafe { buf_rsp(top) });
    // SAFETY: as above.
    let stop_at = if reached { unsafe { (*top).cleanup } } else { core::ptr::null_mut() };
    // the handlers of pthread_cleanup_push whose frames are left, newest first
    loop {
        let b = cleanup::head();
        if b.is_null() || b == stop_at || !(end || reached || b as usize <= cfa) {
            break;
        }
        // SAFETY: the head record of this thread's list, live on its stack (its frame is not unwound yet).
        unsafe { crate::cancel::run_cleanup(b) };
    }
    if reached {
        // SAFETY: `top` is live (see above).
        let prev = unsafe { (*top).prev };
        // SAFETY: own descriptor.
        unsafe { *unwind = prev };
        // SAFETY: `top` was filled by __sigsetjmp_cancel in a frame that is still live.
        unsafe { rl_unwind_longjmp(top, 1) };
    }
    if end {
        // SAFETY: own descriptor.
        crate::thread::thread_exit(unsafe { *field_of!(t, exit_value: *mut c_void) });
    }
    URC_NO_REASON
}

/// Unwind the calling thread's stack under `stop`. Returns only if there is no unwinder or it failed.
///
/// # Safety
/// Called by the thread that is ending, with its exit value set (cancel::unwind_continue's contract).
pub(crate) unsafe fn forced_unwind() {
    let Some((forced, _)) = resolve() else { return };
    let t = current_thread();
    let exc = field_of!(t, exc: UnwindException);
    // SAFETY: the calling thread's own descriptor; the exception object is used only by its own unwind.
    let e = unsafe { &mut *exc };
    e.exception_class = 0;
    e.exception_cleanup = Some(exception_cleanup);
    // SAFETY: libgcc's forced unwind of this thread's stack under `stop` (which ends the thread at the end of the stack).
    unsafe { forced(exc, stop, core::ptr::null_mut()) };
    // (a failed unwind comes back here: the caller carries on without the frames)
}
