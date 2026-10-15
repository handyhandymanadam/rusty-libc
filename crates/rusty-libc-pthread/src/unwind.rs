#![cfg(feature = "unwind")]
use crate::cancel::{UnwindBuf, UnwindException, rl_unwind_longjmp};
use crate::thread::{current_thread, field_of};
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};
use rusty_libc_core::cleanup;

type StopFn = unsafe extern "C" fn(c_int, c_int, u64, *mut UnwindException, *mut c_void, *mut c_void) -> c_int;
type ForcedUnwind = unsafe extern "C" fn(*mut UnwindException, StopFn, *mut c_void) -> c_int;
type GetCfa = unsafe extern "C" fn(*mut c_void) -> usize;

const UA_END_OF_STACK: c_int = 16;
const URC_NO_REASON: c_int = 0;

static FORCED: AtomicUsize = AtomicUsize::new(0);
static CFA: AtomicUsize = AtomicUsize::new(0);
static STATE: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(feature = "unwind-dl"))]
fn find() -> (usize, usize) {
    macro_rules! weak_addr {
        ($sym:literal) => {{
            let a: usize;
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
        unsafe { dlsym(h, name.as_ptr()) as usize }
    };
    let mut f = sym(core::ptr::null_mut(), c"_Unwind_ForcedUnwind");
    let mut c = sym(core::ptr::null_mut(), c"_Unwind_GetCFA");
    if f == 0 || c == 0 {
        let h = unsafe { dlopen(c"libgcc_s.so.1".as_ptr(), 2) };
        if !h.is_null() {
            f = sym(h, c"_Unwind_ForcedUnwind");
            c = sym(h, c"_Unwind_GetCFA");
        }
    }
    if f == 0 || c == 0 { (0, 0) } else { (f, c) }
}

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
    let forced = unsafe { core::mem::transmute::<usize, ForcedUnwind>(f) };
    let cfa = unsafe { core::mem::transmute::<usize, GetCfa>(c) };
    Some((forced, cfa))
}

unsafe extern "C" fn exception_cleanup(_reason: c_int, _exc: *mut UnwindException) {
    let msg = b"FATAL: exception not rethrown\n";
    let _ = rusty_libc_core::unistd::write(2, msg);
    rusty_libc_core::process::abort();
}

unsafe fn buf_rsp(b: *const UnwindBuf) -> usize {
    let guard: usize;
    unsafe { core::arch::asm!("mov {0}, qword ptr fs:[0x30]", out(reg) guard, options(nostack, preserves_flags, readonly)) };
    let saved = unsafe { (*b).jmp[6] };
    (saved as usize).rotate_right(0x11) ^ guard
}

unsafe extern "C" fn stop(_version: c_int, actions: c_int, _class: u64, _exc: *mut UnwindException, context: *mut c_void, _arg: *mut c_void) -> c_int {
    let t = current_thread();
    let get_cfa: GetCfa = unsafe { core::mem::transmute::<usize, GetCfa>(CFA.load(Ordering::Acquire)) };
    let end = actions & UA_END_OF_STACK != 0;
    let cfa = if end { usize::MAX } else { unsafe { get_cfa(context) } };
    let unwind = field_of!(t, unwind: *mut UnwindBuf);
    let top = unsafe { *unwind };
    let reached = !top.is_null() && (end || cfa >= unsafe { buf_rsp(top) });
    let stop_at = if reached { unsafe { (*top).cleanup } } else { core::ptr::null_mut() };
    loop {
        let b = cleanup::head();
        if b.is_null() || b == stop_at || !(end || reached || b as usize <= cfa) {
            break;
        }
        unsafe { crate::cancel::run_cleanup(b) };
    }
    if reached {
        let prev = unsafe { (*top).prev };
        unsafe { *unwind = prev };
        unsafe { rl_unwind_longjmp(top, 1) };
    }
    if end {
        crate::thread::thread_exit(unsafe { *field_of!(t, exit_value: *mut c_void) });
    }
    URC_NO_REASON
}

pub(crate) unsafe fn forced_unwind() {
    let Some((forced, _)) = resolve() else { return };
    let t = current_thread();
    let exc = field_of!(t, exc: UnwindException);
    let e = unsafe { &mut *exc };
    e.exception_class = 0;
    e.exception_cleanup = Some(exception_cleanup);
    unsafe { forced(exc, stop, core::ptr::null_mut()) };
}
