use crate::sys::*;
use crate::thread::{Thread, current_thread, field_of, shared_field, tid_word};
use core::arch::global_asm;
use rusty_libc_core::cleanup;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, Ordering};
use rusty_libc_core::signal::{KSigaction, SA_RESTORER, sigaction};

pub const DISABLE_BIT: u32 = 1;
pub const ASYNC_BIT: u32 = 2;
pub const CANCELED_BIT: u32 = 4;
pub const EXITING_BIT: u32 = 8;

pub const PTHREAD_CANCEL_ENABLE: c_int = 0;
pub const PTHREAD_CANCEL_DISABLE: c_int = 1;
pub const PTHREAD_CANCEL_DEFERRED: c_int = 0;
pub const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;
pub const PTHREAD_CANCELED: usize = usize::MAX;

pub const SIGCANCEL: c_int = 32;
pub const SIGSETXID: c_int = 33;
pub const INTERNAL_SIGNALS: u64 = (1 << (SIGCANCEL - 1)) | (1 << (SIGSETXID - 1));

const SA_SIGINFO: u64 = 4;
const SA_RESTART: u64 = 0x1000_0000;

unsafe extern "C" {
    fn rl_syscall_cancel_arch(cancelp: *const AtomicU32, nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize;
    static rl_cancel_start: u8;
    static rl_cancel_end: u8;
    fn rl_sigreturn();
}

global_asm!(
    ".text",
    ".globl rl_syscall_cancel_arch",
    ".type rl_syscall_cancel_arch, @function",
    "rl_syscall_cancel_arch:",
    ".cfi_startproc",
    ".globl rl_cancel_start",
    "rl_cancel_start:",
    "mov eax, dword ptr [rdi]",
    "and eax, 13",
    "cmp eax, 4",
    "je 2f",
    "mov rax, rsi",
    "mov rdi, rdx",
    "mov rsi, rcx",
    "mov rdx, r8",
    "mov r10, r9",
    "mov r8, qword ptr [rsp + 8]",
    "mov r9, qword ptr [rsp + 16]",
    "syscall",
    ".globl rl_cancel_end",
    "rl_cancel_end:",
    "ret",
    "2:",
    "sub rsp, 8",
    ".cfi_adjust_cfa_offset 8",
    "call {docancel}",
    "ud2",
    ".cfi_endproc",
    ".size rl_syscall_cancel_arch, . - rl_syscall_cancel_arch",
    docancel = sym do_cancel_c,
);

global_asm!(rusty_libc_core::restorer_asm!("rl_sigreturn"));

extern "C" fn do_cancel_c() -> ! {
    do_cancel()
}

pub fn restorer() -> usize {
    rl_sigreturn as *const () as usize
}

#[inline(always)]
fn word() -> &'static AtomicU32 {
    let p = rusty_libc_core::tls::current().cast::<u8>().wrapping_add(core::mem::offset_of!(rusty_libc_core::tls::Tcb, cancelhandling));
    unsafe { &*p.cast::<AtomicU32>() }
}

#[inline(always)]
pub(crate) unsafe fn word_of<'a>(t: *mut Thread) -> &'a AtomicU32 {
    unsafe { shared_field(field_of!(t, tcb.cancelhandling: AtomicU32)) }
}

pub fn ensure_init() {
    static DONE: AtomicU32 = AtomicU32::new(0);
    if DONE.load(Ordering::Acquire) == 2 {
        return;
    }
    if DONE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        let act = KSigaction { handler: sigcancel_handler as *const () as usize, flags: SA_SIGINFO | SA_RESTART | SA_RESTORER, restorer: rl_sigreturn as *const () as usize, mask: 0 };
        let _ = sigaction(SIGCANCEL, Some(&act));
        rusty_libc_core::tls::CANCEL_SYSCALL.store(hook as *const () as usize, Ordering::Release);
        DONE.store(2, Ordering::Release);
    } else {
        while DONE.load(Ordering::Acquire) != 2 {
            sched_yield();
        }
    }
}

extern "C" fn hook(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    unsafe { syscall_cp(nr, a1, a2, a3, a4, a5, a6) }
}

pub unsafe fn syscall_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let r = unsafe { rl_syscall_cancel_arch(word(), nr, a1, a2, a3, a4, a5, a6) };
    if r == (-(EINTR as isize)) as usize {
        testcancel();
    }
    r
}

extern "C" fn sigcancel_handler(sig: c_int, info: *const u8, uc: *mut u8) {
    if sig != SIGCANCEL {
        return;
    }
    let si_code = unsafe { *(info.wrapping_add(8) as *const i32) };
    let si_pid = unsafe { *(info.wrapping_add(16) as *const i32) };
    if si_code != -6 || si_pid != getpid() {
        return;
    }
    let h = word().load(Ordering::Acquire);
    if h & CANCELED_BIT == 0 || h & (DISABLE_BIT | EXITING_BIT) != 0 {
        return;
    }
    let rip = unsafe { *(uc.wrapping_add(40 + 16 * 8) as *const usize) };
    let start = &raw const rl_cancel_start as usize;
    let end = &raw const rl_cancel_end as usize;
    if h & ASYNC_BIT != 0 || (rip >= start && rip < end) {
        do_cancel();
    }
}

pub fn do_cancel() -> ! {
    let t = current_thread();
    word().fetch_or(EXITING_BIT | DISABLE_BIT, Ordering::AcqRel);
    word().fetch_and(!ASYNC_BIT, Ordering::AcqRel);
    unsafe { crate::setxid::set_exiting(t) };
    unsafe { *field_of!(t, exit_value: *mut c_void) = PTHREAD_CANCELED as *mut c_void };
    unsafe { unwind_continue() }
}

#[repr(C)]
pub struct UnwindBuf {
    pub jmp: [u64; 8],
    pub mask_was_saved: c_int,
    pub prev: *mut UnwindBuf,
    pub cleanup: *mut CleanupBuf,
    pub canceltype: c_int,
    pub pad: [*mut c_void; 1],
}
const _: () = assert!(core::mem::size_of::<UnwindBuf>() == 104);
const _: () = assert!(core::mem::offset_of!(UnwindBuf, prev) == 72);

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn rl_unwind_longjmp(_env: *mut UnwindBuf, _val: c_int) -> ! {
    core::arch::naked_asm!(
        "mov rbx, [rdi]",
        "mov rbp, [rdi + 8]",
        "ror rbp, 0x11",
        "xor rbp, qword ptr fs:[0x30]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        "mov rdx, [rdi + 48]",
        "ror rdx, 0x11",
        "xor rdx, qword ptr fs:[0x30]",
        "mov rcx, [rdi + 56]",
        "ror rcx, 0x11",
        "xor rcx, qword ptr fs:[0x30]",
        "mov eax, esi",
        "mov rsp, rdx",
        "jmp rcx",
    )
}

#[repr(C, align(16))]
pub struct UnwindException {
    pub exception_class: u64,
    pub exception_cleanup: Option<unsafe extern "C" fn(c_int, *mut UnwindException)>,
    pub private_1: u64,
    pub private_2: u64,
}

impl UnwindException {
    pub const fn new() -> UnwindException {
        UnwindException { exception_class: 0, exception_cleanup: None, private_1: 0, private_2: 0 }
    }
}

impl Default for UnwindException {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) unsafe fn unwind_continue() -> ! {
    let t = current_thread();
    #[cfg(feature = "unwind")]
    unsafe {
        crate::unwind::forced_unwind()
    };
    let unwind = field_of!(t, unwind: *mut UnwindBuf);
    let top = unsafe { *unwind };
    let stop = if top.is_null() { core::ptr::null_mut() } else { unsafe { (*top).cleanup } };
    while !cleanup::head().is_null() && cleanup::head() != stop {
        unsafe { run_cleanup(cleanup::head()) };
    }
    if top.is_null() {
        crate::thread::thread_exit(unsafe { *field_of!(t, exit_value: *mut c_void) })
    }
    let prev = unsafe { (*top).prev };
    unsafe { *unwind = prev };
    unsafe { rl_unwind_longjmp(top, 1) }
}

pub(crate) unsafe fn run_cleanup(b: *mut CleanupBuf) {
    let b = unsafe { &*b };
    cleanup::set_head(b.prev);
    unsafe { (b.routine)(b.arg) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel(buf: *mut c_void) {
    let b = unsafe { arg_mut(buf as *mut UnwindBuf) };
    let unwind = field_of!(current_thread(), unwind: *mut UnwindBuf);
    b.prev = unsafe { *unwind };
    b.cleanup = cleanup::head();
    unsafe { *unwind = b };
}

unsafe fn unregister(buf: *mut c_void) -> &'static mut UnwindBuf {
    let b = unsafe { arg_mut(buf as *mut UnwindBuf) };
    unsafe { *field_of!(current_thread(), unwind: *mut UnwindBuf) = b.prev };
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel(buf: *mut c_void) {
    unsafe { unregister(buf) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel_defer(buf: *mut c_void) {
    let mut old = 0;
    setcanceltype(PTHREAD_CANCEL_DEFERRED, Some(&mut old));
    unsafe { __pthread_register_cancel(buf) };
    unsafe { arg_mut(buf as *mut UnwindBuf) }.canceltype = old;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel_restore(buf: *mut c_void) {
    let b = unsafe { unregister(buf) };
    setcanceltype(b.canceltype, None);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unwind_next(buf: *mut c_void) -> ! {
    unsafe { unregister(buf) };
    unsafe { unwind_continue() }
}

#[repr(C)]
pub struct CleanupFrame {
    pub cancel_routine: Option<unsafe extern "C" fn(*mut c_void)>,
    pub cancel_arg: *mut c_void,
    pub do_it: c_int,
    pub cancel_type: c_int,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_cleanup_routine(frame: *mut c_void) {
    let frame = unsafe { arg(frame as *const CleanupFrame) };
    if frame.do_it != 0 {
        if let Some(f) = frame.cancel_routine {
            unsafe { f(frame.cancel_arg) };
        }
    }
}

#[inline]
pub fn testcancel() {
    let h = word().load(Ordering::Acquire);
    if h & (CANCELED_BIT | DISABLE_BIT | EXITING_BIT) == CANCELED_BIT {
        do_cancel();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pthread_testcancel() {
    testcancel();
}

pub fn setcancelstate(state: c_int, oldstate: Option<&mut c_int>) -> c_int {
    if state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE {
        return EINVAL;
    }
    ensure_init();
    let w = word();
    let mut old = w.load(Ordering::Relaxed);
    loop {
        let new = if state == PTHREAD_CANCEL_DISABLE { old | DISABLE_BIT } else { old & !DISABLE_BIT };
        if new == old {
            break;
        }
        match w.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
    if let Some(o) = oldstate {
        *o = if old & DISABLE_BIT != 0 { PTHREAD_CANCEL_DISABLE } else { PTHREAD_CANCEL_ENABLE };
    }
    if state == PTHREAD_CANCEL_ENABLE {
        let h = w.load(Ordering::Acquire);
        if h & (CANCELED_BIT | ASYNC_BIT | DISABLE_BIT | EXITING_BIT) == (CANCELED_BIT | ASYNC_BIT) {
            do_cancel();
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int {
    setcancelstate(state, unsafe { oldstate.as_mut() })
}

pub fn setcanceltype(ctype: c_int, oldtype: Option<&mut c_int>) -> c_int {
    if ctype != PTHREAD_CANCEL_DEFERRED && ctype != PTHREAD_CANCEL_ASYNCHRONOUS {
        return EINVAL;
    }
    ensure_init();
    let w = word();
    let mut old = w.load(Ordering::Relaxed);
    loop {
        let new = if ctype == PTHREAD_CANCEL_ASYNCHRONOUS { old | ASYNC_BIT } else { old & !ASYNC_BIT };
        if new == old {
            break;
        }
        match w.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
    if let Some(o) = oldtype {
        *o = if old & ASYNC_BIT != 0 { PTHREAD_CANCEL_ASYNCHRONOUS } else { PTHREAD_CANCEL_DEFERRED };
    }
    if ctype == PTHREAD_CANCEL_ASYNCHRONOUS {
        let h = w.load(Ordering::Acquire);
        if h & (CANCELED_BIT | DISABLE_BIT | EXITING_BIT) == CANCELED_BIT {
            do_cancel();
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcanceltype(ctype: c_int, oldtype: *mut c_int) -> c_int {
    setcanceltype(ctype, unsafe { oldtype.as_mut() })
}

#[inline]
pub unsafe fn cancel(t: *mut Thread) -> c_int {
    ensure_init();
    let tid = unsafe { tid_word(t) };
    if tid.load(Ordering::Relaxed) < 0 {
        return ESRCH;
    }
    #[cfg(feature = "unwind-dl")]
    let _ = crate::unwind::resolve();
    let w = unsafe { word_of(t) };
    let mut old = w.load(Ordering::Relaxed);
    loop {
        if old & (CANCELED_BIT | EXITING_BIT) != 0 {
            return 0;
        }
        match w.compare_exchange_weak(old, old | CANCELED_BIT, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
    if old & DISABLE_BIT != 0 {
        return 0;
    }
    if t == current_thread() {
        if old & ASYNC_BIT != 0 {
            do_cancel();
        }
        return 0;
    }
    let tid = tid.load(Ordering::Relaxed);
    if tid > 0 {
        tgkill(getpid(), tid, SIGCANCEL);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cancel(th: PthreadT) -> c_int {
    unsafe { cancel(th as *mut Thread) }
}

pub use rusty_libc_core::cleanup::CleanupBuf;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    unsafe { cleanup::push(buf, routine, arg) };
}

unsafe fn pop_and_run(buf: *mut CleanupBuf, execute: c_int) -> &'static CleanupBuf {
    unsafe { cleanup::pop(buf) };
    let b = unsafe { arg(buf) };
    if execute != 0 {
        unsafe { (b.routine)(b.arg) };
    }
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop(buf: *mut CleanupBuf, execute: c_int) {
    unsafe { pop_and_run(buf, execute) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push_defer(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    let mut old = 0;
    setcanceltype(PTHREAD_CANCEL_DEFERRED, Some(&mut old));
    unsafe { _pthread_cleanup_push(buf, routine, arg) };
    unsafe { (*buf).canceltype = old };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop_restore(buf: *mut CleanupBuf, execute: c_int) {
    let b = unsafe { pop_and_run(buf, execute) };
    setcanceltype(b.canceltype, None);
}

pub unsafe fn with_cleanup<R>(routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void, body: impl FnOnce() -> R) -> R {
    unsafe { cleanup::with(routine, arg, body) }
}
