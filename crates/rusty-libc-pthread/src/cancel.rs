use crate::sys::*;
use crate::thread::{Thread, current_thread};
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
    ".globl rl_sigreturn",
    ".type rl_sigreturn, @function",
    "rl_sigreturn:",
    "mov eax, 15",
    "syscall",
    ".size rl_sigreturn, . - rl_sigreturn",
    docancel = sym do_cancel_c,
);

extern "C" fn do_cancel_c() -> ! {
    do_cancel()
}

#[cfg(feature = "unwind")]
unsafe extern "C" {
    fn rl_cancel_here() -> !;
}
#[cfg(feature = "unwind")]
global_asm!(
    ".text",
    ".globl rl_cancel_here",
    ".type rl_cancel_here, @function",
    "rl_cancel_here:",
    ".cfi_startproc",
    ".cfi_def_cfa rsp, 8",
    ".cfi_offset rip, -8",
    "push rbp",
    ".cfi_def_cfa_offset 16",
    ".cfi_offset rbp, -16",
    "mov rbp, rsp",
    ".cfi_def_cfa_register rbp",
    "and rsp, -16",
    "call {docancel}",
    "ud2",
    ".cfi_endproc",
    ".size rl_cancel_here, . - rl_cancel_here",
    docancel = sym do_cancel_c,
);

pub fn restorer() -> usize {
    rl_sigreturn as *const () as usize
}

#[inline(always)]
fn word() -> &'static AtomicU32 {
    unsafe { &*(&raw const (*rusty_libc_core::tls::current()).cancelhandling as *const AtomicU32) }
}

pub fn ensure_init() {
    static DONE: AtomicU32 = AtomicU32::new(0);
    if DONE.load(Ordering::Acquire) == 2 {
        return;
    }
    if DONE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        let act = KSigaction { handler: sigcancel_handler as *const () as usize, flags: SA_SIGINFO | SA_RESTART | SA_RESTORER, restorer: rl_sigreturn as *const () as usize, mask: u64::MAX };
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
    unsafe {
        let r = rl_syscall_cancel_arch(word(), nr, a1, a2, a3, a4, a5, a6);
        if r == (-(EINTR as isize)) as usize {
            testcancel();
        }
        r
    }
}

extern "C" fn sigcancel_handler(sig: c_int, info: *const u8, uc: *mut u8) {
    if sig != SIGCANCEL {
        return;
    }
    unsafe {
        let si_code = *(info.add(8) as *const i32);
        let si_pid = *(info.add(16) as *const i32);
        if si_code != -6 || si_pid != getpid() {
            return;
        }
        let h = word().load(Ordering::Acquire);
        if h & CANCELED_BIT == 0 || h & (DISABLE_BIT | EXITING_BIT) != 0 {
            return;
        }
        let rip = *(uc.add(40 + 16 * 8) as *const usize);
        let start = &raw const rl_cancel_start as usize;
        let end = &raw const rl_cancel_end as usize;
        if h & ASYNC_BIT != 0 || (rip >= start && rip < end) {
            #[cfg(feature = "unwind")]
            if crate::unwind::available() {
                let rsp_slot = uc.add(40 + 15 * 8) as *mut usize;
                let rip_slot = uc.add(40 + 16 * 8) as *mut usize;
                let new_rsp = *rsp_slot - 8;
                *(new_rsp as *mut usize) = if rip == start { start + 1 } else { rip };
                *rsp_slot = new_rsp;
                *rip_slot = rl_cancel_here as *const () as usize;
                return;
            }
            let saved = *(uc.add(40 + 256) as *const u64);
            sigprocmask_set(2, saved);
            do_cancel();
        }
    }
}

pub fn do_cancel() -> ! {
    unsafe {
        let t = current_thread();
        word().fetch_or(EXITING_BIT | DISABLE_BIT, Ordering::AcqRel);
        word().fetch_and(!ASYNC_BIT, Ordering::AcqRel);
        (*t).exit_value = PTHREAD_CANCELED as *mut c_void;
        unwind_continue()
    }
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
    unsafe {
        let t = current_thread();
        #[cfg(feature = "unwind")]
        crate::unwind::forced_unwind();
        {
            let top = (*t).unwind;
            let stop = if top.is_null() { core::ptr::null_mut() } else { (*top).cleanup };
            while !cleanup::head().is_null() && cleanup::head() != stop {
                let b = cleanup::head();
                cleanup::set_head((*b).prev);
                ((*b).routine)((*b).arg);
            }
            if top.is_null() {
                crate::thread::thread_exit((*t).exit_value)
            }
            (*t).unwind = (*top).prev;
            rl_unwind_longjmp(top, 1);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel(buf: *mut c_void) {
    unsafe {
        let b = buf as *mut UnwindBuf;
        let t = current_thread();
        (*b).prev = (*t).unwind;
        (*b).cleanup = cleanup::head();
        (*t).unwind = b;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel(buf: *mut c_void) {
    unsafe {
        let b = buf as *mut UnwindBuf;
        (*current_thread()).unwind = (*b).prev;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel_defer(buf: *mut c_void) {
    unsafe {
        let mut old = 0;
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &mut old);
        __pthread_register_cancel(buf);
        (*(buf as *mut UnwindBuf)).canceltype = old;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel_restore(buf: *mut c_void) {
    unsafe {
        let b = buf as *mut UnwindBuf;
        (*current_thread()).unwind = (*b).prev;
        pthread_setcanceltype((*b).canceltype, core::ptr::null_mut());
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unwind_next(buf: *mut c_void) -> ! {
    unsafe {
        (*current_thread()).unwind = (*(buf as *mut UnwindBuf)).prev;
        unwind_continue()
    }
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
    unsafe {
        let frame = frame as *mut CleanupFrame;
        if (*frame).do_it != 0 {
            if let Some(f) = (*frame).cancel_routine {
                f((*frame).cancel_arg);
            }
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int {
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
    if !oldstate.is_null() {
        unsafe { *oldstate = if old & DISABLE_BIT != 0 { PTHREAD_CANCEL_DISABLE } else { PTHREAD_CANCEL_ENABLE } };
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
pub unsafe extern "C" fn pthread_setcanceltype(ctype: c_int, oldtype: *mut c_int) -> c_int {
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
    if !oldtype.is_null() {
        unsafe { *oldtype = if old & ASYNC_BIT != 0 { PTHREAD_CANCEL_ASYNCHRONOUS } else { PTHREAD_CANCEL_DEFERRED } };
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
pub unsafe extern "C" fn pthread_cancel(th: PthreadT) -> c_int {
    ensure_init();
    unsafe {
        let t = th as *mut Thread;
        if (*t).tcb.tid < 0 {
            return ESRCH;
        }
        let w = &*(&raw const (*t).tcb.cancelhandling as *const AtomicU32);
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
        let tid = (*t).tcb.tid;
        if tid > 0 {
            tgkill(getpid(), tid, SIGCANCEL);
        }
        0
    }
}

pub use rusty_libc_core::cleanup::CleanupBuf;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    unsafe {
        cleanup::push(buf, routine, arg);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop(buf: *mut CleanupBuf, execute: c_int) {
    unsafe {
        cleanup::pop(buf);
        if execute != 0 {
            ((*buf).routine)((*buf).arg);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push_defer(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    unsafe {
        let mut old = 0;
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &mut old);
        _pthread_cleanup_push(buf, routine, arg);
        (*buf).canceltype = old;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop_restore(buf: *mut CleanupBuf, execute: c_int) {
    unsafe {
        cleanup::pop(buf);
        if execute != 0 {
            ((*buf).routine)((*buf).arg);
        }
        pthread_setcanceltype((*buf).canceltype, core::ptr::null_mut());
    }
}

pub unsafe fn with_cleanup<R>(routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void, body: impl FnOnce() -> R) -> R {
    unsafe { cleanup::with(routine, arg, body) }
}
