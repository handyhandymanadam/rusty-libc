//! Thread cancellation: pthread_cancel, cancel state and type, testcancel, cleanup handlers, and the
//! cancellable system call stub.
//!
//! Design (the same race-free scheme glibc 2.34+ uses, written for this library):
//! * `Tcb.cancelhandling` holds four bits: DISABLE, ASYNC, CANCELED (a request is pending), EXITING.
//! * `pthread_cancel` sets CANCELED and, when the target has cancellation enabled, sends it the
//!   internal signal SIGCANCEL (32) with tgkill.
//! * Blocking system calls go through `rl_syscall_cancel_arch`: it tests the pending bit right
//!   before the `syscall` instruction. The signal handler cancels the thread when the interrupted
//!   instruction pointer is inside that stub before the syscall completed, so no cancel request is
//!   lost between the test and the call. A call that was interrupted by the signal returns EINTR
//!   and the wrapper then acts on the pending request.
//! * Acting on a request: with an unwinder (`_Unwind_ForcedUnwind`, see `unwind.rs`) the thread's frames are unwound as
//!   glibc does it: landing pads run (C++ destructors, `-fexceptions` cleanup attributes, Rust `Drop`), the handlers of
//!   `pthread_cleanup_push` run as their frames are left, and the thread ends with the exit value PTHREAD_CANCELED at the
//!   end of the stack. Without an unwinder (a static program that uses no exceptions, the Rust runtime test programs) the
//!   cleanup handlers run in one go (a linked list, newest first), then the TSD destructors, and the thread ends:
//!   destructors of C++ or Rust objects on its stack do not run. The same holds for `pthread_exit`.
//! * What a Rust thread can rely on without an unwinder: handlers registered with `pthread_cleanup_push` (or
//!   `rusty_libc_core::cleanup`) run, in reverse order, at a cancellation point or in `pthread_exit`; `Drop` of values on its stack
//!   does not run. The library's own critical sections that contain a cancellation point (stdio stream locks, the
//!   `system` signal state, the resolver's static-buffer locks, a condition wait's mutex) register such handlers (rusty-libc-core
//!   `cleanup`), as glibc's do through its unwinder. Programs built with glibc's own non-exception cleanup macros
//!   (`__pthread_register_cancel`) work either way, see `UnwindBuf`.
//! * The SIGCANCEL handler acts inside the handler (asynchronous type, or interrupted inside the cancellable syscall stub
//!   before its syscall completed), as glibc's, so no `rt_sigreturn` is made on the way to the thread's end: it copies the
//!   interrupted registers to a 176-byte frame at the top of the signal frame, moves the stack pointer there and starts the
//!   forced unwind from code whose unwind information reads that frame as a signal frame (`rl_cancel_switch`), so the
//!   kernel's signal frame (about 3 KB) is not under the unwind. The restorers (`rl_sigreturn`) keep glibc's signal-frame
//!   unwind information for other handlers.
//!
//! Unsafe left (U3): the cancellable system call stub, the signal restorer and the buffer jump (assembly); the signal
//! handler's siginfo/ucontext reads; the cleanup records and glibc-style buffers, which live on the thread's stack and are
//! reached through raw pointers; the calls of the program's handlers.
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
/// The exit value of a cancelled thread: `(void *) -1`.
pub const PTHREAD_CANCELED: usize = usize::MAX;

/// The signal that carries a cancellation request (glibc's SIGCANCEL).
pub const SIGCANCEL: c_int = 32;
/// glibc's SIGSETXID; reserved here too so that signal numbers 32 and 33 stay out of user masks.
pub const SIGSETXID: c_int = 33;
/// Bits of the signals the thread layer keeps for itself.
pub const INTERNAL_SIGNALS: u64 = (1 << (SIGCANCEL - 1)) | (1 << (SIGSETXID - 1));

const SA_SIGINFO: u64 = 4;
const SA_RESTART: u64 = 0x1000_0000;

unsafe extern "C" {
    fn rl_syscall_cancel_arch(cancelp: *const AtomicU32, nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize;
    static rl_cancel_start: u8;
    static rl_cancel_end: u8;
    fn rl_sigreturn();
    fn rl_cancel_switch(uc: *mut u8) -> !;
}

// The cancellable syscall: arguments as the C ABI gives them (rdi = word, rsi = number, rdx, rcx,
// r8, r9 = a1..a4, stack = a5, a6). `rl_cancel_start`..`rl_cancel_end` is the range in which the
// handler may cancel (up to and including the syscall instruction).
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
    // rl_cancel_switch(ucontext): the SIGCANCEL handler acts (see there). The interrupted registers (gregs, at 40..176 of
    // the ucontext) are copied to the same offsets of a frame F = (interrupted rsp - 128 - 176) & -16: below the red zone,
    // inside the signal frame's vector save area (which lies right below the red zone and is at least 512 bytes; the
    // ucontext itself lies below it), then rsp = F and on to the call of do_cancel below.
    ".balign 16",
    ".globl rl_cancel_switch",
    ".hidden rl_cancel_switch",
    ".type rl_cancel_switch,@function",
    "rl_cancel_switch:",
    "mov rax, [rdi + 0xa0]",
    "sub rax, 304",
    "and rax, -16",
    "lea rsi, [rdi + 0x28]",
    "lea rdi, [rax + 0x28]",
    "mov ecx, 17",
    "rep movsq",
    "mov rsp, rax",
    "jmp 3f",
    ".size rl_cancel_switch, . - rl_cancel_switch",
    // its continuation, with signal-frame unwind information for the frame at rsp (the rules of
    // rusty_libc_core::restorer_asm): the forced unwind of `do_cancel` walks through it into the interrupted code
    ".cfi_startproc simple",
    ".cfi_signal_frame",
    ".cfi_escape 0x0f, 0x04, 0x77, 0xa0, 0x01, 0x06",
    ".cfi_escape 0x10, 0x08, 0x02, 0x77, 0x28",
    ".cfi_escape 0x10, 0x09, 0x02, 0x77, 0x30",
    ".cfi_escape 0x10, 0x0a, 0x02, 0x77, 0x38",
    ".cfi_escape 0x10, 0x0b, 0x03, 0x77, 0xc0, 0x00",
    ".cfi_escape 0x10, 0x0c, 0x03, 0x77, 0xc8, 0x00",
    ".cfi_escape 0x10, 0x0d, 0x03, 0x77, 0xd0, 0x00",
    ".cfi_escape 0x10, 0x0e, 0x03, 0x77, 0xd8, 0x00",
    ".cfi_escape 0x10, 0x0f, 0x03, 0x77, 0xe0, 0x00",
    ".cfi_escape 0x10, 0x05, 0x03, 0x77, 0xe8, 0x00",
    ".cfi_escape 0x10, 0x04, 0x03, 0x77, 0xf0, 0x00",
    ".cfi_escape 0x10, 0x06, 0x03, 0x77, 0xf8, 0x00",
    ".cfi_escape 0x10, 0x03, 0x03, 0x77, 0x80, 0x01",
    ".cfi_escape 0x10, 0x01, 0x03, 0x77, 0x88, 0x01",
    ".cfi_escape 0x10, 0x00, 0x03, 0x77, 0x90, 0x01",
    ".cfi_escape 0x10, 0x02, 0x03, 0x77, 0x98, 0x01",
    ".cfi_escape 0x10, 0x07, 0x03, 0x77, 0xa0, 0x01",
    ".cfi_escape 0x10, 0x10, 0x03, 0x77, 0xa8, 0x01",
    "3:",
    "call {docancel}",
    "ud2",
    ".cfi_endproc",
    docancel = sym do_cancel_c,
);

// The restorer of the SIGCANCEL handler, with glibc's unwind information for the signal frame: a cancellation acting inside
// the handler unwinds through it into the interrupted code.
global_asm!(rusty_libc_core::restorer_asm!("rl_sigreturn"));

extern "C" fn do_cancel_c() -> ! {
    do_cancel()
}

/// Address of the `rt_sigreturn` stub, for programs that install their own signal handlers with
/// `rt_sigaction` (SA_RESTORER).
pub fn restorer() -> usize {
    rl_sigreturn as *const () as usize
}

/// The calling thread's `cancelhandling` word.
#[inline(always)]
fn word() -> &'static AtomicU32 {
    let p = rusty_libc_core::tls::current().cast::<u8>().wrapping_add(core::mem::offset_of!(rusty_libc_core::tls::Tcb, cancelhandling));
    // SAFETY: the calling thread's TCB lives as long as the thread; the word is an aligned u32 that other threads change
    // (pthread_cancel), so it is used only atomically.
    unsafe { &*p.cast::<AtomicU32>() }
}

/// Thread `t`'s `cancelhandling` word.
///
/// # Safety
/// `t` is a thread descriptor of this process that stays mapped for `'a`.
#[inline(always)]
pub(crate) unsafe fn word_of<'a>(t: *mut Thread) -> &'a AtomicU32 {
    // SAFETY: forwarded contract; the word is used only atomically.
    unsafe { shared_field(field_of!(t, tcb.cancelhandling: AtomicU32)) }
}

/// Install the cancel signal handler and the cancellable-syscall hook (once).
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
    // SAFETY: core's cancellable system calls pass arguments valid for `nr` (CANCEL_SYSCALL's contract).
    unsafe { syscall_cp(nr, a1, a2, a3, a4, a5, a6) }
}

/// A system call that is a cancellation point. Returns the raw kernel result (-errno on error).
///
/// # Safety
/// Arguments must be valid for system call `nr`.
pub unsafe fn syscall_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    // SAFETY: the stub tests the word and makes system call `nr` with the caller's arguments (forwarded contract).
    let r = unsafe { rl_syscall_cancel_arch(word(), nr, a1, a2, a3, a4, a5, a6) };
    if r == (-(EINTR as isize)) as usize {
        testcancel();
    }
    r
}

/// The start of the kernel's `siginfo_t` (what the handler reads of it).
#[repr(C)]
struct SigInfoHead {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad: i32,
    si_pid: i32,
}

/// The start of the kernel's x86-64 `ucontext_t` up to `uc_sigmask` (glibc's layout: `uc_mcontext.gregs` at 40, the mask at
/// 296).
#[repr(C)]
struct UcHead {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: [u64; 3],
    gregs: [u64; 23],
    fpregs: u64,
    reserved: [u64; 8],
    uc_sigmask: u64,
}
const _: () = assert!(core::mem::offset_of!(UcHead, gregs) == 40 && core::mem::offset_of!(UcHead, uc_sigmask) == 296);
const REG_RIP: usize = 16;

extern "C" fn sigcancel_handler(sig: c_int, info: *const u8, uc: *mut u8) {
    if sig != SIGCANCEL {
        return;
    }
    // SAFETY: SA_SIGINFO: the kernel passes a valid siginfo_t (si_code at offset 8, si_pid at 16), read-only here.
    let info = unsafe { &*(info as *const SigInfoHead) };
    // only accept the signal when it was sent by pthread_cancel (tgkill from this process)
    if info.si_code != -6 || info.si_pid != getpid() {
        return;
    }
    let h = word().load(Ordering::Acquire);
    if h & CANCELED_BIT == 0 || h & (DISABLE_BIT | EXITING_BIT) != 0 {
        return;
    }
    // SAFETY: the kernel passes a valid, 8-aligned ucontext_t on this thread's stack; `UcHead` is its leading part, only
    // read here.
    let rip = unsafe { &*(uc as *const UcHead) }.gregs[REG_RIP] as usize;
    let start = &raw const rl_cancel_start as usize;
    let end = &raw const rl_cancel_end as usize;
    if h & ASYNC_BIT != 0 || (rip >= start && rip < end) {
        // act inside the handler, as glibc does (no rt_sigreturn; the handler's mask, SIGCANCEL blocked, stays in force while
        // the cleanup handlers run), but not on top of the kernel's signal frame (about 3 KB with AVX-512 state), which
        // would stay under the whole forced unwind, the deepest stack use of a cancelled thread (FIXLIST #79):
        // `rl_cancel_switch` copies the interrupted registers to a 176-byte frame at the top of the signal frame (in its
        // vector save area, which nothing reads without an rt_sigreturn), moves the stack pointer there and calls
        // `do_cancel` from code whose unwind information reads that frame as `rl_sigreturn`'s reads the signal frame: the
        // unwind walks from it into the interrupted code.
        // SAFETY: `uc` is the kernel's ucontext_t of this delivery, below the interrupted stack pointer's red zone, and
        // this handler never returns (neither does the thread: `do_cancel` ends it).
        unsafe { rl_cancel_switch(uc) };
    }
}

/// Act on a cancellation request now: run the cleanup handlers, end the thread.
pub fn do_cancel() -> ! {
    let t = current_thread();
    // the cleanup handlers run with cancellation disabled and the type deferred (what pthread_setcancelstate and
    // pthread_setcanceltype report to a handler, glibc's tst-cleanup5)
    word().fetch_or(EXITING_BIT | DISABLE_BIT, Ordering::AcqRel);
    word().fetch_and(!ASYNC_BIT, Ordering::AcqRel);
    // SAFETY: the calling thread's own descriptor.
    unsafe { crate::setxid::set_exiting(t) };
    // SAFETY: as above; only this thread writes its exit value.
    unsafe { *field_of!(t, exit_value: *mut c_void) = PTHREAD_CANCELED as *mut c_void };
    // SAFETY: called by the thread that is ending, with its exit value set.
    unsafe { unwind_continue() }
}

/// glibc's `__pthread_unwind_buf_t` (104 bytes): what code built against glibc's non-exception cleanup
/// macros keeps on its stack. `jmp` and `mask_was_saved` are the `__sigsetjmp_cancel` buffer; `prev`,
/// `cleanup` and `canceltype` are glibc's private data (`priv.data`).
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

/// Jump to a buffer filled by `__sigsetjmp` (unmangling the way `__sigsetjmp` mangled), returning `val`.
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

/// libgcc's `struct _Unwind_Exception` (32 bytes, aligned to 16): the object a forced unwind is thrown with (glibc keeps one
/// in each thread's descriptor, `exc`).
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

/// Carry on ending the thread (`exit_value` is set): run the handlers of `pthread_cleanup_push` newer
/// than the innermost glibc-style buffer, then jump into that buffer (its code runs its handler and calls
/// `__pthread_unwind_next`, which comes back here); with no buffer left, run the TSD destructors and end.
///
/// # Safety
/// Called by the thread that is ending, after its `exit_value` was set; the registered buffers are live on its stack.
pub(crate) unsafe fn unwind_continue() -> ! {
    let t = current_thread();
    // with an unwinder the frames are unwound (it ends the thread itself, or comes back if it cannot unwind)
    #[cfg(feature = "unwind")]
    // SAFETY: forwarded contract.
    unsafe {
        crate::unwind::forced_unwind()
    };
    let unwind = field_of!(t, unwind: *mut UnwindBuf);
    // SAFETY: the calling thread's own descriptor; only this thread changes its buffer list.
    let top = unsafe { *unwind };
    // SAFETY: a non-NULL `top` is a registered buffer, live on this thread's stack (the frame that registered it has not
    // returned: it unregisters on its way out).
    let stop = if top.is_null() { core::ptr::null_mut() } else { unsafe { (*top).cleanup } };
    while !cleanup::head().is_null() && cleanup::head() != stop {
        // SAFETY: a registered handler record, live on this thread's stack.
        unsafe { run_cleanup(cleanup::head()) };
    }
    if top.is_null() {
        // SAFETY: as above (own descriptor).
        crate::thread::thread_exit(unsafe { *field_of!(t, exit_value: *mut c_void) })
    }
    // SAFETY: `top` is live (see above).
    let prev = unsafe { (*top).prev };
    // SAFETY: own descriptor.
    unsafe { *unwind = prev };
    // SAFETY: `top` was filled by __sigsetjmp_cancel in a frame that is still live: jumping there resumes it.
    unsafe { rl_unwind_longjmp(top, 1) }
}

/// Pop the innermost cleanup record `b` and run its handler.
///
/// # Safety
/// `b` is the head of the calling thread's cleanup list (live on its stack), and its routine may be called with its argument.
pub(crate) unsafe fn run_cleanup(b: *mut CleanupBuf) {
    // SAFETY: forwarded contract.
    let b = unsafe { &*b };
    cleanup::set_head(b.prev);
    // SAFETY: the program's handler, called with its argument (forwarded contract).
    unsafe { (b.routine)(b.arg) };
}

/// `__pthread_register_cancel (buf)`: push a cancellation buffer (after `__sigsetjmp_cancel` filled its
/// jump buffer).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel(buf: *mut c_void) {
    // SAFETY: `buf` is the caller's __pthread_unwind_buf_t, live until it unregisters it (C contract).
    let b = unsafe { arg_mut(buf as *mut UnwindBuf) };
    let unwind = field_of!(current_thread(), unwind: *mut UnwindBuf);
    // SAFETY: the calling thread's own descriptor; only this thread changes its buffer list.
    b.prev = unsafe { *unwind };
    b.cleanup = cleanup::head();
    // SAFETY: as above.
    unsafe { *unwind = b };
}

/// Pop the calling thread's cancellation buffer `buf`: the list goes back to the one before it.
///
/// # Safety
/// `buf` is the calling thread's innermost registered buffer.
unsafe fn unregister(buf: *mut c_void) -> &'static mut UnwindBuf {
    // SAFETY: forwarded contract (a live buffer of the caller).
    let b = unsafe { arg_mut(buf as *mut UnwindBuf) };
    // SAFETY: the calling thread's own descriptor.
    unsafe { *field_of!(current_thread(), unwind: *mut UnwindBuf) = b.prev };
    b
}

/// `__pthread_unregister_cancel (buf)`: pop it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel(buf: *mut c_void) {
    // SAFETY: `buf` is the caller's innermost buffer (C contract).
    unsafe { unregister(buf) };
}

/// `__pthread_register_cancel_defer (buf)`: as `__pthread_register_cancel`, and switch to deferred
/// cancellation, remembering the old type in the buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel_defer(buf: *mut c_void) {
    let mut old = 0;
    setcanceltype(PTHREAD_CANCEL_DEFERRED, Some(&mut old));
    // SAFETY: forwarded C contract.
    unsafe { __pthread_register_cancel(buf) };
    // SAFETY: `buf` is the caller's live buffer (C contract).
    unsafe { arg_mut(buf as *mut UnwindBuf) }.canceltype = old;
}

/// `__pthread_unregister_cancel_restore (buf)`: pop it and restore the cancellation type saved by
/// `__pthread_register_cancel_defer`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel_restore(buf: *mut c_void) {
    // SAFETY: `buf` is the caller's innermost buffer (C contract).
    let b = unsafe { unregister(buf) };
    setcanceltype(b.canceltype, None);
}

/// `__pthread_unwind_next (buf)`: the cleanup code of a buffer has run; go on with the next one (or end
/// the thread).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unwind_next(buf: *mut c_void) -> ! {
    // SAFETY: `buf` is the innermost buffer, whose cleanup code just ran (C contract of glibc's macros).
    unsafe { unregister(buf) };
    // SAFETY: the thread is ending (its exit value was set before the jump into the buffer).
    unsafe { unwind_continue() }
}

/// glibc's `struct __pthread_cleanup_frame` (what its `__cleanup__` attribute macros keep on the stack).
#[repr(C)]
pub struct CleanupFrame {
    pub cancel_routine: Option<unsafe extern "C" fn(*mut c_void)>,
    pub cancel_arg: *mut c_void,
    pub do_it: c_int,
    pub cancel_type: c_int,
}

/// `__pthread_cleanup_routine (frame)`: the `__cleanup__` handler of glibc's macros for the exception
/// case (run when the scope ends or is unwound): call the routine when `do_it` is set. (It is called on
/// cancellation when the thread's stack is unwound, see `unwind.rs`; without an unwinder the cancellation
/// does not unwind and the routine is not called for code built that way.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_cleanup_routine(frame: *mut c_void) {
    // SAFETY: `frame` is the caller's struct __pthread_cleanup_frame (C contract).
    let frame = unsafe { arg(frame as *const CleanupFrame) };
    if frame.do_it != 0 {
        if let Some(f) = frame.cancel_routine {
            // SAFETY: the program's routine with its argument.
            unsafe { f(frame.cancel_arg) };
        }
    }
}

/// If a cancellation request is pending and cancellation is enabled, act on it.
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

/// `pthread_setcancelstate`: EINVAL for a bad state; the old state goes to `oldstate` before a pending request is acted
/// on (enabling with asynchronous type and a request pending acts at once).
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
    // enabling with asynchronous type and a request pending: act at once
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
    // SAFETY: `oldstate` is NULL or a writable int (C contract).
    setcancelstate(state, unsafe { oldstate.as_mut() })
}

/// `pthread_setcanceltype`: EINVAL for a bad type; the old type goes to `oldtype` before a pending request is acted on
/// (switching to asynchronous with a request pending acts at once).
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
    // SAFETY: `oldtype` is NULL or a writable int (C contract).
    setcanceltype(ctype, unsafe { oldtype.as_mut() })
}

/// `pthread_cancel` on thread `t`.
#[inline]
///
/// # Safety
/// `t` is a thread handle of this process that was not reaped.
pub unsafe fn cancel(t: *mut Thread) -> c_int {
    ensure_init();
    // SAFETY: forwarded contract.
    let tid = unsafe { tid_word(t) };
    if tid.load(Ordering::Relaxed) < 0 {
        return ESRCH;
    }
    // the shared library finds (or loads) the unwinder here, in the cancelling thread, as glibc's pthread_cancel does
    // (`__libc_unwind_link_get`): the cancelled thread, which may have a small stack, does not run dlopen of libgcc_s.so.1
    // when it acts on the request (FIXLIST #79)
    #[cfg(feature = "unwind-dl")]
    let _ = crate::unwind::resolve();
    // SAFETY: forwarded contract.
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
        // acts when the target enables cancellation and reaches a cancellation point
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
    // SAFETY: `th` is a live thread handle (C contract).
    unsafe { cancel(th as *mut Thread) }
}

pub use rusty_libc_core::cleanup::CleanupBuf;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    // SAFETY: `buf` is the caller's record, live until it pops it (C contract).
    unsafe { cleanup::push(buf, routine, arg) };
}

/// Pop `buf` and run its handler if `execute`.
///
/// # Safety
/// `buf` is the calling thread's innermost cleanup record.
unsafe fn pop_and_run(buf: *mut CleanupBuf, execute: c_int) -> &'static CleanupBuf {
    // SAFETY: forwarded contract.
    unsafe { cleanup::pop(buf) };
    // SAFETY: the record stays live in the caller's frame.
    let b = unsafe { arg(buf) };
    if execute != 0 {
        // SAFETY: the program's handler with its argument.
        unsafe { (b.routine)(b.arg) };
    }
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop(buf: *mut CleanupBuf, execute: c_int) {
    // SAFETY: `buf` is the caller's innermost record (C contract).
    unsafe { pop_and_run(buf, execute) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_push_defer(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    let mut old = 0;
    setcanceltype(PTHREAD_CANCEL_DEFERRED, Some(&mut old));
    // SAFETY: forwarded C contract.
    unsafe { _pthread_cleanup_push(buf, routine, arg) };
    // SAFETY: the record just pushed, live in the caller's frame.
    unsafe { (*buf).canceltype = old };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _pthread_cleanup_pop_restore(buf: *mut CleanupBuf, execute: c_int) {
    // SAFETY: `buf` is the caller's innermost record (C contract).
    let b = unsafe { pop_and_run(buf, execute) };
    setcanceltype(b.canceltype, None);
}

/// Run `body` with a cleanup handler registered (Rust-side convenience used inside this crate).
///
/// # Safety
/// As `rusty_libc_core::cleanup::with`: `routine(arg)` may be called if the thread ends inside `body`.
pub unsafe fn with_cleanup<R>(routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void, body: impl FnOnce() -> R) -> R {
    // SAFETY: forwarded contract.
    unsafe { cleanup::with(routine, arg, body) }
}
