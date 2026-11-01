//! setjmp.h: setjmp, _setjmp, __sigsetjmp, longjmp, _longjmp, siglongjmp, __longjmp_chk.
//!
//! The buffer is glibc's `struct __jmp_buf_tag` (200 bytes, see `types::JmpBufTag`): rbx, rbp,
//! r12-r15, rsp and the return address, then the "mask was saved" flag and the saved signal mask.
//! rbp, rsp and the return address are mangled the way glibc does (`PTR_MANGLE`: xor with the
//! pointer guard at `%fs:0x30`, then rotate left by 17), so a buffer is valid inside one process
//! only, which is all `longjmp` needs.
//!
//! `setjmp`-family functions return twice. Rust has no way to say that, so Rust code that calls
//! them must (1) call them through a small `#[inline(never)]` function, (2) keep every value that
//! must survive the second return in memory (atomics, `read_volatile`), and (3) not assume
//! anything about its locals after the second return. C compilers know the names and handle this
//! themselves. The assembly saves and restores exactly what the C ABI keeps across a call.
//!
//! Not done: glibc's `_longjmp_unwind` (pthread cleanup handlers run when `longjmp` leaves their
//! scope: rusty-libc-pthread has no cleanup stack yet) and the CET shadow stack handling (the shadow
//! stack is not enabled for programs started by our `_start`).
//!
//! Unsafe here (BRIEF-UNSAFE U2/U3): the naked assembly of the setjmp family and of the register restore, kept as it is;
//! the conversion of the `jmp_buf` pointer the C caller passes; the read of the pointer guard from the TCB; the stack
//! pointer read of `__longjmp_chk`. A `longjmp` over Rust frames skips their destructors, which the Rust Reference (p.632,
//! "Behavior considered undefined": a frame deallocated without running its locals' destructors) counts as undefined
//! behaviour: Rust callers must only jump over frames that own nothing with a destructor (see the note above).
use crate::consts::{SS_ONSTACK, SIG_BLOCK, SIG_SETMASK};
use crate::stack::sigaltstack_rs;
use crate::types::JmpBufTag;
use crate::wait::sigmask_c;
use core::arch::naked_asm;
use core::ffi::c_int;

/// What every `setjmp` ends with: save the mask if asked to. Returns 0 (the first return).
extern "C" fn sigjmp_save(env: *mut JmpBufTag, savemask: c_int) -> c_int {
    // SAFETY: `env` is the caller's 200-byte `jmp_buf`, valid and unshared for the call (the contract of `__sigsetjmp`, which
    // jumps here with its arguments unchanged).
    let env = unsafe { &mut *env };
    env.mask_was_saved = (savemask != 0 && sigmask_c(SIG_BLOCK, None, Some(&mut env.saved_mask)) == 0) as c_int;
    0
}

/// `__sigsetjmp (env, savemask)`: save the registers, and the signal mask if `savemask` is nonzero
/// (what `sigsetjmp` expands to). Returns 0, and again with the value given to `longjmp`.
///
/// # Safety
/// `env` must point at a buffer of 200 bytes; see the module note about returning twice.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __sigsetjmp(_env: *mut JmpBufTag, _savemask: c_int) -> c_int {
    naked_asm!(
        "mov [rdi], rbx",
        "mov rax, rbp",
        "xor rax, qword ptr fs:[0x30]",
        "rol rax, 0x11",
        "mov [rdi + 8], rax",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        // the stack pointer as it will be after we return
        "lea rdx, [rsp + 8]",
        "xor rdx, qword ptr fs:[0x30]",
        "rol rdx, 0x11",
        "mov [rdi + 48], rdx",
        // the address we return to
        "mov rax, [rsp]",
        "xor rax, qword ptr fs:[0x30]",
        "rol rax, 0x11",
        "mov [rdi + 56], rax",
        "jmp {save}",
        save = sym sigjmp_save,
    )
}

/// `_setjmp (env)`: `__sigsetjmp (env, 0)`, the signal mask is not saved.
///
/// # Safety
/// As `__sigsetjmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn _setjmp(_env: *mut JmpBufTag) -> c_int {
    naked_asm!("xor esi, esi", "jmp {s}", s = sym __sigsetjmp)
}

/// `setjmp (env)` as a function: `__sigsetjmp (env, 1)`. (The `setjmp` macro of <setjmp.h> calls
/// `_setjmp`, so the signal mask is saved only by this function and by `sigsetjmp (env, 1)`.)
///
/// # Safety
/// As `__sigsetjmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(_env: *mut JmpBufTag) -> c_int {
    naked_asm!("mov esi, 1", "jmp {s}", s = sym __sigsetjmp)
}

/// Restore the saved registers from the `jmpbuf` array and continue at the saved return address
/// with `val` as the return value.
#[unsafe(naked)]
unsafe extern "C" fn restore_regs(_jmpbuf: *const i64, _val: c_int) -> ! {
    naked_asm!(
        "mov r8, [rdi + 48]",
        "mov r9, [rdi + 8]",
        "mov rdx, [rdi + 56]",
        "ror r8, 0x11",
        "xor r8, qword ptr fs:[0x30]",
        "ror r9, 0x11",
        "xor r9, qword ptr fs:[0x30]",
        "ror rdx, 0x11",
        "xor rdx, qword ptr fs:[0x30]",
        "mov rbx, [rdi]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        "mov eax, esi",
        "mov rsp, r8",
        "mov rbp, r9",
        "jmp rdx",
    )
}

/// Restore the signal mask if the buffer saved it (errno set if that fails, as the C `sigprocmask` call glibc makes).
#[inline(always)]
fn restore_mask(env: &JmpBufTag) {
    if env.mask_was_saved != 0 {
        sigmask_c(SIG_SETMASK, Some(&env.saved_mask), None);
    }
}

/// # Safety
/// As `longjmp`.
#[inline(always)]
unsafe fn longjmp_impl(env: *mut JmpBufTag, val: c_int) -> ! {
    // SAFETY: `env` was filled by a `setjmp` and is valid for reads (the caller's contract).
    let env = unsafe { &*env };
    restore_mask(env);
    // SAFETY: the registers come from a `setjmp` whose caller has not returned (the caller's contract), so the saved stack
    // and return address are live.
    unsafe { restore_regs(env.jmpbuf.as_ptr(), if val == 0 { 1 } else { val }) }
}

/// `longjmp (env, val)`: go back to the `setjmp` that filled `env`, which returns `val` (1 if 0);
/// restores the signal mask if the buffer saved it.
///
/// # Safety
/// `env` must have been filled by a `setjmp` whose caller has not returned.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn longjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    // SAFETY: forwarded contract.
    unsafe { longjmp_impl(env, val) }
}

/// `_longjmp`: the same as `longjmp`.
///
/// # Safety
/// As `longjmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _longjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    // SAFETY: forwarded contract.
    unsafe { longjmp_impl(env, val) }
}

/// `siglongjmp`: the same as `longjmp`.
///
/// # Safety
/// As `longjmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn siglongjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    // SAFETY: forwarded contract.
    unsafe { longjmp_impl(env, val) }
}

/// The pointer guard (`%fs:0x30`, the TCB's `pointer_guard`), which `PTR_MANGLE` mixes into the saved pointers.
#[inline(always)]
fn pointer_guard() -> usize {
    // SAFETY: `current()` is the calling thread's TCB, valid for the thread's life; the guard is written once at start-up
    // (or thread creation) before any `setjmp` can run.
    unsafe { (*rusty_libc_core::tls::current()).pointer_guard }
}

/// The saved stack pointer of a buffer, un-mangled.
fn saved_sp(env: &JmpBufTag) -> usize {
    (env.jmpbuf[6] as usize).rotate_right(0x11) ^ pointer_guard()
}

/// May `__longjmp_chk` jump to a frame whose stack pointer is `target`? Yes when the target is above the current stack
/// pointer `here`, or when we run on the alternate signal stack and the target is outside it, or when the alternate stack
/// cannot be read (no check then, as glibc; errno is set as by the `sigaltstack` call).
fn longjmp_target_ok(here: usize, target: usize) -> bool {
    if here <= target {
        return true;
    }
    match sigaltstack_rs(None) {
        Err(e) => {
            rusty_libc_core::errno::set(e.0);
            true
        }
        Ok(ss) if ss.ss_flags & SS_ONSTACK == 0 => false,
        Ok(ss) => (ss.ss_sp as usize).wrapping_add(ss.ss_size).wrapping_sub(target) >= ss.ss_size,
    }
}

/// `__longjmp_chk`: what `longjmp` becomes with _FORTIFY_SOURCE. Refuses (prints "*** longjmp
/// causes uninitialized stack frame ***: terminated" and aborts) a jump to a stack frame below the
/// current one, unless it leaves the alternate signal stack.
///
/// # Safety
/// As `longjmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __longjmp_chk(env: *mut JmpBufTag, val: c_int) -> ! {
    // SAFETY: as in `longjmp_impl`.
    let env = unsafe { &*env };
    restore_mask(env);
    let target = saved_sp(env);
    let here: usize;
    // SAFETY: reads the stack pointer into a register; no memory access.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) here, options(nomem, nostack, preserves_flags)) };
    if !longjmp_target_ok(here, target) {
        let _ = rusty_libc_core::unistd::write_nocancel(2, b"*** longjmp causes uninitialized stack frame ***: terminated\n");
        rusty_libc_core::process::abort();
    }
    // SAFETY: as in `longjmp_impl`.
    unsafe { restore_regs(env.jmpbuf.as_ptr(), if val == 0 { 1 } else { val }) }
}
