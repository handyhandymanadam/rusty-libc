use crate::consts::{SS_ONSTACK, SIG_BLOCK, SIG_SETMASK};
use crate::stack::sigaltstack_rs;
use crate::types::JmpBufTag;
use crate::wait::sigmask_c;
use core::arch::naked_asm;
use core::ffi::c_int;

extern "C" fn sigjmp_save(env: *mut JmpBufTag, savemask: c_int) -> c_int {
    let env = unsafe { &mut *env };
    env.mask_was_saved = (savemask != 0 && sigmask_c(SIG_BLOCK, None, Some(&mut env.saved_mask)) == 0) as c_int;
    0
}

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
        "lea rdx, [rsp + 8]",
        "xor rdx, qword ptr fs:[0x30]",
        "rol rdx, 0x11",
        "mov [rdi + 48], rdx",
        "mov rax, [rsp]",
        "xor rax, qword ptr fs:[0x30]",
        "rol rax, 0x11",
        "mov [rdi + 56], rax",
        "jmp {save}",
        save = sym sigjmp_save,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn _setjmp(_env: *mut JmpBufTag) -> c_int {
    naked_asm!("xor esi, esi", "jmp {s}", s = sym __sigsetjmp)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(_env: *mut JmpBufTag) -> c_int {
    naked_asm!("mov esi, 1", "jmp {s}", s = sym __sigsetjmp)
}

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

#[inline(always)]
fn restore_mask(env: &JmpBufTag) {
    if env.mask_was_saved != 0 {
        sigmask_c(SIG_SETMASK, Some(&env.saved_mask), None);
    }
}

#[inline(always)]
unsafe fn longjmp_impl(env: *mut JmpBufTag, val: c_int) -> ! {
    let env = unsafe { &*env };
    restore_mask(env);
    unsafe { restore_regs(env.jmpbuf.as_ptr(), if val == 0 { 1 } else { val }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn longjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    unsafe { longjmp_impl(env, val) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _longjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    unsafe { longjmp_impl(env, val) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn siglongjmp(env: *mut JmpBufTag, val: c_int) -> ! {
    unsafe { longjmp_impl(env, val) }
}

#[inline(always)]
fn pointer_guard() -> usize {
    unsafe { (*rusty_libc_core::tls::current()).pointer_guard }
}

fn saved_sp(env: &JmpBufTag) -> usize {
    (env.jmpbuf[6] as usize).rotate_right(0x11) ^ pointer_guard()
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __longjmp_chk(env: *mut JmpBufTag, val: c_int) -> ! {
    let env = unsafe { &*env };
    restore_mask(env);
    let target = saved_sp(env);
    let here: usize;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) here, options(nomem, nostack, preserves_flags)) };
    if !longjmp_target_ok(here, target) {
        let _ = rusty_libc_core::unistd::write_nocancel(2, b"*** longjmp causes uninitialized stack frame ***: terminated\n");
        rusty_libc_core::process::abort();
    }
    unsafe { restore_regs(env.jmpbuf.as_ptr(), if val == 0 { 1 } else { val }) }
}
