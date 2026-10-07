use crate::consts::{SS_ONSTACK, SIG_BLOCK, SIG_SETMASK};
use crate::stack::sigaltstack;
use crate::types::{JmpBufTag, StackT};
use crate::wait::sigprocmask;
use core::arch::naked_asm;
use core::ffi::c_int;

extern "C" fn sigjmp_save(env: *mut JmpBufTag, savemask: c_int) -> c_int {
    unsafe {
        (*env).mask_was_saved = (savemask != 0 && sigprocmask(SIG_BLOCK, core::ptr::null(), &mut (*env).saved_mask) == 0) as c_int;
    }
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
unsafe fn longjmp_impl(env: *mut JmpBufTag, val: c_int) -> ! {
    unsafe {
        if (*env).mask_was_saved != 0 {
            sigprocmask(SIG_SETMASK, &(*env).saved_mask, core::ptr::null_mut());
        }
        restore_regs((*env).jmpbuf.as_ptr(), if val == 0 { 1 } else { val })
    }
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

unsafe fn saved_sp(env: *const JmpBufTag) -> usize {
    unsafe {
        let guard = (*rusty_libc_core::tls::current()).pointer_guard;
        ((*env).jmpbuf[6] as usize).rotate_right(0x11) ^ guard
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __longjmp_chk(env: *mut JmpBufTag, val: c_int) -> ! {
    unsafe {
        if (*env).mask_was_saved != 0 {
            sigprocmask(SIG_SETMASK, &(*env).saved_mask, core::ptr::null_mut());
        }
        let target = saved_sp(env);
        let here: usize;
        core::arch::asm!("mov {}, rsp", out(reg) here, options(nomem, nostack, preserves_flags));
        if here > target {
            let mut ss = StackT::ZERO;
            let ok = if sigaltstack(core::ptr::null(), &mut ss) != 0 {
                true
            } else if ss.ss_flags & SS_ONSTACK == 0 {
                false
            } else {
                (ss.ss_sp as usize).wrapping_add(ss.ss_size).wrapping_sub(target) >= ss.ss_size
            };
            if !ok {
                let msg = b"*** longjmp causes uninitialized stack frame ***: terminated\n";
                rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, 2, msg.as_ptr() as usize, msg.len());
                rusty_libc_core::process::abort();
            }
        }
        restore_regs((*env).jmpbuf.as_ptr(), if val == 0 { 1 } else { val })
    }
}
