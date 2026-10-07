use crate::consts::{REG_R8, REG_R9, REG_R12, REG_R13, REG_R14, REG_R15, REG_RBP, REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RIP, REG_RSI, REG_RSP};
use crate::fail;
use crate::types::{FpState, MContext, UContext};
use core::arch::naked_asm;
use core::ffi::c_int;
use core::mem::offset_of;

const fn greg(i: usize) -> usize {
    offset_of!(UContext, uc_mcontext) + offset_of!(MContext, gregs) + i * 8
}
const O_FPREGS: usize = offset_of!(UContext, uc_mcontext) + offset_of!(MContext, fpregs);
const O_SIGMASK: usize = offset_of!(UContext, uc_sigmask);
const O_FPREGS_MEM: usize = offset_of!(UContext, fpregs_mem);
const O_MXCSR: usize = O_FPREGS_MEM + offset_of!(FpState, mxcsr);

extern "C" fn set_errno_fail(e: c_int) -> c_int {
    fail(e)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn getcontext(_ucp: *mut UContext) -> c_int {
    naked_asm!(
        "mov [rdi + {o_rbx}], rbx",
        "mov [rdi + {o_rbp}], rbp",
        "mov [rdi + {o_r12}], r12",
        "mov [rdi + {o_r13}], r13",
        "mov [rdi + {o_r14}], r14",
        "mov [rdi + {o_r15}], r15",
        "mov [rdi + {o_rdi}], rdi",
        "mov [rdi + {o_rsi}], rsi",
        "mov [rdi + {o_rdx}], rdx",
        "mov [rdi + {o_rcx}], rcx",
        "mov [rdi + {o_r8}], r8",
        "mov [rdi + {o_r9}], r9",
        "mov rcx, [rsp]",
        "mov [rdi + {o_rip}], rcx",
        "lea rcx, [rsp + 8]",
        "mov [rdi + {o_rsp}], rcx",
        "lea rcx, [rdi + {o_fpregs_mem}]",
        "mov [rdi + {o_fpregs}], rcx",
        "fnstenv [rcx]",
        "fldenv [rcx]",
        "stmxcsr [rdi + {o_mxcsr}]",
        "lea rdx, [rdi + {o_sigmask}]",
        "xor esi, esi",
        "xor edi, edi",
        "mov r10d, 8",
        "mov eax, 14",
        "syscall",
        "cmp rax, -4095",
        "jae 2f",
        "xor eax, eax",
        "ret",
        "2:",
        "neg eax",
        "mov edi, eax",
        "jmp {fail}",
        o_rbx = const greg(REG_RBX),
        o_rbp = const greg(REG_RBP),
        o_r12 = const greg(REG_R12),
        o_r13 = const greg(REG_R13),
        o_r14 = const greg(REG_R14),
        o_r15 = const greg(REG_R15),
        o_rdi = const greg(REG_RDI),
        o_rsi = const greg(REG_RSI),
        o_rdx = const greg(REG_RDX),
        o_rcx = const greg(REG_RCX),
        o_r8 = const greg(REG_R8),
        o_r9 = const greg(REG_R9),
        o_rip = const greg(REG_RIP),
        o_rsp = const greg(REG_RSP),
        o_fpregs_mem = const O_FPREGS_MEM,
        o_fpregs = const O_FPREGS,
        o_mxcsr = const O_MXCSR,
        o_sigmask = const O_SIGMASK,
        fail = sym set_errno_fail,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn setcontext(_ucp: *const UContext) -> c_int {
    naked_asm!(
        "push rdi",
        "lea rsi, [rdi + {o_sigmask}]",
        "xor edx, edx",
        "mov edi, 2",
        "mov r10d, 8",
        "mov eax, 14",
        "syscall",
        "pop rdx",
        "cmp rax, -4095",
        "jae 2f",
        "mov rcx, [rdx + {o_fpregs}]",
        "fldenv [rcx]",
        "ldmxcsr [rdx + {o_mxcsr}]",
        "mov rsp, [rdx + {o_rsp}]",
        "mov rbx, [rdx + {o_rbx}]",
        "mov rbp, [rdx + {o_rbp}]",
        "mov r12, [rdx + {o_r12}]",
        "mov r13, [rdx + {o_r13}]",
        "mov r14, [rdx + {o_r14}]",
        "mov r15, [rdx + {o_r15}]",
        "mov rcx, [rdx + {o_rip}]",
        "push rcx",
        "mov rsi, [rdx + {o_rsi}]",
        "mov rdi, [rdx + {o_rdi}]",
        "mov rcx, [rdx + {o_rcx}]",
        "mov r8, [rdx + {o_r8}]",
        "mov r9, [rdx + {o_r9}]",
        "mov rdx, [rdx + {o_rdx}]",
        "xor eax, eax",
        "ret",
        "2:",
        "neg eax",
        "mov edi, eax",
        "jmp {fail}",
        o_rbx = const greg(REG_RBX),
        o_rbp = const greg(REG_RBP),
        o_r12 = const greg(REG_R12),
        o_r13 = const greg(REG_R13),
        o_r14 = const greg(REG_R14),
        o_r15 = const greg(REG_R15),
        o_rdi = const greg(REG_RDI),
        o_rsi = const greg(REG_RSI),
        o_rdx = const greg(REG_RDX),
        o_rcx = const greg(REG_RCX),
        o_r8 = const greg(REG_R8),
        o_r9 = const greg(REG_R9),
        o_rip = const greg(REG_RIP),
        o_rsp = const greg(REG_RSP),
        o_fpregs = const O_FPREGS,
        o_mxcsr = const O_MXCSR,
        o_sigmask = const O_SIGMASK,
        fail = sym set_errno_fail,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn swapcontext(_oucp: *mut UContext, _ucp: *const UContext) -> c_int {
    naked_asm!(
        "mov [rdi + {o_rbx}], rbx",
        "mov [rdi + {o_rbp}], rbp",
        "mov [rdi + {o_r12}], r12",
        "mov [rdi + {o_r13}], r13",
        "mov [rdi + {o_r14}], r14",
        "mov [rdi + {o_r15}], r15",
        "mov [rdi + {o_rdi}], rdi",
        "mov [rdi + {o_rsi}], rsi",
        "mov [rdi + {o_rdx}], rdx",
        "mov [rdi + {o_rcx}], rcx",
        "mov [rdi + {o_r8}], r8",
        "mov [rdi + {o_r9}], r9",
        "mov rcx, [rsp]",
        "mov [rdi + {o_rip}], rcx",
        "lea rcx, [rsp + 8]",
        "mov [rdi + {o_rsp}], rcx",
        "lea rcx, [rdi + {o_fpregs_mem}]",
        "mov [rdi + {o_fpregs}], rcx",
        "fnstenv [rcx]",
        "stmxcsr [rdi + {o_mxcsr}]",
        "mov r12, rsi",
        "mov r9, rdi",
        "lea rdx, [rdi + {o_sigmask}]",
        "lea rsi, [rsi + {o_sigmask}]",
        "mov edi, 2",
        "mov r10d, 8",
        "mov eax, 14",
        "syscall",
        "cmp rax, -4095",
        "jae 2f",
        "mov rdx, r12",
        "mov rcx, [rdx + {o_fpregs}]",
        "fldenv [rcx]",
        "ldmxcsr [rdx + {o_mxcsr}]",
        "mov rsp, [rdx + {o_rsp}]",
        "mov rbx, [rdx + {o_rbx}]",
        "mov rbp, [rdx + {o_rbp}]",
        "mov r12, [rdx + {o_r12}]",
        "mov r13, [rdx + {o_r13}]",
        "mov r14, [rdx + {o_r14}]",
        "mov r15, [rdx + {o_r15}]",
        "mov rcx, [rdx + {o_rip}]",
        "push rcx",
        "mov rdi, [rdx + {o_rdi}]",
        "mov rsi, [rdx + {o_rsi}]",
        "mov rcx, [rdx + {o_rcx}]",
        "mov r8, [rdx + {o_r8}]",
        "mov r9, [rdx + {o_r9}]",
        "mov rdx, [rdx + {o_rdx}]",
        "xor eax, eax",
        "ret",
        "2:",
        "mov r12, [r9 + {o_r12}]",
        "neg eax",
        "mov edi, eax",
        "jmp {fail}",
        o_rbx = const greg(REG_RBX),
        o_rbp = const greg(REG_RBP),
        o_r12 = const greg(REG_R12),
        o_r13 = const greg(REG_R13),
        o_r14 = const greg(REG_R14),
        o_r15 = const greg(REG_R15),
        o_rdi = const greg(REG_RDI),
        o_rsi = const greg(REG_RSI),
        o_rdx = const greg(REG_RDX),
        o_rcx = const greg(REG_RCX),
        o_r8 = const greg(REG_R8),
        o_r9 = const greg(REG_R9),
        o_rip = const greg(REG_RIP),
        o_rsp = const greg(REG_RSP),
        o_fpregs_mem = const O_FPREGS_MEM,
        o_fpregs = const O_FPREGS,
        o_mxcsr = const O_MXCSR,
        o_sigmask = const O_SIGMASK,
        fail = sym set_errno_fail,
    )
}

extern "C" fn start_exit(status: c_int) -> ! {
    rusty_libc_core::process::exit(status)
}

#[unsafe(naked)]
unsafe extern "C" fn __start_context() -> ! {
    naked_asm!(
        "mov rdi, [rbx]",
        "mov rsp, rbx",
        "and rsp, -16",
        "test rdi, rdi",
        "je 2f",
        "call {setcontext}",
        "mov rdi, rax",
        "2:",
        "call {exit}",
        "hlt",
        setcontext = sym setcontext,
        exit = sym start_exit,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn makecontext(ucp: *mut UContext, func: extern "C" fn(), argc: c_int, mut args: ...) {
    unsafe {
        let ucp = &mut *ucp;
        let top = ucp.uc_stack.ss_sp as usize + ucp.uc_stack.ss_size;
        let stack_args = if argc > 6 { argc as usize - 6 } else { 0 };
        let sp = (((top as *mut i64).sub(stack_args + 1) as usize) & !15usize) - 8;
        let sp = sp as *mut i64;
        let idx_uc_link = stack_args + 1;
        let g = &mut ucp.uc_mcontext.gregs;
        g[REG_RIP] = func as usize as i64;
        g[REG_RBX] = sp.add(idx_uc_link) as usize as i64;
        g[REG_RSP] = sp as usize as i64;
        *sp = __start_context as *const () as usize as i64;
        *sp.add(idx_uc_link) = ucp.uc_link as usize as i64;
        for i in 0..argc.max(0) as usize {
            let v: i64 = args.next_arg::<i64>();
            match i {
                0 => g[REG_RDI] = v,
                1 => g[REG_RSI] = v,
                2 => g[REG_RDX] = v,
                3 => g[REG_RCX] = v,
                4 => g[REG_R8] = v,
                5 => g[REG_R9] = v,
                _ => *sp.add(i - 5) = v,
            }
        }
    }
}
