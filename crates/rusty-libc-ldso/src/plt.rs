use crate::audit;
use crate::map::*;
use crate::sys;
use crate::util::*;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::*};

pub const SLOT_SIZE: usize = 32;

#[repr(C)]
pub struct Slot {
    pub addr: usize,
    pub bound: *mut LinkMap,
    pub boundndx: u32,
    pub enterexit: u32,
    pub flags: u32,
    pub init: u32,
}

#[inline(always)]
pub fn wanted() -> bool {
    crate::profile::enabled() || audit::au().n != 0
}

unsafe fn slot_of(m: *mut LinkMap, idx: usize) -> *mut Slot {
    let n = (*m).pltrelsz / core::mem::size_of::<crate::elf::Rela>();
    if idx >= n {
        return core::ptr::null_mut();
    }
    if (*m).plt_cache.is_null() {
        let len = (n * SLOT_SIZE).max(SLOT_SIZE);
        let mem = sys::mmap(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
        if mem < 0 && mem > -4096 {
            return core::ptr::null_mut();
        }
        let table = mem as usize;
        if AtomicUsize::from_ptr((&raw mut (*m).plt_cache) as *mut usize).compare_exchange(0, table, AcqRel, Acquire).is_err() {
            sys::munmap(table, len);
        }
    }
    ((*m).plt_cache as *mut Slot).add(idx)
}

unsafe extern "C" fn plt_fixup(m: *mut LinkMap, idx: usize, retaddr: usize, regs: *mut audit::Regs, framesize: *mut isize) -> usize {
    *framesize = -1;
    let slot = slot_of(m, idx);
    let mut local = Slot { addr: 0, bound: core::ptr::null_mut(), boundndx: 0, enterexit: 0xffff, flags: 0, init: 0 };
    let s: *mut Slot = if slot.is_null() { &mut local } else { slot };
    if AtomicU32::from_ptr(&raw mut (*s).init).load(Acquire) == 0 {
        let r = &*(*m).jmprel.add(idx);
        let symidx = (r.info >> 32) as usize;
        match crate::reloc::bind_ex(m, symidx, true, false, false) {
            Some(res) => {
                let mut value = res.addr;
                let (mut ee, mut fl) = (0xffffu32, 0u32);
                let mut ndx = 0u32;
                if !res.map.is_null() {
                    ndx = ((res.sym as usize - (*res.map).symtab as usize) / core::mem::size_of::<crate::elf::Sym>()) as u32;
                    if audit::active() {
                        let name = cstr((*res.map).strtab.add((*res.sym).name as usize));
                        let (v, e, f) = audit::symbind_slot(res.sym, res.map, m, name, value);
                        value = v;
                        ee = e;
                        fl = f;
                    }
                }
                (*s).addr = value;
                (*s).bound = res.map;
                (*s).boundndx = ndx;
                (*s).enterexit = ee;
                (*s).flags = fl;
                AtomicU32::from_ptr(&raw mut (*s).init).store(1, Release);
            }
            None => {
                crate::eprint!("{}: {}\n", Bytes(cstr(st().prog_name)), Bytes(error_str()));
                sys::exit(127)
            }
        }
    }
    let mut value = (*s).addr;
    if audit::active() && (*s).enterexit & audit::LA_SYMB_NOPLTENTER == 0 {
        let mut ee = (*s).enterexit;
        audit::pltenter(m, (*s).bound, (*s).boundndx, &mut ee, (*s).flags, &mut value, regs, &mut *framesize);
        (*s).enterexit = ee;
    }
    if crate::profile::enabled() {
        crate::profile::mcount(retaddr, value);
    }
    value
}

unsafe extern "C" fn plt_exit(m: *mut LinkMap, idx: usize, inregs: *const audit::Regs, outregs: *mut audit::Retval) {
    let slot = slot_of(m, idx);
    if slot.is_null() || (*slot).init == 0 {
        return;
    }
    audit::pltexit(m, (*slot).bound, (*slot).boundndx, (*slot).enterexit, (*slot).addr, inregs, outregs);
}

#[unsafe(naked)]
pub unsafe extern "C" fn _dl_runtime_profile() {
    core::arch::naked_asm!(
        "push rbx",
        "push rax",
        "push 0",
        "push 0",
        "mov rbx, rsp",
        "sub rsp, 4864",
        "and rsp, -64",
        "lea r11, [rsp + 4096]",
        "mov [rbx], r11",
        "mov [r11], rdx",
        "mov [r11 + 8], r8",
        "mov [r11 + 16], r9",
        "mov [r11 + 24], rcx",
        "mov [r11 + 32], rsi",
        "mov [r11 + 40], rdi",
        "mov [r11 + 48], rbp",
        "lea r10, [rbx + 48]",
        "mov [r11 + 56], r10",
        "xor r10d, r10d",
        "mov [rsp + 512], r10",
        "mov [rsp + 520], r10",
        "mov [rsp + 528], r10",
        "mov [rsp + 536], r10",
        "mov [rsp + 544], r10",
        "mov [rsp + 552], r10",
        "mov [rsp + 560], r10",
        "mov [rsp + 568], r10",
        "mov eax, -1",
        "mov edx, -1",
        "xsave [rsp]",
        "movups [r11 + 64], xmm0",
        "movups [r11 + 80], xmm1",
        "movups [r11 + 96], xmm2",
        "movups [r11 + 112], xmm3",
        "movups [r11 + 128], xmm4",
        "movups [r11 + 144], xmm5",
        "movups [r11 + 160], xmm6",
        "movups [r11 + 176], xmm7",
        "lea rdi, [r11 + 192]",
        "mov ecx, 72",
        "xor eax, eax",
        "rep stosq",
        "movups [r11 + 192], xmm0",
        "movups [r11 + 256], xmm1",
        "movups [r11 + 320], xmm2",
        "movups [r11 + 384], xmm3",
        "movups [r11 + 448], xmm4",
        "movups [r11 + 512], xmm5",
        "movups [r11 + 576], xmm6",
        "movups [r11 + 640], xmm7",
        "mov rdi, [rbx + 32]",
        "mov rsi, [rbx + 40]",
        "mov rdx, [rbx + 48]",
        "mov rcx, [rbx]",
        "lea r8, [rbx + 8]",
        "call {fixup}",
        "mov r11, rax",
        "mov eax, -1",
        "mov edx, -1",
        "xrstor [rsp]",
        "mov r10, [rbx]",
        "movups xmm8, [r10 + 64]",
        "pcmpeqb xmm8, [rsp + 160]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm0, [r10 + 64]",
        "2:",
        "movups xmm8, [r10 + 80]",
        "pcmpeqb xmm8, [rsp + 176]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm1, [r10 + 80]",
        "2:",
        "movups xmm8, [r10 + 96]",
        "pcmpeqb xmm8, [rsp + 192]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm2, [r10 + 96]",
        "2:",
        "movups xmm8, [r10 + 112]",
        "pcmpeqb xmm8, [rsp + 208]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm3, [r10 + 112]",
        "2:",
        "movups xmm8, [r10 + 128]",
        "pcmpeqb xmm8, [rsp + 224]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm4, [r10 + 128]",
        "2:",
        "movups xmm8, [r10 + 144]",
        "pcmpeqb xmm8, [rsp + 240]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm5, [r10 + 144]",
        "2:",
        "movups xmm8, [r10 + 160]",
        "pcmpeqb xmm8, [rsp + 256]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm6, [r10 + 160]",
        "2:",
        "movups xmm8, [r10 + 176]",
        "pcmpeqb xmm8, [rsp + 272]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm7, [r10 + 176]",
        "2:",
        "mov rax, [rbx + 16]",
        "mov rdx, [r10]",
        "mov r8, [r10 + 8]",
        "mov r9, [r10 + 16]",
        "mov rcx, [r10 + 24]",
        "mov rsi, [r10 + 32]",
        "mov rdi, [r10 + 40]",
        "mov r10, [rbx + 8]",
        "test r10, r10",
        "jns 3f",
        "mov rsp, rbx",
        "mov rbx, [rsp + 24]",
        "add rsp, 48",
        "jmp r11",
        "3:",
        "lea rsi, [rbx + 56]",
        "lea rcx, [r10 + 8]",
        "and rcx, -16",
        "sub rsp, rcx",
        "mov rdi, rsp",
        "rep movsb",
        "mov r10, [rbx]",
        "mov rcx, [r10 + 24]",
        "mov rsi, [r10 + 32]",
        "mov rdi, [r10 + 40]",
        "call r11",
        "mov r10, [rbx]",
        "lea rsp, [r10 - 4096]",
        "mov [rsp], rax",
        "mov [rsp + 8], rdx",
        "fstp tbyte ptr [rsp + 48]",
        "fstp tbyte ptr [rsp + 64]",
        "xor r11d, r11d",
        "mov [rsp + 768], r11",
        "mov [rsp + 776], r11",
        "mov [rsp + 784], r11",
        "mov [rsp + 792], r11",
        "mov [rsp + 800], r11",
        "mov [rsp + 808], r11",
        "mov [rsp + 816], r11",
        "mov [rsp + 824], r11",
        "mov eax, -1",
        "mov edx, -1",
        "xsave [rsp + 256]",
        "movups [rsp + 16], xmm0",
        "movups [rsp + 32], xmm1",
        "lea rdi, [rsp + 80]",
        "mov ecx, 20",
        "xor eax, eax",
        "rep stosq",
        "movups [rsp + 80], xmm0",
        "movups [rsp + 144], xmm1",
        "mov rdi, [rbx + 32]",
        "mov rsi, [rbx + 40]",
        "mov rdx, [rbx]",
        "mov rcx, rsp",
        "call {exit}",
        "mov eax, -1",
        "mov edx, -1",
        "xrstor [rsp + 256]",
        "movups xmm8, [rsp + 16]",
        "pcmpeqb xmm8, [rsp + 416]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm0, [rsp + 16]",
        "2:",
        "movups xmm8, [rsp + 32]",
        "pcmpeqb xmm8, [rsp + 432]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "je 2f",
        "movups xmm1, [rsp + 32]",
        "2:",
        "mov rax, [rsp]",
        "mov rdx, [rsp + 8]",
        "fld tbyte ptr [rsp + 64]",
        "fld tbyte ptr [rsp + 48]",
        "mov rsp, rbx",
        "mov rbx, [rsp + 24]",
        "add rsp, 48",
        "ret",
        fixup = sym plt_fixup,
        exit = sym plt_exit,
    )
}
