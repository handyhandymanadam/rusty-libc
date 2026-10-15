#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::audit;
use crate::map::*;
use crate::sys;
use crate::util::*;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::*};

pub const SLOT_SIZE: usize = 32;

#[repr(C)]
pub struct Slot {
    pub addr: usize,
    pub bound: Option<Map>,
    pub boundndx: u32,
    pub enterexit: u32,
    pub flags: u32,
    pub init: u32,
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct SlotHead {
    addr: usize,
    bound: Option<Map>,
    boundndx: u32,
    enterexit: u32,
    flags: u32,
}
const _: () = assert!(core::mem::size_of::<SlotHead>() == core::mem::offset_of!(Slot, init));
const _: () = assert!(core::mem::offset_of!(SlotHead, enterexit) == core::mem::offset_of!(Slot, enterexit));
const _: () = assert!(core::mem::size_of::<Slot>() == SLOT_SIZE);

fn slot_init(s: *mut Slot) -> *mut u32 {
    (s as *mut u8).wrapping_add(core::mem::offset_of!(Slot, init)) as *mut u32
}

#[inline(always)]
pub fn wanted() -> bool {
    crate::profile::enabled() || audit::au().n != 0
}

fn slot_of(m: Map, idx: usize) -> *mut Slot {
    let n = m.pltrelsz() / core::mem::size_of::<crate::elf::Rela>();
    if idx >= n {
        return core::ptr::null_mut();
    }
    let cache = unsafe { AtomicUsize::from_ptr(m.plt_cache_field()) };
    if cache.load(Acquire) == 0 {
        let len = (n * SLOT_SIZE).max(SLOT_SIZE);
        let mem = sys::mmap_new(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
        if mem < 0 && mem > -4096 {
            return core::ptr::null_mut();
        }
        let table = mem as usize;
        if cache.compare_exchange(0, table, AcqRel, Acquire).is_err() {
            unsafe { sys::munmap(table, len) };
        }
    }
    (cache.load(Acquire) as *mut Slot).wrapping_add(idx)
}

unsafe extern "C" fn plt_fixup(m: *mut LinkMap, idx: usize, retaddr: usize, regs: *mut audit::Regs, framesize: *mut isize) -> usize {
    let framesize = unsafe { &mut *framesize };
    *framesize = -1;
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { sys::exit(127) };
    let slot = slot_of(m, idx);
    let mut local = Slot { addr: 0, bound: None, boundndx: 0, enterexit: 0xffff, flags: 0, init: 0 };
    let s: *mut Slot = if slot.is_null() { &mut local } else { slot };
    let init = unsafe { AtomicU32::from_ptr(slot_init(s)) };
    if init.load(Acquire) == 0 {
        let r = &m.jmprels()[idx];
        let symidx = (r.info >> 32) as usize;
        match unsafe { crate::reloc::bind_ex(m, symidx, true, false, false) } {
            Some(res) => {
                let mut value = res.addr;
                let (mut ee, mut fl) = (0xffffu32, 0u32);
                let mut ndx = 0u32;
                if let Some(rm) = res.map {
                    ndx = rm.sym_index(res.sym) as u32;
                    if audit::active() {
                        let name = rm.sym_name(res.sym).bytes();
                        let (v, e, f) = audit::symbind_slot(res.sym, rm, m, name, value);
                        value = v;
                        ee = e;
                        fl = f;
                    }
                }
                unsafe { (s as *mut SlotHead).write(SlotHead { addr: value, bound: res.map, boundndx: ndx, enterexit: ee, flags: fl }) };
                init.store(1, Release);
            }
            None => {
                crate::eprint!("{}: {}\n", Bytes(crate::reloc::prog_name()), Bytes(error_str()));
                sys::exit(127)
            }
        }
    }
    let rec = unsafe { (s as *const SlotHead).read() };
    let mut value = rec.addr;
    if audit::active() && rec.enterexit & audit::LA_SYMB_NOPLTENTER == 0 {
        let mut ee = rec.enterexit;
        unsafe { audit::pltenter(m, rec.bound, rec.boundndx, &mut ee, rec.flags, &mut value, regs, framesize) };
        unsafe { (*s).enterexit = ee };
    }
    if crate::profile::enabled() {
        crate::profile::mcount(retaddr, value);
    }
    value
}

unsafe extern "C" fn plt_exit(m: *mut LinkMap, idx: usize, inregs: *const audit::Regs, outregs: *mut audit::Retval) {
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { return };
    let slot = slot_of(m, idx);
    if slot.is_null() {
        return;
    }
    if unsafe { AtomicU32::from_ptr(slot_init(slot)) }.load(Acquire) == 0 {
        return;
    }
    let rec = unsafe { (slot as *const SlotHead).read() };
    unsafe { audit::pltexit(m, rec.bound, rec.boundndx, rec.enterexit, rec.addr, inregs, outregs) };
}

static VEC_LEVEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

pub static NO_XSAVE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

pub fn init_xsave(force: bool) {
    let l1 = core::arch::x86_64::__cpuid(1);
    let no = force || l1.ecx & (1 << 26) == 0 || l1.ecx & (1 << 27) == 0;
    NO_XSAVE.store(no as u8, Relaxed);
}

pub fn init_vector_level() {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, Relaxed) {
        return;
    }
    let xcr0 = || {
        unsafe { _xgetbv(0) }
    };
    let level = {
        let l1 = __cpuid(1);
        if l1.ecx & (1 << 27) == 0 || l1.ecx & (1 << 28) == 0 || xcr0() & 6 != 6 {
            0
        } else if __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 16) != 0 && xcr0() & 0xe0 == 0xe0 {
            2
        } else {
            1
        }
    };
    VEC_LEVEL.store(level, Relaxed);
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
        "cmp byte ptr [rip + {nox}], 0",
        "jne 818f",
        "mov eax, -1",
        "mov edx, -1",
        "xsave [rsp]",
        "jmp 819f",
        "818:",
        "fxsave [rsp]",
        "819:",
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
        "movzx r10d, byte ptr [rip + {lvl}]",
        "cmp r10d, 2",
        "je 6f",
        "cmp r10d, 1",
        "je 5f",
        "movups [r11 + 192], xmm0",
        "movups [r11 + 256], xmm1",
        "movups [r11 + 320], xmm2",
        "movups [r11 + 384], xmm3",
        "movups [r11 + 448], xmm4",
        "movups [r11 + 512], xmm5",
        "movups [r11 + 576], xmm6",
        "movups [r11 + 640], xmm7",
        "jmp 7f",
        "5:",
        "vmovdqu [r11 + 192], ymm0",
        "vmovdqu [r11 + 256], ymm1",
        "vmovdqu [r11 + 320], ymm2",
        "vmovdqu [r11 + 384], ymm3",
        "vmovdqu [r11 + 448], ymm4",
        "vmovdqu [r11 + 512], ymm5",
        "vmovdqu [r11 + 576], ymm6",
        "vmovdqu [r11 + 640], ymm7",
        "jmp 7f",
        "6:",
        "vmovdqu64 [r11 + 192], zmm0",
        "vmovdqu64 [r11 + 256], zmm1",
        "vmovdqu64 [r11 + 320], zmm2",
        "vmovdqu64 [r11 + 384], zmm3",
        "vmovdqu64 [r11 + 448], zmm4",
        "vmovdqu64 [r11 + 512], zmm5",
        "vmovdqu64 [r11 + 576], zmm6",
        "vmovdqu64 [r11 + 640], zmm7",
        "7:",
        "mov rdi, [rbx + 32]",
        "mov rsi, [rbx + 40]",
        "mov rdx, [rbx + 48]",
        "mov rcx, [rbx]",
        "lea r8, [rbx + 8]",
        "call {fixup}",
        "mov r11, rax",
        "cmp byte ptr [rip + {nox}], 0",
        "jne 828f",
        "mov eax, -1",
        "mov edx, -1",
        "xrstor [rsp]",
        "jmp 829f",
        "828:",
        "fxrstor [rsp]",
        "829:",
        "mov r10, [rbx]",
        "movzx esi, byte ptr [rip + {lvl}]",
        "movups xmm8, [r10 + 64]",
        "pcmpeqb xmm8, [rsp + 160]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 100f",
        "cmp esi, 2",
        "je 200f",
        "cmp esi, 1",
        "jne 300f",
        "vmovdqu ymm0, [r10 + 192]",
        "movups [r10 + 64], xmm0",
        "jmp 300f",
        "200:",
        "vmovdqu64 zmm0, [r10 + 192]",
        "movups [r10 + 64], xmm0",
        "jmp 300f",
        "100:",
        "movups xmm0, [r10 + 64]",
        "movups [r10 + 192], xmm0",
        "300:",
        "movups xmm8, [r10 + 80]",
        "pcmpeqb xmm8, [rsp + 176]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 101f",
        "cmp esi, 2",
        "je 201f",
        "cmp esi, 1",
        "jne 301f",
        "vmovdqu ymm1, [r10 + 256]",
        "movups [r10 + 80], xmm1",
        "jmp 301f",
        "201:",
        "vmovdqu64 zmm1, [r10 + 256]",
        "movups [r10 + 80], xmm1",
        "jmp 301f",
        "101:",
        "movups xmm1, [r10 + 80]",
        "movups [r10 + 256], xmm1",
        "301:",
        "movups xmm8, [r10 + 96]",
        "pcmpeqb xmm8, [rsp + 192]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 102f",
        "cmp esi, 2",
        "je 202f",
        "cmp esi, 1",
        "jne 302f",
        "vmovdqu ymm2, [r10 + 320]",
        "movups [r10 + 96], xmm2",
        "jmp 302f",
        "202:",
        "vmovdqu64 zmm2, [r10 + 320]",
        "movups [r10 + 96], xmm2",
        "jmp 302f",
        "102:",
        "movups xmm2, [r10 + 96]",
        "movups [r10 + 320], xmm2",
        "302:",
        "movups xmm8, [r10 + 112]",
        "pcmpeqb xmm8, [rsp + 208]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 103f",
        "cmp esi, 2",
        "je 203f",
        "cmp esi, 1",
        "jne 303f",
        "vmovdqu ymm3, [r10 + 384]",
        "movups [r10 + 112], xmm3",
        "jmp 303f",
        "203:",
        "vmovdqu64 zmm3, [r10 + 384]",
        "movups [r10 + 112], xmm3",
        "jmp 303f",
        "103:",
        "movups xmm3, [r10 + 112]",
        "movups [r10 + 384], xmm3",
        "303:",
        "movups xmm8, [r10 + 128]",
        "pcmpeqb xmm8, [rsp + 224]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 104f",
        "cmp esi, 2",
        "je 204f",
        "cmp esi, 1",
        "jne 304f",
        "vmovdqu ymm4, [r10 + 448]",
        "movups [r10 + 128], xmm4",
        "jmp 304f",
        "204:",
        "vmovdqu64 zmm4, [r10 + 448]",
        "movups [r10 + 128], xmm4",
        "jmp 304f",
        "104:",
        "movups xmm4, [r10 + 128]",
        "movups [r10 + 448], xmm4",
        "304:",
        "movups xmm8, [r10 + 144]",
        "pcmpeqb xmm8, [rsp + 240]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 105f",
        "cmp esi, 2",
        "je 205f",
        "cmp esi, 1",
        "jne 305f",
        "vmovdqu ymm5, [r10 + 512]",
        "movups [r10 + 144], xmm5",
        "jmp 305f",
        "205:",
        "vmovdqu64 zmm5, [r10 + 512]",
        "movups [r10 + 144], xmm5",
        "jmp 305f",
        "105:",
        "movups xmm5, [r10 + 144]",
        "movups [r10 + 512], xmm5",
        "305:",
        "movups xmm8, [r10 + 160]",
        "pcmpeqb xmm8, [rsp + 256]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 106f",
        "cmp esi, 2",
        "je 206f",
        "cmp esi, 1",
        "jne 306f",
        "vmovdqu ymm6, [r10 + 576]",
        "movups [r10 + 160], xmm6",
        "jmp 306f",
        "206:",
        "vmovdqu64 zmm6, [r10 + 576]",
        "movups [r10 + 160], xmm6",
        "jmp 306f",
        "106:",
        "movups xmm6, [r10 + 160]",
        "movups [r10 + 576], xmm6",
        "306:",
        "movups xmm8, [r10 + 176]",
        "pcmpeqb xmm8, [rsp + 272]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 107f",
        "cmp esi, 2",
        "je 207f",
        "cmp esi, 1",
        "jne 307f",
        "vmovdqu ymm7, [r10 + 640]",
        "movups [r10 + 176], xmm7",
        "jmp 307f",
        "207:",
        "vmovdqu64 zmm7, [r10 + 640]",
        "movups [r10 + 176], xmm7",
        "jmp 307f",
        "107:",
        "movups xmm7, [r10 + 176]",
        "movups [r10 + 640], xmm7",
        "307:",
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
        "cmp byte ptr [rip + {nox}], 0",
        "jne 838f",
        "mov eax, -1",
        "mov edx, -1",
        "xsave [rsp + 256]",
        "jmp 839f",
        "838:",
        "fxsave [rsp + 256]",
        "839:",
        "movups [rsp + 16], xmm0",
        "movups [rsp + 32], xmm1",
        "lea rdi, [rsp + 80]",
        "mov ecx, 20",
        "xor eax, eax",
        "rep stosq",
        "movzx esi, byte ptr [rip + {lvl}]",
        "cmp esi, 2",
        "je 6f",
        "cmp esi, 1",
        "je 5f",
        "movups [rsp + 80], xmm0",
        "movups [rsp + 144], xmm1",
        "jmp 7f",
        "5:",
        "vmovdqu [rsp + 80], ymm0",
        "vmovdqu [rsp + 144], ymm1",
        "jmp 7f",
        "6:",
        "vmovdqu64 [rsp + 80], zmm0",
        "vmovdqu64 [rsp + 144], zmm1",
        "7:",
        "mov rdi, [rbx + 32]",
        "mov rsi, [rbx + 40]",
        "mov rdx, [rbx]",
        "mov rcx, rsp",
        "call {exit}",
        "cmp byte ptr [rip + {nox}], 0",
        "jne 848f",
        "mov eax, -1",
        "mov edx, -1",
        "xrstor [rsp + 256]",
        "jmp 849f",
        "848:",
        "fxrstor [rsp + 256]",
        "849:",
        "movzx esi, byte ptr [rip + {lvl}]",
        "movups xmm8, [rsp + 16]",
        "pcmpeqb xmm8, [rsp + 416]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 400f",
        "cmp esi, 2",
        "je 500f",
        "cmp esi, 1",
        "jne 600f",
        "vmovdqu ymm0, [rsp + 80]",
        "jmp 600f",
        "500:",
        "vmovdqu64 zmm0, [rsp + 80]",
        "jmp 600f",
        "400:",
        "movups xmm0, [rsp + 16]",
        "600:",
        "movups xmm8, [rsp + 32]",
        "pcmpeqb xmm8, [rsp + 432]",
        "pmovmskb eax, xmm8",
        "cmp eax, 0xffff",
        "jne 401f",
        "cmp esi, 2",
        "je 501f",
        "cmp esi, 1",
        "jne 601f",
        "vmovdqu ymm1, [rsp + 144]",
        "jmp 601f",
        "501:",
        "vmovdqu64 zmm1, [rsp + 144]",
        "jmp 601f",
        "401:",
        "movups xmm1, [rsp + 32]",
        "601:",
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
        lvl = sym VEC_LEVEL,
        nox = sym NO_XSAVE,
    )
}
