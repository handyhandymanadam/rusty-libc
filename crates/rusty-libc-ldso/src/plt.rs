//! The PLT trampoline used while profiling (`LD_PROFILE`) or auditing (`LD_AUDIT`): `_dl_runtime_profile`, glibc's name for it.
//!
//! With either feature every object's lazy PLT enters here instead of `_dl_runtime_resolve`, and the PLT slot is never patched,
//! so each call comes back: the first one looks the target up (and asks the audit libraries, `la_symbind64`), every call then
//! gives the audit libraries' `la_pltenter` the registers (glibc's `La_x86_64_regs`), may be redirected by them, is counted by
//! the profiler (`profile::mcount`), and is made. When a `la_pltenter` asked for a frame size the call is made from a copy
//! of the stack arguments and returns here, and `la_pltexit` sees (and may change) the return registers (`La_x86_64_retval`)
//! before the original caller gets them back. Without such a request the target is jumped to and returns to the caller itself.
//!
//! The whole vector state is saved and restored exactly (xsave); the audit library sees the full ymm (AVX) or zmm
//! (AVX-512) registers in `lr_vector` and `lrv_vector0/1`, as with glibc, and a register it changed there (or its
//! `lr_xmm` / `lrv_xmm0/1`) is what the function gets; after `la_pltenter` the two views of a register are made to agree, so
//! `la_pltexit` sees the changed values in both. Not handled: the registers zmm8-31 and the mask registers are
//! restored but not shown.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::audit;
use crate::map::*;
use crate::sys;
use crate::util::*;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::*};

/// Size of one cached PLT slot (`Slot`).
pub const SLOT_SIZE: usize = 32;

/// glibc's `struct reloc_result` for one PLT slot: what the first call found.
#[repr(C)]
pub struct Slot {
    pub addr: usize,
    pub bound: Option<Map>,
    pub boundndx: u32,
    pub enterexit: u32,
    pub flags: u32,
    pub init: u32,
}

/// The fields of a `Slot` before `init` (bytes 0..28): what the first call stores and every call reads. Kept apart so that
/// `init`, which threads read and publish atomically, is never touched by a plain access.
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

/// The address of a slot record's `init` word.
fn slot_init(s: *mut Slot) -> *mut u32 {
    (s as *mut u8).wrapping_add(core::mem::offset_of!(Slot, init)) as *mut u32
}

/// Do lazily bound PLT slots go through the tracing trampoline?
#[inline(always)]
pub fn wanted() -> bool {
    crate::profile::enabled() || audit::au().n != 0
}

/// The cached record of PLT slot `idx` of `m` (the table is made on first use; NULL when `idx` is not a PLT slot or there is no
/// memory).
fn slot_of(m: Map, idx: usize) -> *mut Slot {
    let n = m.pltrelsz() / core::mem::size_of::<crate::elf::Rela>();
    if idx >= n {
        return core::ptr::null_mut();
    }
    // SAFETY: the `plt_cache` word of a live link map; every access after the map was zeroed is through this atomic (dlclose
    // clears it with a plain store only when no thread can call through the object any more).
    let cache = unsafe { AtomicUsize::from_ptr(m.plt_cache_field()) };
    if cache.load(Acquire) == 0 {
        let len = (n * SLOT_SIZE).max(SLOT_SIZE);
        let mem = sys::mmap_new(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
        if mem < 0 && mem > -4096 {
            return core::ptr::null_mut();
        }
        // another thread may have been first: keep the winner's table
        let table = mem as usize;
        if cache.compare_exchange(0, table, AcqRel, Acquire).is_err() {
            // SAFETY: our own fresh mapping, which lost the race and was never published.
            unsafe { sys::munmap(table, len) };
        }
    }
    (cache.load(Acquire) as *mut Slot).wrapping_add(idx)
}

/// Called by the trampoline: resolve (once per slot), audit, count; returns the address to call. `framesize` is set to -1 (no
/// la_pltexit) or the number of stack-argument bytes to copy.
///
/// # Safety
/// Called by `_dl_runtime_profile` with the link map PLT0 pushed (GOT[1]), the PLT relocation index, the caller's return
/// address and the trampoline's register block and frame-size word.
unsafe extern "C" fn plt_fixup(m: *mut LinkMap, idx: usize, retaddr: usize, regs: *mut audit::Regs, framesize: *mut isize) -> usize {
    // SAFETY: the frame-size word of the trampoline's frame (caller's contract).
    let framesize = unsafe { &mut *framesize };
    *framesize = -1;
    // SAFETY: GOT[1] holds the address of the object's link map (caller's contract).
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { sys::exit(127) };
    let slot = slot_of(m, idx);
    let mut local = Slot { addr: 0, bound: None, boundndx: 0, enterexit: 0xffff, flags: 0, init: 0 };
    let s: *mut Slot = if slot.is_null() { &mut local } else { slot };
    // SAFETY: `s` is the slot's record in the object's table (32-byte records, made by `slot_of`) or `local`; its `init`
    // word is only accessed atomically.
    let init = unsafe { AtomicU32::from_ptr(slot_init(s)) };
    if init.load(Acquire) == 0 {
        let r = &m.jmprels()[idx];
        let symidx = (r.info >> 32) as usize;
        // SAFETY: the symbol of one of the object's PLT relocations; the program is running, so resolvers may run.
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
                // SAFETY: the record's fields before `init` (see above); until `init` is published only threads that also
                // found it 0 write them, all with the same values (glibc's reloc_result has the same benign race).
                unsafe { (s as *mut SlotHead).write(SlotHead { addr: value, bound: res.map, boundndx: ndx, enterexit: ee, flags: fl }) };
                init.store(1, Release);
            }
            None => {
                crate::eprint!("{}: {}\n", Bytes(crate::reloc::prog_name()), Bytes(error_str()));
                sys::exit(127)
            }
        }
    }
    // SAFETY: the record's fields are initialised (`init` is 1, published with Release and read with Acquire); a copy.
    let rec = unsafe { (s as *const SlotHead).read() };
    let mut value = rec.addr;
    if audit::active() && rec.enterexit & audit::LA_SYMB_NOPLTENTER == 0 {
        let mut ee = rec.enterexit;
        // SAFETY: the trampoline's register block (caller's contract).
        unsafe { audit::pltenter(m, rec.bound, rec.boundndx, &mut ee, rec.flags, &mut value, regs, framesize) };
        // SAFETY: the slot's `enterexit` word (glibc updates it the same way).
        unsafe { (*s).enterexit = ee };
    }
    if crate::profile::enabled() {
        crate::profile::mcount(retaddr, value);
    }
    value
}

/// Called by the trampoline after the function returned (only when a la_pltenter asked for it).
///
/// # Safety
/// As [`plt_fixup`], with the trampoline's register blocks for the call and its return.
unsafe extern "C" fn plt_exit(m: *mut LinkMap, idx: usize, inregs: *const audit::Regs, outregs: *mut audit::Retval) {
    // SAFETY: GOT[1] holds the address of the object's link map (caller's contract).
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { return };
    let slot = slot_of(m, idx);
    if slot.is_null() {
        return;
    }
    // SAFETY: the slot's record in the object's table; `init` is read atomically.
    if unsafe { AtomicU32::from_ptr(slot_init(slot)) }.load(Acquire) == 0 {
        return;
    }
    // SAFETY: an initialised record (see above); a copy of its fields before `init`.
    let rec = unsafe { (slot as *const SlotHead).read() };
    // SAFETY: the trampoline's register blocks (caller's contract).
    unsafe { audit::pltexit(m, rec.bound, rec.boundndx, rec.enterexit, rec.addr, inregs, outregs) };
}

/// What the audit libraries are shown of the vector registers: 0 the xmm registers only, 1 ymm, 2 zmm (glibc picks the
/// matching `_dl_runtime_profile` variant by the CPU features; here one trampoline branches on this byte). Set by
/// `init_vector_level` before the first trampoline is installed.
static VEC_LEVEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// 1 when the trampolines that save the whole vector state must use fxsave/fxrstor (512 bytes, the legacy SSE area) because
/// the processor has no XSAVE or the operating system has not enabled it (CPUID.1:ECX bits 26 and 27: pre-2008 Intel, QEMU's
/// Nehalem and qemu64 models); 0 (the initial value) means xsave/xrstor. glibc has `_xsave`/`_fxsave` variants for the same reason.
/// Read by the assembly of `_dl_runtime_profile` and `_dl_tlsdesc_dynamic`.
pub static NO_XSAVE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Choose the save instruction (`force` is the test hook LD_RL_FORCE_FXSAVE). Called once, early in the loader's start.
pub fn init_xsave(force: bool) {
    let l1 = core::arch::x86_64::__cpuid(1);
    let no = force || l1.ecx & (1 << 26) == 0 || l1.ecx & (1 << 27) == 0;
    NO_XSAVE.store(no as u8, Relaxed);
}

/// The bytes the state-saving trampolines reserve for one save area (a multiple of 64): what xsave writes for the components
/// the operating system enabled (XCR0) except AMX's tile configuration and data (bits 17 and 18, call-clobbered like glibc's
/// STATE_SAVE_MASK leaves them out: 8 KB of tile data would not fit, and glibc does not save them either), or 576 for fxsave
/// (the 512-byte legacy area and the 64-byte header the trampolines clear). Starts at 4096 (the old fixed size: enough for
/// AVX-512's 2696 bytes) until `init_xsave_size` measures it, before the first trampoline that reads it can run. Read by the
/// assembly of `_dl_runtime_profile` and `_dl_tlsdesc_dynamic`, which reserve this much instead of a fixed 4096 (FIXLIST #79:
/// with AVX2 the area is 832 bytes, so 3 KB of stack less under every call that needs a dynamic TLS block).
pub static XSAVE_SIZE: AtomicUsize = AtomicUsize::new(4096);

/// The xsave/xrstor component mask the trampolines pass in edx:eax: everything but AMX (bits 17 and 18; see `XSAVE_SIZE`).
pub const XSAVE_MASK_LO: u32 = !((1 << 17) | (1 << 18));

/// Measure `XSAVE_SIZE` (once; `init_xsave` has run). Called before the first TLS descriptor that uses
/// `_dl_tlsdesc_dynamic` is written and before profiling or auditing trampolines are installed (`init_vector_level`).
pub fn init_xsave_size() {
    use core::arch::x86_64::{__cpuid_count, _xgetbv};
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, Relaxed) {
        return;
    }
    let mut size = 576u32;
    if NO_XSAVE.load(Relaxed) == 0 {
        // SAFETY: XGETBV with ECX 0 only reads XCR0; NO_XSAVE is 0 only when CPUID.1:ECX says XSAVE and OSXSAVE are set.
        let xcr0 = unsafe { _xgetbv(0) } & XSAVE_MASK_LO as u64;
        // components 0 and 1 are the legacy area; each other one is at CPUID.(0xD, i).EBX, EAX bytes long (standard format)
        for i in 2..63u32 {
            if xcr0 & (1 << i) != 0 {
                let c = __cpuid_count(0xd, i);
                size = size.max(c.ebx.saturating_add(c.eax));
            }
        }
    }
    XSAVE_SIZE.store((size as usize + 63) & !63, Relaxed);
}

/// Find out what the processor and the operating system save (CPUID leaf 1 and 7, XCR0).
pub fn init_vector_level() {
    use core::arch::x86_64::{__cpuid, __cpuid_count, _xgetbv};
    static DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if DONE.swap(true, Relaxed) {
        return;
    }
    // xgetbv(0) reads XCR0; it is executed only when CPUID says OSXSAVE is set (the `||` stops before it otherwise)
    let xcr0 = || {
        // SAFETY: XGETBV with ECX 0 only reads processor state; reached only when CPUID.1:ECX.OSXSAVE is set (see above).
        unsafe { _xgetbv(0) }
    };
    let level = {
        let l1 = __cpuid(1);
        // OSXSAVE (bit 27) and AVX (bit 28), then the OS saving the SSE and AVX state (XCR0 bits 1, 2)
        if l1.ecx & (1 << 27) == 0 || l1.ecx & (1 << 28) == 0 || xcr0() & 6 != 6 {
            0
        } else if __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 16) != 0 && xcr0() & 0xe0 == 0xe0 {
            // AVX512F, and the OS saving opmask, ZMM_Hi256 and Hi16_ZMM (XCR0 bits 5, 6, 7)
            2
        } else {
            1
        }
    };
    VEC_LEVEL.store(level, Relaxed);
    init_xsave_size();
}

/// GOT[2] of every object while profiling or auditing. Stack on entry: link map, relocation index, return address, arguments.
/// Frame: `[rbx]` regs, `[rbx+8]` frame size, `[rbx+16]` saved rax, `[rbx+24]` saved rbx, `[rbx+32]` link map,
/// `[rbx+40]` index, `[rbx+48]` return address, `[rbx+56]` the first stack argument; below: `XSAVE_SIZE` + 256 bytes of save
/// area (the state at entry; reused after the call for the return value and, 256 bytes up, a second save area) and
/// `La_x86_64_regs` (768 bytes).
///
/// # Safety
/// Entered only from PLT0 of an object `reloc::setup_lazy_got` set up (never called from Rust).
#[unsafe(naked)]
pub unsafe extern "C" fn _dl_runtime_profile() {
    core::arch::naked_asm!(
        "push rbx",
        "push rax",
        "push 0",
        "push 0",
        "mov rbx, rsp",
        // the save area: XSAVE_SIZE + 256 bytes (at the exit a La_x86_64_retval and a second save area share it)
        "mov r11, qword ptr [rip + {xs}]",
        "add r11, 256",
        "sub rsp, r11",
        "sub rsp, 768",
        "and rsp, -64",
        "add r11, rsp",
        "mov [rbx], r11",
        // the integer argument registers
        "mov [r11], rdx",
        "mov [r11 + 8], r8",
        "mov [r11 + 16], r9",
        "mov [r11 + 24], rcx",
        "mov [r11 + 32], rsi",
        "mov [r11 + 40], rdi",
        "mov [r11 + 48], rbp",
        "lea r10, [rbx + 48]",
        "mov [r11 + 56], r10",
        // the whole vector state: the header of the xsave area must be zero except what xsave writes
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
        "mov eax, {mask}",
        "mov edx, -1",
        "xsave [rsp]",
        "jmp 819f",
        "818:",
        "fxsave [rsp]",
        "819:",
        // lr_xmm, and lr_vector (zero but for the low 16 bytes)
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
        // lr_vector: the whole register (ymm or zmm, by what the OS saves), the rest zero
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
        // everything back as it was, except what an audit library changed in the registers it was shown
        "cmp byte ptr [rip + {nox}], 0",
        "jne 828f",
        "mov eax, {mask}",
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
        // no la_pltexit: drop our frame (and the link map and index the PLT pushed) and jump; the target returns to the caller
        "mov rsp, rbx",
        "mov rbx, [rsp + 24]",
        "add rsp, 48",
        "jmp r11",
        "3:",
        // call the target from a copy of its stack arguments
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
        // the return registers into a La_x86_64_retval at the bottom of the old xsave area, a second xsave area above it
        "mov r10, [rbx]",
        "mov rsp, r10",
        "sub rsp, qword ptr [rip + {xs}]",
        "sub rsp, 256",
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
        "mov eax, {mask}",
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
        "mov eax, {mask}",
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
        xs = sym XSAVE_SIZE,
        mask = const XSAVE_MASK_LO,
    )
}
