//! execinfo.h: backtrace, backtrace_symbols, backtrace_symbols_fd.
//!
//! `backtrace` walks the stack of the calling thread with the call frame information of the program
//! (DWARF `.eh_frame`, what gcc and rustc emit for every function and what glibc's backtrace reads through
//! libgcc), so it works for code compiled without frame pointers. The frame information is found through
//! the program header `PT_GNU_EH_FRAME` (the sorted `.eh_frame_hdr` table) when the program was linked with
//! one, and otherwise (a static program: gcc links it without that table) by finding the section `.eh_frame`
//! in the loaded read-only segments from memory alone, as glibc's static backtrace does (libgcc there gets
//! the section from crtbeginT.o's registration): no file is read, so it works in a chroot or a sandbox
//! without /proc. The first address returned is the return address of the call to `backtrace`; the walk
//! ends at a frame without information or with an undefined return address, or after `size` addresses.
//! Signal frames (the `__restore_rt` trampoline) are stepped through using the saved context.
//!
//! `backtrace_symbols` and `backtrace_symbols_fd` print `FILE(SYMBOL+0xOFFSET) [0xADDRESS]` under the dynamic
//! loader (`FILE() [0xADDRESS]` without a symbol and load bias, `[0xADDRESS]` outside every object); in a static
//! program every line is `[0xADDRESS]`, as glibc's static one prints.
//!
//! Unsafe in this module (BRIEF-UNSAFE.md U2). The walk reads memory that no Rust type describes: the frame information
//! (`.eh_frame`, `.eh_frame_hdr`), the code bytes of the signal trampoline and the calling thread's stack. All of those reads
//! go through [`Mem`], whose single unsafe constructor states the trust the walk rests on (the same trust glibc's
//! backtrace places in libgcc's unwinder: the program's frame information is well formed and describes the stack that is
//! being walked). `Mem` is private to this module, so that rule is checked here and nowhere else (Rust for Rustaceans
//! p.233: soundness is judged at the privacy boundary). What stays unsafe besides `Mem`: the naked assembly front end of
//! `backtrace`, the loader's `__libc_ldso_find_object` / `__libc_ldso_dladdr1` calls (weak symbols read with inline
//! assembly and called through a pointer), the scratch mapping of the `.eh_frame` search, the program header table from
//! the auxiliary vector, and the C caller's buffers (converted once at each entry point).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::dlfcn::image;
use core::ffi::{c_char, c_int, c_void};
#[cfg(feature = "shared")]
use core::ffi::CStr;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

// ------------------------------------------------------------------ trusted memory

/// Read access to the memory the walk trusts: the loaded objects' frame information and code, and the calling thread's
/// stack. Every address the module computes from that information (record lengths, CIE pointers, encoded pointers, CFA
/// and register rules) is read through it; it never writes.
#[derive(Clone, Copy)]
struct Mem(());

impl Mem {
    /// The token.
    ///
    /// # Safety
    /// Only addresses taken from the running program's own frame information, code and the calling thread's stack (and
    /// what that information leads to) may be read through it: the frame information of every loaded object is well formed
    /// and its rules describe the frames being walked, as libgcc's unwinder assumes for glibc's backtrace.
    #[inline(always)]
    unsafe fn trusted() -> Mem {
        Mem(())
    }

    #[inline(always)]
    fn u8(self, a: u64) -> u8 {
        // SAFETY: `a` is inside the trusted memory (`Mem::trusted`'s contract).
        unsafe { (a as *const u8).read() }
    }

    #[inline(always)]
    fn u16(self, a: u64) -> u16 {
        // SAFETY: as `u8`; any alignment.
        unsafe { (a as *const u16).read_unaligned() }
    }

    #[inline(always)]
    fn u32(self, a: u64) -> u32 {
        // SAFETY: as `u8`; any alignment.
        unsafe { (a as *const u32).read_unaligned() }
    }

    #[inline(always)]
    fn u64(self, a: u64) -> u64 {
        // SAFETY: as `u8`; any alignment.
        unsafe { (a as *const u64).read_unaligned() }
    }

    /// `n` bytes at `a`.
    #[inline(always)]
    fn bytes(self, a: u64, n: usize) -> &'static [u8] {
        // SAFETY: the bytes are inside the trusted memory, which stays mapped and unchanged while the program runs (loaded
        // code and read-only frame information).
        unsafe { core::slice::from_raw_parts(a as *const u8, n) }
    }
}

// ------------------------------------------------------------------ DWARF reading

struct Reader {
    m: Mem,
    p: u64,
}

impl Reader {
    fn u8(&mut self) -> u8 {
        let v = self.m.u8(self.p);
        self.p += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = self.m.u16(self.p);
        self.p += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = self.m.u32(self.p);
        self.p += 4;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = self.m.u64(self.p);
        self.p += 8;
        v
    }
    fn uleb(&mut self) -> u64 {
        let (mut r, mut shift) = (0u64, 0u32);
        loop {
            let b = self.u8();
            if shift < 64 {
                r |= ((b & 0x7f) as u64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return r;
            }
        }
    }
    fn sleb(&mut self) -> i64 {
        let (mut r, mut shift) = (0i64, 0u32);
        loop {
            let b = self.u8();
            if shift < 64 {
                r |= ((b & 0x7f) as i64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    r |= -1i64 << shift;
                }
                return r;
            }
        }
    }
    /// A pointer in the encoding `enc` (DW_EH_PE_*); `datarel_base` is for the datarel application.
    fn encoded(&mut self, enc: u8, datarel_base: u64) -> u64 {
        if enc == 0xff {
            return 0;
        }
        let here = self.p;
        let mut v = match enc & 0x0f {
            0x00 => self.u64(),
            0x01 => self.uleb(),
            0x02 => self.u16() as u64,
            0x03 => self.u32() as u64,
            0x04 => self.u64(),
            0x09 => self.sleb() as u64,
            0x0a => self.u16() as i16 as i64 as u64,
            0x0b => self.u32() as i32 as i64 as u64,
            0x0c => self.u64(),
            _ => 0,
        };
        match enc & 0x70 {
            0x10 => v = v.wrapping_add(here),
            0x30 => v = v.wrapping_add(datarel_base),
            _ => {}
        }
        if enc & 0x80 != 0 && v != 0 {
            v = self.m.u64(v);
        }
        v
    }
}

/// A parsed CIE.
struct Cie {
    code_align: u64,
    data_align: i64,
    #[allow(dead_code)]
    ra_reg: u64,
    fde_enc: u8,
    signal: bool,
    has_z: bool,
    insns: u64,
    insns_end: u64,
}

/// An FDE with its CIE.
struct Fde {
    cie: Cie,
    start: u64,
    #[allow(dead_code)]
    end: u64,
    insns: u64,
    insns_end: u64,
}

/// The extent of one record: `(length of the contents, header size)` at `p`, or None at the terminator.
fn record_len(m: Mem, p: u64) -> Option<(usize, usize)> {
    let l = m.u32(p);
    if l == 0 {
        return None;
    }
    if l == 0xffff_ffff {
        let l64 = m.u64(p + 4);
        return Some((l64 as usize, 12));
    }
    Some((l as usize, 4))
}

fn parse_cie(m: Mem, p: u64) -> Option<Cie> {
    let (len, hdr) = record_len(m, p)?;
    let end = p.wrapping_add((hdr + len) as u64);
    let mut r = Reader { m, p: p + hdr as u64 };
    let id = r.u32();
    if id != 0 {
        return None;
    }
    let version = r.u8();
    // the augmentation string
    let aug = r.p;
    while r.u8() != 0 {}
    let aug_len = (r.p - aug) as usize - 1;
    let aug = m.bytes(aug, aug_len);
    if version >= 4 {
        r.u8(); // address size
        r.u8(); // segment size
    }
    let code_align = r.uleb();
    let data_align = r.sleb();
    let ra_reg = if version == 1 { r.u8() as u64 } else { r.uleb() };
    let mut cie = Cie { code_align, data_align, ra_reg, fde_enc: 0, signal: false, has_z: false, insns: 0, insns_end: end };
    if aug.first() == Some(&b'z') {
        cie.has_z = true;
        let alen = r.uleb() as usize;
        let after = r.p.wrapping_add(alen as u64);
        for &c in &aug[1..] {
            match c {
                b'L' => {
                    r.u8();
                }
                b'R' => cie.fde_enc = r.u8(),
                b'P' => {
                    let enc = r.u8();
                    r.encoded(enc, 0);
                }
                b'S' => cie.signal = true,
                _ => {}
            }
        }
        r.p = after;
    } else if !aug.is_empty() {
        return None;
    }
    cie.insns = r.p;
    Some(cie)
}

/// The FDE at `p` (when it covers `pc`), with its CIE.
fn parse_fde(m: Mem, p: u64, pc: u64) -> Option<Fde> {
    let (len, hdr) = record_len(m, p)?;
    let end = p.wrapping_add((hdr + len) as u64);
    let idp = p + hdr as u64;
    let id = m.u32(idp);
    if id == 0 {
        return None; // a CIE
    }
    let cie_ptr = idp.wrapping_sub(id as u64);
    let cie = parse_cie(m, cie_ptr)?;
    let mut r = Reader { m, p: idp + 4 };
    let start = r.encoded(cie.fde_enc, 0);
    let range = r.encoded(cie.fde_enc & 0x0f, 0);
    if pc < start || pc >= start.wrapping_add(range) {
        return None;
    }
    if cie.has_z {
        let alen = r.uleb() as usize;
        r.p = r.p.wrapping_add(alen as u64);
    }
    Some(Fde { start, end: start + range, insns: r.p, insns_end: end, cie })
}

// ------------------------------------------------------------------ finding the frame information

const PT_GNU_EH_FRAME: u32 = 0x6474e550;
const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;

#[repr(C)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// The program header table from the auxiliary vector (empty when there is none).
fn program_headers() -> &'static [Phdr] {
    // SAFETY: getauxval takes a plain value (it sets errno to ENOENT for a missing entry, as before).
    let ph = unsafe { rusty_libc_util::auxv::getauxval(AT_PHDR) } as *const Phdr;
    // SAFETY: as above.
    let n = unsafe { rusty_libc_util::auxv::getauxval(AT_PHNUM) } as usize;
    if ph.is_null() {
        return &[];
    }
    // SAFETY: AT_PHDR/AT_PHNUM describe the program's header table, which the kernel mapped with the program and which
    // stays mapped and unchanged while it runs.
    unsafe { rusty_libc_core::ffi::slice(ph, n) }
}

/// The FDE of `pc` from the sorted table of `.eh_frame_hdr` (binary search).
fn find_in_hdr(m: Mem, hdr: u64, pc: u64) -> Option<Fde> {
    let mut r = Reader { m, p: hdr };
    let version = r.u8();
    let ptr_enc = r.u8();
    let cnt_enc = r.u8();
    let tab_enc = r.u8();
    if version != 1 {
        return None;
    }
    let base = hdr;
    let _eh_frame = r.encoded(ptr_enc, base);
    let count = r.encoded(cnt_enc, base) as usize;
    if tab_enc != 0x3b {
        // only the common (datarel | sdata4) table is read; others fall back to scanning
        return None;
    }
    let table = r.p;
    // entry `i` of the table of (initial location, FDE address) pairs, each an sdata4 relative to the header
    let entry = |i: usize| base.wrapping_add(m.u32(table + 4 * i as u64) as i32 as i64 as u64);
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let loc = entry(mid * 2);
        if loc <= pc {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let fde = entry((lo - 1) * 2 + 1);
    parse_fde(m, fde, pc)
}

/// The start and size of `.eh_frame` in memory, found once (0 when it could not be found), and whether that search is done
/// (0: not yet, 1: a result is being stored, 2: stored).
static EH_FRAME: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_SIZE: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_STATE: AtomicU64 = AtomicU64::new(0);

const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;

/// Whether the bytes at `c` look like a CIE that ends at or before `hi`: a length that fits, id 0, version 1 or 3, and an
/// augmentation string that is empty or `z` followed by the letters gcc and LLVM write, ended inside the record.
fn cie_plausible(m: Mem, c: u64, hi: u64) -> bool {
    if c + 12 > hi {
        return false;
    }
    let len = m.u32(c) as u64;
    if len < 12 || len & 3 != 0 || c + 4 + len > hi || m.u32(c + 4) != 0 {
        return false;
    }
    let v = m.u8(c + 8);
    if v != 1 && v != 3 {
        return false;
    }
    let end = c + 4 + len;
    let mut q = c + 9;
    let first = m.u8(q);
    if first != 0 && first != b'z' {
        return false;
    }
    while q < end && m.u8(q) != 0 {
        if !matches!(m.u8(q), b'z' | b'L' | b'P' | b'R' | b'S' | b'B') {
            return false;
        }
        q += 1;
    }
    q < end
}

/// The FDE of the function at `target` in `[lo, hi)`: a record whose pc-relative 4-byte start address (the encoding gcc
/// and LLVM use, `DW_EH_PE_pcrel | DW_EH_PE_sdata4`) is exactly `target` and whose CIE pointer leads to a CIE of that
/// encoding.
fn find_anchor(m: Mem, lo: u64, hi: u64, target: u64) -> Option<u64> {
    // from the end down: the section is near the end of its segment, so few pages are touched
    if hi < lo + 12 {
        return None;
    }
    let mut p = lo + ((hi - 12 - lo) & !3);
    loop {
        let pcb = (p + 8).wrapping_add(m.u32(p + 8) as i32 as i64 as u64);
        if pcb == target {
            let id = m.u32(p + 4) as u64;
            let len = m.u32(p) as u64;
            let cie = (p + 4).wrapping_sub(id);
            if id != 0
                && len >= 12
                && p + 4 + len <= hi
                && cie >= lo
                && cie < p
                && (cie - lo) & 3 == 0
                && cie_plausible(m, cie, hi)
                && parse_cie(m, cie).is_some_and(|c| c.fde_enc == 0x1b)
            {
                return Some(p);
            }
        }
        if p < lo + 4 {
            return None;
        }
        p -= 4;
    }
}

/// An anonymous private mapping used as zero-filled scratch memory; unmapped when dropped.
struct Scratch {
    addr: usize,
    len: usize,
}

impl Scratch {
    /// mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0), or None when it fails.
    fn map(len: usize) -> Option<Scratch> {
        // SAFETY: a new anonymous mapping at an address the kernel picks: no existing memory is touched.
        let m = unsafe { rusty_libc_core::syscall::syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, len, 3, 0x22, usize::MAX, 0) };
        if m > usize::MAX - 4095 {
            return None;
        }
        Some(Scratch { addr: m, len })
    }

    /// The first `n` bytes (`n` at most the mapped length).
    fn bytes(&mut self, n: usize) -> &mut [u8] {
        assert!(n <= self.len);
        // SAFETY: the mapping is readable and writable, at least `n` bytes long, owned by `self` alone and unmapped only
        // when `self` is dropped, which the borrow of `self` rules out while the slice lives.
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, n) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // SAFETY: unmaps only the mapping `self` owns; no slice of it outlives `self`.
        unsafe { rusty_libc_core::syscall::syscall2(rusty_libc_core::syscall::SYS_MUNMAP, self.addr, self.len) };
    }
}

/// The extent of the `.eh_frame` section around the record at `a` inside `[lo, hi)`. Records follow each other (a 4-byte
/// length, then an id: 0 for a CIE, else the distance back to the FDE's CIE). Backwards from `a`, every position whose
/// record is well formed and ends exactly where a record that leads to `a` starts is marked; the section starts at the
/// first such position that is a CIE, from which every FDE up to `a` names a CIE of that chain and that some FDE names
/// (bytes before the section cannot pass all of that by chance); the marking stops 64 KiB below the lowest record. Forwards from `a`, records are followed while they are
/// well formed, up to the zero terminator, the end of the segment or the first record that is not frame information.
fn chain_around(m: Mem, lo: u64, hi: u64, a: u64) -> Option<(u64, u64)> {
    let words = ((hi - lo) / 4) as usize;
    let bytes = words.div_ceil(8);
    let maplen = (2 * bytes).div_ceil(4096) * 4096;
    let mut map = Scratch::map(maplen)?;
    let (good, cie) = map.bytes(2 * bytes).split_at_mut(bytes);
    let idx = |x: u64| ((x - lo) / 4) as usize;
    let get = |b: &[u8], x: u64| b[idx(x) / 8] & (1 << (idx(x) % 8)) != 0;
    let set = |b: &mut [u8], x: u64| b[idx(x) / 8] |= 1 << (idx(x) % 8);
    set(good, a);
    // records are far shorter than 64 KiB: no record of the section starts further below the lowest one found
    const REC_MAX: u64 = 1 << 16;
    let (mut c, mut lowest) = (a, a);
    while c > lo && lowest - c <= REC_MAX {
        c -= 4;
        let len = m.u32(c) as u64;
        if len < 12 || len & 3 != 0 {
            continue;
        }
        let e = c + 4 + len;
        if e > a || !get(good, e) {
            continue;
        }
        let id = m.u32(c + 4) as u64;
        if id == 0 {
            if !cie_plausible(m, c, e) {
                continue;
            }
            set(cie, c);
        } else {
            let t = (c + 4).wrapping_sub(id);
            if t < lo || t >= c || (t - lo) & 3 != 0 {
                continue;
            }
        }
        set(good, c);
        lowest = c;
    }
    let verify = |s: u64| {
        let (mut x, mut named) = (s, false);
        while x < a {
            let len = m.u32(x) as u64;
            let id = m.u32(x + 4) as u64;
            if id != 0 {
                let t = (x + 4).wrapping_sub(id);
                if t < s || !get(cie, t) {
                    return false;
                }
                named |= t == s;
            }
            x += 4 + len;
        }
        x == a && named
    };
    let mut start = None;
    let mut s = lowest;
    while s < a {
        let i = idx(s);
        if good[i / 8] == 0 {
            s = lo + ((i / 8 + 1) * 8 * 4) as u64;
            continue;
        }
        if get(good, s) && get(cie, s) && verify(s) {
            start = Some(s);
            break;
        }
        s += 4;
    }
    start.map(|start| {
        let mut x = a;
        while x + 8 <= hi {
            let len = m.u32(x) as u64;
            if len < 12 || len & 3 != 0 || x + 4 + len > hi {
                break; // the terminator (length 0), or no record
            }
            let id = m.u32(x + 4) as u64;
            if id == 0 {
                if !cie_plausible(m, x, hi) {
                    break;
                }
                set(cie, x);
            } else {
                let t = (x + 4).wrapping_sub(id);
                if t < start || t >= x || (t - lo) & 3 != 0 || !get(cie, t) {
                    break;
                }
            }
            x += 4 + len;
        }
        (start, x - start)
    })
    // `map` is unmapped here, after the result is computed (as before: mmap, the search, munmap)
}

/// `.eh_frame` of a static program without `.eh_frame_hdr`, from memory alone (no file is read: a chroot or a sandbox
/// without /proc works too). The section is not in any table the program keeps in memory, so it is found through a
/// record known to be in it: the FDE of `backtrace_impl` itself, looked for in the read-only loaded segments (AT_PHDR).
fn eh_frame_in_memory(m: Mem) -> Option<(u64, u64)> {
    let phs = program_headers();
    if phs.is_empty() {
        return None;
    }
    let bias = image().map_or(0, |(b, _, _)| b);
    let target = backtrace_impl as *const () as u64;
    // the last read-only segment first: the section follows the code and the read-only data
    for h in phs.iter().rev() {
        if h.p_type != PT_LOAD || h.p_flags & PF_W != 0 || h.p_filesz < 16 {
            continue;
        }
        let lo = (h.p_vaddr.wrapping_add(bias) + 3) & !3;
        let hi = lo + ((h.p_vaddr.wrapping_add(bias) + h.p_filesz - lo) & !3);
        if let Some(a) = find_anchor(m, lo, hi, target) {
            return chain_around(m, lo, hi, a);
        }
    }
    None
}

// Offsets in the ELF64 file header and section header (`Elf64_Ehdr`, `Elf64_Shdr`).
const EHDR_SIZE: usize = 64;
const E_SHOFF: usize = 40;
const E_SHENTSIZE: usize = 58;
const E_SHNUM: usize = 60;
const E_SHSTRNDX: usize = 62;
const SHDR_SIZE: usize = 64;
const SH_NAME: usize = 0;
const SH_ADDR: usize = 16;
const SH_OFFSET: usize = 24;
const SH_SIZE: usize = 32;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

/// pread(2) of all of `buf` (pread64, not a cancellation point), retried after short reads; false on error or end of file.
fn pread_all(fd: i32, buf: &mut [u8], off: u64) -> bool {
    let mut got = 0;
    while got < buf.len() {
        let rest = &mut buf[got..];
        // SAFETY: the kernel writes at most `rest.len()` bytes into `rest`.
        let r = unsafe { rusty_libc_core::syscall::syscall4(17, fd as usize, rest.as_mut_ptr() as usize, rest.len(), (off + got as u64) as usize) };
        if r > usize::MAX - 4095 || r == 0 {
            return false;
        }
        got += r;
    }
    true
}

/// `.eh_frame` through the section headers of the program's file (`/proc/self/exe`): used only when the search in
/// memory finds nothing.
fn eh_frame_from_file() -> Option<(u64, u64)> {
    // SAFETY: a NUL-terminated literal path.
    let fd = unsafe { rusty_libc_core::unistd::open(c"/proc/self/exe".as_ptr(), 0o2000000, 0) }.ok()?;
    let mut found = None;
    let mut eh = [0u8; EHDR_SIZE];
    let mut ok = pread_all(fd, &mut eh, 0) && &eh[..4] == b"\x7fELF" && le16(&eh, E_SHENTSIZE) as usize == SHDR_SIZE && le16(&eh, E_SHNUM) > 0 && le16(&eh, E_SHNUM) < 200;
    if ok {
        let mut sh = [0u8; 200 * SHDR_SIZE];
        let n = le16(&eh, E_SHNUM) as usize;
        let shs = &mut sh[..n * SHDR_SIZE];
        ok = pread_all(fd, shs, le64(&eh, E_SHOFF));
        let strndx = le16(&eh, E_SHSTRNDX) as usize;
        if ok && strndx < n {
            let strsec = &shs[strndx * SHDR_SIZE..][..SHDR_SIZE];
            let (str_size, str_off) = (le64(strsec, SH_SIZE), le64(strsec, SH_OFFSET));
            if str_size > 0 && str_size < 8192 {
                let mut names = [0u8; 8192];
                if pread_all(fd, &mut names[..str_size as usize], str_off) {
                    for s in shs.as_chunks::<SHDR_SIZE>().0 {
                        let nm = &names[le32(s, SH_NAME) as usize..];
                        let addr = le64(s, SH_ADDR);
                        if nm.starts_with(b".eh_frame\0") && addr != 0 {
                            found = Some((addr + image().map_or(0, |(b, _, _)| b), le64(s, SH_SIZE)));
                        }
                    }
                }
            }
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    found
}

/// `.eh_frame` of a program without a header table: looked for once and kept. A thread (or a signal handler) that comes
/// while another one is still looking looks for itself instead of waiting; every search finds the same.
fn eh_frame(m: Mem) -> Option<(u64, u64)> {
    if EH_FRAME_STATE.load(Ordering::Acquire) == 2 {
        let base = EH_FRAME.load(Ordering::Relaxed);
        return (base != 0).then(|| (base, EH_FRAME_SIZE.load(Ordering::Relaxed)));
    }
    let r = eh_frame_in_memory(m).or_else(eh_frame_from_file);
    if EH_FRAME_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        let (base, size) = r.unwrap_or((0, 0));
        EH_FRAME_SIZE.store(size, Ordering::Relaxed);
        EH_FRAME.store(base, Ordering::Relaxed);
        EH_FRAME_STATE.store(2, Ordering::Release);
    }
    r
}

/// The loader's `_dl_find_object` (`__libc_ldso_find_object`, a weak reference: None in a static program).
#[cfg(feature = "shared")]
fn ldso_find_object() -> Option<unsafe extern "C" fn(u64, *mut u64) -> c_int> {
    let f: usize;
    // SAFETY: reads the GOT slot of a weak symbol (0 when the loader did not define it); no memory is written.
    unsafe {
        core::arch::asm!(".weak __libc_ldso_find_object", "mov {0}, qword ptr [rip + __libc_ldso_find_object@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags))
    };
    if f == 0 {
        return None;
    }
    // SAFETY: a non-zero slot holds the address of the loader's function, which has this C signature.
    Some(unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u64, *mut u64) -> c_int>(f) })
}

/// The FDE covering `pc`: through the header table when the program has one, else by scanning `.eh_frame`.
fn find_fde(m: Mem, pc: u64) -> Option<Fde> {
    // under the dynamic loader the code may be in any loaded object: ask the loader which one and use its table
    #[cfg(feature = "shared")]
    {
        if let Some(find) = ldso_find_object() {
            // struct dl_find_object: flags, map_start, map_end, link_map, eh_frame (the .eh_frame_hdr), reserved
            let mut r = [0u64; 12];
            // SAFETY: `r` is larger than struct dl_find_object, which the loader fills.
            if unsafe { find(pc, r.as_mut_ptr()) } == 0 && r[4] != 0 {
                return find_in_hdr(m, r[4], pc);
            }
            return None;
        }
    }
    let bias = image().map_or(0, |(b, _, _)| b);
    for h in program_headers() {
        if h.p_type == PT_GNU_EH_FRAME
            && let Some(f) = find_in_hdr(m, h.p_vaddr.wrapping_add(bias), pc)
        {
            return Some(f);
        }
    }
    let (base, size) = eh_frame(m)?;
    let mut p = base;
    let end = base + size;
    while p < end {
        let (len, hdr) = record_len(m, p)?;
        if let Some(f) = parse_fde(m, p, pc) {
            return Some(f);
        }
        p = p.wrapping_add((hdr + len) as u64);
    }
    None
}

// ------------------------------------------------------------------ executing the call frame information

/// The registers that are tracked: rax..r15 by DWARF number (0..16) and the return address (16).
#[derive(Clone, Copy)]
struct Regs {
    r: [u64; 17],
}

const RBX: usize = 3;
const RBP: usize = 6;
const RSP: usize = 7;
const RA: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum Rule {
    Same,
    Undefined,
    /// saved at CFA + n
    Offset(i64),
    /// the value is CFA + n
    ValOffset(i64),
    Register(u8),
    /// saved at the address computed by the expression (pointer, length)
    Expr(u64, usize),
    ValExpr(u64, usize),
}

#[derive(Clone, Copy)]
enum CfaRule {
    RegOff(usize, i64),
    Expr(u64, usize),
}

#[derive(Clone, Copy)]
struct Frame {
    cfa: CfaRule,
    rules: [Rule; 17],
}

/// Evaluate a DWARF expression over the registers (for CFA and register rules); `initial` is pushed first.
fn eval_expr(m: Mem, p: u64, len: usize, regs: &Regs, initial: Option<u64>) -> Option<u64> {
    {
        let mut r = Reader { m, p };
        let end = p.wrapping_add(len as u64);
        let mut st = [0u64; 32];
        let mut sp = 0usize;
        if let Some(v) = initial {
            st[0] = v;
            sp = 1;
        }
        macro_rules! push {
            ($v:expr) => {{
                if sp >= 32 {
                    return None;
                }
                st[sp] = $v;
                sp += 1;
            }};
        }
        macro_rules! pop {
            () => {{
                if sp == 0 {
                    return None;
                }
                sp -= 1;
                st[sp]
            }};
        }
        while r.p < end {
            let op = r.u8();
            match op {
                0x30..=0x4f => push!((op - 0x30) as u64),
                0x70..=0x8f => {
                    let reg = (op - 0x70) as usize;
                    let off = r.sleb();
                    if reg > 16 {
                        return None;
                    }
                    push!(regs.r[reg].wrapping_add(off as u64));
                }
                0x08 => push!(r.u8() as u64),
                0x09 => push!(r.u8() as i8 as i64 as u64),
                0x0a => push!(r.u16() as u64),
                0x0b => push!(r.u16() as i16 as i64 as u64),
                0x0c => push!(r.u32() as u64),
                0x0d => push!(r.u32() as i32 as i64 as u64),
                0x0e | 0x0f => push!(r.u64()),
                0x10 => push!(r.uleb()),
                0x11 => push!(r.sleb() as u64),
                0x12 => {
                    let v = pop!();
                    push!(v);
                    push!(v);
                }
                0x13 => {
                    pop!();
                }
                0x16 => {
                    let a = pop!();
                    let b = pop!();
                    push!(a);
                    push!(b);
                }
                0x06 => {
                    let a = pop!();
                    push!(m.u64(a));
                }
                0x1a => {
                    let (b, a) = (pop!(), pop!());
                    push!(a & b);
                }
                0x21 => {
                    let (b, a) = (pop!(), pop!());
                    push!(a | b);
                }
                0x22 => {
                    let (b, a) = (pop!(), pop!());
                    push!(a.wrapping_add(b));
                }
                0x1c => {
                    let (b, a) = (pop!(), pop!());
                    push!(a.wrapping_sub(b));
                }
                0x23 => {
                    let a = pop!();
                    push!(a.wrapping_add(r.uleb()));
                }
                0x24 => {
                    let (b, a) = (pop!(), pop!());
                    push!(a.wrapping_shl(b as u32));
                }
                0x25 => {
                    let (b, a) = (pop!(), pop!());
                    push!(a.wrapping_shr(b as u32));
                }
                0x29 => {
                    let (b, a) = (pop!(), pop!());
                    push!((a == b) as u64);
                }
                0x2a => {
                    let (b, a) = (pop!(), pop!());
                    push!(((a as i64) >= (b as i64)) as u64);
                }
                0x2b => {
                    let (b, a) = (pop!(), pop!());
                    push!(((a as i64) > (b as i64)) as u64);
                }
                0x2c => {
                    let (b, a) = (pop!(), pop!());
                    push!(((a as i64) <= (b as i64)) as u64);
                }
                0x2d => {
                    let (b, a) = (pop!(), pop!());
                    push!(((a as i64) < (b as i64)) as u64);
                }
                0x2e => {
                    let (b, a) = (pop!(), pop!());
                    push!((a != b) as u64);
                }
                _ => return None,
            }
        }
        if sp == 0 { None } else { Some(st[sp - 1]) }
    }
}

/// Run the instructions of `[p, end)` up to the location `pc` (`loc` is where the table starts).
#[allow(clippy::too_many_arguments)]
fn run_cfa(m: Mem, cie: &Cie, p: u64, end: u64, mut loc: u64, pc: u64, f: &mut Frame, initial: &Frame) {
    {
        let mut r = Reader { m, p };
        let mut stack: [Frame; 8] = [*f; 8];
        let mut depth = 0usize;
        while r.p < end {
            let op = r.u8();
            match op >> 6 {
                1 => {
                    loc += (op & 0x3f) as u64 * cie.code_align;
                    if loc > pc {
                        return;
                    }
                    continue;
                }
                2 => {
                    let reg = (op & 0x3f) as usize;
                    let off = r.uleb() as i64 * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::Offset(off);
                    }
                    continue;
                }
                3 => {
                    let reg = (op & 0x3f) as usize;
                    if reg < 17 {
                        f.rules[reg] = initial.rules[reg];
                    }
                    continue;
                }
                _ => {}
            }
            match op {
                0x00 => {}
                0x01 => {
                    loc = r.u64();
                    if loc > pc {
                        return;
                    }
                }
                0x02 => {
                    loc += r.u8() as u64 * cie.code_align;
                    if loc > pc {
                        return;
                    }
                }
                0x03 => {
                    loc += r.u16() as u64 * cie.code_align;
                    if loc > pc {
                        return;
                    }
                }
                0x04 => {
                    loc += r.u32() as u64 * cie.code_align;
                    if loc > pc {
                        return;
                    }
                }
                0x05 => {
                    let reg = r.uleb() as usize;
                    let off = r.uleb() as i64 * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::Offset(off);
                    }
                }
                0x06 => {
                    let reg = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = initial.rules[reg];
                    }
                }
                0x07 => {
                    let reg = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = Rule::Undefined;
                    }
                }
                0x08 => {
                    let reg = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = Rule::Same;
                    }
                }
                0x09 => {
                    let reg = r.uleb() as usize;
                    let other = r.uleb() as u8;
                    if reg < 17 {
                        f.rules[reg] = Rule::Register(other);
                    }
                }
                0x0a => {
                    if depth < 8 {
                        stack[depth] = *f;
                        depth += 1;
                    }
                }
                0x0b => {
                    if depth > 0 {
                        depth -= 1;
                        let saved_cfa = f.cfa;
                        *f = stack[depth];
                        let _ = saved_cfa;
                    }
                }
                0x0c => {
                    let reg = r.uleb() as usize;
                    let off = r.uleb() as i64;
                    f.cfa = CfaRule::RegOff(reg, off);
                }
                0x0d => {
                    let reg = r.uleb() as usize;
                    if let CfaRule::RegOff(_, off) = f.cfa {
                        f.cfa = CfaRule::RegOff(reg, off);
                    } else {
                        f.cfa = CfaRule::RegOff(reg, 0);
                    }
                }
                0x0e => {
                    let off = r.uleb() as i64;
                    if let CfaRule::RegOff(reg, _) = f.cfa {
                        f.cfa = CfaRule::RegOff(reg, off);
                    }
                }
                0x0f => {
                    let len = r.uleb() as usize;
                    f.cfa = CfaRule::Expr(r.p, len);
                    r.p = r.p.wrapping_add(len as u64);
                }
                0x10 => {
                    let reg = r.uleb() as usize;
                    let len = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = Rule::Expr(r.p, len);
                    }
                    r.p = r.p.wrapping_add(len as u64);
                }
                0x11 => {
                    let reg = r.uleb() as usize;
                    let off = r.sleb() * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::Offset(off);
                    }
                }
                0x12 => {
                    let reg = r.uleb() as usize;
                    let off = r.sleb() * cie.data_align;
                    f.cfa = CfaRule::RegOff(reg, off);
                }
                0x13 => {
                    let off = r.sleb() * cie.data_align;
                    if let CfaRule::RegOff(reg, _) = f.cfa {
                        f.cfa = CfaRule::RegOff(reg, off);
                    }
                }
                0x14 => {
                    let reg = r.uleb() as usize;
                    let off = r.uleb() as i64 * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::ValOffset(off);
                    }
                }
                0x15 => {
                    let reg = r.uleb() as usize;
                    let off = r.sleb() * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::ValOffset(off);
                    }
                }
                0x16 => {
                    let reg = r.uleb() as usize;
                    let len = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = Rule::ValExpr(r.p, len);
                    }
                    r.p = r.p.wrapping_add(len as u64);
                }
                0x2e => {
                    r.uleb(); // DW_CFA_GNU_args_size
                }
                0x2f => {
                    let reg = r.uleb() as usize;
                    let off = -(r.uleb() as i64) * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::Offset(off);
                    }
                }
                _ => return, // unknown instruction: stop here
            }
        }
    }
}

/// The caller's registers from the context of one frame, or None at the end of the stack.
fn step(m: Mem, regs: &Regs, lookup_pc: u64) -> Option<(Regs, bool)> {
    {
        let fde = find_fde(m, lookup_pc)?;
        let blank = Frame { cfa: CfaRule::RegOff(RSP, 8), rules: [Rule::Same; 17] };
        let mut initial = blank;
        // return address column: saved at CFA - 8 unless the table says otherwise (it always does)
        run_cfa(m, &fde.cie, fde.cie.insns, fde.cie.insns_end, fde.start, u64::MAX, &mut initial, &blank);
        let mut f = initial;
        run_cfa(m, &fde.cie, fde.insns, fde.insns_end, fde.start, lookup_pc, &mut f, &initial);
        let cfa = match f.cfa {
            CfaRule::RegOff(reg, off) => {
                if reg > 16 {
                    return None;
                }
                regs.r[reg].wrapping_add(off as u64)
            }
            CfaRule::Expr(p, len) => eval_expr(m, p, len, regs, None)?,
        };
        let mut out = *regs;
        for reg in 0..17 {
            let rule = f.rules[reg];
            let v = match rule {
                Rule::Same => regs.r[reg],
                Rule::Undefined => {
                    if reg == RA {
                        return None;
                    }
                    regs.r[reg]
                }
                Rule::Offset(n) => m.u64((cfa as i64 + n) as u64),
                Rule::ValOffset(n) => (cfa as i64 + n) as u64,
                Rule::Register(o) => regs.r[(o as usize).min(16)],
                Rule::Expr(p, len) => m.u64(eval_expr(m, p, len, regs, Some(cfa))?),
                Rule::ValExpr(p, len) => eval_expr(m, p, len, regs, Some(cfa))?,
            };
            out.r[reg] = v;
        }
        // the return address column is the register `ra_reg` (16 on x86-64); without a rule it is lost
        if matches!(f.rules[RA], Rule::Same) {
            return None;
        }
        out.r[RSP] = cfa;
        Some((out, fde.cie.signal))
    }
}

/// Whether `pc` is the signal return trampoline (`mov rax, 15; syscall`).
fn is_sigreturn(m: Mem, pc: u64) -> bool {
    let a = m.bytes(pc, 9);
    a == b"\x48\xc7\xc0\x0f\x00\x00\x00\x0f\x05" || &a[..7] == b"\xb8\x0f\x00\x00\x00\x0f\x05"
}

/// The registers of the interrupted code from the `ucontext` the trampoline's stack pointer addresses.
fn from_ucontext(m: Mem, regs: &Regs) -> Regs {
    let uc = regs.r[RSP];
    // ucontext: flags, link, stack_t (3 words), then gregs: r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip
    let g = |i: u64| m.u64(uc + 8 * (5 + i));
    let mut out = *regs;
    out.r[12] = g(4);
    out.r[13] = g(5);
    out.r[14] = g(6);
    out.r[15] = g(7);
    out.r[RBP] = g(10);
    out.r[RBX] = g(11);
    out.r[RSP] = g(15);
    out.r[RA] = g(16);
    out
}

/// The walk: fill `buf` with the return addresses from `first` (the first frame's context) on.
fn walk(m: Mem, buf: &mut [*mut c_void], first: Regs) -> c_int {
    {
        let size = buf.len();
        let mut regs = first;
        let mut count = 0;
        // the pc of the first frame is a return address; after a signal frame it is exact
        let mut exact = false;
        while count < size {
            let pc = regs.r[RA];
            if pc == 0 {
                break;
            }
            buf[count] = pc as *mut c_void;
            count += 1;
            if is_sigreturn(m, pc) {
                // the saved context of the interrupted code
                regs = from_ucontext(m, &regs);
                exact = true;
                continue;
            }
            let lookup = if exact { pc } else { pc - 1 };
            match step(m, &regs, lookup) {
                Some((next, _signal)) => {
                    // the stack grows down: a frame whose caller is not above it ends the walk
                    if next.r[RSP] <= regs.r[RSP] {
                        break;
                    }
                    regs = next;
                    exact = false;
                }
                None => break,
            }
        }
        count as c_int
    }
}

/// The part of `backtrace` written in Rust; `saved` is rbp, rbx, r12-r15 and the return address as the
/// assembly front end left them on the stack.
///
/// # Safety
/// `buf` has room for `size` pointers (C's `backtrace` contract); `saved` is the block the front end pushed.
unsafe extern "C" fn backtrace_impl(buf: *mut *mut c_void, size: c_int, saved: *const u64) -> c_int {
    // SAFETY: the caller of `backtrace` gives room for `size` pointers; nothing else uses the buffer during the call.
    let out = unsafe { rusty_libc_core::ffi::slice_mut(buf, size.max(0) as usize) };
    // SAFETY: from here on only the calling thread's stack (starting at the front end's own block) and the frame
    // information and code of the loaded objects are read.
    let m = unsafe { Mem::trusted() };
    let s = saved as u64;
    let mut regs = Regs { r: [0; 17] };
    regs.r[RBP] = m.u64(s);
    regs.r[RBX] = m.u64(s + 8);
    regs.r[12] = m.u64(s + 16);
    regs.r[13] = m.u64(s + 24);
    regs.r[14] = m.u64(s + 32);
    regs.r[15] = m.u64(s + 40);
    regs.r[RA] = m.u64(s + 48);
    regs.r[RSP] = s + 56;
    walk(m, out, regs)
}

/// backtrace: the return addresses of the calling thread's stack, innermost first, into `buffer` (at most
/// `size`); the count.
///
/// # Safety
/// `buffer` has room for `size` pointers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn backtrace(_buffer: *mut *mut c_void, _size: c_int) -> c_int {
    // push the callee-saved registers as the caller left them (the unwinder starts from the caller's
    // frame), pass the block to the Rust part, and pop it again
    core::arch::naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push rbx",
        "push rbp",
        "mov rdx, rsp",
        "sub rsp, 8",
        "call {imp}",
        "add rsp, 8",
        "add rsp, 48",
        "ret",
        imp = sym backtrace_impl,
    )
}

/// `__backtrace`, the exported internal name.
///
/// # Safety
/// As `backtrace`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __backtrace(_buffer: *mut *mut c_void, _size: c_int) -> c_int {
    core::arch::naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push rbx",
        "push rbp",
        "mov rdx, rsp",
        "sub rsp, 8",
        "call {imp}",
        "add rsp, 8",
        "add rsp, 48",
        "ret",
        imp = sym backtrace_impl,
    )
}

// ------------------------------------------------------------------ symbols

/// glibc's `backtrace_symbols` line for a loaded object, using the loader's dladdr: `FILE(SYMBOL+0xOFF) [ADDR]`,
/// `FILE(+0xOFF) [ADDR]` when the object has no symbol for the address. Returns (file name, symbol name, base, address).
#[cfg(feature = "shared")]
fn describe_loaded(addr: u64) -> Option<(&'static CStr, Option<&'static CStr>, u64, u64)> {
    let f: usize;
    // SAFETY: reads the GOT slot of a weak symbol (0 when the loader did not define it); no memory is written.
    unsafe {
        core::arch::asm!(".weak __libc_ldso_dladdr1", "mov {0}, qword ptr [rip + __libc_ldso_dladdr1@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags))
    };
    if f == 0 {
        return None;
    }
    let mut info = [0u64; 4];
    let mut map: u64 = 0;
    // SAFETY: a non-zero slot holds the address of the loader's dladdr1, which has this C signature.
    let dladdr1 = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u64, *mut u64, *mut u64, c_int) -> c_int>(f) };
    // SAFETY: `info` has room for a Dl_info, `map` for the link_map pointer RTLD_DL_LINKMAP stores.
    if unsafe { dladdr1(addr, info.as_mut_ptr(), &mut map, 2 /* RTLD_DL_LINKMAP */) } == 0 {
        return None;
    }
    // Dl_info: fname, fbase, sname, saddr. Without a symbol the address is described relative to the object's load
    // bias (struct link_map's first field), which is zero for a program that is not position independent
    let base = if info[2] == 0 {
        // SAFETY: on success `map` is the loader's link_map of the object, alive while the object is loaded; l_addr is
        // its first field.
        unsafe { (map as *const u64).read() }
    } else {
        info[3]
    };
    // SAFETY: on success dli_fname is the object's NUL-terminated name, kept by the loader while the object is loaded.
    let fname = unsafe { rusty_libc_core::ffi::cstr_nonnull(info[0] as *const c_char) };
    // SAFETY: dli_sname is NULL or the symbol's NUL-terminated name in the object's string table.
    let sname = unsafe { rusty_libc_core::ffi::cstr(info[2] as *const c_char) };
    Some((fname, sname, base, addr))
}

/// One line of backtrace_symbols into `out` (no NUL needed by callers: the length is returned).
fn format_line(out: &mut [u8], addr: *mut c_void, with_nl: bool) -> usize {
    use rusty_libc_stdio::rust_api::{Arg, snprintf};
    let mut tmp = [0u8; 4400];
    let line: &mut [u8] = &mut tmp;
    #[cfg(feature = "shared")]
    let n = match describe_loaded(addr as u64) {
        Some((f, None, 0, _)) => {
            // nothing to be relative to: glibc prints empty parentheses
            let fmt = if with_nl { c"%s() [%p]\n" } else { c"%s() [%p]" };
            snprintf(line, fmt, &[Arg::Str(f), Arg::Ptr(addr as *const c_void)])
        }
        Some((f, sname, base, a)) => {
            let sn = sname.unwrap_or(c"");
            let (sign, off) = if a >= base { (b'+', a - base) } else { (b'-', base - a) };
            let fmt = if with_nl { c"%s(%s%c%#lx) [%p]\n" } else { c"%s(%s%c%#lx) [%p]" };
            snprintf(line, fmt, &[Arg::Str(f), Arg::Str(sn), Arg::Int(sign as i64), Arg::Uint(off), Arg::Ptr(addr as *const c_void)])
        }
        None => snprintf(line, if with_nl { c"[%p]\n" } else { c"[%p]" }, &[Arg::Ptr(addr as *const c_void)]),
    };
    // a static program: glibc's static dladdr finds no object for any address, so every line is just the address
    #[cfg(not(feature = "shared"))]
    let n = snprintf(line, if with_nl { c"[%p]\n" } else { c"[%p]" }, &[Arg::Ptr(addr as *const c_void)]);
    let n = (n.max(0) as usize).min(line.len() - 1).min(out.len());
    out[..n].copy_from_slice(&line[..n]);
    n
}

/// The total size of the backtrace_symbols block for `addrs`: the pointer array and every line with its NUL.
fn symbols_size(addrs: &[*mut c_void]) -> usize {
    let mut scratch = [0u8; 4400];
    let total: usize = addrs.iter().map(|&a| format_line(&mut scratch, a, false) + 1).sum();
    addrs.len() * size_of::<*mut c_char>() + total
}

/// Fill a backtrace_symbols block: `ptrs` (one per address) point to the lines written one after another into `text`.
fn symbols_fill(addrs: &[*mut c_void], ptrs: &mut [*mut c_char], text: &mut [u8]) {
    let mut scratch = [0u8; 4400];
    let mut at = 0;
    for (p, &a) in ptrs.iter_mut().zip(addrs) {
        let n = format_line(&mut scratch, a, false);
        let dst = &mut text[at..at + n + 1];
        dst[..n].copy_from_slice(&scratch[..n]);
        dst[n] = 0;
        *p = dst.as_mut_ptr().cast();
        at += n + 1;
    }
}

/// backtrace_symbols: a malloc'd array of strings describing the addresses (one block: free it with
/// one `free`). NULL when out of memory.
///
/// # Safety
/// `buffer` holds `size` addresses.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    let size = size.max(0) as usize;
    // SAFETY: the caller's buffer holds `size` addresses.
    let addrs = unsafe { rusty_libc_core::ffi::slice(buffer, size) };
    // first pass: the lengths
    let total = symbols_size(addrs);
    // SAFETY: malloc takes a plain size.
    let result = unsafe { rusty_libc_malloc::malloc(total) } as *mut *mut c_char;
    if result.is_null() {
        return null_mut();
    }
    // SAFETY: the new block holds `size` pointers (malloc's alignment suits them) ...
    let ptrs = unsafe { rusty_libc_core::ffi::slice_mut(result, size) };
    let text_len = total - size * size_of::<*mut c_char>();
    // SAFETY: ... followed by `text_len` bytes for the lines; the two parts do not overlap and nothing else uses the block.
    let text = unsafe { rusty_libc_core::ffi::bytes_mut(result.cast::<u8>().wrapping_add(size * size_of::<*mut c_char>()), text_len) };
    symbols_fill(addrs, ptrs, text);
    result
}

/// `__backtrace_symbols`.
///
/// # Safety
/// As `backtrace_symbols`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { backtrace_symbols(buffer, size) }
}

/// The lines of backtrace_symbols_fd written to `fd` (one write per line, not a cancellation point).
pub fn symbols_to_fd(addrs: &[*mut c_void], fd: c_int) {
    let mut line = [0u8; 4400];
    for &a in addrs {
        let n = format_line(&mut line, a, true);
        let _ = rusty_libc_core::unistd::write_nocancel(fd, &line[..n]);
    }
}

/// backtrace_symbols_fd: the same descriptions, one line each, written to `fd` (nothing is allocated).
///
/// # Safety
/// `buffer` holds `size` addresses.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    // SAFETY: the caller's buffer holds `size` addresses.
    symbols_to_fd(unsafe { rusty_libc_core::ffi::slice(buffer, size.max(0) as usize) }, fd)
}

/// `__backtrace_symbols_fd`.
///
/// # Safety
/// As `backtrace_symbols_fd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    // SAFETY: forwarded contract.
    unsafe { backtrace_symbols_fd(buffer, size, fd) }
}
