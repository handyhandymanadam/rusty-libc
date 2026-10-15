#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::dlfcn::image;
use core::ffi::{c_char, c_int, c_void};
#[cfg(feature = "shared")]
use core::ffi::CStr;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
struct Mem(());

impl Mem {
    #[inline(always)]
    unsafe fn trusted() -> Mem {
        Mem(())
    }

    #[inline(always)]
    fn u8(self, a: u64) -> u8 {
        unsafe { (a as *const u8).read() }
    }

    #[inline(always)]
    fn u16(self, a: u64) -> u16 {
        unsafe { (a as *const u16).read_unaligned() }
    }

    #[inline(always)]
    fn u32(self, a: u64) -> u32 {
        unsafe { (a as *const u32).read_unaligned() }
    }

    #[inline(always)]
    fn u64(self, a: u64) -> u64 {
        unsafe { (a as *const u64).read_unaligned() }
    }

    #[inline(always)]
    fn bytes(self, a: u64, n: usize) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(a as *const u8, n) }
    }
}

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

struct Fde {
    cie: Cie,
    start: u64,
    #[allow(dead_code)]
    end: u64,
    insns: u64,
    insns_end: u64,
}

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
    let aug = r.p;
    while r.u8() != 0 {}
    let aug_len = (r.p - aug) as usize - 1;
    let aug = m.bytes(aug, aug_len);
    if version >= 4 {
        r.u8();
        r.u8();
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

fn parse_fde(m: Mem, p: u64, pc: u64) -> Option<Fde> {
    let (len, hdr) = record_len(m, p)?;
    let end = p.wrapping_add((hdr + len) as u64);
    let idp = p + hdr as u64;
    let id = m.u32(idp);
    if id == 0 {
        return None;
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

fn program_headers() -> &'static [Phdr] {
    let ph = unsafe { rusty_libc_util::auxv::getauxval(AT_PHDR) } as *const Phdr;
    let n = unsafe { rusty_libc_util::auxv::getauxval(AT_PHNUM) } as usize;
    if ph.is_null() {
        return &[];
    }
    unsafe { rusty_libc_core::ffi::slice(ph, n) }
}

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
        return None;
    }
    let table = r.p;
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

static EH_FRAME: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_SIZE: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_STATE: AtomicU64 = AtomicU64::new(0);

const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;

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

fn find_anchor(m: Mem, lo: u64, hi: u64, target: u64) -> Option<u64> {
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

struct Scratch {
    addr: usize,
    len: usize,
}

impl Scratch {
    fn map(len: usize) -> Option<Scratch> {
        let m = unsafe { rusty_libc_core::syscall::syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, len, 3, 0x22, usize::MAX, 0) };
        if m > usize::MAX - 4095 {
            return None;
        }
        Some(Scratch { addr: m, len })
    }

    fn bytes(&mut self, n: usize) -> &mut [u8] {
        assert!(n <= self.len);
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, n) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        unsafe { rusty_libc_core::syscall::syscall2(rusty_libc_core::syscall::SYS_MUNMAP, self.addr, self.len) };
    }
}

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
                break;
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
}

fn eh_frame_in_memory(m: Mem) -> Option<(u64, u64)> {
    let phs = program_headers();
    if phs.is_empty() {
        return None;
    }
    let bias = image().map_or(0, |(b, _, _)| b);
    let target = backtrace_impl as *const () as u64;
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

fn pread_all(fd: i32, buf: &mut [u8], off: u64) -> bool {
    let mut got = 0;
    while got < buf.len() {
        let rest = &mut buf[got..];
        let r = unsafe { rusty_libc_core::syscall::syscall4(17, fd as usize, rest.as_mut_ptr() as usize, rest.len(), (off + got as u64) as usize) };
        if r > usize::MAX - 4095 || r == 0 {
            return false;
        }
        got += r;
    }
    true
}

fn eh_frame_from_file() -> Option<(u64, u64)> {
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

#[cfg(feature = "shared")]
fn ldso_find_object() -> Option<unsafe extern "C" fn(u64, *mut u64) -> c_int> {
    let f: usize;
    unsafe {
        core::arch::asm!(".weak __libc_ldso_find_object", "mov {0}, qword ptr [rip + __libc_ldso_find_object@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags))
    };
    if f == 0 {
        return None;
    }
    Some(unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u64, *mut u64) -> c_int>(f) })
}

fn find_fde(m: Mem, pc: u64) -> Option<Fde> {
    #[cfg(feature = "shared")]
    {
        if let Some(find) = ldso_find_object() {
            let mut r = [0u64; 12];
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
    Offset(i64),
    ValOffset(i64),
    Register(u8),
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
                    r.uleb();
                }
                0x2f => {
                    let reg = r.uleb() as usize;
                    let off = -(r.uleb() as i64) * cie.data_align;
                    if reg < 17 {
                        f.rules[reg] = Rule::Offset(off);
                    }
                }
                _ => return,
            }
        }
    }
}

fn step(m: Mem, regs: &Regs, lookup_pc: u64) -> Option<(Regs, bool)> {
    {
        let fde = find_fde(m, lookup_pc)?;
        let blank = Frame { cfa: CfaRule::RegOff(RSP, 8), rules: [Rule::Same; 17] };
        let mut initial = blank;
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
        if matches!(f.rules[RA], Rule::Same) {
            return None;
        }
        out.r[RSP] = cfa;
        Some((out, fde.cie.signal))
    }
}

fn is_sigreturn(m: Mem, pc: u64) -> bool {
    let a = m.bytes(pc, 9);
    a == b"\x48\xc7\xc0\x0f\x00\x00\x00\x0f\x05" || &a[..7] == b"\xb8\x0f\x00\x00\x00\x0f\x05"
}

fn from_ucontext(m: Mem, regs: &Regs) -> Regs {
    let uc = regs.r[RSP];
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

fn walk(m: Mem, buf: &mut [*mut c_void], first: Regs) -> c_int {
    {
        let size = buf.len();
        let mut regs = first;
        let mut count = 0;
        let mut exact = false;
        while count < size {
            let pc = regs.r[RA];
            if pc == 0 {
                break;
            }
            buf[count] = pc as *mut c_void;
            count += 1;
            if is_sigreturn(m, pc) {
                regs = from_ucontext(m, &regs);
                exact = true;
                continue;
            }
            let lookup = if exact { pc } else { pc - 1 };
            match step(m, &regs, lookup) {
                Some((next, _signal)) => {
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

unsafe extern "C" fn backtrace_impl(buf: *mut *mut c_void, size: c_int, saved: *const u64) -> c_int {
    let out = unsafe { rusty_libc_core::ffi::slice_mut(buf, size.max(0) as usize) };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn backtrace(_buffer: *mut *mut c_void, _size: c_int) -> c_int {
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

#[cfg(feature = "shared")]
fn describe_loaded(addr: u64) -> Option<(&'static CStr, Option<&'static CStr>, u64, u64)> {
    let f: usize;
    unsafe {
        core::arch::asm!(".weak __libc_ldso_dladdr1", "mov {0}, qword ptr [rip + __libc_ldso_dladdr1@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags))
    };
    if f == 0 {
        return None;
    }
    let mut info = [0u64; 4];
    let mut map: u64 = 0;
    let dladdr1 = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(u64, *mut u64, *mut u64, c_int) -> c_int>(f) };
    if unsafe { dladdr1(addr, info.as_mut_ptr(), &mut map, 2 ) } == 0 {
        return None;
    }
    let base = if info[2] == 0 {
        unsafe { (map as *const u64).read() }
    } else {
        info[3]
    };
    let fname = unsafe { rusty_libc_core::ffi::cstr_nonnull(info[0] as *const c_char) };
    let sname = unsafe { rusty_libc_core::ffi::cstr(info[2] as *const c_char) };
    Some((fname, sname, base, addr))
}

fn format_line(out: &mut [u8], addr: *mut c_void, with_nl: bool) -> usize {
    use rusty_libc_stdio::rust_api::{Arg, snprintf};
    let mut tmp = [0u8; 4400];
    let line: &mut [u8] = &mut tmp;
    #[cfg(feature = "shared")]
    let n = match describe_loaded(addr as u64) {
        Some((f, None, 0, _)) => {
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
    #[cfg(not(feature = "shared"))]
    let n = snprintf(line, if with_nl { c"[%p]\n" } else { c"[%p]" }, &[Arg::Ptr(addr as *const c_void)]);
    let n = (n.max(0) as usize).min(line.len() - 1).min(out.len());
    out[..n].copy_from_slice(&line[..n]);
    n
}

fn symbols_size(addrs: &[*mut c_void]) -> usize {
    let mut scratch = [0u8; 4400];
    let total: usize = addrs.iter().map(|&a| format_line(&mut scratch, a, false) + 1).sum();
    addrs.len() * size_of::<*mut c_char>() + total
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    let size = size.max(0) as usize;
    let addrs = unsafe { rusty_libc_core::ffi::slice(buffer, size) };
    let total = symbols_size(addrs);
    let result = unsafe { rusty_libc_malloc::malloc(total) } as *mut *mut c_char;
    if result.is_null() {
        return null_mut();
    }
    let ptrs = unsafe { rusty_libc_core::ffi::slice_mut(result, size) };
    let text_len = total - size * size_of::<*mut c_char>();
    let text = unsafe { rusty_libc_core::ffi::bytes_mut(result.cast::<u8>().wrapping_add(size * size_of::<*mut c_char>()), text_len) };
    symbols_fill(addrs, ptrs, text);
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    unsafe { backtrace_symbols(buffer, size) }
}

pub fn symbols_to_fd(addrs: &[*mut c_void], fd: c_int) {
    let mut line = [0u8; 4400];
    for &a in addrs {
        let n = format_line(&mut line, a, true);
        let _ = rusty_libc_core::unistd::write_nocancel(fd, &line[..n]);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    symbols_to_fd(unsafe { rusty_libc_core::ffi::slice(buffer, size.max(0) as usize) }, fd)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    unsafe { backtrace_symbols_fd(buffer, size, fd) }
}
