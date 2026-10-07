use crate::dlfcn::image;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

struct Reader {
    p: *const u8,
}

impl Reader {
    unsafe fn u8(&mut self) -> u8 {
        unsafe {
            let v = *self.p;
            self.p = self.p.add(1);
            v
        }
    }
    unsafe fn u16(&mut self) -> u16 {
        unsafe {
            let v = (self.p as *const u16).read_unaligned();
            self.p = self.p.add(2);
            v
        }
    }
    unsafe fn u32(&mut self) -> u32 {
        unsafe {
            let v = (self.p as *const u32).read_unaligned();
            self.p = self.p.add(4);
            v
        }
    }
    unsafe fn u64(&mut self) -> u64 {
        unsafe {
            let v = (self.p as *const u64).read_unaligned();
            self.p = self.p.add(8);
            v
        }
    }
    unsafe fn uleb(&mut self) -> u64 {
        unsafe {
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
    }
    unsafe fn sleb(&mut self) -> i64 {
        unsafe {
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
    }
    unsafe fn encoded(&mut self, enc: u8, datarel_base: u64) -> u64 {
        unsafe {
            if enc == 0xff {
                return 0;
            }
            let here = self.p as u64;
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
                v = (v as *const u64).read_unaligned();
            }
            v
        }
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
    insns: *const u8,
    insns_end: *const u8,
}

struct Fde {
    cie: Cie,
    start: u64,
    #[allow(dead_code)]
    end: u64,
    insns: *const u8,
    insns_end: *const u8,
}

unsafe fn record_len(p: *const u8) -> Option<(usize, usize)> {
    unsafe {
        let l = (p as *const u32).read_unaligned();
        if l == 0 {
            return None;
        }
        if l == 0xffff_ffff {
            let l64 = (p.add(4) as *const u64).read_unaligned();
            return Some((l64 as usize, 12));
        }
        Some((l as usize, 4))
    }
}

unsafe fn parse_cie(p: *const u8) -> Option<Cie> {
    unsafe {
        let (len, hdr) = record_len(p)?;
        let end = p.add(hdr + len);
        let mut r = Reader { p: p.add(hdr) };
        let id = r.u32();
        if id != 0 {
            return None;
        }
        let version = r.u8();
        let aug = r.p;
        while r.u8() != 0 {}
        let aug_len = r.p.offset_from(aug) as usize - 1;
        let aug = core::slice::from_raw_parts(aug, aug_len);
        if version >= 4 {
            r.u8();
            r.u8();
        }
        let code_align = r.uleb();
        let data_align = r.sleb();
        let ra_reg = if version == 1 { r.u8() as u64 } else { r.uleb() };
        let mut cie = Cie { code_align, data_align, ra_reg, fde_enc: 0, signal: false, has_z: false, insns: core::ptr::null(), insns_end: end };
        if aug.first() == Some(&b'z') {
            cie.has_z = true;
            let alen = r.uleb() as usize;
            let after = r.p.add(alen);
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
}

unsafe fn parse_fde(p: *const u8, pc: u64) -> Option<Fde> {
    unsafe {
        let (len, hdr) = record_len(p)?;
        let end = p.add(hdr + len);
        let idp = p.add(hdr);
        let id = (idp as *const u32).read_unaligned();
        if id == 0 {
            return None;
        }
        let cie_ptr = idp.sub(id as usize);
        let cie = parse_cie(cie_ptr)?;
        let mut r = Reader { p: idp.add(4) };
        let start = r.encoded(cie.fde_enc, 0);
        let range = r.encoded(cie.fde_enc & 0x0f, 0);
        if pc < start || pc >= start.wrapping_add(range) {
            return None;
        }
        if cie.has_z {
            let alen = r.uleb() as usize;
            r.p = r.p.add(alen);
        }
        Some(Fde { start, end: start + range, insns: r.p, insns_end: end, cie })
    }
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

unsafe fn find_in_hdr(hdr: *const u8, pc: u64) -> Option<Fde> {
    unsafe {
        let mut r = Reader { p: hdr };
        let version = r.u8();
        let ptr_enc = r.u8();
        let cnt_enc = r.u8();
        let tab_enc = r.u8();
        if version != 1 {
            return None;
        }
        let base = hdr as u64;
        let _eh_frame = r.encoded(ptr_enc, base);
        let count = r.encoded(cnt_enc, base) as usize;
        if tab_enc != 0x3b {
            return None;
        }
        let table = r.p as *const i32;
        let (mut lo, mut hi) = (0usize, count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let loc = base.wrapping_add(*table.add(mid * 2) as i64 as u64);
            if loc <= pc {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let fde = base.wrapping_add(*table.add((lo - 1) * 2 + 1) as i64 as u64);
        parse_fde(fde as *const u8, pc)
    }
}

static EH_FRAME: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_SIZE: AtomicU64 = AtomicU64::new(0);
static EH_FRAME_TRIED: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct Ehdr {
    ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

unsafe fn pread_all(fd: usize, buf: *mut u8, len: usize, off: u64) -> bool {
    unsafe {
        let mut got = 0;
        while got < len {
            let r = rusty_libc_core::syscall::syscall4(17, fd, buf.add(got) as usize, len - got, (off + got as u64) as usize);
            if r > usize::MAX - 4095 || r == 0 {
                return false;
            }
            got += r;
        }
        true
    }
}

unsafe fn locate_eh_frame_section() {
    unsafe {
        if EH_FRAME_TRIED.swap(1, Ordering::AcqRel) != 0 {
            return;
        }
        let fd = rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_OPEN, c"/proc/self/exe".as_ptr() as usize, 0o2000000, 0);
        if fd > usize::MAX - 4095 {
            return;
        }
        let mut eh: Ehdr = core::mem::zeroed();
        let mut ok = pread_all(fd, (&raw mut eh).cast(), size_of::<Ehdr>(), 0) && &eh.ident[..4] == b"\x7fELF" && eh.e_shentsize as usize == size_of::<Shdr>() && eh.e_shnum > 0 && eh.e_shnum < 200;
        if ok {
            let mut sh = [const { core::mem::MaybeUninit::<Shdr>::uninit() }; 200];
            let n = eh.e_shnum as usize;
            ok = pread_all(fd, sh.as_mut_ptr().cast(), n * size_of::<Shdr>(), eh.e_shoff);
            if ok && (eh.e_shstrndx as usize) < n {
                let shs = core::slice::from_raw_parts(sh.as_ptr() as *const Shdr, n);
                let strsec = &shs[eh.e_shstrndx as usize];
                if strsec.sh_size > 0 && strsec.sh_size < 8192 {
                    let mut names = [0u8; 8192];
                    if pread_all(fd, names.as_mut_ptr(), strsec.sh_size as usize, strsec.sh_offset) {
                        for s in shs {
                            let nm = &names[s.sh_name as usize..];
                            if nm.starts_with(b".eh_frame\0") && s.sh_addr != 0 {
                                EH_FRAME_SIZE.store(s.sh_size, Ordering::Release);
                                EH_FRAME.store(s.sh_addr + image().map_or(0, |(b, _, _)| b), Ordering::Release);
                            }
                        }
                    }
                }
            }
        }
        rusty_libc_core::syscall::syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd);
    }
}

unsafe fn find_fde(pc: u64) -> Option<Fde> {
    unsafe {
        #[cfg(feature = "shared")]
        {
            let f: usize;
            core::arch::asm!(".weak __libc_ldso_find_object", "mov {0}, qword ptr [rip + __libc_ldso_find_object@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags));
            if f != 0 {
                let mut r = [0u64; 12];
                let find: unsafe extern "C" fn(u64, *mut u64) -> c_int = core::mem::transmute(f);
                if find(pc, r.as_mut_ptr()) == 0 && r[4] != 0 {
                    return find_in_hdr(r[4] as *const u8, pc);
                }
                return None;
            }
        }
        let ph = rusty_libc_util::auxv::getauxval(AT_PHDR) as *const Phdr;
        let n = rusty_libc_util::auxv::getauxval(AT_PHNUM) as usize;
        let bias = image().map_or(0, |(b, _, _)| b);
        if !ph.is_null() {
            for h in core::slice::from_raw_parts(ph, n) {
                if h.p_type == PT_GNU_EH_FRAME
                    && let Some(f) = find_in_hdr(h.p_vaddr.wrapping_add(bias) as *const u8, pc)
                {
                    return Some(f);
                }
            }
        }
        locate_eh_frame_section();
        let base = EH_FRAME.load(Ordering::Acquire);
        let size = EH_FRAME_SIZE.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        let mut p = base as *const u8;
        let end = (base + size) as *const u8;
        while p < end {
            let (len, hdr) = record_len(p)?;
            if let Some(f) = parse_fde(p, pc) {
                return Some(f);
            }
            p = p.add(hdr + len);
        }
        None
    }
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
    Expr(*const u8, usize),
    ValExpr(*const u8, usize),
}

#[derive(Clone, Copy)]
enum CfaRule {
    RegOff(usize, i64),
    Expr(*const u8, usize),
}

#[derive(Clone, Copy)]
struct Frame {
    cfa: CfaRule,
    rules: [Rule; 17],
}

unsafe fn eval_expr(p: *const u8, len: usize, regs: &Regs, initial: Option<u64>) -> Option<u64> {
    unsafe {
        let mut r = Reader { p };
        let end = p.add(len);
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
                    push!((a as *const u64).read_unaligned());
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
unsafe fn run_cfa(cie: &Cie, p: *const u8, end: *const u8, mut loc: u64, pc: u64, f: &mut Frame, initial: &Frame) {
    unsafe {
        let mut r = Reader { p };
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
                    r.p = r.p.add(len);
                }
                0x10 => {
                    let reg = r.uleb() as usize;
                    let len = r.uleb() as usize;
                    if reg < 17 {
                        f.rules[reg] = Rule::Expr(r.p, len);
                    }
                    r.p = r.p.add(len);
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
                    r.p = r.p.add(len);
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

unsafe fn step(regs: &Regs, lookup_pc: u64) -> Option<(Regs, bool)> {
    unsafe {
        let fde = find_fde(lookup_pc)?;
        let blank = Frame { cfa: CfaRule::RegOff(RSP, 8), rules: [Rule::Same; 17] };
        let mut initial = blank;
        run_cfa(&fde.cie, fde.cie.insns, fde.cie.insns_end, fde.start, u64::MAX, &mut initial, &blank);
        let mut f = initial;
        run_cfa(&fde.cie, fde.insns, fde.insns_end, fde.start, lookup_pc, &mut f, &initial);
        let cfa = match f.cfa {
            CfaRule::RegOff(reg, off) => {
                if reg > 16 {
                    return None;
                }
                regs.r[reg].wrapping_add(off as u64)
            }
            CfaRule::Expr(p, len) => eval_expr(p, len, regs, None)?,
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
                Rule::Offset(n) => ((cfa as i64 + n) as *const u64).read_unaligned(),
                Rule::ValOffset(n) => (cfa as i64 + n) as u64,
                Rule::Register(o) => regs.r[(o as usize).min(16)],
                Rule::Expr(p, len) => (eval_expr(p, len, regs, Some(cfa))? as *const u64).read_unaligned(),
                Rule::ValExpr(p, len) => eval_expr(p, len, regs, Some(cfa))?,
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

unsafe fn is_sigreturn(pc: u64) -> bool {
    unsafe {
        let p = pc as *const u8;
        let a = core::slice::from_raw_parts(p, 9);
        a == b"\x48\xc7\xc0\x0f\x00\x00\x00\x0f\x05" || &a[..7] == b"\xb8\x0f\x00\x00\x00\x0f\x05"
    }
}

unsafe fn from_ucontext(regs: &Regs) -> Regs {
    unsafe {
        let uc = regs.r[RSP] as *const u64;
        let g = uc.add(5);
        let mut out = *regs;
        out.r[12] = g.add(4).read();
        out.r[13] = g.add(5).read();
        out.r[14] = g.add(6).read();
        out.r[15] = g.add(7).read();
        out.r[RBP] = g.add(10).read();
        out.r[RBX] = g.add(11).read();
        out.r[RSP] = g.add(15).read();
        out.r[RA] = g.add(16).read();
        out
    }
}

unsafe fn walk(buf: *mut *mut c_void, size: c_int, first: Regs) -> c_int {
    unsafe {
        let mut regs = first;
        let mut count = 0;
        let mut exact = false;
        while count < size {
            let pc = regs.r[RA];
            if pc == 0 {
                break;
            }
            *buf.add(count as usize) = pc as *mut c_void;
            count += 1;
            if is_sigreturn(pc) {
                regs = from_ucontext(&regs);
                exact = true;
                continue;
            }
            let lookup = if exact { pc } else { pc - 1 };
            match step(&regs, lookup) {
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
        count
    }
}

unsafe extern "C" fn backtrace_impl(buf: *mut *mut c_void, size: c_int, saved: *const u64) -> c_int {
    unsafe {
        let mut regs = Regs { r: [0; 17] };
        regs.r[RBP] = *saved;
        regs.r[RBX] = *saved.add(1);
        regs.r[12] = *saved.add(2);
        regs.r[13] = *saved.add(3);
        regs.r[14] = *saved.add(4);
        regs.r[15] = *saved.add(5);
        regs.r[RA] = *saved.add(6);
        regs.r[RSP] = saved.add(7) as u64;
        walk(buf, size, regs)
    }
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

fn describe(addr: u64) -> Option<(*const c_char, u64)> {
    unsafe {
        let (bias, start, end) = image()?;
        if addr < start || addr >= end {
            return None;
        }
        let name = crate::dlfcn::program_name_ptr();
        if name.is_null() || *name == 0 {
            return None;
        }
        Some((name, bias))
    }
}

#[cfg(feature = "shared")]
fn describe_loaded(addr: u64) -> Option<(*const c_char, *const c_char, u64, u64)> {
    unsafe {
        let f: usize;
        core::arch::asm!(".weak __libc_ldso_dladdr1", "mov {0}, qword ptr [rip + __libc_ldso_dladdr1@GOTPCREL]", out(reg) f, options(nostack, readonly, preserves_flags));
        if f == 0 {
            return None;
        }
        let mut info = [0u64; 4];
        let mut map: u64 = 0;
        let dladdr1: unsafe extern "C" fn(u64, *mut u64, *mut u64, c_int) -> c_int = core::mem::transmute(f);
        if dladdr1(addr, info.as_mut_ptr(), &mut map, 2 ) == 0 {
            return None;
        }
        let base = if info[2] == 0 { *(map as *const u64) } else { info[3] };
        Some((info[0] as *const c_char, info[2] as *const c_char, base, addr))
    }
}

fn format_line(out: &mut [u8], addr: *mut c_void, with_nl: bool) -> usize {
    use rusty_libc_stdio::rust_api::{Arg, snprintf};
    let n: usize;
    let mut tmp = [0u8; 4400];
    let line: &mut [u8] = &mut tmp;
    #[cfg(feature = "shared")]
    {
        let nl = if with_nl { "\n" } else { "" };
        let _ = nl;
        if let Some((fname, sname, base, a)) = describe_loaded(addr as u64) {
            let f = unsafe { core::ffi::CStr::from_ptr(fname) };
            let sn = if sname.is_null() { c"" } else { unsafe { core::ffi::CStr::from_ptr(sname) } };
            if sname.is_null() && base == 0 {
                let fmt = if with_nl { c"%s() [%p]\n" } else { c"%s() [%p]" };
                let n = snprintf(line, fmt, &[Arg::Str(f), Arg::Ptr(addr as *const c_void)]).max(0) as usize;
                let n = n.min(line.len() - 1).min(out.len());
                out[..n].copy_from_slice(&line[..n]);
                return n;
            }
            let (sign, off) = if a >= base { (b'+', a - base) } else { (b'-', base - a) };
            let fmt = if with_nl { c"%s(%s%c%#lx) [%p]\n" } else { c"%s(%s%c%#lx) [%p]" };
            let n = snprintf(line, fmt, &[Arg::Str(f), Arg::Str(sn), Arg::Int(sign as i64), Arg::Uint(off), Arg::Ptr(addr as *const c_void)]).max(0) as usize;
            let n = n.min(line.len() - 1).min(out.len());
            out[..n].copy_from_slice(&line[..n]);
            return n;
        }
        let fmt = if with_nl { c"[%p]\n" } else { c"[%p]" };
        let n = snprintf(line, fmt, &[Arg::Ptr(addr as *const c_void)]).max(0) as usize;
        let n = n.min(line.len() - 1).min(out.len());
        out[..n].copy_from_slice(&line[..n]);
        return n;
    }
    #[cfg(not(feature = "shared"))]
    match describe(addr as u64) {
        Some((fname, bias)) => {
            let f = unsafe { core::ffi::CStr::from_ptr(fname) };
            if bias == 0 {
                n = snprintf(line, if with_nl { c"%s() [%p]\n" } else { c"%s() [%p]" }, &[Arg::Str(f), Arg::Ptr(addr as *const c_void)]).max(0) as usize;
            } else {
                let a = addr as u64;
                let (sign, off) = if a >= bias { (b'+', a - bias) } else { (b'-', bias - a) };
                let fmt = if with_nl { c"%s(%c%#lx) [%p]\n" } else { c"%s(%c%#lx) [%p]" };
                n = snprintf(line, fmt, &[Arg::Str(f), Arg::Int(sign as i64), Arg::Uint(off), Arg::Ptr(addr as *const c_void)]).max(0) as usize;
            }
        }
        None => {
            let fmt = if with_nl { c"[%p]\n" } else { c"[%p]" };
            n = snprintf(line, fmt, &[Arg::Ptr(addr as *const c_void)]).max(0) as usize;
        }
    }
    let n = n.min(line.len() - 1).min(out.len());
    out[..n].copy_from_slice(&line[..n]);
    n
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    unsafe {
        let size = size.max(0) as usize;
        let mut total = 0usize;
        let mut scratch = [0u8; 4400];
        for i in 0..size {
            total += format_line(&mut scratch, *buffer.add(i), false) + 1;
        }
        let result = rusty_libc_malloc::malloc(size * size_of::<*mut c_char>() + total) as *mut *mut c_char;
        if result.is_null() {
            return null_mut();
        }
        let mut last = result.add(size) as *mut u8;
        for i in 0..size {
            *result.add(i) = last as *mut c_char;
            let n = format_line(&mut scratch, *buffer.add(i), false);
            core::ptr::copy_nonoverlapping(scratch.as_ptr(), last, n);
            *last.add(n) = 0;
            last = last.add(n + 1);
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char {
    unsafe { backtrace_symbols(buffer, size) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    unsafe {
        let mut line = [0u8; 4400];
        for i in 0..size.max(0) as usize {
            let n = format_line(&mut line, *buffer.add(i), true);
            rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, fd as usize, line.as_ptr() as usize, n);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    unsafe { backtrace_symbols_fd(buffer, size, fd) }
}

