#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::lookup::*;
use crate::map::*;
use crate::sys;
use crate::tls;
use crate::util::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

pub static NOIFUNC: AtomicBool = AtomicBool::new(false);

pub struct Resolved {
    pub sym: &'static Sym,
    pub map: Option<Map>,
    pub addr: usize,
}

fn global_scope(m: Map) -> &'static [Map] {
    ns(m.l_ns() as usize).scope()
}

fn own_scope(m: Map) -> &'static [Map] {
    if m.in_global() { &[] } else { m.scope() }
}

fn extra_scope(m: Map) -> &'static [Map] {
    if m.in_global() { &[] } else { m.xscope() }
}

pub unsafe fn call_resolver(addr: usize) -> usize {
    let f: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
    f()
}

fn describe(m: Map) -> &'static [u8] {
    let n = m.name();
    if n.is_empty() { prog_name() } else { n }
}

pub fn prog_name() -> &'static [u8] {
    unsafe { crate::ffi::cstr_opt(st().prog_name) }.unwrap_or(b"")
}

pub unsafe fn bind(m: Map, idx: usize, plt: bool, copy: bool) -> Option<Resolved> {
    unsafe { bind_ex(m, idx, plt, copy, true) }
}

pub unsafe fn bind_ex(m: Map, idx: usize, plt: bool, copy: bool, audit: bool) -> Option<Resolved> {
    let sym = unsafe { m.sym(idx) };
    let bindt = sym.info >> 4;
    let vis = sym.other & 3;
    if bindt == STB_LOCAL || vis != STV_DEFAULT {
        let mut addr = sym_value_addr(m.l_addr(), sym);
        if sym.info & 0xf == STT_GNU_IFUNC && sym.shndx != 0 && !NOIFUNC.load(Relaxed) && !copy {
            addr = unsafe { call_resolver(addr) };
        }
        return Some(Resolved { sym, map: Some(m), addr });
    }
    let (name, hash) = m.sym_name(sym).bytes_gnu_hash();
    let ver = unsafe { ref_version(m, idx) };
    let g = global_scope(m);
    let own = own_scope(m);
    let xs = extra_scope(m);
    let f = Flags { plt, skip: if copy { Some(m) } else { None }, newest: false };
    let found = if m.deepbind() { lookup_hashed(name, hash, ver.as_ref(), &[own, xs, g], &f) } else { lookup_hashed(name, hash, ver.as_ref(), &[g, own, xs], &f) };
    if let Some(found) = found {
        let mut addr = sym_addr(&found);
        let t = found.sym.info & 0xf;
        if t == STT_GNU_IFUNC && !NOIFUNC.load(Relaxed) {
            addr = unsafe { call_resolver(addr) };
        }
        found.map.set_used(true);
        if audit && plt && !copy && t != STT_TLS && crate::audit::active() {
            addr = crate::audit::symbind(found.sym, Some(found.map), Some(m), name, addr, plt);
        }
        if found.map.dlopened() && !found.map.nodelete() && found.map != m {
            crate::dl::note_binding(Some(m), Some(found.map));
        }
        return Some(Resolved { sym: found.sym, map: Some(found.map), addr });
    }
    if bindt == STB_WEAK {
        return Some(Resolved { sym, map: None, addr: 0 });
    }
    let vname: &[u8] = match &ver {
        Some(v) => v.name.bytes(),
        None => b"",
    };
    if st().lenient {
        if ver.is_some() {
            crate::eprint!("{}: warning: unresolved symbol {} (version {}) needed by {}\n", Bytes(prog_name()), Bytes(name), Bytes(vname), Bytes(describe(m)));
        } else {
            crate::eprint!("{}: warning: unresolved symbol {} needed by {}\n", Bytes(prog_name()), Bytes(name), Bytes(describe(m)));
        }
        return Some(Resolved { sym, map: None, addr: unresolved_stub as *const () as usize });
    }
    if ver.is_some() {
        set_error_occ("symbol lookup error", describe(m), 0, format_args!("undefined symbol: {}, version {}", Bytes(name), Bytes(vname)));
    } else {
        set_error_occ("symbol lookup error", describe(m), 0, format_args!("undefined symbol: {}", Bytes(name)));
    }
    None
}

extern "C" fn unresolved_stub() -> ! {
    crate::eprint!("{}: call to an unresolved symbol (see the warnings above)\n", Bytes(prog_name()));
    crate::sys::exit(127)
}

unsafe fn apply_relr(m: Map) {
    let base = m.l_addr() as u64;
    let mut w: *mut u64 = core::ptr::null_mut();
    for &e in m.relrs() {
        if e & 1 == 0 {
            w = (m.l_addr() + e as usize) as *mut u64;
            let v = unsafe { *w };
            unsafe { *w = v.wrapping_add(base) };
            w = w.wrapping_add(1);
        } else {
            let mut bits = e >> 1;
            while bits != 0 {
                let p = w.wrapping_add(bits.trailing_zeros() as usize);
                let v = unsafe { *p };
                unsafe { *p = v.wrapping_add(base) };
                bits &= bits - 1;
            }
            w = w.wrapping_add(63);
        }
    }
}

unsafe fn apply(m: Map, r: &Rela, plt_table: bool) -> bool {
    let ty = (r.info & 0xffff_ffff) as u32;
    let idx = (r.info >> 32) as usize;
    let place = (m.l_addr() + r.offset as usize) as *mut u64;
    let a = r.addend as u64;
    let l = m.l_addr() as u64;
    match ty {
        R_X86_64_NONE => {}
        R_X86_64_RELATIVE => unsafe { *place = l.wrapping_add(a) },
        R_X86_64_IRELATIVE => {
            let v = unsafe { call_resolver(l.wrapping_add(a) as usize) } as u64;
            unsafe { *place = v };
        }
        R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            if ty == R_X86_64_JUMP_SLOT && idx != 0 && m.lazy_plt() && !m.pltgot().is_null() {
                let v = unsafe { *place };
                unsafe { *place = v.wrapping_add(l) };
                m.set_lazy_pending(true);
                return true;
            }
            if idx == 0 {
                unsafe { *place = if ty == R_X86_64_64 { l.wrapping_add(a) } else { 0 } };
                return true;
            }
            match unsafe { bind(m, idx, ty == R_X86_64_JUMP_SLOT, false) } {
                Some(res) => unsafe { *place = if ty == R_X86_64_64 { (res.addr as u64).wrapping_add(a) } else { res.addr as u64 } },
                None => {
                    if ty == R_X86_64_JUMP_SLOT && m.lazy_plt() && !m.pltgot().is_null() {
                        let v = unsafe { *place };
                        unsafe { *place = v.wrapping_add(l) };
                        m.set_lazy_pending(true);
                    } else {
                        return false;
                    }
                }
            }
        }
        R_X86_64_SIZE64 => {
            let sz = if idx == 0 { 0 } else { unsafe { m.sym(idx) }.size };
            let Some(res) = (if idx == 0 { None } else { unsafe { bind(m, idx, false, false) } }) else {
                unsafe { *place = sz.wrapping_add(a) };
                return true;
            };
            unsafe { *place = res.sym.size.wrapping_add(a) };
        }
        R_X86_64_COPY => {
            let Some(res) = (unsafe { bind(m, idx, false, true) }) else { return false };
            let Some(rmap) = res.map else { return true };
            if !rmap.relocated() && !rmap.is_ldso() && rmap != m && !unsafe { relocate(rmap) } {
                return false;
            }
            let n = unsafe { m.sym(idx) }.size.min(res.sym.size) as usize;
            unsafe { core::ptr::copy_nonoverlapping(res.addr as *const u8, place as *mut u8, n) };
        }
        R_X86_64_DTPMOD64 => {
            let v = if idx == 0 {
                m.tls_modid() as u64
            } else {
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                res.map.map_or(0, |rm| rm.tls_modid() as u64)
            };
            unsafe { *place = v };
        }
        R_X86_64_DTPOFF64 => {
            let v = if idx == 0 {
                0
            } else {
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                if res.map.is_none() { 0 } else { res.sym.value }
            };
            unsafe { *place = v.wrapping_add(a) };
        }
        R_X86_64_TPOFF64 => {
            let (map, v) = if idx == 0 {
                (m, 0)
            } else {
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                let Some(rm) = res.map else {
                    unsafe { *place = 0 };
                    return true;
                };
                (rm, res.sym.value)
            };
            if !map.tls_static() && !tls::add_static_late(map) {
                set_error_at(describe(m), 0, format_args!("cannot allocate memory in static TLS block"));
                return false;
            }
            unsafe { *place = v.wrapping_add(a).wrapping_sub(map.tls_offset() as u64) };
        }
        R_X86_64_TLSDESC => {
            let target = if idx == 0 {
                Some((m, 0))
            } else {
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                res.map.map(|rm| (rm, res.sym.value))
            };
            let (f, arg) = match target {
                None => (tls::_dl_tlsdesc_return as *const () as usize as u64, 0),
                Some((map, v)) if map.tls_static() => (tls::_dl_tlsdesc_return as *const () as usize as u64, v.wrapping_add(a).wrapping_sub(map.tls_offset() as u64)),
                Some((map, v)) => {
                    let ti = alloc_perm(core::mem::size_of::<tls::TlsIndex>(), 8) as *mut tls::TlsIndex;
                    unsafe { ti.write(tls::TlsIndex { module: map.tls_modid(), offset: v.wrapping_add(a) as usize }) };
                    (tls::_dl_tlsdesc_dynamic as *const () as usize as u64, ti as u64)
                }
            };
            unsafe { place.write(f) };
            unsafe { place.wrapping_add(1).write(arg) };
        }
        _ => {
            let _ = plt_table;
            set_error_at(describe(m), 0, format_args!("unsupported relocation type {}", ty));
            return false;
        }
    }
    true
}

pub unsafe fn relocate(m: Map) -> bool {
    if m.relocated() {
        return true;
    }
    let textrel = m.textrel();
    if textrel && !make_text_writable(m, true) {
        return false;
    }
    let ok = unsafe { relocate_body(m) };
    if textrel {
        make_text_writable(m, false);
    }
    if ok {
        tls::after_relocate(m);
    }
    ok
}

fn make_text_writable(m: Map, writable: bool) -> bool {
    for p in m.phdrs() {
        if p.typ != PT_LOAD || p.flags & PF_W != 0 {
            continue;
        }
        let start = m.l_addr() + (p.vaddr as usize & !(sys::PAGE - 1));
        let end = (m.l_addr() + (p.vaddr + p.memsz) as usize + sys::PAGE - 1) & !(sys::PAGE - 1);
        let orig = (if p.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if p.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
        let prot = if writable { orig | sys::PROT_WRITE | sys::PROT_READ } else { orig };
        let r = unsafe { sys::mprotect(start, end - start, prot) };
        if r < 0 && writable {
            set_error_at(describe(m), if r == -13 { 13 } else { 12 }, format_args!("cannot make segment writable for relocation"));
            return false;
        }
    }
    true
}

pub static PHASE_CYCLES: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

fn add_cycles(i: usize, c: u64) {
    PHASE_CYCLES[i].store(PHASE_CYCLES[i].load(Relaxed).wrapping_add(c), Relaxed);
}

unsafe fn setup_lazy_got(m: Map) {
    let got = m.pltgot();
    unsafe { *got.wrapping_add(1) = m.as_ptr() as usize };
    let resolver = if crate::plt::wanted() {
        if crate::profile::enabled() {
            crate::profile::note_map(m);
        }
        crate::plt::init_vector_level();
        crate::plt::_dl_runtime_profile as *const () as usize
    } else {
        _dl_runtime_resolve as *const () as usize
    };
    unsafe { *got.wrapping_add(2) = resolver };
}

fn lazy_plt_decide(m: Map) -> bool {
    (!st().bind_now_env || crate::profile::enabled()) && !m.rtld_now() && (!m.bind_now() || crate::audit::plt_hooks_for(m))
}

unsafe fn relocate_body(m: Map) -> bool {
    m.set_lazy_plt(lazy_plt_decide(m));
    let t1 = unsafe { core::arch::x86_64::_rdtsc() };
    if m.pltrelsz() != 0 && !m.pltgot().is_null() && m.lazy_plt() {
        unsafe { setup_lazy_got(m) };
    }
    if m.relrsz() != 0 {
        unsafe { apply_relr(m) };
    }
    let t2 = unsafe { core::arch::x86_64::_rdtsc() };
    add_cycles(1, t2 - t1);
    let relas = m.relas();
    for r in relas {
        let ty = (r.info & 0xffff_ffff) as u32;
        if ty == R_X86_64_IRELATIVE {
            continue;
        }
        if !unsafe { apply(m, r, false) } {
            return false;
        }
    }
    for r in relas {
        if (r.info & 0xffff_ffff) as u32 == R_X86_64_IRELATIVE && !unsafe { apply(m, r, false) } {
            return false;
        }
    }
    let jmprels = m.jmprels();
    for pass in 0..2 {
        for r in jmprels {
            let irel = (r.info & 0xffff_ffff) as u32 == R_X86_64_IRELATIVE;
            if irel != (pass == 1) {
                continue;
            }
            if !unsafe { apply(m, r, true) } {
                return false;
            }
        }
    }
    add_cycles(2, unsafe { core::arch::x86_64::_rdtsc() } - t2);
    if m.lazy_pending() {
        unsafe { setup_lazy_got(m) };
    }
    m.set_relocated(true);
    true
}

#[unsafe(naked)]
pub unsafe extern "C" fn _dl_runtime_resolve() {
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push rbp",
        "mov rbp, rsp",
        "sub rsp, 144",
        "and rsp, -16",
        "movdqu [rsp], xmm0",
        "movdqu [rsp + 16], xmm1",
        "movdqu [rsp + 32], xmm2",
        "movdqu [rsp + 48], xmm3",
        "movdqu [rsp + 64], xmm4",
        "movdqu [rsp + 80], xmm5",
        "movdqu [rsp + 96], xmm6",
        "movdqu [rsp + 112], xmm7",
        "mov rdi, [rbp + 64]",
        "mov rsi, [rbp + 72]",
        "call {resolve}",
        "mov r11, rax",
        "movdqu xmm0, [rsp]",
        "movdqu xmm1, [rsp + 16]",
        "movdqu xmm2, [rsp + 32]",
        "movdqu xmm3, [rsp + 48]",
        "movdqu xmm4, [rsp + 64]",
        "movdqu xmm5, [rsp + 80]",
        "movdqu xmm6, [rsp + 96]",
        "movdqu xmm7, [rsp + 112]",
        "mov rsp, rbp",
        "pop rbp",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "add rsp, 16",
        "jmp r11",
        resolve = sym resolve_lazy,
    )
}

unsafe extern "C" fn resolve_lazy(m: *mut LinkMap, idx: usize) -> usize {
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { crate::sys::exit(127) };
    let r = &m.jmprels()[idx];
    let symidx = (r.info >> 32) as usize;
    match unsafe { bind(m, symidx, true, false) } {
        Some(res) => {
            let place = (m.l_addr() + r.offset as usize) as *mut usize;
            unsafe { *place = res.addr };
            res.addr
        }
        None => {
            crate::eprint!("{}: {}\n", Bytes(prog_name()), Bytes(error_str()));
            crate::sys::exit(127)
        }
    }
}
