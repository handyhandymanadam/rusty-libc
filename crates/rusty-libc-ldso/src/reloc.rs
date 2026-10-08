use crate::elf::*;
use crate::lookup::*;
use crate::map::*;
use crate::tls;
use crate::sys;
use crate::util::*;
use core::ptr::null_mut;

pub static mut NOIFUNC: bool = false;

pub struct Resolved {
    pub sym: *const Sym,
    pub map: *mut LinkMap,
    pub addr: usize,
}

unsafe fn global_scope() -> &'static [*mut LinkMap] {
    unsafe { core::slice::from_raw_parts((&raw const st().global) as *const *mut LinkMap, st().nglobal) }
}

unsafe fn own_scope(m: *mut LinkMap) -> &'static [*mut LinkMap] {
    unsafe {
        if (*m).in_global || (*m).scope.is_null() {
            &[]
        } else {
            core::slice::from_raw_parts((*m).scope, (*m).nscope)
        }
    }
}

unsafe fn extra_scope(m: *mut LinkMap) -> &'static [*mut LinkMap] {
    unsafe {
        if (*m).in_global || (*m).xscope.is_null() {
            &[]
        } else {
            core::slice::from_raw_parts((*m).xscope, (*m).nxscope)
        }
    }
}

pub unsafe fn call_resolver(addr: usize) -> usize {
    unsafe {
        let f: extern "C" fn() -> usize = core::mem::transmute(addr);
        f()
    }
}

fn describe(m: *mut LinkMap) -> &'static [u8] {
    unsafe {
        let n = cstr((*m).l_name);
        if n.is_empty() { cstr(st().prog_name) } else { n }
    }
}

pub unsafe fn bind(m: *mut LinkMap, idx: usize, plt: bool, copy: bool) -> Option<Resolved> {
    unsafe { bind_ex(m, idx, plt, copy, true) }
}

pub unsafe fn bind_ex(m: *mut LinkMap, idx: usize, plt: bool, copy: bool, audit: bool) -> Option<Resolved> {
    unsafe {
        let sym = (*m).symtab.add(idx);
        let bindt = (*sym).info >> 4;
        let vis = (*sym).other & 3;
        if bindt == STB_LOCAL || vis != STV_DEFAULT {
            let mut addr = sym_value_addr((*m).l_addr, sym);
            if (*sym).info & 0xf == STT_GNU_IFUNC && (*sym).shndx != 0 && !NOIFUNC && !copy {
                addr = call_resolver(addr);
            }
            return Some(Resolved { sym, map: m, addr });
        }
        let (name, hash) = cstr_gnu_hash((*m).strtab.add((*sym).name as usize));
        let ver = ref_version(m, idx);
        let g = global_scope();
        let own = own_scope(m);
        let xs = extra_scope(m);
        let f = Flags { plt, skip: if copy { m } else { null_mut() }, newest: false };
        let found = if (*m).deepbind { lookup_hashed(name, hash, ver.as_ref(), &[own, xs, g], &f) } else { lookup_hashed(name, hash, ver.as_ref(), &[g, own, xs], &f) };
        if let Some(found) = found {
            let mut addr = sym_addr(&found);
            let t = (*found.sym).info & 0xf;
            if t == STT_GNU_IFUNC && !NOIFUNC {
                addr = call_resolver(addr);
            }
            (*found.map).used = true;
            if audit && plt && !copy && t != STT_TLS && crate::audit::active() {
                addr = crate::audit::symbind(found.sym, found.map, m, name, addr, plt);
            }
            if (*found.map).dlopened && !(*found.map).nodelete && found.map != m {
                crate::dl::note_binding(m, found.map);
            }
            return Some(Resolved { sym: found.sym, map: found.map, addr });
        }
        if bindt == STB_WEAK {
            return Some(Resolved { sym, map: null_mut(), addr: 0 });
        }
        let vname: &[u8] = match &ver {
            Some(v) => cstr(v.name),
            None => b"",
        };
        if st().lenient {
            if ver.is_some() {
                crate::eprint!("{}: warning: unresolved symbol {} (version {}) needed by {}\n", Bytes(cstr(st().prog_name)), Bytes(name), Bytes(vname), Bytes(describe(m)));
            } else {
                crate::eprint!("{}: warning: unresolved symbol {} needed by {}\n", Bytes(cstr(st().prog_name)), Bytes(name), Bytes(describe(m)));
            }
            return Some(Resolved { sym, map: null_mut(), addr: unresolved_stub as usize });
        }
        if ver.is_some() {
            set_error(format_args!("symbol lookup error: {}: undefined symbol: {}, version {}", Bytes(describe(m)), Bytes(name), Bytes(vname)));
        } else {
            set_error(format_args!("symbol lookup error: {}: undefined symbol: {}", Bytes(describe(m)), Bytes(name)));
        }
        None
    }
}

extern "C" fn unresolved_stub() -> ! {
    crate::eprint!("{}: call to an unresolved symbol (see the warnings above)\n", Bytes(unsafe { cstr(st().prog_name) }));
    crate::sys::exit(127)
}

unsafe fn apply_relr(m: *mut LinkMap) {
    unsafe {
        let base = (*m).l_addr as u64;
        let n = (*m).relrsz / 8;
        let mut w: *mut u64 = null_mut();
        for i in 0..n {
            let e = *(*m).relr.add(i);
            if e & 1 == 0 {
                w = ((*m).l_addr + e as usize) as *mut u64;
                *w = (*w).wrapping_add(base);
                w = w.add(1);
            } else {
                let mut bits = e >> 1;
                while bits != 0 {
                    let p = w.add(bits.trailing_zeros() as usize);
                    *p = (*p).wrapping_add(base);
                    bits &= bits - 1;
                }
                w = w.add(63);
            }
        }
    }
}

unsafe fn apply(m: *mut LinkMap, r: &Rela, plt_table: bool) -> bool {
    unsafe {
        let ty = (r.info & 0xffff_ffff) as u32;
        let idx = (r.info >> 32) as usize;
        let place = ((*m).l_addr + r.offset as usize) as *mut u64;
        let a = r.addend as u64;
        let l = (*m).l_addr as u64;
        match ty {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => *place = l.wrapping_add(a),
            R_X86_64_IRELATIVE => *place = call_resolver(l.wrapping_add(a) as usize) as u64,
            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                if ty == R_X86_64_JUMP_SLOT && idx != 0 && lazy_plt(m) && !(*m).pltgot.is_null() {
                    *place = (*place).wrapping_add(l);
                    (*m).lazy_pending = true;
                    return true;
                }
                if idx == 0 {
                    *place = if ty == R_X86_64_64 { l.wrapping_add(a) } else { 0 };
                    return true;
                }
                match bind(m, idx, ty == R_X86_64_JUMP_SLOT, false) {
                    Some(res) => *place = if ty == R_X86_64_64 { (res.addr as u64).wrapping_add(a) } else { res.addr as u64 },
                    None => {
                        if ty == R_X86_64_JUMP_SLOT && lazy_plt(m) && !(*m).pltgot.is_null() {
                            *place = (*place).wrapping_add(l);
                            (*m).lazy_pending = true;
                        } else {
                            return false;
                        }
                    }
                }
            }
            R_X86_64_SIZE64 => {
                let sz = if idx == 0 { 0 } else { (*(*m).symtab.add(idx)).size };
                let Some(res) = (if idx == 0 { None } else { bind(m, idx, false, false) }) else {
                    *place = sz.wrapping_add(a);
                    return true;
                };
                *place = (*res.sym).size.wrapping_add(a);
            }
            R_X86_64_COPY => {
                let Some(res) = bind(m, idx, false, true) else { return false };
                if res.map.is_null() {
                    return true;
                }
                if !(*res.map).relocated && !(*res.map).is_ldso && res.map != m && !relocate(res.map) {
                    return false;
                }
                let n = (*(*m).symtab.add(idx)).size.min((*res.sym).size) as usize;
                core::ptr::copy_nonoverlapping(res.addr as *const u8, place as *mut u8, n);
            }
            R_X86_64_DTPMOD64 => {
                if idx == 0 {
                    *place = (*m).tls_modid as u64;
                } else {
                    let Some(res) = bind(m, idx, false, false) else { return false };
                    *place = if res.map.is_null() { 0 } else { (*res.map).tls_modid as u64 };
                }
            }
            R_X86_64_DTPOFF64 => {
                let v = if idx == 0 { 0 } else {
                    let Some(res) = bind(m, idx, false, false) else { return false };
                    if res.map.is_null() { 0 } else { (*res.sym).value }
                };
                *place = v.wrapping_add(a);
            }
            R_X86_64_TPOFF64 => {
                let (map, v) = if idx == 0 { (m, 0) } else {
                    let Some(res) = bind(m, idx, false, false) else { return false };
                    if res.map.is_null() {
                        *place = 0;
                        return true;
                    }
                    (res.map, (*res.sym).value)
                };
                if !(*map).tls_static && !tls::add_static_late(map) {
                    set_error(format_args!("{}: cannot allocate memory in static TLS block", Bytes(describe(m))));
                    return false;
                }
                *place = v.wrapping_add(a).wrapping_sub((*map).tls_offset as u64);
            }
            R_X86_64_TLSDESC => {
                let (map, v) = if idx == 0 { (m, 0) } else {
                    let Some(res) = bind(m, idx, false, false) else { return false };
                    if res.map.is_null() {
                        (null_mut(), 0)
                    } else {
                        (res.map, (*res.sym).value)
                    }
                };
                if map.is_null() {
                    *place = tls::_dl_tlsdesc_return as usize as u64;
                    *place.add(1) = 0;
                } else if (*map).tls_static {
                    *place = tls::_dl_tlsdesc_return as usize as u64;
                    *place.add(1) = v.wrapping_add(a).wrapping_sub((*map).tls_offset as u64);
                } else {
                    let ti = alloc_perm(core::mem::size_of::<tls::TlsIndex>(), 8) as *mut tls::TlsIndex;
                    (*ti).module = (*map).tls_modid;
                    (*ti).offset = v.wrapping_add(a) as usize;
                    *place = tls::_dl_tlsdesc_dynamic as usize as u64;
                    *place.add(1) = ti as u64;
                }
            }
            _ => {
                let _ = plt_table;
                set_error(format_args!("{}: unsupported relocation type {}", Bytes(describe(m)), ty));
                return false;
            }
        }
        true
    }
}

pub unsafe fn apply_copy_relocs(m: *mut LinkMap) -> bool {
    unsafe {
        if (*m).relocated || (*m).copy_done {
            return true;
        }
        let n = (*m).relasz / core::mem::size_of::<Rela>();
        let mut k = 0u32;
        let mut all = true;
        for i in 0..n {
            let r = &*(*m).rela.add(i);
            if (r.info & 0xffff_ffff) as u32 != R_X86_64_COPY {
                continue;
            }
            let mut skip = false;
            if k < 64 && (r.info >> 32) != 0 {
                if let Some(res) = bind(m, (r.info >> 32) as usize, false, true) {
                    skip = !res.map.is_null() && !(*res.map).relocated && !(*res.map).is_ldso && res.map != m && !crate::audit::in_audit_closure(res.map);
                }
            }
            if skip {
                all = false;
            } else {
                if !apply(m, r, false) {
                    return false;
                }
                if k < 64 {
                    (*m).copy_mask |= 1 << k;
                }
            }
            k += 1;
        }
        (*m).copy_done = all;
        true
    }
}

pub unsafe fn relocate(m: *mut LinkMap) -> bool {
    unsafe {
        if (*m).relocated {
            return true;
        }
        let textrel = (*m).textrel;
        if textrel && !make_text_writable(m, true) {
            return false;
        }
        let ok = relocate_body(m);
        if textrel {
            make_text_writable(m, false);
        }
        if ok {
            tls::after_relocate(m);
        }
        ok
    }
}

unsafe fn make_text_writable(m: *mut LinkMap, writable: bool) -> bool {
    unsafe {
        for i in 0..(*m).phnum {
            let p = &*(*m).phdr.add(i);
            if p.typ != PT_LOAD || p.flags & PF_W != 0 {
                continue;
            }
            let start = (*m).l_addr + (p.vaddr as usize & !(sys::PAGE - 1));
            let end = ((*m).l_addr + (p.vaddr + p.memsz) as usize + sys::PAGE - 1) & !(sys::PAGE - 1);
            let orig = (if p.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if p.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
            let prot = if writable { orig | sys::PROT_WRITE | sys::PROT_READ } else { orig };
            let r = sys::mprotect(start, end - start, prot);
            if r < 0 && writable {
                set_error(format_args!("{}: cannot make segment writable for relocation: {}", Bytes(describe(m)), if r == -13 { "Permission denied" } else { "Cannot allocate memory" }));
                return false;
            }
        }
        true
    }
}

pub static mut PHASE_CYCLES: [u64; 3] = [0; 3];

unsafe fn setup_lazy_got(m: *mut LinkMap) {
    unsafe {
        *(*m).pltgot.add(1) = m as usize;
        if crate::plt::wanted() {
            if crate::profile::enabled() {
                crate::profile::note_map(m);
            }
            crate::plt::init_vector_level();
            *(*m).pltgot.add(2) = crate::plt::_dl_runtime_profile as usize;
        } else {
            *(*m).pltgot.add(2) = _dl_runtime_resolve as usize;
        }
    }
}

unsafe fn lazy_plt_decide(m: *mut LinkMap) -> bool {
    unsafe { (!st().bind_now_env || crate::profile::enabled()) && !(*m).rtld_now && (!(*m).bind_now || crate::audit::plt_hooks_for(m)) }
}

#[inline(always)]
unsafe fn lazy_plt(m: *mut LinkMap) -> bool {
    unsafe { (*m).lazy_plt }
}

unsafe fn relocate_body(m: *mut LinkMap) -> bool {
    unsafe {
        (*m).lazy_plt = lazy_plt_decide(m);
        let t1 = core::arch::x86_64::_rdtsc();
        if (*m).pltrelsz != 0 && !(*m).pltgot.is_null() && lazy_plt(m) {
            setup_lazy_got(m);
        }
        if (*m).relrsz != 0 {
            apply_relr(m);
        }
        let t2 = core::arch::x86_64::_rdtsc();
        PHASE_CYCLES[1] += t2 - t1;
        let n = (*m).relasz / core::mem::size_of::<Rela>();
        let mut k = 0u32;
        for i in 0..n {
            let r = &*(*m).rela.add(i);
            let ty = (r.info & 0xffff_ffff) as u32;
            if ty == R_X86_64_COPY {
                if (*m).copy_done || (k < 64 && (*m).copy_mask >> k & 1 != 0) {
                    k += 1;
                    continue;
                }
                k += 1;
            } else if ty == R_X86_64_IRELATIVE {
                continue;
            }
            if !apply(m, r, false) {
                return false;
            }
        }
        for i in 0..n {
            let r = &*(*m).rela.add(i);
            if (r.info & 0xffff_ffff) as u32 == R_X86_64_IRELATIVE && !apply(m, r, false) {
                return false;
            }
        }
        let np = (*m).pltrelsz / core::mem::size_of::<Rela>();
        for pass in 0..2 {
            for i in 0..np {
                let r = &*(*m).jmprel.add(i);
                let irel = (r.info & 0xffff_ffff) as u32 == R_X86_64_IRELATIVE;
                if irel != (pass == 1) {
                    continue;
                }
                if !apply(m, r, true) {
                    return false;
                }
            }
        }
        PHASE_CYCLES[2] += core::arch::x86_64::_rdtsc() - t2;
        if (*m).lazy_pending {
            setup_lazy_got(m);
        }
        (*m).relocated = true;
        true
    }
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
    unsafe {
        let r = &*(*m).jmprel.add(idx);
        let symidx = (r.info >> 32) as usize;
        match bind(m, symidx, true, false) {
            Some(res) => {
                let place = ((*m).l_addr + r.offset as usize) as *mut usize;
                *place = res.addr;
                res.addr
            }
            None => {
                crate::eprint!("{}: {}\n", Bytes(cstr(st().prog_name)), Bytes(error_str()));
                crate::sys::exit(127)
            }
        }
    }
}
