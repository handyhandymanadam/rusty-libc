//! Applying relocations (x86-64): RELA, RELR, PLT slots, TLS, IRELATIVE, COPY.
//!
//! What stays unsafe here, by its nature: the stores into the object being relocated (each address is the object's load
//! address plus an offset from its own relocation table), the calls of IFUNC resolvers, and the lazy-binding trampoline.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::lookup::*;
use crate::map::*;
use crate::sys;
use crate::tls;
use crate::util::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// Set while a trace (`ld.so --list` with LD_WARN or LD_DEBUG=unused) only looks symbols up: nothing is relocated, so no
/// IFUNC resolver may run.
pub static NOIFUNC: AtomicBool = AtomicBool::new(false);

/// What a symbol reference resolved to.
pub struct Resolved {
    /// The definition, or for an undefined weak reference the referencing symbol itself.
    pub sym: &'static Sym,
    pub map: Option<Map>,
    /// The address (0 for an undefined weak symbol).
    pub addr: usize,
}

/// The global scope of the namespace `m` lives in.
fn global_scope(m: Map) -> &'static [Map] {
    ns(m.l_ns() as usize).scope()
}

fn own_scope(m: Map) -> &'static [Map] {
    if m.in_global() { &[] } else { m.scope() }
}

/// The scopes later dlopen calls added to `m` (glibc's extra `l_scope` entries).
fn extra_scope(m: Map) -> &'static [Map] {
    if m.in_global() { &[] } else { m.xscope() }
}

/// Call an IFUNC resolver; its result is the function's address.
///
/// # Safety
/// `addr` is the address of an STT_GNU_IFUNC resolver (or an IRELATIVE target) of an object whose code may run now.
pub unsafe fn call_resolver(addr: usize) -> usize {
    // SAFETY: a resolver takes no arguments and returns an address (caller's contract).
    let f: extern "C" fn() -> usize = unsafe { core::mem::transmute(addr) };
    f()
}

fn describe(m: Map) -> &'static [u8] {
    let n = m.name();
    if n.is_empty() { prog_name() } else { n }
}

/// The program's name for messages.
pub fn prog_name() -> &'static [u8] {
    // SAFETY: prog_name is argv[0], the path of a direct invocation or a literal: strings that live for the process.
    unsafe { crate::ffi::cstr_opt(st().prog_name) }.unwrap_or(b"")
}

/// Resolve symbol `idx` of `m` for a relocation. `None` after the failure message was recorded.
///
/// # Safety
/// `idx` is the index of a symbol of `m` (from its relocation table), and IFUNC resolvers may run (`m`'s scope is relocated).
pub unsafe fn bind(m: Map, idx: usize, plt: bool, copy: bool) -> Option<Resolved> {
    // SAFETY: forwarded contract.
    unsafe { bind_ex(m, idx, plt, copy, true) }
}

/// `bind`, with `audit` false the audit libraries are not asked (the caller does it, per PLT slot: see plt.rs).
///
/// # Safety
/// As [`bind`].
pub unsafe fn bind_ex(m: Map, idx: usize, plt: bool, copy: bool, audit: bool) -> Option<Resolved> {
    // SAFETY: `idx` is a symbol of `m` (caller's contract).
    let sym = unsafe { m.sym(idx) };
    let bindt = sym.info >> 4;
    let vis = sym.other & 3;
    if bindt == STB_LOCAL || vis != STV_DEFAULT {
        let mut addr = sym_value_addr(m.l_addr(), sym);
        // a protected (or hidden) indirect function bound to its own object is still an indirect function: the value is what
        // its resolver returns (glibc's elf_machine_rela calls the resolver for every defined STT_GNU_IFUNC symbol)
        if sym.info & 0xf == STT_GNU_IFUNC && sym.shndx != 0 && !NOIFUNC.load(Relaxed) && !copy {
            // SAFETY: a defined STT_GNU_IFUNC symbol's address is its resolver; resolvers may run (caller's contract).
            addr = unsafe { call_resolver(addr) };
        }
        return Some(Resolved { sym, map: Some(m), addr });
    }
    let (name, hash) = m.sym_name(sym).bytes_gnu_hash();
    // SAFETY: `idx` is a symbol of `m` (caller's contract).
    let ver = unsafe { ref_version(m, idx) };
    let g = global_scope(m);
    let own = own_scope(m);
    let xs = extra_scope(m);
    let f = Flags { plt, skip: if copy { Some(m) } else { None }, newest: false };
    let scopes: [&[Map]; 3] = if m.deepbind() { [own, xs, g] } else { [g, own, xs] };
    let found = lookup_hashed(name, hash, ver.as_ref(), &scopes, &f);
    if crate::ldebug::mask() & (crate::ldebug::SYMBOLS | crate::ldebug::BINDINGS | crate::ldebug::STATISTICS) != 0 {
        debug_lookup(Some(m), false, name, ver.as_ref(), &scopes, f.skip, found);
    }
    if let Some(found) = found {
        let mut addr = sym_addr(&found);
        let t = found.sym.info & 0xf;
        if t == STT_GNU_IFUNC && !NOIFUNC.load(Relaxed) {
            // SAFETY: the address of an STT_GNU_IFUNC definition is its resolver; resolvers may run (caller's contract).
            addr = unsafe { call_resolver(addr) };
        }
        found.map.set_used(true);
        if audit && plt && !copy && t != STT_TLS && crate::audit::active() {
            addr = crate::audit::symbind(found.sym, Some(found.map), Some(m), name, addr, plt);
        }
        // a binding into a dlopen()ed library this one does not need (RTLD_GLOBAL): pins it or becomes a reference
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
    if crate::ldebug::errors_on() {
        crate::ldebug::lookup_error(m, name, ver.as_ref().map(|v| v.name.bytes()));
    }
    if ver.is_some() {
        set_error_occ("symbol lookup error", describe(m), 0, format_args!("undefined symbol: {}, version {}", Bytes(name), Bytes(vname)));
    } else {
        set_error_occ("symbol lookup error", describe(m), 0, format_args!("undefined symbol: {}", Bytes(name)));
    }
    None
}

/// `LD_DEBUG=symbols`, `bindings` and `statistics` for one lookup (glibc's `_dl_lookup_symbol_x`): the objects searched,
/// the binding, the count.
#[cold]
#[inline(never)]
pub(crate) fn debug_lookup(undef: Option<Map>, protected: bool, name: &[u8], ver: Option<&VerRef>, scopes: &[&[Map]], skip: Option<Map>, found: Option<Found>) {
    use crate::ldebug;
    let dm = ldebug::mask();
    if dm & ldebug::STATISTICS != 0 {
        ldebug::count_relocation();
    }
    if dm & ldebug::SYMBOLS != 0 {
        ldebug::symbol_lookups(name, scopes, skip, found.map(|f| f.map));
    }
    if dm & ldebug::BINDINGS != 0
        && let (Some(u), Some(f)) = (undef, found)
    {
        ldebug::binding(u, f.map, protected, name, ver.map(|v| v.name.bytes()));
    }
}

/// Where lenient binding sends calls to symbols nobody defines.
extern "C" fn unresolved_stub() -> ! {
    crate::eprint!("{}: call to an unresolved symbol (see the warnings above)\n", Bytes(prog_name()));
    crate::sys::exit(127)
}

/// # Safety
/// `m` is mapped writable where its RELR table points (relocation time).
unsafe fn apply_relr(m: Map) {
    let base = m.l_addr() as u64;
    let mut w: *mut u64 = core::ptr::null_mut();
    for &e in m.relrs() {
        if e & 1 == 0 {
            w = (m.l_addr() + e as usize) as *mut u64;
            // SAFETY: an address entry of the object's RELR table: a word of its writable data (caller's contract).
            let v = unsafe { *w };
            // SAFETY: as above.
            unsafe { *w = v.wrapping_add(base) };
            w = w.wrapping_add(1);
        } else {
            let mut bits = e >> 1;
            while bits != 0 {
                let p = w.wrapping_add(bits.trailing_zeros() as usize);
                // SAFETY: a bitmap entry names words that follow the last address entry, inside the object's data.
                let v = unsafe { *p };
                // SAFETY: as above.
                unsafe { *p = v.wrapping_add(base) };
                bits &= bits - 1;
            }
            w = w.wrapping_add(63);
        }
    }
}

/// Apply one relocation entry. False after recording an error.
///
/// # Safety
/// `r` is an entry of `m`'s relocation tables and `m` is being relocated (its segments writable where they must be).
unsafe fn apply(m: Map, r: &Rela, plt_table: bool) -> bool {
    let ty = (r.info & 0xffff_ffff) as u32;
    let idx = (r.info >> 32) as usize;
    let place = (m.l_addr() + r.offset as usize) as *mut u64;
    let a = r.addend as u64;
    let l = m.l_addr() as u64;
    // SAFETY (for every `unsafe` below that reads or writes `place` or `place + 1`): the relocation's target, a word (two
    // for TLSDESC) of the object's own data, writable while it is relocated (caller's contract); `idx` is a symbol of `m`.
    match ty {
        R_X86_64_NONE => {}
        // SAFETY: see above.
        R_X86_64_RELATIVE => unsafe { *place = l.wrapping_add(a) },
        R_X86_64_IRELATIVE => {
            // SAFETY: an IRELATIVE addend is the object's own resolver; the object is relocated up to its IRELATIVE
            // entries, which come last.
            let v = unsafe { call_resolver(l.wrapping_add(a) as usize) } as u64;
            // SAFETY: see above.
            unsafe { *place = v };
        }
        R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            // lazy binding: a PLT slot initially holds the address of its PLT stub (link-time offset), which pushes the
            // relocation index and enters _dl_runtime_resolve through PLT0 and GOT[2]; relocating it is just a rebase
            if ty == R_X86_64_JUMP_SLOT && idx != 0 && m.lazy_plt() && !m.pltgot().is_null() {
                // SAFETY: see above.
                let v = unsafe { *place };
                // SAFETY: see above.
                unsafe { *place = v.wrapping_add(l) };
                m.set_lazy_pending(true);
                return true;
            }
            if idx == 0 {
                // SAFETY: see above.
                unsafe { *place = if ty == R_X86_64_64 { l.wrapping_add(a) } else { 0 } };
                return true;
            }
            // SAFETY: see above (bind's contract: a symbol of `m`, resolvers may run during relocation).
            match unsafe { bind(m, idx, ty == R_X86_64_JUMP_SLOT, false) } {
                // SAFETY: see above.
                Some(res) => unsafe { *place = if ty == R_X86_64_64 { (res.addr as u64).wrapping_add(a) } else { res.addr as u64 } },
                None => {
                    // a PLT slot of an object that is not bound at load time stays lazy: the call fails when (if) made
                    if ty == R_X86_64_JUMP_SLOT && m.lazy_plt() && !m.pltgot().is_null() {
                        // SAFETY: see above.
                        let v = unsafe { *place };
                        // SAFETY: see above.
                        unsafe { *place = v.wrapping_add(l) };
                        m.set_lazy_pending(true);
                    } else {
                        return false;
                    }
                }
            }
        }
        R_X86_64_SIZE64 => {
            // SAFETY: see above.
            let sz = if idx == 0 { 0 } else { unsafe { m.sym(idx) }.size };
            // SAFETY: see above.
            let Some(res) = (if idx == 0 { None } else { unsafe { bind(m, idx, false, false) } }) else {
                // SAFETY: see above.
                unsafe { *place = sz.wrapping_add(a) };
                return true;
            };
            // SAFETY: see above.
            unsafe { *place = res.sym.size.wrapping_add(a) };
        }
        R_X86_64_COPY => {
            // SAFETY: see above.
            let Some(res) = (unsafe { bind(m, idx, false, true) }) else { return false };
            let Some(rmap) = res.map else { return true };
            // the copy must see initialised data: the library that defines the variable may not be relocated yet when the
            // copies are made early (audit libraries that do not need libc.so.6 leave it for the normal pass)
            // SAFETY: the defining object is loaded and its own dependencies come before it (relocate's contract).
            if !rmap.relocated() && !rmap.is_ldso() && rmap != m && !unsafe { relocate(rmap) } {
                return false;
            }
            // SAFETY: see above.
            let n = unsafe { m.sym(idx) }.size.min(res.sym.size) as usize;
            // SAFETY: the definition's data (`n` bytes, at most its size) in another, relocated object, and the program's
            // space for its copy (at most its own symbol's size): two different objects.
            unsafe { core::ptr::copy_nonoverlapping(res.addr as *const u8, place as *mut u8, n) };
        }
        R_X86_64_DTPMOD64 => {
            let v = if idx == 0 {
                m.tls_modid() as u64
            } else {
                // SAFETY: see above.
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                res.map.map_or(0, |rm| rm.tls_modid() as u64)
            };
            // SAFETY: see above.
            unsafe { *place = v };
        }
        R_X86_64_DTPOFF64 => {
            let v = if idx == 0 {
                0
            } else {
                // SAFETY: see above.
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                if res.map.is_none() { 0 } else { res.sym.value }
            };
            // SAFETY: see above.
            unsafe { *place = v.wrapping_add(a) };
        }
        R_X86_64_TPOFF64 => {
            let (map, v) = if idx == 0 {
                (m, 0)
            } else {
                // SAFETY: see above.
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                let Some(rm) = res.map else {
                    // SAFETY: see above.
                    unsafe { *place = 0 };
                    return true;
                };
                (rm, res.sym.value)
            };
            if !map.tls_static() && !tls::add_static_late(map) {
                set_error_at(describe(m), 0, format_args!("cannot allocate memory in static TLS block"));
                return false;
            }
            // SAFETY: see above.
            unsafe { *place = v.wrapping_add(a).wrapping_sub(map.tls_offset() as u64) };
        }
        R_X86_64_TLSDESC => {
            let target = if idx == 0 {
                Some((m, 0))
            } else {
                // SAFETY: see above.
                let Some(res) = (unsafe { bind(m, idx, false, false) }) else { return false };
                res.map.map(|rm| (rm, res.sym.value))
            };
            let (f, arg) = match target {
                None => (tls::_dl_tlsdesc_return as *const () as usize as u64, 0),
                Some((map, v)) if map.tls_static() => (tls::_dl_tlsdesc_return as *const () as usize as u64, v.wrapping_add(a).wrapping_sub(map.tls_offset() as u64)),
                Some((map, v)) => {
                    // the trampoline's save area is measured before its first descriptor exists
                    crate::plt::init_xsave_size();
                    let ti = alloc_perm(core::mem::size_of::<tls::TlsIndex>(), 8) as *mut tls::TlsIndex;
                    // SAFETY: a fresh permanent block for a `TlsIndex`, ours alone (read by `_dl_tlsdesc_dynamic` later).
                    unsafe { ti.write(tls::TlsIndex { module: map.tls_modid(), offset: v.wrapping_add(a) as usize }) };
                    (tls::_dl_tlsdesc_dynamic as *const () as usize as u64, ti as u64)
                }
            };
            // SAFETY: see above (a TLSDESC target is two words: function and argument).
            unsafe { place.write(f) };
            // SAFETY: see above.
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

/// Relocate `m` completely (RELA, RELR, PLT). False after recording an error.
///
/// # Safety
/// `m` is a mapped object of the loader's lists, relocated in glibc's order (the objects its IFUNC resolvers and COPY
/// relocations depend on first), at start-up or under the loader lock.
pub unsafe fn relocate(m: Map) -> bool {
    if m.relocated() {
        return true;
    }
    // DT_TEXTREL: relocations that write into read-only segments (glibc: PROT_READ|PROT_WRITE, executable bit kept)
    let textrel = m.textrel();
    if textrel && !make_text_writable(m, true) {
        return false;
    }
    // SAFETY: `m` is a mapped object being relocated once (its `relocated` flag is still clear); its writable segments (and,
    // for DT_TEXTREL, the others) are writable now.
    let ok = unsafe { relocate_body(m) };
    if textrel {
        make_text_writable(m, false);
    }
    if ok {
        tls::after_relocate(m);
    }
    ok
}

/// Make the read-only PT_LOAD segments of `m` writable (`writable`) or restore their protection.
fn make_text_writable(m: Map, writable: bool) -> bool {
    for p in m.phdrs() {
        if p.typ != PT_LOAD || p.flags & PF_W != 0 {
            continue;
        }
        let start = m.l_addr() + (p.vaddr as usize & !(sys::PAGE - 1));
        let end = (m.l_addr() + (p.vaddr + p.memsz) as usize + sys::PAGE - 1) & !(sys::PAGE - 1);
        let orig = (if p.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if p.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
        let prot = if writable { orig | sys::PROT_WRITE | sys::PROT_READ } else { orig };
        // SAFETY: one of the object's own read-only segments: adding write access takes nothing away; taking it back after
        // relocation restores what the object asked for (nothing writes there afterwards).
        let r = unsafe { sys::mprotect(start, end - start, prot) };
        if r < 0 && writable {
            set_error_at(describe(m), if r == -13 { 13 } else { 12 }, format_args!("cannot make segment writable for relocation"));
            return false;
        }
    }
    true
}

/// TSC cycles spent per relocation phase over all objects: RELR, RELA and PLT slots (LD_DEBUG=statistics). (Populating the
/// writable segment with MADV_POPULATE_WRITE first was tried and cost more than the page faults of the pages that
/// relocation really writes.)
pub static PHASE_CYCLES: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

fn add_cycles(i: usize, c: u64) {
    PHASE_CYCLES[i].store(PHASE_CYCLES[i].load(Relaxed).wrapping_add(c), Relaxed);
}

/// GOT[1] (the link map) and GOT[2] (the resolver) of an object with lazy PLT slots.
///
/// # Safety
/// `m` has a PLT GOT (`pltgot` not NULL) and is being relocated.
unsafe fn setup_lazy_got(m: Map) {
    let got = m.pltgot();
    // SAFETY: GOT[1] of the object's PLT GOT, writable during relocation (caller's contract).
    unsafe { *got.wrapping_add(1) = m.as_ptr() as usize };
    let resolver = if crate::plt::wanted() {
        // LD_PROFILE or LD_AUDIT: every lazy PLT goes through the profiling trampoline and its slots are never patched
        if crate::profile::enabled() {
            crate::profile::note_map(m);
        }
        crate::plt::init_vector_level();
        crate::plt::_dl_runtime_profile as *const () as usize
    } else {
        _dl_runtime_resolve as *const () as usize
    };
    // SAFETY: GOT[2], as above.
    unsafe { *got.wrapping_add(2) = resolver };
}

/// Does `m` get lazy PLT binding? glibc's rule (_dl_relocate_object): not with LD_BIND_NOW or for a dlopen with RTLD_NOW; an object
/// marked bind-now is bound at load time too, unless audit libraries with PLT hooks (la_pltenter / la_pltexit) are installed:
/// then it stays lazy so that every call reaches the hooks (the audit libraries themselves are bound at load time).
fn lazy_plt_decide(m: Map) -> bool {
    (!st().bind_now_env || crate::profile::enabled()) && !m.rtld_now() && (!m.bind_now() || crate::audit::plt_hooks_for(m))
}

/// # Safety
/// As [`relocate`]'s inner call: `m` mapped, not relocated yet, its segments writable.
unsafe fn relocate_body(m: Map) -> bool {
    m.set_lazy_plt(lazy_plt_decide(m));
    if crate::ldebug::on(crate::ldebug::RELOC) {
        crate::ldebug::relocation(m, m.lazy_plt());
    }
    // SAFETY: reading the time-stamp counter has no memory effects.
    let t1 = unsafe { core::arch::x86_64::_rdtsc() };
    // an IRELATIVE resolver (an ifunc of the object itself) may call through this object's lazy PLT before the PLT
    // slots are processed: the resolver entry in GOT[2] must be there already (glibc's elf_machine_runtime_setup)
    if m.pltrelsz() != 0 && !m.pltgot().is_null() && m.lazy_plt() {
        // SAFETY: the object has a PLT GOT and is being relocated (caller's contract).
        unsafe { setup_lazy_got(m) };
    }
    if m.relrsz() != 0 {
        // SAFETY: being relocated (caller's contract).
        unsafe { apply_relr(m) };
    }
    // SAFETY: as above.
    let t2 = unsafe { core::arch::x86_64::_rdtsc() };
    add_cycles(1, t2 - t1);
    let relas = m.relas();
    // COPY relocations last among the ordinary ones is not required; IRELATIVE entries in .rela.dyn go last
    for r in relas {
        let ty = (r.info & 0xffff_ffff) as u32;
        if ty == R_X86_64_IRELATIVE {
            continue;
        }
        // SAFETY: an entry of `m`'s table; being relocated (caller's contract).
        if !unsafe { apply(m, r, false) } {
            return false;
        }
    }
    for r in relas {
        // SAFETY: as above.
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
            // SAFETY: as above.
            if !unsafe { apply(m, r, true) } {
                return false;
            }
        }
    }
    // SAFETY: as above.
    add_cycles(2, unsafe { core::arch::x86_64::_rdtsc() } - t2);
    if m.lazy_pending() {
        // SAFETY: lazy slots were left, so the object has a PLT GOT; being relocated.
        unsafe { setup_lazy_got(m) };
    }
    m.set_relocated(true);
    true
}

/// The PLT stub of a slot left lazy pushes the relocation index, PLT0 pushes the link map and jumps here. We try to
/// bind the symbol now (it may have appeared with a dlopen); if it is still undefined the process ends with glibc's message.
///
/// # Safety
/// Entered only from PLT0 of an object `setup_lazy_got` set up (never called from Rust).
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

/// # Safety
/// Called by `_dl_runtime_resolve` with the link map PLT0 pushed (GOT[1], set by `setup_lazy_got`) and the index of the
/// PLT relocation of the slot that was called.
unsafe extern "C" fn resolve_lazy(m: *mut LinkMap, idx: usize) -> usize {
    // SAFETY: GOT[1] holds the address of the object's link map (caller's contract).
    let Some(m) = (unsafe { Map::from_ptr(m) }) else { crate::sys::exit(127) };
    let r = &m.jmprels()[idx];
    let symidx = (r.info >> 32) as usize;
    // SAFETY: the symbol of one of the object's PLT relocations; the program is running, so resolvers may run.
    match unsafe { bind(m, symidx, true, false) } {
        Some(res) => {
            let place = (m.l_addr() + r.offset as usize) as *mut usize;
            // SAFETY: the PLT slot (GOT entry) of that relocation, writable (lazy slots are outside RELRO).
            unsafe { *place = res.addr };
            res.addr
        }
        None => {
            crate::eprint!("{}: {}\n", Bytes(prog_name()), Bytes(error_str()));
            crate::sys::exit(127)
        }
    }
}
