//! rtld-audit interface (LD_AUDIT, --audit); the PLT trampoline for `la_pltenter`/`la_pltexit` is in plt.rs.
//!
//! Supported: `la_version` (negotiation; a library asking for more than version 2, or returning 0, is dropped with
//! glibc's message), `la_activity` (ADD/CONSISTENT around start-up and around every dlopen, DELETE/CONSISTENT around
//! dlclose), `la_objopen` (for the program, every library and the loader, with the BINDTO/BINDFROM flags honoured),
//! `la_preinit` (after relocation and the audit libraries' own initialisation, before the other constructors),
//! `la_symbind64` (for every symbol bound lazily through a PLT slot and for everything bound after start-up) and
//! `la_objclose` (dlclose and exit), `la_objsearch` (the name a library is looked for under, and every candidate path), `la_x86_64_gnu_pltenter` and `la_x86_64_gnu_pltexit` (every lazily bound PLT call).
//!
//! Each audit library is loaded into a namespace of its own (as glibc does), so it and what it needs, a copy of libc.so.6
//! included, never bind to the program's symbols (a program's own malloc is not reached from audit code) and never interpose
//! on them; `dlmopen` cannot name such a namespace. Not supported:
//! `la_symbind64` / the PLT hooks for symbols the loader binds at start-up (-z now objects:
//! the audit library is not yet initialised then).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::ffi::CStrRef;
use crate::lookup::*;
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::util::*;
use core::ffi::CStr;
use core::ptr::null_mut;

pub const LAV_CURRENT: u32 = 2;
pub const LA_SER_ORIG: u32 = 0x01;
pub const LA_SER_LIBPATH: u32 = 0x02;
pub const LA_SER_RUNPATH: u32 = 0x04;
pub const LA_SER_CONFIG: u32 = 0x08;
pub const LA_SER_DEFAULT: u32 = 0x40;
pub const LA_ACT_CONSISTENT: u32 = 0;
pub const LA_ACT_ADD: u32 = 1;
pub const LA_ACT_DELETE: u32 = 2;
pub const LA_FLG_BINDTO: u32 = 1;
pub const LA_FLG_BINDFROM: u32 = 2;
pub const MAX_AUDIT: usize = 8;

// The rtld-audit entry points (glibc's <link.h>), as an audit library defines them.
type VersionFn = unsafe extern "C" fn(u32) -> u32;
type ObjsearchFn = unsafe extern "C" fn(*const u8, *mut usize, u32) -> *const u8;
type ActivityFn = unsafe extern "C" fn(*mut usize, u32);
type ObjopenFn = unsafe extern "C" fn(*mut LinkMap, isize, *mut usize) -> u32;
type PreinitFn = unsafe extern "C" fn(*mut usize);
type Symbind64Fn = unsafe extern "C" fn(*const Sym, u32, *mut usize, *mut usize, *mut u32, *const u8) -> usize;
type ObjcloseFn = unsafe extern "C" fn(*mut usize) -> u32;
type PltEnter = unsafe extern "C" fn(*mut Sym, u32, *mut usize, *mut usize, *mut Regs, *mut u32, *const u8, *mut isize) -> usize;
type PltExit = unsafe extern "C" fn(*mut Sym, u32, *mut usize, *mut usize, *const Regs, *mut Retval, *const u8) -> u32;

#[derive(Clone, Copy)]
pub struct Lib {
    pub map: Option<Map>,
    pub version: u32,
    f_objsearch: Option<ObjsearchFn>,
    f_activity: Option<ActivityFn>,
    f_objopen: Option<ObjopenFn>,
    f_preinit: Option<PreinitFn>,
    f_symbind64: Option<Symbind64Fn>,
    f_objclose: Option<ObjcloseFn>,
    f_pltenter: Option<PltEnter>,
    f_pltexit: Option<PltExit>,
}

const NO_LIB: Lib = Lib { map: None, version: 0, f_objsearch: None, f_activity: None, f_objopen: None, f_preinit: None, f_symbind64: None, f_objclose: None, f_pltenter: None, f_pltexit: None };

pub const LA_SYMB_NOPLTENTER: u32 = 1;
pub const LA_SYMB_NOPLTEXIT: u32 = 2;
pub const LA_SYMB_DLSYM: u32 = 0x08;
pub const LA_SYMB_ALTVALUE: u32 = 0x10;

pub struct Audit {
    pub libs: [Lib; MAX_AUDIT],
    pub n: usize,
    /// Set once the audit libraries are initialised and `la_version` was answered: callbacks only happen from then on.
    pub ready: bool,
    /// Maps mapped for the audit libraries and their dependencies, in their namespaces (the loader's mirrors not counted).
    maps: [Option<Map>; 64],
    pub nmaps: usize,
    /// The namespaces of the audit libraries, one bit each (glibc marks their maps `l_auditing`).
    pub ns_mask: u32,
}

impl Audit {
    /// The maps of the audit libraries' namespaces, in load order.
    pub fn maps(&self) -> impl DoubleEndedIterator<Item = Map> + '_ {
        self.maps[..self.nmaps].iter().flatten().copied()
    }
}

static AUDIT: SyncCell<Audit> = SyncCell::new(Audit { libs: [NO_LIB; MAX_AUDIT], n: 0, ready: false, maps: [None; 64], nmaps: 0, ns_mask: 0 });

/// Is namespace `ns` an audit library's?
#[inline(always)]
pub fn is_audit_ns(ns: usize) -> bool {
    au().ns_mask >> ns & 1 != 0
}

/// The audit libraries. Rule: set up at start-up (one thread); afterwards only `ready` changes (at exit, `finish`) and the
/// records are read.
#[inline(always)]
pub fn au() -> &'static mut Audit {
    // SAFETY: AUDIT is a static (lives for ever); written at start-up only (rule above).
    unsafe { &mut *AUDIT.as_ptr() }
}

#[inline(always)]
pub fn active() -> bool {
    au().ready && au().n != 0
}

/// Does any audit library want `la_objsearch`?
#[inline(always)]
pub fn wants_objsearch() -> bool {
    active() && au().libs[..au().n].iter().any(|l| l.f_objsearch.is_some())
}

/// glibc's `_dl_audit_objsearch`: every audit library with `la_objsearch` may replace the name a library is searched or
/// opened under (`code`: the `LA_SER_*` flag); null means "do not load this". Nothing happens for a loader that is
/// None or belongs to the audit libraries themselves, or for code 0.
pub fn objsearch(name: &CStr, l: Option<Map>, code: u32) -> *const u8 {
    let mut name = name.as_ptr() as *const u8;
    let Some(l) = l else { return name };
    if code == 0 || !wants_objsearch() || is_audit_map(l) {
        return name;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_objsearch {
            // SAFETY: the audit library's la_objsearch, with the name (a NUL-terminated string), the object's cookie and
            // the flag (the rtld-audit interface).
            name = unsafe { f(name, l.audit_cookie_ptr(i), code) };
            if name.is_null() {
                return name;
            }
        }
    }
    name
}

/// The address of `name` in the audit library `m` alone (0: not defined).
fn find_fn(m: Map, name: &[u8]) -> usize {
    let own = [m];
    let fl = Flags { plt: false, skip: None, newest: false };
    match lookup(name, None, &[&own], &fl) {
        Some(f) => sym_addr(&f),
        None => 0,
    }
}

/// An audit entry point of `m` with the C type `F` (None when the library does not define it).
///
/// # Safety
/// `F` is the function pointer type the rtld-audit interface gives `name`.
unsafe fn audit_fn<F: Copy>(m: Map, name: &[u8]) -> Option<F> {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    let a = find_fn(m, name);
    // SAFETY: a function's address in the audit library, as the function pointer type `F` (caller's contract; same size).
    if a == 0 { None } else { Some(unsafe { core::mem::transmute_copy::<usize, F>(&a) }) }
}

/// Map the audit libraries named in `list` (':' separated), each with what it needs into a new namespace (glibc loads
/// them with `LM_ID_NEWLM`). Failures are reported with glibc's wording and the library is skipped.
pub fn load(list: &[u8], from_option: bool) {
    for name in list.split(|&c| c == b':' || c == b' ') {
        if name.is_empty() || au().n >= MAX_AUDIT {
            continue;
        }
        let Some(nsid) = crate::dl::new_namespace() else {
            set_error_at(name, 22, format_args!("no more namespaces available for dlmopen()"));
            report_fail(name, from_option);
            continue;
        };
        au().ns_mask |= 1 << nsid;
        crate::debug_initialize(nsid);
        let m = load_library(nsid, name, None);
        let Some(m) = m.filter(|&m| load_deps(m)) else {
            report_fail(name, from_option);
            // the namespace is given up again
            crate::dl::discard_from(ns(nsid).head);
            au().ns_mask &= !(1 << nsid);
            trim_nns();
            continue;
        };
        for cur in ns(nsid).maps() {
            if au().nmaps < 64 && !cur.is_ldso() {
                let k = au().nmaps;
                au().maps[k] = Some(cur);
                au().nmaps += 1;
                cur.set_nodelete(true);
                cur.set_refcount(cur.refcount() + 1);
            }
        }
        crate::build_scope(m);
        // like dlmopen: the new maps relocate against their namespace's global scope (empty), then the scope of the audit library
        for cur in ns(nsid).maps() {
            if cur.scope_ptr().is_null() {
                // SAFETY: `m`'s scope array (maps of this namespace) with its count.
                unsafe { cur.set_scope(m.scope_ptr()) };
                // SAFETY: as above.
                unsafe { cur.set_nscope(m.nscope()) };
            }
        }
        let mut l = NO_LIB;
        l.map = Some(m);
        let k = au().n;
        au().libs[k] = l;
        au().n += 1;
    }
}

fn report_fail(name: &[u8], _from_option: bool) {
    let e = error_str();
    let e = e.strip_prefix(name).and_then(|r| r.strip_prefix(b": ")).unwrap_or(e);
    let reason: &[u8] = if e.starts_with(b"cannot open shared object file") { b"cannot open shared object file" } else { e };
    crate::eprint!("ERROR: ld.so: object '{}' cannot be loaded as audit interface: {}; ignored.\n", Bytes(name), Bytes(reason));
}

/// Load the DT_NEEDED closure of `m` (the maps appear at the end of the list; nothing is added to the global scope).
fn load_deps(m: Map) -> bool {
    let mut cur = Some(m);
    while let Some(c) = cur {
        if !c.is_ldso() && c.needed_ptr().is_null() && !crate::load_needed(c, false, |_| {}) {
            return false;
        }
        cur = c.next();
    }
    true
}

/// After the audit libraries are initialised (and before the program's own relocation, so that `la_symbind64` sees the
/// bindings made at start-up): version handshake, then the start-up notifications `la_objopen` and `la_activity`.
///
/// # Safety
/// Start-up, after the audit libraries' namespaces are relocated and initialised (their code may run).
pub unsafe fn announce_open() {
    // la_version
    let mut kept = 0usize;
    for i in 0..au().n {
        let mut l = au().libs[i];
        let Some(lm) = l.map else { continue };
        // SAFETY: la_version's type in the rtld-audit interface.
        let Some(fv) = (unsafe { audit_fn::<VersionFn>(lm, b"la_version") }) else {
            // glibc: a library without la_version is not an audit module
            crate::eprint!("ERROR: ld.so: object '{}' cannot be loaded as audit interface: undefined symbol: la_version; ignored.\n", Bytes(lm.name()));
            continue;
        };
        // SAFETY: the library's la_version (relocated and initialised: caller's contract).
        let v = unsafe { fv(LAV_CURRENT) };
        if v == 0 || v > LAV_CURRENT {
            crate::eprint!("ERROR: audit interface '{}' requires version {} (maximum supported version {}); ignored.\n", Bytes(lm.name()), v, LAV_CURRENT);
            continue;
        }
        l.version = v;
        // SAFETY: the entry point's type in the rtld-audit interface (the same for the lookups below).
        l.f_objsearch = unsafe { audit_fn(lm, b"la_objsearch") };
        // SAFETY: as above.
        l.f_activity = unsafe { audit_fn(lm, b"la_activity") };
        // SAFETY: as above.
        l.f_objopen = unsafe { audit_fn(lm, b"la_objopen") };
        // SAFETY: as above.
        l.f_preinit = unsafe { audit_fn(lm, b"la_preinit") };
        // SAFETY: as above.
        l.f_symbind64 = unsafe { audit_fn(lm, b"la_symbind64") };
        // SAFETY: as above.
        l.f_objclose = unsafe { audit_fn(lm, b"la_objclose") };
        // SAFETY: as above.
        l.f_pltenter = unsafe { audit_fn(lm, b"la_x86_64_gnu_pltenter") };
        // SAFETY: as above.
        l.f_pltexit = unsafe { audit_fn(lm, b"la_x86_64_gnu_pltexit") };
        au().libs[kept] = l;
        kept += 1;
    }
    au().n = kept;
    au().ready = kept != 0;
    if kept == 0 {
        return;
    }
    // glibc's order: the program and the loader are announced first, then la_activity(ADD), then the libraries in load order
    objopen(main_map());
    objopen(ldso_map());
    activity(LA_ACT_ADD);
    for cur in ns(0).maps() {
        if !is_audit_map(cur) && !cur.is_main() && !cur.is_ldso() {
            objopen(cur);
        }
    }
    activity(LA_ACT_CONSISTENT);
}

/// `la_preinit`: after relocation, before the constructors of the program's libraries.
pub fn announce_preinit() {
    if !active() {
        return;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_preinit {
            // SAFETY: the library's la_preinit with the program's cookie (rtld-audit interface).
            unsafe { f(main_map().audit_cookie_ptr(i)) };
        }
    }
}

/// glibc's `consider_profiling` for the object `m`: some audit library has `la_x86_64_gnu_pltenter` or `la_x86_64_gnu_pltexit`, and `m`
/// is not in an audit library's namespace.
pub fn plt_hooks_for(m: Map) -> bool {
    active() && au().libs[..au().n].iter().any(|l| l.f_pltenter.is_some() || l.f_pltexit.is_some()) && !is_audit_map(m)
}

/// Is `m` in an audit library's namespace (the library, what it needs, the loader's mirror there)?
pub fn is_audit_map(m: Map) -> bool {
    is_audit_ns(m.l_ns() as usize)
}

/// `la_activity` for the base namespace (its cookie is the program's).
pub fn activity(flag: u32) {
    activity_map(main_map(), flag)
}

/// The map whose cookie stands for namespace `n` in `la_activity` (glibc: the head of the namespace's list): the program for
/// the base namespace, the first map of any other.
pub fn ns_head(n: usize) -> Option<Map> {
    if n == 0 { st().main_map } else { ns(n).head }
}

/// `la_activity` for namespace `nsid`.
pub fn activity_ns(nsid: usize, flag: u32) {
    if let Some(head) = ns_head(nsid) {
        activity_map(head, flag);
    }
}

/// `la_activity` with the cookie of `head` (which may not have been announced yet: glibc's cookie starts as the map's address).
pub fn activity_map(head: Map, flag: u32) {
    if !active() {
        return;
    }
    for i in 0..au().n {
        let l = au().libs[i];
        if !head.audit_opened() {
            head.set_audit_cookie(i, head.as_ptr() as usize);
        }
        if let Some(f) = l.f_activity {
            // SAFETY: the library's la_activity with the namespace head's cookie (rtld-audit interface).
            unsafe { f(head.audit_cookie_ptr(i), flag) };
        }
    }
}

/// The namespace head whose `la_activity(LA_ACT_DELETE)` the running dlclose sent (None: none yet). Under the loader lock.
static CLOSING: SyncCell<Option<Map>> = SyncCell::new(None);

/// A map that dlclose unloads: the first one of the call sends `la_activity(LA_ACT_DELETE)` for its namespace, every one gets
/// its `la_objclose`.
pub fn close_one(m: Map) {
    if !active() || !m.audit_opened() {
        return;
    }
    // SAFETY: CLOSING is used by dlclose only, under the loader lock.
    if unsafe { CLOSING.read() }.is_none() {
        let h = ns_head(m.l_ns() as usize);
        // SAFETY: as above.
        unsafe { CLOSING.write(h) };
        if let Some(h) = h {
            activity_map(h, LA_ACT_DELETE);
        }
    }
    objclose(m);
    m.set_audit_opened(false);
}

/// The end of a dlclose: `la_activity(LA_ACT_CONSISTENT)` with the cookie the DELETE used, if anything was unloaded.
pub fn close_done() {
    // SAFETY: CLOSING is used by dlclose only, under the loader lock.
    if let Some(h) = unsafe { CLOSING.read() } {
        // SAFETY: as above.
        unsafe { CLOSING.write(None) };
        // glibc 2.43 sends no CONSISTENT when the dlclose emptied a whole dlmopen namespace (no head map left; glibc bug
        // 32068, which tst-audit23 documents): the same here
        let n = h.l_ns() as usize;
        if n == 0 || ns(n).head.is_some() {
            activity_map(h, LA_ACT_CONSISTENT);
        }
    }
}

/// `la_objopen` for a newly mapped object (every audit library, in order).
pub fn objopen(m: Map) {
    if !active() {
        return;
    }
    m.set_audit_opened(true);
    make_libnames(m);
    for i in 0..au().n {
        let l = au().libs[i];
        // glibc starts every cookie as the address of the object's link map
        m.set_audit_cookie(i, m.as_ptr() as usize);
        if let Some(f) = l.f_objopen {
            // SAFETY: the library's la_objopen with the link map, its namespace and its cookie (rtld-audit interface).
            let fl = unsafe { f(m.as_ptr(), m.l_ns(), m.audit_cookie_ptr(i)) };
            m.set_audit_flags(i, fl);
            m.set_audit_any_plt(m.audit_any_plt() | (fl != 0));
        }
    }
}

/// glibc's `l_libname` list, which audit libraries (sotruss's) read to name an object: the name it was asked for (the
/// program: empty), then its soname when that is another string.
fn make_libnames(m: Map) {
    if !m.l_libname().is_null() {
        return;
    }
    let first: *const u8 = if m.is_main() {
        c"".as_ptr() as *const u8
    } else if !m.req_name_ptr().is_null() {
        m.req_name_ptr()
    } else {
        m.l_name()
    };
    let a = alloc_perm(core::mem::size_of::<LibName>(), 8) as *mut LibName;
    // SAFETY: a fresh permanent block for a `LibName`, ours alone.
    unsafe { a.write(LibName { name: first, next: null_mut(), dont_free: 1 }) };
    // SAFETY: a list of permanent records whose names live as long as the map (`l_name`, `req_name`, the soname).
    unsafe { m.set_l_libname(a) };
    let first_bytes: &[u8] = if m.is_main() { b"" } else if let Some(r) = m.req_name() { r } else { m.name() };
    if let Some(so) = m.soname()
        && so != first_bytes
    {
        let b = alloc_perm(core::mem::size_of::<LibName>(), 8) as *mut LibName;
        // SAFETY: a fresh permanent block for a `LibName`, ours alone.
        unsafe { b.write(LibName { name: m.soname_ptr(), next: null_mut(), dont_free: 1 }) };
        // SAFETY: the record written just above, not yet visible to anyone else.
        unsafe { (*a).next = b };
    }
}

/// `la_objclose` for an object that is going away.
pub fn objclose(m: Map) {
    if !active() {
        return;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_objclose
            && m.audit_opened()
        {
            // SAFETY: the library's la_objclose with the object's cookie (rtld-audit interface).
            unsafe { f(m.audit_cookie_ptr(i)) };
        }
    }
}

/// A copy of `name` with its NUL in a 256-byte buffer (the name the audit libraries are shown, cut at 255 bytes).
fn name_buf(name: &[u8]) -> [u8; 256] {
    let mut nbuf = [0u8; 256];
    let n = name.len().min(255);
    nbuf[..n].copy_from_slice(&name[..n]);
    nbuf
}

/// `la_symbind64` for a binding of `sym` (a symbol of `defmap`) referenced from `refmap`: returns the address the audit
/// libraries want to be used.
pub fn symbind(sym: &'static Sym, defmap: Option<Map>, refmap: Option<Map>, name: &[u8], mut addr: usize, jmp_slot: bool) -> usize {
    let (Some(defmap), Some(refmap)) = (defmap, refmap) else { return addr };
    if !active() {
        return addr;
    }
    let ndx = defmap.sym_index(sym);
    let nbuf = name_buf(name);
    for i in 0..au().n {
        let Some(f) = au().libs[i].f_symbind64 else { continue };
        // only objects whose la_objopen asked for it (BINDFROM for the referencing object, BINDTO for the definition)
        if refmap.audit_flags(i) & LA_FLG_BINDFROM == 0 || defmap.audit_flags(i) & LA_FLG_BINDTO == 0 {
            continue;
        }
        // a PLT slot bound at start-up is never traced: glibc's flags say so before the library is asked
        let mut flags = if jmp_slot { LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT } else { 0u32 };
        // like glibc: a copy of the symbol whose value is the address about to be used (absolute; for an IFUNC the
        // address the resolver returned), so that `return sym->st_value` leaves the binding as it is
        let mut copy = *sym;
        copy.value = addr as u64;
        // SAFETY: the library's la_symbind64 with the symbol copy, its index, both cookies, the flags and the name
        // (rtld-audit interface); everything lives across the call.
        let new = unsafe { f(&copy, ndx as u32, refmap.audit_cookie_ptr(i), defmap.audit_cookie_ptr(i), &mut flags, nbuf.as_ptr()) };
        if new != 0 {
            addr = new;
        }
    }
    addr
}

/// `_dl_audit_symbind_alt`: `la_symbind64` for an address that dlsym / dlvsym is about to return (`LA_SYMB_DLSYM`), `caller` being the object
/// containing the call (the main program when there is none). A library is asked when the caller asked for BINDFROM or the
/// definition for BINDTO (glibc's test here is an "or"); each library sees the value the previous one returned.
pub fn symbind_dlsym(caller: Option<Map>, sym: &'static Sym, defmap: Map, name: &[u8], addr: usize) -> usize {
    let Some(caller) = caller.or(st().main_map) else { return addr };
    if !active() || !(caller.audit_any_plt() || defmap.audit_any_plt()) {
        return addr;
    }
    let ndx = defmap.sym_index(sym);
    let nbuf = name_buf(name);
    let mut copy = *sym;
    copy.value = addr as u64;
    let mut alt = 0u32;
    for i in 0..au().n {
        let Some(f) = au().libs[i].f_symbind64 else { continue };
        if caller.audit_flags(i) & LA_FLG_BINDFROM != 0 || defmap.audit_flags(i) & LA_FLG_BINDTO != 0 {
            let mut flags = alt | LA_SYMB_DLSYM;
            // SAFETY: as in `symbind`.
            let new = unsafe { f(&copy, ndx as u32, caller.audit_cookie_ptr(i), defmap.audit_cookie_ptr(i), &mut flags, nbuf.as_ptr()) };
            if new as u64 != copy.value {
                alt = LA_SYMB_ALTVALUE;
                copy.value = new as u64;
            }
        }
    }
    copy.value as usize
}

/// `la_objclose` for `m` if it was announced and not closed yet.
pub fn objclose_once(m: Map) {
    if m.audit_opened() {
        objclose(m);
        m.set_audit_opened(false);
    }
}

/// At exit, once every namespace but the audit libraries' own was finished: the audit libraries hear nothing more.
pub fn finish() {
    if active() {
        au().ready = false;
    }
}

// ---- la_pltenter / la_pltexit: the per-slot protocol of glibc's _dl_audit_symbind / _dl_audit_pltenter / _dl_audit_pltexit

/// `La_x86_64_regs`: what a la_pltenter function sees of the call (the registers at the PLT entry).
#[repr(C)]
pub struct Regs {
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rcx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub xmm: [[u8; 16]; 8],
    pub vector: [[u8; 64]; 8],
    pub unused: [u8; 64],
}

/// `La_x86_64_retval`: the return registers a la_pltexit function sees (and may change).
#[repr(C)]
pub struct Retval {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: [u8; 16],
    pub xmm1: [u8; 16],
    pub st0: [u8; 16],
    pub st1: [u8; 16],
    pub vector0: [u8; 64],
    pub vector1: [u8; 64],
    pub unused: [u8; 32],
}

/// `_dl_audit_symbind` for a lazily bound PLT slot: ask every audit library (`la_symbind64`) and work out which of them want
/// `la_pltenter` and `la_pltexit` calls. Returns the address to use, the `enterexit` word (bits 0 and 1: nobody wants
/// enter / exit; two bits per audit library from bit 2 on) and the flags the libraries left.
pub fn symbind_slot(sym: &'static Sym, defmap: Map, refmap: Map, name: &[u8], addr: usize) -> (usize, u32, u32) {
    if !active() || !(refmap.audit_any_plt() || defmap.audit_any_plt()) {
        // "not interesting": every bit set
        return (addr, 0xffff, 0);
    }
    let ndx = defmap.sym_index(sym);
    let nbuf = name_buf(name);
    let mut copy = *sym;
    copy.value = addr as u64;
    let mut enterexit = 3u32;
    let mut flags = 0u32;
    for i in 0..au().n {
        let l = au().libs[i];
        if refmap.audit_flags(i) & LA_FLG_BINDFROM != 0 && defmap.audit_flags(i) & LA_FLG_BINDTO != 0 {
            if let Some(f) = l.f_symbind64 {
                // SAFETY: as in `symbind`.
                let new = unsafe { f(&copy, ndx as u32, refmap.audit_cookie_ptr(i), defmap.audit_cookie_ptr(i), &mut flags, nbuf.as_ptr()) };
                if new as u64 != copy.value {
                    flags |= LA_SYMB_ALTVALUE;
                    copy.value = new as u64;
                }
            }
            enterexit &= flags & 3;
            enterexit |= (flags & 3) << ((i + 1) * 2);
        } else {
            enterexit |= 3 << ((i + 1) * 2);
        }
    }
    (copy.value as usize, enterexit, flags)
}

/// The symbol `ndx` of `bound` and its name, for the PLT hooks.
fn plt_sym(bound: Map, ndx: u32) -> (&'static Sym, CStrRef) {
    // SAFETY: `ndx` was computed from a symbol `bind` found in `bound` (plt.rs keeps it with the slot).
    let defsym = unsafe { bound.sym(ndx as usize) };
    (defsym, bound.sym_name(defsym))
}

/// `_dl_audit_pltenter`: call every interested library's la_pltenter; they may change the address to call (`value`) and ask
/// for the stack arguments to be copied (`framesize`: -1 none, otherwise the number of bytes, which also asks for la_pltexit).
///
/// # Safety
/// `regs` is the trampoline's register block (`La_x86_64_regs`), valid for the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn pltenter(m: Map, bound: Option<Map>, ndx: u32, enterexit: &mut u32, slot_flags: u32, value: &mut usize, regs: *mut Regs, framesize: &mut isize) {
    let Some(bound) = bound else { return };
    if !active() || *enterexit & LA_SYMB_NOPLTENTER != 0 {
        return;
    }
    let (defsym, name) = plt_sym(bound, ndx);
    let mut sym = *defsym;
    sym.value = *value as u64;
    let mut flags = slot_flags;
    for i in 0..au().n {
        let l = au().libs[i];
        let Some(f) = l.f_pltenter else { continue };
        if *enterexit & (LA_SYMB_NOPLTENTER << (2 * (i + 1))) == 0 {
            let mut new_framesize: isize = -1;
            // SAFETY: the library's la_x86_64_gnu_pltenter with the symbol copy, both cookies, the registers (caller's
            // contract), the flags, the name and the frame size word (rtld-audit interface).
            let new = unsafe { f(&mut sym, ndx, m.audit_cookie_ptr(i), bound.audit_cookie_ptr(i), regs, &mut flags, name.as_ptr(), &mut new_framesize) };
            if new as u64 != sym.value {
                flags |= LA_SYMB_ALTVALUE;
                sym.value = new as u64;
            }
            *enterexit |= (flags & 3) << (2 * (i + 1));
            if *enterexit & (LA_SYMB_NOPLTEXIT << (2 * (i + 1))) == 0 && new_framesize != -1 && *framesize != -2 {
                if *framesize == -1 {
                    *framesize = new_framesize;
                } else if new_framesize != *framesize {
                    *framesize = new_framesize.max(*framesize);
                }
            }
        }
    }
    *value = sym.value as usize;
}

/// `_dl_audit_pltexit`: after the function returned (only when some la_pltenter asked for it with a frame size).
///
/// # Safety
/// `inregs` and `outregs` are the trampoline's register blocks, valid for the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn pltexit(m: Map, bound: Option<Map>, ndx: u32, enterexit: u32, addr: usize, inregs: *const Regs, outregs: *mut Retval) {
    let Some(bound) = bound else { return };
    if !active() {
        return;
    }
    let (defsym, name) = plt_sym(bound, ndx);
    let mut sym = *defsym;
    sym.value = addr as u64;
    for i in 0..au().n {
        let l = au().libs[i];
        let Some(f) = l.f_pltexit else { continue };
        // (glibc tests LA_SYMB_NOPLTEXIT >> (2 * cnt): the summary bit for the first library, nothing for the others)
        if enterexit & (LA_SYMB_NOPLTEXIT >> (2 * i)) == 0 {
            // SAFETY: the library's la_x86_64_gnu_pltexit with the symbol copy, both cookies, the registers (caller's
            // contract) and the name (rtld-audit interface).
            unsafe { f(&mut sym, ndx, m.audit_cookie_ptr(i), bound.audit_cookie_ptr(i), inregs, outregs, name.as_ptr()) };
        }
    }
}
