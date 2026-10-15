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
    pub ready: bool,
    maps: [Option<Map>; 64],
    pub nmaps: usize,
    pub ns_mask: u32,
}

impl Audit {
    pub fn maps(&self) -> impl DoubleEndedIterator<Item = Map> + '_ {
        self.maps[..self.nmaps].iter().flatten().copied()
    }
}

static AUDIT: SyncCell<Audit> = SyncCell::new(Audit { libs: [NO_LIB; MAX_AUDIT], n: 0, ready: false, maps: [None; 64], nmaps: 0, ns_mask: 0 });

#[inline(always)]
pub fn is_audit_ns(ns: usize) -> bool {
    au().ns_mask >> ns & 1 != 0
}

#[inline(always)]
pub fn au() -> &'static mut Audit {
    unsafe { &mut *AUDIT.as_ptr() }
}

#[inline(always)]
pub fn active() -> bool {
    au().ready && au().n != 0
}

#[inline(always)]
pub fn wants_objsearch() -> bool {
    active() && au().libs[..au().n].iter().any(|l| l.f_objsearch.is_some())
}

pub fn objsearch(name: &CStr, l: Option<Map>, code: u32) -> *const u8 {
    let mut name = name.as_ptr() as *const u8;
    let Some(l) = l else { return name };
    if code == 0 || !wants_objsearch() || is_audit_map(l) {
        return name;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_objsearch {
            name = unsafe { f(name, l.audit_cookie_ptr(i), code) };
            if name.is_null() {
                return name;
            }
        }
    }
    name
}

fn find_fn(m: Map, name: &[u8]) -> usize {
    let own = [m];
    let fl = Flags { plt: false, skip: None, newest: false };
    match lookup(name, None, &[&own], &fl) {
        Some(f) => sym_addr(&f),
        None => 0,
    }
}

unsafe fn audit_fn<F: Copy>(m: Map, name: &[u8]) -> Option<F> {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    let a = find_fn(m, name);
    if a == 0 { None } else { Some(unsafe { core::mem::transmute_copy::<usize, F>(&a) }) }
}

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
        for cur in ns(nsid).maps() {
            if cur.scope_ptr().is_null() {
                unsafe { cur.set_scope(m.scope_ptr()) };
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

pub unsafe fn announce_open() {
    let mut kept = 0usize;
    for i in 0..au().n {
        let mut l = au().libs[i];
        let Some(lm) = l.map else { continue };
        let Some(fv) = (unsafe { audit_fn::<VersionFn>(lm, b"la_version") }) else {
            crate::eprint!("ERROR: ld.so: object '{}' cannot be loaded as audit interface: undefined symbol: la_version; ignored.\n", Bytes(lm.name()));
            continue;
        };
        let v = unsafe { fv(LAV_CURRENT) };
        if v == 0 || v > LAV_CURRENT {
            crate::eprint!("ERROR: audit interface '{}' requires version {} (maximum supported version {}); ignored.\n", Bytes(lm.name()), v, LAV_CURRENT);
            continue;
        }
        l.version = v;
        l.f_objsearch = unsafe { audit_fn(lm, b"la_objsearch") };
        l.f_activity = unsafe { audit_fn(lm, b"la_activity") };
        l.f_objopen = unsafe { audit_fn(lm, b"la_objopen") };
        l.f_preinit = unsafe { audit_fn(lm, b"la_preinit") };
        l.f_symbind64 = unsafe { audit_fn(lm, b"la_symbind64") };
        l.f_objclose = unsafe { audit_fn(lm, b"la_objclose") };
        l.f_pltenter = unsafe { audit_fn(lm, b"la_x86_64_gnu_pltenter") };
        l.f_pltexit = unsafe { audit_fn(lm, b"la_x86_64_gnu_pltexit") };
        au().libs[kept] = l;
        kept += 1;
    }
    au().n = kept;
    au().ready = kept != 0;
    if kept == 0 {
        return;
    }
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

pub fn announce_preinit() {
    if !active() {
        return;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_preinit {
            unsafe { f(main_map().audit_cookie_ptr(i)) };
        }
    }
}

pub fn plt_hooks_for(m: Map) -> bool {
    active() && au().libs[..au().n].iter().any(|l| l.f_pltenter.is_some() || l.f_pltexit.is_some()) && !is_audit_map(m)
}

pub fn is_audit_map(m: Map) -> bool {
    is_audit_ns(m.l_ns() as usize)
}

pub fn activity(flag: u32) {
    activity_map(main_map(), flag)
}

pub fn ns_head(n: usize) -> Option<Map> {
    if n == 0 { st().main_map } else { ns(n).head }
}

pub fn activity_ns(nsid: usize, flag: u32) {
    if let Some(head) = ns_head(nsid) {
        activity_map(head, flag);
    }
}

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
            unsafe { f(head.audit_cookie_ptr(i), flag) };
        }
    }
}

static CLOSING: SyncCell<Option<Map>> = SyncCell::new(None);

pub fn close_one(m: Map) {
    if !active() || !m.audit_opened() {
        return;
    }
    if unsafe { CLOSING.read() }.is_none() {
        let h = ns_head(m.l_ns() as usize);
        unsafe { CLOSING.write(h) };
        if let Some(h) = h {
            activity_map(h, LA_ACT_DELETE);
        }
    }
    objclose(m);
    m.set_audit_opened(false);
}

pub fn close_done() {
    if let Some(h) = unsafe { CLOSING.read() } {
        unsafe { CLOSING.write(None) };
        let n = h.l_ns() as usize;
        if n == 0 || ns(n).head.is_some() {
            activity_map(h, LA_ACT_CONSISTENT);
        }
    }
}

pub fn objopen(m: Map) {
    if !active() {
        return;
    }
    m.set_audit_opened(true);
    make_libnames(m);
    for i in 0..au().n {
        let l = au().libs[i];
        m.set_audit_cookie(i, m.as_ptr() as usize);
        if let Some(f) = l.f_objopen {
            let fl = unsafe { f(m.as_ptr(), m.l_ns(), m.audit_cookie_ptr(i)) };
            m.set_audit_flags(i, fl);
            m.set_audit_any_plt(m.audit_any_plt() | (fl != 0));
        }
    }
}

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
    unsafe { a.write(LibName { name: first, next: null_mut(), dont_free: 1 }) };
    unsafe { m.set_l_libname(a) };
    let first_bytes: &[u8] = if m.is_main() { b"" } else if let Some(r) = m.req_name() { r } else { m.name() };
    if let Some(so) = m.soname()
        && so != first_bytes
    {
        let b = alloc_perm(core::mem::size_of::<LibName>(), 8) as *mut LibName;
        unsafe { b.write(LibName { name: m.soname_ptr(), next: null_mut(), dont_free: 1 }) };
        unsafe { (*a).next = b };
    }
}

pub fn objclose(m: Map) {
    if !active() {
        return;
    }
    for i in 0..au().n {
        if let Some(f) = au().libs[i].f_objclose
            && m.audit_opened()
        {
            unsafe { f(m.audit_cookie_ptr(i)) };
        }
    }
}

fn name_buf(name: &[u8]) -> [u8; 256] {
    let mut nbuf = [0u8; 256];
    let n = name.len().min(255);
    nbuf[..n].copy_from_slice(&name[..n]);
    nbuf
}

pub fn symbind(sym: &'static Sym, defmap: Option<Map>, refmap: Option<Map>, name: &[u8], mut addr: usize, jmp_slot: bool) -> usize {
    let (Some(defmap), Some(refmap)) = (defmap, refmap) else { return addr };
    if !active() {
        return addr;
    }
    let ndx = defmap.sym_index(sym);
    let nbuf = name_buf(name);
    for i in 0..au().n {
        let Some(f) = au().libs[i].f_symbind64 else { continue };
        if refmap.audit_flags(i) & LA_FLG_BINDFROM == 0 || defmap.audit_flags(i) & LA_FLG_BINDTO == 0 {
            continue;
        }
        let mut flags = if jmp_slot { LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT } else { 0u32 };
        let mut copy = *sym;
        copy.value = addr as u64;
        let new = unsafe { f(&copy, ndx as u32, refmap.audit_cookie_ptr(i), defmap.audit_cookie_ptr(i), &mut flags, nbuf.as_ptr()) };
        if new != 0 {
            addr = new;
        }
    }
    addr
}

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
            let new = unsafe { f(&copy, ndx as u32, caller.audit_cookie_ptr(i), defmap.audit_cookie_ptr(i), &mut flags, nbuf.as_ptr()) };
            if new as u64 != copy.value {
                alt = LA_SYMB_ALTVALUE;
                copy.value = new as u64;
            }
        }
    }
    copy.value as usize
}

pub fn objclose_once(m: Map) {
    if m.audit_opened() {
        objclose(m);
        m.set_audit_opened(false);
    }
}

pub fn finish() {
    if active() {
        au().ready = false;
    }
}

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

pub fn symbind_slot(sym: &'static Sym, defmap: Map, refmap: Map, name: &[u8], addr: usize) -> (usize, u32, u32) {
    if !active() || !(refmap.audit_any_plt() || defmap.audit_any_plt()) {
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

fn plt_sym(bound: Map, ndx: u32) -> (&'static Sym, CStrRef) {
    let defsym = unsafe { bound.sym(ndx as usize) };
    (defsym, bound.sym_name(defsym))
}

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
        if enterexit & (LA_SYMB_NOPLTEXIT >> (2 * i)) == 0 {
            unsafe { f(&mut sym, ndx, m.audit_cookie_ptr(i), bound.audit_cookie_ptr(i), inregs, outregs, name.as_ptr()) };
        }
    }
}
