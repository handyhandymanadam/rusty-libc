#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::audit;
use crate::elf::*;
use crate::ffi::{CStrRef, at, cstr, cstr_nul, cstr_opt, slice};
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::util::*;
use core::ffi::{CStr, c_int};
use core::ptr::{NonNull, null, null_mut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering::Relaxed};

#[derive(Clone, Copy)]
pub struct VerInfo {
    pub name: Option<CStrRef>,
    pub hash: u32,
    pub file: Option<CStrRef>,
    pub hidden: bool,
}

#[repr(C)]
pub struct LibName {
    pub name: *const u8,
    pub next: *mut LibName,
    pub dont_free: i32,
}

#[repr(C)]
pub struct LinkMap {
    pub l_addr: usize,
    pub l_name: *const u8,
    pub l_ld: *mut Dyn,
    pub l_next: *mut LinkMap,
    pub l_prev: *mut LinkMap,
    pub l_real: *mut LinkMap,
    pub l_ns: isize,
    pub l_libname: *mut LibName,
    pub soname: *const u8,
    pub phdr: *const Phdr,
    pub phnum: usize,
    pub entry: usize,
    pub map_start: usize,
    pub map_end: usize,
    pub typ: u16,
    pub strtab: *const u8,
    pub strsz: usize,
    pub symtab: *const Sym,
    pub gnu_nbuckets: u32,
    pub gnu_symoffset: u32,
    pub gnu_bloom_size: u32,
    pub gnu_bloom_shift: u32,
    pub gnu_bloom: *const u64,
    pub gnu_buckets: *const u32,
    pub gnu_chain: *const u32,
    pub hash_nbucket: u32,
    pub hash_nchain: u32,
    pub hash_buckets: *const u32,
    pub hash_chains: *const u32,
    pub versym: *const u16,
    pub verdef: *const Verdef,
    pub verdefnum: usize,
    pub verneed: *const Verneed,
    pub verneednum: usize,
    pub vers: *mut VerInfo,
    pub nvers: usize,
    pub rela: *const Rela,
    pub relasz: usize,
    pub jmprel: *const Rela,
    pub pltrelsz: usize,
    pub relr: *const u64,
    pub relrsz: usize,
    pub pltgot: *mut usize,
    pub init: usize,
    pub fini: usize,
    pub init_array: *const usize,
    pub init_arraysz: usize,
    pub fini_array: *const usize,
    pub fini_arraysz: usize,
    pub preinit_array: *const usize,
    pub preinit_arraysz: usize,
    pub flags: u64,
    pub flags_1: u64,
    pub bind_now: bool,
    pub audit_str: u64,
    pub depaudit_str: u64,
    pub rtld_now: bool,
    pub lazy_plt: bool,
    pub textrel: bool,
    pub dyn_adjusted: bool,
    pub rpath: *const u8,
    pub runpath: *const u8,
    pub relro_start: usize,
    pub relro_len: usize,
    pub eh_frame_hdr: usize,
    pub needed: *mut *mut LinkMap,
    pub nneeded: usize,
    pub loader: *mut LinkMap,
    pub origin: *const u8,
    pub tls_modid: usize,
    pub tls_image: usize,
    pub tls_filesz: usize,
    pub tls_memsz: usize,
    pub tls_align: usize,
    pub tls_offset: usize,
    pub tls_static: bool,
    pub dev: u64,
    pub ino: u64,
    pub relocated: bool,
    pub init_called: bool,
    pub opening: bool,
    pub fini_called: bool,
    pub is_main: bool,
    pub is_ldso: bool,
    pub is_vdso: bool,
    pub in_global: bool,
    pub nodelete: bool,
    pub dlopened: bool,
    pub reldeps: *mut *mut LinkMap,
    pub nreldeps: usize,
    pub creldeps: usize,
    pub unloading: bool,
    pub removed: bool,
    pub refcount: usize,
    pub scope: *mut *mut LinkMap,
    pub nscope: usize,
    pub xscope: *mut *mut LinkMap,
    pub nxscope: usize,
    pub init_seq: usize,
    pub lazy_pending: bool,
    pub deepbind: bool,
    pub audit_cookie: [usize; 8],
    pub audit_flags: [u32; 8],
    pub audit_opened: bool,
    pub filtees: *mut *mut LinkMap,
    pub nfiltees: usize,
    pub filter_hard: bool,

    pub plt_cache: *mut usize,
    pub used: bool,
    pub req_name: *const u8,
    pub audit_any_plt: bool,
    pub tls_dtor_count: usize,
}

const _: () = assert!(core::mem::offset_of!(LinkMap, tls_modid) == 504);
const _: () = assert!(core::mem::offset_of!(LinkMap, tls_offset) == 544);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Map(NonNull<LinkMap>);

impl core::fmt::Debug for Map {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Map({:p})", self.0)
    }
}

impl Map {
    #[inline(always)]
    pub unsafe fn from_ptr(p: *mut LinkMap) -> Option<Map> {
        NonNull::new(p).map(Map)
    }

    #[inline(always)]
    pub fn as_ptr(self) -> *mut LinkMap {
        self.0.as_ptr()
    }

    #[inline(always)]
    pub fn opt_ptr(m: Option<Map>) -> *mut LinkMap {
        match m {
            Some(m) => m.as_ptr(),
            None => null_mut(),
        }
    }
}

macro_rules! map_fields {
    (safe { $($f:ident, $set:ident : $t:ty;)* } unsafe { $($uf:ident => $ug:ident, $uset:ident : $ut:ty;)* }) => {
        impl Map {
            $(
                #[inline(always)]
                pub fn $f(self) -> $t {
                    unsafe { (*self.0.as_ptr()).$f }
                }
                #[inline(always)]
                pub fn $set(self, v: $t) {
                    unsafe { (*self.0.as_ptr()).$f = v }
                }
            )*
            $(
                #[inline(always)]
                pub fn $ug(self) -> $ut {
                    unsafe { (*self.0.as_ptr()).$uf }
                }
                #[inline(always)]
                pub unsafe fn $uset(self, v: $ut) {
                    unsafe { (*self.0.as_ptr()).$uf = v }
                }
            )*
        }
    };
}

map_fields! {
    safe {
        l_addr, set_l_addr: usize;
        l_ns, set_l_ns: isize;
        entry, set_entry: usize;
        map_start, set_map_start: usize;
        map_end, set_map_end: usize;
        typ, set_typ: u16;
        gnu_nbuckets, set_gnu_nbuckets: u32;
        gnu_symoffset, set_gnu_symoffset: u32;
        gnu_bloom_size, set_gnu_bloom_size: u32;
        gnu_bloom_shift, set_gnu_bloom_shift: u32;
        hash_nbucket, set_hash_nbucket: u32;
        hash_nchain, set_hash_nchain: u32;
        init, set_init: usize;
        fini, set_fini: usize;
        flags, set_flags: u64;
        flags_1, set_flags_1: u64;
        bind_now, set_bind_now: bool;
        rtld_now, set_rtld_now: bool;
        lazy_plt, set_lazy_plt: bool;
        textrel, set_textrel: bool;
        dyn_adjusted, set_dyn_adjusted: bool;
        relro_start, set_relro_start: usize;
        relro_len, set_relro_len: usize;
        eh_frame_hdr, set_eh_frame_hdr: usize;
        tls_modid, set_tls_modid: usize;
        tls_align, set_tls_align: usize;
        tls_offset, set_tls_offset: usize;
        tls_static, set_tls_static: bool;
        dev, set_dev: u64;
        ino, set_ino: u64;
        relocated, set_relocated: bool;
        init_called, set_init_called: bool;
        opening, set_opening: bool;
        fini_called, set_fini_called: bool;
        is_main, set_is_main: bool;
        is_ldso, set_is_ldso: bool;
        is_vdso, set_is_vdso: bool;
        in_global, set_in_global: bool;
        nodelete, set_nodelete: bool;
        dlopened, set_dlopened: bool;
        unloading, set_unloading: bool;
        removed, set_removed: bool;
        refcount, set_refcount: usize;
        init_seq, set_init_seq: usize;
        lazy_pending, set_lazy_pending: bool;
        deepbind, set_deepbind: bool;
        audit_opened, set_audit_opened: bool;
        filter_hard, set_filter_hard: bool;
        audit_any_plt, set_audit_any_plt: bool;
        tls_dtor_count, set_tls_dtor_count: usize;
    }
    unsafe {
        l_name => l_name, set_l_name: *const u8;
        l_ld => l_ld, set_l_ld: *mut Dyn;
        l_libname => l_libname, set_l_libname: *mut LibName;
        soname => soname_ptr, set_soname: *const u8;
        phdr => phdr, set_phdr: *const Phdr;
        phnum => phnum, set_phnum: usize;
        strtab => strtab, set_strtab: *const u8;
        strsz => strsz, set_strsz: usize;
        symtab => symtab, set_symtab: *const Sym;
        gnu_bloom => gnu_bloom, set_gnu_bloom: *const u64;
        gnu_buckets => gnu_buckets, set_gnu_buckets: *const u32;
        gnu_chain => gnu_chain, set_gnu_chain: *const u32;
        hash_buckets => hash_buckets, set_hash_buckets: *const u32;
        hash_chains => hash_chains, set_hash_chains: *const u32;
        versym => versym, set_versym: *const u16;
        verdef => verdef, set_verdef: *const Verdef;
        verdefnum => verdefnum, set_verdefnum: usize;
        verneed => verneed, set_verneed: *const Verneed;
        verneednum => verneednum, set_verneednum: usize;
        vers => vers_ptr, set_vers: *mut VerInfo;
        nvers => nvers, set_nvers: usize;
        rela => rela, set_rela: *const Rela;
        relasz => relasz, set_relasz: usize;
        jmprel => jmprel, set_jmprel: *const Rela;
        pltrelsz => pltrelsz, set_pltrelsz: usize;
        relr => relr, set_relr: *const u64;
        relrsz => relrsz, set_relrsz: usize;
        pltgot => pltgot, set_pltgot: *mut usize;
        init_array => init_array_ptr, set_init_array: *const usize;
        init_arraysz => init_arraysz, set_init_arraysz: usize;
        fini_array => fini_array_ptr, set_fini_array: *const usize;
        fini_arraysz => fini_arraysz, set_fini_arraysz: usize;
        preinit_array => preinit_array_ptr, set_preinit_array: *const usize;
        preinit_arraysz => preinit_arraysz, set_preinit_arraysz: usize;
        audit_str => audit_str, set_audit_str: u64;
        depaudit_str => depaudit_str, set_depaudit_str: u64;
        rpath => rpath_ptr, set_rpath: *const u8;
        runpath => runpath_ptr, set_runpath: *const u8;
        needed => needed_ptr, set_needed: *mut *mut LinkMap;
        nneeded => nneeded, set_nneeded: usize;
        origin => origin_ptr, set_origin: *const u8;
        tls_image => tls_image, set_tls_image: usize;
        tls_filesz => tls_filesz, set_tls_filesz: usize;
        tls_memsz => tls_memsz, set_tls_memsz: usize;
        reldeps => reldeps_ptr, set_reldeps: *mut *mut LinkMap;
        nreldeps => nreldeps, set_nreldeps: usize;
        creldeps => creldeps, set_creldeps: usize;
        scope => scope_ptr, set_scope: *mut *mut LinkMap;
        nscope => nscope, set_nscope: usize;
        xscope => xscope_ptr, set_xscope: *mut *mut LinkMap;
        nxscope => nxscope, set_nxscope: usize;
        filtees => filtees_ptr, set_filtees: *mut *mut LinkMap;
        nfiltees => nfiltees, set_nfiltees: usize;
        plt_cache => plt_cache, set_plt_cache: *mut usize;
        req_name => req_name_ptr, set_req_name: *const u8;
    }
}

impl Map {
    #[inline(always)]
    fn link(p: *mut LinkMap) -> Option<Map> {
        unsafe { Map::from_ptr(p) }
    }

    #[inline(always)]
    fn link_field(self, off: usize) -> *mut *mut LinkMap {
        (self.as_ptr() as *mut u8).wrapping_add(off) as *mut *mut LinkMap
    }

    #[inline(always)]
    fn get_link(self, off: usize) -> Option<Map> {
        Map::link(unsafe { *self.link_field(off) })
    }

    #[inline(always)]
    fn put_link(self, off: usize, v: Option<Map>) {
        unsafe { *self.link_field(off) = Map::opt_ptr(v) }
    }

    #[inline(always)]
    pub fn next(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, l_next))
    }
    #[inline(always)]
    pub fn set_next(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, l_next), v)
    }
    #[inline(always)]
    pub fn prev(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, l_prev))
    }
    #[inline(always)]
    pub fn set_prev(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, l_prev), v)
    }
    #[inline(always)]
    pub fn real(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, l_real))
    }
    #[inline(always)]
    pub fn set_real(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, l_real), v)
    }
    #[inline(always)]
    pub fn loader(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, loader))
    }
    #[inline(always)]
    pub fn set_loader(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, loader), v)
    }

    #[inline(always)]
    fn used_atomic(self) -> &'static core::sync::atomic::AtomicBool {
        let p = (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, used)) as *mut bool;
        unsafe { core::sync::atomic::AtomicBool::from_ptr(p) }
    }
    #[inline(always)]
    pub fn used(self) -> bool {
        self.used_atomic().load(core::sync::atomic::Ordering::Relaxed)
    }
    #[inline(always)]
    pub fn set_used(self, v: bool) {
        self.used_atomic().store(v, core::sync::atomic::Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn audit_cookie_ptr(self, i: usize) -> *mut usize {
        assert!(i < 8);
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, audit_cookie) + i * 8) as *mut usize
    }
    #[inline(always)]
    pub fn audit_cookie(self, i: usize) -> usize {
        unsafe { *self.audit_cookie_ptr(i) }
    }
    #[inline(always)]
    pub fn set_audit_cookie(self, i: usize, v: usize) {
        unsafe { *self.audit_cookie_ptr(i) = v }
    }
    #[inline(always)]
    fn audit_flags_ptr(self, i: usize) -> *mut u32 {
        assert!(i < 8);
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, audit_flags) + i * 4) as *mut u32
    }
    #[inline(always)]
    pub fn audit_flags(self, i: usize) -> u32 {
        unsafe { *self.audit_flags_ptr(i) }
    }
    #[inline(always)]
    pub fn set_audit_flags(self, i: usize, v: u32) {
        unsafe { *self.audit_flags_ptr(i) = v }
    }
    #[inline(always)]
    pub fn plt_cache_field(self) -> *mut usize {
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, plt_cache)) as *mut usize
    }

    #[inline]
    pub fn name(self) -> &'static [u8] {
        unsafe { cstr_opt(self.l_name()) }.unwrap_or(b"")
    }
    #[inline]
    pub fn soname(self) -> Option<&'static [u8]> {
        unsafe { cstr_opt(self.soname_ptr()) }
    }
    #[inline]
    pub fn rpath(self) -> Option<&'static [u8]> {
        unsafe { cstr_opt(self.rpath_ptr()) }
    }
    #[inline]
    pub fn runpath(self) -> Option<&'static [u8]> {
        unsafe { cstr_opt(self.runpath_ptr()) }
    }
    #[inline]
    pub fn origin(self) -> Option<&'static [u8]> {
        unsafe { cstr_opt(self.origin_ptr()) }
    }
    #[inline]
    pub fn req_name(self) -> Option<&'static [u8]> {
        unsafe { cstr_opt(self.req_name_ptr()) }
    }
    #[inline]
    pub fn phdrs(self) -> &'static [Phdr] {
        unsafe { slice(self.phdr(), self.phnum()) }
    }
    #[inline]
    pub fn needed(self) -> &'static [Map] {
        unsafe { slice(self.needed_ptr() as *const Map, self.nneeded()) }
    }
    #[inline]
    pub fn filtees(self) -> &'static [Map] {
        unsafe { slice(self.filtees_ptr() as *const Map, self.nfiltees()) }
    }
    #[inline]
    pub fn reldeps(self) -> &'static [Map] {
        unsafe { slice(self.reldeps_ptr() as *const Map, self.nreldeps()) }
    }
    #[inline]
    pub fn scope(self) -> &'static [Map] {
        unsafe { slice(self.scope_ptr() as *const Map, self.nscope()) }
    }
    #[inline]
    pub fn xscope(self) -> &'static [Map] {
        unsafe { slice(self.xscope_ptr() as *const Map, self.nxscope()) }
    }
    #[inline]
    pub fn vers(self) -> &'static [VerInfo] {
        unsafe { slice(self.vers_ptr() as *const VerInfo, self.nvers()) }
    }
    #[inline]
    pub fn relas(self) -> &'static [Rela] {
        unsafe { slice(self.rela(), self.relasz() / core::mem::size_of::<Rela>()) }
    }
    #[inline]
    pub fn jmprels(self) -> &'static [Rela] {
        unsafe { slice(self.jmprel(), self.pltrelsz() / core::mem::size_of::<Rela>()) }
    }
    #[inline]
    pub fn relrs(self) -> &'static [u64] {
        unsafe { slice(self.relr(), self.relrsz() / 8) }
    }
    #[inline]
    pub fn init_array(self) -> &'static [usize] {
        unsafe { slice(self.init_array_ptr(), self.init_arraysz() / 8) }
    }
    #[inline]
    pub fn fini_array(self) -> &'static [usize] {
        unsafe { slice(self.fini_array_ptr(), self.fini_arraysz() / 8) }
    }
    #[inline]
    pub fn preinit_array(self) -> &'static [usize] {
        unsafe { slice(self.preinit_array_ptr(), self.preinit_arraysz() / 8) }
    }
    #[inline]
    pub fn gnu_bloom_words(self) -> &'static [u64] {
        unsafe { slice(self.gnu_bloom(), self.gnu_bloom_size() as usize) }
    }
    #[inline]
    pub fn gnu_bucket_words(self) -> &'static [u32] {
        unsafe { slice(self.gnu_buckets(), self.gnu_nbuckets() as usize) }
    }
    #[inline]
    pub fn hash_bucket_words(self) -> &'static [u32] {
        unsafe { slice(self.hash_buckets(), self.hash_nbucket() as usize) }
    }
    #[inline]
    pub fn hash_chain_words(self) -> &'static [u32] {
        unsafe { slice(self.hash_chains(), self.hash_nchain() as usize) }
    }
    #[inline]
    pub fn dynamic(self) -> DynIter {
        DynIter(self.l_ld())
    }
    pub fn dep_names(self) -> impl Iterator<Item = (&'static [u8], u8)> {
        let kind_of = |t: i64| match t {
            DT_NEEDED => 0u8,
            DT_AUXILIARY => 1,
            DT_FILTER => 2,
            _ => 3,
        };
        let firsts = self.dynamic().filter(move |d| kind_of(d.tag) == 0);
        let filtees = self.dynamic().filter(move |d| matches!(kind_of(d.tag), 1 | 2));
        firsts.chain(filtees).map(move |d| (unsafe { self.str_at(d.val as usize) }, kind_of(d.tag)))
    }
    pub fn needed_names(self) -> impl Iterator<Item = &'static [u8]> {
        self.dynamic().filter(|d| d.tag == DT_NEEDED).map(move |d| unsafe { self.str_at(d.val as usize) })
    }
    pub fn verdefs(self) -> impl Iterator<Item = (&'static Verdef, CStrRef)> {
        let mut vd = self.verdef();
        (0..self.verdefnum()).map(move |_| {
            let e = unsafe { at(vd) };
            let da = unsafe { at((vd as *const u8).wrapping_add(e.aux as usize) as *const Verdaux) };
            let name = unsafe { self.str_ref(da.name as usize) };
            vd = (vd as *const u8).wrapping_add(e.next as usize) as *const Verdef;
            (e, name)
        })
    }
    pub fn verneeds(self) -> impl Iterator<Item = (&'static Verneed, CStrRef, VernauxIter)> {
        let mut vn = self.verneed();
        (0..self.verneednum()).map(move |_| {
            let e = unsafe { at(vn) };
            let file = unsafe { self.str_ref(e.file as usize) };
            let aux = VernauxIter { map: self, at: (vn as *const u8).wrapping_add(e.aux as usize) as *const Vernaux, left: e.cnt };
            vn = (vn as *const u8).wrapping_add(e.next as usize) as *const Verneed;
            (e, file, aux)
        })
    }

    #[inline(always)]
    pub unsafe fn str_at(self, off: usize) -> &'static [u8] {
        unsafe { cstr(self.strtab().wrapping_add(off)) }
    }

    #[inline(always)]
    pub unsafe fn str_ref(self, off: usize) -> CStrRef {
        unsafe { CStrRef::new(self.strtab().wrapping_add(off)) }
    }

    #[inline(always)]
    pub unsafe fn sym(self, idx: usize) -> &'static Sym {
        unsafe { at(self.symtab().wrapping_add(idx)) }
    }

    #[inline(always)]
    pub fn sym_index(self, s: &Sym) -> usize {
        (s as *const Sym as usize).wrapping_sub(self.symtab() as usize) / core::mem::size_of::<Sym>()
    }

    #[inline(always)]
    pub fn sym_name(self, s: &'static Sym) -> CStrRef {
        unsafe { self.str_ref(s.name as usize) }
    }
}

pub struct DynIter(*const Dyn);

impl Iterator for DynIter {
    type Item = Dyn;
    #[inline]
    fn next(&mut self) -> Option<Dyn> {
        let d = unsafe { *self.0 };
        if d.tag == DT_NULL {
            return None;
        }
        self.0 = self.0.wrapping_add(1);
        Some(d)
    }
}

pub struct VernauxIter {
    map: Map,
    at: *const Vernaux,
    left: u16,
}

impl Iterator for VernauxIter {
    type Item = (&'static Vernaux, CStrRef);
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let a = unsafe { at(self.at) };
        let name = unsafe { self.map.str_ref(a.name as usize) };
        self.at = (self.at as *const u8).wrapping_add(a.next as usize) as *const Vernaux;
        Some((a, name))
    }
}

pub const MAX_MAPS: usize = 1024;

pub const DL_NNS: usize = 16;

pub struct Ns {
    pub head: Option<Map>,
    pub tail: Option<Map>,
    pub nmaps: usize,
    global: *mut Option<Map>,
    pub nglobal: usize,
    pub libc_map: Option<Map>,
}

static BASE_GLOBAL: SyncCell<[Option<Map>; MAX_MAPS]> = SyncCell::new([None; MAX_MAPS]);

impl Ns {
    const EMPTY: Ns = Ns { head: None, tail: None, nmaps: 0, global: null_mut(), nglobal: 0, libc_map: None };

    pub fn scope(&self) -> &'static [Map] {
        if self.global.is_null() {
            return &[];
        }
        unsafe { slice(self.global as *const Map, self.nglobal) }
    }

    pub fn push_global(&mut self, m: Map) -> bool {
        if self.nglobal >= MAX_MAPS {
            return false;
        }
        if self.global.is_null() {
            self.global = alloc_perm(MAX_MAPS * core::mem::size_of::<Option<Map>>(), 8) as *mut Option<Map>;
        }
        unsafe { *self.global.wrapping_add(self.nglobal) = Some(m) };
        self.nglobal += 1;
        true
    }

    pub fn remove_global(&mut self, m: Map) {
        if self.global.is_null() {
            return;
        }
        let g = unsafe { crate::ffi::slice_mut(self.global, self.nglobal) };
        let mut j = 0;
        for i in 0..g.len() {
            if g[i] != Some(m) {
                g[j] = g[i];
                j += 1;
            }
        }
        self.nglobal = j;
    }

    pub fn maps(&self) -> MapIter {
        MapIter(self.head)
    }
}

pub struct MapIter(pub Option<Map>);

impl Iterator for MapIter {
    type Item = Map;
    #[inline]
    fn next(&mut self) -> Option<Map> {
        let m = self.0?;
        self.0 = m.next();
        Some(m)
    }
}

#[inline(always)]
pub fn ns(n: usize) -> &'static mut Ns {
    &mut st().ns[n]
}

#[inline(always)]
pub fn ns_of(m: Option<Map>) -> usize {
    match m {
        Some(m) => m.l_ns() as usize,
        None => 0,
    }
}

pub struct State {
    pub ns: [Ns; DL_NNS],
    pub nns: usize,
    pub main_map: Option<Map>,
    pub ldso_map: Option<Map>,
    pub argc: usize,
    pub argv: *mut *mut u8,
    pub envp: *mut *mut u8,
    pub auxv: *mut usize,
    pub library_path: *const u8,
    pub preload: *const u8,
    pub secure: bool,
    pub map32: bool,
    pub started: bool,
    pub stack_exec: bool,
    pub execstack_mode: u8,
    pub tls_nns: usize,
    pub tls_optional: usize,
    pub hard_error: bool,
    pub lenient: bool,
    pub debug: bool,
    pub bind_now_env: bool,
    pub trace: bool,
    pub prog_name: *const u8,
    pub page_size: usize,
    pub error: *mut u8,
    pub error_cap: usize,
    pub error_len: usize,
    pub error_obj: (usize, usize),
    pub error_msg: (usize, usize),
    pub error_code: c_int,
    pub ldso_base: usize,
    pub audit: *const u8,
    pub trace_versions: bool,
    pub trace_warn: bool,
    pub trace_unused: bool,
}

pub static STATE: SyncCell<State> = SyncCell::new(State {
    ns: {
        let mut t = [Ns::EMPTY; DL_NNS];
        t[0].global = BASE_GLOBAL.as_ptr() as *mut Option<Map>;
        t
    },
    nns: 1,
    main_map: None,
    ldso_map: None,
    argc: 0,
    argv: null_mut(),
    envp: null_mut(),
    auxv: null_mut(),
    library_path: null(),
    preload: null(),
    secure: false,
    map32: false,
    started: false,
    stack_exec: true,
    execstack_mode: 1,
    tls_nns: 4,
    tls_optional: 512,
    hard_error: false,
    lenient: false,
    debug: false,
    bind_now_env: false,
    trace: false,
    prog_name: null(),
    page_size: 4096,
    error: null_mut(),
    error_cap: 512,
    error_len: 0,
    error_obj: (0, 0),
    error_msg: (0, 0),
    error_code: 0,
    ldso_base: 0,
    audit: null(),
    trace_versions: false,
    trace_warn: false,
    trace_unused: false,
});

#[inline(always)]
pub fn st() -> &'static mut State {
    unsafe { &mut *STATE.as_ptr() }
}

#[inline]
pub fn main_map() -> Map {
    match st().main_map {
        Some(m) => m,
        None => crate::die(format_args!("internal error: no program map")),
    }
}

#[inline]
pub fn ldso_map() -> Map {
    match st().ldso_map {
        Some(m) => m,
        None => crate::die(format_args!("internal error: no loader map")),
    }
}

static ERR0: SyncCell<[u8; 512]> = SyncCell::new([0; 512]);

pub struct Count(pub usize);
impl core::fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

pub fn set_error(args: core::fmt::Arguments) {
    set_error_at(b"", 0, args)
}

pub fn set_error_at(obj: &[u8], code: c_int, args: core::fmt::Arguments) {
    set_error_occ("", obj, code, args)
}

pub fn set_error_occ(occasion: &str, obj: &[u8], code: c_int, args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct W<'a>(&'a mut [u8], usize);
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            self.0[self.1..self.1 + s.len()].copy_from_slice(s.as_bytes());
            self.1 += s.len();
            Ok(())
        }
    }
    let s = st();
    let mut c = Count(0);
    let _ = c.write_fmt(args);
    let sep = if obj.is_empty() { 0 } else { 2 };
    let tail = if code != 0 { 2 + errno_text(code).len() } else { 0 };
    let occ = if occasion.is_empty() { 0 } else { occasion.len() + 2 };
    let total = occ + obj.len() + sep + c.0 + tail;
    if s.error.is_null() {
        s.error = ERR0.as_ptr() as *mut u8;
    }
    if total + 1 > s.error_cap {
        let cap = (total + 1).next_power_of_two();
        s.error = alloc_perm(cap, 1);
        s.error_cap = cap;
    }
    let buf = unsafe { crate::ffi::slice_mut(s.error, s.error_cap) };
    let mut w = W(buf, 0);
    if occ != 0 {
        let _ = w.write_str(occasion);
        let _ = w.write_str(": ");
    }
    w.0[occ..occ + obj.len()].copy_from_slice(obj);
    w.1 += obj.len();
    if sep != 0 {
        let _ = w.write_str(": ");
    }
    let m0 = w.1;
    let _ = w.write_fmt(args);
    if code != 0 {
        let _ = w.write_str(": ");
        let _ = w.write_str(errno_text(code));
    }
    let n = w.1;
    w.0[n] = 0;
    s.error_obj = (occ, occ + obj.len());
    s.error_msg = (m0, m0 + c.0);
    s.error_code = code;
    s.error_len = n;
}

pub fn set_error_obj(obj: &[u8]) {
    let s = st();
    if s.error_obj.1 != s.error_obj.0 || s.error_len == 0 {
        return;
    }
    let msg = error_msg();
    let code = s.error_code;
    let mut tmp = [0u8; 512];
    let held: &[u8] = if msg.len() <= tmp.len() {
        tmp[..msg.len()].copy_from_slice(msg);
        &tmp[..msg.len()]
    } else {
        let p = alloc_perm(msg.len(), 1);
        let d = unsafe { crate::ffi::slice_mut(p, msg.len()) };
        d.copy_from_slice(msg);
        d
    };
    set_error_at(obj, code, format_args!("{}", RawText(held)));
}

struct RawText<'a>(&'a [u8]);
impl core::fmt::Display for RawText<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}

pub fn error_str() -> &'static [u8] {
    let s = st();
    if s.error.is_null() {
        return &[];
    }
    unsafe { slice(s.error as *const u8, s.error_len) }
}

pub fn error_obj() -> &'static [u8] {
    let s = st();
    &error_str()[s.error_obj.0..s.error_obj.1]
}
pub fn error_msg() -> &'static [u8] {
    let s = st();
    &error_str()[s.error_msg.0..s.error_msg.1]
}
pub fn error_code() -> c_int {
    st().error_code
}

pub fn new_map() -> Map {
    let p = alloc_calloc(core::mem::size_of::<LinkMap>(), 16) as *mut LinkMap;
    let m = unsafe { Map::from_ptr(p) };
    match m {
        Some(m) => {
            m.set_real(Some(m));
            m
        }
        None => crate::die(format_args!("cannot allocate memory")),
    }
}

pub fn link_map(m: Map) {
    let s = ns(m.l_ns() as usize);
    m.set_prev(s.tail);
    m.set_next(None);
    match s.tail {
        None => s.head = Some(m),
        Some(t) => t.set_next(Some(m)),
    }
    s.tail = Some(m);
    s.nmaps += 1;
    if s.libc_map.is_none() && m.soname() == Some(b"libc.so.6") {
        s.libc_map = Some(m);
    }
}

pub fn unlink_map(m: Map) {
    let s = ns(m.l_ns() as usize);
    match m.prev() {
        None => {
            s.head = m.next();
            crate::rdebug_set_map(m.l_ns() as usize, s.head);
        }
        Some(p) => p.set_next(m.next()),
    }
    match m.next() {
        None => s.tail = m.prev(),
        Some(n) => n.set_prev(m.prev()),
    }
    s.nmaps -= 1;
    if s.libc_map == Some(m) {
        s.libc_map = None;
    }
    trim_nns();
}

pub fn trim_nns() {
    let s = st();
    while s.nns > 1 && ns(s.nns - 1).head.is_none() {
        s.nns -= 1;
    }
}

pub unsafe fn parse_dynamic(m: Map) {
    let a = m.l_addr();
    let mut hash = 0usize;
    let mut gnu = 0usize;
    let mut versym = 0usize;
    for d in m.dynamic() {
        let v = d.val as usize;
        match d.tag {
            DT_STRTAB => unsafe { m.set_strtab((a + v) as *const u8) },
            DT_STRSZ => unsafe { m.set_strsz(v) },
            DT_SYMTAB => unsafe { m.set_symtab((a + v) as *const Sym) },
            DT_HASH => hash = a + v,
            DT_GNU_HASH => gnu = a + v,
            DT_RELA => unsafe { m.set_rela((a + v) as *const Rela) },
            DT_RELASZ => unsafe { m.set_relasz(v) },
            DT_JMPREL => unsafe { m.set_jmprel((a + v) as *const Rela) },
            DT_PLTRELSZ => unsafe { m.set_pltrelsz(v) },
            DT_RELR => unsafe { m.set_relr((a + v) as *const u64) },
            DT_RELRSZ => unsafe { m.set_relrsz(v) },
            DT_PLTGOT => unsafe { m.set_pltgot((a + v) as *mut usize) },
            DT_INIT => m.set_init(a + v),
            DT_FINI => m.set_fini(a + v),
            DT_INIT_ARRAY => unsafe { m.set_init_array((a + v) as *const usize) },
            DT_INIT_ARRAYSZ => unsafe { m.set_init_arraysz(v) },
            DT_FINI_ARRAY => unsafe { m.set_fini_array((a + v) as *const usize) },
            DT_FINI_ARRAYSZ => unsafe { m.set_fini_arraysz(v) },
            DT_PREINIT_ARRAY => unsafe { m.set_preinit_array((a + v) as *const usize) },
            DT_PREINIT_ARRAYSZ => unsafe { m.set_preinit_arraysz(v) },
            DT_VERSYM => versym = a + v,
            DT_VERDEF => unsafe { m.set_verdef((a + v) as *const Verdef) },
            DT_VERDEFNUM => unsafe { m.set_verdefnum(v) },
            DT_VERNEED => unsafe { m.set_verneed((a + v) as *const Verneed) },
            DT_VERNEEDNUM => unsafe { m.set_verneednum(v) },
            DT_FLAGS => m.set_flags(v as u64),
            DT_FLAGS_1 => m.set_flags_1(v as u64),
            DT_AUDIT => unsafe { m.set_audit_str(v as u64 + 1) },
            DT_DEPAUDIT => unsafe { m.set_depaudit_str(v as u64 + 1) },
            DT_BIND_NOW => m.set_bind_now(true),
            DT_TEXTREL => m.set_textrel(true),
            DT_SYMBOLIC => m.set_flags(m.flags() | DF_SYMBOLIC),
            DT_DEBUG => {}
            _ => {}
        }
    }
    if m.flags() & DF_TEXTREL != 0 {
        m.set_textrel(true);
    }
    if m.flags() & DF_BIND_NOW != 0 || m.flags_1() & DF_1_NOW != 0 {
        m.set_bind_now(true);
    }
    if m.flags_1() & DF_1_NODELETE != 0 {
        m.set_nodelete(true);
    }
    let strtab = m.strtab();
    for d in m.dynamic() {
        let p = strtab.wrapping_add(d.val as usize);
        match d.tag {
            DT_SONAME => unsafe { m.set_soname(p) },
            DT_RPATH => unsafe { m.set_rpath(p) },
            DT_RUNPATH => unsafe { m.set_runpath(p) },
            _ => {}
        }
    }
    if gnu != 0 {
        let h = gnu as *const u32;
        let hdr = unsafe { slice(h, 4) };
        m.set_gnu_nbuckets(hdr[0]);
        m.set_gnu_symoffset(hdr[1]);
        m.set_gnu_bloom_size(hdr[2]);
        m.set_gnu_bloom_shift(hdr[3]);
        let bloom = h.wrapping_add(4) as *const u64;
        let buckets = h.wrapping_add(4 + 2 * hdr[2] as usize);
        unsafe { m.set_gnu_bloom(bloom) };
        unsafe { m.set_gnu_buckets(buckets) };
        unsafe { m.set_gnu_chain(buckets.wrapping_add(hdr[0] as usize)) };
    }
    if hash != 0 {
        let h = hash as *const u32;
        let hdr = unsafe { slice(h, 2) };
        m.set_hash_nbucket(hdr[0]);
        m.set_hash_nchain(hdr[1]);
        unsafe { m.set_hash_buckets(h.wrapping_add(2)) };
        unsafe { m.set_hash_chains(h.wrapping_add(2 + hdr[0] as usize)) };
    }
    unsafe { m.set_versym(versym as *const u16) };
    build_versions(m);
    let writable = m.phdrs().iter().any(|p| p.typ == PT_DYNAMIC && p.flags & PF_W != 0);
    if writable && a != 0 && !m.dyn_adjusted() {
        m.set_dyn_adjusted(true);
        dyn_rebase(m, a as u64, true);
    }
}

pub fn dyn_rebase(m: Map, a: u64, add: bool) {
    let mut d = m.l_ld();
    loop {
        let e = unsafe { *d };
        if e.tag == DT_NULL {
            break;
        }
        if matches!(e.tag, DT_HASH | DT_PLTGOT | DT_STRTAB | DT_SYMTAB | DT_RELA | DT_JMPREL | DT_VERSYM | DT_GNU_HASH | DT_RELR) {
            let v = if add { e.val.wrapping_add(a) } else { e.val.wrapping_sub(a) };
            unsafe { (*d).val = v };
        }
        d = d.wrapping_add(1);
    }
}

fn build_versions(m: Map) {
    let mut max = 0usize;
    for (vd, _) in m.verdefs() {
        max = max.max(vd.ndx as usize & 0x7fff);
    }
    for (_, _, aux) in m.verneeds() {
        for (a, _) in aux {
            max = max.max(a.other as usize & 0x7fff);
        }
    }
    if max == 0 {
        return;
    }
    let tbl = alloc_perm((max + 1) * core::mem::size_of::<VerInfo>(), 8) as *mut VerInfo;
    let t = unsafe { crate::ffi::slice_mut(tbl, max + 1) };
    for e in t.iter_mut() {
        *e = VerInfo { name: None, hash: 0, file: None, hidden: false };
    }
    for (vd, name) in m.verdefs() {
        let idx = vd.ndx as usize & 0x7fff;
        if vd.flags & 1 == 0 {
            t[idx] = VerInfo { name: Some(name), hash: vd.hash, file: None, hidden: false };
        }
    }
    for (_, file, aux) in m.verneeds() {
        for (a, name) in aux {
            let idx = a.other as usize & 0x7fff;
            t[idx] = VerInfo { name: Some(name), hash: a.hash, file: Some(file), hidden: a.other & 0x8000 != 0 };
        }
    }
    unsafe { m.set_vers(tbl) };
    unsafe { m.set_nvers(max + 1) };
}

pub unsafe fn scan_phdrs(m: Map) {
    let a = m.l_addr();
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for p in m.phdrs() {
        if p.typ == PT_LOAD {
            lo = lo.min(page_down(p.vaddr as usize));
            hi = hi.max(page_up((p.vaddr + p.memsz) as usize));
        }
    }
    if m.map_end() == 0 && lo != usize::MAX {
        m.set_map_start(a + lo);
        m.set_map_end(a + hi);
    }
    for p in m.phdrs() {
        match p.typ {
            PT_DYNAMIC => unsafe { m.set_l_ld((a + p.vaddr as usize) as *mut Dyn) },
            PT_TLS => {
                unsafe { m.set_tls_image(a + p.vaddr as usize) };
                unsafe { m.set_tls_filesz(p.filesz as usize) };
                unsafe { m.set_tls_memsz(p.memsz as usize) };
                m.set_tls_align((p.align as usize).max(1));
            }
            PT_GNU_RELRO => {
                m.set_relro_start(a + p.vaddr as usize);
                m.set_relro_len(p.memsz as usize);
            }
            PT_GNU_EH_FRAME => m.set_eh_frame_hdr(a + p.vaddr as usize),
            _ => {}
        }
    }
}

fn page_down(x: usize) -> usize {
    x & !(sys::PAGE - 1)
}
fn page_up(x: usize) -> usize {
    (x + sys::PAGE - 1) & !(sys::PAGE - 1)
}

pub fn make_stack_executable() -> isize {
    let page = crate::__libc_stack_end.load(core::sync::atomic::Ordering::Relaxed) & !(sys::PAGE - 1);
    let r = unsafe { sys::mprotect(page, sys::PAGE, sys::PROT_READ | sys::PROT_WRITE | sys::PROT_EXEC | 0x0100_0000 ) };
    if r == 0 {
        st().stack_exec = true;
    }
    r
}

pub fn errno_text(e: c_int) -> &'static str {
    match e {
        1 => "Operation not permitted",
        2 => "No such file or directory",
        5 => "Input/output error",
        8 => "Exec format error",
        12 => "Cannot allocate memory",
        13 => "Permission denied",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        23 => "Too many open files in system",
        24 => "Too many open files",
        36 => "File name too long",
        40 => "Too many levels of symbolic links",
        _ => "Unknown error",
    }
}

fn neg_errno(r: isize) -> c_int {
    if r < 0 && r > -4096 { -r as c_int } else { 0 }
}

pub static SKIPPED: AtomicU8 = AtomicU8::new(0);

pub fn map_file(nsid: usize, path: &CStr, name: &'static CStr, loader: Option<Map>) -> Option<Map> {
    let fd = sys::open(path);
    if fd < 0 {
        set_error_at(b"", neg_errno(fd), format_args!("cannot open shared object file"));
        return None;
    }
    let r = map_fd(nsid, fd, name, loader);
    sys::close(fd);
    if r.is_none() {
        match SKIPPED.load(Relaxed) {
            1 => set_error(format_args!("wrong ELF class: ELFCLASS32")),
            2 => set_error_at(b"", 2, format_args!("cannot open shared object file")),
            _ => {}
        }
    }
    r
}

fn map_fd(nsid: usize, fd: isize, name: &'static CStr, loader: Option<Map>) -> Option<Map> {
    let (dev, ino) = sys::fstat_id(fd);
    if let Some(cur) = ns(nsid).maps().find(|c| c.dev() == dev && c.ino() == ino && dev != 0 && !c.unloading()) {
        return Some(cur);
    }
    let mut hdr_buf = core::mem::MaybeUninit::<[u64; 128]>::uninit();
    let hdr_bytes = unsafe { crate::ffi::slice_mut(hdr_buf.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>, 1024) };
    SKIPPED.store(0, Relaxed);
    let file = name.to_bytes();
    let n = sys::pread(fd, hdr_bytes, 0);
    if n < core::mem::size_of::<Ehdr>() as isize {
        let e = neg_errno(n);
        set_error_at(file, e, format_args!("{}", if e == 0 { "file too short" } else { "cannot read file data" }));
        return None;
    }
    let hdr = hdr_buf.as_ptr() as *const u8;
    let eh = unsafe { at(hdr as *const Ehdr) };
    let id = &eh.ident;
    let osabi_ok = id[7] == 0 || id[7] == 3;
    let abiver_ok = id[8] == 0 || (id[7] == 3 && id[8] < 4);
    if &id[..4] != b"\x7fELF" || id[4] != 2 || id[5] != 1 || id[6] != 1 || !osabi_ok || !abiver_ok || id[9..16].iter().any(|&b| b != 0) {
        let msg = if &id[..4] != b"\x7fELF" {
            "invalid ELF header"
        } else if id[4] != 2 {
            SKIPPED.store(1, Relaxed);
            set_error(format_args!("wrong ELF class: ELFCLASS32"));
            return None;
        } else if id[5] != 1 {
            "ELF file data encoding not little-endian"
        } else if id[6] != 1 {
            "ELF file version ident does not match current one"
        } else if !osabi_ok {
            "ELF file OS ABI invalid"
        } else if !abiver_ok {
            "ELF file ABI version invalid"
        } else {
            "nonzero padding in e_ident"
        };
        set_error_at(file, 0, format_args!("{}", msg));
        return None;
    }
    if eh.version != 1 {
        set_error_at(file, 0, format_args!("ELF file version does not match current one"));
        return None;
    }
    if eh.machine != EM_X86_64 {
        SKIPPED.store(2, Relaxed);
        set_error_at(b"", 2, format_args!("cannot open shared object file"));
        return None;
    }
    if eh.typ != ET_DYN && eh.typ != ET_EXEC {
        set_error_at(file, 0, format_args!("only ET_DYN and ET_EXEC can be loaded"));
        return None;
    }
    if eh.phentsize as usize != core::mem::size_of::<Phdr>() {
        set_error_at(file, 0, format_args!("ELF file's phentsize not the expected size"));
        return None;
    }
    let phn = eh.phnum as usize;
    let phsz = phn * core::mem::size_of::<Phdr>();
    let ph: &[Phdr] = if eh.phoff as usize + phsz > n as usize {
        let phbuf = alloc_perm(phsz, 8);
        let dst = unsafe { crate::ffi::slice_mut(phbuf as *mut core::mem::MaybeUninit<u8>, phsz) };
        let r = sys::pread(fd, dst, eh.phoff as usize);
        if r != phsz as isize {
            set_error_at(file, neg_errno(r), format_args!("cannot read file data"));
            return None;
        }
        unsafe { slice(phbuf as *const Phdr, phn) }
    } else {
        unsafe { slice(hdr.wrapping_add(eh.phoff as usize) as *const Phdr, phn) }
    };
    if ph.iter().any(|p| p.typ == PT_LOAD && (p.vaddr.wrapping_sub(p.offset) as usize) & (sys::PAGE - 1) != 0) {
        set_error(format_args!("ELF load command address/offset not page-aligned"));
        return None;
    }
    if !st().stack_exec && ph.iter().find(|p| p.typ == PT_GNU_STACK).is_none_or(|p| p.flags & PF_X != 0) {
        let err = if !st().started && st().execstack_mode == 1 { make_stack_executable() } else { -22 };
        if err != 0 {
            set_error_at(b"", neg_errno(err), format_args!("cannot enable executable stack as shared object requires"));
            st().hard_error = true;
            return None;
        }
    }
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for p in ph {
        if p.typ == PT_LOAD {
            lo = lo.min(page_down(p.vaddr as usize));
            hi = hi.max(page_up((p.vaddr + p.memsz) as usize));
        }
    }
    if lo == usize::MAX {
        set_error(format_args!("object file has no loadable segments"));
        return None;
    }
    if st().started && eh.typ == ET_EXEC {
        set_error(format_args!("cannot dynamically load executable"));
        return None;
    }
    let span = hi - lo;
    let first_load = ph.iter().find(|p| p.typ == PT_LOAD)?;
    let merged = first_load.flags & PF_W == 0 && first_load.memsz == first_load.filesz && page_down(first_load.vaddr as usize) == lo;
    let base = if eh.typ == ET_EXEC {
        let (prot0, flags, fd0, off0) = if merged {
            let p0 = (if first_load.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if first_load.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
            (p0, sys::MAP_PRIVATE | sys::MAP_FIXED_NOREPLACE, fd, page_down(first_load.offset as usize))
        } else {
            (sys::PROT_NONE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_FIXED_NOREPLACE, -1, 0)
        };
        let r = sys::mmap_new(lo, span, prot0, flags, fd0, off0);
        if r < 0 && r > -4096 {
            set_error(format_args!("cannot map executable at its fixed address"));
            return None;
        }
        0usize
    } else if merged {
        let prot0 = (if first_load.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if first_load.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
        let r = sys::mmap_new(0, span, prot0, sys::MAP_PRIVATE | map32_flag(ph), fd, page_down(first_load.offset as usize));
        if r < 0 && r > -4096 {
            set_error(format_args!("failed to map segment from shared object"));
            return None;
        }
        (r as usize).wrapping_sub(lo)
    } else {
        let r = sys::mmap_new(0, span, sys::PROT_NONE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | map32_flag(ph), -1, 0);
        if r < 0 && r > -4096 {
            set_error(format_args!("failed to map segment from shared object"));
            return None;
        }
        (r as usize).wrapping_sub(lo)
    };
    let mut first = true;
    let mut load0_off = 0usize;
    let mut load0_vaddr = 0usize;
    let mut prev_end = 0usize;
    for p in ph {
        if p.typ != PT_LOAD {
            continue;
        }
        let was_first = first;
        if first {
            load0_off = p.offset as usize;
            load0_vaddr = p.vaddr as usize;
            first = false;
        }
        let prot = (if p.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if p.flags & PF_W != 0 { sys::PROT_WRITE } else { 0 }) | (if p.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
        let vaddr = p.vaddr as usize;
        let start = page_down(vaddr);
        let off = page_down(p.offset as usize);
        let filend = vaddr + p.filesz as usize;
        if merged && !was_first && start > prev_end {
            unsafe { sys::mprotect(base + prev_end, start - prev_end, sys::PROT_NONE) };
        }
        if !(merged && was_first) {
            let r = unsafe { sys::mmap(base + start, page_up(filend) - start, prot, sys::MAP_PRIVATE | sys::MAP_FIXED, fd, off) };
            if r < 0 && r > -4096 {
                set_error(format_args!("failed to map segment from shared object"));
                unsafe { sys::munmap(base + lo, span) };
                return None;
            }
        }
        let memend = vaddr + p.memsz as usize;
        prev_end = page_up(memend);
        if memend > filend {
            if p.flags & PF_W != 0 && filend & (sys::PAGE - 1) != 0 {
                let z = page_up(filend) - filend;
                unsafe { core::ptr::write_bytes((base + filend) as *mut u8, 0, z.min(memend - filend)) };
            }
            let anon_start = page_up(filend);
            let anon_end = page_up(memend);
            if anon_end > anon_start {
                let r = unsafe { sys::mmap(base + anon_start, anon_end - anon_start, prot, sys::MAP_PRIVATE | sys::MAP_FIXED | sys::MAP_ANONYMOUS, -1, 0) };
                if r < 0 && r > -4096 {
                    set_error(format_args!("failed to map segment from shared object"));
                    return None;
                }
            }
        }
    }
    let m = new_map();
    m.set_l_ns(nsid as isize);
    m.set_l_addr(base);
    unsafe { m.set_l_name(name.as_ptr() as *const u8) };
    m.set_typ(eh.typ);
    m.set_map_start(base + lo);
    m.set_map_end(base + hi);
    m.set_entry(base + eh.entry as usize);
    m.set_dev(dev);
    m.set_ino(ino);
    m.set_loader(loader);
    let ph_copy = alloc_perm(phsz, 8) as *mut Phdr;
    unsafe { crate::ffi::slice_mut(ph_copy, phn) }.copy_from_slice(ph);
    let in_map = (eh.phoff as usize) >= load0_off && (eh.phoff as usize + phsz) <= load0_off + 0x100000;
    let phdr = if in_map { (base + load0_vaddr + (eh.phoff as usize - load0_off)) as *const Phdr } else { ph_copy as *const Phdr };
    unsafe { m.set_phdr(phdr) };
    unsafe { m.set_phnum(phn) };
    unsafe { scan_phdrs(m) };
    if m.l_ld().is_null() {
        set_error(format_args!("object file has no dynamic section"));
        return None;
    }
    unsafe { parse_dynamic(m) };
    Some(m)
}

pub fn protect_relro(m: Map) {
    if m.relro_len() != 0 {
        let s = page_down(m.relro_start());
        let e = page_down(m.relro_start() + m.relro_len());
        if e > s {
            unsafe { sys::mprotect(s, e - s, sys::PROT_READ) };
        }
    }
}

const MAX_PATH: usize = 4096;

pub fn origin_of(m: Map) -> &'static [u8] {
    if let Some(o) = m.origin() {
        return o;
    }
    let mut path = PathBuf::new();
    let mut p: &[u8] = m.name();
    if p.is_empty() {
        path.reserve(4096);
        if path.readlink(c"/proc/self/exe") > 0 {
            p = path.bytes();
        }
    }
    let end = p.iter().rposition(|&c| c == b'/');
    let dir: &[u8] = match end {
        Some(0) => b"/",
        Some(i) => &p[..i],
        None => b".",
    };
    let o = dup(dir);
    unsafe { m.set_origin(o.as_ptr() as *const u8) };
    o.to_bytes()
}

pub(crate) fn expand(elem: &[u8], requester: Option<Map>, out: &mut PathBuf) -> usize {
    let put = |out: &mut PathBuf, s: &[u8]| {
        for &c in s {
            if out.len() < MAX_PATH - 1 {
                if out.len() + 2 > out.cap() {
                    out.reserve(out.len() + 2);
                }
                out.push(c);
            }
        }
    };
    let mut i = 0usize;
    while i < elem.len() {
        if elem[i] == b'$' {
            let rest = &elem[i + 1..];
            let (name, brace) = if rest.first() == Some(&b'{') {
                let e = rest.iter().position(|&c| c == b'}').unwrap_or(rest.len());
                (&rest[1..e], true)
            } else {
                let e = rest.iter().position(|&c| !(c.is_ascii_alphanumeric() || c == b'_')).unwrap_or(rest.len());
                (&rest[..e], false)
            };
            let consumed = 1 + name.len() + if brace { 2 } else { 0 };
            match (name, requester) {
                (b"ORIGIN", Some(r)) => put(out, origin_of(r)),
                (b"LIB", _) => put(out, b"lib64"),
                (b"PLATFORM", _) => put(out, b"x86_64"),
                _ => put(out, &elem[i..i + consumed]),
            }
            i += consumed;
        } else {
            put(out, &elem[i..i + 1]);
            i += 1;
        }
    }
    if out.len() + 1 > out.cap() {
        out.reserve(out.len() + 1);
    }
    out.len()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    Map(Map),
    Exists,
}

fn probe_found(nsid: usize, fd: isize) -> Hit {
    if PROBE_IDENT.load(Relaxed) {
        let (dev, ino) = sys::fstat_id(fd);
        sys::close(fd);
        return match ns(nsid).maps().find(|c| c.dev() == dev && c.ino() == ino && dev != 0 && !c.unloading()) {
            Some(m) => Hit::Map(m),
            None => Hit::Exists,
        };
    }
    sys::close(fd);
    Hit::Exists
}

unsafe fn searched_name(r: *const u8, path: &CStr) -> &CStr {
    if r == path.as_ptr() as *const u8 {
        return path;
    }
    let other = unsafe { cstr_nul(r) };
    if other.to_bytes() != path.to_bytes() { other } else { path }
}

fn try_dirs(nsid: usize, list: &[u8], name: &[u8], requester: Option<Map>, loader: Option<Map>, code: u32, found_err: &mut bool) -> Option<Hit> {
    let probe = PROBE_ONLY.load(Relaxed);
    for elem in list.split(|&c| c == b':') {
        let mut path = PathBuf::new();
        let n = if elem.is_empty() {
            path.push(b'.');
            1
        } else {
            expand(elem, requester, &mut path)
        };
        if n + 1 + name.len() + 1 > MAX_PATH {
            continue;
        }
        path.reserve(n + 1 + name.len() + 1);
        path.push(b'/');
        path.extend(name);
        let candidate = path.as_cstr();
        let mut openp = candidate;
        if !probe && audit::wants_objsearch() {
            let r = audit::objsearch(candidate, loader, code);
            if r.is_null() {
                continue;
            }
            openp = unsafe { searched_name(r, candidate) };
        }
        let fd = sys::open(openp);
        if fd < 0 {
            continue;
        }
        if SECURE_SEARCH.load(Relaxed) && sys::fstat_mode(fd) & 0o4000 == 0 {
            sys::close(fd);
            continue;
        }
        if probe {
            return Some(probe_found(nsid, fd));
        }
        let m = map_fd(nsid, fd, dup(candidate.to_bytes()), requester);
        sys::close(fd);
        if let Some(m) = m {
            return Some(Hit::Map(m));
        }
        match SKIPPED.load(Relaxed) {
            1 => *found_err = true,
            2 => {}
            _ => {
                st().hard_error = true;
                return None;
            }
        }
    }
    None
}

const DEFAULT_DIRS: &[u8] = b"/lib64:/usr/lib64:/lib:/usr/lib";

pub static SECURE_SEARCH: AtomicBool = AtomicBool::new(false);
const PROBE_ONLY_SKIP_CACHE: bool = false;

struct Cache {
    ptr: usize,
    len: usize,
    tried: bool,
    open_err: isize,
}
static CACHE: SyncCell<Cache> = SyncCell::new(Cache { ptr: 0, len: 0, tried: false, open_err: 0 });

pub(crate) fn cache_open_error() -> Option<&'static str> {
    let c = cache_load();
    if c.open_err < 0 { Some(errno_text(neg_errno(c.open_err))) } else { None }
}

fn cache_load() -> Cache {
    unsafe {
        CACHE.with_unsync(|c| {
            if !c.tried {
                c.tried = true;
                let fd = sys::open(c"/etc/ld.so.cache");
                if fd < 0 {
                    c.open_err = fd;
                } else {
                    let len = sys::fstat_size(fd);
                    if len > 16 {
                        let r = sys::mmap_new(0, len, sys::PROT_READ, sys::MAP_PRIVATE, fd, 0);
                        if !(r < 0 && r > -4096) {
                            c.ptr = r as usize;
                            c.len = len;
                        }
                    }
                    sys::close(fd);
                }
            }
            Cache { ptr: c.ptr, len: c.len, tried: c.tried, open_err: c.open_err }
        })
    }
}

pub(crate) fn cache_lookup(name: &[u8]) -> Option<&'static [u8]> {
    let c = cache_load();
    if c.ptr == 0 {
        return None;
    }
    let file: &'static [u8] = unsafe { slice(c.ptr as *const u8, c.len) };
    let rd32 = |off: usize| -> u32 { file.get(off..off + 4).map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]])) };
    let mut hdr = 0usize;
    if file.get(..11) == Some(&b"ld.so-1.7.0"[..]) {
        let nlibs = rd32(12) as usize;
        hdr = (16 + nlibs * 12 + 7) & !7;
    }
    if hdr + 48 > c.len || &file[hdr..hdr + 20] != b"glibc-ld.so.cache1.1" {
        return None;
    }
    let nlibs = rd32(hdr + 20) as usize;
    let entries = hdr + 48;
    if entries + nlibs * 24 > c.len {
        return None;
    }
    let key_of = |i: usize| rd32(entries + i * 24 + 4) as usize;
    let (mut lo, mut hi) = (0usize, nlibs);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let k = key_of(mid);
        if k >= c.len || libcmp(&file[k..], name) > 0 {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut i = lo;
    while i < nlibs {
        let e = entries + i * 24;
        let key = rd32(e + 4) as usize;
        let val = rd32(e + 8) as usize;
        if key >= c.len || libcmp(&file[key..], name) != 0 {
            break;
        }
        i += 1;
        let flags = rd32(e);
        let hwcaps = u64::from(rd32(e + 16)) | u64::from(rd32(e + 20)) << 32;
        if flags & 0xff00 != 0x0300 || (hwcaps >> 62) & 1 != 0 || val >= c.len || !cache_str_eq(&file[key..], name) {
            continue;
        }
        return Some(cache_str(&file[val..]));
    }
    None
}

fn cache_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(n) => &s[..n],
        None => s,
    }
}

fn cache_str_eq(s: &[u8], name: &[u8]) -> bool {
    s.len() > name.len() && &s[..name.len()] == name && s[name.len()] == 0
}

fn libcmp(s1: &[u8], name: &[u8]) -> i32 {
    let at1 = |i: usize| -> u8 { if i < s1.len() { s1[i] } else { 0 } };
    let at = |j: usize| -> u8 { if j < name.len() { name[j] } else { 0 } };
    let (mut i, mut j) = (0usize, 0usize);
    while at1(i) != 0 {
        let c1 = at1(i);
        let c2 = at(j);
        if c1.is_ascii_digit() {
            if c2.is_ascii_digit() {
                let (mut v1, mut v2) = ((c1 - b'0') as i64, (c2 - b'0') as i64);
                i += 1;
                j += 1;
                while at1(i).is_ascii_digit() {
                    v1 = v1 * 10 + (at1(i) - b'0') as i64;
                    i += 1;
                }
                while at(j).is_ascii_digit() {
                    v2 = v2 * 10 + (at(j) - b'0') as i64;
                    j += 1;
                }
                if v1 != v2 {
                    return if v1 > v2 { 1 } else { -1 };
                }
            } else {
                return 1;
            }
        } else if c2.is_ascii_digit() {
            return -1;
        } else if c1 != c2 {
            return c1 as i32 - c2 as i32;
        } else {
            i += 1;
            j += 1;
        }
    }
    0 - at(j) as i32
}

static PROBE_ONLY: AtomicBool = AtomicBool::new(false);

static PROBE_IDENT: AtomicBool = AtomicBool::new(false);

pub fn find_loaded_by_file(nsid: usize, name: &[u8], requester: Option<Map>) -> Option<Map> {
    PROBE_ONLY.store(true, Relaxed);
    PROBE_IDENT.store(true, Relaxed);
    let r = load_library_search(nsid, name, requester);
    PROBE_IDENT.store(false, Relaxed);
    PROBE_ONLY.store(false, Relaxed);
    match r {
        Some(Hit::Map(m)) => Some(m),
        _ => None,
    }
}

pub fn library_exists(nsid: usize, name: &[u8], requester: Option<Map>) -> bool {
    PROBE_ONLY.store(true, Relaxed);
    let r = load_library_search(nsid, name, requester);
    PROBE_ONLY.store(false, Relaxed);
    r.is_some()
}

pub fn find_loaded(nsid: usize, name: &[u8]) -> Option<Map> {
    ns(nsid).maps().find(|c| {
        if c.unloading() {
            return false;
        }
        if c.soname() == Some(name) {
            return true;
        }
        let n = c.name();
        n == name && !n.is_empty()
    })
}

fn names_ldso(name: &[u8]) -> bool {
    match st().ldso_map {
        None => false,
        Some(l) => l.soname() == Some(name) || l.name() == name,
    }
}

fn ldso_mirror(nsid: usize) -> Map {
    let real = ldso_map();
    let m = new_map();
    unsafe { core::ptr::copy_nonoverlapping(real.as_ptr() as *const u8, m.as_ptr() as *mut u8, core::mem::size_of::<LinkMap>()) };
    m.set_real(Some(real));
    m.set_l_ns(nsid as isize);
    m.set_prev(None);
    m.set_next(None);
    m.set_refcount(0);
    m.set_nodelete(false);
    m.set_in_global(false);
    unsafe { m.set_scope(null_mut()) };
    unsafe { m.set_nscope(0) };
    unsafe { m.set_xscope(null_mut()) };
    unsafe { m.set_nxscope(0) };
    unsafe { m.set_reldeps(null_mut()) };
    unsafe { m.set_nreldeps(0) };
    unsafe { m.set_creldeps(0) };
    m.set_opening(false);
    m.set_dlopened(true);
    link_map(m);
    m
}

pub fn load_library(nsid: usize, name: &[u8], requester: Option<Map>) -> Option<Map> {
    if let Some(m) = find_loaded(nsid, name) {
        return Some(m);
    }
    if nsid != 0 && names_ldso(name) {
        return Some(ldso_mirror(nsid));
    }
    if nsid != 0 && name == b"libc.so.6" && !PROBE_ONLY.load(Relaxed)
        && let Some(base) = ns(0).libc_map
    {
        let path = base.name();
        if !path.is_empty() && path.contains(&b'/')
            && let Some(Hit::Map(m)) = load_library_search(nsid, path, requester)
        {
            return Some(m);
        }
    }
    match load_library_search(nsid, name, requester) {
        Some(Hit::Map(m)) => Some(m),
        _ => None,
    }
}

fn load_library_search(nsid: usize, name: &[u8], requester: Option<Map>) -> Option<Hit> {
    let probe_only = PROBE_ONLY.load(Relaxed);
    let asked = name;
    let mut name = name;
    let mut buf = PathBuf::new();
    if !probe_only && audit::wants_objsearch() && requester.is_some() {
        buf.reserve(name.len() + 1);
        buf.extend(name);
        let orig = buf.as_cstr();
        let r = audit::objsearch(orig, requester, audit::LA_SER_ORIG);
        if r.is_null() {
            set_error_at(name, 2, format_args!("cannot open shared object file"));
            return None;
        }
        if r != orig.as_ptr() as *const u8 {
            name = unsafe { cstr(r) };
        }
    }
    let mut m: Option<Hit> = None;
    let mut bad = false;
    st().hard_error = false;
    let main_or = |r: Option<Map>| r.or(st().main_map);
    if name.contains(&b'/') {
        let mut path = PathBuf::new();
        if name.len() >= 4095 {
            set_error_at(name, 36, format_args!("cannot open shared object file"));
            return None;
        }
        expand(name, requester, &mut path);
        let p = path.as_cstr();
        m = if probe_only {
            let fd = sys::open(p);
            if fd < 0 {
                set_error_at(b"", neg_errno(fd), format_args!("cannot open shared object file"));
                None
            } else {
                Some(probe_found(nsid, fd))
            }
        } else {
            map_file(nsid, p, dup(p.to_bytes()), requester).map(Hit::Map)
        };
        if m.is_none() {
            set_error_obj(name);
        }
    } else {
        let mut r = requester;
        while m.is_none() && !st().hard_error {
            let Some(rm) = r else { break };
            if let (Some(rp), None) = (rm.rpath(), rm.runpath()) {
                m = try_dirs(nsid, rp, name, Some(rm), requester, audit::LA_SER_RUNPATH, &mut bad);
            }
            r = rm.loader();
        }
        if m.is_none() && !st().hard_error && !st().library_path.is_null() {
            let lp = unsafe { cstr(st().library_path) };
            m = try_dirs(nsid, lp, name, requester, main_or(requester), audit::LA_SER_LIBPATH, &mut bad);
        }
        if m.is_none() && !st().hard_error
            && let Some(rp) = requester.and_then(|r| r.runpath())
        {
            m = try_dirs(nsid, rp, name, requester, requester, audit::LA_SER_RUNPATH, &mut bad);
        }
        if m.is_none() && !st().hard_error && nsid != 0
            && let Some(base) = ns(0).libc_map
        {
            let p = base.name();
            if let Some(slash) = p.iter().rposition(|&c| c == b'/') {
                m = try_dirs(nsid, &p[..slash.max(1)], name, requester, main_or(requester), audit::LA_SER_DEFAULT, &mut bad);
            }
        }
        if m.is_none() && !st().hard_error && !PROBE_ONLY_SKIP_CACHE && !SECURE_SEARCH.load(Relaxed)
            && let Some(path) = cache_lookup(name)
        {
            let mut dir = PathBuf::new();
            if path.len() < MAX_PATH - 1 {
                dir.reserve(path.len() + 1);
                dir.extend(path);
                let candidate = dir.as_cstr();
                let mut openp = Some(candidate);
                if !probe_only && audit::wants_objsearch() {
                    let r = audit::objsearch(candidate, main_or(requester), audit::LA_SER_CONFIG);
                    openp = if r.is_null() {
                        None
                    } else {
                        Some(unsafe { searched_name(r, candidate) })
                    };
                }
                let fd = match openp {
                    None => -1,
                    Some(p) => sys::open(p),
                };
                if fd >= 0 {
                    if probe_only {
                        sys::close(fd);
                        return Some(Hit::Exists);
                    }
                    m = map_fd(nsid, fd, dup(path), requester).map(Hit::Map);
                    sys::close(fd);
                    if m.is_none() {
                        let sk = SKIPPED.load(Relaxed);
                        if sk == 1 {
                            bad = true;
                        } else if sk == 0 {
                            st().hard_error = true;
                        }
                    }
                }
            }
        }
        if m.is_none() && !st().hard_error {
            m = try_dirs(nsid, DEFAULT_DIRS, name, requester, main_or(requester), audit::LA_SER_DEFAULT, &mut bad);
        }
        if m.is_none() && st().hard_error {
            set_error_obj(name);
        } else if m.is_none() && bad {
            set_error_at(name, 0, format_args!("wrong ELF class: ELFCLASS32"));
        } else if m.is_none() {
            set_error_at(name, 2, format_args!("cannot open shared object file"));
        }
    }
    let hit = m?;
    if let Hit::Map(mm) = hit {
        let n = ns(mm.l_ns() as usize);
        if !probe_only && mm.prev().is_none() && n.head != Some(mm) && mm.next().is_none() && n.tail != Some(mm) {
            link_map(mm);
        }
        if !probe_only && mm.req_name_ptr().is_null() {
            unsafe { mm.set_req_name(dup(asked).as_ptr() as *const u8) };
        }
    }
    Some(hit)
}

fn map32_flag(ph: &[Phdr]) -> usize {
    if st().map32 && ph.iter().any(|p| p.typ == PT_LOAD && p.flags & PF_X != 0) { 0x40 } else { 0 }
}
