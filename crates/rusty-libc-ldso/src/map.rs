//! Link maps: mapping an ELF file into memory, parsing its dynamic section, finding libraries on disk.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::audit;
use crate::ldebug;
use crate::elf::*;
use crate::ffi::{CStrRef, at, cstr, cstr_nul, cstr_opt, slice};
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::util::*;
use core::ffi::{CStr, c_int};
use core::ptr::{NonNull, null, null_mut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering::Relaxed};

/// Symbol version information of one `.gnu.version` index (from DT_VERDEF or DT_VERNEED); all zero (None) for an index
/// neither defines.
#[derive(Clone, Copy)]
pub struct VerInfo {
    pub name: Option<CStrRef>,
    pub hash: u32,
    /// For a DT_VERNEED entry: the file that should define it (soname); None for a DT_VERDEF entry.
    pub file: Option<CStrRef>,
    pub hidden: bool,
}

/// glibc's `struct libname_list`: the names a library is known by (the first is the one it was asked for).
#[repr(C)]
pub struct LibName {
    pub name: *const u8,
    pub next: *mut LibName,
    pub dont_free: i32,
}

/// `struct link_map` of glibc starts with these five fields (the public part: `l_addr`, `l_name`, `l_ld`, `l_next`,
/// `l_prev`), so debuggers and `dlinfo(RTLD_DI_LINKMAP)` users see what they expect; the rest is ours.
#[repr(C)]
pub struct LinkMap {
    pub l_addr: usize,
    pub l_name: *const u8,
    pub l_ld: *mut Dyn,
    pub l_next: *mut LinkMap,
    pub l_prev: *mut LinkMap,
    /// The next three are glibc's `l_real`, `l_ns` and `l_libname` (audit libraries such as sotruss's read the name list).
    pub l_real: *mut LinkMap,
    pub l_ns: isize,
    pub l_libname: *mut LibName,
    // ---- private from here
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
    // DT_GNU_HASH
    pub gnu_nbuckets: u32,
    pub gnu_symoffset: u32,
    pub gnu_bloom_size: u32,
    pub gnu_bloom_shift: u32,
    pub gnu_bloom: *const u64,
    pub gnu_buckets: *const u32,
    pub gnu_chain: *const u32,
    // DT_HASH
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
    /// DT_AUDIT / DT_DEPAUDIT: offset in the string table plus one (0: the tag is absent).
    pub audit_str: u64,
    pub depaudit_str: u64,
    /// Loaded by dlopen with RTLD_NOW: every PLT slot is bound at load time whatever the audit libraries ask (glibc's reloc_mode without RTLD_LAZY).
    pub rtld_now: bool,
    /// The PLT of this object is bound lazily (decided once, at the start of its relocation: see `reloc::lazy_plt_decide`).
    pub lazy_plt: bool,
    /// DT_TEXTREL: relocations in a read-only segment; the segments are made writable while relocating.
    pub textrel: bool,
    /// The load address has been added to the address entries of the dynamic section (see `parse_dynamic`).
    pub dyn_adjusted: bool,
    pub rpath: *const u8,
    pub runpath: *const u8,
    pub relro_start: usize,
    pub relro_len: usize,
    pub eh_frame_hdr: usize,
    /// DT_NEEDED names (offsets into strtab) are re-read from the dynamic section; the resolved maps:
    pub needed: *mut *mut LinkMap,
    pub nneeded: usize,
    /// The map that asked for this one (for RPATH inheritance and $ORIGIN); null for the program.
    pub loader: *mut LinkMap,
    pub origin: *const u8,
    // TLS
    pub tls_modid: usize,
    pub tls_image: usize,
    pub tls_filesz: usize,
    pub tls_memsz: usize,
    pub tls_align: usize,
    /// Static TLS offset below the thread pointer (valid when `tls_static`).
    pub tls_offset: usize,
    pub tls_static: bool,
    pub dev: u64,
    pub ino: u64,
    pub relocated: bool,
    pub init_called: bool,
    /// Created by a dlopen that has not finished yet (its constructors have not run): a nested dlopen of this map, for example from
    /// an audit callback, returns it without running them (glibc `dl_open_worker_begin`, early return for a map with a search list).
    pub opening: bool,
    pub fini_called: bool,
    pub is_main: bool,
    pub is_ldso: bool,
    /// The kernel's vDSO image (listed, never searched globally).
    pub is_vdso: bool,
    pub in_global: bool,
    pub nodelete: bool,
    /// Loaded by dlopen (glibc's `lt_loaded`), as opposed to the program and what it needs at startup.
    pub dlopened: bool,
    /// Maps this one bound a symbol to without needing them (`l_reldeps`): kept loaded while this one is.
    pub reldeps: *mut *mut LinkMap,
    pub nreldeps: usize,
    pub creldeps: usize,
    pub unloading: bool,
    /// Destructors have run and the object is on its way out: symbol lookup skips it (glibc's `l_removed`). While its own
    /// destructors run (`unloading`) it is still searched, they may call each other lazily.
    pub removed: bool,
    /// Number of dlopen handles plus number of loaded maps that need this one.
    pub refcount: usize,
    /// Local search scope (this map and its dependencies, breadth first).
    pub scope: *mut *mut LinkMap,
    pub nscope: usize,
    /// Scopes added when a later dlopen needed this (already loaded) object: that group's objects, searched after `scope`.
    pub xscope: *mut *mut LinkMap,
    pub nxscope: usize,
    /// Dependency-first order used for constructors, set by `order_init`.
    pub init_seq: usize,
    pub lazy_pending: bool,
    pub deepbind: bool,
    /// rtld-audit: per audit library, the cookie `la_objopen` may set and the flags it returned.
    pub audit_cookie: [usize; 8],
    pub audit_flags: [u32; 8],
    pub audit_opened: bool,
    /// DT_FILTER / DT_AUXILIARY: the loaded filtees (also in `needed`); a symbol found in this object is looked up in them first.
    pub filtees: *mut *mut LinkMap,
    pub nfiltees: usize,
    /// The object has a DT_FILTER (not only DT_AUXILIARY entries): a symbol the filtees do not have is not provided.
    pub filter_hard: bool,

    /// Profiling (LD_PROFILE): resolved PLT targets by relocation index (null until the first call through the profiling PLT).
    pub plt_cache: *mut usize,
    /// Some relocation of the program bound a symbol defined here (glibc's `l_used`; read by `LD_DEBUG=unused`).
    pub used: bool,
    /// The name this library was asked for (DT_NEEDED string or dlopen argument); null for the program.
    pub req_name: *const u8,
    /// Some audit library's la_objopen returned binding flags for this object (glibc's `l_audit_any_plt`).
    pub audit_any_plt: bool,
    /// `thread_local` destructors of this object not yet run (glibc's `l_tls_dtor_count`): while nonzero, dlclose keeps it.
    pub tls_dtor_count: usize,
    /// dlopen calls minus dlclose calls on this object (glibc's `l_direct_opencount`; only `LD_DEBUG=files` shows it: the
    /// loader's own reference count, `refcount`, also counts the objects that need this one).
    pub direct_opens: usize,
}

// libthread_db finds a module's TLS id and static offset at these offsets (rusty-libc-core thread_db::LINK_MAP_TLS_MODID and
// LINK_MAP_TLS_OFFSET, which the descriptors give it)
const _: () = assert!(core::mem::offset_of!(LinkMap, tls_modid) == 504);
const _: () = assert!(core::mem::offset_of!(LinkMap, tls_offset) == 544);

// ---- Map: the loader's handle to a link map ----

/// A link map the loader made (`new_map`). Link maps are never freed (they come from permanent memory or the program's
/// `calloc`, and nothing gives them back), so a `Map` always points to a valid `LinkMap`. Its fields are read and written
/// through the raw pointer: no reference to a `LinkMap` is ever made, so the many handles to one map (lists, scopes,
/// dependency arrays, C callers' handles) never alias a `&mut` (Rust for Rustaceans p.288: the C side's invariants in a type;
/// Rust Design Patterns p.97-98: the unsafe part in one small module, a safe interface on top).
///
/// Synchronisation: the fields are plain memory, written at start-up (one thread) or under the loader lock (`dl::DL_LOCK`),
/// as glibc writes its `struct link_map` under `dl_load_lock`; `used`, which lazy binding sets from any thread, is written
/// atomically.
///
/// Invariant (what the safe accessors rely on): the pointer fields describe the object as its ELF headers and dynamic
/// section do. `l_ld` is a DT_NULL-terminated dynamic section; (`phdr`, `phnum`) its program headers; the string fields are
/// NUL-terminated strings; `strtab`/`strsz`, the hash tables, the version tables (well-formed DT_VERDEF and DT_VERNEED
/// chains, `vers` with `nvers` entries) and the relocation tables are those of the object; the map arrays (`needed`,
/// `filtees`, `reldeps`, `scope`, `xscope`) hold that many maps; the `*mut LinkMap` links are NULL or maps. The setters of
/// these fields are `unsafe` and their callers vouch for it (the object's own headers: `map_fd`, `scan_phdrs`,
/// `parse_dynamic`; arrays the loader fills). The object's data stays valid while it is mapped, until `dl::drop_map`, after
/// which no list, scope or array reaches the map. The loader trusts the contents of the objects it maps, as glibc does: a
/// malformed table is not detected.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Map(NonNull<LinkMap>);

impl core::fmt::Debug for Map {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Map({:p})", self.0)
    }
}

impl Map {
    /// The handle of the link map at `p` (NULL: None).
    ///
    /// # Safety
    /// `p` is NULL or a link map made by `new_map` (or an exact copy of one: `ldso_mirror`).
    #[inline(always)]
    pub unsafe fn from_ptr(p: *mut LinkMap) -> Option<Map> {
        NonNull::new(p).map(Map)
    }

    /// The map's address (what C callers get as a handle and what `l_next` stores).
    #[inline(always)]
    pub fn as_ptr(self) -> *mut LinkMap {
        self.0.as_ptr()
    }

    /// The address of a link field value (NULL for None), as `LinkMap` stores it.
    #[inline(always)]
    pub fn opt_ptr(m: Option<Map>) -> *mut LinkMap {
        match m {
            Some(m) => m.as_ptr(),
            None => null_mut(),
        }
    }
}

/// Field accessors. `get` reads the field; `set` writes it: `safe` fields hold plain values, `unsafe` ones carry part of the
/// invariant above (their setters are `unsafe fn`).
macro_rules! map_fields {
    (safe { $($f:ident, $set:ident : $t:ty;)* } unsafe { $($uf:ident => $ug:ident, $uset:ident : $ut:ty;)* }) => {
        impl Map {
            $(
                #[inline(always)]
                pub fn $f(self) -> $t {
                    // SAFETY: a `Map` points to a live `LinkMap` (never freed); a plain read of one field through the raw
                    // pointer (writers are serialised by the loader lock or start-up, see `Map`).
                    unsafe { (*self.0.as_ptr()).$f }
                }
                #[inline(always)]
                pub fn $set(self, v: $t) {
                    // SAFETY: as for the read; a plain write of one field, under the loader lock or at start-up.
                    unsafe { (*self.0.as_ptr()).$f = v }
                }
            )*
            $(
                #[inline(always)]
                pub fn $ug(self) -> $ut {
                    // SAFETY: as for the plain fields: a read of one field of a live `LinkMap`.
                    unsafe { (*self.0.as_ptr()).$uf }
                }
                /// # Safety
                /// The value keeps this field's part of the invariant (see [`Map`]).
                #[inline(always)]
                pub unsafe fn $uset(self, v: $ut) {
                    // SAFETY: a write of one field of a live `LinkMap`; the value keeps the invariant (caller's contract).
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
        direct_opens, set_direct_opens: usize;
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
    /// A `*mut LinkMap` link field (NULL or a map, by the invariant) as an `Option<Map>`.
    #[inline(always)]
    fn link(p: *mut LinkMap) -> Option<Map> {
        // SAFETY: the link fields hold NULL or maps (invariant of `Map`; their setters take `Option<Map>`).
        unsafe { Map::from_ptr(p) }
    }

    #[inline(always)]
    fn link_field(self, off: usize) -> *mut *mut LinkMap {
        (self.as_ptr() as *mut u8).wrapping_add(off) as *mut *mut LinkMap
    }

    #[inline(always)]
    fn get_link(self, off: usize) -> Option<Map> {
        // SAFETY: `off` is the offset of one of the `*mut LinkMap` fields of the live `LinkMap` (the callers below pass
        // `offset_of!`), aligned; a plain read under the loader's rule.
        Map::link(unsafe { *self.link_field(off) })
    }

    #[inline(always)]
    fn put_link(self, off: usize, v: Option<Map>) {
        // SAFETY: as in `get_link`; a plain write of NULL or a map keeps the link invariant.
        unsafe { *self.link_field(off) = Map::opt_ptr(v) }
    }

    /// The next map in its namespace's list (`l_next`).
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
    /// glibc's `l_real`: the map itself, or for a mirror of the loader the loader's real map.
    #[inline(always)]
    pub fn real(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, l_real))
    }
    #[inline(always)]
    pub fn set_real(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, l_real), v)
    }
    /// The map that asked for this one (RPATH inheritance, $ORIGIN); None for the program.
    #[inline(always)]
    pub fn loader(self) -> Option<Map> {
        self.get_link(core::mem::offset_of!(LinkMap, loader))
    }
    #[inline(always)]
    pub fn set_loader(self, v: Option<Map>) {
        self.put_link(core::mem::offset_of!(LinkMap, loader), v)
    }

    /// `used` (glibc's `l_used`): set by lazy binding from any thread, so read and written atomically.
    #[inline(always)]
    fn used_atomic(self) -> &'static core::sync::atomic::AtomicBool {
        let p = (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, used)) as *mut bool;
        // SAFETY: the `used` field of a live `LinkMap` (never freed: 'static), a `bool`, aligned; every access to it after
        // `new_map` zeroed it goes through this atomic.
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

    /// The address of the rtld-audit cookie of audit library `i` (what `la_objopen` and friends get to keep their data in).
    #[inline(always)]
    pub fn audit_cookie_ptr(self, i: usize) -> *mut usize {
        assert!(i < 8);
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, audit_cookie) + i * 8) as *mut usize
    }
    #[inline(always)]
    pub fn audit_cookie(self, i: usize) -> usize {
        // SAFETY: `audit_cookie_ptr` checked `i` and points into the live `LinkMap`; a plain read under the loader's rule.
        unsafe { *self.audit_cookie_ptr(i) }
    }
    #[inline(always)]
    pub fn set_audit_cookie(self, i: usize, v: usize) {
        // SAFETY: as in `audit_cookie`; a plain write.
        unsafe { *self.audit_cookie_ptr(i) = v }
    }
    #[inline(always)]
    fn audit_flags_ptr(self, i: usize) -> *mut u32 {
        assert!(i < 8);
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, audit_flags) + i * 4) as *mut u32
    }
    /// The binding flags `la_objopen` of audit library `i` returned for this object.
    #[inline(always)]
    pub fn audit_flags(self, i: usize) -> u32 {
        // SAFETY: `audit_flags_ptr` checked `i` and points into the live `LinkMap`; a plain read.
        unsafe { *self.audit_flags_ptr(i) }
    }
    #[inline(always)]
    pub fn set_audit_flags(self, i: usize, v: u32) {
        // SAFETY: as in `audit_flags`; a plain write.
        unsafe { *self.audit_flags_ptr(i) = v }
    }
    /// The address of the `plt_cache` field (profiling: installed with a compare-and-swap).
    #[inline(always)]
    pub fn plt_cache_field(self) -> *mut usize {
        (self.as_ptr() as *mut u8).wrapping_add(core::mem::offset_of!(LinkMap, plt_cache)) as *mut usize
    }

    // ---- views of the object's data (the invariant of `Map`) ----

    /// The object's file name (`l_name`; empty for the program, and for a map not named yet).
    #[inline]
    pub fn name(self) -> &'static [u8] {
        // SAFETY: `l_name` is NULL or a NUL-terminated string that lives as long as the map (invariant).
        unsafe { cstr_opt(self.l_name()) }.unwrap_or(b"")
    }
    /// DT_SONAME.
    #[inline]
    pub fn soname(self) -> Option<&'static [u8]> {
        // SAFETY: NULL or a string of the object's string table (invariant).
        unsafe { cstr_opt(self.soname_ptr()) }
    }
    /// DT_RPATH.
    #[inline]
    pub fn rpath(self) -> Option<&'static [u8]> {
        // SAFETY: NULL or a string of the object's string table (invariant).
        unsafe { cstr_opt(self.rpath_ptr()) }
    }
    /// DT_RUNPATH.
    #[inline]
    pub fn runpath(self) -> Option<&'static [u8]> {
        // SAFETY: NULL or a string of the object's string table (invariant).
        unsafe { cstr_opt(self.runpath_ptr()) }
    }
    /// `$ORIGIN` once computed (`origin_of`).
    #[inline]
    pub fn origin(self) -> Option<&'static [u8]> {
        // SAFETY: NULL or a string `dup` made (permanent).
        unsafe { cstr_opt(self.origin_ptr()) }
    }
    /// The name this library was asked for.
    #[inline]
    pub fn req_name(self) -> Option<&'static [u8]> {
        // SAFETY: NULL or a string `dup` made (permanent).
        unsafe { cstr_opt(self.req_name_ptr()) }
    }
    /// The program headers.
    #[inline]
    pub fn phdrs(self) -> &'static [Phdr] {
        // SAFETY: (`phdr`, `phnum`) are the object's program headers (invariant), never written.
        unsafe { slice(self.phdr(), self.phnum()) }
    }
    /// The maps this one needs (DT_NEEDED and filtees, in order; filled while it is loaded).
    #[inline]
    pub fn needed(self) -> &'static [Map] {
        // SAFETY: `nneeded` maps (non-NULL `*mut LinkMap`, the layout of `Map`) at `needed` (invariant); the array is only
        // appended to (past `nneeded`) while loading.
        unsafe { slice(self.needed_ptr() as *const Map, self.nneeded()) }
    }
    /// The loaded filtees (DT_FILTER / DT_AUXILIARY).
    #[inline]
    pub fn filtees(self) -> &'static [Map] {
        // SAFETY: as `needed`.
        unsafe { slice(self.filtees_ptr() as *const Map, self.nfiltees()) }
    }
    /// The maps this one bound symbols to without needing them (glibc's `l_reldeps`).
    #[inline]
    pub fn reldeps(self) -> &'static [Map] {
        // SAFETY: as `needed` (a full array is replaced by a bigger copy, never changed in place).
        unsafe { slice(self.reldeps_ptr() as *const Map, self.nreldeps()) }
    }
    /// The local search scope (empty until `build_scope`).
    #[inline]
    pub fn scope(self) -> &'static [Map] {
        // SAFETY: as `needed` (built once, never changed in place).
        unsafe { slice(self.scope_ptr() as *const Map, self.nscope()) }
    }
    /// The scopes later dlopen calls added.
    #[inline]
    pub fn xscope(self) -> &'static [Map] {
        // SAFETY: as `needed` (replaced by a new array, never changed in place).
        unsafe { slice(self.xscope_ptr() as *const Map, self.nxscope()) }
    }
    /// `.gnu.version` index -> version, both defined and needed ones.
    #[inline]
    pub fn vers(self) -> &'static [VerInfo] {
        // SAFETY: `nvers` entries at `vers` (invariant), written once by `build_versions`.
        unsafe { slice(self.vers_ptr() as *const VerInfo, self.nvers()) }
    }
    /// DT_RELA.
    #[inline]
    pub fn relas(self) -> &'static [Rela] {
        // SAFETY: the object's relocation table (invariant).
        unsafe { slice(self.rela(), self.relasz() / core::mem::size_of::<Rela>()) }
    }
    /// DT_JMPREL.
    #[inline]
    pub fn jmprels(self) -> &'static [Rela] {
        // SAFETY: the object's PLT relocation table (invariant).
        unsafe { slice(self.jmprel(), self.pltrelsz() / core::mem::size_of::<Rela>()) }
    }
    /// DT_RELR.
    #[inline]
    pub fn relrs(self) -> &'static [u64] {
        // SAFETY: the object's RELR table (invariant).
        unsafe { slice(self.relr(), self.relrsz() / 8) }
    }
    /// DT_INIT_ARRAY.
    #[inline]
    pub fn init_array(self) -> &'static [usize] {
        // SAFETY: the object's constructor array (invariant), relocated before it is read.
        unsafe { slice(self.init_array_ptr(), self.init_arraysz() / 8) }
    }
    /// DT_FINI_ARRAY.
    #[inline]
    pub fn fini_array(self) -> &'static [usize] {
        // SAFETY: the object's destructor array (invariant).
        unsafe { slice(self.fini_array_ptr(), self.fini_arraysz() / 8) }
    }
    /// DT_PREINIT_ARRAY.
    #[inline]
    pub fn preinit_array(self) -> &'static [usize] {
        // SAFETY: the object's pre-constructor array (invariant).
        unsafe { slice(self.preinit_array_ptr(), self.preinit_arraysz() / 8) }
    }
    /// The GNU hash table's Bloom filter words.
    #[inline]
    pub fn gnu_bloom_words(self) -> &'static [u64] {
        // SAFETY: `gnu_bloom_size` words at `gnu_bloom` (the object's DT_GNU_HASH, invariant).
        unsafe { slice(self.gnu_bloom(), self.gnu_bloom_size() as usize) }
    }
    /// The GNU hash table's buckets.
    #[inline]
    pub fn gnu_bucket_words(self) -> &'static [u32] {
        // SAFETY: `gnu_nbuckets` words at `gnu_buckets` (invariant).
        unsafe { slice(self.gnu_buckets(), self.gnu_nbuckets() as usize) }
    }
    /// The SysV hash table's buckets.
    #[inline]
    pub fn hash_bucket_words(self) -> &'static [u32] {
        // SAFETY: `hash_nbucket` words at `hash_buckets` (the object's DT_HASH, invariant).
        unsafe { slice(self.hash_buckets(), self.hash_nbucket() as usize) }
    }
    /// The SysV hash table's chains (one per symbol).
    #[inline]
    pub fn hash_chain_words(self) -> &'static [u32] {
        // SAFETY: `hash_nchain` words at `hash_chains` (invariant).
        unsafe { slice(self.hash_chains(), self.hash_nchain() as usize) }
    }
    /// The entries of the dynamic section, up to DT_NULL.
    #[inline]
    pub fn dynamic(self) -> DynIter {
        DynIter(self.l_ld())
    }
    /// The DT_NEEDED names (kind 0), then the DT_AUXILIARY (1) and DT_FILTER (2) filtee names.
    pub fn dep_names(self) -> impl Iterator<Item = (&'static [u8], u8)> {
        let kind_of = |t: i64| match t {
            DT_NEEDED => 0u8,
            DT_AUXILIARY => 1,
            DT_FILTER => 2,
            _ => 3,
        };
        let firsts = self.dynamic().filter(move |d| kind_of(d.tag) == 0);
        let filtees = self.dynamic().filter(move |d| matches!(kind_of(d.tag), 1 | 2));
        // SAFETY: the values of DT_NEEDED, DT_AUXILIARY and DT_FILTER are offsets of strings of the object's string table
        // (invariant: its dynamic section and string table).
        firsts.chain(filtees).map(move |d| (unsafe { self.str_at(d.val as usize) }, kind_of(d.tag)))
    }
    /// The DT_NEEDED names.
    pub fn needed_names(self) -> impl Iterator<Item = &'static [u8]> {
        // SAFETY: as in `dep_names`.
        self.dynamic().filter(|d| d.tag == DT_NEEDED).map(move |d| unsafe { self.str_at(d.val as usize) })
    }
    /// The DT_VERDEF entries: (entry, its first name).
    pub fn verdefs(self) -> impl Iterator<Item = (&'static Verdef, CStrRef)> {
        let mut vd = self.verdef();
        (0..self.verdefnum()).map(move |_| {
            // SAFETY: `verdefnum` well-formed entries chained by `vd_next` from `verdef`, each with its Verdaux at `vd_aux`
            // naming a string of the string table (invariant).
            let e = unsafe { at(vd) };
            // SAFETY: as above.
            let da = unsafe { at((vd as *const u8).wrapping_add(e.aux as usize) as *const Verdaux) };
            // SAFETY: as above.
            let name = unsafe { self.str_ref(da.name as usize) };
            vd = (vd as *const u8).wrapping_add(e.next as usize) as *const Verdef;
            (e, name)
        })
    }
    /// The DT_VERNEED entries: (entry, the file name it names, its Vernaux entries with their names).
    pub fn verneeds(self) -> impl Iterator<Item = (&'static Verneed, CStrRef, VernauxIter)> {
        let mut vn = self.verneed();
        (0..self.verneednum()).map(move |_| {
            // SAFETY: `verneednum` well-formed entries chained by `vn_next` from `verneed`, each naming a string of the
            // string table and followed (at `vn_aux`) by `vn_cnt` chained Vernaux entries (invariant).
            let e = unsafe { at(vn) };
            // SAFETY: as above.
            let file = unsafe { self.str_ref(e.file as usize) };
            let aux = VernauxIter { map: self, at: (vn as *const u8).wrapping_add(e.aux as usize) as *const Vernaux, left: e.cnt };
            vn = (vn as *const u8).wrapping_add(e.next as usize) as *const Verneed;
            (e, file, aux)
        })
    }

    /// The string at offset `off` of the string table.
    ///
    /// # Safety
    /// `off` is the offset of a string of this object's string table (a value read from its own tables).
    #[inline(always)]
    pub unsafe fn str_at(self, off: usize) -> &'static [u8] {
        // SAFETY: the string table holds a NUL-terminated string at `off` (caller's contract) while the object is mapped.
        unsafe { cstr(self.strtab().wrapping_add(off)) }
    }

    /// The string at offset `off` of the string table, by address.
    ///
    /// # Safety
    /// As [`Map::str_at`].
    #[inline(always)]
    pub unsafe fn str_ref(self, off: usize) -> CStrRef {
        // SAFETY: a NUL-terminated string of the object's string table (caller's contract), valid while it is mapped.
        unsafe { CStrRef::new(self.strtab().wrapping_add(off)) }
    }

    /// Symbol `idx` of the dynamic symbol table.
    ///
    /// # Safety
    /// `idx` is the index of a symbol of this object's symbol table (a value read from its own tables).
    #[inline(always)]
    pub unsafe fn sym(self, idx: usize) -> &'static Sym {
        // SAFETY: `idx` is inside the symbol table (caller's contract), which stays mapped while the object is loaded.
        unsafe { at(self.symtab().wrapping_add(idx)) }
    }

    /// The index of a symbol of this object's symbol table (what `sym` takes).
    #[inline(always)]
    pub fn sym_index(self, s: &Sym) -> usize {
        (s as *const Sym as usize).wrapping_sub(self.symtab() as usize) / core::mem::size_of::<Sym>()
    }

    /// The name of a symbol of this object.
    #[inline(always)]
    pub fn sym_name(self, s: &'static Sym) -> CStrRef {
        // SAFETY: the symbol's st_name is a string of the same object's string table (invariant: its tables).
        unsafe { self.str_ref(s.name as usize) }
    }
}

/// The entries of a dynamic section up to DT_NULL (copies).
pub struct DynIter(*const Dyn);

impl Iterator for DynIter {
    type Item = Dyn;
    #[inline]
    fn next(&mut self) -> Option<Dyn> {
        // SAFETY: the pointer walks a DT_NULL-terminated dynamic section (invariant of `Map`: `l_ld`) and stops at DT_NULL.
        let d = unsafe { *self.0 };
        if d.tag == DT_NULL {
            return None;
        }
        self.0 = self.0.wrapping_add(1);
        Some(d)
    }
}

/// The Vernaux entries of one Verneed: (entry, its version name).
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
        // SAFETY: one of the `vn_cnt` well-formed Vernaux entries of the map's DT_VERNEED (invariant).
        let a = unsafe { at(self.at) };
        // SAFETY: its name is a string of the string table (invariant).
        let name = unsafe { self.map.str_ref(a.name as usize) };
        self.at = (self.at as *const u8).wrapping_add(a.next as usize) as *const Vernaux;
        Some((a, name))
    }
}

pub const MAX_MAPS: usize = 1024;

/// Namespaces the loader can hold (glibc's `DL_NNS`): 0 is the base namespace (`LM_ID_BASE`, the program's).
pub const DL_NNS: usize = 16;

/// One namespace (glibc's `struct link_namespaces`): its own list of maps and its own global scope. Symbol lookup, name lookup
/// and the same-file check only look inside one namespace.
pub struct Ns {
    pub head: Option<Map>,
    pub tail: Option<Map>,
    pub nmaps: usize,
    /// The global scope: the program, preloaded libraries, then everything loaded at startup (and RTLD_GLOBAL dlopens).
    /// `MAX_MAPS` entries, allocated when the namespace gets its first global map (namespace 0 uses `BASE_GLOBAL`); the first
    /// `nglobal` are maps.
    global: *mut Option<Map>,
    pub nglobal: usize,
    /// The libc.so.6 of this namespace (glibc's `libc_map`); None while there is none. Set when a map with the soname
    /// `libc.so.6` is mapped, cleared when it goes.
    pub libc_map: Option<Map>,
}

/// Namespace 0's global scope (the others are allocated).
static BASE_GLOBAL: SyncCell<[Option<Map>; MAX_MAPS]> = SyncCell::new([None; MAX_MAPS]);

impl Ns {
    const EMPTY: Ns = Ns { head: None, tail: None, nmaps: 0, global: null_mut(), nglobal: 0, libc_map: None };

    /// The global scope of this namespace, in search order. (The array is appended to under the loader lock; `remove_global`,
    /// run by dlclose under the loader lock, compacts it in place.)
    pub fn scope(&self) -> &'static [Map] {
        if self.global.is_null() {
            return &[];
        }
        // SAFETY: `global` is a `MAX_MAPS`-entry array (BASE_GLOBAL or a permanent block) whose first `nglobal` entries are
        // maps (`push_global`); `Option<Map>` entries that are `Some` have the layout of `Map`.
        unsafe { slice(self.global as *const Map, self.nglobal) }
    }

    /// Append `m` to the global scope (false when the scope is full).
    pub fn push_global(&mut self, m: Map) -> bool {
        if self.nglobal >= MAX_MAPS {
            return false;
        }
        if self.global.is_null() {
            self.global = alloc_perm(MAX_MAPS * core::mem::size_of::<Option<Map>>(), 8) as *mut Option<Map>;
        }
        // SAFETY: `global` has `MAX_MAPS` entries (just allocated, zeroed = None, or BASE_GLOBAL) and nglobal < MAX_MAPS.
        unsafe { *self.global.wrapping_add(self.nglobal) = Some(m) };
        self.nglobal += 1;
        true
    }

    /// Take `m` out of the global scope.
    pub fn remove_global(&mut self, m: Map) {
        if self.global.is_null() {
            return;
        }
        // SAFETY: the first `nglobal` entries of the `MAX_MAPS`-entry array; `&mut self` is the namespace's only user here
        // (dlclose, under the loader lock).
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

    /// The maps of the namespace in list order (`l_next`).
    pub fn maps(&self) -> MapIter {
        MapIter(self.head)
    }
}

/// A walk along `l_next`.
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

/// The namespace `n` (the loader's rule for `STATE`: see [`st`]).
#[inline(always)]
pub fn ns(n: usize) -> &'static mut Ns {
    &mut st().ns[n]
}

/// The namespace of `m` (the base namespace for None).
#[inline(always)]
pub fn ns_of(m: Option<Map>) -> usize {
    match m {
        Some(m) => m.l_ns() as usize,
        None => 0,
    }
}

pub struct State {
    pub ns: [Ns; DL_NNS],
    /// One more than the highest namespace in use (glibc's `_dl_nns`).
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
    /// LD_PREFER_MAP_32BIT_EXEC / glibc.cpu.prefer_map_32bit_exec: libraries with executable code are mapped in the low 2 GB.
    pub map32: bool,
    /// Start-up is over: files mapped from now on come from dlopen.
    pub started: bool,
    /// Is the process's stack executable (the program's PT_GNU_STACK, executable when it has none)? A library that needs an
    /// executable stack cannot be loaded otherwise.
    pub stack_exec: bool,
    /// `glibc.rtld.execstack` (0 forbid, 1 default, 2 force); see `stack_exec`.
    pub execstack_mode: u8,
    /// `glibc.rtld.nns` and `glibc.rtld.optional_static_tls` (see `tls::static_surplus`).
    pub tls_nns: usize,
    pub tls_optional: usize,
    /// A file was found and mapping it failed for a reason that ends the search (glibc's `lose:` after the file was opened and
    /// checked, as opposed to a file that is not usable at all): the error text is in the error buffer.
    pub hard_error: bool,
    pub lenient: bool,
    pub debug: bool,
    pub bind_now_env: bool,
    pub trace: bool,
    pub prog_name: *const u8,
    pub page_size: usize,
    /// The latest message (`set_error`): null means the built-in buffer `ERR0`; it grows when a message needs more, so a long file
    /// name is quoted in full (glibc builds the text with malloc).
    pub error: *mut u8,
    pub error_cap: usize,
    pub error_len: usize,
    /// The parts of the composed text: the object name is the byte range `error_obj`, the message the range `error_msg`;
    /// `error_code` is the error number (0: none).
    pub error_obj: (usize, usize),
    pub error_msg: (usize, usize),
    pub error_code: c_int,
    pub ldso_base: usize,
    /// LD_AUDIT / --audit list (null: none).
    pub audit: *const u8,
    /// Trace mode extras: LD_VERBOSE (version information), LD_WARN (undefined symbols), LD_DEBUG=unused.
    pub trace_versions: bool,
    pub trace_warn: bool,
    pub trace_unused: bool,
    /// The library path came from `--library-path`, not LD_LIBRARY_PATH (the name `LD_DEBUG=libs` gives that list).
    pub library_path_opt: bool,
    /// `LD_DEBUG=libs` only: which list each search directory first came from (see `DebugDirs`; allocated on first use,
    /// so the loader's written data stays as small as it was).
    pub debug_dirs: Option<DebugDirs>,
}

/// glibc keeps one record per search directory, shared by every list that names it, and labels it with the list that
/// named it first (the system directories, then the program's DT_RPATH or DT_RUNPATH and LD_LIBRARY_PATH at start-up, then
/// each object's lists when they are first searched); `print_search_path` prints those labels. Kept (as a hash of the
/// directory) only while `LD_DEBUG=libs` is on.
pub struct DebugDirs {
    /// Each directory's hash (8 bytes, native order), the kind of list that named it first, and that list's file.
    hash: &'static mut [u8],
    kind: &'static mut [u8],
    owner: &'static mut [Option<Map>],
    n: usize,
}
const DEBUG_DIRS: usize = 48;

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
    library_path_opt: false,
    debug_dirs: None,
});

/// The loader's state. Rule (glibc's for its `_rtld_global`): written at start-up, while the process has one thread, and
/// afterwards only under the loader lock (`dl::DL_LOCK`), which every path that changes the namespaces or the error buffer
/// takes; the fields read without the lock (`prog_name`, `secure`, `trace` ...) are set once at start-up. The returned
/// reference is the loader's long-standing interface to its state (one `&mut` per call, used briefly); U3 keeps it on the
/// list of what remains to be narrowed.
#[inline(always)]
pub fn st() -> &'static mut State {
    // SAFETY: STATE is a static (lives for ever); the synchronisation rule above keeps writers apart.
    unsafe { &mut *STATE.as_ptr() }
}

/// The program's map (set at start-up, before any other code needs it).
#[inline]
pub fn main_map() -> Map {
    match st().main_map {
        Some(m) => m,
        None => crate::die(format_args!("internal error: no program map")),
    }
}

/// The loader's own map (set at start-up, before any other code needs it).
#[inline]
pub fn ldso_map() -> Map {
    match st().ldso_map {
        Some(m) => m,
        None => crate::die(format_args!("internal error: no loader map")),
    }
}

/// The built-in error buffer (the first 512 bytes of every message).
static ERR0: SyncCell<[u8; 512]> = SyncCell::new([0; 512]);

/// Counts the bytes a formatted message takes.
pub struct Count(pub usize);
impl core::fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// Record an error message without an object name or error number (see `set_error_at`).
pub fn set_error(args: core::fmt::Arguments) {
    set_error_at(b"", 0, args)
}

/// Record an error the way glibc's `_dl_signal_error (errcode, objname, NULL, errstring)` does: the object it is about (may be
/// empty), the message (`args`) and an error number (0: none). The buffer holds the composed text "OBJECT: MESSAGE: STRERROR"
/// (what a fatal startup error prints); the parts are kept apart (`error_obj`, `error_msg`, `error_code`) for libc.so.6's
/// dlerror, which composes and translates the message itself as glibc's dlerror.c does.
pub fn set_error_at(obj: &[u8], code: c_int, args: core::fmt::Arguments) {
    set_error_occ("", obj, code, args)
}

/// `set_error_at` with glibc's "occasion" in front of the composed text ("symbol lookup error: OBJECT: MESSAGE", what a
/// failed binding prints when it ends the program); dlerror never shows it.
pub fn set_error_occ(occasion: &str, obj: &[u8], code: c_int, args: core::fmt::Arguments) {
    use core::fmt::Write;
    /// Writes into the error buffer, whose room for the whole text was made first (the length was counted with `Count`).
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
    // SAFETY: `error` is ERR0 (512 bytes = the initial `error_cap`) or a permanent block of `error_cap` bytes; only this
    // function writes it, under the loader's rule for STATE, and no slice of it (`error_str` ...) is held across this call.
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

/// Name the object of the recorded error when it has none yet (glibc passes the file name it tried with the message).
pub fn set_error_obj(obj: &[u8]) {
    let s = st();
    if s.error_obj.1 != s.error_obj.0 || s.error_len == 0 {
        return;
    }
    let msg = error_msg();
    let code = s.error_code;
    // the message moves: copy it out of the buffer first (a long one into a fresh block)
    let mut tmp = [0u8; 512];
    let held: &[u8] = if msg.len() <= tmp.len() {
        tmp[..msg.len()].copy_from_slice(msg);
        &tmp[..msg.len()]
    } else {
        let d = crate::util::perm_bytes(msg.len());
        d.copy_from_slice(msg);
        d
    };
    set_error_at(obj, code, format_args!("{}", RawText(held)));
}

/// Bytes written as they are (a message already composed by `set_error_at`).
struct RawText<'a>(&'a [u8]);
impl core::fmt::Display for RawText<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // the message part of the buffer was written from `str` pieces only (`Bytes` makes file names printable), so it is
        // UTF-8; anything else would be shown with replacement marks
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}

/// The composed text of the latest error.
pub fn error_str() -> &'static [u8] {
    let s = st();
    if s.error.is_null() {
        return &[];
    }
    // SAFETY: `error_len` bytes were written by `set_error_occ` into the buffer, which only a later `set_error_occ` changes.
    unsafe { slice(s.error as *const u8, s.error_len) }
}

/// The parts of the latest error: the object name, the message, the error number.
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

/// A new, zeroed link map (its `l_real` is itself).
pub fn new_map() -> Map {
    let p = alloc_calloc(core::mem::size_of::<LinkMap>(), 16) as *mut LinkMap;
    // SAFETY: a fresh zeroed block for a `LinkMap` (every field's zero is a valid value: NULL pointers, 0, false), never
    // freed.
    let m = unsafe { Map::from_ptr(p) };
    match m {
        Some(m) => {
            m.set_real(Some(m));
            m
        }
        None => crate::die(format_args!("cannot allocate memory")),
    }
}

/// Append to the list of loaded maps (the order of `l_next`).
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
            // the list head debuggers read (glibc `_dl_close_worker`; only a namespace other than 0 loses its first map)
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

/// The highest namespaces that hold no map any more are given up (glibc's `_dl_nns` shrinks in `_dl_close_worker`).
pub fn trim_nns() {
    let s = st();
    while s.nns > 1 && ns(s.nns - 1).head.is_none() {
        s.nns -= 1;
    }
}

/// Read the dynamic section of `m` into its fields.
///
/// # Safety
/// `m`'s `l_addr` and `l_ld` are those of a mapped ELF object (`l_ld` its DT_NULL-terminated dynamic section) whose tables are
/// well formed, and (`phdr`, `phnum`) are its program headers.
pub unsafe fn parse_dynamic(m: Map) {
    let a = m.l_addr();
    let mut hash = 0usize;
    let mut gnu = 0usize;
    let mut versym = 0usize;
    for d in m.dynamic() {
        let v = d.val as usize;
        match d.tag {
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_STRTAB => unsafe { m.set_strtab((a + v) as *const u8) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_STRSZ => unsafe { m.set_strsz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_SYMTAB => unsafe { m.set_symtab((a + v) as *const Sym) },
            DT_HASH => hash = a + v,
            DT_GNU_HASH => gnu = a + v,
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_RELA => unsafe { m.set_rela((a + v) as *const Rela) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_RELASZ => unsafe { m.set_relasz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_JMPREL => unsafe { m.set_jmprel((a + v) as *const Rela) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_PLTRELSZ => unsafe { m.set_pltrelsz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_RELR => unsafe { m.set_relr((a + v) as *const u64) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_RELRSZ => unsafe { m.set_relrsz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_PLTGOT => unsafe { m.set_pltgot((a + v) as *mut usize) },
            DT_INIT => m.set_init(a + v),
            DT_FINI => m.set_fini(a + v),
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_INIT_ARRAY => unsafe { m.set_init_array((a + v) as *const usize) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_INIT_ARRAYSZ => unsafe { m.set_init_arraysz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_FINI_ARRAY => unsafe { m.set_fini_array((a + v) as *const usize) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_FINI_ARRAYSZ => unsafe { m.set_fini_arraysz(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_PREINIT_ARRAY => unsafe { m.set_preinit_array((a + v) as *const usize) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_PREINIT_ARRAYSZ => unsafe { m.set_preinit_arraysz(v) },
            DT_VERSYM => versym = a + v,
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_VERDEF => unsafe { m.set_verdef((a + v) as *const Verdef) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_VERDEFNUM => unsafe { m.set_verdefnum(v) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_VERNEED => unsafe { m.set_verneed((a + v) as *const Verneed) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_VERNEEDNUM => unsafe { m.set_verneednum(v) },
            DT_FLAGS => m.set_flags(v as u64),
            DT_FLAGS_1 => m.set_flags_1(v as u64),
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
            DT_AUDIT => unsafe { m.set_audit_str(v as u64 + 1) },
            // SAFETY: an address or size the object's own dynamic section gives (plus its load address): the invariant (caller's contract).
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
    // names (offsets) need the string table: second pass
    let strtab = m.strtab();
    for d in m.dynamic() {
        let p = strtab.wrapping_add(d.val as usize);
        match d.tag {
            // SAFETY: a string of the object's string table (the offset is the object's own).
            DT_SONAME => unsafe { m.set_soname(p) },
            // SAFETY: as above.
            DT_RPATH => unsafe { m.set_rpath(p) },
            // SAFETY: as above.
            DT_RUNPATH => unsafe { m.set_runpath(p) },
            _ => {}
        }
    }
    if gnu != 0 {
        let h = gnu as *const u32;
        // SAFETY: DT_GNU_HASH starts with four words: nbuckets, symoffset, bloom size, bloom shift (the object's table).
        let hdr = unsafe { slice(h, 4) };
        m.set_gnu_nbuckets(hdr[0]);
        m.set_gnu_symoffset(hdr[1]);
        m.set_gnu_bloom_size(hdr[2]);
        m.set_gnu_bloom_shift(hdr[3]);
        let bloom = h.wrapping_add(4) as *const u64;
        let buckets = h.wrapping_add(4 + 2 * hdr[2] as usize);
        // SAFETY: the Bloom words follow the header, the buckets follow them, the chains follow the buckets (gABI layout of
        // DT_GNU_HASH; the counts were just stored).
        unsafe { m.set_gnu_bloom(bloom) };
        // SAFETY: as above.
        unsafe { m.set_gnu_buckets(buckets) };
        // SAFETY: as above.
        unsafe { m.set_gnu_chain(buckets.wrapping_add(hdr[0] as usize)) };
    }
    if hash != 0 {
        let h = hash as *const u32;
        // SAFETY: DT_HASH starts with nbucket and nchain (the object's table).
        let hdr = unsafe { slice(h, 2) };
        m.set_hash_nbucket(hdr[0]);
        m.set_hash_nchain(hdr[1]);
        // SAFETY: the buckets follow the two counts, the chains follow the buckets (gABI layout of DT_HASH).
        unsafe { m.set_hash_buckets(h.wrapping_add(2)) };
        // SAFETY: as above.
        unsafe { m.set_hash_chains(h.wrapping_add(2 + hdr[0] as usize)) };
    }
    // SAFETY: DT_VERSYM of the object (or NULL when it has none).
    unsafe { m.set_versym(versym as *const u16) };
    build_versions(m);
    // glibc adds the load address to these entries of the dynamic section in place (programs and libraries that walk
    // _DYNAMIC, such as unwinders and self-inspecting tools, rely on it); the others keep their link-time values
    let writable = m.phdrs().iter().any(|p| p.typ == PT_DYNAMIC && p.flags & PF_W != 0);
    if writable && a != 0 && !m.dyn_adjusted() {
        m.set_dyn_adjusted(true);
        dyn_rebase(m, a as u64, true);
    }
}

/// Add (`add`) or take back the load address `a` in the address entries of `m`'s dynamic section, in place: what glibc does
/// to a writable dynamic section, and what a static-pie program run by the loader expects undone.
pub fn dyn_rebase(m: Map, a: u64, add: bool) {
    let mut d = m.l_ld();
    loop {
        // SAFETY: `d` walks the DT_NULL-terminated dynamic section (invariant of `Map`) and stops at DT_NULL.
        let e = unsafe { *d };
        if e.tag == DT_NULL {
            break;
        }
        if matches!(e.tag, DT_HASH | DT_PLTGOT | DT_STRTAB | DT_SYMTAB | DT_RELA | DT_JMPREL | DT_VERSYM | DT_GNU_HASH | DT_RELR) {
            let v = if add { e.val.wrapping_add(a) } else { e.val.wrapping_sub(a) };
            // SAFETY: an entry of a dynamic section in a writable segment (the callers check PF_W or own the image); the
            // loader's own `l_ld` reads above are copies, no reference to the entry exists.
            unsafe { (*d).val = v };
        }
        d = d.wrapping_add(1);
    }
}

/// Table from `.gnu.version` index to version name/hash for both the versions this object defines and those it needs.
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
    // SAFETY: a fresh permanent block for max + 1 `VerInfo`s, zeroed (all None/0/false: valid values), ours until published
    // below.
    let t = unsafe { crate::ffi::slice_mut(tbl, max + 1) };
    for e in t.iter_mut() {
        *e = VerInfo { name: None, hash: 0, file: None, hidden: false };
    }
    for (vd, name) in m.verdefs() {
        let idx = vd.ndx as usize & 0x7fff;
        // the base definition (VER_FLG_BASE, the object's own name, index 1) is not a version a symbol can match: index 1
        // stays the global version with an empty name, so an unversioned definition in an object that defines versions
        // (a program linked with libmcheck.a, say) still satisfies a versioned reference, as in glibc
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
    // SAFETY: `tbl` holds max + 1 initialised entries whose names point into the object's string table.
    unsafe { m.set_vers(tbl) };
    // SAFETY: the count of the table just stored.
    unsafe { m.set_nvers(max + 1) };
}

/// Record what the program headers say: TLS template, RELRO range, EH frame header, entry, dynamic section.
///
/// # Safety
/// `m`'s `l_addr` and (`phdr`, `phnum`) are those of a mapped ELF object.
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
            // SAFETY: the object's dynamic section, mapped at its load address (caller's contract).
            PT_DYNAMIC => unsafe { m.set_l_ld((a + p.vaddr as usize) as *mut Dyn) },
            PT_TLS => {
                // SAFETY: the object's TLS initialisation image and its sizes, from its PT_TLS.
                unsafe { m.set_tls_image(a + p.vaddr as usize) };
                // SAFETY: as above.
                unsafe { m.set_tls_filesz(p.filesz as usize) };
                // SAFETY: as above.
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

/// glibc's `_dl_make_stack_executable`: the stack of the initial thread (and what the kernel grows it into) becomes
/// executable. 0, or a negative errno.
pub fn make_stack_executable() -> isize {
    let page = crate::__libc_stack_end.load(core::sync::atomic::Ordering::Relaxed) & !(sys::PAGE - 1);
    // SAFETY: adds PROT_EXEC to the stack's page (and PROT_GROWSDOWN to the area below): nothing that uses it loses access.
    let r = unsafe { sys::mprotect(page, sys::PAGE, sys::PROT_READ | sys::PROT_WRITE | sys::PROT_EXEC | 0x0100_0000 /* PROT_GROWSDOWN */) };
    if r == 0 {
        st().stack_exec = true;
    }
    r
}

/// The English text of an error number, for the composed message a fatal error prints (libc.so.6's dlerror uses its own
/// strerror, translated).
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

/// The error number of a failed system call's return value (0 for a short read, which leaves errno 0 in glibc).
fn neg_errno(r: isize) -> c_int {
    if r < 0 && r > -4096 { -r as c_int } else { 0 }
}

/// Why the last `map_fd` refused a file that a library search skips (glibc's `open_verify` returns -1 for these instead of
/// failing the search): 1 an ELF file of the other class, 2 one for another machine. 0: the refusal ends the search.
/// (Written and read under the loader lock; an atomic so that no access needs `unsafe`.)
pub static SKIPPED: AtomicU8 = AtomicU8::new(0);

/// Open and map the ELF file at `path` into namespace `nsid`. `name` is what gets recorded as `l_name` (a string that lives
/// as long as the map). On failure the message (without the file name) is left in the error buffer and None is returned.
pub fn map_file(nsid: usize, path: &CStr, name: &'static CStr, loader: Option<Map>, asked: &[u8]) -> Option<Map> {
    let fd = sys::open(path);
    if fd < 0 {
        if ldebug::on(ldebug::LIBS) {
            ldebug::line(b"    (no such file)\n");
        }
        set_error_at(b"", neg_errno(fd), format_args!("cannot open shared object file"));
        return None;
    }
    let r = map_fd(nsid, fd, name, loader, asked);
    sys::close(fd);
    if r.is_none() {
        // a file given by its path that is for the other class or machine (glibc: found_other_class / ENOENT)
        match SKIPPED.load(Relaxed) {
            1 => set_error(format_args!("wrong ELF class: ELFCLASS32")),
            2 => set_error_at(b"", 2, format_args!("cannot open shared object file")),
            _ => {}
        }
    }
    r
}

/// Map the ELF object open on `fd` (`name`: its path, kept as `l_name`; `asked`: the name it was asked for, for
/// `LD_DEBUG=files`).
fn map_fd(nsid: usize, fd: isize, name: &'static CStr, loader: Option<Map>, asked: &[u8]) -> Option<Map> {
    let (dev, ino) = sys::fstat_id(fd);
    // an object of this namespace that is already loaded under another name (symlink): reuse it
    if let Some(cur) = ns(nsid).maps().find(|c| c.dev() == dev && c.ino() == ino && dev != 0 && !c.unloading()) {
        return Some(cur);
    }
    // not zero-filled (only the n bytes pread returns are read): a cleared 1 KB buffer is a stack page touched for nothing
    let mut hdr_buf = core::mem::MaybeUninit::<[u64; 128]>::uninit(); // u64s: the ELF header is read in place
    // SAFETY: the 1024 bytes of `hdr_buf` as bytes that need no initialisation (`MaybeUninit<u8>`), borrowed exclusively.
    let hdr_bytes = unsafe { crate::ffi::slice_mut(hdr_buf.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>, 1024) };
    SKIPPED.store(0, Relaxed);
    // at most MAX_MAPS maps in a namespace, one of them kept for the loader's mirror (glibc has no limit): every list the
    // loader makes over a namespace (scopes, the global scope, the new maps of a dlopen, constructor and destructor order,
    // dl_iterate_phdr) has room for that many, so none is ever cut short. A dlopen past it fails (its new maps are dropped)
    // with this message; at start-up it is the fatal error of a library that cannot be loaded.
    if ns(nsid).nmaps >= MAX_MAPS - 1 {
        set_error_at(b"", 0, format_args!("cannot map more than {} objects in one namespace", MAX_MAPS - 1));
        return None;
    }
    // glibc's open_verify: the checks of the ELF header, in its order and with its messages; they name the file that was
    // opened (`name`, the path); the later ones (`_dl_map_object_from_fd`) leave the name to the caller
    let file = name.to_bytes();
    let n = sys::pread(fd, hdr_bytes, 0);
    if n < core::mem::size_of::<Ehdr>() as isize {
        let e = neg_errno(n);
        set_error_at(file, e, format_args!("{}", if e == 0 { "file too short" } else { "cannot read file data" }));
        return None;
    }
    let hdr = hdr_buf.as_ptr() as *const u8;
    // SAFETY: pread wrote n >= size_of::<Ehdr>() bytes at the start of the 8-aligned buffer; an `Ehdr` is plain data.
    let eh = unsafe { at(hdr as *const Ehdr) };
    let id = &eh.ident;
    // bytes 0..8 as expected (OS ABI SYSV or GNU), an ABI version the C library knows, zero padding
    let osabi_ok = id[7] == 0 || id[7] == 3;
    let abiver_ok = id[8] == 0 || (id[7] == 3 && id[8] < 4);
    if &id[..4] != b"\x7fELF" || id[4] != 2 || id[5] != 1 || id[6] != 1 || !osabi_ok || !abiver_ok || id[9..16].iter().any(|&b| b != 0) {
        let msg = if &id[..4] != b"\x7fELF" {
            "invalid ELF header"
        } else if id[4] != 2 {
            SKIPPED.store(1, Relaxed);
            if ldebug::on(ldebug::LIBS) {
                ldebug::line(b"    (incompatible ELF class)\n");
            }
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
        if ldebug::on(ldebug::LIBS) {
            ldebug::line(b"    (incompatible ELF machine)\n");
        }
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
    // glibc's _dl_map_object_from_fd: the end of the search, then the new map
    search_done();
    if ldebug::on(ldebug::FILES) {
        ldebug::generating(asked, nsid);
    }
    let phn = eh.phnum as usize;
    let phsz = phn * core::mem::size_of::<Phdr>();
    let ph: &[Phdr] = if eh.phoff as usize + phsz > n as usize {
        let phbuf = alloc_perm(phsz, 8);
        // SAFETY: a fresh permanent block of phsz bytes, ours alone (`MaybeUninit<u8>` needs no initialisation).
        let dst = unsafe { crate::ffi::slice_mut(phbuf as *mut core::mem::MaybeUninit<u8>, phsz) };
        let r = sys::pread(fd, dst, eh.phoff as usize);
        if r != phsz as isize {
            set_error_at(file, neg_errno(r), format_args!("cannot read file data"));
            return None;
        }
        // SAFETY: pread filled all phsz bytes of the 8-aligned block; `Phdr` is plain data.
        unsafe { slice(phbuf as *const Phdr, phn) }
    } else {
        // SAFETY: the headers lie inside the n bytes pread wrote (checked above); e_phoff of an ELF64 file is 8-aligned (the
        // gABI); `Phdr` is plain data. The buffer lives until this function returns, and `ph` is not kept beyond it.
        unsafe { slice(hdr.wrapping_add(eh.phoff as usize) as *const Phdr, phn) }
    };
    // a segment whose address and file offset differ by more than whole pages cannot be mapped; glibc refuses the object
    if ph.iter().any(|p| p.typ == PT_LOAD && (p.vaddr.wrapping_sub(p.offset) as usize) & (sys::PAGE - 1) != 0) {
        set_error(format_args!("ELF load command address/offset not page-aligned"));
        return None;
    }
    // glibc 2.43 (dl-load.c): an object that asks for an executable stack (a PT_GNU_STACK with PF_X, or none at all: the
    // x86-64 default is RWX) while the stack is not executable makes the stack executable if it is loaded at start-up and
    // glibc.rtld.execstack is 1; dlopen and the other tunable values refuse it
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
    // dlopen of a program (glibc: after the load commands were collected)
    if st().started && eh.typ == ET_EXEC {
        set_error(format_args!("cannot dynamically load executable"));
        return None;
    }
    let span = hi - lo;
    // glibc's maplength (LD_DEBUG=files): from the first segment's page to the end of the last segment's memory
    let alloc_end = ph.iter().rfind(|p| p.typ == PT_LOAD).map_or(hi, |p| (p.vaddr + p.memsz) as usize);
    // Reserve the whole address range, then map the segments over it. A shared object whose first segment is read-only
    // and has no .bss (libc.so.6, every ordinary library) is mapped over the whole range at once, with that segment's
    // file and protection: one system call fewer per library; the later segments replace the rest, and any gap
    // between segments is made inaccessible afterwards (as glibc does).
    let first_load = ph.iter().find(|p| p.typ == PT_LOAD)?;
    let merged = first_load.flags & PF_W == 0 && first_load.memsz == first_load.filesz && page_down(first_load.vaddr as usize) == lo;
    let base = if eh.typ == ET_EXEC {
        // (a program run as `ld.so prog`, not linked as a PIE: at its own address, which must be free)
        let (prot0, flags, fd0, off0) = if merged {
            let p0 = (if first_load.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if first_load.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
            (p0, sys::MAP_PRIVATE | sys::MAP_FIXED_NOREPLACE, fd, page_down(first_load.offset as usize))
        } else {
            (sys::PROT_NONE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_FIXED_NOREPLACE, -1, 0)
        };
        // (MAP_FIXED_NOREPLACE: the kernel refuses rather than replace a mapping that is there)
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
    let mut prev_end = 0usize; // end (page-rounded) of the previous segment, for the holes of a merged mapping
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
            // a hole between two segments is still the first segment's file at its protection: close it
            // SAFETY: the hole lies inside the range reserved for this object above, which nothing uses yet.
            unsafe { sys::mprotect(base + prev_end, start - prev_end, sys::PROT_NONE) };
        }
        if !(merged && was_first) {
            // SAFETY: MAP_FIXED over the range reserved for this object above (nothing else lives there, nothing uses it yet).
            let r = unsafe { sys::mmap(base + start, page_up(filend) - start, prot, sys::MAP_PRIVATE | sys::MAP_FIXED, fd, off) };
            if r < 0 && r > -4096 {
                set_error(format_args!("failed to map segment from shared object"));
                // SAFETY: the object's own range, given up (no map describes it).
                unsafe { sys::munmap(base + lo, span) };
                return None;
            }
        }
        let memend = vaddr + p.memsz as usize;
        prev_end = page_up(memend);
        if memend > filend {
            // the tail of the last file page belongs to .bss and must read as zero
            if p.flags & PF_W != 0 && filend & (sys::PAGE - 1) != 0 {
                let z = page_up(filend) - filend;
                // SAFETY: the rest of the segment's last file page, just mapped writable and private, used by nobody yet.
                unsafe { core::ptr::write_bytes((base + filend) as *mut u8, 0, z.min(memend - filend)) };
            }
            let anon_start = page_up(filend);
            let anon_end = page_up(memend);
            if anon_end > anon_start {
                // SAFETY: MAP_FIXED inside the range reserved for this object (its .bss pages), used by nobody yet.
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
    // SAFETY: a string that lives as long as the map (the caller's `&'static CStr`).
    unsafe { m.set_l_name(name.as_ptr() as *const u8) };
    m.set_typ(eh.typ);
    m.set_map_start(base + lo);
    m.set_map_end(base + hi);
    m.set_entry(base + eh.entry as usize);
    m.set_dev(dev);
    m.set_ino(ino);
    m.set_loader(loader);
    // keep a copy of the program headers (the file mapping may not include them; they usually do)
    let ph_copy = alloc_perm(phsz, 8) as *mut Phdr;
    // SAFETY: a fresh permanent block for `phn` headers, ours alone.
    unsafe { crate::ffi::slice_mut(ph_copy, phn) }.copy_from_slice(ph);
    // The mapped copy is what dl_iterate_phdr reports when it exists; our copy is what we parse.
    let in_map = (eh.phoff as usize) >= load0_off && (eh.phoff as usize + phsz) <= load0_off + 0x100000;
    let phdr = if in_map { (base + load0_vaddr + (eh.phoff as usize - load0_off)) as *const Phdr } else { ph_copy as *const Phdr };
    // SAFETY: the object's program headers: inside its first mapped segment (in_map) or our copy of them.
    unsafe { m.set_phdr(phdr) };
    // SAFETY: their number.
    unsafe { m.set_phnum(phn) };
    // SAFETY: the object was just mapped at `base` with these program headers.
    unsafe { scan_phdrs(m) };
    if m.l_ld().is_null() {
        set_error(format_args!("object file has no dynamic section"));
        return None;
    }
    // SAFETY: `l_ld` is the mapped object's dynamic section (scan_phdrs), the loader trusts its tables.
    unsafe { parse_dynamic(m) };
    if ldebug::on(ldebug::FILES) {
        ldebug::map_info(m, alloc_end - lo);
    }
    Some(m)
}

/// Make the RELRO range read-only (after relocation).
pub fn protect_relro(m: Map) {
    if m.relro_len() != 0 {
        let s = page_down(m.relro_start());
        let e = page_down(m.relro_start() + m.relro_len());
        if e > s {
            // SAFETY: the object's PT_GNU_RELRO pages: relocation is done and nothing writes them any more (glibc's rule).
            unsafe { sys::mprotect(s, e - s, sys::PROT_READ) };
        }
    }
}

// ---- finding libraries ----

/// The longest file name the loader builds (PATH_MAX).
const MAX_PATH: usize = 4096;

/// `$ORIGIN` of a map: the directory of its file.
pub fn origin_of(m: Map) -> &'static [u8] {
    if let Some(o) = m.origin() {
        return o;
    }
    let mut path = PathBuf::new();
    let mut p: &[u8] = m.name();
    if p.is_empty() {
        // the program in interpreter mode: ask the kernel
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
    // SAFETY: a string `dup` made (permanent).
    unsafe { m.set_origin(o.as_ptr() as *const u8) };
    o.to_bytes()
}

/// Expand `$ORIGIN`, `$LIB`, `$PLATFORM` (and the `${...}` forms) in a search path element, appending to `out` (empty when
/// called); returns the length.
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

/// What a library search found: a mapped (or already loaded) map, or, in a probe (`PROBE_ONLY`), a file that exists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    Map(Map),
    Exists,
}

/// A file the search found while `PROBE_ONLY` is set: closes `fd` and returns the loaded library that is this file when
/// `PROBE_IDENT` is set and one is (RTLD_NOLOAD: whatever name that one was loaded under, a DT_NEEDED entry with a path, a
/// symlink), else `Exists` (a file exists, nothing is mapped).
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

/// The file an audit library's `la_objsearch` named instead of `path` (`r`, not NULL), when it is another string.
///
/// # Safety
/// `r` is what `audit::objsearch` returned for `path`: `path` itself or a NUL-terminated string (the rtld-audit contract).
unsafe fn searched_name(r: *const u8, path: &CStr) -> &CStr {
    if r == path.as_ptr() as *const u8 {
        return path;
    }
    // SAFETY: a NUL-terminated string from la_objsearch (caller's contract), used for the open that follows.
    let other = unsafe { cstr_nul(r) };
    if other.to_bytes() != path.to_bytes() { other } else { path }
}

/// Try the directories of a colon-separated list; returns the mapped map (or None with the "not found" state).
#[allow(clippy::too_many_arguments)]
fn try_dirs(nsid: usize, list: &[u8], name: &[u8], requester: Option<Map>, loader: Option<Map>, code: u32, found_err: &mut bool, what: Search) -> Option<Hit> {
    let probe = PROBE_ONLY.load(Relaxed);
    let libs = ldebug::on(ldebug::LIBS);
    let mut cur_kind = 0u8;
    if libs {
        let (k, o) = what.kind_owner();
        dirs_register(list, requester, k, o);
    }
    let mut off = 0usize;
    for elem in list.split(|&c| c == b':') {
        let rest = &list[off.min(list.len())..];
        off += elem.len() + 1;
        // one buffer, left uninitialised: zero-filling two 4 KB arrays per directory touched three stack pages, and a page
        // fault costs about as much as ten system calls
        let mut path = PathBuf::new();
        let n = if elem.is_empty() {
            path.push(b'.');
            1
        } else {
            expand(elem, requester, &mut path)
        };
        if libs {
            let k = dir_owner(&path.bytes()[..n]).0;
            if k != cur_kind {
                cur_kind = k;
                debug_search_path(rest, requester);
            }
        }
        if n + 1 + name.len() + 1 > MAX_PATH {
            continue;
        }
        path.reserve(n + 1 + name.len() + 1);
        path.push(b'/');
        path.extend(name);
        let candidate = path.as_cstr();
        // the audit libraries may replace the file to open (the object keeps the candidate's name, as in glibc) or veto it
        let mut openp = candidate;
        if !probe && audit::wants_objsearch() {
            let r = audit::objsearch(candidate, loader, code);
            if r.is_null() {
                continue;
            }
            // SAFETY: `r` came from objsearch for `candidate`.
            openp = unsafe { searched_name(r, candidate) };
        }
        if libs {
            ldebug::trying(candidate.to_bytes());
        }
        let fd = sys::open(openp);
        if fd < 0 {
            if libs {
                ldebug::line(b"    (no such file)\n");
            }
            continue;
        }
        if SECURE_SEARCH.load(Relaxed) && sys::fstat_mode(fd) & 0o4000 == 0 {
            // glibc's open_path: "refusing to load file ..., the shared object cannot be tested for being SUID or the
            // bit is not set"
            if libs {
                ldebug::refusing(candidate.to_bytes());
            }
            sys::close(fd);
            continue;
        }
        if probe {
            return Some(probe_found(nsid, fd));
        }
        // map from the descriptor we already have (opening the file a second time cost two more system calls per library)
        let m = map_fd(nsid, fd, dup(candidate.to_bytes()), requester, name);
        sys::close(fd);
        if let Some(m) = m {
            return Some(Hit::Map(m));
        }
        // a file for the other class or machine is skipped and the search goes on (glibc's open_verify returns -1); any
        // other refusal ends it with that file's message
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

/// Which list a search walks, for `LD_DEBUG=libs` (glibc's `what` and `where` of a search path).
#[derive(Clone, Copy)]
enum Search {
    Rpath(Map),
    LibraryPath,
    Runpath(Map),
    System,
}

const K_RPATH: u8 = 1;
const K_LIBPATH: u8 = 2;
const K_RUNPATH: u8 = 3;
const K_SYSTEM: u8 = 4;

impl Search {
    fn kind_owner(self) -> (u8, Option<Map>) {
        match self {
            Search::Rpath(m) => (K_RPATH, Some(m)),
            Search::LibraryPath => (K_LIBPATH, None),
            Search::Runpath(m) => (K_RUNPATH, Some(m)),
            Search::System => (K_SYSTEM, None),
        }
    }
}

/// A search directory as glibc compares them: without its trailing slashes (except "/").
fn dir_hash(d: &[u8]) -> u64 {
    let mut d = d;
    while d.len() > 1 && d.last() == Some(&b'/') {
        d = &d[..d.len() - 1];
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in d {
        h = (h ^ u64::from(c)).wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Each element of `list`, expanded (an empty one is the current directory).
fn each_expanded(list: &[u8], requester: Option<Map>, f: &mut dyn FnMut(&[u8])) {
    for elem in list.split(|&c| c == b':') {
        let mut path = PathBuf::new();
        if elem.is_empty() {
            path.push(b'.');
        } else {
            expand(elem, requester, &mut path);
        }
        f(path.bytes());
    }
}

/// Record the directories of `list` that no list named before (`LD_DEBUG=libs`).
fn dirs_register(list: &[u8], requester: Option<Map>, kind: u8, owner: Option<Map>) {
    each_expanded(list, requester, &mut |d| {
        let h = dir_hash(d);
        let Some(t) = st().debug_dirs.as_mut() else { return };
        if t.n < DEBUG_DIRS && dir_index(t, h).is_none() {
            t.hash[8 * t.n..8 * t.n + 8].copy_from_slice(&h.to_ne_bytes());
            t.kind[t.n] = kind;
            t.owner[t.n] = owner;
            t.n += 1;
        }
    });
}

fn dir_index(t: &DebugDirs, h: u64) -> Option<usize> {
    (0..t.n).find(|&i| t.hash[8 * i..8 * i + 8] == h.to_ne_bytes())
}

/// The lists glibc's `_dl_init_paths` decomposes at start-up, in its order (`lp`: the library path).
fn dirs_init(lp: Option<&[u8]>) {
    if st().debug_dirs.is_some() {
        return;
    }
    st().debug_dirs = Some(DebugDirs { hash: perm_bytes(8 * DEBUG_DIRS), kind: perm_bytes(DEBUG_DIRS), owner: perm_maps(DEBUG_DIRS), n: 0 });
    dirs_register(DEFAULT_DIRS, None, K_SYSTEM, None);
    if let Some(main) = st().main_map {
        if let Some(rp) = main.runpath() {
            dirs_register(rp, Some(main), K_RUNPATH, Some(main));
        } else if let Some(rp) = main.rpath() {
            dirs_register(rp, Some(main), K_RPATH, Some(main));
        }
    }
    if let Some(lp) = lp {
        dirs_register(lp, st().main_map, K_LIBPATH, None);
    }
}

fn dir_owner(d: &[u8]) -> (u8, Option<Map>) {
    let h = dir_hash(d);
    match st().debug_dirs.as_ref() {
        Some(t) => dir_index(t, h).map_or((0, None), |i| (t.kind[i], t.owner[i])),
        None => (0, None),
    }
}

/// `LD_DEBUG=libs`: glibc's `print_search_path` from the directory `rest` starts with: it and the directories after it
/// with the same label, then the label (which list named the first of them first, and from which file).
#[cold]
#[inline(never)]
fn debug_search_path(rest: &[u8], requester: Option<Map>) {
    let mut m = ldebug::Msg::new();
    m.t(b" search path=");
    let mut kind = 0u8;
    let mut owner = None;
    let mut first = true;
    let mut done = false;
    each_expanded(rest, requester, &mut |d| {
        if done {
            return;
        }
        let (k, o) = dir_owner(d);
        if first {
            (kind, owner) = (k, o);
        } else if k != kind {
            done = true;
            return;
        }
        if !first {
            m.t(b":");
        }
        first = false;
        m.s(d);
    });
    let what: &[u8] = match kind {
        K_RPATH => b"RPATH",
        K_RUNPATH => b"RUNPATH",
        K_LIBPATH if st().library_path_opt => b"--library-path",
        K_LIBPATH => b"LD_LIBRARY_PATH",
        _ => b"system search path",
    };
    ldebug::search_path_end(&mut m, what, if matches!(kind, K_RPATH | K_RUNPATH) { owner } else { None });
}

const DEFAULT_DIRS: &[u8] = b"/lib64:/usr/lib64:/lib:/usr/lib";

/// Set while a secure (set-user-ID) program loads its preloads and audit libraries (glibc's `__RTLD_SECURE`): a name is
/// not looked up in /etc/ld.so.cache, and a file found in a search directory is used only if it has the set-user-ID bit.
pub static SECURE_SEARCH: AtomicBool = AtomicBool::new(false);
const PROBE_ONLY_SKIP_CACHE: bool = false;

// ---- /etc/ld.so.cache (the glibc-ld.so.cache1.1 format) ----

/// The cache file, mapped read-only on first use (start-up or under the loader lock).
struct Cache {
    ptr: usize,
    len: usize,
    tried: bool,
    /// The failed open of /etc/ld.so.cache (negative errno), 0 when it opened or was not tried.
    open_err: isize,
}
static CACHE: SyncCell<Cache> = SyncCell::new(Cache { ptr: 0, len: 0, tried: false, open_err: 0 });

/// The errno a lookup that only searched /etc/ld.so.cache leaves behind, as text: glibc reports the errno of the failed
/// open of the cache, and none when the cache was read.
pub(crate) fn cache_open_error() -> Option<&'static str> {
    let c = cache_load();
    if c.open_err < 0 { Some(errno_text(neg_errno(c.open_err))) } else { None }
}

/// The cache, mapped once. (A copy of the record: it never changes after the first call.)
fn cache_load() -> Cache {
    // SAFETY: CACHE is used at start-up (one thread) and under the loader lock only (library searches); nothing in this
    // closure comes back here.
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

/// The path of the library `name` in the cache, for the x86-64 ABI. Entries for glibc-hwcaps directories (specific CPUs) are skipped.
pub(crate) fn cache_lookup(name: &[u8]) -> Option<&'static [u8]> {
    let c = cache_load();
    if c.ptr == 0 {
        return None;
    }
    // SAFETY: the cache file mapped read-only, `len` bytes, never unmapped or written.
    let file: &'static [u8] = unsafe { slice(c.ptr as *const u8, c.len) };
    let rd32 = |off: usize| -> u32 { file.get(off..off + 4).map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]])) };
    let mut hdr = 0usize;
    if file.get(..11) == Some(&b"ld.so-1.7.0"[..]) {
        // old header (11 bytes + pad, nlibs, 12-byte entries), the new one follows 8-aligned
        let nlibs = rd32(12) as usize;
        hdr = (16 + nlibs * 12 + 7) & !7;
    }
    if hdr + 48 > c.len || &file[hdr..hdr + 20] != b"glibc-ld.so.cache1.1" {
        return None;
    }
    let nlibs = rd32(hdr + 20) as usize;
    // header: magic 17 + version 3, nlibs, len_strings, flags(8), extension_offset(32 bits), unused[3]: 48 bytes
    let entries = hdr + 48;
    if entries + nlibs * 24 > c.len {
        return None;
    }
    // the entries are sorted by `_dl_cache_libcmp` of the library name, descending (checked on this machine's cache):
    // binary search for the first entry that is not above `name`, then walk the run of equal names
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

/// The NUL-terminated string at the start of `s` (all of `s` when it has no NUL: the cache is read-only, a missing NUL
/// cannot run past the mapping).
fn cache_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(n) => &s[..n],
        None => s,
    }
}

/// Is the NUL-terminated string at the start of `s` equal to `name`?
fn cache_str_eq(s: &[u8], name: &[u8]) -> bool {
    s.len() > name.len() && &s[..name.len()] == name && s[name.len()] == 0
}

/// glibc's `_dl_cache_libcmp`: names compared byte by byte, runs of digits as numbers (the order of /etc/ld.so.cache).
/// `s1` is a NUL-terminated string at the start of the slice (its end counts as NUL).
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

/// While set, the library search only checks that a file exists (RTLD_NOLOAD wants the error for a missing library).
static PROBE_ONLY: AtomicBool = AtomicBool::new(false);

/// While set together with `PROBE_ONLY`, a found file is compared with the loaded libraries (device and inode).
static PROBE_IDENT: AtomicBool = AtomicBool::new(false);

/// The loaded library that is the file the search for `name` finds (None: none is loaded, nothing is mapped).
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

/// Does the search for `name` find a file? (nothing is mapped)
pub fn library_exists(nsid: usize, name: &[u8], requester: Option<Map>) -> bool {
    PROBE_ONLY.store(true, Relaxed);
    let r = load_library_search(nsid, name, requester);
    PROBE_ONLY.store(false, Relaxed);
    r.is_some()
}

/// Is a map with this soname or file name already loaded in namespace `nsid`?
pub fn find_loaded(nsid: usize, name: &[u8]) -> Option<Map> {
    ns(nsid).maps().find(|c| {
        if c.unloading() {
            return false;
        }
        if c.soname() == Some(name) {
            return true;
        }
        let n = c.name();
        // (glibc's _dl_name_match_p: also the name it was first asked for, e.g. a DT_NEEDED name of a library without a
        // soname)
        (n == name && !n.is_empty()) || c.req_name() == Some(name)
    })
}

/// Is `name` a request for the loader itself (its soname, or the path it is known by)?
fn names_ldso(name: &[u8]) -> bool {
    match st().ldso_map {
        None => false,
        Some(l) => l.soname() == Some(name) || l.name() == name,
    }
}

/// The loader is mapped once per process. In a namespace other than the base one, a library that needs it (libc.so.6 does) is
/// given a mirror: a map of its own, in that namespace's list and scopes, that describes the same image (`l_real` points to the
/// real map; glibc `dl-load.c`). Symbol lookup there finds the loader's exports at the real addresses.
fn ldso_mirror(nsid: usize) -> Map {
    let real = ldso_map();
    let m = new_map();
    // SAFETY: two distinct link maps (a fresh one and the loader's), copied as bytes: every field of the copy then
    // describes the loader's image as the real map's do (the invariant holds for it as for the original); the links and
    // arrays that must not be shared are reset below.
    unsafe { core::ptr::copy_nonoverlapping(real.as_ptr() as *const u8, m.as_ptr() as *mut u8, core::mem::size_of::<LinkMap>()) };
    m.set_real(Some(real));
    m.set_l_ns(nsid as isize);
    m.set_prev(None);
    m.set_next(None);
    m.set_refcount(0);
    m.set_direct_opens(0);
    m.set_nodelete(false);
    m.set_in_global(false);
    // SAFETY: an empty array (NULL, 0) keeps the invariant (as for the resets below).
    unsafe { m.set_scope(null_mut()) };
    // SAFETY: as above.
    unsafe { m.set_nscope(0) };
    // SAFETY: as above.
    unsafe { m.set_xscope(null_mut()) };
    // SAFETY: as above.
    unsafe { m.set_nxscope(0) };
    // SAFETY: as above.
    unsafe { m.set_reldeps(null_mut()) };
    // SAFETY: as above.
    unsafe { m.set_nreldeps(0) };
    // SAFETY: as above.
    unsafe { m.set_creldeps(0) };
    m.set_opening(false);
    m.set_dlopened(true);
    link_map(m);
    m
}

/// Set by dlopen while it looks up the object it was asked for (glibc's `__RTLD_CALLMAP`): `LD_DEBUG=files` says
/// "dynamically loaded by" instead of "needed by".
pub static CALLMAP: AtomicBool = AtomicBool::new(false);

/// `LD_DEBUG=libs`: a search by name ends with an empty line, which glibc prints before it maps the file it found (and so
/// before that file's `LD_DEBUG=files` lines); set while that line is still to come.
static SEARCH_NL: AtomicBool = AtomicBool::new(false);

fn search_done() {
    if SEARCH_NL.load(Relaxed) {
        SEARCH_NL.store(false, Relaxed);
        ldebug::line(b"\n");
    }
}

/// Find, map and register the library `name` in namespace `nsid` for `requester` (None for preloads and dlopen of the
/// program's own scope). Returns an existing map of that namespace if the library is already loaded. None on failure with
/// the message in the error buffer (`NAME: message`).
pub fn load_library(nsid: usize, name: &[u8], requester: Option<Map>) -> Option<Map> {
    if let Some(m) = find_loaded(nsid, name) {
        return Some(m);
    }
    if ldebug::on(ldebug::FILES)
        && let Some(r) = requester
        && !PROBE_ONLY.load(Relaxed)
    {
        ldebug::file_needed(name, nsid, r, CALLMAP.load(Relaxed));
    }
    if nsid != 0 && names_ldso(name) {
        return Some(ldso_mirror(nsid));
    }
    // A new namespace gets another copy of the libc of the process: a lookup of `libc.so.6` there maps the file the base
    // namespace's libc came from, not whatever the search path finds first (a program run from a build directory, with
    // its libc found through its own DT_RPATH, would otherwise get the system's libc into a loader that is not its own).
    // In glibc's installation both searches end at the same file.
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
    // la_objsearch(LA_SER_ORIG): the audit libraries may rename the library or refuse it
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
            // SAFETY: la_objsearch returns NULL or a NUL-terminated string (rtld-audit contract), which lives at least for
            // this search.
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
            // RTLD_NOLOAD and the existence check map nothing
            let fd = sys::open(p);
            if fd < 0 {
                if ldebug::on(ldebug::LIBS) {
                    ldebug::line(b"    (no such file)\n");
                }
                set_error_at(b"", neg_errno(fd), format_args!("cannot open shared object file"));
                None
            } else {
                Some(probe_found(nsid, fd))
            }
        } else {
            map_file(nsid, p, dup(p.to_bytes()), requester, name).map(Hit::Map)
        };
        if m.is_none() {
            // the messages that do not name the file yet name it as it was asked for
            set_error_obj(name);
        }
    } else {
        let libs = ldebug::on(ldebug::LIBS);
        // SAFETY: library_path is a string `dup` made or an argv string (both live for the process).
        let lp = if st().library_path.is_null() { None } else { Some(unsafe { cstr(st().library_path) }) };
        if libs {
            dirs_init(lp);
            ldebug::find_library(name, nsid);
            SEARCH_NL.store(true, Relaxed);
        }
        // 1. DT_RPATH of the requester and of the maps that loaded it (only when there is no DT_RUNPATH)
        let mut r = requester;
        while m.is_none() && !st().hard_error {
            let Some(rm) = r else { break };
            if let (Some(rp), None) = (rm.rpath(), rm.runpath()) {
                m = try_dirs(nsid, rp, name, Some(rm), requester, audit::LA_SER_RUNPATH, &mut bad, Search::Rpath(rm));
            }
            r = rm.loader();
        }
        // 2. LD_LIBRARY_PATH / --library-path
        if m.is_none() && !st().hard_error
            && let Some(lp) = lp
        {
            m = try_dirs(nsid, lp, name, requester, main_or(requester), audit::LA_SER_LIBPATH, &mut bad, Search::LibraryPath);
        }
        // 3. DT_RUNPATH of the requester
        if m.is_none() && !st().hard_error
            && let Some(rq) = requester
            && let Some(rp) = rq.runpath()
        {
            m = try_dirs(nsid, rp, name, requester, requester, audit::LA_SER_RUNPATH, &mut bad, Search::Runpath(rq));
        }
        // 4. (a namespace other than the base one) the directory the base namespace's libc.so.6 came from, standing in for the
        // system directories: in glibc's installation the C library's own files (libm.so.6 and the rest) are found there by step 5;
        // a program run from a build directory finds ours through its own DT_RPATH, which a namespace's RUNPATH library does not use
        if m.is_none() && !st().hard_error && nsid != 0
            && let Some(base) = ns(0).libc_map
        {
            let p = base.name();
            if let Some(slash) = p.iter().rposition(|&c| c == b'/') {
                m = try_dirs(nsid, &p[..slash.max(1)], name, requester, main_or(requester), audit::LA_SER_DEFAULT, &mut bad, Search::System);
            }
        }
        // 5. /etc/ld.so.cache, then the system directories
        if m.is_none() && !st().hard_error && !PROBE_ONLY_SKIP_CACHE && !SECURE_SEARCH.load(Relaxed) && libs {
            ldebug::line(b" search cache=/etc/ld.so.cache\n");
        }
        if m.is_none() && !st().hard_error && !PROBE_ONLY_SKIP_CACHE && !SECURE_SEARCH.load(Relaxed)
            && let Some(path) = cache_lookup(name)
        {
            if libs {
                ldebug::trying(path);
            }
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
                        // SAFETY: `r` came from objsearch for `candidate`.
                        Some(unsafe { searched_name(r, candidate) })
                    };
                }
                let fd = match openp {
                    None => -1,
                    Some(p) => sys::open(p),
                };
                if fd < 0 && openp.is_some() && libs {
                    ldebug::line(b"    (no such file)\n");
                }
                if fd >= 0 {
                    if probe_only {
                        sys::close(fd);
                        search_done();
                        return Some(Hit::Exists);
                    }
                    m = map_fd(nsid, fd, dup(path), requester, name).map(Hit::Map);
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
            m = try_dirs(nsid, DEFAULT_DIRS, name, requester, main_or(requester), audit::LA_SER_DEFAULT, &mut bad, Search::System);
        }
        search_done();
        if m.is_none() && st().hard_error {
            set_error_obj(name);
        } else if m.is_none() && bad {
            // only files of the other class were found (glibc's found_other_class)
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
            // SAFETY: a string `dup` made (permanent).
            unsafe { mm.set_req_name(dup(asked).as_ptr() as *const u8) };
        }
    }
    Some(hit)
}

/// MAP_32BIT for the address range of a library with executable code when the preference is set (`State::map32`).
fn map32_flag(ph: &[Phdr]) -> usize {
    if st().map32 && ph.iter().any(|p| p.typ == PT_LOAD && p.flags & PF_X != 0) { 0x40 } else { 0 }
}
