use crate::elf::*;
use crate::sys;
use crate::util::*;
use core::ptr::{null, null_mut};

#[derive(Clone, Copy)]
pub struct VerInfo {
    pub name: *const u8,
    pub hash: u32,
    pub file: *const u8,
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
    pub copy_done: bool,
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
}

pub const MAX_MAPS: usize = 1024;

pub struct State {
    pub head: *mut LinkMap,
    pub tail: *mut LinkMap,
    pub nmaps: usize,
    pub global: [*mut LinkMap; MAX_MAPS],
    pub nglobal: usize,
    pub main_map: *mut LinkMap,
    pub ldso_map: *mut LinkMap,
    pub argc: usize,
    pub argv: *mut *mut u8,
    pub envp: *mut *mut u8,
    pub auxv: *mut usize,
    pub library_path: *const u8,
    pub preload: *const u8,
    pub secure: bool,
    pub map32: bool,
    pub started: bool,
    pub lenient: bool,
    pub debug: bool,
    pub bind_now_env: bool,
    pub trace: bool,
    pub prog_name: *const u8,
    pub page_size: usize,
    pub error: [u8; 512],
    pub error_len: usize,
    pub ldso_base: usize,
    pub audit: *const u8,
    pub trace_versions: bool,
    pub trace_warn: bool,
    pub trace_unused: bool,
}

pub static mut STATE: State = State {
    head: null_mut(),
    tail: null_mut(),
    nmaps: 0,
    global: [null_mut(); MAX_MAPS],
    nglobal: 0,
    main_map: null_mut(),
    ldso_map: null_mut(),
    argc: 0,
    argv: null_mut(),
    envp: null_mut(),
    auxv: null_mut(),
    library_path: null(),
    preload: null(),
    secure: false,
    map32: false,
    started: false,
    lenient: false,
    debug: false,
    bind_now_env: false,
    trace: false,
    prog_name: null(),
    page_size: 4096,
    error: [0; 512],
    error_len: 0,
    ldso_base: 0,
    audit: null(),
    trace_versions: false,
    trace_warn: false,
    trace_unused: false,
};

#[inline(always)]
pub fn st() -> &'static mut State {
    unsafe { &mut *(&raw mut STATE) }
}

pub fn set_error(args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct W<'a>(&'a mut [u8], usize);
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &c in s.as_bytes() {
                if self.1 < self.0.len() - 1 {
                    self.0[self.1] = c;
                    self.1 += 1;
                }
            }
            Ok(())
        }
    }
    let s = st();
    let mut w = W(&mut s.error, 0);
    let _ = w.write_fmt(args);
    let n = w.1;
    s.error[n] = 0;
    s.error_len = n;
}

pub fn error_str() -> &'static [u8] {
    let s = st();
    unsafe { core::slice::from_raw_parts((&raw const s.error) as *const u8, s.error_len) }
}

pub unsafe fn new_map() -> *mut LinkMap {
    unsafe {
        let m = alloc_perm(core::mem::size_of::<LinkMap>(), 16) as *mut LinkMap;
        (*m).l_real = m;
        m
    }
}

pub unsafe fn link_map(m: *mut LinkMap) {
    unsafe {
        let s = st();
        (*m).l_prev = s.tail;
        (*m).l_next = null_mut();
        if s.tail.is_null() {
            s.head = m;
        } else {
            (*s.tail).l_next = m;
        }
        s.tail = m;
        s.nmaps += 1;
    }
}

pub unsafe fn unlink_map(m: *mut LinkMap) {
    unsafe {
        let s = st();
        if (*m).l_prev.is_null() {
            s.head = (*m).l_next;
        } else {
            (*(*m).l_prev).l_next = (*m).l_next;
        }
        if (*m).l_next.is_null() {
            s.tail = (*m).l_prev;
        } else {
            (*(*m).l_next).l_prev = (*m).l_prev;
        }
        s.nmaps -= 1;
    }
}

pub unsafe fn parse_dynamic(m: *mut LinkMap) {
    unsafe {
        let a = (*m).l_addr;
        let mut d = (*m).l_ld;
        let mut hash = 0usize;
        let mut gnu = 0usize;
        let mut versym = 0usize;
        while (*d).tag != DT_NULL {
            let v = (*d).val as usize;
            match (*d).tag {
                DT_STRTAB => (*m).strtab = (a + v) as *const u8,
                DT_STRSZ => (*m).strsz = v,
                DT_SYMTAB => (*m).symtab = (a + v) as *const Sym,
                DT_HASH => hash = a + v,
                DT_GNU_HASH => gnu = a + v,
                DT_RELA => (*m).rela = (a + v) as *const Rela,
                DT_RELASZ => (*m).relasz = v,
                DT_JMPREL => (*m).jmprel = (a + v) as *const Rela,
                DT_PLTRELSZ => (*m).pltrelsz = v,
                DT_RELR => (*m).relr = (a + v) as *const u64,
                DT_RELRSZ => (*m).relrsz = v,
                DT_PLTGOT => (*m).pltgot = (a + v) as *mut usize,
                DT_INIT => (*m).init = a + v,
                DT_FINI => (*m).fini = a + v,
                DT_INIT_ARRAY => (*m).init_array = (a + v) as *const usize,
                DT_INIT_ARRAYSZ => (*m).init_arraysz = v,
                DT_FINI_ARRAY => (*m).fini_array = (a + v) as *const usize,
                DT_FINI_ARRAYSZ => (*m).fini_arraysz = v,
                DT_PREINIT_ARRAY => (*m).preinit_array = (a + v) as *const usize,
                DT_PREINIT_ARRAYSZ => (*m).preinit_arraysz = v,
                DT_VERSYM => versym = a + v,
                DT_VERDEF => (*m).verdef = (a + v) as *const Verdef,
                DT_VERDEFNUM => (*m).verdefnum = v,
                DT_VERNEED => (*m).verneed = (a + v) as *const Verneed,
                DT_VERNEEDNUM => (*m).verneednum = v,
                DT_FLAGS => (*m).flags = v as u64,
                DT_FLAGS_1 => (*m).flags_1 = v as u64,
                DT_BIND_NOW => (*m).bind_now = true,
                DT_TEXTREL => (*m).textrel = true,
                DT_SYMBOLIC => (*m).flags |= DF_SYMBOLIC,
                DT_DEBUG => {}
                _ => {}
            }
            d = d.add(1);
        }
        if (*m).flags & DF_TEXTREL != 0 {
            (*m).textrel = true;
        }
        if (*m).flags & DF_BIND_NOW != 0 || (*m).flags_1 & DF_1_NOW != 0 {
            (*m).bind_now = true;
        }
        if (*m).flags_1 & DF_1_NODELETE != 0 {
            (*m).nodelete = true;
        }
        let mut d = (*m).l_ld;
        while (*d).tag != DT_NULL {
            let v = (*d).val as usize;
            match (*d).tag {
                DT_SONAME => (*m).soname = (*m).strtab.add(v),
                DT_RPATH => (*m).rpath = (*m).strtab.add(v),
                DT_RUNPATH => (*m).runpath = (*m).strtab.add(v),
                _ => {}
            }
            d = d.add(1);
        }
        if gnu != 0 {
            let h = gnu as *const u32;
            (*m).gnu_nbuckets = *h;
            (*m).gnu_symoffset = *h.add(1);
            (*m).gnu_bloom_size = *h.add(2);
            (*m).gnu_bloom_shift = *h.add(3);
            (*m).gnu_bloom = h.add(4) as *const u64;
            (*m).gnu_buckets = h.add(4 + 2 * (*m).gnu_bloom_size as usize);
            (*m).gnu_chain = (*m).gnu_buckets.add((*m).gnu_nbuckets as usize);
        }
        if hash != 0 {
            let h = hash as *const u32;
            (*m).hash_nbucket = *h;
            (*m).hash_nchain = *h.add(1);
            (*m).hash_buckets = h.add(2);
            (*m).hash_chains = h.add(2 + (*m).hash_nbucket as usize);
        }
        (*m).versym = versym as *const u16;
        build_versions(m);
        let mut writable = false;
        for i in 0..(*m).phnum {
            let p = &*(*m).phdr.add(i);
            if p.typ == PT_DYNAMIC && p.flags & PF_W != 0 {
                writable = true;
            }
        }
        if writable && a != 0 && !(*m).dyn_adjusted {
            (*m).dyn_adjusted = true;
            let mut d = (*m).l_ld;
            while (*d).tag != DT_NULL {
                if matches!((*d).tag, DT_HASH | DT_PLTGOT | DT_STRTAB | DT_SYMTAB | DT_RELA | DT_JMPREL | DT_VERSYM | DT_GNU_HASH | DT_RELR) {
                    (*d).val = (*d).val.wrapping_add(a as u64);
                }
                d = d.add(1);
            }
        }
    }
}

unsafe fn build_versions(m: *mut LinkMap) {
    unsafe {
        let mut max = 0usize;
        let mut vd = (*m).verdef;
        for _ in 0..(*m).verdefnum {
            max = max.max((*vd).ndx as usize & 0x7fff);
            vd = (vd as *const u8).add((*vd).next as usize) as *const Verdef;
        }
        let mut vn = (*m).verneed;
        for _ in 0..(*m).verneednum {
            let mut aux = (vn as *const u8).add((*vn).aux as usize) as *const Vernaux;
            for _ in 0..(*vn).cnt {
                max = max.max((*aux).other as usize & 0x7fff);
                aux = (aux as *const u8).add((*aux).next as usize) as *const Vernaux;
            }
            vn = (vn as *const u8).add((*vn).next as usize) as *const Verneed;
        }
        if max == 0 {
            return;
        }
        let tbl = alloc_perm((max + 1) * core::mem::size_of::<VerInfo>(), 8) as *mut VerInfo;
        for i in 0..=max {
            *tbl.add(i) = VerInfo { name: null(), hash: 0, file: null(), hidden: false };
        }
        let mut vd = (*m).verdef;
        for _ in 0..(*m).verdefnum {
            let idx = (*vd).ndx as usize & 0x7fff;
            let aux = (vd as *const u8).add((*vd).aux as usize) as *const Verdaux;
            *tbl.add(idx) = VerInfo { name: (*m).strtab.add((*aux).name as usize), hash: (*vd).hash, file: null(), hidden: false };
            vd = (vd as *const u8).add((*vd).next as usize) as *const Verdef;
        }
        let mut vn = (*m).verneed;
        for _ in 0..(*m).verneednum {
            let file = (*m).strtab.add((*vn).file as usize);
            let mut aux = (vn as *const u8).add((*vn).aux as usize) as *const Vernaux;
            for _ in 0..(*vn).cnt {
                let idx = (*aux).other as usize & 0x7fff;
                *tbl.add(idx) = VerInfo { name: (*m).strtab.add((*aux).name as usize), hash: (*aux).hash, file, hidden: (*aux).other & 0x8000 != 0 };
                aux = (aux as *const u8).add((*aux).next as usize) as *const Vernaux;
            }
            vn = (vn as *const u8).add((*vn).next as usize) as *const Verneed;
        }
        (*m).vers = tbl;
        (*m).nvers = max + 1;
    }
}

pub unsafe fn dep_names(m: *mut LinkMap, mut f: impl FnMut(&'static [u8], u8)) {
    unsafe {
        for pass in 0..2 {
            let mut d = (*m).l_ld;
            while (*d).tag != DT_NULL {
                let kind = match (*d).tag {
                    DT_NEEDED => 0,
                    DT_AUXILIARY => 1,
                    DT_FILTER => 2,
                    _ => 3,
                };
                if kind != 3 && (kind == 0) == (pass == 0) {
                    f(cstr((*m).strtab.add((*d).val as usize)), kind);
                }
                d = d.add(1);
            }
        }
    }
}

pub unsafe fn needed_names(m: *mut LinkMap, mut f: impl FnMut(&'static [u8])) {
    unsafe {
        let mut d = (*m).l_ld;
        while (*d).tag != DT_NULL {
            if (*d).tag == DT_NEEDED {
                f(cstr((*m).strtab.add((*d).val as usize)));
            }
            d = d.add(1);
        }
    }
}

pub unsafe fn scan_phdrs(m: *mut LinkMap) {
    unsafe {
        let a = (*m).l_addr;
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for i in 0..(*m).phnum {
            let p = &*(*m).phdr.add(i);
            if p.typ == PT_LOAD {
                lo = lo.min(page_down(p.vaddr as usize));
                hi = hi.max(page_up((p.vaddr + p.memsz) as usize));
            }
        }
        if (*m).map_end == 0 && lo != usize::MAX {
            (*m).map_start = a + lo;
            (*m).map_end = a + hi;
        }
        for i in 0..(*m).phnum {
            let p = &*(*m).phdr.add(i);
            match p.typ {
                PT_DYNAMIC => (*m).l_ld = (a + p.vaddr as usize) as *mut Dyn,
                PT_TLS => {
                    (*m).tls_image = a + p.vaddr as usize;
                    (*m).tls_filesz = p.filesz as usize;
                    (*m).tls_memsz = p.memsz as usize;
                    (*m).tls_align = (p.align as usize).max(1);
                }
                PT_GNU_RELRO => {
                    (*m).relro_start = a + p.vaddr as usize;
                    (*m).relro_len = p.memsz as usize;
                }
                PT_GNU_EH_FRAME => (*m).eh_frame_hdr = a + p.vaddr as usize,
                _ => {}
            }
        }
    }
}

fn page_down(x: usize) -> usize {
    x & !(sys::PAGE - 1)
}
fn page_up(x: usize) -> usize {
    (x + sys::PAGE - 1) & !(sys::PAGE - 1)
}

fn errno_text(e: isize) -> &'static str {
    match -e {
        2 => "No such file or directory",
        13 => "Permission denied",
        12 => "Cannot allocate memory",
        20 => "Not a directory",
        21 => "Is a directory",
        24 => "Too many open files",
        8 => "Exec format error",
        _ => "Input/output error",
    }
}

pub unsafe fn map_file(path: *const u8, name: *const u8, loader: *mut LinkMap) -> *mut LinkMap {
    unsafe {
        let fd = sys::open(path);
        if fd < 0 {
            set_error(format_args!("cannot open shared object file: {}", errno_text(fd)));
            return null_mut();
        }
        let r = map_fd(fd, name, loader);
        sys::close(fd);
        r
    }
}

unsafe fn map_fd(fd: isize, name: *const u8, loader: *mut LinkMap) -> *mut LinkMap {
    unsafe {
        let (dev, ino) = sys::fstat_id(fd);
        let mut cur = st().head;
        while !cur.is_null() {
            if (*cur).dev == dev && (*cur).ino == ino && dev != 0 && !(*cur).unloading {
                return cur;
            }
            cur = (*cur).l_next;
        }
        let mut hdr_buf = core::mem::MaybeUninit::<[u64; 128]>::uninit();
        let hdr = hdr_buf.as_mut_ptr() as *mut u8;
        let n = sys::pread(fd, hdr, 1024, 0);
        if n < 0 {
            set_error(format_args!("cannot read file data: {}", errno_text(n)));
            return null_mut();
        }
        if n < core::mem::size_of::<Ehdr>() as isize {
            set_error(format_args!("file too short"));
            return null_mut();
        }
        let eh = &*(hdr as *const Ehdr);
        if &eh.ident[..4] != b"\x7fELF" || eh.ident[5] != 1 || eh.ident[6] != 1 {
            set_error(format_args!("invalid ELF header"));
            return null_mut();
        }
        if eh.ident[4] != 2 {
            set_error(format_args!("wrong ELF class: ELFCLASS32"));
            return null_mut();
        }
        if eh.machine != EM_X86_64 || (eh.typ != ET_DYN && eh.typ != ET_EXEC) {
            set_error(format_args!("cannot open shared object file: not an x86-64 shared object"));
            return null_mut();
        }
        if st().started && eh.typ == ET_EXEC {
            set_error(format_args!("cannot dynamically load executable"));
            return null_mut();
        }
        let phn = eh.phnum as usize;
        let phsz = phn * core::mem::size_of::<Phdr>();
        let mut phbuf: *mut u8 = hdr.add(eh.phoff as usize);
        if eh.phoff as usize + phsz > n as usize {
            phbuf = alloc_perm(phsz, 8);
            if sys::pread(fd, phbuf, phsz, eh.phoff as usize) != phsz as isize {
                set_error(format_args!("file too short"));
                return null_mut();
            }
        }
        let ph = core::slice::from_raw_parts(phbuf as *const Phdr, phn);
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for p in ph {
            if p.typ == PT_LOAD {
                lo = lo.min(page_down(p.vaddr as usize));
                hi = hi.max(page_up((p.vaddr + p.memsz) as usize));
            }
        }
        if lo == usize::MAX {
            set_error(format_args!("object file has no loadable segments"));
            return null_mut();
        }
        let span = hi - lo;
        let first_load = ph.iter().find(|p| p.typ == PT_LOAD).unwrap();
        let merged = first_load.flags & PF_W == 0 && first_load.memsz == first_load.filesz && page_down(first_load.vaddr as usize) == lo;
        let base;
        if eh.typ == ET_EXEC {
            let (prot0, flags, fd0, off0) = if merged {
                let p0 = (if first_load.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if first_load.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
                (p0, sys::MAP_PRIVATE | sys::MAP_FIXED_NOREPLACE, fd, page_down(first_load.offset as usize))
            } else {
                (sys::PROT_NONE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_FIXED_NOREPLACE, -1, 0)
            };
            let r = sys::mmap(lo, span, prot0, flags, fd0, off0);
            if r < 0 && r > -4096 {
                set_error(format_args!("cannot map executable at its fixed address"));
                return null_mut();
            }
            base = 0usize;
        } else if merged {
            let prot0 = (if first_load.flags & PF_R != 0 { sys::PROT_READ } else { 0 }) | (if first_load.flags & PF_X != 0 { sys::PROT_EXEC } else { 0 });
            let r = sys::mmap(0, span, prot0, sys::MAP_PRIVATE | map32_flag(ph), fd, page_down(first_load.offset as usize));
            if r < 0 && r > -4096 {
                set_error(format_args!("failed to map segment from shared object: {}", errno_text(r)));
                return null_mut();
            }
            base = (r as usize).wrapping_sub(lo);
        } else {
            let r = sys::mmap(0, span, sys::PROT_NONE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | map32_flag(ph), -1, 0);
            if r < 0 && r > -4096 {
                set_error(format_args!("failed to map segment from shared object: {}", errno_text(r)));
                return null_mut();
            }
            base = (r as usize).wrapping_sub(lo);
        }
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
                sys::mprotect(base + prev_end, start - prev_end, sys::PROT_NONE);
            }
            if !(merged && was_first) {
                let r = sys::mmap(base + start, page_up(filend) - start, prot, sys::MAP_PRIVATE | sys::MAP_FIXED, fd, off);
                if r < 0 && r > -4096 {
                    set_error(format_args!("failed to map segment from shared object: {}", errno_text(r)));
                    sys::munmap(base + lo, span);
                    return null_mut();
                }
            }
            let memend = vaddr + p.memsz as usize;
            prev_end = page_up(memend);
            if memend > filend {
                if p.flags & PF_W != 0 && filend & (sys::PAGE - 1) != 0 {
                    let z = page_up(filend) - filend;
                    core::ptr::write_bytes((base + filend) as *mut u8, 0, z.min(memend - filend));
                }
                let anon_start = page_up(filend);
                let anon_end = page_up(memend);
                if anon_end > anon_start {
                    let r = sys::mmap(base + anon_start, anon_end - anon_start, prot, sys::MAP_PRIVATE | sys::MAP_FIXED | sys::MAP_ANONYMOUS, -1, 0);
                    if r < 0 && r > -4096 {
                        set_error(format_args!("failed to map segment from shared object: {}", errno_text(r)));
                        return null_mut();
                    }
                }
            }
        }
        let m = new_map();
        (*m).l_addr = base;
        (*m).l_name = name;
        (*m).typ = eh.typ;
        (*m).map_start = base + lo;
        (*m).map_end = base + hi;
        (*m).entry = base + eh.entry as usize;
        (*m).dev = dev;
        (*m).ino = ino;
        (*m).loader = loader;
        let ph_copy = alloc_perm(phsz, 8) as *mut Phdr;
        core::ptr::copy_nonoverlapping(ph.as_ptr(), ph_copy, phn);
        (*m).phdr = (base + load0_vaddr + (eh.phoff as usize - load0_off)) as *const Phdr;
        let in_map = (eh.phoff as usize) >= load0_off && (eh.phoff as usize + phsz) <= load0_off + 0x100000;
        if !in_map {
            (*m).phdr = ph_copy;
        }
        (*m).phnum = phn;
        scan_phdrs(m);
        if (*m).l_ld.is_null() {
            set_error(format_args!("object file has no dynamic section"));
            return null_mut();
        }
        parse_dynamic(m);
        m
    }
}

pub unsafe fn protect_relro(m: *mut LinkMap) {
    unsafe {
        if (*m).relro_len != 0 {
            let s = page_down((*m).relro_start);
            let e = page_down((*m).relro_start + (*m).relro_len);
            if e > s {
                sys::mprotect(s, e - s, sys::PROT_READ);
            }
        }
    }
}

const MAX_PATH: usize = 4096;

pub unsafe fn origin_of(m: *mut LinkMap) -> &'static [u8] {
    unsafe {
        if (*m).origin.is_null() {
            let mut path = PathBuf::new();
            let mut p: &[u8] = cstr((*m).l_name);
            if p.is_empty() {
                path.grow(0, 4096);
                let n = sys::readlink(c"/proc/self/exe".as_ptr() as *const u8, path.ptr(), path.cap() - 1);
                if n > 0 {
                    p = core::slice::from_raw_parts(path.ptr(), n as usize);
                }
            }
            let end = p.iter().rposition(|&c| c == b'/');
            let dir: &[u8] = match end {
                Some(0) => b"/",
                Some(i) => &p[..i],
                None => b".",
            };
            (*m).origin = dup(dir);
        }
        cstr((*m).origin)
    }
}

pub(crate) unsafe fn expand(elem: &[u8], requester: *mut LinkMap, out: &mut PathBuf) -> usize {
    unsafe {
        let mut n = 0usize;
        let mut i = 0usize;
        let put = |out: &mut PathBuf, n: &mut usize, s: &[u8]| {
            for &c in s {
                if *n < MAX_PATH - 1 {
                    if *n + 2 > out.cap() {
                        out.grow(*n, *n + 2);
                    }
                    *out.ptr().add(*n) = c;
                    *n += 1;
                }
            }
        };
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
                match name {
                    b"ORIGIN" if !requester.is_null() => {
                        let o = origin_of(requester);
                        put(out, &mut n, o);
                    }
                    b"LIB" => put(out, &mut n, b"lib64"),
                    b"PLATFORM" => put(out, &mut n, b"x86_64"),
                    _ => put(out, &mut n, &elem[i..i + consumed]),
                }
                i += consumed;
            } else {
                put(out, &mut n, &elem[i..i + 1]);
                i += 1;
            }
        }
        if n + 1 > out.cap() {
            out.grow(n, n + 1);
        }
        *out.ptr().add(n) = 0;
        n
    }
}

unsafe fn try_dirs(list: &[u8], name: &[u8], requester: *mut LinkMap, found_err: &mut bool) -> *mut LinkMap {
    unsafe {
        let probe = PROBE_ONLY;
        for elem in list.split(|&c| c == b':') {
            let mut path = PathBuf::new();
            let n = if elem.is_empty() {
                *path.ptr() = b'.';
                1
            } else {
                expand(elem, requester, &mut path)
            };
            if n + 1 + name.len() + 1 > MAX_PATH {
                continue;
            }
            path.grow(n, n + 1 + name.len() + 1);
            *path.ptr().add(n) = b'/';
            core::ptr::copy_nonoverlapping(name.as_ptr(), path.ptr().add(n + 1), name.len());
            let plen = n + 1 + name.len();
            *path.ptr().add(plen) = 0;
            let fd = sys::open(path.ptr());
            if fd < 0 {
                continue;
            }
            if probe {
                if PROBE_IDENT {
                    let (dev, ino) = sys::fstat_id(fd);
                    sys::close(fd);
                    let mut cur = st().head;
                    while !cur.is_null() {
                        if (*cur).dev == dev && (*cur).ino == ino && dev != 0 && !(*cur).unloading {
                            return cur;
                        }
                        cur = (*cur).l_next;
                    }
                    return 1 as *mut LinkMap;
                }
                sys::close(fd);
                return 1 as *mut LinkMap;
            }
            let m = map_fd(fd, dup(core::slice::from_raw_parts(path.ptr(), plen)), requester);
            sys::close(fd);
            if !m.is_null() {
                return m;
            }
            *found_err = true;
        }
        null_mut()
    }
}

const DEFAULT_DIRS: &[u8] = b"/lib64:/usr/lib64:/lib:/usr/lib";
const PROBE_ONLY_SKIP_CACHE: bool = false;

static mut CACHE_PTR: usize = 0;
static mut CACHE_LEN: usize = 0;
static mut CACHE_TRIED: bool = false;

unsafe fn cache_load() {
    unsafe {
        if CACHE_TRIED {
            return;
        }
        CACHE_TRIED = true;
        let fd = sys::open(c"/etc/ld.so.cache".as_ptr() as *const u8);
        if fd < 0 {
            return;
        }
        let len = sys::fstat_size(fd);
        if len > 16 {
            let r = sys::mmap(0, len, sys::PROT_READ, sys::MAP_PRIVATE, fd, 0);
            if !(r < 0 && r > -4096) {
                CACHE_PTR = r as usize;
                CACHE_LEN = len;
            }
        }
        sys::close(fd);
    }
}

unsafe fn cache_lookup(name: &[u8]) -> Option<&'static [u8]> {
    unsafe {
        cache_load();
        if CACHE_PTR == 0 {
            return None;
        }
        let base = CACHE_PTR as *const u8;
        let rd32 = |off: usize| -> u32 { core::ptr::read_unaligned(base.add(off) as *const u32) };
        let mut hdr = 0usize;
        if core::slice::from_raw_parts(base, 11) == b"ld.so-1.7.0" {
            let nlibs = rd32(12) as usize;
            hdr = (16 + nlibs * 12 + 7) & !7;
        }
        if hdr + 48 > CACHE_LEN || core::slice::from_raw_parts(base.add(hdr), 20) != b"glibc-ld.so.cache1.1" {
            return None;
        }
        let nlibs = rd32(hdr + 20) as usize;
        let entries = hdr + 48;
        if entries + nlibs * 24 > CACHE_LEN {
            return None;
        }
        let key_of = |i: usize| rd32(entries + i * 24 + 4) as usize;
        let (mut lo, mut hi) = (0usize, nlibs);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let k = key_of(mid);
            if k >= CACHE_LEN || libcmp(base.add(k), name) > 0 {
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
            if key >= CACHE_LEN || libcmp(base.add(key), name) != 0 {
                break;
            }
            i += 1;
            let flags = rd32(e);
            let hwcaps = core::ptr::read_unaligned(base.add(e + 16) as *const u64);
            if flags & 0xff00 != 0x0300 || (hwcaps >> 62) & 1 != 0 || val >= CACHE_LEN || !cstr_eq(base.add(key), name) {
                continue;
            }
            return Some(cstr(base.add(val)));
        }
        None
    }
}

unsafe fn libcmp(mut p1: *const u8, name: &[u8]) -> i32 {
    unsafe {
        let mut j = 0usize;
        let at = |j: usize| -> u8 { if j < name.len() { name[j] } else { 0 } };
        while *p1 != 0 {
            let c1 = *p1;
            let c2 = at(j);
            if c1.is_ascii_digit() {
                if c2.is_ascii_digit() {
                    let (mut v1, mut v2) = ((c1 - b'0') as i64, (c2 - b'0') as i64);
                    p1 = p1.add(1);
                    j += 1;
                    while (*p1).is_ascii_digit() {
                        v1 = v1 * 10 + (*p1 - b'0') as i64;
                        p1 = p1.add(1);
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
                p1 = p1.add(1);
                j += 1;
            }
        }
        0 - at(j) as i32
    }
}

static mut PROBE_ONLY: bool = false;

static mut PROBE_IDENT: bool = false;

pub unsafe fn find_loaded_by_file(name: &[u8], requester: *mut LinkMap) -> *mut LinkMap {
    unsafe {
        PROBE_ONLY = true;
        PROBE_IDENT = true;
        let r = load_library_search(name, requester);
        PROBE_IDENT = false;
        PROBE_ONLY = false;
        if r as usize == 1 { null_mut() } else { r }
    }
}

pub unsafe fn library_exists(name: &[u8], requester: *mut LinkMap) -> bool {
    unsafe {
        PROBE_ONLY = true;
        let r = load_library_search(name, requester);
        PROBE_ONLY = false;
        !r.is_null()
    }
}

pub unsafe fn find_loaded(name: &[u8]) -> *mut LinkMap {
    unsafe {
        let mut cur = st().head;
        while !cur.is_null() {
            if !(*cur).unloading {
                if !(*cur).soname.is_null() && cstr((*cur).soname) == name {
                    return cur;
                }
                let n = cstr((*cur).l_name);
                if n == name && !n.is_empty() {
                    return cur;
                }
            }
            cur = (*cur).l_next;
        }
        null_mut()
    }
}

pub unsafe fn load_library(name: &[u8], requester: *mut LinkMap) -> *mut LinkMap {
    unsafe {
        let m = find_loaded(name);
        if !m.is_null() {
            return m;
        }
        load_library_search(name, requester)
    }
}

unsafe fn load_library_search(name: &[u8], requester: *mut LinkMap) -> *mut LinkMap {
    unsafe {
        let mut m: *mut LinkMap = null_mut();
        let mut bad = false;
        if name.contains(&b'/') {
            let mut path = PathBuf::new();
            if name.len() >= 4095 {
                set_error(format_args!("{}: cannot open shared object file: File name too long", Bytes(name)));
                return null_mut();
            }
            let n = expand(name, requester, &mut path);
            m = map_file(path.ptr(), dup(core::slice::from_raw_parts(path.ptr(), n)), requester);
            if m.is_null() {
                let e = error_str();
                let mut tmp = [0u8; 400];
                let l = e.len().min(399);
                tmp[..l].copy_from_slice(&e[..l]);
                set_error(format_args!("{}: {}", Bytes(name), Bytes(&tmp[..l])));
            }
        } else {
            let mut r = requester;
            while m.is_null() && !r.is_null() {
                if !(*r).rpath.is_null() && (*r).runpath.is_null() {
                    m = try_dirs(cstr((*r).rpath), name, r, &mut bad);
                }
                r = (*r).loader;
            }
            if m.is_null() && !st().library_path.is_null() {
                m = try_dirs(cstr(st().library_path), name, requester, &mut bad);
            }
            if m.is_null() && !requester.is_null() && !(*requester).runpath.is_null() {
                m = try_dirs(cstr((*requester).runpath), name, requester, &mut bad);
            }
            if m.is_null() && !PROBE_ONLY_SKIP_CACHE {
                if let Some(path) = cache_lookup(name) {
                    let mut dir = PathBuf::new();
                    if path.len() < MAX_PATH - 1 {
                        dir.grow(0, path.len() + 1);
                        core::ptr::copy_nonoverlapping(path.as_ptr(), dir.ptr(), path.len());
                        *dir.ptr().add(path.len()) = 0;
                        let fd = sys::open(dir.ptr());
                        if fd >= 0 {
                            if PROBE_ONLY {
                                sys::close(fd);
                                return 1 as *mut LinkMap;
                            }
                            m = map_fd(fd, dup(path), requester);
                            sys::close(fd);
                        }
                    }
                }
            }
            if m.is_null() {
                m = try_dirs(DEFAULT_DIRS, name, requester, &mut bad);
            }
            if m.is_null() {
                set_error(format_args!("{}: cannot open shared object file: No such file or directory", Bytes(name)));
            }
        }
        if m.is_null() {
            return null_mut();
        }
        if !PROBE_ONLY && (*m).l_prev.is_null() && st().head != m && (*m).l_next.is_null() && st().tail != m {
            link_map(m);
        }
        if !PROBE_ONLY && (*m).req_name.is_null() {
            (*m).req_name = dup(name);
        }
        m
    }
}

unsafe fn map32_flag(ph: &[Phdr]) -> usize {
    if st().map32 && ph.iter().any(|p| p.typ == PT_LOAD && p.flags & PF_X != 0) { 0x40 } else { 0 }
}
