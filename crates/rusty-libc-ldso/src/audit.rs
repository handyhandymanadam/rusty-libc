use crate::elf::*;
use crate::lookup::*;
use crate::map::*;
use crate::util::*;
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

#[derive(Clone, Copy)]
pub struct Lib {
    pub map: *mut LinkMap,
    pub version: u32,
    pub f_objsearch: usize,
    pub f_activity: usize,
    pub f_objopen: usize,
    pub f_preinit: usize,
    pub f_symbind64: usize,
    pub f_objclose: usize,
    pub f_pltenter: usize,
    pub f_pltexit: usize,
}

const NO_LIB: Lib = Lib { map: null_mut(), version: 0, f_objsearch: 0, f_activity: 0, f_objopen: 0, f_preinit: 0, f_symbind64: 0, f_objclose: 0, f_pltenter: 0, f_pltexit: 0 };

pub const LA_SYMB_NOPLTENTER: u32 = 1;
pub const LA_SYMB_NOPLTEXIT: u32 = 2;
pub const LA_SYMB_DLSYM: u32 = 0x08;
pub const LA_SYMB_ALTVALUE: u32 = 0x10;

pub struct Audit {
    pub libs: [Lib; MAX_AUDIT],
    pub n: usize,
    pub ready: bool,
    pub maps: [*mut LinkMap; 64],
    pub nmaps: usize,
}

pub static mut AUDIT: Audit = Audit { libs: [NO_LIB; MAX_AUDIT], n: 0, ready: false, maps: [null_mut(); 64], nmaps: 0 };

#[inline(always)]
pub fn au() -> &'static mut Audit {
    unsafe { &mut *(&raw mut AUDIT) }
}

#[inline(always)]
pub fn active() -> bool {
    au().ready && au().n != 0
}

#[inline(always)]
pub fn wants_objsearch() -> bool {
    active() && au().libs[..au().n].iter().any(|l| l.f_objsearch != 0)
}

pub unsafe fn objsearch(mut name: *const u8, l: *mut LinkMap, code: u32) -> *const u8 {
    unsafe {
        if l.is_null() || code == 0 || !wants_objsearch() || in_audit_closure(l) || is_audit_map(l) {
            return name;
        }
        for i in 0..au().n {
            let f = au().libs[i].f_objsearch;
            if f != 0 {
                let f: unsafe extern "C" fn(*const u8, *mut usize, u32) -> *const u8 = core::mem::transmute(f);
                name = f(name, &raw mut (*l).audit_cookie[i], code);
                if name.is_null() {
                    return name;
                }
            }
        }
        name
    }
}

unsafe fn find_fn(m: *mut LinkMap, name: &[u8]) -> usize {
    unsafe {
        let own = [m];
        let fl = Flags { plt: false, skip: null_mut(), newest: false };
        match lookup(name, None, &[&own], &fl) {
            Some(f) => sym_addr(&f),
            None => 0,
        }
    }
}

pub unsafe fn load(list: &[u8], from_option: bool) {
    unsafe {
        for name in list.split(|&c| c == b':' || c == b' ') {
            if name.is_empty() || au().n >= MAX_AUDIT {
                continue;
            }
            let before = st().tail;
            let m = load_library(name, null_mut());
            if m.is_null() {
                report_fail(name, from_option);
                continue;
            }
            let first_new = if before.is_null() { st().head } else { (*before).l_next };
            if !load_deps(m) {
                report_fail(name, from_option);
                continue;
            }
            let mut cur = first_new;
            while !cur.is_null() {
                if au().nmaps < 64 && !(*cur).in_global {
                    au().maps[au().nmaps] = cur;
                    au().nmaps += 1;
                    (*cur).nodelete = true;
                    (*cur).refcount += 1;
                }
                cur = (*cur).l_next;
            }
            crate::build_scope(m);
            let mut cur = first_new;
            while !cur.is_null() {
                if (*cur).scope.is_null() {
                    (*cur).scope = (*m).scope;
                    (*cur).nscope = (*m).nscope;
                }
                cur = (*cur).l_next;
            }
            let mut l = NO_LIB;
            l.map = m;
            au().libs[au().n] = l;
            au().n += 1;
        }
    }
}

unsafe fn report_fail(name: &[u8], _from_option: bool) {
    let e = error_str();
    let e = e.strip_prefix(name).and_then(|r| r.strip_prefix(b": ")).unwrap_or(e);
    let reason: &[u8] = if e.starts_with(b"cannot open shared object file") { b"cannot open shared object file" } else { e };
    crate::eprint!("ERROR: ld.so: object '{}' cannot be loaded as audit interface: {}; ignored.\n", Bytes(name), Bytes(reason));
}

unsafe fn load_deps(m: *mut LinkMap) -> bool {
    unsafe {
        let mut cur = m;
        while !cur.is_null() {
            let c = cur;
            if !(*c).is_ldso && (*c).needed.is_null() {
                let mut count = 0usize;
                needed_names(c, |_| count += 1);
                (*c).needed = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
                (*c).nneeded = 0;
                let mut ok = true;
                needed_names(c, |name| {
                    if !ok {
                        return;
                    }
                    let d = load_library(name, c);
                    if d.is_null() {
                        ok = false;
                        return;
                    }
                    *(*c).needed.add((*c).nneeded) = d;
                    (*c).nneeded += 1;
                });
                if !ok {
                    return false;
                }
            }
            cur = (*c).l_next;
        }
        true
    }
}

pub unsafe fn announce_open() {
    unsafe {
        let mut kept = 0usize;
        for i in 0..au().n {
            let mut l = au().libs[i];
            let fv = find_fn(l.map, b"la_version");
            if fv == 0 {
                crate::eprint!("ERROR: ld.so: object '{}' cannot be loaded as audit interface: undefined symbol: la_version; ignored.\n", Bytes(cstr((*l.map).l_name)));
                continue;
            }
            let f: unsafe extern "C" fn(u32) -> u32 = core::mem::transmute(fv);
            let v = f(LAV_CURRENT);
            if v == 0 || v > LAV_CURRENT {
                crate::eprint!("ERROR: audit interface '{}' requires version {} (maximum supported version {}); ignored.\n", Bytes(cstr((*l.map).l_name)), v, LAV_CURRENT);
                continue;
            }
            l.version = v;
            l.f_objsearch = find_fn(l.map, b"la_objsearch");
            l.f_activity = find_fn(l.map, b"la_activity");
            l.f_objopen = find_fn(l.map, b"la_objopen");
            l.f_preinit = find_fn(l.map, b"la_preinit");
            l.f_symbind64 = find_fn(l.map, b"la_symbind64");
            l.f_objclose = find_fn(l.map, b"la_objclose");
            l.f_pltenter = find_fn(l.map, b"la_x86_64_gnu_pltenter");
            l.f_pltexit = find_fn(l.map, b"la_x86_64_gnu_pltexit");
            au().libs[kept] = l;
            kept += 1;
        }
        au().n = kept;
        au().ready = kept != 0;
        if kept == 0 {
            return;
        }
        objopen(st().main_map);
        objopen(st().ldso_map);
        activity(LA_ACT_ADD);
        let mut cur = st().head;
        while !cur.is_null() {
            if !is_audit_map(cur) && !(*cur).is_main && !(*cur).is_ldso {
                objopen(cur);
            }
            cur = (*cur).l_next;
        }
        activity(LA_ACT_CONSISTENT);
    }
}

pub unsafe fn announce_preinit() {
    unsafe {
        if !active() {
            return;
        }
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_preinit != 0 {
                let f: unsafe extern "C" fn(*mut usize) = core::mem::transmute(l.f_preinit);
                f(&raw mut (*st().main_map).audit_cookie[i]);
            }
        }
    }
}

pub unsafe fn plt_hooks_for(m: *mut LinkMap) -> bool {
    unsafe { active() && au().libs[..au().n].iter().any(|l| l.f_pltenter != 0 || l.f_pltexit != 0) && !in_audit_closure(m) }
}

pub unsafe fn in_audit_closure(m: *mut LinkMap) -> bool {
    unsafe {
        let mut list: [*mut LinkMap; 256] = [null_mut(); 256];
        let mut n = 0;
        for i in 0..au().n {
            list[n] = au().libs[i].map;
            n += 1;
        }
        let mut i = 0;
        while i < n {
            let c = list[i];
            i += 1;
            if c == m {
                return true;
            }
            for k in 0..(*c).nneeded {
                let d = *(*c).needed.add(k);
                if !list[..n].contains(&d) && n < 256 {
                    list[n] = d;
                    n += 1;
                }
            }
        }
        false
    }
}

unsafe fn is_audit_map(m: *mut LinkMap) -> bool {
    unsafe {
        for i in 0..au().nmaps {
            if au().maps[i] == m {
                return true;
            }
        }
        false
    }
}

pub unsafe fn activity(flag: u32) {
    unsafe {
        if !active() {
            return;
        }
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_activity != 0 {
                let f: unsafe extern "C" fn(*mut usize, u32) = core::mem::transmute(l.f_activity);
                f(&raw mut (*st().main_map).audit_cookie[i], flag);
            }
        }
    }
}

pub unsafe fn objopen(m: *mut LinkMap) {
    unsafe {
        if !active() {
            return;
        }
        (*m).audit_opened = true;
        make_libnames(m);
        for i in 0..au().n {
            let l = au().libs[i];
            (*m).audit_cookie[i] = m as usize;
            if l.f_objopen != 0 {
                let f: unsafe extern "C" fn(*mut LinkMap, isize, *mut usize) -> u32 = core::mem::transmute(l.f_objopen);
                (*m).audit_flags[i] = f(m, 0, &raw mut (*m).audit_cookie[i]);
                (*m).audit_any_plt |= (*m).audit_flags[i] != 0;
            }
        }
    }
}

unsafe fn make_libnames(m: *mut LinkMap) {
    unsafe {
        if !(*m).l_libname.is_null() {
            return;
        }
        let first: *const u8 = if (*m).is_main {
            c"".as_ptr() as *const u8
        } else if !(*m).req_name.is_null() {
            (*m).req_name
        } else {
            (*m).l_name
        };
        let a = alloc_perm(core::mem::size_of::<LibName>(), 8) as *mut LibName;
        (*a).name = first;
        (*a).dont_free = 1;
        (*m).l_libname = a;
        if !(*m).soname.is_null() && cstr((*m).soname) != cstr(first) {
            let b = alloc_perm(core::mem::size_of::<LibName>(), 8) as *mut LibName;
            (*b).name = (*m).soname;
            (*b).dont_free = 1;
            (*a).next = b;
        }
    }
}

pub unsafe fn objclose(m: *mut LinkMap) {
    unsafe {
        if !active() {
            return;
        }
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_objclose != 0 && (*m).audit_opened {
                let f: unsafe extern "C" fn(*mut usize) -> u32 = core::mem::transmute(l.f_objclose);
                f(&raw mut (*m).audit_cookie[i]);
            }
        }
    }
}

pub unsafe fn symbind(sym: *const Sym, defmap: *mut LinkMap, refmap: *mut LinkMap, name: &[u8], mut addr: usize, jmp_slot: bool) -> usize {
    unsafe {
        if !active() || defmap.is_null() || refmap.is_null() {
            return addr;
        }
        let ndx = (sym as usize - (*defmap).symtab as usize) / core::mem::size_of::<Sym>();
        let mut nbuf = [0u8; 256];
        let n = name.len().min(255);
        nbuf[..n].copy_from_slice(&name[..n]);
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_symbind64 == 0 {
                continue;
            }
            if (*refmap).audit_flags[i] & LA_FLG_BINDFROM == 0 || (*defmap).audit_flags[i] & LA_FLG_BINDTO == 0 {
                continue;
            }
            let f: unsafe extern "C" fn(*const Sym, u32, *mut usize, *mut usize, *mut u32, *const u8) -> usize = core::mem::transmute(l.f_symbind64);
            let mut flags = if jmp_slot { LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT } else { 0u32 };
            let mut copy = *sym;
            copy.value = addr as u64;
            let new = f(&copy, ndx as u32, &raw mut (*refmap).audit_cookie[i], &raw mut (*defmap).audit_cookie[i], &mut flags, nbuf.as_ptr());
            if new != 0 {
                addr = new;
            }
        }
        addr
    }
}

pub unsafe fn symbind_dlsym(caller: *mut LinkMap, sym: *const Sym, defmap: *mut LinkMap, name: &[u8], mut addr: usize) -> usize {
    unsafe {
        let caller = if caller.is_null() { st().main_map } else { caller };
        if !active() || defmap.is_null() || caller.is_null() || !((*caller).audit_any_plt || (*defmap).audit_any_plt) {
            return addr;
        }
        let ndx = (sym as usize - (*defmap).symtab as usize) / core::mem::size_of::<Sym>();
        let mut nbuf = [0u8; 256];
        let n = name.len().min(255);
        nbuf[..n].copy_from_slice(&name[..n]);
        let mut copy = *sym;
        copy.value = addr as u64;
        let mut alt = 0u32;
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_symbind64 != 0 && ((*caller).audit_flags[i] & LA_FLG_BINDFROM != 0 || (*defmap).audit_flags[i] & LA_FLG_BINDTO != 0) {
                let f: unsafe extern "C" fn(*const Sym, u32, *mut usize, *mut usize, *mut u32, *const u8) -> usize = core::mem::transmute(l.f_symbind64);
                let mut flags = alt | LA_SYMB_DLSYM;
                let new = f(&copy, ndx as u32, &raw mut (*caller).audit_cookie[i], &raw mut (*defmap).audit_cookie[i], &mut flags, nbuf.as_ptr());
                if new as u64 != copy.value {
                    alt = LA_SYMB_ALTVALUE;
                    copy.value = new as u64;
                }
            }
        }
        addr = copy.value as usize;
        addr
    }
}

pub unsafe fn close_all() {
    unsafe {
        if !active() {
            return;
        }
        activity(LA_ACT_DELETE);
        objclose(st().main_map);
        let mut cur = st().head;
        while !cur.is_null() {
            if !is_audit_map(cur) && !(*cur).is_main && !(*cur).is_ldso && !(*cur).is_vdso {
                objclose(cur);
                (*cur).audit_opened = false;
            }
            cur = (*cur).l_next;
        }
        objclose(st().ldso_map);
        activity(LA_ACT_CONSISTENT);
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

pub unsafe fn symbind_slot(sym: *const Sym, defmap: *mut LinkMap, refmap: *mut LinkMap, name: &[u8], addr: usize) -> (usize, u32, u32) {
    unsafe {
        if !active() || defmap.is_null() || refmap.is_null() || !((*refmap).audit_any_plt || (*defmap).audit_any_plt) {
            return (addr, 0xffff, 0);
        }
        let ndx = (sym as usize - (*defmap).symtab as usize) / core::mem::size_of::<Sym>();
        let mut nbuf = [0u8; 256];
        let n = name.len().min(255);
        nbuf[..n].copy_from_slice(&name[..n]);
        let mut copy = *sym;
        copy.value = addr as u64;
        let mut enterexit = 3u32;
        let mut flags = 0u32;
        for i in 0..au().n {
            let l = au().libs[i];
            if (*refmap).audit_flags[i] & LA_FLG_BINDFROM != 0 && (*defmap).audit_flags[i] & LA_FLG_BINDTO != 0 {
                if l.f_symbind64 != 0 {
                    let f: unsafe extern "C" fn(*const Sym, u32, *mut usize, *mut usize, *mut u32, *const u8) -> usize = core::mem::transmute(l.f_symbind64);
                    let new = f(&copy, ndx as u32, &raw mut (*refmap).audit_cookie[i], &raw mut (*defmap).audit_cookie[i], &mut flags, nbuf.as_ptr());
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
}

type PltEnter = unsafe extern "C" fn(*mut Sym, u32, *mut usize, *mut usize, *mut Regs, *mut u32, *const u8, *mut isize) -> usize;
type PltExit = unsafe extern "C" fn(*mut Sym, u32, *mut usize, *mut usize, *const Regs, *mut Retval, *const u8) -> u32;

pub unsafe fn pltenter(m: *mut LinkMap, bound: *mut LinkMap, ndx: u32, enterexit: &mut u32, slot_flags: u32, value: &mut usize, regs: *mut Regs, framesize: &mut isize) {
    unsafe {
        if !active() || *enterexit & LA_SYMB_NOPLTENTER != 0 || bound.is_null() {
            return;
        }
        let defsym = (*bound).symtab.add(ndx as usize);
        let name = (*bound).strtab.add((*defsym).name as usize);
        let mut sym = *defsym;
        sym.value = *value as u64;
        let mut flags = slot_flags;
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_pltenter != 0 && *enterexit & (LA_SYMB_NOPLTENTER << (2 * (i + 1))) == 0 {
                let f: PltEnter = core::mem::transmute(l.f_pltenter);
                let mut new_framesize: isize = -1;
                let new = f(&mut sym, ndx, &raw mut (*m).audit_cookie[i], &raw mut (*bound).audit_cookie[i], regs, &mut flags, name, &mut new_framesize);
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
}

pub unsafe fn pltexit(m: *mut LinkMap, bound: *mut LinkMap, ndx: u32, enterexit: u32, addr: usize, inregs: *const Regs, outregs: *mut Retval) {
    unsafe {
        if !active() || bound.is_null() {
            return;
        }
        let defsym = (*bound).symtab.add(ndx as usize);
        let name = (*bound).strtab.add((*defsym).name as usize);
        let mut sym = *defsym;
        sym.value = addr as u64;
        for i in 0..au().n {
            let l = au().libs[i];
            if l.f_pltexit != 0 && enterexit & (LA_SYMB_NOPLTEXIT >> (2 * i)) == 0 {
                let f: PltExit = core::mem::transmute(l.f_pltexit);
                f(&mut sym, ndx, &raw mut (*m).audit_cookie[i], &raw mut (*bound).audit_cookie[i], inregs, outregs, name);
            }
        }
    }
}
