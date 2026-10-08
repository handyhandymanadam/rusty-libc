use crate::elf::*;
use crate::lookup::*;
use crate::map::*;
use crate::reloc;
use crate::sys;
use crate::tls;
use crate::util::*;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};

pub const RTLD_NOLOAD: c_int = 0x4;
pub const RTLD_DEEPBIND: c_int = 0x8;
pub const RTLD_GLOBAL: c_int = 0x100;
pub const RTLD_NODELETE: c_int = 0x1000;

static DL_LOCK: Lock = Lock::new();
static mut ADDS: u64 = 1;
static mut SUBS: u64 = 0;

#[repr(C)]
pub struct ErrBuf {
    state: u8,
    len: usize,
    text: [u8; 512],
    ext: *mut u8,
    ext_cap: usize,
}
pub const ERRBUF_SIZE: usize = core::mem::size_of::<ErrBuf>();
static mut EARLY_ERR: ErrBuf = ErrBuf { state: 0, len: 0, text: [0; 512], ext: null_mut(), ext_cap: 0 };

pub unsafe fn free_errbuf(p: *mut u8) {
    let b = p as *mut ErrBuf;
    if !(*b).ext.is_null() {
        free_blk((*b).ext, (*b).ext_cap, 16);
    }
    free_blk(p, ERRBUF_SIZE, 16);
}

unsafe fn err_buf() -> *mut ErrBuf {
    if !tls::ready() {
        return &raw mut EARLY_ERR;
    }
    let slot = (sys::thread_pointer() + 0x48) as *mut usize;
    if *slot == 0 {
        *slot = alloc_blk(ERRBUF_SIZE, 16) as usize;
    }
    *slot as *mut ErrBuf
}

unsafe fn err_room(b: *mut ErrBuf, n: usize) -> *mut u8 {
    if n + 1 <= (*b).text.len() {
        return (*b).text.as_mut_ptr();
    }
    if n + 1 > (*b).ext_cap {
        let cap = (n + 1).next_power_of_two();
        let p = alloc_blk(cap, 16);
        if p.is_null() {
            return (*b).text.as_mut_ptr();
        }
        if !(*b).ext.is_null() {
            free_blk((*b).ext, (*b).ext_cap, 16);
        }
        (*b).ext = p;
        (*b).ext_cap = cap;
    }
    (*b).ext
}

unsafe fn err_text(b: *mut ErrBuf) -> *mut u8 {
    if (*b).len + 1 > (*b).text.len() && !(*b).ext.is_null() { (*b).ext } else { (*b).text.as_mut_ptr() }
}

unsafe fn publish_error() {
    let e = error_str();
    let b = err_buf();
    let room = err_room(b, e.len());
    let n = if room == (*b).text.as_mut_ptr() { e.len().min(511) } else { e.len() };
    core::ptr::copy_nonoverlapping(e.as_ptr(), room, n);
    *room.add(n) = 0;
    (*b).len = n;
    (*b).state = 1;
}

unsafe fn fail(args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct W(*mut u8, usize, usize);
    impl Write for W {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &c in s.as_bytes() {
                if self.1 < self.2 {
                    unsafe { *self.0.add(self.1) = c };
                    self.1 += 1;
                }
            }
            Ok(())
        }
    }
    let b = err_buf();
    let mut c = Count(0);
    let _ = c.write_fmt(args);
    let room = err_room(b, c.0);
    let limit = if room == (*b).text.as_mut_ptr() { 511 } else { c.0 };
    let mut w = W(room, 0, limit);
    let _ = w.write_fmt(args);
    let n = w.1;
    *room.add(n) = 0;
    (*b).len = n;
    (*b).state = 1;
}

unsafe fn succeed() {
    let b = err_buf();
    if (*b).state == 1 {
        (*b).state = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlerror() -> *const c_char {
    let b = err_buf();
    if (*b).state == 1 {
        (*b).state = 2;
        err_text(b) as *const c_char
    } else {
        (*b).state = 0;
        null()
    }
}

pub unsafe fn map_of_addr(addr: usize) -> *mut LinkMap {
    let mut cur = st().head;
    while !cur.is_null() {
        if !(*cur).unloading && addr >= (*cur).map_start && addr < (*cur).map_end {
            return cur;
        }
        cur = (*cur).l_next;
    }
    null_mut()
}

unsafe fn object_name(m: *mut LinkMap) -> &'static [u8] {
    let n = cstr((*m).l_name);
    if n.is_empty() { cstr(st().prog_name) } else { n }
}

unsafe fn load_deps_new(first: *mut LinkMap) -> bool {
    let mut cur = first;
    while !cur.is_null() {
        let m = cur;
        if !(*m).is_ldso && (*m).needed.is_null() {
            let mut count = 0usize;
            dep_names(m, |_, _| count += 1);
            (*m).needed = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
            (*m).nneeded = 0;
            (*m).filtees = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
            (*m).nfiltees = 0;
            let mut ok = true;
            dep_names(m, |name, kind| {
                if !ok {
                    return;
                }
                let d = load_library(name, m);
                if d.is_null() {
                    ok = kind != 0;
                    return;
                }
                *(*m).needed.add((*m).nneeded) = d;
                (*m).nneeded += 1;
                if kind != 0 {
                    *(*m).filtees.add((*m).nfiltees) = d;
                    (*m).nfiltees += 1;
                    if kind == 2 {
                        (*m).filter_hard = true;
                    }
                }
            });
            if !ok {
                return false;
            }
        }
        cur = (*m).l_next;
    }
    true
}

unsafe fn discard_from(first: *mut LinkMap) {
    let mut list: [*mut LinkMap; 256] = [null_mut(); 256];
    let mut n = 0;
    let mut cur = first;
    while !cur.is_null() && n < 256 {
        list[n] = cur;
        n += 1;
        cur = (*cur).l_next;
    }
    for &m in &list[..n] {
        drop_map(m);
    }
}

unsafe fn drop_map(m: *mut LinkMap) {
    let s = st();
    (*m).unloading = true;
    (*m).removed = true;
    let mut j = 0;
    for i in 0..s.nglobal {
        if s.global[i] != m {
            s.global[j] = s.global[i];
            j += 1;
        }
    }
    s.nglobal = j;
    (*m).in_global = false;
    tls::remove_module(m);
    unlink_map(m);
    if !(*m).plt_cache.is_null() {
        let n = ((*m).pltrelsz / core::mem::size_of::<Rela>()).max(1) * crate::plt::SLOT_SIZE;
        sys::munmap((*m).plt_cache as usize, n);
        (*m).plt_cache = null_mut();
    }
    sys::munmap((*m).map_start, (*m).map_end - (*m).map_start);
}

pub unsafe fn open_object(name: Option<&[u8]>, mode: c_int, caller: usize) -> *mut LinkMap {
    let s = st();
    let Some(name) = name else { return s.main_map };
    if name.is_empty() {
        return s.main_map;
    }
    let requester = map_of_addr(caller);
    if mode & SPROF != 0 {
        return sprof_open(name, requester);
    }
    if mode & RTLD_NOLOAD != 0 {
        let mut m = find_loaded(name);
        if m.is_null() {
            m = find_loaded_by_file(name, requester);
        }
        if !m.is_null() && mode & RTLD_GLOBAL != 0 {
            promote_global(m);
        }
        if !m.is_null() {
            (*m).refcount += 1;
        }
        if m.is_null() && !library_exists(name, requester) {
            set_error(format_args!("{}: cannot open shared object file: No such file or directory", Bytes(name)));
        }
        return m;
    }
    let tail_before = s.tail;
    let root = load_library(name, requester);
    if root.is_null() {
        discard_from(if tail_before.is_null() { s.head } else { (*tail_before).l_next });
        return null_mut();
    }
    let first_new = if tail_before.is_null() { s.head } else { (*tail_before).l_next };
    if (*root).opening && first_new.is_null() {
        if mode & RTLD_GLOBAL != 0 {
            promote_global(root);
        }
        (*root).refcount += 1;
        return root;
    }
    if root == s.main_map {
        set_error(format_args!("{}: cannot dynamically load {}", Bytes(name), if (*root).flags_1 & 0x0800_0000 != 0 { "position-independent executable" } else { "executable" }));
        return null_mut();
    }
    if (*root).flags_1 & 0x0800_0000 != 0 {
        set_error(format_args!("{}: cannot dynamically load position-independent executable", Bytes(name)));
        discard_from(first_new);
        return null_mut();
    }
    if !load_deps_new(first_new) {
        discard_from(first_new);
        return null_mut();
    }
    {
        let mut bad = (*root).flags_1 & 0x40 != 0;
        let mut c = first_new;
        while !c.is_null() {
            bad |= (*c).flags_1 & 0x40 != 0;
            c = (*c).l_next;
        }
        if bad {
            set_error(format_args!("{}: shared object cannot be dlopen()ed", Bytes(name)));
            discard_from(first_new);
            return null_mut();
        }
    }
    if (*root).scope.is_null() {
        crate::build_scope(root);
    }
    for i in 0..(*root).nscope {
        let d = *(*root).scope.add(i);
        let mut is_new = false;
        let mut c = first_new;
        while !c.is_null() {
            if c == d {
                is_new = true;
            }
            c = (*c).l_next;
        }
        if is_new || (*d).in_global || d == root {
            continue;
        }
        add_extra_scope(d, root);
    }
    let mut cur = first_new;
    while !cur.is_null() {
        (*cur).dlopened = true;
        (*cur).opening = true;
        if (*cur).scope.is_null() {
            (*cur).scope = (*root).scope;
            (*cur).nscope = (*root).nscope;
        }
        if mode & RTLD_DEEPBIND != 0 {
            (*cur).deepbind = true;
        }
        if mode & 0x2 != 0 && !crate::profile::enabled() {
            (*cur).bind_now = true;
            (*cur).rtld_now = true;
        }
        cur = (*cur).l_next;
    }
    let mut cur = first_new;
    while !cur.is_null() {
        if !tls::add_module(cur, false) || ((*cur).flags & DF_STATIC_TLS != 0 && !tls::add_static_late(cur)) {
            set_error(format_args!("{}: cannot allocate memory in static TLS block", Bytes(object_name(cur))));
            discard_from(first_new);
            return null_mut();
        }
        cur = (*cur).l_next;
    }
    if mode & RTLD_GLOBAL != 0 {
        promote_global(root);
    }
    let mut list: [*mut LinkMap; 256] = [null_mut(); 256];
    let mut n = 0;
    let mut cur = first_new;
    while !cur.is_null() && n < 256 {
        list[n] = cur;
        n += 1;
        cur = (*cur).l_next;
    }
    crate::_r_debug.state = 1;
    crate::_dl_debug_state();
    crate::audit::activity(crate::audit::LA_ACT_ADD);
    for &m in &list[..n] {
        crate::audit::objopen(m);
    }
    for i in (0..n).rev() {
        if !reloc::relocate(list[i]) {
            discard_from(first_new);
            crate::_r_debug.state = 0;
            crate::_dl_debug_state();
            crate::audit::activity(crate::audit::LA_ACT_CONSISTENT);
            return null_mut();
        }
    }
    crate::profile::start();
    for &m in &list[..n] {
        protect_relro(m);
        ADDS += 1;
        for k in 0..(*m).nneeded {
            (*(*(*m).needed.add(k))).refcount += 1;
        }
    }
    if mode & RTLD_NODELETE != 0 {
        (*root).nodelete = true;
    }
    (*root).refcount += 1;
    crate::_r_debug.state = 0;
    crate::_dl_debug_state();
    crate::audit::activity(crate::audit::LA_ACT_CONSISTENT);
    let mut cur = first_new;
    while !cur.is_null() {
        (*cur).opening = false;
        cur = (*cur).l_next;
    }
    crate::init_tree(root, false);
    root
}

unsafe fn promote_global(m: *mut LinkMap) {
    if (*m).scope.is_null() {
        crate::build_scope(m);
    }
    for i in 0..(*m).nscope {
        let d = *(*m).scope.add(i);
        if !(*d).is_ldso {
            let s = st();
            if !(*d).in_global && s.nglobal < MAX_MAPS {
                s.global[s.nglobal] = d;
                s.nglobal += 1;
                (*d).in_global = true;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlopen(file: *const u8, mode: c_int, caller: usize) -> *mut c_void {
    if mode & !(0x3 | RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_GLOBAL | RTLD_NODELETE | 0x4000_0000) != 0 {
        fail(format_args!("invalid mode parameter"));
        return null_mut();
    }
    if mode & 0x3 == 0 {
        if file.is_null() {
            fail(format_args!("invalid mode for dlopen(): Invalid argument"));
        } else {
            fail(format_args!("{}: invalid mode for dlopen(): Invalid argument", Bytes(cstr(file))));
        }
        return null_mut();
    }
    DL_LOCK.lock();
    set_error(format_args!(""));
    let r = open_object(if file.is_null() { None } else { Some(cstr(file)) }, mode, caller);
    if r.is_null() {
        if st().error_len != 0 {
            publish_error();
        }
    } else {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

unsafe fn needs(from: *mut LinkMap, to: *mut LinkMap) -> bool {
    let mut stack: [*mut LinkMap; 256] = [null_mut(); 256];
    let mut seen: [*mut LinkMap; 256] = [null_mut(); 256];
    let (mut sp, mut ns) = (0usize, 0usize);
    stack[0] = from;
    sp += 1;
    while sp > 0 {
        sp -= 1;
        let m = stack[sp];
        if m == to {
            return true;
        }
        if seen[..ns].contains(&m) || ns >= 256 {
            continue;
        }
        seen[ns] = m;
        ns += 1;
        for k in 0..(*m).nneeded {
            if sp < 256 {
                stack[sp] = *(*m).needed.add(k);
                sp += 1;
            }
        }
    }
    false
}

pub unsafe fn note_binding(undef: *mut LinkMap, def: *mut LinkMap) {
    if undef.is_null() || def.is_null() || def == undef || !(*def).dlopened || (*def).nodelete {
        return;
    }
    DL_LOCK.lock();
    if !(*def).nodelete && !needs(undef, def) {
        if !(*undef).dlopened {
            (*def).nodelete = true;
        } else {
            let mut known = false;
            for k in 0..(*undef).nreldeps {
                known |= *(*undef).reldeps.add(k) == def;
            }
            if !known {
                if (*undef).nreldeps == (*undef).creldeps {
                    let nc = if (*undef).creldeps == 0 { 8 } else { (*undef).creldeps * 2 };
                    let nb = alloc_perm(nc * core::mem::size_of::<usize>(), 8) as *mut *mut LinkMap;
                    for k in 0..(*undef).nreldeps {
                        *nb.add(k) = *(*undef).reldeps.add(k);
                    }
                    (*undef).reldeps = nb;
                    (*undef).creldeps = nc;
                }
                *(*undef).reldeps.add((*undef).nreldeps) = def;
                (*undef).nreldeps += 1;
                (*def).refcount += 1;
            }
        }
    }
    DL_LOCK.unlock();
}

unsafe fn release(m: *mut LinkMap) {
    if (*m).refcount > 0 {
        (*m).refcount -= 1;
    }
    if (*m).refcount > 0 || (*m).nodelete || (*m).is_main || (*m).is_ldso || (*m).unloading {
        return;
    }
    (*m).unloading = true;
    crate::_r_debug.state = 2;
    crate::_dl_debug_state();
    if (*m).init_called {
        crate::run_fini(m);
    }
    for k in 0..(*m).nneeded {
        release(*(*m).needed.add(k));
    }
    for k in 0..(*m).nreldeps {
        release(*(*m).reldeps.add(k));
    }
    (*m).unloading = false;
    (*m).removed = true;
    crate::audit::activity(crate::audit::LA_ACT_DELETE);
    crate::audit::objclose(m);
    drop_map(m);
    SUBS += 1;
    crate::_r_debug.state = 0;
    crate::_dl_debug_state();
    crate::audit::activity(crate::audit::LA_ACT_CONSISTENT);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlclose(handle: *mut c_void) -> c_int {
    DL_LOCK.lock();
    if sprof_is_handle(handle) {
        sprof_close(handle);
        succeed();
        DL_LOCK.unlock();
        return 0;
    }
    let m = handle as *mut LinkMap;
    let r = if m.is_null() || m == st().main_map {
        succeed();
        0
    } else {
        let mut cur = st().head;
        let mut ok = false;
        while !cur.is_null() {
            if cur == m && !(*cur).unloading {
                ok = true;
            }
            cur = (*cur).l_next;
        }
        if !ok {
            fail(format_args!("invalid handle"));
            -1
        } else {
            release(m);
            succeed();
            0
        }
    };
    DL_LOCK.unlock();
    r
}

unsafe fn tls_symbol_address(f: &Found) -> usize {
    let ti = tls::TlsIndex { module: (*f.map).tls_modid, offset: (*f.sym).value as usize };
    tls::__tls_get_addr(&ti)
}

pub unsafe fn symbol_lookup(handle: *mut c_void, name: &[u8], ver: Option<&VerRef>, caller: usize) -> usize {
    let s = st();
    let g = core::slice::from_raw_parts((&raw const s.global) as *const *mut LinkMap, s.nglobal);
    let fl = Flags { plt: false, skip: null_mut(), newest: ver.is_none() };
    let found: Option<Found>;
    let where_: Option<*mut LinkMap>;
    match handle as usize {
        0 => {
            found = lookup(name, ver, &[g], &fl);
            where_ = None;
            if let Some(f) = &found {
                let c = map_of_addr(caller);
                note_binding(if c.is_null() { s.main_map } else { c }, f.map);
            }
        }
        usize::MAX => {
            let c = map_of_addr(caller);
            if c.is_null() {
                fail(format_args!("RTLD_NEXT used in code not dynamically loaded"));
                return 0;
            }
            let mut scope: [*mut LinkMap; 1024] = [null_mut(); 1024];
            let mut n = 0;
            let mut seen = false;
            for &m in g {
                if seen && n < 1024 {
                    scope[n] = m;
                    n += 1;
                }
                if m == c {
                    seen = true;
                }
            }
            if !seen && !(*c).scope.is_null() {
                for i in 0..(*c).nscope {
                    let m = *(*c).scope.add(i);
                    if seen && n < 1024 {
                        scope[n] = m;
                        n += 1;
                    }
                    if m == c {
                        seen = true;
                    }
                }
                for &m in g {
                    if n < 1024 {
                        scope[n] = m;
                        n += 1;
                    }
                }
            }
            found = lookup(name, ver, &[&scope[..n]], &fl);
            where_ = None;
            if let Some(f) = &found {
                note_binding(c, f.map);
            }
        }
        _ => {
            let m = handle as *mut LinkMap;
            if m == s.main_map {
                found = lookup(name, ver, &[g], &fl);
            } else {
                if (*m).scope.is_null() {
                    crate::build_scope(m);
                }
                let own = core::slice::from_raw_parts((*m).scope, (*m).nscope);
                found = lookup(name, ver, &[own], &fl);
            }
            where_ = Some(m);
        }
    }
    match found {
        Some(f) => {
            let t = (*f.sym).info & 0xf;
            if t == STT_TLS {
                return tls_symbol_address(&f);
            }
            let a = sym_addr(&f);
            let a = if t == STT_GNU_IFUNC { reloc::call_resolver(a) } else { a };
            if crate::audit::active() { crate::audit::symbind_dlsym(map_of_addr(caller), f.sym, f.map, name, a) } else { a }
        }
        None => {
            let vtext: &[u8] = match ver {
                Some(v) => cstr(v.name),
                None => b"",
            };
            let who: &[u8] = match where_ {
                Some(m) if m != s.main_map => object_name(m),
                _ => cstr(s.prog_name),
            };
            if ver.is_some() {
                fail(format_args!("{}: undefined symbol: {}, version {}", Bytes(who), Bytes(name), Bytes(vtext)));
            } else {
                fail(format_args!("{}: undefined symbol: {}", Bytes(who), Bytes(name)));
            }
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlsym(handle: *mut c_void, name: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    let r = symbol_lookup(handle, cstr(name), None, caller);
    if r != 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlvsym(handle: *mut c_void, name: *const u8, version: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    let v = if version.is_null() { None } else { Some(VerRef { name: version, hash: elf_hash(cstr(version)), file: null(), hidden: true }) };
    let r = symbol_lookup(handle, cstr(name), v.as_ref(), caller);
    if r != 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

unsafe fn symbol_count(m: *mut LinkMap) -> usize {
    if (*m).gnu_nbuckets != 0 {
        let mut max = 0u32;
        for b in 0..(*m).gnu_nbuckets as usize {
            max = max.max(*(*m).gnu_buckets.add(b));
        }
        if max < (*m).gnu_symoffset {
            return (*m).gnu_symoffset as usize;
        }
        let mut i = max;
        loop {
            let ch = *(*m).gnu_chain.add((i - (*m).gnu_symoffset) as usize);
            if ch & 1 != 0 {
                break;
            }
            i += 1;
        }
        return i as usize + 1;
    }
    (*m).hash_nchain as usize
}

unsafe fn addr_info(addr: usize, info: *mut DlInfo, sym_out: *mut *const Sym, map_out: *mut *mut LinkMap) -> c_int {
    let m = map_of_addr(addr);
    if m.is_null() {
        return 0;
    }
    (*info).dli_fname = if (*m).is_main && !(*m).l_name.is_null() && cstr((*m).l_name).is_empty() { st().prog_name as *const c_char } else { (*m).l_name as *const c_char };
    (*info).dli_fbase = (*m).map_start as *mut c_void;
    (*info).dli_sname = null();
    (*info).dli_saddr = null_mut();
    if !map_out.is_null() {
        *map_out = m;
    }
    if !sym_out.is_null() {
        *sym_out = null();
    }
    if (*m).symtab.is_null() {
        return 1;
    }
    let n = symbol_count(m);
    let mut best: *const Sym = null();
    for i in 0..n {
        let s = (*m).symtab.add(i);
        let t = (*s).info & 0xf;
        let a = crate::lookup::sym_value_addr((*m).l_addr, s);
        if t == STT_TLS || addr < a {
            continue;
        }
        let exact_only = (*s).shndx == SHN_UNDEF || (*s).size == 0;
        if exact_only { if addr != a { continue; } } else if addr >= a + (*s).size as usize {
            continue;
        }
        if (*s).shndx == SHN_UNDEF && (*s).value == 0 {
            continue;
        }
        if best.is_null() || a > crate::lookup::sym_value_addr((*m).l_addr, best) || (a == crate::lookup::sym_value_addr((*m).l_addr, best) && (*s).info >> 4 == STB_GLOBAL && (*best).info >> 4 != STB_GLOBAL) {
            best = s;
        }
    }
    if !best.is_null() {
        (*info).dli_sname = (*m).strtab.add((*best).name as usize) as *const c_char;
        (*info).dli_saddr = crate::lookup::sym_value_addr((*m).l_addr, best) as *mut c_void;
        if !sym_out.is_null() {
            *sym_out = best;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr(addr: usize, info: *mut DlInfo) -> c_int {
    DL_LOCK.lock();
    let r = addr_info(addr, info, null_mut(), null_mut());
    DL_LOCK.unlock();
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr1(addr: usize, info: *mut DlInfo, extra: *mut *mut c_void, flags: c_int) -> c_int {
    DL_LOCK.lock();
    let mut sym: *const Sym = null();
    let mut map: *mut LinkMap = null_mut();
    let r = addr_info(addr, info, &mut sym, &mut map);
    if r != 0 && !extra.is_null() {
        match flags {
            1 => *extra = sym as *mut c_void,
            2 => *extra = map as *mut c_void,
            _ => {}
        }
    }
    DL_LOCK.unlock();
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void, _caller: usize) -> c_int {
    DL_LOCK.lock();
    let m = if handle.is_null() { st().main_map } else { handle as *mut LinkMap };
    let r = match request {
        1 => {
            *(arg as *mut c_int as *mut isize) = 0;
            0
        }
        2 => {
            *(arg as *mut *mut LinkMap) = m;
            0
        }
        4 | 5 => {
            serinfo(m, arg as *mut usize, request == 5);
            0
        }
        6 => {
            let o = origin_of(m);
            let dst = arg as *mut u8;
            core::ptr::copy_nonoverlapping(o.as_ptr(), dst, o.len());
            *dst.add(o.len()) = 0;
            0
        }
        9 => {
            *(arg as *mut usize) = (*m).tls_modid;
            0
        }
        10 => {
            let id = (*m).tls_modid;
            let mut p: usize = 0;
            if id != 0 && tls::ready() {
                let tp = sys::thread_pointer();
                let d = *((tp + 8) as *const usize) as *const tls::Dtv;
                if !d.is_null() && id <= (*d.sub(1)).val && (*d.add(id)).val != usize::MAX {
                    p = (*d.add(id)).val;
                }
            }
            *(arg as *mut usize) = p;
            0
        }
        11 => {
            *(arg as *mut *const Phdr) = (*m).phdr;
            (*m).phnum as c_int
        }
        _ => {
            fail(format_args!("unsupported dlinfo request"));
            -1
        }
    };
    if r >= 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r
}

unsafe fn each_dir(list: &[u8], ctx: *mut LinkMap, f: &mut dyn FnMut(&[u8])) {
    unsafe {
        let norm = |elem: &[u8], buf: &mut PathBuf| -> usize {
            let mut n = if elem.is_empty() { 0 } else { expand(elem, ctx, buf) };
            if n == 0 {
                *buf.ptr() = b'.';
                n = 1;
            }
            while n > 1 && *buf.ptr().add(n - 1) == b'/' {
                n -= 1;
            }
            n
        };
        let mut i = 0usize;
        for elem in list.split(|&c| c == b':') {
            let mut cur = PathBuf::new();
            let n = norm(elem, &mut cur);
            let me = core::slice::from_raw_parts(cur.ptr(), n);
            let mut dup = false;
            for prev in list.split(|&c| c == b':').take(i) {
                let mut pb = PathBuf::new();
                let pn = norm(prev, &mut pb);
                if core::slice::from_raw_parts(pb.ptr(), pn) == me {
                    dup = true;
                    break;
                }
            }
            if !dup {
                f(me);
            }
            i += 1;
        }
    }
}

unsafe fn serinfo(m: *mut LinkMap, si: *mut usize, counting: bool) {
    unsafe {
        let cnt_ptr = si.add(1) as *mut u32;
        if counting {
            *si = 0;
            *cnt_ptr = 0;
        }
        let ser = si.add(2);
        let mut alloc = (ser as *mut u8).add(*cnt_ptr as usize * 16);
        let mut idx = 0usize;
        let mut total = 0usize;
        let mut count = 0u32;
        let mut add = |name: &[u8]| {
            if counting {
                count += 1;
                total += (name.len() + 1).max(2);
            } else {
                let slot = ser.add(idx * 2);
                *slot = alloc as usize;
                core::ptr::copy_nonoverlapping(name.as_ptr(), alloc, name.len());
                *alloc.add(name.len()) = 0;
                alloc = alloc.add(name.len() + 1);
                *(slot.add(1) as *mut u32) = 0;
                idx += 1;
            }
        };
        let main = st().main_map;
        if (*m).runpath.is_null() {
            let mut l = m;
            while !l.is_null() {
                if l != main && !(*l).rpath.is_null() {
                    each_dir(cstr((*l).rpath), l, &mut add);
                }
                l = (*l).loader;
            }
        }
        if !st().library_path.is_null() {
            each_dir(cstr(st().library_path), main, &mut add);
        }
        if !(*m).runpath.is_null() {
            each_dir(cstr((*m).runpath), m, &mut add);
        }
        if (*m).flags_1 & 0x800 == 0 {
            add(b"/lib64");
            add(b"/usr/lib64");
        }
        if counting {
            *cnt_ptr = count;
            *si = total + 16 + count as usize * 16;
        }
    }
}

#[repr(C)]
pub struct DlPhdrInfo {
    pub dlpi_addr: u64,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const Phdr,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

type PhdrCb = unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_iterate_phdr(cb: Option<PhdrCb>, data: *mut c_void) -> c_int {
    let Some(cb) = cb else { return 0 };
    DL_LOCK.lock();
    let mut list: [*mut LinkMap; 1024] = [null_mut(); 1024];
    let mut n = 0;
    list[0] = st().main_map;
    n += 1;
    let mut cur = st().head;
    while !cur.is_null() && n < 1024 {
        if cur != st().main_map && !(*cur).unloading && !(*cur).is_ldso {
            list[n] = cur;
            n += 1;
        }
        cur = (*cur).l_next;
    }
    if !st().ldso_map.is_null() && n < 1024 {
        list[n] = st().ldso_map;
        n += 1;
    }
    let adds = ADDS;
    let subs = SUBS;
    DL_LOCK.unlock();
    let mut ret = 0;
    for &m in &list[..n] {
        let id = (*m).tls_modid;
        let mut tlsdata: usize = 0;
        if id != 0 && tls::ready() {
            let tp = sys::thread_pointer();
            let d = *((tp + 8) as *const usize) as *const tls::Dtv;
            if !d.is_null() && id <= (*d.sub(1)).val && (*d.add(id)).val != usize::MAX {
                tlsdata = (*d.add(id)).val;
            }
        }
        let mut info = DlPhdrInfo {
            dlpi_addr: (*m).l_addr as u64,
            dlpi_name: (*m).l_name as *const c_char,
            dlpi_phdr: (*m).phdr,
            dlpi_phnum: (*m).phnum as u16,
            dlpi_adds: adds,
            dlpi_subs: subs,
            dlpi_tls_modid: id,
            dlpi_tls_data: tlsdata as *mut c_void,
        };
        ret = cb(&mut info, core::mem::size_of::<DlPhdrInfo>(), data);
        if ret != 0 {
            break;
        }
    }
    ret
}

#[repr(C)]
pub struct DlFindObject {
    pub dlfo_flags: u64,
    pub dlfo_map_start: *mut c_void,
    pub dlfo_map_end: *mut c_void,
    pub dlfo_link_map: *mut LinkMap,
    pub dlfo_eh_frame: *mut c_void,
    pub reserved: [u64; 7],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_find_object(pc: usize, result: *mut DlFindObject) -> c_int {
    let m = map_of_addr(pc);
    if m.is_null() {
        return -1;
    }
    *result = DlFindObject {
        dlfo_flags: 0,
        dlfo_map_start: (*m).map_start as *mut c_void,
        dlfo_map_end: (*m).map_end as *mut c_void,
        dlfo_link_map: m,
        dlfo_eh_frame: (*m).eh_frame_hdr as *mut c_void,
        reserved: [0; 7],
    };
    0
}

const SPROF: c_int = 0x4000_0000;
const SH_SIZE: usize = 1024;
const SH_INFO: usize = 64;
const SH_NINFO: usize = 84;
const SH_PHDR: usize = 736;
const SH_ENTRY: usize = 744;
const SH_PHNUM: usize = 752;
const SH_FLAGS: usize = 852;
const SH_MAP_START: usize = 912;
const SH_MAP_END: usize = 920;
const SH_OURS: usize = 960;
const SH_MAP: usize = 968;
const SH_FRESH: usize = 976;
static mut SPROF_HANDLES: [*mut u8; 16] = [null_mut(); 16];

fn l_info_index(t: u64) -> Option<usize> {
    if t < 38 {
        Some(t as usize)
    } else if (0x7000_0000..0x7000_0004).contains(&t) {
        Some(38 + (t - 0x7000_0000) as usize)
    } else if (0x6fff_fff0..=0x6fff_ffff).contains(&t) {
        Some(42 + (0x6fff_ffff - t) as usize)
    } else if (0x7fff_fffd..=0x7fff_ffff).contains(&t) {
        Some(58 + (0x7fff_ffff - t) as usize)
    } else if (0x6fff_fdf5..=0x6fff_fdff).contains(&t) {
        Some(61 + (0x6fff_fdff - t) as usize)
    } else if (0x6fff_fef5..=0x6fff_feff).contains(&t) {
        Some(73 + (0x6fff_feff - t) as usize)
    } else {
        None
    }
}

unsafe fn sprof_open(name: &[u8], requester: *mut LinkMap) -> *mut LinkMap {
    let s = st();
    let tail_before = s.tail;
    let m = load_library(name, requester);
    if m.is_null() {
        return null_mut();
    }
    let fresh = s.tail != tail_before;
    let mut slot = usize::MAX;
    for i in 0..16 {
        if SPROF_HANDLES[i].is_null() {
            slot = i;
            break;
        }
    }
    let h = alloc_blk(SH_SIZE, 16);
    if slot == usize::MAX || h.is_null() {
        if fresh {
            drop_map(m);
        }
        set_error(format_args!("cannot allocate memory"));
        return null_mut();
    }
    let w = |off: usize, v: usize| *(h.add(off) as *mut usize) = v;
    w(0, (*m).l_addr);
    w(8, (*m).l_name as usize);
    w(16, (*m).l_ld as usize);
    w(40, h as usize);
    let mut d = (*m).l_ld;
    while (*d).tag != DT_NULL {
        if let Some(i) = l_info_index((*d).tag as u64) {
            if i < SH_NINFO {
                w(SH_INFO + 8 * i, d as usize);
            }
        }
        d = d.add(1);
    }
    w(SH_PHDR, (*m).phdr as usize);
    w(SH_ENTRY, (*m).entry);
    *(h.add(SH_PHNUM) as *mut u16) = (*m).phnum as u16;
    *(h.add(SH_FLAGS) as *mut u8) = 2;
    if !(*m).dyn_adjusted {
        *h.add(SH_FLAGS + 2) = 0x20;
    }
    w(SH_MAP_START, (*m).map_start);
    w(SH_MAP_END, (*m).map_end);
    w(SH_OURS, 0x5350_524f_4648_444c);
    w(SH_MAP, m as usize);
    w(SH_FRESH, fresh as usize);
    SPROF_HANDLES[slot] = h;
    h as *mut LinkMap
}

unsafe fn sprof_is_handle(h: *mut c_void) -> bool {
    !h.is_null() && SPROF_HANDLES.contains(&(h as *mut u8))
}

unsafe fn sprof_close(h: *mut c_void) {
    let h = h as *mut u8;
    let m = *(h.add(SH_MAP) as *const usize) as *mut LinkMap;
    let fresh = *(h.add(SH_FRESH) as *const usize) != 0;
    for i in 0..16 {
        if SPROF_HANDLES[i] == h {
            SPROF_HANDLES[i] = null_mut();
        }
    }
    free_blk(h, SH_SIZE, 16);
    if fresh && !(*m).relocated {
        drop_map(m);
    }
}

unsafe fn add_extra_scope(d: *mut LinkMap, root: *mut LinkMap) {
    unsafe {
        let mut list: [*mut LinkMap; 512] = [null_mut(); 512];
        let mut n = 0;
        let have = |l: &[*mut LinkMap], m: *mut LinkMap| l.contains(&m);
        let own: &[*mut LinkMap] = if (*d).scope.is_null() { &[] } else { core::slice::from_raw_parts((*d).scope, (*d).nscope) };
        if !(*d).xscope.is_null() {
            for i in 0..(*d).nxscope {
                if n < 512 {
                    list[n] = *(*d).xscope.add(i);
                    n += 1;
                }
            }
        }
        let before = n;
        for i in 0..(*root).nscope {
            let m = *(*root).scope.add(i);
            if !have(own, m) && !have(&list[..n], m) && n < 512 {
                list[n] = m;
                n += 1;
            }
        }
        if n == before {
            return;
        }
        let arr = crate::alloc_perm(n * 8, 8) as *mut *mut LinkMap;
        core::ptr::copy_nonoverlapping(list.as_ptr(), arr, n);
        (*d).xscope = arr;
        (*d).nxscope = n;
    }
}
