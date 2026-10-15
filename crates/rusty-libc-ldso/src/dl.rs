#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::ffi::{CStrRef, cstr, cstr_opt};
use crate::lookup::*;
use crate::map::*;
use crate::reloc;
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::tls;
use crate::util::*;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub const RTLD_NOLOAD: c_int = 0x4;
pub const RTLD_DEEPBIND: c_int = 0x8;
pub const RTLD_GLOBAL: c_int = 0x100;
pub const RTLD_NODELETE: c_int = 0x1000;

static DL_LOCK: Lock = Lock::new();

pub(crate) fn fork_child_reset() {
    DL_LOCK.reset();
}
static ADDS: AtomicU64 = AtomicU64::new(1);
static SUBS: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
pub struct ErrBuf {
    state: u8,
    code: c_int,
    obj_len: usize,
    msg_len: usize,
    inline: [u8; 512],
    ext: *mut u8,
    ext_cap: usize,
}
pub const DL_ERROR_SLOT: usize = 0x80;
pub const ERRBUF_SIZE: usize = core::mem::size_of::<ErrBuf>();
static EARLY_ERR: SyncCell<ErrBuf> = SyncCell::new(ErrBuf { state: 0, code: 0, obj_len: 0, msg_len: 0, inline: [0; 512], ext: null_mut(), ext_cap: 0 });

impl ErrBuf {
    fn cap(&self) -> usize {
        if self.ext.is_null() { 512 } else { self.ext_cap }
    }
    fn rec_len(&self) -> usize {
        self.obj_len + 1 + self.msg_len + 1
    }
    fn data(&mut self) -> &mut [u8] {
        if self.ext.is_null() {
            &mut self.inline
        } else {
            unsafe { crate::ffi::slice_mut(self.ext, self.ext_cap) }
        }
    }
    fn data_ptr(&mut self) -> *mut u8 {
        if self.ext.is_null() { self.inline.as_mut_ptr() } else { self.ext }
    }
    fn reserve(&mut self, need: usize, keep: usize) -> bool {
        if need <= self.cap() {
            return true;
        }
        let c = need.next_power_of_two();
        let p = alloc_blk(c, 16);
        if p.is_null() {
            return false;
        }
        let dst = unsafe { crate::ffi::slice_mut(p, c) };
        dst[..keep].copy_from_slice(&self.data()[..keep]);
        self.set_ext(p, c);
        true
    }
    fn set_ext(&mut self, p: *mut u8, c: usize) {
        if !self.ext.is_null() {
            unsafe { free_blk(self.ext, self.ext_cap, 16) };
        }
        self.ext = p;
        self.ext_cap = c;
    }
}

pub unsafe fn free_errbuf(p: *mut u8) {
    let b = p as *mut ErrBuf;
    let b = unsafe { &mut *b };
    if !b.ext.is_null() {
        unsafe { free_blk(b.ext, b.ext_cap, 16) };
    }
    unsafe { free_blk(p, ERRBUF_SIZE, 16) };
}

unsafe fn err_buf<'a>() -> Option<&'a mut ErrBuf> {
    if !tls::ready() {
        return Some(unsafe { &mut *EARLY_ERR.as_ptr() });
    }
    let slot = (sys::thread_pointer() + DL_ERROR_SLOT) as *mut usize;
    let mut p = unsafe { *slot } as *mut ErrBuf;
    if p.is_null() {
        p = alloc_blk(ERRBUF_SIZE, 16) as *mut ErrBuf;
        if p.is_null() {
            return None;
        }
        unsafe { *slot = p as usize };
    }
    Some(unsafe { &mut *p })
}

type MsgWriter<'a> = &'a dyn Fn(&mut dyn FnMut(&[u8]));

fn record(obj: &[u8], code: c_int, msg: MsgWriter) {
    let Some(b) = (unsafe { err_buf() }) else { return };
    let mut mlen = 0usize;
    msg(&mut |p: &[u8]| mlen += p.len());
    let (mut olen, mut mlen) = (obj.len(), mlen);
    if !b.reserve(olen + mlen + 2, 0) {
        olen = olen.min(255);
        mlen = mlen.min(b.cap() - olen - 2);
    }
    let d = b.data();
    d[..olen].copy_from_slice(&obj[..olen]);
    d[olen] = 0;
    let mut at = 0usize;
    msg(&mut |p: &[u8]| {
        let n = p.len().min(mlen - at);
        d[olen + 1 + at..olen + 1 + at + n].copy_from_slice(&p[..n]);
        at += n;
    });
    d[olen + 1 + mlen] = 0;
    b.obj_len = olen;
    b.msg_len = mlen;
    b.code = code;
    b.state = 1;
}

fn publish_error() {
    let m = error_msg();
    record(error_obj(), error_code(), &|out: &mut dyn FnMut(&[u8])| out(m));
}

fn fail_at(obj: &[u8], code: c_int, args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct W<'a>(&'a mut dyn FnMut(&[u8]));
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            (self.0)(s.as_bytes());
            Ok(())
        }
    }
    record(obj, code, &|out: &mut dyn FnMut(&[u8])| {
        let _ = W(out).write_fmt(args);
    });
}

fn fail(args: core::fmt::Arguments) {
    fail_at(b"", 0, args)
}

fn succeed() {
    if let Some(b) = unsafe { err_buf() }
        && b.state == 1
    {
        b.state = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlerror_record(obj: *mut *const c_char, msg: *mut *const c_char, code: *mut c_int) -> c_int {
    let Some(b) = (unsafe { err_buf() }) else { return 0 };
    if b.state != 1 {
        b.state = 0;
        return 0;
    }
    let d = b.data_ptr();
    unsafe { *obj = d as *const c_char };
    unsafe { *msg = d.wrapping_add(b.obj_len + 1) as *const c_char };
    unsafe { *code = b.code };
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlerror_compose(pieces: *const (*const u8, usize), n: usize) -> *const c_char {
    let Some(b) = (unsafe { err_buf() }) else { return c"out of memory".as_ptr() };
    let parts = unsafe { crate::ffi::slice(pieces, n) };
    let total: usize = parts.iter().map(|p| p.1).sum();
    let rl = b.rec_len();
    b.state = 2;
    if total + 1 + rl > b.cap() {
        let c = (total + 1 + rl).next_power_of_two();
        let p = alloc_blk(c, 16);
        if p.is_null() {
            return b.data_ptr().wrapping_add(b.obj_len + 1) as *const c_char;
        }
        unsafe { core::ptr::copy_nonoverlapping(b.data_ptr(), p, rl) };
        let mut at = rl;
        for &(q, l) in parts {
            unsafe { core::ptr::copy_nonoverlapping(q, p.wrapping_add(at), l) };
            at += l;
        }
        unsafe { *p.wrapping_add(at) = 0 };
        b.set_ext(p, c);
        return p.wrapping_add(rl) as *const c_char;
    }
    let d = b.data_ptr();
    let mut at = rl;
    for &(q, l) in parts {
        unsafe { core::ptr::copy(q, d.wrapping_add(at), l) };
        at += l;
    }
    unsafe { *d.wrapping_add(at) = 0 };
    d.wrapping_add(rl) as *const c_char
}

pub fn map_of_addr(addr: usize) -> Option<Map> {
    (0..st().nns).find_map(|n| ns(n).maps().find(|c| !c.unloading() && addr >= c.map_start() && addr < c.map_end()))
}

fn object_name(m: Map) -> &'static [u8] {
    let n = m.name();
    if n.is_empty() { reloc::prog_name() } else { n }
}

fn load_deps_new(first: Option<Map>) -> bool {
    let mut cur = first;
    while let Some(m) = cur {
        if !m.is_ldso() && m.needed_ptr().is_null() && !crate::load_needed(m, true, |_| {}) {
            return false;
        }
        cur = m.next();
    }
    true
}

#[cold]
#[inline(never)]
pub fn discard_from(first: Option<Map>) {
    let mut list: [Option<Map>; 256] = [None; 256];
    let mut n = 0;
    for m in MapIter(first) {
        if n == 256 {
            break;
        }
        list[n] = Some(m);
        n += 1;
    }
    for m in list[..n].iter().flatten() {
        drop_map(*m);
    }
}

fn drop_map(m: Map) {
    m.set_unloading(true);
    m.set_removed(true);
    ns(m.l_ns() as usize).remove_global(m);
    m.set_in_global(false);
    tls::remove_module(m);
    unlink_map(m);
    if m.real() != Some(m) {
        return;
    }
    if !m.plt_cache().is_null() {
        let n = (m.pltrelsz() / core::mem::size_of::<Rela>()).max(1) * crate::plt::SLOT_SIZE;
        unsafe { sys::munmap(m.plt_cache() as usize, n) };
        unsafe { m.set_plt_cache(null_mut()) };
    }
    unsafe { sys::munmap(m.map_start(), m.map_end() - m.map_start()) };
}

pub fn new_namespace() -> Option<usize> {
    let s = st();
    let mut n = 1;
    while n < s.nns && ns(n).head.is_some() {
        n += 1;
    }
    if n == DL_NNS {
        return None;
    }
    if n == s.nns {
        s.nns += 1;
    }
    Some(n)
}

pub const LM_ID_BASE: isize = 0;
pub const LM_ID_NEWLM: isize = -1;
pub const LM_ID_CALLER: isize = -2;

enum Opened {
    Map(Map),
    Sprof(*mut u8),
}

fn open_object(lmid: isize, name: Option<&[u8]>, mode: c_int, caller: usize) -> Option<Opened> {
    let s = st();
    let Some(name) = name.filter(|n| !n.is_empty()) else { return s.main_map.map(Opened::Map) };
    let requester = map_of_addr(caller);
    let nsid = if lmid == LM_ID_NEWLM {
        let Some(n) = new_namespace() else {
            set_error_at(name, 22, format_args!("no more namespaces available for dlmopen()"));
            return None;
        };
        n
    } else if lmid == LM_ID_CALLER {
        ns_of(requester)
    } else if lmid == LM_ID_BASE {
        0
    } else if lmid < 0 || lmid as usize >= s.nns || ns(lmid as usize).head.is_none() || crate::audit::is_audit_ns(lmid as usize) {
        set_error_at(name, 22, format_args!("invalid target namespace in dlmopen()"));
        return None;
    } else {
        lmid as usize
    };
    if lmid == LM_ID_NEWLM {
        crate::debug_change_state(crate::debug_update(nsid), crate::RT_CONSISTENT);
    }
    crate::debug_initialize(nsid);
    let r = if mode & SPROF != 0 { sprof_open(name, requester).map(Opened::Sprof) } else { open_in(nsid, requester, name, mode).map(Opened::Map) };
    if r.is_none() {
        trim_nns();
    }
    r
}

fn open_in(nsid: usize, requester: Option<Map>, name: &[u8], mode: c_int) -> Option<Map> {
    let s = st();
    if mode & RTLD_NOLOAD != 0 {
        let m = find_loaded(nsid, name).or_else(|| find_loaded_by_file(nsid, name, requester));
        if let Some(m) = m {
            if mode & RTLD_GLOBAL != 0 {
                promote_global(m);
            }
            m.set_refcount(m.refcount() + 1);
        } else if !library_exists(nsid, name, requester) {
            set_error_at(name, 2, format_args!("cannot open shared object file"));
        }
        return m;
    }
    let tail_before = ns(nsid).tail;
    let after = |t: Option<Map>| match t {
        None => ns(nsid).head,
        Some(t) => t.next(),
    };
    let Some(root) = load_library(nsid, name, requester) else {
        discard_from(after(tail_before));
        return None;
    };
    let first_new = after(tail_before);
    if root.opening() && first_new.is_none() {
        if mode & RTLD_GLOBAL != 0 {
            promote_global(root);
        }
        root.set_refcount(root.refcount() + 1);
        return Some(root);
    }
    if Some(root) == s.main_map {
        set_error_at(name, 0, format_args!("cannot dynamically load {}", if root.flags_1() & 0x0800_0000 != 0 { "position-independent executable" } else { "executable" }));
        return None;
    }
    if root.flags_1() & 0x0800_0000 != 0 {
        set_error_at(name, 0, format_args!("cannot dynamically load position-independent executable"));
        discard_from(first_new);
        return None;
    }
    if !load_deps_new(first_new) {
        discard_from(first_new);
        return None;
    }
    if root.flags_1() & 0x40 != 0 || MapIter(first_new).any(|c| c.flags_1() & 0x40 != 0) {
        set_error_at(name, 0, format_args!("shared object cannot be dlopen()ed"));
        discard_from(first_new);
        return None;
    }
    for cur in MapIter(first_new) {
        if !crate::check_map_versions(cur) {
            discard_from(first_new);
            return None;
        }
    }
    if root.scope_ptr().is_null() {
        crate::build_scope(root);
    }
    for &d in root.scope() {
        let is_new = MapIter(first_new).any(|c| c == d);
        if is_new || d.in_global() || d == root {
            continue;
        }
        add_extra_scope(d, root);
    }
    for cur in MapIter(first_new) {
        cur.set_dlopened(true);
        cur.set_opening(true);
        if cur.scope_ptr().is_null() {
            unsafe { cur.set_scope(root.scope_ptr()) };
            unsafe { cur.set_nscope(root.nscope()) };
        }
        if mode & RTLD_DEEPBIND != 0 {
            cur.set_deepbind(true);
        }
        if mode & 0x2 != 0 && !crate::profile::enabled() {
            cur.set_bind_now(true);
            cur.set_rtld_now(true);
        }
    }
    for cur in MapIter(first_new) {
        if !tls::add_module(cur, false) || (cur.flags() & DF_STATIC_TLS != 0 && !tls::add_static_late(cur)) {
            set_error_at(object_name(cur), 0, format_args!("cannot allocate memory in static TLS block"));
            discard_from(first_new);
            return None;
        }
    }
    if mode & RTLD_GLOBAL != 0 {
        promote_global(root);
    }
    let ok = if MapIter(first_new).nth(32).is_none() { finish::<32>(nsid, root, first_new, mode) } else { finish_big(nsid, root, first_new, mode) };
    if !ok {
        return None;
    }
    crate::init_tree(root, false);
    Some(root)
}

#[inline(never)]
fn finish_big(nsid: usize, root: Map, first_new: Option<Map>, mode: c_int) -> bool {
    finish::<256>(nsid, root, first_new, mode)
}

fn finish<const N: usize>(nsid: usize, root: Map, first_new: Option<Map>, mode: c_int) -> bool {
    let mut list: [Option<Map>; N] = [None; N];
    let mut n = 0;
    for cur in MapIter(first_new) {
        if n == N {
            break;
        }
        list[n] = Some(cur);
        n += 1;
    }
    let list = &list[..n];
    let rd = crate::debug_update(nsid);
    crate::debug_change_state(rd, crate::RT_ADD);
    crate::audit::activity_ns(nsid, crate::audit::LA_ACT_ADD);
    for m in list.iter().flatten() {
        crate::audit::objopen(*m);
    }
    for m in list.iter().rev().flatten() {
        if !unsafe { reloc::relocate(*m) } {
            discard_from(first_new);
            crate::debug_change_state(rd, crate::RT_CONSISTENT);
            crate::audit::activity_ns(nsid, crate::audit::LA_ACT_CONSISTENT);
            return false;
        }
    }
    crate::profile::start();
    if nsid != 0
        && let Some(lm) = ns(nsid).libc_map.filter(|lm| list.contains(&Some(*lm)))
    {
        call_libc_early_init(lm, false);
    }
    for m in list.iter().flatten() {
        protect_relro(*m);
        ADDS.store(ADDS.load(Relaxed) + 1, Relaxed);
        for &d in m.needed() {
            d.set_refcount(d.refcount() + 1);
        }
    }
    if mode & RTLD_NODELETE != 0 {
        root.set_nodelete(true);
    }
    root.set_refcount(root.refcount() + 1);
    crate::debug_change_state(rd, crate::RT_CONSISTENT);
    crate::audit::activity_ns(nsid, crate::audit::LA_ACT_CONSISTENT);
    for cur in MapIter(first_new) {
        cur.set_opening(false);
    }
    true
}

pub fn call_libc_early_init(libc: Map, initial: bool) {
    let fl = Flags { plt: false, skip: None, newest: false };
    if let Some(f) = lookup(b"__libc_early_init", None, &[&[libc]], &fl) {
        let f: extern "C" fn(bool) = unsafe { core::mem::transmute(sym_addr(&f)) };
        f(initial);
    }
}

fn promote_global(m: Map) {
    if m.scope_ptr().is_null() {
        crate::build_scope(m);
    }
    for &d in m.scope() {
        if !d.is_ldso() && !d.in_global() && ns(m.l_ns() as usize).push_global(d) {
            d.set_in_global(true);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlopen(file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    unsafe { dlmopen_impl(LM_ID_CALLER, file, mode, caller, env) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlmopen(lmid: isize, file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    unsafe { dlmopen_impl(lmid, file, mode, caller, env) }
}

unsafe fn dlmopen_impl(lmid: isize, file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    let file = unsafe { cstr_opt(file) };
    if mode & !(0x3 | RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_GLOBAL | RTLD_NODELETE | 0x4000_0000) != 0 {
        fail(format_args!("invalid mode parameter"));
        return null_mut();
    }
    if mode & 0x3 == 0 {
        fail_at(file.unwrap_or(b""), 22, format_args!("invalid mode for dlopen()"));
        return null_mut();
    }
    DL_LOCK.lock();
    set_error(format_args!(""));
    let outer_env = crate::init_env_swap(env);
    let r = open_object(lmid, file, mode, caller);
    crate::init_env_swap(outer_env);
    match r {
        None => {
            if st().error_len != 0 {
                publish_error();
            }
        }
        Some(_) => succeed(),
    }
    DL_LOCK.unlock();
    match r {
        None => null_mut(),
        Some(Opened::Map(m)) => m.as_ptr() as *mut c_void,
        Some(Opened::Sprof(h)) => h as *mut c_void,
    }
}

fn needs(from: Map, to: Map) -> bool {
    match needs_in::<32>(from, to) {
        Some(r) => r,
        None => needs_big(from, to),
    }
}

#[inline(never)]
fn needs_big(from: Map, to: Map) -> bool {
    needs_in::<256>(from, to).unwrap_or(false)
}

#[inline(always)]
fn needs_in<const N: usize>(from: Map, to: Map) -> Option<bool> {
    let small = N < 256;
    let mut stack: [Option<Map>; N] = [None; N];
    let mut seen: [Option<Map>; N] = [None; N];
    let (mut sp, mut ns) = (0usize, 0usize);
    stack[0] = Some(from);
    sp += 1;
    while sp > 0 {
        sp -= 1;
        let m = stack[sp];
        if m == Some(to) {
            return Some(true);
        }
        if seen[..ns].contains(&m) {
            continue;
        }
        if ns >= N {
            if small {
                return None;
            }
            continue;
        }
        seen[ns] = m;
        ns += 1;
        if let Some(m) = m {
            for &d in m.needed() {
                if sp < N {
                    stack[sp] = Some(d);
                    sp += 1;
                } else if small {
                    return None;
                }
            }
        }
    }
    Some(false)
}

pub fn note_binding(undef: Option<Map>, def: Option<Map>) {
    let (Some(undef), Some(def)) = (undef, def) else { return };
    if def == undef || !def.dlopened() || def.nodelete() {
        return;
    }
    DL_LOCK.lock();
    if !def.nodelete() && !needs(undef, def) {
        if !undef.dlopened() {
            def.set_nodelete(true);
        } else if !undef.reldeps().contains(&def) {
            if undef.nreldeps() == undef.creldeps() {
                let nc = if undef.creldeps() == 0 { 8 } else { undef.creldeps() * 2 };
                let nb = alloc_perm(nc * core::mem::size_of::<usize>(), 8) as *mut *mut LinkMap;
                let dst = unsafe { crate::ffi::slice_mut(nb as *mut Option<Map>, nc) };
                for (k, &r) in undef.reldeps().iter().enumerate() {
                    dst[k] = Some(r);
                }
                unsafe { undef.set_reldeps(nb) };
                unsafe { undef.set_creldeps(nc) };
            }
            let k = undef.nreldeps();
            unsafe { *undef.reldeps_ptr().wrapping_add(k) = def.as_ptr() };
            unsafe { undef.set_nreldeps(k + 1) };
            def.set_refcount(def.refcount() + 1);
        }
    }
    DL_LOCK.unlock();
}

fn release(m: Map) {
    if m.refcount() > 0 {
        m.set_refcount(m.refcount() - 1);
    }
    if m.is_ldso() && m.real() != Some(m) {
        if m.refcount() == 0 && !m.unloading() {
            crate::audit::close_one(m);
            drop_map(m);
        }
        return;
    }
    if m.refcount() > 0 || m.nodelete() || m.is_main() || m.is_ldso() || m.unloading() || m.tls_dtor_count() > 0 {
        return;
    }
    m.set_unloading(true);
    let rd = crate::debug_update(m.l_ns() as usize);
    crate::debug_change_state(rd, crate::RT_DELETE);
    if m.init_called() {
        crate::run_fini(m);
    }
    crate::audit::close_one(m);
    for &d in m.needed() {
        release(d);
    }
    for &d in m.reldeps() {
        release(d);
    }
    m.set_unloading(false);
    m.set_removed(true);
    drop_map(m);
    SUBS.store(SUBS.load(Relaxed) + 1, Relaxed);
    crate::debug_change_state(rd, crate::RT_CONSISTENT);
}

fn release_kept(nsid: usize) {
    while let Some(m) = ns(nsid).maps().find(|c| {
        c.dlopened() && c.refcount() == 0 && c.tls_dtor_count() == 0 && !c.nodelete() && !c.unloading() && !c.opening() && !c.is_ldso()
    }) {
        release(m);
        if !m.removed() {
            break;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_tls_dtor_ref(dso: usize, delta: isize) {
    DL_LOCK.lock();
    if let Some(m) = map_of_addr(dso).filter(|m| m.dlopened()) {
        m.set_tls_dtor_count(m.tls_dtor_count().saturating_add_signed(delta));
    }
    DL_LOCK.unlock();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlclose(handle: *mut c_void) -> c_int {
    DL_LOCK.lock();
    if sprof_is_handle(handle) {
        unsafe { sprof_close(handle as *mut u8) };
        succeed();
        DL_LOCK.unlock();
        return 0;
    }
    let p = handle as *mut LinkMap;
    let r = if p.is_null() || p == Map::opt_ptr(st().main_map) {
        succeed();
        0
    } else {
        let found = (0..st().nns).find_map(|n| ns(n).maps().find(|c| c.as_ptr() == p && !c.unloading()));
        match found {
            None => {
                fail(format_args!("invalid handle"));
                -1
            }
            Some(m) => {
                release(m);
                release_kept(m.l_ns() as usize);
                crate::audit::close_done();
                succeed();
                0
            }
        }
    };
    DL_LOCK.unlock();
    r
}

fn tls_symbol_address(f: &Found) -> usize {
    let ti = tls::TlsIndex { module: f.map.tls_modid(), offset: f.sym.value as usize };
    unsafe { tls::__tls_get_addr(&ti) }
}

#[derive(Clone, Copy)]
pub enum Handle {
    Default,
    Next,
    Map(Map),
}

pub fn symbol_lookup(handle: Handle, name: &[u8], ver: Option<&VerRef>, caller: usize) -> usize {
    let s = st();
    let caller_map = match handle {
        Handle::Default | Handle::Next => map_of_addr(caller),
        Handle::Map(_) => None,
    };
    let g = ns(ns_of(caller_map)).scope();
    let fl = Flags { plt: false, skip: None, newest: ver.is_none() };
    let found: Option<Found>;
    let where_: Option<Map>;
    match handle {
        Handle::Default => {
            let own: &[Map] = match caller_map {
                Some(c) if !c.in_global() => c.scope(),
                _ => &[],
            };
            found = lookup(name, ver, &[g, own], &fl);
            where_ = None;
            if let Some(f) = &found {
                note_binding(caller_map.or(s.main_map), Some(f.map));
            }
        }
        Handle::Next => {
            let Some(c) = caller_map else {
                fail(format_args!("RTLD_NEXT used in code not dynamically loaded"));
                return 0;
            };
            let after = |list: &'static [Map]| list.iter().position(|&m| m == c).map(|i| &list[i + 1..]);
            let cap = |list: &'static [Map], room: usize| &list[..list.len().min(room)];
            let (first, second): (&[Map], &[Map]) = match after(g) {
                Some(rest) => (cap(rest, 1024), &[]),
                None if !c.scope_ptr().is_null() => match after(c.scope()) {
                    Some(rest) => {
                        let rest = cap(rest, 1024);
                        (rest, cap(g, 1024 - rest.len()))
                    }
                    None => (&[], cap(g, 1024)),
                },
                None => (&[], &[]),
            };
            found = lookup(name, ver, &[first, second], &fl);
            where_ = None;
            if let Some(f) = &found {
                note_binding(Some(c), Some(f.map));
            }
        }
        Handle::Map(m) => {
            if Some(m) == s.main_map {
                found = lookup(name, ver, &[ns(0).scope()], &fl);
            } else {
                if m.scope_ptr().is_null() {
                    crate::build_scope(m);
                }
                found = lookup(name, ver, &[m.scope()], &fl);
            }
            where_ = Some(m);
        }
    }
    match found {
        Some(f) => {
            let t = f.sym.info & 0xf;
            if t == STT_TLS {
                return tls_symbol_address(&f);
            }
            let a = sym_addr(&f);
            let a = if t == STT_GNU_IFUNC { unsafe { reloc::call_resolver(a) } } else { a };
            if crate::audit::active() { crate::audit::symbind_dlsym(map_of_addr(caller), f.sym, f.map, name, a) } else { a }
        }
        None => {
            let vtext: &[u8] = match ver {
                Some(v) => v.name.bytes(),
                None => b"",
            };
            let who: &[u8] = match where_ {
                Some(m) if Some(m) != s.main_map => object_name(m),
                _ => reloc::prog_name(),
            };
            if ver.is_some() {
                fail_at(who, 0, format_args!("undefined symbol: {}, version {}", Bytes(name), Bytes(vtext)));
            } else {
                fail_at(who, 0, format_args!("undefined symbol: {}", Bytes(name)));
            }
            0
        }
    }
}

unsafe fn handle_of(handle: *mut c_void) -> Handle {
    match handle as usize {
        0 => Handle::Default,
        usize::MAX => Handle::Next,
        _ => match unsafe { Map::from_ptr(handle as *mut LinkMap) } {
            Some(m) => Handle::Map(m),
            None => Handle::Default,
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlsym(handle: *mut c_void, name: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    let h = unsafe { handle_of(handle) };
    let r = symbol_lookup(h, unsafe { cstr(name) }, None, caller);
    if r != 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlvsym(handle: *mut c_void, name: *const u8, version: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    let v = if version.is_null() {
        None
    } else {
        let vs = unsafe { CStrRef::new(version) };
        Some(VerRef { name: vs, hash: elf_hash(vs.bytes()), file: None, hidden: true })
    };
    let h = unsafe { handle_of(handle) };
    let r = symbol_lookup(h, unsafe { cstr(name) }, v.as_ref(), caller);
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

fn symbol_count(m: Map) -> usize {
    if m.gnu_nbuckets() != 0 {
        let max = m.gnu_bucket_words().iter().copied().max().unwrap_or(0);
        if max < m.gnu_symoffset() {
            return m.gnu_symoffset() as usize;
        }
        let mut i = max;
        loop {
            let ch = unsafe { *m.gnu_chain().wrapping_add((i - m.gnu_symoffset()) as usize) };
            if ch & 1 != 0 {
                break;
            }
            i += 1;
        }
        return i as usize + 1;
    }
    m.hash_nchain() as usize
}

struct AddrInfo {
    map: Map,
    fname: *const c_char,
    sym: Option<&'static Sym>,
}

fn addr_info(addr: usize) -> Option<AddrInfo> {
    let m = map_of_addr(addr)?;
    let fname = if m.is_main() && !m.l_name().is_null() && m.name().is_empty() { st().prog_name as *const c_char } else { m.l_name() as *const c_char };
    let mut info = AddrInfo { map: m, fname, sym: None };
    if m.symtab().is_null() {
        return Some(info);
    }
    let n = symbol_count(m);
    let mut best: Option<&'static Sym> = None;
    for i in 0..n {
        let s = unsafe { m.sym(i) };
        let t = s.info & 0xf;
        let a = sym_value_addr(m.l_addr(), s);
        if t == STT_TLS || addr < a {
            continue;
        }
        let exact_only = s.shndx == SHN_UNDEF || s.size == 0;
        if exact_only {
            if addr != a {
                continue;
            }
        } else if addr >= a + s.size as usize {
            continue;
        }
        if s.shndx == SHN_UNDEF && s.value == 0 {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => {
                let ba = sym_value_addr(m.l_addr(), b);
                a > ba || (a == ba && s.info >> 4 == STB_GLOBAL && b.info >> 4 != STB_GLOBAL)
            }
        };
        if better {
            best = Some(s);
        }
    }
    info.sym = best;
    Some(info)
}

fn fill_dlinfo(i: &AddrInfo, out: &mut DlInfo) {
    out.dli_fname = i.fname;
    out.dli_fbase = i.map.map_start() as *mut c_void;
    match i.sym {
        Some(s) => {
            out.dli_sname = i.map.sym_name(s).as_ptr() as *const c_char;
            out.dli_saddr = sym_value_addr(i.map.l_addr(), s) as *mut c_void;
        }
        None => {
            out.dli_sname = null();
            out.dli_saddr = null_mut();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr(addr: usize, info: *mut DlInfo) -> c_int {
    DL_LOCK.lock();
    let r = match addr_info(addr) {
        None => 0,
        Some(i) => {
            fill_dlinfo(&i, unsafe { &mut *info });
            1
        }
    };
    DL_LOCK.unlock();
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr1(addr: usize, info: *mut DlInfo, extra: *mut *mut c_void, flags: c_int) -> c_int {
    DL_LOCK.lock();
    let r = match addr_info(addr) {
        None => 0,
        Some(i) => {
            fill_dlinfo(&i, unsafe { &mut *info });
            if let Some(e) = unsafe { crate::ffi::out(extra) } {
                match flags {
                    1 => *e = i.sym.map_or(null(), |s| s as *const Sym) as *mut c_void,
                    2 => *e = i.map.as_ptr() as *mut c_void,
                    _ => {}
                }
            }
            1
        }
    };
    DL_LOCK.unlock();
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void, _caller: usize) -> c_int {
    DL_LOCK.lock();
    let m = if handle.is_null() {
        main_map()
    } else {
        match unsafe { Map::from_ptr(handle as *mut LinkMap) } {
            Some(m) => m,
            None => main_map(),
        }
    };
    let r = match request {
        1 => {
            unsafe { *(arg as *mut isize) = m.l_ns() };
            0
        }
        2 => {
            unsafe { *(arg as *mut *mut LinkMap) = m.as_ptr() };
            0
        }
        4 | 5 => {
            unsafe { serinfo(m, arg as *mut usize, request == 5) };
            0
        }
        6 => {
            let o = origin_of(m);
            let dst = unsafe { crate::ffi::slice_mut(arg as *mut u8, o.len() + 1) };
            dst[..o.len()].copy_from_slice(o);
            dst[o.len()] = 0;
            0
        }
        9 => {
            unsafe { *(arg as *mut usize) = m.tls_modid() };
            0
        }
        10 => {
            unsafe { *(arg as *mut usize) = tls::current_block(m.tls_modid()) };
            0
        }
        11 => {
            unsafe { *(arg as *mut *const Phdr) = m.phdr() };
            m.phnum() as c_int
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

fn each_dir(list: &[u8], ctx: Option<Map>, f: &mut dyn FnMut(&[u8])) {
    let norm = |elem: &[u8], buf: &mut PathBuf| {
        let n = if elem.is_empty() { 0 } else { expand(elem, ctx, buf) };
        if n == 0 {
            buf.truncate(0);
            buf.push(b'.');
        }
        let mut n = buf.len();
        while n > 1 && buf.bytes()[n - 1] == b'/' {
            n -= 1;
        }
        buf.truncate(n);
    };
    for (i, elem) in list.split(|&c| c == b':').enumerate() {
        let mut cur = PathBuf::new();
        norm(elem, &mut cur);
        let me = cur.bytes();
        let mut dup = false;
        for prev in list.split(|&c| c == b':').take(i) {
            let mut pb = PathBuf::new();
            norm(prev, &mut pb);
            if pb.bytes() == me {
                dup = true;
                break;
            }
        }
        if !dup {
            f(me);
        }
    }
}

unsafe fn serinfo(m: Map, si: *mut usize, counting: bool) {
    let cnt_ptr = si.wrapping_add(1) as *mut u32;
    if counting {
        unsafe { *si = 0 };
        unsafe { *cnt_ptr = 0 };
    }
    let ser = si.wrapping_add(2);
    let mut alloc = (ser as *mut u8).wrapping_add(unsafe { *cnt_ptr } as usize * 16);
    let mut idx = 0usize;
    let mut total = 0usize;
    let mut count = 0u32;
    let mut add = |name: &[u8]| {
        if counting {
            count += 1;
            total += (name.len() + 1).max(2);
        } else {
            let slot = ser.wrapping_add(idx * 2);
            unsafe { *slot = alloc as usize };
            let dst = unsafe { crate::ffi::slice_mut(alloc, name.len() + 1) };
            dst[..name.len()].copy_from_slice(name);
            dst[name.len()] = 0;
            alloc = alloc.wrapping_add(name.len() + 1);
            unsafe { *(slot.wrapping_add(1) as *mut u32) = 0 };
            idx += 1;
        }
    };
    let main = st().main_map;
    if m.runpath().is_none() {
        let mut l = Some(m);
        while let Some(lm) = l {
            if Some(lm) != main
                && let Some(rp) = lm.rpath()
            {
                each_dir(rp, Some(lm), &mut add);
            }
            l = lm.loader();
        }
    }
    if !st().library_path.is_null() {
        each_dir(unsafe { cstr(st().library_path) }, main, &mut add);
    }
    if let Some(rp) = m.runpath() {
        each_dir(rp, Some(m), &mut add);
    }
    if m.flags_1() & 0x800 == 0 {
        add(b"/lib64");
        add(b"/usr/lib64");
    }
    if counting {
        unsafe { *cnt_ptr = count };
        unsafe { *si = total + 16 + count as usize * 16 };
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
pub unsafe extern "C" fn __libc_ldso_iterate_phdr(cb: Option<PhdrCb>, data: *mut c_void, caller: usize) -> c_int {
    let Some(cb) = cb else { return 0 };
    match iterate_phdr_in::<64>(cb, data, caller) {
        Some(r) => r,
        None => iterate_phdr_big(cb, data, caller),
    }
}

#[inline(never)]
fn iterate_phdr_big(cb: PhdrCb, data: *mut c_void, caller: usize) -> c_int {
    iterate_phdr_in::<1024>(cb, data, caller).unwrap_or(0)
}

#[inline(always)]
fn iterate_phdr_in<const N: usize>(cb: PhdrCb, data: *mut c_void, caller: usize) -> Option<c_int> {
    let small = N < 1024;
    DL_LOCK.lock();
    let mut list: [Option<Map>; N] = [None; N];
    let mut n = 0;
    let mut full = false;
    let nsid = ns_of(map_of_addr(caller));
    if nsid == 0 {
        list[0] = st().main_map;
        n += 1;
        for cur in ns(0).maps() {
            if Some(cur) != st().main_map && !cur.unloading() && !cur.is_ldso() {
                if n == N {
                    full = true;
                    break;
                }
                list[n] = Some(cur);
                n += 1;
            }
        }
        if st().ldso_map.is_some() {
            if n < N {
                list[n] = st().ldso_map;
                n += 1;
            } else {
                full = true;
            }
        }
    } else {
        for cur in ns(nsid).maps() {
            if !cur.unloading() {
                if n == N {
                    full = true;
                    break;
                }
                list[n] = cur.real();
                n += 1;
            }
        }
    }
    let adds = ADDS.load(Relaxed);
    let subs = SUBS.load(Relaxed);
    DL_LOCK.unlock();
    if full && small {
        return None;
    }
    let mut ret = 0;
    for m in list[..n].iter().flatten() {
        let id = m.tls_modid();
        let mut info = DlPhdrInfo {
            dlpi_addr: m.l_addr() as u64,
            dlpi_name: m.l_name() as *const c_char,
            dlpi_phdr: m.phdr(),
            dlpi_phnum: m.phnum() as u16,
            dlpi_adds: adds,
            dlpi_subs: subs,
            dlpi_tls_modid: id,
            dlpi_tls_data: tls::current_block(id) as *mut c_void,
        };
        ret = unsafe { cb(&mut info, core::mem::size_of::<DlPhdrInfo>(), data) };
        if ret != 0 {
            break;
        }
    }
    Some(ret)
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
    let Some(m) = map_of_addr(pc) else { return -1 };
    let r = DlFindObject {
        dlfo_flags: 0,
        dlfo_map_start: m.map_start() as *mut c_void,
        dlfo_map_end: m.map_end() as *mut c_void,
        dlfo_link_map: m.as_ptr(),
        dlfo_eh_frame: m.eh_frame_hdr() as *mut c_void,
        reserved: [0; 7],
    };
    unsafe { result.write(r) };
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
static SPROF_HANDLES: SyncCell<[*mut u8; 16]> = SyncCell::new([null_mut(); 16]);

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

fn sprof_open(name: &[u8], requester: Option<Map>) -> Option<*mut u8> {
    let nsid = ns_of(requester);
    let tail_before = ns(nsid).tail;
    let m = load_library(nsid, name, requester)?;
    let fresh = ns(nsid).tail != tail_before;
    let slot = unsafe { SPROF_HANDLES.with_unsync(|t| t.iter().position(|h| h.is_null())) };
    let h = alloc_blk(SH_SIZE, 16);
    let (Some(slot), false) = (slot, h.is_null()) else {
        if fresh {
            drop_map(m);
        }
        set_error(format_args!("cannot allocate memory"));
        return None;
    };
    let rec = unsafe { crate::ffi::slice_mut(h as *mut usize, SH_SIZE / 8) };
    let mut w = |off: usize, v: usize| rec[off / 8] = v;
    w(0, m.l_addr());
    w(8, m.l_name() as usize);
    w(16, m.l_ld() as usize);
    w(40, h as usize);
    let mut d = m.l_ld();
    for e in m.dynamic() {
        if let Some(i) = l_info_index(e.tag as u64)
            && i < SH_NINFO
        {
            w(SH_INFO + 8 * i, d as usize);
        }
        d = d.wrapping_add(1);
    }
    w(SH_PHDR, m.phdr() as usize);
    w(SH_ENTRY, m.entry());
    w(SH_MAP_START, m.map_start());
    w(SH_MAP_END, m.map_end());
    w(SH_OURS, 0x5350_524f_4648_444c);
    w(SH_MAP, m.as_ptr() as usize);
    w(SH_FRESH, fresh as usize);
    let bytes = unsafe { crate::ffi::slice_mut(h, SH_SIZE) };
    bytes[SH_PHNUM..SH_PHNUM + 2].copy_from_slice(&(m.phnum() as u16).to_ne_bytes());
    bytes[SH_FLAGS] = 2;
    if !m.dyn_adjusted() {
        bytes[SH_FLAGS + 2] = 0x20;
    }
    unsafe { SPROF_HANDLES.with_unsync(|t| t[slot] = h) };
    Some(h)
}

fn sprof_is_handle(h: *mut c_void) -> bool {
    !h.is_null() && unsafe { SPROF_HANDLES.with_unsync(|t| t.contains(&(h as *mut u8))) }
}

unsafe fn sprof_close(h: *mut u8) {
    let rec = unsafe { crate::ffi::slice(h as *const usize, SH_SIZE / 8) };
    let (mp, fresh) = (rec[SH_MAP / 8] as *mut LinkMap, rec[SH_FRESH / 8] != 0);
    let m = unsafe { Map::from_ptr(mp) };
    unsafe {
        SPROF_HANDLES.with_unsync(|t| {
            for e in t.iter_mut() {
                if *e == h {
                    *e = null_mut();
                }
            }
        })
    };
    unsafe { free_blk(h, SH_SIZE, 16) };
    if let Some(m) = m.filter(|m| fresh && !m.relocated()) {
        drop_map(m);
    }
}

fn add_extra_scope(d: Map, root: Map) {
    if !add_extra_scope_in::<32>(d, root) {
        add_extra_scope_big(d, root);
    }
}

#[inline(never)]
fn add_extra_scope_big(d: Map, root: Map) {
    add_extra_scope_in::<512>(d, root);
}

#[inline(always)]
fn add_extra_scope_in<const N: usize>(d: Map, root: Map) -> bool {
    let small = N < 512;
    let mut list: [Option<Map>; N] = [None; N];
    let mut n = 0;
    let own = d.scope();
    for &x in d.xscope() {
        if n < N {
            list[n] = Some(x);
            n += 1;
        } else if small {
            return false;
        }
    }
    let before = n;
    for &m in root.scope() {
        if !own.contains(&m) && !list[..n].contains(&Some(m)) {
            if n < N {
                list[n] = Some(m);
                n += 1;
            } else if small {
                return false;
            }
        }
    }
    if n == before {
        return true;
    }
    let arr = alloc_perm(n * 8, 8) as *mut Option<Map>;
    unsafe { crate::ffi::slice_mut(arr, n) }.copy_from_slice(&list[..n]);
    unsafe { d.set_xscope(arr as *mut *mut LinkMap) };
    unsafe { d.set_nxscope(n) };
    true
}
