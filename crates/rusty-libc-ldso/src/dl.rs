//! The dl* interface: dlopen, dlsym, dlvsym, dlclose, dlerror, dladdr, dladdr1, dlinfo, dl_iterate_phdr and
//! `_dl_find_object`. libc.so.6 exports the public names (glibc keeps them in libc since 2.34) as tiny trampolines that
//! jump to the `__libc_ldso_*` functions here, passing the caller's return address in `%rdx`/`%rcx` where the interface
//! needs the calling object (RTLD_NEXT, the search path of the caller).
//!
//! The exported functions convert their C arguments once (handles to `Map`, strings to slices) and call the safe functions
//! below. A handle a C caller passes is taken as a link map without a check (glibc does not check either), except by
//! dlclose, which looks for it in the lists first.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::ldebug;
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

/// Called by `tls::__libc_ldso_fork_child` (see there).
pub(crate) fn fork_child_reset() {
    DL_LOCK.reset();
}
/// dl_iterate_phdr's `dlpi_adds` and `dlpi_subs` (changed under DL_LOCK).
static ADDS: AtomicU64 = AtomicU64::new(1);
static SUBS: AtomicU64 = AtomicU64::new(0);

// ---- dlerror ----
//
// glibc composes dlerror's text in libc (dlfcn/dlerror.c): the loader only records what failed (`_dl_signal_error`: the object
// name, the message, an error number) and dlerror makes "OBJECT: MESSAGE: STRERROR" of it, translating the message and the
// error text in the "libc" domain, and sets errno to the error number. The record of a thread lives here; libc.so.6's dlerror
// reads it (`__libc_ldso_dlerror_record`) and stores the text it composed next to it (`__libc_ldso_dlerror_compose`).

/// A thread's pending dlerror record. Lives in a block hung off the thread's TCB (`Tcb.dl_error`, %fs:0x80) so that each thread
/// has its own, as POSIX requires; before the thread pointer exists a static block stands in.
#[repr(C)]
pub struct ErrBuf {
    /// 0 nothing, 1 an error is waiting to be read, 2 it was handed out (the next call clears it)
    state: u8,
    code: c_int,
    /// The data: the object name and its NUL, the message and its NUL (together `rec_len` bytes), then the text dlerror composed.
    obj_len: usize,
    msg_len: usize,
    inline: [u8; 512],
    /// Data that does not fit `inline` lives in a block of `ext_cap` bytes (used from then on; freed with the thread).
    ext: *mut u8,
    ext_cap: usize,
}
/// The TCB word holding the error buffer's address (rusty-libc-core `Tcb::dl_error`; glibc's tcbhead_t keeps `feature_1`,
/// `__private_tm` and `__private_ss` at 0x48..0x80, which code outside the C library reads, so ours starts at 0x80).
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
    /// The data area (`cap()` bytes).
    fn data(&mut self) -> &mut [u8] {
        if self.ext.is_null() {
            &mut self.inline
        } else {
            // SAFETY: `ext` is a block of `ext_cap` bytes this buffer owns (allocated by `reserve`/compose).
            unsafe { crate::ffi::slice_mut(self.ext, self.ext_cap) }
        }
    }
    fn data_ptr(&mut self) -> *mut u8 {
        if self.ext.is_null() { self.inline.as_mut_ptr() } else { self.ext }
    }
    /// Make room for `need` bytes of data; the first `keep` bytes move along. False without memory.
    fn reserve(&mut self, need: usize, keep: usize) -> bool {
        if need <= self.cap() {
            return true;
        }
        let c = need.next_power_of_two();
        let p = alloc_blk(c, 16);
        if p.is_null() {
            return false;
        }
        // SAFETY: a fresh block of `c` > `keep` bytes, ours alone.
        let dst = unsafe { crate::ffi::slice_mut(p, c) };
        dst[..keep].copy_from_slice(&self.data()[..keep]);
        self.set_ext(p, c);
        true
    }
    /// Take `p` (a block of `c` bytes from `alloc_blk`) as the data area, freeing the old one.
    fn set_ext(&mut self, p: *mut u8, c: usize) {
        if !self.ext.is_null() {
            // SAFETY: the old extension block, allocated with this size, no longer used.
            unsafe { free_blk(self.ext, self.ext_cap, 16) };
        }
        self.ext = p;
        self.ext_cap = c;
    }
}

/// Free a thread's error buffer (its extension block too) when the thread ends.
///
/// # Safety
/// `p` is a thread's buffer made by `err_buf` and the thread has ended.
pub unsafe fn free_errbuf(p: *mut u8) {
    let b = p as *mut ErrBuf;
    // SAFETY: the buffer of an ended thread (caller's contract): nobody else uses it.
    let b = unsafe { &mut *b };
    if !b.ext.is_null() {
        // SAFETY: its extension block, allocated with this size.
        unsafe { free_blk(b.ext, b.ext_cap, 16) };
    }
    // SAFETY: the buffer itself, allocated by `err_buf` with ERRBUF_SIZE.
    unsafe { free_blk(p, ERRBUF_SIZE, 16) };
}

/// The calling thread's error buffer (allocated on first use; None without memory).
///
/// # Safety
/// No other reference to the calling thread's buffer is live (each dl* entry point takes it once). Before the thread pointer
/// exists there is one thread, which uses the static stand-in.
unsafe fn err_buf<'a>() -> Option<&'a mut ErrBuf> {
    if !tls::ready() {
        // SAFETY: one thread before TLS exists; no other reference (caller's contract).
        return Some(unsafe { &mut *EARLY_ERR.as_ptr() });
    }
    let slot = (sys::thread_pointer() + DL_ERROR_SLOT) as *mut usize;
    // SAFETY: the calling thread's own TCB word (Tcb.dl_error).
    let mut p = unsafe { *slot } as *mut ErrBuf;
    if p.is_null() {
        p = alloc_blk(ERRBUF_SIZE, 16) as *mut ErrBuf;
        if p.is_null() {
            return None;
        }
        // SAFETY: a fresh, zeroed block of ERRBUF_SIZE bytes (a zeroed `ErrBuf` is a valid empty one), kept in the calling
        // thread's TCB word.
        unsafe { *slot = p as usize };
    }
    // SAFETY: the calling thread's own buffer; only it uses the buffer, and no other reference is live (caller's contract).
    Some(unsafe { &mut *p })
}

/// Writes a message by handing its pieces to the sink it is given (called twice: to count, then to copy).
type MsgWriter<'a> = &'a dyn Fn(&mut dyn FnMut(&[u8]));

/// Make (object name, message, error number) the pending record of this thread. Without memory for a long one, the parts are
/// cut to what fits.
fn record(obj: &[u8], code: c_int, msg: MsgWriter) {
    // SAFETY: the only reference to this thread's buffer for the call.
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

/// Make the error recorded by `set_error_at` the pending dlerror record of this thread.
fn publish_error() {
    let m = error_msg();
    record(error_obj(), error_code(), &|out: &mut dyn FnMut(&[u8])| out(m));
}

/// Record a failure straight into this thread's buffer (no shared state: callable without the loader lock).
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

/// A call that succeeded discards a record that was not read (glibc frees the result object).
fn succeed() {
    // SAFETY: the only reference to this thread's buffer for the call.
    if let Some(b) = unsafe { err_buf() }
        && b.state == 1
    {
        b.state = 0;
    }
}

/// libc.so.6's dlerror, first half (glibc `__dlerror` up to the composition): 1 and the parts of the pending record (they
/// stay valid until the next dl* call of the thread); 0 when there is none, and a record that was handed out already is
/// dropped (a second dlerror returns NULL).
///
/// # Safety
/// The three pointers are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlerror_record(obj: *mut *const c_char, msg: *mut *const c_char, code: *mut c_int) -> c_int {
    // SAFETY: the only reference to this thread's buffer for the call.
    let Some(b) = (unsafe { err_buf() }) else { return 0 };
    if b.state != 1 {
        b.state = 0;
        return 0;
    }
    let d = b.data_ptr();
    // SAFETY: writable out-parameters (caller's contract).
    unsafe { *obj = d as *const c_char };
    // SAFETY: as above; the message starts after the object name and its NUL.
    unsafe { *msg = d.wrapping_add(b.obj_len + 1) as *const c_char };
    // SAFETY: as above.
    unsafe { *code = b.code };
    1
}

/// libc.so.6's dlerror, second half: keep the text it composed (the concatenation of `n` pieces, each a pointer and a length)
/// with the record, mark the record handed out and return the text. The pieces may point into the record itself. Without
/// memory for the text, the record's message is returned (glibc's fallback when asprintf fails).
///
/// # Safety
/// `pieces` points to `n` (pointer, length) pairs, each naming readable bytes (possibly inside this thread's record).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlerror_compose(pieces: *const (*const u8, usize), n: usize) -> *const c_char {
    // The pieces may point into the buffer, so the copying below works through raw pointers (no slice of the buffer is
    // made while they are read).
    // SAFETY: the only reference to this thread's buffer for the call.
    let Some(b) = (unsafe { err_buf() }) else { return c"out of memory".as_ptr() };
    // SAFETY: `n` pairs (caller's contract); the pairs themselves are not in the buffer.
    let parts = unsafe { crate::ffi::slice(pieces, n) };
    let total: usize = parts.iter().map(|p| p.1).sum();
    let rl = b.rec_len();
    b.state = 2;
    if total + 1 + rl > b.cap() {
        // a new block: the record and then the pieces (which may point into the old block) are copied before it is freed
        let c = (total + 1 + rl).next_power_of_two();
        let p = alloc_blk(c, 16);
        if p.is_null() {
            return b.data_ptr().wrapping_add(b.obj_len + 1) as *const c_char;
        }
        // SAFETY: the old data area's first `rl` bytes (the record) into the fresh block of `c` bytes.
        unsafe { core::ptr::copy_nonoverlapping(b.data_ptr(), p, rl) };
        let mut at = rl;
        for &(q, l) in parts {
            // SAFETY: a readable piece (caller's contract) into the fresh block (total + 1 + rl <= c): no overlap.
            unsafe { core::ptr::copy_nonoverlapping(q, p.wrapping_add(at), l) };
            at += l;
        }
        // SAFETY: inside the fresh block (at = rl + total < c).
        unsafe { *p.wrapping_add(at) = 0 };
        b.set_ext(p, c);
        return p.wrapping_add(rl) as *const c_char;
    }
    let d = b.data_ptr();
    let mut at = rl;
    for &(q, l) in parts {
        // (the destination lies after the record, the pieces in it or elsewhere: they never overlap)
        // SAFETY: a readable piece (caller's contract) into the data area after the record (rl + total + 1 <= cap); `copy`
        // allows the two to overlap.
        unsafe { core::ptr::copy(q, d.wrapping_add(at), l) };
        at += l;
    }
    // SAFETY: inside the data area (at < cap).
    unsafe { *d.wrapping_add(at) = 0 };
    d.wrapping_add(rl) as *const c_char
}

// ---- helpers ----

/// The loaded object whose mapped range holds `addr`.
pub fn map_of_addr(addr: usize) -> Option<Map> {
    (0..st().nns).find_map(|n| ns(n).maps().find(|c| !c.unloading() && addr >= c.map_start() && addr < c.map_end()))
}

fn object_name(m: Map) -> &'static [u8] {
    let n = m.name();
    if n.is_empty() { reloc::prog_name() } else { n }
}

fn load_deps_new(first: Option<Map>) -> bool {
    // breadth first over the maps that were just mapped; load_library appends the dependencies after them
    let mut cur = first;
    while let Some(m) = cur {
        if !m.is_ldso() && m.needed_ptr().is_null() && !crate::load_needed(m, true, |_| {}) {
            return false;
        }
        cur = m.next();
    }
    true
}

/// Remove every map from `first` on (they were mapped by a dlopen that failed). Out of line: inlined, its list made the frame
/// of every dlopen bigger (FIXLIST #79); the list (up to `MAX_MAPS`, 256 before: the rest stayed mapped) is in a scratch
/// mapping.
#[cold]
#[inline(never)]
pub fn discard_from(first: Option<Map>) {
    let mut s = Scratch::for_maps_or_die(MAX_MAPS);
    let list = s.maps::<MAX_MAPS>();
    let mut n = 0;
    for m in MapIter(first) {
        if n == MAX_MAPS {
            break;
        }
        list[n] = Some(m);
        n += 1;
    }
    for m in list[..n].iter().flatten() {
        drop_map(*m);
    }
}

/// Forget a map and give its address range back.
fn drop_map(m: Map) {
    if ldebug::on(ldebug::FILES) {
        ldebug::destroying(m);
    }
    m.set_unloading(true);
    m.set_removed(true);
    ns(m.l_ns() as usize).remove_global(m);
    m.set_in_global(false);
    tls::remove_module(m);
    unlink_map(m);
    if m.real() != Some(m) {
        // a mirror of the loader's map (see `ldso_mirror`): the image belongs to the real map
        return;
    }
    if !m.plt_cache().is_null() {
        let n = (m.pltrelsz() / core::mem::size_of::<Rela>()).max(1) * crate::plt::SLOT_SIZE;
        // SAFETY: the object's PLT record table (`plt::slot_of`), unreachable now that the object is out of every list and
        // its code is about to go.
        unsafe { sys::munmap(m.plt_cache() as usize, n) };
        // SAFETY: an empty table keeps the invariant.
        unsafe { m.set_plt_cache(null_mut()) };
    }
    // SAFETY: the object's own address range; it is out of every list and scope, its destructors have run (or it never
    // ran): nothing uses its pages any more (glibc's dlclose unmaps the same way).
    unsafe { sys::munmap(m.map_start(), m.map_end() - m.map_start()) };
}

// ---- dlopen / dlclose ----

/// The first free namespace slot from 1 up (glibc `_dl_open` for `LM_ID_NEWLM`, and the audit libraries at start-up), or
/// None when all `DL_NNS` are in use.
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

/// glibc's namespace ids: the base namespace, "make a new one" (`dlmopen` only) and "the caller's" (what `dlopen` uses).
pub const LM_ID_BASE: isize = 0;
pub const LM_ID_NEWLM: isize = -1;
pub const LM_ID_CALLER: isize = -2;

/// What a dlopen returns: a map, or for `__RTLD_SPROF` glibc's record for `sprof`.
enum Opened {
    Map(Map),
    Sprof(*mut u8),
}

/// `dlopen`/`dlmopen`: open `name` in the namespace `lmid` (glibc `_dl_open`). A new namespace takes the first free slot
/// from 1 up; any other id must be the base namespace or one that holds something.
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
        // a plain dlopen loads into the namespace of the code that calls it
        ns_of(requester)
    } else if lmid == LM_ID_BASE {
        0
    } else if lmid < 0 || lmid as usize >= s.nns || ns(lmid as usize).head.is_none() || crate::audit::is_audit_ns(lmid as usize) {
        // a namespace nothing lives in cannot be named: only LM_ID_NEWLM makes one; nor can an audit library's (code running
        // in it reaches it with a plain dlopen)
        set_error_at(name, 22, format_args!("invalid target namespace in dlmopen()"));
        return None;
    } else {
        lmid as usize
    };
    // the debugger's view of the namespace (glibc `_dl_open` marks a new one consistent, `dl_open_worker_begin` initialises it)
    if lmid == LM_ID_NEWLM {
        crate::debug_change_state(crate::debug_update(nsid), crate::RT_CONSISTENT);
    }
    crate::debug_initialize(nsid);
    let r = if mode & SPROF != 0 { sprof_open(name, requester).map(Opened::Sprof) } else { open_in(nsid, requester, name, mode).map(Opened::Map) };
    if r.is_none() {
        // a namespace that was made for this call and got nothing is given up again
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
                promote_global(m, true);
            }
            // like glibc, RTLD_NOLOAD of a library that is loaded counts as an open: the program closes the handle
            // it gets back (dlclose on it must not unload a library somebody else still uses)
            m.set_refcount(m.refcount() + 1);
            m.set_direct_opens(m.direct_opens() + 1);
            if ldebug::on(ldebug::FILES) {
                ldebug::opening(m, m.direct_opens());
            }
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
    crate::map::CALLMAP.store(true, Relaxed);
    let root = load_library(nsid, name, requester);
    crate::map::CALLMAP.store(false, Relaxed);
    let Some(root) = root else {
        // glibc names the file in the message; load_library did
        discard_from(after(tail_before));
        return None;
    };
    let first_new = after(tail_before);
    // a nested dlopen (from an audit callback or a constructor) of a map an outer dlopen is still setting up: the outer one relocates it
    // and runs its constructors, so this one only takes a reference (glibc `dl_open_worker_begin` returns early for a map that
    // already has a search list, without activity notifications or constructors)
    if root.opening() && first_new.is_none() {
        if mode & RTLD_GLOBAL != 0 {
            promote_global(root, true);
        }
        root.set_refcount(root.refcount() + 1);
        root.set_direct_opens(root.direct_opens() + 1);
        if ldebug::on(ldebug::FILES) {
            ldebug::opening(root, root.direct_opens());
        }
        return Some(root);
    }
    // the program itself, or a position-independent executable, cannot be opened (glibc's messages)
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
    // DF_1_NOOPEN (-z nodlopen): neither the object asked for nor anything it brings in may be opened by dlopen
    if root.flags_1() & 0x40 != 0 || MapIter(first_new).any(|c| c.flags_1() & 0x40 != 0) {
        set_error_at(name, 0, format_args!("shared object cannot be dlopen()ed"));
        discard_from(first_new);
        return None;
    }
    // the versions the new maps need from their libraries (glibc's dl_open_worker_begin: `_dl_check_map_versions` of each new map)
    for cur in MapIter(first_new) {
        if !crate::check_map_versions(cur) {
            discard_from(first_new);
            return None;
        }
    }
    // (LD_DEBUG=scopes: glibc shows the scopes of an object that was not open with a scope of its own yet)
    let show_scopes = ldebug::on(ldebug::SCOPES) && (first_new.is_some() || root.scope_ptr().is_null());
    if root.scope_ptr().is_null() {
        crate::build_scope(root);
    }
    if show_scopes {
        crate::show_scope(root, 0, first_new.is_some(), &|_| false);
    }
    // an already loaded object this group needs (and that is not global) gets the group's scope too, so that its lazily bound
    // symbols can be defined by the new objects (glibc's update_scope; tst dblload)
    for &d in root.scope() {
        let is_new = MapIter(first_new).any(|c| c == d);
        if is_new || d.in_global() || d == root {
            continue;
        }
        add_extra_scope(d, root);
    }
    // every new map relocates against the global scope, then the scope of the object that was asked for
    for cur in MapIter(first_new) {
        cur.set_dlopened(true);
        cur.set_opening(true);
        if cur.scope_ptr().is_null() {
            // SAFETY: `root`'s scope array (maps of this namespace) with its count.
            unsafe { cur.set_scope(root.scope_ptr()) };
            // SAFETY: as above.
            unsafe { cur.set_nscope(root.nscope()) };
        }
        if mode & RTLD_DEEPBIND != 0 {
            cur.set_deepbind(true);
        }
        // RTLD_NOW: bind every PLT slot now (a missing function makes dlopen fail); RTLD_LAZY leaves them to the first call
        if mode & 0x2 != 0 && !crate::profile::enabled() {
            cur.set_bind_now(true);
            cur.set_rtld_now(true);
        }
    }
    // TLS
    for cur in MapIter(first_new) {
        if !tls::add_module(cur, false) || (cur.flags() & DF_STATIC_TLS != 0 && !tls::add_static_late(cur)) {
            set_error_at(object_name(cur), 0, format_args!("cannot allocate memory in static TLS block"));
            discard_from(first_new);
            return None;
        }
    }
    if mode & RTLD_GLOBAL != 0 {
        // (LD_DEBUG=scopes announces the new global objects after the constructors, where glibc adds them)
        promote_global(root, first_new.is_none());
    }
    // relocate, last mapped first: the new maps in a 32-map list (a dlopen's usual count), more in the `MAX_MAPS` list of
    // `finish_big`, out of line (a 2 KB array in this frame was on the stack of every dlopen and of the constructors it runs,
    // also on a thread with a small stack, FIXLIST #79)
    let ok = if MapIter(first_new).nth(32).is_none() {
        finish::<32>(&mut [None; 32], nsid, root, first_new, mode)
    } else {
        finish_big(nsid, root, first_new, mode)
    };
    if !ok {
        return None;
    }
    if show_scopes {
        // glibc's update_scopes: every object of the new scope, from the scope this dlopen added to it
        let is_new = |c: Map| MapIter(first_new).any(|x| x == c);
        for &d in root.scope() {
            let extended = d.dlopened() && d.init_called() && !d.in_global() && d != root && d.xscope().contains(&root);
            crate::show_scope(d, if extended { 2 } else { 0 }, is_new(d), &is_new);
        }
    }
    crate::init_tree(root, false);
    if mode & RTLD_GLOBAL != 0 && first_new.is_some() && ldebug::on(ldebug::SCOPES) {
        for &d in root.scope() {
            if MapIter(first_new).any(|c| c == d) {
                ldebug::add_global(d);
            }
        }
    }
    if ldebug::on(ldebug::FILES) {
        ldebug::opening(root, root.direct_opens());
    }
    Some(root)
}

/// [`finish`] with room for `MAX_MAPS` new maps (256 before: the maps past them were never relocated), the list in a scratch
/// mapping.
#[cold]
#[inline(never)]
fn finish_big(nsid: usize, root: Map, first_new: Option<Map>, mode: c_int) -> bool {
    let mut s = Scratch::for_maps_or_die(MAX_MAPS);
    finish::<MAX_MAPS>(s.maps::<MAX_MAPS>(), nsid, root, first_new, mode)
}

/// The end of `open_in` before the constructors: relocate the new maps (at most N, from `first_new` on; `list` all `None`),
/// protect their RELRO, count their references; false (after discarding them) when a relocation failed.
#[inline(always)]
fn finish<const N: usize>(list: &mut [Option<Map>; N], nsid: usize, root: Map, first_new: Option<Map>, mode: c_int) -> bool {
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
    // la_objopen comes before the relocation (glibc announces a map as it is mapped): the bindings made by the relocation reach
    // la_symbind64 with the binding flags the libraries asked for
    for m in list.iter().flatten() {
        crate::audit::objopen(*m);
    }
    for m in list.iter().rev().flatten() {
        // SAFETY: a new map of this dlopen, relocated last mapped first (dependencies before what needs them), under the
        // loader lock.
        if !unsafe { reloc::relocate(*m) } {
            discard_from(first_new);
            crate::debug_change_state(rd, crate::RT_CONSISTENT);
            crate::audit::activity_ns(nsid, crate::audit::LA_ACT_CONSISTENT);
            return false;
        }
    }
    crate::profile::start();
    // a libc.so.6 that was mapped for this call (the copy of a new namespace) is told it is not the initial one (glibc
    // `_dl_call_libc_early_init`); the base namespace's copy was set up at start-up
    if nsid != 0
        && let Some(lm) = ns(nsid).libc_map.filter(|lm| list.contains(&Some(*lm)))
    {
        call_libc_early_init(lm, false);
    }
    for m in list.iter().flatten() {
        protect_relro(*m);
        ADDS.store(ADDS.load(Relaxed) + 1, Relaxed);
        // each new map holds a reference on the maps it needs
        for &d in m.needed() {
            d.set_refcount(d.refcount() + 1);
        }
    }
    if mode & RTLD_NODELETE != 0 {
        root.set_nodelete(true);
    }
    root.set_refcount(root.refcount() + 1);
    root.set_direct_opens(root.direct_opens() + 1);
    crate::debug_change_state(rd, crate::RT_CONSISTENT);
    crate::audit::activity_ns(nsid, crate::audit::LA_ACT_CONSISTENT);
    for cur in MapIter(first_new) {
        cur.set_opening(false);
    }
    true
}

/// Call `__libc_early_init(initial)` of the libc.so.6 `libc` (found directly in that map, not through any scope).
pub fn call_libc_early_init(libc: Map, initial: bool) {
    let fl = Flags { plt: false, skip: None, newest: false };
    if let Some(f) = lookup(b"__libc_early_init", None, &[&[libc]], &fl) {
        // SAFETY: libc.so.6's `void __libc_early_init(_Bool)`, relocated before this call.
        let f: extern "C" fn(bool) = unsafe { core::mem::transmute(sym_addr(&f)) };
        f(initial);
    }
}

fn promote_global(m: Map, announce: bool) {
    if m.scope_ptr().is_null() {
        crate::build_scope(m);
    }
    for &d in m.scope() {
        if !d.is_ldso() && !d.in_global() && ns(m.l_ns() as usize).push_global(d) {
            d.set_in_global(true);
            if announce && ldebug::on(ldebug::SCOPES) {
                ldebug::add_global(d);
            }
        }
    }
}

/// # Safety
/// `file` is NULL or a NUL-terminated string; `env` is NULL or the caller's environment.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlopen(file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    // SAFETY: forwarded contract.
    unsafe { dlmopen_impl(LM_ID_CALLER, file, mode, caller, env) }
}

/// `dlmopen(lmid, file, mode)`; the trampoline in libc.so.6 adds the caller's address and that libc's current `environ`
/// (what the constructors get).
///
/// # Safety
/// As [`__libc_ldso_dlopen`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlmopen(lmid: isize, file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    // SAFETY: forwarded contract.
    unsafe { dlmopen_impl(lmid, file, mode, caller, env) }
}

/// # Safety
/// As [`__libc_ldso_dlopen`].
unsafe fn dlmopen_impl(lmid: isize, file: *const u8, mode: c_int, caller: usize, env: *mut *mut u8) -> *mut c_void {
    // SAFETY: NULL or a NUL-terminated string that lives for the call (caller's contract).
    let file = unsafe { cstr_opt(file) };
    // unknown bits first ("invalid mode parameter"), then the missing RTLD_LAZY/RTLD_NOW choice
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
    // a nested dlopen (from a constructor) brings its own value; the outer one's comes back after it
    let outer_env = crate::init_env_swap(env);
    let r = open_object(lmid, file, mode, caller);
    crate::init_env_swap(outer_env);
    match r {
        None => {
            // RTLD_NOLOAD of an object that is not loaded fails without a message
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

/// Does `from` need `to` through its DT_NEEDED closure (glibc's `l_initfini`)?
///
/// The walk runs with 32-entry arrays first (the usual closure); one that outgrows them is walked again with the 256-entry
/// arrays of `needs_big`, out of line: 4 KB of arrays in the frame of every binding to a dlopen()ed library (`note_binding`)
/// were on the stack of a thread with a small stack too (FIXLIST #79).
fn needs(from: Map, to: Map) -> bool {
    match needs_in::<32>(&mut [None; 32], &mut [None; 32], from, to) {
        Some(r) => r,
        None => needs_big(from, to),
    }
}

/// The `MAX_MAPS`-entry walk of [`needs`] (256 before), its two arrays in a scratch mapping (4 KB were on the stack of the
/// binding thread).
#[cold]
#[inline(never)]
fn needs_big(from: Map, to: Map) -> bool {
    let mut s = Scratch::for_maps_or_die(2 * MAX_MAPS);
    let (stack, seen) = s.maps::<{ 2 * MAX_MAPS }>().split_at_mut(MAX_MAPS);
    let (Ok(stack), Ok(seen)) = (<&mut [Option<Map>; MAX_MAPS]>::try_from(stack), <&mut [Option<Map>; MAX_MAPS]>::try_from(seen)) else {
        return false;
    };
    needs_in::<MAX_MAPS>(stack, seen, from, to).unwrap_or(false)
}

/// [`needs`] with N-entry arrays (all `None`): None when the walk outgrew them (only for N below `MAX_MAPS`; at `MAX_MAPS`
/// entries are dropped, as before at 256).
#[inline(always)]
fn needs_in<const N: usize>(stack: &mut [Option<Map>; N], seen: &mut [Option<Map>; N], from: Map, to: Map) -> Option<bool> {
    let small = N < MAX_MAPS;
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

/// glibc's `add_dependency`: the definition of a symbol that `undef` just bound to (a relocation, or dlsym of RTLD_DEFAULT /
/// RTLD_NEXT from code in `undef`) lies in the dlopen()ed `def`, which `undef` does not need. If `undef` is the program or a
/// startup library (it can never be unloaded) `def` is pinned; otherwise `undef` keeps `def` loaded while it is.
pub fn note_binding(undef: Option<Map>, def: Option<Map>) {
    let (Some(undef), Some(def)) = (undef, def) else { return };
    if def == undef || !def.dlopened() || def.nodelete() {
        return;
    }
    DL_LOCK.lock();
    if !def.nodelete() && !needs(undef, def) {
        if !undef.dlopened() {
            if ldebug::on(ldebug::BINDINGS) {
                ldebug::nodelete_ref(def, undef);
            }
            def.set_nodelete(true);
        } else if !undef.reldeps().contains(&def) {
            if ldebug::on(ldebug::FILES) {
                ldebug::reldep(def, undef);
            }
            if undef.nreldeps() == undef.creldeps() {
                let nc = if undef.creldeps() == 0 { 8 } else { undef.creldeps() * 2 };
                let dst = crate::util::perm_maps(nc);
                for (k, &r) in undef.reldeps().iter().enumerate() {
                    dst[k] = Some(r);
                }
                // SAFETY: the new permanent array of `nc` > nreldeps entries holds the same maps (the rest None = NULL).
                unsafe { undef.set_reldeps(dst.as_mut_ptr() as *mut *mut LinkMap) };
                // SAFETY: its capacity.
                unsafe { undef.set_creldeps(nc) };
            }
            let k = undef.nreldeps();
            // SAFETY: k < creldeps: an entry of the array (past the `nreldeps` that slices see).
            unsafe { *undef.reldeps_ptr().wrapping_add(k) = def.as_ptr() };
            // SAFETY: entry k is a map now.
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
        // a mirror of the loader goes with the last library of its namespace that needs it
        if m.refcount() == 0 && !m.unloading() {
            crate::audit::close_one(m);
            drop_map(m);
        }
        return;
    }
    // a map with thread_local destructors still to run stays (glibc's l_tls_dtor_count check in _dl_close_worker); a later
    // dlclose unloads it once they ran (`release_kept`)
    if m.refcount() > 0 || m.nodelete() || m.is_main() || m.is_ldso() || m.unloading() || m.tls_dtor_count() > 0 {
        return;
    }
    m.set_unloading(true);
    let rd = crate::debug_update(m.l_ns() as usize);
    crate::debug_change_state(rd, crate::RT_DELETE);
    // destructors first (the library's own __cxa_finalize call runs from its fini array), then the dependencies
    if m.init_called() {
        crate::run_fini(m);
    }
    // la_objclose of the map before those of its dependencies (glibc reports them in list order), all inside one
    // la_activity(DELETE) ... la_activity(CONSISTENT) bracket per dlclose
    crate::audit::close_one(m);
    for &d in m.needed() {
        release(d);
    }
    // the maps it bound symbols to without needing them
    for &d in m.reldeps() {
        release(d);
    }
    m.set_unloading(false);
    m.set_removed(true);
    drop_map(m);
    SUBS.store(SUBS.load(Relaxed) + 1, Relaxed);
    crate::debug_change_state(rd, crate::RT_CONSISTENT);
}

/// Unload the maps of namespace `nsid` that a dlclose kept only for their pending `thread_local` destructors, now that
/// those ran: glibc's `_dl_close_worker` looks at every map of the namespace on each dlclose. Such a map is the only kind
/// a dlopen()ed one left in the list with no reference.
fn release_kept(nsid: usize) {
    while let Some(m) = ns(nsid).maps().find(|c| {
        c.dlopened() && c.refcount() == 0 && c.tls_dtor_count() == 0 && !c.nodelete() && !c.unloading() && !c.opening() && !c.is_ldso()
    }) {
        release(m);
        if !m.removed() {
            break; // kept after all: do not loop on it
        }
    }
}

/// `__libc_ldso_tls_dtor_ref(dso, delta)`: libc.so.6 registered (+1) or ran (-1) a `thread_local` destructor whose
/// `__cxa_thread_atexit_impl` named `dso` (the object's `&__dso_handle`): count it on the dlopen()ed object holding that
/// address (glibc's `l_tls_dtor_count`; the program and its start-up libraries are never unloaded, so they are not counted).
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_tls_dtor_ref(dso: usize, delta: isize) {
    DL_LOCK.lock();
    if let Some(m) = map_of_addr(dso).filter(|m| m.dlopened()) {
        m.set_tls_dtor_count(m.tls_dtor_count().saturating_add_signed(delta));
    }
    DL_LOCK.unlock();
}

/// # Safety
/// `handle` is NULL, a handle dlopen returned, or anything else (it is looked for in the lists before use).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlclose(handle: *mut c_void) -> c_int {
    DL_LOCK.lock();
    if sprof_is_handle(handle) {
        // SAFETY: one of the records `sprof_open` made (just checked).
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
        // a handle that is not a loaded map (of any namespace)
        let found = (0..st().nns).find_map(|n| ns(n).maps().find(|c| c.as_ptr() == p && !c.unloading()));
        match found {
            None => {
                fail(format_args!("invalid handle"));
                -1
            }
            Some(m) => {
                m.set_direct_opens(m.direct_opens().saturating_sub(1));
                if ldebug::on(ldebug::FILES) && (m.direct_opens() > 0 || !m.dlopened()) {
                    // glibc's _dl_close_worker: a map that stays open (or was loaded at start-up)
                    ldebug::closing(m, m.direct_opens());
                }
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

// ---- dlsym ----

fn tls_symbol_address(f: &Found) -> usize {
    let ti = tls::TlsIndex { module: f.map.tls_modid(), offset: f.sym.value as usize };
    // SAFETY: a tls_index on our stack; the calling thread has a thread pointer (the program runs).
    unsafe { tls::__tls_get_addr(&ti) }
}

/// What dlsym was asked to search.
#[derive(Clone, Copy)]
pub enum Handle {
    Default,
    Next,
    Map(Map),
}

pub fn symbol_lookup(handle: Handle, name: &[u8], ver: Option<&VerRef>, caller: usize) -> usize {
    let s = st();
    // RTLD_DEFAULT and RTLD_NEXT search the global scope of the caller's namespace (the base one for code that is not in a map)
    let caller_map = match handle {
        Handle::Default | Handle::Next => map_of_addr(caller),
        Handle::Map(_) => None,
    };
    let g = ns(ns_of(caller_map)).scope();
    let fl = Flags { plt: false, skip: None, newest: ver.is_none() };
    let found: Option<Found>;
    let where_: Option<Map>;
    // (for LD_DEBUG: the scopes searched)
    let mut used: [&[Map]; 2] = [&[], &[]];
    match handle {
        Handle::Default => {
            // the global scope of the caller's namespace, then the caller's own scope: code in a namespace other than the base
            // one (or loaded RTLD_LOCAL) finds its own objects' symbols through RTLD_DEFAULT (glibc searches `l_scope` of the caller)
            let own: &[Map] = match caller_map {
                Some(c) if !c.in_global() => c.scope(),
                _ => &[],
            };
            found = lookup(name, ver, &[g, own], &fl);
            used = [g, own];
            where_ = None;
            // an implicit lookup from the caller's object: the definition cannot be unloaded under it
            if let Some(f) = &found {
                note_binding(caller_map.or(s.main_map), Some(f.map));
            }
        }
        Handle::Next => {
            let Some(c) = caller_map else {
                fail(format_args!("RTLD_NEXT used in code not dynamically loaded"));
                return 0;
            };
            // the maps after the caller in its own search order: the rest of the global scope after it, or, when it is not
            // global, the rest of its own scope after it and then the whole global scope (at most 1024 maps in all). Slices
            // of the scopes, not a copy: a 1024-map array made this frame 8 KB, the deepest of a thread's first
            // pthread_exit (dlsym of the unwinder, FIXLIST #79)
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
            used = [first, second];
            where_ = None;
            if let Some(f) = &found {
                note_binding(Some(c), Some(f.map));
            }
        }
        Handle::Map(m) => {
            if Some(m) == s.main_map {
                found = lookup(name, ver, &[ns(0).scope()], &fl);
                used[0] = ns(0).scope();
            } else {
                if m.scope_ptr().is_null() {
                    crate::build_scope(m);
                }
                found = lookup(name, ver, &[m.scope()], &fl);
                used[0] = m.scope();
            }
            where_ = Some(m);
        }
    }
    if ldebug::mask() & (ldebug::SYMBOLS | ldebug::BINDINGS | ldebug::STATISTICS) != 0 {
        // glibc's dlsym: the reference is the caller's object (RTLD_DEFAULT, RTLD_NEXT) or the handle's
        let undef = match handle {
            Handle::Map(m) => Some(m),
            _ => caller_map.or(s.main_map),
        };
        reloc::debug_lookup(undef, false, name, ver, &used, None, found);
    }
    match found {
        Some(f) => {
            let t = f.sym.info & 0xf;
            if t == STT_TLS {
                return tls_symbol_address(&f);
            }
            let a = sym_addr(&f);
            // SAFETY: the address of a loaded, relocated object's STT_GNU_IFUNC definition is its resolver.
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
            if ldebug::errors_on() {
                let undef = match handle {
                    Handle::Map(m) => Some(m),
                    _ => caller_map.or(s.main_map),
                };
                if let Some(u) = undef {
                    ldebug::lookup_error(u, name, ver.map(|v| v.name.bytes()));
                }
            }
            if ver.is_some() {
                fail_at(who, 0, format_args!("undefined symbol: {}, version {}", Bytes(name), Bytes(vtext)));
            } else {
                fail_at(who, 0, format_args!("undefined symbol: {}", Bytes(name)));
            }
            0
        }
    }
}

/// A dlsym handle: RTLD_DEFAULT (NULL), RTLD_NEXT (-1) or a link map.
///
/// # Safety
/// `handle` is RTLD_DEFAULT, RTLD_NEXT or a handle dlopen returned (glibc does not check it either).
unsafe fn handle_of(handle: *mut c_void) -> Handle {
    match handle as usize {
        0 => Handle::Default,
        usize::MAX => Handle::Next,
        // SAFETY: a link map (caller's contract), never NULL here.
        _ => match unsafe { Map::from_ptr(handle as *mut LinkMap) } {
            Some(m) => Handle::Map(m),
            None => Handle::Default,
        },
    }
}

/// # Safety
/// `handle` as for [`handle_of`]; `name` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlsym(handle: *mut c_void, name: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    // SAFETY: forwarded contract.
    let h = unsafe { handle_of(handle) };
    // SAFETY: a NUL-terminated string that lives for the call (caller's contract).
    let r = symbol_lookup(h, unsafe { cstr(name) }, None, caller);
    if r != 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

/// # Safety
/// As [`__libc_ldso_dlsym`]; `version` is NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlvsym(handle: *mut c_void, name: *const u8, version: *const u8, caller: usize) -> *mut c_void {
    DL_LOCK.lock();
    let v = if version.is_null() {
        None
    } else {
        // SAFETY: a NUL-terminated string that lives for the call (caller's contract); the VerRef does not outlive it.
        let vs = unsafe { CStrRef::new(version) };
        Some(VerRef { name: vs, hash: elf_hash(vs.bytes()), file: None, hidden: true })
    };
    // SAFETY: forwarded contract.
    let h = unsafe { handle_of(handle) };
    // SAFETY: a NUL-terminated string that lives for the call (caller's contract).
    let r = symbol_lookup(h, unsafe { cstr(name) }, v.as_ref(), caller);
    if r != 0 {
        succeed();
    }
    DL_LOCK.unlock();
    r as *mut c_void
}

// ---- dladdr ----

#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

/// Number of entries of the dynamic symbol table.
fn symbol_count(m: Map) -> usize {
    if m.gnu_nbuckets() != 0 {
        let max = m.gnu_bucket_words().iter().copied().max().unwrap_or(0);
        if max < m.gnu_symoffset() {
            return m.gnu_symoffset() as usize;
        }
        let mut i = max;
        loop {
            // SAFETY: the chain of the object's last bucket: entries up to one with bit 0 set (its own GNU hash table).
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

/// What dladdr finds for `addr`: the object and its nearest symbol.
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
        // SAFETY: i < the number of symbols of the table (`symbol_count`).
        let s = unsafe { m.sym(i) };
        let t = s.info & 0xf;
        let a = sym_value_addr(m.l_addr(), s);
        // glibc's rule (dl-addr.c): not TLS; the address is inside [value, value + size), or, for a symbol with no size or
        // an undefined one (a non-PIE program's canonical PLT address for a function it imports), exactly its value
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

/// Fill a `Dl_info` from what `addr_info` found.
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

/// # Safety
/// `info` points to a writable `Dl_info`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr(addr: usize, info: *mut DlInfo) -> c_int {
    DL_LOCK.lock();
    let r = match addr_info(addr) {
        None => 0,
        Some(i) => {
            // SAFETY: a writable `Dl_info` (caller's contract; NULL is not accepted, as in glibc).
            fill_dlinfo(&i, unsafe { &mut *info });
            1
        }
    };
    DL_LOCK.unlock();
    r
}

/// # Safety
/// `info` points to a writable `Dl_info`; `extra` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dladdr1(addr: usize, info: *mut DlInfo, extra: *mut *mut c_void, flags: c_int) -> c_int {
    DL_LOCK.lock();
    let r = match addr_info(addr) {
        None => 0,
        Some(i) => {
            // SAFETY: a writable `Dl_info` (caller's contract).
            fill_dlinfo(&i, unsafe { &mut *info });
            // SAFETY: NULL or writable (caller's contract).
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

// ---- dlinfo ----

/// # Safety
/// `handle` is NULL or a handle dlopen returned; `arg` points to what the request writes (glibc's sizes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void, _caller: usize) -> c_int {
    DL_LOCK.lock();
    let m = if handle.is_null() {
        main_map()
    } else {
        // SAFETY: a link map dlopen returned (caller's contract), not NULL here.
        match unsafe { Map::from_ptr(handle as *mut LinkMap) } {
            Some(m) => m,
            None => main_map(),
        }
    };
    // (each write through `arg` below: the object the request names, writable: caller's contract)
    let r = match request {
        1 => {
            // SAFETY: see above.
            unsafe { *(arg as *mut isize) = m.l_ns() };
            0
        }
        2 => {
            // SAFETY: see above.
            unsafe { *(arg as *mut *mut LinkMap) = m.as_ptr() };
            0
        }
        4 | 5 => {
            // SAFETY: see above (a Dl_serinfo of the size RTLD_DI_SERINFOSIZE reported).
            unsafe { serinfo(m, arg as *mut usize, request == 5) };
            0
        }
        6 => {
            let o = origin_of(m);
            // SAFETY: see above (glibc's buffer of at least PATH_MAX bytes).
            let dst = unsafe { crate::ffi::slice_mut(arg as *mut u8, o.len() + 1) };
            dst[..o.len()].copy_from_slice(o);
            dst[o.len()] = 0;
            0
        }
        9 => {
            // SAFETY: see above.
            unsafe { *(arg as *mut usize) = m.tls_modid() };
            0
        }
        10 => {
            // SAFETY: see above.
            unsafe { *(arg as *mut usize) = tls::current_block(m.tls_modid()) };
            0
        }
        11 => {
            // RTLD_DI_PHDR: the program headers; the result is their number
            // SAFETY: see above.
            unsafe { *(arg as *mut *const Phdr) = m.phdr() };
            m.phnum() as c_int
        }
        _ => {
            // CONFIGADDR (3), PROFILENAME (7), PROFILEOUT (8) and every unknown request
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

/// The directories of one search path list as glibc's `Dl_serinfo` shows them: `$ORIGIN` and friends expanded (against `ctx`),
/// an empty element is ".", trailing slashes are dropped ("/" stays), repeated directories of the same list appear once.
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

/// RTLD_DI_SERINFO / RTLD_DI_SERINFOSIZE (glibc's `_dl_rtld_di_serinfo`): the directories searched for the dependencies of `m`:
/// the RPATHs of the loaders (not the program's own, which glibc leaves out of this list), LD_LIBRARY_PATH, the RUNPATH of `m`,
/// the default directories (`flags` is 0 for all, as in glibc).
///
/// # Safety
/// `si` is a `Dl_serinfo`: when counting, its first two words are writable; otherwise it is as large as the size a counting
/// call reported, with `dls_cnt` as that call set it.
unsafe fn serinfo(m: Map, si: *mut usize, counting: bool) {
    // struct Dl_serinfo { size_t dls_size; unsigned dls_cnt; Dl_serpath dls_serpath[]; }, Dl_serpath { char *name; unsigned flags; }
    let cnt_ptr = si.wrapping_add(1) as *mut u32;
    if counting {
        // SAFETY: the first two words (caller's contract).
        unsafe { *si = 0 };
        // SAFETY: as above.
        unsafe { *cnt_ptr = 0 };
    }
    let ser = si.wrapping_add(2);
    // SAFETY: dls_cnt (caller's contract).
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
            // SAFETY: entry `idx` < dls_cnt of dls_serpath (the counting call counted the same directories).
            unsafe { *slot = alloc as usize };
            // SAFETY: the string area after the entries, as large as the counting call reported.
            let dst = unsafe { crate::ffi::slice_mut(alloc, name.len() + 1) };
            dst[..name.len()].copy_from_slice(name);
            dst[name.len()] = 0;
            alloc = alloc.wrapping_add(name.len() + 1);
            // SAFETY: the entry's flags word.
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
        // SAFETY: library_path is a string `dup` made or an argv string (both live for the process).
        each_dir(unsafe { cstr(st().library_path) }, main, &mut add);
    }
    if let Some(rp) = m.runpath() {
        each_dir(rp, Some(m), &mut add);
    }
    if m.flags_1() & 0x800 == 0 {
        // DF_1_NODEFLIB off: glibc's default directories
        add(b"/lib64");
        add(b"/usr/lib64");
    }
    if counting {
        // SAFETY: the first two words (caller's contract).
        unsafe { *cnt_ptr = count };
        // SAFETY: as above.
        unsafe { *si = total + 16 + count as usize * 16 };
    }
}

// ---- dl_iterate_phdr, _dl_find_object ----

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

/// # Safety
/// `cb` is NULL or a dl_iterate_phdr callback; `data` is passed to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_iterate_phdr(cb: Option<PhdrCb>, data: *mut c_void, caller: usize) -> c_int {
    let Some(cb) = cb else { return 0 };
    // the maps are listed under the lock and reported after it: in a 64-map list (the usual program), else in the 1024-map
    // list of `iterate_phdr_big`, out of line (an 8 KB array in this frame was on the stack of every unwinder walk that
    // asks for the objects, also on a thread with a small stack, FIXLIST #79)
    match iterate_phdr_in::<64>(&mut [None; 64], cb, data, caller) {
        Some(r) => r,
        None => iterate_phdr_big(cb, data, caller),
    }
}

/// [`__libc_ldso_iterate_phdr`] with room for 1024 maps (its parts: called only from there, with its arguments), the list in
/// a scratch mapping: 8 KB on the stack of the unwinding thread were too much for a small stack.
#[cold]
#[inline(never)]
fn iterate_phdr_big(cb: PhdrCb, data: *mut c_void, caller: usize) -> c_int {
    let mut s = Scratch::for_maps_or_die(1024);
    iterate_phdr_in::<1024>(s.maps::<1024>(), cb, data, caller).unwrap_or(0)
}

/// The maps of the caller's namespace (at most N; None, before any callback, when they do not fit and N is below 1024, where
/// the list was cut as before), each reported to `cb` until it returns non-zero. Called only by `__libc_ldso_iterate_phdr`
/// (directly or through `iterate_phdr_big`) with its arguments: `cb` is the program's dl_iterate_phdr callback.
#[inline(always)]
fn iterate_phdr_in<const N: usize>(list: &mut [Option<Map>; N], cb: PhdrCb, data: *mut c_void, caller: usize) -> Option<c_int> {
    let small = N < 1024;
    DL_LOCK.lock();
    let mut n = 0;
    let mut full = false;
    // the namespace of the caller is the one that is reported (glibc `__dl_iterate_phdr`)
    let nsid = ns_of(map_of_addr(caller));
    if nsid == 0 {
        // the program first, then the rest in load order
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
        // glibc lists the loader last
        if st().ldso_map.is_some() {
            if n < N {
                list[n] = st().ldso_map;
                n += 1;
            } else {
                full = true;
            }
        }
    } else {
        // another namespace: its maps in list order, the mirror of the loader described by the real map
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
        // SAFETY: the caller's callback with a valid `dl_phdr_info` on our stack and its size, and the caller's data.
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

/// # Safety
/// `result` points to a writable `struct dl_find_object`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_find_object(pc: usize, result: *mut DlFindObject) -> c_int {
    // no lock: the unwinder may call this while a lock-holding thread is being unwound; the list is only appended to
    let Some(m) = map_of_addr(pc) else { return -1 };
    let r = DlFindObject {
        dlfo_flags: 0,
        dlfo_map_start: m.map_start() as *mut c_void,
        dlfo_map_end: m.map_end() as *mut c_void,
        dlfo_link_map: m.as_ptr(),
        dlfo_eh_frame: m.eh_frame_hdr() as *mut c_void,
        reserved: [0; 7],
    };
    // SAFETY: writable (caller's contract).
    unsafe { result.write(r) };
    0
}

// ---- dlopen(..., __RTLD_SPROF): the handle glibc's `sprof` reads ----
//
// `sprof` dlopen()s the library it analyses with the private flag __RTLD_SPROF (nothing is relocated or run) and
// reads glibc's `struct link_map` directly: l_addr, l_name, l_info[DT_STRTAB / DT_SYMTAB / DT_SONAME] (through
// D_PTR, which adds l_addr when the l_ld_readonly bit is set), l_phdr, l_phnum, l_map_start. Our own map has another
// layout, so such an open returns a separate record that has glibc's field offsets (x86-64, glibc 2.43; the
// offsets are those compiled into /usr/bin/sprof and were checked against its disassembly) and points into the
// real map's data. dlclose of it frees the record (and unmaps a library that was mapped only for it).

const SPROF: c_int = 0x4000_0000;
const SH_SIZE: usize = 1024;
const SH_INFO: usize = 64;
const SH_NINFO: usize = 84; // DT_NUM 38 + DT_THISPROCNUM 4 + DT_VERSIONTAGNUM 16 + DT_EXTRANUM 3 + DT_VALNUM 12 + DT_ADDRNUM 11
const SH_PHDR: usize = 736;
const SH_ENTRY: usize = 744;
const SH_PHNUM: usize = 752;
const SH_FLAGS: usize = 852; // l_direct_opencount is at 848; the bit fields start here
const SH_MAP_START: usize = 912;
const SH_MAP_END: usize = 920;
const SH_OURS: usize = 960; // beyond glibc's fields that sprof reads: our own bookkeeping
const SH_MAP: usize = 968;
const SH_FRESH: usize = 976;
/// The records handed out (NULL: free). Under the loader lock.
static SPROF_HANDLES: SyncCell<[*mut u8; 16]> = SyncCell::new([null_mut(); 16]);

/// Index into glibc's `l_info` for a dynamic tag (None: not kept there), x86-64.
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
    // SAFETY: SPROF_HANDLES is used under the loader lock only.
    let slot = unsafe { SPROF_HANDLES.with_unsync(|t| t.iter().position(|h| h.is_null())) };
    let h = alloc_blk(SH_SIZE, 16);
    let (Some(slot), false) = (slot, h.is_null()) else {
        if fresh {
            drop_map(m);
        }
        set_error(format_args!("cannot allocate memory"));
        return None;
    };
    // SAFETY: a fresh zeroed block of SH_SIZE bytes, 16-aligned, ours until handed out.
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
    // SAFETY: the same block as bytes (the word view above is no longer used).
    let bytes = unsafe { crate::ffi::slice_mut(h, SH_SIZE) };
    bytes[SH_PHNUM..SH_PHNUM + 2].copy_from_slice(&(m.phnum() as u16).to_ne_bytes());
    // l_type = lt_loaded; l_ld_readonly (bit 21) when the dynamic section still holds link-time addresses
    bytes[SH_FLAGS] = 2;
    if !m.dyn_adjusted() {
        bytes[SH_FLAGS + 2] = 0x20;
    }
    // SAFETY: SPROF_HANDLES is used under the loader lock only.
    unsafe { SPROF_HANDLES.with_unsync(|t| t[slot] = h) };
    Some(h)
}

fn sprof_is_handle(h: *mut c_void) -> bool {
    // SAFETY: SPROF_HANDLES is used under the loader lock only (dlclose holds it).
    !h.is_null() && unsafe { SPROF_HANDLES.with_unsync(|t| t.contains(&(h as *mut u8))) }
}

/// # Safety
/// `h` is one of the records `sprof_open` made (`sprof_is_handle`), under the loader lock.
unsafe fn sprof_close(h: *mut u8) {
    // SAFETY: a record of SH_SIZE bytes (caller's contract).
    let rec = unsafe { crate::ffi::slice(h as *const usize, SH_SIZE / 8) };
    let (mp, fresh) = (rec[SH_MAP / 8] as *mut LinkMap, rec[SH_FRESH / 8] != 0);
    // SAFETY: the map `sprof_open` stored in the record.
    let m = unsafe { Map::from_ptr(mp) };
    // SAFETY: SPROF_HANDLES is used under the loader lock only.
    unsafe {
        SPROF_HANDLES.with_unsync(|t| {
            for e in t.iter_mut() {
                if *e == h {
                    *e = null_mut();
                }
            }
        })
    };
    // SAFETY: the record, allocated with SH_SIZE; no longer handed out.
    unsafe { free_blk(h, SH_SIZE, 16) };
    if let Some(m) = m.filter(|m| fresh && !m.relocated()) {
        drop_map(m);
    }
}

/// Append the maps of `root`'s scope that `d` cannot see yet to `d`'s extra scope.
fn add_extra_scope(d: Map, root: Map) {
    // a 32-map work list first (the usual case), else the `MAX_MAPS` one of `add_extra_scope_big`, out of line (a 4 KB array
    // in the frame of a dlopen, FIXLIST #79)
    if !add_extra_scope_in::<32>(&mut [None; 32], d, root) {
        add_extra_scope_big(d, root);
    }
}

/// The `MAX_MAPS` list of [`add_extra_scope`] (512 before) in a scratch mapping.
#[cold]
#[inline(never)]
fn add_extra_scope_big(d: Map, root: Map) {
    let mut s = Scratch::for_maps_or_die(MAX_MAPS);
    add_extra_scope_in::<MAX_MAPS>(s.maps::<MAX_MAPS>(), d, root);
}

/// [`add_extra_scope`] with an N-map list: false (nothing changed) when the list does not fit and N is below `MAX_MAPS`, where
/// it is cut as before at 512.
#[inline(always)]
fn add_extra_scope_in<const N: usize>(list: &mut [Option<Map>; N], d: Map, root: Map) -> bool {
    let small = N < MAX_MAPS;
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
    let arr = crate::util::perm_maps(n);
    arr.copy_from_slice(&list[..n]);
    // SAFETY: `n` maps (all `Some`), permanent.
    unsafe { d.set_xscope(arr.as_mut_ptr() as *mut *mut LinkMap) };
    // SAFETY: their count.
    unsafe { d.set_nxscope(n) };
    true
}
