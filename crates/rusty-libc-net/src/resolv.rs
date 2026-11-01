//! resolv.h and arpa/nameser.h functions: `res_init` and the `res_n*` family over a `struct __res_state`,
//! `res_mkquery`, `res_query`, `res_search`, `res_send`, `dn_comp`, `dn_expand`, `dn_skipname`,
//! `ns_name_*` and the `res_*ok` name checks.
//!
//! The state is converted to a [`crate::dns::Config`] for each call (name servers from `nsaddr_list` and
//! the IPv6 extension, search list from `dnsrch`, `ndots`, `retrans`, `retry`, `options`). Not provided:
//! the debugging printers (`p_query`, `fp_query`, ...), `res_hostalias`, `res_isourserver`, `res_nopt`
//! and the `__res_context_*` internals. Message parsing and printing (`ns_initparse`, `ns_sprintrr`, ...) is in [`crate::nsparse`].
//!
//! U2 (BRIEF-UNSAFE.md): the C functions convert their pointers once and call safe functions on references and slices
//! (`ninit`, `nquery`, `nsend`, `nmkquery`, `ntop`, `uncompress_name`, `expand`). What stays unsafe: the thread's state
//! blocks (malloc/free, the thread-exit handlers), the program-owned pointers inside `struct __res_state` (IPv6 server
//! addresses, the search list), and `ns_name_pack`'s compression table, whose message glibc reads without a bound.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::dns::{self, Config, Server};
use crate::strerr::set_h_errno;
use crate::types::*;
use crate::util::Buf;
use crate::wire;
use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi};

pub const MAXNS: usize = 3;
pub const MAXDNSRCH: usize = 6;
pub const MAXRESOLVSORT: usize = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SortEnt {
    pub addr: in_addr,
    pub mask: u32,
}

/// The IPv6 extension at the end of `struct __res_state`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResExt {
    pub nscount: u16,
    pub nsmap: [u16; MAXNS],
    pub nssocks: [c_int; MAXNS],
    pub nscount6: u16,
    pub nsinit: u16,
    pub nsaddrs: [*mut sockaddr_in6; MAXNS],
    /// glibc's `__glibc_extension_index` (programs see `unsigned int __glibc_reserved[2]`): the index of the configuration
    /// the state is attached to, XORed with glibc's INDEX_MAGIC (see [`attach_index`]).
    pub extension_index: u64,
}

/// `struct __res_state` (568 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResState {
    pub retrans: c_int,
    pub retry: c_int,
    pub options: c_ulong,
    pub nscount: c_int,
    pub nsaddr_list: [sockaddr_in; MAXNS],
    pub id: c_ushort,
    pub dnsrch: [*mut c_char; MAXDNSRCH + 1],
    pub defdname: [c_char; 256],
    pub pfcode: c_ulong,
    /// ndots:4, nsort:4, ipv6_unavail:1, unused:23
    pub bits: c_uint,
    pub sort_list: [SortEnt; MAXRESOLVSORT],
    pub qhook: *mut c_void,
    pub rhook: *mut c_void,
    pub res_h_errno: c_int,
    pub vcsock: c_int,
    pub flags: c_uint,
    pub u: ResExt,
}

impl ResState {
    /// An all-zero state, as glibc's `_res` and per-thread states start (`_vcsock` and `nssocks` 0 too; `res_init` sets
    /// them to -1).
    pub const fn zero() -> ResState {
        ResState {
            retrans: 0,
            retry: 0,
            options: 0,
            nscount: 0,
            nsaddr_list: [sockaddr_in { sin_family: 0, sin_port: 0, sin_addr: in_addr { s_addr: 0 }, sin_zero: [0; 8] }; MAXNS],
            id: 0,
            dnsrch: [core::ptr::null_mut(); MAXDNSRCH + 1],
            defdname: [0; 256],
            pfcode: 0,
            bits: 0,
            sort_list: [SortEnt { addr: in_addr { s_addr: 0 }, mask: 0 }; MAXRESOLVSORT],
            qhook: core::ptr::null_mut(),
            rhook: core::ptr::null_mut(),
            res_h_errno: 0,
            vcsock: 0,
            flags: 0,
            u: ResExt { nscount: 0, nsmap: [0; MAXNS], nssocks: [0; MAXNS], nscount6: 0, nsinit: 0, nsaddrs: [core::ptr::null_mut(); MAXNS], extension_index: 0 },
        }
    }
}

/// The data symbol `_res` (a compatibility symbol of glibc 2.43): the resolver state of the main
/// thread, which is what old programs that use `_res` directly mean (`__res_state()` returns its
/// address there, as `__resp` does in glibc). A `SyncCell` (same layout as the `ResState` it holds): C programs and the
/// main thread write it without a lock, as with glibc; other threads use their own block (see `__res_state`).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _res: SyncCell<ResState> = SyncCell::new(ResState::zero());

/// This thread's `__res_state()` (NULL until first used).
#[thread_local]
static RESP_PTR: Cell<*mut ResState> = Cell::new(core::ptr::null_mut());

/// A fresh block from the library's allocator holding `v` (NULL without memory). Freed with `rusty_libc_malloc::free`.
fn heap_new<T>(v: T) -> *mut T {
    let p = heap_alloc::<T>();
    if !p.is_null() {
        // SAFETY: `p` is a fresh block of `size_of::<T>()` bytes, aligned by malloc for any type, ours alone.
        unsafe { p.write(v) };
    }
    p
}

/// A block for a server's `_ext` copy (glibc's `malloc (sizeof (struct sockaddr_in6))` in res_send), not yet written; NULL
/// without memory. It goes into the state's `nsaddrs`, written there first ([`sync_ext`]). (Not zeroed here: the compiler
/// would turn malloc and the zeroing into one calloc call, which a program that replaces malloc would see.)
pub(crate) fn ext_block() -> *mut sockaddr_in6 {
    heap_alloc::<sockaddr_in6>()
}

/// A fresh block from the library's allocator (the public, interposable malloc) for a `T`, not yet written; NULL without
/// memory.
fn heap_alloc<T>() -> *mut T {
    // SAFETY: plain allocation.
    unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<T>()) }.cast()
}

/// A per-thread block holding `v`, kept in the thread-local `cell` and given back by `dtor` (one of the `release_*`
/// handlers, with `cell`'s address) when the thread exits; NULL (and `cell` untouched) without memory or a handler slot.
fn thread_block<T>(cell: &Cell<*mut T>, v: T, dtor: unsafe extern "C" fn(*mut c_void)) -> *mut T {
    let p = heap_new(v);
    if p.is_null() {
        return p;
    }
    if !rusty_libc_core::tls::register_thread_dtor(dtor, cell.as_ptr() as *mut c_void, 0) {
        // SAFETY: the block came from heap_new and was never handed out.
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
        return core::ptr::null_mut();
    }
    cell.set(p);
    p
}

/// The body of the thread-exit handlers: give back the thread's block in `slot` (unless it is `keep`) and forget it, so
/// that a later use in this thread makes a new one.
///
/// # Safety
/// `slot` is the exiting thread's cell registered by `thread_block` (still alive while its handlers run); its block came
/// from `heap_new`.
unsafe fn release<T>(slot: *mut *mut T, keep: *mut T) {
    // SAFETY: the caller's contract: the thread's own cell, nothing else uses it while the handlers run.
    let slot = unsafe { &mut *slot };
    if !slot.is_null() && *slot != keep {
        // SAFETY: the caller's contract: a block from heap_new, owned by this thread.
        unsafe { rusty_libc_malloc::free(*slot as *mut c_void) };
    }
    *slot = core::ptr::null_mut();
}

/// Thread-exit handler of a thread's resolver state block (`obj` is the address of the thread's `RESP_PTR`). The main
/// thread's `_res` is not a block.
unsafe extern "C" fn release_resp(obj: *mut c_void) {
    // glibc's __res_thread_freeres: a state set up (nscount not 0) gets `__res_iclose(&_res, true)`, which closes the
    // sockets RES_STAYOPEN kept, frees the server copies and gives back the configuration index
    if !STATE_LENT.get() {
        with_this_state(|st| {
            if st.nscount != 0 {
                iclose(st, true);
                st.options = 0;
            }
        });
    }
    // SAFETY: registered by `thread_block` with the thread's `RESP_PTR`.
    unsafe { release(obj as *mut *mut ResState, _res.as_ptr()) }
}

/// `&_res` of this thread: the global `_res` in the main thread, a per-thread state elsewhere. The per-thread state (about
/// 570 bytes) is allocated on first use and freed when the thread exits: it is not in the thread's static TLS, which every
/// thread pays for (and every dlmopen namespace's copy of libc.so.6). Without memory the thread gets the shared `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_state() -> *mut ResState {
    if RESP_PTR.get().is_null() {
        // the initial thread uses `_res` (glibc: `__resp` starts as `&_res` there; no system call to tell)
        let main = rusty_libc_core::tls::is_initial_thread();
        RESP_PTR.set(_res.as_ptr());
        if !main {
            thread_block(&RESP_PTR, ResState::zero(), release_resp);
        }
    }
    RESP_PTR.get()
}

/// Set while `with_this_state` lends the calling thread's state out.
#[thread_local]
static STATE_LENT: Cell<bool> = Cell::new(false);

/// Run `f` with the calling thread's resolver state (`*__res_state()`).
///
/// This is the library's only safe way to that state, and it refuses to nest (it panics, which aborts in the library), so
/// `f` holds the only Rust reference to it. The main thread's `_res` is also the C program's, which writes it without a lock
/// as with glibc, but no C code runs inside `f`. (A thread that got no memory for its own state shares `_res`, racing as
/// such programs race on glibc's `_res`.)
pub(crate) fn with_this_state<R>(f: impl FnOnce(&mut ResState) -> R) -> R {
    assert!(!STATE_LENT.replace(true), "resolver state lent twice");
    // SAFETY: `__res_state` returns a valid, aligned state that lives until the thread exits; no other reference to it is
    // live (see above).
    let r = f(unsafe { &mut *__res_state() });
    STATE_LENT.set(false);
    r
}

/// `__res_randomid`: a random 16-bit query id.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_randomid() -> c_uint {
    let mut idb = [0u8; 2];
    let _ = dns::getrandom2(&mut idb);
    u16::from_ne_bytes(idb) as c_uint
}

fn set_herr(st: &mut ResState, h: c_int) {
    set_h_errno(h);
    st.res_h_errno = h;
}

// ---------------------------------------------------------------- state <-> Config

/// `res_nclose`: give back the IPv6 server addresses of the state.
pub fn nclose(s: &mut ResState) {
    for i in 0..MAXNS {
        free_ext(s, i);
    }
}

/// Free the `_ext` address of server slot `i` (when not NULL) and set it to NULL.
fn free_ext(s: &mut ResState, i: usize) {
    let p = s.u.nsaddrs[i];
    if !p.is_null() {
        // SAFETY: a non-NULL entry is a block `fill` or `sync_ext` got from the library's allocator (or one the program put
        // there for the library to free, as glibc's res_nclose does).
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
        s.u.nsaddrs[i] = core::ptr::null_mut();
    }
}

/// `res_ninit`: fill `s` from the process-wide configuration and mark it initialised.
/// Without memory for the configuration index it fails with ENOMEM and leaves the state as it was (glibc's `__res_vinit`:
/// `__resolv_conf_attach` fails before `update_from_conf`).
pub fn ninit(s: &mut ResState) -> c_int {
    let (cfg, generation) = dns::default_config_gen();
    let Some(index) = attach_index() else {
        errno::set(ENOMEM);
        return -1;
    };
    nclose(s);
    fill(s, &cfg, index);
    remember_init(s, generation);
    0
}

/// [`ninit`] for the implicit init before a lookup: without memory for the index the state is still set up, with index 0
/// (glibc's `maybe_init` makes the lookup fail instead; not copied, see FIXLIST #138).
fn ninit_implicit(s: &mut ResState) {
    if ninit(s) < 0 {
        let (cfg, generation) = dns::default_config_gen();
        nclose(s);
        fill(s, &cfg, 0);
        remember_init(s, generation);
    }
}

/// The values glibc's `has_preinit_values` looks for: `retrans`, `retry` or `options` (apart from `RES_INIT`) set to
/// something other than zero and the defaults.
fn has_preinit_values(s: &ResState) -> bool {
    (s.retrans != 0 && s.retrans != 5)
        || (s.retry != 0 && s.retry != 2)
        || (s.options != 0 && (s.options & !(dns::RES_INIT as c_ulong)) != dns::RES_DEFAULT as c_ulong)
}

/// `res_init` on the calling thread's state, as glibc 2.43 (res_libc.c `res_init`, res_init.c `__res_vinit` with
/// preinit): `retrans` and `retry` a program set before the call are kept (zero means the default), `options` only when
/// the program also set `RES_INIT` in them; when any of them differs from the defaults the file is read again starting
/// from them (resolv.conf and `RES_OPTIONS` still apply over them), else the process-wide configuration is used. The
/// state is then attached to a configuration that is not the process-wide one, so the next lookup that finds the state
/// unchanged replaces it with the process-wide configuration, as glibc's `maybe_init` does (see `current_config`).
pub fn init_preinit(s: &mut ResState) -> c_int {
    if s.retrans == 0 {
        s.retrans = 5;
    }
    if s.retry == 0 {
        s.retry = 2;
    }
    if s.options & dns::RES_INIT as c_ulong == 0 {
        s.options = dns::RES_DEFAULT as c_ulong;
    } else if s.nscount > 0 {
        // glibc's res_init on a state set up before: `__res_iclose (&_res, true)` (sockets closed, copies freed, index
        // given back)
        iclose(s, true);
    }
    let (cfg, generation) = if has_preinit_values(s) {
        let path = crate::nss::etc_path(b"/resolv.conf");
        (dns::Config::load_preinit(&path, s.retrans, s.retry, s.options as u32), 0)
    } else {
        dns::default_config_gen()
    };
    // glibc's __res_vinit: no memory for the configuration index fails with ENOMEM before the state is filled
    let Some(index) = attach_index() else {
        errno::set(ENOMEM);
        return -1;
    };
    nclose(s);
    fill(s, &cfg, index);
    s.id = __res_randomid() as c_ushort;
    remember_init(s, generation);
    0
}

/// After an init of the calling thread's own state: remember what it was set to and from which configuration
/// (`generation` 0: not the process-wide one).
fn remember_init(s: &ResState, generation: u64) {
    if core::ptr::eq(s, __res_state()) {
        let snap = init_snap_slot();
        if !snap.is_null() {
            let c = config_of(s);
            // SAFETY: the slot is this thread's own block (init_snap_slot), initialised, and not borrowed elsewhere.
            unsafe { *snap = Some((c, generation)) };
        }
    }
}

/// Write `cfg` into `s` and mark it initialised, as glibc 2.43's `update_from_conf` (resolv_conf.c): `_vcsock` -1, the
/// servers' `nssocks` -1, `_u._ext.nscount` 0 (res_send makes its copy on the first send), `nsaddrs` only for IPv6 servers;
/// `nsmap`, `nscount6`, `nsinit` and the `nssocks` past the servers are left as they were (glibc 2.43 never writes them).
/// The rest of the state is rewritten.
fn fill(s: &mut ResState, cfg: &Config, index: u64) {
    let old = s.u;
    *s = ResState::zero();
    s.vcsock = -1;
    s.u.nsmap = old.nsmap;
    s.u.nscount6 = old.nscount6;
    s.u.nsinit = old.nsinit;
    s.u.nssocks = old.nssocks;
    s.retrans = (cfg.timeout_ms / 1000) as c_int;
    s.retry = cfg.attempts;
    s.options = (cfg.options | dns::RES_INIT) as c_ulong;
    s.bits = (cfg.ndots & 0xf) | ((cfg.nsort.min(MAXRESOLVSORT) as c_uint) << 4);
    for (e, &(addr, mask)) in s.sort_list.iter_mut().zip(&cfg.sort[..cfg.nsort.min(MAXRESOLVSORT)]) {
        *e = SortEnt { addr: in_addr { s_addr: addr }, mask };
    }
    s.id = 0;
    let mut n4 = 0usize;
    for i in 0..cfg.nservers.min(MAXNS) {
        let sv = cfg.servers[i];
        if sv.family == AF_INET {
            s.nsaddr_list[n4] = sockaddr_in { sin_family: AF_INET as u16, sin_port: sv.port.to_be(), sin_addr: in_addr { s_addr: u32::from_ne_bytes([sv.addr[0], sv.addr[1], sv.addr[2], sv.addr[3]]) }, sin_zero: [0; 8] };
        } else {
            let p = heap_new(sockaddr_in6 { sin6_family: AF_INET6 as u16, sin6_port: sv.port.to_be(), sin6_flowinfo: 0, sin6_addr: in6_addr { s6_addr: sv.addr }, sin6_scope_id: sv.scope });
            if !p.is_null() {
                s.u.nsaddrs[i] = p;
            }
            s.nsaddr_list[i].sin_family = 0;
        }
        n4 += 1;
        s.u.nssocks[i] = -1;
    }
    s.nscount = n4 as c_int;
    s.u.extension_index = index;
    // search list: names stored one after the other in defdname
    let mut off = 0usize;
    for i in 0..cfg.nsearch.min(MAXDNSRCH) {
        let b = cfg.search[i].as_bytes();
        if off + b.len() + 1 > 256 {
            break;
        }
        for (k, c) in b.iter().enumerate() {
            s.defdname[off + k] = *c as c_char;
        }
        s.defdname[off + b.len()] = 0;
        s.dnsrch[i] = s.defdname.as_mut_ptr().wrapping_add(off);
        off += b.len() + 1;
    }
}

/// Fill `st` from the process-wide configuration and mark it initialised.
///
/// # Safety
/// `st` points to a writable state.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_ninit(st: *mut ResState) -> c_int {
    // SAFETY: the caller's contract (glibc dereferences the state as well: NULL faults there too).
    ninit(unsafe { &mut *st })
}

/// # Safety
/// The calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_init() -> c_int {
    with_this_state(init_preinit)
}

/// `res_nclose`, as glibc 2.43 (`__res_iclose(statp, true)`).
///
/// # Safety
/// `st` points to a state set up by `res_ninit` (or zeroed).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nclose(st: *mut ResState) {
    // SAFETY: the caller's contract.
    iclose(unsafe { &mut *st }, true)
}

/// glibc's `__res_iclose`: close the sockets of the state: `_vcsock` when it is 0 or more (then -1, RES_F_VC and RES_F_CONN
/// cleared) and the `nssocks` entry that is not -1 of each server slot below `nscount` with an `_ext` address (then -1).
/// Like glibc this closes whatever descriptor the state names, also the 0 of a state never set up by res_init. With
/// `free_addr` also free those slots' `_ext` addresses and give back the configuration index (`res_nclose`).
pub fn iclose(s: &mut ResState, free_addr: bool) {
    if s.vcsock >= 0 {
        let _ = rusty_libc_core::unistd::close(s.vcsock);
        s.vcsock = -1;
        s.flags &= !(RES_F_VC | RES_F_CONN);
    }
    for ns in 0..(s.nscount.max(0) as usize).min(MAXNS) {
        if s.u.nsaddrs[ns].is_null() {
            continue;
        }
        if s.u.nssocks[ns] != -1 {
            let _ = rusty_libc_core::unistd::close(s.u.nssocks[ns]);
            s.u.nssocks[ns] = -1;
        }
        if free_addr {
            free_ext(s, ns);
        }
    }
    if free_addr {
        detach_index(s);
    }
}

/// # Safety
/// As `res_nclose`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_iclose(st: *mut ResState, free_addr: bool) {
    // SAFETY: the caller's contract.
    iclose(unsafe { &mut *st }, free_addr)
}

/// The address in `_u._ext.nsaddrs[i]` of `s` (None when NULL).
pub(crate) fn ext_addr(s: &ResState, i: usize) -> Option<sockaddr_in6> {
    let p = s.u.nsaddrs[i];
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-NULL `nsaddrs` entry points to a `sockaddr_in6`: a block `fill` or `sync_ext` got from the library's
    // allocator, or one the program put there (glibc reads and writes it the same way).
    Some(unsafe { *p })
}

/// glibc's `sock_eq` for an `nsaddr_list` entry `a` (family not 0) and the `_ext` copy `b`: same family, port and address,
/// or an IPv4 address and its v4-mapped IPv6 form. (An `nsaddr_list` entry claiming AF_INET6, which glibc reads 28 bytes
/// of, counts as different: the copy is then made again, which writes the same bytes.)
fn sock_eq(a: &sockaddr_in, b: &sockaddr_in6) -> bool {
    let b4_addr = b.sin6_flowinfo; // the `sin_addr` of a sockaddr_in stored in the block
    if a.sin_family == b.sin6_family {
        return a.sin_family == AF_INET as u16 && a.sin_port == b.sin6_port && a.sin_addr.s_addr == b4_addr;
    }
    a.sin_family == AF_INET as u16
        && a.sin_port == b.sin6_port
        && b.sin6_addr.s6_addr[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        && u32::from_ne_bytes([b.sin6_addr.s6_addr[12], b.sin6_addr.s6_addr[13], b.sin6_addr.s6_addr[14], b.sin6_addr.s6_addr[15]]) == a.sin_addr.s_addr
}

/// glibc 2.43 `__res_context_send`'s private copy of the server list, run on the state after a send that got past the
/// "no name server" check (so `nscount` > 0): a copy made before is dropped when `nscount` or an `nsaddr_list` entry
/// changed since (its `__res_iclose` was done on the sockets by the send, see [`state_socks`]); then, when there is no
/// copy, every server with an `nsaddr_list` family gets its `sockaddr_in` in its `nsaddrs` block (allocated when NULL; the
/// rest of the `sockaddr_in6` zero), its `nssocks` entry -1, and `_ext.nscount` is set to `nscount`. IPv6 servers (family
/// 0) keep the block `res_init` made. The sockets the send left (kept under RES_STAYOPEN) are written over the `nssocks`
/// entries afterwards ([`end_lookup`]). The new blocks are the ones the send got (`ext`, see [`dns::PreSend::alloc`]): where
/// it got none the send failed, as glibc's, and the copy stops there (`_ext.nscount` stays 0).
pub fn sync_ext(s: &mut ResState, ext: &[*mut sockaddr_in6; MAXNS]) {
    let n = (s.nscount.max(0) as usize).min(MAXNS);
    if n == 0 {
        return;
    }
    if s.u.nscount != 0 {
        let changed = c_int::from(s.u.nscount) != s.nscount
            || (0..n).any(|ns| s.nsaddr_list[ns].sin_family != 0 && !ext_addr(s, ns).is_some_and(|b| sock_eq(&s.nsaddr_list[ns], &b)));
        if changed {
            // the send closed the sockets (dns::Socks::begin) and they are written back after this
            s.u.nscount = 0;
        }
    }
    if s.u.nscount == 0 {
        for ns in 0..n {
            s.u.nssocks[ns] = -1;
            let a = s.nsaddr_list[ns];
            if a.sin_family == 0 {
                continue;
            }
            let mut z = [0u8; 16];
            z[..8].copy_from_slice(&a.sin_zero);
            let v = sockaddr_in6 { sin6_family: a.sin_family, sin6_port: a.sin_port, sin6_flowinfo: a.sin_addr.s_addr, sin6_addr: in6_addr { s6_addr: z }, sin6_scope_id: 0 };
            let mut p = s.u.nsaddrs[ns];
            if p.is_null() {
                if ext[ns].is_null() {
                    // no memory: glibc's send returned -1 here
                    return;
                }
                p = ext[ns];
                s.u.nsaddrs[ns] = p;
            }
            // SAFETY: as in `ext_addr`: a non-NULL entry is a writable `sockaddr_in6` (glibc copies into it the same way); a
            // block from `ext_block` is one.
            unsafe { p.write(v) };
        }
        s.u.nscount = s.nscount as u16;
    }
}

/// glibc's private `_flags` bits for the TCP connection (resolv/resolv-internal.h).
const RES_F_VC: c_uint = dns::RES_F_VC;
const RES_F_CONN: c_uint = dns::RES_F_CONN;

/// The sockets of `s` as glibc's res_send finds them, to lend to the sends of a lookup on `s` (see [`dns::StateSocks`]):
/// with what its start does to them when its copy of the servers is stale or not yet made (as [`sync_ext`] decides).
fn state_socks(s: &ResState) -> dns::StateSocks {
    let n = (s.nscount.max(0) as usize).min(MAXNS);
    let has_ext: [bool; MAXNS] = core::array::from_fn(|i| !s.u.nsaddrs[i].is_null());
    let needclose = s.u.nscount != 0
        && (c_int::from(s.u.nscount) != s.nscount
            || (0..n).any(|ns| s.nsaddr_list[ns].sin_family != 0 && !ext_addr(s, ns).is_some_and(|b| sock_eq(&s.nsaddr_list[ns], &b))));
    let fresh = s.u.nscount == 0 || needclose;
    let after: [bool; MAXNS] = core::array::from_fn(|i| has_ext[i] || (fresh && i < n && s.nsaddr_list[i].sin_family != 0));
    let alloc: [bool; MAXNS] = core::array::from_fn(|i| fresh && i < n && s.nsaddr_list[i].sin_family != 0 && !has_ext[i]);
    dns::StateSocks {
        udp: s.u.nssocks,
        vc: s.vcsock,
        vc_flags: s.flags & (RES_F_VC | RES_F_CONN),
        nscount: n,
        has_ext,
        presend: Some(dns::PreSend { needclose, fresh, has_ext: after, alloc }),
        ext: [core::ptr::null_mut(); MAXNS],
    }
}

/// Lend the sockets of `s` to the sends of a lookup on it; returns what [`end_lookup`] needs to give back.
fn begin_lookup(s: &ResState) -> Option<dns::StateSocks> {
    dns::reset_send_marks();
    dns::lend_state_socks(state_socks(s))
}

/// After a lookup on `s` that [`begin_lookup`] started: the h_errno its queries and searches wrote; when a send was made,
/// its copy of the servers ([`sync_ext`]); then the sockets as the sends left them.
fn end_lookup(s: &mut ResState, prev: Option<dns::StateSocks>) {
    // glibc's res_query and res_search write the state's res_h_errno (RES_SET_H_ERRNO) whenever they set h_errno, also
    // inside gethostbyname, getaddrinfo and the other name service lookups on the thread's `_res`
    if let Some(h) = dns::take_res_herr() {
        s.res_h_errno = h;
    }
    let k = dns::take_state_socks();
    if dns::take_send_reached() {
        sync_ext(s, &k.map_or([core::ptr::null_mut(); MAXNS], |k| k.ext));
    }
    if let Some(k) = k {
        s.u.nssocks = k.udp;
        s.vcsock = k.vc;
        s.flags = (s.flags & !(RES_F_VC | RES_F_CONN)) | k.vc_flags;
    }
    dns::restore_state_socks(prev);
}

/// glibc's INDEX_MAGIC (resolv_conf.c), XORed into `__glibc_extension_index`.
const INDEX_MAGIC: u64 = 0x26a8_fa5e_48af_8061;

/// glibc 2.43's table of configuration indexes (resolv_conf.c `struct resolv_conf_global`: `array`, `free_list_start`):
/// 8-byte slots, a used one holding 2 (glibc: the configuration's pointer), a free one the next free slot as
/// `(index << 1) | 1` (0: the end of the list); a freed slot goes to the front of the free list and is the next one taken.
struct IndexTable {
    slots: crate::nss::ZBuf,
    len: usize,
    free_start: u64,
    /// The table could not grow once: glibc's dynarray is then marked failed (array freed, size 0) for good, and every
    /// later attach fails with ENOMEM.
    failed: bool,
}

static INDEX_TABLE: crate::util::Spin<IndexTable> = crate::util::Spin::new(IndexTable { slots: crate::nss::ZBuf::new(), len: 0, free_start: 0, failed: false });

impl IndexTable {
    fn get(&self, i: usize) -> u64 {
        let b = &self.slots.as_slice()[i * 8..i * 8 + 8];
        u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
    fn set(&mut self, i: usize, v: u64) {
        self.slots.as_mut_slice()[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
    }
}

/// glibc's `__resolv_conf_attach` for the index: take the first free slot, or a new one at the end of the table; returns
/// the value for the state's `__glibc_extension_index` (the index XOR INDEX_MAGIC). The table grows as glibc's dynarray
/// does (4 slots, then `n + n/2 + 1`), so it needs memory at the same points; None without it (glibc's res_init then
/// fails with ENOMEM before it changes the state). As glibc's dynarray, a table that could not grow is dropped and stays
/// failed: every later attach fails too (glibc would even take a slot left on the free list from the freed table and
/// stop on an assertion; here that fails with ENOMEM as well).
fn attach_index() -> Option<u64> {
    let mut t = INDEX_TABLE.lock();
    if t.failed {
        return None;
    }
    let index = if t.free_start & 1 != 0 {
        let i = (t.free_start >> 1) as usize;
        t.free_start = t.get(i);
        i
    } else {
        let i = t.len;
        let cap = t.slots.cap() / 8;
        if i >= cap {
            let ncap = if cap == 0 { 4 } else { cap + cap / 2 + 1 };
            if !t.slots.grow(ncap * 8) {
                // glibc's mark_failed: the array is freed and its size is 0 (so no index is given back to it later)
                t.slots = crate::nss::ZBuf::new();
                t.len = 0;
                t.failed = true;
                return None;
            }
        }
        t.len += 1;
        i
    };
    t.set(index, 2);
    Some(index as u64 ^ INDEX_MAGIC)
}

/// glibc's `__resolv_conf_detach`: give the state's slot back (when its index names a used slot) and clear the index.
fn detach_index(s: &mut ResState) {
    let index = s.u.extension_index ^ INDEX_MAGIC;
    let mut t = INDEX_TABLE.lock();
    if index < t.len as u64 {
        let i = index as usize;
        let v = t.get(i);
        // a used slot: glibc tests only the low bit (a slot freed when the free list was empty holds 0, and glibc would
        // crash on it; it counts as free here)
        if v & 1 == 0 && v != 0 {
            let head = t.free_start;
            t.set(i, head);
            t.free_start = ((i as u64) << 1) | 1;
        }
    }
    drop(t);
    s.u.extension_index = 0;
}

/// The configuration of the calling thread's state for one name lookup (see [`current_config`]); its sends use the state's
/// sockets, and when it is dropped after the lookup the state gets them back with the copy of the servers a send made
/// ([`end_lookup`]), as glibc's res_send does on the thread's `_res`.
pub struct LookupConfig(Config, Option<dns::StateSocks>);

impl core::ops::Deref for LookupConfig {
    type Target = Config;
    fn deref(&self) -> &Config {
        &self.0
    }
}

impl Drop for LookupConfig {
    fn drop(&mut self) {
        let prev = self.1.take();
        if STATE_LENT.get() {
            dns::restore_state_socks(prev);
        } else {
            with_this_state(|st| end_lookup(st, prev));
        }
    }
}

/// glibc 2.43's `maybe_init` (resolv_context.c) before each use of a state: initialise it when `RES_INIT` is not set;
/// else, unless it has `RES_NORELOAD` (see below), a state still equal to what the last init of the calling thread's own state left
/// in it is rewritten with the process-wide configuration when that is another one now (resolv.conf changed, or
/// `res_init` read the file with preinit values). Returns the process-wide configuration when the state is (now) equal
/// to it, `None` when the state is to be used as it is (edited by the program, not the thread's own, or `RES_NORELOAD`).
fn ensure_init(s: &mut ResState) -> Option<Config> {
    if s.options & dns::RES_INIT as c_ulong == 0 {
        ninit_implicit(s);
    }
    let generation = unchanged_since_init(s);
    // RES_NORELOAD in a state set from the process-wide configuration came from it, which then never reloads from the
    // file (dns::default_config): it changes only by the Rust API's set_default_config / reset_default, which a state
    // left as it was follows
    if s.options & dns::RES_NORELOAD as c_ulong != 0 && generation.is_none_or(|g| g == 0) {
        return None;
    }
    let generation = generation?;
    let (current, now) = dns::default_config_gen();
    if generation != now {
        // glibc's maybe_init reattaching the state: `__res_iclose (resp, true)` when it has servers
        if s.nscount > 0 {
            iclose(s, true);
        }
        nclose(s);
        // (without memory for the index glibc's maybe_init fails the lookup; here the state gets index 0)
        fill(s, &current, attach_index().unwrap_or(0));
        remember_init(s, now);
    }
    Some(current)
}

/// The generation `remember_init` noted when `s` is the calling thread's own state and still holds what that init put
/// there.
fn unchanged_since_init(s: &ResState) -> Option<u64> {
    if !core::ptr::eq(s, __res_state()) {
        return None;
    }
    let slot = INIT_SNAP.get();
    // SAFETY: a non-NULL slot is this thread's initialised snapshot block; nothing writes it while this reference lives (it
    // is only reached from this thread, and the reference ends before this function returns).
    let snapshot: Option<&Snapshot> = unsafe { slot.as_ref() };
    match snapshot {
        Some(Some((snap, generation))) if same_config(snap, &config_of(s)) => Some(*generation),
        _ => None,
    }
}

fn config_of(s: &ResState) -> Config {
    let mut c = Config::defaults();
    c.options = (s.options as u32) & !dns::RES_INIT;
    c.ndots = s.bits & 0xf;
    // as glibc reads the state: retrans 0 or below gives one second per try, retry 0 or below no try
    c.timeout_ms = s.retrans as i64 * 1000;
    c.attempts = s.retry;
    c.nservers = 0;
    // glibc's __res_get_nsaddr: `nsaddr_list[i]` unless its family is 0 and `_u._ext.nsaddrs[i]` holds an address (an
    // IPv6 server; after a query the IPv4 servers have copies there too, which are not read). Every slot below `nscount`
    // is a server, also one glibc cannot use: its send then fails when it reaches that slot (dns::Socks::open, send_vc).
    // No server (`nscount` 0 or below) stays so: glibc's send fails with ESRCH (dns::Send::run).
    for i in 0..(s.nscount.max(0) as usize).min(MAXNS) {
        let a = s.nsaddr_list[i];
        let port = u16::from_be(a.sin_port);
        c.servers[c.nservers] = match (s.nsaddr_list[i].sin_family == 0).then(|| ext_addr(s, i)).flatten() {
            Some(a6) => Server::v6(a6.sin6_addr.s6_addr, u16::from_be(a6.sin6_port), a6.sin6_scope_id),
            None if a.sin_family == AF_INET as u16 => Server::v4(a.sin_addr.s_addr.to_ne_bytes(), port),
            None => {
                let mut b = [0u8; 12];
                b[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
                b[4..].copy_from_slice(&a.sin_zero);
                if a.sin_family == AF_INET6 as u16 {
                    // AF_INET6 written into an IPv4 slot: glibc reads a sockaddr_in6 from there (into the next slot);
                    // here the address is the slot's sin_zero followed by zeros
                    let mut v6 = [0u8; 16];
                    v6[..8].copy_from_slice(&a.sin_zero);
                    Server::v6(v6, port, 0)
                } else {
                    Server::other(c_int::from(a.sin_family), b, port)
                }
            }
        };
        c.nservers += 1;
    }
    c.nsearch = 0;
    for &p in s.dnsrch.iter().take(MAXDNSRCH) {
        if p.is_null() {
            break;
        }
        // SAFETY: the search list holds C strings up to its first NULL (into defdname, or the program's own strings, which
        // glibc reads the same way).
        if let Some(b) = Buf::<256>::from(unsafe { ffi::cstr_bytes(p) }) {
            c.search[c.nsearch] = b;
            c.nsearch += 1;
        }
    }
    c
}

/// The configuration `res_init` left in this thread's state and the generation of the process-wide configuration it came
/// from (0: a preinit configuration), `None` until it ran. A block of about 1.7 KB allocated on first use and freed when
/// the thread exits, for the same reason as the state itself (see `__res_state`).
type Snapshot = Option<(Config, u64)>;

#[thread_local]
static INIT_SNAP: Cell<*mut Snapshot> = Cell::new(core::ptr::null_mut());

unsafe extern "C" fn release_snap(obj: *mut c_void) {
    // SAFETY: registered by `thread_block` with the thread's `INIT_SNAP`.
    unsafe { release(obj as *mut *mut Snapshot, core::ptr::null_mut()) }
}

/// The thread's snapshot slot, made on first use; null when there is no memory (the snapshot is then not kept, and the
/// state is served from the thread's own settings as for a program that edited it).
fn init_snap_slot() -> *mut Snapshot {
    if INIT_SNAP.get().is_null() {
        return thread_block(&INIT_SNAP, None, release_snap);
    }
    INIT_SNAP.get()
}

fn same_config(a: &Config, b: &Config) -> bool {
    a.nservers == b.nservers
        && a.servers[..a.nservers] == b.servers[..b.nservers]
        && a.nsearch == b.nsearch
        && (0..a.nsearch).all(|i| a.search[i].as_bytes() == b.search[i].as_bytes())
        && a.ndots == b.ndots
        && a.timeout_ms == b.timeout_ms
        && a.attempts == b.attempts
        && a.options == b.options
}

/// glibc's `__resolv_context_get` for the calling thread's state, without a lookup: initialise it like `maybe_init` (a
/// state without RES_INIT gets `res_ninit`; one still equal to the last init follows a changed resolv.conf).
pub fn init_this_state() {
    with_this_state(|st| {
        ensure_init(st);
    });
}

/// The configuration the name-lookup functions (`gethostbyname*`, `getaddrinfo`, `getnameinfo`, ...) use: the calling
/// thread's resolver state (`_res` / `__res_state()`), initialised like `res_init` when it is not yet, so a program
/// that edits its state gets its settings honoured, as in glibc. A state still equal to what `res_init` made is
/// served from the process-wide configuration, which follows changes of resolv.conf; when that configuration is another
/// one than the state was set from (resolv.conf changed, or `res_init` read it with preinit values), the state is
/// rewritten with it first, as glibc 2.43's `maybe_init` reattaches it. A state with `RES_NORELOAD` is used as it is.
pub fn current_config() -> LookupConfig {
    with_this_state(|st| {
        let c = ensure_init(st).unwrap_or_else(|| config_of(st));
        LookupConfig(c, begin_lookup(st))
    })
}

/// A failed query: h_errno from the error, and errno as glibc's send leaves it (ECONNREFUSED when no server could be
/// reached, ETIMEDOUT when none answered in time), which callers such as `res_gethostbyname` test.
fn herr_result(st: &mut ResState, e: dns::HErr) -> c_int {
    if e.errno != 0 {
        errno::set(e.errno);
    }
    set_herr(st, e.h);
    -1
}

/// The arguments the `res_n*` shells share: the state, a name (None for NULL) and the caller's buffer (None for NULL, else
/// `len` bytes, none when negative).
///
/// # Safety
/// `st` points to a writable state; `name` is NULL or a C string; a non-NULL `buf` is writable for `len` bytes; none of them
/// is used by anything else during the call.
unsafe fn qargs<'a>(st: *mut ResState, name: *const c_char, buf: *mut c_uchar, len: c_int) -> (&'a mut ResState, Option<&'a [u8]>, Option<&'a mut [u8]>) {
    // SAFETY: the caller's contract.
    let name = unsafe { ffi::cstr(name) }.map(CStr::to_bytes);
    let buf = if buf.is_null() {
        None
    } else {
        // SAFETY: the caller's contract.
        Some(unsafe { ffi::bytes_mut(buf, len.max(0) as usize) })
    };
    // SAFETY: the caller's contract (glibc dereferences the state too: a NULL one faults there as well).
    (unsafe { &mut *st }, name, buf)
}

/// h_errno after a query that got an answer, as glibc 2.43: res_query leaves it (and the state's res_h_errno) as it was;
/// res_search leaves what it set while searching (HOST_NOT_FOUND when it starts, then each failed name's value).
fn query_ok(st: &mut ResState, search: bool) {
    if search {
        set_herr(st, dns::search_herr());
    }
}

/// The answer was received into our own buffer (the caller's could not hold a header): copy what fits, as glibc does.
fn finish_answer(ans: &[u8], n: usize, answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    let m = n.min(anslen.max(0) as usize);
    if let Some(b) = answer {
        b[..m].copy_from_slice(&ans[..m]);
    }
    m as c_int
}

/// `res_nquery` (`search` false) or `res_nsearch` (true) over references: `answer` is the caller's buffer (None for NULL)
/// and `anslen` its length as given. A buffer that can hold a header receives the answer directly (as glibc does: a longer
/// TCP answer is cut to it and its whole length returned, a longer UDP answer is cut).
pub fn nquery(st: &mut ResState, search: bool, name: &[u8], class: c_int, ty: c_int, answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    ensure_init(st);
    let cfg = config_of(st);
    let prev = begin_lookup(st);
    let r = nquery_cfg(st, &cfg, search, name, class, ty, answer, anslen);
    end_lookup(st, prev);
    r
}

fn nquery_cfg(st: &mut ResState, cfg: &Config, search: bool, name: &[u8], class: c_int, ty: c_int, answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    let run = |buf: &mut [u8], adv: usize| if search { dns::search_adv(cfg, name, class as u16, ty as u16, buf, adv) } else { dns::query_adv(cfg, name, class as u16, ty as u16, buf, adv) };
    match answer {
        Some(buf) if anslen >= wire::HFIXEDSZ as c_int => match run(buf, anslen as usize) {
            Ok(n) => {
                query_ok(st, search);
                n as c_int
            }
            Err(e) => herr_result(st, e),
        },
        answer => {
            let mut ans = [0u8; 4096];
            match run(&mut ans, anslen.max(0) as usize) {
                Ok(n) => {
                    query_ok(st, search);
                    finish_answer(&ans, n, answer, anslen)
                }
                Err(e) => herr_result(st, e),
            }
        }
    }
}

/// # Safety
/// glibc's contract for `res_nquery`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquery(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: glibc's contract: a valid state, a C string, `anslen` writable bytes at `answer`.
    let (st, name, answer) = unsafe { qargs(st, name, answer, anslen) };
    nquery(st, false, name.unwrap_or_default(), class, ty, answer, anslen)
}

/// # Safety
/// glibc's contract for `res_nsearch`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsearch(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: glibc's contract: a valid state, a C string, `anslen` writable bytes at `answer`.
    let (st, name, answer) = unsafe { qargs(st, name, answer, anslen) };
    nquery(st, true, name.unwrap_or_default(), class, ty, answer, anslen)
}

/// `res_nquerydomain` over references (`domain` None for NULL).
pub fn nquerydomain(st: &mut ResState, nm: &[u8], domain: Option<&[u8]>, class: c_int, ty: c_int, answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    ensure_init(st);
    let mut full = Buf::<1026>::new();
    match domain {
        None => {
            if nm.len() >= dns::MAXDNAME {
                errno::set(EMSGSIZE);
                set_herr(st, NETDB_INTERNAL);
                return -1;
            }
            full.push_all(nm.strip_suffix(b".").unwrap_or(nm));
        }
        Some(d) => {
            if nm.len() + d.len() + 1 >= dns::MAXDNAME {
                errno::set(EMSGSIZE);
                set_herr(st, NETDB_INTERNAL);
                return -1;
            }
            full.push_all(nm);
            full.push(b'.');
            full.push_all(d);
        }
    }
    nquery(st, false, full.as_bytes(), class, ty, answer, anslen)
}

/// # Safety
/// glibc's contract for `res_nquerydomain`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquerydomain(st: *mut ResState, name: *const c_char, domain: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: glibc's contract: a valid state, a C string, `anslen` writable bytes at `answer`.
    let (st, nm, answer) = unsafe { qargs(st, name, answer, anslen) };
    // SAFETY: glibc's contract: `domain` is NULL or a C string.
    let domain = unsafe { ffi::cstr(domain) }.map(CStr::to_bytes);
    nquerydomain(st, nm.unwrap_or_default(), domain, class, ty, answer, anslen)
}

/// `res_nsend` over references.
pub fn nsend(st: &mut ResState, m: &[u8], answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    ensure_init(st);
    let cfg = config_of(st);
    let prev = begin_lookup(st);
    let r = nsend_cfg(&cfg, m, answer, anslen);
    end_lookup(st, prev);
    r
}

fn nsend_cfg(cfg: &Config, m: &[u8], answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    // RES_NOAAAA rewrites an AAAA query (glibc's context_send_common)
    let run = |ans: &mut [u8]| {
        let mut a = dns::Answer::fixed(ans);
        match dns::send_query_noaaaa(cfg, m, &mut a) {
            Some(r) => r,
            None => dns::send_query_ans(cfg, m, &mut a),
        }
    };
    let sent = match answer {
        Some(buf) if anslen >= wire::HFIXEDSZ as c_int => run(buf).map(|n| n as c_int),
        answer => {
            let mut own = [0u8; 4096];
            run(&mut own).map(|n| finish_answer(&own, n.min(own.len()), answer, anslen))
        }
    };
    // a failed send sets errno only: glibc's res_send (context_send_common, __res_context_send) leaves h_errno and the
    // state's res_h_errno as they were
    match sent {
        Ok(n) => n,
        Err(dns::SendErr::Refused) => {
            errno::set(ECONNREFUSED);
            -1
        }
        Err(dns::SendErr::Timeout) => {
            errno::set(ETIMEDOUT);
            -1
        }
        Err(dns::SendErr::Other(e)) => {
            errno::set(e);
            -1
        }
    }
}

/// # Safety
/// glibc's contract for `res_nsend`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsend(st: *mut ResState, msg: *const c_uchar, msglen: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: glibc's contract: a valid state and `anslen` writable bytes at `answer`.
    let (st, _, answer) = unsafe { qargs(st, core::ptr::null(), answer, anslen) };
    // SAFETY: glibc's contract: `msg` has `msglen` readable bytes.
    let m = unsafe { ffi::bytes(msg, msglen.max(0) as usize) };
    nsend(st, m, answer, anslen)
}

/// `res_nmkquery` over references (`buf` None for NULL, `buflen` as the caller gave it).
pub fn nmkquery(st: &mut ResState, op: c_int, dname: &[u8], class: c_int, ty: c_int, buf: Option<&mut [u8]>, buflen: c_int) -> c_int {
    ensure_init(st);
    // glibc's __res_context_mkquery: a class or type out of range, no buffer or one without room for the header and the
    // question's fixed part, an opcode other than QUERY and NOTIFY: -1 with errno and h_errno untouched
    let Some(out) = buf else { return -1 };
    if !(0..=65535).contains(&class) || !(0..=65535).contains(&ty) || buflen < (wire::HFIXEDSZ + 4) as c_int || (op != 0 && op != 4) {
        return -1;
    }
    // a fresh id from the state like glibc (res_randomid)
    let id = __res_randomid() as u16;
    st.id = id;
    let rd = st.options & dns::RES_RECURSE as c_ulong != 0;
    // (glibc adds the OPT record when it sends, not when it builds the query)
    let mut tmp = [0u8; 1600];
    // the name does not compress into the room left: ns_name_compress's EMSGSIZE (h_errno untouched, as in glibc)
    let Some(n) = wire::build_query(id, dname, ty as u16, class as u16, rd, None, &mut tmp) else {
        errno::set(EMSGSIZE);
        return -1;
    };
    if n > out.len() {
        errno::set(EMSGSIZE);
        return -1;
    }
    out[..n].copy_from_slice(&tmp[..n]);
    dns::mkquery_errno(&tmp[..n]);
    if st.options & dns::RES_TRUSTAD as c_ulong != 0 {
        out[3] |= 0x20;
    }
    if op == 4 {
        // NS_NOTIFY_OP: opcode 4
        let h = wire::Header::parse(out).unwrap();
        wire::Header { flags: (h.flags & !0x7800) | (4 << 11), ..h }.write(out);
    }
    n as c_int
}

/// # Safety
/// glibc's contract for `res_nmkquery`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nmkquery(st: *mut ResState, op: c_int, dname: *const c_char, class: c_int, ty: c_int, _data: *const c_uchar, _datalen: c_int, _newrr: *const c_uchar, buf: *mut c_uchar, buflen: c_int) -> c_int {
    // SAFETY: glibc's contract: a valid state, a C string, `buflen` writable bytes at `buf`. (glibc reads `dname` only after
    // its checks; a NULL one, which those checks may refuse first, is taken as empty here instead of being read.)
    let (st, dname, out) = unsafe { qargs(st, dname, buf, buflen) };
    nmkquery(st, op, dname.unwrap_or_default(), class, ty, out, buflen)
}

/// # Safety
/// glibc's contract; uses the calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_query(name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: the thread's own state; the other arguments under glibc's contract.
    unsafe { res_nquery(__res_state(), name, class, ty, answer, anslen) }
}

/// # Safety
/// glibc's contract; uses the calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_search(name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: the thread's own state; the other arguments under glibc's contract.
    unsafe { res_nsearch(__res_state(), name, class, ty, answer, anslen) }
}

/// # Safety
/// glibc's contract; uses the calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_querydomain(name: *const c_char, domain: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: the thread's own state; the other arguments under glibc's contract.
    unsafe { res_nquerydomain(__res_state(), name, domain, class, ty, answer, anslen) }
}

/// # Safety
/// glibc's contract; uses the calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_send(msg: *const c_uchar, msglen: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    // SAFETY: the thread's own state; the other arguments under glibc's contract.
    unsafe { res_nsend(__res_state(), msg, msglen, answer, anslen) }
}

/// # Safety
/// glibc's contract; uses the calling thread's `_res`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_mkquery(op: c_int, dname: *const c_char, class: c_int, ty: c_int, data: *const c_uchar, datalen: c_int, newrr: *const c_uchar, buf: *mut c_uchar, buflen: c_int) -> c_int {
    // SAFETY: the thread's own state; the other arguments under glibc's contract.
    unsafe { res_nmkquery(__res_state(), op, dname, class, ty, data, datalen, newrr, buf, buflen) }
}

// ---------------------------------------------------------------- domain names

fn msgerr() -> c_int {
    errno::set(EMSGSIZE);
    -1
}

/// The characters `ntop` writes as they are (printable, not one of its special characters).
static NTOP_PLAIN: [bool; 256] = {
    let mut t = [false; 256];
    let mut c = 0x21;
    while c < 0x7f {
        t[c] = !matches!(c as u8, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$');
        c += 1;
    }
    t
};

/// `dst.copy_from_slice(src)` for a short run (a label: at most 63 bytes) without a call to memcpy: fixed-size moves, the
/// last one overlapping the one before, so no byte outside `dst` is written.
#[inline(always)]
fn copy_small(dst: &mut [u8], src: &[u8]) {
    fn mv<const N: usize>(d: &mut [u8], s: &[u8], at: usize) {
        let d: &mut [u8; N] = (&mut d[at..at + N]).try_into().unwrap_or_else(|_| unreachable!());
        *d = *s[at..at + N].first_chunk().unwrap_or_else(|| unreachable!());
    }
    let n = src.len();
    assert_eq!(dst.len(), n);
    if n >= 8 {
        let mut i = 0;
        while i + 8 <= n {
            mv::<8>(dst, src, i);
            i += 8;
        }
        if i < n {
            mv::<8>(dst, src, n - 8);
        }
    } else if n >= 4 {
        mv::<4>(dst, src, 0);
        mv::<4>(dst, src, n - 4);
    } else if n > 0 {
        dst[0] = src[0];
        dst[n - 1] = src[n - 1];
        if n == 3 {
            dst[1] = src[1];
        }
    }
}

/// glibc's `ns_name_ntop` without errno: writes the text of the uncompressed wire name `src` into `dst` character by
/// character, so a name that does not fit leaves the part that did (as glibc does). The bytes written including the NUL,
/// or None (also for a name that runs off the end of `src`).
#[inline]
pub(crate) fn ntop(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let dstsiz = dst.len();
    let mut cp = 0usize;
    let mut dn = 0usize;
    loop {
        let l = *src.get(cp)? as usize;
        cp += 1;
        if l == 0 {
            break;
        }
        if l >= 64 {
            return None;
        }
        if dn != 0 {
            if dn >= dstsiz {
                return None;
            }
            dst[dn] = b'.';
            dn += 1;
        }
        let label = src.get(cp..cp + l)?;
        cp += l;
        if dstsiz - dn > 4 * l {
            // room for the longest form of every character (4 bytes each): the room checks of the loop below would all
            // pass, so the label is written without them. Most labels have only plain characters: copy them as they are
            // and look at the result after (a label with any other character is written again below).
            if label.iter().all(|&c| NTOP_PLAIN[c as usize]) {
                copy_small(&mut dst[dn..dn + l], label);
                dn += l;
                continue;
            }
            let out = &mut dst[dn..dn + 4 * l];
            let mut k = 0usize;
            for &c in label {
                if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                    out[k] = b'\\';
                    out[k + 1] = c;
                    k += 2;
                } else if !(c > 0x20 && c < 0x7f) {
                    out[k] = b'\\';
                    out[k + 1] = b'0' + c / 100;
                    out[k + 2] = b'0' + (c % 100) / 10;
                    out[k + 3] = b'0' + c % 10;
                    k += 4;
                } else {
                    out[k] = c;
                    k += 1;
                }
            }
            dn += k;
            continue;
        }
        for &c in label {
            if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                if dstsiz - dn < 2 {
                    return None;
                }
                dst[dn] = b'\\';
                dst[dn + 1] = c;
                dn += 2;
            } else if !(c > 0x20 && c < 0x7f) {
                if dstsiz - dn < 4 {
                    return None;
                }
                dst[dn] = b'\\';
                dst[dn + 1] = b'0' + c / 100;
                dst[dn + 2] = b'0' + (c % 100) / 10;
                dst[dn + 3] = b'0' + c % 10;
                dn += 4;
            } else {
                if dstsiz - dn < 2 {
                    return None;
                }
                dst[dn] = c;
                dn += 1;
            }
        }
    }
    if dn == 0 {
        if dn >= dstsiz {
            return None;
        }
        dst[0] = b'.';
        dn += 1;
    }
    if dn >= dstsiz {
        return None;
    }
    dst[dn] = 0;
    Some(dn + 1)
}

/// `ns_name_uncompress` without errno: the name at offset `off` of the message `m` as text (root as ".") into `dst`;
/// returns the bytes the name occupies at `off`.
#[inline]
pub(crate) fn uncompress_name(m: &[u8], off: usize, dst: &mut [u8]) -> Option<usize> {
    // NS_MAXCDNAME bytes, as in glibc (a name of 255 wire bytes does not fit: the unpacker needs room for its NUL)
    let mut tmp = [0u8; wire::MAXCDNAME];
    let used = wire::name_unpack(m, off, &mut tmp)?;
    ntop(&tmp, dst)?;
    Some(used)
}

/// `ns_name_skip` without errno: the bytes the name at the start of `m` occupies.
#[inline]
pub(crate) fn skip_name(m: &[u8]) -> Option<usize> {
    wire::name_skip(m, 0)
}

/// `p - base` when `p` is not before `base` (the C code's "is it inside the message" test).
pub(crate) fn offset_in(base: *const u8, p: *const u8) -> Option<usize> {
    let off = (p as usize).wrapping_sub(base as usize) as isize;
    if off < 0 { None } else { Some(off as usize) }
}

/// The bytes `msg..eom` (none when `eom` is before `msg`).
///
/// # Safety
/// `msg..eom` is readable and unchanged for `'a`.
pub(crate) unsafe fn msg_slice<'a>(msg: *const u8, eom: *const u8) -> &'a [u8] {
    let n = (eom as usize).wrapping_sub(msg as usize) as isize;
    // SAFETY: the caller's contract; a negative length reads nothing.
    unsafe { ffi::bytes(msg, n.max(0) as usize) }
}

/// The message `msg..eom` and an output buffer of `dstsiz` bytes at `dst`, as the name functions take them.
///
/// # Safety
/// As `msg_slice` for the message; `dst` is writable for `dstsiz` bytes (any pointer when 0) and overlaps nothing else used.
pub(crate) unsafe fn msg_dst<'a>(msg: *const u8, eom: *const u8, dst: *mut u8, dstsiz: usize) -> (&'a [u8], &'a mut [u8]) {
    // SAFETY: the caller's contract.
    let d = unsafe { ffi::bytes_mut(dst, dstsiz) };
    // SAFETY: the caller's contract.
    (unsafe { msg_slice(msg, eom) }, d)
}

/// The length of the uncompressed wire name at `p` as far as `ns_name_ntop` reads it: up to and including its root label, or
/// up to a label byte of 64 or more (where `ntop` stops).
///
/// # Safety
/// `p` points to an uncompressed wire name.
unsafe fn wire_name_len(p: *const u8) -> usize {
    let mut i = 0usize;
    loop {
        // SAFETY: `i` is at a label length byte of the name (the caller's contract), which is readable.
        let l = unsafe { *p.wrapping_add(i) } as usize;
        i += 1;
        if l == 0 || l >= 64 {
            return i;
        }
        i += l;
    }
}

/// `ns_name_pack`'s check of the source name: its length if it is a legal uncompressed name (labels under 64 bytes, at most
/// NS_MAXCDNAME bytes in all), reading through `at` label byte by label byte.
fn legal_name_len(at: impl Fn(usize) -> Option<u8>) -> Option<usize> {
    let mut l = 0usize;
    loop {
        let n = at(l)? as usize;
        if n >= 64 {
            return None;
        }
        l += n + 1;
        if l > wire::MAXCDNAME {
            return None;
        }
        if n == 0 {
            return Some(l);
        }
    }
}

/// # Safety
/// `msg..eom` is the message, `src` points into it, `dst` has `dstsiz` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_uncompress(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    // SAFETY: glibc's contract: `msg..eom` is the message, `dst` has `dstsiz` writable bytes.
    let (m, d) = unsafe { msg_dst(msg, eom, dst.cast::<u8>(), dstsiz) };
    match offset_in(msg, src).and_then(|off| uncompress_name(m, off, d)) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

/// # Safety
/// As [`ns_name_uncompress`]; `dst` receives the uncompressed wire form.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_unpack(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    let Some(off) = offset_in(msg, src) else { return msgerr() };
    // SAFETY: glibc's contract: `msg..eom` is the message, `dst` has `dstsiz` writable bytes.
    let (m, d) = unsafe { msg_dst(msg, eom, dst, dstsiz) };
    match wire::name_unpack(m, off, d) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

/// # Safety
/// `src` is an uncompressed wire name; `dst` has `dstsiz` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntop(src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    // SAFETY: glibc's contract: `src` is a wire name.
    let n = unsafe { wire_name_len(src) };
    // SAFETY: the `n` bytes were just read as the name.
    let s = unsafe { ffi::bytes(src, n) };
    // SAFETY: glibc's contract: `dst` has `dstsiz` writable bytes.
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), dstsiz) };
    match ntop(s, d) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

/// # Safety
/// `src` is a C string; `dst` has `dstsiz` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pton(src: *const c_char, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    // SAFETY: glibc's contract: `dst` has `dstsiz` writable bytes.
    let d = unsafe { ffi::bytes_mut(dst, dstsiz) };
    // SAFETY: glibc's contract: `src` is a C string.
    match wire::name_pton(unsafe { ffi::cstr_bytes(src) }, d) {
        Some((_, fq)) => fq as c_int,
        None => msgerr(),
    }
}

/// # Safety
/// `*ptrptr` points into the message that ends at `eom`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_skip(ptrptr: *mut *const c_uchar, eom: *const c_uchar) -> c_int {
    // SAFETY: glibc's contract: `ptrptr` is a readable and writable pointer.
    let pp = unsafe { &mut *ptrptr };
    let start = *pp;
    // SAFETY: glibc's contract: `start..eom` is (the rest of) the message.
    match skip_name(unsafe { msg_slice(start, eom) }) {
        Some(n) => {
            *pp = start.wrapping_add(n);
            0
        }
        None => msgerr(),
    }
}

/// Look for `domain` (an uncompressed wire name) among the names the compression pointers `dnptrs..lastdnptr` point to,
/// following compression pointers inside the message at `msg` as glibc's dn_find does: the offset of the match, -1 with
/// ENOENT when there is none, -1 with EMSGSIZE for a bad label.
///
/// # Safety
/// `dnptrs..lastdnptr` is readable; each entry and every name and compression target reached from it lies in the readable
/// message that starts at `msg` (glibc reads the same bytes, without a bound).
unsafe fn dn_find(domain: &[u8], msg: *const c_uchar, dnptrs: *const *const c_uchar, lastdnptr: *const *const c_uchar) -> c_int {
    // SAFETY: every pointer `rd` is given is a byte of the message reached as described in the contract.
    let rd = |p: *const u8| unsafe { *p };
    let diff = |p: *const u8| (p as isize).wrapping_sub(msg as isize);
    let mut cpp = dnptrs;
    while cpp < lastdnptr {
        // SAFETY: `cpp` is inside `dnptrs..lastdnptr` (the contract).
        let mut sp = unsafe { *cpp };
        while rd(sp) != 0 && (rd(sp) & 0xc0) == 0 && diff(sp) < 0x4000 {
            let mut dn = 0usize;
            let mut cp = sp;
            'outer: loop {
                let n = rd(cp) as usize;
                cp = cp.wrapping_add(1);
                if n == 0 {
                    break;
                }
                match n & 0xc0 {
                    0 => {
                        // `domain` is a legal name: `dn` stays on its labels and stops at its root label
                        if n as u8 != domain[dn] {
                            break 'outer;
                        }
                        dn += 1;
                        for _ in 0..n {
                            if !domain[dn].eq_ignore_ascii_case(&rd(cp)) {
                                break 'outer;
                            }
                            dn += 1;
                            cp = cp.wrapping_add(1);
                        }
                        if domain[dn] == 0 && rd(cp) == 0 {
                            return diff(sp) as c_int;
                        }
                        if domain[dn] != 0 {
                            continue;
                        }
                        break 'outer;
                    }
                    0xc0 => {
                        cp = msg.wrapping_add(((n & 0x3f) << 8) | rd(cp) as usize);
                    }
                    _ => {
                        errno::set(EMSGSIZE);
                        return -1;
                    }
                }
            }
            sp = sp.wrapping_add(rd(sp) as usize + 1);
        }
        cpp = cpp.wrapping_add(1);
    }
    errno::set(ENOENT);
    -1
}

/// `ns_name_pack` of the legal wire name `src` (exactly its bytes).
///
/// # Safety
/// `dst` is writable for `dstsiz` bytes (when positive) and does not overlap `src`; `dnptrs` is NULL or glibc's compression
/// table: a message pointer, then entries up to a NULL one, writable up to `lastdnptr`, with dn_find's contract for the
/// message.
unsafe fn pack(src: &[u8], dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    let diff = |p: *const u8, q: *const u8| (p as isize).wrapping_sub(q as isize);
    let mut dstp = dst;
    let eob = dst.wrapping_offset(dstsiz as isize);
    let mut msg: *const c_uchar = core::ptr::null();
    let mut cpp: *mut *const c_uchar = core::ptr::null_mut();
    let mut lpp: *mut *const c_uchar = core::ptr::null_mut();
    let mut dnp = dnptrs;
    // SAFETY: only called below for the table's first slot (a non-NULL table starts with the message pointer) and for its
    // entries up to the NULL one, which are readable (the contract).
    let slot = |p: *mut *const c_uchar| unsafe { *p };
    if !dnp.is_null() {
        msg = slot(dnp);
        dnp = dnp.wrapping_add(1);
        if !msg.is_null() {
            cpp = dnp;
            while !slot(cpp).is_null() {
                cpp = cpp.wrapping_add(1);
            }
            lpp = cpp;
        }
    }
    let mut i = 0usize;
    let mut first = true;
    let ok = loop {
        let n = src[i] as usize;
        if n != 0 && !msg.is_null() {
            // SAFETY: `dnp..lpp` are the table's entries, with the message they point into (the contract).
            let f = unsafe { dn_find(&src[i..], msg, dnp, lpp) };
            if f >= 0 {
                if diff(eob, dstp) <= 1 {
                    break false;
                }
                // SAFETY: `dstp` and `dstp + 1` are before `eob`, inside `dst` (checked above).
                unsafe { core::ptr::copy_nonoverlapping([((f >> 8) as u8) | 0xc0, (f % 256) as u8].as_ptr(), dstp, 2) };
                return diff(dstp.wrapping_add(2), dst) as c_int;
            }
            if !lastdnptr.is_null() && cpp < lastdnptr.wrapping_sub(1) && diff(dstp, msg) < 0x4000 && first {
                // SAFETY: `cpp` and `cpp + 1` are before `lastdnptr`, inside the writable table (aligned for pointers).
                unsafe { cpp.cast::<[*const c_uchar; 2]>().write([dstp, core::ptr::null()]) };
                cpp = cpp.wrapping_add(1);
                first = false;
            }
        }
        if n >= 64 {
            break false;
        }
        if (n + 1) as isize > diff(eob, dstp) {
            break false;
        }
        // SAFETY: the `n + 1` bytes at `dstp` are before `eob` (checked above), inside `dst`, which nothing else reaches
        // meanwhile; `src` does not overlap it.
        let out = unsafe { core::slice::from_raw_parts_mut(dstp, n + 1) };
        // (fixed-size moves: a memcpy call per label cost more than the label)
        copy_small(out, &src[i..i + n + 1]);
        i += n + 1;
        dstp = dstp.wrapping_add(n + 1);
        if n == 0 {
            break true;
        }
    };
    if !ok || dstp > eob {
        if !msg.is_null() && !lpp.is_null() {
            // SAFETY: `lpp` is the table's NULL entry found above (readable and writable).
            unsafe { *lpp = core::ptr::null() };
        }
        errno::set(EMSGSIZE);
        return -1;
    }
    diff(dstp, dst) as c_int
}

/// # Safety
/// glibc's contract for `ns_name_pack`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pack(src: *const c_uchar, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    // legal domain? (read label by label: a bad name is refused before anything past its bad label is read)
    // SAFETY: glibc's contract: `src` is a wire name; `legal_name_len` reads its label bytes in order and stops at the root
    // label or at the first bad one.
    let Some(len) = legal_name_len(|i| Some(unsafe { *src.wrapping_add(i) })) else { return msgerr() };
    // SAFETY: the `len` bytes of the name were just read.
    let s = unsafe { ffi::bytes(src, len) };
    // SAFETY: glibc's contract for the rest.
    unsafe { pack(s, dst, dstsiz, dnptrs, lastdnptr) }
}

/// # Safety
/// glibc's contract for `ns_name_compress`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_compress(src: *const c_char, dst: *mut c_uchar, dstsiz: usize, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    let mut tmp = [0u8; wire::MAXCDNAME + 1];
    // SAFETY: glibc's contract: `src` is a C string.
    let Some((len, _)) = wire::name_pton(unsafe { ffi::cstr_bytes(src) }, &mut tmp[..wire::MAXCDNAME]) else { return msgerr() };
    // name_pton writes only legal names (labels under 64 bytes, at most MAXCDNAME in all) and returns their length
    debug_assert_eq!(legal_name_len(|i| tmp.get(i).copied()), Some(len));
    // SAFETY: glibc's contract for `dst` and the table; `tmp` is our own, so it does not overlap `dst`.
    unsafe { pack(&tmp[..len], dst, dstsiz as c_int, dnptrs, lastdnptr) }
}

/// # Safety
/// glibc's contract for `dn_comp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_comp(src: *const c_char, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *mut c_uchar, lastdnptr: *mut *mut c_uchar) -> c_int {
    // SAFETY: the same contract.
    unsafe { ns_name_compress(src, dst, dstsiz as usize, dnptrs as *mut *const c_uchar, lastdnptr as *mut *const c_uchar) }
}

/// `dn_expand` over slices: the name at `off` of `m` (None: before the message) as text into `dst`, the root as an empty
/// string. The bytes the name occupies, or -1 with EMSGSIZE.
pub fn expand(m: &[u8], off: Option<usize>, dst: &mut [u8]) -> c_int {
    match off.and_then(|off| uncompress_name(m, off, dst)) {
        Some(n) => {
            // the root name comes back as an empty string here (ns_name_uncompress gives ".")
            if dst[0] == b'.' {
                dst[0] = 0;
            }
            n as c_int
        }
        None => msgerr(),
    }
}

/// # Safety
/// glibc's contract for `dn_expand`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_expand(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: c_int) -> c_int {
    // SAFETY: glibc's contract: `msg..eom` is the message, `dst` has `dstsiz` writable bytes.
    let (m, d) = unsafe { msg_dst(msg, eom, dst.cast::<u8>(), dstsiz.max(0) as usize) };
    expand(m, offset_in(msg, src), d)
}

/// # Safety
/// glibc's contract for `dn_skipname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_skipname(ptr: *const c_uchar, eom: *const c_uchar) -> c_int {
    // SAFETY: glibc's contract: `ptr..eom` is (the rest of) the message.
    match skip_name(unsafe { msg_slice(ptr, eom) }) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

// ---------------------------------------------------------------- name checks

fn printable_string(s: &[u8]) -> bool {
    s.iter().all(|&c| c > b' ' && c <= b'~')
}

fn binary_hnok(w: &[u8]) -> bool {
    let mut i = 0;
    while i < w.len() {
        let l = w[i] as usize;
        if l == 0 {
            break;
        }
        i += 1;
        for k in 0..l {
            let c = w[i + k];
            if !(c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
                return false;
            }
        }
        i += l;
    }
    true
}

fn pton_buf(dn: &[u8]) -> Option<[u8; wire::MAXCDNAME + 2]> {
    let mut b = [0u8; wire::MAXCDNAME + 2];
    if !printable_string(dn) {
        return None;
    }
    wire::name_pton(dn, &mut b[..wire::MAXCDNAME + 1])?;
    Some(b)
}

/// `res_hnok` on a name given as bytes (glibc's nss_dns refuses to query a name that fails it).
pub(crate) fn hostname_ok(name: &[u8]) -> bool {
    let Some(b) = pton_buf(name) else { return false };
    !(b[0] > 0 && b[1] == b'-') && binary_hnok(&b)
}

/// # Safety
/// `dn` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_hnok(dn: *const c_char) -> c_int {
    // SAFETY: glibc's contract: `dn` is a C string.
    hostname_ok(unsafe { ffi::cstr_bytes(dn) }) as c_int
}

/// `res_dnok` on a name given as bytes.
pub(crate) fn dname_ok(name: &[u8]) -> bool {
    pton_buf(name).is_some()
}

/// # Safety
/// `dn` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_dnok(dn: *const c_char) -> c_int {
    // SAFETY: glibc's contract: `dn` is a C string.
    dname_ok(unsafe { ffi::cstr_bytes(dn) }) as c_int
}

/// # Safety
/// `dn` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_ownok(dn: *const c_char) -> c_int {
    // SAFETY: glibc's contract: `dn` is a C string.
    let Some(b) = pton_buf(unsafe { ffi::cstr_bytes(dn) }) else { return 0 };
    if b[0] > 0 && b[1] == b'-' {
        return 0;
    }
    if b[0] == 1 && b[1] == b'*' { binary_hnok(&b[2..]) as c_int } else { binary_hnok(&b) as c_int }
}

/// # Safety
/// `dn` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_mailok(dn: *const c_char) -> c_int {
    // SAFETY: glibc's contract: `dn` is a C string.
    let Some(b) = pton_buf(unsafe { ffi::cstr_bytes(dn) }) else { return 0 };
    let l = b[0] as usize;
    if l == 0 {
        return 1;
    }
    let tail = &b[1 + l..];
    if tail[0] == 0 {
        return 0;
    }
    binary_hnok(tail) as c_int
}

#[allow(dead_code)]
fn _unused(_: c_long) {}
