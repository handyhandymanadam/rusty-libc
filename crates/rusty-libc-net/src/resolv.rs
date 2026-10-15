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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResExt {
    pub nscount: u16,
    pub nsmap: [u16; MAXNS],
    pub nssocks: [c_int; MAXNS],
    pub nscount6: u16,
    pub nsinit: u16,
    pub nsaddrs: [*mut sockaddr_in6; MAXNS],
    pub extension_index: u64,
}

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

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _res: SyncCell<ResState> = SyncCell::new(ResState::zero());

#[thread_local]
static RESP_PTR: Cell<*mut ResState> = Cell::new(core::ptr::null_mut());

fn heap_new<T>(v: T) -> *mut T {
    let p = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<T>()) } as *mut T;
    if !p.is_null() {
        unsafe { p.write(v) };
    }
    p
}

fn thread_block<T>(cell: &Cell<*mut T>, v: T, dtor: unsafe extern "C" fn(*mut c_void)) -> *mut T {
    let p = heap_new(v);
    if p.is_null() {
        return p;
    }
    if !rusty_libc_core::tls::register_thread_dtor(dtor, cell.as_ptr() as *mut c_void, 0) {
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
        return core::ptr::null_mut();
    }
    cell.set(p);
    p
}

unsafe fn release<T>(slot: *mut *mut T, keep: *mut T) {
    let slot = unsafe { &mut *slot };
    if !slot.is_null() && *slot != keep {
        unsafe { rusty_libc_malloc::free(*slot as *mut c_void) };
    }
    *slot = core::ptr::null_mut();
}

unsafe extern "C" fn release_resp(obj: *mut c_void) {
    if !STATE_LENT.get() {
        with_this_state(|st| {
            if st.nscount != 0 {
                iclose(st, true);
                st.options = 0;
            }
        });
    }
    unsafe { release(obj as *mut *mut ResState, _res.as_ptr()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_state() -> *mut ResState {
    if RESP_PTR.get().is_null() {
        let main = rusty_libc_core::tls::is_initial_thread();
        RESP_PTR.set(_res.as_ptr());
        if !main {
            thread_block(&RESP_PTR, ResState::zero(), release_resp);
        }
    }
    RESP_PTR.get()
}

#[thread_local]
static STATE_LENT: Cell<bool> = Cell::new(false);

pub(crate) fn with_this_state<R>(f: impl FnOnce(&mut ResState) -> R) -> R {
    assert!(!STATE_LENT.replace(true), "resolver state lent twice");
    let r = f(unsafe { &mut *__res_state() });
    STATE_LENT.set(false);
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_randomid() -> c_uint {
    let mut idb = [0u8; 2];
    let _ = unsafe { rusty_libc_core::syscall::syscall3(318, idb.as_mut_ptr() as usize, 2, 0) };
    u16::from_ne_bytes(idb) as c_uint
}

fn set_herr(st: &mut ResState, h: c_int) {
    set_h_errno(h);
    st.res_h_errno = h;
}

pub fn nclose(s: &mut ResState) {
    for i in 0..MAXNS {
        free_ext(s, i);
    }
}

fn free_ext(s: &mut ResState, i: usize) {
    let p = s.u.nsaddrs[i];
    if !p.is_null() {
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
        s.u.nsaddrs[i] = core::ptr::null_mut();
    }
}

pub fn ninit(s: &mut ResState) -> c_int {
    nclose(s);
    let (cfg, generation) = dns::default_config_gen();
    fill(s, &cfg);
    remember_init(s, generation);
    0
}

fn has_preinit_values(s: &ResState) -> bool {
    (s.retrans != 0 && s.retrans != 5)
        || (s.retry != 0 && s.retry != 2)
        || (s.options != 0 && (s.options & !(dns::RES_INIT as c_ulong)) != dns::RES_DEFAULT as c_ulong)
}

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
        iclose(s, true);
    }
    let (cfg, generation) = if has_preinit_values(s) {
        let path = crate::nss::etc_path(b"/resolv.conf");
        (dns::Config::load_preinit(&path, s.retrans, s.retry, s.options as u32), 0)
    } else {
        dns::default_config_gen()
    };
    nclose(s);
    fill(s, &cfg);
    s.id = __res_randomid() as c_ushort;
    remember_init(s, generation);
    0
}

fn remember_init(s: &ResState, generation: u64) {
    if core::ptr::eq(s, __res_state()) {
        let snap = init_snap_slot();
        if !snap.is_null() {
            let c = config_of(s);
            unsafe { *snap = Some((c, generation)) };
        }
    }
}

fn fill(s: &mut ResState, cfg: &Config) {
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
    attach_index(s);
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_ninit(st: *mut ResState) -> c_int {
    ninit(unsafe { &mut *st })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_init() -> c_int {
    with_this_state(init_preinit)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nclose(st: *mut ResState) {
    iclose(unsafe { &mut *st }, true)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_iclose(st: *mut ResState, free_addr: bool) {
    iclose(unsafe { &mut *st }, free_addr)
}

pub(crate) fn ext_addr(s: &ResState, i: usize) -> Option<sockaddr_in6> {
    let p = s.u.nsaddrs[i];
    if p.is_null() {
        return None;
    }
    Some(unsafe { *p })
}

fn sock_eq(a: &sockaddr_in, b: &sockaddr_in6) -> bool {
    let b4_addr = b.sin6_flowinfo;
    if a.sin_family == b.sin6_family {
        return a.sin_family == AF_INET as u16 && a.sin_port == b.sin6_port && a.sin_addr.s_addr == b4_addr;
    }
    a.sin_family == AF_INET as u16
        && a.sin_port == b.sin6_port
        && b.sin6_addr.s6_addr[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        && u32::from_ne_bytes([b.sin6_addr.s6_addr[12], b.sin6_addr.s6_addr[13], b.sin6_addr.s6_addr[14], b.sin6_addr.s6_addr[15]]) == a.sin_addr.s_addr
}

pub fn sync_ext(s: &mut ResState) {
    let n = (s.nscount.max(0) as usize).min(MAXNS);
    if n == 0 {
        return;
    }
    if s.u.nscount != 0 {
        let changed = c_int::from(s.u.nscount) != s.nscount
            || (0..n).any(|ns| s.nsaddr_list[ns].sin_family != 0 && !ext_addr(s, ns).is_some_and(|b| sock_eq(&s.nsaddr_list[ns], &b)));
        if changed {
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
            let p = s.u.nsaddrs[ns];
            if p.is_null() {
                s.u.nsaddrs[ns] = heap_new(v);
            } else {
                unsafe { p.write(v) };
            }
        }
        s.u.nscount = s.nscount as u16;
    }
}

const RES_F_VC: c_uint = dns::RES_F_VC;
const RES_F_CONN: c_uint = dns::RES_F_CONN;

fn state_socks(s: &ResState) -> dns::StateSocks {
    let n = (s.nscount.max(0) as usize).min(MAXNS);
    let has_ext: [bool; MAXNS] = core::array::from_fn(|i| !s.u.nsaddrs[i].is_null());
    let needclose = s.u.nscount != 0
        && (c_int::from(s.u.nscount) != s.nscount
            || (0..n).any(|ns| s.nsaddr_list[ns].sin_family != 0 && !ext_addr(s, ns).is_some_and(|b| sock_eq(&s.nsaddr_list[ns], &b))));
    let fresh = s.u.nscount == 0 || needclose;
    let after: [bool; MAXNS] = core::array::from_fn(|i| has_ext[i] || (fresh && i < n && s.nsaddr_list[i].sin_family != 0));
    dns::StateSocks {
        udp: s.u.nssocks,
        vc: s.vcsock,
        vc_flags: s.flags & (RES_F_VC | RES_F_CONN),
        nscount: n,
        has_ext,
        presend: Some(dns::PreSend { needclose, fresh, has_ext: after }),
    }
}

fn begin_lookup(s: &ResState) -> Option<dns::StateSocks> {
    dns::reset_send_marks();
    dns::lend_state_socks(state_socks(s))
}

fn end_lookup(s: &mut ResState, prev: Option<dns::StateSocks>) {
    if dns::take_send_reached() {
        sync_ext(s);
    }
    if let Some(k) = dns::take_state_socks() {
        s.u.nssocks = k.udp;
        s.vcsock = k.vc;
        s.flags = (s.flags & !(RES_F_VC | RES_F_CONN)) | k.vc_flags;
    }
    dns::restore_state_socks(prev);
}

const INDEX_MAGIC: u64 = 0x26a8_fa5e_48af_8061;

struct IndexTable {
    slots: crate::nss::ZBuf,
    len: usize,
    free_start: u64,
}

static INDEX_TABLE: crate::util::Spin<IndexTable> = crate::util::Spin::new(IndexTable { slots: crate::nss::ZBuf::new(), len: 0, free_start: 0 });

impl IndexTable {
    fn get(&self, i: usize) -> u64 {
        let b = &self.slots.as_slice()[i * 8..i * 8 + 8];
        u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
    fn set(&mut self, i: usize, v: u64) {
        self.slots.as_mut_slice()[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
    }
}

fn attach_index(s: &mut ResState) {
    let mut t = INDEX_TABLE.lock();
    let index = if t.free_start & 1 != 0 {
        let i = (t.free_start >> 1) as usize;
        t.free_start = t.get(i);
        i
    } else {
        let i = t.len;
        if (i + 1) * 8 > t.slots.cap() && !t.slots.grow(((i + 1) * 16).max(64)) {
            s.u.extension_index = 0;
            return;
        }
        t.len += 1;
        i
    };
    t.set(index, 2);
    s.u.extension_index = index as u64 ^ INDEX_MAGIC;
}

fn detach_index(s: &mut ResState) {
    let index = s.u.extension_index ^ INDEX_MAGIC;
    let mut t = INDEX_TABLE.lock();
    if index < t.len as u64 {
        let i = index as usize;
        let v = t.get(i);
        if v & 1 == 0 && v != 0 {
            let head = t.free_start;
            t.set(i, head);
            t.free_start = ((i as u64) << 1) | 1;
        }
    }
    drop(t);
    s.u.extension_index = 0;
}

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

fn ensure_init(s: &mut ResState) -> Option<Config> {
    if s.options & dns::RES_INIT as c_ulong == 0 {
        ninit(s);
    }
    let generation = unchanged_since_init(s);
    if s.options & dns::RES_NORELOAD as c_ulong != 0 && generation.is_none_or(|g| g == 0) {
        return None;
    }
    let generation = generation?;
    let (current, now) = dns::default_config_gen();
    if generation != now {
        if s.nscount > 0 {
            iclose(s, true);
        }
        nclose(s);
        fill(s, &current);
        remember_init(s, now);
    }
    Some(current)
}

fn unchanged_since_init(s: &ResState) -> Option<u64> {
    if !core::ptr::eq(s, __res_state()) {
        return None;
    }
    let slot = INIT_SNAP.get();
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
    c.timeout_ms = s.retrans as i64 * 1000;
    c.attempts = s.retry;
    c.nservers = 0;
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
        if let Some(b) = Buf::<256>::from(unsafe { ffi::cstr_bytes(p) }) {
            c.search[c.nsearch] = b;
            c.nsearch += 1;
        }
    }
    c
}

type Snapshot = Option<(Config, u64)>;

#[thread_local]
static INIT_SNAP: Cell<*mut Snapshot> = Cell::new(core::ptr::null_mut());

unsafe extern "C" fn release_snap(obj: *mut c_void) {
    unsafe { release(obj as *mut *mut Snapshot, core::ptr::null_mut()) }
}

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

pub fn init_this_state() {
    with_this_state(|st| {
        ensure_init(st);
    });
}

pub fn current_config() -> LookupConfig {
    with_this_state(|st| {
        let c = ensure_init(st).unwrap_or_else(|| config_of(st));
        LookupConfig(c, begin_lookup(st))
    })
}

fn herr_result(st: &mut ResState, e: dns::HErr) -> c_int {
    if e.errno != 0 {
        errno::set(e.errno);
    }
    set_herr(st, e.h);
    -1
}

unsafe fn qargs<'a>(st: *mut ResState, name: *const c_char, buf: *mut c_uchar, len: c_int) -> (&'a mut ResState, Option<&'a [u8]>, Option<&'a mut [u8]>) {
    let name = unsafe { ffi::cstr(name) }.map(CStr::to_bytes);
    let buf = if buf.is_null() {
        None
    } else {
        Some(unsafe { ffi::bytes_mut(buf, len.max(0) as usize) })
    };
    (unsafe { &mut *st }, name, buf)
}

fn query_ok(st: &mut ResState, search: bool) {
    if search {
        set_herr(st, dns::search_herr());
    }
}

fn finish_answer(ans: &[u8], n: usize, answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    let m = n.min(anslen.max(0) as usize);
    if let Some(b) = answer {
        b[..m].copy_from_slice(&ans[..m]);
    }
    m as c_int
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquery(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    let (st, name, answer) = unsafe { qargs(st, name, answer, anslen) };
    nquery(st, false, name.unwrap_or_default(), class, ty, answer, anslen)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsearch(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    let (st, name, answer) = unsafe { qargs(st, name, answer, anslen) };
    nquery(st, true, name.unwrap_or_default(), class, ty, answer, anslen)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquerydomain(st: *mut ResState, name: *const c_char, domain: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    let (st, nm, answer) = unsafe { qargs(st, name, answer, anslen) };
    let domain = unsafe { ffi::cstr(domain) }.map(CStr::to_bytes);
    nquerydomain(st, nm.unwrap_or_default(), domain, class, ty, answer, anslen)
}

pub fn nsend(st: &mut ResState, m: &[u8], answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
    ensure_init(st);
    let cfg = config_of(st);
    let prev = begin_lookup(st);
    let r = nsend_cfg(&cfg, m, answer, anslen);
    end_lookup(st, prev);
    r
}

fn nsend_cfg(cfg: &Config, m: &[u8], answer: Option<&mut [u8]>, anslen: c_int) -> c_int {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsend(st: *mut ResState, msg: *const c_uchar, msglen: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    let (st, _, answer) = unsafe { qargs(st, core::ptr::null(), answer, anslen) };
    let m = unsafe { ffi::bytes(msg, msglen.max(0) as usize) };
    nsend(st, m, answer, anslen)
}

pub fn nmkquery(st: &mut ResState, op: c_int, dname: &[u8], class: c_int, ty: c_int, buf: Option<&mut [u8]>, buflen: c_int) -> c_int {
    ensure_init(st);
    let Some(out) = buf else { return -1 };
    if !(0..=65535).contains(&class) || !(0..=65535).contains(&ty) || buflen < (wire::HFIXEDSZ + 4) as c_int || (op != 0 && op != 4) {
        return -1;
    }
    let id = __res_randomid() as u16;
    st.id = id;
    let rd = st.options & dns::RES_RECURSE as c_ulong != 0;
    let mut tmp = [0u8; 1600];
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
        let h = wire::Header::parse(out).unwrap();
        wire::Header { flags: (h.flags & !0x7800) | (4 << 11), ..h }.write(out);
    }
    n as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nmkquery(st: *mut ResState, op: c_int, dname: *const c_char, class: c_int, ty: c_int, _data: *const c_uchar, _datalen: c_int, _newrr: *const c_uchar, buf: *mut c_uchar, buflen: c_int) -> c_int {
    let (st, dname, out) = unsafe { qargs(st, dname, buf, buflen) };
    nmkquery(st, op, dname.unwrap_or_default(), class, ty, out, buflen)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_query(name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe { res_nquery(__res_state(), name, class, ty, answer, anslen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_search(name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe { res_nsearch(__res_state(), name, class, ty, answer, anslen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_querydomain(name: *const c_char, domain: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe { res_nquerydomain(__res_state(), name, domain, class, ty, answer, anslen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_send(msg: *const c_uchar, msglen: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe { res_nsend(__res_state(), msg, msglen, answer, anslen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_mkquery(op: c_int, dname: *const c_char, class: c_int, ty: c_int, data: *const c_uchar, datalen: c_int, newrr: *const c_uchar, buf: *mut c_uchar, buflen: c_int) -> c_int {
    unsafe { res_nmkquery(__res_state(), op, dname, class, ty, data, datalen, newrr, buf, buflen) }
}

fn msgerr() -> c_int {
    errno::set(EMSGSIZE);
    -1
}

static NTOP_PLAIN: [bool; 256] = {
    let mut t = [false; 256];
    let mut c = 0x21;
    while c < 0x7f {
        t[c] = !matches!(c as u8, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$');
        c += 1;
    }
    t
};

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

#[inline]
pub(crate) fn uncompress_name(m: &[u8], off: usize, dst: &mut [u8]) -> Option<usize> {
    let mut tmp = [0u8; wire::MAXCDNAME];
    let used = wire::name_unpack(m, off, &mut tmp)?;
    ntop(&tmp, dst)?;
    Some(used)
}

#[inline]
pub(crate) fn skip_name(m: &[u8]) -> Option<usize> {
    wire::name_skip(m, 0)
}

pub(crate) fn offset_in(base: *const u8, p: *const u8) -> Option<usize> {
    let off = (p as usize).wrapping_sub(base as usize) as isize;
    if off < 0 { None } else { Some(off as usize) }
}

pub(crate) unsafe fn msg_slice<'a>(msg: *const u8, eom: *const u8) -> &'a [u8] {
    let n = (eom as usize).wrapping_sub(msg as usize) as isize;
    unsafe { ffi::bytes(msg, n.max(0) as usize) }
}

pub(crate) unsafe fn msg_dst<'a>(msg: *const u8, eom: *const u8, dst: *mut u8, dstsiz: usize) -> (&'a [u8], &'a mut [u8]) {
    let d = unsafe { ffi::bytes_mut(dst, dstsiz) };
    (unsafe { msg_slice(msg, eom) }, d)
}

unsafe fn wire_name_len(p: *const u8) -> usize {
    let mut i = 0usize;
    loop {
        let l = unsafe { *p.wrapping_add(i) } as usize;
        i += 1;
        if l == 0 || l >= 64 {
            return i;
        }
        i += l;
    }
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_uncompress(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    let (m, d) = unsafe { msg_dst(msg, eom, dst.cast::<u8>(), dstsiz) };
    match offset_in(msg, src).and_then(|off| uncompress_name(m, off, d)) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_unpack(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    let Some(off) = offset_in(msg, src) else { return msgerr() };
    let (m, d) = unsafe { msg_dst(msg, eom, dst, dstsiz) };
    match wire::name_unpack(m, off, d) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntop(src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    let n = unsafe { wire_name_len(src) };
    let s = unsafe { ffi::bytes(src, n) };
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), dstsiz) };
    match ntop(s, d) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pton(src: *const c_char, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    let d = unsafe { ffi::bytes_mut(dst, dstsiz) };
    match wire::name_pton(unsafe { ffi::cstr_bytes(src) }, d) {
        Some((_, fq)) => fq as c_int,
        None => msgerr(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_skip(ptrptr: *mut *const c_uchar, eom: *const c_uchar) -> c_int {
    let pp = unsafe { &mut *ptrptr };
    let start = *pp;
    match skip_name(unsafe { msg_slice(start, eom) }) {
        Some(n) => {
            *pp = start.wrapping_add(n);
            0
        }
        None => msgerr(),
    }
}

unsafe fn dn_find(domain: &[u8], msg: *const c_uchar, dnptrs: *const *const c_uchar, lastdnptr: *const *const c_uchar) -> c_int {
    let rd = |p: *const u8| unsafe { *p };
    let diff = |p: *const u8| (p as isize).wrapping_sub(msg as isize);
    let mut cpp = dnptrs;
    while cpp < lastdnptr {
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

unsafe fn pack(src: &[u8], dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    let diff = |p: *const u8, q: *const u8| (p as isize).wrapping_sub(q as isize);
    let mut dstp = dst;
    let eob = dst.wrapping_offset(dstsiz as isize);
    let mut msg: *const c_uchar = core::ptr::null();
    let mut cpp: *mut *const c_uchar = core::ptr::null_mut();
    let mut lpp: *mut *const c_uchar = core::ptr::null_mut();
    let mut dnp = dnptrs;
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
            let f = unsafe { dn_find(&src[i..], msg, dnp, lpp) };
            if f >= 0 {
                if diff(eob, dstp) <= 1 {
                    break false;
                }
                unsafe { core::ptr::copy_nonoverlapping([((f >> 8) as u8) | 0xc0, (f % 256) as u8].as_ptr(), dstp, 2) };
                return diff(dstp.wrapping_add(2), dst) as c_int;
            }
            if !lastdnptr.is_null() && cpp < lastdnptr.wrapping_sub(1) && diff(dstp, msg) < 0x4000 && first {
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
        let out = unsafe { core::slice::from_raw_parts_mut(dstp, n + 1) };
        copy_small(out, &src[i..i + n + 1]);
        i += n + 1;
        dstp = dstp.wrapping_add(n + 1);
        if n == 0 {
            break true;
        }
    };
    if !ok || dstp > eob {
        if !msg.is_null() && !lpp.is_null() {
            unsafe { *lpp = core::ptr::null() };
        }
        errno::set(EMSGSIZE);
        return -1;
    }
    diff(dstp, dst) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pack(src: *const c_uchar, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    let Some(len) = legal_name_len(|i| Some(unsafe { *src.wrapping_add(i) })) else { return msgerr() };
    let s = unsafe { ffi::bytes(src, len) };
    unsafe { pack(s, dst, dstsiz, dnptrs, lastdnptr) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_compress(src: *const c_char, dst: *mut c_uchar, dstsiz: usize, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    let mut tmp = [0u8; wire::MAXCDNAME + 1];
    let Some((len, _)) = wire::name_pton(unsafe { ffi::cstr_bytes(src) }, &mut tmp[..wire::MAXCDNAME]) else { return msgerr() };
    debug_assert_eq!(legal_name_len(|i| tmp.get(i).copied()), Some(len));
    unsafe { pack(&tmp[..len], dst, dstsiz as c_int, dnptrs, lastdnptr) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_comp(src: *const c_char, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *mut c_uchar, lastdnptr: *mut *mut c_uchar) -> c_int {
    unsafe { ns_name_compress(src, dst, dstsiz as usize, dnptrs as *mut *const c_uchar, lastdnptr as *mut *const c_uchar) }
}

pub fn expand(m: &[u8], off: Option<usize>, dst: &mut [u8]) -> c_int {
    match off.and_then(|off| uncompress_name(m, off, dst)) {
        Some(n) => {
            if dst[0] == b'.' {
                dst[0] = 0;
            }
            n as c_int
        }
        None => msgerr(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_expand(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: c_int) -> c_int {
    let (m, d) = unsafe { msg_dst(msg, eom, dst.cast::<u8>(), dstsiz.max(0) as usize) };
    expand(m, offset_in(msg, src), d)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_skipname(ptr: *const c_uchar, eom: *const c_uchar) -> c_int {
    match skip_name(unsafe { msg_slice(ptr, eom) }) {
        Some(n) => n as c_int,
        None => msgerr(),
    }
}

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

pub(crate) fn hostname_ok(name: &[u8]) -> bool {
    let Some(b) = pton_buf(name) else { return false };
    !(b[0] > 0 && b[1] == b'-') && binary_hnok(&b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_hnok(dn: *const c_char) -> c_int {
    hostname_ok(unsafe { ffi::cstr_bytes(dn) }) as c_int
}

pub(crate) fn dname_ok(name: &[u8]) -> bool {
    pton_buf(name).is_some()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_dnok(dn: *const c_char) -> c_int {
    dname_ok(unsafe { ffi::cstr_bytes(dn) }) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_ownok(dn: *const c_char) -> c_int {
    let Some(b) = pton_buf(unsafe { ffi::cstr_bytes(dn) }) else { return 0 };
    if b[0] > 0 && b[1] == b'-' {
        return 0;
    }
    if b[0] == 1 && b[1] == b'*' { binary_hnok(&b[2..]) as c_int } else { binary_hnok(&b) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_mailok(dn: *const c_char) -> c_int {
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
