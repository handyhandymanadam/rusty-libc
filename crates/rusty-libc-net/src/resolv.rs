use crate::dns::{self, Config, Server};
use crate::strerr::set_h_errno;
use crate::types::*;
use crate::util::{Buf, cbytes};
use crate::wire;
use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};
use rusty_libc_core::errno;

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
    pub extension_index: c_uint,
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
            vcsock: -1,
            flags: 0,
            u: ResExt { nscount: 0, nsmap: [0; MAXNS], nssocks: [-1; MAXNS], nscount6: 0, nsinit: 0, nsaddrs: [core::ptr::null_mut(); MAXNS], extension_index: 0 },
        }
    }
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut _res: ResState = ResState::zero();

#[thread_local]
static mut RESP_PTR: *mut ResState = core::ptr::null_mut();

unsafe extern "C" fn release_resp(obj: *mut c_void) {
    unsafe {
        let slot = obj as *mut *mut ResState;
        let p = *slot;
        if !p.is_null() && p != &raw mut _res {
            rusty_libc_malloc::free(p as *mut c_void);
        }
        *slot = core::ptr::null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_state() -> *mut ResState {
    unsafe {
        if RESP_PTR.is_null() {
            let main = rusty_libc_core::syscall::syscall0(186) == rusty_libc_core::syscall::syscall0(39);
            RESP_PTR = &raw mut _res;
            if !main {
                let p = rusty_libc_malloc::malloc(core::mem::size_of::<ResState>()) as *mut ResState;
                if !p.is_null() {
                    p.write(ResState::zero());
                    if rusty_libc_core::tls::register_thread_dtor(release_resp, (&raw mut RESP_PTR) as *mut c_void) {
                        RESP_PTR = p;
                    } else {
                        rusty_libc_malloc::free(p as *mut c_void);
                    }
                }
            }
        }
        RESP_PTR
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __res_randomid() -> c_uint {
    let mut idb = [0u8; 2];
    let _ = unsafe { rusty_libc_core::syscall::syscall3(318, idb.as_mut_ptr() as usize, 2, 0) };
    u16::from_ne_bytes(idb) as c_uint
}

fn set_herr(st: *mut ResState, h: c_int) {
    set_h_errno(h);
    if !st.is_null() {
        unsafe { (*st).res_h_errno = h };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_ninit(st: *mut ResState) -> c_int {
    unsafe {
        __res_nclose(st);
        let cfg = dns::default_config();
        *st = ResState::zero();
        let s = &mut *st;
        s.retrans = (cfg.timeout_ms / 1000) as c_int;
        s.retry = cfg.attempts as c_int;
        s.options = (cfg.options | dns::RES_INIT) as c_ulong;
        s.bits = cfg.ndots & 0xf;
        s.id = 0;
        let mut n4 = 0usize;
        for i in 0..cfg.nservers.min(MAXNS) {
            let sv = cfg.servers[i];
            if sv.family == AF_INET {
                s.nsaddr_list[n4] = sockaddr_in { sin_family: AF_INET as u16, sin_port: sv.port.to_be(), sin_addr: in_addr { s_addr: u32::from_ne_bytes([sv.addr[0], sv.addr[1], sv.addr[2], sv.addr[3]]) }, sin_zero: [0; 8] };
            } else {
                let p = rusty_libc_malloc::malloc(core::mem::size_of::<sockaddr_in6>()) as *mut sockaddr_in6;
                if !p.is_null() {
                    *p = sockaddr_in6 { sin6_family: AF_INET6 as u16, sin6_port: sv.port.to_be(), sin6_flowinfo: 0, sin6_addr: in6_addr { s6_addr: sv.addr }, sin6_scope_id: sv.scope };
                    s.u.nsaddrs[i] = p;
                }
                s.nsaddr_list[i].sin_family = 0;
            }
            n4 += 1;
            s.u.nsmap[i] = 1;
        }
        s.nscount = n4 as c_int;
        s.u.nscount = n4 as u16;
        s.u.nscount6 = (0..MAXNS).filter(|&i| !s.u.nsaddrs[i].is_null()).count() as u16;
        s.u.nsinit = 1;
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
            s.dnsrch[i] = s.defdname.as_mut_ptr().add(off);
            off += b.len() + 1;
        }
        if st == __res_state() {
            let snap = init_snap_slot();
            if !snap.is_null() {
                *snap = Some(config_of(st));
            }
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_init() -> c_int {
    unsafe { __res_ninit(__res_state()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nclose(st: *mut ResState) {
    unsafe {
        for i in 0..MAXNS {
            let p = (*st).u.nsaddrs[i];
            if !p.is_null() {
                rusty_libc_malloc::free(p as *mut c_void);
                (*st).u.nsaddrs[i] = core::ptr::null_mut();
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_iclose(st: *mut ResState, _free_addr: bool) {
    unsafe { __res_nclose(st) }
}

unsafe fn ensure_init(st: *mut ResState) {
    unsafe {
        if (*st).options & dns::RES_INIT as c_ulong == 0 {
            __res_ninit(st);
        }
    }
}

unsafe fn config_of(st: *mut ResState) -> Config {
    unsafe {
        let s = &*st;
        let mut c = Config::defaults();
        c.options = (s.options as u32) & !dns::RES_INIT;
        c.ndots = s.bits & 0xf;
        c.timeout_ms = (s.retrans.max(0) as u32) * 1000;
        if c.timeout_ms == 0 {
            c.timeout_ms = 5000;
        }
        c.attempts = s.retry.max(1) as u32;
        c.nservers = 0;
        for i in 0..(s.nscount.max(0) as usize).min(MAXNS) {
            let p6 = s.u.nsaddrs[i];
            if !p6.is_null() {
                c.servers[c.nservers] = Server::v6((*p6).sin6_addr.s6_addr, u16::from_be((*p6).sin6_port), (*p6).sin6_scope_id);
                c.nservers += 1;
            } else if s.nsaddr_list[i].sin_family == AF_INET as u16 {
                let a = s.nsaddr_list[i].sin_addr.s_addr.to_ne_bytes();
                c.servers[c.nservers] = Server::v4(a, u16::from_be(s.nsaddr_list[i].sin_port));
                c.nservers += 1;
            }
        }
        c.finish();
        c.nsearch = 0;
        for i in 0..MAXDNSRCH {
            let p = s.dnsrch[i];
            if p.is_null() {
                break;
            }
            if let Some(b) = Buf::<256>::from(cbytes(p)) {
                c.search[c.nsearch] = b;
                c.nsearch += 1;
            }
        }
        c
    }
}

#[thread_local]
static mut INIT_SNAP: *mut Option<Config> = core::ptr::null_mut();

unsafe extern "C" fn release_snap(obj: *mut c_void) {
    unsafe {
        let slot = obj as *mut *mut Option<Config>;
        if !(*slot).is_null() {
            rusty_libc_malloc::free(*slot as *mut c_void);
        }
        *slot = core::ptr::null_mut();
    }
}

unsafe fn init_snap_slot() -> *mut Option<Config> {
    unsafe {
        if INIT_SNAP.is_null() {
            let p = rusty_libc_malloc::malloc(core::mem::size_of::<Option<Config>>()) as *mut Option<Config>;
            if p.is_null() {
                return p;
            }
            p.write(None);
            if !rusty_libc_core::tls::register_thread_dtor(release_snap, (&raw mut INIT_SNAP) as *mut c_void) {
                rusty_libc_malloc::free(p as *mut c_void);
                return core::ptr::null_mut();
            }
            INIT_SNAP = p;
        }
        INIT_SNAP
    }
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

pub fn current_config() -> Config {
    unsafe {
        let st = __res_state();
        if (*st).options & dns::RES_INIT as c_ulong == 0 {
            __res_ninit(st);
        }
        let c = config_of(st);
        let slot = INIT_SNAP;
        let none = None;
        let snapshot: &Option<Config> = if slot.is_null() { &none } else { &*slot };
        match snapshot {
            Some(snap) if same_config(snap, &c) => dns::default_config(),
            _ => c,
        }
    }
}

fn herr_result(st: *mut ResState, e: dns::HErr) -> c_int {
    if e.errno != 0 {
        errno::set(e.errno);
    }
    set_herr(st, e.h);
    -1
}

unsafe fn caller_buffer<'a>(answer: *mut c_uchar, anslen: c_int) -> Option<&'a mut [u8]> {
    if answer.is_null() || anslen < wire::HFIXEDSZ as c_int {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts_mut(answer, anslen as usize) })
}

unsafe fn finish_answer(ans: &[u8], n: usize, answer: *mut c_uchar, anslen: c_int) -> c_int {
    let m = n.min(anslen.max(0) as usize);
    unsafe { core::ptr::copy_nonoverlapping(ans.as_ptr(), answer, m) };
    m as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquery(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe {
        ensure_init(st);
        let cfg = config_of(st);
        if let Some(buf) = caller_buffer(answer, anslen) {
            return match dns::query_adv(&cfg, cbytes(name), class as u16, ty as u16, buf, anslen as usize) {
                Ok(n) => {
                    set_herr(st, NETDB_SUCCESS);
                    n as c_int
                }
                Err(e) => herr_result(st, e),
            };
        }
        let mut ans = [0u8; 4096];
        match dns::query_adv(&cfg, cbytes(name), class as u16, ty as u16, &mut ans, anslen.max(0) as usize) {
            Ok(n) => {
                set_herr(st, NETDB_SUCCESS);
                finish_answer(&ans, n, answer, anslen)
            }
            Err(e) => herr_result(st, e),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsearch(st: *mut ResState, name: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe {
        ensure_init(st);
        let cfg = config_of(st);
        if let Some(buf) = caller_buffer(answer, anslen) {
            return match dns::search_adv(&cfg, cbytes(name), class as u16, ty as u16, buf, anslen as usize) {
                Ok(n) => {
                    set_herr(st, NETDB_SUCCESS);
                    n as c_int
                }
                Err(e) => herr_result(st, e),
            };
        }
        let mut ans = [0u8; 4096];
        match dns::search_adv(&cfg, cbytes(name), class as u16, ty as u16, &mut ans, anslen.max(0) as usize) {
            Ok(n) => {
                set_herr(st, NETDB_SUCCESS);
                finish_answer(&ans, n, answer, anslen)
            }
            Err(e) => herr_result(st, e),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nquerydomain(st: *mut ResState, name: *const c_char, domain: *const c_char, class: c_int, ty: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe {
        ensure_init(st);
        let nm = cbytes(name);
        let mut full = Buf::<1026>::new();
        if domain.is_null() {
            if nm.len() >= dns::MAXDNAME {
                errno::set(EMSGSIZE);
                set_herr(st, NETDB_INTERNAL);
                return -1;
            }
            full.push_all(nm.strip_suffix(b".").unwrap_or(nm));
        } else {
            let d = cbytes(domain);
            if nm.len() + d.len() + 1 >= dns::MAXDNAME {
                errno::set(EMSGSIZE);
                set_herr(st, NETDB_INTERNAL);
                return -1;
            }
            full.push_all(nm);
            full.push(b'.');
            full.push_all(d);
        }
        full.push(0);
        res_nquery(st, full.b.as_ptr() as *const c_char, class, ty, answer, anslen)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nsend(st: *mut ResState, msg: *const c_uchar, msglen: c_int, answer: *mut c_uchar, anslen: c_int) -> c_int {
    unsafe {
        ensure_init(st);
        let cfg = config_of(st);
        let m = core::slice::from_raw_parts(msg, msglen.max(0) as usize);
        let mut own = [0u8; 4096];
        let (ans, direct) = match caller_buffer(answer, anslen) {
            Some(b) => (b, true),
            None => (&mut own[..], false),
        };
        let sent = {
            let mut a = dns::Answer::fixed(ans);
            match dns::send_query_noaaaa(&cfg, m, &mut a) {
                Some(r) => r,
                None => dns::send_query_ans(&cfg, m, &mut a),
            }
        };
        match sent {
            Ok(n) if direct => n as c_int,
            Ok(n) => finish_answer(ans, n.min(ans.len()), answer, anslen),
            Err(dns::SendErr::Refused) => {
                errno::set(ECONNREFUSED);
                set_herr(st, TRY_AGAIN);
                -1
            }
            Err(dns::SendErr::Timeout) => {
                errno::set(ETIMEDOUT);
                set_herr(st, TRY_AGAIN);
                -1
            }
            Err(dns::SendErr::Other(e)) => {
                errno::set(e);
                set_herr(st, TRY_AGAIN);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_nmkquery(st: *mut ResState, op: c_int, dname: *const c_char, class: c_int, ty: c_int, _data: *const c_uchar, _datalen: c_int, _newrr: *const c_uchar, buf: *mut c_uchar, buflen: c_int) -> c_int {
    unsafe {
        ensure_init(st);
        if buflen < wire::HFIXEDSZ as c_int || (op != 0 && op != 4) {
            errno::set(EINVAL);
            set_herr(st, NETDB_INTERNAL);
            return -1;
        }
        let s = &mut *st;
        let id = __res_randomid() as u16;
        s.id = id;
        let out = core::slice::from_raw_parts_mut(buf, buflen as usize);
        let rd = s.options & dns::RES_RECURSE as c_ulong != 0;
        let mut tmp = [0u8; 1600];
        let Some(n) = wire::build_query(id, cbytes(dname), ty as u16, class as u16, rd, None, &mut tmp) else {
            errno::set(EMSGSIZE);
            set_herr(st, NETDB_INTERNAL);
            return -1;
        };
        if n > out.len() {
            errno::set(EMSGSIZE);
            set_herr(st, NETDB_INTERNAL);
            return -1;
        }
        out[..n].copy_from_slice(&tmp[..n]);
        if s.options & dns::RES_TRUSTAD as c_ulong != 0 {
            out[3] |= 0x20;
        }
        if op == 4 {
            let h = wire::Header::parse(out).unwrap();
            wire::Header { flags: (h.flags & !0x7800) | (4 << 11), ..h }.write(out);
        }
        n as c_int
    }
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

pub(crate) unsafe fn ntop_raw(src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> Option<usize> {
    unsafe {
        let mut cp = src;
        let mut dn = 0usize;
        loop {
            let l = *cp as usize;
            cp = cp.add(1);
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
                *dst.add(dn) = b'.';
                dn += 1;
            }
            for _ in 0..l {
                let c = *cp;
                cp = cp.add(1);
                if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                    if dstsiz - dn < 2 {
                        return None;
                    }
                    *dst.add(dn) = b'\\';
                    *dst.add(dn + 1) = c;
                    dn += 2;
                } else if !(c > 0x20 && c < 0x7f) {
                    if dstsiz - dn < 4 {
                        return None;
                    }
                    *dst.add(dn) = b'\\';
                    *dst.add(dn + 1) = b'0' + c / 100;
                    *dst.add(dn + 2) = b'0' + (c % 100) / 10;
                    *dst.add(dn + 3) = b'0' + c % 10;
                    dn += 4;
                } else {
                    if dstsiz - dn < 2 {
                        return None;
                    }
                    *dst.add(dn) = c;
                    dn += 1;
                }
            }
        }
        if dn == 0 {
            if dn >= dstsiz {
                return None;
            }
            *dst = b'.';
            dn += 1;
        }
        if dn >= dstsiz {
            return None;
        }
        *dst.add(dn) = 0;
        Some(dn + 1)
    }
}

pub(crate) unsafe fn uncompress_name(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> Option<usize> {
    unsafe {
        let mlen = (eom as usize).wrapping_sub(msg as usize) as isize;
        let m = core::slice::from_raw_parts(msg, mlen.max(0) as usize);
        let off = (src as usize).wrapping_sub(msg as usize) as isize;
        if off < 0 {
            return None;
        }
        let mut tmp = [0u8; wire::MAXCDNAME];
        let used = wire::name_unpack(m, off as usize, &mut tmp)?;
        ntop_raw(tmp.as_ptr(), dst, dstsiz)?;
        Some(used)
    }
}

pub(crate) unsafe fn skip_name(p: *const c_uchar, eom: *const c_uchar) -> Option<usize> {
    unsafe {
        let m = core::slice::from_raw_parts(p, eom.offset_from(p).max(0) as usize);
        wire::name_skip(m, 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_uncompress(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    unsafe {
        match uncompress_name(msg, eom, src, dst as *mut c_uchar, dstsiz) {
            Some(n) => n as c_int,
            None => msgerr(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_unpack(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    unsafe {
        let m = core::slice::from_raw_parts(msg, eom.offset_from(msg) as usize);
        let off = src.offset_from(msg);
        if off < 0 {
            return msgerr();
        }
        let d = core::slice::from_raw_parts_mut(dst, dstsiz);
        match wire::name_unpack(m, off as usize, d) {
            Some(n) => n as c_int,
            None => msgerr(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntop(src: *const c_uchar, dst: *mut c_char, dstsiz: usize) -> c_int {
    unsafe {
        match ntop_raw(src, dst as *mut c_uchar, dstsiz) {
            Some(n) => n as c_int,
            None => msgerr(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pton(src: *const c_char, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    unsafe {
        let d = core::slice::from_raw_parts_mut(dst, dstsiz);
        match wire::name_pton(cbytes(src), d) {
            Some((_, fq)) => fq as c_int,
            None => msgerr(),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_skip(ptrptr: *mut *const c_uchar, eom: *const c_uchar) -> c_int {
    unsafe {
        let start = *ptrptr;
        match skip_name(start, eom) {
            Some(n) => {
                *ptrptr = start.add(n);
                0
            }
            None => msgerr(),
        }
    }
}

unsafe fn dn_find(domain: *const c_uchar, msg: *const c_uchar, dnptrs: *const *const c_uchar, lastdnptr: *const *const c_uchar) -> c_int {
    unsafe {
        let mut cpp = dnptrs;
        while cpp < lastdnptr {
            let mut sp = *cpp;
            while *sp != 0 && (*sp & 0xc0) == 0 && sp.offset_from(msg) < 0x4000 {
                let mut dn = domain;
                let mut cp = sp;
                'outer: loop {
                    let n = *cp as usize;
                    cp = cp.add(1);
                    if n == 0 {
                        break;
                    }
                    match n & 0xc0 {
                        0 => {
                            if n as u8 != *dn {
                                break 'outer;
                            }
                            dn = dn.add(1);
                            for _ in 0..n {
                                if !(*dn).eq_ignore_ascii_case(&*cp) {
                                    break 'outer;
                                }
                                dn = dn.add(1);
                                cp = cp.add(1);
                            }
                            if *dn == 0 && *cp == 0 {
                                return sp.offset_from(msg) as c_int;
                            }
                            if *dn != 0 {
                                continue;
                            }
                            break 'outer;
                        }
                        0xc0 => {
                            cp = msg.add(((n & 0x3f) << 8) | *cp as usize);
                        }
                        _ => {
                            errno::set(EMSGSIZE);
                            return -1;
                        }
                    }
                }
                sp = sp.add(*sp as usize + 1);
            }
            cpp = cpp.add(1);
        }
        errno::set(ENOENT);
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pack(src: *const c_uchar, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    unsafe {
        let mut dstp = dst;
        let eob = dst.offset(dstsiz as isize);
        #[allow(unused_assignments)]
        let mut msg: *const c_uchar = core::ptr::null();
        let mut cpp: *mut *const c_uchar = core::ptr::null_mut();
        let mut lpp: *mut *const c_uchar = core::ptr::null_mut();
        let mut dnp = dnptrs;
        if !dnp.is_null() {
            msg = *dnp;
            dnp = dnp.add(1);
            if !msg.is_null() {
                cpp = dnp;
                while !(*cpp).is_null() {
                    cpp = cpp.add(1);
                }
                lpp = cpp;
            }
        } else {
            msg = core::ptr::null();
        }
        let mut l = 0usize;
        let mut srcp = src;
        loop {
            let n = *srcp as usize;
            if n >= 64 {
                return msgerr();
            }
            l += n + 1;
            if l > wire::MAXCDNAME {
                return msgerr();
            }
            srcp = srcp.add(n + 1);
            if n == 0 {
                break;
            }
        }
        srcp = src;
        let mut first = true;
        let ok = loop {
            let n = *srcp as usize;
            if n != 0 && !msg.is_null() {
                let f = dn_find(srcp, msg, dnp as *const *const c_uchar, lpp as *const *const c_uchar);
                if f >= 0 {
                    if eob.offset_from(dstp) <= 1 {
                        break false;
                    }
                    *dstp = ((f >> 8) as u8) | 0xc0;
                    *dstp.add(1) = (f % 256) as u8;
                    return dstp.add(2).offset_from(dst) as c_int;
                }
                if !lastdnptr.is_null() && cpp < lastdnptr.sub(1) && dstp.offset_from(msg) < 0x4000 && first {
                    *cpp = dstp;
                    cpp = cpp.add(1);
                    *cpp = core::ptr::null();
                    first = false;
                }
            }
            if n >= 64 {
                break false;
            }
            if (n + 1) as isize > eob.offset_from(dstp) {
                break false;
            }
            core::ptr::copy_nonoverlapping(srcp, dstp, n + 1);
            srcp = srcp.add(n + 1);
            dstp = dstp.add(n + 1);
            if n == 0 {
                break true;
            }
        };
        if !ok || dstp > eob {
            if !msg.is_null() && !lpp.is_null() {
                *lpp = core::ptr::null();
            }
            errno::set(EMSGSIZE);
            return -1;
        }
        dstp.offset_from(dst) as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_compress(src: *const c_char, dst: *mut c_uchar, dstsiz: usize, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) -> c_int {
    unsafe {
        let mut tmp = [0u8; wire::MAXCDNAME + 1];
        if wire::name_pton(cbytes(src), &mut tmp[..wire::MAXCDNAME]).is_none() {
            return msgerr();
        }
        ns_name_pack(tmp.as_ptr(), dst, dstsiz as c_int, dnptrs, lastdnptr)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_comp(src: *const c_char, dst: *mut c_uchar, dstsiz: c_int, dnptrs: *mut *mut c_uchar, lastdnptr: *mut *mut c_uchar) -> c_int {
    unsafe { ns_name_compress(src, dst, dstsiz as usize, dnptrs as *mut *const c_uchar, lastdnptr as *mut *const c_uchar) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_expand(msg: *const c_uchar, eom: *const c_uchar, src: *const c_uchar, dst: *mut c_char, dstsiz: c_int) -> c_int {
    unsafe {
        let n = ns_name_uncompress(msg, eom, src, dst, dstsiz.max(0) as usize);
        if n > 0 && *dst == b'.' as c_char {
            *dst = 0;
        }
        n
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dn_skipname(ptr: *const c_uchar, eom: *const c_uchar) -> c_int {
    unsafe {
        let mut p = ptr;
        if ns_name_skip(&mut p, eom) == -1 {
            return -1;
        }
        p.offset_from(ptr) as c_int
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
    hostname_ok(unsafe { cbytes(dn) }) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_dnok(dn: *const c_char) -> c_int {
    pton_buf(unsafe { cbytes(dn) }).is_some() as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_ownok(dn: *const c_char) -> c_int {
    let Some(b) = pton_buf(unsafe { cbytes(dn) }) else { return 0 };
    if b[0] > 0 && b[1] == b'-' {
        return 0;
    }
    if b[0] == 1 && b[1] == b'*' { binary_hnok(&b[2..]) as c_int } else { binary_hnok(&b) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn res_mailok(dn: *const c_char) -> c_int {
    let Some(b) = pton_buf(unsafe { cbytes(dn) }) else { return 0 };
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
