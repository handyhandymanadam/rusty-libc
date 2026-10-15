#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::resolv::{ResState, dname_ok, hostname_ok, nquery, with_this_state};
use crate::strerr::set_h_errno;
use crate::types::{EAFNOSUPPORT, EINVAL, HOST_NOT_FOUND, NETDB_INTERNAL, NETDB_SUCCESS, NO_RECOVERY, hostent};
use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi};

const MAXALIASES: usize = 35;
const MAXADDRS: usize = 35;
const MAXHOSTNAMELEN: usize = 256;
const MAXDNAME: usize = 1025;
const HOSTBUF: usize = 8 * 1024;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const T_A: c_int = 1;
const T_CNAME: c_int = 5;
const T_PTR: c_int = 12;
const T_AAAA: c_int = 28;
const C_IN: c_int = 1;
const HFIXEDSZ: usize = 12;
const QFIXEDSZ: usize = 4;
const ECONNREFUSED: c_int = 111;

struct Compat {
    host: hostent,
    aliases: [*mut c_char; MAXALIASES],
    addr_ptrs: [*mut c_char; MAXADDRS + 1],
    hostbuf: [u8; HOSTBUF],
    host_addr: [u8; 16],
    file_buf: [u8; 4096],
    file_pos: usize,
    file_len: usize,
    stayopen: c_int,
    ent_name: usize,
    ent_aliases: [usize; MAXALIASES],
    ent_naliases: usize,
}

const STATE_SIZE: usize = core::mem::size_of::<Compat>();

static STATE: SyncCell<Compat> = SyncCell::new(Compat {
    host: hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() },
    aliases: [core::ptr::null_mut(); MAXALIASES],
    addr_ptrs: [core::ptr::null_mut(); MAXADDRS + 1],
    hostbuf: [0; HOSTBUF],
    host_addr: [0; 16],
    file_buf: [0; 4096],
    file_pos: 0,
    file_len: 0,
    stayopen: 0,
    ent_name: 0,
    ent_aliases: [0; MAXALIASES],
    ent_naliases: 0,
});

static HOSTF: AtomicI32 = AtomicI32::new(-1);

unsafe fn with_state<R>(f: impl FnOnce(&mut Compat) -> R) -> R {
    unsafe { STATE.with_unsync(f) }
}

impl Compat {
    fn buf_ptr(&mut self, off: usize) -> *mut c_char {
        self.hostbuf.as_mut_ptr().wrapping_add(off).cast::<c_char>()
    }

    fn host_ptr(&mut self) -> *mut hostent {
        &raw mut self.host
    }

    fn single_addr(&mut self) {
        self.addr_ptrs[0] = self.host_addr.as_mut_ptr().cast::<c_char>();
        self.addr_ptrs[1] = core::ptr::null_mut();
        self.host.h_addr_list = self.addr_ptrs.as_mut_ptr();
    }
}

fn text(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn detach<'a>(s: &'a [u8], local: &'a mut [u8; STATE_SIZE]) -> &'a [u8] {
    let a = STATE.as_ptr() as usize;
    let p = s.as_ptr() as usize;
    if p < a + STATE_SIZE && p + s.len() > a {
        let n = s.len().min(STATE_SIZE);
        local[..n].copy_from_slice(&s[..n]);
        &local[..n]
    } else {
        s
    }
}

unsafe fn with_input<R>(p: *const u8, len: Option<usize>, f: impl FnOnce(&mut Compat, &[u8]) -> R) -> R {
    let mut local = [0u8; STATE_SIZE];
    let s = match len {
        None => unsafe { ffi::cstr_bytes(p) },
        Some(n) => unsafe { ffi::bytes(p, n) },
    };
    let input = detach(s, &mut local);
    unsafe { with_state(|st| f(st, input)) }
}

fn use_inet6() -> bool {
    false
}

fn herr(v: c_int) {
    set_h_errno(v);
}

fn addrsort(hostbuf: &[u8], offs: &mut [usize], st: &ResState) {
    let nsort = (st.bits >> 4) & 0xf;
    let num = offs.len();
    let mut aval = [0i16; MAXADDRS];
    let mut needsort = 0usize;
    for i in 0..num {
        let o = offs[i];
        let a = u32::from_ne_bytes([hostbuf[o], hostbuf[o + 1], hostbuf[o + 2], hostbuf[o + 3]]);
        let mut j = 0usize;
        while (j as u32) < nsort {
            if st.sort_list[j].addr.s_addr == (a & st.sort_list[j].mask) {
                break;
            }
            j += 1;
        }
        aval[i] = j as i16;
        if needsort == 0 && i > 0 && (j as i16) < aval[i - 1] {
            needsort = i;
        }
    }
    if needsort == 0 {
        return;
    }
    while needsort < num {
        let mut j = needsort as isize - 1;
        while j >= 0 {
            let ju = j as usize;
            if aval[ju] > aval[ju + 1] {
                aval.swap(ju, ju + 1);
                offs.swap(ju, ju + 1);
            } else {
                break;
            }
            j -= 1;
        }
        needsort += 1;
    }
}

fn be16(b: &[u8], i: usize) -> c_int {
    u16::from_be_bytes([b[i], b[i + 1]]) as c_int
}

fn expand_at(st: &mut Compat, m: &[u8], cp: usize, bp: usize, buflen: c_int) -> c_int {
    let start = bp.min(HOSTBUF);
    let len = (buflen.max(0) as usize).min(HOSTBUF - start);
    crate::resolv::expand(m, Some(cp), &mut st.hostbuf[start..start + len])
}

fn getanswer(st: &mut Compat, rs: &ResState, full: &[u8; 4096], anslen: usize, qname: &[u8], qtype: c_int) -> bool {
    st.host.h_name = core::ptr::null_mut();
    let m = &full[..anslen];
    let eom = anslen;
    let name_ok: fn(&[u8]) -> bool = match qtype {
        T_A | T_AAAA => hostname_ok,
        T_PTR => dname_ok,
        _ => return false,
    };
    let ancount_hdr = be16(full, 6);
    let qdcount = be16(full, 4);
    let mut bp = 0usize;
    let mut buflen: c_int = HOSTBUF as c_int;
    let mut cp = 0usize;
    macro_rules! bounded_incr {
        ($x:expr) => {
            cp += $x as usize;
            if cp > eom {
                herr(NO_RECOVERY);
                return false;
            }
        };
    }
    macro_rules! bounds_check {
        ($ptr:expr, $count:expr) => {
            if $ptr + $count as usize > eom {
                herr(NO_RECOVERY);
                return false;
            }
        };
    }
    bounded_incr!(HFIXEDSZ);
    if qdcount != 1 {
        herr(NO_RECOVERY);
        return false;
    }
    let mut n = expand_at(st, m, cp, bp, buflen);
    if n < 0 || !name_ok(text(&st.hostbuf[bp..])) {
        herr(NO_RECOVERY);
        return false;
    }
    bounded_incr!(n as usize + QFIXEDSZ);
    let mut hname: Option<usize> = None;
    let mut qname_at: Option<usize> = None;
    if qtype == T_A || qtype == T_AAAA {
        n = text(&st.hostbuf[bp..]).len() as c_int + 1;
        if n as usize >= MAXHOSTNAMELEN {
            herr(NO_RECOVERY);
            return false;
        }
        hname = Some(bp);
        st.host.h_name = st.buf_ptr(bp);
        bp += n as usize;
        buflen -= n;
        qname_at = hname;
    }
    let mut na = 0usize;
    st.aliases[0] = core::ptr::null_mut();
    st.host.h_aliases = st.aliases.as_mut_ptr();
    let mut nh = 0usize;
    let mut addr_offs = [0usize; MAXADDRS];
    st.addr_ptrs[0] = core::ptr::null_mut();
    st.host.h_addr_list = st.addr_ptrs.as_mut_ptr();
    let mut tname: Option<usize> = None;
    let mut haveanswer = 0;
    let mut had_error = 0;
    let mut ancount = ancount_hdr;
    let mut tbuf = [0u8; MAXDNAME];
    while ancount > 0 && cp < eom && had_error == 0 {
        ancount -= 1;
        n = expand_at(st, m, cp, bp, buflen);
        if n < 0 || !name_ok(text(&st.hostbuf[bp..])) {
            had_error += 1;
            continue;
        }
        cp += n as usize;
        bounds_check!(cp, 3 * 2 + 4);
        let ty = be16(m, cp);
        cp += 2;
        let class = be16(m, cp);
        cp += 2 + 4;
        n = be16(m, cp);
        cp += 2;
        bounds_check!(cp, n);
        let erdata = cp + n as usize;
        if class != C_IN {
            cp += n as usize;
            continue;
        }
        if (qtype == T_A || qtype == T_AAAA) && ty == T_CNAME {
            if na >= MAXALIASES - 1 {
                continue;
            }
            n = crate::resolv::expand(m, Some(cp), &mut tbuf);
            if n < 0 || !name_ok(text(&tbuf)) {
                had_error += 1;
                continue;
            }
            cp += n as usize;
            if cp != erdata {
                herr(NO_RECOVERY);
                return false;
            }
            st.aliases[na] = st.buf_ptr(bp);
            na += 1;
            n = text(&st.hostbuf[bp..]).len() as c_int + 1;
            if n as usize >= MAXHOSTNAMELEN {
                had_error += 1;
                continue;
            }
            bp += n as usize;
            buflen -= n;
            n = text(&tbuf).len() as c_int + 1;
            if n > buflen || n as usize >= MAXHOSTNAMELEN {
                had_error += 1;
                continue;
            }
            st.hostbuf[bp..bp + n as usize].copy_from_slice(&tbuf[..n as usize]);
            hname = Some(bp);
            st.host.h_name = st.buf_ptr(bp);
            bp += n as usize;
            buflen -= n;
            continue;
        }
        if qtype == T_PTR && ty == T_CNAME {
            n = crate::resolv::expand(m, Some(cp), &mut tbuf);
            if n < 0 || !dname_ok(text(&tbuf)) {
                had_error += 1;
                continue;
            }
            cp += n as usize;
            if cp != erdata {
                herr(NO_RECOVERY);
                return false;
            }
            n = text(&tbuf).len() as c_int + 1;
            if n > buflen || n as usize >= MAXHOSTNAMELEN {
                had_error += 1;
                continue;
            }
            st.hostbuf[bp..bp + n as usize].copy_from_slice(&tbuf[..n as usize]);
            tname = Some(bp);
            bp += n as usize;
            buflen -= n;
            continue;
        }
        if ty != qtype {
            cp += n as usize;
            continue;
        }
        match ty {
            T_PTR => {
                let same = {
                    let tn = match tname {
                        None => qname,
                        Some(o) => text(&st.hostbuf[o..]),
                    };
                    tn.eq_ignore_ascii_case(text(&st.hostbuf[bp..]))
                };
                if !same {
                    cp += n as usize;
                    continue;
                }
                n = expand_at(st, m, cp, bp, buflen);
                if n < 0 || !hostname_ok(text(&st.hostbuf[bp..])) {
                    had_error += 1;
                } else {
                    cp += n as usize;
                    if cp != erdata {
                        herr(NO_RECOVERY);
                        return false;
                    }
                    if haveanswer == 0 {
                        hname = Some(bp);
                        st.host.h_name = st.buf_ptr(bp);
                    } else if na < MAXALIASES - 1 {
                        st.aliases[na] = st.buf_ptr(bp);
                        na += 1;
                    } else {
                        n = -1;
                    }
                    if n != -1 {
                        n = text(&st.hostbuf[bp..]).len() as c_int + 1;
                        if n as usize >= MAXHOSTNAMELEN {
                            had_error += 1;
                        } else {
                            bp += n as usize;
                            buflen -= n;
                        }
                    }
                }
            }
            T_A | T_AAAA => {
                let same = hname.is_some_and(|o| text(&st.hostbuf[o..]).eq_ignore_ascii_case(text(&st.hostbuf[bp..])));
                if !same {
                    cp += n as usize;
                    continue;
                }
                if n != st.host.h_length {
                    cp += n as usize;
                    continue;
                }
                if haveanswer == 0 {
                    hname = Some(bp);
                    st.host.h_name = st.buf_ptr(bp);
                    let nn = text(&st.hostbuf[bp..]).len() as c_int + 1;
                    bp += nn as usize;
                    buflen -= nn;
                }
                let pad = 4 - ((st.hostbuf.as_ptr() as usize).wrapping_add(bp) % 4);
                buflen -= pad as c_int;
                bp += pad;
                if bp + n as usize >= HOSTBUF {
                    had_error += 1;
                    continue;
                }
                if nh >= MAXADDRS - 1 {
                    cp += n as usize;
                    continue;
                }
                st.addr_ptrs[nh] = st.buf_ptr(bp);
                addr_offs[nh] = bp;
                nh += 1;
                st.hostbuf[bp..bp + n as usize].copy_from_slice(&m[cp..cp + n as usize]);
                bp += n as usize;
                buflen -= n;
                cp += n as usize;
                if cp != erdata {
                    herr(NO_RECOVERY);
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
        if had_error == 0 {
            haveanswer += 1;
        }
    }
    if haveanswer != 0 {
        st.aliases[na] = core::ptr::null_mut();
        st.addr_ptrs[nh] = core::ptr::null_mut();
        if (rs.bits >> 4) & 0xf != 0 && haveanswer > 1 && qtype == T_A {
            let num = (haveanswer as usize).min(nh);
            addrsort(&st.hostbuf, &mut addr_offs[..num], rs);
            for (i, &o) in addr_offs[..num].iter().enumerate() {
                st.addr_ptrs[i] = st.buf_ptr(o);
            }
        }
        if hname.is_none() {
            let q: &[u8] = match qname_at {
                None => qname,
                Some(o) => text(&st.hostbuf[o..]),
            };
            let qlen = q.len();
            n = qlen as c_int + 1;
            if n > buflen || n as usize >= MAXHOSTNAMELEN {
                herr(NO_RECOVERY);
                return false;
            }
            let mut qcopy = [0u8; MAXHOSTNAMELEN];
            qcopy[..qlen].copy_from_slice(q);
            st.hostbuf[bp..bp + qlen].copy_from_slice(&qcopy[..qlen]);
            st.hostbuf[bp + qlen] = 0;
            st.host.h_name = st.buf_ptr(bp);
        }
        herr(NETDB_SUCCESS);
        return true;
    }
    herr(NO_RECOVERY);
    false
}

fn fill_literal(st: &mut Compat, name: &[u8]) {
    let n = name.len().min(MAXDNAME);
    st.hostbuf[..n].copy_from_slice(&name[..n]);
    st.hostbuf[n..=MAXDNAME].fill(0);
    st.host.h_name = st.buf_ptr(0);
    st.aliases[0] = core::ptr::null_mut();
    st.host.h_aliases = st.aliases.as_mut_ptr();
    st.single_addr();
}

fn pton_into(af: c_int, name: &[u8], dst: &mut [u8; 16]) -> c_int {
    if af == AF_INET {
        match crate::inet::parse_ipv4(name) {
            Some(a) => {
                dst[..4].copy_from_slice(&a);
                1
            }
            None => 0,
        }
    } else {
        match crate::inet::parse_ipv6(name) {
            Some(a) => {
                *dst = a;
                1
            }
            None => 0,
        }
    }
}

fn res_gethostbyname2_context(st: &mut Compat, name: &[u8], af: c_int) -> *mut hostent {
    let (size, ty) = match af {
        AF_INET => (4, T_A),
        AF_INET6 => (16, T_AAAA),
        _ => {
            herr(NETDB_INTERNAL);
            errno::set(EAFNOSUPPORT);
            return core::ptr::null_mut();
        }
    };
    st.host.h_addrtype = af;
    st.host.h_length = size;
    with_this_state(|rs| lookup_name(st, rs, name, af, ty))
}

fn lookup_name(st: &mut Compat, rs: &mut ResState, name: &[u8], af: c_int, ty: c_int) -> *mut hostent {
    let mut name = name;
    let alias;
    if name.contains(&b'.') {
        if let Some(a) = crate::resdebug::host_alias(rs.options, name) {
            alias = a;
            name = alias.as_bytes();
        }
    }
    let nb = name;
    if !nb.is_empty() && nb[0].is_ascii_digit() {
        let mut i = 0;
        loop {
            if i == nb.len() {
                if nb[i - 1] == b'.' {
                    break;
                }
                if pton_into(af, name, &mut st.host_addr) <= 0 {
                    herr(HOST_NOT_FOUND);
                    return core::ptr::null_mut();
                }
                fill_literal(st, name);
                herr(NETDB_SUCCESS);
                return st.host_ptr();
            }
            if !nb[i].is_ascii_digit() && nb[i] != b'.' {
                break;
            }
            i += 1;
        }
    }
    let first_hex = !nb.is_empty() && nb[0].is_ascii_hexdigit() && nb.contains(&b':');
    if first_hex || (!nb.is_empty() && nb[0] == b':') {
        let mut i = 0;
        loop {
            if i == nb.len() {
                if nb[i - 1] == b'.' {
                    break;
                }
                if pton_into(af, name, &mut st.host_addr) <= 0 {
                    herr(HOST_NOT_FOUND);
                    return core::ptr::null_mut();
                }
                fill_literal(st, name);
                herr(NETDB_SUCCESS);
                return st.host_ptr();
            }
            if !nb[i].is_ascii_hexdigit() && nb[i] != b':' && nb[i] != b'.' {
                break;
            }
            i += 1;
        }
    }
    let mut buf = [0u8; 4096];
    let n = nquery(rs, true, name, C_IN, ty, Some(&mut buf), 4096);
    if n < 0 {
        if errno::get() == ECONNREFUSED {
            return gethtbyname2(st, name, af);
        }
        return core::ptr::null_mut();
    }
    if getanswer(st, rs, &buf, (n as usize).min(4096), name, ty) { st.host_ptr() } else { core::ptr::null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyname(name: *const c_char) -> *mut hostent {
    unsafe { with_input(name.cast::<u8>(), None, res_gethostbyname) }
}

fn res_gethostbyname(st: &mut Compat, name: &[u8]) -> *mut hostent {
    if use_inet6() {
        let hp = res_gethostbyname2_context(st, name, AF_INET6);
        if !hp.is_null() {
            return hp;
        }
    }
    res_gethostbyname2_context(st, name, AF_INET)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyname2(name: *const c_char, _af: c_int) -> *mut hostent {
    unsafe { with_input(name.cast::<u8>(), None, |st, name| res_gethostbyname2_context(st, name, AF_INET)) }
}

fn gethostbyaddr(st: &mut Compat, addr: &[u8], af: c_int) -> *mut hostent {
    let len = addr.len();
    let mut q = crate::util::Buf::<80>::new();
    if af == AF_INET {
        for i in (0..4).rev() {
            q.push_u32(addr[i] as u32);
            q.push(b'.');
        }
        q.push_all(b"in-addr.arpa");
    } else {
        for n in (0..16).rev() {
            q.push(b"0123456789abcdef"[(addr[n] & 0xf) as usize]);
            q.push(b'.');
            q.push(b"0123456789abcdef"[(addr[n] >> 4) as usize]);
            q.push(b'.');
        }
        q.push_all(b"ip6.arpa");
    }
    let mut buf = [0u8; 4096];
    let found = with_this_state(|rs| {
        let n = nquery(rs, false, q.as_bytes(), C_IN, T_PTR, Some(&mut buf), 4096);
        if n < 0 {
            return Err(errno::get() == ECONNREFUSED);
        }
        Ok(getanswer(st, rs, &buf, (n as usize).min(4096), q.as_bytes(), T_PTR))
    });
    match found {
        Err(true) => return gethtbyaddr(st, addr, af),
        Err(false) | Ok(false) => return core::ptr::null_mut(),
        Ok(true) => {}
    }
    st.host.h_addrtype = af;
    st.host.h_length = len as c_int;
    st.host_addr[..len].copy_from_slice(addr);
    st.single_addr();
    herr(NETDB_SUCCESS);
    st.host_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyaddr(addr: *const c_void, len: u32, af: c_int) -> *mut hostent {
    let uaddr = addr as *const u8;
    let mut af = af;
    let mut len = len;
    let mut a = [0u8; 16];
    const MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    const TUNNELLED: [u8; 12] = [0; 12];
    let n = if (af == AF_INET && len == 4) || (af == AF_INET6 && len == 16) { len as usize } else { 0 };
    a[..n].copy_from_slice(unsafe { ffi::bytes(uaddr, n) });
    if af == AF_INET6 && len == 16 && (a[..12] == MAPPED || a[..12] == TUNNELLED) {
        a.copy_within(12..16, 0);
        af = AF_INET;
        len = 4;
    }
    let size = match af {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => {
            errno::set(EAFNOSUPPORT);
            herr(NETDB_INTERNAL);
            return core::ptr::null_mut();
        }
    };
    if size != len {
        errno::set(EINVAL);
        herr(NETDB_INTERNAL);
        return core::ptr::null_mut();
    }
    unsafe { with_state(|st| gethostbyaddr(st, &a[..len as usize], af)) }
}

fn hostf_open(st: &mut Compat) -> bool {
    let Ok(fd) = (unsafe { rusty_libc_core::unistd::open(c"/etc/hosts".as_ptr(), 0o2000000, 0) }) else { return false };
    HOSTF.store(fd, Ordering::Relaxed);
    st.file_pos = 0;
    st.file_len = 0;
    true
}

fn sethtent(st: &mut Compat, f: c_int) {
    let fd = HOSTF.load(Ordering::Relaxed);
    if fd < 0 {
        hostf_open(st);
    } else {
        let _ = rusty_libc_core::unistd::lseek(fd, 0, 0);
        st.file_pos = 0;
        st.file_len = 0;
    }
    st.stayopen = f;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_sethtent(f: c_int) {
    unsafe { with_state(|st| sethtent(st, f)) }
}

fn endhtent(st: &mut Compat) {
    let fd = HOSTF.load(Ordering::Relaxed);
    if fd >= 0 && st.stayopen == 0 {
        let _ = rusty_libc_core::unistd::close(fd);
        HOSTF.store(-1, Ordering::Relaxed);
    }
}

fn fgets_hosts(st: &mut Compat) -> Option<usize> {
    let fd = HOSTF.load(Ordering::Relaxed);
    let mut n = 0usize;
    loop {
        if st.file_pos >= st.file_len {
            match rusty_libc_core::unistd::read_nocancel(fd, &mut st.file_buf) {
                Ok(0) | Err(_) => break,
                Ok(r) => {
                    st.file_pos = 0;
                    st.file_len = r;
                }
            }
        }
        let c = st.file_buf[st.file_pos];
        st.file_pos += 1;
        st.hostbuf[n] = c;
        n += 1;
        if c == b'\n' || n == HOSTBUF - 1 {
            break;
        }
    }
    if n == 0 {
        return None;
    }
    st.hostbuf[n] = 0;
    Some(n)
}

fn strpbrk(b: &[u8], from: usize, set: &[u8]) -> Option<usize> {
    text(&b[from..]).iter().position(|c| set.contains(c)).map(|i| from + i)
}

fn gethtent(st: &mut Compat) -> bool {
    if HOSTF.load(Ordering::Relaxed) < 0 && !hostf_open(st) {
        herr(NETDB_INTERNAL);
        return false;
    }
    loop {
        if fgets_hosts(st).is_none() {
            herr(HOST_NOT_FOUND);
            return false;
        }
        if st.hostbuf[0] == b'#' {
            continue;
        }
        let Some(i) = strpbrk(&st.hostbuf, 0, b"#\n") else { continue };
        st.hostbuf[i] = 0;
        let Some(i) = strpbrk(&st.hostbuf, 0, b" \t") else { continue };
        st.hostbuf[i] = 0;
        let mut cp = i + 1;
        let (af, len);
        if pton_into(AF_INET6, text(&st.hostbuf), &mut st.host_addr) > 0 {
            af = AF_INET6;
            len = 16;
        } else if pton_into(AF_INET, text(&st.hostbuf), &mut st.host_addr) > 0 {
            af = AF_INET;
            len = 4;
        } else {
            continue;
        }
        st.single_addr();
        st.host.h_length = len;
        st.host.h_addrtype = af;
        while st.hostbuf[cp] == b' ' || st.hostbuf[cp] == b'\t' {
            cp += 1;
        }
        st.host.h_name = st.buf_ptr(cp);
        st.ent_name = cp;
        let mut q = 0usize;
        st.host.h_aliases = st.aliases.as_mut_ptr();
        let mut cur: Option<usize> = match strpbrk(&st.hostbuf, cp, b" \t") {
            Some(i) => {
                st.hostbuf[i] = 0;
                Some(i + 1)
            }
            None => None,
        };
        while let Some(c) = cur {
            if st.hostbuf[c] == 0 {
                break;
            }
            if st.hostbuf[c] == b' ' || st.hostbuf[c] == b'\t' {
                cur = Some(c + 1);
                continue;
            }
            if q < MAXALIASES - 1 {
                st.aliases[q] = st.buf_ptr(c);
                st.ent_aliases[q] = c;
                q += 1;
            }
            cur = match strpbrk(&st.hostbuf, c, b" \t") {
                Some(i) => {
                    st.hostbuf[i] = 0;
                    Some(i + 1)
                }
                None => None,
            };
        }
        st.aliases[q] = core::ptr::null_mut();
        st.ent_naliases = q;
        herr(NETDB_SUCCESS);
        return true;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtent() -> *mut hostent {
    unsafe { with_state(|st| if gethtent(st) { st.host_ptr() } else { core::ptr::null_mut() }) }
}

fn gethtbyname2(st: &mut Compat, name: &[u8], af: c_int) -> *mut hostent {
    sethtent(st, 0);
    let found = 'outer: loop {
        if !gethtent(st) {
            break false;
        }
        if st.host.h_addrtype != af {
            continue;
        }
        if text(&st.hostbuf[st.ent_name..]).eq_ignore_ascii_case(name) {
            break true;
        }
        for &o in &st.ent_aliases[..st.ent_naliases] {
            if text(&st.hostbuf[o..]).eq_ignore_ascii_case(name) {
                break 'outer true;
            }
        }
    };
    endhtent(st);
    if found { st.host_ptr() } else { core::ptr::null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyname2(name: *const c_char, af: c_int) -> *mut hostent {
    unsafe { with_input(name.cast::<u8>(), None, |st, name| gethtbyname2(st, name, af)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyname(name: *const c_char) -> *mut hostent {
    unsafe { with_input(name.cast::<u8>(), None, gethtbyname) }
}

fn gethtbyname(st: &mut Compat, name: &[u8]) -> *mut hostent {
    if use_inet6() {
        let hp = gethtbyname2(st, name, AF_INET6);
        if !hp.is_null() {
            return hp;
        }
    }
    gethtbyname2(st, name, AF_INET)
}

fn gethtbyaddr(st: &mut Compat, addr: &[u8], af: c_int) -> *mut hostent {
    sethtent(st, 0);
    let found = loop {
        if !gethtent(st) {
            break false;
        }
        if st.host.h_addrtype == af && st.host_addr.get(..addr.len()) == Some(addr) {
            break true;
        }
    };
    endhtent(st);
    if found { st.host_ptr() } else { core::ptr::null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyaddr(addr: *const c_char, len: usize, af: c_int) -> *mut hostent {
    unsafe { with_input(addr.cast::<u8>(), Some(len), |st, addr| gethtbyaddr(st, addr, af)) }
}

