use crate::resolv::{__res_state, ResState, res_dnok, res_hnok, res_nquery, res_nsearch};
use crate::strerr::set_h_errno;
use crate::types::{EAFNOSUPPORT, EINVAL, HOST_NOT_FOUND, NETDB_INTERNAL, NETDB_SUCCESS, NO_RECOVERY, hostent};
use crate::util::{cbytes, cstrlen};
use core::ffi::{c_char, c_int, c_uchar, c_void};
use rusty_libc_core::errno;

const MAXALIASES: usize = 35;
const MAXADDRS: usize = 35;
const MAXHOSTNAMELEN: usize = 256;
const MAXDNAME: usize = 1025;
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

static mut H_ADDR_PTRS: [*mut c_char; MAXADDRS + 1] = [core::ptr::null_mut(); MAXADDRS + 1];
static mut HOST: hostent = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
static mut HOST_ALIASES: [*mut c_char; MAXALIASES] = [core::ptr::null_mut(); MAXALIASES];
static mut HOSTBUF: [u8; 8 * 1024] = [0; 8 * 1024];
static mut HOST_ADDR: [u8; 16] = [0; 16];
static mut HOSTF: c_int = -1;
static mut HOSTF_BUF: [u8; 4096] = [0; 4096];
static mut HOSTF_POS: usize = 0;
static mut HOSTF_LEN: usize = 0;
static mut STAYOPEN: c_int = 0;

fn use_inet6() -> bool {
    false
}

unsafe fn hostbuf_ptr() -> *mut u8 {
    (&raw mut HOSTBUF) as *mut u8
}

fn herr(v: c_int) {
    set_h_errno(v);
}

unsafe fn map_v4v6_address(src: *const u8, dst: *mut u8) {
    unsafe {
        let mut tmp = [0u8; 4];
        core::ptr::copy_nonoverlapping(src, tmp.as_mut_ptr(), 4);
        for i in 0..10 {
            *dst.add(i) = 0;
        }
        *dst.add(10) = 0xff;
        *dst.add(11) = 0xff;
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), dst.add(12), 4);
    }
}

unsafe fn map_v4v6_hostent(hp: *mut hostent, bpp: &mut *mut u8, lenp: &mut isize) {
    unsafe {
        if (*hp).h_addrtype != AF_INET || (*hp).h_length != 4 {
            return;
        }
        (*hp).h_addrtype = AF_INET6;
        (*hp).h_length = 16;
        let mut ap = (*hp).h_addr_list;
        while !(*ap).is_null() {
            let i = 4 - (*bpp as usize % 4);
            if *lenp < (i + 16) as isize {
                *ap = core::ptr::null_mut();
                return;
            }
            *bpp = bpp.add(i);
            *lenp -= i as isize;
            map_v4v6_address(*ap as *const u8, *bpp);
            *ap = *bpp as *mut c_char;
            *bpp = bpp.add(16);
            *lenp -= 16;
            ap = ap.add(1);
        }
    }
}

unsafe fn addrsort(ap: *mut *mut c_char, num: usize, st: &ResState) {
    unsafe {
        let nsort = (st.bits >> 4) & 0xf;
        let mut aval = [0i16; MAXADDRS];
        let mut needsort = 0usize;
        for i in 0..num {
            let a = *(*ap.add(i) as *const u32);
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
                    core::ptr::swap(ap.add(ju), ap.add(ju + 1));
                } else {
                    break;
                }
                j -= 1;
            }
            needsort += 1;
        }
    }
}

fn be16(p: *const u8) -> c_int {
    unsafe { u16::from_be_bytes([*p, *p.add(1)]) as c_int }
}

unsafe fn strcasecmp_c(a: *const c_char, b: *const c_char) -> bool {
    unsafe { cbytes(a).eq_ignore_ascii_case(cbytes(b)) }
}

unsafe fn getanswer(answer: *const u8, anslen: c_int, qname: *const c_char, qtype: c_int) -> *mut hostent {
    unsafe {
        let host = &raw mut HOST;
        let mut qname = qname;
        let mut tname = qname;
        (*host).h_name = core::ptr::null_mut();
        let eom = answer.add(anslen as usize);
        let name_ok: unsafe extern "C" fn(*const c_char) -> c_int = match qtype {
            T_A | T_AAAA => res_hnok,
            T_PTR => res_dnok,
            _ => return core::ptr::null_mut(),
        };
        let ancount_hdr = be16(answer.add(6));
        let qdcount = be16(answer.add(4));
        let hostbuf = hostbuf_ptr();
        let mut bp = hostbuf;
        let mut buflen: c_int = 8192;
        let mut cp = answer;
        macro_rules! bounded_incr {
            ($x:expr) => {
                cp = cp.add($x as usize);
                if cp > eom {
                    herr(NO_RECOVERY);
                    return core::ptr::null_mut();
                }
            };
        }
        macro_rules! bounds_check {
            ($ptr:expr, $count:expr) => {
                if $ptr.add($count as usize) > eom {
                    herr(NO_RECOVERY);
                    return core::ptr::null_mut();
                }
            };
        }
        bounded_incr!(HFIXEDSZ);
        if qdcount != 1 {
            herr(NO_RECOVERY);
            return core::ptr::null_mut();
        }
        let mut n = crate::resolv::dn_expand(answer, eom, cp, bp as *mut c_char, buflen);
        if n < 0 || name_ok(bp as *const c_char) == 0 {
            herr(NO_RECOVERY);
            return core::ptr::null_mut();
        }
        bounded_incr!(n as usize + QFIXEDSZ);
        if qtype == T_A || qtype == T_AAAA {
            n = cstrlen(bp as *const c_char) as c_int + 1;
            if n as usize >= MAXHOSTNAMELEN {
                herr(NO_RECOVERY);
                return core::ptr::null_mut();
            }
            (*host).h_name = bp as *mut c_char;
            bp = bp.add(n as usize);
            buflen -= n;
            qname = (*host).h_name;
        }
        let aliases = (&raw mut HOST_ALIASES) as *mut *mut c_char;
        let mut ap = aliases;
        *ap = core::ptr::null_mut();
        (*host).h_aliases = aliases;
        let addr_ptrs = (&raw mut H_ADDR_PTRS) as *mut *mut c_char;
        let mut hap = addr_ptrs;
        *hap = core::ptr::null_mut();
        (*host).h_addr_list = addr_ptrs;
        let mut haveanswer = 0;
        let mut had_error = 0;
        let mut ancount = ancount_hdr;
        let mut tbuf = [0 as c_char; MAXDNAME];
        while ancount > 0 && cp < eom && had_error == 0 {
            ancount -= 1;
            n = crate::resolv::dn_expand(answer, eom, cp, bp as *mut c_char, buflen);
            if n < 0 || name_ok(bp as *const c_char) == 0 {
                had_error += 1;
                continue;
            }
            cp = cp.add(n as usize);
            bounds_check!(cp, 3 * 2 + 4);
            let ty = be16(cp);
            cp = cp.add(2);
            let class = be16(cp);
            cp = cp.add(2 + 4);
            n = be16(cp);
            cp = cp.add(2);
            bounds_check!(cp, n);
            let erdata = cp.add(n as usize);
            if class != C_IN {
                cp = cp.add(n as usize);
                continue;
            }
            if (qtype == T_A || qtype == T_AAAA) && ty == T_CNAME {
                if ap >= aliases.add(MAXALIASES - 1) {
                    continue;
                }
                n = crate::resolv::dn_expand(answer, eom, cp, tbuf.as_mut_ptr(), MAXDNAME as c_int);
                if n < 0 || name_ok(tbuf.as_ptr()) == 0 {
                    had_error += 1;
                    continue;
                }
                cp = cp.add(n as usize);
                if cp != erdata {
                    herr(NO_RECOVERY);
                    return core::ptr::null_mut();
                }
                *ap = bp as *mut c_char;
                ap = ap.add(1);
                n = cstrlen(bp as *const c_char) as c_int + 1;
                if n as usize >= MAXHOSTNAMELEN {
                    had_error += 1;
                    continue;
                }
                bp = bp.add(n as usize);
                buflen -= n;
                n = cstrlen(tbuf.as_ptr()) as c_int + 1;
                if n > buflen || n as usize >= MAXHOSTNAMELEN {
                    had_error += 1;
                    continue;
                }
                core::ptr::copy_nonoverlapping(tbuf.as_ptr() as *const u8, bp, n as usize);
                (*host).h_name = bp as *mut c_char;
                bp = bp.add(n as usize);
                buflen -= n;
                continue;
            }
            if qtype == T_PTR && ty == T_CNAME {
                n = crate::resolv::dn_expand(answer, eom, cp, tbuf.as_mut_ptr(), MAXDNAME as c_int);
                if n < 0 || res_dnok(tbuf.as_ptr()) == 0 {
                    had_error += 1;
                    continue;
                }
                cp = cp.add(n as usize);
                if cp != erdata {
                    herr(NO_RECOVERY);
                    return core::ptr::null_mut();
                }
                n = cstrlen(tbuf.as_ptr()) as c_int + 1;
                if n > buflen || n as usize >= MAXHOSTNAMELEN {
                    had_error += 1;
                    continue;
                }
                core::ptr::copy_nonoverlapping(tbuf.as_ptr() as *const u8, bp, n as usize);
                tname = bp as *const c_char;
                bp = bp.add(n as usize);
                buflen -= n;
                continue;
            }
            if ty != qtype {
                cp = cp.add(n as usize);
                continue;
            }
            match ty {
                T_PTR => {
                    if !strcasecmp_c(tname, bp as *const c_char) {
                        cp = cp.add(n as usize);
                        continue;
                    }
                    n = crate::resolv::dn_expand(answer, eom, cp, bp as *mut c_char, buflen);
                    if n < 0 || res_hnok(bp as *const c_char) == 0 {
                        had_error += 1;
                    } else {
                        cp = cp.add(n as usize);
                        if cp != erdata {
                            herr(NO_RECOVERY);
                            return core::ptr::null_mut();
                        }
                        if haveanswer == 0 {
                            (*host).h_name = bp as *mut c_char;
                        } else if ap < aliases.add(MAXALIASES - 1) {
                            *ap = bp as *mut c_char;
                            ap = ap.add(1);
                        } else {
                            n = -1;
                        }
                        if n != -1 {
                            n = cstrlen(bp as *const c_char) as c_int + 1;
                            if n as usize >= MAXHOSTNAMELEN {
                                had_error += 1;
                            } else {
                                bp = bp.add(n as usize);
                                buflen -= n;
                            }
                        }
                    }
                }
                T_A | T_AAAA => {
                    if !strcasecmp_c((*host).h_name, bp as *const c_char) {
                        cp = cp.add(n as usize);
                        continue;
                    }
                    if n != (*host).h_length {
                        cp = cp.add(n as usize);
                        continue;
                    }
                    if haveanswer == 0 {
                        (*host).h_name = bp as *mut c_char;
                        let nn = cstrlen(bp as *const c_char) as c_int + 1;
                        bp = bp.add(nn as usize);
                        buflen -= nn;
                    }
                    let pad = 4 - (bp as usize % 4);
                    buflen -= pad as c_int;
                    bp = bp.add(pad);
                    if bp.add(n as usize) >= hostbuf.add(8192) {
                        had_error += 1;
                        continue;
                    }
                    if hap >= addr_ptrs.add(MAXADDRS - 1) {
                        cp = cp.add(n as usize);
                        continue;
                    }
                    *hap = bp as *mut c_char;
                    hap = hap.add(1);
                    core::ptr::copy(cp, bp, n as usize);
                    bp = bp.add(n as usize);
                    buflen -= n;
                    cp = cp.add(n as usize);
                    if cp != erdata {
                        herr(NO_RECOVERY);
                        return core::ptr::null_mut();
                    }
                }
                _ => {
                    return core::ptr::null_mut();
                }
            }
            if had_error == 0 {
                haveanswer += 1;
            }
        }
        if haveanswer != 0 {
            *ap = core::ptr::null_mut();
            *hap = core::ptr::null_mut();
            let st = &*__res_state();
            if (st.bits >> 4) & 0xf != 0 && haveanswer > 1 && qtype == T_A {
                addrsort(addr_ptrs, haveanswer as usize, st);
            }
            if (*host).h_name.is_null() {
                n = cstrlen(qname) as c_int + 1;
                if n > buflen || n as usize >= MAXHOSTNAMELEN {
                    herr(NO_RECOVERY);
                    return core::ptr::null_mut();
                }
                core::ptr::copy_nonoverlapping(qname as *const u8, bp, n as usize);
                (*host).h_name = bp as *mut c_char;
                bp = bp.add(n as usize);
                buflen -= n;
            }
            if use_inet6() {
                let mut l = buflen as isize;
                map_v4v6_hostent(host, &mut bp, &mut l);
            }
            herr(NETDB_SUCCESS);
            return host;
        }
        herr(NO_RECOVERY);
        core::ptr::null_mut()
    }
}

unsafe fn fill_literal(name: *const c_char, af: c_int, bp_len: &mut (*mut u8, isize)) -> Option<*mut hostent> {
    unsafe {
        let host = &raw mut HOST;
        let aliases = (&raw mut HOST_ALIASES) as *mut *mut c_char;
        let addr_ptrs = (&raw mut H_ADDR_PTRS) as *mut *mut c_char;
        let hostbuf = hostbuf_ptr();
        let n = cstrlen(name).min(MAXDNAME);
        core::ptr::copy_nonoverlapping(name as *const u8, hostbuf, n);
        for i in n..MAXDNAME {
            *hostbuf.add(i) = 0;
        }
        *hostbuf.add(MAXDNAME) = 0;
        *bp_len = (hostbuf.add(MAXDNAME), 8192 - MAXDNAME as isize);
        (*host).h_name = hostbuf as *mut c_char;
        (*host).h_aliases = aliases;
        *aliases = core::ptr::null_mut();
        *addr_ptrs = (&raw mut HOST_ADDR) as *mut c_char;
        *addr_ptrs.add(1) = core::ptr::null_mut();
        (*host).h_addr_list = addr_ptrs;
        let _ = af;
        Some(host)
    }
}

unsafe fn res_gethostbyname2_context(name: *const c_char, af: c_int) -> *mut hostent {
    unsafe {
        let host = &raw mut HOST;
        let (size, ty) = match af {
            AF_INET => (4, T_A),
            AF_INET6 => (16, T_AAAA),
            _ => {
                herr(NETDB_INTERNAL);
                errno::set(EAFNOSUPPORT);
                return core::ptr::null_mut();
            }
        };
        (*host).h_addrtype = af;
        (*host).h_length = size;
        let st = __res_state();
        let mut name = name;
        let mut abuf = [0 as c_char; MAXDNAME];
        let nb = cbytes(name);
        if nb.contains(&b'.') {
            if let Some(a) = crate::resdebug::host_alias((*st).options, nb) {
                core::ptr::copy_nonoverlapping(a.b.as_ptr(), abuf.as_mut_ptr() as *mut u8, a.len);
                abuf[a.len] = 0;
                name = abuf.as_ptr();
            }
        }
        let nb = cbytes(name);
        let ainet6 = |name: *const c_char| -> c_int { crate::inet::inet_pton(af, name, (&raw mut HOST_ADDR) as *mut c_void) };
        if !nb.is_empty() && nb[0].is_ascii_digit() {
            let mut i = 0;
            loop {
                if i == nb.len() {
                    if nb[i - 1] == b'.' {
                        break;
                    }
                    if ainet6(name) <= 0 {
                        herr(HOST_NOT_FOUND);
                        return core::ptr::null_mut();
                    }
                    let mut bl = (core::ptr::null_mut(), 0);
                    fill_literal(name, af, &mut bl);
                    if use_inet6() {
                        let (mut bp, mut len) = bl;
                        map_v4v6_hostent(host, &mut bp, &mut len);
                    }
                    herr(NETDB_SUCCESS);
                    return host;
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
                    if ainet6(name) <= 0 {
                        herr(HOST_NOT_FOUND);
                        return core::ptr::null_mut();
                    }
                    let mut bl = (core::ptr::null_mut(), 0);
                    fill_literal(name, af, &mut bl);
                    herr(NETDB_SUCCESS);
                    return host;
                }
                if !nb[i].is_ascii_hexdigit() && nb[i] != b':' && nb[i] != b'.' {
                    break;
                }
                i += 1;
            }
        }
        let mut buf = [0u8; 4096];
        let n = res_nsearch(st, name, C_IN, ty, buf.as_mut_ptr(), 4096);
        if n < 0 {
            if errno::get() == ECONNREFUSED {
                return _gethtbyname2(name, af);
            }
            return core::ptr::null_mut();
        }
        getanswer(buf.as_ptr(), n, name, ty)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyname(name: *const c_char) -> *mut hostent {
    unsafe {
        if use_inet6() {
            let hp = res_gethostbyname2_context(name, AF_INET6);
            if !hp.is_null() {
                return hp;
            }
        }
        res_gethostbyname2_context(name, AF_INET)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyname2(name: *const c_char, _af: c_int) -> *mut hostent {
    unsafe { res_gethostbyname2_context(name, AF_INET) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_gethostbyaddr(addr: *const c_void, len: u32, af: c_int) -> *mut hostent {
    unsafe {
        let mut uaddr = addr as *const u8;
        let mut af = af;
        let mut len = len;
        const MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        const TUNNELLED: [u8; 12] = [0; 12];
        if af == AF_INET6 && len == 16 {
            let head = core::slice::from_raw_parts(uaddr, 12);
            if head == MAPPED || head == TUNNELLED {
                uaddr = uaddr.add(12);
                af = AF_INET;
                len = 4;
            }
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
        let mut qbuf = [0u8; MAXDNAME + 1];
        let mut q = crate::util::Buf::<80>::new();
        if af == AF_INET {
            for i in (0..4).rev() {
                q.push_u32(*uaddr.add(i) as u32);
                q.push(b'.');
            }
            q.push_all(b"in-addr.arpa");
        } else {
            for n in (0..16).rev() {
                q.push(b"0123456789abcdef"[(*uaddr.add(n) & 0xf) as usize]);
                q.push(b'.');
                q.push(b"0123456789abcdef"[(*uaddr.add(n) >> 4) as usize]);
                q.push(b'.');
            }
            q.push_all(b"ip6.arpa");
        }
        qbuf[..q.len].copy_from_slice(q.as_bytes());
        let st = __res_state();
        let mut buf = [0u8; 4096];
        let n = res_nquery(st, qbuf.as_ptr() as *const c_char, C_IN, T_PTR, buf.as_mut_ptr(), 4096);
        if n < 0 {
            if errno::get() == ECONNREFUSED {
                return _gethtbyaddr(uaddr as *const c_char, len as usize, af);
            }
            return core::ptr::null_mut();
        }
        let hp = getanswer(buf.as_ptr(), n, qbuf.as_ptr() as *const c_char, T_PTR);
        if hp.is_null() {
            return core::ptr::null_mut();
        }
        (*hp).h_addrtype = af;
        (*hp).h_length = len as c_int;
        let host_addr = (&raw mut HOST_ADDR) as *mut u8;
        core::ptr::copy(uaddr, host_addr, len as usize);
        let addr_ptrs = (&raw mut H_ADDR_PTRS) as *mut *mut c_char;
        *addr_ptrs = host_addr as *mut c_char;
        *addr_ptrs.add(1) = core::ptr::null_mut();
        if af == AF_INET && use_inet6() {
            map_v4v6_address(host_addr, host_addr);
            (*hp).h_addrtype = AF_INET6;
            (*hp).h_length = 16;
        }
        herr(NETDB_SUCCESS);
        hp
    }
}

unsafe fn hostf_open() -> bool {
    unsafe {
        let fd = rusty_libc_core::syscall::syscall4(257, (-100isize) as usize, c"/etc/hosts".as_ptr() as usize, 0o2000000, 0) as isize;
        if fd < 0 {
            return false;
        }
        HOSTF = fd as c_int;
        HOSTF_POS = 0;
        HOSTF_LEN = 0;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_sethtent(f: c_int) {
    unsafe {
        if HOSTF < 0 {
            hostf_open();
        } else {
            rusty_libc_core::syscall::syscall3(8, HOSTF as usize, 0, 0);
            HOSTF_POS = 0;
            HOSTF_LEN = 0;
        }
        STAYOPEN = f;
    }
}

unsafe fn endhtent() {
    unsafe {
        if HOSTF >= 0 && STAYOPEN == 0 {
            rusty_libc_core::syscall::syscall1(3, HOSTF as usize);
            HOSTF = -1;
        }
    }
}

unsafe fn fgets_hosts() -> Option<usize> {
    unsafe {
        let out = hostbuf_ptr();
        let mut n = 0usize;
        loop {
            if HOSTF_POS >= HOSTF_LEN {
                let r = rusty_libc_core::syscall::syscall3(0, HOSTF as usize, (&raw mut HOSTF_BUF) as *mut u8 as usize, 4096) as isize;
                if r <= 0 {
                    break;
                }
                HOSTF_POS = 0;
                HOSTF_LEN = r as usize;
            }
            let c = (*(&raw const HOSTF_BUF))[HOSTF_POS];
            HOSTF_POS += 1;
            *out.add(n) = c;
            n += 1;
            if c == b'\n' || n == 8191 {
                break;
            }
        }
        if n == 0 {
            return None;
        }
        *out.add(n) = 0;
        Some(n)
    }
}

unsafe fn strpbrk_idx(p: *const u8, set: &[u8]) -> Option<usize> {
    unsafe {
        let mut i = 0;
        while *p.add(i) != 0 {
            if set.contains(&*p.add(i)) {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtent() -> *mut hostent {
    unsafe {
        if HOSTF < 0 && !hostf_open() {
            herr(NETDB_INTERNAL);
            return core::ptr::null_mut();
        }
        let host = &raw mut HOST;
        let aliases = (&raw mut HOST_ALIASES) as *mut *mut c_char;
        let addr_ptrs = (&raw mut H_ADDR_PTRS) as *mut *mut c_char;
        let host_addr = (&raw mut HOST_ADDR) as *mut u8;
        loop {
            if fgets_hosts().is_none() {
                herr(HOST_NOT_FOUND);
                return core::ptr::null_mut();
            }
            let p = hostbuf_ptr();
            if *p == b'#' {
                continue;
            }
            let Some(i) = strpbrk_idx(p, b"#\n") else { continue };
            *p.add(i) = 0;
            let Some(i) = strpbrk_idx(p, b" \t") else { continue };
            *p.add(i) = 0;
            let mut cp = p.add(i + 1);
            let (af, len);
            if crate::inet::inet_pton(AF_INET6, p as *const c_char, host_addr as *mut c_void) > 0 {
                af = AF_INET6;
                len = 16;
            } else if crate::inet::inet_pton(AF_INET, p as *const c_char, host_addr as *mut c_void) > 0 {
                if use_inet6() {
                    map_v4v6_address(host_addr, host_addr);
                    af = AF_INET6;
                    len = 16;
                } else {
                    af = AF_INET;
                    len = 4;
                }
            } else {
                continue;
            }
            *addr_ptrs = host_addr as *mut c_char;
            *addr_ptrs.add(1) = core::ptr::null_mut();
            (*host).h_addr_list = addr_ptrs;
            (*host).h_length = len;
            (*host).h_addrtype = af;
            while *cp == b' ' || *cp == b'\t' {
                cp = cp.add(1);
            }
            (*host).h_name = cp as *mut c_char;
            let mut q = aliases;
            (*host).h_aliases = aliases;
            let mut cur: *mut u8 = cp;
            match strpbrk_idx(cur, b" \t") {
                Some(i) => {
                    *cur.add(i) = 0;
                    cur = cur.add(i + 1);
                }
                None => cur = core::ptr::null_mut(),
            }
            while !cur.is_null() && *cur != 0 {
                if *cur == b' ' || *cur == b'\t' {
                    cur = cur.add(1);
                    continue;
                }
                if q < aliases.add(MAXALIASES - 1) {
                    *q = cur as *mut c_char;
                    q = q.add(1);
                }
                match strpbrk_idx(cur, b" \t") {
                    Some(i) => {
                        *cur.add(i) = 0;
                        cur = cur.add(i + 1);
                    }
                    None => cur = core::ptr::null_mut(),
                }
            }
            *q = core::ptr::null_mut();
            herr(NETDB_SUCCESS);
            return host;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyname2(name: *const c_char, af: c_int) -> *mut hostent {
    unsafe {
        __rl_sethtent(0);
        let mut p;
        'outer: loop {
            p = __rl_gethtent();
            if p.is_null() {
                break;
            }
            if (*p).h_addrtype != af {
                continue;
            }
            if strcasecmp_c((*p).h_name, name) {
                break;
            }
            let mut cp = (*p).h_aliases;
            while !(*cp).is_null() {
                if strcasecmp_c(*cp, name) {
                    break 'outer;
                }
                cp = cp.add(1);
            }
        }
        endhtent();
        p
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyname(name: *const c_char) -> *mut hostent {
    unsafe {
        if use_inet6() {
            let hp = __rl_gethtbyname2(name, AF_INET6);
            if !hp.is_null() {
                return hp;
            }
        }
        __rl_gethtbyname2(name, AF_INET)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_gethtbyaddr(addr: *const c_char, len: usize, af: c_int) -> *mut hostent {
    unsafe {
        __rl_sethtent(0);
        let mut p;
        loop {
            p = __rl_gethtent();
            if p.is_null() {
                break;
            }
            if (*p).h_addrtype == af && core::slice::from_raw_parts(*(*p).h_addr_list as *const u8, len) == core::slice::from_raw_parts(addr as *const u8, len) {
                break;
            }
        }
        endhtent();
        p
    }
}

unsafe fn _gethtbyname2(name: *const c_char, af: c_int) -> *mut hostent {
    unsafe { __rl_gethtbyname2(name, af) }
}

unsafe fn _gethtbyaddr(addr: *const c_char, len: usize, af: c_int) -> *mut hostent {
    unsafe { __rl_gethtbyaddr(addr, len, af) }
}

#[allow(dead_code)]
fn _unused(_: c_uchar) {}
