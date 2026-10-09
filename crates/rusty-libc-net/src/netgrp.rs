use crate::nss;
use crate::util::{eq_nocase, is_space};
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::errno;

const ERANGE: i32 = 34;
const ENOMEM: i32 = 12;
const EAGAIN: i32 = 11;

#[derive(PartialEq, Clone, Copy)]
enum St {
    Success,
    NotFound,
    Unavail,
    TryAgain,
    Return,
}

#[repr(C)]
struct NameList {
    next: *mut NameList,
}

unsafe fn nl_name(n: *const NameList) -> *const u8 {
    unsafe { (n as *const u8).add(size_of::<NameList>()) }
}

unsafe fn nl_new(name: *const u8, len: usize) -> *mut NameList {
    unsafe {
        let p = rusty_libc_malloc::malloc(size_of::<NameList>() + len + 1) as *mut NameList;
        if p.is_null() {
            return null_mut();
        }
        core::ptr::copy_nonoverlapping(name, (p as *mut u8).add(size_of::<NameList>()), len);
        *(p as *mut u8).add(size_of::<NameList>() + len) = 0;
        p
    }
}

unsafe fn nl_contains(mut l: *const NameList, name: &[u8]) -> bool {
    unsafe {
        while !l.is_null() {
            if cbytes_u8(nl_name(l)) == name {
                return true;
            }
            l = (*l).next;
        }
        false
    }
}

unsafe fn nl_free(mut l: *mut NameList) {
    unsafe {
        while !l.is_null() {
            let n = (*l).next;
            rusty_libc_malloc::free(l.cast());
            l = n;
        }
    }
}

unsafe fn cbytes_u8<'a>(p: *const u8) -> &'a [u8] {
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

#[repr(C)]
struct NetGrent {
    typ: c_int,
    host: *const c_char,
    user: *const c_char,
    domain: *const c_char,
    data: *mut u8,
    data_size: usize,
    cursor: *mut u8,
    first: c_int,
    known: *mut NameList,
    needed: *mut NameList,
    nip: usize,
}

impl NetGrent {
    const fn new() -> NetGrent {
        NetGrent { typ: 0, host: core::ptr::null(), user: core::ptr::null(), domain: core::ptr::null(), data: null_mut(), data_size: 0, cursor: null_mut(), first: 0, known: null_mut(), needed: null_mut(), nip: 0 }
    }
}

use rusty_libc_core::nssent::{self, EntOps, Fn3};
use rusty_libc_core::nssmod;

fn ng_order() -> nssmod::Order {
    nssmod::order(b"netgroup")
}

struct NgOps;

fn ng_fn_name(f: Fn3) -> &'static [u8] {
    match f {
        Fn3::Set => b"setnetgrent",
        Fn3::Get => b"getnetgrent_r",
        Fn3::End => b"endnetgrent",
    }
}

fn ng_module_fn(src: &nssmod::Source, f: Fn3) -> usize {
    if src.is(b"dns") {
        return 0;
    }
    nssmod::function(src.name(), ng_fn_name(f))
}

impl EntOps for NgOps {
    fn has(&mut self, src: &nssmod::Source, f: Fn3) -> bool {
        nssent::is_files(src) || ng_module_fn(src, f) != 0
    }
    fn call_set(&mut self, _src: &nssmod::Source, _stay: i32) -> i32 {
        0
    }
    fn call_get(&mut self, _src: &nssmod::Source) -> i32 {
        0
    }
    fn call_end(&mut self, _src: &nssmod::Source) {}
}

fn st_of(status: i32) -> St {
    match status {
        -2 => St::TryAgain,
        -1 => St::Unavail,
        0 => St::NotFound,
        1 => St::Success,
        _ => St::Return,
    }
}

unsafe fn src_set(src: &nssmod::Source, group: &[u8], group_c: *const u8, d: &mut NetGrent) -> St {
    unsafe {
        if nssent::is_files(src) {
            return files_set(group, d);
        }
        let f = ng_module_fn(src, Fn3::Set);
        if f == 0 {
            return St::Unavail;
        }
        let f: unsafe extern "C" fn(*const u8, *mut NetGrent) -> c_int = core::mem::transmute(f);
        st_of(f(group_c, d))
    }
}

unsafe fn src_get(src: &nssmod::Source, d: &mut NetGrent, buffer: *mut u8, buflen: usize) -> St {
    unsafe {
        if nssent::is_files(src) {
            return parseline(d, buffer, buflen);
        }
        let f = ng_module_fn(src, Fn3::Get);
        if f == 0 {
            return St::Unavail;
        }
        let f: unsafe extern "C" fn(*mut NetGrent, *mut u8, usize, *mut c_int) -> c_int = core::mem::transmute(f);
        st_of(f(d, buffer, buflen, errno::location()))
    }
}

unsafe fn src_end(src: &nssmod::Source, d: &mut NetGrent) {
    unsafe {
        if nssent::is_files(src) {
            files_end(d);
            return;
        }
        let f = ng_module_fn(src, Fn3::End);
        if f != 0 {
            let f: unsafe extern "C" fn(*mut NetGrent) -> c_int = core::mem::transmute(f);
            f(d);
        }
    }
}

fn ng_lookup(ord: &nssmod::Order, nip: &mut usize, f: Fn3) -> i32 {
    nssent::lookup(ord, nip, f, &mut NgOps)
}

fn ng_next2(ord: &nssmod::Order, nip: &mut usize, f: Fn3, status: St) -> i32 {
    let s = match status {
        St::TryAgain => -2,
        St::Unavail => -1,
        St::NotFound => 0,
        St::Success => 1,
        St::Return => 2,
    };
    nssent::next2(ord, nip, f, s, false, &mut NgOps)
}

fn read_file(path: &crate::util::Buf<320>) -> Result<(*mut u8, usize), i32> {
    unsafe {
        let fd = match rusty_libc_core::unistd::open(path.b.as_ptr() as *const c_char, 0o2000000, 0) {
            Ok(fd) => fd,
            Err(e) => return Err(e.0),
        };
        let mut cap = 4096usize;
        let mut buf = rusty_libc_malloc::malloc(cap) as *mut u8;
        let mut len = 0usize;
        if buf.is_null() {
            let _ = rusty_libc_core::unistd::close(fd);
            return Err(ENOMEM);
        }
        loop {
            if len == cap {
                cap *= 2;
                let nb = rusty_libc_malloc::realloc(buf.cast(), cap) as *mut u8;
                if nb.is_null() {
                    rusty_libc_malloc::free(buf.cast());
                    let _ = rusty_libc_core::unistd::close(fd);
                    return Err(ENOMEM);
                }
                buf = nb;
            }
            match rusty_libc_core::unistd::read(fd, core::slice::from_raw_parts_mut(buf.add(len), cap - len)) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.0 == 4 => {}
                Err(_) => break,
            }
        }
        let _ = rusty_libc_core::unistd::close(fd);
        Ok((buf, len))
    }
}

unsafe fn files_end(d: &mut NetGrent) {
    unsafe {
        rusty_libc_malloc::free(d.data.cast());
        d.data = null_mut();
        d.cursor = null_mut();
    }
}

unsafe fn files_set(group: &[u8], d: &mut NetGrent) -> St {
    unsafe {
        if group.is_empty() {
            return St::Unavail;
        }
        let path = nss::etc_path(b"/netgroup");
        let (file, flen) = match read_file(&path) {
            Ok(x) => x,
            Err(e) => return if e == EAGAIN { St::TryAgain } else { St::Unavail },
        };
        let bytes = core::slice::from_raw_parts(file, flen);
        let mut pos = 0usize;
        let next_line = |pos: &mut usize| -> Option<(usize, usize)> {
            if *pos >= flen {
                return None;
            }
            let s = *pos;
            let mut e = s;
            while e < flen && bytes[e] != b'\n' {
                e += 1;
            }
            let end = if e < flen { e + 1 } else { e };
            *pos = end;
            Some((s, end))
        };
        let mut status = St::NotFound;
        let mut out: Vec8 = Vec8::new();
        while let Some((s, end)) = next_line(&mut pos) {
            let line = &bytes[s..end];
            let found = line.len() > group.len() && line[..group.len()] == *group && is_space(line[group.len()]);
            if found {
                if !out.extend(&line[group.len() + 1..]) {
                    rusty_libc_malloc::free(file.cast());
                    files_end(d);
                    return St::Unavail;
                }
            }
            let mut cur = (s, end);
            while cur.1 - cur.0 > 1 && bytes[cur.1 - 1] == b'\n' && bytes[cur.1 - 2] == b'\\' {
                if found {
                    out.len -= 2;
                }
                match next_line(&mut pos) {
                    Some((s2, e2)) => {
                        cur = (s2, e2);
                        if found {
                            if !out.push(b' ') || !out.extend(&bytes[s2..e2]) {
                                rusty_libc_malloc::free(file.cast());
                                files_end(d);
                                return St::Unavail;
                            }
                        }
                    }
                    None => break,
                }
            }
            if found {
                status = St::Success;
                break;
            }
        }
        rusty_libc_malloc::free(file.cast());
        if status == St::Success {
            if !out.push(0) {
                return St::Unavail;
            }
            d.data = out.p;
            d.cursor = d.data;
            d.first = 1;
        } else {
            out.free();
            files_end(d);
        }
        status
    }
}

struct Vec8 {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl Vec8 {
    const fn new() -> Vec8 {
        Vec8 { p: null_mut(), len: 0, cap: 0 }
    }
    unsafe fn reserve(&mut self, extra: usize) -> bool {
        unsafe {
            if self.len + extra > self.cap {
                let ncap = (self.len + extra).max(self.cap * 2).max(512);
                let np = rusty_libc_malloc::realloc(self.p.cast(), ncap) as *mut u8;
                if np.is_null() {
                    return false;
                }
                self.p = np;
                self.cap = ncap;
            }
            true
        }
    }
    fn push(&mut self, b: u8) -> bool {
        unsafe {
            if !self.reserve(1) {
                return false;
            }
            *self.p.add(self.len) = b;
            self.len += 1;
            true
        }
    }
    fn extend(&mut self, s: &[u8]) -> bool {
        unsafe {
            if !self.reserve(s.len() + 1) {
                return false;
            }
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.p.add(self.len), s.len());
            self.len += s.len();
            true
        }
    }
    fn free(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.cast()) };
        self.p = null_mut();
        self.len = 0;
        self.cap = 0;
    }
}

unsafe fn strip_whitespace(str_: *mut u8) -> *const c_char {
    unsafe {
        let mut cp = str_;
        while is_space(*cp) {
            cp = cp.add(1);
        }
        let s = cp;
        while *cp != 0 && !is_space(*cp) {
            cp = cp.add(1);
        }
        *cp = 0;
        if *s == 0 { core::ptr::null() } else { s as *const c_char }
    }
}

unsafe fn parseline(d: &mut NetGrent, buffer: *mut u8, buflen: usize) -> St {
    unsafe {
        let mut cp = d.cursor;
        if cp.is_null() {
            return St::NotFound;
        }
        while is_space(*cp) {
            cp = cp.add(1);
        }
        let not_found = |first: bool| if first { St::NotFound } else { St::Return };
        if *cp != b'(' {
            let name = cp;
            while *cp != 0 && !is_space(*cp) {
                cp = cp.add(1);
            }
            if name != cp {
                let last = *cp == 0;
                d.typ = 1;
                d.host = name as *const c_char;
                *cp = 0;
                if !last {
                    cp = cp.add(1);
                }
                d.cursor = cp;
                d.first = 0;
                return St::Success;
            }
            return not_found(d.first != 0);
        }
        cp = cp.add(1);
        let host = cp;
        while *cp != b',' {
            if *cp == 0 {
                return not_found(d.first != 0);
            }
            cp = cp.add(1);
        }
        cp = cp.add(1);
        let user = cp;
        while *cp != b',' {
            if *cp == 0 {
                return not_found(d.first != 0);
            }
            cp = cp.add(1);
        }
        cp = cp.add(1);
        let domain = cp;
        while *cp != b')' {
            if *cp == 0 {
                return not_found(d.first != 0);
            }
            cp = cp.add(1);
        }
        cp = cp.add(1);
        let n = cp.offset_from(host) as usize;
        if n > buflen {
            errno::set(ERANGE);
            return St::TryAgain;
        }
        core::ptr::copy_nonoverlapping(host, buffer, n);
        d.typ = 0;
        *buffer.add(user.offset_from(host) as usize - 1) = 0;
        d.host = strip_whitespace(buffer);
        *buffer.add(domain.offset_from(host) as usize - 1) = 0;
        d.user = strip_whitespace(buffer.add(user.offset_from(host) as usize));
        *buffer.add(n - 1) = 0;
        d.domain = strip_whitespace(buffer.add(domain.offset_from(host) as usize));
        d.cursor = cp;
        d.first = 0;
        St::Success
    }
}

static mut DS_ORD: nssmod::Order = nssmod::Order::EMPTY;

unsafe fn end_hook(d: &mut NetGrent, ord: &nssmod::Order) {
    unsafe {
        if d.nip == 0 {
            return;
        }
        let src = ord.e[d.nip - 1];
        if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
            src_end(&src, d);
        }
        d.nip = 0;
    }
}

unsafe fn set_reuse(group: *const u8, d: &mut NetGrent, ord: &mut nssmod::Order) -> bool {
    unsafe {
        end_hook(d, ord);
        let g = cbytes_u8(group);
        let mut status = St::Unavail;
        *ord = ng_order();
        let mut i = 0usize;
        let mut no_more = if ord.n == 0 { 1 } else { ng_lookup(ord, &mut i, Fn3::Set) };
        if ord.n != 0 {
            d.nip = i + 1;
        }
        while no_more == 0 {
            status = src_set(&ord.e[i], g, group, d);
            let old = i;
            no_more = ng_next2(ord, &mut i, Fn3::Set, status);
            d.nip = i + 1;
            if status == St::Success && no_more == 0 {
                let src = ord.e[old];
                if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
                    src_end(&src, d);
                }
            }
        }
        let n = nl_new(group, g.len());
        if n.is_null() {
            errno::set(ENOMEM);
            status = St::TryAgain;
        } else {
            (*n).next = d.known;
            d.known = n;
        }
        status == St::Success
    }
}

unsafe fn internal_set(group: *const u8, d: &mut NetGrent, ord: &mut nssmod::Order) -> bool {
    unsafe {
        nl_free(d.known);
        d.known = null_mut();
        nl_free(d.needed);
        d.needed = null_mut();
        set_reuse(group, d, ord)
    }
}

unsafe fn internal_end(d: &mut NetGrent, ord: &nssmod::Order) {
    unsafe {
        end_hook(d, ord);
        nl_free(d.known);
        d.known = null_mut();
        nl_free(d.needed);
        d.needed = null_mut();
    }
}

unsafe fn internal_get(hostp: *mut *mut c_char, userp: *mut *mut c_char, domainp: *mut *mut c_char, d: &mut NetGrent, ord: &mut nssmod::Order, buffer: *mut u8, buflen: usize) -> c_int {
    unsafe {
        let mut status = St::NotFound;
        if d.nip != 0 && (nssent::is_files(&ord.e[d.nip - 1]) || ng_module_fn(&ord.e[d.nip - 1], Fn3::Get) != 0) {
            loop {
                let src = ord.e[d.nip - 1];
                status = src_get(&src, d, buffer, buflen);
                if status == St::Return || (status == St::NotFound && !d.needed.is_null()) {
                    let mut found = false;
                    while !d.needed.is_null() && !found {
                        let tmp = d.needed;
                        d.needed = (*tmp).next;
                        (*tmp).next = d.known;
                        d.known = tmp;
                        found = set_reuse(nl_name(d.known), d, ord);
                    }
                    if found && d.nip != 0 {
                        let s = ord.e[d.nip - 1];
                        if nssent::is_files(&s) || ng_module_fn(&s, Fn3::Get) != 0 {
                            continue;
                        }
                    }
                } else if status == St::Success && d.typ == 1 {
                    let g = cbytes_u8(d.host as *const u8);
                    if nl_contains(d.known, g) || nl_contains(d.needed, g) {
                        continue;
                    }
                    let n = nl_new(g.as_ptr(), g.len());
                    if n.is_null() {
                        status = St::Return;
                    } else {
                        (*n).next = d.needed;
                        d.needed = n;
                        continue;
                    }
                }
                break;
            }
        }
        if status == St::Success {
            *hostp = d.host as *mut c_char;
            *userp = d.user as *mut c_char;
            *domainp = d.domain as *mut c_char;
        }
        (status == St::Success) as c_int
    }
}

pub(crate) struct PrivNetgr {
    d: NetGrent,
    ord: nssmod::Order,
}

impl PrivNetgr {
    pub(crate) const fn new() -> PrivNetgr {
        PrivNetgr { d: NetGrent::new(), ord: nssmod::Order::EMPTY }
    }
    pub(crate) unsafe fn set(&mut self, group: *const u8) -> bool {
        unsafe { internal_set(group, &mut self.d, &mut self.ord) }
    }
    pub(crate) unsafe fn get(&mut self, host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char, buffer: *mut u8, buflen: usize) -> c_int {
        unsafe { internal_get(host, user, domain, &mut self.d, &mut self.ord, buffer, buflen) }
    }
    pub(crate) unsafe fn end(&mut self) {
        unsafe { internal_end(&mut self.d, &self.ord) }
    }
}

struct Lock(AtomicBool);
static LOCK: Lock = Lock(AtomicBool::new(false));
static mut DATASET: NetGrent = NetGrent::new();
static mut BUFFER: [u8; 1024] = [0; 1024];

struct Guard;
impl Guard {
    fn new() -> Guard {
        while LOCK.0.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        Guard
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.0.store(false, Ordering::Release);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setnetgrent(group: *const c_char) -> c_int {
    unsafe {
        let _g = Guard::new();
        internal_set(group as *const u8, &mut *(&raw mut DATASET), &mut *(&raw mut DS_ORD)) as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endnetgrent() {
    unsafe {
        let _g = Guard::new();
        internal_end(&mut *(&raw mut DATASET), &*(&raw const DS_ORD));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent_r(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char, buffer: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let _g = Guard::new();
        internal_get(host, user, domain, &mut *(&raw mut DATASET), &mut *(&raw mut DS_ORD), buffer as *mut u8, buflen)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char) -> c_int {
    unsafe {
        let _g = Guard::new();
        internal_get(host, user, domain, &mut *(&raw mut DATASET), &mut *(&raw mut DS_ORD), (&raw mut BUFFER) as *mut u8, 1024)
    }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn innetgr(netgroup: *const c_char, host: *const c_char, user: *const c_char, domain: *const c_char) -> c_int {
    unsafe {
        let mut entry = NetGrent::new();
        let mut result = 0;
        let mut current_group = netgroup as *const u8;
        let ng = cbytes_u8(netgroup as *const u8);
        let opt = |p: *const c_char| -> Option<&[u8]> { if p.is_null() { None } else { Some(cbytes_u8(p as *const u8)) } };
        let (host, user, domain) = (opt(host), opt(user), opt(domain));
        loop {
            let ord = ng_order();
            let mut i = 0usize;
            let mut no_more = if ord.n == 0 { 1 } else { ng_lookup(&ord, &mut i, Fn3::Set) };
            while no_more == 0 {
                entry.nip = i + 1;
                let src = ord.e[i];
                let mut status = src_set(&src, cbytes_u8(current_group), current_group, &mut entry);
                if status == St::Success && (nssent::is_files(&src) || ng_module_fn(&src, Fn3::Get) != 0) {
                    let mut buffer = [0u8; 1024];
                    while src_get(&src, &mut entry, buffer.as_mut_ptr(), buffer.len()) == St::Success {
                        if entry.typ == 1 {
                            let g = cbytes_u8(entry.host as *const u8);
                            if !nl_contains(entry.known, g) && !nl_contains(entry.needed, g) && g != ng {
                                let n = nl_new(g.as_ptr(), g.len());
                                if n.is_null() {
                                    result = -1;
                                    break;
                                }
                                (*n).next = entry.needed;
                                entry.needed = n;
                            }
                        } else {
                            let eh = if entry.host.is_null() { None } else { Some(cbytes_u8(entry.host as *const u8)) };
                            let eu = if entry.user.is_null() { None } else { Some(cbytes_u8(entry.user as *const u8)) };
                            let ed = if entry.domain.is_null() { None } else { Some(cbytes_u8(entry.domain as *const u8)) };
                            let m = |e: Option<&[u8]>, q: Option<&[u8]>, nocase: bool| match (e, q) {
                                (Some(e), Some(q)) => if nocase { eq_nocase(e, q) } else { e == q },
                                _ => true,
                            };
                            if m(eh, host, true) && m(eu, user, false) && m(ed, domain, true) {
                                result = 1;
                                break;
                            }
                        }
                    }
                    status = St::Return;
                }
                if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
                    src_end(&src, &mut entry);
                }
                if result != 0 {
                    break;
                }
                no_more = ng_next2(&ord, &mut i, Fn3::Set, status);
            }
            if result == 0 && !entry.needed.is_null() {
                let tmp = entry.needed;
                entry.needed = (*tmp).next;
                (*tmp).next = entry.known;
                entry.known = tmp;
                current_group = nl_name(tmp);
                continue;
            }
            break;
        }
        nl_free(entry.known);
        nl_free(entry.needed);
        (result == 1) as c_int
    }
}
