#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::nss;
use crate::util::{HeapVec, eq_nocase, is_space};
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

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

struct Name(HeapVec<u8>);

impl Name {
    fn of(b: &[u8]) -> Option<Name> {
        let mut v = HeapVec::new();
        if v.extend_from(b) && v.push(0) { Some(Name(v)) } else { None }
    }
    fn cstr(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.0).unwrap_or_default()
    }
}

struct Names {
    bytes: HeapVec<u8>,
    ranges: HeapVec<(usize, usize)>,
}

impl Names {
    const fn new() -> Names {
        Names { bytes: HeapVec::new(), ranges: HeapVec::new() }
    }
    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
    fn push(&mut self, name: &[u8]) -> bool {
        let s = self.bytes.len();
        self.bytes.extend_from(name) && self.ranges.push((s, s + name.len()))
    }
    fn contains(&self, name: &[u8]) -> bool {
        self.ranges.iter().any(|&(s, e)| &self.bytes[s..e] == name)
    }
    fn pop(&mut self) -> Option<Name> {
        let &(s, e) = self.ranges.last()?;
        let n = Name::of(&self.bytes[s..e]);
        let mut r = HeapVec::new();
        let k = self.ranges.len() - 1;
        if !r.extend_from(&self.ranges[..k]) {
            return None;
        }
        self.ranges = r;
        n
    }
    fn free(&mut self) {
        *self = Names::new();
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
    known: *mut u8,
    needed: *mut u8,
    nip: usize,
}

struct Ng {
    d: NetGrent,
    text: HeapVec<u8>,
    cur: Option<usize>,
    known: Names,
    needed: Names,
    got: bool,
}

impl Ng {
    const fn new() -> Ng {
        Ng {
            d: NetGrent { typ: 0, host: core::ptr::null(), user: core::ptr::null(), domain: core::ptr::null(), data: null_mut(), data_size: 0, cursor: null_mut(), first: 0, known: null_mut(), needed: null_mut(), nip: 0 },
            text: HeapVec::new(),
            cur: None,
            known: Names::new(),
            needed: Names::new(),
            got: false,
        }
    }
    fn strs(&self) -> [Option<&[u8]>; 3] {
        if !self.got {
            return [None; 3];
        }
        [self.d.host, self.d.user, self.d.domain].map(|p| unsafe { ffi::cstr(p) }.map(CStr::to_bytes))
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

fn src_set(src: &nssmod::Source, group: &CStr, st: &mut Ng) -> St {
    st.got = false;
    if nssent::is_files(src) {
        return files_set(group.to_bytes(), st);
    }
    let f = ng_module_fn(src, Fn3::Set);
    if f == 0 {
        return St::Unavail;
    }
    let f: extern "C" fn(*const c_char, *mut NetGrent) -> c_int = unsafe { core::mem::transmute(f) };
    st_of(f(group.as_ptr(), &mut st.d))
}

fn src_get(src: &nssmod::Source, st: &mut Ng, buffer: &mut [u8]) -> St {
    st.got = false;
    let r = if nssent::is_files(src) {
        parseline(st, buffer)
    } else {
        let f = ng_module_fn(src, Fn3::Get);
        if f == 0 {
            return St::Unavail;
        }
        let f: extern "C" fn(*mut NetGrent, *mut u8, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
        st_of(f(&mut st.d, buffer.as_mut_ptr(), buffer.len(), errno::location()))
    };
    st.got = r == St::Success;
    r
}

fn src_end(src: &nssmod::Source, st: &mut Ng) {
    st.got = false;
    if nssent::is_files(src) {
        files_end(st);
        return;
    }
    let f = ng_module_fn(src, Fn3::End);
    if f != 0 {
        let f: extern "C" fn(*mut NetGrent) -> c_int = unsafe { core::mem::transmute(f) };
        f(&mut st.d);
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

fn grow_zeroed(v: &mut HeapVec<u8>, n: usize) -> bool {
    let zeros = [0u8; 512];
    let mut left = n;
    while left > 0 {
        let k = left.min(zeros.len());
        if !v.extend_from(&zeros[..k]) {
            return false;
        }
        left -= k;
    }
    true
}

fn read_file(path: &crate::util::Buf<320>) -> Result<(HeapVec<u8>, usize), i32> {
    let Ok(path) = CStr::from_bytes_until_nul(&path.b) else { return Err(ENOMEM) };
    let fd = match unsafe { rusty_libc_core::unistd::open(path.as_ptr(), 0o2000000, 0) } {
        Ok(fd) => fd,
        Err(e) => return Err(e.0),
    };
    let mut buf = HeapVec::new();
    if !grow_zeroed(&mut buf, 4096) {
        let _ = rusty_libc_core::unistd::close(fd);
        return Err(ENOMEM);
    }
    let mut len = 0usize;
    loop {
        if len == buf.len() && !grow_zeroed(&mut buf, len) {
            let _ = rusty_libc_core::unistd::close(fd);
            return Err(ENOMEM);
        }
        match rusty_libc_core::unistd::read(fd, &mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.0 == 4 => {}
            Err(_) => break,
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    Ok((buf, len))
}

fn files_end(st: &mut Ng) {
    st.text = HeapVec::new();
    st.cur = None;
}

struct Text {
    v: HeapVec<u8>,
    len: usize,
}

impl Text {
    fn push(&mut self, b: u8) -> bool {
        if self.len < self.v.len() {
            self.v[self.len] = b;
        } else if !self.v.push(b) {
            return false;
        }
        self.len += 1;
        true
    }
    fn extend(&mut self, s: &[u8]) -> bool {
        s.iter().all(|&b| self.push(b))
    }
}

fn files_set(group: &[u8], st: &mut Ng) -> St {
    if group.is_empty() {
        return St::Unavail;
    }
    let path = nss::etc_path(b"/netgroup");
    let (file, flen) = match read_file(&path) {
        Ok(x) => x,
        Err(e) => return if e == EAGAIN { St::TryAgain } else { St::Unavail },
    };
    let bytes = &file[..flen];
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
    let mut out = Text { v: HeapVec::new(), len: 0 };
    let mut oom = false;
    while let Some((s, end)) = next_line(&mut pos) {
        let line = &bytes[s..end];
        let found = line.len() > group.len() && line[..group.len()] == *group && is_space(line[group.len()]);
        if found {
            if !out.extend(&line[group.len() + 1..]) {
                oom = true;
                break;
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
                            oom = true;
                            break;
                        }
                    }
                }
                None => break,
            }
        }
        if oom {
            break;
        }
        if found {
            status = St::Success;
            break;
        }
    }
    drop(file);
    if oom {
        files_end(st);
        return St::Unavail;
    }
    if status == St::Success {
        if !out.push(0) {
            return St::Unavail;
        }
        st.text = out.v;
        st.cur = Some(0);
        st.d.first = 1;
    } else {
        files_end(st);
    }
    status
}

fn strip_whitespace(b: &mut [u8], start: usize) -> Option<usize> {
    let mut c = start;
    while is_space(b[c]) {
        c += 1;
    }
    let s = c;
    while b[c] != 0 && !is_space(b[c]) {
        c += 1;
    }
    b[c] = 0;
    if b[s] == 0 { None } else { Some(s) }
}

fn parseline(st: &mut Ng, buffer: &mut [u8]) -> St {
    let Some(start) = st.cur else { return St::NotFound };
    let d = &mut st.d;
    let t = &mut st.text[start..];
    let mut i = 0usize;
    while is_space(t[i]) {
        i += 1;
    }
    let not_found = |first: bool| if first { St::NotFound } else { St::Return };
    if t[i] != b'(' {
        let name = i;
        while t[i] != 0 && !is_space(t[i]) {
            i += 1;
        }
        if name != i {
            let last = t[i] == 0;
            d.typ = 1;
            t[i] = 0;
            if !last {
                i += 1;
            }
            d.host = t.as_ptr().wrapping_add(name).cast::<c_char>();
            st.cur = Some(start + i);
            d.first = 0;
            return St::Success;
        }
        return not_found(d.first != 0);
    }
    let skip_to = |i: &mut usize, stop: u8| -> bool {
        while t[*i] != stop {
            if t[*i] == 0 {
                return false;
            }
            *i += 1;
        }
        *i += 1;
        true
    };
    i += 1;
    let host = i;
    if !skip_to(&mut i, b',') {
        return not_found(d.first != 0);
    }
    let user = i;
    if !skip_to(&mut i, b',') {
        return not_found(d.first != 0);
    }
    let domain = i;
    if !skip_to(&mut i, b')') {
        return not_found(d.first != 0);
    }
    let n = i - host;
    if n > buffer.len() {
        errno::set(ERANGE);
        return St::TryAgain;
    }
    let b = &mut buffer[..n];
    b.copy_from_slice(&t[host..i]);
    d.typ = 0;
    b[user - host - 1] = 0;
    let h = strip_whitespace(b, 0);
    b[domain - host - 1] = 0;
    let u = strip_whitespace(b, user - host);
    b[n - 1] = 0;
    let dm = strip_whitespace(b, domain - host);
    let bp = buffer.as_ptr();
    let at = |o: Option<usize>| o.map_or(core::ptr::null(), |o| bp.wrapping_add(o).cast::<c_char>());
    d.host = at(h);
    d.user = at(u);
    d.domain = at(dm);
    st.cur = Some(start + i);
    d.first = 0;
    St::Success
}

fn end_hook(st: &mut Ng, ord: &nssmod::Order) {
    if st.d.nip == 0 {
        return;
    }
    let src = ord.e[st.d.nip - 1];
    if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
        src_end(&src, st);
    }
    st.d.nip = 0;
}

fn set_reuse(group: &CStr, st: &mut Ng, ord: &mut nssmod::Order) -> bool {
    end_hook(st, ord);
    let mut status = St::Unavail;
    *ord = ng_order();
    let mut i = 0usize;
    let mut no_more = if ord.n == 0 { 1 } else { ng_lookup(ord, &mut i, Fn3::Set) };
    if ord.n != 0 {
        st.d.nip = i + 1;
    }
    while no_more == 0 {
        status = src_set(&ord.e[i], group, st);
        let old = i;
        no_more = ng_next2(ord, &mut i, Fn3::Set, status);
        st.d.nip = i + 1;
        if status == St::Success && no_more == 0 {
            let src = ord.e[old];
            if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
                src_end(&src, st);
            }
        }
    }
    if !st.known.push(group.to_bytes()) {
        errno::set(ENOMEM);
        status = St::TryAgain;
    }
    status == St::Success
}

fn internal_set(group: &CStr, st: &mut Ng, ord: &mut nssmod::Order) -> bool {
    st.known.free();
    st.needed.free();
    set_reuse(group, st, ord)
}

fn internal_end(st: &mut Ng, ord: &nssmod::Order) {
    end_hook(st, ord);
    st.known.free();
    st.needed.free();
}

pub(crate) type Triple = (*mut c_char, *mut c_char, *mut c_char);

fn internal_get(st: &mut Ng, ord: &mut nssmod::Order, buffer: &mut [u8]) -> Option<Triple> {
    let mut status = St::NotFound;
    if st.d.nip != 0 && (nssent::is_files(&ord.e[st.d.nip - 1]) || ng_module_fn(&ord.e[st.d.nip - 1], Fn3::Get) != 0) {
        loop {
            let src = ord.e[st.d.nip - 1];
            status = src_get(&src, st, buffer);
            if status == St::Return || (status == St::NotFound && !st.needed.is_empty()) {
                let mut found = false;
                while !found {
                    let Some(n) = st.needed.pop() else { break };
                    found = set_reuse(n.cstr(), st, ord);
                }
                if found && st.d.nip != 0 {
                    let s = ord.e[st.d.nip - 1];
                    if nssent::is_files(&s) || ng_module_fn(&s, Fn3::Get) != 0 {
                        continue;
                    }
                }
            } else if status == St::Success && st.d.typ == 1 {
                let [g, _, _] = st.strs();
                let g = g.unwrap_or(b"");
                if st.known.contains(g) || st.needed.contains(g) {
                    continue;
                }
                let n = Name::of(g);
                match n {
                    Some(n) if st.needed.push(n.cstr().to_bytes()) => continue,
                    _ => status = St::Return,
                }
            }
            break;
        }
    }
    if status == St::Success { Some((st.d.host as *mut c_char, st.d.user as *mut c_char, st.d.domain as *mut c_char)) } else { None }
}

pub(crate) struct PrivNetgr {
    st: Ng,
    ord: nssmod::Order,
}

impl PrivNetgr {
    pub(crate) const fn new() -> PrivNetgr {
        PrivNetgr { st: Ng::new(), ord: nssmod::Order::EMPTY }
    }
    pub(crate) fn set(&mut self, group: &CStr) -> bool {
        internal_set(group, &mut self.st, &mut self.ord)
    }
    pub(crate) fn get(&mut self, buffer: &mut [u8]) -> Option<Triple> {
        internal_get(&mut self.st, &mut self.ord, buffer)
    }
    pub(crate) fn end(&mut self) {
        internal_end(&mut self.st, &self.ord)
    }
}

struct Lock(AtomicBool);
static LOCK: Lock = Lock(AtomicBool::new(false));

struct Global {
    st: Ng,
    ord: nssmod::Order,
    buffer: [u8; 1024],
}

static GLOBAL: SyncCell<Global> = SyncCell::new(Global { st: Ng::new(), ord: nssmod::Order::EMPTY, buffer: [0; 1024] });

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

fn with_global<R>(f: impl FnOnce(&mut Global) -> R) -> R {
    let _g = Guard::new();
    unsafe { GLOBAL.with_unsync(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setnetgrent(group: *const c_char) -> c_int {
    let group = unsafe { ffi::cstr_nonnull(group) };
    with_global(|g| internal_set(group, &mut g.st, &mut g.ord)) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endnetgrent() {
    with_global(|g| internal_end(&mut g.st, &g.ord))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent_r(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char, buffer: *mut c_char, buflen: usize) -> c_int {
    let buffer = unsafe { ffi::bytes_mut(buffer.cast::<u8>(), buflen) };
    match with_global(|g| internal_get(&mut g.st, &mut g.ord, buffer)) {
        Some(t) => {
            let [h, u, d] = [host, user, domain].map(|p| unsafe { &mut *p });
            (*h, *u, *d) = t;
            1
        }
        None => 0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char) -> c_int {
    with_global(|g| match internal_get(&mut g.st, &mut g.ord, &mut g.buffer) {
        Some(t) => {
            let [h, u, d] = [host, user, domain].map(|p| unsafe { &mut *p });
            (*h, *u, *d) = t;
            1
        }
        None => 0,
    })
}

pub fn in_netgroup(netgroup: &CStr, host: Option<&[u8]>, user: Option<&[u8]>, domain: Option<&[u8]>) -> bool {
    let mut entry = Ng::new();
    let mut result = 0;
    let ng = netgroup.to_bytes();
    let mut cur: Option<Name> = None;
    loop {
        let group: &CStr = match &cur {
            Some(n) => n.cstr(),
            None => netgroup,
        };
        let ord = ng_order();
        let mut i = 0usize;
        let mut no_more = if ord.n == 0 { 1 } else { ng_lookup(&ord, &mut i, Fn3::Set) };
        while no_more == 0 {
            entry.d.nip = i + 1;
            let src = ord.e[i];
            let mut status = src_set(&src, group, &mut entry);
            if status == St::Success && (nssent::is_files(&src) || ng_module_fn(&src, Fn3::Get) != 0) {
                let mut buffer = [0u8; 1024];
                while src_get(&src, &mut entry, &mut buffer) == St::Success {
                    let [eh, eu, ed] = entry.strs();
                    if entry.d.typ == 1 {
                        let g = eh.unwrap_or(b"");
                        let is_cur = cur.as_ref().is_some_and(|n| n.cstr().to_bytes() == g);
                        if !entry.known.contains(g) && !is_cur && !entry.needed.contains(g) && g != ng {
                            let n = Name::of(g);
                            if !n.is_some_and(|n| entry.needed.push(n.cstr().to_bytes())) {
                                result = -1;
                                break;
                            }
                        }
                    } else {
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
        if result == 0 && !entry.needed.is_empty() {
            if let Some(n) = cur.take()
                && !entry.known.push(n.cstr().to_bytes())
            {
                break;
            }
            cur = entry.needed.pop();
            if cur.is_none() {
                break;
            }
            continue;
        }
        break;
    }
    drop(cur);
    entry.known.free();
    entry.needed.free();
    result == 1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn innetgr(netgroup: *const c_char, host: *const c_char, user: *const c_char, domain: *const c_char) -> c_int {
    let netgroup = unsafe { ffi::cstr_nonnull(netgroup) };
    let [host, user, domain] = [host, user, domain].map(|p| unsafe { ffi::cstr(p) }.map(CStr::to_bytes));
    in_netgroup(netgroup, host, user, domain) as c_int
}
