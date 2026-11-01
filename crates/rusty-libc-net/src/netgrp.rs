//! netdb.h netgroups: `setnetgrent`, `getnetgrent`, `getnetgrent_r`, `endnetgrent`, `innetgr`, on the `files`
//! database `/etc/netgroup` (the service list comes from the `netgroup:` line of nsswitch.conf; only `files` is
//! known, any other source is skipped like the other databases here).
//!
//! The file has lines `name (host,user,domain) (host,user,domain) othergroup ...`, long lines continued with a
//! backslash at the end. `setnetgrent` finds the group and keeps its text; `getnetgrent` hands out the triples one
//! by one, and when a group names other groups it goes through those too (each group at most once);
//! `innetgr` searches a triple the same way. The algorithms (including their quirks) follow glibc 2.43
//! nss/getnetgrent_r.c and nss/nss_files/files-netgrp.c, read as reference and written in Rust.
//!
//! U2: the state is an [`Ng`]: glibc's `struct __netgrent` (the layout the plug-in modules fill) plus, in Rust types, what
//! only this file uses: the `files` text and its read position, and the lists of known and needed groups (the struct's own
//! fields for them stay NULL). What stays unsafe: the module functions (one transmute each), the strings a source stored in
//! the entry (read only after a successful get), the global state under its lock and the C arguments.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::nss::{self, ZBuf};
use crate::util::{HeapVec, eq_nocase, is_space};
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::nscd;
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

/// A NUL-terminated copy of a group name (empty when out of memory).
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

/// A list of group names (glibc's `struct name_list`): membership, push, and pop of the last pushed.
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
    /// false when out of memory (the list is unchanged then).
    fn push(&mut self, name: &[u8]) -> bool {
        let s = self.bytes.len();
        self.bytes.extend_from(name) && self.ranges.push((s, s + name.len()))
    }
    fn contains(&self, name: &[u8]) -> bool {
        self.ranges.iter().any(|&(s, e)| &self.bytes[s..e] == name)
    }
    /// The last pushed name (a copy), taken off the list; None when empty or out of memory.
    fn pop(&mut self) -> Option<Name> {
        let &(s, e) = self.ranges.last()?;
        let n = Name::of(&self.bytes[s..e]);
        // the ranges shrink by rebuilding (HeapVec cannot truncate); lists are short
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

/// glibc's `struct __netgrent`, with its layout: plug-in modules (`_nss_NAME_setnetgrent` and friends) fill it in.
#[repr(C)]
struct NetGrent {
    /// 0: the last entry is a triple, 1: it is the name of another group (then `host` holds the name: glibc's union).
    typ: c_int,
    host: *const c_char,
    user: *const c_char,
    domain: *const c_char,
    /// The text of the group's line and how far it has been read (the modules' own; `files` keeps its text in `Ng`).
    data: *mut u8,
    data_size: usize,
    cursor: *mut u8,
    /// No entry returned yet from this text (an empty or bad text then means "not found").
    first: c_int,
    /// glibc's lists of known and needed groups (always NULL here: see `Ng`).
    known: *mut u8,
    needed: *mut u8,
    /// The source in use plus one (0: none); glibc keeps a pointer into the list of sources here.
    nip: usize,
}

/// The netgroup state: the C entry plus what only this file uses.
struct Ng {
    d: NetGrent,
    /// The `files` source's text of the group (NUL-terminated) and the read position in it (None: no text).
    text: HeapVec<u8>,
    cur: Option<usize>,
    known: Names,
    needed: Names,
    /// The last get succeeded: the entry's strings were stored by the source and may be read.
    got: bool,
    /// The entries the name service cache daemon sent (three NUL-terminated strings each), `daemon_len` bytes, and the read
    /// position. Used while `d.nip` is [`DAEMON`].
    daemon: ZBuf,
    daemon_len: usize,
    daemon_at: usize,
}

/// `d.nip` while the entries come from the name service cache daemon (glibc keeps -1 there).
const DAEMON: usize = usize::MAX;

impl Ng {
    const fn new() -> Ng {
        Ng {
            d: NetGrent { typ: 0, host: core::ptr::null(), user: core::ptr::null(), domain: core::ptr::null(), data: null_mut(), data_size: 0, cursor: null_mut(), first: 0, known: null_mut(), needed: null_mut(), nip: 0 },
            text: HeapVec::new(),
            cur: None,
            known: Names::new(),
            needed: Names::new(),
            got: false,
            daemon: ZBuf::new(),
            daemon_len: 0,
            daemon_at: 0,
        }
    }
    /// The entry's strings after a successful get: host (or the group name), user, domain (None: NULL).
    fn strs(&self) -> [Option<&[u8]>; 3] {
        if !self.got {
            return [None; 3];
        }
        // SAFETY: after a successful get the source stored NULL or C strings (in the caller's buffer, our text or the
        // module's memory), which stay until the next get or end; `&self` keeps those from running meanwhile.
        [self.d.host, self.d.user, self.d.domain].map(|p| unsafe { ffi::cstr(p) }.map(CStr::to_bytes))
    }
}

use rusty_libc_core::nssent::{self, EntOps, Fn3};
use rusty_libc_core::nssmod;

/// The sources of the `netgroup` database: the override of `__nss_configure_lookup`, else nsswitch.conf, else `files`.
fn ng_order() -> nssmod::Order {
    nssmod::order(b"netgroup")
}

/// What the netgroup functions of a source are: `files` is built in, `dns` has none, the rest are module functions.
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

/// `_nss_NAME_setnetgrent` of source `src` (files: built in).
fn src_set(src: &nssmod::Source, group: &CStr, st: &mut Ng) -> St {
    st.got = false;
    if nssent::is_files(src) {
        return files_set(group.to_bytes(), st);
    }
    let f = ng_module_fn(src, Fn3::Set);
    if f == 0 {
        return St::Unavail;
    }
    // SAFETY: `f` is the module's `_nss_NAME_setnetgrent`, whose C type this is (glibc's NSS module ABI); it is called
    // once, below, with a C string and the valid entry.
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
        // SAFETY: `f` is the module's `_nss_NAME_getnetgrent_r`, whose C type this is; called once, below, with the valid
        // entry, the buffer's writable bytes and the calling thread's errno pointer.
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
        // SAFETY: `f` is the module's `_nss_NAME_endnetgrent`, whose C type this is; called once with the valid entry.
        let f: extern "C" fn(*mut NetGrent) -> c_int = unsafe { core::mem::transmute(f) };
        f(&mut st.d);
    }
}

/// glibc's `__nss_netgroup_lookup2`: the first source that has `setnetgrent`. 0 found.
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

/// `n` more zero bytes at the end of `v` (false when out of memory).
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

/// The whole of a file: (buffer, bytes read). The buffer starts at 4096 bytes and doubles when full, so the reads ask for
/// the same sizes as before.
fn read_file(path: &crate::util::Buf<320>) -> Result<(HeapVec<u8>, usize), i32> {
    // etc_path always ends the path with a NUL (it is the last byte pushed); a path with none cannot be opened
    let Ok(path) = CStr::from_bytes_until_nul(&path.b) else { return Err(ENOMEM) };
    // SAFETY: `path` is a C string.
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

/// `_nss_files_endnetgrent`: drop the text.
fn files_end(st: &mut Ng) {
    st.text = HeapVec::new();
    st.cur = None;
}

/// A text being built that can drop its last bytes (glibc's line buffer edits).
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

/// `_nss_files_setnetgrent`: find `group` in the file and keep its text.
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
    // line k: bytes[s..e] with the newline at e (when e < flen); getline's length includes it
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
            // the text after the name and the separator, newline included
            if !out.extend(&line[group.len() + 1..]) {
                oom = true;
                break;
            }
        }
        // a backslash before the newline: the next line goes on
        let mut cur = (s, end);
        while cur.1 - cur.0 > 1 && bytes[cur.1 - 1] == b'\n' && bytes[cur.1 - 2] == b'\\' {
            if found {
                out.len -= 2;
            }
            match next_line(&mut pos) {
                Some((s2, e2)) => {
                    cur = (s2, e2);
                    if found {
                        // a separator where the backslash was, then the new line (its newline replaces the old one)
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
        // NUL-terminate and keep
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

/// Strip white space round the field of `b` that starts at `start` and ends at a NUL; its start, or None when empty.
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

/// `_nss_netgroup_parseline`: the next entry of the `files` text.
fn parseline(st: &mut Ng, buffer: &mut [u8]) -> St {
    let Some(start) = st.cur else { return St::NotFound };
    let d = &mut st.d;
    // the text from the read position to its NUL (the last byte)
    let t = &mut st.text[start..];
    let mut i = 0usize;
    while is_space(t[i]) {
        i += 1;
    }
    let not_found = |first: bool| if first { St::NotFound } else { St::Return };
    if t[i] != b'(' {
        // a list of other groups
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
    // up to the next `stop` (the NUL ends the text: a bad entry)
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
    // before copying to the caller's buffer make sure it is big enough
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

/// `endnetgrent_hook`: close the service in use.
fn end_hook(st: &mut Ng, ord: &nssmod::Order) {
    // (glibc's endnetgrent_hook leaves the daemon's entries alone: getnetgrent goes on with them after endnetgrent)
    if st.d.nip == 0 || st.d.nip == DAEMON {
        return;
    }
    let src = ord.e[st.d.nip - 1];
    if nssent::is_files(&src) || ng_module_fn(&src, Fn3::End) != 0 {
        src_end(&src, st);
    }
    st.d.nip = 0;
}

/// `__internal_setnetgrent_reuse`: open the group through the sources; true when found.
fn set_reuse(group: &CStr, st: &mut Ng, ord: &mut nssmod::Order) -> bool {
    if st.d.nip == DAEMON {
        st.daemon = ZBuf::new();
        st.d.nip = 0;
    }
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
    // add the group to the known ones
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

/// A triple: host, user, domain (each a C string or NULL for "any").
pub(crate) type Triple = (*mut c_char, *mut c_char, *mut c_char);

/// glibc's `nscd_getnetgrent`: the next entry of the daemon's answer; an empty string is NULL ("any").
fn daemon_entry(st: &mut Ng) -> Option<Triple> {
    let data = st.daemon.as_slice().get(..st.daemon_len)?;
    let [host, user, domain] = nscd::reply::netgroup_entry(data, &mut st.daemon_at)?;
    let base = data.as_ptr();
    let at = |r: Option<core::ops::Range<usize>>| r.map_or(null_mut(), |r| base.wrapping_add(r.start).cast_mut().cast::<c_char>());
    st.d.typ = 0;
    st.got = false;
    Some((at(host), at(user), at(domain)))
}

/// `nscd_setnetgrent` and `setnetgrent` of glibc: ask the daemon first; its answer, found or not, is final. None: use the
/// sources (`__internal_setnetgrent`).
fn daemon_set(group: &CStr, st: &mut Ng) -> Option<c_int> {
    let mut sink = ZBuf::new();
    match nscd::netgroup(group.to_bytes(), &mut sink) {
        nscd::Netgroup::Fallback => None,
        nscd::Netgroup::NotFound => {
            errno::set(0);
            Some(0)
        }
        nscd::Netgroup::Found { len } => {
            st.known.free();
            st.needed.free();
            st.daemon = sink;
            st.daemon_len = len;
            st.daemon_at = 0;
            st.d.nip = DAEMON;
            st.d.first = 1;
            Some(1)
        }
    }
}

/// `__internal_getnetgrent_r`: the next triple, or None.
fn internal_get(st: &mut Ng, ord: &mut nssmod::Order, buffer: &mut [u8]) -> Option<Triple> {
    if st.d.nip == DAEMON {
        return daemon_entry(st);
    }
    let mut status = St::NotFound;
    if st.d.nip != 0 && (nssent::is_files(&ord.e[st.d.nip - 1]) || ng_module_fn(&ord.e[st.d.nip - 1], Fn3::Get) != 0) {
        loop {
            let src = ord.e[st.d.nip - 1];
            status = src_get(&src, st, buffer);
            if status == St::Return || (status == St::NotFound && !st.needed.is_empty()) {
                // the last one of this group: go to the next group if there is one (set_reuse adds the name to the known
                // ones, as glibc's moving the list node there does)
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
                // the name of another group
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

/// glibc's `__internal_setnetgrent`, `__internal_getnetgrent_r` and `__internal_endnetgrent` on a state of their own (the
/// compat source walks a netgroup without touching the one a program opened with `setnetgrent`).
pub(crate) struct PrivNetgr {
    st: Ng,
    ord: nssmod::Order,
}

impl PrivNetgr {
    pub(crate) const fn new() -> PrivNetgr {
        PrivNetgr { st: Ng::new(), ord: nssmod::Order::EMPTY }
    }
    /// Open `group`; true when some source knows it.
    pub(crate) fn set(&mut self, group: &CStr) -> bool {
        internal_set(group, &mut self.st, &mut self.ord)
    }
    /// The next triple, or None; the strings are in `buffer` or in the state.
    pub(crate) fn get(&mut self, buffer: &mut [u8]) -> Option<Triple> {
        internal_get(&mut self.st, &mut self.ord, buffer)
    }
    pub(crate) fn end(&mut self) {
        internal_end(&mut self.st, &self.ord)
    }
}

struct Lock(AtomicBool);
static LOCK: Lock = Lock(AtomicBool::new(false));

/// The state of `setnetgrent`/`getnetgrent`: the entry, the sources `d.nip` points into (glibc keeps pointers into the
/// list itself) and `getnetgrent`'s static buffer.
struct Global {
    st: Ng,
    ord: nssmod::Order,
    buffer: [u8; 1024],
}

/// Rule: touched only inside [`with_global`], under LOCK.
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
    // SAFETY: LOCK is held for the call, and GLOBAL is only reached here; `f` (this module's code and the NSS modules it
    // calls) never re-enters the netgroup functions that take LOCK (a re-entry would spin forever, as before).
    unsafe { GLOBAL.with_unsync(f) }
}

/// `setnetgrent (netgroup)`: open a netgroup for `getnetgrent`; 1 if it exists, 0 if not.
///
/// # Safety
/// `group` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setnetgrent(group: *const c_char) -> c_int {
    // SAFETY: `group` is a C string (the contract; glibc also faults on NULL).
    let group = unsafe { ffi::cstr_nonnull(group) };
    with_global(|g| match daemon_set(group, &mut g.st) {
        Some(r) => r,
        None => internal_set(group, &mut g.st, &mut g.ord) as c_int,
    })
}

/// `endnetgrent ()`: close the netgroup and forget what was read.
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endnetgrent() {
    with_global(|g| internal_end(&mut g.st, &g.ord))
}

/// `getnetgrent_r (host, user, domain, buffer, buflen)`: the next triple of the open netgroup (the strings are
/// in `buffer`; a NULL pointer means "any"); 1, or 0 at the end (and for ERANGE: the buffer is too small).
///
/// # Safety
/// The pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent_r(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char, buffer: *mut c_char, buflen: usize) -> c_int {
    // SAFETY: `buffer` is writable for `buflen` bytes and used by nothing else during the call (the contract).
    let buffer = unsafe { ffi::bytes_mut(buffer.cast::<u8>(), buflen) };
    match with_global(|g| internal_get(&mut g.st, &mut g.ord, buffer)) {
        Some(t) => {
            // SAFETY: the out-pointers are valid for writes (the contract; glibc does not check them either).
            let [h, u, d] = [host, user, domain].map(|p| unsafe { &mut *p });
            (*h, *u, *d) = t;
            1
        }
        None => 0,
    }
}

/// `getnetgrent (host, user, domain)`: `getnetgrent_r` with a static 1024 byte buffer.
///
/// # Safety
/// The pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent(host: *mut *mut c_char, user: *mut *mut c_char, domain: *mut *mut c_char) -> c_int {
    // the triple is stored under the lock, as before
    with_global(|g| match internal_get(&mut g.st, &mut g.ord, &mut g.buffer) {
        Some(t) => {
            // SAFETY: the out-pointers are valid for writes (the contract).
            let [h, u, d] = [host, user, domain].map(|p| unsafe { &mut *p });
            (*h, *u, *d) = t;
            1
        }
        None => 0,
    })
}

/// `innetgr` on Rust values: is the triple in the netgroup (or in a group it names)? None matches anything.
pub fn in_netgroup(netgroup: &CStr, host: Option<&[u8]>, user: Option<&[u8]>, domain: Option<&[u8]>) -> bool {
    // the name service cache daemon first: its answer is final
    match nscd::in_netgroup(netgroup.to_bytes(), host, user, domain) {
        nscd::InNetgroup::Fallback => {}
        nscd::InNetgroup::NotFound => {
            errno::set(0);
            return false;
        }
        nscd::InNetgroup::Result(r) => return r != 0,
    }
    let mut entry = Ng::new();
    let mut result = 0;
    let ng = netgroup.to_bytes();
    // the group being searched once it came off the needed list (glibc moves it to the known ones first; it is
    // compared as one of them)
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
                        // not seen before and not the group being asked about
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
                // a source that knows the group ends the search
                status = St::Return;
            }
            // free all resources of the source
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

/// `innetgr (netgroup, host, user, domain)`: is the triple in the netgroup (or in a group it names)? A NULL
/// part matches anything, as does an empty part of an entry; host and domain compare without regard to case.
/// Like glibc it walks the sources (files and plug-in modules) and stops at the first one that knows the group.
///
/// # Safety
/// `netgroup` is a C string; the others are C strings or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn innetgr(netgroup: *const c_char, host: *const c_char, user: *const c_char, domain: *const c_char) -> c_int {
    // SAFETY: `netgroup` is a C string (the contract).
    let netgroup = unsafe { ffi::cstr_nonnull(netgroup) };
    // SAFETY: C strings or NULL (the contract).
    let [host, user, domain] = [host, user, domain].map(|p| unsafe { ffi::cstr(p) }.map(CStr::to_bytes));
    in_netgroup(netgroup, host, user, domain) as c_int
}
