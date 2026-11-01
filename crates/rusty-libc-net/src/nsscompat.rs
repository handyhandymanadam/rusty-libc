//! The `compat` source of passwd, group, shadow and initgroups (glibc's libnss_compat): the files with NIS-style entries.
//!
//! In /etc/passwd (and /etc/shadow) `+name` takes the user `name` from the `passwd_compat` sources (`shadow_compat`), `-name`
//! hides it, `+@netgroup` / `-@netgroup` do the same for the users of a netgroup, and a lone `+` takes every user that is
//! left; non-empty fields of a `+` line replace the fetched ones. /etc/group knows `+group`, `-group` and `+` (`group_compat`).
//! The rules, including glibc's quirks, follow glibc 2.43 nss/nss_compat/compat-pwd.c, compat-grp.c, compat-spwd.c and
//! compat-initgroups.c (LGPL, read as a reference; nothing copied). As in glibc only the FIRST source of a `*_compat` line is
//! used (its default is `nis`, which Fedora does not ship: then `+` entries find nothing).
//!
//! The library answers a `compat` source itself (rusty-libc-util asks [`__rl_nss_compat_function`]), so it works in static
//! programs too; the functions are also exported as glibc's `_nss_compat_*` (GLIBC_PRIVATE) for libnss_compat.so.2.
//!
//! U2: the entries (`struct passwd`, `group`, `spwd`) and the caller's buffer stay raw memory inside: the compat rules hand
//! the sources keys that point into the very buffer the next lookup overwrites (a glibc quirk kept on purpose, see
//! `Impl::getnam`), so the buffer cannot be one Rust slice while those keys live. The raw parts sit behind three small types
//! in [`raw`], each built once at the C boundary: [`raw::CBuf`] (the caller's buffer: writable bytes, cut into disjoint
//! views), [`raw::Key`] (a NUL-terminated key that may point into that buffer) and [`raw::Out`] (the result entry, which knows
//! whether its last lookup filled it, so its strings may be read). The rest is safe code over them; what stays unsafe beside
//! them: the module functions (one transmute each), the `files` parser calls, the global states under their locks, the
//! initgroups arrays the sources realloc.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::netgrp::{PrivNetgr, in_netgroup};
use crate::util::HeapVec;
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use raw::{CBuf, Key, Out, Plus};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::nssmod;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_util::pwd::{CompatFile, Gid, Group, Passwd, Spwd, Uid};

const TRYAGAIN: c_int = -2;
const UNAVAIL: c_int = -1;
const NOTFOUND: c_int = 0;
const SUCCESS: c_int = 1;
const RETURN: c_int = 2;
const ERANGE: c_int = 34;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;

/// The raw memory of the compat functions, each kind behind one type whose constructor states the contract.
mod raw {
    use super::{Changes, Kind, SUCCESS};
    use rusty_libc_util::pwd::Group;
    use crate::util::HeapVec;
    use core::ffi::{CStr, c_char};
    use core::marker::PhantomData;

    /// `len` writable bytes at `p` for `'a` (the caller's `buffer, buflen` or a buffer of ours). The views cut from it
    /// ([`CBuf::sub`], [`CBuf::take_tail`]) borrow it mutably, so at most one view of any byte is in use at a time; the
    /// sources get the pointer and length, Rust code a slice only through [`CBuf::lend`].
    pub(super) struct CBuf<'a> {
        p: *mut c_char,
        len: usize,
        _m: PhantomData<&'a mut [u8]>,
    }

    impl<'a> CBuf<'a> {
        /// # Safety
        /// `p` is writable for `len` bytes during `'a` and nothing reaches them except through this view.
        pub(super) unsafe fn new(p: *mut c_char, len: usize) -> CBuf<'a> {
            CBuf { p, len, _m: PhantomData }
        }
        pub(super) fn from_slice(s: &'a mut [u8]) -> CBuf<'a> {
            CBuf { p: s.as_mut_ptr().cast(), len: s.len(), _m: PhantomData }
        }
        pub(super) fn ptr(&self) -> *mut c_char {
            self.p
        }
        pub(super) fn len(&self) -> usize {
            self.len
        }
        /// A view of the whole buffer, for a callee that may shorten it.
        pub(super) fn sub(&mut self) -> CBuf<'_> {
            CBuf { p: self.p, len: self.len, _m: PhantomData }
        }
        /// Cut the last `n` bytes off this view (for good) and return them as a view of their own; None when shorter.
        pub(super) fn take_tail(&mut self, n: usize) -> Option<CBuf<'a>> {
            if n > self.len {
                return None;
            }
            self.len -= n;
            Some(CBuf { p: self.p.wrapping_add(self.len), len: n, _m: PhantomData })
        }
        /// The bytes as a slice (for Rust code that writes them: the netgroup reader, the field copies).
        pub(super) fn lend(&mut self) -> &mut [u8] {
            // SAFETY: `len` writable bytes for `'a` that only this view reaches (constructor contract), borrowed for the
            // slice's lifetime through `&mut self`.
            unsafe { rusty_libc_core::ffi::bytes_mut(self.p.cast::<u8>(), self.len) }
        }
    }

    /// A key for a by-name lookup: NUL-terminated memory that stays readable while lookups run (the caller's string, our
    /// copy, or a name in the caller's buffer, which those lookups overwrite: then the bytes compared are whatever is
    /// there by then, as in glibc).
    #[derive(Clone, Copy)]
    pub(super) struct Key<'a>(*const c_char, PhantomData<&'a ()>);

    impl<'a> Key<'a> {
        pub(super) fn of(c: &'a CStr) -> Key<'a> {
            Key(c.as_ptr(), PhantomData)
        }
        pub(super) fn ptr(self) -> *const c_char {
            self.0
        }
        fn at(self, i: usize) -> u8 {
            // SAFETY: the key is NUL-terminated (the type's invariant) and callers stop at its first NUL.
            unsafe { self.0.wrapping_add(i).read() as u8 }
        }
        pub(super) fn first(self) -> u8 {
            self.at(0)
        }
        /// strcmp(key, name) == 0 on the key's memory as it is now.
        pub(super) fn live_eq(self, name: &[u8]) -> bool {
            let mut i = 0;
            loop {
                let x = self.at(i);
                if x != name.get(i).copied().unwrap_or(0) {
                    return false;
                }
                if x == 0 {
                    return true;
                }
                i += 1;
            }
        }
    }

    /// The result entry of a lookup and whether the last lookup into it succeeded (then its strings are C strings in the
    /// buffer or the module's memory; the only writer of that memory between lookups, the netgroup reader, clears the flag
    /// first through [`Out::forget`]).
    pub(super) struct Out<'a, E> {
        res: &'a mut E,
        filled: bool,
    }

    impl<'a, E: Kind> Out<'a, E> {
        pub(super) fn new(res: &'a mut E) -> Out<'a, E> {
            Out { res, filled: false }
        }
        /// For a lookup: the entry's pointer; the status it returns decides whether the entry counts as filled.
        pub(super) fn fill(&mut self, f: impl FnOnce(*mut E) -> i32) -> i32 {
            self.filled = false;
            let st = f(self.res);
            self.filled = st == SUCCESS;
            st
        }
        /// The buffer the entry's strings live in is about to be overwritten.
        pub(super) fn forget(&mut self) {
            self.filled = false;
        }
        pub(super) fn get(&self) -> &E {
            self.res
        }
        /// The name of the filled entry ("" when not filled: callers only ask after a SUCCESS).
        pub(super) fn name(&self) -> &[u8] {
            if !self.filled {
                return b"";
            }
            // SAFETY: the entry is filled, so its name is a C string still in place.
            unsafe { rusty_libc_core::ffi::cstr(self.res.name()) }.map_or(b"", CStr::to_bytes)
        }
        /// The name from byte `skip` on as a lookup key (glibc passes `name + skip`, a pointer into the buffer).
        pub(super) fn key(&self, skip: usize) -> Key<'a> {
            if !self.filled || self.name().len() < skip {
                return Key::of(c"");
            }
            Key(self.res.name().wrapping_add(skip), PhantomData)
        }
    }

    impl Out<'_, Group> {
        /// Is `user` in the member list of the filled entry (a NULL-terminated array of C strings)?
        pub(super) fn has_member(&self, user: &[u8]) -> bool {
            if !self.filled {
                return false;
            }
            let mut m = self.res.gr_mem.cast_const();
            loop {
                // SAFETY: the entry is filled: `gr_mem` is a NULL-terminated array of C strings; the loop stops at the NULL.
                let p = unsafe { m.read() };
                if p.is_null() {
                    return false;
                }
                // SAFETY: a member is a C string (as above).
                if unsafe { rusty_libc_core::ffi::cstr_bytes(p) } == user {
                    return true;
                }
                m = m.wrapping_add(1);
            }
        }
    }

    /// The overriding fields of a `+` line (glibc keeps strdup'ed copies in a `struct passwd` / `spwd`): the non-empty
    /// strings with their NUL, and an entry holding the numeric fields that differ from the defaults.
    pub(super) struct Plus<E> {
        strs: [Option<HeapVec<u8>>; 4],
        nums: E,
    }

    impl<E: Changes> Plus<E> {
        pub(super) fn new() -> Plus<E> {
            Plus { strs: [None, None, None, None], nums: E::zero() }
        }
        /// The fields of the filled entry (glibc's `copy_*_changes` with no buffer: strdup of each non-empty field; a copy
        /// that cannot be made is left out, as strdup's NULL was).
        pub(super) fn of(out: &mut Out<E>) -> Plus<E> {
            let mut p = Plus::new();
            if !out.filled {
                return p;
            }
            let mut i = 0;
            let strs = &mut p.strs;
            out.res.each_str(&mut |f| {
                // SAFETY: the entry is filled: its string fields are NULL or C strings.
                let s = unsafe { rusty_libc_core::ffi::cstr(*f) }.map(CStr::to_bytes_with_nul);
                if let Some(s) = s
                    && s.len() > 1
                {
                    let mut v = HeapVec::new();
                    if v.extend_from(s) {
                        strs[i] = Some(v);
                    }
                }
                i += 1;
            });
            p.nums.copy_nums(out.res);
            p
        }
        /// The room the strings need in the buffer (`pwd_need_buflen`).
        pub(super) fn need(&self) -> usize {
            self.strs.iter().flatten().map(|v| v.len()).sum()
        }
        /// Lay the fields over the filled entry (glibc's `copy_*_changes` with a buffer): a string goes over the old one when
        /// that is long enough, else into `tail` (sized by [`Plus::need`]).
        pub(super) fn apply(&self, out: &mut Out<E>, mut tail: CBuf) {
            if !out.filled {
                return;
            }
            let t = tail.lend();
            // offsets in `t` of the strings placed there, per field (pointers are made after all the writes)
            let mut placed: [Option<usize>; 4] = [None; 4];
            let mut off = 0usize;
            let mut i = 0;
            out.res.each_str(&mut |f| {
                if let Some(src) = &self.strs[i] {
                    // SAFETY: the entry is filled: the field is NULL or a C string in place.
                    let old = unsafe { rusty_libc_core::ffi::cstr(*f) };
                    if old.is_some_and(|o| o.to_bytes().len() + 1 >= src.len()) {
                        // SAFETY: the old string (in the caller's buffer or the module's memory, writable) is at least as
                        // long as `src` without its NUL; `src` is our copy elsewhere.
                        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().cast::<c_char>(), *f, src.len()) };
                    } else if off + src.len() <= t.len() {
                        t[off..off + src.len()].copy_from_slice(src);
                        placed[i] = Some(off);
                        off += src.len();
                    }
                }
                i += 1;
            });
            let base = t.as_mut_ptr().cast::<c_char>();
            let mut i = 0;
            out.res.each_str(&mut |f| {
                if let Some(o) = placed[i] {
                    *f = base.wrapping_add(o);
                }
                i += 1;
            });
            out.res.copy_nums(&self.nums);
        }
    }
}

/// A NUL-terminated copy of a name (glibc copies the `+name` part to the stack before the buffer is reused); a copy that
/// could not be made (out of memory) reads as the empty name.
struct Name(HeapVec<u8>);

impl Name {
    fn of(b: &[u8]) -> Name {
        let mut v = HeapVec::new();
        if !(v.extend_from(b) && v.push(0)) {
            v.clear();
        }
        Name(v)
    }
    fn cstr(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.0).unwrap_or_default()
    }
    fn bytes(&self) -> &[u8] {
        self.cstr().to_bytes()
    }
}

/// `__nss_get_default_domain` of glibc 2.43 (nss_compat/nisdomain.c) never calls getdomainname: its cached name starts empty
/// and is only refreshed when it is not, so the domain is always "".
const DEFAULT_DOMAIN: &[u8] = b"";

// ---------------------------------------------------------------- the blacklist of -name / -@netgroup / handled +name entries

/// The names seen so far, as one string `|a|b|c|` (glibc's `struct blacklist_t`; `active` is its non-NULL data).
struct Blacklist {
    buf: HeapVec<u8>,
    active: bool,
}

impl Blacklist {
    const fn new() -> Blacklist {
        Blacklist { buf: HeapVec::new(), active: false }
    }
    /// glibc's `current`: the length of the string (0 when there is none).
    fn current(&self) -> usize {
        if self.active { self.buf.len() } else { 0 }
    }
    fn reset(&mut self) {
        if self.active {
            self.buf.clear();
            self.buf.push(b'|');
        }
    }
    fn contains(&self, name: &[u8]) -> bool {
        if !self.active {
            return false;
        }
        let n = name.len() + 2;
        self.buf.windows(n).any(|w| w[0] == b'|' && w[n - 1] == b'|' && &w[1..n - 1] == name)
    }
    fn store(&mut self, name: &[u8]) {
        if !self.active {
            self.buf.clear();
            if !self.buf.push(b'|') {
                return;
            }
            self.active = true;
        } else if self.contains(name) {
            return;
        }
        if !self.buf.extend_from(name) || !self.buf.push(b'|') {
            // as glibc when realloc fails: the list is dropped
            self.free();
        }
    }
    fn free(&mut self) {
        *self = Blacklist::new();
    }
}

// ---------------------------------------------------------------- the *_compat sources

/// The first source of a `*_compat` database line: glibc's `__nss_lookup_function` on it is all the compat module uses.
#[derive(Clone, Copy)]
enum Back {
    None,
    Files,
    Module(nssmod::Source),
}

fn backend(db: &[u8]) -> Back {
    let o = nssmod::order(db);
    if o.n == 0 {
        return Back::None;
    }
    let s = o.e[0];
    if s.is(b"files") {
        Back::Files
    } else if s.is_builtin() {
        Back::None
    } else {
        Back::Module(s)
    }
}

impl Back {
    fn module_fn(&self, func: &[u8]) -> usize {
        match self {
            Back::Module(s) => nssmod::function(s.name(), func),
            _ => 0,
        }
    }
}

type GetNam<E> = extern "C" fn(*const c_char, *mut E, *mut c_char, usize, *mut c_int) -> c_int;
type GetId<E> = extern "C" fn(u32, *mut E, *mut c_char, usize, *mut c_int) -> c_int;
type GetEnt<E> = extern "C" fn(*mut E, *mut c_char, usize, *mut c_int) -> c_int;
type SetEnt = extern "C" fn(c_int) -> c_int;
type EndEnt = extern "C" fn() -> c_int;
// The module functions are typed as plain (safe) `extern "C" fn` pointers: each is made by one transmute of the address
// nssmod found for that name (the transmute's SAFETY says why the type is right) and called right there with valid
// arguments, never kept.

/// One of the three entry types, with what the compat rules need of it.
trait Kind: Sized + 'static {
    /// The `*_compat` database, the file, the module function names.
    const DB: &'static [u8];
    const FILE: &'static [u8];
    const SET: &'static [u8];
    const GETNAM: &'static [u8];
    const GETENT: &'static [u8];
    const END: &'static [u8];
    fn zero() -> Self;
    fn name(&self) -> *const c_char;
    /// The next line of the `files` parser into `r` and `buf`.
    fn next(f: &mut CompatFile, r: &mut Out<Self>, buf: &mut CBuf) -> c_int;
    /// The state the `files` source of the `*_compat` database keeps for its enumeration. Rule: touched only under
    /// FILES_LOCK.
    fn files_slot() -> &'static SyncCell<Option<CompatFile>>;
}

impl Kind for Passwd {
    const DB: &'static [u8] = b"passwd_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::PASSWD_FILE;
    const SET: &'static [u8] = b"setpwent";
    const GETNAM: &'static [u8] = b"getpwnam_r";
    const GETENT: &'static [u8] = b"getpwent_r";
    const END: &'static [u8] = b"endpwent";
    fn zero() -> Passwd {
        Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() }
    }
    fn name(&self) -> *const c_char {
        self.pw_name
    }
    fn next(f: &mut CompatFile, r: &mut Out<Passwd>, buf: &mut CBuf) -> c_int {
        // SAFETY: a valid entry, and the buffer's `len` writable bytes (CBuf's invariant).
        r.fill(|e| unsafe { f.next_passwd(e, buf.ptr().cast(), buf.len()) })
    }
    fn files_slot() -> &'static SyncCell<Option<CompatFile>> {
        static S: SyncCell<Option<CompatFile>> = SyncCell::new(None);
        &S
    }
}

impl Kind for Group {
    const DB: &'static [u8] = b"group_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::GROUP_FILE;
    const SET: &'static [u8] = b"setgrent";
    const GETNAM: &'static [u8] = b"getgrnam_r";
    const GETENT: &'static [u8] = b"getgrent_r";
    const END: &'static [u8] = b"endgrent";
    fn zero() -> Group {
        Group { gr_name: null_mut(), gr_passwd: null_mut(), gr_gid: 0, gr_mem: null_mut() }
    }
    fn name(&self) -> *const c_char {
        self.gr_name
    }
    fn next(f: &mut CompatFile, r: &mut Out<Group>, buf: &mut CBuf) -> c_int {
        // SAFETY: as for Passwd.
        r.fill(|e| unsafe { f.next_group(e, buf.ptr().cast(), buf.len()) })
    }
    fn files_slot() -> &'static SyncCell<Option<CompatFile>> {
        static S: SyncCell<Option<CompatFile>> = SyncCell::new(None);
        &S
    }
}

impl Kind for Spwd {
    const DB: &'static [u8] = b"shadow_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::SHADOW_FILE;
    const SET: &'static [u8] = b"setspent";
    const GETNAM: &'static [u8] = b"getspnam_r";
    const GETENT: &'static [u8] = b"getspent_r";
    const END: &'static [u8] = b"endspent";
    fn zero() -> Spwd {
        Spwd { sp_namp: null_mut(), sp_pwdp: null_mut(), sp_lstchg: 0, sp_min: 0, sp_max: 0, sp_warn: -1, sp_inact: -1, sp_expire: -1, sp_flag: !0 }
    }
    fn name(&self) -> *const c_char {
        self.sp_namp
    }
    fn next(f: &mut CompatFile, r: &mut Out<Spwd>, buf: &mut CBuf) -> c_int {
        // SAFETY: as for Passwd.
        r.fill(|e| unsafe { f.next_spwd(e, buf.ptr().cast(), buf.len()) })
    }
    fn files_slot() -> &'static SyncCell<Option<CompatFile>> {
        static S: SyncCell<Option<CompatFile>> = SyncCell::new(None);
        &S
    }
}

/// Open `E::FILE` (one of rusty-libc-util's NUL-terminated path constants).
fn open_file<E: Kind>() -> Result<CompatFile, c_int> {
    // SAFETY: the path constants of rusty-libc-util's pwd module are NUL-terminated.
    unsafe { CompatFile::open(E::FILE) }
}

static FILES_LOCK: RawMutex = RawMutex::new();

/// Run `f` on `E`'s files-source state under FILES_LOCK.
fn with_files_slot<E: Kind, R>(f: impl FnOnce(&mut Option<CompatFile>) -> R) -> R {
    FILES_LOCK.lock_always();
    // SAFETY: FILES_LOCK is held (the slot's rule) and `f` does not reach the slot again.
    let r = unsafe { E::files_slot().with_unsync(f) };
    FILES_LOCK.unlock_always();
    r
}

fn fail_open(e: c_int) -> c_int {
    errno::set(e);
    if e == EAGAIN { TRYAGAIN } else { UNAVAIL }
}

/// The `files` source of a `*_compat` database (glibc's `_nss_files_*` functions): the by-name lookup skips a key that starts
/// with `+` or `-`, the by-id one entries whose name does.
fn files_lookup<E: Kind>(res: &mut Out<E>, buf: &mut CBuf, errnop: &mut c_int, matches: &dyn Fn(&Out<E>) -> bool) -> c_int {
    let mut f = match open_file::<E>() {
        Ok(f) => f,
        Err(e) => {
            *errnop = e;
            return fail_open(e);
        }
    };
    let st = loop {
        let st = E::next(&mut f, res, buf);
        if st != SUCCESS || matches(res) {
            break st;
        }
    };
    f.close();
    if st == TRYAGAIN || st == UNAVAIL {
        *errnop = errno::get();
    }
    st
}

/// The functions of the first source of `E::DB`.
struct Impl<E: Kind> {
    back: Back,
    _e: core::marker::PhantomData<E>,
}

impl<E: Kind> Impl<E> {
    fn get() -> Impl<E> {
        Impl { back: backend(E::DB), _e: core::marker::PhantomData }
    }
    fn has(&self, func: &[u8]) -> bool {
        match self.back {
            Back::None => false,
            Back::Files => true,
            Back::Module(_) => self.back.module_fn(func) != 0,
        }
    }
    fn set(&self, stay: c_int) -> Option<c_int> {
        match self.back {
            Back::None => None,
            Back::Files => Some(with_files_slot::<E, _>(|slot| match slot {
                Some(f) => {
                    f.rewind();
                    SUCCESS
                }
                None => match open_file::<E>() {
                    Ok(f) => {
                        *slot = Some(f);
                        SUCCESS
                    }
                    Err(e) => fail_open(e),
                },
            })),
            Back::Module(_) => {
                let f = self.back.module_fn(E::SET);
                if f == 0 {
                    return None;
                }
                // SAFETY: `f` is the module's `_nss_NAME_set*ent`, whose C type this is (glibc's NSS module ABI); it takes
                // a plain int, so any call is fine.
                let f = unsafe { core::mem::transmute::<usize, SetEnt>(f) };
                Some(f(stay))
            }
        }
    }
    fn end(&self) -> bool {
        match self.back {
            Back::None => false,
            Back::Files => {
                with_files_slot::<E, _>(|slot| {
                    if let Some(f) = slot.take() {
                        f.close();
                    }
                });
                true
            }
            Back::Module(_) => {
                let f = self.back.module_fn(E::END);
                if f == 0 {
                    return false;
                }
                // SAFETY: `f` is the module's `_nss_NAME_end*ent`, whose C type this is; no arguments.
                let f = unsafe { core::mem::transmute::<usize, EndEnt>(f) };
                f();
                true
            }
        }
    }
    /// By name. `name` may point into `buf` (see Key).
    fn getnam(&self, name: Key, res: &mut Out<E>, buf: &mut CBuf, errnop: &mut c_int) -> c_int {
        match self.back {
            Back::None => UNAVAIL,
            // glibc's files source tests the key on every line, as it is then: the compat module hands it keys that point
            // into the buffer the lines are read into (`+name` lines, netgroup members), which the first line overwrites, so
            // those lookups find nothing (observed with glibc 2.43); the key is used the same way here
            Back::Files => files_lookup::<E>(res, buf, errnop, &|e: &Out<E>| !matches!(name.first(), b'+' | b'-') && name.live_eq(e.name())),
            Back::Module(_) => match self.back.module_fn(E::GETNAM) {
                0 => UNAVAIL,
                f => {
                    // SAFETY: `f` is the module's `_nss_NAME_get*nam_r`, whose C type this is; it is called once, below,
                    // with a C string key, a valid entry, the buffer's writable bytes and a valid errno pointer.
                    let f = unsafe { core::mem::transmute::<usize, GetNam<E>>(f) };
                    res.fill(|e| f(name.ptr(), e, buf.ptr(), buf.len(), errnop))
                }
            },
        }
    }
    fn getid(&self, func: &[u8], id: u32, res: &mut Out<E>, buf: &mut CBuf, errnop: &mut c_int, id_of: fn(&E) -> u32) -> c_int {
        match self.back {
            Back::None => UNAVAIL,
            Back::Files => files_lookup::<E>(res, buf, errnop, &|e: &Out<E>| id_of(e.get()) == id && !matches!(e.name().first(), Some(b'+' | b'-'))),
            Back::Module(_) => match self.back.module_fn(func) {
                0 => UNAVAIL,
                f => {
                    // SAFETY: `f` is the module's `_nss_NAME_get*id_r`, whose C type this is; called once, below, with a
                    // valid entry, the buffer's writable bytes and a valid errno pointer.
                    let f = unsafe { core::mem::transmute::<usize, GetId<E>>(f) };
                    res.fill(|e| f(id, e, buf.ptr(), buf.len(), errnop))
                }
            },
        }
    }
    fn getent(&self, res: &mut Out<E>, buf: &mut CBuf, errnop: &mut c_int) -> c_int {
        match self.back {
            Back::None => UNAVAIL,
            Back::Files => {
                let st = with_files_slot::<E, _>(|slot| {
                    if slot.is_none() {
                        match open_file::<E>() {
                            Ok(f) => *slot = Some(f),
                            Err(e) => return Err(e),
                        }
                    }
                    let Some(f) = slot.as_mut() else { return Ok(UNAVAIL) };
                    Ok(E::next(f, res, buf))
                });
                match st {
                    Err(e) => {
                        *errnop = e;
                        fail_open(e)
                    }
                    Ok(st) => {
                        if st == TRYAGAIN || st == UNAVAIL {
                            *errnop = errno::get();
                        }
                        st
                    }
                }
            }
            // (glibc calls a missing getgrent_r of the source after a split group in initgroups; here it is UNAVAIL)
            Back::Module(_) => match self.back.module_fn(E::GETENT) {
                0 => UNAVAIL,
                f => {
                    // SAFETY: `f` is the module's `_nss_NAME_get*ent_r`, whose C type this is; called once, below, with a
                    // valid entry, the buffer's writable bytes and a valid errno pointer.
                    let f = unsafe { core::mem::transmute::<usize, GetEnt<E>>(f) };
                    res.fill(|e| f(e, buf.ptr(), buf.len(), errnop))
                }
            },
        }
    }
}

// ---------------------------------------------------------------- passwd and shadow (the same rules)

/// The fields a `+` line can override (glibc's `copy_pwd_changes` / `copy_spwd_changes`), for [`Plus`].
trait Changes: Kind {
    /// compat-spwd.c checks a failed `setspent` of the source when it expands a netgroup, compat-pwd.c when it expands `+`.
    const SHADOW: bool;
    /// Each overridable string field, in glibc's order (at most four).
    fn each_str(&mut self, f: &mut dyn FnMut(&mut *mut c_char));
    /// Copy the numeric fields of `src` that differ from the defaults (none for passwd).
    fn copy_nums(&mut self, src: &Self);
}

impl Changes for Passwd {
    const SHADOW: bool = false;
    fn each_str(&mut self, f: &mut dyn FnMut(&mut *mut c_char)) {
        f(&mut self.pw_passwd);
        f(&mut self.pw_gecos);
        f(&mut self.pw_dir);
        f(&mut self.pw_shell);
    }
    fn copy_nums(&mut self, _src: &Passwd) {}
}

impl Changes for Spwd {
    const SHADOW: bool = true;
    fn each_str(&mut self, f: &mut dyn FnMut(&mut *mut c_char)) {
        f(&mut self.sp_pwdp);
    }
    fn copy_nums(&mut self, src: &Spwd) {
        if src.sp_lstchg != 0 {
            self.sp_lstchg = src.sp_lstchg;
        }
        if src.sp_min != 0 {
            self.sp_min = src.sp_min;
        }
        if src.sp_max != 0 {
            self.sp_max = src.sp_max;
        }
        if src.sp_warn != -1 {
            self.sp_warn = src.sp_warn;
        }
        if src.sp_inact != -1 {
            self.sp_inact = src.sp_inact;
        }
        if src.sp_expire != -1 {
            self.sp_expire = src.sp_expire;
        }
        if src.sp_flag != !0 {
            self.sp_flag = src.sp_flag;
        }
    }
}

/// glibc's `ent_t` of compat-pwd.c / compat-spwd.c.
struct PwEnt<E: Changes> {
    netgroup: bool,
    first: bool,
    files: bool,
    setent_status: c_int,
    stream: Option<CompatFile>,
    bl: Blacklist,
    /// The overriding fields of the `+` or `+@netgroup` line being expanded.
    pwd: Plus<E>,
    ng: PrivNetgr,
}

impl<E: Changes> PwEnt<E> {
    fn new() -> PwEnt<E> {
        PwEnt { netgroup: false, first: false, files: true, setent_status: SUCCESS, stream: None, bl: Blacklist::new(), pwd: Plus::new(), ng: PrivNetgr::new() }
    }
}

fn internal_setent<E: Changes>(ent: &mut PwEnt<E>, im: &Impl<E>, stayopen: c_int, needent: bool) -> c_int {
    let mut status = SUCCESS;
    if ent.netgroup {
        ent.ng.end();
    }
    ent.first = false;
    ent.netgroup = false;
    ent.files = true;
    ent.setent_status = SUCCESS;
    ent.bl.reset();
    match &mut ent.stream {
        Some(f) => f.rewind(),
        None => match open_file::<E>() {
            Ok(f) => ent.stream = Some(f),
            Err(e) => status = fail_open(e),
        },
    }
    ent.pwd = Plus::new();
    if needent && status == SUCCESS && let Some(st) = im.set(stayopen) {
        ent.setent_status = st;
    }
    status
}

fn internal_endent<E: Changes>(ent: &mut PwEnt<E>) {
    if let Some(f) = ent.stream.take() {
        f.close();
    }
    if ent.netgroup {
        ent.ng.end();
    }
    ent.first = false;
    ent.netgroup = false;
    ent.bl.reset();
    ent.pwd = Plus::new();
}

/// `internal_endpwent_noerror` for a lookup's own state (its blacklist is freed too).
fn end_local<E: Changes>(ent: &mut PwEnt<E>) {
    let saved = errno::get();
    internal_endent(ent);
    ent.bl.free();
    errno::set(saved);
}

/// The strings of a netgroup triple (NULL or C strings in the buffer the reader was lent, or in the netgroup state; valid
/// until the next read).
fn triple_strs<'a>(t: [*mut c_char; 2]) -> [Option<&'a CStr>; 2] {
    // SAFETY: PrivNetgr::get returns NULL or C strings (its `Triple`), which stay until the next get or end (the callers
    // use them before either).
    t.map(|p| unsafe { rusty_libc_core::ffi::cstr(p) })
}

/// `getpwent_next_nss_netgr`: the next user of the netgroup being expanded (opened here when `group` is given and this is the
/// first call), fetched by name from the `*_compat` source; RETURN when the netgroup is done.
fn next_netgr<E: Changes>(name: Option<&[u8]>, result: &mut Out<E>, ent: &mut PwEnt<E>, im: &Impl<E>, group: Option<&CStr>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(E::GETNAM) {
        return UNAVAIL;
    }
    if E::SHADOW && ent.setent_status != SUCCESS {
        return ent.setent_status;
    }
    if ent.first {
        ent.ng = PrivNetgr::new();
        ent.ng.set(group.unwrap_or_default());
        ent.first = false;
    }
    // this call's own view: it shortens it for each member it looks up, as glibc's `buflen -= p2len`
    let mut buffer = buffer.sub();
    loop {
        result.forget();
        let Some((_host, user, domain)) = ent.ng.get(buffer.lend()) else {
            ent.ng.end();
            ent.netgroup = false;
            ent.pwd = Plus::new();
            return RETURN;
        };
        let [user_c, domain_c] = triple_strs([user, domain]);
        let Some(user_c) = user_c else { continue };
        let user_b = user_c.to_bytes();
        if user_b.first() == Some(&b'-') {
            continue;
        }
        if let Some(d) = domain_c
            && d.to_bytes() != DEFAULT_DOMAIN
        {
            continue;
        }
        if let Some(n) = name
            && user_b != n
        {
            continue;
        }
        let Some(tail) = buffer.take_tail(ent.pwd.need()) else {
            *errnop = ERANGE;
            return TRYAGAIN;
        };
        // (the member's name is in `buffer`, which the lookup reuses: as in glibc)
        if im.getnam(Key::of(user_c), result, &mut buffer, errnop) != SUCCESS {
            continue;
        }
        let rn = result.name();
        if !ent.bl.contains(rn) {
            ent.bl.store(rn);
            ent.pwd.apply(result, tail);
            break;
        }
    }
    SUCCESS
}

/// `getpwent_next_nss`: the next entry of the `*_compat` source (for a lone `+`), skipping blacklisted names.
fn next_nss<E: Changes>(result: &mut Out<E>, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(E::GETENT) {
        return UNAVAIL;
    }
    if !E::SHADOW && ent.setent_status != SUCCESS {
        return ent.setent_status;
    }
    let mut buffer = buffer.sub();
    let Some(tail) = buffer.take_tail(ent.pwd.need()) else {
        *errnop = ERANGE;
        return TRYAGAIN;
    };
    if !E::SHADOW {
        ent.first = false;
    }
    loop {
        let st = im.getent(result, &mut buffer, errnop);
        if st != SUCCESS {
            return st;
        }
        if !ent.bl.contains(result.name()) {
            break;
        }
    }
    ent.pwd.apply(result, tail);
    SUCCESS
}

/// `getpwnam_plususer`: the user `name` from the `*_compat` source with the fields of the `+` line in `result` laid over it.
fn nam_plususer<E: Changes>(name: Key, result: &mut Out<E>, ent: &PwEnt<E>, im: &Impl<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(E::GETNAM) {
        return UNAVAIL;
    }
    let pwd = Plus::of(result);
    let mut buffer = buffer.sub();
    let Some(tail) = buffer.take_tail(pwd.need()) else {
        *errnop = ERANGE;
        return TRYAGAIN;
    };
    let st = im.getnam(name, result, &mut buffer, errnop);
    if st != SUCCESS {
        return st;
    }
    if ent.bl.contains(result.name()) {
        return NOTFOUND;
    }
    pwd.apply(result, tail);
    SUCCESS
}

/// `getpwent_next_file`: the next entry of the file, expanding the compat lines.
fn next_file<E: Changes>(result: &mut Out<E>, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    loop {
        let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
        let pos = stream.tell();
        let st = E::next(stream, result, buffer);
        if st == NOTFOUND {
            return NOTFOUND;
        }
        if st != SUCCESS {
            *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
            return st;
        }
        if !matches!(result.name().first(), Some(b'+' | b'-')) {
            break; // a real entry
        }
        // a copy: the lookups below reuse the buffer the name is in
        let nm = Name::of(result.name());
        let nm = nm.bytes();
        match nm {
            [b'-', b'@', _, ..] => {
                // -@netgroup: its users are hidden
                let mut buf2 = [0u8; 1024];
                let mut ng = PrivNetgr::new();
                ng.set(Name::of(&nm[2..]).cstr());
                while let Some((_, user, _)) = ng.get(&mut buf2) {
                    if let [Some(u), _] = triple_strs([user, null_mut()])
                        && u.to_bytes().first() != Some(&b'-')
                    {
                        ent.bl.store(u.to_bytes());
                    }
                }
                ng.end();
            }
            [b'+', b'@', _, ..] => {
                // +@netgroup: its users, from the *_compat source
                ent.netgroup = true;
                ent.first = true;
                ent.pwd = Plus::of(result);
                let g = Name::of(&nm[2..]);
                let st = next_netgr(None, result, ent, im, Some(g.cstr()), buffer, errnop);
                if st == RETURN {
                    continue;
                }
                return st;
            }
            [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
            [b'+', c, ..] if *c != b'@' => {
                // +name: that user (once)
                // the name is kept for the blacklist; the lookup gets the copy in the buffer, as in glibc
                let st = nam_plususer(result.key(1), result, ent, im, buffer, errnop);
                ent.bl.store(&nm[1..]);
                if st == SUCCESS {
                    break;
                } else if st == RETURN || st == NOTFOUND {
                    continue;
                } else {
                    if st == TRYAGAIN {
                        stream_seek(ent, pos);
                        *errnop = ERANGE;
                    }
                    return st;
                }
            }
            [b'+'] => {
                // +: every user left
                ent.files = false;
                ent.first = true;
                ent.pwd = Plus::of(result);
                return next_nss(result, ent, im, buffer, errnop);
            }
            _ => {}
        }
    }
    SUCCESS
}

fn stream_seek<E: Changes>(ent: &mut PwEnt<E>, pos: i64) {
    if let Some(s) = ent.stream.as_mut() {
        s.seek(pos);
    }
}

fn internal_getent<E: Changes>(pw: &mut Out<E>, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if ent.netgroup {
        let st = next_netgr(None, pw, ent, im, None, buffer, errnop);
        if st == RETURN { next_file(pw, ent, im, buffer, errnop) } else { st }
    } else if ent.files {
        next_file(pw, ent, im, buffer, errnop)
    } else {
        next_nss(pw, ent, im, buffer, errnop)
    }
}

/// `innetgr(group, NULL, user, NULL)`.
fn user_in_netgroup(group: &Name, user: &[u8]) -> bool {
    in_netgroup(group.cstr(), None, Some(user), None)
}

/// `internal_getpwnam_r`: `name` through the file's compat lines.
fn internal_getnam<E: Changes>(name: &CStr, result: &mut Out<E>, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    let key = name.to_bytes();
    loop {
        let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
        let st = E::next(stream, result, buffer);
        if st == NOTFOUND {
            return NOTFOUND;
        }
        if st != SUCCESS {
            *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
            return st;
        }
        if !matches!(result.name().first(), Some(b'+' | b'-')) {
            if result.name() == key {
                return SUCCESS;
            }
            continue;
        }
        let nm = Name::of(result.name());
        let nm = nm.bytes();
        match nm {
            [b'-', b'@', _, ..] => {
                if user_in_netgroup(&Name::of(&nm[2..]), key) {
                    return NOTFOUND;
                }
                continue;
            }
            [b'+', b'@', _, ..] => {
                if user_in_netgroup(&Name::of(&nm[2..]), key) {
                    let st = nam_plususer(Key::of(name), result, ent, im, buffer, errnop);
                    if st == RETURN {
                        continue;
                    }
                    return st;
                }
                continue;
            }
            [b'-', c, ..] if *c != b'@' => {
                if &nm[1..] == key {
                    return NOTFOUND;
                }
                continue;
            }
            [b'+', c, ..] if *c != b'@' => {
                if key == &nm[1..] {
                    let st = nam_plususer(Key::of(name), result, ent, im, buffer, errnop);
                    return if st == RETURN { NOTFOUND } else { st };
                }
            }
            [b'+'] => {
                let st = nam_plususer(Key::of(name), result, ent, im, buffer, errnop);
                if st == SUCCESS {
                    break;
                }
                return if st == RETURN { NOTFOUND } else { st };
            }
            _ => {}
        }
    }
    SUCCESS
}

/// The global enumeration state of passwd and shadow (glibc's `ext_ent`), each with its lock. Rule: `ent` is touched only
/// in [`Global::with`], under `lock`.
struct Global<E: Changes> {
    lock: RawMutex,
    ent: SyncCell<Option<PwEnt<E>>>,
}

static PW_EXT: Global<Passwd> = Global { lock: RawMutex::new(), ent: SyncCell::new(None) };
static SP_EXT: Global<Spwd> = Global { lock: RawMutex::new(), ent: SyncCell::new(None) };

impl<E: Changes> Global<E> {
    /// Run `f` on the state under the lock.
    fn with<R>(&self, f: impl FnOnce(&mut PwEnt<E>) -> R) -> R {
        self.lock.lock_always();
        // SAFETY: `lock` is held (the rule), and `f` (the compat code and the modules it calls) does not reach this state
        // again: a module calling back into the compat source would deadlock on `lock` first, as in glibc.
        let r = unsafe { self.ent.with_unsync(|e| f(e.get_or_insert_with(PwEnt::new))) };
        self.lock.unlock_always();
        r
    }
}

fn compat_setent<E: Changes>(g: &Global<E>, stayopen: c_int) -> c_int {
    let im = Impl::<E>::get();
    g.with(|e| internal_setent(e, &im, stayopen, true))
}

fn compat_endent<E: Changes>(g: &Global<E>) -> c_int {
    let im = Impl::<E>::get();
    g.with(|e| {
        if im.has(E::END) {
            im.end();
        }
        internal_endent(e);
        SUCCESS
    })
}

fn compat_getent<E: Changes>(g: &Global<E>, res: &mut Out<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    let im = Impl::<E>::get();
    g.with(|e| {
        let mut st = SUCCESS;
        if e.stream.is_none() {
            st = internal_setent(e, &im, 1, true);
        }
        if st == SUCCESS {
            st = internal_getent(res, e, &im, buffer, errnop);
        }
        st
    })
}

fn compat_getnam<E: Changes>(name: &CStr, res: &mut Out<E>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if matches!(name.to_bytes().first(), Some(b'-' | b'+')) {
        return NOTFOUND;
    }
    let im = Impl::<E>::get();
    let mut ent = PwEnt::<E>::new();
    let mut st = internal_setent(&mut ent, &im, 0, false);
    if st == SUCCESS {
        st = internal_getnam(name, res, &mut ent, &im, buffer, errnop);
    }
    end_local(&mut ent);
    st
}

// ---------------------------------------------------------------- getpwuid

/// `getpwuid_plususer`: the user `uid` from `passwd_compat`, with the fields of the `+` line in `result` laid over it; RETURN
/// when the source has no such user.
fn uid_plususer(uid: Uid, result: &mut Out<Passwd>, im: &Impl<Passwd>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(b"getpwuid_r") {
        return UNAVAIL;
    }
    let pwd = Plus::of(result);
    let mut buffer = buffer.sub();
    let Some(tail) = buffer.take_tail(pwd.need()) else {
        *errnop = ERANGE;
        return TRYAGAIN;
    };
    let st = im.getid(b"getpwuid_r", uid, result, &mut buffer, errnop, |e| e.pw_uid);
    if st == SUCCESS {
        pwd.apply(result, tail);
        return SUCCESS;
    }
    RETURN
}

fn internal_getpwuid(uid: Uid, result: &mut Out<Passwd>, ent: &mut PwEnt<Passwd>, im: &Impl<Passwd>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    let innetgr_user = |g: &Name, result: &Out<Passwd>| user_in_netgroup(g, result.name());
    loop {
        let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
        let st = Passwd::next(stream, result, buffer);
        if st == NOTFOUND {
            return NOTFOUND;
        }
        if st != SUCCESS {
            *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
            return st;
        }
        if !matches!(result.name().first(), Some(b'+' | b'-')) {
            if result.get().pw_uid == uid {
                return SUCCESS;
            }
            continue;
        }
        let nm = Name::of(result.name());
        let nm = nm.bytes();
        match nm {
            [b'-', b'@', _, ..] => {
                let g = Name::of(&nm[2..]);
                let st = uid_plususer(uid, result, im, buffer, errnop);
                if st == SUCCESS && innetgr_user(&g, result) {
                    return NOTFOUND;
                }
                continue;
            }
            [b'+', b'@', _, ..] => {
                let g = Name::of(&nm[2..]);
                let st = uid_plususer(uid, result, im, buffer, errnop);
                if st == RETURN {
                    continue;
                }
                if st == SUCCESS {
                    if innetgr_user(&g, result) {
                        return SUCCESS;
                    }
                } else {
                    return st;
                }
                continue;
            }
            [b'-', c, ..] if *c != b'@' => {
                // glibc tests the user name as a netgroup name here
                let g = Name::of(&nm[1..]);
                let st = uid_plususer(uid, result, im, buffer, errnop);
                if st == SUCCESS && innetgr_user(&g, result) {
                    return NOTFOUND;
                }
                continue;
            }
            [b'+', c, ..] if *c != b'@' => {
                let st = uid_plususer(uid, result, im, buffer, errnop);
                if st == RETURN {
                    continue;
                }
                if st == SUCCESS {
                    if &nm[1..] == result.name() {
                        return SUCCESS;
                    }
                } else {
                    return st;
                }
                continue;
            }
            [b'+'] => {
                let st = uid_plususer(uid, result, im, buffer, errnop);
                if st == SUCCESS {
                    break;
                }
                return if st == RETURN { NOTFOUND } else { st };
            }
            _ => {}
        }
    }
    SUCCESS
}

// ---------------------------------------------------------------- the exported passwd and shadow functions

/// The C arguments of a `_nss_compat_get*_r` (glibc does not check the pointers for NULL either).
///
/// # Safety
/// `res` and `errnop` are valid, aligned and not otherwise accessed during the call; `buffer` is writable for `buflen`
/// bytes and not otherwise accessed during the call.
unsafe fn r_args<'a, E: Kind>(res: *mut E, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> (Out<'a, E>, CBuf<'a>, &'a mut c_int) {
    // SAFETY: the contract.
    let res = Out::new(unsafe { &mut *res });
    // SAFETY: the contract.
    let buf = unsafe { CBuf::new(buffer, buflen) };
    // SAFETY: the contract.
    (res, buf, unsafe { &mut *errnop })
}

/// # Safety
/// As glibc's `_nss_compat_setpwent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setpwent(stayopen: c_int) -> c_int {
    compat_setent(&PW_EXT, stayopen)
}

/// # Safety
/// As glibc's `_nss_compat_endpwent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endpwent() -> c_int {
    compat_endent(&PW_EXT)
}

/// # Safety
/// As glibc's `_nss_compat_getpwent_r`: valid result, buffer and errno pointers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwent_r(pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: valid pointers (the contract).
    let (mut pwd, mut buf, errnop) = unsafe { r_args(pwd, buffer, buflen, errnop) };
    compat_getent(&PW_EXT, &mut pwd, &mut buf, errnop)
}

/// # Safety
/// As glibc's `_nss_compat_getpwnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwnam_r(name: *const c_char, pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: `name` is a C string (the contract).
    let name = unsafe { rusty_libc_core::ffi::cstr_nonnull(name) };
    // SAFETY: valid pointers (the contract).
    let (mut pwd, mut buf, errnop) = unsafe { r_args(pwd, buffer, buflen, errnop) };
    compat_getnam(name, &mut pwd, &mut buf, errnop)
}

/// # Safety
/// As glibc's `_nss_compat_getpwuid_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwuid_r(uid: Uid, pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: valid pointers (the contract).
    let (mut pwd, mut buf, errnop) = unsafe { r_args(pwd, buffer, buflen, errnop) };
    let im = Impl::<Passwd>::get();
    let mut ent = PwEnt::<Passwd>::new();
    let mut st = internal_setent(&mut ent, &im, 0, false);
    if st == SUCCESS {
        st = internal_getpwuid(uid, &mut pwd, &mut ent, &im, &mut buf, errnop);
    }
    end_local(&mut ent);
    st
}

/// # Safety
/// As glibc's `_nss_compat_setspent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setspent(stayopen: c_int) -> c_int {
    compat_setent(&SP_EXT, stayopen)
}

/// # Safety
/// As glibc's `_nss_compat_endspent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endspent() -> c_int {
    compat_endent(&SP_EXT)
}

/// # Safety
/// As glibc's `_nss_compat_getspent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getspent_r(sp: *mut Spwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: valid pointers (the contract).
    let (mut sp, mut buf, errnop) = unsafe { r_args(sp, buffer, buflen, errnop) };
    compat_getent(&SP_EXT, &mut sp, &mut buf, errnop)
}

/// # Safety
/// As glibc's `_nss_compat_getspnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getspnam_r(name: *const c_char, sp: *mut Spwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: `name` is a C string (the contract).
    let name = unsafe { rusty_libc_core::ffi::cstr_nonnull(name) };
    // SAFETY: valid pointers (the contract).
    let (mut sp, mut buf, errnop) = unsafe { r_args(sp, buffer, buflen, errnop) };
    compat_getnam(name, &mut sp, &mut buf, errnop)
}

// ---------------------------------------------------------------- group

/// glibc's `ent_t` of compat-grp.c.
struct GrEnt {
    files: bool,
    setent_status: c_int,
    stream: Option<CompatFile>,
    bl: Blacklist,
}

impl GrEnt {
    const fn new() -> GrEnt {
        GrEnt { files: true, setent_status: SUCCESS, stream: None, bl: Blacklist::new() }
    }
}

fn gr_setent(ent: &mut GrEnt, im: &Impl<Group>, stayopen: c_int, needent: bool) -> c_int {
    let mut status = SUCCESS;
    ent.files = true;
    ent.bl.reset();
    match &mut ent.stream {
        Some(f) => f.rewind(),
        None => match open_file::<Group>() {
            Ok(f) => ent.stream = Some(f),
            Err(e) => status = fail_open(e),
        },
    }
    // (glibc leaves setent_status as it was when there is no setgrent to call)
    if needent && status == SUCCESS && let Some(st) = im.set(stayopen) {
        ent.setent_status = st;
    }
    status
}

fn gr_endent(ent: &mut GrEnt) {
    if let Some(f) = ent.stream.take() {
        f.close();
    }
    ent.bl.reset();
}

fn gr_end_local(ent: &mut GrEnt) {
    let saved = errno::get();
    gr_endent(ent);
    ent.bl.free();
    errno::set(saved);
}

fn gr_next_nss(result: &mut Out<Group>, ent: &mut GrEnt, im: &Impl<Group>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(Group::GETENT) {
        return UNAVAIL;
    }
    if ent.setent_status != SUCCESS {
        return ent.setent_status;
    }
    loop {
        let st = im.getent(result, buffer, errnop);
        if st != SUCCESS {
            return st;
        }
        if !ent.bl.contains(result.name()) {
            return SUCCESS;
        }
    }
}

/// `getgrnam_plusgroup`.
fn plusgroup(name: Key, result: &mut Out<Group>, bl: &Blacklist, im: &Impl<Group>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    if !im.has(Group::GETNAM) {
        return UNAVAIL;
    }
    let st = im.getnam(name, result, buffer, errnop);
    if st != SUCCESS {
        return st;
    }
    if bl.contains(result.name()) {
        return NOTFOUND;
    }
    SUCCESS
}

/// Read the next line of the group file: SUCCESS with the entry, or the status to return.
fn gr_line(ent: &mut GrEnt, result: &mut Out<Group>, buffer: &mut CBuf, errnop: &mut c_int) -> (c_int, i64) {
    let Some(stream) = ent.stream.as_mut() else { return (UNAVAIL, 0) };
    let pos = stream.tell();
    let st = Group::next(stream, result, buffer);
    if st != SUCCESS && st != NOTFOUND {
        *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
    }
    (st, pos)
}

fn gr_next_file(result: &mut Out<Group>, ent: &mut GrEnt, im: &Impl<Group>, buffer: &mut CBuf, errnop: &mut c_int) -> c_int {
    loop {
        let (st, pos) = gr_line(ent, result, buffer, errnop);
        if st != SUCCESS {
            return st;
        }
        if !matches!(result.name().first(), Some(b'+' | b'-')) {
            return SUCCESS;
        }
        let nm = Name::of(result.name());
        let nm = nm.bytes();
        match nm {
            [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
            [b'+', c, ..] if *c != b'@' => {
                let st = plusgroup(result.key(1), result, &ent.bl, im, buffer, errnop);
                ent.bl.store(&nm[1..]);
                if st == SUCCESS {
                    return SUCCESS;
                } else if st == RETURN || st == NOTFOUND {
                    continue;
                } else {
                    if st == TRYAGAIN {
                        if let Some(s) = ent.stream.as_mut() {
                            s.seek(pos);
                        }
                        *errnop = ERANGE;
                        return TRYAGAIN;
                    }
                    return st;
                }
            }
            [b'+'] => {
                ent.files = false;
                return gr_next_nss(result, ent, im, buffer, errnop);
            }
            _ => {}
        }
    }
}

/// Rule: touched only in [`with_gr_ext`], under GR_LOCK.
static GR_EXT: SyncCell<GrEnt> = SyncCell::new(GrEnt::new());
static GR_LOCK: RawMutex = RawMutex::new();

fn with_gr_ext<R>(f: impl FnOnce(&mut GrEnt) -> R) -> R {
    GR_LOCK.lock_always();
    // SAFETY: GR_LOCK is held (the rule); `f` does not reach GR_EXT again (see Global::with).
    let r = unsafe { GR_EXT.with_unsync(f) };
    GR_LOCK.unlock_always();
    r
}

/// # Safety
/// As glibc's `_nss_compat_setgrent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setgrent(stayopen: c_int) -> c_int {
    let im = Impl::<Group>::get();
    with_gr_ext(|ent| gr_setent(ent, &im, stayopen, true))
}

/// # Safety
/// As glibc's `_nss_compat_endgrent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endgrent() -> c_int {
    let im = Impl::<Group>::get();
    with_gr_ext(|ent| {
        if im.has(Group::END) {
            im.end();
        }
        gr_endent(ent);
    });
    SUCCESS
}

/// # Safety
/// As glibc's `_nss_compat_getgrent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrent_r(grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: valid pointers (the contract).
    let (mut grp, mut buf, errnop) = unsafe { r_args(grp, buffer, buflen, errnop) };
    let im = Impl::<Group>::get();
    with_gr_ext(|ent| {
        let mut st = SUCCESS;
        if ent.stream.is_none() {
            st = gr_setent(ent, &im, 1, true);
        }
        if st == SUCCESS {
            st = if ent.files { gr_next_file(&mut grp, ent, &im, &mut buf, errnop) } else { gr_next_nss(&mut grp, ent, &im, &mut buf, errnop) };
        }
        st
    })
}

/// # Safety
/// As glibc's `_nss_compat_getgrnam_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrnam_r(name: *const c_char, grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: `name` is a C string (the contract).
    let name = unsafe { rusty_libc_core::ffi::cstr_nonnull(name) };
    // SAFETY: valid pointers (the contract).
    let (mut grp, mut buf, errnop) = unsafe { r_args(grp, buffer, buflen, errnop) };
    let key = name.to_bytes();
    if matches!(key.first(), Some(b'-' | b'+')) {
        return NOTFOUND;
    }
    let im = Impl::<Group>::get();
    let mut ent = GrEnt::new();
    let mut st = gr_setent(&mut ent, &im, 0, false);
    if st == SUCCESS {
        st = loop {
            let (s, _) = gr_line(&mut ent, &mut grp, &mut buf, errnop);
            if s != SUCCESS {
                break s;
            }
            let nm = grp.name();
            if !matches!(nm.first(), Some(b'+' | b'-')) {
                if nm == key {
                    break SUCCESS;
                }
                continue;
            }
            // (a -@... line too: glibc compares the rest of the name)
            let plus = nm[0] == b'+';
            let rest_is_key = &nm[1..] == key;
            if !plus {
                if nm.len() > 1 && rest_is_key {
                    break NOTFOUND;
                }
            } else if nm.len() == 1 || rest_is_key {
                // `+name` with this name, or a lone `+`
                let s = plusgroup(Key::of(name), &mut grp, &ent.bl, &im, &mut buf, errnop);
                if s != RETURN {
                    break s;
                }
            }
        };
    }
    gr_end_local(&mut ent);
    st
}

/// # Safety
/// As glibc's `_nss_compat_getgrgid_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrgid_r(gid: Gid, grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    // SAFETY: valid pointers (the contract).
    let (mut grp, mut buf, errnop) = unsafe { r_args(grp, buffer, buflen, errnop) };
    let im = Impl::<Group>::get();
    let mut ent = GrEnt::new();
    let mut st = gr_setent(&mut ent, &im, 0, false);
    if st == SUCCESS {
        st = loop {
            let (s, _) = gr_line(&mut ent, &mut grp, &mut buf, errnop);
            if s != SUCCESS {
                break s;
            }
            if !matches!(grp.name().first(), Some(b'+' | b'-')) {
                if grp.get().gr_gid == gid {
                    break SUCCESS;
                }
                continue;
            }
            let nm = Name::of(grp.name());
            let nm = nm.bytes();
            match nm {
                [b'-', _, ..] => ent.bl.store(&nm[1..]),
                [b'+', _, ..] => {
                    let s = plusgroup(grp.key(1), &mut grp, &ent.bl, &im, &mut buf, errnop);
                    ent.bl.store(&nm[1..]);
                    if s == SUCCESS && grp.get().gr_gid == gid {
                        break SUCCESS;
                    }
                }
                [b'+'] => {
                    if !im.has(b"getgrgid_r") {
                        break UNAVAIL;
                    }
                    let s = im.getid(b"getgrgid_r", gid, &mut grp, &mut buf, errnop, |e| e.gr_gid);
                    break if s == RETURN { NOTFOUND } else { s };
                }
                _ => {}
            }
        };
    }
    gr_end_local(&mut ent);
    st
}

// ---------------------------------------------------------------- initgroups

/// glibc's `ent_t` of compat-initgroups.c.
struct IgEnt {
    files: bool,
    need_endgrent: bool,
    skip_initgroups_dyn: bool,
    stream: Option<CompatFile>,
    bl: Blacklist,
}

type InitgroupsDyn = extern "C" fn(*const c_char, Gid, *mut i64, *mut i64, *mut *mut Gid, i64, *mut c_int) -> c_int;

/// A group list as the `initgroups_dyn` functions keep it: a malloc'd array of `size` entries, `start` of them used (the
/// caller's of `_nss_compat_initgroups_dyn`, or ours for a source's `initgroups_dyn`).
struct GroupList<'a> {
    start: &'a mut i64,
    size: &'a mut i64,
    groups: &'a mut *mut Gid,
    limit: i64,
}

impl GroupList<'_> {
    /// Append `gid` (growing the array as glibc's `add_group` does; silently dropped at the limit or when realloc fails).
    fn add(&mut self, gid: Gid) {
        if *self.start == *self.size {
            if self.limit > 0 && *self.size == self.limit {
                return;
            }
            let newsize = if self.limit <= 0 { 2 * *self.size } else { self.limit.min(2 * *self.size) };
            // SAFETY: `groups` is a malloc'd array (the invariant of this type).
            let ng = unsafe { rusty_libc_malloc::realloc((*self.groups).cast(), newsize as usize * size_of::<Gid>()) }.cast::<Gid>();
            if ng.is_null() {
                return;
            }
            *self.groups = ng;
            *self.size = newsize;
        }
        // SAFETY: `start < size`, the array's length in entries.
        unsafe { (*self.groups).wrapping_add(*self.start as usize).write(gid) };
        *self.start += 1;
    }
    /// The entries in use.
    fn used(&self) -> &[Gid] {
        // SAFETY: the first `start` entries of the malloc'd array are written (by add or by the source that filled it).
        unsafe { rusty_libc_core::ffi::slice(*self.groups, (*self.start).max(0) as usize) }
    }
}

/// `check_and_add_group`: add the group when `user` is a member; true when the user is not in its member list.
fn check_and_add(user: &[u8], group: Gid, gl: &mut GroupList, grp: &Out<Group>) -> bool {
    let g = grp.get().gr_gid;
    if g == group {
        return false;
    }
    if grp.has_member(user) {
        gl.add(g);
        return false;
    }
    true
}

/// The `initgroups_dyn` of the first `group_compat` source.
#[derive(Clone, Copy)]
enum Dyn {
    Files,
    Module(InitgroupsDyn),
}

fn ig_dyn(im: &Impl<Group>) -> Option<Dyn> {
    match im.back {
        Back::Files => Some(Dyn::Files),
        Back::Module(_) => {
            let f = im.back.module_fn(b"initgroups_dyn");
            // SAFETY: `f` is the module's `_nss_NAME_initgroups_dyn`, whose C type this is; ig_next_nss calls it once with
            // a C string, its own group list's pointers and a valid errno pointer.
            if f == 0 { None } else { Some(Dyn::Module(unsafe { core::mem::transmute::<usize, InitgroupsDyn>(f) })) }
        }
        Back::None => None,
    }
}

impl Dyn {
    /// Run the source's `initgroups_dyn` for `user` into `gl`.
    fn call(self, user: &CStr, group: Gid, gl: &mut GroupList, errnop: &mut c_int) -> c_int {
        match self {
            Dyn::Files => {
                // SAFETY: `user` is a C string; `gl.groups` is a malloc'd array of `*gl.size` entries (GroupList's invariant).
                unsafe { rusty_libc_util::pwd::files_initgroups_dyn(user.as_ptr(), group, gl.start, gl.size, gl.groups, gl.limit) };
                SUCCESS
            }
            Dyn::Module(f) => f(user.as_ptr(), group, gl.start, gl.size, gl.groups, gl.limit, errnop),
        }
    }
}

/// A malloc'd array of `n` group ids, freed when dropped (the list a source's `initgroups_dyn` may realloc).
struct GidArray(*mut Gid);

impl GidArray {
    fn new(n: usize) -> Option<GidArray> {
        // SAFETY: plain allocation.
        let p = unsafe { rusty_libc_malloc::malloc(n * size_of::<Gid>()) }.cast::<Gid>();
        if p.is_null() { None } else { Some(GidArray(p)) }
    }
}

impl Drop for GidArray {
    fn drop(&mut self) {
        // SAFETY: our malloc'd (possibly reallocated by the source) array, freed once.
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

/// A buffer of ours for retried lookups (glibc's scratch buffer: grown by doubling, contents not kept).
fn scratch(len: usize) -> Option<HeapVec<u8>> {
    let mut v = HeapVec::new();
    let zeros = [0u8; 1024];
    while v.len() < len {
        if !v.extend_from(&zeros[..(len - v.len()).min(zeros.len())]) {
            return None;
        }
    }
    Some(v)
}

fn ig_next_nss(ent: &mut IgEnt, im: &Impl<Group>, buffer: &mut CBuf, user: &CStr, group: Gid, gl: &mut GroupList, errnop: &mut c_int) -> c_int {
    let mut grpbuf = Group::zero();
    let mut grp = Out::new(&mut grpbuf);
    let limit = gl.limit;
    if !ent.skip_initgroups_dyn {
        let dynf = ig_dyn(im).expect("checked by the caller");
        let mut mystart: i64 = 0;
        let mut mysize: i64 = if limit <= 0 { *gl.size } else { limit };
        let Some(mut my) = GidArray::new(mysize as usize) else { return TRYAGAIN };
        let mut mine = GroupList { start: &mut mystart, size: &mut mysize, groups: &mut my.0, limit };
        if dynf.call(user, group, &mut mine, errnop) == SUCCESS {
            let mut status = NOTFOUND;
            let mut go_iter = false;
            if ent.bl.current() <= 1 {
                for &g in mine.used() {
                    gl.add(g);
                }
            } else {
                let mut tmp: Option<HeapVec<u8>> = None;
                let mut tmplen = buffer.len();
                'scan: {
                    for &g in mine.used() {
                        loop {
                            status = match tmp.as_mut() {
                                Some(t) => im.getid(b"getgrgid_r", g, &mut grp, &mut CBuf::from_slice(t), errnop, |e| e.gr_gid),
                                None => im.getid(b"getgrgid_r", g, &mut grp, buffer, errnop, |e| e.gr_gid),
                            };
                            if !(status == TRYAGAIN && *errnop == ERANGE) {
                                break;
                            }
                            if tmplen.checked_mul(2).is_none() {
                                errno::set(ENOMEM);
                                status = TRYAGAIN;
                                break 'scan;
                            }
                            tmplen = (tmplen * 2).max(1024);
                            drop(tmp.take());
                            tmp = scratch(tmplen);
                            if tmp.is_none() {
                                status = TRYAGAIN;
                                break 'scan;
                            }
                        }
                        if status != NOTFOUND {
                            if status != SUCCESS {
                                break 'scan;
                            }
                            if !ent.bl.contains(grp.name()) && check_and_add(user.to_bytes(), group, gl, &grp) {
                                if im.set(1).is_some() {
                                    ent.need_endgrent = true;
                                }
                                ent.skip_initgroups_dyn = true;
                                go_iter = true;
                                break 'scan;
                            }
                        }
                    }
                    status = NOTFOUND;
                }
            }
            drop(my);
            if !go_iter {
                return status;
            }
        }
    }
    // step through the whole group list of the source
    let mut status;
    loop {
        status = im.getent(&mut grp, buffer, errnop);
        if status != SUCCESS {
            break;
        }
        if !ent.bl.contains(grp.name()) {
            break;
        }
    }
    if status == SUCCESS {
        check_and_add(user.to_bytes(), group, gl, &grp);
    }
    status
}

fn ig_getent(ent: &mut IgEnt, im: &Impl<Group>, buffer: &mut CBuf, user: &CStr, group: Gid, gl: &mut GroupList, errnop: &mut c_int) -> c_int {
    if !ent.files {
        return ig_next_nss(ent, im, buffer, user, group, gl, errnop);
    }
    let mut grpbuf = Group::zero();
    let mut grp = Out::new(&mut grpbuf);
    loop {
        let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
        let st = Group::next(stream, &mut grp, buffer);
        if st == NOTFOUND {
            return NOTFOUND;
        }
        if st != SUCCESS {
            *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
            return st;
        }
        if !matches!(grp.name().first(), Some(b'+' | b'-')) {
            break;
        }
        let nm = Name::of(grp.name());
        let nm = nm.bytes();
        match nm {
            [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
            [b'+', c, ..] if *c != b'@' => {
                if ent.bl.contains(&nm[1..]) {
                    continue;
                }
                ent.bl.store(&nm[1..]);
                if !im.has(Group::GETNAM) {
                    return UNAVAIL;
                }
                if im.getnam(grp.key(1), &mut grp, buffer, errnop) != SUCCESS {
                    continue;
                }
                check_and_add(user.to_bytes(), group, gl, &grp);
                return SUCCESS;
            }
            [b'+'] => {
                if ig_dyn(im).is_none() || !im.has(b"getgrgid_r") {
                    if im.set(1).is_some() {
                        ent.need_endgrent = true;
                    }
                    ent.skip_initgroups_dyn = true;
                    if !im.has(Group::GETENT) {
                        return UNAVAIL;
                    }
                }
                ent.files = false;
                return ig_next_nss(ent, im, buffer, user, group, gl, errnop);
            }
            _ => {}
        }
    }
    check_and_add(user.to_bytes(), group, gl, &grp);
    SUCCESS
}

/// # Safety
/// As glibc's `_nss_compat_initgroups_dyn`: `groups` points to a malloc'd array of `*size` entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_initgroups_dyn(user: *const c_char, group: Gid, start: *mut i64, size: *mut i64, groups: *mut *mut Gid, limit: i64, errnop: *mut c_int) -> c_int {
    let im = Impl::<Group>::get();
    let mut ent = IgEnt { files: true, need_endgrent: false, skip_initgroups_dyn: false, stream: None, bl: Blacklist::new() };
    match open_file::<Group>() {
        Ok(f) => ent.stream = Some(f),
        Err(e) => return fail_open(e),
    }
    // SAFETY: `user` is a C string (the contract).
    let user = unsafe { rusty_libc_core::ffi::cstr_nonnull(user) };
    // SAFETY: valid, unaliased pointers (the contract).
    let [start, size] = [start, size].map(|p| unsafe { &mut *p });
    // SAFETY: as above; `*groups` is a malloc'd array of `*size` entries (GroupList's invariant).
    let mut gl = GroupList { start, size, groups: unsafe { &mut *groups }, limit };
    // SAFETY: as above.
    let errnop = unsafe { &mut *errnop };
    let mut len = 1024usize;
    let mut status = SUCCESS;
    match scratch(len) {
        None => status = TRYAGAIN,
        Some(mut buf) => loop {
            let st = ig_getent(&mut ent, &im, &mut CBuf::from_slice(&mut buf), user, group, &mut gl, errnop);
            if st == TRYAGAIN && *errnop == ERANGE {
                // scratch_buffer_grow: double, contents not kept
                drop(buf);
                len *= 2;
                match scratch(len) {
                    Some(b) => buf = b,
                    None => {
                        status = TRYAGAIN;
                        break;
                    }
                }
                continue;
            }
            if st != SUCCESS {
                break;
            }
        },
    }
    let saved = errno::get();
    if let Some(f) = ent.stream.take() {
        f.close();
    }
    if ent.need_endgrent {
        im.end();
    }
    ent.bl.free();
    errno::set(saved);
    status
}

// ---------------------------------------------------------------- the table rusty-libc-util asks

/// The address of `_nss_compat_<name>`, or 0 (rusty-libc-util calls it for a `compat` source).
///
/// # Safety
/// `name` points to `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_nss_compat_function(name: *const u8, len: usize) -> usize {
    // SAFETY: `name` points to `len` readable bytes (the contract).
    let n = unsafe { rusty_libc_core::ffi::bytes(name, len) };
    let f: usize = match n {
        b"setpwent" => _nss_compat_setpwent as *const () as usize,
        b"getpwent_r" => _nss_compat_getpwent_r as *const () as usize,
        b"endpwent" => _nss_compat_endpwent as *const () as usize,
        b"getpwnam_r" => _nss_compat_getpwnam_r as *const () as usize,
        b"getpwuid_r" => _nss_compat_getpwuid_r as *const () as usize,
        b"setgrent" => _nss_compat_setgrent as *const () as usize,
        b"getgrent_r" => _nss_compat_getgrent_r as *const () as usize,
        b"endgrent" => _nss_compat_endgrent as *const () as usize,
        b"getgrnam_r" => _nss_compat_getgrnam_r as *const () as usize,
        b"getgrgid_r" => _nss_compat_getgrgid_r as *const () as usize,
        b"initgroups_dyn" => _nss_compat_initgroups_dyn as *const () as usize,
        b"setspent" => _nss_compat_setspent as *const () as usize,
        b"getspent_r" => _nss_compat_getspent_r as *const () as usize,
        b"endspent" => _nss_compat_endspent as *const () as usize,
        b"getspnam_r" => _nss_compat_getspnam_r as *const () as usize,
        _ => 0,
    };
    f
}
