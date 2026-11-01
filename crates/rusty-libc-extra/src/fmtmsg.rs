//! fmtmsg.h: `fmtmsg` (the X/Open message display) and `addseverity`.
//!
//! The environment is read on the first `fmtmsg` call: MSGVERB (a list of `label`, `severity`,
//! `text`, `action`, `tag` separated by colons: the parts to print; an unknown word makes it
//! print everything) and SEV_LEVEL (`keyword,level,printstring` entries separated by colons: user
//! severities above MM_INFO). Console output goes to syslog at LOG_ERR, as in glibc.
//! Behaviour checked against glibc 2.43 by tests/c/fmtmsg_diff.c under many environments.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_int, c_long};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::sync_cell::SyncCell;

pub const MM_PRINT: c_long = 0x100;
pub const MM_CONSOLE: c_long = 0x200;
pub const MM_NOSEV: c_int = 0;
pub const MM_HALT: c_int = 1;
pub const MM_ERROR: c_int = 2;
pub const MM_WARNING: c_int = 3;
pub const MM_INFO: c_int = 4;
pub const MM_NOTOK: c_int = -1;
pub const MM_OK: c_int = 0;
pub const MM_NOMSG: c_int = 1;
pub const MM_NOCON: c_int = 4;

const LABEL_MASK: i32 = 1;
const SEVERITY_MASK: i32 = 2;
const TEXT_MASK: i32 = 4;
const ACTION_MASK: i32 = 8;
const TAG_MASK: i32 = 16;
const ALL: i32 = 31;

/// What to print (MSGVERB); all parts until the environment says otherwise.
static PRINT: AtomicI32 = AtomicI32::new(ALL);
static INIT: AtomicBool = AtomicBool::new(false);
static INIT_LOCK: RawMutex = RawMutex::new();
static LOCK: RawMutex = RawMutex::new();

/// A user-defined severity: heap node; `name` is the caller's string itself (glibc's `addseverity` keeps the pointer, it does
/// not copy: changing the string later changes the label, and freeing it is the caller's business).
struct Sev {
    severity: c_int,
    name: *const u8,
    next: *mut Sev,
}
/// The head of the user severity list. Rule: touched only under LOCK (`with_user`). Every node is a malloc'd `Sev` owned by
/// the list; a node's `name` is a C string its definer keeps valid (addseverity's contract) or a copy made here.
static USER: SyncCell<*mut Sev> = SyncCell::new(core::ptr::null_mut());

/// Run `f` on the list head with LOCK held (always taken: also before the process is marked multithreaded).
fn with_user<R>(f: impl FnOnce(&mut *mut Sev) -> R) -> R {
    LOCK.lock_always();
    // SAFETY: USER is only touched under LOCK, which is held for the call; `f` does not take LOCK.
    let r = unsafe { USER.with_unsync(f) };
    LOCK.unlock_always();
    r
}

/// A node of the list.
///
/// # Safety
/// `node` is a non-NULL node of the USER list, reached under LOCK; the reference is dropped before LOCK is released.
unsafe fn node_mut<'a>(node: *mut Sev) -> &'a mut Sev {
    // SAFETY: forwarded contract (a live malloc'd `Sev`, exclusive under LOCK).
    unsafe { &mut *node }
}

fn malloc(n: usize) -> *mut u8 {
    crate::mntent::malloc(n)
}

const BUILTIN: [(c_int, &[u8]); 4] = [(MM_HALT, b"HALT"), (MM_ERROR, b"ERROR"), (MM_WARNING, b"WARNING"), (MM_INFO, b"INFO")];

/// Add, replace (`name`: a NUL-terminated string that is kept, not copied) or remove (`None`) a user severity; false on failure.
/// A replaced or removed string is not freed (glibc's `internal_addseverity`).
///
/// # Safety
/// `name`, if given, is a C string that stays valid while it is in the list.
unsafe fn set_severity(severity: c_int, name: Option<*const u8>) -> bool {
    with_user(|head| {
        let mut link: &mut *mut Sev = head;
        while !link.is_null() {
            let node = *link;
            // SAFETY: a non-NULL link of the list, under LOCK (with_user).
            let n = unsafe { node_mut(node) };
            if n.severity == severity {
                match name {
                    Some(x) => n.name = x,
                    None => {
                        *link = n.next;
                        // SAFETY: the node is unlinked and was malloc'd by this module; freed once.
                        unsafe { rusty_libc_malloc::free(node.cast()) };
                    }
                }
                return true;
            }
            link = &mut n.next;
        }
        // not in the list: removing it fails; adding appends
        let Some(x) = name else { return false };
        let node = malloc(core::mem::size_of::<Sev>()).cast::<Sev>();
        if node.is_null() {
            return false;
        }
        // SAFETY: a fresh malloc block (aligned for any type) of the size of `Sev`.
        unsafe { node.write(Sev { severity, name: x, next: core::ptr::null_mut() }) };
        *link = node;
        true
    })
}

/// The name of a severity: built in, or user-defined (a copy); `None` if there is none.
fn severity_name(severity: c_int, out: &mut [u8; 512]) -> Option<usize> {
    for (s, n) in BUILTIN {
        if s == severity {
            out[..n.len()].copy_from_slice(n);
            return Some(n.len());
        }
    }
    with_user(|head| {
        let mut p = *head;
        while !p.is_null() {
            // SAFETY: a non-NULL node of the list, under LOCK.
            let n = unsafe { node_mut(p) };
            if n.severity == severity {
                // SAFETY: a listed name is a valid C string (the list's rule).
                let name = unsafe { rusty_libc_core::ffi::cstr_bytes(n.name) };
                // long names are cut: the caller's buffer is fixed size
                let l = name.len().min(out.len());
                out[..l].copy_from_slice(&name[..l]);
                return Some(l);
            }
            p = n.next;
        }
        None
    })
}

fn init() {
    if INIT.load(Ordering::Acquire) {
        return;
    }
    INIT_LOCK.lock_always();
    if !INIT.load(Ordering::Acquire) {
        init_from_env();
        INIT.store(true, Ordering::Release);
    }
    INIT_LOCK.unlock_always();
}

/// The value of an environment variable as bytes.
fn env(name: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: getenv is safe against concurrent environment changes (core::env); environment strings are never freed.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    // SAFETY: a non-NULL getenv result is a NUL-terminated string that is never freed.
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(|c| c.to_bytes())
}

fn init_from_env() {
    let msgverb = env(b"MSGVERB");
    let sevlevel = env(b"SEV_LEVEL");
    if let Some(mut s) = msgverb.filter(|s| !s.is_empty()) {
        let mut new_print = 0;
        const KEYWORDS: [(&[u8], i32); 5] = [(b"label", LABEL_MASK), (b"severity", SEVERITY_MASK), (b"text", TEXT_MASK), (b"action", ACTION_MASK), (b"tag", TAG_MASK)];
        while !s.is_empty() {
            let hit = KEYWORDS.iter().find(|(k, _)| s.starts_with(k) && matches!(s.get(k.len()), None | Some(b':')));
            match hit {
                Some((k, bit)) => {
                    new_print |= bit;
                    s = &s[k.len()..];
                    if s.first() == Some(&b':') {
                        s = &s[1..];
                    }
                }
                None => {
                    // an unknown word: the default (print everything)
                    new_print = ALL;
                    break;
                }
            }
        }
        PRINT.store(new_print, Ordering::Relaxed);
    }
    if let Some(mut s) = sevlevel {
        while !s.is_empty() {
            let end = s.iter().position(|&c| c == b':').unwrap_or(s.len());
            let entry = &s[..end];
            // keyword (ignored) , level , printstring
            if let Some(comma) = entry.iter().position(|&c| c == b',') {
                let rest = &entry[comma + 1..];
                // strtol needs a NUL-terminated string
                let mut buf = [0u8; 80];
                let probe = &rest[..rest.len().min(buf.len() - 1)];
                buf[..probe.len()].copy_from_slice(probe);
                let mut endp: *mut c_char = core::ptr::null_mut();
                // SAFETY: `buf` is NUL-terminated (its last byte stays 0); strtol writes `endp` into it.
                let level = unsafe { rusty_libc_stdlib::num::strtol(buf.as_ptr().cast(), &mut endp, 0) } as c_int;
                let consumed = endp.addr() - buf.as_ptr().addr();
                if consumed != 0 && consumed < probe.len() && probe[consumed] == b',' && level > MM_INFO {
                    // glibc strndup's the string for the list (and frees it only when adding fails)
                    let name = &rest[consumed + 1..];
                    let copy = malloc(name.len() + 1);
                    if !copy.is_null() {
                        // SAFETY: `copy` is a fresh malloc block of `name.len() + 1` bytes, only used through this slice here.
                        let c = unsafe { rusty_libc_core::ffi::bytes_mut(copy, name.len() + 1) };
                        c[..name.len()].copy_from_slice(name);
                        c[name.len()] = 0;
                        // SAFETY: `copy` is a C string that the list keeps (never freed while listed).
                        if !unsafe { set_severity(level, Some(copy)) } {
                            // SAFETY: the list did not take it; freed once.
                            unsafe { rusty_libc_malloc::free(copy.cast()) };
                        }
                    }
                }
            }
            s = &s[end..];
            if s.first() == Some(&b':') {
                s = &s[1..];
            }
        }
    }
}

/// The safe core of fmtmsg (the Rust API): `None` for an absent (NULL) part.
pub fn fmtmsg_r(classification: c_long, label: Option<&[u8]>, severity: c_int, text: Option<&[u8]>, action: Option<&[u8]>, tag: Option<&[u8]>) -> c_int {
    init();
    if let Some(l) = label {
        // "<at most 10 characters>:<at most 14 characters>"
        match l.iter().position(|&c| c == b':') {
            Some(c) if c <= 10 && l.len() - c - 1 <= 14 => {}
            _ => return MM_NOTOK,
        }
    }
    let mut name = [0u8; 512];
    let name_len = if severity == MM_NOSEV {
        None
    } else {
        match severity_name(severity, &mut name) {
            Some(n) => Some(n),
            None => return MM_NOTOK,
        }
    };
    let print = PRINT.load(Ordering::Relaxed);
    let label = label.filter(|_| print & LABEL_MASK != 0);
    let do_severity = print & SEVERITY_MASK != 0 && name_len.is_some();
    let text = text.filter(|_| print & TEXT_MASK != 0);
    let action = action.filter(|_| print & ACTION_MASK != 0);
    let tag = tag.filter(|_| print & TAG_MASK != 0);
    let (do_text, do_action, do_tag) = (text.is_some(), action.is_some(), tag.is_some());

    // build the message once (it is the same for stderr and the console)
    let mut msg = Msg::new();
    if let Some(l) = label {
        msg.push(l);
        if do_severity | do_text | do_action | do_tag {
            msg.push(b": ");
        }
    }
    if do_severity {
        msg.push(&name[..name_len.unwrap_or(0)]);
        if do_text | do_action | do_tag {
            msg.push(b": ");
        }
    }
    if let Some(t) = text {
        msg.push(t);
        if do_action | do_tag {
            msg.push(b"\n");
        }
    }
    if let Some(a) = action {
        msg.push(b"TO FIX: ");
        msg.push(a);
        if do_tag {
            msg.push(b"  ");
        }
    }
    if let Some(t) = tag {
        msg.push(t);
    }
    msg.push(b"\n");

    let mut result = MM_OK;
    if classification & MM_PRINT != 0 {
        let s = msg.bytes();
        // SAFETY: stderr is set at start-up and only read.
        let err = unsafe { rusty_libc_stdio::stderr.read() };
        // SAFETY: `s` is readable for its length; stderr is an open stream.
        let n = unsafe { rusty_libc_stdio::fwrite(s.as_ptr().cast(), 1, s.len(), err) };
        if n != s.len() {
            result = MM_NOMSG;
        }
    }
    if classification & MM_CONSOLE != 0 {
        crate::syslog::syslog_text(3, msg.bytes());
    }
    result
}

/// fmtmsg(3): display a message on stderr (MM_PRINT) and/or the console (MM_CONSOLE).
///
/// # Safety
/// The strings are NULL or C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmtmsg(classification: c_long, label: *const c_char, severity: c_int, text: *const c_char, action: *const c_char, tag: *const c_char) -> c_int {
    // SAFETY: each string is NULL or a C string (caller's contract).
    let part = |p: *const c_char| unsafe { rusty_libc_core::ffi::cstr(p) }.map(|c| c.to_bytes());
    fmtmsg_r(classification, part(label), severity, part(text), part(action), part(tag))
}

/// The message under construction: grows on the heap past the first 1 KB (a malloc failure drops the piece, as before).
struct Msg {
    small: [u8; 1024],
    /// The heap copy once the message outgrew `small`: a malloc block of `cap` bytes owned by this value.
    big: *mut u8,
    cap: usize,
    len: usize,
}

impl Msg {
    fn new() -> Msg {
        Msg { small: [0; 1024], big: core::ptr::null_mut(), cap: 1024, len: 0 }
    }
    /// The whole buffer (`cap` bytes).
    fn buf(&mut self) -> &mut [u8] {
        if self.big.is_null() {
            &mut self.small
        } else {
            // SAFETY: `big` is this value's malloc block of `cap` bytes, reached only through `self`.
            unsafe { rusty_libc_core::ffi::bytes_mut(self.big, self.cap) }
        }
    }
    fn push(&mut self, s: &[u8]) {
        if self.len + s.len() > self.cap {
            let ncap = (self.len + s.len()).next_power_of_two();
            let nb = malloc(ncap);
            if nb.is_null() {
                return;
            }
            let len = self.len;
            // SAFETY: `nb` is a fresh malloc block of `ncap` bytes, only used through this slice here.
            let new = unsafe { rusty_libc_core::ffi::bytes_mut(nb, ncap) };
            new[..len].copy_from_slice(&self.buf()[..len]);
            if !self.big.is_null() {
                // SAFETY: the old heap block is owned by this value and replaced right after; freed once.
                unsafe { rusty_libc_malloc::free(self.big.cast()) };
            }
            self.big = nb;
            self.cap = ncap;
        }
        let len = self.len;
        self.buf()[len..len + s.len()].copy_from_slice(s);
        self.len += s.len();
    }
    fn bytes(&mut self) -> &[u8] {
        let len = self.len;
        &self.buf()[..len]
    }
}

impl Drop for Msg {
    fn drop(&mut self) {
        if !self.big.is_null() {
            // SAFETY: the heap block is owned by this value; freed once.
            unsafe { rusty_libc_malloc::free(self.big.cast()) };
        }
    }
}

/// addseverity(3): define (or with a NULL `string` remove) a severity above MM_INFO for `fmtmsg`.
/// The built-in levels cannot be changed; failure is -1 (MM_NOTOK) without touching errno.
///
/// # Safety
/// `string` is NULL or a C string that stays valid while it is defined.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn addseverity(severity: c_int, string: *const c_char) -> c_int {
    // no init() here: the environment is read at the first fmtmsg call, so definitions made
    // before it are replaced by SEV_LEVEL's (glibc does the same)
    if severity <= MM_INFO {
        return MM_NOTOK;
    }
    // SAFETY: `string` is NULL or a C string kept valid by the caller (forwarded contract).
    let ok = unsafe { set_severity(severity, if string.is_null() { None } else { Some(string as *const u8) }) };
    if ok { MM_OK } else { MM_NOTOK }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn severities_add_replace_remove() {
        unsafe {
            assert_eq!(addseverity(0, c"X".as_ptr()), MM_NOTOK);
            assert_eq!(addseverity(4, c"X".as_ptr()), MM_NOTOK);
            assert_eq!(addseverity(-3, c"X".as_ptr()), MM_NOTOK);
            assert_eq!(addseverity(40, c"FORTY".as_ptr()), MM_OK);
            let mut n = [0u8; 512];
            assert_eq!(severity_name(40, &mut n), Some(5));
            assert_eq!(&n[..5], b"FORTY");
            assert_eq!(addseverity(40, c"QUARANTE".as_ptr()), MM_OK);
            assert_eq!(severity_name(40, &mut n), Some(8));
            assert_eq!(addseverity(40, core::ptr::null()), MM_OK);
            assert_eq!(severity_name(40, &mut n), None);
            assert_eq!(addseverity(40, core::ptr::null()), MM_NOTOK);
            assert_eq!(addseverity(2, core::ptr::null()), MM_NOTOK);
        }
    }

    #[test]
    fn label_checks() {
        unsafe {
            let t = c"t".as_ptr();
            // not a valid label: no colon, over 10 before it, over 14 after it
            assert_eq!(fmtmsg(0, c"nocolon".as_ptr(), MM_ERROR, t, core::ptr::null(), core::ptr::null()), MM_NOTOK);
            assert_eq!(fmtmsg(0, c"01234567890:x".as_ptr(), MM_ERROR, t, core::ptr::null(), core::ptr::null()), MM_NOTOK);
            assert_eq!(fmtmsg(0, c"UX:fifteen-chars-x".as_ptr(), MM_ERROR, t, core::ptr::null(), core::ptr::null()), MM_NOTOK);
            assert_eq!(fmtmsg(0, c"0123456789:x".as_ptr(), MM_ERROR, t, core::ptr::null(), core::ptr::null()), MM_OK);
            // unknown severity
            assert_eq!(fmtmsg(0, c"UX:x".as_ptr(), 77, t, core::ptr::null(), core::ptr::null()), MM_NOTOK);
        }
    }
}
