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

static PRINT: AtomicI32 = AtomicI32::new(ALL);
static INIT: AtomicBool = AtomicBool::new(false);
static INIT_LOCK: RawMutex = RawMutex::new();
static LOCK: RawMutex = RawMutex::new();

struct Sev {
    severity: c_int,
    name: *const u8,
    next: *mut Sev,
}
static USER: SyncCell<*mut Sev> = SyncCell::new(core::ptr::null_mut());

fn with_user<R>(f: impl FnOnce(&mut *mut Sev) -> R) -> R {
    LOCK.lock_always();
    let r = unsafe { USER.with_unsync(f) };
    LOCK.unlock_always();
    r
}

unsafe fn node_mut<'a>(node: *mut Sev) -> &'a mut Sev {
    unsafe { &mut *node }
}

fn malloc(n: usize) -> *mut u8 {
    crate::mntent::malloc(n)
}

const BUILTIN: [(c_int, &[u8]); 4] = [(MM_HALT, b"HALT"), (MM_ERROR, b"ERROR"), (MM_WARNING, b"WARNING"), (MM_INFO, b"INFO")];

unsafe fn set_severity(severity: c_int, name: Option<*const u8>) -> bool {
    with_user(|head| {
        let mut link: &mut *mut Sev = head;
        while !link.is_null() {
            let node = *link;
            let n = unsafe { node_mut(node) };
            if n.severity == severity {
                match name {
                    Some(x) => n.name = x,
                    None => {
                        *link = n.next;
                        unsafe { rusty_libc_malloc::free(node.cast()) };
                    }
                }
                return true;
            }
            link = &mut n.next;
        }
        let Some(x) = name else { return false };
        let node = malloc(core::mem::size_of::<Sev>()).cast::<Sev>();
        if node.is_null() {
            return false;
        }
        unsafe { node.write(Sev { severity, name: x, next: core::ptr::null_mut() }) };
        *link = node;
        true
    })
}

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
            let n = unsafe { node_mut(p) };
            if n.severity == severity {
                let name = unsafe { rusty_libc_core::ffi::cstr_bytes(n.name) };
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

fn env(name: &[u8]) -> Option<&'static [u8]> {
    let p = unsafe { rusty_libc_core::env::getenv(name) };
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
            if let Some(comma) = entry.iter().position(|&c| c == b',') {
                let rest = &entry[comma + 1..];
                let mut buf = [0u8; 80];
                let probe = &rest[..rest.len().min(buf.len() - 1)];
                buf[..probe.len()].copy_from_slice(probe);
                let mut endp: *mut c_char = core::ptr::null_mut();
                let level = unsafe { rusty_libc_stdlib::num::strtol(buf.as_ptr().cast(), &mut endp, 0) } as c_int;
                let consumed = endp.addr() - buf.as_ptr().addr();
                if consumed != 0 && consumed < probe.len() && probe[consumed] == b',' && level > MM_INFO {
                    let name = &rest[consumed + 1..];
                    let copy = malloc(name.len() + 1);
                    if !copy.is_null() {
                        let c = unsafe { rusty_libc_core::ffi::bytes_mut(copy, name.len() + 1) };
                        c[..name.len()].copy_from_slice(name);
                        c[name.len()] = 0;
                        if !unsafe { set_severity(level, Some(copy)) } {
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

pub fn fmtmsg_r(classification: c_long, label: Option<&[u8]>, severity: c_int, text: Option<&[u8]>, action: Option<&[u8]>, tag: Option<&[u8]>) -> c_int {
    init();
    if let Some(l) = label {
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
        let err = unsafe { rusty_libc_stdio::stderr.read() };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmtmsg(classification: c_long, label: *const c_char, severity: c_int, text: *const c_char, action: *const c_char, tag: *const c_char) -> c_int {
    let part = |p: *const c_char| unsafe { rusty_libc_core::ffi::cstr(p) }.map(|c| c.to_bytes());
    fmtmsg_r(classification, part(label), severity, part(text), part(action), part(tag))
}

struct Msg {
    small: [u8; 1024],
    big: *mut u8,
    cap: usize,
    len: usize,
}

impl Msg {
    fn new() -> Msg {
        Msg { small: [0; 1024], big: core::ptr::null_mut(), cap: 1024, len: 0 }
    }
    fn buf(&mut self) -> &mut [u8] {
        if self.big.is_null() {
            &mut self.small
        } else {
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
            let new = unsafe { rusty_libc_core::ffi::bytes_mut(nb, ncap) };
            new[..len].copy_from_slice(&self.buf()[..len]);
            if !self.big.is_null() {
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
            unsafe { rusty_libc_malloc::free(self.big.cast()) };
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn addseverity(severity: c_int, string: *const c_char) -> c_int {
    if severity <= MM_INFO {
        return MM_NOTOK;
    }
    let ok = unsafe { set_severity(severity, if string.is_null() { None } else { Some(string as *const u8) }) };
    if ok { MM_OK } else { MM_NOTOK }
}

