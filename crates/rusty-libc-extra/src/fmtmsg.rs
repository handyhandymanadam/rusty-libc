use core::ffi::{c_char, c_int, c_long};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use rusty_libc_core::lock::RawMutex;

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
    name: *mut u8,
    next: *mut Sev,
}
static mut USER: *mut Sev = core::ptr::null_mut();

const BUILTIN: [(c_int, &[u8]); 4] = [(MM_HALT, b"HALT"), (MM_ERROR, b"ERROR"), (MM_WARNING, b"WARNING"), (MM_INFO, b"INFO")];

unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::ffi::CStr::from_ptr(p).to_bytes() }
}

unsafe fn set_severity(severity: c_int, name: Option<&[u8]>) -> bool {
    unsafe {
        LOCK.lock_always();
        let ok = (|| {
            let mut link: *mut *mut Sev = &raw mut USER;
            while !(*link).is_null() {
                let node = *link;
                if (*node).severity == severity {
                    match name {
                        Some(n) => {
                            let copy = rusty_libc_malloc::malloc(n.len() + 1) as *mut u8;
                            if copy.is_null() {
                                return false;
                            }
                            core::ptr::copy_nonoverlapping(n.as_ptr(), copy, n.len());
                            *copy.add(n.len()) = 0;
                            rusty_libc_malloc::free((*node).name.cast());
                            (*node).name = copy;
                            return true;
                        }
                        None => {
                            *link = (*node).next;
                            rusty_libc_malloc::free((*node).name.cast());
                            rusty_libc_malloc::free(node.cast());
                            return true;
                        }
                    }
                }
                link = &raw mut (*node).next;
            }
            let Some(n) = name else { return false };
            let node = rusty_libc_malloc::malloc(core::mem::size_of::<Sev>()) as *mut Sev;
            let copy = rusty_libc_malloc::malloc(n.len() + 1) as *mut u8;
            if node.is_null() || copy.is_null() {
                rusty_libc_malloc::free(node.cast());
                rusty_libc_malloc::free(copy.cast());
                return false;
            }
            core::ptr::copy_nonoverlapping(n.as_ptr(), copy, n.len());
            *copy.add(n.len()) = 0;
            node.write(Sev { severity, name: copy, next: core::ptr::null_mut() });
            *link = node;
            true
        })();
        LOCK.unlock_always();
        ok
    }
}

unsafe fn severity_name(severity: c_int, out: &mut [u8; 512]) -> Option<usize> {
    unsafe {
        for (s, n) in BUILTIN {
            if s == severity {
                out[..n.len()].copy_from_slice(n);
                return Some(n.len());
            }
        }
        LOCK.lock_always();
        let mut r = None;
        let mut p = USER;
        while !p.is_null() {
            if (*p).severity == severity {
                let n = cstr((*p).name.cast());
                let l = n.len().min(out.len());
                out[..l].copy_from_slice(&n[..l]);
                r = Some(l);
                break;
            }
            p = (*p).next;
        }
        LOCK.unlock_always();
        r
    }
}

fn init() {
    if INIT.load(Ordering::Acquire) {
        return;
    }
    INIT_LOCK.lock_always();
    if !INIT.load(Ordering::Acquire) {
        unsafe { init_from_env() };
        INIT.store(true, Ordering::Release);
    }
    INIT_LOCK.unlock_always();
}

unsafe fn init_from_env() {
    unsafe {
        let msgverb = rusty_libc_core::env::getenv(b"MSGVERB");
        let sevlevel = rusty_libc_core::env::getenv(b"SEV_LEVEL");
        if !msgverb.is_null() && *msgverb != 0 {
            let mut s = cstr(msgverb);
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
        if !sevlevel.is_null() {
            let mut s = cstr(sevlevel);
            while !s.is_empty() {
                let end = s.iter().position(|&c| c == b':').unwrap_or(s.len());
                let entry = &s[..end];
                if let Some(comma) = entry.iter().position(|&c| c == b',') {
                    let rest = &entry[comma + 1..];
                    let mut buf = [0u8; 80];
                    let probe = &rest[..rest.len().min(buf.len() - 1)];
                    buf[..probe.len()].copy_from_slice(probe);
                    let mut endp: *mut c_char = core::ptr::null_mut();
                    let level = rusty_libc_stdlib::num::strtol(buf.as_ptr().cast(), &mut endp, 0) as c_int;
                    let consumed = endp as usize - buf.as_ptr() as usize;
                    if consumed != 0 && consumed < probe.len() && probe[consumed] == b',' && level > MM_INFO {
                        let name = &rest[consumed + 1..];
                        set_severity(level, Some(name));
                    }
                }
                s = &s[end..];
                if s.first() == Some(&b':') {
                    s = &s[1..];
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmtmsg(classification: c_long, label: *const c_char, severity: c_int, text: *const c_char, action: *const c_char, tag: *const c_char) -> c_int {
    unsafe {
        init();
        if !label.is_null() {
            let l = cstr(label);
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
        let do_label = print & LABEL_MASK != 0 && !label.is_null();
        let do_severity = print & SEVERITY_MASK != 0 && name_len.is_some();
        let do_text = print & TEXT_MASK != 0 && !text.is_null();
        let do_action = print & ACTION_MASK != 0 && !action.is_null();
        let do_tag = print & TAG_MASK != 0 && !tag.is_null();

        let mut msg = Msg::new();
        if do_label {
            msg.push(cstr(label));
        }
        if do_label && (do_severity | do_text | do_action | do_tag) {
            msg.push(b": ");
        }
        if do_severity {
            msg.push(&name[..name_len.unwrap_or(0)]);
        }
        if do_severity && (do_text | do_action | do_tag) {
            msg.push(b": ");
        }
        if do_text {
            msg.push(cstr(text));
        }
        if do_text && (do_action | do_tag) {
            msg.push(b"\n");
        }
        if do_action {
            msg.push(b"TO FIX: ");
            msg.push(cstr(action));
        }
        if do_action && do_tag {
            msg.push(b"  ");
        }
        if do_tag {
            msg.push(cstr(tag));
        }
        msg.push(b"\n");

        let mut result = MM_OK;
        if classification & MM_PRINT != 0 {
            let s = msg.bytes();
            let n = rusty_libc_stdio::fwrite(s.as_ptr().cast(), 1, s.len(), rusty_libc_stdio::stderr);
            if n != s.len() {
                result = MM_NOMSG;
            }
        }
        if classification & MM_CONSOLE != 0 {
            crate::syslog::syslog_text(3, msg.bytes());
        }
        result
    }
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
    fn ptr(&mut self) -> *mut u8 {
        if self.big.is_null() { self.small.as_mut_ptr() } else { self.big }
    }
    fn push(&mut self, s: &[u8]) {
        if self.len + s.len() > self.cap {
            let ncap = (self.len + s.len()).next_power_of_two();
            let nb = unsafe { rusty_libc_malloc::malloc(ncap) as *mut u8 };
            if nb.is_null() {
                return;
            }
            unsafe { core::ptr::copy_nonoverlapping(self.ptr(), nb, self.len) };
            if !self.big.is_null() {
                unsafe { rusty_libc_malloc::free(self.big.cast()) };
            }
            self.big = nb;
            self.cap = ncap;
        }
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr().add(self.len), s.len()) };
        self.len += s.len();
    }
    fn bytes(&mut self) -> &[u8] {
        let (p, l) = (self.ptr(), self.len);
        unsafe { core::slice::from_raw_parts(p, l) }
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
    unsafe {
        if severity <= MM_INFO {
            return MM_NOTOK;
        }
        let ok = set_severity(severity, if string.is_null() { None } else { Some(cstr(string)) });
        if ok { MM_OK } else { MM_NOTOK }
    }
}

