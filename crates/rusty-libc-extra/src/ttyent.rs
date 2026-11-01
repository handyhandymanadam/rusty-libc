//! ttyent.h: `getttyent`, `getttynam`, `setttyent`, `endttyent` on `/etc/ttys`.
//!
//! The format (4.4BSD): `name getty-command type [off|on] [secure] [window=cmd] # comment`, fields
//! separated by blanks, double quotes group a field (`\"` inside quotes is a quote), `#` starts the comment.
//! Lines longer than 99 characters are skipped. The result is one static structure whose strings live in a
//! 100 byte static line buffer. The structure of the code follows glibc 2.43 misc/getttyent.c (BSD
//! licence), written in Rust.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::mntent::Stream;
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::fopen;

pub const TTY_ON: c_int = 0x01;
pub const TTY_SECURE: c_int = 0x02;

/// `struct ttyent`.
#[repr(C)]
pub struct Ttyent {
    pub ty_name: *mut c_char,
    pub ty_getty: *mut c_char,
    pub ty_type: *mut c_char,
    pub ty_status: c_int,
    pub ty_window: *mut c_char,
    pub ty_comment: *mut c_char,
}

const MAXLINELENGTH: usize = 100;

/// glibc's static ttyent state: the stream (NULL: closed; otherwise open and owned here), the returned entry, the line
/// its strings point into, the character a field was cut at, and the file name.
struct State {
    zapchar: u8,
    tf: *mut FILE,
    tty: Ttyent,
    line: [u8; MAXLINELENGTH],
    path: *const c_char,
}

/// Rule: the ttyent functions are MT-Unsafe in glibc (race:ttyent): callers do not run them concurrently; each exported
/// function holds the state only for its own duration.
static STATE: SyncCell<State> = SyncCell::new(State {
    zapchar: 0,
    tf: null_mut(),
    tty: Ttyent { ty_name: null_mut(), ty_getty: null_mut(), ty_type: null_mut(), ty_status: 0, ty_window: null_mut(), ty_comment: null_mut() },
    line: [0; MAXLINELENGTH],
    path: c"/etc/ttys".as_ptr(),
});

/// Run `f` on the state.
///
/// # Safety
/// The ttyent rule: no other ttyent function runs at the same time; `f` does not reach STATE again.
unsafe fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // SAFETY: exclusive by the ttyent rule (forwarded contract).
    unsafe { STATE.with_unsync(f) }
}

/// The address of `line[i]` and of the entry inside the static (what the C caller gets back).
fn line_ptr(i: usize) -> *mut c_char {
    STATE.as_ptr().cast::<c_char>().wrapping_add(core::mem::offset_of!(State, line) + i)
}
fn tty_ptr() -> *mut Ttyent {
    STATE.as_ptr().cast::<u8>().wrapping_add(core::mem::offset_of!(State, tty)).cast::<Ttyent>()
}

/// Read another file than `/etc/ttys` from the next `setttyent` on (tests; the C interface has no such call).
///
/// # Safety
/// `path` stays valid while the stream is in use; it is not copied.
pub unsafe fn set_path(path: *const c_char) {
    // SAFETY: ttyent rule (set_path is used like the exported functions, never concurrently with them).
    unsafe { with_state(|st| st.path = if path.is_null() { c"/etc/ttys".as_ptr() } else { path }) };
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

/// Skip over the current field at `p`, removing quotes, and return the start of the next one.
fn skip(line: &mut [u8], zapchar: &mut u8, mut p: usize) -> usize {
    let mut q = false;
    let mut t = p;
    while line[p] != 0 {
        let c = line[p];
        if c == b'"' {
            q = !q;
            p += 1;
            continue;
        }
        if q && c == b'\\' && line[p + 1] == b'"' {
            p += 1;
        }
        line[t] = line[p];
        t += 1;
        if q {
            p += 1;
            continue;
        }
        if c == b'#' {
            *zapchar = c;
            line[p] = 0;
            break;
        }
        if c == b'\t' || c == b' ' || c == b'\n' {
            *zapchar = c;
            line[p] = 0;
            p += 1;
            while matches!(line[p], b'\t' | b' ' | b'\n') {
                p += 1;
            }
            break;
        }
        p += 1;
    }
    // glibc writes t[-1]; t is past the field's first byte whenever the loop ran, and every call starts on a non-NUL byte
    t = t.saturating_sub(1);
    line[t] = 0;
    p
}

fn value(line: &[u8], p: usize) -> Option<usize> {
    let end = p + line[p..].iter().position(|&c| c == 0)?;
    line[p..end].iter().position(|&c| c == b'=').map(|e| p + e + 1)
}

fn word_is(line: &[u8], p: usize, word: &[u8], next: impl Fn(u8) -> bool) -> bool {
    for (i, &w) in word.iter().enumerate() {
        if line[p + i] != w {
            return false;
        }
    }
    next(line[p + word.len()])
}

impl State {
    /// The open stream (only while `tf` is not NULL).
    fn stream(&self) -> Stream {
        debug_assert!(!self.tf.is_null());
        // SAFETY: a non-NULL `tf` is the stream setttyent opened, open until endttyent clears it.
        unsafe { Stream::new(self.tf) }
    }

    fn set(&mut self) -> c_int {
        if !self.tf.is_null() {
            self.stream().rewind();
            return 1;
        }
        // SAFETY: `path` is a C string (the default or one set_path's caller keeps valid); the mode is a literal.
        self.tf = unsafe { fopen(self.path, c"rce".as_ptr()) };
        if !self.tf.is_null() {
            // we do the locking ourselves
            self.stream().set_locking(2);
            return 1;
        }
        0
    }

    fn end(&mut self) -> c_int {
        if !self.tf.is_null() {
            let rval = (self.stream().close() != -1) as c_int;
            self.tf = null_mut();
            return rval;
        }
        1
    }

    fn get(&mut self) -> *mut Ttyent {
        if self.tf.is_null() && self.set() == 0 {
            return null_mut();
        }
        let stream = self.stream();
        let line = &mut self.line;
        let mut p;
        loop {
            p = 0;
            if !stream.fgets(line, MAXLINELENGTH as c_int) {
                return null_mut();
            }
            let len = line.iter().position(|&c| c == 0).unwrap_or(MAXLINELENGTH);
            // skip lines that are too big
            if !line[..len].contains(&b'\n') {
                loop {
                    let c = stream.getc();
                    if c == b'\n' as c_int || c == -1 {
                        break;
                    }
                }
                continue;
            }
            while isspace(line[p]) {
                p += 1;
            }
            if line[p] != 0 && line[p] != b'#' {
                break;
            }
        }
        let zap = &mut self.zapchar;
        *zap = 0;
        let tty = &mut self.tty;
        tty.ty_name = line_ptr(p);
        p = skip(line, zap, p);
        tty.ty_getty = line_ptr(p);
        if line[p] == 0 {
            tty.ty_getty = null_mut();
            tty.ty_type = null_mut();
        } else {
            p = skip(line, zap, p);
            tty.ty_type = line_ptr(p);
            if line[p] == 0 {
                tty.ty_type = null_mut();
            } else {
                p = skip(line, zap, p);
            }
        }
        tty.ty_status = 0;
        tty.ty_window = null_mut();
        while line[p] != 0 {
            if word_is(line, p, b"off", isspace) {
                tty.ty_status &= !TTY_ON;
            } else if word_is(line, p, b"on", isspace) {
                tty.ty_status |= TTY_ON;
            } else if word_is(line, p, b"secure", isspace) {
                tty.ty_status |= TTY_SECURE;
            } else if word_is(line, p, b"window", |c| c == b'=') {
                tty.ty_window = value(line, p).map_or(null_mut(), line_ptr);
            } else {
                break;
            }
            p = skip(line, zap, p);
        }
        if *zap == b'#' || line[p] == b'#' {
            loop {
                p += 1;
                let c = line[p];
                if !(c == b' ' || c == b'\t') {
                    break;
                }
            }
        }
        tty.ty_comment = line_ptr(p);
        if line[p] == 0 {
            tty.ty_comment = null_mut();
        }
        if let Some(nl) = line[p..].iter().take_while(|&&c| c != 0).position(|&c| c == b'\n') {
            line[p + nl] = 0;
        }
        tty_ptr()
    }
}

/// `setttyent ()`: open (or rewind) the file; 1 on success, 0 when it cannot be opened.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setttyent() -> c_int {
    // SAFETY: ttyent rule (the exported functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(State::set) }
}

/// `endttyent ()`: close the file; 1 on success.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endttyent() -> c_int {
    // SAFETY: ttyent rule.
    unsafe { with_state(State::end) }
}

/// `getttyent ()`: the next entry of the file (opened on the first call), NULL at the end.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttyent() -> *mut Ttyent {
    // SAFETY: ttyent rule.
    unsafe { with_state(State::get) }
}

/// `getttynam (tty)`: the entry named `tty` (the file is opened and closed again), NULL when there is none.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttynam(tty: *const c_char) -> *mut Ttyent {
    // SAFETY: `tty` is a C string (caller's contract).
    let name = unsafe { rusty_libc_core::ffi::cstr_bytes(tty) };
    let find = |st: &mut State| {
        st.set();
        let mut t;
        loop {
            t = st.get();
            if t.is_null() {
                break;
            }
            // strcmp(tty, ty_name): the name is a NUL-terminated piece of the line (skip cut it)
            let rest = &st.line[st.tty.ty_name.addr() - line_ptr(0).addr()..];
            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            if rest[..end] == *name {
                break;
            }
        }
        st.end();
        t
    };
    // SAFETY: ttyent rule.
    unsafe { with_state(find) }
}
