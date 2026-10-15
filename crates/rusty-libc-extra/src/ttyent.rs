#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::mntent::Stream;
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::fopen;

pub const TTY_ON: c_int = 0x01;
pub const TTY_SECURE: c_int = 0x02;

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

struct State {
    zapchar: u8,
    tf: *mut FILE,
    tty: Ttyent,
    line: [u8; MAXLINELENGTH],
    path: *const c_char,
}

static STATE: SyncCell<State> = SyncCell::new(State {
    zapchar: 0,
    tf: null_mut(),
    tty: Ttyent { ty_name: null_mut(), ty_getty: null_mut(), ty_type: null_mut(), ty_status: 0, ty_window: null_mut(), ty_comment: null_mut() },
    line: [0; MAXLINELENGTH],
    path: c"/etc/ttys".as_ptr(),
});

unsafe fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    unsafe { STATE.with_unsync(f) }
}

fn line_ptr(i: usize) -> *mut c_char {
    STATE.as_ptr().cast::<c_char>().wrapping_add(core::mem::offset_of!(State, line) + i)
}
fn tty_ptr() -> *mut Ttyent {
    STATE.as_ptr().cast::<u8>().wrapping_add(core::mem::offset_of!(State, tty)).cast::<Ttyent>()
}

pub unsafe fn set_path(path: *const c_char) {
    unsafe { with_state(|st| st.path = if path.is_null() { c"/etc/ttys".as_ptr() } else { path }) };
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

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
    fn stream(&self) -> Stream {
        debug_assert!(!self.tf.is_null());
        unsafe { Stream::new(self.tf) }
    }

    fn set(&mut self) -> c_int {
        if !self.tf.is_null() {
            self.stream().rewind();
            return 1;
        }
        self.tf = unsafe { fopen(self.path, c"rce".as_ptr()) };
        if !self.tf.is_null() {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setttyent() -> c_int {
    unsafe { with_state(State::set) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endttyent() -> c_int {
    unsafe { with_state(State::end) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttyent() -> *mut Ttyent {
    unsafe { with_state(State::get) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttynam(tty: *const c_char) -> *mut Ttyent {
    let name = unsafe { rusty_libc_core::ffi::cstr_bytes(tty) };
    let find = |st: &mut State| {
        st.set();
        let mut t;
        loop {
            t = st.get();
            if t.is_null() {
                break;
            }
            let rest = &st.line[st.tty.ty_name.addr() - line_ptr(0).addr()..];
            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            if rest[..end] == *name {
                break;
            }
        }
        st.end();
        t
    };
    unsafe { with_state(find) }
}
