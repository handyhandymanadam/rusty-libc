use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::{fclose, fgets, fopen, getc, rewind};

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

static mut ZAPCHAR: c_char = 0;
static mut TF: *mut FILE = null_mut();
static mut TTY: Ttyent = Ttyent { ty_name: null_mut(), ty_getty: null_mut(), ty_type: null_mut(), ty_status: 0, ty_window: null_mut(), ty_comment: null_mut() };
static mut LINE: [c_char; MAXLINELENGTH] = [0; MAXLINELENGTH];
static mut PATH: *const c_char = c"/etc/ttys".as_ptr();

pub unsafe fn set_path(path: *const c_char) {
    unsafe { PATH = if path.is_null() { c"/etc/ttys".as_ptr() } else { path } };
}

fn isspace(c: c_char) -> bool {
    rusty_libc_ctype::is_space(c as u8 as i32)
}

unsafe fn skip(mut p: *mut c_char) -> *mut c_char {
    unsafe {
        let mut q = false;
        let mut t = p;
        while *p != 0 {
            let c = *p as u8;
            if c == b'"' {
                q = !q;
                p = p.add(1);
                continue;
            }
            if q && c == b'\\' && *p.add(1) as u8 == b'"' {
                p = p.add(1);
            }
            *t = *p;
            t = t.add(1);
            if q {
                p = p.add(1);
                continue;
            }
            if c == b'#' {
                ZAPCHAR = c as c_char;
                *p = 0;
                break;
            }
            if c == b'\t' || c == b' ' || c == b'\n' {
                ZAPCHAR = c as c_char;
                *p = 0;
                p = p.add(1);
                while matches!(*p as u8, b'\t' | b' ' | b'\n') {
                    p = p.add(1);
                }
                break;
            }
            p = p.add(1);
        }
        t = t.sub(1);
        *t = 0;
        p
    }
}

unsafe fn value(p: *mut c_char) -> *mut c_char {
    unsafe {
        let e = rusty_libc_mem::strchr(p, b'=' as c_int);
        if e.is_null() { null_mut() } else { e.add(1) }
    }
}

unsafe fn word_is(p: *const c_char, word: &[u8], next: impl Fn(u8) -> bool) -> bool {
    unsafe {
        for (i, &w) in word.iter().enumerate() {
            if *p.add(i) as u8 != w {
                return false;
            }
        }
        next(*p.add(word.len()) as u8)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setttyent() -> c_int {
    unsafe {
        if !TF.is_null() {
            rewind(TF);
            return 1;
        }
        let mode = c"rce";
        TF = fopen(PATH, mode.as_ptr());
        if !TF.is_null() {
            rusty_libc_stdio::stdio_ext::__fsetlocking(TF, 2);
            return 1;
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endttyent() -> c_int {
    unsafe {
        if !TF.is_null() {
            let rval = (fclose(TF) != -1) as c_int;
            TF = null_mut();
            return rval;
        }
        1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttyent() -> *mut Ttyent {
    unsafe {
        if TF.is_null() && setttyent() == 0 {
            return null_mut();
        }
        let line = &raw mut LINE as *mut c_char;
        let mut p;
        loop {
            p = line;
            if fgets(p, MAXLINELENGTH as c_int, TF).is_null() {
                return null_mut();
            }
            if rusty_libc_mem::strchr(p, b'\n' as c_int).is_null() {
                loop {
                    let c = getc(TF);
                    if c == b'\n' as c_int || c == -1 {
                        break;
                    }
                }
                continue;
            }
            while isspace(*p) {
                p = p.add(1);
            }
            if *p != 0 && *p as u8 != b'#' {
                break;
            }
        }
        ZAPCHAR = 0;
        let tty = &mut *(&raw mut TTY);
        tty.ty_name = p;
        p = skip(p);
        tty.ty_getty = p;
        if *p == 0 {
            tty.ty_getty = null_mut();
            tty.ty_type = null_mut();
        } else {
            p = skip(p);
            tty.ty_type = p;
            if *p == 0 {
                tty.ty_type = null_mut();
            } else {
                p = skip(p);
            }
        }
        tty.ty_status = 0;
        tty.ty_window = null_mut();
        while *p != 0 {
            if word_is(p, b"off", |c| isspace(c as c_char)) {
                tty.ty_status &= !TTY_ON;
            } else if word_is(p, b"on", |c| isspace(c as c_char)) {
                tty.ty_status |= TTY_ON;
            } else if word_is(p, b"secure", |c| isspace(c as c_char)) {
                tty.ty_status |= TTY_SECURE;
            } else if word_is(p, b"window", |c| c == b'=') {
                tty.ty_window = value(p);
            } else {
                break;
            }
            p = skip(p);
        }
        if ZAPCHAR as u8 == b'#' || *p as u8 == b'#' {
            loop {
                p = p.add(1);
                let c = *p as u8;
                if !(c == b' ' || c == b'\t') {
                    break;
                }
            }
        }
        tty.ty_comment = p;
        if *p == 0 {
            tty.ty_comment = null_mut();
        }
        let nl = rusty_libc_mem::strchr(p, b'\n' as c_int);
        if !nl.is_null() {
            *nl = 0;
        }
        tty
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getttynam(tty: *const c_char) -> *mut Ttyent {
    unsafe {
        setttyent();
        let mut t;
        loop {
            t = getttyent();
            if t.is_null() || rusty_libc_mem::strcmp(tty, (*t).ty_name) == 0 {
                break;
            }
        }
        endttyent();
        t
    }
}
