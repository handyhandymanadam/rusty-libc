#![allow(non_upper_case_globals)]
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr::{null, null_mut};
use rusty_libc_stdio::file::File;
use rusty_libc_stdio::fmt::Sink;
use rusty_libc_stdio::rust_api::{Arg, snprintf};
use rusty_libc_util::getopt::{COption, Data, getopt_internal_r};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgpOption {
    pub name: *const c_char,
    pub key: c_int,
    pub arg: *const c_char,
    pub flags: c_int,
    pub doc: *const c_char,
    pub group: c_int,
}

pub type ArgpParser = unsafe extern "C" fn(c_int, *mut c_char, *mut ArgpState) -> c_int;
pub type HelpFilter = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_char;

#[repr(C)]
pub struct Argp {
    pub options: *const ArgpOption,
    pub parser: Option<ArgpParser>,
    pub args_doc: *const c_char,
    pub doc: *const c_char,
    pub children: *const ArgpChild,
    pub help_filter: Option<HelpFilter>,
    pub argp_domain: *const c_char,
}

#[repr(C)]
pub struct ArgpChild {
    pub argp: *const Argp,
    pub flags: c_int,
    pub header: *const c_char,
    pub group: c_int,
}

#[repr(C)]
pub struct ArgpState {
    pub root_argp: *const Argp,
    pub argc: c_int,
    pub argv: *mut *mut c_char,
    pub next: c_int,
    pub flags: c_uint,
    pub arg_num: c_uint,
    pub quoted: c_int,
    pub input: *mut c_void,
    pub child_inputs: *mut *mut c_void,
    pub hook: *mut c_void,
    pub name: *mut c_char,
    pub err_stream: *mut File,
    pub out_stream: *mut File,
    pub pstate: *mut c_void,
}

const _: () = assert!(size_of::<ArgpOption>() == 48);
const _: () = assert!(size_of::<Argp>() == 56);
const _: () = assert!(size_of::<ArgpChild>() == 32);
const _: () = assert!(size_of::<ArgpState>() == 96);

unsafe impl Sync for ArgpOption {}

pub const OPTION_ARG_OPTIONAL: c_int = 0x1;
pub const OPTION_HIDDEN: c_int = 0x2;
pub const OPTION_ALIAS: c_int = 0x4;
pub const OPTION_DOC: c_int = 0x8;
pub const OPTION_NO_USAGE: c_int = 0x10;

pub const ARGP_ERR_UNKNOWN: c_int = 7;
pub const ARGP_KEY_ARG: c_int = 0;
pub const ARGP_KEY_ARGS: c_int = 0x1000006;
pub const ARGP_KEY_END: c_int = 0x1000001;
pub const ARGP_KEY_NO_ARGS: c_int = 0x1000002;
pub const ARGP_KEY_INIT: c_int = 0x1000003;
pub const ARGP_KEY_FINI: c_int = 0x1000007;
pub const ARGP_KEY_SUCCESS: c_int = 0x1000004;
pub const ARGP_KEY_ERROR: c_int = 0x1000005;

pub const ARGP_KEY_HELP_PRE_DOC: c_int = 0x2000001;
pub const ARGP_KEY_HELP_POST_DOC: c_int = 0x2000002;
pub const ARGP_KEY_HELP_HEADER: c_int = 0x2000003;
pub const ARGP_KEY_HELP_EXTRA: c_int = 0x2000004;
pub const ARGP_KEY_HELP_DUP_ARGS_NOTE: c_int = 0x2000005;
pub const ARGP_KEY_HELP_ARGS_DOC: c_int = 0x2000006;

pub const ARGP_PARSE_ARGV0: c_uint = 0x01;
pub const ARGP_NO_ERRS: c_uint = 0x02;
pub const ARGP_NO_ARGS: c_uint = 0x04;
pub const ARGP_IN_ORDER: c_uint = 0x08;
pub const ARGP_NO_HELP: c_uint = 0x10;
pub const ARGP_NO_EXIT: c_uint = 0x20;
pub const ARGP_LONG_ONLY: c_uint = 0x40;
pub const ARGP_SILENT: c_uint = ARGP_NO_EXIT | ARGP_NO_ERRS | ARGP_NO_HELP;

pub const ARGP_HELP_USAGE: c_uint = 0x01;
pub const ARGP_HELP_SHORT_USAGE: c_uint = 0x02;
pub const ARGP_HELP_SEE: c_uint = 0x04;
pub const ARGP_HELP_LONG: c_uint = 0x08;
pub const ARGP_HELP_PRE_DOC: c_uint = 0x10;
pub const ARGP_HELP_POST_DOC: c_uint = 0x20;
pub const ARGP_HELP_DOC: c_uint = ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC;
pub const ARGP_HELP_BUG_ADDR: c_uint = 0x40;
pub const ARGP_HELP_LONG_ONLY: c_uint = 0x80;
pub const ARGP_HELP_EXIT_ERR: c_uint = 0x100;
pub const ARGP_HELP_EXIT_OK: c_uint = 0x200;
pub const ARGP_HELP_STD_ERR: c_uint = ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR;
pub const ARGP_HELP_STD_USAGE: c_uint = ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR;
pub const ARGP_HELP_STD_HELP: c_uint = ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG | ARGP_HELP_EXIT_OK | ARGP_HELP_DOC | ARGP_HELP_BUG_ADDR;

const EBADKEY: c_int = ARGP_ERR_UNKNOWN;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut argp_program_version: *const c_char = null();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut argp_program_version_hook: Option<unsafe extern "C" fn(*mut File, *mut ArgpState)> = None;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut argp_program_bug_address: *const c_char = null();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut argp_err_exit_status: c_int = 64;

#[cfg(feature = "export")]
unsafe extern "C" {
    static mut program_invocation_name: *mut c_char;
    static mut program_invocation_short_name: *mut c_char;
}
#[cfg(not(feature = "export"))]
use rusty_libc_util::err::{program_invocation_name, program_invocation_short_name};

unsafe fn short_program_name() -> *mut c_char {
    unsafe {
        let p = program_invocation_short_name;
        if p.is_null() { c"".as_ptr() as *mut c_char } else { p }
    }
}

unsafe fn slen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s) }
}

unsafe fn cstr<'a>(p: *const c_char) -> &'a CStr {
    unsafe { CStr::from_ptr(p) }
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

fn isalnum(c: u8) -> bool {
    rusty_libc_ctype::is_alnum(c as i32)
}

fn isprint(c: c_int) -> bool {
    rusty_libc_ctype::is_print(c)
}

unsafe fn out(stream: *mut File, parts: &[&[u8]]) {
    unsafe {
        for p in parts {
            if !p.is_empty() {
                rusty_libc_stdio::fwrite(p.as_ptr().cast(), 1, p.len(), stream);
            }
        }
    }
}

unsafe fn flush_exit(status: c_int) -> ! {
    rusty_libc_core::process::exit(status)
}

unsafe fn oend(o: *const ArgpOption) -> bool {
    unsafe { (*o).key == 0 && (*o).name.is_null() && (*o).doc.is_null() && (*o).group == 0 }
}

unsafe fn oshort(o: *const ArgpOption) -> bool {
    unsafe {
        if (*o).flags & OPTION_DOC != 0 {
            false
        } else {
            let k = (*o).key;
            k > 0 && k <= 255 && isprint(k)
        }
    }
}

unsafe fn ovisible(o: *const ArgpOption) -> bool {
    unsafe { (*o).flags & OPTION_HIDDEN == 0 }
}
unsafe fn oalias(o: *const ArgpOption) -> bool {
    unsafe { (*o).flags & OPTION_ALIAS != 0 }
}
unsafe fn odoc(o: *const ArgpOption) -> bool {
    unsafe { (*o).flags & OPTION_DOC != 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_short(opt: *const ArgpOption) -> c_int {
    unsafe { oshort(opt) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_end(opt: *const ArgpOption) -> c_int {
    unsafe { oend(opt) as c_int }
}

struct FmtStream {
    stream: *mut File,
    lmargin: usize,
    rmargin: usize,
    wmargin: isize,
    point_offs: usize,
    point_col: isize,
    buf: *mut u8,
    p: *mut u8,
    end: *mut u8,
}

const INIT_BUF_SIZE: usize = 200;
const PRINTF_SIZE_GUESS: usize = 150;

fn isblank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

impl FmtStream {
    unsafe fn new(stream: *mut File, lmargin: usize, rmargin: usize, wmargin: isize) -> *mut FmtStream {
        unsafe {
            let fs = rusty_libc_malloc::malloc(size_of::<FmtStream>()) as *mut FmtStream;
            if fs.is_null() {
                return null_mut();
            }
            let buf = rusty_libc_malloc::calloc(1, INIT_BUF_SIZE) as *mut u8;
            if buf.is_null() {
                rusty_libc_malloc::free(fs.cast());
                return null_mut();
            }
            fs.write(FmtStream { stream, lmargin, rmargin, wmargin, point_offs: 0, point_col: 0, buf, p: buf, end: buf.add(INIT_BUF_SIZE) });
            fs
        }
    }

    unsafe fn free(fs: *mut FmtStream) {
        unsafe {
            (*fs).update();
            if (*fs).p > (*fs).buf {
                out((*fs).stream, &[core::slice::from_raw_parts((*fs).buf, (*fs).p.offset_from((*fs).buf) as usize)]);
            }
            rusty_libc_malloc::free((*fs).buf.cast());
            rusty_libc_malloc::free(fs.cast());
        }
    }

    unsafe fn put_raw(&self, b: &[u8]) {
        unsafe { out(self.stream, &[b]) }
    }

    unsafe fn update(&mut self) {
        unsafe {
            let mut buf = self.buf.add(self.point_offs);
            while buf < self.p {
                if self.point_col == 0 && self.lmargin != 0 {
                    let pad = self.lmargin;
                    if self.p.add(pad) < self.end {
                        core::ptr::copy(buf, buf.add(pad), self.p.offset_from(buf) as usize);
                        self.p = self.p.add(pad);
                        core::ptr::write_bytes(buf, b' ', pad);
                        buf = buf.add(pad);
                    } else {
                        for _ in 0..pad {
                            rusty_libc_stdio::putc(b' ' as c_int, self.stream);
                        }
                    }
                    self.point_col = pad as isize;
                }
                let mut len = self.p.offset_from(buf) as usize;
                let mut nl: *mut u8 = rusty_libc_mem::memchr(buf.cast(), b'\n' as c_int, len) as *mut u8;
                if self.point_col < 0 {
                    self.point_col = 0;
                }
                if nl.is_null() {
                    if (self.point_col as usize).wrapping_add(len) < self.rmargin {
                        self.point_col += len as isize;
                        break;
                    } else {
                        nl = self.p;
                    }
                } else if self.point_col + nl.offset_from(buf) < self.rmargin as isize {
                    self.point_col = 0;
                    buf = nl.add(1);
                    continue;
                }
                let r = self.rmargin - 1;
                if self.wmargin < 0 {
                    if nl < self.p {
                        let dst = buf.add(r.wrapping_sub(self.point_col as usize));
                        core::ptr::copy(nl, dst, self.p.offset_from(nl) as usize);
                        self.p = self.p.sub(nl.offset_from(dst) as usize);
                        self.point_col = 0;
                        buf = buf.add(r + 1);
                    } else {
                        self.point_col += len as isize;
                        self.p = self.p.sub((self.point_col as usize).wrapping_sub(r));
                        break;
                    }
                } else {
                    let mut p: *mut u8 = buf.offset((r + 1) as isize - self.point_col);
                    while p >= buf && !isblank(*p) {
                        p = p.sub(1);
                    }
                    let mut nextline = p.add(1);
                    if nextline > buf {
                        if p >= buf {
                            loop {
                                p = p.sub(1);
                                if !(p >= buf && isblank(*p)) {
                                    break;
                                }
                            }
                        }
                        nl = p.add(1);
                    } else {
                        p = buf.offset((r + 1) as isize - self.point_col);
                        loop {
                            p = p.add(1);
                            if !(p < nl && !isblank(*p)) {
                                break;
                            }
                        }
                        if p == nl {
                            self.point_col = 0;
                            buf = nl.add(1);
                            continue;
                        }
                        nl = p;
                        loop {
                            p = p.add(1);
                            if !isblank(*p) {
                                break;
                            }
                        }
                        nextline = p;
                    }
                    let at_end = nextline == buf.add(len + 1);
                    let need_more = if at_end { self.end.offset_from(nl) < self.wmargin + 1 } else { nextline.offset_from(nl.add(1)) < self.wmargin };
                    if need_more && self.p > nextline {
                        if self.end.offset_from(self.p) > self.wmargin + 1 {
                            let mv = self.p.offset_from(nextline) as usize;
                            core::ptr::copy(nextline, nl.add(1 + self.wmargin as usize), mv);
                            nextline = nl.add(1 + self.wmargin as usize);
                            len = nextline.add(mv).offset_from(buf) as usize;
                            *nl = b'\n';
                            nl = nl.add(1);
                        } else {
                            if nl > self.buf {
                                self.put_raw(core::slice::from_raw_parts(self.buf, nl.offset_from(self.buf) as usize));
                            }
                            rusty_libc_stdio::putc(b'\n' as c_int, self.stream);
                            len += buf.offset_from(self.buf) as usize;
                            buf = self.buf;
                            nl = buf;
                        }
                    } else {
                        *nl = b'\n';
                        nl = nl.add(1);
                    }
                    let at_end2 = nextline == buf.add(len + 1);
                    if nextline.offset_from(nl) >= self.wmargin || (at_end2 && self.end.offset_from(nextline) >= self.wmargin) {
                        for _ in 0..self.wmargin {
                            *nl = b' ';
                            nl = nl.add(1);
                        }
                    } else {
                        for _ in 0..self.wmargin {
                            rusty_libc_stdio::putc(b' ' as c_int, self.stream);
                        }
                    }
                    if nl < nextline {
                        core::ptr::copy(nextline, nl, (buf.add(len)).offset_from(nextline) as usize);
                    }
                    len -= nextline.offset_from(buf) as usize;
                    buf = nl;
                    self.p = nl.add(len);
                    self.point_col = if self.wmargin != 0 { self.wmargin } else { -1 };
                }
            }
            self.point_offs = self.p.offset_from(self.buf) as usize;
        }
    }

    unsafe fn ensure(&mut self, amount: usize) -> bool {
        unsafe {
            if (self.end.offset_from(self.p) as usize) < amount {
                self.update();
                let n = self.p.offset_from(self.buf) as usize;
                let wrote = if n > 0 { rusty_libc_stdio::fwrite(self.buf.cast(), 1, n, self.stream) } else { 0 };
                if wrote == n {
                    self.p = self.buf;
                    self.point_offs = 0;
                } else {
                    self.p = self.p.sub(wrote);
                    self.point_offs = self.point_offs.wrapping_sub(wrote);
                    core::ptr::copy(self.buf.add(wrote), self.buf, self.p.offset_from(self.buf) as usize);
                    return false;
                }
                if (self.end.offset_from(self.buf) as usize) < amount {
                    let old_size = self.end.offset_from(self.buf) as usize;
                    let new_size = old_size + amount;
                    let nb = rusty_libc_malloc::realloc(self.buf.cast(), new_size) as *mut u8;
                    if nb.is_null() {
                        rusty_libc_core::errno::set(ENOMEM);
                        return false;
                    }
                    self.buf = nb;
                    self.end = nb.add(new_size);
                    self.p = self.buf;
                }
            }
            true
        }
    }

    unsafe fn write(&mut self, s: &[u8]) -> usize {
        unsafe {
            if self.p.add(s.len()) <= self.end || self.ensure(s.len()) {
                core::ptr::copy_nonoverlapping(s.as_ptr(), self.p, s.len());
                self.p = self.p.add(s.len());
                s.len()
            } else {
                0
            }
        }
    }

    unsafe fn puts(&mut self, s: *const c_char) -> c_int {
        unsafe {
            let l = slen(s);
            if l != 0 {
                let w = self.write(core::slice::from_raw_parts(s as *const u8, l));
                if w == l { 0 } else { -1 }
            } else {
                0
            }
        }
    }

    unsafe fn putc(&mut self, ch: c_int) -> c_int {
        unsafe {
            if self.p < self.end || self.ensure(1) {
                *self.p = ch as u8;
                self.p = self.p.add(1);
                ch as u8 as c_int
            } else {
                -1
            }
        }
    }

    unsafe fn set_lmargin(&mut self, m: usize) -> usize {
        unsafe {
            if (self.p.offset_from(self.buf) as usize) > self.point_offs {
                self.update();
            }
            let old = self.lmargin;
            self.lmargin = m;
            old
        }
    }

    unsafe fn set_wmargin(&mut self, m: isize) -> isize {
        unsafe {
            if (self.p.offset_from(self.buf) as usize) > self.point_offs {
                self.update();
            }
            let old = self.wmargin;
            self.wmargin = m;
            old
        }
    }

    unsafe fn point(&mut self) -> usize {
        unsafe {
            if (self.p.offset_from(self.buf) as usize) > self.point_offs {
                self.update();
            }
            if self.point_col >= 0 { self.point_col as usize } else { 0 }
        }
    }

    unsafe fn printf(&mut self, fmt: &CStr, args: &[Arg]) -> isize {
        unsafe {
            let mut size_guess = PRINTF_SIZE_GUESS;
            loop {
                if !self.ensure(size_guess) {
                    return -1;
                }
                let avail = self.end.offset_from(self.p) as usize;
                let n = snprintf(core::slice::from_raw_parts_mut(self.p, avail), fmt, args);
                if n >= 0 && (n as usize) >= avail {
                    size_guess = n as usize + 1;
                    continue;
                }
                let n = n.max(0);
                self.p = self.p.add(n as usize);
                return n as isize;
            }
        }
    }
}

const NUPARAMS: usize = 9;
const DUP_ARGS: usize = 0;
const DUP_ARGS_NOTE: usize = 1;
const SHORT_OPT_COL: usize = 2;
const LONG_OPT_COL: usize = 3;
const DOC_OPT_COL: usize = 4;
const OPT_DOC_COL: usize = 5;
const HEADER_COL: usize = 6;
const USAGE_INDENT: usize = 7;
const RMARGIN: usize = 8;

static mut UPARAMS: [c_int; NUPARAMS] = [0, 1, 2, 6, 2, 29, 1, 12, 79];

const UPARAM_NAMES: [(&[u8], bool, usize); NUPARAMS] = [
    (b"dup-args", true, DUP_ARGS),
    (b"dup-args-note", true, DUP_ARGS_NOTE),
    (b"short-opt-col", false, SHORT_OPT_COL),
    (b"long-opt-col", false, LONG_OPT_COL),
    (b"doc-opt-col", false, DOC_OPT_COL),
    (b"opt-doc-col", false, OPT_DOC_COL),
    (b"header-col", false, HEADER_COL),
    (b"usage-indent", false, USAGE_INDENT),
    (b"rmargin", false, RMARGIN),
];

unsafe fn up(i: usize) -> c_int {
    unsafe { (*(&raw const UPARAMS))[i] }
}

unsafe fn failure_text(state: *const ArgpState, msg: &CStr, args: &[Arg]) {
    unsafe {
        let mut buf = [0u8; 600];
        let n = snprintf(&mut buf, msg, args);
        let n = (n.max(0) as usize).min(buf.len() - 1);
        buf[n] = 0;
        failure_str(state, 0, 0, Some(&buf[..n]));
    }
}

unsafe fn fill_in_uparams(state: *const ArgpState) {
    unsafe {
        let var = rusty_libc_stdlib::env::getenv(c"ARGP_HELP_FMT".as_ptr());
        if var.is_null() {
            return;
        }
        let mut var = var as *const u8;
        let skipws = |p: &mut *const u8| {
            while isspace(**p) {
                *p = (*p).add(1);
            }
        };
        while *var != 0 {
            skipws(&mut var);
            if (*var).is_ascii_alphabetic() {
                let mut unspec = false;
                let mut val: c_int = 0;
                let mut arg = var;
                while isalnum(*arg) || *arg == b'-' || *arg == b'_' {
                    arg = arg.add(1);
                }
                let mut var_len = arg.offset_from(var) as usize;
                skipws(&mut arg);
                if *arg == 0 || *arg == b',' {
                    unspec = true;
                } else if *arg == b'=' {
                    arg = arg.add(1);
                    skipws(&mut arg);
                }
                if unspec {
                    if *var == b'n' && *var.add(1) == b'o' && *var.add(2) == b'-' {
                        val = 0;
                        var = var.add(3);
                        var_len -= 3;
                    } else {
                        val = 1;
                    }
                } else if (*arg).is_ascii_digit() {
                    let mut ep: *mut c_char = null_mut();
                    val = rusty_libc_stdlib::num::strtol(arg as *const c_char, &mut ep, 10) as c_int;
                    arg = ep as *const u8;
                    skipws(&mut arg);
                }
                let name = core::slice::from_raw_parts(var, var_len);
                let mut found = false;
                for (n, is_bool, idx) in UPARAM_NAMES {
                    if n == name {
                        found = true;
                        if unspec && !is_bool {
                            let mut t = [0u8; 300];
                            let k = var_len.min(200);
                            t[..k].copy_from_slice(&name[..k]);
                            failure_text(state, c"%s: ARGP_HELP_FMT parameter requires a value", &[Arg::Str(CStr::from_bytes_until_nul(&t).unwrap())]);
                        } else {
                            (*(&raw mut UPARAMS))[idx] = val;
                        }
                        break;
                    }
                }
                if !found {
                    let mut t = [0u8; 300];
                    let k = var_len.min(200);
                    t[..k].copy_from_slice(&name[..k]);
                    failure_text(state, c"%s: Unknown ARGP_HELP_FMT parameter", &[Arg::Str(CStr::from_bytes_until_nul(&t).unwrap())]);
                }
                var = arg;
                if *var == b',' {
                    var = var.add(1);
                }
            } else if *var != 0 {
                failure_text(state, c"Garbage in ARGP_HELP_FMT: %s", &[Arg::Str(CStr::from_ptr(var as *const c_char))]);
                break;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct HolEntry {
    opt: *const ArgpOption,
    num: c_uint,
    short_options: *mut u8,
    group: c_int,
    cluster: *mut HolCluster,
    argp: *const Argp,
}

struct HolCluster {
    header: *const c_char,
    index: c_int,
    group: c_int,
    parent: *mut HolCluster,
    argp: *const Argp,
    depth: c_int,
    next: *mut HolCluster,
}

struct Hol {
    entries: *mut HolEntry,
    num_entries: c_uint,
    short_options: *mut u8,
    clusters: *mut HolCluster,
}

unsafe fn find_char(ch: u8, mut beg: *const u8, end: *const u8) -> bool {
    unsafe {
        while beg < end {
            if *beg == ch {
                return true;
            }
            beg = beg.add(1);
        }
        false
    }
}

unsafe fn make_hol(argp: *const Argp, cluster: *mut HolCluster) -> *mut Hol {
    unsafe {
        let hol = rusty_libc_malloc::malloc(size_of::<Hol>()) as *mut Hol;
        (*hol).num_entries = 0;
        (*hol).clusters = null_mut();
        (*hol).entries = null_mut();
        (*hol).short_options = null_mut();
        let opts = (*argp).options;
        if !opts.is_null() {
            let mut cur_group = 0;
            let mut num_short = 0usize;
            let mut o = opts;
            while !oend(o) {
                if !oalias(o) {
                    (*hol).num_entries += 1;
                }
                if oshort(o) {
                    num_short += 1;
                }
                o = o.add(1);
            }
            (*hol).entries = rusty_libc_malloc::malloc(size_of::<HolEntry>() * (*hol).num_entries as usize) as *mut HolEntry;
            (*hol).short_options = rusty_libc_malloc::malloc(num_short + 1) as *mut u8;
            let mut so = (*hol).short_options;
            let mut o = opts;
            let mut entry = (*hol).entries;
            while !oend(o) {
                (*entry).opt = o;
                (*entry).num = 0;
                (*entry).short_options = so;
                cur_group = if (*o).group != 0 {
                    (*o).group
                } else if (*o).name.is_null() && (*o).key == 0 {
                    cur_group + 1
                } else {
                    cur_group
                };
                (*entry).group = cur_group;
                (*entry).cluster = cluster;
                (*entry).argp = argp;
                loop {
                    (*entry).num += 1;
                    if oshort(o) && !find_char((*o).key as u8, (*hol).short_options, so) {
                        *so = (*o).key as u8;
                        so = so.add(1);
                    }
                    o = o.add(1);
                    if !(!oend(o) && oalias(o)) {
                        break;
                    }
                }
                entry = entry.add(1);
            }
            *so = 0;
        }
        hol
    }
}

unsafe fn hol_add_cluster(hol: *mut Hol, group: c_int, header: *const c_char, index: c_int, parent: *mut HolCluster, argp: *const Argp) -> *mut HolCluster {
    unsafe {
        let cl = rusty_libc_malloc::malloc(size_of::<HolCluster>()) as *mut HolCluster;
        if !cl.is_null() {
            (*cl).group = group;
            (*cl).header = header;
            (*cl).index = index;
            (*cl).parent = parent;
            (*cl).argp = argp;
            (*cl).depth = if parent.is_null() { 0 } else { (*parent).depth + 1 };
            (*cl).next = (*hol).clusters;
            (*hol).clusters = cl;
        }
        cl
    }
}

unsafe fn hol_free(hol: *mut Hol) {
    unsafe {
        let mut cl = (*hol).clusters;
        while !cl.is_null() {
            let next = (*cl).next;
            rusty_libc_malloc::free(cl.cast());
            cl = next;
        }
        if (*hol).num_entries > 0 {
            rusty_libc_malloc::free((*hol).entries.cast());
            rusty_libc_malloc::free((*hol).short_options.cast());
        }
        rusty_libc_malloc::free(hol.cast());
    }
}

type OptFn = unsafe fn(opt: *const ArgpOption, real: *const ArgpOption, cookie: *mut c_void) -> c_int;

unsafe fn hol_entry_short_iterate(entry: *const HolEntry, func: OptFn, cookie: *mut c_void) -> c_int {
    unsafe {
        let mut val = 0;
        let mut real = (*entry).opt;
        let mut so = (*entry).short_options;
        let mut opt = real;
        let mut nopts = (*entry).num;
        while nopts > 0 && val == 0 {
            if oshort(opt) && *so as c_int == (*opt).key {
                if !oalias(opt) {
                    real = opt;
                }
                if ovisible(opt) {
                    val = func(opt, real, cookie);
                }
                so = so.add(1);
            }
            opt = opt.add(1);
            nopts -= 1;
        }
        val
    }
}

unsafe fn hol_entry_long_iterate(entry: *const HolEntry, func: OptFn, cookie: *mut c_void) -> c_int {
    unsafe {
        let mut val = 0;
        let mut real = (*entry).opt;
        let mut opt = real;
        let mut nopts = (*entry).num;
        while nopts > 0 && val == 0 {
            if !(*opt).name.is_null() {
                if !oalias(opt) {
                    real = opt;
                }
                if ovisible(opt) {
                    val = func(opt, real, cookie);
                }
            }
            opt = opt.add(1);
            nopts -= 1;
        }
        val
    }
}

unsafe fn until_short(opt: *const ArgpOption, _real: *const ArgpOption, _cookie: *mut c_void) -> c_int {
    unsafe { if oshort(opt) { (*opt).key } else { 0 } }
}

unsafe fn hol_entry_first_short(entry: *const HolEntry) -> c_int {
    unsafe { hol_entry_short_iterate(entry, until_short, null_mut()) }
}

unsafe fn hol_entry_first_long(entry: *const HolEntry) -> *const c_char {
    unsafe {
        let mut opt = (*entry).opt;
        let mut num = (*entry).num;
        while num > 0 {
            if !(*opt).name.is_null() && ovisible(opt) {
                return (*opt).name;
            }
            opt = opt.add(1);
            num -= 1;
        }
        null()
    }
}

unsafe fn hol_find_entry(hol: *mut Hol, name: &CStr) -> *mut HolEntry {
    unsafe {
        let mut entry = (*hol).entries;
        let mut n = (*hol).num_entries;
        while n > 0 {
            n -= 1;
            let mut opt = (*entry).opt;
            let mut num_opts = (*entry).num;
            while num_opts > 0 {
                num_opts -= 1;
                if !(*opt).name.is_null() && ovisible(opt) && rusty_libc_mem::strcmp((*opt).name, name.as_ptr()) == 0 {
                    return entry;
                }
                opt = opt.add(1);
            }
            entry = entry.add(1);
        }
        null_mut()
    }
}

unsafe fn hol_set_group(hol: *mut Hol, name: &CStr, group: c_int) {
    unsafe {
        let e = hol_find_entry(hol, name);
        if !e.is_null() {
            (*e).group = group;
        }
    }
}

fn group_cmp(g1: c_int, g2: c_int) -> c_int {
    if (g1 < 0 && g2 < 0) || (g1 >= 0 && g2 >= 0) { g1.wrapping_sub(g2) } else { g2.wrapping_sub(g1) }
}

unsafe fn hol_sibling_cluster_cmp(c1: *const HolCluster, c2: *const HolCluster) -> c_int {
    unsafe {
        let cmp = group_cmp((*c1).group, (*c2).group);
        if cmp != 0 {
            return cmp;
        }
        (*c2).index - (*c1).index
    }
}

unsafe fn hol_cousin_cluster_cmp(c1: *const HolCluster, c2: *const HolCluster) -> c_int {
    unsafe {
        if (*c1).parent == (*c2).parent {
            hol_sibling_cluster_cmp(c1, c2)
        } else {
            let cmp = hol_cousin_cluster_cmp((*c1).parent, (*c2).parent);
            if cmp != 0 {
                return cmp;
            }
            let cmp = group_cmp((*c1).group, (*c2).group);
            if cmp != 0 {
                return cmp;
            }
            (*c2).index - (*c1).index
        }
    }
}

unsafe fn hol_cluster_cmp(mut c1: *const HolCluster, mut c2: *const HolCluster) -> c_int {
    unsafe {
        if (*c1).depth > (*c2).depth {
            loop {
                c1 = (*c1).parent;
                if (*c1).depth <= (*c2).depth {
                    break;
                }
            }
            let cmp = hol_cousin_cluster_cmp(c1, c2);
            if cmp != 0 {
                return cmp;
            }
            1
        } else if (*c1).depth < (*c2).depth {
            loop {
                c2 = (*c2).parent;
                if (*c1).depth >= (*c2).depth {
                    break;
                }
            }
            let cmp = hol_cousin_cluster_cmp(c1, c2);
            if cmp != 0 {
                return cmp;
            }
            -1
        } else {
            hol_cousin_cluster_cmp(c1, c2)
        }
    }
}

unsafe fn hol_cluster_base(mut cl: *mut HolCluster) -> *mut HolCluster {
    unsafe {
        while !(*cl).parent.is_null() {
            cl = (*cl).parent;
        }
        cl
    }
}

unsafe fn canon_doc_option(name: &mut *const c_char) -> bool {
    unsafe {
        while isspace(**name as u8) {
            *name = (*name).add(1);
        }
        let non_opt = **name as u8 != b'-';
        while **name != 0 && !isalnum(**name as u8) {
            *name = (*name).add(1);
        }
        non_opt
    }
}

fn tolower(c: c_int) -> c_int {
    rusty_libc_ctype::to_lower(c)
}

unsafe fn hol_entry_cmp(e1: *const HolEntry, e2: *const HolEntry) -> c_int {
    unsafe {
        let group1 = if (*e1).cluster.is_null() { (*e1).group } else { (*hol_cluster_base((*e1).cluster)).group };
        let group2 = if (*e2).cluster.is_null() { (*e2).group } else { (*hol_cluster_base((*e2).cluster)).group };
        let mut cmp = group_cmp(group1, group2);
        if cmp != 0 {
            return cmp;
        }
        cmp = (!(*e1).cluster.is_null()) as c_int - (!(*e2).cluster.is_null()) as c_int;
        if cmp != 0 {
            return cmp;
        }
        if !(*e1).cluster.is_null() {
            cmp = hol_cluster_cmp((*e1).cluster, (*e2).cluster);
            if cmp != 0 {
                return cmp;
            }
        }
        cmp = group_cmp((*e1).group, (*e2).group);
        if cmp != 0 {
            return cmp;
        }
        let mut long1 = hol_entry_first_long(e1);
        let mut long2 = hol_entry_first_long(e2);
        let doc1 = if odoc((*e1).opt) { (!long1.is_null() && canon_doc_option(&mut long1)) as c_int } else { 0 };
        let doc2 = if odoc((*e2).opt) { (!long2.is_null() && canon_doc_option(&mut long2)) as c_int } else { 0 };
        cmp = doc1 - doc2;
        if cmp != 0 {
            return cmp;
        }
        let short1 = hol_entry_first_short(e1);
        let short2 = hol_entry_first_short(e2);
        let first1 = if short1 != 0 {
            short1 as u8
        } else if !long1.is_null() {
            *long1 as u8
        } else {
            0
        };
        let first2 = if short2 != 0 {
            short2 as u8
        } else if !long2.is_null() {
            *long2 as u8
        } else {
            0
        };
        cmp = tolower(first1 as c_int) - tolower(first2 as c_int);
        if cmp != 0 {
            return cmp;
        }
        cmp = first2 as c_int - first1 as c_int;
        if cmp != 0 {
            return cmp;
        }
        cmp = (short1 != 0) as c_int - (short2 != 0) as c_int;
        if cmp != 0 {
            return cmp;
        }
        if short1 == 0 {
            cmp = (!long1.is_null()) as c_int - (!long2.is_null()) as c_int;
            if cmp != 0 {
                return cmp;
            }
            if !long1.is_null() {
                cmp = rusty_libc_mem::strcasecmp(long1, long2);
                if cmp != 0 {
                    return cmp;
                }
            }
        }
        0
    }
}

unsafe extern "C" fn hol_entry_qcmp(a: *const c_void, b: *const c_void) -> c_int {
    unsafe { hol_entry_cmp(a as *const HolEntry, b as *const HolEntry) }
}

unsafe fn hol_sort(hol: *mut Hol) {
    unsafe {
        if (*hol).num_entries > 0 {
            rusty_libc_stdlib::sort::qsort((*hol).entries.cast(), (*hol).num_entries as usize, size_of::<HolEntry>(), hol_entry_qcmp);
        }
    }
}

unsafe fn hol_append(hol: *mut Hol, more: *mut Hol) {
    unsafe {
        let mut cl_end: *mut *mut HolCluster = &raw mut (*hol).clusters;
        while !(*cl_end).is_null() {
            cl_end = &raw mut (**cl_end).next;
        }
        *cl_end = (*more).clusters;
        (*more).clusters = null_mut();
        if (*more).num_entries > 0 {
            if (*hol).num_entries == 0 {
                (*hol).num_entries = (*more).num_entries;
                (*hol).entries = (*more).entries;
                (*hol).short_options = (*more).short_options;
                (*more).num_entries = 0;
            } else {
                let num_entries = (*hol).num_entries + (*more).num_entries;
                let entries = rusty_libc_malloc::malloc(num_entries as usize * size_of::<HolEntry>()) as *mut HolEntry;
                let hol_so_len = slen((*hol).short_options as *const c_char);
                let short_options = rusty_libc_malloc::malloc(hol_so_len + slen((*more).short_options as *const c_char) + 1) as *mut u8;
                core::ptr::copy_nonoverlapping((*hol).entries, entries, (*hol).num_entries as usize);
                core::ptr::copy_nonoverlapping((*more).entries, entries.add((*hol).num_entries as usize), (*more).num_entries as usize);
                core::ptr::copy_nonoverlapping((*hol).short_options, short_options, hol_so_len);
                let mut e = entries;
                for _ in 0..(*hol).num_entries {
                    (*e).short_options = short_options.offset((*e).short_options.offset_from((*hol).short_options));
                    e = e.add(1);
                }
                let mut so = short_options.add(hol_so_len);
                let mut more_so = (*more).short_options;
                for _ in 0..(*more).num_entries {
                    (*e).short_options = so;
                    let mut opt = (*e).opt;
                    let mut opts_left = (*e).num;
                    while opts_left > 0 {
                        let ch = *more_so;
                        if oshort(opt) && ch as c_int == (*opt).key {
                            if !find_char(ch, short_options, short_options.add(hol_so_len)) {
                                *so = ch;
                                so = so.add(1);
                            }
                            more_so = more_so.add(1);
                        }
                        opt = opt.add(1);
                        opts_left -= 1;
                    }
                    e = e.add(1);
                }
                *so = 0;
                rusty_libc_malloc::free((*hol).entries.cast());
                rusty_libc_malloc::free((*hol).short_options.cast());
                (*hol).entries = entries;
                (*hol).num_entries = num_entries;
                (*hol).short_options = short_options;
            }
        }
        hol_free(more);
    }
}

unsafe fn argp_hol(argp: *const Argp, cluster: *mut HolCluster) -> *mut Hol {
    unsafe {
        let mut child = (*argp).children;
        let hol = make_hol(argp, cluster);
        if !child.is_null() {
            while !(*child).argp.is_null() {
                let child_cluster = if (*child).group != 0 || !(*child).header.is_null() {
                    hol_add_cluster(hol, (*child).group, (*child).header, child.offset_from((*argp).children) as c_int, cluster, argp)
                } else {
                    cluster
                };
                hol_append(hol, argp_hol((*child).argp, child_cluster));
                child = child.add(1);
            }
        }
        hol
    }
}

unsafe fn indent_to(stream: *mut FmtStream, col: c_uint) {
    unsafe {
        let mut needed = col as c_int - (*stream).point() as c_int;
        while needed > 0 {
            needed -= 1;
            (*stream).putc(b' ' as c_int);
        }
    }
}

unsafe fn space(stream: *mut FmtStream, ensure: usize) {
    unsafe {
        if (*stream).point() + ensure >= (*stream).rmargin {
            (*stream).putc(b'\n' as c_int);
        } else {
            (*stream).putc(b' ' as c_int);
        }
    }
}

unsafe fn arg_print(real: *const ArgpOption, req_fmt: &CStr, opt_fmt: &CStr, stream: *mut FmtStream) {
    unsafe {
        if !(*real).arg.is_null() {
            let a = cstr((*real).arg);
            if (*real).flags & OPTION_ARG_OPTIONAL != 0 {
                (*stream).printf(opt_fmt, &[Arg::Str(a)]);
            } else {
                (*stream).printf(req_fmt, &[Arg::Str(a)]);
            }
        }
    }
}

struct HolHelpState {
    prev_entry: *mut HolEntry,
    sep_groups: bool,
    suppressed_dup_arg: bool,
}

struct PentryState {
    entry: *const HolEntry,
    stream: *mut FmtStream,
    hhstate: *mut HolHelpState,
    first: bool,
    state: *const ArgpState,
}

unsafe fn filter_doc(doc: *const c_char, key: c_int, argp: *const Argp, state: *const ArgpState) -> *const c_char {
    unsafe {
        if !argp.is_null()
            && let Some(f) = (*argp).help_filter
        {
            let input = argp_input(argp, state);
            f(key, doc, input) as *const c_char
        } else {
            doc
        }
    }
}

unsafe fn print_header(s: *const c_char, argp: *const Argp, pest: *mut PentryState) {
    unsafe {
        let tstr = s;
        let fstr = filter_doc(tstr, ARGP_KEY_HELP_HEADER, argp, (*pest).state);
        if !fstr.is_null() {
            if *fstr != 0 {
                if !(*(*pest).hhstate).prev_entry.is_null() {
                    (*(*pest).stream).putc(b'\n' as c_int);
                }
                indent_to((*pest).stream, up(HEADER_COL) as c_uint);
                (*(*pest).stream).set_lmargin(up(HEADER_COL) as usize);
                (*(*pest).stream).set_wmargin(up(HEADER_COL) as isize);
                (*(*pest).stream).puts(fstr);
                (*(*pest).stream).set_lmargin(0);
                (*(*pest).stream).putc(b'\n' as c_int);
            }
            (*(*pest).hhstate).sep_groups = true;
        }
        if fstr != tstr {
            rusty_libc_malloc::free(fstr as *mut c_void);
        }
    }
}

unsafe fn hol_cluster_is_child(mut cl1: *const HolCluster, cl2: *const HolCluster) -> bool {
    unsafe {
        while !cl1.is_null() && cl1 != cl2 {
            cl1 = (*cl1).parent;
        }
        cl1 == cl2
    }
}

unsafe fn comma(col: c_uint, pest: *mut PentryState) {
    unsafe {
        if (*pest).first {
            let pe = (*(*pest).hhstate).prev_entry;
            let cl = (*(*pest).entry).cluster;
            if (*(*pest).hhstate).sep_groups && !pe.is_null() && (*(*pest).entry).group != (*pe).group {
                (*(*pest).stream).putc(b'\n' as c_int);
            }
            if !cl.is_null() && !(*cl).header.is_null() && *(*cl).header != 0 && (pe.is_null() || ((*pe).cluster != cl && !hol_cluster_is_child((*pe).cluster, cl))) {
                let old_wm = (*(*pest).stream).wmargin;
                print_header((*cl).header, (*cl).argp, pest);
                (*(*pest).stream).set_wmargin(old_wm);
            }
            (*pest).first = false;
        } else {
            (*(*pest).stream).puts(c", ".as_ptr());
        }
        indent_to((*pest).stream, col);
    }
}

unsafe fn hol_entry_help(entry: *mut HolEntry, state: *const ArgpState, stream: *mut FmtStream, hhstate: *mut HolHelpState) {
    unsafe {
        let real = (*entry).opt;
        let mut so = (*entry).short_options;
        let mut have_long_opt = false;
        let old_lm = (*stream).set_lmargin(0);
        let old_wm = (*stream).wmargin;
        let mut pest = PentryState { entry, stream, hhstate, first: true, state };
        let pest_p: *mut PentryState = &mut pest;
        if !odoc(real) {
            let mut opt = real;
            let mut num = (*entry).num;
            while num > 0 {
                if !(*opt).name.is_null() && ovisible(opt) {
                    have_long_opt = true;
                    break;
                }
                opt = opt.add(1);
                num -= 1;
            }
        }
        (*stream).set_wmargin(up(SHORT_OPT_COL) as isize);
        let mut opt = real;
        let mut num = (*entry).num;
        while num > 0 {
            if oshort(opt) && (*opt).key == *so as c_int {
                if ovisible(opt) {
                    comma(up(SHORT_OPT_COL) as c_uint, pest_p);
                    (*stream).putc(b'-' as c_int);
                    (*stream).putc(*so as c_int);
                    if !have_long_opt || up(DUP_ARGS) != 0 {
                        arg_print(real, c" %s", c"[%s]", stream);
                    } else if !(*real).arg.is_null() {
                        (*hhstate).suppressed_dup_arg = true;
                    }
                }
                so = so.add(1);
            }
            opt = opt.add(1);
            num -= 1;
        }
        if odoc(real) {
            (*stream).set_wmargin(up(DOC_OPT_COL) as isize);
            let mut opt = real;
            let mut num = (*entry).num;
            while num > 0 {
                if !(*opt).name.is_null() && ovisible(opt) {
                    comma(up(DOC_OPT_COL) as c_uint, pest_p);
                    (*stream).puts((*opt).name);
                }
                opt = opt.add(1);
                num -= 1;
            }
        } else {
            (*stream).set_wmargin(up(LONG_OPT_COL) as isize);
            let mut opt = real;
            let mut num = (*entry).num;
            while num > 0 {
                if !(*opt).name.is_null() && ovisible(opt) {
                    comma(up(LONG_OPT_COL) as c_uint, pest_p);
                    (*stream).printf(c"--%s", &[Arg::Str(cstr((*opt).name))]);
                    arg_print(real, c"=%s", c"[=%s]", stream);
                }
                opt = opt.add(1);
                num -= 1;
            }
        }
        (*stream).set_lmargin(0);
        if pest.first {
            if !oshort(real) && (*real).name.is_null() {
                print_header((*real).doc, (*entry).argp, pest_p);
            } else {
                (*stream).set_lmargin(old_lm);
                (*stream).set_wmargin(old_wm);
                return;
            }
        } else {
            let tstr = (*real).doc;
            let fstr = filter_doc(tstr, (*real).key, (*entry).argp, state);
            if !fstr.is_null() && *fstr != 0 {
                let col = (*stream).point() as c_uint;
                (*stream).set_lmargin(up(OPT_DOC_COL) as usize);
                (*stream).set_wmargin(up(OPT_DOC_COL) as isize);
                if col > (up(OPT_DOC_COL) + 3) as c_uint {
                    (*stream).putc(b'\n' as c_int);
                } else if col >= up(OPT_DOC_COL) as c_uint {
                    (*stream).puts(c"   ".as_ptr());
                } else {
                    indent_to(stream, up(OPT_DOC_COL) as c_uint);
                }
                (*stream).puts(fstr);
            }
            if !fstr.is_null() && fstr != tstr {
                rusty_libc_malloc::free(fstr as *mut c_void);
            }
            (*stream).set_lmargin(0);
            (*stream).putc(b'\n' as c_int);
        }
        (*hhstate).prev_entry = entry;
        (*stream).set_lmargin(old_lm);
        (*stream).set_wmargin(old_wm);
    }
}

unsafe fn hol_help(hol: *mut Hol, state: *const ArgpState, stream: *mut FmtStream) {
    unsafe {
        let mut hhstate = HolHelpState { prev_entry: null_mut(), sep_groups: false, suppressed_dup_arg: false };
        let mut entry = (*hol).entries;
        let mut num = (*hol).num_entries;
        while num > 0 {
            hol_entry_help(entry, state, stream, &mut hhstate);
            entry = entry.add(1);
            num -= 1;
        }
        if hhstate.suppressed_dup_arg && up(DUP_ARGS_NOTE) != 0 {
            let tstr = c"Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.".as_ptr();
            let fstr = filter_doc(tstr, ARGP_KEY_HELP_DUP_ARGS_NOTE, if state.is_null() { null() } else { (*state).root_argp }, state);
            if !fstr.is_null() && *fstr != 0 {
                (*stream).putc(b'\n' as c_int);
                (*stream).puts(fstr);
                (*stream).putc(b'\n' as c_int);
            }
            if !fstr.is_null() && fstr != tstr {
                rusty_libc_malloc::free(fstr as *mut c_void);
            }
        }
    }
}

struct SnaoCookie {
    end: *mut u8,
}

unsafe fn add_argless_short_opt(opt: *const ArgpOption, real: *const ArgpOption, cookie: *mut c_void) -> c_int {
    unsafe {
        let c = cookie as *mut SnaoCookie;
        if !(!(*opt).arg.is_null() || !(*real).arg.is_null()) && ((*opt).flags | (*real).flags) & OPTION_NO_USAGE == 0 {
            *(*c).end = (*opt).key as u8;
            (*c).end = (*c).end.add(1);
        }
        0
    }
}

unsafe fn usage_argful_short_opt(opt: *const ArgpOption, real: *const ArgpOption, cookie: *mut c_void) -> c_int {
    unsafe {
        let stream = cookie as *mut FmtStream;
        let mut arg = (*opt).arg;
        let flags = (*opt).flags | (*real).flags;
        if arg.is_null() {
            arg = (*real).arg;
        }
        if !arg.is_null() && flags & OPTION_NO_USAGE == 0 {
            if flags & OPTION_ARG_OPTIONAL != 0 {
                (*stream).printf(c" [-%c[%s]]", &[Arg::Int(i64::from((*opt).key)), Arg::Str(cstr(arg))]);
            } else {
                space(stream, 6 + slen(arg));
                (*stream).printf(c"[-%c %s]", &[Arg::Int(i64::from((*opt).key)), Arg::Str(cstr(arg))]);
            }
        }
        0
    }
}

unsafe fn usage_long_opt(opt: *const ArgpOption, real: *const ArgpOption, cookie: *mut c_void) -> c_int {
    unsafe {
        let stream = cookie as *mut FmtStream;
        let mut arg = (*opt).arg;
        let flags = (*opt).flags | (*real).flags;
        if arg.is_null() {
            arg = (*real).arg;
        }
        if flags & OPTION_NO_USAGE == 0 {
            let name = Arg::Str(cstr((*opt).name));
            if !arg.is_null() {
                if flags & OPTION_ARG_OPTIONAL != 0 {
                    (*stream).printf(c" [--%s[=%s]]", &[name, Arg::Str(cstr(arg))]);
                } else {
                    (*stream).printf(c" [--%s=%s]", &[name, Arg::Str(cstr(arg))]);
                }
            } else {
                (*stream).printf(c" [--%s]", &[name]);
            }
        }
        0
    }
}

unsafe fn hol_usage(hol: *mut Hol, stream: *mut FmtStream) {
    unsafe {
        if (*hol).num_entries > 0 {
            let mut buf = rusty_libc_malloc::malloc(slen((*hol).short_options as *const c_char) + 2) as *mut u8;
            let start = buf;
            let mut cookie = SnaoCookie { end: buf };
            let mut entry = (*hol).entries;
            for _ in 0..(*hol).num_entries {
                hol_entry_short_iterate(entry, add_argless_short_opt, (&raw mut cookie).cast());
                entry = entry.add(1);
            }
            if cookie.end > start {
                *cookie.end = 0;
                (*stream).printf(c" [-%s]", &[Arg::Str(CStr::from_ptr(start as *const c_char))]);
            }
            buf = start;
            let mut entry = (*hol).entries;
            for _ in 0..(*hol).num_entries {
                hol_entry_short_iterate(entry, usage_argful_short_opt, stream.cast());
                entry = entry.add(1);
            }
            let mut entry = (*hol).entries;
            for _ in 0..(*hol).num_entries {
                hol_entry_long_iterate(entry, usage_long_opt, stream.cast());
                entry = entry.add(1);
            }
            rusty_libc_malloc::free(buf.cast());
        }
    }
}

unsafe fn argp_args_levels(argp: *const Argp) -> usize {
    unsafe {
        let mut levels = 0;
        let mut child = (*argp).children;
        if !(*argp).args_doc.is_null() && !rusty_libc_mem::strchr((*argp).args_doc, b'\n' as c_int).is_null() {
            levels += 1;
        }
        if !child.is_null() {
            while !(*child).argp.is_null() {
                levels += argp_args_levels((*child).argp);
                child = child.add(1);
            }
        }
        levels
    }
}

unsafe fn argp_args_usage(argp: *const Argp, state: *const ArgpState, levels: &mut *mut u8, mut advance: bool, stream: *mut FmtStream) -> bool {
    unsafe {
        let our_level = *levels;
        let mut multiple = false;
        let mut child = (*argp).children;
        let tdoc = (*argp).args_doc;
        let mut nl: *const c_char = null();
        let fdoc = filter_doc(tdoc, ARGP_KEY_HELP_ARGS_DOC, argp, state);
        if !fdoc.is_null() {
            let mut cp = fdoc;
            nl = rusty_libc_mem::strchrnul(cp, b'\n' as c_int);
            if *nl != 0 {
                multiple = true;
                for _ in 0..*our_level {
                    cp = nl.add(1);
                    nl = rusty_libc_mem::strchrnul(cp, b'\n' as c_int);
                }
                *levels = (*levels).add(1);
            }
            space(stream, 1 + nl.offset_from(cp) as usize);
            (*stream).write(core::slice::from_raw_parts(cp as *const u8, nl.offset_from(cp) as usize));
        }
        if !fdoc.is_null() && fdoc != tdoc {
            rusty_libc_malloc::free(fdoc as *mut c_void);
        }
        if !child.is_null() {
            while !(*child).argp.is_null() {
                advance = !argp_args_usage((*child).argp, state, levels, advance, stream);
                child = child.add(1);
            }
        }
        if advance && multiple {
            if *nl != 0 {
                *our_level += 1;
                advance = false;
            } else if *our_level > 0 {
                *our_level = 0;
            }
        }
        !advance
    }
}

unsafe fn argp_doc(argp: *const Argp, state: *const ArgpState, post: bool, pre_blank: bool, first_only: bool, stream: *mut FmtStream) -> bool {
    unsafe {
        let mut inp_text: *const c_char;
        let mut input: *mut c_void = null_mut();
        let mut anything = false;
        let mut inp_text_limit = 0usize;
        let doc = (*argp).doc;
        let mut child = (*argp).children;
        if !doc.is_null() {
            let vt = rusty_libc_mem::strchr(doc, 0x0b);
            inp_text = if post {
                if !vt.is_null() { vt.add(1) } else { null() }
            } else {
                doc
            };
            inp_text_limit = if !post && !vt.is_null() { vt.offset_from(doc) as usize } else { 0 };
        } else {
            inp_text = null();
        }
        let text: *const c_char;
        if let Some(f) = (*argp).help_filter {
            if inp_text_limit != 0 {
                inp_text = rusty_libc_malloc::strndup(inp_text, inp_text_limit);
            }
            input = argp_input(argp, state);
            text = f(if post { ARGP_KEY_HELP_POST_DOC } else { ARGP_KEY_HELP_PRE_DOC }, inp_text, input) as *const c_char;
        } else {
            text = inp_text;
        }
        if !text.is_null() {
            if pre_blank {
                (*stream).putc(b'\n' as c_int);
            }
            if text == inp_text && inp_text_limit != 0 {
                (*stream).write(core::slice::from_raw_parts(inp_text as *const u8, inp_text_limit));
            } else {
                (*stream).puts(text);
            }
            if (*stream).point() > (*stream).lmargin {
                (*stream).putc(b'\n' as c_int);
            }
            anything = true;
        }
        if !text.is_null() && text != inp_text {
            rusty_libc_malloc::free(text as *mut c_void);
        }
        if !inp_text.is_null() && inp_text_limit != 0 && (*argp).help_filter.is_some() {
            rusty_libc_malloc::free(inp_text as *mut c_void);
        }
        if post && let Some(f) = (*argp).help_filter {
            let text = f(ARGP_KEY_HELP_EXTRA, null(), input);
            if !text.is_null() {
                if anything || pre_blank {
                    (*stream).putc(b'\n' as c_int);
                }
                (*stream).puts(text);
                rusty_libc_malloc::free(text.cast());
                if (*stream).point() > (*stream).lmargin {
                    (*stream).putc(b'\n' as c_int);
                }
                anything = true;
            }
        }
        if !child.is_null() {
            while !(*child).argp.is_null() && !(first_only && anything) {
                anything |= argp_doc((*child).argp, state, post, anything || pre_blank, first_only, stream);
                child = child.add(1);
            }
        }
        anything
    }
}

unsafe fn help_inner(argp: *const Argp, state: *const ArgpState, stream: *mut File, flags: c_uint, name: *const c_char) {
    unsafe {
        let mut flags = flags;
        let mut anything = false;
        let mut hol: *mut Hol = null_mut();
        if stream.is_null() {
            return;
        }
        rusty_libc_stdio::flockfile(stream);
        fill_in_uparams(state);
        let fs = FmtStream::new(stream, 0, up(RMARGIN) as usize, 0);
        if fs.is_null() {
            rusty_libc_stdio::funlockfile(stream);
            return;
        }
        if flags & (ARGP_HELP_USAGE | ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG) != 0 {
            hol = argp_hol(argp, null_mut());
            hol_set_group(hol, c"help", -1);
            hol_set_group(hol, c"version", -1);
            hol_sort(hol);
        }
        if flags & (ARGP_HELP_USAGE | ARGP_HELP_SHORT_USAGE) != 0 {
            let mut first_pattern = true;
            let num_pattern_levels = argp_args_levels(argp);
            let pattern_levels = rusty_libc_malloc::calloc(num_pattern_levels.max(1), 1) as *mut u8;
            loop {
                let old_wm = (*fs).set_wmargin(up(USAGE_INDENT) as isize);
                let mut levels = pattern_levels;
                if first_pattern {
                    (*fs).printf(c"%s %s", &[Arg::Str(c"Usage:"), Arg::Str(cstr(name))]);
                } else {
                    (*fs).printf(c"%s %s", &[Arg::Str(c"  or: "), Arg::Str(cstr(name))]);
                }
                let old_lm = (*fs).set_lmargin(up(USAGE_INDENT) as usize);
                if flags & ARGP_HELP_SHORT_USAGE != 0 {
                    if (*hol).num_entries > 0 {
                        (*fs).puts(c" [OPTION...]".as_ptr());
                    }
                } else {
                    hol_usage(hol, fs);
                    flags |= ARGP_HELP_SHORT_USAGE;
                }
                let more_patterns = argp_args_usage(argp, state, &mut levels, true, fs);
                (*fs).set_wmargin(old_wm);
                (*fs).set_lmargin(old_lm);
                (*fs).putc(b'\n' as c_int);
                anything = true;
                first_pattern = false;
                if !more_patterns {
                    break;
                }
            }
            rusty_libc_malloc::free(pattern_levels.cast());
        }
        if flags & ARGP_HELP_PRE_DOC != 0 {
            anything |= argp_doc(argp, state, false, false, true, fs);
        }
        if flags & ARGP_HELP_SEE != 0 {
            (*fs).printf(c"Try `%s --help' or `%s --usage' for more information.\n", &[Arg::Str(cstr(name)), Arg::Str(cstr(name))]);
            anything = true;
        }
        if flags & ARGP_HELP_LONG != 0 && (*hol).num_entries > 0 {
            if anything {
                (*fs).putc(b'\n' as c_int);
            }
            hol_help(hol, state, fs);
            anything = true;
        }
        if flags & ARGP_HELP_POST_DOC != 0 {
            anything |= argp_doc(argp, state, true, anything, false, fs);
        }
        if flags & ARGP_HELP_BUG_ADDR != 0 && !argp_program_bug_address.is_null() {
            if anything {
                (*fs).putc(b'\n' as c_int);
            }
            (*fs).printf(c"Report bugs to %s.\n", &[Arg::Str(cstr(argp_program_bug_address))]);
        }
        rusty_libc_stdio::funlockfile(stream);
        if !hol.is_null() {
            hol_free(hol);
        }
        FmtStream::free(fs);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_help(argp: *const Argp, stream: *mut File, flags: c_uint, name: *mut c_char) {
    unsafe { help_inner(argp, null(), stream, flags, name) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_state_help(state: *const ArgpState, stream: *mut File, flags: c_uint) {
    unsafe {
        if (state.is_null() || (*state).flags & ARGP_NO_ERRS == 0) && !stream.is_null() {
            let mut flags = flags;
            if !state.is_null() && (*state).flags & ARGP_LONG_ONLY != 0 {
                flags |= ARGP_HELP_LONG_ONLY;
            }
            help_inner(if state.is_null() { null() } else { (*state).root_argp }, state, stream, flags, if state.is_null() { short_program_name() } else { (*state).name });
            if state.is_null() || (*state).flags & ARGP_NO_EXIT == 0 {
                if flags & ARGP_HELP_EXIT_ERR != 0 {
                    flush_exit(argp_err_exit_status);
                }
                if flags & ARGP_HELP_EXIT_OK != 0 {
                    flush_exit(0);
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_usage(state: *const ArgpState) {
    unsafe { argp_state_help(state, rusty_libc_stdio::stderr, ARGP_HELP_STD_USAGE) }
}

struct Collect {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            if self.len + bytes.len() + 1 > self.cap {
                let ncap = (self.len + bytes.len() + 1).max(self.cap * 2).max(128);
                let np = rusty_libc_malloc::realloc(self.p.cast(), ncap) as *mut u8;
                if np.is_null() {
                    return false;
                }
                self.p = np;
                self.cap = ncap;
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.p.add(self.len), bytes.len());
            self.len += bytes.len();
            *self.p.add(self.len) = 0;
            true
        }
    }
}

unsafe fn vformat(fmt: *const c_char, ap: &mut core::ffi::VaList) -> Option<Collect> {
    unsafe {
        let mut c = Collect { p: null_mut(), len: 0, cap: 0 };
        if rusty_libc_stdio::printf_api::run(&mut c, fmt, ap) < 0 {
            rusty_libc_malloc::free(c.p.cast());
            return None;
        }
        if c.p.is_null() {
            c.put(b"");
        }
        Some(c)
    }
}

unsafe fn name_of(state: *const ArgpState) -> *const c_char {
    unsafe { if state.is_null() { short_program_name() } else { (*state).name } }
}

unsafe fn error_str(state: *const ArgpState, msg: &[u8]) {
    unsafe {
        if state.is_null() || (*state).flags & ARGP_NO_ERRS == 0 {
            let stream = if state.is_null() { rusty_libc_stdio::stderr } else { (*state).err_stream };
            if !stream.is_null() {
                rusty_libc_stdio::flockfile(stream);
                out(stream, &[cstr(name_of(state)).to_bytes(), b": ", msg, b"\n"]);
                argp_state_help(state, stream, ARGP_HELP_STD_ERR);
                rusty_libc_stdio::funlockfile(stream);
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_error(state: *const ArgpState, fmt: *const c_char, mut args: ...) {
    unsafe {
        if state.is_null() || (*state).flags & ARGP_NO_ERRS == 0 {
            let stream = if state.is_null() { rusty_libc_stdio::stderr } else { (*state).err_stream };
            if !stream.is_null() {
                let ap: &mut core::ffi::VaList = &mut args;
                let c = vformat(fmt, ap);
                let msg: &[u8] = match &c {
                    Some(c) if !c.p.is_null() => core::slice::from_raw_parts(c.p, c.len),
                    _ => b"(null)",
                };
                error_str(state, msg);
                if let Some(c) = c {
                    rusty_libc_malloc::free(c.p.cast());
                }
            }
        }
    }
}

fn strerror_bytes(code: c_int) -> &'static [u8] {
    match rusty_libc_core::messages::error_message(code) {
        Some(m) => m.to_bytes(),
        None => b"Unknown error",
    }
}

unsafe fn failure_str(state: *const ArgpState, status: c_int, errnum: c_int, msg: Option<&[u8]>) {
    unsafe {
        if state.is_null() || (*state).flags & ARGP_NO_ERRS == 0 {
            let stream = if state.is_null() { rusty_libc_stdio::stderr } else { (*state).err_stream };
            if !stream.is_null() {
                rusty_libc_stdio::flockfile(stream);
                out(stream, &[cstr(name_of(state)).to_bytes()]);
                if let Some(m) = msg {
                    out(stream, &[b": ", m]);
                }
                if errnum != 0 {
                    out(stream, &[b": ", strerror_bytes(errnum)]);
                }
                out(stream, &[b"\n"]);
                rusty_libc_stdio::funlockfile(stream);
                if status != 0 && (state.is_null() || (*state).flags & ARGP_NO_EXIT == 0) {
                    flush_exit(status);
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_failure(state: *const ArgpState, status: c_int, errnum: c_int, fmt: *const c_char, mut args: ...) {
    unsafe {
        if state.is_null() || (*state).flags & ARGP_NO_ERRS == 0 {
            let stream = if state.is_null() { rusty_libc_stdio::stderr } else { (*state).err_stream };
            if !stream.is_null() {
                if fmt.is_null() {
                    failure_str(state, status, errnum, None);
                } else {
                    let ap: &mut core::ffi::VaList = &mut args;
                    let c = vformat(fmt, ap);
                    let msg: &[u8] = match &c {
                        Some(c) if !c.p.is_null() => core::slice::from_raw_parts(c.p, c.len),
                        _ => b"(null)",
                    };
                    failure_str(state, status, errnum, Some(msg));
                    if let Some(c) = c {
                        rusty_libc_malloc::free(c.p.cast());
                    }
                }
            }
        }
    }
}

const KEY_END: c_int = -1;
const KEY_ARG: c_int = 1;
const KEY_ERR: c_int = b'?' as c_int;
const GROUP_BITS: u32 = 8;
const USER_BITS: u32 = 32 - GROUP_BITS;
const USER_MASK: c_int = (1 << USER_BITS) - 1;

const OPT_PROGNAME: c_int = -2;
const OPT_USAGE: c_int = -3;
const OPT_HANG: c_int = -4;

struct SyncArr<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArr<T, N> {}

macro_rules! opt {
    ($name:expr, $key:expr, $arg:expr, $flags:expr, $doc:expr, $group:expr) => {
        ArgpOption { name: $name, key: $key, arg: $arg, flags: $flags, doc: $doc, group: $group }
    };
}

static ARGP_DEFAULT_OPTIONS: SyncArr<ArgpOption, 5> = SyncArr([
    opt!(c"help".as_ptr(), b'?' as c_int, null(), 0, c"Give this help list".as_ptr(), -1),
    opt!(c"usage".as_ptr(), OPT_USAGE, null(), 0, c"Give a short usage message".as_ptr(), 0),
    opt!(c"program-name".as_ptr(), OPT_PROGNAME, c"NAME".as_ptr(), OPTION_HIDDEN, c"Set the program name".as_ptr(), 0),
    opt!(c"HANG".as_ptr(), OPT_HANG, c"SECS".as_ptr(), OPTION_ARG_OPTIONAL | OPTION_HIDDEN, c"Hang for SECS seconds (default 3600)".as_ptr(), 0),
    opt!(null(), 0, null(), 0, null(), 0),
]);

static ARGP_VERSION_OPTIONS: SyncArr<ArgpOption, 2> = SyncArr([opt!(c"version".as_ptr(), b'V' as c_int, null(), 0, c"Print program version".as_ptr(), -1), opt!(null(), 0, null(), 0, null(), 0)]);

struct SyncArgp(Argp);
unsafe impl Sync for SyncArgp {}

static mut ARGP_HANG: c_int = 0;

unsafe extern "C" fn argp_default_parser(key: c_int, arg: *mut c_char, state: *mut ArgpState) -> c_int {
    unsafe {
        match key {
            63 => argp_state_help(state, (*state).out_stream, ARGP_HELP_STD_HELP),
            OPT_USAGE => argp_state_help(state, (*state).out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK),
            OPT_PROGNAME => {
                program_invocation_name = arg;
                let s = rusty_libc_mem::strrchr(arg, b'/' as c_int);
                (*state).name = if s.is_null() { arg } else { s.add(1) };
                program_invocation_short_name = (*state).name;
                if (*state).flags & (ARGP_PARSE_ARGV0 | ARGP_NO_ERRS) == ARGP_PARSE_ARGV0 {
                    *(*state).argv = arg;
                }
            }
            OPT_HANG => {
                ARGP_HANG = if arg.is_null() { 3600 } else { rusty_libc_stdlib::num::strtol(arg, null_mut(), 10) as c_int };
                while ARGP_HANG > 0 {
                    ARGP_HANG -= 1;
                    rusty_libc_time::clock::sleep(1);
                }
            }
            _ => return EBADKEY,
        }
        0
    }
}

static ARGP_DEFAULT_ARGP: SyncArgp = SyncArgp(Argp { options: ARGP_DEFAULT_OPTIONS.0.as_ptr(), parser: Some(argp_default_parser), args_doc: null(), doc: null(), children: null(), help_filter: None, argp_domain: c"libc".as_ptr() });

unsafe extern "C" fn argp_version_parser(key: c_int, _arg: *mut c_char, state: *mut ArgpState) -> c_int {
    unsafe {
        match key {
            86 => {
                if let Some(h) = argp_program_version_hook {
                    h((*state).out_stream, state);
                } else if !argp_program_version.is_null() {
                    out((*state).out_stream, &[cstr(argp_program_version).to_bytes(), b"\n"]);
                } else {
                    argp_error(state, c"%s".as_ptr(), c"(PROGRAM ERROR) No version known!?".as_ptr());
                }
                if (*state).flags & ARGP_NO_EXIT == 0 {
                    flush_exit(0);
                }
            }
            _ => return EBADKEY,
        }
        0
    }
}

static ARGP_VERSION_ARGP: SyncArgp = SyncArgp(Argp { options: ARGP_VERSION_OPTIONS.0.as_ptr(), parser: Some(argp_version_parser), args_doc: null(), doc: null(), children: null(), help_filter: None, argp_domain: c"libc".as_ptr() });

unsafe fn find_long_option(long_options: *mut COption, name: *const c_char) -> c_int {
    unsafe {
        let mut l = long_options;
        while !(*l).name.is_null() {
            if !name.is_null() && rusty_libc_mem::strcmp((*l).name, name) == 0 {
                return l.offset_from(long_options) as c_int;
            }
            l = l.add(1);
        }
        if name.is_null() { l.offset_from(long_options) as c_int } else { -1 }
    }
}

struct Group {
    parser: Option<ArgpParser>,
    argp: *const Argp,
    short_end: *mut u8,
    args_processed: c_uint,
    parent: *mut Group,
    parent_index: c_uint,
    input: *mut c_void,
    child_inputs: *mut *mut c_void,
    hook: *mut c_void,
}

unsafe fn group_parse(group: *mut Group, state: *mut ArgpState, key: c_int, arg: *mut c_char) -> c_int {
    unsafe {
        if let Some(p) = (*group).parser {
            (*state).hook = (*group).hook;
            (*state).input = (*group).input;
            (*state).child_inputs = (*group).child_inputs;
            (*state).arg_num = (*group).args_processed;
            let err = p(key, arg, state);
            (*group).hook = (*state).hook;
            err
        } else {
            EBADKEY
        }
    }
}

struct Parser {
    argp: *const Argp,
    short_opts: *mut u8,
    long_opts: *mut COption,
    opt_data: Data,
    groups: *mut Group,
    egroup: *mut Group,
    child_inputs: *mut *mut c_void,
    try_getopt: bool,
    state: ArgpState,
    storage: *mut u8,
}

struct ConvertState {
    parser: *mut Parser,
    short_end: *mut u8,
    long_end: *mut COption,
    child_inputs_end: *mut *mut c_void,
}

unsafe fn convert_options(argp: *const Argp, mut parent: *mut Group, parent_index: c_uint, mut group: *mut Group, cvt: &mut ConvertState) -> *mut Group {
    unsafe {
        let mut real = (*argp).options;
        let mut children = (*argp).children;
        if !real.is_null() || (*argp).parser.is_some() {
            if !real.is_null() {
                let mut opt = real;
                while !oend(opt) {
                    if !oalias(opt) {
                        real = opt;
                    }
                    if !odoc(real) {
                        if oshort(opt) {
                            *cvt.short_end = (*opt).key as u8;
                            cvt.short_end = cvt.short_end.add(1);
                            if !(*real).arg.is_null() {
                                *cvt.short_end = b':';
                                cvt.short_end = cvt.short_end.add(1);
                                if (*real).flags & OPTION_ARG_OPTIONAL != 0 {
                                    *cvt.short_end = b':';
                                    cvt.short_end = cvt.short_end.add(1);
                                }
                            }
                            *cvt.short_end = 0;
                        }
                        if !(*opt).name.is_null() && find_long_option((*cvt.parser).long_opts, (*opt).name) < 0 {
                            (*cvt.long_end).name = (*opt).name;
                            (*cvt.long_end).has_arg = if !(*real).arg.is_null() {
                                if (*real).flags & OPTION_ARG_OPTIONAL != 0 { 2 } else { 1 }
                            } else {
                                0
                            };
                            (*cvt.long_end).flag = null_mut();
                            let key = if (*opt).key != 0 { (*opt).key } else { (*real).key };
                            (*cvt.long_end).val = (key & USER_MASK).wrapping_add(((group.offset_from((*cvt.parser).groups) as c_int) + 1) << USER_BITS);
                            cvt.long_end = cvt.long_end.add(1);
                            (*cvt.long_end).name = null();
                        }
                    }
                    opt = opt.add(1);
                }
            }
            (*group).parser = (*argp).parser;
            (*group).argp = argp;
            (*group).short_end = cvt.short_end;
            (*group).args_processed = 0;
            (*group).parent = parent;
            (*group).parent_index = parent_index;
            (*group).input = null_mut();
            (*group).hook = null_mut();
            (*group).child_inputs = null_mut();
            if !children.is_null() {
                let mut num_children = 0usize;
                while !(*children.add(num_children)).argp.is_null() {
                    num_children += 1;
                }
                (*group).child_inputs = cvt.child_inputs_end;
                cvt.child_inputs_end = cvt.child_inputs_end.add(num_children);
            }
            parent = group;
            group = group.add(1);
        } else {
            parent = null_mut();
        }
        if !children.is_null() {
            let mut index = 0;
            while !(*children).argp.is_null() {
                group = convert_options((*children).argp, parent, index, group, cvt);
                children = children.add(1);
                index += 1;
            }
        }
        group
    }
}

unsafe fn parser_convert(parser: *mut Parser, argp: *const Argp, flags: c_uint) {
    unsafe {
        let mut cvt = ConvertState { parser, short_end: (*parser).short_opts, long_end: (*parser).long_opts, child_inputs_end: (*parser).child_inputs };
        if flags & ARGP_IN_ORDER != 0 {
            *cvt.short_end = b'-';
            cvt.short_end = cvt.short_end.add(1);
        } else if flags & ARGP_NO_ARGS != 0 {
            *cvt.short_end = b'+';
            cvt.short_end = cvt.short_end.add(1);
        }
        *cvt.short_end = 0;
        (*cvt.long_end).name = null();
        (*parser).argp = argp;
        if !argp.is_null() {
            (*parser).egroup = convert_options(argp, null_mut(), 0, (*parser).groups, &mut cvt);
        } else {
            (*parser).egroup = (*parser).groups;
        }
    }
}

struct ParserSizes {
    short_len: usize,
    long_len: usize,
    num_groups: usize,
    num_child_inputs: usize,
}

unsafe fn calc_sizes(argp: *const Argp, szs: &mut ParserSizes) {
    unsafe {
        let mut child = (*argp).children;
        let mut opt = (*argp).options;
        if !opt.is_null() || (*argp).parser.is_some() {
            szs.num_groups += 1;
            if !opt.is_null() {
                let mut num_opts = 0;
                while !oend(opt) {
                    opt = opt.add(1);
                    num_opts += 1;
                }
                szs.short_len += num_opts * 3;
                szs.long_len += num_opts;
            }
        }
        if !child.is_null() {
            while !(*child).argp.is_null() {
                calc_sizes((*child).argp, szs);
                child = child.add(1);
                szs.num_child_inputs += 1;
            }
        }
    }
}

unsafe fn parser_init(parser: *mut Parser, argp: *const Argp, argc: c_int, argv: *mut *mut c_char, flags: c_uint, input: *mut c_void) -> c_int {
    unsafe {
        let mut err = 0;
        let mut szs = ParserSizes { short_len: if flags & ARGP_NO_ARGS != 0 { 0 } else { 1 }, long_len: 0, num_groups: 0, num_child_inputs: 0 };
        if !argp.is_null() {
            calc_sizes(argp, &mut szs);
        }
        let glen = (szs.num_groups + 1) * size_of::<Group>();
        let clen = szs.num_child_inputs * size_of::<*mut c_void>();
        let llen = (szs.long_len + 1) * size_of::<COption>();
        let slen_ = szs.short_len + 1;
        (*parser).storage = rusty_libc_malloc::malloc(glen + clen + llen + slen_) as *mut u8;
        if (*parser).storage.is_null() {
            return ENOMEM;
        }
        (*parser).groups = (*parser).storage as *mut Group;
        (*parser).child_inputs = (*parser).storage.add(glen) as *mut *mut c_void;
        (*parser).long_opts = (*parser).storage.add(glen + clen) as *mut COption;
        (*parser).short_opts = (*parser).storage.add(glen + clen + llen);
        (*parser).opt_data = Data::new();
        core::ptr::write_bytes((*parser).child_inputs as *mut u8, 0, clen);
        parser_convert(parser, argp, flags);
        core::ptr::write_bytes(&raw mut (*parser).state, 0, 1);
        (*parser).state.root_argp = (*parser).argp;
        (*parser).state.argc = argc;
        (*parser).state.argv = argv;
        (*parser).state.flags = flags;
        (*parser).state.err_stream = rusty_libc_stdio::stderr;
        (*parser).state.out_stream = rusty_libc_stdio::stdout;
        (*parser).state.next = 0;
        (*parser).state.pstate = parser.cast();
        (*parser).try_getopt = true;
        if (*parser).groups < (*parser).egroup {
            (*(*parser).groups).input = input;
        }
        let mut group = (*parser).groups;
        while group < (*parser).egroup && (err == 0 || err == EBADKEY) {
            if !(*group).parent.is_null() {
                (*group).input = *(*(*group).parent).child_inputs.add((*group).parent_index as usize);
            }
            if (*group).parser.is_none() && !(*(*group).argp).children.is_null() && !(*(*(*group).argp).children).argp.is_null() {
                *(*group).child_inputs = (*group).input;
            }
            err = group_parse(group, &raw mut (*parser).state, ARGP_KEY_INIT, null_mut());
            group = group.add(1);
        }
        if err == EBADKEY {
            err = 0;
        }
        if err != 0 {
            return err;
        }
        if (*parser).state.flags & ARGP_NO_ERRS != 0 {
            (*parser).opt_data.opterr = 0;
            if (*parser).state.flags & ARGP_PARSE_ARGV0 != 0 {
                (*parser).state.argv = (*parser).state.argv.sub(1);
                (*parser).state.argc += 1;
            }
        } else {
            (*parser).opt_data.opterr = 1;
        }
        if (*parser).state.argv == argv && !(*argv).is_null() {
            let short_name = rusty_libc_mem::strrchr(*argv, b'/' as c_int);
            (*parser).state.name = if short_name.is_null() { *argv } else { short_name.add(1) };
        } else {
            (*parser).state.name = short_program_name();
        }
        0
    }
}

unsafe fn parser_finalize(parser: *mut Parser, mut err: c_int, arg_ebadkey: bool, end_index: *mut c_int) -> c_int {
    unsafe {
        let st = &raw mut (*parser).state;
        if err == EBADKEY && arg_ebadkey {
            err = 0;
        }
        if err == 0 {
            if (*st).next == (*st).argc {
                let mut group = (*parser).groups;
                while group < (*parser).egroup && (err == 0 || err == EBADKEY) {
                    if (*group).args_processed == 0 {
                        err = group_parse(group, st, ARGP_KEY_NO_ARGS, null_mut());
                    }
                    group = group.add(1);
                }
                let mut group = (*parser).egroup.wrapping_sub(1);
                while group >= (*parser).groups && (err == 0 || err == EBADKEY) {
                    err = group_parse(group, st, ARGP_KEY_END, null_mut());
                    group = group.wrapping_sub(1);
                }
                if err == EBADKEY {
                    err = 0;
                }
                if !end_index.is_null() {
                    *end_index = (*st).next;
                }
            } else if !end_index.is_null() {
                *end_index = (*st).next;
            } else {
                if (*st).flags & ARGP_NO_ERRS == 0 && !(*st).err_stream.is_null() {
                    out((*st).err_stream, &[cstr((*st).name).to_bytes(), b": Too many arguments\n"]);
                }
                err = EBADKEY;
            }
        }
        if err != 0 {
            if err == EBADKEY {
                argp_state_help(st, (*st).err_stream, ARGP_HELP_STD_ERR);
            }
            let mut group = (*parser).groups;
            while group < (*parser).egroup {
                group_parse(group, st, ARGP_KEY_ERROR, null_mut());
                group = group.add(1);
            }
        } else {
            let mut group = (*parser).egroup.wrapping_sub(1);
            while group >= (*parser).groups && (err == 0 || err == EBADKEY) {
                err = group_parse(group, st, ARGP_KEY_SUCCESS, null_mut());
                group = group.wrapping_sub(1);
            }
            if err == EBADKEY {
                err = 0;
            }
        }
        let mut group = (*parser).egroup.wrapping_sub(1);
        while group >= (*parser).groups {
            group_parse(group, st, ARGP_KEY_FINI, null_mut());
            group = group.wrapping_sub(1);
        }
        if err == EBADKEY {
            err = EINVAL;
        }
        rusty_libc_malloc::free((*parser).storage.cast());
        err
    }
}

unsafe fn parser_parse_arg(parser: *mut Parser, val: *mut c_char) -> c_int {
    unsafe {
        let st = &raw mut (*parser).state;
        (*st).next -= 1;
        let index = (*st).next;
        let mut err = EBADKEY;
        let mut key = 0;
        let mut group = (*parser).groups;
        while group < (*parser).egroup && err == EBADKEY {
            (*st).next += 1;
            key = ARGP_KEY_ARG;
            err = group_parse(group, st, key, val);
            if err == EBADKEY {
                (*st).next -= 1;
                key = ARGP_KEY_ARGS;
                err = group_parse(group, st, key, null_mut());
            }
            group = group.add(1);
        }
        if err == 0 {
            if key == ARGP_KEY_ARGS {
                (*st).next = (*st).argc;
            }
            if (*st).next > index {
                group = group.sub(1);
                (*group).args_processed += ((*st).next - index) as c_uint;
            } else {
                (*parser).try_getopt = true;
            }
        }
        err
    }
}

unsafe fn parser_parse_opt(parser: *mut Parser, opt: c_int, val: *mut c_char) -> c_int {
    unsafe {
        let st = &raw mut (*parser).state;
        let group_key = opt >> USER_BITS;
        let mut err = EBADKEY;
        let optarg = (*parser).opt_data.optarg;
        let _ = val;
        if group_key == 0 {
            let short_index = rusty_libc_mem::strchr((*parser).short_opts as *const c_char, opt) as *mut u8;
            if !short_index.is_null() {
                let mut group = (*parser).groups;
                while group < (*parser).egroup {
                    if (*group).short_end > short_index {
                        err = group_parse(group, st, opt, optarg);
                        break;
                    }
                    group = group.add(1);
                }
            }
        } else {
            let user_key = (if opt & (1 << (USER_BITS - 1)) != 0 { !USER_MASK } else { 0 }) | (opt & USER_MASK);
            err = group_parse((*parser).groups.add((group_key - 1) as usize), st, user_key, optarg);
        }
        if err == EBADKEY {
            let bad = c"(PROGRAM ERROR) Option should have been recognized!?";
            if group_key == 0 {
                argp_error(st, c"-%c: %s".as_ptr(), opt, bad.as_ptr());
            } else {
                let mut long_opt = (*parser).long_opts;
                while (*long_opt).val != opt && !(*long_opt).name.is_null() {
                    long_opt = long_opt.add(1);
                }
                argp_error(st, c"--%s: %s".as_ptr(), if (*long_opt).name.is_null() { c"???".as_ptr() } else { (*long_opt).name }, bad.as_ptr());
            }
        }
        err
    }
}

unsafe fn parser_parse_next(parser: *mut Parser, arg_ebadkey: &mut bool) -> c_int {
    unsafe {
        let st = &raw mut (*parser).state;
        let mut opt: c_int;
        if (*st).quoted != 0 && (*st).next < (*st).quoted {
            (*st).quoted = 0;
        }
        if (*parser).try_getopt && (*st).quoted == 0 {
            (*parser).opt_data.optind = (*st).next;
            (*parser).opt_data.optopt = KEY_END;
            opt = getopt_internal_r((*st).argc, (*st).argv, (*parser).short_opts as *const c_char, (*parser).long_opts, null_mut(), (*st).flags & ARGP_LONG_ONLY != 0, &mut (*parser).opt_data, false);
            (*st).next = (*parser).opt_data.optind;
            if opt == KEY_END {
                (*parser).try_getopt = false;
                if (*st).next > 1 && rusty_libc_mem::strcmp(*(*st).argv.add(((*st).next - 1) as usize), c"--".as_ptr()) == 0 {
                    (*st).quoted = (*st).next;
                }
            } else if opt == KEY_ERR && (*parser).opt_data.optopt != KEY_END {
                *arg_ebadkey = false;
                return EBADKEY;
            }
        } else {
            opt = KEY_END;
        }
        if opt == KEY_END {
            if (*st).next >= (*st).argc || (*st).flags & ARGP_NO_ARGS != 0 {
                *arg_ebadkey = true;
                return EBADKEY;
            } else {
                opt = KEY_ARG;
                (*parser).opt_data.optarg = *(*st).argv.add((*st).next as usize);
                (*st).next += 1;
            }
        }
        let err = if opt == KEY_ARG { parser_parse_arg(parser, (*parser).opt_data.optarg) } else { parser_parse_opt(parser, opt, (*parser).opt_data.optarg) };
        if err == EBADKEY {
            *arg_ebadkey = opt == KEY_END || opt == KEY_ARG;
        }
        err
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(unused_assignments)]
pub unsafe extern "C" fn argp_parse(argp: *const Argp, argc: c_int, argv: *mut *mut c_char, flags: c_uint, end_index: *mut c_int, input: *mut c_void) -> c_int {
    unsafe {
        let mut argp = argp;
        let mut child = [ArgpChild { argp: null(), flags: 0, header: null(), group: 0 }, ArgpChild { argp: null(), flags: 0, header: null(), group: 0 }, ArgpChild { argp: null(), flags: 0, header: null(), group: 0 }, ArgpChild { argp: null(), flags: 0, header: null(), group: 0 }];
        let mut top_argp = Argp { options: null(), parser: None, args_doc: null(), doc: null(), children: child.as_ptr(), help_filter: None, argp_domain: null() };
        let mut arg_ebadkey = false;
        if flags & ARGP_NO_HELP == 0 {
            let mut ci = 0;
            if !argp.is_null() {
                child[ci].argp = argp;
                ci += 1;
            }
            child[ci].argp = &ARGP_DEFAULT_ARGP.0;
            ci += 1;
            if !argp_program_version.is_null() || (*(&raw const argp_program_version_hook)).is_some() {
                child[ci].argp = &ARGP_VERSION_ARGP.0;
                ci += 1;
            }
            let _ = ci;
            argp = &top_argp;
        }
        let _ = &mut top_argp;
        let mut parser = core::mem::MaybeUninit::<Parser>::zeroed();
        let p = parser.as_mut_ptr();
        let mut err = parser_init(p, argp, argc, argv, flags, input);
        if err == 0 {
            while err == 0 {
                err = parser_parse_next(p, &mut arg_ebadkey);
            }
            err = parser_finalize(p, err, arg_ebadkey, end_index);
        }
        err
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _argp_input(argp: *const Argp, state: *const ArgpState) -> *mut c_void {
    unsafe { argp_input(argp, state) }
}

unsafe fn argp_input(argp: *const Argp, state: *const ArgpState) -> *mut c_void {
    unsafe {
        if !state.is_null() {
            let parser = (*state).pstate as *mut Parser;
            let mut group = (*parser).groups;
            while group < (*parser).egroup {
                if (*group).argp == argp {
                    return (*group).input;
                }
                group = group.add(1);
            }
        }
        null_mut()
    }
}
