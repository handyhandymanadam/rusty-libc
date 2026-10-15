#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem::CVec;
use crate::fnmatch::fnmatch_bytes;
use crate::glob::{GLOB_NOCHECK, Glob, glob, globfree};
use crate::pwd::{Passwd, pwnam_into, pwuid_into};
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::{syscall, unistd};

pub const WRDE_DOOFFS: c_int = 1 << 0;
pub const WRDE_APPEND: c_int = 1 << 1;
pub const WRDE_NOCMD: c_int = 1 << 2;
pub const WRDE_REUSE: c_int = 1 << 3;
pub const WRDE_SHOWERR: c_int = 1 << 4;
pub const WRDE_UNDEF: c_int = 1 << 5;

pub const WRDE_NOSYS: c_int = -1;
pub const WRDE_NOSPACE: c_int = 1;
pub const WRDE_BADCHAR: c_int = 2;
pub const WRDE_BADVAL: c_int = 3;
pub const WRDE_CMDSUB: c_int = 4;
pub const WRDE_SYNTAX: c_int = 5;

#[repr(C)]
pub struct Wordexp {
    pub we_wordc: usize,
    pub we_wordv: *mut *mut c_char,
    pub we_offs: usize,
}

impl Wordexp {
    pub const fn new() -> Wordexp {
        Wordexp { we_wordc: 0, we_wordv: null_mut(), we_offs: 0 }
    }
}

impl Default for Wordexp {
    fn default() -> Self {
        Wordexp::new()
    }
}

type R = Result<(), c_int>;

fn at(w: &[u8], i: usize) -> u8 {
    w.get(i).copied().unwrap_or(0)
}

fn cs(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(n) => &b[..n],
        None => b,
    }
}

fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn is_space(c: u8) -> bool {
    c == b' ' || (9..=13).contains(&c)
}

fn in_set(set: &[u8], c: u8) -> bool {
    c == 0 || set.contains(&c)
}

fn utoa(mut n: u64, buf: &mut [u8; 21]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

mod words {
    use super::{R, WRDE_NOSPACE, Wordexp};
    use crate::cmem::CVec;
    use core::ffi::c_char;
    use core::ptr::null_mut;

    pub(super) struct W {
        buf: CVec<u8>,
        max: usize,
    }

    const W_CHUNK: usize = 100;

    impl W {
        pub(super) const fn new() -> W {
            W { buf: CVec::new(), max: 0 }
        }
        pub(super) fn empty() -> Result<W, i32> {
            let mut w = W::new();
            if !w.buf.reserve_total(1) || !w.buf.push(0) {
                return Err(WRDE_NOSPACE);
            }
            Ok(w)
        }
        pub(super) fn copy_of(b: &[u8]) -> Result<W, i32> {
            let mut w = W::new();
            if !w.buf.reserve_total(b.len() + 1) || !w.buf.extend(b) || !w.buf.push(0) {
                return Err(WRDE_NOSPACE);
            }
            w.max = b.len();
            Ok(w)
        }
        pub(super) fn is_null(&self) -> bool {
            self.buf.len() == 0
        }
        pub(super) fn bytes(&self) -> &[u8] {
            let s = self.buf.as_slice();
            if s.is_empty() { s } else { &s[..s.len() - 1] }
        }
        pub(super) fn len(&self) -> usize {
            self.bytes().len()
        }
        pub(super) fn cstr(&self) -> &[u8] {
            let s = self.buf.as_slice();
            if s.is_empty() { b"\0" } else { &s[..=super::cs(s).len()] }
        }
        pub(super) fn with_nul_mut(&mut self) -> &mut [u8] {
            self.buf.as_mut_slice()
        }
        pub(super) fn free(&mut self) {
            *self = W::new();
        }
        fn grow(&mut self, by: usize) -> bool {
            if !self.buf.reserve_total(1 + self.max + by) {
                self.free();
                return false;
            }
            self.max += by;
            true
        }
        pub(super) fn addchar(&mut self, ch: u8) -> bool {
            if self.len() == self.max && !self.grow(W_CHUNK) {
                return false;
            }
            self.put(&[ch])
        }
        fn put(&mut self, s: &[u8]) -> bool {
            if self.buf.len() > 0 {
                self.buf.resize(self.buf.len() - 1, 0);
            }
            self.buf.extend(s) && self.buf.push(0)
        }
        pub(super) fn addmem(&mut self, s: &[u8]) -> bool {
            if self.len() + s.len() > self.max {
                let grow = if 2 * s.len() > W_CHUNK { 2 * s.len() } else { W_CHUNK };
                if !self.grow(grow) {
                    return false;
                }
            }
            if self.max == 0 && s.is_empty() && self.is_null() {
                return false;
            }
            self.put(s)
        }
        pub(super) fn pop(&mut self) {
            let n = self.buf.len();
            self.buf.resize(n - 1, 0);
            if let Some(last) = self.buf.as_mut_slice().last_mut() {
                *last = 0;
            }
        }
        fn take(&mut self) -> *mut c_char {
            let b = core::mem::replace(&mut self.buf, CVec::new());
            self.max = 0;
            b.into_raw().0.cast()
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Pw(*mut Wordexp);

    impl Pw {
        pub(super) const NULL: Pw = Pw(null_mut());

        pub(super) unsafe fn new(p: *mut Wordexp) -> Pw {
            Pw(p)
        }
        pub(super) fn is_null(self) -> bool {
            self.0.is_null()
        }
        fn we<'a>(self) -> &'a mut Wordexp {
            debug_assert!(!self.0.is_null());
            unsafe { &mut *self.0 }
        }
        pub(super) fn wordc(self) -> usize {
            self.we().we_wordc
        }
        pub(super) fn add(self, word: &mut W) -> R {
            let mut tmp;
            let w = if word.is_null() {
                tmp = W::empty()?;
                &mut tmp
            } else {
                word
            };
            let we = self.we();
            let num_p = 2 + we.we_wordc + we.we_offs;
            let nv = unsafe { crate::cmem::realloc(we.we_wordv, core::mem::size_of::<*mut c_char>() * num_p) };
            if nv.is_null() {
                return Err(WRDE_NOSPACE);
            }
            we.we_wordv = nv;
            let at = we.we_offs + we.we_wordc;
            let s = w.take();
            unsafe { nv.wrapping_add(at).write(s) };
            we.we_wordc += 1;
            unsafe { nv.wrapping_add(at + 1).write(null_mut()) };
            Ok(())
        }
        pub(super) fn save(self) -> Wordexp {
            let we = self.we();
            Wordexp { we_wordc: we.we_wordc, we_wordv: we.we_wordv, we_offs: we.we_offs }
        }
        pub(super) fn restore(self, old: Wordexp) {
            *self.we() = old;
        }
        pub(super) fn set_wordc(self, n: usize) {
            self.we().we_wordc = n;
        }
        pub(super) fn fresh(self, n: usize, zero_offs: bool) -> bool {
            let we = self.we();
            let p = crate::cmem::calloc(n, core::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
            we.we_wordv = p;
            if p.is_null() {
                return false;
            }
            if zero_offs {
                we.we_offs = 0;
            }
            true
        }
        pub(super) fn offs(self) -> usize {
            self.we().we_offs
        }
        pub(super) fn free_words(self) {
            if self.0.is_null() {
                return;
            }
            let we = self.we();
            if we.we_wordv.is_null() {
                return;
            }
            let mut i = we.we_offs;
            loop {
                let w = unsafe { *we.we_wordv.wrapping_add(i) };
                if w.is_null() {
                    break;
                }
                unsafe { crate::cmem::free(w) };
                i += 1;
            }
            unsafe { crate::cmem::free(we.we_wordv) };
            we.we_wordv = null_mut();
        }
        pub(super) fn word<'a>(self, i: usize) -> &'a [u8] {
            let we = self.we();
            assert!(i < we.we_wordc);
            let p = unsafe { *we.we_wordv.wrapping_add(we.we_offs + i) };
            unsafe { rusty_libc_core::ffi::cstr_nonnull(p) }.to_bytes_with_nul()
        }
    }
}

use words::{Pw, W};

fn nospace_if_null(w: &W) -> R {
    if w.is_null() { Err(WRDE_NOSPACE) } else { Ok(()) }
}

fn ok_or_nospace(ok: bool) -> R {
    if ok { Ok(()) } else { Err(WRDE_NOSPACE) }
}

fn wcopy(b: &[u8]) -> Result<W, c_int> {
    W::copy_of(b)
}

#[derive(Clone, Copy)]
struct Cx<'a> {
    flags: c_int,
    ifs: &'a [u8],
    white: &'a [u8],
}

fn args() -> (c_int, *mut *mut c_char) {
    crate::err::args()
}

fn argv_at<'a>(i: usize) -> Option<&'a [u8]> {
    let (argc, argv) = args();
    if argv.is_null() || argc <= 0 {
        return None;
    }
    let p = unsafe { *argv.wrapping_add(i) };
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(CStr::to_bytes)
}

fn getenv_bytes(name: &[u8]) -> Option<&'static [u8]> {
    crate::cmem::getenv(name)
}

fn parse_backslash(word: &mut W, words: &[u8], offset: &mut usize) -> R {
    match at(words, 1 + *offset) {
        0 => Err(WRDE_SYNTAX),
        b'\n' => {
            *offset += 1;
            Ok(())
        }
        c => {
            ok_or_nospace(word.addchar(c))?;
            *offset += 1;
            Ok(())
        }
    }
}

fn parse_qtd_backslash(word: &mut W, words: &[u8], offset: &mut usize) -> R {
    match at(words, 1 + *offset) {
        0 => Err(WRDE_SYNTAX),
        b'\n' => {
            *offset += 1;
            Ok(())
        }
        c @ (b'$' | b'`' | b'"' | b'\\') => {
            ok_or_nospace(word.addchar(c))?;
            *offset += 1;
            Ok(())
        }
        c => {
            ok_or_nospace(word.addchar(words[*offset]) && word.addchar(c))?;
            *offset += 1;
            Ok(())
        }
    }
}

fn home_of(user: Option<&[u8]>) -> Result<Option<W>, c_int> {
    let name = match user {
        Some(u) => Some(wcopy(u)?),
        None => None,
    };
    let uid = unistd::getuid();
    let mut len = 1024usize;
    let mut buf: CVec<u8> = CVec::new();
    let mut pwd = Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() };
    let found = loop {
        if !buf.resize(len, 0) {
            return Err(WRDE_NOSPACE);
        }
        let r = match &name {
            Some(n) => match CStr::from_bytes_until_nul(n.cstr()) {
                Ok(c) => pwnam_into(c, &mut pwd, buf.as_mut_slice()),
                Err(_) => Ok(false),
            },
            None => pwuid_into(uid, &mut pwd, buf.as_mut_slice()),
        };
        match r {
            Err(34) => {
                if len >= 1 << 26 {
                    return Err(WRDE_NOSPACE);
                }
                len *= 2;
            }
            Ok(f) => break f && !pwd.pw_dir.is_null(),
            Err(_) => break false,
        }
    };
    if !found {
        return Ok(None);
    }
    let d = unsafe { CStr::from_ptr(pwd.pw_dir) };
    wcopy(d.to_bytes()).map(Some)
}

fn parse_tilde(word: &mut W, words: &[u8], offset: &mut usize, wordc: usize) -> R {
    if word.len() != 0 {
        let last = word.bytes()[word.len() - 1];
        if !(last == b'=' && wordc == 0) && !(last == b':' && cs(word.bytes()).contains(&b'=') && wordc == 0) {
            return ok_or_nospace(word.addchar(b'~'));
        }
    }

    let mut i = 1 + *offset;
    while at(words, i) != 0 {
        let c = words[i];
        if c == b':' || c == b'/' || c == b' ' || c == b'\t' {
            break;
        }
        if c == b'\\' {
            return ok_or_nospace(word.addchar(b'~'));
        }
        i += 1;
    }

    if i == 1 + *offset {
        if let Some(home) = getenv_bytes(b"HOME") {
            ok_or_nospace(word.addmem(home))?;
        } else {
            match home_of(None)? {
                Some(dir) => ok_or_nospace(word.addmem(dir.bytes()))?,
                None => ok_or_nospace(word.addchar(b'~'))?,
            }
        }
    } else {
        let user = &words[1 + *offset..i];
        match home_of(Some(user))? {
            Some(dir) => {
                word.addmem(dir.bytes());
            }
            None => {
                if word.addchar(b'~') {
                    word.addmem(user);
                }
            }
        }
        *offset = i - 1;
    }
    nospace_if_null(word)
}

fn do_parse_glob(glob_word: &[u8], word: &mut W, pw: Pw, cx: Cx) -> R {
    let mut g = Glob::new();
    if unsafe { glob(glob_word.as_ptr().cast(), GLOB_NOCHECK, None, &mut g) } != 0 {
        return Err(WRDE_NOSPACE);
    }
    struct Free<'a>(&'a mut Glob);
    impl Drop for Free<'_> {
        fn drop(&mut self) {
            unsafe { globfree(self.0) };
        }
    }
    let g = Free(&mut g);
    let paths = || unsafe { g.0.paths() }.map(CStr::to_bytes_with_nul);

    if cx.ifs.is_empty() {
        for (m, p) in paths().enumerate() {
            if m == 0 {
                word.addmem(cs(p));
            } else {
                if word.is_null() {
                    break;
                }
                if word.addchar(b' ') {
                    word.addmem(cs(p));
                }
            }
        }
        return nospace_if_null(word);
    }

    if !word.is_null() {
        word.free();
    }
    for p in paths() {
        let mut copy = wcopy(cs(p))?;
        pw.add(&mut copy)?;
    }
    Ok(())
}

fn parse_glob(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    let mut list = Wordexp::new();
    let lp = unsafe { Pw::new(&mut list) };
    let r = parse_glob_in(word, words, offset, cx, pw, lp);
    lp.free_words();
    r
}

fn parse_glob_in(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw, list: Pw) -> R {
    let mut quoted = 0;
    while at(words, *offset) != 0 {
        let c = words[*offset];
        if cx.ifs.contains(&c) {
            break;
        }
        if c == b'\'' && quoted == 0 {
            quoted = 1;
        } else if c == b'\'' && quoted == 1 {
            quoted = 0;
        } else if c == b'"' && quoted == 0 {
            quoted = 2;
        } else if c == b'"' && quoted == 2 {
            quoted = 0;
        } else if quoted != 1 && c == b'$' {
            parse_dollars(word, words, offset, cx, list, quoted == 2)?;
        } else if c == b'\\' {
            if quoted != 0 {
                parse_qtd_backslash(word, words, offset)?;
            } else {
                parse_backslash(word, words, offset)?;
            }
        } else {
            ok_or_nospace(word.addchar(c))?;
        }
        *offset += 1;
    }

    *offset = offset.wrapping_sub(1);

    let r = list.add(word);
    word.free();
    r?;
    for i in 0..list.wordc() {
        do_parse_glob(list.word(i), word, pw, cx)?;
    }
    Ok(())
}

fn parse_squote(word: &mut W, words: &[u8], offset: &mut usize) -> R {
    while at(words, *offset) != 0 {
        if words[*offset] != b'\'' {
            ok_or_nospace(word.addchar(words[*offset]))?;
        } else {
            return Ok(());
        }
        *offset += 1;
    }
    Err(WRDE_SYNTAX)
}

fn ev_at(e: &[u8], i: usize) -> u8 {
    e.get(i).copied().unwrap_or(0)
}

fn eval_val(e: &mut [u8], pos: &mut usize, result: &mut i64) -> bool {
    let mut digit = *pos;
    while ev_at(e, digit) != 0 && is_space(e[digit]) {
        digit += 1;
    }
    if ev_at(e, digit) == b'(' {
        digit += 1;
        while ev_at(e, *pos) != 0 && ev_at(e, *pos) != b')' {
            *pos += 1;
        }
        if ev_at(e, *pos) == 0 {
            return true;
        }
        e[*pos] = 0;
        *pos += 1;
        return eval_expr(&mut e[digit..], result);
    }
    if digit >= e.len() {
        return true;
    }
    let mut end: *mut c_char = null_mut();
    let base = e.as_ptr() as usize;
    if e.last() != Some(&0) {
        return true;
    }
    *result = unsafe { rusty_libc_stdlib::num::strtol(e[digit..].as_ptr().cast(), &mut end, 0) };
    let new = end as usize - base;
    *pos = new;
    new == digit
}

fn eval_multdiv(e: &mut [u8], pos: &mut usize, result: &mut i64) -> bool {
    if eval_val(e, pos, result) {
        return true;
    }
    while ev_at(e, *pos) != 0 {
        while ev_at(e, *pos) != 0 && is_space(e[*pos]) {
            *pos += 1;
        }
        let mut arg = 0i64;
        if ev_at(e, *pos) == b'*' {
            *pos += 1;
            if eval_val(e, pos, &mut arg) {
                return true;
            }
            *result = result.wrapping_mul(arg);
        } else if ev_at(e, *pos) == b'/' {
            *pos += 1;
            if eval_val(e, pos, &mut arg) {
                return true;
            }
            if arg == 0 || (arg == -1 && *result == i64::MIN) {
                return true;
            }
            *result /= arg;
        } else {
            break;
        }
    }
    false
}

fn eval_expr(e: &mut [u8], result: &mut i64) -> bool {
    let mut pos = 0usize;
    if eval_multdiv(e, &mut pos, result) {
        return true;
    }
    while ev_at(e, pos) != 0 {
        while ev_at(e, pos) != 0 && is_space(e[pos]) {
            pos += 1;
        }
        let mut arg = 0i64;
        if ev_at(e, pos) == b'+' {
            pos += 1;
            if eval_multdiv(e, &mut pos, &mut arg) {
                return true;
            }
            *result = result.wrapping_add(arg);
        } else if ev_at(e, pos) == b'-' {
            pos += 1;
            if eval_multdiv(e, &mut pos, &mut arg) {
                return true;
            }
            *result = result.wrapping_sub(arg);
        } else {
            break;
        }
    }
    false
}

fn eval_text(expr: &mut W, out: &mut i64) -> bool {
    if expr.is_null() {
        return false;
    }
    eval_expr(expr.with_nul_mut(), out)
}

fn parse_arith(word: &mut W, words: &[u8], offset: &mut usize, flags: c_int, bracket: bool) -> R {
    let mut paren_depth = 1;
    let mut expr = W::new();
    let cx = Cx { flags, ifs: &[], white: &[] };
    while at(words, *offset) != 0 {
        match words[*offset] {
            b'$' => parse_dollars(&mut expr, words, offset, cx, Pw::NULL, true)?,
            b'`' => {
                *offset += 1;
                parse_backtick(&mut expr, words, offset, cx, Pw::NULL)?;
            }
            b'\\' => parse_qtd_backslash(&mut expr, words, offset)?,
            b')' => {
                paren_depth -= 1;
                if paren_depth == 0 {
                    if bracket || at(words, 1 + *offset) != b')' {
                        return Err(WRDE_SYNTAX);
                    }
                    *offset += 1;
                    let mut numresult = 0i64;
                    if eval_text(&mut expr, &mut numresult) {
                        return Err(WRDE_SYNTAX);
                    }
                    let convert: u64;
                    if numresult < 0 {
                        convert = numresult.wrapping_neg() as u64;
                        ok_or_nospace(word.addchar(b'-'))?;
                    } else {
                        convert = numresult as u64;
                    }
                    let mut buf = [0u8; 21];
                    ok_or_nospace(word.addmem(utoa(convert, &mut buf)))?;
                    return Ok(());
                }
                ok_or_nospace(expr.addchar(b')'))?;
            }
            b']' => {
                if bracket && paren_depth == 1 {
                    let mut numresult = 0i64;
                    if eval_text(&mut expr, &mut numresult) {
                        return Err(WRDE_SYNTAX);
                    }
                    let mut buf = [0u8; 21];
                    ok_or_nospace(word.addmem(utoa(numresult as u64, &mut buf)))?;
                    return Ok(());
                }
                return Err(WRDE_SYNTAX);
            }
            b'\n' | b';' | b'{' | b'}' => return Err(WRDE_BADCHAR),
            c => {
                if c == b'(' {
                    paren_depth += 1;
                }
                ok_or_nospace(expr.addchar(c))?;
            }
        }
        *offset += 1;
    }
    Err(WRDE_SYNTAX)
}

const O_CLOEXEC: i32 = 0o2000000;
const O_WRONLY: i32 = 1;
const EINTR: i32 = 4;
const WNOHANG: i32 = 1;
const SYS_KILL: usize = 62;
const SIGKILL: usize = 9;

fn read_retry(fd: i32, buf: &mut [u8]) -> isize {
    loop {
        match unistd::read(fd, buf) {
            Ok(n) => return n as isize,
            Err(e) if e.0 == EINTR => continue,
            Err(_) => return -1,
        }
    }
}

fn waitpid_retry(pid: i32, options: i32, status: &mut i32) -> i32 {
    loop {
        match unistd::waitpid(pid, options) {
            Ok((p, st)) => {
                if p > 0 {
                    *status = st;
                }
                return p;
            }
            Err(e) if e.0 == EINTR => continue,
            Err(_) => return -1,
        }
    }
}

fn close_fd(fd: i32) {
    if fd >= 0 {
        let _ = unistd::close(fd);
    }
}

fn spawn_sh(comm: &[u8], fildes: [i32; 2], showerr: bool, noexec: bool) -> i32 {
    let ifs_set = getenv_bytes(b"IFS").is_some();
    let environ = unsafe { rusty_libc_core::env::block() };
    let entry = |i: usize| unsafe { *environ.wrapping_add(i) };
    let mut newenv: CVec<*const c_char> = CVec::new();
    if ifs_set {
        let mut n = 0usize;
        if !environ.is_null() {
            while !entry(n).is_null() {
                n += 1;
            }
        }
        if !newenv.reserve_total(n + 1) {
            return -1;
        }
        for i in 0..n {
            let e = entry(i);
            if !unsafe { CStr::from_ptr(e) }.to_bytes().starts_with(b"IFS=") {
                newenv.push(e);
            }
        }
        newenv.push(core::ptr::null());
    }
    let envp: *const *const c_char = if ifs_set { newenv.as_mut_ptr() } else { environ as *const *const c_char };

    let sh = c"/bin/sh".as_ptr();
    let flag = if noexec { c"-nc".as_ptr() } else { c"-c".as_ptr() };
    let args: [*const c_char; 4] = [sh, flag, comm.as_ptr().cast(), core::ptr::null()];

    use rusty_libc_core::spawn::{A_CLOSE, A_DUP2, A_OPEN, PosixSpawnFileActions, SpawnAction, spawnix};
    let act = |tag, fd, arg, path| SpawnAction { tag, fd, arg, mode: 0, path };
    let mut acts = [act(0, 0, 0, null_mut()); 3];
    let mut n = 0usize;
    if fildes[1] != -1 {
        if fildes[1] != 1 {
            acts[n] = act(A_DUP2, fildes[1], 1, null_mut());
            acts[n + 1] = act(A_CLOSE, fildes[1], 0, null_mut());
            n += 2;
        } else {
            acts[n] = act(A_DUP2, fildes[1], fildes[1], null_mut());
            n += 1;
        }
    }
    if !showerr {
        acts[n] = act(A_OPEN, 2, O_WRONLY, c"/dev/null".as_ptr() as *mut c_char);
        n += 1;
    }
    let fa = PosixSpawnFileActions { allocated: n as c_int, used: n as c_int, actions: acts.as_mut_ptr(), pad: [0; 16] };
    let mut pid: c_int = -1;
    let err = unsafe { spawnix(&mut pid, sh, &fa, core::ptr::null(), args.as_ptr(), envp, false, false) };
    drop(newenv);
    if err != 0 {
        return -1;
    }
    pid
}

fn exec_comm(comm: &W, word: &mut W, cx: Cx, pw: Pw) -> R {
    let flags = cx.flags;
    let mut maxnewlines = 0usize;
    let mut buffer = [0u8; 128];
    let mut status = 0i32;
    let mut noexec = false;

    if flags & WRDE_NOCMD != 0 {
        return Err(WRDE_CMDSUB);
    }
    if comm.is_null() || cs(comm.bytes()).is_empty() {
        return Ok(());
    }
    let (rd, wr) = match unistd::pipe2(O_CLOEXEC) {
        Ok(p) => p,
        Err(_) => return Err(WRDE_NOSPACE),
    };
    let mut fildes = [rd, wr];

    loop {
        let pid = spawn_sh(comm.cstr(), fildes, if noexec { false } else { flags & WRDE_SHOWERR != 0 }, noexec);
        if pid < 0 {
            close_fd(fildes[0]);
            close_fd(fildes[1]);
            return Err(WRDE_NOSPACE);
        }
        if noexec {
            let r = waitpid_retry(pid, 0, &mut status);
            return if r == pid && status != 0 { Err(WRDE_SYNTAX) } else { Ok(()) };
        }
        close_fd(fildes[1]);
        fildes[1] = -1;

        let no_space = |fd: i32| -> R {
            unsafe { syscall::syscall2(SYS_KILL, pid as usize, SIGKILL) };
            let mut st = 0;
            waitpid_retry(pid, 0, &mut st);
            close_fd(fd);
            Err(WRDE_NOSPACE)
        };

        let mut copying = 0;
        let buflen: isize;
        loop {
            let mut bl = read_retry(fildes[0], &mut buffer);
            if bl < 1 {
                if waitpid_retry(pid, if bl == 0 { 0 } else { WNOHANG }, &mut status) == 0 {
                    continue;
                }
                bl = read_retry(fildes[0], &mut buffer);
                if bl < 1 {
                    buflen = bl;
                    break;
                }
            }
            let chunk = &buffer[..bl as usize];

            if pw.is_null() {
                maxnewlines += chunk.len();
                if !word.addmem(chunk) {
                    return no_space(fildes[0]);
                }
                continue;
            }

            for &ch in chunk {
                if in_set(cx.ifs, ch) {
                    if !in_set(cx.white, ch) {
                        if copying == 2 {
                            copying = 0;
                            continue;
                        }
                        copying = 0;
                    } else if ch == b'\n' {
                        if copying == 1 {
                            copying = 3;
                        }
                        continue;
                    } else {
                        if copying != 1 && copying != 3 {
                            continue;
                        }
                        copying = 2;
                    }
                    if pw.add(word) == Err(WRDE_NOSPACE) {
                        return no_space(fildes[0]);
                    }
                    word.free();
                    maxnewlines = 0;
                } else {
                    if copying == 3 {
                        if pw.add(word) == Err(WRDE_NOSPACE) {
                            return no_space(fildes[0]);
                        }
                        word.free();
                    }
                    copying = 1;
                    if ch == b'\n' {
                        maxnewlines += 1;
                    } else {
                        maxnewlines = 0;
                    }
                    if !word.addchar(ch) {
                        return no_space(fildes[0]);
                    }
                }
            }
        }

        while maxnewlines != 0 {
            maxnewlines -= 1;
            if word.len() > 0 && word.bytes()[word.len() - 1] == b'\n' {
                word.pop();
                if word.len() == 0 {
                    word.free();
                    break;
                }
            } else {
                break;
            }
        }

        close_fd(fildes[0]);
        fildes[0] = -1;

        if buflen < 1 && status != 0 {
            noexec = true;
            continue;
        }
        return Ok(());
    }
}

fn parse_comm(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    let mut paren_depth = 1;
    let mut quoted = 0;
    let mut comm = W::new();
    while at(words, *offset) != 0 {
        let c = words[*offset];
        match c {
            b'\'' => {
                if quoted == 0 {
                    quoted = 1;
                } else if quoted == 1 {
                    quoted = 0;
                }
            }
            b'"' => {
                if quoted == 0 {
                    quoted = 2;
                } else if quoted == 2 {
                    quoted = 0;
                }
            }
            b')' => {
                if quoted == 0 {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        if !comm.is_null() {
                            return exec_comm(&comm, word, cx, pw);
                        }
                        return Ok(());
                    }
                }
            }
            b'(' if quoted == 0 => paren_depth += 1,
            _ => {}
        }
        ok_or_nospace(comm.addchar(c))?;
        *offset += 1;
    }
    Err(WRDE_SYNTAX)
}

fn parse_backtick(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    let mut squoting = false;
    let mut comm = W::new();
    while at(words, *offset) != 0 {
        let c = words[*offset];
        match c {
            b'`' => return exec_comm(&comm, word, cx, pw),
            b'\\' => {
                if squoting {
                    parse_qtd_backslash(&mut comm, words, offset)?;
                } else {
                    parse_backslash(&mut comm, words, offset)?;
                }
            }
            _ => {
                if c == b'\'' {
                    squoting = !squoting;
                }
                ok_or_nospace(comm.addchar(c))?;
            }
        }
        *offset += 1;
    }
    Err(WRDE_SYNTAX)
}

const ACT_NONE: u8 = 0;
const ACT_RP_SHORT_LEFT: u8 = b'#';
const ACT_RP_LONG_LEFT: u8 = b'L';
const ACT_RP_SHORT_RIGHT: u8 = b'%';
const ACT_RP_LONG_RIGHT: u8 = b'R';
const ACT_NULL_ERROR: u8 = b'?';
const ACT_NULL_SUBST: u8 = b'-';
const ACT_NONNULL_SUBST: u8 = b'+';
const ACT_NULL_ASSIGN: u8 = b'=';

const FNM_NOMATCH: c_int = 1;

fn fnm(pattern: &[u8], s: &[u8]) -> bool {
    fnmatch_bytes(pattern, s, 0) != FNM_NOMATCH
}

fn expand_pattern(pattern: &W, flags: c_int) -> Result<W, c_int> {
    let pb: &[u8] = pattern.bytes();
    let mut expanded = W::new();
    let cx = Cx { flags, ifs: &[], white: &[] };
    let mut quoted = 0;
    let mut pi = 0usize;
    while at(pb, pi) != 0 {
        let c = pb[pi];
        let mut add = true;
        match c {
            b'"' => {
                if quoted == 2 {
                    quoted = 0;
                    add = false;
                } else if quoted == 0 {
                    quoted = 2;
                    add = false;
                }
            }
            b'\'' => {
                if quoted == 1 {
                    quoted = 0;
                    add = false;
                } else if quoted == 0 {
                    quoted = 1;
                    add = false;
                }
            }
            b'*' | b'?' => {
                if quoted != 0 {
                    ok_or_nospace(expanded.addchar(b'\\'))?;
                }
            }
            b'$' => {
                let mut off = 0usize;
                parse_dollars(&mut expanded, &pb[pi..], &mut off, cx, Pw::NULL, true)?;
                pi += off;
                add = false;
            }
            b'~' => {
                if quoted == 0 && expanded.len() == 0 {
                    let mut off = 0usize;
                    parse_tilde(&mut expanded, &pb[pi..], &mut off, 0)?;
                    pi += off;
                    add = false;
                }
            }
            b'\\' => {
                ok_or_nospace(expanded.addchar(b'\\'))?;
                pi += 1;
            }
            _ => {}
        }
        if add {
            ok_or_nospace(expanded.addchar(pb[pi]))?;
        }
        pi += 1;
    }
    Ok(expanded)
}

fn parse_param(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw, quoted: bool) -> R {
    let flags = cx.flags;
    let start = *offset;
    let mut env = W::new();
    let mut pattern = W::new();
    let mut value: Option<W> = None;
    let mut action = ACT_NONE;
    let mut depth = 0;
    let mut colon_seen = false;
    let mut seen_hash = false;
    let mut pattern_is_quoted = 0;
    let mut special = false;
    let brace = at(words, *offset) == b'{';

    'collect: {
        if brace {
            *offset += 1;
        }

        if at(words, *offset) == b'#' {
            seen_hash = true;
            if !brace {
                break 'collect;
            }
            *offset += 1;
        }

        let c = at(words, *offset);
        if is_alpha(c) || c == b'_' {
            loop {
                ok_or_nospace(env.addchar(words[*offset]))?;
                *offset += 1;
                let n = at(words, *offset);
                if !(is_alnum(n) || n == b'_') {
                    break;
                }
            }
        } else if is_digit(c) {
            special = true;
            loop {
                ok_or_nospace(env.addchar(words[*offset]))?;
                if !brace {
                    break 'collect;
                }
                *offset += 1;
                if !is_digit(at(words, *offset)) {
                    break;
                }
            }
        } else if c == b'*' || c == b'@' || c == b'$' {
            special = true;
            ok_or_nospace(env.addchar(c))?;
            *offset += 1;
        } else if brace {
            return Err(WRDE_SYNTAX);
        }

        if brace {
            match at(words, *offset) {
                b'}' => break 'collect,
                b'#' => {
                    action = ACT_RP_SHORT_LEFT;
                    if at(words, 1 + *offset) == b'#' {
                        *offset += 1;
                        action = ACT_RP_LONG_LEFT;
                    }
                }
                b'%' => {
                    action = ACT_RP_SHORT_RIGHT;
                    if at(words, 1 + *offset) == b'%' {
                        *offset += 1;
                        action = ACT_RP_LONG_RIGHT;
                    }
                }
                b':' => {
                    if !matches!(at(words, 1 + *offset), b'-' | b'=' | b'?' | b'+') {
                        return Err(WRDE_SYNTAX);
                    }
                    colon_seen = true;
                    *offset += 1;
                    action = words[*offset];
                }
                c @ (b'-' | b'=' | b'?' | b'+') => action = c,
                _ => return Err(WRDE_SYNTAX),
            }

            *offset += 1;
            while at(words, *offset) != 0 {
                match words[*offset] {
                    b'{' => {
                        if pattern_is_quoted == 0 {
                            depth += 1;
                        }
                    }
                    b'}' => {
                        if pattern_is_quoted == 0 {
                            if depth == 0 {
                                break 'collect;
                            }
                            depth -= 1;
                        }
                    }
                    b'\\' => {
                        if pattern_is_quoted == 0 {
                            *offset += 1;
                            if at(words, *offset) == 0 {
                                return Err(WRDE_SYNTAX);
                            }
                            ok_or_nospace(pattern.addchar(b'\\'))?;
                        }
                    }
                    b'\'' => {
                        if pattern_is_quoted == 0 {
                            pattern_is_quoted = 1;
                        } else if pattern_is_quoted == 1 {
                            pattern_is_quoted = 0;
                        }
                    }
                    b'"' => {
                        if pattern_is_quoted == 0 {
                            pattern_is_quoted = 2;
                        } else if pattern_is_quoted == 2 {
                            pattern_is_quoted = 0;
                        }
                    }
                    _ => {}
                }
                ok_or_nospace(pattern.addchar(words[*offset]))?;
                *offset += 1;
            }
        }

        *offset = offset.wrapping_sub(1);
    }

    if at(words, start) == b'{' && at(words, *offset) != b'}' {
        return Err(WRDE_SYNTAX);
    }

    let mut nbuf = [0u8; 21];
    let (argc, _) = args();
    if env.is_null() {
        if seen_hash {
            value = Some(wcopy(utoa((argc - 1) as i64 as u64, &mut nbuf))?);
            seen_hash = false;
        } else {
            *offset = start.wrapping_sub(1);
            return ok_or_nospace(word.addchar(b'$'));
        }
    } else if is_digit(env.bytes()[0]) {
        let mut n: u64 = 0;
        for &d in env.bytes() {
            n = n.saturating_mul(10).saturating_add((d - b'0') as u64);
        }
        if n >= argc as u64 {
            value = None;
        } else if let Some(a) = argv_at(n as usize) {
            value = Some(wcopy(a)?);
        }
    } else if special {
        let sp = env.bytes()[0];
        if sp == b'$' {
            let pid = unistd::getpid();
            value = Some(wcopy(utoa(pid as i64 as u64, &mut nbuf))?);
        } else if (sp == b'*' || sp == b'@') && seen_hash {
            let n = if argc > 0 { argc - 1 } else { 0 };
            ok_or_nospace(word.addmem(utoa(n as i64 as u64, &mut nbuf)))?;
            return Ok(());
        } else if sp == b'*' || (sp == b'@' && !quoted) {
            let mut joined = W::empty()?;
            let mut p = 1;
            while let Some(a) = argv_at(p) {
                if p > 1 {
                    ok_or_nospace(joined.addchar(b' '))?;
                }
                ok_or_nospace(joined.addmem(a))?;
                p += 1;
            }
            value = Some(joined);
        } else {
            if argc == 2 {
                value = Some(wcopy(argv_at(1).unwrap_or(&[]))?);
            } else if argc > 2 {
                if pw.is_null() {
                    return Err(WRDE_NOSPACE);
                }
                ok_or_nospace(word.addmem(argv_at(1).unwrap_or(&[])))?;
                pw.add(word)?;
                let mut p = 2;
                while argv_at(p + 1).is_some() {
                    let mut nw = wcopy(argv_at(p).unwrap_or(&[]))?;
                    pw.add(&mut nw)?;
                    p += 1;
                }
                word.free();
                value = Some(wcopy(argv_at(p).unwrap_or(&[]))?);
            } else {
                return Ok(());
            }
        }
    } else if let Some(v) = getenv_bytes(env.bytes()) {
        value = Some(wcopy(v)?);
    }

    if value.is_none() && flags & WRDE_UNDEF != 0 {
        return Err(WRDE_BADVAL);
    }

    let vbytes = |v: &Option<W>| -> usize { v.as_ref().map_or(0, |w| cs(w.bytes()).len()) };
    let v_nonempty = |v: &Option<W>| -> bool { vbytes(v) != 0 };

    if action != ACT_NONE {
        let expand = match action {
            ACT_RP_SHORT_LEFT | ACT_RP_LONG_LEFT | ACT_RP_SHORT_RIGHT | ACT_RP_LONG_RIGHT => true,
            ACT_NULL_ERROR | ACT_NULL_SUBST | ACT_NULL_ASSIGN => value.is_none() || (!v_nonempty(&value) && colon_seen),
            ACT_NONNULL_SUBST => value.is_some() && (v_nonempty(&value) || !colon_seen),
            _ => false,
        };
        if expand {
            pattern = expand_pattern(&pattern, flags)?;
        }

        match action {
            ACT_RP_SHORT_LEFT | ACT_RP_LONG_LEFT | ACT_RP_SHORT_RIGHT | ACT_RP_LONG_RIGHT => {
                if let Some(v) = value.as_mut()
                    && !pattern.is_null()
                    && pattern.cstr()[0] != 0
                {
                    let n = cs(v.bytes()).len();
                    let pat = pattern.cstr();
                    let vb = &mut v.with_nul_mut()[..=n];
                    let mut newv: Option<W> = None;
                    match action {
                        ACT_RP_SHORT_LEFT | ACT_RP_LONG_LEFT => {
                            let mut p = if action == ACT_RP_SHORT_LEFT { 0 } else { n as isize };
                            let step = if action == ACT_RP_SHORT_LEFT { 1 } else { -1 };
                            while p >= 0 && p as usize <= n {
                                let i = p as usize;
                                let c = vb[i];
                                vb[i] = 0;
                                let m = fnm(pat, &vb[..=i]);
                                vb[i] = c;
                                if m {
                                    newv = Some(wcopy(&vb[i..n])?);
                                    break;
                                }
                                p += step;
                            }
                        }
                        _ => {
                            let mut p = if action == ACT_RP_SHORT_RIGHT { n as isize } else { 0 };
                            let step = if action == ACT_RP_SHORT_RIGHT { -1 } else { 1 };
                            while p >= 0 && p as usize <= n {
                                let i = p as usize;
                                if fnm(pat, &vb[i..]) {
                                    newv = Some(wcopy(&vb[..i])?);
                                    break;
                                }
                                p += step;
                            }
                        }
                    }
                    if newv.is_some() {
                        value = newv;
                    }
                }
            }
            ACT_NULL_ERROR => {
                if v_nonempty(&value) {
                } else {
                    if colon_seen || value.is_none() {
                        let msg: &[u8] = if pattern.is_null() || pattern.cstr()[0] == 0 { rusty_libc_core::i18n::tr(c"parameter null or not set").to_bytes() } else { cs(pattern.bytes()) };
                        let mut line = W::new();
                        line.addmem(env.bytes());
                        line.addmem(b": ");
                        line.addmem(msg);
                        line.addchar(b'\n');
                        if !line.is_null() {
                            let e = rusty_libc_stdio::file::stderr_ptr();
                            rusty_libc_stdio::file::write_bytes(unsafe { rusty_libc_stdio::file::stream(e) }, line.bytes());
                        }
                    }
                    return Ok(());
                }
            }
            ACT_NULL_SUBST => {
                if !v_nonempty(&value) {
                    if !colon_seen && value.is_some() {
                        return Ok(());
                    }
                    value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                }
            }
            ACT_NONNULL_SUBST => {
                if value.is_some() && (v_nonempty(&value) || !colon_seen) {
                    value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                } else {
                    return Ok(());
                }
            }
            ACT_NULL_ASSIGN if !v_nonempty(&value) => {
                if !colon_seen && value.is_some() {
                    return Ok(());
                }
                value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                let vp: &[u8] = match &value {
                    Some(v) => v.cstr(),
                    None => b"\0",
                };
                unsafe { rusty_libc_stdlib::env::setenv(env.cstr().as_ptr().cast(), vp.as_ptr().cast(), 1) };
            }
            _ => {}
        }
    }

    drop(env);
    drop(pattern);

    if seen_hash {
        let mut nb = [0u8; 21];
        return ok_or_nospace(word.addmem(utoa(vbytes(&value) as u64, &mut nb)));
    }

    let value = match value {
        Some(v) => v,
        None => return Ok(()),
    };

    if quoted || pw.is_null() {
        return ok_or_nospace(word.addmem(cs(value.bytes())));
    }

    let vc = cs(value.bytes());
    let vat = |i: usize| at(vc, i);
    let mut field_begin = 0usize;
    let mut seen_nonws_ifs = false;
    loop {
        if field_begin != 0 && pw.add(word) == Err(WRDE_NOSPACE) {
            return Err(WRDE_NOSPACE);
        }

        while vat(field_begin) != 0 && cx.white.contains(&vat(field_begin)) {
            field_begin += 1;
        }
        if !seen_nonws_ifs && vat(field_begin) == 0 {
            break;
        }

        let mut field_end = field_begin;
        while vat(field_end) != 0 && !cx.ifs.contains(&vat(field_end)) {
            field_end += 1;
        }

        let mut next_field = field_end;
        while vat(next_field) != 0 && cx.white.contains(&vat(next_field)) {
            next_field += 1;
        }

        seen_nonws_ifs = false;
        if vat(next_field) != 0 && cx.ifs.contains(&vat(next_field)) {
            seen_nonws_ifs = true;
            next_field += 1;
        }

        if !word.addmem(&vc[field_begin..field_end]) && field_end > field_begin {
            return Err(WRDE_NOSPACE);
        }

        field_begin = next_field;
        if !(seen_nonws_ifs || vat(field_begin) != 0) {
            break;
        }
    }
    Ok(())
}

fn parse_dollars(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw, quoted: bool) -> R {
    match at(words, 1 + *offset) {
        b'"' | b'\'' | 0 => ok_or_nospace(word.addchar(b'$')),
        b'(' => {
            if at(words, 2 + *offset) == b'(' {
                let mut i = 3 + *offset;
                let mut depth = 0i32;
                while at(words, i) != 0 && !(depth == 0 && words[i] == b')') {
                    if words[i] == b'(' {
                        depth += 1;
                    } else if words[i] == b')' {
                        depth -= 1;
                    }
                    i += 1;
                }
                if at(words, i) == b')' && at(words, i + 1) == b')' {
                    *offset += 3;
                    return parse_arith(word, words, offset, cx.flags, false);
                }
            }
            *offset += 2;
            parse_comm(word, words, offset, cx, if quoted { Pw::NULL } else { pw })
        }
        b'[' => {
            *offset += 2;
            parse_arith(word, words, offset, cx.flags, true)
        }
        _ => {
            *offset += 1;
            parse_param(word, words, offset, cx, pw, quoted)
        }
    }
}

fn parse_dquote(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    let plain = Cx { flags: cx.flags, ifs: &[], white: &[] };
    while at(words, *offset) != 0 {
        match words[*offset] {
            b'"' => return Ok(()),
            b'$' => parse_dollars(word, words, offset, cx, pw, true)?,
            b'`' => {
                *offset += 1;
                parse_backtick(word, words, offset, plain, Pw::NULL)?;
            }
            b'\\' => parse_qtd_backslash(word, words, offset)?,
            c => ok_or_nospace(word.addchar(c))?,
        }
        *offset += 1;
    }
    Err(WRDE_SYNTAX)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wordfree(pwordexp: *mut Wordexp) {
    unsafe { Pw::new(pwordexp) }.free_words();
}

fn wordexp_in(words: &[u8], pw: Pw, flags: c_int, word: &mut W) -> c_int {
    let mut old_word = pw.save();
    let error: c_int;

    if flags & WRDE_REUSE != 0 {
        pw.free_words();
        old_word.we_wordc = 0;
        old_word.we_wordv = null_mut();
        pw.set_wordc(0);
    }

    'run: {
        if flags & WRDE_APPEND == 0 {
            pw.set_wordc(0);
            let ok = if flags & WRDE_DOOFFS != 0 { pw.fresh(1 + pw.offs(), false) } else { pw.fresh(1, true) };
            if !ok {
                error = WRDE_NOSPACE;
                break 'run;
            }
        }

        let ifs_bytes: &[u8] = match getenv_bytes(b"IFS") {
            None => b" \t\n",
            Some(v) => v,
        };
        let ifs_copy = match wcopy(ifs_bytes) {
            Ok(w) => w,
            Err(e) => {
                error = e;
                break 'run;
            }
        };
        let ifs = ifs_copy.bytes();
        let mut white = [0u8; 3];
        let mut nw = 0usize;
        if getenv_bytes(b"IFS").is_none() {
            white = *b" \t\n";
            nw = 3;
        } else {
            for &c in ifs {
                if (c == b' ' || c == b'\t' || c == b'\n') && !white[..nw].contains(&c) {
                    white[nw] = c;
                    nw += 1;
                }
            }
        }
        let cx = Cx { flags, ifs, white: &white[..nw] };

        let mut off = 0usize;
        while at(words, off) != 0 {
            let c = words[off];
            let r: R = match c {
                b'\\' => parse_backslash(word, words, &mut off),
                b'$' => parse_dollars(word, words, &mut off, cx, pw, false),
                b'`' => {
                    off += 1;
                    parse_backtick(word, words, &mut off, cx, pw)
                }
                b'"' => {
                    off += 1;
                    let r = parse_dquote(word, words, &mut off, cx, pw);
                    if r.is_ok()
                        && word.len() == 0
                        && let Err(e) = pw.add(&mut W::new())
                    {
                        return e;
                    }
                    r
                }
                b'\'' => {
                    off += 1;
                    let r = parse_squote(word, words, &mut off);
                    if r.is_ok()
                        && word.len() == 0
                        && let Err(e) = pw.add(&mut W::new())
                    {
                        return e;
                    }
                    r
                }
                b'~' => parse_tilde(word, words, &mut off, pw.wordc()),
                b'*' | b'[' | b'?' => parse_glob(word, words, &mut off, cx, pw),
                _ => {
                    if c != b' ' && c != b'\t' {
                        if b"\n|&;<>(){}".contains(&c) {
                            Err(WRDE_BADCHAR)
                        } else if word.addchar(c) {
                            Ok(())
                        } else {
                            Err(WRDE_NOSPACE)
                        }
                    } else {
                        let mut r = Ok(());
                        if !word.is_null() {
                            r = pw.add(word);
                        }
                        if r.is_ok() {
                            word.free();
                        }
                        r
                    }
                }
            };
            if let Err(e) = r {
                error = e;
                break 'run;
            }
            off += 1;
        }

        if word.is_null() {
            return 0;
        }
        return match pw.add(word) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    word.free();
    if error == WRDE_NOSPACE {
        return WRDE_NOSPACE;
    }
    if flags & WRDE_APPEND == 0 {
        pw.free_words();
    }
    pw.restore(old_word);
    error
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wordexp(words: *const c_char, pwordexp: *mut Wordexp, flags: c_int) -> c_int {
    let w = unsafe { rusty_libc_core::ffi::cstr_nonnull(words) }.to_bytes();
    let mut word = W::new();
    wordexp_in(w, unsafe { Pw::new(pwordexp) }, flags, &mut word)
}

pub struct WordList {
    raw: Wordexp,
}

impl WordList {
    pub fn len(&self) -> usize {
        self.raw.we_wordc
    }

    pub fn is_empty(&self) -> bool {
        self.raw.we_wordc == 0
    }

    pub fn get(&self, i: usize) -> Option<&CStr> {
        if i >= self.raw.we_wordc {
            return None;
        }
        let pw = unsafe { Pw::new(&self.raw as *const Wordexp as *mut Wordexp) };
        CStr::from_bytes_with_nul(pw.word(i)).ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CStr> + '_ {
        (0..self.raw.we_wordc).filter_map(move |i| self.get(i))
    }

    pub fn as_raw(&self) -> &Wordexp {
        &self.raw
    }
}

impl Drop for WordList {
    fn drop(&mut self) {
        unsafe { Pw::new(&mut self.raw) }.free_words();
    }
}

pub fn expand(words: &CStr, flags: c_int) -> Result<WordList, c_int> {
    let mut list = WordList { raw: Wordexp::new() };
    let flags = flags & !(WRDE_APPEND | WRDE_REUSE | WRDE_DOOFFS);
    let mut word = W::new();
    match wordexp_in(words.to_bytes(), unsafe { Pw::new(&mut list.raw) }, flags, &mut word) {
        0 => Ok(list),
        e => Err(e),
    }
}
