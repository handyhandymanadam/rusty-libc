//! wordexp.h: `wordexp` and `wordfree`, POSIX.2 shell word expansion with glibc 2.43's behaviour.
//!
//! The expander is a recursive-descent parser over the input string, written to give the same
//! results as glibc's `posix/wordexp.c`, quirks included:
//! * Tilde expansion knows `~` (`$HOME`, else the passwd entry of the user id) and `~name`; `~+` and
//!   `~-` are not special (they are looked up as user names and stay literal).
//! * Parameters: `$name`, `${name}`, `$1`..., `$*`, `$@`, `$#`, `$$`, `${#name}` and the operators
//!   `:-` `:=` `:?` `:+` `-` `=` `?` `+` `#` `##` `%` `%%`. `$?` and `$0` have no special meaning
//!   beyond what the digit rule gives (`$0` is `argv[0]`, `$?` is a lone `$` followed by `?`). The
//!   positional parameters are the program's own `argv` (`__libc_argc` / `__libc_argv`, set by the
//!   startup code through `__init_misc`, or by [`crate::err::set_args`]).
//! * `${x?w}` prints `x: w` on stderr and expands to nothing; it does not fail.
//! * `$(...)` and backticks run `/bin/sh -c` in a child (stdout through a pipe, stderr to
//!   `/dev/null` unless `WRDE_SHOWERR`, `IFS` removed from the child's environment); when the
//!   command fails, the text is run once more with `sh -nc` to tell a syntax error (`WRDE_SYNTAX`)
//!   from a command that merely failed.
//! * `$((...))` and `$[...]` use glibc's small evaluator: decimal, octal and hex constants, unary
//!   signs through `strtol`, `+ - * /` with the usual precedence, and parentheses (a `(` group ends
//!   at the first `)`, so nested groups are a syntax error). `$[ ]` prints its result as an unsigned
//!   64-bit number (glibc does), `$(( ))` prints a sign.
//! * Pathname expansion goes through [`crate::glob::glob`] with `GLOB_NOCHECK`.
//! * Empty expansions glibc itself reports as `WRDE_NOSPACE` (a quoted empty parameter that adds
//!   nothing to a word, for instance `"$EMPTY"`) do the same here: the word buffer logic is a direct
//!   transcription, including a NULL buffer standing for an empty word.
//!
//! The memory layout of `wordexp_t` and of the results (`we_wordv` is one `malloc` block of
//! `we_offs + we_wordc + 1` pointers, every word a separate `malloc` string, so `wordfree` and the
//! caller's `free` agree with the C library's allocator) equals glibc's.
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

/// `wordexp_t`.
#[repr(C)]
pub struct Wordexp {
    pub we_wordc: usize,
    pub we_wordv: *mut *mut c_char,
    pub we_offs: usize,
}

impl Wordexp {
    /// An empty `wordexp_t` ready for the first call.
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

/// `at(words, i)`: the byte at `i`, or NUL past the end (the C string terminator).
fn at(w: &[u8], i: usize) -> u8 {
    w.get(i).copied().unwrap_or(0)
}

/// The bytes before the first NUL (a C string's content).
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

/// `strchr(set, c) != NULL`: the terminating NUL counts as a member.
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

/// The growing word and the result list: the only raw memory of the expander.
mod words {
    use super::{R, WRDE_NOSPACE, Wordexp};
    use crate::cmem::CVec;
    use core::ffi::c_char;
    use core::ptr::null_mut;

    /// A growing word: glibc's `(char *word, size_t word_length, size_t max_length)`, on the C heap with a NUL after
    /// the text. A NULL buffer is an empty word that was never started ("ignored if it is the last word"); a buffer
    /// that holds no characters yet but is allocated is a real empty word.
    pub(super) struct W {
        /// the text and its NUL (empty when NULL)
        buf: CVec<u8>,
        /// glibc's `max_length` (the block holds `max + 1` bytes)
        max: usize,
    }

    const W_CHUNK: usize = 100;

    impl W {
        pub(super) const fn new() -> W {
            W { buf: CVec::new(), max: 0 }
        }
        /// An allocated empty word (glibc: `malloc (1)` with a NUL in it); Err when memory ran out.
        pub(super) fn empty() -> Result<W, i32> {
            let mut w = W::new();
            if !w.buf.reserve_total(1) || !w.buf.push(0) {
                return Err(WRDE_NOSPACE);
            }
            Ok(w)
        }
        /// A fresh allocated NUL-terminated copy (never NULL, so an empty string is a set value).
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
        /// The text (without the NUL).
        pub(super) fn bytes(&self) -> &[u8] {
            let s = self.buf.as_slice();
            if s.is_empty() { s } else { &s[..s.len() - 1] }
        }
        pub(super) fn len(&self) -> usize {
            self.bytes().len()
        }
        /// The text up to its first NUL, with that NUL (a C string); "" for NULL.
        pub(super) fn cstr(&self) -> &[u8] {
            let s = self.buf.as_slice();
            if s.is_empty() { b"\0" } else { &s[..=super::cs(s).len()] }
        }
        /// The text and its NUL, writable (empty for NULL).
        pub(super) fn with_nul_mut(&mut self) -> &mut [u8] {
            self.buf.as_mut_slice()
        }
        /// Drop the buffer: `free (word); word = w_newword ()`.
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
        /// `w_addchar`; false when the buffer is NULL afterwards (out of memory).
        pub(super) fn addchar(&mut self, ch: u8) -> bool {
            if self.len() == self.max && !self.grow(W_CHUNK) {
                return false;
            }
            self.put(&[ch])
        }
        /// Append `s` after the text (room is there), keeping the NUL after it.
        fn put(&mut self, s: &[u8]) -> bool {
            if self.buf.len() > 0 {
                self.buf.resize(self.buf.len() - 1, 0);
            }
            self.buf.extend(s) && self.buf.push(0)
        }
        /// `w_addmem`: false when the buffer is NULL afterwards. Adding nothing to a NULL buffer leaves
        /// it NULL, which callers report as `WRDE_NOSPACE` like glibc does.
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
        /// Remove the last character (the word must not be empty).
        pub(super) fn pop(&mut self) {
            let n = self.buf.len();
            self.buf.resize(n - 1, 0);
            if let Some(last) = self.buf.as_mut_slice().last_mut() {
                *last = 0;
            }
        }
        /// Give the buffer away (to the word list, which frees it with `free`); the word becomes NULL.
        fn take(&mut self) -> *mut c_char {
            let b = core::mem::replace(&mut self.buf, CVec::new());
            self.max = 0;
            b.into_raw().0.cast()
        }
    }

    /// The caller's `wordexp_t` while one call works on it (or none: no field splitting). Invariant: a non-NULL
    /// pointer is the `wordexp_t` of the running `wordexp` call, used by nothing else meanwhile; its vector is NULL or
    /// a malloc'd array of `we_offs + we_wordc + 1` entries (`we_offs` NULLs, the words as malloc'd C strings, a NULL).
    #[derive(Clone, Copy)]
    pub(super) struct Pw(*mut Wordexp);

    impl Pw {
        pub(super) const NULL: Pw = Pw(null_mut());

        /// # Safety
        /// `p` points to a `wordexp_t` as the type's invariant describes, for the whole use of the value and its copies.
        pub(super) unsafe fn new(p: *mut Wordexp) -> Pw {
            Pw(p)
        }
        pub(super) fn is_null(self) -> bool {
            self.0.is_null()
        }
        fn we<'a>(self) -> &'a mut Wordexp {
            debug_assert!(!self.0.is_null());
            // SAFETY: the running call's own `wordexp_t` (the type's invariant); each use of the reference ends before
            // the next one starts (no method keeps it).
            unsafe { &mut *self.0 }
        }
        pub(super) fn wordc(self) -> usize {
            self.we().we_wordc
        }
        /// `w_addword`: append a word (NULL stands for "") to the list. On success the list owns it (the word is
        /// emptied); on failure the caller still owns it.
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
            // SAFETY: NULL or the list's malloc'd vector; on success the old pointer is not used again.
            let nv = unsafe { crate::cmem::realloc(we.we_wordv, core::mem::size_of::<*mut c_char>() * num_p) };
            if nv.is_null() {
                return Err(WRDE_NOSPACE);
            }
            we.we_wordv = nv;
            let at = we.we_offs + we.we_wordc;
            let s = w.take();
            // SAFETY: entries `at` and `at + 1` are inside the `num_p` entries just allocated.
            unsafe { nv.wrapping_add(at).write(s) };
            we.we_wordc += 1;
            // SAFETY: as above.
            unsafe { nv.wrapping_add(at + 1).write(null_mut()) };
            Ok(())
        }
        /// The members, to put back after a failed call.
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
        /// A fresh vector of `n` NULL entries (calloc); false when memory ran out. With `zero_offs` `we_offs`
        /// becomes 0.
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
        /// `wordfree`.
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
                // SAFETY: the vector holds the words and a NULL after them (the type's invariant); the loop stops there.
                let w = unsafe { *we.we_wordv.wrapping_add(i) };
                if w.is_null() {
                    break;
                }
                // SAFETY: a word is a malloc'd string owned by the list, which is freed now.
                unsafe { crate::cmem::free(w) };
                i += 1;
            }
            // SAFETY: the list's malloc'd vector, cleared right after.
            unsafe { crate::cmem::free(we.we_wordv) };
            we.we_wordv = null_mut();
        }
        /// Word `i` (with its NUL).
        pub(super) fn word<'a>(self, i: usize) -> &'a [u8] {
            let we = self.we();
            assert!(i < we.we_wordc);
            // SAFETY: entry `we_offs + i` is a word (the type's invariant; checked index).
            let p = unsafe { *we.we_wordv.wrapping_add(we.we_offs + i) };
            // SAFETY: a word is a C string owned by the list, which outlives the caller's use (the list is not changed
            // while the slice is used).
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

/// A fresh allocated NUL-terminated copy (never NULL, so an empty string is a set value).
fn wcopy(b: &[u8]) -> Result<W, c_int> {
    W::copy_of(b)
}

/// What the parsers share: the flags and the field separators (IFS characters, and the white
/// space among them). Parsers that are told not to split get empty separators.
#[derive(Clone, Copy)]
struct Cx<'a> {
    flags: c_int,
    ifs: &'a [u8],
    white: &'a [u8],
}

fn args() -> (c_int, *mut *mut c_char) {
    crate::err::args()
}

/// `argv[i]` of the program as bytes, if present.
fn argv_at<'a>(i: usize) -> Option<&'a [u8]> {
    let (argc, argv) = args();
    if argv.is_null() || argc <= 0 {
        return None;
    }
    // SAFETY: the program's argument vector (set at start-up) holds `argc` pointers and a NULL; callers ask for at most
    // the one after the last, which the loops stop at.
    let p = unsafe { *argv.wrapping_add(i) };
    // SAFETY: NULL or one of the program's argument strings, which live for the whole program.
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(CStr::to_bytes)
}

fn getenv_bytes(name: &[u8]) -> Option<&'static [u8]> {
    // (valid until the variable changes, which the expander does only after it is done with the value)
    crate::cmem::getenv(name)
}

// ------------------------------------------------------------------------------ backslashes

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

// ------------------------------------------------------------------------------ tilde

/// The home directory of `user` (None: of the calling user id) from the passwd database;
/// `Ok(None)` when there is no such entry or it has no directory.
fn home_of(user: Option<&[u8]>) -> Result<Option<W>, c_int> {
    // the user name as a C string
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
                // ERANGE: grow the scratch buffer
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
    // SAFETY: the entry's home directory is a C string in `buf` (not written any more) or a module's memory.
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
        // tilde on its own: $HOME, or the passwd entry of the user id when HOME is unset
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

// ------------------------------------------------------------------------------ globbing

/// Glob `glob_word` (with its NUL) with GLOB_NOCHECK and add the matches.
fn do_parse_glob(glob_word: &[u8], word: &mut W, pw: Pw, cx: Cx) -> R {
    let mut g = Glob::new();
    // SAFETY: `glob_word` is a C string and `g` a zeroed glob_t; no errfunc.
    if unsafe { glob(glob_word.as_ptr().cast(), GLOB_NOCHECK, None, &mut g) } != 0 {
        // only memory problems can happen with GLOB_NOCHECK
        return Err(WRDE_NOSPACE);
    }
    struct Free<'a>(&'a mut Glob);
    impl Drop for Free<'_> {
        fn drop(&mut self) {
            // SAFETY: the glob_t a successful glob call filled.
            unsafe { globfree(self.0) };
        }
    }
    let g = Free(&mut g);
    // SAFETY: the result of a successful glob call, freed only when `g` drops after the last use.
    let paths = || unsafe { g.0.paths() }.map(CStr::to_bytes_with_nul);

    if cx.ifs.is_empty() {
        // no field splitting: the matches become one word, separated by spaces
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
    // SAFETY: our own zeroed wordexp_t, used only through this handle until it is freed below.
    let lp = unsafe { Pw::new(&mut list) };
    let r = parse_glob_in(word, words, offset, cx, pw, lp);
    lp.free_words();
    r
}

fn parse_glob_in(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw, list: Pw) -> R {
    // We are poised at a '*', a '[' or a '?'. Collect the whole word (with its quoting and
    // expansions), then glob each resulting word.
    let mut quoted = 0; // 1 if singly-quoted, 2 if doubly
    while at(words, *offset) != 0 {
        let c = words[*offset];
        if cx.ifs.contains(&c) {
            break; // reached IFS
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

    // re-parse the character we stopped at
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
    Err(WRDE_SYNTAX) // unterminated string
}

// ------------------------------------------------------------------------------ arithmetic

fn ev_at(e: &[u8], i: usize) -> u8 {
    e.get(i).copied().unwrap_or(0)
}

/// `eval_expr_val`: a constant or a parenthesised group; `pos` is glibc's `*expr`. True = error.
fn eval_val(e: &mut [u8], pos: &mut usize, result: &mut i64) -> bool {
    let mut digit = *pos;
    while ev_at(e, digit) != 0 && is_space(e[digit]) {
        digit += 1;
    }
    if ev_at(e, digit) == b'(' {
        // scan for the closing paren, from the start of the value (the first ')' ends the group)
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
    // POSIX requires decimal, octal and hexadecimal constants: base 0
    let mut end: *mut c_char = null_mut();
    let base = e.as_ptr() as usize;
    if e.last() != Some(&0) {
        return true;
    }
    // SAFETY: `e` ends with a NUL (checked: the expression text and its NUL), so from `digit` on it is a C string;
    // strtol stores where it stopped, inside that string.
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
            // division by zero or integer overflow
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

/// `eval_expr`: sums and differences of products. True = syntax error.
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

/// Evaluate the collected expression text (NULL = empty = 0).
fn eval_text(expr: &mut W, out: &mut i64) -> bool {
    if expr.is_null() {
        return false;
    }
    eval_expr(expr.with_nul_mut(), out)
}

fn parse_arith(word: &mut W, words: &[u8], offset: &mut usize, flags: c_int, bracket: bool) -> R {
    // We are poised just after "$((" or "$["
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
                    // go: evaluate
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
                    // glibc prints the result of $[ ] as an unsigned number
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
    Err(WRDE_SYNTAX) // premature end
}

// ------------------------------------------------------------------------------ command substitution

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

/// `waitpid` with `TEMP_FAILURE_RETRY`; the status is stored when a child was reaped.
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

/// `exec_comm_child`: start `/bin/sh -c comm` (`-nc` to only check the syntax) with stdout on
/// `fildes[1]` (unless -1) and stderr on `/dev/null` unless `showerr`; the child's environment has
/// no `IFS`. Returns the child's pid, or -1 when the program could not be started.
fn spawn_sh(comm: &[u8], fildes: [i32; 2], showerr: bool, noexec: bool) -> i32 {
    let ifs_set = getenv_bytes(b"IFS").is_some();
    // SAFETY: reads the environment pointer.
    let environ = unsafe { rusty_libc_core::env::block() };
    // SAFETY: the environment block holds C strings up to a NULL; the callers stop at the NULL.
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
            // SAFETY: an entry of the environment block, a C string.
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

    // glibc's exec_comm_child: posix_spawn with file actions, no fork (a fork copies the page tables of the
    // caller, so its cost grows with the caller's memory). The shell's stdout is the pipe's write end (a
    // dup2 of the descriptor onto itself when it already is 1, which clears close-on-exec), its stderr is
    // /dev/null unless `showerr`.
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
        // (at most three actions in all: the first branch adds two, this one is the third)
        acts[n] = act(A_OPEN, 2, O_WRONLY, c"/dev/null".as_ptr() as *mut c_char);
        n += 1;
    }
    let fa = PosixSpawnFileActions { allocated: n as c_int, used: n as c_int, actions: acts.as_mut_ptr(), pad: [0; 16] };
    let mut pid: c_int = -1;
    // SAFETY: C strings for the program and arguments (`comm` ends with its NUL), a NULL-terminated environment, file
    // actions whose paths are C strings and which name our pipe's descriptors.
    let err = unsafe { spawnix(&mut pid, sh, &fa, core::ptr::null(), args.as_ptr(), envp, false, false) };
    drop(newenv);
    if err != 0 {
        return -1;
    }
    pid
}

/// `exec_comm`: run the command and append its output to `word` (split into fields when `pw` is not
/// NULL).
fn exec_comm(comm: &W, word: &mut W, cx: Cx, pw: Pw) -> R {
    let flags = cx.flags;
    let mut maxnewlines = 0usize;
    let mut buffer = [0u8; 128];
    let mut status = 0i32;
    let mut noexec = false;

    // do nothing if command substitution should not succeed
    if flags & WRDE_NOCMD != 0 {
        return Err(WRDE_CMDSUB);
    }
    // do not start a shell unless necessary
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
        // if we are just testing the syntax, only wait
        if noexec {
            let r = waitpid_retry(pid, 0, &mut status);
            return if r == pid && status != 0 { Err(WRDE_SYNTAX) } else { Ok(()) };
        }
        close_fd(fildes[1]);
        fildes[1] = -1;

        let no_space = |fd: i32| -> R {
            // SAFETY: plain values; `pid` is our child.
            unsafe { syscall::syscall2(SYS_KILL, pid as usize, SIGKILL) };
            let mut st = 0;
            waitpid_retry(pid, 0, &mut st);
            close_fd(fd);
            Err(WRDE_NOSPACE)
        };

        // 'copying' (field splitting only):
        //  0 searching for the first character of a field that is not IFS white space
        //  1 copying the text of a field
        //  2 searching for a possible non-white-space IFS
        //  3 searching for a non-newline after a field
        let mut copying = 0;
        let buflen: isize;
        loop {
            let mut bl = read_retry(fildes[0], &mut buffer);
            if bl < 1 {
                // EOF: do not use WNOHANG then, to avoid busy looping until the child exits
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
                // quoted: no field splitting
                maxnewlines += chunk.len();
                if !word.addmem(chunk) {
                    return no_space(fildes[0]);
                }
                continue;
            }

            for &ch in chunk {
                if in_set(cx.ifs, ch) {
                    // current character is IFS
                    if !in_set(cx.white, ch) {
                        // IFS but not white space
                        if copying == 2 {
                            // text<space><comma><space>moretext: strip the white space after it
                            copying = 0;
                            continue;
                        }
                        copying = 0;
                        // fall through and delimit the field
                    } else if ch == b'\n' {
                        // (IFS) newline: the end of a field being copied, but maybe all that
                        // is left is trailing newlines: search for a non-newline
                        if copying == 1 {
                            copying = 3;
                        }
                        continue;
                    } else {
                        // IFS white space, not a newline: ignore it unless copying a field or
                        // searching for a non-newline after one
                        if copying != 1 && copying != 3 {
                            continue;
                        }
                        // end of field (search for a non-white-space IFS afterwards)
                        copying = 2;
                    }
                    // first IFS white space (non-newline) or IFS non-white-space: delimit
                    if pw.add(word) == Err(WRDE_NOSPACE) {
                        return no_space(fildes[0]);
                    }
                    word.free();
                    maxnewlines = 0;
                } else {
                    // not an IFS character
                    if copying == 3 {
                        // nothing but newlines since the last field: delimit it first
                        if pw.add(word) == Err(WRDE_NOSPACE) {
                            return no_space(fildes[0]);
                        }
                        word.free();
                    }
                    copying = 1;
                    if ch == b'\n' {
                        maxnewlines += 1; // happens if the newline is not in IFS
                    } else {
                        maxnewlines = 0;
                    }
                    if !word.addchar(ch) {
                        return no_space(fildes[0]);
                    }
                }
            }
        }

        // chop off trailing newlines (POSIX.2), at most the ones this substitution added
        while maxnewlines != 0 {
            maxnewlines -= 1;
            if word.len() > 0 && word.bytes()[word.len() - 1] == b'\n' {
                word.pop();
                // a last word of only newlines becomes a new word that is ignored when nothing follows
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

        // check for a syntax error (execute again with -n)
        if buflen < 1 && status != 0 {
            noexec = true;
            continue;
        }
        return Ok(());
    }
}

fn parse_comm(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    // We are poised just after "$("
    let mut paren_depth = 1;
    let mut quoted = 0; // 1 for singly-quoted, 2 for doubly-quoted
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
                        // go: give the script to the shell
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
    Err(WRDE_SYNTAX) // premature end
}

fn parse_backtick(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    // We are poised just after "`"
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
    Err(WRDE_SYNTAX) // premature end
}

// ------------------------------------------------------------------------------ parameters

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

/// `fnmatch (pattern, string, 0) != FNM_NOMATCH` for byte strings (both with their NUL).
fn fnm(pattern: &[u8], s: &[u8]) -> bool {
    fnmatch_bytes(pattern, s, 0) != FNM_NOMATCH
}

/// Expand a `${name op pattern}` pattern: tilde, parameter, command and arithmetic expansion,
/// quotes turned into escapes so the result can go to `fnmatch`.
fn expand_pattern(pattern: &W, flags: c_int) -> Result<W, c_int> {
    let pb: &[u8] = pattern.bytes();
    let mut expanded = W::new();
    let cx = Cx { flags, ifs: &[], white: &[] };
    let mut quoted = 0; // 1: single quotes; 2: double
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
                    // a quoted wildcard becomes an escaped wildcard
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
    // We are poised just after "$"
    let flags = cx.flags;
    let start = *offset;
    let mut env = W::new();
    let mut pattern = W::new();
    let mut value: Option<W> = None;
    let mut action = ACT_NONE;
    let mut depth = 0;
    let mut colon_seen = false;
    let mut seen_hash = false;
    let mut pattern_is_quoted = 0; // 1 for singly-quoted, 2 for doubly-quoted
    let mut special = false;
    let brace = at(words, *offset) == b'{';

    'collect: {
        if brace {
            *offset += 1;
        }

        // first collect the parameter name
        if at(words, *offset) == b'#' {
            seen_hash = true;
            if !brace {
                break 'collect;
            }
            *offset += 1;
        }

        let c = at(words, *offset);
        if is_alpha(c) || c == b'_' {
            // normal parameter name
            loop {
                ok_or_nospace(env.addchar(words[*offset]))?;
                *offset += 1;
                let n = at(words, *offset);
                if !(is_alnum(n) || n == b'_') {
                    break;
                }
            }
        } else if is_digit(c) {
            // numeric parameter name
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
            // special parameter
            special = true;
            ok_or_nospace(env.addchar(c))?;
            *offset += 1;
        } else if brace {
            return Err(WRDE_SYNTAX);
        }

        if brace {
            // check for a special action to be applied to the value
            match at(words, *offset) {
                b'}' => break 'collect, // evaluate
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

            // now collect the pattern, but do not expand it yet
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
                        // quoted: a normal character; otherwise an escape (the next character is literal)
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

        // end of the input string: reparse the character that we stopped at
        *offset = offset.wrapping_sub(1);
    }

    // envsubst:
    if at(words, start) == b'{' && at(words, *offset) != b'}' {
        return Err(WRDE_SYNTAX);
    }

    let mut nbuf = [0u8; 21];
    let (argc, _) = args();
    if env.is_null() {
        if seen_hash {
            // $# expands to the number of positional parameters
            value = Some(wcopy(utoa((argc - 1) as i64 as u64, &mut nbuf))?);
            seen_hash = false;
        } else {
            // just $ on its own
            *offset = start.wrapping_sub(1);
            return ok_or_nospace(word.addchar(b'$'));
        }
    } else if is_digit(env.bytes()[0]) {
        // a positional parameter
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
            // ${#*} or ${#@}
            let n = if argc > 0 { argc - 1 } else { 0 };
            ok_or_nospace(word.addmem(utoa(n as i64 as u64, &mut nbuf)))?;
            return Ok(());
        } else if sp == b'*' || (sp == b'@' && !quoted) {
            // $* or unquoted $@: the parameters joined by spaces
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
            // a quoted "$@": each parameter is a separate word
            if argc == 2 {
                value = Some(wcopy(argv_at(1).unwrap_or(&[]))?);
            } else if argc > 2 {
                if pw.is_null() {
                    return Err(WRDE_NOSPACE);
                }
                // append the first parameter to the current word
                ok_or_nospace(word.addmem(argv_at(1).unwrap_or(&[])))?;
                pw.add(word)?;
                let mut p = 2;
                while argv_at(p + 1).is_some() {
                    let mut nw = wcopy(argv_at(p).unwrap_or(&[]))?;
                    pw.add(&mut nw)?;
                    p += 1;
                }
                // start a new word with the last parameter
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
        return Err(WRDE_BADVAL); // variable not defined
    }

    let vbytes = |v: &Option<W>| -> usize { v.as_ref().map_or(0, |w| cs(w.bytes()).len()) };
    let v_nonempty = |v: &Option<W>| -> bool { vbytes(v) != 0 };

    if action != ACT_NONE {
        // first find out if the pattern is going to be used
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
                    // the value up to its first NUL, with that NUL
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
                    // substitute the parameter
                } else {
                    if colon_seen || value.is_none() {
                        let msg: &[u8] = if pattern.is_null() || pattern.cstr()[0] == 0 { rusty_libc_core::i18n::tr(c"parameter null or not set").to_bytes() } else { cs(pattern.bytes()) };
                        let mut line = W::new();
                        line.addmem(env.bytes());
                        line.addmem(b": ");
                        line.addmem(msg);
                        line.addchar(b'\n');
                        if !line.is_null() {
                            // (a volatile load of the `stderr` variable)
                            let e = rusty_libc_stdio::file::stderr_ptr();
                            // SAFETY: the program's stderr stream (no lock, as before).
                            rusty_libc_stdio::file::write_bytes(unsafe { rusty_libc_stdio::file::stream(e) }, line.bytes());
                        }
                    }
                    // glibc returns success without adding anything
                    return Ok(());
                }
            }
            ACT_NULL_SUBST => {
                if !v_nonempty(&value) {
                    if !colon_seen && value.is_some() {
                        return Ok(()); // substitute NULL
                    }
                    value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                }
            }
            ACT_NONNULL_SUBST => {
                if value.is_some() && (v_nonempty(&value) || !colon_seen) {
                    value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                } else {
                    return Ok(()); // substitute NULL
                }
            }
            ACT_NULL_ASSIGN if !v_nonempty(&value) => {
                if !colon_seen && value.is_some() {
                    return Ok(()); // substitute NULL
                }
                value = if pattern.is_null() { None } else { Some(wcopy(cs(pattern.bytes()))?) };
                let vp: &[u8] = match &value {
                    Some(v) => v.cstr(),
                    None => b"\0",
                };
                // SAFETY: both are C strings (the name and the value with their NULs).
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
        // quoted: no field splitting
        return ok_or_nospace(word.addmem(cs(value.bytes())));
    }

    // need to field-split
    let vc = cs(value.bytes());
    let vat = |i: usize| at(vc, i);
    let mut field_begin = 0usize;
    let mut seen_nonws_ifs = false;
    loop {
        // if this is not the first field, start a new word
        if field_begin != 0 && pw.add(word) == Err(WRDE_NOSPACE) {
            return Err(WRDE_NOSPACE);
        }

        // skip IFS white space before the field
        while vat(field_begin) != 0 && cx.white.contains(&vat(field_begin)) {
            field_begin += 1;
        }
        if !seen_nonws_ifs && vat(field_begin) == 0 {
            break; // nothing but white space
        }

        // search for the end of the field
        let mut field_end = field_begin;
        while vat(field_end) != 0 && !cx.ifs.contains(&vat(field_end)) {
            field_end += 1;
        }

        // the character after the end of the field, skipping white space IFS after it
        let mut next_field = field_end;
        while vat(next_field) != 0 && cx.white.contains(&vat(next_field)) {
            next_field += 1;
        }

        // skip at most one non-white-space IFS character after the field
        seen_nonws_ifs = false;
        if vat(next_field) != 0 && cx.ifs.contains(&vat(next_field)) {
            seen_nonws_ifs = true;
            next_field += 1;
        }

        // tag a copy onto the current word
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
    // We are poised at "$"
    match at(words, 1 + *offset) {
        b'"' | b'\'' | 0 => ok_or_nospace(word.addchar(b'$')),
        b'(' => {
            if at(words, 2 + *offset) == b'(' {
                // differentiate between $((1+3)) and $((echo);(ls))
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
            *offset += 1; // parse_param needs to know if "{" is there
            parse_param(word, words, offset, cx, pw, quoted)
        }
    }
}

fn parse_dquote(word: &mut W, words: &[u8], offset: &mut usize, cx: Cx, pw: Pw) -> R {
    // We are poised just after a double quote
    let plain = Cx { flags: cx.flags, ifs: &[], white: &[] };
    while at(words, *offset) != 0 {
        match words[*offset] {
            b'"' => return Ok(()),
            // quoted: no field splitting, though "$@" may need to
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
    Err(WRDE_SYNTAX) // unterminated string
}

// ------------------------------------------------------------------------------ the entry points

/// `wordfree`: free the words and the vector of a `wordexp` result.
///
/// # Safety
/// `pwordexp` is NULL or points to a `wordexp_t` that holds a `wordexp` result (or zeros).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wordfree(pwordexp: *mut Wordexp) {
    // SAFETY: NULL or a wordexp_t holding a result or zeros (caller's contract), ours for the call.
    unsafe { Pw::new(pwordexp) }.free_words();
}

fn wordexp_in(words: &[u8], pw: Pw, flags: c_int, word: &mut W) -> c_int {
    let mut old_word = pw.save();
    let error: c_int;

    if flags & WRDE_REUSE != 0 {
        // minimal implementation of WRDE_REUSE
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

    // the field separators: IFS unset means space, tab, newline; the white space ones of a
        // set IFS are collected without duplicates
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
                    // is it a word separator?
                    if c != b' ' && c != b'\t' {
                        // not a word separator, but is it a valid word character?
                        if b"\n|&;<>(){}".contains(&c) {
                            Err(WRDE_BADCHAR)
                        } else if word.addchar(c) {
                            Ok(())
                        } else {
                            Err(WRDE_NOSPACE)
                        }
                    } else {
                        // if a word has been delimited, add it to the list
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

        // end of string: a word separator at the end means nothing is left
        if word.is_null() {
            return 0;
        }
        // no field separator at the end
        return match pw.add(word) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    // error: free the memory used (unless the error is WRDE_NOSPACE) and put the members back
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

/// `wordexp`: expand `words` like a POSIX shell would (without running anything but command
/// substitutions) into `pwordexp`. Returns 0 or one of the `WRDE_*` codes.
///
/// # Safety
/// `words` is a C string; `pwordexp` points to a `wordexp_t` (zeroed, or holding an earlier result
/// when `WRDE_APPEND` or `WRDE_REUSE` is given).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wordexp(words: *const c_char, pwordexp: *mut Wordexp, flags: c_int) -> c_int {
    // SAFETY: a C string (caller's contract).
    let w = unsafe { rusty_libc_core::ffi::cstr_nonnull(words) }.to_bytes();
    let mut word = W::new();
    // SAFETY: the caller's wordexp_t, zeroed or holding an earlier result (caller's contract), ours for the call.
    wordexp_in(w, unsafe { Pw::new(pwordexp) }, flags, &mut word)
}

// ------------------------------------------------------------------------------ the Rust API

/// The result of [`expand`]: the expanded words, freed (like `wordfree`) when dropped.
pub struct WordList {
    raw: Wordexp,
}

impl WordList {
    /// Number of words.
    pub fn len(&self) -> usize {
        self.raw.we_wordc
    }

    pub fn is_empty(&self) -> bool {
        self.raw.we_wordc == 0
    }

    /// The `i`th word.
    pub fn get(&self, i: usize) -> Option<&CStr> {
        if i >= self.raw.we_wordc {
            return None;
        }
        // SAFETY: our own list, filled by a successful wordexp; borrowed (not changed) while the result is used.
        let pw = unsafe { Pw::new(&self.raw as *const Wordexp as *mut Wordexp) };
        CStr::from_bytes_with_nul(pw.word(i)).ok()
    }

    /// All words in order.
    pub fn iter(&self) -> impl Iterator<Item = &CStr> + '_ {
        (0..self.raw.we_wordc).filter_map(move |i| self.get(i))
    }

    /// The underlying `wordexp_t` (for handing to C code); still owned by this list.
    pub fn as_raw(&self) -> &Wordexp {
        &self.raw
    }
}

impl Drop for WordList {
    fn drop(&mut self) {
        // SAFETY: our own list, holding a wordexp result or zeros.
        unsafe { Pw::new(&mut self.raw) }.free_words();
    }
}

/// Expand `words` with the `WRDE_*` `flags` (`WRDE_NOCMD`, `WRDE_SHOWERR`, `WRDE_UNDEF`; the flags
/// about reusing a result make no sense for a fresh list and are ignored). `Err` is the `WRDE_*` code.
pub fn expand(words: &CStr, flags: c_int) -> Result<WordList, c_int> {
    let mut list = WordList { raw: Wordexp::new() };
    let flags = flags & !(WRDE_APPEND | WRDE_REUSE | WRDE_DOOFFS);
    let mut word = W::new();
    // SAFETY: our own zeroed list.
    match wordexp_in(words.to_bytes(), unsafe { Pw::new(&mut list.raw) }, flags, &mut word) {
        0 => Ok(list),
        e => Err(e),
    }
}
