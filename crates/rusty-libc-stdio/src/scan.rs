//! The scanf engine: formatted input from any character source (a FILE or a string).
//!
//! Behaviour follows glibc 2.43's `vfscanf` as observed (read for behaviour, not copied): the same
//! lazy whitespace rules, the same "0x" and sign handling, the same one-character look-ahead,
//! the same quirks about when an input failure is reported as EOF. POSIX (SUSv5) is the written
//! specification.
//!
//! Locale: the decimal point (a multibyte string for narrow input, a wide character for wide input)
//! and, with the `'` flag, the thousands separator and grouping of LC_NUMERIC are honoured; the `I`
//! flag (locale input digits) is accepted and ignored. The wide conversions (`%lc`, `%ls`, `%l[`)
//! accept ASCII only.
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::floatparse::{self as fp, Bits, Target};
use crate::fmt::FmtChar;

pub const EOF: c_int = -1;

/// Entry-point flavours: the old `scanf` symbols treat `%as`, `%aS` and `%a[` as "allocate" (a GNU
/// extension); the C99 and later symbols read `%a` as a float.
pub const MODE_LEGACY_A: u32 = 1;
/// C23 entry points: `%i` accepts a `0b` prefix.
pub const MODE_C23_BIN: u32 = 2;

const LONG: u32 = 0x0001;
const LONGDBL: u32 = 0x0002;
const SHORT: u32 = 0x0004;
const SUPPRESS: u32 = 0x0008;
const NUMBER_SIGNED: u32 = 0x0040;
const GNU_MALLOC: u32 = 0x0100;
const CHAR: u32 = 0x0200;
const GROUP: u32 = 0x0080;
const HEXA_FLOAT: u32 = 0x0800;
const READ_POINTER: u32 = 0x1000;
const POSIX_MALLOC: u32 = 0x2000;
const I18N: u32 = 0x4000;
const MALLOC: u32 = GNU_MALLOC | POSIX_MALLOC;

/// A character source: `get` returns the next byte or EOF, `unget` takes one back. The methods are safe: each source
/// establishes what they need when it is made (an `unsafe` constructor: a NUL-terminated string, an open stream held
/// locked), and the engine keeps the protocol below.
pub trait Src {
    /// A source of wide characters (`wint_t`, WEOF is -1 like EOF): the wide scanf functions.
    const WIDE: bool = false;
    fn get(&mut self) -> c_int;
    /// `c` is the byte most recently returned by `get` (never EOF).
    fn unget(&mut self, c: c_int);
    /// Input that is already in memory, if any (refilling an empty buffer): (start, length). The bytes
    /// stay unread until `advance`. A string source may report an unbounded length: its NUL ends it.
    fn peek(&mut self) -> (*const u8, usize) {
        (core::ptr::null(), 0)
    }
    /// Mark `n` peeked bytes as read (`n` no more than `peek` offered, and not past a string's NUL).
    fn advance(&mut self, _n: usize) {}
    /// glibc's `ORIENT` at the top of the narrow scanf functions: a stream fixes its byte orientation
    /// here, and a wide-oriented one makes the call return EOF at once (no errno).
    fn orient_ok(&mut self) -> bool {
        true
    }
}

/// Where the pointer arguments come from: `pos` is 0 for "the next one", or the 1-based `%N$` index.
pub trait PtrArgs {
    fn next(&mut self, pos: usize) -> *mut c_void;
}

/// A source over a NUL-terminated string.
pub struct StrSrc {
    p: *const u8,
}

impl StrSrc {
    /// # Safety
    /// `p` is a NUL-terminated string that outlives the source.
    pub unsafe fn new(p: *const u8) -> StrSrc {
        StrSrc { p }
    }
}

// `p` stays inside the string: `get` steps over non-NUL bytes only, `unget` steps back over the byte `get` returned,
// `advance` over bytes `peek` handed out before the NUL (the `Src` protocol).
impl Src for StrSrc {
    fn get(&mut self) -> c_int {
        // SAFETY: `new`'s contract and the protocol above: `p` is inside the string (at most at its NUL).
        let b = unsafe { *self.p };
        if b == 0 {
            EOF
        } else {
            self.p = self.p.wrapping_add(1);
            c_int::from(b)
        }
    }
    fn unget(&mut self, _c: c_int) {
        self.p = self.p.wrapping_sub(1);
    }
    fn peek(&mut self) -> (*const u8, usize) {
        (self.p, usize::MAX)
    }
    fn advance(&mut self, n: usize) {
        self.p = self.p.wrapping_add(n);
    }
}

/// A growable byte buffer on the heap.
struct Buf {
    p: *mut u8,
    len: usize,
    cap: usize,
    oom: bool,
}

// Invariant: `p` is null (`len` = `cap` = 0) or a malloc'd block of `cap` bytes, the first `len` written. The block is the
// buffer's until `release` frees it or a `%ms` conversion hands it to the program (`finish_alloc`).
impl Buf {
    const fn new() -> Buf {
        Buf { p: null_mut(), len: 0, cap: 0, oom: false }
    }
    fn push(&mut self, b: u8) {
        if self.len == self.cap {
            let nc = if self.cap == 0 { 64 } else { self.cap * 2 };
            // SAFETY: `p` is null or our own malloc'd block (the invariant).
            let np = unsafe { rusty_libc_malloc::realloc(self.p.cast(), nc) } as *mut u8;
            if np.is_null() {
                self.oom = true;
                return;
            }
            self.p = np;
            self.cap = nc;
        }
        // SAFETY: `len < cap`: inside the block.
        unsafe { *self.p.wrapping_add(self.len) = b };
        self.len += 1;
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: the invariant: `len` bytes written.
        if self.p.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.p, self.len) } }
    }
    fn release(&mut self) {
        // SAFETY: null or our own block (not handed over: a handed-over buffer is never released), forgotten right below.
        unsafe { crate::file::free(self.p) };
        *self = Buf::new();
    }
}

/// Bytes collected for one number: kept on the stack, spilling to the heap only for very long input.
struct Text {
    inline: [u8; 96],
    len: usize,
    heap: Buf,
    spilled: bool,
}

impl Text {
    const fn new() -> Text {
        Text { inline: [0; 96], len: 0, heap: Buf::new(), spilled: false }
    }
    fn push(&mut self, b: u8) {
        if !self.spilled {
            if self.len < self.inline.len() {
                self.inline[self.len] = b;
                self.len += 1;
                return;
            }
            self.spilled = true;
            for i in 0..self.len {
                self.heap.push(self.inline[i]);
            }
        }
        self.heap.push(b);
        self.len = self.heap.len;
    }
    fn oom(&self) -> bool {
        self.heap.oom
    }
    fn bytes(&self) -> &[u8] {
        if self.spilled { self.heap.bytes() } else { &self.inline[..self.len] }
    }
    fn release(&mut self) {
        self.heap.release();
    }
}

/// A list of `char **` slots that hold allocated strings (so a failure can free them again).
struct SlotList {
    p: *mut *mut *mut u8,
    len: usize,
    cap: usize,
}

// Invariant: `p` is null (`len` = `cap` = 0) or the list's own malloc'd block of `cap` slots, the first `len` written.
impl SlotList {
    fn push(&mut self, s: *mut *mut u8) {
        if self.len == self.cap {
            let nc = if self.cap == 0 { 8 } else { self.cap * 2 };
            // SAFETY: `p` is null or our own malloc'd block (the invariant).
            let np = unsafe { rusty_libc_malloc::realloc(self.p.cast(), nc * core::mem::size_of::<usize>()) } as *mut *mut *mut u8;
            if np.is_null() {
                return;
            }
            self.p = np;
            self.cap = nc;
        }
        // SAFETY: `len < cap`: inside the block.
        unsafe { *self.p.wrapping_add(self.len) = s };
        self.len += 1;
    }
    fn as_slice(&self) -> &[*mut *mut u8] {
        // SAFETY: the invariant: `len` slots written.
        if self.p.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.p, self.len) } }
    }
    fn free(&mut self) {
        // SAFETY: null or our own block, forgotten right below.
        unsafe { crate::file::free(self.p.cast()) };
        *self = SlotList { p: null_mut(), len: 0, cap: 0 };
    }
}

enum Stop {
    /// Matching failure: stop, report the assignments so far.
    Conv,
    /// Input failure: like Conv, but EOF if nothing was assigned.
    Input,
    /// Stop with errno already set, count unchanged (bad encoding).
    Encode,
    /// Stop and report EOF (allocation failure with `m`).
    Nomem,
}

fn is_space(c: c_int) -> bool {
    c == 32 || (9..=13).contains(&c)
}

fn lower(c: c_int) -> c_int {
    if (b'A' as c_int..=b'Z' as c_int).contains(&c) { c + 32 } else { c }
}

fn is_digit(c: c_int) -> bool {
    (b'0' as c_int..=b'9' as c_int).contains(&c)
}

fn is_xdigit(c: c_int) -> bool {
    is_digit(c) || (b'a' as c_int..=b'f' as c_int).contains(&lower(c))
}

fn digit_value(c: c_int) -> u32 {
    if is_digit(c) { (c - b'0' as c_int) as u32 } else { (lower(c) - b'a' as c_int) as u32 + 10 }
}

struct Spec {
    flags: u32,
    width: i64, // -1: unlimited
    argpos: usize,
}

struct Engine<'a, S: Src, A: PtrArgs, F: FmtChar> {
    src: &'a mut S,
    args: &'a mut A,
    mode: u32,
    nu: Option<rusty_libc_core::locale::Numeric>,
    read_in: usize,
    c: c_int,
    /// errno at the read that returned EOF; `inchar` restores it on every later call (glibc's `inchar_errno`).
    inchar_errno: c_int,
    done: c_int,
    strptr: *mut *mut u8,
    slots: SlotList,
    _f: core::marker::PhantomData<F>,
}

impl<S: Src, A: PtrArgs, F: FmtChar> Engine<'_, S, A, F> {
    /// The numeric rules of the locale in force, looked up on first use (most scans need none).
    #[inline]
    fn nu(&mut self) -> rusty_libc_core::locale::Numeric {
        *self.nu.get_or_insert_with(rusty_libc_core::locale::numeric)
    }

    /// White space as the input is classified: iswspace for wide input.
    #[inline(always)]
    fn sp(&self, c: c_int) -> bool {
        if S::WIDE { rusty_libc_wchar::wctype::is_space(c as u32) } else { is_space(c) }
    }

    fn inchar(&mut self) -> c_int {
        if self.c == EOF {
            errno::set(self.inchar_errno);
            return EOF;
        }
        self.c = self.src.get();
        if self.c != EOF {
            self.read_in += 1;
        } else {
            self.inchar_errno = errno::get();
        }
        self.c
    }

    fn unget(&mut self, c: c_int) {
        if c != EOF {
            self.read_in -= 1;
            self.src.unget(c);
        }
    }

    fn arg(&mut self, sp: &Spec) -> *mut c_void {
        self.args.next(sp.argpos)
    }

    /// Narrow input that a `l` conversion stores as `wchar_t` (`%lc`, `%ls`, `%l[`, `%C`, `%S`): the multibyte character
    /// whose first byte `first` was just read, completed with more bytes and decoded in the locale's charset. The bytes are
    /// left in `bytes[..n]` so that a character that does not belong can be pushed back. `Err`: invalid (errno is EILSEQ) or
    /// the input ends inside the character.
    fn read_mb(&mut self, first: c_int, bytes: &mut [u8; 6]) -> Result<(u32, usize), ()> {
        bytes[0] = first as u8;
        let mut n = 1;
        if first < 0x80 {
            return Ok((first as u32, 1));
        }
        let mut st = rusty_libc_wchar::mbstate_t::default();
        loop {
            match rusty_libc_wchar::mbyte::decode_char(&bytes[..n], &mut st) {
                rusty_libc_wchar::mbyte::Decoded::Char(w, _) => return Ok((w, n)),
                rusty_libc_wchar::mbyte::Decoded::Invalid => {
                    errno::set(84);
                    return Err(());
                }
                rusty_libc_wchar::mbyte::Decoded::Incomplete => {
                    if n == 6 {
                        errno::set(84);
                        return Err(());
                    }
                    let c = self.inchar();
                    if c == EOF {
                        errno::set(84);
                        return Err(());
                    }
                    bytes[n] = c as u8;
                    n += 1;
                    // (a fresh state each round: decode_char restarts on the whole prefix)
                    st = rusty_libc_wchar::mbstate_t::default();
                }
            }
        }
    }

    /// Push back the bytes of a multibyte character read with `read_mb` (last byte first).
    fn unget_mb(&mut self, bytes: &[u8]) {
        for &b in bytes.iter().rev() {
            self.unget(c_int::from(b));
        }
    }

    /// The first character of the multibyte string `pat` was just read (`*c`): read and compare the
    /// rest. `width` counts what is left of the field (-1: unlimited) and shrinks by every extra
    /// character read. On a mismatch `*c` becomes the character that failed; with `pushback` the
    /// matched prefix goes back to the input (glibc does that for integers, not for floats).
    fn match_rest(&mut self, pat: &[u8], c: &mut c_int, width: &mut i64, pushback: bool) -> bool {
        for (j, &p) in pat.iter().enumerate().skip(1) {
            let ch = if *width == 0 { EOF } else { self.inchar() };
            if ch != EOF && *width > 0 {
                *width -= 1;
            }
            if ch != c_int::from(p) {
                if pushback {
                    if *width != 0 || ch != EOF {
                        self.unget(ch);
                    }
                    for k in (1..j).rev() {
                        self.unget(c_int::from(pat[k]));
                    }
                    *c = c_int::from(pat[0]);
                } else {
                    *c = ch;
                }
                return false;
            }
        }
        true
    }

    /// Does the character just read start the thousands separator, and is the whole separator
    /// there? (Narrow input compares the multibyte string, wide input one wide character.)
    fn at_thousands(&mut self, c: &mut c_int, width: &mut i64, pushback: bool) -> bool {
        if S::WIDE {
            return *c as u32 == self.nu().thousands_wc;
        }
        let th = self.nu().thousands_sep;
        if th.is_empty() || *c != c_int::from(th[0]) {
            return false;
        }
        self.match_rest(th, c, width, pushback)
    }

    /// `%I`: does the character just read start one of the locale's own digits (LC_CTYPE's INDIGITS0_MB ... INDIGITS9_MB, the
    /// INDIGITSn_WC for wide input)? The digit's value; the character is consumed (a partial match is given back). The map to_inpunct adds the digits some locales (fa_IR) define only there.
    fn at_indigit(&mut self, c: &mut c_int, width: &mut i64) -> Option<u32> {
        let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE)?;
        // a locale such as fa_IR keeps ASCII INDIGITS and gives its own digits only through the map to_inpunct
        let map = rusty_libc_wchar::wctype::trans_by_name(b"to_inpunct");
        for n in 0..10usize {
            if S::WIDE {
                let p = d.cstr(31 + n) as *const u32;
                // SAFETY: the INDIGITSn_WC strings of the locale data: null or a wide string ending in 0 (its first
                // character exists).
                if !p.is_null() && unsafe { *p } != 0 && unsafe { *p } == *c as u32 {
                    return Some(n as u32);
                }
            } else {
                let pat = d.bytes(20 + n);
                if !pat.is_empty() && c_int::from(pat[0]) == *c && self.match_rest(pat, c, width, true) {
                    return Some(n as u32);
                }
            }
            if !map.is_null() {
                let w = rusty_libc_wchar::wctype::map_by_desc(u32::from(b'0') + n as u32, map);
                if w != u32::from(b'0') + n as u32 {
                    if S::WIDE {
                        if *c as u32 == w {
                            return Some(n as u32);
                        }
                    } else {
                        let mut b = [0u8; 6];
                        if let Some(k) = rusty_libc_wchar::mbyte::encode_char(w, &mut b)
                            && c_int::from(b[0]) == *c
                            && self.match_rest(&b[..k], c, width, true)
                        {
                            return Some(n as u32);
                        }
                    }
                }
            }
        }
        None
    }

    /// The same for the decimal point.
    fn at_decimal(&mut self, c: &mut c_int, width: &mut i64) -> bool {
        if S::WIDE {
            return *c as u32 == self.nu().decimal_wc;
        }
        let dp = self.nu().decimal_point;
        if dp.is_empty() || *c != c_int::from(dp[0]) {
            return false;
        }
        self.match_rest(dp, c, width, false)
    }

    /// The whole format.
    ///
    /// # Safety
    /// `fmt` is NUL-terminated; the pointer arguments match its conversions.
    unsafe fn body(&mut self, fmt: *const F, skip_space: &mut bool) -> Result<(), Stop> {
        let mut f = fmt;
        while fmt_at!(f, 0) != 0 {
            let b = fmt_at!(f, 0);
            let raw = fmt_raw!(f, 0);
            f = f.wrapping_add(1);
            if !F::WIDE && b >= 0x80 {
                // a multibyte character in a narrow format must match byte for byte
                let c = self.inchar();
                if c == EOF {
                    return Err(Stop::Input);
                }
                if c != raw as c_int {
                    self.unget(c);
                    return Err(Stop::Conv);
                }
                continue;
            }
            // (a wide format character is an ordinary one whatever it is: white space skipping applies to it)
            let fc = if F::WIDE { raw as c_int } else { c_int::from(b) };
            if fc != b'%' as c_int {
                if self.sp(fc) {
                    *skip_space = true;
                    continue;
                }
                let c = self.inchar();
                if c == EOF {
                    return Err(Stop::Input);
                }
                if *skip_space {
                    while self.sp(self.c) {
                        if self.inchar() == EOF {
                            return Err(Stop::Input);
                        }
                    }
                    *skip_space = false;
                }
                if self.c != fc {
                    let c = self.c;
                    self.unget(c);
                    return Err(Stop::Conv);
                }
                // a run of ordinary characters that the buffered input already matches; a white space in the
                // format (followed by an ordinary character) matches any amount of white space in the buffer
                let (p, avail) = self.src.peek();
                if !p.is_null() {
                    // byte `i` of the peeked input: read only below `avail` and never past a string source's NUL (a
                    // byte is looked at only after the bytes before it matched non-NUL format characters)
                    // SAFETY: `peek` handed out `avail` readable bytes (a string: up to its NUL); see above for the index.
                    let at = |i: usize| unsafe { *p.wrapping_add(i) };
                    let (mut k, mut j) = (0usize, 0usize);
                    loop {
                        let want = fmt_at!(f, j);
                        if want == 0 || want == b'%' || want >= 0x80 {
                            break;
                        }
                        if is_space(c_int::from(want)) {
                            let mut jj = j + 1;
                            while is_space(c_int::from(fmt_at!(f, jj))) {
                                jj += 1;
                            }
                            let next = fmt_at!(f, jj);
                            if next == 0 || next == b'%' || next >= 0x80 {
                                break;
                            }
                            let mut kk = k;
                            while kk < avail && is_space(c_int::from(at(kk))) {
                                kk += 1;
                            }
                            if kk >= avail || at(kk) != next {
                                break;
                            }
                            k = kk + 1;
                            j = jj + 1;
                            continue;
                        }
                        if k >= avail || at(k) != want {
                            break;
                        }
                        k += 1;
                        j += 1;
                    }
                    if k > 0 {
                        self.src.advance(k);
                        self.read_in += k;
                        self.c = c_int::from(at(k - 1));
                        f = f.wrapping_add(j);
                    }
                }
                continue;
            }
            // a conversion specification
            let mut sp = Spec { flags: 0, width: 0, argpos: 0 };
            let mut got_width = false;
            if fmt_at!(f, 0).is_ascii_digit() {
                // SAFETY: the function's contract: the format is NUL-terminated and `f` points into it.
                let n = unsafe { read_int(&mut f) };
                if fmt_at!(f, 0) == b'$' {
                    f = f.wrapping_add(1);
                    sp.argpos = n as usize;
                } else {
                    sp.width = n;
                    got_width = true;
                }
            }
            if !got_width {
                while matches!(fmt_at!(f, 0), b'*' | b'\'' | b'I') {
                    match fmt_at!(f, 0) {
                        b'*' => sp.flags |= SUPPRESS,
                        b'\'' => {
                            // grouping only matters when the locale has a thousands separator
                            if if S::WIDE { self.nu().thousands_wc != 0 } else { !self.nu().thousands_sep.is_empty() } {
                                sp.flags |= GROUP;
                            }
                        }
                        b'I' => sp.flags |= I18N,
                        _ => {}
                    }
                    f = f.wrapping_add(1);
                }
                if fmt_at!(f, 0).is_ascii_digit() {
                    // SAFETY: the function's contract: the format is NUL-terminated and `f` points into it.
                    sp.width = unsafe { read_int(&mut f) };
                }
            }
            if sp.width == 0 {
                sp.width = -1;
            }
            // length modifiers
            let m = fmt_at!(f, 0);
            f = f.wrapping_add(1);
            match m {
                b'h' => {
                    if fmt_at!(f, 0) == b'h' {
                        f = f.wrapping_add(1);
                        sp.flags |= CHAR;
                    } else {
                        sp.flags |= SHORT;
                    }
                }
                b'l' => {
                    if fmt_at!(f, 0) == b'l' {
                        f = f.wrapping_add(1);
                        sp.flags |= LONGDBL | LONG;
                    } else {
                        sp.flags |= LONG;
                    }
                }
                b'q' | b'L' => sp.flags |= LONGDBL | LONG,
                b'a' => {
                    if !matches!(fmt_at!(f, 0), b's' | b'S' | b'[') || self.mode & MODE_LEGACY_A == 0 {
                        f = f.wrapping_sub(1);
                    } else {
                        sp.flags |= GNU_MALLOC;
                    }
                }
                b'm' => {
                    sp.flags |= POSIX_MALLOC;
                    if fmt_at!(f, 0) == b'l' {
                        f = f.wrapping_add(1);
                        sp.flags |= LONG;
                    }
                }
                b'z' | b'j' | b't' => sp.flags |= LONG,
                b'w' => {
                    let mut fast = false;
                    if fmt_at!(f, 0) == b'f' {
                        f = f.wrapping_add(1);
                        fast = true;
                    }
                    let mut bits = 0;
                    if fmt_at!(f, 0).is_ascii_digit() {
                        // SAFETY: the function's contract: the format is NUL-terminated and `f` points into it.
                        bits = unsafe { read_int(&mut f) };
                    }
                    if fast {
                        bits = match bits {
                            8 => 8,
                            16 | 32 | 64 => 64,
                            x => x,
                        };
                    }
                    match bits {
                        8 => sp.flags |= CHAR,
                        16 => sp.flags |= SHORT,
                        32 => {}
                        64 => sp.flags |= LONGDBL | LONG,
                        _ => {
                            errno::set(22);
                            return Err(Stop::Encode);
                        }
                    }
                }
                _ => f = f.wrapping_sub(1),
            }
            if fmt_at!(f, 0) == 0 {
                return Err(Stop::Conv);
            }
            let conv = fmt_at!(f, 0);
            f = f.wrapping_add(1);
            // eat whitespace before everything except %[ %c %C %n
            if *skip_space || !matches!(conv, b'[' | b'c' | b'C' | b'n') {
                let save = errno::get();
                errno::set(0);
                loop {
                    if self.c == EOF || self.inchar() == EOF {
                        // (glibc only reacts to EINTR here, which never happens for us)
                    }
                    if !self.sp(self.c) {
                        break;
                    }
                }
                errno::set(save);
                let c = self.c;
                self.unget(c);
                *skip_space = false;
            }
            match conv {
                b'%' => {
                    let c = self.inchar();
                    if c == EOF {
                        return Err(Stop::Input);
                    }
                    if c != c_int::from(b'%') {
                        self.unget(c);
                        return Err(Stop::Conv);
                    }
                }
                b'n' => {
                    if sp.flags & SUPPRESS == 0 {
                        let p = self.arg(&sp);
                        let v = self.read_in;
                        // The function's contract: a `%n` argument points to an integer of the size its length modifier
                        // names; each branch stores that one.
                        if sp.flags & LONG != 0 {
                            // SAFETY: see above.
                            unsafe { (p as *mut i64).write_unaligned(v as i64) };
                        } else if sp.flags & SHORT != 0 {
                            // SAFETY: see above.
                            unsafe { (p as *mut i16).write_unaligned(v as i16) };
                        } else if sp.flags & CHAR == 0 {
                            // SAFETY: see above.
                            unsafe { (p as *mut i32).write_unaligned(v as i32) };
                        } else {
                            // SAFETY: see above.
                            unsafe { (p as *mut i8).write_unaligned(v as i8) };
                        }
                    }
                }
                b'c' | b'C' => {
                    if conv == b'C' {
                        sp.flags |= LONG;
                    }
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.conv_c(&mut sp) }?;
                }
                b's' | b'S' => {
                    if conv == b'S' {
                        sp.flags |= LONG;
                    }
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.conv_s(&mut sp) }?;
                }
                b'[' => {
                    // SAFETY: the function's contract: the format (`f` inside it) and the pointer arguments.
                    let r = unsafe { self.conv_set(&mut sp, &mut f) };
                    r?;
                }
                b'x' | b'X' => {
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 16) }?
                }
                b'o' => {
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 8) }?
                }
                b'b' => {
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 2) }?
                }
                b'u' => {
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 10) }?
                }
                b'd' => {
                    sp.flags |= NUMBER_SIGNED;
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 10) }?
                }
                b'i' => {
                    sp.flags |= NUMBER_SIGNED;
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 0) }?
                }
                b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.float(&mut sp) }?
                }
                b'p' => {
                    sp.flags &= !(SHORT | LONGDBL);
                    sp.flags |= LONG | READ_POINTER;
                    // SAFETY: the function's contract: the pointer arguments match the format's conversions.
                    unsafe { self.number(&mut sp, 16) }?
                }
                _ => return Err(Stop::Conv),
            }
        }
        Ok(())
    }

    /// Prepare the destination of a string-like conversion. Returns (plain pointer, is_alloc).
    ///
    /// # Safety
    /// The conversion's pointer argument is what it takes (a `char **` for the allocating forms).
    unsafe fn string_target(&mut self, sp: &Spec) -> Result<*mut u8, Stop> {
        if sp.flags & SUPPRESS != 0 {
            return Ok(null_mut());
        }
        if sp.flags & MALLOC != 0 {
            let sp_ = self.arg(sp) as *mut *mut u8;
            if sp_.is_null() {
                return Err(Stop::Conv);
            }
            self.strptr = sp_;
            // SAFETY: the caller's contract: a `char **`.
            unsafe { *sp_ = null_mut() };
            self.slots.push(sp_);
            return Ok(null_mut());
        }
        let p = self.arg(sp) as *mut u8;
        if p.is_null() {
            return Err(Stop::Conv);
        }
        Ok(p)
    }

    /// Finish a string-like conversion into an allocated buffer.
    ///
    /// # Safety
    /// `strptr` is the conversion's `char **` (set by `string_target`).
    unsafe fn finish_alloc(&mut self, buf: &mut Buf) -> Result<(), Stop> {
        if buf.oom {
            buf.release();
            return Err(Stop::Nomem);
        }
        // SAFETY: the caller's contract (the block is handed to the program).
        unsafe { *self.strptr = buf.p };
        self.strptr = null_mut();
        Ok(())
    }

    /// Store one input character `c` of a string-like conversion at `*dst` (or in `buf` for the allocating
    /// forms). Wide input without `l` is stored in its multibyte form; with `l` as a `wchar_t`. Narrow input
    /// with `l` is stored as a `wchar_t` (only ASCII is understood so far: anything else is EILSEQ).
    /// False: the character cannot be stored (errno is set).
    ///
    /// # Safety
    /// Without `alloc`, `*dst` points into the conversion's destination array with room for the character (the program's
    /// promise: the array is big enough for the field).
    unsafe fn store_char(&mut self, sp: &Spec, alloc: bool, buf: &mut Buf, dst: &mut *mut u8, c: c_int) -> bool {
        let wide_out = sp.flags & LONG != 0;
        if S::WIDE && !wide_out {
            let mut b = [0u8; 6];
            let Some(n) = rusty_libc_wchar::mbyte::encode_char(c as u32, &mut b) else {
                errno::set(84);
                return false;
            };
            for &byte in &b[..n] {
                if alloc {
                    buf.push(byte);
                } else {
                    // SAFETY: the caller's contract.
                    unsafe { **dst = byte };
                    *dst = dst.wrapping_add(1);
                }
            }
            return true;
        }
        let unit = if wide_out { 4 } else { 1 };
        let v = (c as u32).to_le_bytes();
        for &byte in &v[..unit] {
            if alloc {
                buf.push(byte);
            } else {
                // SAFETY: the caller's contract.
                unsafe { **dst = byte };
                *dst = dst.wrapping_add(1);
            }
        }
        true
    }

    /// The terminator of a string-like conversion (a NUL byte, or a NUL `wchar_t` with `l`).
    ///
    /// # Safety
    /// As `store_char`, with room for the terminator.
    unsafe fn store_nul(&mut self, sp: &Spec, alloc: bool, buf: &mut Buf, dst: &mut *mut u8) {
        // (wide input stored as multibyte: glibc writes the terminator twice)
        for _ in 0..if sp.flags & LONG != 0 { 4 } else if S::WIDE { 2 } else { 1 } {
            if alloc {
                buf.push(0);
            } else {
                // SAFETY: the caller's contract.
                unsafe { **dst = 0 };
                *dst = dst.wrapping_add(1);
            }
        }
    }

    /// # Safety
    /// The conversion's pointer argument is what it takes, its array big enough for the field.
    unsafe fn conv_c(&mut self, sp: &mut Spec) -> Result<(), Stop> {
        if sp.width == -1 {
            sp.width = 1;
        }
        // SAFETY: the function's contract: the pointer arguments match the format's conversions.
        let dst = unsafe { self.string_target(sp) }?;
        let mut dst = dst;
        let mut buf = Buf::new();
        let alloc = sp.flags & MALLOC != 0;
        let mut c = self.inchar();
        if c == EOF {
            return Err(Stop::Input);
        }
        let mut width = sp.width;
        loop {
            if !S::WIDE && sp.flags & LONG != 0 {
                let mut mb = [0u8; 6];
                match self.read_mb(c, &mut mb) {
                    Ok((w, _)) => c = w as c_int,
                    Err(()) => {
                        if alloc {
                            buf.release();
                        }
                        return Err(Stop::Encode);
                    }
                }
            }
            // SAFETY: the function's contract: the destination array has room for the field.
            if sp.flags & SUPPRESS == 0 && !unsafe { self.store_char(sp, alloc, &mut buf, &mut dst, c) } {
                if alloc {
                    buf.release();
                }
                return Err(Stop::Encode);
            }
            width -= 1;
            if !(width > 0 && self.inchar() != EOF) {
                break;
            }
            c = self.c;
        }
        if width > 0 {
            if alloc {
                buf.release();
            }
            return Err(Stop::Input);
        }
        if sp.flags & SUPPRESS == 0 {
            if alloc {
                // SAFETY: `strptr` was set by `string_target` for this allocating conversion.
                unsafe { self.finish_alloc(&mut buf) }?;
            }
            self.done += 1;
        }
        Ok(())
    }

    /// # Safety
    /// As `conv_c`, with room for the terminator.
    unsafe fn conv_s(&mut self, sp: &mut Spec) -> Result<(), Stop> {
        // SAFETY: the function's contract: the pointer arguments match the format's conversions.
        let dst = unsafe { self.string_target(sp) }?;
        let mut dst = dst;
        let mut buf = Buf::new();
        let alloc = sp.flags & MALLOC != 0;
        let mut c = self.inchar();
        if c == EOF {
            return Err(Stop::Input);
        }
        let mut width = sp.width;
        loop {
            if self.sp(c) {
                self.unget(c);
                break;
            }
            if !S::WIDE && sp.flags & LONG != 0 {
                let mut mb = [0u8; 6];
                match self.read_mb(c, &mut mb) {
                    Ok((w, _)) => c = w as c_int,
                    Err(()) => {
                        if alloc {
                            buf.release();
                        }
                        return Err(Stop::Encode);
                    }
                }
            }
            // SAFETY: the function's contract: the destination array has room for the field.
            if sp.flags & SUPPRESS == 0 && !unsafe { self.store_char(sp, alloc, &mut buf, &mut dst, c) } {
                if alloc {
                    buf.release();
                }
                return Err(Stop::Encode);
            }
            let more = if width <= 0 {
                true
            } else {
                width -= 1;
                width > 0
            };
            if !(more && self.inchar() != EOF) {
                break;
            }
            c = self.c;
        }
        if sp.flags & SUPPRESS == 0 {
            // SAFETY: the function's contract: the destination array has room for the field and its terminator.
            unsafe { self.store_nul(sp, alloc, &mut buf, &mut dst) };
            if alloc {
                // SAFETY: `strptr` was set by `string_target` for this allocating conversion.
                unsafe { self.finish_alloc(&mut buf) }?;
            }
            self.done += 1;
        }
        Ok(())
    }

    /// # Safety
    /// As `conv_s`; `*fp_` points into the NUL-terminated format, just after the `[`.
    unsafe fn conv_set(&mut self, sp: &mut Spec, fp_: &mut *const F) -> Result<(), Stop> {
        // SAFETY: the function's contract: the pointer arguments match the format's conversions.
        let dst = unsafe { self.string_target(sp) }?;
        let mut dst = dst;
        let mut f = *fp_;
        let not_in = if fmt_at!(f, 0) == b'^' {
            f = f.wrapping_add(1);
            true
        } else {
            false
        };
        let set_start = f;
        // find the end of the set
        if fmt_at!(f, 0) == b']' || fmt_at!(f, 0) == b'-' {
            f = f.wrapping_add(1);
        }
        loop {
            let fc = fmt_at!(f, 0);
            if fc == 0 {
                *fp_ = f;
                return Err(Stop::Conv);
            }
            f = f.wrapping_add(1);
            if fc == b']' {
                break;
            }
        }
        let set_end = f.wrapping_sub(1); // the closing bracket
        *fp_ = f;
        // narrow input: a table of the 256 bytes; wide input looks the character up in the set text
        let mut map = [false; 256];
        if !S::WIDE {
            let mut g = set_start;
            let first = fmt_at!(g, 0) as i8;
            if first == b']' as i8 || first == b'-' as i8 {
                map[fmt_at!(g, 0) as usize] = true;
                g = g.wrapping_add(1);
            }
            while g < set_end {
                let fc = fmt_at!(g, 0);
                g = g.wrapping_add(1);
                // `a-z` range: glibc compares as signed char and adds up to, not including, the end
                if fc == b'-' && g < set_end && (fmt_at!(g, 0) != b']') && (fmt_at!(g.wrapping_sub(2), 0) as i8) <= (fmt_at!(g, 0) as i8) {
                    let mut x = fmt_at!(g.wrapping_sub(2), 0) as i8;
                    while x < fmt_at!(g, 0) as i8 {
                        map[x as u8 as usize] = true;
                        x += 1;
                    }
                } else {
                    map[fc as usize] = true;
                }
            }
        }
        let wide_in_set = |c: u32| -> bool {
            // wide: the characters and ranges of the set text
            let mut g = set_start;
            let mut prev: Option<u32> = None;
            let mut first = true;
            while g < set_end {
                let raw = fmt_raw!(g, 0);
                g = g.wrapping_add(1);
                if raw == u32::from(b'-') && !first && g < set_end && prev.is_some() {
                    let hi = fmt_raw!(g, 0);
                    let lo = prev.unwrap();
                    if (lo as i32) <= (hi as i32) {
                        if (lo as i32) <= (c as i32) && (c as i32) <= (hi as i32) {
                            return true;
                        }
                        g = g.wrapping_add(1);
                        prev = Some(hi); // the end of a range can start the next one
                        continue;
                    }
                }
                if raw == c {
                    return true;
                }
                prev = Some(raw);
                first = false;
            }
            false
        };
        // narrow input stored as wchar_t: the set text is decoded as multibyte characters (a byte that is not valid stands for
        // itself, as in glibc's bug14), and the input is taken one multibyte character at a time
        let mb_wide = !S::WIDE && sp.flags & LONG != 0;
        let narrow_in_set = |c: u32| -> bool {
            let mut g = set_start;
            let mut prev: Option<u32> = None;
            let mut first = true;
            // the next set character: (wide character, bytes used)
            let next = |g: *const F| -> (u32, usize) {
                let mut tmp = [0u8; 6];
                let mut k = 0;
                while k < 6 && g.wrapping_add(k) < set_end {
                    tmp[k] = fmt_raw!(g, k) as u8;
                    k += 1;
                    if let rusty_libc_wchar::mbyte::Decoded::Char(w, n) = rusty_libc_wchar::mbyte::decode_char(&tmp[..k], &mut rusty_libc_wchar::mbstate_t::default()) {
                        return (w, n);
                    }
                    if tmp[0] < 0x80 {
                        break;
                    }
                }
                (u32::from(tmp[0]), 1)
            };
            while g < set_end {
                let (raw, n) = next(g);
                g = g.wrapping_add(n);
                if raw == u32::from(b'-') && !first && g < set_end && prev.is_some() {
                    let (hi, hn) = next(g);
                    let lo = prev.unwrap();
                    if (lo as i32) <= (hi as i32) {
                        if (lo as i32) <= (c as i32) && (c as i32) <= (hi as i32) {
                            return true;
                        }
                        g = g.wrapping_add(hn);
                        prev = Some(hi);
                        continue;
                    }
                }
                if raw == c {
                    return true;
                }
                prev = Some(raw);
                first = false;
            }
            false
        };
        let alloc = sp.flags & MALLOC != 0;
        let mut buf = Buf::new();
        let now = self.read_in;
        let mut c = self.inchar();
        if c == EOF {
            return Err(Stop::Input);
        }
        let mut width = sp.width;
        loop {
            let mut mb = [0u8; 6];
            let mut mb_len = 0;
            if mb_wide {
                match self.read_mb(c, &mut mb) {
                    Ok((w, n)) => {
                        c = w as c_int;
                        mb_len = n;
                    }
                    Err(()) => {
                        if alloc {
                            buf.release();
                        }
                        return Err(Stop::Encode);
                    }
                }
            }
            let member = if S::WIDE {
                wide_in_set(c as u32)
            } else if mb_wide {
                narrow_in_set(c as u32)
            } else {
                map[c as usize & 0xff]
            };
            if member == not_in {
                if mb_wide {
                    self.unget_mb(&mb[..mb_len]);
                } else {
                    self.unget(c);
                }
                break;
            }
            // SAFETY: the function's contract: the destination array has room for the field.
            if sp.flags & SUPPRESS == 0 && !unsafe { self.store_char(sp, alloc, &mut buf, &mut dst, c) } {
                if alloc {
                    buf.release();
                }
                return Err(Stop::Encode);
            }
            let more = if width < 0 {
                true
            } else {
                width -= 1;
                width > 0
            };
            if !(more && self.inchar() != EOF) {
                break;
            }
            c = self.c;
        }
        if now == self.read_in {
            if alloc {
                buf.release();
            }
            return Err(Stop::Conv);
        }
        if sp.flags & SUPPRESS == 0 {
            // SAFETY: the function's contract: the destination array has room for the field and its terminator.
            unsafe { self.store_nul(sp, alloc, &mut buf, &mut dst) };
            if alloc {
                // SAFETY: `strptr` was set by `string_target` for this allocating conversion.
                unsafe { self.finish_alloc(&mut buf) }?;
            }
            self.done += 1;
        }
        Ok(())
    }

    /// Integer conversions: `base` 0 means "decide from the prefix" (%i).
    /// # Safety
    /// The conversion's pointer argument points to an integer of the size its length modifier names.
    unsafe fn number(&mut self, sp: &mut Spec, base0: u32) -> Result<(), Stop> {
        let mut base = base0;
        let mut c = self.inchar();
        if c == EOF {
            return Err(Stop::Input);
        }
        let mut width = sp.width;
        let mut neg = false;
        let mut has_sign = false;
        let mut ndigits = 0usize; // characters that count as digits
        let mut value: u64 = 0;
        let mut overflow = false;
        if c == b'-' as c_int || c == b'+' as c_int {
            neg = c == b'-' as c_int;
            has_sign = true;
            if width > 0 {
                width -= 1;
            }
            c = self.inchar();
        }
        let push = |d: u32, base: u32, value: &mut u64, overflow: &mut bool| {
            match value.checked_mul(u64::from(base)).and_then(|v| v.checked_add(u64::from(d))) {
                Some(v) => *value = v,
                None => *overflow = true,
            }
        };
        if width != 0 && c == b'0' as c_int {
            if width > 0 {
                width -= 1;
            }
            c = self.inchar();
            if width != 0 && lower(c) == b'x' as c_int && (base == 0 || base == 16) {
                base = 16;
                if width > 0 {
                    width -= 1;
                }
                if width == 0 {
                    return Err(Stop::Conv);
                }
                c = self.inchar();
            } else if width != 0
                && lower(c) == b'b' as c_int
                && (base == 2 || (self.mode & MODE_C23_BIN != 0 && base == 0))
            {
                base = 2;
                if width > 0 {
                    width -= 1;
                }
                if width == 0 {
                    return Err(Stop::Conv);
                }
                c = self.inchar();
            } else {
                if base == 0 {
                    base = 8;
                }
                ndigits += 1; // the leading zero stays in the number
            }
        }
        if base == 0 {
            base = 10;
        }
        if base == 10 && sp.flags & GROUP != 0 {
            // digits with thousands separators (kept as ','), then only the correctly grouped prefix counts
            let mut gt = Text::new();
            if ndigits == 1 {
                gt.push(b'0');
            }
            while c != EOF && width != 0 {
                if is_digit(c) {
                    gt.push(c as u8);
                } else if self.at_thousands(&mut c, &mut width, true) {
                    gt.push(b',');
                } else {
                    break;
                }
                if width > 0 {
                    width -= 1;
                }
                c = self.inchar();
            }
            if gt.oom() {
                gt.release();
                return Err(Stop::Nomem);
            }
            let bytes = gt.bytes();
            // glibc quirk kept: with a multibyte separator in narrow input the grouping is not
            // checked (its end-of-number scan stops inside the separator)
            let end = if bytes.first() == Some(&b',') {
                0
            } else if !S::WIDE && self.nu().thousands_sep.len() > 1 {
                bytes.len()
            } else {
                rusty_libc_core::locale::correctly_grouped_prefix(bytes, self.nu().grouping)
            };
            ndigits = 0;
            value = 0;
            overflow = false;
            for &b in &bytes[..end] {
                if b != b',' {
                    push(u32::from(b - b'0'), 10, &mut value, &mut overflow);
                    ndigits += 1;
                }
            }
            gt.release();
        } else if sp.flags & I18N != 0 && base == 10 {
            // %Id: the locale's own digits count as well as 0-9
            while c != EOF && width != 0 {
                let dv = if is_digit(c) { Some((c - b'0' as c_int) as u32) } else { self.at_indigit(&mut c, &mut width) };
                let Some(dv) = dv else { break };
                push(dv, 10, &mut value, &mut overflow);
                ndigits += 1;
                if width > 0 {
                    width -= 1;
                }
                c = self.inchar();
            }
        } else {
            while c != EOF && width != 0 {
                if base == 16 {
                    if !is_xdigit(c) {
                        break;
                    }
                } else if !is_digit(c) || (c - b'0' as c_int) as u32 >= base {
                    break;
                }
                push(digit_value(c), base, &mut value, &mut overflow);
                ndigits += 1;
                if width > 0 {
                    width -= 1;
                }
                c = self.inchar();
            }
        }
        if ndigits == 0 {
            // no number; a pointer may also be spelled "(nil)"
            let _ = has_sign;
            if !has_sign
                && sp.flags & READ_POINTER != 0
                && !(0..5).contains(&width)
                && c == b'(' as c_int
                && lower(self.inchar()) == b'n' as c_int
                && lower(self.inchar()) == b'i' as c_int
                && lower(self.inchar()) == b'l' as c_int
                && self.inchar() == b')' as c_int
            {
                value = 0;
            } else {
                // glibc pushes back the last character read, which after a failed "(nil)"
                // look-ahead is the one that failed (possibly EOF: then "(" stays consumed)
                let last = self.c;
                self.unget(last);
                return Err(Stop::Conv);
            }
        } else {
            self.unget(c);
        }
        // strtol / strtoul semantics: saturate; unsigned conversions wrap a minus sign
        let signed = sp.flags & NUMBER_SIGNED != 0;
        let num: u64 = if signed {
            if neg {
                if overflow || value > (1u64 << 63) { i64::MIN as u64 } else { (value as i64).wrapping_neg() as u64 }
            } else if overflow || value > i64::MAX as u64 {
                i64::MAX as u64
            } else {
                value
            }
        } else if overflow {
            u64::MAX
        } else if neg {
            value.wrapping_neg()
        } else {
            value
        };
        if sp.flags & SUPPRESS == 0 {
            let p = self.arg(sp);
            // The function's contract: the argument points to an integer of the size the length modifier names; each
            // branch stores that one.
            if sp.flags & LONG != 0 {
                // SAFETY: see above.
                unsafe { (p as *mut u64).write_unaligned(num) };
            } else if sp.flags & SHORT != 0 {
                // SAFETY: see above.
                unsafe { (p as *mut u16).write_unaligned(num as u16) };
            } else if sp.flags & CHAR == 0 {
                // SAFETY: see above.
                unsafe { (p as *mut u32).write_unaligned(num as u32) };
            } else {
                // SAFETY: see above.
                unsafe { (p as *mut u8).write_unaligned(num as u8) };
            }
            self.done += 1;
        }
        Ok(())
    }

    /// Floating point conversions: collect the longest text glibc accepts, then convert it exactly.
    ///
    /// # Safety
    /// The conversion's pointer argument points to the floating type its length modifier names.
    unsafe fn float(&mut self, sp: &mut Spec) -> Result<(), Stop> {
        let mut text = Text::new();
        let r = self.float_collect(sp, &mut text);
        let r = match r {
            // SAFETY: the function's contract.
            Ok(()) => unsafe { self.float_store(sp, &text) },
            Err(e) => Err(e),
        };
        text.release();
        r
    }

    fn float_collect(&mut self, sp: &mut Spec, text: &mut Text) -> Result<(), Stop> {
        let mut c = self.inchar();
        let mut width = sp.width;
        if width > 0 {
            width -= 1;
        }
        if c == EOF {
            return Err(Stop::Input);
        }
        let (mut got_digit, mut got_dot, mut got_e, mut got_sign) = (false, false, false, false);
        if c == b'-' as c_int || c == b'+' as c_int {
            got_sign = true;
            text.push(c as u8);
            if width == 0 || self.inchar() == EOF {
                return Err(Stop::Conv);
            }
            c = self.c;
            if width > 0 {
                width -= 1;
            }
        }
        // "nan", "nan(...)", "inf", "infinity"
        if lower(c) == b'n' as c_int {
            text.push(c as u8);
            for want in *b"an" {
                if width == 0 || self.inchar() == EOF || lower(self.c) != c_int::from(want) {
                    return Err(Stop::Conv);
                }
                if width > 0 {
                    width -= 1;
                }
                text.push(self.c as u8);
            }
            if width != 0 && self.inchar() != EOF {
                if self.c == b'(' as c_int {
                    if width > 0 {
                        width -= 1;
                    }
                    text.push(b'(');
                    loop {
                        if width == 0 || self.inchar() == EOF {
                            return Err(Stop::Conv);
                        }
                        let c = self.c;
                        let ok = (b'0' as c_int..=b'9' as c_int).contains(&c)
                            || (b'A' as c_int..=b'Z' as c_int).contains(&c)
                            || (b'a' as c_int..=b'z' as c_int).contains(&c)
                            || c == b'_' as c_int
                            || c == b')' as c_int;
                        if !ok {
                            return Err(Stop::Conv);
                        }
                        if width > 0 {
                            width -= 1;
                        }
                        text.push(c as u8);
                        if c == b')' as c_int {
                            break;
                        }
                    }
                } else {
                    let c = self.c;
                    self.unget(c);
                }
            }
            return Ok(());
        }
        if lower(c) == b'i' as c_int {
            text.push(c as u8);
            for want in *b"nf" {
                if width == 0 || self.inchar() == EOF || lower(self.c) != c_int::from(want) {
                    return Err(Stop::Conv);
                }
                if width > 0 {
                    width -= 1;
                }
                text.push(self.c as u8);
            }
            if width != 0 && self.inchar() != EOF {
                if lower(self.c) == b'i' as c_int {
                    if width > 0 {
                        width -= 1;
                    }
                    text.push(self.c as u8);
                    for want in *b"nity" {
                        if width == 0 || self.inchar() == EOF || lower(self.c) != c_int::from(want) {
                            return Err(Stop::Conv);
                        }
                        if width > 0 {
                            width -= 1;
                        }
                        text.push(self.c as u8);
                    }
                } else {
                    let c = self.c;
                    self.unget(c);
                }
            }
            return Ok(());
        }
        let mut exp_char = b'e' as c_int;
        if width != 0 && c == b'0' as c_int {
            text.push(c as u8);
            c = self.inchar();
            if width > 0 {
                width -= 1;
            }
            if lower(c) == b'x' as c_int {
                if width == 0 {
                    return Err(Stop::Conv);
                }
                text.push(c as u8);
                sp.flags |= HEXA_FLOAT;
                exp_char = b'p' as c_int;
                c = self.inchar();
                if width > 0 {
                    width -= 1;
                }
            } else {
                got_digit = true;
            }
        }
        let mut last = *text.bytes().last().unwrap_or(&0);
        loop {
            if text.oom() {
                return Err(Stop::Nomem);
            }
            if is_digit(c) || (!got_e && sp.flags & HEXA_FLOAT != 0 && is_xdigit(c)) {
                text.push(c as u8);
                last = c as u8;
                got_digit = true;
            } else if got_e && c_int::from(last) == exp_char && (c == b'-' as c_int || c == b'+' as c_int) {
                text.push(c as u8);
                last = c as u8;
            } else if got_digit && !got_e && lower(c) == exp_char {
                text.push(exp_char as u8);
                last = exp_char as u8;
                got_e = true;
                got_dot = true;
                got_digit = false;
            } else if !got_dot && self.at_decimal(&mut c, &mut width) {
                text.push(b'.');
                last = b'.';
                got_dot = true;
            } else if !got_dot && sp.flags & GROUP != 0 && sp.flags & HEXA_FLOAT == 0 && self.at_thousands(&mut c, &mut width, false) {
                text.push(b',');
                last = b',';
            } else {
                self.unget(c);
                break;
            }
            if width == 0 || self.inchar() == EOF {
                break;
            }
            c = self.c;
            if width > 0 {
                width -= 1;
            }
        }
        if text.oom() {
            return Err(Stop::Nomem);
        }
        if sp.flags & GROUP != 0 && text.bytes().contains(&b',') {
            // keep the correctly grouped part of the integer digits, drop the separators
            let t = text.bytes();
            let sign = usize::from(matches!(t.first(), Some(b'-' | b'+')));
            let int_end = t.iter().position(|&b| b == b'.' || b == b'e' || b == b'E').unwrap_or(t.len());
            let end = sign + rusty_libc_core::locale::correctly_grouped_prefix(&t[sign..int_end], self.nu().grouping);
            let keep_rest = end == int_end;
            let mut out = Text::new();
            for (i, &b) in t.iter().enumerate() {
                if (i < end || (keep_rest && i >= int_end)) && b != b',' {
                    out.push(b);
                }
            }
            text.release();
            *text = out;
        }
        let n = text.len;
        if n == usize::from(got_sign) || (sp.flags & HEXA_FLOAT != 0 && n == 2 + usize::from(got_sign)) || !got_digit {
            return Err(Stop::Conv);
        }
        Ok(())
    }

    /// # Safety
    /// As `float`.
    unsafe fn float_store(&mut self, sp: &Spec, text: &Text) -> Result<(), Stop> {
        let target = if sp.flags & LONGDBL != 0 {
            Target::X87
        } else if sp.flags & (LONG | LONGDBL) != 0 {
            Target::F64
        } else {
            Target::F32
        };
        let Some(v) = fp::convert(text.bytes(), target).map(|c| c.bits) else {
            return Err(Stop::Conv);
        };
        if sp.flags & SUPPRESS == 0 {
            let p = self.arg(sp);
            // The function's contract: the argument points to a float, double or long double as the length modifier names;
            // each arm stores that one (an x87 long double: 8 bytes of mantissa, then the 2-byte sign and exponent).
            match v {
                // SAFETY: see above.
                Bits::F32(b) => unsafe { (p as *mut u32).write_unaligned(b) },
                // SAFETY: see above.
                Bits::F64(b) => unsafe { (p as *mut u64).write_unaligned(b) },
                Bits::X87(m, se) => {
                    // SAFETY: see above.
                    unsafe { (p as *mut u64).write_unaligned(m) };
                    // SAFETY: see above.
                    unsafe { (p.cast::<u8>().wrapping_add(8) as *mut u16).write_unaligned(se) };
                }
                // SAFETY: see above.
                Bits::F128(b) => unsafe { (p as *mut u128).write_unaligned(b) },
            }
            self.done += 1;
        }
        Ok(())
    }
}

/// A decimal number at `*f`, which moves past its digits.
///
/// # Safety
/// `*f` points into a NUL-terminated format.
unsafe fn read_int<F: FmtChar>(f: &mut *const F) -> i64 {
    let mut v: i64 = 0;
    while fmt_at!(*f, 0).is_ascii_digit() {
        v = (v * 10 + i64::from(fmt_at!(*f, 0) - b'0')).min(i64::from(i32::MAX));
        *f = f.wrapping_add(1);
    }
    v
}

/// Run the scanf engine over `src` with the format `fmt` (NUL-terminated).
///
/// # Safety
/// `fmt` must be NUL-terminated; the pointer arguments must match the format.
pub unsafe fn scan<S: Src, A: PtrArgs, F: FmtChar>(src: &mut S, fmt: *const F, args: &mut A, mode: u32) -> c_int {
    let mut e = Engine { src, args, mode, nu: None, read_in: 0, c: 0, inchar_errno: 0, done: 0, strptr: null_mut(), slots: SlotList { p: null_mut(), len: 0, cap: 0 }, _f: core::marker::PhantomData };
    let mut skip_space = false;
    // SAFETY: the function's contract.
    match unsafe { e.body(fmt, &mut skip_space) } {
        Ok(()) => {
            if skip_space {
                loop {
                    e.inchar();
                    if !e.sp(e.c) {
                        break;
                    }
                }
                let c = e.c;
                e.unget(c);
            }
        }
        Err(Stop::Conv) | Err(Stop::Encode) => {}
        Err(Stop::Input) => {
            if e.done == 0 {
                e.done = EOF;
            }
        }
        Err(Stop::Nomem) => {
            e.done = EOF;
            errno::set(12);
        }
    }
    if e.done == EOF {
        for &slot in e.slots.as_slice() {
            // SAFETY: a `char **` argument of a `%m` conversion (the function's contract), into which this call stored a
            // block it allocated: freed and cleared again, as glibc does when the call fails.
            let p = unsafe { *slot };
            // SAFETY: as above.
            unsafe { crate::file::free(p) };
            // SAFETY: as above.
            unsafe { *slot = null_mut() };
        }
    } else if !e.strptr.is_null() {
        // a conversion that failed midway: free its partial string
        // SAFETY: the `%m` argument of the conversion that failed (the function's contract).
        unsafe { *e.strptr = null_mut() };
    }
    e.slots.free();
    e.done
}
