//! fnmatch.h: `fnmatch` with FNM_PATHNAME, FNM_NOESCAPE, FNM_PERIOD, FNM_LEADING_DIR, FNM_CASEFOLD
//! and FNM_EXTMATCH, in every locale.
//!
//! The matcher is a backtracking matcher that follows the structure of glibc's (the parts of its behaviour that are
//! visible and easy to get wrong are kept on purpose). It exists twice from one source, as in glibc: over bytes
//! (`T = u8`) and over wide characters (`T = u32`).
//! * `fnmatch` runs the wide version first when `MB_CUR_MAX != 1` and both strings convert to wide
//!   characters (so `?` and `[...]` match one multibyte character), and **also runs the byte version
//!   when the wide one says "no match"**, exactly as glibc 2.43 does (its `fnmatch` falls through);
//!   when a string does not convert (invalid multibyte text) only the byte version runs. In a
//!   single-byte locale, or the C locale, only the byte version runs, with no conversion and no allocation.
//! * a `*` records where to resume instead of recursing for the common case (the `ends` argument),
//! * `[` with no closing `]` is a literal `[`, but a range cut short by the end of the pattern
//!   (`[a-`) is "no match",
//! * `[!...]` negates, and so does `[^...]` unless `POSIXLY_CORRECT` is set (looked up once, at the
//!   first bracket, and remembered like glibc does),
//! * class names in `[:name:]` may only contain the letters a..y (glibc's check), an unknown class
//!   name means "no match"; bytes are classified with the locale's ctype table, wide characters with
//!   `iswctype`,
//! * ranges `[a-z]` compare collation sequence values (the locale's `LC_COLLATE` tables; by value when the
//!   locale has no collation rules), `[=c=]` matches characters whose first-pass weights equal c's (the
//!   character itself without collation rules), `[.c.]` is a collating symbol (single characters only
//!   without collation rules, the locale's named elements with them),
//! * under FNM_PERIOD a leading period (and one after a `/` with FNM_PATHNAME) is matched only by a
//!   literal period; a trailing backslash never matches unless FNM_NOESCAPE.
//! * FNM_EXTMATCH supports `?(a|b)`, `*(a|b)`, `+(a|b)`, `@(a|b)`, `!(a|b)`, nested.
//!
//! Positions are indices into the pattern and the string, which are slices that end with their NUL (glibc walks
//! pointers to the same characters); the matcher's hot reads go through [`zs`] (a NUL-terminated slice and a position
//! that never passes its NUL), which reads without bounds checks. Unsafe code (BRIEF-UNSAFE U2; fnmatch's speed blocks
//! allowed by Adam 2026-10-15): converting the C strings at the entry, the two unchecked reads of `zs`, the
//! multibyte-to-wide conversion, the locale's first-pass weights (which read a C string), the vector `memchr`, and the
//! locale flags word.
//!
//! Written from glibc 2.43's posix/fnmatch.c and fnmatch_loop.c (LGPL, read as reference).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem::CVec;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicI32, Ordering};
use rusty_libc_locale::coll::{Collation, NO_SEQ};

pub const FNM_PATHNAME: c_int = 1;
/// glibc's other name for FNM_PATHNAME.
pub const FNM_FILE_NAME: c_int = 1;
pub const FNM_NOESCAPE: c_int = 2;
pub const FNM_PERIOD: c_int = 4;
pub const FNM_LEADING_DIR: c_int = 8;
pub const FNM_CASEFOLD: c_int = 16;
pub const FNM_EXTMATCH: c_int = 32;
pub const FNM_NOMATCH: c_int = 1;

const CHAR_CLASS_MAX_LENGTH: usize = 256;

/// 0 = not looked up yet, 1 = POSIXLY_CORRECT set, -1 = not set (glibc caches it the same way; the value is idempotent,
/// so a race between two first lookups is harmless).
static POSIXLY_CORRECT: AtomicI32 = AtomicI32::new(0);

fn posixly() -> i32 {
    let v = POSIXLY_CORRECT.load(Ordering::Relaxed);
    if v != 0 {
        return v;
    }
    let v = if crate::cmem::getenv(b"POSIXLY_CORRECT").is_none() { -1 } else { 1 };
    POSIXLY_CORRECT.store(v, Ordering::Relaxed);
    v
}

/// A character of the matcher: a byte or a wide character.
trait Ch: Copy + PartialEq + 'static {
    const WIDE: bool;
    fn v(self) -> u32;
    fn of(v: u32) -> Self;
    /// The slice as wide characters (only for `u32`).
    fn wide(s: &[Self]) -> Option<&[u32]>;
    /// The slice as bytes (only for `u8`).
    fn bytes(s: &[Self]) -> Option<&[u8]>;
}

impl Ch for u8 {
    const WIDE: bool = false;
    #[inline(always)]
    fn v(self) -> u32 {
        self as u32
    }
    #[inline(always)]
    fn of(v: u32) -> u8 {
        v as u8
    }
    fn wide(_: &[u8]) -> Option<&[u32]> {
        None
    }
    fn bytes(s: &[u8]) -> Option<&[u8]> {
        Some(s)
    }
}

impl Ch for u32 {
    const WIDE: bool = true;
    #[inline(always)]
    fn v(self) -> u32 {
        self
    }
    #[inline(always)]
    fn of(v: u32) -> u32 {
        v
    }
    fn wide(s: &[u32]) -> Option<&[u32]> {
        Some(s)
    }
    fn bytes(_: &[u32]) -> Option<&[u8]> {
        None
    }
}

/// An ASCII character as a `T`.
#[inline(always)]
fn k<T: Ch>(b: u8) -> T {
    T::of(b as u32)
}

/// The character at `i`, or NUL past the end (the slices end with their NUL; glibc never reads past it).
#[inline(always)]
fn at<T: Ch>(s: &[T], i: usize) -> T {
    match s.get(i) {
        Some(&c) => c,
        None => k(0),
    }
}

/// NUL-terminated slices and positions in them, read without bounds checks (the only unsafe reads of the matcher).
///
/// glibc's matcher walks pointers and never looks past a string's NUL; the safe port read through `at`, which checks
/// every index and was 1.1-1.2x pre-U2's time in the matcher (FIXLIST #85). Here the check is replaced by an invariant
/// kept by construction: a [`Z`] is a slice whose last element is NUL (checked once, when it is made), and a [`Cur`]
/// is a position in a `Z` that never passes that NUL (it moves forward only over a character that is not NUL). So every
/// read is in bounds, and reading at the NUL gives NUL, which is what `at` gives past the end: the matcher's results do
/// not change. The fields are private to this module, so no other code can break the invariant.
mod zs {
    use super::Ch;

    /// A slice that ends with a NUL (`T` 0), so it is not empty.
    #[derive(Clone, Copy)]
    pub(super) struct Z<'a, T: Ch>(&'a [T]);

    impl<'a, T: Ch> Z<'a, T> {
        /// `s` when it ends with a NUL.
        #[inline(always)]
        pub(super) fn new(s: &'a [T]) -> Option<Z<'a, T>> {
            if s.last()?.v() == 0 { Some(Z(s)) } else { None }
        }
        #[inline(always)]
        pub(super) fn slice(self) -> &'a [T] {
            self.0
        }
        /// The byte view (the same slice, so it ends with the same NUL); `None` for wide characters.
        #[inline(always)]
        pub(super) fn bytes(self) -> Option<Z<'a, u8>> {
            T::bytes(self.0).map(Z)
        }
        /// The character at `i`, NUL from the terminating NUL on (as `at`).
        #[inline(always)]
        pub(super) fn at(self, i: usize) -> T {
            let j = i.min(self.0.len() - 1);
            // SAFETY: the slice is not empty (it ends with a NUL), so `len - 1` does not wrap and `j < len`.
            unsafe { *self.0.get_unchecked(j) }
        }
        /// The position `i` (the NUL's position for any `i` past it: the same characters are read there).
        #[inline(always)]
        pub(super) fn cur(self, i: usize) -> Cur<'a, T> {
            Cur { z: self.0, i: i.min(self.0.len() - 1) }
        }
    }

    /// A position in a [`Z`]: `i < z.len()`, so `z[i]` is readable; the last element of `z` is NUL.
    #[derive(Clone, Copy)]
    pub(super) struct Cur<'a, T: Ch> {
        z: &'a [T],
        i: usize,
    }

    impl<'a, T: Ch> Cur<'a, T> {
        /// The character here.
        #[inline(always)]
        pub(super) fn get(self) -> T {
            // SAFETY: `i < z.len()` (the invariant: `Z::cur` clamps, `take` and `next` move only off a character that is
            // not the final NUL, `to` clamps).
            unsafe { *self.z.get_unchecked(self.i) }
        }
        /// The next position; the same one at the NUL (the matcher reads NUL there either way, as `at` reads NUL past
        /// the end). Right after a `get` that returned a character that is not NUL the compiler drops the test, and the
        /// step is a plain increment.
        #[inline(always)]
        pub(super) fn next(self) -> Cur<'a, T> {
            // (z[i] is not NUL, so i is not the last index: i + 1 < len)
            if self.get().v() != 0 { Cur { z: self.z, i: self.i + 1 } } else { self }
        }
        /// The character here and the next position, when the character is not NUL (`None` at the NUL). The step is a
        /// plain increment, with no test on the path that uses it.
        #[inline(always)]
        pub(super) fn take(self) -> Option<(T, Cur<'a, T>)> {
            let c = self.get();
            // (z[i] is not NUL, so i is not the last index: i + 1 < len)
            if c.v() != 0 { Some((c, Cur { z: self.z, i: self.i + 1 })) } else { None }
        }
        /// The character after this one (NUL at and after the NUL, as `at(p + 1)`).
        #[inline(always)]
        pub(super) fn peek(self) -> T {
            self.at(1)
        }
        /// The character `k` positions on (NUL at and after the NUL, as `at(p + k)`).
        #[inline(always)]
        pub(super) fn at(self, k: usize) -> T {
            Z(self.z).at(self.i + k)
        }
        /// The position `k` on (clamped to the NUL).
        #[inline(always)]
        pub(super) fn skip(self, k: usize) -> Cur<'a, T> {
            self.to(self.i + k)
        }
        /// The position `i` of the same slice (clamped to the NUL, as `Z::cur`).
        #[inline(always)]
        pub(super) fn to(self, i: usize) -> Cur<'a, T> {
            Z(self.z).cur(i)
        }
        #[inline(always)]
        pub(super) fn pos(self) -> usize {
            self.i
        }
        /// The characters from `k` positions on (empty past the end).
        #[inline(always)]
        pub(super) fn tail(self, k: usize) -> &'a [T] {
            self.z.get(self.i + k..).unwrap_or(&[])
        }
    }
}
use zs::{Cur, Z};

const QM: u32 = b'?' as u32;
const STAR: u32 = b'*' as u32;
const BSL: u32 = b'\\' as u32;
const LBR: u32 = b'[' as u32;
const PLUS: u32 = b'+' as u32;
const AT: u32 = b'@' as u32;
const BANG: u32 = b'!' as u32;
const SLASH: u32 = b'/' as u32;

/// Pattern characters the matcher treats specially: `? * [ \ + @ !` and `/`.
static SPECIAL: [bool; 128] = {
    let mut t = [false; 128];
    let s = b"?*[\\+@!";
    let mut i = 0;
    while i < s.len() {
        t[s[i] as usize] = true;
        i += 1;
    }
    t
};

/// FOLD: lower case under FNM_CASEFOLD (`tolower` for bytes, `towlower` for wide characters).
#[inline]
fn fold<T: Ch>(c: T, flags: c_int) -> T {
    if flags & FNM_CASEFOLD == 0 {
        c
    } else if T::WIDE {
        T::of(rusty_libc_wchar::wctype::to_lower(c.v()))
    } else {
        T::of(rusty_libc_ctype::to_lower(c.v() as i32) as u32)
    }
}

fn no_leading_period(flags: c_int) -> bool {
    flags & (FNM_FILE_NAME | FNM_PERIOD) == (FNM_FILE_NAME | FNM_PERIOD)
}

/// Position to resume matching at after a `*` (glibc's `struct fnmatch_struct`): indices into the pattern and the
/// string of the call that recorded it; `pattern` is `None` until a `*` records one.
struct Ends {
    pattern: Option<usize>,
    string: usize,
    no_leading_period: bool,
}

/// The class named by `name` (the 12 POSIX classes) tested on `c`; `None` for an unknown name.
fn class_test<T: Ch>(name: &[u8], c: T) -> Option<bool> {
    if T::WIDE {
        let desc = rusty_libc_wchar::wctype::class_by_name(name);
        if desc == 0 {
            return None;
        }
        return Some(rusty_libc_wchar::wctype::in_class(c.v(), desc));
    }
    let c = c.v() as i32;
    Some(match name {
        b"alnum" => rusty_libc_ctype::is_alnum(c),
        b"alpha" => rusty_libc_ctype::is_alpha(c),
        b"blank" => rusty_libc_ctype::is_blank(c),
        b"cntrl" => rusty_libc_ctype::is_cntrl(c),
        b"digit" => rusty_libc_ctype::is_digit(c),
        b"graph" => rusty_libc_ctype::is_graph(c),
        b"lower" => rusty_libc_ctype::is_lower(c),
        b"print" => rusty_libc_ctype::is_print(c),
        b"punct" => rusty_libc_ctype::is_punct(c),
        b"space" => rusty_libc_ctype::is_space(c),
        b"upper" => rusty_libc_ctype::is_upper(c),
        b"xdigit" => rusty_libc_ctype::is_xdigit(c),
        _ => return None,
    })
}

/// The class name at the start of `body` (after `[:`): letters a..y up to `:]`, at most seven; its length and the name
/// packed by [`name_key`]. `None` when it is not such a name.
#[allow(clippy::almost_complete_range)] // the half-open `a..z` is glibc's test for class names (as in bracket_members)
#[inline(always)]
fn class_name(body: &[u8]) -> Option<(usize, u64)> {
    let mut key = 0u64;
    let mut i = 0;
    loop {
        let x = at(body, i);
        if x == b':' && at(body, i + 1) == b']' {
            return Some((i, key));
        }
        if !(b'a'..b'z').contains(&x) || i == 7 {
            return None;
        }
        key |= u64::from(x) << (8 * i);
        i += 1;
    }
}

/// A class name of up to eight bytes as one word (byte `i` of the name in byte `i`; the rest zeros).
const fn name_key(name: &[u8]) -> u64 {
    let mut k = 0u64;
    let mut i = 0;
    while i < name.len() {
        k |= (name[i] as u64) << (8 * i);
        i += 1;
    }
    k
}

/// [`class_test`] for a byte and a name packed by [`name_key`] (the names hold no NUL, so equal words are equal names):
/// one word compare per name instead of a slice compare, and no call.
#[inline(always)]
fn class_test_key(key: u64, c: u8) -> Option<bool> {
    const ALNUM: u64 = name_key(b"alnum");
    const ALPHA: u64 = name_key(b"alpha");
    const BLANK: u64 = name_key(b"blank");
    const CNTRL: u64 = name_key(b"cntrl");
    const DIGIT: u64 = name_key(b"digit");
    const GRAPH: u64 = name_key(b"graph");
    const LOWER: u64 = name_key(b"lower");
    const PRINT: u64 = name_key(b"print");
    const PUNCT: u64 = name_key(b"punct");
    const SPACE: u64 = name_key(b"space");
    const UPPER: u64 = name_key(b"upper");
    const XDIGIT: u64 = name_key(b"xdigit");
    let c = i32::from(c);
    Some(match key {
        ALNUM => rusty_libc_ctype::is_alnum(c),
        ALPHA => rusty_libc_ctype::is_alpha(c),
        BLANK => rusty_libc_ctype::is_blank(c),
        CNTRL => rusty_libc_ctype::is_cntrl(c),
        DIGIT => rusty_libc_ctype::is_digit(c),
        GRAPH => rusty_libc_ctype::is_graph(c),
        LOWER => rusty_libc_ctype::is_lower(c),
        PRINT => rusty_libc_ctype::is_print(c),
        PUNCT => rusty_libc_ctype::is_punct(c),
        SPACE => rusty_libc_ctype::is_space(c),
        UPPER => rusty_libc_ctype::is_upper(c),
        XDIGIT => rusty_libc_ctype::is_xdigit(c),
        _ => return None,
    })
}

/// The collation sequence value of `c` (glibc reads `collseq[c]` / `__collseq_table_lookup`; a locale without
/// collation rules orders by value). `NO_SEQ` when the wide table does not know the character.
fn seq_of<T: Ch>(coll: &Collation, c: T) -> u32 {
    if T::WIDE {
        // no collation rules (C.UTF-8): glibc's identity table, which covers only the first 256 characters
        if coll.nrules() == 0 { if c.v() < 256 { c.v() } else { NO_SEQ } } else { coll.seq_wc(c.v()) }
    } else {
        coll.seq_mb(c.v() as u8)
    }
}

/// The collation data of the locale in force, read on first use.
struct Loc {
    coll: Option<Collation>,
}

impl Loc {
    fn get(&mut self) -> &Collation {
        self.coll.get_or_insert_with(Collation::current)
    }
    fn nrules(&mut self) -> u32 {
        self.get().nrules()
    }
}

/// How a bracket expression ended.
enum Bracket {
    /// A member matched; `p` is left inside the list.
    Matched,
    /// Reached the closing `]` without a match (`p` is past it).
    NotMatched,
    /// No closing `]`: the `[` is an ordinary character.
    Literal,
    /// Ill-formed: the whole match fails.
    Fail,
}

/// The first-pass weights of the collating element at the start of `s` (a NUL-terminated slice): (rule, weights).
fn primary<T: Ch>(s: &[T]) -> Option<(u8, &'static [u8], &'static [u32])> {
    debug_assert!(s.last().is_some_and(|c| c.v() == 0));
    if let Some(w) = T::wide(s) {
        // SAFETY: `w` ends with a NUL, so it is a wide C string.
        let (rule, wt, _) = unsafe { rusty_libc_locale::primary_wc(w.as_ptr()) }?;
        Some((rule, &[], wt))
    } else {
        let b = T::bytes(s)?;
        // SAFETY: `b` ends with a NUL, so it is a C string.
        let (rule, wt, _) = unsafe { rusty_libc_locale::primary_mb(b.as_ptr()) }?;
        Some((rule, wt, &[]))
    }
}

/// `[=c=]` against the element at the start of `n` (the string from the current position, with its NUL), in a locale
/// with collation rules (glibc's FINDIDX comparison of the first-pass weights).
fn equiv_matches<T: Ch>(s: T, n: &[T]) -> bool {
    let pat = [s, k(0)];
    let Some(a) = primary(&pat) else { return false };
    let Some(b) = primary(n) else { return false };
    a == b
}

/// The text of a `[.name.]` whose `[.` the caller has consumed up to (`pat[*p]` is the `.` after `[`): advances `*p`
/// past the `.]` and returns the start of the name and its length, or `None` when the pattern ends first.
fn read_symbol<T: Ch>(pat: &[T], p: &mut usize) -> Option<(usize, usize)> {
    let startp = *p;
    let mut c1 = 0usize;
    loop {
        *p += 1;
        let c = at(pat, *p);
        if c.v() == b'.' as u32 && at(pat, *p + 1).v() == b']' as u32 {
            *p += 2;
            break;
        }
        if c.v() == 0 {
            return None;
        }
        c1 += 1;
    }
    Some((startp + 1, c1))
}

/// A collating symbol in a locale with collation rules: the table entry for the element `name`, as
/// (sequence value truncated the way glibc stores it, element length).
fn find_symbol<T: Ch>(coll: &Collation, name: &[T]) -> Option<(u32, usize)> {
    if let Some(w) = T::wide(name) {
        coll.symbol_by_wide(w).map(|(seq, e)| (seq, e.len()))
    } else {
        coll.symbol_by_bytes(T::bytes(name)?).map(|(seq, e)| (seq, e.len()))
    }
}

/// glibc stores a collation sequence value it reads from a table in a variable of the character type: a (signed)
/// `char` for the lower bound of a range in the byte version, an `unsigned char` for the upper bound, a full word in
/// the wide version.
#[inline]
fn as_cold<T: Ch>(seq: u32) -> u32 {
    if T::WIDE { seq } else { seq as u8 as i8 as i32 as u32 }
}

#[inline]
fn as_cend<T: Ch>(seq: u32) -> u32 {
    if T::WIDE { seq } else { seq as u8 as u32 }
}

/// True when the locale's collation is plain byte order (the built-in C locale or none): ranges compare byte values.
#[inline]
fn byte_order_collation() -> bool {
    rusty_libc_core::locale::current(rusty_libc_core::locale::LC_COLLATE).is_none_or(|d| d.flags() & rusty_libc_core::locale::F_BUILTIN_C != 0)
}

/// Byte-order fast path of `bracket_members` for the common lists: plain characters, `a-z` ranges and `[:class:]`, from
/// position `i` of `pat` (after the `[` and its `!`): the outcome and the position after it (plain arguments and results,
/// which stay in registers). `None` for anything else (escapes, `[. .]`, `[= =]`, unterminated lists): the general code
/// decides.
#[allow(clippy::almost_complete_range)] // the half-open `a..z` is glibc's test for class names (as in bracket_members)
#[inline]
fn bracket_fast(pat: Z<u8>, i: usize, fnc: u8, nv: u8, flags: c_int) -> Option<(Bracket, usize)> {
    let r = bracket_fast_in(pat.cur(i), fnc, nv, flags);
    r.map(|(b, q)| (b, q.pos()))
}

/// [`bracket_fast`] on a position.
#[allow(clippy::almost_complete_range)]
#[inline(always)]
fn bracket_fast_in(mut q: Cur<u8>, fnc: u8, nv: u8, flags: c_int) -> Option<(Bracket, Cur<u8>)> {
    let noescape = flags & FNM_NOESCAPE != 0;
    let mut first = true;
    loop {
        let (c, r) = q.take()?;
        if c == b'\\' && !noescape {
            return None;
        }
        if c == b']' && !first {
            return Some((Bracket::NotMatched, r));
        }
        first = false;
        let t = r.take();
        let nx = t.map_or(0, |x| x.0);
        if c == b'[' {
            if nx == b'.' || nx == b'=' {
                return None;
            }
            if let Some((b':', r2)) = t {
                // the name is read in place: letters a..y up to `:]`, at most seven, packed into a word for the look-up
                let body = r2.tail(0);
                // (nine bytes, the longest name and its `:]`, are there in nearly every pattern: read without checks)
                let (i, key) = match body.first_chunk::<9>() {
                    Some(b) => class_name(b)?,
                    None => class_name(body)?,
                };
                q = r2.skip(i + 2);
                match class_test_key(key, nv) {
                    None => return None,
                    Some(true) => return Some((Bracket::Matched, q)),
                    Some(false) => continue,
                }
            }
        }
        let lo = fold(c, flags);
        if let Some((b'-', r2)) = t
            && let Some((h, r3)) = r2.take()
            && h != b']'
        {
            if (h == b'\\' && !noescape) || (h == b'[' && r3.get() == b'.') {
                return None;
            }
            let hi = fold(h, flags);
            q = r3;
            if lo <= fnc && fnc <= hi {
                return Some((Bracket::Matched, q));
            }
            continue;
        }
        q = r;
        if lo == fnc {
            return Some((Bracket::Matched, q));
        }
    }
}

/// The members of a bracket expression, `*p` after the optional `!`/`^`; `fnc` is the (folded) character
/// to match and `s[n]` the raw one.
/// (Never inlined: the matcher's main loop stays small and keeps its registers; brackets that need this are rare.)
#[allow(unused_assignments)]
#[inline(never)]
fn bracket_members<T: Ch>(pat: &[T], p: &mut usize, s: &[T], n: usize, fnc: T, flags: c_int, adv: &mut usize) -> Bracket {
    let noescape = flags & FNM_NOESCAPE != 0;
    // the collation tables are read only when a range, an equivalence class or a collating symbol needs them
    let mut loc = Loc { coll: None };
    let nv = at(s, n);
    let mut c = at(pat, *p);
    *p += 1;
    loop {
        let mut normal = false; // jump to the "ordinary character or range start" code
        let mut done_element = false; // the element was handled; c holds the next character
        let mut cold: T = k(0);
        let mut cold_seq: u32 = 0; // the value of `cold` when it is a sequence value
        let mut is_seqval = false;
        if !noescape && c.v() == BSL {
            if at(pat, *p).v() == 0 {
                return Bracket::Fail;
            }
            c = fold(at(pat, *p), flags);
            *p += 1;
            normal = true;
        } else if c.v() == LBR && at(pat, *p).v() == b':' as u32 {
            let startp = *p;
            let mut name = [0u8; CHAR_CLASS_MAX_LENGTH + 1];
            let mut c1 = 0usize;
            let mut ok = true;
            loop {
                if c1 == CHAR_CLASS_MAX_LENGTH {
                    return Bracket::Fail;
                }
                *p += 1;
                c = at(pat, *p);
                if c.v() == b':' as u32 && at(pat, *p + 1).v() == b']' as u32 {
                    *p += 2;
                    break;
                }
                #[allow(clippy::almost_complete_range)]
                if !((b'a' as u32)..(b'z' as u32)).contains(&c.v()) {
                    *p = startp;
                    c = k(b'[');
                    ok = false;
                    break;
                }
                name[c1] = c.v() as u8;
                c1 += 1;
            }
            if !ok {
                normal = true;
            } else {
                match class_test(&name[..c1], nv) {
                    None => return Bracket::Fail,
                    Some(true) => return Bracket::Matched,
                    Some(false) => {}
                }
                c = at(pat, *p);
                *p += 1;
                done_element = true;
            }
        } else if c.v() == LBR && at(pat, *p).v() == b'=' as u32 {
            let startp = *p;
            *p += 1;
            c = at(pat, *p);
            let mut literal = false;
            let mut sym: T = k(0);
            if c.v() == 0 {
                literal = true;
            } else {
                sym = c;
                *p += 1;
                c = at(pat, *p);
                if c.v() != b'=' as u32 || at(pat, *p + 1).v() != b']' as u32 {
                    literal = true;
                }
            }
            if literal {
                *p = startp;
                c = k(b'[');
                normal = true;
            } else {
                *p += 2;
                if loc.nrules() == 0 {
                    if nv == sym {
                        return Bracket::Matched;
                    }
                } else if equiv_matches(sym, &s[n..]) {
                    return Bracket::Matched;
                }
                c = at(pat, *p);
                *p += 1;
                done_element = true;
            }
        } else if c.v() == 0 {
            return Bracket::Literal;
        } else if c.v() == LBR && at(pat, *p).v() == b'.' as u32 {
            // collating symbol
            let Some((name, c1)) = read_symbol(pat, p) else { return Bracket::Fail };
            // a symbol before `-` is the start of a range: then its collation sequence is what counts
            let is_range = at(pat, *p).v() == b'-' as u32 && at(pat, *p + 1).v() != 0;
            if loc.nrules() == 0 {
                // no names in the collation data: only the character itself
                if c1 != 1 {
                    return Bracket::Fail;
                }
                if !is_range && nv == at(pat, name) {
                    return Bracket::Matched;
                }
                cold = at(pat, name);
                c = at(pat, *p);
                *p += 1;
            } else if let Some((seq, elen)) = find_symbol::<T>(loc.get(), &pat[name..name + c1]) {
                if !is_range {
                    let mut same = true;
                    for i in 0..elen {
                        // the element may run to the end of the string; the strings end in a NUL
                        if at(s, n + i).v() != at(pat, name + i).v() {
                            same = false;
                            break;
                        }
                    }
                    if same {
                        *adv = elen - 1;
                        return Bracket::Matched;
                    }
                }
                is_seqval = true;
                cold_seq = as_cold::<T>(seq);
                c = at(pat, *p);
                *p += 1;
            } else if c1 == 1 {
                // not a defined element: match it as a single character
                if !is_range && nv == at(pat, name) {
                    return Bracket::Matched;
                }
                cold = at(pat, name);
                c = at(pat, *p);
                *p += 1;
            } else {
                return Bracket::Fail;
            }
        } else {
            c = fold(c, flags);
            normal = true;
        }
        if normal {
            let is_range = at(pat, *p).v() == b'-' as u32 && at(pat, *p + 1).v() != 0 && at(pat, *p + 1).v() != b']' as u32;
            if !is_range && c == fnc {
                return Bracket::Matched;
            }
            is_seqval = false;
            cold = c;
            c = at(pat, *p);
            *p += 1;
        }
        if !done_element && c.v() == b'-' as u32 && at(pat, *p).v() != b']' as u32 {
            let mut cend = at(pat, *p);
            *p += 1;
            let fcollseq = seq_of(loc.get(), fnc);
            // (a wide character the table does not know cannot be in a range: glibc skips the rest of the range
            // handling, leaving the upper bound consumed)
            'range: {
                if T::WIDE && fcollseq == NO_SEQ {
                    break 'range;
                }
                let lcollseq = if is_seqval { cold_seq } else { seq_of(loc.get(), cold) };
                let mut cend_seq = 0u32;
                is_seqval = false;
                if cend.v() == LBR && at(pat, *p).v() == b'.' as u32 {
                    let Some((name, c1)) = read_symbol(pat, p) else { return Bracket::Fail };
                    if loc.nrules() == 0 {
                        if c1 != 1 {
                            return Bracket::Fail;
                        }
                        cend = at(pat, name);
                    } else if let Some((seq, _)) = find_symbol::<T>(loc.get(), &pat[name..name + c1]) {
                        is_seqval = true;
                        cend_seq = as_cend::<T>(seq);
                    } else if c1 == 1 {
                        cend = at(pat, name);
                        c = at(pat, *p);
                        *p += 1;
                    } else {
                        return Bracket::Fail;
                    }
                } else {
                    if !noescape && cend.v() == BSL {
                        cend = at(pat, *p);
                        *p += 1;
                    }
                    if cend.v() == 0 {
                        return Bracket::Fail;
                    }
                    cend = fold(cend, flags);
                }
                if (T::WIDE && lcollseq == u32::MAX) || lcollseq <= fcollseq {
                    // look at the upper bound
                    let hcollseq = if is_seqval {
                        cend_seq
                    } else {
                        let h = seq_of(loc.get(), cend);
                        if T::WIDE && h == NO_SEQ {
                            // no information about the upper bound: matches only when the lower bound matched exactly
                            if lcollseq != fcollseq {
                                break 'range;
                            }
                            return Bracket::Matched;
                        }
                        h
                    };
                    if lcollseq <= hcollseq && fcollseq <= hcollseq {
                        return Bracket::Matched;
                    }
                }
            }
            c = at(pat, *p);
            *p += 1;
        }
        if c.v() == b']' as u32 {
            return Bracket::NotMatched;
        }
    }
}

/// After a member matched: skip the rest of the list to its `]`. Err(()) = the whole match fails;
/// Ok(true) = list was not terminated (the `[` is literal); Ok(false) = skipped.
#[inline]
fn skip_rest<T: Ch>(p: &mut Cur<T>, flags: c_int) -> Result<bool, ()> {
    let noescape = flags & FNM_NOESCAPE != 0;
    loop {
        let Some((c, q)) = p.take() else { return Ok(true) };
        let c = c.v();
        *p = q;
        if c == b']' as u32 {
            return Ok(false);
        }
        if !noescape && c == BSL {
            if p.get().v() == 0 {
                return Err(());
            }
            *p = p.next();
        } else if c == LBR && p.get().v() == b':' as u32 {
            let startp = *p;
            let mut c1 = 0;
            let mut ok = true;
            loop {
                *p = p.next();
                let cc = p.get().v();
                c1 += 1;
                if c1 == CHAR_CLASS_MAX_LENGTH {
                    return Err(());
                }
                if cc == b':' as u32 && p.peek().v() == b']' as u32 {
                    break;
                }
                #[allow(clippy::almost_complete_range)]
                if !((b'a' as u32)..(b'z' as u32)).contains(&cc) {
                    // not a class name: the `:` is an ordinary member
                    *p = startp;
                    ok = false;
                    break;
                }
            }
            if ok {
                *p = p.next().next();
            }
        } else if c == LBR && p.get().v() == b'=' as u32 {
            *p = p.next();
            if p.get().v() == 0 {
                return Err(());
            }
            *p = p.next();
            if p.get().v() != b'=' as u32 || p.peek().v() != b']' as u32 {
                return Err(());
            }
            *p = p.next().next();
        } else if c == LBR && p.get().v() == b'.' as u32 {
            loop {
                *p = p.next();
                let cc = p.get().v();
                if cc == 0 {
                    return Err(());
                }
                if cc == b'.' as u32 && p.peek().v() == b']' as u32 {
                    break;
                }
            }
            *p = p.next().next();
        }
    }
}

/// The first `c` in `s[from..end]`, as an index.
#[inline]
fn memchr<T: Ch>(s: &[T], from: usize, c: T, end: usize) -> Option<usize> {
    if from >= end {
        return None;
    }
    let hay = &s[from..end];
    // (not under Miri, which cannot run the vector code's inline assembly)
    if let Some(b) = T::bytes(hay)
        && b.len() > 12
        && !cfg!(miri)
    {
        // SAFETY: `b` is readable for its length.
        let r = unsafe { rusty_libc_mem::memchr(b.as_ptr().cast(), c.v() as i32, b.len()) } as usize;
        return if r == 0 { None } else { Some(from + (r - b.as_ptr() as usize)) };
    }
    // short, or wide: a plain loop
    hay.iter().position(|&x| x == c).map(|i| from + i)
}

/// Skip the extended pattern starting at the `(` at `pattern`: returns the position after the
/// matching `)`, or `pattern` itself when it is not a valid extended pattern.
fn end_pattern<T: Ch>(pat: &[T], pattern: usize) -> usize {
    let mut p = pattern;
    loop {
        p += 1;
        let c = at(pat, p).v();
        if c == 0 {
            return pattern;
        } else if c == LBR {
            let pc = posixly();
            p += 1;
            if at(pat, p).v() == BANG || (pc < 0 && at(pat, p).v() == b'^' as u32) {
                p += 1;
            }
            if at(pat, p).v() == b']' as u32 {
                p += 1;
            }
            while at(pat, p).v() != b']' as u32 {
                let x = at(pat, p).v();
                p += 1;
                if x == 0 {
                    return pattern;
                }
            }
        } else if matches!(c, QM | STAR | PLUS | AT | BANG) && at(pat, p + 1).v() == b'(' as u32 {
            p = end_pattern(pat, p + 1);
            if at(pat, p).v() == 0 {
                return pattern;
            }
        } else if c == b')' as u32 {
            break;
        }
    }
    p + 1
}

/// An alternative of an extended pattern: its start and length in the pattern.
type Item = (usize, usize);

/// The alternatives of an extended pattern, as ranges of the pattern (glibc copies each into a NUL-terminated buffer; the
/// matcher reads a slice's end as its NUL, so a range of the pattern is the same sub-pattern without the copy): the
/// first eight inline, the rest on the heap.
struct Alts {
    inline: [Item; 8],
    n: usize,
    more: CVec<Item>,
}

impl Alts {
    #[inline]
    fn new() -> Alts {
        Alts { inline: [(0, 0); 8], n: 0, more: CVec::new() }
    }
    #[inline]
    fn len(&self) -> usize {
        self.n
    }
    #[inline]
    fn item(&self, i: usize) -> Item {
        if i < 8 { self.inline[i] } else { self.more.as_slice()[i - 8] }
    }
    #[inline]
    fn push(&mut self, it: Item) -> bool {
        if self.n < 8 {
            self.inline[self.n] = it;
        } else if !self.more.push(it) {
            return false;
        }
        self.n += 1;
        true
    }
    /// Alternative `i` of `pat`.
    #[inline]
    fn get<'p, T: Ch>(&self, pat: &'p [T], i: usize) -> &'p [T] {
        let (o, l) = self.item(i);
        &pat[o..o + l]
    }
}

/// `?(...)`/`@(...)`: each alternative followed by the rest of the pattern (`rest`, without its NUL), matched in turn as
/// one pattern; the concatenation is built in `buf` (a stack buffer for short ones, else the heap, as glibc's alloca or
/// malloc): the rest and its NUL once, at `longest`, and each alternative in front of it. Returns 0 on the first match,
/// FNM_NOMATCH when none matches, -2 when memory ran out.
#[allow(clippy::too_many_arguments)]
fn ext_cat<T: Ch>(buf: &mut [T], list: &Alts, longest: usize, pat: Z<T>, rest: &[T], s: Z<T>, string: usize, string_end: usize, nlp: bool, flags2: c_int) -> c_int {
    let mut heap = CVec::<T>::new();
    let need = longest + rest.len() + 1;
    let buf: &mut [T] = if need <= buf.len() {
        &mut buf[..need]
    } else {
        if !heap.resize(need, k(0)) {
            return -2;
        }
        heap.as_mut_slice()
    };
    let Some((nul, tail)) = buf.split_last_mut() else { return -2 };
    *nul = k(0);
    let Some(rest_slot) = tail.get_mut(longest..) else { return -2 };
    rest_slot.copy_from_slice(rest);
    for i in 0..list.len() {
        let item = list.get(pat.slice(), i);
        // (every alternative is at most `longest` long)
        let Some(start) = longest.checked_sub(item.len()) else { return -2 };
        buf[start..longest].copy_from_slice(item);
        if let Some(z) = Z::new(&buf[start..])
            && fct(z, 0, s, string, string_end, nlp, flags2, None) == 0
        {
            return 0;
        }
    }
    FNM_NOMATCH
}

/// Extended-pattern operator `opt` (one of `?*+@!`) whose `(` is at `pattern`. Returns -1 when the
/// operator is not well formed (the caller then treats the character literally), -2 on memory
/// failure, else 0 / FNM_NOMATCH.
#[allow(clippy::too_many_arguments)]
fn ext_match<T: Ch>(opt: u32, pat: Z<T>, pattern: usize, s: Z<T>, string: usize, string_end: usize, nlp: bool, flags: c_int) -> c_int {
    let mut list = Alts::new();
    let mut level: isize = 0;
    let mut startp = pattern + 1;
    let mut q = pat.cur(startp);
    // the longest alternative (sizes the buffer of `?(...)`/`@(...)`)
    let mut longest = 0usize;
    // parse the alternatives
    while level >= 0 {
        let Some((c, nq)) = q.take() else { return -1 };
        let c = c.v();
        if c == LBR {
            let pc = posixly();
            let mut r = nq;
            if r.get().v() == BANG || (pc < 0 && r.get().v() == b'^' as u32) {
                r = r.next();
            }
            if r.get().v() == b']' as u32 {
                r = r.next();
            }
            while r.get().v() != b']' as u32 {
                let Some((_, r1)) = r.take() else { return -1 };
                r = r1;
            }
            q = r.next();
            continue;
        } else if matches!(c, QM | STAR | PLUS | AT | BANG) && nq.get().v() == b'(' as u32 {
            level += 1;
        } else if c == b')' as u32 || c == b'|' as u32 {
            let p = q.pos();
            if level == 0 {
                if !list.push((startp, p - startp)) {
                    return -2;
                }
                longest = longest.max(p - startp);
                if c == b'|' as u32 {
                    startp = p + 1;
                }
            }
            if c == b')' as u32 {
                level -= 1;
            }
        }
        q = nq;
    }
    let p = q.pos();
    // p is just after the closing parenthesis
    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
    match opt {
        STAR | PLUS | BANG => ext_alts(opt, &list, pat, pattern, p, s, string, string_end, nlp, flags, flags2),
        QM | AT => {
            if opt == QM && fct(pat, p, s, string, string_end, nlp, flags, None) == 0 {
                return 0;
            }
            // the rest of the pattern, up to its NUL
            let pv = pat.slice();
            let rest = pv.get(p..).unwrap_or(&[]);
            let rest = &rest[..rest.iter().position(|c| c.v() == 0).unwrap_or(rest.len())];
            let need = longest + rest.len() + 1;
            if need <= 64 {
                ext_cat(&mut [k::<T>(0); 64], &list, longest, pat, rest, s, string, string_end, nlp, flags2)
            } else if need <= 512 {
                ext_cat(&mut [k::<T>(0); 512], &list, longest, pat, rest, s, string, string_end, nlp, flags2)
            } else {
                ext_cat(&mut [], &list, longest, pat, rest, s, string, string_end, nlp, flags2)
            }
        }
        _ => -1,
    }
}

/// `*(...)`, `+(...)`, `!(...)` (`p` just after the `)`, `pattern` at the `(`): each alternative is matched as a pattern
/// of its own. (Its own function: the copy buffer is not part of every `ext_match` frame.)
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn ext_alts<T: Ch>(opt: u32, list: &Alts, pat: Z<T>, pattern: usize, p: usize, s: Z<T>, string: usize, string_end: usize, nlp: bool, flags: c_int, flags2: c_int) -> c_int {
    let after = |rs: usize| -> bool { if rs == string { nlp } else { s.at(rs - 1).v() == SLASH && no_leading_period(flags) } };
    let nitems = list.len();
    // `*(...)`, `+(...)`, `!(...)` match each alternative as a pattern of its own: NUL-terminated copies (as glibc's
    // list), in a stack buffer when they fit
    let mut zstack = [k::<T>(0); 128];
    let mut zheap = CVec::<T>::new();
    let mut zlist = Alts::new();
    let zbuf: &[T] = {
        let total: usize = (0..nitems).map(|i| list.item(i).1 + 1).sum();
        let buf: &mut [T] = if total <= zstack.len() {
            &mut zstack[..total]
        } else {
            if !zheap.resize(total, k(0)) {
                return -2;
            }
            zheap.as_mut_slice()
        };
        let mut o = 0;
        for i in 0..nitems {
            let item = list.get(pat.slice(), i);
            buf[o..o + item.len()].copy_from_slice(item);
            buf[o + item.len()] = k(0);
            if !zlist.push((o, item.len() + 1)) {
                return -2;
            }
            o += item.len() + 1;
        }
        buf
    };
    let zitem = |i: usize| Z::new(zlist.get(zbuf, i));
    match opt {
        STAR | PLUS => {
            if opt == STAR && fct(pat, p, s, string, string_end, nlp, flags, None) == 0 {
                return 0;
            }
            for i in 0..nitems {
                let Some(item) = zitem(i) else { return -2 };
                let mut rs = string;
                while rs <= string_end {
                    if fct(item, 0, s, string, rs, nlp, flags2, None) == 0
                        && (fct(pat, p, s, rs, string_end, after(rs), flags2, None) == 0 || (rs != string && fct(pat, pattern - 1, s, rs, string_end, after(rs), flags2, None) == 0))
                    {
                        return 0;
                    }
                    rs += 1;
                }
            }
            FNM_NOMATCH
        }
        BANG => {
            let mut rs = string;
            while rs <= string_end {
                let mut any = false;
                for i in 0..nitems {
                    if zitem(i).is_some_and(|z| fct(z, 0, s, string, rs, nlp, flags2, None) == 0) {
                        any = true;
                        break;
                    }
                }
                if !any && fct(pat, p, s, rs, string_end, after(rs), flags2, None) == 0 {
                    return 0;
                }
                rs += 1;
            }
            FNM_NOMATCH
        }
        _ => -1,
    }
}

/// The matcher (glibc's `internal_fnmatch` / `internal_fnwmatch`): 0 on a match, FNM_NOMATCH otherwise. The pattern
/// starts at `pat[p0]`, the string at `s[n0]` and ends at `s[string_end]` (both slices end with a NUL).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn fct<T: Ch>(pat: Z<T>, p0: usize, s: Z<T>, n0: usize, string_end: usize, mut no_leading_period_: bool, flags: c_int, mut ends: Option<&mut Ends>) -> c_int {
    let mut p = pat.cur(p0);
    let mut n = n0;
    let extmatch = flags & FNM_EXTMATCH != 0;
    let slash_special = no_leading_period(flags);
    let Some(sv) = s.slice().get(..string_end) else { return FNM_NOMATCH };
    loop {
        // a run of ordinary characters that equal the string's: step over it without the dispatch below
        {
            let mut m = 0usize;
            let mut q = p;
            // (the string side is bounded by the loop condition; the pattern side stops at its NUL, tested first so that
            // the step to the next pattern character is a plain increment)
            if !T::WIDE && flags & FNM_CASEFOLD != 0 && !rusty_libc_core::locale::ctype_special() {
                // byte characters, no locale-specific case mapping: ASCII lower case inline
                let lower = |v: u32| if v.wrapping_sub(65) < 26 { v | 32 } else { v };
                while n + m < sv.len() {
                    let (pc, nc) = (q.get().v(), sv[n + m].v());
                    if pc == 0 {
                        break;
                    }
                    let q1 = q.next();
                    if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && nc == SLASH) {
                        m += 1;
                        q = q1;
                        continue;
                    }
                    if (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) {
                        break;
                    }
                    if pc != nc && (pc >= 128 || nc >= 128 || lower(pc) != lower(nc)) {
                        break;
                    }
                    m += 1;
                    q = q1;
                }
            } else if flags & FNM_CASEFOLD == 0 {
                // no case folding: equal and not special is the common step, tested first
                let qm_ok = !extmatch;
                let nlp0 = no_leading_period_;
                let fname = flags & FNM_FILE_NAME != 0;
                while n + m < sv.len() {
                    let (pc, nc) = (q.get().v(), sv[n + m].v());
                    if pc == 0 {
                        break;
                    }
                    let q1 = q.next();
                    if pc == nc && !(pc < 128 && SPECIAL[pc as usize]) && !(pc == SLASH && slash_special) {
                        m += 1;
                        q = q1;
                        continue;
                    }
                    if pc == QM && qm_ok && (m != 0 || !nlp0) && !(fname && nc == SLASH) {
                        m += 1;
                        q = q1;
                        continue;
                    }
                    break;
                }
            } else {
                while n + m < sv.len() {
                    let (praw, nraw) = (q.get(), sv[n + m]);
                    let pc = praw.v();
                    if pc == 0 {
                        break;
                    }
                    let q1 = q.next();
                    if pc == QM && !extmatch && (m != 0 || !no_leading_period_) && !(flags & FNM_FILE_NAME != 0 && nraw.v() == SLASH) {
                        m += 1;
                        q = q1;
                        continue;
                    }
                    if (pc < 128 && SPECIAL[pc as usize]) || (pc == SLASH && slash_special) || fold(praw, flags) != fold(nraw, flags) {
                        break;
                    }
                    m += 1;
                    q = q1;
                }
            }
            if m != 0 {
                p = q;
                n += m;
                no_leading_period_ = false;
            }
        }
        let Some((mut c, p1)) = p.take() else { break };
        p = p1;
        let mut new_nlp = false;
        c = fold(c, flags);
        // `normal` = the default branch: compare the character literally
        let mut normal = false;
        match c.v() {
            QM => {
                if extmatch && p.get().v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p.pos(), s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                }
                if n == string_end || (s.at(n).v() == SLASH && flags & FNM_FILE_NAME != 0) || (s.at(n).v() == b'.' as u32 && no_leading_period_) {
                    return FNM_NOMATCH;
                }
            }
            BSL => {
                if flags & FNM_NOESCAPE == 0 {
                    let Some((c1, p1)) = p.take() else { return FNM_NOMATCH };
                    p = p1;
                    c = fold(c1, flags);
                }
                if n == string_end || fold(s.at(n), flags) != c {
                    return FNM_NOMATCH;
                }
            }
            STAR => {
                if extmatch && p.get().v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p.pos(), s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                } else if let Some(e) = ends.as_deref_mut() {
                    e.pattern = Some(p.pos() - 1);
                    e.string = n;
                    e.no_leading_period = no_leading_period_;
                    return 0;
                }
                if n != string_end && s.at(n).v() == b'.' as u32 && no_leading_period_ {
                    return FNM_NOMATCH;
                }
                // (`at_c`: the position of `c`, where the code below starts the rest of the pattern)
                let mut at_c = p;
                loop {
                    let Some((c1, p1)) = at_c.take() else {
                        // the pattern ends in stars: a name with another slash cannot match unless FNM_LEADING_DIR is set
                        return if flags & FNM_FILE_NAME == 0 || flags & FNM_LEADING_DIR != 0 || memchr(s.slice(), n, k(b'/'), string_end).is_none() { 0 } else { FNM_NOMATCH };
                    };
                    c = c1;
                    p = p1;
                    if c.v() != QM && c.v() != STAR {
                        break;
                    }
                    if p.get().v() == b'(' as u32 && extmatch {
                        let endp = end_pattern(pat.slice(), p.pos());
                        if endp != p.pos() {
                            at_c = p.to(endp);
                            continue;
                        }
                    }
                    if c.v() == QM {
                        if n == string_end || (s.at(n).v() == SLASH && flags & FNM_FILE_NAME != 0) {
                            return FNM_NOMATCH;
                        }
                        n += 1;
                    }
                    at_c = p;
                }
                // (p is past `c`, which is not NUL)
                let mut end = Ends { pattern: None, string: 0, no_leading_period: false };
                // (the `*/` case below finds the slash itself)
                let endp = if flags & FNM_FILE_NAME != 0 && c.v() != SLASH { memchr(s.slice(), n, k(b'/'), string_end) } else { None }.unwrap_or(string_end);
                // `found` = jump into the loop epilogue of the last branch below
                let mut found = false;
                if c.v() == LBR || (extmatch && (c.v() == AT || c.v() == PLUS || c.v() == BANG) && p.get().v() == b'(' as u32) {
                    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                    p = at_c;
                    // byte order, a plain bracket list: reject a position whose character is decided without the recursion
                    let pre = !T::WIDE && c.v() == LBR && p.peek().v() != b'^' as u32 && byte_order_collation();
                    let neg = pre && p.peek().v() == BANG;
                    let patb = pat.bytes();
                    let p1 = p.pos() + 1 + neg as usize;
                    while n < endp {
                        if pre && let Some(pb) = patb {
                            let nc = fold(s.at(n), flags);
                            match bracket_fast(pb, p1, nc.v() as u8, s.at(n).v() as u8, flags).map(|r| r.0) {
                                Some(Bracket::NotMatched) if !neg => {
                                    n += 1;
                                    no_leading_period_ = false;
                                    continue;
                                }
                                Some(Bracket::Matched) if neg => {
                                    n += 1;
                                    no_leading_period_ = false;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        if fct(pat, p.pos(), s, n, string_end, no_leading_period_, flags2, Some(&mut end)) == 0 {
                            found = true;
                            break;
                        }
                        n += 1;
                        no_leading_period_ = false;
                    }
                } else if c.v() == SLASH && flags & FNM_FILE_NAME != 0 {
                    n = memchr(s.slice(), n, k(b'/'), string_end).unwrap_or(string_end);
                    if n < string_end && s.at(n).v() == SLASH {
                        if ends.is_none() {
                            // the rest of the pattern against the rest of the name, in this frame (what the call
                            // below returns is the result of the whole match: no later `*` records anything here)
                            n += 1;
                            no_leading_period_ = flags & FNM_PERIOD != 0;
                            continue;
                        }
                        if fct(pat, p.pos(), s, n + 1, string_end, flags & FNM_PERIOD != 0, flags, None) == 0 {
                            return 0;
                        }
                    }
                } else {
                    // `*literal` at the end of the pattern (no special character, no slash): the literal can only match the
                    // end of the string, so test that instead of trying each position (what the loop below finds)
                    if flags & (FNM_LEADING_DIR | FNM_CASEFOLD) == 0
                        && let Some(lit) = literal_tail(at_c)
                    {
                        // (the literal starts before `endp`: the star does not match a slash under FNM_PATHNAME)
                        let Some(start) = string_end.checked_sub(lit.len()).filter(|&st| st >= n && st < endp) else { return FNM_NOMATCH };
                        return if sv.get(start..) == Some(lit) { 0 } else { FNM_NOMATCH };
                    }
                    let flags2 = if flags & FNM_FILE_NAME != 0 { flags } else { flags & !FNM_PERIOD };
                    if c.v() == BSL && flags & FNM_NOESCAPE == 0 {
                        c = p.get();
                    }
                    c = fold(c, flags);
                    p = at_c;
                    while n < endp {
                        if flags & FNM_CASEFOLD == 0 {
                            // skip to the next occurrence of the literal (vector scan)
                            let Some(q) = memchr(s.slice(), n, c, endp) else { break };
                            if q != n {
                                n = q;
                                no_leading_period_ = false;
                            }
                        }
                        if fold(s.at(n), flags) == c && fct(pat, p.pos(), s, n, string_end, no_leading_period_, flags2, Some(&mut end)) == 0 {
                            found = true;
                            break;
                        }
                        n += 1;
                        no_leading_period_ = false;
                    }
                }
                if found {
                    // a nested `*` recorded where to resume: continue from there; otherwise the
                    // rest of the pattern already matched the rest of the string
                    let Some(ep) = end.pattern else { return 0 };
                    p = p.to(ep);
                    n = end.string;
                    no_leading_period_ = end.no_leading_period;
                    continue;
                }
                return FNM_NOMATCH;
            }
            LBR => {
                let p_init = p;
                let n_init = n;
                let pc = posixly();
                if n == string_end {
                    return FNM_NOMATCH;
                }
                if s.at(n).v() == b'.' as u32 && no_leading_period_ {
                    return FNM_NOMATCH;
                }
                if s.at(n).v() == SLASH && flags & FNM_FILE_NAME != 0 {
                    return FNM_NOMATCH;
                }
                let not = p.get().v() == BANG || (pc < 0 && p.get().v() == b'^' as u32);
                if not {
                    p = p.next();
                }
                let fnc = fold(s.at(n), flags);
                let mut literal = false;
                let mut adv = 0usize;
                let fast = match pat.bytes() {
                    Some(pb) if byte_order_collation() => bracket_fast(pb, p.pos(), fnc.v() as u8, s.at(n).v() as u8, flags).map(|(r, bp)| {
                        p = p.to(bp);
                        r
                    }),
                    _ => None,
                };
                let r = match fast {
                    Some(r) => r,
                    None => {
                        let mut pi = p.pos();
                        let r = bracket_members(pat.slice(), &mut pi, s.slice(), n, fnc, flags, &mut adv);
                        p = p.to(pi);
                        r
                    }
                };
                match r {
                    Bracket::Fail => return FNM_NOMATCH,
                    Bracket::Literal => literal = true,
                    Bracket::NotMatched => {
                        if !not {
                            return FNM_NOMATCH;
                        }
                    }
                    Bracket::Matched => match skip_rest(&mut p, flags) {
                        Err(()) => return FNM_NOMATCH,
                        Ok(true) => literal = true,
                        Ok(false) => {
                            if not {
                                return FNM_NOMATCH;
                            }
                            // a multi-character collating element matched: the string moves past all of it
                            n += adv;
                        }
                    },
                }
                if literal {
                    p = p_init;
                    n = n_init;
                    c = k(b'[');
                    normal = true;
                }
            }
            PLUS | AT | BANG => {
                if extmatch && p.get().v() == b'(' as u32 {
                    let res = ext_match(c.v(), pat, p.pos(), s, n, string_end, no_leading_period_, flags);
                    if res != -1 {
                        return res;
                    }
                }
                normal = true;
            }
            SLASH => {
                if no_leading_period(flags) {
                    if n == string_end || c != s.at(n) {
                        return FNM_NOMATCH;
                    }
                    new_nlp = true;
                } else {
                    normal = true;
                }
            }
            _ => normal = true,
        }
        if normal && (n == string_end || c != fold(s.at(n), flags)) {
            return FNM_NOMATCH;
        }
        no_leading_period_ = new_nlp;
        n += 1;
    }
    if n == string_end {
        return 0;
    }
    if flags & FNM_LEADING_DIR != 0 && s.at(n).v() == SLASH {
        return 0;
    }
    FNM_NOMATCH
}

/// The pattern from `p` to its NUL when it holds only ordinary characters (no `? * [ \ + @ !`, no slash): those match
/// themselves, one for one. `None` otherwise (or when it is empty).
#[inline]
fn literal_tail<'a, T: Ch>(p: Cur<'a, T>) -> Option<&'a [T]> {
    let mut q = p;
    while let Some((c, q1)) = q.take() {
        let c = c.v();
        if (c < 128 && SPECIAL[c as usize]) || c == SLASH {
            return None;
        }
        q = q1;
    }
    let t = p.tail(0);
    t.get(..q.pos() - p.pos()).filter(|t| !t.is_empty())
}

/// A wide string with its NUL: in a stack buffer or on the heap.
enum Wide<'a> {
    Stack(&'a [u32]),
    Heap(CVec<u32>),
}

impl Wide<'_> {
    fn get(&self) -> &[u32] {
        match self {
            Wide::Stack(s) => s,
            Wide::Heap(h) => h.as_slice(),
        }
    }
}

/// Convert a multibyte string (with its NUL) to wide characters with `mbsrtowcs` (what glibc's
/// `fnmatch_convert_to_wide` does): the wide string with its NUL and whether the conversion reached the NUL, or `None`
/// when the text is not valid in the locale's charset.
///
/// A text that ends inside a multibyte character (GB18030 `\x81\x31`, EUC-JP `\xa4`, ...) is not invalid for
/// `mbsrtowcs`: it converts the complete characters before it and stops there without an error. glibc's
/// `fnmatch_convert_to_wide` then takes its second path (made for a buffer that is too small) and converts again into a
/// buffer of that many characters plus one, which `mbsrtowcs` leaves without a terminating L'\0': the wide text is the
/// complete characters followed by whatever the buffer held before (the scratch buffer on its stack). The string's end
/// is given by its length, so only the pattern is affected (see `wide_match`); the result here is the complete
/// characters, terminated, with `false`.
fn to_wide<'a>(s: &[u8], stack: &'a mut [u32; 256]) -> Option<(Wide<'a>, bool)> {
    use rusty_libc_wchar::mbstate_t;
    use rusty_libc_wchar::mbyte::mbsrtowcs;
    debug_assert!(s.last() == Some(&0));
    let conv = |dst: *mut u32, len: usize| -> (usize, bool) {
        let mut ps = mbstate_t::default();
        let mut src = s.as_ptr() as *const c_char;
        // SAFETY: `src` is a C string (`s` ends with its NUL); `dst` is NULL or writable for `len` wide characters.
        let r = unsafe { mbsrtowcs(dst.cast(), &mut src, len, &mut ps) };
        (r, src.is_null())
    };
    // fits in the stack buffer? (mbsrtowcs stops at `len` characters, leaving `src` non-NULL)
    let (r, done) = conv(stack.as_mut_ptr(), stack.len());
    if r == usize::MAX {
        return None;
    }
    if done {
        return Some((Wide::Stack(&stack[..=r]), true));
    }
    if r < stack.len() {
        // stopped before the buffer was full: the text ends inside a character
        stack[r] = 0;
        return Some((Wide::Stack(&stack[..=r]), false));
    }
    let (n, _) = conv(core::ptr::null_mut(), 0);
    if n == usize::MAX {
        return None;
    }
    let mut buf = CVec::<u32>::new();
    if !buf.resize(n + 1, 0) {
        return None;
    }
    let (_, done) = conv(buf.as_mut_ptr(), n + 1);
    Some((Wide::Heap(buf), done))
}

/// fnmatch(3) on byte strings with their NULs: 0 when `string` matches `pattern`, `FNM_NOMATCH` (1) when not.
pub fn fnmatch_bytes(pattern: &[u8], string: &[u8], flags: c_int) -> c_int {
    debug_assert!(pattern.last() == Some(&0) && string.last() == Some(&0));
    // SAFETY: `pattern` ends with its NUL and outlives the call.
    unsafe { fnmatch_in(pattern.as_ptr(), Some(pattern), string, flags) }
}

/// The body of `fnmatch`: the pattern is still a C string (the quick path reads it in place, glibc's matcher needs it
/// measured), the string is measured. The matcher itself is never inlined ([`fct`]), so the quick path pays for no large
/// stack frame.
///
/// # Safety
/// `pattern` is a C string that stays valid during the call; `known` is None or that string with its NUL.
#[inline(always)]
unsafe fn fnmatch_in(pattern: *const u8, known: Option<&[u8]>, string: &[u8], flags: c_int) -> c_int {
    let slen = string.len() - 1;
    let pat = || {
        // SAFETY: a C string (the function's contract).
        known.unwrap_or_else(|| unsafe { rusty_libc_core::ffi::cstr_nonnull(pattern) }.to_bytes_with_nul())
    };
    // multibyte locale: the wide version first (glibc: `r == 0` is final, anything else falls through to the byte
    // version). Pure ASCII text and pattern take the byte version alone: the two agree there (not under
    // FNM_CASEFOLD, where `towlower` and the byte `tolower` can differ, as in Turkish).
    if rusty_libc_wchar::mbyte::mb_cur_max() != 1 {
        let p = pat();
        if !(flags & FNM_CASEFOLD == 0 && string.is_ascii() && p.is_ascii()) && wide_match(p, string, flags) {
            return 0;
        }
    }
    if flags & !(FNM_NOESCAPE | FNM_CASEFOLD) == 0
        // SAFETY: as above.
        && let Some(r) = unsafe { simple_match(pattern, &string[..slen], flags & FNM_CASEFOLD != 0) }
    {
        return r;
    }
    match (Z::new(pat()), Z::new(string)) {
        (Some(p), Some(s)) => fct::<u8>(p, 0, s, 0, slen, flags & FNM_PERIOD != 0, flags, None),
        _ => FNM_NOMATCH,
    }
}

/// fnmatch(3): 0 when `string` matches `pattern`, `FNM_NOMATCH` (1) when not.
///
/// # Safety
/// Both arguments are NUL-terminated strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int {
    // SAFETY: a C string (caller's contract).
    let s = unsafe { rusty_libc_core::ffi::cstr_nonnull(string) };
    // SAFETY: as above.
    unsafe { fnmatch_in(pattern.cast(), None, s.to_bytes_with_nul(), flags) }
}

/// The commonest patterns, `literal`, `*literal`, `literal*` and `*literal*` (no `? * [ \` and no non-ASCII byte in the literal), without
/// FNM_PATHNAME, FNM_PERIOD, FNM_LEADING_DIR or FNM_EXTMATCH: an equality, prefix, suffix or substring test. `None` for any
/// other pattern.
/// `pattern` ends with its NUL, `s` is the string without it.
///
/// # Safety
/// `pattern` is a C string.
#[inline(always)]
unsafe fn simple_match(pattern: *const u8, s: &[u8], casefold: bool) -> Option<c_int> {
    if casefold && rusty_libc_core::locale::ctype_special() {
        return None;
    }
    // byte `i` of the pattern; the loop below reads them in order and stops at the NUL
    let byte = |i: usize| {
        // SAFETY: every byte before `i` was read and is not NUL, so byte `i` is part of the C string.
        unsafe { *pattern.wrapping_add(i) }
    };
    let star = byte(0) == b'*';
    let base = star as usize;
    let mut l = 0usize;
    let mut trailing = false;
    // `*literal*`
    let mut both = false;
    loop {
        let c = byte(base + l);
        if c == 0 {
            break;
        }
        if c == b'*' && !star && byte(base + l + 1) == 0 {
            trailing = true;
            break;
        }
        if c >= 128 || c == b'?' || c == b'*' || c == b'[' || c == b'\\' {
            if c == b'*' && star && l != 0 && byte(base + l + 1) == 0 {
                both = true;
                break;
            }
            return None;
        }
        l += 1;
    }
    // SAFETY: the `l` bytes after the optional `*` were read above and are not NUL.
    let lit = unsafe { rusty_libc_core::ffi::bytes(pattern.wrapping_add(base), l) };
    if both {
        // `*literal*`: a substring test
        return Some(if contains(s, lit, casefold) { 0 } else { FNM_NOMATCH });
    }
    let slen = s.len();
    let t = if trailing {
        // `literal*`: a prefix test
        s.get(..l)
    } else if star {
        s.get(slen.wrapping_sub(l)..)
    } else if slen == l {
        Some(s)
    } else {
        None
    };
    let Some(t) = t else { return Some(FNM_NOMATCH) };
    let same = if !casefold { eq_bytes(lit, t) } else { eq_ascii_casefold(lit, t) };
    Some(if same { 0 } else { FNM_NOMATCH })
}

/// Does `s` contain `lit` (not empty, ASCII), up to ASCII case under `casefold`? (Candidates by the vector `memchr` of
/// the first byte; out of line, so that it leaves the code of the other quick tests as it was.)
#[inline(never)]
fn contains(s: &[u8], lit: &[u8], casefold: bool) -> bool {
    let l = lit.len();
    let (Some(&first), Some(last)) = (lit.first(), s.len().checked_sub(l)) else { return false };
    if casefold {
        return (0..=last).any(|i| s.get(i..i + l).is_some_and(|t| eq_ascii_casefold(lit, t)));
    }
    let mut i = 0;
    while let Some(j) = memchr(s, i, first, last + 1) {
        if s.get(j..j + l).is_some_and(|t| eq_bytes(lit, t)) {
            return true;
        }
        i = j + 1;
    }
    false
}

/// `a == b` for slices of the same length up to ASCII case (`a` is ASCII; a byte of `b` from 128 up matches only itself).
/// An indexed loop: the iterator form was not inlined.
#[inline(always)]
fn eq_ascii_casefold(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    let (a, b) = (&a[..n], &b[..n]);
    let mut i = 0;
    while i < n {
        let (x, y) = (a[i], b[i]);
        if x != y && !(y < 128 && x.eq_ignore_ascii_case(&y)) {
            break;
        }
        i += 1;
    }
    i == n
}

/// `a == b` for slices of the same length, in 8-byte words, then bytes (short literals: no `memcmp` call).
#[inline(always)]
fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if b.len() != n {
        return false;
    }
    let mut i = 0;
    while i + 8 <= n {
        let (Some(x), Some(y)) = (a[i..].first_chunk::<8>(), b[i..].first_chunk::<8>()) else { return false };
        if u64::from_ne_bytes(*x) != u64::from_ne_bytes(*y) {
            return false;
        }
        i += 8;
    }
    while i < n {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The wide-character match of `fnmatch` (its own function: the two 1 KB conversion buffers must not make every
/// byte-locale call pay for a 2 KB frame).
#[inline(never)]
fn wide_match(pattern: &[u8], s: &[u8], flags: c_int) -> bool {
    let mut pstack = [0u32; 256];
    let mut sstack = [0u32; 256];
    let mut r = FNM_NOMATCH;
    // A pattern that ends inside a multibyte character: glibc's wide pattern is its complete characters followed by stale
    // contents of its scratch buffer instead of a L'\0' (see `to_wide`), which almost never match; its fnmatch then
    // falls back to the byte matcher. That fallback is taken here at once.
    if let Some((wp, true)) = to_wide(pattern, &mut pstack)
        && let Some((ws, _)) = to_wide(s, &mut sstack)
    {
        let (wp, ws) = (wp.get(), ws.get());
        if let (Some(zp), Some(zw)) = (Z::new(wp), Z::new(ws)) {
            r = fct::<u32>(zp, 0, zw, 0, ws.len() - 1, flags & FNM_PERIOD != 0, flags, None);
        }
    }
    r == 0
}

/// Rust API: does `string` match `pattern` under `flags`? Neither may contain a NUL.
pub fn matches(pattern: &core::ffi::CStr, string: &core::ffi::CStr, flags: c_int) -> bool {
    fnmatch_bytes(pattern.to_bytes_with_nul(), string.to_bytes_with_nul(), flags) == 0
}

#[cfg(test)]
mod key_tests {
    /// The packed-name class look-up of the byte fast path agrees with the slice one on every byte, for the 12 names and
    /// for near misses.
    #[test]
    fn class_test_key_matches_class_test() {
        let names: [&[u8]; 18] = [
            b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower", b"print", b"punct", b"space", b"upper",
            b"xdigit", b"alph", b"alphaa", b"xdigi", b"a", b"digits", b"uppe",
        ];
        for name in names {
            for c in 0..=255u8 {
                assert_eq!(super::class_test_key(super::name_key(name), c), super::class_test::<u8>(name, c), "{name:?} {c}");
            }
        }
    }
}

/// Host-free cases (results from glibc 2.43, C locale) through the byte matcher, so that the unchecked reads of [`zs`]
/// can run under Miri (`cargo +nightly miri test -p rusty-libc-util fnmatch::zs_tests`; the other fnmatch tests call the host
/// fnmatch through FFI, which Miri cannot).
#[cfg(test)]
mod zs_tests {
    #[test]
    fn byte_matcher_matches_glibc() {
        let cases: &[(&[u8], &[u8], i32, i32)] = &[
        (b"*.c\0", b"main.c\0", 0, 0),
        (b"*.c\0", b"main.c\0", 37, 0),
        (b"*.c\0", b"abcdefgh9\0", 16, 1),
        (b"*.c\0", b"barbell.c\0", 1, 0),
        (b"*.c\0", b"barbell.c\0", 11, 0),
        (b"*.c\0", b"a.a\0", 32, 1),
        (b"*.c\0", b"dz\0", 4, 1),
        (b"*.c\0", b"*a\0", 0, 1),
        (b"*.c\0", b"*a\0", 37, 1),
        (b"*.c\0", b".h\0", 16, 1),
        (b"*.c\0", b"ac\0", 1, 1),
        (b"*.c\0", b"ac\0", 11, 1),
        (b"*.c\0", b"\0", 32, 1),
        (b"*.c\0", b"a/.b\0", 4, 1),
        (b"Makefile\0", b"Makefile\0", 0, 0),
        (b"Makefile\0", b"Makefile\0", 37, 0),
        (b"Makefile\0", b"deadbeef_42_notes.txt\0", 16, 1),
        (b"Makefile\0", b"readme.md\0", 1, 1),
        (b"Makefile\0", b"readme.md\0", 11, 1),
        (b"Makefile\0", b"bb\0", 32, 1),
        (b"Makefile\0", b"]abc\0", 4, 1),
        (b"Makefile\0", b"a\\\0", 0, 1),
        (b"Makefile\0", b"a\\\0", 37, 1),
        (b"Makefile\0", b"f\0", 16, 1),
        (b"Makefile\0", b"abbac\0", 1, 1),
        (b"Makefile\0", b"abbac\0", 11, 1),
        (b"Makefile\0", b"/x\0", 32, 1),
        (b"Makefile\0", b"a\0", 4, 1),
        (b"src/*/foo?.[ch]\0", b"src/lib/foo1.c\0", 0, 0),
        (b"src/*/foo?.[ch]\0", b"src/lib/foo1.c\0", 37, 0),
        (b"src/*/foo?.[ch]\0", b"hayneedlestack\0", 16, 1),
        (b"src/*/foo?.[ch]\0", b"ababcx\0", 1, 1),
        (b"src/*/foo?.[ch]\0", b"ababcx\0", 11, 1),
        (b"src/*/foo?.[ch]\0", b"y\0", 32, 1),
        (b"src/*/foo?.[ch]\0", b"[a-\0", 4, 1),
        (b"src/*/foo?.[ch]\0", b"a/b\0", 0, 1),
        (b"src/*/foo?.[ch]\0", b"a/b\0", 37, 1),
        (b"src/*/foo?.[ch]\0", b"ab\0", 16, 1),
        (b"src/*/foo?.[ch]\0", b"xaybz\0", 1, 1),
        (b"src/*/foo?.[ch]\0", b"xaybz\0", 11, 1),
        (b"src/*/foo?.[ch]\0", b".x\0", 32, 1),
        (b"src/*/foo?.[ch]\0", b"main.c\0", 4, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"abcdefgh9\0", 0, 0),
        (b"[[:alpha:]]*[[:digit:]]\0", b"abcdefgh9\0", 37, 0),
        (b"[[:alpha:]]*[[:digit:]]\0", b"barbell.c\0", 16, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"a.a\0", 1, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"a.a\0", 11, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"dz\0", 32, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"*a\0", 4, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b".h\0", 0, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b".h\0", 37, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"ac\0", 16, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"\0", 1, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"\0", 11, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"a/.b\0", 32, 1),
        (b"[[:alpha:]]*[[:digit:]]\0", b"Makefile\0", 4, 1),
        (b"[a-f]*[0-9]*.txt\0", b"deadbeef_42_notes.txt\0", 0, 0),
        (b"[a-f]*[0-9]*.txt\0", b"deadbeef_42_notes.txt\0", 37, 0),
        (b"[a-f]*[0-9]*.txt\0", b"readme.md\0", 16, 1),
        (b"[a-f]*[0-9]*.txt\0", b"bb\0", 1, 1),
        (b"[a-f]*[0-9]*.txt\0", b"bb\0", 11, 1),
        (b"[a-f]*[0-9]*.txt\0", b"]abc\0", 32, 1),
        (b"[a-f]*[0-9]*.txt\0", b"a\\\0", 4, 1),
        (b"[a-f]*[0-9]*.txt\0", b"f\0", 0, 1),
        (b"[a-f]*[0-9]*.txt\0", b"f\0", 37, 1),
        (b"[a-f]*[0-9]*.txt\0", b"abbac\0", 16, 1),
        (b"[a-f]*[0-9]*.txt\0", b"/x\0", 1, 1),
        (b"[a-f]*[0-9]*.txt\0", b"/x\0", 11, 1),
        (b"[a-f]*[0-9]*.txt\0", b"a\0", 32, 1),
        (b"[a-f]*[0-9]*.txt\0", b"src/lib/foo1.c\0", 4, 1),
        (b"*needle*\0", b"hayneedlestack\0", 0, 0),
        (b"*needle*\0", b"hayneedlestack\0", 37, 0),
        (b"*needle*\0", b"ababcx\0", 16, 1),
        (b"*needle*\0", b"y\0", 1, 1),
        (b"*needle*\0", b"y\0", 11, 1),
        (b"*needle*\0", b"[a-\0", 32, 1),
        (b"*needle*\0", b"a/b\0", 4, 1),
        (b"*needle*\0", b"ab\0", 0, 1),
        (b"*needle*\0", b"ab\0", 37, 1),
        (b"*needle*\0", b"xaybz\0", 16, 1),
        (b"*needle*\0", b".x\0", 1, 1),
        (b"*needle*\0", b".x\0", 11, 1),
        (b"*needle*\0", b"main.c\0", 32, 1),
        (b"*needle*\0", b"abcdefgh9\0", 4, 1),
        (b"@(foo|bar|baz)*.c\0", b"barbell.c\0", 0, 1),
        (b"@(foo|bar|baz)*.c\0", b"barbell.c\0", 37, 0),
        (b"@(foo|bar|baz)*.c\0", b"a.a\0", 16, 1),
        (b"@(foo|bar|baz)*.c\0", b"dz\0", 1, 1),
        (b"@(foo|bar|baz)*.c\0", b"dz\0", 11, 1),
        (b"@(foo|bar|baz)*.c\0", b"*a\0", 32, 1),
        (b"@(foo|bar|baz)*.c\0", b".h\0", 4, 1),
        (b"@(foo|bar|baz)*.c\0", b"ac\0", 0, 1),
        (b"@(foo|bar|baz)*.c\0", b"ac\0", 37, 1),
        (b"@(foo|bar|baz)*.c\0", b"\0", 16, 1),
        (b"@(foo|bar|baz)*.c\0", b"a/.b\0", 1, 1),
        (b"@(foo|bar|baz)*.c\0", b"a/.b\0", 11, 1),
        (b"@(foo|bar|baz)*.c\0", b"Makefile\0", 32, 1),
        (b"@(foo|bar|baz)*.c\0", b"deadbeef_42_notes.txt\0", 4, 1),
        (b"README*\0", b"readme.md\0", 0, 1),
        (b"README*\0", b"readme.md\0", 37, 1),
        (b"README*\0", b"bb\0", 16, 1),
        (b"README*\0", b"]abc\0", 1, 1),
        (b"README*\0", b"]abc\0", 11, 1),
        (b"README*\0", b"a\\\0", 32, 1),
        (b"README*\0", b"f\0", 4, 1),
        (b"README*\0", b"abbac\0", 0, 1),
        (b"README*\0", b"abbac\0", 37, 1),
        (b"README*\0", b"/x\0", 16, 1),
        (b"README*\0", b"a\0", 1, 1),
        (b"README*\0", b"a\0", 11, 1),
        (b"README*\0", b"src/lib/foo1.c\0", 32, 1),
        (b"README*\0", b"hayneedlestack\0", 4, 1),
        (b"*(ab|c)x\0", b"ababcx\0", 0, 1),
        (b"*(ab|c)x\0", b"ababcx\0", 37, 0),
        (b"*(ab|c)x\0", b"y\0", 16, 1),
        (b"*(ab|c)x\0", b"[a-\0", 1, 1),
        (b"*(ab|c)x\0", b"[a-\0", 11, 1),
        (b"*(ab|c)x\0", b"a/b\0", 32, 1),
        (b"*(ab|c)x\0", b"ab\0", 4, 1),
        (b"*(ab|c)x\0", b"xaybz\0", 0, 1),
        (b"*(ab|c)x\0", b"xaybz\0", 37, 1),
        (b"*(ab|c)x\0", b".x\0", 16, 1),
        (b"*(ab|c)x\0", b"main.c\0", 1, 1),
        (b"*(ab|c)x\0", b"main.c\0", 11, 1),
        (b"*(ab|c)x\0", b"abcdefgh9\0", 32, 1),
        (b"*(ab|c)x\0", b"barbell.c\0", 4, 1),
        (b"+(a|.)\0", b"a.a\0", 0, 1),
        (b"+(a|.)\0", b"a.a\0", 37, 0),
        (b"+(a|.)\0", b"dz\0", 16, 1),
        (b"+(a|.)\0", b"*a\0", 1, 1),
        (b"+(a|.)\0", b"*a\0", 11, 1),
        (b"+(a|.)\0", b".h\0", 32, 1),
        (b"+(a|.)\0", b"ac\0", 4, 1),
        (b"+(a|.)\0", b"\0", 0, 1),
        (b"+(a|.)\0", b"\0", 37, 1),
        (b"+(a|.)\0", b"a/.b\0", 16, 1),
        (b"+(a|.)\0", b"Makefile\0", 1, 1),
        (b"+(a|.)\0", b"Makefile\0", 11, 1),
        (b"+(a|.)\0", b"deadbeef_42_notes.txt\0", 32, 1),
        (b"+(a|.)\0", b"readme.md\0", 4, 1),
        (b"!(a)b\0", b"bb\0", 0, 1),
        (b"!(a)b\0", b"bb\0", 37, 0),
        (b"!(a)b\0", b"]abc\0", 16, 1),
        (b"!(a)b\0", b"a\\\0", 1, 1),
        (b"!(a)b\0", b"a\\\0", 11, 1),
        (b"!(a)b\0", b"f\0", 32, 1),
        (b"!(a)b\0", b"abbac\0", 4, 1),
        (b"!(a)b\0", b"/x\0", 0, 1),
        (b"!(a)b\0", b"/x\0", 37, 1),
        (b"!(a)b\0", b"a\0", 16, 1),
        (b"!(a)b\0", b"src/lib/foo1.c\0", 1, 1),
        (b"!(a)b\0", b"src/lib/foo1.c\0", 11, 1),
        (b"!(a)b\0", b"hayneedlestack\0", 32, 1),
        (b"!(a)b\0", b"ababcx\0", 4, 1),
        (b"?(x)y\0", b"y\0", 0, 1),
        (b"?(x)y\0", b"y\0", 37, 0),
        (b"?(x)y\0", b"[a-\0", 16, 1),
        (b"?(x)y\0", b"a/b\0", 1, 1),
        (b"?(x)y\0", b"a/b\0", 11, 1),
        (b"?(x)y\0", b"ab\0", 32, 1),
        (b"?(x)y\0", b"xaybz\0", 4, 1),
        (b"?(x)y\0", b".x\0", 0, 1),
        (b"?(x)y\0", b".x\0", 37, 1),
        (b"?(x)y\0", b"main.c\0", 16, 1),
        (b"?(x)y\0", b"abcdefgh9\0", 1, 1),
        (b"?(x)y\0", b"abcdefgh9\0", 11, 1),
        (b"?(x)y\0", b"barbell.c\0", 32, 1),
        (b"?(x)y\0", b"a.a\0", 4, 1),
        (b"[!a-c]?\0", b"dz\0", 0, 0),
        (b"[!a-c]?\0", b"dz\0", 37, 0),
        (b"[!a-c]?\0", b"*a\0", 16, 0),
        (b"[!a-c]?\0", b".h\0", 1, 0),
        (b"[!a-c]?\0", b".h\0", 11, 0),
        (b"[!a-c]?\0", b"ac\0", 32, 1),
        (b"[!a-c]?\0", b"\0", 4, 1),
        (b"[!a-c]?\0", b"a/.b\0", 0, 1),
        (b"[!a-c]?\0", b"a/.b\0", 37, 1),
        (b"[!a-c]?\0", b"Makefile\0", 16, 1),
        (b"[!a-c]?\0", b"deadbeef_42_notes.txt\0", 1, 1),
        (b"[!a-c]?\0", b"deadbeef_42_notes.txt\0", 11, 1),
        (b"[!a-c]?\0", b"readme.md\0", 32, 1),
        (b"[!a-c]?\0", b"bb\0", 4, 1),
        (b"[]a]*\0", b"]abc\0", 0, 0),
        (b"[]a]*\0", b"]abc\0", 37, 0),
        (b"[]a]*\0", b"a\\\0", 16, 0),
        (b"[]a]*\0", b"f\0", 1, 1),
        (b"[]a]*\0", b"f\0", 11, 1),
        (b"[]a]*\0", b"abbac\0", 32, 0),
        (b"[]a]*\0", b"/x\0", 4, 1),
        (b"[]a]*\0", b"a\0", 0, 0),
        (b"[]a]*\0", b"a\0", 37, 0),
        (b"[]a]*\0", b"src/lib/foo1.c\0", 16, 1),
        (b"[]a]*\0", b"hayneedlestack\0", 1, 1),
        (b"[]a]*\0", b"hayneedlestack\0", 11, 1),
        (b"[]a]*\0", b"ababcx\0", 32, 0),
        (b"[]a]*\0", b"y\0", 4, 1),
        (b"[a-\0", b"[a-\0", 0, 1),
        (b"[a-\0", b"[a-\0", 37, 1),
        (b"[a-\0", b"a/b\0", 16, 1),
        (b"[a-\0", b"ab\0", 1, 1),
        (b"[a-\0", b"ab\0", 11, 1),
        (b"[a-\0", b"xaybz\0", 32, 1),
        (b"[a-\0", b".x\0", 4, 1),
        (b"[a-\0", b"main.c\0", 0, 1),
        (b"[a-\0", b"main.c\0", 37, 1),
        (b"[a-\0", b"abcdefgh9\0", 16, 1),
        (b"[a-\0", b"barbell.c\0", 1, 1),
        (b"[a-\0", b"barbell.c\0", 11, 1),
        (b"[a-\0", b"a.a\0", 32, 1),
        (b"[a-\0", b"dz\0", 4, 1),
        (b"\\*a\0", b"*a\0", 0, 0),
        (b"\\*a\0", b"*a\0", 37, 0),
        (b"\\*a\0", b".h\0", 16, 1),
        (b"\\*a\0", b"ac\0", 1, 1),
        (b"\\*a\0", b"ac\0", 11, 1),
        (b"\\*a\0", b"\0", 32, 1),
        (b"\\*a\0", b"a/.b\0", 4, 1),
        (b"\\*a\0", b"Makefile\0", 0, 1),
        (b"\\*a\0", b"Makefile\0", 37, 1),
        (b"\\*a\0", b"deadbeef_42_notes.txt\0", 16, 1),
        (b"\\*a\0", b"readme.md\0", 1, 1),
        (b"\\*a\0", b"readme.md\0", 11, 1),
        (b"\\*a\0", b"bb\0", 32, 1),
        (b"\\*a\0", b"]abc\0", 4, 1),
        (b"a\\\0", b"a\\\0", 0, 1),
        (b"a\\\0", b"a\\\0", 37, 1),
        (b"a\\\0", b"f\0", 16, 1),
        (b"a\\\0", b"abbac\0", 1, 1),
        (b"a\\\0", b"abbac\0", 11, 1),
        (b"a\\\0", b"/x\0", 32, 1),
        (b"a\\\0", b"a\0", 4, 1),
        (b"a\\\0", b"src/lib/foo1.c\0", 0, 1),
        (b"a\\\0", b"src/lib/foo1.c\0", 37, 1),
        (b"a\\\0", b"hayneedlestack\0", 16, 1),
        (b"a\\\0", b"ababcx\0", 1, 1),
        (b"a\\\0", b"ababcx\0", 11, 1),
        (b"a\\\0", b"y\0", 32, 1),
        (b"a\\\0", b"[a-\0", 4, 1),
        (b"*/b\0", b"a/b\0", 0, 0),
        (b"*/b\0", b"a/b\0", 37, 0),
        (b"*/b\0", b"ab\0", 16, 1),
        (b"*/b\0", b"xaybz\0", 1, 1),
        (b"*/b\0", b"xaybz\0", 11, 1),
        (b"*/b\0", b".x\0", 32, 1),
        (b"*/b\0", b"main.c\0", 4, 1),
        (b"*/b\0", b"abcdefgh9\0", 0, 1),
        (b"*/b\0", b"abcdefgh9\0", 37, 1),
        (b"*/b\0", b"barbell.c\0", 16, 1),
        (b"*/b\0", b"a.a\0", 1, 1),
        (b"*/b\0", b"a.a\0", 11, 1),
        (b"*/b\0", b"dz\0", 32, 1),
        (b"*/b\0", b"*a\0", 4, 1),
        (b"*.[ch]\0", b".h\0", 0, 0),
        (b"*.[ch]\0", b".h\0", 37, 1),
        (b"*.[ch]\0", b"ac\0", 16, 1),
        (b"*.[ch]\0", b"\0", 1, 1),
        (b"*.[ch]\0", b"\0", 11, 1),
        (b"*.[ch]\0", b"a/.b\0", 32, 1),
        (b"*.[ch]\0", b"Makefile\0", 4, 1),
        (b"*.[ch]\0", b"deadbeef_42_notes.txt\0", 0, 1),
        (b"*.[ch]\0", b"deadbeef_42_notes.txt\0", 37, 1),
        (b"*.[ch]\0", b"readme.md\0", 16, 1),
        (b"*.[ch]\0", b"bb\0", 1, 1),
        (b"*.[ch]\0", b"bb\0", 11, 1),
        (b"*.[ch]\0", b"]abc\0", 32, 1),
        (b"*.[ch]\0", b"a\\\0", 4, 1),
        (b"[[:foo:]]\0", b"f\0", 0, 1),
        (b"[[:foo:]]\0", b"f\0", 37, 1),
        (b"[[:foo:]]\0", b"abbac\0", 16, 1),
        (b"[[:foo:]]\0", b"/x\0", 1, 1),
        (b"[[:foo:]]\0", b"/x\0", 11, 1),
        (b"[[:foo:]]\0", b"a\0", 32, 1),
        (b"[[:foo:]]\0", b"src/lib/foo1.c\0", 4, 1),
        (b"[[:foo:]]\0", b"hayneedlestack\0", 0, 1),
        (b"[[:foo:]]\0", b"hayneedlestack\0", 37, 1),
        (b"[[:foo:]]\0", b"ababcx\0", 16, 1),
        (b"[[:foo:]]\0", b"y\0", 1, 1),
        (b"[[:foo:]]\0", b"y\0", 11, 1),
        (b"[[:foo:]]\0", b"[a-\0", 32, 1),
        (b"[[:foo:]]\0", b"a/b\0", 4, 1),
        (b"[=a=]b\0", b"ab\0", 0, 0),
        (b"[=a=]b\0", b"ab\0", 37, 0),
        (b"[=a=]b\0", b"xaybz\0", 16, 1),
        (b"[=a=]b\0", b".x\0", 1, 1),
        (b"[=a=]b\0", b".x\0", 11, 1),
        (b"[=a=]b\0", b"main.c\0", 32, 1),
        (b"[=a=]b\0", b"abcdefgh9\0", 4, 1),
        (b"[=a=]b\0", b"barbell.c\0", 0, 1),
        (b"[=a=]b\0", b"barbell.c\0", 37, 1),
        (b"[=a=]b\0", b"a.a\0", 16, 1),
        (b"[=a=]b\0", b"dz\0", 1, 1),
        (b"[=a=]b\0", b"dz\0", 11, 1),
        (b"[=a=]b\0", b"*a\0", 32, 1),
        (b"[=a=]b\0", b".h\0", 4, 1),
        (b"[.a.]c\0", b"ac\0", 0, 0),
        (b"[.a.]c\0", b"ac\0", 37, 0),
        (b"[.a.]c\0", b"\0", 16, 1),
        (b"[.a.]c\0", b"a/.b\0", 1, 1),
        (b"[.a.]c\0", b"a/.b\0", 11, 1),
        (b"[.a.]c\0", b"Makefile\0", 32, 1),
        (b"[.a.]c\0", b"deadbeef_42_notes.txt\0", 4, 1),
        (b"[.a.]c\0", b"readme.md\0", 0, 1),
        (b"[.a.]c\0", b"readme.md\0", 37, 1),
        (b"[.a.]c\0", b"bb\0", 16, 1),
        (b"[.a.]c\0", b"]abc\0", 1, 1),
        (b"[.a.]c\0", b"]abc\0", 11, 1),
        (b"[.a.]c\0", b"a\\\0", 32, 1),
        (b"[.a.]c\0", b"f\0", 4, 1),
        (b"*([ab])c\0", b"abbac\0", 0, 1),
        (b"*([ab])c\0", b"abbac\0", 37, 0),
        (b"*([ab])c\0", b"/x\0", 16, 1),
        (b"*([ab])c\0", b"a\0", 1, 1),
        (b"*([ab])c\0", b"a\0", 11, 1),
        (b"*([ab])c\0", b"src/lib/foo1.c\0", 32, 1),
        (b"*([ab])c\0", b"hayneedlestack\0", 4, 1),
        (b"*([ab])c\0", b"ababcx\0", 0, 1),
        (b"*([ab])c\0", b"ababcx\0", 37, 1),
        (b"*([ab])c\0", b"y\0", 16, 1),
        (b"*([ab])c\0", b"[a-\0", 1, 1),
        (b"*([ab])c\0", b"[a-\0", 11, 1),
        (b"*([ab])c\0", b"a/b\0", 32, 1),
        (b"*([ab])c\0", b"ab\0", 4, 1),
        (b"x*y*z\0", b"xaybz\0", 0, 0),
        (b"x*y*z\0", b"xaybz\0", 37, 0),
        (b"x*y*z\0", b".x\0", 16, 1),
        (b"x*y*z\0", b"main.c\0", 1, 1),
        (b"x*y*z\0", b"main.c\0", 11, 1),
        (b"x*y*z\0", b"abcdefgh9\0", 32, 1),
        (b"x*y*z\0", b"barbell.c\0", 4, 1),
        (b"x*y*z\0", b"a.a\0", 0, 1),
        (b"x*y*z\0", b"a.a\0", 37, 1),
        (b"x*y*z\0", b"dz\0", 16, 1),
        (b"x*y*z\0", b"*a\0", 1, 1),
        (b"x*y*z\0", b"*a\0", 11, 1),
        (b"x*y*z\0", b".h\0", 32, 1),
        (b"x*y*z\0", b"ac\0", 4, 1),
        (b"**\0", b"\0", 0, 0),
        (b"**\0", b"\0", 37, 0),
        (b"**\0", b"a/.b\0", 16, 0),
        (b"**\0", b"Makefile\0", 1, 0),
        (b"**\0", b"Makefile\0", 11, 0),
        (b"**\0", b"deadbeef_42_notes.txt\0", 32, 0),
        (b"**\0", b"readme.md\0", 4, 0),
        (b"**\0", b"bb\0", 0, 0),
        (b"**\0", b"bb\0", 37, 0),
        (b"**\0", b"]abc\0", 16, 0),
        (b"**\0", b"a\\\0", 1, 0),
        (b"**\0", b"a\\\0", 11, 0),
        (b"**\0", b"f\0", 32, 0),
        (b"**\0", b"abbac\0", 4, 0),
        (b"*\0", b"/x\0", 0, 0),
        (b"*\0", b"/x\0", 37, 1),
        (b"*\0", b"a\0", 16, 0),
        (b"*\0", b"src/lib/foo1.c\0", 1, 1),
        (b"*\0", b"src/lib/foo1.c\0", 11, 0),
        (b"*\0", b"hayneedlestack\0", 32, 0),
        (b"*\0", b"ababcx\0", 4, 0),
        (b"*\0", b"y\0", 0, 0),
        (b"*\0", b"y\0", 37, 0),
        (b"*\0", b"[a-\0", 16, 0),
        (b"*\0", b"a/b\0", 1, 1),
        (b"*\0", b"a/b\0", 11, 0),
        (b"*\0", b"ab\0", 32, 0),
        (b"*\0", b"xaybz\0", 4, 0),
        (b"\0", b".x\0", 0, 1),
        (b"\0", b".x\0", 37, 1),
        (b"\0", b"main.c\0", 16, 1),
        (b"\0", b"abcdefgh9\0", 1, 1),
        (b"\0", b"abcdefgh9\0", 11, 1),
        (b"\0", b"barbell.c\0", 32, 1),
        (b"\0", b"a.a\0", 4, 1),
        (b"\0", b"dz\0", 0, 1),
        (b"\0", b"dz\0", 37, 1),
        (b"\0", b"*a\0", 16, 1),
        (b"\0", b".h\0", 1, 1),
        (b"\0", b".h\0", 11, 1),
        (b"\0", b"ac\0", 32, 1),
        (b"\0", b"\0", 4, 0),
        (b".*\0", b"a/.b\0", 0, 1),
        (b".*\0", b"a/.b\0", 37, 1),
        (b".*\0", b"Makefile\0", 16, 1),
        (b".*\0", b"deadbeef_42_notes.txt\0", 1, 1),
        (b".*\0", b"deadbeef_42_notes.txt\0", 11, 1),
        (b".*\0", b"readme.md\0", 32, 1),
        (b".*\0", b"bb\0", 4, 1),
        (b".*\0", b"]abc\0", 0, 1),
        (b".*\0", b"]abc\0", 37, 1),
        (b".*\0", b"a\\\0", 16, 1),
        (b".*\0", b"f\0", 1, 1),
        (b".*\0", b"f\0", 11, 1),
        (b".*\0", b"abbac\0", 32, 1),
        (b".*\0", b"/x\0", 4, 1),
        (b"*/.*\0", b"a\0", 0, 1),
        (b"*/.*\0", b"a\0", 37, 1),
        (b"*/.*\0", b"src/lib/foo1.c\0", 16, 1),
        (b"*/.*\0", b"hayneedlestack\0", 1, 1),
        (b"*/.*\0", b"hayneedlestack\0", 11, 1),
        (b"*/.*\0", b"ababcx\0", 32, 1),
        (b"*/.*\0", b"y\0", 4, 1),
        (b"*/.*\0", b"[a-\0", 0, 1),
        (b"*/.*\0", b"[a-\0", 37, 1),
        (b"*/.*\0", b"a/b\0", 16, 1),
        (b"*/.*\0", b"ab\0", 1, 1),
        (b"*/.*\0", b"ab\0", 11, 1),
        (b"*/.*\0", b"xaybz\0", 32, 1),
        (b"*/.*\0", b".x\0", 4, 1),
        ];
        for &(p, s, f, want) in cases {
            assert_eq!(super::fnmatch_bytes(p, s, f), want, "{:?} {:?} {f}", core::str::from_utf8(p), core::str::from_utf8(s));
        }
    }
}
