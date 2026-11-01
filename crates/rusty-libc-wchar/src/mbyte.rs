//! Multibyte conversion: mbrtowc, wcrtomb, mbrlen, mbsrtowcs, mbsnrtowcs, wcsrtombs, wcsnrtombs,
//! mbsinit, btowc, wctob, mblen, mbtowc, wctomb, mbstowcs, wcstombs, MB_CUR_MAX and the uchar.h
//! functions (mbrtoc8, c8rtomb, mbrtoc16, c16rtomb, mbrtoc32, c32rtomb). No iconv.
//!
//! Two character sets, chosen with [`set_charset`](crate::set_charset):
//! - `C`: ASCII only. A byte above 0x7f is EILSEQ (checked against glibc 2.43 in the "C" locale:
//!   `mbrtowc`, `mbtowc`, `mbsrtowcs` fail, `btowc` and `wctob` give EOF/WEOF, `MB_CUR_MAX` is 1).
//! - `Utf8`: glibc's UTF-8 rules, which are looser than the standard's: sequences of 5 and 6 bytes
//!   and values up to 0x7fffffff are accepted on input and written on output (so `MB_CUR_MAX` is 6);
//!   overlong forms and surrogates (U+D800..U+DFFF) are EILSEQ; U+110000 and above is not.
//!   An overlong or otherwise bad *incomplete* prefix such as E0 80 is only reported once the
//!   sequence is complete (the first call returns -2), as glibc does.
//!
//! The functions follow glibc's structure, not just its results: `mbstate_t` holds the bytes read so
//! far in the same layout (`count` = bytes seen | length needed << 8, `value` = the bits so far), a
//! conversion that fails leaves the state as it was, a conversion that completes sets `count` to 0
//! and leaves `value` alone, and the string functions cut their input into the same chunks, so the
//! `*src` pointer left behind after an error or a full buffer is the same.
//! The functions with a hidden state (`mbrtowc` with no `ps`, `mbtowc`, `wctomb`, ...) keep one
//! state each, as glibc does. `wcsrtombs` and `wcsnrtombs` called with a state that holds a partial
//! UTF-8 sequence do what glibc does (see `tomb_stateful`: it glues the saved bytes to the front of
//! the wide string's bytes), except that 4 or 5 saved bytes give EILSEQ where glibc aborts.
//!
//! Unsafe here (BRIEF-UNSAFE.md U2): the exported functions turn their pointers into slices (input bytes, output wide
//! characters or bytes), `&mut mbstate_t` and out-parameters once, and the converters (`towc`, `tomb`, `tomb_stateful`)
//! are safe code on slices. Left unsafe: those boundary conversions, the reads and writes of the caller's `*src`
//! pointer, the hidden states (one `SyncCell` per function: C11 7.29.6.3 lets calls with a null state race), the calls
//! through the charset hooks rusty-libc-locale installs (their signatures take raw pointers) and the published locale
//! data read for the codeset name and `MB_CUR_MAX`.
use crate::{Charset, charset, mbstate_t, wchar_t, wint_t, WEOF};
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes, out, slice_mut};
use rusty_libc_core::sync_cell::SyncCell;

pub const EILSEQ: i32 = 84;
/// Longest multibyte sequence of any supported charset (glibc's `MB_LEN_MAX`).
pub const MB_LEN_MAX: usize = 16;

const ERR: usize = usize::MAX; // (size_t)-1
const INCOMPLETE: usize = usize::MAX - 1; // (size_t)-2
const PENDING: usize = usize::MAX - 2; // (size_t)-3

/// The longest output slice made from a C length: lengths beyond it cannot be real (and would make an invalid slice);
/// a C caller that passes `(size_t)-1` for "no limit" gets this instead, which no conversion can fill.
const MAX_ELEMS: usize = isize::MAX as usize / 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// All input was used.
    Empty,
    /// The output is full (input may be left).
    Full,
    Illegal,
    /// The input ends inside a character (its bytes were moved into the state).
    Incomplete,
}

/// A hidden conversion state, one per function that has one in glibc. Synchronisation rule: none; C11 7.29.6.3 says
/// the functions called with a null state pointer need not avoid data races, so the C caller keeps such calls to one
/// thread at a time (as with glibc, whose hidden states are plain statics).
type Hidden = SyncCell<mbstate_t>;
const INITIAL: mbstate_t = mbstate_t { count: 0, value: 0 };

static S_MBRTOWC: Hidden = Hidden::new(INITIAL);
static S_MBRLEN: Hidden = Hidden::new(INITIAL);
static S_MBSRTOWCS: Hidden = Hidden::new(INITIAL);
static S_MBSNRTOWCS: Hidden = Hidden::new(INITIAL);
static S_WCRTOMB: Hidden = Hidden::new(INITIAL);
static S_WCSRTOMBS: Hidden = Hidden::new(INITIAL);
static S_WCSNRTOMBS: Hidden = Hidden::new(INITIAL);
static S_MBTOWC: Hidden = Hidden::new(INITIAL);
static S_WCTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC8: Hidden = Hidden::new(INITIAL);
static S_C8RTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC16: Hidden = Hidden::new(INITIAL);
static S_C16RTOMB: Hidden = Hidden::new(INITIAL);
static S_MBRTOC32: Hidden = Hidden::new(INITIAL);
static S_C32RTOMB: Hidden = Hidden::new(INITIAL);

/// The state a call works on: the caller's `ps`, or the function's hidden one when `ps` is NULL.
///
/// # Safety
/// `ps` is NULL or a valid state that nothing else uses during the call; with NULL, no other call uses the hidden state
/// `own` at the same time (the C rule above).
#[inline(always)]
unsafe fn state<'a>(ps: *mut mbstate_t, own: &'static Hidden) -> &'a mut mbstate_t {
    let p = if ps.is_null() { own.as_ptr() } else { ps };
    // SAFETY: forwarded contract.
    unsafe { &mut *p }
}

/// Put every hidden state back to the initial state (tests only).
#[cfg(test)]
pub(crate) fn reset_hidden_states() {
    for h in [
        &S_MBRTOWC, &S_MBRLEN, &S_MBSRTOWCS, &S_MBSNRTOWCS, &S_WCRTOMB, &S_WCSRTOMBS, &S_WCSNRTOMBS, &S_MBTOWC, &S_WCTOMB, &S_MBRTOC8, &S_C8RTOMB, &S_MBRTOC16, &S_C16RTOMB, &S_MBRTOC32, &S_C32RTOMB,
    ] {
        // SAFETY: the tests that use the hidden states hold the crate's test lock.
        unsafe { h.write(mbstate_t::default()) };
    }
}

// ---- UTF-8 to wide ----

enum Dec {
    Ok(u32, usize),
    Incomplete,
    Illegal,
}

/// Length and lead-byte mask of the UTF-8 sequence that starts with `b0` (glibc's: up to 6 bytes), or `None`.
#[inline(always)]
fn lead(b0: u8) -> Option<(usize, u8)> {
    match b0 {
        0xc2..=0xdf => Some((2, 0x1f)),
        0xe0..=0xef => Some((3, 0x0f)),
        0xf0..=0xf7 => Some((4, 0x07)),
        0xf8..=0xfb => Some((5, 0x03)),
        0xfc..=0xfd => Some((6, 0x01)),
        _ => None,
    }
}

/// Decode one character from the start of `b` (not empty) by glibc's rules.
#[inline(always)]
fn decode(b: &[u8]) -> Dec {
    let b0 = b[0];
    if b0 < 0x80 {
        return Dec::Ok(u32::from(b0), 1);
    }
    let Some((cnt, mask)) = lead(b0) else { return Dec::Illegal };
    if b.len() < cnt {
        // not enough input: the bytes there must all be continuation bytes, else it is an error now
        if b[1..].iter().any(|&c| c & 0xc0 != 0x80) {
            return Dec::Illegal;
        }
        return Dec::Incomplete;
    }
    let mut ch = u32::from(b0 & mask);
    for &c in &b[1..cnt] {
        if c & 0xc0 != 0x80 {
            return Dec::Illegal;
        }
        ch = (ch << 6) | u32::from(c & 0x3f);
    }
    if (cnt > 2 && (ch >> (5 * cnt - 4)) == 0) || (0xd800..=0xdfff).contains(&ch) {
        return Dec::Illegal;
    }
    Dec::Ok(ch, cnt)
}

/// Save the bytes of an incomplete sequence (1..=5 of them) into the state, as glibc lays it out.
fn store_rest(st: &mut mbstate_t, b: &[u8]) {
    let m = b.len();
    let (cnt, mask) = lead(b[0]).unwrap_or((6, 0x01));
    let mut ch = u32::from(b[0] & mask);
    for &c in &b[1..] {
        ch = (ch << 6) | u32::from(c & 0x3f);
    }
    let r = cnt - m;
    ch = ch.wrapping_shl((r * 6) as u32);
    st.count = m as i32 | ((cnt as i32) << 8);
    st.value = ch;
}

/// Convert from the bytes of `src` into the wide characters of `out`. Returns how it stopped, the bytes used and the
/// characters written. This is glibc's UTF-8 step as `mbrtowc` and the `mbs*towcs` functions drive it.
fn utf8_towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    let mut pos = 0usize;
    let mut produced = 0usize;
    if st.count & 7 != 0 {
        // a character was left half done by an earlier call: rebuild its bytes and finish it
        let inlen = (st.count & 255) as usize;
        let ntotal = (st.count as u32 >> 8) as usize;
        if !(2..=6).contains(&ntotal) || inlen == 0 || inlen >= ntotal {
            return (Status::Illegal, 0, 0);
        }
        if out.is_empty() {
            return (Status::Full, 0, 0);
        }
        if src.is_empty() {
            return (Status::Empty, 0, 0);
        }
        const INMASK: [u8; 5] = [0xc0, 0xe0, 0xf0, 0xf8, 0xfc];
        let mut buf = [0u8; 6];
        buf[0] = INMASK[ntotal - 2];
        let mut wch = st.value;
        let mut nt = ntotal;
        loop {
            nt -= 1;
            if nt < inlen {
                buf[nt] = 0x80 | (wch & 0x3f) as u8;
            }
            wch >>= 6;
            if nt <= 1 {
                break;
            }
        }
        buf[0] |= wch as u8;
        let taken = (6 - inlen).min(src.len());
        let total = inlen + taken;
        buf[inlen..total].copy_from_slice(&src[..taken]);
        match decode(&buf[..total]) {
            Dec::Ok(ch, cnt) => {
                pos = cnt.saturating_sub(inlen);
                out[0] = ch;
                produced = 1;
                st.count = 0;
            }
            Dec::Incomplete => {
                store_rest(st, &buf[..total]);
                return (Status::Incomplete, taken, 0);
            }
            Dec::Illegal => return (Status::Illegal, 0, 0),
        }
    }
    loop {
        // a run of ASCII bytes, one character each (what `decode` gives them, without its checks)
        let (s, o) = (&src[pos..], &mut out[produced..]);
        let m = s.len().min(o.len());
        let mut k = 0;
        while k < m && s[k] < 0x80 {
            o[k] = u32::from(s[k]);
            k += 1;
        }
        pos += k;
        produced += k;
        if pos == src.len() {
            return (Status::Empty, pos, produced);
        }
        if produced == out.len() {
            return (Status::Full, pos, produced);
        }
        match decode(&src[pos..]) {
            Dec::Ok(ch, cnt) => {
                out[produced] = ch;
                produced += 1;
                pos += cnt;
            }
            Dec::Incomplete => {
                store_rest(st, &src[pos..]);
                return (Status::Incomplete, src.len(), produced);
            }
            Dec::Illegal => return (Status::Illegal, pos, produced),
        }
    }
}

/// The same for the C locale: ASCII bytes only.
fn ascii_towc(src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    let n = src.len().min(out.len());
    for (i, (&b, o)) in src.iter().zip(out.iter_mut()).enumerate() {
        if b > 0x7f {
            return (Status::Illegal, i, i);
        }
        *o = u32::from(b);
    }
    (if n == src.len() { Status::Empty } else { Status::Full }, n, n)
}

/// Bytes to wide characters in the charset `cs`: (status, bytes used, characters written).
#[inline(always)]
fn towc_cs(cs: Charset, st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    match cs {
        Charset::Utf8 => utf8_towc(st, src, out),
        Charset::C => ascii_towc(src, out),
        Charset::Other => other_towc(st, src, out),
    }
}

/// Bytes to wide characters in the current charset.
#[inline(always)]
fn towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    towc_cs(charset(), st, src, out)
}

// ---- other charsets (tables in rusty-libc-iconv, reached through hooks) ----

/// The codeset name of the LC_CTYPE data in force (NUL-free bytes in a buffer, and the length).
pub fn codeset_name() -> ([u8; 48], usize) {
    let mut b = [0u8; 48];
    let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
        return (b, 0);
    };
    let s = d.bytes(14);
    let n = s.len().min(47);
    b[..n].copy_from_slice(&s[..n]);
    (b, n)
}

/// `mbrtowc` for a charset that is neither C nor UTF-8: `(codeset name, state, source, bytes available, output, room)`
/// gives the status and the number of characters produced. The codeset is the one in force ([`codeset_name`]), or the one
/// a wide stream kept from the locale it was made wide in (glibc's `_IO_fwide` keeps that locale's conversion steps).
pub type OtherToWc = unsafe fn(&[u8], &mut mbstate_t, &mut *const u8, usize, *mut u32, usize) -> (Status, usize);
/// `wcrtomb` for such a charset: `(codeset name, character, output)`.
pub type OtherEncode = fn(&[u8], u32, &mut [u8; 6]) -> Option<usize>;
/// `wcsrtombs` for such a charset: `(state, source, wide characters available, output, room)` gives the status and the
/// number of bytes produced; `*source` moves over the characters used.
pub type OtherToMb = unsafe fn(&mut mbstate_t, &mut *const u32, usize, *mut u8, usize) -> (Status, usize);
/// Calls the function with the bytes and the value of every character of such a charset (every valid sequence of up to 4 bytes).
/// (`f(bytes, wc, count)`: `count` > 1 only for a run of GB18030's four-byte codes, see rusty-libc-iconv's `cjk::each_char`.)
pub type OtherEach = fn(&mut dyn FnMut(&[u8], u32, u32));

static OTHER_TOWC: AtomicUsize = AtomicUsize::new(0);
static OTHER_ENCODE: AtomicUsize = AtomicUsize::new(0);
static OTHER_EACH: AtomicUsize = AtomicUsize::new(0);
static OTHER_TOMB: AtomicUsize = AtomicUsize::new(0);

/// Install the conversions of the charsets that are neither C nor UTF-8 (EUC-JP, GBK, ISO-8859-x ...). Their tables
/// are in rusty-libc-iconv, which is large: a static program that only matches patterns (fnmatch, glob, regcomp) or calls
/// mbrtowc in the C and UTF-8 locales must not pull them in. rusty-libc-locale, whose setlocale and newlocale are the only
/// way to leave those two charsets, installs the hooks when a locale with another charset is installed or created.
pub fn set_other_hooks(towc: OtherToWc, encode: OtherEncode, each: OtherEach, tomb: OtherToMb) {
    OTHER_TOMB.store(tomb as usize, Ordering::Release);
    OTHER_TOWC.store(towc as usize, Ordering::Release);
    OTHER_ENCODE.store(encode as usize, Ordering::Release);
    OTHER_EACH.store(each as usize, Ordering::Release);
}

/// The multibyte characters of the charset in force as rows (see rusty-libc-iconv `Converter::each_row`): `(ranges, f)`, with
/// `f(head, trails)`; false when the charset has no rows.
pub type OtherRows = fn(Option<&[(u32, u32)]>, &mut dyn FnMut(&[u8], &[u64; 4]), &mut dyn FnMut(&[u8], u32, u32)) -> bool;

static OTHER_ROWS: rusty_libc_core::lock::Locked<Option<OtherRows>> = rusty_libc_core::lock::Locked::new(None);

/// Install the rows hook (with [`set_other_hooks`]).
pub fn set_other_rows_hook(rows: OtherRows) {
    OTHER_ROWS.with(|h| *h = Some(rows));
}

/// The single-byte characters of the charset in force (see rusty-libc-iconv `Converter::single_bytes`).
pub type OtherSingles = fn() -> Option<[u64; 4]>;

static OTHER_SINGLES: rusty_libc_core::lock::Locked<Option<OtherSingles>> = rusty_libc_core::lock::Locked::new(None);

/// Install the single-bytes hook (with [`set_other_hooks`]).
pub fn set_other_singles_hook(f: OtherSingles) {
    OTHER_SINGLES.with(|h| *h = Some(f));
}

/// The bytes that are a character by themselves in the charset in force, which is neither C nor UTF-8, as a 256-bit set;
/// `None` when the charset has no such answer (or no locale with such a charset was ever installed).
pub fn other_single_bytes() -> Option<[u64; 4]> {
    match OTHER_SINGLES.with(|h| *h) {
        Some(h) => h(),
        None => None,
    }
}

/// The multibyte characters (two or more bytes) of the charset in force, which is neither C nor UTF-8, as rows: the head
/// bytes and the 256-bit set of the last bytes of the characters, in byte order, only those whose value is in `ranges`
/// (sorted, disjoint) when it is given. False (nothing reported) when the charset has no rows or no locale with such a
/// charset was ever installed; GB18030's four-byte codes are not among them (see [`each_other_char`]).
pub fn each_other_row(ranges: Option<&[(u32, u32)]>, f: &mut dyn FnMut(&[u8], &[u64; 4]), runs: &mut dyn FnMut(&[u8], u32, u32)) -> bool {
    // (the lock is released before the hook runs: it is held for a copy of the pointer only)
    match OTHER_ROWS.with(|h| *h) {
        Some(h) => h(ranges, f, runs),
        None => false,
    }
}

/// Every character of the charset in force, which is neither C nor UTF-8, as its bytes and value (nothing when no locale
/// with such a charset was ever installed).
pub fn each_other_char(f: &mut dyn FnMut(&[u8], u32, u32)) {
    let h = OTHER_EACH.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: only set_other_hooks stores here, with an OtherEach.
        let h: OtherEach = unsafe { core::mem::transmute::<usize, OtherEach>(h) };
        h(f);
    }
}

/// The installed `OtherToWc` hook.
#[inline(always)]
fn towc_hook() -> Option<OtherToWc> {
    let f = OTHER_TOWC.load(Ordering::Acquire);
    // SAFETY: only set_other_hooks stores here, with an OtherToWc.
    (f != 0).then(|| unsafe { core::mem::transmute::<usize, OtherToWc>(f) })
}

/// [`other_towc_in`] on raw input: `avail` bytes at `src` (for `mbrtowc`, whose `n` may be larger than any slice).
///
/// # Safety
/// The hook reads no further than the bytes of one character from `src`, which the caller vouches for (`avail` bytes,
/// or the bytes up to the character's end).
unsafe fn other_towc_raw(name: &[u8], st: &mut mbstate_t, src: *const u8, avail: usize, out: &mut [u32]) -> (Status, usize, usize) {
    let Some(f) = towc_hook() else { return (Status::Illegal, 0, 0) };
    let mut p = src;
    // SAFETY: the input as the caller vouches; `out` is writable for its length.
    let (s, n) = unsafe { f(name, st, &mut p, avail, out.as_mut_ptr(), out.len()) };
    (s, p as usize - src as usize, n)
}

/// Bytes to wide characters in codeset `name` (neither C nor UTF-8).
fn other_towc_in(name: &[u8], st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    // SAFETY: the whole slice is readable.
    unsafe { other_towc_raw(name, st, src.as_ptr(), src.len(), out) }
}

/// Bytes to wide characters in the codeset in force (neither C nor UTF-8).
/// (Never inlined: its codeset-name buffer would enlarge the frame of the C and UTF-8 paths that share the caller.)
#[inline(never)]
fn other_towc(st: &mut mbstate_t, src: &[u8], out: &mut [u32]) -> (Status, usize, usize) {
    let (name, nl) = codeset_name();
    other_towc_in(&name[..nl], st, src, out)
}

/// Wide characters (the units of `src`, 4 bytes each, native order) to bytes through the `OtherToMb` hook.
fn other_tomb(st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let f = OTHER_TOMB.load(Ordering::Acquire);
    if f == 0 {
        return (Status::Illegal, 0, 0);
    }
    // SAFETY: only set_other_hooks stores here, with an OtherToMb.
    let f: OtherToMb = unsafe { core::mem::transmute::<usize, OtherToMb>(f) };
    let start = src.as_ptr().cast::<u32>();
    let mut p = start;
    // SAFETY: `src` holds `src.len() / 4` readable units (4-aligned: only the UTF-8 shifted path uses misaligned units, and
    // it never reaches here); `out` is writable for its length.
    let (s, n) = unsafe { f(st, &mut p, src.len() / 4, out.as_mut_ptr(), out.len()) };
    (s, (p as usize - start as usize) / 4, n)
}

/// `wc` in the codeset in force (neither C nor UTF-8).
/// (Never inlined: its codeset-name buffer would enlarge the frame of the C and UTF-8 paths that share the caller.)
#[inline(never)]
fn other_encode(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    let (name, nl) = codeset_name();
    encode_in(&name[..nl], wc, out)
}

/// `wc` encoded in codeset `name` (one that is neither C nor UTF-8: the codeset of a locale that was in force, see
/// [`codeset_name`]); None when it cannot be, or when no locale with such a codeset was ever installed.
pub fn encode_in(name: &[u8], wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    let f = OTHER_ENCODE.load(Ordering::Acquire);
    if f == 0 {
        return None;
    }
    // SAFETY: only set_other_hooks stores here, with an OtherEncode.
    let f: OtherEncode = unsafe { core::mem::transmute::<usize, OtherEncode>(f) };
    f(name, wc, out)
}

/// The first character of `bytes` in codeset `name` (see [`encode_in`]) from a fresh state; Invalid when no locale with
/// such a codeset was ever installed.
pub fn decode_in(name: &[u8], bytes: &[u8]) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut st = mbstate_t::default();
    let mut w = 0u32;
    let (status, used, produced) = other_towc_in(name, &mut st, bytes, core::slice::from_mut(&mut w));
    decoded(status, used, produced, w)
}

// ---- wide to UTF-8 ----

/// Write `wc` as UTF-8 (glibc's rules: up to 0x7fffffff, no surrogates) into `out`; the length, or
/// `None` if it cannot be encoded.
fn encode_utf8(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    if wc < 0x80 {
        out[0] = wc as u8;
        return Some(1);
    }
    if wc > 0x7fff_ffff || (0xd800..=0xdfff).contains(&wc) {
        return None;
    }
    let mut step = 2usize;
    while step < 6 && (wc & (!0u32 << (5 * step + 1))) != 0 {
        step += 1;
    }
    out[0] = (0xffff_ff00u32 >> step) as u8;
    let mut w = wc;
    let mut i = step;
    while i > 1 {
        i -= 1;
        out[i] = 0x80 | (w & 0x3f) as u8;
        w >>= 6;
    }
    out[0] |= w as u8;
    Some(step)
}

/// Unit `k` of a wide string seen as bytes (4 per unit, native order, any alignment).
#[inline(always)]
fn unit(src: &[u8], k: usize) -> u32 {
    let b: [u8; 4] = src[4 * k..4 * k + 4].try_into().unwrap_or([0; 4]);
    u32::from_ne_bytes(b)
}

/// Convert the wide characters in `src` (4 bytes each, native order; a trailing part unit is ignored) into the bytes of
/// `out`. A character that does not fit is left (status Full). Returns the status, the units used and the bytes written.
fn tomb(st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    tomb_cs(charset(), st, src, out)
}

/// [`tomb`] in the charset `cs`.
fn tomb_cs(cs: Charset, st: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let units = src.len() / 4;
    if cs == Charset::Other {
        if units != 0 && out.is_empty() {
            return (Status::Full, 0, 0);
        }
        return other_tomb(st, &src[..units * 4], out);
    }
    let cap = out.len();
    let (mut i, mut produced) = (0usize, 0usize);
    loop {
        // ASCII run (the same one byte in UTF-8 and in the C locale): four characters at a time, then singly
        let mut run = 0;
        for (sb, ob) in src[4 * i..4 * units].as_chunks::<16>().0.iter().zip(out[produced..].as_chunks_mut::<4>().0) {
            let [a, b, c, d] = [0, 1, 2, 3].map(|k| u32::from_ne_bytes([sb[4 * k], sb[4 * k + 1], sb[4 * k + 2], sb[4 * k + 3]]));
            if (a | b | c | d) >= 0x80 {
                break;
            }
            *ob = (a | (b << 8) | (c << 16) | (d << 24)).to_le_bytes();
            run += 4;
        }
        i += run;
        produced += run;
        while i < units && produced < cap {
            let wc = unit(src, i);
            if wc >= 0x80 {
                break;
            }
            out[produced] = wc as u8;
            produced += 1;
            i += 1;
        }
        if i == units {
            return (Status::Empty, i, produced);
        }
        if produced >= cap {
            return (Status::Full, i, produced);
        }
        let wc = unit(src, i);
        let mut b = [0u8; 6];
        let n = match cs {
            Charset::Utf8 => encode_utf8(wc, &mut b),
            Charset::C => {
                b[0] = wc as u8;
                if wc <= 0x7f { Some(1) } else { None }
            }
            Charset::Other => other_encode(wc, &mut b),
        };
        let Some(n) = n else {
            if (wc >> 7) == (0xe0000 >> 7) {
                // Unicode tag characters U+E0000..U+E007F: an encoder that cannot write them skips them silently (as glibc's)
                i += 1;
                continue;
            }
            return (Status::Illegal, i, produced);
        };
        let Some(dst) = out.get_mut(produced..produced + n) else { return (Status::Full, i, produced) };
        // a byte loop: at most 6 bytes, cheaper than a call into memcpy
        for (d, &x) in dst.iter_mut().zip(&b[..n]) {
            *d = x;
        }
        produced += n;
        i += 1;
    }
}

/// `tomb` for the wide-to-multibyte string functions, which also copes with a state that holds the
/// start of a UTF-8 character (a half-read one left by `mbrtowc`). glibc's internal-to-UTF-8 step
/// takes the bytes saved in the state (`value`, little endian, `count & 7` of them) as the first
/// bytes of a 4-byte wide character and fills the rest from the input, so the input is then read
/// 4 bytes at a time at a shifted position (the `*src` left behind can be misaligned); at the end
/// 1 to 3 bytes of the last wide character can remain, they go into the state and the call fails
/// as an incomplete input (EILSEQ). Nothing is changed in the state by a call that outputs
/// nothing for lack of room or because of an illegal character.
/// `src` is the input as BYTES; returns the status, the bytes used and the bytes written.
fn tomb_stateful(ps: &mut mbstate_t, src: &[u8], out: &mut [u8]) -> (Status, usize, usize) {
    let avail = src.len();
    let mut pos = 0usize;
    let mut produced = 0usize;
    let n = (ps.count & 7) as usize;
    if n != 0 {
        let need = 4 - n;
        if out.is_empty() {
            return (Status::Full, 0, 0);
        }
        let mut bytes = ps.value.to_le_bytes();
        if avail < need {
            // the whole rest of the input is still not enough for one wide character
            bytes[n..n + avail].copy_from_slice(src);
            ps.value = u32::from_le_bytes(bytes);
            ps.count = (ps.count & !7) | (n + avail) as i32;
            return (Status::Incomplete, avail, 0);
        }
        bytes[n..].copy_from_slice(&src[..need]);
        let wc = u32::from_le_bytes(bytes);
        let mut b = [0u8; 6];
        let Some(len) = encode_utf8(wc, &mut b) else { return (Status::Illegal, 0, 0) };
        if len > out.len() {
            return (Status::Full, 0, 0);
        }
        out[..len].copy_from_slice(&b[..len]);
        produced = len;
        ps.count &= !7;
        pos = need;
    }
    let rest = &src[pos..];
    let whole = rest.len() / 4 * 4;
    let (status, used, p) = tomb(ps, &rest[..whole], &mut out[produced..]);
    produced += p;
    pos += used * 4;
    if status == Status::Empty && pos != avail {
        let tail = &src[pos..];
        let mut bytes = ps.value.to_le_bytes();
        bytes[..tail.len()].copy_from_slice(tail);
        ps.value = u32::from_le_bytes(bytes);
        ps.count = (ps.count & !7) | tail.len() as i32;
        return (Status::Incomplete, avail, produced);
    }
    (status, pos, produced)
}

// ---- restartable single character functions ----

/// `mbrtowc` on a resolved state.
///
/// # Safety
/// `s` NULL or readable for `n` bytes (or up to the end of the character it starts); `pwc` NULL or writable.
#[inline(always)]
unsafe fn mbrtowc_in(pwc: *mut wchar_t, s: *const c_char, n: usize, st: &mut mbstate_t) -> usize {
    let (pwc, s, n) = if s.is_null() { (core::ptr::null_mut(), c"".as_ptr(), 1) } else { (pwc, s, n) };
    if n == 0 {
        return INCOMPLETE;
    }
    let cs = charset();
    if cs != Charset::Other && st.count & 7 == 0 {
        // no half-read character: decode the first one directly (what `towc_cs` does for one character, without its
        // loop); C and UTF-8 read at most 6 bytes, so the first MB_LEN_MAX of the `n` give the same answer
        // SAFETY: readable for `n` bytes (forwarded contract), of which the slice takes at most 16.
        let src = unsafe { bytes(s.cast::<u8>(), n.min(MB_LEN_MAX)) };
        let d = if cs == Charset::Utf8 {
            decode(src)
        } else if src[0] < 0x80 {
            Dec::Ok(u32::from(src[0]), 1)
        } else {
            Dec::Illegal
        };
        return match d {
            Dec::Ok(ch, cnt) => {
                // SAFETY: `pwc` is NULL or writable (forwarded contract).
                if let Some(w) = unsafe { out(pwc) } {
                    *w = ch as wchar_t;
                }
                if ch == 0 { 0 } else { cnt }
            }
            Dec::Incomplete => {
                store_rest(st, src);
                INCOMPLETE
            }
            Dec::Illegal => {
                errno::set(EILSEQ);
                ERR
            }
        };
    }
    // SAFETY: forwarded contract.
    unsafe { mbrtowc_slow(pwc, s, n, st, cs) }
}

/// `mbrtowc_in` with a half-read character in the state, or in a charset other than C and UTF-8 (out of line: the
/// fast path above then needs no stack frame).
///
/// # Safety
/// As `mbrtowc_in`, with `s` not NULL and `n > 0`.
#[inline(never)]
unsafe fn mbrtowc_slow(pwc: *mut wchar_t, s: *const c_char, n: usize, st: &mut mbstate_t, cs: Charset) -> usize {
    let mut buf = 0u32;
    let out: &mut [u32] = match pwc.is_null() {
        true => core::slice::from_mut(&mut buf),
        // SAFETY: `pwc` is writable (forwarded contract).
        false => unsafe { slice_mut(pwc.cast::<u32>(), 1) },
    };
    let (status, used, produced) = if cs == Charset::Other {
        let (name, nl) = codeset_name();
        // SAFETY: forwarded contract.
        unsafe { other_towc_raw(&name[..nl], st, s.cast(), n, out) }
    } else {
        // C and UTF-8 read at most 6 bytes of one character: the first MB_LEN_MAX of the `n` give the same answer
        // SAFETY: readable for `n` bytes (forwarded contract), of which the slice takes at most 16.
        towc_cs(cs, st, unsafe { bytes(s.cast(), n.min(MB_LEN_MAX)) }, out)
    };
    match status {
        Status::Empty | Status::Full => {
            if produced > 0 && out[0] == 0 {
                0
            } else {
                used
            }
        }
        Status::Incomplete => INCOMPLETE,
        Status::Illegal => {
            errno::set(EILSEQ);
            ERR
        }
    }
}

/// Convert the next multibyte character of `s` (at most `n` bytes) to a wide character, resuming
/// from `ps`. Returns the bytes used (0 for the NUL character), (size_t)-2 if the bytes so far
/// start a valid character that needs more (they are kept in `ps`), or (size_t)-1 with EILSEQ.
/// With `s` NULL it is a call on an empty string, which resets `ps` unless a character is pending.
///
/// # Safety
/// `s` valid for `n` bytes (or NULL), `pwc` NULL or writable, `ps` NULL or a valid state.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtowc(pwc: *mut wchar_t, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBRTOWC) };
    // SAFETY: forwarded contract.
    unsafe { mbrtowc_in(pwc, s, n, st) }
}

/// Length of the next multibyte character, like `mbrtowc` without storing it.
///
/// glibc's internal name for `mbrlen`.
///
/// # Safety
/// As `mbrlen`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract.
    unsafe { mbrlen(s, n, ps) }
}

/// # Safety
/// As `mbrtowc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBRLEN) };
    // SAFETY: forwarded contract.
    unsafe { mbrtowc_in(core::ptr::null_mut(), s, n, st) }
}

/// `wcrtomb` on a resolved state in the charset `cs`, into `buf`; the number of bytes, or `None` (EILSEQ is set).
fn wcrtomb_buf(cs: Charset, wc: u32, st: &mut mbstate_t, buf: &mut [u8; MB_LEN_MAX]) -> Option<usize> {
    if wc == 0 {
        // the NUL character: back to the initial state, then a NUL byte (BIG5-HKSCS first writes the character it holds back)
        let produced = if cs == Charset::Other && (st.count & !7) != 0 {
            tomb_cs(cs, st, &wc.to_ne_bytes(), buf).2
        } else {
            buf[0] = 0;
            1
        };
        *st = mbstate_t::default();
        return Some(produced);
    }
    if cs == Charset::Utf8 && st.count & 7 != 0 {
        // a half-read multibyte character is in the state: glibc glues its bytes to the front of
        // the wide character's bytes and encodes the result, keeping the rest of the bytes. It
        // always ends in an error.
        let k = (st.count & 7) as usize;
        if k <= 3 {
            let mut four = [0u8; 4];
            four[..k].copy_from_slice(&st.value.to_le_bytes()[..k]);
            four[k..].copy_from_slice(&wc.to_le_bytes()[..4 - k]);
            let mut e = [0u8; 6];
            if encode_utf8(u32::from_le_bytes(four), &mut e).is_some() {
                let mut v = st.value.to_le_bytes();
                v[..k].copy_from_slice(&wc.to_le_bytes()[4 - k..]);
                st.value = u32::from_le_bytes(v);
                st.count = (st.count & !7) | k as i32;
            }
        }
        errno::set(EILSEQ);
        return None;
    }
    let (status, _, produced) = tomb_cs(cs, st, &wc.to_ne_bytes(), buf);
    if status == Status::Illegal || status == Status::Incomplete {
        errno::set(EILSEQ);
        return None;
    }
    Some(produced)
}

/// # Safety
/// `s` NULL or writable for the bytes of one character.
#[inline(always)]
unsafe fn wcrtomb_in(s: *mut c_char, wc: wchar_t, st: &mut mbstate_t) -> usize {
    let wc = if s.is_null() { 0 } else { wc as u32 };
    let cs = charset();
    if (1..0x80).contains(&wc) && st.count & 7 == 0 && cs != Charset::Other {
        // ASCII in the C and UTF-8 charsets with no half-read character in the state: the byte itself (what the
        // general path below gives, without its buffer)
        // SAFETY: `s` is not NULL (`wc` is not 0) and writable for the character's byte (forwarded contract).
        unsafe { *s = wc as c_char };
        return 1;
    }
    if cs == Charset::Utf8 && st.count & 7 == 0 && wc != 0 {
        // UTF-8 with no half-read character: the encoder alone (the general path gives the same bytes or EILSEQ, and
        // leaves the state alone)
        let mut e = [0u8; 6];
        let Some(n) = encode_utf8(wc, &mut e) else {
            errno::set(EILSEQ);
            return ERR;
        };
        // SAFETY: `s` is not NULL (`wc` is not 0) and writable for the character's bytes (forwarded contract).
        for (d, &b) in unsafe { slice_mut(s.cast::<u8>(), n) }.iter_mut().zip(&e[..n]) {
            *d = b;
        }
        return n;
    }
    let mut buf = [0u8; MB_LEN_MAX];
    let Some(n) = wcrtomb_buf(cs, wc, st, &mut buf) else { return ERR };
    if !s.is_null() {
        // SAFETY: `s` is writable for the character's bytes (forwarded contract).
        unsafe { slice_mut(s.cast::<u8>(), n) }.copy_from_slice(&buf[..n]);
    }
    n
}

/// Write the multibyte form of `wc` to `s` (at least `MB_CUR_MAX` bytes) and return its length, or
/// (size_t)-1 with EILSEQ. With `wc` 0 (or `s` NULL) the state is reset and a NUL byte is written.
///
/// # Safety
/// `s` NULL or writable for `MB_CUR_MAX` bytes; `ps` NULL or a valid state.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_WCRTOMB) };
    // SAFETY: forwarded contract.
    unsafe { wcrtomb_in(s, wc, st) }
}

/// Is `ps` in the initial state (or NULL)?
///
/// # Safety
/// `ps` NULL or a valid state.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsinit(ps: *const mbstate_t) -> c_int {
    // SAFETY: `ps` is NULL or a valid state (forwarded contract).
    c_int::from(unsafe { ps.as_ref() }.is_none_or(|p| p.count == 0))
}

/// Single byte to wide character: the ASCII byte, or WEOF for everything else (in both charsets).
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn btowc(c: c_int) -> wint_t {
    if (0..=0x7f).contains(&c) {
        return c as wint_t;
    }
    // glibc takes any value of a signed or unsigned char as that byte (btowc(-128) reads 0x80); EOF is WEOF
    let c = if (-128..-1).contains(&c) { c & 0xff } else { c };
    if charset() == Charset::Other && (0x80..=0xff).contains(&c) {
        // glibc's GBK module has a one-byte shortcut that knows only ASCII: btowc(0x80) is WEOF there
        // although mbrtowc reads the byte as the euro sign (iconvdata/gbk.c, ONEBYTE_BODY).
        let (name, nl) = codeset_name();
        if c == 0x80 && name[..nl].eq_ignore_ascii_case(b"GBK") {
            return WEOF;
        }
        // a byte that is no character by itself (a lead byte, an invalid one) is WEOF: no conversion needed to know it
        if let Some(set) = single_bytes_cached()
            && set[(c >> 6) as usize] >> (c & 63) & 1 == 0
        {
            return WEOF;
        }
        let mut st = mbstate_t::default();
        let mut w = 0u32;
        let (status, _, produced) = other_towc(&mut st, &[c as u8], core::slice::from_mut(&mut w));
        if produced == 1 && status != Status::Illegal {
            BTOWC_SLOT.store(w, Ordering::Relaxed);
            return w;
        }
        if produced == 0 && status == Status::Empty {
            // CP1255 and its kin: a base letter that waits for a combining mark gives no character. glibc's btowc then
            // returns its uninitialised local `wc`, which holds what the previous successful conversion left in that
            // stack slot (found by the compatibility sweep): the value of the last successful conversion plays that role.
            return BTOWC_SLOT.load(Ordering::Relaxed);
        }
    }
    WEOF
}

/// The single-byte characters of the charset in force, kept for `btowc` (a conversion per call costs about 1,300 instructions, and
/// the regex compiler's collation code asks for all the high bytes): made on the first call after the locale changed.
struct SingleCache {
    key: usize,
    name: [u8; 48],
    name_len: usize,
    set: Option<[u64; 4]>,
    valid: bool,
}

static SINGLE_CACHE: rusty_libc_core::lock::Locked<SingleCache> =
    rusty_libc_core::lock::Locked::new(SingleCache { key: 0, name: [0; 48], name_len: 0, set: None, valid: false });

fn single_bytes_cached() -> Option<[u64; 4]> {
    let key = rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE);
    let (name, nl) = codeset_name();
    SINGLE_CACHE.with(|c| {
        if !(c.valid && c.key == key && c.name_len == nl && c.name[..nl] == name[..nl]) {
            c.set = other_single_bytes();
            c.key = key;
            c.name = name;
            c.name_len = nl;
            c.valid = true;
        }
        c.set
    })
}

/// What glibc's btowc leaves in its stack slot `wc` (see `btowc`).
static BTOWC_SLOT: AtomicU32 = AtomicU32::new(0);

/// Wide character to single byte: the ASCII value, or EOF (-1) for everything else.
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctob(c: wint_t) -> c_int {
    if c <= 0x7f {
        return c as c_int;
    }
    if charset() == Charset::Other {
        let mut b = [0u8; 6];
        if let Some(1) = other_encode(c, &mut b) {
            return i32::from(b[0]);
        }
    }
    -1
}

/// `MB_CUR_MAX`: the longest multibyte character of the current charset (1 for C, 6 for UTF-8).
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_get_mb_cur_max() -> usize {
    mb_cur_max()
}

/// The Rust name of `MB_CUR_MAX`.
#[inline]
pub fn mb_cur_max() -> usize {
    match charset() {
        Charset::C => 1,
        Charset::Utf8 => 6,
        Charset::Other => {
            rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE).map_or(1, |d| (d.word(13) as usize).max(1))
        }
    }
}

// ---- strings ----

/// The C string at `p` with its NUL.
///
/// # Safety
/// `p` is a NUL-terminated string that stays valid for `'a`.
#[inline(always)]
unsafe fn cstr_with_nul<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: forwarded contract.
    let n = unsafe { rusty_libc_core::ffi::cstr_len(p) } + 1;
    // SAFETY: the bytes before the NUL and the NUL are readable.
    unsafe { bytes(p.cast(), n) }
}

/// The bytes of the string at `p` up to and including its NUL, or the first `n + 1` if no NUL comes before byte `n`.
///
/// # Safety
/// `p` is readable for `n + 1` bytes, or up to its NUL if that comes first.
#[inline(always)]
unsafe fn cstr_upto<'a>(p: *const c_char, n: usize) -> &'a [u8] {
    // SAFETY: strnlen reads no further than the first `n` bytes or the NUL.
    let l = unsafe { rusty_libc_mem::strnlen(p, n) };
    // SAFETY: the `l` bytes counted are readable and so is the next one: the NUL when `l < n`, else byte `n`.
    unsafe { bytes(p.cast(), l + 1) }
}

/// The units of a wide string slice as bytes (native order).
#[inline(always)]
fn wide_bytes(s: &[u32]) -> &[u8] {
    // SAFETY: the same memory, `4 * len` initialised bytes, u8 has no alignment; the borrow keeps the lifetime.
    unsafe { core::slice::from_raw_parts(s.as_ptr().cast::<u8>(), s.len() * 4) }
}

/// Count the characters `src` converts to, on a copy of the state, 64 at a time; and the last one converted.
fn count_towc(st: &mbstate_t, src: &[u8]) -> (Status, usize, u32) {
    let mut temp = *st;
    let mut buf = [0u32; 64];
    let (mut pos, mut result, mut last) = (0usize, 0usize, 1u32);
    loop {
        let (s, used, produced) = towc(&mut temp, &src[pos..], &mut buf);
        pos += used;
        result += produced;
        if produced > 0 {
            last = buf[produced - 1];
        }
        if s != Status::Full {
            return (s, result, last);
        }
    }
}

/// `mbsrtowcs(out, &p, out.len(), &state)` from the initial state on the C string whose bytes before the NUL are `src`,
/// in the charset in force: up to `out.len()` characters, the terminating 0 too if it fits; returns how many were written
/// without the 0 (with `out` None: the length). None with errno EILSEQ for an invalid sequence, or one cut short by the
/// end of the string (the characters before it are written). For `wcsftime`'s `%Z`.
pub(crate) fn mbs_no_nul(src: &[u8], out: Option<&mut [u32]>) -> Option<usize> {
    let mut st = mbstate_t::default();
    let (status, r) = match out {
        None => {
            let (s, r, _) = count_towc(&st, src);
            (s, r)
        }
        Some(o) => {
            let (s, _, r) = towc(&mut st, src, o);
            if s == Status::Empty
                && let Some(d) = o.get_mut(r)
            {
                *d = 0;
            }
            (s, r)
        }
    };
    if status == Status::Illegal || status == Status::Incomplete {
        errno::set(EILSEQ);
        return None;
    }
    Some(r)
}

/// `mbsrtowcs` on a resolved state.
///
/// # Safety
/// `src` valid, `*src` a NUL-terminated string; `dst` NULL or writable for `len` characters.
unsafe fn mbsrtowcs_in(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: &mut mbstate_t) -> usize {
    // SAFETY: `src` is valid (forwarded contract).
    let start = unsafe { *src };
    let (status, result);
    if dst.is_null() {
        // count only
        // SAFETY: `*src` is a NUL-terminated string.
        let input = unsafe { cstr_with_nul(start) };
        let (s, mut r, _) = count_towc(ps, input);
        if s == Status::Empty && r > 0 {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        // SAFETY: `dst` writable for `len` characters (forwarded contract).
        let out = unsafe { slice_mut(dst.cast::<u32>(), len.min(MAX_ELEMS)) };
        let mut pos = 0usize; // bytes of the source used
        let mut produced_total = 0usize;
        let mut s = Status::Full;
        while produced_total < out.len() {
            // worst case one input byte per output character; the byte after them is looked at too
            // SAFETY: the string goes on to its NUL, so with no NUL among the next `len_rem` bytes the one after them is
            // still a byte of the string or the NUL.
            let chunk = unsafe { cstr_upto(start.wrapping_add(pos), out.len() - produced_total) };
            let (st2, used, produced) = towc(ps, chunk, &mut out[produced_total..]);
            produced_total += produced;
            pos += used;
            s = st2;
            // stop unless the whole chunk was read and it did not end in the NUL
            if (st2 != Status::Empty && st2 != Status::Incomplete) || used != chunk.len() || chunk[used - 1] == 0 {
                break;
            }
        }
        let mut r = produced_total;
        let mut end = start.wrapping_add(pos);
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        // SAFETY: `src` is valid.
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

/// Convert the multibyte string at `*src` into at most `len` wide characters at `dst`, resuming
/// from `ps`. Stops at the NUL (written, `*src` set to NULL, not counted), at `len` characters
/// (`*src` after the last character converted) or at an invalid sequence (`*src` at its first
/// byte, -1 and EILSEQ). With `dst` NULL it only counts.
///
/// # Safety
/// `src` points to a valid NUL-terminated string; `dst` NULL or writable for `len` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsrtowcs(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBSRTOWCS) };
    // SAFETY: forwarded contract.
    unsafe { mbsrtowcs_in(dst, src, len, st) }
}

/// Like `mbsrtowcs` but reads at most `nmc` bytes (the string need not be terminated).
///
/// # Safety
/// `*src` valid for `nmc` bytes or up to its NUL; `dst` NULL or writable for `len` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbsnrtowcs(dst: *mut wchar_t, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let ps = unsafe { state(ps, &S_MBSNRTOWCS) };
    if nmc == 0 {
        return 0;
    }
    // SAFETY: `src` is valid (forwarded contract).
    let start = unsafe { *src };
    // SAFETY: `*src` is readable for `nmc` bytes or up to its NUL.
    let input = unsafe { cstr_upto(start, nmc - 1) };
    let (status, result);
    if dst.is_null() {
        let (s, mut r, last) = count_towc(ps, input);
        if s == Status::Empty && last == 0 {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        // SAFETY: `dst` writable for `len` characters (forwarded contract).
        let out = unsafe { slice_mut(dst.cast::<u32>(), len.min(MAX_ELEMS)) };
        let (s, used, mut r) = towc(ps, input, out);
        let mut end = start.wrapping_add(used);
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        // SAFETY: `src` is valid.
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

/// Count the bytes the wide characters of `src` convert to, on a copy of the state, 256 at a time (glibc's chunking);
/// `shifted` uses the converter for a state holding a half-read UTF-8 character. Returns the status, the count and the
/// last byte.
fn count_tomb(st: &mbstate_t, src: &[u8], shifted: bool) -> (Status, usize, u8) {
    let mut temp = *st;
    let mut buf = [0u8; 256];
    let (mut pos, mut result, mut last) = (0usize, 0usize, 1u8);
    loop {
        let (s, used, produced) = if shifted {
            tomb_stateful(&mut temp, &src[pos..], &mut buf)
        } else {
            let (s, units, p) = tomb(&mut temp, &src[pos..], &mut buf);
            (s, units * 4, p)
        };
        pos += used;
        result += produced;
        if produced > 0 {
            last = buf[produced - 1];
        }
        if s != Status::Full {
            return (s, result, last);
        }
    }
}

/// The wide-to-multibyte string conversions once the input is known: `input` is the wide characters (terminator
/// included when there is one) as bytes, from `*src`; `dst` NULL only counts. `shifted`: the state holds a half-read
/// UTF-8 character (see `tomb_stateful`).
///
/// # Safety
/// `src` valid and `*src` the start of `input`; `dst` NULL or writable for `len` bytes.
unsafe fn wcsrtombs_core(dst: *mut c_char, src: *mut *const wchar_t, input: &[u8], len: usize, ps: &mut mbstate_t, shifted: bool, by_last: bool) -> usize {
    let (status, result);
    if dst.is_null() {
        let (s, mut r, last) = count_tomb(ps, input, shifted);
        if s == Status::Empty && (if by_last { last == 0 } else { r > 0 }) {
            r -= 1;
        }
        (status, result) = (s, r);
    } else {
        // SAFETY: `dst` writable for `len` bytes (forwarded contract).
        let out = unsafe { slice_mut(dst.cast::<u8>(), len.min(isize::MAX as usize)) };
        let (s, used, mut r) = if shifted {
            tomb_stateful(ps, input, out)
        } else {
            let (s, units, p) = tomb(ps, input, out);
            (s, units * 4, p)
        };
        // a byte position: misaligned after a shifted conversion, as glibc leaves it
        let mut end = input.as_ptr().wrapping_add(used).cast::<wchar_t>();
        if s == Status::Empty && r > 0 && out[r - 1] == 0 {
            end = core::ptr::null();
            r -= 1;
        }
        // SAFETY: `src` is valid.
        unsafe { *src = end };
        (status, result) = (s, r);
    }
    if status == Status::Illegal || (shifted && status == Status::Incomplete) {
        errno::set(EILSEQ);
        return ERR;
    }
    result
}

/// `wcsrtombs` and `wcsnrtombs` on a resolved state: `limit` is `nwc` for wcsnrtombs (`None`: wcsrtombs).
///
/// # Safety
/// `src` valid and `*src` a wide string readable up to its 0 (or `limit` characters); `dst` NULL or writable for `len`
/// bytes.
unsafe fn wcsrtombs_in(dst: *mut c_char, src: *mut *const wchar_t, limit: Option<usize>, len: usize, ps: &mut mbstate_t) -> usize {
    // SAFETY: `src` is valid (forwarded contract).
    let start = unsafe { *src };
    // SAFETY: `*src` is a wide string (forwarded contract).
    let w = unsafe { crate::wcstr::WStr::new(start) };
    // the characters before the 0, or the first `nwc - 1` (wcsnrtombs) or `len` (wcsrtombs with an output) of them
    let count = match limit {
        Some(nwc) => w.len_max(nwc - 1),
        None if dst.is_null() => w.len(),
        None => w.len_max(len),
    };
    // SAFETY: element `count` is readable too: it is the 0 that ended the count, or a character of the string (which goes
    // on past the limit, within the `nwc` characters wcsnrtombs's caller vouches for).
    let input = unsafe { rusty_libc_core::ffi::slice(w.as_ptr().cast::<u32>(), count + 1) };
    let shifted = ps.count & 7 != 0 && charset() == Charset::Utf8;
    if shifted && ps.count & 7 >= 4 {
        // glibc's converter asserts here
        errno::set(EILSEQ);
        return ERR;
    }
    // wcsrtombs's count drops the NUL when anything was counted, the others when the last byte is the NUL (the same
    // thing for every charset here; kept as glibc's code has it)
    let by_last = shifted || limit.is_some();
    // SAFETY: forwarded contract; `input` starts at `*src`.
    unsafe { wcsrtombs_core(dst, src, wide_bytes(input), len, ps, shifted, by_last) }
}

/// Convert the wide string at `*src` into at most `len` bytes at `dst` (only whole characters are
/// written). Stops at the NUL (written, `*src` set to NULL, not counted), when the next character
/// does not fit (`*src` at it), or at an unencodable character (`*src` at it, -1 and EILSEQ). With
/// `dst` NULL it only counts.
///
/// # Safety
/// `src` points to a valid wide string; `dst` NULL or writable for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrtombs(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_WCSRTOMBS) };
    // SAFETY: forwarded contract.
    unsafe { wcsrtombs_in(dst, src, None, len, st) }
}

/// Like `wcsrtombs` but reads at most `nwc` wide characters.
///
/// # Safety
/// `*src` valid for `nwc` characters or up to its 0; `dst` NULL or writable for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnrtombs(dst: *mut c_char, src: *mut *const wchar_t, nwc: usize, len: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_WCSNRTOMBS) };
    if nwc == 0 {
        return 0;
    }
    // SAFETY: forwarded contract.
    unsafe { wcsrtombs_in(dst, src, Some(nwc), len, st) }
}

// ---- stdlib.h: functions with hidden state ----

/// Convert one multibyte character, with a hidden state shared by calls to `mbtowc`. Returns the
/// bytes used (0 for NUL) or -1 (no errno for a character that is only incomplete). `s` NULL
/// resets the state and returns 0 (no charset here has shift states).
///
/// # Safety
/// `s` valid for `n` bytes (or NULL); `pwc` NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbtowc(pwc: *mut wchar_t, s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        // SAFETY: the hidden state (see `Hidden`).
        unsafe { S_MBTOWC.write(mbstate_t::default()) };
        return 0;
    }
    // SAFETY: `s` is readable (forwarded contract; a C caller passes at least the byte it points to).
    if unsafe { *s } == 0 {
        // SAFETY: `pwc` NULL or writable.
        if let Some(w) = unsafe { out(pwc) } {
            *w = 0;
        }
        return 0;
    }
    // SAFETY: the hidden state (see `Hidden`).
    let st = unsafe { state(core::ptr::null_mut(), &S_MBTOWC) };
    // SAFETY: forwarded contract.
    let r = unsafe { mbrtowc_in(pwc, s, n, st) };
    if r > usize::MAX - 2 { -1 } else { r as c_int }
}

/// Number of bytes of the next multibyte character (a fresh state every call), 0 for NUL, -1 if
/// invalid or incomplete. `s` NULL resets and returns 0.
///
/// # Safety
/// `s` valid for `n` bytes (or NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        // SAFETY: the hidden state (see `Hidden`).
        unsafe { S_MBRLEN.write(mbstate_t::default()) };
        return 0;
    }
    // SAFETY: `s` is readable (forwarded contract).
    if unsafe { *s } == 0 {
        return 0;
    }
    let mut st = mbstate_t::default();
    // SAFETY: forwarded contract.
    let r = unsafe { mbrtowc_in(core::ptr::null_mut(), s, n, &mut st) };
    if r > usize::MAX - 2 { -1 } else { r as c_int }
}

/// Multibyte form of `wc` into `s` with a hidden state shared by calls to `wctomb`. `s` NULL resets
/// the state and returns 0.
///
/// # Safety
/// `s` NULL or writable for `MB_CUR_MAX` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: wchar_t) -> c_int {
    if s.is_null() {
        // SAFETY: the hidden state (see `Hidden`).
        unsafe { S_WCTOMB.write(mbstate_t::default()) };
        return 0;
    }
    // SAFETY: the hidden state (see `Hidden`).
    let st = unsafe { state(core::ptr::null_mut(), &S_WCTOMB) };
    // SAFETY: forwarded contract.
    let r = unsafe { wcrtomb_in(s, wc, st) };
    if r == ERR { -1 } else { r as c_int }
}

/// `mbsrtowcs` from the initial state.
///
/// # Safety
/// `s` a valid NUL-terminated string; `pwcs` NULL or writable for `n` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbstowcs(pwcs: *mut wchar_t, s: *const c_char, n: usize) -> usize {
    let mut st = mbstate_t::default();
    let mut p = s;
    // SAFETY: forwarded contract; `p` is a local.
    unsafe { mbsrtowcs_in(pwcs, &mut p, n, &mut st) }
}

/// `wcsrtombs` from the initial state.
///
/// # Safety
/// `pwcs` a valid wide string; `s` NULL or writable for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstombs(s: *mut c_char, pwcs: *const wchar_t, n: usize) -> usize {
    let mut st = mbstate_t::default();
    let mut p = pwcs;
    // SAFETY: forwarded contract; `p` is a local.
    unsafe { wcsrtombs_in(s, &mut p, None, n, &mut st) }
}

// ---- uchar.h ----

/// `mbrtoc32`: the same as `mbrtowc` with its own hidden state (char32_t is the Unicode value).
///
/// # Safety
/// As `mbrtowc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc32(pc32: *mut u32, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBRTOC32) };
    // SAFETY: forwarded contract.
    unsafe { mbrtowc_in(pc32.cast(), s, n, st) }
}

/// `c32rtomb`: the same as `wcrtomb` with its own hidden state.
///
/// # Safety
/// As `wcrtomb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c32rtomb(s: *mut c_char, c32: u32, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_C32RTOMB) };
    // SAFETY: forwarded contract.
    unsafe { wcrtomb_in(s, c32 as wchar_t, st) }
}

const PENDING_BIT: i32 = i32::MIN; // 0x80000000 in `count`

/// Next UTF-16 code unit of the multibyte character at `s`: characters above U+FFFF come out as
/// two calls (the second returns (size_t)-3 and uses no input).
///
/// # Safety
/// As `mbrtowc`; `pc16` NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc16(pc16: *mut u16, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBRTOC16) };
    // SAFETY: `pc16` NULL or writable (forwarded contract).
    let pc16 = unsafe { out(pc16) };
    if st.count & PENDING_BIT != 0 {
        st.count &= i32::MAX;
        if let Some(p) = pc16 {
            *p = st.value as u16;
        }
        st.value = 0;
        return PENDING;
    }
    let (pc16, s, n) = if s.is_null() { (None, c"".as_ptr(), 1) } else { (pc16, s, n) };
    let mut wc: wchar_t = 0;
    // SAFETY: forwarded contract; `wc` is a local.
    let r = unsafe { mbrtowc_in(&mut wc, s, n, st) };
    if r == ERR || r == INCOMPLETE {
        return r;
    }
    let wc = wc as u32;
    if wc < 0x10000 {
        if let Some(p) = pc16 {
            *p = wc as u16;
        }
    } else {
        if let Some(p) = pc16 {
            *p = (0xd7c0 + (wc >> 10)) as u16;
        }
        st.count |= PENDING_BIT;
        st.value = 0xdc00 + (wc & 0x3ff);
    }
    r
}

/// Take UTF-16 code units: a high surrogate is remembered (returns 0, writes nothing), a pair
/// completes it and is written as one character.
///
/// # Safety
/// As `wcrtomb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c16rtomb(s: *mut c_char, c16: u16, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_C16RTOMB) };
    let mut wc = u32::from(c16);
    if s.is_null() {
        st.count &= i32::MAX;
        st.value = 0;
        wc = 0;
    }
    if st.count & PENDING_BIT != 0 {
        st.count &= i32::MAX;
        if (0xdc00..0xe000).contains(&wc) {
            wc = 0x10000 + ((st.value & 0x3ff) << 10) + (wc & 0x3ff);
        } else {
            wc = st.value;
        }
        st.value = 0;
    } else if (0xd800..0xdc00).contains(&wc) {
        st.count |= PENDING_BIT;
        st.value = wc;
        return 0;
    }
    // SAFETY: forwarded contract.
    unsafe { wcrtomb_in(s, wc as wchar_t, st) }
}

/// Next UTF-8 code unit of the multibyte character at `s` (a char8_t is a byte; in the C charset
/// ASCII only): a character longer than one byte takes several calls, the later ones return
/// (size_t)-3 and use no input.
///
/// # Safety
/// As `mbrtowc`; `pc8` NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc8(pc8: *mut u8, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_MBRTOC8) };
    if st.count & PENDING_BIT != 0 {
        // the remaining code units are kept in value's bytes, in reverse; byte 3 is the index of the next
        let mut v = st.value.to_le_bytes();
        let i = usize::from(v[3]);
        // SAFETY: `pc8` NULL or writable (forwarded contract).
        if let Some(p) = unsafe { out(pc8) } {
            *p = v[i.min(3)];
        }
        if i == 0 {
            st.count &= i32::MAX;
            st.value = 0;
        } else {
            v[3] -= 1;
            st.value = u32::from_le_bytes(v);
        }
        return PENDING;
    }
    let (pc8, s, n) = if s.is_null() { (core::ptr::null_mut(), c"".as_ptr(), 1) } else { (pc8, s, n) };
    let mut wc: wchar_t = 0;
    // SAFETY: forwarded contract; `wc` is a local.
    let r = unsafe { mbrtowc_in(&mut wc, s, n, st) };
    if r <= n {
        let wc = wc as u32;
        let mut v = st.value.to_le_bytes();
        let first;
        if wc <= 0x7f {
            first = wc as u8;
        } else if wc <= 0x7ff {
            first = 0xc0 + ((wc >> 6) & 0x1f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 0;
            st.count |= PENDING_BIT;
        } else if wc <= 0xffff {
            first = 0xe0 + ((wc >> 12) & 0x0f) as u8;
            v[1] = 0x80 + ((wc >> 6) & 0x3f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 1;
            st.count |= PENDING_BIT;
        } else if wc <= 0x10ffff {
            first = 0xf0 + ((wc >> 18) & 0x07) as u8;
            v[2] = 0x80 + ((wc >> 12) & 0x3f) as u8;
            v[1] = 0x80 + ((wc >> 6) & 0x3f) as u8;
            v[0] = 0x80 + (wc & 0x3f) as u8;
            v[3] = 2;
            st.count |= PENDING_BIT;
        } else {
            // above U+10FFFF there is no UTF-8 for the standard: nothing is stored or returned
            st.value = u32::from_le_bytes(v);
            return if r == 0 && wc != 0 { PENDING } else { r };
        }
        // SAFETY: `pc8` NULL or writable (forwarded contract).
        if let Some(p) = unsafe { out(pc8) } {
            *p = first;
        }
        st.value = u32::from_le_bytes(v);
    }
    if r == 0 && wc != 0 { PENDING } else { r }
}

/// Take UTF-8 code units one at a time and write the character when it is complete (returns 0
/// until then).
///
/// # Safety
/// As `wcrtomb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn c8rtomb(s: *mut c_char, c8: u8, ps: *mut mbstate_t) -> usize {
    // SAFETY: forwarded contract (the hidden state: see `Hidden`).
    let st = unsafe { state(ps, &S_C8RTOMB) };
    let c8 = if s.is_null() { 0 } else { c8 };
    let wc: u32;
    let mut v = st.value.to_le_bytes();
    if st.count & PENDING_BIT == 0 {
        if (0x80..=0xc1).contains(&c8) || c8 >= 0xf5 {
            errno::set(EILSEQ);
            return ERR;
        }
        if c8 >= 0xc2 {
            st.count |= PENDING_BIT;
            v[0] = c8;
            v[3] = 1;
            st.value = u32::from_le_bytes(v);
            return 0;
        }
        wc = u32::from(c8);
    } else {
        let cu1 = v[0];
        if v[3] == 1 {
            if !(0x80..=0xbf).contains(&c8) || (cu1 == 0xe0 && c8 < 0xa0) || (cu1 == 0xed && c8 > 0x9f) || (cu1 == 0xf0 && c8 < 0x90) || (cu1 == 0xf4 && c8 > 0x8f) {
                errno::set(EILSEQ);
                return ERR;
            }
            if cu1 >= 0xe0 {
                v[1] = c8;
                v[3] += 1;
                st.value = u32::from_le_bytes(v);
                return 0;
            }
            wc = (u32::from(cu1 & 0x1f) << 6) + u32::from(c8 & 0x3f);
        } else {
            let cu2 = v[1];
            if !(0x80..=0xbf).contains(&c8) {
                errno::set(EILSEQ);
                return ERR;
            }
            if v[3] == 2 && cu1 >= 0xf0 {
                v[2] = c8;
                v[3] += 1;
                st.value = u32::from_le_bytes(v);
                return 0;
            }
            if cu1 < 0xf0 {
                wc = (u32::from(cu1 & 0x0f) << 12) + (u32::from(cu2 & 0x3f) << 6) + u32::from(c8 & 0x3f);
            } else {
                let cu3 = v[2];
                wc = (u32::from(cu1 & 0x07) << 18) + (u32::from(cu2 & 0x3f) << 12) + (u32::from(cu3 & 0x3f) << 6) + u32::from(c8 & 0x3f);
            }
        }
        st.count &= i32::MAX;
        st.value = 0;
    }
    // SAFETY: forwarded contract.
    unsafe { wcrtomb_in(s, wc as wchar_t, st) }
}

// ---- Rust API ----

/// What [`decode`] found at the start of a byte slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// A character and the number of bytes it took.
    Char(u32, usize),
    /// The bytes are the start of a valid character; more are needed.
    Incomplete,
    /// Not valid in the current charset (EILSEQ).
    Invalid,
}

fn decoded(status: Status, used: usize, produced: usize, w: u32) -> Decoded {
    match status {
        Status::Empty | Status::Full if produced == 1 => Decoded::Char(w, used),
        Status::Incomplete => Decoded::Incomplete,
        _ => Decoded::Invalid,
    }
}

/// Decode the first character of `bytes` in the current charset, with an explicit state (use
/// `mbstate_t::default()` to start). Like `mbrtowc`, but a NUL byte is `Char(0, 1)`.
pub fn decode_char(bytes: &[u8], state: &mut mbstate_t) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut w = 0u32;
    let (status, used, produced) = towc(state, bytes, core::slice::from_mut(&mut w));
    decoded(status, used, produced, w)
}

/// Like [`decode_char`] but in an explicit charset with a fresh state (what a stream that fixed its
/// charset at its first wide operation uses).
pub fn decode_cs(cs: Charset, bytes: &[u8]) -> Decoded {
    if bytes.is_empty() {
        return Decoded::Incomplete;
    }
    let mut st = mbstate_t::default();
    let mut w = 0u32;
    let (status, used, produced) = towc_cs(cs, &mut st, bytes, core::slice::from_mut(&mut w));
    decoded(status, used, produced, w)
}

/// Like [`encode_char`] but in an explicit charset.
pub fn encode_cs(cs: Charset, wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    match cs {
        Charset::Other => other_encode(wc, out),
        Charset::Utf8 => encode_utf8(wc, out),
        Charset::C => {
            out[0] = wc as u8;
            if wc <= 0x7f { Some(1) } else { None }
        }
    }
}

/// Encode `wc` in the current charset into `out`; the number of bytes, or `None` (EILSEQ).
pub fn encode_char(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    encode_cs(charset(), wc, out)
}

/// Convert the multibyte text `src` (to its first NUL or its end) to wide characters in `dst`
/// (a NUL is added if there is room). Returns the number of characters, or `Err(offset)` of the
/// first byte that cannot be converted. Stops silently when `dst` is full.
pub fn to_wide(src: &[u8], dst: &mut [u32]) -> Result<usize, usize> {
    let mut st = mbstate_t::default();
    let (mut pos, mut n) = (0usize, 0usize);
    while pos < src.len() && src[pos] != 0 && n < dst.len() {
        match decode_char(&src[pos..], &mut st) {
            Decoded::Char(c, used) => {
                dst[n] = c;
                n += 1;
                pos += used;
            }
            _ => return Err(pos),
        }
    }
    if n < dst.len() {
        dst[n] = 0;
    }
    Ok(n)
}

/// Convert the wide text `src` (to its first 0 or its end) to multibyte in `dst` (a NUL byte is
/// added if there is room); only whole characters are written. Returns the number of bytes, or
/// `Err(index)` of the first character that cannot be converted.
pub fn to_multibyte(src: &[u32], dst: &mut [u8]) -> Result<usize, usize> {
    let mut n = 0usize;
    for (i, &c) in src.iter().enumerate() {
        if c == 0 {
            break;
        }
        let mut b = [0u8; 6];
        let Some(l) = encode_char(c, &mut b) else { return Err(i) };
        if n + l > dst.len() {
            break;
        }
        dst[n..n + l].copy_from_slice(&b[..l]);
        n += l;
    }
    if n < dst.len() {
        dst[n] = 0;
    }
    Ok(n)
}

#[cfg(test)]
mod tests;
