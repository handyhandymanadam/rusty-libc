//! //TRANSLIT: glibc's `__gconv_transliterate`.
//!
//! When the target charset cannot represent a character, glibc looks it up in the transliteration table of
//! the calling thread's LC_CTYPE (a sorted list of source strings, each with a list of replacement strings to try in
//! order), then in the locale's ignore ranges, then uses the locale's default replacement. In the "C" and
//! "POSIX" locales the tables are the ones in `translit_tables.rs`, generated from the host by
//! `tools/gen_translit.py` (they are what `nl_langinfo(_NL_CTYPE_TRANSLIT_*)` returns in the C locale); in any
//! other locale they come from the locale's own LC_CTYPE data, items 61-69 (so `a` for `ä` in en_US.UTF-8, `ae`
//! in de_DE.UTF-8). A replacement counts only if the target can represent all of it; a replacement that is
//! representable but does not fit in the remaining output ends the conversion with "output full"
//! (glibc does not try the next, shorter, replacement then).
use crate::engine::{EBody, St, enc_loop};
use crate::translit_tables::{DEFAULT_MISSING, FROM_IDX, FROM_TBL, TO_IDX, TO_TBL};
use crate::gconv_abi::{EMPTY_INPUT, FULL_OUTPUT, ILLEGAL_INPUT, INCOMPLETE_INPUT, OK};
use core::ffi::c_int;
use rusty_libc_core::ffi::slice;

/// The tables in force: the built-in ones of the C locale, or those of a locale's LC_CTYPE data.
enum Tab {
    C,
    Locale(Loc),
}

/// A locale's `_NL_CTYPE_TRANSLIT_*` items (published locale data lives for the life of the program, aligned to 4 bytes and
/// never written). Kept as pointers read one entry at a time: with slices (bounds checks in the binary search) a //TRANSLIT
/// conversion in the C locale took 1.12x the time (bench, 7 interleaved pinned runs), because the extra code in the shared
/// search loop changed how the C-table path compiles.
struct Loc {
    size: usize,
    src_idx: *const u32,
    src_tbl: *const u32,
    to_idx: *const u32,
    to_tbl: *const u32,
    default_missing: *const u32,
    default_missing_len: usize,
    ignore: *const u32,
    ignore_len: usize,
}

impl Tab {
    /// The tables of the calling thread's LC_CTYPE.
    fn current() -> Tab {
        let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
            return Tab::C;
        };
        if d.flags() & rusty_libc_core::locale::F_BUILTIN_C != 0 || d.nstrings() < 70 {
            return Tab::C;
        }
        let wp = |i: usize| d.cstr(i).cast::<u32>();
        Tab::Locale(Loc {
            size: d.word(61) as usize,
            src_idx: wp(62),
            src_tbl: wp(63),
            to_idx: wp(64),
            to_tbl: wp(65),
            default_missing: wp(67),
            default_missing_len: d.word(66) as usize,
            ignore: wp(69),
            ignore_len: d.word(68) as usize,
        })
    }

    fn size(&self) -> usize {
        match self {
            Tab::C => FROM_IDX.len(),
            Tab::Locale(l) => l.size,
        }
    }

    fn src_idx(&self, i: usize) -> usize {
        match self {
            Tab::C => FROM_IDX[i] as usize,
            Tab::Locale(l) => {
                let p = l.src_idx.wrapping_add(i);
                // SAFETY: the binary search keeps `i < size`, and item 62 has `size` (item 61) entries (glibc's layout).
                unsafe { *p as usize }
            }
        }
    }

    fn to_idx(&self, i: usize) -> usize {
        match self {
            Tab::C => TO_IDX[i] as usize,
            Tab::Locale(l) => {
                let p = l.to_idx.wrapping_add(i);
                // SAFETY: as `src_idx` (item 64 also has `size` entries).
                unsafe { *p as usize }
            }
        }
    }

    fn src_tbl(&self, i: usize) -> u32 {
        match self {
            Tab::C => FROM_TBL[i],
            Tab::Locale(l) => {
                let p = l.src_tbl.wrapping_add(i);
                // SAFETY: `i` is an index from `src_idx` plus a position inside that NUL-terminated source string, at most its
                // NUL (the search stops there), so `p` is inside the table, which is aligned and lives forever.
                unsafe { *p }
            }
        }
    }

    fn to_tbl(&self, i: usize) -> u32 {
        match self {
            Tab::C => TO_TBL[i],
            Tab::Locale(l) => {
                let p = l.to_tbl.wrapping_add(i);
                // SAFETY: `i` is an index from `to_idx` plus a position inside that entry's NUL-terminated replacement strings
                // (the loops stop at each NUL and at the empty string that ends the list), so `p` is inside the table. (A
                // volatile read: the loop that measures a replacement string is otherwise turned into a call of `wcslen`,
                // which the Rust runtime does not have.)
                unsafe { core::ptr::read_volatile(p) }
            }
        }
    }

    /// The replacement strings `len` characters long starting at `idx`.
    fn to_slice(&self, idx: usize, len: usize) -> &'static [u32] {
        match self {
            Tab::C => &TO_TBL[idx..idx + len],
            Tab::Locale(l) => {
                let p = l.to_tbl.wrapping_add(idx);
                // SAFETY: the replacement at `idx` was found NUL-terminated after `len` characters (`to_tbl`), so those `len`
                // entries are inside the table, aligned, and never written.
                unsafe { slice(p, len) }
            }
        }
    }

    fn default_missing(&self) -> &'static [u32] {
        match self {
            Tab::C => &DEFAULT_MISSING,
            Tab::Locale(l) => {
                // SAFETY: item 67 holds item 66 characters (glibc's layout).
                unsafe { slice(l.default_missing, l.default_missing_len) }
            }
        }
    }

    /// Is `c` in one of the locale's ignore ranges (first, last, step triples; the C locale has none)?
    fn ignored(&self, c: u32) -> bool {
        let Tab::Locale(l) = self else { return false };
        // SAFETY: item 69 holds item 68 triples (glibc's layout).
        let ignore = unsafe { slice(l.ignore, 3 * l.ignore_len) };
        for &[lo, hi, step] in ignore.as_chunks::<3>().0 {
            if lo <= c && c <= hi && step != 0 && (c - lo).is_multiple_of(step) {
                return true;
            } else if c < lo {
                break;
            }
        }
        false
    }
}

/// Try to transliterate the character at the front of `inp` (the rest of the current chunk).
/// On success returns `St::Ok` with `used` characters consumed and `wrote` bytes written.
#[allow(clippy::too_many_arguments)]
pub fn transliterate<F: FnMut(&[u32], &mut [u8]) -> EBody>(
    flags: u32,
    inp: &[u32],
    out: &mut [u8],
    used: &mut usize,
    wrote: &mut usize,
    irr: &mut usize,
    min_out: usize,
    tags: bool,
    prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>,
    body: &mut F,
) -> St {
    let tab = Tab::current();
    let size = tab.size();
    let end = inp.len();
    if end == 0 {
        return St::Empty;
    }
    let mut low = 0usize;
    let mut high = size;
    while low < high {
        let med = (low + high) / 2;
        let idx = tab.src_idx(med);
        let mut cnt = 0usize;
        loop {
            if tab.src_tbl(idx + cnt) != inp[cnt] {
                break;
            }
            cnt += 1;
            if !(tab.src_tbl(idx + cnt) != 0 && cnt < end) {
                break;
            }
        }
        if cnt > 0 && tab.src_tbl(idx + cnt) == 0 {
            // Found a matching source string: try its replacements in order.
            let mut idx2 = tab.to_idx(med);
            loop {
                let mut len = 0usize;
                while tab.to_tbl(idx2 + len) != 0 {
                    len += 1;
                }
                let alt = tab.to_slice(idx2, len);
                let mut ai = 0usize;
                let mut ao = 0usize;
                let mut res = match prep(out, &mut ao) {
                    Some(st) => st,
                    None => enc_loop(flags, alt, &mut ai, out, &mut ao, None, min_out, tags, prep, crate::engine::no_fast_enc, body),
                };
                if res != St::Illegal {
                    if res == St::Empty {
                        *used = cnt;
                        *irr += 1;
                        res = St::Ok;
                    }
                    if res != St::Full {
                        *wrote = ao;
                    }
                    return res;
                }
                idx2 += len + 1;
                if tab.to_tbl(idx2) == 0 {
                    break;
                }
            }
        } else if cnt > 0 && cnt == end {
            // The input is a prefix of an entry: glibc asks for more input.
            return St::Incomplete;
        }
        if cnt >= end || tab.src_tbl(idx + cnt) < inp[cnt] {
            low = med + 1;
        } else {
            high = med;
        }
    }
    // A character the locale says to ignore is dropped (it counts as an irreversible conversion).
    if tab.ignored(inp[0]) {
        *used = 1;
        *wrote = 0;
        *irr += 1;
        return St::Ok;
    }
    // Last chance: the default replacement.
    let default = tab.default_missing();
    if !default.is_empty() {
        let mut ai = 0usize;
        let mut ao = 0usize;
        let mut res = match prep(out, &mut ao) {
            Some(st) => st,
            None => enc_loop(flags, default, &mut ai, out, &mut ao, None, min_out, tags, prep, crate::engine::no_fast_enc, body),
        };
        if res != St::Illegal {
            if res == St::Empty {
                *irr += 1;
                *used = 1;
                res = St::Ok;
            }
            *wrote = ao;
            return res;
        }
    }
    St::Illegal
}

/// What a wide stream writes for one character its charset cannot represent (`translit_one`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Replacement {
    /// This text (every character of it writable).
    Text(&'static [u32]),
    /// Nothing: the locale says to ignore the character.
    Ignore,
    /// No replacement can be written (glibc's conversion then fails).
    Illegal,
}

/// glibc's `__gconv_transliterate` as a wide stream's conversion calls it for the single character `wc` (an unbuffered
/// stream converts one character at a time; the replacements are not transliterated again, as glibc's inner conversion
/// gets no `irreversible` counter): the first replacement in the calling thread's LC_CTYPE table (the built-in tables in
/// the C locale) that `writable` accepts, else nothing for a character in an ignore range, else the default replacement
/// if `writable` accepts it. A character that only starts a longer source string is not matched (glibc: incomplete
/// input, which fails the write).
pub fn translit_one(wc: u32, writable: &mut dyn FnMut(&[u32]) -> bool) -> Replacement {
    let tab = Tab::current();
    let mut low = 0usize;
    let mut high = tab.size();
    while low < high {
        let med = (low + high) / 2;
        let idx = tab.src_idx(med);
        let first = tab.src_tbl(idx);
        if first == wc {
            if tab.src_tbl(idx + 1) != 0 {
                return Replacement::Illegal; // a prefix of a longer source string
            }
            let mut idx2 = tab.to_idx(med);
            loop {
                let mut len = 0usize;
                while tab.to_tbl(idx2 + len) != 0 {
                    len += 1;
                }
                let alt = tab.to_slice(idx2, len);
                if writable(alt) {
                    return Replacement::Text(alt);
                }
                idx2 += len + 1;
                if tab.to_tbl(idx2) == 0 {
                    break;
                }
            }
            // (glibc keeps searching after a source whose replacements all failed: no other entry has the same source)
            break;
        }
        if first < wc {
            low = med + 1;
        } else {
            high = med;
        }
    }
    if tab.ignored(wc) {
        return Replacement::Ignore;
    }
    let default = tab.default_missing();
    if !default.is_empty() && writable(default) {
        return Replacement::Text(default);
    }
    Replacement::Illegal
}

/// What [`transliterate_raw`] decided.
pub(crate) struct Transliterated {
    /// The `__GCONV_*` status to return.
    pub status: c_int,
    /// Input bytes used up.
    pub consumed: usize,
    /// Irreversible conversions made.
    pub irreversible: usize,
    /// Is the output the last attempt wrote to be kept?
    pub commit: bool,
}

/// glibc's `__gconv_transliterate` (iconv/gconv_trans.c) on the raw input: the UCS-4 text at the front of `input` is looked up
/// in the calling thread's table, then in the locale's ignore ranges, then the default replacement is tried, as in
/// [`transliterate`]. `attempt` converts one replacement (host-order UCS-4 characters) with the calling step's own conversion
/// function and returns its status; it starts from the output position it was given each time, so the last attempt's output is
/// the one to keep when the result says `commit`. `None`: nothing worked (the step reports illegal input).
pub(crate) fn transliterate_raw(
    input: &[u8],
    attempt: &mut dyn FnMut(&[u32]) -> c_int,
) -> Option<Transliterated> {
    let tab = Tab::current();
    let size = tab.size();
    let avail = input.len() / 4;
    let word = |i: usize| {
        u32::from_ne_bytes([
            input[4 * i],
            input[4 * i + 1],
            input[4 * i + 2],
            input[4 * i + 3],
        ])
    };
    // not even one whole character
    let short = |len: usize| {
        Some(Transliterated {
            status: if len == 0 {
                EMPTY_INPUT
            } else {
                INCOMPLETE_INPUT
            },
            consumed: 0,
            irreversible: 0,
            commit: false,
        })
    };
    let finish = |res: c_int, chars: usize, commit: bool| {
        let (status, consumed, irreversible) = if res == EMPTY_INPUT {
            (OK, chars * 4, 1)
        } else {
            (res, 0, 0)
        };
        Some(Transliterated {
            status,
            consumed,
            irreversible,
            commit,
        })
    };
    if size != 0 {
        if avail == 0 {
            return short(input.len());
        }
        let (mut low, mut high) = (0usize, size);
        while low < high {
            let med = (low + high) / 2;
            let idx = tab.src_idx(med);
            let mut cnt = 0usize;
            loop {
                if tab.src_tbl(idx + cnt) != word(cnt) {
                    break;
                }
                cnt += 1;
                if !(tab.src_tbl(idx + cnt) != 0 && cnt < avail) {
                    break;
                }
            }
            if cnt > 0 && tab.src_tbl(idx + cnt) == 0 {
                // a matching source string: try its replacements in order
                let mut idx2 = tab.to_idx(med);
                loop {
                    let mut len = 0usize;
                    while tab.to_tbl(idx2 + len) != 0 {
                        len += 1;
                    }
                    let res = attempt(tab.to_slice(idx2, len));
                    if res != ILLEGAL_INPUT {
                        return finish(res, cnt, res != FULL_OUTPUT);
                    }
                    idx2 += len + 1;
                    if tab.to_tbl(idx2) == 0 {
                        break;
                    }
                }
            } else if cnt > 0 && cnt == avail {
                // the input is a prefix of a source string: more input could match
                return Some(Transliterated {
                    status: INCOMPLETE_INPUT,
                    consumed: 0,
                    irreversible: 0,
                    commit: false,
                });
            }
            if cnt >= avail || tab.src_tbl(idx + cnt) < word(cnt) {
                low = med + 1;
            } else {
                high = med;
            }
        }
    }
    // the character may be one the locale says to ignore
    if let Tab::Locale(l) = &tab
        && l.ignore_len != 0
    {
        if avail == 0 {
            return short(input.len());
        }
        if tab.ignored(word(0)) {
            return Some(Transliterated {
                status: OK,
                consumed: 4,
                irreversible: 1,
                commit: false,
            });
        }
    }
    // one last chance: the default replacement
    let default = tab.default_missing();
    if !default.is_empty() {
        if avail == 0 {
            return short(input.len());
        }
        let res = attempt(default);
        if res != ILLEGAL_INPUT {
            return finish(res, 1, true);
        }
    }
    None
}
