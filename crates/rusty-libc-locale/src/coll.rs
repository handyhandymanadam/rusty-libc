//! Read access to the collation tables of the locale in force for the pattern matchers (fnmatch, regex): the
//! collation sequence of a character (`_NL_COLLATE_COLLSEQMB` / `COLLSEQWC`), collating symbols, and the first-pass
//! weights of a character (what glibc's `findidx` gives; two characters are in one equivalence class when these
//! are equal). Layouts follow glibc's `locale/coll-lookup.c`, `locale/weight.h` and `posix/regcomp.c` /
//! `posix/fnmatch_loop.c` (LGPL, read as reference).
//!
//! The tables are slices of the locale image, bounded by the end of the image (the format stores no table sizes); a read
//! past the end gives 0.
use crate::data::{as_i32, as_u32, item};
use crate::mem::rd32;


/// The collation data of the locale in force, as glibc's `parse_bracket_exp` reads it at the
/// start of every bracket expression: the number of sorting rules, the byte table
/// (`_NL_COLLATE_COLLSEQMB`), the wide-character table (`_NL_COLLATE_COLLSEQWC`, a three-level
/// table read with `__collseq_table_lookup`) and the collating-symbol table.
///
/// The data comes straight from `rusty_libc_core::locale` (where rusty-libc-locale publishes the loaded
/// categories), so the regex crate needs no dependency on rusty-libc-locale and no hook.
#[derive(Clone, Copy)]
pub struct Collation {
    nrules: u32,
    /// `_NL_COLLATE_COLLSEQMB` (256 bytes), None for the built-in data.
    seqmb: Option<&'static [u8]>,
    /// `_NL_COLLATE_COLLSEQWC` (byte offsets inside it).
    seqwc: Option<&'static [u8]>,
    symb_size: i32,
    symb: &'static [i32],
    extra: &'static [u8],
}

const NL_NRULES: usize = 0;
const NL_SYMB_HASH_SIZEMB: usize = 13;
const NL_SYMB_TABLEMB: usize = 14;
const NL_SYMB_EXTRAMB: usize = 15;
const NL_COLLSEQMB: usize = 16;
const NL_COLLSEQWC: usize = 17;

/// The first and last index of the children (each `1 << shift` characters, `n` of them) of the block that starts at `base`
/// that hold characters of `lo..=hi`; `None` when none does.
#[inline]
pub(crate) fn child_span(base: u32, shift: u32, n: u32, lo: u32, hi: u32) -> Option<(u32, u32)> {
    if n == 0 || hi < base {
        return None;
    }
    let first = if lo > base { (lo - base).checked_shr(shift).unwrap_or(0) } else { 0 };
    let last = (hi - base).checked_shr(shift).unwrap_or(0).min(n - 1);
    if first > last { None } else { Some((first, last)) }
}

/// `UINT_MAX`: "no collation sequence value".
pub const NO_SEQ: u32 = u32::MAX;

/// Byte `i` of `b`, 0 past its end.
#[inline(always)]
fn byte(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

impl Collation {
    /// The data of the calling thread's locale (no data: the built-in C locale, byte order).
    pub fn current() -> Collation {
        let none = Collation { nrules: 0, seqmb: None, seqwc: None, symb_size: 0, symb: &[], extra: &[] };
        let Some(d) = crate::data::current_cat(rusty_libc_core::locale::LC_COLLATE) else { return none };
        // the built-in C and C.UTF-8 data carry no byte table: byte order
        if (d.nstrings() as usize) <= NL_COLLSEQWC || d.flags() & rusty_libc_core::locale::F_BUILTIN_C != 0 {
            return none;
        }
        let nrules = d.word(NL_NRULES);
        let mut c = Collation { nrules, seqmb: Some(item(d, NL_COLLSEQMB)), ..none };
        if nrules != 0 {
            c.seqwc = Some(item(d, NL_COLLSEQWC));
            c.symb_size = d.word(NL_SYMB_HASH_SIZEMB) as i32;
            c.symb = as_i32(item(d, NL_SYMB_TABLEMB));
            c.extra = item(d, NL_SYMB_EXTRAMB);
        }
        c
    }

    /// Number of sorting rules (0: the locale has no collation data, characters sort by value).
    pub fn nrules(&self) -> u32 {
        self.nrules
    }

    /// glibc's `__collseq_table_lookup`.
    pub fn seq_wc(&self, wc: u32) -> u32 {
        let tb = self.seqwc.unwrap_or(&[]);
        // the table has the layout locale/coll-lookup.c reads; every offset comes from it. The five header words are
        // read with one length check (a regex bracket in an EUC locale looks up every character of the charset).
        let Some(h) = tb.first_chunk::<20>() else { return NO_SEQ };
        let t = |k: usize| u32::from_ne_bytes([h[4 * k], h[4 * k + 1], h[4 * k + 2], h[4 * k + 3]]);
        let shift1 = t(0);
        let index1 = wc.checked_shr(shift1).unwrap_or(0);
        let bound = t(1);
        if index1 < bound {
            let lookup1 = rd32(tb, 4 * (5 + index1 as usize));
            if lookup1 != 0 {
                let shift2 = t(2);
                let mask2 = t(3);
                let index2 = wc.checked_shr(shift2).unwrap_or(0) & mask2;
                let lookup2 = rd32(tb, lookup1 as usize + 4 * index2 as usize);
                if lookup2 != 0 {
                    let mask3 = t(4);
                    return rd32(tb, lookup2 as usize + 4 * (wc & mask3) as usize);
                }
            }
        }
        NO_SEQ
    }

    /// The collation sequence value of the single byte `ch` read as a character of the locale
    /// (`__btowc` first when the locale has rules); `NO_SEQ` when it is not a character.
    /// True when every byte's sequence value is the byte itself (no rules, no byte table: the C locale).
    #[inline]
    pub fn is_byte_identity(&self) -> bool {
        self.nrules == 0 && self.seqmb.is_none()
    }

    pub fn seq_of_byte(&self, ch: u8) -> u32 {
        if self.nrules == 0 {
            return self.seq_mb(ch);
        }
        // SAFETY: btowc takes any int (its contract is "always safe to call").
        let wc = unsafe { rusty_libc_wchar::mbyte::btowc(i32::from(ch)) };
        self.seq_wc(wc)
    }

    /// `collseqmb[ch]`: the byte table, which glibc reads (not the wide table) for a collating
    /// symbol of one character that the locale does not define.
    pub fn seq_mb(&self, ch: u8) -> u32 {
        match self.seqmb {
            None => u32::from(ch),
            // COLLSEQMB is a table of 256 bytes
            Some(t) => u32::from(byte(t, ch as usize)),
        }
    }

    /// The entries of the collating-symbol table that are in use: the offset of each one's data in `extra`.
    fn entries(&self) -> impl Iterator<Item = usize> + '_ {
        // (pairs of words: hash value, offset; a table that ends early ends the walk, where glibc would read past it)
        self.symb.as_chunks::<2>().0.iter().take(self.symb_size.max(0) as usize).filter(|e| e[0] != 0).map(|e| e[1] as usize)
    }

    /// glibc's `seek_collating_symbol_entry` plus the sequence value of the entry: the value of the
    /// collating symbol `name`, if the locale defines one with that name.
    pub fn symbol_seq(&self, name: &[u8]) -> Option<u32> {
        if self.nrules == 0 {
            return None;
        }
        // the symbol table and its extra data have the layout regcomp.c reads
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize;
            let len = byte(ex, idx) as usize;
            if len == name.len() && ex.get(idx + 1..idx + 1 + len) == Some(name) {
                // skip the byte sequence, align, skip the mb sequence value and the wide sequence
                idx += 1 + len;
                idx = (idx + 3) & !3;
                idx += 4;
                idx += 4 * (1 + rd32(ex, idx) as usize);
                return Some(rd32(ex, idx));
            }
        }
        None
    }
}

impl Collation {
    /// fnmatch's lookup of a collating symbol `[.xy.]`: the table entry whose *byte sequence* (not its name) is
    /// `elem`, as `(collation sequence value, the sequence)`.
    pub fn symbol_by_bytes(&self, elem: &[u8]) -> Option<(u32, &'static [u8])> {
        if self.nrules == 0 {
            return None;
        }
        // the symbol table and its extra data have the layout fnmatch_loop.c reads
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize; // skip the name
            let len = byte(ex, idx) as usize;
            if len == elem.len()
                && let Some(bytes) = ex.get(idx + 1..idx + 1 + len)
                && bytes == elem
            {
                idx += 1 + len;
                idx = (idx + 3) & !3;
                return Some((rd32(ex, idx), bytes));
            }
        }
        None
    }

    /// Wide form of [`Collation::symbol_by_bytes`]: matched against the entry's wide-character sequence.
    pub fn symbol_by_wide(&self, elem: &[u32]) -> Option<(u32, &'static [u32])> {
        if self.nrules == 0 {
            return None;
        }
        // as above; the wide sequence follows the byte sequence, 4-byte aligned, after one word
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize; // the name
            idx += 1 + byte(ex, idx) as usize; // the byte sequence
            idx = (idx + 3) & !3;
            let w = idx + 4;
            let len = rd32(ex, w) as usize;
            if len == elem.len() && elem.iter().enumerate().all(|(i, &x)| rd32(ex, w + 4 * (1 + i)) == x) {
                let seq = rd32(ex, w + 4 * (1 + len));
                let words = ex.get(w + 4..).map_or(&[][..], as_u32);
                return Some((seq, words.get(..len).unwrap_or(&[])));
            }
        }
        None
    }
}

impl Collation {
    /// regcomp's `[.name.]`: glibc's `seek_collating_symbol_entry` skips the entry's first string (its name in the
    /// locale source) and compares `name` with the SECOND one, the byte sequence of the element: `[.ch.]` names the
    /// element whose characters are "ch". Returns that sequence.
    pub fn symbol_elem(&self, name: &[u8]) -> Option<&'static [u8]> {
        self.symbol_by_bytes(name).map(|(_, bytes)| bytes)
    }
}

impl Collation {
    /// Calls `f(bytes, sequence value)` for every entry of the collating-symbol table: the byte sequence of the element (a
    /// character or the characters of a contraction such as Czech "ch") and its collation sequence value, the one glibc's
    /// `find_collation_sequence_value` returns (after the entry's wide-character sequence).
    pub fn each_element(&self, f: &mut dyn FnMut(&'static [u8], u32)) {
        if self.nrules == 0 {
            return;
        }
        // the symbol table and its extra data have the layout regexec.c's find_collation_sequence_value reads
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize; // the name
            let len = byte(ex, idx) as usize;
            let bytes = ex.get(idx + 1..idx + 1 + len).unwrap_or(&[]);
            idx += 1 + len;
            idx = (idx + 3) & !3;
            idx += 4; // the multibyte sequence value
            idx += 4 * (1 + rd32(ex, idx) as usize); // the wide sequence
            f(bytes, rd32(ex, idx));
        }
    }

    /// Calls `emit(lo, hi)` for every maximal run of characters from 0x80 up whose collation sequence value lies in
    /// `lo_seq..=hi_seq`, in increasing order (what a range `[a-z]` of a bracket expression means for the wide
    /// characters of a locale with collation rules). Walks the three-level table, so it costs time in proportion to
    /// the characters the table knows. Nothing without rules.
    pub fn seq_runs(&self, lo_seq: u32, hi_seq: u32, emit: &mut dyn FnMut(u32, u32)) {
        self.seq_runs_in(lo_seq, hi_seq, 0, u32::MAX, emit)
    }

    /// `seq_runs` for the characters of `lo..=hi` only (cut to that window; only the parts of the table that can hold them
    /// are read).
    pub fn seq_runs_in(&self, lo_seq: u32, hi_seq: u32, lo: u32, hi: u32, emit: &mut dyn FnMut(u32, u32)) {
        let Some(tb) = self.seqwc else { return };
        let lo = lo.max(0x80);
        if lo > hi {
            return;
        }
        if self.nrules == 0 {
            return;
        }
        let t = |k: usize| rd32(tb, 4 * k);
        let mut cur: Option<(u32, u32)> = None;
        fn put(emit: &mut dyn FnMut(u32, u32), cur: &mut Option<(u32, u32)>, wc: u32) {
            match cur {
                Some((_, last)) if *last + 1 == wc => *last = wc,
                _ => {
                    if let Some((a, b)) = cur.take() {
                        emit(a, b);
                    }
                    *cur = Some((wc, wc));
                }
            }
        }
        // the table has the layout `seq_wc` reads (coll-lookup.c); every offset comes from it
        let (shift1, bound1, shift2, mask2, mask3) = (t(0), t(1), t(2), t(3), t(4));
        let Some((f1, e1)) = child_span(0, shift1, bound1, lo, hi) else { return };
        for i1 in f1..=e1 {
            let l1 = t(5 + i1 as usize);
            if l1 == 0 {
                continue;
            }
            let Some((f2, e2)) = child_span(i1 << shift1, shift2, mask2.wrapping_add(1), lo, hi) else { continue };
            for i2 in f2..=e2 {
                let l2 = rd32(tb, l1 as usize + 4 * i2 as usize);
                if l2 == 0 {
                    continue;
                }
                let base = (i1 << shift1) + (i2 << shift2);
                // the third-level block: mask3 + 1 words at byte offset l2 (any alignment)
                let words = (mask3 as usize).wrapping_add(1);
                let Some(lvl3) = tb.get(l2 as usize..(l2 as usize).saturating_add(words.saturating_mul(4))) else { continue };
                let Some((f3, e3)) = child_span(base, 0, mask3.wrapping_add(1), lo, hi) else { continue };
                for (i3, wbytes) in lvl3[4 * f3 as usize..(4 * (e3 as usize + 1)).min(lvl3.len())].as_chunks::<4>().0.iter().enumerate() {
                    let i3 = i3 + f3 as usize;
                    let v = u32::from_ne_bytes(*wbytes);
                    let wc = base + i3 as u32;
                    if v != NO_SEQ && lo_seq <= v && v <= hi_seq && wc >= 0x80 {
                        put(emit, &mut cur, wc);
                    }
                }
            }
        }
        if let Some((a, b)) = cur {
            emit(a, b);
        }
    }
}
