//! Sets of multibyte characters as byte automata.
//!
//! The matcher runs on bytes. glibc matches a multibyte character with one node that consumes all of its bytes;
//! here a set of characters (a bracket expression, `.`, a letter and its other-case forms) is turned into a
//! small tree of single-byte nodes: an alternation over the first byte, then the following bytes, each level a
//! 256-bit set. For UTF-8 the characters of a set are first written as ranges of code points and split into
//! ranges of byte sequences (the algorithm of the Rust `utf8-ranges` crate); for other multibyte charsets
//! (EUC-JP, EUC-KR, GBK ...) the list of all characters of the charset is built once (by decoding every byte
//! sequence that can start a character) and cached.
use crate::charset::{self, Mb};
use crate::sync::Spin;
use crate::vec::{self, V};

/// One character class as a sequence of byte ranges (at most 4 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Seq {
    pub r: [(u8, u8); 6],
    pub n: u8,
}

fn utf8_len(wc: u32) -> usize {
    match wc {
        0..=0x7f => 1,
        0x80..=0x7ff => 2,
        0x800..=0xffff => 3,
        _ => 4,
    }
}

fn utf8_encode(wc: u32, out: &mut [u8; 4]) -> usize {
    match utf8_len(wc) {
        1 => {
            out[0] = wc as u8;
            1
        }
        2 => {
            out[0] = 0xc0 | (wc >> 6) as u8;
            out[1] = 0x80 | (wc & 0x3f) as u8;
            2
        }
        3 => {
            out[0] = 0xe0 | (wc >> 12) as u8;
            out[1] = 0x80 | ((wc >> 6) & 0x3f) as u8;
            out[2] = 0x80 | (wc & 0x3f) as u8;
            3
        }
        _ => {
            out[0] = 0xf0 | (wc >> 18) as u8;
            out[1] = 0x80 | ((wc >> 12) & 0x3f) as u8;
            out[2] = 0x80 | ((wc >> 6) & 0x3f) as u8;
            out[3] = 0x80 | (wc & 0x3f) as u8;
            4
        }
    }
}

/// Split the code points `lo..=hi` (valid scalar values) into UTF-8 byte-range sequences.
pub fn utf8_ranges(lo: u32, hi: u32, out: &mut V<Seq>) {
    let mut stack: V<(u32, u32)> = V::new();
    stack.push((lo, hi));
    while let Some((lo, hi)) = stack.pop() {
        if lo > hi {
            continue;
        }
        // surrogates are not characters
        if lo <= 0xdfff && hi >= 0xd800 {
            if hi > 0xdfff {
                stack.push((0xe000, hi));
            }
            if lo < 0xd800 {
                stack.push((lo, 0xd7ff));
            }
            continue;
        }
        // keep one encoding length per piece
        let mut split = false;
        for &b in &[0x7fu32, 0x7ff, 0xffff] {
            if lo <= b && b < hi {
                stack.push((b + 1, hi));
                stack.push((lo, b));
                split = true;
                break;
            }
        }
        if split {
            continue;
        }
        if hi <= 0x7f {
            out.push(Seq { r: [(lo as u8, hi as u8), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)], n: 1 });
            continue;
        }
        let mut again = false;
        for i in 1..4u32 {
            let m: u32 = (1 << (6 * i)) - 1;
            if (lo & !m) != (hi & !m) {
                if lo & m != 0 {
                    stack.push(((lo | m) + 1, hi));
                    stack.push((lo, lo | m));
                    again = true;
                    break;
                }
                if hi & m != m {
                    stack.push((hi & !m, hi));
                    stack.push((lo, (hi & !m) - 1));
                    again = true;
                    break;
                }
            }
        }
        if again {
            continue;
        }
        let (mut a, mut b) = ([0u8; 4], [0u8; 4]);
        let n = utf8_encode(lo, &mut a);
        utf8_encode(hi, &mut b);
        let mut s = Seq { r: [(0, 0); 6], n: n as u8 };
        for k in 0..n {
            s.r[k] = (a[k], b[k]);
        }
        out.push(s);
    }
}

// ---- the characters of a non-UTF-8 multibyte charset

/// One character: its bytes and value.
#[derive(Clone, Copy)]
pub struct Ch {
    pub b: [u8; 4],
    pub n: u8,
    pub wc: u32,
}

/// A run of GB18030's four-byte codes: the `n` codes from index `idx` on (see `gb_index`), with the characters `wc`,
/// `wc + 1` ... (rusty-libc-iconv hands GB18030's 1,100,000 four-byte characters over as a few hundred such runs).
#[derive(Clone, Copy)]
pub struct Run {
    pub idx: u32,
    pub wc: u32,
    pub n: u32,
}

/// The index of a four-byte GB18030 code (its place in the order of all four-byte codes: the last byte counts
/// 0x30..=0x39, the third 0x81..=0xfe, the second 0x30..=0x39, the first 0x81..=0xfe; rusty-libc-iconv's order).
fn gb_index(b: &[u8]) -> u32 {
    (((u32::from(b[0]) - 0x81) * 10 + (u32::from(b[1]) - 0x30)) * 126 + (u32::from(b[2]) - 0x81)) * 10 + (u32::from(b[3]) - 0x30)
}

/// The bytes of the digits of an index: their bases and counts, and the number of codes one step of each digit covers.
const GB_BASE: [u8; 4] = [0x81, 0x30, 0x81, 0x30];
const GB_RADIX: [u32; 4] = [126, 10, 126, 10];
const GB_WEIGHT: [u32; 4] = [12600, 1260, 10, 1];

struct Cache {
    key: usize,
    /// The list (kept here, not copied out: a copy of the 13,000 characters of EUC-JP touched 160 KB of new memory, about
    /// 40 page faults, in the first compile of a program); read only with the lock held (`with_other_set`).
    chars: V<Ch>,
    /// False until a list was made for `key` (or after a memory failure).
    ok: bool,
    runs: &'static [Run],
}

static CACHE: Spin<Cache> = Spin::new(Cache { key: 0, chars: V::new(), ok: false, runs: &[] });

/// Run `f` on all characters of the charset in force (not UTF-8): those listed one by one, and (GB18030 only) the runs of
/// four-byte codes; the list is empty on memory failure. The list's lock is held meanwhile: `f` must not come back here.
pub fn with_other_set<R>(f: impl FnOnce(&[Ch], &'static [Run]) -> R) -> R {
    // the identity of the locale's ctype data tells when the charset changed
    let key = rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE);
    CACHE.with(|c| {
        if c.key != key || !c.ok {
            let mut v: V<Ch> = V::new();
            let mut runs: V<Run> = V::new();
            // (room for a large CJK charset at once: EUC-JP has about 13,000 characters)
            v.reserve(16384);
            // (a character of one byte that glibc's regex does not count as one, `sb_chars`: GBK's 0x80, is not listed)
            let sbc = charset::sb_chars(Mb::Other);
            rusty_libc_wchar::mbyte::each_other_char(&mut |bytes, wc, n| {
                if bytes.len() == 1 && sbc[usize::from(bytes[0] >> 6)] >> (bytes[0] & 63) & 1 == 0 {
                    return;
                }
                if n > 1 {
                    if bytes.len() == 4 {
                        runs.push(Run { idx: gb_index(bytes), wc, n });
                    }
                    return;
                }
                // the bytes assembled in a register: a copy of 1 to 4 bytes into the array, read back at once, stalled the
                // store forwarding on every character
                let mut w = 0u32;
                for (i, &x) in bytes.iter().take(4).enumerate() {
                    w |= u32::from(x) << (8 * i);
                }
                v.push(Ch { b: w.to_le_bytes(), n: bytes.len() as u8, wc });
            });
            // (no reader holds the old list: every reader holds the lock; the old runs stay allocated, a few KB, as they
            // are handed out as a static slice)
            c.ok = false;
            c.runs = &[];
            c.chars = V::new();
            if !v.oom
                && !runs.oom
                && !v.is_empty()
                && let Some(kept_runs) = vec::leak_copy(&runs)
            {
                c.chars = v;
                c.runs = kept_runs;
                c.key = key;
                c.ok = true;
            }
        }
        f(&c.chars[..], c.runs)
    })
}

/// The first byte at or after `from` that is in `mask` (`set`) or is not (256 when there is none).
fn next_bit(mask: &[u64; 4], from: u32, set: bool) -> u32 {
    let (mut w, mut b) = ((from >> 6) as usize, from & 63);
    while w < 4 {
        let word = if set { mask[w] } else { !mask[w] };
        let x = word >> b;
        if x != 0 {
            return (w as u32) * 64 + b + x.trailing_zeros();
        }
        w += 1;
        b = 0;
    }
    256
}

struct RunsCache {
    key: usize,
    ok: bool,
    runs: &'static [Run],
}

static RUNS: Spin<RunsCache> = Spin::new(RunsCache { key: 0, ok: false, runs: &[] });

/// GB18030's runs of four-byte codes in the charset in force (empty in every other charset). Made without the list of all
/// the charset's characters when the charset has rows (`rusty-libc-iconv` `Converter::each_row`: FIXLIST #148).
pub fn other_runs() -> &'static [Run] {
    let key = rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE);
    let cached = RUNS.with(|c| (c.ok && c.key == key).then_some(c.runs));
    if let Some(r) = cached {
        return r;
    }
    let mut runs: V<Run> = V::new();
    let rows = rusty_libc_wchar::mbyte::each_other_row(
        Some(&[]),
        &mut |_, _| {},
        &mut |bytes, wc, n| {
            if bytes.len() == 4 {
                runs.push(Run { idx: gb_index(bytes), wc, n });
            }
        },
    );
    if !rows {
        // (a charset without rows: the list of its characters has the runs)
        return with_other_set(|_, runs| runs);
    }
    if runs.oom {
        return &[];
    }
    let kept: &'static [Run] = if runs.is_empty() { &[] } else { vec::leak_copy(&runs).unwrap_or(&[]) };
    if runs.is_empty() || !kept.is_empty() {
        RUNS.with(|c| *c = RunsCache { key, ok: true, runs: kept });
    }
    kept
}

/// The sequences of the multibyte characters of two or more bytes (not GB18030's four-byte codes: `other_runs`) of the
/// charset in force whose value is in the normalized `ranges` (all of them for `None`), from its rows: no question per
/// character. The sequences are those of `collect_listed` (without single bytes), in the same order. False (nothing added)
/// when the charset has no rows.
pub fn rows_seqs(ranges: Option<&[(u32, u32)]>, out: &mut V<Seq>) -> bool {
    rusty_libc_wchar::mbyte::each_other_row(
        ranges,
        &mut |head, mask| {
            let n = head.len() + 1;
            let mut s = Seq { r: [(0, 0); 6], n: n as u8 };
            for (i, &b) in head.iter().enumerate() {
                s.r[i] = (b, b);
            }
            // the runs of consecutive last bytes
            let mut t = next_bit(mask, 0, true);
            while t < 256 {
                let end = next_bit(mask, t, false);
                s.r[n - 1] = (t as u8, (end - 1) as u8);
                out.push(s);
                t = next_bit(mask, end, true);
            }
        },
        &mut |_, _, _| {},
    )
}

/// The indices of the four-byte codes of `runs` whose characters are in the normalized ranges `set` (all of them for `None`), as
/// normalized ranges of indices.
fn run_intervals(runs: &[Run], set: Option<&[(u32, u32)]>) -> Ranges {
    let mut iv: Ranges = V::new();
    for r in runs {
        let (lo, hi) = (r.wc, r.wc + (r.n - 1));
        let Some(set) = set else {
            iv.push((r.idx, r.idx + (r.n - 1)));
            continue;
        };
        // the first range that ends at or after the run's first character
        let mut k = set.partition_point(|&(_, e)| e < lo);
        while k < set.len() && set[k].0 <= hi {
            let (a, b) = (set[k].0.max(lo), set[k].1.min(hi));
            iv.push((r.idx + (a - lo), r.idx + (b - lo)));
            k += 1;
        }
    }
    normalize(&mut iv);
    iv
}

/// The sequences of the four-byte codes of `runs` whose characters are in the normalized ranges `set`.
pub fn runs_in(runs: &[Run], set: &Ranges, out: &mut V<Seq>) {
    let mut iv = run_intervals(runs, Some(&set[..]));
    gb_seqs(&mut iv, out);
}

/// The sequences of the four-byte codes of `runs` whose characters `pred` accepts.
fn collect_runs(runs: &[Run], pred: &mut dyn FnMut(u32) -> bool, out: &mut V<Seq>) {
    let mut iv: Ranges = V::new();
    for r in runs {
        let mut start: Option<u32> = None;
        for i in 0..r.n {
            if pred(r.wc + i) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                iv.push((r.idx + s, r.idx + i - 1));
            }
        }
        if let Some(s) = start {
            iv.push((r.idx + s, r.idx + r.n - 1));
        }
    }
    gb_seqs(&mut iv, out);
}

/// The sequences of the four-byte GB18030 codes whose indices are in `iv` (ranges, normalized here). The sequences have
/// the shape the list of single characters gives (`push_char`): one byte for the first byte (so they share their trie
/// node with the two-byte codes of that byte), and below it, at every level, disjoint byte ranges: next digits with the
/// same codes under them form one range, so the automaton stays deterministic.
fn gb_seqs(iv: &mut Ranges, out: &mut V<Seq>) {
    if iv.oom {
        out.oom = true;
        return;
    }
    normalize(iv);
    let mut prefix = Seq { r: [(0, 0); 6], n: 4 };
    gb_level(iv, 0, 0, &mut prefix, out);
}

/// The codes of `iv` (absolute indices, all inside the block of `level` that starts at `base`) below `prefix` (its bytes
/// before `level` are set).
fn gb_level(iv: &[(u32, u32)], base: u32, level: usize, prefix: &mut Seq, out: &mut V<Seq>) {
    if iv.is_empty() {
        return;
    }
    let b = GB_BASE[level];
    if level == 3 {
        for &(lo, hi) in iv {
            prefix.r[3] = (b + (lo - base) as u8, b + (hi - base) as u8);
            out.push(*prefix);
        }
        return;
    }
    let w = GB_WEIGHT[level];
    // the part of `iv` under digit d, relative to its block
    let part = |d: u32, k: &mut usize, v: &mut Ranges| {
        v.clear();
        let (lo, hi) = (base + d * w, base + d * w + (w - 1));
        while *k < iv.len() && iv[*k].1 < lo {
            *k += 1;
        }
        let mut j = *k;
        while j < iv.len() && iv[j].0 <= hi {
            v.push((iv[j].0.max(lo) - lo, iv[j].1.min(hi) - lo));
            j += 1;
        }
    };
    let (mut k, mut cur, mut next): (usize, Ranges, Ranges) = (0, V::new(), V::new());
    let radix = GB_RADIX[level];
    let mut d = 0u32;
    part(d, &mut k, &mut cur);
    while d < radix {
        if cur.is_empty() {
            d += 1;
            if d < radix {
                part(d, &mut k, &mut cur);
            }
            continue;
        }
        // the digits after d with the same codes under them (the first byte is never a range: see `gb_seqs`)
        let mut e = d;
        loop {
            if level == 0 || e + 1 >= radix {
                break;
            }
            let mut k2 = k;
            part(e + 1, &mut k2, &mut next);
            if next.len() != cur.len() || next.iter().zip(cur.iter()).any(|(x, y)| x != y) {
                break;
            }
            e += 1;
        }
        prefix.r[level] = (b + d as u8, b + e as u8);
        if cur.len() == 1 && cur[0] == (0, w - 1) {
            // the whole block: every byte after this one in its full range
            for l in level + 1..4 {
                prefix.r[l] = (GB_BASE[l], GB_BASE[l] + (GB_RADIX[l] - 1) as u8);
            }
            out.push(*prefix);
        } else {
            let abs: Ranges = {
                let mut a: Ranges = V::new();
                let off = base + d * w;
                for &(lo, hi) in cur.iter() {
                    a.push((lo + off, hi + off));
                }
                a
            };
            if abs.oom {
                out.oom = true;
                return;
            }
            gb_level(&abs, base + d * w, level + 1, prefix, out);
        }
        d = e + 1;
        if d < radix {
            part(d, &mut k, &mut cur);
        }
    }
    if cur.oom || next.oom {
        out.oom = true;
    }
}

// ---- the upper case form of each character of a non-UTF-8 charset (REG_ICASE)

/// The upper case form of a character of the list of `with_other_set` and, when that form is a character of one byte, its byte (`-1`
/// otherwise).
#[derive(Clone, Copy)]
pub struct Fold {
    pub up: u32,
    pub single: i16,
}

struct FoldCache {
    key: usize,
    folds: &'static [Fold],
}

static FOLDS: Spin<FoldCache> = Spin::new(FoldCache { key: 0, folds: &[] });

/// The fold table for the characters `chars` (the list of the locale in force), made on the first REG_ICASE bracket and kept
/// for later patterns. Empty on memory failure.
fn other_folds(k: Mb, chars: &[Ch]) -> &'static [Fold] {
    // (the list and the mapping both belong to the locale's ctype data)
    let key = rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE);
    FOLDS.with(|c| {
        if c.key != key || c.folds.is_empty() || c.folds.len() != chars.len() {
            c.folds = &[]; // (an older table is left allocated: another thread may still be reading it)
            let made = vec::leak_with(chars.len(), |i| {
                let ch = chars[i];
                let up = charset::upper_wc(ch.wc);
                let single = if up == ch.wc {
                    if ch.n == 1 { i16::from(ch.b[0]) } else { -1 }
                } else {
                    let mut b = [0u8; 6];
                    if let Some(1) = charset::encode(k, up, &mut b) { i16::from(b[0]) } else { -1 }
                };
                Fold { up, single }
            });
            if let Some(f) = made
                && !f.is_empty()
            {
                c.folds = f;
                c.key = key;
            }
        }
        c.folds
    })
}

// ---- the characters of a non-UTF-8 charset by their upper case form (a REG_ICASE letter)

struct ByUpper {
    key: usize,
    /// (upper case form, index in the list of `with_other_set`), sorted.
    idx: &'static [(u32, u32)],
    /// Questions asked in the locale `key` without the index (it is made once they pass `BY_UPPER_AFTER`).
    asked: u32,
}

static BY_UPPER: Spin<ByUpper> = Spin::new(ByUpper { key: 0, idx: &[], asked: 0 });

/// Sorting the list costs about as much as a dozen passes over it: the index is made for a locale only after that many
/// questions (a program that compiles one or two case-ignored patterns pays the passes, as before).
const BY_UPPER_AFTER: u32 = 12;

/// The sequences of the listed characters (not GB18030's runs) whose upper case form is `want`, in the order of the list:
/// what `collect_folded_listed` with the question "is the upper case form `want`" gives, from an index kept per locale
/// instead of a pass over every character. False (nothing added) when the index could not be made.
pub fn same_upper_listed(k: Mb, want: u32, out: &mut V<Seq>) -> bool {
    with_other_set(|chars, _| {
        let folds = other_folds(k, chars);
        if folds.len() != chars.len() || chars.is_empty() {
            return false;
        }
        let key = rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE);
        let idx = BY_UPPER.with(|c| {
            if c.key != key {
                c.key = key;
                c.idx = &[];
                c.asked = 0;
            }
            if c.idx.len() != chars.len() && c.asked < BY_UPPER_AFTER {
                c.asked += 1;
                return &[][..];
            }
            if c.idx.len() != chars.len() {
                c.idx = &[]; // (an older index is left allocated: another thread may still be reading it)
                let mut v: V<(u32, u32)> = V::with_capacity(chars.len());
                for (i, f) in folds.iter().enumerate() {
                    v.push((f.up, i as u32));
                }
                v.sort_unstable();
                if !v.oom
                    && let Some(l) = vec::leak_copy(&v)
                {
                    c.idx = l;
                    c.key = key;
                }
            }
            c.idx
        });
        if idx.len() != chars.len() {
            return false;
        }
        let first = idx.partition_point(|&(u, _)| u < want);
        for &(u, i) in idx[first..].iter() {
            if u != want {
                break;
            }
            push_char(out, &chars[i as usize]);
        }
        true
    })
}

// ---- the characters the upper case mapping changes (REG_ICASE in a UTF-8 locale)

/// The characters the upper case mapping changes with their upper case forms (increasing), and every other code point
/// as ranges (`kept`): both are the same for every pattern of a locale.
#[derive(Clone, Copy)]
pub struct Cased {
    pub pairs: &'static [(u32, u32)],
    pub kept: &'static [(u32, u32)],
}

/// Read the mapping table and derive `kept` (about a millisecond: the reason this is cached).
pub fn cased_compute(pairs: &mut V<(u32, u32)>, kept: &mut Ranges) {
    rusty_libc_wchar::wctype::upper_changed(&mut |c, u| pairs.push((c, u)));
    let mut points: Ranges = V::new();
    for &(t, _) in pairs.iter() {
        points.push((t, t));
    }
    normalize(&mut points);
    *kept = complement(&points, &[(0, 0x10ffff)]);
}

const CASED_SLOTS: usize = 8;

struct CasedEntry {
    key: (usize, u8),
    cased: Cased,
}

static CASED: Spin<[Option<CasedEntry>; CASED_SLOTS]> = Spin::new([const { None }; CASED_SLOTS]);

fn cased_find(key: (usize, u8)) -> Option<Cased> {
    CASED.with(|slots| slots.iter().flatten().find(|e| e.key == key).map(|e| e.cased))
}

/// The cased table of the locale in force, kept for later patterns. `None` when it could not be kept (all slots taken or
/// no memory): the caller then reads the table itself with `cased_compute`.
pub fn cased_cached() -> Option<Cased> {
    // the identity of the locale's ctype data and the charset tell what the mapping is (locale data lives forever)
    let key = (rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE), rusty_libc_wchar::charset() as u8);
    if let Some(c) = cased_find(key) {
        return Some(c);
    }
    let mut pairs: V<(u32, u32)> = V::new();
    let mut kept: Ranges = V::new();
    cased_compute(&mut pairs, &mut kept);
    if pairs.oom || kept.oom {
        return None;
    }
    // (the tables are never freed: the table of a locale is wanted until the program ends)
    let cased = Cased { pairs: vec::leak_copy(&pairs)?, kept: vec::leak_copy(&kept)? };
    CASED.with(|slots| {
        if let Some(e) = slots.iter().flatten().find(|e| e.key == key) {
            Some(e.cased) // another thread was first (our copy stays allocated: rare)
        } else if let Some(slot) = slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(CasedEntry { key, cased });
            Some(cased)
        } else {
            None
        }
    })
}

/// Forget the kept tables (they stay allocated: a caller may still hold one), for a test that needs a free slot.
#[cfg(test)]
pub fn cased_clear() {
    CASED.with(|slots| slots.iter_mut().for_each(|s| *s = None));
}

/// The sequences of the characters for which `pred(wc, byte length)` is true. Characters of one byte are
/// included only when `singles` is set; UTF-8 code points above `limit` are not looked at.
pub fn collect(k: Mb, singles: bool, limit: u32, pred: &mut dyn FnMut(u32, usize) -> bool, out: &mut V<Seq>) {
    collect_in(k, singles, limit, true, pred, out)
}

/// `collect` without GB18030's runs of four-byte codes (the caller handles them as ranges: `runs_in`).
pub fn collect_listed(k: Mb, singles: bool, limit: u32, pred: &mut dyn FnMut(u32, usize) -> bool, out: &mut V<Seq>) {
    collect_in(k, singles, limit, false, pred, out)
}

fn collect_in(k: Mb, singles: bool, limit: u32, with_runs: bool, pred: &mut dyn FnMut(u32, usize) -> bool, out: &mut V<Seq>) {
    match k {
        Mb::Utf8 => {
            let mut run: Option<u32> = None;
            let mut last = 0u32;
            let start = if singles { 0 } else { 0x80 };
            let mut wc = start;
            while wc <= limit {
                let ok = !(0xd800..=0xdfff).contains(&wc) && pred(wc, utf8_len(wc));
                if ok {
                    if run.is_none() {
                        run = Some(wc);
                    }
                    last = wc;
                } else if let Some(s) = run.take() {
                    utf8_ranges(s, last, out);
                }
                wc += 1;
            }
            if let Some(s) = run {
                utf8_ranges(s, last, out);
            }
        }
        _ => with_other_set(|chars, runs| {
            for c in chars {
                if (c.n > 1 || singles) && pred(c.wc, c.n as usize) {
                    push_char(out, c);
                }
            }
            if with_runs {
                collect_runs(runs, &mut |wc| pred(wc, 4), out);
            }
        }),
    }
}

/// Add one character of a non-UTF-8 charset. Characters come in byte order: a run that differs only in the last byte is
/// one sequence.
fn push_char(out: &mut V<Seq>, c: &Ch) {
    let n = c.n as usize;
    if let Some(last) = out.last_mut()
        && last.n == c.n
        && last.r[..n - 1].iter().zip(c.b.iter()).all(|(r, &b)| *r == (b, b))
        && last.r[n - 1].1.checked_add(1) == Some(c.b[n - 1])
    {
        last.r[n - 1].1 = c.b[n - 1];
        return;
    }
    let mut s = Seq { r: [(0, 0); 6], n: c.n };
    for i in 0..n {
        s.r[i] = (c.b[i], c.b[i]);
    }
    out.push(s);
}

/// Like `collect` for a charset that is not UTF-8, for REG_ICASE: `pred(wc, upper, single)` is asked with the upper case
/// form of each character and, when that form is a character of one byte, that byte (`-1`: it is not). Both come from a
/// table made once per locale, so a pattern does not map and encode every character of the charset again.
pub fn collect_folded(k: Mb, pred: &mut dyn FnMut(u32, u32, i16) -> bool, out: &mut V<Seq>) {
    collect_folded_in(k, true, pred, out)
}

/// `collect_folded` without GB18030's runs of four-byte codes (the caller handles them as ranges: `runs_in`).
pub fn collect_folded_listed(k: Mb, pred: &mut dyn FnMut(u32, u32, i16) -> bool, out: &mut V<Seq>) {
    collect_folded_in(k, false, pred, out)
}

fn collect_folded_in(k: Mb, with_runs: bool, pred: &mut dyn FnMut(u32, u32, i16) -> bool, out: &mut V<Seq>) {
    with_other_set(|chars, all_runs| collect_folded_on(k, chars, all_runs, with_runs, pred, out))
}

fn collect_folded_on(k: Mb, chars: &[Ch], all_runs: &'static [Run], with_runs: bool, pred: &mut dyn FnMut(u32, u32, i16) -> bool, out: &mut V<Seq>) {
    let runs = if with_runs { all_runs } else { &[] };
    // the four-byte GB18030 codes (no fold table: about 1,100,000 characters): only an ASCII character is one byte in
    // GB18030 (the one-byte codes are 0x00..=0x7f), so a form above 0x7f is not one
    collect_runs(
        runs,
        &mut |wc| {
            let up = charset::upper_wc(wc);
            let mut b = [0u8; 6];
            let single = if up < 0x80
                && let Some(1) = charset::encode(k, up, &mut b)
            {
                i16::from(b[0])
            } else {
                -1
            };
            pred(wc, up, single)
        },
        out,
    );
    let folds = other_folds(k, chars);
    if folds.len() != chars.len() {
        // (no memory for the table)
        for c in chars {
            let up = charset::upper_wc(c.wc);
            let mut b = [0u8; 6];
            let single = if let Some(1) = charset::encode(k, up, &mut b) { i16::from(b[0]) } else { -1 };
            if pred(c.wc, up, single) {
                push_char(out, c);
            }
        }
        return;
    }
    for (c, f) in chars.iter().zip(folds.iter()) {
        if pred(c.wc, f.up, f.single) {
            push_char(out, c);
        }
    }
}

/// The sequence of one character.
pub fn seq_of(k: Mb, wc: u32) -> Option<Seq> {
    let mut b = [0u8; 6];
    let n = charset::encode(k, wc, &mut b)?;
    if n > 4 {
        return None;
    }
    let mut s = Seq { r: [(0, 0); 6], n: n as u8 };
    for i in 0..n {
        s.r[i] = (b[i], b[i]);
    }
    Some(s)
}

// ---- a set of sequences that answers "is one of them a prefix of this one, or this one a prefix of one of them" (the
// grouping of collating elements in `parse::units_tree`: a quadratic scan over the group took most of a compile of `[^x]` in
// a UTF-8 locale with thousands of contractions)

const PS_TERM: u8 = 1;
const PS_PREFIX: u8 = 2;

/// Sequences added since the last `clear`, by their prefixes: open addressing, entries of an older generation are empty.
pub struct PrefixSet {
    /// (key, generation, flags)
    slots: V<(u128, u32, u8)>,
    era: u32,
    live: usize,
    /// An empty sequence was added (it is a prefix of every sequence).
    empty: bool,
    pub oom: bool,
}

/// The first `k` byte ranges of `s` and `k` as one key.
fn ps_key(s: &Seq, k: usize) -> u128 {
    let mut key = (k as u128) << 120;
    for (i, &(lo, hi)) in s.r.iter().take(k).enumerate() {
        key |= (u128::from(lo) << (16 * i)) | (u128::from(hi) << (16 * i + 8));
    }
    key
}

fn ps_hash(key: u128) -> u64 {
    // (splitmix64's finisher: every bit of the key reaches the low bits the table index takes)
    let mut x = (key as u64) ^ ((key >> 64) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl PrefixSet {
    pub fn new() -> PrefixSet {
        PrefixSet { slots: V::new(), era: 1, live: 0, empty: false, oom: false }
    }

    /// Forget every sequence.
    pub fn clear(&mut self) {
        self.era = self.era.wrapping_add(1);
        if self.era == 0 {
            // (generation 0 marks never used slots)
            for s in self.slots.iter_mut() {
                s.1 = 0;
            }
            self.era = 1;
        }
        self.live = 0;
        self.empty = false;
    }

    fn find(&self, key: u128) -> (usize, bool) {
        let mask = self.slots.len() - 1;
        let mut i = ps_hash(key) as usize & mask;
        loop {
            let s = &self.slots[i];
            if s.1 != self.era {
                return (i, false);
            }
            if s.0 == key {
                return (i, true);
            }
            i = (i + 1) & mask;
        }
    }

    fn mark(&mut self, key: u128, flag: u8) {
        if (self.live + 1) * 2 > self.slots.len() {
            self.grow();
            if self.oom {
                return;
            }
        }
        let (i, found) = self.find(key);
        if found {
            self.slots[i].2 |= flag;
        } else {
            self.slots[i] = (key, self.era, flag);
            self.live += 1;
        }
    }

    fn grow(&mut self) {
        let old = core::mem::replace(&mut self.slots, V::from_elem((0, 0, 0), 0));
        let n = (old.len() * 2).max(256);
        self.slots = V::from_elem((0, 0, 0), n);
        if self.slots.oom || self.slots.len() != n {
            self.oom = true;
            self.slots = old;
            return;
        }
        for &(key, g, flags) in old.iter() {
            if g == self.era {
                let (i, _) = self.find(key);
                self.slots[i] = (key, g, flags);
            }
        }
    }

    /// Add `s`.
    pub fn add(&mut self, s: &Seq) {
        let n = s.n as usize;
        if n == 0 {
            self.empty = true;
            return;
        }
        for k in 1..=n {
            self.mark(ps_key(s, k), PS_PREFIX);
        }
        self.mark(ps_key(s, n), PS_TERM);
    }

    /// Is a sequence of the set a prefix of `s` (or equal to it), or `s` a prefix of one of them?
    pub fn clashes(&self, s: &Seq) -> bool {
        let n = s.n as usize;
        if self.empty || (n == 0 && self.live > 0) {
            return true;
        }
        if self.live == 0 {
            // (nothing added since the last `clear`; the table may not even be allocated yet)
            return false;
        }
        for k in 1..=n {
            let (i, found) = self.find(ps_key(s, k));
            if !found {
                return false;
            }
            let f = self.slots[i].2;
            if f & PS_TERM != 0 || (k == n && f & PS_PREFIX != 0) {
                return true;
            }
        }
        false
    }
}

impl Default for PrefixSet {
    fn default() -> PrefixSet {
        PrefixSet::new()
    }
}

// ---- the trie

pub type Set = [u64; 4];

fn set_range(s: &mut Set, lo: u8, hi: u8) {
    let (lo, hi) = (u32::from(lo), u32::from(hi));
    // (a word at a time: ranges of 190 bytes are the usual last level of an East Asian set)
    for w in (lo >> 6)..=(hi >> 6) {
        let a = if w == lo >> 6 { lo & 63 } else { 0 };
        let b = if w == hi >> 6 { hi & 63 } else { 63 };
        s[w as usize] |= (!0u64 >> (63 - (b - a))) << a;
    }
}

#[derive(Clone, Copy)]
struct Edge {
    lo: u8,
    hi: u8,
    child: u32,
    next: u32,
}

/// Trie of byte sequences, then a DAG of canonical nodes (equal subtrees share one id).
pub struct Trie {
    head: V<u32>,
    edges: V<Edge>,
    /// Every sequence so far came in order (`seq_cmp`): the children of a node were then added in increasing order, so a
    /// new range is either the node's last added one or not there at all (no scan of the others).
    sorted: bool,
    prev: Option<Seq>,
}

/// The order of sequences by their ranges (a sequence before the longer ones it starts).
pub fn seq_cmp(a: &Seq, b: &Seq) -> core::cmp::Ordering {
    let (na, nb) = (a.n as usize, b.n as usize);
    a.r[..na.min(6)].cmp(&b.r[..nb.min(6)])
}

/// A number whose order is `seq_cmp`'s: the ranges from the top byte down, zero after the last, and the length in the
/// low byte (a sequence before the longer ones it starts, which agree with it in the bytes above).
pub fn seq_key(s: &Seq) -> u128 {
    let mut k = u128::from(s.n);
    for (i, &(lo, hi)) in s.r.iter().take((s.n as usize).min(6)).enumerate() {
        k |= (u128::from(lo) << (120 - 16 * i)) | (u128::from(hi) << (112 - 16 * i));
    }
    k
}

/// Sort `v` in the order of `seq_cmp`.
pub fn sort_seqs(v: &mut V<Seq>) {
    let mut keyed: V<(u128, Seq)> = V::with_capacity(v.len());
    for s in v.iter() {
        keyed.push((seq_key(s), *s));
    }
    if keyed.oom {
        v.sort_unstable_by(seq_cmp);
        return;
    }
    keyed.sort_unstable_by_key(|e| e.0);
    for (d, e) in v.iter_mut().zip(keyed.iter()) {
        *d = e.1;
    }
}

const NIL: u32 = u32::MAX;

impl Trie {
    pub fn new() -> Trie {
        let mut t = Trie { head: V::new(), edges: V::new(), sorted: true, prev: None };
        t.head.push(NIL);
        t
    }

    pub fn insert(&mut self, s: &Seq) {
        if self.sorted {
            if let Some(p) = &self.prev
                && seq_cmp(p, s) == core::cmp::Ordering::Greater
            {
                self.sorted = false;
            }
            self.prev = Some(*s);
        }
        let mut cur = 0u32;
        for &(lo, hi) in s.r.iter().take(s.n as usize) {
            let mut e = self.head[cur as usize];
            let mut found = NIL;
            while e != NIL {
                let ed = self.edges[e as usize];
                if ed.lo == lo && ed.hi == hi {
                    found = e;
                    break;
                }
                if self.sorted {
                    // (the last added child is the largest: an unequal range is new)
                    break;
                }
                e = ed.next;
            }
            if found != NIL {
                cur = self.edges[found as usize].child;
            } else {
                let child = self.head.len() as u32;
                self.head.push(NIL);
                let id = self.edges.len() as u32;
                self.edges.push(Edge { lo, hi, child, next: self.head[cur as usize] });
                self.head[cur as usize] = id;
                cur = child;
            }
        }
    }

    pub fn oom(&self) -> bool {
        self.head.oom || self.edges.oom
    }

    pub fn is_empty(&self) -> bool {
        self.head[0] == NIL
    }

    /// Canonical form: for every distinct subtree, its groups `(child, set of first bytes)`.
    pub fn canon(&self) -> Canon {
        let n = self.head.len();
        let mut id_of: V<u32> = V::from_elem(0, n);
        let mut c = Canon { groups: V::new(), start: V::new(), root: 0, oom: false };
        // id 0 is the empty node (the end of a character)
        c.start.push(0);
        c.groups.push((0, [0; 4])); // placeholder, never read
        let mut index = rehash(&c, 64);
        if index.oom || index.is_empty() {
            c.oom = true;
            return c;
        }
        let mut i = n;
        // (one buffer for the groups of every node)
        let mut gs: V<(u32, Set)> = V::new();
        while i > 0 {
            i -= 1;
            // groups of node i
            gs.clear();
            let mut e = self.head[i];
            while e != NIL {
                let ed = self.edges[e as usize];
                let cid = id_of[ed.child as usize];
                let mut found = None;
                for (k, g) in gs.iter().enumerate() {
                    if g.0 == cid {
                        found = Some(k);
                        break;
                    }
                }
                match found {
                    Some(k) => set_range(&mut gs[k].1, ed.lo, ed.hi),
                    None => {
                        let mut s = [0u64; 4];
                        set_range(&mut s, ed.lo, ed.hi);
                        gs.push((cid, s));
                    }
                }
                e = ed.next;
            }
            if gs.is_empty() {
                id_of[i] = 0;
                continue;
            }
            // sort by child id for a canonical order
            let len = gs.len();
            for a in 1..len {
                let mut b = a;
                while b > 0 && gs[b - 1].0 > gs[b].0 {
                    gs.swap(b - 1, b);
                    b -= 1;
                }
            }
            // an equal node already known? (the known nodes are all different, so there is at most one; it is found by a
            // hash of the groups instead of a scan of every node, which made large sets quadratic)
            let h = groups_hash(&gs);
            let mut same = 0u32;
            let mask = index.len() - 1;
            let mut slot = h as usize & mask;
            while index[slot] != 0 {
                let cand = index[slot];
                let (s0, s1) = c.range(cand);
                if s1 - s0 == len && c.groups[s0..s1] == gs[..] {
                    same = cand;
                    break;
                }
                slot = (slot + 1) & mask;
            }
            if same != 0 {
                id_of[i] = same;
            } else {
                let nid = c.start.len() as u32;
                c.start.push(c.groups.len());
                for g in gs.iter() {
                    c.groups.push(*g);
                }
                id_of[i] = nid;
                index[slot] = nid;
                if (c.start.len() + 1) * 2 > index.len() {
                    index = rehash(&c, index.len() * 2);
                    if index.oom || index.is_empty() {
                        c.oom = true;
                        return c;
                    }
                }
            }
            let _ = &mut id_of;
        }
        c.root = id_of[0];
        c.oom = id_of.oom || c.groups.oom || c.start.oom || gs.oom;
        c
    }
}

/// A hash of a node's groups (for the index of `Trie::canon`).
fn groups_hash(gs: &[(u32, Set)]) -> u64 {
    let mut x = gs.len() as u64;
    for (child, set) in gs {
        for w in [u64::from(*child), set[0], set[1], set[2], set[3]] {
            x = (x ^ w).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            x ^= x >> 29;
        }
    }
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^ (x >> 31)
}

/// An index (open addressing, 0 = empty) of the nodes 1.. of `c` by `groups_hash`, with `size` (a power of two) slots.
fn rehash(c: &Canon, size: usize) -> V<u32> {
    let mut index: V<u32> = V::from_elem(0, size);
    if index.oom || index.len() != size {
        return index;
    }
    for id in 1..c.start.len() as u32 {
        let mut slot = groups_hash(c.groups(id)) as usize & (size - 1);
        while index[slot] != 0 {
            slot = (slot + 1) & (size - 1);
        }
        index[slot] = id;
    }
    index
}

impl Default for Trie {
    fn default() -> Trie {
        Trie::new()
    }
}

/// Canonical nodes: node `i` (i >= 1) owns `groups[start[i]..start[i + 1]]` (the last one runs to the end).
pub struct Canon {
    groups: V<(u32, Set)>,
    start: V<usize>,
    pub root: u32,
    pub oom: bool,
}

impl Canon {
    /// The form of the empty set (cached so that a set without multibyte characters is not searched for again).
    pub fn none() -> Canon {
        Canon { groups: V::new(), start: V::new(), root: u32::MAX, oom: false }
    }

    /// The canonical automaton of the sequences `seqs` (what `tree_put` makes).
    pub fn of_seqs(seqs: &V<Seq>) -> Canon {
        let mut t = Trie::new();
        for s in seqs.iter() {
            t.insert(s);
        }
        if t.is_empty() { Canon::none() } else { t.canon() }
    }

    /// Do the two automata accept the same sequences? (Both are minimal, so their states pair off one to one.)
    pub fn equivalent(&self, o: &Canon) -> bool {
        let (a_none, b_none) = (self.root == u32::MAX || self.root == 0, o.root == u32::MAX || o.root == 0);
        if a_none || b_none {
            return a_none && b_none;
        }
        let mut pa: V<u32> = V::from_elem(NIL, self.start.len());
        let mut pb: V<u32> = V::from_elem(NIL, o.start.len());
        let mut todo: V<(u32, u32)> = V::new();
        pa[self.root as usize] = o.root;
        pb[o.root as usize] = self.root;
        todo.push((self.root, o.root));
        while let Some((x, y)) = todo.pop() {
            let (mut ca, mut cb) = ([NIL; 256], [NIL; 256]);
            for (child, set) in self.groups(x) {
                for byte in 0..256usize {
                    if set[byte >> 6] >> (byte & 63) & 1 != 0 {
                        ca[byte] = *child;
                    }
                }
            }
            for (child, set) in o.groups(y) {
                for byte in 0..256usize {
                    if set[byte >> 6] >> (byte & 63) & 1 != 0 {
                        cb[byte] = *child;
                    }
                }
            }
            for byte in 0..256 {
                let (p, q) = (ca[byte], cb[byte]);
                if (p == NIL) != (q == NIL) || (p == 0) != (q == 0) {
                    return false;
                }
                if p == NIL || p == 0 {
                    continue;
                }
                match (pa[p as usize], pb[q as usize]) {
                    (NIL, NIL) => {
                        pa[p as usize] = q;
                        pb[q as usize] = p;
                        todo.push((p, q));
                    }
                    (m, n) if m == q && n == p => {}
                    _ => return false,
                }
            }
        }
        true
    }

    /// Are the two automata equal, node for node (same numbers)?
    pub fn same(&self, o: &Canon) -> bool {
        self.root == o.root && self.oom == o.oom && self.start[..] == o.start[..] && self.groups[..] == o.groups[..]
    }

    fn range(&self, id: u32) -> (usize, usize) {
        let s = self.start[id as usize];
        let e = if (id as usize + 1) < self.start.len() { self.start[id as usize + 1] } else { self.groups.len() };
        (s, e)
    }

    /// The groups of node `id`: `(child id, set of first bytes)`; child 0 ends the character.
    pub fn groups(&self, id: u32) -> &[(u32, Set)] {
        if id == 0 {
            return &[];
        }
        let (s, e) = self.range(id);
        &self.groups[s..e]
    }
}

// ---- the canonical automaton of a UTF-8 set straight from its ranges of code points

/// Builds the canonical form (as `Trie::canon` would from the UTF-8 sequences of the set) without the sequences and the
/// trie: a state is a block of code points with the bytes still to read; a child block wholly inside the set is the
/// shared "any continuation" state of its depth, one wholly outside has no group, and only the blocks a range boundary
/// cuts are built (each boundary cuts one block per depth). Equal states are merged by hash as in `Trie::canon`, so the
/// result is the same minimal automaton.
struct U8Build<'a> {
    m: &'a [(u32, u32)],
    c: Canon,
    index: V<u32>,
    /// The state of each depth (1..=3) whose every continuation is in the set.
    full: [u32; 4],
    /// The state of each level (1..=3) of GB18030's four-byte codes whose every continuation is in the set (`gb_full`).
    gb_full: [u32; 4],
    /// The last state of a row's last bytes made by `rows_node` (rows next to each other often have the same ones).
    last_leaf: Option<(Set, u32)>,
}

const U8_EMPTY: u8 = 0;
const U8_FULL: u8 = 1;
const U8_PART: u8 = 2;

impl U8Build<'_> {
    /// The id of the state with groups `gs` (sorted here), made if new.
    fn intern(&mut self, gs: &mut V<(u32, Set)>) -> u32 {
        gs.sort_unstable_by_key(|g| g.0);
        let h = groups_hash(gs);
        let mask = self.index.len() - 1;
        let mut slot = h as usize & mask;
        while self.index[slot] != 0 {
            let cand = self.index[slot];
            let (s0, s1) = self.c.range(cand);
            if s1 - s0 == gs.len() && self.c.groups[s0..s1] == gs[..] {
                return cand;
            }
            slot = (slot + 1) & mask;
        }
        let nid = self.c.start.len() as u32;
        self.c.start.push(self.c.groups.len());
        self.c.groups.extend_from_slice(gs);
        self.index[slot] = nid;
        if (self.c.start.len() + 1) * 2 > self.index.len() {
            self.index = rehash(&self.c, self.index.len() * 2);
            if self.index.oom || self.index.is_empty() {
                self.c.oom = true;
                self.index = V::from_elem(0, 2);
            }
        }
        nid
    }

    fn full_id(&mut self, k: usize) -> u32 {
        if k == 0 {
            return 0;
        }
        if self.full[k] == 0 {
            let child = self.full_id(k - 1);
            let mut s: Set = [0; 4];
            set_range(&mut s, 0x80, 0xbf);
            let mut gs: V<(u32, Set)> = V::new();
            gs.push((child, s));
            self.full[k] = self.intern(&mut gs);
        }
        self.full[k]
    }

    /// The groups of the `n` children (bytes `byte0 + i`) of a block that starts at `base`, each child `size` code points
    /// (`size` = 64^`k`: `k` bytes follow the child's byte), with the set clipped to `dom`. Added to `gs`.
    #[allow(clippy::too_many_arguments)]
    fn level(&mut self, dom: (u32, u32), base: u32, size: u32, n: u32, byte0: u8, k: usize, gs: &mut V<(u32, Set)>) {
        let end = base + (size * n - 1);
        let (lo_all, hi_all) = (base.max(dom.0), end.min(dom.1));
        if lo_all > hi_all {
            return;
        }
        let mut st = [U8_EMPTY; 128];
        let mut i = self.m.partition_point(|&(_, e)| e < lo_all);
        while i < self.m.len() && self.m[i].0 <= hi_all {
            let (lo, hi) = (self.m[i].0.max(lo_all), self.m[i].1.min(hi_all));
            i += 1;
            let (c0, c1) = ((lo - base) / size, (hi - base) / size);
            for c in c0..=c1 {
                let (blo, bhi) = (base + c * size, base + c * size + (size - 1));
                let whole = lo <= blo && hi >= bhi && blo >= dom.0 && bhi <= dom.1;
                st[c as usize] = if st[c as usize] == U8_EMPTY && whole { U8_FULL } else { U8_PART };
            }
        }
        for c in 0..n {
            let child = match st[c as usize] {
                U8_EMPTY => continue,
                U8_FULL => self.full_id(k),
                _ => {
                    // (a cut block of single code points cannot happen: size 1 is wholly in or out)
                    let mut sub: V<(u32, Set)> = V::new();
                    self.level(dom, base + c * size, size / 64, 64, 0x80, k - 1, &mut sub);
                    if sub.is_empty() {
                        continue;
                    }
                    self.intern(&mut sub)
                }
            };
            let b = byte0 + c as u8;
            match gs.iter_mut().find(|g| g.0 == child) {
                Some(g) => g.1[(b >> 6) as usize] |= 1u64 << (b & 63),
                None => {
                    let mut s: Set = [0; 4];
                    s[(b >> 6) as usize] |= 1u64 << (b & 63);
                    gs.push((child, s));
                }
            }
        }
    }
}

/// The canonical automaton of the UTF-8 sequences of the code points in the normalized `m` (`Canon::none` when empty).
pub fn utf8_canon(m: &Ranges) -> Canon {
    let mut c = Canon { groups: V::new(), start: V::new(), root: 0, oom: false };
    c.start.push(0);
    c.groups.push((0, [0; 4])); // id 0: the end of a character (placeholder, never read)
    let index = rehash(&c, 64);
    let mut b = U8Build { m, c, index, full: [0; 4], gb_full: [0; 4], last_leaf: None };
    if b.index.oom || b.index.is_empty() {
        b.c.oom = true;
        return b.c;
    }
    let mut gs: V<(u32, Set)> = V::new();
    b.level((0, 0x7f), 0, 1, 128, 0, 0, &mut gs);
    b.level((0x80, 0x7ff), 0, 64, 32, 0xc0, 1, &mut gs);
    // (no surrogates, as `utf8_ranges`)
    b.level((0x800, 0xd7ff), 0, 4096, 16, 0xe0, 2, &mut gs);
    b.level((0xe000, 0xffff), 0, 4096, 16, 0xe0, 2, &mut gs);
    b.level((0x10000, 0x10ffff), 0, 262_144, 8, 0xf0, 3, &mut gs);
    if gs.is_empty() {
        let oom = b.c.oom || gs.oom;
        return Canon { oom, ..Canon::none() };
    }
    b.c.root = b.intern(&mut gs);
    b.c.oom |= gs.oom || b.c.groups.oom || b.c.start.oom;
    b.c
}

// ---- the canonical automaton of a non-UTF-8 set straight from the rows of the charset

/// One row: the head bytes (the prefix and lead byte) and the set of last bytes.
#[derive(Clone, Copy)]
struct RowEnt {
    head: [u8; 3],
    hlen: u8,
    mask: Set,
}

impl U8Build<'_> {
    /// The state of the rows `rows` (all with the same first `depth` head bytes, sorted): the ids are given in the order
    /// `Trie::canon` gives them, which walks the nodes from the last created (the trie of the sorted sequences is made in
    /// depth-first order, so that is: the children from the largest byte down, each subtree the same way, a node after its
    /// children). `None` when two rows are of different lengths under one prefix (no charset has them).
    fn rows_node(&mut self, rows: &[RowEnt], depth: usize) -> Option<u32> {
        if rows[0].hlen as usize == depth {
            // the last bytes of a character: one row, whose runs are leaves of the trie, all of the empty state
            if rows.len() != 1 {
                return None;
            }
            if let Some((m, id)) = self.last_leaf
                && m == rows[0].mask
            {
                return Some(id);
            }
            let mut gs: V<(u32, Set)> = V::new();
            gs.push((0, rows[0].mask));
            let id = self.intern(&mut gs);
            self.last_leaf = Some((rows[0].mask, id));
            return Some(id);
        }
        let mut gs: V<(u32, Set)> = V::new();
        let mut hi = rows.len();
        while hi > 0 {
            let b = rows[hi - 1].head[depth];
            let mut lo = hi - 1;
            while lo > 0 && rows[lo - 1].head[depth] == b {
                lo -= 1;
            }
            let child = self.rows_node(&rows[lo..hi], depth + 1)?;
            match gs.iter_mut().find(|g| g.0 == child) {
                Some(g) => g.1[(b >> 6) as usize] |= 1u64 << (b & 63),
                None => {
                    let mut s: Set = [0; 4];
                    s[(b >> 6) as usize] |= 1u64 << (b & 63);
                    gs.push((child, s));
                }
            }
            hi = lo;
        }
        self.c.oom |= gs.oom;
        Some(self.intern(&mut gs))
    }
}

impl U8Build<'_> {
    /// The state at `level` (1 to 3) of GB18030's four-byte codes of which every code below it is in the set (level 4: the end).
    fn gb_full(&mut self, level: usize) -> u32 {
        if level == 4 {
            return 0;
        }
        if self.gb_full[level] == 0 {
            let child = self.gb_full(level + 1);
            let mut s: Set = [0; 4];
            set_range(&mut s, GB_BASE[level], GB_BASE[level] + (GB_RADIX[level] - 1) as u8);
            let mut gs: V<(u32, Set)> = V::new();
            gs.push((child, s));
            self.gb_full[level] = self.intern(&mut gs);
        }
        self.gb_full[level]
    }

    /// The groups of the state at `level` (1 to 3) of the block of four-byte codes that starts at index `base`, for the codes in
    /// `iv` (normalized ranges of indices, all of them meeting the block), added to `gs`: one group per distinct state the next
    /// byte leads to; a block wholly in `iv` leads to the shared `gb_full` state.
    fn gb_groups(&mut self, iv: &[(u32, u32)], base: u32, level: usize, gs: &mut V<(u32, Set)>) {
        if level == 3 {
            // the last byte: a leaf group of the digits
            let mut s: Set = [0; 4];
            for &(lo, hi) in iv {
                let (a, b) = (lo.max(base) - base, hi.min(base + 9) - base);
                set_range(&mut s, GB_BASE[3] + a as u8, GB_BASE[3] + b as u8);
            }
            gs.push((0, s));
            return;
        }
        let w = GB_WEIGHT[level];
        let radix = GB_RADIX[level];
        let top = base + w * radix - 1;
        let mut j = 0;
        let mut d = 0;
        // (digit by digit, but only the digits that have codes: a run of whole digits under one range is added at once)
        while d < radix {
            while j < iv.len() && iv[j].1 < base + d * w {
                j += 1;
            }
            if j == iv.len() || iv[j].0 > top {
                break;
            }
            d = d.max((iv[j].0.max(base) - base) / w);
            let (blo, bhi) = (base + d * w, base + d * w + (w - 1));
            let mut e = j;
            while e < iv.len() && iv[e].0 <= bhi {
                e += 1;
            }
            let sub = &iv[j..e];
            let (child, last) = if sub[0].0 <= blo && sub[0].1 >= bhi {
                // the last digit whose whole block this range covers
                (self.gb_full(level + 1), (sub[0].1.min(top) + 1 - base) / w - 1)
            } else {
                let mut cg: V<(u32, Set)> = V::new();
                self.gb_groups(sub, blo, level + 1, &mut cg);
                self.c.oom |= cg.oom;
                (self.intern(&mut cg), d)
            };
            let (a, z) = (GB_BASE[level] + d as u8, GB_BASE[level] + last as u8);
            match gs.iter_mut().find(|g| g.0 == child) {
                Some(g) => set_range(&mut g.1, a, z),
                None => {
                    let mut s: Set = [0; 4];
                    set_range(&mut s, a, z);
                    gs.push((child, s));
                }
            }
            d = last + 1;
        }
    }
}

/// `rows_canon` for GB18030, with its four-byte codes: the canonical automaton of the characters (two-byte rows and four-byte
/// codes) whose value is in the normalized `ranges` (`None`: all), built from the rows and the intervals of four-byte code indices
/// directly. It has the language of the trie of `rows_seqs` and `runs_in`, and is minimal (states are merged by their groups), so
/// it is that trie's automaton up to the numbering of the states (`Canon::equivalent`).
pub fn rows_gb_canon(ranges: Option<&[(u32, u32)]>) -> Option<Canon> {
    let runs = other_runs();

    let iv = run_intervals(runs, ranges);
    if iv.oom {
        return None;
    }
    let mut rows: V<RowEnt> = V::new();
    let mut shape_ok = true;
    let ok = rusty_libc_wchar::mbyte::each_other_row(
        ranges,
        &mut |head, mask| {
            if head.len() == 1 && (0x81..=0xfe).contains(&head[0]) {
                rows.push(RowEnt { head: [head[0], 0, 0], hlen: 1, mask: *mask });
            } else {
                shape_ok = false;
            }
        },
        &mut |_, _, _| {},
    );
    if !ok || !shape_ok || rows.oom {
        return None;
    }
    if rows.is_empty() && iv.is_empty() {
        return Some(Canon::none());
    }
    let mut c = Canon { groups: V::new(), start: V::new(), root: 0, oom: false };
    c.start.push(0);
    c.groups.push((0, [0; 4]));
    let index = rehash(&c, 64);
    let mut b = U8Build { m: &[], c, index, full: [0; 4], gb_full: [0; 4], last_leaf: None };
    if b.index.oom || b.index.is_empty() {
        return None;
    }
    let mut root: V<(u32, Set)> = V::new();
    let (mut ri, mut j) = (0, 0);
    for d0 in 0..GB_RADIX[0] {
        let lead = GB_BASE[0] + d0 as u8;
        let (blo, bhi) = (d0 * GB_WEIGHT[0], d0 * GB_WEIGHT[0] + (GB_WEIGHT[0] - 1));
        while j < iv.len() && iv[j].1 < blo {
            j += 1;
        }
        let mut e = j;
        while e < iv.len() && iv[e].0 <= bhi {
            e += 1;
        }
        let mut gs: V<(u32, Set)> = V::new();
        if e > j {
            b.gb_groups(&iv[j..e], blo, 1, &mut gs);
        }
        while ri < rows.len() && rows[ri].head[0] < lead {
            ri += 1;
        }
        if ri < rows.len() && rows[ri].head[0] == lead {
            gs.push((0, rows[ri].mask));
        }
        if gs.is_empty() {
            continue;
        }
        b.c.oom |= gs.oom;
        let id = b.intern(&mut gs);
        match root.iter_mut().find(|g| g.0 == id) {
            Some(g) => g.1[(lead >> 6) as usize] |= 1u64 << (lead & 63),
            None => {
                let mut s: Set = [0; 4];
                s[(lead >> 6) as usize] |= 1u64 << (lead & 63);
                root.push((id, s));
            }
        }
    }
    b.c.root = b.intern(&mut root);
    b.c.oom |= root.oom || b.c.groups.oom || b.c.start.oom;
    Some(b.c)
}

/// The canonical automaton of the multibyte characters of two or more bytes of the charset in force (not GB18030's four-byte
/// codes) whose value is in the normalized `ranges` (`None`: all), from its rows: the same `Canon` as `Trie::canon` gives for the
/// sequences of `rows_seqs`, without making them and the trie (`Canon::none` when there are no characters). `None` when the
/// charset has no rows (or its rows are not of the shape this handles).
pub fn rows_canon(ranges: Option<&[(u32, u32)]>) -> Option<Canon> {
    let mut rows: V<RowEnt> = V::new();
    let ok = rusty_libc_wchar::mbyte::each_other_row(
        ranges,
        &mut |head, mask| {
            if head.len() <= 3 {
                let mut h = [0u8; 3];
                h[..head.len()].copy_from_slice(head);
                rows.push(RowEnt { head: h, hlen: head.len() as u8, mask: *mask });
            }
        },
        &mut |_, _, _| {},
    );
    if !ok || rows.oom {
        return None;
    }
    if rows.is_empty() {
        return Some(Canon::none());
    }
    let mut c = Canon { groups: V::new(), start: V::new(), root: 0, oom: false };
    c.start.push(0);
    c.groups.push((0, [0; 4]));
    let index = rehash(&c, 64);
    let mut b = U8Build { m: &[], c, index, full: [0; 4], gb_full: [0; 4], last_leaf: None };
    if b.index.oom || b.index.is_empty() {
        return None;
    }
    let root = b.rows_node(&rows, 0)?;
    b.c.root = root;
    b.c.oom |= b.c.groups.oom || b.c.start.oom;
    Some(b.c)
}

// ---- the canonical form as a fragment of the node graph

/// The target of a group that ends the character: the node after the fragment.
pub const EXIT: u32 = u32::MAX;

/// A canonical automaton flattened for the matcher (see `nfa::K_MB`): node 0 is the root, nodes 1.. the others, each one
/// consuming one byte and going on to the node of the group the byte is in (`EXIT`: the character is complete). One node of
/// the graph per state of the automaton and no epsilon nodes, where the tree of `Parser::emit_canon` copied a shared state
/// once per path to it and joined the groups of each state with alternation nodes (whose epsilon closures cost time
/// quadratic in the size of the set).
pub struct Frag {
    /// Groups of node `d`: `groups[start[d]..start[d + 1]]`, as `(set of bytes, target node)`.
    pub start: V<u32>,
    pub groups: V<(Set, u32)>,
    /// The bytes node `d` accepts (the union of its groups).
    pub union: V<Set>,
    /// The groups of every node are disjoint (a byte has at most one successor); only then is the fragment used as nodes of
    /// its own (`Parser::emit_canon` builds the tree otherwise).
    pub det: bool,
    /// Some node has two groups or more: the tree would have had an alternation node (glibc's `has_plural`, which decides
    /// whether the submatch walk sifts the state log, must not change).
    pub plural: bool,
    pub oom: bool,
}

impl Frag {
    /// The fragment of nothing (the empty set).
    pub fn empty() -> Frag {
        Frag { start: V::new(), groups: V::new(), union: V::new(), det: true, plural: false, oom: false }
    }

    /// The number of nodes (0: the empty set).
    pub fn nodes(&self) -> usize {
        self.start.len().saturating_sub(1)
    }

    pub fn groups(&self, d: u32) -> &[(Set, u32)] {
        &self.groups[self.start[d as usize] as usize..self.start[d as usize + 1] as usize]
    }

    /// The flattened form of `c`: the nodes reachable from its root, numbered in the order of a depth-first walk.
    pub fn from_canon(c: &Canon) -> Frag {
        let mut f = Frag::empty();
        if c.root == u32::MAX || c.root == 0 {
            return f;
        }
        // local number of each canonical node (NIL: not reached yet)
        let mut local: V<u32> = V::from_elem(NIL, c.start.len());
        let mut order: V<u32> = V::new();
        if local.oom || local.len() != c.start.len() {
            f.oom = true;
            return f;
        }
        local[c.root as usize] = 0;
        order.push(c.root);
        let mut i = 0;
        while i < order.len() {
            let id = order[i];
            i += 1;
            for &(child, _) in c.groups(id) {
                if child != 0 && local[child as usize] == NIL {
                    local[child as usize] = order.len() as u32;
                    order.push(child);
                }
            }
        }
        f.start.reserve(order.len() + 1);
        f.union.reserve(order.len());
        for &id in order.iter() {
            f.start.push(f.groups.len() as u32);
            let gs = c.groups(id);
            if gs.len() > 1 {
                f.plural = true;
            }
            let mut u: Set = [0; 4];
            for &(child, set) in gs {
                if (0..4).any(|k| u[k] & set[k] != 0) {
                    f.det = false;
                }
                for k in 0..4 {
                    u[k] |= set[k];
                }
                f.groups.push((set, if child == 0 { EXIT } else { local[child as usize] }));
            }
            f.union.push(u);
        }
        f.start.push(f.groups.len() as u32);
        f.oom = order.oom || f.start.oom || f.groups.oom || f.union.oom;
        f
    }

    pub fn duplicate(&self) -> Frag {
        let f = Frag { start: self.start.duplicate(), groups: self.groups.duplicate(), union: self.union.duplicate(), det: self.det, plural: self.plural, oom: self.oom };
        let oom = f.start.oom || f.groups.oom || f.union.oom;
        Frag { oom: f.oom || oom, ..f }
    }

    /// The memory the fragment holds (about).
    fn bytes(&self) -> usize {
        self.start.len() * 4 + self.groups.len() * core::mem::size_of::<(Set, u32)>() + self.union.len() * 32
    }
}

// ---- a small cache of the canonical byte automata built for sets (finding the characters of a set scans every character
// of the charset, and building the trie and its canonical form from thousands of sequences takes about a millisecond: a
// compile of `.` or `[[:alpha:]]` in an EUC locale costs only the emission of the small canonical form when it is cached)

/// One part of the collating elements a bracket accepts as a unit (see `Parser::units_tree`): the automaton of a group of
/// them, or of one element with the texts after it that must not follow (`Guard` nodes; empty for a group).
pub struct Unit {
    pub frag: Frag,
    pub rests: V<crate::parse::Rest>,
}

impl Unit {
    fn bytes(&self) -> usize {
        self.frag.bytes() + self.rests.len() * core::mem::size_of::<crate::parse::Rest>() + core::mem::size_of::<Unit>()
    }
}

/// A cached automaton (`canon_put`) or list of units (`units_put`); the keys of the two kinds differ in their first byte.
struct Entry {
    key: V<u8>,
    frag: Frag,
    units: V<Unit>,
    /// The first bytes of a UTF-8 set (`root_put`).
    root: Option<Set>,
}

impl Entry {
    /// The memory the entry holds (about).
    fn bytes(&self) -> usize {
        self.key.len() + self.frag.bytes() + self.units.iter().map(Unit::bytes).sum::<usize>()
    }
}

struct Entries {
    list: V<Entry>,
    /// Where the next entry goes once the list is full (round robin).
    next: usize,
    /// The memory the entries hold.
    total: usize,
}

static ENTRIES: Spin<Entries> = Spin::new(Entries { list: V::new(), next: 0, total: 0 });
const CACHE_SLOTS: usize = 64;
/// At most this much memory in the cache (entries are replaced round robin to stay below it), and no entry larger than a
/// quarter of it is kept.
const CACHE_BYTES: usize = 8 << 20;

/// Runs `f` on the cached automaton for `key` (a description of the set and of the locale), if there is one. The
/// cache lock is held meanwhile: `f` must not use the cache.
pub fn canon_with<R>(key: &[u8], f: impl FnOnce(&Frag) -> R) -> Option<R> {
    ENTRIES.with(|entries| {
        for e in entries.list.iter() {
            if e.key.len() == key.len() && e.key[..] == *key {
                return Some(f(&e.frag));
            }
        }
        None
    })
}

/// Runs `f` on the cached units for `key`, if there are some (as `canon_with`).
pub fn units_with<R>(key: &[u8], f: impl FnOnce(&[Unit]) -> R) -> Option<R> {
    ENTRIES.with(|entries| {
        for e in entries.list.iter() {
            if e.key.len() == key.len() && e.key[..] == *key {
                return Some(f(&e.units));
            }
        }
        None
    })
}

/// The cached first bytes of the UTF-8 set `key`.
pub fn root_get(key: &[u8]) -> Option<Set> {
    ENTRIES.with(|entries| entries.list.iter().find(|e| e.key.len() == key.len() && e.key[..] == *key).and_then(|e| e.root))
}

/// Remember the first bytes of the UTF-8 set `key`.
pub fn root_put(key: &[u8], root: Set) {
    put(key, Entry { key: V::new(), frag: Frag::empty(), units: V::new(), root: Some(root) });
}

/// Remember the units built for `key`.
pub fn units_put(key: &[u8], units: V<Unit>) {
    if units.oom || units.iter().any(|u| u.frag.oom || u.rests.oom) {
        return;
    }
    put(key, Entry { key: V::new(), frag: Frag::empty(), units, root: None });
}

/// Remember the automaton built for `key`.
pub fn canon_put(key: &[u8], frag: Frag) {
    if frag.oom {
        return;
    }
    put(key, Entry { key: V::new(), frag, units: V::new(), root: None });
}

fn put(key: &[u8], mut e: Entry) {
    let bytes = key.len() + e.bytes();
    if bytes > CACHE_BYTES / 4 {
        return;
    }
    let mut k: V<u8> = V::new();
    k.extend_from_slice(key);
    if k.oom {
        return;
    }
    ENTRIES.with(|entries| {
        // room by the memory limit: replace entries round robin (an emptied slot is reused below)
        while entries.total + bytes > CACHE_BYTES && !entries.list.is_empty() {
            let i = entries.next % entries.list.len();
            entries.total -= entries.list[i].bytes();
            entries.list[i] = Entry { key: V::new(), frag: Frag::empty(), units: V::new(), root: None };
            entries.next += 1;
        }
        e.key = k;
        entries.total += bytes;
        if let Some(i) = entries.list.iter().position(|e| e.key.is_empty()) {
            entries.list[i] = e;
        } else if entries.list.len() < CACHE_SLOTS {
            entries.list.push(e);
            if entries.list.oom {
                entries.total -= bytes;
            }
        } else {
            let i = entries.next % CACHE_SLOTS;
            entries.total -= entries.list[i].bytes();
            entries.list[i] = e;
            entries.next += 1;
        }
    });
}

// ---- sets of characters as sorted ranges

/// Sorted, disjoint, non-adjacent ranges of characters.
pub type Ranges = V<(u32, u32)>;

/// The valid characters of UTF-8 from 0x80 up (no surrogates).
pub const UTF8_DOMAIN: [(u32, u32); 2] = [(0x80, 0xd7ff), (0xe000, 0x10ffff)];

/// Sort and merge overlapping or adjacent ranges.
pub fn normalize(r: &mut Ranges) {
    r.sort_unstable();
    let mut w = 0usize;
    for i in 0..r.len() {
        let (lo, hi) = r[i];
        if w > 0 && lo <= r[w - 1].1.saturating_add(1) {
            if hi > r[w - 1].1 {
                r[w - 1].1 = hi;
            }
        } else {
            r[w] = (lo, hi);
            w += 1;
        }
    }
    r.truncate(w);
}

/// The part of the normalized `r` inside the normalized `dom`.
pub fn clip(r: &Ranges, dom: &[(u32, u32)]) -> Ranges {
    // (both sorted and disjoint: one walk over the two, not every pair)
    let mut out: Ranges = V::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < r.len() && j < dom.len() {
        let ((lo, hi), (dlo, dhi)) = (r[i], dom[j]);
        let (a, b) = (lo.max(dlo), hi.min(dhi));
        if a <= b {
            out.push((a, b));
        }
        if hi < dhi {
            i += 1;
        } else {
            j += 1;
        }
    }
    normalize(&mut out);
    out
}

/// `dom` without the normalized `r`.
pub fn complement(r: &Ranges, dom: &[(u32, u32)]) -> Ranges {
    let mut out: Ranges = V::new();
    for &(dlo, dhi) in dom {
        let mut next = dlo;
        for &(lo, hi) in r.iter() {
            if hi < next || lo > dhi {
                continue;
            }
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
            if next > dhi {
                break;
            }
        }
        if next <= dhi && next >= dlo {
            out.push((next, dhi));
        }
    }
    out
}

/// Is `c` in the normalized `r`?
pub fn contains(r: &Ranges, c: u32) -> bool {
    let (mut lo, mut hi) = (0usize, r.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (a, b) = r[mid];
        if c < a {
            hi = mid;
        } else if c > b {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    false
}

/// The sequences of all characters of the normalized `r` (UTF-8).
pub fn utf8_seqs(r: &Ranges, out: &mut V<Seq>) {
    for &(lo, hi) in r.iter() {
        utf8_ranges(lo, hi, out);
    }
}

#[cfg(test)]
pub(crate) mod frag_tests {
    use super::*;

    /// Are the automata `a` and `b` the same (deterministic ones: one walk pairing their states)?
    pub(crate) fn same_frag(a: &Frag, b: &Frag) -> bool {
        if a.nodes() != b.nodes() || a.plural != b.plural || a.det != b.det {
            return false;
        }
        if a.nodes() == 0 {
            return true;
        }
        let mut pair: Vec<u32> = vec![u32::MAX; a.nodes()];
        let mut todo = vec![(0u32, 0u32)];
        pair[0] = 0;
        while let Some((x, y)) = todo.pop() {
            let (ga, gb) = (a.groups(x), b.groups(y));
            if ga.len() != gb.len() {
                return false;
            }
            for (set, t) in ga {
                let Some((_, u)) = gb.iter().find(|(s2, _)| s2 == set) else { return false };
                if (*t == EXIT) != (*u == EXIT) {
                    return false;
                }
                if *t != EXIT {
                    if pair[*t as usize] == u32::MAX {
                        pair[*t as usize] = *u;
                        todo.push((*t, *u));
                    } else if pair[*t as usize] != *u {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn via_trie(r: &Ranges) -> Frag {
        let mut seqs: V<Seq> = V::new();
        utf8_seqs(r, &mut seqs);
        let mut t = Trie::new();
        for s in seqs.iter() {
            t.insert(s);
        }
        if t.is_empty() {
            return Frag::empty();
        }
        Frag::from_canon(&t.canon())
    }

    /// The automaton built from the ranges is the one the trie of the UTF-8 sequences gives, for sets of every shape.
    #[test]
    fn utf8_canon_is_trie_canon() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let marks = [0u32, 0x7f, 0x80, 0x7ff, 0x800, 0xfff, 0x1000, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x3ffff, 0x40000, 0x10ffff];
        let mut sets = 0;
        for round in 0..4000 {
            let mut r: Ranges = V::new();
            let k = 1 + (rnd() % 12) as usize;
            for _ in 0..k {
                let pick = |v: u64| -> u32 {
                    match v % 4 {
                        0 => marks[(v >> 8) as usize % marks.len()].wrapping_add(((v >> 20) % 5) as u32).wrapping_sub(2),
                        1 => ((v >> 8) % 0x800) as u32,
                        2 => ((v >> 8) % 0x10000) as u32,
                        _ => ((v >> 8) % 0x110000) as u32,
                    }
                };
                let a = pick(rnd()).min(0x10ffff);
                let len = match rnd() % 3 {
                    0 => (rnd() % 4) as u32,
                    1 => (rnd() % 300) as u32,
                    _ => (rnd() % 70000) as u32,
                };
                r.push((a, a.saturating_add(len).min(0x10ffff)));
            }
            normalize(&mut r);
            // as the parser gives them: no surrogates (and from 0x80 up unless case is ignored)
            let dom: &[(u32, u32)] = if round % 2 == 0 { &[(0, 0xd7ff), (0xe000, 0x10ffff)] } else { &UTF8_DOMAIN };
            let r = clip(&r, dom);
            let a = Frag::from_canon(&utf8_canon(&r));
            let b = via_trie(&r);
            assert!(same_frag(&a, &b), "set {:x?}: {} vs {} states", &r[..], a.nodes(), b.nodes());
            sets += a.nodes();
        }
        // the whole domain and the classes' shapes
        let mut all: Ranges = V::new();
        all.extend_from_slice(&UTF8_DOMAIN);
        assert!(same_frag(&Frag::from_canon(&utf8_canon(&all)), &via_trie(&all)));
        // (the sets are not trivial: about 20 states each)
        assert!(sets > 4000 * 8, "{sets} states in all");
    }
}
