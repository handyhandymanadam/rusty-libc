//! A bracket set of a UTF-8 locale matched without building its byte automaton (FIXLIST #141): the set stays a
//! description (listed characters, classes, ranges, equivalence classes, negation, case ignoring) and the matcher asks
//! the tables at each character, as glibc's `check_node_accept_bytes` does for its COMPLEX_BRACKET.
//!
//! The matcher still runs on bytes, so the set is an automaton whose states are only implicit (`nfa::K_U8`): the root
//! takes a first byte, then one node per byte read so far (1, 2, 3) takes the next. It is the minimal automaton the
//! parser would otherwise build (`mbset::utf8_canon`) state for state in what it accepts: a byte goes on exactly when a
//! character of the set starts with the bytes read so far (the block of code points those bytes leave is asked:
//! `live`), and the last byte completes the character exactly when it is in the set. Which of the parser's states a
//! thread is in differs (one node per depth here), but no rule of the matcher looks at more than "does this node take
//! this byte, and where to": what consumes a byte inside a character carries no group, constraint or alternative.
//!
//! Every question goes through `runs`: the set's members inside a window of code points, read from the tables through
//! their windowed walkers, which is the set the parser computes for the whole range (`Parser::set_ranges`,
//! `upper_preimage`) cut to the window.
use crate::charset::Collation;
use crate::mbset::{self, Ranges};
use crate::parse::{Set, set_has};
use crate::vec::V;
use core::sync::atomic::{AtomicU64, Ordering};

/// The class numbers of `charset::CLASS_NAMES` as bit numbers of rusty-libc-wchar's classes.
pub(crate) const WBIT: [u32; 12] = [0, 3, 6, 9, 1, 4, 7, 10, 2, 5, 8, 11];

pub struct U8Spec {
    /// The bracket's single bytes after negation (what the set holds below 0x80; read only when case is ignored).
    pub sb: Set,
    pub mbchars: V<u32>,
    pub classes: V<u8>,
    /// Ranges by collation sequence value (`coll.nrules() != 0`) or by code point.
    pub ranges: V<(u32, u32)>,
    pub equivs: V<(u8, &'static [u32])>,
    pub non_match: bool,
    pub has_complex: bool,
    pub icase: bool,
    pub coll: Collation,
    /// The LC_CTYPE (and its charset) and LC_COLLATE the pattern was compiled in: the matcher asks their tables, whatever
    /// locale is in force when it runs (as the automaton built at compile time would answer).
    pub ctype: Option<&'static rusty_libc_core::locale::CatData>,
    pub cs: rusty_libc_wchar::Charset,
    pub collate: Option<&'static rusty_libc_core::locale::CatData>,
    /// REG_ICASE: the characters the upper case mapping changes and the others (`mbset::cased_cached`).
    pub cased: Option<mbset::Cased>,
    /// The first bytes the root takes (the characters of one byte in the set, when case is ignored, and the first bytes
    /// of the longer ones).
    pub root: Set,
    /// What `step` found for the blocks a first byte of three or four and one more byte leave (2 bits each).
    pub memo: [AtomicU64; MEMO_WORDS],
    /// The members of recently asked blocks of 64 code points (`member_in_block`).
    pub blocks: [AtomicU64; 2 * BLOCK_SLOTS],
}

/// Words of `U8Spec::memo`: (16 + 5) first bytes x 64 second bytes x 2 bits.
pub const MEMO_WORDS: usize = 21 * 64 * 2 / 64;

/// The code points of the characters of `n` bytes.
const DOM: [(u32, u32); 5] = [(0, 0), (0, 0x7f), (0x80, 0x7ff), (0x800, 0xffff), (0x10000, 0x10ffff)];

/// The length of the character a first byte starts (0: not a first byte of a character up to U+10FFFF).
#[inline]
pub fn lead_len(b: u8) -> usize {
    match b {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

impl U8Spec {
    /// The members of the set `m` of `Parser::set_ranges` (case not ignored, from 0x80 up) inside `lo..=hi`.
    fn m_runs(&self, lo: u32, hi: u32, out: &mut Ranges) {
        out.clear();
        if !self.has_complex {
            return;
        }
        let mut h: Ranges = V::new();
        for &wc in self.mbchars.iter() {
            if lo <= wc && wc <= hi {
                h.push((wc, wc));
            }
        }
        for &c in self.classes.iter() {
            rusty_libc_wchar::wctype::class_runs_in_at(WBIT[c as usize], lo, hi, self.ctype, self.cs, &mut |a, b| h.push((a, b)));
        }
        if self.coll.nrules() != 0 {
            for &(s, e) in self.ranges.iter() {
                self.coll.seq_runs_in(s, e, lo, hi, &mut |a, b| h.push((a, b)));
            }
            for &(r, w) in self.equivs.iter() {
                rusty_libc_locale::equiv_runs_wc_in_at(self.collate, r, w, lo, hi, &mut |a, b| h.push((a, b)));
            }
        } else {
            for &(s, e) in self.ranges.iter() {
                if e >= 0x80 {
                    let (a, b) = (s.max(0x80).max(lo), e.min(hi));
                    if a <= b {
                        h.push((a, b));
                    }
                }
            }
        }
        mbset::normalize(&mut h);
        // the domain of the set inside the window
        let mut dom = [(0u32, 0u32); 2];
        let mut nd = 0;
        for &(a, b) in mbset::UTF8_DOMAIN.iter() {
            let (a, b) = (a.max(lo), b.min(hi));
            if a <= b {
                dom[nd] = (a, b);
                nd += 1;
            }
        }
        let dom = &dom[..nd];
        let h = mbset::clip(&h, dom);
        let oom = h.oom;
        *out = if self.non_match { mbset::complement(&h, dom) } else { h };
        out.oom |= oom;
    }

    /// The members of the set inside `lo..=hi`, as `Parser::utf8_set_ranges` makes them (case ignored: the characters
    /// whose upper case form is in S).
    pub fn runs(&self, lo: u32, hi: u32, out: &mut Ranges) {
        if !self.icase {
            self.m_runs(lo, hi, out);
            return;
        }
        let Some(cased) = self.cased else {
            out.clear();
            return;
        };
        // S inside the window
        let mut s: Ranges = V::new();
        for b in lo..=hi.min(0x7f) {
            if set_has(&self.sb, b as u8) {
                s.push((b, b));
            }
        }
        let mut m: Ranges = V::new();
        self.m_runs(lo, hi, &mut m);
        s.extend_from_slice(&m);
        mbset::normalize(&mut s);
        // its characters that keep their case, and the changed characters of the window whose upper case form is in S
        let mut res = mbset::clip(&s, kept_in(cased.kept, lo, hi));
        let first = cased.pairs.partition_point(|&(t, _)| t < lo);
        for &(t, u) in cased.pairs[first..].iter() {
            if t > hi {
                break;
            }
            // (S inside the window is at hand when the window holds `u`)
            let hit = if lo <= u && u <= hi { mbset::contains(&s, u) } else { self.s_has(u) };
            if hit {
                res.push((t, t));
            }
        }
        mbset::normalize(&mut res);
        res.oom |= s.oom || m.oom;
        *out = res;
    }

    /// Does a part of the set before negation and before the cut to the domain (`h` of `m_runs`) touch `lo..=hi`?
    fn h_any(&self, lo: u32, hi: u32) -> bool {
        if self.mbchars.iter().any(|&wc| lo <= wc && wc <= hi) {
            return true;
        }
        let mut hit = false;
        for &c in self.classes.iter() {
            rusty_libc_wchar::wctype::class_runs_in_at(WBIT[c as usize], lo, hi, self.ctype, self.cs, &mut |_, _| hit = true);
            if hit {
                return true;
            }
        }
        if self.coll.nrules() != 0 {
            for &(s, e) in self.ranges.iter() {
                self.coll.seq_runs_in(s, e, lo, hi, &mut |_, _| hit = true);
                if hit {
                    return true;
                }
            }
            for &(r, w) in self.equivs.iter() {
                rusty_libc_locale::equiv_runs_wc_in_at(self.collate, r, w, lo, hi, &mut |_, _| hit = true);
                if hit {
                    return true;
                }
            }
            false
        } else {
            self.ranges.iter().any(|&(s, e)| e >= 0x80 && s.max(0x80).max(lo) <= e.min(hi))
        }
    }

    /// Does `m` (see `m_runs`) hold a character of `lo..=hi`? (Without negation a part touching the window inside the
    /// domain is enough; a negated set misses a character there unless its parts cover the window.)
    fn m_any(&self, lo: u32, hi: u32) -> bool {
        if !self.has_complex {
            return false;
        }
        for &(a, b) in mbset::UTF8_DOMAIN.iter() {
            let (a, b) = (a.max(lo), b.min(hi));
            if a > b {
                continue;
            }
            let hit = if !self.non_match {
                self.h_any(a, b)
            } else if a == b {
                !self.h_any(a, a)
            } else {
                let mut r: Ranges = V::new();
                self.m_runs(a, b, &mut r);
                !r.is_empty()
            };
            if hit {
                return true;
            }
        }
        false
    }

    /// Is `u` in S, the set of upper case forms the text is compared against (the ASCII bytes of the set and `m`)?
    fn s_has(&self, u: u32) -> bool {
        if u < 0x80 { set_has(&self.sb, u as u8) } else { self.m_any(u, u) }
    }

    /// Does the set hold a character in `lo..=hi` (clipped to the code points of characters of `n` bytes)? What `runs`
    /// answers, asked without building the runs where a part or a point decides it.
    pub fn live(&self, lo: u32, hi: u32, n: usize) -> bool {
        let (lo, hi) = (lo.max(DOM[n].0), hi.min(DOM[n].1));
        if lo > hi {
            return false;
        }
        if !self.icase {
            return self.m_any(lo, hi);
        }
        let Some(cased) = self.cased else { return false };
        // the changed characters of the window whose upper case form is in S
        let first = cased.pairs.partition_point(|&(t, _)| t < lo);
        let last = first + cased.pairs[first..].partition_point(|&(t, _)| t <= hi);
        let changed = &cased.pairs[first..last];
        if changed.iter().any(|&(_, u)| self.s_has(u)) {
            return true;
        }
        if lo == hi {
            return changed.is_empty() && self.s_has(lo);
        }
        // a character of S in the window that keeps its case: a run of S not made of changed characters only
        let mut s: Ranges = V::new();
        for b in lo..=hi.min(0x7f) {
            if set_has(&self.sb, b as u8) {
                s.push((b, b));
            }
        }
        let mut m: Ranges = V::new();
        self.m_runs(lo, hi, &mut m);
        s.extend_from_slice(&m);
        s.iter().any(|&(a, b)| {
            let i = changed.partition_point(|&(t, _)| t < a);
            let j = i + changed[i..].partition_point(|&(t, _)| t <= b);
            (j - i) as u32 <= b - a
        })
    }

    /// The first bytes the root takes. A set with collation ranges or equivalence classes is read whole for them: its
    /// runs are returned (the parser builds the automaton from them when the set is not kept as a description).
    pub fn compute_root(&mut self) -> Option<Ranges> {
        // a set with collation ranges or equivalence classes costs a walk of the collation table per question: one walk
        // over all characters, then the first bytes from the runs
        if self.coll.nrules() != 0 && (!self.ranges.is_empty() || !self.equivs.is_empty()) {
            let mut r: Ranges = V::new();
            self.runs(0, 0x10ffff, &mut r);
            let any = |lo: u32, hi: u32| {
                let i = r.partition_point(|&(_, e)| e < lo);
                i < r.len() && r[i].0 <= hi
            };
            let mut root: Set = [0; 4];
            if self.icase {
                for c in 0..0x80u32 {
                    if any(c, c) {
                        root[(c >> 6) as usize] |= 1u64 << (c & 63);
                    }
                }
            }
            for b in 0xc2u32..=0xf4 {
                let n = lead_len(b as u8);
                let (base, size) = lead_block(b);
                let (lo, hi) = (base.max(DOM[n].0), (base + (size - 1)).min(DOM[n].1));
                if lo <= hi && any(lo, hi) {
                    root[(b >> 6) as usize] |= 1u64 << (b & 63);
                }
            }
            self.root = root;
            return Some(r);
        }
        let mut root: Set = [0; 4];
        if self.icase {
            let mut r: Ranges = V::new();
            self.runs(0, 0x7f, &mut r);
            for &(a, b) in r.iter() {
                for c in a..=b.min(0x7f) {
                    root[(c >> 6) as usize] |= 1u64 << (c & 63);
                }
            }
        }
        for b in 0xc2u32..=0xf4 {
            let n = lead_len(b as u8);
            let (base, size) = lead_block(b);
            if self.live(base, base + (size - 1), n) {
                root[(b >> 6) as usize] |= 1u64 << (b & 63);
            }
        }
        self.root = root;
        None
    }

    /// How many lengths of characters (1 to 4 bytes) the root starts.
    pub fn lengths(&self) -> usize {
        let has = |lo: u32, hi: u32| (lo..=hi).any(|b| set_has(&self.root, b as u8));
        [has(0, 0x7f), has(0xc2, 0xdf), has(0xe0, 0xef), has(0xf0, 0xf4)].iter().filter(|&&x| x).count()
    }

    /// A node of depth `d` (`d` bytes of the character read: `bytes`, the first is `bytes[0]`) and the next byte `b`:
    /// `None` when the set has no character that starts so, else whether `b` completes the character.
    pub fn step(&self, bytes: &[u8], b: u8) -> Option<bool> {
        if !(0x80..=0xbf).contains(&b) {
            return None;
        }
        let n = lead_len(*bytes.first()?);
        let d = bytes.len();
        if n < 2 || d >= n {
            return None;
        }
        // the code point bits read so far, then the block they leave
        let mut v = u32::from(bytes[0]) & (0x7f >> n);
        for &x in bytes[1..].iter() {
            v = (v << 6) | (u32::from(x) & 0x3f);
        }
        v = (v << 6) | (u32::from(b) & 0x3f);
        let rest = (n - d - 1) as u32;
        if rest == 0 {
            return if self.member_in_block(v, n) { Some(true) } else { None };
        }
        let (lo, hi) = (v << (6 * rest), (v << (6 * rest)) + ((1u32 << (6 * rest)) - 1));
        // the blocks after a first byte and one more (1,344 of them: 64 code points after E0..EF, 4096 after F0..F4) are
        // remembered: a text of such characters asks the same few again and again
        let slot = if d == 1 && rest > 0 {
            let b0 = bytes[0];
            let i = if n == 3 { usize::from(b0 - 0xe0) } else { 16 + usize::from(b0 - 0xf0) };
            Some(i * 64 + usize::from(b - 0x80))
        } else {
            None
        };
        if let Some(i) = slot {
            let w = self.memo[i / 32].load(Ordering::Relaxed) >> (2 * (i % 32));
            if w & 1 != 0 {
                return if w & 2 != 0 { Some(false) } else { None };
            }
        }
        let live = self.live(lo, hi, n);
        if let Some(i) = slot {
            // (two bits: known, live; any thread may fill them, all fill them the same)
            self.memo[i / 32].fetch_or((1 | (u64::from(live) << 1)) << (2 * (i % 32)), Ordering::Relaxed);
        }
        if live { Some(rest == 0) } else { None }
    }
}

impl U8Spec {
    /// Is the character `c` (of `n` bytes) in the set? Answered from the members of its block of 64 code points (the
    /// characters that differ in the last byte only), kept in a small table: a text asks about the same few blocks.
    fn member_in_block(&self, c: u32, n: usize) -> bool {
        let block = c >> 6;
        let tag = u64::from(block + 1) << 32;
        let slot = (block as usize % BLOCK_SLOTS) * 2;
        // (each word holds the block and half of its mask: two words with the block's tag are its two halves, whatever
        // other threads wrote in between, as a block's mask is always the same)
        let (w0, w1) = (self.blocks[slot].load(Ordering::Relaxed), self.blocks[slot + 1].load(Ordering::Relaxed));
        let mask = if w0 & !0xffff_ffff == tag && w1 & !0xffff_ffff == tag {
            (w0 & 0xffff_ffff) | (w1 << 32)
        } else {
            let lo = block << 6;
            let mut m = 0u64;
            let (a, b) = (lo.max(DOM[n].0), (lo + 63).min(DOM[n].1));
            if a <= b {
                let mut r: Ranges = V::new();
                self.runs(a, b, &mut r);
                if r.oom {
                    // (no memory for the runs: the plain question)
                    return self.live(c, c, n);
                }
                for &(x, y) in r.iter() {
                    for k in x.max(a)..=y.min(b) {
                        m |= 1u64 << (k - lo);
                    }
                }
            }
            self.blocks[slot].store(tag | (m & 0xffff_ffff), Ordering::Relaxed);
            self.blocks[slot + 1].store(tag | (m >> 32), Ordering::Relaxed);
            m
        };
        mask >> (c & 63) & 1 != 0
    }
}

/// Slots of `U8Spec::blocks` (two words each).
pub const BLOCK_SLOTS: usize = 64;

/// The block of code points a first byte of two to four bytes starts (before the cut to that length's code points).
fn lead_block(b: u32) -> (u32, u32) {
    match lead_len(b as u8) {
        2 => ((b - 0xc0) << 6, 64),
        3 => ((b - 0xe0) << 12, 4096),
        _ => ((b - 0xf0) << 18, 262_144),
    }
}

/// The part of the kept code points (`Cased::kept`, sorted ranges) that touches `lo..=hi`.
fn kept_in(kept: &[(u32, u32)], lo: u32, hi: u32) -> &[(u32, u32)] {
    let a = kept.partition_point(|&(_, e)| e < lo);
    let b = a + kept[a..].partition_point(|&(s, _)| s <= hi);
    &kept[a..b]
}
