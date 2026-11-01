//! The multibyte characters of a stateless East Asian charset as rows (FIXLIST #148): a head (the prefix bytes and the lead
//! byte, one to three bytes) and the 256-bit set of the last bytes that complete a character. The regex compiler builds the
//! automaton of `.`, of negated brackets and of ranges from these without asking the decoder about every character (EUC-TW has
//! about 150,000 of them, 17 ns each).
//!
//! The rows come straight from the charset's tables (`Mb`): a cell that is not empty is a character, as the decoder's body
//! finds it. `each_row_matches_walk` (tests_extra) checks, for every charset answered here, that the rows give exactly the
//! multibyte characters the walk over all candidate sequences finds (every valid and invalid byte pair, and the three- and
//! four-byte forms), with their values.
use crate::mb::{Mb, Set};

/// Which cells to keep: the characters whose value is in sorted, disjoint ranges (a few ranges are compared, many are looked up
/// in a bitmap of the values below 0xfffe), or all of them.
struct Pick<'a> {
    /// Every cell passes the test of the value: no ranges were given, or they cover all the values a cell can have (0x80 to
    /// 0xfffd, no multibyte character has a smaller one; the surrogates are not characters of any charset).
    bmp_all: bool,
    /// (low, high - low) of the first `nsmall` of a few ranges
    small: [(u16, u16); 6],
    nsmall: usize,
    bitmap: Option<&'a [u64; 1024]>,
    /// The ranges whole (for the characters above 0xffff).
    full: &'a [(u32, u32)],
    wide: Wide,
    /// The values from 0x10000 to 0x2ffff in the ranges (for `Wide::Some`).
    wide_bits: Option<&'a [u64; 2048]>,
}

/// Which of the characters above U+FFFF (cell 0xffff, value in `Mb::wide`) are kept.
#[derive(PartialEq, Clone, Copy)]
enum Wide {
    None,
    /// All of them (the ranges cover U+10000 to U+10FFFF).
    All,
    /// Some: each is looked up.
    Some,
}

impl Pick<'_> {
    /// Is `cp` (above 0xffff) in the ranges?
    fn wide_in(&self, cp: u32) -> bool {
        if let Some(b) = self.wide_bits
            && (0x10000..0x30000).contains(&cp)
        {
            let v = cp - 0x10000;
            return b[(v >> 6) as usize] >> (v & 63) & 1 != 0;
        }
        let i = self.full.partition_point(|&(_, hi)| hi < cp);
        i < self.full.len() && self.full[i].0 <= cp
    }
}

/// Put the 16 flags `bits` at bit `at` of the 256-bit `mask`.
#[inline(always)]
fn deposit(mask: &mut [u64; 4], at: usize, bits: u32) {
    let (w, sh) = (at >> 6, at & 63);
    mask[w] |= u64::from(bits) << sh;
    if sh > 48 && w + 1 < 4 {
        mask[w + 1] |= u64::from(bits) >> (64 - sh);
    }
}

/// The set of the cells of one row whose value has its bit set in `bits` (a bitmap of the values below 0x10000 in which 0, 0xfffe
/// and, unless the characters above U+FFFF are kept, 0xffff are clear), as bits from `lo` on.
fn bitmap_mask(cells: &[u16], lo: usize, bits: &[u64; 1024]) -> [u64; 4] {
    let mut mask = [0u64; 4];
    let mut at = lo;
    let (chunks, rest) = cells.as_chunks::<16>();
    for c in chunks {
        let mut flags = 0u32;
        for (j, &v) in c.iter().enumerate() {
            flags |= (((bits[usize::from(v >> 6)] >> (v & 63)) & 1) as u32) << j;
        }
        deposit(&mut mask, at, flags);
        at += 16;
    }
    for &v in rest {
        deposit(&mut mask, at, ((bits[usize::from(v >> 6)] >> (v & 63)) & 1) as u32);
        at += 1;
    }
    mask
}

/// The set of the cells of one row whose value is in one of the `N` ranges ((low, high - low); `N` = 0: any value), or is 0xffff
/// when the characters above U+FFFF are all kept. Sixteen cells at a time: flags in bytes by vector compares (fixed sizes, so
/// that the compiler vectorizes), then one multiplication per eight flags that gathers the low bit of each byte.
fn range_mask<const N: usize>(cells: &[u16], lo: usize, ranges: [(u16, u16); N], wide_all: bool) -> [u64; 4] {
    let gather = |f: &[u8]| u64::from_le_bytes([f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]]).wrapping_mul(0x0102_0408_1020_4080) >> 56;
    let mut mask = [0u64; 4];
    let mut at = lo;
    let (chunks, rest) = cells.as_chunks::<16>();
    for c in chunks {
        let mut f = [0u8; 16];
        for (b, &v) in f.iter_mut().zip(c) {
            let mut hit = N == 0;
            for &(l, span) in &ranges {
                hit |= v.wrapping_sub(l) <= span;
            }
            *b = u8::from((hit & (v.wrapping_sub(1) < 0xfffd)) | ((v == 0xffff) & wide_all));
        }
        deposit(&mut mask, at, (gather(&f[..8]) | gather(&f[8..]) << 8) as u32);
        at += 16;
    }
    for &v in rest {
        let hit = N == 0 || ranges.iter().any(|&(l, span)| v.wrapping_sub(l) <= span);
        deposit(&mut mask, at, u32::from((hit && v.wrapping_sub(1) < 0xfffd) || (v == 0xffff && wide_all)));
        at += 1;
    }
    mask
}

/// The set of the cells of one row that are not 0, as bits from `lo` on (every cell that is not 0 is a character here: no
/// multibyte character is U+0000, the cell 0xfffe, and `each_row_matches_walk` checks it), four cells in a 64-bit word at a time.
fn nonzero_mask(cells: &[u16], lo: usize) -> [u64; 4] {
    const LOW15: u64 = 0x7fff_7fff_7fff_7fff;
    const TOP: u64 = 0x8000_8000_8000_8000;
    // gathers the top bits of the four lanes (bits 15, 31, 47, 63, moved down to 0, 16, 32, 48) into bits 48 to 51
    const GATHER: u64 = 0x0001_0002_0004_0008;
    let mut mask = [0u64; 4];
    let mut at = lo;
    let (chunks, rest) = cells.as_chunks::<16>();
    for c in chunks {
        let mut bits = 0u32;
        for (k, q) in c.as_chunks::<4>().0.iter().enumerate() {
            let x = u64::from(q[0]) | u64::from(q[1]) << 16 | u64::from(q[2]) << 32 | u64::from(q[3]) << 48;
            let nz = (((x & LOW15) + LOW15) | x) & TOP;
            bits |= (((nz >> 15).wrapping_mul(GATHER) >> 48) as u32 & 0xf) << (4 * k);
        }
        deposit(&mut mask, at, bits);
        at += 16;
    }
    for &v in rest {
        deposit(&mut mask, at, u32::from(v != 0));
        at += 1;
    }
    mask
}

/// The bits `lo..lo + n` of a 256-bit set.
fn span(lo: usize, n: usize) -> [u64; 4] {
    let mut m = [0u64; 4];
    for (w, word) in m.iter_mut().enumerate() {
        let (s, e) = (lo.max(w * 64), (lo + n).min(w * 64 + 64));
        if s < e {
            let len = e - s;
            *word = (if len == 64 { !0 } else { (1u64 << len) - 1 }) << (s - w * 64);
        }
    }
    m
}

/// The trail bytes of row `row` of `set` (`cells`: the row's cells), kept by `pick`.
fn row_mask(m: &Mb, set: &Set, row: usize, cells: &[u16], pick: &Pick) -> [u64; 4] {
    let lo = set.trail_lo as usize;
    // a cell of 0 is no character, 0xfffe is U+0000 (no multibyte character is), 0xffff is a character above U+FFFF
    let wide_all = pick.wide == Wide::All;
    let mut mask = if pick.bmp_all {
        // (a row of cells that are all characters, the usual one in the large sets, is one run of bits: found by a reduction)
        if cells.iter().fold(true, |a, &v| a & ((v.wrapping_sub(1) < 0xfffd) | (v == 0xffff && wide_all))) {
            span(lo, cells.len())
        } else if wide_all {
            nonzero_mask(cells, lo)
        } else {
            range_mask(cells, lo, [], wide_all)
        }
    } else if let Some(b) = pick.bitmap {
        bitmap_mask(cells, lo, b)
    } else {
        let s = pick.small;
        match pick.nsmall {
            1 => range_mask(cells, lo, [s[0]], wide_all),
            2 => range_mask(cells, lo, [s[0], s[1]], wide_all),
            3 | 4 => range_mask(cells, lo, [s[0], s[1], s[2], s[3]], wide_all),
            _ => range_mask(cells, lo, s, wide_all),
        }
    };
    // the characters above U+FFFF that some of the ranges have and others do not
    if pick.wide == Wide::Some && !m.wide.is_empty() {
        let first = set.base + (row * cells.len()) as u32;
        let last = first + cells.len() as u32;
        let i = m.wide.partition_point(|e| e.0 < first);
        for &(pos, cp) in &m.wide[i..] {
            if pos >= last {
                break;
            }
            if pick.wide_in(cp) {
                let t = lo + (pos - first) as usize;
                mask[t >> 6] |= 1u64 << (t & 63);
            }
        }
    }
    mask
}

/// The charsets that have rows (`each_row_matches_walk` checks each one).
pub fn has_rows(k: crate::cjk::Kind) -> bool {
    use crate::cjk::Kind;
    matches!(k, Kind::EucKr | Kind::EucCn | Kind::EucJp | Kind::Uhc | Kind::Gbk | Kind::Big5 | Kind::EucTw | Kind::Gb18030 | Kind::EucJpMs)
}

/// Set the bits of the values `lo..=hi` that fall in `base..base + 64 * bitmap.len()` (bit `v - base`).
fn fill(bitmap: &mut [u64], base: u32, lo: u32, hi: u32) {
    let top = base + (bitmap.len() as u32) * 64 - 1;
    if lo > top || hi < base {
        return;
    }
    let (lo, hi) = ((lo.max(base) - base) as usize, (hi.min(top) - base) as usize);
    // a partial word at each end and whole words between
    for (w, word) in bitmap.iter_mut().enumerate().take((hi >> 6) + 1).skip(lo >> 6) {
        let a = if w == lo >> 6 { lo & 63 } else { 0 };
        let b = if w == hi >> 6 { hi & 63 } else { 63 };
        *word |= (!0u64 >> (63 - (b - a))) << a;
    }
}

/// Do the sorted, disjoint `r` cover 0x80 to 0xfffd (but for the surrogates, which no charset has)?
fn covers_bmp(r: &[(u32, u32)]) -> bool {
    let mut next = 0x80u32;
    for &(lo, hi) in r {
        if hi < next {
            continue;
        }
        if lo > next && !(next >= 0xd800 && lo <= 0xe000) {
            return false;
        }
        next = hi.saturating_add(1);
        if next > 0xfffd {
            return true;
        }
    }
    false
}

/// `f(head, trails)` for every row of two or more bytes of the charset `m`, in byte order, rows without a character left out;
/// `ranges` (sorted, disjoint, non-adjacent) keeps only the characters whose value is in them. False (nothing reported) when
/// the sets are not of the shape the walk below handles.
pub fn each_row(m: &Mb, ranges: Option<&[(u32, u32)]>, f: &mut dyn FnMut(&[u8], &[u64; 4])) -> bool {
    if ranges.is_some_and(<[_]>::is_empty) {
        return true;
    }
    let mut bitmap = [0u64; 1024];
    let mut wide_bits = [0u64; 2048];
    let full = ranges.unwrap_or(&[]);
    let wide = match full.last() {
        _ if ranges.is_none() => Wide::All,
        Some(&(_, hi)) if hi > 0xffff => {
            if full.iter().any(|&(lo, hi)| lo <= 0x10000 && hi >= 0x10ffff) { Wide::All } else { Wide::Some }
        }
        _ => Wide::None,
    };
    let mut pick = Pick { bmp_all: ranges.is_none_or(covers_bmp), small: [(0, 0); 6], nsmall: 0, bitmap: None, full, wide, wide_bits: None };
    if let Some(r) = ranges
        && !pick.bmp_all
    {
        if r.len() <= pick.small.len() {
            for &(lo, hi) in r {
                // (a range from 0xfffe up has no cells)
                if lo < 0xfffe {
                    pick.small[pick.nsmall] = (lo as u16, (hi.min(0xfffd) - lo) as u16);
                    pick.nsmall += 1;
                }
            }
        } else {
            for &(lo, hi) in r {
                fill(&mut bitmap, 0, lo, hi.min(0xfffd));
            }
            // (a cell of 0 is no character; 0xffff is a character above U+FFFF)
            bitmap[0] &= !1;
            if wide == Wide::All {
                bitmap[1023] |= 1u64 << 63;
            }
            pick.bitmap = Some(&bitmap);
        }
    }
    if wide == Wide::Some {
        for &(lo, hi) in full {
            fill(&mut wide_bits, 0x10000, lo, hi);
        }
        pick.wide_bits = Some(&wide_bits);
    }
    walk_sets(m, &pick, f)
}

/// The rows of `m`'s sets of two-byte rectangles in the order of their heads.
fn walk_sets(m: &Mb, pick: &Pick, f: &mut dyn FnMut(&[u8], &[u64; 4])) -> bool {
    let sets = m.sets;
    if sets.iter().any(|s| s.nbytes == 2 && s.plen > 2) {
        return false;
    }
    for b0 in 0..=255u8 {
        for (si, s) in sets.iter().enumerate().filter(|(_, s)| s.nbytes == 2) {
            match s.plen {
                0 => {
                    if (s.lead_lo..=s.lead_hi).contains(&b0) {
                        row(m, s, b0, &[b0], pick, f);
                    }
                }
                1 if s.prefix[0] == b0 => {
                    // (two sets with the same prefix byte would interleave their leads)
                    if sets.iter().enumerate().any(|(j, t)| j != si && t.nbytes == 2 && t.plen == 1 && t.prefix[0] == b0) {
                        return false;
                    }
                    for lead in s.lead_lo..=s.lead_hi {
                        row(m, s, lead, &[b0, lead], pick, f);
                    }
                }
                _ => {}
            }
        }
        if sets.iter().any(|s| s.nbytes == 2 && s.plen == 2 && s.prefix[0] == b0) {
            for b1 in 0..=255u8 {
                for s in sets.iter().filter(|s| s.nbytes == 2 && s.plen == 2 && s.prefix == [b0, b1]) {
                    for lead in s.lead_lo..=s.lead_hi {
                        row(m, s, lead, &[b0, b1, lead], pick, f);
                    }
                }
            }
        }
    }
    true
}

/// The row of lead byte `lead` of `s` (head `head`), if it has characters.
fn row(m: &Mb, s: &Set, lead: u8, head: &[u8], pick: &Pick, f: &mut dyn FnMut(&[u8], &[u64; 4])) {
    let cols = (s.trail_hi - s.trail_lo) as usize + 1;
    let r = (lead - s.lead_lo) as usize;
    let cells = &m.set_data(s)[r * cols..(r + 1) * cols];
    let mask = row_mask(m, s, r, cells, pick);
    if mask != [0; 4] {
        f(head, &mask);
    }
}
