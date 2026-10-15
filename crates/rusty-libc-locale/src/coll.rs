use crate::data::{as_i32, as_u32, item};
use crate::mem::rd32;


#[derive(Clone, Copy)]
pub struct Collation {
    nrules: u32,
    seqmb: Option<&'static [u8]>,
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

pub const NO_SEQ: u32 = u32::MAX;

#[inline(always)]
fn byte(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

impl Collation {
    pub fn current() -> Collation {
        let none = Collation { nrules: 0, seqmb: None, seqwc: None, symb_size: 0, symb: &[], extra: &[] };
        let Some(d) = crate::data::current_cat(rusty_libc_core::locale::LC_COLLATE) else { return none };
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

    pub fn nrules(&self) -> u32 {
        self.nrules
    }

    pub fn seq_wc(&self, wc: u32) -> u32 {
        let tb = self.seqwc.unwrap_or(&[]);
        let t = |k: usize| rd32(tb, 4 * k);
        let shift1 = t(0);
        let index1 = wc.checked_shr(shift1).unwrap_or(0);
        let bound = t(1);
        if index1 < bound {
            let lookup1 = t(5 + index1 as usize);
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

    #[inline]
    pub fn is_byte_identity(&self) -> bool {
        self.nrules == 0 && self.seqmb.is_none()
    }

    pub fn seq_of_byte(&self, ch: u8) -> u32 {
        if self.nrules == 0 {
            return self.seq_mb(ch);
        }
        let wc = unsafe { rusty_libc_wchar::mbyte::btowc(i32::from(ch)) };
        self.seq_wc(wc)
    }

    pub fn seq_mb(&self, ch: u8) -> u32 {
        match self.seqmb {
            None => u32::from(ch),
            Some(t) => u32::from(byte(t, ch as usize)),
        }
    }

    fn entries(&self) -> impl Iterator<Item = usize> + '_ {
        self.symb.as_chunks::<2>().0.iter().take(self.symb_size.max(0) as usize).filter(|e| e[0] != 0).map(|e| e[1] as usize)
    }

    pub fn symbol_seq(&self, name: &[u8]) -> Option<u32> {
        if self.nrules == 0 {
            return None;
        }
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize;
            let len = byte(ex, idx) as usize;
            if len == name.len() && ex.get(idx + 1..idx + 1 + len) == Some(name) {
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
    pub fn symbol_by_bytes(&self, elem: &[u8]) -> Option<(u32, &'static [u8])> {
        if self.nrules == 0 {
            return None;
        }
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize;
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

    pub fn symbol_by_wide(&self, elem: &[u32]) -> Option<(u32, &'static [u32])> {
        if self.nrules == 0 {
            return None;
        }
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize;
            idx += 1 + byte(ex, idx) as usize;
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
    pub fn symbol_elem(&self, name: &[u8]) -> Option<&'static [u8]> {
        self.symbol_by_bytes(name).map(|(_, bytes)| bytes)
    }
}

impl Collation {
    pub fn each_element(&self, f: &mut dyn FnMut(&'static [u8], u32)) {
        if self.nrules == 0 {
            return;
        }
        let ex = self.extra;
        for mut idx in self.entries() {
            idx += 1 + byte(ex, idx) as usize;
            let len = byte(ex, idx) as usize;
            let bytes = ex.get(idx + 1..idx + 1 + len).unwrap_or(&[]);
            idx += 1 + len;
            idx = (idx + 3) & !3;
            idx += 4;
            idx += 4 * (1 + rd32(ex, idx) as usize);
            f(bytes, rd32(ex, idx));
        }
    }

    pub fn seq_runs(&self, lo_seq: u32, hi_seq: u32, emit: &mut dyn FnMut(u32, u32)) {
        let Some(tb) = self.seqwc else { return };
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
        let (shift1, bound1, shift2, mask2, mask3) = (t(0), t(1), t(2), t(3), t(4));
        for i1 in 0..bound1 {
            let l1 = t(5 + i1 as usize);
            if l1 == 0 {
                continue;
            }
            for i2 in 0..=mask2 {
                let l2 = rd32(tb, l1 as usize + 4 * i2 as usize);
                if l2 == 0 {
                    continue;
                }
                let base = (i1 << shift1) + (i2 << shift2);
                let words = (mask3 as usize).wrapping_add(1);
                let Some(lvl3) = tb.get(l2 as usize..(l2 as usize).saturating_add(words.saturating_mul(4))) else { continue };
                for (i3, wbytes) in lvl3.as_chunks::<4>().0.iter().enumerate() {
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
