
#[derive(Clone, Copy)]
pub struct Collation {
    nrules: u32,
    seqmb: *const u8,
    seqwc: *const u8,
    symb_size: i32,
    symb: *const i32,
    extra: *const u8,
}

const NL_NRULES: usize = 0;
const NL_SYMB_HASH_SIZEMB: usize = 13;
const NL_SYMB_TABLEMB: usize = 14;
const NL_SYMB_EXTRAMB: usize = 15;
const NL_COLLSEQMB: usize = 16;
const NL_COLLSEQWC: usize = 17;

pub const NO_SEQ: u32 = u32::MAX;

impl Collation {
    pub fn current() -> Collation {
        let none = Collation { nrules: 0, seqmb: core::ptr::null(), seqwc: core::ptr::null(), symb_size: 0, symb: core::ptr::null(), extra: core::ptr::null() };
        let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_COLLATE);
        if d.is_null() {
            return none;
        }
        let d = unsafe { &*d };
        if (d.nstrings as usize) <= NL_COLLSEQWC || d.flags & rusty_libc_core::locale::F_BUILTIN_C != 0 {
            return none;
        }
        let nrules = d.word(NL_NRULES);
        let mut c = Collation { nrules, seqmb: d.cstr(NL_COLLSEQMB), ..none };
        if nrules != 0 {
            c.seqwc = d.cstr(NL_COLLSEQWC);
            c.symb_size = d.word(NL_SYMB_HASH_SIZEMB) as i32;
            c.symb = d.cstr(NL_SYMB_TABLEMB) as *const i32;
            c.extra = d.cstr(NL_SYMB_EXTRAMB);
        }
        c
    }

    pub fn nrules(&self) -> u32 {
        self.nrules
    }

    pub fn seq_wc(&self, wc: u32) -> u32 {
        let t = self.seqwc as *const u32;
        unsafe {
            let shift1 = *t;
            let index1 = wc.checked_shr(shift1).unwrap_or(0);
            let bound = *t.add(1);
            if index1 < bound {
                let lookup1 = *t.add(5 + index1 as usize);
                if lookup1 != 0 {
                    let shift2 = *t.add(2);
                    let mask2 = *t.add(3);
                    let index2 = wc.checked_shr(shift2).unwrap_or(0) & mask2;
                    let lookup2 = *(self.seqwc.add(lookup1 as usize) as *const u32).add(index2 as usize);
                    if lookup2 != 0 {
                        let mask3 = *t.add(4);
                        return *(self.seqwc.add(lookup2 as usize) as *const u32).add((wc & mask3) as usize);
                    }
                }
            }
        }
        NO_SEQ
    }

    #[inline]
    pub fn is_byte_identity(&self) -> bool {
        self.nrules == 0 && self.seqmb.is_null()
    }

    pub fn seq_of_byte(&self, ch: u8) -> u32 {
        if self.nrules == 0 {
            return self.seq_mb(ch);
        }
        let wc = unsafe { rusty_libc_wchar::mbyte::btowc(i32::from(ch)) };
        self.seq_wc(wc)
    }

    pub fn seq_mb(&self, ch: u8) -> u32 {
        if self.seqmb.is_null() {
            return u32::from(ch);
        }
        u32::from(unsafe { *self.seqmb.add(ch as usize) })
    }

    pub fn symbol_seq(&self, name: &[u8]) -> Option<u32> {
        if self.nrules == 0 {
            return None;
        }
        unsafe {
            for elem in 0..self.symb_size.max(0) as usize {
                if *self.symb.add(2 * elem) == 0 {
                    continue;
                }
                let mut idx = *self.symb.add(2 * elem + 1) as usize;
                idx += 1 + *self.extra.add(idx) as usize;
                let len = *self.extra.add(idx) as usize;
                if len == name.len() && core::slice::from_raw_parts(self.extra.add(idx + 1), len) == name {
                    idx += 1 + len;
                    idx = (idx + 3) & !3;
                    idx += 4;
                    idx += 4 * (1 + core::ptr::read_unaligned(self.extra.add(idx) as *const u32) as usize);
                    return Some(core::ptr::read_unaligned(self.extra.add(idx) as *const u32));
                }
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
        unsafe {
            for e in 0..self.symb_size.max(0) as usize {
                if *self.symb.add(2 * e) == 0 {
                    continue;
                }
                let mut idx = *self.symb.add(2 * e + 1) as usize;
                idx += 1 + *self.extra.add(idx) as usize;
                let len = *self.extra.add(idx) as usize;
                if len == elem.len() && core::slice::from_raw_parts(self.extra.add(idx + 1), len) == elem {
                    let bytes = core::slice::from_raw_parts(self.extra.add(idx + 1), len);
                    idx += 1 + len;
                    idx = (idx + 3) & !3;
                    return Some((core::ptr::read_unaligned(self.extra.add(idx) as *const u32), bytes));
                }
            }
        }
        None
    }

    pub fn symbol_by_wide(&self, elem: &[u32]) -> Option<(u32, &'static [u32])> {
        if self.nrules == 0 {
            return None;
        }
        unsafe {
            for e in 0..self.symb_size.max(0) as usize {
                if *self.symb.add(2 * e) == 0 {
                    continue;
                }
                let mut idx = *self.symb.add(2 * e + 1) as usize;
                idx += 1 + *self.extra.add(idx) as usize;
                idx += 1 + *self.extra.add(idx) as usize;
                idx = (idx + 3) & !3;
                let w = self.extra.add(idx + 4) as *const u32;
                let len = core::ptr::read_unaligned(w) as usize;
                if len == elem.len() {
                    let mut same = true;
                    for (i, &x) in elem.iter().enumerate() {
                        if core::ptr::read_unaligned(w.add(1 + i)) != x {
                            same = false;
                            break;
                        }
                    }
                    if same {
                        let seq = core::ptr::read_unaligned(w.add(1 + len));
                        return Some((seq, core::slice::from_raw_parts(w.add(1), len)));
                    }
                }
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
        unsafe {
            for e in 0..self.symb_size.max(0) as usize {
                if *self.symb.add(2 * e) == 0 {
                    continue;
                }
                let mut idx = *self.symb.add(2 * e + 1) as usize;
                idx += 1 + *self.extra.add(idx) as usize;
                let len = *self.extra.add(idx) as usize;
                let bytes = core::slice::from_raw_parts(self.extra.add(idx + 1), len);
                idx += 1 + len;
                idx = (idx + 3) & !3;
                idx += 4;
                idx += 4 * (1 + core::ptr::read_unaligned(self.extra.add(idx) as *const u32) as usize);
                f(bytes, core::ptr::read_unaligned(self.extra.add(idx) as *const u32));
            }
        }
    }

    pub fn seq_runs(&self, lo_seq: u32, hi_seq: u32, emit: &mut dyn FnMut(u32, u32)) {
        if self.nrules == 0 || self.seqwc.is_null() {
            return;
        }
        let t = self.seqwc as *const u32;
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
        unsafe {
            let (shift1, bound1, shift2, mask2, mask3) = (*t, *t.add(1), *t.add(2), *t.add(3), *t.add(4));
            for i1 in 0..bound1 {
                let l1 = *t.add(5 + i1 as usize);
                if l1 == 0 {
                    continue;
                }
                let lvl2 = self.seqwc.add(l1 as usize) as *const u32;
                for i2 in 0..=mask2 {
                    let l2 = core::ptr::read_unaligned(lvl2.add(i2 as usize));
                    if l2 == 0 {
                        continue;
                    }
                    let lvl3 = self.seqwc.add(l2 as usize) as *const u32;
                    let base = (i1 << shift1) + (i2 << shift2);
                    for i3 in 0..=mask3 {
                        let v = core::ptr::read_unaligned(lvl3.add(i3 as usize));
                        let wc = base + i3;
                        if v != NO_SEQ && lo_seq <= v && v <= hi_seq && wc >= 0x80 {
                            put(emit, &mut cur, wc);
                        }
                    }
                }
            }
        }
        if let Some((a, b)) = cur {
            emit(a, b);
        }
    }
}
