//! Tables of the multibyte charsets (see tools/gen_mb.py for the layout) and their lookups.

/// One rectangle of codes: single bytes (`nbytes == 1`, the byte is the lead) or two bytes after
/// a prefix. Its data (`Mb::set_data`) is dense, row (lead) major: 0 = no character, 0xfffe = U+0000, 0xffff = a
/// character above U+FFFF (listed in `Mb::wide`). Plain data, no references: the charsets' set tables need no relocation.
pub struct Set {
    /// The prefix bytes (the first `plen`).
    pub prefix: [u8; 2],
    pub plen: u8,
    pub lead_lo: u8,
    pub lead_hi: u8,
    pub trail_lo: u8,
    pub trail_hi: u8,
    pub nbytes: u8,
    /// Position of the first entry in the concatenation of all the sets' data.
    pub base: u32,
    /// Where its data is in `Mb::data` (sets with the same data share it) and how long it is.
    pub data_off: u32,
    pub len: u32,
}

impl Set {
    /// The prefix bytes.
    #[inline]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix[..self.plen as usize]
    }
}

/// The tables of one charset, put together in code by its `mb()` (a static of references would be relocated, page by page,
/// at every start of every program).
#[derive(Clone, Copy)]
pub struct Mb {
    pub sets: &'static [Set],
    /// The data of every set (`Set::data_off`, `Set::len`).
    pub data: &'static [u16],
    /// (position, character) for the entries of 0xffff.
    pub wide: &'static [(u32, u32)],
    /// Characters (sorted) and the positions of their codes; see `extra` for the rest.
    pub enc_cp: &'static [u16],
    pub enc_pos: &'static [u16],
    /// (character, code as a big-endian number, length in bytes), sorted by character.
    pub extra: &'static [(u32, u32, u8)],
    /// Runs (first key, first value, length) of a linear part of the mapping: the four-byte codes of
    /// GB18030 (key = the code's index) to characters, and back (key = character, value = index).
    pub runs_dec: &'static [(u32, u32, u32)],
    pub runs_enc: &'static [(u32, u32, u32)],
}

/// `f()` (a charset's `mb`) out of line, for the arms of a `match` that picks a charset's tables: arms that give the tables
/// themselves become lookup tables of their addresses (relocated at every start), arms that call a function a jump table
/// of relative offsets.
#[inline(never)]
pub fn ool<F: FnOnce() -> Mb>(f: F) -> Mb {
    f()
}

/// The bytes of a character (up to 4).
#[derive(Clone, Copy)]
pub struct Code {
    pub bytes: [u8; 4],
    pub len: u8,
}

fn run_lookup(runs: &[(u32, u32, u32)], key: u32) -> Option<u32> {
    let i = runs.partition_point(|r| r.0 <= key);
    if i == 0 {
        return None;
    }
    let (k, v, n) = runs[i - 1];
    if key - k < n { Some(v + (key - k)) } else { None }
}

impl Mb {
    /// A four-byte GB18030 code's index to its character.
    pub fn dec_run(&self, idx: u32) -> Option<u32> {
        run_lookup(self.runs_dec, idx)
    }

    /// A character's four-byte GB18030 index.
    pub fn enc_run(&self, cp: u32) -> Option<u32> {
        run_lookup(self.runs_enc, cp)
    }

    /// The character of a single byte (set 0 must be the single-byte set).
    #[inline]
    pub fn dec1(&self, b: u8) -> Option<u32> {
        self.entry(&self.sets[0], b as usize)
    }

    /// The data of set `s`.
    #[inline]
    pub fn set_data(&self, s: &Set) -> &'static [u16] {
        &self.data[s.data_off as usize..(s.data_off + s.len) as usize]
    }

    #[inline]
    fn entry(&self, set: &Set, idx: usize) -> Option<u32> {
        match self.set_data(set)[idx] {
            0 => None,
            0xfffe => Some(0),
            0xffff => {
                let pos = set.base + idx as u32;
                let i = self.wide.binary_search_by(|e| e.0.cmp(&pos)).ok()?;
                Some(self.wide[i].1)
            }
            v => Some(v as u32),
        }
    }

    /// The character of the two bytes `b1 b2` in set `set`.
    #[inline]
    pub fn dec2(&self, set: usize, b1: u8, b2: u8) -> Option<u32> {
        let s = &self.sets[set];
        if b1 < s.lead_lo || b1 > s.lead_hi || b2 < s.trail_lo || b2 > s.trail_hi {
            return None;
        }
        let cols = (s.trail_hi - s.trail_lo) as usize + 1;
        self.entry(s, (b1 - s.lead_lo) as usize * cols + (b2 - s.trail_lo) as usize)
    }

    /// The code of a character.
    pub fn enc(&self, cp: u32) -> Option<Code> {
        if cp <= 0xffff {
            if let Ok(i) = self.enc_cp.binary_search(&(cp as u16)) {
                let pos = self.enc_pos[i] as u32;
                let si = self.sets.partition_point(|s| s.base <= pos) - 1;
                let s = &self.sets[si];
                let off = (pos - s.base) as usize;
                let mut c = Code { bytes: [0; 4], len: 0 };
                for &p in s.prefix() {
                    c.bytes[c.len as usize] = p;
                    c.len += 1;
                }
                if s.nbytes == 1 {
                    c.bytes[c.len as usize] = s.lead_lo + off as u8;
                    c.len += 1;
                } else {
                    let cols = (s.trail_hi - s.trail_lo) as usize + 1;
                    c.bytes[c.len as usize] = s.lead_lo + (off / cols) as u8;
                    c.bytes[c.len as usize + 1] = s.trail_lo + (off % cols) as u8;
                    c.len += 2;
                }
                return Some(c);
            }
        }
        let i = self.extra.binary_search_by(|e| e.0.cmp(&cp)).ok()?;
        let (_, code, len) = self.extra[i];
        let b = code.to_be_bytes();
        let mut c = Code { bytes: [0; 4], len };
        c.bytes[..len as usize].copy_from_slice(&b[4 - len as usize..]);
        Some(c)
    }
}
