pub struct Set {
    pub prefix: &'static [u8],
    pub lead_lo: u8,
    pub lead_hi: u8,
    pub trail_lo: u8,
    pub trail_hi: u8,
    pub nbytes: u8,
    pub base: u32,
    pub data: &'static [u16],
}

pub struct Mb {
    pub sets: &'static [Set],
    pub wide: &'static [(u32, u32)],
    pub enc_cp: &'static [u16],
    pub enc_pos: &'static [u16],
    pub extra: &'static [(u32, u32, u8)],
    pub runs_dec: &'static [(u32, u32, u32)],
    pub runs_enc: &'static [(u32, u32, u32)],
}

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
    pub fn dec_run(&self, idx: u32) -> Option<u32> {
        run_lookup(self.runs_dec, idx)
    }

    pub fn enc_run(&self, cp: u32) -> Option<u32> {
        run_lookup(self.runs_enc, cp)
    }

    #[inline]
    pub fn dec1(&self, b: u8) -> Option<u32> {
        self.entry(&self.sets[0], b as usize)
    }

    #[inline]
    fn entry(&self, set: &Set, idx: usize) -> Option<u32> {
        match set.data[idx] {
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

    #[inline]
    pub fn dec2(&self, set: usize, b1: u8, b2: u8) -> Option<u32> {
        let s = &self.sets[set];
        if b1 < s.lead_lo || b1 > s.lead_hi || b2 < s.trail_lo || b2 > s.trail_hi {
            return None;
        }
        let cols = (s.trail_hi - s.trail_lo) as usize + 1;
        self.entry(s, (b1 - s.lead_lo) as usize * cols + (b2 - s.trail_lo) as usize)
    }

    pub fn enc(&self, cp: u32) -> Option<Code> {
        if cp <= 0xffff {
            if let Ok(i) = self.enc_cp.binary_search(&(cp as u16)) {
                let pos = self.enc_pos[i] as u32;
                let si = self.sets.partition_point(|s| s.base <= pos) - 1;
                let s = &self.sets[si];
                let off = (pos - s.base) as usize;
                let mut c = Code { bytes: [0; 4], len: 0 };
                for &p in s.prefix {
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
