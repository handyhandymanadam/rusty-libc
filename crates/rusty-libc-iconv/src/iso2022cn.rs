use crate::engine::*;
use crate::iso2022jp::{GB2312, SetRes, dec_set, gb2312};
use crate::mbdata::euc_tw;

const ESC: u8 = 0x1b;
const SO: u8 = 0x0e;
const SI: u8 = 0x0f;

const ASCII_SET: u8 = 0;
const GB_SET: u8 = 8;
const CNS1_SET: u8 = 16;
const CNS2_SET: u8 = 24;
const SEL_MASK: u32 = 24;
const GB_ANN: u32 = 32;
const CNS1_ANN: u32 = 64;
const CNS2_ANN: u32 = 128;
const ANN_MASK: u32 = 224;

pub type CnState = u32;

pub(crate) fn dec_cns(plane2: bool, s: &[u8]) -> SetRes {
    let b1 = s[0];
    if b1 <= 0x20 || b1 > 0x7d {
        return SetRes::Unknown;
    }
    if s.len() < 2 {
        return SetRes::Incomplete;
    }
    let b2 = s[1];
    if b2 <= 0x20 || b2 >= 0x7f {
        return SetRes::Unknown;
    }
    let m = &euc_tw::MB;
    let r = if plane2 {
        match m.sets.iter().position(|st| st.prefix == [0x8e, 0xa2]) {
            Some(si) => m.dec2(si, b1 | 0x80, b2 | 0x80),
            None => None,
        }
    } else {
        m.dec2(1, b1 | 0x80, b2 | 0x80)
    };
    match r {
        Some(c) => SetRes::Char(c),
        None => SetRes::Unknown,
    }
}

pub fn dec(st: &mut CnState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let (set, ann) = ((*st & SEL_MASK) as u8, *st & ANN_MASK);
        let ch = s[0];
        if ch >= 0x7f {
            return Body::Illegal(1);
        }
        if ch == ESC {
            let n = s.len();
            if n < 2 || (s[1] == b'$' && (n < 3 || (s[2] == b')' && n < 4) || (s[2] == b'*' && n < 4))) || (s[1] == 0x4e && n < 4) {
                return Body::Incomplete;
            }
            if s[1] == b'$' && ((s[2] == b')' && (s[3] == b'A' || s[3] == b'G')) || (s[2] == b'*' && s[3] == b'H')) {
                let mut a = ann;
                if s[3] == b'A' {
                    a = GB_ANN;
                } else if s[3] == b'G' {
                    a = CNS1_ANN;
                }
                *st = (*st & SEL_MASK) | a;
                return Body::Skip(4);
            }
        } else if ch == SO {
            let set = if ann == CNS1_ANN { CNS1_SET } else { GB_SET };
            *st = set as u32 | ann;
            return Body::Skip(1);
        } else if ch == SI {
            *st = ASCII_SET as u32 | ann;
            return Body::Skip(1);
        }
        if ch == ESC && s[1] == 0x4e {
            return match dec_cns(true, &s[2..]) {
                SetRes::Char(c) => Body::Char(c, 4),
                _ => Body::Illegal(2),
            };
        }
        if set == ASCII_SET {
            return Body::Char(ch as u32, 1);
        }
        let r = if set == GB_SET { dec_set(GB2312, s) } else { dec_cns(false, s) };
        match r {
            SetRes::Char(c) => Body::Char(c, 2),
            SetRes::Incomplete => Body::Incomplete,
            SetRes::Unknown => Body::Illegal(1),
        }
    })
}

pub(crate) fn cns1(c: u32) -> Option<[u8; 2]> {
    let x = euc_tw::MB.enc(c)?;
    if x.len == 2 && x.bytes[0] >= 0xa1 && x.bytes[1] >= 0xa1 {
        Some([x.bytes[0] - 0x80, x.bytes[1] - 0x80])
    } else {
        None
    }
}

pub(crate) fn cns2(c: u32) -> Option<[u8; 2]> {
    if let Some(x) = euc_tw::MB.enc(c) {
        if x.len == 4 && x.bytes[0] == 0x8e && x.bytes[1] == 0xa2 {
            return Some([x.bytes[2] - 0x80, x.bytes[3] - 0x80]);
        }
    }
    let m = &euc_tw::MB;
    let s = &m.sets[m.sets.iter().position(|st| st.prefix == [0x8e, 0xa2])?];
    let cols = (s.trail_hi - s.trail_lo) as usize + 1;
    if c > 0xffff {
        for (pos, cp) in m.wide {
            if *cp == c && *pos >= s.base && ((*pos - s.base) as usize) < s.data.len() {
                let i = (*pos - s.base) as usize;
                return Some([(s.lead_lo as usize + i / cols) as u8 - 0x80, (s.trail_lo as usize + i % cols) as u8 - 0x80]);
            }
        }
        return None;
    }
    let want = if c == 0 { 0xfffe } else { c as u16 };
    s.data.iter().position(|&v| v == want).map(|i| [(s.lead_lo as usize + i / cols) as u8 - 0x80, (s.trail_lo as usize + i % cols) as u8 - 0x80])
}

pub fn enc(st: &mut CnState, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        let (set, mut ann) = ((*st & SEL_MASK) as u8, *st & ANN_MASK);
        let mut set = set;
        let save = |st: &mut CnState, set: u8, ann: u32| *st = set as u32 | ann;
        if ch < 0x80 {
            let mut n = 0;
            if set != ASCII_SET {
                o[0] = SI;
                set = ASCII_SET;
                n = 1;
                save(st, set, ann);
                if o.len() == 1 {
                    return EBody::PartialFull(1);
                }
            }
            o[n] = ch as u8;
            if ch == 0x0a {
                ann = 0;
            }
            save(st, set, ann);
            return EBody::Ok(1, n + 1);
        }
        let first = if set == GB_SET || (ann & CNS1_ANN) == 0 { gb2312(ch).map(|c| (GB_SET, c)) } else { cns1(ch).map(|c| (CNS1_SET, c)) };
        let first_set = if set == GB_SET || (ann & CNS1_ANN) == 0 { GB_SET } else { CNS1_SET };
        let (used, buf) = match first {
            Some(x) => x,
            None => {
                if let Some(c) = cns2(ch) {
                    (CNS2_SET, c)
                } else {
                    let other = if first_set == GB_SET { cns1(ch) } else { gb2312(ch) };
                    match other {
                        Some(c) => (GB_SET + CNS1_SET - first_set, c),
                        None => return EBody::Illegal,
                    }
                }
            }
        };
        let mut n = 0usize;
        if set != used {
            if (ann & (16 << (used >> 3))) == 0 {
                if o.len() < 4 {
                    return EBody::Full;
                }
                let esc: &[u8; 2] = match used >> 3 {
                    1 => b")A",
                    2 => b")G",
                    _ => b"*H",
                };
                o[0] = ESC;
                o[1] = b'$';
                o[2] = esc[0];
                o[3] = esc[1];
                n = 4;
                if used == GB_SET {
                    ann = (ann & CNS2_ANN) | GB_ANN;
                } else if used == CNS1_SET {
                    ann = (ann & CNS2_ANN) | CNS1_ANN;
                } else {
                    ann |= CNS2_ANN;
                }
                save(st, set, ann);
            }
            if used == CNS2_SET {
                if o.len() < n + 2 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = ESC;
                o[n + 1] = 0x4e;
                n += 2;
            } else if set == ASCII_SET {
                if o.len() < n + 1 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = SO;
                n += 1;
            }
            if o.len() < n + 2 {
                return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
            }
        } else if o.len() < 2 {
            return EBody::Full;
        }
        o[n] = buf[0];
        o[n + 1] = buf[1];
        n += 2;
        set = used;
        save(st, set, ann);
        EBody::Ok(1, n)
    })
}

pub fn emit_reset(st: &mut CnState, out: &mut [u8], op: &mut usize) -> St {
    if *st != 0 {
        if *op >= out.len() {
            return St::Full;
        }
        out[*op] = SI;
        *op += 1;
        *st = 0;
    }
    St::Ok
}
