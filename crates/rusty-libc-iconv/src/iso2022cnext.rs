use crate::engine::*;
use crate::iso2022cn::{cns1, cns2, dec_cns};
use crate::iso2022jp::{GB2312, SetRes, dec_set, gb2312};
use crate::mbdata::{euc_tw, isoir165};

const ESC: u8 = 0x1b;
const SO: u8 = 0x0e;
const SI: u8 = 0x0f;

const ASCII_SET: u32 = 0;
const GB2312_SET: u32 = 1;
const CNS1_SET: u32 = 3;
const IR165_SET: u32 = 4;
const CNS2_SET: u32 = 3 << 3;
const CNS3_SET: u32 = 3 << 5;
const CNS7_SET: u32 = 7 << 5;
const CURRENT_MASK: u32 = 7 | (3 << 3) | (7 << 5);

const GB2312_ANN: u32 = 1 << 8;
const CNS1_ANN: u32 = 3 << 8;
const IR165_ANN: u32 = 4 << 8;
const SO_ANN: u32 = 7 << 8;
const CNS2_ANN: u32 = 3 << 11;
const SS2_ANN: u32 = 3 << 11;
const SS3_ANN: u32 = 7 << 13;

pub type CnExtState = u32;

#[inline]
fn split(st: u32) -> (u32, u32) {
    let v = st >> 3;
    (v & CURRENT_MASK, v & !CURRENT_MASK)
}

#[inline]
fn join(set: u32, ann: u32) -> u32 {
    (set | ann) << 3
}

fn ir165_dec(s: &[u8]) -> SetRes {
    let (b1, b2) = (s[0], s[1]);
    if b1 <= 0x20 || b1 >= 0x7f || b2 <= 0x20 || b2 >= 0x7f {
        return SetRes::Unknown;
    }
    match isoir165::MB.dec2(1, b1, b2) {
        Some(c) => SetRes::Char(c),
        None => SetRes::Unknown,
    }
}

fn ir165_enc(c: u32) -> Option<[u8; 2]> {
    let x = isoir165::MB.enc(c)?;
    if x.len == 2 { Some([x.bytes[0], x.bytes[1]]) } else { None }
}

fn dec_plane(plane: u8, b1: u8, b2: u8) -> Option<u32> {
    if b1 <= 0x20 || b1 >= 0x7f || b2 <= 0x20 || b2 >= 0x7f {
        return None;
    }
    let m = &euc_tw::MB;
    let si = m.sets.iter().position(|st| st.prefix == [0x8e, 0xa0 + plane])?;
    m.dec2(si, b1 | 0x80, b2 | 0x80)
}

fn enc_plane(c: u32) -> Option<(u32, [u8; 2])> {
    let x = euc_tw::MB.enc(c)?;
    if x.len == 4 && x.bytes[0] == 0x8e && (0xa3..=0xa7).contains(&x.bytes[1]) {
        Some(((x.bytes[1] - 0xa0) as u32, [x.bytes[2] - 0x80, x.bytes[3] - 0x80]))
    } else {
        None
    }
}

pub fn dec(st: &mut CnExtState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let (mut set, mut ann) = split(*st);
        let ch = s[0];
        if ch > 0x7f {
            return Body::Illegal(1);
        }
        if ch == ESC {
            let n = s.len();
            if n < 2
                || (s[1] == b'$' && (n < 3 || (matches!(s[2], b')' | b'*' | b'+') && n < 4)))
                || ((s[1] == 0x4e || s[1] == 0x4f) && n < 4)
            {
                return Body::Incomplete;
            }
            if s[1] == b'$' {
                let (kind, f) = (s[2], if n >= 4 { s[3] } else { 0 });
                let ok = match kind {
                    b')' => matches!(f, b'A' | b'E' | b'G'),
                    b'*' => f == b'H',
                    b'+' => matches!(f, b'I' | b'J' | b'K' | b'L' | b'M'),
                    _ => false,
                };
                if ok {
                    match f {
                        b'A' => ann = (ann & !SO_ANN) | GB2312_ANN,
                        b'G' => ann = (ann & !SO_ANN) | CNS1_ANN,
                        b'E' => ann = (ann & !SO_ANN) | IR165_ANN,
                        b'H' => ann = (ann & !SS2_ANN) | CNS2_ANN,
                        _ => ann = (ann & !SS3_ANN) | (((f - b'I') as u32 + 3) << 13),
                    }
                    *st = join(set, ann);
                    return Body::Skip(4);
                }
            }
        } else if ch == SO {
            return match ann & SO_ANN {
                0 => Body::IllegalAfter(1, 1),
                a => {
                    set = a >> 8;
                    *st = join(set, ann);
                    Body::Skip(1)
                }
            };
        } else if ch == SI {
            set = ASCII_SET;
            *st = join(set, ann);
            return Body::Skip(1);
        }
        if ch == ESC && s[1] == 0x4e {
            return match dec_cns(true, &s[2..4]) {
                SetRes::Char(c) => Body::Char(c, 4),
                _ => Body::IllegalAfter(2, 2),
            };
        }
        if ch == ESC && s[1] == 0x4f {
            let plane = match ann & SS3_ANN {
                a if a >= (3 << 13) && a <= (7 << 13) => (a >> 13) as u8,
                _ => return Body::Illegal(4),
            };
            return match dec_plane(plane, s[2], s[3]) {
                Some(c) => Body::Char(c, 4),
                None => Body::Illegal(4),
            };
        }
        if set == ASCII_SET {
            return Body::Char(ch as u32, 1);
        }
        if s.len() < 2 {
            return Body::Incomplete;
        }
        let r = if set == GB2312_SET {
            dec_set(GB2312, s)
        } else if set == IR165_SET {
            ir165_dec(s)
        } else {
            dec_cns(false, s)
        };
        match r {
            SetRes::Char(c) => Body::Char(c, 2),
            SetRes::Incomplete => Body::Incomplete,
            SetRes::Unknown => Body::Illegal(2),
        }
    })
}

pub fn enc(st: &mut CnExtState, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        let (mut set, mut ann) = split(*st);
        if ch < 0x80 {
            let mut n = 0;
            if set != ASCII_SET {
                o[0] = SI;
                set = ASCII_SET;
                n = 1;
                *st = join(set, ann);
                if o.len() == 1 {
                    return EBody::PartialFull(1);
                }
            }
            o[n] = ch as u8;
            if ch == 0x0a {
                ann = 0;
            }
            *st = join(set, ann);
            return EBody::Ok(1, n + 1);
        }
        let so_ann = ann & SO_ANN;
        let (mut buf, mut used) = if set == GB2312_SET || (so_ann != CNS1_ANN && so_ann != IR165_ANN) {
            (gb2312(ch), GB2312_SET)
        } else if set == IR165_SET {
            (ir165_enc(ch), IR165_SET)
        } else {
            (cns1(ch), CNS1_SET)
        };
        if buf.is_none() {
            if let Some(c) = cns2(ch) {
                buf = Some(c);
                used = CNS2_SET;
            } else {
                if used != GB2312_SET {
                    buf = gb2312(ch);
                    if buf.is_some() {
                        used = GB2312_SET;
                    }
                }
                if buf.is_none() && used != IR165_SET {
                    buf = ir165_enc(ch);
                    if buf.is_some() {
                        used = IR165_SET;
                    }
                }
                if buf.is_none() && used != CNS1_SET {
                    buf = cns1(ch);
                    if buf.is_some() {
                        used = CNS1_SET;
                    }
                }
                if buf.is_none() {
                    if let Some((plane, b)) = enc_plane(ch) {
                        buf = Some(b);
                        used = plane << 5;
                    }
                }
                if buf.is_none() {
                    return EBody::Illegal;
                }
            }
        }
        let buf = buf.unwrap();
        let mut n = 0usize;
        if set != used {
            let (need, esc): (bool, &[u8; 2]) = if (used & 7) != 0 {
                ((ann & SO_ANN) != (used << 8), match used {
                    GB2312_SET => b")A",
                    CNS1_SET => b")G",
                    _ => b")E",
                })
            } else if (used & (3 << 3)) != 0 {
                ((ann & SS2_ANN) != (used << 8), b"*H")
            } else {
                ((ann & SS3_ANN) != (used << 8), match used >> 5 {
                    3 => b"+I",
                    4 => b"+J",
                    5 => b"+K",
                    6 => b"+L",
                    _ => b"+M",
                })
            };
            if need {
                if o.len() < 4 {
                    return EBody::Full;
                }
                o[0] = ESC;
                o[1] = b'$';
                o[2] = esc[0];
                o[3] = esc[1];
                n = 4;
                if (used & 7) != 0 {
                    ann = (ann & !SO_ANN) | (used << 8);
                } else if (used & (3 << 3)) != 0 {
                    ann = (ann & !SS2_ANN) | (used << 8);
                } else {
                    ann = (ann & !SS3_ANN) | (used << 8);
                }
                *st = join(set, ann);
            }
            let shift: Option<[u8; 2]> = if used == CNS2_SET {
                Some([ESC, 0x4e])
            } else if (CNS3_SET..=CNS7_SET).contains(&used) {
                Some([ESC, 0x4f])
            } else {
                None
            };
            if let Some(sh) = shift {
                if o.len() < n + 2 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = sh[0];
                o[n + 1] = sh[1];
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
        *st = join(set, ann);
        EBody::Ok(1, n)
    })
}

pub fn emit_reset(st: &mut CnExtState, out: &mut [u8], op: &mut usize) -> St {
    if *st >> 3 != ASCII_SET {
        if *op >= out.len() {
            return St::Full;
        }
        out[*op] = SI;
        *op += 1;
        *st = 0;
    }
    St::Ok
}
