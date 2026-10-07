use crate::engine::*;
use crate::mbdata::big5hkscs::MB;

pub type DecState = u32;
pub type EncState = u32;

pub fn dec(st: &mut DecState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let mut result = St::Empty;
    let (mut i, mut o) = (*ip, *op);
    let (end, cap) = (inp.len(), out.len());
    while i != end {
        if o >= cap {
            result = St::Full;
            break;
        }
        let mut ch = *st >> 3;
        if ch == 0 {
            ch = inp[i] as u32;
            if (0x81..=0xfe).contains(&ch) {
                if i + 1 >= end {
                    result = St::Incomplete;
                    break;
                }
                let b2 = inp[i + 1];
                let found = if ch >= 0x87 && b2 >= 0x40 && b2 <= 0xfe { MB.dec2(1, ch as u8, b2) } else { None };
                match found {
                    Some(c) => {
                        ch = c;
                        i += 2;
                    }
                    None => {
                        let idx = (ch as i32 - 0x87) * 195 + b2 as i32 - 0x40;
                        let combo = match idx {
                            x if x == 195 + 0x22 => Some((0xca, 0x304)),
                            x if x == 195 + 0x24 => Some((0xca, 0x30c)),
                            x if x == 195 + 0x63 => Some((0xea, 0x304)),
                            x if x == 195 + 0x65 => Some((0xea, 0x30c)),
                            _ => None,
                        };
                        match combo {
                            None => {
                                result = St::Illegal;
                                if flags & IGNORE == 0 {
                                    break;
                                }
                                i += 1;
                                *irr += 1;
                                *irr |= crate::engine::ILLEGAL_SEEN;
                                continue;
                            }
                            Some((a, b)) => {
                                i += 2;
                                out[o] = a;
                                o += 1;
                                if o < cap {
                                    out[o] = b;
                                    o += 1;
                                    continue;
                                }
                                *st = (b << 3) | (*st & 7);
                                result = St::Full;
                                break;
                            }
                        }
                    }
                }
            } else if ch == 0xff {
                result = St::Illegal;
                if flags & IGNORE == 0 {
                    break;
                }
                i += 1;
                *irr += 1;
                *irr |= crate::engine::ILLEGAL_SEEN;
                continue;
            } else {
                i += 1;
            }
        } else {
            *st &= 7;
        }
        out[o] = ch;
        o += 1;
    }
    *ip = i;
    *op = o;
    result
}

pub fn enc(st: &mut EncState, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let mut ch = s[0];
        if (*st >> 3) != 0 {
            let lasttwo = *st >> 3;
            let combined = match (ch, lasttwo) {
                (0x304, 0x8866) => Some(0x8862),
                (0x30c, 0x8866) => Some(0x8864),
                (0x304, 0x88a7) => Some(0x88a3),
                (0x30c, 0x88a7) => Some(0x88a5),
                _ => None,
            };
            if o.len() < 2 {
                return EBody::Full;
            }
            return match combined {
                Some(c) => {
                    o[0] = (c >> 8) as u8;
                    o[1] = c as u8;
                    *st &= 7;
                    EBody::Ok(1, 2)
                }
                None => {
                    o[0] = (lasttwo >> 8) as u8;
                    o[1] = lasttwo as u8;
                    *st &= 7;
                    EBody::Ok(0, 2)
                }
            };
        }
        if ch <= 0x80 {
            o[0] = ch as u8;
            return EBody::Ok(1, 1);
        }
        let Some(code) = MB.enc(ch) else {
            return EBody::Illegal;
        };
        if ch == 0xca || ch == 0xea {
            *st = (((code.bytes[0] as u32) << 8 | code.bytes[1] as u32) << 3) | (*st & 7);
            return EBody::Ok(1, 0);
        }
        let n = code.len as usize;
        if n > o.len() {
            return EBody::Full;
        }
        o[..n].copy_from_slice(&code.bytes[..n]);
        ch = 0;
        let _ = ch;
        EBody::Ok(1, n)
    })
}

pub fn enc_emit_reset(st: &mut EncState, out: &mut [u8], op: &mut usize) -> St {
    if (*st >> 3) != 0 {
        if *op + 2 > out.len() {
            return St::Full;
        }
        let l = *st >> 3;
        out[*op] = (l >> 8) as u8;
        out[*op + 1] = l as u8;
        *op += 2;
        *st &= 7;
    }
    St::Ok
}
