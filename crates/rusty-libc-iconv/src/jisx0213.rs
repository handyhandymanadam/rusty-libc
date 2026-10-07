use crate::engine::*;
use crate::mb::Mb;
use crate::mbdata::{euc_jisx0213 as e, shift_jisx0213 as s};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Euc,
    Sjis,
}

pub type DecState = u32;
pub type EncState = u32;

type Tables = (&'static Mb, &'static [(u32, u32, u32)], &'static [u32]);

fn tables(k: Kind) -> Tables {
    match k {
        Kind::Euc => (&e::MB, &e::COMBOS, &e::BUFFERED),
        Kind::Sjis => (&s::MB, &s::COMBOS, &s::BUFFERED),
    }
}

pub fn dec(k: Kind, st: &mut DecState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let (mb, combos, _) = tables(k);
    let mut result = St::Empty;
    let (mut i, mut o) = (*ip, *op);
    let (end, cap) = (inp.len(), out.len());
    macro_rules! illegal {
        ($n:expr) => {{
            result = St::Illegal;
            if flags & IGNORE == 0 {
                break;
            }
            i += $n;
            *irr += 1;
            *irr |= crate::engine::ILLEGAL_SEEN;
            continue;
        }};
    }
    while i != end {
        if o >= cap {
            result = St::Full;
            break;
        }
        let mut ch = *st >> 3;
        if ch == 0 {
            let b = inp[i];
            let mut two: Option<(u32, u32)> = None;
            match k {
                Kind::Euc => {
                    if b < 0x80 {
                        ch = b as u32;
                        i += 1;
                    } else if (0xa1..=0xfe).contains(&b) || b == 0x8e || b == 0x8f {
                        if i + 1 >= end {
                            result = St::Incomplete;
                            break;
                        }
                        let b2 = inp[i + 1];
                        if b2 < 0xa1 || b2 > 0xfe {
                            illegal!(1);
                        }
                        if b == 0x8e {
                            if b2 > 0xdf {
                                illegal!(1);
                            }
                            ch = b2 as u32 + 0xfec0;
                            i += 2;
                        } else {
                            let (r, n, code) = if b == 0x8f {
                                if i + 2 >= end {
                                    result = St::Incomplete;
                                    break;
                                }
                                (mb.dec2(3, b2, inp[i + 2]), 3, 0)
                            } else {
                                (mb.dec2(2, b, b2), 2, (b as u32) << 8 | b2 as u32)
                            };
                            match r {
                                Some(c) => ch = c,
                                None => match combos.iter().find(|x| x.0 == code && n == 2) {
                                    Some(&(_, u1, u2)) => two = Some((u1, u2)),
                                    None => illegal!(1),
                                },
                            }
                            i += n;
                        }
                    } else {
                        illegal!(1);
                    }
                }
                Kind::Sjis => {
                    if b < 0x80 || (0xa1..=0xdf).contains(&b) {
                        ch = mb.dec1(b).unwrap_or(b as u32);
                        i += 1;
                    } else if (0x81..=0x9f).contains(&b) || (0xe0..=0xfc).contains(&b) {
                        if i + 1 >= end {
                            result = St::Incomplete;
                            break;
                        }
                        let b2 = inp[i + 1];
                        if b2 < 0x40 || b2 == 0x7f || b2 > 0xfc {
                            illegal!(1);
                        }
                        match mb.dec2(1, b, b2) {
                            Some(c) => ch = c,
                            None => {
                                let code = (b as u32) << 8 | b2 as u32;
                                match combos.iter().find(|x| x.0 == code) {
                                    Some(&(_, u1, u2)) => two = Some((u1, u2)),
                                    None => illegal!(1),
                                }
                            }
                        }
                        i += 2;
                    } else {
                        illegal!(1);
                    }
                }
            }
            if let Some((u1, u2)) = two {
                out[o] = u1;
                o += 1;
                if o < cap {
                    out[o] = u2;
                    o += 1;
                    continue;
                }
                *st = (u2 << 3) | (*st & 7);
                result = St::Full;
                break;
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

const MARKS: [u32; 5] = [0x02e5, 0x02e9, 0x0300, 0x0301, 0x309a];

pub fn enc(k: Kind, st: &mut EncState, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let (mb, combos, buffered) = tables(k);
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        if (*st >> 3) != 0 {
            let lasttwo = *st >> 3;
            let mut composed = None;
            if MARKS.contains(&ch) {
                for &(code, u1, u2) in combos {
                    if u2 == ch && mb.enc(u1).is_some_and(|c| c.len == 2 && ((c.bytes[0] as u32) << 8 | c.bytes[1] as u32) == lasttwo) {
                        composed = Some(code);
                        break;
                    }
                }
            }
            if o.len() < 2 {
                return EBody::Full;
            }
            return match composed {
                Some(c) => {
                    o[0] = (c >> 8) as u8;
                    o[1] = c as u8;
                    *st = 0;
                    EBody::Ok(1, 2)
                }
                None => {
                    o[0] = (lasttwo >> 8) as u8;
                    o[1] = lasttwo as u8;
                    *st = 0;
                    EBody::Ok(0, 2)
                }
            };
        }
        if ch < 0x80 && !(k == Kind::Sjis && (ch == 0x5c || ch == 0x7e)) {
            o[0] = ch as u8;
            return EBody::Ok(1, 1);
        }
        if k == Kind::Sjis {
            if ch == 0xa5 || ch == 0x203e {
                o[0] = if ch == 0xa5 { 0x5c } else { 0x7e };
                return EBody::Ok(1, 1);
            }
            if (0xff61..=0xff9f).contains(&ch) {
                o[0] = (ch - 0xfec0) as u8;
                return EBody::Ok(1, 1);
            }
        } else if (0xff61..=0xff9f).contains(&ch) {
            if o.len() < 2 {
                return EBody::Full;
            }
            o[0] = 0x8e;
            o[1] = (ch - 0xfec0) as u8;
            return EBody::Ok(1, 2);
        }
        let Some(code) = mb.enc(ch) else {
            return EBody::Illegal;
        };
        if buffered.binary_search(&ch).is_ok() {
            *st = ((code.bytes[0] as u32) << 8 | code.bytes[1] as u32) << 3;
            return EBody::Ok(1, 0);
        }
        let n = code.len as usize;
        if o.len() < n {
            return EBody::Full;
        }
        o[..n].copy_from_slice(&code.bytes[..n]);
        EBody::Ok(1, n)
    })
}

pub fn enc_emit_reset(st: &mut EncState, out: &mut [u8], op: &mut usize) -> St {
    if *st != 0 {
        if *op + 2 > out.len() {
            return St::Full;
        }
        let l = *st >> 3;
        out[*op] = (l >> 8) as u8;
        out[*op + 1] = l as u8;
        *op += 2;
        *st = 0;
    }
    St::Ok
}
