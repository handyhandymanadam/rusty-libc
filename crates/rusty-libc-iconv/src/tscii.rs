use crate::engine::*;
use crate::tsciidata::*;

const NEXT: [u32; 6] = [0, 0x0BB7 << 8, 0x0BC0 << 8, 0x0BCD << 8, (0x0BB0 << 8) + (2 << 4), (0x0BB7 << 8) + (3 << 4)];

pub fn pending(st: u32) -> ([u32; 4], usize) {
    let mut out = [0u32; 4];
    let (mut n, mut st) = (0, st);
    while st != 0 && n < 4 {
        out[n] = st >> 8;
        n += 1;
        st = NEXT[((st >> 4) & 0xf) as usize % 6];
    }
    (out, n)
}

pub fn dec(st: &mut u32, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let mut result = St::Empty;
    let mut i = *ip;
    let mut o = *op;
    let end = inp.len();
    let cap = out.len();
    'outer: while i != end {
        if o >= cap {
            result = St::Full;
            break;
        }
        let mut ch = inp[i] as u32;
        if (*st >> 8) != 0 {
            let last = *st >> 8;
            if last == 0x0BCD && (*st & (1 << 3)) != 0 {
                if ch == 0xa4 || ch == 0xa5 {
                    out[o] = ch + 0xb1d;
                    o += 1;
                    *st = 0;
                    i += 1;
                    continue;
                }
            } else if (0x0BC6..=0x0BC8).contains(&last) {
                if (last == 0x0BC6 && ch == 0xa1) || (last == 0x0BC7 && (ch == 0xa1 || ch == 0xaa)) {
                    out[o] = last + 4 + (ch != 0xa1) as u32;
                    o += 1;
                    *st = 0;
                    i += 1;
                    continue;
                }
                if (0xb8..=0xc9).contains(&ch) && (*st & (1 << 3)) == 0 {
                    out[o] = TO_UCS4[(ch - 0x80) as usize][0] as u32;
                    o += 1;
                    *st |= 1 << 3;
                    i += 1;
                    continue;
                }
            }
            loop {
                out[o] = last;
                o += 1;
                *st = NEXT[((*st >> 4) & 0xf) as usize % 6];
                if !(*st != 0 && o < cap) {
                    break;
                }
            }
            if *st != 0 {
                result = St::Full;
                break;
            }
            continue;
        }
        if ch < 0x80 {
            out[o] = ch;
            o += 1;
            i += 1;
            continue;
        }
        let u1 = TO_UCS4[(ch - 0x80) as usize][0] as u32;
        if u1 != 0 {
            let u2 = TO_UCS4[(ch - 0x80) as usize][1] as u32;
            i += 1;
            out[o] = u1;
            o += 1;
            if u2 != 0 {
                if o >= cap {
                    *st = u2 << 8;
                    result = St::Full;
                    break;
                }
                out[o] = u2;
                o += 1;
            }
            continue;
        }
        match ch {
            0xa6..=0xa8 => {
                ch += 0x0b20;
                *st = ch << 8;
                i += 1;
            }
            0x8a | 0x8b => {
                out[o] = ch + 0x0b2e;
                o += 1;
                *st = (0x0BCD << 8) + (1 << 3);
                i += 1;
            }
            0x82 | 0x87 | 0x8c => {
                let (run, states): (&[u32], &[u32]) = match ch {
                    0x82 => (&[0x0BB8, 0x0BCD, 0x0BB0, 0x0BC0], &[0, (0x0BCD << 8) + (4 << 4), (0x0BB0 << 8) + (2 << 4), 0x0BC0 << 8]),
                    0x87 => (&[0x0B95, 0x0BCD, 0x0BB7], &[0, (0x0BCD << 8) + (1 << 4), 0x0BB7 << 8]),
                    _ => (&[0x0B95, 0x0BCD, 0x0BB7, 0x0BCD], &[0, (0x0BCD << 8) + (5 << 4), (0x0BB7 << 8) + (3 << 4), 0x0BCD << 8]),
                };
                i += 1;
                out[o] = run[0];
                o += 1;
                for k in 1..run.len() {
                    if o >= cap {
                        *st = states[k];
                        result = St::Full;
                        break 'outer;
                    }
                    out[o] = run[k];
                    o += 1;
                }
            }
            _ => {
                result = St::Illegal;
                if flags & IGNORE == 0 {
                    break;
                }
                i += 1;
                *irr += 1;
                *irr |= ILLEGAL_SEEN;
            }
        }
    }
    *ip = i;
    *op = o;
    result
}

#[inline]
fn is_cons(t: u32) -> bool {
    (0xb8..=0xc9).contains(&t)
}

pub fn enc(st: &mut u32, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        if (*st >> 3) != 0 {
            let last = *st >> 3;
            if is_cons(last) {
                let idx = (last - 0xb8) as usize;
                match ch {
                    0x0BC1 => {
                        o[0] = CONSONANT_WITH_U[idx];
                        *st = 0;
                        return EBody::Ok(1, 1);
                    }
                    0x0BC2 => {
                        o[0] = CONSONANT_WITH_UU[idx];
                        *st = 0;
                        return EBody::Ok(1, 1);
                    }
                    0x0BC6..=0x0BC8 => {
                        if o.len() < 2 {
                            return EBody::Full;
                        }
                        o[0] = 0xa6 + (ch - 0x0BC6) as u8;
                        o[1] = last as u8;
                        *st = 0;
                        return EBody::Ok(1, 2);
                    }
                    0x0BCA..=0x0BCC => {
                        if o.len() < 3 {
                            return EBody::Full;
                        }
                        o[0] = if ch == 0x0BCA { 0xa6 } else { 0xa7 };
                        o[1] = last as u8;
                        o[2] = if ch == 0x0BCC { 0xaa } else { 0xa1 };
                        *st = 0;
                        return EBody::Ok(1, 3);
                    }
                    0x0BCD => {
                        let wrote = if last != 0xb8 {
                            o[0] = CONSONANT_WITH_VIRAMA[idx];
                            *st = 0;
                            1
                        } else {
                            *st = 0xec << 3;
                            0
                        };
                        return EBody::Ok(1, wrote);
                    }
                    0x0BBF | 0x0BC0 if last == 0xbc => {
                        o[0] = (ch - 0x0af5) as u8;
                        *st = 0;
                        return EBody::Ok(1, 1);
                    }
                    _ => {}
                }
            } else if (0x83..=0x86).contains(&last) {
                if last >= 0x85 && (ch == 0x0BC1 || ch == 0x0BC2) {
                    o[0] = (last + 5) as u8;
                    *st = 0;
                    return EBody::Ok(0, 1);
                }
                if ch == 0x0BCD {
                    if last != 0x85 {
                        o[0] = (last + 5) as u8;
                        *st = 0;
                        return EBody::Ok(1, 1);
                    }
                    *st = 0x8a << 3;
                    return EBody::Ok(1, 0);
                }
            } else if last == 0xec {
                if ch == 0x0BB7 {
                    *st = 0x87 << 3;
                    return EBody::Ok(1, 0);
                }
            } else if last == 0x8a {
                if ch == 0x0BB0 {
                    *st = 0xc38a << 3;
                    return EBody::Ok(1, 0);
                }
            } else if last == 0x87 {
                if ch == 0x0BCD {
                    o[0] = 0x8c;
                    *st = 0;
                    return EBody::Ok(1, 1);
                }
            } else if ch == 0x0BC0 {
                o[0] = 0x82;
                *st = 0;
                return EBody::Ok(1, 1);
            }
            let n = if (last >> 8) != 0 {
                if o.len() < 2 {
                    return EBody::Full;
                }
                o[0] = (last & 0xff) as u8;
                o[1] = ((last >> 8) & 0xff) as u8;
                2
            } else {
                o[0] = (last & 0xff) as u8;
                1
            };
            *st = 0;
            return EBody::Ok(0, n);
        }
        if ch < 0x80 {
            o[0] = ch as u8;
            return EBody::Ok(1, 1);
        }
        if (0x0B80..=0x0BFF).contains(&ch) {
            let t = UCS4_TO_TSCII[(ch - 0x0B80) as usize] as u32;
            if t != 0 {
                if is_cons(t) || (0x83..=0x86).contains(&t) {
                    *st = t << 3;
                    return EBody::Ok(1, 0);
                }
                o[0] = t as u8;
                return EBody::Ok(1, 1);
            }
            if (0x0BCA..=0x0BCC).contains(&ch) {
                if o.len() < 2 {
                    return EBody::Full;
                }
                o[0] = if ch == 0x0BCA { 0xa6 } else { 0xa7 };
                o[1] = if ch != 0x0BCC { 0xa1 } else { 0xaa };
                return EBody::Ok(1, 2);
            }
            return EBody::Illegal;
        }
        match ch {
            0x00A9 => o[0] = 0xa9,
            0x2018 | 0x2019 => o[0] = (ch - 0x1f87) as u8,
            0x201C | 0x201D => o[0] = (ch - 0x1f89) as u8,
            _ => return EBody::Illegal,
        }
        EBody::Ok(1, 1)
    })
}

pub fn emit_reset(st: &mut u32, out: &mut [u8], op: &mut usize) -> St {
    if *st != 0 {
        let last = *st >> 3;
        if (last >> 8) != 0 {
            if *op + 2 <= out.len() {
                out[*op] = (last & 0xff) as u8;
                out[*op + 1] = ((last >> 8) & 0xff) as u8;
                *op += 2;
                *st = 0;
            } else {
                return St::Full;
            }
        } else if *op < out.len() {
            out[*op] = (last & 0xff) as u8;
            *op += 1;
            *st = 0;
        } else {
            return St::Full;
        }
    }
    St::Ok
}
