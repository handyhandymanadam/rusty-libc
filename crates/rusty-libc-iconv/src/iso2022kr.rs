use crate::engine::*;
use crate::iso2022jp::{KSC5601, SetRes, dec_set, ksc5601};

const ESC: u8 = 0x1b;
const SO: u8 = 0x0e;
const SI: u8 = 0x0f;

pub type KrState = u8;

pub fn dec(set: &mut KrState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let ch = s[0];
        if ch > 0x7f {
            return Body::Illegal(1);
        }
        if ch == ESC {
            if s.len() < 2 || (s[1] == b'$' && (s.len() < 3 || (s[2] == b')' && s.len() < 4))) {
                return Body::Incomplete;
            }
            if s.len() >= 4 && s[1] == b'$' && s[2] == b')' && s[3] == b'C' {
                return Body::Skip(4);
            }
        } else if ch == SO {
            *set = 8;
            return Body::Skip(1);
        } else if ch == SI {
            *set = 0;
            return Body::Skip(1);
        }
        if *set == 0 {
            Body::Char(ch as u32, 1)
        } else {
            match dec_set(KSC5601, s) {
                SetRes::Char(c) => Body::Char(c, 2),
                SetRes::Incomplete => Body::Incomplete,
                SetRes::Unknown => Body::Illegal(1),
            }
        }
    })
}

pub fn enc_prepare(ctx: &Ctx, out: &mut [u8], op: &mut usize) -> Option<St> {
    if ctx.inv == 0 {
        if *op + 4 > out.len() {
            return Some(St::Full);
        }
        out[*op..*op + 4].copy_from_slice(&[ESC, b'$', b')', b'C']);
        *op += 4;
    }
    None
}

pub fn enc(set: &mut KrState, ctx: &Ctx, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let c2 = *ctx;
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut |o: &mut [u8], p: &mut usize| enc_prepare(&c2, o, p), no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        if ch < 0x80 {
            let mut n = 0;
            if *set != 0 {
                o[0] = SI;
                *set = 0;
                n = 1;
                if o.len() == 1 {
                    return EBody::PartialFull(1);
                }
            }
            o[n] = ch as u8;
            EBody::Ok(1, n + 1)
        } else {
            match ksc5601(ch) {
                None => EBody::Illegal,
                Some(c) => {
                    let mut n = 0;
                    if *set != 8 {
                        o[0] = SO;
                        *set = 8;
                        n = 1;
                    }
                    if o.len() < n + 2 {
                        return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                    }
                    o[n] = c[0];
                    o[n + 1] = c[1];
                    EBody::Ok(1, n + 2)
                }
            }
        }
    })
}

pub fn emit_reset(set: &mut KrState, out: &mut [u8], op: &mut usize) -> St {
    if *set != 0 {
        if *op >= out.len() {
            return St::Full;
        }
        out[*op] = SI;
        *op += 1;
        *set = 0;
    }
    St::Ok
}
