use crate::engine::*;

pub struct Comp {
    pub dec: &'static [u16; 256],
    pub enc1: &'static [u32],
    pub comp: &'static [(u16, u16, u16)],
    pub decomp: &'static [(u16, u8, [u8; 3])],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Cp1255,
    Cp1258,
    Tcvn,
}

pub const KINDS: [Kind; 3] = [Kind::Cp1255, Kind::Cp1258, Kind::Tcvn];
pub const COMPOSE_BASE: u8 = 45;

pub fn tables(k: Kind) -> &'static Comp {
    match k {
        Kind::Cp1255 => &crate::composedata::cp1255::COMP_CP1255,
        Kind::Cp1258 => &crate::composedata::cp1258::COMP_CP1258,
        Kind::Tcvn => &crate::composedata::tcvn5712_1::COMP_TCVN5712_1,
    }
}

pub type DecState = u32;

fn params(k: Kind) -> (u32, u32, u32, u32, &'static [u32]) {
    match k {
        Kind::Cp1255 => (0x05d0, 0x05f2, 0x05b0, 0x05c5, &[0xfb2a, 0xfb2b, 0xfb49]),
        _ => (0x0041, 0x01b0, 0x0300, 0x0340, &[]),
    }
}

fn lookup_comp(c: &Comp, last: u32, mark: u32) -> Option<u32> {
    let key = (mark as u16, last as u16);
    if last > 0xffff {
        return None;
    }
    c.comp.binary_search_by(|e| (e.0, e.1).cmp(&key)).ok().map(|i| c.comp[i].2 as u32)
}

pub fn dec(k: Kind, st: &mut DecState, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let c = tables(k);
    let (buf_lo, buf_hi, mark_lo, mark_hi, rebuffer) = params(k);
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let ch = c.dec[s[0] as usize] as u32;
        if ch == 0xffff {
            return Body::Illegal(1);
        }
        let last = *st >> 3;
        let must_buffer = ch >= buf_lo && ch <= buf_hi;
        if last != 0 {
            if ch >= mark_lo && ch < mark_hi {
                if let Some(composed) = lookup_comp(c, last, ch) {
                    if rebuffer.contains(&composed) {
                        *st = composed << 3;
                        return Body::Skip(1);
                    }
                    *st = 0;
                    return Body::Char(composed, 1);
                }
            }
            *st = 0;
            if must_buffer {
                *st = ch << 3;
                return Body::Char(last, 1);
            }
            return Body::Char(last, 0);
        }
        if must_buffer {
            *st = ch << 3;
            Body::Skip(1)
        } else {
            Body::Char(ch, 1)
        }
    })
}

pub fn enc(k: Kind, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let c = tables(k);
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        if ch < 0x10000 {
            let key = ch << 8;
            if let Ok(i) = c.enc1.binary_search_by(|e| (e & !0xff).cmp(&key)) {
                o[0] = (c.enc1[i] & 0xff) as u8;
                return EBody::Ok(1, 1);
            }
            if let Ok(i) = c.decomp.binary_search_by(|e| e.0.cmp(&(ch as u16))) {
                let (_, n, b) = c.decomp[i];
                let n = n as usize;
                if o.len() < n {
                    return EBody::Full;
                }
                o[..n].copy_from_slice(&b[..n]);
                return EBody::Ok(1, n);
            }
        }
        EBody::Illegal
    })
}
