use crate::engine::*;
use crate::mb::Mb;
use crate::mbdata::{ibm930, ibm933, ibm935, ibm937, ibm939, ibm1364, ibm1371, ibm1388, ibm1390, ibm1399};

const SO: u8 = 0x0e;
const SI: u8 = 0x0f;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Ibm930,
    Ibm933,
    Ibm935,
    Ibm937,
    Ibm939,
    Ibm1364,
    Ibm1371,
    Ibm1388,
    Ibm1390,
    Ibm1399,
}

pub const KINDS: [Kind; 10] = [Kind::Ibm930, Kind::Ibm933, Kind::Ibm935, Kind::Ibm937, Kind::Ibm939, Kind::Ibm1364, Kind::Ibm1371, Kind::Ibm1388, Kind::Ibm1390, Kind::Ibm1399];
pub const EBCDIC_BASE: u8 = 48;

pub type State = u32;
const SB: u32 = 0;
const DB: u32 = 64;

fn mb(k: Kind) -> &'static Mb {
    match k {
        Kind::Ibm930 => &ibm930::MB,
        Kind::Ibm933 => &ibm933::MB,
        Kind::Ibm935 => &ibm935::MB,
        Kind::Ibm937 => &ibm937::MB,
        Kind::Ibm939 => &ibm939::MB,
        Kind::Ibm1364 => &ibm1364::MB,
        Kind::Ibm1371 => &ibm1371::MB,
        Kind::Ibm1388 => &ibm1388::MB,
        Kind::Ibm1390 => &ibm1390::MB,
        Kind::Ibm1399 => &ibm1399::MB,
    }
}

fn is13(k: Kind) -> bool {
    !matches!(k, Kind::Ibm930 | Kind::Ibm933 | Kind::Ibm935 | Kind::Ibm937 | Kind::Ibm939)
}

fn combos(k: Kind) -> &'static [(u32, u32, u32)] {
    match k {
        Kind::Ibm1390 => &ibm1390::COMBOS,
        Kind::Ibm1399 => &ibm1399::COMBOS,
        _ => &[],
    }
}

fn limit(k: Kind) -> u32 {
    match k {
        Kind::Ibm1390 | Kind::Ibm1399 => u32::MAX,
        _ => 0xffff,
    }
}

pub fn dec(k: Kind, st: &mut State, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let m = mb(k);
    let (quiet, cb) = (is13(k), combos(k));
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let bad = |n: usize| if quiet { Body::IllegalQuiet(n) } else { Body::Illegal(n) };
        let ch = s[0];
        if ch == SO {
            *st = DB;
            return Body::Skip(1);
        }
        if ch == SI {
            *st = SB;
            return Body::Skip(1);
        }
        if *st == SB {
            match m.dec1(ch) {
                Some(c) => Body::Char(c, 1),
                None => bad(1),
            }
        } else {
            if s.len() < 2 {
                return Body::Incomplete;
            }
            match m.dec2(1, ch, s[1]) {
                Some(c) => Body::Char(c, 2),
                None => match cb.iter().find(|x| x.0 == 0x0e0000 | (ch as u32) << 8 | s[1] as u32) {
                    Some(&(_, u1, u2)) => Body::Two(u1, u2, 2),
                    None => bad(2),
                },
            }
        }
    })
}

pub fn enc(k: Kind, st: &mut State, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let m = mb(k);
    let (quiet, cb, lim) = (is13(k), combos(k), limit(k));
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        let bad = || if quiet { EBody::IllegalPlainQuiet } else { EBody::Illegal };
        if ch >= lim {
            if quiet && is_tag(ch) {
                return EBody::Ok(1, 0);
            }
            return bad();
        }
        if s.len() > 1 {
            if let Some(&(code, _, _)) = cb.iter().find(|x| x.1 == ch && x.2 == s[1]) {
                let mut n = 0;
                if *st == SB {
                    o[0] = SO;
                    *st = DB;
                    n = 1;
                }
                if o.len() < n + 2 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = (code >> 8) as u8;
                o[n + 1] = code as u8;
                return EBody::Ok(2, n + 2);
            }
        }
        let code = m.enc(ch);
        let sb = code.filter(|c| c.len == 1);
        let mut n = 0usize;
        match sb {
            None => {
                let Some(c) = code.filter(|c| c.len == 3 && c.bytes[0] == SO) else {
                    return bad();
                };
                if *st == SB {
                    if o.is_empty() {
                        return EBody::Full;
                    }
                    o[0] = SO;
                    *st = DB;
                    n = 1;
                }
                if o.len() < n + 2 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = c.bytes[1];
                o[n + 1] = c.bytes[2];
                EBody::Ok(1, n + 2)
            }
            Some(c) => {
                if *st == DB {
                    if o.is_empty() {
                        return EBody::Full;
                    }
                    o[0] = SI;
                    *st = SB;
                    n = 1;
                }
                if o.len() < n + 1 {
                    return if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
                }
                o[n] = c.bytes[0];
                EBody::Ok(1, n + 1)
            }
        }
    })
}

pub fn emit_reset(st: &mut State, out: &mut [u8], op: &mut usize) -> St {
    if *st != SB {
        if *op >= out.len() {
            return St::Full;
        }
        out[*op] = SI;
        *op += 1;
        *st = SB;
    }
    St::Ok
}
