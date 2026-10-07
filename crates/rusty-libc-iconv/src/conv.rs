use crate::engine::*;
use crate::names::{self, Cs, SP_INTERNAL};
use crate::unicode::{self as u, Sb, Var};
use crate::utf7;
use crate::cjk;
use crate::iso2022jp::{self, JpState};
use crate::iso2022kr;
use crate::iso2022cn;
use crate::iso2022cnext;
use crate::tscii;
use crate::direct;
use crate::hkscs;
use crate::compose;
use crate::ebcdic;
use crate::jisx0213;
use crate::iso2022jp3;

const CHUNK: usize = 8160;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Ilseq,
    Inval,
    E2big,
}

impl Error {
    pub fn errno(self) -> i32 {
        match self {
            Error::Ilseq => 84,
            Error::Inval => 22,
            Error::E2big => 7,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Dec {
    Ucs4(bool),
    Utf8,
    Ucs2(bool),
    Ascii,
    Utf16(Var),
    Utf32(Var),
    Unicode,
    Utf7(bool, utf7::DecState),
    Cjk(cjk::Kind),
    Jp(bool, JpState),
    Kr(u8),
    Cn(u32),
    CnExt(u32),
    Tscii(u32),
    Hk(u32),
    Cp(compose::Kind, u32),
    Eb(ebcdic::Kind, u32),
    Jx(jisx0213::Kind, u32),
    Jp3(iso2022jp3::State),
    Sb(&'static Sb),
}

#[derive(Clone)]
pub(crate) enum Enc {
    Ucs4(bool),
    Utf8,
    Ucs2(bool),
    Ascii,
    Utf16(Var),
    Utf32(Var),
    Unicode,
    Utf7(bool, u32),
    Cjk(cjk::Kind),
    Jp(bool, JpState),
    Kr(u8),
    Cn(u32),
    CnExt(u32),
    Tscii(u32),
    Hk(u32),
    Cp(compose::Kind),
    Eb(ebcdic::Kind, u32),
    Jx(jisx0213::Kind, u32),
    Jp3(iso2022jp3::State),
    Sb(&'static Sb),
}

fn dec_for(cs: Cs) -> Option<Dec> {
    Some(match cs {
        Cs::Sb(t) => Dec::Sb(t),
        Cs::Special(k) => match k {
            0 => Dec::Ucs4(false),
            1 => Dec::Ucs4(true),
            2 => Dec::Utf8,
            3 => Dec::Ucs2(false),
            4 => Dec::Ucs2(true),
            5 => Dec::Ascii,
            6 => Dec::Utf16(Var::Plain),
            7 => Dec::Utf16(Var::Le),
            8 => Dec::Utf16(Var::Be),
            9 => Dec::Utf32(Var::Plain),
            10 => Dec::Utf32(Var::Le),
            11 => Dec::Utf32(Var::Be),
            12 => Dec::Unicode,
            13 | 14 => Dec::Utf7(k == 14, utf7::DecState::default()),
            40 | 41 => Dec::Jp(k == 41, JpState::default()),
            42 => Dec::Kr(0),
            43 => Dec::Cn(0),
            63 => Dec::CnExt(0),
            64 => Dec::Tscii(0),
            44 => Dec::Hk(0),
            k if k >= compose::COMPOSE_BASE && ((k - compose::COMPOSE_BASE) as usize) < compose::KINDS.len() => Dec::Cp(compose::KINDS[(k - compose::COMPOSE_BASE) as usize], 0),
            k if k >= ebcdic::EBCDIC_BASE && ((k - ebcdic::EBCDIC_BASE) as usize) < ebcdic::KINDS.len() => Dec::Eb(ebcdic::KINDS[(k - ebcdic::EBCDIC_BASE) as usize], 0),
            60 => Dec::Jx(jisx0213::Kind::Euc, 0),
            62 => Dec::Jp3(Default::default()),
            61 => Dec::Jx(jisx0213::Kind::Sjis, 0),
            k if k >= cjk::CJK_BASE && ((k - cjk::CJK_BASE) as usize) < cjk::KINDS.len() => Dec::Cjk(cjk::KINDS[(k - cjk::CJK_BASE) as usize]),
            _ => return None,
        },
    })
}

fn enc_for(cs: Cs) -> Option<Enc> {
    Some(match cs {
        Cs::Sb(t) => Enc::Sb(t),
        Cs::Special(k) => match k {
            0 => Enc::Ucs4(false),
            1 => Enc::Ucs4(true),
            2 => Enc::Utf8,
            3 => Enc::Ucs2(false),
            4 => Enc::Ucs2(true),
            5 => Enc::Ascii,
            6 => Enc::Utf16(Var::Plain),
            7 => Enc::Utf16(Var::Le),
            8 => Enc::Utf16(Var::Be),
            9 => Enc::Utf32(Var::Plain),
            10 => Enc::Utf32(Var::Le),
            11 => Enc::Utf32(Var::Be),
            12 => Enc::Unicode,
            13 | 14 => Enc::Utf7(k == 14, 0),
            40 | 41 => Enc::Jp(k == 41, JpState::default()),
            42 => Enc::Kr(0),
            43 => Enc::Cn(0),
            63 => Enc::CnExt(0),
            64 => Enc::Tscii(0),
            44 => Enc::Hk(0),
            k if k >= compose::COMPOSE_BASE && ((k - compose::COMPOSE_BASE) as usize) < compose::KINDS.len() => Enc::Cp(compose::KINDS[(k - compose::COMPOSE_BASE) as usize]),
            k if k >= ebcdic::EBCDIC_BASE && ((k - ebcdic::EBCDIC_BASE) as usize) < ebcdic::KINDS.len() => Enc::Eb(ebcdic::KINDS[(k - ebcdic::EBCDIC_BASE) as usize], 0),
            60 => Enc::Jx(jisx0213::Kind::Euc, 0),
            62 => Enc::Jp3(Default::default()),
            61 => Enc::Jx(jisx0213::Kind::Sjis, 0),
            k if k >= cjk::CJK_BASE && ((k - cjk::CJK_BASE) as usize) < cjk::KINDS.len() => Enc::Cjk(cjk::KINDS[(k - cjk::CJK_BASE) as usize]),
            _ => return None,
        },
    })
}

impl Dec {
    fn min_in(&self) -> usize {
        match self {
            Dec::Ucs4(_) | Dec::Utf32(_) => 4,
            Dec::Ucs2(_) | Dec::Utf16(_) | Dec::Unicode => 2,
            _ => 1,
        }
    }

    fn stateful(&self) -> bool {
        matches!(self, Dec::Utf7(..) | Dec::Jp(..) | Dec::Kr(..) | Dec::Cn(..) | Dec::CnExt(..) | Dec::Tscii(..) | Dec::Hk(..) | Dec::Cp(..) | Dec::Eb(..) | Dec::Jx(..) | Dec::Jp3(..))
    }

    fn fixed_width(&self) -> bool {
        matches!(self, Dec::Utf32(_) | Dec::Unicode | Dec::Ucs2(_) | Dec::Ucs4(_) | Dec::Sb(_))
    }

    fn prepare(&mut self, ctx: &mut Ctx, inp: &[u8], ip: &mut usize) -> Option<St> {
        match self {
            Dec::Utf16(v) => u::utf16_dec_prepare(*v, ctx, inp, ip),
            Dec::Utf32(v) => u::utf32_dec_prepare(*v, ctx, inp, ip),
            Dec::Unicode => u::unicode_dec_prepare(ctx, inp, ip),
            _ => None,
        }
    }

    fn run(&mut self, ctx: &mut Ctx, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
        let f = ctx.flags;
        match self {
            Dec::Ucs4(le) => u::ucs4_dec(*le, f, inp, ip, out, op, irr),
            Dec::Utf8 => u::utf8_dec(f, inp, ip, out, op, irr),
            Dec::Ucs2(sw) => u::ucs2_dec(*sw, *sw, f, inp, ip, out, op, irr),
            Dec::Ascii => u::ascii_dec(f, inp, ip, out, op, irr),
            Dec::Utf16(_) => u::utf16_dec(f, inp, ip, out, op, irr),
            Dec::Unicode => u::ucs2_dec(f & SWAP != 0, false, f, inp, ip, out, op, irr),
            Dec::Utf32(_) => u::utf32_dec(f, inp, ip, out, op, irr),
            Dec::Utf7(imap, st) => utf7::dec(st, *imap, f, inp, ip, out, op, irr),
            Dec::Cjk(k) => cjk::dec(*k, f, inp, ip, out, op, irr),
            Dec::Jp(jp2, st) => iso2022jp::dec(st, *jp2, f, inp, ip, out, op, irr),
            Dec::Kr(st) => iso2022kr::dec(st, f, inp, ip, out, op, irr),
            Dec::Cn(st) => iso2022cn::dec(st, f, inp, ip, out, op, irr),
            Dec::CnExt(st) => iso2022cnext::dec(st, f, inp, ip, out, op, irr),
            Dec::Tscii(st) => tscii::dec(st, f, inp, ip, out, op, irr),
            Dec::Hk(st) => hkscs::dec(st, f, inp, ip, out, op, irr),
            Dec::Cp(k, st) => compose::dec(*k, st, f, inp, ip, out, op, irr),
            Dec::Eb(k, st) => ebcdic::dec(*k, st, f, inp, ip, out, op, irr),
            Dec::Jx(k, st) => jisx0213::dec(*k, st, f, inp, ip, out, op, irr),
            Dec::Jp3(st) => iso2022jp3::dec(st, f, inp, ip, out, op, irr),
            Dec::Sb(t) => u::sb_dec(t, f, inp, ip, out, op, irr),
        }
    }

    fn pending(&self) -> Option<([u32; 4], usize)> {
        match self {
            Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) if (*st >> 3) != 0 => Some(([*st >> 3, 0, 0, 0], 1)),
            Dec::Jp3(st) if st.aux != 0 => Some(([st.aux, 0, 0, 0], 1)),
            Dec::Tscii(st) if *st != 0 => Some(tscii::pending(*st)),
            _ => None,
        }
    }

    fn reset(&mut self) {
        match self {
            Dec::Utf7(_, st) => *st = utf7::DecState::default(),
            Dec::Jp(_, st) => *st = JpState::default(),
            Dec::Kr(st) => *st = 0,
            Dec::Cn(st) | Dec::CnExt(st) | Dec::Tscii(st) => *st = 0,
            Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) | Dec::Eb(_, st) => *st = 0,
            Dec::Jp3(st) => *st = Default::default(),
            _ => {}
        }
    }
}

impl Enc {
    fn min_out(&self) -> usize {
        match self {
            Enc::Ucs4(_) | Enc::Utf32(_) => 4,
            Enc::Ucs2(_) | Enc::Utf16(_) | Enc::Unicode => 2,
            _ => 1,
        }
    }

    fn prepare(&mut self, ctx: &mut Ctx, out: &mut [u8], op: &mut usize) -> Option<St> {
        match self {
            Enc::Utf16(v) => u::utf16_enc_prepare(*v, ctx, out, op),
            Enc::Utf32(v) => u::utf32_enc_prepare(*v, ctx, out, op),
            Enc::Unicode => u::unicode_enc_prepare(ctx, out, op),
            Enc::Kr(_) => iso2022kr::enc_prepare(ctx, out, op),
            _ => None,
        }
    }

    fn run(&mut self, ctx: &mut Ctx, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
        let f = ctx.flags;
        match self {
            Enc::Ucs4(le) => u::ucs4_enc(*le, inp, ip, out, op),
            Enc::Utf8 => u::utf8_enc(f, inp, ip, out, op, irr),
            Enc::Ucs2(sw) => u::ucs2_enc(*sw, *sw, f, inp, ip, out, op, irr, &mut no_prep),
            Enc::Ascii => u::ascii_enc(f, inp, ip, out, op, irr),
            Enc::Utf16(v) => {
                let (v, mut c) = (*v, *ctx);
                u::utf16_enc(f, inp, ip, out, op, irr, &mut |o, p| u::utf16_enc_prepare(v, &mut c, o, p))
            }
            Enc::Unicode => {
                let mut c = *ctx;
                u::ucs2_enc(f & SWAP != 0, false, f, inp, ip, out, op, irr, &mut |o, p| u::unicode_enc_prepare(&mut c, o, p))
            }
            Enc::Utf32(v) => {
                let (v, mut c) = (*v, *ctx);
                u::utf32_enc(f, inp, ip, out, op, irr, &mut |o, p| u::utf32_enc_prepare(v, &mut c, o, p))
            }
            Enc::Utf7(imap, count) => utf7::enc(count, *imap, f, inp, ip, out, op, irr),
            Enc::Cjk(k) => cjk::enc(*k, f, inp, ip, out, op, irr),
            Enc::Jp(jp2, st) => iso2022jp::enc(st, *jp2, f, inp, ip, out, op, irr),
            Enc::Kr(st) => iso2022kr::enc(st, ctx, f, inp, ip, out, op, irr),
            Enc::Cn(st) => iso2022cn::enc(st, f, inp, ip, out, op, irr),
            Enc::CnExt(st) => iso2022cnext::enc(st, f, inp, ip, out, op, irr),
            Enc::Tscii(st) => tscii::enc(st, f, inp, ip, out, op, irr),
            Enc::Hk(st) => hkscs::enc(st, f, inp, ip, out, op, irr),
            Enc::Cp(k) => compose::enc(*k, f, inp, ip, out, op, irr),
            Enc::Eb(k, st) => ebcdic::enc(*k, st, f, inp, ip, out, op, irr),
            Enc::Jx(k, st) => jisx0213::enc(*k, st, f, inp, ip, out, op, irr),
            Enc::Jp3(st) => iso2022jp3::enc(st, f, inp, ip, out, op, irr),
            Enc::Sb(t) => u::sb_enc(t, f, inp, ip, out, op, irr),
        }
    }

    fn emit_reset(&mut self, out: &mut [u8], op: &mut usize) -> St {
        match self {
            Enc::Utf7(imap, count) => utf7::emit_reset(count, *imap, out, op),
            Enc::Jp(_, st) => iso2022jp::emit_reset(st, out, op),
            Enc::Kr(st) => iso2022kr::emit_reset(st, out, op),
            Enc::Cn(st) => iso2022cn::emit_reset(st, out, op),
            Enc::CnExt(st) => iso2022cnext::emit_reset(st, out, op),
            Enc::Tscii(st) => tscii::emit_reset(st, out, op),
            Enc::Hk(st) => hkscs::enc_emit_reset(st, out, op),
            Enc::Eb(_, st) => ebcdic::emit_reset(st, out, op),
            Enc::Jx(_, st) => jisx0213::enc_emit_reset(st, out, op),
            Enc::Jp3(st) => iso2022jp3::emit_reset(st, out, op),
            _ => St::Ok,
        }
    }

    fn reset(&mut self) {
        match self {
            Enc::Utf7(_, count) => *count = 0,
            Enc::Jp(_, st) => *st = JpState::default(),
            Enc::Kr(st) => *st = 0,
            Enc::Cn(st) | Enc::CnExt(st) | Enc::Tscii(st) => *st = 0,
            Enc::Hk(st) | Enc::Eb(_, st) | Enc::Jx(_, st) => *st = 0,
            Enc::Jp3(st) => *st = Default::default(),
            _ => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    UnknownCharset,
    NoConversion,
}

#[derive(Clone)]
pub struct Converter {
    direct: Option<direct::Kind>,
    dec: Option<Dec>,
    enc: Option<Enc>,
    c1: Ctx,
    c2: Ctx,
    illegal_seen: bool,
}

impl Converter {
    pub fn illegal_seen(&self) -> bool {
        self.illegal_seen
    }

    pub fn new(to: &str, from: &str) -> Result<Converter, OpenError> {
        Self::open(to.as_bytes(), from.as_bytes())
    }

    pub fn open(to: &[u8], from: &[u8]) -> Result<Converter, OpenError> {
        let pt = names::parse(to).ok_or(OpenError::UnknownCharset)?;
        let pf = names::parse(from).ok_or(OpenError::UnknownCharset)?;
        let resolve = |p: &names::Parsed| -> Option<Cs> {
            if p.key() == b"//" { names::lookup_key(b"ANSI_X3.4-1968//") } else { names::lookup_key(p.key()) }
        };
        let (cto, cfrom) = (resolve(&pt).ok_or(OpenError::UnknownCharset)?, resolve(&pf).ok_or(OpenError::UnknownCharset)?);
        let internal = |c: Cs| matches!(c, Cs::Special(SP_INTERNAL));
        let dec = if internal(cfrom) { None } else { Some(dec_for(cfrom).ok_or(OpenError::UnknownCharset)?) };
        let enc = if internal(cto) { None } else { Some(enc_for(cto).ok_or(OpenError::UnknownCharset)?) };
        let mut flags = if pt.ignore { IGNORE } else { 0 };
        let mut c1 = Ctx { flags, inv: 0 };
        if pt.translit {
            flags |= TRANSLIT;
        }
        let c2 = Ctx { flags, inv: 0 };
        if dec.is_none() {
            c1.flags = flags;
        }
        let code = |c: Cs| match c {
            Cs::Special(k) => Some(k),
            Cs::Sb(t) => Some(match t.name() {
                "IBM1008" => 200,
                "IBM420" => 201,
                _ => return None,
            }),
        };
        let direct = match (code(cfrom), code(cto)) {
            (Some(20), Some(17)) => Some(direct::Kind::GbkToGb),
            (Some(17), Some(20)) => Some(direct::Kind::GbToGbk),
            (Some(17), Some(23)) => Some(direct::Kind::GbToBig5),
            (Some(23), Some(17)) => Some(direct::Kind::Big5ToGb),
            (Some(200), Some(201)) => Some(direct::Kind::Ibm1008To420),
            (Some(201), Some(200)) => Some(direct::Kind::Ibm420To1008),
            _ => None,
        };
        let (dec, enc) = if direct.is_some() { (None, None) } else { (dec, enc) };
        Ok(Converter { direct, dec, enc, c1, c2, illegal_seen: false })
    }

    fn last_ctx(&mut self) -> &mut Ctx {
        if self.enc.is_some() { &mut self.c2 } else { &mut self.c1 }
    }

    fn enc_call(&mut self, inp: &[u32], out: &mut [u8], op: &mut usize, irr: &mut usize) -> (St, usize) {
        let enc = self.enc.as_mut().unwrap();
        if let Some(st) = enc.prepare(&mut self.c2, out, op) {
            return (st, 0);
        }
        let mut ip = 0;
        let mut l = 0usize;
        let st = enc.run(&mut self.c2, inp, &mut ip, out, op, Some(&mut l));
        self.c2.inv += 1;
        *irr = ((*irr & !crate::engine::ILLEGAL_SEEN) + (l & !crate::engine::ILLEGAL_SEEN)) | ((*irr | l) & crate::engine::ILLEGAL_SEEN);
        (st, ip)
    }

    fn dec_call(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        let rem = inp.len() - *ip;
        if rem + 2 <= 64 {
            self.dec_call_n::<64>(inp, ip, out, op, irr)
        } else if rem + 2 <= 1024 {
            self.dec_call_n::<1024>(inp, ip, out, op, irr)
        } else {
            self.dec_call_n::<CHUNK>(inp, ip, out, op, irr)
        }
    }

    fn dec_call_n<const N: usize>(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        {
            let dec = self.dec.as_mut().unwrap();
            if let Some(st) = dec.prepare(&mut self.c1, inp, ip) {
                return st;
            }
        }
        let mut buf = [0u32; N];
        let mut lirr = 0usize;
        loop {
            let start = *ip;
            let lirr0 = lirr;
            let saved = if self.dec.as_ref().unwrap().stateful() { self.dec.clone() } else { None };
            let mut n = 0;
            let mut st = {
                let dec = self.dec.as_mut().unwrap();
                dec.run(&mut self.c1, inp, ip, &mut buf, &mut n, &mut lirr)
            };
            self.c1.inv += 1;
            *irr |= lirr & crate::engine::ILLEGAL_SEEN;
            if n > 0 {
                let (res, used) = self.enc_call(&buf[..n], out, op, irr);
                if res != St::Empty {
                    if used != n {
                        *ip = start;
                        if saved.is_some() {
                            self.dec = saved;
                        }
                        let mut n2 = 0;
                        let dec = self.dec.as_mut().unwrap();
                        dec.run(&mut self.c1, inp, ip, &mut buf[..used], &mut n2, &mut lirr);
                        if n2 == 0 && !(dec.fixed_width() && lirr == lirr0) {
                            self.c1.inv -= 1;
                        }
                    }
                    st = res;
                } else if st == St::Full {
                    st = St::Ok;
                }
            }
            if st != St::Ok {
                return st;
            }
        }
    }

    fn single(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        let mut buf = [0u32; CHUNK];
        if let Some(dec) = self.dec.as_mut() {
            if let Some(st) = dec.prepare(&mut self.c1, inp, ip) {
                return st;
            }
            let mut sticky = false;
            loop {
                let cap = ((out.len() - *op) / 4).min(CHUNK);
                let mut n = 0;
                let mut l = 0;
                let st = dec.run(&mut self.c1, inp, ip, &mut buf[..cap], &mut n, &mut l);
                if l & crate::engine::ILLEGAL_SEEN != 0 {
                    self.illegal_seen = true;
                }
                for k in 0..n {
                    out[*op + 4 * k..*op + 4 * k + 4].copy_from_slice(&buf[k].to_le_bytes());
                }
                *op += 4 * n;
                self.c1.inv += 1;
                let more = (out.len() - *op) / 4 > 0;
                if st == St::Full && cap == CHUNK && more {
                    continue;
                }
                if st == St::Illegal && self.c1.flags & IGNORE != 0 && *ip != inp.len() {
                    sticky = true;
                    self.illegal_seen = true;
                    continue;
                }
                return if sticky && st == St::Empty { St::Illegal } else { st };
            }
        }
        let mut sticky = false;
        loop {
            let avail = (inp.len() - *ip) / 4;
            let cnt = avail.min(CHUNK);
            for k in 0..cnt {
                let b = &inp[*ip + 4 * k..];
                buf[k] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            }
            let (st, used) = if self.enc.is_some() {
                self.enc_call(&buf[..cnt], out, op, irr)
            } else {
                let c = cnt.min((out.len() - *op) / 4);
                for k in 0..c {
                    out[*op + 4 * k..*op + 4 * k + 4].copy_from_slice(&buf[k].to_le_bytes());
                }
                *op += 4 * c;
                (if c == cnt { St::Empty } else { St::Full }, c)
            };
            *ip += 4 * used;
            if st == St::Empty && cnt == CHUNK && *ip != inp.len() {
                continue;
            }
            if st == St::Empty && inp.len() - *ip < 4 && *ip != inp.len() {
                let min_out = self.enc.as_ref().map_or(4, |e| e.min_out());
                return if min_out > 1 && out.len() - *op < min_out { St::Full } else { St::Incomplete };
            }
            if st == St::Illegal && self.c2.flags & IGNORE != 0 && *ip != inp.len() {
                sticky = true;
                self.illegal_seen = true;
                continue;
            }
            return if sticky && st == St::Empty { St::Illegal } else { st };
        }
    }

    pub fn convert_raw(&mut self, input: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize) -> Result<usize, Error> {
        let mut irr = 0usize;
        let st = if let Some(k) = self.direct {
            direct::run(k, self.c2.flags, input, ip, out, op, &mut irr)
        } else if self.dec.is_some() && self.enc.is_some() {
            let min = self.dec.as_ref().unwrap().min_in();
            loop {
                let last = *ip;
                let st = self.dec_call(input, ip, out, op, &mut irr);
                if !(st == St::Empty && last != *ip && *ip + min <= input.len()) {
                    break st;
                }
            }
        } else {
            self.single(input, ip, out, op, &mut irr)
        };
        if st == St::Illegal || irr & crate::engine::ILLEGAL_SEEN != 0 {
            self.illegal_seen = true;
        }
        irr &= !crate::engine::ILLEGAL_SEEN;
        match st {
            St::Illegal => Err(Error::Ilseq),
            St::Full => Err(Error::E2big),
            St::Incomplete => Err(Error::Inval),
            St::Empty | St::Ok => Ok(irr),
        }
    }

    pub fn dec_state_word(&self) -> u32 {
        match &self.dec {
            Some(Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) | Dec::Eb(_, st) | Dec::Cn(st)) => *st,
            _ => 0,
        }
    }

    pub fn decode_ucs4(&mut self, input: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize) -> Option<Result<(), Error>> {
        let dec = self.dec.as_mut()?;
        let mut irr = 0usize;
        let st = dec.run(&mut self.c1, input, ip, out, op, &mut irr);
        Some(match st {
            St::Illegal => Err(Error::Ilseq),
            St::Full => Err(Error::E2big),
            St::Incomplete => Err(Error::Inval),
            St::Empty | St::Ok => Ok(()),
        })
    }

    pub fn enc_state_word(&self) -> u32 {
        match &self.enc {
            Some(Enc::Hk(st)) => *st,
            _ => 0,
        }
    }

    pub fn set_enc_state_word(&mut self, v: u32) {
        if let Some(Enc::Hk(st)) = &mut self.enc {
            *st = v;
        }
    }

    pub fn set_dec_state_word(&mut self, v: u32) {
        if let Some(Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) | Dec::Eb(_, st) | Dec::Cn(st)) = &mut self.dec {
            *st = v;
        }
    }

    pub fn flush_raw(&mut self, out: Option<(&mut [u8], &mut usize)>) -> Result<usize, Error> {
        let mut irr_total = 0usize;
        if let Some((o, op)) = out {
            if self.enc.is_some() {
                if let Some((chars, n)) = self.dec.as_ref().and_then(|d| d.pending()) {
                    let mut irr = 0;
                    let start = *op;
                    let (res, used) = self.enc_call(&chars[..n], o, op, &mut irr);
                    irr_total += irr;
                    if used < n && res != St::Illegal {
                        *op = start;
                        return Err(if res == St::Full { Error::E2big } else { Error::Ilseq });
                    }
                    if used == 0 {
                        *op = start;
                        return Err(if res == St::Full { Error::E2big } else { Error::Ilseq });
                    }
                    if let Some(dec) = self.dec.as_mut() {
                        dec.reset();
                    }
                    if res == St::Illegal {
                        return Err(Error::Ilseq);
                    }
                }
            }
            if let Some(dec) = self.dec.as_mut() {
                dec.reset();
            }
            if let Some(enc) = self.enc.as_mut() {
                let start = *op;
                if matches!(enc, Enc::Kr(_)) {
                    if let Some(st) = enc.prepare(&mut self.c2, o, op) {
                        *op = start;
                        return Err(if st == St::Full { Error::E2big } else { Error::Ilseq });
                    }
                }
                let st = enc.emit_reset(o, op);
                if st != St::Ok {
                    *op = start;
                    return Err(if st == St::Full { Error::E2big } else { Error::Ilseq });
                }
                if matches!(enc, Enc::CnExt(_)) && *op > start {
                    irr_total += 1;
                }
            }
        } else {
            if let Some(dec) = self.dec.as_mut() {
                dec.reset();
            }
            if let Some(enc) = self.enc.as_mut() {
                enc.reset();
            }
        }
        self.c1.inv = 0;
        self.c2.inv = 0;
        let _ = self.last_ctx();
        Ok(irr_total)
    }
}
