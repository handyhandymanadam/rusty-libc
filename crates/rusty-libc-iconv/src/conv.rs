//! The converter: glibc's gconv skeleton (rounds through a buffer of 8160 characters, the re-run
//! that finds exactly how much input produced the output that fitted), flushing and resetting.
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

/// The size of glibc's buffer between the two steps, in characters.
const CHUNK: usize = 8160;

/// The error an iconv call ends with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid input (EILSEQ); the input position is at the offending bytes.
    Ilseq,
    /// The input ends inside a character (EINVAL).
    Inval,
    /// The output is full (E2BIG).
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

    /// glibc modules whose input and output units have fixed sizes find the input position after a
    /// short second step by arithmetic, not by running the loop again: the invocation counter is
    /// then not given back (this shows in where a byte order mark is looked for).
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

    /// The characters a decoder holds back (flushing converts them).
    fn pending(&self) -> Option<([u32; 4], usize)> {
        match self {
            Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) if (*st >> 3) != 0 => Some(([*st >> 3, 0, 0, 0], 1)),
            Dec::Jp3(st) if st.aux != 0 => Some(([st.aux, 0, 0, 0], 1)),
            Dec::Tscii(st) if *st != 0 => Some(tscii::pending(*st)),
            _ => None,
        }
    }

    /// Reset the conversion state (what flushing without output does).
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
    /// The smallest output a step of this encoder needs (glibc's MIN_NEEDED_OUTPUT).
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

    /// Write the sequence that returns to the initial state. Nothing for stateless charsets.
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

/// Why `Converter::new` failed (iconv_open sets EINVAL for every one of these).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// The name is not a charset (or not one this library implements).
    UnknownCharset,
    /// The conversion between the two exists in neither direction.
    NoConversion,
}

/// A conversion descriptor: `iconv_open` for Rust.
#[derive(Clone)]
pub struct Converter {
    /// glibc's three one-step converters (no UCS-4 in between).
    direct: Option<direct::Kind>,
    dec: Option<Dec>,
    enc: Option<Enc>,
    c1: Ctx,
    c2: Ctx,
    /// Some call met illegal input, ignored or not (glibc's `__GCONV_ENCOUNTERED_ILLEGAL_INPUT`, which `iconv -c` reads to
    /// exit with failure even when the call that skipped the bytes returned E2BIG).
    illegal_seen: bool,
}

impl Converter {
    /// Has any call met illegal input so far (whether or not it was skipped)?
    pub fn illegal_seen(&self) -> bool {
        self.illegal_seen
    }

    /// Open a conversion from charset `from` to charset `to`, with glibc's name rules (case does
    /// not matter, aliases, `//TRANSLIT` and `//IGNORE` after the target name).
    pub fn new(to: &str, from: &str) -> Result<Converter, OpenError> {
        Self::open(to.as_bytes(), from.as_bytes())
    }

    /// The converters of a `fopen (..., ",ccs=NAME")` stream, from NAME's charset to INTERNAL and back, found as glibc 2.43's
    /// `_IO_new_file_fopen` finds them: the key `names::ccs_key` makes from NAME must be in the alias table as it is, and
    /// must not be INTERNAL (`WCHAR_T` is its alias), which glibc cannot convert from or to itself. Anything else
    /// (unknown, empty, with a suffix) is `UnknownCharset`: fopen fails with EINVAL then.
    pub fn open_ccs(name: &[u8]) -> Result<(Converter, Converter), OpenError> {
        let key = names::ccs_key(name).ok_or(OpenError::UnknownCharset)?;
        match names::lookup_key(key.key()) {
            None | Some(Cs::Special(SP_INTERNAL)) => Err(OpenError::UnknownCharset),
            // (to and from INTERNAL, as glibc's `__wcsmbs_named_conv`: one step each way, host-order UCS-4 values as the
            // charset gives them, e.g. UCS-4 values above 0x10FFFF that a UCS-4LE step would refuse)
            Some(_) => {
                let mut enc = Self::open(key.key(), b"WCHAR_T")?;
                // libio's `cd_out` step: `__internal_use` (only the encoders' byte order mark depends on it) and
                // `__GCONV_TRANSLIT` (a character the charset lacks is transliterated, `?` at worst, in the charset's bytes)
                enc.c1.flags |= INTERNAL_USE | TRANSLIT;
                enc.c2.flags |= INTERNAL_USE | TRANSLIT;
                Ok((Self::open(b"WCHAR_T", key.key())?, enc))
            }
        }
    }

    /// Does this converter read a charset of one byte per character with no state (a table charset or ASCII)? What glibc's
    /// `__libio_codecvt_encoding` reports as 1 for a `ccs=` stream's decoder (its step's `__min_needed_from` and
    /// `__max_needed_from` are both 1): `ftell` then counts one byte for each pending wide character.
    pub fn reads_one_byte_charset(&self) -> bool {
        self.direct.is_none() && matches!(self.dec, Some(Dec::Sb(_)) | Some(Dec::Ascii))
    }

    pub fn open(to: &[u8], from: &[u8]) -> Result<Converter, OpenError> {
        let pt = names::parse(to).ok_or(OpenError::UnknownCharset)?;
        let pf = names::parse(from).ok_or(OpenError::UnknownCharset)?;
        let resolve = |p: &names::Parsed| -> Option<Cs> {
            if p.key() == b"//" {
                // an empty name means the charset of the current locale (glibc's gconv_open)
                // (None: the built-in C locale)
                let cs: &[u8] = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE).map_or(b"ANSI_X3.4-1968", |d| d.bytes(14));
                let mut buf = [0u8; 64];
                let n = cs.len().min(60);
                buf[..n].copy_from_slice(&cs[..n]);
                buf[n..n + 2].copy_from_slice(b"//");
                names::parse(&buf[..n + 2]).and_then(|q| names::lookup_key(q.key()))
            } else {
                names::lookup_key(p.key())
            }
        };
        let (cto, cfrom) = (resolve(&pt).ok_or(OpenError::UnknownCharset)?, resolve(&pf).ok_or(OpenError::UnknownCharset)?);
        let internal = |c: Cs| matches!(c, Cs::Special(SP_INTERNAL));
        let dec = if internal(cfrom) { None } else { Some(dec_for(cfrom).ok_or(OpenError::UnknownCharset)?) };
        let enc = if internal(cto) { None } else { Some(enc_for(cto).ok_or(OpenError::UnknownCharset)?) };
        let mut flags = if pt.ignore { IGNORE } else { 0 };
        let mut c1 = Ctx { flags, inv: 0 };
        // translit applies to the step that reads INTERNAL: the second step, or the only one
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
        // codes: 17 EUC-CN, 20 GBK, 23 BIG5, 200 IBM1008, 201 IBM420
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

    /// The step data of the last step (the one that writes the user's output).
    fn last_ctx(&mut self) -> &mut Ctx {
        if self.enc.is_some() { &mut self.c2 } else { &mut self.c1 }
    }

    /// One call of the second step on a chunk of characters. Returns the status and the number of
    /// characters used; the output position is advanced.
    fn enc_call(&mut self, inp: &[u32], out: &mut [u8], op: &mut usize, irr: &mut usize) -> (St, usize) {
        let enc = self.enc.as_mut().unwrap();
        if let Some(st) = enc.prepare(&mut self.c2, out, op) {
            return (st, 0);
        }
        let mut ip = 0;
        let mut l = 0usize;
        let st = enc.run(&mut self.c2, inp, &mut ip, out, op, Some(&mut l));
        self.c2.inv += 1;
        // (the loops may have set the illegal-input mark in `l`: keep it a mark, not a count)
        *irr = ((*irr & !crate::engine::ILLEGAL_SEEN) + (l & !crate::engine::ILLEGAL_SEEN)) | ((*irr | l) & crate::engine::ILLEGAL_SEEN);
        (st, ip)
    }

    /// The first step: decode into the buffer, hand the buffer to the second step, repeat.
    fn dec_call(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        // The buffer between the steps holds at most CHUNK characters, but no decoder makes more than
        // one character per input byte (plus one the decoder held back), so for a short input a
        // smaller buffer can never fill up and behaves the same (and costs less to set up).
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
            // the decoder's count of skipped characters is not part of iconv's result, but the fact that it skipped
            // illegal input must reach the caller (`iconv -c` exits with failure)
            *irr |= lirr & crate::engine::ILLEGAL_SEEN;
            if n > 0 {
                let (res, used) = self.enc_call(&buf[..n], out, op, irr);
                if res != St::Empty {
                    if used != n {
                        // The second step stopped early: redo this round, stopping after exactly
                        // the characters it used.
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

    /// Only one step (the other charset is INTERNAL): run the loop straight on the user's buffers.
    fn single(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        // As `dec_call`: no decoder makes more than one character per input byte (plus one held back) and the encoder side
        // reads four bytes per character, so for a short input a smaller buffer never fills up and behaves the same; it
        // costs less to set up (a `ccs=` stream converts one character per call: zeroing 32 KiB each time made fputwc on
        // such a stream 5 times slower).
        let rem = inp.len() - *ip;
        if rem + 2 <= 64 {
            self.single_n::<64>(inp, ip, out, op, irr)
        } else if rem + 2 <= 1024 {
            self.single_n::<1024>(inp, ip, out, op, irr)
        } else {
            self.single_n::<CHUNK>(inp, ip, out, op, irr)
        }
    }

    fn single_n<const N: usize>(&mut self, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
        let mut buf = [0u32; N];
        if let Some(dec) = self.dec.as_mut() {
            // X -> INTERNAL: the output is host-order UCS-4 in the user's buffer
            if let Some(st) = dec.prepare(&mut self.c1, inp, ip) {
                return st;
            }
            let mut sticky = false;
            loop {
                let cap = ((out.len() - *op) / 4).min(N);
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
                if st == St::Full && cap == N && more {
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
        // INTERNAL -> X (or INTERNAL -> INTERNAL, which only copies)
        let mut sticky = false;
        loop {
            let avail = (inp.len() - *ip) / 4;
            let cnt = avail.min(N);
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
            if st == St::Empty && cnt == N && *ip != inp.len() {
                continue;
            }
            if st == St::Empty && inp.len() - *ip < 4 && *ip != inp.len() {
                // glibc's loop template checks the output room before the cut-off input when an output
                // unit is wider than one byte (UCS-2, UTF-16, UTF-32, UCS-4): E2BIG, not EINVAL
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

    /// iconv(3) on slices: converts `input[*ip..]` into `out[*op..]`, advancing both, and returns
    /// the number of irreversible conversions or the error (the positions then say how far it got).
    pub fn convert_raw(&mut self, input: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize) -> Result<usize, Error> {
        match self.convert_status(input, ip, out, op) {
            (St::Illegal, _) => Err(Error::Ilseq),
            (St::Full, _) => Err(Error::E2big),
            (St::Incomplete, _) => Err(Error::Inval),
            (St::Empty | St::Ok, irr) => Ok(irr),
        }
    }

    /// [`convert_raw`](Self::convert_raw) with glibc's status as it is: the loops end with `Empty` when they used all the input
    /// and with `Ok` when the last thing they did was a transliteration or a skip of a character that fitted. The two mean
    /// the same to `iconv`, but a module that called this step takes `Ok` for "go on" and forgets an error of its own (see
    /// the plug-in chain). The count of irreversible conversions comes second.
    pub(crate) fn convert_status(&mut self, input: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize) -> (St, usize) {
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
        (st, irr)
    }

    /// The decoder's state word for the charsets that keep their state in one integer (the character
    /// held back, shifted left by 3 bits, as in glibc's `mbstate_t.__count`): CP1255, CP1258, TCVN,
    /// BIG5-HKSCS, the JISX0213 sets, EBCDIC and ISO-2022-CN. 0 for every other decoder.
    pub fn dec_state_word(&self) -> u32 {
        match &self.dec {
            Some(Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) | Dec::Eb(_, st) | Dec::Cn(st)) => *st,
            _ => 0,
        }
    }

    /// The bytes that are a character of one byte by themselves, as a 256-bit set, for a stateless CJK charset or BIG5-HKSCS
    /// (what handing the decoder that one byte gives); `None` for other decoders.
    pub fn single_bytes(&self) -> Option<[u64; 4]> {
        match &self.dec {
            Some(Dec::Cjk(k)) if self.c1.flags & IGNORE == 0 => Some(cjk::single_bytes(*k)),
            // (BIG5-HKSCS: 0x00..=0x80 are characters, a lead byte 0x81..=0xfe needs a second one)
            Some(Dec::Hk(_)) if self.c1.flags & IGNORE == 0 => Some([!0, !0, 1, 0]),
            _ => None,
        }
    }

    /// The multibyte characters (two or more bytes, GB18030's four-byte codes not among them) of the charset as rows: `f(head, trails)`
    /// with the head bytes of a row and the 256-bit set of the last bytes that complete a character, in byte order, only the
    /// characters whose value is in `ranges` (sorted, disjoint) when it is given. False (nothing reported) for a charset that
    /// has no rows (see `rows.rs`).
    /// For GB18030 `runs` is called with all of its runs of four-byte codes (as [`each_char`](Self::each_char) reports them), whatever `ranges`
    /// says. (`ranges` empty: the rows are not walked.)
    pub fn each_row(&self, ranges: Option<&[(u32, u32)]>, f: &mut dyn FnMut(&[u8], &[u64; 4]), runs: &mut dyn FnMut(&[u8], u32, u32)) -> bool {
        if self.c1.flags & IGNORE != 0 {
            return false;
        }
        match &self.dec {
            Some(Dec::Cjk(k)) if crate::rows::has_rows(*k) => {
                let m = cjk::mb(*k);
                if *k == cjk::Kind::Gb18030 {
                    cjk::each_run(&m, runs);
                }
                crate::rows::each_row(&m, ranges, f)
            }
            Some(Dec::Hk(_)) => crate::rows::each_row(&crate::mbdata::big5hkscs::mb(), ranges, f),
            _ => false,
        }
    }

    /// Every character of the charset of a stateless CJK or accent decoder (no IGNORE flag), as the walk over all candidate
    /// sequences with [`decode_ucs4`](Self::decode_ucs4) after a reset finds them, in byte order; false (nothing reported) for other decoders.
    /// (`f(bytes, wc, count)`: see [`cjk::each_char`] for the runs of GB18030's four-byte codes, `count` > 1.)
    pub fn each_char(&self, f: &mut dyn FnMut(&[u8], u32, u32)) -> bool {
        match &self.dec {
            Some(Dec::Cjk(k)) if self.c1.flags & IGNORE == 0 => {
                cjk::each_char(*k, f);
                true
            }
            _ => false,
        }
    }

    /// Run only the decoder (the "to wide character" step, as glibc's `mbrtowc` does: one step, the
    /// caller's buffer is the output): `input[*ip..]` into `out[*op..]` as UCS-4 values. `None` when
    /// this conversion has no separate decoder.
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

    /// The encoder's state word (BIG5-HKSCS: the two bytes held back, shifted left by 3 bits, as in glibc's
    /// `mbstate_t.__count` for `wcrtomb`; 0 for every encoder without such a word).
    pub fn enc_state_word(&self) -> u32 {
        match &self.enc {
            Some(Enc::Hk(st)) => *st,
            _ => 0,
        }
    }

    /// Put back a state word read with [`enc_state_word`](Self::enc_state_word).
    pub fn set_enc_state_word(&mut self, v: u32) {
        if let Some(Enc::Hk(st)) = &mut self.enc {
            *st = v;
        }
    }

    /// Put back a state word read with [`dec_state_word`](Self::dec_state_word) (ignored by the
    /// decoders that have no such word).
    pub fn set_dec_state_word(&mut self, v: u32) {
        if let Some(Dec::Hk(st) | Dec::Cp(_, st) | Dec::Jx(_, st) | Dec::Eb(_, st) | Dec::Cn(st)) = &mut self.dec {
            *st = v;
        }
    }

    /// `iconv(cd, NULL, NULL, &out, &outleft)`: write the bytes that return the output to its
    /// initial state, then reset. With `out == None` (`iconv(cd, NULL, NULL, NULL, NULL)`) only reset.
    pub fn flush_raw(&mut self, out: Option<(&mut [u8], &mut usize)>) -> Result<usize, Error> {
        let mut irr_total = 0usize;
        if let Some((o, op)) = out {
            // a character the decoder holds back goes through the second step first
            if self.enc.is_some() {
                if let Some((chars, n)) = self.dec.as_ref().and_then(|d| d.pending()) {
                    let mut irr = 0;
                    let start = *op;
                    let (res, used) = self.enc_call(&chars[..n], o, op, &mut irr);
                    irr_total += irr;
                    if used < n && res != St::Illegal {
                        // (only the TSCII queue has several: all of it goes out or none)
                        *op = start;
                        return Err(if res == St::Full { Error::E2big } else { Error::Ilseq });
                    }
                    if used == 0 {
                        *op = start;
                        return Err(if res == St::Full { Error::E2big } else { Error::Ilseq });
                    }
                    // the held-back character is gone; an error that was ignored still ends the
                    // flush with EILSEQ (and leaves the rest of the reset undone)
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
                // glibc runs the module's preparation (for ISO-2022-KR the header) before emitting
                // the reset sequence, but only for modules that have a reset sequence at all
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
                // (ISO-2022-CN-EXT is the one module whose shift to the initial state counts as an
                // irreversible conversion)
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
