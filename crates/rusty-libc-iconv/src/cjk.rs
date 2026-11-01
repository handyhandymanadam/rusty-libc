//! The multibyte charsets of East Asia. The tables come from `mbdata/` (generated from the host's
//! iconv); the control flow of each charset (valid byte ranges, when input is incomplete, how many
//! bytes an error skips, the order in which "output full" and "unrepresentable" are decided) follows
//! the glibc module of the same name and is checked against it by the differential tests.
use crate::engine::*;
use crate::mb::{Mb, ool};
use crate::mbdata::{ansi_x3_110, big5, cp932, ibm932, ibm943, euc_cn, euc_jp, euc_jp_ms, euc_kr, euc_tw, gb18030, gbk, iso_6937, iso_6937_2, johab, sjis, t61, uhc};

/// The charsets, in the order of their special codes (`CJK_BASE` + index) in the alias table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    EucKr,
    EucCn,
    EucJp,
    Uhc,
    Gbk,
    Sjis,
    Cp932,
    Big5,
    Johab,
    EucTw,
    Gb18030,
    EucJpMs,
    Iso6937,
    Iso6937_2,
    T61,
    AnsiX3110,
    Ibm932,
    Ibm943,
}

pub const KINDS: [Kind; 18] = [Kind::EucKr, Kind::EucCn, Kind::EucJp, Kind::Uhc, Kind::Gbk, Kind::Sjis, Kind::Cp932, Kind::Big5, Kind::Johab, Kind::EucTw, Kind::Gb18030, Kind::EucJpMs, Kind::Iso6937, Kind::Iso6937_2, Kind::T61, Kind::AnsiX3110, Kind::Ibm932, Kind::Ibm943];
pub const CJK_BASE: u8 = 16;

pub fn mb(k: Kind) -> Mb {
    match k {
        Kind::EucKr => ool(euc_kr::mb),
        Kind::EucCn => ool(euc_cn::mb),
        Kind::EucJp => ool(euc_jp::mb),
        Kind::Uhc => ool(uhc::mb),
        Kind::Gbk => ool(gbk::mb),
        Kind::Sjis => ool(sjis::mb),
        Kind::Cp932 => ool(cp932::mb),
        Kind::Big5 => ool(big5::mb),
        Kind::Johab => ool(johab::mb),
        Kind::EucTw => ool(euc_tw::mb),
        Kind::Gb18030 => ool(gb18030::mb),
        Kind::EucJpMs => ool(euc_jp_ms::mb),
        Kind::Iso6937 => ool(iso_6937::mb),
        Kind::Iso6937_2 => ool(iso_6937_2::mb),
        Kind::T61 => ool(t61::mb),
        Kind::AnsiX3110 => ool(ansi_x3_110::mb),
        Kind::Ibm932 => ool(ibm932::mb),
        Kind::Ibm943 => ool(ibm943::mb),
    }
}

#[inline(always)]
fn body_euc_kr(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x9f {
        Body::Char(ch as u32, 1)
    } else if ch == 0xa0 {
        Body::Illegal(1)
    } else {
        if s.len() < 2 {
            return Body::Incomplete;
        }
        let b2 = s[1];
        if ch == 0xfe || ch == 0xc9 || b2 <= 0xa0 || b2 == 0xff {
            return Body::Illegal(2);
        }
        match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(2),
        }
    }
}

#[inline(always)]
fn body_euc_cn(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        Body::Char(ch as u32, 1)
    } else if (ch <= 0xa0 && ch != 0x8e && ch != 0x8f) || ch == 0xff {
        Body::Illegal(1)
    } else {
        if s.len() < 2 {
            return Body::Incomplete;
        }
        let b2 = s[1];
        if b2 < 0xa1 {
            return Body::Illegal(1);
        }
        match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(2),
        }
    }
}

#[inline(always)]
fn body_euc_jp(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch < 0x8e || (0x90..=0x9f).contains(&ch) {
        return Body::Char(ch as u32, 1);
    }
    if ch == 0xff {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if b2 < 0xa1 {
        return Body::Illegal(1);
    }
    if ch == 0x8e {
        return match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(1),
        };
    }
    if ch == 0x8f {
        if !(0xa2..=0xed).contains(&b2) {
            return Body::Illegal(1);
        }
        if s.len() < 3 {
            return Body::Incomplete;
        }
        return match mb.dec2(3, b2, s[2]) {
            Some(c) => Body::Char(c, 3),
            None => Body::Illegal(1),
        };
    }
    match mb.dec2(2, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(1),
    }
}


#[inline(always)]
fn body_uhc(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        return Body::Char(ch as u32, 1);
    }
    if ch <= 0x80 || ch >= 0xfe || ch == 0xc9 {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if ch < 0xa1 || b2 < 0xa1 {
        if ch > 0xc6 || b2 < 0x41 || b2 > 0xfe || (b2 > 0x5a && b2 < 0x61) || (b2 > 0x7a && b2 < 0x81) || (ch == 0xc6 && b2 > 0x52) {
            return Body::Illegal(1);
        }
    }
    if ch == 0xa2 && b2 == 0xe8 {
        // U+327E is in KS C 5601 but UHC refuses it after having stepped over it
        return Body::IllegalAfter(2, 2);
    }
    match mb.dec2(1, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(2),
    }
}

#[inline(always)]
fn body_gbk(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        return Body::Char(ch as u32, 1);
    }
    if ch == 0x80 {
        return Body::Char(0x20ac, 1);
    }
    if ch == 0xff {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if b2 < 0x40 || (ch == 0xfe && b2 > 0xa0) {
        return Body::Illegal(1);
    }
    match mb.dec2(1, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(2),
    }
}

#[inline(always)]
fn body_sjis(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch < 0x80 || (0xa1..=0xdf).contains(&ch) {
        return Body::Char(mb.dec1(ch).unwrap_or(ch as u32), 1);
    }
    if ch > 0xea || ch == 0xa0 || ch <= 0x80 {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    if s[1] < 0x40 {
        return Body::Illegal(1);
    }
    match mb.dec2(1, ch, s[1]) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(2),
    }
}

#[inline(always)]
fn body_cp932(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch < 0x80 || (0xa1..=0xdf).contains(&ch) {
        return Body::Char(mb.dec1(ch).unwrap_or(ch as u32), 1);
    }
    if ch == 0xa0 || ch <= 0x80 || ch > 0xfc {
        return Body::IllegalQuiet(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    let idx = (ch as u32) * 256 + b2 as u32;
    if b2 < 0x40
        || b2 > 0xfc
        || b2 == 0x7f
        || (idx > 0x84be && idx < 0x8740)
        || (idx > 0x879c && idx < 0x889f)
        || (idx > 0x88fc && idx < 0x8940)
        || (idx > 0x9ffc && idx < 0xe040)
        || (idx > 0xeaa4 && idx < 0xed40)
        || (idx > 0xeefc && idx < 0xf040)
        || idx > 0xfc4b
    {
        return Body::IllegalQuiet(1);
    }
    match mb.dec2(1, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::IllegalQuiet(2),
    }
}

#[inline(always)]
fn body_big5(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if (0xa1..=0xf9).contains(&ch) {
        if s.len() < 2 {
            return Body::Incomplete;
        }
        let b2 = s[1];
        if !((0x40..=0x7e).contains(&b2) || (0xa1..=0xfe).contains(&b2)) {
            return Body::Illegal(1);
        }
        match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(2),
        }
    } else if ch <= 0x80 {
        Body::Char(ch as u32, 1)
    } else {
        Body::Illegal(1)
    }
}

#[inline(always)]
fn body_johab(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        return Body::Char(mb.dec1(ch).unwrap_or(ch as u32), 1);
    }
    if ch > 0xf9 || ch == 0xdf || (ch > 0x7e && ch < 0x84) || (ch > 0xd3 && ch < 0xd9) {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if ch <= 0xd3 {
        // Hangul: initial, medial and final jamo in 5 bits each
        const INIT: [i8; 32] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1];
        const MID: [i8; 32] = [-1, -1, 0, 1, 2, 3, 4, 5, -1, -1, 6, 7, 8, 9, 10, 11, -1, -1, 12, 13, 14, 15, 16, 17, -1, -1, 18, 19, 20, 21, -1, -1];
        const FIN: [i8; 32] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1];
        // finals that have a compatibility jamo of their own
        const FIN_ALONE: [bool; 31] = [false, false, true, false, true, true, false, false, true, true, true, true, true, true, true, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false];
        let idx = (ch as usize) << 8 | b2 as usize;
        let (i, m, f) = (INIT[(idx & 0x7c00) >> 10], MID[(idx & 0x03e0) >> 5], FIN[idx & 0x1f]);
        if i == -1 || m == -1 || f == -1 {
            return Body::Illegal(1);
        }
        if (i > 0 && m > 0) || (i > 0 && m == 0 && f == 0) || (i == 0 && m > 0 && f == 0) {
            return match mb.dec2(1, ch, b2) {
                Some(c) => Body::Char(c, 2),
                None => Body::Illegal(2),
            };
        }
        if (i | m) == 0 && f > 0 {
            return if FIN_ALONE[f as usize - 1] { mb.dec2(1, ch, b2).map_or(Body::Illegal(2), |c| Body::Char(c, 2)) } else { Body::Illegal(2) };
        }
        return Body::Illegal(1);
    }
    if b2 < 0x31 || (b2 > 0x7e && b2 < 0x91) || b2 == 0xff || (ch == 0xd9 && b2 > 0xe8) || (ch == 0xda && b2 > 0xa0 && b2 < 0xd4) || (ch == 0xde && b2 > 0xf1) {
        return Body::Illegal(1);
    }
    match mb.dec2(1, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(2),
    }
}

#[inline(always)]
fn body_euc_tw(mb: &Mb, s: &[u8]) -> Body {
    body_euc_tw_by(mb, s, |b2| euc_tw_plane_set(mb, b2))
}

/// The set of CNS 11643 plane `b2` (0xa1 = plane 1) in EUC-TW's tables: planes without characters have none.
#[inline(always)]
fn euc_tw_plane_set(mb: &Mb, b2: u8) -> Option<usize> {
    mb.sets.iter().position(|st| st.prefix() == [0x8e, b2])
}

/// [`body_euc_tw`] with the plane's set found by `plane_set` (the walk of [`each_char`] looks each plane up once).
#[inline(always)]
fn body_euc_tw_by(mb: &Mb, s: &[u8], plane_set: impl Fn(u8) -> Option<usize>) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        return Body::Char(ch as u32, 1);
    }
    if (ch <= 0xa0 || ch == 0xff) && ch != 0x8e {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if b2 < 0xa1 || b2 == 0xff {
        return Body::Illegal(1);
    }
    if ch == 0x8e {
        if b2 > 0xb0 {
            return Body::Illegal(1);
        }
        if s.len() < 4 {
            return Body::Incomplete;
        }
        // planes without characters have no set
        let Some(set) = plane_set(b2) else {
            return Body::Illegal(1);
        };
        return match mb.dec2(set, s[2], s[3]) {
            Some(c) => Body::Char(c, 4),
            None => Body::Illegal(1),
        };
    }
    match mb.dec2(1, ch, b2) {
        Some(c) => Body::Char(c, 2),
        None => Body::Illegal(2),
    }
}

#[inline(always)]
fn body_gb18030(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if ch <= 0x7f {
        return Body::Char(ch as u32, 1);
    }
    if ch < 0x81 || ch > 0xfe {
        return Body::Illegal(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if b2 < 0x30 {
        return Body::Illegal(2);
    }
    if b2 <= 0x39 {
        if s.len() < 4 {
            return Body::Incomplete;
        }
        let (b3, b4) = (s[2], s[3]);
        if !(0x81..=0xfe).contains(&b3) {
            return Body::Illegal(3);
        }
        if !(0x30..=0x39).contains(&b4) {
            return Body::Illegal(4);
        }
        let idx = (((ch as u32 - 0x81) * 10 + (b2 as u32 - 0x30)) * 126 + (b3 as u32 - 0x81)) * 10 + (b4 as u32 - 0x30);
        return match mb.dec_run(idx) {
            Some(c) => Body::Char(c, 4),
            None => Body::Illegal(4),
        };
    }
    if b2 >= 0x40 {
        return match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(2),
        };
    }
    Body::Illegal(2)
}

/// A character's code in GB18030: one or two bytes from the table, or four from the linear ranges.
#[inline(always)]
fn enc_gb18030(mb: &Mb, c: u32, o: &mut [u8]) -> EBody {
    if let Some(code) = mb.enc(c) {
        let n = code.len as usize;
        if n > o.len() {
            return EBody::Full;
        }
        o[..n].copy_from_slice(&code.bytes[..n]);
        return EBody::Ok(1, n);
    }
    match mb.enc_run(c) {
        None => EBody::Illegal,
        Some(idx) => {
            if o.len() < 4 {
                return EBody::Full;
            }
            o[3] = (idx % 10) as u8 + 0x30;
            let r = idx / 10;
            o[2] = (r % 126) as u8 + 0x81;
            let r = r / 126;
            o[1] = (r % 10) as u8 + 0x30;
            o[0] = (r / 10) as u8 + 0x81;
            EBody::Ok(1, 4)
        }
    }
}

#[inline(always)]
fn body_euc_jp_ms(mb: &Mb, s: &[u8], ignore: bool) -> Body {
    let ch = s[0];
    if ch < 0x8e || (0x90..=0x9f).contains(&ch) {
        return Body::Char(ch as u32, 1);
    }
    if ch == 0xff {
        return Body::IllegalQuiet(1);
    }
    if s.len() < 2 {
        return Body::Incomplete;
    }
    let b2 = s[1];
    if b2 < 0xa1 {
        return Body::IllegalQuiet(1);
    }
    if ch == 0x8e {
        return match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            // glibc skips the two bytes but still writes U+FFFD when it is ignoring errors
            None if ignore => Body::Char(0xfffd, 2),
            None => Body::IllegalQuiet(2),
        };
    }
    if ch == 0x8f {
        if s.len() < 3 {
            return Body::Incomplete;
        }
        let b3 = s[2];
        if b3 == 0xff || b3 < 0xa1 {
            return Body::IllegalQuiet(3);
        }
        return match mb.dec2(3, b2, b3) {
            Some(c) => Body::Char(c, 3),
            None => Body::IllegalQuiet(3),
        };
    }
    if ch >= 0xa1 {
        if b2 == 0xff {
            return Body::IllegalQuiet(2);
        }
        return match mb.dec2(2, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::IllegalQuiet(2),
        };
    }
    Body::IllegalQuiet(1)
}

/// ISO 6937, T.61 and ANSI X3.110: a prefix byte 0xc1..0xcf (a diacritical mark) and a letter.
#[inline(always)]
fn body_accent(mb: &Mb, s: &[u8]) -> Body {
    let ch = s[0];
    if (0xc1..=0xcf).contains(&ch) {
        if s.len() < 2 {
            return Body::Incomplete;
        }
        let b2 = s[1];
        if b2 < 0x20 || b2 >= 0x80 {
            return Body::Illegal(1);
        }
        match mb.dec2(1, ch, b2) {
            Some(c) => Body::Char(c, 2),
            None => Body::Illegal(2),
        }
    } else {
        match mb.dec1(ch) {
            Some(c) => Body::Char(c, 1),
            None => Body::Illegal(1),
        }
    }
}

/// IBM932 and IBM943 (Shift JIS style): every byte that is not a character of its own and not one
/// of the invalid ones starts a two-byte code (in IBM943 every byte above 0xdf does).
#[inline(always)]
fn body_ibm_sjis(mb: &Mb, s: &[u8], is943: bool) -> Body {
    let ch = s[0];
    if ch == 0x80 || ch == 0xa0 || ch >= 0xfd {
        return Body::Illegal(1);
    }
    let sb = if is943 && ch > 0xdf { None } else { mb.dec1(ch) };
    match sb {
        Some(c) => Body::Char(c, 1),
        None => {
            if s.len() < 2 {
                return Body::Incomplete;
            }
            match mb.dec2(1, ch, s[1]) {
                Some(c) => Body::Char(c, 2),
                None => Body::Illegal(2),
            }
        }
    }
}

/// Every character of the charset as the walk over candidate sequences finds it (each byte tried after a prefix that is the
/// start of a longer character, up to 4 bytes), each candidate decided as [`dec`] decides it with room for one character
/// and no IGNORE flag (ASCII through the fast path where `dec` has one, a body that uses fewer bytes or gives two
/// characters is no character): `f(bytes, wc, 1)`, in byte order. (None of these bodies skips bytes;
/// `each_char_matches_decode` checks the whole walk against [`dec`] for every kind.)
///
/// GB18030's four-byte codes (about 1,100,000 characters, mapped to Unicode in long linear runs) are not walked: after the
/// walk of its one- and two-byte codes, each run comes as one call `f(first code, first character, count)`: the run is
/// the `count` codes from the first one on in the four-byte order (the last byte counts 0x30..=0x39, then the third
/// 0x81..=0xfe, the second 0x30..=0x39, the first 0x81..=0xfe), with the characters `wc`, `wc + 1` ... (see [`gb18030_code`]).
pub fn each_char(k: Kind, f: &mut dyn FnMut(&[u8], u32, u32)) {
    let m = &mb(k);
    let ascii = !matches!(k, Kind::Sjis | Kind::Johab | Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 | Kind::Ibm932 | Kind::Ibm943);
    let p = &mut [0u8; 4];
    // The EUC charsets reject every byte below 0xa1 after the first (each body says so, or its tables have no such
    // cell; `each_char_matches_decode` checks the walk against a full walk with `dec`): their walk tries only 0xa1..=0xff
    // there, about a fifth of the candidates (EUC-JP: 0x8f alone had 65,536 three-byte ones).
    let lo = if matches!(k, Kind::EucKr | Kind::EucCn | Kind::EucJp | Kind::EucTw | Kind::EucJpMs) { 0xa1 } else { 0 };
    if k == Kind::Gb18030 {
        // the one- and two-byte codes (a prefix whose second byte is a digit starts a four-byte code: not walked)
        let dead = |s: &[u8]| s.len() == 2 && (0x30..=0x39).contains(&s[1]);
        walk_body(ascii, &|s| body_gb18030(m, s), &dead, p, 0, lo, &mut |b, wc| f(b, wc, 1));
        // the four-byte codes: the index of a code is what body_gb18030 computes; every index below the last code's has
        // a code, and the character of an index is `dec_run`'s (its runs, sorted by index)
        each_run(m, f);
        return;
    }
    each_char_from(k, lo, &mut |b, wc| f(b, wc, 1), m, ascii, p)
}

/// GB18030's runs of four-byte codes as [`each_char`] reports them: `f(first code, first character, count)`.
pub fn each_run(m: &Mb, f: &mut dyn FnMut(&[u8], u32, u32)) {
    for (i, &(idx, wc, n)) in m.runs_dec.iter().enumerate() {
        if idx >= GB18030_FOUR || n == 0 {
            continue;
        }
        // (`dec_run` takes the last run that starts at or below an index: a run ends where the next one starts)
        let end = m.runs_dec.get(i + 1).map_or(GB18030_FOUR, |r| r.0.min(GB18030_FOUR));
        let n = n.min(end.saturating_sub(idx));
        if n == 0 {
            continue;
        }
        f(&gb18030_code(idx), wc, n);
    }
}

/// The number of four-byte GB18030 codes (indices 0..GB18030_FOUR).
pub const GB18030_FOUR: u32 = 126 * 10 * 126 * 10;

/// The four-byte GB18030 code of an index below [`GB18030_FOUR`] (the inverse of the index body_gb18030 computes).
pub fn gb18030_code(idx: u32) -> [u8; 4] {
    [(0x81 + idx / 12600) as u8, (0x30 + idx / 1260 % 10) as u8, (0x81 + idx / 10 % 126) as u8, (0x30 + idx % 10) as u8]
}

/// [`each_char`] with the bytes after the first taken from `lo` up.
fn each_char_from(k: Kind, lo: u8, f: &mut dyn FnMut(&[u8], u32), m: &Mb, ascii: bool, p: &mut [u8; 4]) {
    match k {
        Kind::EucKr => walk_body(ascii, &|s| body_euc_kr(m, s), &no_prune, p, 0, lo, f),
        Kind::EucCn => walk_body(ascii, &|s| body_euc_cn(m, s), &no_prune, p, 0, lo, f),
        Kind::EucJp => walk_body(ascii, &|s| body_euc_jp(m, s), &no_prune, p, 0, lo, f),
        Kind::Uhc => walk_body(ascii, &|s| body_uhc(m, s), &no_prune, p, 0, lo, f),
        Kind::Gbk => walk_body(ascii, &|s| body_gbk(m, s), &no_prune, p, 0, lo, f),
        Kind::Sjis => walk_body(ascii, &|s| body_sjis(m, s), &no_prune, p, 0, lo, f),
        Kind::Cp932 => walk_body(ascii, &|s| body_cp932(m, s), &no_prune, p, 0, lo, f),
        Kind::Big5 => walk_body(ascii, &|s| body_big5(m, s), &no_prune, p, 0, lo, f),
        Kind::Johab => walk_body(ascii, &|s| body_johab(m, s), &no_prune, p, 0, lo, f),
        Kind::EucTw => {
            // each plane's set looked up once for the walk, not once per candidate (EUC-TW has about 150,000 four-byte ones)
            let mut planes = [None; 16];
            for (i, slot) in planes.iter_mut().enumerate() {
                *slot = euc_tw_plane_set(m, 0xa1 + i as u8);
            }
            // a plane without a set, or a row its set does not have, starts no character: its candidates are not tried
            let dead = |s: &[u8]| match *s {
                [0x8e, b2] => (0xa1..=0xb0).contains(&b2) && planes[usize::from(b2 - 0xa1)].is_none(),
                [0x8e, b2, b3] => (0xa1..=0xb0).contains(&b2)
                    && planes[usize::from(b2 - 0xa1)].is_some_and(|i| b3 < m.sets[i].lead_lo || b3 > m.sets[i].lead_hi),
                _ => false,
            };
            walk_body(ascii, &|s| body_euc_tw_by(m, s, |b2| planes[usize::from(b2 - 0xa1)]), &dead, p, 0, lo, f)
        }
        Kind::Gb18030 => walk_body(ascii, &|s| body_gb18030(m, s), &no_prune, p, 0, lo, f),
        Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 => walk_body(ascii, &|s| body_accent(m, s), &no_prune, p, 0, lo, f),
        Kind::Ibm932 | Kind::Ibm943 => walk_body(ascii, &|s| body_ibm_sjis(m, s, k == Kind::Ibm943), &no_prune, p, 0, lo, f),
        Kind::EucJpMs => walk_body(ascii, &|s| body_euc_jp_ms(m, s, false), &no_prune, p, 0, lo, f),
    }
}

/// The bytes that are a whole character by themselves (what a decoder gives one character of one byte for when it is handed
/// just that byte), as a 256-bit set: the single-byte characters of the walk of [`each_char`].
pub fn single_bytes(k: Kind) -> [u64; 4] {
    fn of<B: Fn(&[u8]) -> Body>(ascii: bool, body: B) -> [u64; 4] {
        let mut s = [0u64; 4];
        for b in 0..=255u8 {
            if (ascii && b < 0x80) || matches!(body(&[b]), Body::Char(_, 1)) {
                s[usize::from(b >> 6)] |= 1u64 << (b & 63);
            }
        }
        s
    }
    let m = &mb(k);
    let ascii = !matches!(k, Kind::Sjis | Kind::Johab | Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 | Kind::Ibm932 | Kind::Ibm943);
    match k {
        Kind::EucKr => of(ascii, |s| body_euc_kr(m, s)),
        Kind::EucCn => of(ascii, |s| body_euc_cn(m, s)),
        Kind::EucJp => of(ascii, |s| body_euc_jp(m, s)),
        Kind::Uhc => of(ascii, |s| body_uhc(m, s)),
        Kind::Gbk => of(ascii, |s| body_gbk(m, s)),
        Kind::Sjis => of(ascii, |s| body_sjis(m, s)),
        Kind::Cp932 => of(ascii, |s| body_cp932(m, s)),
        Kind::Big5 => of(ascii, |s| body_big5(m, s)),
        Kind::Johab => of(ascii, |s| body_johab(m, s)),
        Kind::EucTw => of(ascii, |s| body_euc_tw(m, s)),
        Kind::Gb18030 => of(ascii, |s| body_gb18030(m, s)),
        Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 => of(ascii, |s| body_accent(m, s)),
        Kind::Ibm932 | Kind::Ibm943 => of(ascii, |s| body_ibm_sjis(m, s, k == Kind::Ibm943)),
        Kind::EucJpMs => of(ascii, |s| body_euc_jp_ms(m, s, false)),
    }
}

/// For [`walk_body`]: every incomplete prefix may start a character.
fn no_prune(_: &[u8]) -> bool {
    false
}

/// The walk of [`each_char`] with one body (generic, so that the body is inlined into the loop over candidates). `dead(prefix)`
/// says that no sequence that starts with the incomplete `prefix` is a character, so its candidates need not be tried.
fn walk_body<B: Fn(&[u8]) -> Body, D: Fn(&[u8]) -> bool>(ascii: bool, body: &B, dead: &D, p: &mut [u8; 4], len: usize, lo: u8, f: &mut dyn FnMut(&[u8], u32)) {
    for b in (if len == 0 { 0 } else { lo })..=255u8 {
        p[len] = b;
        let n = len + 1;
        let s = &p[..n];
        let r = if ascii && s[0] < 0x80 {
            if n == 1 { Ok(s[0] as u32) } else { Err(false) }
        } else {
            match body(s) {
                Body::Char(c, used) => if used == n { Ok(c) } else { Err(false) },
                Body::Incomplete => Err(true),
                _ => Err(false),
            }
        };
        match r {
            Ok(wc) => f(&p[..n], wc),
            Err(true) if n < 4 && !dead(&p[..n]) => walk_body(ascii, body, dead, p, n, lo, f),
            Err(_) => {}
        }
    }
}

pub fn dec(k: Kind, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let m = &mb(k);
    let ascii = |s: &[u8], o: &mut [u32]| -> (usize, usize) {
        if s[0] >= 0x80 {
            return (0, 0);
        }
        let n = s.len().min(o.len());
        let mut j = 0;
        while j < n && s[j] < 0x80 {
            o[j] = s[j] as u32;
            j += 1;
        }
        (j, j)
    };
    match k {
        Kind::EucKr => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_euc_kr(m, s)),
        Kind::EucCn => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_euc_cn(m, s)),
        Kind::EucJp => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_euc_jp(m, s)),
        Kind::Uhc => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_uhc(m, s)),
        Kind::Gbk => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_gbk(m, s)),
        Kind::Sjis => dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| body_sjis(m, s)),
        Kind::Cp932 => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_cp932(m, s)),
        Kind::Big5 => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_big5(m, s)),
        Kind::Johab => dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| body_johab(m, s)),
        Kind::EucTw => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_euc_tw(m, s)),
        Kind::Gb18030 => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_gb18030(m, s)),
        Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 => dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| body_accent(m, s)),
        Kind::Ibm932 | Kind::Ibm943 => dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| body_ibm_sjis(m, s, k == Kind::Ibm943)),
        Kind::EucJpMs => dec_loop(flags, inp, ip, out, op, irr, 1, ascii, |s| body_euc_jp_ms(m, s, flags & IGNORE != 0)),
    }
}

/// The generic encoder body: look the character up, then see whether its bytes fit.
#[inline(always)]
fn enc_generic(mb: &Mb, c: u32, o: &mut [u8]) -> EBody {
    match mb.enc(c) {
        None => EBody::Illegal,
        Some(code) => {
            let n = code.len as usize;
            if n > o.len() {
                return EBody::Full;
            }
            o[..n].copy_from_slice(&code.bytes[..n]);
            EBody::Ok(1, n)
        }
    }
}

pub fn enc(k: Kind, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let m = &mb(k);
    // ASCII is plain in all of them but SJIS (backslash and tilde) and JOHAB (backslash)
    let plain = !matches!(k, Kind::Sjis | Kind::Johab | Kind::Iso6937 | Kind::Iso6937_2 | Kind::T61 | Kind::AnsiX3110 | Kind::Ibm932 | Kind::Ibm943);
    let fast = |s: &[u32], o: &mut [u8]| -> (usize, usize) {
        if !plain {
            return (0, 0);
        }
        let n = s.len().min(o.len());
        let mut j = 0;
        while j < n && s[j] < 0x80 {
            o[j] = s[j] as u8;
            j += 1;
        }
        (j, j)
    };
    match k {
        Kind::EucJp => enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, fast, &mut |s: &[u32], o: &mut [u8]| {
            let c = s[0];
            if c < 0x8e || (0x90..=0x9f).contains(&c) {
                o[0] = c as u8;
                return EBody::Ok(1, 1);
            }
            if c == 0xa5 || c == 0x203e {
                o[0] = if c == 0xa5 { 0x5c } else { 0x7e };
                return EBody::Ok(1, 1);
            }
            if o.len() < 2 {
                return EBody::Full;
            }
            let r = enc_generic(m, c, o);
            // glibc's JIS X 0212 lookup stores the first byte of the code (without the high bit) before it finds the room too
            // small: a 3-byte character with 2 bytes left leaves that byte behind in the output
            if let (EBody::Full, 2) = (&r, o.len()) {
                if let Some(code) = m.enc(c) {
                    o[1] = code.bytes[1] & 0x7f;
                }
            }
            r
        }),
        Kind::EucKr => enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, fast, &mut |s: &[u32], o: &mut [u8]| {
            let r = enc_generic(m, s[0], o);
            // glibc's EUC-KR step stores the first byte of a two-byte character before it finds no room for the second
            if let (EBody::Full, 1) = (&r, o.len()) {
                if let Some(code) = m.enc(s[0]) {
                    o[0] = code.bytes[0];
                }
            }
            r
        }),
        Kind::Gb18030 => enc_loop(flags, inp, ip, out, op, irr, 1, false, &mut no_prep, fast, &mut |s: &[u32], o: &mut [u8]| enc_gb18030(m, s[0], o)),
        _ => enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, fast, &mut |s: &[u32], o: &mut [u8]| enc_generic(m, s[0], o)),
    }
}
