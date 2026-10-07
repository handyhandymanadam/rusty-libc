use crate::engine::*;
use crate::mb::Mb;
use crate::mbdata::{ansi_x3_110, big5, cp932, ibm932, ibm943, euc_cn, euc_jp, euc_jp_ms, euc_kr, euc_tw, gb18030, gbk, iso_6937, iso_6937_2, johab, sjis, t61, uhc};

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

pub fn mb(k: Kind) -> &'static Mb {
    match k {
        Kind::EucKr => &euc_kr::MB,
        Kind::EucCn => &euc_cn::MB,
        Kind::EucJp => &euc_jp::MB,
        Kind::Uhc => &uhc::MB,
        Kind::Gbk => &gbk::MB,
        Kind::Sjis => &sjis::MB,
        Kind::Cp932 => &cp932::MB,
        Kind::Big5 => &big5::MB,
        Kind::Johab => &johab::MB,
        Kind::EucTw => &euc_tw::MB,
        Kind::Gb18030 => &gb18030::MB,
        Kind::EucJpMs => &euc_jp_ms::MB,
        Kind::Iso6937 => &iso_6937::MB,
        Kind::Iso6937_2 => &iso_6937_2::MB,
        Kind::T61 => &t61::MB,
        Kind::AnsiX3110 => &ansi_x3_110::MB,
        Kind::Ibm932 => &ibm932::MB,
        Kind::Ibm943 => &ibm943::MB,
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
        const INIT: [i8; 32] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1];
        const MID: [i8; 32] = [-1, -1, 0, 1, 2, 3, 4, 5, -1, -1, 6, 7, 8, 9, 10, 11, -1, -1, 12, 13, 14, 15, 16, 17, -1, -1, 18, 19, 20, 21, -1, -1];
        const FIN: [i8; 32] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1];
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
        let Some(set) = mb.sets.iter().position(|st| st.prefix == [0x8e, b2]) else {
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

pub fn dec(k: Kind, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let m = mb(k);
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
    let m = mb(k);
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
            if let (EBody::Full, 2) = (&r, o.len()) {
                if let Some(code) = m.enc(c) {
                    o[1] = code.bytes[1] & 0x7f;
                }
            }
            r
        }),
        Kind::EucKr => enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, fast, &mut |s: &[u32], o: &mut [u8]| {
            let r = enc_generic(m, s[0], o);
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
