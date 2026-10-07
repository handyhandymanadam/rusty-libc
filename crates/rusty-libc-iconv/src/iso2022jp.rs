use crate::engine::*;
use crate::jpextra;
use crate::mbdata::{euc_cn, euc_jp, euc_kr};
use crate::unicode::Sb;

const ESC: u8 = 0x1b;

const ASCII_SET: u8 = 0;
const J0208_1978: u8 = 1;
const J0208_1983: u8 = 2;
const ROMAN: u8 = 3;
const KANA: u8 = 4;
pub(crate) const GB2312: u8 = 5;
pub(crate) const KSC5601: u8 = 6;
const J0212: u8 = 7;

const G2_NONE: u8 = 0;
const G2_8859_1: u8 = 1;
const G2_8859_7: u8 = 2;

const TAG_NONE: u8 = 0;
const TAG_LANGUAGE: u8 = 4;
const TAG_J: u8 = 5;
const TAG_JA: u8 = 1;
const TAG_K: u8 = 6;
const TAG_KO: u8 = 2;
const TAG_Z: u8 = 7;
const TAG_ZH: u8 = 3;

#[derive(Clone, Copy, Default, Debug)]
pub struct JpState {
    pub set: u8,
    pub set2: u8,
    pub tag: u8,
}

fn iso8859_7() -> &'static Sb {
    let i = crate::charsets_gen::SBS.binary_search_by(|t| t.name().cmp("ISO-8859-7")).unwrap();
    &crate::charsets_gen::SBS[i]
}

pub(crate) enum SetRes {
    Char(u32),
    Unknown,
    Incomplete,
}

pub(crate) fn dec_set(set: u8, s: &[u8]) -> SetRes {
    let (b1, avail) = (s[0], s.len());
    let lead_ok = match set {
        J0208_1978 | J0208_1983 => b1 > 0x20,
        J0212 => (0x22..=0x6d).contains(&b1),
        GB2312 => (0x21..=0x77).contains(&b1),
        _ => !(b1 <= 0x20 || b1 >= 0x7e || b1 == 0x49),
    };
    if set == KSC5601 {
        if avail < 2 {
            return SetRes::Incomplete;
        }
        if !lead_ok {
            return SetRes::Unknown;
        }
    } else {
        if !lead_ok {
            return SetRes::Unknown;
        }
        if avail < 2 {
            return SetRes::Incomplete;
        }
    }
    let b2 = s[1];
    if b2 <= 0x20 || b2 >= 0x7f {
        return SetRes::Unknown;
    }
    let (m, si) = match set {
        J0208_1978 | J0208_1983 => (&euc_jp::MB, 2),
        J0212 => (&euc_jp::MB, 3),
        GB2312 => (&euc_cn::MB, 1),
        _ => (&euc_kr::MB, 1),
    };
    match m.dec2(si, b1 | 0x80, b2 | 0x80) {
        Some(c) => SetRes::Char(c),
        None => SetRes::Unknown,
    }
}

pub fn dec(st: &mut JpState, jp2: bool, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let ch = s[0];
        if ch == ESC {
            if s.len() < 3 || (jp2 && s[1] == b'$' && s[2] == b'(' && s.len() < 4) {
                return Body::Incomplete;
            }
            if s[1] == b'(' {
                match s[2] {
                    b'B' => {
                        st.set = ASCII_SET;
                        return Body::Skip(3);
                    }
                    b'J' => {
                        st.set = ROMAN;
                        return Body::Skip(3);
                    }
                    b'I' if jp2 => {
                        st.set = KANA;
                        return Body::Skip(3);
                    }
                    _ => {}
                }
            } else if s[1] == b'$' {
                match s[2] {
                    b'@' => {
                        st.set = J0208_1978;
                        return Body::Skip(3);
                    }
                    b'B' => {
                        st.set = J0208_1983;
                        return Body::Skip(3);
                    }
                    b'A' if jp2 => {
                        st.set = GB2312;
                        return Body::Skip(3);
                    }
                    b'(' if jp2 => match s[3] {
                        b'C' => {
                            st.set = KSC5601;
                            return Body::Skip(4);
                        }
                        b'D' => {
                            st.set = J0212;
                            return Body::Skip(4);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            } else if jp2 && s[1] == b'.' {
                match s[2] {
                    b'A' => {
                        st.set2 = G2_8859_1;
                        return Body::Skip(3);
                    }
                    b'F' => {
                        st.set2 = G2_8859_7;
                        return Body::Skip(3);
                    }
                    _ => {}
                }
            }
        }
        if ch == ESC && jp2 && s[1] == b'N' {
            if st.set2 == G2_8859_1 {
                return Body::Char((s[2] | 0x80) as u32, 3);
            } else if st.set2 == G2_8859_7 {
                if s[2] < 0x20 || s[2] >= 0x80 {
                    return Body::Illegal(1);
                }
                let c = iso8859_7().dec()[s[2] as usize + 0x80];
                if c == 0xffff {
                    return Body::Illegal(3);
                }
                return Body::Char(c as u32, 3);
            } else {
                return Body::Illegal(1);
            }
        }
        if ch >= 0x80 {
            return Body::Illegal(1);
        }
        if st.set == ASCII_SET || ch < 0x21 || ch == 0x7f {
            return Body::Char(ch as u32, 1);
        }
        match st.set {
            ROMAN => match ch {
                0x5c => Body::Char(0xa5, 1),
                0x7e => Body::Char(0x203e, 1),
                _ => Body::Char(ch as u32, 1),
            },
            KANA => {
                if ch <= 0x5f {
                    Body::Char(0xff61 + (ch as u32 - 0x21), 1)
                } else {
                    Body::Illegal(1)
                }
            }
            set => match dec_set(set, s) {
                SetRes::Char(c) => Body::Char(c, 2),
                SetRes::Incomplete => Body::Incomplete,
                SetRes::Unknown => Body::Illegal(1),
            },
        }
    })
}

pub(crate) fn jis0201(c: u32) -> Option<u8> {
    if c == 0xa5 {
        Some(0x5c)
    } else if c == 0x203e {
        Some(0x7e)
    } else if c < 0x7e && c != 0x5c {
        Some(c as u8)
    } else if (0xff61..=0xff9f).contains(&c) {
        Some((c - 0xfec0) as u8)
    } else {
        None
    }
}

fn two(code: crate::mb::Code, lo: u8) -> Option<[u8; 2]> {
    if code.len == 2 && code.bytes[0] >= lo && code.bytes[0] <= 0xfe && code.bytes[1] >= 0xa1 && code.bytes[0] != 0x8e {
        Some([code.bytes[0] - 0x80, code.bytes[1] - 0x80])
    } else {
        None
    }
}

fn low(table: &[(u16, u16)], c: u32) -> Option<[u8; 2]> {
    let i = table.binary_search_by(|e| e.0.cmp(&(c as u16))).ok()?;
    let v = table[i].1;
    Some([(v >> 8) as u8, v as u8])
}

fn is_low(c: u32) -> bool {
    c <= 0xff || c == 0x203e
}

pub(crate) fn jis0208(c: u32) -> Option<[u8; 2]> {
    if is_low(c) {
        return low(&jpextra::J0208, c);
    }
    euc_jp::MB.enc(c).and_then(|x| two(x, 0xa1))
}

fn jis0212(c: u32) -> Option<[u8; 2]> {
    if is_low(c) {
        return low(&jpextra::J0212, c);
    }
    if c >= 0xffff {
        return None;
    }
    if let Some(x) = euc_jp::MB.enc(c) {
        if x.len == 3 && x.bytes[0] == 0x8f {
            return Some([x.bytes[1] - 0x80, x.bytes[2] - 0x80]);
        }
    }
    let s = &euc_jp::MB.sets[3];
    let cols = (s.trail_hi - s.trail_lo) as usize + 1;
    let want = if c == 0 { 0xfffe } else { c as u16 };
    s.data.iter().position(|&v| v == want).map(|i| [(s.lead_lo as usize + i / cols) as u8 - 0x80, (s.trail_lo as usize + i % cols) as u8 - 0x80])
}

pub(crate) fn gb2312(c: u32) -> Option<[u8; 2]> {
    if is_low(c) {
        return low(&jpextra::GB2312, c);
    }
    euc_cn::MB.enc(c).and_then(|x| two(x, 0xa1))
}

pub(crate) fn ksc5601(c: u32) -> Option<[u8; 2]> {
    if is_low(c) {
        return low(&jpextra::KSC5601, c);
    }
    if c == 0x20a9 {
        return None;
    }
    euc_kr::MB.enc(c).and_then(|x| two(x, 0xa1))
}

fn iso8859_7_high(c: u32) -> Option<u8> {
    if !(0xa0..0xffff).contains(&c) {
        return None;
    }
    match iso8859_7().lookup(c) {
        Some(b) if b >= 0xa0 => Some(b),
        _ => None,
    }
}

const JAPANESE: u8 = 2;
const EUROPEAN: u8 = 1;
const CHINESE: u8 = 3;
const KOREAN: u8 = 4;
const OTHER: u8 = 5;
const LISTS: [[u8; 5]; 4] = [[JAPANESE, EUROPEAN, CHINESE, KOREAN, OTHER], [JAPANESE, EUROPEAN, CHINESE, KOREAN, OTHER], [KOREAN, EUROPEAN, JAPANESE, CHINESE, OTHER], [CHINESE, EUROPEAN, JAPANESE, KOREAN, OTHER]];

pub fn enc(st: &mut JpState, jp2: bool, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, false, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        if jp2 {
            if (ch >> 7) == (0xe0000 >> 7) {
                let mut c = ch & 0x7f;
                if (b'A' as u32..=b'Z' as u32).contains(&c) {
                    c += 32;
                }
                let t = st.tag;
                st.tag = if c == 0x01 {
                    TAG_LANGUAGE
                } else if c == b'j' as u32 && t == TAG_LANGUAGE {
                    TAG_J
                } else if c == b'a' as u32 && t == TAG_J {
                    TAG_JA
                } else if c == b'k' as u32 && t == TAG_LANGUAGE {
                    TAG_K
                } else if c == b'o' as u32 && t == TAG_K {
                    TAG_KO
                } else if c == b'z' as u32 && t == TAG_LANGUAGE {
                    TAG_Z
                } else if c == b'h' as u32 && t == TAG_Z {
                    TAG_ZH
                } else if c == 0x7f || t >= TAG_LANGUAGE {
                    TAG_NONE
                } else {
                    t
                };
                return EBody::Ok(1, 0);
            }
            if st.tag >= TAG_LANGUAGE {
                st.tag = TAG_NONE;
            }
        }
        let tag = st.tag;
        let ja = tag == TAG_NONE || tag == TAG_JA;
        let mut written: Option<usize> = None;
        match st.set {
            ASCII_SET => {
                if ch <= 0x7f {
                    o[0] = ch as u8;
                    written = Some(1);
                    if jp2 && ch == 0x0a {
                        st.set2 = G2_NONE;
                    }
                }
            }
            ROMAN if ja => {
                if let Some(b) = jis0201(ch) {
                    if b > 0x20 && b < 0x80 {
                        o[0] = b;
                        written = Some(1);
                    }
                }
            }
            KANA if ja => {
                if let Some(b) = jis0201(ch) {
                    if b > 0xa0 && b < 0xe0 {
                        o[0] = b - 0x80;
                        written = Some(1);
                    }
                }
            }
            set => {
                let avail = o.len();
                let r: Option<Result<[u8; 2], ()>> = match set {
                    J0208_1978 | J0208_1983 if ja => {
                        if avail < 2 {
                            Some(Err(()))
                        } else {
                            jis0208(ch).map(Ok)
                        }
                    }
                    J0212 if ja => jis0212(ch).map(|c| if avail < 2 { Err(()) } else { Ok(c) }),
                    GB2312 if tag == TAG_NONE || tag == TAG_ZH => gb2312(ch).map(|c| if avail < 2 { Err(()) } else { Ok(c) }),
                    KSC5601 if tag == TAG_NONE || tag == TAG_KO => ksc5601(ch).map(|c| if avail < 2 { Err(()) } else { Ok(c) }),
                    _ => None,
                };
                match r {
                    Some(Err(())) => return EBody::Full,
                    Some(Ok(c)) => {
                        o[0] = c[0];
                        o[1] = c[1];
                        written = Some(2);
                    }
                    None => {}
                }
            }
        }
        if written.is_none() && st.tag == TAG_NONE {
            if st.set2 == G2_8859_1 {
                if (0x80..=0xff).contains(&ch) {
                    if o.len() < 3 {
                        return EBody::Full;
                    }
                    o[0] = ESC;
                    o[1] = b'N';
                    o[2] = (ch & 0x7f) as u8;
                    written = Some(3);
                }
            } else if st.set2 == G2_8859_7 {
                if let Some(b) = iso8859_7_high(ch) {
                    if o.len() < 3 {
                        return EBody::Full;
                    }
                    o[0] = ESC;
                    o[1] = b'N';
                    o[2] = b & 0x7f;
                    written = Some(3);
                }
            }
        }
        if let Some(n) = written {
            return EBody::Ok(1, n);
        }
        let mut n = 0usize;
        if ch <= 0x7f {
            if o.len() < 3 {
                return EBody::Full;
            }
            o[0] = ESC;
            o[1] = b'(';
            o[2] = b'B';
            n = 3;
            st.set = ASCII_SET;
            if o.len() < 4 {
                return EBody::PartialFull(n);
            }
            o[3] = ch as u8;
            n = 4;
            if jp2 && ch == 0x0a {
                st.set2 = G2_NONE;
            }
            return EBody::Ok(1, n);
        }
        let list: &[u8] = if jp2 { &LISTS[(st.tag & 3) as usize] } else { &[JAPANESE] };
        fn put(o: &mut [u8], n: &mut usize, esc: &[u8], data: &[u8]) -> (Result<(), ()>, bool) {
            let mut esc_done = false;
            if !esc.is_empty() {
                if o.len() < *n + esc.len() {
                    return (Err(()), false);
                }
                o[*n..*n + esc.len()].copy_from_slice(esc);
                *n += esc.len();
                esc_done = true;
            }
            if o.len() < *n + data.len() {
                return (Err(()), esc_done);
            }
            o[*n..*n + data.len()].copy_from_slice(data);
            *n += data.len();
            (Ok(()), esc_done)
        }
        for &kind in list {
            let mut res: Option<Result<(), ()>> = None;
            match kind {
                EUROPEAN => {
                    if (0x80..=0xff).contains(&ch) {
                        let (r, e) = if st.set2 != G2_8859_1 { put(o, &mut n, &[ESC, b'.', b'A'], &[]) } else { (Ok(()), false) };
                        if e {
                            st.set2 = G2_8859_1;
                        }
                        res = Some(if r.is_ok() { put(o, &mut n, &[], &[ESC, b'N', (ch - 0x80) as u8]).0 } else { r });
                    } else if let Some(b) = iso8859_7_high(ch) {
                        let (r, e) = if st.set2 != G2_8859_7 { put(o, &mut n, &[ESC, b'.', b'F'], &[]) } else { (Ok(()), false) };
                        if e {
                            st.set2 = G2_8859_7;
                        }
                        res = Some(if r.is_ok() { put(o, &mut n, &[], &[ESC, b'N', b - 0x80]).0 } else { r });
                    }
                }
                JAPANESE => {
                    if let Some(b) = jis0201(ch).filter(|&b| b > 0x20 && b < 0x80) {
                        let (r, e) = put(o, &mut n, if st.set != ROMAN { &[ESC, b'(', b'J'] } else { &[] }, &[b]);
                        if e {
                            st.set = ROMAN;
                        }
                        res = Some(r);
                    } else if let Some(c) = jis0208(ch) {
                        let (r, e) = put(o, &mut n, if st.set != J0208_1983 { &[ESC, b'$', b'B'] } else { &[] }, &c);
                        if e {
                            st.set = J0208_1983;
                        }
                        res = Some(r);
                    } else if jp2 {
                        if let Some(c) = jis0212(ch) {
                            let (r, e) = put(o, &mut n, if st.set != J0212 { &[ESC, b'$', b'(', b'D'] } else { &[] }, &c);
                            if e {
                                st.set = J0212;
                            }
                            res = Some(r);
                        }
                    }
                }
                CHINESE => {
                    if let Some(c) = gb2312(ch) {
                        let (r, e) = put(o, &mut n, if st.set != GB2312 { &[ESC, b'$', b'A'] } else { &[] }, &c);
                        if e {
                            st.set = GB2312;
                        }
                        res = Some(r);
                    }
                }
                KOREAN => {
                    if let Some(c) = ksc5601(ch) {
                        let (r, e) = put(o, &mut n, if st.set != KSC5601 { &[ESC, b'$', b'(', b'C'] } else { &[] }, &c);
                        if e {
                            st.set = KSC5601;
                        }
                        res = Some(r);
                    }
                }
                _ => {
                    if let Some(b) = jis0201(ch).filter(|&b| b >= 0x80) {
                        let (r, e) = put(o, &mut n, if st.set != KANA { &[ESC, b'(', b'I'] } else { &[] }, &[b - 0x80]);
                        if e {
                            st.set = KANA;
                        }
                        res = Some(r);
                    }
                }
            }
            match res {
                Some(Ok(())) => return EBody::Ok(1, n),
                Some(Err(())) => return if n > 0 { EBody::PartialFull(n) } else { EBody::Full },
                None => {}
            }
        }
        EBody::Illegal
    })
}

pub fn emit_reset(st: &mut JpState, out: &mut [u8], op: &mut usize) -> St {
    if st.set != ASCII_SET || st.set2 != G2_NONE || st.tag != TAG_NONE {
        if st.set == ASCII_SET {
            *st = JpState::default();
        } else {
            if *op + 3 > out.len() {
                return St::Full;
            }
            out[*op..*op + 3].copy_from_slice(&[ESC, b'(', b'B']);
            *op += 3;
            *st = JpState::default();
        }
    }
    St::Ok
}

