use crate::engine::*;
use crate::iso2022jp::{SetRes, dec_set, jis0201, jis0208};
use crate::mbdata::euc_jisx0213 as e;

const ESC: u8 = 0x1b;

const ASCII: u8 = 0;
const J1978: u8 = 1;
const J1983: u8 = 2;
const ROMAN: u8 = 3;
const KANA: u8 = 4;
const X0213_2000: u8 = 5;
const X0213_P2: u8 = 6;
const X0213_2004: u8 = 7;

#[derive(Clone, Copy, Default, Debug)]
pub struct State {
    pub set: u8,
    pub aux: u32,
}

fn jch(ch: u32) -> u32 {
    let Some(c) = e::MB.enc(ch) else {
        return 0;
    };
    let mut j = match (c.len, c.bytes[0]) {
        (2, 0xa1..=0xfd) | (2, 0xfe) => (((c.bytes[0] & 0x7f) as u32) << 8) | (c.bytes[1] & 0x7f) as u32,
        (3, 0x8f) => 0x8000 | (((c.bytes[1] & 0x7f) as u32) << 8) | (c.bytes[2] & 0x7f) as u32,
        _ => return 0,
    };
    if e::BUFFERED.binary_search(&ch).is_ok() {
        j |= 0x80;
    }
    j
}

fn added_in_2004(v: u32) -> bool {
    match v >> 8 {
        0x2e => v == 0x2e21,
        0x2f => v == 0x2f7e,
        0x4f => v == 0x4f54 || v == 0x4f7e,
        0x74 => v == 0x7427,
        0x7e => (0x7e7a..=0x7e7e).contains(&v),
        _ => false,
    }
}

enum Step {
    Char(u32, usize),
    Two(u32, u32, usize),
    Skip(usize),
    Incomplete,
    Illegal(usize),
}

fn step(st: &mut State, s: &[u8]) -> Step {
    let ch = s[0];
    if ch == ESC {
        if s.len() < 3 || (s[1] == b'$' && s[2] == b'(' && s.len() < 4) {
            return Step::Incomplete;
        }
        if s[1] == b'(' {
            match s[2] {
                b'B' => {
                    st.set = ASCII;
                    return Step::Skip(3);
                }
                b'J' => {
                    st.set = ROMAN;
                    return Step::Skip(3);
                }
                b'I' => {
                    st.set = KANA;
                    return Step::Skip(3);
                }
                _ => {}
            }
        } else if s[1] == b'$' {
            match s[2] {
                b'@' => {
                    st.set = J1978;
                    return Step::Skip(3);
                }
                b'B' => {
                    st.set = J1983;
                    return Step::Skip(3);
                }
                b'(' => match s[3] {
                    b'O' | b'Q' => {
                        st.set = X0213_2004;
                        return Step::Skip(4);
                    }
                    b'P' => {
                        st.set = X0213_P2;
                        return Step::Skip(4);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
    if ch >= 0x80 {
        return Step::Illegal(1);
    }
    if st.set == ASCII || ch < 0x21 || ch == 0x7f {
        return Step::Char(ch as u32, 1);
    }
    match st.set {
        ROMAN => match ch {
            0x5c => Step::Char(0xa5, 1),
            0x7e => Step::Char(0x203e, 1),
            _ => Step::Char(ch as u32, 1),
        },
        KANA => {
            if ch <= 0x5f {
                Step::Char(0xff61 + (ch as u32 - 0x21), 1)
            } else {
                Step::Illegal(1)
            }
        }
        J1978 | J1983 => match dec_set(J1983, s) {
            SetRes::Char(c) => Step::Char(c, 2),
            SetRes::Incomplete => Step::Incomplete,
            SetRes::Unknown => Step::Illegal(1),
        },
        set => {
            if s.len() < 2 {
                return Step::Incomplete;
            }
            let (b1, b2) = (ch, s[1]);
            if !((0x21..=0x7e).contains(&b1) && (0x21..=0x7e).contains(&b2)) {
                return Step::Illegal(1);
            }
            let r = if set == X0213_P2 { e::MB.dec2(3, b1 | 0x80, b2 | 0x80) } else { e::MB.dec2(2, b1 | 0x80, b2 | 0x80) };
            if let Some(c) = r {
                return Step::Char(c, 2);
            }
            let code = ((b1 | 0x80) as u32) << 8 | (b2 | 0x80) as u32;
            match e::COMBOS.iter().find(|x| x.0 == code && set != X0213_P2) {
                Some(&(_, u1, u2)) => Step::Two(u1, u2, 2),
                None => Step::Illegal(1),
            }
        }
    }
}

pub fn dec(st: &mut State, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let mut result = St::Empty;
    let (mut i, mut o) = (*ip, *op);
    let (end, cap) = (inp.len(), out.len());
    while i != end {
        if o >= cap {
            result = St::Full;
            break;
        }
        if st.aux != 0 {
            out[o] = st.aux;
            o += 1;
            st.aux = 0;
            continue;
        }
        match step(st, &inp[i..]) {
            Step::Char(c, n) => {
                out[o] = c;
                o += 1;
                i += n;
            }
            Step::Skip(n) => i += n,
            Step::Incomplete => {
                result = St::Incomplete;
                break;
            }
            Step::Illegal(n) => {
                result = St::Illegal;
                if flags & IGNORE == 0 {
                    break;
                }
                i += n;
                *irr += 1;
                *irr |= crate::engine::ILLEGAL_SEEN;
            }
            Step::Two(u1, u2, n) => {
                i += n;
                out[o] = u1;
                o += 1;
                if o < cap {
                    out[o] = u2;
                    o += 1;
                    continue;
                }
                st.aux = u2;
                result = St::Full;
                break;
            }
        }
    }
    *ip = i;
    *op = o;
    result
}

fn put(o: &mut [u8], n: &mut usize, esc: &[u8], data: &[u8]) -> (bool, bool) {
    let mut esc_done = false;
    if !esc.is_empty() {
        if o.len() < *n + esc.len() {
            return (false, false);
        }
        o[*n..*n + esc.len()].copy_from_slice(esc);
        *n += esc.len();
        esc_done = true;
    }
    if o.len() < *n + data.len() {
        return (false, esc_done);
    }
    o[*n..*n + data.len()].copy_from_slice(data);
    *n += data.len();
    (true, esc_done)
}

pub fn enc(st: &mut State, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        let full = |n: usize| if n > 0 { EBody::PartialFull(n) } else { EBody::Full };
        if st.aux != 0 {
            let lasttwo = st.aux;
            let marks = [0x02e5u32, 0x02e9, 0x0300, 0x0301, 0x309a];
            if marks.contains(&ch) {
                let found = e::COMBOS.iter().find(|&&(code, u1, u2)| u2 == ch && (jch(u1) & 0x7f7f) == (lasttwo & 0xffff) && code != 0);
                if let Some(&(code, _, _)) = found {
                    let need = if (lasttwo >> 16) != 0 || (st.set != X0213_2000 && st.set != X0213_2004) { 4 } else { 0 };
                    if o.len() < need + 2 {
                        return EBody::Full;
                    }
                    let mut n = 0;
                    if need != 0 {
                        o[..4].copy_from_slice(&[ESC, b'$', b'(', b'O']);
                        n = 4;
                        st.set = X0213_2000;
                    }
                    let c = code & 0x7f7f;
                    o[n] = (c >> 8) as u8;
                    o[n + 1] = c as u8;
                    st.aux = 0;
                    return EBody::Ok(1, n + 2);
                }
            }
            let need = if (lasttwo >> 16) != 0 { 3 } else { 0 };
            if o.len() < need + 2 {
                return EBody::Full;
            }
            let mut n = 0;
            if need != 0 {
                o[..3].copy_from_slice(&[ESC, b'$', b'B']);
                n = 3;
            }
            o[n] = (lasttwo >> 8) as u8;
            o[n + 1] = lasttwo as u8;
            st.aux = 0;
            return EBody::Ok(0, n + 2);
        }
        match st.set {
            ASCII => {
                if ch <= 0x7f {
                    o[0] = ch as u8;
                    return EBody::Ok(1, 1);
                }
            }
            ROMAN => {
                if let Some(b) = jis0201(ch).filter(|&b| b > 0x20 && b < 0x80) {
                    o[0] = b;
                    return EBody::Ok(1, 1);
                }
            }
            KANA => {
                if let Some(b) = jis0201(ch).filter(|&b| b >= 0x80) {
                    o[0] = b - 0x80;
                    return EBody::Ok(1, 1);
                }
            }
            J1983 => {
                let code = if o.len() < 2 { Some(None) } else { jis0208(ch).map(Some) };
                if let Some(w) = code {
                    let j = jch(ch);
                    if (j & 0x80) != 0 {
                        st.aux = j & 0x7f7f;
                        return EBody::Ok(1, 0);
                    }
                    return match w {
                        None => EBody::Full,
                        Some(c) => {
                            o[0] = c[0];
                            o[1] = c[1];
                            EBody::Ok(1, 2)
                        }
                    };
                }
            }
            set => {
                if set != J1978 {
                    let j = jch(ch);
                    if j != 0 && if (j & 0x8000) != 0 { set == X0213_P2 } else { set == X0213_2004 || (set == X0213_2000 && !added_in_2004(j)) } {
                        if (j & 0x80) != 0 {
                            st.aux = j & 0x7f7f;
                            return EBody::Ok(1, 0);
                        }
                        if o.len() < 2 {
                            return EBody::Full;
                        }
                        o[0] = ((j >> 8) & 0x7f) as u8;
                        o[1] = (j & 0x7f) as u8;
                        return EBody::Ok(1, 2);
                    }
                }
            }
        }
        if ch <= 0x7f {
            if o.len() < 3 {
                return EBody::Full;
            }
            o[..3].copy_from_slice(&[ESC, b'(', b'B']);
            st.set = ASCII;
            if o.len() < 4 {
                return EBody::PartialFull(3);
            }
            o[3] = ch as u8;
            return EBody::Ok(1, 4);
        }
        let mut n = 0usize;
        if let Some(b) = jis0201(ch).filter(|&b| b > 0x20 && b < 0x80) {
            let (ok, e) = put(o, &mut n, if st.set != ROMAN { &[ESC, b'(', b'J'] } else { &[] }, &[b]);
            if e {
                st.set = ROMAN;
            }
            return if ok { EBody::Ok(1, n) } else { full(n) };
        }
        let j = jch(ch);
        if let Some(c) = jis0208(ch) {
            if (j & 0x80) != 0 {
                st.aux = (u32::from(st.set != J1983) << 16) | (j & 0x7f7f);
                st.set = J1983;
                return EBody::Ok(1, 0);
            }
            let (ok, e) = put(o, &mut n, if st.set != J1983 { &[ESC, b'$', b'B'] } else { &[] }, &c);
            if e {
                st.set = J1983;
            }
            return if ok { EBody::Ok(1, n) } else { full(n) };
        }
        if j != 0 {
            let new_set = if (j & 0x8000) != 0 {
                X0213_P2
            } else if added_in_2004(j) {
                X0213_2004
            } else {
                X0213_2000
            };
            if st.set != new_set {
                if o.len() < 4 {
                    return EBody::Full;
                }
                o[..4].copy_from_slice(&[ESC, b'$', b'(', (new_set - X0213_2000) + b'O']);
                n = 4;
                st.set = new_set;
            }
            if (j & 0x80) != 0 {
                st.aux = j & 0x7f7f;
                return EBody::Ok(1, n);
            }
            if o.len() < n + 2 {
                return full(n);
            }
            o[n] = ((j >> 8) & 0x7f) as u8;
            o[n + 1] = (j & 0x7f) as u8;
            return EBody::Ok(1, n + 2);
        }
        if let Some(b) = jis0201(ch).filter(|&b| b >= 0x80) {
            let (ok, e) = put(o, &mut n, if st.set != KANA { &[ESC, b'(', b'I'] } else { &[] }, &[b - 0x80]);
            if e {
                st.set = KANA;
            }
            return if ok { EBody::Ok(1, n) } else { full(n) };
        }
        EBody::Illegal
    })
}

pub fn emit_reset(st: &mut State, out: &mut [u8], op: &mut usize) -> St {
    if st.set != ASCII || st.aux != 0 {
        let lasttwo = st.aux;
        let need = if lasttwo != 0 { (if (lasttwo >> 16) != 0 { 3 } else { 0 }) + 2 } else { 0 } + if st.set != ASCII { 3 } else { 0 };
        if *op + need > out.len() {
            return St::Full;
        }
        if lasttwo != 0 {
            if (lasttwo >> 16) != 0 {
                out[*op..*op + 3].copy_from_slice(&[ESC, b'$', b'B']);
                *op += 3;
            }
            out[*op] = (lasttwo >> 8) as u8;
            out[*op + 1] = lasttwo as u8;
            *op += 2;
        }
        if st.set != ASCII {
            out[*op..*op + 3].copy_from_slice(&[ESC, b'(', b'B']);
            *op += 3;
        }
        *st = State::default();
    }
    St::Ok
}
