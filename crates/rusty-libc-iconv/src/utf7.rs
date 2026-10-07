use crate::engine::*;

fn shift_char(imap: bool) -> u32 {
    if imap { b'&' as u32 } else { b'+' as u32 }
}

fn between(c: u32, lo: u8, hi: u8) -> bool {
    c >= lo as u32 && c <= hi as u32
}

fn isdirect(ch: u32, imap: bool) -> bool {
    if !imap {
        between(ch, b'A', b'Z')
            || between(ch, b'a', b'z')
            || between(ch, b'0', b'9')
            || ch == b'\'' as u32
            || ch == b'(' as u32
            || ch == b')' as u32
            || between(ch, b',', b'/')
            || ch == b':' as u32
            || ch == b'?' as u32
            || ch == b' ' as u32
            || ch == b'\t' as u32
            || ch == b'\n' as u32
            || ch == b'\r' as u32
    } else {
        ch != b'&' as u32 && between(ch, b' ', b'~')
    }
}

fn isxdirect(ch: u32, imap: bool) -> bool {
    if isdirect(ch, imap) {
        return true;
    }
    if imap {
        return false;
    }
    between(ch, b'!', b'&') || ch == b'*' as u32 || between(ch, b';', b'@') || (between(ch, b'[', b'`') && ch != b'\\' as u32) || between(ch, b'{', b'}')
}

fn needs_explicit_shift(ch: u32) -> bool {
    between(ch, b'A', b'Z') || between(ch, b'a', b'z') || between(ch, b'/', b'9') || ch == b'+' as u32 || ch == b'-' as u32
}

fn base64(i: u32, imap: bool) -> u8 {
    match i {
        0..=25 => i as u8 + b'A',
        26..=51 => i as u8 - 26 + b'a',
        52..=61 => i as u8 - 52 + b'0',
        62 => b'+',
        _ => {
            if imap { b',' } else { b'/' }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct DecState {
    pub count: u32,
    pub wch: u32,
}

pub fn dec(st: &mut DecState, imap: bool, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, no_fast_dec, |s| {
        let ch = s[0] as u32;
        if (st.count >> 3) == 0 {
            if isxdirect(ch, imap) {
                Body::Char(ch, 1)
            } else if ch == shift_char(imap) {
                if s.len() < 2 {
                    return Body::Incomplete;
                }
                if s[1] == b'-' {
                    Body::Char(ch, 2)
                } else {
                    st.count = 32 << 3;
                    st.wch = 0;
                    Body::Skip(1)
                }
            } else {
                Body::Illegal(1)
            }
        } else {
            let i = match ch {
                0x41..=0x5a => ch - 0x41,
                0x61..=0x7a => ch - 0x61 + 26,
                0x30..=0x39 => ch - 0x30 + 52,
                0x2b => 62,
                0x2f if !imap => 63,
                0x2c if imap => 63,
                _ => {
                    if st.wch != 0 || (st.count >> 3) <= 26 || (imap && ch != b'-' as u32) {
                        if flags & IGNORE != 0 {
                            st.count = 0;
                        }
                        return Body::Illegal(1);
                    }
                    st.count = 0;
                    return Body::Skip(usize::from(ch == b'-' as u32));
                }
            };
            let mut shift = st.count >> 3;
            let mut emit = None;
            if shift > 6 {
                shift -= 6;
                let mut wch = st.wch | (i << shift);
                if shift <= 16 && shift > 10 {
                    let wc1 = wch >> 16;
                    if !(0xd800..0xdc00).contains(&wc1) {
                        wch <<= 16;
                        shift += 16;
                        emit = Some(wc1);
                    }
                } else if shift <= 10 && shift > 4 {
                    let wc2 = wch & 0xffff;
                    if !(0xdc00..0xe000).contains(&wc2) {
                        if flags & IGNORE != 0 {
                            st.count = 0;
                        }
                        return Body::Illegal(1);
                    }
                }
                st.wch = wch;
            } else {
                let wc1 = st.wch >> 16;
                let wc2 = (st.wch & 0xffff) | (i >> (6 - shift));
                st.wch = (i << shift) << 26;
                shift += 26;
                emit = Some(0x10000 + ((wc1 - 0xd800) << 10) + (wc2 - 0xdc00));
            }
            st.count = shift << 3;
            match emit {
                Some(c) => Body::Char(c, 1),
                None => Body::Skip(1),
            }
        }
    })
}

pub fn enc(count: &mut u32, imap: bool, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, false, &mut no_prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let ch = s[0];
        let mut n = 0usize;
        let mut put = |o: &mut [u8], b: u8| {
            o[n] = b;
            n += 1;
        };
        if (*count & 0x18) == 0 {
            if isdirect(ch, imap) {
                put(o, ch as u8);
            } else {
                let sh = shift_char(imap);
                let cnt = if ch == sh {
                    2
                } else if ch < 0x10000 {
                    3
                } else if ch < 0x110000 {
                    6
                } else {
                    return EBody::Illegal;
                };
                if cnt > o.len() {
                    return EBody::Full;
                }
                put(o, sh as u8);
                if ch == sh {
                    put(o, b'-');
                } else if ch < 0x10000 {
                    put(o, base64(ch >> 10, imap));
                    put(o, base64((ch >> 4) & 0x3f, imap));
                    *count = ((ch & 15) << 5) | (3 << 3);
                } else {
                    let c1 = 0xd800 + ((ch - 0x10000) >> 10);
                    let c2 = 0xdc00 + ((ch - 0x10000) & 0x3ff);
                    let w = (c1 << 16) | c2;
                    put(o, base64(w >> 26, imap));
                    put(o, base64((w >> 20) & 0x3f, imap));
                    put(o, base64((w >> 14) & 0x3f, imap));
                    put(o, base64((w >> 8) & 0x3f, imap));
                    put(o, base64((w >> 2) & 0x3f, imap));
                    *count = ((w & 3) << 7) | (2 << 3);
                }
            }
        } else if (imap && ch == b'&' as u32) || isdirect(ch, imap) {
            let cnt = usize::from((*count & 0x18) >= 0x10) + usize::from(imap || needs_explicit_shift(ch)) + usize::from(imap && ch == b'&' as u32) + 1;
            if cnt > o.len() {
                return EBody::Full;
            }
            if (*count & 0x18) >= 0x10 {
                put(o, base64((*count >> 3) & !3, imap));
            }
            if imap || needs_explicit_shift(ch) {
                put(o, b'-');
            }
            put(o, ch as u8);
            if imap && ch == b'&' as u32 {
                put(o, b'-');
            }
            *count = 0;
        } else {
            let cnt = if ch < 0x10000 {
                if (*count & 0x18) >= 0x10 { 3 } else { 2 }
            } else if ch < 0x110000 {
                if (*count & 0x18) >= 0x18 { 6 } else { 5 }
            } else {
                return EBody::Illegal;
            };
            if cnt > o.len() {
                return EBody::Full;
            }
            if ch < 0x10000 {
                match (*count >> 3) & 3 {
                    1 => {
                        put(o, base64(ch >> 10, imap));
                        put(o, base64((ch >> 4) & 0x3f, imap));
                        *count = ((ch & 15) << 5) | (3 << 3);
                    }
                    2 => {
                        put(o, base64(((*count >> 3) & !3) | (ch >> 12), imap));
                        put(o, base64((ch >> 6) & 0x3f, imap));
                        put(o, base64(ch & 0x3f, imap));
                        *count = 1 << 3;
                    }
                    _ => {
                        put(o, base64(((*count >> 3) & !3) | (ch >> 14), imap));
                        put(o, base64((ch >> 8) & 0x3f, imap));
                        put(o, base64((ch >> 2) & 0x3f, imap));
                        *count = ((ch & 3) << 7) | (2 << 3);
                    }
                }
            } else {
                let c1 = 0xd800 + ((ch - 0x10000) >> 10);
                let c2 = 0xdc00 + ((ch - 0x10000) & 0x3ff);
                let w = (c1 << 16) | c2;
                match (*count >> 3) & 3 {
                    1 => {
                        put(o, base64(w >> 26, imap));
                        put(o, base64((w >> 20) & 0x3f, imap));
                        put(o, base64((w >> 14) & 0x3f, imap));
                        put(o, base64((w >> 8) & 0x3f, imap));
                        put(o, base64((w >> 2) & 0x3f, imap));
                        *count = ((w & 3) << 7) | (2 << 3);
                    }
                    2 => {
                        put(o, base64(((*count >> 3) & !3) | (w >> 28), imap));
                        put(o, base64((w >> 22) & 0x3f, imap));
                        put(o, base64((w >> 16) & 0x3f, imap));
                        put(o, base64((w >> 10) & 0x3f, imap));
                        put(o, base64((w >> 4) & 0x3f, imap));
                        *count = ((w & 15) << 5) | (3 << 3);
                    }
                    _ => {
                        put(o, base64(((*count >> 3) & !3) | (w >> 30), imap));
                        put(o, base64((w >> 24) & 0x3f, imap));
                        put(o, base64((w >> 18) & 0x3f, imap));
                        put(o, base64((w >> 12) & 0x3f, imap));
                        put(o, base64((w >> 6) & 0x3f, imap));
                        put(o, base64(w & 0x3f, imap));
                        *count = 1 << 3;
                    }
                }
            }
        }
        EBody::Ok(1, n)
    })
}

pub fn emit_reset(count: &mut u32, imap: bool, out: &mut [u8], op: &mut usize) -> St {
    let state = *count;
    if state & 0x18 != 0 {
        let n = usize::from((state & 0x18) >= 0x10) + 1;
        if *op + n > out.len() {
            return St::Full;
        }
        if (state & 0x18) >= 0x10 {
            out[*op] = base64((state >> 3) & !3, imap);
            *op += 1;
        }
        out[*op] = b'-';
        *op += 1;
    }
    *count = 0;
    St::Ok
}
