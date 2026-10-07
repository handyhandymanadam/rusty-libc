#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum St {
    Ok,
    Empty,
    Full,
    Illegal,
    Incomplete,
}

pub const IGNORE: u32 = 2;
pub const ILLEGAL_SEEN: usize = 1 << 62;
pub const SWAP: u32 = 4;
pub const TRANSLIT: u32 = 8;

#[derive(Clone, Copy, Default, Debug)]
pub struct Ctx {
    pub flags: u32,
    pub inv: u32,
}

pub enum Body {
    Char(u32, usize),
    Two(u32, u32, usize),
    Skip(usize),
    Incomplete,
    Illegal(usize),
    IllegalAfter(usize, usize),
    IllegalQuiet(usize),
}

#[inline(always)]
pub fn no_fast_dec(_: &[u8], _: &mut [u32]) -> (usize, usize) {
    (0, 0)
}

#[inline(always)]
pub fn dec_loop(
    flags: u32,
    inp: &[u8],
    ip: &mut usize,
    out: &mut [u32],
    op: &mut usize,
    irr: &mut usize,
    min_in: usize,
    mut fast: impl FnMut(&[u8], &mut [u32]) -> (usize, usize),
    mut body: impl FnMut(&[u8]) -> Body,
) -> St {
    let mut result = St::Empty;
    let mut i = *ip;
    let mut o = *op;
    let end = inp.len();
    let cap = out.len();
    while i != end {
        let (u, c) = fast(&inp[i..], &mut out[o..]);
        if u > 0 {
            i += u;
            o += c;
            continue;
        }
        if min_in > 1 && i + min_in > end {
            result = St::Incomplete;
            break;
        }
        if o >= cap {
            result = St::Full;
            break;
        }
        match body(&inp[i..]) {
            Body::Char(c, n) => {
                out[o] = c;
                o += 1;
                i += n;
            }
            Body::Two(a, b, n) => {
                if o + 2 > cap {
                    result = St::Full;
                    break;
                }
                out[o] = a;
                out[o + 1] = b;
                o += 2;
                i += n;
            }
            Body::Skip(n) => i += n,
            Body::Incomplete => {
                result = St::Incomplete;
                break;
            }
            Body::Illegal(n) => {
                result = St::Illegal;
                if flags & IGNORE == 0 {
                    break;
                }
                i += n;
                *irr += 1;
                *irr |= ILLEGAL_SEEN;
            }
            Body::IllegalAfter(adv, n) => {
                result = St::Illegal;
                i = (i + adv).min(end);
                if flags & IGNORE == 0 {
                    break;
                }
                i = (i + n).min(end);
                *irr += 1;
                *irr |= ILLEGAL_SEEN;
            }
            Body::IllegalQuiet(n) => {
                if flags & IGNORE == 0 {
                    result = St::Illegal;
                    break;
                }
                i += n;
                *irr += 1;
            }
        }
    }
    *ip = i;
    *op = o;
    result
}

pub enum EBody {
    Ok(usize, usize),
    Full,
    PartialFull(usize),
    Illegal,
    IllegalMarked,
    IllegalPlain,
    IllegalPlainQuiet,
}

#[inline]
pub fn is_tag(c: u32) -> bool {
    (c >> 7) == (0xe0000 >> 7)
}

pub fn no_prep(_: &mut [u8], _: &mut usize) -> Option<St> {
    None
}

#[inline(always)]
pub fn no_fast_enc(_: &[u32], _: &mut [u8]) -> (usize, usize) {
    (0, 0)
}

#[inline(always)]
pub fn enc_loop<F: FnMut(&[u32], &mut [u8]) -> EBody, G: FnMut(&[u32], &mut [u8]) -> (usize, usize)>(
    flags: u32,
    inp: &[u32],
    ip: &mut usize,
    out: &mut [u8],
    op: &mut usize,
    mut irr: Option<&mut usize>,
    min_out: usize,
    tags: bool,
    prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>,
    mut fast: G,
    body: &mut F,
) -> St {
    let mut result = St::Empty;
    let mut i = *ip;
    let mut o = *op;
    let end = inp.len();
    let cap = out.len();
    while i != end {
        let (u, w) = fast(&inp[i..], &mut out[o..]);
        if u > 0 {
            i += u;
            o += w;
            continue;
        }
        if o + min_out > cap {
            result = St::Full;
            break;
        }
        let eb = body(&inp[i..], &mut out[o..]);
        let eb = if let EBody::IllegalMarked = eb {
            if let Some(r) = irr.as_deref_mut() {
                *r |= ILLEGAL_SEEN;
            }
            EBody::Illegal
        } else {
            eb
        };
        match eb {
            EBody::Ok(used, wrote) => {
                i += used;
                o += wrote;
            }
            EBody::Full => {
                result = St::Full;
                break;
            }
            EBody::PartialFull(w) => {
                o += w;
                result = St::Full;
                break;
            }
            EBody::IllegalMarked => unreachable!(),
            EBody::IllegalPlain => {
                result = St::Illegal;
                match irr.as_deref_mut() {
                    Some(r) if flags & IGNORE != 0 => {
                        i += 1;
                        *r += 1;
                        *r |= ILLEGAL_SEEN;
                    }
                    _ => break,
                }
            }
            EBody::IllegalPlainQuiet => match irr.as_deref_mut() {
                Some(r) if flags & IGNORE != 0 => {
                    i += 1;
                    *r += 1;
                }
                _ => {
                    result = St::Illegal;
                    break;
                }
            },
            EBody::Illegal => {
                let Some(r) = irr.as_deref_mut() else {
                    result = St::Illegal;
                    break;
                };
                if tags && is_tag(inp[i]) {
                    i += 1;
                    continue;
                }
                result = if flags & TRANSLIT != 0 {
                    let mut used = 0;
                    let mut wrote = 0;
                    let s = crate::translit::transliterate(flags, &inp[i..], &mut out[o..], &mut used, &mut wrote, r, min_out, tags, prep, body);
                    i += used;
                    o += wrote;
                    s
                } else {
                    St::Illegal
                };
                if result != St::Illegal {
                    if result == St::Full || result == St::Incomplete {
                        break;
                    }
                    continue;
                }
                if flags & IGNORE == 0 {
                    break;
                }
                *r += 1;
                *r |= ILLEGAL_SEEN;
                i += 1;
            }
        }
    }
    *ip = i;
    *op = o;
    result
}
