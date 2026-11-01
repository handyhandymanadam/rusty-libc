//! The conversion loops and the transliteration step.
//!
//! glibc converts in two stages, `FROM -> INTERNAL (UCS-4)` and `INTERNAL -> TO`, joined by a buffer
//! of 8160 characters. The loops below have the same contract as glibc's loop template (what is
//! checked first, which status wins, what an ignored error leaves behind), because the observable
//! behaviour of iconv (how much input is consumed when the output fills up or the input is bad,
//! the errno, the return value) follows from it. The module files only supply the per-character
//! bodies.

/// glibc's `__GCONV_*` statuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum St {
    Ok,
    /// All input was used.
    Empty,
    Full,
    Illegal,
    Incomplete,
}

/// Step flags (the values of glibc's `__GCONV_*` flags that matter here).
pub const IGNORE: u32 = 2;
/// Set in an `irr` counter by a loop that skipped illegal input (glibc's `__gconv_mark_illegal_input`, which `iconv -c` reads to
/// exit with failure even when the call that skipped the bytes ended with E2BIG). The call strips it from the count.
pub const ILLEGAL_SEEN: usize = 1 << 62;
pub const SWAP: u32 = 4;
pub const TRANSLIT: u32 = 8;
/// glibc's `__internal_use` step field (set by libio for the converters of a `ccs=` stream): the UTF-16, UTF-32 and UNICODE
/// encoders write no byte order mark (iconvdata/utf-16.c, utf-32.c, unicode.c). Kept apart from glibc's flag values.
pub const INTERNAL_USE: u32 = 1 << 16;

/// Per-step data: the flags and the invocation counter (glibc's `__invocation_counter`: modules use
/// it to find the first call, where byte order marks are read or written).
#[derive(Clone, Copy, Default, Debug)]
pub struct Ctx {
    pub flags: u32,
    pub inv: u32,
}

/// What a decoder body did with the bytes at the front of its input.
pub enum Body {
    /// One character, and how many bytes it used.
    Char(u32, usize),
    /// Two characters from one sequence (the output must have room for both, or nothing is used).
    Two(u32, u32, usize),
    /// Bytes used that produce nothing (an escape sequence).
    Skip(usize),
    Incomplete,
    /// Invalid input; the number of bytes an ignoring conversion skips.
    Illegal(usize),
    /// Invalid input found after the module had already moved the input pointer by `.0` bytes
    /// (glibc's UHC does this for one symbol): the error stops with the pointer moved, and an
    /// ignoring conversion skips `.1` more.
    IllegalAfter(usize, usize),
    /// Like `Illegal`, but an ignored error leaves no "illegal input" status behind (a few glibc
    /// loops do not set the result when they skip).
    IllegalQuiet(usize),
}

#[inline(always)]
pub fn no_fast_dec(_: &[u8], _: &mut [u32]) -> (usize, usize) {
    (0, 0)
}

/// The decoder loop; `fast` converts a run of ordinary characters (it must give the same result as
/// the body would, character by character, and may stop anywhere).
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
        // a run of ordinary characters, converted without the per-character checks
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
                // (glibc runs past the end of the input here; we stop at it)
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

/// What an encoder body did with the characters at the front of its input.
pub enum EBody {
    /// This many characters used, this many bytes written.
    Ok(usize, usize),
    /// Not enough room for this character's output.
    Full,
    /// Not enough room, after this many bytes (an escape sequence) were already written: they stay.
    PartialFull(usize),
    /// Not representable: transliteration, then ignoring, are tried (glibc's
    /// STANDARD_TO_LOOP_ERR_HANDLER).
    Illegal,
    /// Like `Illegal`, but the module marks "illegal input seen" before transliterating (glibc's ISO646 modules call
    /// `__gconv_mark_illegal_input` for every character they cannot write, so `iconv` exits with failure even when the
    /// transliteration then succeeds).
    IllegalMarked,
    /// Not valid at all (a surrogate): only ignoring is tried, no transliteration.
    IllegalPlain,
    /// Like `IllegalPlain`, but an ignored error leaves no status behind.
    IllegalPlainQuiet,
}

/// Unicode tag characters U+E0000..U+E007F: encoders that do not represent them skip them silently.
#[inline]
pub fn is_tag(c: u32) -> bool {
    (c >> 7) == (0xe0000 >> 7)
}

/// No per-call preparation (stateless charsets).
pub fn no_prep(_: &mut [u8], _: &mut usize) -> Option<St> {
    None
}

#[inline(always)]
pub fn no_fast_enc(_: &[u32], _: &mut [u8]) -> (usize, usize) {
    (0, 0)
}

/// The encoder loop (`fast`: as for the decoder). `prep` is the module's PREPARE_LOOP (byte order
/// marks): glibc's transliteration calls the whole step function for each replacement, so the
/// preparation runs again there. `irr` is `None` in the nested call a transliteration makes (glibc
/// passes a null pointer there: no error handling in the nested call).
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
