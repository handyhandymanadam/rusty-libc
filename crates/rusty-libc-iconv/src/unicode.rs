use crate::engine::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Var {
    Plain,
    Le,
    Be,
}

#[inline]
fn get16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
#[inline]
fn get32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}


const HI_BYTES: u128 = 0x8080_8080_8080_8080_8080_8080_8080_8080;

#[inline(always)]
fn ascii_run_dec(s: &[u8], o: &mut [u32]) -> (usize, usize) {
    if s[0] >= 0x80 {
        return (0, 0);
    }
    let n = s.len().min(o.len());
    let mut k = 0;
    while k + 16 <= n {
        let c: &[u8; 16] = s[k..k + 16].try_into().unwrap();
        let w = u128::from_le_bytes(*c);
        if w & HI_BYTES != 0 {
            break;
        }
        let d: &mut [u32; 16] = (&mut o[k..k + 16]).try_into().unwrap();
        for j in 0..16 {
            d[j] = c[j] as u32;
        }
        k += 16;
    }
    while k < n && s[k] < 0x80 {
        o[k] = s[k] as u32;
        k += 1;
    }
    (k, k)
}

#[inline(always)]
fn byte_run_enc(s: &[u32], o: &mut [u8], limit: u32) -> (usize, usize) {
    if s[0] >= limit {
        return (0, 0);
    }
    let n = s.len().min(o.len());
    let mut k = 0;
    while k + 16 <= n {
        let c: &[u32; 16] = s[k..k + 16].try_into().unwrap();
        let mut bad = 0u32;
        for &x in c {
            bad |= u32::from(x >= limit);
        }
        if bad != 0 {
            break;
        }
        let d: &mut [u8; 16] = (&mut o[k..k + 16]).try_into().unwrap();
        for j in 0..16 {
            d[j] = c[j] as u8;
        }
        k += 16;
    }
    while k < n && s[k] < limit {
        o[k] = s[k] as u8;
        k += 1;
    }
    (k, k)
}

#[inline(always)]
fn u16_run_dec(s: &[u8], o: &mut [u32], swap: bool) -> (usize, usize) {
    let n = (s.len() / 2).min(o.len());
    let mut k = 0;
    while k < n {
        let mut v = u16::from_le_bytes([s[2 * k], s[2 * k + 1]]);
        if swap {
            v = v.swap_bytes();
        }
        if (0xd800..0xe000).contains(&v) {
            break;
        }
        o[k] = v as u32;
        k += 1;
    }
    (2 * k, k)
}

#[inline(always)]
fn u16_run_enc(s: &[u32], o: &mut [u8], swap: bool) -> (usize, usize) {
    let n = s.len().min(o.len() / 2);
    let mut k = 0;
    while k < n {
        let c = s[k];
        if c >= 0x10000 || (0xd800..0xe000).contains(&c) {
            break;
        }
        let v = if swap { (c as u16).swap_bytes() } else { c as u16 };
        let b = v.to_le_bytes();
        o[2 * k] = b[0];
        o[2 * k + 1] = b[1];
        k += 1;
    }
    (k, 2 * k)
}


#[inline(always)]
fn utf8_run_dec(s: &[u8], o: &mut [u32]) -> (usize, usize) {
    if s[0] < 0x80 {
        return ascii_run_dec(s, o);
    }
    let (n, cap) = (s.len(), o.len());
    let (mut k, mut c) = (0usize, 0usize);
    while k < n && c < cap {
        let b = s[k];
        if b < 0x80 {
            o[c] = b as u32;
            k += 1;
        } else if (0xc2..0xe0).contains(&b) {
            if k + 1 >= n || s[k + 1] & 0xc0 != 0x80 {
                break;
            }
            o[c] = ((b as u32 & 0x1f) << 6) | (s[k + 1] as u32 & 0x3f);
            k += 2;
        } else if (0xe0..0xf0).contains(&b) {
            if k + 2 >= n || s[k + 1] & 0xc0 != 0x80 || s[k + 2] & 0xc0 != 0x80 {
                break;
            }
            let v = ((b as u32 & 0x0f) << 12) | ((s[k + 1] as u32 & 0x3f) << 6) | (s[k + 2] as u32 & 0x3f);
            if v < 0x800 || (0xd800..0xe000).contains(&v) {
                break;
            }
            o[c] = v;
            k += 3;
        } else if (0xf0..0xf5).contains(&b) {
            if k + 3 >= n || s[k + 1] & 0xc0 != 0x80 || s[k + 2] & 0xc0 != 0x80 || s[k + 3] & 0xc0 != 0x80 {
                break;
            }
            let v = ((b as u32 & 0x07) << 18) | ((s[k + 1] as u32 & 0x3f) << 12) | ((s[k + 2] as u32 & 0x3f) << 6) | (s[k + 3] as u32 & 0x3f);
            if !(0x10000..=0x10ffff).contains(&v) {
                break;
            }
            o[c] = v;
            k += 4;
        } else {
            break;
        }
        c += 1;
    }
    (k, c)
}

#[inline(always)]
fn utf8_run_enc(s: &[u32], o: &mut [u8]) -> (usize, usize) {
    if s[0] < 0x80 {
        return byte_run_enc(s, o, 0x80);
    }
    let (n, cap) = (s.len(), o.len());
    let (mut k, mut w) = (0usize, 0usize);
    while k < n {
        let c = s[k];
        if c < 0x80 {
            if w >= cap {
                break;
            }
            o[w] = c as u8;
            w += 1;
        } else if c < 0x800 {
            if w + 2 > cap {
                break;
            }
            o[w] = 0xc0 | (c >> 6) as u8;
            o[w + 1] = 0x80 | (c & 0x3f) as u8;
            w += 2;
        } else if c < 0x10000 {
            if w + 3 > cap || (0xd800..0xe000).contains(&c) {
                break;
            }
            o[w] = 0xe0 | (c >> 12) as u8;
            o[w + 1] = 0x80 | ((c >> 6) & 0x3f) as u8;
            o[w + 2] = 0x80 | (c & 0x3f) as u8;
            w += 3;
        } else if c <= 0x10ffff {
            if w + 4 > cap {
                break;
            }
            o[w] = 0xf0 | (c >> 18) as u8;
            o[w + 1] = 0x80 | ((c >> 12) & 0x3f) as u8;
            o[w + 2] = 0x80 | ((c >> 6) & 0x3f) as u8;
            o[w + 3] = 0x80 | (c & 0x3f) as u8;
            w += 4;
        } else {
            break;
        }
        k += 1;
    }
    (k, w)
}

pub fn utf8_dec(flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, utf8_run_dec, |s| {
        let ch = s[0] as u32;
        if ch < 0x80 {
            return Body::Char(ch, 1);
        }
        let (cnt, mut c) = if (0xc2..0xe0).contains(&ch) {
            (2, ch & 0x1f)
        } else if ch & 0xf0 == 0xe0 {
            (3, ch & 0x0f)
        } else if ch & 0xf8 == 0xf0 {
            (4, ch & 0x07)
        } else if ch & 0xfc == 0xf8 {
            (5, ch & 0x03)
        } else if ch & 0xfe == 0xfc {
            (6, ch & 0x01)
        } else {
            let mut i = 0;
            loop {
                i += 1;
                if !(i < s.len() && s[i] & 0xc0 == 0x80 && i < 5) {
                    break;
                }
            }
            return Body::Illegal(i);
        };
        if cnt > s.len() {
            let mut i = 1;
            while i < s.len() {
                if s[i] & 0xc0 != 0x80 {
                    break;
                }
                i += 1;
            }
            if i == s.len() {
                return Body::Incomplete;
            }
            return Body::Illegal(i);
        }
        let mut i = 1;
        while i < cnt {
            let b = s[i] as u32;
            if b & 0xc0 != 0x80 {
                break;
            }
            c = (c << 6) | (b & 0x3f);
            i += 1;
        }
        if i < cnt || (cnt > 2 && (c >> (5 * cnt - 4)) == 0) || (0xd800..=0xdfff).contains(&c) {
            return Body::Illegal(i);
        }
        Body::Char(c, cnt)
    })
}

pub fn utf8_enc(flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, false, &mut no_prep, utf8_run_enc, &mut |s: &[u32], o: &mut [u8]| {
        let wc = s[0];
        if wc < 0x80 {
            o[0] = wc as u8;
            EBody::Ok(1, 1)
        } else if wc <= 0x7fff_ffff && !(0xd800..=0xdfff).contains(&wc) {
            let mut step = 2;
            while step < 6 {
                if wc & (!0u32 << (5 * step + 1)) == 0 {
                    break;
                }
                step += 1;
            }
            if step > o.len() {
                return EBody::Full;
            }
            let mut w = wc;
            let mut k = step;
            o[0] = (!0xffu32 >> step) as u8;
            while k > 1 {
                k -= 1;
                o[k] = 0x80 | (w & 0x3f) as u8;
                w >>= 6;
            }
            o[0] |= w as u8;
            EBody::Ok(1, step)
        } else {
            EBody::Illegal
        }
    })
}

pub fn ucs4_dec(le: bool, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let mut i = *ip;
    let mut o = *op;
    let end = inp.len();
    let cap = out.len();
    let mut ret = None;
    while i + 4 <= end && o < cap {
        let b = &inp[i..];
        let v = if le { get32(b) } else { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) };
        if v > 0x7fff_ffff {
            if flags & IGNORE != 0 {
                *irr += 1;
                *irr |= crate::engine::ILLEGAL_SEEN;
                i += 4;
                continue;
            }
            ret = Some(St::Illegal);
            break;
        }
        out[o] = v;
        o += 1;
        i += 4;
    }
    *ip = i;
    *op = o;
    if let Some(r) = ret {
        return r;
    }
    if i == end {
        St::Empty
    } else if le {
        if i + 4 > end { St::Incomplete } else { St::Full }
    } else if o >= cap {
        St::Full
    } else {
        St::Incomplete
    }
}

pub fn ucs4_enc(le: bool, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize) -> St {
    let n = (inp.len() - *ip).min((out.len() - *op) / 4);
    for k in 0..n {
        let v = inp[*ip + k];
        let b = if le { v.to_le_bytes() } else { v.to_be_bytes() };
        out[*op + 4 * k..*op + 4 * k + 4].copy_from_slice(&b);
    }
    *ip += n;
    *op += 4 * n;
    if *ip == inp.len() { St::Empty } else { St::Full }
}

pub fn ucs2_dec(swap: bool, quiet: bool, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 2, |s: &[u8], o: &mut [u32]| u16_run_dec(s, o, swap), |s| {
        let mut u = get16(s);
        if swap {
            u = u.swap_bytes();
        }
        if (0xd800..0xe000).contains(&u) {
            return if quiet { Body::IllegalQuiet(2) } else { Body::Illegal(2) };
        }
        Body::Char(u as u32, 2)
    })
}

pub fn ucs2_enc(swap: bool, quiet: bool, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>, prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 2, true, prep, |s: &[u32], o: &mut [u8]| u16_run_enc(s, o, swap), &mut |s: &[u32], o: &mut [u8]| {
        let v = s[0];
        if v >= 0x10000 {
            EBody::Illegal
        } else if (0xd800..0xe000).contains(&v) {
            if quiet { EBody::IllegalPlainQuiet } else { EBody::IllegalPlain }
        } else {
            let u = if swap { (v as u16).swap_bytes() } else { v as u16 };
            o[..2].copy_from_slice(&u.to_le_bytes());
            EBody::Ok(1, 2)
        }
    })
}

pub fn unicode_dec_prepare(ctx: &mut Ctx, inp: &[u8], ip: &mut usize) -> Option<St> {
    if ctx.inv == 0 {
        if *ip + 2 > inp.len() {
            return Some(if *ip == inp.len() { St::Empty } else { St::Incomplete });
        }
        let b = get16(&inp[*ip..]);
        if b == 0xfeff {
            *ip += 2;
        } else if b == 0xfffe {
            ctx.flags |= SWAP;
            *ip += 2;
        }
    }
    None
}

pub fn unicode_enc_prepare(ctx: &mut Ctx, out: &mut [u8], op: &mut usize) -> Option<St> {
    if ctx.inv == 0 {
        if *op + 2 > out.len() {
            return Some(St::Full);
        }
        out[*op] = 0xff;
        out[*op + 1] = 0xfe;
        *op += 2;
    }
    None
}

pub fn utf16_dec_prepare(var: Var, ctx: &mut Ctx, inp: &[u8], ip: &mut usize) -> Option<St> {
    if ctx.inv == 0 {
        if var == Var::Plain {
            if *ip + 2 > inp.len() {
                return Some(if *ip == inp.len() { St::Empty } else { St::Incomplete });
            }
            let b = get16(&inp[*ip..]);
            if b == 0xfeff {
                *ip += 2;
            } else if b == 0xfffe {
                ctx.flags |= SWAP;
                *ip += 2;
            }
        } else if var == Var::Be {
            ctx.flags |= SWAP;
        }
    }
    None
}

pub fn utf16_enc_prepare(var: Var, ctx: &mut Ctx, out: &mut [u8], op: &mut usize) -> Option<St> {
    if ctx.inv == 0 {
        if var == Var::Plain {
            if *op + 2 > out.len() {
                return Some(St::Full);
            }
            out[*op] = 0xff;
            out[*op + 1] = 0xfe;
            *op += 2;
        } else if var == Var::Be {
            ctx.flags |= SWAP;
        }
    }
    None
}

pub fn utf16_dec(flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let swap = flags & SWAP != 0;
    dec_loop(flags, inp, ip, out, op, irr, 2, |s: &[u8], o: &mut [u32]| u16_run_dec(s, o, swap), |s| {
        let mut u1 = get16(s);
        if swap {
            u1 = u1.swap_bytes();
        }
        if !(0xd800..=0xdfff).contains(&u1) {
            return Body::Char(u1 as u32, 2);
        }
        if u1 >= 0xdc00 {
            return Body::Illegal(2);
        }
        if s.len() < 4 {
            return Body::Incomplete;
        }
        let mut u2 = get16(&s[2..]);
        if swap {
            u2 = u2.swap_bytes();
        }
        if !(0xdc00..=0xdfff).contains(&u2) {
            return Body::Illegal(2);
        }
        Body::Char((((u1 as u32) - 0xd7c0) << 10) + (u2 as u32 - 0xdc00), 4)
    })
}

pub fn utf16_enc(flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>, prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>) -> St {
    let swap = flags & SWAP != 0;
    enc_loop(flags, inp, ip, out, op, irr, 2, false, prep, |s: &[u32], o: &mut [u8]| u16_run_enc(s, o, swap), &mut |s: &[u32], o: &mut [u8]| {
        let c = s[0];
        if (0xd800..0xe000).contains(&c) {
            return EBody::IllegalPlain;
        }
        let put = |o: &mut [u8], v: u32| {
            let u = if swap { (v as u16).swap_bytes() } else { v as u16 };
            o[..2].copy_from_slice(&u.to_le_bytes());
        };
        if c >= 0x10000 {
            if c >= 0x110000 {
                return EBody::Illegal;
            }
            if o.len() < 4 {
                return EBody::Full;
            }
            put(o, 0xd7c0 + (c >> 10));
            put(&mut o[2..], 0xdc00 + (c & 0x3ff));
            EBody::Ok(1, 4)
        } else {
            put(o, c);
            EBody::Ok(1, 2)
        }
    })
}

pub fn utf32_dec_prepare(var: Var, ctx: &mut Ctx, inp: &[u8], ip: &mut usize) -> Option<St> {
    if var == Var::Plain {
        if ctx.inv == 0 {
            if *ip + 4 > inp.len() {
                return Some(if *ip == inp.len() { St::Empty } else { St::Incomplete });
            }
            let b = get32(&inp[*ip..]);
            if b == 0x0000_feff {
                *ip += 4;
            } else if b == 0xfffe_0000 {
                ctx.flags |= SWAP;
                *ip += 4;
            }
        }
    } else if ctx.inv == 0 && var == Var::Be {
        ctx.flags |= SWAP;
    }
    None
}

pub fn utf32_enc_prepare(var: Var, ctx: &mut Ctx, out: &mut [u8], op: &mut usize) -> Option<St> {
    if var == Var::Plain {
        if ctx.inv == 0 {
            if *op + 4 > out.len() {
                return Some(St::Full);
            }
            out[*op..*op + 4].copy_from_slice(&0xfeffu32.to_le_bytes());
            *op += 4;
        }
    } else if ctx.inv == 0 && var == Var::Be {
        ctx.flags |= SWAP;
    }
    None
}

pub fn utf32_dec(flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let swap = flags & SWAP != 0;
    dec_loop(flags, inp, ip, out, op, irr, 4, no_fast_dec, |s| {
        let mut u = get32(s);
        if swap {
            u = u.swap_bytes();
        }
        if u >= 0x110000 || (0xd800..0xe000).contains(&u) {
            return Body::Illegal(4);
        }
        Body::Char(u, 4)
    })
}

pub fn utf32_enc(flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>, prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>) -> St {
    let swap = flags & SWAP != 0;
    enc_loop(flags, inp, ip, out, op, irr, 4, false, prep, no_fast_enc, &mut |s: &[u32], o: &mut [u8]| {
        let c = s[0];
        if c >= 0x110000 {
            return EBody::Illegal;
        }
        if (0xd800..0xe000).contains(&c) {
            return EBody::IllegalPlain;
        }
        let v = if swap { c.swap_bytes() } else { c };
        o[..4].copy_from_slice(&v.to_le_bytes());
        EBody::Ok(1, 4)
    })
}

pub fn ascii_dec(flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    dec_loop(flags, inp, ip, out, op, irr, 1, ascii_run_dec, |s| if s[0] > 0x7f { Body::Illegal(1) } else { Body::Char(s[0] as u32, 1) })
}

pub fn ascii_enc(flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    enc_loop(flags, inp, ip, out, op, irr, 1, true, &mut no_prep, |s: &[u32], o: &mut [u8]| byte_run_enc(s, o, 0x80), &mut |s: &[u32], o: &mut [u8]| {
        if s[0] > 0x7f {
            EBody::Illegal
        } else {
            o[0] = s[0] as u8;
            EBody::Ok(1, 1)
        }
    })
}

pub struct Sb {
    name_off: u32,
    name_len: u16,
    dec_off: u32,
    hi_off: u32,
    blocks_off: u32,
    nblocks: u16,
    zero_off: u32,
    nzero: u16,
    pub ident: u16,
    pub dec_ident: u16,
}

impl Sb {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(name_off: u32, name_len: u16, dec_off: u32, hi_off: u32, blocks_off: u32, nblocks: u16, zero_off: u32, nzero: u16, ident: u16, dec_ident: u16) -> Sb {
        Sb { name_off, name_len, dec_off, hi_off, blocks_off, nblocks, zero_off, nzero, ident, dec_ident }
    }

    #[inline(always)]
    fn at(off: u32) -> *const u8 {
        unsafe { (&raw const crate::charsets_gen::SB_BLOB as *const u8).add(off as usize) }
    }

    pub fn name(&self) -> &'static str {
        let b = &crate::charsets_gen::SB_NAMES[self.name_off as usize..self.name_off as usize + self.name_len as usize];
        unsafe { core::str::from_utf8_unchecked(b) }
    }
    #[inline(always)]
    pub fn dec(&self) -> &'static [u16; 256] {
        unsafe { &*(Self::at(self.dec_off) as *const [u16; 256]) }
    }
    #[inline(always)]
    pub fn hi(&self) -> &'static [u8; 256] {
        unsafe { &*(Self::at(self.hi_off) as *const [u8; 256]) }
    }
    #[inline(always)]
    pub fn blocks(&self) -> &'static [[u8; 256]] {
        unsafe { core::slice::from_raw_parts(Self::at(self.blocks_off) as *const [u8; 256], self.nblocks as usize) }
    }
    #[inline(always)]
    pub fn zero(&self) -> &'static [u16] {
        unsafe { core::slice::from_raw_parts(Self::at(self.zero_off) as *const u16, self.nzero as usize) }
    }

    #[inline(always)]
    pub fn lookup(&self, ch: u32) -> Option<u8> {
        if ch >= 0x10000 {
            return None;
        }
        let b = self.hi()[(ch >> 8) as usize];
        if b != 0 {
            let v = self.blocks()[b as usize - 1][(ch & 255) as usize];
            if v != 0 {
                return Some(v);
            }
        }
        if self.zero().contains(&(ch as u16)) { Some(0) } else { None }
    }
}

pub struct AliasTable<const N: usize>(pub [(u32, u8, u16); N]);

impl<const N: usize> AliasTable<N> {
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        N
    }
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        N == 0
    }
    pub fn name(&self, i: usize) -> &'static str {
        let (off, len, _) = self.0[i];
        let b = &crate::charsets_gen::ALIAS_NAMES[off as usize..off as usize + len as usize];
        unsafe { core::str::from_utf8_unchecked(b) }
    }
    pub fn code(&self, i: usize) -> u16 {
        self.0[i].2
    }
    pub fn find(&self, key: &[u8]) -> Option<usize> {
        let (mut lo, mut hi) = (0usize, N);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.name(mid).as_bytes().cmp(key) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        (0..N).map(|i| self.name(i))
    }
}

pub fn sb_dec(t: &Sb, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u32], op: &mut usize, irr: &mut usize) -> St {
    let lim = t.dec_ident as usize;
    let dec = t.dec();
    dec_loop(
        flags,
        inp,
        ip,
        out,
        op,
        irr,
        1,
        |s: &[u8], o: &mut [u32]| {
            let n = s.len().min(o.len());
            let mut k = 0;
            if lim == 256 {
                while k < n {
                    o[k] = s[k] as u32;
                    k += 1;
                }
            } else if lim > 0 {
                while k < n && (s[k] as usize) < lim {
                    o[k] = s[k] as u32;
                    k += 1;
                }
            }
            (k, k)
        },
        |s| {
            let c = dec[s[0] as usize];
            if c == 0xffff { Body::Illegal(1) } else { Body::Char(c as u32, 1) }
        },
    )
}

fn is_iso646_module(name: &str) -> bool {
    matches!(
        name,
        "BS_4730" | "CSA_Z243.4-1985-1" | "CSA_Z243.4-1985-2" | "DIN_66003" | "DS_2089" | "ES" | "ES2" | "GB_1988-80" | "IT" | "JIS_C6220-1969-RO" | "JIS_C6229-1984-B" | "JUS_I.B1.002"
            | "KSC5636" | "MSZ_7795.3" | "NC_NC00-10" | "NF_Z_62-010" | "NF_Z_62-010_1973" | "NS_4551-1" | "NS_4551-2" | "PT" | "PT2" | "SEN_850200_B" | "SEN_850200_C"
    )
}

pub fn sb_enc(t: &Sb, flags: u32, inp: &[u32], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: Option<&mut usize>) -> St {
    let ident = t.ident as u32;
    let marked = is_iso646_module(t.name());
    enc_loop(
        flags,
        inp,
        ip,
        out,
        op,
        irr,
        1,
        true,
        &mut no_prep,
        |s: &[u32], o: &mut [u8]| if ident > 0 { byte_run_enc(s, o, ident) } else { (0, 0) },
        &mut |s: &[u32], o: &mut [u8]| match t.lookup(s[0]) {
            Some(b) => {
                o[0] = b;
                EBody::Ok(1, 1)
            }
            None if marked => EBody::IllegalMarked,
            None => EBody::Illegal,
        },
    )
}
