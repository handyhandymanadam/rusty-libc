#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::cmem::CVec;
pub use crate::zstr::Unit;
use crate::zstr::ZStr;

pub enum Rewrite<T> {
    Plain,
    Zero,
    Copy { buf: *mut T, pre: usize, resume: usize, sod: usize, hex: bool },
}

pub enum Grouped<T: Unit> {
    Plain,
    Zero,
    Copy(Copied<T>),
}

pub struct Copied<T: Unit> {
    buf: CVec<T>,
    pre: usize,
    resume: usize,
    sod: usize,
    hex: bool,
}

pub enum Text<'a, T: Unit> {
    Plain,
    Zero,
    Copy(ZStr<'a, T>),
}

fn digit(c: u32, hex: bool) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&c) || (hex && (u32::from(b'a')..=u32::from(b'f')).contains(&(c | 0x20)))
}

fn at_sep<T: Unit>(q: &ZStr<'_, T>, sep: &[u32]) -> bool {
    let mut t = *q;
    for &c in sep {
        if t.at_end() || t.cur().code() != c {
            return false;
        }
        t.bump();
    }
    true
}

pub fn rewrite_z<'a, T: Unit>(z: ZStr<'a, T>, sep: &[u32], grouping: &[u8], space: impl Fn(u32) -> bool) -> (Grouped<T>, &'a [T]) {
    let g0 = grouping.first().map_or(0, |&b| b as i8);
    if sep.is_empty() || sep[0] == 0 || g0 <= 0 || g0 == 127 {
        return (Grouped::Plain, &[]);
    }
    let mut p = z;
    while !p.at_end() && space(p.cur().code()) {
        p.bump();
    }
    if p.cur().code() == u32::from(b'-') || p.cur().code() == u32::from(b'+') {
        p.bump();
    }
    let hex = p.cur().code() == u32::from(b'0') && p.peek(1).code() | 0x20 == u32::from(b'x');
    if hex {
        p.bump_n(2);
    }
    let sod = p.pos();
    if !digit(p.cur().code(), hex) {
        return (Grouped::Plain, &[]);
    }
    let (mut units, mut seps) = (0usize, false);
    loop {
        if digit(p.cur().code(), hex) {
            p.bump();
        } else if at_sep(&p, sep) {
            p.bump_n(sep.len());
            seps = true;
        } else {
            break;
        }
        units += 1;
    }
    if !seps {
        return (Grouped::Plain, &[]);
    }
    let cp = p.pos();
    let text = p.scanned();
    let is_digit_at = |q: usize| digit(text[q].code(), false);
    let tp = if hex {
        cp
    } else {
        let Some(mut shape) = CVec::filled(units, b'0') else { return (Grouped::Plain, &[]) };
        let (mut q, mut k) = (sod, 0usize);
        let s = shape.as_mut_slice();
        while q < cp {
            if is_digit_at(q) {
                q += 1;
            } else {
                s[k] = b',';
                q += sep.len();
            }
            k += 1;
        }
        let n = rusty_libc_core::locale::correctly_grouped_prefix(shape.as_slice(), grouping);
        drop(shape);
        let (mut q, mut k) = (sod, 0usize);
        while k < n {
            q += if is_digit_at(q) { 1 } else { sep.len() };
            k += 1;
        }
        q
    };
    if tp == sod {
        return (Grouped::Zero, text);
    }
    let (text, rest) = if tp == cp {
        let all = p.rest_to_end();
        (all, all.len() - cp)
    } else {
        (text, 0)
    };
    let mut buf = CVec::<T>::new();
    if !buf.reserve_total(cp + rest + 1) {
        return (Grouped::Plain, &[]);
    }
    let grow = |n: usize, _| n;
    let mut ok = buf.extend_with(&text[..sod], grow);
    let mut q = sod;
    while q < tp {
        if digit(text[q].code(), hex) {
            ok &= buf.extend_with(&text[q..q + 1], grow);
            q += 1;
        } else {
            q += sep.len();
        }
    }
    let pre = buf.len();
    ok &= buf.extend_with(&text[cp..cp + rest], grow) && buf.extend_with(&[T::NUL], grow);
    debug_assert!(ok);
    (Grouped::Copy(Copied { buf, pre, resume: tp, sod, hex }), text)
}

impl<T: Unit> Grouped<T> {
    pub fn text(&self) -> Text<'_, T> {
        match self {
            Grouped::Plain => Text::Plain,
            Grouped::Zero => Text::Zero,
            Grouped::Copy(Copied { buf, .. }) => ZStr::from_slice(buf.as_slice()).map_or(Text::Zero, Text::Copy),
        }
    }

    pub fn end_of(&self, seen: &[T], consumed: usize, sep_len: usize) -> usize {
        match *self {
            Grouped::Plain => consumed,
            Grouped::Zero => 0,
            Grouped::Copy(Copied { pre, resume, sod, hex, .. }) => end_in_text(seen, consumed, sep_len, pre, resume, sod, hex),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn end_in_text<T: Unit>(seen: &[T], consumed: usize, sep_len: usize, pre: usize, resume: usize, sod: usize, hex: bool) -> usize {
    if consumed == 0 {
        0
    } else if consumed >= pre {
        resume + (consumed - pre)
    } else if consumed <= sod {
        consumed
    } else {
        let (mut q, mut k) = (sod, sod);
        while k < consumed {
            if digit(seen[q].code(), hex) {
                k += 1;
                q += 1;
            } else {
                q += sep_len;
            }
        }
        q
    }
}

pub unsafe fn rewrite<T: Unit>(s: *const T, sep: &[u32], grouping: &[u8], space: impl Fn(u32) -> bool) -> Rewrite<T> {
    let z = unsafe { ZStr::new(s) };
    match rewrite_z(z, sep, grouping, space).0 {
        Grouped::Plain => Rewrite::Plain,
        Grouped::Zero => Rewrite::Zero,
        Grouped::Copy(Copied { buf, pre, resume, sod, hex }) => Rewrite::Copy { buf: buf.into_raw().0, pre, resume, sod, hex },
    }
}

pub unsafe fn end_of<T: Unit>(s: *const T, r: &Rewrite<T>, consumed: usize, sep_len: usize) -> usize {
    match *r {
        Rewrite::Plain => consumed,
        Rewrite::Zero => 0,
        Rewrite::Copy { pre, resume, sod, hex, .. } => {
            let mut z = unsafe { ZStr::new(s) };
            z.bump_n(resume);
            end_in_text(z.scanned(), consumed, sep_len, pre, resume, sod, hex)
        }
    }
}

pub unsafe fn release<T>(r: Rewrite<T>) {
    if let Rewrite::Copy { buf, .. } = r {
        unsafe { crate::cmem::free(buf) };
    }
}
