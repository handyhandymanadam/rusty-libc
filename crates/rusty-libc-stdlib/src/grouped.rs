//! The `group` argument of glibc's `__strtod_internal` family (`__strtof_internal`, `__strtold_internal`,
//! `__strtof128_internal` and the `__wcsto*_internal` forms): with a nonzero `group` the integer digits may carry the
//! LC_NUMERIC thousands separator, and only the correctly grouped prefix of them counts (glibc 2.43 stdlib/strtod_l.c and
//! grouping.c, LGPL, read as a reference for the rules; written here in Rust).
//!
//! The converters themselves know no separators: [`rewrite_z`] looks at the text, and when separators matter it builds a
//! copy without them (cut at the end of the correctly grouped prefix), which the plain converter reads;
//! [`Grouped::end_of`] maps the converter's end back into the caller's text. All of it is safe code on a [`ZStr`] cursor
//! and an owned [`CVec`]; [`rewrite`], [`end_of`] and [`release`] are the raw-pointer forms rusty-libc-wchar uses.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::cmem::CVec;
pub use crate::zstr::Unit;
use crate::zstr::ZStr;

/// What the converter reads instead of the caller's text (the raw form, for rusty-libc-wchar).
pub enum Rewrite<T> {
    /// The text as it is (no grouping in this locale, or no separator in the digits).
    Plain,
    /// glibc's "no correctly grouped prefix at all": the value 0.0 with the end at the start; the converter reads an
    /// empty string.
    Zero,
    /// A malloc'd NUL-terminated copy: the text before the digits, the digits without separators, then (when the whole
    /// integer part was correctly grouped) the rest of the text. `pre` is the length of the first two parts in the copy,
    /// `resume` where the rest starts (or the cut is) in the caller's text, `sod` where the digits start.
    Copy { buf: *mut T, pre: usize, resume: usize, sod: usize, hex: bool },
}

/// What the converter reads instead of the caller's text (the owned form: the copy is freed when this is dropped).
pub enum Grouped<T: Unit> {
    Plain,
    Zero,
    /// As [`Rewrite::Copy`], with the copy (including its NUL) owned.
    Copy(Copied<T>),
}

/// The copy of [`Grouped::Copy`] and where its parts came from (see [`Rewrite::Copy`]).
pub struct Copied<T: Unit> {
    buf: CVec<T>,
    pre: usize,
    resume: usize,
    sod: usize,
    hex: bool,
}

/// The text the converter reads, from [`Grouped::text`].
pub enum Text<'a, T: Unit> {
    /// The caller's text.
    Plain,
    /// An empty string.
    Zero,
    /// The copy.
    Copy(ZStr<'a, T>),
}

fn digit(c: u32, hex: bool) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&c) || (hex && (u32::from(b'a')..=u32::from(b'f')).contains(&(c | 0x20)))
}

/// Does the text at `q` start with the separator `sep` (its units' codes)?
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

/// Decide how a `group != 0` conversion reads the text at `z`. `sep` is the thousands separator (its bytes, or one wide
/// character), `grouping` LC_NUMERIC's grouping string, `space` the converter's white-space test. Also returns the units
/// of the text it looked at (enough for [`Grouped::end_of`]).
pub fn rewrite_z<'a, T: Unit>(z: ZStr<'a, T>, sep: &[u32], grouping: &[u8], space: impl Fn(u32) -> bool) -> (Grouped<T>, &'a [T]) {
    // glibc: grouping applies when the first group size is positive and not CHAR_MAX, and the separator is not empty
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
    // hexadecimal numbers are not grouped, but glibc still skips separators among their digits
    let hex = p.cur().code() == u32::from(b'0') && p.peek(1).code() | 0x20 == u32::from(b'x');
    if hex {
        p.bump_n(2);
    }
    let sod = p.pos();
    // a separator cannot start the number (glibc sees no number there)
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
    // the longest correctly grouped prefix (grouping.c works on the digits with each separator as one ',')
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
        // back from units to text positions
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
    debug_assert!(ok); // the room was made above
    (Grouped::Copy(Copied { buf, pre, resume: tp, sod, hex }), text)
}

impl<T: Unit> Grouped<T> {
    /// The text the converter reads.
    pub fn text(&self) -> Text<'_, T> {
        match self {
            Grouped::Plain => Text::Plain,
            Grouped::Zero => Text::Zero,
            // the copy ends with its NUL (made so in rewrite_z), so from_slice always succeeds
            Grouped::Copy(Copied { buf, .. }) => ZStr::from_slice(buf.as_slice()).map_or(Text::Zero, Text::Copy),
        }
    }

    /// Where in the caller's text the converter stopped, given that it read `consumed` units of [`Grouped::text`];
    /// `seen` is the slice [`rewrite_z`] returned with `self`.
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
        // inside the digits: step over as many digits, skipping separators
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

/// [`rewrite_z`] on a raw string, with the copy handed over as a raw block (free it with [`release`]).
///
/// # Safety
/// `s` is NUL-terminated.
pub unsafe fn rewrite<T: Unit>(s: *const T, sep: &[u32], grouping: &[u8], space: impl Fn(u32) -> bool) -> Rewrite<T> {
    // SAFETY: forwarded contract.
    let z = unsafe { ZStr::new(s) };
    match rewrite_z(z, sep, grouping, space).0 {
        Grouped::Plain => Rewrite::Plain,
        Grouped::Zero => Rewrite::Zero,
        Grouped::Copy(Copied { buf, pre, resume, sod, hex }) => Rewrite::Copy { buf: buf.into_raw().0, pre, resume, sod, hex },
    }
}

/// Where in the caller's text `s` the converter stopped, given that it read `consumed` units of the rewritten text.
///
/// # Safety
/// `s` is the NUL-terminated text `r` was made from.
pub unsafe fn end_of<T: Unit>(s: *const T, r: &Rewrite<T>, consumed: usize, sep_len: usize) -> usize {
    match *r {
        Rewrite::Plain => consumed,
        Rewrite::Zero => 0,
        Rewrite::Copy { pre, resume, sod, hex, .. } => {
            // the digit walk stays before `resume` (the end of the grouped digits), which rewrite saw
            // SAFETY: forwarded contract.
            let mut z = unsafe { ZStr::new(s) };
            z.bump_n(resume);
            end_in_text(z.scanned(), consumed, sep_len, pre, resume, sod, hex)
        }
    }
}

/// Free the copy, if one was made.
///
/// # Safety
/// `r` came from [`rewrite`] and is not used afterwards.
pub unsafe fn release<T>(r: Rewrite<T>) {
    if let Rewrite::Copy { buf, .. } = r {
        // SAFETY: `buf` is the block rewrite made (malloc'd by CVec), freed once (the caller's contract).
        unsafe { crate::cmem::free(buf) };
    }
}
