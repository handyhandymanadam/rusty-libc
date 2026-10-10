use crate::tables::*;
use crate::{CHARSET, Charset, charset, code_charset, wchar_t, wint_t};
use core::sync::atomic::Ordering;
use crate::wstring::locale_t;
use core::ffi::{CStr, c_char, c_int, c_ulong};

const CLASS_NAMES: [&[u8]; 14] = [
    b"alnum",
    b"alpha",
    b"blank",
    b"cntrl",
    b"digit",
    b"graph",
    b"lower",
    b"print",
    b"punct",
    b"space",
    b"upper",
    b"xdigit",
    b"combining",
    b"combining_level3",
];

#[inline]
fn props(c: u32) -> u16 {
    if c > 0x10ffff {
        return 3 << 14;
    }
    let blk = PROPS_INDEX[(c >> PROPS_SHIFT) as usize] as usize;
    PROPS_DATA[(blk << PROPS_SHIFT) | (c as usize & ((1 << PROPS_SHIFT) - 1))]
}

#[inline]
fn delta(index: &[u8], data: &[i32], shift: u32, c: u32) -> u32 {
    if c > 0x10ffff {
        return c;
    }
    let blk = index[(c >> shift) as usize] as usize;
    c.wrapping_add(data[(blk << shift) | (c as usize & ((1 << shift) - 1))] as u32)
}

#[inline(always)]
fn has(c: u32, bit: u32) -> bool {
    has_in(core::ptr::null(), true, c, bit)
}

#[inline]
fn ctype_of(loc: usize) -> *const rusty_libc_core::locale::CatData {
    rusty_libc_core::locale::of_locale(loc, rusty_libc_core::locale::LC_CTYPE)
}

#[inline(always)]
fn wtab(d: *const rusty_libc_core::locale::CatData, use_cur: bool) -> Option<&'static rusty_libc_core::locale::WideTables> {
    if rusty_libc_core::locale::wide_special() {
        core::hint::cold_path();
        return rusty_libc_core::locale::wide_tables(if use_cur { ctype_of(0) } else { d });
    }
    None
}

#[inline(always)]
fn has_in(d: *const rusty_libc_core::locale::CatData, use_cur: bool, c: u32, bit: u32) -> bool {
    if !rusty_libc_core::locale::locale_slow() {
        return match code_charset(CHARSET.load(Ordering::Relaxed) as u32) {
            Charset::Utf8 | Charset::Other => props(c) & (1 << bit) != 0,
            Charset::C => c < 0x80 && ASCII_CLASS[c as usize] & (1 << bit) != 0,
        };
    }
    if bit < 12
        && let Some(w) = wtab(d, use_cur)
    {
        return unsafe { rusty_libc_core::locale::class_lookup(w.class[bit as usize], c) };
    }
    match charset() {
        Charset::Utf8 | Charset::Other => props(c) & (1 << bit) != 0,
        Charset::C => c < 0x80 && ASCII_CLASS[c as usize] & (1 << bit) != 0,
    }
}

static ASCII_CLASS: [u16; 128] = {
    let mut t = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = ascii_class(i as u8);
        i += 1;
    }
    t
};

const fn ascii_class(b: u8) -> u16 {
    let c = b as u32;
    let upper = c >= 0x41 && c <= 0x5a;
    let lower = c >= 0x61 && c <= 0x7a;
    let digit = c >= 0x30 && c <= 0x39;
    let alpha = upper || lower;
    let xdigit = digit || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
    let cntrl = c < 0x20 || c == 0x7f;
    let print = c >= 0x20 && c < 0x7f;
    let graph = c > 0x20 && c < 0x7f;
    let space = c == 0x20 || (c >= 9 && c <= 13);
    let blank = c == 0x20 || c == 9;
    let punct = graph && !alpha && !digit;
    (alpha || digit) as u16
        | (alpha as u16) << 1
        | (blank as u16) << 2
        | (cntrl as u16) << 3
        | (digit as u16) << 4
        | (graph as u16) << 5
        | (lower as u16) << 6
        | (print as u16) << 7
        | (punct as u16) << 8
        | (space as u16) << 9
        | (upper as u16) << 10
        | (xdigit as u16) << 11
}

macro_rules! classes {
    ($($rust:ident, $c:ident, $cl:ident, $bit:expr, $doc:expr;)*) => {$(
        #[inline]
        pub fn $rust(c: u32) -> bool {
            has(c, $bit)
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c(wc: wint_t) -> c_int {
            c_int::from(has(wc, $bit))
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cl(wc: wint_t, locale: locale_t) -> c_int {
            c_int::from(has_in(ctype_of(locale as usize), false, wc, $bit))
        }
    )*};
}

classes! {
    is_alnum, iswalnum, iswalnum_l, 0, "Letter or digit (iswalnum).";
    is_alpha, iswalpha, iswalpha_l, 1, "Letter (iswalpha).";
    is_blank, iswblank, iswblank_l, 2, "Blank: space, tab and other horizontal space (iswblank).";
    is_cntrl, iswcntrl, iswcntrl_l, 3, "Control character (iswcntrl).";
    is_digit, iswdigit, iswdigit_l, 4, "Decimal digit 0-9 (iswdigit).";
    is_graph, iswgraph, iswgraph_l, 5, "Printable and not a space (iswgraph).";
    is_lower, iswlower, iswlower_l, 6, "Lower case letter (iswlower).";
    is_print, iswprint, iswprint_l, 7, "Printable (iswprint).";
    is_punct, iswpunct, iswpunct_l, 8, "Punctuation or symbol (iswpunct).";
    is_space, iswspace, iswspace_l, 9, "White space (iswspace).";
    is_upper, iswupper, iswupper_l, 10, "Upper case letter (iswupper).";
    is_xdigit, iswxdigit, iswxdigit_l, 11, "Hexadecimal digit (iswxdigit).";
}

#[inline]
pub fn to_lower(c: u32) -> u32 {
    if let Some(w) = wtab(core::ptr::null(), true) {
        return unsafe { rusty_libc_core::locale::trans_lookup(w.tolower, c) };
    }
    to_lower_builtin(c)
}

fn to_lower_builtin(c: u32) -> u32 {
    match charset() {
        Charset::Utf8 | Charset::Other => delta(&LOWER_INDEX, &LOWER_DATA, LOWER_SHIFT, c),
        Charset::C => if (0x41..=0x5a).contains(&c) { c + 32 } else { c },
    }
}

#[inline]
pub fn to_upper(c: u32) -> u32 {
    if let Some(w) = wtab(core::ptr::null(), true) {
        return unsafe { rusty_libc_core::locale::trans_lookup(w.toupper, c) };
    }
    to_upper_builtin(c)
}

fn to_upper_builtin(c: u32) -> u32 {
    match charset() {
        Charset::Utf8 | Charset::Other => delta(&UPPER_INDEX, &UPPER_DATA, UPPER_SHIFT, c),
        Charset::C => if (0x61..=0x7a).contains(&c) { c - 32 } else { c },
    }
}

pub fn class_runs(bit: u32, emit: &mut dyn FnMut(u32, u32)) {
    if let Some(w) = wtab(core::ptr::null(), true)
        && bit < 12
    {
        let mut from_0x80 = |lo: u32, hi: u32| {
            if hi >= 0x80 {
                emit(lo.max(0x80), hi);
            }
        };
        unsafe { rusty_libc_core::locale::class_runs(w.class[bit as usize], &mut from_0x80) };
        return;
    }
    if charset() == Charset::C {
        return;
    }
    let bsz = 1usize << PROPS_SHIFT;
    let mut masks = [0u128; 512];
    let mut known = [false; 512];
    let mut cur: Option<(u32, u32)> = None;
    for (blk, &index) in PROPS_INDEX.iter().enumerate().take(0x110000usize >> PROPS_SHIFT) {
        let idx = index as usize;
        if !known[idx] {
            let mut m = 0u128;
            for i in 0..bsz {
                if PROPS_DATA[(idx << PROPS_SHIFT) | i] & (1 << bit) != 0 {
                    m |= 1u128 << i;
                }
            }
            masks[idx] = m;
            known[idx] = true;
        }
        let mut m = masks[idx];
        let base = (blk << PROPS_SHIFT) as u32;
        while m != 0 {
            let tz = m.trailing_zeros();
            let len = (m >> tz).trailing_ones();
            let (lo, hi) = (base + tz, base + tz + len - 1);
            match &mut cur {
                Some((_, last)) if *last + 1 == lo => *last = hi,
                _ => {
                    if let Some((a, b)) = cur.take()
                        && b >= 0x80
                    {
                        emit(a.max(0x80), b);
                    }
                    cur = Some((lo, hi));
                }
            }
            m &= !(if len >= 128 { u128::MAX } else { ((1u128 << len) - 1) << tz });
        }
    }
    if let Some((a, b)) = cur
        && b >= 0x80
    {
        emit(a.max(0x80), b);
    }
}

pub fn upper_changed(emit: &mut dyn FnMut(u32, u32)) {
    if let Some(w) = wtab(core::ptr::null(), true) {
        unsafe { rusty_libc_core::locale::trans_changed(w.toupper, emit) };
        return;
    }
    match charset() {
        Charset::C => {
            for c in 0x61..=0x7au32 {
                emit(c, c - 32);
            }
        }
        _ => {
            let bsz = 1usize << UPPER_SHIFT;
            for (blk, &index) in UPPER_INDEX.iter().enumerate().take(0x110000usize >> UPPER_SHIFT) {
                let idx = index as usize;
                let data = &UPPER_DATA[idx << UPPER_SHIFT..(idx + 1) << UPPER_SHIFT];
                for (i, &d) in data.iter().enumerate().take(bsz) {
                    if d != 0 {
                        let c = ((blk << UPPER_SHIFT) + i) as u32;
                        emit(c, c.wrapping_add(d as u32));
                    }
                }
            }
        }
    }
}

#[inline]
pub fn to_title(c: u32) -> u32 {
    match charset() {
        Charset::Utf8 | Charset::Other => delta(&TITLE_INDEX, &TITLE_DATA, TITLE_SHIFT, c),
        Charset::C => c,
    }
}

pub fn is_combining(c: u32) -> bool {
    has(c, 12)
}

pub fn is_combining_level3(c: u32) -> bool {
    has(c, 13)
}

#[inline]
pub fn width(c: u32) -> Option<u8> {
    if !rusty_libc_core::locale::locale_slow() {
        return width_in(code_charset(CHARSET.load(Ordering::Relaxed) as u32), c);
    }
    if let Some(w) = wtab(core::ptr::null(), true) {
        return match unsafe { rusty_libc_core::locale::width_lookup(w.width, c) } {
            0xff => None,
            x => Some(x),
        };
    }
    width_in(charset(), c)
}

#[inline(always)]
fn width_in(cs: Charset, c: u32) -> Option<u8> {
    match cs {
        Charset::Utf8 | Charset::Other => match props(c) >> 14 {
            3 => None,
            w => Some(w as u8),
        },
        Charset::C => match c {
            0 => Some(0),
            0x20..=0x7e => Some(1),
            _ => None,
        },
    }
}

pub fn str_width(s: &[u32]) -> Option<usize> {
    let mut total = 0;
    for &c in s {
        if c == 0 {
            break;
        }
        total += width(c)? as usize;
    }
    Some(total)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towlower(wc: wint_t) -> wint_t {
    to_lower(wc)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towupper(wc: wint_t) -> wint_t {
    to_upper(wc)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towlower_l(wc: wint_t, locale: locale_t) -> wint_t {
    match wtab(ctype_of(locale as usize), false) {
        Some(w) => unsafe { rusty_libc_core::locale::trans_lookup(w.tolower, wc) },
        None => to_lower_builtin(wc),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towupper_l(wc: wint_t, locale: locale_t) -> wint_t {
    match wtab(ctype_of(locale as usize), false) {
        Some(w) => unsafe { rusty_libc_core::locale::trans_lookup(w.toupper, wc) },
        None => to_upper_builtin(wc),
    }
}

const CLASS_TAG: c_ulong = 0x5743_0000;

static TRANS: [i32; 3] = [0, 1, 2];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctype(name: *const c_char) -> c_ulong {
    unsafe { class_by_name(CStr::from_ptr(name).to_bytes()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctype_l(name: *const c_char, _locale: locale_t) -> c_ulong {
    unsafe { wctype(name) }
}

pub fn class_by_name(name: &[u8]) -> c_ulong {
    let limit = if charset() == Charset::Utf8 { 14 } else { 12 };
    for (i, n) in CLASS_NAMES.iter().enumerate().take(limit) {
        if *n == name {
            return CLASS_TAG + i as c_ulong;
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype(wc: wint_t, desc: c_ulong) -> c_int {
    in_class(wc, desc) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype_l(wc: wint_t, desc: c_ulong, locale: locale_t) -> c_int {
    let i = desc.wrapping_sub(CLASS_TAG);
    (i < 14 && has_in(ctype_of(locale as usize), false, wc, i as u32)) as c_int
}

pub fn in_class(wc: u32, desc: c_ulong) -> bool {
    let i = desc.wrapping_sub(CLASS_TAG);
    i < 14 && has(wc, i as u32)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans(name: *const c_char) -> *const i32 {
    unsafe { trans_by_name(CStr::from_ptr(name).to_bytes()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans_l(name: *const c_char, locale: locale_t) -> *const i32 {
    unsafe {
        let name = CStr::from_ptr(name).to_bytes();
        if name == b"to_inpunct" {
            return inpunct_of(wtab(ctype_of(locale as usize), false));
        }
        trans_by_name(name)
    }
}

fn inpunct_of(w: Option<&rusty_libc_core::locale::WideTables>) -> *const i32 {
    w.map_or(core::ptr::null(), |w| w.inpunct.cast())
}

pub fn trans_by_name(name: &[u8]) -> *const i32 {
    match name {
        b"to_inpunct" => inpunct_of(wtab(core::ptr::null(), true)),
        b"tolower" => &TRANS[0],
        b"toupper" => &TRANS[1],
        b"totitle" if charset() != Charset::C => &TRANS[2],
        _ => core::ptr::null(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans(wc: wint_t, desc: *const i32) -> wint_t {
    map_by_desc(wc, desc)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans_l(wc: wint_t, desc: *const i32, _locale: locale_t) -> wint_t {
    map_by_desc(wc, desc)
}

pub fn map_by_desc(wc: u32, desc: *const i32) -> u32 {
    if core::ptr::eq(desc, &TRANS[0]) {
        to_lower(wc)
    } else if core::ptr::eq(desc, &TRANS[1]) {
        to_upper(wc)
    } else if core::ptr::eq(desc, &TRANS[2]) {
        to_title(wc)
    } else if desc.is_null() {
        wc
    } else {
        unsafe { rusty_libc_core::locale::trans_lookup(desc.cast(), wc) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcwidth(wc: wchar_t) -> c_int {
    match width(wc as u32) {
        Some(w) => c_int::from(w),
        None => -1,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcswidth(s: *const wchar_t, n: usize) -> c_int {
    unsafe {
        let mut total: c_int = 0;
        if !rusty_libc_core::locale::locale_slow() {
            let cs = code_charset(CHARSET.load(Ordering::Relaxed) as u32);
            for i in 0..n {
                let c = *s.add(i);
                if c == 0 {
                    break;
                }
                match width_in(cs, c as u32) {
                    Some(w) => total = total.wrapping_add(c_int::from(w)),
                    None => return -1,
                }
            }
            return total;
        }
        for i in 0..n {
            let c = *s.add(i);
            if c == 0 {
                break;
            }
            match width(c as u32) {
                Some(w) => total = total.wrapping_add(c_int::from(w)),
                None => return -1,
            }
        }
        total
    }
}


rusty_libc_core::tail_alias!(__towlower_l => towlower_l);
rusty_libc_core::tail_alias!(__towupper_l => towupper_l);
rusty_libc_core::tail_alias!(__iswctype_l => iswctype_l);
rusty_libc_core::tail_alias!(__wctype_l => wctype_l);
rusty_libc_core::tail_alias!(__wctrans_l => wctrans_l);
rusty_libc_core::tail_alias!(__towctrans_l => towctrans_l);
