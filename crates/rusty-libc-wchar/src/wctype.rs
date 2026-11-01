//! wctype.h: wide character classification (`iswalpha` ...), case mapping (`towupper` ...), the
//! named class and mapping lookups (`wctype`, `iswctype`, `wctrans`, `towctrans`) and the column
//! width functions of wchar.h (`wcwidth`, `wcswidth`).
//!
//! What they answer depends on the current [`Charset`](crate::Charset):
//! - `C`: ASCII only, as in glibc's "C" locale (checked: iswalpha, towupper and the rest give
//!   nothing and change nothing for 0x80 and above; `wcwidth` is 1 for printable ASCII, 0 for NUL,
//!   -1 for everything else).
//! - `Utf8`: the Unicode data of glibc 2.43's "C.UTF-8" (identical to en_US.UTF-8 and ja_JP.UTF-8 on
//!   the reference machine), from [`crate::tables`] (generated from the host, see `tools/`). The two
//!   extra classes "combining" and "combining_level3" and the extra mapping "totitle" exist only here.
//!   Turkish and Azeri locales map i and I differently and are not covered.
use crate::tables::*;
use crate::{CHARSET, Charset, charset, code_charset, wchar_t, wint_t};
use core::sync::atomic::Ordering;
use crate::wstring::locale_t;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::cstr_bytes;

/// The class names of `wctype()`, in the order of the bit positions of the property word.
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

/// The property word of a code point in the UTF-8 locale: classes, and width in bits 14..=15.
#[inline]
fn props(c: u32) -> u16 {
    if c > 0x10ffff {
        return 3 << 14; // no class, width -1
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

/// Is `c` in the class whose bit is `bit` (one of the 14 property bits), in the current charset?
#[inline(always)]
fn has(c: u32, bit: u32) -> bool {
    has_in(None, true, c, bit)
}

/// The LC_CTYPE data for a `locale_t` argument (`loc` 0: the locale in force).
///
/// # Safety
/// `loc` is 0, LC_GLOBAL_LOCALE or a locale object (core's `locale::of_locale`).
#[inline]
unsafe fn ctype_of(loc: usize) -> Option<&'static rusty_libc_core::locale::CatData> {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_core::locale::of_locale(loc, rusty_libc_core::locale::LC_CTYPE) }
}

/// The wide tables of the locale in `d` (or the current one if `use_cur`), if it has any.
#[inline(always)]
fn wtab(d: Option<&'static rusty_libc_core::locale::CatData>, use_cur: bool) -> Option<&'static rusty_libc_core::locale::WideTables> {
    if rusty_libc_core::locale::wide_special() {
        // a locale with its own tables (en_US ...): off the fast path of the C and C.UTF-8 locales
        core::hint::cold_path();
        return rusty_libc_core::locale::wide_tables(if use_cur { rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) } else { d });
    }
    None
}

#[inline(always)]
fn has_in(d: Option<&'static rusty_libc_core::locale::CatData>, use_cur: bool, c: u32, bit: u32) -> bool {
    if !rusty_libc_core::locale::locale_slow() {
        // no wide tables and no thread locale anywhere: only the process-wide charset matters
        return match code_charset(CHARSET.load(Ordering::Relaxed) as u32) {
            Charset::Utf8 | Charset::Other => props(c) & (1 << bit) != 0,
            Charset::C => c < 0x80 && ASCII_CLASS[c as usize] & (1 << bit) != 0,
        };
    }
    if bit < 12
        && let Some(w) = wtab(d, use_cur)
    {
        // SAFETY: tables of a loaded locale.
        return unsafe { rusty_libc_core::locale::class_lookup(w.class[bit as usize], c) };
    }
    match charset() {
        Charset::Utf8 | Charset::Other => props(c) & (1 << bit) != 0,
        Charset::C => c < 0x80 && ASCII_CLASS[c as usize] & (1 << bit) != 0,
    }
}

/// `ascii_class` of every ASCII character, computed at compile time.
static ASCII_CLASS: [u16; 128] = {
    let mut t = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        t[i] = ascii_class(i as u8);
        i += 1;
    }
    t
};

/// The class bits of an ASCII byte (the C locale), the same layout as the property word.
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

// ---- Rust API ----

macro_rules! classes {
    ($($rust:ident, $c:ident, $cl:ident, $bit:expr, $doc:expr;)*) => {$(
        #[doc = $doc]
        #[inline]
        pub fn $rust(c: u32) -> bool {
            has(c, $bit)
        }
        #[doc = $doc]
        ///
        /// # Safety
        /// Always safe to call.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c(wc: wint_t) -> c_int {
            c_int::from(has(wc, $bit))
        }
        /// # Safety
        /// `locale` is a locale_t or LC_GLOBAL_LOCALE.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cl(wc: wint_t, locale: locale_t) -> c_int {
            // SAFETY: the contract.
            let d = unsafe { ctype_of(locale as usize) };
            c_int::from(has_in(d, false, wc, $bit))
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

/// Lower case of `c` (itself when it has none), in the current charset.
#[inline]
pub fn to_lower(c: u32) -> u32 {
    if let Some(w) = wtab(None, true) {
        // SAFETY: tables of a loaded locale.
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

/// Upper case of `c` (itself when it has none), in the current charset.
#[inline]
pub fn to_upper(c: u32) -> u32 {
    if let Some(w) = wtab(None, true) {
        // SAFETY: tables of a loaded locale.
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

/// Calls `emit(lo, hi)` for every maximal run of characters from 0x80 up that are in class number `bit` (the order of
/// `CLASS_NAMES`: alnum 0, alpha 1, blank 2, cntrl 3, digit 4, graph 5, lower 6, print 7, punct 8, space 9, upper 10,
/// xdigit 11) in the current locale, in increasing order. Walks the tables by blocks (what a bracket expression of a
/// multibyte locale needs: the set of non-ASCII members of a class without asking 1.1 million characters).
pub fn class_runs(bit: u32, emit: &mut dyn FnMut(u32, u32)) {
    class_runs_in(bit, 0, u32::MAX, emit)
}

/// `class_runs` for the characters of `lo..=hi`: the runs cut to that window (only the parts of the tables that can hold
/// them are read).
pub fn class_runs_in(bit: u32, lo: u32, hi: u32, emit: &mut dyn FnMut(u32, u32)) {
    class_runs_in_at(bit, lo, hi, rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE), charset(), emit)
}

/// `class_runs_in` in a given LC_CTYPE (`d`, with its charset `cs`) instead of the calling thread's: what a compiled
/// pattern asks at match time about the locale it was compiled in (locale data stays loaded for good).
pub fn class_runs_in_at(bit: u32, lo: u32, hi: u32, d: Option<&'static rusty_libc_core::locale::CatData>, cs: Charset, emit: &mut dyn FnMut(u32, u32)) {
    let lo = lo.max(0x80);
    if lo > hi {
        return;
    }
    if let Some(w) = wtab(d, false)
        && bit < 12
    {
        // SAFETY: tables of a loaded locale.
        unsafe { rusty_libc_core::locale::class_runs_in(w.class[bit as usize], lo, hi, emit) };
        return;
    }
    if cs == Charset::C {
        return;
    }
    // built-in Unicode data: the property word of each block of 1 << PROPS_SHIFT characters through its block index
    let bsz = 1usize << PROPS_SHIFT;
    let mut masks = [0u128; 512];
    let mut known = [false; 512];
    let mut cur: Option<(u32, u32)> = None;
    let (wlo, whi) = (lo, hi);
    let mut emit = |a: u32, b: u32| {
        let (a, b) = (a.max(wlo), b.min(whi));
        if a <= b {
            emit(a, b);
        }
    };
    let first = (lo >> PROPS_SHIFT) as usize;
    let last = ((hi.min(0x10ffff) >> PROPS_SHIFT) as usize).min((0x110000usize >> PROPS_SHIFT) - 1);
    for (blk, &index) in PROPS_INDEX.iter().enumerate().take(last + 1).skip(first) {
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

/// Calls `emit(c, upper)` for every character the upper case mapping of the current locale changes (in increasing
/// order of `c`).
pub fn upper_changed(emit: &mut dyn FnMut(u32, u32)) {
    if let Some(w) = wtab(None, true) {
        // SAFETY: tables of a loaded locale.
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

/// Title case of `c` (the "totitle" mapping; only the UTF-8 charset has one, the C one gives `c`).
#[inline]
pub fn to_title(c: u32) -> u32 {
    match charset() {
        Charset::Utf8 | Charset::Other => delta(&TITLE_INDEX, &TITLE_DATA, TITLE_SHIFT, c),
        Charset::C => c,
    }
}

/// Is `c` a combining character ("combining" class, UTF-8 only).
pub fn is_combining(c: u32) -> bool {
    has(c, 12)
}

/// Is `c` in the "combining_level3" class (UTF-8 only).
pub fn is_combining_level3(c: u32) -> bool {
    has(c, 13)
}

/// Terminal columns taken by `c` (0, 1 or 2), or `None` for a character that cannot be printed
/// (what `wcwidth` returns -1 for).
#[inline]
pub fn width(c: u32) -> Option<u8> {
    if !rusty_libc_core::locale::locale_slow() {
        // no wide tables and no thread locale anywhere: only the process-wide charset matters
        return width_in(code_charset(CHARSET.load(Ordering::Relaxed) as u32), c);
    }
    if let Some(w) = wtab(None, true) {
        // SAFETY: tables of a loaded locale.
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

/// Columns of a string (up to its 0 or the end of the slice), `None` if any character has none.
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

// ---- C: case mapping ----

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towlower(wc: wint_t) -> wint_t {
    to_lower(wc)
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towupper(wc: wint_t) -> wint_t {
    to_upper(wc)
}

/// # Safety
/// `locale` is a locale_t or LC_GLOBAL_LOCALE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towlower_l(wc: wint_t, locale: locale_t) -> wint_t {
    // SAFETY: the contract (a locale_t or LC_GLOBAL_LOCALE, used during the call).
    to_lower_loc(wc, unsafe { rusty_libc_core::locale::Loc::from_raw(locale as usize) })
}

/// `towlower_l` on a checked locale argument (`wcsftime_l`'s case mapping too).
pub fn to_lower_loc(wc: u32, loc: rusty_libc_core::locale::Loc) -> u32 {
    match wtab(rusty_libc_core::locale::loc_cat(loc, rusty_libc_core::locale::LC_CTYPE), false) {
        // SAFETY: tables of a loaded locale.
        Some(w) => unsafe { rusty_libc_core::locale::trans_lookup(w.tolower, wc) },
        None => to_lower_builtin(wc),
    }
}

/// # Safety
/// `locale` is a locale_t or LC_GLOBAL_LOCALE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towupper_l(wc: wint_t, locale: locale_t) -> wint_t {
    // SAFETY: the contract (a locale_t or LC_GLOBAL_LOCALE, used during the call).
    to_upper_loc(wc, unsafe { rusty_libc_core::locale::Loc::from_raw(locale as usize) })
}

/// `towupper_l` on a checked locale argument (`wcsftime_l`'s case mapping too).
pub fn to_upper_loc(wc: u32, loc: rusty_libc_core::locale::Loc) -> u32 {
    match wtab(rusty_libc_core::locale::loc_cat(loc, rusty_libc_core::locale::LC_CTYPE), false) {
        // SAFETY: tables of a loaded locale.
        Some(w) => unsafe { rusty_libc_core::locale::trans_lookup(w.toupper, wc) },
        None => to_upper_builtin(wc),
    }
}

// ---- C: named classes and mappings ----

/// `wctype_t`: glibc makes it an `unsigned long` that is really a pointer into the locale. Here a
/// class is `CLASS_TAG + bit number`; 0 means "no such class".
const CLASS_TAG: c_ulong = 0x5743_0000;

/// `wctrans_t` is `const int32_t *` in glibc; these three statics are the descriptors of the maps every locale has.
/// `to_inpunct` is different: its descriptor is the locale's own table (as in glibc), so it works after a locale change.
static TRANS: [i32; 3] = [0, 1, 2]; // tolower, toupper, totitle

/// Look up a class by name ("alpha", ...). In the C charset only the twelve standard classes
/// exist; "combining" and "combining_level3" are UTF-8 only. Returns 0 for an unknown name.
///
/// # Safety
/// `name` must be a valid NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctype(name: *const c_char) -> c_ulong {
    // SAFETY: `name` is a NUL-terminated string (forwarded contract).
    class_by_name(unsafe { cstr_bytes(name) })
}

/// # Safety
/// As `wctype`; the locale is ignored until the locale phase.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctype_l(name: *const c_char, _locale: locale_t) -> c_ulong {
    // SAFETY: forwarded contract.
    unsafe { wctype(name) }
}

/// The class descriptor for `name` (0 if the current charset has no such class).
pub fn class_by_name(name: &[u8]) -> c_ulong {
    let limit = if charset() == Charset::Utf8 { 14 } else { 12 };
    for (i, n) in CLASS_NAMES.iter().enumerate().take(limit) {
        if *n == name {
            return CLASS_TAG + i as c_ulong;
        }
    }
    0
}

/// Is `wc` in the class `desc` (from `wctype`)? 0 for a descriptor that is not one.
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype(wc: wint_t, desc: c_ulong) -> c_int {
    in_class(wc, desc) as c_int
}

/// # Safety
/// `locale` is a locale_t or LC_GLOBAL_LOCALE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iswctype_l(wc: wint_t, desc: c_ulong, locale: locale_t) -> c_int {
    let i = desc.wrapping_sub(CLASS_TAG);
    // SAFETY: the contract.
    (i < 14 && has_in(unsafe { ctype_of(locale as usize) }, false, wc, i as u32)) as c_int
}

/// Membership test by descriptor.
pub fn in_class(wc: u32, desc: c_ulong) -> bool {
    let i = desc.wrapping_sub(CLASS_TAG);
    i < 14 && has(wc, i as u32)
}

/// Look up a character mapping by name: "tolower", "toupper" (and "totitle" in the UTF-8 charset).
/// Returns null for an unknown name.
///
/// # Safety
/// `name` must be a valid NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans(name: *const c_char) -> *const i32 {
    // SAFETY: `name` is a NUL-terminated string (forwarded contract).
    trans_by_name(unsafe { cstr_bytes(name) })
}

/// # Safety
/// As `wctrans`; `locale` is a locale_t or LC_GLOBAL_LOCALE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans_l(name: *const c_char, locale: locale_t) -> *const i32 {
    // SAFETY: `name` is a NUL-terminated string (forwarded contract).
    let name = unsafe { cstr_bytes(name) };
    if name == b"to_inpunct" {
        // SAFETY: the contract.
        return inpunct_of(wtab(unsafe { ctype_of(locale as usize) }, false));
    }
    trans_by_name(name)
}

/// The descriptor of `to_inpunct` in the tables `w` (null if there are none or the locale has no such map).
fn inpunct_of(w: Option<&rusty_libc_core::locale::WideTables>) -> *const i32 {
    w.map_or(core::ptr::null(), |w| w.inpunct.cast())
}

/// The mapping descriptor for `name` (null if the current locale has no such mapping).
pub fn trans_by_name(name: &[u8]) -> *const i32 {
    match name {
        b"to_inpunct" => inpunct_of(wtab(None, true)),
        b"tolower" => &TRANS[0],
        b"toupper" => &TRANS[1],
        b"totitle" if charset() != Charset::C => &TRANS[2],
        _ => core::ptr::null(),
    }
}

/// Apply the mapping `desc` (from `wctrans`) to `wc`. A null descriptor leaves `wc` alone.
///
/// # Safety
/// `desc` must be null or come from `wctrans`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans(wc: wint_t, desc: *const i32) -> wint_t {
    map_by_desc(wc, desc)
}

/// # Safety
/// As `towctrans`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans_l(wc: wint_t, desc: *const i32, _locale: locale_t) -> wint_t {
    map_by_desc(wc, desc)
}

/// Mapping by descriptor.
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
        // SAFETY: not one of ours and not null: the table of `to_inpunct` that `wctrans` returned from a loaded locale.
        unsafe { rusty_libc_core::locale::trans_lookup(desc.cast(), wc) }
    }
}

// ---- C: width ----

/// Columns needed for `wc`: 0 for NUL and combining characters, 1 or 2 for printable ones, -1 for
/// anything unprintable.
///
/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcwidth(wc: wchar_t) -> c_int {
    match width(wc as u32) {
        Some(w) => c_int::from(w),
        None => -1,
    }
}

/// Columns needed for the first `n` characters of `s` (stopping at the 0); -1 if one of them is
/// unprintable.
///
/// # Safety
/// `s` must be valid up to its 0 or `n` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcswidth(s: *const wchar_t, n: usize) -> c_int {
    // SAFETY: `s` is readable up to its 0 or `n` characters (forwarded contract).
    swidth(unsafe { crate::wcstr::CharsN::new(s, n) })
}

/// `wcswidth` of the characters `s` yields.
#[inline(always)]
fn swidth(s: crate::wcstr::CharsN) -> c_int {
    let mut total: c_int = 0;
    if !rusty_libc_core::locale::locale_slow() {
        // the charset cannot change under a call that holds no lock: look it up once
        let cs = code_charset(CHARSET.load(Ordering::Relaxed) as u32);
        for c in s {
            match width_in(cs, c) {
                Some(w) => total = total.wrapping_add(c_int::from(w)),
                None => return -1,
            }
        }
        return total;
    }
    for c in s {
        match width(c) {
            Some(w) => total = total.wrapping_add(c_int::from(w)),
            None => return -1,
        }
    }
    total
}


#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::Loc;

    mod g {
        use core::ffi::{c_char, c_int, c_ulong};
        unsafe extern "C" {
            pub fn iswalnum(c: u32) -> c_int;
            pub fn iswalpha(c: u32) -> c_int;
            pub fn iswblank(c: u32) -> c_int;
            pub fn iswcntrl(c: u32) -> c_int;
            pub fn iswdigit(c: u32) -> c_int;
            pub fn iswgraph(c: u32) -> c_int;
            pub fn iswlower(c: u32) -> c_int;
            pub fn iswprint(c: u32) -> c_int;
            pub fn iswpunct(c: u32) -> c_int;
            pub fn iswspace(c: u32) -> c_int;
            pub fn iswupper(c: u32) -> c_int;
            pub fn iswxdigit(c: u32) -> c_int;
            pub fn towlower(c: u32) -> u32;
            pub fn towupper(c: u32) -> u32;
            pub fn wcwidth(c: i32) -> c_int;
            pub fn wcswidth(s: *const i32, n: usize) -> c_int;
            pub fn wctype(n: *const c_char) -> c_ulong;
            pub fn iswctype(c: u32, d: c_ulong) -> c_int;
            pub fn wctrans(n: *const c_char) -> *const i32;
            pub fn towctrans(c: u32, d: *const i32) -> u32;
        }
    }

    type Pair = (unsafe extern "C" fn(u32) -> c_int, unsafe extern "C" fn(u32) -> c_int, &'static str);

    fn pairs() -> Vec<Pair> {
        vec![
            (iswalnum, g::iswalnum, "alnum"),
            (iswalpha, g::iswalpha, "alpha"),
            (iswblank, g::iswblank, "blank"),
            (iswcntrl, g::iswcntrl, "cntrl"),
            (iswdigit, g::iswdigit, "digit"),
            (iswgraph, g::iswgraph, "graph"),
            (iswlower, g::iswlower, "lower"),
            (iswprint, g::iswprint, "print"),
            (iswpunct, g::iswpunct, "punct"),
            (iswspace, g::iswspace, "space"),
            (iswupper, g::iswupper, "upper"),
            (iswxdigit, g::iswxdigit, "xdigit"),
        ]
    }

    /// Code points to test: everything up to 0x110010, plus the awkward large values.
    fn all_points() -> impl Iterator<Item = u32> {
        (0..=0x110010u32).chain([0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff, 0x1000_0000, 0xdead_beef])
    }

    fn check_locale(host: &str, cs: Charset) {
        let _l = Loc::new(host, cs);
        let pairs = pairs();
        let mut bad = Vec::new();
        for c in all_points() {
            for (ours, theirs, name) in &pairs {
                let (a, b) = unsafe { (ours(c) != 0, theirs(c) != 0) };
                if a != b && bad.len() < 20 {
                    bad.push(format!("isw{name}({c:#x}): ours {a}, host {b}"));
                }
            }
            let (ul, hl) = unsafe { (towlower(c), g::towlower(c)) };
            let (uu, hu) = unsafe { (towupper(c), g::towupper(c)) };
            if (ul != hl || uu != hu) && bad.len() < 20 {
                bad.push(format!("tow({c:#x}): lower {ul:#x}/{hl:#x} upper {uu:#x}/{hu:#x}"));
            }
            let (w, hw) = unsafe { (wcwidth(c as i32), g::wcwidth(c as i32)) };
            if w != hw && bad.len() < 20 {
                bad.push(format!("wcwidth({c:#x}): ours {w}, host {hw}"));
            }
        }
        assert!(bad.is_empty(), "{host}: {bad:#?}");
    }

    #[test]
    fn classes_case_and_width_c_locale() {
        check_locale("C", Charset::C);
    }

    #[test]
    fn classes_case_and_width_c_utf8() {
        check_locale("C.UTF-8", Charset::Utf8);
    }

    #[test]
    fn classes_case_and_width_en_us_utf8() {
        check_locale("en_US.UTF-8", Charset::Utf8);
    }

    #[test]
    fn classes_case_and_width_ja_utf8() {
        check_locale("ja_JP.UTF-8", Charset::Utf8);
    }

    fn named(host: &str, cs: Charset) {
        let _l = Loc::new(host, cs);
        let names: [&[u8]; 18] = [
            b"alnum\0", b"alpha\0", b"blank\0", b"cntrl\0", b"digit\0", b"graph\0", b"lower\0", b"print\0", b"punct\0", b"space\0", b"upper\0", b"xdigit\0", b"combining\0", b"combining_level3\0", b"ALPHA\0", b"\0", b"special\0", b"alpha \0",
        ];
        for n in names {
            let p = n.as_ptr() as *const c_char;
            let (ours, theirs) = unsafe { (wctype(p), g::wctype(p)) };
            assert_eq!(ours != 0, theirs != 0, "wctype({:?}) in {host}", core::str::from_utf8(n));
            if ours != 0 {
                for c in (0..0x3000u32).chain([0x1f600, 0x10ffff, 0xe0001, 0x110000]) {
                    unsafe {
                        assert_eq!(iswctype(c, ours) != 0, g::iswctype(c, theirs) != 0, "iswctype({c:#x}, {:?}) in {host}", core::str::from_utf8(n));
                    }
                }
            }
        }
        let maps: [&[u8]; 7] = [b"tolower\0", b"toupper\0", b"totitle\0", b"toalpha\0", b"\0", b"TOUPPER\0", b"tojhira\0"];
        for n in maps {
            let p = n.as_ptr() as *const c_char;
            let (ours, theirs) = unsafe { (wctrans(p), g::wctrans(p)) };
            assert_eq!(ours.is_null(), theirs.is_null(), "wctrans({:?}) in {host}", core::str::from_utf8(n));
            if !ours.is_null() {
                for c in all_points() {
                    unsafe {
                        assert_eq!(towctrans(c, ours), g::towctrans(c, theirs), "towctrans({c:#x}, {:?}) in {host}", core::str::from_utf8(n));
                    }
                }
            }
        }
        // a null descriptor: the character comes back
        unsafe {
            assert_eq!(towctrans(0x41, core::ptr::null()), g::towctrans(0x41, core::ptr::null()));
            assert_eq!(iswctype(0x41, 0), g::iswctype(0x41, 0));
        }
    }

    #[test]
    fn wctype_and_wctrans_c() {
        named("C", Charset::C);
    }

    #[test]
    fn wctype_and_wctrans_utf8() {
        named("C.UTF-8", Charset::Utf8);
    }

    #[test]
    fn wcswidth_matches_host() {
        for (host, cs) in [("C", Charset::C), ("C.UTF-8", Charset::Utf8)] {
            let _l = Loc::new(host, cs);
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let pool: Vec<i32> = vec![0x41, 0x20, 0x7e, 0x7f, 0x1, 0x300, 0x4e00, 0x1f600, 0xff21, 0xe9, 0x200b, 0x110000, -1, 0xd800, 0x0, 0x1100];
            for _ in 0..20000 {
                let len = (next() % 8) as usize;
                let mut s: Vec<i32> = (0..len).map(|_| pool[(next() % pool.len() as u64) as usize]).collect();
                s.push(0);
                s.extend_from_slice(&[0x4e00, 0x7f]);
                let n = (next() % 12) as usize;
                let (a, b) = unsafe { (wcswidth(s.as_ptr(), n), g::wcswidth(s.as_ptr(), n)) };
                assert_eq!(a, b, "{host} {s:x?} n={n}");
            }
        }
    }

    #[test]
    fn rust_api_follows_charset() {
        {
            let _l = Loc::c();
            assert!(!is_alpha(0xe9));
            assert_eq!(to_upper(0xe9), 0xe9);
            assert_eq!(width(0x4e00), None);
        }
        {
            let _l = Loc::utf8();
            assert!(is_alpha(0xe9) && is_lower(0xe9));
            assert_eq!(to_upper(0xe9), 0xc9);
            assert_eq!(to_title(0x1c6), 0x1c5);
            assert_eq!(width(0x4e00), Some(2));
            assert_eq!(str_width(&[0x41, 0x4e00, 0x300, 0]), Some(3));
            assert_eq!(str_width(&[0x41, 0x7f]), None);
            assert!(is_combining(0x300));
        }
    }
}

// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__towlower_l => towlower_l);
rusty_libc_core::tail_alias!(__towupper_l => towupper_l);
rusty_libc_core::tail_alias!(__iswctype_l => iswctype_l);
rusty_libc_core::tail_alias!(__wctype_l => wctype_l);
rusty_libc_core::tail_alias!(__wctrans_l => wctrans_l);
rusty_libc_core::tail_alias!(__towctrans_l => towctrans_l);
