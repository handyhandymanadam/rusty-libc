//! ctype.h: character classification and case mapping. The C locale's tables are built in; once a
//! locale with different single-byte tables (an ISO-8859 locale, Turkish case rules) has been
//! installed, the functions read the tables of the locale in force (rusty-libc-core's `locale` module).
//! The functions take an `int` that is an `unsigned char` value or EOF, like C.
//! glibc's headers turn `isalpha(c)` into a table lookup through `__ctype_b_loc()`, so those
//! three table accessors are provided too: programs built against glibc's headers keep working.
//!
//! Unsafe areas (BRIEF-UNSAFE U2/U3): the functions that take a plain `int` are safe (also as C functions); the `_l`
//! functions stay `unsafe fn` because C passes them a `locale_t` that core's `locale::of_locale` reads. What is left unsafe:
//! one read of a locale's class table (`class_in`, the table covers -128..=255), the `__isX_l` aliases that forward to the
//! `_l` functions, and the in-place rewrite of the wide compatibility tables (`set_wide_compat`, under `WIDE_LOCK`).
//! The data objects old programs read (`__ctype_b`, `__ctype32_b`, ...) are `AtomicPtr`s: the same 8-byte pointer objects,
//! written with plain (Relaxed) stores as glibc's `setlocale` writes them.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod tables;

use core::cell::Cell;
use core::ffi::{c_int, c_ushort, c_void};
use core::sync::atomic::{AtomicPtr, Ordering::Relaxed};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::locale::{self as loc, CatData};
use rusty_libc_core::sync_cell::SyncCell;
use tables::{CLASS, LOWER, UPPER};

// glibc's class bits (little-endian layout: the bit number is swapped within the 16-bit word)
const UPPER_BIT: u16 = 0x0100;
const LOWER_BIT: u16 = 0x0200;
const ALPHA_BIT: u16 = 0x0400;
const DIGIT_BIT: u16 = 0x0800;
const XDIGIT_BIT: u16 = 0x1000;
const SPACE_BIT: u16 = 0x2000;
const PRINT_BIT: u16 = 0x4000;
const GRAPH_BIT: u16 = 0x8000;
const BLANK_BIT: u16 = 0x0001;
const CNTRL_BIT: u16 = 0x0002;
const PUNCT_BIT: u16 = 0x0004;
const ALNUM_BIT: u16 = 0x0008;

/// The class bits of `c` in the locale in force; characters outside -128..=255 (and EOF is -1,
/// which is inside) have none.
#[inline]
pub fn class_of(c: i32) -> u16 {
    if (-128..=255).contains(&c) {
        if loc::ctype_special() {
            core::hint::cold_path();
            return class_in(loc::current(loc::LC_CTYPE), c);
        }
        CLASS[(c + 128) as usize]
    } else {
        0
    }
}

/// The class bits of `c` in the LC_CTYPE data `d` (None: the C locale).
#[inline]
pub fn class_in(d: Option<&CatData>, c: i32) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    match loc::ctype_tables(d) {
        Some(t) => {
            let p = t.class.wrapping_offset(c as isize);
            // SAFETY: a locale's class table has an entry for every character -128..=255 (glibc's layout, `t.class` points
            // at the entry for 0), and `c` was checked to be in that range; published locale data lives for ever.
            unsafe { *p }
        }
        None => CLASS[(c + 128) as usize],
    }
}

/// `class_of` for the locale argument `locale` of an `_l` function (LC_GLOBAL_LOCALE, a locale_t or null).
///
/// # Safety
/// `locale` is a locale_t, LC_GLOBAL_LOCALE or null (core's `locale::of_locale`).
#[inline]
unsafe fn class_l(c: i32, locale: *mut c_void) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    if loc::ctype_special() {
        // SAFETY: forwarded contract.
        return class_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    CLASS[(c + 128) as usize]
}

macro_rules! classifier {
    ($rust:ident, $c:ident, $cl:ident, $bit:expr) => {
        /// True if the character is in the class (C locale).
        #[inline]
        pub fn $rust(c: i32) -> bool {
            class_of(c) & $bit != 0
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $c(c: c_int) -> c_int {
            c_int::from(class_of(c) & $bit != 0)
        }
        /// # Safety
        /// `locale` is a locale_t (or LC_GLOBAL_LOCALE).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cl(c: c_int, locale: *mut c_void) -> c_int {
            // SAFETY: the function's contract is `class_l`'s.
            c_int::from(unsafe { class_l(c, locale) } & $bit != 0)
        }
    };
}

classifier!(is_alnum, isalnum, isalnum_l, ALNUM_BIT);
classifier!(is_alpha, isalpha, isalpha_l, ALPHA_BIT);
classifier!(is_blank, isblank, isblank_l, BLANK_BIT);
classifier!(is_cntrl, iscntrl, iscntrl_l, CNTRL_BIT);
classifier!(is_digit, isdigit, isdigit_l, DIGIT_BIT);
classifier!(is_graph, isgraph, isgraph_l, GRAPH_BIT);
classifier!(is_lower, islower, islower_l, LOWER_BIT);
classifier!(is_print, isprint, isprint_l, PRINT_BIT);
classifier!(is_punct, ispunct, ispunct_l, PUNCT_BIT);
classifier!(is_space, isspace, isspace_l, SPACE_BIT);
classifier!(is_upper, isupper, isupper_l, UPPER_BIT);
classifier!(is_xdigit, isxdigit, isxdigit_l, XDIGIT_BIT);

/// True for 0..=127.
pub fn is_ascii(c: i32) -> bool {
    (0..=127).contains(&c)
}

/// True for 0..=127 (any int).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isascii(c: c_int) -> c_int {
    c_int::from(c & !0x7f == 0)
}

/// The low seven bits of `c`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7f
}

/// Lower case of `c`; characters without one, and values outside -128..=255, are unchanged.
#[inline]
pub fn to_lower(c: i32) -> i32 {
    if (-128..=255).contains(&c) {
        if loc::ctype_special() {
            core::hint::cold_path();
            return loc::tolower_in(loc::current(loc::LC_CTYPE), c);
        }
        i32::from(LOWER[(c + 128) as usize])
    } else {
        c
    }
}

/// Upper case of `c`.
#[inline]
pub fn to_upper(c: i32) -> i32 {
    if (-128..=255).contains(&c) {
        if loc::ctype_special() {
            core::hint::cold_path();
            return loc::toupper_in(loc::current(loc::LC_CTYPE), c);
        }
        i32::from(UPPER[(c + 128) as usize])
    } else {
        c
    }
}

/// Lower case of `c` in the locale in force.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tolower(c: c_int) -> c_int {
    to_lower(c)
}

/// Upper case of `c` in the locale in force.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn toupper(c: c_int) -> c_int {
    to_upper(c)
}

/// # Safety
/// `locale` is a locale_t (or LC_GLOBAL_LOCALE).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tolower_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        // SAFETY: `locale` is a locale_t or LC_GLOBAL_LOCALE (the contract).
        return loc::tolower_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    if (-128..=255).contains(&c) { i32::from(LOWER[(c + 128) as usize]) } else { c }
}

/// # Safety
/// `locale` is a locale_t (or LC_GLOBAL_LOCALE).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn toupper_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        // SAFETY: `locale` is a locale_t or LC_GLOBAL_LOCALE (the contract).
        return loc::toupper_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    if (-128..=255).contains(&c) { i32::from(UPPER[(c + 128) as usize]) } else { c }
}

/// The C locale's tables (class bits, lower case, upper case; entry `c + 128`), for comparing a
/// locale's own tables with them.
pub fn c_tables() -> (&'static [u16; 384], &'static [i16; 384], &'static [i16; 384]) {
    (&CLASS, &LOWER, &UPPER)
}

/// Old macros as functions: lower case without checking that `c` is an upper-case letter.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _tolower(c: c_int) -> c_int {
    to_lower(c)
}

/// Upper case without checking that `c` is a lower-case letter.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _toupper(c: c_int) -> c_int {
    to_upper(c)
}

// glibc's lower/upper tables hold `int`s: ours widened at compile time, in static storage. glibc's header macros and the old
// data pointers index them -128..=255 from the entry for character 0, so the pointers C gets are `table + 128`
// (`wrapping_add`: safe pointer arithmetic that keeps the whole table's provenance; it is folded to a constant address).
const fn widen(src: &[i16; 384]) -> [i32; 384] {
    let mut out = [0i32; 384];
    let mut i = 0;
    while i < 384 {
        out[i] = src[i] as i32;
        i += 1;
    }
    out
}
static C_LOWER32: [i32; 384] = widen(&LOWER);
static C_UPPER32: [i32; 384] = widen(&UPPER);

/// The C locale's class table as glibc lays it out (pointer to the entry for character 0, valid for -128..=255).
#[inline(always)]
fn c_class_ptr() -> *const u16 {
    CLASS.as_ptr().wrapping_add(128)
}
/// The C locale's lower-case table as glibc lays it out (`int`s, entry for character 0).
#[inline(always)]
fn c_lower_ptr() -> *const i32 {
    C_LOWER32.as_ptr().wrapping_add(128)
}
/// The C locale's upper-case table as glibc lays it out.
#[inline(always)]
fn c_upper_ptr() -> *const i32 {
    C_UPPER32.as_ptr().wrapping_add(128)
}

// The wide-character twins glibc 2.0..2.2 programs read (`__ctype32_b`, `__ctype32_tolower`, `__ctype32_toupper`: `uint32_t` tables of
// the classes (the `_ISwbit` layout) and the case mappings of the wide characters 0..255 of the global locale; the case tables
// have the 384 entries of the byte tables, index -128..255). The C locale's are derived from the byte tables here; a `setlocale` that
// changes LC_CTYPE has rusty-libc-locale compute the new ones (`set_wide_compat`).
const fn wbit(bit: u32) -> u32 {
    if bit < 8 {
        (1u32 << bit) << 24
    } else if bit < 16 {
        (1u32 << bit) << 8
    } else if bit < 24 {
        (1u32 << bit) >> 8
    } else {
        (1u32 << bit) >> 24
    }
}
const fn class32_of_c() -> [u32; 256] {
    let mut out = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let c16 = CLASS[i + 128] as u32;
        let mut bit = 0;
        while bit < 12 {
            // the byte table's `_ISbit` layout (little endian)
            let b16 = if bit < 8 { (1u32 << bit) << 8 } else { (1u32 << bit) >> 8 };
            if c16 & b16 != 0 {
                out[i] |= wbit(bit);
            }
            bit += 1;
        }
        i += 1;
    }
    out
}
/// The C locale's wide class table (what `CLASS32W` is reset to).
static C_CLASS32W: [u32; 256] = class32_of_c();

// The wide tables of the global locale, rewritten in place by `set_wide_compat` (C programs hold `__ctype32_b`, which points
// here). Synchronisation rule: written only with `WIDE_LOCK` held (and `setlocale`, the only caller, holds its own lock as
// well); C programs read them without a lock, which glibc's contract allows only while no thread changes the global locale
// (`setlocale` is MT-Unsafe there too).
static CLASS32W: SyncCell<[u32; 256]> = SyncCell::new(class32_of_c());
static LOWER32W: SyncCell<[u32; 384]> = SyncCell::new([0; 384]);
static UPPER32W: SyncCell<[u32; 384]> = SyncCell::new([0; 384]);
static WIDE_LOCK: RawMutex = RawMutex::new();

/// `__ctype32_b`: the wide class table of the global locale (entry for wide character 0).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_b: AtomicPtr<u32> = AtomicPtr::new(CLASS32W.as_ptr().cast::<u32>());
/// `__ctype32_tolower`: the wide lower-case table of the global locale (entry for character 0).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_tolower: AtomicPtr<u32> = AtomicPtr::new(C_LOWER32.as_ptr().wrapping_add(128).cast::<u32>().cast_mut());
/// `__ctype32_toupper`: the wide upper-case table of the global locale (entry for character 0).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_toupper: AtomicPtr<u32> = AtomicPtr::new(C_UPPER32.as_ptr().wrapping_add(128).cast::<u32>().cast_mut());

/// Install the wide tables of a new LC_CTYPE (`class`, `lower` and `upper` indexed by wide character 0..255).
/// `None`: back to the C locale's built-in tables.
pub fn set_wide_compat(tables: Option<(&[u32; 256], &[u32; 384], &[u32; 384])>) {
    let _g = WIDE_LOCK.guard();
    match tables {
        Some((c, l, u)) => {
            // SAFETY: the three tables are written only here, with WIDE_LOCK held (the rule stated at their definition).
            unsafe { CLASS32W.write(*c) };
            // SAFETY: as above.
            unsafe { LOWER32W.write(*l) };
            // SAFETY: as above.
            unsafe { UPPER32W.write(*u) };
            __ctype32_b.store(CLASS32W.as_ptr().cast::<u32>(), Relaxed);
            // a locale's tables are indexed from the wide character 0 (the C locale's, below, from -128)
            __ctype32_tolower.store(LOWER32W.as_ptr().cast::<u32>(), Relaxed);
            __ctype32_toupper.store(UPPER32W.as_ptr().cast::<u32>(), Relaxed);
        }
        None => {
            // SAFETY: as above.
            unsafe { CLASS32W.write(C_CLASS32W) };
            __ctype32_b.store(CLASS32W.as_ptr().cast::<u32>(), Relaxed);
            __ctype32_tolower.store(c_lower_ptr().cast::<u32>().cast_mut(), Relaxed);
            __ctype32_toupper.store(c_upper_ptr().cast::<u32>().cast_mut(), Relaxed);
        }
    }
}

/// `__ctype_b`: the class table of the global locale (entry for character 0).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_b: AtomicPtr<c_ushort> = AtomicPtr::new(CLASS.as_ptr().wrapping_add(128).cast_mut());
/// `__ctype_tolower`: the lower-case table of the global locale.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_tolower: AtomicPtr<c_int> = AtomicPtr::new(C_LOWER32.as_ptr().wrapping_add(128).cast_mut());
/// `__ctype_toupper`: the upper-case table of the global locale.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_toupper: AtomicPtr<c_int> = AtomicPtr::new(C_UPPER32.as_ptr().wrapping_add(128).cast_mut());

/// Point `__ctype_b`, `__ctype_tolower` and `__ctype_toupper` at the tables of the global LC_CTYPE
/// (what glibc's `_nl_postload_ctype` does); `setlocale` calls this after a change.
pub fn refresh_compat_vars() {
    let (b, lo, up) = match loc::ctype_tables(loc::global(loc::LC_CTYPE)) {
        Some(t) => (t.class, t.lower, t.upper),
        None => (c_class_ptr(), c_lower_ptr(), c_upper_ptr()),
    };
    __ctype_b.store(b.cast_mut(), Relaxed);
    __ctype_tolower.store(lo.cast_mut(), Relaxed);
    __ctype_toupper.store(up.cast_mut(), Relaxed);
}

// The per-thread slots whose addresses `__ctype_b_loc` and friends return (C reads `**slot`). A `Cell` in a `#[thread_local]`
// static: only the owning thread reaches it by name, and the C side reads it through the returned pointer on that thread.
#[thread_local]
static TL_CLASS: Cell<*const u16> = Cell::new(core::ptr::null());
#[thread_local]
static TL_LOWER: Cell<*const i32> = Cell::new(core::ptr::null());
#[thread_local]
static TL_UPPER: Cell<*const i32> = Cell::new(core::ptr::null());

/// `isctype (c, mask)`: the class bits of `c` that are in `mask` (the old function behind the
/// `__isctype` macro; the result is the masked bits, not 0 or 1). Characters outside -128..=255
/// have no bits (glibc reads past its table there).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isctype(c: c_int, mask: c_int) -> c_int {
    (class_of(c) & mask as c_ushort) as c_int
}

/// Address of the pointer to the class table (`(*__ctype_b_loc())[c]` is the class bits of `c`). The slot is per thread and
/// refreshed from the locale in force at each call (glibc's header macros call it for every use).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_b_loc() -> *mut *const c_ushort {
    TL_CLASS.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.class,
        None => c_class_ptr(),
    });
    TL_CLASS.as_ptr()
}

/// Address of the pointer to the lower-case table.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_tolower_loc() -> *mut *const c_int {
    TL_LOWER.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.lower,
        None => c_lower_ptr(),
    });
    TL_LOWER.as_ptr()
}

/// Address of the pointer to the upper-case table.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_toupper_loc() -> *mut *const c_int {
    TL_UPPER.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.upper,
        None => c_upper_ptr(),
    });
    TL_UPPER.as_ptr()
}

/// The three tables of the C locale as glibc lays them out (for locale objects that use it).
pub fn c_glibc_tables() -> (*const u16, *const i32, *const i32) {
    (c_class_ptr(), c_lower_ptr(), c_upper_ptr())
}

// glibc's internal names for the `_l` classifiers (compiled objects reference them).
/// # Safety
/// As `isalnum_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isalnum_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isalnum_l(c, locale) }
}
/// # Safety
/// As `isalpha_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isalpha_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isalpha_l(c, locale) }
}
/// # Safety
/// As `isblank_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isblank_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isblank_l(c, locale) }
}
/// # Safety
/// As `iscntrl_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __iscntrl_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { iscntrl_l(c, locale) }
}
/// # Safety
/// As `isdigit_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isdigit_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isdigit_l(c, locale) }
}
/// # Safety
/// As `isgraph_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isgraph_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isgraph_l(c, locale) }
}
/// # Safety
/// As `islower_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __islower_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { islower_l(c, locale) }
}
/// # Safety
/// As `isprint_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isprint_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isprint_l(c, locale) }
}
/// # Safety
/// As `ispunct_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ispunct_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { ispunct_l(c, locale) }
}
/// # Safety
/// As `isspace_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isspace_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isspace_l(c, locale) }
}
/// # Safety
/// As `isupper_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isupper_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isupper_l(c, locale) }
}
/// # Safety
/// As `isxdigit_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isxdigit_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { isxdigit_l(c, locale) }
}
/// # Safety
/// As `tolower_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __tolower_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { tolower_l(c, locale) }
}
/// # Safety
/// As `toupper_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __toupper_l(c: c_int, locale: *mut c_void) -> c_int {
    // SAFETY: the caller keeps the same contract (`locale` is a locale_t or LC_GLOBAL_LOCALE).
    unsafe { toupper_l(c, locale) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use core::ffi::c_int;

    #[test]
    fn compat_table_pointers_and_isctype() {
        unsafe {
            // the three old data pointers start at the C locale's tables
            for c in -128i32..=255 {
                assert_eq!(*__ctype_b.load(Relaxed).offset(c as isize), CLASS[(c + 128) as usize]);
                assert_eq!(*__ctype_tolower.load(Relaxed).offset(c as isize), i32::from(LOWER[(c + 128) as usize]));
                assert_eq!(*__ctype_toupper.load(Relaxed).offset(c as isize), i32::from(UPPER[(c + 128) as usize]));
            }
            refresh_compat_vars();
            assert_eq!(*__ctype_b.load(Relaxed).offset(b'a' as isize) & ALPHA_BIT, ALPHA_BIT);
            assert_eq!(*__ctype_toupper.load(Relaxed).offset(b'a' as isize), b'A' as i32);
        }
        // isctype is the masked class bits, like the __isctype macro
        for c in -128..=255 {
            for mask in [0x100, 0x200, 0x400, 0x800, 0x2000, 0x4004, 0x0008, 0xffff] {
                assert_eq!(isctype(c, mask), i32::from(CLASS[(c + 128) as usize] & mask as u16));
            }
        }
        assert_eq!(isctype(300, 0xffff), 0);
    }

    #[test]
    fn wide_compat_tables_install_and_restore() {
        let class = [7u32; 256];
        let lower: [u32; 384] = core::array::from_fn(|i| i as u32);
        let upper: [u32; 384] = core::array::from_fn(|i| 1000 + i as u32);
        set_wide_compat(Some((&class, &lower, &upper)));
        unsafe {
            assert_eq!(*__ctype32_b.load(Relaxed).add(200), 7);
            assert_eq!(*__ctype32_tolower.load(Relaxed).add(5), 5);
            assert_eq!(*__ctype32_toupper.load(Relaxed).add(5), 1005);
        }
        set_wide_compat(None);
        unsafe {
            for c in 0..256usize {
                assert_eq!(*__ctype32_b.load(Relaxed).add(c), class32_of_c()[c]);
            }
            for c in -128isize..=255 {
                assert_eq!(*__ctype32_tolower.load(Relaxed).offset(c) as i32, i32::from(LOWER[(c + 128) as usize]));
                assert_eq!(*__ctype32_toupper.load(Relaxed).offset(c) as i32, i32::from(UPPER[(c + 128) as usize]));
            }
        }
    }

    unsafe extern "C" {
        fn isalnum(c: c_int) -> c_int;
        fn isalpha(c: c_int) -> c_int;
        fn isblank(c: c_int) -> c_int;
        fn iscntrl(c: c_int) -> c_int;
        fn isdigit(c: c_int) -> c_int;
        fn isgraph(c: c_int) -> c_int;
        fn islower(c: c_int) -> c_int;
        fn isprint(c: c_int) -> c_int;
        fn ispunct(c: c_int) -> c_int;
        fn isspace(c: c_int) -> c_int;
        fn isupper(c: c_int) -> c_int;
        fn isxdigit(c: c_int) -> c_int;
        fn tolower(c: c_int) -> c_int;
        fn toupper(c: c_int) -> c_int;
        fn __ctype_b_loc() -> *mut *const u16;
        fn __ctype_tolower_loc() -> *mut *const i32;
        fn __ctype_toupper_loc() -> *mut *const i32;
    }

    #[test]
    fn every_character_matches_glibc() {
        type F = unsafe extern "C" fn(c_int) -> c_int;
        type Pair = (&'static str, F, fn(i32) -> bool);
        let pairs: [Pair; 12] = [
            ("alnum", isalnum, is_alnum),
            ("alpha", isalpha, is_alpha),
            ("blank", isblank, is_blank),
            ("cntrl", iscntrl, is_cntrl),
            ("digit", isdigit, is_digit),
            ("graph", isgraph, is_graph),
            ("lower", islower, is_lower),
            ("print", isprint, is_print),
            ("punct", ispunct, is_punct),
            ("space", isspace, is_space),
            ("upper", isupper, is_upper),
            ("xdigit", isxdigit, is_xdigit),
        ];
        for c in -128..=255 {
            for (name, theirs, ours) in pairs {
                assert_eq!(unsafe { theirs(c) } != 0, ours(c), "is{name}({c})");
            }
            assert_eq!(unsafe { tolower(c) }, to_lower(c), "tolower({c})");
            assert_eq!(unsafe { toupper(c) }, to_upper(c), "toupper({c})");
        }
    }

    #[test]
    fn the_tables_match_glibcs() {
        unsafe {
            let (b, lo, up) = (*__ctype_b_loc(), *__ctype_tolower_loc(), *__ctype_toupper_loc());
            let (ob, olo, oup) = (*super::__ctype_b_loc(), *super::__ctype_tolower_loc(), *super::__ctype_toupper_loc());
            for c in -128..=255isize {
                assert_eq!(*ob.offset(c), *b.offset(c), "class {c}");
                assert_eq!(*olo.offset(c), *lo.offset(c), "lower {c}");
                assert_eq!(*oup.offset(c), *up.offset(c), "upper {c}");
            }
        }
    }
}
