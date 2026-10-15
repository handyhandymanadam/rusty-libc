#![no_std]
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

#[inline]
pub fn class_in(d: Option<&CatData>, c: i32) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    match loc::ctype_tables(d) {
        Some(t) => {
            let p = t.class.wrapping_offset(c as isize);
            unsafe { *p }
        }
        None => CLASS[(c + 128) as usize],
    }
}

#[inline]
unsafe fn class_l(c: i32, locale: *mut c_void) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    if loc::ctype_special() {
        return class_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    CLASS[(c + 128) as usize]
}

macro_rules! classifier {
    ($rust:ident, $c:ident, $cl:ident, $bit:expr) => {
        #[inline]
        pub fn $rust(c: i32) -> bool {
            class_of(c) & $bit != 0
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $c(c: c_int) -> c_int {
            c_int::from(class_of(c) & $bit != 0)
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cl(c: c_int, locale: *mut c_void) -> c_int {
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

pub fn is_ascii(c: i32) -> bool {
    (0..=127).contains(&c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isascii(c: c_int) -> c_int {
    c_int::from(c & !0x7f == 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7f
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tolower(c: c_int) -> c_int {
    to_lower(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn toupper(c: c_int) -> c_int {
    to_upper(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tolower_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        return loc::tolower_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    if (-128..=255).contains(&c) { i32::from(LOWER[(c + 128) as usize]) } else { c }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn toupper_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        return loc::toupper_in(unsafe { loc::of_locale(locale as usize, loc::LC_CTYPE) }, c);
    }
    if (-128..=255).contains(&c) { i32::from(UPPER[(c + 128) as usize]) } else { c }
}

pub fn c_tables() -> (&'static [u16; 384], &'static [i16; 384], &'static [i16; 384]) {
    (&CLASS, &LOWER, &UPPER)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _tolower(c: c_int) -> c_int {
    to_lower(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _toupper(c: c_int) -> c_int {
    to_upper(c)
}

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

#[inline(always)]
fn c_class_ptr() -> *const u16 {
    CLASS.as_ptr().wrapping_add(128)
}
#[inline(always)]
fn c_lower_ptr() -> *const i32 {
    C_LOWER32.as_ptr().wrapping_add(128)
}
#[inline(always)]
fn c_upper_ptr() -> *const i32 {
    C_UPPER32.as_ptr().wrapping_add(128)
}

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
static C_CLASS32W: [u32; 256] = class32_of_c();

static CLASS32W: SyncCell<[u32; 256]> = SyncCell::new(class32_of_c());
static LOWER32W: SyncCell<[u32; 384]> = SyncCell::new([0; 384]);
static UPPER32W: SyncCell<[u32; 384]> = SyncCell::new([0; 384]);
static WIDE_LOCK: RawMutex = RawMutex::new();

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_b: AtomicPtr<u32> = AtomicPtr::new(CLASS32W.as_ptr().cast::<u32>());
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_tolower: AtomicPtr<u32> = AtomicPtr::new(C_LOWER32.as_ptr().wrapping_add(128).cast::<u32>().cast_mut());
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype32_toupper: AtomicPtr<u32> = AtomicPtr::new(C_UPPER32.as_ptr().wrapping_add(128).cast::<u32>().cast_mut());

pub fn set_wide_compat(tables: Option<(&[u32; 256], &[u32; 384], &[u32; 384])>) {
    let _g = WIDE_LOCK.guard();
    match tables {
        Some((c, l, u)) => {
            unsafe { CLASS32W.write(*c) };
            unsafe { LOWER32W.write(*l) };
            unsafe { UPPER32W.write(*u) };
            __ctype32_b.store(CLASS32W.as_ptr().cast::<u32>(), Relaxed);
            __ctype32_tolower.store(LOWER32W.as_ptr().cast::<u32>(), Relaxed);
            __ctype32_toupper.store(UPPER32W.as_ptr().cast::<u32>(), Relaxed);
        }
        None => {
            unsafe { CLASS32W.write(C_CLASS32W) };
            __ctype32_b.store(CLASS32W.as_ptr().cast::<u32>(), Relaxed);
            __ctype32_tolower.store(c_lower_ptr().cast::<u32>().cast_mut(), Relaxed);
            __ctype32_toupper.store(c_upper_ptr().cast::<u32>().cast_mut(), Relaxed);
        }
    }
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_b: AtomicPtr<c_ushort> = AtomicPtr::new(CLASS.as_ptr().wrapping_add(128).cast_mut());
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_tolower: AtomicPtr<c_int> = AtomicPtr::new(C_LOWER32.as_ptr().wrapping_add(128).cast_mut());
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __ctype_toupper: AtomicPtr<c_int> = AtomicPtr::new(C_UPPER32.as_ptr().wrapping_add(128).cast_mut());

pub fn refresh_compat_vars() {
    let (b, lo, up) = match loc::ctype_tables(loc::global(loc::LC_CTYPE)) {
        Some(t) => (t.class, t.lower, t.upper),
        None => (c_class_ptr(), c_lower_ptr(), c_upper_ptr()),
    };
    __ctype_b.store(b.cast_mut(), Relaxed);
    __ctype_tolower.store(lo.cast_mut(), Relaxed);
    __ctype_toupper.store(up.cast_mut(), Relaxed);
}

#[thread_local]
static TL_CLASS: Cell<*const u16> = Cell::new(core::ptr::null());
#[thread_local]
static TL_LOWER: Cell<*const i32> = Cell::new(core::ptr::null());
#[thread_local]
static TL_UPPER: Cell<*const i32> = Cell::new(core::ptr::null());

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isctype(c: c_int, mask: c_int) -> c_int {
    (class_of(c) & mask as c_ushort) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_b_loc() -> *mut *const c_ushort {
    TL_CLASS.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.class,
        None => c_class_ptr(),
    });
    TL_CLASS.as_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_tolower_loc() -> *mut *const c_int {
    TL_LOWER.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.lower,
        None => c_lower_ptr(),
    });
    TL_LOWER.as_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __ctype_toupper_loc() -> *mut *const c_int {
    TL_UPPER.set(match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
        Some(t) => t.upper,
        None => c_upper_ptr(),
    });
    TL_UPPER.as_ptr()
}

pub fn c_glibc_tables() -> (*const u16, *const i32, *const i32) {
    (c_class_ptr(), c_lower_ptr(), c_upper_ptr())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isalnum_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isalnum_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isalpha_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isalpha_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isblank_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isblank_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __iscntrl_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { iscntrl_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isdigit_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isdigit_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isgraph_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isgraph_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __islower_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { islower_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isprint_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isprint_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ispunct_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { ispunct_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isspace_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isspace_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isupper_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isupper_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __isxdigit_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { isxdigit_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __tolower_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { tolower_l(c, locale) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __toupper_l(c: c_int, locale: *mut c_void) -> c_int {
    unsafe { toupper_l(c, locale) }
}

