#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]

mod tables;

use core::ffi::{c_int, c_ushort, c_void};
use rusty_libc_core::locale::{self as loc, CatData};
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
pub fn class_in(d: *const CatData, c: i32) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    match loc::ctype_tables(d) {
        Some(t) => unsafe { *t.class.offset(c as isize) },
        None => CLASS[(c + 128) as usize],
    }
}

#[inline]
fn class_l(c: i32, locale: *mut c_void) -> u16 {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    if loc::ctype_special() {
        return class_in(loc::of_locale(locale as usize, loc::LC_CTYPE), c);
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
        pub unsafe extern "C" fn $c(c: c_int) -> c_int {
            c_int::from(class_of(c) & $bit != 0)
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cl(c: c_int, locale: *mut c_void) -> c_int {
            c_int::from(class_l(c, locale) & $bit != 0)
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
pub unsafe extern "C" fn isascii(c: c_int) -> c_int {
    c_int::from(c & !0x7f == 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn toascii(c: c_int) -> c_int {
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
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    to_lower(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    to_upper(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tolower_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        return loc::tolower_in(loc::of_locale(locale as usize, loc::LC_CTYPE), c);
    }
    if (-128..=255).contains(&c) { i32::from(LOWER[(c + 128) as usize]) } else { c }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn toupper_l(c: c_int, locale: *mut c_void) -> c_int {
    if loc::ctype_special() && (-128..=255).contains(&c) {
        return loc::toupper_in(loc::of_locale(locale as usize, loc::LC_CTYPE), c);
    }
    if (-128..=255).contains(&c) { i32::from(UPPER[(c + 128) as usize]) } else { c }
}

pub fn c_tables() -> (&'static [u16; 384], &'static [i16; 384], &'static [i16; 384]) {
    (&CLASS, &LOWER, &UPPER)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _tolower(c: c_int) -> c_int {
    to_lower(c)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _toupper(c: c_int) -> c_int {
    to_upper(c)
}

static CLASS_PTR: SyncPtr<u16> = SyncPtr(unsafe { CLASS.as_ptr().add(128) });
struct SyncPtr<T>(*const T);
unsafe impl<T> Sync for SyncPtr<T> {}

static mut LOWER32: [i32; 384] = [0; 384];
static mut UPPER32: [i32; 384] = [0; 384];
static INIT32: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn init32() -> (*const i32, *const i32) {
    unsafe {
        let (lo, up) = (&mut *core::ptr::addr_of_mut!(LOWER32), &mut *core::ptr::addr_of_mut!(UPPER32));
        if !INIT32.load(core::sync::atomic::Ordering::Acquire) {
            for i in 0..384 {
                lo[i] = i32::from(LOWER[i]);
                up[i] = i32::from(UPPER[i]);
            }
            INIT32.store(true, core::sync::atomic::Ordering::Release);
        }
        (lo.as_ptr().add(128), up.as_ptr().add(128))
    }
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
static mut CLASS32W: [u32; 256] = class32_of_c();
static mut LOWER32W: [u32; 384] = [0; 384];
static mut UPPER32W: [u32; 384] = [0; 384];

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype32_b: *const u32 = (&raw const CLASS32W) as *const u32;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype32_tolower: *const u32 = unsafe { (C_LOWER32.as_ptr() as *const u32).add(128) };
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype32_toupper: *const u32 = unsafe { (C_UPPER32.as_ptr() as *const u32).add(128) };

pub fn set_wide_compat(tables: Option<(&[u32; 256], &[u32; 384], &[u32; 384])>) {
    unsafe {
        match tables {
            Some((c, l, u)) => {
                CLASS32W = *c;
                LOWER32W = *l;
                UPPER32W = *u;
                __ctype32_b = (&raw const CLASS32W) as *const u32;
                __ctype32_tolower = &raw const LOWER32W as *const u32;
                __ctype32_toupper = &raw const UPPER32W as *const u32;
            }
            None => {
                CLASS32W = class32_of_c();
                __ctype32_b = (&raw const CLASS32W) as *const u32;
                __ctype32_tolower = (C_LOWER32.as_ptr() as *const u32).add(128);
                __ctype32_toupper = (C_UPPER32.as_ptr() as *const u32).add(128);
            }
        }
    }
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype_b: *const c_ushort = unsafe { CLASS.as_ptr().add(128) };
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype_tolower: *const c_int = unsafe { C_LOWER32.as_ptr().add(128) };
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __ctype_toupper: *const c_int = unsafe { C_UPPER32.as_ptr().add(128) };

pub fn refresh_compat_vars() {
    unsafe {
        match loc::ctype_tables(loc::global(loc::LC_CTYPE)) {
            Some(t) => {
                __ctype_b = t.class;
                __ctype_tolower = t.lower;
                __ctype_toupper = t.upper;
            }
            None => {
                __ctype_b = CLASS.as_ptr().add(128);
                __ctype_tolower = C_LOWER32.as_ptr().add(128);
                __ctype_toupper = C_UPPER32.as_ptr().add(128);
            }
        }
    }
}

#[thread_local]
static mut TL_CLASS: *const u16 = core::ptr::null();
#[thread_local]
static mut TL_LOWER: *const i32 = core::ptr::null();
#[thread_local]
static mut TL_UPPER: *const i32 = core::ptr::null();

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isctype(c: c_int, mask: c_int) -> c_int {
    (class_of(c) & mask as c_ushort) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_b_loc() -> *mut *const c_ushort {
    unsafe {
        TL_CLASS = match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
            Some(t) => t.class,
            None => CLASS_PTR.0,
        };
        core::ptr::addr_of_mut!(TL_CLASS)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_tolower_loc() -> *mut *const c_int {
    unsafe {
        TL_LOWER = match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
            Some(t) => t.lower,
            None => init32().0,
        };
        core::ptr::addr_of_mut!(TL_LOWER)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_toupper_loc() -> *mut *const c_int {
    unsafe {
        TL_UPPER = match loc::ctype_tables(loc::current(loc::LC_CTYPE)) {
            Some(t) => t.upper,
            None => init32().1,
        };
        core::ptr::addr_of_mut!(TL_UPPER)
    }
}

pub fn c_glibc_tables() -> (*const u16, *const i32, *const i32) {
    let (lo, up) = init32();
    (CLASS_PTR.0, lo, up)
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

