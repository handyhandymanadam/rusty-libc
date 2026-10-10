#![no_std]
#![no_builtins]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments, clippy::manual_is_multiple_of, clippy::ptr_eq, clippy::unnecessary_cast)]

mod archive;
mod builtin_tables;
mod charsets;
mod collate;
pub mod coll;
pub use collate::{equiv_runs_wc, primary_mb, primary_wc};
mod data;
mod find;
mod gettext;
mod other;
mod catgets;
mod plural;

pub use catgets::{catclose, catgets, catopen};
pub use gettext::{bind_textdomain_codeset, bindtextdomain, dcgettext, dcngettext, dgettext, dngettext, gettext, ngettext, textdomain};

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};
use find::{CAT_NAMES, NameBuf, cstr_bytes};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::locale::{self as core_locale, CatData};
use rusty_libc_wchar::{Charset, set_charset};

pub const LC_CTYPE: c_int = 0;
pub const LC_NUMERIC: c_int = 1;
pub const LC_TIME: c_int = 2;
pub const LC_COLLATE: c_int = 3;
pub const LC_MONETARY: c_int = 4;
pub const LC_MESSAGES: c_int = 5;
pub const LC_ALL: c_int = 6;
pub const LC_PAPER: c_int = 7;
pub const LC_NAME: c_int = 8;
pub const LC_ADDRESS: c_int = 9;
pub const LC_TELEPHONE: c_int = 10;
pub const LC_MEASUREMENT: c_int = 11;
pub const LC_IDENTIFICATION: c_int = 12;

const NCAT: usize = 13;

#[repr(C)]
pub struct Lconv {
    pub decimal_point: *const c_char,
    pub thousands_sep: *const c_char,
    pub grouping: *const c_char,
    pub int_curr_symbol: *const c_char,
    pub currency_symbol: *const c_char,
    pub mon_decimal_point: *const c_char,
    pub mon_thousands_sep: *const c_char,
    pub mon_grouping: *const c_char,
    pub positive_sign: *const c_char,
    pub negative_sign: *const c_char,
    pub int_frac_digits: c_char,
    pub frac_digits: c_char,
    pub p_cs_precedes: c_char,
    pub p_sep_by_space: c_char,
    pub n_cs_precedes: c_char,
    pub n_sep_by_space: c_char,
    pub p_sign_posn: c_char,
    pub n_sign_posn: c_char,
    pub int_p_cs_precedes: c_char,
    pub int_p_sep_by_space: c_char,
    pub int_n_cs_precedes: c_char,
    pub int_n_sep_by_space: c_char,
    pub int_p_sign_posn: c_char,
    pub int_n_sign_posn: c_char,
}
unsafe impl Sync for Lconv {}

const CHAR_MAX: c_char = 127;

static LOCK: RawMutex = RawMutex::new();
static C_NAME: [u8; 2] = *b"C\0";

static mut G_NAMES: [*const u8; NCAT] = [C_NAME.as_ptr(); NCAT];

fn dup_name(s: &[u8]) -> *const u8 {
    if s == b"C" {
        return C_NAME.as_ptr();
    }
    unsafe {
        let p = rusty_libc_malloc::malloc(s.len() + 1) as *mut u8;
        if p.is_null() {
            return core::ptr::null();
        }
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        *p.add(s.len()) = 0;
        p
    }
}

fn free_name(p: *const u8) {
    if !p.is_null() && p != C_NAME.as_ptr() {
        unsafe { rusty_libc_malloc::free(p as *mut _) };
    }
}

fn locpath() -> Option<&'static [u8]> {
    find::env(b"LOCPATH")
}

fn composite(names: &[&[u8]; NCAT], first: usize) -> *const u8 {
    let f = names[first];
    let same = (0..NCAT).filter(|&i| i != LC_ALL as usize).all(|i| names[i] == f);
    if same {
        return dup_name(f);
    }
    let mut len = 0;
    for i in 0..NCAT {
        if i != LC_ALL as usize {
            len += CAT_NAMES[i].len() + 1 + names[i].len() + 1;
        }
    }
    let p = unsafe { rusty_libc_malloc::malloc(len) } as *mut u8;
    if p.is_null() {
        return core::ptr::null();
    }
    let mut at = 0;
    for i in 0..NCAT {
        if i == LC_ALL as usize {
            continue;
        }
        for part in [CAT_NAMES[i].as_bytes(), b"=", names[i], b";"] {
            unsafe { core::ptr::copy_nonoverlapping(part.as_ptr(), p.add(at), part.len()) };
            at += part.len();
        }
    }
    unsafe { *p.add(at - 1) = 0 };
    p
}

fn split_composite<'a>(locale: &'a [u8], out: &mut [&'a [u8]; NCAT], have: &mut u32) -> bool {
    let mut np = locale;
    while let Some(eq) = np.iter().position(|&b| b == b'=') {
        let key = &np[..eq];
        let Some(cnt) = (0..NCAT).find(|&c| c != LC_ALL as usize && CAT_NAMES[c].as_bytes() == key) else { return false };
        let val = &np[eq + 1..];
        match val.iter().position(|&b| b == b';') {
            Some(semi) => {
                out[cnt] = &val[..semi];
                *have |= 1 << cnt;
                np = &val[semi + 1..];
            }
            None => {
                out[cnt] = val;
                *have |= 1 << cnt;
                break;
            }
        }
    }
    true
}

fn charset_of(d: *const CatData) -> Charset {
    let code = unsafe { (*d).flags } >> core_locale::F_CHARSET_SHIFT & 0xff;
    match code {
        0 => Charset::C,
        1 => Charset::Utf8,
        _ => Charset::Other,
    }
}

fn tolower_hook(c: i32, loc: usize) -> i32 {
    core_locale::tolower_in(core_locale::of_locale(loc, LC_CTYPE as usize), c)
}

fn note_special(cats: &[*const CatData; NCAT]) {
    let d = cats[LC_CTYPE as usize];
    let special_ctype = !d.is_null() && unsafe { (*d).flags } & core_locale::F_CTYPE_SPECIAL != 0;
    let c = cats[LC_COLLATE as usize];
    let collating = !c.is_null() && unsafe { (*c).flags } & core_locale::F_PLAIN == 0;
    if !d.is_null() && unsafe { (*d).flags } & core_locale::F_WIDE_TABLES != 0 {
        core_locale::WIDE_SPECIAL.store(true, core::sync::atomic::Ordering::Release);
    }
    if !d.is_null() && matches!(charset_of(d), Charset::Other) {
        other::install();
    }
    if special_ctype {
        core_locale::CTYPE_SPECIAL.store(true, core::sync::atomic::Ordering::Release);
    }
    if special_ctype || collating {
        rusty_libc_mem::hooks::install(tolower_hook, collate::strcoll_hook, collate::strxfrm_hook);
        rusty_libc_mem::hooks::activate();
    }
    if collating {
        core_locale::install_wide_collation(collate::wcscoll_hook, collate::wcsxfrm_hook);
    }
}

fn refresh_wide_compat(ctype: *const CatData) {
    use rusty_libc_wchar::wctype::{iswctype, towlower, towupper, wctype};
    if ctype.is_null() || core_locale::ctype_tables(ctype).is_none() {
        rusty_libc_ctype::set_wide_compat(None);
        return;
    }
    const NAMES: [&core::ffi::CStr; 12] = [c"upper", c"lower", c"alpha", c"digit", c"xdigit", c"space", c"print", c"graph", c"blank", c"cntrl", c"punct", c"alnum"];
    let mut class = [0u32; 256];
    let mut lower = [0u32; 384];
    let mut upper = [0u32; 384];
    unsafe {
        let descs: [core::ffi::c_ulong; 12] = core::array::from_fn(|i| wctype(NAMES[i].as_ptr()));
        for wc in 0..256u32 {
            let mut bits = 0u32;
            for (bit, &d) in descs.iter().enumerate() {
                if iswctype(wc, d) != 0 {
                    bits |= wide_bit(bit as u32);
                }
            }
            class[wc as usize] = bits;
        }
        for wc in 0..256u32 {
            lower[wc as usize] = towlower(wc);
            upper[wc as usize] = towupper(wc);
        }
    }
    rusty_libc_ctype::set_wide_compat(Some((&class, &lower, &upper)));
}

const fn wide_bit(bit: u32) -> u32 {
    if bit < 8 {
        (1u32 << bit) << 24
    } else if bit < 16 {
        (1u32 << bit) << 8
    } else {
        (1u32 << bit) >> 8
    }
}

fn publish_global(cats: &[*const CatData; NCAT]) {
    note_special(cats);
    for (i, &d) in cats.iter().enumerate() {
        if i != LC_ALL as usize {
            core_locale::set_global(i, d);
        }
    }
    set_charset(charset_of(cats[LC_CTYPE as usize]));
    rusty_libc_ctype::refresh_compat_vars();
    refresh_wide_compat(cats[LC_CTYPE as usize]);
    gettext::bump_cat_cntr();
}

fn global_data(cat: usize) -> *const CatData {
    if cat == LC_ALL as usize {
        return core::ptr::null();
    }
    let p = core_locale::global(cat);
    if p.is_null() { data::builtin(false, cat) } else { p }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if !(0..NCAT as c_int).contains(&category) {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    if locale.is_null() {
        return unsafe { (*core::ptr::addr_of!(G_NAMES))[category as usize] as *mut c_char };
    }
    unsafe { setlocale_set(category as usize, locale) }
}

#[inline(never)]
unsafe fn setlocale_set(cat: usize, locale: *const c_char) -> *mut c_char {
    let g = LOCK.guard();
    let _ = &g;
    let arg = cstr_bytes(locale.cast());
    let names = unsafe { &mut *core::ptr::addr_of_mut!(G_NAMES) };
    if arg == cstr_bytes(names[cat]) {
        return names[cat] as *mut c_char;
    }
    let lp = locpath();
    if cat == LC_ALL as usize {
        let mut newnames: [&[u8]; NCAT] = [arg; NCAT];
        if arg.contains(&b';') {
            let mut have = 0;
            if !split_composite(arg, &mut newnames, &mut have) {
                errno::set(errno::EINVAL);
                return null_mut();
            }
            if (0..NCAT).any(|c| c != LC_ALL as usize && have & (1 << c) == 0) {
                errno::set(errno::EINVAL);
                return null_mut();
            }
        }
        let mut found: [Option<find::Found>; NCAT] = [const { None }; NCAT];
        for c in (0..NCAT).rev() {
            if c == LC_ALL as usize {
                continue;
            }
            match find::find_locale(c, newnames[c], lp) {
                Ok(f) => found[c] = Some(f),
                Err(e) => {
                    errno::set(e);
                    return null_mut();
                }
            }
        }
        let resolved: [NameBuf; NCAT] = core::array::from_fn(|c| match &found[c] {
            Some(f) => f.name,
            None => NameBuf::new(b"C"),
        });
        let refs: [&[u8]; NCAT] = core::array::from_fn(|c| resolved[c].as_bytes());
        let comp = composite(&refs, 0);
        if comp.is_null() {
            errno::set(12);
            return null_mut();
        }
        let mut cats = [core::ptr::null::<CatData>(); NCAT];
        for c in 0..NCAT {
            if let Some(f) = &found[c] {
                cats[c] = f.data;
                let old = names[c];
                names[c] = dup_name(refs[c]);
                free_name(old);
            }
        }
        free_name(names[LC_ALL as usize]);
        names[LC_ALL as usize] = comp;
        publish_global(&cats);
        gettext::note_locale_changed();
        return comp as *mut c_char;
    }
    let f = match find::find_locale(cat, arg, lp) {
        Ok(f) => f,
        Err(e) => {
            errno::set(e);
            return null_mut();
        }
    };
    let mut all: [&[u8]; NCAT] = core::array::from_fn(|c| cstr_bytes(names[c]));
    all[cat] = f.name.as_bytes();
    let comp = composite(&all, cat);
    if comp.is_null() {
        errno::set(12);
        return null_mut();
    }
    let newname = dup_name(f.name.as_bytes());
    let old = names[cat];
    names[cat] = newname;
    free_name(old);
    free_name(names[LC_ALL as usize]);
    names[LC_ALL as usize] = comp;
    let mut cats: [*const CatData; NCAT] = core::array::from_fn(global_data);
    cats[cat] = f.data;
    publish_global(&cats);
    gettext::note_locale_changed();
    newname as *mut c_char
}

fn cur_data(cat: usize, loc: usize) -> *const CatData {
    let p = core_locale::of_locale(loc, cat);
    if p.is_null() { data::builtin(false, cat) } else { p }
}

static mut LCONV: Lconv = C_LCONV_INIT;
const C_LCONV_INIT: Lconv = Lconv {
    decimal_point: c".".as_ptr(),
    thousands_sep: c"".as_ptr(),
    grouping: c"".as_ptr(),
    int_curr_symbol: c"".as_ptr(),
    currency_symbol: c"".as_ptr(),
    mon_decimal_point: c"".as_ptr(),
    mon_thousands_sep: c"".as_ptr(),
    mon_grouping: c"".as_ptr(),
    positive_sign: c"".as_ptr(),
    negative_sign: c"".as_ptr(),
    int_frac_digits: CHAR_MAX,
    frac_digits: CHAR_MAX,
    p_cs_precedes: CHAR_MAX,
    p_sep_by_space: CHAR_MAX,
    n_cs_precedes: CHAR_MAX,
    n_sep_by_space: CHAR_MAX,
    p_sign_posn: CHAR_MAX,
    n_sign_posn: CHAR_MAX,
    int_p_cs_precedes: CHAR_MAX,
    int_p_sep_by_space: CHAR_MAX,
    int_n_cs_precedes: CHAR_MAX,
    int_n_sep_by_space: CHAR_MAX,
    int_p_sign_posn: CHAR_MAX,
    int_n_sign_posn: CHAR_MAX,
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn localeconv() -> *const Lconv {
    let n = cur_data(LC_NUMERIC as usize, 0);
    let m = cur_data(LC_MONETARY as usize, 0);
    unsafe {
        let r = &mut *core::ptr::addr_of_mut!(LCONV);
        if LCONV_KEY[0].load(Ordering::Acquire) != n as usize || LCONV_KEY[1].load(Ordering::Acquire) != m as usize {
            fill_lconv_from(r, n, m);
            LCONV_KEY[0].store(n as usize, Ordering::Release);
            LCONV_KEY[1].store(m as usize, Ordering::Release);
        }
        r
    }
}

static LCONV_KEY: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

pub fn lconv_of(loc: usize) -> Lconv {
    let mut r = C_LCONV_INIT;
    fill_lconv(&mut r, loc);
    r
}

fn fill_lconv(r: &mut Lconv, loc: usize) {
    fill_lconv_from(r, cur_data(LC_NUMERIC as usize, loc), cur_data(LC_MONETARY as usize, loc));
}

fn fill_lconv_from(r: &mut Lconv, n: *const CatData, m: *const CatData) {
    unsafe {
        let n = &*n;
        let m = &*m;
        let nostop = |p: *const u8| -> *const c_char { if *p == 127 || *p == 255 { c"".as_ptr() } else { p.cast() } };
        r.decimal_point = n.cstr(0).cast();
        r.thousands_sep = n.cstr(1).cast();
        r.grouping = nostop(n.cstr(2));
        r.int_curr_symbol = m.cstr(0).cast();
        r.currency_symbol = m.cstr(1).cast();
        r.mon_decimal_point = m.cstr(2).cast();
        r.mon_thousands_sep = m.cstr(3).cast();
        r.mon_grouping = nostop(m.cstr(4));
        r.positive_sign = m.cstr(5).cast();
        r.negative_sign = m.cstr(6).cast();
        let b = |i: usize| -> c_char {
            let v = m.byte(i);
            if v == 255 { CHAR_MAX } else { v as c_char }
        };
        r.int_frac_digits = b(7);
        r.frac_digits = b(8);
        r.p_cs_precedes = b(9);
        r.p_sep_by_space = b(10);
        r.n_cs_precedes = b(11);
        r.n_sep_by_space = b(12);
        r.p_sign_posn = b(13);
        r.n_sign_posn = b(14);
        r.int_p_cs_precedes = b(16);
        r.int_p_sep_by_space = b(17);
        r.int_n_cs_precedes = b(18);
        r.int_n_sep_by_space = b(19);
        r.int_p_sign_posn = b(20);
        r.int_n_sign_posn = b(21);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nl_langinfo(item: c_int) -> *const c_char {
    nl_langinfo_l(item, core_locale::thread() as *mut LocaleStruct)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nl_langinfo_l(item: c_int, loc: *mut LocaleStruct) -> *const c_char {
    let cat = (item >> 16) as usize;
    if item < 0 || cat >= NCAT || cat == LC_ALL as usize {
        return c"".as_ptr();
    }
    let index = (item & 0xffff) as usize;
    if index == 0xffff {
        return name_of(loc as usize, cat).cast();
    }
    let d = unsafe { &*cur_data(cat, loc as usize) };
    if index >= d.nstrings as usize {
        return c"".as_ptr();
    }
    unsafe { *d.values.add(index) as *const c_char }
}

pub(crate) fn name_of(loc: usize, cat: usize) -> *const u8 {
    if loc == 0 {
        let t = core_locale::thread();
        if t.is_null() {
            return unsafe { (*core::ptr::addr_of!(G_NAMES))[cat] };
        }
        return unsafe { (*(t as *const LocaleStruct)).names[cat].cast() };
    }
    if loc == LC_GLOBAL_LOCALE {
        return unsafe { (*core::ptr::addr_of!(G_NAMES))[cat] };
    }
    unsafe { (*(loc as *const LocaleStruct)).names[cat].cast() }
}

#[repr(C)]
pub struct LocaleStruct {
    locales: [*const CatData; NCAT],
    ctype_b: *const u16,
    ctype_tolower: *const i32,
    ctype_toupper: *const i32,
    names: [*const c_char; NCAT],
}

const LC_GLOBAL_LOCALE: usize = usize::MAX;

static mut C_LOCOBJ: LocaleStruct = LocaleStruct {
    locales: [core::ptr::null(); NCAT],
    ctype_b: core::ptr::null(),
    ctype_tolower: core::ptr::null(),
    ctype_toupper: core::ptr::null(),
    names: [core::ptr::null(); NCAT],
};

fn fill_pointers(l: &mut LocaleStruct) {
    match core_locale::ctype_tables(l.locales[LC_CTYPE as usize]) {
        Some(t) => {
            l.ctype_b = t.class;
            l.ctype_tolower = t.lower;
            l.ctype_toupper = t.upper;
        }
        None => {
            let (b, lo, up) = rusty_libc_ctype::c_glibc_tables();
            l.ctype_b = b;
            l.ctype_tolower = lo;
            l.ctype_toupper = up;
        }
    }
}

fn c_locobj() -> *mut LocaleStruct {
    unsafe {
        let l = &mut *core::ptr::addr_of_mut!(C_LOCOBJ);
        if l.locales[0].is_null() {
            for c in 0..NCAT {
                if c != LC_ALL as usize {
                    l.locales[c] = data::builtin(false, c);
                    l.names[c] = C_NAME.as_ptr().cast();
                }
            }
            fill_pointers(l);
        }
        l
    }
}

fn snapshot(loc: usize) -> ([*const CatData; NCAT], [NameBuf; NCAT]) {
    let mut cats = [core::ptr::null::<CatData>(); NCAT];
    let mut names = [NameBuf::new(b"C"); NCAT];
    for c in 0..NCAT {
        if c != LC_ALL as usize {
            cats[c] = cur_data(c, loc);
            names[c] = NameBuf::new(cstr_bytes(name_of(loc, c)));
        }
    }
    (cats, names)
}

fn alloc_locale(cats: &[*const CatData; NCAT], names: &[&[u8]; NCAT]) -> *mut LocaleStruct {
    note_special(cats);
    let total: usize = (0..NCAT).filter(|&c| c != LC_ALL as usize && names[c] != b"C").map(|c| names[c].len() + 1).sum();
    unsafe {
        let p = rusty_libc_malloc::calloc(1, core::mem::size_of::<LocaleStruct>() + total) as *mut LocaleStruct;
        if p.is_null() {
            errno::set(12);
            return null_mut();
        }
        let mut area = (p as *mut u8).add(core::mem::size_of::<LocaleStruct>());
        for c in 0..NCAT {
            if c == LC_ALL as usize {
                continue;
            }
            (*p).locales[c] = cats[c];
            if names[c] == b"C" {
                (*p).names[c] = C_NAME.as_ptr().cast();
            } else {
                core::ptr::copy_nonoverlapping(names[c].as_ptr(), area, names[c].len());
                *area.add(names[c].len()) = 0;
                (*p).names[c] = area.cast();
                area = area.add(names[c].len() + 1);
            }
        }
        fill_pointers(&mut *p);
        p
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn newlocale(mask: c_int, locale: *const c_char, base: *mut LocaleStruct) -> *mut LocaleStruct {
    const ALL: c_int = 0x1fbf;
    let mask = if mask == 1 << LC_ALL { ALL } else { mask };
    if mask & !ALL != 0 || locale.is_null() {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    let g = LOCK.guard();
    let _ = &g;
    let mut base = base;
    let cl = c_locobj();
    if base == cl {
        base = null_mut();
    }
    let arg = cstr_bytes(locale.cast());
    if (base.is_null() || mask == ALL) && (mask == 0 || arg == b"C") {
        return cl;
    }
    let (mut cats, bnames) = if base.is_null() { snapshot(cl as usize) } else { snapshot(base as usize) };
    let mut resolved = bnames;
    if mask != 0 {
        let mut newnames: [&[u8]; NCAT] = [arg; NCAT];
        if arg.contains(&b';') {
            let mut have = 0u32;
            if !split_composite(arg, &mut newnames, &mut have) || (mask as u32) & !have != 0 {
                errno::set(errno::EINVAL);
                return null_mut();
            }
        }
        let lp = locpath();
        for c in 0..NCAT {
            if c == LC_ALL as usize || mask & (1 << c) == 0 {
                continue;
            }
            match find::find_locale(c, newnames[c], lp) {
                Ok(f) => {
                    cats[c] = f.data;
                    resolved[c] = f.name;
                }
                Err(e) => {
                    errno::set(e);
                    return null_mut();
                }
            }
        }
    }
    let refs: [&[u8]; NCAT] = core::array::from_fn(|c| resolved[c].as_bytes());
    let r = alloc_locale(&cats, &refs);
    if !r.is_null() && !base.is_null() && base as usize != LC_GLOBAL_LOCALE {
        unsafe { rusty_libc_malloc::free(base.cast()) };
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn duplocale(loc: *mut LocaleStruct) -> *mut LocaleStruct {
    if loc.is_null() {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    let g = LOCK.guard();
    let _ = &g;
    if loc == c_locobj() {
        return loc;
    }
    let (cats, names) = snapshot(loc as usize);
    let refs: [&[u8]; NCAT] = core::array::from_fn(|c| names[c].as_bytes());
    alloc_locale(&cats, &refs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freelocale(loc: *mut LocaleStruct) {
    if !loc.is_null() && loc as usize != LC_GLOBAL_LOCALE {
        let g = LOCK.guard();
        let _ = &g;
        if loc != c_locobj() {
            unsafe { rusty_libc_malloc::free(loc.cast()) };
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uselocale(loc: *mut LocaleStruct) -> *mut LocaleStruct {
    let t = core_locale::thread();
    let old = if t.is_null() { LC_GLOBAL_LOCALE as *mut LocaleStruct } else { t as *mut LocaleStruct };
    if !loc.is_null() {
        if loc as usize == LC_GLOBAL_LOCALE {
            core_locale::set_thread(core::ptr::null());
        } else {
            core_locale::set_thread(loc as *const *const CatData);
        }
    }
    old
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __uselocale(loc: *mut LocaleStruct) -> *mut LocaleStruct {
    unsafe { uselocale(loc) }
}


rusty_libc_core::tail_alias!(__newlocale => newlocale);
rusty_libc_core::tail_alias!(__duplocale => duplocale);
rusty_libc_core::tail_alias!(__freelocale => freelocale);
rusty_libc_core::tail_alias!(__nl_langinfo_l => nl_langinfo_l);
