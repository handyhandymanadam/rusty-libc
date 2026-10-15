#![no_std]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![no_builtins]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments, clippy::manual_is_multiple_of, clippy::ptr_eq, clippy::unnecessary_cast)]

mod archive;
mod builtin_tables;
mod charsets;
mod collate;
pub mod coll;
pub use collate::{equiv_runs_wc, primary_bytes, primary_mb, primary_wc, primary_wide, strcoll_bytes, strxfrm_bytes, wcscoll_wide, wcsxfrm_wide};
mod data;
mod find;
mod mem;
mod gettext;
mod other;
mod catgets;
mod plural;

pub use catgets::{catclose, catgets, catopen};
pub use gettext::{bind_textdomain_codeset, bindtextdomain, dcgettext, dcngettext, dgettext, dngettext, gettext, ngettext, textdomain};

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use find::{CAT_NAMES, NameBuf};
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::lock::{Guard, Locked, RawMutex};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::locale::{self as core_locale, CatData, Loc};
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

const CHAR_MAX: c_char = 127;

static LOCK: RawMutex = RawMutex::new();
static C_NAME: [u8; 2] = *b"C\0";

static G_NAMES: [AtomicPtr<u8>; NCAT] = [const { AtomicPtr::new(C_NAME.as_ptr().cast_mut()) }; NCAT];

#[inline(always)]
fn g_name(cat: usize) -> *const u8 {
    G_NAMES[cat].load(Ordering::Acquire)
}

#[inline]
unsafe fn name_bytes<'a>(p: *const u8) -> &'a [u8] {
    unsafe { ffi::cstr_bytes_scalar(p) }
}

fn dup_name(s: &[u8]) -> *const u8 {
    if s == b"C" {
        return C_NAME.as_ptr();
    }
    mem::dup_cstr(s)
}

fn free_name(p: *const u8) {
    if !p.is_null() && p != C_NAME.as_ptr() {
        unsafe { mem::free(p.cast_mut()) };
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
    let p = mem::malloc(len);
    if p.is_null() {
        return core::ptr::null();
    }
    let out = unsafe { mem::block(p, len) };
    let mut at = 0;
    for i in 0..NCAT {
        if i == LC_ALL as usize {
            continue;
        }
        for part in [CAT_NAMES[i].as_bytes(), b"=", names[i], b";"] {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
    }
    out[at - 1] = 0;
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

type Cats = [Option<&'static CatData>; NCAT];

fn raw(d: Option<&'static CatData>) -> *const CatData {
    d.map_or(core::ptr::null(), |d| d as *const CatData)
}

fn charset_of(d: &CatData) -> Charset {
    let code = d.flags() >> core_locale::F_CHARSET_SHIFT & 0xff;
    match code {
        0 => Charset::C,
        1 => Charset::Utf8,
        _ => Charset::Other,
    }
}

fn tolower_hook(c: i32, loc: Loc) -> i32 {
    core_locale::tolower_in(data::locale_cat(loc, LC_CTYPE as usize), c)
}

fn note_special(cats: &Cats) {
    let d = cats[LC_CTYPE as usize];
    let special_ctype = d.is_some_and(|d| d.flags() & core_locale::F_CTYPE_SPECIAL != 0);
    let collating = cats[LC_COLLATE as usize].is_some_and(|c| c.flags() & core_locale::F_PLAIN == 0);
    if d.is_some_and(|d| d.flags() & core_locale::F_WIDE_TABLES != 0) {
        core_locale::WIDE_SPECIAL.store(true, core::sync::atomic::Ordering::Release);
    }
    if d.is_some_and(|d| matches!(charset_of(d), Charset::Other)) {
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

struct WideCompat {
    class: [u32; 256],
    lower: [u32; 384],
    upper: [u32; 384],
}

struct WideCached {
    key: usize,
    generation: usize,
    tables: &'static mut WideCompat,
}

const WIDE_CACHE: usize = 8;

static WIDE_CACHED: Locked<([Option<WideCached>; WIDE_CACHE], usize)> = Locked::new(([const { None }; WIDE_CACHE], 0));

fn refresh_wide_compat(ctype: Option<&'static CatData>) {
    static WIDE_FROM: AtomicPtr<CatData> = AtomicPtr::new(null_mut());
    static WIDE_GEN: AtomicUsize = AtomicUsize::new(0);
    if core_locale::ctype_tables(ctype).is_none() {
        WIDE_FROM.store(null_mut(), Ordering::Relaxed);
        rusty_libc_ctype::set_wide_compat(None);
        return;
    }
    let key = ctype.map_or(null_mut(), |d| core::ptr::from_ref(d).cast_mut());
    let gen_now = data::FREED_GEN.load(Ordering::Acquire);
    let own_thread_locale = !core::ptr::eq(core_locale::current(core_locale::LC_CTYPE).map_or(core::ptr::null(), core::ptr::from_ref), key);
    let cacheable = !key.is_null() && !own_thread_locale;
    if cacheable && WIDE_FROM.load(Ordering::Relaxed) == key && WIDE_GEN.load(Ordering::Relaxed) == gen_now {
        return;
    }
    WIDE_CACHED.with(|(slots, next)| {
        if cacheable && let Some(c) = slots.iter().flatten().find(|c| c.key == key as usize && c.generation == gen_now) {
            rusty_libc_ctype::set_wide_compat(Some((&c.tables.class, &c.tables.lower, &c.tables.upper)));
            return;
        }
        let mut fresh = WideCompat { class: [0; 256], lower: [0; 384], upper: [0; 384] };
        compute_wide_compat(&mut fresh);
        rusty_libc_ctype::set_wide_compat(Some((&fresh.class, &fresh.lower, &fresh.upper)));
        if cacheable {
            let slot = &mut slots[*next];
            match slot {
                Some(c) => {
                    *c.tables = fresh;
                    c.key = key as usize;
                    c.generation = gen_now;
                }
                None => {
                    if let Some(tables) = mem::leak(fresh) {
                        *slot = Some(WideCached { key: key as usize, generation: gen_now, tables });
                    }
                }
            }
            *next = (*next + 1) % WIDE_CACHE;
        }
    });
    WIDE_FROM.store(if cacheable { key } else { null_mut() }, Ordering::Relaxed);
    WIDE_GEN.store(gen_now, Ordering::Relaxed);
}

fn compute_wide_compat(t: &mut WideCompat) {
    use rusty_libc_wchar::wctype::{class_by_name, in_class, to_lower, to_upper};
    const NAMES: [&[u8]; 12] = [b"upper", b"lower", b"alpha", b"digit", b"xdigit", b"space", b"print", b"graph", b"blank", b"cntrl", b"punct", b"alnum"];
    let descs: [core::ffi::c_ulong; 12] = core::array::from_fn(|i| class_by_name(NAMES[i]));
    for wc in 0..256u32 {
        let mut bits = 0u32;
        for (bit, &d) in descs.iter().enumerate() {
            if in_class(wc, d) {
                bits |= wide_bit(bit as u32);
            }
        }
        t.class[wc as usize] = bits;
    }
    for wc in 0..256u32 {
        t.lower[wc as usize] = to_lower(wc);
        t.upper[wc as usize] = to_upper(wc);
    }
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

fn publish_global(cats: &Cats) {
    note_special(cats);
    for (i, &d) in cats.iter().enumerate() {
        if i != LC_ALL as usize {
            core_locale::set_global(i, d);
        }
    }
    if let Some(d) = cats[LC_CTYPE as usize] {
        set_charset(charset_of(d));
    }
    rusty_libc_ctype::refresh_compat_vars();
    refresh_wide_compat(cats[LC_CTYPE as usize]);
    gettext::bump_cat_cntr();
}

fn global_data(cat: usize) -> Option<&'static CatData> {
    if cat == LC_ALL as usize {
        return None;
    }
    Some(data::global_cat(cat).unwrap_or_else(|| data::builtin(false, cat)))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if !(0..NCAT as c_int).contains(&category) {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    if locale.is_null() {
        return g_name(category as usize) as *mut c_char;
    }
    let arg = unsafe { ffi::cstr_bytes_scalar(locale) };
    setlocale_set(category as usize, arg)
}

#[inline(never)]
pub fn setlocale_set(cat: usize, arg: &[u8]) -> *mut c_char {
    let g = LOCK.guard();
    let _ = &g;
    let names = &G_NAMES;
    if arg == unsafe { name_bytes(g_name(cat)) } {
        return g_name(cat) as *mut c_char;
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
        let mut cats: Cats = [None; NCAT];
        for c in 0..NCAT {
            if let Some(f) = &found[c] {
                cats[c] = Some(f.data);
                let old = g_name(c);
                names[c].store(dup_name(refs[c]).cast_mut(), Ordering::Release);
                free_name(old);
            }
        }
        free_name(g_name(LC_ALL as usize));
        names[LC_ALL as usize].store(comp.cast_mut(), Ordering::Release);
        publish_global(&cats);
        gettext::note_locale_changed();
        gettext::note_messages_locale(unsafe { name_bytes(g_name(LC_MESSAGES as usize)) });
        return comp as *mut c_char;
    }
    let f = match find::find_locale(cat, arg, lp) {
        Ok(f) => f,
        Err(e) => {
            errno::set(e);
            return null_mut();
        }
    };
    let mut all: [&[u8]; NCAT] = core::array::from_fn(|c| unsafe { name_bytes(g_name(c)) });
    all[cat] = f.name.as_bytes();
    let comp = composite(&all, cat);
    if comp.is_null() {
        errno::set(12);
        return null_mut();
    }
    let newname = dup_name(f.name.as_bytes());
    let old = g_name(cat);
    names[cat].store(newname.cast_mut(), Ordering::Release);
    free_name(old);
    free_name(g_name(LC_ALL as usize));
    names[LC_ALL as usize].store(comp.cast_mut(), Ordering::Release);
    let mut cats: Cats = core::array::from_fn(global_data);
    cats[cat] = Some(f.data);
    publish_global(&cats);
    gettext::note_locale_changed();
    gettext::note_messages_locale(unsafe { name_bytes(g_name(LC_MESSAGES as usize)) });
    newname as *mut c_char
}

pub(crate) fn messages_name() -> &'static [u8] {
    unsafe { name_bytes(g_name(LC_MESSAGES as usize)) }
}

fn cur_data(cat: usize, loc: Loc) -> &'static CatData {
    match data::locale_cat(loc, cat) {
        Some(d) => d,
        None => data::builtin(false, cat),
    }
}

static LCONV: SyncCell<Lconv> = SyncCell::new(C_LCONV_INIT);
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
    let n = cur_data(LC_NUMERIC as usize, Loc::CURRENT);
    let m = cur_data(LC_MONETARY as usize, Loc::CURRENT);
    let (nk, mk) = (n as *const CatData as usize, m as *const CatData as usize);
    if LCONV_KEY[0].load(Ordering::Acquire) != nk || LCONV_KEY[1].load(Ordering::Acquire) != mk {
        refill_lconv(n, m);
    }
    LCONV.as_ptr()
}

#[cold]
#[inline(never)]
fn refill_lconv(n: &'static CatData, m: &'static CatData) {
    unsafe { LCONV.write(lconv_from(n, m)) };
    LCONV_KEY[0].store(n as *const CatData as usize, Ordering::Release);
    LCONV_KEY[1].store(m as *const CatData as usize, Ordering::Release);
}

static LCONV_KEY: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

pub fn lconv_of(loc: Loc) -> Lconv {
    lconv_from(cur_data(LC_NUMERIC as usize, loc), cur_data(LC_MONETARY as usize, loc))
}

fn lconv_from(n: &CatData, m: &CatData) -> Lconv {
    let nostop = |d: &CatData, i: usize| -> *const c_char { if matches!(d.byte(i), 127 | 255) { c"".as_ptr() } else { d.cstr(i).cast() } };
    let b = |i: usize| -> c_char {
        let v = m.byte(i);
        if v == 255 { CHAR_MAX } else { v as c_char }
    };
    Lconv {
        decimal_point: n.cstr(0).cast(),
        thousands_sep: n.cstr(1).cast(),
        grouping: nostop(n, 2),
        int_curr_symbol: m.cstr(0).cast(),
        currency_symbol: m.cstr(1).cast(),
        mon_decimal_point: m.cstr(2).cast(),
        mon_thousands_sep: m.cstr(3).cast(),
        mon_grouping: nostop(m, 4),
        positive_sign: m.cstr(5).cast(),
        negative_sign: m.cstr(6).cast(),
        int_frac_digits: b(7),
        frac_digits: b(8),
        p_cs_precedes: b(9),
        p_sep_by_space: b(10),
        n_cs_precedes: b(11),
        n_sep_by_space: b(12),
        p_sign_posn: b(13),
        n_sign_posn: b(14),
        int_p_cs_precedes: b(16),
        int_p_sep_by_space: b(17),
        int_n_cs_precedes: b(18),
        int_n_sep_by_space: b(19),
        int_p_sign_posn: b(20),
        int_n_sign_posn: b(21),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nl_langinfo(item: c_int) -> *const c_char {
    langinfo(item, Loc::CURRENT)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo_l(item: c_int, loc: *mut LocaleStruct) -> *const c_char {
    langinfo(item, unsafe { Loc::from_raw(loc as usize) })
}

pub fn langinfo(item: c_int, loc: Loc) -> *const c_char {
    let cat = (item >> 16) as usize;
    if item < 0 || cat >= NCAT || cat == LC_ALL as usize {
        return c"".as_ptr();
    }
    let index = (item & 0xffff) as usize;
    if index == 0xffff {
        return name_of(loc, cat).cast();
    }
    cur_data(cat, loc).cstr(index).cast()
}

pub(crate) fn name_of(loc: Loc, cat: usize) -> *const u8 {
    let obj = if loc == Loc::CURRENT { core_locale::thread() as usize } else { loc.raw() };
    if obj == 0 || obj == LC_GLOBAL_LOCALE {
        return g_name(cat);
    }
    let l = obj as *const LocaleStruct;
    unsafe { (*l).names[cat].cast() }
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

static C_LOCOBJ: SyncCell<LocaleStruct> = SyncCell::new(LocaleStruct {
    locales: [core::ptr::null(); NCAT],
    ctype_b: core::ptr::null(),
    ctype_tolower: core::ptr::null(),
    ctype_toupper: core::ptr::null(),
    names: [core::ptr::null(); NCAT],
});
static C_LOCOBJ_READY: AtomicBool = AtomicBool::new(false);

fn fill_pointers(l: &mut LocaleStruct) {
    match core_locale::ctype_tables(unsafe { data::published(l.locales[LC_CTYPE as usize]) }) {
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

#[inline]
fn c_locobj(_g: &Guard<'_>) -> *mut LocaleStruct {
    if !C_LOCOBJ_READY.load(Ordering::Acquire) {
        c_locobj_fill();
    }
    C_LOCOBJ.as_ptr()
}

#[cold]
#[inline(never)]
fn c_locobj_fill() {
    let mut l = LocaleStruct { locales: [core::ptr::null(); NCAT], ctype_b: core::ptr::null(), ctype_tolower: core::ptr::null(), ctype_toupper: core::ptr::null(), names: [core::ptr::null(); NCAT] };
    for c in 0..NCAT {
        if c != LC_ALL as usize {
            l.locales[c] = data::builtin(false, c);
            l.names[c] = C_NAME.as_ptr().cast();
        }
    }
    fill_pointers(&mut l);
    unsafe { C_LOCOBJ.write(l) };
    C_LOCOBJ_READY.store(true, Ordering::Release);
}

fn snapshot(loc: Loc) -> (Cats, [NameBuf; NCAT]) {
    let mut cats: Cats = [None; NCAT];
    let mut names = [NameBuf::new(b"C"); NCAT];
    for c in 0..NCAT {
        if c != LC_ALL as usize {
            cats[c] = Some(cur_data(c, loc));
            names[c] = NameBuf::new(unsafe { name_bytes(name_of(loc, c)) });
        }
    }
    (cats, names)
}

fn alloc_locale(cats: &Cats, names: &[&[u8]; NCAT]) -> *mut LocaleStruct {
    note_special(cats);
    const SZ: usize = core::mem::size_of::<LocaleStruct>();
    let total: usize = (0..NCAT).filter(|&c| c != LC_ALL as usize && names[c] != b"C").map(|c| names[c].len() + 1).sum();
    let p = mem::calloc(1, SZ + total);
    if p.is_null() {
        errno::set(12);
        return null_mut();
    }
    let area_ptr = p.wrapping_add(SZ);
    let area = unsafe { mem::block(area_ptr, total) };
    let mut l = LocaleStruct { locales: [core::ptr::null(); NCAT], ctype_b: core::ptr::null(), ctype_tolower: core::ptr::null(), ctype_toupper: core::ptr::null(), names: [core::ptr::null(); NCAT] };
    let mut at = 0;
    for c in 0..NCAT {
        if c == LC_ALL as usize {
            continue;
        }
        l.locales[c] = raw(cats[c]);
        if names[c] == b"C" {
            l.names[c] = C_NAME.as_ptr().cast();
        } else {
            area[at..at + names[c].len()].copy_from_slice(names[c]);
            area[at + names[c].len()] = 0;
            l.names[c] = area_ptr.wrapping_add(at).cast();
            at += names[c].len() + 1;
        }
    }
    fill_pointers(&mut l);
    let p = p.cast::<LocaleStruct>();
    unsafe { p.write(l) };
    p
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn newlocale(mask: c_int, locale: *const c_char, base: *mut LocaleStruct) -> *mut LocaleStruct {
    const ALL: c_int = 0x1fbf;
    let mask = if mask == 1 << LC_ALL { ALL } else { mask };
    if mask & !ALL != 0 || locale.is_null() {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    let arg = unsafe { ffi::cstr_bytes_scalar(locale) };
    unsafe { newlocale_core(mask, arg, base as usize) }
}

unsafe fn newlocale_core(mask: c_int, arg: &[u8], base: usize) -> *mut LocaleStruct {
    const ALL: c_int = 0x1fbf;
    let g = LOCK.guard();
    let cl = c_locobj(&g);
    let base = if base == cl as usize { 0 } else { base };
    if (base == 0 || mask == ALL) && (mask == 0 || arg == b"C") {
        return cl;
    }
    let from = unsafe { Loc::from_raw(if base == 0 { cl as usize } else { base }) };
    let (mut cats, bnames) = snapshot(from);
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
                    cats[c] = Some(f.data);
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
    gettext::note_messages_locale(refs[LC_MESSAGES as usize]);
    let r = alloc_locale(&cats, &refs);
    if !r.is_null() && base != 0 && base != LC_GLOBAL_LOCALE {
        unsafe { mem::free(base as *mut LocaleStruct) };
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
    if loc == c_locobj(&g) {
        return loc;
    }
    let (cats, names) = snapshot(unsafe { Loc::from_raw(loc as usize) });
    let refs: [&[u8]; NCAT] = core::array::from_fn(|c| names[c].as_bytes());
    alloc_locale(&cats, &refs)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freelocale(loc: *mut LocaleStruct) {
    if !loc.is_null() && loc as usize != LC_GLOBAL_LOCALE {
        let g = LOCK.guard();
        if loc != c_locobj(&g) {
            unsafe { mem::free(loc) };
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uselocale(loc: *mut LocaleStruct) -> *mut LocaleStruct {
    let t = core_locale::thread();
    let old = if t.is_null() { LC_GLOBAL_LOCALE as *mut LocaleStruct } else { t as *mut LocaleStruct };
    if !loc.is_null() {
        if loc as usize == LC_GLOBAL_LOCALE {
            unsafe { core_locale::set_thread(core::ptr::null()) };
        } else {
            unsafe { core_locale::set_thread(loc as *const *const CatData) };
        }
    }
    old
}

rusty_libc_core::tail_alias!(__newlocale => newlocale);
rusty_libc_core::tail_alias!(__uselocale => uselocale);
rusty_libc_core::tail_alias!(__duplocale => duplocale);
rusty_libc_core::tail_alias!(__freelocale => freelocale);
rusty_libc_core::tail_alias!(__nl_langinfo_l => nl_langinfo_l);
