//! locale.h and langinfo.h: `setlocale` (with glibc's name rules and composite names),
//! `localeconv`, `nl_langinfo(_l)`, `newlocale`, `duplocale`, `freelocale`, `uselocale`.
//!
//! Locale data comes from the built-in "C"/"POSIX" and "C.UTF-8" tables, from glibc's locale
//! archive (`/usr/lib/locale/locale-archive`), and from per-locale directories (default
//! `/usr/lib/locale`, or LOCPATH); see `find` for the lookup rules (the ones of glibc's
//! `_nl_find_locale`) and `archive` / `data` for the file formats. Loaded data is published to the
//! crates below through rusty-libc-core's `locale` module: printf, scanf, strtod, strftime, strcoll and
//! the wide character functions read the current locale from there.
//!
//! `setlocale(LC_CTYPE, ...)` switches rusty-libc-wchar's character set; `uselocale` installs a
//! thread-local locale object that all of them (and `nl_langinfo`, `localeconv`) follow.
//!
//! Unsafe code (BRIEF-UNSAFE U2: thin unsafe shell, safe core). Every block holds one operation with a `// SAFETY:`
//! comment (denied below). What is left:
//! - C arguments: each exported function converts its C strings once (core's `ffi`) and a `locale_t` once into a `Loc`
//!   (core's checked locale argument: only its unsafe constructor makes one, so the safe functions that take a `Loc`
//!   may read the locale it names), and dereferences a catalog handle the caller passes.
//! - `mem`: malloc/calloc/realloc/free, slices over fresh blocks, the read-only `mmap` of locale files and catalogs (kept
//!   for good, so given out as `&'static [u8]`).
//! - `data`: a published `CatData` pointer as a reference, the image extent stored after its values, aligned word views of
//!   the image's tables; the tables themselves are read through bounds-checked slices.
//! - Globals: atomics, or `SyncCell`s whose accessors state their rule (LOCK, gettext's STATE, the converter spin lock,
//!   "written once before a Release flag").
//! - gettext's `struct binding` list (glibc's layout, exported), whose domain name lies after the fixed part.
//! - The multibyte hooks for other charsets (`other`) and the wide-string hooks (`collate`): raw pointers whose lengths
//!   are only known by their terminators or by the caller's count.
#![cfg_attr(not(test), no_std)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
// LLVM would turn the wide string loops into calls to wcslen, which a Rust-only program does not link
#![no_builtins]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments, clippy::manual_is_multiple_of, clippy::ptr_eq, clippy::unnecessary_cast)]

mod archive;
mod builtin_tables;
mod charsets;
mod collate;
pub mod coll;
pub use collate::{equiv_runs_wc, equiv_runs_wc_in, equiv_runs_wc_in_at, primary_bytes, primary_mb, primary_wc, primary_wide, strcoll_bytes, strxfrm_bytes, wcscoll_wide, wcsxfrm_wide};
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

/// Number of category slots (LC_ALL's slot 6 stays unused).
const NCAT: usize = 13;

/// glibc's `struct lconv` (x86-64 layout).
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

/// Names of the process-wide locale; slot `LC_ALL` holds the composite name. Heap strings from [`dup_name`] /
/// [`composite`], or the static "C". Stored only under LOCK; `setlocale(cat, NULL)` and `nl_langinfo` read them without
/// it, as glibc's do (the atomics make that read well defined; the string itself is freed only when it is replaced).
static G_NAMES: [AtomicPtr<u8>; NCAT] = [const { AtomicPtr::new(C_NAME.as_ptr().cast_mut()) }; NCAT];

/// The global name of category `cat`.
#[inline(always)]
fn g_name(cat: usize) -> *const u8 {
    G_NAMES[cat].load(Ordering::Acquire)
}

/// The bytes of a locale name: one from G_NAMES or a `locale_t`, made by [`dup_name`], [`composite`] or
/// [`alloc_locale`] (or the static "C"), or a C string argument.
///
/// # Safety
/// `p` points to a NUL-terminated string that stays valid for `'a` (names are freed only under LOCK, when replaced or
/// with their `locale_t`).
#[inline]
unsafe fn name_bytes<'a>(p: *const u8) -> &'a [u8] {
    // SAFETY: the caller's contract.
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
        // SAFETY: a name other than the static "C" was made by dup_name/composite (malloc) and is no longer in any table
        // (the caller has just replaced it).
        unsafe { mem::free(p.cast_mut()) };
    }
}

fn locpath() -> Option<&'static [u8]> {
    find::env(b"LOCPATH")
}

/// glibc's `new_composite_name`: the single name if all categories share it ("C" for C/POSIX),
/// else "LC_CTYPE=..;LC_NUMERIC=..;...". `names[i]` is the name of category i; sameness is judged
/// against `names[first]`.
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
    // SAFETY: a fresh block of `len` bytes, ours alone until returned.
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
    // the last ';' becomes the NUL
    out[at - 1] = 0;
    p
}

/// Split a composite "CAT=name;CAT=name" argument the way setlocale/newlocale do; `have` gets the
/// categories named, `out[i]` their names. Returns false for a bogus category name.
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

/// The data of one locale: per category the published data (None only in the LC_ALL slot).
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

/// Publish the global data to the crates below and switch the character set.
fn tolower_hook(c: i32, loc: Loc) -> i32 {
    core_locale::tolower_in(data::locale_cat(loc, LC_CTYPE as usize), c)
}

/// Switch on the locale-dependent paths of the crates below when a locale that needs them is
/// installed or created: special single-byte case tables, collation rules.
fn note_special(cats: &Cats) {
    let d = cats[LC_CTYPE as usize];
    let special_ctype = d.is_some_and(|d| d.flags() & core_locale::F_CTYPE_SPECIAL != 0);
    let collating = cats[LC_COLLATE as usize].is_some_and(|c| c.flags() & core_locale::F_PLAIN == 0);
    if d.is_some_and(|d| d.flags() & core_locale::F_WIDE_TABLES != 0) {
        core_locale::WIDE_SPECIAL.store(true, core::sync::atomic::Ordering::Release);
    }
    if d.is_some_and(|d| matches!(charset_of(d), Charset::Other)) {
        // the charset needs rusty-libc-iconv: hand rusty-libc-wchar its conversions (see rusty_libc_wchar::mbyte::set_other_hooks)
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

/// The wide compatibility tables (`__ctype32_b`, `__ctype32_tolower`, `__ctype32_toupper`) computed for one LC_CTYPE.
struct WideCompat {
    class: [u32; 256],
    lower: [u32; 384],
    upper: [u32; 384],
}

/// Tables computed for the LC_CTYPE data at `key` while data::FREED_GEN was `generation`.
struct WideCached {
    key: usize,
    generation: usize,
    tables: &'static mut WideCompat,
}

/// Number of LC_CTYPE data whose wide tables setlocale keeps (4 KiB each, allocated on first use, reused round robin).
const WIDE_CACHE: usize = 8;

/// The kept wide tables and the slot the next new data takes. Reached only by `refresh_wide_compat`, i.e. by setlocale
/// with LOCK held, so its own lock is never contended.
static WIDE_CACHED: Locked<([Option<WideCached>; WIDE_CACHE], usize)> = Locked::new(([const { None }; WIDE_CACHE], 0));

/// `__ctype32_b` and friends of the new global LC_CTYPE: the class bits (glibc's `_ISwbit` layout) and the case mappings of the
/// wide characters 0..255, from the wide functions of that locale. The built-in C locale restores the built-in tables.
fn refresh_wide_compat(ctype: Option<&'static CatData>) {
    // The LC_CTYPE data the tables were last computed from (null: none) and data::FREED_GEN at that time. Interned
    // locale data is not changed after it is published and not freed without bumping FREED_GEN, so the same pointer
    // and generation mean the same tables: programs such as bash call setlocale a dozen times at start-up with the same
    // locale, and the 3072 class tests below cost ~0.3M instructions each time. The class tests read the calling
    // thread's locale: a thread with its own locale (uselocale) always recomputes, as before. Only setlocale (with LOCK
    // held) gets here, so Relaxed is enough.
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
        // a switch back to an LC_CTYPE seen before (and not freed since) takes the tables kept for it (FIXLIST #129
        // follow-up: two locales in turn cost ~22k cycles per setlocale(LC_CTYPE), mostly the class tests)
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

/// The wide tables from the wide functions of the calling thread's locale.
fn compute_wide_compat(t: &mut WideCompat) {
    use rusty_libc_wchar::wctype::{class_by_name, in_class, to_lower, to_upper};
    // class names in glibc's bit order: upper lower alpha digit xdigit space print graph blank cntrl punct alnum
    const NAMES: [&[u8]; 12] = [b"upper", b"lower", b"alpha", b"digit", b"xdigit", b"space", b"print", b"graph", b"blank", b"cntrl", b"punct", b"alnum"];
    // (what wctype / iswctype / towlower / towupper return: their safe cores)
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
    // a new locale: let the message catalog functions know (glibc: ++_nl_msg_cat_cntr in setlocale)
    gettext::bump_cat_cntr();
}

/// The global data of category `cat` (not LC_ALL): what setlocale installed, or the built-in C data.
fn global_data(cat: usize) -> Option<&'static CatData> {
    if cat == LC_ALL as usize {
        return None;
    }
    Some(data::global_cat(cat).unwrap_or_else(|| data::builtin(false, cat)))
}

/// `setlocale(category, locale)`.
///
/// # Safety
/// `locale` is NULL or a valid C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if !(0..NCAT as c_int).contains(&category) {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    if locale.is_null() {
        // a racy read of the global names, like glibc's
        return g_name(category as usize) as *mut c_char;
    }
    // SAFETY: `locale` is a C string (the caller's contract), read for this call only.
    let arg = unsafe { ffi::cstr_bytes_scalar(locale) };
    // the setting path has a big stack frame (probed page by page): keep it out of the query path
    setlocale_set(category as usize, arg)
}

/// The setting half of `setlocale`: install `arg` for category `cat` (LC_ALL: all of them, or a composite name). Returns
/// the new name (owned by the library) or null with errno set.
#[inline(never)]
pub fn setlocale_set(cat: usize, arg: &[u8]) -> *mut c_char {
    let g = LOCK.guard();
    let _ = &g;
    let names = &G_NAMES;
    // SAFETY: a name in G_NAMES stays valid while LOCK is held (only setlocale replaces and frees them, under LOCK).
    if arg == unsafe { name_bytes(g_name(cat)) } {
        return g_name(cat) as *mut c_char; // changing to the same thing
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
            // a composite must name every category
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
        // (the names read in place: a copy of the 13 name buffers was 3.8 KB more of this frame, a stack page probed and
        // faulted in by every program's setlocale(LC_ALL, ""))
        let refs: [&[u8]; NCAT] = core::array::from_fn(|c| match &found[c] {
            Some(f) => f.name.as_bytes(),
            None => b"C",
        });
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
        // SAFETY: as above (LOCK is held).
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
    // the names after the change; glibc judges sameness against the new name
    // SAFETY: as above (LOCK is held for the life of `all`).
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
    // SAFETY: as above.
    gettext::note_messages_locale(unsafe { name_bytes(g_name(LC_MESSAGES as usize)) });
    newname as *mut c_char
}

/// The global LC_MESSAGES name (what `setlocale(LC_MESSAGES, NULL)` returns).
pub(crate) fn messages_name() -> &'static [u8] {
    // SAFETY: a global name stays valid until setlocale replaces it (a racy read, as glibc's catopen makes).
    unsafe { name_bytes(g_name(LC_MESSAGES as usize)) }
}

/// The data of category `cat` of locale `loc`; the built-in C data where none is installed.
fn cur_data(cat: usize, loc: Loc) -> &'static CatData {
    match data::locale_cat(loc, cat) {
        Some(d) => d,
        None => data::builtin(false, cat),
    }
}

/// localeconv's static result: overwritten by each call that finds other data in force (POSIX: localeconv need not be
/// thread-safe, and its result may be overwritten by a later call, as glibc's is). Written only by `localeconv`.
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

/// `localeconv()`: the numeric and monetary conventions of the current locale (one static result
/// that every call overwrites, like glibc's).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn localeconv() -> *const Lconv {
    // The result depends only on the two category data pointers in force, so the static is refilled
    // only when they changed since the last call (any thread; a changed pair refills it, like glibc's
    // refill on every call).
    let n = cur_data(LC_NUMERIC as usize, Loc::CURRENT);
    let m = cur_data(LC_MONETARY as usize, Loc::CURRENT);
    let (nk, mk) = (n as *const CatData as usize, m as *const CatData as usize);
    if LCONV_KEY[0].load(Ordering::Acquire) != nk || LCONV_KEY[1].load(Ordering::Acquire) != mk {
        refill_lconv(n, m);
    }
    LCONV.as_ptr()
}

/// Refill localeconv's static result from the data pair `n`, `m` (kept out of the fast path).
#[cold]
#[inline(never)]
fn refill_lconv(n: &'static CatData, m: &'static CatData) {
    // SAFETY: only localeconv writes LCONV; concurrent calls are outside POSIX's guarantees for localeconv (as in glibc,
    // which refills its static result on every call).
    unsafe { LCONV.write(lconv_from(n, m)) };
    LCONV_KEY[0].store(n as *const CatData as usize, Ordering::Release);
    LCONV_KEY[1].store(m as *const CatData as usize, Ordering::Release);
}

/// The category data pair LCONV was last filled from (0: not filled yet).
static LCONV_KEY: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// The numeric and monetary conventions of the locale `loc` as a `struct lconv` the caller owns. The strings point into
/// the locale's data, which lives forever.
pub fn lconv_of(loc: Loc) -> Lconv {
    lconv_from(cur_data(LC_NUMERIC as usize, loc), cur_data(LC_MONETARY as usize, loc))
}

fn lconv_from(n: &CatData, m: &CatData) -> Lconv {
    // a grouping that starts with CHAR_MAX (or 255) means "no grouping": ""
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

/// `nl_langinfo(item)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nl_langinfo(item: c_int) -> *const c_char {
    langinfo(item, Loc::CURRENT)
}

/// `nl_langinfo_l(item, locale)`.
///
/// # Safety
/// `loc` is LC_GLOBAL_LOCALE or a locale object from newlocale/duplocale, not freed (null is read as the calling
/// thread's locale).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo_l(item: c_int, loc: *mut LocaleStruct) -> *const c_char {
    // SAFETY: the caller's contract.
    langinfo(item, unsafe { Loc::from_raw(loc as usize) })
}

/// `nl_langinfo_l` on a checked locale argument: a string of the locale's data (or its name), "" for an unknown item.
pub fn langinfo(item: c_int, loc: Loc) -> *const c_char {
    let cat = (item >> 16) as usize;
    if item < 0 || cat >= NCAT || cat == LC_ALL as usize {
        return c"".as_ptr();
    }
    let index = (item & 0xffff) as usize;
    if index == 0xffff {
        // NL_LOCALE_NAME(category): the locale's name for the category
        return name_of(loc, cat).cast();
    }
    // (out of range: "")
    cur_data(cat, loc).cstr(index).cast()
}

/// The name of category `cat` of locale `loc`.
pub(crate) fn name_of(loc: Loc, cat: usize) -> *const u8 {
    let obj = if loc == Loc::CURRENT { core_locale::thread() as usize } else { loc.raw() };
    if obj == 0 || obj == LC_GLOBAL_LOCALE {
        // a racy read of the global names like glibc's
        return g_name(cat);
    }
    let l = obj as *const LocaleStruct;
    // SAFETY: a thread's locale object, or the object a `Loc` names, is a LocaleStruct from alloc_locale (or the C object),
    // alive while it is in use (the `Loc`'s contract; `set_thread`'s for the thread's, as in glibc).
    unsafe { (*l).names[cat].cast() }
}

/// glibc's `struct __locale_struct`: 13 data pointers, three ctype table pointers, 13 names (232
/// bytes). The data pointers are rusty-libc-core `CatData`; names live after the struct in the same
/// allocation (or are the static "C").
#[repr(C)]
pub struct LocaleStruct {
    locales: [*const CatData; NCAT],
    ctype_b: *const u16,
    ctype_tolower: *const i32,
    ctype_toupper: *const i32,
    names: [*const c_char; NCAT],
}

const LC_GLOBAL_LOCALE: usize = usize::MAX;

/// The static locale object of the C locale. Filled once under LOCK (before C_LOCOBJ_READY is set, Release); after that
/// only read.
static C_LOCOBJ: SyncCell<LocaleStruct> = SyncCell::new(LocaleStruct {
    locales: [core::ptr::null(); NCAT],
    ctype_b: core::ptr::null(),
    ctype_tolower: core::ptr::null(),
    ctype_toupper: core::ptr::null(),
    names: [core::ptr::null(); NCAT],
});
static C_LOCOBJ_READY: AtomicBool = AtomicBool::new(false);

fn fill_pointers(l: &mut LocaleStruct) {
    // SAFETY: a LocaleStruct's category pointers are null or published data (set from `Cats` by `alloc_locale`, or the
    // built-in data by `c_locobj`).
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

/// The static locale object of the C locale (what `newlocale(LC_ALL_MASK, "C", 0)` returns). `_g` is LOCK's guard.
#[inline]
fn c_locobj(_g: &Guard<'_>) -> *mut LocaleStruct {
    if !C_LOCOBJ_READY.load(Ordering::Acquire) {
        c_locobj_fill();
    }
    C_LOCOBJ.as_ptr()
}

/// Fill the C locale object (first use; LOCK is held).
#[cold]
#[inline(never)]
fn c_locobj_fill() {
    // building the compat tables may allocate (and a program's malloc may set errno, as glibc's test-strerror-errno does);
    // glibc's C object is static, so newlocale/duplocale of "C" never change errno
    let saved = errno::get();
    let mut l = LocaleStruct { locales: [core::ptr::null(); NCAT], ctype_b: core::ptr::null(), ctype_tolower: core::ptr::null(), ctype_toupper: core::ptr::null(), names: [core::ptr::null(); NCAT] };
    for c in 0..NCAT {
        if c != LC_ALL as usize {
            l.locales[c] = data::builtin(false, c);
            l.names[c] = C_NAME.as_ptr().cast();
        }
    }
    fill_pointers(&mut l);
    // SAFETY: LOCK is held by the caller of c_locobj (no other writer) and the object has not been handed out yet (READY
    // is false), so nothing reads it.
    unsafe { C_LOCOBJ.write(l) };
    C_LOCOBJ_READY.store(true, Ordering::Release);
    errno::set(saved);
}

/// A snapshot of locale `loc` (a locale object, LC_GLOBAL_LOCALE or null for the thread's). Callers hold LOCK (the names
/// stay valid while they are copied).
fn snapshot(loc: Loc) -> (Cats, [NameBuf; NCAT]) {
    let mut cats: Cats = [None; NCAT];
    let mut names = [NameBuf::new(b"C"); NCAT];
    for c in 0..NCAT {
        if c != LC_ALL as usize {
            cats[c] = Some(cur_data(c, loc));
            // SAFETY: the names of a live locale (or the global ones, under LOCK) are valid C strings.
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
    // SAFETY: the `total` bytes after the struct in the fresh block are ours alone.
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
    // SAFETY: the block starts with room for the struct, aligned (malloc gives 16), and is still ours alone.
    unsafe { p.write(l) };
    p
}

/// `newlocale(mask, locale, base)`: categories in `mask` get `locale`, the others come from `base`
/// ("C" if `base` is NULL). `base` is freed and a new object returned, as in glibc.
///
/// # Safety
/// `locale` is a valid C string; `base` is NULL, LC_GLOBAL_LOCALE or a locale_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn newlocale(mask: c_int, locale: *const c_char, base: *mut LocaleStruct) -> *mut LocaleStruct {
    const ALL: c_int = 0x1fbf; // LC_ALL_MASK: bits 0-5 and 7-12
    let mask = if mask == 1 << LC_ALL { ALL } else { mask };
    if mask & !ALL != 0 || locale.is_null() {
        errno::set(errno::EINVAL);
        return null_mut();
    }
    // SAFETY: `locale` is a C string (the caller's contract), read during this call.
    let arg = unsafe { ffi::cstr_bytes_scalar(locale) };
    // SAFETY: `base` is NULL, LC_GLOBAL_LOCALE or a locale_t the new object replaces (the caller's contract).
    unsafe { newlocale_core(mask, arg, base as usize) }
}

/// newlocale on a parsed name: the new object, or null with errno set.
///
/// # Safety
/// `base` is 0, LC_GLOBAL_LOCALE or a live locale_t; when a new object is returned, `base` (a locale_t) has been freed.
unsafe fn newlocale_core(mask: c_int, arg: &[u8], base: usize) -> *mut LocaleStruct {
    const ALL: c_int = 0x1fbf;
    let g = LOCK.guard();
    let cl = c_locobj(&g);
    let base = if base == cl as usize { 0 } else { base };
    if (base == 0 || mask == ALL) && (mask == 0 || arg == b"C") {
        return cl;
    }
    // SAFETY: the C object is static; `base` is LC_GLOBAL_LOCALE or a live locale object (the caller's contract).
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
        // SAFETY: `base` is a locale object from newlocale/duplocale that the new one replaces (the caller's contract).
        unsafe { mem::free(base as *mut LocaleStruct) };
    }
    r
}

/// `duplocale(locale)`.
///
/// # Safety
/// `loc` is LC_GLOBAL_LOCALE or a locale_t.
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
    // SAFETY: `loc` is LC_GLOBAL_LOCALE or a live locale object (the caller's contract; null was refused above).
    let (cats, names) = snapshot(unsafe { Loc::from_raw(loc as usize) });
    let refs: [&[u8]; NCAT] = core::array::from_fn(|c| names[c].as_bytes());
    alloc_locale(&cats, &refs)
}

/// `freelocale(locale)`.
///
/// # Safety
/// `loc` was returned by `newlocale` or `duplocale` and is not in use.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freelocale(loc: *mut LocaleStruct) {
    if !loc.is_null() && loc as usize != LC_GLOBAL_LOCALE {
        let g = LOCK.guard();
        if loc != c_locobj(&g) {
            // SAFETY: allocated by alloc_locale (the caller's contract) and not used again.
            unsafe { mem::free(loc) };
        }
    }
}

/// `uselocale(locale)`: set (or with NULL just query) the calling thread's locale; returns the
/// previous one (LC_GLOBAL_LOCALE if the thread used the global locale).
///
/// # Safety
/// `loc` is NULL, LC_GLOBAL_LOCALE or a locale_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uselocale(loc: *mut LocaleStruct) -> *mut LocaleStruct {
    let t = core_locale::thread();
    let old = if t.is_null() { LC_GLOBAL_LOCALE as *mut LocaleStruct } else { t as *mut LocaleStruct };
    if !loc.is_null() {
        if loc as usize == LC_GLOBAL_LOCALE {
            // SAFETY: null: back to the global locale.
            unsafe { core_locale::set_thread(core::ptr::null()) };
        } else {
            // SAFETY: `loc` is a locale_t (the contract): a LocaleStruct from `alloc_locale` (or the C object), whose first
            // NCAT words are null or published `&'static CatData`s; C forbids freeing it while it is in use.
            unsafe { core_locale::set_thread(loc as *const *const CatData) };
        }
    }
    old
}

#[cfg(test)]
mod tests;

// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__newlocale => newlocale);
// `__uselocale`: the old internal name of `uselocale`.
rusty_libc_core::tail_alias!(__uselocale => uselocale);
rusty_libc_core::tail_alias!(__duplocale => duplocale);
rusty_libc_core::tail_alias!(__freelocale => freelocale);
rusty_libc_core::tail_alias!(__nl_langinfo_l => nl_langinfo_l);
