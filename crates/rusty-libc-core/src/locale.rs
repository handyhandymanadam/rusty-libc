//! The current locale as the crates below rusty-libc-locale see it.
//!
//! rusty-libc-locale owns the locale objects (`setlocale`, `uselocale`, `newlocale`); printf, scanf,
//! strtod, strftime, strcoll and the wide character functions only need to know "what are the
//! decimal point, the day names, the collation tables right now". This module holds that: one
//! pointer per category for the process-wide locale and one pointer to the calling thread's
//! `locale_t` (set by `uselocale`). A reader costs one thread-local load and one atomic load.
//!
//! A category's data is a [`CatData`]: glibc's `struct __locale_data` reduced to what a reader
//! needs, a table of values indexed like `nl_langinfo` (a pointer to a NUL-terminated string, or a
//! 32-bit word for the numeric items). A `locale_t` object starts with 13 `*const CatData`, one
//! per category in glibc's category order (`LC_CTYPE` = 0 ... `LC_IDENTIFICATION` = 12); the
//! pointer may be null, which means the built-in C locale.
//!
//! Soundness (FIXLIST #103): a [`CatData`] can only be made with the unsafe [`CatData::new`], whose contract is that its tables
//! are valid and live for good; so a `&CatData` is proof enough for the safe readers ([`ctype_tables`], [`toupper_in`],
//! [`numeric_of`], ...), which take `Option<&CatData>` (None: the built-in C locale) instead of a raw pointer. The global
//! table holds such references ([`set_global`] is safe); a thread's locale object is a raw `locale_t`, so [`set_thread`] and
//! [`of_locale`] are unsafe fns whose callers vouch for it.
//!
//! What stays unsafe here: the locale tables are data rusty-libc-locale mapped from locale files or built in, reached through
//! raw pointers that live for the rest of the process (published data is never freed or changed). Their size is in the
//! tables themselves, not known up front, so the readers keep raw reads (one per block, at the indices the table's own
//! header bounds) instead of slices; they are on the hot paths of the wide character functions.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ptr::null;
use core::sync::atomic::{AtomicPtr, Ordering};

pub const LC_CTYPE: usize = 0;
pub const LC_NUMERIC: usize = 1;
pub const LC_TIME: usize = 2;
pub const LC_COLLATE: usize = 3;
pub const LC_MONETARY: usize = 4;
pub const LC_MESSAGES: usize = 5;
pub const LC_PAPER: usize = 7;
pub const LC_NAME: usize = 8;
pub const LC_ADDRESS: usize = 9;
pub const LC_TELEPHONE: usize = 10;
pub const LC_MEASUREMENT: usize = 11;
pub const LC_IDENTIFICATION: usize = 12;
/// Number of category slots (LC_ALL's slot 6 stays unused).
pub const NCAT: usize = 13;

/// `locale_t` value meaning "the global locale".
pub const LC_GLOBAL_LOCALE: usize = usize::MAX;

/// LC_NUMERIC: the decimal point is exactly ".".
pub const F_DOT: u32 = 1;
/// LC_NUMERIC: there is a thousands separator and a grouping rule (`'` flag has an effect).
pub const F_GROUP: u32 = 2;
/// LC_TIME and LC_COLLATE: the data is the C locale's (readers may use their built-in fast path).
pub const F_PLAIN: u32 = 4;
/// Data of the built-in C locale (any category): a few glibc quirks are tied to it.
pub const F_BUILTIN_C: u32 = 0x10;
/// LC_CTYPE: `aux` points at a [`CtypeTables`] (the locale file's single-byte tables).
pub const F_CTYPE_TABLES: u32 = 0x20;
/// LC_CTYPE: those tables differ from the C locale's (see [`CTYPE_SPECIAL`]).
pub const F_CTYPE_SPECIAL: u32 = 0x40;
/// LC_CTYPE: `aux` has wide tables (see [`WideTables`]).
pub const F_WIDE_TABLES: u32 = 0x80;
/// LC_CTYPE: bits 8..16 hold the character set code (see rusty-libc-wchar's `Charset`).
pub const F_CHARSET_SHIFT: u32 = 8;

/// The single-byte class and case tables of an LC_CTYPE category: pointers to the entry for
/// character 0 (valid for -128..=255), like glibc's `__ctype_b`, `__ctype_toupper`, `__ctype_tolower`.
#[repr(C)]
pub struct CtypeTables {
    pub class: *const u16,
    pub upper: *const i32,
    pub lower: *const i32,
    /// The wide character tables of the locale file, or null (built-in data).
    pub wide: *const WideTables,
}

/// The multi-level wide character tables of an LC_CTYPE category (glibc's `wctype_table_lookup`,
/// `wctrans_table_lookup` and `wcwidth_table_lookup` formats, see wctype/wchar-lookup.h, LGPL).
#[repr(C)]
pub struct WideTables {
    /// Bit tables by class in the order alnum, alpha, blank, cntrl, digit, graph, lower, print,
    /// punct, space, upper, xdigit.
    pub class: [*const u8; 12],
    pub toupper: *const u8,
    pub tolower: *const u8,
    pub width: *const u8,
    /// The map `to_inpunct` (ASCII digits and separators to the locale's own, as in fa_IR), or null if the locale has none.
    pub inpunct: *const u8,
}

/// Set once a locale with wide tables has been installed or created; until then rusty-libc-wchar uses
/// its built-in Unicode tables.
pub static WIDE_SPECIAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Set (never cleared) once a locale with wide tables was installed or a thread installed a locale object:
/// one flag for the fast paths of rusty-libc-wchar's classification, which read the process-wide charset until then.
pub static LOCALE_SLOW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// False while only the process-wide charset can matter to wide classification (no wide tables, no thread locale).
#[inline(always)]
pub fn locale_slow() -> bool {
    LOCALE_SLOW.load(Ordering::Relaxed)
}

/// True if some locale in use may have wide tables.
#[inline(always)]
pub fn wide_special() -> bool {
    WIDE_SPECIAL.load(Ordering::Relaxed)
}

/// The wide tables of LC_CTYPE data `d`.
#[inline]
pub fn wide_tables(d: Option<&CatData>) -> Option<&'static WideTables> {
    let t = ctype_tables(d)?;
    if t.wide.is_null() {
        None
    } else {
        // SAFETY: set at load time, lives forever and is never written again (`CatData::new`'s contract covers the tables).
        Some(unsafe { &*t.wide })
    }
}

/// Word `i` of a three-level table: the header (shift1, bound1, shift2, mask2, mask3), then the level-1 offsets.
///
/// # Safety
/// `t` is a table of a loaded locale and `i` an index its header allows (header words 0..5, level-1 entries below bound1,
/// or an offset the table itself holds).
#[inline(always)]
unsafe fn word(t: *const u32, i: usize) -> u32 {
    // SAFETY: caller's contract; tables are 4-byte aligned in the locale file and in the built-in data.
    let p = unsafe { t.add(i) };
    // SAFETY: as above: `p` is inside the table.
    unsafe { *p }
}

#[inline]
unsafe fn tab3(table: *const u8, wc: u32, shift3: bool) -> Option<*const u8> {
    // returns the address of the final entry for the 3-level layouts; for bit tables the word index is wc >> 5
    // (each `word`: header words 0..5 exist in every table, the caller's contract; a level-1 entry exists below bound1;
    // level-2 and level-3 offsets come from the table, which places them inside itself, and the indices are masked)
    let t = table as *const u32;
    // SAFETY: header word 0.
    let shift1 = unsafe { word(t, 0) };
    let index1 = wc >> shift1;
    // SAFETY: header word 1.
    if index1 >= unsafe { word(t, 1) } {
        return None;
    }
    // SAFETY: level-1 entry below bound1.
    let lookup1 = unsafe { word(t, 5 + index1 as usize) };
    if lookup1 == 0 {
        return None;
    }
    // SAFETY: header word 2.
    let shift2 = unsafe { word(t, 2) };
    // SAFETY: header word 3.
    let index2 = (wc >> shift2) & unsafe { word(t, 3) };
    // SAFETY: `lookup1` is the byte offset of a level-2 block inside the table.
    let lvl2 = unsafe { table.add(lookup1 as usize) } as *const u32;
    // SAFETY: `index2` is masked to the level-2 block's size.
    let lookup2 = unsafe { word(lvl2, index2 as usize) };
    if lookup2 == 0 {
        return None;
    }
    // SAFETY: header word 4.
    let mask3 = unsafe { word(t, 4) };
    let index3 = if shift3 { (wc >> 5) & mask3 } else { wc & mask3 };
    // SAFETY: `lookup2` is the offset of a level-3 block; `index3` is masked to its size.
    Some(unsafe { table.add(lookup2 as usize + index3 as usize * if shift3 { 4 } else { 1 }) })
}

/// glibc's `wctype_table_lookup`: is `wc` in the class bit table.
///
/// # Safety
/// `table` is a class table of a loaded locale.
pub unsafe fn class_lookup(table: *const u8, wc: u32) -> bool {
    // SAFETY: forwarded contract.
    match unsafe { tab3(table, wc, true) } {
        // SAFETY: `p` is a level-3 word of the table (tab3).
        Some(p) => (unsafe { core::ptr::read_unaligned(p as *const u32) } >> (wc & 31)) & 1 != 0,
        None => false,
    }
}

/// glibc's `wctrans_table_lookup`.
///
/// # Safety
/// `table` is a map table of a loaded locale.
pub unsafe fn trans_lookup(table: *const u8, wc: u32) -> u32 {
    // the reads as in `tab3` (same layout, an i32 difference at the end)
    let t = table as *const u32;
    // SAFETY: header word 0 (caller's contract: a table of a loaded locale).
    let index1 = wc >> unsafe { word(t, 0) };
    // SAFETY: header word 1.
    if index1 >= unsafe { word(t, 1) } {
        return wc;
    }
    // SAFETY: level-1 entry below bound1.
    let lookup1 = unsafe { word(t, 5 + index1 as usize) };
    if lookup1 == 0 {
        return wc;
    }
    // SAFETY: header word 2.
    let shift2 = unsafe { word(t, 2) };
    // SAFETY: header word 3.
    let index2 = (wc >> shift2) & unsafe { word(t, 3) };
    // SAFETY: `lookup1` is the byte offset of a level-2 block inside the table.
    let lvl2 = unsafe { table.add(lookup1 as usize) } as *const u32;
    // SAFETY: `index2` is masked to the level-2 block's size.
    let lookup2 = unsafe { word(lvl2, index2 as usize) };
    if lookup2 == 0 {
        return wc;
    }
    // SAFETY: header word 4.
    let index3 = wc & unsafe { word(t, 4) };
    // SAFETY: `lookup2` is the offset of a level-3 block of i32 differences.
    let lvl3 = unsafe { table.add(lookup2 as usize) } as *const u32;
    // SAFETY: `index3` is masked to the level-3 block's size.
    let d = unsafe { word(lvl3, index3 as usize) } as i32;
    wc.wrapping_add(d as u32)
}

/// The first and last index of the children (each `1 << shift` characters, `n` of them) of the block that starts at `base`
/// that hold characters of `lo..=hi`; `None` when none does.
#[inline]
fn child_span(base: u32, shift: u32, n: u32, lo: u32, hi: u32) -> Option<(u32, u32)> {
    if n == 0 || hi < base {
        return None;
    }
    let first = if lo > base { (lo - base).checked_shr(shift).unwrap_or(0) } else { 0 };
    let last = (hi - base).checked_shr(shift).unwrap_or(0).min(n - 1);
    if first > last { None } else { Some((first, last)) }
}

/// Calls `emit(lo, hi)` for every maximal run of characters of `lo..=hi` that are in the class bit table `table` (the
/// layout `class_lookup` reads), cut to that window, in increasing order. Walks the three levels, so a table costs time in
/// proportion to what it holds, not to the 0x110000 characters, and only the parts that can hold characters of the window
/// are read (a question about one character reads one word of each level).
///
/// # Safety
/// `table` is a class table of a loaded locale.
pub unsafe fn class_runs_in(table: *const u8, lo: u32, hi: u32, emit: &mut dyn FnMut(u32, u32)) {
    {
        let t = table as *const u32;
        // SAFETY: the five header words (caller's contract).
        let hdr = unsafe { *(t as *const [u32; 5]) };
        let [shift1, bound1, shift2, mask2, mask3] = hdr;
        let mut cur: Option<(u32, u32)> = None;
        let (wlo, whi) = (lo, hi);
        let put = |emit: &mut dyn FnMut(u32, u32), cur: &mut Option<(u32, u32)>, lo: u32, hi: u32| {
            let (lo, hi) = (lo.max(wlo), hi.min(whi));
            if lo > hi {
                return;
            }
            match cur {
                Some((_, last)) if *last + 1 == lo => *last = hi,
                _ => {
                    if let Some((a, b)) = cur.take() {
                        emit(a, b);
                    }
                    *cur = Some((lo, hi));
                }
            }
        };
        let Some((f1, e1)) = child_span(0, shift1, bound1, lo, hi) else { return };
        for i1 in f1..=e1 {
            // SAFETY: level-1 entry below bound1.
            let l1 = unsafe { word(t, 5 + i1 as usize) };
            if l1 == 0 {
                continue;
            }
            // SAFETY: `l1` is the offset of a level-2 block inside the table.
            let lvl2 = unsafe { table.add(l1 as usize) } as *const u32;
            let Some((f2, e2)) = child_span(i1 << shift1, shift2, mask2.wrapping_add(1), lo, hi) else { continue };
            for i2 in f2..=e2 {
                // SAFETY: a level-2 block has mask2 + 1 entries.
                let l2 = unsafe { word(lvl2, i2 as usize) };
                if l2 == 0 {
                    continue;
                }
                // SAFETY: `l2` is the offset of a level-3 block inside the table.
                let lvl3 = unsafe { table.add(l2 as usize) } as *const u32;
                let Some((f3, e3)) = child_span((i1 << shift1) + (i2 << shift2), 5, mask3.wrapping_add(1), lo, hi) else { continue };
                for i3 in f3..=e3 {
                    // SAFETY: a level-3 block has mask3 + 1 words.
                    let w3 = unsafe { lvl3.add(i3 as usize) };
                    // SAFETY: `w3` is inside the block (above).
                    let mut word = u64::from(unsafe { core::ptr::read_unaligned(w3) });
                    if word == 0 {
                        continue;
                    }
                    let base = (i1 << shift1) + (i2 << shift2) + (i3 << 5);
                    while word != 0 {
                        let tz = word.trailing_zeros();
                        let len = (word >> tz).trailing_ones();
                        put(emit, &mut cur, base + tz, base + tz + len - 1);
                        word &= !(((1u64 << len) - 1) << tz);
                    }
                }
            }
        }
        if let Some((a, b)) = cur {
            emit(a, b);
        }
    }
}

/// Calls `emit(wc, mapped)` for every character the map table `table` (the layout `trans_lookup` reads) changes.
///
/// # Safety
/// `table` is a map table of a loaded locale.
pub unsafe fn trans_changed(table: *const u8, emit: &mut dyn FnMut(u32, u32)) {
    {
        let t = table as *const u32;
        // SAFETY: the five header words (caller's contract).
        let hdr = unsafe { *(t as *const [u32; 5]) };
        let [shift1, bound1, shift2, mask2, mask3] = hdr;
        for i1 in 0..bound1 {
            // SAFETY: level-1 entry below bound1.
            let l1 = unsafe { word(t, 5 + i1 as usize) };
            if l1 == 0 {
                continue;
            }
            // SAFETY: `l1` is the offset of a level-2 block inside the table.
            let lvl2 = unsafe { table.add(l1 as usize) } as *const u32;
            for i2 in 0..=mask2 {
                // SAFETY: a level-2 block has mask2 + 1 entries.
                let l2 = unsafe { word(lvl2, i2 as usize) };
                if l2 == 0 {
                    continue;
                }
                // SAFETY: `l2` is the offset of a level-3 block inside the table.
                let lvl3 = unsafe { table.add(l2 as usize) } as *const i32;
                for i3 in 0..=mask3 {
                    // SAFETY: a level-3 block has mask3 + 1 entries.
                    let e3 = unsafe { lvl3.add(i3 as usize) };
                    // SAFETY: `e3` is inside the block (above).
                    let d = unsafe { core::ptr::read_unaligned(e3) };
                    if d != 0 {
                        let wc = (i1 << shift1) + (i2 << shift2) + i3;
                        emit(wc, wc.wrapping_add(d as u32));
                    }
                }
            }
        }
    }
}

/// glibc's `wcwidth_table_lookup`: 0xff means "not printable".
///
/// # Safety
/// `table` is the width table of a loaded locale.
pub unsafe fn width_lookup(table: *const u8, wc: u32) -> u8 {
    // SAFETY: forwarded contract.
    match unsafe { tab3(table, wc, false) } {
        // SAFETY: `p` is a level-3 byte of the table (tab3).
        Some(p) => unsafe { *p },
        None => 0xff,
    }
}

/// Set (and never cleared) once a locale whose single-byte tables differ from the C locale's has
/// been installed or created: until then `isalpha`, `toupper`, `strcasecmp` ... may use their fast
/// built-in ASCII tables.
pub static CTYPE_SPECIAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// True if the single-byte tables of some locale in use may differ from the C locale's.
#[inline(always)]
pub fn ctype_special() -> bool {
    CTYPE_SPECIAL.load(Ordering::Relaxed)
}

/// The tables of LC_CTYPE data `d` (None for the C locale or data without tables).
#[inline]
pub fn ctype_tables(d: Option<&CatData>) -> Option<&'static CtypeTables> {
    let d = d?;
    // SAFETY: `aux` is a CtypeTables that lives forever when the flag says so (`CatData::new`'s contract).
    if d.flags & F_CTYPE_TABLES != 0 { Some(unsafe { &*(d.aux as *const CtypeTables) }) } else { None }
}

/// Upper-case a byte (as an int in -128..=255; others unchanged) with the case table of LC_CTYPE data `d`.
#[inline]
pub fn toupper_in(d: Option<&CatData>, c: i32) -> i32 {
    if let Some(t) = ctype_tables(d)
        && (-128..=255).contains(&c)
    {
        // SAFETY: the table covers -128..=255 around `upper` (checked range).
        let e = unsafe { t.upper.offset(c as isize) };
        // SAFETY: `e` is an entry of the table.
        return unsafe { *e };
    }
    if (b'a' as i32..=b'z' as i32).contains(&c) { c - 32 } else { c }
}

/// Lower-case a byte with the case table of LC_CTYPE data `d`.
#[inline]
pub fn tolower_in(d: Option<&CatData>, c: i32) -> i32 {
    if let Some(t) = ctype_tables(d)
        && (-128..=255).contains(&c)
    {
        // SAFETY: the table covers -128..=255 around `lower` (checked range).
        let e = unsafe { t.lower.offset(c as isize) };
        // SAFETY: `e` is an entry of the table.
        return unsafe { *e };
    }
    if (b'A' as i32..=b'Z' as i32).contains(&c) { c + 32 } else { c }
}

/// One category of one locale. Made only by [`CatData::new`] (its fields are private: the readers trust them).
#[repr(C)]
pub struct CatData {
    /// Number of entries in `values`.
    nstrings: u32,
    /// `F_*` bits, category specific.
    flags: u32,
    /// One entry per item: a `*const u8` to a NUL-terminated string, or the word itself.
    values: *const usize,
    /// Category specific cache owned by rusty-libc-locale (parsed collation tables, era table).
    aux: *const u8,
}
// SAFETY: CatData is immutable once published, and what its pointers reach is too (never written or freed afterwards).
unsafe impl Sync for CatData {}
// SAFETY: as above: moving the record to another thread moves only pointers to immutable, never-freed data.
unsafe impl Send for CatData {}

impl CatData {
    /// Category data with `nstrings` values at `values`, the `F_*` bits `flags` and the category's cache `aux`.
    ///
    /// # Safety
    /// For the rest of the process (the data is never freed, and never changed once shared): `values` points to `nstrings`
    /// readable words (and to whatever more the maker keeps after them); each entry that a reader takes as a string (the
    /// string items: the readers' `idx` constants, `nl_langinfo`) is the address of a NUL-terminated string. If `flags` has
    /// [`F_CTYPE_TABLES`], `aux` points to a [`CtypeTables`] whose tables cover -128..=255 around their pointers and whose
    /// `wide` is null or a valid [`WideTables`]; for the other categories `aux` is what their owner (rusty-libc-locale)
    /// documents for that category.
    pub const unsafe fn new(nstrings: u32, flags: u32, values: *const usize, aux: *const u8) -> CatData {
        CatData { nstrings, flags, values, aux }
    }
    /// Number of entries.
    #[inline(always)]
    pub fn nstrings(&self) -> u32 {
        self.nstrings
    }
    /// The `F_*` bits.
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.flags
    }
    /// The values (see [`CatData::new`]).
    #[inline(always)]
    pub fn values(&self) -> *const usize {
        self.values
    }
    /// The category's cache (see [`CatData::new`]).
    #[inline(always)]
    pub fn aux(&self) -> *const u8 {
        self.aux
    }
    /// The string item `i` (empty if out of range), without the NUL.
    pub fn bytes(&self, i: usize) -> &'static [u8] {
        let p = self.cstr(i);
        // SAFETY: values point at NUL-terminated strings that live as long as the locale data (forever).
        // (Kept as its own loop, not ffi::cstr_bytes_scalar: through that #[inline] helper LLVM inlined locale::numeric_of
        // into printf's write_pieces and snprintf got 15% slower; measured on the U1 branch, bench/cover_bench.c.)
        let mut n = 0;
        loop {
            // SAFETY: bytes 0..n are not NUL, so byte n is still part of the string (at worst its NUL).
            let q = unsafe { p.add(n) };
            // SAFETY: as above.
            if unsafe { *q } == 0 {
                break;
            }
            n += 1;
        }
        // SAFETY: the `n` bytes before the NUL are readable and never change or go away (published locale data).
        unsafe { core::slice::from_raw_parts(p, n) }
    }
    /// Pointer to the NUL-terminated string item `i` ("" if out of range).
    pub fn cstr(&self, i: usize) -> *const u8 {
        if i >= self.nstrings as usize {
            return c"".as_ptr().cast();
        }
        // SAFETY: i is below `nstrings`, the length of `values`.
        let v = unsafe { self.values.add(i) };
        // SAFETY: as above.
        unsafe { *v as *const u8 }
    }
    /// The word item `i` (0 if out of range).
    pub fn word(&self, i: usize) -> u32 {
        if i >= self.nstrings as usize {
            return 0;
        }
        // SAFETY: i is below `nstrings`, the length of `values`.
        let v = unsafe { self.values.add(i) };
        // SAFETY: as above.
        unsafe { *v as u32 }
    }
    /// First byte of string item `i`: the "byte" items (week days, digits of the monetary format).
    pub fn byte(&self, i: usize) -> u8 {
        // SAFETY: cstr always points at least at a NUL.
        unsafe { *self.cstr(i) }
    }
}

/// Process-wide locale (what `setlocale` changed).
static GLOBAL: [AtomicPtr<CatData>; NCAT] = [const { AtomicPtr::new(core::ptr::null_mut()) }; NCAT];

/// The `locale_t` the calling thread installed with `uselocale` (its first 13 words are the
/// category pointers); null if the thread uses the global locale.
#[thread_local]
static THREAD: core::cell::Cell<*const *const CatData> = core::cell::Cell::new(null());

/// Install `data` as the global data of category `cat` (called by `setlocale`; None: the built-in C locale).
pub fn set_global(cat: usize, data: Option<&'static CatData>) {
    if cat < NCAT {
        GLOBAL[cat].store(data.map_or(core::ptr::null_mut(), |d| core::ptr::from_ref(d).cast_mut()), Ordering::Release);
    }
}

/// The global data of category `cat` (None: C locale), ignoring any thread locale.
#[inline]
pub fn global(cat: usize) -> Option<&'static CatData> {
    // SAFETY: the table holds null or `&'static CatData`s (`set_global`).
    unsafe { GLOBAL[cat].load(Ordering::Acquire).as_ref() }
}

/// Install the calling thread's locale object (null: back to the global locale).
///
/// # Safety
/// `locales` is null or a locale object that starts with [`NCAT`] pointers, each null or a `&'static CatData` (as
/// rusty-libc-locale's `newlocale` makes them), and it stays valid while it is installed (`freelocale` of the object in
/// use is undefined in C too).
pub unsafe fn set_thread(locales: *const *const CatData) {
    if !locales.is_null() {
        THREAD_USED.store(true, Ordering::Relaxed);
        LOCALE_SLOW.store(true, Ordering::Relaxed);
    }
    THREAD.set(locales);
}

/// Set once any thread has installed a locale object with `uselocale`: until then every reader can
/// skip the thread-local lookup.
pub static THREAD_USED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The calling thread's locale object, or null.
#[inline]
pub fn thread() -> *const *const CatData {
    if !THREAD_USED.load(Ordering::Relaxed) {
        return null();
    }
    THREAD.get()
}

/// Category `cat` (below [`NCAT`], else a panic) of the locale object `obj`.
///
/// # Safety
/// `obj` is a locale object as [`set_thread`] describes.
#[inline(always)]
unsafe fn object_cat(obj: *const *const CatData, cat: usize) -> Option<&'static CatData> {
    // SAFETY: a locale object starts with NCAT category pointers (the contract).
    let cats = unsafe { &*obj.cast::<[*const CatData; NCAT]>() };
    // SAFETY: each is null or a `&'static CatData` (the contract).
    unsafe { cats[cat].as_ref() }
}

/// The data of category `cat` in force for the calling thread (None: built-in C locale).
#[inline]
pub fn current(cat: usize) -> Option<&'static CatData> {
    cat_of_thread(thread(), cat)
}

/// [`current`] of two categories, with one look at the thread's locale (`THREAD_USED` is an atomic, so two calls of
/// [`current`] read it and the thread pointer twice).
#[inline]
pub fn current2(a: usize, b: usize) -> (Option<&'static CatData>, Option<&'static CatData>) {
    let t = thread();
    (cat_of_thread(t, a), cat_of_thread(t, b))
}

/// Category `cat` in force for a thread whose locale is `t`, a value [`thread`] returned (private: only such values reach
/// it).
#[inline(always)]
fn cat_of_thread(t: *const *const CatData, cat: usize) -> Option<&'static CatData> {
    if t.is_null() {
        global(cat)
    } else {
        // SAFETY: `t` came from `thread()`: a non-null thread locale was installed by `set_thread`, whose caller vouched
        // for it.
        unsafe { object_cat(t, cat) }
    }
}

/// The address of [`current`]'s data (null for the C locale): an identity for caches keyed by the locale in force.
#[inline]
pub fn current_key(cat: usize) -> usize {
    current(cat).map_or(0, |d| core::ptr::from_ref(d) as usize)
}

/// The data of category `cat` of a `locale_t` argument: `loc` is a locale object, LC_GLOBAL_LOCALE
/// (the global locale), or null (treated like the current locale, as a lenient reading).
///
/// # Safety
/// `loc` is 0, [`LC_GLOBAL_LOCALE`], or a locale object as [`set_thread`] describes (from `newlocale`/`duplocale`, not
/// freed).
#[inline]
pub unsafe fn of_locale(loc: usize, cat: usize) -> Option<&'static CatData> {
    if loc == 0 {
        current(cat)
    } else if loc == LC_GLOBAL_LOCALE {
        global(cat)
    } else {
        // SAFETY: `loc` is a locale object (the contract).
        unsafe { object_cat(loc as *const *const CatData, cat) }
    }
}

/// A locale argument checked at the C boundary (see [`Loc`]'s constructor): what safe code passes around instead of a raw
/// `locale_t`.
pub use rusty_libc_mem::hooks::Loc;

/// The data of category `cat` of locale `loc` (the calling thread's, the global one, or a locale object), None for the
/// built-in C locale.
#[inline]
pub fn loc_cat(loc: Loc, cat: usize) -> Option<&'static CatData> {
    // SAFETY: a `Loc` is 0, LC_GLOBAL_LOCALE or a live locale object (the contract of its only constructor).
    unsafe { of_locale(loc.raw(), cat) }
}

/// The numeric formatting rules in force.
#[derive(Clone, Copy)]
pub struct Numeric {
    pub decimal_point: &'static [u8],
    pub thousands_sep: &'static [u8],
    /// glibc's grouping string: bytes are group sizes; the last one repeats unless followed by
    /// CHAR_MAX (127 or 255) which ends grouping.
    pub grouping: &'static [u8],
    /// The decimal point and thousands separator as wide characters (0: none).
    pub decimal_wc: u32,
    pub thousands_wc: u32,
}

/// The C locale's rules.
pub const C_NUMERIC: Numeric = Numeric { decimal_point: b".", thousands_sep: b"", grouping: b"", decimal_wc: 46, thousands_wc: 0 };

/// The numeric rules of the category data `d` (None: C).
pub fn numeric_of(d: Option<&CatData>) -> Numeric {
    let Some(d) = d else {
        return C_NUMERIC;
    };
    Numeric { decimal_point: d.bytes(0), thousands_sep: d.bytes(1), grouping: d.bytes(2), decimal_wc: d.word(3), thousands_wc: d.word(4) }
}

/// The numeric rules in force for the calling thread.
#[inline]
pub fn numeric() -> Numeric {
    numeric_of(current(LC_NUMERIC))
}

/// The numeric rules of a `locale_t` argument.
///
/// # Safety
/// As [`of_locale`].
pub unsafe fn numeric_of_locale(loc: usize) -> Numeric {
    // SAFETY: forwarded contract.
    numeric_of(unsafe { of_locale(loc, LC_NUMERIC) })
}

/// True if the decimal point is "." in the data `d` (None: C), the only thing a plain `%f` needs.
#[inline]
pub fn numeric_dot(d: Option<&CatData>) -> bool {
    d.is_none_or(|d| d.flags & F_DOT != 0)
}

/// `wcscoll` with a locale argument (0: the locale in force).
pub type WColl = unsafe fn(a: *const u32, b: *const u32, loc: usize) -> i32;
/// `wcsxfrm` with a locale argument.
pub type WXfrm = unsafe fn(dest: *mut u32, src: *const u32, n: usize, loc: usize) -> usize;

static WCOLL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static WXFRM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static WCOLL_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Register the wide collation functions (rusty-libc-locale does this when it installs a locale with
/// collation rules); `wcscoll` and `wcsxfrm` call them from then on.
pub fn install_wide_collation(coll: WColl, xfrm: WXfrm) {
    WCOLL.store(coll as usize, Ordering::Release);
    WXFRM.store(xfrm as usize, Ordering::Release);
    WCOLL_ACTIVE.store(true, Ordering::Release);
}

/// The registered `wcscoll` function, once wide collation is active.
#[inline]
pub fn wide_coll() -> Option<WColl> {
    if !WCOLL_ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let f = WCOLL.load(Ordering::Acquire);
    // SAFETY: stored from a `WColl` fn pointer.
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, WColl>(f) }) }
}

/// The registered `wcsxfrm` function, once wide collation is active.
#[inline]
pub fn wide_xfrm() -> Option<WXfrm> {
    if !WCOLL_ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let f = WXFRM.load(Ordering::Acquire);
    // SAFETY: stored from a `WXfrm` fn pointer.
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, WXfrm>(f) }) }
}

/// Item indices inside the category data (glibc's `_NL_ITEM_INDEX` values).
pub mod idx {
    pub const DECIMAL_POINT: usize = 0;
    pub const THOUSANDS_SEP: usize = 1;
    pub const GROUPING: usize = 2;
    pub const DECIMAL_POINT_WC: usize = 3;
    pub const THOUSANDS_SEP_WC: usize = 4;

    pub const CTYPE_MB_CUR_MAX: usize = 13;
    pub const CTYPE_CODESET_NAME: usize = 14;
    pub const CTYPE_INDIGITS0_MB: usize = 20;
    pub const CTYPE_INDIGITS0_WC: usize = 31;
    pub const CTYPE_OUTDIGIT0_MB: usize = 41;
    pub const CTYPE_OUTDIGIT0_WC: usize = 51;

    pub const ABDAY_1: usize = 0;
    pub const DAY_1: usize = 7;
    pub const ABMON_1: usize = 14;
    pub const MON_1: usize = 26;
    pub const AM_STR: usize = 38;
    pub const PM_STR: usize = 39;
    pub const D_T_FMT: usize = 40;
    pub const D_FMT: usize = 41;
    pub const T_FMT: usize = 42;
    pub const T_FMT_AMPM: usize = 43;
    pub const ERA: usize = 44;
    pub const ERA_YEAR: usize = 45;
    pub const ERA_D_FMT: usize = 46;
    pub const ALT_DIGITS: usize = 47;
    pub const ERA_D_T_FMT: usize = 48;
    pub const ERA_T_FMT: usize = 49;
    pub const ERA_NUM_ENTRIES: usize = 50;
    pub const ERA_ENTRIES: usize = 51;
    pub const WABDAY_1: usize = 52;
    pub const WDAY_1: usize = 59;
    pub const WABMON_1: usize = 66;
    pub const WMON_1: usize = 78;
    pub const WAM_STR: usize = 90;
    pub const WD_T_FMT: usize = 92;
    pub const WERA_YEAR: usize = 96;
    pub const WERA_D_FMT: usize = 97;
    pub const WALT_DIGITS: usize = 98;
    pub const WERA_D_T_FMT: usize = 99;
    pub const WERA_T_FMT: usize = 100;
    pub const WEEK_NDAYS: usize = 101;
    pub const WEEK_1STDAY: usize = 102;
    pub const WEEK_1STWEEK: usize = 103;
    pub const FIRST_WEEKDAY: usize = 104;
    pub const FIRST_WORKDAY: usize = 105;
    pub const CAL_DIRECTION: usize = 106;
    pub const DATE_FMT: usize = 108;
    pub const ALTMON_1: usize = 111;
    pub const ABALTMON_1: usize = 135;
}

/// glibc's grouping iterator (stdio-common/grouping_iterator.c, LGPL): walks the digits of a number
/// from the left and says before which digit a thousands separator goes.
pub struct GroupIter {
    g: &'static [u8],
    pos: isize,
    in_group: u32,
    remaining: u32,
    non_repeating: u32,
    /// Number of separators the whole number gets.
    pub separators: u32,
}

impl Numeric {
    /// Start grouping a number of `digits` digits (no grouping when the rule says none).
    pub fn group_iter(&self, digits: usize) -> GroupIter {
        let g: &'static [u8] = self.grouping;
        let digits = digits as u32;
        let none = GroupIter { g, pos: 0, in_group: digits, remaining: digits, non_repeating: 0, separators: 0 };
        let at = |p: isize| -> i8 { g.get(p as usize).map_or(0, |&b| b as i8) };
        if digits <= 1 || at(0) == 127 || at(0) <= 0 {
            return none;
        }
        let (mut to_group, mut non_rep, mut groups, mut p) = (digits, 0u32, 0u32, 0isize);
        loop {
            non_rep += at(p) as u32;
            if to_group <= at(p) as u32 {
                break;
            }
            groups += 1;
            to_group -= at(p) as u32;
            p += 1;
            let nx = at(p);
            if nx == 127 || nx < 0 {
                break;
            } else if nx == 0 {
                p -= 1;
                non_rep -= at(p) as u32;
                let repeats = (to_group - 1) / at(p) as u32;
                groups += repeats;
                to_group -= repeats * at(p) as u32;
                break;
            }
        }
        GroupIter { g, pos: p, in_group: to_group, remaining: digits, non_repeating: non_rep, separators: groups }
    }
}

impl GroupIter {
    /// Advance past one digit; true if a separator goes in front of it.
    pub fn next_digit(&mut self) -> bool {
        self.remaining -= 1;
        if self.in_group > 0 {
            self.in_group -= 1;
            return false;
        }
        if self.remaining < self.non_repeating {
            self.pos -= 1;
        }
        let v = self.g.get(self.pos as usize).map_or(0, |&b| b as u32);
        self.in_group = v.wrapping_sub(1);
        true
    }
}

/// glibc's `__correctly_grouped_prefix` (stdlib/grouping.c, LGPL) for a digit text whose thousands
/// separators have been replaced by the single byte `,`: the length of the longest prefix of
/// `text` that obeys the grouping rule `grouping` (no grouping at all is allowed).
pub fn correctly_grouped_prefix(text: &[u8], grouping: &[u8]) -> usize {
    let g = |i: usize| -> i8 { grouping.get(i).map_or(0, |&b| b as i8) };
    let find_sep = |mut cp: isize| -> isize {
        while cp >= 0 && text[cp as usize] != b',' {
            cp -= 1;
        }
        cp
    };
    let mut end = text.len() as isize;
    while end >= 1 {
        let mut gp = 0usize;
        let mut cp = find_sep(end - 1);
        if cp < 0 {
            return end as usize;
        }
        if end - cp == g(gp) as isize + 1 {
            let new_end = cp;
            loop {
                gp += 1;
                if g(gp) == 0 {
                    gp -= 1;
                }
                cp -= 1;
                if g(gp) == 127 || g(gp) < 0 {
                    cp = find_sep(cp);
                    if cp < 0 {
                        return end as usize;
                    }
                } else {
                    let group_end = cp;
                    cp = find_sep(cp);
                    if cp < 0 && group_end - cp <= g(gp) as isize {
                        return end as usize;
                    }
                    if cp < 0 || group_end - cp != g(gp) as isize {
                        break;
                    }
                }
            }
            end = new_end;
        } else if end - cp > g(gp) as isize + 1 {
            end = cp + g(gp) as isize + 1;
        } else {
            end = cp;
        }
    }
    end.max(0) as usize
}
