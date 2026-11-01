//! Locale category data: interpreting a locale file image (from the archive, a directory file, or
//! the built-in tables) as a [`CatData`].
//!
//! A locale file image (glibc's format, read from the files on this machine and from
//! `locale/loadlocale.c`, LGPL): `u32 magic`, `u32 nstrings`, `u32 strindex[nstrings]` (byte
//! offsets from the start of the image), then the data. Item `i` is a NUL-terminated string at
//! `strindex[i]`, except for the "word" items, whose 32-bit value is stored (4-aligned) there.
use crate::builtin_tables as bt;
use crate::mem::{self, rd32};
use crate::mem::Published;
use rusty_libc_core::locale::{CatData, CtypeTables, Loc, WideTables, F_BUILTIN_C, F_CHARSET_SHIFT, F_CTYPE_SPECIAL, F_CTYPE_TABLES, F_WIDE_TABLES, F_DOT, F_GROUP, F_PLAIN, LC_COLLATE, LC_CTYPE, LC_NUMERIC, LC_TIME, NCAT};

/// glibc's `LIMAGIC(category)`.
pub fn magic(cat: usize) -> u32 {
    let c = cat as u32;
    match cat {
        LC_COLLATE => 0x2005_1014 ^ c,
        LC_CTYPE => 0x2009_0720 ^ c,
        _ => 0x2003_1115 ^ c,
    }
}

pub use bt::CODESET_IDX;

fn is_word(cat: usize, idx: usize) -> bool {
    bt::WORDS[cat].binary_search(&(idx as u16)).is_ok()
}

/// Entries remembered so far: one `CatData` per distinct image address (loading the same locale twice yields the same
/// pointer), in a hash table keyed by the image address ([`Cache`]): a fixed array of buckets, each a chain of entries
/// that only grows at its end. An entry is published by one compare-exchange on the empty link at the chain's end, so two
/// threads that intern at once (the built-in data is interned on first use without the locale lock) can neither
/// overwrite each other's entry nor keep two entries for one image (FIXLIST #108): the loser of a race at a link finds the
/// winner's entry there and, for the same image, returns it. Every image is remembered: the memory is bounded by the number
/// of distinct images, which stay mapped for good anyway (with a fixed-size cache, each load of an image beyond its end
/// allocated new data that was never freed: FIXLIST #111). A lookup walks one chain: about entries/512 links, where the
/// former single list of slots compared up to every entry (60,000 slot visits per setlocale with all 5287 archive
/// locales loaded: FIXLIST #122). (A fixed bucket array needs no resizing, the hard part of a lock-free hash table:
/// Herlihy and Shavit, The Art of Multiprocessor Programming, 13.3, p. 330; separate chaining, a new key checked against
/// its chain and then added to it: Weiss, Data Structures and Algorithm Analysis in C, 5.3, p. 191.)
/// Bumped (before the memory is released) by any code that frees a `CatData` this module published. Nothing frees one
/// (FIXLIST #111 was fixed by remembering every entry instead); the counter lets caches keyed by a `CatData` address
/// (setlocale's wide compatibility tables) notice a freed and reused address if a later change starts freeing entries.
pub static FREED_GEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Buckets of the global cache: 512 links, the 4 KiB the former first chunk of 512 slots took.
const CACHE: usize = 512;
static CACHE_SLOTS: Cache<CACHE> = Cache::new();

/// One cache entry: the image address it is keyed by, its data, and the next entry of its bucket (empty at the end).
/// Entries are leaked and never freed or changed after they are published.
struct Entry {
    key: usize,
    data: &'static CatData,
    next: Published<Entry>,
}

/// The intern cache: `B` buckets (a power of two), each the head link of a chain of [`Entry`]s.
pub(crate) struct Cache<const B: usize> {
    heads: [Published<Entry>; B],
}

impl<const B: usize> Cache<B> {
    pub(crate) const fn new() -> Self {
        const { assert!(B.is_power_of_two()) };
        Cache { heads: [const { Published::empty() }; B] }
    }

    /// The head link of the bucket of image address `key`: multiplicative (Fibonacci) hashing, the high bits of the key
    /// times 2^64 / golden ratio (Knuth, The Art of Computer Programming 3, 6.4, p. 528, on why low bits alone, as a
    /// power-of-two modulus takes them, are a poor hash of aligned addresses).
    #[inline]
    fn bucket(&self, key: usize) -> &Published<Entry> {
        let bits = B.trailing_zeros();
        let h = if bits == 0 { 0 } else { ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - bits)) as usize };
        &self.heads[h]
    }

    /// The number of entries in the whole table (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.chain_lengths().sum()
    }

    /// The length of each bucket's chain (tests).
    #[cfg(test)]
    fn chain_lengths(&self) -> impl Iterator<Item = usize> + '_ {
        self.heads.iter().map(|h| {
            let mut n = 0;
            let mut e = h.get();
            while let Some(x) = e {
                n += 1;
                e = x.next.get();
            }
            n
        })
    }

    /// The longest chain (tests).
    #[cfg(test)]
    pub(crate) fn longest(&self) -> usize {
        self.chain_lengths().max().unwrap_or(0)
    }
}

/// The global intern cache's entry count and longest chain (tests).
#[cfg(test)]
pub(crate) fn cache_stats() -> (usize, usize) {
    (CACHE_SLOTS.len(), CACHE_SLOTS.longest())
}

/// A `CatData` pointer that this library published (from [`intern`], kept in core's tables or in a `locale_t`) as the
/// reference it stands for; None for null.
///
/// # Safety
/// `p` is null or a pointer [`intern`] returned (published data is never freed and never changed after publication).
#[inline(always)]
pub(crate) unsafe fn published(p: *const CatData) -> Option<&'static CatData> {
    // SAFETY: the caller's contract: null or a live, immutable CatData.
    unsafe { p.as_ref() }
}

/// The data of category `cat` in force for the calling thread (core's `current`), None for the built-in C locale.
#[inline(always)]
pub(crate) fn current_cat(cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::current(cat)
}

/// The global data of category `cat` (core's `global`), None for the built-in C locale.
#[inline(always)]
pub(crate) fn global_cat(cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::global(cat)
}

/// The data of category `cat` of locale `loc` (core's `loc_cat`), None for the built-in C locale.
#[inline(always)]
pub(crate) fn locale_cat(loc: Loc, cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::loc_cat(loc, cat)
}

/// The whole file image a CatData was interned from (it stays mapped, or is a built-in static, for good).
#[inline]
pub(crate) fn image_of(d: &CatData) -> &'static [u8] {
    let n = d.nstrings() as usize;
    let extra = d.values().wrapping_add(n);
    // SAFETY: every CatData is made by `intern_in`, which allocates two words after the `n` values and stores the
    // image's address there and its length after it (the CatData was built before it could be shared).
    let p = unsafe { extra.read() } as *const u8;
    // SAFETY: as above, the second extra word.
    let len = unsafe { extra.wrapping_add(1).read() };
    // SAFETY: `len` bytes at `p` are the image, which is never unmapped or changed.
    unsafe { rusty_libc_core::ffi::bytes(p, len) }
}

/// The parsed collation tables of LC_COLLATE data `d` (None when it has no rules).
#[inline]
pub(crate) fn coll_tables(d: &CatData) -> Option<&'static crate::collate::CollTables> {
    // SAFETY: `intern_in` sets `aux` of LC_COLLATE data to null or to a CollTables it leaked (the callers pass LC_COLLATE
    // data: core's LC_COLLATE slots and a `locale_t`'s are filled only with data interned for LC_COLLATE).
    unsafe { d.aux().cast::<crate::collate::CollTables>().as_ref() }
}

/// The bytes of string item `i` of `d` from its start to the end of the image (the format stores no item lengths, so
/// the end of the image is the bound a table read can be checked against); empty for an item out of range.
#[inline]
pub(crate) fn item(d: &CatData, i: usize) -> &'static [u8] {
    let img = image_of(d);
    if i >= d.nstrings() as usize {
        return &[];
    }
    let off = (d.cstr(i) as usize).wrapping_sub(img.as_ptr() as usize);
    img.get(off..).unwrap_or(&[])
}

/// `b` as native-endian 32-bit words (its whole words); empty if `b` does not start 4-aligned (an invalid image: the
/// tables of locale files are aligned, as glibc reads them through `uint32_t *`).
#[inline]
pub(crate) fn as_u32(b: &'static [u8]) -> &'static [u32] {
    if !b.as_ptr().cast::<u32>().is_aligned() {
        return &[];
    }
    // SAFETY: the pointer is 4-aligned (checked), the `len / 4` words lie inside `b`, every bit pattern is a valid u32, and
    // the image is never written or unmapped.
    unsafe { rusty_libc_core::ffi::slice(b.as_ptr().cast::<u32>(), b.len() / 4) }
}

/// [`as_u32`] for signed words.
#[inline]
pub(crate) fn as_i32(b: &'static [u8]) -> &'static [i32] {
    if !b.as_ptr().cast::<i32>().is_aligned() {
        return &[];
    }
    // SAFETY: as in `as_u32`.
    unsafe { rusty_libc_core::ffi::slice(b.as_ptr().cast::<i32>(), b.len() / 4) }
}

/// The 16-bit word at `off` of `b` (native endianness, any alignment); 0 when it does not fit.
fn rd16(b: &[u8], off: usize) -> u16 {
    match b.get(off..off.wrapping_add(2)) {
        Some(w) => u16::from_ne_bytes([w[0], w[1]]),
        None => 0,
    }
}

/// Turn the image `img` of category `cat` into a CatData. None (and nothing allocated) if the image is not valid for the
/// category, like glibc's `_nl_intern_locale_data`. Safe to call from any thread at any time: threads that intern the same
/// image at once all get the one entry that was published first.
/// A built-in image gives the built-in data ([`builtin`], with its flags), also when the cache is full.
pub fn intern(cat: usize, img: &'static [u8]) -> Option<&'static CatData> {
    for utf8 in [false, true] {
        let b = bt::blob(utf8, cat);
        if !b.is_empty() && core::ptr::eq(b.as_ptr(), img.as_ptr()) {
            return Some(builtin(utf8, cat));
        }
    }
    intern_in(&CACHE_SLOTS, cat, img, 0)
}

/// The data that the chain starting at link `link` holds for the image at `key`, None when it holds none.
fn cached(mut link: &Published<Entry>, key: usize) -> Option<&'static CatData> {
    while let Some(e) = link.get() {
        if e.key == key {
            return Some(e.data);
        }
        link = &e.next;
    }
    None
}

/// Intern `img` (as [`intern`], with `extra` flag bits set before the data is published) in the cache `cache` (the global
/// [`CACHE_SLOTS`]; a test's own chain in the race tests).
pub(crate) fn intern_in<const B: usize>(cache: &Cache<B>, cat: usize, img: &'static [u8], extra: u32) -> Option<&'static CatData> {
    let ptr = img.as_ptr();
    let key = ptr as usize;
    let bucket = cache.bucket(key);
    if let Some(d) = cached(bucket, key) {
        return Some(d);
    }
    let len = img.len();
    if len < 8 || rd32(img, 0) != magic(cat) {
        return None;
    }
    let n = rd32(img, 4) as usize;
    if n < bt::NSTRINGS[cat] as usize || 8 + n * 4 >= len {
        return None;
    }
    // one block: the header, then the n values (as glibc's `struct __locale_data` with its `values[]`), then the image's
    // address and length (see `image_of`)
    const HDR: usize = core::mem::size_of::<CatData>();
    const { assert!(HDR % core::mem::size_of::<usize>() == 0) };
    let block = mem::calloc(1, HDR + (n + 2) * core::mem::size_of::<usize>());
    if block.is_null() {
        return None;
    }
    let values_ptr = block.wrapping_add(HDR).cast::<usize>();
    // SAFETY: the block holds the header and then `n + 2` zeroed, 16+HDR-aligned usize values; nobody else sees it yet.
    let words: &mut [usize] = unsafe { rusty_libc_core::ffi::slice_mut(values_ptr, n + 2) };
    let (values, extra_words) = words.split_at_mut(n);
    extra_words[0] = ptr as usize;
    extra_words[1] = len;
    let mut valid = true;
    for (i, v) in values.iter_mut().enumerate() {
        let off = rd32(img, 8 + i * 4) as usize;
        if off > len || is_word(cat, i) && (off % 4 != 0 || off + 4 > len) {
            valid = false;
            break;
        }
        *v = if is_word(cat, i) { rd32(img, off) as usize } else { ptr.wrapping_add(off) as usize };
    }
    if !valid {
        // SAFETY: the block is ours and not referenced after this.
        unsafe { mem::free(block) };
        return None;
    }
    // SAFETY: `values_ptr` has the `n` values just filled from the image, which is mapped (or built in) for good, as is the
    // block; the string items point into the image at offsets checked above, NUL-terminated as the locale file format makes
    // them; no flags and no `aux` yet.
    let plain = unsafe { CatData::new(n as u32, 0, values_ptr, core::ptr::null()) };
    let mut flags = compute_flags(cat, &plain, img) | extra;
    let mut aux: *const u8 = core::ptr::null();
    if cat == LC_CTYPE
        && let Some((t, special)) = ctype_tables(img)
    {
        if !t.wide.is_null() {
            flags |= F_WIDE_TABLES;
        }
        flags |= F_CTYPE_TABLES | if special { F_CTYPE_SPECIAL } else { 0 };
        aux = (t as *const CtypeTables).cast();
    }
    if cat == LC_COLLATE
        && let Some(t) = crate::collate::build_tables(&plain)
    {
        // (no memory: the data is not usable)
        let Some(t) = mem::leak(t) else {
            // SAFETY: the block is ours and not referenced after this.
            unsafe { mem::free(block) };
            return None;
        };
        aux = (t as *const crate::collate::CollTables).cast();
    }
    // SAFETY: as `plain`; with F_CTYPE_TABLES `aux` is the leaked CtypeTables of `ctype_tables` (its tables checked to fit the
    // image, `wide` null or leaked WideTables), for LC_COLLATE null or the leaked CollTables (`coll_tables` reads it).
    let head = unsafe { CatData::new(n as u32, flags, values_ptr, aux) };
    let d = block.cast::<CatData>();
    // SAFETY: the block starts with room for the header, aligned for it (malloc gives 16), and is still ours alone.
    unsafe { d.write(head) };
    // SAFETY: initialised just above; never freed or written again.
    let d: &'static CatData = unsafe { &*d };
    // Publish at the end of the bucket's chain. An entry another thread published meanwhile with data of the same image
    // wins: that data is returned, and this one, which nobody has seen, stays unused (leaked, as all CatData are kept: a
    // rare race, at most once per racing thread and image).
    // (no memory for the entry: the data is handed out uncached)
    let Some(entry) = mem::leak(Entry { key, data: d, next: Published::empty() }) else { return Some(d) };
    let entry: &'static Entry = entry;
    let mut link = bucket;
    loop {
        match link.publish(entry) {
            Ok(()) => return Some(d),
            Err(other) if other.key == key => return Some(other.data),
            Err(other) => link = &other.next,
        }
    }
}

/// The single-byte class and case tables of an LC_CTYPE image (items 0, 1 and 3: 384 u16 class words and two 384 int case
/// tables, entry 0 being character -128), and whether any entry differs from the C locale's. None if they do not fit.
fn ctype_tables(img: &'static [u8]) -> Option<(&'static CtypeTables, bool)> {
    let len = img.len();
    let off = |i: usize| rd32(img, 8 + i * 4) as usize;
    let (oc, ou, ol) = (off(0), off(1), off(3));
    if oc + 768 > len || ou + 1536 > len || ol + 1536 > len || oc % 2 != 0 || ou % 4 != 0 || ol % 4 != 0 {
        return None;
    }
    // special: any entry differs from the C locale's
    let (cc, cl, cu) = rusty_libc_ctype::c_tables();
    let special = (0..384usize).any(|i| {
        rd16(img, oc + 2 * i) != cc[i] || rd32(img, ol + 4 * i) as i32 != i32::from(cl[i]) || rd32(img, ou + 4 * i) as i32 != i32::from(cu[i])
    });
    // entry 128 is character 0 (the C tables are indexed from -128)
    let class = img[oc + 256..].as_ptr().cast::<u16>();
    let upper = img[ou + 512..].as_ptr().cast::<i32>();
    let lower = img[ol + 512..].as_ptr().cast::<i32>();
    let t = mem::leak(CtypeTables { class, upper, lower, wide: wide_tables(img) })?;
    Some((t, special))
}

/// The wide tables of an LC_CTYPE image: classes found by name in the class-name list, the two maps
/// by name in the map-name list, and the width table. Null if any is missing (the built-in
/// locales carry none); `to_inpunct` may be missing.
fn wide_tables(img: &'static [u8]) -> *const WideTables {
    let len = img.len();
    let item = |i: usize| -> Option<usize> {
        let o = rd32(img, 8 + i * 4) as usize;
        if o < len { Some(o) } else { None }
    };
    let word = |i: usize| item(i).filter(|o| o % 4 == 0 && o + 4 <= len).map(|o| rd32(img, o) as usize);
    let (Some(class_names), Some(map_names), Some(width), Some(coff), Some(moff)) = (item(10), item(11), item(12), word(17), word(18)) else { return core::ptr::null() };
    // the up to 20 names of a NUL-separated list that ends with an empty name
    let names = |start: usize| -> [Option<&[u8]>; 20] {
        let mut out = [None; 20];
        let mut p = start;
        let mut k = 0;
        while p < len && img[p] != 0 && k < 20 {
            let mut e = p;
            while e < len && img[e] != 0 {
                e += 1;
            }
            out[k] = Some(&img[p..e]);
            k += 1;
            p = e + 1;
        }
        out
    };
    let find = |list: &[Option<&[u8]>; 20], want: &[u8]| -> Option<usize> {
        for (i, s) in list.iter().enumerate() {
            if (*s)? == want {
                return Some(i);
            }
        }
        None
    };
    let cl = names(class_names);
    let mp = names(map_names);
    const ORDER: [&[u8]; 12] = [b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower", b"print", b"punct", b"space", b"upper", b"xdigit"];
    let tab = |idx: usize| -> Option<*const u8> {
        let o = item(idx)?;
        if o % 4 == 0 && o + 20 <= len { Some(img[o..].as_ptr()) } else { None }
    };
    let mut class = [core::ptr::null::<u8>(); 12];
    for (k, name) in ORDER.iter().enumerate() {
        let Some(i) = find(&cl, name) else { return core::ptr::null() };
        let Some(t) = tab(coff + i) else { return core::ptr::null() };
        class[k] = t;
    }
    let (Some(iu), Some(il)) = (find(&mp, b"toupper"), find(&mp, b"tolower")) else { return core::ptr::null() };
    let (Some(tu), Some(tl)) = (tab(moff + iu), tab(moff + il)) else { return core::ptr::null() };
    let tw = img[width..].as_ptr();
    // (the map is optional: only locales with their own digits define it)
    let inpunct = find(&mp, b"to_inpunct").and_then(|i| tab(moff + i)).unwrap_or(core::ptr::null());
    match mem::leak(WideTables { class, toupper: tu, tolower: tl, width: tw, inpunct }) {
        Some(w) => w,
        None => core::ptr::null(),
    }
}

/// Charset codes carried in LC_CTYPE's flags. 0 and 1 are the two the wide character functions
/// know natively; single-byte sets are numbered by rusty-libc-locale's table (see `charsets`).
pub fn charset_code(codeset: &[u8]) -> u8 {
    if let Some(c) = crate::charsets::code_of_other(codeset) {
        return c;
    }
    crate::charsets::code_of(codeset)
}

/// The flag bits for a freshly interned category (see rusty-libc-core's `locale` module); `img` is its image.
fn compute_flags(cat: usize, d: &CatData, img: &[u8]) -> u32 {
    match cat {
        LC_NUMERIC => {
            let mut f = 0;
            if d.bytes(0) == b"." {
                f |= F_DOT;
            }
            let g = d.bytes(2);
            if !d.bytes(1).is_empty() && !g.is_empty() && g[0] != 127 && g[0] != 255 && g[0] != 0 {
                f |= F_GROUP;
            }
            f
        }
        LC_TIME => {
            // plain: identical to the C locale's data, so strftime may use its built-in names
            let c = builtin_blob(false, LC_TIME);
            if same_items(c, d, img) { F_PLAIN } else { 0 }
        }
        LC_COLLATE => {
            if d.word(0) == 0 {
                F_PLAIN
            } else {
                0
            }
        }
        LC_CTYPE => (charset_code(d.bytes(CODESET_IDX[LC_CTYPE])) as u32) << F_CHARSET_SHIFT,
        _ => 0,
    }
}

/// True if every item the C locale's LC_TIME data has holds the same value in `d` (interned from the image `img`).
fn same_items(c: &[u8], d: &CatData, img: &[u8]) -> bool {
    let cn = rd32(c, 4) as usize;
    if (d.nstrings() as usize) < cn {
        return false;
    }
    for i in 0..cn {
        let off = rd32(c, 8 + i * 4) as usize;
        if is_word(LC_TIME, i) {
            if rd32(c, off) != d.word(i) {
                return false;
            }
            continue;
        }
        // the string items of `d` point into its image at its own offsets
        let doff = rd32(img, 8 + i * 4) as usize;
        if bt::WIDE[LC_TIME].binary_search(&(i as u16)).is_ok() {
            // wide strings: NUL-terminated u32 sequences
            let mut k = 0;
            loop {
                let b = rd32(img, doff + k * 4);
                if rd32(c, off + k * 4) != b {
                    return false;
                }
                if b == 0 {
                    break;
                }
                k += 1;
            }
        } else if mem::cstr_at(img, doff) != mem::cstr_at(c, off) {
            return false;
        }
    }
    true
}

pub fn builtin_blob(utf8: bool, cat: usize) -> &'static [u8] {
    bt::blob(utf8, cat)
}

static BUILTIN: [[Published<CatData>; NCAT]; 2] = [[const { Published::empty() }; NCAT], [const { Published::empty() }; NCAT]];

/// The built-in C (`utf8` false) or C.UTF-8 data of a category: one CatData for the whole run. Any thread, any time (the
/// C locale functions reach it without the locale lock).
#[inline]
pub fn builtin(utf8: bool, cat: usize) -> &'static CatData {
    match BUILTIN[utf8 as usize][cat].get() {
        Some(d) => d,
        None => builtin_first(utf8, cat),
    }
}

/// The first use of a built-in category: intern it (with F_BUILTIN_C for the C data) and fill its slot; when threads race,
/// the first to fill the slot wins and all return its data (FIXLIST #108).
#[cold]
#[inline(never)]
fn builtin_first(utf8: bool, cat: usize) -> &'static CatData {
    let b = bt::blob(utf8, cat);
    let d = intern_in(&CACHE_SLOTS, cat, b, if utf8 { 0 } else { F_BUILTIN_C }).expect("built-in locale data is valid");
    match BUILTIN[utf8 as usize][cat].publish(d) {
        Ok(()) => d,
        Err(first) => first,
    }
}
