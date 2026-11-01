//! The gettext family: `gettext`, `dgettext`, `dcgettext`, `ngettext`, `dngettext`, `dcngettext`,
//! `textdomain`, `bindtextdomain`, `bind_textdomain_codeset`.
//!
//! Message catalogs are GNU `.mo` files (format of glibc's `intl/gmo.h` and `loadmsgcat.c`, LGPL,
//! which also give the lookup rules implemented here): `/usr/share/locale/<locale>/LC_MESSAGES/
//! <domain>.mo`. The language list is the locale name of the category, or the `LANGUAGE`
//! variable's colon separated list unless the locale is C or C.<charset>; every entry is expanded
//! as an alias and tried in its generalisations (the codeset, then the territory, then the modifier
//! dropped). A translation that is in another charset than the locale's (or `OUTPUT_CHARSET`, or
//! the `bind_textdomain_codeset` charset) is converted through rusty-libc-iconv with transliteration.
//!
//! Memory: catalogs are mapped for good and parsed on slices of the mapping; the caches (known translations, loaded
//! catalogs, conversions) are lists of nodes that are never freed, linked through `&'static` references once built.
//! Everything that changes after it is published is changed under STATE (atomics where readers may look without it).
use crate::find;
use crate::mem::{self, rd32};
use crate::plural::{self, Plural};
use core::ffi::{c_char, c_int, c_ulong};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::locale as core_locale;
use rusty_libc_core::sync_cell::SyncCell;

const LC_MESSAGES: usize = 5;
const LC_ALL: c_int = 6;
const NLS_MAGIC: u32 = 0x9504_12de;
const NLS_MAGIC_SWAPPED: u32 = 0xde12_0495;
const SEGMENTS_END: u32 = !0;
/// glibc's `_nl_default_dirname` (exported, GLIBC_2.2.5): where catalogs are looked for when a domain has no binding.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _nl_default_dirname: [u8; 18] = *b"/usr/share/locale\0";
/// The library's own copy, which bindings to the default directory point at: glibc's code uses a hidden alias, so a program
/// that copy-relocates `_nl_default_dirname` sees a different address there, as here.
static DEFAULT_DIRNAME_OWN: [u8; 18] = *b"/usr/share/locale\0";
const DEFAULT_DIRNAME: &[u8] = &DEFAULT_DIRNAME_OWN;
const DEFAULT_DOMAIN: &[u8] = b"messages\0";

static STATE: RawMutex = RawMutex::new();
/// glibc's `_nl_msg_cat_cntr`: bumped when anything that could change a translation changed (a successful
/// `setlocale`, every successful `textdomain`, a modified `bindtextdomain` / `bind_textdomain_codeset`); the
/// translations found earlier are only reused while it is unchanged. Changed under STATE.
static CATALOG_COUNTER: AtomicU32 = AtomicU32::new(0);

fn counter() -> u32 {
    CATALOG_COUNTER.load(Ordering::Relaxed)
}

/// One more change (callers hold STATE).
fn bump_counter() {
    CATALOG_COUNTER.store(counter().wrapping_add(1), Ordering::Relaxed);
}

/// Tell the message functions that the locale changed (called by `setlocale`).
pub(crate) fn note_locale_changed() {
    let _g = STATE.guard();
    bump_counter();
}

/// The bytes of a C string the gettext state holds (a domain name, a binding's directory or codeset).
///
/// # Safety
/// `p` points to a NUL-terminated string that stays valid for `'a` (the state's strings are freed only under STATE, when
/// replaced, so a caller holding STATE may read them).
#[inline]
unsafe fn state_str<'a>(p: *const u8) -> &'a [u8] {
    // SAFETY: the caller's contract.
    unsafe { ffi::cstr_bytes_scalar(p) }
}

/// A translation found at some time (glibc's `known_translation_t`): glibc returns it again without looking at
/// the catalogs or at LANGUAGE while `counter` is the current one. Keyed by domain, message id, category and
/// the locale name of the category. Never freed; the atomics are changed under STATE.
struct Known {
    next: Option<&'static Known>,
    domainname: &'static [u8],
    msgid: &'static [u8],
    localename: &'static [u8],
    category: c_int,
    counter: AtomicU32,
    domain: AtomicPtr<Domain>,
    translation: AtomicPtr<u8>,
    length: AtomicUsize,
}
const KNOWN_BUCKETS: usize = 512;
/// Bucket heads: null or a node leaked by `remember` (changed under STATE).
static KNOWN: [AtomicPtr<Known>; KNOWN_BUCKETS] = [const { AtomicPtr::new(null_mut()) }; KNOWN_BUCKETS];

fn known_bucket(msgid: &[u8], category: c_int) -> usize {
    let mut h: u32 = 0x811c_9dc5 ^ category as u32;
    for &b in msgid {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    h as usize % KNOWN_BUCKETS
}

fn known_head(bucket: usize) -> Option<&'static Known> {
    // SAFETY: KNOWN holds null or nodes leaked by `remember`, never freed or moved.
    unsafe { KNOWN[bucket].load(Ordering::Acquire).as_ref() }
}

fn known_find(dname: &[u8], msgid: &[u8], category: c_int, localename: &[u8]) -> Option<&'static Known> {
    let mut k = known_head(known_bucket(msgid, category));
    while let Some(n) = k {
        if n.category == category && n.msgid == msgid && n.domainname == dname && n.localename == localename {
            return Some(n);
        }
        k = n.next;
    }
    None
}

/// A malloc'd copy of `s` (with a NUL after it) that is never freed, as a slice without the NUL.
fn leak_bytes(s: &[u8]) -> Option<&'static [u8]> {
    let p = mem::dup_cstr(s);
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` holds a copy of `s` (then a NUL) that is never freed or written again.
    Some(unsafe { ffi::bytes(p, s.len()) })
}

/// The symbolic name of a category (glibc's `category_to_name`).
fn category_name(category: c_int) -> &'static [u8] {
    match category {
        0 => b"LC_CTYPE",
        1 => b"LC_NUMERIC",
        2 => b"LC_TIME",
        3 => b"LC_COLLATE",
        4 => b"LC_MONETARY",
        5 => b"LC_MESSAGES",
        7 => b"LC_PAPER",
        8 => b"LC_NAME",
        9 => b"LC_ADDRESS",
        10 => b"LC_TELEPHONE",
        11 => b"LC_MEASUREMENT",
        12 => b"LC_IDENTIFICATION",
        _ => b"LC_UNKNOWN",
    }
}
/// The default domain: DEFAULT_DOMAIN or a malloc'd name. Changed under STATE; `textdomain(NULL)` reads it without.
static CURRENT_DOMAIN: AtomicPtr<u8> = AtomicPtr::new(DEFAULT_DOMAIN.as_ptr().cast_mut());
/// glibc's `_nl_domain_bindings` (exported, GLIBC_2.2.5): the `bindtextdomain` list, sorted by domain name, in glibc's
/// `struct binding` layout (an `AtomicPtr` has the layout of the pointer). Changed only under STATE.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _nl_domain_bindings: AtomicPtr<Binding> = AtomicPtr::new(null_mut());

/// glibc's `_nl_msg_cat_cntr`: counts the changes that make cached translations stale (a new default
/// domain, a changed binding, a successful `setlocale`). Programs that cache translations themselves
/// (KDE's i18n, rpm) compare it to the value they saw. (An `AtomicI32` has the layout of `int`.)
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _nl_msg_cat_cntr: AtomicI32 = AtomicI32::new(0);

/// Count one change of the catalogs.
pub(crate) fn bump_cat_cntr() {
    // a plain counter: callers hold no lock, but a lost increment only delays a cache flush (a load and a store, as
    // glibc's `++_nl_msg_cat_cntr`)
    _nl_msg_cat_cntr.store(_nl_msg_cat_cntr.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
}

/// Loaded catalogs by path (never freed; the head changes under STATE).
struct Loaded {
    next: Option<&'static Loaded>,
    path: &'static [u8],
    domain: Option<&'static Domain>,
}
static LOADED: AtomicPtr<Loaded> = AtomicPtr::new(null_mut());

/// glibc's `struct binding` (gettextP.h): next, dirname, codeset, then the domain name inline. The pointer fields are
/// atomics (the layout of plain pointers) because nodes are linked and changed in place under STATE while programs may
/// read the exported list.
#[repr(C)]
pub struct Binding {
    next: AtomicPtr<Binding>,
    dirname: AtomicPtr<u8>,
    codeset: AtomicPtr<u8>,
    domainname: [u8; 0],
}

/// A node of the binding list (made by `set_binding_values` and never freed).
#[derive(Clone, Copy)]
struct BindingRef(core::ptr::NonNull<Binding>);

impl BindingRef {
    /// The node `p` points to, None for null.
    ///
    /// # Safety
    /// `p` is null or a node of the binding list (it keeps the provenance of its whole allocation, name included).
    unsafe fn new(p: *mut Binding) -> Option<BindingRef> {
        core::ptr::NonNull::new(p).map(BindingRef)
    }
    fn first() -> Option<BindingRef> {
        // SAFETY: the list head is null or a node.
        unsafe { BindingRef::new(_nl_domain_bindings.load(Ordering::Acquire)) }
    }
    fn get(self) -> &'static Binding {
        // SAFETY: nodes are never freed; their fields are atomics, so a shared reference is all anyone needs.
        unsafe { self.0.as_ref() }
    }
    fn next(self) -> Option<BindingRef> {
        // SAFETY: a node's `next` is null or a node.
        unsafe { BindingRef::new(self.get().next.load(Ordering::Acquire)) }
    }
    /// The domain name stored after the fixed part.
    fn domain(self) -> &'static [u8] {
        let name = self.0.as_ptr().cast::<u8>().wrapping_add(core::mem::offset_of!(Binding, domainname));
        // SAFETY: `set_binding_values` writes the NUL-terminated name there and never changes it; the node is never freed.
        unsafe { ffi::cstr_bytes_scalar(name) }
    }
    fn as_ptr(self) -> *mut Binding {
        self.0.as_ptr()
    }
}

/// A converted copy of a catalog's translations, for one output charset (never freed).
struct Conversion {
    next: Option<&'static Conversion>,
    encoding: &'static [u8],
    /// Changed only under STATE.
    st: SyncCell<ConvState>,
}

struct ConvState {
    /// Per string index (originals first, then system dependent ones): the converted translation
    /// (pointer and length including the NULs), or null if not converted yet.
    ptrs: Option<&'static mut [Option<core::ptr::NonNull<u8>>]>,
    lens: Option<&'static mut [usize]>,
    /// -1: not tried, 0: no conversion needed, 1: converters in `dec` and `enc`, -2: cannot convert.
    mode: i32,
    /// catalog charset to UCS-4
    dec: Option<rusty_libc_iconv::Converter>,
    /// UCS-4 to the output charset (without //TRANSLIT: transliteration is done here with the locale's tables)
    enc: Option<rusty_libc_iconv::Converter>,
}

/// A system dependent string pair of a revision 1 catalog: the original with its NUL (and any plural original after an
/// inner NUL), the translation without its final NUL.
#[derive(Clone, Copy)]
struct Sysdep {
    orig: &'static [u8],
    trans: &'static [u8],
}

struct Domain {
    data: &'static [u8],
    swap: bool,
    nstrings: u32,
    orig_off: usize,
    trans_off: usize,
    hash_size: u32,
    /// Offset of the hash table (None: no table).
    hash_off: Option<usize>,
    sysdep: &'static [Sysdep],
    plural: Plural,
    nplurals: u64,
    /// List head: null or a node leaked by `find_msg` (changed under STATE).
    conversions: AtomicPtr<Conversion>,
}

impl Domain {
    fn conversions(&self) -> Option<&'static Conversion> {
        // SAFETY: null or a node leaked by `find_msg`, never freed.
        unsafe { self.conversions.load(Ordering::Acquire).as_ref() }
    }
    fn word(&self, off: usize) -> u32 {
        w(self.swap, rd32(self.data, off))
    }
}

fn w(swap: bool, x: u32) -> u32 {
    if swap { x.swap_bytes() } else { x }
}

/// glibc's `__hash_string` (hashpjw).
fn hash_string(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in s {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & (0xf << 28);
        if g != 0 {
            h ^= g >> 24;
            h ^= g;
        }
    }
    h
}

/// The system dependent segment strings msgfmt can ask for (the `PRI*` macros of inttypes.h).
fn sysdep_value(name: &[u8]) -> Option<&'static [u8]> {
    if !name.starts_with(b"PRI") || name.len() < 5 {
        return None;
    }
    let conv = name[3];
    if !matches!(conv, b'd' | b'i' | b'o' | b'u' | b'x' | b'X') {
        return None;
    }
    let rest = &name[4..];
    // x86-64: 8, 16, 32 bit (and the LEAST/FAST forms of those) use the plain conversion; 64 bit, MAX and PTR use `l`
    let long = match rest {
        b"8" | b"16" | b"32" | b"LEAST8" | b"LEAST16" | b"LEAST32" | b"FAST8" => false,
        b"64" | b"LEAST64" | b"FAST16" | b"FAST32" | b"FAST64" | b"MAX" | b"PTR" => true,
        _ => return None,
    };
    let (plain, longer): (&'static [u8], &'static [u8]) = match conv {
        b'd' => (b"d", b"ld"),
        b'i' => (b"i", b"li"),
        b'o' => (b"o", b"lo"),
        b'u' => (b"u", b"lu"),
        b'x' => (b"x", b"lx"),
        _ => (b"X", b"lX"),
    };
    Some(if long { longer } else { plain })
}

/// Load (and cache) the `.mo` file at `path` (NUL-terminated). None if there is none or it is invalid. Callers hold STATE.
fn load_domain(path: &[u8]) -> Option<&'static Domain> {
    let name = &path[..path.len() - 1];
    // SAFETY: LOADED holds null or a node leaked below, never freed.
    let mut l = unsafe { LOADED.load(Ordering::Acquire).as_ref() };
    while let Some(n) = l {
        if n.path == name {
            return n.domain;
        }
        l = n.next;
    }
    let domain = read_domain(path);
    // SAFETY: as above.
    let head = unsafe { LOADED.load(Ordering::Acquire).as_ref() };
    if let Some(p) = leak_bytes(name)
        && let Some(node) = mem::leak(Loaded { next: head, path: p, domain })
    {
        LOADED.store(node, Ordering::Release);
    }
    domain
}

fn read_domain(path: &[u8]) -> Option<&'static Domain> {
    let data = crate::archive::map_file(path, None)?;
    let size = data.len();
    if size < 48 {
        return None;
    }
    let magic = rd32(data, 0);
    if magic != NLS_MAGIC && magic != NLS_MAGIC_SWAPPED {
        return None;
    }
    let swap = magic != NLS_MAGIC;
    let revision = w(swap, rd32(data, 4));
    if revision >> 16 > 1 {
        return None;
    }
    let nstrings = w(swap, rd32(data, 8));
    let orig_off = w(swap, rd32(data, 12)) as usize;
    let trans_off = w(swap, rd32(data, 16)) as usize;
    let hash_size = w(swap, rd32(data, 20));
    let hash_off = w(swap, rd32(data, 24)) as usize;
    // the tables must lie inside the file
    let fits = |off: usize, n: usize| off.checked_add(n).is_some_and(|e| e <= size);
    if !fits(orig_off, nstrings as usize * 8) || !fits(trans_off, nstrings as usize * 8) {
        return None;
    }
    let hash_off = if hash_size > 2 {
        if !fits(hash_off, hash_size as usize * 4) {
            return None;
        }
        Some(hash_off)
    } else {
        None
    };
    let mut d = Domain {
        data,
        swap,
        nstrings,
        orig_off,
        trans_off,
        hash_size,
        hash_off,
        sysdep: &[],
        plural: Plural::germanic(),
        nplurals: 2,
        conversions: AtomicPtr::new(null_mut()),
    };
    if revision & 0xffff >= 1 {
        hash_off?;
        d.sysdep = load_sysdep(swap, data)?;
    }
    // the header entry: plural forms
    if let Some((header, _)) = find_raw_idx(&d, b"") {
        let end = header.iter().position(|&b| b == 0).unwrap_or(header.len());
        let (pl, n) = plural::extract(&header[..end]);
        d.plural = pl;
        d.nplurals = n;
    }
    mem::leak(d).map(|d| &*d)
}

/// System dependent strings of a revision 1 catalog (the mapping `data`): build the concatenated strings. None for an
/// invalid catalog.
fn load_sysdep(swap: bool, data: &'static [u8]) -> Option<&'static [Sysdep]> {
    let size = data.len();
    let rd = |off: usize| w(swap, rd32(data, off));
    let n_strings = rd(36) as usize;
    if n_strings == 0 {
        return Some(&[]);
    }
    let n_segments = rd(28) as usize;
    let seg_off = rd(32) as usize;
    let orig_off = rd(40) as usize;
    let trans_off = rd(44) as usize;
    let fits = |off: usize, n: usize| off.checked_add(n).is_some_and(|e| e <= size);
    if !fits(seg_off, n_segments * 8) || !fits(orig_off, n_strings * 4) || !fits(trans_off, n_strings * 4) {
        return None;
    }
    // values of the segments (None: this system does not know the name)
    let mut values: [Option<&'static [u8]>; 64] = [None; 64];
    if n_segments > 64 {
        return None;
    }
    for (i, slot) in values.iter_mut().enumerate().take(n_segments) {
        let len = rd(seg_off + i * 8) as usize;
        let off = rd(seg_off + i * 8 + 4) as usize;
        if len == 0 || !fits(off, len) || data[off + len - 1] != 0 {
            return None;
        }
        *slot = sysdep_value(&data[off..off + len - 1]);
    }
    let out = SysdepTable::new(n_strings)?;
    let mut out = out;
    'strings: for i in 0..n_strings {
        // build the pair; skip it if a segment is unknown
        let mut pair: [&'static [u8]; 2] = [&[], &[]];
        for (j, slot) in pair.iter_mut().enumerate() {
            let tab = if j == 0 { orig_off } else { trans_off };
            let sd = rd(tab + i * 4) as usize;
            if !fits(sd, 4) {
                return None;
            }
            let mut static_seg = rd(sd) as usize;
            let mut p = sd + 4;
            // first pass: size and validity
            let mut need = 0usize;
            let mut q = p;
            loop {
                if !fits(q, 8) {
                    return None;
                }
                let segsize = rd(q) as usize;
                let sysref = rd(q + 4);
                need += segsize;
                if sysref == SEGMENTS_END {
                    break;
                }
                if sysref as usize >= n_segments {
                    return None;
                }
                let Some(v) = values[sysref as usize] else { continue 'strings };
                need += v.len();
                q += 8;
            }
            let bp = mem::malloc(need + 1);
            if bp.is_null() {
                return None;
            }
            // SAFETY: a fresh block of `need + 1` bytes, never freed (the strings live as long as the catalog).
            let buf: &'static mut [u8] = unsafe { mem::block(bp, need + 1) };
            let mut at = 0;
            loop {
                let segsize = rd(p) as usize;
                let sysref = rd(p + 4);
                // (a static segment outside the file is an invalid catalog: glibc would read past the mapping)
                buf[at..at + segsize].copy_from_slice(data.get(static_seg..static_seg + segsize)?);
                at += segsize;
                static_seg += segsize;
                if sysref == SEGMENTS_END {
                    break;
                }
                let v = values[sysref as usize].unwrap_or(b"");
                buf[at..at + v.len()].copy_from_slice(v);
                at += v.len();
                p += 8;
            }
            buf[at] = 0;
            // the original keeps its NUL (the lookup compares up to it); the translation's length excludes it
            *slot = if j == 0 { &buf[..at + 1] } else { &buf[..at] };
        }
        out.push(Sysdep { orig: pair[0], trans: pair[1] });
    }
    Some(out.finish())
}

/// The table of system dependent strings being built (never freed).
struct SysdepTable {
    items: &'static mut [core::mem::MaybeUninit<Sysdep>],
    n: usize,
}

impl SysdepTable {
    fn new(cap: usize) -> Option<SysdepTable> {
        let p = mem::calloc(cap.max(1), core::mem::size_of::<Sysdep>()).cast::<core::mem::MaybeUninit<Sysdep>>();
        if p.is_null() {
            return None;
        }
        // SAFETY: a fresh block of `cap` entries, 16-aligned and never freed; `MaybeUninit` holds any bytes.
        Some(SysdepTable { items: unsafe { ffi::slice_mut(p, cap) }, n: 0 })
    }
    fn push(&mut self, s: Sysdep) {
        self.items[self.n].write(s);
        self.n += 1;
    }
    fn finish(self) -> &'static [Sysdep] {
        let n = self.n;
        let p = self.items.as_ptr().cast::<Sysdep>();
        // SAFETY: the first `n` entries were written by `push`; the block is never freed or written again.
        unsafe { ffi::slice(p, n) }
    }
}

/// The translation of `msgid` as stored in the catalog (no conversion): its bytes (with the final NUL; plural entries
/// hold their forms separated by NULs; a system dependent one without the final NUL), and the string's index.
fn find_raw_idx(d: &Domain, msgid: &[u8]) -> Option<(&'static [u8], usize)> {
    let data = d.data;
    let size = data.len();
    let nstrings = d.nstrings as usize;
    let orig = |i: usize| -> (usize, usize) { (d.word(d.orig_off + 8 * i + 4) as usize, d.word(d.orig_off + 8 * i) as usize) };
    let found = |act: usize| -> Option<(&'static [u8], usize)> {
        let off = d.word(d.trans_off + 8 * act + 4) as usize;
        let len = d.word(d.trans_off + 8 * act) as usize + 1;
        let end = off.checked_add(len).filter(|&e| e <= size)?;
        Some((&data[off..end], act))
    };
    // the bytes at `off` are msgid and then a NUL
    let same = |s: &[u8], off: usize| -> bool { s.get(off..off + msgid.len()) == Some(msgid) && s.get(off + msgid.len()) == Some(&0) };
    if let Some(hash_off) = d.hash_off {
        let hv = hash_string(msgid);
        let size_h = d.hash_size;
        let mut idx = hv % size_h;
        let incr = 1 + hv % (size_h - 2);
        let mut tries = 0u32;
        loop {
            let nstr = d.word(hash_off + 4 * idx as usize);
            if nstr == 0 {
                return None;
            }
            let nstr = nstr as usize - 1;
            if nstr < nstrings {
                let (p, len) = orig(nstr);
                if len >= msgid.len() && p.checked_add(msgid.len()).is_some_and(|e| e < size) && same(data, p) {
                    return found(nstr);
                }
            } else if let Some(e) = d.sysdep.get(nstr - nstrings)
                && e.orig.len() - 1 > msgid.len()
                && same(e.orig, 0)
            {
                return Some((e.trans, nstr));
            }
            idx = if idx >= size_h - incr { idx - (size_h - incr) } else { idx + incr };
            tries += 1;
            if tries > size_h {
                return None;
            }
        }
    }
    // no hash table: binary search in the sorted originals
    let (mut bottom, mut top) = (0usize, nstrings);
    while bottom < top {
        let act = (bottom + top) / 2;
        let (p, _) = orig(act);
        let os = mem::cstr_at(data, p);
        match msgid.cmp(os) {
            core::cmp::Ordering::Less => top = act,
            core::cmp::Ordering::Greater => bottom = act + 1,
            core::cmp::Ordering::Equal => return found(act),
        }
    }
    None
}

/// Locale transliteration data of LC_CTYPE data `ct` (glibc's `_NL_CTYPE_TRANSLIT_*` items), if the
/// locale has any (the built-in C locale carries no tables here). The tables are slices of the locale image from each
/// table's start (the format stores sizes as counts, which are checked against the image as they are used).
struct Translit {
    size: usize,
    from_idx: &'static [u8],
    from_tbl: &'static [u8],
    to_idx: &'static [u8],
    to_tbl: &'static [u8],
    default_missing: &'static [u8],
    default_missing_len: usize,
    ignore: &'static [u8],
    ignore_len: usize,
}

/// Word `i` (native-endian u32) of a table slice; 0 past its end.
#[inline]
fn wd(t: &[u8], i: usize) -> u32 {
    rd32(t, i.wrapping_mul(4))
}

fn translit_tables(ct: Option<&'static core_locale::CatData>) -> Option<Translit> {
    let d = ct?;
    if d.flags() & core_locale::F_BUILTIN_C != 0 || d.nstrings() < 70 {
        return None;
    }
    let it = |i: usize| crate::data::item(d, i);
    Some(Translit {
        size: d.word(61) as usize,
        from_idx: it(62),
        from_tbl: it(63),
        to_idx: it(64),
        to_tbl: it(65),
        default_missing: it(67),
        default_missing_len: d.word(66) as usize,
        ignore: it(69),
        ignore_len: d.word(68) as usize,
    })
}

/// A malloc'd byte buffer grown by doubling (the converted translations are kept, so the block is handed out).
struct OutBuf {
    p: *mut u8,
    cap: usize,
    len: usize,
}

impl OutBuf {
    fn reserve(&mut self, extra: usize) -> bool {
        if self.len + extra <= self.cap {
            return true;
        }
        let mut nc = (self.cap * 2).max(64);
        while nc < self.len + extra {
            nc *= 2;
        }
        // SAFETY: `p` is null or this buffer's own block; on success the old pointer is replaced and not used again.
        let np = unsafe { mem::realloc(self.p, nc) };
        if np.is_null() {
            return false;
        }
        self.p = np;
        self.cap = nc;
        true
    }
    fn space(&mut self) -> &mut [u8] {
        // SAFETY: `cap` bytes of this buffer's own block (empty when there is none yet), borrowed with `self`.
        unsafe { mem::block(self.p, self.cap) }
    }
    fn release(self) {
        // SAFETY: the buffer's own block (or null), not used again.
        unsafe { mem::free(self.p) };
    }
}

/// Encode the code points `cps` with `enc`, appending to `out`. Ok(()) if all went through, Err(true)
/// for "illegal input" (a character the charset cannot hold), Err(false) for any other failure.
fn encode_run(enc: &mut rusty_libc_iconv::Converter, cps: &[u32], out: &mut OutBuf) -> Result<(), bool> {
    let mut bytes = [0u8; 64];
    let n = cps.len().min(16);
    for (i, &c) in cps[..n].iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }
    loop {
        if !out.reserve(64) {
            return Err(false);
        }
        let (mut ip, mut op) = (0usize, out.len);
        match enc.convert_raw(&bytes[..n * 4], &mut ip, out.space(), &mut op) {
            Ok(_) if ip == n * 4 => {
                out.len = op;
                return Ok(());
            }
            Ok(_) => return Err(false),
            Err(rusty_libc_iconv::Error::E2big) => {
                // the characters did not fit: more room (the converter may have written part of them; retry from the start)
                if !out.reserve(out.cap + 64) {
                    return Err(false);
                }
                continue;
            }
            Err(rusty_libc_iconv::Error::Ilseq) => return Err(true),
            Err(_) => return Err(false),
        }
    }
}

/// The code points of a 0-terminated word list starting at word `at` of `t` (stops at the end of `t`), into `buf`.
fn words_until_zero<'b>(t: &[u8], at: usize, buf: &'b mut [u32; 64]) -> (&'b [u32], usize) {
    let mut l = 0;
    while wd(t, at + l) != 0 {
        if l < buf.len() {
            buf[l] = wd(t, at + l);
        }
        l += 1;
    }
    (&buf[..l.min(64)], l)
}

/// glibc's `__gconv_transliterate`: replace the unconvertible character at `w[0]` (the rest of the
/// text follows in `w`) using the locale's rules; returns how many input characters were used.
fn transliterate(enc: &mut rusty_libc_iconv::Converter, t: &Translit, w: &[u32], out: &mut OutBuf) -> Result<usize, ()> {
    if t.size != 0 {
        let (mut low, mut high) = (0usize, t.size);
        while low < high {
            let med = (low + high) / 2;
            let idx = wd(t.from_idx, med) as usize;
            let mut cnt = 0usize;
            loop {
                if wd(t.from_tbl, idx + cnt) != w[cnt] {
                    break;
                }
                cnt += 1;
                if !(wd(t.from_tbl, idx + cnt) != 0 && cnt < w.len()) {
                    break;
                }
            }
            if cnt > 0 && wd(t.from_tbl, idx + cnt) == 0 {
                // a matching input sequence: the first replacement that converts
                let mut idx2 = wd(t.to_idx, med) as usize;
                loop {
                    let mut buf = [0u32; 64];
                    let (cps, l) = words_until_zero(t.to_tbl, idx2, &mut buf);
                    let before = out.len;
                    match encode_run(enc, cps, out) {
                        Ok(()) => return Ok(cnt),
                        Err(true) => out.len = before,
                        Err(false) => return Err(()),
                    }
                    idx2 += l + 1;
                    if wd(t.to_tbl, idx2) == 0 {
                        break;
                    }
                }
            } else if cnt > 0 && cnt == w.len() {
                // the input is a prefix of an entry: glibc reports incomplete input
                return Err(());
            }
            if cnt >= w.len() || wd(t.from_tbl, idx + cnt) < w[cnt] {
                low = med + 1;
            } else {
                high = med;
            }
        }
    }
    // characters to ignore
    let wc = w[0];
    for i in 0..t.ignore_len {
        let (lo, hi, step) = (wd(t.ignore, 3 * i), wd(t.ignore, 3 * i + 1), wd(t.ignore, 3 * i + 2));
        if lo <= wc && wc <= hi && step != 0 && (wc - lo) % step == 0 {
            return Ok(1);
        } else if wc < lo {
            break;
        }
    }
    // the default replacement
    if t.default_missing_len != 0 {
        let mut buf = [0u32; 16];
        let m = t.default_missing_len.min(16);
        for (k, slot) in buf.iter_mut().enumerate().take(m) {
            *slot = wd(t.default_missing, k);
        }
        let before = out.len;
        match encode_run(enc, &buf[..m], out) {
            Ok(()) => return Ok(1),
            Err(true) => out.len = before,
            Err(false) => return Err(()),
        }
    }
    Err(())
}

/// Convert the translation `input` (in the catalog's charset, plural forms separated by NULs) to
/// the output charset, with the locale's transliteration for characters the charset lacks. The
/// result is malloc'd and stays valid for the life of the program.
fn convert_text(dec: &mut rusty_libc_iconv::Converter, enc: &mut rusty_libc_iconv::Converter, input: &[u8], ct: Option<&'static core_locale::CatData>) -> Option<(*mut u8, usize)> {
    // to UCS-4: at most one character per input byte
    let wcap = (input.len() + 1) * 4;
    let wbuf = mem::malloc(wcap);
    if wbuf.is_null() {
        return None;
    }
    let _ = dec.flush_raw(None);
    let (mut ip, mut op) = (0usize, 0usize);
    // SAFETY: a fresh block of `wcap` bytes, ours until freed below.
    let r = dec.convert_raw(input, &mut ip, unsafe { mem::block(wbuf, wcap) }, &mut op);
    if r.is_err() || ip != input.len() {
        // SAFETY: our block, not used again.
        unsafe { mem::free(wbuf) };
        return None;
    }
    let n = op / 4;
    // SAFETY: the block is 16-aligned and its first `n * 4` bytes were written by the converter (UCS-4 words); it is
    // only read through `words` until it is freed below.
    let words: &[u32] = unsafe { ffi::slice(wbuf.cast::<u32>(), n) };
    let tl = translit_tables(ct);
    let mut out = OutBuf { p: null_mut(), cap: 0, len: 0 };
    let _ = enc.flush_raw(None);
    let mut i = 0;
    let ok = loop {
        if i >= n {
            break true;
        }
        match encode_run(enc, &words[i..i + 1], &mut out) {
            Ok(()) => i += 1,
            Err(true) => match &tl {
                Some(t) => match transliterate(enc, t, &words[i..], &mut out) {
                    Ok(used) => i += used,
                    Err(()) => break false,
                },
                // the built-in C locale: its transliteration (what glibc's C locale does with
                // a character the output charset lacks; "?" when it has no entry)
                None => {
                    let rep = rusty_libc_stdio::translit::lookup(words[i]);
                    let mut cps = [0u32; 16];
                    let m = rep.len().min(16);
                    for (k, &b) in rep[..m].iter().enumerate() {
                        cps[k] = u32::from(b);
                    }
                    let before = out.len;
                    match encode_run(enc, &cps[..m], &mut out) {
                        Ok(()) => i += 1,
                        Err(_) => {
                            out.len = before;
                            break false;
                        }
                    }
                }
            },
            Err(false) => break false,
        }
    };
    // SAFETY: our block; `words` is not used after this.
    unsafe { mem::free(wbuf) };
    if !ok {
        out.release();
        return None;
    }
    if out.p.is_null() {
        // an empty translation still needs a (NUL-free) allocation
        out.reserve(1);
    }
    Some((out.p, out.len))
}

/// The charset translations are returned in. Callers hold STATE (the binding's codeset stays valid).
fn output_charset(binding: Option<BindingRef>) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut put = |s: &[u8]| {
        let n = s.len().min(63);
        out[..n].copy_from_slice(&s[..n]);
    };
    if let Some(b) = binding {
        let cs = b.get().codeset.load(Ordering::Acquire);
        if !cs.is_null() {
            // SAFETY: a binding's codeset is a malloc'd C string replaced (and freed) only under STATE, which is held.
            put(unsafe { state_str(cs) });
            return out;
        }
    }
    if let Some(v) = find::env(b"OUTPUT_CHARSET") {
        put(v);
        return out;
    }
    match crate::data::current_cat(core_locale::LC_CTYPE) {
        None => put(b"ANSI_X3.4-1968"),
        Some(d) => put(d.bytes(crate::data::CODESET_IDX[0])),
    }
    out
}

/// Look `msgid` up in `d` and, if the catalog's charset differs from the output charset, convert.
/// Returns (pointer, length) of the translation, None if there is none (or it cannot be converted). Callers hold STATE.
fn find_msg(dom: &'static Domain, binding: Option<BindingRef>, msgid: &[u8]) -> Option<(*const u8, usize)> {
    let (raw, act) = find_raw_idx(dom, msgid)?;
    let (ptr, len) = (raw.as_ptr(), raw.len());
    let enc = output_charset(binding);
    let encoding = &enc[..enc.iter().position(|&b| b == 0).unwrap_or(64)];
    // an existing conversion table for this encoding?
    let mut cv = dom.conversions();
    while let Some(c) = cv {
        if c.encoding == encoding {
            break;
        }
        cv = c.next;
    }
    let cv: &'static Conversion = match cv {
        Some(c) => c,
        None => {
            let st = ConvState { ptrs: None, lens: None, mode: -1, dec: None, enc: None };
            let Some(enc_name) = leak_bytes(encoding) else { return Some((ptr, len)) };
            let Some(c) = mem::leak(Conversion { next: dom.conversions(), encoding: enc_name, st: SyncCell::new(st) }) else { return Some((ptr, len)) };
            dom.conversions.store(c, Ordering::Release);
            let c: &'static Conversion = c;
            // SAFETY: STATE is held (the only rule for a Conversion's state) and nothing else reaches it in this call.
            unsafe { c.st.with_unsync(|st| st.mode = conversion_mode(dom, encoding, st)) };
            c
        }
    };
    // SAFETY: STATE is held; the closure does not reach this cell again.
    unsafe { cv.st.with_unsync(|st| converted(st, dom, act, raw)) }.map(|r| r.unwrap_or((ptr, len)))
}

/// The conversion a new table needs (sets the converters in `st` for mode 1).
fn conversion_mode(dom: &Domain, encoding: &[u8], st: &mut ConvState) -> i32 {
    // the catalog's own charset from its header entry
    let Some((header, _)) = find_raw_idx(dom, b"") else { return 0 };
    let Some(pos) = header.windows(8).position(|x| x == b"charset=") else { return 0 };
    let rest = &header[pos + 8..];
    let n = rest.iter().position(|&b| matches!(b, b' ' | b'\t' | b'\n' | 0)).unwrap_or(rest.len());
    let charset = &rest[..n];
    if crate::charsets::same_charset(charset, encoding) {
        return 0;
    }
    // like glibc: transliteration is always wanted; without it an unconvertible
    // character would drop the translation
    let dec = rusty_libc_iconv::Converter::open(b"UCS-4LE", charset);
    let encoding_name: &[u8] = if encoding.contains(&b'/') { &encoding[..encoding.iter().position(|&b| b == b'/').unwrap_or(encoding.len())] } else { encoding };
    let enc = rusty_libc_iconv::Converter::open(encoding_name, b"UCS-4LE");
    match (dec, enc) {
        (Ok(d), Ok(e)) => {
            st.dec = Some(d);
            st.enc = Some(e);
            1
        }
        _ => -2, // no conversion possible: the translation is not used
    }
}

/// The translation `raw` (string `act` of `dom`) through the conversion state `st`: Some(None) for "use it as stored",
/// Some(Some(converted)), or None when it cannot be used.
fn converted(st: &mut ConvState, dom: &Domain, act: usize, raw: &[u8]) -> Option<Option<(*const u8, usize)>> {
    match st.mode {
        1 => {
            let total = dom.nstrings as usize + dom.sysdep.len();
            if st.ptrs.is_none() {
                st.ptrs = mem::leak_default::<Option<core::ptr::NonNull<u8>>>(total);
                st.lens = mem::leak_default::<usize>(total);
                if st.ptrs.is_none() || st.lens.is_none() {
                    return None;
                }
            }
            if act >= total {
                return None;
            }
            let (ptrs, lens) = (st.ptrs.as_deref_mut()?, st.lens.as_deref_mut()?);
            if ptrs[act].is_none() {
                // convert all the plural forms in one go (the NULs convert like any character)
                let ct = crate::data::current_cat(core_locale::LC_CTYPE);
                let (dec, enc) = (st.dec.as_mut()?, st.enc.as_mut()?);
                let (out, n) = convert_text(dec, enc, raw, ct)?;
                ptrs[act] = core::ptr::NonNull::new(out);
                lens[act] = n;
            }
            Some(ptrs[act].map(|p| (p.as_ptr() as *const u8, lens[act])))
        }
        -2 => None,
        _ => Some(None),
    }
}

/// The plural form `n` of the translation at `translation` (`len` bytes, inside the catalog or a converted copy).
fn plural_lookup(d: &Domain, n: u64, translation: *const u8, len: usize) -> *const u8 {
    let mut index = d.plural.eval(n);
    if index >= d.nplurals {
        index = 0;
    }
    // SAFETY: `translation` is a translation `find_msg` returned: `len` bytes that live for the rest of the process.
    let t = unsafe { ffi::bytes(translation, len) };
    let mut p = 0usize;
    while index > 0 {
        index -= 1;
        // the forms are NUL-terminated strings inside the translation (a form without its NUL ends the scan)
        while t.get(p).is_some_and(|&b| b != 0) {
            p += 1;
        }
        p += 1;
        if p >= len {
            return translation;
        }
    }
    translation.wrapping_add(p)
}

fn find_binding(domain: &[u8]) -> Option<BindingRef> {
    let mut b = BindingRef::first();
    while let Some(n) = b {
        match domain.cmp(n.domain()) {
            core::cmp::Ordering::Equal => return Some(n),
            core::cmp::Ordering::Less => return None,
            core::cmp::Ordering::Greater => b = n.next(),
        }
    }
    None
}

/// The name of the locale of `category` as `setlocale(category, NULL)` would report it for this
/// thread (the thread locale object's name, or the global one).
fn locale_name(category: usize) -> &'static [u8] {
    // SAFETY: a locale name stays valid while the locale is in use (glibc's gettext reads it the same way).
    unsafe { ffi::cstr_bytes_scalar(crate::name_of(core_locale::Loc::CURRENT, category)) }
}

/// getcwd(2) into `buf`: the length of the path (without its NUL).
fn getcwd(buf: &mut [u8]) -> Result<usize, rusty_libc_core::Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    let r = unsafe { rusty_libc_core::syscall::syscall2(79, buf.as_mut_ptr() as usize, buf.len()) };
    rusty_libc_core::syscall::check(r)?;
    Ok(buf.iter().position(|&b| b == 0).unwrap_or(0))
}

/// glibc's `__dcigettext`.
///
/// # Safety
/// `msgid1` (and `msgid2` if `plural`) are NUL-terminated; `domainname` is NULL or NUL-terminated.
unsafe fn dcigettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, plural: bool, n: c_ulong, category: c_int) -> *mut c_char {
    if msgid1.is_null() {
        return null_mut();
    }
    let untranslated = (if !plural || n == 1 { msgid1 } else { msgid2 }) as *mut c_char;
    if !(0..13).contains(&category) || category == LC_ALL {
        return untranslated;
    }
    // SAFETY: NULL or a C string (the caller's contract).
    let domain = unsafe { ffi::cstr(domainname) }.map(|c| c.to_bytes());
    // SAFETY: a C string (the caller's contract).
    let msgid = unsafe { ffi::cstr_bytes_scalar(msgid1) };
    let saved_errno = errno::get();
    let r = translate(domain, msgid, plural.then_some(n as u64), category);
    errno::set(saved_errno);
    r.map_or(untranslated, |p| p as *mut c_char)
}

/// The translation of `msgid` in `domain` (None: the default domain) for `category`, with plural form `plural` (Some(n)),
/// or None when there is none. The Rust form of `__dcigettext`.
pub fn translate(domain: Option<&[u8]>, msgid: &[u8], plural: Option<u64>, category: c_int) -> Option<*const u8> {
    let _g = STATE.guard();
    let dname: &[u8] = match domain {
        Some(d) => d,
        // SAFETY: the default domain stays valid while STATE is held (textdomain replaces and frees it under STATE).
        None => unsafe { state_str(CURRENT_DOMAIN.load(Ordering::Acquire)) },
    };
    // translations found before are returned again while nothing relevant changed
    let localename = locale_name(category as usize);
    let known = known_find(dname, msgid, category, localename);
    if let Some(k) = known
        && k.counter.load(Ordering::Relaxed) == counter()
    {
        let (p, l) = (k.translation.load(Ordering::Relaxed), k.length.load(Ordering::Relaxed));
        // SAFETY: a known entry's domain is a catalog leaked by `read_domain`, never freed.
        let d = unsafe { &*k.domain.load(Ordering::Relaxed) };
        let r = match plural {
            Some(n) => plural_lookup(d, n, p, l),
            None => p,
        };
        return Some(r);
    }
    let binding = find_binding(dname);
    let dirname: &[u8] = match binding {
        None => &DEFAULT_DIRNAME[..DEFAULT_DIRNAME.len() - 1],
        // SAFETY: a binding's directory is replaced (and freed) only under STATE, which is held.
        Some(b) => unsafe { state_str(b.get().dirname.load(Ordering::Acquire)) },
    };
    // a relative directory is relative to the working directory now
    let mut cwdbuf = [0u8; 1024];
    let mut absdir = [0u8; 1100];
    let dirname: &[u8] = if !dirname.starts_with(b"/") {
        let cl = getcwd(&mut cwdbuf).ok()?;
        if cl + 1 + dirname.len() >= absdir.len() {
            return None;
        }
        absdir[..cl].copy_from_slice(&cwdbuf[..cl]);
        absdir[cl] = b'/';
        absdir[cl + 1..cl + 1 + dirname.len()].copy_from_slice(dirname);
        &absdir[..cl + 1 + dirname.len()]
    } else {
        dirname
    };
    // the language list: LANGUAGE unless the locale is C or C.<charset>
    let locale = locale_name(category as usize);
    let categoryvalue: &[u8] = if locale.first() == Some(&b'C') && matches!(locale.get(1), None | Some(&b'.')) {
        locale
    } else {
        match find::env(b"LANGUAGE") {
            Some(l) => l,
            None => locale,
        }
    };
    // "<category>/<domain>.mo"
    let catname: &[u8] = category_name(category);
    let mut xdomain = [0u8; 300];
    if catname.len() + 1 + dname.len() + 4 > xdomain.len() {
        return None;
    }
    let mut xl = 0;
    for part in [catname, b"/", dname, b".mo"] {
        xdomain[xl..xl + part.len()].copy_from_slice(part);
        xl += part.len();
    }
    let tail = &xdomain[..xl];
    let mut rest = categoryvalue;
    loop {
        while rest.first() == Some(&b':') {
            rest = &rest[1..];
        }
        let single: &[u8];
        if rest.is_empty() {
            // everything searched: an implicit "C" entry, no translation
            single = b"C";
        } else {
            let e = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
            single = &rest[..e];
            rest = &rest[e..];
        }
        // a set-user-ID program must not reach files outside the catalog directories (glibc: ENABLE_SECURE)
        if single.contains(&b'/') && rusty_libc_core::lock::at_secure() == Some(true) {
            continue;
        }
        if untranslated_name(single) {
            return None;
        }
        // alias, then the candidate files in glibc's order
        let alias = find::expand_alias(single);
        let work: &[u8] = match &alias {
            Some(a) => a.as_bytes(),
            None => single,
        };
        let mut hit: Option<(&'static Domain, *const u8, usize)> = None;
        find::for_each_candidate(work, dirname, tail, |path| {
            let Some(d) = load_domain(path) else { return false };
            if let Some((p, l)) = find_msg(d, binding, msgid) {
                hit = Some((d, p, l));
                return true;
            }
            false
        });
        if let Some((d, p, l)) = hit {
            // remember it (or refresh the entry that was out of date)
            match known {
                None => remember(dname, msgid, localename, category, d, p, l),
                Some(k) => {
                    k.counter.store(counter(), Ordering::Relaxed);
                    k.domain.store(d as *const Domain as *mut Domain, Ordering::Relaxed);
                    k.translation.store(p.cast_mut(), Ordering::Relaxed);
                    k.length.store(l, Ordering::Relaxed);
                }
            }
            let r = match plural {
                Some(n) => plural_lookup(d, n, p, l),
                None => p,
            };
            return Some(r);
        }
    }
}

/// Add a known translation (callers hold STATE). Nothing is added when memory is short.
fn remember(dname: &[u8], msgid: &[u8], localename: &[u8], category: c_int, d: &'static Domain, p: *const u8, l: usize) {
    let strs = [dname, msgid, localename];
    let blocks = strs.map(mem::dup_cstr);
    if blocks.iter().any(|p| p.is_null()) {
        for p in blocks {
            // SAFETY: our own fresh blocks (or null), not used again.
            unsafe { mem::free(p) };
        }
        return;
    }
    // SAFETY: each block holds a copy of its string (then a NUL) and is never freed from here on.
    let [dm, mi, ln]: [&'static [u8]; 3] = core::array::from_fn(|k| unsafe { ffi::bytes(blocks[k], strs[k].len()) });
    let b = known_bucket(msgid, category);
    let node = Known {
        next: known_head(b),
        domainname: dm,
        msgid: mi,
        localename: ln,
        category,
        counter: AtomicU32::new(counter()),
        domain: AtomicPtr::new(d as *const Domain as *mut Domain),
        translation: AtomicPtr::new(p.cast_mut()),
        length: AtomicUsize::new(l),
    };
    if let Some(nk) = mem::leak(node) {
        KNOWN[b].store(nk, Ordering::Release);
    }
}

/// `dcgettext(domainname, msgid, category)`.
///
/// # Safety
/// Valid C strings (`domainname` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dcgettext(domainname: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char {
    // SAFETY: the caller's contract is dcigettext's.
    unsafe { dcigettext(domainname, msgid, null(), false, 0, category) }
}

/// `dgettext(domainname, msgid)`.
///
/// # Safety
/// Valid C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dgettext(domainname: *const c_char, msgid: *const c_char) -> *mut c_char {
    // SAFETY: as above.
    unsafe { dcigettext(domainname, msgid, null(), false, 0, LC_MESSAGES as c_int) }
}

// `__dcgettext`, `__dgettext`: the old internal names (a tail jump to the real function).
rusty_libc_core::tail_alias!(__dcgettext => dcgettext);
rusty_libc_core::tail_alias!(__dgettext => dgettext);

/// `gettext(msgid)`.
///
/// # Safety
/// `msgid` is a valid C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
    // SAFETY: as above.
    unsafe { dcigettext(null(), msgid, null(), false, 0, LC_MESSAGES as c_int) }
}

/// `dcngettext(domainname, msgid1, msgid2, n, category)`.
///
/// # Safety
/// Valid C strings (`domainname` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dcngettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, n: c_ulong, category: c_int) -> *mut c_char {
    // SAFETY: as above.
    unsafe { dcigettext(domainname, msgid1, msgid2, true, n, category) }
}

/// `dngettext(domainname, msgid1, msgid2, n)`.
///
/// # Safety
/// Valid C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dngettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, n: c_ulong) -> *mut c_char {
    // SAFETY: as above.
    unsafe { dcigettext(domainname, msgid1, msgid2, true, n, LC_MESSAGES as c_int) }
}

/// `ngettext(msgid1, msgid2, n)`.
///
/// # Safety
/// Valid C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ngettext(msgid1: *const c_char, msgid2: *const c_char, n: c_ulong) -> *mut c_char {
    // SAFETY: as above.
    unsafe { dcigettext(null(), msgid1, msgid2, true, n, LC_MESSAGES as c_int) }
}

/// `textdomain(domainname)`: set (or with NULL query) the default domain; "" selects "messages".
///
/// # Safety
/// `domainname` is NULL or a valid C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
    // SAFETY: NULL or a C string (the caller's contract).
    match unsafe { ffi::cstr(domainname) } {
        None => CURRENT_DOMAIN.load(Ordering::Acquire).cast(),
        Some(new) => set_textdomain(new.to_bytes()).cast_mut().cast(),
    }
}

/// The setting half of `textdomain`: the new default domain (owned by the library), or null when memory is short.
pub fn set_textdomain(new: &[u8]) -> *const u8 {
    let _g = STATE.guard();
    let old = CURRENT_DOMAIN.load(Ordering::Acquire);
    let default = &DEFAULT_DOMAIN[..DEFAULT_DOMAIN.len() - 1];
    let new_domain: *const u8 = if new.is_empty() || new == default {
        DEFAULT_DOMAIN.as_ptr()
    // SAFETY: the current domain stays valid while STATE is held.
    } else if new == unsafe { state_str(old) } {
        old
    } else {
        let p = mem::dup_cstr(new);
        if p.is_null() {
            return null();
        }
        p
    };
    CURRENT_DOMAIN.store(new_domain.cast_mut(), Ordering::Release);
    bump_cat_cntr();
    // (every successful call counts: programs call textdomain(textdomain(NULL)) to say "the environment changed")
    bump_counter();
    if old as *const u8 != new_domain && old as *const u8 != DEFAULT_DOMAIN.as_ptr() {
        // SAFETY: a domain other than the default was malloc'd by a previous textdomain and has just been replaced.
        unsafe { mem::free(old) };
    }
    new_domain
}

/// What `set_binding_values` is asked to change: absent (the function does not take that value), NULL (report only)
/// or a new value.
#[derive(Clone, Copy)]
enum Arg<'a> {
    Absent,
    Query,
    Set(&'a [u8]),
}

impl<'a> Arg<'a> {
    /// A C argument of a function that takes the value.
    ///
    /// # Safety
    /// `p` is NULL or a C string valid for `'a`.
    unsafe fn of(p: *const c_char) -> Arg<'a> {
        // SAFETY: the caller's contract.
        match unsafe { ffi::cstr(p) } {
            None => Arg::Query,
            Some(s) => Arg::Set(s.to_bytes()),
        }
    }
}

/// glibc's `set_binding_values`: returns (dirname, codeset) as reported for the arguments that were passed.
fn set_binding_values(dname: &[u8], dirname: Arg, codeset: Arg) -> (*mut u8, *mut u8) {
    if dname.is_empty() {
        return (null_mut(), null_mut());
    }
    let _g = STATE.guard();
    let default_dir = &DEFAULT_DIRNAME[..DEFAULT_DIRNAME.len() - 1];
    let default_dir_ptr = DEFAULT_DIRNAME.as_ptr().cast_mut();
    let b = find_binding(dname);
    let mut rdir: *mut u8 = null_mut();
    let mut rcs: *mut u8 = null_mut();
    let mut modified = false;
    if let Some(b) = b {
        let node = b.get();
        match dirname {
            Arg::Absent => {}
            Arg::Query => rdir = node.dirname.load(Ordering::Acquire),
            Arg::Set(dn) => {
                let curp = node.dirname.load(Ordering::Acquire);
                // SAFETY: the binding's directory stays valid while STATE is held.
                let cur = unsafe { state_str(curp) };
                let mut result = curp;
                if dn != cur {
                    let newd = if dn == default_dir { default_dir_ptr } else { mem::dup_cstr(dn) };
                    if !newd.is_null() {
                        if curp as *const u8 != DEFAULT_DIRNAME.as_ptr() {
                            // SAFETY: a directory other than the default was malloc'd here; it is replaced below and was
                            // only reachable through this node.
                            unsafe { mem::free(curp) };
                        }
                        node.dirname.store(newd, Ordering::Release);
                        result = newd;
                        modified = true;
                    }
                }
                rdir = result;
            }
        }
        match codeset {
            Arg::Absent => {}
            Arg::Query => rcs = node.codeset.load(Ordering::Acquire),
            Arg::Set(cn) => {
                let curp = node.codeset.load(Ordering::Acquire);
                let mut result = curp;
                // SAFETY: the binding's codeset stays valid while STATE is held.
                if curp.is_null() || unsafe { state_str(curp) } != cn {
                    let newc = mem::dup_cstr(cn);
                    if !newc.is_null() {
                        // SAFETY: the old codeset was malloc'd here (or is null) and is replaced below.
                        unsafe { mem::free(curp) };
                        node.codeset.store(newc, Ordering::Release);
                        result = newc;
                        modified = true;
                    }
                }
                rcs = result;
            }
        }
    } else if !matches!(dirname, Arg::Set(_)) && !matches!(codeset, Arg::Set(_)) {
        // just the defaults
        if !matches!(dirname, Arg::Absent) {
            rdir = default_dir_ptr;
        }
    } else {
        let size = core::mem::size_of::<Binding>() + dname.len() + 1;
        let block = mem::malloc(size);
        if block.is_null() {
            return (null_mut(), null_mut());
        }
        let dir: *mut u8 = match dirname {
            Arg::Set(dn) if dn != default_dir => mem::dup_cstr(dn),
            _ => default_dir_ptr,
        };
        let cs: *mut u8 = match codeset {
            Arg::Set(c) => mem::dup_cstr(c),
            _ => null_mut(),
        };
        if dir.is_null() {
            // SAFETY: our fresh block, not used again.
            unsafe { mem::free(block) };
            return (null_mut(), null_mut());
        }
        // SAFETY: the block has room for the name after the fixed part; ours alone until linked below.
        let tail = unsafe { mem::block(block, size) };
        let at = core::mem::offset_of!(Binding, domainname);
        tail[at..at + dname.len()].copy_from_slice(dname);
        tail[at + dname.len()] = 0;
        let nb = block.cast::<Binding>();
        // SAFETY: the block starts with room for the fixed part, 16-aligned; it is still ours alone.
        unsafe { nb.write(Binding { next: AtomicPtr::new(null_mut()), dirname: AtomicPtr::new(dir), codeset: AtomicPtr::new(cs), domainname: [] }) };
        // SAFETY: just initialised; it keeps the provenance of the whole block.
        let Some(new) = (unsafe { BindingRef::new(nb) }) else { return (null_mut(), null_mut()) };
        // keep the list sorted by domain name
        match BindingRef::first() {
            Some(first) if dname >= first.domain() => {
                let mut p = first;
                while let Some(nx) = p.next() {
                    if dname <= nx.domain() {
                        break;
                    }
                    p = nx;
                }
                new.get().next.store(p.get().next.load(Ordering::Acquire), Ordering::Relaxed);
                p.get().next.store(new.as_ptr(), Ordering::Release);
            }
            first => {
                new.get().next.store(first.map_or(null_mut(), BindingRef::as_ptr), Ordering::Relaxed);
                _nl_domain_bindings.store(new.as_ptr(), Ordering::Release);
            }
        }
        if !matches!(dirname, Arg::Absent) {
            rdir = dir;
        }
        if !matches!(codeset, Arg::Absent) {
            rcs = cs;
        }
        modified = true;
    }
    if modified {
        bump_cat_cntr();
        bump_counter();
    }
    (rdir, rcs)
}

/// The domain argument of bindtextdomain / bind_textdomain_codeset: None for NULL or "".
///
/// # Safety
/// `p` is NULL or a C string valid for `'a`.
unsafe fn domain_arg<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    unsafe { ffi::cstr(p) }.map(|c| c.to_bytes()).filter(|d| !d.is_empty())
}

/// `bindtextdomain(domainname, dirname)`: look for the domain's catalogs in `dirname` (NULL: just
/// report the binding).
///
/// # Safety
/// Valid C strings (`dirname` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bindtextdomain(domainname: *const c_char, dirname: *const c_char) -> *mut c_char {
    // SAFETY: NULL or a C string (the caller's contract).
    let Some(d) = (unsafe { domain_arg(domainname) }) else { return null_mut() };
    // SAFETY: as above.
    let dir = unsafe { Arg::of(dirname) };
    set_binding_values(d, dir, Arg::Absent).0.cast()
}

/// `bind_textdomain_codeset(domainname, codeset)`: the charset the domain's messages are returned in.
///
/// # Safety
/// Valid C strings (`codeset` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bind_textdomain_codeset(domainname: *const c_char, codeset: *const c_char) -> *mut c_char {
    // SAFETY: NULL or a C string (the caller's contract).
    let Some(d) = (unsafe { domain_arg(domainname) }) else { return null_mut() };
    // SAFETY: as above.
    let cs = unsafe { Arg::of(codeset) };
    set_binding_values(d, Arg::Absent, cs).1.cast()
}


// ---- the hooks behind rusty_libc_core::i18n (the C library's own messages) ----

/// `TranslateFn`: `dcgettext(domain, msgid, LC_MESSAGES)`, in the locale object `loc` when it is not 0 (glibc's
/// `strerror_l` does `uselocale(loc)` around `_()`).
unsafe fn translate_hook(domain: *const c_char, msgid: *const c_char, loc: usize) -> *const c_char {
    if loc == 0 {
        // SAFETY: the hook's contract (C strings) is dcigettext's.
        return unsafe { dcigettext(domain, msgid, null(), false, 0, LC_MESSAGES as c_int) };
    }
    // SAFETY: `loc` is a locale object the caller (strerror_l and friends) passes, alive for the call.
    let old = unsafe { crate::uselocale(loc as *mut crate::LocaleStruct) };
    // SAFETY: as above.
    let r = unsafe { dcigettext(domain, msgid, null(), false, 0, LC_MESSAGES as c_int) };
    // SAFETY: `old` is what uselocale returned: the thread's previous locale or LC_GLOBAL_LOCALE.
    unsafe { crate::uselocale(old) };
    r
}

struct HookSink<'a>(&'a mut dyn FnMut(&[u8]));
impl rusty_libc_stdio::fmt::Sink for HookSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> bool {
        (self.0)(bytes);
        true
    }
}

struct HookArgs<'a> {
    a: &'a [u64],
    next: usize,
}
impl rusty_libc_stdio::fmt::Args for HookArgs<'_> {
    fn get(&mut self, _kind: rusty_libc_stdio::fmt::Kind, pos: Option<usize>) -> rusty_libc_stdio::fmt::Val {
        let i = match pos {
            Some(p) => p.wrapping_sub(1),
            None => {
                self.next += 1;
                self.next - 1
            }
        };
        rusty_libc_stdio::fmt::Val::I(self.a.get(i).copied().unwrap_or(0))
    }
}

/// `FormatFn`: a translated message format run through the printf engine.
unsafe fn format_hook(fmt: *const c_char, args: &[u64], out: &mut dyn FnMut(&[u8])) {
    let saved = errno::get();
    // SAFETY: fmt is a NUL-terminated translated format whose conversions take the given words.
    unsafe { rusty_libc_stdio::fmt::format(&mut HookSink(out), fmt as *const u8, &mut HookArgs { a: args, next: 0 }) };
    errno::set(saved);
}

/// True if the locale name is one for which gettext never translates (C, C.<charset>, POSIX).
fn untranslated_name(name: &[u8]) -> bool {
    (name.first() == Some(&b'C') && matches!(name.get(1), None | Some(&b'.'))) || name == b"POSIX"
}

/// Called by `setlocale` and `newlocale` with the LC_MESSAGES name they selected: the first non-C one switches on
/// the translation of the library's own messages.
pub(crate) fn note_messages_locale(name: &[u8]) {
    if !untranslated_name(name) && !rusty_libc_core::i18n::active() {
        rusty_libc_core::i18n::install(translate_hook, format_hook);
    }
}
