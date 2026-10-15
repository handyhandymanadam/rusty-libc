use crate::builtin_tables as bt;
use crate::mem::{self, rd32};
use crate::mem::Published;
use rusty_libc_core::locale::{CatData, CtypeTables, Loc, WideTables, F_BUILTIN_C, F_CHARSET_SHIFT, F_CTYPE_SPECIAL, F_CTYPE_TABLES, F_WIDE_TABLES, F_DOT, F_GROUP, F_PLAIN, LC_COLLATE, LC_CTYPE, LC_NUMERIC, LC_TIME, NCAT};

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

pub static FREED_GEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
const CACHE: usize = 512;
static CACHE_SLOTS: Cache<CACHE> = Cache::new();

struct Entry {
    key: usize,
    data: &'static CatData,
    next: Published<Entry>,
}

pub(crate) struct Cache<const B: usize> {
    heads: [Published<Entry>; B],
}

impl<const B: usize> Cache<B> {
    pub(crate) const fn new() -> Self {
        const { assert!(B.is_power_of_two()) };
        Cache { heads: [const { Published::empty() }; B] }
    }

    #[inline]
    fn bucket(&self, key: usize) -> &Published<Entry> {
        let bits = B.trailing_zeros();
        let h = if bits == 0 { 0 } else { ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - bits)) as usize };
        &self.heads[h]
    }

}

#[inline(always)]
pub(crate) unsafe fn published(p: *const CatData) -> Option<&'static CatData> {
    unsafe { p.as_ref() }
}

#[inline(always)]
pub(crate) fn current_cat(cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::current(cat)
}

#[inline(always)]
pub(crate) fn global_cat(cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::global(cat)
}

#[inline(always)]
pub(crate) fn locale_cat(loc: Loc, cat: usize) -> Option<&'static CatData> {
    rusty_libc_core::locale::loc_cat(loc, cat)
}

#[inline]
pub(crate) fn image_of(d: &CatData) -> &'static [u8] {
    let n = d.nstrings() as usize;
    let extra = d.values().wrapping_add(n);
    let p = unsafe { extra.read() } as *const u8;
    let len = unsafe { extra.wrapping_add(1).read() };
    unsafe { rusty_libc_core::ffi::bytes(p, len) }
}

#[inline]
pub(crate) fn coll_tables(d: &CatData) -> Option<&'static crate::collate::CollTables> {
    unsafe { d.aux().cast::<crate::collate::CollTables>().as_ref() }
}

#[inline]
pub(crate) fn item(d: &CatData, i: usize) -> &'static [u8] {
    let img = image_of(d);
    if i >= d.nstrings() as usize {
        return &[];
    }
    let off = (d.cstr(i) as usize).wrapping_sub(img.as_ptr() as usize);
    img.get(off..).unwrap_or(&[])
}

#[inline]
pub(crate) fn as_u32(b: &'static [u8]) -> &'static [u32] {
    if !b.as_ptr().cast::<u32>().is_aligned() {
        return &[];
    }
    unsafe { rusty_libc_core::ffi::slice(b.as_ptr().cast::<u32>(), b.len() / 4) }
}

#[inline]
pub(crate) fn as_i32(b: &'static [u8]) -> &'static [i32] {
    if !b.as_ptr().cast::<i32>().is_aligned() {
        return &[];
    }
    unsafe { rusty_libc_core::ffi::slice(b.as_ptr().cast::<i32>(), b.len() / 4) }
}

fn rd16(b: &[u8], off: usize) -> u16 {
    match b.get(off..off.wrapping_add(2)) {
        Some(w) => u16::from_ne_bytes([w[0], w[1]]),
        None => 0,
    }
}

pub fn intern(cat: usize, img: &'static [u8]) -> Option<&'static CatData> {
    for utf8 in [false, true] {
        let b = bt::blob(utf8, cat);
        if !b.is_empty() && core::ptr::eq(b.as_ptr(), img.as_ptr()) {
            return Some(builtin(utf8, cat));
        }
    }
    intern_in(&CACHE_SLOTS, cat, img, 0)
}

fn cached(mut link: &Published<Entry>, key: usize) -> Option<&'static CatData> {
    while let Some(e) = link.get() {
        if e.key == key {
            return Some(e.data);
        }
        link = &e.next;
    }
    None
}

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
    const HDR: usize = core::mem::size_of::<CatData>();
    const { assert!(HDR % core::mem::size_of::<usize>() == 0) };
    let block = mem::calloc(1, HDR + (n + 2) * core::mem::size_of::<usize>());
    if block.is_null() {
        return None;
    }
    let values_ptr = block.wrapping_add(HDR).cast::<usize>();
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
        unsafe { mem::free(block) };
        return None;
    }
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
        let Some(t) = mem::leak(t) else {
            unsafe { mem::free(block) };
            return None;
        };
        aux = (t as *const crate::collate::CollTables).cast();
    }
    let head = unsafe { CatData::new(n as u32, flags, values_ptr, aux) };
    let d = block.cast::<CatData>();
    unsafe { d.write(head) };
    let d: &'static CatData = unsafe { &*d };
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

fn ctype_tables(img: &'static [u8]) -> Option<(&'static CtypeTables, bool)> {
    let len = img.len();
    let off = |i: usize| rd32(img, 8 + i * 4) as usize;
    let (oc, ou, ol) = (off(0), off(1), off(3));
    if oc + 768 > len || ou + 1536 > len || ol + 1536 > len || oc % 2 != 0 || ou % 4 != 0 || ol % 4 != 0 {
        return None;
    }
    let (cc, cl, cu) = rusty_libc_ctype::c_tables();
    let special = (0..384usize).any(|i| {
        rd16(img, oc + 2 * i) != cc[i] || rd32(img, ol + 4 * i) as i32 != i32::from(cl[i]) || rd32(img, ou + 4 * i) as i32 != i32::from(cu[i])
    });
    let class = img[oc + 256..].as_ptr().cast::<u16>();
    let upper = img[ou + 512..].as_ptr().cast::<i32>();
    let lower = img[ol + 512..].as_ptr().cast::<i32>();
    let t = mem::leak(CtypeTables { class, upper, lower, wide: wide_tables(img) })?;
    Some((t, special))
}

fn wide_tables(img: &'static [u8]) -> *const WideTables {
    let len = img.len();
    let item = |i: usize| -> Option<usize> {
        let o = rd32(img, 8 + i * 4) as usize;
        if o < len { Some(o) } else { None }
    };
    let word = |i: usize| item(i).filter(|o| o % 4 == 0 && o + 4 <= len).map(|o| rd32(img, o) as usize);
    let (Some(class_names), Some(map_names), Some(width), Some(coff), Some(moff)) = (item(10), item(11), item(12), word(17), word(18)) else { return core::ptr::null() };
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
    let inpunct = find(&mp, b"to_inpunct").and_then(|i| tab(moff + i)).unwrap_or(core::ptr::null());
    match mem::leak(WideTables { class, toupper: tu, tolower: tl, width: tw, inpunct }) {
        Some(w) => w,
        None => core::ptr::null(),
    }
}

pub fn charset_code(codeset: &[u8]) -> u8 {
    if let Some(c) = crate::charsets::code_of_other(codeset) {
        return c;
    }
    crate::charsets::code_of(codeset)
}

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
        let doff = rd32(img, 8 + i * 4) as usize;
        if bt::WIDE[LC_TIME].binary_search(&(i as u16)).is_ok() {
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

#[inline]
pub fn builtin(utf8: bool, cat: usize) -> &'static CatData {
    match BUILTIN[utf8 as usize][cat].get() {
        Some(d) => d,
        None => builtin_first(utf8, cat),
    }
}

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
