use crate::find::{self, cstr_bytes};
use crate::plural::{self, Plural};
use core::ffi::{c_char, c_int, c_ulong};
use core::ptr::{null, null_mut};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::locale as core_locale;

const LC_MESSAGES: usize = 5;
const LC_ALL: c_int = 6;
const NLS_MAGIC: u32 = 0x9504_12de;
const NLS_MAGIC_SWAPPED: u32 = 0xde12_0495;
const SEGMENTS_END: u32 = !0;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _nl_default_dirname: [u8; 18] = *b"/usr/share/locale\0";
static DEFAULT_DIRNAME_OWN: [u8; 18] = *b"/usr/share/locale\0";
const DEFAULT_DIRNAME: &[u8] = &DEFAULT_DIRNAME_OWN;
const DEFAULT_DOMAIN: &[u8] = b"messages\0";

static STATE: RawMutex = RawMutex::new();
static mut CATALOG_COUNTER: u32 = 0;

pub(crate) fn note_locale_changed() {
    let _g = STATE.guard();
    unsafe { CATALOG_COUNTER = CATALOG_COUNTER.wrapping_add(1) };
}

struct Known {
    next: *mut Known,
    domainname: *mut u8,
    msgid: *mut u8,
    localename: *mut u8,
    category: c_int,
    counter: u32,
    domain: *mut Domain,
    translation: *const u8,
    length: usize,
}
const KNOWN_BUCKETS: usize = 512;
static mut KNOWN: [*mut Known; KNOWN_BUCKETS] = [null_mut(); KNOWN_BUCKETS];

fn known_bucket(msgid: &[u8], category: c_int) -> usize {
    let mut h: u32 = 0x811c_9dc5 ^ category as u32;
    for &b in msgid {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    h as usize % KNOWN_BUCKETS
}

unsafe fn known_find(dname: &[u8], msgid: &[u8], category: c_int, localename: &[u8]) -> *mut Known {
    unsafe {
        let mut k = (&raw const KNOWN).cast::<*mut Known>().add(known_bucket(msgid, category)).read();
        while !k.is_null() {
            if (*k).category == category && cstr_bytes((*k).msgid) == msgid && cstr_bytes((*k).domainname) == dname && cstr_bytes((*k).localename) == localename {
                return k;
            }
            k = (*k).next;
        }
        null_mut()
    }
}

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
static mut CURRENT_DOMAIN: *const u8 = DEFAULT_DOMAIN.as_ptr();
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut _nl_domain_bindings: *mut Binding = null_mut();

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut _nl_msg_cat_cntr: c_int = 0;

pub(crate) fn bump_cat_cntr() {
    unsafe {
        let p = &raw mut _nl_msg_cat_cntr;
        p.write_volatile(p.read_volatile().wrapping_add(1));
    }
}
static mut LOADED: *mut Loaded = null_mut();

#[repr(C)]
pub struct Binding {
    next: *mut Binding,
    dirname: *mut u8,
    codeset: *mut u8,
    domainname: [u8; 0],
}

impl Binding {
    unsafe fn domain(b: *const Binding) -> &'static [u8] {
        unsafe { cstr_bytes((&raw const (*b).domainname).cast()) }
    }
}

struct Conversion {
    next: *mut Conversion,
    encoding: *mut u8,
    ptrs: *mut *mut u8,
    lens: *mut usize,
    mode: i32,
    dec: Option<rusty_libc_iconv::Converter>,
    enc: Option<rusty_libc_iconv::Converter>,
}

struct Domain {
    data: *const u8,
    size: usize,
    swap: bool,
    nstrings: u32,
    orig_tab: *const u32,
    trans_tab: *const u32,
    hash_size: u32,
    hash_tab: *const u32,
    sysdep: *mut [usize; 4],
    n_sysdep: usize,
    plural: Plural,
    nplurals: u64,
    conversions: *mut Conversion,
}

struct Loaded {
    next: *mut Loaded,
    path: *mut u8,
    domain: *mut Domain,
}

fn w(swap: bool, x: u32) -> u32 {
    if swap { x.swap_bytes() } else { x }
}

fn dup(s: &[u8]) -> *mut u8 {
    unsafe {
        let p = rusty_libc_malloc::malloc(s.len() + 1) as *mut u8;
        if p.is_null() {
            return p;
        }
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        *p.add(s.len()) = 0;
        p
    }
}

fn rd(p: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(p.add(off) as *const u32) }
}

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

fn sysdep_value(name: &[u8]) -> Option<&'static [u8]> {
    if !name.starts_with(b"PRI") || name.len() < 5 {
        return None;
    }
    let conv = name[3];
    if !matches!(conv, b'd' | b'i' | b'o' | b'u' | b'x' | b'X') {
        return None;
    }
    let rest = &name[4..];
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

fn load_domain(path: &[u8]) -> *mut Domain {
    unsafe {
        let mut l = LOADED;
        while !l.is_null() {
            if cstr_bytes((*l).path) == &path[..path.len() - 1] {
                return (*l).domain;
            }
            l = (*l).next;
        }
        let domain = read_domain(path);
        let node = rusty_libc_malloc::malloc(core::mem::size_of::<Loaded>()) as *mut Loaded;
        if !node.is_null() {
            *node = Loaded { next: LOADED, path: dup(&path[..path.len() - 1]), domain };
            LOADED = node;
        }
        domain
    }
}

fn read_domain(path: &[u8]) -> *mut Domain {
    let Some((data, size)) = crate::archive::map_file(path, None) else { return null_mut() };
    if size < 48 {
        return null_mut();
    }
    let magic = rd(data, 0);
    if magic != NLS_MAGIC && magic != NLS_MAGIC_SWAPPED {
        return null_mut();
    }
    let swap = magic != NLS_MAGIC;
    let revision = w(swap, rd(data, 4));
    if revision >> 16 > 1 {
        return null_mut();
    }
    let nstrings = w(swap, rd(data, 8));
    let orig_off = w(swap, rd(data, 12)) as usize;
    let trans_off = w(swap, rd(data, 16)) as usize;
    let hash_size = w(swap, rd(data, 20));
    let hash_off = w(swap, rd(data, 24)) as usize;
    let fits = |off: usize, n: usize| off.checked_add(n).is_some_and(|e| e <= size);
    if !fits(orig_off, nstrings as usize * 8) || !fits(trans_off, nstrings as usize * 8) {
        return null_mut();
    }
    let hash_tab = if hash_size > 2 {
        if !fits(hash_off, hash_size as usize * 4) {
            return null_mut();
        }
        unsafe { data.add(hash_off) as *const u32 }
    } else {
        null()
    };
    let d = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<Domain>()) } as *mut Domain;
    if d.is_null() {
        return null_mut();
    }
    unsafe {
        (*d).data = data;
        (*d).size = size;
        (*d).swap = swap;
        (*d).nstrings = nstrings;
        (*d).orig_tab = data.add(orig_off) as *const u32;
        (*d).trans_tab = data.add(trans_off) as *const u32;
        (*d).hash_size = hash_size;
        (*d).hash_tab = hash_tab;
        (*d).plural = Plural::germanic();
        (*d).nplurals = 2;
        if revision & 0xffff >= 1 {
            if hash_tab.is_null() {
                rusty_libc_malloc::free(d.cast());
                return null_mut();
            }
            if !load_sysdep(d, data, size) {
                rusty_libc_malloc::free(d.cast());
                return null_mut();
            }
        }
        if let Some((p, len)) = find_msg_raw(&*d, b"") {
            let header = core::slice::from_raw_parts(p, len);
            let end = header.iter().position(|&b| b == 0).unwrap_or(header.len());
            let (pl, n) = plural::extract(&header[..end]);
            (*d).plural = pl;
            (*d).nplurals = n;
        }
    }
    d
}

unsafe fn load_sysdep(d: *mut Domain, data: *const u8, size: usize) -> bool {
    unsafe {
        let swap = (*d).swap;
        let n_strings = w(swap, rd(data, 36)) as usize;
        if n_strings == 0 {
            return true;
        }
        let n_segments = w(swap, rd(data, 28)) as usize;
        let seg_off = w(swap, rd(data, 32)) as usize;
        let orig_off = w(swap, rd(data, 40)) as usize;
        let trans_off = w(swap, rd(data, 44)) as usize;
        let fits = |off: usize, n: usize| off.checked_add(n).is_some_and(|e| e <= size);
        if !fits(seg_off, n_segments * 8) || !fits(orig_off, n_strings * 4) || !fits(trans_off, n_strings * 4) {
            return false;
        }
        let mut values: [Option<&'static [u8]>; 64] = [None; 64];
        if n_segments > 64 {
            return false;
        }
        for (i, slot) in values.iter_mut().enumerate().take(n_segments) {
            let len = w(swap, rd(data, seg_off + i * 8)) as usize;
            let off = w(swap, rd(data, seg_off + i * 8 + 4)) as usize;
            if len == 0 || !fits(off, len) || *data.add(off + len - 1) != 0 {
                return false;
            }
            *slot = sysdep_value(core::slice::from_raw_parts(data.add(off), len - 1));
        }
        let out = rusty_libc_malloc::calloc(n_strings, core::mem::size_of::<[usize; 4]>()) as *mut [usize; 4];
        if out.is_null() {
            return false;
        }
        let mut count = 0;
        'strings: for i in 0..n_strings {
            let mut pair = [0usize; 4];
            for j in 0..2 {
                let tab = if j == 0 { orig_off } else { trans_off };
                let sd = w(swap, rd(data, tab + i * 4)) as usize;
                if !fits(sd, 4) {
                    rusty_libc_malloc::free(out.cast());
                    return false;
                }
                let mut static_seg = data.add(w(swap, rd(data, sd)) as usize);
                let mut p = sd + 4;
                let mut need = 0usize;
                let mut q = p;
                loop {
                    if !fits(q, 8) {
                        rusty_libc_malloc::free(out.cast());
                        return false;
                    }
                    let segsize = w(swap, rd(data, q)) as usize;
                    let sysref = w(swap, rd(data, q + 4));
                    need += segsize;
                    if sysref == SEGMENTS_END {
                        break;
                    }
                    if sysref as usize >= n_segments {
                        rusty_libc_malloc::free(out.cast());
                        return false;
                    }
                    let Some(v) = values[sysref as usize] else { continue 'strings };
                    need += v.len();
                    q += 8;
                }
                let buf = rusty_libc_malloc::malloc(need + 1) as *mut u8;
                if buf.is_null() {
                    rusty_libc_malloc::free(out.cast());
                    return false;
                }
                let mut at = 0;
                loop {
                    let segsize = w(swap, rd(data, p)) as usize;
                    let sysref = w(swap, rd(data, p + 4));
                    core::ptr::copy_nonoverlapping(static_seg, buf.add(at), segsize);
                    at += segsize;
                    static_seg = static_seg.add(segsize);
                    if sysref == SEGMENTS_END {
                        break;
                    }
                    let v = values[sysref as usize].unwrap_or(b"");
                    core::ptr::copy_nonoverlapping(v.as_ptr(), buf.add(at), v.len());
                    at += v.len();
                    p += 8;
                }
                *buf.add(at) = 0;
                pair[2 * j] = buf as usize;
                pair[2 * j + 1] = at;
            }
            *out.add(count) = pair;
            count += 1;
        }
        (*d).sysdep = out;
        (*d).n_sysdep = count;
        true
    }
}

unsafe fn find_raw_idx(d: &Domain, msgid: &[u8]) -> Option<(*const u8, usize, usize)> {
    unsafe {
        let swap = d.swap;
        let nstrings = d.nstrings as usize;
        let orig = |i: usize| -> (*const u8, usize) { (d.data.add(w(swap, *d.orig_tab.add(2 * i + 1)) as usize), w(swap, *d.orig_tab.add(2 * i)) as usize) };
        let found = |act: usize| -> Option<(*const u8, usize, usize)> {
            let off = w(swap, *d.trans_tab.add(2 * act + 1)) as usize;
            let len = w(swap, *d.trans_tab.add(2 * act)) as usize + 1;
            if off.checked_add(len).is_none_or(|e| e > d.size) {
                return None;
            }
            Some((d.data.add(off), len, act))
        };
        let same = |p: *const u8| -> bool { msgid.iter().enumerate().all(|(i, &c)| *p.add(i) == c) && *p.add(msgid.len()) == 0 };
        if !d.hash_tab.is_null() {
            let hv = hash_string(msgid);
            let size = d.hash_size;
            let mut idx = hv % size;
            let incr = 1 + hv % (size - 2);
            let mut tries = 0u32;
            loop {
                let nstr = w(swap, *d.hash_tab.add(idx as usize));
                if nstr == 0 {
                    return None;
                }
                let nstr = nstr as usize - 1;
                if nstr < nstrings {
                    let (p, len) = orig(nstr);
                    if len >= msgid.len() && p as usize + msgid.len() < d.data as usize + d.size && same(p) {
                        return found(nstr);
                    }
                } else if nstr - nstrings < d.n_sysdep {
                    let e = &*d.sysdep.add(nstr - nstrings);
                    if e[1] > msgid.len() && same(e[0] as *const u8) {
                        return Some((e[2] as *const u8, e[3], nstr));
                    }
                }
                idx = if idx >= size - incr { idx - (size - incr) } else { idx + incr };
                tries += 1;
                if tries > size {
                    return None;
                }
            }
        }
        let (mut bottom, mut top) = (0usize, nstrings);
        while bottom < top {
            let act = (bottom + top) / 2;
            let (p, _) = orig(act);
            let os = cstr_bytes(p);
            match msgid.cmp(os) {
                core::cmp::Ordering::Less => top = act,
                core::cmp::Ordering::Greater => bottom = act + 1,
                core::cmp::Ordering::Equal => return found(act),
            }
        }
        None
    }
}

unsafe fn find_msg_raw(d: &Domain, msgid: &[u8]) -> Option<(*const u8, usize)> {
    unsafe { find_raw_idx(d, msgid).map(|(p, l, _)| (p, l)) }
}

struct Translit {
    size: usize,
    from_idx: *const u32,
    from_tbl: *const u32,
    to_idx: *const u32,
    to_tbl: *const u32,
    default_missing: *const u32,
    default_missing_len: usize,
    ignore: *const u32,
    ignore_len: usize,
}

fn translit_tables(ct: *const core_locale::CatData) -> Option<Translit> {
    if ct.is_null() {
        return None;
    }
    let d = unsafe { &*ct };
    if d.flags & core_locale::F_BUILTIN_C != 0 || d.nstrings < 70 {
        return None;
    }
    let wp = |i: usize| d.cstr(i) as *const u32;
    Some(Translit {
        size: d.word(61) as usize,
        from_idx: wp(62),
        from_tbl: wp(63),
        to_idx: wp(64),
        to_tbl: wp(65),
        default_missing: wp(67),
        default_missing_len: d.word(66) as usize,
        ignore: wp(69),
        ignore_len: d.word(68) as usize,
    })
}

struct OutBuf {
    p: *mut u8,
    cap: usize,
    len: usize,
}

impl OutBuf {
    unsafe fn reserve(&mut self, extra: usize) -> bool {
        unsafe {
            if self.len + extra <= self.cap {
                return true;
            }
            let mut nc = (self.cap * 2).max(64);
            while nc < self.len + extra {
                nc *= 2;
            }
            let np = rusty_libc_malloc::realloc(self.p.cast(), nc) as *mut u8;
            if np.is_null() {
                return false;
            }
            self.p = np;
            self.cap = nc;
            true
        }
    }
}

unsafe fn encode_run(enc: &mut rusty_libc_iconv::Converter, cps: &[u32], out: &mut OutBuf) -> Result<(), bool> {
    unsafe {
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
            let outs = core::slice::from_raw_parts_mut(out.p, out.cap);
            match enc.convert_raw(&bytes[..n * 4], &mut ip, outs, &mut op) {
                Ok(_) if ip == n * 4 => {
                    out.len = op;
                    return Ok(());
                }
                Ok(_) => return Err(false),
                Err(rusty_libc_iconv::Error::E2big) => {
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
}

unsafe fn transliterate(enc: &mut rusty_libc_iconv::Converter, t: &Translit, w: &[u32], out: &mut OutBuf) -> Result<usize, ()> {
    unsafe {
        if t.size != 0 {
            let (mut low, mut high) = (0usize, t.size);
            while low < high {
                let med = (low + high) / 2;
                let idx = *t.from_idx.add(med) as usize;
                let mut cnt = 0usize;
                loop {
                    if *t.from_tbl.add(idx + cnt) != w[cnt] {
                        break;
                    }
                    cnt += 1;
                    if !(*t.from_tbl.add(idx + cnt) != 0 && cnt < w.len()) {
                        break;
                    }
                }
                if cnt > 0 && *t.from_tbl.add(idx + cnt) == 0 {
                    let mut idx2 = *t.to_idx.add(med) as usize;
                    loop {
                        let mut l = 0;
                        while *t.to_tbl.add(idx2 + l) != 0 {
                            l += 1;
                        }
                        let cps = core::slice::from_raw_parts(t.to_tbl.add(idx2), l);
                        let before = out.len;
                        match encode_run(enc, cps, out) {
                            Ok(()) => return Ok(cnt),
                            Err(true) => out.len = before,
                            Err(false) => return Err(()),
                        }
                        idx2 += l + 1;
                        if *t.to_tbl.add(idx2) == 0 {
                            break;
                        }
                    }
                } else if cnt > 0 && cnt == w.len() {
                    return Err(());
                }
                if cnt >= w.len() || *t.from_tbl.add(idx + cnt) < w[cnt] {
                    low = med + 1;
                } else {
                    high = med;
                }
            }
        }
        let wc = w[0];
        for i in 0..t.ignore_len {
            let r = t.ignore.add(3 * i);
            let (lo, hi, step) = (*r, *r.add(1), *r.add(2));
            if lo <= wc && wc <= hi && step != 0 && (wc - lo) % step == 0 {
                return Ok(1);
            } else if wc < lo {
                break;
            }
        }
        if t.default_missing_len != 0 {
            let cps = core::slice::from_raw_parts(t.default_missing, t.default_missing_len);
            let before = out.len;
            match encode_run(enc, cps, out) {
                Ok(()) => return Ok(1),
                Err(true) => out.len = before,
                Err(false) => return Err(()),
            }
        }
        Err(())
    }
}

unsafe fn convert_text(dec: &mut rusty_libc_iconv::Converter, enc: &mut rusty_libc_iconv::Converter, input: &[u8], ct: *const core_locale::CatData) -> Option<(*mut u8, usize)> {
    unsafe {
        let wbuf = rusty_libc_malloc::malloc((input.len() + 1) * 4) as *mut u8;
        if wbuf.is_null() {
            return None;
        }
        let _ = dec.flush_raw(None);
        let (mut ip, mut op) = (0usize, 0usize);
        let r = dec.convert_raw(input, &mut ip, core::slice::from_raw_parts_mut(wbuf, (input.len() + 1) * 4), &mut op);
        if r.is_err() || ip != input.len() {
            rusty_libc_malloc::free(wbuf.cast());
            return None;
        }
        let n = op / 4;
        let words = core::slice::from_raw_parts(wbuf as *const u32, n);
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
        rusty_libc_malloc::free(wbuf.cast());
        if !ok {
            if !out.p.is_null() {
                rusty_libc_malloc::free(out.p.cast());
            }
            return None;
        }
        if out.p.is_null() {
            out.reserve(1);
        }
        Some((out.p, out.len))
    }
}

fn output_charset(binding: *const Binding) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut put = |s: &[u8]| {
        let n = s.len().min(63);
        out[..n].copy_from_slice(&s[..n]);
    };
    unsafe {
        if !binding.is_null() && !(*binding).codeset.is_null() {
            put(cstr_bytes((*binding).codeset));
            return out;
        }
    }
    if let Some(v) = find::env(b"OUTPUT_CHARSET") {
        put(v);
        return out;
    }
    let d = core_locale::current(core_locale::LC_CTYPE);
    if d.is_null() {
        put(b"ANSI_X3.4-1968");
    } else {
        put(unsafe { (*d).bytes(crate::data::CODESET_IDX[0]) });
    }
    out
}

unsafe fn find_msg(d: *mut Domain, binding: *const Binding, msgid: &[u8]) -> Option<(*const u8, usize)> {
    unsafe {
        let dom = &mut *d;
        let (ptr, len, act) = find_raw_idx(dom, msgid)?;
        let enc = output_charset(binding);
        let encoding = &enc[..enc.iter().position(|&b| b == 0).unwrap_or(64)];
        let mut cv = dom.conversions;
        while !cv.is_null() {
            if cstr_bytes((*cv).encoding) == encoding {
                break;
            }
            cv = (*cv).next;
        }
        if cv.is_null() {
            cv = rusty_libc_malloc::calloc(1, core::mem::size_of::<Conversion>()) as *mut Conversion;
            if cv.is_null() {
                return Some((ptr, len));
            }
            core::ptr::write(cv, Conversion { next: dom.conversions, encoding: dup(encoding), ptrs: null_mut(), lens: null_mut(), mode: -1, dec: None, enc: None });
            dom.conversions = cv;
            if let Some((hp, hl)) = find_msg_raw(dom, b"") {
                let header = core::slice::from_raw_parts(hp, hl);
                if let Some(pos) = header.windows(8).position(|x| x == b"charset=") {
                    let rest = &header[pos + 8..];
                    let n = rest.iter().position(|&b| matches!(b, b' ' | b'\t' | b'\n' | 0)).unwrap_or(rest.len());
                    let charset = &rest[..n];
                    let same = crate::charsets::same_charset(charset, encoding);
                    if same {
                        (*cv).mode = 0;
                    } else {
                        let dec = rusty_libc_iconv::Converter::open(b"UCS-4LE", charset);
                        let encoding_name: &[u8] = if encoding.contains(&b'/') { &encoding[..encoding.iter().position(|&b| b == b'/').unwrap_or(encoding.len())] } else { encoding };
                        let enc = rusty_libc_iconv::Converter::open(encoding_name, b"UCS-4LE");
                        match (dec, enc) {
                            (Ok(d), Ok(e)) => {
                                (*cv).dec = Some(d);
                                (*cv).enc = Some(e);
                                (*cv).mode = 1;
                            }
                            _ => (*cv).mode = -2,
                        }
                    }
                } else {
                    (*cv).mode = 0;
                }
            } else {
                (*cv).mode = 0;
            }
        }
        match (*cv).mode {
            1 => {
                let total = dom.nstrings as usize + dom.n_sysdep;
                if (*cv).ptrs.is_null() {
                    (*cv).ptrs = rusty_libc_malloc::calloc(total, core::mem::size_of::<*mut u8>()) as *mut *mut u8;
                    (*cv).lens = rusty_libc_malloc::calloc(total, core::mem::size_of::<usize>()) as *mut usize;
                    if (*cv).ptrs.is_null() || (*cv).lens.is_null() {
                        return None;
                    }
                }
                if act >= total {
                    return None;
                }
                if (*(*cv).ptrs.add(act)).is_null() {
                    let input = core::slice::from_raw_parts(ptr, len);
                    let ct = core_locale::current(core_locale::LC_CTYPE);
                    match convert_text((*cv).dec.as_mut().unwrap(), (*cv).enc.as_mut().unwrap(), input, ct) {
                        Some((out, n)) => {
                            *(*cv).ptrs.add(act) = out;
                            *(*cv).lens.add(act) = n;
                        }
                        None => return None,
                    }
                }
                Some(((*(*cv).ptrs.add(act)) as *const u8, *(*cv).lens.add(act)))
            }
            -2 => None,
            _ => Some((ptr, len)),
        }
    }
}

fn plural_lookup(d: &Domain, n: u64, translation: *const u8, len: usize) -> *const u8 {
    let mut index = d.plural.eval(n);
    if index >= d.nplurals {
        index = 0;
    }
    let mut p = translation;
    unsafe {
        while index > 0 {
            index -= 1;
            while *p != 0 {
                p = p.add(1);
            }
            p = p.add(1);
            if p >= translation.add(len) {
                return translation;
            }
        }
    }
    p
}

fn find_binding(domain: &[u8]) -> *mut Binding {
    unsafe {
        let mut b = _nl_domain_bindings;
        while !b.is_null() {
            match domain.cmp(Binding::domain(b)) {
                core::cmp::Ordering::Equal => return b,
                core::cmp::Ordering::Less => return null_mut(),
                core::cmp::Ordering::Greater => b = (*b).next,
            }
        }
        null_mut()
    }
}

fn locale_name(category: usize) -> &'static [u8] {
    cstr_bytes(crate::name_of(0, category))
}

unsafe fn dcigettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, plural: bool, n: c_ulong, category: c_int) -> *mut c_char {
    unsafe {
        if msgid1.is_null() {
            return null_mut();
        }
        let untranslated = || -> *mut c_char { (if !plural || n == 1 { msgid1 } else { msgid2 }) as *mut c_char };
        if !(0..13).contains(&category) || category == LC_ALL {
            return untranslated();
        }
        let saved_errno = errno::get();
        let _g = STATE.guard();
        let result = (|| -> Option<*mut c_char> {
            let domain_ptr: *const u8 = if domainname.is_null() { CURRENT_DOMAIN } else { domainname.cast() };
            let dname = cstr_bytes(domain_ptr);
            let msgid = cstr_bytes(msgid1.cast());
            let localename = locale_name(category as usize);
            let known = known_find(dname, msgid, category, localename);
            if !known.is_null() && (*known).counter == CATALOG_COUNTER {
                let (d, p, l) = ((*known).domain, (*known).translation, (*known).length);
                let r = if plural { plural_lookup(&*d, n as u64, p, l) } else { p };
                return Some(r as *mut c_char);
            }
            let binding = find_binding(dname);
            let dirname: &[u8] = if binding.is_null() { &DEFAULT_DIRNAME[..DEFAULT_DIRNAME.len() - 1] } else { cstr_bytes((*binding).dirname) };
            let mut cwdbuf = [0u8; 1024];
            let mut absdir = [0u8; 1100];
            let dirname: &[u8] = if !dirname.starts_with(b"/") {
                let r = rusty_libc_core::syscall::syscall2(79, cwdbuf.as_mut_ptr() as usize, cwdbuf.len());
                if rusty_libc_core::syscall::check(r).is_err() {
                    return None;
                }
                let cl = cwdbuf.iter().position(|&b| b == 0).unwrap_or(0);
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
            let locale = locale_name(category as usize);
            let categoryvalue: &[u8] = if locale.first() == Some(&b'C') && matches!(locale.get(1), None | Some(&b'.')) {
                locale
            } else {
                match find::env(b"LANGUAGE") {
                    Some(l) => l,
                    None => locale,
                }
            };
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
                    single = b"C";
                } else {
                    let e = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
                    single = &rest[..e];
                    rest = &rest[e..];
                }
                if (single.first() == Some(&b'C') && matches!(single.get(1), None | Some(&b'.'))) || single == b"POSIX" {
                    return None;
                }
                let alias = find::expand_alias(single);
                let work: &[u8] = match &alias {
                    Some(a) => a.as_bytes(),
                    None => single,
                };
                let mut hit: Option<(*mut Domain, *const u8, usize)> = None;
                find::for_each_candidate(work, dirname, tail, |path| {
                    let d = load_domain(path);
                    if d.is_null() {
                        return false;
                    }
                    if let Some((p, l)) = find_msg(d, binding, msgid) {
                        hit = Some((d, p, l));
                        return true;
                    }
                    false
                });
                if let Some((d, p, l)) = hit {
                    if known.is_null() {
                        let nk = rusty_libc_malloc::malloc(core::mem::size_of::<Known>()) as *mut Known;
                        if !nk.is_null() {
                            let (dm, mi, ln) = (dup(dname), dup(msgid), dup(localename));
                            if dm.is_null() || mi.is_null() || ln.is_null() {
                                rusty_libc_malloc::free(dm.cast());
                                rusty_libc_malloc::free(mi.cast());
                                rusty_libc_malloc::free(ln.cast());
                                rusty_libc_malloc::free(nk.cast());
                            } else {
                                let b = known_bucket(msgid, category);
                                *nk = Known { next: (&raw const KNOWN).cast::<*mut Known>().add(b).read(), domainname: dm, msgid: mi, localename: ln, category, counter: CATALOG_COUNTER, domain: d, translation: p, length: l };
                                (&raw mut KNOWN).cast::<*mut Known>().add(b).write(nk);
                            }
                        }
                    } else {
                        (*known).counter = CATALOG_COUNTER;
                        (*known).domain = d;
                        (*known).translation = p;
                        (*known).length = l;
                    }
                    let r = if plural { plural_lookup(&*d, n as u64, p, l) } else { p };
                    return Some(r as *mut c_char);
                }
            }
        })();
        errno::set(saved_errno);
        result.unwrap_or_else(untranslated)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dcgettext(domainname: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char {
    unsafe { dcigettext(domainname, msgid, null(), false, 0, category) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dgettext(domainname: *const c_char, msgid: *const c_char) -> *mut c_char {
    unsafe { dcigettext(domainname, msgid, null(), false, 0, LC_MESSAGES as c_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dcgettext(domainname: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char {
    unsafe { dcgettext(domainname, msgid, category) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dgettext(domainname: *const c_char, msgid: *const c_char) -> *mut c_char {
    unsafe { dgettext(domainname, msgid) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
    unsafe { dcigettext(null(), msgid, null(), false, 0, LC_MESSAGES as c_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dcngettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, n: c_ulong, category: c_int) -> *mut c_char {
    unsafe { dcigettext(domainname, msgid1, msgid2, true, n, category) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dngettext(domainname: *const c_char, msgid1: *const c_char, msgid2: *const c_char, n: c_ulong) -> *mut c_char {
    unsafe { dcigettext(domainname, msgid1, msgid2, true, n, LC_MESSAGES as c_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ngettext(msgid1: *const c_char, msgid2: *const c_char, n: c_ulong) -> *mut c_char {
    unsafe { dcigettext(null(), msgid1, msgid2, true, n, LC_MESSAGES as c_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
    unsafe {
        if domainname.is_null() {
            return CURRENT_DOMAIN as *mut c_char;
        }
        let _g = STATE.guard();
        let new = cstr_bytes(domainname.cast());
        let old = CURRENT_DOMAIN;
        let default = &DEFAULT_DOMAIN[..DEFAULT_DOMAIN.len() - 1];
        let new_domain: *const u8 = if new.is_empty() || new == default {
            DEFAULT_DOMAIN.as_ptr()
        } else if new == cstr_bytes(old) {
            old
        } else {
            let p = dup(new);
            if p.is_null() {
                return null_mut();
            }
            p
        };
        CURRENT_DOMAIN = new_domain;
        bump_cat_cntr();
        CATALOG_COUNTER = CATALOG_COUNTER.wrapping_add(1);
        if old != new_domain && old != DEFAULT_DOMAIN.as_ptr() {
            rusty_libc_malloc::free(old as *mut _);
        }
        new_domain as *mut c_char
    }
}

unsafe fn set_binding_values(domainname: *const c_char, dirname: Option<*const c_char>, codeset: Option<*const c_char>) -> (*mut c_char, *mut c_char) {
    unsafe {
        if domainname.is_null() || *domainname == 0 {
            return (null_mut(), null_mut());
        }
        let _g = STATE.guard();
        let dname = cstr_bytes(domainname.cast());
        let default_dir = &DEFAULT_DIRNAME[..DEFAULT_DIRNAME.len() - 1];
        let b = find_binding(dname);
        let mut rdir: *mut u8 = null_mut();
        let mut rcs: *mut u8 = null_mut();
        let dir_arg = dirname.filter(|p| !p.is_null());
        let cs_arg = codeset.filter(|p| !p.is_null());
        let mut modified = false;
        if !b.is_null() {
            if dirname.is_some() {
                match dir_arg {
                    None => rdir = (*b).dirname,
                    Some(d) => {
                        let dn = cstr_bytes(d.cast());
                        let cur = cstr_bytes((*b).dirname);
                        let mut result = (*b).dirname;
                        if dn != cur {
                            let newd = if dn == default_dir { DEFAULT_DIRNAME.as_ptr() as *mut u8 } else { dup(dn) };
                            if !newd.is_null() {
                                if (*b).dirname as *const u8 != DEFAULT_DIRNAME.as_ptr() {
                                    rusty_libc_malloc::free((*b).dirname.cast());
                                }
                                (*b).dirname = newd;
                                result = newd;
                                modified = true;
                            }
                        }
                        rdir = result;
                    }
                }
            }
            if codeset.is_some() {
                match cs_arg {
                    None => rcs = (*b).codeset,
                    Some(c) => {
                        let cn = cstr_bytes(c.cast());
                        let mut result = (*b).codeset;
                        if result.is_null() || cstr_bytes(result) != cn {
                            let newc = dup(cn);
                            if !newc.is_null() {
                                if !(*b).codeset.is_null() {
                                    rusty_libc_malloc::free((*b).codeset.cast());
                                }
                                (*b).codeset = newc;
                                result = newc;
                                modified = true;
                            }
                        }
                        rcs = result;
                    }
                }
            }
        } else if dir_arg.is_none() && cs_arg.is_none() {
            if dirname.is_some() {
                rdir = DEFAULT_DIRNAME.as_ptr() as *mut u8;
            }
        } else {
            let nb = rusty_libc_malloc::malloc(core::mem::size_of::<Binding>() + dname.len() + 1) as *mut Binding;
            if nb.is_null() {
                return (null_mut(), null_mut());
            }
            let dir: *mut u8 = match dir_arg {
                None => DEFAULT_DIRNAME.as_ptr() as *mut u8,
                Some(d) => {
                    let dn = cstr_bytes(d.cast());
                    if dn == default_dir { DEFAULT_DIRNAME.as_ptr() as *mut u8 } else { dup(dn) }
                }
            };
            let cs: *mut u8 = match cs_arg {
                None => null_mut(),
                Some(c) => dup(cstr_bytes(c.cast())),
            };
            if dir.is_null() {
                rusty_libc_malloc::free(nb.cast());
                return (null_mut(), null_mut());
            }
            nb.write(Binding { next: null_mut(), dirname: dir, codeset: cs, domainname: [] });
            let name = (&raw mut (*nb).domainname).cast::<u8>();
            core::ptr::copy_nonoverlapping(dname.as_ptr(), name, dname.len());
            *name.add(dname.len()) = 0;
            if _nl_domain_bindings.is_null() || dname < Binding::domain(_nl_domain_bindings) {
                (*nb).next = _nl_domain_bindings;
                _nl_domain_bindings = nb;
            } else {
                let mut p = _nl_domain_bindings;
                while !(*p).next.is_null() && dname > Binding::domain((*p).next) {
                    p = (*p).next;
                }
                (*nb).next = (*p).next;
                (*p).next = nb;
            }
            if dirname.is_some() {
                rdir = dir;
            }
            if codeset.is_some() {
                rcs = cs;
            }
            modified = true;
        }
        if modified {
            bump_cat_cntr();
            CATALOG_COUNTER = CATALOG_COUNTER.wrapping_add(1);
        }
        (rdir as *mut c_char, rcs as *mut c_char)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bindtextdomain(domainname: *const c_char, dirname: *const c_char) -> *mut c_char {
    unsafe { set_binding_values(domainname, Some(dirname), None).0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bind_textdomain_codeset(domainname: *const c_char, codeset: *const c_char) -> *mut c_char {
    unsafe { set_binding_values(domainname, None, Some(codeset)).1 }
}

