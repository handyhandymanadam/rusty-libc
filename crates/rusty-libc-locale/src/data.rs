use crate::builtin_tables as bt;
use core::sync::atomic::{AtomicPtr, Ordering};
use rusty_libc_core::locale::{CatData, CtypeTables, WideTables, F_BUILTIN_C, F_CHARSET_SHIFT, F_CTYPE_SPECIAL, F_CTYPE_TABLES, F_WIDE_TABLES, F_DOT, F_GROUP, F_PLAIN, LC_COLLATE, LC_CTYPE, LC_NUMERIC, LC_TIME, NCAT};

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

fn rd32(p: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(p.add(off).cast::<u32>()) }
}

const CACHE: usize = 512;
static CACHE_KEYS: [AtomicPtr<u8>; CACHE] = [const { AtomicPtr::new(core::ptr::null_mut()) }; CACHE];
static CACHE_VALS: [AtomicPtr<CatData>; CACHE] = [const { AtomicPtr::new(core::ptr::null_mut()) }; CACHE];

pub fn intern(cat: usize, ptr: *const u8, len: usize) -> Option<*const CatData> {
    for i in 0..CACHE {
        let k = CACHE_KEYS[i].load(Ordering::Acquire);
        if k.is_null() {
            break;
        }
        if k as *const u8 == ptr {
            return Some(CACHE_VALS[i].load(Ordering::Acquire));
        }
    }
    if len < 8 || rd32(ptr, 0) != magic(cat) {
        return None;
    }
    let n = rd32(ptr, 4) as usize;
    if n < bt::NSTRINGS[cat] as usize || 8 + n * 4 >= len {
        return None;
    }
    let mem = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<CatData>() + n * core::mem::size_of::<usize>()) } as *mut u8;
    if mem.is_null() {
        return None;
    }
    let d = mem as *mut CatData;
    let values = unsafe { mem.add(core::mem::size_of::<CatData>()) } as *mut usize;
    for i in 0..n {
        let off = rd32(ptr, 8 + i * 4) as usize;
        if off > len {
            unsafe { rusty_libc_malloc::free(mem.cast()) };
            return None;
        }
        let v = if is_word(cat, i) {
            if off % 4 != 0 || off + 4 > len {
                unsafe { rusty_libc_malloc::free(mem.cast()) };
                return None;
            }
            rd32(ptr, off) as usize
        } else {
            unsafe { ptr.add(off) as usize }
        };
        unsafe { *values.add(i) = v };
    }
    unsafe {
        (*d).nstrings = n as u32;
        (*d).values = values;
    }
    let flags = unsafe { compute_flags(cat, &*d) };
    unsafe { (*d).flags = flags };
    if cat == LC_CTYPE {
        unsafe { ctype_tables(d, ptr, len) };
    }
    for i in 0..CACHE {
        if CACHE_KEYS[i].load(Ordering::Relaxed).is_null() {
            CACHE_VALS[i].store(d, Ordering::Release);
            CACHE_KEYS[i].store(ptr as *mut u8, Ordering::Release);
            break;
        }
    }
    Some(d)
}

unsafe fn ctype_tables(d: *mut CatData, ptr: *const u8, len: usize) {
    let off = |i: usize| rd32(ptr, 8 + i * 4) as usize;
    let (oc, ou, ol) = (off(0), off(1), off(3));
    if oc + 768 > len || ou + 1536 > len || ol + 1536 > len || oc % 2 != 0 || ou % 4 != 0 || ol % 4 != 0 {
        return;
    }
    let t = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<CtypeTables>()) } as *mut CtypeTables;
    if t.is_null() {
        return;
    }
    unsafe {
        let class = (ptr.add(oc) as *const u16).add(128);
        let upper = (ptr.add(ou) as *const i32).add(128);
        let lower = (ptr.add(ol) as *const i32).add(128);
        *t = CtypeTables { class, upper, lower, wide: wide_tables(ptr, len) };
        if !(*t).wide.is_null() {
            (*d).flags |= F_WIDE_TABLES;
        }
        let (cc, cl, cu) = rusty_libc_ctype::c_tables();
        let mut special = false;
        for i in 0..384usize {
            let k = i as isize - 128;
            if *class.offset(k) != cc[i] || *lower.offset(k) != i32::from(cl[i]) || *upper.offset(k) != i32::from(cu[i]) {
                special = true;
                break;
            }
        }
        (*d).aux = t as *const u8;
        (*d).flags |= F_CTYPE_TABLES | if special { F_CTYPE_SPECIAL } else { 0 };
    }
}

unsafe fn wide_tables(ptr: *const u8, len: usize) -> *const WideTables {
    let item = |i: usize| -> Option<usize> {
        let o = rd32(ptr, 8 + i * 4) as usize;
        if o < len { Some(o) } else { None }
    };
    let word = |i: usize| item(i).filter(|o| o % 4 == 0 && o + 4 <= len).map(|o| rd32(ptr, o) as usize);
    let (Some(class_names), Some(map_names), Some(width), Some(coff), Some(moff)) = (item(10), item(11), item(12), word(17), word(18)) else { return core::ptr::null() };
    unsafe {
        let names = |start: usize| -> [Option<usize>; 20] {
            let mut out = [None; 20];
            let mut p = start;
            let mut k = 0;
            while p < len && *ptr.add(p) != 0 && k < 20 {
                let mut e = p;
                while e < len && *ptr.add(e) != 0 {
                    e += 1;
                }
                out[k] = Some(p);
                k += 1;
                p = e + 1;
            }
            out
        };
        let find = |list: &[Option<usize>; 20], want: &[u8]| -> Option<usize> {
            for (i, s) in list.iter().enumerate() {
                let s = (*s)?;
                let mut n = 0;
                while *ptr.add(s + n) != 0 {
                    n += 1;
                }
                if core::slice::from_raw_parts(ptr.add(s), n) == want {
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
            if o % 4 == 0 && o + 20 <= len { Some(ptr.add(o)) } else { None }
        };
        let mut class = [core::ptr::null::<u8>(); 12];
        for (k, name) in ORDER.iter().enumerate() {
            let Some(i) = find(&cl, name) else { return core::ptr::null() };
            let Some(t) = tab(coff + i) else { return core::ptr::null() };
            class[k] = t;
        }
        let (Some(iu), Some(il)) = (find(&mp, b"toupper"), find(&mp, b"tolower")) else { return core::ptr::null() };
        let (Some(tu), Some(tl), Some(tw)) = (tab(moff + iu), tab(moff + il), item(12).map(|_| ptr.add(width))) else { return core::ptr::null() };
        let w = rusty_libc_malloc::calloc(1, core::mem::size_of::<WideTables>()) as *mut WideTables;
        if w.is_null() {
            return core::ptr::null();
        }
        *w = WideTables { class, toupper: tu, tolower: tl, width: tw };
        w
    }
}

pub fn charset_code(codeset: &[u8]) -> u8 {
    if let Some(c) = crate::charsets::code_of_other(codeset) {
        return c;
    }
    crate::charsets::code_of(codeset)
}

fn compute_flags(cat: usize, d: &CatData) -> u32 {
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
            if same_items(c, d) { F_PLAIN } else { 0 }
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

fn same_items(c: &[u8], d: &CatData) -> bool {
    let cn = rd32(c.as_ptr(), 4) as usize;
    if (d.nstrings as usize) < cn {
        return false;
    }
    for i in 0..cn {
        let off = rd32(c.as_ptr(), 8 + i * 4) as usize;
        if is_word(LC_TIME, i) {
            if rd32(c.as_ptr(), off) != d.word(i) {
                return false;
            }
        } else if bt::WIDE[LC_TIME].binary_search(&(i as u16)).is_ok() {
            let dp = d.cstr(i) as *const u32;
            let mut k = 0;
            loop {
                let b = unsafe { core::ptr::read_unaligned(dp.add(k)) };
                if rd32(c.as_ptr(), off + k * 4) != b {
                    return false;
                }
                if b == 0 {
                    break;
                }
                k += 1;
            }
        } else {
            let ds = d.cstr(i);
            let mut k = 0;
            loop {
                let b = unsafe { *ds.add(k) };
                if c[off + k] != b {
                    return false;
                }
                if b == 0 {
                    break;
                }
                k += 1;
            }
        }
    }
    true
}

pub fn builtin_blob(utf8: bool, cat: usize) -> &'static [u8] {
    bt::blob(utf8, cat)
}

static BUILTIN: [[AtomicPtr<CatData>; NCAT]; 2] = [[const { AtomicPtr::new(core::ptr::null_mut()) }; NCAT], [const { AtomicPtr::new(core::ptr::null_mut()) }; NCAT]];

pub fn builtin(utf8: bool, cat: usize) -> *const CatData {
    let slot = &BUILTIN[utf8 as usize][cat];
    let p = slot.load(Ordering::Acquire);
    if !p.is_null() {
        return p;
    }
    let b = bt::blob(utf8, cat);
    let d = intern(cat, b.as_ptr(), b.len()).expect("built-in locale data is valid");
    if !utf8 {
        unsafe { (*(d as *mut CatData)).flags |= F_BUILTIN_C };
    }
    slot.store(d as *mut CatData, Ordering::Release);
    d
}
