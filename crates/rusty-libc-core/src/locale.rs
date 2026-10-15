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
pub const NCAT: usize = 13;

pub const LC_GLOBAL_LOCALE: usize = usize::MAX;

pub const F_DOT: u32 = 1;
pub const F_GROUP: u32 = 2;
pub const F_PLAIN: u32 = 4;
pub const F_BUILTIN_C: u32 = 0x10;
pub const F_CTYPE_TABLES: u32 = 0x20;
pub const F_CTYPE_SPECIAL: u32 = 0x40;
pub const F_WIDE_TABLES: u32 = 0x80;
pub const F_CHARSET_SHIFT: u32 = 8;

#[repr(C)]
pub struct CtypeTables {
    pub class: *const u16,
    pub upper: *const i32,
    pub lower: *const i32,
    pub wide: *const WideTables,
}

#[repr(C)]
pub struct WideTables {
    pub class: [*const u8; 12],
    pub toupper: *const u8,
    pub tolower: *const u8,
    pub width: *const u8,
    pub inpunct: *const u8,
}

pub static WIDE_SPECIAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub static LOCALE_SLOW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline(always)]
pub fn locale_slow() -> bool {
    LOCALE_SLOW.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn wide_special() -> bool {
    WIDE_SPECIAL.load(Ordering::Relaxed)
}

#[inline]
pub fn wide_tables(d: Option<&CatData>) -> Option<&'static WideTables> {
    let t = ctype_tables(d)?;
    if t.wide.is_null() {
        None
    } else {
        Some(unsafe { &*t.wide })
    }
}

#[inline(always)]
unsafe fn word(t: *const u32, i: usize) -> u32 {
    let p = unsafe { t.add(i) };
    unsafe { *p }
}

#[inline]
unsafe fn tab3(table: *const u8, wc: u32, shift3: bool) -> Option<*const u8> {
    let t = table as *const u32;
    let shift1 = unsafe { word(t, 0) };
    let index1 = wc >> shift1;
    if index1 >= unsafe { word(t, 1) } {
        return None;
    }
    let lookup1 = unsafe { word(t, 5 + index1 as usize) };
    if lookup1 == 0 {
        return None;
    }
    let shift2 = unsafe { word(t, 2) };
    let index2 = (wc >> shift2) & unsafe { word(t, 3) };
    let lvl2 = unsafe { table.add(lookup1 as usize) } as *const u32;
    let lookup2 = unsafe { word(lvl2, index2 as usize) };
    if lookup2 == 0 {
        return None;
    }
    let mask3 = unsafe { word(t, 4) };
    let index3 = if shift3 { (wc >> 5) & mask3 } else { wc & mask3 };
    Some(unsafe { table.add(lookup2 as usize + index3 as usize * if shift3 { 4 } else { 1 }) })
}

pub unsafe fn class_lookup(table: *const u8, wc: u32) -> bool {
    match unsafe { tab3(table, wc, true) } {
        Some(p) => (unsafe { core::ptr::read_unaligned(p as *const u32) } >> (wc & 31)) & 1 != 0,
        None => false,
    }
}

pub unsafe fn trans_lookup(table: *const u8, wc: u32) -> u32 {
    let t = table as *const u32;
    let index1 = wc >> unsafe { word(t, 0) };
    if index1 >= unsafe { word(t, 1) } {
        return wc;
    }
    let lookup1 = unsafe { word(t, 5 + index1 as usize) };
    if lookup1 == 0 {
        return wc;
    }
    let shift2 = unsafe { word(t, 2) };
    let index2 = (wc >> shift2) & unsafe { word(t, 3) };
    let lvl2 = unsafe { table.add(lookup1 as usize) } as *const u32;
    let lookup2 = unsafe { word(lvl2, index2 as usize) };
    if lookup2 == 0 {
        return wc;
    }
    let index3 = wc & unsafe { word(t, 4) };
    let lvl3 = unsafe { table.add(lookup2 as usize) } as *const u32;
    let d = unsafe { word(lvl3, index3 as usize) } as i32;
    wc.wrapping_add(d as u32)
}

pub unsafe fn class_runs(table: *const u8, emit: &mut dyn FnMut(u32, u32)) {
    {
        let t = table as *const u32;
        let hdr = unsafe { *(t as *const [u32; 5]) };
        let [shift1, bound1, shift2, mask2, mask3] = hdr;
        let mut cur: Option<(u32, u32)> = None;
        fn put(emit: &mut dyn FnMut(u32, u32), cur: &mut Option<(u32, u32)>, lo: u32, hi: u32) {
            match cur {
                Some((_, last)) if *last + 1 == lo => *last = hi,
                _ => {
                    if let Some((a, b)) = cur.take() {
                        emit(a, b);
                    }
                    *cur = Some((lo, hi));
                }
            }
        }
        for i1 in 0..bound1 {
            let l1 = unsafe { word(t, 5 + i1 as usize) };
            if l1 == 0 {
                continue;
            }
            let lvl2 = unsafe { table.add(l1 as usize) } as *const u32;
            for i2 in 0..=mask2 {
                let l2 = unsafe { word(lvl2, i2 as usize) };
                if l2 == 0 {
                    continue;
                }
                let lvl3 = unsafe { table.add(l2 as usize) } as *const u32;
                for i3 in 0..=mask3 {
                    let w3 = unsafe { lvl3.add(i3 as usize) };
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

pub unsafe fn trans_changed(table: *const u8, emit: &mut dyn FnMut(u32, u32)) {
    {
        let t = table as *const u32;
        let hdr = unsafe { *(t as *const [u32; 5]) };
        let [shift1, bound1, shift2, mask2, mask3] = hdr;
        for i1 in 0..bound1 {
            let l1 = unsafe { word(t, 5 + i1 as usize) };
            if l1 == 0 {
                continue;
            }
            let lvl2 = unsafe { table.add(l1 as usize) } as *const u32;
            for i2 in 0..=mask2 {
                let l2 = unsafe { word(lvl2, i2 as usize) };
                if l2 == 0 {
                    continue;
                }
                let lvl3 = unsafe { table.add(l2 as usize) } as *const i32;
                for i3 in 0..=mask3 {
                    let e3 = unsafe { lvl3.add(i3 as usize) };
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

pub unsafe fn width_lookup(table: *const u8, wc: u32) -> u8 {
    match unsafe { tab3(table, wc, false) } {
        Some(p) => unsafe { *p },
        None => 0xff,
    }
}

pub static CTYPE_SPECIAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline(always)]
pub fn ctype_special() -> bool {
    CTYPE_SPECIAL.load(Ordering::Relaxed)
}

#[inline]
pub fn ctype_tables(d: Option<&CatData>) -> Option<&'static CtypeTables> {
    let d = d?;
    if d.flags & F_CTYPE_TABLES != 0 { Some(unsafe { &*(d.aux as *const CtypeTables) }) } else { None }
}

#[inline]
pub fn toupper_in(d: Option<&CatData>, c: i32) -> i32 {
    if let Some(t) = ctype_tables(d)
        && (-128..=255).contains(&c)
    {
        let e = unsafe { t.upper.offset(c as isize) };
        return unsafe { *e };
    }
    if (b'a' as i32..=b'z' as i32).contains(&c) { c - 32 } else { c }
}

#[inline]
pub fn tolower_in(d: Option<&CatData>, c: i32) -> i32 {
    if let Some(t) = ctype_tables(d)
        && (-128..=255).contains(&c)
    {
        let e = unsafe { t.lower.offset(c as isize) };
        return unsafe { *e };
    }
    if (b'A' as i32..=b'Z' as i32).contains(&c) { c + 32 } else { c }
}

#[repr(C)]
pub struct CatData {
    nstrings: u32,
    flags: u32,
    values: *const usize,
    aux: *const u8,
}
unsafe impl Sync for CatData {}
unsafe impl Send for CatData {}

impl CatData {
    pub const unsafe fn new(nstrings: u32, flags: u32, values: *const usize, aux: *const u8) -> CatData {
        CatData { nstrings, flags, values, aux }
    }
    #[inline(always)]
    pub fn nstrings(&self) -> u32 {
        self.nstrings
    }
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.flags
    }
    #[inline(always)]
    pub fn values(&self) -> *const usize {
        self.values
    }
    #[inline(always)]
    pub fn aux(&self) -> *const u8 {
        self.aux
    }
    pub fn bytes(&self, i: usize) -> &'static [u8] {
        let p = self.cstr(i);
        let mut n = 0;
        loop {
            let q = unsafe { p.add(n) };
            if unsafe { *q } == 0 {
                break;
            }
            n += 1;
        }
        unsafe { core::slice::from_raw_parts(p, n) }
    }
    pub fn cstr(&self, i: usize) -> *const u8 {
        if i >= self.nstrings as usize {
            return c"".as_ptr().cast();
        }
        let v = unsafe { self.values.add(i) };
        unsafe { *v as *const u8 }
    }
    pub fn word(&self, i: usize) -> u32 {
        if i >= self.nstrings as usize {
            return 0;
        }
        let v = unsafe { self.values.add(i) };
        unsafe { *v as u32 }
    }
    pub fn byte(&self, i: usize) -> u8 {
        unsafe { *self.cstr(i) }
    }
}

static GLOBAL: [AtomicPtr<CatData>; NCAT] = [const { AtomicPtr::new(core::ptr::null_mut()) }; NCAT];

#[thread_local]
static THREAD: core::cell::Cell<*const *const CatData> = core::cell::Cell::new(null());

pub fn set_global(cat: usize, data: Option<&'static CatData>) {
    if cat < NCAT {
        GLOBAL[cat].store(data.map_or(core::ptr::null_mut(), |d| core::ptr::from_ref(d).cast_mut()), Ordering::Release);
    }
}

#[inline]
pub fn global(cat: usize) -> Option<&'static CatData> {
    unsafe { GLOBAL[cat].load(Ordering::Acquire).as_ref() }
}

pub unsafe fn set_thread(locales: *const *const CatData) {
    if !locales.is_null() {
        THREAD_USED.store(true, Ordering::Relaxed);
        LOCALE_SLOW.store(true, Ordering::Relaxed);
    }
    THREAD.set(locales);
}

pub static THREAD_USED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline]
pub fn thread() -> *const *const CatData {
    if !THREAD_USED.load(Ordering::Relaxed) {
        return null();
    }
    THREAD.get()
}

#[inline(always)]
unsafe fn object_cat(obj: *const *const CatData, cat: usize) -> Option<&'static CatData> {
    let cats = unsafe { &*obj.cast::<[*const CatData; NCAT]>() };
    unsafe { cats[cat].as_ref() }
}

#[inline]
pub fn current(cat: usize) -> Option<&'static CatData> {
    cat_of_thread(thread(), cat)
}

#[inline]
pub fn current2(a: usize, b: usize) -> (Option<&'static CatData>, Option<&'static CatData>) {
    let t = thread();
    (cat_of_thread(t, a), cat_of_thread(t, b))
}

#[inline(always)]
fn cat_of_thread(t: *const *const CatData, cat: usize) -> Option<&'static CatData> {
    if t.is_null() {
        global(cat)
    } else {
        unsafe { object_cat(t, cat) }
    }
}

#[inline]
pub fn current_key(cat: usize) -> usize {
    current(cat).map_or(0, |d| core::ptr::from_ref(d) as usize)
}

#[inline]
pub unsafe fn of_locale(loc: usize, cat: usize) -> Option<&'static CatData> {
    if loc == 0 {
        current(cat)
    } else if loc == LC_GLOBAL_LOCALE {
        global(cat)
    } else {
        unsafe { object_cat(loc as *const *const CatData, cat) }
    }
}

pub use rusty_libc_mem::hooks::Loc;

#[inline]
pub fn loc_cat(loc: Loc, cat: usize) -> Option<&'static CatData> {
    unsafe { of_locale(loc.raw(), cat) }
}

#[derive(Clone, Copy)]
pub struct Numeric {
    pub decimal_point: &'static [u8],
    pub thousands_sep: &'static [u8],
    pub grouping: &'static [u8],
    pub decimal_wc: u32,
    pub thousands_wc: u32,
}

pub const C_NUMERIC: Numeric = Numeric { decimal_point: b".", thousands_sep: b"", grouping: b"", decimal_wc: 46, thousands_wc: 0 };

pub fn numeric_of(d: Option<&CatData>) -> Numeric {
    let Some(d) = d else {
        return C_NUMERIC;
    };
    Numeric { decimal_point: d.bytes(0), thousands_sep: d.bytes(1), grouping: d.bytes(2), decimal_wc: d.word(3), thousands_wc: d.word(4) }
}

#[inline]
pub fn numeric() -> Numeric {
    numeric_of(current(LC_NUMERIC))
}

pub unsafe fn numeric_of_locale(loc: usize) -> Numeric {
    numeric_of(unsafe { of_locale(loc, LC_NUMERIC) })
}

#[inline]
pub fn numeric_dot(d: Option<&CatData>) -> bool {
    d.is_none_or(|d| d.flags & F_DOT != 0)
}

pub type WColl = unsafe fn(a: *const u32, b: *const u32, loc: usize) -> i32;
pub type WXfrm = unsafe fn(dest: *mut u32, src: *const u32, n: usize, loc: usize) -> usize;

static WCOLL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static WXFRM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static WCOLL_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn install_wide_collation(coll: WColl, xfrm: WXfrm) {
    WCOLL.store(coll as usize, Ordering::Release);
    WXFRM.store(xfrm as usize, Ordering::Release);
    WCOLL_ACTIVE.store(true, Ordering::Release);
}

#[inline]
pub fn wide_coll() -> Option<WColl> {
    if !WCOLL_ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let f = WCOLL.load(Ordering::Acquire);
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, WColl>(f) }) }
}

#[inline]
pub fn wide_xfrm() -> Option<WXfrm> {
    if !WCOLL_ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let f = WXFRM.load(Ordering::Acquire);
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, WXfrm>(f) }) }
}

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

pub struct GroupIter {
    g: &'static [u8],
    pos: isize,
    in_group: u32,
    remaining: u32,
    non_repeating: u32,
    pub separators: u32,
}

impl Numeric {
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
