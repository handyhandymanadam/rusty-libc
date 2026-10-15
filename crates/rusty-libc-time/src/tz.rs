#![allow(non_upper_case_globals)]
use crate::calendar::{Tm, offtime};
use crate::mbuf::MBuf;
use crate::sys;
use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_long};
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicPtr, Ordering::Relaxed};
use rusty_libc_core::sync_cell::SyncCell;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __tzname: [AtomicPtr<c_char>; 2] = [AtomicPtr::new(c"GMT".as_ptr().cast_mut()), AtomicPtr::new(c"GMT".as_ptr().cast_mut())];
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __daylight: AtomicI32 = AtomicI32::new(0);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __timezone: AtomicI64 = AtomicI64::new(0);

const _: () = assert!(size_of::<[AtomicPtr<c_char>; 2]>() == 16 && align_of::<AtomicPtr<c_char>>() == align_of::<*mut c_char>());
const _: () = assert!(size_of::<AtomicI32>() == size_of::<c_int>() && align_of::<AtomicI32>() == align_of::<c_int>());
const _: () = assert!(size_of::<AtomicI64>() == size_of::<c_long>() && align_of::<AtomicI64>() == align_of::<c_long>());

#[cfg(feature = "export")]
core::arch::global_asm!(
    ".globl tzname",
    ".type tzname, @object",
    ".size tzname, 16",
    ".set tzname, __tzname",
    ".globl daylight",
    ".type daylight, @object",
    ".size daylight, 4",
    ".set daylight, __daylight",
    ".globl timezone",
    ".type timezone, @object",
    ".size timezone, 8",
    ".set timezone, __timezone",
);

#[inline]
fn tzname_get(i: usize) -> *mut c_char {
    __tzname[i].load(Relaxed)
}

#[inline]
fn tzname_set(i: usize, p: *mut c_char) {
    __tzname[i].store(p, Relaxed)
}

#[inline]
fn name_ptr(n: Option<&'static CStr>) -> *mut c_char {
    n.map_or(null_mut(), |s| s.as_ptr().cast_mut())
}

const TZDEFAULT: &[u8] = b"/etc/localtime";
const TZDEFRULES: &[u8] = b"posixrules";
const TZDIR: &[u8] = b"/usr/share/zoneinfo";

#[repr(C)]
struct TzStr {
    next: *mut TzStr,
    len: usize,
}

struct StrPool {
    head: *mut TzStr,
}

unsafe fn node_data(t: *mut TzStr) -> &'static [u8] {
    let len = unsafe { (*t).len };
    unsafe { core::slice::from_raw_parts(t.wrapping_add(1).cast::<u8>(), len + 1) }
}

impl StrPool {
    fn intern(&mut self, s: &[u8]) -> Option<&'static CStr> {
        let len = s.len();
        let mut last: *mut TzStr = null_mut();
        let mut t = self.head;
        while !t.is_null() {
            let data = unsafe { node_data(t) };
            let tlen = data.len() - 1;
            if len <= tlen && &data[tlen - len..tlen] == s {
                return CStr::from_bytes_until_nul(&data[tlen - len..]).ok();
            }
            last = t;
            t = unsafe { (*t).next };
        }
        let new = unsafe { rusty_libc_malloc::malloc(size_of::<TzStr>() + len + 1) }.cast::<TzStr>();
        let new = NonNull::new(new)?;
        unsafe { new.write(TzStr { next: null_mut(), len }) };
        let dst = unsafe { core::slice::from_raw_parts_mut(new.as_ptr().wrapping_add(1).cast::<u8>(), len + 1) };
        dst[..len].copy_from_slice(s);
        dst[len] = 0;
        if last.is_null() {
            self.head = new.as_ptr();
        } else {
            unsafe { (*last).next = new.as_ptr() };
        }
        CStr::from_bytes_until_nul(unsafe { node_data(new.as_ptr()) }).ok()
    }

    fn intern_c(&mut self, s: &[u8]) -> Option<&'static CStr> {
        self.intern(until_nul(s))
    }
}

fn until_nul(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

const J0: u8 = 0;
const J1: u8 = 1;
const M: u8 = 2;

#[derive(Clone, Copy)]
struct Rule {
    name: Option<&'static CStr>,
    typ: u8,
    m: u16,
    n: u16,
    d: u16,
    secs: i32,
    offset: i32,
    change: i64,
    computed_for: i32,
}

const RULE0: Rule = Rule { name: None, typ: J0, m: 0, n: 0, d: 0, secs: 0, offset: 0, change: 0, computed_for: 0 };

const MON_YDAY: [[u16; 13]; 2] = [
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
    [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

fn isleap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn update_vars(r: &[Rule; 2]) {
    __daylight.store((r[0].offset != r[1].offset) as c_int, Relaxed);
    __timezone.store(-(r[0].offset as c_long), Relaxed);
    tzname_set(0, name_ptr(r[0].name));
    tzname_set(1, name_ptr(r[1].name));
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn scan_hu(s: &[u8], mut pos: usize) -> Option<(u16, usize)> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    while isspace(at(pos)) {
        pos += 1;
    }
    let mut neg = false;
    if at(pos) == b'+' || at(pos) == b'-' {
        neg = at(pos) == b'-';
        pos += 1;
    }
    if !at(pos).is_ascii_digit() {
        return None;
    }
    let mut v: u64 = 0;
    while at(pos).is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((at(pos) - b'0') as u64);
        pos += 1;
    }
    let v = if neg { v.wrapping_neg() } else { v };
    Some((v as u16, pos))
}

fn scan_hms(s: &[u8], defaults: [u16; 3]) -> ([u16; 3], usize, usize) {
    let mut v = defaults;
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let Some((a, p)) = scan_hu(s, 0) else { return (v, 0, 0) };
    v[0] = a;
    let mut consumed = p;
    let mut count = 1;
    if at(p) == b':'
        && let Some((b, p2)) = scan_hu(s, p + 1)
    {
        v[1] = b;
        consumed = p2;
        count = 2;
        if at(p2) == b':'
            && let Some((c, p3)) = scan_hu(s, p2 + 1)
        {
            v[2] = c;
            consumed = p3;
            count = 3;
        }
    }
    (v, count, consumed)
}

fn compute_offset(ss: u32, mm: u32, hh: u32) -> i32 {
    (ss.min(59) + mm.min(59) * 60 + hh.min(24) * 3600) as i32
}

struct Cur<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cur<'_> {
    fn at(&self, k: usize) -> u8 {
        self.s.get(self.i + k).copied().unwrap_or(0)
    }
    fn rest(&self) -> &[u8] {
        &self.s[self.i.min(self.s.len())..]
    }
}

fn parse_tzname(z: &mut Zone, c: &mut Cur, which: usize) -> bool {
    let start = c.i;
    let mut p = start;
    let at = |i: usize| c.s.get(i).copied().unwrap_or(0);
    while at(p).is_ascii_alphabetic() {
        p += 1;
    }
    let mut st = start;
    let mut len = p - start;
    if len < 3 {
        p = c.i;
        if at(p) != b'<' {
            return false;
        }
        p += 1;
        st = p;
        while at(p).is_ascii_alphanumeric() || at(p) == b'+' || at(p) == b'-' {
            p += 1;
        }
        len = p - st;
        let close = at(p);
        p += 1;
        if close != b'>' || len < 3 {
            return false;
        }
    }
    let Some(bytes) = c.s.get(st..st + len) else { return false };
    let Some(name) = z.strings.intern(bytes) else { return false };
    z.rules[which].name = Some(name);
    c.i = p;
    true
}

fn parse_offset(r: &mut [Rule; 2], c: &mut Cur, which: usize) -> bool {
    let ch = c.at(0);
    if which == 0 && (ch == 0 || (ch != b'+' && ch != b'-' && !ch.is_ascii_digit())) {
        return false;
    }
    let sign: i32;
    if ch == b'-' || ch == b'+' {
        sign = if ch == b'-' { 1 } else { -1 };
        c.i += 1;
    } else {
        sign = -1;
    }
    let (v, count, consumed) = scan_hms(c.rest(), [0, 0, 0]);
    if count > 0 {
        r[which].offset = sign * compute_offset(v[2] as u32, v[1] as u32, v[0] as u32);
    } else if which == 0 {
        r[0].offset = 0;
        return false;
    } else {
        r[1].offset = r[0].offset + 3600;
    }
    c.i += consumed;
    true
}

fn parse_rule(r: &mut Rule, c: &mut Cur, which: usize) -> bool {
    if c.at(0) == b',' {
        c.i += 1;
    }
    let ch = c.at(0);
    if ch == b'J' || ch.is_ascii_digit() {
        r.typ = if ch == b'J' { J1 } else { J0 };
        if r.typ == J1 {
            c.i += 1;
            if !c.at(0).is_ascii_digit() {
                return false;
            }
        }
        let mut d: u64 = 0;
        while c.at(0).is_ascii_digit() {
            d = d.saturating_mul(10).saturating_add((c.at(0) - b'0') as u64);
            c.i += 1;
        }
        if d > 365 || (r.typ == J1 && d == 0) {
            return false;
        }
        r.d = d as u16;
    } else if ch == b'M' {
        r.typ = M;
        let s = c.rest();
        let at = |i: usize| s.get(i).copied().unwrap_or(0);
        let Some((m, p1)) = scan_hu(s, 1) else { return false };
        r.m = m;
        if at(p1) != b'.' {
            return false;
        }
        let Some((n, p2)) = scan_hu(s, p1 + 1) else { return false };
        r.n = n;
        if at(p2) != b'.' {
            return false;
        }
        let Some((d, p3)) = scan_hu(s, p2 + 1) else { return false };
        r.d = d;
        if r.m < 1 || r.m > 12 || r.n < 1 || r.n > 5 || r.d > 6 {
            return false;
        }
        c.i += p3;
    } else if ch == 0 {
        r.typ = M;
        if which == 0 {
            r.m = 3;
            r.n = 2;
            r.d = 0;
        } else {
            r.m = 11;
            r.n = 1;
            r.d = 0;
        }
    } else {
        return false;
    }
    let ch = c.at(0);
    if ch != 0 && ch != b'/' && ch != b',' {
        return false;
    } else if ch == b'/' {
        c.i += 1;
        if c.at(0) == 0 {
            return false;
        }
        let negative = c.at(0) == b'-';
        if negative {
            c.i += 1;
        }
        let (v, _count, consumed) = scan_hms(c.rest(), [2, 0, 0]);
        c.i += consumed;
        let secs = v[0] as i32 * 3600 + v[1] as i32 * 60 + v[2] as i32;
        r.secs = if negative { -secs } else { secs };
    } else {
        r.secs = 2 * 3600;
    }
    r.computed_for = -1;
    true
}

fn tzset_parse_tz(z: &mut Zone, tz: &[u8]) -> bool {
    z.rules = [RULE0; 2];
    z.rules[0].name = Some(c"");
    z.rules[1].name = Some(c"");
    let mut c = Cur { s: tz, i: 0 };
    let mut by_string = true;
    if parse_tzname(z, &mut c, 0) && parse_offset(&mut z.rules, &mut c, 0) {
        if c.at(0) != 0 {
            if parse_tzname(z, &mut c, 1) {
                parse_offset(&mut z.rules, &mut c, 1);
                if c.at(0) == 0 || (c.at(0) == b',' && c.at(1) == 0) {
                    let r = z.rules;
                    tzfile_default(z, r[0].name, r[1].name, r[0].offset, r[1].offset);
                    if z.file.used {
                        z.old_tz = MBuf::empty();
                        return false;
                    }
                    by_string = false;
                }
            }
            if parse_rule(&mut z.rules[0], &mut c, 0) {
                parse_rule(&mut z.rules[1], &mut c, 1);
            }
        } else {
            z.rules[1].name = z.rules[0].name;
            z.rules[1].offset = z.rules[0].offset;
        }
    }
    update_vars(&z.rules);
    by_string
}

fn compute_change(rule: &mut Rule, year: i32) {
    if year != -1 && rule.computed_for == year {
        return;
    }
    let mut t: i64 = if year > 1970 {
        let y1 = year.wrapping_sub(1);
        (year
            .wrapping_sub(1970)
            .wrapping_mul(365)
            .wrapping_add(y1 / 4 - 1970 / 4)
            .wrapping_sub(y1 / 100 - 1970 / 100)
            .wrapping_add(y1 / 400 - 1970 / 400)) as i64
            * 86400
    } else {
        0
    };
    match rule.typ {
        J1 => {
            t += (rule.d as i64 - 1) * 86400;
            if rule.d >= 60 && isleap(year as i64) {
                t += 86400;
            }
        }
        J0 => {
            t += rule.d as i64 * 86400;
        }
        _ => {
            let base = isleap(year as i64) as isize * 13 + rule.m as isize;
            let at = |k: isize| -> i64 {
                let idx = base + k;
                if (0..26).contains(&idx) { MON_YDAY[(idx / 13) as usize][(idx % 13) as usize] as i64 } else { 0 }
            };
            t += at(-1) * 86400;
            let m1 = (rule.m as i32 + 9) % 12 + 1;
            let yy0 = if rule.m <= 2 { year - 1 } else { year };
            let yy1 = yy0 / 100;
            let yy2 = yy0 % 100;
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }
            let mut d = rule.d as i32 - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..rule.n {
                if (d + 7) as i64 >= at(0) - at(-1) {
                    break;
                }
                d += 7;
            }
            t += d as i64 * 86400;
        }
    }
    rule.change = t - rule.offset as i64 + rule.secs as i64;
    rule.computed_for = year;
}

fn tz_compute(r: &mut [Rule; 2], timer: i64, tm: &mut Tm, use_localtime: bool) {
    let year = 1900i32.wrapping_add(tm.tm_year);
    compute_change(&mut r[0], year);
    compute_change(&mut r[1], year);
    if use_localtime {
        let isdst = if r[0].change > r[1].change {
            timer < r[1].change || timer >= r[0].change
        } else {
            timer >= r[0].change && timer < r[1].change
        };
        tm.tm_isdst = isdst as c_int;
        tm.tm_zone = tzname_get(isdst as usize);
        tm.tm_gmtoff = r[isdst as usize].offset as c_long;
    }
}

#[derive(Clone, Copy)]
struct TType {
    offset: i32,
    isdst: u8,
    idx: u8,
    isstd: u8,
    isgmt: u8,
}

const TTYPE0: TType = TType { offset: 0, isdst: 0, idx: 0, isstd: 0, isgmt: 0 };

#[derive(Clone, Copy)]
struct Leap {
    transition: i64,
    change: i64,
}

struct TzFile {
    used: bool,
    dev: u64,
    ino: u64,
    mtime: i64,
    trans: MBuf<i64>,
    idxs: MBuf<u8>,
    types: MBuf<TType>,
    names_base: MBuf<u8>,
    names_off: usize,
    leaps: MBuf<Leap>,
    tzspec: MBuf<u8>,
    stdoff: i64,
    dstoff: i64,
    daylight_saved: c_int,
    default_names: bool,
    nchars1: usize,
    spec_rules: Option<[Rule; 2]>,
    name_memo: [Cell<Option<&'static CStr>>; 256],
}

impl TzFile {
    const fn new() -> TzFile {
        TzFile {
            used: false,
            dev: 0,
            ino: 0,
            mtime: 0,
            trans: MBuf::empty(),
            idxs: MBuf::empty(),
            types: MBuf::empty(),
            names_base: MBuf::empty(),
            names_off: 0,
            leaps: MBuf::empty(),
            tzspec: MBuf::empty(),
            stdoff: 0,
            dstoff: 0,
            daylight_saved: 0,
            default_names: false,
            nchars1: 0,
            spec_rules: None,
            name_memo: [const { Cell::new(None) }; 256],
        }
    }

    fn names(&self) -> &[u8] {
        self.names_base.get(self.names_off..).unwrap_or(&[])
    }

    fn name_at(&self, idx: usize) -> &[u8] {
        until_nul(self.names().get(idx..).unwrap_or(&[]))
    }

    fn free_data(&mut self) {
        self.trans = MBuf::empty();
        self.idxs = MBuf::empty();
        self.types = MBuf::empty();
        self.names_base = MBuf::empty();
        self.names_off = 0;
        self.leaps = MBuf::empty();
        self.tzspec = MBuf::empty();
        self.default_names = false;
        self.nchars1 = 0;
        self.spec_rules = None;
        self.clear_name_memo();
    }

    fn clear_name_memo(&self) {
        for m in &self.name_memo {
            m.set(None);
        }
    }

    fn type_name(&self, strings: &mut StrPool, t: &TType) -> *mut c_char {
        let memo = &self.name_memo[t.idx as usize];
        if let Some(n) = memo.get() {
            return name_ptr(Some(n));
        }
        let n = strings.intern_c(self.name_at(t.idx as usize));
        memo.set(n);
        name_ptr(n)
    }
}

fn be32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> i64 {
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn secure() -> bool {
    use core::sync::atomic::AtomicU8;
    static S: AtomicU8 = AtomicU8::new(2);
    let v = S.load(Relaxed);
    if v != 2 {
        return v == 1;
    }
    let s = match rusty_libc_core::lock::at_secure() {
        Some(v) => v,
        None => crate::vdso::auxv_entry(23) != 0,
    };
    S.store(s as u8, Relaxed);
    s
}

fn tzfile_read(z: &mut Zone, file: &[u8], extra: usize) {
    let f = &mut z.file;
    let was_using = f.used;
    f.used = false;
    let fname = until_nul(file);
    if fname.is_empty() {
        f.free_data();
        return;
    }
    if secure() && ((fname[0] == b'/' && fname != TZDEFAULT && !fname.starts_with(TZDIR)) || fname.windows(3).any(|w| w == b"../")) {
        f.free_data();
        return;
    }
    let mut path = [0u8; 4352];
    let plen = if fname[0] != b'/' {
        let dir: &[u8] = match sys::getenv(b"TZDIR") {
            Some(d) if !d.is_empty() => d,
            _ => TZDIR,
        };
        if dir.len() + 1 + fname.len() + 1 > path.len() {
            f.free_data();
            return;
        }
        path[..dir.len()].copy_from_slice(dir);
        path[dir.len()] = b'/';
        path[dir.len() + 1..dir.len() + 1 + fname.len()].copy_from_slice(fname);
        dir.len() + 1 + fname.len()
    } else {
        if fname.len() + 1 > path.len() {
            f.free_data();
            return;
        }
        path[..fname.len()].copy_from_slice(fname);
        fname.len()
    };
    path[plen] = 0;
    let Ok(cpath) = CStr::from_bytes_until_nul(&path) else { return };
    if was_using
        && let Ok(st) = sys::stat(cpath)
        && f.ino == st.st_ino
        && f.dev == st.st_dev
        && f.mtime == st.st_mtime
    {
        f.used = true;
        return;
    }
    let Ok(fd) = sys::open_rdonly_cloexec(cpath) else {
        f.free_data();
        return;
    };
    let mut data: Option<MBuf<u8>> = None;
    let mut len = 0usize;
    if let Ok(st) = sys::fstat(fd) {
        f.free_data();
        f.dev = st.st_dev;
        f.ino = st.st_ino;
        f.mtime = st.st_mtime;
        let size = st.st_size.clamp(0, 64 << 20) as usize;
        data = MBuf::filled(size + 1, 0u8);
        if let Some(d) = data.as_mut() {
            while len < size {
                match rusty_libc_core::unistd::read_nocancel(fd, &mut d[len..size]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
                    Err(_) => break,
                }
            }
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    let Some(data) = data else { return };
    let parsed = parse_tzif(f, &data[..len], extra);
    drop(data);
    if !parsed {
        f.free_data();
        return;
    }
    f.used = true;
    let f = &z.file;
    let types = f.types.as_slice();
    let idxs = f.idxs.as_slice();
    let trans_n = f.trans.len();
    tzname_set(0, null_mut());
    tzname_set(1, null_mut());
    let mut i = trans_n;
    while i > 0 {
        i -= 1;
        let t = &types[idxs[i] as usize];
        let dst = t.isdst as usize;
        if tzname_get(dst).is_null() {
            tzname_set(dst, name_ptr(z.strings.intern_c(f.name_at(t.idx as usize))));
            if !tzname_get(1 - dst).is_null() {
                break;
            }
        }
    }
    if tzname_get(0).is_null() {
        tzname_set(0, name_ptr(z.strings.intern_c(f.names())));
    }
    if tzname_get(1).is_null() {
        tzname_set(1, tzname_get(0));
    }
    let f = &mut z.file;
    let types = f.types.as_slice();
    let idxs = f.idxs.as_slice();
    f.daylight_saved = 0;
    if trans_n == 0 {
        f.stdoff = types[0].offset as i64;
        f.dstoff = f.stdoff;
    } else {
        f.stdoff = 0;
        let trans_idx = |i: usize| types[idxs[i] as usize];
        let mut i = trans_n - 1;
        loop {
            if trans_idx(i).isdst == 0 {
                f.stdoff = trans_idx(i).offset as i64;
                break;
            } else {
                f.daylight_saved = 1;
            }
            if i == 0 {
                i = usize::MAX;
                break;
            }
            i -= 1;
        }
        if i != usize::MAX {
            while i > 0 && f.daylight_saved == 0 {
                i -= 1;
                f.daylight_saved = trans_idx(i).isdst as c_int;
            }
        }
    }
    __daylight.store(f.daylight_saved, Relaxed);
    __timezone.store(-f.stdoff, Relaxed);
}

fn parse_tzif(f: &mut TzFile, d: &[u8], extra: usize) -> bool {
    let mut pos = 0usize;
    let mut width = 4usize;
    loop {
        if d.len() < pos + 44 || &d[pos..pos + 4] != b"TZif" {
            return false;
        }
        let version = d[pos + 4];
        let isgmt = be32(&d[pos + 20..]);
        let isstd = be32(&d[pos + 24..]);
        let nleaps = be32(&d[pos + 28..]);
        let ntrans = be32(&d[pos + 32..]);
        let ntypes = be32(&d[pos + 36..]);
        let chars = be32(&d[pos + 40..]);
        if isgmt < 0 || isstd < 0 || nleaps < 0 || ntrans < 0 || ntypes < 0 || chars < 0 {
            return false;
        }
        let (isgmt, isstd, nleaps, ntrans, ntypes, chars) = (isgmt as usize, isstd as usize, nleaps as usize, ntrans as usize, ntypes as usize, chars as usize);
        if isstd > ntypes || isgmt > ntypes {
            return false;
        }
        pos += 44;
        if width == 4 && version != 0 {
            width = 8;
            pos += ntrans * 5 + ntypes * 6 + chars + nleaps * 8 + isstd + isgmt;
            continue;
        }
        let mut tzspec_len = 0usize;
        if width == 8 {
            let rem = match d.len().checked_sub(pos) {
                Some(r) => r,
                None => return false,
            };
            let need = ntrans * 9 + ntypes * 6 + chars;
            if rem < need {
                return false;
            }
            tzspec_len = rem - need;
            if tzspec_len < nleaps * 12 {
                return false;
            }
            tzspec_len -= nleaps * 12;
            if tzspec_len < isstd {
                return false;
            }
            tzspec_len -= isstd;
            if tzspec_len == 0 || tzspec_len - 1 < isgmt {
                return false;
            }
            tzspec_len -= isgmt + 1;
            if tzspec_len == 0 {
                return false;
            }
        }
        let trans = MBuf::filled(ntrans, 0i64);
        let leaps = MBuf::filled(nleaps, Leap { transition: 0, change: 0 });
        let types = MBuf::filled(ntypes, TTYPE0);
        let idxs = MBuf::filled(ntrans, 0u8);
        let names = MBuf::filled(chars + 1 + extra, 0u8);
        if width == 8 && tzspec_len > 0 {
            f.tzspec = MBuf::filled(tzspec_len, 0u8).unwrap_or(MBuf::empty());
        }
        let (Some(trans), Some(leaps), Some(types), Some(idxs), Some(names)) = (trans, leaps, types, idxs, names) else {
            return false;
        };
        f.trans = trans;
        f.leaps = leaps;
        f.types = types;
        f.idxs = idxs;
        f.names_base = names;
        let need_total = ntrans * width + ntrans + ntypes * 6 + chars + nleaps * (width + 4) + isstd + isgmt;
        if d.len() < pos + need_total {
            return false;
        }
        for (i, t) in f.trans.iter_mut().enumerate() {
            let b = &d[pos + i * width..];
            *t = if width == 4 { be32(b) as i64 } else { be64(b) };
        }
        pos += ntrans * width;
        for (i, x) in f.idxs.iter_mut().enumerate() {
            let v = d[pos + i];
            if v as usize >= ntypes {
                return false;
            }
            *x = v;
        }
        pos += ntrans;
        for (i, t) in f.types.iter_mut().enumerate() {
            let b = &d[pos + i * 6..];
            let isdst = b[4];
            let idx = b[5];
            if isdst > 1 || idx as usize > chars {
                return false;
            }
            *t = TType { offset: be32(b), isdst, idx, isstd: 0, isgmt: 0 };
        }
        pos += ntypes * 6;
        f.names_base[..chars].copy_from_slice(&d[pos..pos + chars]);
        f.names_base[chars] = 0;
        f.names_off = 0;
        f.nchars1 = chars + 1;
        pos += chars;
        for (i, l) in f.leaps.iter_mut().enumerate() {
            let b = &d[pos + i * (width + 4)..];
            let transition = if width == 4 { be32(b) as i64 } else { be64(b) };
            let change = be32(&b[width..]) as i64;
            *l = Leap { transition, change };
        }
        pos += nleaps * (width + 4);
        for i in 0..isstd {
            f.types[i].isstd = (d[pos + i] != 0) as u8;
        }
        pos += isstd;
        for i in 0..isgmt {
            f.types[i].isgmt = (d[pos + i] != 0) as u8;
        }
        pos += isgmt;
        if !f.tzspec.is_empty_block() {
            if d.len() >= pos + tzspec_len && d[pos] == b'\n' {
                f.tzspec[..tzspec_len - 1].copy_from_slice(&d[pos + 1..pos + tzspec_len]);
                f.tzspec[tzspec_len - 1] = 0;
                if f.tzspec[0] == 0 {
                    f.tzspec = MBuf::empty();
                }
            } else {
                f.tzspec = MBuf::empty();
            }
        }
        return true;
    }
}

fn tzfile_default(z: &mut Zone, std: Option<&'static CStr>, dst: Option<&'static CStr>, stdoff: i32, dstoff: i32) {
    let (Some(std), Some(dst)) = (std, dst) else { return };
    let (stdb, dstb) = (std.to_bytes_with_nul(), dst.to_bytes_with_nul());
    let (stdlen, dstlen) = (stdb.len(), dstb.len());
    let mut name = [0u8; 16];
    name[..TZDEFRULES.len()].copy_from_slice(TZDEFRULES);
    tzfile_read(z, &name, stdlen + dstlen);
    let f = &mut z.file;
    if !f.used {
        return;
    }
    if f.types.len() < 2 {
        f.used = false;
        return;
    }
    let cp = f.nchars1;
    f.names_base[cp..cp + stdlen].copy_from_slice(stdb);
    f.names_base[cp + stdlen..cp + stdlen + dstlen].copy_from_slice(dstb);
    f.names_off = cp;
    f.clear_name_memo();
    f.default_names = true;
    let mut isdst = false;
    for i in 0..f.trans.len() {
        let tt = f.types[f.idxs[i] as usize];
        f.idxs[i] = tt.isdst;
        if tt.isgmt != 0 {
        } else if isdst && tt.isstd == 0 {
            f.trans[i] += dstoff as i64 - f.dstoff;
        } else {
            f.trans[i] += stdoff as i64 - f.stdoff;
        }
        isdst = tt.isdst != 0;
    }
    f.types.truncate(2);
    f.stdoff = stdoff as i64;
    f.dstoff = dstoff as i64;
    let t = f.types.as_mut_slice();
    t[0] = TType { offset: stdoff, isdst: 0, idx: 0, isstd: t[0].isstd, isgmt: t[0].isgmt };
    t[1] = TType { offset: dstoff, isdst: 1, idx: stdlen as u8, isstd: t[1].isstd, isgmt: t[1].isgmt };
    tzname_set(0, std.as_ptr().cast_mut());
    tzname_set(1, dst.as_ptr().cast_mut());
    __timezone.store(-(stdoff as c_long), Relaxed);
    f.dev = 0;
    f.ino = 0;
    f.mtime = 0;
}

struct Zone {
    rules: [Rule; 2],
    file: TzFile,
    old_tz: MBuf<u8>,
    initialized: bool,
    strings: StrPool,
}

static ZONE: SyncCell<Zone> = SyncCell::new(Zone { rules: [RULE0; 2], file: TzFile::new(), old_tz: MBuf::empty(), initialized: false, strings: StrPool { head: null_mut() } });

static TZ_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

#[inline]
fn with_zone<R>(f: impl FnOnce(&mut Zone) -> R) -> R {
    let _g = TZ_LOCK.guard();
    unsafe { ZONE.with_unsync(f) }
}

fn tzset_internal(z: &mut Zone, always: bool) {
    if z.initialized && !always {
        return;
    }
    z.initialized = true;
    let mut tz: Option<&[u8]> = None;
    if let Some(mut s) = sys::getenv(b"TZ") {
        if s.is_empty() {
            s = b"Universal";
        }
        if s[0] == b':' {
            s = &s[1..];
        }
        tz = Some(s);
    }
    if let Some(s) = tz
        && !z.old_tz.is_empty_block()
        && until_nul(&z.old_tz) == s
    {
        return;
    }
    let tz = tz.unwrap_or(TZDEFAULT);
    z.rules[0].name = None;
    z.rules[1].name = None;
    z.old_tz = MBuf::empty();
    z.old_tz = dup(tz);
    let mut buf = [0u8; 512];
    let owned: MBuf<u8>;
    let tzc: &[u8] = if tz.len() < buf.len() {
        buf[..tz.len()].copy_from_slice(tz);
        &buf[..tz.len() + 1]
    } else {
        owned = dup(tz);
        owned.get(..tz.len() + 1).unwrap_or(b"\0")
    };
    tzfile_read(z, tzc, 0);
    if z.file.used {
        return;
    }
    if tz.is_empty() || tz == TZDEFAULT {
        z.rules = [RULE0; 2];
        z.rules[0].name = Some(c"UTC");
        z.rules[1].name = Some(c"UTC");
        z.rules[0].change = -1;
        z.rules[1].change = -1;
        update_vars(&z.rules);
        return;
    }
    tzset_parse_tz(z, tzc);
}

fn dup(s: &[u8]) -> MBuf<u8> {
    match MBuf::filled(s.len() + 1, 0u8) {
        Some(mut p) => {
            p[..s.len()].copy_from_slice(s);
            p
        }
        None => MBuf::empty(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tzset() {
    tzset_now()
}

pub fn tzset_now() {
    with_zone(|z| {
        tzset_internal(z, true);
        if !z.file.used {
            tzname_set(0, name_ptr(z.rules[0].name));
            tzname_set(1, name_ptr(z.rules[1].name));
        }
    })
}

fn tzfile_compute(z: &mut Zone, timer: i64, use_localtime: bool, tp: &mut Tm) -> (i64, i32) {
    if use_localtime {
        tzname_set(0, null_mut());
        tzname_set(1, null_mut());
        let ntrans = z.file.trans.len();
        let ti: usize;
        let mut spec_done = false;
        if ntrans == 0 || timer < z.file.trans[0] {
            let (f, strings) = (&z.file, &mut z.strings);
            let types = f.types.as_slice();
            let mut name = |t: &TType| f.type_name(strings, t);
            let mut i = 0;
            while i < types.len() && types[i].isdst != 0 {
                if tzname_get(1).is_null() {
                    tzname_set(1, name(&types[i]));
                }
                i += 1;
            }
            if i == types.len() {
                i = 0;
            }
            tzname_set(0, name(&types[i]));
            if tzname_get(1).is_null() {
                let mut j = i;
                while j < types.len() {
                    if types[j].isdst != 0 {
                        tzname_set(1, name(&types[j]));
                        break;
                    }
                    j += 1;
                }
            }
            ti = i;
        } else if timer >= z.file.trans[ntrans - 1] {
            if z.file.tzspec.is_empty_block() {
                ti = found(z, ntrans);
            } else {
                if let Some(r) = z.file.spec_rules {
                    z.rules = r;
                    update_vars(&z.rules);
                } else {
                    let spec = until_nul(&z.file.tzspec);
                    let mut specz = [0u8; 256];
                    let n = spec.len().min(255);
                    specz[..n].copy_from_slice(&spec[..n]);
                    if tzset_parse_tz(z, &specz[..n + 1]) {
                        z.file.spec_rules = Some(z.rules);
                    }
                }
                let mut tm2 = *tp;
                if !offtime(timer, 0, &mut tm2) {
                    ti = found_after_parse(z, ntrans);
                } else {
                    *tp = tm2;
                    tz_compute(&mut z.rules, timer, tp, true);
                    if z.file.spec_rules.is_some() {
                        z.file.spec_rules = Some(z.rules);
                    }
                    spec_done = true;
                    ti = 0;
                }
            }
        } else {
            let i = z.file.trans.partition_point(|&t| t <= timer);
            ti = found(z, i);
        }
        if !spec_done {
            let f = &z.file;
            let info = f.types[ti];
            __daylight.store(f.daylight_saved, Relaxed);
            __timezone.store(-f.stdoff, Relaxed);
            if tzname_get(0).is_null() {
                tzname_set(0, name_ptr(z.strings.intern_c(f.names())));
            }
            if tzname_get(1).is_null() {
                tzname_set(1, tzname_get(0));
            }
            tp.tm_isdst = info.isdst as c_int;
            tp.tm_zone = tzname_get(info.isdst as usize);
            tp.tm_gmtoff = info.offset as c_long;
        }
    }
    let leaps = z.file.leaps.as_slice();
    if leaps.is_empty() {
        return (0, 0);
    }
    let mut i = leaps.len();
    loop {
        if i == 0 {
            return (0, 0);
        }
        i -= 1;
        if timer >= leaps[i].transition {
            break;
        }
    }
    let correct = leaps[i].change;
    let mut hit = 0;
    if timer == leaps[i].transition && leaps[i].change > (if i == 0 { 0 } else { leaps[i - 1].change }) {
        hit = 1;
        while i > 0 && leaps[i].transition == leaps[i - 1].transition + 1 && leaps[i].change == leaps[i - 1].change + 1 {
            hit += 1;
            i -= 1;
        }
    }
    (correct, hit)
}

fn found(z: &mut Zone, i: usize) -> usize {
    let (f, strings) = (&z.file, &mut z.strings);
    let (types, idxs) = (f.types.as_slice(), f.idxs.as_slice());
    let mut name = |t: &TType| f.type_name(strings, t);
    let t0 = &types[idxs[i - 1] as usize];
    tzname_set(t0.isdst as usize, name(t0));
    let mut j = i;
    while j < idxs.len() {
        let t = &types[idxs[j] as usize];
        let dst = t.isdst as usize;
        if tzname_get(dst).is_null() {
            tzname_set(dst, name(t));
            if !tzname_get(1 - dst).is_null() {
                break;
            }
        }
        j += 1;
    }
    if tzname_get(0).is_null() {
        tzname_set(0, tzname_get(1));
    }
    idxs[i - 1] as usize
}

fn found_after_parse(z: &mut Zone, n: usize) -> usize {
    let (f, strings) = (&z.file, &mut z.strings);
    let (types, idxs) = (f.types.as_slice(), f.idxs.as_slice());
    let n = n.min(idxs.len());
    if n == 0 {
        return 0;
    }
    let t0 = &types[idxs[n - 1] as usize];
    tzname_set(t0.isdst as usize, f.type_name(strings, t0));
    if tzname_get(0).is_null() {
        tzname_set(0, tzname_get(1));
    }
    idxs[n - 1] as usize
}

fn tz_convert_locked(z: &mut Zone, timer: i64, use_localtime: bool, tm: &mut Tm, always: bool) -> bool {
    tzset_internal(z, always && use_localtime);
    let leap_correction: i64;
    let leap_extra: i32;
    if z.file.used {
        let (c, e) = tzfile_compute(z, timer, use_localtime, tm);
        leap_correction = c;
        leap_extra = e;
    } else {
        if use_localtime {
            if !offtime(timer, 0, tm) {
                return false;
            }
            tz_compute(&mut z.rules, timer, tm, true);
        }
        leap_correction = 0;
        leap_extra = 0;
    }
    if !use_localtime {
        tm.tm_isdst = 0;
        tm.tm_zone = c"GMT".as_ptr();
        tm.tm_gmtoff = 0;
    }
    if offtime(timer, tm.tm_gmtoff - leap_correction, tm) {
        tm.tm_sec += leap_extra;
        true
    } else {
        false
    }
}

pub(crate) fn tz_convert(timer: i64, use_localtime: bool, tm: &mut Tm, always: bool) -> bool {
    with_zone(|z| tz_convert_locked(z, timer, use_localtime, tm, always))
}

pub(crate) fn tz_convert_static(timer: i64, use_localtime: bool, buf: &SyncCell<Tm>, always: bool) -> *mut Tm {
    with_zone(|z| {
        let ok = unsafe { buf.with_unsync(|tm| tz_convert_locked(z, timer, use_localtime, tm, always)) };
        if ok { buf.as_ptr() } else { null_mut() }
    })
}

pub(crate) fn tzname_ptr(i: usize) -> *const c_char {
    tzname_get(i)
}

pub fn names() -> ([&'static [u8]; 2], i64, bool) {
    let mut out: [&'static [u8]; 2] = [b"", b""];
    for (i, o) in out.iter_mut().enumerate() {
        if let Some(s) = unsafe { rusty_libc_core::ffi::cstr(tzname_get(i)) } {
            *o = s.to_bytes();
        }
    }
    (out, __timezone.load(Relaxed), __daylight.load(Relaxed) != 0)
}

