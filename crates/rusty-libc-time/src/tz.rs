#![allow(non_upper_case_globals)]
use crate::calendar::{Tm, offtime};
use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::{null, null_mut};
use rusty_libc_core::{env, syscall};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __tzname: [*mut c_char; 2] = [c"GMT".as_ptr().cast_mut(), c"GMT".as_ptr().cast_mut()];
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __daylight: c_int = 0;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __timezone: c_long = 0;

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

const TZDEFAULT: &[u8] = b"/etc/localtime";
const TZDEFRULES: &[u8] = b"posixrules";
const TZDIR: &[u8] = b"/usr/share/zoneinfo";

unsafe fn alloc<T>(n: usize) -> *mut T {
    unsafe { rusty_libc_malloc::malloc((n * core::mem::size_of::<T>()).max(1)).cast() }
}

unsafe fn release<T>(p: *mut T) {
    unsafe {
        if !p.is_null() {
            rusty_libc_malloc::free(p.cast::<c_void>());
        }
    }
}

unsafe fn cstrlen(s: *const u8) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

unsafe fn cslice<'a>(s: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(s, cstrlen(s)) }
}

struct TzStr {
    next: *mut TzStr,
    len: usize,
}

static mut TZSTRINGS: *mut TzStr = null_mut();

unsafe fn tzstring_len(s: *const u8, len: usize) -> *const u8 {
    unsafe {
        let mut u: *mut TzStr = null_mut();
        let mut t = TZSTRINGS;
        while !t.is_null() {
            if len <= (*t).len {
                let data = t.add(1).cast::<u8>();
                let p = data.add((*t).len - len);
                if core::slice::from_raw_parts(p, len) == core::slice::from_raw_parts(s, len) {
                    return p;
                }
            }
            u = t;
            t = (*t).next;
        }
        let new: *mut TzStr = rusty_libc_malloc::malloc(core::mem::size_of::<TzStr>() + len + 1).cast();
        if new.is_null() {
            return null();
        }
        (*new).next = null_mut();
        (*new).len = len;
        let data = new.add(1).cast::<u8>();
        core::ptr::copy_nonoverlapping(s, data, len);
        *data.add(len) = 0;
        if u.is_null() {
            TZSTRINGS = new;
        } else {
            (*u).next = new;
        }
        data
    }
}

unsafe fn tzstring(s: *const u8) -> *const u8 {
    unsafe { tzstring_len(s, cstrlen(s)) }
}

const J0: u8 = 0;
const J1: u8 = 1;
const M: u8 = 2;

#[derive(Clone, Copy)]
struct Rule {
    name: *const u8,
    typ: u8,
    m: u16,
    n: u16,
    d: u16,
    secs: i32,
    offset: i32,
    change: i64,
    computed_for: i32,
}

const RULE0: Rule = Rule { name: null(), typ: J0, m: 0, n: 0, d: 0, secs: 0, offset: 0, change: 0, computed_for: 0 };

static mut RULES: [Rule; 2] = [RULE0; 2];

const MON_YDAY: [[u16; 13]; 2] = [
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
    [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

fn isleap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

#[allow(clippy::deref_addrof)]
unsafe fn rules() -> &'static mut [Rule; 2] {
    unsafe { &mut *(&raw mut RULES) }
}

unsafe fn update_vars() {
    unsafe {
        let r = rules();
        __daylight = (r[0].offset != r[1].offset) as c_int;
        __timezone = -(r[0].offset as c_long);
        __tzname[0] = r[0].name as *mut c_char;
        __tzname[1] = r[1].name as *mut c_char;
    }
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

unsafe fn parse_tzname(c: &mut Cur, which: usize) -> bool {
    unsafe {
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
        let name = tzstring_len(c.s.as_ptr().add(st), len);
        if name.is_null() {
            return false;
        }
        rules()[which].name = name;
        c.i = p;
        true
    }
}

unsafe fn parse_offset(c: &mut Cur, which: usize) -> bool {
    unsafe {
        let r = rules();
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
}

unsafe fn parse_rule(c: &mut Cur, which: usize) -> bool {
    unsafe {
        let r = &mut rules()[which];
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
}

unsafe fn tzset_parse_tz(tz: &[u8]) {
    unsafe {
        let r = rules();
        *r = [RULE0; 2];
        r[0].name = c"".as_ptr().cast();
        r[1].name = c"".as_ptr().cast();
        let mut c = Cur { s: tz, i: 0 };
        if parse_tzname(&mut c, 0) && parse_offset(&mut c, 0) {
            if c.at(0) != 0 {
                if parse_tzname(&mut c, 1) {
                    parse_offset(&mut c, 1);
                    if c.at(0) == 0 || (c.at(0) == b',' && c.at(1) == 0) {
                        let r = rules();
                        tzfile_default(r[0].name, r[1].name, r[0].offset, r[1].offset);
                        if (*tzf()).used {
                            release(OLD_TZ);
                            OLD_TZ = null_mut();
                            return;
                        }
                    }
                }
                if parse_rule(&mut c, 0) {
                    parse_rule(&mut c, 1);
                }
            } else {
                let r = rules();
                r[1].name = r[0].name;
                r[1].offset = r[0].offset;
            }
        }
        update_vars();
    }
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

unsafe fn tz_compute(timer: i64, tm: &mut Tm, use_localtime: bool) {
    unsafe {
        let r = rules();
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
            tm.tm_zone = __tzname[isdst as usize];
            tm.tm_gmtoff = r[isdst as usize].offset as c_long;
        }
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
    trans: *mut i64,
    ntrans: usize,
    idxs: *mut u8,
    types: *mut TType,
    ntypes: usize,
    names_base: *mut u8,
    names: *mut u8,
    leaps: *mut Leap,
    nleaps: usize,
    tzspec: *mut u8,
    stdoff: i64,
    dstoff: i64,
    daylight_saved: c_int,
    default_names: bool,
    nchars1: usize,
}

static mut TZFILE: TzFile = TzFile {
    used: false,
    dev: 0,
    ino: 0,
    mtime: 0,
    trans: null_mut(),
    ntrans: 0,
    idxs: null_mut(),
    types: null_mut(),
    ntypes: 0,
    names_base: null_mut(),
    names: null_mut(),
    leaps: null_mut(),
    nleaps: 0,
    tzspec: null_mut(),
    stdoff: 0,
    dstoff: 0,
    daylight_saved: 0,
    default_names: false,
    nchars1: 0,
};

unsafe fn tzf() -> *mut TzFile {
    &raw mut TZFILE
}

unsafe fn free_tzfile_data(f: &mut TzFile) {
    unsafe {
        release(f.trans);
        release(f.idxs);
        release(f.types);
        release(f.names_base);
        release(f.leaps);
        release(f.tzspec);
        f.trans = null_mut();
        f.idxs = null_mut();
        f.types = null_mut();
        f.names_base = null_mut();
        f.names = null_mut();
        f.leaps = null_mut();
        f.tzspec = null_mut();
        f.ntrans = 0;
        f.ntypes = 0;
        f.nleaps = 0;
        f.default_names = false;
        f.nchars1 = 0;
    }
}

fn be32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> i64 {
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

const SYS_OPENAT: usize = 257;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;
const SYS_FSTAT: usize = 5;
const SYS_NEWFSTATAT: usize = 262;
const AT_FDCWD: usize = -100isize as usize;
const O_RDONLY_CLOEXEC: usize = 0o2000000;

#[repr(C)]
struct KStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _unused: [i64; 3],
}

fn secure() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static S: AtomicU8 = AtomicU8::new(2);
    let v = S.load(Ordering::Relaxed);
    if v != 2 {
        return v == 1;
    }
    let s = crate::vdso::auxv_entry(23) != 0;
    S.store(s as u8, Ordering::Relaxed);
    s
}

unsafe fn tzfile_read(file: &[u8], extra: usize) {
    unsafe {
        let f = &mut *tzf();
        let was_using = f.used;
        f.used = false;
        let fname = &file[..file.iter().position(|&c| c == 0).unwrap_or(file.len())];
        if fname.is_empty() {
            free_tzfile_data(f);
            return;
        }
        if secure()
            && ((fname[0] == b'/' && fname != TZDEFAULT && !fname.starts_with(TZDIR)) || fname.windows(3).any(|w| w == b"../"))
        {
            free_tzfile_data(f);
            return;
        }
        let mut path = [0u8; 4352];
        let plen = if fname[0] != b'/' {
            let d = env::getenv(b"TZDIR");
            let dir: &[u8] = if d.is_null() || *d == 0 { TZDIR } else { cslice(d.cast()) };
            if dir.len() + 1 + fname.len() + 1 > path.len() {
                free_tzfile_data(f);
                return;
            }
            path[..dir.len()].copy_from_slice(dir);
            path[dir.len()] = b'/';
            path[dir.len() + 1..dir.len() + 1 + fname.len()].copy_from_slice(fname);
            dir.len() + 1 + fname.len()
        } else {
            if fname.len() + 1 > path.len() {
                free_tzfile_data(f);
                return;
            }
            path[..fname.len()].copy_from_slice(fname);
            fname.len()
        };
        path[plen] = 0;
        let mut st: KStat = core::mem::zeroed();
        if was_using
            && syscall::check(syscall::syscall4(SYS_NEWFSTATAT, AT_FDCWD, path.as_ptr() as usize, &mut st as *mut KStat as usize, 0)).is_ok()
            && f.ino == st.st_ino
            && f.dev == st.st_dev
            && f.mtime == st.st_mtime
        {
            f.used = true;
            return;
        }
        let fd = syscall::syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY_CLOEXEC, 0);
        if syscall::check(fd).is_err() {
            free_tzfile_data(f);
            return;
        }
        let ok = syscall::check(syscall::syscall2(SYS_FSTAT, fd, &mut st as *mut KStat as usize)).is_ok();
        let mut data: *mut u8 = null_mut();
        let mut len = 0usize;
        if ok {
            free_tzfile_data(f);
            f.dev = st.st_dev;
            f.ino = st.st_ino;
            f.mtime = st.st_mtime;
            let size = st.st_size.clamp(0, 64 << 20) as usize;
            data = alloc::<u8>(size + 1);
            if !data.is_null() {
                while len < size {
                    let r = syscall::syscall3(SYS_READ, fd, data.add(len) as usize, size - len);
                    match syscall::check(r) {
                        Ok(0) => break,
                        Ok(n) => len += n,
                        Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
                        Err(_) => break,
                    }
                }
            }
        }
        syscall::syscall1(SYS_CLOSE, fd);
        if data.is_null() {
            return;
        }
        let parsed = parse_tzif(f, core::slice::from_raw_parts(data, len), extra);
        release(data);
        if !parsed {
            free_tzfile_data(f);
            return;
        }
        f.used = true;
        let ntypes = f.ntypes;
        let types = core::slice::from_raw_parts(f.types, ntypes);
        let idxs = core::slice::from_raw_parts(f.idxs, f.ntrans);
        let trans_n = f.ntrans;
        let name_of = |t: &TType| tzstring(f.names.add(t.idx as usize));
        __tzname[0] = null_mut();
        __tzname[1] = null_mut();
        let mut i = trans_n;
        while i > 0 {
            i -= 1;
            let t = &types[idxs[i] as usize];
            let dst = t.isdst as usize;
            if __tzname[dst].is_null() {
                __tzname[dst] = name_of(t) as *mut c_char;
                if !__tzname[1 - dst].is_null() {
                    break;
                }
            }
        }
        if __tzname[0].is_null() {
            __tzname[0] = tzstring(f.names) as *mut c_char;
        }
        if __tzname[1].is_null() {
            __tzname[1] = __tzname[0];
        }
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
        __daylight = f.daylight_saved;
        __timezone = -f.stdoff;
    }
}

unsafe fn parse_tzif(f: &mut TzFile, d: &[u8], extra: usize) -> bool {
    unsafe {
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
            let (isgmt, isstd, nleaps, ntrans, ntypes, chars) =
                (isgmt as usize, isstd as usize, nleaps as usize, ntrans as usize, ntypes as usize, chars as usize);
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
            f.trans = alloc::<i64>(ntrans);
            f.leaps = alloc::<Leap>(nleaps);
            f.types = alloc::<TType>(ntypes);
            f.idxs = alloc::<u8>(ntrans);
            f.names_base = alloc::<u8>(chars + 1 + extra);
            if width == 8 && tzspec_len > 0 {
                f.tzspec = alloc::<u8>(tzspec_len);
            }
            if f.trans.is_null() || f.leaps.is_null() || f.types.is_null() || f.idxs.is_null() || f.names_base.is_null() {
                return false;
            }
            f.ntrans = ntrans;
            f.ntypes = ntypes;
            f.nleaps = nleaps;
            let need_total = ntrans * width + ntrans + ntypes * 6 + chars + nleaps * (width + 4) + isstd + isgmt;
            if d.len() < pos + need_total {
                return false;
            }
            for i in 0..ntrans {
                let b = &d[pos + i * width..];
                *f.trans.add(i) = if width == 4 { be32(b) as i64 } else { be64(b) };
            }
            pos += ntrans * width;
            for i in 0..ntrans {
                let v = d[pos + i];
                if v as usize >= ntypes {
                    return false;
                }
                *f.idxs.add(i) = v;
            }
            pos += ntrans;
            for i in 0..ntypes {
                let b = &d[pos + i * 6..];
                let isdst = b[4];
                let idx = b[5];
                if isdst > 1 || idx as usize > chars {
                    return false;
                }
                *f.types.add(i) = TType { offset: be32(b), isdst, idx, isstd: 0, isgmt: 0 };
            }
            pos += ntypes * 6;
            core::ptr::copy_nonoverlapping(d.as_ptr().add(pos), f.names_base, chars);
            *f.names_base.add(chars) = 0;
            f.names = f.names_base;
            f.nchars1 = chars + 1;
            pos += chars;
            for i in 0..nleaps {
                let b = &d[pos + i * (width + 4)..];
                let transition = if width == 4 { be32(b) as i64 } else { be64(b) };
                let change = be32(&b[width..]) as i64;
                *f.leaps.add(i) = Leap { transition, change };
            }
            pos += nleaps * (width + 4);
            for i in 0..isstd {
                (*f.types.add(i)).isstd = (d[pos + i] != 0) as u8;
            }
            pos += isstd;
            for i in 0..isgmt {
                (*f.types.add(i)).isgmt = (d[pos + i] != 0) as u8;
            }
            pos += isgmt;
            if !f.tzspec.is_null() {
                if d.len() >= pos + tzspec_len && d[pos] == b'\n' {
                    core::ptr::copy_nonoverlapping(d.as_ptr().add(pos + 1), f.tzspec, tzspec_len - 1);
                    *f.tzspec.add(tzspec_len - 1) = 0;
                    if *f.tzspec == 0 {
                        release(f.tzspec);
                        f.tzspec = null_mut();
                    }
                } else {
                    release(f.tzspec);
                    f.tzspec = null_mut();
                }
            }
            return true;
        }
    }
}

unsafe fn tzfile_default(std: *const u8, dst: *const u8, stdoff: i32, dstoff: i32) {
    unsafe {
        let stdlen = cstrlen(std) + 1;
        let dstlen = cstrlen(dst) + 1;
        let mut name = [0u8; 16];
        name[..TZDEFRULES.len()].copy_from_slice(TZDEFRULES);
        tzfile_read(&name, stdlen + dstlen);
        let f = &mut *tzf();
        if !f.used {
            return;
        }
        if f.ntypes < 2 {
            f.used = false;
            return;
        }
        let cp = f.names_extra_ptr();
        core::ptr::copy_nonoverlapping(std, cp, stdlen);
        core::ptr::copy_nonoverlapping(dst, cp.add(stdlen), dstlen);
        f.names = cp;
        f.default_names = true;
        f.ntypes = 2;
        let mut isdst = false;
        for i in 0..f.ntrans {
            let tt = *f.types.add(*f.idxs.add(i) as usize);
            *f.idxs.add(i) = tt.isdst;
            if tt.isgmt != 0 {
            } else if isdst && tt.isstd == 0 {
                *f.trans.add(i) += dstoff as i64 - f.dstoff;
            } else {
                *f.trans.add(i) += stdoff as i64 - f.stdoff;
            }
            isdst = tt.isdst != 0;
        }
        f.stdoff = stdoff as i64;
        f.dstoff = dstoff as i64;
        let t = f.types;
        *t = TType { offset: stdoff, isdst: 0, idx: 0, isstd: (*t).isstd, isgmt: (*t).isgmt };
        *t.add(1) = TType { offset: dstoff, isdst: 1, idx: stdlen as u8, isstd: (*t.add(1)).isstd, isgmt: (*t.add(1)).isgmt };
        __tzname[0] = std as *mut c_char;
        __tzname[1] = dst as *mut c_char;
        __timezone = -(stdoff as c_long);
        f.dev = 0;
        f.ino = 0;
        f.mtime = 0;
    }
}

impl TzFile {
    unsafe fn names_extra_ptr(&self) -> *mut u8 {
        unsafe { self.names_base.add(self.nchars1) }
    }
}

static mut OLD_TZ: *mut u8 = null_mut();
static mut INITIALIZED: bool = false;

unsafe fn dup(s: &[u8]) -> *mut u8 {
    unsafe {
        let p = alloc::<u8>(s.len() + 1);
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
            *p.add(s.len()) = 0;
        }
        p
    }
}

static TZ_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

unsafe fn tzset_internal(always: bool) {
    unsafe {
        if INITIALIZED && !always {
            return;
        }
        INITIALIZED = true;
        let envtz = env::getenv(b"TZ");
        let mut tz: Option<&[u8]> = None;
        if !envtz.is_null() {
            let mut s = cslice(envtz.cast());
            if s.is_empty() {
                s = b"Universal";
            }
            if s[0] == b':' {
                s = &s[1..];
            }
            tz = Some(s);
        }
        if let Some(s) = tz
            && !OLD_TZ.is_null()
            && cslice(OLD_TZ) == s
        {
            return;
        }
        let tz = tz.unwrap_or(TZDEFAULT);
        let r = rules();
        r[0].name = null();
        r[1].name = null();
        release(OLD_TZ);
        OLD_TZ = dup(tz);
        let mut buf = [0u8; 512];
        let owned: *mut u8;
        let tzc: &[u8] = if tz.len() < buf.len() {
            buf[..tz.len()].copy_from_slice(tz);
            owned = null_mut();
            &buf[..tz.len() + 1]
        } else {
            owned = dup(tz);
            core::slice::from_raw_parts(owned, tz.len() + 1)
        };
        tzfile_read(tzc, 0);
        if (*tzf()).used {
            release(owned);
            return;
        }
        if tz.is_empty() || tz == TZDEFAULT {
            *rules() = [RULE0; 2];
            let r = rules();
            r[0].name = c"UTC".as_ptr().cast();
            r[1].name = c"UTC".as_ptr().cast();
            r[0].change = -1;
            r[1].change = -1;
            update_vars();
            release(owned);
            return;
        }
        tzset_parse_tz(tzc);
        release(owned);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tzset() {
    unsafe {
        let _g = TZ_LOCK.guard();
        tzset_internal(true);
        if !(*tzf()).used {
            let r = rules();
            __tzname[0] = r[0].name as *mut c_char;
            __tzname[1] = r[1].name as *mut c_char;
        }
    }
}

unsafe fn tzfile_compute(timer: i64, use_localtime: bool, tp: &mut Tm) -> (i64, i32) {
    unsafe {
        let f = &mut *tzf();
        if use_localtime {
            __tzname[0] = null_mut();
            __tzname[1] = null_mut();
            let types = core::slice::from_raw_parts(f.types, f.ntypes);
            let trans = core::slice::from_raw_parts(f.trans, f.ntrans);
            let idxs = core::slice::from_raw_parts(f.idxs, f.ntrans);
            let name = |t: &TType| tzstring(f.names.add(t.idx as usize)) as *mut c_char;
            let found = |i: usize| -> usize {
                let t0 = &types[idxs[i - 1] as usize];
                __tzname[t0.isdst as usize] = name(t0);
                let mut j = i;
                while j < trans.len() {
                    let t = &types[idxs[j] as usize];
                    let dst = t.isdst as usize;
                    if __tzname[dst].is_null() {
                        __tzname[dst] = name(t);
                        if !__tzname[1 - dst].is_null() {
                            break;
                        }
                    }
                    j += 1;
                }
                if __tzname[0].is_null() {
                    __tzname[0] = __tzname[1];
                }
                idxs[i - 1] as usize
            };
            let ti: usize;
            let mut spec_done = false;
            if trans.is_empty() || timer < trans[0] {
                let mut i = 0;
                while i < types.len() && types[i].isdst != 0 {
                    if __tzname[1].is_null() {
                        __tzname[1] = name(&types[i]);
                    }
                    i += 1;
                }
                if i == types.len() {
                    i = 0;
                }
                __tzname[0] = name(&types[i]);
                if __tzname[1].is_null() {
                    let mut j = i;
                    while j < types.len() {
                        if types[j].isdst != 0 {
                            __tzname[1] = name(&types[j]);
                            break;
                        }
                        j += 1;
                    }
                }
                ti = i;
            } else if timer >= trans[trans.len() - 1] {
                if f.tzspec.is_null() {
                    ti = found(trans.len());
                } else {
                    let spec = cslice(f.tzspec);
                    let mut specz = [0u8; 256];
                    let n = spec.len().min(255);
                    specz[..n].copy_from_slice(&spec[..n]);
                    tzset_parse_tz(&specz[..n + 1]);
                    let f = &mut *tzf();
                    let mut tm2 = *tp;
                    if !offtime(timer, 0, &mut tm2) {
                        ti = found_after_parse(f, trans.len());
                    } else {
                        *tp = tm2;
                        tz_compute(timer, tp, true);
                        spec_done = true;
                        ti = 0;
                    }
                }
            } else {
                let i = trans.partition_point(|&t| t <= timer);
                ti = found(i);
            }
            if !spec_done {
                let f = &mut *tzf();
                let types = core::slice::from_raw_parts(f.types, f.ntypes);
                let info = types[ti];
                __daylight = f.daylight_saved;
                __timezone = -f.stdoff;
                if __tzname[0].is_null() {
                    __tzname[0] = tzstring(f.names) as *mut c_char;
                }
                if __tzname[1].is_null() {
                    __tzname[1] = __tzname[0];
                }
                tp.tm_isdst = info.isdst as c_int;
                tp.tm_zone = __tzname[info.isdst as usize];
                tp.tm_gmtoff = info.offset as c_long;
            }
        }
        let f = &*tzf();
        if f.nleaps == 0 {
            return (0, 0);
        }
        let leaps = core::slice::from_raw_parts(f.leaps, f.nleaps);
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
}

unsafe fn found_after_parse(f: &mut TzFile, n: usize) -> usize {
    unsafe {
        let types = core::slice::from_raw_parts(f.types, f.ntypes);
        let idxs = core::slice::from_raw_parts(f.idxs, f.ntrans);
        let t0 = &types[idxs[n - 1] as usize];
        __tzname[t0.isdst as usize] = tzstring(f.names.add(t0.idx as usize)) as *mut c_char;
        if __tzname[0].is_null() {
            __tzname[0] = __tzname[1];
        }
        idxs[n - 1] as usize
    }
}

pub(crate) unsafe fn tz_convert(timer: i64, use_localtime: bool, tp: *mut Tm, always: bool) -> *mut Tm {
    unsafe {
        let _g = TZ_LOCK.guard();
        tzset_internal(always && use_localtime);
        let tm = &mut *tp;
        let leap_correction: i64;
        let leap_extra: i32;
        if (*tzf()).used {
            let (c, e) = tzfile_compute(timer, use_localtime, tm);
            leap_correction = c;
            leap_extra = e;
        } else {
            if use_localtime {
                if !offtime(timer, 0, tm) {
                    return null_mut();
                }
                tz_compute(timer, tm, true);
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
            tp
        } else {
            null_mut()
        }
    }
}

#[allow(clippy::deref_addrof)]
pub(crate) fn tzname_ptr(i: usize) -> *const c_char {
    unsafe { (*(&raw const __tzname))[i] }
}

#[allow(clippy::deref_addrof)]
pub fn names() -> ([&'static [u8]; 2], i64, bool) {
    unsafe {
        let mut out: [&'static [u8]; 2] = [b"", b""];
        for (i, o) in out.iter_mut().enumerate() {
            let p = (*(&raw const __tzname))[i];
            if !p.is_null() {
                *o = cslice(p.cast());
            }
        }
        (out, __timezone, __daylight != 0)
    }
}

