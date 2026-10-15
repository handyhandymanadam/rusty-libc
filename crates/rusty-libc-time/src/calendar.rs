use crate::clock::TimeT;
use crate::sys;
use crate::tz::{self, tz_convert};
use core::ffi::{c_char, c_int, c_long};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI64, Ordering::Relaxed};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{Errno, errno};

const EINVAL: i32 = 22;
const EOVERFLOW: i32 = 75;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Tm {
    pub tm_sec: c_int,
    pub tm_min: c_int,
    pub tm_hour: c_int,
    pub tm_mday: c_int,
    pub tm_mon: c_int,
    pub tm_year: c_int,
    pub tm_wday: c_int,
    pub tm_yday: c_int,
    pub tm_isdst: c_int,
    pub tm_gmtoff: c_long,
    pub tm_zone: *const c_char,
}

impl Default for Tm {
    fn default() -> Tm {
        Tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: null() }
    }
}

const MON_YDAY: [[i32; 13]; 2] = [
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
    [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

pub(crate) fn offtime(t: i64, offset: i64, tp: &mut Tm) -> bool {
    let (days, rem) = match t.checked_add(offset) {
        Some(total) if total >= 0 => ((total as u64 / 86400) as i64, (total as u64 % 86400) as i32),
        Some(total) => (total.div_euclid(86400), total.rem_euclid(86400) as i32),
        None => {
            let total = t as i128 + offset as i128;
            (total.div_euclid(86400) as i64, total.rem_euclid(86400) as i32)
        }
    };
    tp.tm_hour = rem / 3600;
    tp.tm_min = rem % 3600 / 60;
    tp.tm_sec = rem % 60;
    tp.tm_wday = if days >= 0 { ((4 + days as u64) % 7) as c_int } else { (4 + days).rem_euclid(7) as c_int };
    let z = days + 719_468;
    let (era, doe) = if z >= 0 { ((z as u64 / 146_097) as i64, (z as u64 % 146_097) as u32) } else { (z.div_euclid(146_097), z.rem_euclid(146_097) as u32) };
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + (m <= 2) as i64;
    let ty = y - 1900;
    if ty != ty as i32 as i64 {
        tp.tm_year = ty as i32;
        errno::set(EOVERFLOW);
        return false;
    }
    tp.tm_year = ty as i32;
    let leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) as usize;
    tp.tm_mon = (m - 1) as c_int;
    tp.tm_mday = d as c_int;
    tp.tm_yday = MON_YDAY[leap][(m - 1) as usize] + d as i32 - 1;
    true
}

const TM0: Tm = Tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: null() };

static TMBUF: SyncCell<Tm> = SyncCell::new(TM0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime_r(t: *const TimeT, tp: *mut Tm) -> *mut Tm {
    let t = unsafe { *sys::arg(t) };
    let tm = unsafe { sys::arg_mut(tp) };
    if tz_convert(t, false, tm, false) { tp } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime(t: *const TimeT) -> *mut Tm {
    let t = unsafe { *sys::arg(t) };
    tz::tz_convert_static(t, false, &TMBUF, false)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime_r(t: *const TimeT, tp: *mut Tm) -> *mut Tm {
    let t = unsafe { *sys::arg(t) };
    let tm = unsafe { sys::arg_mut(tp) };
    if tz_convert(t, true, tm, false) { tp } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime(t: *const TimeT) -> *mut Tm {
    let t = unsafe { *sys::arg(t) };
    tz::tz_convert_static(t, true, &TMBUF, true)
}

type Convert = fn(i64, &mut Tm) -> bool;

fn convert_gm(t: i64, tm: &mut Tm) -> bool {
    tz_convert(t, false, tm, false)
}

fn convert_local(t: i64, tm: &mut Tm) -> bool {
    tz_convert(t, true, tm, false)
}

fn shr(a: i64, b: u32) -> i64 {
    a >> b
}

fn isdst_differ(a: c_int, b: c_int) -> bool {
    ((a == 0) != (b == 0)) && a >= 0 && b >= 0
}

#[allow(clippy::too_many_arguments)]
fn ydhms_diff(year1: i64, yday1: i64, hour1: i64, min1: i64, sec1: i64, year0: i64, yday0: i64, hour0: i64, min0: i64, sec0: i64) -> i64 {
    let a4 = shr(year1, 2) + shr(1900, 2) - (year1 & 3 == 0) as i64;
    let b4 = shr(year0, 2) + shr(1900, 2) - (year0 & 3 == 0) as i64;
    let a100 = (a4 + (a4 < 0) as i64) / 25 - (a4 < 0) as i64;
    let b100 = (b4 + (b4 < 0) as i64) / 25 - (b4 < 0) as i64;
    let a400 = shr(a100, 2);
    let b400 = shr(b100, 2);
    let leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
    let years = year1 - year0;
    let days = 365 * years + yday1 - yday0 + leap_days;
    let hours = 24 * days + hour1 - hour0;
    let minutes = 60 * hours + min1 - min0;
    60 * minutes + sec1 - sec0
}

fn long_int_avg(a: i64, b: i64) -> i64 {
    shr(a, 1) + shr(b, 1) + ((a | b) & 1)
}

fn tm_diff(year: i64, yday: i64, hour: i64, min: i64, sec: i64, tp: &Tm) -> i64 {
    ydhms_diff(year, yday, hour, min, sec, tp.tm_year as i64, tp.tm_yday as i64, tp.tm_hour as i64, tp.tm_min as i64, tp.tm_sec as i64)
}

fn ranged_convert(convert: Convert, t: &mut i64, tp: &mut Tm) -> Result<(), ()> {
    let t1 = *t;
    if convert(t1, tp) {
        return Ok(());
    }
    if errno::get() != EOVERFLOW {
        return Err(());
    }
    let mut bad = t1;
    let mut ok = 0i64;
    let mut oktm = Tm { tm_sec: -1, ..Tm::default() };
    loop {
        let mid = long_int_avg(ok, bad);
        if mid == ok || mid == bad {
            break;
        }
        if convert(mid, tp) {
            ok = mid;
            oktm = *tp;
        } else if errno::get() != EOVERFLOW {
            return Err(());
        } else {
            bad = mid;
        }
    }
    if oktm.tm_sec < 0 {
        return Err(());
    }
    *t = ok;
    *tp = oktm;
    Ok(())
}

fn mktime_internal(tp: &mut Tm, convert: Convert, offset: &mut i64) -> i64 {
    let mut remaining_probes = 6;
    let mut sec = tp.tm_sec;
    let min = tp.tm_min as i64;
    let hour = tp.tm_hour as i64;
    let mday = tp.tm_mday as i64;
    let mon = tp.tm_mon;
    let year_requested = tp.tm_year;
    let isdst = tp.tm_isdst;
    let mut dst2 = 0;

    let mon_remainder = mon % 12;
    let negative_mon_remainder = (mon_remainder < 0) as i32;
    let mon_years = (mon / 12 - negative_mon_remainder) as i64;
    let year = year_requested as i64 + mon_years;
    let leap = {
        (year & 3) == 0 && (year % 100 != 0 || ((year / 100) & 3) == ((-19i64) & 3))
    };
    let mon_yday = MON_YDAY[leap as usize][(mon_remainder + 12 * negative_mon_remainder) as usize] as i64 - 1;
    let yday = mon_yday + mday;
    let off = *offset;
    let sec_requested = sec;
    sec = sec.clamp(0, 59);
    let negative_offset_guess = (0i64.wrapping_sub(off)) as i32;
    let t0 = ydhms_diff(year, yday, hour, min, sec as i64, 70, 0, 0, 0, negative_offset_guess as i64);
    let mut t = t0;
    let mut t1 = t0;
    let mut t2 = t0;
    let mut tm = Tm::default();

    loop {
        if ranged_convert(convert, &mut t, &mut tm).is_err() {
            return -1;
        }
        let dt = tm_diff(year, yday, hour, min, sec as i64, &tm);
        if dt == 0 {
            break;
        }
        if t == t1
            && t != t2
            && (tm.tm_isdst < 0 || (if isdst < 0 { dst2 <= (tm.tm_isdst != 0) as i32 } else { (isdst != 0) != (tm.tm_isdst != 0) }))
        {
            return finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm);
        }
        remaining_probes -= 1;
        if remaining_probes == 0 {
            errno::set(EOVERFLOW);
            return -1;
        }
        t1 = t2;
        t2 = t;
        t = t.wrapping_add(dt);
        dst2 = (tm.tm_isdst != 0) as i32;
    }

    if isdst_differ(isdst, tm.tm_isdst) {
        let dst_difference = (isdst == 0) as i64 - (tm.tm_isdst == 0) as i64;
        let stride = 601_200i64;
        let duration_max = 457_243_209i64;
        let delta_bound = duration_max / 2 + stride;
        let mut delta = stride;
        while delta < delta_bound {
            for direction in [-1i64, 1] {
                if let Some(mut ot) = t.checked_add(delta * direction) {
                    let mut otm = Tm::default();
                    if ranged_convert(convert, &mut ot, &mut otm).is_err() {
                        return -1;
                    }
                    if !isdst_differ(isdst, otm.tm_isdst) {
                        let gt = ot.wrapping_add(tm_diff(year, yday, hour, min, sec as i64, &otm));
                        if convert(gt, &mut tm) {
                            t = gt;
                            return finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm);
                        }
                        if errno::get() != EOVERFLOW {
                            return -1;
                        }
                    }
                }
            }
            delta += stride;
        }
        t = t.wrapping_add(3600 * dst_difference);
        if convert(t, &mut tm) {
            return finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm);
        }
        errno::set(EOVERFLOW);
        return -1;
    }
    finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm)
}

#[allow(clippy::too_many_arguments)]
fn finish(tp: &mut Tm, convert: Convert, offset: &mut i64, mut t: i64, t0: i64, neg_guess: i32, sec: c_int, sec_requested: c_int, mut tm: Tm) -> i64 {
    *offset = t.wrapping_sub(t0).wrapping_sub(neg_guess as i64);
    if sec_requested != tm.tm_sec {
        let mut adj = (sec == 0 && tm.tm_sec == 60) as i64;
        adj -= sec as i64;
        adj += sec_requested as i64;
        match t.checked_add(adj) {
            Some(n) => t = n,
            None => {
                errno::set(EOVERFLOW);
                return -1;
            }
        }
        if !convert(t, &mut tm) {
            return -1;
        }
    }
    *tp = tm;
    t
}

static LOCALTIME_OFFSET: AtomicI64 = AtomicI64::new(0);
static GMTIME_OFFSET: AtomicI64 = AtomicI64::new(0);

fn mktime_with(tm: &mut Tm, convert: Convert, state: &AtomicI64) -> i64 {
    let mut off = state.load(Relaxed);
    let t = mktime_internal(tm, convert, &mut off);
    state.store(off, Relaxed);
    t
}

pub fn mktime_tm(tm: &mut Tm) -> TimeT {
    tz::tzset_now();
    mktime_with(tm, convert_local, &LOCALTIME_OFFSET)
}

pub fn timegm_tm(tm: &mut Tm) -> TimeT {
    tm.tm_isdst = 0;
    mktime_with(tm, convert_gm, &GMTIME_OFFSET)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mktime(tp: *mut Tm) -> TimeT {
    mktime_tm(unsafe { sys::arg_mut(tp) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timelocal(tp: *mut Tm) -> TimeT {
    mktime_tm(unsafe { sys::arg_mut(tp) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timegm(tp: *mut Tm) -> TimeT {
    timegm_tm(unsafe { sys::arg_mut(tp) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dysize(year: c_int) -> c_int {
    if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 }
}

const AB_DAY: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const AB_MON: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

fn put_int(out: &mut [u8], n: &mut usize, v: i32, width: usize, digits: usize) {
    let mut tmp = [0u8; 16];
    let mut k = tmp.len();
    let mut u = v.unsigned_abs();
    loop {
        k -= 1;
        tmp[k] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    let mut nd = tmp.len() - k;
    while nd < digits {
        k -= 1;
        tmp[k] = b'0';
        nd += 1;
    }
    if v < 0 {
        k -= 1;
        tmp[k] = b'-';
    }
    let len = tmp.len() - k;
    for _ in len..width {
        out[*n] = b' ';
        *n += 1;
    }
    for &b in &tmp[k..] {
        out[*n] = b;
        *n += 1;
    }
}

fn asctime_text(tm: Option<&Tm>, out: &mut [u8; 128]) -> Option<usize> {
    let Some(tm) = tm else {
        errno::set(EINVAL);
        return None;
    };
    if tm.tm_year > i32::MAX - 1900 {
        errno::set(EOVERFLOW);
        return None;
    }
    let mut n = 0usize;
    let day: &[u8; 3] = if (0..7).contains(&tm.tm_wday) { AB_DAY[tm.tm_wday as usize] } else { b"???" };
    let mon: &[u8; 3] = if (0..12).contains(&tm.tm_mon) { AB_MON[tm.tm_mon as usize] } else { b"???" };
    out[..3].copy_from_slice(day);
    out[3] = b' ';
    out[4..7].copy_from_slice(mon);
    n = n.max(7);
    put_int(out, &mut n, tm.tm_mday, 3, 1);
    out[n] = b' ';
    n += 1;
    put_int(out, &mut n, tm.tm_hour, 0, 2);
    out[n] = b':';
    n += 1;
    put_int(out, &mut n, tm.tm_min, 0, 2);
    out[n] = b':';
    n += 1;
    put_int(out, &mut n, tm.tm_sec, 0, 2);
    out[n] = b' ';
    n += 1;
    put_int(out, &mut n, 1900i32.wrapping_add(tm.tm_year), 0, 1);
    out[n] = b'\n';
    n += 1;
    Some(n)
}

fn put_truncated(text: &[u8], buf: &mut [u8]) -> bool {
    let n = text.len();
    let keep = n.min(buf.len().saturating_sub(1));
    if !buf.is_empty() {
        buf[..keep].copy_from_slice(&text[..keep]);
        buf[keep] = 0;
    }
    if n >= buf.len() {
        errno::set(EOVERFLOW);
        return false;
    }
    true
}

pub fn asctime_into(tm: &Tm, buf: &mut [u8]) -> bool {
    let mut text = [0u8; 128];
    match asctime_text(Some(tm), &mut text) {
        Some(n) => put_truncated(&text[..n], buf),
        None => false,
    }
}

static ASCTIME_BUF: SyncCell<[u8; 114]> = SyncCell::new([0; 114]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime_r(tp: *const Tm, buf: *mut c_char) -> *mut c_char {
    let tm = unsafe { tp.as_ref() };
    let mut text = [0u8; 128];
    let Some(n) = asctime_text(tm, &mut text) else { return null_mut() };
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), 26) };
    if put_truncated(&text[..n], out) { buf } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime(tp: *const Tm) -> *mut c_char {
    let tm = unsafe { tp.as_ref() };
    asctime_static(tm)
}

fn asctime_static(tm: Option<&Tm>) -> *mut c_char {
    let mut text = [0u8; 128];
    let Some(n) = asctime_text(tm, &mut text) else { return null_mut() };
    let ok = unsafe { ASCTIME_BUF.with_unsync(|b| put_truncated(&text[..n], b)) };
    if ok { ASCTIME_BUF.as_ptr().cast() } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime(t: *const TimeT) -> *mut c_char {
    let t = unsafe { *sys::arg(t) };
    let p = tz::tz_convert_static(t, true, &TMBUF, true);
    asctime_static(unsafe { p.as_ref() })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime_r(t: *const TimeT, buf: *mut c_char) -> *mut c_char {
    let t = unsafe { *sys::arg(t) };
    let mut tm = Tm::default();
    let ok = tz_convert(t, true, &mut tm, false);
    unsafe { asctime_r(if ok { &tm } else { null() }, buf) }
}

pub fn to_utc(t: i64) -> Result<Tm, Errno> {
    let mut tm = Tm::default();
    if tz_convert(t, false, &mut tm, false) { Ok(tm) } else { Err(Errno(errno::get())) }
}

pub fn to_local(t: i64) -> Result<Tm, Errno> {
    let mut tm = Tm::default();
    if tz_convert(t, true, &mut tm, false) { Ok(tm) } else { Err(Errno(errno::get())) }
}

pub fn from_local(tm: &mut Tm) -> Result<i64, Errno> {
    errno::set(0);
    let t = mktime_tm(tm);
    if t == -1 && errno::get() == EOVERFLOW { Err(Errno(EOVERFLOW)) } else { Ok(t) }
}

pub fn from_utc(tm: &mut Tm) -> Result<i64, Errno> {
    errno::set(0);
    let t = timegm_tm(tm);
    if t == -1 && errno::get() == EOVERFLOW { Err(Errno(EOVERFLOW)) } else { Ok(t) }
}

