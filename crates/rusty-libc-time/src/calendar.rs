//! Broken-down time: `gmtime`, `localtime`, `mktime`, `timegm`, `asctime`, `ctime` and their
//! `_r` forms, for the 64-bit `time_t` of x86-64.
//!
//! `mktime` is a probing search, like glibc's: guess the offset, convert, correct by the error,
//! and handle DST gaps and overlaps (`tm_isdst` is honoured when it names a real alternative),
//! out-of-range fields (they are normalised) and leap seconds. `localtime` and `gmtime` return one
//! shared static `struct tm` (C89 rule, as glibc), `localtime` rereads `TZ` each call.
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

/// `struct tm` with glibc's layout (the `tm_gmtoff` and `tm_zone` extensions at the end).
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

/// Fill year, month, day, weekday, yearday and the time of day of `t + offset` (UTC offset in
/// seconds). False with errno `EOVERFLOW` when the year does not fit `tm_year`.
pub(crate) fn offtime(t: i64, offset: i64, tp: &mut Tm) -> bool {
    // common case: t + offset fits in i64 (every real time); the i128 sum is only for the extremes
    // (non-negative values, every time since 1970, take unsigned division: the same quotient and remainder as the
    // Euclidean forms without their sign fix-ups)
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
    // days since 1970-01-01 to a civil date (proleptic Gregorian)
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

/// The `struct tm` that `gmtime` and `localtime` return (one shared result, as C89 says); written only under the zone lock
/// (`tz::tz_convert_static`).
static TMBUF: SyncCell<Tm> = SyncCell::new(TM0);

/// `struct tm *gmtime_r(const time_t *, struct tm *)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime_r(t: *const TimeT, tp: *mut Tm) -> *mut Tm {
    // SAFETY: `t` points to a time_t (the C contract; a NULL faults, as in glibc).
    let t = unsafe { *sys::arg(t) };
    // SAFETY: `tp` is the caller's struct tm, not otherwise accessed during the call (a NULL faults, as in glibc).
    let tm = unsafe { sys::arg_mut(tp) };
    if tz_convert(t, false, tm, false) { tp } else { null_mut() }
}

/// `struct tm *gmtime(const time_t *)`: result in a static buffer shared with `localtime`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gmtime(t: *const TimeT) -> *mut Tm {
    // SAFETY: `t` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(t) };
    tz::tz_convert_static(t, false, &TMBUF, false)
}

/// `struct tm *localtime_r(const time_t *, struct tm *)`. Does not reread `TZ` after the first call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime_r(t: *const TimeT, tp: *mut Tm) -> *mut Tm {
    // SAFETY: `t` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(t) };
    // SAFETY: `tp` is the caller's struct tm, not otherwise accessed during the call.
    let tm = unsafe { sys::arg_mut(tp) };
    if tz_convert(t, true, tm, false) { tp } else { null_mut() }
}

/// `struct tm *localtime(const time_t *)`: rereads `TZ`; result in the static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn localtime(t: *const TimeT) -> *mut Tm {
    // SAFETY: `t` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(t) };
    tz::tz_convert_static(t, true, &TMBUF, true)
}

// ------------------------------------------------------------------ mktime

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

/// Seconds from (year0-yday0 hour0:min0:sec0) to (year1-yday1 hour1:min1:sec1), every minute
/// counted as 60 seconds.
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

/// Convert `*t` with `convert`; if the time is out of range for the conversion, move to the
/// nearest convertible time (binary search) and return that. Err means errno is set.
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

/// The search behind `mktime` and `timegm`. `offset` is the caller's guess state, kept between
/// calls (a static in each of mktime and timegm).
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
        // leapyear(year): year is relative to 1900
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
            // oscillating: the time lies in a spring-forward gap
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
        // no unusual DST offset nearby: assume one hour
        t = t.wrapping_add(3600 * dst_difference);
        if convert(t, &mut tm) {
            return finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm);
        }
        errno::set(EOVERFLOW);
        return -1;
    }
    finish(tp, convert, offset, t, t0, negative_offset_guess, sec, sec_requested, tm)
}

/// The common exit of `mktime_internal`: remember the offset, apply the requested seconds.
#[allow(clippy::too_many_arguments)]
fn finish(tp: &mut Tm, convert: Convert, offset: &mut i64, mut t: i64, t0: i64, neg_guess: i32, sec: c_int, sec_requested: c_int, mut tm: Tm) -> i64 {
    *offset = t.wrapping_sub(t0).wrapping_sub(neg_guess as i64);
    if sec_requested != tm.tm_sec {
        // adjust for the seconds actually requested; repair a false match on a leap second
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

/// The guess states of `mktime` and `timegm` (glibc's `localtime_offset` and timegm's static): only a starting point for
/// the search, so a race between two threads changes nothing but the number of probes. Relaxed atomics: no other memory
/// depends on them (Rust for Rustaceans p.256).
static LOCALTIME_OFFSET: AtomicI64 = AtomicI64::new(0);
static GMTIME_OFFSET: AtomicI64 = AtomicI64::new(0);

/// `mktime_internal` with a guess state kept in `state`.
fn mktime_with(tm: &mut Tm, convert: Convert, state: &AtomicI64) -> i64 {
    let mut off = state.load(Relaxed);
    let t = mktime_internal(tm, convert, &mut off);
    state.store(off, Relaxed);
    t
}

/// `mktime` on a Rust reference: local broken-down time to seconds, normalising `*tm` (-1 with `EOVERFLOW`).
pub fn mktime_tm(tm: &mut Tm) -> TimeT {
    tz::tzset_now();
    mktime_with(tm, convert_local, &LOCALTIME_OFFSET)
}

/// `timegm` on a Rust reference.
pub fn timegm_tm(tm: &mut Tm) -> TimeT {
    tm.tm_isdst = 0;
    mktime_with(tm, convert_gm, &GMTIME_OFFSET)
}

/// `time_t mktime(struct tm *)`: local broken-down time to seconds, normalising `*tp`. -1 with
/// `EOVERFLOW` when it cannot be represented. Sets `tzname` as `tzset` does.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mktime(tp: *mut Tm) -> TimeT {
    // SAFETY: `tp` is the caller's struct tm, not otherwise accessed during the call (a NULL faults, as in glibc).
    mktime_tm(unsafe { sys::arg_mut(tp) })
}

/// `time_t timelocal(struct tm *)`: the same as `mktime`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timelocal(tp: *mut Tm) -> TimeT {
    // SAFETY: as `mktime`.
    mktime_tm(unsafe { sys::arg_mut(tp) })
}

/// `time_t timegm(struct tm *)`: UTC broken-down time to seconds (`tm_isdst` is ignored).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timegm(tp: *mut Tm) -> TimeT {
    // SAFETY: as `mktime`.
    timegm_tm(unsafe { sys::arg_mut(tp) })
}

/// `int dysize(int year)`: days in the (full, e.g. 2024) year.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dysize(year: c_int) -> c_int {
    if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 }
}

// ------------------------------------------------------------------ asctime and ctime

const AB_DAY: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const AB_MON: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// Append `v` like `%<width>.<digits>d`.
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

/// The text of `"%.3s %.3s%3d %.2d:%.2d:%.2d %d\n"` for `tm` and its length; None (errno EINVAL for no `tm`, EOVERFLOW for
/// a year that does not fit) as glibc.
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

/// Copy the text into `buf` truncated like snprintf (with a NUL); false (errno EOVERFLOW) if it did not fit.
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

/// `asctime` into `buf` (capacity `buf.len()`): true on success, false with errno set.
pub fn asctime_into(tm: &Tm, buf: &mut [u8]) -> bool {
    let mut text = [0u8; 128];
    match asctime_text(Some(tm), &mut text) {
        Some(n) => put_truncated(&text[..n], buf),
        None => false,
    }
}

/// The buffer of `asctime` and `ctime` (114 bytes, as glibc's).
static ASCTIME_BUF: SyncCell<[u8; 114]> = SyncCell::new([0; 114]);

/// `char *asctime_r(const struct tm *, char *buf)`: `buf` is guaranteed 26 bytes only; a year of
/// five digits makes the result too long (EOVERFLOW, NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime_r(tp: *const Tm, buf: *mut c_char) -> *mut c_char {
    // SAFETY: `tp` is NULL or a valid struct tm (the C contract).
    let tm = unsafe { tp.as_ref() };
    let mut text = [0u8; 128];
    let Some(n) = asctime_text(tm, &mut text) else { return null_mut() };
    // SAFETY: `buf` has room for 26 bytes and nothing else accesses them during the call (asctime_r's contract; a
    // NULL faults, as in glibc).
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), 26) };
    if put_truncated(&text[..n], out) { buf } else { null_mut() }
}

/// `char *asctime(const struct tm *)`: static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asctime(tp: *const Tm) -> *mut c_char {
    // SAFETY: `tp` is NULL or a valid struct tm (the C contract).
    let tm = unsafe { tp.as_ref() };
    asctime_static(tm)
}

/// `asctime` into the shared static buffer.
fn asctime_static(tm: Option<&Tm>) -> *mut c_char {
    let mut text = [0u8; 128];
    let Some(n) = asctime_text(tm, &mut text) else { return null_mut() };
    // SAFETY: asctime and ctime are not thread-safe (C89: one shared result buffer, the same in glibc): the caller does
    // not run them in two threads at once, so nothing else touches the buffer during the call.
    let ok = unsafe { ASCTIME_BUF.with_unsync(|b| put_truncated(&text[..n], b)) };
    if ok { ASCTIME_BUF.as_ptr().cast() } else { null_mut() }
}

/// `char *ctime(const time_t *)`: `asctime(localtime(t))` (same static buffers).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime(t: *const TimeT) -> *mut c_char {
    // SAFETY: `t` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(t) };
    let p = tz::tz_convert_static(t, true, &TMBUF, true);
    // SAFETY: `p` is NULL or the static result buffer, just written; read here as `asctime(localtime(t))` reads it (the
    // same thread-unsafety as both).
    asctime_static(unsafe { p.as_ref() })
}

/// `char *ctime_r(const time_t *, char *buf)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctime_r(t: *const TimeT, buf: *mut c_char) -> *mut c_char {
    // SAFETY: `t` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(t) };
    let mut tm = Tm::default();
    let ok = tz_convert(t, true, &mut tm, false);
    // SAFETY: as `asctime_r` (only reached for a converted time: `localtime_r` failing gives `asctime_r(NULL)`).
    unsafe { asctime_r(if ok { &tm } else { null() }, buf) }
}

// ------------------------------------------------------------------ Rust API

/// UTC broken-down time of `t`.
pub fn to_utc(t: i64) -> Result<Tm, Errno> {
    let mut tm = Tm::default();
    if tz_convert(t, false, &mut tm, false) { Ok(tm) } else { Err(Errno(errno::get())) }
}

/// Local broken-down time of `t` (does not reread `TZ`; call `tz::tzset` after changing it).
pub fn to_local(t: i64) -> Result<Tm, Errno> {
    let mut tm = Tm::default();
    if tz_convert(t, true, &mut tm, false) { Ok(tm) } else { Err(Errno(errno::get())) }
}

/// Seconds since the epoch of a local broken-down time; `tm` is normalised.
pub fn from_local(tm: &mut Tm) -> Result<i64, Errno> {
    errno::set(0);
    let t = mktime_tm(tm);
    if t == -1 && errno::get() == EOVERFLOW { Err(Errno(EOVERFLOW)) } else { Ok(t) }
}

/// Seconds since the epoch of a UTC broken-down time; `tm` is normalised.
pub fn from_utc(tm: &mut Tm) -> Result<i64, Errno> {
    errno::set(0);
    let t = timegm_tm(tm);
    if t == -1 && errno::get() == EOVERFLOW { Err(Errno(EOVERFLOW)) } else { Ok(t) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::testutil::*;
    use std::ffi::CStr;

    fn host_errno() -> i32 {
        unsafe { *libc::__errno_location() }
    }
    fn clear_errno() {
        errno::set(0);
        unsafe { *libc::__errno_location() = 0 };
    }

    #[test]
    fn gmtime_r_matches_host() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        let mut rng = Rng(0xdead_beef);
        for _ in 0..200_000 {
            let t = random_time(&mut rng);
            let mut a = Tm::default();
            let mut b: libc::tm = unsafe { core::mem::zeroed() };
            clear_errno();
            let ra = unsafe { gmtime_r(&t, &mut a) };
            let rb = unsafe { libc::gmtime_r(&t, &mut b) };
            assert_eq!(ra.is_null(), rb.is_null(), "t={t}");
            if rb.is_null() {
                assert_eq!(errno::get(), host_errno(), "t={t}");
            } else {
                assert!(same_tm(&a, &ours_tm(&b)), "t={t}: {a:?} vs {b:?}");
            }
        }
        // the calendar around a few known days
        let known = [(0i64, (70, 0, 1, 4)), (951_782_400, (100, 1, 29, 2)), (-1, (69, 11, 31, 3)), (-2_208_988_800, (0, 0, 1, 1)), (253_402_300_799, (8099, 11, 31, 5))];
        for (t, (y, m, d, wd)) in known {
            let tm = to_utc(t).unwrap();
            assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_wday), (y, m, d, wd), "t={t}");
        }
    }

    #[test]
    fn gmtime_static_buffer_and_eoverflow() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("UTC"));
        unsafe {
            let t1 = 86400i64;
            let t2 = 2 * 86400i64;
            let p1 = gmtime(&t1);
            let p2 = gmtime(&t2);
            assert_eq!(p1, p2);
            assert_eq!((*p1).tm_mday, 3);
            let h1 = libc::gmtime(&t1);
            let h2 = libc::gmtime(&t2);
            assert_eq!(h1, h2);
            // out of range
            clear_errno();
            assert!(gmtime(&i64::MAX).is_null());
            assert!(libc::gmtime(&i64::MAX).is_null());
            assert_eq!(errno::get(), host_errno());
            assert_eq!(errno::get(), 75);
            assert_eq!(to_utc(i64::MAX), Err(Errno(75)));
        }
    }

    fn mktime_compare(tz: Option<&str>, tm: &Tm, with_timegm: bool) {
        let mut a = *tm;
        let mut b = host_tm(tm);
        clear_errno();
        let (ra, rb) = unsafe {
            if with_timegm { (timegm(&mut a), libc::timegm(&mut b)) } else { (mktime(&mut a), libc::mktime(&mut b)) }
        };
        assert_eq!(ra, rb, "TZ={tz:?} gm={with_timegm} in={tm:?}");
        if rb == -1 {
            assert_eq!(errno::get(), host_errno(), "errno TZ={tz:?} in={tm:?}");
        }
        if rb != -1 || errno::get() == 0 {
            // normalised fields (also on -1 that is a valid time)
            assert!(same_tm(&a, &ours_tm(&b)), "TZ={tz:?} gm={with_timegm} in={tm:?}\n ours {a:?}\n host {b:?}");
        }
    }

    #[test]
    fn mktime_and_timegm_match_host_on_random_fields() {
        let _g = lock();
        let _e = EnvGuard::new();
        let mut rng = Rng(0x00c0_ffee);
        for tz in TZS {
            set_tz(*tz);
            for _ in 0..3000 {
                let tm = random_tm(&mut rng);
                mktime_compare(*tz, &tm, false);
                mktime_compare(*tz, &tm, true);
            }
        }
    }

    #[test]
    fn mktime_dst_gaps_and_overlaps() {
        let _g = lock();
        let _e = EnvGuard::new();
        let mk = |y: i32, mo: i32, d: i32, h: i32, mi: i32, s: i32, dst: i32| Tm { tm_year: y - 1900, tm_mon: mo - 1, tm_mday: d, tm_hour: h, tm_min: mi, tm_sec: s, tm_isdst: dst, ..Tm::default() };
        // (zone, year, month, day) of a spring-forward and a fall-back day; every minute of the
        // surrounding hours with every tm_isdst
        let cases = [
            ("America/New_York", 2024, 3, 10),
            ("America/New_York", 2024, 11, 3),
            ("Europe/London", 2024, 3, 31),
            ("Europe/London", 2024, 10, 27),
            ("Australia/Lord_Howe", 2024, 10, 6),
            ("Australia/Lord_Howe", 2024, 4, 7),
            ("America/Sao_Paulo", 2018, 11, 4),
            ("Pacific/Auckland", 2024, 9, 29),
            ("EST5EDT,M3.2.0,M11.1.0", 2030, 3, 10),
            ("EST5EDT,M3.2.0,M11.1.0", 2030, 11, 3),
            ("America/New_York", 2050, 3, 13),
            ("America/New_York", 1974, 1, 6),
            ("Africa/Casablanca", 2024, 3, 31),
            ("Europe/Dublin", 2024, 10, 27),
        ];
        for (tz, y, mo, d) in cases {
            set_tz(Some(tz));
            for h in 0..5 {
                for mi in (0..60).step_by(5) {
                    for dst in [-1, 0, 1] {
                        mktime_compare(Some(tz), &mk(y, mo, d, h, mi, 7, dst), false);
                    }
                }
            }
        }
        // the actual values for New York
        set_tz(Some("America/New_York"));
        let mut gap = mk(2024, 3, 10, 2, 30, 0, -1);
        assert_eq!(from_local(&mut gap), Ok(1_710_055_800)); // 03:30 EDT
        assert_eq!((gap.tm_hour, gap.tm_isdst), (3, 1));
        let mut over = mk(2024, 11, 3, 1, 30, 0, 0);
        assert_eq!(from_local(&mut over), Ok(1_730_615_400)); // 01:30 EST, second occurrence
        let mut over1 = mk(2024, 11, 3, 1, 30, 0, 1);
        assert_eq!(from_local(&mut over1), Ok(1_730_611_800)); // 01:30 EDT, first occurrence
    }

    #[test]
    fn mktime_round_trips_and_sets_zone_fields() {
        let _g = lock();
        let _e = EnvGuard::new();
        let mut rng = Rng(31337);
        for tz in ["America/New_York", "Europe/London", "Asia/Kolkata", "Australia/Lord_Howe", "EST5EDT,M3.2.0,M11.1.0", "UTC"] {
            set_tz(Some(tz));
            for _ in 0..5000 {
                let t = rng.range(-2_000_000_000, 4_000_000_000);
                let mut tm = to_local(t).unwrap();
                let isdst = tm.tm_isdst;
                let mut c = tm;
                c.tm_isdst = isdst; // the exact answer is only unambiguous with the right flag
                assert_eq!(from_local(&mut c), Ok(t), "TZ={tz} t={t} {tm:?}");
                assert!(same_tm(&c, &tm), "TZ={tz} t={t}");
                tm.tm_gmtoff = 12345;
                tm.tm_zone = core::ptr::null();
                tm.tm_isdst = isdst;
                assert_eq!(from_local(&mut tm), Ok(t));
                assert_ne!(tm.tm_gmtoff, 12345);
                assert!(!tm.tm_zone.is_null());
                // UTC round trip
                let mut u = to_utc(t).unwrap();
                assert_eq!(from_utc(&mut u), Ok(t));
                assert_eq!((u.tm_gmtoff, zone_str(&u).as_deref()), (0, Some("GMT")));
            }
        }
        // overflow
        set_tz(Some("UTC"));
        // one second past the last representable year: EOVERFLOW
        let mut tm = Tm { tm_year: i32::MAX, tm_mon: 11, tm_mday: 31, tm_hour: 23, tm_min: 59, tm_sec: 60, ..Tm::default() };
        errno::set(0);
        assert_eq!(from_local(&mut tm), Err(Errno(75)));
        let mut tm = Tm { tm_year: i32::MAX, tm_mon: 12, tm_mday: 1, ..Tm::default() };
        assert_eq!(from_utc(&mut tm), Err(Errno(75)));
        let mut tm = Tm { tm_year: i32::MAX, tm_mon: 11, tm_mday: 31, tm_hour: 23, tm_min: 59, tm_sec: 59, ..Tm::default() };
        errno::set(0);
        let r = from_utc(&mut tm);
        let mut h = host_tm(&Tm { tm_year: i32::MAX, tm_mon: 11, tm_mday: 31, tm_hour: 23, tm_min: 59, tm_sec: 59, ..Tm::default() });
        clear_errno();
        let hr = unsafe { libc::timegm(&mut h) };
        assert_eq!(r.unwrap_or(-1), hr);
        // timelocal is mktime
        let mut a = Tm { tm_year: 100, tm_mday: 1, ..Tm::default() };
        let mut b = a;
        unsafe { assert_eq!(timelocal(&mut a), mktime(&mut b)) };
        assert_eq!(dysize(1900), 365);
        assert_eq!(dysize(2000), 366);
        assert_eq!(dysize(2024), 366);
        assert_eq!(dysize(2023), 365);
    }

    #[test]
    fn mktime_sets_tzname_like_tzset() {
        let _g = lock();
        let _e = EnvGuard::new();
        set_tz(Some("America/New_York"));
        unsafe { std::env::set_var("TZ", "Asia/Tokyo") };
        let mut tm = Tm { tm_year: 124, tm_mon: 0, tm_mday: 1, ..Tm::default() };
        let mut h = host_tm(&tm);
        unsafe {
            mktime(&mut tm);
            libc::mktime(&mut h);
        }
        assert_eq!(our_tz_vars(), tz_vars());
        assert_eq!(our_tz_vars().0.as_deref(), Some("JST"));
    }

    fn cstr(p: *const core::ffi::c_char) -> Option<String> {
        if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
    }

    #[test]
    fn asctime_and_ctime_match_host() {
        let _g = lock();
        let _e = EnvGuard::new();
        let mut rng = Rng(2468);
        set_tz(Some("America/New_York"));
        unsafe {
            for i in 0..60_000 {
                let mut tm = random_tm(&mut rng);
                if i % 3 == 0 {
                    // plausible fields so that many conversions fit in 26 bytes
                    tm.tm_year = rng.range(-1900, 8000) as i32;
                    tm.tm_mon = rng.range(-1, 12) as i32;
                    tm.tm_wday = rng.range(-1, 7) as i32;
                    tm.tm_mday = rng.range(-5, 40) as i32;
                    tm.tm_hour = rng.range(-3, 30) as i32;
                    tm.tm_min = rng.range(-3, 70) as i32;
                    tm.tm_sec = rng.range(-3, 70) as i32;
                }
                let htm = host_tm(&tm);
                let mut ba = [0x55 as core::ffi::c_char; 40];
                let mut bb = [0x55 as core::ffi::c_char; 40];
                clear_errno();
                let ra = asctime_r(&tm, ba.as_mut_ptr());
                let rb = libc::asctime_r(&htm, bb.as_mut_ptr());
                assert_eq!(ra.is_null(), rb.is_null(), "{tm:?}");
                if rb.is_null() {
                    assert_eq!(errno::get(), host_errno(), "{tm:?}");
                }
                assert_eq!(ba, bb, "asctime_r buffers for {tm:?}");
                // static-buffer form
                clear_errno();
                let sa = cstr(asctime(&tm));
                let sb = cstr(host_asctime(&htm));
                assert_eq!(sa, sb, "asctime {tm:?}");
                if sb.is_none() {
                    assert_eq!(errno::get(), host_errno());
                }
            }
            assert!(asctime(core::ptr::null()).is_null());
            assert_eq!(errno::get(), 22);
            assert!(asctime_r(core::ptr::null(), core::ptr::null_mut()).is_null());
            // ctime and ctime_r
            for _ in 0..30_000 {
                let t = random_time(&mut rng);
                let mut ba = [0x55 as core::ffi::c_char; 40];
                let mut bb = [0x55 as core::ffi::c_char; 40];
                clear_errno();
                let ra = ctime_r(&t, ba.as_mut_ptr());
                let rb = libc::ctime_r(&t, bb.as_mut_ptr());
                assert_eq!(ra.is_null(), rb.is_null(), "t={t}");
                if rb.is_null() {
                    assert_eq!(errno::get(), host_errno(), "t={t}");
                }
                assert_eq!(ba, bb, "t={t}");
                clear_errno();
                let sa = cstr(ctime(&t));
                let sb = cstr(host_ctime(&t));
                assert_eq!(sa, sb, "ctime t={t}");
                if sb.is_none() {
                    assert_eq!(errno::get(), host_errno(), "ctime errno t={t}");
                }
            }
            let t = 1_700_000_000i64;
            assert_eq!(cstr(ctime(&t)).unwrap(), "Tue Nov 14 17:13:20 2023\n");
            // ctime and asctime share the static buffer
            assert_eq!(ctime(&t) as usize, asctime(&to_local(t).unwrap()) as usize);
        }
    }
}
