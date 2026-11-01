//! time.h and sys/time.h: clocks (with the vDSO fast path), sleeping, broken-down time, time zones,
//! strftime and strptime.
//!
//! Unsafe areas (what stays unsafe, and where): the calls through the kernel's vDSO and the system calls that pass a
//! caller's pointer to the kernel (clock.rs: the clock_gettime/gettimeofday/time/clock_getres fast paths are kept as they
//! were, the caller's pointer goes straight to the vDSO); the SIGEV_THREAD timer descriptors and jobs in malloc'd memory and
//! the program's notification functions (clock.rs); the C boundary conversions of the exported functions (core's `ffi`,
//! `sys::arg`/`arg_mut`); the malloc'd tables of the zone code (`mbuf`) and its list of interned names (tz.rs); the
//! `SyncCell` of the zone state, entered only under the zone lock (tz.rs `with_zone`), and the static results of
//! gmtime/localtime, asctime/ctime and getdate (thread-unsafe by their C contract); the walks over the locale's binary era
//! table and alternative-digit lists (timeloc.rs); `tm_zone` and `tzname` strings read for `%Z`. The public C objects
//! (`tzname`, `daylight`, `timezone`, `getdate_err`) are atomics with the C types' layout. Everything else (the TZif and
//! POSIX TZ parsers, the conversions, mktime, the strftime/strptime engines, getdate's matching) is safe code on slices.
#![cfg_attr(not(test), no_std)]
// LLVM would turn the wide string loops into calls to wcslen, which a Rust-only program does not link
#![no_builtins]
#![allow(clippy::missing_safety_doc)]
// Thin unsafe shell, safe core (BRIEF-UNSAFE.md U2): every unsafe block holds one unsafe operation and says why it is sound.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod clock; // time, clock, clock_gettime..., nanosleep, sleep, usleep, gettimeofday, itimers, timers
pub mod vdso; // finding clock_gettime and friends in the kernel's vDSO
pub mod tz; // tzset, tzname, timezone, daylight, TZif files, POSIX TZ strings
pub mod calendar; // gmtime, localtime, mktime, timegm, asctime, ctime, difftime (and the _r forms)
pub mod strftime; // strftime, strptime, getdate (locale aware)
pub mod timeloc; // the LC_TIME data they use
mod mbuf; // malloc'd arrays seen as slices (the zone tables, getdate's template file)
mod sys; // system calls on paths and environment values, C argument conversions

/// One lock for tests that touch global state (TZ, errno, signals).
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Helpers shared by the tests of the calendar, tz and strftime modules.
#[cfg(test)]
pub(crate) mod testutil {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use crate::calendar::Tm;
    use std::ffi::CStr;

    pub fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    unsafe extern "C" {
        #[link_name = "tzset"]
        pub fn host_tzset();
        #[link_name = "asctime"]
        pub fn host_asctime(tm: *const libc::tm) -> *mut core::ffi::c_char;
        #[link_name = "ctime"]
        pub fn host_ctime(t: *const i64) -> *mut core::ffi::c_char;
        #[link_name = "tzname"]
        pub static HOST_TZNAME: [*const core::ffi::c_char; 2];
        #[link_name = "timezone"]
        pub static HOST_TIMEZONE: core::ffi::c_long;
        #[link_name = "daylight"]
        pub static HOST_DAYLIGHT: core::ffi::c_int;
    }

    /// The `TZ` values the tests run under: unset, empty, files, POSIX strings (valid and not).
    pub const TZS: &[Option<&str>] = &[
        None,
        Some(""),
        Some("UTC"),
        Some("UTC0"),
        Some("Universal"),
        Some("GMT0"),
        Some("America/New_York"),
        Some(":America/Chicago"),
        Some("Europe/London"),
        Some("Asia/Kolkata"),
        Some("Australia/Lord_Howe"),
        Some("Pacific/Auckland"),
        Some("America/Sao_Paulo"),
        Some("Asia/Tokyo"),
        Some("Africa/Casablanca"),
        Some("Pacific/Kiritimati"),
        Some("Europe/Dublin"),
        Some("/usr/share/zoneinfo/Europe/Paris"),
        Some("EST5EDT"),
        Some("EST5EDT,M3.2.0,M11.1.0"),
        Some("PST8PDT"),
        Some("CET-1CEST"),
        Some("CET-1CEST,M3.5.0,M10.5.0/3"),
        Some("<+03>-3"),
        Some("<-0330>3:30<-0230>,M3.2.0,M11.1.0"),
        Some("abc-1:30:15def,J60/3,300/-1"),
        Some("XXX3YYY,M10.5.0/-2,M3.5.0/3"),
        Some("NZST-12NZDT,M9.5.0,M4.1.0/3"),
        Some("AEST-10AEDT,J1,J365/25"),
        Some("EST+5"),
        Some("ABC"),
        Some("ABC5"),
        Some("Foo"),
        Some("A"),
        Some("5"),
        Some("<>3"),
        Some("EST5EDT,M13.1.0,M11.1.0"),
        Some("EST5EDT,M3.2.0"),
        Some("EST5EDT,J0,J5"),
        Some("EST5EDT,"),
        Some("EST5EDT4,M3.2.0/2:30,M11.1.0/1:45:10"),
        Some("Nonexistent/Zone"),
        Some("right/UTC"),
        Some("right/America/New_York"),
        Some("posix/Europe/London"),
        Some("Etc/GMT+5"),
        Some("../zoneinfo/UTC"),
    ];

    /// Set (or remove) `TZ` and make our implementation and the host's reread it.
    pub fn set_tz(tz: Option<&str>) {
        unsafe {
            match tz {
                Some(v) => std::env::set_var("TZ", v),
                None => std::env::remove_var("TZ"),
            }
            crate::tz::tzset();
            host_tzset();
        }
    }

    /// Restores `TZ` (and `TZDIR`) when dropped.
    pub struct EnvGuard {
        tz: Option<String>,
        tzdir: Option<String>,
    }

    impl EnvGuard {
        pub fn new() -> EnvGuard {
            EnvGuard { tz: std::env::var("TZ").ok(), tzdir: std::env::var("TZDIR").ok() }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.tz {
                    Some(v) => std::env::set_var("TZ", v),
                    None => std::env::remove_var("TZ"),
                }
                match &self.tzdir {
                    Some(v) => std::env::set_var("TZDIR", v),
                    None => std::env::remove_var("TZDIR"),
                }
                crate::tz::tzset();
                host_tzset();
            }
        }
    }

    /// xorshift64* generator.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        /// Uniform in lo..=hi.
        pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
            let span = (hi as i128 - lo as i128 + 1) as u128;
            (lo as i128 + (self.next() as u128 % span) as i128) as i64
        }
        pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
            &v[self.range(0, v.len() as i64 - 1) as usize]
        }
    }

    pub fn host_tm(tm: &Tm) -> libc::tm {
        unsafe { core::mem::transmute_copy::<Tm, libc::tm>(tm) }
    }

    pub fn ours_tm(tm: &libc::tm) -> Tm {
        unsafe { core::mem::transmute_copy::<libc::tm, Tm>(tm) }
    }

    pub fn zone_str(tm: &Tm) -> Option<String> {
        if tm.tm_zone.is_null() { None } else { Some(unsafe { CStr::from_ptr(tm.tm_zone) }.to_string_lossy().into_owned()) }
    }

    /// Field by field (zone compared as a string).
    pub fn same_tm(a: &Tm, b: &Tm) -> bool {
        a.tm_sec == b.tm_sec
            && a.tm_min == b.tm_min
            && a.tm_hour == b.tm_hour
            && a.tm_mday == b.tm_mday
            && a.tm_mon == b.tm_mon
            && a.tm_year == b.tm_year
            && a.tm_wday == b.tm_wday
            && a.tm_yday == b.tm_yday
            && a.tm_isdst == b.tm_isdst
            && a.tm_gmtoff == b.tm_gmtoff
            && zone_str(a) == zone_str(b)
    }

    pub fn tz_vars() -> (Option<String>, Option<String>, i64, i32) {
        unsafe {
            let n = |p: *const core::ffi::c_char| if p.is_null() { None } else { Some(CStr::from_ptr(p).to_string_lossy().into_owned()) };
            (n(HOST_TZNAME[0]), n(HOST_TZNAME[1]), HOST_TIMEZONE, HOST_DAYLIGHT)
        }
    }

    pub fn our_tz_vars() -> (Option<String>, Option<String>, i64, i32) {
        use core::sync::atomic::Ordering::Relaxed;
        let n = |p: *const core::ffi::c_char| if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) };
        let names = [crate::tz::__tzname[0].load(Relaxed), crate::tz::__tzname[1].load(Relaxed)];
        (n(names[0]), n(names[1]), crate::tz::__timezone.load(Relaxed), crate::tz::__daylight.load(Relaxed))
    }

    /// A random broken-down time, mostly in range, sometimes wild.
    pub fn random_tm(rng: &mut Rng) -> Tm {
        let mut tm = Tm::default();
        let wild = rng.range(0, 19) == 0;
        tm.tm_year = if wild { rng.range(i32::MIN as i64, i32::MAX as i64) as i32 } else { rng.range(-100, 1100) as i32 };
        tm.tm_mon = if wild { rng.range(-100_000, 100_000) as i32 } else { rng.range(-14, 26) as i32 };
        tm.tm_mday = if wild { rng.range(-100_000, 100_000) as i32 } else { rng.range(-40, 70) as i32 };
        tm.tm_hour = if wild { rng.range(-100_000, 100_000) as i32 } else { rng.range(-30, 60) as i32 };
        tm.tm_min = if wild { rng.range(-100_000, 100_000) as i32 } else { rng.range(-70, 130) as i32 };
        tm.tm_sec = if wild { rng.range(-100_000, 100_000) as i32 } else { rng.range(-70, 130) as i32 };
        tm.tm_isdst = *rng.pick(&[-1, 0, 1, 1, 0, -1, 7, -5]);
        tm.tm_wday = rng.range(0, 6) as i32;
        tm.tm_yday = rng.range(0, 365) as i32;
        tm
    }

    /// A random `time_t`: mostly years 1900..2100, with some far ones.
    pub fn random_time(rng: &mut Rng) -> i64 {
        match rng.range(0, 9) {
            0 => rng.range(-(1 << 40), 1 << 40),
            1 => rng.range(-(1 << 33), 1 << 33),
            2 => rng.range(2_100_000_000, 4_000_000_000),
            3 => *rng.pick(&[0, -1, 1, i64::MAX, i64::MIN, i64::MAX - 1, 67_767_976_233_532_799, -67_768_040_609_740_800, 67_768_036_191_676_799, 253_402_300_799, 253_402_300_800, -62_135_596_800]),
            _ => rng.range(-2_208_988_800, 4_102_444_800),
        }
    }
}
