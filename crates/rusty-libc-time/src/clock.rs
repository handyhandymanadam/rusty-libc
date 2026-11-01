//! Clocks, sleeping, interval timers, POSIX timers and file timestamps.
//!
//! Reading the clocks goes through the vDSO when the kernel offers it (`vdso.rs`) and falls back to
//! the system calls. Behaviour follows glibc 2.43 on x86-64 (64-bit `time_t`): `nanosleep` and
//! friends restart nothing by themselves, `clock_nanosleep` returns the error number instead of
//! setting `errno`, `sleep` returns the whole seconds left when a signal interrupts it, and so on.
//!
//! `SIGEV_THREAD` timers work as in glibc: a helper thread (started by the first such `timer_create`) receives the kernel
//! timer's signal (`SIGEV_THREAD_ID`, signal 32) and starts a detached thread running the user's function each time the
//! timer expires; `timer_create` fails with `EAGAIN` when the helper cannot be started. A `timer_t` is, as in glibc, the
//! kernel timer's id with the top bit set, or for a `SIGEV_THREAD` timer the address of its descriptor.
use crate::vdso;
use core::ffi::{c_char, c_int, c_uint, c_void};
use crate::sys;
use rusty_libc_core::{Errno, errno, ffi, syscall};

// ------------------------------------------------------------------ types and constants

/// `struct timespec` (x86-64: two 64-bit fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct timeval`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `struct itimerval`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

/// `struct itimerspec`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Itimerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

/// `struct timezone` (obsolete; only for `gettimeofday`/`settimeofday`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: c_int,
    pub tz_dsttime: c_int,
}

/// `struct utimbuf` (utime.h).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Utimbuf {
    pub actime: i64,
    pub modtime: i64,
}

/// `struct timeb` (sys/timeb.h).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timeb {
    pub time: i64,
    pub millitm: u16,
    pub timezone: i16,
    pub dstflag: i16,
}

/// The thread-notification half of `union sigval`.
#[derive(Clone, Copy)]
#[repr(C)]
pub union Sigval {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

/// The tail of `struct sigevent` (a union padded to 48 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub union SigevUn {
    pub pad: [c_int; 12],
    pub tid: c_int,
    pub thread: [usize; 2], // sigev_notify_function, sigev_notify_attributes
}

/// `struct sigevent` (64 bytes on x86-64).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Sigevent {
    pub sigev_value: Sigval,
    pub sigev_signo: c_int,
    pub sigev_notify: c_int,
    pub un: SigevUn,
}

/// `time_t`, `clock_t`, `locale_t` (named so the generated headers print the C names).
pub type TimeT = i64;
pub type ClockT = i64;
pub type LocaleT = *mut c_void;

/// `clockid_t`, `timer_t`.
pub type ClockId = c_int;
pub type TimerId = *mut c_void;

pub const CLOCK_REALTIME: ClockId = 0;
pub const CLOCK_MONOTONIC: ClockId = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: ClockId = 2;
pub const CLOCK_THREAD_CPUTIME_ID: ClockId = 3;
pub const CLOCK_MONOTONIC_RAW: ClockId = 4;
pub const CLOCK_REALTIME_COARSE: ClockId = 5;
pub const CLOCK_MONOTONIC_COARSE: ClockId = 6;
pub const CLOCK_BOOTTIME: ClockId = 7;
pub const CLOCK_REALTIME_ALARM: ClockId = 8;
pub const CLOCK_BOOTTIME_ALARM: ClockId = 9;
pub const CLOCK_TAI: ClockId = 11;
pub const TIMER_ABSTIME: c_int = 1;
pub const ITIMER_REAL: c_int = 0;
pub const ITIMER_VIRTUAL: c_int = 1;
pub const ITIMER_PROF: c_int = 2;
pub const TIME_UTC: c_int = 1;
pub const TIME_MONOTONIC: c_int = 2;
pub const TIME_ACTIVE: c_int = 3;
pub const TIME_THREAD_ACTIVE: c_int = 4;
pub const CLOCKS_PER_SEC: i64 = 1_000_000;
pub const SIGEV_SIGNAL: c_int = 0;
pub const SIGEV_NONE: c_int = 1;
pub const SIGEV_THREAD: c_int = 2;
pub const SIGEV_THREAD_ID: c_int = 4;
pub const SIGALRM: c_int = 14;
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// The kernel's names for "this process's / this thread's CPU clock" (`~0 << 3 | CPUCLOCK_SCHED`).
const PROCESS_CLOCK: ClockId = (!0 << 3) | 2;
#[allow(dead_code)]
const THREAD_CLOCK: ClockId = (!0 << 3) | 2 | 4;

const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;
const EAGAIN: i32 = 11;
const ESRCH: i32 = 3;

const AT_FDCWD: usize = -100isize as usize;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;

const SYS_GETITIMER: usize = 36;
const SYS_SETITIMER: usize = 38;
const SYS_GETTIMEOFDAY: usize = 96;
const SYS_SETTIMEOFDAY: usize = 164;
const SYS_TIME: usize = 201;
const SYS_TIMER_CREATE: usize = 222;
const SYS_TIMER_SETTIME: usize = 223;
const SYS_TIMER_GETTIME: usize = 224;
const SYS_TIMER_GETOVERRUN: usize = 225;
const SYS_TIMER_DELETE: usize = 226;
const SYS_CLOCK_SETTIME: usize = 227;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_CLOCK_GETRES: usize = 229;
const SYS_CLOCK_NANOSLEEP: usize = 230;
const SYS_UTIMENSAT: usize = 280;
const SYS_CLOCK_ADJTIME: usize = 305;

// ------------------------------------------------------------------ helpers

/// The error number if a raw return value is a kernel error.
#[inline]
fn raw_err(ret: usize) -> Option<i32> {
    if ret > usize::MAX - 4095 { Some((ret as isize).wrapping_neg() as i32) } else { None }
}

/// Set errno and return -1.
#[inline]
fn fail(e: i32) -> c_int {
    errno::set(e);
    -1
}

/// Return 0, or set errno and return -1, from a raw system call result.
#[inline]
fn finish(ret: usize) -> c_int {
    match raw_err(ret) {
        None => 0,
        Some(e) => fail(e),
    }
}

/// A raw return value as `Result` for the Rust API.
#[inline]
fn res(ret: usize) -> Result<usize, Errno> {
    syscall::check(ret)
}

/// `0 <= ns < 10^9`.
#[inline]
fn valid_nanoseconds(ns: i64) -> bool {
    (0..1_000_000_000).contains(&ns)
}

/// Call a vDSO function that returns `0` or `-errno`; `None` when it answers `-ENOSYS` (try the
/// system call), `Some(ret)` otherwise.
#[inline]
fn vdso_status(r: c_int) -> Option<c_int> {
    if r == -ENOSYS { None } else { Some(r) }
}

// ------------------------------------------------------------------ reading clocks
//
// The fast paths: `clock_gettime`, `gettimeofday`, `time` and `clock_getres` call the kernel's vDSO functions with the
// caller's pointer, as glibc does (no copy through a local: a bad pointer faults in the vDSO there too), and make the
// system call only when there is no vDSO or it answers ENOSYS. Each call through the vDSO and each system call with a
// caller's pointer is one unsafe operation: the pointer goes to code that writes through it.

/// Read `clock` into `*tp`: `0` or `-errno`. vDSO first, system call otherwise.
///
/// # Safety
/// `tp` points to a writable `struct timespec`, or is a pointer the vDSO may fault on / the kernel answers EFAULT for.
#[inline]
unsafe fn clock_gettime_raw(clock: ClockId, tp: *mut Timespec) -> c_int {
    if let Some(f) = vdso::clock_gettime() {
        // SAFETY: the vDSO's clock_gettime writes one timespec through `tp` (the caller's contract).
        let r = unsafe { f(clock, tp.cast()) };
        if let Some(r) = vdso_status(r) {
            return r;
        }
    }
    // SAFETY: the kernel writes one timespec at `tp` or answers EFAULT.
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETTIME, clock as isize as usize, tp as usize) };
    match raw_err(r) {
        None => 0,
        Some(e) => -e,
    }
}

/// `int clock_gettime(clockid_t, struct timespec *)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_gettime(clock: ClockId, tp: *mut Timespec) -> c_int {
    // SAFETY: the caller's contract is clock_gettime's.
    let r = unsafe { clock_gettime_raw(clock, tp) };
    if r == 0 { 0 } else { fail(-r) }
}

/// `time_t time(time_t *)`. Like glibc, a bad pointer faults (the vDSO writes through it).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn time(t: *mut TimeT) -> TimeT {
    if let Some(f) = vdso::time() {
        // SAFETY: the vDSO's time writes through `t` when it is not NULL (the caller's contract).
        return unsafe { f(t) };
    }
    // SAFETY: the kernel writes through `t` when it is not NULL, or answers EFAULT.
    let r = unsafe { syscall::syscall1(SYS_TIME, t as usize) };
    match raw_err(r) {
        None => r as i64,
        Some(e) => {
            errno::set(e);
            -1
        }
    }
}

/// `int gettimeofday(struct timeval *, void *)`. The second argument is the obsolete `struct
/// timezone *` (the kernel's `sys_tz`, normally zeros).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int {
    if let Some(f) = vdso::gettimeofday() {
        // SAFETY: the vDSO's gettimeofday writes through `tv` and `tz` when they are not NULL (the caller's contract).
        let r = unsafe { f(tv.cast(), tz) };
        if let Some(r) = vdso_status(r) {
            return if r == 0 { 0 } else { fail(-r) };
        }
    }
    if !tz.is_null() {
        // SAFETY: a non-NULL `tz` points to a writable `struct timezone` (the caller's contract).
        unsafe { core::ptr::write_bytes(tz.cast::<u8>(), 0, core::mem::size_of::<Timezone>()) };
    }
    // SAFETY: the kernel writes through `tv` and `tz` when they are not NULL, or answers EFAULT.
    finish(unsafe { syscall::syscall2(SYS_GETTIMEOFDAY, tv as usize, tz as usize) })
}

/// `int clock_getres(clockid_t, struct timespec *)`; the result may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getres(clock: ClockId, res: *mut Timespec) -> c_int {
    if let Some(f) = vdso::clock_getres() {
        // SAFETY: the vDSO's clock_getres writes through `res` when it is not NULL (the caller's contract).
        let r = unsafe { f(clock, res.cast()) };
        if let Some(r) = vdso_status(r) {
            return if r == 0 { 0 } else { fail(-r) };
        }
    }
    // SAFETY: the kernel writes through `res` when it is not NULL, or answers EFAULT.
    finish(unsafe { syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, res as usize) })
}

/// `int clock_settime(clockid_t, const struct timespec *)`: EINVAL for a bad nanosecond field,
/// then the system call (EPERM without CAP_SYS_TIME).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_settime(clock: ClockId, tp: *const Timespec) -> c_int {
    // SAFETY: `tp` points to a timespec (the C contract; a NULL faults, as in glibc).
    let ts = unsafe { sys::arg(tp) };
    clock_settime_ts(clock, ts)
}

/// `clock_settime` of a timespec of ours.
fn clock_settime_ts(clock: ClockId, ts: &Timespec) -> c_int {
    if !valid_nanoseconds(ts.tv_nsec) {
        return fail(EINVAL);
    }
    // SAFETY: the kernel reads one timespec from `ts`.
    finish(unsafe { syscall::syscall2(SYS_CLOCK_SETTIME, clock as isize as usize, ts as *const Timespec as usize) })
}

/// `clock_t clock(void)`: process CPU time in microseconds (`CLOCKS_PER_SEC` is 1000000), -1 on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock() -> ClockT {
    let Ok(ts) = now(CLOCK_PROCESS_CPUTIME_ID) else {
        // glibc returns -1 without touching errno beyond what clock_gettime set.
        return -1;
    };
    ts.tv_sec.wrapping_mul(CLOCKS_PER_SEC).wrapping_add(ts.tv_nsec / (1_000_000_000 / CLOCKS_PER_SEC))
}

/// `int clock_getcpuclockid(pid_t, clockid_t *)`: returns 0 or an error number (not errno).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getcpuclockid(pid: c_int, clock_id: *mut ClockId) -> c_int {
    let pidclock: ClockId = ((!(pid as u32)) << 3 | 2) as ClockId;
    // SAFETY: plain values (a NULL result pointer: the kernel only checks the clock).
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETRES, pidclock as isize as usize, 0) };
    match raw_err(r) {
        None => {
            // SAFETY: `clock_id` is writable (the C contract; a NULL faults, as in glibc).
            *unsafe { sys::arg_mut(clock_id) } = pidclock;
            0
        }
        Some(EINVAL) => ESRCH,
        Some(e) => e,
    }
}

/// `double difftime(time_t, time_t)`: exact difference, rounded once.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn difftime(t1: TimeT, t0: TimeT) -> f64 {
    (t1 as i128 - t0 as i128) as f64
}

/// `int timespec_get(struct timespec *, int base)` (C11, with glibc 2.43's C23 time bases):
/// returns `base` on success, 0 on failure. The time base is the clock id plus one.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_get(ts: *mut Timespec, base: c_int) -> c_int {
    // SAFETY: the caller's contract is clock_gettime's.
    if unsafe { clock_gettime(base.wrapping_sub(1), ts) } == 0 { base } else { 0 }
}

/// `int timespec_getres(struct timespec *, int base)` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_getres(ts: *mut Timespec, base: c_int) -> c_int {
    // SAFETY: the caller's contract is clock_getres's.
    if unsafe { clock_getres(base.wrapping_sub(1), ts) } == 0 { base } else { 0 }
}

// ------------------------------------------------------------------ setting the clock

/// `int settimeofday(const struct timeval *, const struct timezone *)`. With both given: EINVAL.
/// With only a time: `clock_settime(CLOCK_REALTIME)`. Neither: glibc faults; we return EFAULT.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn settimeofday(tv: *const Timeval, tz: *const Timezone) -> c_int {
    if !tz.is_null() {
        if !tv.is_null() {
            return fail(EINVAL);
        }
        // SAFETY: the kernel reads one `struct timezone` at `tz`, or answers EFAULT.
        return finish(unsafe { syscall::syscall2(SYS_SETTIMEOFDAY, 0, tz as usize) });
    }
    // SAFETY: `tv` is NULL or points to a timeval (the C contract).
    let Some(tv) = (unsafe { tv.as_ref() }) else { return fail(EFAULT) };
    clock_settime_ts(CLOCK_REALTIME, &Timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec.wrapping_mul(1000) })
}

/// `int stime(const time_t *)` (obsolete). Not exported as a C symbol: glibc 2.43's `libc.a` does not define it, `<time.h>`
/// does not declare it, and `libc.so.6` carries only the compatibility version `stime@GLIBC_2.2.5` (no default version, so
/// nothing can be linked to it any more). Kept as a Rust function (it is `clock_settime` of CLOCK_REALTIME); the symbol
/// `__rl_stime_impl` is the target of the `stime@GLIBC_2.2.5` compatibility alias in rusty-libc-cabi (compat_symver.rs).
#[cfg_attr(feature = "export", unsafe(export_name = "__rl_stime_impl"))]
pub unsafe extern "C" fn stime(when: *const TimeT) -> c_int {
    // SAFETY: `when` points to a time_t (the C contract).
    let t = unsafe { *sys::arg(when) };
    clock_settime_ts(CLOCK_REALTIME, &Timespec { tv_sec: t, tv_nsec: 0 })
}

/// `struct timex` as far as `adjtime` needs it: 208 bytes, `modes` first, `offset` second.
#[repr(C)]
struct Timex {
    modes: c_uint,
    _pad: c_uint,
    offset: i64,
    rest: [i64; 24],
}

const ADJ_OFFSET_SINGLESHOT: c_uint = 0x8001;
const ADJ_OFFSET_SS_READ: c_uint = 0xa001;

/// `int adjtime(const struct timeval *, struct timeval *)`: slew the clock by `delta`, return the
/// part not yet applied in `olddelta`. Needs CAP_SYS_TIME to change the clock (EPERM).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn adjtime(delta: *const Timeval, olddelta: *mut Timeval) -> c_int {
    // SAFETY: `delta` is NULL or points to a timeval (the C contract).
    let delta = unsafe { delta.as_ref() };
    // SAFETY: `olddelta` is NULL or a writable timeval, not otherwise accessed during the call (the C contract).
    let olddelta = unsafe { ffi::out(olddelta) };
    adjtime_rs(delta, olddelta)
}

/// `adjtime` on references.
fn adjtime_rs(delta: Option<&Timeval>, olddelta: Option<&mut Timeval>) -> c_int {
    const MAX_SEC: i64 = (i32::MAX as i64) / 1_000_000 - 2;
    const MIN_SEC: i64 = (i32::MIN as i64) / 1_000_000 + 2;
    let mut tx = Timex { modes: 0, _pad: 0, offset: 0, rest: [0; 24] };
    if let Some(d) = delta {
        let sec = d.tv_sec.wrapping_add(d.tv_usec / 1_000_000);
        let usec = d.tv_usec % 1_000_000;
        if !(MIN_SEC..=MAX_SEC).contains(&sec) {
            return fail(EINVAL);
        }
        tx.offset = usec + sec * 1_000_000;
        tx.modes = ADJ_OFFSET_SINGLESHOT;
    } else {
        tx.modes = ADJ_OFFSET_SS_READ;
    }
    // SAFETY: the kernel reads and writes one `struct timex` (208 bytes) at `tx`.
    let r = unsafe { syscall::syscall2(SYS_CLOCK_ADJTIME, CLOCK_REALTIME as usize, &raw mut tx as usize) };
    if let Some(e) = raw_err(r) {
        return fail(e);
    }
    if let Some(o) = olddelta {
        if tx.offset < 0 {
            o.tv_usec = -(-tx.offset % 1_000_000);
            o.tv_sec = -(-tx.offset / 1_000_000);
        } else {
            o.tv_usec = tx.offset % 1_000_000;
            o.tv_sec = tx.offset / 1_000_000;
        }
    }
    0
}

/// `int ftime(struct timeb *)` (obsolete): always 0.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftime(tb: *mut Timeb) -> c_int {
    let ts = now(CLOCK_REALTIME).unwrap_or_default();
    // SAFETY: `tb` is writable (the C contract; a NULL faults, as in glibc).
    let tb = unsafe { sys::arg_mut(tb) };
    tb.time = ts.tv_sec;
    tb.millitm = (ts.tv_nsec / 1_000_000) as u16;
    tb.timezone = 0;
    tb.dstflag = 0;
    0
}

// ------------------------------------------------------------------ sleeping

/// `int clock_nanosleep(clockid_t, int flags, const struct timespec *req, struct timespec *rem)`.
/// Returns 0 or the error number (errno is not set). `rem` is filled on EINTR for relative sleeps.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_nanosleep(clock: ClockId, flags: c_int, req: *const Timespec, rem: *mut Timespec) -> c_int {
    if clock == CLOCK_THREAD_CPUTIME_ID {
        return EINVAL;
    }
    let clock = if clock == CLOCK_PROCESS_CPUTIME_ID { PROCESS_CLOCK } else { clock };
    // SAFETY: the kernel reads one timespec at `req` and writes one at `rem` (when not NULL), or answers EFAULT; the
    // call is a cancellation point, as glibc's.
    let r = unsafe { rusty_libc_core::tls::syscall_cp(SYS_CLOCK_NANOSLEEP, clock as isize as usize, flags as isize as usize, req as usize, rem as usize, 0, 0) };
    raw_err(r).unwrap_or(0)
}

/// `int nanosleep(const struct timespec *, struct timespec *)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int {
    // SAFETY: the caller's contract is clock_nanosleep's.
    let e = unsafe { clock_nanosleep(CLOCK_REALTIME, 0, req, rem) };
    if e != 0 { fail(e) } else { 0 }
}

/// `unsigned sleep(unsigned seconds)`: 0 after the full time; after a signal, the whole seconds
/// that were left (errno stays EINTR). errno is otherwise restored.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sleep(seconds: c_uint) -> c_uint {
    let saved = errno::get();
    let ts_in = Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
    let mut ts = ts_in;
    // SAFETY: both pointers are our own timespecs.
    if unsafe { nanosleep(&ts_in, &mut ts) } < 0 {
        return ts.tv_sec as c_uint;
    }
    errno::set(saved);
    0
}

/// `int usleep(useconds_t)`: sleep for microseconds; -1 with errno on a signal (EINTR).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn usleep(usec: c_uint) -> c_int {
    let ts = Timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: (usec % 1_000_000) as i64 * 1000 };
    // SAFETY: `ts` is our own timespec; no remainder is asked for.
    unsafe { nanosleep(&ts, core::ptr::null_mut()) }
}

// ------------------------------------------------------------------ interval timers

/// `int getitimer(int which, struct itimerval *)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getitimer(which: c_int, value: *mut Itimerval) -> c_int {
    // SAFETY: the kernel writes one itimerval at `value`, or answers EFAULT.
    finish(unsafe { syscall::syscall2(SYS_GETITIMER, which as isize as usize, value as usize) })
}

/// `int setitimer(int which, const struct itimerval *, struct itimerval *old)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setitimer(which: c_int, new: *const Itimerval, old: *mut Itimerval) -> c_int {
    // SAFETY: the kernel reads one itimerval at `new` and writes one at `old` (when not NULL), or answers EFAULT.
    finish(unsafe { syscall::syscall3(SYS_SETITIMER, which as isize as usize, new as usize, old as usize) })
}

// ------------------------------------------------------------------ POSIX timers

/// A `SIGEV_THREAD` timer: the user's function and argument, the cloned thread attributes, the kernel timer.
#[repr(C)]
struct Timer {
    notify: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)>,
    value: rusty_libc_ipc::notify::SigVal,
    attr: *mut c_void,
    ktimer: c_int,
}

/// The signal the kernel timers of `SIGEV_THREAD` timers send to the helper (glibc's SIGTIMER is its SIGCANCEL, 32).
const SIGTIMER: c_int = 32;
const SI_TIMER: c_int = -2;
static HELPER_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// 0 = not started, 1 = starting, 2 = running, 3 = could not start
static HELPER_STATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

struct Job {
    f: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)>,
    v: rusty_libc_ipc::notify::SigVal,
}

/// The thread that runs the user's function after one expiration.
unsafe extern "C" fn timer_notify_thread(arg: *mut c_void) -> *mut c_void {
    // SAFETY: `arg` is the Job the helper malloc'd and wrote for this thread, which only this thread reads.
    let Job { f, v } = unsafe { arg.cast::<Job>().read() };
    // SAFETY: the Job's block came from malloc and is not used again.
    unsafe { rusty_libc_malloc::free(arg) };
    rusty_libc_ipc::notify::detach_self();
    rusty_libc_ipc::notify::unblock_all(); // (it was created by a thread that has every signal blocked)
    if let Some(f) = f {
        // SAFETY: the program's notification function, called with its value as SIGEV_THREAD asks.
        unsafe { f(v) };
    }
    core::ptr::null_mut()
}

/// The helper: wait for the timers' signal and start a thread per expiration.
unsafe extern "C" fn timer_helper_thread(_arg: *mut c_void) -> *mut c_void {
    let set: u64 = 1 << (SIGTIMER - 1);
    loop {
        let mut info = [0u8; 128];
        // rt_sigtimedwait(set, info, NULL, 8): the signals are blocked in this thread, so only this call takes them
        // SAFETY: the kernel reads the 8-byte set and writes at most 128 bytes of siginfo into `info`.
        let r = unsafe { syscall::syscall4(128, &set as *const u64 as usize, info.as_mut_ptr() as usize, 0, 8) };
        if r as isize != SIGTIMER as isize {
            continue;
        }
        let code = c_int::from_ne_bytes([info[8], info[9], info[10], info[11]]);
        if code != SI_TIMER {
            continue;
        }
        let tp = usize::from_ne_bytes(info[24..32].try_into().unwrap()) as *const Timer;
        if tp.is_null() {
            continue;
        }
        // SAFETY: an SI_TIMER signal of SIGTIMER carries the descriptor address timer_create gave the kernel timer;
        // the descriptor lives until timer_delete has deleted the kernel timer (glibc has the same window).
        let t = unsafe { &*tp };
        // SAFETY: malloc may be called with any size; the result is checked for NULL.
        let j = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<Job>()) }.cast::<Job>();
        if j.is_null() {
            continue;
        }
        // SAFETY: `j` is a fresh block big enough and aligned for a Job.
        unsafe { j.write(Job { f: t.notify, v: t.value }) };
        // SAFETY: `t.attr` is the attribute object cloned at timer_create (or NULL).
        if unsafe { rusty_libc_ipc::notify::spawn(timer_notify_thread, j as *mut c_void, t.attr, 0) } != 0 {
            // SAFETY: the thread was not started, so the Job is still ours.
            unsafe { rusty_libc_malloc::free(j as *mut c_void) };
        }
    }
}

unsafe extern "C" fn timer_fork_child() {
    // the helper does not exist in the child: the next SIGEV_THREAD timer starts a new one
    HELPER_TID.store(0, core::sync::atomic::Ordering::Release);
    HELPER_STATE.store(0, core::sync::atomic::Ordering::Release);
}

unsafe extern "C" fn timer_fork_nop() {}

/// Start the helper thread once; false if it cannot be started.
fn start_timer_helper() -> bool {
    use core::sync::atomic::Ordering::*;
    loop {
        match HELPER_STATE.compare_exchange(0, 1, AcqRel, Acquire) {
            Ok(_) => break,
            Err(2) => return true,
            Err(3) => return false,
            Err(_) => {
                // another thread is starting it (glibc: pthread_once)
                rusty_libc_core::lock::futex_wait(&HELPER_STATE, 1);
            }
        }
    }
    static HOOKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if HOOKED.swap(1, AcqRel) == 0 {
        rusty_libc_core::process::register_fork_handlers(timer_fork_nop, timer_fork_nop, timer_fork_child);
    }
    // the helper's thread id from its descriptor, as glibc's __timer_start_helper_thread takes it (the clone call set it
    // before pthread_create returned): no waiting for the helper to report, no gettid/sched_yield
    let mut tid: c_int = 0;
    let r = rusty_libc_ipc::notify::with_signals_blocked(|| {
        // SAFETY: no attribute object (NULL): a detached thread with a 128 KiB stack.
        unsafe { rusty_libc_ipc::notify::spawn_tid(timer_helper_thread, core::ptr::null_mut(), core::ptr::null(), 128 * 1024, &mut tid) }
    });
    let ok = r == 0 && tid > 0;
    if ok {
        HELPER_TID.store(tid, Release);
    }
    HELPER_STATE.store(if ok { 2 } else { 3 }, Release);
    rusty_libc_core::lock::futex_wake(&HELPER_STATE, u32::MAX);
    ok
}

/// A `struct sigevent` with every byte zero but the fields given.
fn sigevent(value: *mut c_void, signo: c_int, notify: c_int) -> Sigevent {
    Sigevent { sigev_value: Sigval { sival_ptr: value }, sigev_signo: signo, sigev_notify: notify, un: SigevUn { pad: [0; 12] } }
}

/// `int timer_create(clockid_t, struct sigevent *, timer_t *)`. `SIGEV_THREAD` uses the helper thread (EAGAIN when it
/// cannot be started); a NULL `sigevent` means `SIGEV_SIGNAL` with `SIGALRM`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_create(clock: ClockId, evp: *mut Sigevent, timerid: *mut TimerId) -> c_int {
    let kclock = match clock {
        CLOCK_PROCESS_CPUTIME_ID => PROCESS_CLOCK,
        CLOCK_THREAD_CPUTIME_ID => THREAD_CLOCK,
        c => c,
    };
    // SAFETY: `evp` is NULL or points to a struct sigevent (the C contract).
    if let Some(ev) = unsafe { evp.as_ref() }
        && ev.sigev_notify == SIGEV_THREAD
    {
        if !start_timer_helper() {
            return fail(EAGAIN);
        }
        // SAFETY: for SIGEV_THREAD the tail of the union holds the function and the attribute pointer (plain words).
        let [func, attr_p] = unsafe { ev.un.thread };
        // SAFETY: `attr_p` is NULL or the program's initialised pthread_attr_t (SIGEV_THREAD's contract).
        let attr = match unsafe { rusty_libc_ipc::notify::attr_clone(attr_p as *const c_void) } {
            Ok(a) => a,
            Err(e) => return fail(e),
        };
        // SAFETY: malloc may be called with any size; the result is checked for NULL.
        let t = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<Timer>()) }.cast::<Timer>();
        if t.is_null() {
            // SAFETY: `attr` came from attr_clone just now and is not used again.
            unsafe { rusty_libc_ipc::notify::attr_free(attr) };
            return fail(12);
        }
        // SAFETY: the word is NULL or the program's notification function (SIGEV_THREAD's contract); a function pointer
        // and `Option` of one have the size of a word, and NULL is `None`.
        let f: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)> = unsafe { core::mem::transmute::<usize, _>(func) };
        // SAFETY: both members of the union are a word; the pointer member is read as glibc copies `sigev_value`.
        let v = rusty_libc_ipc::notify::SigVal { sival_ptr: unsafe { ev.sigev_value.sival_ptr } };
        // SAFETY: `t` is a fresh block big enough and aligned for a Timer.
        unsafe { t.write(Timer { notify: f, value: v, attr, ktimer: 0 }) };
        let mut kev = sigevent(t as *mut c_void, SIGTIMER, SIGEV_THREAD_ID);
        kev.un.tid = HELPER_TID.load(core::sync::atomic::Ordering::Acquire); // to the helper thread
        let mut kid_out: c_int = 0;
        // SAFETY: the kernel reads `kev` and writes the timer id into `kid_out`.
        let r = unsafe { syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, &raw mut kev as usize, &raw mut kid_out as usize) };
        if let Some(e) = raw_err(r) {
            // SAFETY: `attr` and `t` are ours (made above) and not used again.
            unsafe { rusty_libc_ipc::notify::attr_free(attr) };
            // SAFETY: as above.
            unsafe { rusty_libc_malloc::free(t as *mut c_void) };
            return fail(e);
        }
        // SAFETY: `t` is our initialised descriptor; the helper only reads `notify`, `value` and `attr`.
        unsafe { (*t).ktimer = kid_out };
        // SAFETY: `timerid` is writable (the C contract; a NULL faults, as in glibc).
        *unsafe { sys::arg_mut(timerid) } = thread_timer_id(t);
        return 0;
    }
    let local = sigevent(core::ptr::null_mut(), SIGALRM, SIGEV_SIGNAL);
    let ev: *const Sigevent = if evp.is_null() { &local } else { evp };
    let mut kid: c_int = 0;
    // SAFETY: the kernel reads one sigevent at `ev` (ours, or the caller's: EFAULT if bad) and writes the id into `kid`.
    let r = unsafe { syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, ev as usize, &raw mut kid as usize) };
    if let Some(e) = raw_err(r) {
        return fail(e);
    }
    // SAFETY: `timerid` is writable (the C contract).
    *unsafe { sys::arg_mut(timerid) } = kid as isize as TimerId; // glibc's encoding: a plain timer is the kernel's id
    0
}

/// glibc's `timer_t` encoding: a plain timer is the kernel's timer id itself (so the first timer of a process is 0, and
/// programs can compare it with `si_timerid`), a `SIGEV_THREAD` timer is its descriptor's address shifted right by one with
/// the top bit set.
fn thread_timer_id(t: *mut Timer) -> TimerId {
    (isize::MIN as usize | (t as usize) >> 1) as TimerId
}

fn is_thread_timer(t: TimerId) -> bool {
    (t as isize) < 0
}

fn thread_timer(t: TimerId) -> *mut Timer {
    ((t as usize) << 1) as *mut Timer
}

/// The kernel's timer id of a `timer_t`.
///
/// # Safety
/// `t` is a timer from `timer_create` that was not deleted (for a `SIGEV_THREAD` timer: its descriptor is live).
#[inline]
unsafe fn kid(t: TimerId) -> usize {
    if is_thread_timer(t) {
        // SAFETY: a live SIGEV_THREAD timer's descriptor (caller's contract).
        (unsafe { (*thread_timer(t)).ktimer }) as usize
    } else {
        t as usize as u32 as usize
    }
}

/// `int timer_settime(timer_t, int flags, const struct itimerspec *, struct itimerspec *old)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(t: TimerId, flags: c_int, new: *const Itimerspec, old: *mut Itimerspec) -> c_int {
    // SAFETY: `t` is a live timer (the C contract).
    let k = unsafe { kid(t) };
    // SAFETY: the kernel reads one itimerspec at `new` and writes one at `old` (when not NULL), or answers EFAULT.
    finish(unsafe { syscall::syscall4(SYS_TIMER_SETTIME, k, flags as isize as usize, new as usize, old as usize) })
}

/// `int timer_gettime(timer_t, struct itimerspec *)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(t: TimerId, value: *mut Itimerspec) -> c_int {
    // SAFETY: `t` is a live timer (the C contract).
    let k = unsafe { kid(t) };
    // SAFETY: the kernel writes one itimerspec at `value`, or answers EFAULT.
    finish(unsafe { syscall::syscall2(SYS_TIMER_GETTIME, k, value as usize) })
}

/// `int timer_getoverrun(timer_t)`: the overrun count, or -1.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(t: TimerId) -> c_int {
    // SAFETY: `t` is a live timer (the C contract).
    let k = unsafe { kid(t) };
    // SAFETY: plain values.
    let r = unsafe { syscall::syscall1(SYS_TIMER_GETOVERRUN, k) };
    match raw_err(r) {
        None => r as c_int,
        Some(e) => fail(e),
    }
}

/// `int timer_delete(timer_t)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(t: TimerId) -> c_int {
    // SAFETY: `t` is a live timer (the C contract).
    let k = unsafe { kid(t) };
    // SAFETY: plain values.
    let r = finish(unsafe { syscall::syscall1(SYS_TIMER_DELETE, k) });
    if r == 0 && is_thread_timer(t) {
        // a SIGEV_THREAD timer: its descriptor and cloned attributes go too
        let p = thread_timer(t);
        // SAFETY: the descriptor is live until here (caller's contract) and its kernel timer is gone.
        let attr = unsafe { (*p).attr };
        // SAFETY: the attribute object was cloned for this timer and is not used again.
        unsafe { rusty_libc_ipc::notify::attr_free(attr) };
        // SAFETY: the descriptor came from malloc in timer_create and is not used again.
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
    }
    r
}

// ------------------------------------------------------------------ file timestamps

/// `utimensat(fd, path, ts, flags)` as glibc's helper does it.
///
/// # Safety
/// `path` is NULL or a C string, `ts` NULL or two timespecs (or pointers the kernel answers EFAULT for).
#[inline]
unsafe fn utimensat(fd: usize, path: *const c_char, ts: *const Timespec, flags: usize) -> c_int {
    // SAFETY: the kernel reads the path and the two timespecs (caller's contract).
    finish(unsafe { syscall::syscall4(SYS_UTIMENSAT, fd, path as usize, ts as usize, flags) })
}

/// `utimensat` with the times given as two timevals (NULL: now), as glibc's utimes family converts them (microseconds
/// times 1000, wrapping like the C multiplication).
///
/// # Safety
/// `tvp` is NULL or points to two timevals; `path` as for [`utimensat`].
#[inline]
unsafe fn utimensat_tv(fd: usize, path: *const c_char, tvp: *const Timeval, flags: usize) -> c_int {
    let ts = if tvp.is_null() {
        None
    } else {
        // SAFETY: two timevals at `tvp` (caller's contract).
        let tv = unsafe { ffi::slice(tvp, 2) };
        Some([0, 1].map(|i| Timespec { tv_sec: tv[i].tv_sec, tv_nsec: tv[i].tv_usec.wrapping_mul(1000) }))
    };
    // SAFETY: `path` is the caller's (contract); `ts` is ours.
    unsafe { utimensat(fd, path, pair_ptr(&ts), flags) }
}

/// The pointer the kernel gets for an optional pair.
#[inline]
fn pair_ptr(ts: &Option<[Timespec; 2]>) -> *const Timespec {
    ts.as_ref().map_or(core::ptr::null(), |t| t.as_ptr())
}

/// `int utimes(const char *file, const struct timeval tvp[2])`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    // SAFETY: `tvp` is NULL or two timevals, `file` a C string (the C contract; the kernel answers EFAULT for a bad one).
    unsafe { utimensat_tv(AT_FDCWD, file, tvp, 0) }
}

/// `int lutimes(const char *file, const struct timeval tvp[2])`: like utimes, but a symbolic link
/// itself is changed.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lutimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    // SAFETY: as `utimes`.
    unsafe { utimensat_tv(AT_FDCWD, file, tvp, AT_SYMLINK_NOFOLLOW) }
}

/// `int futimes(int fd, const struct timeval tvp[2])`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimes(fd: c_int, tvp: *const Timeval) -> c_int {
    // SAFETY: `tvp` as for `utimes`; no path.
    unsafe { utimensat_tv(fd as isize as usize, core::ptr::null(), tvp, 0) }
}

/// `int futimesat(int fd, const char *file, const struct timeval tvp[2])`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimesat(fd: c_int, file: *const c_char, tvp: *const Timeval) -> c_int {
    // SAFETY: as `utimes`.
    unsafe { utimensat_tv(fd as isize as usize, file, tvp, 0) }
}

/// `int utime(const char *file, const struct utimbuf *times)` (utime.h).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utime(file: *const c_char, times: *const Utimbuf) -> c_int {
    // SAFETY: `times` is NULL or a utimbuf (the C contract).
    let ts = unsafe { times.as_ref() }.map(|t| [Timespec { tv_sec: t.actime, tv_nsec: 0 }, Timespec { tv_sec: t.modtime, tv_nsec: 0 }]);
    // SAFETY: as `utimes`.
    unsafe { utimensat(AT_FDCWD, file, pair_ptr(&ts), 0) }
}

// ------------------------------------------------------------------ Rust API

/// Read a clock.
pub fn now(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    // SAFETY: `ts` is our own timespec.
    let r = unsafe { clock_gettime_raw(clock, &mut ts) };
    if r == 0 { Ok(ts) } else { Err(Errno(-r)) }
}

/// Resolution of a clock.
pub fn resolution(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    if let Some(f) = vdso::clock_getres() {
        // SAFETY: the vDSO's clock_getres writes one timespec into `ts`.
        let r = unsafe { f(clock, (&raw mut ts).cast()) };
        if r != -ENOSYS {
            return if r == 0 { Ok(ts) } else { Err(Errno(-r)) };
        }
    }
    // SAFETY: the kernel writes one timespec into `ts`.
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, &raw mut ts as usize) };
    res(r).map(|_| ts)
}

/// Seconds since the Unix epoch (`CLOCK_REALTIME`).
pub fn unix_time() -> i64 {
    // SAFETY: no result pointer.
    unsafe { time(core::ptr::null_mut()) }
}

/// Sleep for `req` on `CLOCK_REALTIME`. If a signal interrupts, the error is `EINTR` and the
/// second value is the time left.
pub fn sleep_for(req: Timespec) -> Result<(), (Errno, Timespec)> {
    let mut rem = Timespec::default();
    // SAFETY: both timespecs are ours.
    let e = unsafe { clock_nanosleep(CLOCK_REALTIME, 0, &req, &mut rem) };
    if e == 0 { Ok(()) } else { Err((Errno(e), rem)) }
}

/// Sleep until the absolute time `at` on `clock`. Errors are the `clock_nanosleep` error numbers.
pub fn sleep_until(clock: ClockId, at: Timespec) -> Result<(), Errno> {
    // SAFETY: `at` is ours; no remainder is asked for.
    let e = unsafe { clock_nanosleep(clock, TIMER_ABSTIME, &at, core::ptr::null_mut()) };
    if e == 0 { Ok(()) } else { Err(Errno(e)) }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    const EINTR: i32 = 4;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    // host glibc functions the libc crate does not bind
    unsafe extern "C" {
        #[link_name = "clock"]
        fn host_clock() -> i64;
        #[link_name = "timespec_get"]
        fn host_timespec_get(ts: *mut libc::timespec, base: i32) -> i32;
        #[link_name = "timespec_getres"]
        fn host_timespec_getres(ts: *mut libc::timespec, base: i32) -> i32;
    }

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn host_ts(clock: i32) -> (i32, libc::timespec, i32) {
        let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
        unsafe { *libc::__errno_location() = 0 };
        let r = unsafe { libc::clock_gettime(clock, &mut ts) };
        (r, ts, unsafe { *libc::__errno_location() })
    }

    #[test]
    fn clock_gettime_every_clock_id_matches_host_status() {
        let _g = lock();
        // 0..=11 are the kernel's clocks (10 is CLOCK_SGI_CYCLE, unsupported); 12.. and negatives are invalid.
        for id in (-8..=40).chain([100, 1000, i32::MAX, i32::MIN]) {
            let (hr, hts, herr) = host_ts(id);
            let mut ts = Timespec::default();
            errno::set(0);
            let r = unsafe { clock_gettime(id, &mut ts) };
            assert_eq!(r, hr, "clock {id} return");
            if hr == 0 {
                // Same clock: the two readings are close (one second is generous, also for CPU clocks).
                let d = (ts.tv_sec - hts.tv_sec).abs();
                assert!(d <= 1, "clock {id}: {ts:?} vs {hts:?}");
                assert!(ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000);
            } else {
                assert_eq!(errno::get(), herr, "clock {id} errno");
            }
        }
    }

    /// How a call ends in a child process: Ok((return value, errno)) or Err(signal number).
    fn in_child(f: fn() -> (i32, i32)) -> Result<(i32, i32), i32> {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let (r, e) = f();
            let out = [r, e];
            unsafe {
                libc::write(fds[1], out.as_ptr().cast(), 8);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut st = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut st, 0) }, pid);
        let mut got = [0i32; 2];
        let n = unsafe { libc::read(fds[0], got.as_mut_ptr().cast(), 8) };
        unsafe { libc::close(fds[0]) };
        if libc::WIFSIGNALED(st) { Err(libc::WTERMSIG(st)) } else { assert_eq!(n, 8); Ok((got[0], got[1])) }
    }

    #[test]
    fn clock_gettime_bad_pointer_as_glibc() {
        let _g = lock();
        // A clock the kernel serves through the system call reports EFAULT for a bad pointer, ours as glibc's.
        let bad = core::ptr::without_provenance_mut::<Timespec>(8);
        errno::set(0);
        assert_eq!(unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, bad) }, -1);
        assert_eq!(errno::get(), EFAULT);
        let host = in_child(|| unsafe {
            let r = libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, core::ptr::without_provenance_mut(8));
            (r, *libc::__errno_location())
        });
        assert_eq!(host, Ok((-1, EFAULT)));
        // The clocks the vDSO serves write through the pointer in user space: glibc's call dies with SIGSEGV (the vDSO
        // does not fall back to the system call for a bad pointer; a clock source the vDSO cannot read, e.g. hpet or
        // acpi_pm instead of tsc, would take the system call and EFAULT), and ours must behave the same way.
        let host = in_child(|| unsafe { (libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::without_provenance_mut(8)), *libc::__errno_location()) });
        let ours = in_child(|| unsafe { (clock_gettime(CLOCK_REALTIME, core::ptr::without_provenance_mut(8)), errno::get()) });
        assert_eq!(ours, host);
        assert!(host == Err(libc::SIGSEGV) || host == Ok((-1, EFAULT)), "{host:?}");
    }

    #[test]
    fn vdso_and_syscall_agree() {
        let _g = lock();
        assert!(vdso::clock_gettime().is_some());
        for id in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME, CLOCK_TAI, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE] {
            let mut a = Timespec::default();
            let mut b = Timespec::default();
            let mut c = Timespec::default();
            unsafe {
                assert_eq!(clock_gettime_raw(id, &mut a), 0);
                let r = syscall::syscall2(SYS_CLOCK_GETTIME, id as usize, &mut b as *mut Timespec as usize);
                assert_eq!(r, 0);
                assert_eq!(clock_gettime_raw(id, &mut c), 0);
            }
            // a <= b <= c (monotonic) for the monotonic clocks; realtime can in theory step, but not here.
            let ns = |t: Timespec| t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128;
            assert!(ns(a) <= ns(b) + 5_000_000 && ns(b) <= ns(c) + 5_000_000, "clock {id}: {a:?} {b:?} {c:?}");
            if id != CLOCK_REALTIME && id != CLOCK_TAI && id != CLOCK_REALTIME_COARSE {
                assert!(ns(a) <= ns(b) && ns(b) <= ns(c), "monotonic clock {id}");
            }
        }
        // time and gettimeofday through the vDSO and through the system calls.
        unsafe {
            let t1 = time(core::ptr::null_mut());
            let t2 = syscall::syscall1(SYS_TIME, 0) as i64;
            assert!((t2 - t1).abs() <= 1);
            let mut tv = Timeval::default();
            assert_eq!(syscall::syscall2(SYS_GETTIMEOFDAY, &mut tv as *mut Timeval as usize, 0), 0);
            assert!((tv.tv_sec - t1).abs() <= 1);
        }
    }

    #[test]
    fn time_and_gettimeofday_match_host() {
        let _g = lock();
        unsafe {
            let mut t = 0i64;
            let r = time(&mut t);
            assert_eq!(r, t);
            let h = libc::time(core::ptr::null_mut());
            assert!((h - r).abs() <= 1);
            let mut tv = Timeval::default();
            let mut tz = Timezone { tz_minuteswest: 77, tz_dsttime: 77 };
            assert_eq!(gettimeofday(&mut tv, &mut tz as *mut Timezone as *mut c_void), 0);
            let mut htv: libc::timeval = core::mem::zeroed();
            let mut htz = Timezone::default();
            assert_eq!(libc::gettimeofday(&mut htv, &mut htz as *mut Timezone as *mut _), 0);
            assert!((tv.tv_sec - htv.tv_sec).abs() <= 1);
            assert!(tv.tv_usec >= 0 && tv.tv_usec < 1_000_000);
            assert_eq!((tz.tz_minuteswest, tz.tz_dsttime), (htz.tz_minuteswest, htz.tz_dsttime));
            assert_eq!(gettimeofday(&mut tv, core::ptr::null_mut()), 0);
            // a null timeval with a timezone is allowed by the kernel
            assert_eq!(gettimeofday(core::ptr::null_mut(), core::ptr::null_mut()), 0);
        }
        assert!((unix_time() - unsafe { libc::time(core::ptr::null_mut()) }).abs() <= 1);
    }

    #[test]
    fn clock_getres_matches_host() {
        let _g = lock();
        for id in (-3..=13).chain([i32::MAX]) {
            let mut hts: libc::timespec = unsafe { core::mem::zeroed() };
            unsafe { *libc::__errno_location() = 0 };
            let hr = unsafe { libc::clock_getres(id, &mut hts) };
            let herr = unsafe { *libc::__errno_location() };
            let mut ts = Timespec::default();
            errno::set(0);
            let r = unsafe { clock_getres(id, &mut ts) };
            assert_eq!(r, hr, "clock {id}");
            if hr == 0 {
                assert_eq!((ts.tv_sec, ts.tv_nsec), (hts.tv_sec, hts.tv_nsec), "clock {id}");
                assert_eq!(resolution(id).unwrap(), ts);
            } else {
                assert_eq!(errno::get(), herr, "clock {id}");
                assert_eq!(resolution(id), Err(Errno(herr)));
            }
        }
        // NULL result is allowed and validates the clock
        assert_eq!(unsafe { clock_getres(CLOCK_MONOTONIC, core::ptr::null_mut()) }, 0);
        errno::set(0);
        assert_eq!(unsafe { clock_getres(99, core::ptr::null_mut()) }, -1);
        assert_eq!(errno::get(), EINVAL);
    }

    #[test]
    fn clock_and_cpuclockid() {
        let _g = lock();
        unsafe {
            let c0 = clock();
            assert!(c0 >= 0);
            // burn a little CPU: clock() must advance
            let start = Instant::now();
            let mut x = 1u64;
            while start.elapsed() < Duration::from_millis(30) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
            std::hint::black_box(x);
            let c1 = clock();
            assert!(c1 > c0, "{c0} {c1}");
            let hc = host_clock();
            assert!((hc - c1).abs() < 2_000_000);

            let mut id = 0;
            let mut hid = 0;
            assert_eq!(clock_getcpuclockid(0, &mut id), libc::clock_getcpuclockid(0, &mut hid));
            assert_eq!(id, hid);
            let pid = libc::getpid();
            assert_eq!(clock_getcpuclockid(pid, &mut id), 0);
            assert_eq!(libc::clock_getcpuclockid(pid, &mut hid), 0);
            assert_eq!(id, hid);
            let mut ts = Timespec::default();
            assert_eq!(clock_gettime(id, &mut ts), 0);
            // a pid that does not exist
            for bad in [i32::MAX - 5, 4_000_000] {
                let a = clock_getcpuclockid(bad, &mut id);
                let b = libc::clock_getcpuclockid(bad, &mut hid);
                assert_eq!(a, b, "pid {bad}");
                assert_eq!(a, ESRCH);
            }
            // a negative pid
            assert_eq!(clock_getcpuclockid(-1, &mut id), libc::clock_getcpuclockid(-1, &mut hid));
        }
    }

    #[test]
    fn timespec_get_and_getres() {
        let _g = lock();
        unsafe {
            for base in -1..=12 {
                let mut ts = Timespec::default();
                let mut hts: libc::timespec = core::mem::zeroed();
                let r = timespec_get(&mut ts, base);
                let h = host_timespec_get(&mut hts, base);
                assert_eq!(r, h, "base {base}");
                if h != 0 {
                    assert!((ts.tv_sec - hts.tv_sec).abs() <= 1);
                }
                let mut ts = Timespec::default();
                let mut hts: libc::timespec = core::mem::zeroed();
                let r = timespec_getres(&mut ts, base);
                let h = host_timespec_getres(&mut hts, base);
                assert_eq!(r, h, "getres base {base}");
                if h != 0 {
                    assert_eq!((ts.tv_sec, ts.tv_nsec), (hts.tv_sec, hts.tv_nsec));
                }
            }
        }
    }

    #[test]
    fn difftime_matches_host() {
        let vals = [0i64, 1, -1, 86_400, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1, 1 << 53, (1 << 53) + 1, 1_700_000_000, -62_135_596_800, 253_402_300_799];
        for &a in &vals {
            for &b in &vals {
                let ours = difftime(a, b);
                let host = unsafe { libc::difftime(a, b) };
                assert_eq!(ours.to_bits(), host.to_bits(), "difftime({a}, {b})");
            }
        }
    }

    #[test]
    fn settime_failure_paths_change_nothing() {
        let _g = lock();
        unsafe {
            // bad nanoseconds: EINVAL before anything else
            for ns in [-1i64, 1_000_000_000, i64::MAX, i64::MIN] {
                let ts = Timespec { tv_sec: 0, tv_nsec: ns };
                errno::set(0);
                assert_eq!(clock_settime(CLOCK_REALTIME, &ts), -1);
                assert_eq!(errno::get(), EINVAL, "{ns}");
            }
            // both tv and tz: EINVAL
            let tv = Timeval::default();
            let tz = Timezone::default();
            errno::set(0);
            assert_eq!(settimeofday(&tv, &tz), -1);
            assert_eq!(errno::get(), EINVAL);
            // bad microseconds
            let tv = Timeval { tv_sec: 0, tv_usec: 1_000_000 };
            errno::set(0);
            assert_eq!(settimeofday(&tv, core::ptr::null()), -1);
            assert_eq!(errno::get(), EINVAL);
            let tv = Timeval { tv_sec: 0, tv_usec: -1 };
            errno::set(0);
            assert_eq!(settimeofday(&tv, core::ptr::null()), -1);
            assert_eq!(errno::get(), EINVAL);
            // a clock that cannot be set at all: monotonic clocks give EINVAL (kernel), same as host
            let ts = Timespec { tv_sec: 1, tv_nsec: 0 };
            let hts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
            for id in [CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_PROCESS_CPUTIME_ID, 77, -5] {
                errno::set(0);
                *libc::__errno_location() = 0;
                let r = clock_settime(id, &ts);
                let h = libc::clock_settime(id, &hts);
                assert_eq!(r, h, "clock {id}");
                assert_eq!(errno::get(), *libc::__errno_location(), "clock {id}");
            }
            // adjtime with an out-of-range delta: EINVAL; the in-range case would need CAP_SYS_TIME
            let big = Timeval { tv_sec: 3000, tv_usec: 0 };
            errno::set(0);
            assert_eq!(adjtime(&big, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
            let big = Timeval { tv_sec: -3000, tv_usec: 0 };
            errno::set(0);
            assert_eq!(adjtime(&big, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
            // reading the pending adjustment needs no privilege on current kernels
            let mut old = Timeval { tv_sec: 5, tv_usec: 5 };
            let mut hold = libc::timeval { tv_sec: 5, tv_usec: 5 };
            let r = adjtime(core::ptr::null(), &mut old);
            let h = libc::adjtime(core::ptr::null(), &mut hold);
            assert_eq!(r, h);
            if h == 0 {
                assert_eq!(old.tv_sec, hold.tv_sec);
            }
            // stime and settimeofday with a valid value as an unprivileged user fail with EPERM
            // (only tried when this test process is not root)
            if libc::geteuid() != 0 {
                let now = unix_time();
                errno::set(0);
                assert_eq!(stime(&now), -1);
                assert_eq!(errno::get(), 1);
                let tv = Timeval { tv_sec: now, tv_usec: 0 };
                errno::set(0);
                assert_eq!(settimeofday(&tv, core::ptr::null()), -1);
                assert_eq!(errno::get(), 1);
                let tz = Timezone { tz_minuteswest: 0, tz_dsttime: 0 };
                errno::set(0);
                assert_eq!(settimeofday(core::ptr::null(), &tz), -1);
                assert_eq!(errno::get(), 1);
            }
        }
    }

    #[test]
    fn ftime_fills_time() {
        let _g = lock();
        unsafe {
            let mut tb = Timeb { time: 1, millitm: 7777, timezone: 5, dstflag: 5 };
            assert_eq!(ftime(&mut tb), 0);
            assert!((tb.time - libc::time(core::ptr::null_mut())).abs() <= 1);
            assert!(tb.millitm < 1000);
            assert_eq!((tb.timezone, tb.dstflag), (0, 0));
            assert_eq!(core::mem::size_of::<Timeb>(), 16);
        }
    }

    #[test]
    fn struct_sizes_match_glibc() {
        assert_eq!(core::mem::size_of::<Timespec>(), core::mem::size_of::<libc::timespec>());
        assert_eq!(core::mem::size_of::<Timeval>(), core::mem::size_of::<libc::timeval>());
        assert_eq!(core::mem::size_of::<Itimerval>(), core::mem::size_of::<libc::itimerval>());
        assert_eq!(core::mem::size_of::<Itimerspec>(), core::mem::size_of::<libc::itimerspec>());
        assert_eq!(core::mem::size_of::<Utimbuf>(), core::mem::size_of::<libc::utimbuf>());
        assert_eq!(core::mem::size_of::<Sigevent>(), 64);
        assert_eq!(core::mem::size_of::<Timex>(), core::mem::size_of::<libc::timex>());
        assert_eq!(core::mem::size_of::<Timezone>(), 8);
    }

    // ---- sleeping and signals

    static HANDLED: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn on_usr1(_: i32) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    /// Install a SIGUSR1 handler without SA_RESTART, run `f` while a helper thread sends the
    /// signal to this thread after `delay`, restore the old handler.
    fn with_signal<R>(delay: Duration, f: impl FnOnce() -> R) -> R {
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = on_usr1 as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            let mut old: libc::sigaction = core::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGUSR1, &sa, &mut old), 0);
            let me = libc::pthread_self();
            let h = std::thread::spawn(move || {
                std::thread::sleep(delay);
                libc::pthread_kill(me, libc::SIGUSR1);
            });
            let r = f();
            h.join().unwrap();
            libc::sigaction(libc::SIGUSR1, &old, core::ptr::null_mut());
            r
        }
    }

    #[test]
    fn nanosleep_sleeps_and_reports_remaining_on_eintr() {
        let _g = lock();
        unsafe {
            // plain sleep: at least the requested time
            let t0 = Instant::now();
            let req = Timespec { tv_sec: 0, tv_nsec: 40_000_000 };
            assert_eq!(nanosleep(&req, core::ptr::null_mut()), 0);
            assert!(t0.elapsed() >= Duration::from_millis(40));
            // bad arguments, same errno as the host
            for bad in [Timespec { tv_sec: 0, tv_nsec: -1 }, Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 }, Timespec { tv_sec: -1, tv_nsec: 0 }] {
                errno::set(0);
                *libc::__errno_location() = 0;
                let r = nanosleep(&bad, core::ptr::null_mut());
                let hb = libc::timespec { tv_sec: bad.tv_sec, tv_nsec: bad.tv_nsec };
                let h = libc::nanosleep(&hb, core::ptr::null_mut());
                assert_eq!(r, h);
                assert_eq!(errno::get(), *libc::__errno_location(), "{bad:?}");
            }
            // interrupted: -1/EINTR and the rest in rem
            HANDLED.store(0, Ordering::SeqCst);
            let req = Timespec { tv_sec: 5, tv_nsec: 0 };
            let mut rem = Timespec::default();
            let t0 = Instant::now();
            let r = with_signal(Duration::from_millis(60), || {
                errno::set(0);
                let r = nanosleep(&req, &mut rem);
                (r, errno::get())
            });
            assert_eq!(r, (-1, EINTR));
            assert_eq!(HANDLED.load(Ordering::SeqCst), 1);
            let waited = t0.elapsed();
            assert!(waited < Duration::from_secs(2));
            assert!(rem.tv_sec == 4 && rem.tv_nsec > 0 || rem.tv_sec == 5 && rem.tv_nsec == 0 || rem.tv_sec == 4, "{rem:?}");
            let left = rem.tv_sec as f64 + rem.tv_nsec as f64 / 1e9;
            assert!((5.0 - left - waited.as_secs_f64()).abs() < 0.2, "left {left} waited {waited:?}");
            // the Rust API gives the same
            let r = with_signal(Duration::from_millis(40), || sleep_for(Timespec { tv_sec: 5, tv_nsec: 0 }));
            let (e, rem) = r.unwrap_err();
            assert_eq!(e, Errno(EINTR));
            assert!(rem.tv_sec >= 4);
        }
    }

    #[test]
    fn clock_nanosleep_returns_error_numbers_and_handles_abs() {
        let _g = lock();
        unsafe {
            let req = Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
            errno::set(1234);
            assert_eq!(clock_nanosleep(CLOCK_MONOTONIC, 0, &req, core::ptr::null_mut()), 0);
            assert_eq!(errno::get(), 1234, "errno untouched");
            // invalid clock ids and flags: same error numbers as the host
            for (clock, flags) in [(CLOCK_THREAD_CPUTIME_ID, 0), (99, 0), (-1, 0), (CLOCK_MONOTONIC, 2), (CLOCK_REALTIME_ALARM, 0), (CLOCK_TAI, 0)] {
                let short = Timespec { tv_sec: 0, tv_nsec: 1000 };
                let hshort = libc::timespec { tv_sec: 0, tv_nsec: 1000 };
                let r = clock_nanosleep(clock, flags, &short, core::ptr::null_mut());
                let h = libc::clock_nanosleep(clock, flags, &hshort, core::ptr::null_mut());
                assert_eq!(r, h, "clock {clock} flags {flags}");
            }
            // bad nanoseconds
            let bad = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
            assert_eq!(clock_nanosleep(CLOCK_MONOTONIC, 0, &bad, core::ptr::null_mut()), EINVAL);
            // absolute: a time in the past returns at once, a near future time waits
            let past = Timespec { tv_sec: 1, tv_nsec: 0 };
            let t0 = Instant::now();
            assert_eq!(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &past, core::ptr::null_mut()), 0);
            assert!(t0.elapsed() < Duration::from_millis(50));
            let mut at = now(CLOCK_MONOTONIC).unwrap();
            at.tv_nsec += 50_000_000;
            if at.tv_nsec >= 1_000_000_000 {
                at.tv_nsec -= 1_000_000_000;
                at.tv_sec += 1;
            }
            let t0 = Instant::now();
            assert_eq!(sleep_until(CLOCK_MONOTONIC, at), Ok(()));
            assert!(t0.elapsed() >= Duration::from_millis(30));
            // absolute sleeps are interrupted too, and leave rem alone
            let mut at = now(CLOCK_MONOTONIC).unwrap();
            at.tv_sec += 5;
            let mut rem = Timespec { tv_sec: 99, tv_nsec: 99 };
            let r = with_signal(Duration::from_millis(40), || clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &at, &mut rem));
            assert_eq!(r, EINTR);
            assert_eq!(rem, Timespec { tv_sec: 99, tv_nsec: 99 });
            // CPU-time clock sleeps (process clock) are accepted by the kernel: interrupt it
            let req = Timespec { tv_sec: 5, tv_nsec: 0 };
            let r = with_signal(Duration::from_millis(40), || clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, &req, core::ptr::null_mut()));
            assert_eq!(r, EINTR);
        }
    }

    #[test]
    fn sleep_and_usleep() {
        let _g = lock();
        unsafe {
            assert_eq!(sleep(0), 0);
            errno::set(77);
            let t0 = Instant::now();
            assert_eq!(usleep(30_000), 0);
            assert!(t0.elapsed() >= Duration::from_millis(30));
            // sleep(1): full second, errno restored
            errno::set(77);
            let t0 = Instant::now();
            assert_eq!(sleep(1), 0);
            assert!(t0.elapsed() >= Duration::from_millis(999));
            assert_eq!(errno::get(), 77, "sleep restores errno after a full sleep");
            // interrupted sleep: returns the whole seconds left (4 for a 5 second sleep cut at ~50 ms)
            errno::set(0);
            let r = with_signal(Duration::from_millis(50), || (sleep(5), errno::get()));
            assert_eq!(r, (4, EINTR));
            // interrupted usleep: -1 and EINTR
            let r = with_signal(Duration::from_millis(50), || {
                errno::set(0);
                (usleep(3_000_000), errno::get())
            });
            assert_eq!(r, (-1, EINTR));
            // usleep above one second works
            let t0 = Instant::now();
            assert_eq!(usleep(1_050_000), 0);
            assert!(t0.elapsed() >= Duration::from_millis(1050));
        }
    }

    // ---- interval timers

    #[test]
    fn itimers_match_host() {
        let _g = lock();
        unsafe {
            // ITIMER_PROF/VIRTUAL never expire here (CPU time); set, read back, disarm.
            for which in [ITIMER_VIRTUAL, ITIMER_PROF] {
                let new = Itimerval { it_interval: Timeval { tv_sec: 0, tv_usec: 0 }, it_value: Timeval { tv_sec: 1000, tv_usec: 250 } };
                let mut old = Itimerval { it_interval: Timeval { tv_sec: 9, tv_usec: 9 }, it_value: Timeval { tv_sec: 9, tv_usec: 9 } };
                assert_eq!(setitimer(which, &new, &mut old), 0);
                assert_eq!(old, Itimerval::default());
                let mut cur = Itimerval::default();
                assert_eq!(getitimer(which, &mut cur), 0);
                let mut hcur: libc::itimerval = core::mem::zeroed();
                assert_eq!(libc::getitimer(which as _, &mut hcur), 0);
                assert!(cur.it_value.tv_sec == 1000 || cur.it_value.tv_sec == 999);
                assert_eq!(cur.it_value.tv_sec, hcur.it_value.tv_sec);
                assert_eq!(setitimer(which, &Itimerval::default(), &mut old), 0);
                assert!(old.it_value.tv_sec >= 999);
                assert_eq!(getitimer(which, &mut cur), 0);
                assert_eq!(cur, Itimerval::default());
            }
            // errors: bad `which`, bad microseconds
            for which in [-1, 3, 100] {
                let mut cur = Itimerval::default();
                errno::set(0);
                *libc::__errno_location() = 0;
                assert_eq!(getitimer(which, &mut cur), -1);
                assert_eq!(libc::getitimer(which as _, &mut core::mem::zeroed()), -1);
                assert_eq!(errno::get(), *libc::__errno_location(), "which {which}");
                errno::set(0);
                assert_eq!(setitimer(which, &cur, core::ptr::null_mut()), -1);
                assert_eq!(errno::get(), EINVAL);
            }
            let bad = Itimerval { it_interval: Timeval::default(), it_value: Timeval { tv_sec: 1, tv_usec: 1_000_000 } };
            errno::set(0);
            assert_eq!(setitimer(ITIMER_VIRTUAL, &bad, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
        }
    }

    static ALRM_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ALRM_CODE: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn on_alrm(_: i32, info: *mut libc::siginfo_t, _: *mut c_void) {
        unsafe { ALRM_CODE.store((*info).si_code as usize, Ordering::SeqCst) };
        ALRM_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    /// Run `f` with a SIGALRM handler installed process-wide (the signal may land in any thread).
    fn with_alrm<R>(f: impl FnOnce() -> R) -> R {
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = on_alrm as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = libc::SA_SIGINFO;
            let mut old: libc::sigaction = core::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGALRM, &sa, &mut old), 0);
            ALRM_COUNT.store(0, Ordering::SeqCst);
            let r = f();
            libc::sigaction(libc::SIGALRM, &old, core::ptr::null_mut());
            r
        }
    }

    fn wait_alrm() -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(3) {
            if ALRM_COUNT.load(Ordering::SeqCst) > 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn itimer_real_delivers_sigalrm_to_the_process() {
        let _g = lock();
        with_alrm(|| unsafe {
            let new = Itimerval { it_interval: Timeval::default(), it_value: Timeval { tv_sec: 0, tv_usec: 50_000 } };
            assert_eq!(setitimer(ITIMER_REAL, &new, core::ptr::null_mut()), 0);
            let mut cur = Itimerval::default();
            assert_eq!(getitimer(ITIMER_REAL, &mut cur), 0);
            assert!(cur.it_value.tv_sec == 0 && cur.it_value.tv_usec <= 50_000);
            assert!(wait_alrm(), "SIGALRM arrived");
            assert_eq!(ALRM_CODE.load(Ordering::SeqCst) as i32, libc::SI_KERNEL);
            assert_eq!(getitimer(ITIMER_REAL, &mut cur), 0);
            assert_eq!(cur, Itimerval::default());
        });
    }

    // ---- POSIX timers

    #[test]
    fn posix_timers() {
        let _g = lock();
        unsafe {
            // SIGEV_NONE timer: arm, read, overrun, delete
            let mut ev: Sigevent = core::mem::zeroed();
            ev.sigev_notify = SIGEV_NONE;
            let mut t: TimerId = core::ptr::null_mut();
            assert_eq!(timer_create(CLOCK_MONOTONIC, &mut ev, &mut t), 0);
            let new = Itimerspec { it_interval: Timespec { tv_sec: 0, tv_nsec: 10_000_000 }, it_value: Timespec { tv_sec: 0, tv_nsec: 10_000_000 } };
            let mut old = Itimerspec { it_interval: Timespec { tv_sec: 5, tv_nsec: 5 }, it_value: Timespec { tv_sec: 5, tv_nsec: 5 } };
            assert_eq!(timer_settime(t, 0, &new, &mut old), 0);
            assert_eq!(old, Itimerspec::default());
            std::thread::sleep(Duration::from_millis(100));
            let mut cur = Itimerspec::default();
            assert_eq!(timer_gettime(t, &mut cur), 0);
            assert_eq!(cur.it_interval, new.it_interval);
            assert!(cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 10_000_000);
            let over = timer_getoverrun(t);
            assert!(over >= 0, "overrun {over}"); // a SIGEV_NONE timer queues no signal, so the kernel counts none
            assert_eq!(timer_delete(t), 0);
            // deleted: EINVAL everywhere (same as host)
            errno::set(0);
            assert_eq!(timer_gettime(t, &mut cur), -1);
            assert_eq!(errno::get(), EINVAL);
            errno::set(0);
            assert_eq!(timer_getoverrun(t), -1);
            assert_eq!(errno::get(), EINVAL);
            errno::set(0);
            assert_eq!(timer_delete(t), -1);
            assert_eq!(errno::get(), EINVAL);
            errno::set(0);
            assert_eq!(timer_settime(t, 0, &new, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
        }
    }

    #[test]
    fn posix_timer_signal_and_defaults() {
        let _g = lock();
        unsafe {
            // NULL sigevent: SIGALRM to the process
            with_alrm(|| {
                let mut t: TimerId = core::ptr::null_mut();
                assert_eq!(timer_create(CLOCK_REALTIME, core::ptr::null_mut(), &mut t), 0);
                let one_shot = Itimerspec { it_interval: Timespec::default(), it_value: Timespec { tv_sec: 0, tv_nsec: 30_000_000 } };
                assert_eq!(timer_settime(t, 0, &one_shot, core::ptr::null_mut()), 0);
                assert!(wait_alrm());
                assert_eq!(ALRM_CODE.load(Ordering::SeqCst) as i32, libc::SI_TIMER);
                assert_eq!(timer_delete(t), 0);
            });
            // SIGUSR2 with a value to this thread (SIGEV_THREAD_ID), absolute time on the realtime clock
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR2);
            let mut old: libc::sigset_t = core::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            let mut t: TimerId = core::ptr::null_mut();
            let mut ev: Sigevent = core::mem::zeroed();
            ev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
            ev.sigev_signo = libc::SIGUSR2;
            ev.sigev_value.sival_int = 4242;
            ev.un.tid = libc::syscall(libc::SYS_gettid) as c_int;
            assert_eq!(timer_create(CLOCK_REALTIME, &mut ev, &mut t), 0);
            let mut at = now(CLOCK_REALTIME).unwrap();
            at.tv_nsec += 30_000_000;
            if at.tv_nsec >= 1_000_000_000 {
                at.tv_nsec -= 1_000_000_000;
                at.tv_sec += 1;
            }
            let abs = Itimerspec { it_interval: Timespec::default(), it_value: at };
            assert_eq!(timer_settime(t, TIMER_ABSTIME, &abs, core::ptr::null_mut()), 0);
            let ts = libc::timespec { tv_sec: 2, tv_nsec: 0 };
            let mut info: libc::siginfo_t = core::mem::zeroed();
            assert_eq!(libc::sigtimedwait(&set, &mut info, &ts), libc::SIGUSR2);
            assert_eq!(info.si_code, libc::SI_TIMER);
            assert_eq!(info.si_value().sival_ptr as usize as i32, 4242);
            assert_eq!(timer_delete(t), 0);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, core::ptr::null_mut());
        }
    }

    #[test]
    fn posix_timer_errors_and_sigev_thread() {
        let _g = lock();
        unsafe {
            let mut t: TimerId = core::ptr::null_mut();
            // SIGEV_THREAD timers are created (a helper thread runs the notification) and deleted
            let mut ev: Sigevent = core::mem::zeroed();
            ev.sigev_notify = SIGEV_THREAD;
            assert_eq!(timer_create(CLOCK_REALTIME, &mut ev, &mut t), 0);
            assert_eq!(timer_delete(t), 0);
            // bad clock, bad signal number, bad notify
            for (clock, notify, signo) in [(99, SIGEV_SIGNAL, 10), (CLOCK_REALTIME, SIGEV_SIGNAL, 9999), (CLOCK_REALTIME, 77, 10), (CLOCK_THREAD_CPUTIME_ID, SIGEV_NONE, 0), (CLOCK_PROCESS_CPUTIME_ID, SIGEV_NONE, 0), (CLOCK_BOOTTIME, SIGEV_NONE, 0), (CLOCK_REALTIME_ALARM, SIGEV_NONE, 0), (-1, SIGEV_NONE, 0), (CLOCK_MONOTONIC_RAW, SIGEV_NONE, 0)] {
                let mut ev: Sigevent = core::mem::zeroed();
                ev.sigev_notify = notify;
                ev.sigev_signo = signo;
                let mut hev: libc::sigevent = core::mem::zeroed();
                hev.sigev_notify = notify;
                hev.sigev_signo = signo;
                let mut ht: libc::timer_t = core::ptr::null_mut();
                errno::set(0);
                *libc::__errno_location() = 0;
                let r = timer_create(clock, &mut ev, &mut t);
                let h = libc::timer_create(clock, &mut hev, &mut ht);
                assert_eq!(r, h, "clock {clock} notify {notify} signo {signo}");
                assert_eq!(errno::get(), *libc::__errno_location(), "clock {clock} notify {notify}");
                if r == 0 {
                    assert_eq!(timer_delete(t), 0);
                    assert_eq!(libc::timer_delete(ht), 0);
                }
            }
            // bad nanoseconds in settime
            let mut ev: Sigevent = core::mem::zeroed();
            ev.sigev_notify = SIGEV_NONE;
            assert_eq!(timer_create(CLOCK_MONOTONIC, &mut ev, &mut t), 0);
            let bad = Itimerspec { it_interval: Timespec::default(), it_value: Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 } };
            errno::set(0);
            assert_eq!(timer_settime(t, 0, &bad, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
            assert_eq!(timer_delete(t), 0);
        }
    }

    // ---- file timestamps

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("libc-time-{}-{}", std::process::id(), name));
        p
    }

    fn mtime_atime(p: &std::path::Path) -> ((i64, i64), (i64, i64)) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).unwrap();
        ((m.atime(), m.atime_nsec()), (m.mtime(), m.mtime_nsec()))
    }

    #[test]
    fn utimes_family() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let _g = lock();
        let p = tmp_path("utimes");
        let l = tmp_path("utimes-link");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&l);
        let f = std::fs::File::create(&p).unwrap();
        std::os::unix::fs::symlink(&p, &l).unwrap();
        let cp = CString::new(p.as_os_str().as_bytes()).unwrap();
        let cl = CString::new(l.as_os_str().as_bytes()).unwrap();
        unsafe {
            let tv = [Timeval { tv_sec: 1_000_000_000, tv_usec: 123_456 }, Timeval { tv_sec: 1_100_000_000, tv_usec: 999_999 }];
            assert_eq!(utimes(cp.as_ptr(), tv.as_ptr()), 0);
            assert_eq!(mtime_atime(&p), ((1_000_000_000, 123_456_000), (1_100_000_000, 999_999_000)));
            // through the link: the target changes
            let tv2 = [Timeval { tv_sec: 1_200_000_000, tv_usec: 1 }, Timeval { tv_sec: 1_300_000_000, tv_usec: 2 }];
            assert_eq!(utimes(cl.as_ptr(), tv2.as_ptr()), 0);
            assert_eq!(mtime_atime(&p), ((1_200_000_000, 1000), (1_300_000_000, 2000)));
            // lutimes: the link changes, the target does not
            let tv3 = [Timeval { tv_sec: 1_400_000_000, tv_usec: 3 }, Timeval { tv_sec: 1_500_000_000, tv_usec: 4 }];
            assert_eq!(lutimes(cl.as_ptr(), tv3.as_ptr()), 0);
            assert_eq!(mtime_atime(&p), ((1_200_000_000, 1000), (1_300_000_000, 2000)));
            use std::os::unix::fs::MetadataExt;
            let lm = std::fs::symlink_metadata(&l).unwrap();
            // (atime of a symlink can be moved by any reader of the link under relatime: compare it only when untouched)
            assert_eq!((lm.mtime(), lm.mtime_nsec()), (1_500_000_000, 4000));
            assert!(lm.atime() == 1_400_000_000 || lm.atime() >= 1_500_000_000, "atime {}", lm.atime());
            // futimes
            let tv4 = [Timeval { tv_sec: 1_600_000_000, tv_usec: 5 }, Timeval { tv_sec: 1_700_000_000, tv_usec: 6 }];
            assert_eq!(futimes(f.as_raw_fd(), tv4.as_ptr()), 0);
            assert_eq!(mtime_atime(&p), ((1_600_000_000, 5000), (1_700_000_000, 6000)));
            // futimesat with a directory fd and a relative name
            let dir = std::fs::File::open(std::env::temp_dir()).unwrap();
            let name = CString::new(p.file_name().unwrap().as_bytes()).unwrap();
            let tv5 = [Timeval { tv_sec: 1_000_000_001, tv_usec: 0 }, Timeval { tv_sec: 1_000_000_002, tv_usec: 0 }];
            assert_eq!(futimesat(dir.as_raw_fd(), name.as_ptr(), tv5.as_ptr()), 0);
            assert_eq!(mtime_atime(&p), ((1_000_000_001, 0), (1_000_000_002, 0)));
            // utime
            let ub = Utimbuf { actime: 1_111_111_111, modtime: 1_222_222_222 };
            assert_eq!(utime(cp.as_ptr(), &ub), 0);
            assert_eq!(mtime_atime(&p), ((1_111_111_111, 0), (1_222_222_222, 0)));
            // NULL times: now
            assert_eq!(utime(cp.as_ptr(), core::ptr::null()), 0);
            let ((a, _), (m, _)) = mtime_atime(&p);
            assert!((a - libc::time(core::ptr::null_mut())).abs() <= 2 && (m - a).abs() <= 1);
            assert_eq!(utimes(cp.as_ptr(), core::ptr::null()), 0);
            // errors: same errno as the host
            let missing = CString::new("/nonexistent-dir/xyz").unwrap();
            let badtv = [Timeval { tv_sec: 1, tv_usec: 1_000_000 }, Timeval { tv_sec: 1, tv_usec: 0 }];
            let negtv = [Timeval { tv_sec: 1, tv_usec: -1 }, Timeval { tv_sec: 1, tv_usec: 0 }];
            let htv = |t: &[Timeval; 2]| [libc::timeval { tv_sec: t[0].tv_sec, tv_usec: t[0].tv_usec }, libc::timeval { tv_sec: t[1].tv_sec, tv_usec: t[1].tv_usec }];
            for (path, tvs) in [(&missing, &tv), (&cp, &badtv), (&cp, &negtv)] {
                errno::set(0);
                *libc::__errno_location() = 0;
                let r = utimes(path.as_ptr(), tvs.as_ptr());
                let h = libc::utimes(path.as_ptr(), htv(tvs).as_ptr());
                assert_eq!(r, h);
                assert_eq!(errno::get(), *libc::__errno_location());
            }
            for fd in [-1, 9999] {
                errno::set(0);
                *libc::__errno_location() = 0;
                let r = futimes(fd, tv.as_ptr());
                let h = libc::futimes(fd, htv(&tv).as_ptr());
                assert_eq!(r, h);
                assert_eq!(errno::get(), *libc::__errno_location(), "fd {fd}");
            }
            errno::set(0);
            *libc::__errno_location() = 0;
            assert_eq!(utime(missing.as_ptr(), &ub), -1);
            assert_eq!(libc::utime(missing.as_ptr(), &libc::utimbuf { actime: 1, modtime: 1 }), -1);
            assert_eq!(errno::get(), *libc::__errno_location());
        }
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&l);
    }
}
