use crate::vdso;
use core::ffi::{c_char, c_int, c_uint, c_void};
use crate::sys;
use rusty_libc_core::{Errno, errno, ffi, syscall};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Itimerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: c_int,
    pub tz_dsttime: c_int,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Utimbuf {
    pub actime: i64,
    pub modtime: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timeb {
    pub time: i64,
    pub millitm: u16,
    pub timezone: i16,
    pub dstflag: i16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union Sigval {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union SigevUn {
    pub pad: [c_int; 12],
    pub tid: c_int,
    pub thread: [usize; 2],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Sigevent {
    pub sigev_value: Sigval,
    pub sigev_signo: c_int,
    pub sigev_notify: c_int,
    pub un: SigevUn,
}

pub type TimeT = i64;
pub type ClockT = i64;
pub type LocaleT = *mut c_void;

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

#[inline]
fn raw_err(ret: usize) -> Option<i32> {
    if ret > usize::MAX - 4095 { Some((ret as isize).wrapping_neg() as i32) } else { None }
}

#[inline]
fn fail(e: i32) -> c_int {
    errno::set(e);
    -1
}

#[inline]
fn finish(ret: usize) -> c_int {
    match raw_err(ret) {
        None => 0,
        Some(e) => fail(e),
    }
}

#[inline]
fn res(ret: usize) -> Result<usize, Errno> {
    syscall::check(ret)
}

#[inline]
fn valid_nanoseconds(ns: i64) -> bool {
    (0..1_000_000_000).contains(&ns)
}

#[inline]
fn vdso_status(r: c_int) -> Option<c_int> {
    if r == -ENOSYS { None } else { Some(r) }
}

#[inline]
unsafe fn clock_gettime_raw(clock: ClockId, tp: *mut Timespec) -> c_int {
    if let Some(f) = vdso::clock_gettime() {
        let r = unsafe { f(clock, tp.cast()) };
        if let Some(r) = vdso_status(r) {
            return r;
        }
    }
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETTIME, clock as isize as usize, tp as usize) };
    match raw_err(r) {
        None => 0,
        Some(e) => -e,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_gettime(clock: ClockId, tp: *mut Timespec) -> c_int {
    let r = unsafe { clock_gettime_raw(clock, tp) };
    if r == 0 { 0 } else { fail(-r) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn time(t: *mut TimeT) -> TimeT {
    if let Some(f) = vdso::time() {
        return unsafe { f(t) };
    }
    let r = unsafe { syscall::syscall1(SYS_TIME, t as usize) };
    match raw_err(r) {
        None => r as i64,
        Some(e) => {
            errno::set(e);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int {
    if let Some(f) = vdso::gettimeofday() {
        let r = unsafe { f(tv.cast(), tz) };
        if let Some(r) = vdso_status(r) {
            return if r == 0 { 0 } else { fail(-r) };
        }
    }
    if !tz.is_null() {
        unsafe { core::ptr::write_bytes(tz.cast::<u8>(), 0, core::mem::size_of::<Timezone>()) };
    }
    finish(unsafe { syscall::syscall2(SYS_GETTIMEOFDAY, tv as usize, tz as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getres(clock: ClockId, res: *mut Timespec) -> c_int {
    if let Some(f) = vdso::clock_getres() {
        let r = unsafe { f(clock, res.cast()) };
        if let Some(r) = vdso_status(r) {
            return if r == 0 { 0 } else { fail(-r) };
        }
    }
    finish(unsafe { syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, res as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_settime(clock: ClockId, tp: *const Timespec) -> c_int {
    let ts = unsafe { sys::arg(tp) };
    clock_settime_ts(clock, ts)
}

fn clock_settime_ts(clock: ClockId, ts: &Timespec) -> c_int {
    if !valid_nanoseconds(ts.tv_nsec) {
        return fail(EINVAL);
    }
    finish(unsafe { syscall::syscall2(SYS_CLOCK_SETTIME, clock as isize as usize, ts as *const Timespec as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock() -> ClockT {
    let Ok(ts) = now(CLOCK_PROCESS_CPUTIME_ID) else {
        return -1;
    };
    ts.tv_sec.wrapping_mul(CLOCKS_PER_SEC).wrapping_add(ts.tv_nsec / (1_000_000_000 / CLOCKS_PER_SEC))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getcpuclockid(pid: c_int, clock_id: *mut ClockId) -> c_int {
    let pidclock: ClockId = ((!(pid as u32)) << 3 | 2) as ClockId;
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETRES, pidclock as isize as usize, 0) };
    match raw_err(r) {
        None => {
            *unsafe { sys::arg_mut(clock_id) } = pidclock;
            0
        }
        Some(EINVAL) => ESRCH,
        Some(e) => e,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn difftime(t1: TimeT, t0: TimeT) -> f64 {
    (t1 as i128 - t0 as i128) as f64
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_get(ts: *mut Timespec, base: c_int) -> c_int {
    if unsafe { clock_gettime(base.wrapping_sub(1), ts) } == 0 { base } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_getres(ts: *mut Timespec, base: c_int) -> c_int {
    if unsafe { clock_getres(base.wrapping_sub(1), ts) } == 0 { base } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn settimeofday(tv: *const Timeval, tz: *const Timezone) -> c_int {
    if !tz.is_null() {
        if !tv.is_null() {
            return fail(EINVAL);
        }
        return finish(unsafe { syscall::syscall2(SYS_SETTIMEOFDAY, 0, tz as usize) });
    }
    let Some(tv) = (unsafe { tv.as_ref() }) else { return fail(EFAULT) };
    clock_settime_ts(CLOCK_REALTIME, &Timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec.wrapping_mul(1000) })
}

#[cfg_attr(feature = "export", unsafe(export_name = "__rl_stime_impl"))]
pub unsafe extern "C" fn stime(when: *const TimeT) -> c_int {
    let t = unsafe { *sys::arg(when) };
    clock_settime_ts(CLOCK_REALTIME, &Timespec { tv_sec: t, tv_nsec: 0 })
}

#[repr(C)]
struct Timex {
    modes: c_uint,
    _pad: c_uint,
    offset: i64,
    rest: [i64; 24],
}

const ADJ_OFFSET_SINGLESHOT: c_uint = 0x8001;
const ADJ_OFFSET_SS_READ: c_uint = 0xa001;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn adjtime(delta: *const Timeval, olddelta: *mut Timeval) -> c_int {
    let delta = unsafe { delta.as_ref() };
    let olddelta = unsafe { ffi::out(olddelta) };
    adjtime_rs(delta, olddelta)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftime(tb: *mut Timeb) -> c_int {
    let ts = now(CLOCK_REALTIME).unwrap_or_default();
    let tb = unsafe { sys::arg_mut(tb) };
    tb.time = ts.tv_sec;
    tb.millitm = (ts.tv_nsec / 1_000_000) as u16;
    tb.timezone = 0;
    tb.dstflag = 0;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_nanosleep(clock: ClockId, flags: c_int, req: *const Timespec, rem: *mut Timespec) -> c_int {
    if clock == CLOCK_THREAD_CPUTIME_ID {
        return EINVAL;
    }
    let clock = if clock == CLOCK_PROCESS_CPUTIME_ID { PROCESS_CLOCK } else { clock };
    let r = unsafe { rusty_libc_core::tls::syscall_cp(SYS_CLOCK_NANOSLEEP, clock as isize as usize, flags as isize as usize, req as usize, rem as usize, 0, 0) };
    raw_err(r).unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int {
    let e = unsafe { clock_nanosleep(CLOCK_REALTIME, 0, req, rem) };
    if e != 0 { fail(e) } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sleep(seconds: c_uint) -> c_uint {
    let saved = errno::get();
    let ts_in = Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
    let mut ts = ts_in;
    if unsafe { nanosleep(&ts_in, &mut ts) } < 0 {
        return ts.tv_sec as c_uint;
    }
    errno::set(saved);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn usleep(usec: c_uint) -> c_int {
    let ts = Timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: (usec % 1_000_000) as i64 * 1000 };
    unsafe { nanosleep(&ts, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getitimer(which: c_int, value: *mut Itimerval) -> c_int {
    finish(unsafe { syscall::syscall2(SYS_GETITIMER, which as isize as usize, value as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setitimer(which: c_int, new: *const Itimerval, old: *mut Itimerval) -> c_int {
    finish(unsafe { syscall::syscall3(SYS_SETITIMER, which as isize as usize, new as usize, old as usize) })
}

#[repr(C)]
struct Timer {
    notify: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)>,
    value: rusty_libc_ipc::notify::SigVal,
    attr: *mut c_void,
    ktimer: c_int,
}

const SIGTIMER: c_int = 32;
const SI_TIMER: c_int = -2;
static HELPER_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static HELPER_STATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

struct Job {
    f: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)>,
    v: rusty_libc_ipc::notify::SigVal,
}

unsafe extern "C" fn timer_notify_thread(arg: *mut c_void) -> *mut c_void {
    let Job { f, v } = unsafe { arg.cast::<Job>().read() };
    unsafe { rusty_libc_malloc::free(arg) };
    rusty_libc_ipc::notify::detach_self();
    rusty_libc_ipc::notify::unblock_all();
    if let Some(f) = f {
        unsafe { f(v) };
    }
    core::ptr::null_mut()
}

unsafe extern "C" fn timer_helper_thread(_arg: *mut c_void) -> *mut c_void {
    let set: u64 = 1 << (SIGTIMER - 1);
    loop {
        let mut info = [0u8; 128];
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
        let t = unsafe { &*tp };
        let j = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<Job>()) }.cast::<Job>();
        if j.is_null() {
            continue;
        }
        unsafe { j.write(Job { f: t.notify, v: t.value }) };
        if unsafe { rusty_libc_ipc::notify::spawn(timer_notify_thread, j as *mut c_void, t.attr, 0) } != 0 {
            unsafe { rusty_libc_malloc::free(j as *mut c_void) };
        }
    }
}

unsafe extern "C" fn timer_fork_child() {
    HELPER_TID.store(0, core::sync::atomic::Ordering::Release);
    HELPER_STATE.store(0, core::sync::atomic::Ordering::Release);
}

unsafe extern "C" fn timer_fork_nop() {}

fn start_timer_helper() -> bool {
    use core::sync::atomic::Ordering::*;
    loop {
        match HELPER_STATE.compare_exchange(0, 1, AcqRel, Acquire) {
            Ok(_) => break,
            Err(2) => return true,
            Err(3) => return false,
            Err(_) => {
                rusty_libc_core::lock::futex_wait(&HELPER_STATE, 1);
            }
        }
    }
    static HOOKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if HOOKED.swap(1, AcqRel) == 0 {
        rusty_libc_core::process::register_fork_handlers(timer_fork_nop, timer_fork_nop, timer_fork_child);
    }
    let mut tid: c_int = 0;
    let r = rusty_libc_ipc::notify::with_signals_blocked(|| {
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

fn sigevent(value: *mut c_void, signo: c_int, notify: c_int) -> Sigevent {
    Sigevent { sigev_value: Sigval { sival_ptr: value }, sigev_signo: signo, sigev_notify: notify, un: SigevUn { pad: [0; 12] } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_create(clock: ClockId, evp: *mut Sigevent, timerid: *mut TimerId) -> c_int {
    let kclock = match clock {
        CLOCK_PROCESS_CPUTIME_ID => PROCESS_CLOCK,
        CLOCK_THREAD_CPUTIME_ID => THREAD_CLOCK,
        c => c,
    };
    if let Some(ev) = unsafe { evp.as_ref() }
        && ev.sigev_notify == SIGEV_THREAD
    {
        if !start_timer_helper() {
            return fail(EAGAIN);
        }
        let [func, attr_p] = unsafe { ev.un.thread };
        let attr = match unsafe { rusty_libc_ipc::notify::attr_clone(attr_p as *const c_void) } {
            Ok(a) => a,
            Err(e) => return fail(e),
        };
        let t = unsafe { rusty_libc_malloc::malloc(core::mem::size_of::<Timer>()) }.cast::<Timer>();
        if t.is_null() {
            unsafe { rusty_libc_ipc::notify::attr_free(attr) };
            return fail(12);
        }
        let f: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)> = unsafe { core::mem::transmute::<usize, _>(func) };
        let v = rusty_libc_ipc::notify::SigVal { sival_ptr: unsafe { ev.sigev_value.sival_ptr } };
        unsafe { t.write(Timer { notify: f, value: v, attr, ktimer: 0 }) };
        let mut kev = sigevent(t as *mut c_void, SIGTIMER, SIGEV_THREAD_ID);
        kev.un.tid = HELPER_TID.load(core::sync::atomic::Ordering::Acquire);
        let mut kid_out: c_int = 0;
        let r = unsafe { syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, &raw mut kev as usize, &raw mut kid_out as usize) };
        if let Some(e) = raw_err(r) {
            unsafe { rusty_libc_ipc::notify::attr_free(attr) };
            unsafe { rusty_libc_malloc::free(t as *mut c_void) };
            return fail(e);
        }
        unsafe { (*t).ktimer = kid_out };
        *unsafe { sys::arg_mut(timerid) } = thread_timer_id(t);
        return 0;
    }
    let local = sigevent(core::ptr::null_mut(), SIGALRM, SIGEV_SIGNAL);
    let ev: *const Sigevent = if evp.is_null() { &local } else { evp };
    let mut kid: c_int = 0;
    let r = unsafe { syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, ev as usize, &raw mut kid as usize) };
    if let Some(e) = raw_err(r) {
        return fail(e);
    }
    *unsafe { sys::arg_mut(timerid) } = kid as isize as TimerId;
    0
}

fn thread_timer_id(t: *mut Timer) -> TimerId {
    (isize::MIN as usize | (t as usize) >> 1) as TimerId
}

fn is_thread_timer(t: TimerId) -> bool {
    (t as isize) < 0
}

fn thread_timer(t: TimerId) -> *mut Timer {
    ((t as usize) << 1) as *mut Timer
}

#[inline]
unsafe fn kid(t: TimerId) -> usize {
    if is_thread_timer(t) {
        (unsafe { (*thread_timer(t)).ktimer }) as usize
    } else {
        t as usize as u32 as usize
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(t: TimerId, flags: c_int, new: *const Itimerspec, old: *mut Itimerspec) -> c_int {
    let k = unsafe { kid(t) };
    finish(unsafe { syscall::syscall4(SYS_TIMER_SETTIME, k, flags as isize as usize, new as usize, old as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(t: TimerId, value: *mut Itimerspec) -> c_int {
    let k = unsafe { kid(t) };
    finish(unsafe { syscall::syscall2(SYS_TIMER_GETTIME, k, value as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(t: TimerId) -> c_int {
    let k = unsafe { kid(t) };
    let r = unsafe { syscall::syscall1(SYS_TIMER_GETOVERRUN, k) };
    match raw_err(r) {
        None => r as c_int,
        Some(e) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(t: TimerId) -> c_int {
    let k = unsafe { kid(t) };
    let r = finish(unsafe { syscall::syscall1(SYS_TIMER_DELETE, k) });
    if r == 0 && is_thread_timer(t) {
        let p = thread_timer(t);
        let attr = unsafe { (*p).attr };
        unsafe { rusty_libc_ipc::notify::attr_free(attr) };
        unsafe { rusty_libc_malloc::free(p as *mut c_void) };
    }
    r
}

#[inline]
unsafe fn utimensat(fd: usize, path: *const c_char, ts: *const Timespec, flags: usize) -> c_int {
    finish(unsafe { syscall::syscall4(SYS_UTIMENSAT, fd, path as usize, ts as usize, flags) })
}

#[inline]
unsafe fn utimensat_tv(fd: usize, path: *const c_char, tvp: *const Timeval, flags: usize) -> c_int {
    let ts = if tvp.is_null() {
        None
    } else {
        let tv = unsafe { ffi::slice(tvp, 2) };
        Some([0, 1].map(|i| Timespec { tv_sec: tv[i].tv_sec, tv_nsec: tv[i].tv_usec.wrapping_mul(1000) }))
    };
    unsafe { utimensat(fd, path, pair_ptr(&ts), flags) }
}

#[inline]
fn pair_ptr(ts: &Option<[Timespec; 2]>) -> *const Timespec {
    ts.as_ref().map_or(core::ptr::null(), |t| t.as_ptr())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe { utimensat_tv(AT_FDCWD, file, tvp, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lutimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe { utimensat_tv(AT_FDCWD, file, tvp, AT_SYMLINK_NOFOLLOW) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimes(fd: c_int, tvp: *const Timeval) -> c_int {
    unsafe { utimensat_tv(fd as isize as usize, core::ptr::null(), tvp, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimesat(fd: c_int, file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe { utimensat_tv(fd as isize as usize, file, tvp, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utime(file: *const c_char, times: *const Utimbuf) -> c_int {
    let ts = unsafe { times.as_ref() }.map(|t| [Timespec { tv_sec: t.actime, tv_nsec: 0 }, Timespec { tv_sec: t.modtime, tv_nsec: 0 }]);
    unsafe { utimensat(AT_FDCWD, file, pair_ptr(&ts), 0) }
}

pub fn now(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    let r = unsafe { clock_gettime_raw(clock, &mut ts) };
    if r == 0 { Ok(ts) } else { Err(Errno(-r)) }
}

pub fn resolution(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    if let Some(f) = vdso::clock_getres() {
        let r = unsafe { f(clock, (&raw mut ts).cast()) };
        if r != -ENOSYS {
            return if r == 0 { Ok(ts) } else { Err(Errno(-r)) };
        }
    }
    let r = unsafe { syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, &raw mut ts as usize) };
    res(r).map(|_| ts)
}

pub fn unix_time() -> i64 {
    unsafe { time(core::ptr::null_mut()) }
}

pub fn sleep_for(req: Timespec) -> Result<(), (Errno, Timespec)> {
    let mut rem = Timespec::default();
    let e = unsafe { clock_nanosleep(CLOCK_REALTIME, 0, &req, &mut rem) };
    if e == 0 { Ok(()) } else { Err((Errno(e), rem)) }
}

pub fn sleep_until(clock: ClockId, at: Timespec) -> Result<(), Errno> {
    let e = unsafe { clock_nanosleep(clock, TIMER_ABSTIME, &at, core::ptr::null_mut()) };
    if e == 0 { Ok(()) } else { Err(Errno(e)) }
}

