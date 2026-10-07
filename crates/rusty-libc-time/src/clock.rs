use crate::vdso;
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::{Errno, errno, syscall};

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
    unsafe {
        if let Some(f) = vdso::clock_gettime() {
            let r = f(clock, tp.cast());
            if let Some(r) = vdso_status(r) {
                return r;
            }
        }
        let r = syscall::syscall2(SYS_CLOCK_GETTIME, clock as isize as usize, tp as usize);
        match raw_err(r) {
            None => 0,
            Some(e) => -e,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_gettime(clock: ClockId, tp: *mut Timespec) -> c_int {
    unsafe {
        let r = clock_gettime_raw(clock, tp);
        if r == 0 { 0 } else { fail(-r) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn time(t: *mut TimeT) -> TimeT {
    unsafe {
        if let Some(f) = vdso::time() {
            return f(t);
        }
        let r = syscall::syscall1(SYS_TIME, t as usize);
        match raw_err(r) {
            None => r as i64,
            Some(e) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int {
    unsafe {
        if let Some(f) = vdso::gettimeofday() {
            let r = f(tv.cast(), tz);
            if let Some(r) = vdso_status(r) {
                return if r == 0 { 0 } else { fail(-r) };
            }
        }
        if !tz.is_null() {
            core::ptr::write_bytes(tz.cast::<u8>(), 0, core::mem::size_of::<Timezone>());
        }
        finish(syscall::syscall2(SYS_GETTIMEOFDAY, tv as usize, tz as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getres(clock: ClockId, res: *mut Timespec) -> c_int {
    unsafe {
        if let Some(f) = vdso::clock_getres() {
            let r = f(clock, res.cast());
            if let Some(r) = vdso_status(r) {
                return if r == 0 { 0 } else { fail(-r) };
            }
        }
        finish(syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, res as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_settime(clock: ClockId, tp: *const Timespec) -> c_int {
    unsafe {
        if !valid_nanoseconds((*tp).tv_nsec) {
            return fail(EINVAL);
        }
        finish(syscall::syscall2(SYS_CLOCK_SETTIME, clock as isize as usize, tp as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock() -> ClockT {
    unsafe {
        let mut ts = Timespec::default();
        if clock_gettime_raw(CLOCK_PROCESS_CPUTIME_ID, &mut ts) != 0 {
            return -1;
        }
        ts.tv_sec.wrapping_mul(CLOCKS_PER_SEC).wrapping_add(ts.tv_nsec / (1_000_000_000 / CLOCKS_PER_SEC))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getcpuclockid(pid: c_int, clock_id: *mut ClockId) -> c_int {
    unsafe {
        let pidclock: ClockId = ((!(pid as u32)) << 3 | 2) as ClockId;
        let r = syscall::syscall2(SYS_CLOCK_GETRES, pidclock as isize as usize, 0);
        match raw_err(r) {
            None => {
                *clock_id = pidclock;
                0
            }
            Some(EINVAL) => ESRCH,
            Some(e) => e,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn difftime(t1: TimeT, t0: TimeT) -> f64 {
    (t1 as i128 - t0 as i128) as f64
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_get(ts: *mut Timespec, base: c_int) -> c_int {
    unsafe { if clock_gettime(base.wrapping_sub(1), ts) == 0 { base } else { 0 } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timespec_getres(ts: *mut Timespec, base: c_int) -> c_int {
    unsafe { if clock_getres(base.wrapping_sub(1), ts) == 0 { base } else { 0 } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn settimeofday(tv: *const Timeval, tz: *const Timezone) -> c_int {
    unsafe {
        if !tz.is_null() {
            if !tv.is_null() {
                return fail(EINVAL);
            }
            return finish(syscall::syscall2(SYS_SETTIMEOFDAY, 0, tz as usize));
        }
        if tv.is_null() {
            return fail(EFAULT);
        }
        let ts = Timespec { tv_sec: (*tv).tv_sec, tv_nsec: (*tv).tv_usec.wrapping_mul(1000) };
        clock_settime(CLOCK_REALTIME, &ts)
    }
}

#[cfg_attr(feature = "export", unsafe(export_name = "__rl_stime_impl"))]
pub unsafe extern "C" fn stime(when: *const TimeT) -> c_int {
    unsafe {
        let ts = Timespec { tv_sec: *when, tv_nsec: 0 };
        clock_settime(CLOCK_REALTIME, &ts)
    }
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
    unsafe {
        const MAX_SEC: i64 = (i32::MAX as i64) / 1_000_000 - 2;
        const MIN_SEC: i64 = (i32::MIN as i64) / 1_000_000 + 2;
        let mut tx = Timex { modes: 0, _pad: 0, offset: 0, rest: [0; 24] };
        if !delta.is_null() {
            let d = *delta;
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
        let r = syscall::syscall2(SYS_CLOCK_ADJTIME, CLOCK_REALTIME as usize, &mut tx as *mut Timex as usize);
        if let Some(e) = raw_err(r) {
            return fail(e);
        }
        if !olddelta.is_null() {
            if tx.offset < 0 {
                (*olddelta).tv_usec = -(-tx.offset % 1_000_000);
                (*olddelta).tv_sec = -(-tx.offset / 1_000_000);
            } else {
                (*olddelta).tv_usec = tx.offset % 1_000_000;
                (*olddelta).tv_sec = tx.offset / 1_000_000;
            }
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftime(tb: *mut Timeb) -> c_int {
    unsafe {
        let mut ts = Timespec::default();
        clock_gettime_raw(CLOCK_REALTIME, &mut ts);
        (*tb).time = ts.tv_sec;
        (*tb).millitm = (ts.tv_nsec / 1_000_000) as u16;
        (*tb).timezone = 0;
        (*tb).dstflag = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_nanosleep(clock: ClockId, flags: c_int, req: *const Timespec, rem: *mut Timespec) -> c_int {
    unsafe {
        if clock == CLOCK_THREAD_CPUTIME_ID {
            return EINVAL;
        }
        let clock = if clock == CLOCK_PROCESS_CPUTIME_ID { PROCESS_CLOCK } else { clock };
        let r = rusty_libc_core::tls::syscall_cp(SYS_CLOCK_NANOSLEEP, clock as isize as usize, flags as isize as usize, req as usize, rem as usize, 0, 0);
        raw_err(r).unwrap_or(0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int {
    unsafe {
        let e = clock_nanosleep(CLOCK_REALTIME, 0, req, rem);
        if e != 0 { fail(e) } else { 0 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sleep(seconds: c_uint) -> c_uint {
    unsafe {
        let saved = errno::get();
        let ts_in = Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
        let mut ts = ts_in;
        if nanosleep(&ts_in, &mut ts) < 0 {
            return ts.tv_sec as c_uint;
        }
        errno::set(saved);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn usleep(usec: c_uint) -> c_int {
    unsafe {
        let ts = Timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: (usec % 1_000_000) as i64 * 1000 };
        nanosleep(&ts, core::ptr::null_mut())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getitimer(which: c_int, value: *mut Itimerval) -> c_int {
    unsafe { finish(syscall::syscall2(SYS_GETITIMER, which as isize as usize, value as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setitimer(which: c_int, new: *const Itimerval, old: *mut Itimerval) -> c_int {
    unsafe { finish(syscall::syscall3(SYS_SETITIMER, which as isize as usize, new as usize, old as usize)) }
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
    unsafe {
        let j = arg as *mut Job;
        let (f, v) = ((*j).f, (*j).v);
        rusty_libc_malloc::free(arg);
        rusty_libc_ipc::notify::detach_self();
        rusty_libc_ipc::notify::unblock_all();
        if let Some(f) = f {
            f(v);
        }
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn timer_helper_thread(_arg: *mut c_void) -> *mut c_void {
    use core::sync::atomic::Ordering::*;
    unsafe {
        HELPER_TID.store(syscall::syscall0(syscall::SYS_GETTID) as c_int, Release);
        HELPER_STATE.store(2, Release);
        let set: u64 = 1 << (SIGTIMER - 1);
        loop {
            let mut info = [0u8; 128];
            let r = syscall::syscall4(128, &set as *const u64 as usize, info.as_mut_ptr() as usize, 0, 8);
            if r as isize != SIGTIMER as isize {
                continue;
            }
            let code = core::ptr::read_unaligned(info.as_ptr().add(8) as *const c_int);
            if code != SI_TIMER {
                continue;
            }
            let tp = core::ptr::read_unaligned(info.as_ptr().add(24) as *const *mut Timer);
            if tp.is_null() {
                continue;
            }
            let j = rusty_libc_malloc::malloc(core::mem::size_of::<Job>()) as *mut Job;
            if j.is_null() {
                continue;
            }
            j.write(Job { f: (*tp).notify, v: (*tp).value });
            if rusty_libc_ipc::notify::spawn(timer_notify_thread, j as *mut c_void, (*tp).attr, 0) != 0 {
                rusty_libc_malloc::free(j as *mut c_void);
            }
        }
    }
}

unsafe extern "C" fn timer_fork_child() {
    HELPER_TID.store(0, core::sync::atomic::Ordering::Release);
    HELPER_STATE.store(0, core::sync::atomic::Ordering::Release);
}

unsafe extern "C" fn timer_fork_nop() {}

unsafe fn start_timer_helper() -> bool {
    use core::sync::atomic::Ordering::*;
    unsafe {
        loop {
            match HELPER_STATE.compare_exchange(0, 1, AcqRel, Acquire) {
                Ok(_) => break,
                Err(2) => return true,
                Err(3) => return false,
                Err(_) => {
                    syscall::syscall0(24);
                }
            }
        }
        static HOOKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        if HOOKED.swap(1, AcqRel) == 0 {
            rusty_libc_core::process::register_fork_handlers(timer_fork_nop, timer_fork_nop, timer_fork_child);
        }
        let r = rusty_libc_ipc::notify::with_signals_blocked(|| rusty_libc_ipc::notify::spawn(timer_helper_thread, core::ptr::null_mut(), core::ptr::null(), 128 * 1024));
        if r != 0 {
            HELPER_STATE.store(3, Release);
            return false;
        }
        while HELPER_STATE.load(Acquire) == 1 {
            syscall::syscall0(24);
        }
        HELPER_TID.load(Acquire) != 0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_create(clock: ClockId, evp: *mut Sigevent, timerid: *mut TimerId) -> c_int {
    unsafe {
        let kclock = match clock {
            CLOCK_PROCESS_CPUTIME_ID => PROCESS_CLOCK,
            CLOCK_THREAD_CPUTIME_ID => THREAD_CLOCK,
            c => c,
        };
        if !evp.is_null() && (*evp).sigev_notify == SIGEV_THREAD {
            if !start_timer_helper() {
                return fail(EAGAIN);
            }
            let attr = match rusty_libc_ipc::notify::attr_clone((*evp).un.thread[1] as *const c_void) {
                Ok(a) => a,
                Err(e) => return fail(e),
            };
            let t = rusty_libc_malloc::malloc(core::mem::size_of::<Timer>()) as *mut Timer;
            if t.is_null() {
                rusty_libc_ipc::notify::attr_free(attr);
                return fail(12);
            }
            let f: Option<unsafe extern "C" fn(rusty_libc_ipc::notify::SigVal)> = core::mem::transmute((*evp).un.thread[0]);
            let v = rusty_libc_ipc::notify::SigVal { sival_ptr: (*evp).sigev_value.sival_ptr };
            t.write(Timer { notify: f, value: v, attr, ktimer: 0 });
            let mut kev: Sigevent = core::mem::zeroed();
            kev.sigev_value.sival_ptr = t as *mut c_void;
            kev.sigev_signo = SIGTIMER;
            kev.sigev_notify = 4;
            kev.un.tid = HELPER_TID.load(core::sync::atomic::Ordering::Acquire);
            let mut kid_out: c_int = 0;
            let r = syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, &mut kev as *mut Sigevent as usize, &mut kid_out as *mut c_int as usize);
            if let Some(e) = raw_err(r) {
                rusty_libc_ipc::notify::attr_free(attr);
                rusty_libc_malloc::free(t as *mut c_void);
                return fail(e);
            }
            (*t).ktimer = kid_out;
            *timerid = t as TimerId;
            return 0;
        }
        let mut local: Sigevent = core::mem::zeroed();
        let ev: *mut Sigevent = if evp.is_null() {
            local.sigev_notify = SIGEV_SIGNAL;
            local.sigev_signo = SIGALRM;
            local.sigev_value.sival_ptr = core::ptr::null_mut();
            &mut local
        } else {
            evp
        };
        let mut kid: c_int = 0;
        let r = syscall::syscall3(SYS_TIMER_CREATE, kclock as isize as usize, ev as usize, &mut kid as *mut c_int as usize);
        if let Some(e) = raw_err(r) {
            return fail(e);
        }
        *timerid = (isize::MIN as usize | kid as u32 as usize) as TimerId;
        0
    }
}

#[inline]
unsafe fn kid(t: TimerId) -> usize {
    unsafe {
        if (t as isize) < 0 { (t as usize) & 0x7fff_ffff } else { (*(t as *mut Timer)).ktimer as usize }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(t: TimerId, flags: c_int, new: *const Itimerspec, old: *mut Itimerspec) -> c_int {
    unsafe { finish(syscall::syscall4(SYS_TIMER_SETTIME, kid(t), flags as isize as usize, new as usize, old as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(t: TimerId, value: *mut Itimerspec) -> c_int {
    unsafe { finish(syscall::syscall2(SYS_TIMER_GETTIME, kid(t), value as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(t: TimerId) -> c_int {
    unsafe {
        let r = syscall::syscall1(SYS_TIMER_GETOVERRUN, kid(t));
        match raw_err(r) {
            None => r as c_int,
            Some(e) => fail(e),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(t: TimerId) -> c_int {
    unsafe {
        let r = finish(syscall::syscall1(SYS_TIMER_DELETE, kid(t)));
        if r == 0 && (t as isize) >= 0 {
            let p = t as *mut Timer;
            rusty_libc_ipc::notify::attr_free((*p).attr);
            rusty_libc_malloc::free(p as *mut c_void);
        }
        r
    }
}

#[inline]
unsafe fn utimensat(fd: usize, path: *const c_char, ts: *const Timespec, flags: usize) -> c_int {
    unsafe { finish(syscall::syscall4(SYS_UTIMENSAT, fd, path as usize, ts as usize, flags)) }
}

#[inline]
unsafe fn tv_to_ts(tvp: *const Timeval, ts: &mut [Timespec; 2]) {
    unsafe {
        for (i, t) in ts.iter_mut().enumerate() {
            let tv = *tvp.add(i);
            *t = Timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec.wrapping_mul(1000) };
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe {
        let mut ts = [Timespec::default(); 2];
        if !tvp.is_null() {
            tv_to_ts(tvp, &mut ts);
        }
        utimensat(AT_FDCWD, file, if tvp.is_null() { core::ptr::null() } else { ts.as_ptr() }, 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lutimes(file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe {
        let mut ts = [Timespec::default(); 2];
        if !tvp.is_null() {
            tv_to_ts(tvp, &mut ts);
        }
        utimensat(AT_FDCWD, file, if tvp.is_null() { core::ptr::null() } else { ts.as_ptr() }, AT_SYMLINK_NOFOLLOW)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimes(fd: c_int, tvp: *const Timeval) -> c_int {
    unsafe {
        let mut ts = [Timespec::default(); 2];
        if !tvp.is_null() {
            tv_to_ts(tvp, &mut ts);
        }
        utimensat(fd as isize as usize, core::ptr::null(), if tvp.is_null() { core::ptr::null() } else { ts.as_ptr() }, 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimesat(fd: c_int, file: *const c_char, tvp: *const Timeval) -> c_int {
    unsafe {
        let mut ts = [Timespec::default(); 2];
        if !tvp.is_null() {
            tv_to_ts(tvp, &mut ts);
        }
        utimensat(fd as isize as usize, file, if tvp.is_null() { core::ptr::null() } else { ts.as_ptr() }, 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utime(file: *const c_char, times: *const Utimbuf) -> c_int {
    unsafe {
        let mut ts = [Timespec::default(); 2];
        if !times.is_null() {
            ts[0] = Timespec { tv_sec: (*times).actime, tv_nsec: 0 };
            ts[1] = Timespec { tv_sec: (*times).modtime, tv_nsec: 0 };
        }
        utimensat(AT_FDCWD, file, if times.is_null() { core::ptr::null() } else { ts.as_ptr() }, 0)
    }
}

pub fn now(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    let r = unsafe { clock_gettime_raw(clock, &mut ts) };
    if r == 0 { Ok(ts) } else { Err(Errno(-r)) }
}

pub fn resolution(clock: ClockId) -> Result<Timespec, Errno> {
    let mut ts = Timespec::default();
    let r = unsafe {
        if let Some(f) = vdso::clock_getres() {
            let r = f(clock, (&mut ts as *mut Timespec).cast());
            if r != -ENOSYS {
                return if r == 0 { Ok(ts) } else { Err(Errno(-r)) };
            }
        }
        syscall::syscall2(SYS_CLOCK_GETRES, clock as isize as usize, &mut ts as *mut Timespec as usize)
    };
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

