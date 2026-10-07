use core::ffi::c_int;
use core::sync::atomic::AtomicU32;
use rusty_libc_core::syscall::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall6};

pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const ESRCH: c_int = 3;
pub const EINTR: c_int = 4;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EACCES: c_int = 13;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const EINVAL: c_int = 22;
pub const ENFILE: c_int = 23;
pub const EMFILE: c_int = 24;
pub const ERANGE: c_int = 34;
pub const EDEADLK: c_int = 35;
pub const ENAMETOOLONG: c_int = 36;
pub const ENOSYS: c_int = 38;
pub const EOVERFLOW: c_int = 75;
pub const ENOTSUP: c_int = 95;
pub const ETIMEDOUT: c_int = 110;
pub const EOWNERDEAD: c_int = 130;
pub const ENOTRECOVERABLE: c_int = 131;

pub const SYS_FUTEX: usize = 202;
pub const SYS_CLONE: usize = 56;
pub const SYS_EXIT: usize = 60;
pub const SYS_GETTID: usize = 186;
pub const SYS_TGKILL: usize = 234;
pub const SYS_RT_TGSIGQUEUEINFO: usize = 297;
pub const SYS_SET_ROBUST_LIST: usize = 273;
pub const SYS_SCHED_YIELD: usize = 24;
pub const SYS_SCHED_SETPARAM: usize = 142;
pub const SYS_SCHED_GETPARAM: usize = 143;
pub const SYS_SCHED_SETSCHEDULER: usize = 144;
pub const SYS_SCHED_GETSCHEDULER: usize = 145;
pub const SYS_SCHED_SETAFFINITY: usize = 203;
pub const SYS_SCHED_GETAFFINITY: usize = 204;
pub const SYS_PRCTL: usize = 157;
pub const SYS_PRLIMIT64: usize = 302;
pub const SYS_CLOCK_GETTIME: usize = 228;
pub const SYS_NANOSLEEP: usize = 35;
pub const SYS_CLOCK_NANOSLEEP: usize = 230;

pub const FUTEX_WAIT: usize = 0;
pub const FUTEX_WAKE: usize = 1;
pub const FUTEX_CMP_REQUEUE: usize = 4;
pub const FUTEX_LOCK_PI: usize = 6;
pub const FUTEX_UNLOCK_PI: usize = 7;
pub const FUTEX_TRYLOCK_PI: usize = 8;
pub const FUTEX_WAIT_BITSET: usize = 9;
pub const FUTEX_LOCK_PI2: usize = 13;
pub const FUTEX_PRIVATE_FLAG: usize = 128;
pub const FUTEX_CLOCK_REALTIME: usize = 256;
pub const FUTEX_BITSET_MATCH_ANY: usize = 0xffff_ffff;

pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

pub const CLOCK_REALTIME: c_int = 0;
pub const CLOCK_MONOTONIC: c_int = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigsetT {
    pub val: [u64; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuSet {
    pub bits: [u64; 16],
}

pub type PthreadT = core::ffi::c_ulong;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedParam {
    pub sched_priority: c_int,
}

#[inline]
pub fn valid_nsec(ts: &Timespec) -> bool {
    (0..1_000_000_000).contains(&ts.tv_nsec)
}

#[inline]
pub fn errno_of(ret: usize) -> c_int {
    if ret > usize::MAX - 4095 { (ret as isize).wrapping_neg() as c_int } else { 0 }
}

#[inline]
fn pflag(private: bool) -> usize {
    if private { FUTEX_PRIVATE_FLAG } else { 0 }
}

#[inline]
pub unsafe fn sys_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    unsafe {
        crate::cancel::syscall_cp(nr, a1, a2, a3, a4, a5, a6)
    }
}

#[inline(always)]
pub fn gettid() -> i32 {
    unsafe {
        (*rusty_libc_core::tls::current()).tid
    }
}

pub fn raw_gettid() -> i32 {
    unsafe { syscall0(SYS_GETTID) as i32 }
}

pub fn getpid() -> i32 {
    unsafe { syscall0(39) as i32 }
}

#[inline]
pub fn futex_wait(addr: *const AtomicU32, val: u32, private: bool) -> c_int {
    errno_of(unsafe { syscall4(SYS_FUTEX, addr as usize, FUTEX_WAIT | pflag(private), val as usize, 0) })
}

fn abs_check(clock: c_int, abs: *const Timespec) -> c_int {
    if !abs.is_null() {
        let ts = unsafe { &*abs };
        if !valid_nsec(ts) || (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) {
            return EINVAL;
        }
        if ts.tv_sec < 0 {
            return ETIMEDOUT;
        }
    }
    0
}

fn wait_op(clock: c_int, private: bool) -> usize {
    let mut op = FUTEX_WAIT_BITSET | pflag(private);
    if clock == CLOCK_REALTIME {
        op |= FUTEX_CLOCK_REALTIME;
    }
    op
}

pub fn futex_wait_abs_cp(addr: *const AtomicU32, val: u32, clock: c_int, abs: *const Timespec, private: bool) -> c_int {
    let e = abs_check(clock, abs);
    if e != 0 {
        return e;
    }
    errno_of(unsafe { sys_cp(SYS_FUTEX, addr as usize, wait_op(clock, private), val as usize, abs as usize, 0, FUTEX_BITSET_MATCH_ANY) })
}

pub fn futex_wait_abs(addr: *const AtomicU32, val: u32, clock: c_int, abs: *const Timespec, private: bool) -> c_int {
    let e = abs_check(clock, abs);
    if e != 0 {
        return e;
    }
    errno_of(unsafe { syscall6(SYS_FUTEX, addr as usize, wait_op(clock, private), val as usize, abs as usize, 0, FUTEX_BITSET_MATCH_ANY) })
}

pub fn futex_wait_cp(addr: *const AtomicU32, val: u32, private: bool) -> c_int {
    errno_of(unsafe { sys_cp(SYS_FUTEX, addr as usize, FUTEX_WAIT | pflag(private), val as usize, 0, 0, 0) })
}

#[inline]
pub fn futex_wake(addr: *const AtomicU32, n: i32, private: bool) -> i32 {
    unsafe { syscall3(SYS_FUTEX, addr as usize, FUTEX_WAKE | pflag(private), n as usize) as i32 }
}

pub fn tgkill(pid: i32, tid: i32, sig: c_int) -> c_int {
    errno_of(unsafe { syscall3(SYS_TGKILL, pid as usize, tid as usize, sig as usize) })
}

pub fn clock_gettime(clock: c_int, ts: &mut Timespec) -> c_int {
    errno_of(unsafe { syscall2(SYS_CLOCK_GETTIME, clock as usize, ts as *mut Timespec as usize) })
}

pub fn sched_yield() {
    unsafe { syscall0(SYS_SCHED_YIELD) };
}

pub unsafe fn mmap(len: usize, prot: usize) -> Result<*mut u8, c_int> {
    let r = unsafe { syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, len, prot, 0x22 | 0x20000, usize::MAX, 0) };
    let e = errno_of(r);
    if e != 0 { Err(e) } else { Ok(r as *mut u8) }
}

pub unsafe fn munmap(p: *mut u8, len: usize) {
    unsafe { syscall2(rusty_libc_core::syscall::SYS_MUNMAP, p as usize, len) };
}

pub unsafe fn mprotect(p: *mut u8, len: usize, prot: usize) -> c_int {
    errno_of(unsafe { syscall3(rusty_libc_core::syscall::SYS_MPROTECT, p as usize, len, prot) })
}

pub fn sigprocmask_set(how: usize, set: u64) -> u64 {
    let mut old = 0u64;
    unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how, &set as *const u64 as usize, &mut old as *mut u64 as usize, 8) };
    old
}

pub fn exit_thread() -> ! {
    loop {
        unsafe { syscall1(SYS_EXIT, 0) };
    }
}

pub const PAGE: usize = 4096;

pub fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

#[inline(always)]
pub unsafe fn au32<'a>(p: *const u32) -> &'a AtomicU32 {
    unsafe { &*(p as *const AtomicU32) }
}

pub fn timespec_add_ns(ts: &mut Timespec, ns: i64) {
    let total = ts.tv_nsec + ns;
    ts.tv_sec += total.div_euclid(1_000_000_000);
    ts.tv_nsec = total.rem_euclid(1_000_000_000);
}
