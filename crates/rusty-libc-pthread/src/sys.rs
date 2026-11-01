//! Raw system calls and constants the thread layer uses: futex, clock-aware absolute waits,
//! signals, scheduling, and the glibc-compatible error numbers.
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

/// `struct timespec` of x86-64 Linux.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// glibc's `sigset_t`: 1024 bits; the kernel only looks at the first 64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigsetT {
    pub val: [u64; 16],
}

/// glibc's `cpu_set_t`: 1024 bits.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuSet {
    pub bits: [u64; 16],
}

/// `pthread_t`: the address of the thread's TCB.
pub type PthreadT = core::ffi::c_ulong;

/// The `struct sched_param` of glibc.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedParam {
    pub sched_priority: c_int,
}

#[inline]
pub fn valid_nsec(ts: &Timespec) -> bool {
    (0..1_000_000_000).contains(&ts.tv_nsec)
}

/// Kernel errno of a raw return value, 0 if it is not an error.
#[inline]
pub fn errno_of(ret: usize) -> c_int {
    if ret > usize::MAX - 4095 { (ret as isize).wrapping_neg() as c_int } else { 0 }
}

#[inline]
fn pflag(private: bool) -> usize {
    if private { FUTEX_PRIVATE_FLAG } else { 0 }
}

/// Raw cancellable system call (a cancellation point). Host unit tests have no thread descriptor of
/// ours behind %fs, so there it is the plain call.
///
/// # Safety
/// Arguments must be valid for system call `nr`.
#[inline]
pub unsafe fn sys_cp(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    #[cfg(not(test))]
    // SAFETY: forwarded contract.
    unsafe {
        crate::cancel::syscall_cp(nr, a1, a2, a3, a4, a5, a6)
    }
    #[cfg(test)]
    // SAFETY: forwarded contract.
    unsafe {
        syscall6(nr, a1, a2, a3, a4, a5, a6)
    }
}

/// Kernel thread id of the calling thread (from the TCB; host unit tests ask the kernel).
#[inline(always)]
pub fn gettid() -> i32 {
    #[cfg(not(test))]
    {
        rusty_libc_core::tls::current_tid()
    }
    #[cfg(test)]
    {
        rusty_libc_core::unistd::gettid()
    }
}

pub use rusty_libc_core::unistd::{getpid, gettid as raw_gettid};

/// The address of a futex word or a timeout as a system-call argument (0 for no timeout).
#[inline(always)]
fn word_arg(addr: &AtomicU32) -> usize {
    addr as *const AtomicU32 as usize
}

#[inline(always)]
fn abs_arg(abs: Option<&Timespec>) -> usize {
    abs.map_or(0, |t| t as *const Timespec as usize)
}

/// FUTEX_WAIT without timeout; returns 0, EAGAIN, EINTR.
#[inline]
pub fn futex_wait(addr: &AtomicU32, val: u32, private: bool) -> c_int {
    // SAFETY: FUTEX_WAIT only reads the word, which `addr` keeps alive for the call; no timeout pointer.
    errno_of(unsafe { syscall4(SYS_FUTEX, word_arg(addr), FUTEX_WAIT | pflag(private), val as usize, 0) })
}

fn abs_check(clock: c_int, abs: Option<&Timespec>) -> c_int {
    if let Some(ts) = abs {
        if !valid_nsec(ts) || (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC) {
            return EINVAL;
        }
        // the kernel rejects a negative time although it is a valid time in the past: glibc answers ETIMEDOUT itself
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

/// Cancellable FUTEX_WAIT with an absolute deadline on `clock` (CLOCK_REALTIME or CLOCK_MONOTONIC);
/// `abs` None means no timeout. Returns 0, EAGAIN, EINTR, ETIMEDOUT, EINVAL.
pub fn futex_wait_abs_cp(addr: &AtomicU32, val: u32, clock: c_int, abs: Option<&Timespec>, private: bool) -> c_int {
    let e = abs_check(clock, abs);
    if e != 0 {
        return e;
    }
    // SAFETY: FUTEX_WAIT_BITSET reads the word and the timeout, both borrowed for the call.
    errno_of(unsafe { sys_cp(SYS_FUTEX, word_arg(addr), wait_op(clock, private), val as usize, abs_arg(abs), 0, FUTEX_BITSET_MATCH_ANY) })
}

/// Same as `futex_wait_abs_cp` but not a cancellation point.
pub fn futex_wait_abs(addr: &AtomicU32, val: u32, clock: c_int, abs: Option<&Timespec>, private: bool) -> c_int {
    let e = abs_check(clock, abs);
    if e != 0 {
        return e;
    }
    // SAFETY: FUTEX_WAIT_BITSET reads the word and the timeout, both borrowed for the call.
    errno_of(unsafe { syscall6(SYS_FUTEX, word_arg(addr), wait_op(clock, private), val as usize, abs_arg(abs), 0, FUTEX_BITSET_MATCH_ANY) })
}

/// Cancellable FUTEX_WAIT without timeout.
pub fn futex_wait_cp(addr: &AtomicU32, val: u32, private: bool) -> c_int {
    // SAFETY: FUTEX_WAIT only reads the word, borrowed for the call.
    errno_of(unsafe { sys_cp(SYS_FUTEX, word_arg(addr), FUTEX_WAIT | pflag(private), val as usize, 0, 0, 0) })
}

#[inline]
pub fn futex_wake(addr: &AtomicU32, n: i32, private: bool) -> i32 {
    // SAFETY: FUTEX_WAKE does not touch the memory (the address is only a key).
    unsafe { syscall3(SYS_FUTEX, word_arg(addr), FUTEX_WAKE | pflag(private), n as usize) as i32 }
}

/// The low 32 bits of a 64-bit futex-holding word (x86-64 is little-endian: the low half comes first), as the word the
/// kernel waits on (glibc's semaphores wait on the value half of their 64-bit word).
#[inline(always)]
pub fn low_word(w: &core::sync::atomic::AtomicU64) -> &AtomicU32 {
    // SAFETY: an AtomicU64 is 8-aligned and 8 bytes, so its first 4 bytes are a valid, aligned AtomicU32 for the borrow; mixed-
    // size atomic access to the same bytes is what glibc does with this word and is well defined on x86-64.
    unsafe { &*(w as *const core::sync::atomic::AtomicU64 as *const AtomicU32) }
}

/// tgkill(2): 0 or the error number.
pub fn tgkill(pid: i32, tid: i32, sig: c_int) -> c_int {
    rusty_libc_core::signal::tgkill(pid, tid, sig).err().map_or(0, |e| e.0)
}

pub fn clock_gettime(clock: c_int, ts: &mut Timespec) -> c_int {
    // SAFETY: `ts` is a valid, exclusively borrowed struct timespec for the call.
    errno_of(unsafe { rusty_libc_core::vdso::clock_gettime_raw(clock, ts as *mut Timespec as *mut core::ffi::c_void) })
}

pub fn sched_yield() {
    // SAFETY: sched_yield takes no arguments.
    unsafe { syscall0(SYS_SCHED_YIELD) };
}

/// Anonymous private read/write mapping (MAP_STACK) at an address the kernel picks (no MAP_FIXED, so no existing memory
/// is touched); the caller owns the result.
pub fn mmap(len: usize, prot: usize) -> Result<*mut u8, c_int> {
    // MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK
    // SAFETY: a new anonymous mapping without MAP_FIXED changes no memory the program already uses.
    let r = unsafe { syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, len, prot, 0x22 | 0x20000, usize::MAX, 0) };
    let e = errno_of(r);
    if e != 0 { Err(e) } else { Ok(r as *mut u8) }
}

/// # Safety
/// `p`/`len` must be a mapping made by `mmap` that nothing uses any more.
pub unsafe fn munmap(p: *mut u8, len: usize) {
    // SAFETY: forwarded contract.
    unsafe { syscall2(rusty_libc_core::syscall::SYS_MUNMAP, p as usize, len) };
}

/// # Safety
/// `p`/`len` must lie inside a mapping of ours whose memory nothing in use lives in when the protection is removed.
pub unsafe fn mprotect(p: *mut u8, len: usize, prot: usize) -> c_int {
    // SAFETY: forwarded contract.
    errno_of(unsafe { syscall3(rusty_libc_core::syscall::SYS_MPROTECT, p as usize, len, prot) })
}

/// rt_sigprocmask(how, set): returns the old mask.
pub fn sigprocmask_set(how: usize, set: u64) -> u64 {
    let mut old = 0u64;
    // SAFETY: both masks are locals of the right size (8 bytes) for the call.
    unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how, &set as *const u64 as usize, &mut old as *mut u64 as usize, 8) };
    old
}

/// End the calling thread only (not the process).
pub fn exit_thread() -> ! {
    loop {
        // SAFETY: exit(0) ends this thread; nothing runs after it.
        unsafe { syscall1(SYS_EXIT, 0) };
    }
}

pub const PAGE: usize = 4096;

pub fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

/// The atomic view of a u32 field of a C struct.
///
/// # Safety
/// `p` must be valid and aligned for the lifetime used.
#[inline(always)]
pub unsafe fn au32<'a>(p: *const u32) -> &'a AtomicU32 {
    // SAFETY: forwarded contract; AtomicU32 has the size and alignment of u32.
    unsafe { &*(p as *const AtomicU32) }
}

/// A C object argument that glibc dereferences without a NULL check (a NULL argument faults, as it does in glibc).
///
/// # Safety
/// `p` points to a valid, initialised `T` that nothing writes for `'a`.
#[inline(always)]
pub unsafe fn arg<'a, T>(p: *const T) -> &'a T {
    // SAFETY: forwarded contract.
    unsafe { &*p }
}

/// A C object argument or out-parameter that glibc writes without a NULL check.
///
/// # Safety
/// `p` points to a valid `T` (for an out-parameter of a plain type: any bit pattern) that nothing else accesses for `'a`.
#[inline(always)]
pub unsafe fn arg_mut<'a, T>(p: *mut T) -> &'a mut T {
    // SAFETY: forwarded contract.
    unsafe { &mut *p }
}

/// Add `ns` nanoseconds to a timespec.
pub fn timespec_add_ns(ts: &mut Timespec, ns: i64) {
    let total = ts.tv_nsec + ns;
    ts.tv_sec += total.div_euclid(1_000_000_000);
    ts.tv_nsec = total.rem_euclid(1_000_000_000);
}
