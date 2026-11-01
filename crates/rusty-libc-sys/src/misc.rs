//! Process and system calls that do not fit elsewhere: prctl, getrandom, getentropy, sysinfo and
//! the processor counts, the sched.h family, namespaces (unshare, setns), reboot, mount and
//! the new mount API, swapon, ptrace, personality, klogctl, the timex calls, times, statfs and
//! statvfs, extended attributes, fsuid, acct, quotactl, pidfd calls and the variadic `syscall`.
//!
//! Return values follow glibc 2.43 on x86_64: `-1` with errno set on failure unless a function's
//! note says otherwise.
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{check, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use rusty_libc_core::{Errno, errno};
use crate::kernel::plain;

// ---------------------------------------------------------------- shared helpers

/// Kernel return value to C: the value, or -1 with errno set.
#[inline]
pub(crate) fn sc(ret: usize) -> isize {
    if ret > usize::MAX - 4095 {
        errno::set((ret as isize).wrapping_neg() as i32);
        -1
    } else {
        ret as isize
    }
}

/// Like [`sc`] for `int` results.
#[inline]
pub(crate) fn sci(ret: usize) -> c_int {
    sc(ret) as c_int
}

const SYS_SCHED_YIELD: usize = 24;
const SYS_SYSINFO: usize = 99;
const SYS_TIMES: usize = 100;
const SYS_PTRACE: usize = 101;
const SYS_SYSLOG: usize = 103;
const SYS_PERSONALITY: usize = 135;
const SYS_STATFS: usize = 137;
const SYS_FSTATFS: usize = 138;
const SYS_SCHED_SETPARAM: usize = 142;
const SYS_SCHED_GETPARAM: usize = 143;
const SYS_SCHED_SETSCHEDULER: usize = 144;
const SYS_SCHED_GETSCHEDULER: usize = 145;
const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
const SYS_SCHED_RR_GET_INTERVAL: usize = 148;
const SYS_PIVOT_ROOT: usize = 155;
const SYS_PRCTL: usize = 157;
const SYS_ACCT: usize = 163;
const SYS_MOUNT: usize = 165;
const SYS_UMOUNT2: usize = 166;
const SYS_SWAPON: usize = 167;
const SYS_SWAPOFF: usize = 168;
const SYS_REBOOT: usize = 169;
const SYS_QUOTACTL: usize = 179;
const SYS_SETXATTR: usize = 188;
const SYS_LSETXATTR: usize = 189;
const SYS_FSETXATTR: usize = 190;
const SYS_GETXATTR: usize = 191;
const SYS_LGETXATTR: usize = 192;
const SYS_FGETXATTR: usize = 193;
const SYS_LISTXATTR: usize = 194;
const SYS_LLISTXATTR: usize = 195;
const SYS_FLISTXATTR: usize = 196;
const SYS_REMOVEXATTR: usize = 197;
const SYS_LREMOVEXATTR: usize = 198;
const SYS_FREMOVEXATTR: usize = 199;
const SYS_SETFSUID: usize = 122;
const SYS_SETFSGID: usize = 123;
const SYS_SCHED_SETAFFINITY: usize = 203;
const SYS_SCHED_GETAFFINITY: usize = 204;
const SYS_UNSHARE: usize = 272;
const SYS_SETNS: usize = 308;
const SYS_CAPGET: usize = 125;
const SYS_CAPSET: usize = 126;
const SYS_CLOCK_ADJTIME: usize = 305;
const SYS_SCHED_SETATTR: usize = 314;
const SYS_SCHED_GETATTR: usize = 315;
const SYS_PIDFD_SEND_SIGNAL: usize = 424;
const SYS_OPEN_TREE: usize = 428;
const SYS_MOVE_MOUNT: usize = 429;
const SYS_FSOPEN: usize = 430;
const SYS_FSCONFIG: usize = 431;
const SYS_FSMOUNT: usize = 432;
const SYS_FSPICK: usize = 433;
const SYS_PIDFD_OPEN: usize = 434;
const SYS_PIDFD_GETFD: usize = 438;
const SYS_MOUNT_SETATTR: usize = 442;

const EIO: i32 = 5;
const EINTR: i32 = 4;
const EFAULT: i32 = 14;
const CLOCK_REALTIME: c_int = 0;
const ST_VALID: c_ulong = 0x20;

// ---------------------------------------------------------------- prctl, getrandom, getentropy

/// `prctl(option, ...)`: four more unsigned long arguments are passed through, as glibc does.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn prctl(option: c_int, mut args: ...) -> c_int {
    let mut a = [0 as c_ulong; 4];
    for v in &mut a {
        // SAFETY: glibc's prctl reads four more `unsigned long` arguments whatever the option; missing ones read unspecified
        // values that the option ignores (the same as glibc).
        *v = unsafe { args.next_arg::<c_ulong>() };
    }
    // SAFETY: the arguments go to the kernel as the caller gave them; pointer arguments of an option are checked by the
    // kernel (EFAULT) and must be valid as that option says (the caller's contract).
    sci(unsafe { syscall5(SYS_PRCTL, option as usize, a[0] as usize, a[1] as usize, a[2] as usize, a[3] as usize) })
}

/// Fill `buf` with random bytes from the kernel; the result is the number of bytes stored.
pub fn getrandom_r(buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), flags as usize)) }
}

/// # Safety
/// `buf` has `len` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrandom(buf: *mut c_void, len: usize, flags: c_uint) -> isize {
    // a cancellation point, as in glibc (getentropy and arc4random make the system call directly: not one)
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(rusty_libc_core::syscall::SYS_GETRANDOM, buf as usize, len, flags as usize, 0, 0, 0)) }
}

/// Exactly `len` (at most 256) random bytes: 0 on success, -1 with EIO for a longer request.
///
/// # Safety
/// `buf` has `len` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
    if len > 256 {
        errno::set(EIO);
        return -1;
    }
    let mut p = buf as usize;
    let end = p + len;
    while p < end {
        // SAFETY: [p, end) is the unfilled tail of the caller's `len` writable bytes; the kernel checks it (EFAULT).
        let n = sc(unsafe { syscall3(rusty_libc_core::syscall::SYS_GETRANDOM, p, end - p, 0) });
        if n < 0 {
            if errno::get() == EINTR {
                continue;
            }
            return -1;
        }
        if n == 0 {
            errno::set(EIO);
            return -1;
        }
        p += n as usize;
    }
    0
}

// ---------------------------------------------------------------- sysinfo and processor counts

/// `struct sysinfo` (112 bytes on x86_64, the kernel's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sysinfo {
    pub uptime: c_long,
    pub loads: [c_ulong; 3],
    pub totalram: c_ulong,
    pub freeram: c_ulong,
    pub sharedram: c_ulong,
    pub bufferram: c_ulong,
    pub totalswap: c_ulong,
    pub freeswap: c_ulong,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: c_ulong,
    pub freehigh: c_ulong,
    pub mem_unit: c_uint,
}

/// sysinfo(2) from Rust.
pub fn sysinfo_r() -> Result<sysinfo, Errno> {
    let mut s = sysinfo::default();
    // SAFETY: the kernel writes one `struct sysinfo` into the local `s`.
    unsafe { check(syscall1(SYS_SYSINFO, &mut s as *mut sysinfo as usize))? };
    Ok(s)
}

/// # Safety
/// `info` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sysinfo(info: *mut sysinfo) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall1(SYS_SYSINFO, info as usize)) }
}

/// Number of online processors (sysfs, then /proc/stat, then the affinity mask; 2 as a last resort): rusty-libc-rs-core's
/// `cpus::online`, the one copy of glibc 2.43's steps that sysconf, malloc and the Rust face use too.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_nprocs() -> c_int {
    rusty_libc_rs_core::cpus::online()
}

/// Number of configured (possible) processors (rusty-libc-rs-core's `cpus::configured`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_nprocs_conf() -> c_int {
    rusty_libc_rs_core::cpus::configured()
}

/// (num * mem_unit) / page size without overflowing, as glibc does.
fn mempages(num: c_ulong, mut mem_unit: c_uint) -> c_long {
    let mut ps: c_ulong = 4096;
    while mem_unit > 1 && ps > 1 {
        mem_unit >>= 1;
        ps >>= 1;
    }
    let mut num = num.wrapping_mul(mem_unit as c_ulong);
    while ps > 1 {
        ps >>= 1;
        num >>= 1;
    }
    num as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_phys_pages() -> c_long {
    let s = sysinfo_r().unwrap_or_default();
    mempages(s.totalram, s.mem_unit)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn get_avphys_pages() -> c_long {
    let s = sysinfo_r().unwrap_or_default();
    mempages(s.freeram, s.mem_unit)
}

// ---------------------------------------------------------------- sched.h

/// `struct sched_param`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sched_param {
    pub sched_priority: c_int,
}

/// `struct sched_attr` (version 1, 56 bytes, as in glibc 2.43; the first version was 48 bytes without
/// the two utilisation clamps).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct sched_attr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    pub sched_util_min: u32,
    pub sched_util_max: u32,
}

/// getcpu(2): the CPU and NUMA node the caller runs on (either pointer may be NULL).
///
/// # Safety
/// `cpu` and `node` are NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getcpu(cpu: *mut c_uint, node: *mut c_uint) -> c_int {
    // through the vDSO, as glibc (INLINE_VSYSCALL); the system call only without one
    // SAFETY: the caller's pointers (NULL or writable) go to the vDSO or the kernel untouched.
    unsafe { sci(rusty_libc_core::vdso::getcpu_raw(cpu, node)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_yield() -> c_int {
    sci(plain!(SYS_SCHED_YIELD))
}

/// Affinity mask of `pid` (0 = caller). Returns 0; bytes past what the kernel wrote are zeroed.
///
/// # Safety
/// `mask` has `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getaffinity(pid: c_int, size: usize, mask: *mut c_void) -> c_int {
    // SAFETY: the caller's mask goes to the kernel untouched; it checks it (EFAULT) and writes at most `size` bytes.
    let r = sc(unsafe { syscall3(SYS_SCHED_GETAFFINITY, pid as usize, size.min(i32::MAX as usize), mask as usize) });
    if r != -1 {
        let w = r as usize;
        if size > w {
            // SAFETY: `mask` has `size` writable bytes (contract); the kernel has finished with it.
            let m = unsafe { rusty_libc_core::ffi::bytes_mut(mask.cast::<u8>(), size) };
            m[w..].fill(0);
        }
        return 0;
    }
    -1
}

/// # Safety
/// `mask` has `size` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setaffinity(pid: c_int, size: usize, mask: *const c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_SCHED_SETAFFINITY, pid as usize, size, mask as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_getscheduler(pid: c_int) -> c_int {
    sci(plain!(SYS_SCHED_GETSCHEDULER, pid as usize))
}

/// # Safety
/// `param` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setscheduler(pid: c_int, policy: c_int, param: *const sched_param) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_SCHED_SETSCHEDULER, pid as usize, policy as usize, param as usize)) }
}

/// # Safety
/// `param` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getparam(pid: c_int, param: *mut sched_param) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_SCHED_GETPARAM, pid as usize, param as usize)) }
}

/// # Safety
/// `param` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setparam(pid: c_int, param: *const sched_param) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_SCHED_SETPARAM, pid as usize, param as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    sci(plain!(SYS_SCHED_GET_PRIORITY_MAX, policy as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    sci(plain!(SYS_SCHED_GET_PRIORITY_MIN, policy as usize))
}

/// # Safety
/// `tp` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_rr_get_interval(pid: c_int, tp: *mut crate::poll::timespec) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_SCHED_RR_GET_INTERVAL, pid as usize, tp as usize)) }
}

/// # Safety
/// `attr` has `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getattr(pid: c_int, attr: *mut sched_attr, size: c_uint, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_SCHED_GETATTR, pid as usize, attr as usize, size as usize, flags as usize)) }
}

/// # Safety
/// `attr` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setattr(pid: c_int, attr: *mut sched_attr, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_SCHED_SETATTR, pid as usize, attr as usize, flags as usize)) }
}

/// The CPU the caller is running on, or -1.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sched_getcpu() -> c_int {
    let mut cpu: c_uint = 0;
    // glibc reads the CPU from its rseq area, else from the vDSO's getcpu (we do not register rseq: the vDSO)
    // SAFETY: `cpu` is a local; no node pointer.
    let r = sci(unsafe { rusty_libc_core::vdso::getcpu_raw(&mut cpu, core::ptr::null_mut()) });
    if r == -1 { -1 } else { cpu as c_int }
}

/// Allocate a CPU set for `count` CPUs (what CPU_ALLOC does).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sched_cpualloc(count: usize) -> *mut c_void {
        crate::kernel::malloc(count.div_ceil(64) * 8)
}

/// # Safety
/// `set` came from `__sched_cpualloc` (or is NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpufree(set: *mut c_void) {
    // SAFETY: `set` came from `__sched_cpualloc` (malloc) or is NULL (contract).
    unsafe { rusty_libc_malloc::free(set) }
}

/// Number of CPUs in a set of `setsize` bytes (what CPU_COUNT_S does).
///
/// # Safety
/// `set` has `setsize` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpucount(setsize: usize, set: *const u8) -> c_int {
    // SAFETY: `set` has `setsize` readable bytes (contract).
    let s = unsafe { rusty_libc_core::ffi::bytes(set, setsize) };
    s.iter().map(|b| b.count_ones()).sum::<u32>() as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn unshare(flags: c_int) -> c_int {
    sci(plain!(SYS_UNSHARE, flags as usize))
}

/// Read the capability sets of a process (the raw system call; libcap builds on it). Not declared in
/// any glibc header (`sys/capability.h` is libcap's), but exported by libc.so.6 and used by BusyBox.
///
/// # Safety
/// `header` points to a `struct __user_cap_header_struct` (version, pid); `data` is NULL (only the
/// version is queried) or points to as many `__user_cap_data_struct` as the version needs (2 for v3).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn capget(header: *mut c_void, data: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_CAPGET, header as usize, data as usize)) }
}

/// Set the capability sets of a process (raw system call, see [`capget`]).
///
/// # Safety
/// `header` points to a `struct __user_cap_header_struct`; `data` to the matching data structs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn capset(header: *mut c_void, data: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_CAPSET, header as usize, data as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    sci(plain!(SYS_SETNS, fd as usize, nstype as usize))
}

// ---------------------------------------------------------------- reboot, mount, swap

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn reboot(howto: c_int) -> c_int {
    // SAFETY: the magic numbers and `howto` are values; no command writes user memory (LINUX_REBOOT_CMD_RESTART2 reads a
    // string through the unset fourth argument, as glibc's three-argument call does; the kernel checks that read).
    unsafe { sci(syscall3(SYS_REBOOT, 0xfee1_dead, 672274793, howto as isize as usize)) }
}

/// # Safety
/// All strings are C strings or NULL; `data` is what the filesystem type expects.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mount(source: *const c_char, target: *const c_char, fstype: *const c_char, flags: c_ulong, data: *const c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_MOUNT, source as usize, target as usize, fstype as usize, flags as usize, data as usize)) }
}

/// # Safety
/// `target` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_UMOUNT2, target as usize, 0)) }
}

/// # Safety
/// `target` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_UMOUNT2, target as usize, flags as usize)) }
}

/// # Safety
/// Both are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_PIVOT_ROOT, new_root as usize, put_old as usize)) }
}

/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_tree(dfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_OPEN_TREE, dfd as isize as usize, path as usize, flags as usize)) }
}

/// # Safety
/// Both paths are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn move_mount(from_dfd: c_int, from_path: *const c_char, to_dfd: c_int, to_path: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe {
        sci(syscall5(SYS_MOVE_MOUNT, from_dfd as isize as usize, from_path as usize, to_dfd as isize as usize, to_path as usize, flags as usize))
    }
}

/// # Safety
/// `fsname` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsopen(fsname: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_FSOPEN, fsname as usize, flags as usize)) }
}

/// # Safety
/// `key`, `value` are as the command needs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsconfig(fd: c_int, cmd: c_uint, key: *const c_char, value: *const c_void, aux: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_FSCONFIG, fd as usize, cmd as usize, key as usize, value as usize, aux as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fsmount(fd: c_int, flags: c_uint, attr_flags: c_uint) -> c_int {
    sci(plain!(SYS_FSMOUNT, fd as usize, flags as usize, attr_flags as usize))
}

/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fspick(dfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_FSPICK, dfd as isize as usize, path as usize, flags as usize)) }
}

/// # Safety
/// `path` is a C string; `attr` has `size` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mount_setattr(dfd: c_int, path: *const c_char, flags: c_uint, attr: *mut c_void, size: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_MOUNT_SETATTR, dfd as isize as usize, path as usize, flags as usize, attr as usize, size)) }
}

/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swapon(path: *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_SWAPON, path as usize, flags as usize)) }
}

/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall1(SYS_SWAPOFF, path as usize)) }
}

// ---------------------------------------------------------------- ptrace, personality, klogctl, acct, quotactl

/// `ptrace(request, pid, addr, data)`. For the PEEK requests the word read is the return value
/// and errno is cleared on success, as glibc does.
///
/// # Safety
/// As ptrace(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ptrace(request: c_int, mut args: ...) -> c_long {
    // SAFETY: ptrace's prototype passes pid, addr and data after the request; glibc reads all three for every request
    // (missing ones read unspecified values the request ignores).
    let pid = unsafe { args.next_arg::<c_int>() };
    // SAFETY: as above.
    let addr = unsafe { args.next_arg::<*mut c_void>() };
    // SAFETY: as above.
    let mut data = unsafe { args.next_arg::<*mut c_void>() };
    let mut word: c_long = 0;
    let peek = request > 0 && request < 4;
    if peek {
        data = &mut word as *mut c_long as *mut c_void;
    }
    // SAFETY: for the PEEK requests `data` is the local `word`; otherwise the caller's pointers go to the kernel untouched
    // (it checks them: EFAULT; what it writes in the tracee is the caller's business, as with glibc).
    let res = sc(unsafe { syscall4(SYS_PTRACE, request as isize as usize, pid as isize as usize, addr as usize, data as usize) }) as c_long;
    if res >= 0 && peek {
        errno::set(0);
        return word;
    }
    res
}

/// Returns the previous personality (or the current one for 0xffffffff); the kernel never fails.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn personality(persona: c_ulong) -> c_int {
    plain!(SYS_PERSONALITY, persona as u32 as usize) as isize as c_int
}

/// # Safety
/// `buf` has `len` bytes when the type reads the log.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn klogctl(kind: c_int, buf: *mut c_char, len: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_SYSLOG, kind as usize, buf as usize, len as isize as usize)) }
}

/// # Safety
/// `file` is a C string or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn acct(file: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall1(SYS_ACCT, file as usize)) }
}

/// # Safety
/// As quotactl(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn quotactl(cmd: c_int, special: *const c_char, id: c_int, addr: *mut c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_QUOTACTL, cmd as usize, special as usize, id as isize as usize, addr as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_open(pid: c_int, flags: c_uint) -> c_int {
    sci(plain!(SYS_PIDFD_OPEN, pid as usize, flags as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) -> c_int {
    sci(plain!(SYS_PIDFD_GETFD, pidfd as usize, targetfd as usize, flags as usize))
}

/// # Safety
/// `info` is NULL or a siginfo_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_send_signal(pidfd: c_int, sig: c_int, info: *mut c_void, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_PIDFD_SEND_SIGNAL, pidfd as usize, sig as usize, info as usize, flags as usize)) }
}

/// `syscall(number, ...)`: six arguments are passed through; -1 with errno on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn syscall(number: c_long, mut args: ...) -> c_long {
    let mut a = [0 as c_long; 6];
    for v in &mut a {
        // SAFETY: glibc's syscall reads six `long` arguments whatever the call; missing ones read unspecified values the
        // call ignores.
        *v = unsafe { args.next_arg::<c_long>() };
    }
    // SAFETY: the caller passes what the kernel expects for system call `number` (contract); the kernel checks pointers.
    sc(unsafe { syscall6(number as usize, a[0] as usize, a[1] as usize, a[2] as usize, a[3] as usize, a[4] as usize, a[5] as usize) }) as c_long
}

// ---------------------------------------------------------------- timex

/// `struct timex` (208 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct timex {
    pub modes: c_uint,
    pub offset: c_long,
    pub freq: c_long,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub status: c_int,
    pub constant: c_long,
    pub precision: c_long,
    pub tolerance: c_long,
    pub time: crate::poll::timeval,
    pub tick: c_long,
    pub ppsfreq: c_long,
    pub jitter: c_long,
    pub shift: c_int,
    pub stabil: c_long,
    pub jitcnt: c_long,
    pub calcnt: c_long,
    pub errcnt: c_long,
    pub stbcnt: c_long,
    pub tai: c_int,
    pub _pad: [c_int; 11],
}

/// `struct ntptimeval`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ntptimeval {
    pub time: crate::poll::timeval,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub tai: c_long,
    pub reserved: [c_long; 4],
}

/// # Safety
/// `tx` is a timex (modes selects what is set; setting needs privilege).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clock_adjtime(clock: c_int, tx: *mut timex) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_CLOCK_ADJTIME, clock as usize, tx as usize)) }
}

/// # Safety
/// As [`clock_adjtime`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn adjtimex(tx: *mut timex) -> c_int {
    // SAFETY: `tx` is the caller's, with clock_adjtime's contract.
    unsafe { clock_adjtime(CLOCK_REALTIME, tx) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`clock_adjtime`].
    ntp_adjtime => adjtimex(tx: *mut timex) -> c_int
);

/// # Safety
/// `ntv` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettime(ntv: *mut ntptimeval) -> c_int {
    let mut t = timex::default();
    // SAFETY: `t` is a local `struct timex` (modes 0: read only).
    let r = unsafe { clock_adjtime(CLOCK_REALTIME, &mut t) };
    // SAFETY: `ntv` is writable (contract).
    let ntv = unsafe { &mut *ntv };
    ntv.time = t.time;
    ntv.maxerror = t.maxerror;
    ntv.esterror = t.esterror;
    r
}

/// # Safety
/// `ntv` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettimex(ntv: *mut ntptimeval) -> c_int {
    let mut t = timex::default();
    // SAFETY: `t` is a local `struct timex` (modes 0: read only).
    let r = unsafe { clock_adjtime(CLOCK_REALTIME, &mut t) };
    // SAFETY: `ntv` is writable (contract).
    let ntv = unsafe { &mut *ntv };
    ntv.time = t.time;
    ntv.maxerror = t.maxerror;
    ntv.esterror = t.esterror;
    ntv.tai = t.tai as c_long;
    ntv.reserved = [0; 4];
    r
}

// ---------------------------------------------------------------- times

/// `struct tms`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct tms {
    pub tms_utime: c_long,
    pub tms_stime: c_long,
    pub tms_cutime: c_long,
    pub tms_cstime: c_long,
}

/// Ticks since an arbitrary point. Never fails: a result of -1 is returned as 0, because on
/// Linux -1 is a valid tick count (glibc does the same). errno is not touched.
///
/// # Safety
/// `buf` is NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn times(buf: *mut tms) -> c_long {
    // SAFETY: `buf` (NULL or writable) goes to the kernel untouched; it checks it (EFAULT).
    let ret = unsafe { syscall1(SYS_TIMES, buf as usize) };
    if ret > usize::MAX - 4095 && (ret as isize).wrapping_neg() as i32 == EFAULT && !buf.is_null() {
        // Not necessarily an error (a tick count can look like -EFAULT); like glibc, touch
        // the buffer: it faults if the pointer is bad.
        // SAFETY: `buf` is not NULL and writable by the contract (a bad one faults here, as in glibc); `tms_utime` is its
        // first field.
        let _ = unsafe { core::ptr::read_volatile(buf.cast::<c_long>()) };
    }
    if ret as isize == -1 { 0 } else { ret as c_long }
}

// ---------------------------------------------------------------- statfs, statvfs

/// `struct statfs` (the same as `statfs64` on x86_64; 120 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct statfs {
    pub f_type: c_long,
    pub f_bsize: c_long,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [c_int; 2],
    pub f_namelen: c_long,
    pub f_frsize: c_long,
    pub f_flags: c_long,
    pub f_spare: [c_long; 4],
}

/// `struct statvfs` (the same as `statvfs64` on x86_64; 112 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct statvfs {
    pub f_bsize: c_ulong,
    pub f_frsize: c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: c_ulong,
    pub f_flag: c_ulong,
    pub f_namemax: c_ulong,
    pub f_type: c_uint,
    pub __f_spare: [c_int; 5],
}

/// statfs(2) to the statvfs shape, with glibc's conversions.
pub fn statfs_to_statvfs(fs: &statfs) -> statvfs {
    statvfs {
        f_bsize: fs.f_bsize as c_ulong,
        f_frsize: if fs.f_frsize != 0 { fs.f_frsize } else { fs.f_bsize } as c_ulong,
        f_blocks: fs.f_blocks,
        f_bfree: fs.f_bfree,
        f_bavail: fs.f_bavail,
        f_files: fs.f_files,
        f_ffree: fs.f_ffree,
        f_favail: fs.f_ffree,
        f_fsid: (fs.f_fsid[0] as u32 as c_ulong) | ((fs.f_fsid[1] as u32 as c_ulong) << 32),
        f_flag: (fs.f_flags as c_ulong) ^ ST_VALID,
        f_namemax: fs.f_namelen as c_ulong,
        f_type: fs.f_type as c_uint,
        __f_spare: [0; 5],
    }
}

/// statfs for a path.
///
/// # Safety
/// `path` is a C string.
pub unsafe fn statfs_r(path: *const c_char) -> Result<statfs, Errno> {
    let mut s = statfs::default();
    // SAFETY: `path` is a C string (contract) the kernel only reads; it writes one `struct statfs` into the local `s`.
    check(unsafe { syscall2(SYS_STATFS, path as usize, &mut s as *mut statfs as usize) })?;
    Ok(s)
}

/// # Safety
/// `path` is a C string; `buf` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut statfs) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_STATFS, path as usize, buf as usize)) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`statfs()`].
    statfs64 => statfs(path: *const c_char, buf: *mut statfs) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut statfs) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_FSTATFS, fd as usize, buf as usize)) }
}

crate::unistd::alias!(
    /// # Safety
    /// `buf` is writable.
    fstatfs64 => fstatfs(fd: c_int, buf: *mut statfs) -> c_int
);

/// # Safety
/// `path` is a C string; `buf` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut statvfs) -> c_int {
    let mut fs = statfs::default();
    // SAFETY: `path` is the caller's C string; `fs` is a local.
    if unsafe { statfs(path, &mut fs) } < 0 {
        return -1;
    }
    // SAFETY: `buf` is writable (contract).
    unsafe { buf.write(statfs_to_statvfs(&fs)) };
    0
}

crate::unistd::alias!(
    /// # Safety
    /// As [`statvfs()`].
    statvfs64 => statvfs(path: *const c_char, buf: *mut statvfs) -> c_int
);

/// # Safety
/// `buf` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs(fd: c_int, buf: *mut statvfs) -> c_int {
    let mut fs = statfs::default();
    // SAFETY: `fs` is a local.
    if unsafe { fstatfs(fd, &mut fs) } < 0 {
        return -1;
    }
    // SAFETY: `buf` is writable (contract).
    unsafe { buf.write(statfs_to_statvfs(&fs)) };
    0
}

crate::unistd::alias!(
    /// # Safety
    /// `buf` is writable.
    fstatvfs64 => fstatvfs(fd: c_int, buf: *mut statvfs) -> c_int
);

// ---------------------------------------------------------------- extended attributes

/// # Safety
/// `path`, `name` are C strings; `value` has `size` writable bytes (or size is 0).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall4(SYS_GETXATTR, path as usize, name as usize, value as usize, size)) }
}

/// # Safety
/// As [`getxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgetxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall4(SYS_LGETXATTR, path as usize, name as usize, value as usize, size)) }
}

/// # Safety
/// As [`getxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall4(SYS_FGETXATTR, fd as usize, name as usize, value as usize, size)) }
}

/// # Safety
/// `path`, `name` are C strings; `value` has `size` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_SETXATTR, path as usize, name as usize, value as usize, size, flags as usize)) }
}

/// # Safety
/// As [`setxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lsetxattr(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_LSETXATTR, path as usize, name as usize, value as usize, size, flags as usize)) }
}

/// # Safety
/// As [`setxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetxattr(fd: c_int, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_FSETXATTR, fd as usize, name as usize, value as usize, size, flags as usize)) }
}

/// # Safety
/// `list` has `size` writable bytes (or size is 0).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall3(SYS_LISTXATTR, path as usize, list as usize, size)) }
}

/// # Safety
/// As [`listxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall3(SYS_LLISTXATTR, path as usize, list as usize, size)) }
}

/// # Safety
/// As [`listxattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall3(SYS_FLISTXATTR, fd as usize, list as usize, size)) }
}

/// # Safety
/// `path`, `name` are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_REMOVEXATTR, path as usize, name as usize)) }
}

/// # Safety
/// As [`removexattr`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_LREMOVEXATTR, path as usize, name as usize)) }
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_FREMOVEXATTR, fd as usize, name as usize)) }
}

// ---------------------------------------------------------------- fsuid

/// Sets the filesystem uid and returns the previous one (the kernel gives no error).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setfsuid(uid: c_uint) -> c_int {
    sci(plain!(SYS_SETFSUID, uid as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setfsgid(gid: c_uint) -> c_int {
    sci(plain!(SYS_SETFSGID, gid as usize))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;
    use std::ffi::CString;

    #[test]
    fn capget_matches_the_host() {
        // header { version, pid }: version 0 asks the kernel for its preferred version (EINVAL + version written back)
        let mut h1 = [0u32, 0u32];
        let mut h2 = [0u32, 0u32];
        let r1 = unsafe { capget(h1.as_mut_ptr().cast(), core::ptr::null_mut()) };
        let r2 = unsafe { libc::syscall(libc::SYS_capget, h2.as_mut_ptr(), core::ptr::null_mut::<u32>()) };
        assert_eq!(r1 as i64, r2 as i64);
        assert_eq!(h1, h2);
        assert_eq!(h1[0], 0x2008_0522);
        let mut d1 = [0u32; 6];
        let mut d2 = [0u32; 6];
        let r1 = unsafe { capget(h1.as_mut_ptr().cast(), d1.as_mut_ptr().cast()) };
        let r2 = unsafe { libc::syscall(libc::SYS_capget, h2.as_mut_ptr(), d2.as_mut_ptr()) };
        assert_eq!((r1 as i64, d1), (r2 as i64, d2));
        // a bad pid fails the same way
        h1[1] = 0x7fff_fff0;
        let r = unsafe { capget(h1.as_mut_ptr().cast(), d1.as_mut_ptr().cast()) };
        assert_eq!(r, -1);
        assert_eq!(rusty_libc_core::errno::get(), libc::ESRCH);
    }

    /// The host libc's own versions of functions the `libc` crate does not declare.
    mod host {
        use core::ffi::{c_int, c_long};
        unsafe extern "C" {
            pub fn get_nprocs() -> c_int;
            pub fn get_nprocs_conf() -> c_int;
            pub fn get_phys_pages() -> c_long;
            pub fn get_avphys_pages() -> c_long;
        }
    }

    fn herrno() -> i32 {
        unsafe { *libc::__errno_location() }
    }

    fn euid_is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(core::mem::size_of::<sysinfo>(), core::mem::size_of::<libc::sysinfo>());
        assert_eq!(core::mem::size_of::<sysinfo>(), 112);
        assert_eq!(core::mem::size_of::<statfs>(), 120);
        assert_eq!(core::mem::size_of::<statfs>(), core::mem::size_of::<libc::statfs>());
        assert_eq!(core::mem::size_of::<statvfs>(), 112);
        assert_eq!(core::mem::size_of::<statvfs>(), core::mem::size_of::<libc::statvfs>());
        assert_eq!(core::mem::size_of::<timex>(), 208);
        assert_eq!(core::mem::size_of::<timex>(), core::mem::size_of::<libc::timex>());
        assert_eq!(core::mem::size_of::<ntptimeval>(), 72);
        assert_eq!(core::mem::size_of::<tms>(), 32);
        assert_eq!(core::mem::size_of::<sched_attr>(), 56);
    }

    #[test]
    fn prctl_name() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::thread::spawn(|| unsafe {
            let name = b"libcsys-test\0";
            assert_eq!(prctl(15, name.as_ptr() as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong), 0);
            let mut got = [0u8; 16];
            assert_eq!(prctl(16, got.as_mut_ptr() as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong), 0);
            assert_eq!(&got[..13], name);
            let mut h = [0u8; 16];
            assert_eq!(libc::prctl(16, h.as_mut_ptr() as c_ulong, 0, 0, 0), 0);
            assert_eq!(got, h);
            // a long name is truncated to 15 characters, as by the kernel
            let long = b"abcdefghijklmnopqrstuvwxyz\0";
            assert_eq!(prctl(15, long.as_ptr() as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong), 0);
            prctl(16, got.as_mut_ptr() as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong);
            assert_eq!(&got[..15], &long[..15]);
            assert_eq!(got[15], 0);
            // return value passes through (PR_GET_DUMPABLE) and errors set errno
            let d = prctl(3, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong);
            assert_eq!(d, libc::prctl(3, 0, 0, 0, 0));
            assert_eq!(prctl(9999, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong), -1);
            assert_eq!(errno::get(), libc::EINVAL);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn random() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut a = [0u8; 64];
            let mut b = [0u8; 64];
            assert_eq!(getrandom(a.as_mut_ptr().cast(), 64, 0), 64);
            assert_eq!(getrandom(b.as_mut_ptr().cast(), 64, 1), 64);
            assert_ne!(a, b);
            assert_ne!(a, [0u8; 64]);
            assert_eq!(getrandom(a.as_mut_ptr().cast(), 0, 0), 0);
            assert_eq!(getrandom(a.as_mut_ptr().cast(), 8, 0x80), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(libc::getrandom(a.as_mut_ptr().cast(), 8, 0x80), -1);
            assert_eq!(herrno(), libc::EINVAL);
            // getentropy: up to 256 bytes, EIO above
            let mut big = [0u8; 300];
            assert_eq!(getentropy(big.as_mut_ptr().cast(), 256), 0);
            assert!(big[..256].iter().any(|&x| x != 0));
            assert_eq!(big[256], 0);
            assert_eq!(getentropy(big.as_mut_ptr().cast(), 257), -1);
            assert_eq!(errno::get(), libc::EIO);
            assert_eq!(libc::getentropy(big.as_mut_ptr().cast(), 257), -1);
            assert_eq!(herrno(), libc::EIO);
            assert_eq!(getentropy(big.as_mut_ptr().cast(), 0), 0);
            assert_eq!(getentropy(core::ptr::null_mut(), 5), -1);
            assert_eq!(errno::get(), libc::EFAULT);
            // Rust API
            assert_eq!(getrandom_r(&mut a, 0), Ok(64));
        }
    }

    #[test]
    fn sysinfo_and_processor_counts_match_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut s = sysinfo::default();
            let mut h: libc::sysinfo = core::mem::zeroed();
            assert_eq!(self::sysinfo(&mut s), 0);
            assert_eq!(libc::sysinfo(&mut h), 0);
            assert_eq!(s.totalram, h.totalram);
            assert_eq!(s.mem_unit, h.mem_unit);
            assert_eq!(s.totalswap, h.totalswap);
            assert!((s.uptime - h.uptime).abs() <= 2);
            assert!(s.freeram <= s.totalram);
            assert!(s.procs > 0);
            assert_eq!(sysinfo_r().unwrap().totalram, s.totalram);
            assert_eq!(self::sysinfo(core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), libc::EFAULT);
            assert_eq!(get_nprocs(), host::get_nprocs());
            assert_eq!(get_nprocs_conf(), host::get_nprocs_conf());
            assert!(get_nprocs() >= 1);
            assert_eq!(get_phys_pages(), host::get_phys_pages());
            let (a, b) = (get_avphys_pages(), host::get_avphys_pages());
            assert!((a - b).abs() < 64 * 1024 * 1024 / 4096, "avphys {a} vs {b}");
            // sysfs list parser (rusty-libc-rs-core's)
            use rusty_libc_rs_core::cpus;
            assert_eq!(cpus::range_count(b"0-15\n"), 16);
            assert_eq!(cpus::range_count(b"0\n"), 1);
            assert_eq!(cpus::range_count(b"0-3,5,8-9\n"), 7);
            assert_eq!(cpus::range_count(b"\n"), 0);
            assert_eq!(cpus::range_count(b""), 0);
            assert_eq!(cpus::range_count(b"x"), 0);
            assert_eq!(cpus::range_count(b"2-1\n"), 0);
            assert!(cpus::from_proc_stat() >= host::get_nprocs());
            assert!(cpus::from_affinity() >= 1);
            // page arithmetic
            assert_eq!(mempages(1 << 20, 1), (1 << 20) / 4096);
            assert_eq!(mempages(1 << 20, 4096), 1 << 20);
        }
    }

    #[test]
    fn sched_calls_match_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(sched_yield(), 0);
            // affinity: same answer as the host, with the tail of the buffer zeroed
            let mut a = [0xffu8; 256];
            let mut h = [0xffu8; 256];
            assert_eq!(sched_getaffinity(0, 256, a.as_mut_ptr().cast()), 0);
            assert_eq!(libc::sched_getaffinity(0, 256, h.as_mut_ptr().cast()), 0);
            assert_eq!(a, h);
            assert_eq!(a[255], 0);
            let n: u32 = a.iter().map(|b| b.count_ones()).sum();
            assert_eq!(n as c_int, rusty_libc_rs_core::cpus::from_affinity());
            // too small a buffer: EINVAL for both
            let mut small = [0u8; 1];
            let r = sched_getaffinity(0, 1, small.as_mut_ptr().cast());
            let e = errno::get();
            let rh = libc::sched_getaffinity(0, 1, small.as_mut_ptr().cast());
            assert_eq!((r, e), (rh, herrno()));
            // setting the current mask is accepted
            assert_eq!(sched_setaffinity(0, 128, a.as_ptr().cast()), 0);
            let empty = [0u8; 128];
            assert_eq!(sched_setaffinity(0, 128, empty.as_ptr().cast()), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // policies and priorities
            assert_eq!(sched_getscheduler(0), libc::sched_getscheduler(0));
            for pol in [0, 1, 2, 3, 5, 6, 7, 99, -1] {
                let (a, ea) = (sched_get_priority_max(pol), errno::get());
                let b = libc::sched_get_priority_max(pol);
                assert_eq!(a, b, "max {pol}");
                if a == -1 {
                    assert_eq!(ea, herrno());
                }
                assert_eq!(sched_get_priority_min(pol), libc::sched_get_priority_min(pol), "min {pol}");
            }
            let mut p = sched_param { sched_priority: 77 };
            assert_eq!(sched_getparam(0, &mut p), 0);
            assert_eq!(p.sched_priority, 0);
            assert_eq!(sched_getscheduler(-1), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            let mut ts = crate::poll::timespec::default();
            let mut hts: libc::timespec = core::mem::zeroed();
            assert_eq!(sched_rr_get_interval(0, &mut ts), libc::sched_rr_get_interval(0, &mut hts));
            assert_eq!((ts.tv_sec, ts.tv_nsec), (hts.tv_sec, hts.tv_nsec));
            // the unprivileged failure paths (as root these would change the scheduler: skipped)
            if !euid_is_root() {
                let fifo = sched_param { sched_priority: 1 };
                assert_eq!(sched_setscheduler(0, 1, &fifo), -1);
                assert_eq!(errno::get(), libc::EPERM);
                assert_eq!(libc::sched_setscheduler(0, 1, &fifo as *const sched_param as *const libc::sched_param), -1);
                assert_eq!(herrno(), libc::EPERM);
            }
            // set to what it already is
            let other = sched_param { sched_priority: 0 };
            let cur = sched_getscheduler(0);
            assert_eq!(sched_setscheduler(0, cur & 0xff, &other), 0);
            assert_eq!(sched_setparam(0, &other), 0);
            assert_eq!(sched_setparam(0, core::ptr::null()), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // sched_getattr
            let mut attr = sched_attr::default();
            assert_eq!(sched_getattr(0, &mut attr, 48, 0), 0);
            assert_eq!(attr.size, 48);
            assert_eq!(attr.sched_policy as c_int, cur & 0xff);
            assert_eq!(sched_getattr(0, &mut attr, 1, 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(sched_setattr(-1, &mut attr, 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // getcpu
            let c = sched_getcpu();
            assert!(c >= 0 && c < host::get_nprocs_conf().max(64));
            // namespaces: no-op and failure paths only
            assert_eq!(unshare(0), 0);
            assert_eq!(unshare(0x1), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(setns(-1, 0), -1);
            assert_eq!(errno::get(), libc::EBADF);
            // CPU set helpers
            let set = __sched_cpualloc(65) as *mut u8;
            assert!(!set.is_null());
            core::ptr::write_bytes(set, 0xff, 16);
            assert_eq!(__sched_cpucount(16, set), 128);
            assert_eq!(__sched_cpucount(8, set), 64);
            __sched_cpufree(set.cast());
        }
    }

    #[test]
    fn privileged_calls_fail_without_changing_anything() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if euid_is_root() {
            return; // as root even the failure paths below could do real work
        }
        unsafe {
            let nowhere = CString::new("/nonexistent-libc-sys-dir").unwrap();
            // reboot with a bogus command: EPERM before anything happens
            assert_eq!(reboot(0x1234_5678), -1);
            assert_eq!(errno::get(), libc::EPERM);
            // mount: EPERM
            assert_eq!(mount(core::ptr::null(), nowhere.as_ptr(), core::ptr::null(), 0, core::ptr::null()), -1);
            let e = errno::get();
            assert_eq!(libc::mount(core::ptr::null(), nowhere.as_ptr(), core::ptr::null(), 0, core::ptr::null()), -1);
            assert_eq!(e, herrno());
            assert_eq!(umount(nowhere.as_ptr()), -1);
            let e = errno::get();
            assert_eq!(libc::umount(nowhere.as_ptr()), -1);
            assert_eq!(e, herrno());
            assert_eq!(umount2(nowhere.as_ptr(), 0), -1);
            assert_eq!(errno::get(), e);
            assert_eq!(libc::umount2(nowhere.as_ptr(), 0), -1);
            assert_eq!(pivot_root(nowhere.as_ptr(), nowhere.as_ptr()), -1);
            let e = errno::get();
            assert_eq!(libc::syscall(155, nowhere.as_ptr(), nowhere.as_ptr()), -1);
            assert_eq!(e, herrno());
            // swap
            assert_eq!(swapon(nowhere.as_ptr(), 0), -1);
            let e = errno::get();
            assert_eq!(libc::swapon(nowhere.as_ptr(), 0), -1);
            assert_eq!(e, herrno());
            assert_eq!(swapoff(nowhere.as_ptr()), -1);
            let e = errno::get();
            assert_eq!(libc::swapoff(nowhere.as_ptr()), -1);
            assert_eq!(e, herrno());
            // accounting
            assert_eq!(acct(nowhere.as_ptr()), -1);
            let e = errno::get();
            assert_eq!(libc::acct(nowhere.as_ptr()), -1);
            assert_eq!(e, herrno());
            // the new mount API
            let bogus = CString::new("bogusfs").unwrap();
            assert_eq!(fsopen(bogus.as_ptr(), 0), -1);
            let e = errno::get();
            assert_eq!(libc::syscall(430, bogus.as_ptr(), 0) as c_int, -1);
            assert_eq!(e, herrno());
            // every call below fails; the error number must be the host's (the kernel checks
            // privilege before the descriptor, so it is not always EBADF)
            let same = |ours: c_int, host: libc::c_long| {
                let (e, h) = (errno::get(), herrno());
                assert_eq!((ours, host), (-1, -1));
                assert_eq!(e, h);
            };
            same(fsmount(-1, 0, 0), libc::syscall(432, -1, 0, 0));
            same(fsconfig(-1, 0, core::ptr::null(), core::ptr::null(), 0), libc::syscall(431, -1, 0, 0, 0, 0));
            same(fspick(-1, c"".as_ptr(), 0), libc::syscall(433, -1, c"".as_ptr(), 0));
            same(open_tree(-1, c"".as_ptr(), 0), libc::syscall(428, -1, c"".as_ptr(), 0));
            same(move_mount(-1, c"".as_ptr(), -1, c"".as_ptr(), 0), libc::syscall(429, -1, c"".as_ptr(), -1, c"".as_ptr(), 0));
            same(mount_setattr(-1, c"".as_ptr(), 0, core::ptr::null_mut(), 0), libc::syscall(442, -1, c"".as_ptr(), 0, 0, 0));
            // quota
            assert_eq!(quotactl(0, nowhere.as_ptr(), 0, core::ptr::null_mut()), libc::syscall(179, 0, nowhere.as_ptr(), 0, 0) as c_int);
            // setting the clock: EPERM (modes with ADJ_SETOFFSET)
            let mut tx = timex { modes: 0x0100, ..timex::default() };
            assert_eq!(adjtimex(&mut tx), -1);
            assert_eq!(errno::get(), libc::EPERM);
        }
    }

    #[test]
    fn ptrace_peek_and_errors() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        static WORD: i64 = 0x0123_4567_89ab_cdef;
        unsafe {
            // no such process
            let a = ptrace(16, 0x7fff_fff0 as c_int, 0usize, 0usize); // PTRACE_ATTACH
            let e = errno::get();
            let b = libc::ptrace(libc::PTRACE_ATTACH, 0x7fff_fff0, 0, 0);
            assert_eq!((a, e), (b as c_long, herrno()));
            assert_eq!(e, libc::ESRCH);
            // a real tracee: fork, TRACEME, stop; read its memory through PEEKDATA
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                libc::raise(libc::SIGSTOP);
                libc::_exit(0);
            }
            let mut st = 0;
            assert_eq!(libc::waitpid(pid, &mut st, 0), pid);
            assert!(libc::WIFSTOPPED(st));
            errno::set(99);
            let v = ptrace(2, pid, &WORD as *const i64 as usize, 0usize); // PTRACE_PEEKDATA
            assert_eq!(v, WORD as c_long);
            assert_eq!(errno::get(), 0);
            assert_eq!(v, libc::ptrace(libc::PTRACE_PEEKDATA, pid, &WORD as *const i64, 0) as c_long);
            // PEEK at an unmapped address fails with EIO and returns -1
            errno::set(0);
            let bad = ptrace(2, pid, 8usize, 0usize);
            assert_eq!(bad, -1);
            assert_eq!(errno::get(), libc::EIO);
            // POKE then PEEK
            assert_eq!(ptrace(5, pid, &WORD as *const i64 as usize, 0x55usize), 0); // PTRACE_POKEDATA
            assert_eq!(ptrace(2, pid, &WORD as *const i64 as usize, 0usize), 0x55);
            assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
            libc::waitpid(pid, &mut st, 0);
        }
    }

    #[test]
    fn personality_klogctl_syscall() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            assert_eq!(personality(0xffff_ffff), libc::personality(0xffff_ffff));
            assert_eq!(personality(0xffff_ffff), 0);
            let r = klogctl(10, core::ptr::null_mut(), 0);
            let e = errno::get();
            let h = libc::klogctl(10, core::ptr::null_mut(), 0);
            assert_eq!(r, h);
            if r == -1 {
                assert_eq!(e, herrno());
            }
            let r2 = klogctl(9999, core::ptr::null_mut(), 0);
            let e2 = errno::get();
            assert_eq!(r2, libc::klogctl(9999, core::ptr::null_mut(), 0));
            assert_eq!(e2, herrno());
            // syscall(): arguments pass through, results as for libc, errors set errno
            assert_eq!(syscall(39), libc::getpid() as c_long);
            assert_eq!(syscall(186), libc::syscall(186));
            assert_eq!(syscall(1, 9999 as c_long, 0 as c_long, 0 as c_long), -1);
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(syscall(100_000), -1);
            assert_eq!(errno::get(), libc::ENOSYS);
            let msg = b"via syscall\n";
            assert_eq!(syscall(1, 2 as c_long, msg.as_ptr() as c_long, 12 as c_long), 12);
        }
    }

    #[test]
    fn timex_and_ntp_read_only() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut a = timex::default();
            let mut h: libc::timex = core::mem::zeroed();
            let ra = adjtimex(&mut a);
            let rh = libc::adjtimex(&mut h);
            assert!(ra >= 0);
            assert_eq!(ra, rh);
            assert_eq!(a.offset, h.offset);
            assert_eq!(a.freq, h.freq);
            assert_eq!(a.status, h.status);
            assert_eq!(a.tick, h.tick);
            assert_eq!(a.constant, h.constant);
            assert!((a.time.tv_sec - h.time.tv_sec).abs() <= 1);
            let mut b = timex::default();
            assert_eq!(ntp_adjtime(&mut b), ra);
            assert_eq!(b.tick, a.tick);
            let mut c = timex::default();
            assert_eq!(clock_adjtime(0, &mut c), ra);
            let mut n = ntptimeval { tai: 12345, ..ntptimeval::default() };
            assert_eq!(ntp_gettime(&mut n), ra);
            assert!((n.time.tv_sec - a.time.tv_sec).abs() <= 1);
            assert_eq!(n.maxerror, a.maxerror);
            assert_eq!(n.tai, 12345); // ntp_gettime leaves tai alone
            let mut x = ntptimeval { reserved: [9; 4], ..ntptimeval::default() };
            assert_eq!(ntp_gettimex(&mut x), ra);
            assert_eq!(x.tai, a.tai as c_long);
            assert_eq!(x.reserved, [0; 4]);
            assert_eq!(clock_adjtime(9999, &mut c), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(adjtimex(core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), libc::EFAULT);
        }
    }

    #[test]
    fn times_matches_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut a = tms::default();
            let mut h: libc::tms = core::mem::zeroed();
            let ta = times(&mut a);
            let th = libc::times(&mut h);
            assert!((th - ta).abs() <= 2, "{ta} vs {th}");
            assert!((a.tms_utime - h.tms_utime).abs() <= 2);
            assert!((a.tms_stime - h.tms_stime).abs() <= 2);
            assert_eq!((a.tms_cutime, a.tms_cstime), (h.tms_cutime, h.tms_cstime));
            // NULL buffer allowed; the clock advances
            let t1 = times(core::ptr::null_mut());
            std::thread::sleep(std::time::Duration::from_millis(30));
            let t2 = times(core::ptr::null_mut());
            assert!(t2 > t1);
            // errno untouched
            errno::set(321);
            times(core::ptr::null_mut());
            assert_eq!(errno::get(), 321);
        }
    }

    #[test]
    fn statfs_statvfs_match_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            for dir in ["/", "/tmp", "/proc", "/dev/shm"] {
                let c = CString::new(dir).unwrap();
                let mut a = statfs::default();
                let mut h: libc::statfs = core::mem::zeroed();
                let (ra, rh) = (self::statfs(c.as_ptr(), &mut a), libc::statfs(c.as_ptr(), &mut h));
                assert_eq!(ra, rh, "{dir}");
                if ra != 0 {
                    continue;
                }
                assert_eq!(a.f_type, h.f_type as c_long);
                assert_eq!(a.f_bsize, h.f_bsize as c_long);
                assert_eq!(a.f_frsize, h.f_frsize as c_long);
                assert_eq!(a.f_namelen, h.f_namelen as c_long);
                assert_eq!(a.f_flags, core::mem::transmute_copy::<libc::statfs, [c_long; 15]>(&h)[10], "{dir}");
                assert_eq!(a.f_blocks, h.f_blocks as u64);
                let hfsid: [c_int; 2] = core::mem::transmute_copy(&h.f_fsid);
                assert_eq!(a.f_fsid, hfsid);
                assert_eq!(a.f_spare, [0; 4]);
                let mut a64 = statfs::default();
                assert_eq!(statfs64(c.as_ptr(), &mut a64), 0);
                assert_eq!(a64.f_type, a.f_type);
                // statvfs: converted fields
                let mut v = statvfs::default();
                let mut hv: libc::statvfs = core::mem::zeroed();
                assert_eq!(self::statvfs(c.as_ptr(), &mut v), 0);
                assert_eq!(libc::statvfs(c.as_ptr(), &mut hv), 0);
                assert_eq!(v.f_bsize, hv.f_bsize);
                assert_eq!(v.f_frsize, hv.f_frsize);
                assert_eq!(v.f_blocks, hv.f_blocks as u64);
                assert_eq!(v.f_fsid, hv.f_fsid);
                assert_eq!(v.f_flag, hv.f_flag, "{dir}: flags");
                assert_eq!(v.f_namemax, hv.f_namemax);
                assert_eq!(v.f_files, hv.f_files as u64);
                assert_eq!(v.f_favail, v.f_ffree);
                assert_eq!(v.f_type, a.f_type as c_uint);
                assert_eq!(v.__f_spare, [0; 5]);
                assert_eq!(v.f_flag & ST_VALID, 0);
                let mut v64 = statvfs::default();
                assert_eq!(statvfs64(c.as_ptr(), &mut v64), 0);
                assert_eq!(v64.f_fsid, v.f_fsid);
                // descriptor forms
                let fd = libc::open(c.as_ptr(), libc::O_RDONLY);
                assert!(fd >= 0);
                let mut fa = statfs::default();
                assert_eq!(fstatfs(fd, &mut fa), 0);
                assert_eq!(fa.f_type, a.f_type);
                assert_eq!(fa.f_fsid, a.f_fsid);
                assert_eq!(fstatfs64(fd, &mut fa), 0);
                let mut fv = statvfs::default();
                assert_eq!(fstatvfs(fd, &mut fv), 0);
                assert_eq!(fv.f_flag, v.f_flag);
                assert_eq!(fstatvfs64(fd, &mut fv), 0);
                libc::close(fd);
                // Rust API
                assert_eq!(statfs_r(c.as_ptr()).unwrap().f_type, a.f_type);
                assert_eq!(statfs_to_statvfs(&a).f_flag, v.f_flag);
            }
            // errors
            let missing = CString::new("/nonexistent-libc-sys").unwrap();
            let mut a = statfs::default();
            let mut v = statvfs::default();
            assert_eq!(self::statfs(missing.as_ptr(), &mut a), -1);
            assert_eq!(errno::get(), libc::ENOENT);
            assert_eq!(self::statvfs(missing.as_ptr(), &mut v), -1);
            assert_eq!(errno::get(), libc::ENOENT);
            assert_eq!(fstatfs(-1, &mut a), -1);
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(fstatvfs(-1, &mut v), -1);
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(statfs_r(missing.as_ptr()), Err(Errno(libc::ENOENT)));
        }
    }

    #[test]
    fn xattr_roundtrip() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut path = std::env::temp_dir();
        path.push(format!("libc-sys-xattr-{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let c = CString::new(path.to_str().unwrap()).unwrap();
        let name = c"user.libcsys";
        let name2 = c"user.second";
        unsafe {
            // the file may already carry attributes of its own (an SELinux label): note their size
            let base = listxattr(c.as_ptr(), core::ptr::null_mut(), 0);
            assert!(base >= 0);
            let r = setxattr(c.as_ptr(), name.as_ptr(), b"value1".as_ptr().cast(), 6, 0);
            if r == -1 && (errno::get() == libc::ENOTSUP || errno::get() == libc::EPERM) {
                eprintln!("xattr not supported on {}: skipped", path.display());
                let _ = std::fs::remove_file(&path);
                return;
            }
            assert_eq!(r, 0, "errno {}", errno::get());
            // get: size query, exact buffer, too small, missing name
            assert_eq!(getxattr(c.as_ptr(), name.as_ptr(), core::ptr::null_mut(), 0), 6);
            let mut buf = [0u8; 16];
            assert_eq!(getxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), 16), 6);
            assert_eq!(&buf[..6], b"value1");
            assert_eq!(libc::getxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), 16), 6);
            assert_eq!(getxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), 3), -1);
            assert_eq!(errno::get(), libc::ERANGE);
            assert_eq!(getxattr(c.as_ptr(), name2.as_ptr(), buf.as_mut_ptr().cast(), 16), -1);
            assert_eq!(errno::get(), libc::ENODATA);
            // flags: XATTR_CREATE on an existing name, XATTR_REPLACE on a missing one
            assert_eq!(setxattr(c.as_ptr(), name.as_ptr(), b"v".as_ptr().cast(), 1, 1), -1);
            assert_eq!(errno::get(), libc::EEXIST);
            assert_eq!(setxattr(c.as_ptr(), name2.as_ptr(), b"v".as_ptr().cast(), 1, 2), -1);
            assert_eq!(errno::get(), libc::ENODATA);
            assert_eq!(setxattr(c.as_ptr(), name2.as_ptr(), b"two".as_ptr().cast(), 3, 1), 0);
            // list
            let n = listxattr(c.as_ptr(), core::ptr::null_mut(), 0);
            assert_eq!(n, base + "user.libcsys\0user.second\0".len() as isize);
            let mut lst = [0 as c_char; 256];
            assert_eq!(listxattr(c.as_ptr(), lst.as_mut_ptr(), 256), n);
            let mut hl = [0 as c_char; 256];
            assert_eq!(libc::listxattr(c.as_ptr(), hl.as_mut_ptr(), 256), n);
            assert_eq!(lst[..n as usize], hl[..n as usize]);
            let text: Vec<u8> = lst[..n as usize].iter().map(|&b| b as u8).collect();
            assert!(text.windows(13).any(|w| w == b"user.libcsys\0"));
            assert!(text.windows(12).any(|w| w == b"user.second\0"));
            assert_eq!(listxattr(c.as_ptr(), lst.as_mut_ptr(), 4), -1);
            assert_eq!(errno::get(), libc::ERANGE);
            // l* forms on the file itself, f* forms on a descriptor
            assert_eq!(lgetxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), 16), 6);
            assert_eq!(lsetxattr(c.as_ptr(), name.as_ptr(), b"value2".as_ptr().cast(), 6, 2), 0);
            assert_eq!(llistxattr(c.as_ptr(), core::ptr::null_mut(), 0), n);
            let fd = libc::open(c.as_ptr(), libc::O_RDONLY);
            assert_eq!(fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), 16), 6);
            assert_eq!(&buf[..6], b"value2");
            assert_eq!(fsetxattr(fd, name.as_ptr(), b"value3".as_ptr().cast(), 6, 0), 0);
            assert_eq!(flistxattr(fd, core::ptr::null_mut(), 0), n);
            // remove: each form, and a name that is gone
            assert_eq!(removexattr(c.as_ptr(), name.as_ptr()), 0);
            assert_eq!(removexattr(c.as_ptr(), name.as_ptr()), -1);
            assert_eq!(errno::get(), libc::ENODATA);
            assert_eq!(fremovexattr(fd, name2.as_ptr()), 0);
            assert_eq!(listxattr(c.as_ptr(), core::ptr::null_mut(), 0), base);
            assert_eq!(lsetxattr(c.as_ptr(), name.as_ptr(), b"z".as_ptr().cast(), 1, 0), 0);
            assert_eq!(lremovexattr(c.as_ptr(), name.as_ptr()), 0);
            libc::close(fd);
            // errors: missing file, bad descriptor
            let missing = CString::new("/nonexistent-libc-sys").unwrap();
            assert_eq!(getxattr(missing.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), 16), -1);
            assert_eq!(errno::get(), libc::ENOENT);
            assert_eq!(fgetxattr(-1, name.as_ptr(), buf.as_mut_ptr().cast(), 16), -1);
            assert_eq!(errno::get(), libc::EBADF);
            // a name outside the namespaces: ENOTSUP
            assert_eq!(setxattr(c.as_ptr(), c"bogus.name".as_ptr(), b"v".as_ptr().cast(), 1, 0), -1);
            assert_eq!(errno::get(), libc::ENOTSUP);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fsuid_pidfd_calls() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            // an invalid uid changes nothing and returns the current fsuid
            let cur = libc::geteuid();
            assert_eq!(setfsuid(u32::MAX) as u32, cur);
            assert_eq!(setfsuid(u32::MAX) as u32, cur);
            let g = libc::getegid();
            assert_eq!(setfsgid(u32::MAX) as u32, g);
            // pidfd on ourselves
            let pidfd = pidfd_open(libc::getpid(), 0);
            assert!(pidfd >= 0);
            assert_eq!(pidfd_send_signal(pidfd, 0, core::ptr::null_mut(), 0), 0);
            assert_eq!(pidfd_send_signal(pidfd, 99999, core::ptr::null_mut(), 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            let dup = pidfd_getfd(pidfd, 0, 0);
            if dup >= 0 {
                libc::close(dup);
            }
            libc::close(pidfd);
            assert_eq!(pidfd_open(-1, 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(pidfd_getfd(-1, 0, 0), -1);
            assert_eq!(errno::get(), libc::EBADF);
        }
    }
}
