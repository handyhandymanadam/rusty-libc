//! Old and rare calls glibc 2.43 still exports on x86-64: gtty/stty and chflags/fchflags (stubs
//! that fail with ENOSYS, as in glibc), sysctl (the removed `_sysctl` system call: the kernel
//! answers ENOSYS), ioperm/iopl/modify_ldt (x86 privileged I/O and the LDT), the module calls
//! (init_module, delete_module, create_module, query_module, get_kernel_syms), nfsservctl, bdflush,
//! uselib, ustat, vlimit, llseek, arch_prctl, clone and pidfd_getpid.
//!
//! Behaviour was measured against glibc 2.43 on this machine (tests/c/legacy_diff.c).
use crate::resource::Rlimit;
#[cfg(test)]
use crate::resource::{getrlimit, setrlimit};
use crate::unistd::rc;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3, syscall4, syscall5};
use crate::kernel::plain;
use rusty_libc_core::errno;

const ENOSYS: c_int = 38;
const EINVAL: c_int = 22;
const EBADF: c_int = 9;
const ESRCH: c_int = 3;
const ENOENT: c_int = 2;

mod nr {
    pub const ARCH_PRCTL: usize = 158;
    pub const MODIFY_LDT: usize = 154;
    pub const IOPL: usize = 172;
    pub const IOPERM: usize = 173;
    pub const CREATE_MODULE: usize = 174;
    pub const INIT_MODULE: usize = 175;
    pub const DELETE_MODULE: usize = 176;
    pub const GET_KERNEL_SYMS: usize = 177;
    pub const QUERY_MODULE: usize = 178;
    pub const NFSSERVCTL: usize = 180;
    pub const USTAT: usize = 136;
    pub const USELIB: usize = 134;
    pub const OPENAT: usize = 257;
    pub const CLOSE: usize = 3;
}

fn fail(e: c_int) -> c_int {
    errno::set(e);
    -1
}

/// gtty(3): glibc 2.43 only has the stub, which fails with ENOSYS (EINVAL for a NULL `params`).
///
/// # Safety
/// `params` is NULL or a `struct sgttyb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gtty(_fd: c_int, params: *mut c_void) -> c_int {
    fail(if params.is_null() { EINVAL } else { ENOSYS })
}

/// stty(3): the same stub as `gtty`.
///
/// # Safety
/// `params` is NULL or a `struct sgttyb`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn stty(_fd: c_int, params: *const c_void) -> c_int {
    fail(if params.is_null() { EINVAL } else { ENOSYS })
}

/// chflags: BSD file flags do not exist on Linux; glibc fails with ENOSYS.
///
/// # Safety
/// `file` is a C string (not read).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chflags(_file: *const c_char, _flags: c_ulong) -> c_int {
    fail(ENOSYS)
}

/// fchflags: see `chflags`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchflags(_fd: c_int, _flags: c_ulong) -> c_int {
    fail(ENOSYS)
}

/// sysctl(2): glibc 2.43 keeps it as a compatibility symbol that fails with ENOSYS without a system call (the kernel's
/// `_sysctl` is gone; making the call anyway is one a seccomp allowlist made from glibc's calls does not have).
///
/// # Safety
/// Any arguments (unused).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sysctl(_name: *mut c_int, _nlen: c_int, _oldval: *mut c_void, _oldlenp: *mut usize, _newval: *mut c_void, _newlen: usize) -> c_int {
    fail(ENOSYS)
}

/// ioperm(2): allow or forbid access to `num` I/O ports from `from` (needs CAP_SYS_RAWIO).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ioperm(from: c_ulong, num: c_ulong, turn_on: c_int) -> c_int {
    // SAFETY: values only; port access changes no memory of the program.
    rc(unsafe { syscall3(nr::IOPERM, from as usize, num as usize, turn_on as isize as usize) })
}

/// iopl(2): set the I/O privilege level (needs CAP_SYS_RAWIO to raise it).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn iopl(level: c_int) -> c_int {
    // SAFETY: a value only; the I/O privilege level changes no memory of the program.
    rc(unsafe { syscall1(nr::IOPL, level as isize as usize) })
}

/// modify_ldt(2): read or write the local descriptor table; returns the kernel's result.
///
/// # Safety
/// `ptr` is valid for `bytecount` bytes (or the descriptor, as `func` says).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn modify_ldt(func: c_int, ptr: *mut c_void, bytecount: c_ulong) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall3(nr::MODIFY_LDT, func as isize as usize, ptr as usize, bytecount as usize) })
}

/// init_module(2): load a kernel module from the image in memory.
///
/// # Safety
/// `image` is valid for `len` bytes; `params` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn init_module(image: *mut c_void, len: c_ulong, params: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall3(nr::INIT_MODULE, image as usize, len as usize, params as usize) })
}

/// delete_module(2): unload a kernel module.
///
/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall2(nr::DELETE_MODULE, name as usize, flags as usize) })
}

/// create_module(2): removed from Linux 2.6; the kernel answers ENOSYS.
///
/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn create_module(name: *const c_char, size: usize) -> c_long {
    // SAFETY: `name` goes to the kernel untouched (it answers ENOSYS without reading it).
    let r = rc(unsafe { syscall2(nr::CREATE_MODULE, name as usize, size) });
    r as c_long
}

/// query_module(2): removed from Linux 2.6; the kernel answers ENOSYS.
///
/// # Safety
/// `buf` and `ret` are as the old system call took them.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn query_module(name: *const c_char, which: c_int, buf: *mut c_void, bufsize: usize, ret: *mut usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall5(nr::QUERY_MODULE, name as usize, which as isize as usize, buf as usize, bufsize, ret as usize) })
}

/// get_kernel_syms(2): removed from Linux 2.6; the kernel answers ENOSYS.
///
/// # Safety
/// `table` is NULL or a buffer for the symbol table.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_kernel_syms(table: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall1(nr::GET_KERNEL_SYMS, table as usize) })
}

/// nfsservctl(2): removed in Linux 3.1; the kernel answers ENOSYS.
///
/// # Safety
/// The pointers are as the old system call took them.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_long {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall3(nr::NFSSERVCTL, cmd as isize as usize, argp as usize, resp as usize) }) as c_long
}

/// uselib(2): load a shared library with the old a.out/ELF loader (CONFIG_USELIB, off on most kernels).
///
/// # Safety
/// `library` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uselib(library: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall1(nr::USELIB, library as usize) })
}

/// ustat(2).
///
/// # Safety
/// `ubuf` is a `struct ustat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ustat(dev: c_ulong, ubuf: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall2(nr::USTAT, dev as usize, ubuf as usize) })
}

/// bdflush(2): removed from Linux; there is no such system call on x86-64, glibc fails with ENOSYS.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn bdflush(_func: c_int, _data: c_long) -> c_int {
    fail(ENOSYS)
}

crate::unistd::alias!(
    /// `__sysctl`: the internal name of `sysctl`.
    ///
    /// # Safety
    /// As `sysctl`.
    __sysctl => sysctl(name: *mut c_int, nlen: c_int, oldval: *mut c_void, oldlenp: *mut usize, newval: *mut c_void, newlen: usize) -> c_int
);

/// isastream (STREAMS): Linux has no STREAMS, so a valid descriptor is not a stream (0); a bad one is
/// EBADF.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isastream(fildes: c_int) -> c_int {
    // fcntl(fd, F_GETFD) is the cheapest check that the descriptor is open
    match rusty_libc_core::unistd::fcntl_int(fildes, rusty_libc_core::unistd::F_GETFD, 0) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

/// getmsg (STREAMS): not implemented on Linux, ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmsg(_fildes: c_int, _ctlptr: *mut c_void, _dataptr: *mut c_void, _flagsp: *mut c_int) -> c_int {
    fail(ENOSYS)
}

/// getpmsg (STREAMS): ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpmsg(_fildes: c_int, _ctlptr: *mut c_void, _dataptr: *mut c_void, _bandp: *mut c_int, _flagsp: *mut c_int) -> c_int {
    fail(ENOSYS)
}

/// putmsg (STREAMS): ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putmsg(_fildes: c_int, _ctlptr: *const c_void, _dataptr: *const c_void, _flags: c_int) -> c_int {
    fail(ENOSYS)
}

/// putpmsg (STREAMS): ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putpmsg(_fildes: c_int, _ctlptr: *const c_void, _dataptr: *const c_void, _band: c_int, _flags: c_int) -> c_int {
    fail(ENOSYS)
}

/// fattach (STREAMS): ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fattach(_fildes: c_int, _path: *const c_char) -> c_int {
    fail(ENOSYS)
}

/// fdetach (STREAMS): ENOSYS.
///
/// # Safety
/// Not read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdetach(_path: *const c_char) -> c_int {
    fail(ENOSYS)
}

/// sstk (4.2BSD stack size change): not implemented, ENOSYS.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sstk(_increment: c_int) -> *mut c_void {
    errno::set(ENOSYS);
    -1isize as *mut c_void
}

/// `struct vtimes` of the old 4.2BSD `vtimes` call.
#[repr(C)]
pub struct Vtimes {
    pub vm_utime: c_int,
    pub vm_stime: c_int,
    pub vm_idsrss: c_uint,
    pub vm_ixrss: c_uint,
    pub vm_maxrss: c_int,
    pub vm_majflt: c_int,
    pub vm_minflt: c_int,
    pub vm_nswap: c_int,
    pub vm_inblk: c_int,
    pub vm_oublk: c_int,
}

/// vtimes (4.2BSD): resource usage of this process and of its waited-for children, in the old units
/// (times in 1/60 s), from getrusage. 0, or -1 with errno.
///
/// # Safety
/// `current` and `child` are NULL or point to a `struct vtimes`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vtimes(current: *mut Vtimes, child: *mut Vtimes) -> c_int {
    const HZ: i64 = 60;
    fn from_usage(v: &mut Vtimes, r: &crate::resource::Rusage) {
        let ticks = |t: &crate::resource::Timeval| (t.tv_sec * HZ + t.tv_usec * HZ / 1_000_000) as c_int;
        v.vm_utime = ticks(&r.ru_utime);
        v.vm_stime = ticks(&r.ru_stime);
        // the old average of data+stack size over run time: the kernel keeps neither
        v.vm_idsrss = (r.ru_idrss as u64).wrapping_add(r.ru_isrss as u64) as c_uint;
        // vm_ixrss and vm_maxrss are never written (glibc leaves them as they were)
        v.vm_majflt = r.ru_majflt as c_int;
        v.vm_minflt = r.ru_minflt as c_int;
        v.vm_nswap = r.ru_nswap as c_int;
        v.vm_inblk = r.ru_inblock as c_int;
        v.vm_oublk = r.ru_oublock as c_int;
    }
    let mut usage = crate::resource::Rusage::default();
    // SAFETY: `current` is NULL or a writable `struct vtimes` (contract); `as_mut` checks NULL.
    if let Some(cur) = unsafe { current.as_mut() } {
        // SAFETY: `usage` is a local `struct rusage`.
        if unsafe { crate::resource::getrusage(crate::resource::RUSAGE_SELF, (&mut usage as *mut crate::resource::Rusage).cast()) } < 0 {
            return -1;
        }
        from_usage(cur, &usage);
    }
    // SAFETY: as for `current`.
    if let Some(ch) = unsafe { child.as_mut() } {
        // SAFETY: as above.
        if unsafe { crate::resource::getrusage(crate::resource::RUSAGE_CHILDREN, (&mut usage as *mut crate::resource::Rusage).cast()) } < 0 {
            return -1;
        }
        from_usage(ch, &usage);
    }
    0
}

/// vlimit (4.2BSD): set the soft limit of a resource, LIM_CPU .. LIM_MAXRSS (1..=6); the hard limit
/// stays. `value` is sign-extended into `rlim_t`. Any other resource: EINVAL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vlimit(resource: c_int, value: c_int) -> c_int {
    use crate::resource::{RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_RSS, RLIMIT_STACK};
    let res = match resource {
        1 => RLIMIT_CPU,
        2 => RLIMIT_FSIZE,
        3 => RLIMIT_DATA,
        4 => RLIMIT_STACK,
        5 => RLIMIT_CORE,
        6 => RLIMIT_RSS,
        _ => return fail(EINVAL),
    };
    let mut lim = Rlimit::default();
    if crate::resource::rs::getrlimit_into(res, &mut lim) < 0 {
        return -1;
    }
    lim.rlim_cur = value as i64 as u64;
    crate::resource::rs::setrlimit_from(res, &lim)
}

/// llseek: the old name of `lseek64`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    crate::unistd::lseek(fd, offset, whence)
}

/// arch_prctl(2): `ARCH_SET_FS`, `ARCH_GET_CPUID` ...; the result is the kernel's (a value for the
/// GET codes that return one, else 0), -1 with errno on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn arch_prctl(code: c_int, addr: c_ulong) -> c_int {
    // SAFETY: the C interface, as glibc's: ARCH_SET_FS/ARCH_SET_GS move the thread pointer and the GET codes store through
    // `addr` (the kernel checks it: EFAULT); a program that uses them takes over the TLS the library relies on, exactly as
    // with glibc.
    rc(unsafe { syscall2(nr::ARCH_PRCTL, code as isize as usize, addr as usize) })
}

// clone(fn, stack, flags, arg, ptid, tls, ctid): glibc's x86-64 wrapper. NULL `fn` or `stack` is
// EINVAL; `fn` and `arg` are put on the new stack and the child calls fn(arg), then exits with its
// return value. rl_clone_raw takes the arguments as the C function does and returns the kernel's
// raw result (negative errno on failure).
core::arch::global_asm!(
    ".text",
    ".globl rl_clone_raw",
    ".type rl_clone_raw, @function",
    "rl_clone_raw:",
    "mov rax, -22",
    "test rdi, rdi",
    "jz 2f",
    "test rsi, rsi",
    "jz 2f",
    "and rsi, -16",
    "sub rsi, 16",
    "mov qword ptr [rsi + 8], rcx",
    "mov qword ptr [rsi], rdi",
    "mov rdi, rdx",
    "mov rdx, r8",
    "mov r8, r9",
    "mov r10, qword ptr [rsp + 8]",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jz 3f",
    "2:",
    "ret",
    "3:",
    "xor ebp, ebp",
    "pop rax",
    "pop rdi",
    "call rax",
    "mov rdi, rax",
    "mov eax, 60",
    "syscall",
    "ud2",
    ".size rl_clone_raw, . - rl_clone_raw",
);

unsafe extern "C" {
    fn rl_clone_raw(f: unsafe extern "C" fn(*mut c_void) -> c_int, stack: *mut c_void, flags: c_int, arg: *mut c_void, ptid: *mut c_int, tls: *mut c_void, ctid: *mut c_int) -> isize;
}

/// clone(2) with a function to run in the child: `fn(arg)` runs on `stack` (the top of the new
/// stack; the caller aligns it) and its return value is the child's exit status. The optional
/// arguments are `pid_t *ptid, void *tls, pid_t *ctid` (read whether or not the flags use them, as
/// glibc's assembly does; the kernel ignores them without the matching flags). Returns the child's
/// thread id, or -1 with errno.
///
/// # Safety
/// As clone(2): the child shares what `flags` say it shares and runs on the caller's `stack`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clone(f: Option<unsafe extern "C" fn(*mut c_void) -> c_int>, stack: *mut c_void, flags: c_int, arg: *mut c_void, mut args: ...) -> c_int {
    let mut opt = [core::ptr::null_mut::<c_void>(); 3];
    for v in &mut opt {
        // SAFETY: glibc's clone reads ptid, tls and ctid whatever the flags (missing ones read unspecified values the
        // kernel ignores without the matching flags).
        *v = unsafe { args.next_arg::<*mut c_void>() };
    }
    let [ptid, tls, ctid] = opt;
    let Some(f) = f else { return fail(EINVAL) };
    // SAFETY: the caller's contract is clone(2)'s (the child runs `f(arg)` on `stack` and shares what `flags` say).
    rc(unsafe { rl_clone_raw(f, stack, flags, arg, ptid.cast(), tls, ctid.cast()) } as usize)
}

/// pidfd_getpid (glibc 2.39): the process id a pidfd refers to, read from /proc/self/fdinfo/<fd>.
/// EBADF for a descriptor that is not a pidfd, ESRCH when the process is gone.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pidfd_getpid(fd: c_int) -> c_int {
    if fd < 0 {
        return fail(EBADF);
    }
    // "/proc/self/fdinfo/" + digits + NUL
    let mut path = [0u8; 40];
    let prefix = b"/proc/self/fdinfo/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 12];
    let mut n = fd as u32;
    let mut k = digits.len();
    loop {
        k -= 1;
        digits[k] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let dl = digits.len() - k;
    path[prefix.len()..prefix.len() + dl].copy_from_slice(&digits[k..]);
    const AT_FDCWD: usize = -100isize as usize;
    const O_RDONLY_CLOEXEC: usize = 0o2000000;
    // SAFETY: `path` is NUL-terminated (its tail is zeros: 18 + at most 10 digits < 40 bytes); the kernel only reads it.
    let f = unsafe { syscall4(nr::OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY_CLOEXEC, 0) };
    let f = match syscall::check(f) {
        Ok(v) => v as c_int,
        Err(e) => {
            errno::set(if e.0 == ENOENT { EBADF } else { e.0 });
            return -1;
        }
    };
    // fdinfo is small; read it whole
    let mut buf = [0u8; 1024];
    let mut len = 0usize;
    loop {
        let r = crate::kernel::read_nocancel(f as usize, &mut buf[len..]);
        match syscall::check(r) {
            Ok(0) => break,
            Ok(m) => {
                len += m;
                if len == buf.len() {
                    break;
                }
            }
            Err(e) => {
                plain!(nr::CLOSE, f as usize);
                errno::set(e.0);
                return -1;
            }
        }
    }
    plain!(nr::CLOSE, f as usize);
    let text = &buf[..len];
    let mut pid: Option<i32> = None;
    for line in text.split(|&c| c == b'\n') {
        if let Some(rest) = line.strip_prefix(b"Pid:") {
            let rest = rest.trim_ascii_start();
            let (neg, rest) = match rest.first() {
                Some(b'-') => (true, &rest[1..]),
                Some(b'+') => (false, &rest[1..]),
                _ => (false, rest),
            };
            let mut v: i64 = 0;
            let mut any = false;
            for &c in rest {
                if !c.is_ascii_digit() {
                    break;
                }
                any = true;
                v = (v * 10 + (c - b'0') as i64).min(i32::MAX as i64 + 1);
            }
            if any {
                pid = Some(if neg { -(v as i32) } else { v as i32 });
                break;
            }
        }
    }
    match pid {
        None => fail(EBADF),
        Some(-1) => fail(ESRCH),
        Some(p) => p,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn gtty_stty_are_stubs() {
        let mut buf = [0u8; 8];
        unsafe {
            assert_eq!(gtty(0, buf.as_mut_ptr().cast()), -1);
            assert_eq!(errno::get(), ENOSYS);
            assert_eq!(gtty(0, core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
            assert_eq!(stty(0, buf.as_ptr().cast()), -1);
            assert_eq!(errno::get(), ENOSYS);
            assert_eq!(stty(0, core::ptr::null()), -1);
            assert_eq!(errno::get(), EINVAL);
        }
    }

    #[test]
    fn chflags_is_enosys() {
        unsafe {
            assert_eq!(chflags(c"/tmp".as_ptr(), 0), -1);
        }
        assert_eq!(errno::get(), ENOSYS);
        assert_eq!(fchflags(0, 0), -1);
        assert_eq!(errno::get(), ENOSYS);
    }

    #[test]
    fn sysctl_fails_like_the_kernel() {
        let mut name = [1, 1];
        let mut buf = [0u8; 64];
        let mut len = buf.len();
        let r = unsafe { sysctl(name.as_mut_ptr(), 2, buf.as_mut_ptr().cast(), &mut len, core::ptr::null_mut(), 0) };
        assert_eq!(r, -1);
        assert_eq!(errno::get(), ENOSYS);
    }

    #[test]
    fn vlimit_sets_the_soft_limit() {
        assert_eq!(vlimit(0, 1), -1);
        assert_eq!(errno::get(), EINVAL);
        assert_eq!(vlimit(7, 1), -1);
        assert_eq!(vlimit(-1, 1), -1);
        assert_eq!(errno::get(), EINVAL);
        let mut old = Rlimit::default();
        unsafe { getrlimit(crate::resource::RLIMIT_CORE, &mut old) };
        assert_eq!(vlimit(5, 0), 0);
        let mut now = Rlimit::default();
        unsafe { getrlimit(crate::resource::RLIMIT_CORE, &mut now) };
        assert_eq!(now.rlim_cur, 0);
        assert_eq!(now.rlim_max, old.rlim_max);
        unsafe { setrlimit(crate::resource::RLIMIT_CORE, &old) };
    }

    #[test]
    fn iopl_level_out_of_range_is_einval() {
        assert_eq!(iopl(4), -1);
        assert_eq!(errno::get(), EINVAL);
        assert_eq!(iopl(0), 0);
    }

    #[test]
    fn llseek_is_lseek64() {
        let fd = unsafe { libc::open(c"/proc/self/stat".as_ptr(), 0) };
        assert!(fd >= 0);
        assert_eq!(llseek(fd, 3, 0), 3);
        assert_eq!(llseek(fd, 2, 1), 5);
        assert_eq!(llseek(-1, 0, 0), -1);
        assert_eq!(errno::get(), EBADF);
        unsafe { libc::close(fd) };
    }

    #[test]
    fn arch_prctl_get_cpuid() {
        // ARCH_GET_CPUID = 0x1011 returns 1 (cpuid enabled) on a normal process
        assert_eq!(arch_prctl(0x1011, 0), 1);
        assert_eq!(arch_prctl(0x7777, 0), -1);
        assert_eq!(errno::get(), EINVAL);
    }

    #[test]
    fn pidfd_getpid_reads_fdinfo() {
        assert_eq!(pidfd_getpid(-1), -1);
        assert_eq!(errno::get(), EBADF);
        assert_eq!(pidfd_getpid(999), -1);
        assert_eq!(errno::get(), EBADF);
        let fd = unsafe { libc::syscall(434, libc::getpid(), 0) } as c_int;
        assert!(fd >= 0);
        assert_eq!(pidfd_getpid(fd), unsafe { libc::getpid() });
        unsafe { libc::close(fd) };
        let plain = unsafe { libc::open(c"/proc/self/stat".as_ptr(), 0) };
        assert_eq!(pidfd_getpid(plain), -1);
        assert_eq!(errno::get(), EBADF);
        unsafe { libc::close(plain) };
    }

    unsafe extern "C" fn child(arg: *mut c_void) -> c_int {
        arg as usize as c_int + 3
    }

    #[test]
    fn clone_runs_the_function_in_the_child() {
        unsafe {
            assert_eq!(clone(None, core::ptr::null_mut(), 17, core::ptr::null_mut(), core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>()), -1);
            assert_eq!(errno::get(), EINVAL);
            assert_eq!(clone(Some(child), core::ptr::null_mut(), 17, core::ptr::null_mut(), core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>()), -1);
            assert_eq!(errno::get(), EINVAL);
            let mut stack = vec![0u8; 65536];
            let top = stack.as_mut_ptr().add(stack.len()) as *mut c_void;
            // SIGCHLD exit signal, no CLONE_VM: the child gets a copy of the address space
            let pid = clone(Some(child), top, 17, 4 as *mut c_void, core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>(), core::ptr::null_mut::<c_void>());
            assert!(pid > 0);
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 7);
        }
    }
}
