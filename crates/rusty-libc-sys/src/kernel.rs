//! The crate's audited system-call entry points (BRIEF-UNSAFE.md U2).
//!
//! Three kinds of system call, three rules:
//! - Plain-value calls (`dup`, `fsync`, `setpgid`, `umask` ...): every argument is a number, the kernel reads and writes no
//!   memory of ours, and the call cannot unmap, protect or otherwise invalidate memory the program uses. They are made with
//!   the [`plain!`] and [`plain_cp!`] macros, which are safe: the call number must be on the list in [`is_plain`], checked
//!   at compile time (a `const` block), and that list is the one place to audit. These four functions hold the only unsafe
//!   blocks such calls need.
//! - The set*id calls with plain values go through [`setxid`] (the whole-process mechanism of core, glibc's
//!   `INLINE_SETXID_SYSCALL`), with the same kind of compile-time list.
//! - Calls that pass pointers stay raw at the place they are made: in an exported C function the pointers are the caller's,
//!   passed to the kernel untouched (the kernel checks each one and fails with EFAULT where it cannot read or write, so a
//!   NULL or bad pointer gives the error glibc gives). They are not turned into references first: a reference to memory that
//!   is not valid is undefined behaviour the moment it exists, even if never used (The Rustonomicon p.12), and passing the
//!   raw pointer keeps glibc's EFAULT results and the exact system calls. Calls on the library's own locals and slices are
//!   one unsafe block each with the reason next to it.
//!
//! Sources: The Rustonomicon p.248 (a safe wrapper takes slices and keeps the raw call inside) and p.12 (what counts as an
//! invalid reference); Translating C to Safer Rust (Emre et al., OOPSLA 2021) p.8 (a pointer handed to an external call can
//! only be made safe by replacing that call, so these stay raw); Comprehensive Rust p.324 (a SAFETY comment per block).

use core::ffi::{CStr, c_int};
use rusty_libc_core::syscall;

/// A system call number on the plain-value list ([`is_plain`]). Only [`Plain::of`] makes one, and only in a `const`
/// context through the macros, so a number not on the list does not compile.
#[derive(Clone, Copy)]
pub(crate) struct Plain(usize);

impl Plain {
    /// `n` as a plain-value call. Panics (a compile-time error inside `const { }`) when `n` is not on the list.
    pub(crate) const fn of(n: usize) -> Plain {
        assert!(is_plain(n), "not a plain-value system call");
        Plain(n)
    }
}

/// The x86-64 system calls whose arguments are only numbers and that cannot invalidate memory the program uses. Not here on
/// purpose: anything taking a pointer (read, stat, ioctl, fcntl, prctl ...), the memory calls (brk, mmap, munmap, mremap,
/// mprotect, madvise, mlock ranges, pkey_mprotect, process_mrelease), clone/fork/vfork, arch_prctl (moves the thread
/// pointer), reboot (a pointer argument for one command), ioperm and iopl (hardware access).
pub(crate) const fn is_plain(n: usize) -> bool {
    matches!(
        n,
        3       // close
        | 8     // lseek
        | 24    // sched_yield
        | 32    // dup
        | 33    // dup2
        | 34    // pause
        | 37    // alarm
        | 39    // getpid
        | 73    // flock
        | 74    // fsync
        | 75    // fdatasync
        | 77    // ftruncate
        | 81    // fchdir
        | 91    // fchmod
        | 93    // fchown
        | 95    // umask
        | 102   // getuid
        | 104   // getgid
        | 107   // geteuid
        | 108   // getegid
        | 109   // setpgid
        | 110   // getppid
        | 111   // getpgrp
        | 112   // setsid
        | 121   // getpgid
        | 122   // setfsuid
        | 123   // setfsgid
        | 124   // getsid
        | 135   // personality
        | 140   // getpriority
        | 141   // setpriority
        | 145   // sched_getscheduler
        | 146   // sched_get_priority_max
        | 147   // sched_get_priority_min
        | 151   // mlockall
        | 152   // munlockall
        | 153   // vhangup
        | 162   // sync
        | 186   // gettid
        | 187   // readahead
        | 213   // epoll_create
        | 221   // fadvise64
        | 231   // exit_group
        | 253   // inotify_init
        | 255   // inotify_rm_watch
        | 272   // unshare
        | 276   // tee
        | 277   // sync_file_range
        | 283   // timerfd_create
        | 285   // fallocate
        | 290   // eventfd2
        | 291   // epoll_create1
        | 292   // dup3
        | 294   // inotify_init1
        | 300   // fanotify_init
        | 306   // syncfs
        | 308   // setns
        | 330   // pkey_alloc
        | 331   // pkey_free
        | 432   // fsmount
        | 434   // pidfd_open
        | 436   // close_range
        | 438   // pidfd_getfd
    )
}

/// A plain-value system call with no arguments; the raw kernel result.
#[inline(always)]
pub(crate) fn call0(n: Plain) -> usize {
    // SAFETY: `n` is on the plain-value list (only `Plain::of` makes one): no memory is read or written, none invalidated.
    unsafe { syscall::syscall0(n.0) }
}

/// A plain-value system call with one argument.
#[inline(always)]
pub(crate) fn call1(n: Plain, a: usize) -> usize {
    // SAFETY: as in `call0`: the argument is a number the kernel does not dereference.
    unsafe { syscall::syscall1(n.0, a) }
}

/// A plain-value system call with two arguments.
#[inline(always)]
pub(crate) fn call2(n: Plain, a: usize, b: usize) -> usize {
    // SAFETY: as in `call0`.
    unsafe { syscall::syscall2(n.0, a, b) }
}

/// A plain-value system call with three arguments.
#[inline(always)]
pub(crate) fn call3(n: Plain, a: usize, b: usize, c: usize) -> usize {
    // SAFETY: as in `call0`.
    unsafe { syscall::syscall3(n.0, a, b, c) }
}

/// A plain-value system call with four arguments.
#[inline(always)]
pub(crate) fn call4(n: Plain, a: usize, b: usize, c: usize, d: usize) -> usize {
    // SAFETY: as in `call0`.
    unsafe { syscall::syscall4(n.0, a, b, c, d) }
}

/// A plain-value system call that is a cancellation point (core's `syscall_cp`: through rusty-libc-pthread's hook once a
/// thread may be cancelled).
#[inline(always)]
pub(crate) fn call_cp(n: Plain, a: usize, b: usize, c: usize, d: usize) -> usize {
    // SAFETY: as in `call0`; the hook makes the same system call.
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, a, b, c, d, 0, 0) }
}

/// A set*id call number with plain arguments (setuid, setgid, setreuid, setregid, setresuid, setresgid; not setgroups,
/// whose second argument is a pointer).
#[derive(Clone, Copy)]
pub(crate) struct SetId(usize);

impl SetId {
    /// `n` as a plain set*id call; a compile-time error inside `const { }` for any other number.
    pub(crate) const fn of(n: usize) -> SetId {
        assert!(matches!(n, 105 | 106 | 113 | 114 | 117 | 119), "not a plain set*id system call");
        SetId(n)
    }
}

/// A plain set*id system call for every thread of the process (core's `setxid_syscall`); the raw kernel result.
#[inline]
pub(crate) fn setxid(n: SetId, a: usize, b: usize, c: usize) -> usize {
    // SAFETY: the numbers `SetId` admits take only ids (numbers); the per-thread hook makes the same call on each thread.
    unsafe { rusty_libc_core::unistd::setxid_syscall(n.0, a, b, c) }
}

/// A plain-value system call (safe): `plain!(nr::FSYNC, fd as usize)`. The number must be on [`is_plain`]'s list, checked
/// at compile time. Arguments are `usize`, cast at the call site exactly as the raw call took them.
macro_rules! plain {
    ($n:expr) => {
        $crate::kernel::call0(const { $crate::kernel::Plain::of($n) })
    };
    ($n:expr, $a:expr) => {
        $crate::kernel::call1(const { $crate::kernel::Plain::of($n) }, $a)
    };
    ($n:expr, $a:expr, $b:expr) => {
        $crate::kernel::call2(const { $crate::kernel::Plain::of($n) }, $a, $b)
    };
    ($n:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::call3(const { $crate::kernel::Plain::of($n) }, $a, $b, $c)
    };
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $crate::kernel::call4(const { $crate::kernel::Plain::of($n) }, $a, $b, $c, $d)
    };
}
pub(crate) use plain;

/// [`plain!`] for a call that is a cancellation point (made through core's `syscall_cp`, unused arguments 0).
macro_rules! plain_cp {
    ($n:expr) => {
        $crate::kernel::call_cp(const { $crate::kernel::Plain::of($n) }, 0, 0, 0, 0)
    };
    ($n:expr, $a:expr) => {
        $crate::kernel::call_cp(const { $crate::kernel::Plain::of($n) }, $a, 0, 0, 0)
    };
    ($n:expr, $a:expr, $b:expr) => {
        $crate::kernel::call_cp(const { $crate::kernel::Plain::of($n) }, $a, $b, 0, 0)
    };
    ($n:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::call_cp(const { $crate::kernel::Plain::of($n) }, $a, $b, $c, 0)
    };
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $crate::kernel::call_cp(const { $crate::kernel::Plain::of($n) }, $a, $b, $c, $d)
    };
}
pub(crate) use plain_cp;

/// [`setxid`] with the number checked at compile time: `setid!(nr::SETUID, uid as usize, 0, 0)`.
macro_rules! setid {
    ($n:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::setxid(const { $crate::kernel::SetId::of($n) }, $a, $b, $c)
    };
}
pub(crate) use setid;

/// `openat(AT_FDCWD, path, flags, mode)`, not a cancellation point (glibc's `__open_nocancel`); the raw kernel result.
#[inline]
pub(crate) fn open_nocancel(path: &CStr, flags: usize, mode: usize) -> usize {
    // SAFETY: `path` is a NUL-terminated string that outlives the call; the kernel only reads it.
    unsafe { syscall::sys_open(path.as_ptr() as usize, flags, mode) }
}

/// `openat(dirfd, path, flags, mode)` as a cancellation point (glibc's `open`/`openat`); the raw kernel result.
#[inline]
pub(crate) fn openat_cp(dirfd: usize, path: &CStr, flags: usize, mode: usize) -> usize {
    // SAFETY: as in `open_nocancel`.
    unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_OPENAT, dirfd, path.as_ptr() as usize, flags, mode, 0, 0) }
}

/// read(2) into `buf`, not a cancellation point; the raw kernel result.
#[inline]
pub(crate) fn read_nocancel(fd: usize, buf: &mut [u8]) -> usize {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { syscall::syscall3(syscall::SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len()) }
}

/// write(2) from `buf`, not a cancellation point; the raw kernel result.
#[inline]
pub(crate) fn write_nocancel(fd: usize, buf: &[u8]) -> usize {
    // SAFETY: the kernel reads `buf.len()` bytes of `buf`.
    unsafe { syscall::syscall3(syscall::SYS_WRITE, fd, buf.as_ptr() as usize, buf.len()) }
}

/// The kernel's `struct stat` (144 bytes) as 18 words, for code that needs only a few fields.
pub(crate) type KStat = [u64; 18];

/// A buffer for the kernel's 144-byte `struct stat`: 144 bytes for which every bit pattern is a valid value. Private to
/// this module (only the two impls below), so the system calls that write through it stay sound.
pub(crate) trait StatBuf: private::Sealed {
    fn stat_addr(&mut self) -> usize;
}
mod private {
    pub trait Sealed {}
    impl Sealed for super::KStat {}
    impl Sealed for crate::stat::Stat {}
}
impl StatBuf for KStat {
    fn stat_addr(&mut self) -> usize {
        self.as_mut_ptr() as usize
    }
}
impl StatBuf for crate::stat::Stat {
    fn stat_addr(&mut self) -> usize {
        self as *mut crate::stat::Stat as usize
    }
}
const _: () = assert!(size_of::<KStat>() == 144 && size_of::<crate::stat::Stat>() == 144);

/// newfstatat(dirfd, path, st, flags) into `st`; the raw kernel result.
#[inline]
pub(crate) fn fstatat<S: StatBuf>(dirfd: usize, path: &CStr, st: &mut S, flags: usize) -> usize {
    // SAFETY: `path` is NUL-terminated and only read; the kernel writes one 144-byte `struct stat` into `st` (StatBuf).
    unsafe { syscall::syscall4(syscall::SYS_NEWFSTATAT, dirfd, path.as_ptr() as usize, st.stat_addr(), flags) }
}

/// fstat(2) (the fstat system call, as glibc's fstat makes it) into `st`; the raw kernel result.
#[inline]
pub(crate) fn fstat(fd: usize, st: &mut crate::stat::Stat) -> usize {
    // SAFETY: `Stat` is the kernel's 144-byte `struct stat`; the kernel writes one into `st`.
    unsafe { syscall::syscall2(syscall::SYS_FSTAT, fd, st as *mut crate::stat::Stat as usize) }
}

/// getdents64(2) into `buf` (8-byte aligned words); the raw kernel result (bytes stored).
#[inline]
pub(crate) fn getdents64(fd: usize, buf: &mut [u64]) -> usize {
    // SAFETY: the kernel writes at most `buf.len() * 8` bytes into `buf`.
    unsafe { syscall::syscall3(217, fd, buf.as_mut_ptr() as usize, buf.len() * 8) }
}

/// An ioctl whose argument is a pointer to one `int` the kernel writes (TIOCGPGRP, TIOCGSID ...): the raw result and the
/// value.
#[inline]
pub(crate) fn ioctl_get_int(fd: usize, request: usize) -> (usize, c_int) {
    let mut v: c_int = 0;
    // SAFETY: the requests used with this write one `int` through the pointer, here the local `v`.
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, request, &mut v as *mut c_int as usize) };
    (r, v)
}

/// An ioctl whose argument is a pointer to one `int` the kernel reads (TIOCSPGRP ...); the raw result.
#[inline]
pub(crate) fn ioctl_set_int(fd: usize, request: usize, v: &c_int) -> usize {
    // SAFETY: the requests used with this read one `int` through the pointer.
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, request, v as *const c_int as usize) }
}

/// The TCGETS2 ioctl (glibc 2.43's isatty and tcgetattr) into a scratch buffer; the raw result.
#[inline]
pub(crate) fn tcgets2(fd: usize) -> usize {
    let mut termios = [0u8; 64];
    // SAFETY: TCGETS2 writes a 44-byte `struct termios2`; the local buffer has 64 bytes.
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, rusty_libc_core::unistd::TCGETS2, termios.as_mut_ptr() as usize) }
}

/// malloc(3) of the library's own allocator. Safe to call: it has no precondition and returns a raw pointer (NULL on
/// failure); using the block is what needs care.
#[inline(always)]
pub(crate) fn malloc(n: usize) -> *mut core::ffi::c_void {
    // SAFETY: malloc has no precondition.
    unsafe { rusty_libc_malloc::malloc(n) }
}

/// A zero-filled malloc'd byte buffer, freed when dropped (the library's own scratch memory: getcwd's long-path walk).
pub(crate) struct MallocBuf {
    p: core::ptr::NonNull<u8>,
    len: usize,
}

impl MallocBuf {
    /// `len` zero bytes from malloc, or None when malloc fails.
    pub(crate) fn zeroed(len: usize) -> Option<MallocBuf> {
        let p = core::ptr::NonNull::new(malloc(len).cast::<u8>())?;
        // SAFETY: a fresh block of `len` writable bytes.
        unsafe { core::ptr::write_bytes(p.as_ptr(), 0, len) };
        Some(MallocBuf { p, len })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: the block holds `len` initialised bytes (zeroed at allocation) owned by `self`.
        unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`; `&mut self` makes the borrow exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.len) }
    }
}

impl Drop for MallocBuf {
    fn drop(&mut self) {
        // SAFETY: the block came from malloc in `zeroed` and is freed once, here.
        unsafe { rusty_libc_malloc::free(self.p.as_ptr().cast()) };
    }
}

/// A system call whose only pointer arguments are NUL-terminated path strings the kernel reads (never writes), in the
/// positions the `path*` helpers below pass them; every other argument is a number. Only `PathCall::of` in a `const`
/// block makes one: a number not on the list for that shape does not compile.
#[derive(Clone, Copy)]
pub(crate) struct PathCall(usize);

/// Where the path arguments of a [`PathCall`] go.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathShape {
    /// `nr(path, a, b, c)`: access, truncate, chdir, mkdir, rmdir, creat, unlink, chmod, chown, lchown, chroot.
    First,
    /// `nr(dirfd, path, a, b)`: openat, mkdirat, mknodat.
    Second,
    /// `nr(path1, path2)`: link, symlink.
    Two,
}

impl PathCall {
    /// `n` with its path arguments in `shape`'s positions; a compile-time error inside `const { }` otherwise.
    pub(crate) const fn of(n: usize, shape: PathShape) -> PathCall {
        let ok = match shape {
            PathShape::First => matches!(n, 21 | 76 | 80 | 83 | 84 | 85 | 87 | 90 | 92 | 94 | 161),
            PathShape::Second => matches!(n, 257..=259), // openat, mkdirat, mknodat
            PathShape::Two => matches!(n, 86 | 88),
        };
        assert!(ok, "not a path-only system call of this shape");
        PathCall(n)
    }
}

/// `nr(path, a, b, c)` for a [`PathShape::First`] call; the raw kernel result.
#[inline(always)]
pub(crate) fn path_call(n: PathCall, path: &CStr, a: usize, b: usize, c: usize) -> usize {
    // SAFETY: `n` takes `path` as its only pointer (PathCall's list), a NUL-terminated string the kernel only reads.
    unsafe { syscall::syscall4(n.0, path.as_ptr() as usize, a, b, c) }
}

/// [`path_call`] as a cancellation point (creat).
#[inline(always)]
pub(crate) fn path_call_cp(n: PathCall, path: &CStr, a: usize, b: usize, c: usize) -> usize {
    // SAFETY: as in `path_call`.
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, path.as_ptr() as usize, a, b, c, 0, 0) }
}

/// `nr(dirfd, path, a, b)` for a [`PathShape::Second`] call; the raw kernel result.
#[inline(always)]
pub(crate) fn dir_path_call(n: PathCall, dirfd: usize, path: &CStr, a: usize, b: usize) -> usize {
    // SAFETY: as in `path_call`, the path in the second position.
    unsafe { syscall::syscall4(n.0, dirfd, path.as_ptr() as usize, a, b) }
}

/// [`dir_path_call`] as a cancellation point (openat).
#[inline(always)]
pub(crate) fn dir_path_call_cp(n: PathCall, dirfd: usize, path: &CStr, a: usize, b: usize) -> usize {
    // SAFETY: as in `dir_path_call`.
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, dirfd, path.as_ptr() as usize, a, b, 0, 0) }
}

/// `nr(p1, p2)` for a [`PathShape::Two`] call; the raw kernel result.
#[inline(always)]
pub(crate) fn path_path_call(n: PathCall, p1: &CStr, p2: &CStr) -> usize {
    // SAFETY: as in `path_call`, with two paths.
    unsafe { syscall::syscall2(n.0, p1.as_ptr() as usize, p2.as_ptr() as usize) }
}

/// A path-only system call (safe): `on_path!(First nr::CHDIR, path, 0, 0, 0)`, `on_path!(Second nr::MKDIRAT, dirfd, path, mode,
/// 0)`, `on_path!(Two nr::LINK, old, new)`; unused value arguments are 0 (the kernel ignores them). `on_path_cp!` for the
/// cancellation points.
macro_rules! on_path {
    (First $n:expr, $p:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::path_call(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::First) }, $p, $a, $b, $c)
    };
    (Second $n:expr, $d:expr, $p:expr, $a:expr, $b:expr) => {
        $crate::kernel::dir_path_call(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::Second) }, $d, $p, $a, $b)
    };
    (Two $n:expr, $p:expr, $q:expr) => {
        $crate::kernel::path_path_call(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::Two) }, $p, $q)
    };
}
pub(crate) use on_path;

/// [`on_path!`] for the cancellation points.
macro_rules! on_path_cp {
    (First $n:expr, $p:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::path_call_cp(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::First) }, $p, $a, $b, $c)
    };
    (Second $n:expr, $d:expr, $p:expr, $a:expr, $b:expr) => {
        $crate::kernel::dir_path_call_cp(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::Second) }, $d, $p, $a, $b)
    };
}
pub(crate) use on_path_cp;

/// A `[u64; N]` buffer seen as bytes (getdents64 and stat buffers are kept as u64 arrays for their 8-byte alignment).
pub(crate) fn u64_bytes<const N: usize>(b: &[u64; N]) -> &[u8] {
    // SAFETY: u8 has no alignment or validity requirement; the length is the array's size in bytes; the borrow is shared.
    unsafe { core::slice::from_raw_parts(b.as_ptr().cast::<u8>(), N * 8) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_calls() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pid = plain!(39);
        assert_eq!(pid as i32, rusty_libc_core::unistd::getpid());
        let old = plain!(95, 0o022);
        assert_eq!(plain!(95, old), 0o022);
        // dup of a closed descriptor: the raw -EBADF
        assert_eq!(plain!(32, -1i32 as usize) as isize, -9);
        assert_eq!(plain_cp!(74, -1i32 as usize) as isize, -9);
    }

    #[test]
    fn u64_bytes_view() {
        let words = [0x0102030405060708u64, 0];
        assert_eq!(u64_bytes(&words).len(), 16);
        assert_eq!(u64_bytes(&words)[0], 8);
    }
}
