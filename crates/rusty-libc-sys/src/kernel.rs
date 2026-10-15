use core::ffi::{CStr, c_int};
use rusty_libc_core::syscall;

#[derive(Clone, Copy)]
pub(crate) struct Plain(usize);

impl Plain {
    pub(crate) const fn of(n: usize) -> Plain {
        assert!(is_plain(n), "not a plain-value system call");
        Plain(n)
    }
}

pub(crate) const fn is_plain(n: usize) -> bool {
    matches!(
        n,
        3
        | 8
        | 24
        | 32
        | 33
        | 34
        | 37
        | 39
        | 73
        | 74
        | 75
        | 77
        | 81
        | 91
        | 93
        | 95
        | 102
        | 104
        | 107
        | 108
        | 109
        | 110
        | 111
        | 112
        | 121
        | 122
        | 123
        | 124
        | 135
        | 140
        | 141
        | 145
        | 146
        | 147
        | 151
        | 152
        | 153
        | 162
        | 186
        | 187
        | 213
        | 221
        | 231
        | 253
        | 255
        | 272
        | 276
        | 277
        | 283
        | 285
        | 290
        | 291
        | 292
        | 294
        | 300
        | 306
        | 308
        | 330
        | 331
        | 432
        | 434
        | 436
        | 438
    )
}

#[inline(always)]
pub(crate) fn call0(n: Plain) -> usize {
    unsafe { syscall::syscall0(n.0) }
}

#[inline(always)]
pub(crate) fn call1(n: Plain, a: usize) -> usize {
    unsafe { syscall::syscall1(n.0, a) }
}

#[inline(always)]
pub(crate) fn call2(n: Plain, a: usize, b: usize) -> usize {
    unsafe { syscall::syscall2(n.0, a, b) }
}

#[inline(always)]
pub(crate) fn call3(n: Plain, a: usize, b: usize, c: usize) -> usize {
    unsafe { syscall::syscall3(n.0, a, b, c) }
}

#[inline(always)]
pub(crate) fn call4(n: Plain, a: usize, b: usize, c: usize, d: usize) -> usize {
    unsafe { syscall::syscall4(n.0, a, b, c, d) }
}

#[inline(always)]
pub(crate) fn call_cp(n: Plain, a: usize, b: usize, c: usize, d: usize) -> usize {
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, a, b, c, d, 0, 0) }
}

#[derive(Clone, Copy)]
pub(crate) struct SetId(usize);

impl SetId {
    pub(crate) const fn of(n: usize) -> SetId {
        assert!(matches!(n, 105 | 106 | 113 | 114 | 117 | 119), "not a plain set*id system call");
        SetId(n)
    }
}

#[inline]
pub(crate) fn setxid(n: SetId, a: usize, b: usize, c: usize) -> usize {
    unsafe { rusty_libc_core::unistd::setxid_syscall(n.0, a, b, c) }
}

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

macro_rules! setid {
    ($n:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::setxid(const { $crate::kernel::SetId::of($n) }, $a, $b, $c)
    };
}
pub(crate) use setid;

#[inline]
pub(crate) fn open_nocancel(path: &CStr, flags: usize, mode: usize) -> usize {
    unsafe { syscall::sys_open(path.as_ptr() as usize, flags, mode) }
}

#[inline]
pub(crate) fn openat_cp(dirfd: usize, path: &CStr, flags: usize, mode: usize) -> usize {
    unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_OPENAT, dirfd, path.as_ptr() as usize, flags, mode, 0, 0) }
}

#[inline]
pub(crate) fn read_nocancel(fd: usize, buf: &mut [u8]) -> usize {
    unsafe { syscall::syscall3(syscall::SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len()) }
}

#[inline]
pub(crate) fn write_nocancel(fd: usize, buf: &[u8]) -> usize {
    unsafe { syscall::syscall3(syscall::SYS_WRITE, fd, buf.as_ptr() as usize, buf.len()) }
}

pub(crate) type KStat = [u64; 18];

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

#[inline]
pub(crate) fn fstatat<S: StatBuf>(dirfd: usize, path: &CStr, st: &mut S, flags: usize) -> usize {
    unsafe { syscall::syscall4(syscall::SYS_NEWFSTATAT, dirfd, path.as_ptr() as usize, st.stat_addr(), flags) }
}

#[inline]
pub(crate) fn fstat(fd: usize, st: &mut crate::stat::Stat) -> usize {
    unsafe { syscall::syscall2(syscall::SYS_FSTAT, fd, st as *mut crate::stat::Stat as usize) }
}

#[inline]
pub(crate) fn getdents64(fd: usize, buf: &mut [u64]) -> usize {
    unsafe { syscall::syscall3(217, fd, buf.as_mut_ptr() as usize, buf.len() * 8) }
}

#[inline]
pub(crate) fn ioctl_get_int(fd: usize, request: usize) -> (usize, c_int) {
    let mut v: c_int = 0;
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, request, &mut v as *mut c_int as usize) };
    (r, v)
}

#[inline]
pub(crate) fn ioctl_set_int(fd: usize, request: usize, v: &c_int) -> usize {
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, request, v as *const c_int as usize) }
}

#[inline]
pub(crate) fn tcgets2(fd: usize) -> usize {
    let mut termios = [0u8; 64];
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd, rusty_libc_core::unistd::TCGETS2, termios.as_mut_ptr() as usize) }
}

#[inline(always)]
pub(crate) fn malloc(n: usize) -> *mut core::ffi::c_void {
    unsafe { rusty_libc_malloc::malloc(n) }
}

pub(crate) struct MallocBuf {
    p: core::ptr::NonNull<u8>,
    len: usize,
}

impl MallocBuf {
    pub(crate) fn zeroed(len: usize) -> Option<MallocBuf> {
        let p = core::ptr::NonNull::new(malloc(len).cast::<u8>())?;
        unsafe { core::ptr::write_bytes(p.as_ptr(), 0, len) };
        Some(MallocBuf { p, len })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.len) }
    }
}

impl Drop for MallocBuf {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.as_ptr().cast()) };
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PathCall(usize);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathShape {
    First,
    Second,
    Two,
}

impl PathCall {
    pub(crate) const fn of(n: usize, shape: PathShape) -> PathCall {
        let ok = match shape {
            PathShape::First => matches!(n, 21 | 76 | 80 | 83 | 84 | 85 | 87 | 90 | 92 | 94 | 161),
            PathShape::Second => matches!(n, 257..=259),
            PathShape::Two => matches!(n, 86 | 88),
        };
        assert!(ok, "not a path-only system call of this shape");
        PathCall(n)
    }
}

#[inline(always)]
pub(crate) fn path_call(n: PathCall, path: &CStr, a: usize, b: usize, c: usize) -> usize {
    unsafe { syscall::syscall4(n.0, path.as_ptr() as usize, a, b, c) }
}

#[inline(always)]
pub(crate) fn path_call_cp(n: PathCall, path: &CStr, a: usize, b: usize, c: usize) -> usize {
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, path.as_ptr() as usize, a, b, c, 0, 0) }
}

#[inline(always)]
pub(crate) fn dir_path_call(n: PathCall, dirfd: usize, path: &CStr, a: usize, b: usize) -> usize {
    unsafe { syscall::syscall4(n.0, dirfd, path.as_ptr() as usize, a, b) }
}

#[inline(always)]
pub(crate) fn dir_path_call_cp(n: PathCall, dirfd: usize, path: &CStr, a: usize, b: usize) -> usize {
    unsafe { rusty_libc_core::tls::syscall_cp(n.0, dirfd, path.as_ptr() as usize, a, b, 0, 0) }
}

#[inline(always)]
pub(crate) fn path_path_call(n: PathCall, p1: &CStr, p2: &CStr) -> usize {
    unsafe { syscall::syscall2(n.0, p1.as_ptr() as usize, p2.as_ptr() as usize) }
}

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

macro_rules! on_path_cp {
    (First $n:expr, $p:expr, $a:expr, $b:expr, $c:expr) => {
        $crate::kernel::path_call_cp(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::First) }, $p, $a, $b, $c)
    };
    (Second $n:expr, $d:expr, $p:expr, $a:expr, $b:expr) => {
        $crate::kernel::dir_path_call_cp(const { $crate::kernel::PathCall::of($n, $crate::kernel::PathShape::Second) }, $d, $p, $a, $b)
    };
}
pub(crate) use on_path_cp;

pub(crate) fn u64_bytes<const N: usize>(b: &[u64; N]) -> &[u8] {
    unsafe { core::slice::from_raw_parts(b.as_ptr().cast::<u8>(), N * 8) }
}

