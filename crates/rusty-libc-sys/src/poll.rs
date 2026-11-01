//! sys/poll.h, sys/select.h, sys/epoll.h, sys/eventfd.h, sys/signalfd.h, sys/timerfd.h,
//! sys/inotify.h and sys/fanotify.h.
//!
//! Signal masks cross the C ABI as `*const sigset_t` (glibc's 128-byte type); only the first 8
//! bytes (the kernel's set) are read, and the kernel is told the size is 8, as glibc does.
use crate::misc::{sc, sci};
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{check, syscall2, syscall3, syscall4, syscall5};
use rusty_libc_core::{Errno, errno};
use crate::kernel::plain;

const SYS_POLL: usize = 7;
const SYS_SELECT_PSELECT6: usize = 270;
const SYS_PPOLL: usize = 271;
const SYS_EPOLL_CREATE: usize = 213;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_PWAIT: usize = 281;
const SYS_EPOLL_PWAIT2: usize = 441;
const SYS_EPOLL_CREATE1: usize = 291;
const SYS_EVENTFD2: usize = 290;
const SYS_SIGNALFD4: usize = 289;
const SYS_TIMERFD_CREATE: usize = 283;
const SYS_TIMERFD_SETTIME: usize = 286;
const SYS_TIMERFD_GETTIME: usize = 287;
const SYS_INOTIFY_INIT: usize = 253;
const SYS_INOTIFY_ADD_WATCH: usize = 254;
const SYS_INOTIFY_RM_WATCH: usize = 255;
const SYS_INOTIFY_INIT1: usize = 294;
const SYS_FANOTIFY_INIT: usize = 300;
const SYS_FANOTIFY_MARK: usize = 301;
const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;

const EINVAL: i32 = 22;
const KERNEL_SIGSET: usize = 8;
const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_SEC: i64 = 1_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct itimerspec {
    pub it_interval: timespec,
    pub it_value: timespec,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

/// `fd_set`: 1024 bits.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct fd_set {
    pub fds_bits: [c_long; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union epoll_data {
    pub ptr: *mut c_void,
    pub fd: c_int,
    pub u32_: u32,
    pub u64_: u64,
}

/// Packed on x86_64 (12 bytes), like the kernel's.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct epoll_event {
    pub events: u32,
    pub data: epoll_data,
}

// ---------------------------------------------------------------- Rust API

/// poll(2); the result is the number of ready descriptors.
pub fn poll_r(fds: &mut [pollfd], timeout_ms: i32) -> Result<usize, Errno> {
    // SAFETY: the kernel reads and writes the `fds.len()` entries of `fds` (revents).
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_POLL, fds.as_mut_ptr() as usize, fds.len(), timeout_ms as isize as usize, 0, 0, 0)) }
}

/// eventfd2(2).
pub fn eventfd_r(initval: u32, flags: i32) -> Result<i32, Errno> {
    check(plain!(SYS_EVENTFD2, initval as usize, flags as usize)).map(|v| v as i32)
}

/// epoll_create1(2).
pub fn epoll_create1_r(flags: i32) -> Result<i32, Errno> {
    check(plain!(SYS_EPOLL_CREATE1, flags as usize)).map(|v| v as i32)
}

/// epoll_ctl(2).
pub fn epoll_ctl_r(epfd: i32, op: i32, fd: i32, ev: Option<&mut epoll_event>) -> Result<(), Errno> {
    let p = ev.map_or(0, |e| e as *mut epoll_event as usize);
    // SAFETY: `p` is NULL or a live `epoll_event` the kernel reads.
    unsafe { check(syscall4(SYS_EPOLL_CTL, epfd as usize, op as usize, fd as usize, p)).map(|_| ()) }
}

/// epoll_wait(2); the result is the number of events stored.
pub fn epoll_wait_r(epfd: i32, events: &mut [epoll_event], timeout_ms: i32) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `events.len()` events (every bit pattern is a valid `epoll_event`).
    unsafe {
        check(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, events.len(), timeout_ms as isize as usize, 0, 0))
    }
}

// ---------------------------------------------------------------- poll, select

/// # Safety
/// `fds` points to `nfds` entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn poll(fds: *mut pollfd, nfds: c_ulong, timeout: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_POLL, fds as usize, nfds as usize, timeout as isize as usize, 0, 0, 0)) }
}

/// The timeout is copied first so the kernel's remaining-time update does not reach the caller.
///
/// # Safety
/// As ppoll(2); `sigmask` is NULL or a sigset_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ppoll(fds: *mut pollfd, nfds: c_ulong, timeout: *const timespec, sigmask: *const c_void) -> c_int {
    let mut tv = if timeout.is_null() {
        timespec::default()
    } else {
        // SAFETY: `timeout` is not NULL, so it points to a readable timespec (contract).
        unsafe { timeout.read() }
    };
    let tp = if timeout.is_null() { 0 } else { &mut tv as *mut timespec as usize };
    // SAFETY: `fds` and `sigmask` are the caller's, passed to the kernel untouched (it checks them: EFAULT); `tp` is NULL or
    // the local copy of the timeout.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_PPOLL, fds as usize, nfds as usize, tp, sigmask as usize, KERNEL_SIGSET, 0) })
}

/// select(2) as glibc does it: through pselect6 with the timeout normalized; the remaining time
/// is written back to `timeout` (the Linux behaviour).
///
/// # Safety
/// As select(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn select(nfds: c_int, r: *mut fd_set, w: *mut fd_set, e: *mut fd_set, timeout: *mut timeval) -> c_int {
    let tv = if timeout.is_null() {
        timeval::default()
    } else {
        // SAFETY: `timeout` is not NULL, so it points to a readable timeval (contract).
        unsafe { timeout.read() }
    };
    let mut s: i64 = tv.tv_sec;
    let mut us: i32 = tv.tv_usec as i32;
    if s < 0 || us < 0 {
        errno::set(EINVAL);
        return -1;
    }
    let ns: i64;
    if (us as i64) / USEC_PER_SEC > i64::MAX - s {
        s = i64::MAX;
        ns = NSEC_PER_SEC - 1;
    } else {
        s += (us as i64) / USEC_PER_SEC;
        us %= USEC_PER_SEC as i32;
        ns = us as i64 * 1000;
    }
    let mut ts = timespec { tv_sec: s, tv_nsec: ns };
    let tp = if timeout.is_null() { 0 } else { &mut ts as *mut timespec as usize };
    // SAFETY: the fd_set pointers are the caller's (NULL or valid), passed to the kernel untouched (it checks them:
    // EFAULT); `tp` is NULL or the local timespec.
    let ret = sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SELECT_PSELECT6, nfds as usize, r as usize, w as usize, e as usize, tp, 0) });
    if !timeout.is_null() {
        // SAFETY: `timeout` is not NULL, so it is writable (contract): the remaining time goes back, as on Linux.
        unsafe { timeout.write(timeval { tv_sec: ts.tv_sec, tv_usec: ts.tv_nsec / 1000 }) };
    }
    ret
}

/// # Safety
/// As pselect(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    let mut tv = if timeout.is_null() {
        timespec::default()
    } else {
        // SAFETY: `timeout` is not NULL, so it points to a readable timespec (contract).
        unsafe { timeout.read() }
    };
    let tp = if timeout.is_null() { 0 } else { &mut tv as *mut timespec as usize };
    let data: [usize; 2] = [sigmask as usize, KERNEL_SIGSET];
    // SAFETY: the fd_set and sigmask pointers are the caller's, passed to the kernel untouched (it checks them: EFAULT);
    // `tp` is NULL or the local timespec and `data` the local {sigmask, size} pair pselect6 reads.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SELECT_PSELECT6, nfds as usize, r as usize, w as usize, e as usize, tp, data.as_ptr() as usize) })
}

// ---------------------------------------------------------------- epoll

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn epoll_create(size: c_int) -> c_int {
    if size <= 0 {
        errno::set(EINVAL);
        return -1;
    }
    sci(plain!(SYS_EPOLL_CREATE, size as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn epoll_create1(flags: c_int) -> c_int {
    sci(plain!(SYS_EPOLL_CREATE1, flags as usize))
}

/// # Safety
/// `ev` is NULL (for EPOLL_CTL_DEL) or an event.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut epoll_event) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_EPOLL_CTL, epfd as usize, op as usize, fd as usize, ev as usize)) }
}

/// # Safety
/// `events` has room for `maxevents`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_wait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_WAIT, epfd as usize, events as usize, maxevents as usize, timeout as isize as usize, 0, 0)) }
}

/// # Safety
/// As [`epoll_wait`]; `sigmask` is NULL or a sigset_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe {
        sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_PWAIT, epfd as usize, events as usize, maxevents as usize, timeout as isize as usize, sigmask as usize, KERNEL_SIGSET))
    }
}

/// # Safety
/// As [`epoll_pwait`]; `timeout` is NULL or a timespec.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait2(
    epfd: c_int,
    events: *mut epoll_event,
    maxevents: c_int,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe {
        sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_PWAIT2, epfd as usize, events as usize, maxevents as usize, timeout as usize, sigmask as usize, KERNEL_SIGSET))
    }
}

// ---------------------------------------------------------------- eventfd, signalfd, timerfd

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn eventfd(count: c_uint, flags: c_int) -> c_int {
    sci(plain!(SYS_EVENTFD2, count as usize, flags as usize))
}

/// Reads the 8-byte counter. Returns 0, or -1 if fewer than 8 bytes came back (errno as the read left it).
///
/// # Safety
/// `value` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut u64) -> c_int {
    // SAFETY: `value` (writable, contract) goes to the kernel untouched; it writes at most 8 bytes and checks it (EFAULT).
    if sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_READ, fd as usize, value as usize, 8, 0, 0, 0) }) == 8 { 0 } else { -1 }
}

/// Adds to the counter; 0, or -1 if the write was not 8 bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn eventfd_write(fd: c_int, value: u64) -> c_int {
    // SAFETY: the kernel reads the 8 bytes of the local `value`.
    if sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_WRITE, fd as usize, &value as *const u64 as usize, 8, 0, 0, 0) }) == 8 { 0 } else { -1 }
}

/// # Safety
/// `mask` is a sigset_t.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn signalfd(fd: c_int, mask: *const c_void, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_SIGNALFD4, fd as isize as usize, mask as usize, KERNEL_SIGSET, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn timerfd_create(clock: c_int, flags: c_int) -> c_int {
    sci(plain!(SYS_TIMERFD_CREATE, clock as usize, flags as usize))
}

/// # Safety
/// `new` is an itimerspec; `old` is NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_settime(fd: c_int, flags: c_int, new: *const itimerspec, old: *mut itimerspec) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_TIMERFD_SETTIME, fd as usize, flags as usize, new as usize, old as usize)) }
}

/// # Safety
/// `cur` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_gettime(fd: c_int, cur: *mut itimerspec) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_TIMERFD_GETTIME, fd as usize, cur as usize)) }
}

// ---------------------------------------------------------------- inotify, fanotify

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_init() -> c_int {
    sci(plain!(SYS_INOTIFY_INIT))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_init1(flags: c_int) -> c_int {
    sci(plain!(SYS_INOTIFY_INIT1, flags as usize))
}

/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_INOTIFY_ADD_WATCH, fd as usize, path as usize, mask as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    sci(plain!(SYS_INOTIFY_RM_WATCH, fd as usize, wd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fanotify_init(flags: c_uint, event_f_flags: c_uint) -> c_int {
    sci(plain!(SYS_FANOTIFY_INIT, flags as usize, event_f_flags as usize))
}

/// # Safety
/// `path` is NULL or a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_mark(fd: c_int, flags: c_uint, mask: u64, dirfd: c_int, path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_FANOTIFY_MARK, fd as usize, flags as usize, mask as usize, dirfd as isize as usize, path as usize)) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;

    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    const POLLHUP: i16 = 0x10;
    const POLLNVAL: i16 = 0x20;
    const EPOLLIN: u32 = 1;
    const EPOLL_CTL_ADD: c_int = 1;
    const EPOLL_CTL_DEL: c_int = 2;
    const EFD_NONBLOCK: c_int = 0o4000;
    const EFD_CLOEXEC: c_int = 0o2000000;

    fn pipe() -> (c_int, c_int) {
        let mut fds = [0 as c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    fn close(fds: &[c_int]) {
        for &f in fds {
            unsafe { libc::close(f) };
        }
    }

    fn ts(sec: i64, nsec: i64) -> timespec {
        timespec { tv_sec: sec, tv_nsec: nsec }
    }

    #[test]
    fn struct_layouts() {
        assert_eq!(core::mem::size_of::<pollfd>(), 8);
        assert_eq!(core::mem::size_of::<timespec>(), 16);
        assert_eq!(core::mem::size_of::<timeval>(), 16);
        assert_eq!(core::mem::size_of::<itimerspec>(), 32);
        assert_eq!(core::mem::size_of::<fd_set>(), 128);
        assert_eq!(core::mem::size_of::<epoll_event>(), 12);
        assert_eq!(core::mem::size_of::<epoll_event>(), core::mem::size_of::<libc::epoll_event>());
    }

    #[test]
    fn poll_and_ppoll_on_a_pipe() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (r, w) = pipe();
        unsafe {
            let mut fds = [pollfd { fd: r, events: POLLIN, revents: 0 }, pollfd { fd: w, events: POLLOUT, revents: 0 }];
            assert_eq!(poll(fds.as_mut_ptr(), 2, 0), 1);
            assert_eq!((fds[0].revents, fds[1].revents), (0, POLLOUT));
            libc::write(w, b"hi".as_ptr().cast(), 2);
            let mut hf = fds;
            assert_eq!(poll(fds.as_mut_ptr(), 2, 100), 2);
            assert_eq!(libc::poll(hf.as_mut_ptr().cast(), 2, 100), 2);
            assert_eq!(fds[0].revents, POLLIN);
            assert_eq!((fds[0].revents, fds[1].revents), (hf[0].revents, hf[1].revents));
            // timeout: nothing readable on an empty pipe
            let (r2, w2) = pipe();
            let mut f2 = [pollfd { fd: r2, events: POLLIN, revents: 0 }];
            let t0 = std::time::Instant::now();
            assert_eq!(poll(f2.as_mut_ptr(), 1, 30), 0);
            assert!(t0.elapsed() >= std::time::Duration::from_millis(25));
            // ppoll: the caller's timeout is not modified
            let tmo = ts(0, 20_000_000);
            assert_eq!(ppoll(f2.as_mut_ptr(), 1, &tmo, core::ptr::null()), 0);
            assert_eq!(tmo, ts(0, 20_000_000));
            // hang up and invalid descriptors
            libc::close(w2);
            assert_eq!(poll(f2.as_mut_ptr(), 1, 100), 1);
            assert_eq!(f2[0].revents & POLLHUP, POLLHUP);
            let mut bad = [pollfd { fd: 9999, events: POLLIN, revents: 0 }];
            assert_eq!(poll(bad.as_mut_ptr(), 1, 0), 1);
            assert_eq!(bad[0].revents, POLLNVAL);
            // negative fd entries are ignored
            let mut neg = [pollfd { fd: -1, events: POLLIN, revents: 5 }];
            assert_eq!(poll(neg.as_mut_ptr(), 1, 0), 0);
            assert_eq!(neg[0].revents, 0);
            // bad timeout value in a timespec: EINVAL
            let badt = ts(0, -1);
            assert_eq!(ppoll(f2.as_mut_ptr(), 1, &badt, core::ptr::null()), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // Rust API
            let mut rf = [pollfd { fd: r, events: POLLIN, revents: 0 }];
            assert_eq!(poll_r(&mut rf, 0), Ok(1));
            close(&[r, w, r2]);
        }
    }

    #[test]
    fn select_and_pselect_on_a_pipe() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (r, w) = pipe();
        unsafe {
            let set = |fd: c_int| {
                let mut s = fd_set { fds_bits: [0; 16] };
                s.fds_bits[(fd / 64) as usize] |= 1 << (fd % 64);
                s
            };
            let isset = |s: &fd_set, fd: c_int| s.fds_bits[(fd / 64) as usize] >> (fd % 64) & 1 == 1;
            let mut rs = set(r);
            let mut tv = timeval { tv_sec: 0, tv_usec: 0 };
            assert_eq!(select(r + 1, &mut rs, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv), 0);
            libc::write(w, b"x".as_ptr().cast(), 1);
            let mut rs = set(r);
            let mut tv = timeval { tv_sec: 1, tv_usec: 5 };
            assert_eq!(select(r + 1, &mut rs, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv), 1);
            assert!(isset(&rs, r));
            // like Linux, the timeout is updated with the time left (at most what was given)
            assert!(tv.tv_sec < 1 || (tv.tv_sec == 1 && tv.tv_usec <= 5));
            // timeout normalisation: tv_usec above a second is carried
            let mut rs = set(r);
            libc::read(r, [0u8; 1].as_mut_ptr().cast(), 1);
            let mut tv = timeval { tv_sec: 0, tv_usec: 1_020_000 };
            let t0 = std::time::Instant::now();
            assert_eq!(select(r + 1, &mut rs, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv), 0);
            assert!(t0.elapsed() >= std::time::Duration::from_millis(1000));
            assert!(tv.tv_sec == 0 && tv.tv_usec == 0, "timeout is zero after expiry, got {tv:?}");
            // negative values: EINVAL
            let mut tv = timeval { tv_sec: -1, tv_usec: 0 };
            let mut rs = set(r);
            assert_eq!(select(r + 1, &mut rs, core::ptr::null_mut(), core::ptr::null_mut(), &mut tv), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(libc::select(r + 1, &mut core::mem::zeroed(), core::ptr::null_mut(), core::ptr::null_mut(), &mut libc::timeval { tv_sec: -1, tv_usec: 0 }), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
            // pselect: ready write end, timeout left alone
            let mut ws = set(w);
            let t = ts(5, 0);
            assert_eq!(pselect(w + 1, core::ptr::null_mut(), &mut ws, core::ptr::null_mut(), &t, core::ptr::null()), 1);
            assert!(isset(&ws, w));
            assert_eq!(t, ts(5, 0));
            // bad fd
            let gone = libc::dup(r);
            libc::close(gone);
            let mut bs = set(gone);
            assert_eq!(select(gone + 1, &mut bs, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), libc::EBADF);
        }
        close(&[r, w]);
    }

    #[test]
    fn eventfd_and_epoll() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            assert!(efd >= 0);
            let mut v = 0u64;
            // nothing there yet: -1 with EAGAIN, like the host
            assert_eq!(eventfd_read(efd, &mut v), -1);
            assert_eq!(errno::get(), libc::EAGAIN);
            assert_eq!(libc::eventfd_read(efd, &mut v), -1);
            assert_eq!(eventfd_write(efd, 5), 0);
            assert_eq!(eventfd_write(efd, 3), 0);
            let ep = epoll_create1(EFD_CLOEXEC);
            assert!(ep >= 0);
            let mut ev = epoll_event { events: EPOLLIN, data: epoll_data { u64_: 0xdead_beef_1234 } };
            assert_eq!(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &mut ev), 0);
            assert_eq!(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &mut ev), -1);
            assert_eq!(errno::get(), libc::EEXIST);
            let mut out = [epoll_event { events: 0, data: epoll_data { u64_: 0 } }; 4];
            assert_eq!(epoll_wait(ep, out.as_mut_ptr(), 4, 100), 1);
            let (e, d) = (out[0].events, out[0].data.u64_);
            assert_eq!((e, d), (EPOLLIN, 0xdead_beef_1234));
            assert_eq!(eventfd_read(efd, &mut v), 0);
            assert_eq!(v, 8);
            // drained: no more events within the timeout
            assert_eq!(epoll_wait(ep, out.as_mut_ptr(), 4, 10), 0);
            // epoll_pwait and epoll_pwait2 with no mask
            eventfd_write(efd, 1);
            assert_eq!(epoll_pwait(ep, out.as_mut_ptr(), 4, 100, core::ptr::null()), 1);
            let t = ts(0, 50_000_000);
            assert_eq!(epoll_pwait2(ep, out.as_mut_ptr(), 4, &t, core::ptr::null()), 1);
            assert_eq!(epoll_ctl(ep, EPOLL_CTL_DEL, efd, core::ptr::null_mut()), 0);
            assert_eq!(epoll_wait(ep, out.as_mut_ptr(), 0, 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(epoll_create(0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            let old = epoll_create(10);
            assert!(old >= 0);
            // Rust API
            let e2 = epoll_create1_r(0).unwrap();
            let mut ev2 = epoll_event { events: EPOLLIN, data: epoll_data { fd: efd } };
            epoll_ctl_r(e2, EPOLL_CTL_ADD, efd, Some(&mut ev2)).unwrap();
            assert_eq!(epoll_wait_r(e2, &mut out, 100), Ok(1));
            let f3 = eventfd_r(7, 0).unwrap();
            assert_eq!(libc::close(f3), 0);
            // eventfd_write of a full counter would block: the all-ones value is rejected
            assert_eq!(eventfd_write(efd, u64::MAX), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            for fd in [efd, ep, old, e2] {
                libc::close(fd);
            }
        }
    }

    #[test]
    fn timerfd_and_signalfd() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let tfd = timerfd_create(1, 0o4000);
            assert!(tfd >= 0);
            let new = itimerspec { it_interval: ts(0, 0), it_value: ts(0, 30_000_000) };
            let mut old = itimerspec::default();
            assert_eq!(timerfd_settime(tfd, 0, &new, &mut old), 0);
            assert_eq!(old, itimerspec::default());
            let mut cur = itimerspec::default();
            assert_eq!(timerfd_gettime(tfd, &mut cur), 0);
            assert!(cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 30_000_000);
            let mut fds = [pollfd { fd: tfd, events: POLLIN, revents: 0 }];
            assert_eq!(poll(fds.as_mut_ptr(), 1, 1000), 1);
            let mut expirations = 0u64;
            assert_eq!(libc::read(tfd, (&mut expirations as *mut u64).cast(), 8), 8);
            assert_eq!(expirations, 1);
            assert_eq!(timerfd_create(99, 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(timerfd_settime(tfd, 0, core::ptr::null(), core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), libc::EFAULT);
            libc::close(tfd);

            // signalfd: block SIGUSR1, raise it, read the siginfo from the descriptor
            let mut mask: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGUSR1);
            let mut oldmask: libc::sigset_t = core::mem::zeroed();
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut oldmask), 0);
            let sfd = signalfd(-1, (&mask as *const libc::sigset_t).cast(), 0o4000 | 0o2000000);
            assert!(sfd >= 0);
            libc::raise(libc::SIGUSR1);
            let mut fds = [pollfd { fd: sfd, events: POLLIN, revents: 0 }];
            assert_eq!(poll(fds.as_mut_ptr(), 1, 1000), 1);
            let mut info = [0u8; 128];
            assert_eq!(libc::read(sfd, info.as_mut_ptr().cast(), 128), 128);
            assert_eq!(u32::from_ne_bytes(info[0..4].try_into().unwrap()), libc::SIGUSR1 as u32);
            libc::close(sfd);
            // a descriptor that is not a signalfd: EINVAL
            let efd = eventfd(0, 0);
            assert_eq!(signalfd(efd, (&mask as *const libc::sigset_t).cast(), 0), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            libc::close(efd);
            libc::pthread_sigmask(libc::SIG_SETMASK, &oldmask, core::ptr::null_mut());
        }
    }

    #[test]
    fn inotify_and_fanotify() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let ifd = inotify_init1(0o4000 | 0o2000000);
            assert!(ifd >= 0);
            let dir = std::env::temp_dir();
            let mut path = dir.clone();
            path.push(format!("libc-sys-inotify-{}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            const IN_CREATE: u32 = 0x100;
            let wd = inotify_add_watch(ifd, cpath.as_ptr(), IN_CREATE);
            assert!(wd > 0);
            std::fs::write(path.join("newfile"), b"1").unwrap();
            let mut fds = [pollfd { fd: ifd, events: POLLIN, revents: 0 }];
            assert_eq!(poll(fds.as_mut_ptr(), 1, 1000), 1);
            let mut buf = [0u8; 256];
            let n = libc::read(ifd, buf.as_mut_ptr().cast(), 256);
            assert!(n >= 16);
            assert_eq!(i32::from_ne_bytes(buf[0..4].try_into().unwrap()), wd);
            assert_eq!(u32::from_ne_bytes(buf[4..8].try_into().unwrap()), IN_CREATE);
            assert_eq!(inotify_rm_watch(ifd, wd), 0);
            assert_eq!(inotify_rm_watch(ifd, wd), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            let missing = std::ffi::CString::new("/nonexistent-libc-sys").unwrap();
            assert_eq!(inotify_add_watch(ifd, missing.as_ptr(), IN_CREATE), -1);
            assert_eq!(errno::get(), libc::ENOENT);
            libc::close(ifd);
            let i2 = inotify_init();
            assert!(i2 >= 0);
            libc::close(i2);
            let _ = std::fs::remove_dir_all(&path);
            // fanotify needs privilege (EPERM) or a missing feature: the host must agree
            let f = fanotify_init(0, 0);
            let ours = errno::get();
            let h = libc::fanotify_init(0, 0);
            assert_eq!(f >= 0, h >= 0);
            if f < 0 {
                assert_eq!(ours, *libc::__errno_location());
            } else {
                libc::close(f);
                libc::close(h);
            }
            assert_eq!(fanotify_mark(-1, 1, 1, -100, core::ptr::null()), -1);
            assert_eq!(errno::get(), libc::EBADF);
        }
    }
}
