use crate::misc::{sc, sci};
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{check, syscall1, syscall2, syscall3, syscall4, syscall5};
use rusty_libc_core::{Errno, errno};

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

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct epoll_event {
    pub events: u32,
    pub data: epoll_data,
}

pub fn poll_r(fds: &mut [pollfd], timeout_ms: i32) -> Result<usize, Errno> {
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_POLL, fds.as_mut_ptr() as usize, fds.len(), timeout_ms as isize as usize, 0, 0, 0)) }
}

pub fn eventfd_r(initval: u32, flags: i32) -> Result<i32, Errno> {
    unsafe { check(syscall2(SYS_EVENTFD2, initval as usize, flags as usize)).map(|v| v as i32) }
}

pub fn epoll_create1_r(flags: i32) -> Result<i32, Errno> {
    unsafe { check(syscall1(SYS_EPOLL_CREATE1, flags as usize)).map(|v| v as i32) }
}

pub fn epoll_ctl_r(epfd: i32, op: i32, fd: i32, ev: Option<&mut epoll_event>) -> Result<(), Errno> {
    let p = ev.map_or(0, |e| e as *mut epoll_event as usize);
    unsafe { check(syscall4(SYS_EPOLL_CTL, epfd as usize, op as usize, fd as usize, p)).map(|_| ()) }
}

pub fn epoll_wait_r(epfd: i32, events: &mut [epoll_event], timeout_ms: i32) -> Result<usize, Errno> {
    unsafe {
        check(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, events.len(), timeout_ms as isize as usize, 0, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn poll(fds: *mut pollfd, nfds: c_ulong, timeout: c_int) -> c_int {
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_POLL, fds as usize, nfds as usize, timeout as isize as usize, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ppoll(fds: *mut pollfd, nfds: c_ulong, timeout: *const timespec, sigmask: *const c_void) -> c_int {
    unsafe {
        let mut tv = if timeout.is_null() { timespec::default() } else { *timeout };
        let tp = if timeout.is_null() { 0 } else { &mut tv as *mut timespec as usize };
        sci(rusty_libc_core::tls::syscall_cp(SYS_PPOLL, fds as usize, nfds as usize, tp, sigmask as usize, KERNEL_SIGSET, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn select(nfds: c_int, r: *mut fd_set, w: *mut fd_set, e: *mut fd_set, timeout: *mut timeval) -> c_int {
    unsafe {
        let mut s: i64 = if timeout.is_null() { 0 } else { (*timeout).tv_sec };
        let mut us: i32 = if timeout.is_null() { 0 } else { (*timeout).tv_usec as i32 };
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
        let ret = sci(rusty_libc_core::tls::syscall_cp(SYS_SELECT_PSELECT6, nfds as usize, r as usize, w as usize, e as usize, tp, 0));
        if !timeout.is_null() {
            (*timeout).tv_sec = ts.tv_sec;
            (*timeout).tv_usec = ts.tv_nsec / 1000;
        }
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    r: *mut fd_set,
    w: *mut fd_set,
    e: *mut fd_set,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    unsafe {
        let mut tv = if timeout.is_null() { timespec::default() } else { *timeout };
        let tp = if timeout.is_null() { 0 } else { &mut tv as *mut timespec as usize };
        let data: [usize; 2] = [sigmask as usize, KERNEL_SIGSET];
        sci(rusty_libc_core::tls::syscall_cp(SYS_SELECT_PSELECT6, nfds as usize, r as usize, w as usize, e as usize, tp, data.as_ptr() as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn epoll_create(size: c_int) -> c_int {
    if size <= 0 {
        errno::set(EINVAL);
        return -1;
    }
    unsafe { sci(syscall1(SYS_EPOLL_CREATE, size as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn epoll_create1(flags: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_EPOLL_CREATE1, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut epoll_event) -> c_int {
    unsafe { sci(syscall4(SYS_EPOLL_CTL, epfd as usize, op as usize, fd as usize, ev as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_wait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int) -> c_int {
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_WAIT, epfd as usize, events as usize, maxevents as usize, timeout as isize as usize, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait(epfd: c_int, events: *mut epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const c_void) -> c_int {
    unsafe {
        sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_PWAIT, epfd as usize, events as usize, maxevents as usize, timeout as isize as usize, sigmask as usize, KERNEL_SIGSET))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait2(
    epfd: c_int,
    events: *mut epoll_event,
    maxevents: c_int,
    timeout: *const timespec,
    sigmask: *const c_void,
) -> c_int {
    unsafe {
        sci(rusty_libc_core::tls::syscall_cp(SYS_EPOLL_PWAIT2, epfd as usize, events as usize, maxevents as usize, timeout as usize, sigmask as usize, KERNEL_SIGSET))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn eventfd(count: c_uint, flags: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_EVENTFD2, count as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut u64) -> c_int {
    unsafe {
        if sc(rusty_libc_core::tls::syscall_cp(SYS_READ, fd as usize, value as usize, 8, 0, 0, 0)) == 8 { 0 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn eventfd_write(fd: c_int, value: u64) -> c_int {
    unsafe {
        if sc(rusty_libc_core::tls::syscall_cp(SYS_WRITE, fd as usize, &value as *const u64 as usize, 8, 0, 0, 0)) == 8 { 0 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn signalfd(fd: c_int, mask: *const c_void, flags: c_int) -> c_int {
    unsafe { sci(syscall4(SYS_SIGNALFD4, fd as isize as usize, mask as usize, KERNEL_SIGSET, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn timerfd_create(clock: c_int, flags: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_TIMERFD_CREATE, clock as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_settime(fd: c_int, flags: c_int, new: *const itimerspec, old: *mut itimerspec) -> c_int {
    unsafe { sci(syscall4(SYS_TIMERFD_SETTIME, fd as usize, flags as usize, new as usize, old as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn timerfd_gettime(fd: c_int, cur: *mut itimerspec) -> c_int {
    unsafe { sci(syscall2(SYS_TIMERFD_GETTIME, fd as usize, cur as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_init() -> c_int {
    unsafe { sci(rusty_libc_core::syscall::syscall0(SYS_INOTIFY_INIT)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_init1(flags: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_INOTIFY_INIT1, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int {
    unsafe { sci(syscall3(SYS_INOTIFY_ADD_WATCH, fd as usize, path as usize, mask as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    unsafe { sci(syscall2(SYS_INOTIFY_RM_WATCH, fd as usize, wd as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fanotify_init(flags: c_uint, event_f_flags: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_FANOTIFY_INIT, flags as usize, event_f_flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_mark(fd: c_int, flags: c_uint, mask: u64, dirfd: c_int, path: *const c_char) -> c_int {
    unsafe { sci(syscall5(SYS_FANOTIFY_MARK, fd as usize, flags as usize, mask as usize, dirfd as isize as usize, path as usize)) }
}

