use crate::cancel;
use crate::sys::*;
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::sync::atomic::{AtomicU64, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::syscall::{syscall2, syscall3, syscall4, syscall6};

const SEM_VALUE_MAX: u64 = i32::MAX as u64;
const SEM_VALUE_MASK: u64 = 0xffff_ffff;
const SEM_NWAITERS_SHIFT: u32 = 32;

#[repr(C)]
pub struct Sem {
    data: AtomicU64,
    private: i32,
    pad: i32,
    rest: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<Sem>() == 32);

fn fail(e: c_int) -> c_int {
    errno::set(e);
    -1
}

fn is_private(s: &Sem) -> bool {
    s.private == 0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_init(sem: *mut Sem, pshared: c_int, value: c_uint) -> c_int {
    unsafe {
        if value as u64 > SEM_VALUE_MAX {
            return fail(EINVAL);
        }
        (*sem).data = AtomicU64::new(value as u64);
        (*sem).private = if pshared == 0 { 0 } else { 128 };
        (*sem).pad = 0;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_destroy(_sem: *mut Sem) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_getvalue(sem: *mut Sem, sval: *mut c_int) -> c_int {
    unsafe {
        *sval = ((*sem).data.load(Ordering::Relaxed) & SEM_VALUE_MASK) as c_int;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_post(sem: *mut Sem) -> c_int {
    unsafe {
        let s = &*sem;
        let private = is_private(s);
        let mut d = s.data.load(Ordering::Relaxed);
        loop {
            if d & SEM_VALUE_MASK == SEM_VALUE_MAX {
                return fail(EOVERFLOW);
            }
            match s.data.compare_exchange_weak(d, d + 1, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => break,
                Err(x) => d = x,
            }
        }
        if d >> SEM_NWAITERS_SHIFT > 0 {
            futex_wake(&s.data as *const AtomicU64 as *const core::sync::atomic::AtomicU32, 1, private);
        }
        0
    }
}

fn wait_fast(s: &Sem, definitive: bool) -> bool {
    let mut d = s.data.load(Ordering::Relaxed);
    loop {
        if d & SEM_VALUE_MASK == 0 {
            return false;
        }
        match s.data.compare_exchange_weak(d, d - 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(x) => d = x,
        }
        if !definitive {
            return false;
        }
    }
}

unsafe extern "C" fn wait_cleanup(arg: *mut c_void) {
    unsafe {
        let s = &*(arg as *const Sem);
        s.data.fetch_sub(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
    }
}

fn wait_slow(s: &Sem, clock: c_int, abs: *const Timespec) -> c_int {
    let private = is_private(s);
    let mut d = s.data.fetch_add(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
    let word = &s.data as *const AtomicU64 as *const core::sync::atomic::AtomicU32;
    let result = unsafe {
        cancel::with_cleanup(wait_cleanup, s as *const Sem as *mut c_void, || loop {
            if d & SEM_VALUE_MASK == 0 {
                let err = futex_wait_abs_cp(word, 0, clock, abs, private);
                if err == ETIMEDOUT || err == EINTR || err == EOVERFLOW {
                    s.data.fetch_sub(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
                    return fail(err);
                }
                d = s.data.load(Ordering::Relaxed);
            } else {
                match s.data.compare_exchange_weak(d, d - 1 - (1u64 << SEM_NWAITERS_SHIFT), Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => return 0,
                    Err(x) => d = x,
                }
            }
        })
    };
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_wait(sem: *mut Sem) -> c_int {
    unsafe {
        cancel::testcancel();
        let s = &*sem;
        if wait_fast(s, false) {
            return 0;
        }
        wait_slow(s, CLOCK_REALTIME, core::ptr::null())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_trywait(sem: *mut Sem) -> c_int {
    unsafe {
        if wait_fast(&*sem, true) {
            return 0;
        }
        fail(EAGAIN)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_timedwait(sem: *mut Sem, abstime: *const Timespec) -> c_int {
    unsafe {
        if !valid_nsec(&*abstime) {
            return fail(EINVAL);
        }
        cancel::testcancel();
        let s = &*sem;
        if wait_fast(s, false) {
            return 0;
        }
        wait_slow(s, CLOCK_REALTIME, abstime)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_clockwait(sem: *mut Sem, clockid: c_int, abstime: *const Timespec) -> c_int {
    unsafe {
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return fail(EINVAL);
        }
        if !valid_nsec(&*abstime) {
            return fail(EINVAL);
        }
        cancel::testcancel();
        let s = &*sem;
        if wait_fast(s, false) {
            return 0;
        }
        wait_slow(s, clockid, abstime)
    }
}

const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_RDWR: usize = 2;
const O_NOFOLLOW: usize = 0o400000;
const O_CLOEXEC: usize = 0o2000000;
const NAME_MAX: usize = 255;
const SEM_FAILED: *mut Sem = core::ptr::null_mut();

struct Open {
    dev: u64,
    ino: u64,
    sem: *mut Sem,
    refs: u32,
}

const MAX_OPEN: usize = 128;
static REG_LOCK: RawMutex = RawMutex::new();
static mut REG: [Open; MAX_OPEN] = [const { Open { dev: 0, ino: 0, sem: core::ptr::null_mut(), refs: 0 } }; MAX_OPEN];
static TMP_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

unsafe fn shm_path(name: *const c_char, buf: &mut [u8; 300]) -> Option<usize> {
    unsafe {
        let mut p = name as *const u8;
        while *p == b'/' {
            p = p.add(1);
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        let nm = core::slice::from_raw_parts(p, len);
        if len == 0 || nm.contains(&b'/') || nm == b"." || nm == b".." {
            errno::set(EINVAL);
            return None;
        }
        if len > NAME_MAX - 4 {
            errno::set(ENAMETOOLONG);
            return None;
        }
        let pre = b"/dev/shm/sem.";
        buf[..pre.len()].copy_from_slice(pre);
        buf[pre.len()..pre.len() + len].copy_from_slice(nm);
        buf[pre.len() + len] = 0;
        Some(pre.len() + len)
    }
}

#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    pad0: u32,
    st_rdev: u64,
    st_size: i64,
    rest: [u64; 12],
}

unsafe fn register(fd: usize) -> *mut Sem {
    unsafe {
        let mut st: Stat = core::mem::zeroed();
        if errno_of(syscall2(rusty_libc_core::syscall::SYS_FSTAT, fd, &mut st as *mut Stat as usize)) != 0 {
            return SEM_FAILED;
        }
        REG_LOCK.lock_always();
        let reg = &mut *(&raw mut REG);
        let mut free = None;
        for (i, e) in reg.iter_mut().enumerate() {
            if e.refs != 0 && e.dev == st.st_dev && e.ino == st.st_ino {
                e.refs += 1;
                let s = e.sem;
                REG_LOCK.unlock_always();
                return s;
            }
            if e.refs == 0 && free.is_none() {
                free = Some(i);
            }
        }
        let Some(i) = free else {
            REG_LOCK.unlock_always();
            errno::set(EMFILE);
            return SEM_FAILED;
        };
        let r = syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, core::mem::size_of::<Sem>(), 3, 1 , fd, 0);
        if errno_of(r) != 0 {
            REG_LOCK.unlock_always();
            errno::set(errno_of(r));
            return SEM_FAILED;
        }
        reg[i] = Open { dev: st.st_dev, ino: st.st_ino, sem: r as *mut Sem, refs: 1 };
        REG_LOCK.unlock_always();
        r as *mut Sem
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_open(name: *const c_char, oflag: c_int, mut args: ...) -> *mut Sem {
    unsafe {
        let mut path = [0u8; 300];
        let Some(plen) = shm_path(name, &mut path) else { return SEM_FAILED };
        let (mut mode, mut value) = (0u32, 0u32);
        if oflag & O_CREAT != 0 {
            mode = args.next_arg::<c_uint>();
            value = args.next_arg::<c_uint>();
            if value as u64 > SEM_VALUE_MAX {
                errno::set(EINVAL);
                return SEM_FAILED;
            }
        }
        loop {
            let fd = syscall4(rusty_libc_core::syscall::SYS_OPENAT, usize::MAX - 99 , path.as_ptr() as usize, O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0);
            let e = errno_of(fd);
            if e == 0 {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0);
                    errno::set(EEXIST);
                    return SEM_FAILED;
                }
                let s = register(fd);
                syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0);
                return s;
            }
            if e != ENOENT || oflag & O_CREAT == 0 {
                errno::set(e);
                return SEM_FAILED;
            }
            let mut tmp = [0u8; 64];
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tname = format_tmp(&mut tmp, getpid() as u32, n);
            let fd = syscall4(rusty_libc_core::syscall::SYS_OPENAT, usize::MAX - 99, tname.as_ptr() as usize, O_RDWR | O_CLOEXEC | 0o200 | 0o100, (mode & 0o777) as usize);
            if errno_of(fd) != 0 {
                errno::set(errno_of(fd));
                return SEM_FAILED;
            }
            let mut init: Sem = core::mem::zeroed();
            init.data = AtomicU64::new(value as u64);
            init.private = 128;
            let w = syscall3(rusty_libc_core::syscall::SYS_WRITE, fd, &init as *const Sem as usize, core::mem::size_of::<Sem>());
            if errno_of(w) != 0 || w != core::mem::size_of::<Sem>() {
                syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0);
                syscall2(rusty_libc_core::syscall::SYS_UNLINK, tname.as_ptr() as usize, 0);
                errno::set(if errno_of(w) != 0 { errno_of(w) } else { EAGAIN });
                return SEM_FAILED;
            }
            let l = syscall2(86 , tname.as_ptr() as usize, path.as_ptr() as usize);
            syscall2(rusty_libc_core::syscall::SYS_UNLINK, tname.as_ptr() as usize, 0);
            let le = errno_of(l);
            if le == 0 {
                let s = register(fd);
                syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0);
                return s;
            }
            syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0);
            if le == EEXIST {
                if oflag & O_EXCL != 0 {
                    errno::set(EEXIST);
                    return SEM_FAILED;
                }
                continue;
            }
            errno::set(le);
            let _ = plen;
            return SEM_FAILED;
        }
    }
}

fn format_tmp(buf: &mut [u8; 64], pid: u32, n: u32) -> &[u8] {
    let pre = b"/dev/shm/sem.rlibc-tmp-";
    buf[..pre.len()].copy_from_slice(pre);
    let mut i = pre.len();
    for mut v in [pid, n] {
        let mut digits = [0u8; 10];
        let mut k = 0;
        loop {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
            if v == 0 {
                break;
            }
        }
        while k > 0 {
            k -= 1;
            buf[i] = digits[k];
            i += 1;
        }
        buf[i] = b'-';
        i += 1;
    }
    buf[i] = 0;
    &buf[..=i]
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_close(sem: *mut Sem) -> c_int {
    unsafe {
        REG_LOCK.lock_always();
        let reg = &mut *(&raw mut REG);
        for e in reg.iter_mut() {
            if e.refs != 0 && e.sem == sem {
                e.refs -= 1;
                if e.refs == 0 {
                    syscall2(rusty_libc_core::syscall::SYS_MUNMAP, sem as usize, core::mem::size_of::<Sem>());
                    e.sem = core::ptr::null_mut();
                }
                REG_LOCK.unlock_always();
                return 0;
            }
        }
        REG_LOCK.unlock_always();
        fail(EINVAL)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    unsafe {
        let mut path = [0u8; 300];
        if shm_path(name, &mut path).is_none() {
            return -1;
        }
        let r = syscall2(rusty_libc_core::syscall::SYS_UNLINK, path.as_ptr() as usize, 0);
        let e = errno_of(r);
        if e == 0 {
            return 0;
        }
        fail(if e == EPERM { EACCES } else { e })
    }
}

