use crate::cancel;
use crate::sys::*;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::sync::atomic::{AtomicU64, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::sync_cell::SyncCell;
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

impl Sem {
    const fn new(value: u32, private: i32) -> Sem {
        Sem { data: AtomicU64::new(value as u64), private, pad: 0, rest: [0; 2] }
    }
}

macro_rules! sem_ref {
    ($p:expr) => {{
        unsafe { arg($p as *const Sem) }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_init(sem: *mut Sem, pshared: c_int, value: c_uint) -> c_int {
    if value as u64 > SEM_VALUE_MAX {
        return fail(EINVAL);
    }
    let head = sem.cast::<[u64; 2]>();
    let new = Sem::new(value, if pshared == 0 { 0 } else { 128 });
    unsafe { head.write([new.data.load(Ordering::Relaxed), (new.private as u32 as u64) | ((new.pad as u32 as u64) << 32)]) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_destroy(_sem: *mut Sem) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_getvalue(sem: *mut Sem, sval: *mut c_int) -> c_int {
    let v = (sem_ref!(sem).data.load(Ordering::Relaxed) & SEM_VALUE_MASK) as c_int;
    unsafe { *sval = v };
    0
}

#[inline]
pub fn post(s: &Sem) -> c_int {
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
        futex_wake(low_word(&s.data), 1, private);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_post(sem: *mut Sem) -> c_int {
    post(sem_ref!(sem))
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
    let s = unsafe { &*(arg as *const Sem) };
    s.data.fetch_sub(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
}

fn wait_slow(s: &Sem, clock: c_int, abs: Option<&Timespec>) -> c_int {
    let private = is_private(s);
    let mut d = s.data.fetch_add(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
    let word = low_word(&s.data);
    unsafe {
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
    }
}

pub fn wait(s: &Sem, clock: c_int, abs: Option<&Timespec>) -> c_int {
    cancel::testcancel();
    if wait_fast(s, false) {
        return 0;
    }
    wait_slow(s, clock, abs)
}

#[inline]
pub fn trywait(s: &Sem) -> c_int {
    if wait_fast(s, true) {
        return 0;
    }
    fail(EAGAIN)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_wait(sem: *mut Sem) -> c_int {
    cancel::testcancel();
    let s = sem_ref!(sem);
    if wait_fast(s, false) {
        return 0;
    }
    wait_slow(s, CLOCK_REALTIME, None)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_trywait(sem: *mut Sem) -> c_int {
    trywait(sem_ref!(sem))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_timedwait(sem: *mut Sem, abstime: *const Timespec) -> c_int {
    let abs = unsafe { arg(abstime) };
    if !valid_nsec(abs) {
        return fail(EINVAL);
    }
    wait(sem_ref!(sem), CLOCK_REALTIME, Some(abs))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_clockwait(sem: *mut Sem, clockid: c_int, abstime: *const Timespec) -> c_int {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return fail(EINVAL);
    }
    let abs = unsafe { arg(abstime) };
    if !valid_nsec(abs) {
        return fail(EINVAL);
    }
    wait(sem_ref!(sem), clockid, Some(abs))
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
static REG: SyncCell<[Open; MAX_OPEN]> = SyncCell::new([const { Open { dev: 0, ino: 0, sem: core::ptr::null_mut(), refs: 0 } }; MAX_OPEN]);
static TMP_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn with_reg<R>(f: impl FnOnce(&mut [Open; MAX_OPEN]) -> R) -> R {
    REG_LOCK.lock_always();
    let r = unsafe { REG.with_unsync(f) };
    REG_LOCK.unlock_always();
    r
}

fn sem_name(name: &[u8]) -> Result<&[u8], c_int> {
    let start = name.iter().position(|&c| c != b'/').unwrap_or(name.len());
    let nm = &name[start..];
    if nm.is_empty() || nm.contains(&b'/') || nm == b"." || nm == b".." {
        return Err(EINVAL);
    }
    if nm.len() > NAME_MAX - 4 {
        return Err(ENAMETOOLONG);
    }
    Ok(nm)
}

fn shm_path<'a>(name: &CStr, buf: &'a mut [u8; 300]) -> Option<&'a CStr> {
    let nm = match sem_name(name.to_bytes()) {
        Ok(n) => n,
        Err(e) => {
            errno::set(e);
            return None;
        }
    };
    let pre = b"/dev/shm/sem.";
    buf[..pre.len()].copy_from_slice(pre);
    buf[pre.len()..pre.len() + nm.len()].copy_from_slice(nm);
    buf[pre.len() + nm.len()] = 0;
    CStr::from_bytes_with_nul(&buf[..=pre.len() + nm.len()]).ok()
}

unsafe fn name_arg<'a>(name: *const c_char) -> &'a CStr {
    unsafe { rusty_libc_core::ffi::cstr_nonnull(name) }
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

fn openat(path: &CStr, flags: usize, mode: usize) -> usize {
    unsafe { syscall4(rusty_libc_core::syscall::SYS_OPENAT, usize::MAX - 99 , path.as_ptr() as usize, flags, mode) }
}

fn close(fd: usize) {
    unsafe { syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0) };
}

fn unlink(path: &CStr) -> usize {
    unsafe { syscall2(rusty_libc_core::syscall::SYS_UNLINK, path.as_ptr() as usize, 0) }
}

fn register(fd: usize) -> *mut Sem {
    let mut st = Stat { st_dev: 0, st_ino: 0, st_nlink: 0, st_mode: 0, st_uid: 0, st_gid: 0, pad0: 0, st_rdev: 0, st_size: 0, rest: [0; 12] };
    if errno_of(unsafe { syscall2(rusty_libc_core::syscall::SYS_FSTAT, fd, &mut st as *mut Stat as usize) }) != 0 {
        return SEM_FAILED;
    }
    let r = with_reg(|reg| {
        let mut free = None;
        for (i, e) in reg.iter_mut().enumerate() {
            if e.refs != 0 && e.dev == st.st_dev && e.ino == st.st_ino {
                e.refs += 1;
                return Ok(e.sem);
            }
            if e.refs == 0 && free.is_none() {
                free = Some(i);
            }
        }
        let Some(i) = free else { return Err(EMFILE) };
        let r = unsafe { syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, core::mem::size_of::<Sem>(), 3, 1 , fd, 0) };
        if errno_of(r) != 0 {
            return Err(errno_of(r));
        }
        reg[i] = Open { dev: st.st_dev, ino: st.st_ino, sem: r as *mut Sem, refs: 1 };
        Ok(r as *mut Sem)
    });
    match r {
        Ok(s) => s,
        Err(e) => {
            errno::set(e);
            SEM_FAILED
        }
    }
}

pub fn open(name: &CStr, oflag: c_int, mode: u32, value: u32) -> *mut Sem {
    let mut path = [0u8; 300];
    let Some(path) = shm_path(name, &mut path) else { return SEM_FAILED };
    loop {
        let fd = openat(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0);
        let e = errno_of(fd);
        if e == 0 {
            if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                close(fd);
                errno::set(EEXIST);
                return SEM_FAILED;
            }
            let s = register(fd);
            close(fd);
            return s;
        }
        if e != ENOENT || oflag & O_CREAT == 0 {
            errno::set(e);
            return SEM_FAILED;
        }
        let mut tmp = [0u8; 64];
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tname = format_tmp(&mut tmp, getpid() as u32, n);
        let fd = openat(tname, O_RDWR | O_CLOEXEC | 0o200 | 0o100, (mode & 0o777) as usize);
        if errno_of(fd) != 0 {
            errno::set(errno_of(fd));
            return SEM_FAILED;
        }
        let init = Sem::new(value, 128);
        let w = unsafe { syscall3(rusty_libc_core::syscall::SYS_WRITE, fd, &init as *const Sem as usize, core::mem::size_of::<Sem>()) };
        if errno_of(w) != 0 || w != core::mem::size_of::<Sem>() {
            close(fd);
            unlink(tname);
            errno::set(if errno_of(w) != 0 { errno_of(w) } else { EAGAIN });
            return SEM_FAILED;
        }
        let l = unsafe { syscall2(86 , tname.as_ptr() as usize, path.as_ptr() as usize) };
        unlink(tname);
        let le = errno_of(l);
        if le == 0 {
            let s = register(fd);
            close(fd);
            return s;
        }
        close(fd);
        if le == EEXIST {
            if oflag & O_EXCL != 0 {
                errno::set(EEXIST);
                return SEM_FAILED;
            }
            continue;
        }
        errno::set(le);
        return SEM_FAILED;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_open(name: *const c_char, oflag: c_int, mut args: ...) -> *mut Sem {
    let name = unsafe { name_arg(name) };
    let mut path = [0u8; 300];
    if shm_path(name, &mut path).is_none() {
        return SEM_FAILED;
    }
    let (mut mode, mut value) = (0u32, 0u32);
    if oflag & O_CREAT != 0 {
        mode = unsafe { args.next_arg::<c_uint>() };
        value = unsafe { args.next_arg::<c_uint>() };
        if value as u64 > SEM_VALUE_MAX {
            errno::set(EINVAL);
            return SEM_FAILED;
        }
    }
    open(name, oflag, mode, value)
}

fn format_tmp(buf: &mut [u8; 64], pid: u32, n: u32) -> &CStr {
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
    CStr::from_bytes_with_nul(&buf[..=i]).unwrap_or(c"")
}

pub fn close_sem(sem: *mut Sem) -> c_int {
    let found = with_reg(|reg| {
        for e in reg.iter_mut() {
            if e.refs != 0 && e.sem == sem {
                e.refs -= 1;
                if e.refs == 0 {
                    unsafe { syscall2(rusty_libc_core::syscall::SYS_MUNMAP, sem as usize, core::mem::size_of::<Sem>()) };
                    e.sem = core::ptr::null_mut();
                }
                return true;
            }
        }
        false
    });
    if found { 0 } else { fail(EINVAL) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_close(sem: *mut Sem) -> c_int {
    close_sem(sem)
}

pub fn unlink_sem(name: &CStr) -> c_int {
    let mut path = [0u8; 300];
    let Some(path) = shm_path(name, &mut path) else { return -1 };
    let e = errno_of(unlink(path));
    if e == 0 {
        return 0;
    }
    fail(if e == EPERM { EACCES } else { e })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    unlink_sem(unsafe { name_arg(name) })
}

