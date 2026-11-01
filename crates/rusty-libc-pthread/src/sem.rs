//! semaphore.h: sem_t (32 bytes; glibc's new_sem in its first 16: a 64-bit word with the value in the
//! low 32 bits and the number of waiters above, then the futex-shared flag, 0 = private), unnamed and named
//! (in /dev/shm as `sem.NAME`, like glibc) semaphores.
//! The wait/post algorithm is glibc's 64-bit variant (derived from nptl/sem_*.c, LGPL-2.1; see
//! LICENSES.md). sem_wait and sem_timedwait are cancellation points.
//!
//! Safe core: the value word is an atomic, so post/wait work on `&Sem`; named semaphores keep their registry in a
//! `SyncCell` under REG_LOCK. Unsafe left: the boundary conversions, the system calls with pointer arguments, sem_open's
//! variadic arguments.
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
    /// glibc's encoding (nptl FUTEX_PRIVATE = 0, FUTEX_SHARED = 128 = FUTEX_PRIVATE_FLAG): 0 for a process-private
    /// semaphore, 128 for one shared between processes. Named semaphores are shared with processes running
    /// glibc, so the stored value must mean the same thing to both.
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
    /// A semaphore with `value`, process-private or shared (glibc's 0 / 128 encoding).
    const fn new(value: u32, private: i32) -> Sem {
        Sem { data: AtomicU64::new(value as u64), private, pad: 0, rest: [0; 2] }
    }
}

/// The exported functions convert the semaphore pointer once (glibc uses it without a NULL check). The fields other threads
/// change are atomics (`data`); `private` is written only by sem_init.
macro_rules! sem_ref {
    ($p:expr) => {{
        // SAFETY: the C caller passes an initialised sem_t that stays valid for the call.
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
    // the first 16 bytes only (the value word, the shared flag, the pad), as glibc's sem_init; the rest is left as it was
    // SAFETY: `sem` is writable memory for one sem_t (C contract) that no other thread uses during the init; `[u64; 2]` is
    // the first half of its layout (both are 8-aligned).
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
    // SAFETY: `sval` is a writable int (C contract; written without a NULL check, as glibc).
    unsafe { *sval = v };
    0
}

/// `sem_post`: 0, or -1 with errno EOVERFLOW.
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
    // SAFETY: `arg` is the semaphore registered by wait_slow, valid while its waiter waits.
    let s = unsafe { &*(arg as *const Sem) };
    s.data.fetch_sub(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
}

fn wait_slow(s: &Sem, clock: c_int, abs: Option<&Timespec>) -> c_int {
    let private = is_private(s);
    let mut d = s.data.fetch_add(1u64 << SEM_NWAITERS_SHIFT, Ordering::Relaxed);
    let word = low_word(&s.data);
    // SAFETY: the handler gets `s`, which outlives the call (the handler only runs inside it).
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

/// `sem_wait` / `sem_timedwait` / `sem_clockwait` after the argument checks: a cancellation point; 0 or -1 with errno.
pub fn wait(s: &Sem, clock: c_int, abs: Option<&Timespec>) -> c_int {
    #[cfg(not(test))]
    cancel::testcancel();
    if wait_fast(s, false) {
        return 0;
    }
    wait_slow(s, clock, abs)
}

/// `sem_trywait`: 0, or -1 with errno EAGAIN.
#[inline]
pub fn trywait(s: &Sem) -> c_int {
    if wait_fast(s, true) {
        return 0;
    }
    fail(EAGAIN)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_wait(sem: *mut Sem) -> c_int {
    #[cfg(not(test))]
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
    // SAFETY: `abstime` is a valid struct timespec (C contract; read without a NULL check, as glibc).
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
    // SAFETY: `abstime` is a valid struct timespec (C contract; read without a NULL check, as glibc).
    let abs = unsafe { arg(abstime) };
    if !valid_nsec(abs) {
        return fail(EINVAL);
    }
    wait(sem_ref!(sem), clockid, Some(abs))
}

// ---- named semaphores -----------------------------------------------------------------------

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
/// The open named semaphores (one mapping per file, counted). Touched only with REG_LOCK held (`with_reg`).
static REG: SyncCell<[Open; MAX_OPEN]> = SyncCell::new([const { Open { dev: 0, ino: 0, sem: core::ptr::null_mut(), refs: 0 } }; MAX_OPEN]);
static TMP_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Run `f` on the registry with its lock held.
fn with_reg<R>(f: impl FnOnce(&mut [Open; MAX_OPEN]) -> R) -> R {
    REG_LOCK.lock_always();
    // SAFETY: REG is only touched here, with REG_LOCK held, and `f` does not reach REG again.
    let r = unsafe { REG.with_unsync(f) };
    REG_LOCK.unlock_always();
    r
}

/// The name of a semaphore without its leading slashes, checked as glibc checks it: Err(errno) for a bad name.
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

/// "/dev/shm/sem.NAME" (NUL-terminated in `buf`) for a semaphore name; None (with errno set) for a bad name.
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

/// The C string argument `name` (read without a NULL check, as glibc).
///
/// # Safety
/// `name` is a NUL-terminated string that stays valid for `'a`.
unsafe fn name_arg<'a>(name: *const c_char) -> &'a CStr {
    // SAFETY: forwarded contract.
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

/// Raw open of a NUL-terminated path at AT_FDCWD: the fd or -errno as the kernel returns it.
fn openat(path: &CStr, flags: usize, mode: usize) -> usize {
    // SAFETY: the kernel reads the borrowed NUL-terminated path.
    unsafe { syscall4(rusty_libc_core::syscall::SYS_OPENAT, usize::MAX - 99 /* AT_FDCWD */, path.as_ptr() as usize, flags, mode) }
}

fn close(fd: usize) {
    // SAFETY: plain-value system call on an fd this module opened.
    unsafe { syscall2(rusty_libc_core::syscall::SYS_CLOSE, fd, 0) };
}

fn unlink(path: &CStr) -> usize {
    // SAFETY: the kernel reads the borrowed NUL-terminated path.
    unsafe { syscall2(rusty_libc_core::syscall::SYS_UNLINK, path.as_ptr() as usize, 0) }
}

/// The semaphore of the open file `fd`: its existing mapping (counted once more) or a new one.
fn register(fd: usize) -> *mut Sem {
    let mut st = Stat { st_dev: 0, st_ino: 0, st_nlink: 0, st_mode: 0, st_uid: 0, st_gid: 0, pad0: 0, st_rdev: 0, st_size: 0, rest: [0; 12] };
    // SAFETY: the kernel writes a struct stat (144 bytes, the size of Stat) into the borrowed local.
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
        // SAFETY: a new shared mapping of the semaphore file at an address the kernel picks (no existing memory changes).
        let r = unsafe { syscall6(rusty_libc_core::syscall::SYS_MMAP, 0, core::mem::size_of::<Sem>(), 3, 1 /* MAP_SHARED */, fd, 0) };
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

/// `sem_open` after the variadic arguments were read (`mode`, `value` matter only with O_CREAT).
pub fn open(name: &CStr, oflag: c_int, mode: u32, value: u32) -> *mut Sem {
    let mut path = [0u8; 300];
    let Some(path) = shm_path(name, &mut path) else { return SEM_FAILED };
    loop {
        // try an existing semaphore first
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
        // create: write a temporary file, then link it into place (atomic appearance)
        let mut tmp = [0u8; 64];
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tname = format_tmp(&mut tmp, getpid() as u32, n);
        let fd = openat(tname, O_RDWR | O_CLOEXEC | 0o200 | 0o100, (mode & 0o777) as usize);
        if errno_of(fd) != 0 {
            errno::set(errno_of(fd));
            return SEM_FAILED;
        }
        // FUTEX_SHARED in glibc's encoding: shared between processes
        let init = Sem::new(value, 128);
        // SAFETY: the kernel reads the borrowed 32-byte semaphore image.
        let w = unsafe { syscall3(rusty_libc_core::syscall::SYS_WRITE, fd, &init as *const Sem as usize, core::mem::size_of::<Sem>()) };
        if errno_of(w) != 0 || w != core::mem::size_of::<Sem>() {
            close(fd);
            unlink(tname);
            errno::set(if errno_of(w) != 0 { errno_of(w) } else { EAGAIN });
            return SEM_FAILED;
        }
        // SAFETY: the kernel reads the two borrowed NUL-terminated paths.
        let l = unsafe { syscall2(86 /* link */, tname.as_ptr() as usize, path.as_ptr() as usize) };
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
            continue; // somebody else created it first: open theirs
        }
        errno::set(le);
        return SEM_FAILED;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_open(name: *const c_char, oflag: c_int, mut args: ...) -> *mut Sem {
    // SAFETY: `name` is a NUL-terminated string (C contract).
    let name = unsafe { name_arg(name) };
    // (the name is checked before the variadic arguments are read, as before; `open` checks it again, without a system call)
    let mut path = [0u8; 300];
    if shm_path(name, &mut path).is_none() {
        return SEM_FAILED;
    }
    let (mut mode, mut value) = (0u32, 0u32);
    if oflag & O_CREAT != 0 {
        // SAFETY: with O_CREAT the caller passes the mode and the value (C contract).
        mode = unsafe { args.next_arg::<c_uint>() };
        // SAFETY: as above.
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
    // (digits and dashes only before the one NUL)
    CStr::from_bytes_with_nul(&buf[..=i]).unwrap_or(c"")
}

/// `sem_close`: 0, or -1 with errno EINVAL for a semaphore that is not open.
pub fn close_sem(sem: *mut Sem) -> c_int {
    let found = with_reg(|reg| {
        for e in reg.iter_mut() {
            if e.refs != 0 && e.sem == sem {
                e.refs -= 1;
                if e.refs == 0 {
                    // SAFETY: the registry's own mapping, no longer counted; the program closed its last handle.
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

/// `sem_unlink`: 0, or -1 with errno.
pub fn unlink_sem(name: &CStr) -> c_int {
    let mut path = [0u8; 300];
    let Some(path) = shm_path(name, &mut path) else { return -1 };
    let e = errno_of(unlink(path));
    if e == 0 {
        return 0;
    }
    // as glibc: a directory-permission refusal reads as EACCES
    fail(if e == EPERM { EACCES } else { e })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    // SAFETY: `name` is a NUL-terminated string (C contract).
    unlink_sem(unsafe { name_arg(name) })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<Sem>(), 32);
    }

    #[test]
    fn counting() {
        unsafe {
            let mut s: Sem = core::mem::zeroed();
            assert_eq!(sem_init(&mut s, 0, 2), 0);
            assert_eq!(sem_trywait(&mut s), 0);
            assert_eq!(sem_wait(&mut s), 0);
            assert_eq!(sem_trywait(&mut s), -1);
            assert_eq!(errno::get(), EAGAIN);
            assert_eq!(sem_post(&mut s), 0);
            let mut v = 0;
            sem_getvalue(&mut s, &mut v);
            assert_eq!(v, 1);
            assert_eq!(sem_init(&mut s, 0, u32::MAX), -1);
            assert_eq!(errno::get(), EINVAL);
        }
    }

    #[test]
    fn timedwait_times_out() {
        unsafe {
            let mut s: Sem = core::mem::zeroed();
            sem_init(&mut s, 0, 0);
            let mut now = Timespec::default();
            clock_gettime(CLOCK_REALTIME, &mut now);
            timespec_add_ns(&mut now, 20_000_000);
            assert_eq!(sem_timedwait(&mut s, &now), -1);
            assert_eq!(errno::get(), ETIMEDOUT);
            let bad = Timespec { tv_sec: 0, tv_nsec: -5 };
            assert_eq!(sem_timedwait(&mut s, &bad), -1);
            assert_eq!(errno::get(), EINVAL);
            assert_eq!(sem_clockwait(&mut s, 7, &now), -1);
            assert_eq!(errno::get(), EINVAL);
        }
    }

    #[test]
    fn post_wakes_waiter() {
        let s = std::sync::Arc::new(core::cell::UnsafeCell::new(unsafe { core::mem::zeroed::<Sem>() }));
        struct P(*mut Sem);
        unsafe impl Send for P {}
        unsafe { sem_init(s.get(), 0, 0) };
        let p = P(s.get());
        let h = std::thread::spawn(move || {
            let p = p;
            unsafe { sem_wait(p.0) }
        });
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sem_post(s.get()) };
        assert_eq!(h.join().unwrap(), 0);
    }

    #[test]
    fn named_semaphore() {
        unsafe {
            let name = c"/rlibc-test-sem-unit";
            sem_unlink(name.as_ptr());
            assert_eq!(sem_open(name.as_ptr(), 0), SEM_FAILED);
            assert_eq!(errno::get(), ENOENT);
            let a = sem_open(name.as_ptr(), O_CREAT | O_EXCL, 0o600u32, 3u32);
            assert_ne!(a, SEM_FAILED);
            assert_eq!(sem_open(name.as_ptr(), O_CREAT | O_EXCL, 0o600u32, 3u32), SEM_FAILED);
            assert_eq!(errno::get(), EEXIST);
            let b = sem_open(name.as_ptr(), 0);
            assert_eq!(a, b);
            let mut v = 0;
            sem_getvalue(a, &mut v);
            assert_eq!(v, 3);
            assert_eq!(sem_close(a), 0);
            assert_eq!(sem_close(b), 0);
            assert_eq!(sem_close(b), -1);
            assert_eq!(sem_unlink(name.as_ptr()), 0);
            assert_eq!(sem_unlink(name.as_ptr()), -1);
            assert_eq!(errno::get(), ENOENT);
            assert_eq!(sem_open(c"a/b".as_ptr(), 0), SEM_FAILED);
            assert_eq!(errno::get(), EINVAL);
        }
    }
}
