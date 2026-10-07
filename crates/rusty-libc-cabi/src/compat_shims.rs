use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};
use rusty_libc_core::errno;

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_regexec(preg: *const rusty_libc_regex::cabi::RegexT, string: *const c_char, nmatch: usize, pmatch: *mut rusty_libc_regex::cabi::RegMatch, eflags: c_int) -> c_int {
    unsafe { rusty_libc_regex::cabi::regexec(preg, string, nmatch, pmatch, eflags & 3 ) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    unsafe {
        if resolved.is_null() {
            errno::set(EINVAL);
            return core::ptr::null_mut();
        }
        rusty_libc_stdlib::misc::realpath(path, resolved)
    }
}

const FTW_OLD_FLAGS: c_int = 1  | 2  | 4  | 8 ;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_nftw(path: *const c_char, func: rusty_libc_extra::ftw::NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    unsafe { rusty_libc_extra::ftw::nftw(path, func, descriptors, flags & FTW_OLD_FLAGS) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_nftw64(path: *const c_char, func: rusty_libc_extra::ftw::NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    unsafe { rusty_libc_extra::ftw::nftw64(path, func, descriptors, flags & FTW_OLD_FLAGS) }
}

const OLD_CPUSET_SIZE: usize = 128;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_sched_getaffinity(pid: c_int, set: *mut c_void) -> c_int {
    unsafe { rusty_libc_sys::misc::sched_getaffinity(pid, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_sched_setaffinity(pid: c_int, set: *const c_void) -> c_int {
    unsafe { rusty_libc_sys::misc::sched_setaffinity(pid, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_getaffinity_np(th: rusty_libc_pthread::PthreadT, set: *mut rusty_libc_pthread::CpuSet) -> c_int {
    unsafe { rusty_libc_pthread::pthread_getaffinity_np(th, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_setaffinity_np(th: rusty_libc_pthread::PthreadT, set: *const rusty_libc_pthread::CpuSet) -> c_int {
    unsafe { rusty_libc_pthread::pthread_setaffinity_np(th, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_attr_getaffinity_np(attr: *const rusty_libc_pthread::PthreadAttr, set: *mut rusty_libc_pthread::CpuSet) -> c_int {
    unsafe { rusty_libc_pthread::pthread_attr_getaffinity_np(attr, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_attr_setaffinity_np(attr: *mut rusty_libc_pthread::PthreadAttr, set: *const rusty_libc_pthread::CpuSet) -> c_int {
    unsafe { rusty_libc_pthread::pthread_attr_setaffinity_np(attr, OLD_CPUSET_SIZE, set) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __rl_compat_quick_exit(status: c_int) -> ! {
    rusty_libc_core::tls::run_thread_dtors();
    rusty_libc_stdlib::misc::quick_exit(status)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_cfgetospeed(t: *const rusty_libc_sys::termios::termios) -> u32 {
    unsafe { rusty_libc_sys::termios::cfgetospeed_old(t) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_cfgetispeed(t: *const rusty_libc_sys::termios::termios) -> u32 {
    unsafe { rusty_libc_sys::termios::cfgetispeed_old(t) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_cfsetospeed(t: *mut rusty_libc_sys::termios::termios, speed: u32) -> c_int {
    unsafe { rusty_libc_sys::termios::cfsetospeed_old(t, speed) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_cfsetispeed(t: *mut rusty_libc_sys::termios::termios, speed: u32) -> c_int {
    unsafe { rusty_libc_sys::termios::cfsetispeed_old(t, speed) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_cfsetspeed(t: *mut rusty_libc_sys::termios::termios, speed: u32) -> c_int {
    unsafe { rusty_libc_sys::termios::cfsetspeed_old(t, speed) }
}

const OLD_TIMER_MAX: usize = 256;
#[allow(clippy::declare_interior_mutable_const)]
const NO_TIMER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static TIMER_COMPAT_LIST: [AtomicPtr<c_void>; OLD_TIMER_MAX] = [NO_TIMER; OLD_TIMER_MAX];

fn old_timer(id: c_int) -> rusty_libc_time::clock::TimerId {
    TIMER_COMPAT_LIST.get(id as usize).map_or(core::ptr::null_mut(), |s| s.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_timer_create(clock: rusty_libc_time::clock::ClockId, evp: *mut rusty_libc_time::clock::Sigevent, timerid: *mut c_int) -> c_int {
    unsafe {
        let mut newp: rusty_libc_time::clock::TimerId = core::ptr::null_mut();
        let res = rusty_libc_time::clock::timer_create(clock, evp, &mut newp);
        if res != 0 {
            return res;
        }
        for (i, slot) in TIMER_COMPAT_LIST.iter().enumerate() {
            if slot.compare_exchange(core::ptr::null_mut(), newp, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                *timerid = i as c_int;
                return 0;
            }
        }
        rusty_libc_time::clock::timer_delete(newp);
        errno::set(EINVAL);
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_timer_delete(timerid: c_int) -> c_int {
    unsafe {
        let res = rusty_libc_time::clock::timer_delete(old_timer(timerid));
        if res == 0
            && let Some(s) = TIMER_COMPAT_LIST.get(timerid as usize)
        {
            s.store(core::ptr::null_mut(), Ordering::Release);
        }
        res
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_timer_settime(timerid: c_int, flags: c_int, value: *const rusty_libc_time::clock::Itimerspec, ovalue: *mut rusty_libc_time::clock::Itimerspec) -> c_int {
    unsafe { rusty_libc_time::clock::timer_settime(old_timer(timerid), flags, value, ovalue) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_timer_gettime(timerid: c_int, value: *mut rusty_libc_time::clock::Itimerspec) -> c_int {
    unsafe { rusty_libc_time::clock::timer_gettime(old_timer(timerid), value) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_timer_getoverrun(timerid: c_int) -> c_int {
    unsafe { rusty_libc_time::clock::timer_getoverrun(old_timer(timerid)) }
}

#[repr(C)]
pub struct OldCond {
    cond: AtomicPtr<rusty_libc_pthread::cond::Cond>,
}

unsafe fn real_cond(old: *mut OldCond) -> Result<*mut rusty_libc_pthread::cond::Cond, c_int> {
    unsafe {
        let cur = (*old).cond.load(Ordering::Acquire);
        if !cur.is_null() {
            return Ok(cur);
        }
        let newcond = rusty_libc_malloc::calloc(core::mem::size_of::<rusty_libc_pthread::cond::Cond>(), 1) as *mut rusty_libc_pthread::cond::Cond;
        if newcond.is_null() {
            return Err(ENOMEM);
        }
        match (*old).cond.compare_exchange(core::ptr::null_mut(), newcond, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(newcond),
            Err(other) => {
                rusty_libc_malloc::free(newcond.cast());
                Ok(other)
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_init(cond: *mut OldCond, attr: *const rusty_libc_pthread::cond::CondAttr) -> c_int {
    unsafe {
        (*cond).cond.store(core::ptr::null_mut(), Ordering::Release);
        if !attr.is_null() && (*attr).value != 0 {
            return EINVAL;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_destroy(cond: *mut OldCond) -> c_int {
    unsafe {
        rusty_libc_malloc::free((*cond).cond.load(Ordering::Acquire).cast());
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_wait(cond: *mut OldCond, mutex: *mut rusty_libc_pthread::mutex::Mutex) -> c_int {
    unsafe {
        match real_cond(cond) {
            Ok(c) => rusty_libc_pthread::pthread_cond_wait(c, mutex),
            Err(e) => e,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_timedwait(cond: *mut OldCond, mutex: *mut rusty_libc_pthread::mutex::Mutex, abstime: *const rusty_libc_pthread::Timespec) -> c_int {
    unsafe {
        match real_cond(cond) {
            Ok(c) => rusty_libc_pthread::pthread_cond_timedwait(c, mutex, abstime),
            Err(e) => e,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_signal(cond: *mut OldCond) -> c_int {
    unsafe {
        match real_cond(cond) {
            Ok(c) => rusty_libc_pthread::pthread_cond_signal(c),
            Err(e) => e,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_pthread_cond_broadcast(cond: *mut OldCond) -> c_int {
    unsafe {
        match real_cond(cond) {
            Ok(c) => rusty_libc_pthread::pthread_cond_broadcast(c),
            Err(e) => e,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_glob(pattern: *const c_char, flags: c_int, errfunc: Option<rusty_libc_util::glob::ErrFn>, pglob: *mut rusty_libc_util::glob::Glob) -> c_int {
    unsafe { rusty_libc_util::glob::glob_compat(pattern, flags, errfunc, pglob) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_fmemopen(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut rusty_libc_stdio::file::File {
    unsafe { rusty_libc_stdio::file_extra::fmemopen_old(buf, len, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const rusty_libc_extra::spawn::PosixSpawnFileActions,
    attrp: *const rusty_libc_extra::spawn::PosixSpawnattr,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { rusty_libc_extra::spawn::posix_spawn_compat(pid, path, file_actions, attrp, argv, envp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const rusty_libc_extra::spawn::PosixSpawnFileActions,
    attrp: *const rusty_libc_extra::spawn::PosixSpawnattr,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { rusty_libc_extra::spawn::posix_spawnp_compat(pid, file, file_actions, attrp, argv, envp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_lio_listio(mode: c_int, list: *const *mut rusty_libc_ipc::aio::Aiocb, nent: c_int, sig: *mut rusty_libc_ipc::notify::SigEvent) -> c_int {
    unsafe { rusty_libc_ipc::aio::lio_listio_old(mode, list, nent, sig) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_compat_lio_listio64(mode: c_int, list: *const *mut rusty_libc_ipc::aio::Aiocb64, nent: c_int, sig: *mut rusty_libc_ipc::notify::SigEvent) -> c_int {
    unsafe { rusty_libc_ipc::aio::lio_listio_old(mode, list as *const *mut rusty_libc_ipc::aio::Aiocb, nent, sig) }
}

#[cfg(feature = "shared")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stime(when: *const i64) -> c_int {
    unsafe { rusty_libc_time::clock::stime(when) }
}
