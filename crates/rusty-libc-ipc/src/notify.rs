//! Completion notification shared by mq_notify and POSIX AIO: `struct sigevent`, starting a detached
//! helper thread (with every signal blocked while it is created, so it never sees a signal), and
//! the thread-creation seam that host unit tests replace (a test process has no thread descriptor of
//! ours behind %fs, so there the host's pthread_create is used).
use core::ffi::{c_int, c_void};

pub const SIGEV_SIGNAL: c_int = 0;
pub const SIGEV_NONE: c_int = 1;
pub const SIGEV_THREAD: c_int = 2;
pub const SIGEV_THREAD_ID: c_int = 4;

/// `union sigval`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SigVal {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

/// `struct sigevent` (64 bytes). The union at offset 16 holds the thread function and attributes for
/// SIGEV_THREAD (`_sigev_thread`) or the thread id for SIGEV_THREAD_ID.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigEvent {
    pub sigev_value: SigVal,
    pub sigev_signo: c_int,
    pub sigev_notify: c_int,
    pub sigev_notify_function: Option<unsafe extern "C" fn(SigVal)>,
    pub sigev_notify_attributes: *mut c_void,
    pub pad: [c_int; 8],
}

impl SigEvent {
    pub const fn none() -> SigEvent {
        SigEvent {
            sigev_value: SigVal { sival_ptr: core::ptr::null_mut() },
            sigev_signo: 0,
            sigev_notify: SIGEV_NONE,
            sigev_notify_function: None,
            sigev_notify_attributes: core::ptr::null_mut(),
            pad: [0; 8],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<SigEvent>() == 64);
    assert!(core::mem::offset_of!(SigEvent, sigev_signo) == 8);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify) == 12);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify_function) == 16);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify_attributes) == 24);
};

pub type ThreadFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// Size of glibc's `pthread_attr_t`.
pub const ATTR_SIZE: usize = 56;

/// Block every signal in the calling thread; returns the old mask. (The kernel's rt_sigprocmask works
/// on the raw 64-bit mask; the internal cancellation and set-id signals are included on purpose: the
/// thread being created must not see them before it is set up, the mask is restored right after.)
fn block_all() -> u64 {
    crate::kernel::sigprocmask(0, u64::MAX, true)
}

fn restore_mask(old: u64) {
    crate::kernel::sigprocmask(2, old, false);
}

/// Run `f` with all signals blocked (the thread created inside inherits the empty-of-signals mask).
pub fn with_signals_blocked<R>(f: impl FnOnce() -> R) -> R {
    let old = block_all();
    let r = f();
    restore_mask(old);
    r
}

/// Unblock every signal in the calling thread (what a notification thread does first).
pub fn unblock_all() {
    crate::kernel::sigprocmask(2, 0, false);
}

/// Create a thread running `f(arg)`. `attr` is a `pthread_attr_t` (or null). With `attr` null the
/// thread is created detached with a `stack` byte stack (0 = default). Returns 0 or an error number.
///
/// # Safety
/// `attr` is null or an initialised attribute object.
pub unsafe fn spawn(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize) -> c_int {
    let mut tid = 0;
    // SAFETY: forwarded contract.
    unsafe { spawn_tid(f, arg, attr, stack, &mut tid) }
}

/// As `spawn`, and store the new thread's kernel thread id (from its descriptor) in `*tid`.
///
/// # Safety
/// As `spawn`.
#[cfg(not(test))]
pub unsafe fn spawn_tid(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize, tid: &mut c_int) -> c_int {
    use rusty_libc_pthread::attr::*;
    use rusty_libc_pthread::thread::{pthread_create, pthread_gettid_np};
    let mut th: rusty_libc_pthread::PthreadT = 0;
    let r = if !attr.is_null() {
        // SAFETY: `attr` is an initialised attribute object (the caller's contract); `th` is a local.
        unsafe { pthread_create(&mut th, attr.cast::<PthreadAttr>(), f, arg) }
    } else {
        let mut a = core::mem::MaybeUninit::<PthreadAttr>::uninit();
        // SAFETY: pthread_attr_init initialises the local attribute object.
        unsafe { pthread_attr_init(a.as_mut_ptr()) };
        // SAFETY: `a` was initialised above.
        unsafe { pthread_attr_setdetachstate(a.as_mut_ptr(), 1) };
        if stack != 0 {
            // SAFETY: as above.
            unsafe { pthread_attr_setstacksize(a.as_mut_ptr(), stack) };
        }
        // SAFETY: `a` is initialised; `th` is a local.
        let r = unsafe { pthread_create(&mut th, a.as_ptr(), f, arg) };
        // SAFETY: `a` is initialised and not used again.
        unsafe { pthread_attr_destroy(a.as_mut_ptr()) };
        r
    };
    if r == 0 {
        // SAFETY: `th` is the thread just created; its descriptor stays valid at least until it exits, and the kernel id is
        // stored in it before pthread_create returns.
        *tid = unsafe { pthread_gettid_np(th) };
    }
    r
}

/// Host unit tests: the host's pthread_create (a test process has no thread descriptor of ours behind %fs).
///
/// # Safety
/// As `spawn`.
#[cfg(test)]
pub unsafe fn spawn_tid(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize, tid: &mut c_int) -> c_int {
    let mut th: libc::pthread_t = 0;
    // SAFETY: the same function type; only the `unsafe` qualifier differs (C has none).
    let start = unsafe { core::mem::transmute::<ThreadFn, extern "C" fn(*mut c_void) -> *mut c_void>(f) };
    let r = if !attr.is_null() {
        // SAFETY: `attr` is an initialised attribute object (the caller's contract).
        unsafe { libc::pthread_create(&mut th, attr.cast::<libc::pthread_attr_t>(), start, arg) }
    } else {
        // SAFETY: an all-zero pthread_attr_t is a valid value to hand to pthread_attr_init.
        let mut a: libc::pthread_attr_t = unsafe { core::mem::zeroed() };
        // SAFETY: a local attribute object.
        unsafe { libc::pthread_attr_init(&mut a) };
        // SAFETY: initialised above.
        unsafe { libc::pthread_attr_setdetachstate(&mut a, libc::PTHREAD_CREATE_DETACHED) };
        if stack != 0 {
            // SAFETY: initialised above.
            unsafe { libc::pthread_attr_setstacksize(&mut a, stack.max(64 * 1024)) };
        }
        // SAFETY: initialised above.
        let r = unsafe { libc::pthread_create(&mut th, &a, start, arg) };
        // SAFETY: initialised above, not used again.
        unsafe { libc::pthread_attr_destroy(&mut a) };
        r
    };
    if r == 0 {
        // glibc's struct pthread keeps the thread id at 0x2d0 (set by clone before pthread_create returns)
        // SAFETY: `th` is the host glibc's thread descriptor of the thread just created.
        *tid = unsafe { *((th as usize + 0x2d0) as *const c_int) };
    }
    r
}

/// Make a detached copy of a thread attribute object on the heap (SIGEV_THREAD attributes outlive the
/// caller's). Null in, null out. Returns Err(errno).
///
/// # Safety
/// `src` is null or an initialised attribute.
#[cfg(not(test))]
pub unsafe fn attr_clone(src: *const c_void) -> Result<*mut c_void, c_int> {
    use rusty_libc_pthread::attr::{PthreadAttr, attr_copy};
    if src.is_null() {
        return Ok(core::ptr::null_mut());
    }
    let p = crate::util::malloc(ATTR_SIZE).cast::<PthreadAttr>();
    if p.is_null() {
        return Err(12);
    }
    // SAFETY: `p` has room for an attribute object; `src` is an initialised one (the caller's contract).
    let r = unsafe { attr_copy(p, src.cast::<PthreadAttr>()) };
    if r != 0 {
        // SAFETY: our own block from malloc above.
        unsafe { rusty_libc_malloc::free(p.cast()) };
        return Err(r);
    }
    Ok(p.cast())
}

/// Host unit tests: a byte copy.
///
/// # Safety
/// As the library version.
#[cfg(test)]
pub unsafe fn attr_clone(src: *const c_void) -> Result<*mut c_void, c_int> {
    if src.is_null() {
        return Ok(core::ptr::null_mut());
    }
    let p = crate::util::malloc(ATTR_SIZE).cast::<u8>();
    if p.is_null() {
        return Err(12);
    }
    // SAFETY: `src` is an attribute object (ATTR_SIZE bytes); `p` is a fresh block of that size.
    unsafe { core::ptr::copy_nonoverlapping(src.cast::<u8>(), p, ATTR_SIZE) };
    Ok(p.cast())
}

/// Destroy and free an attribute made by [`attr_clone`].
///
/// # Safety
/// `p` came from `attr_clone` and is not used again.
#[cfg(not(test))]
pub unsafe fn attr_free(p: *mut c_void) {
    if !p.is_null() {
        // SAFETY: an attribute object initialised by attr_clone (the caller's contract).
        unsafe { rusty_libc_pthread::attr::pthread_attr_destroy(p.cast()) };
        // SAFETY: the block came from malloc in attr_clone and is not used again.
        unsafe { rusty_libc_malloc::free(p) };
    }
}

/// Host unit tests: free the byte copy.
///
/// # Safety
/// As the library version.
#[cfg(test)]
pub unsafe fn attr_free(p: *mut c_void) {
    if !p.is_null() {
        // SAFETY: the block came from malloc in attr_clone and is not used again.
        unsafe { rusty_libc_malloc::free(p) };
    }
}

/// Detach the calling thread.
#[cfg(not(test))]
pub fn detach_self() {
    // SAFETY: pthread_self is the calling thread, which is alive.
    unsafe { rusty_libc_pthread::thread::pthread_detach(rusty_libc_pthread::thread::pthread_self()) };
}

#[cfg(test)]
pub fn detach_self() {
    // SAFETY: no preconditions.
    let me = unsafe { libc::pthread_self() };
    // SAFETY: the calling thread, which is alive.
    unsafe { libc::pthread_detach(me) };
}
