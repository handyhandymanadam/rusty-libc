//! The per-stream recursive lock (glibc's `_IO_lock_t`) and the helpers every stdio entry point uses.
//!
//! Layout: a futex mutex (`rusty_libc_core::lock::RawMutex`), the owner (the thread pointer, `%fs:0`: unique
//! for every live thread, the same in a forked child, and valid on the host in unit tests) and a
//! recursion count that only the owner touches.
//!
//! Single-thread fast path: an exported function runs its body through `locked`, which costs one
//! load of `%fs:0x18` and a branch while the process has one thread, and takes no lock. Exceptions
//! that always take a real lock: `flockfile`/`ftrylockfile` (so a lock taken before the first
//! `pthread_create` still protects the stream afterwards), the fork handlers and fclose's drain.
//! A stream whose owner turned on `__fsetlocking(BYCALLER)` is never locked implicitly.
//!
//! Lock order: a stream lock may be taken while holding another stream lock only by the fork handler
//! (with a time bound); the open-list lock (`file::LIST`) is a leaf: nothing blocking is ever acquired
//! while it is held.
use crate::file::File;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use rusty_libc_core::cleanup::CleanupBuf;
use core::sync::atomic::{AtomicUsize, Ordering};
use rusty_libc_core::lock::{RawMutex, multithreaded};

pub struct FLock {
    m: RawMutex,
    owner: AtomicUsize,
    count: UnsafeCell<u32>,
}

// SAFETY: `count` is only touched by the thread named in `owner`, which holds `m`.
unsafe impl Sync for FLock {}

impl Default for FLock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(all(test, miri)))]
#[inline(always)]
fn me() -> usize {
    rusty_libc_core::tls::current() as usize
}

/// Under Miri (no inline assembly): an address unique to the thread, as `%fs:0` is.
#[cfg(all(test, miri))]
fn me() -> usize {
    std::thread_local!(static ME: u8 = const { 0 });
    ME.with(|m| m as *const u8 as usize)
}

impl FLock {
    pub const fn new() -> FLock {
        FLock { m: RawMutex::new(), owner: AtomicUsize::new(0), count: UnsafeCell::new(0) }
    }

    /// Take the lock for sure (recursive).
    #[inline]
    pub fn lock(&self) {
        let me = me();
        if self.owner.load(Ordering::Relaxed) == me {
            // SAFETY: we are the owner.
            unsafe { *self.count.get() += 1 };
            return;
        }
        // one thread: a free lock is taken by two plain stores (no compare-and-swap, no call)
        // SAFETY: a stream lock is process-private; `multithreaded()` is false.
        if !multithreaded() && unsafe { self.m.take_single_thread() } {
            self.owner.store(me, Ordering::Relaxed);
            // SAFETY: we hold the mutex.
            unsafe { *self.count.get() = 1 };
            return;
        }
        self.lock_first(me);
    }

    /// The lock is not ours yet: take the mutex (out of line, so the recursive path above needs no saved registers).
    #[inline(never)]
    fn lock_first(&self, me: usize) {
        self.m.lock_fast();
        self.owner.store(me, Ordering::Relaxed);
        // SAFETY: we hold the mutex.
        unsafe { *self.count.get() = 1 };
    }

    /// Take the lock if it is free or ours; false if another thread holds it.
    #[inline]
    pub fn try_lock(&self) -> bool {
        let me = me();
        if self.owner.load(Ordering::Relaxed) == me {
            // SAFETY: we are the owner.
            unsafe { *self.count.get() += 1 };
            return true;
        }
        if !self.m.try_lock_fast() {
            return false;
        }
        self.owner.store(me, Ordering::Relaxed);
        // SAFETY: we hold the mutex.
        unsafe { *self.count.get() = 1 };
        true
    }

    /// `try_lock`, then keep trying (sleeping on the lock word in slices of 1 ms) until about `cycles` TSC cycles passed.
    pub fn lock_timeout(&self, cycles: u64) -> bool {
        if self.try_lock() {
            return true;
        }
        // SAFETY: rdtsc has no preconditions.
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        loop {
            self.m.wait_held(1_000_000);
            if self.try_lock() {
                return true;
            }
            // SAFETY: as above.
            if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) > cycles {
                return false;
            }
        }
    }

    /// Release one level. A call from a thread that does not own the lock does nothing (a stray
    /// `funlockfile`); returns whether a level was released.
    #[inline]
    pub fn unlock(&self) -> bool {
        if self.owner.load(Ordering::Relaxed) != me() {
            return false;
        }
        // SAFETY: we are the owner: only this thread touches `count`.
        let c = unsafe { *self.count.get() } - 1;
        // SAFETY: as above.
        unsafe { *self.count.get() = c };
        if c == 0 {
            self.owner.store(0, Ordering::Relaxed);
            self.m.unlock_fast();
        }
        true
    }

    /// True if the calling thread holds the lock.
    pub fn held_by_me(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == me()
    }

    /// Forget every holder (a forked child whose lock was owned by a thread that no longer exists).
    ///
    /// # Safety
    /// Only when no other thread can be using the lock.
    pub unsafe fn reset(&self) {
        // SAFETY: caller's promise: no other thread uses the lock; the mutex is a single atomic word (interior mutable), so
        // storing a fresh one through the shared reference is a plain store into an `UnsafeCell`.
        unsafe { core::ptr::write(&self.m as *const RawMutex as *mut RawMutex, RawMutex::new()) };
        // SAFETY: as above: nobody else touches `count`.
        unsafe { *self.count.get() = 0 };
        self.owner.store(0, Ordering::Relaxed);
    }
}

/// `locked!(f, move || body)`: run `body` with the stream `f` locked. Nothing is taken while the
/// process has a single thread (or the stream is in caller-locked mode); the lock taken is the lock
/// released. A macro rather than a function so the single-thread path is exactly one load of
/// `%fs:0x18`, a branch and `body` (no closure is built, nothing spilled to the stack); the locking
/// path builds the closure and calls `locked_mt`, a cold function that is not inlined.
/// Must be used inside an `unsafe` block.
///
/// `locked!(f, |s| body)`: the same, with `s: &mut File` made from `f` once the lock is held (the thin-shell form: the
/// exported function's body is safe code on the reference). Only for a pointer that the calling function's own contract
/// promises is an open stream (its `# Safety` section); every use is in an exported `unsafe extern "C"` function.
macro_rules! locked {
    ($f:expr, move || $body:expr) => {{
        let stream: *mut $crate::file::File = $f;
        if !rusty_libc_core::lock::multithreaded() { $body } else { $crate::flock::locked_mt(stream, move || $body) }
    }};
    ($f:expr, |$s:ident| $body:expr) => {{
        let stream: *mut $crate::file::File = $f;
        if !rusty_libc_core::lock::multithreaded() {
            // SAFETY: the calling function's contract: `stream` is an open stream; one thread, so no other thread uses it.
            let $s = unsafe { $crate::file::stream(stream) };
            $body
        } else {
            let op = move || {
                // SAFETY: as above; `locked_mt` holds the stream's lock (or the caller locks) while this runs.
                let $s = unsafe { $crate::file::stream(stream) };
                $body
            };
            // SAFETY: the calling function's contract: `stream` is an open stream.
            unsafe { $crate::flock::locked_mt(stream, op) }
        }
    }};
}
pub(crate) use locked;

/// The handler that releases a stream lock when a thread is cancelled (or calls `pthread_exit`) inside a
/// stdio call: glibc's `_IO_acquire_lock` does the same with a cleanup attribute and the unwinder.
/// Without it the stream stays locked for ever and every other thread that uses it hangs.
unsafe extern "C" fn unlock_on_cancel(arg: *mut c_void) {
    // SAFETY: `arg` is the stream the registering function holds locked (a reference to its lock only).
    unsafe { crate::file::lock_of(arg.cast()) }.unlock();
}

/// A cancellation-cleanup registration for a stream lock taken by the library itself: `arm` after taking
/// the lock, `disarm` before releasing it (dropping a still armed value disarms it). The value must stay
/// where it is between `arm` and `disarm`.
pub struct LockCleanup {
    buf: MaybeUninit<CleanupBuf>,
    armed: bool,
}

impl LockCleanup {
    #[inline(always)]
    pub const fn idle() -> LockCleanup {
        LockCleanup { buf: MaybeUninit::uninit(), armed: false }
    }

    /// Register the release of `f`'s lock (one level) as the thread's innermost cancellation handler.
    ///
    /// # Safety
    /// `f` is valid and locked by this thread; `self` does not move until `disarm`.
    #[inline(always)]
    pub unsafe fn arm(&mut self, f: *mut File) {
        // SAFETY: caller's promise.
        unsafe { rusty_libc_core::cleanup::push(self.buf.as_mut_ptr(), unlock_on_cancel, f.cast()) };
        self.armed = true;
    }

    #[inline(always)]
    pub fn disarm(&mut self) {
        if self.armed {
            // SAFETY: armed by this thread, innermost.
            unsafe { rusty_libc_core::cleanup::pop(self.buf.as_mut_ptr()) };
            self.armed = false;
        }
    }
}

impl Drop for LockCleanup {
    #[inline(always)]
    fn drop(&mut self) {
        self.disarm();
    }
}

/// The locking half of `locked!`.
///
/// # Safety
/// `f` must point to a valid stream.
#[inline(never)]
#[cold]
pub unsafe fn locked_mt<R, F: FnOnce() -> R>(f: *mut File, op: F) -> R {
    // SAFETY: caller's promise: a valid stream (its `Shared` part: other threads use it at the same time, by design).
    let sh = unsafe { crate::file::shared_of(f) };
    let real = !sh.nolock.load(Ordering::Relaxed);
    let l = &sh.lock;
    let mut cg = LockCleanup::idle();
    if real {
        l.lock();
        // SAFETY: we hold the lock; `cg` stays here until it is disarmed.
        unsafe { cg.arm(f) };
    }
    let r = op();
    if real {
        cg.disarm();
        l.unlock();
    }
    r
}

/// Lock for a manual critical section: returns a token for `unlock_file` (true if a lock was taken).
///
/// # Safety
/// `f` must point to a valid stream.
#[inline(always)]
pub unsafe fn lock_file(f: *mut File) -> bool {
    if !multithreaded() {
        return false;
    }
    // SAFETY: caller's promise: a valid stream (its `Shared` part only).
    let sh = unsafe { crate::file::shared_of(f) };
    if sh.nolock.load(Ordering::Relaxed) {
        return false;
    }
    sh.lock.lock();
    true
}

/// Release what `lock_file` returned the token for.
///
/// # Safety
/// `f` must point to a valid stream.
#[inline(always)]
pub unsafe fn unlock_file(f: *mut File, token: bool) {
    if token {
        // SAFETY: caller's promise; a reference to the lock only.
        unsafe { crate::file::lock_of(f) }.unlock();
    }
}

/// A scope guard over `lock_file`; the lock is also released if the thread is cancelled while the guard
/// is alive. Create it with `idle()` and take the lock with `lock` once it sits in its final place:
/// `let mut g = StreamGuard::idle(); unsafe { g.lock(f) };`.
pub struct StreamGuard {
    f: *mut File,
    token: bool,
    cleanup: LockCleanup,
}

impl StreamGuard {
    #[inline(always)]
    pub const fn idle() -> StreamGuard {
        StreamGuard { f: core::ptr::null_mut(), token: false, cleanup: LockCleanup::idle() }
    }

    /// # Safety
    /// `f` must point to a valid stream that outlives the guard; the guard must not move afterwards.
    #[inline(always)]
    pub unsafe fn lock(&mut self, f: *mut File) {
        self.f = f;
        // SAFETY: caller's promise.
        self.token = unsafe { lock_file(f) };
        if self.token {
            // SAFETY: we hold the lock; the guard (and its cleanup record) does not move afterwards (caller's promise).
            unsafe { self.cleanup.arm(f) };
        }
    }
}

impl Drop for StreamGuard {
    #[inline(always)]
    fn drop(&mut self) {
        self.cleanup.disarm();
        // SAFETY: `lock`'s promise.
        unsafe { unlock_file(self.f, self.token) };
    }
}
