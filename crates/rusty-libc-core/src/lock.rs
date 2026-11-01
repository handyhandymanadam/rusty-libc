//! A tiny futex lock for the runtime's own data (malloc, stdio, registries).
//!
//! Single-thread fast path: while the process has only one thread (`Tcb.multiple_threads == 0`,
//! which rusty-libc-pthread sets before it creates the second thread) `lock` takes nothing and costs one
//! load and a branch. `lock` returns a token that says whether a real lock was taken, and `unlock`
//! takes the token back, so a lock "taken" in single-thread mode is never released as a real one
//! even if a thread was created in between. Not recursive, not fair, not async-signal-safe against
//! its own holder.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::syscall::syscall4;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

const SYS_FUTEX: usize = 202;
const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;

/// glibc's `__libc_single_threaded`: 1 until the first thread is created (libstdc++ and Rust's std read
/// it to skip atomics); rusty-libc-pthread clears it with `note_multithreaded`. An `AtomicU8`: the same one byte of
/// `.data` as the C `char` programs read, written here with plain (relaxed) byte stores.
#[cfg_attr(feature = "export-mem", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static __libc_single_threaded: AtomicU8 = AtomicU8::new(1);

/// glibc's `__libc_early_init` (GLIBC_PRIVATE): the loader calls it once for each copy of libc.so.6 it maps after relocating it and
/// before its constructors run, with `initial` true for the copy of the base namespace and false for the copies of the other
/// `dlmopen` namespaces. A copy that is not the initial one reports "multi-threaded" from the start: threads the program (or
/// another namespace) creates are not known to it, so its single-thread fast paths would be wrong.
#[cfg_attr(feature = "export-mem", unsafe(no_mangle))]
pub extern "C" fn __libc_early_init(initial: bool) {
    __libc_single_threaded.store(initial as u8, Ordering::Relaxed);
    LIBC_INITIAL.store(initial as u8, Ordering::Relaxed);
}

/// glibc's `__libc_initial`: 1 in the libc.so.6 of the base namespace (and in a static program), 0 in the copy of any other
/// `dlmopen` namespace. Only the initial copy owns the process's program break (see `rusty-libc-malloc`).
static LIBC_INITIAL: AtomicU8 = AtomicU8::new(1);

/// Is this copy of libc the initial one (see `__libc_early_init`)?
pub fn libc_initial() -> bool {
    LIBC_INITIAL.load(Ordering::Relaxed) != 0
}

/// `AT_SECURE` from the auxiliary vector (glibc's `__libc_enable_secure`): 0 or 1, 2 while the startup code has not recorded it
/// (a Rust test binary).
static AT_SECURE: AtomicU8 = AtomicU8::new(2);

/// Record the kernel's `AT_SECURE` flag (the startup code does this from the auxiliary vector).
pub fn set_at_secure(v: bool) {
    AT_SECURE.store(v as u8, Ordering::Relaxed);
}

/// glibc's `__libc_enable_secure` as a bool: the kernel's `AT_SECURE`; before the startup code recorded it (Rust test
/// binaries), whether the real and effective user or group ids differ. No system call once the startup code ran (glibc
/// makes none for this: a seccomp allowlist made from its calls may lack getuid/geteuid).
pub fn secure() -> bool {
    at_secure().unwrap_or_else(|| {
        // the four id calls as before (getuid, geteuid, getgid, getegid: no arguments, cannot fail)
        let id = |nr: usize| {
            // SAFETY: `nr` is one of the four id calls above, which take no arguments (the zeros are ignored).
            unsafe { syscall4(nr, 0, 0, 0, 0) }
        };
        id(102) != id(107) || id(104) != id(108)
    })
}

/// Was the program started set-user-ID/set-group-ID (or with raised capabilities), per the kernel's `AT_SECURE`?
/// `None` before the startup code recorded it.
pub fn at_secure() -> Option<bool> {
    match AT_SECURE.load(Ordering::Relaxed) {
        2 => None,
        v => Some(v != 0),
    }
}

/// Record that a second thread is about to exist.
pub fn note_multithreaded() {
    __libc_single_threaded.store(0, Ordering::Relaxed);
}

/// True once the process has more than one thread (or ever had).
#[cfg(not(miri))]
#[inline(always)]
pub fn multithreaded() -> bool {
    // One load straight from the thread control block (`multiple_threads` is at %fs:0x18, where
    // glibc keeps its own flag too): no pointer to chase first.
    let v: i32;
    // SAFETY: a 4-byte read of the TCB's `multiple_threads` field (offset asserted in tls.rs); the thread pointer is set
    // up by `tls::init_main`, the loader or thread creation before any code that can take a lock runs.
    unsafe { core::arch::asm!("mov {0:e}, fs:[0x18]", out(reg) v, options(nostack, readonly, preserves_flags)) };
    v != 0
}

/// Under Miri (no inline assembly, no thread control block): always the multithreaded paths (the unit tests that Miri runs
/// model several threads).
#[cfg(miri)]
pub fn multithreaded() -> bool {
    true
}

/// Wait on a futex word while it holds `expected` (private futex, no timeout). Returns on wake-up,
/// value mismatch or signal; the caller re-checks.
#[inline]
pub fn futex_wait(word: &AtomicU32, expected: u32) {
    // SAFETY: the kernel only reads the 4-byte word (a live `&AtomicU32`, accessed atomically); no timeout pointer.
    unsafe { syscall4(SYS_FUTEX, word as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, expected as usize, 0) };
}

/// Wait on a futex word while it holds `expected`, at most `ns` nanoseconds (private futex). For a waiter that polls a
/// condition nobody signals (instead of sched_yield, which a seccomp allowlist made from glibc's calls may lack).
#[inline]
pub fn futex_wait_timeout(word: &AtomicU32, expected: u32, ns: u64) {
    let ts = [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64];
    // SAFETY: the kernel reads the word (a live `&AtomicU32`) and the local timespec `ts`.
    unsafe { syscall4(SYS_FUTEX, word as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, expected as usize, ts.as_ptr() as usize) };
}

/// Wake up to `n` waiters of a private futex word.
#[inline]
pub fn futex_wake(word: &AtomicU32, n: u32) {
    // SAFETY: FUTEX_WAKE uses the word's address only as a key; plain values otherwise.
    unsafe { syscall4(SYS_FUTEX, word as *const AtomicU32 as usize, FUTEX_WAKE_PRIVATE, n as usize, 0) };
}

/// Take a free futex word (0 -> 1) that only this process can touch while it has a single thread (`multithreaded()` false,
/// private futex): a plain load and a plain store, no read-modify-write. glibc's mutex lock does the same for private mutexes while
/// single-threaded (`lll_mutex_lock_optimized`). A signal handler that runs between the two and takes and releases the lock leaves
/// it free again, so the store is still right. Returns true if it took the word, false (nothing changed) if it was held.
///
/// # Safety
/// `w` must be private to this process and the process must never have had a second thread.
#[inline(always)]
pub unsafe fn take01_single_thread(w: &AtomicU32) -> bool {
    if w.load(Ordering::Relaxed) != 0 {
        return false;
    }
    w.store(1, Ordering::Relaxed);
    true
}

/// Store 0 into a futex word that the single-thread rule above allows to be released without an exchange; returns the old value.
///
/// # Safety
/// As `take01_single_thread`.
#[inline(always)]
pub unsafe fn release_single_thread(w: &AtomicU32) -> u32 {
    let s = w.load(Ordering::Relaxed);
    w.store(0, Ordering::Release);
    s
}

/// The raw lock: 0 unlocked, 1 locked, 2 locked with possible waiters (one futex word: it can sit in C-visible structs).
#[repr(transparent)]
pub struct RawMutex {
    state: AtomicU32,
}

impl Default for RawMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl RawMutex {
    pub const fn new() -> RawMutex {
        RawMutex { state: AtomicU32::new(0) }
    }

    /// Take the lock for sure (also in single-thread mode).
    #[inline]
    pub fn lock_always(&self) {
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            self.lock_slow();
        }
    }

    #[cold]
    fn lock_slow(&self) {
        let mut spins = 0;
        // short spin before sleeping: the critical sections here are tiny
        while spins < 50 {
            if self.state.load(Ordering::Relaxed) == 0 && self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                return;
            }
            core::hint::spin_loop();
            spins += 1;
        }
        while self.state.swap(2, Ordering::Acquire) != 0 {
            futex_wait(&self.state, 2);
        }
    }

    /// Sleep while the lock is held, at most `ns` nanoseconds (a timed futex wait on its word; nothing is taken or
    /// marked). For a caller that polls with a deadline instead of sched_yield (a seccomp allowlist made from glibc's
    /// calls has futex and maybe no sched_yield).
    pub fn wait_held(&self, ns: u64) {
        let v = self.state.load(Ordering::Relaxed);
        if v != 0 {
            let ts = [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64];
            // SAFETY: the kernel reads our own lock word and the local timespec `ts`.
            let r = unsafe { syscall4(SYS_FUTEX, &self.state as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, v as usize, ts.as_ptr() as usize) };
            if r == 0 {
                // woken by an unlock: that wake-up was meant for a thread sleeping in `lock_slow`; pass it on, or that thread
                // could sleep for ever once someone takes the lock without marking it contended
                futex_wake(&self.state, 1);
            }
        }
    }

    /// Try to take the lock for sure.
    #[inline]
    pub fn try_lock_always(&self) -> bool {
        self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Release a lock taken with `lock_always`.
    #[inline]
    pub fn unlock_always(&self) {
        if self.state.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.state, 1);
        }
    }

    /// `lock_always`, but while the process has only ever had one thread a free lock is taken by a plain load and store
    /// (see `take01_single_thread`). Release with `unlock_fast`.
    #[inline(always)]
    pub fn lock_fast(&self) {
        // SAFETY: a RawMutex is process-private.
        if !multithreaded() && unsafe { take01_single_thread(&self.state) } {
            return;
        }
        self.lock_always();
    }

    /// `take01_single_thread` on this lock.
    ///
    /// # Safety
    /// As `take01_single_thread`: the lock is private and the process has never had a second thread (`multithreaded()` false).
    #[inline(always)]
    pub unsafe fn take_single_thread(&self) -> bool {
        // SAFETY: forwarded contract.
        unsafe { take01_single_thread(&self.state) }
    }

    /// `try_lock_always` with the single-thread form of `lock_fast`.
    #[inline(always)]
    pub fn try_lock_fast(&self) -> bool {
        if !multithreaded() {
            // SAFETY: as in `lock_fast`.
            return unsafe { take01_single_thread(&self.state) };
        }
        self.try_lock_always()
    }

    /// Release a lock taken with `lock_fast` or `try_lock_fast`: a plain store instead of an exchange while single-threaded.
    #[inline(always)]
    pub fn unlock_fast(&self) {
        if !multithreaded() {
            // SAFETY: as in `lock_fast`.
            if unsafe { release_single_thread(&self.state) } == 2 {
                futex_wake(&self.state, 1);
            }
            return;
        }
        self.unlock_always();
    }

    /// Take the lock unless the process is single-threaded. Pass the result to `unlock`.
    #[inline(always)]
    pub fn lock(&self) -> bool {
        if !multithreaded() {
            return false;
        }
        self.lock_always();
        true
    }

    /// Release what `lock` returned the token for.
    #[inline(always)]
    pub fn unlock(&self, taken: bool) {
        if taken {
            self.unlock_always();
        }
    }

    /// Run `body` with the lock held, and release it if the thread is cancelled (or calls `pthread_exit`)
    /// inside `body`: for critical sections that contain a cancellation point (a blocking read or write,
    /// a DNS query), which would otherwise leave the lock taken for ever.
    ///
    /// # Safety
    /// `self` must outlive the call (a static), and `body` must not unlock it.
    #[inline]
    pub unsafe fn with_cancel_unlock<R>(&'static self, body: impl FnOnce() -> R) -> R {
        unsafe extern "C" fn release(arg: *mut core::ffi::c_void) {
            // SAFETY: `arg` is the `&'static RawMutex` registered below, held by the cancelled thread.
            unsafe { (*(arg as *const RawMutex)).unlock_always() };
        }
        let taken = self.lock();
        // SAFETY: caller's promise.
        let r = if taken { unsafe { crate::cleanup::with(release, self as *const RawMutex as *mut core::ffi::c_void, body) } } else { body() };
        self.unlock(taken);
        r
    }

    /// Take the lock (fast path as `lock`) and release it when the guard drops.
    #[inline(always)]
    pub fn guard(&self) -> Guard<'_> {
        Guard { m: self, taken: self.lock() }
    }
}

/// Releases the lock when dropped.
pub struct Guard<'a> {
    m: &'a RawMutex,
    taken: bool,
}

impl Drop for Guard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.m.unlock(self.taken);
    }
}

/// A `RawMutex` around a value, for statics: `static X: Locked<T> = Locked::new(v)`.
pub struct Locked<T> {
    lock: RawMutex,
    value: UnsafeCell<T>,
}

// SAFETY: access to the value goes through the lock.
unsafe impl<T: Send> Sync for Locked<T> {}

impl<T> Locked<T> {
    pub const fn new(value: T) -> Locked<T> {
        Locked { lock: RawMutex::new(), value: UnsafeCell::new(value) }
    }

    /// Run `f` with exclusive access to the value.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let _g = self.lock.guard();
        // SAFETY: the guard excludes other threads (or there is only one).
        f(unsafe { &mut *self.value.get() })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn lock_unlock_cycle() {
        let m = RawMutex::new();
        m.lock_always();
        assert!(!m.try_lock_always());
        m.unlock_always();
        assert!(m.try_lock_always());
        m.unlock_always();
    }

    #[test]
    fn token_roundtrip() {
        let m = RawMutex::new();
        let t = m.lock();
        m.unlock(t);
        assert!(m.try_lock_always());
    }

    #[test]
    fn contended_counter() {
        use std::sync::Arc;
        struct Shared(RawMutex, UnsafeCell<u64>);
        unsafe impl Sync for Shared {}
        let s = Arc::new(Shared(RawMutex::new(), UnsafeCell::new(0)));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for _ in 0..20000 {
                        s.0.lock_always();
                        unsafe { *s.1.get() += 1 };
                        s.0.unlock_always();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(unsafe { *s.1.get() }, 80000);
    }
}
