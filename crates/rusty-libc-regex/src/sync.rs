//! `Spin<T>`: a value behind a spin lock of one flag, for the crate's caches (the set automata, the charset lists, the case
//! tables of `mbset`). (The per-pattern DFA keeps its flag and cell as two fields of its own: see `dfa::Dfa`.) It replaces `static mut` plus a separate `AtomicBool` with one type
//! whose only ways to the value take the lock, so the callers need no unsafe code.
//!
//! The lock is the one those places used before, unchanged: `swap(true, Acquire)` to take it (spinning),
//! `store(false, Release)` to release it; no system call. The critical sections are short (a lookup, a pointer copy),
//! and a signal handler that compiled a pattern while the interrupted code held a cache lock
//! would spin for ever, as before (regcomp is not async-signal-safe).
//!
//! Sources: Mara Bos, Rust Atomics and Locks, ch. 4 "An Unsafe Spin Lock" (a lock that hands out `&mut T` makes the
//! callers' code safe; `Sync` needs only `T: Send`, since one thread at a time has the value); the Edition Guide p.94
//! (an `UnsafeCell` wrapper in a `static` instead of `static mut`). The cell is core's `SyncCell`, so the crate adds no
//! `unsafe impl` of its own: `Spin` is `Sync` through it, and the `T: Send` bound sits on every method that reaches the
//! value.
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::sync_cell::SyncCell;

pub struct Spin<T> {
    lock: AtomicBool,
    value: SyncCell<T>,
}

impl<T: Send> Spin<T> {
    pub const fn new(value: T) -> Spin<T> {
        Spin { lock: AtomicBool::new(false), value: SyncCell::new(value) }
    }

    /// Run `f` with the lock held (spinning until it is free). `f` must not use the same `Spin` again (it would spin for
    /// ever; it cannot alias the value).
    #[inline(always)]
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock, so no other thread reads or writes the value until the release below (every access
        // goes through this lock); a nested use of this `Spin` inside `f` spins on the lock and never reaches the value.
        let r = unsafe { self.value.with_unsync(f) };
        self.lock.store(false, Ordering::Release);
        r
    }

}
