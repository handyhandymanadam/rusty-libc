//! `SyncCell<T>`: a global with interior mutability whose synchronisation rule is stated at each access (BRIEF-UNSAFE.md U1).
//!
//! It replaces `static mut` (crate by crate in U2): `static X: SyncCell<T> = SyncCell::new(v)`. Taking `&X` is safe; touching
//! the value is not, and each accessor's name says which rule the caller relies on:
//! - [`SyncCell::with_unsync`]: nothing else can access the value meanwhile (one thread: start-up before any thread is
//!   created, the child after fork; or a lock that is not `lock::Locked`'s own). The `&mut T` lives only inside the closure,
//!   so it cannot escape (a bounded lifetime instead of `static mut`'s free-for-all, The Rustonomicon p.58-59).
//! - [`SyncCell::read`] / [`SyncCell::write`]: a plain copy in or out under the same rule, for flags and pointers that are
//!   set once at start-up and read later.
//! - [`SyncCell::as_ptr`]: a raw pointer (as `&raw mut STATIC`) for C interfaces and for per-field access.
//!
//! A value guarded by one lock of its own should be a `lock::Locked<T>` instead (fully safe); a counter or flag touched by
//! several threads should be an atomic.
//!
//! `Sync` for every `T`, as the Edition Guide p.94-95 describes for an UnsafeCell wrapper used in a static ("useful if you
//! have external locks or other guarantees"): the only ways to the value are the unsafe accessors, whose contracts include
//! the cross-thread requirements, so this is never weaker than the `static mut` it replaces (which has no bound at all).
//! std's unstable `SyncUnsafeCell` asks for `T: Sync`; that would rule out the raw pointers most of the library's globals
//! hold. `Send` stays automatic (`T: Send`), so a non-`Send` value is never moved to, or dropped on, another thread by
//! safe code.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;

/// An `UnsafeCell` that may be put in a `static`. See the module documentation for the rules.
#[repr(transparent)]
pub struct SyncCell<T>(UnsafeCell<T>);

// SAFETY: every access to the value is through an unsafe accessor whose contract forbids data races and covers use from any
// thread (see the module documentation); sharing `&SyncCell<T>` alone gives safe code nothing to race on.
unsafe impl<T> Sync for SyncCell<T> {}

impl<T> SyncCell<T> {
    /// A cell holding `value` (usable in a `static`).
    pub const fn new(value: T) -> SyncCell<T> {
        SyncCell(UnsafeCell::new(value))
    }

    /// A raw pointer to the value. Getting it is safe; using it is under the same rule as the other accessors.
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    /// Run `f` with exclusive access to the value.
    ///
    /// # Safety
    /// For the duration of the call nothing else reads or writes the value: the process has one thread (start-up before
    /// the first thread is created, a forked child) or the caller holds the lock that guards this cell, and no signal
    /// handler that touches it can run. `f` must not reach this cell again (no nested `with_unsync`/`read`/`write`).
    #[inline(always)]
    pub unsafe fn with_unsync<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: exclusive for the call (caller's contract); the reference does not outlive `f`.
        f(unsafe { &mut *self.0.get() })
    }

    /// A copy of the value.
    ///
    /// # Safety
    /// No write to the value can happen at the same time (it was written before the threads that read it exist, or the
    /// caller holds the lock that guards it).
    #[inline(always)]
    pub unsafe fn read(&self) -> T
    where
        T: Copy,
    {
        // SAFETY: no concurrent write (caller's contract); the pointer is valid and aligned (it is our own cell).
        unsafe { *self.0.get() }
    }

    /// Replace the value (the old one is dropped).
    ///
    /// # Safety
    /// Nothing else reads or writes the value at the same time (the rule of [`SyncCell::with_unsync`]).
    #[inline(always)]
    pub unsafe fn write(&self, value: T) {
        // SAFETY: exclusive access (caller's contract); the pointer is valid and aligned.
        unsafe { *self.0.get() = value };
    }

    /// Exclusive access through an exclusive borrow of the cell itself (no rule needed: the borrow checker proves it).
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    static FLAG: SyncCell<usize> = SyncCell::new(0);
    static PTR: SyncCell<*const u8> = SyncCell::new(core::ptr::null());
    static TABLE: SyncCell<[u32; 4]> = SyncCell::new([0; 4]);

    #[test]
    fn static_read_write() {
        // SAFETY: only this test touches FLAG.
        unsafe {
            FLAG.write(5);
            assert_eq!(FLAG.read(), 5);
        }
    }

    #[test]
    fn holds_raw_pointers() {
        static DATA: [u8; 2] = [1, 2];
        // SAFETY: only this test touches PTR.
        unsafe {
            PTR.write(DATA.as_ptr());
            assert_eq!(*PTR.read().add(1), 2);
        }
    }

    #[test]
    fn with_unsync_mutates_in_place() {
        // SAFETY: only this test touches TABLE.
        let sum = unsafe {
            TABLE.with_unsync(|t| {
                t[2] = 7;
                t.iter().sum::<u32>()
            })
        };
        assert_eq!(sum, 7);
        assert_eq!(TABLE.as_ptr().cast::<u32>(), TABLE.as_ptr() as *mut u32);
        let mut local = SyncCell::new(1u8);
        *local.get_mut() += 1;
        // SAFETY: `local` is not shared.
        assert_eq!(unsafe { local.read() }, 2);
    }

    #[test]
    fn under_an_external_lock() {
        use crate::lock::RawMutex;
        static L: RawMutex = RawMutex::new();
        static COUNT: SyncCell<u64> = SyncCell::new(0);
        let hs: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..10000 {
                        // std threads do not mark the process multithreaded, so take the lock for sure
                        L.lock_always();
                        // SAFETY: COUNT is only touched under L.
                        unsafe { COUNT.with_unsync(|c| *c += 1) };
                        L.unlock_always();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        // SAFETY: every thread that wrote COUNT has been joined.
        assert_eq!(unsafe { COUNT.read() }, 40000);
    }
}
