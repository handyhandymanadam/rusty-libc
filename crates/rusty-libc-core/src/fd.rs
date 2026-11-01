//! Owned and borrowed file descriptors for the library's own code (BRIEF-UNSAFE.md U1). The C ABI keeps plain `int` fds.
//!
//! [`Fd`] owns a descriptor and closes it exactly once: when dropped, or by [`Fd::close`] (which reports the error), never
//! both; [`Fd::into_raw`] gives ownership away without closing. [`BorrowedFd<'a>`] is a descriptor that stays open for `'a`
//! because something else (an `Fd`, or the caller of a C function) owns it; it never closes. The lifetime is what makes the
//! pair sound (Comprehensive Rust p.735-737: `PhantomData` ties the borrow to the owner, so the owner cannot be dropped while
//! a `BorrowedFd` is alive).
//!
//! Closing uses the plain close system call (glibc's `__close_nocancel`), so dropping an `Fd` is never a cancellation point.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::Errno;
use core::marker::PhantomData;

/// An owned file descriptor (always >= 0); closed when dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct Fd(i32);

impl Fd {
    /// Take ownership of `fd`.
    ///
    /// # Safety
    /// `fd` is an open descriptor (>= 0, checked in debug builds) that nothing else will close or keep using as its own
    /// after this `Fd` closes it.
    #[inline]
    pub unsafe fn from_raw(fd: i32) -> Fd {
        debug_assert!(fd >= 0);
        Fd(fd)
    }

    /// The descriptor number, still owned by `self`.
    #[inline]
    pub fn as_raw(&self) -> i32 {
        self.0
    }

    /// Give up ownership without closing: the caller now owns the number (e.g. it is returned to C).
    #[inline]
    pub fn into_raw(self) -> i32 {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }

    /// A borrow that cannot outlive `self`.
    #[inline]
    pub fn borrow(&self) -> BorrowedFd<'_> {
        BorrowedFd { fd: self.0, _owner: PhantomData }
    }

    /// Close now and report the result (the descriptor is gone either way: Linux frees it even when close fails).
    #[inline]
    pub fn close(self) -> Result<(), Errno> {
        crate::unistd::close(self.into_raw())
    }
}

impl Drop for Fd {
    #[inline]
    fn drop(&mut self) {
        let _ = crate::unistd::close(self.0);
    }
}

/// A file descriptor that stays open for `'a`; never closed through this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowedFd<'a> {
    fd: i32,
    _owner: PhantomData<&'a Fd>,
}

impl BorrowedFd<'_> {
    /// Borrow a descriptor owned elsewhere (a C caller's `int`).
    ///
    /// # Safety
    /// `fd` stays open (not closed or replaced by dup2) for the lifetime the caller picks. A negative or closed number is not
    /// memory-unsafe (system calls report EBADF) but breaks the invariant code using the borrow may rely on.
    #[inline]
    pub unsafe fn borrow_raw(fd: i32) -> Self {
        BorrowedFd { fd, _owner: PhantomData }
    }

    /// The descriptor number.
    #[inline]
    pub fn as_raw(&self) -> i32 {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd;

    const O_CLOEXEC: i32 = 0o2000000;

    /// True if `fd` is open (fcntl F_GETFD succeeds).
    fn is_open(fd: i32) -> bool {
        unistd::fcntl_int(fd, unistd::F_GETFD, 0).is_ok()
    }

    /// A pipe whose ends sit at `at` and `at + 1`: numbers far above what the kernel hands out to the other tests running
    /// in parallel, so "closed" and "still open" checks cannot be disturbed by a number being reused.
    fn pipe_at(at: i32) -> (Fd, Fd) {
        let (r, w) = unistd::pipe2(O_CLOEXEC).unwrap();
        assert_eq!(unistd::dup3(r, at, O_CLOEXEC), Ok(at));
        assert_eq!(unistd::dup3(w, at + 1, O_CLOEXEC), Ok(at + 1));
        unistd::close(r).unwrap();
        unistd::close(w).unwrap();
        // SAFETY: the two numbers were just made by dup3 and are owned by nobody else.
        unsafe { (Fd::from_raw(at), Fd::from_raw(at + 1)) }
    }

    #[test]
    fn drop_closes() {
        let (r, w) = pipe_at(900);
        assert!(is_open(900));
        drop(r);
        assert!(!is_open(900));
        assert!(is_open(901));
        drop(w);
        assert!(!is_open(901));
    }

    #[test]
    fn close_closes_exactly_once() {
        let (r, w) = pipe_at(910);
        assert_eq!(r.close(), Ok(()));
        assert!(!is_open(910));
        // a new descriptor at the same number: nothing left over from the old Fd may close it
        let (r2, w2) = pipe_at(910);
        drop(w);
        assert!(is_open(910));
        drop((r2, w2));
        assert!(!is_open(910));
    }

    #[test]
    fn into_raw_gives_ownership_away() {
        let (r, w) = pipe_at(920);
        let n = r.into_raw();
        assert!(is_open(n));
        // SAFETY: we own `n` again (into_raw above).
        drop(unsafe { Fd::from_raw(n) });
        assert!(!is_open(n));
        drop(w);
    }

    #[test]
    fn borrow_does_not_close() {
        let (r, w) = pipe_at(930);
        {
            let b = r.borrow();
            let c = b;
            assert_eq!(c.as_raw(), 930);
            assert_eq!(unistd::write(w.as_raw(), b"x"), Ok(1));
            let mut buf = [0u8; 1];
            assert_eq!(unistd::read(b.as_raw(), &mut buf), Ok(1));
        }
        assert!(is_open(930));
        // SAFETY: `r` outlives the borrow.
        let raw = unsafe { BorrowedFd::borrow_raw(r.as_raw()) };
        assert_eq!(raw, r.borrow());
        drop((r, w));
    }
}
