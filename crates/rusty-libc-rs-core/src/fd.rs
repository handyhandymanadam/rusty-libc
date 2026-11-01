//! Descriptor ownership without std: `OwnedRawFd` (owns an open descriptor and closes it once, on drop) and
//! `BorrowedRawFd<'a>` (a descriptor some owner keeps open for `'a`). They carry the invariants of std's `OwnedFd` /
//! `BorrowedFd` (Rust I/O safety, RFC 3128; The Rust RFC Book p. 3705: a raw number is only turned into an owned or
//! borrowed handle by code that knows the OS gave it out and that nothing else owns it, hence the `unsafe` constructors;
//! Comprehensive Rust p. 737: the borrow's lifetime ties it to the owner that keeps the descriptor open). With the `std`
//! feature `OwnedRawFd` converts into std's `OwnedFd` and `BorrowedFd` into `BorrowedRawFd` (same representation, no
//! system call; the other directions are not needed yet).
//!
//! Safe ways to get an `OwnedRawFd`: a call that creates a descriptor ([`dup_cloexec`], a spawn's pidfd). Room is left for
//! other safe constructors that can prove ownership (e.g. a claim-once registry of descriptors inherited at startup).

use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};
use core::marker::PhantomData;

/// An open descriptor this value owns; closed when dropped. Never -1.
#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OwnedRawFd {
    fd: i32,
}

impl OwnedRawFd {
    /// Take ownership of descriptor `fd`.
    ///
    /// # Safety
    /// `fd` is an open descriptor that nothing else owns or will close (std's `OwnedFd::from_raw_fd` contract); it must not
    /// be -1.
    #[inline]
    pub const unsafe fn from_raw(fd: i32) -> OwnedRawFd {
        assert!(fd != -1, "OwnedRawFd: -1 is not a descriptor");
        OwnedRawFd { fd }
    }

    /// The descriptor number (still owned by `self`).
    #[inline]
    pub const fn as_raw(&self) -> i32 {
        self.fd
    }

    /// Give up ownership without closing: the caller now owns the number.
    #[inline]
    pub fn into_raw(self) -> i32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    /// Borrow it for the lifetime of `&self`.
    #[inline]
    pub const fn borrow(&self) -> BorrowedRawFd<'_> {
        BorrowedRawFd { fd: self.fd, _owner: PhantomData }
    }
}

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        // close(2)'s errors are ignored, as std's OwnedFd does (the descriptor is released even when close reports EINTR/EIO).
        // SAFETY: we own the descriptor (type invariant) and nothing uses it after this drop.
        let _ = unsafe { syscall3(nr::CLOSE, self.fd as usize, 0, 0) };
    }
}

/// A descriptor kept open by some owner for at least `'a`. Never -1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BorrowedRawFd<'a> {
    fd: i32,
    _owner: PhantomData<&'a OwnedRawFd>,
}

impl BorrowedRawFd<'_> {
    /// Borrow descriptor `fd`.
    ///
    /// # Safety
    /// `fd` stays open for the whole lifetime chosen by the caller (std's `BorrowedFd::borrow_raw` contract); not -1.
    #[inline]
    pub const unsafe fn borrow_raw(fd: i32) -> Self {
        assert!(fd != -1, "BorrowedRawFd: -1 is not a descriptor");
        BorrowedRawFd { fd, _owner: PhantomData }
    }

    /// The descriptor number.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.fd
    }
}

/// fcntl(fd, F_DUPFD_CLOEXEC, min_fd): a new descriptor (the lowest free number >= `min_fd`) for the same open file, with
/// FD_CLOEXEC set. EINVAL for a negative `min_fd`.
pub fn dup_cloexec(fd: BorrowedRawFd<'_>, min_fd: i32) -> Result<OwnedRawFd, Errno> {
    const F_DUPFD_CLOEXEC: usize = 1030;
    if min_fd < 0 {
        return Err(Errno::EINVAL);
    }
    // SAFETY: F_DUPFD_CLOEXEC takes an integer argument; `fd` is borrowed and only duplicated.
    let new = cvt(unsafe { syscall3(nr::FCNTL, fd.as_raw() as usize, F_DUPFD_CLOEXEC, min_fd as usize) })? as i32;
    // SAFETY: the kernel just created `new` for this call; nothing else knows it.
    Ok(unsafe { OwnedRawFd::from_raw(new) })
}

#[cfg(feature = "std")]
mod std_conv {
    use super::{BorrowedRawFd, OwnedRawFd};
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    impl From<OwnedRawFd> for OwnedFd {
        fn from(fd: OwnedRawFd) -> OwnedFd {
            // SAFETY: `fd` owned the open descriptor (type invariant) and hands that ownership over.
            unsafe { OwnedFd::from_raw_fd(fd.into_raw()) }
        }
    }

    impl<'a> From<BorrowedFd<'a>> for BorrowedRawFd<'a> {
        fn from(fd: BorrowedFd<'a>) -> BorrowedRawFd<'a> {
            // SAFETY: a `BorrowedFd<'a>` guarantees the descriptor stays open for 'a (and is not -1).
            unsafe { BorrowedRawFd::borrow_raw(fd.as_raw_fd()) }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::os::fd::AsRawFd;

    fn fd_open(fd: i32) -> bool {
        // F_GETFD on a number: EBADF when closed (plain integer call, no effect)
        !crate::syscall::is_err(plain!(nr::FCNTL, fd, 1))
    }

    #[test]
    fn dup_and_close_once() {
        let f = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: `f` keeps the descriptor open while `b` is used.
        let b = unsafe { BorrowedRawFd::borrow_raw(f.as_raw_fd()) };
        let fd = dup_cloexec(b, 100).unwrap();
        let n = fd.as_raw();
        assert!(n >= 100);
        assert!(fd_open(n));
        assert_eq!(fd.borrow().as_raw(), n);
        drop(fd);
        assert!(!fd_open(n));
        assert_eq!(dup_cloexec(b, -1), Err(Errno::EINVAL));
    }

    #[test]
    fn into_raw_does_not_close() {
        let f = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: `f` keeps the descriptor open while `b` is used.
        let b = unsafe { BorrowedRawFd::borrow_raw(f.as_raw_fd()) };
        let fd = dup_cloexec(b, 200).unwrap();
        let n = fd.into_raw();
        assert!(fd_open(n));
        // SAFETY: `n` came from into_raw just above: we own it.
        drop(unsafe { OwnedRawFd::from_raw(n) });
        assert!(!fd_open(n));
    }
}
