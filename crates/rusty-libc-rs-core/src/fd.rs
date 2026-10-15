use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};
use core::marker::PhantomData;

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct OwnedRawFd {
    fd: i32,
}

impl OwnedRawFd {
    #[inline]
    pub const unsafe fn from_raw(fd: i32) -> OwnedRawFd {
        assert!(fd != -1, "OwnedRawFd: -1 is not a descriptor");
        OwnedRawFd { fd }
    }

    #[inline]
    pub const fn as_raw(&self) -> i32 {
        self.fd
    }

    #[inline]
    pub fn into_raw(self) -> i32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }

    #[inline]
    pub const fn borrow(&self) -> BorrowedRawFd<'_> {
        BorrowedRawFd { fd: self.fd, _owner: PhantomData }
    }
}

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        let _ = unsafe { syscall3(nr::CLOSE, self.fd as usize, 0, 0) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BorrowedRawFd<'a> {
    fd: i32,
    _owner: PhantomData<&'a OwnedRawFd>,
}

impl BorrowedRawFd<'_> {
    #[inline]
    pub const unsafe fn borrow_raw(fd: i32) -> Self {
        assert!(fd != -1, "BorrowedRawFd: -1 is not a descriptor");
        BorrowedRawFd { fd, _owner: PhantomData }
    }

    #[inline]
    pub const fn as_raw(self) -> i32 {
        self.fd
    }
}

pub fn dup_cloexec(fd: BorrowedRawFd<'_>, min_fd: i32) -> Result<OwnedRawFd, Errno> {
    const F_DUPFD_CLOEXEC: usize = 1030;
    if min_fd < 0 {
        return Err(Errno::EINVAL);
    }
    let new = cvt(unsafe { syscall3(nr::FCNTL, fd.as_raw() as usize, F_DUPFD_CLOEXEC, min_fd as usize) })? as i32;
    Ok(unsafe { OwnedRawFd::from_raw(new) })
}

#[cfg(feature = "std")]
mod std_conv {
    use super::{BorrowedRawFd, OwnedRawFd};
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    impl From<OwnedRawFd> for OwnedFd {
        fn from(fd: OwnedRawFd) -> OwnedFd {
            unsafe { OwnedFd::from_raw_fd(fd.into_raw()) }
        }
    }

    impl<'a> From<BorrowedFd<'a>> for BorrowedRawFd<'a> {
        fn from(fd: BorrowedFd<'a>) -> BorrowedRawFd<'a> {
            unsafe { BorrowedRawFd::borrow_raw(fd.as_raw_fd()) }
        }
    }
}

