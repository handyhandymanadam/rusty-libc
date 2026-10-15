#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::Errno;
use core::marker::PhantomData;

#[derive(Debug, PartialEq, Eq)]
pub struct Fd(i32);

impl Fd {
    #[inline]
    pub unsafe fn from_raw(fd: i32) -> Fd {
        debug_assert!(fd >= 0);
        Fd(fd)
    }

    #[inline]
    pub fn as_raw(&self) -> i32 {
        self.0
    }

    #[inline]
    pub fn into_raw(self) -> i32 {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }

    #[inline]
    pub fn borrow(&self) -> BorrowedFd<'_> {
        BorrowedFd { fd: self.0, _owner: PhantomData }
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowedFd<'a> {
    fd: i32,
    _owner: PhantomData<&'a Fd>,
}

impl BorrowedFd<'_> {
    #[inline]
    pub unsafe fn borrow_raw(fd: i32) -> Self {
        BorrowedFd { fd, _owner: PhantomData }
    }

    #[inline]
    pub fn as_raw(&self) -> i32 {
        self.fd
    }
}

