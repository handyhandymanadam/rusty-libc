//! fcntl(F_GETLK) and fcntl(F_OFD_GETLK) with the lock owner's pid kept as a plain integer: the kernel reports -1 for an
//! open-file-description lock (glibc manual 13.17, p. 415: "the l_pid field ... will be set to -1 to indicate that the
//! lock is not associated with a process") and 0 for an owner outside the caller's PID namespace, so the value cannot
//! go straight into a positive pid type (rustix 1.1.5's `fcntl_getlk` does that; rusty-libc-rs replaces it).

use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::syscall::{nr, syscall3};

const F_GETLK: usize = 5;
const F_OFD_GETLK: usize = 36;

/// F_RDLCK.
pub const F_RDLCK: i16 = 0;
/// F_WRLCK.
pub const F_WRLCK: i16 = 1;
/// F_UNLCK.
pub const F_UNLCK: i16 = 2;

/// The kernel's `struct flock` (x86-64; the same as `flock64`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flock {
    /// F_RDLCK, F_WRLCK or F_UNLCK.
    pub l_type: i16,
    /// SEEK_SET, SEEK_CUR or SEEK_END: what `l_start` counts from.
    pub l_whence: i16,
    /// Start of the range.
    pub l_start: i64,
    /// Length of the range; 0 means "to the end of the file and beyond".
    pub l_len: i64,
    /// The owner of a conflicting lock (output): its pid, -1 for an open-file-description lock, 0 when the owner is
    /// outside the caller's PID namespace.
    pub l_pid: i32,
}

/// fcntl(fd, F_GETLK, lock) (`ofd` false) or fcntl(fd, F_OFD_GETLK, lock) (`ofd` true): `lock` describes the lock the
/// caller would like to place; on return it describes the first conflicting lock, or has `l_type` F_UNLCK (the other
/// fields unchanged) when there is none. For F_OFD_GETLK `l_pid` is set to 0 first, as the kernel requires (EINVAL
/// otherwise).
pub fn getlk(fd: BorrowedRawFd<'_>, ofd: bool, lock: &mut Flock) -> Result<(), Errno> {
    if ofd {
        lock.l_pid = 0;
    }
    let cmd = if ofd { F_OFD_GETLK } else { F_GETLK };
    // SAFETY: the kernel reads and writes one `struct flock` (32 bytes, plain integers, #[repr(C)] with the kernel's
    // layout) through `lock`, a valid exclusive reference; `fd` is borrowed and its locks are only queried.
    cvt(unsafe { syscall3(nr::FCNTL, fd.as_raw() as usize, cmd, lock as *mut Flock as usize) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn layout_and_no_conflict() {
        assert_eq!(core::mem::size_of::<Flock>(), 32);
        let f = std::fs::File::open("/proc/self/status").unwrap();
        // SAFETY: `f` keeps the descriptor open while `fd` is used.
        let fd = unsafe { BorrowedRawFd::borrow_raw(f.as_raw_fd()) };
        let mut l = Flock { l_type: F_RDLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 7 };
        getlk(fd, false, &mut l).unwrap();
        assert_eq!(l.l_type, F_UNLCK);
        let mut l = Flock { l_type: F_RDLCK, l_pid: 7, ..Flock::default() };
        getlk(fd, true, &mut l).unwrap();
        assert_eq!((l.l_type, l.l_pid), (F_UNLCK, 0));
        let mut bad = Flock { l_type: 9, ..Flock::default() };
        assert_eq!(getlk(fd, false, &mut bad), Err(Errno::EINVAL));
    }
}
