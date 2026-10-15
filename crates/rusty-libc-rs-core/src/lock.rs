use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::syscall::{nr, syscall3};

const F_GETLK: usize = 5;
const F_OFD_GETLK: usize = 36;

pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

pub fn getlk(fd: BorrowedRawFd<'_>, ofd: bool, lock: &mut Flock) -> Result<(), Errno> {
    if ofd {
        lock.l_pid = 0;
    }
    let cmd = if ofd { F_OFD_GETLK } else { F_GETLK };
    cvt(unsafe { syscall3(nr::FCNTL, fd.as_raw() as usize, cmd, lock as *mut Flock as usize) })?;
    Ok(())
}

