use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::syscall::{nr, syscall6};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_cred(fd: BorrowedRawFd<'_>) -> Result<UCred, Errno> {
    const SOL_SOCKET: usize = 1;
    const SO_PEERCRED: usize = 17;
    let mut cred = UCred::default();
    let mut len = core::mem::size_of::<UCred>() as u32;
    cvt(unsafe { syscall6(nr::GETSOCKOPT, fd.as_raw() as usize, SOL_SOCKET, SO_PEERCRED, &raw mut cred as usize, &raw mut len as usize, 0) })?;
    Ok(cred)
}

