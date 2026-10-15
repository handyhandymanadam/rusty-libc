#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Errno(pub i32);

#[allow(missing_docs)]
impl Errno {
    pub const EPERM: Errno = Errno(1);
    pub const ENOENT: Errno = Errno(2);
    pub const E2BIG: Errno = Errno(7);
    pub const EINTR: Errno = Errno(4);
    pub const ENOEXEC: Errno = Errno(8);
    pub const EBADF: Errno = Errno(9);
    pub const ECHILD: Errno = Errno(10);
    pub const EACCES: Errno = Errno(13);
    pub const ENODEV: Errno = Errno(19);
    pub const ENOTDIR: Errno = Errno(20);
    pub const EINVAL: Errno = Errno(22);
    pub const ENAMETOOLONG: Errno = Errno(36);
    pub const ENOSYS: Errno = Errno(38);
    pub const ETIMEDOUT: Errno = Errno(110);
    pub const ESTALE: Errno = Errno(116);

    #[inline(always)]
    pub const fn of(r: isize) -> Option<Errno> {
        if crate::syscall::is_err(r) { Some(Errno(-(r as i32))) } else { None }
    }
}

#[inline(always)]
pub(crate) const fn cvt(r: isize) -> Result<usize, Errno> {
    match Errno::of(r) {
        Some(e) => Err(e),
        None => Ok(r as usize),
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

#[cfg(feature = "std")]
impl From<Errno> for std::io::Error {
    fn from(e: Errno) -> std::io::Error {
        std::io::Error::from_raw_os_error(e.0)
    }
}
