use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Who {
    Process = 0,
    Children = -1,
    Thread = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct RawRusage {
    pub utime_sec: i64,
    pub utime_usec: i64,
    pub stime_sec: i64,
    pub stime_usec: i64,
    pub maxrss: i64,
    pub ixrss: i64,
    pub idrss: i64,
    pub isrss: i64,
    pub minflt: i64,
    pub majflt: i64,
    pub nswap: i64,
    pub inblock: i64,
    pub oublock: i64,
    pub msgsnd: i64,
    pub msgrcv: i64,
    pub nsignals: i64,
    pub nvcsw: i64,
    pub nivcsw: i64,
}

pub fn getrusage(who: Who) -> Result<RawRusage, Errno> {
    let mut ru = RawRusage::default();
    cvt(unsafe { syscall3(nr::GETRUSAGE, who as i32 as usize, &raw mut ru as usize, 0) })?;
    Ok(ru)
}

const _: () = assert!(core::mem::size_of::<RawRusage>() == 144);

