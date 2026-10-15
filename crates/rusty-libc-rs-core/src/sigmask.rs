use crate::errno::Errno;
use crate::signal::SigSet;
use core::ffi::c_int;

type CSigset = [u64; 16];

unsafe extern "C" {
    fn pthread_sigmask(how: c_int, set: *const CSigset, old: *mut CSigset) -> c_int;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    Block = 0,
    Unblock = 1,
    SetMask = 2,
}

pub fn thread_mask(how: How, set: Option<SigSet>) -> Result<SigSet, Errno> {
    let new: Option<CSigset> = set.map(|s| {
        let mut c = [0u64; 16];
        c[0] = s.0;
        c
    });
    let mut old: CSigset = [0; 16];
    let p = new.as_ref().map_or(core::ptr::null(), |n| n as *const CSigset);
    match unsafe { pthread_sigmask(how as c_int, p, &mut old) } {
        0 => Ok(SigSet(old[0])),
        e => Err(Errno(e)),
    }
}

