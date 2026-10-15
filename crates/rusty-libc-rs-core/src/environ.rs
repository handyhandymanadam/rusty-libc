use crate::errno::Errno;
use core::ffi::c_char;
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::vec::Vec;

unsafe extern "C" {
    static environ: *const *const c_char;
}

pub fn entries() -> Vec<OsString> {
    let mut out = Vec::new();
    let v = unsafe { environ };
    if v.is_null() {
        return out;
    }
    let mut i = 0;
    loop {
        let p = unsafe { *v.wrapping_add(i) };
        if p.is_null() {
            break;
        }
        out.push(OsString::from_vec(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()));
        i += 1;
    }
    out
}

fn check_name(key: &OsStr) -> Result<(), Errno> {
    let k = key.as_bytes();
    if k.is_empty() || k.contains(&b'=') || k.contains(&0) { Err(Errno::EINVAL) } else { Ok(()) }
}

struct SignalsBlocked(u64);

impl SignalsBlocked {
    fn new() -> SignalsBlocked {
        SignalsBlocked(crate::signal::set_mask(!crate::signal::INTERNAL))
    }
}

impl Drop for SignalsBlocked {
    fn drop(&mut self) {
        crate::signal::set_mask(self.0);
    }
}

fn single() -> Result<(), Errno> {
    if crate::threads::single_threaded()? { Ok(()) } else { Err(Errno(16)) }
}

pub fn set(key: &OsStr, value: &OsStr) -> Result<(), Errno> {
    check_name(key)?;
    if value.as_bytes().contains(&0) {
        return Err(Errno::EINVAL);
    }
    single()?;
    let _blocked = SignalsBlocked::new();
    unsafe { std::env::set_var(key, value) };
    Ok(())
}

pub fn remove(key: &OsStr) -> Result<(), Errno> {
    check_name(key)?;
    single()?;
    let _blocked = SignalsBlocked::new();
    unsafe { std::env::remove_var(key) };
    Ok(())
}

