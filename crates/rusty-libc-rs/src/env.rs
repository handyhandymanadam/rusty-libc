use rustix::io;
use std::ffi::{OsStr, OsString};

pub fn vars_raw() -> Vec<OsString> {
    rusty_libc_rs_core::environ::entries()
}

pub fn set_var(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> io::Result<()> {
    rusty_libc_rs_core::environ::set(key.as_ref(), value.as_ref()).map_err(crate::errno)
}

pub fn remove_var(key: impl AsRef<OsStr>) -> io::Result<()> {
    rusty_libc_rs_core::environ::remove(key.as_ref()).map_err(crate::errno)
}

pub fn is_single_threaded() -> io::Result<bool> {
    rusty_libc_rs_core::threads::single_threaded().map_err(crate::errno)
}
