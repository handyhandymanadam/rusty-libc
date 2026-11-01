//! The process environment as the running C library holds it: every entry raw ([`vars_raw`]), and setting or removing
//! a variable as a SAFE call that works only while the process has one thread ([`set_var`], [`remove_var`]).
//!
//! Why not always: since the 2024 edition `std::env::set_var` / `remove_var` are `unsafe`, because another thread may
//! read the environment at the same time through the C library's getenv (C code, or Rust code calling into C), which
//! takes no lock (The Rust Edition Guide, p. 114; POSIX requires getenv to be thread-safe only "except when another
//! thread modifies the environment", SUSv5). No safe form exists for a threaded process: a lock would have to be
//! taken by every reader, and C readers do not take one (APUE 2nd ed. p. 610). With a single thread there is no other
//! reader, which is exactly std's safety condition; this module checks that with a verified /proc thread count
//! (rusty-libc-rs-core `threads`: procfs's own file describing this process) right before the change, and refuses
//! with EBUSY otherwise. Programs that need different variables for children should give them to the child
//! (`Command::env`) instead.
//!
//! Reading ([`vars_raw`]) is always allowed, as getenv is: a reader can only race a writer that broke the writers'
//! contract (an unsafe `set_var` while threads run, or C code calling setenv beside other threads).

use rustix::io;
use std::ffi::{OsStr, OsString};

/// Every entry of the environment exactly as the C library's `environ` holds it, in order: "NAME=value" byte strings,
/// including entries `std::env::vars_os` skips (no '=', an empty name such as "=x", an empty string). For `env` with no
/// arguments, which prints them all.
pub fn vars_raw() -> Vec<OsString> {
    rusty_libc_rs_core::environ::entries()
}

/// Set `key` to `value` (setenv(key, value, 1) via std) when the process is single-threaded. EINVAL: empty name, '='
/// or NUL in the name, NUL in the value. EBUSY: the process has other threads. ENOENT / ENODEV: /proc/self/status
/// could not be read or checked (no thread count, no change).
pub fn set_var(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> io::Result<()> {
    rusty_libc_rs_core::environ::set(key.as_ref(), value.as_ref()).map_err(crate::errno)
}

/// Remove `key` (unsetenv via std) when the process is single-threaded. Errors as [`set_var`].
pub fn remove_var(key: impl AsRef<OsStr>) -> io::Result<()> {
    rusty_libc_rs_core::environ::remove(key.as_ref()).map_err(crate::errno)
}

/// Is the process single-threaded right now (the condition [`set_var`] checks)? See rusty-libc-rs-core `threads`
/// for how the answer is verified.
pub fn is_single_threaded() -> io::Result<bool> {
    rusty_libc_rs_core::threads::single_threaded().map_err(crate::errno)
}
