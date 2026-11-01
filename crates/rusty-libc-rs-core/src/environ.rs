//! The running C library's environment vector (feature `libc-services`): every entry as bytes, and changing it only
//! when the process is single-threaded.
//!
//! # Reading
//!
//! [`entries`] copies each string of the C library's `environ` (the vector getenv(3) searches; std's
//! `env::vars_os` reads the same one but skips entries without a '=' and empty ones). Reading is what the C library's
//! getenv does, which POSIX requires to be thread-safe "except when another thread modifies the environment" (SUSv5,
//! getenv/secure_getenv rationale). Modifying it while others read is the modifier's fault by every contract that
//! allows it: POSIX's, and Rust's `std::env::set_var`, which since the 2024 edition is `unsafe` with the rule that no
//! other thread may read or write the environment concurrently by any means (The Rust Edition Guide, p. 114). The face's
//! own writers below are single-threaded by check, so they never race this reader.
//!
//! # Writing
//!
//! [`set`] and [`remove`] change the environment through `std::env::set_var` / `remove_var` (std's lock, then the C
//! library's setenv / unsetenv) only after [`crate::threads::single_threaded`] says the process has one thread: with
//! no other thread there is no concurrent reader (getenv in C, std::env::var, this module), which is exactly the
//! condition `set_var` asks for. Every signal but glibc's internal 32/33 is blocked on the thread during the update, so
//! a signal handler (getenv is not async-signal-safe, but handlers that call it exist) cannot see a half-made update;
//! a handler running before or after sees the old or the new environment. In a threaded process they refuse with EBUSY; there is no sound safe form for that
//! case (APUE 2nd ed. p. 610: a thread-safe getenv/putenv pair needs one lock shared by every reader, which C code
//! calling getenv does not take).

use crate::errno::Errno;
use core::ffi::c_char;
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::vec::Vec;

unsafe extern "C" {
    /// The C library's environment vector (glibc and rusty-libc export it as `environ`).
    static environ: *const *const c_char;
}

/// Every entry of the running C library's environment, in order, as bytes (entries without '=' and with an empty
/// name included; std's `vars_os` drops those).
pub fn entries() -> Vec<OsString> {
    let mut out = Vec::new();
    // SAFETY: reading the pointer value of the C library's exported `environ` variable (no writer runs concurrently by
    // the contracts in the module documentation).
    let v = unsafe { environ };
    if v.is_null() {
        return out;
    }
    let mut i = 0;
    loop {
        // SAFETY: `environ` is a NULL-terminated vector; `i` stops at the terminating NULL, so the element read is
        // inside it (wrapping_add makes the offset itself safe; the read is the one unsafe operation).
        let p = unsafe { *v.wrapping_add(i) };
        if p.is_null() {
            break;
        }
        // SAFETY: each non-NULL entry is a NUL-terminated string owned by the C library or the start-up stack.
        out.push(OsString::from_vec(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()));
        i += 1;
    }
    out
}

fn check_name(key: &OsStr) -> Result<(), Errno> {
    let k = key.as_bytes();
    if k.is_empty() || k.contains(&b'=') || k.contains(&0) { Err(Errno::EINVAL) } else { Ok(()) }
}

/// Blocks every signal except glibc's internal 32/33 on the calling thread while alive (the old mask comes back on
/// drop, also on unwind), so no handler runs in the middle of an environment update and sees half of it.
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
    if crate::threads::single_threaded()? { Ok(()) } else { Err(Errno(16)) } // EBUSY
}

/// setenv(key, value, 1) through std and the running C library, only in a single-threaded process. EINVAL: empty name,
/// '=' or NUL in the name, NUL in the value. EBUSY: other threads exist. ENOENT/ENODEV: the thread count could not be
/// read (see `threads`).
pub fn set(key: &OsStr, value: &OsStr) -> Result<(), Errno> {
    check_name(key)?;
    if value.as_bytes().contains(&0) {
        return Err(Errno::EINVAL);
    }
    single()?;
    let _blocked = SignalsBlocked::new();
    // SAFETY: the process has one thread (checked just above; only this thread could create another, and nothing
    // between the check and this call does), so no other thread reads or writes the environment: `set_var`'s safety
    // condition. Signals are blocked on this thread meanwhile, so no handler (which could call getenv) runs in the
    // middle of the update. The name and value pass `set_var`'s checks (no panic).
    unsafe { std::env::set_var(key, value) };
    Ok(())
}

/// unsetenv(key) through std and the running C library, only in a single-threaded process. Errors as [`set`].
pub fn remove(key: &OsStr) -> Result<(), Errno> {
    check_name(key)?;
    single()?;
    let _blocked = SignalsBlocked::new();
    // SAFETY: as in `set` (one thread, signals blocked on it).
    unsafe { std::env::remove_var(key) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_match_std() {
        let ours: Vec<(OsString, OsString)> = entries()
            .into_iter()
            .filter_map(|e| {
                let b = e.as_bytes();
                let pos = b.iter().skip(1).position(|&c| c == b'=')? + 1;
                Some((OsString::from_vec(b[..pos].to_vec()), OsString::from_vec(b[pos + 1..].to_vec())))
            })
            .collect();
        assert_eq!(ours, std::env::vars_os().collect::<Vec<_>>());
    }

    #[test]
    fn refused_in_threaded_process() {
        // a second thread alive during the calls
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            rx.recv().ok();
        });
        assert_eq!(set(OsStr::new("RLRS_X"), OsStr::new("1")), Err(Errno(16)));
        assert_eq!(remove(OsStr::new("RLRS_X")), Err(Errno(16)));
        tx.send(()).unwrap();
        h.join().unwrap();
        assert_eq!(set(OsStr::new("A=B"), OsStr::new("1")), Err(Errno::EINVAL));
        assert_eq!(set(OsStr::new(""), OsStr::new("1")), Err(Errno::EINVAL));
        assert_eq!(set(OsStr::new("A"), OsStr::from_bytes(b"x\0")), Err(Errno::EINVAL));
    }
}
