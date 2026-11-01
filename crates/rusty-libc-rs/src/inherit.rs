//! Adopting a descriptor inherited at exec (`rusty_libc_rs::fd::take_inherited`): the safe form of
//! `OwnedFd::from_raw_fd(n)` / `BorrowedFd::borrow_raw(n)` for a number the parent left open (`3>file`,
//! `--inherit-fd N`). The snapshot and the soundness argument are in rusty-libc-rs-core's `inherited` module.

use std::os::fd::{OwnedFd, RawFd};

pub use rusty_libc_rs_core::inherited::LIMIT as INHERITED_FD_LIMIT;

/// Take ownership of descriptor `fd`, inherited by the process (open before `main`): the same open file description
/// as the parent's (shared offset and flags; sockets, pipes, terminals, anything). Returns `None` unless `fd` is in
/// 3..[`INHERITED_FD_LIMIT`] (1024), was open when the startup snapshot was taken, has not been taken before (only the
/// first call for a number can succeed), and still refers to the same file (fstat device and inode).
///
/// Sound in safe code: a number can be adopted once, only if it was open before `main`, never 0-2 (std's stdin, stdout
/// and stderr assume those stay open), and only if it was not replaced by another file. The one assumption is that
/// no other code in the process claims the same number through `unsafe` (`from_raw_fd`, `borrow_raw`, `close`), or
/// opened and kept it in a constructor before `main`. The full argument is on rusty-libc-rs-core's
/// `inherited::take_inherited`.
///
/// The snapshot needs this crate in the main executable (not a library loaded with dlopen); without it every call
/// returns `None` ([`inherited_snapshot_taken`] tells).
pub fn take_inherited(fd: RawFd) -> Option<OwnedFd> {
    rusty_libc_rs_core::inherited::take_inherited(fd).map(OwnedFd::from)
}

/// Was descriptor `fd` open when the startup snapshot was taken (before `main`)? True also after it was taken.
pub fn was_inherited(fd: RawFd) -> bool {
    rusty_libc_rs_core::inherited::was_inherited(fd)
}

/// Was the startup snapshot of inherited descriptors taken? False when this crate is not linked into the main
/// executable (e.g. loaded with dlopen): then [`take_inherited`] always returns `None`.
pub fn inherited_snapshot_taken() -> bool {
    rusty_libc_rs_core::inherited::snapshot_taken()
}
