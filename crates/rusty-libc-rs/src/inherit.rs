use std::os::fd::{OwnedFd, RawFd};

pub use rusty_libc_rs_core::inherited::LIMIT as INHERITED_FD_LIMIT;

pub fn take_inherited(fd: RawFd) -> Option<OwnedFd> {
    rusty_libc_rs_core::inherited::take_inherited(fd).map(OwnedFd::from)
}

pub fn was_inherited(fd: RawFd) -> bool {
    rusty_libc_rs_core::inherited::was_inherited(fd)
}

pub fn inherited_snapshot_taken() -> bool {
    rusty_libc_rs_core::inherited::snapshot_taken()
}
