//! Reopening a descriptor by number through /proc (`rusty_libc_rs::fd::reopen_fd`). Duplicating a descriptor to an
//! `OwnedFd` is rustix's (`rusty_libc_rs::io::{dup, fcntl_dupfd_cloexec}`; this crate's `dup_cloexec` was the same call).
//!
//! Why there is no safe "adopt this fd number" or "dup this fd number": Rust's I/O-safety rule (std::io, "I/O Safety")
//! says a safe function that takes a plain integer, treats it as a file descriptor and acts on it is unsound: the
//! number may belong to another part of the program (a library's epoll, memfd or socket), and duplicating it hands out
//! its open file description (shared offset, shared O_NONBLOCK, reading data meant for the owner); adopting it as an
//! `OwnedFd` closes it twice. Those entry points stay `unsafe` (`BorrowedFd::borrow_raw`, `OwnedFd::from_raw_fd`).
//! What *is* safe is opening the path `/proc/self/fd/N`: std treats such paths like any other file name (std::os::unix::io,
//! "`/proc/self/mem` and similar OS features"), and `reopen_fd` does exactly that, with the descriptor's own access mode.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::RawFd;

/// The access-mode and append flags of descriptor `fd`, from /proc/self/fdinfo (the `flags:` line, octal).
fn fd_flags(fd: RawFd) -> io::Result<(u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    let mut flags = None;
    let mut pos = 0;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("flags:") {
            flags = u32::from_str_radix(v.trim(), 8).ok();
        } else if let Some(v) = line.strip_prefix("pos:") {
            pos = v.trim().parse().unwrap_or(0);
        }
    }
    flags.map(|f| (f, pos)).ok_or_else(|| io::Error::other("no flags line in /proc/self/fdinfo"))
}

/// Open descriptor number `fd` again through `/proc/self/fd/<fd>`: a *new* open file description of the same file
/// (O_CLOEXEC), opened with `fd`'s access mode and O_APPEND; for a regular file the new one starts at `fd`'s current
/// offset. Differences from dup(2): the offset is not shared afterwards, and objects that cannot be opened by path
/// (sockets, most anonymous inodes such as epoll or eventfd) fail with ENXIO. Pipes, FIFOs, terminals, regular and
/// deleted files work. The result names whatever the number refers to at the time of the call.
pub fn reopen_fd(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(9)); // EBADF
    }
    let (flags, pos) = fd_flags(fd)?;
    let mut opts = std::fs::OpenOptions::new();
    match flags & 3 {
        0 => opts.read(true),
        1 => opts.write(true),
        _ => opts.read(true).write(true),
    };
    if flags & 0o2000 != 0 {
        opts.append(true);
    }
    let mut file = opts.open(format!("/proc/self/fd/{fd}"))?;
    if flags & 0o2000 == 0 && pos > 0 && file.metadata()?.is_file() {
        file.seek(SeekFrom::Start(pos))?;
    }
    Ok(file)
}
