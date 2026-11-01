//! Is the calling process single-threaded right now? (feature `std`). The proof a few process-wide changes need before
//! they can be offered as safe calls: changing the environment (other threads may read it through the C library's
//! getenv without a lock) and an in-place exec that maps descriptor numbers above 2 (other threads may own them).
//!
//! The answer comes from the kernel: `/proc/self/status`, after checking that the file really is procfs's
//! (fstatfs f_type PROC_SUPER_MAGIC) and that it describes this process as procfs sees it (`Tgid` and `Pid` equal
//! getpid()), so a substituted file (a bind mount in a user namespace) or a procfs of another PID namespace is not
//! believed; then `Threads: 1`.
//!
//! Why a "yes" stays true until the caller's next step: a new thread of a process can only be created by a thread of
//! that process (clone with CLONE_THREAD). With one thread, only the caller could create another, and the face's code
//! between the check and the change creates none. (A signal handler on the caller's thread could, but pthread_create
//! is not async-signal-safe, so a handler doing that is already undefined behaviour in C.) Limit: a process created by
//! clone(CLONE_VM) without CLONE_THREAD shares the memory but is not a thread (not counted); only unsafe code makes such
//! a process, and it then owns that hazard.

use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};
use std::io::Read;
use std::string::String;
use std::os::fd::AsRawFd;

/// procfs's f_type.
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// The calling process's thread count (`Threads:` of a checked `/proc/self/status`). ENOENT when /proc is not
/// mounted, ENODEV when the file is not procfs's or does not describe this process.
pub fn thread_count() -> Result<usize, Errno> {
    let mut f = std::fs::File::open("/proc/self/status").map_err(io_errno)?;
    // struct statfs is 120 bytes on x86-64; f_type is the first word
    let mut st = [0i64; 15];
    // SAFETY: the kernel writes one 120-byte struct statfs into the local `st`; the descriptor is borrowed from `f`.
    cvt(unsafe { syscall3(nr::FSTATFS, f.as_raw_fd() as usize, st.as_mut_ptr() as usize, 0) })?;
    if st[0] != PROC_SUPER_MAGIC {
        return Err(Errno::ENODEV);
    }
    let mut text = String::new();
    f.read_to_string(&mut text).map_err(io_errno)?;
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.trim().parse::<i64>().ok());
    let me = i64::from(crate::process::getpid());
    match (field("Tgid:"), field("Pid:"), field("Threads:")) {
        (Some(t), Some(p), Some(n)) if t == me && p == me && n > 0 => Ok(n as usize),
        _ => Err(Errno::ENODEV),
    }
}

/// Is the calling process single-threaded now (see the module documentation for why the answer holds until the
/// caller creates a thread)?
pub fn single_threaded() -> Result<bool, Errno> {
    thread_count().map(|n| n == 1)
}

fn io_errno(e: std::io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(Errno::EINVAL.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_threads() {
        let n = thread_count().unwrap();
        assert!(n >= 1);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            rx.recv().ok();
        });
        ready_rx.recv().unwrap();
        assert!(thread_count().unwrap() >= 2);
        assert_eq!(single_threaded(), Ok(false));
        tx.send(()).unwrap();
        h.join().unwrap();
    }
}
