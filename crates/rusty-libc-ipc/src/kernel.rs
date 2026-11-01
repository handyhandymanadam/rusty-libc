//! The crate's plain-value system calls (BRIEF-UNSAFE.md U2): every argument is a number, the kernel reads and writes no
//! memory of ours, and the call cannot unmap or protect memory the program uses. Each is a safe function with the one unsafe
//! block it needs; the raw kernel result is returned unchanged (`util::sc`/`res` turn it into errno or `Result`).
//!
//! The calls that pass pointers stay raw where they are made: in an exported C function the pointers are the caller's,
//! handed to the kernel untouched, so a NULL or bad pointer gives the EFAULT glibc gives (a reference to memory that is not
//! valid would be undefined behaviour the moment it exists, The Rustonomicon p.12). Calls on the library's own locals and
//! slices are one unsafe block each with the reason next to it.
use rusty_libc_core::syscall::{syscall1, syscall2, syscall3, syscall4};

const SYS_CLOSE: usize = 3;
const SYS_SHMGET: usize = 29;
const SYS_SOCKET: usize = 41;
const SYS_SEMGET: usize = 64;
const SYS_SEMCTL: usize = 66;
const SYS_MSGGET: usize = 68;
const SYS_MSGCTL: usize = 71;
const SYS_SHMCTL: usize = 31;
const SYS_FCNTL: usize = 72;
const SYS_FSYNC: usize = 74;
const SYS_FDATASYNC: usize = 75;
const F_GETFL: usize = 3;

/// msgget(2).
#[inline]
pub(crate) fn msgget(key: usize, flags: usize) -> usize {
    // SAFETY: plain values; the kernel reads no memory of ours.
    unsafe { syscall2(SYS_MSGGET, key, flags) }
}

/// semget(2).
#[inline]
pub(crate) fn semget(key: usize, nsems: usize, flags: usize) -> usize {
    // SAFETY: plain values.
    unsafe { syscall3(SYS_SEMGET, key, nsems, flags) }
}

/// shmget(2).
#[inline]
pub(crate) fn shmget(key: usize, size: usize, flags: usize) -> usize {
    // SAFETY: plain values (creating a segment maps nothing).
    unsafe { syscall3(SYS_SHMGET, key, size, flags) }
}

/// semctl(2) for the commands whose fourth argument is a number or unused: GETVAL, GETPID, GETNCNT, GETZCNT, SETVAL,
/// IPC_RMID. Any other command takes a pointer and is refused here (debug assertion; the callers pass constants).
#[inline]
pub(crate) fn semctl_val(id: usize, num: usize, cmd: i32, val: usize) -> usize {
    use crate::sysv::{GETNCNT, GETPID, GETVAL, GETZCNT, IPC_RMID, SETVAL};
    debug_assert!(matches!(cmd, GETVAL | GETPID | GETNCNT | GETZCNT | SETVAL | IPC_RMID));
    // SAFETY: for these commands the fourth argument is a value or ignored; the kernel dereferences nothing.
    unsafe { syscall4(SYS_SEMCTL, id, num, cmd as usize, val) }
}

/// msgctl(id, IPC_RMID, NULL).
#[inline]
pub(crate) fn msgctl_rmid(id: usize) -> usize {
    // SAFETY: IPC_RMID ignores the buffer argument, which is NULL anyway.
    unsafe { syscall3(SYS_MSGCTL, id, crate::sysv::IPC_RMID as usize, 0) }
}

/// shmctl(id, IPC_RMID, NULL): marks the segment for removal; existing mappings stay valid until detached.
#[inline]
pub(crate) fn shmctl_rmid(id: usize) -> usize {
    // SAFETY: IPC_RMID ignores the buffer argument, which is NULL; no mapping is touched.
    unsafe { syscall3(SYS_SHMCTL, id, crate::sysv::IPC_RMID as usize, 0) }
}

/// close(2) (the plain call: glibc's mq_close is close).
#[inline]
pub(crate) fn close(fd: usize) -> usize {
    // SAFETY: plain value.
    unsafe { syscall1(SYS_CLOSE, fd) }
}

/// fcntl(fd, F_GETFL), made the way glibc's aio functions make it (two arguments).
#[inline]
pub(crate) fn fcntl_getfl(fd: usize) -> usize {
    // SAFETY: F_GETFL takes no third argument and dereferences nothing.
    unsafe { syscall2(SYS_FCNTL, fd, F_GETFL) }
}

/// fsync(2).
#[inline]
pub(crate) fn fsync(fd: usize) -> usize {
    // SAFETY: plain value.
    unsafe { syscall1(SYS_FSYNC, fd) }
}

/// fdatasync(2).
#[inline]
pub(crate) fn fdatasync(fd: usize) -> usize {
    // SAFETY: plain value.
    unsafe { syscall1(SYS_FDATASYNC, fd) }
}

/// socket(2).
#[inline]
pub(crate) fn socket(family: usize, ty: usize, proto: usize) -> usize {
    // SAFETY: plain values.
    unsafe { syscall3(SYS_SOCKET, family, ty, proto) }
}

/// rt_sigprocmask(how, &set, NULL, 8) when `old` is false, or with the old mask returned when it is true (the exact calls
/// the notification helpers made before: the old-mask pointer is NULL where they did not want it).
#[inline]
pub(crate) fn sigprocmask(how: usize, set: u64, want_old: bool) -> u64 {
    let mut old = 0u64;
    let oldp = if want_old { &raw mut old as usize } else { 0 };
    // SAFETY: the kernel reads the local `set` (8 bytes) and writes the old mask into the local `old` or nowhere.
    unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how, &raw const set as usize, oldp, 8) };
    old
}

/// futex(word, FUTEX_WAIT_PRIVATE, expected, NULL): sleep while `word` holds `expected`; the raw kernel result (EINTR on a
/// signal, EAGAIN when the word differs). Not a cancellation point.
#[inline]
pub(crate) fn futex_wait(word: &core::sync::atomic::AtomicU32, expected: u32) -> usize {
    const SYS_FUTEX: usize = 202;
    const FUTEX_WAIT_PRIVATE: usize = 128;
    // SAFETY: the kernel reads the borrowed word; no timeout.
    unsafe { syscall4(SYS_FUTEX, word as *const core::sync::atomic::AtomicU32 as usize, FUTEX_WAIT_PRIVATE, expected as usize, 0) }
}
