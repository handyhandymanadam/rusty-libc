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

#[inline]
pub(crate) fn msgget(key: usize, flags: usize) -> usize {
    unsafe { syscall2(SYS_MSGGET, key, flags) }
}

#[inline]
pub(crate) fn semget(key: usize, nsems: usize, flags: usize) -> usize {
    unsafe { syscall3(SYS_SEMGET, key, nsems, flags) }
}

#[inline]
pub(crate) fn shmget(key: usize, size: usize, flags: usize) -> usize {
    unsafe { syscall3(SYS_SHMGET, key, size, flags) }
}

#[inline]
pub(crate) fn semctl_val(id: usize, num: usize, cmd: i32, val: usize) -> usize {
    use crate::sysv::{GETNCNT, GETPID, GETVAL, GETZCNT, IPC_RMID, SETVAL};
    debug_assert!(matches!(cmd, GETVAL | GETPID | GETNCNT | GETZCNT | SETVAL | IPC_RMID));
    unsafe { syscall4(SYS_SEMCTL, id, num, cmd as usize, val) }
}

#[inline]
pub(crate) fn msgctl_rmid(id: usize) -> usize {
    unsafe { syscall3(SYS_MSGCTL, id, crate::sysv::IPC_RMID as usize, 0) }
}

#[inline]
pub(crate) fn shmctl_rmid(id: usize) -> usize {
    unsafe { syscall3(SYS_SHMCTL, id, crate::sysv::IPC_RMID as usize, 0) }
}

#[inline]
pub(crate) fn close(fd: usize) -> usize {
    unsafe { syscall1(SYS_CLOSE, fd) }
}

#[inline]
pub(crate) fn fcntl_getfl(fd: usize) -> usize {
    unsafe { syscall2(SYS_FCNTL, fd, F_GETFL) }
}

#[inline]
pub(crate) fn fsync(fd: usize) -> usize {
    unsafe { syscall1(SYS_FSYNC, fd) }
}

#[inline]
pub(crate) fn fdatasync(fd: usize) -> usize {
    unsafe { syscall1(SYS_FDATASYNC, fd) }
}

#[inline]
pub(crate) fn socket(family: usize, ty: usize, proto: usize) -> usize {
    unsafe { syscall3(SYS_SOCKET, family, ty, proto) }
}

#[inline]
pub(crate) fn sigprocmask(how: usize, set: u64, want_old: bool) -> u64 {
    let mut old = 0u64;
    let oldp = if want_old { &raw mut old as usize } else { 0 };
    unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, how, &raw const set as usize, oldp, 8) };
    old
}

#[inline]
pub(crate) fn futex_wait(word: &core::sync::atomic::AtomicU32, expected: u32) -> usize {
    const SYS_FUTEX: usize = 202;
    const FUTEX_WAIT_PRIVATE: usize = 128;
    unsafe { syscall4(SYS_FUTEX, word as *const core::sync::atomic::AtomicU32 as usize, FUTEX_WAIT_PRIVATE, expected as usize, 0) }
}
