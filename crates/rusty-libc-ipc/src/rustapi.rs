//! Rust API: small safe wrappers for the System V queue, semaphore set and shared-memory segment.
//! No allocation: callers pass their own buffers. Errors are
//! `Errno` values straight from the kernel. The wrappers never remove an object by themselves
//! except `ShmMap` (which detaches on drop); call `remove` for the rest.
use crate::kernel;
use crate::sysv::*;
use crate::util::res;
use core::ffi::{c_int, c_long};
use rusty_libc_core::Errno;
use rusty_libc_core::syscall::{syscall1, syscall3, syscall4};
use rusty_libc_core::tls::syscall_cp;

/// A System V message queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgQueue {
    id: c_int,
}

impl MsgQueue {
    /// Open or create the queue for `key` (see msgget(2)).
    pub fn get(key: key_t, flags: c_int) -> Result<MsgQueue, Errno> {
        res(kernel::msgget(key as usize, flags as usize)).map(|id| MsgQueue { id: id as c_int })
    }
    /// A new private queue with permission bits `mode`.
    pub fn private(mode: c_int) -> Result<MsgQueue, Errno> {
        Self::get(IPC_PRIVATE, IPC_CREAT | IPC_EXCL | (mode & 0o777))
    }
    pub fn from_id(id: c_int) -> MsgQueue {
        MsgQueue { id }
    }
    pub fn id(&self) -> c_int {
        self.id
    }
    /// Send `data` with type `mtype` (> 0). `scratch` must hold 8 + `data.len()` bytes: the system
    /// call wants the type word and the text in one buffer. Cancellation point.
    pub fn send(&self, mtype: c_long, data: &[u8], scratch: &mut [u8], flags: c_int) -> Result<(), Errno> {
        if scratch.len() < 8 + data.len() {
            return Err(Errno(crate::util::EINVAL));
        }
        scratch[..8].copy_from_slice(&mtype.to_ne_bytes());
        scratch[8..8 + data.len()].copy_from_slice(data);
        // SAFETY: the kernel reads the type word and `data.len()` bytes of text from `scratch`, which holds them (checked).
        res(unsafe { syscall_cp(SYS_MSGSND, self.id as usize, scratch.as_ptr() as usize, data.len(), flags as usize, 0, 0) }).map(|_| ())
    }
    /// Receive a message selected by `mtype` (see msgrcv(2)) into `scratch` (8 bytes of type, then the
    /// text; the text can be at most `scratch.len() - 8`). Returns the type and the text.
    /// Cancellation point.
    pub fn recv<'a>(&self, mtype: c_long, scratch: &'a mut [u8], flags: c_int) -> Result<(c_long, &'a [u8]), Errno> {
        if scratch.len() < 8 {
            return Err(Errno(crate::util::EINVAL));
        }
        let max = scratch.len() - 8;
        // SAFETY: the kernel writes the type word and at most `max` bytes of text: `scratch` has 8 + `max` bytes.
        let n = res(unsafe { syscall_cp(SYS_MSGRCV, self.id as usize, scratch.as_mut_ptr() as usize, max, mtype as usize, flags as usize, 0) })?;
        let mut t = [0u8; 8];
        t.copy_from_slice(&scratch[..8]);
        Ok((c_long::from_ne_bytes(t), &scratch[8..8 + n]))
    }
    pub fn stat(&self) -> Result<MsqidDs, Errno> {
        let mut ds = MsqidDs::default();
        // SAFETY: IPC_STAT writes one `struct msqid_ds` into the local `ds`.
        res(unsafe { syscall3(SYS_MSGCTL, self.id as usize, IPC_STAT as usize, &raw mut ds as usize) })?;
        Ok(ds)
    }
    /// Change `msg_perm.uid/gid/mode` and `msg_qbytes` (IPC_SET).
    pub fn set(&self, ds: &MsqidDs) -> Result<(), Errno> {
        // SAFETY: IPC_SET reads one `struct msqid_ds` from the borrowed `ds`.
        res(unsafe { syscall3(SYS_MSGCTL, self.id as usize, IPC_SET as usize, ds as *const MsqidDs as usize) }).map(|_| ())
    }
    pub fn remove(&self) -> Result<(), Errno> {
        res(kernel::msgctl_rmid(self.id as usize)).map(|_| ())
    }
}

/// A System V semaphore set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemSet {
    id: c_int,
}

impl SemSet {
    pub fn get(key: key_t, nsems: c_int, flags: c_int) -> Result<SemSet, Errno> {
        res(kernel::semget(key as usize, nsems as usize, flags as usize)).map(|id| SemSet { id: id as c_int })
    }
    pub fn private(nsems: c_int, mode: c_int) -> Result<SemSet, Errno> {
        Self::get(IPC_PRIVATE, nsems, IPC_CREAT | IPC_EXCL | (mode & 0o777))
    }
    pub fn from_id(id: c_int) -> SemSet {
        SemSet { id }
    }
    pub fn id(&self) -> c_int {
        self.id
    }
    /// Apply `ops` atomically (not a cancellation point, like glibc's semop).
    pub fn op(&self, ops: &mut [Sembuf]) -> Result<(), Errno> {
        self.semtimedop(ops, None)
    }
    /// Apply `ops` atomically, giving up with EAGAIN after `timeout` (not a cancellation point).
    pub fn timed_op(&self, ops: &mut [Sembuf], timeout: &Timespec) -> Result<(), Errno> {
        self.semtimedop(ops, Some(timeout))
    }
    fn semtimedop(&self, ops: &mut [Sembuf], timeout: Option<&Timespec>) -> Result<(), Errno> {
        let tp = timeout.map_or(0, |t| t as *const Timespec as usize);
        // SAFETY: the kernel reads `ops.len()` operations from the borrowed slice and the borrowed timeout (or none).
        res(unsafe { syscall4(SYS_SEMTIMEDOP, self.id as usize, ops.as_mut_ptr() as usize, ops.len(), tp) }).map(|_| ())
    }
    /// semctl for the commands whose argument is a number or unused.
    fn ctl(&self, num: c_int, cmd: c_int, arg: usize) -> Result<usize, Errno> {
        res(kernel::semctl_val(self.id as usize, num as usize, cmd, arg))
    }

    pub fn value(&self, num: c_int) -> Result<c_int, Errno> {
        self.ctl(num, GETVAL, 0).map(|v| v as c_int)
    }
    pub fn set_value(&self, num: c_int, v: c_int) -> Result<(), Errno> {
        self.ctl(num, SETVAL, v as usize).map(|_| ())
    }
    pub fn pid(&self, num: c_int) -> Result<c_int, Errno> {
        self.ctl(num, GETPID, 0).map(|v| v as c_int)
    }
    pub fn waiting_for_increase(&self, num: c_int) -> Result<c_int, Errno> {
        self.ctl(num, GETNCNT, 0).map(|v| v as c_int)
    }
    pub fn waiting_for_zero(&self, num: c_int) -> Result<c_int, Errno> {
        self.ctl(num, GETZCNT, 0).map(|v| v as c_int)
    }
    /// All values; `out.len()` must be the set's size.
    pub fn values(&self, out: &mut [u16]) -> Result<(), Errno> {
        // SAFETY: GETALL writes one u16 per semaphore into `out`. The kernel reads the set's size, not ours, so a
        // shorter slice is the documented caller error ("must be the set's size").
        res(unsafe { syscall4(SYS_SEMCTL, self.id as usize, 0, GETALL as usize, out.as_mut_ptr() as usize) }).map(|_| ())
    }
    pub fn set_values(&self, vals: &[u16]) -> Result<(), Errno> {
        // SAFETY: SETALL reads one u16 per semaphore from `vals` (the set's size, as for `values`).
        res(unsafe { syscall4(SYS_SEMCTL, self.id as usize, 0, SETALL as usize, vals.as_ptr() as usize) }).map(|_| ())
    }
    pub fn stat(&self) -> Result<SemidDs, Errno> {
        let mut ds = SemidDs::default();
        // SAFETY: IPC_STAT writes one `struct semid_ds` into the local `ds`.
        res(unsafe { syscall4(SYS_SEMCTL, self.id as usize, 0, IPC_STAT as usize, &raw mut ds as usize) })?;
        Ok(ds)
    }
    pub fn remove(&self) -> Result<(), Errno> {
        self.ctl(0, IPC_RMID, 0).map(|_| ())
    }
}

/// A System V shared-memory segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shm {
    id: c_int,
}

impl Shm {
    pub fn get(key: key_t, size: usize, flags: c_int) -> Result<Shm, Errno> {
        res(kernel::shmget(key as usize, size, flags as usize)).map(|id| Shm { id: id as c_int })
    }
    pub fn private(size: usize, mode: c_int) -> Result<Shm, Errno> {
        Self::get(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | (mode & 0o777))
    }
    pub fn from_id(id: c_int) -> Shm {
        Shm { id }
    }
    pub fn id(&self) -> c_int {
        self.id
    }
    /// Map the segment anywhere (`flags` as for shmat: SHM_RDONLY, SHM_EXEC). The mapping is
    /// detached when the returned value is dropped.
    pub fn attach(&self, flags: c_int) -> Result<ShmMap, Errno> {
        let len = self.stat()?.shm_segsz;
        // SAFETY: address NULL: the kernel picks a free range, so no existing memory is replaced.
        let p = res(unsafe { syscall3(SYS_SHMAT, self.id as usize, 0, flags as usize) })?;
        Ok(ShmMap { ptr: p as *mut u8, len })
    }
    pub fn stat(&self) -> Result<ShmidDs, Errno> {
        let mut ds = ShmidDs::default();
        // SAFETY: IPC_STAT writes one `struct shmid_ds` into the local `ds`.
        res(unsafe { syscall3(SYS_SHMCTL, self.id as usize, IPC_STAT as usize, &raw mut ds as usize) })?;
        Ok(ds)
    }
    pub fn remove(&self) -> Result<(), Errno> {
        res(kernel::shmctl_rmid(self.id as usize)).map(|_| ())
    }
}

/// An attached shared-memory segment; detaches on drop.
pub struct ShmMap {
    ptr: *mut u8,
    len: usize,
}

impl ShmMap {
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The mapped bytes. Other processes may write them at the same time, so the contents can change
    /// under the slice: use volatile or atomic accesses for data that is shared live.
    ///
    /// # Safety
    /// The segment must be attached read-write for `as_mut_slice`; nothing may alias the slice
    /// in this process.
    pub unsafe fn as_slice(&self) -> &[u8] {
        // SAFETY: the mapping covers `len` bytes while `self` lives; no aliasing writes is the caller's contract.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
    /// # Safety
    /// See [`ShmMap::as_slice`].
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_mut_slice(&self) -> &mut [u8] {
        // SAFETY: as `as_slice`; writable and unaliased is the caller's contract.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for ShmMap {
    fn drop(&mut self) {
        // SAFETY: `ptr` is our own attachment (from `attach`); the slices borrowed from `self` are gone with the borrow.
        unsafe { syscall1(SYS_SHMDT, self.ptr as usize) };
    }
}
