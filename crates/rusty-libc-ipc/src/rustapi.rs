use crate::sysv::*;
use crate::util::res;
use core::ffi::{c_int, c_long};
use rusty_libc_core::Errno;
use rusty_libc_core::syscall::{syscall1, syscall2, syscall3, syscall4};
use rusty_libc_core::tls::syscall_cp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgQueue {
    id: c_int,
}

impl MsgQueue {
    pub fn get(key: key_t, flags: c_int) -> Result<MsgQueue, Errno> {
        res(unsafe { syscall2(SYS_MSGGET, key as usize, flags as usize) }).map(|id| MsgQueue { id: id as c_int })
    }
    pub fn private(mode: c_int) -> Result<MsgQueue, Errno> {
        Self::get(IPC_PRIVATE, IPC_CREAT | IPC_EXCL | (mode & 0o777))
    }
    pub fn from_id(id: c_int) -> MsgQueue {
        MsgQueue { id }
    }
    pub fn id(&self) -> c_int {
        self.id
    }
    pub fn send(&self, mtype: c_long, data: &[u8], scratch: &mut [u8], flags: c_int) -> Result<(), Errno> {
        if scratch.len() < 8 + data.len() {
            return Err(Errno(crate::util::EINVAL));
        }
        scratch[..8].copy_from_slice(&mtype.to_ne_bytes());
        scratch[8..8 + data.len()].copy_from_slice(data);
        res(unsafe { syscall_cp(SYS_MSGSND, self.id as usize, scratch.as_ptr() as usize, data.len(), flags as usize, 0, 0) }).map(|_| ())
    }
    pub fn recv<'a>(&self, mtype: c_long, scratch: &'a mut [u8], flags: c_int) -> Result<(c_long, &'a [u8]), Errno> {
        if scratch.len() < 8 {
            return Err(Errno(crate::util::EINVAL));
        }
        let max = scratch.len() - 8;
        let n = res(unsafe { syscall_cp(SYS_MSGRCV, self.id as usize, scratch.as_mut_ptr() as usize, max, mtype as usize, flags as usize, 0) })?;
        let mut t = [0u8; 8];
        t.copy_from_slice(&scratch[..8]);
        Ok((c_long::from_ne_bytes(t), &scratch[8..8 + n]))
    }
    pub fn stat(&self) -> Result<MsqidDs, Errno> {
        let mut ds = MsqidDs::default();
        res(unsafe { syscall3(SYS_MSGCTL, self.id as usize, IPC_STAT as usize, &mut ds as *mut MsqidDs as usize) })?;
        Ok(ds)
    }
    pub fn set(&self, ds: &MsqidDs) -> Result<(), Errno> {
        res(unsafe { syscall3(SYS_MSGCTL, self.id as usize, IPC_SET as usize, ds as *const MsqidDs as usize) }).map(|_| ())
    }
    pub fn remove(&self) -> Result<(), Errno> {
        res(unsafe { syscall3(SYS_MSGCTL, self.id as usize, IPC_RMID as usize, 0) }).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemSet {
    id: c_int,
}

impl SemSet {
    pub fn get(key: key_t, nsems: c_int, flags: c_int) -> Result<SemSet, Errno> {
        res(unsafe { syscall3(SYS_SEMGET, key as usize, nsems as usize, flags as usize) }).map(|id| SemSet { id: id as c_int })
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
    pub fn op(&self, ops: &mut [Sembuf]) -> Result<(), Errno> {
        res(unsafe { syscall3(SYS_SEMOP, self.id as usize, ops.as_mut_ptr() as usize, ops.len()) }).map(|_| ())
    }
    pub fn timed_op(&self, ops: &mut [Sembuf], timeout: &Timespec) -> Result<(), Errno> {
        res(unsafe { syscall4(SYS_SEMTIMEDOP, self.id as usize, ops.as_mut_ptr() as usize, ops.len(), timeout as *const Timespec as usize) })
            .map(|_| ())
    }
    fn ctl(&self, num: c_int, cmd: c_int, arg: usize) -> Result<usize, Errno> {
        res(unsafe { syscall4(SYS_SEMCTL, self.id as usize, num as usize, cmd as usize, arg) })
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
    pub fn values(&self, out: &mut [u16]) -> Result<(), Errno> {
        self.ctl(0, GETALL, out.as_mut_ptr() as usize).map(|_| ())
    }
    pub fn set_values(&self, vals: &[u16]) -> Result<(), Errno> {
        self.ctl(0, SETALL, vals.as_ptr() as usize).map(|_| ())
    }
    pub fn stat(&self) -> Result<SemidDs, Errno> {
        let mut ds = SemidDs::default();
        self.ctl(0, IPC_STAT, &mut ds as *mut SemidDs as usize)?;
        Ok(ds)
    }
    pub fn remove(&self) -> Result<(), Errno> {
        self.ctl(0, IPC_RMID, 0).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shm {
    id: c_int,
}

impl Shm {
    pub fn get(key: key_t, size: usize, flags: c_int) -> Result<Shm, Errno> {
        res(unsafe { syscall3(SYS_SHMGET, key as usize, size, flags as usize) }).map(|id| Shm { id: id as c_int })
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
    pub fn attach(&self, flags: c_int) -> Result<ShmMap, Errno> {
        let len = self.stat()?.shm_segsz;
        let p = res(unsafe { syscall3(SYS_SHMAT, self.id as usize, 0, flags as usize) })?;
        Ok(ShmMap { ptr: p as *mut u8, len })
    }
    pub fn stat(&self) -> Result<ShmidDs, Errno> {
        let mut ds = ShmidDs::default();
        res(unsafe { syscall3(SYS_SHMCTL, self.id as usize, IPC_STAT as usize, &mut ds as *mut ShmidDs as usize) })?;
        Ok(ds)
    }
    pub fn remove(&self) -> Result<(), Errno> {
        res(unsafe { syscall3(SYS_SHMCTL, self.id as usize, IPC_RMID as usize, 0) }).map(|_| ())
    }
}

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
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_mut_slice(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for ShmMap {
    fn drop(&mut self) {
        unsafe { syscall1(SYS_SHMDT, self.ptr as usize) };
    }
}
