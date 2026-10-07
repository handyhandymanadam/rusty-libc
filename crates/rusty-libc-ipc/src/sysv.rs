use crate::util::{sc, sci};
use core::ffi::{c_int, c_long, c_ulong, c_void};
use rusty_libc_core::syscall::{syscall1, syscall2, syscall3, syscall4};
use rusty_libc_core::tls::syscall_cp;

pub const SYS_SHMGET: usize = 29;
pub const SYS_SHMAT: usize = 30;
pub const SYS_SHMCTL: usize = 31;
pub const SYS_SEMGET: usize = 64;
pub const SYS_SEMOP: usize = 65;
pub const SYS_SEMCTL: usize = 66;
pub const SYS_SHMDT: usize = 67;
pub const SYS_MSGGET: usize = 68;
pub const SYS_MSGSND: usize = 69;
pub const SYS_MSGRCV: usize = 70;
pub const SYS_MSGCTL: usize = 71;
pub const SYS_SEMTIMEDOP: usize = 220;
pub const SYS_STAT: usize = 4;

pub const IPC_CREAT: c_int = 0o1000;
pub const IPC_EXCL: c_int = 0o2000;
pub const IPC_NOWAIT: c_int = 0o4000;
pub const IPC_RMID: c_int = 0;
pub const IPC_SET: c_int = 1;
pub const IPC_STAT: c_int = 2;
pub const IPC_INFO: c_int = 3;
pub const IPC_PRIVATE: key_t = 0;

pub const MSG_NOERROR: c_int = 0o10000;
pub const MSG_EXCEPT: c_int = 0o20000;
pub const MSG_COPY: c_int = 0o40000;
pub const MSG_STAT: c_int = 11;
pub const MSG_INFO: c_int = 12;
pub const MSG_STAT_ANY: c_int = 13;

pub const SEM_UNDO: c_int = 0x1000;
pub const GETPID: c_int = 11;
pub const GETVAL: c_int = 12;
pub const GETALL: c_int = 13;
pub const GETNCNT: c_int = 14;
pub const GETZCNT: c_int = 15;
pub const SETVAL: c_int = 16;
pub const SETALL: c_int = 17;
pub const SEM_STAT: c_int = 18;
pub const SEM_INFO: c_int = 19;
pub const SEM_STAT_ANY: c_int = 20;

pub const SHM_R: c_int = 0o400;
pub const SHM_W: c_int = 0o200;
pub const SHM_RDONLY: c_int = 0o10000;
pub const SHM_RND: c_int = 0o20000;
pub const SHM_REMAP: c_int = 0o40000;
pub const SHM_EXEC: c_int = 0o100000;
pub const SHM_LOCK: c_int = 11;
pub const SHM_UNLOCK: c_int = 12;
pub const SHM_STAT: c_int = 13;
pub const SHM_INFO: c_int = 14;
pub const SHM_STAT_ANY: c_int = 15;
pub const SHM_DEST: c_int = 0o1000;
pub const SHM_LOCKED: c_int = 0o2000;
pub const SHM_HUGETLB: c_int = 0o4000;
pub const SHM_NORESERVE: c_int = 0o10000;
pub const SHM_HUGE_SHIFT: c_int = 26;
pub const SHM_HUGE_MASK: c_int = 0x3f;

#[allow(non_camel_case_types)]
pub type key_t = i32;
#[allow(non_camel_case_types)]
pub type time_t = i64;
#[allow(non_camel_case_types)]
pub type pid_t = i32;
#[allow(non_camel_case_types)]
pub type ssize_t = isize;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcPerm {
    pub key: key_t,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: u16,
    pub pad2: u16,
    pub reserved1: c_ulong,
    pub reserved2: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsqidDs {
    pub msg_perm: IpcPerm,
    pub msg_stime: time_t,
    pub msg_rtime: time_t,
    pub msg_ctime: time_t,
    pub msg_cbytes: c_ulong,
    pub msg_qnum: c_ulong,
    pub msg_qbytes: c_ulong,
    pub msg_lspid: pid_t,
    pub msg_lrpid: pid_t,
    pub reserved4: c_ulong,
    pub reserved5: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SemidDs {
    pub sem_perm: IpcPerm,
    pub sem_otime: time_t,
    pub sem_otime_high: c_ulong,
    pub sem_ctime: time_t,
    pub sem_ctime_high: c_ulong,
    pub sem_nsems: c_ulong,
    pub reserved3: c_ulong,
    pub reserved4: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmidDs {
    pub shm_perm: IpcPerm,
    pub shm_segsz: usize,
    pub shm_atime: time_t,
    pub shm_dtime: time_t,
    pub shm_ctime: time_t,
    pub shm_cpid: pid_t,
    pub shm_lpid: pid_t,
    pub shm_nattch: c_ulong,
    pub reserved5: c_ulong,
    pub reserved6: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsgInfo {
    pub msgpool: c_int,
    pub msgmap: c_int,
    pub msgmax: c_int,
    pub msgmnb: c_int,
    pub msgmni: c_int,
    pub msgssz: c_int,
    pub msgtql: c_int,
    pub msgseg: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SemInfo {
    pub semmap: c_int,
    pub semmni: c_int,
    pub semmns: c_int,
    pub semmnu: c_int,
    pub semmsl: c_int,
    pub semopm: c_int,
    pub semume: c_int,
    pub semusz: c_int,
    pub semvmx: c_int,
    pub semaem: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmInfoLimits {
    pub shmmax: c_ulong,
    pub shmmin: c_ulong,
    pub shmmni: c_ulong,
    pub shmseg: c_ulong,
    pub shmall: c_ulong,
    pub reserved1: c_ulong,
    pub reserved2: c_ulong,
    pub reserved3: c_ulong,
    pub reserved4: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmInfo {
    pub used_ids: c_int,
    pub shm_tot: c_ulong,
    pub shm_rss: c_ulong,
    pub shm_swp: c_ulong,
    pub swap_attempts: c_ulong,
    pub swap_successes: c_ulong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsgBuf {
    pub mtype: c_long,
    pub mtext: [u8; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Semun {
    pub val: c_int,
    pub buf: *mut SemidDs,
    pub array: *mut u16,
    pub info: *mut SemInfo,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

const _: () = {
    assert!(core::mem::size_of::<IpcPerm>() == 48);
    assert!(core::mem::size_of::<MsqidDs>() == 120);
    assert!(core::mem::size_of::<SemidDs>() == 104);
    assert!(core::mem::size_of::<ShmidDs>() == 112);
    assert!(core::mem::size_of::<MsgInfo>() == 32);
    assert!(core::mem::size_of::<SemInfo>() == 40);
    assert!(core::mem::size_of::<ShmInfoLimits>() == 72);
    assert!(core::mem::size_of::<ShmInfo>() == 48);
    assert!(core::mem::size_of::<Sembuf>() == 6);
    assert!(core::mem::size_of::<Semun>() == 8);
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftok(path: *const core::ffi::c_char, id: c_int) -> key_t {
    let mut st = [0u64; 18];
    if sc(unsafe { syscall2(SYS_STAT, path as usize, st.as_mut_ptr() as usize) }) < 0 {
        return -1;
    }
    (((st[1] & 0xffff) | ((st[0] & 0xff) << 16) | (((id as u64) & 0xff) << 24)) as u32) as key_t
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn msgget(key: key_t, flags: c_int) -> c_int {
    sci(unsafe { syscall2(SYS_MSGGET, key as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn msgctl(id: c_int, cmd: c_int, buf: *mut MsqidDs) -> c_int {
    sci(unsafe { syscall3(SYS_MSGCTL, id as usize, cmd as usize, buf as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn msgsnd(id: c_int, msg: *const c_void, size: usize, flags: c_int) -> c_int {
    sci(unsafe { syscall_cp(SYS_MSGSND, id as usize, msg as usize, size, flags as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn msgrcv(id: c_int, msg: *mut c_void, size: usize, ty: c_long, flags: c_int) -> ssize_t {
    sc(unsafe { syscall_cp(SYS_MSGRCV, id as usize, msg as usize, size, ty as usize, flags as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn semget(key: key_t, nsems: c_int, flags: c_int) -> c_int {
    sci(unsafe { syscall3(SYS_SEMGET, key as usize, nsems as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn semop(id: c_int, ops: *mut Sembuf, n: usize) -> c_int {
    sci(unsafe { syscall3(SYS_SEMOP, id as usize, ops as usize, n) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn semtimedop(id: c_int, ops: *mut Sembuf, n: usize, timeout: *const Timespec) -> c_int {
    sci(unsafe { syscall4(SYS_SEMTIMEDOP, id as usize, ops as usize, n, timeout as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn semctl(id: c_int, num: c_int, cmd: c_int, mut args: ...) -> c_int {
    unsafe {
        let arg: usize = match cmd {
            SETVAL | GETALL | SETALL | IPC_STAT | IPC_SET | SEM_STAT | SEM_STAT_ANY | IPC_INFO | SEM_INFO => args.next_arg::<usize>(),
            _ => 0,
        };
        sci(syscall4(SYS_SEMCTL, id as usize, num as usize, cmd as usize, arg))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn shmget(key: key_t, size: usize, flags: c_int) -> c_int {
    sci(unsafe { syscall3(SYS_SHMGET, key as usize, size, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shmctl(id: c_int, cmd: c_int, buf: *mut ShmidDs) -> c_int {
    sci(unsafe { syscall3(SYS_SHMCTL, id as usize, cmd as usize, buf as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shmat(id: c_int, addr: *const c_void, flags: c_int) -> *mut c_void {
    sc(unsafe { syscall3(SYS_SHMAT, id as usize, addr as usize, flags as usize) }) as *mut c_void
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shmdt(addr: *const c_void) -> c_int {
    sci(unsafe { syscall1(SYS_SHMDT, addr as usize) })
}
