use super::{errno, host_errno, lock};
use crate::rustapi::*;
use crate::sysv::*;
use core::ffi::{c_long, c_void};
use rusty_libc_core::Errno;
use std::ffi::CString;

/// Removes the object on drop (also when a test fails half way).
struct Guard(u8, i32);
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            match self.0 {
                b'm' => libc::msgctl(self.1, libc::IPC_RMID, core::ptr::null_mut()),
                b's' => libc::semctl(self.1, 0, libc::IPC_RMID),
                _ => libc::shmctl(self.1, libc::IPC_RMID, core::ptr::null_mut()),
            };
        }
    }
}

fn bytes<T>(v: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) }
}

fn msq() -> (i32, Guard) {
    let id = msgget(IPC_PRIVATE, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(id >= 0, "msgget errno {}", errno());
    (id, Guard(b'm', id))
}

fn sem(n: i32) -> (i32, Guard) {
    let id = semget(IPC_PRIVATE, n, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(id >= 0, "semget errno {}", errno());
    (id, Guard(b's', id))
}

fn shm(size: usize) -> (i32, Guard) {
    let id = shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(id >= 0, "shmget errno {}", errno());
    (id, Guard(b'h', id))
}

/// A key that no other test run uses: from the process id and a per-test number.
fn key(n: i32) -> key_t {
    0x2b00_0000 | ((unsafe { libc::getpid() } & 0xfffff) << 4) | (n & 15)
}

#[test]
fn layouts_and_constants_equal_glibc() {
    use core::mem::size_of;
    assert_eq!(size_of::<IpcPerm>(), size_of::<libc::ipc_perm>());
    assert_eq!(size_of::<MsqidDs>(), size_of::<libc::msqid_ds>());
    assert_eq!(size_of::<SemidDs>(), size_of::<libc::semid_ds>());
    assert_eq!(size_of::<ShmidDs>(), size_of::<libc::shmid_ds>());
    assert_eq!(size_of::<Sembuf>(), size_of::<libc::sembuf>());
    assert_eq!(size_of::<MsgInfo>(), size_of::<libc::msginfo>());
    assert_eq!(IPC_CREAT, libc::IPC_CREAT);
    assert_eq!(IPC_EXCL, libc::IPC_EXCL);
    assert_eq!(IPC_NOWAIT, libc::IPC_NOWAIT);
    assert_eq!((IPC_RMID, IPC_SET, IPC_STAT, IPC_INFO), (libc::IPC_RMID, libc::IPC_SET, libc::IPC_STAT, libc::IPC_INFO));
    assert_eq!((MSG_NOERROR, MSG_EXCEPT, MSG_COPY), (libc::MSG_NOERROR, libc::MSG_EXCEPT, libc::MSG_COPY));
    assert_eq!((MSG_STAT, MSG_INFO, MSG_STAT_ANY), (libc::MSG_STAT, libc::MSG_INFO, 13));
    assert_eq!(SEM_UNDO, libc::SEM_UNDO);
    assert_eq!((GETPID, GETVAL, GETALL, GETNCNT, GETZCNT, SETVAL, SETALL), (libc::GETPID, libc::GETVAL, libc::GETALL, libc::GETNCNT, libc::GETZCNT, libc::SETVAL, libc::SETALL));
    assert_eq!((SEM_STAT, SEM_INFO), (libc::SEM_STAT, libc::SEM_INFO));
    assert_eq!((SHM_RDONLY, SHM_RND, SHM_REMAP, SHM_EXEC), (libc::SHM_RDONLY, libc::SHM_RND, libc::SHM_REMAP, libc::SHM_EXEC));
    assert_eq!((SHM_LOCK, SHM_UNLOCK), (libc::SHM_LOCK, libc::SHM_UNLOCK));
    assert_eq!((SHM_STAT, SHM_INFO, SHM_STAT_ANY), (13, 14, 15)); // the libc crate lacks them: the C constants test checks
}

#[test]
fn ftok_equals_host() {
    let dir = std::env::temp_dir();
    let f = dir.join(format!("ipc-ftok-{}", std::process::id()));
    std::fs::write(&f, b"x").unwrap();
    let mut paths: Vec<CString> = ["/", "/tmp", "/etc/passwd", "/usr", "/proc/self", "/dev/null", "/nonexistent/x", "/etc/passwd/x"]
        .iter()
        .map(|s| CString::new(*s).unwrap())
        .collect();
    paths.push(CString::new(f.to_str().unwrap()).unwrap());
    for p in &paths {
        for id in [0, 1, 65, 255, 256, 0x1ff, -1, i32::MAX, i32::MIN] {
            let a = unsafe { ftok(p.as_ptr(), id) };
            let ea = errno();
            let b = unsafe { libc::ftok(p.as_ptr(), id) };
            let eb = host_errno();
            assert_eq!(a, b, "ftok({:?}, {})", p, id);
            if b == -1 {
                assert_eq!(ea, eb, "errno for {:?}", p);
            }
        }
    }
    std::fs::remove_file(&f).unwrap();
}

#[test]
fn msg_roundtrip_types_and_flags() {
    let _l = lock();
    let (id, _g) = msq();
    #[repr(C)]
    struct M {
        t: c_long,
        text: [u8; 64],
    }
    let send = |t: c_long, s: &[u8], fl: i32| -> i32 {
        let mut m = M { t, text: [0; 64] };
        m.text[..s.len()].copy_from_slice(s);
        unsafe { msgsnd(id, &m as *const M as *const c_void, s.len(), fl) }
    };
    let recv = |t: c_long, max: usize, fl: i32| -> (isize, c_long, Vec<u8>) {
        let mut m = M { t: 0, text: [0xee; 64] };
        let n = unsafe { msgrcv(id, &mut m as *mut M as *mut c_void, max, t, fl) };
        (n, m.t, if n > 0 { m.text[..n as usize].to_vec() } else { vec![] })
    };
    assert_eq!(send(5, b"five", 0), 0);
    assert_eq!(send(2, b"two", 0), 0);
    assert_eq!(send(9, b"nine", 0), 0);
    assert_eq!(send(2, b"deux", 0), 0);
    let st = MsqidDs { ..{ let mut d = MsqidDs::default(); assert_eq!(unsafe { msgctl(id, IPC_STAT, &mut d) }, 0); d } };
    assert_eq!(st.msg_qnum, 4);
    assert_eq!(st.msg_cbytes, 15);
    assert_eq!(st.msg_lspid, unsafe { libc::getpid() });
    // type 0: oldest; positive: oldest of that type; negative: lowest type <= |t|; MSG_EXCEPT
    assert_eq!(recv(0, 64, 0), (4, 5, b"five".to_vec()));
    assert_eq!(recv(2, 64, 0), (3, 2, b"two".to_vec()));
    assert_eq!(send(1, b"one", 0), 0);
    assert_eq!(recv(-9, 64, 0), (3, 1, b"one".to_vec()));
    assert_eq!(recv(-2, 64, 0), (4, 2, b"deux".to_vec()));
    assert_eq!(send(9, b"nine2", 0), 0);
    assert_eq!(send(3, b"three", 0), 0);
    assert_eq!(recv(9, 64, MSG_EXCEPT), (5, 3, b"three".to_vec()));
    // empty for that selection: ENOMSG without IPC_NOWAIT would block; with it:
    let (n, _, _) = recv(7, 64, IPC_NOWAIT);
    assert_eq!((n, errno()), (-1, 42), "ENOMSG");
    // too long: E2BIG, message stays; MSG_NOERROR truncates and removes it
    let (n, _, _) = recv(9, 2, 0);
    assert_eq!((n, errno()), (-1, 7), "E2BIG");
    let (n, t, text) = recv(9, 2, MSG_NOERROR);
    assert_eq!((n, t, text), (2, 9, b"ni".to_vec()));
    assert_eq!(recv(9, 64, 0), (5, 9, b"nine2".to_vec()));
    // empty queue, IPC_NOWAIT: ENOMSG
    let (n, _, _) = recv(0, 64, IPC_NOWAIT);
    assert_eq!((n, errno()), (-1, 42));
    // zero-length message
    assert_eq!(send(4, b"", 0), 0);
    assert_eq!(recv(0, 64, 0), (0, 4, vec![]));
    // type 0 is invalid for msgsnd
    assert_eq!(send(0, b"x", 0), -1);
    assert_eq!(errno(), 22);
}

#[test]
fn msg_errors() {
    let _l = lock();
    let (id, _g) = msq();
    // EEXIST and ENOENT on keyed queues
    let k = key(1);
    let a = msgget(k, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(a >= 0);
    let _ga = Guard(b'm', a);
    assert_eq!(msgget(k, IPC_CREAT | IPC_EXCL | 0o600), -1);
    assert_eq!(errno(), 17);
    assert_eq!(msgget(k, 0), a);
    assert_eq!(msgget(key(2), 0), -1);
    assert_eq!(errno(), 2);
    // EINVAL for a bad id; EIDRM is for a removed queue after use
    let mut d = MsqidDs::default();
    assert_eq!(unsafe { msgctl(-1, IPC_STAT, &mut d) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { msgctl(id, 99, &mut d) }, -1);
    assert_eq!(errno(), 22);
    // EAGAIN: fill the queue (msg_qbytes 16384) with IPC_NOWAIT
    #[repr(C)]
    struct M {
        t: c_long,
        text: [u8; 4096],
    }
    let m = M { t: 1, text: [7; 4096] };
    let mut sent = 0;
    loop {
        let r = unsafe { msgsnd(id, &m as *const M as *const c_void, 4096, IPC_NOWAIT) };
        if r < 0 {
            assert_eq!(errno(), 11, "EAGAIN");
            break;
        }
        sent += 1;
        assert!(sent < 10);
    }
    assert_eq!(sent, 4);
    // EACCES: no permission on the queue after IPC_SET of the mode (own queue, so msgsnd as owner still works:
    // check instead the bad-pointer error)
    let r = unsafe { msgsnd(id, 8usize as *const c_void, 4, IPC_NOWAIT) };
    assert_eq!((r, errno()), (-1, 14), "EFAULT");
    // msgrcv with msgsz too big for the kernel
    let r = unsafe { msgrcv(id, core::ptr::null_mut(), usize::MAX, 0, IPC_NOWAIT) };
    assert_eq!((r, errno()), (-1, 22));
}

#[test]
fn msg_idrm_wakes_blocked_receiver() {
    let _l = lock();
    let (id, g) = msq();
    let t = std::thread::spawn(move || {
        let mut m = [0u8; 64];
        let r = unsafe { msgrcv(id, m.as_mut_ptr() as *mut c_void, 8, 0, 0) };
        (r, errno())
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(unsafe { msgctl(id, IPC_RMID, core::ptr::null_mut()) }, 0);
    let (r, e) = t.join().unwrap();
    assert_eq!((r, e), (-1, 43), "EIDRM");
    // second removal: EINVAL
    assert_eq!(unsafe { msgctl(id, IPC_RMID, core::ptr::null_mut()) }, -1);
    assert_eq!(errno(), 22);
    core::mem::forget(g);
}

#[test]
fn msg_ctl_stat_info_equal_host() {
    let _l = lock();
    let (id, _g) = msq();
    let mut a = MsqidDs::default();
    let mut b: libc::msqid_ds = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { msgctl(id, IPC_STAT, &mut a) }, 0);
    assert_eq!(unsafe { libc::msgctl(id, libc::IPC_STAT, &mut b) }, 0);
    assert_eq!(bytes(&a), bytes(&b));
    assert_eq!(a.msg_perm.mode, 0o600);
    assert_eq!(a.msg_perm.uid, unsafe { libc::geteuid() });
    // IPC_SET: shrink msg_qbytes, change mode
    a.msg_qbytes = 4096;
    a.msg_perm.mode = 0o640;
    assert_eq!(unsafe { msgctl(id, IPC_SET, &mut a) }, 0);
    assert_eq!(unsafe { libc::msgctl(id, libc::IPC_STAT, &mut b) }, 0);
    assert_eq!((b.msg_qbytes, b.msg_perm.mode & 0o777), (4096, 0o640));
    let mut c = MsqidDs::default();
    assert_eq!(unsafe { msgctl(id, IPC_STAT, &mut c) }, 0);
    assert_eq!(bytes(&c), bytes(&b));
    // raising msg_qbytes above msgmnb needs CAP_SYS_RESOURCE: EPERM for us
    c.msg_qbytes = 1 << 30;
    assert_eq!(unsafe { msgctl(id, IPC_SET, &mut c) }, -1);
    assert_eq!(errno(), 1);
    // IPC_INFO and MSG_INFO (structure msginfo)
    let mut i1 = MsgInfo::default();
    let mut i2: libc::msginfo = unsafe { core::mem::zeroed() };
    let r1 = unsafe { msgctl(0, IPC_INFO, &mut i1 as *mut MsgInfo as *mut MsqidDs) };
    let r2 = unsafe { libc::msgctl(0, libc::IPC_INFO, &mut i2 as *mut libc::msginfo as *mut libc::msqid_ds) };
    assert_eq!(r1, r2);
    assert_eq!(bytes(&i1), bytes(&i2));
    let mut j1 = MsgInfo::default();
    let mut j2: libc::msginfo = unsafe { core::mem::zeroed() };
    let r1 = unsafe { msgctl(0, MSG_INFO, &mut j1 as *mut MsgInfo as *mut MsqidDs) };
    let r2 = unsafe { libc::msgctl(0, libc::MSG_INFO, &mut j2 as *mut libc::msginfo as *mut libc::msqid_ds) };
    assert_eq!(r1, r2);
    assert_eq!(bytes(&j1), bytes(&j2));
    // MSG_STAT by index returns the id
    let mut s1 = MsqidDs::default();
    let r1 = unsafe { msgctl(r1.max(0), MSG_STAT, &mut s1) };
    assert!(r1 >= 0 || errno() == 22);
    let mut s3 = MsqidDs::default();
    let r3 = unsafe { msgctl(id, MSG_STAT_ANY, &mut s3) };
    let mut s4: libc::msqid_ds = unsafe { core::mem::zeroed() };
    let r4 = unsafe { libc::msgctl(id, 13, &mut s4) };
    assert_eq!(r3, r4);
}

#[test]
fn msg_rust_api() {
    let _l = lock();
    let q = MsgQueue::private(0o600).unwrap();
    let _g = Guard(b'm', q.id());
    let mut scratch = [0u8; 64];
    q.send(7, b"hello", &mut scratch, 0).unwrap();
    q.send(3, b"abc", &mut scratch, 0).unwrap();
    assert_eq!(q.stat().unwrap().msg_qnum, 2);
    let mut rb = [0u8; 64];
    let (t, text) = q.recv(3, &mut rb, 0).unwrap();
    assert_eq!((t, text), (3, &b"abc"[..]));
    let mut small = [0u8; 10];
    assert_eq!(q.recv(0, &mut small, 0).unwrap_err(), Errno(7));
    assert_eq!(q.recv(0, &mut rb, IPC_NOWAIT).unwrap(), (7, &b"hello"[..]));
    assert_eq!(q.recv(0, &mut rb, IPC_NOWAIT).unwrap_err(), Errno(42));
    assert_eq!(q.send(1, b"toolong", &mut small, 0).unwrap_err(), Errno(22));
    let mut st = q.stat().unwrap();
    st.msg_qbytes = 8192;
    q.set(&st).unwrap();
    assert_eq!(q.stat().unwrap().msg_qbytes, 8192);
    q.remove().unwrap();
    assert_eq!(q.stat().unwrap_err(), Errno(22));
    core::mem::forget(_g);
}

#[test]
fn sem_ops_undo_and_timeouts() {
    let _l = lock();
    let (id, _g) = sem(3);
    let mut a = [0u16; 3];
    // SETVAL / GETVAL / GETALL / SETALL
    assert_eq!(unsafe { semctl(id, 1, SETVAL, 5usize) }, 0);
    assert_eq!(unsafe { semctl(id, 1, GETVAL) }, 5);
    assert_eq!(unsafe { semctl(id, 0, GETALL, a.as_mut_ptr()) }, 0);
    assert_eq!(a, [0, 5, 0]);
    let set = [1u16, 2, 3];
    assert_eq!(unsafe { semctl(id, 0, SETALL, set.as_ptr()) }, 0);
    assert_eq!(unsafe { semctl(id, 2, GETVAL) }, 3);
    assert_eq!(unsafe { semctl(id, 0, GETPID) }, unsafe { libc::semctl(id, 0, libc::GETPID) });
    // atomic set: all or nothing (second op would block with IPC_NOWAIT: EAGAIN, nothing applied)
    let mut ops = [Sembuf { sem_num: 0, sem_op: 1, sem_flg: 0 }, Sembuf { sem_num: 1, sem_op: -5, sem_flg: IPC_NOWAIT as i16 }];
    assert_eq!(unsafe { semop(id, ops.as_mut_ptr(), 2) }, -1);
    assert_eq!(errno(), 11);
    assert_eq!(unsafe { semctl(id, 0, GETVAL) }, 1);
    ops[1].sem_op = -2;
    assert_eq!(unsafe { semop(id, ops.as_mut_ptr(), 2) }, 0);
    assert_eq!(unsafe { semctl(id, 0, GETALL, a.as_mut_ptr()) }, 0);
    assert_eq!(a, [2, 0, 3]);
    assert_eq!(unsafe { semctl(id, 0, GETPID) }, unsafe { libc::getpid() });
    // wait for zero with IPC_NOWAIT
    let mut z = [Sembuf { sem_num: 0, sem_op: 0, sem_flg: IPC_NOWAIT as i16 }];
    assert_eq!(unsafe { semop(id, z.as_mut_ptr(), 1) }, -1);
    assert_eq!(errno(), 11);
    // timeout: semtimedop returns EAGAIN after the time
    let mut w = [Sembuf { sem_num: 1, sem_op: -1, sem_flg: 0 }];
    let ts = Timespec { tv_sec: 0, tv_nsec: 100_000_000 };
    let t0 = std::time::Instant::now();
    assert_eq!(unsafe { semtimedop(id, w.as_mut_ptr(), 1, &ts) }, -1);
    assert_eq!(errno(), 11);
    let dt = t0.elapsed().as_millis();
    assert!((90..1500).contains(&dt), "timed out after {} ms", dt);
    // invalid timeout
    let bad = Timespec { tv_sec: 0, tv_nsec: 2_000_000_000 };
    assert_eq!(unsafe { semtimedop(id, w.as_mut_ptr(), 1, &bad) }, -1);
    assert_eq!(errno(), 22);
    // GETNCNT / GETZCNT with a waiting thread
    let t = std::thread::spawn(move || {
        let mut o = [Sembuf { sem_num: 1, sem_op: -1, sem_flg: 0 }];
        unsafe { semop(id, o.as_mut_ptr(), 1) }
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(unsafe { semctl(id, 1, GETNCNT) }, 1);
    assert_eq!(unsafe { semctl(id, 1, GETZCNT) }, 0);
    let mut up = [Sembuf { sem_num: 1, sem_op: 1, sem_flg: 0 }];
    assert_eq!(unsafe { semop(id, up.as_mut_ptr(), 1) }, 0);
    assert_eq!(t.join().unwrap(), 0);
    // SEM_UNDO: a child adds 4 with undo and exits: the value goes back
    let before = unsafe { semctl(id, 2, GETVAL) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut o = [Sembuf { sem_num: 2, sem_op: 4, sem_flg: SEM_UNDO as i16 }];
        let r = unsafe { semop(id, o.as_mut_ptr(), 1) };
        let v = unsafe { semctl(id, 2, GETVAL) };
        unsafe { libc::_exit(if r == 0 && v == before + 4 { 0 } else { 1 }) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(status, 0);
    assert_eq!(unsafe { semctl(id, 2, GETVAL) }, before);
}

#[test]
fn sem_errors() {
    let _l = lock();
    let (id, _g) = sem(2);
    let k = key(3);
    let a = semget(k, 2, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(a >= 0);
    let _ga = Guard(b's', a);
    assert_eq!(semget(k, 2, IPC_CREAT | IPC_EXCL | 0o600), -1);
    assert_eq!(errno(), 17);
    assert_eq!(semget(key(4), 2, 0), -1);
    assert_eq!(errno(), 2);
    // asking for more semaphores than the set has: EINVAL
    assert_eq!(semget(k, 5, 0), -1);
    assert_eq!(errno(), 22);
    assert_eq!(semget(IPC_PRIVATE, 0, IPC_CREAT | 0o600), -1);
    assert_eq!(errno(), 22);
    // ERANGE: value above SEMVMX (32767)
    assert_eq!(unsafe { semctl(id, 0, SETVAL, 40000usize) }, -1);
    assert_eq!(errno(), 34);
    // EFBIG: semaphore number out of range in semop
    let mut o = [Sembuf { sem_num: 5, sem_op: 1, sem_flg: 0 }];
    assert_eq!(unsafe { semop(id, o.as_mut_ptr(), 1) }, -1);
    assert_eq!(errno(), 27);
    // E2BIG: more than SEMOPM (500) operations
    let mut many = vec![Sembuf { sem_num: 0, sem_op: 0, sem_flg: IPC_NOWAIT as i16 }; 501];
    assert_eq!(unsafe { semop(id, many.as_mut_ptr(), 501) }, -1);
    assert_eq!(errno(), 7);
    // EINVAL: no operations, bad semnum in semctl, bad id
    assert_eq!(unsafe { semop(id, o.as_mut_ptr(), 0) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { semctl(id, 7, GETVAL) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { semctl(-1, 0, GETVAL) }, -1);
    assert_eq!(errno(), 22);
    // ERANGE: SETVAL via semop above the maximum
    let mut up = [Sembuf { sem_num: 0, sem_op: 32767, sem_flg: 0 }];
    assert_eq!(unsafe { semop(id, up.as_mut_ptr(), 1) }, 0);
    let mut up1 = [Sembuf { sem_num: 0, sem_op: 1, sem_flg: 0 }];
    assert_eq!(unsafe { semop(id, up1.as_mut_ptr(), 1) }, -1);
    assert_eq!(errno(), 34);
}

#[test]
fn sem_idrm() {
    let _l = lock();
    let (id, g) = sem(1);
    let t = std::thread::spawn(move || {
        let mut o = [Sembuf { sem_num: 0, sem_op: -1, sem_flg: 0 }];
        let r = unsafe { semop(id, o.as_mut_ptr(), 1) };
        (r, errno())
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(unsafe { semctl(id, 0, IPC_RMID) }, 0);
    assert_eq!(t.join().unwrap(), (-1, 43));
    core::mem::forget(g);
}

#[test]
fn sem_ctl_stat_info_equal_host() {
    let _l = lock();
    let (id, _g) = sem(4);
    let mut a = SemidDs::default();
    let mut b: libc::semid_ds = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { semctl(id, 0, IPC_STAT, &mut a as *mut SemidDs) }, 0);
    assert_eq!(unsafe { libc::semctl(id, 0, libc::IPC_STAT, &mut b as *mut libc::semid_ds) }, 0);
    assert_eq!(bytes(&a), bytes(&b));
    assert_eq!(a.sem_nsems, 4);
    let mut up = [Sembuf { sem_num: 3, sem_op: 1, sem_flg: 0 }];
    assert_eq!(unsafe { semop(id, up.as_mut_ptr(), 1) }, 0);
    assert_eq!(unsafe { semctl(id, 0, IPC_STAT, &mut a as *mut SemidDs) }, 0);
    assert_eq!(unsafe { libc::semctl(id, 0, libc::IPC_STAT, &mut b as *mut libc::semid_ds) }, 0);
    assert_eq!(bytes(&a), bytes(&b));
    assert!(a.sem_otime > 0);
    // IPC_SET the mode
    a.sem_perm.mode = 0o660;
    assert_eq!(unsafe { semctl(id, 0, IPC_SET, &mut a as *mut SemidDs) }, 0);
    assert_eq!(unsafe { libc::semctl(id, 0, libc::IPC_STAT, &mut b as *mut libc::semid_ds) }, 0);
    assert_eq!(b.sem_perm.mode & 0o777, 0o660);
    // IPC_INFO / SEM_INFO
    let mut i1 = SemInfo::default();
    let mut i2: libc::seminfo = unsafe { core::mem::zeroed() };
    let r1 = unsafe { semctl(0, 0, IPC_INFO, &mut i1 as *mut SemInfo) };
    let r2 = unsafe { libc::semctl(0, 0, libc::IPC_INFO, &mut i2 as *mut libc::seminfo) };
    assert_eq!(r1, r2);
    assert_eq!(bytes(&i1), bytes(&i2));
    assert_eq!((i1.semmsl, i1.semopm, i1.semvmx), (32000, 500, 32767));
    let mut j1 = SemInfo::default();
    let mut j2: libc::seminfo = unsafe { core::mem::zeroed() };
    let r1 = unsafe { semctl(0, 0, SEM_INFO, &mut j1 as *mut SemInfo) };
    let r2 = unsafe { libc::semctl(0, 0, libc::SEM_INFO, &mut j2 as *mut libc::seminfo) };
    assert_eq!(r1, r2);
    assert_eq!((j1.semmni, j1.semmsl), (j2.semmni, j2.semmsl));
    // SEM_STAT_ANY on the index returns the id
    let mut s1 = SemidDs::default();
    let r3 = unsafe { semctl(id, 0, SEM_STAT_ANY, &mut s1 as *mut SemidDs) };
    let mut s2: libc::semid_ds = unsafe { core::mem::zeroed() };
    let r4 = unsafe { libc::semctl(id, 0, SEM_STAT_ANY, &mut s2 as *mut libc::semid_ds) };
    assert_eq!(r3, r4);
}

#[test]
fn sem_rust_api() {
    let _l = lock();
    let s = SemSet::private(2, 0o600).unwrap();
    let _g = Guard(b's', s.id());
    s.set_value(0, 3).unwrap();
    assert_eq!(s.value(0).unwrap(), 3);
    let mut all = [0u16; 2];
    s.values(&mut all).unwrap();
    assert_eq!(all, [3, 0]);
    s.set_values(&[9, 8]).unwrap();
    assert_eq!(s.value(1).unwrap(), 8);
    s.op(&mut [Sembuf { sem_num: 0, sem_op: -9, sem_flg: 0 }, Sembuf { sem_num: 1, sem_op: 1, sem_flg: 0 }]).unwrap();
    assert_eq!(s.value(1).unwrap(), 9);
    let e = s.timed_op(&mut [Sembuf { sem_num: 0, sem_op: -1, sem_flg: 0 }], &Timespec { tv_sec: 0, tv_nsec: 20_000_000 }).unwrap_err();
    assert_eq!(e, Errno(11));
    assert_eq!(s.stat().unwrap().sem_nsems, 2);
    assert_eq!(s.pid(1).unwrap(), unsafe { libc::getpid() });
    assert_eq!(s.waiting_for_increase(0).unwrap(), 0);
    assert_eq!(s.waiting_for_zero(0).unwrap(), 0);
    s.remove().unwrap();
    assert_eq!(s.value(0).unwrap_err(), Errno(22));
    core::mem::forget(_g);
}

#[test]
fn shm_shares_data_between_forked_processes() {
    let _l = lock();
    let (id, _g) = shm(8192);
    let p = unsafe { shmat(id, core::ptr::null(), 0) } as *mut u8;
    assert_ne!(p as isize, -1, "shmat errno {}", errno());
    assert_eq!(p as usize % 4096, 0);
    unsafe { core::ptr::write_bytes(p, 0, 8192) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // child: attach again (own address), read what the parent wrote, write a reply
        let q = unsafe { shmat(id, core::ptr::null(), 0) } as *mut u8;
        if q as isize == -1 {
            unsafe { libc::_exit(2) };
        }
        let mut ok = true;
        for i in 0..100 {
            ok &= unsafe { *q.add(i) } == i as u8 + 1;
        }
        // the inherited mapping is the same memory too
        ok &= unsafe { *p.add(99) } == 100;
        unsafe {
            for i in 0..100 {
                *q.add(4096 + i) = (255 - i) as u8;
            }
            shmdt(q as *const c_void);
            libc::_exit(if ok { 0 } else { 1 });
        }
    }
    unsafe {
        for i in 0..100 {
            *p.add(i) = i as u8 + 1;
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(status, 0);
    for i in 0..100 {
        assert_eq!(unsafe { *p.add(4096 + i) }, (255 - i) as u8);
    }
    // nattch is 1 again after the child detached; shmid_ds equals the host's
    let mut a = ShmidDs::default();
    let mut b: libc::shmid_ds = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { shmctl(id, IPC_STAT, &mut a) }, 0);
    assert_eq!(unsafe { libc::shmctl(id, libc::IPC_STAT, &mut b) }, 0);
    assert_eq!(bytes(&a), bytes(&b));
    assert_eq!((a.shm_segsz, a.shm_nattch, a.shm_cpid, a.shm_lpid), (8192, 1, unsafe { libc::getpid() }, pid));
    assert_eq!(unsafe { shmdt(p as *const c_void) }, 0);
    // detached address: EINVAL
    assert_eq!(unsafe { shmdt(p as *const c_void) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { shmctl(id, IPC_STAT, &mut a) }, 0);
    assert_eq!(a.shm_nattch, 0);
}

#[test]
fn shm_flags_and_errors() {
    let _l = lock();
    let (id, _g) = shm(4096);
    // SHM_RDONLY: a read works; SHM_RND rounds an address down; unaligned address without SHM_RND: EINVAL
    let p = unsafe { shmat(id, core::ptr::null(), SHM_RDONLY) } as *mut u8;
    assert_ne!(p as isize, -1);
    assert_eq!(unsafe { *p }, 0);
    let bad = unsafe { shmat(id, (p as usize + 100) as *const c_void, 0) };
    assert_eq!((bad as isize, errno()), (-1, 22));
    assert_eq!(unsafe { shmdt(p as *const c_void) }, 0);
    // attach at a chosen page-aligned address
    let want = 0x5000_0000_0000usize;
    let q = unsafe { shmat(id, want as *const c_void, 0) };
    assert_eq!(q as usize, want);
    let r = unsafe { shmat(id, (want + 100) as *const c_void, SHM_RND) };
    assert_eq!((r as usize, errno()), (usize::MAX, 22), "overlapping attach at the rounded address");
    assert_eq!(unsafe { shmdt(q as *const c_void) }, 0);
    // EEXIST / ENOENT / EINVAL
    let k = key(5);
    let a = shmget(k, 4096, IPC_CREAT | IPC_EXCL | 0o600);
    assert!(a >= 0);
    let _ga = Guard(b'h', a);
    assert_eq!(shmget(k, 4096, IPC_CREAT | IPC_EXCL | 0o600), -1);
    assert_eq!(errno(), 17);
    assert_eq!(shmget(key(6), 4096, 0), -1);
    assert_eq!(errno(), 2);
    assert_eq!(shmget(k, 1 << 20, 0), -1);
    assert_eq!(errno(), 22);
    assert_eq!(shmget(IPC_PRIVATE, 0, IPC_CREAT | 0o600), -1);
    assert_eq!(errno(), 22);
    assert_eq!(shmget(IPC_PRIVATE, usize::MAX, IPC_CREAT | 0o600), -1);
    assert_eq!(errno(), 22);
    let mut d = ShmidDs::default();
    assert_eq!(unsafe { shmctl(-1, IPC_STAT, &mut d) }, -1);
    assert_eq!(errno(), 22);
    assert_eq!(unsafe { shmat(-1, core::ptr::null(), 0) } as isize, -1);
    assert_eq!(errno(), 22);
    // removing an attached segment marks it SHM_DEST until the last detach
    let (id2, g2) = shm(4096);
    let p2 = unsafe { shmat(id2, core::ptr::null(), 0) };
    assert_eq!(unsafe { shmctl(id2, IPC_RMID, core::ptr::null_mut()) }, 0);
    assert_eq!(unsafe { shmctl(id2, IPC_STAT, &mut d) }, 0);
    assert!(d.shm_perm.mode & SHM_DEST as u32 != 0);
    assert_eq!(unsafe { shmdt(p2) }, 0);
    assert_eq!(unsafe { shmctl(id2, IPC_STAT, &mut d) }, -1);
    assert_eq!(errno(), 22);
    core::mem::forget(g2);
}

#[test]
fn shm_ctl_info_equal_host() {
    let _l = lock();
    let (id, _g) = shm(4096);
    let mut a = ShmInfoLimits::default();
    let mut b = ShmInfoLimits::default();
    let r1 = unsafe { shmctl(0, IPC_INFO, &mut a as *mut ShmInfoLimits as *mut ShmidDs) };
    let r2 = unsafe { libc::shmctl(0, libc::IPC_INFO, &mut b as *mut ShmInfoLimits as *mut libc::shmid_ds) };
    assert_eq!(r1, r2);
    assert_eq!(bytes(&a), bytes(&b));
    assert_eq!(a.shmmin, 1);
    let mut c = ShmInfo::default();
    let mut d = ShmInfo::default();
    let r1 = unsafe { shmctl(0, SHM_INFO, &mut c as *mut ShmInfo as *mut ShmidDs) };
    let r2 = unsafe { libc::shmctl(0, 14, &mut d as *mut ShmInfo as *mut libc::shmid_ds) };
    assert!(r1 >= 0 && r2 >= r1);
    assert!(c.used_ids >= 1 && d.used_ids >= 1);
    // SHM_STAT_ANY with the id works without read permission checks
    let mut s1 = ShmidDs::default();
    let r3 = unsafe { shmctl(id, SHM_STAT_ANY, &mut s1) };
    let mut s2: libc::shmid_ds = unsafe { core::mem::zeroed() };
    let r4 = unsafe { libc::shmctl(id, 15, &mut s2) };
    assert_eq!(r3, r4);
    assert_eq!(bytes(&s1), bytes(&s2));
    // IPC_SET changes the mode only
    let mut s = ShmidDs::default();
    assert_eq!(unsafe { shmctl(id, IPC_STAT, &mut s) }, 0);
    s.shm_perm.mode = 0o640;
    assert_eq!(unsafe { shmctl(id, IPC_SET, &mut s) }, 0);
    assert_eq!(unsafe { libc::shmctl(id, libc::IPC_STAT, &mut s2) }, 0);
    assert_eq!(s2.shm_perm.mode & 0o777, 0o640);
    // SHM_LOCK without privilege: EPERM (user is not root; RLIMIT_MEMLOCK may allow it for small segments)
    let r = unsafe { shmctl(id, SHM_LOCK, core::ptr::null_mut()) };
    let e = errno();
    let r2 = unsafe { libc::shmctl(id, libc::SHM_LOCK, core::ptr::null_mut()) };
    assert_eq!(r, r2);
    if r == -1 {
        assert_eq!(e, host_errno());
    } else {
        assert_eq!(unsafe { shmctl(id, SHM_UNLOCK, core::ptr::null_mut()) }, 0);
    }
}

#[test]
fn shm_rust_api() {
    let _l = lock();
    let s = Shm::private(5000, 0o600).unwrap();
    let _g = Guard(b'h', s.id());
    assert_eq!(s.stat().unwrap().shm_segsz, 5000);
    {
        let m = s.attach(0).unwrap();
        assert_eq!(m.len(), 5000);
        unsafe { m.as_mut_slice()[..5].copy_from_slice(b"hello") };
        assert_eq!(s.stat().unwrap().shm_nattch, 1);
        let m2 = s.attach(SHM_RDONLY).unwrap();
        assert_eq!(unsafe { &m2.as_slice()[..5] }, b"hello");
        assert_eq!(s.stat().unwrap().shm_nattch, 2);
    }
    assert_eq!(s.stat().unwrap().shm_nattch, 0);
    s.remove().unwrap();
    assert_eq!(s.stat().unwrap_err(), Errno(22));
    core::mem::forget(_g);
    assert_eq!(Shm::get(key(7), 100, 0).unwrap_err(), Errno(2));
}
