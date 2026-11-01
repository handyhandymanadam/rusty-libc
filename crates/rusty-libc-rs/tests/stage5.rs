//! FIXLIST #127 stage 5: checked recvmsg/sendmsg with descriptors and credentials.
#![allow(clippy::undocumented_unsafe_blocks)]

mod common;
use common::*;

mod msg {
    use super::*;
    use rusty_libc_rs::net::{Credentials, RecvFlags, SendFlags, ancillary_space, recvmsg, sendmsg, sockopt};
    use std::io::{IoSlice, IoSliceMut, Read, Write};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    /// Does the pipe of write end `w` still have a reader in this process (EPIPE when not; Rust ignores SIGPIPE)?
    fn has_reader(w: &mut std::io::PipeWriter) -> bool {
        match w.write(b"z") {
            Ok(_) => true,
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => false,
            Err(e) => panic!("{e}"),
        }
    }

    /// No reader left (within 2 s: a child another test thread is spawning holds copies of every descriptor from its
    /// clone until its exec closes the close-on-exec ones).
    fn no_reader(w: &mut std::io::PipeWriter) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while has_reader(w) {
            if std::time::Instant::now() > end {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }

    fn cloexec(fd: &impl AsRawFd) -> bool {
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
    }

    #[test]
    fn descriptors_and_credentials() {
        let (a, b) = UnixStream::pair().unwrap();
        sockopt::set_socket_passcred(&b, true).unwrap();
        let (r1, mut w1) = std::io::pipe().unwrap();
        w1.write_all(b"through the pipe").unwrap();
        let f = std::fs::File::open("/proc/self/status").unwrap();
        let me = Credentials::current();
        assert_eq!(me.pid, Some(rustix_pid()));
        let n = sendmsg(&a, &[IoSlice::new(b"msg")], &[r1.as_fd(), f.as_fd()], Some(&me), SendFlags::empty()).unwrap();
        assert_eq!(n, 3);
        drop(r1);
        let mut data = [0u8; 16];
        let mut control = vec![0u8; ancillary_space(2, true)];
        let m = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
        assert_eq!((m.bytes, &data[..3]), (3, &b"msg"[..]));
        assert!(!m.control_truncated());
        assert_eq!(m.credentials, Some(me));
        assert!(m.pidfd.is_none());
        assert_eq!(m.fds.len(), 2);
        assert!(m.fds.iter().all(cloexec));
        let mut fds = m.fds.into_iter();
        let mut text = [0u8; 16];
        std::fs::File::from(fds.next().unwrap()).read_exact(&mut text).unwrap();
        assert_eq!(&text, b"through the pipe");
        // the received read end was the last one: closing it leaves none
        assert!(no_reader(&mut w1));
        let mut status = String::new();
        std::fs::File::from(fds.next().unwrap()).read_to_string(&mut status).unwrap();
        assert!(status.starts_with("Name:"));
    }

    fn rustix_pid() -> rusty_libc_rs::Pid {
        rusty_libc_rs::process::getpid()
    }

    #[test]
    fn truncated_control_closes_what_arrived() {
        let (a, b) = UnixStream::pair().unwrap();
        let pipes: Vec<_> = (0..3).map(|_| std::io::pipe().unwrap()).collect();
        let reads: Vec<_> = pipes.iter().map(|(r, _)| r.as_fd()).collect();
        sendmsg(&a, &[IoSlice::new(b"x")], &reads, None, SendFlags::empty()).unwrap();
        drop(reads);
        let mut writers: Vec<_> = pipes.into_iter().map(|(_, w)| w).collect();
        let mut data = [0u8; 1];
        // room for one: the kernel installs one and drops two (MSG_CTRUNC); the one that arrived is closed too
        let mut control = vec![0u8; ancillary_space(1, false)];
        let m = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
        assert!(m.control_truncated());
        assert!(m.fds.is_empty() && m.pidfd.is_none());
        assert_eq!((m.bytes, data), (1, *b"x"));
        assert!(writers.iter_mut().all(no_reader));
    }

    /// Our sendmsg against the host C library's recvmsg with CMSG_FIRSTHDR/CMSG_NXTHDR, and the host's sendmsg
    /// against our recvmsg: the same messages.
    #[test]
    fn same_as_the_c_library() {
        let (a, b) = UnixStream::pair().unwrap();
        sockopt::set_socket_passcred(&b, true).unwrap();
        sockopt::set_socket_passcred(&a, true).unwrap();
        let f = std::fs::File::open("/dev/null").unwrap();
        sendmsg(&a, &[IoSlice::new(b"ab")], &[f.as_fd(), f.as_fd()], Some(&Credentials::current()), SendFlags::empty()).unwrap();
        // receive with the C library
        let mut data = [0u8; 4];
        let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
        let mut cbuf = [0u64; 16];
        let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
        mh.msg_iov = &mut iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf.as_mut_ptr().cast();
        mh.msg_controllen = std::mem::size_of_val(&cbuf);
        let n = unsafe { libc::recvmsg(b.as_raw_fd(), &mut mh, libc::MSG_CMSG_CLOEXEC) };
        assert_eq!(n, 2);
        let mut seen = Vec::new();
        let mut c = unsafe { libc::CMSG_FIRSTHDR(&mh) };
        while !c.is_null() {
            let h = unsafe { &*c };
            let payload = h.cmsg_len as usize - unsafe { libc::CMSG_LEN(0) } as usize;
            seen.push((h.cmsg_level, h.cmsg_type, payload));
            if h.cmsg_type == libc::SCM_RIGHTS {
                for i in 0..payload / 4 {
                    let fd = unsafe { (libc::CMSG_DATA(c) as *const i32).add(i).read_unaligned() };
                    unsafe { libc::close(fd) };
                }
            } else if h.cmsg_type == libc::SCM_CREDENTIALS {
                let u = unsafe { (libc::CMSG_DATA(c) as *const libc::ucred).read_unaligned() };
                assert_eq!((u.pid, u.uid, u.gid), (std::process::id() as i32, unsafe { libc::getuid() }, unsafe { libc::getgid() }));
            }
            c = unsafe { libc::CMSG_NXTHDR(&mh, c) };
        }
        // (the kernel puts the credentials first)
        assert_eq!(seen, [(libc::SOL_SOCKET, libc::SCM_CREDENTIALS, 12), (libc::SOL_SOCKET, libc::SCM_RIGHTS, 8)]);
        assert_eq!(mh.msg_flags & libc::MSG_CTRUNC, 0);
        // send with the C library (SCM_RIGHTS with 1 descriptor, CMSG_SPACE-sized), receive with ours
        let mut cbuf = [0u64; 4];
        let mut iov = libc::iovec { iov_base: b"cd".as_ptr() as *mut _, iov_len: 2 };
        let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
        mh.msg_iov = &mut iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf.as_mut_ptr().cast();
        mh.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&mh);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
            (libc::CMSG_DATA(c) as *mut i32).write_unaligned(f.as_raw_fd());
        }
        assert_eq!(unsafe { libc::sendmsg(b.as_raw_fd(), &mh, 0) }, 2);
        let mut control = vec![0u8; ancillary_space(1, true)];
        let m = recvmsg(&a, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
        assert_eq!((m.bytes, &data[..2]), (2, &b"cd"[..]));
        assert_eq!(m.fds.len(), 1);
        // SO_PASSCRED on `a`: the kernel adds the sender's credentials
        assert_eq!(m.credentials, Some(Credentials::current()));
    }

    #[test]
    fn pidfd_of_the_sender() {
        const SO_PASSPIDFD: i32 = 76;
        let (a, b) = UnixStream::pair().unwrap();
        let one: i32 = 1;
        let r = unsafe { libc::setsockopt(b.as_raw_fd(), libc::SOL_SOCKET, SO_PASSPIDFD, (&raw const one).cast(), 4) };
        if r != 0 {
            eprintln!("SO_PASSPIDFD not supported (kernel before 6.5): skipped");
            return;
        }
        sendmsg(&a, &[IoSlice::new(b"p")], &[], None, SendFlags::empty()).unwrap();
        let mut data = [0u8; 1];
        let mut control = vec![0u8; 64];
        let m = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
        let pidfd: OwnedFd = m.pidfd.expect("SCM_PIDFD");
        assert!(cloexec(&pidfd));
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).unwrap();
        let pid = info.lines().find_map(|l| l.strip_prefix("Pid:")).unwrap().trim().parse::<u32>().unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn flags_and_limits() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut data = [0u8; 4];
        // nothing queued: DONTWAIT gives EAGAIN
        let e = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut [], RecvFlags::DONTWAIT).unwrap_err();
        assert_eq!(e, rusty_libc_rs::io::Errno::AGAIN);
        // an unknown flag bit: EINVAL
        let e = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut [], RecvFlags::from_bits_retain(0x10000)).unwrap_err();
        assert_eq!(e, rusty_libc_rs::io::Errno::INVAL);
        let f = std::fs::File::open("/dev/null").unwrap();
        let many = vec![f.as_fd(); rusty_libc_rs::net::MAX_FDS + 1];
        assert_eq!(sendmsg(&a, &[IoSlice::new(b"x")], &many, None, SendFlags::empty()), Err(rusty_libc_rs::io::Errno::INVAL));
        // PEEK: the data stays, and each peek gets its own copies of the descriptors
        sendmsg(&a, &[IoSlice::new(b"pk")], &[f.as_fd()], None, SendFlags::empty()).unwrap();
        let mut control = vec![0u8; ancillary_space(1, false)];
        let p = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::PEEK).unwrap();
        let m = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
        assert_eq!((p.bytes, m.bytes, p.fds.len(), m.fds.len()), (2, 2, 1, 1));
        assert_ne!(p.fds[0].as_raw_fd(), m.fds[0].as_raw_fd());
    }

    const NS: &str = "msg::credentials_from_outside_the_pid_namespace";

    /// The case rustix gets wrong: a sender outside the receiver's PID namespace arrives as pid 0, here `None`.
    #[test]
    fn credentials_from_outside_the_pid_namespace() {
        if in_scenario(NS) {
            let s: OwnedFd = rusty_libc_rs::fd::take_inherited(3).expect("fd 3");
            sockopt::set_socket_passcred(&s, true).unwrap();
            let mut data = [0u8; 2];
            let mut control = vec![0u8; ancillary_space(0, true)];
            let m = recvmsg(&s, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::WAITALL).unwrap();
            assert_eq!(&data, b"go");
            let c = m.credentials.expect("credentials");
            assert_eq!(c.pid, None, "the sender has no pid in this namespace");
            assert_eq!(c.uid, rusty_libc_rs::process::getuid());
            // and the peer credentials of the same socket agree
            assert_eq!(rusty_libc_rs::net::sockopt::socket_peercred(&s).unwrap().pid, None);
            return;
        }
        let (a, b) = UnixStream::pair().unwrap();
        let (mut c, out) = scenario_command(NS, &["unshare", "-r", "-p", "-f", "--kill-child"]);
        c.fd(3, OwnedFd::from(b));
        let child = c.spawn().unwrap();
        drop(c);
        // explicit credentials travel with the data; the receiver's SO_PASSCRED (set by the child before it reads) is
        // checked when it receives, so no wait is needed
        sendmsg(&a, &[IoSlice::new(b"go")], &[], Some(&Credentials::current()), SendFlags::empty()).unwrap();
        scenario_passed(NS, child, out);
    }
}

mod lock {
    use super::*;
    use rusty_libc_rs::process::{Flock, FlockOffsetType, FlockType, LockConflict, fcntl_getlk, fcntl_ofd_getlk};
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};

    fn tmpfile(name: &str) -> std::path::PathBuf {
        let dir = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let p = dir.join(format!("rlrs-lock-{}-{name}", std::process::id()));
        std::fs::write(&p, [0u8; 100]).unwrap();
        p
    }

    fn set(fd: &impl AsRawFd, cmd: i32, typ: i32, start: i64, len: i64) {
        let mut l: libc::flock = unsafe { std::mem::zeroed() };
        l.l_type = typ as i16;
        l.l_whence = libc::SEEK_SET as i16;
        l.l_start = start;
        l.l_len = len;
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), cmd, &l) }, 0, "{}", std::io::Error::last_os_error());
    }

    fn want(typ: FlockType, start: u64, length: u64) -> Flock {
        Flock { start, length, pid: None, typ, offset_type: FlockOffsetType::Set }
    }

    /// The case rustix gets wrong: an open-file-description lock is reported with l_pid -1.
    #[test]
    fn ofd_lock_owner_is_none() {
        let p = tmpfile("ofd");
        let a = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let b = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
        set(&a, libc::F_OFD_SETLK, libc::F_WRLCK, 10, 20);
        let c = fcntl_getlk(&b, &want(FlockType::ReadLock, 0, 0)).unwrap();
        assert_eq!(c, Some(LockConflict { typ: FlockType::WriteLock, offset_type: FlockOffsetType::Set, start: 10, length: 20, pid: None }));
        let c = fcntl_ofd_getlk(&b, &want(FlockType::WriteLock, 15, 1)).unwrap();
        assert_eq!(c.map(|c| (c.start, c.length, c.pid)), Some((10, 20, None)));
        // outside the range, and through the same open file description: no conflict
        assert_eq!(fcntl_getlk(&b, &want(FlockType::WriteLock, 30, 5)).unwrap(), None);
        assert_eq!(fcntl_ofd_getlk(&a, &want(FlockType::WriteLock, 0, 0)).unwrap(), None);
        // our own process lock conflicts with an OFD lock asked through another description, not with F_GETLK
        set(&b, libc::F_SETLK, libc::F_RDLCK, 50, 5);
        assert_eq!(fcntl_getlk(&a, &want(FlockType::WriteLock, 50, 1)).unwrap(), None);
        let c = fcntl_ofd_getlk(&a, &want(FlockType::WriteLock, 50, 1)).unwrap().unwrap();
        assert_eq!((c.typ, c.start, c.length, c.pid), (FlockType::ReadLock, 50, 5, Some(rusty_libc_rs::process::getpid())));
        // the same answers as the host C library
        let mut l: libc::flock = unsafe { std::mem::zeroed() };
        l.l_type = libc::F_RDLCK as i16;
        assert_eq!(unsafe { libc::fcntl(b.as_raw_fd(), libc::F_GETLK, &mut l) }, 0);
        assert_eq!((l.l_type as i32, l.l_start, l.l_len, l.l_pid), (libc::F_WRLCK, 10, 20, -1));
        std::fs::remove_file(&p).unwrap();
    }

    const HOLDER: &str = "lock::process_lock_owner";

    /// A process-associated lock held by another process: its pid.
    #[test]
    fn process_lock_owner() {
        if in_scenario(HOLDER) {
            let f = rusty_libc_rs::fd::take_inherited(3).expect("fd 3");
            set(&f, libc::F_SETLK, libc::F_WRLCK, 0, 10);
            // hold it until the parent closes its end of the pipe at fd 4
            let mut r = std::fs::File::from(rusty_libc_rs::fd::take_inherited(4).expect("fd 4"));
            let _ = r.read(&mut [0u8; 1]);
            return;
        }
        let p = tmpfile("proc");
        let f = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (r, w) = std::io::pipe().unwrap();
        let (mut c, out) = scenario_command(HOLDER, &[]);
        c.fd(3, OwnedFd::from(f.try_clone().unwrap())).fd(4, r);
        let child = c.spawn().unwrap();
        drop(c);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let got = loop {
            if let Some(x) = fcntl_getlk(&f, &want(FlockType::ReadLock, 5, 1)).unwrap() {
                break x;
            }
            assert!(std::time::Instant::now() < deadline, "the child never took the lock");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!((got.typ, got.start, got.length, got.pid), (FlockType::WriteLock, 0, 10, Some(child.pid())));
        drop(w);
        scenario_passed(HOLDER, child, out);
        std::fs::remove_file(&p).unwrap();
    }

    const NS: &str = "lock::owner_outside_the_pid_namespace";

    /// A lock owner outside the caller's PID namespace: the kernel reports 0, here `None`. The owner is a holder
    /// process (scenario `process_lock_owner`), not this test process: closing any descriptor of the file, as spawning
    /// does with its copies, would release a lock this process held (POSIX lock semantics).
    #[test]
    fn owner_outside_the_pid_namespace() {
        if in_scenario(NS) {
            let f = rusty_libc_rs::fd::take_inherited(3).expect("fd 3");
            let c = fcntl_getlk(&f, &want(FlockType::ReadLock, 0, 0)).unwrap().expect("conflict");
            assert_eq!((c.typ, c.start, c.length, c.pid), (FlockType::WriteLock, 0, 10, None));
            return;
        }
        let p = tmpfile("ns");
        let f = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (r, w) = std::io::pipe().unwrap();
        let (mut c, out) = scenario_command(HOLDER, &[]);
        c.fd(3, OwnedFd::from(f.try_clone().unwrap())).fd(4, r);
        let holder = c.spawn().unwrap();
        drop(c);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while fcntl_getlk(&f, &want(FlockType::ReadLock, 0, 0)).unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline, "the holder never took the lock");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (mut c, out2) = scenario_command(NS, &["unshare", "-r", "-p", "-f", "--kill-child"]);
        c.fd(3, OwnedFd::from(std::fs::File::open(&p).unwrap()));
        let child = c.spawn().unwrap();
        drop(c);
        scenario_passed(NS, child, out2);
        drop(w);
        scenario_passed(HOLDER, holder, out);
        std::fs::remove_file(&p).unwrap();
    }
}

mod script {
    use super::*;
    use rusty_libc_rs::Command;
    use std::os::unix::fs::PermissionsExt;

    /// A directory with `noshebang` (a script without #!, executable) and `plain` (the same, not executable).
    fn scripts(tag: &str) -> std::path::PathBuf {
        let base = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("rlrs-script-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let body = "echo \"0=$0 n=$# 1=$1 2=$2\"\nexit 7\n";
        for (name, mode) in [("noshebang", 0o755), ("plain", 0o644)] {
            let p = d.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        d
    }

    fn output(c: &mut Command<'_>) -> (String, i32) {
        let (r, w) = std::io::pipe().unwrap();
        c.stdout(w);
        // ETXTBSY: another test thread may still hold a just-written file open for writing in a forked child
        let mut child = loop {
            match c.spawn() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(std::time::Duration::from_millis(20)),
                r => break r.unwrap(),
            }
        };
        c.stdout(rusty_libc_rs::Stdio::Inherit);
        let text = read_all(r);
        (text, child.wait().unwrap().code().unwrap())
    }

    #[test]
    fn enoexec_runs_with_bin_sh() {
        let d = scripts("sh");
        let p = d.join("noshebang");
        // a path: /bin/sh FILE ARGS (argv[0] dropped)
        let mut c = Command::new(&p);
        c.arg0("ignored").args(["a", "b c"]);
        assert_eq!(output(&mut c), (format!("0={} n=2 1=a 2=b c\n", p.display()), 7));
        // a bare name searched in PATH: the candidate's full path becomes $0
        let mut c = Command::new("noshebang");
        c.env("PATH", &d).arg("x");
        assert_eq!(output(&mut c), (format!("0={} n=1 1=x 2=\n", p.display()), 7));
        // turned off: posix_spawnp's ENOEXEC
        let mut c = Command::new(&p);
        c.shell_fallback(false);
        let e = c.spawn().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOEXEC));
        // not executable: EACCES, no shell
        let e = Command::new(d.join("plain")).spawn().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EACCES));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The same as the host C library's execvp (a forked child runs execvp; its output is compared).
    #[test]
    fn same_as_host_execvp() {
        let d = scripts("cmp");
        let mut c = Command::new("noshebang");
        c.env("PATH", &d).args(["1", "2"]);
        let ours = output(&mut c);
        // the reference: env(1) is a glibc program that calls execvp
        let out = std::process::Command::new("/usr/bin/env").env("PATH", &d).args(["noshebang", "1", "2"]).output().unwrap();
        assert_eq!(ours, (String::from_utf8(out.stdout).unwrap(), out.status.code().unwrap()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    const EXEC: &str = "script::exec_in_place_falls_back_too";

    /// Command::exec (no fork) takes the same fallback: the scenario process becomes /bin/sh running the script.
    #[test]
    fn exec_in_place_falls_back_too() {
        if in_scenario(EXEC) {
            let p = std::env::var_os("RLRS_SCRIPT").unwrap();
            let e = Command::new(p).arg("from-exec").exec();
            panic!("exec returned: {e}");
        }
        let d = scripts("exec");
        let (mut c, out) = scenario_command(EXEC, &[]);
        c.env("RLRS_SCRIPT", d.join("noshebang"));
        let mut child = c.spawn().unwrap();
        drop(c);
        let text = read_all(out);
        let code = child.wait().unwrap().code();
        assert!(text.contains(&format!("0={} n=1 1=from-exec 2=\n", d.join("noshebang").display())), "{text}");
        assert_eq!(code, Some(7));
        std::fs::remove_dir_all(&d).unwrap();
    }
}

mod dlopen {
    use rusty_libc_rs::fd::{inherited_snapshot_taken, take_inherited, was_inherited};
    use std::ffi::{CString, c_int};
    use std::os::fd::AsRawFd;

    /// target/<profile>/examples/libdlopen_probe.so: the first ancestor directory of this test binary with an
    /// `examples/libdlopen_probe.so` (deps/ in the classic layout, build/<crate>/<hash>/out/ in the new one).
    /// RLRS_DLOPEN_PROBE overrides.
    fn probe_path() -> std::path::PathBuf {
        if let Some(p) = std::env::var_os("RLRS_DLOPEN_PROBE") {
            return p.into();
        }
        let exe = std::env::var_os("RLRS_TEST_EXE").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_exe().unwrap());
        exe.ancestors()
            .map(|a| a.join("examples").join("libdlopen_probe.so"))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("no examples/libdlopen_probe.so above {}: build the tests with `cargo test -p rusty-libc-rs` (it builds the examples)", exe.display()))
    }

    fn sym<T: Copy>(h: *mut libc::c_void, name: &str) -> T {
        let n = CString::new(name).unwrap();
        let p = unsafe { libc::dlsym(h, n.as_ptr()) };
        assert!(!p.is_null(), "{name}");
        unsafe { std::mem::transmute_copy(&p) }
    }

    /// rusty-libc-rs-core's snapshot runs only in the main executable: a shared object containing it, loaded with
    /// dlopen while the program has descriptors open, must not take it (take_inherited -> None, snapshot not taken).
    #[test]
    fn no_snapshot_in_a_dlopened_library() {
        // control: this test binary (the main executable) took its snapshot
        assert!(inherited_snapshot_taken());
        let p = probe_path();
        // descriptors open at dlopen time: a file and a pipe (in a wrongly taken snapshot they would look inherited)
        let f = std::fs::File::open("/proc/self/status").unwrap();
        let (r, _w) = std::io::pipe().unwrap();
        let fds = [f.as_raw_fd(), r.as_raw_fd()];
        assert!(fds.iter().all(|&n| !was_inherited(n) && take_inherited(n).is_none()));
        let c = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!h.is_null(), "dlopen: {:?}", unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) });
        let ctor_ran: extern "C" fn() -> c_int = sym(h, "rlrs_probe_ctor_ran");
        let taken: extern "C" fn() -> c_int = sym(h, "rlrs_probe_snapshot_taken");
        let inherited: extern "C" fn(c_int) -> c_int = sym(h, "rlrs_probe_was_inherited");
        let take: extern "C" fn(c_int) -> c_int = sym(h, "rlrs_probe_take");
        assert_eq!(ctor_ran(), 1, "the loader ran the object's initialisers");
        assert_eq!(taken(), 0, "the dlopen'ed copy must not take the snapshot");
        for n in fds.into_iter().chain(3..64) {
            assert_eq!(inherited(n), 0, "fd {n}");
            assert_eq!(take(n), -1, "fd {n}");
        }
        // still open and ours
        assert!(unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(unsafe { libc::fcntl(r.as_raw_fd(), libc::F_GETFD) } >= 0);
        // (not dlclose'd: an object holding Rust std state is not meant to be unloaded)
    }
}
