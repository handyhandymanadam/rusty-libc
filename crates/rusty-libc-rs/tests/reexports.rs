//! The rustix pieces rusty-sh needs, reached through rusty_libc_rs's re-exports (FIXLIST #127 stage 2), against the
//! host C library: termios get/set on a PTY, ttyname, poll, waitpid and kill on a spawned child, umask, fstat, getrlimit,
//! read/seek, access, dup. Run on glibc and under rusty-libc's loader by tools/rusty-libc-rs-tests.sh.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

mod common;
use common::*;
use rusty_libc_rs::event::{PollFd, PollFlags, Timespec, poll};
use rusty_libc_rs::fd::{AsFd, AsRawFd, OwnedFd};
use rusty_libc_rs::fs::{Access, Mode, OFlags, SeekFrom, access, fstat, open, seek};
use rusty_libc_rs::io::{dup, read, write};
use rusty_libc_rs::process::{Resource, WaitOptions, getrlimit, kill_process, kill_process_group, test_kill_process, umask, waitpid};
use rusty_libc_rs::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rusty_libc_rs::termios::{LocalModes, OptionalActions, isatty, tcgetattr, tcsetattr, ttyname};
use rusty_libc_rs::*;

/// A PTY pair made only with rusty_libc_rs calls: (master, slave), the slave opened with O_NOCTTY.
fn rl_pty() -> (OwnedFd, OwnedFd, std::ffi::CString) {
    let m = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
    grantpt(&m).unwrap();
    unlockpt(&m).unwrap();
    let name = ptsname(&m, Vec::new()).unwrap();
    let s = open(name.as_c_str(), OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    (m, s, name)
}

#[test]
fn termios_round_trip_on_a_pty() {
    let (_m, s, name) = rl_pty();
    assert!(isatty(&s));
    assert_eq!(ttyname(&s, Vec::new()).unwrap(), name);
    let mut t = tcgetattr(&s).unwrap();
    // what the host's tcgetattr reads is the same
    let mut ht: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(s.as_raw_fd(), &mut ht) }, 0);
    assert_eq!(t.local_modes.bits(), ht.c_lflag);
    assert!(t.local_modes.contains(LocalModes::ECHO | LocalModes::ICANON));
    // raw-ish mode as a shell's line editor sets it, then back
    let saved = t.clone();
    t.local_modes.remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
    tcsetattr(&s, OptionalActions::Now, &t).unwrap();
    let t2 = tcgetattr(&s).unwrap();
    assert!(!t2.local_modes.intersects(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG));
    assert_eq!(unsafe { libc::tcgetattr(s.as_raw_fd(), &mut ht) }, 0);
    assert_eq!(ht.c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG), 0);
    tcsetattr(&s, OptionalActions::Now, &saved).unwrap();
    assert_eq!(tcgetattr(&s).unwrap().local_modes, saved.local_modes);
    // not a terminal
    let f = std::fs::File::open("/dev/null").unwrap();
    assert!(!isatty(&f));
    assert_eq!(tcgetattr(&f).unwrap_err(), en(libc::ENOTTY));
}

#[test]
fn poll_on_a_pipe() {
    let (r, w) = rusty_libc_rs::pipe::pipe().unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut fds = [PollFd::new(&r, PollFlags::IN)];
    assert_eq!(poll(&mut fds, Some(&zero)).unwrap(), 0);
    assert_eq!(write(&w, b"x").unwrap(), 1);
    let mut fds = [PollFd::new(&r, PollFlags::IN)];
    assert_eq!(poll(&mut fds, None).unwrap(), 1);
    assert!(fds[0].revents().contains(PollFlags::IN));
    let mut b = [0u8; 4];
    assert_eq!(read(&r, &mut b).unwrap(), 1);
    drop(w);
    let mut fds = [PollFd::new(&r, PollFlags::IN)];
    assert_eq!(poll(&mut fds, Some(&zero)).unwrap(), 1);
    assert!(fds[0].revents().contains(PollFlags::HUP));
}

#[test]
fn waitpid_and_kill_on_a_spawned_child() {
    let c = Command::new("/bin/sleep").arg("30").process_group(None).spawn().unwrap();
    let p = c.pid();
    test_kill_process(p).unwrap();
    assert!(waitpid(Some(p), WaitOptions::NOHANG).unwrap().is_none());
    // stop it, see it stopped (WUNTRACED), continue, kill its group
    kill_process(p, Signal::STOP).unwrap();
    let (wp, st) = waitpid(Some(p), WaitOptions::UNTRACED).unwrap().unwrap();
    assert_eq!(wp, p);
    assert!(st.stopped());
    assert_eq!(st.stopping_signal(), Some(libc::SIGSTOP));
    kill_process(p, Signal::CONT).unwrap();
    let (_, st) = waitpid(Some(p), WaitOptions::CONTINUED).unwrap().unwrap();
    assert!(st.continued());
    kill_process_group(p, Signal::TERM).unwrap();
    let (_, st) = waitpid(Some(p), WaitOptions::empty()).unwrap().unwrap();
    assert!(st.signaled());
    assert_eq!(st.terminating_signal(), Some(libc::SIGTERM));
    // reaped: gone
    assert_eq!(waitpid(Some(p), WaitOptions::empty()).unwrap_err(), en(libc::ECHILD));
    assert_eq!(test_kill_process(p).unwrap_err(), en(libc::ESRCH));
    // an exit status through waitpid
    let c = Command::new("/bin/sh").args(["-c", "exit 5"]).spawn().unwrap();
    let (_, st) = waitpid(Some(c.pid()), WaitOptions::empty()).unwrap().unwrap();
    assert_eq!(st.exit_status(), Some(5));
}

#[test]
fn umask_round_trip() {
    isolated("umask_round_trip", || {
        let old = umask(Mode::from_raw_mode(0o027));
        assert_eq!(unsafe { libc::umask(0o077) }, 0o027);
        assert_eq!(umask(old), Mode::from_raw_mode(0o077));
        // a file made now has the old mask applied
        let p = std::env::temp_dir().join(format!("rlrs-umask-{}", std::process::id()));
        umask(Mode::from_raw_mode(0o022));
        let f = open(p.as_path(), OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC, Mode::from_raw_mode(0o666)).unwrap();
        assert_eq!(fstat(&f).unwrap().st_mode & 0o777, 0o644);
        std::fs::remove_file(&p).unwrap();
    });
}

#[test]
fn fstat_read_seek_access_dup() {
    let p = std::env::temp_dir().join(format!("rlrs-fstat-{}-{:?}", std::process::id(), std::thread::current().id()));
    std::fs::write(&p, b"0123456789").unwrap();
    let f = open(p.as_path(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    let st = fstat(&f).unwrap();
    let md = std::fs::metadata(&p).unwrap();
    assert_eq!(st.st_size, 10);
    assert_eq!(st.st_ino, std::os::unix::fs::MetadataExt::ino(&md));
    let mut hs: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(f.as_raw_fd(), &mut hs) }, 0);
    assert_eq!((st.st_dev, st.st_ino, st.st_mode, st.st_nlink), (hs.st_dev, hs.st_ino, hs.st_mode, hs.st_nlink));
    // read 4, step back 2 (what rusty-sh's input does to un-read), read again
    let mut b = [0u8; 4];
    assert_eq!(read(&f, &mut b).unwrap(), 4);
    assert_eq!(seek(&f, SeekFrom::Current(-2)).unwrap(), 2);
    assert_eq!(read(&f, &mut b).unwrap(), 4);
    assert_eq!(&b, b"2345");
    // a dup shares the offset
    let d = dup(&f).unwrap();
    assert_eq!(seek(&d, SeekFrom::Current(0)).unwrap(), 6);
    assert_ne!(d.as_fd().as_raw_fd(), f.as_raw_fd());
    access(p.as_path(), Access::READ_OK).unwrap();
    assert_eq!(access(p.as_path(), Access::EXEC_OK).unwrap_err(), en(libc::EACCES));
    assert_eq!(access("/nonexistent-rlrs", Access::EXISTS).unwrap_err(), en(libc::ENOENT));
    std::fs::remove_file(&p).unwrap();
}

#[test]
fn getrlimit_matches_host() {
    let l = getrlimit(Resource::Nofile);
    let mut h = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut h) }, 0);
    let conv = |v: libc::rlim_t| if v == libc::RLIM_INFINITY { None } else { Some(v) };
    assert_eq!((l.current, l.maximum), (conv(h.rlim_cur), conv(h.rlim_max)));
}

#[test]
fn socket_peercred_replacement() {
    use rusty_libc_rs::net::sockopt::socket_peercred;
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let c = socket_peercred(&a).unwrap();
    assert_eq!(c.pid, Some(rusty_libc_rs::process::getpid()));
    assert_eq!(c.uid, Some(rusty_libc_rs::process::getuid()));
    assert_eq!(c.gid, Some(rusty_libc_rs::process::getgid()));
    // no peer: pid 0 and uid/gid -1 from the kernel (rustix's own version would build an invalid Pid here)
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let c = socket_peercred(&l).unwrap();
    assert_eq!((c.pid, c.uid, c.gid), (None, None, None));
    let f = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(socket_peercred(&f).unwrap_err(), en(libc::ENOTSOCK));
}

/// Every path ~/Claude/tmp/rustface/rusty-sh-migration.md names exists with the stated shape (compile check plus
/// cheap calls).
#[test]
fn migration_note_paths() {
    use rusty_libc_rs::Errno;
    let _: Option<Pid> = rusty_libc_rs::process::getppid();
    let _: Option<Pid> = rusty_libc_rs::process::getpgrp();
    let _: Option<Pid> = rusty_libc_rs::process::getpgid(None).unwrap();
    assert_eq!(Pid::as_raw(None), 0);
    let me = rusty_libc_rs::process::getpid();
    assert_eq!(Pid::as_raw(Some(me)), me.as_raw_nonzero().get());
    rusty_libc_rs::process::test_kill_process(me).unwrap();
    let _: [Signal; 6] = [Signal::CHILD, Signal::ALARM, Signal::IO, Signal::POWER, Signal::TSTP, Signal::TTOU];
    assert_eq!((1..=31).filter_map(Signal::from_named_raw).count(), 31);
    assert_eq!(SigNum::from(Signal::INT).name().unwrap(), "SIGINT");
    let _ = rusty_libc_rs::signal::get_signal(Signal::PIPE).unwrap();
    let e = std::io::Error::from_raw_os_error(libc::EMFILE);
    assert_eq!(Errno::from_io_error(&e), Some(Errno::MFILE));
    let _: [Errno; 4] = [Errno::INTR, Errno::CHILD, Errno::NOEXEC, Errno::INVAL];
    let _ = rusty_libc_rs::termios::OutputModes::OPOST | rusty_libc_rs::termios::OutputModes::ONLCR;
    let f = std::fs::File::open("/dev/null").unwrap();
    let st = fstat(&f).unwrap();
    assert_eq!(rusty_libc_rs::fs::FileType::from_raw_mode(st.st_mode), rusty_libc_rs::fs::FileType::CharacterDevice);
    let mut fds = [PollFd::from_borrowed_fd(f.as_fd(), PollFlags::IN)];
    assert_eq!(poll(&mut fds, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })).unwrap(), 1);
    assert_eq!(rusty_libc_rs::pipe::PIPE_BUF, 4096);
    let (r, _w) = rusty_libc_rs::pipe::pipe().unwrap();
    assert!(rusty_libc_rs::pipe::fcntl_setpipe_size(&r, 65536).unwrap() >= 65536);
    let _: Vec<rusty_libc_rs::Gid> = rusty_libc_rs::process::getgroups().unwrap();
    assert_eq!(rusty_libc_rs::process::getuid().is_root(), unsafe { libc::getuid() } == 0);
    assert_eq!(Mode::from_raw_mode(0o22).as_raw_mode(), 0o22);
    access("/", Access::EXISTS).unwrap();
    let _ = rusty_libc_rs::process::WaitOptions::NOHANG | rusty_libc_rs::process::WaitOptions::UNTRACED;
    let _ = rusty_libc_rs::process::WaitIdOptions::STOPPED | rusty_libc_rs::process::WaitIdOptions::NOHANG;
    let _ = rusty_libc_rs::signal::Action::Ignore;
}
