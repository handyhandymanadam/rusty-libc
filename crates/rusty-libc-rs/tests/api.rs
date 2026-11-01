//! The non-spawn API against the host C library (libc crate): confstr, ids, process groups, sessions, signal
//! dispositions, descriptors, terminal calls, waitid. Anything that changes process-wide state runs in its own process
//! (`common::isolated`).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

mod common;
use common::*;
use rusty_libc_rs::fd::reopen_fd;
use rusty_libc_rs::io::fcntl_dupfd_cloexec;
use rusty_libc_rs::process::{WaitCode, WaitId, WaitIdOptions, WaitInfo, getegid, geteuid, getgid, getpgid, getpgrp, getpid, getppid, getsid, getuid, setpgid, setsid, waitid};
use rusty_libc_rs::signal::{blocked_signals, get_signal, set_signal};
use rusty_libc_rs::termios::{set_controlling_terminal, tcgetpgrp, tcgetsid, tcsetpgrp};
use rusty_libc_rs::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};

fn host_confstr(name: i32) -> Option<Vec<u8>> {
    unsafe {
        let n = libc::confstr(name, std::ptr::null_mut(), 0);
        if n == 0 {
            return None;
        }
        let mut b = vec![0u8; n];
        assert_eq!(libc::confstr(name, b.as_mut_ptr().cast(), n), n);
        b.pop();
        Some(b)
    }
}

#[test]
fn confstr_matches_host_for_every_name() {
    for name in -5..=1300 {
        assert_eq!(confstr(name), host_confstr(name), "confstr({name})");
    }
    assert_eq!(confstr(CS_PATH).as_deref(), Some(&b"/usr/bin"[..]));
    assert_eq!(confstr_os(CS_PATH).unwrap(), "/usr/bin");
}

#[test]
fn confstr_follows_getconf_dir() {
    // a directory with only the ILP32_OFF32 spec file, named by GETCONF_DIR in a new process
    let dir = std::env::temp_dir().join(format!("rlrs-getconf-{}", std::env::var("RLRS_SCENARIO").map(|_| raw(getppid().unwrap())).unwrap_or(raw(getpid()))));
    if std::env::var_os("RLRS_SCENARIO").is_none() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("POSIX_V6_ILP32_OFF32"), "").unwrap();
    }
    isolated_env("confstr_follows_getconf_dir", &[("GETCONF_DIR", dir.as_os_str())], || {
        assert_eq!(std::env::var_os("GETCONF_DIR").as_deref(), Some(dir.as_os_str()));
        for name in [1, 4, 5, 1100, 1101, 1104, 1116, 1136, 1137] {
            assert_eq!(confstr(name), host_confstr(name), "confstr({name}) with GETCONF_DIR");
        }
        assert!(String::from_utf8(confstr(1).unwrap()).unwrap().contains("POSIX_V6_ILP32_OFF32"));
    });
    if std::env::var_os("RLRS_SCENARIO").is_none() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[test]
fn ids_match_host() {
    // the re-exported rustix calls (they replaced this crate's own copies) against the host C library
    unsafe {
        assert_eq!(getuid().as_raw(), libc::getuid());
        assert_eq!(geteuid().as_raw(), libc::geteuid());
        assert_eq!(getgid().as_raw(), libc::getgid());
        assert_eq!(getegid().as_raw(), libc::getegid());
        assert_eq!(raw(getpid()), libc::getpid());
        assert_eq!(raw(getpid()) as u32, std::process::id());
        assert_eq!(raw(getppid().unwrap()), libc::getppid());
        assert_eq!(rawo(getpgrp()), libc::getpgrp());
        assert_eq!(rawo(getpgid(None).unwrap()), libc::getpgid(0));
        assert_eq!(rawo(getpgid(getppid()).unwrap()), libc::getpgid(libc::getppid()));
        assert_eq!(rawo(getsid(None).unwrap()), libc::getsid(0));
        // in a PID namespace whose group/session lie outside (tools/rusty-libc-rs-tests.sh runs us in one) these are
        // None, where rustix's own getpgrp would panic (debug) or build an invalid Pid (release)
        assert_eq!(getpgrp().is_none(), libc::getpgrp() == 0);
        assert_eq!(getsid(None).unwrap().is_none(), libc::getsid(0) == 0);
        assert_eq!(getpgid(None).unwrap().is_none(), libc::getpgid(0) == 0);
        // a pid that does not exist
        assert_eq!(getpgid(Some(pid(i32::MAX))).unwrap_err(), en(libc::ESRCH));
        assert_eq!(getsid(Some(pid(i32::MAX))).unwrap_err(), en(libc::ESRCH));
    }
}

#[test]
fn setpgid_and_setsid() {
    isolated("setpgid_and_setsid", || {
        let me = getpid();
        // started by the test harness: not a group leader, so setsid works once
        assert_ne!(getpgrp(), Some(me));
        let sid = setsid().unwrap();
        assert_eq!(sid, me);
        assert_eq!(getsid(None).unwrap(), Some(me));
        assert_eq!(getpgrp(), Some(me));
        // now a group leader: a second setsid fails with EPERM, as the host's
        assert_eq!(setsid().unwrap_err(), en(libc::EPERM));
        assert_eq!(unsafe { libc::setsid() }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        // setpgid of a session leader: EPERM (both)
        assert_eq!(setpgid(None, None).unwrap_err(), en(libc::EPERM));
        assert_eq!(unsafe { libc::setpgid(0, 0) }, -1);
        // (a negative pgid, EINVAL before, cannot be written with rustix's Pid)
    });
}

#[test]
fn setpgid_new_group() {
    isolated("setpgid_new_group", || {
        let me = getpid();
        setpgid(None, None).unwrap();
        assert_eq!(getpgrp(), Some(me));
        assert_eq!(unsafe { libc::getpgrp() }, raw(me));
        // a child joins our group by its pid
        let mut c = Command::new("/bin/sleep").arg("5").process_group(None).spawn().unwrap();
        assert_eq!(getpgid(Some(c.pid())).unwrap(), Some(c.pid()));
        setpgid(Some(c.pid()), Some(me)).unwrap_err(); // the child has executed: EACCES (as the host)
        c.send_signal(Signal::KILL).unwrap();
        c.wait().unwrap();
    });
}

#[test]
fn signal_dispositions() {
    isolated("signal_dispositions", || {
        assert_eq!(get_signal(Signal::USR1).unwrap(), Disposition::Default);
        assert_eq!(set_signal(Signal::USR1, Action::Ignore).unwrap(), Disposition::Default);
        assert_eq!(get_signal(Signal::USR1).unwrap(), Disposition::Ignore);
        // the host sees it ignored
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) }, 0);
        assert_eq!(old.sa_sigaction, libc::SIG_IGN);
        // and an ignored signal does nothing
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        assert_eq!(set_signal(Signal::USR1, Action::Default).unwrap(), Disposition::Ignore);
        // a handler installed through the C library is reported as such and can be replaced
        extern "C" fn h(_: i32) {}
        unsafe { libc::signal(libc::SIGUSR2, h as *const () as libc::sighandler_t) };
        assert_eq!(get_signal(Signal::USR2).unwrap(), Disposition::Handler);
        assert_eq!(set_signal(Signal::USR2, Action::Ignore).unwrap(), Disposition::Handler);
        assert_eq!(get_signal(Signal::USR2).unwrap(), Disposition::Ignore);
        // Rust's runtime ignores SIGPIPE
        assert_eq!(get_signal(Signal::PIPE).unwrap(), Disposition::Ignore);
        // numbers outside 1..=64 cannot be made at all
        for n in [0, -1, 65] {
            assert_eq!(SigNum::new(n), None, "SigNum::new({n})");
        }
        // refused
        for s in [SigNum::new(32).unwrap(), SigNum::new(33).unwrap(), Signal::KILL.into(), Signal::STOP.into()] {
            assert_eq!(set_signal(s, Action::Ignore).unwrap_err(), en(libc::EINVAL), "signal {s:?}");
            assert!(get_signal(s).is_err());
        }
        // real-time signals are allowed
        assert_eq!(set_signal(SigNum::RTMIN, Action::Ignore).unwrap(), Disposition::Default);
        assert_eq!(set_signal(SigNum::RTMAX, Action::Ignore).unwrap(), Disposition::Default);
        assert_eq!(set_signal(SigNum::rt(3).unwrap(), Action::Ignore).unwrap(), Disposition::Default);
        assert_eq!(unsafe { libc::sigaction(libc::SIGRTMIN() + 3, std::ptr::null(), &mut old) }, 0);
        assert_eq!(old.sa_sigaction, libc::SIG_IGN);
        assert_eq!(blocked_signals(), SigSet::empty());
    });
}

#[test]
fn sigset_bits() {
    let s = SigSet::empty().with(Signal::INT).with(SigNum::RTMAX);
    assert_eq!(s.bits(), (1 << 1) | (1 << 63));
    assert!(s.contains(Signal::INT) && !s.contains(Signal::QUIT));
    assert_eq!(s.without(Signal::INT).bits(), 1 << 63);
    assert_eq!(SigSet::full().bits(), u64::MAX);
    assert_eq!(SigSet::from_bits(6), SigSet::empty().with(Signal::INT).with(Signal::QUIT));
}

#[test]
fn signal_names_match_host_and_bash() {
    // standard names: glibc's sigabbrev_np (without SIG) for 1..=31, except 29: glibc says POLL, bash's kill -l says IO
    // (we follow bash; both names are accepted)
    unsafe extern "C" {
        fn sigabbrev_np(sig: i32) -> *const std::ffi::c_char;
    }
    for n in 1..=31 {
        let k = SigNum::new(n).unwrap();
        let host = unsafe { std::ffi::CStr::from_ptr(sigabbrev_np(n)) }.to_str().unwrap();
        if n != 29 {
            assert_eq!(k.name().unwrap(), format!("SIG{host}"), "signal {n}");
        }
        assert_eq!(SigNum::from_name(&k.name().unwrap()), Some(k));
        assert_eq!(SigNum::from_name(host), Some(k));
        assert_eq!(SigNum::from_name(&host.to_ascii_lowercase()), Some(k));
    }
    // real-time names as bash's kill -l prints them
    assert_eq!(SigNum::RTMIN.name().unwrap(), "SIGRTMIN");
    assert_eq!(SigNum::rt(1).unwrap().name().unwrap(), "SIGRTMIN+1");
    assert_eq!(SigNum::rt(15).unwrap().name().unwrap(), "SIGRTMIN+15");
    assert_eq!(SigNum::rt(16).unwrap().name().unwrap(), "SIGRTMAX-14");
    assert_eq!(SigNum::RTMAX.name().unwrap(), "SIGRTMAX");
    for n in 34..=64 {
        let k = SigNum::new(n).unwrap();
        assert_eq!(SigNum::from_name(&k.name().unwrap()), Some(k));
    }
    assert_eq!(SigNum::new(32).unwrap().name(), None);
    assert_eq!(SigNum::from_name("RTMIN+30"), Some(SigNum::RTMAX));
    assert_eq!(SigNum::from_name("RTMAX-30"), Some(SigNum::RTMIN));
    assert_eq!(SigNum::from_name("SIGIOT"), Some(Signal::ABORT.into()));
    assert_eq!(SigNum::from_name("CLD"), Some(Signal::CHILD.into()));
    assert_eq!(SigNum::new(29).unwrap().name().unwrap(), "SIGIO");
    for bad in ["", "SIG", "RTMIN+31", "RTMAX-31", "RTMIN++1", "RTMIN+-1", "RTMIN+", "15", "SIGFOO", "RTMIN+ 1"] {
        assert_eq!(SigNum::from_name(bad), None, "{bad:?}");
    }
}

#[test]
fn kill_with_any_signal() {
    use rusty_libc_rs::signal::{kill_process, kill_process_group};
    // a real-time signal (rustix's kill_process cannot send one) to a child, and to its group
    let mut c = Command::new("/bin/sleep").arg("30").process_group(None).spawn().unwrap();
    kill_process(c.pid(), SigNum::rt(2).unwrap()).unwrap();
    let i = waitid(WaitId::Pid(c.pid()), WaitIdOptions::EXITED).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Killed(SigNum::rt(2).unwrap()));
    assert!(c.wait().is_err());
    let c = Command::new("/bin/sleep").arg("30").process_group(None).spawn().unwrap();
    assert_eq!(kill_process(c.pid(), SigNum::new(32).unwrap()).unwrap_err(), en(libc::EINVAL));
    kill_process_group(c.pid(), Signal::TERM).unwrap();
    let i = waitid(WaitId::Pid(c.pid()), WaitIdOptions::EXITED).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Killed(Signal::TERM.into()));
}

#[test]
fn signum_conversions() {
    // every rustix Signal converts, and back
    for n in 1..=31 {
        let s = Signal::from_named_raw(n).unwrap();
        let k = SigNum::from(s);
        assert_eq!(k.as_raw(), n);
        assert_eq!(k.signal(), Some(s));
        assert_eq!(k, s);
        assert!(!k.is_realtime());
    }
    assert_eq!(SigNum::RTMIN.as_raw(), libc::SIGRTMIN());
    assert_eq!(SigNum::RTMAX.as_raw(), libc::SIGRTMAX());
    assert_eq!(SigNum::rt(0), Some(SigNum::RTMIN));
    assert_eq!(SigNum::rt(30), Some(SigNum::RTMAX));
    assert_eq!(SigNum::rt(31), None);
    assert_eq!(SigNum::rt(-1), None);
    assert_eq!(SigNum::RTMIN.signal(), None);
    assert_eq!(format!("{:?}", SigNum::rt(2).unwrap()), "SIGRTMIN+2");
    assert_eq!(format!("{:?}", SigNum::from(Signal::TERM)), "\"Signal::TERM\"");
    assert_eq!(format!("{:?}", SigNum::new(32).unwrap()), "SigNum(32)");
}

#[test]
fn dup_cloexec_gives_owned_cloexec_copy() {
    // rustix's fcntl_dupfd_cloexec replaced this crate's dup_cloexec: the same checks
    let f = tempfile("dup");
    let d = fcntl_dupfd_cloexec(f.as_fd(), 100).unwrap();
    assert!(d.as_raw_fd() >= 100);
    let flags = unsafe { libc::fcntl(d.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    let (mut a, mut b): (libc::stat, libc::stat) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    unsafe {
        libc::fstat(f.as_raw_fd(), &mut a);
        libc::fstat(d.as_raw_fd(), &mut b);
    }
    assert_eq!((a.st_dev, a.st_ino), (b.st_dev, b.st_ino));
    let low = fcntl_dupfd_cloexec(f.as_fd(), 0).unwrap();
    assert!(low.as_raw_fd() >= 0);
    // (a negative minimum, EINVAL before, trips a debug assertion in rustix: not tested)
    // the copy shares the offset (same open file description)
    let mut fa = std::fs::File::from(d);
    fa.write_all(b"abc").unwrap();
    let mut f2 = f;
    assert_eq!(f2.stream_position().unwrap(), 3);
}

fn tempfile(tag: &str) -> std::fs::File {
    let p = std::env::temp_dir().join(format!("rlrs-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    f
}

#[test]
fn reopen_fd_by_number() {
    // a read-write regular file at offset 5: the reopened one starts at 5 and can read and write
    let mut f = tempfile("reopen");
    f.write_all(b"hello world").unwrap();
    f.seek(SeekFrom::Start(5)).unwrap();
    let mut r = reopen_fd(f.as_raw_fd()).unwrap();
    let mut s = String::new();
    r.read_to_string(&mut s).unwrap();
    assert_eq!(s, " world");
    r.write_all(b"!").unwrap();
    assert_ne!(r.as_raw_fd(), f.as_raw_fd());
    assert_eq!(unsafe { libc::fcntl(r.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    // a pipe's read end reads what the write end gets
    let (pr, mut pw) = std::io::pipe().unwrap();
    let mut rr = reopen_fd(pr.as_raw_fd()).unwrap();
    pw.write_all(b"xy").unwrap();
    drop(pw);
    let mut b = [0u8; 2];
    rr.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"xy");
    // write-only stays write-only
    let wo = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
    let mut w = reopen_fd(wo.as_raw_fd()).unwrap();
    assert!(w.read(&mut b).is_err());
    w.write_all(b"z").unwrap();
    // sockets cannot be reopened by path; bad numbers fail
    let (s1, _s2) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(reopen_fd(s1.as_raw_fd()).unwrap_err().raw_os_error(), Some(libc::ENXIO));
    assert!(reopen_fd(-1).is_err());
    assert!(reopen_fd(999_999).is_err());
}

#[test]
fn terminal_calls_fail_like_host_on_non_terminals() {
    let f = tempfile("tty");
    assert_eq!(set_controlling_terminal(&f, false).unwrap_err(), en(libc::ENOTTY));
    assert_eq!(tcgetpgrp(&f).unwrap_err(), en(libc::ENOTTY));
    assert_eq!(tcsetpgrp(&f, getpid()).unwrap_err(), en(libc::ENOTTY));
    assert_eq!(tcgetsid(&f).unwrap_err(), en(libc::ENOTTY));
    assert_eq!(unsafe { libc::tcgetpgrp(f.as_raw_fd()) }, -1);
    // a terminal that is not ours: not the controlling terminal
    let (_m, s) = pty();
    assert_eq!(tcgetpgrp(&s).unwrap_err(), en(libc::ENOTTY));
    assert_eq!(unsafe { libc::tcgetpgrp(s.as_raw_fd()) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOTTY));
}

#[test]
fn controlling_terminal_and_foreground_group() {
    isolated("controlling_terminal_and_foreground_group", || {
        // closing the PTY master at the end hangs up the terminal: SIGHUP to its controlling process (us)
        set_signal(Signal::HUP, Action::Ignore).unwrap();
        let (_m, slave) = pty();
        // not a session leader: EPERM (as the host)
        assert_eq!(set_controlling_terminal(&slave, false).unwrap_err(), en(libc::EPERM));
        assert_eq!(unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0) }, -1);
        let me = setsid().unwrap();
        set_controlling_terminal(&slave, false).unwrap();
        assert_eq!(tcgetsid(&slave).unwrap(), Some(me));
        assert_eq!(unsafe { libc::tcgetsid(slave.as_raw_fd()) }, raw(me));
        assert_eq!(tcgetpgrp(&slave).unwrap(), Some(me));
        assert_eq!(unsafe { libc::tcgetpgrp(slave.as_raw_fd()) }, raw(me));
        // again: already our controlling terminal, fine (Linux returns 0)
        set_controlling_terminal(&slave, false).unwrap();
        // a child in a new group takes the foreground (done in the child with SIGTTOU blocked)
        let (r, w) = std::io::pipe().unwrap();
        let mut c = Command::new("/bin/cat").arg("/proc/self/stat").stdin(slave.as_fd()).stdout(w).process_group(None).foreground(0, true).spawn().unwrap();
        let st = parse_stat(&read_all(r));
        assert!(c.wait().unwrap().success());
        assert_eq!(st.pgrp, raw(c.pid()));
        assert_eq!(st.session, raw(me));
        assert_eq!(st.tpgid, raw(c.pid()));
        assert_eq!(st.tty_nr, tty_nr(&slave));
        // we are now in the background: taking the terminal back needs SIGTTOU ignored (a shell does that)
        assert_eq!(set_signal(Signal::TTOU, Action::Ignore).unwrap(), Disposition::Default);
        tcsetpgrp(&slave, me).unwrap();
        assert_eq!(tcgetpgrp(&slave).unwrap(), Some(me));
        // the same steps through std + pre_exec + the host C library give the same picture
        let (r, w) = std::io::pipe().unwrap();
        let mut cmd = std::process::Command::new("/bin/cat");
        cmd.arg("/proc/self/stat").stdin(slave.try_clone().unwrap()).stdout(w);
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
                libc::setpgid(0, 0);
                libc::tcsetpgrp(0, libc::getpgrp());
                Ok(())
            });
        }
        let mut sc = cmd.spawn().unwrap();
        drop(cmd); // std's Command keeps the pipe's write end
        let st2 = parse_stat(&read_all(r));
        sc.wait().unwrap();
        assert_eq!((st2.pgrp, st2.session, st2.tpgid, st2.tty_nr), (st2.pid, raw(me), st2.pid, st.tty_nr));
        tcsetpgrp(&slave, me).unwrap();
        // tcsetpgrp to a group that does not exist: ESRCH, as the host
        assert_eq!(tcsetpgrp(&slave, pid(i32::MAX)).unwrap_err(), en(libc::ESRCH));
        assert_eq!(unsafe { libc::tcsetpgrp(slave.as_raw_fd(), i32::MAX) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        // a group of another session: EPERM
        assert_eq!(tcsetpgrp(&slave, getppid().unwrap()).unwrap_err(), en(libc::EPERM));
    });
}

#[test]
fn background_tcsetpgrp_with_sigttou_blocked_by_spawned_child() {
    // a background child (not ignoring SIGTTOU: reset_signal) still takes the foreground: our child does the
    // tcsetpgrp with every signal blocked, so no SIGTTOU stops it
    isolated("background_tcsetpgrp_with_sigttou_blocked_by_spawned_child", || {
        // closing the PTY master at the end hangs up the terminal: SIGHUP to its controlling process (us)
        set_signal(Signal::HUP, Action::Ignore).unwrap();
        let (_m, slave) = pty();
        let me = setsid().unwrap();
        set_controlling_terminal(&slave, false).unwrap();
        set_signal(Signal::TTOU, Action::Ignore).unwrap();
        let (r, w) = std::io::pipe().unwrap();
        let mut c = Command::new("/bin/cat")
            .args(["/proc/self/stat", "/proc/self/status"])
            .stdin(slave.as_fd())
            .stdout(w)
            .process_group(None)
            .foreground(0, true)
            .reset_signal(Signal::TTOU)
            .spawn()
            .unwrap();
        let out = read_all(r);
        let status = c.wait().unwrap();
        assert!(status.success(), "{status:?}");
        let st = parse_stat(&out);
        assert_eq!(st.tpgid, raw(c.pid()));
        let (_blk, ign, _cgt) = sig_masks(&out);
        assert_eq!(ign & (1 << (libc::SIGTTOU - 1)), 0, "SIGTTOU reset to default in the child");
        tcsetpgrp(&slave, me).unwrap();
    });
}

// ------------------------------------------------------------------------------------------------ waitid

fn spawn_sh(script: &str) -> Child {
    Command::new("/bin/sh").args(["-c", script]).spawn().unwrap()
}

fn sn(s: Signal) -> SigNum {
    s.into()
}

#[test]
fn waitid_exit_codes_and_wnowait() {
    let c = spawn_sh("exit 3");
    let p = c.pid();
    // WNOWAIT reports without reaping: the host sees the same afterwards
    let i = waitid(WaitId::Pid(p), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT).unwrap().unwrap();
    assert_eq!(i, WaitInfo { pid: p, uid: getuid(), code: WaitCode::Exited(3) });
    assert_eq!((i.exit_code(), i.signal()), (Some(3), None));
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::waitid(libc::P_PID, raw(p) as u32, &mut si, libc::WEXITED | libc::WNOWAIT) }, 0);
    assert_eq!(unsafe { (si.si_pid(), si.si_status(), si.si_uid()) }, (raw(p), 3, getuid().as_raw()));
    assert_eq!(si.si_code, libc::CLD_EXITED);
    let ws = i.wait_status();
    assert!(libc::WIFEXITED(ws) && libc::WEXITSTATUS(ws) == 3);
    assert_eq!(i.exit_status().code(), Some(3));
    // now reap it
    assert_eq!(waitid(WaitId::Pid(p), WaitIdOptions::EXITED).unwrap().unwrap().code, WaitCode::Exited(3));
    assert_eq!(waitid(WaitId::Pid(p), WaitIdOptions::EXITED).unwrap_err(), en(libc::ECHILD));
    // no flags: EINVAL; not our child: ECHILD
    assert_eq!(waitid(WaitId::Pid(p), WaitIdOptions::empty()).unwrap_err(), en(libc::EINVAL));
    assert_eq!(waitid(WaitId::Pid(Pid::INIT), WaitIdOptions::EXITED).unwrap_err(), en(libc::ECHILD));
}

#[test]
fn waitid_stop_continue_kill() {
    let mut c = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let p = c.pid();
    assert_eq!(waitid(c.wait_id(), WaitIdOptions::EXITED | WaitIdOptions::STOPPED | WaitIdOptions::NOHANG).unwrap(), None);
    c.send_signal(Signal::STOP).unwrap();
    let i = waitid(WaitId::Pid(p), WaitIdOptions::STOPPED).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Stopped(sn(Signal::STOP)));
    assert_eq!(i.signal(), Some(sn(Signal::STOP)));
    let ws = i.wait_status();
    assert!(libc::WIFSTOPPED(ws) && libc::WSTOPSIG(ws) == libc::SIGSTOP);
    c.send_signal(Signal::CONT).unwrap();
    let i = waitid(WaitId::Pid(p), WaitIdOptions::CONTINUED).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Continued);
    assert_eq!(i.signal(), Some(sn(Signal::CONT)));
    assert!(libc::WIFCONTINUED(i.wait_status()));
    c.send_signal(Signal::KILL).unwrap();
    let i = waitid(c.wait_id(), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Killed(sn(Signal::KILL)));
    let ws = i.wait_status();
    assert!(libc::WIFSIGNALED(ws) && libc::WTERMSIG(ws) == libc::SIGKILL && !libc::WCOREDUMP(ws));
    let st = c.wait().unwrap();
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&st), Some(libc::SIGKILL));
    assert_eq!(c.wait().unwrap(), st);
    assert!(c.send_signal(Signal::KILL).is_err());
}

#[test]
fn waitid_by_process_group_and_pidfd() {
    let mut c = Command::new("/bin/sh").args(["-c", "exit 9"]).process_group(None).spawn().unwrap();
    let i = waitid(WaitId::Pgid(Some(c.pid())), WaitIdOptions::EXITED | WaitIdOptions::NOWAIT).unwrap().unwrap();
    assert_eq!((i.pid, i.code), (c.pid(), WaitCode::Exited(9)));
    let fd = c.pidfd().expect("clone3 gives a pidfd");
    let i = waitid(WaitId::PidFd(fd), WaitIdOptions::EXITED).unwrap().unwrap();
    assert_eq!(i.code, WaitCode::Exited(9));
    assert!(c.wait().is_err()); // already reaped through waitid
}

#[test]
fn waitid_any_child() {
    isolated("waitid_any_child", || {
        let a = spawn_sh("exit 4");
        let b = spawn_sh("kill -TERM $$");
        // a real-time signal ends a third one: WaitCode names it
        let c = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        c.send_signal(SigNum::rt(1).unwrap()).unwrap();
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(waitid(WaitId::All, WaitIdOptions::EXITED).unwrap().unwrap());
        }
        seen.sort_by_key(|i| raw(i.pid));
        let mut want = vec![(a.pid(), WaitCode::Exited(4)), (b.pid(), WaitCode::Killed(sn(Signal::TERM))), (c.pid(), WaitCode::Killed(SigNum::rt(1).unwrap()))];
        want.sort_by_key(|w| raw(w.0));
        assert_eq!(seen.iter().map(|i| (i.pid, i.code)).collect::<Vec<_>>(), want);
        assert_eq!(waitid(WaitId::All, WaitIdOptions::EXITED | WaitIdOptions::NOHANG).unwrap_err(), en(libc::ECHILD));
        // the internal signals are not sent
        assert_eq!(c.send_signal(SigNum::new(32).unwrap()).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    });
}

#[test]
fn wait_status_encoding_matches_host_macros() {
    let n = |k: i32| SigNum::new(k).unwrap();
    for (code, check) in [
        (WaitCode::Exited(0), "exit0"),
        (WaitCode::Exited(255), "exit255"),
        (WaitCode::Killed(n(9)), "sig9"),
        (WaitCode::Dumped(n(11)), "core11"),
        (WaitCode::Stopped(n(20)), "stop20"),
        (WaitCode::Trapped(n(5)), "stop5"),
        (WaitCode::Continued, "cont"),
    ] {
        let ws = WaitInfo { pid: Pid::INIT, uid: Uid::ROOT, code }.wait_status();
        let got = if libc::WIFEXITED(ws) {
            format!("exit{}", libc::WEXITSTATUS(ws))
        } else if libc::WIFSIGNALED(ws) {
            format!("{}{}", if libc::WCOREDUMP(ws) { "core" } else { "sig" }, libc::WTERMSIG(ws))
        } else if libc::WIFSTOPPED(ws) {
            format!("stop{}", libc::WSTOPSIG(ws))
        } else if libc::WIFCONTINUED(ws) {
            "cont".into()
        } else {
            "?".into()
        };
        assert_eq!(got, check);
    }
}
