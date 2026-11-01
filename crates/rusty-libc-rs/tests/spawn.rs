//! The spawn builder: arguments, environment, directory, descriptors, errors, sessions, process groups, controlling
//! terminal and foreground (in a PTY), signal dispositions and mask, both clone paths (clone3 and the plain clone
//! fallback), many threads at once, and the same steps through std + pre_exec + the host C library for comparison.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

mod common;
use common::*;
use libc::{SIGINT, SIGPIPE, SIGRTMAX, SIGTERM, SIGTSTP, SIGTTOU, SIGUSR1, SIGUSR2};
use rusty_libc_rs::io::fcntl_dupfd_cloexec;
use rusty_libc_rs::process::{geteuid, getsid};
use rusty_libc_rs::signal::{blocked_signals, get_signal, set_signal};
use rusty_libc_rs::*;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::ExitStatusExt;

fn bit(sig: i32) -> u64 {
    1 << (sig - 1)
}

/// Run `cmd` with its stdout on a pipe; (output, exit status).
fn output(cmd: &mut Command<'_>) -> (String, std::process::ExitStatus) {
    let (r, w) = std::io::pipe().unwrap();
    cmd.stdout(w);
    let mut c = cmd.spawn().unwrap();
    cmd.stdout(Stdio::Inherit); // drop our copy of the write end
    let out = read_all(r);
    (out, c.wait().unwrap())
}

/// All spawn checks that do not need a terminal; run with clone3 (in this process) and with the plain clone fallback
/// (in a scenario process). `legacy`: expect no pidfd.
fn spawn_checks(legacy: bool) {
    // argv and argv[0]
    let (out, st) = output(Command::new("/bin/cat").arg0("my-name").arg("/proc/self/cmdline"));
    assert!(st.success());
    assert_eq!(out, "my-name\0/proc/self/cmdline\0");
    let (out, _) = output(Command::new("/bin/echo").args(["a b", "", "c"]));
    assert_eq!(out, "a b  c\n");
    // non-UTF-8 argument bytes pass through
    let (r, w) = std::io::pipe().unwrap();
    let mut c = Command::new("/bin/cat").arg("/proc/self/cmdline").arg(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"\xff\xfe")).stdout(w).spawn().unwrap();
    let mut bytes = Vec::new();
    std::fs::File::from(std::os::fd::OwnedFd::from(r)).read_to_end(&mut bytes).unwrap();
    c.wait().unwrap();
    assert_eq!(bytes, b"/bin/cat\0/proc/self/cmdline\0\xff\xfe\0");

    // environment: cleared + set, removed, inherited
    let (out, _) = output(Command::new("/usr/bin/env").env_clear().env("B", "2").env("A", "1"));
    assert_eq!(out, "A=1\nB=2\n");
    let (out, _) = output(Command::new("/usr/bin/env").env("RLRS_X", "y").env_remove("HOME"));
    assert!(out.lines().any(|l| l == "RLRS_X=y"));
    assert!(!out.lines().any(|l| l.starts_with("HOME=")));
    if let Some(p) = std::env::var_os("PATH") {
        let (out, _) = output(&mut Command::new("/usr/bin/env"));
        assert!(out.lines().any(|l| l.as_bytes() == [b"PATH=".as_slice(), std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str())].concat()));
    }

    // working directory, and a relative program path relative to it
    let (out, _) = output(Command::new("/bin/pwd").arg("-P").current_dir("/"));
    assert_eq!(out, "/\n");
    let (out, st) = output(Command::new("./cat").arg("/proc/self/cmdline").current_dir("/bin").arg0("rel"));
    assert!(st.success());
    assert_eq!(out, "rel\0/proc/self/cmdline\0");

    // PATH search: the child's PATH when the environment is set
    let (out, st) = output(Command::new("echo").arg("found").env_clear().env("PATH", "/nonexistent::/usr/bin"));
    assert!(st.success());
    assert_eq!(out, "found\n");
    let e = Command::new("echo").env_clear().env("PATH", "/nonexistent").spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Exec, Some(libc::ENOENT)));
    // a PATH directory with a non-executable match: EACCES remembered, later match used
    let dir = std::env::temp_dir().join(format!("rlrs-path-{}-{legacy}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("echo"), "not executable").unwrap();
    let (out, _) = output(Command::new("echo").arg("second").env("PATH", format!("{}:/usr/bin", dir.display())));
    assert_eq!(out, "second\n");
    let e = Command::new("echo").env("PATH", dir.as_os_str()).spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Exec, Some(libc::EACCES)));

    // stdin from a file, stderr to a pipe, stdin /dev/null
    let f = tmp_with(b"from a file\n");
    let (out, _) = output(Command::new("/bin/cat").stdin(f));
    assert_eq!(out, "from a file\n");
    let (er, ew) = std::io::pipe().unwrap();
    let mut c = Command::new("/bin/sh").args(["-c", "echo to-stderr >&2"]).stderr(ew).spawn().unwrap();
    assert_eq!(read_all(er), "to-stderr\n");
    assert!(c.wait().unwrap().success());
    let (out, _) = output(Command::new("/bin/cat").stdin(Stdio::Null));
    assert_eq!(out, "");
    // a borrowed descriptor stays open in the parent
    let f = tmp_with(b"borrowed\n");
    let (out, _) = output(Command::new("/bin/cat").stdin(f.as_fd()));
    assert_eq!(out, "borrowed\n");
    assert!(unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) } >= 0);

    // extra descriptors, including swapped numbers (A's number gets B and the other way round)
    let a = tmp_with(b"AAA");
    let b = tmp_with(b"BBB");
    let (na, nb) = (a.as_raw_fd(), b.as_raw_fd());
    let script = format!("cat <&{na}; echo; cat <&{nb}");
    let (out, st) = output(Command::new("/bin/sh").args(["-c", &script]).fd(na, b.as_fd()).fd(nb, a.as_fd()));
    assert!(st.success(), "{st:?}");
    assert_eq!(out, "BBB\nAAA");
    // a mapping onto 1 overrides stdout; a mapping to a high number
    let (r, w) = std::io::pipe().unwrap();
    let mut c = Command::new("/bin/sh").args(["-c", "echo high >&57"]).fd(57, w).spawn().unwrap();
    assert_eq!(read_all(r), "high\n");
    assert!(c.wait().unwrap().success());
    // the parent's own descriptors with FD_CLOEXEC do not leak; the mapped ones are not FD_CLOEXEC in the child
    let high = fcntl_dupfd_cloexec(&a, 200).unwrap();
    let (out, _) = output(Command::new("/bin/sh").args(["-c", "ls /proc/self/fd"]).fd(9, Stdio::Null));
    let fds: Vec<i32> = out.split_whitespace().filter_map(|s| s.parse().ok()).collect();
    assert!(fds.contains(&9), "{fds:?}");
    assert!(!fds.contains(&high.as_raw_fd()), "{fds:?}");
    drop(high);

    // exit statuses
    let mut c = Command::new("/bin/sh").args(["-c", "exit 7"]).spawn().unwrap();
    assert!(c.try_wait().map(|s| s.is_none() || s.unwrap().code() == Some(7)).unwrap());
    assert_eq!(c.wait().unwrap().code(), Some(7));
    let mut c = Command::new("/bin/sh").args(["-c", "kill -TERM $$"]).spawn().unwrap();
    assert_eq!(c.wait().unwrap().signal(), Some(SIGTERM));
    assert_eq!(c.pidfd().is_none(), legacy);

    // failures, with their step
    let e = Command::new("/nonexistent/prog").spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Exec, Some(libc::ENOENT)));
    let e = Command::new("/tmp").spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Exec, Some(libc::EACCES)));
    let script = dir.join("noexec-format");
    std::fs::write(&script, b"\x01\x02\x03 not a program").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    // ETXTBSY: a fork-like child of a test running in parallel can still hold the write descriptor of the file just
    // written (until its exec closes it); retry until that window has passed
    // (without the /bin/sh fallback, posix_spawnp's behaviour; with it the file would run as a shell script)
    let mut e = Command::new(&script).shell_fallback(false).spawn_detailed().unwrap_err();
    for _ in 0..100 {
        if e.error.raw_os_error() != Some(libc::ETXTBSY) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        e = Command::new(&script).shell_fallback(false).spawn_detailed().unwrap_err();
    }
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Exec, Some(libc::ENOEXEC)));
    let e = Command::new("/bin/true").current_dir("/nonexistent-dir").spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Chdir, Some(libc::ENOENT)));
    let e: std::io::Error = Command::new("/bin/true").current_dir("/nonexistent-dir").spawn().unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    let e = Command::new("/bin/true").arg("a\0b").spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.kind()), (Stage::Prepare, std::io::ErrorKind::InvalidInput));
    let e = Command::new("/bin/true").env("A=B", "x").spawn_detailed().unwrap_err();
    assert_eq!(e.stage, Stage::Prepare);
    let e = Command::new("/bin/true").setsid(true).process_group(Some(pid(5))).spawn_detailed().unwrap_err();
    assert_eq!(e.stage, Stage::Prepare);
    for s in [Signal::KILL.into(), Signal::STOP.into(), SigNum::new(32).unwrap(), SigNum::new(33).unwrap()] {
        let e = Command::new("/bin/true").reset_signal(s).spawn_detailed().unwrap_err();
        assert_eq!(e.stage, Stage::Prepare, "reset_signal({s:?})");
    }
    let e = Command::new("/bin/true").fd(-1, Stdio::Null).spawn_detailed().unwrap_err();
    assert_eq!(e.stage, Stage::Prepare);
    let e = Command::new("/bin/true").process_group(Some(pid(i32::MAX))).spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Setpgid, Some(libc::EPERM)));
    let e = Command::new("/bin/true").controlling_terminal(0, false).stdin(Stdio::Null).spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::ControllingTerminal, Some(libc::ENOTTY)));
    let e = Command::new("/bin/true").foreground(0, true).stdin(Stdio::Null).spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Foreground, Some(libc::ENOTTY)));
    // ... but not when the foreground is optional
    assert!(Command::new("/bin/true").foreground(0, false).stdin(Stdio::Null).spawn().unwrap().wait().unwrap().success());

    // session and process group, against the same steps through std + pre_exec
    let me = std::process::id() as i32;
    let my_sid = rawo(getsid(None).unwrap());
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/stat").setsid(true));
    let st = parse_stat(&out);
    assert_eq!((st.session, st.pgrp, st.tty_nr, st.ppid), (st.pid, st.pid, 0, me));
    let std_st = std_stat(|| unsafe {
        libc::setsid();
    });
    assert_eq!((std_st.session, std_st.pgrp, std_st.tty_nr), (std_st.pid, std_st.pid, 0));
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/stat").process_group(None));
    let st = parse_stat(&out);
    assert_eq!((st.session, st.pgrp), (my_sid, st.pid));
    let std_st = std_stat(|| unsafe {
        libc::setpgid(0, 0);
    });
    assert_eq!((std_st.session, std_st.pgrp), (my_sid, std_st.pid));
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/stat").setsid(true).process_group(None));
    assert_eq!(parse_stat(&out).session, parse_stat(&out).pid);
    // joining an existing group
    let mut leader = Command::new("/bin/sleep").arg("30").process_group(None).spawn().unwrap();
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/stat").process_group(Some(leader.pid())));
    assert_eq!(parse_stat(&out).pgrp, raw(leader.pid()));
    leader.send_signal(Signal::KILL).unwrap();
    assert_eq!(leader.wait().unwrap().signal(), Some(libc::SIGKILL));

    // signals: SIGPIPE back to default (this Rust process ignores it), unless kept; the mask
    assert_eq!(get_signal(Signal::PIPE).unwrap(), Disposition::Ignore);
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/status"));
    let (blk, ign, cgt) = sig_masks(&out);
    assert_eq!(ign & bit(SIGPIPE), 0);
    assert_eq!(cgt, 0);
    assert_eq!(blk, blocked_signals().bits());
    let (std_blk, std_ign, std_cgt) = sig_masks(&std_status());
    assert_eq!((blk, ign, cgt), (std_blk, std_ign, std_cgt), "same signal state as std's spawn");
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/status").keep_signal(Signal::PIPE));
    assert_ne!(sig_masks(&out).1 & bit(SIGPIPE), 0);
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/status").signal_mask(SigSet::empty().with(Signal::USR1).with(SigNum::RTMAX).with(SigNum::new(32).unwrap())));
    assert_eq!(sig_masks(&out).0, bit(SIGUSR1) | bit(SIGRTMAX()));

    // the pidfd becomes readable when the child ends
    if !legacy {
        let mut c = Command::new("/bin/true").spawn().unwrap();
        let mut pfd = libc::pollfd { fd: c.pidfd().unwrap().as_raw_fd(), events: libc::POLLIN, revents: 0 };
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 10_000) }, 1);
        assert!(c.try_wait().unwrap().unwrap().success());
    }
    std::fs::remove_dir_all(&dir).ok();
}

fn tmp_with(content: &[u8]) -> std::fs::File {
    use std::io::{Seek, SeekFrom};
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!("rlrs-sp-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    f.write_all(content).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f
}

/// /proc/self/stat of a `cat` started through std with `pre` as its pre_exec hook.
fn std_stat(pre: fn()) -> Stat {
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.arg("/proc/self/stat");
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
            pre();
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    parse_stat(&String::from_utf8(out.stdout).unwrap())
}

/// /proc/self/status of a `cat` started through std (no hooks: std's default spawn).
fn std_status() -> String {
    String::from_utf8(std::process::Command::new("/bin/cat").arg("/proc/self/status").output().unwrap().stdout).unwrap()
}

#[test]
fn spawn_with_clone3() {
    spawn_checks(false);
}

#[test]
fn spawn_with_plain_clone_fallback() {
    isolated("spawn_with_plain_clone_fallback", || {
        spawn::set_force_legacy_clone(true);
        spawn_checks(true);
    });
}

/// A parent with handlers, ignored job-control signals and a blocked signal: the child gets no handler (reset), keeps
/// what was ignored unless reset, and the parent's mask unless one is given. Both clone paths.
fn signal_inheritance(legacy: bool) {
    spawn::set_force_legacy_clone(legacy);
    extern "C" fn h(_: i32) {}
    unsafe {
        libc::signal(SIGUSR2, h as *const () as libc::sighandler_t);
        libc::signal(SIGINT, h as *const () as libc::sighandler_t);
    }
    set_signal(Signal::TTOU, Action::Ignore).unwrap();
    set_signal(Signal::TSTP, Action::Ignore).unwrap();
    let mut m: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut m);
        libc::sigaddset(&mut m, SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &m, std::ptr::null_mut());
    }
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/status"));
    let (blk, ign, cgt) = sig_masks(&out);
    assert_eq!(cgt, 0, "no handler survives");
    assert_eq!(ign & (bit(SIGTTOU) | bit(SIGTSTP)), bit(SIGTTOU) | bit(SIGTSTP));
    assert_eq!(ign & (bit(SIGUSR2) | bit(SIGINT) | bit(SIGPIPE)), 0);
    assert_eq!(blk, bit(SIGUSR1));
    // the same as std's spawn (which resets SIGPIPE too and keeps the mask)
    assert_eq!(sig_masks(&std_status()), (blk, ign, cgt));
    let (out, _) = output(Command::new("/bin/cat").arg("/proc/self/status").reset_signal(Signal::TTOU).reset_signal(Signal::TSTP).signal_mask(SigSet::empty()));
    let (blk, ign, _) = sig_masks(&out);
    assert_eq!(ign & (bit(SIGTTOU) | bit(SIGTSTP)), 0);
    assert_eq!(blk, 0);
    // our handlers are untouched in the parent
    assert_eq!(get_signal(Signal::USR2).unwrap(), Disposition::Handler);
    assert_eq!(get_signal(Signal::INT).unwrap(), Disposition::Handler);
    assert_eq!(blocked_signals(), SigSet::empty().with(Signal::USR1));
}

#[test]
fn signal_inheritance_clone3() {
    isolated("signal_inheritance_clone3", || signal_inheritance(false));
}

#[test]
fn signal_inheritance_plain_clone() {
    isolated("signal_inheritance_plain_clone", || signal_inheritance(true));
}

/// New session + controlling terminal + foreground in a PTY, from a process that is not a session leader, compared
/// with std + pre_exec doing the same through the host C library.
fn session_in_pty(legacy: bool) {
    spawn::set_force_legacy_clone(legacy);
    let (_master, slave) = pty();
    let (r, w) = std::io::pipe().unwrap();
    let mut c = Command::new("/bin/cat")
        .arg("/proc/self/stat")
        .stdin(slave.as_fd())
        .stdout(w)
        .setsid(true)
        .controlling_terminal(0, false)
        .foreground(0, true)
        .spawn()
        .unwrap();
    let st = parse_stat(&read_all(r));
    assert!(c.wait().unwrap().success());
    let cp = raw(c.pid());
    assert_eq!((st.session, st.pgrp, st.tpgid, st.tty_nr), (cp, cp, cp, tty_nr(&slave)));

    let (r, w) = std::io::pipe().unwrap();
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.arg("/proc/self/stat").stdin(slave.try_clone().unwrap()).stdout(w);
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            libc::setsid();
            if libc::ioctl(0, libc::TIOCSCTTY, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::tcsetpgrp(0, libc::getpgrp());
            Ok(())
        });
    }
    let mut sc = cmd.spawn().unwrap();
    drop(cmd);
    let st2 = parse_stat(&read_all(r));
    sc.wait().unwrap();
    assert_eq!((st2.session, st2.pgrp, st2.tpgid, st2.tty_nr), (st2.pid, st2.pid, st2.pid, st.tty_nr));
    // a terminal that is another session's controlling terminal cannot be taken without steal (the terminal's old
    // session is gone here: its leader exited, so it is free again)
    let mut keeper = Command::new("/bin/sleep").arg("30").stdin(slave.as_fd()).setsid(true).controlling_terminal(0, false).spawn().unwrap();
    let e = Command::new("/bin/true").stdin(slave.as_fd()).setsid(true).controlling_terminal(0, false).spawn_detailed().unwrap_err();
    assert_eq!((e.stage, e.error.raw_os_error()), (Stage::ControllingTerminal, Some(libc::EPERM)));
    let e = Command::new("/bin/true").stdin(slave.as_fd()).setsid(true).controlling_terminal(0, true).spawn_detailed();
    if geteuid().as_raw() != 0 {
        // stealing needs CAP_SYS_ADMIN
        assert_eq!(e.unwrap_err().error.raw_os_error(), Some(libc::EPERM));
    }
    keeper.send_signal(Signal::KILL).unwrap();
    keeper.wait().unwrap();
}

#[test]
fn session_and_controlling_terminal_in_pty() {
    isolated("session_and_controlling_terminal_in_pty", || session_in_pty(false));
}

#[test]
fn session_and_controlling_terminal_in_pty_plain_clone() {
    isolated("session_and_controlling_terminal_in_pty_plain_clone", || session_in_pty(true));
}

#[test]
fn many_threads_spawning_at_once() {
    let threads: Vec<_> = (0..8)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..40 {
                    // other threads allocate and free meanwhile; the children must still see their own arguments
                    let v: Vec<String> = (0..50).map(|k| format!("{t}-{i}-{k}")).collect();
                    let (r, w) = std::io::pipe().unwrap();
                    let mut c = Command::new("/bin/echo").arg(&v[49]).stdout(w).spawn().unwrap();
                    let out = read_all(r);
                    assert_eq!(out.trim_end(), v[49]);
                    assert!(c.wait().unwrap().success());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn clone_failure_is_reported() {
    // RLIMIT_NPROC 0 makes clone fail with EAGAIN: only in an isolated run (tools/rusty-libc-rs-tests.sh: a user + PID
    // namespace in a memory-capped scope), never as plain adam on a shared machine
    if std::env::var_os("RLRS_ISOLATED").is_none() {
        eprintln!("clone_failure_is_reported: skipped (needs RLRS_ISOLATED, see tools/rusty-libc-rs-tests.sh)");
        return;
    }
    isolated("clone_failure_is_reported", || {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &lim) }, 0);
        for legacy in [false, true] {
            spawn::set_force_legacy_clone(legacy);
            let e = Command::new("/bin/true").spawn_detailed().unwrap_err();
            assert_eq!((e.stage, e.error.raw_os_error()), (Stage::Clone, Some(libc::EAGAIN)), "legacy {legacy}");
        }
        // the parent's signal mask is restored after the failure
        assert_eq!(blocked_signals(), SigSet::empty());
    });
}

#[test]
fn stdin_pipe_round_trip() {
    let (cr, mut pw) = std::io::pipe().unwrap();
    let (pr, cw) = std::io::pipe().unwrap();
    let mut c = Command::new("/usr/bin/tr").args(["a-z", "A-Z"]).stdin(cr).stdout(cw).spawn().unwrap();
    pw.write_all(b"hello\n").unwrap();
    drop(pw);
    let mut s = String::new();
    std::fs::File::from(std::os::fd::OwnedFd::from(pr)).read_to_string(&mut s).unwrap();
    assert_eq!(s, "HELLO\n");
    assert!(c.wait().unwrap().success());
}
