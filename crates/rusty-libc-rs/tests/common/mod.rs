//! Shared test helpers: running a test body in a fresh process (for anything that changes process-wide state: session,
//! process group, signal dispositions, rlimits), reading /proc/<pid>/stat and status, and PTY pairs (through the host C
//! library: test code only).
#![allow(dead_code, clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A `Pid` as the C `pid_t`.
pub fn raw(p: rusty_libc_rs::Pid) -> i32 {
    p.as_raw_nonzero().get()
}

/// An optional `Pid` as the C `pid_t` (0 for `None`: an id outside this PID namespace).
pub fn rawo(p: Option<rusty_libc_rs::Pid>) -> i32 {
    p.map_or(0, raw)
}

/// A positive `pid_t` as a `Pid`.
pub fn pid(n: i32) -> rusty_libc_rs::Pid {
    rusty_libc_rs::Pid::from_raw(n).unwrap()
}

/// A C errno value as rustix's `Errno`.
pub fn en(n: i32) -> rusty_libc_rs::Errno {
    rusty_libc_rs::Errno::from_raw_os_error(n)
}

/// Run `body` in a new process (this test binary again, with only this test selected). The parent asserts the child
/// passed. Under rusty-libc (RLRS_LOADER set by tools/rusty-libc-rs-tests.sh) the child starts through that loader too.
pub fn isolated(name: &str, body: impl FnOnce()) {
    isolated_env(name, &[], body)
}

/// `isolated` with extra environment variables for the new process.
pub fn isolated_env(name: &str, envs: &[(&str, &std::ffi::OsStr)], body: impl FnOnce()) {
    if std::env::var("RLRS_SCENARIO").as_deref() == Ok(name) {
        body();
        return;
    }
    let exe = std::env::var_os("RLRS_TEST_EXE").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_exe().unwrap());
    let mut cmd = match std::env::var_os("RLRS_LOADER") {
        Some(ld) => {
            let mut c = std::process::Command::new(ld);
            c.arg("--library-path").arg(std::env::var_os("RLRS_LIBPATH").unwrap()).arg(&exe);
            c
        }
        None => std::process::Command::new(&exe),
    };
    let mut child = cmd
        .args([name, "--exact", "--nocapture", "--test-threads=1", "--include-ignored"])
        .env("RLRS_SCENARIO", name)
        .envs(envs.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // a hung scenario is killed after 60 s (only this child, by its handle)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let (mut o, mut e) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let to = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut o, &mut v).ok();
        v
    });
    let te = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut v).ok();
        v
    });
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            let st = child.wait().unwrap();
            eprintln!("scenario {name} timed out");
            break st;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let out = std::process::Output { status, stdout: to.join().unwrap(), stderr: te.join().unwrap() };
    let so = String::from_utf8_lossy(&out.stdout);
    let se = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && so.contains("1 passed"), "scenario {name} failed: {:?}\n{so}\n{se}", out.status);
}

/// Fields of /proc/<pid>/stat after the command name: (state, ppid, pgrp, session, tty_nr, tpgid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
}

pub fn parse_stat(s: &str) -> Stat {
    let s = s.lines().next().unwrap();
    let pid = s.split_whitespace().next().unwrap().parse().unwrap();
    let rest = &s[s.rfind(')').unwrap() + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Stat { pid, ppid: f[1].parse().unwrap(), pgrp: f[2].parse().unwrap(), session: f[3].parse().unwrap(), tty_nr: f[4].parse().unwrap(), tpgid: f[5].parse().unwrap() }
}

/// SigBlk, SigIgn, SigCgt from a /proc/<pid>/status text.
pub fn sig_masks(status: &str) -> (u64, u64, u64) {
    let get = |k: &str| {
        let line = status.lines().find(|l| l.starts_with(k)).unwrap();
        u64::from_str_radix(line[k.len()..].trim(), 16).unwrap()
    };
    (get("SigBlk:"), get("SigIgn:"), get("SigCgt:"))
}

/// A new PTY pair (master, slave), the slave opened with O_NOCTTY.
pub fn pty() -> (OwnedFd, File) {
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        assert!(m >= 0, "posix_openpt");
        let master = OwnedFd::from_raw_fd(m);
        assert_eq!(libc::grantpt(m), 0);
        assert_eq!(libc::unlockpt(m), 0);
        let mut buf = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(m, buf.as_mut_ptr(), buf.len()), 0);
        let name = CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_owned();
        let slave = std::fs::OpenOptions::new().read(true).write(true).custom_flags_noctty().open(name).unwrap();
        (master, slave)
    }
}

trait NoCtty {
    fn custom_flags_noctty(&mut self) -> &mut Self;
}
impl NoCtty for std::fs::OpenOptions {
    fn custom_flags_noctty(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, libc::O_NOCTTY)
    }
}

/// /proc/<pid>/stat's tty_nr for the terminal `f` (major << 8 | minor low byte | minor high bits << 12).
pub fn tty_nr(f: &File) -> i32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(f.as_raw_fd(), &mut st) }, 0);
    let (maj, min) = (libc::major(st.st_rdev) as i32, libc::minor(st.st_rdev) as i32);
    (min & 0xff) | (maj << 8) | ((min & !0xff) << 12)
}

/// Read all of a pipe.
pub fn read_all(r: impl Into<OwnedFd>) -> String {
    use std::io::Read;
    let mut f = File::from(r.into());
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    s
}

/// A `rusty_libc_rs::Command` that runs scenario `name` of this test binary (as `isolated` does), started through
/// `prefix` (e.g. `["unshare", "-r", "-p", "-f", "--kill-child"]`, empty for none) and through rusty-libc's loader when
/// RLRS_LOADER is set. stdout/stderr are a pipe the caller passes to `scenario_passed`; add fds etc. before spawning.
pub fn scenario_command<'a>(name: &str, prefix: &[&str]) -> (rusty_libc_rs::Command<'a>, std::io::PipeReader) {
    let exe = std::env::var_os("RLRS_TEST_EXE").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_exe().unwrap());
    let mut words: Vec<std::ffi::OsString> = prefix.iter().map(|s| s.into()).collect();
    if let Some(ld) = std::env::var_os("RLRS_LOADER") {
        words.push(ld);
        words.push("--library-path".into());
        words.push(std::env::var_os("RLRS_LIBPATH").unwrap());
    }
    words.push(exe.into_os_string());
    let mut c = rusty_libc_rs::Command::new(&words[0]);
    c.args(&words[1..]).args([name, "--exact", "--nocapture", "--test-threads=1", "--include-ignored"]).env("RLRS_SCENARIO", name);
    let (r, w) = std::io::pipe().unwrap();
    let w2 = w.try_clone().unwrap();
    c.stdin(rusty_libc_rs::Stdio::Null).stdout(w).stderr(w2);
    (c, r)
}

/// Wait for a scenario started from `scenario_command` (60 s limit, then it is killed by its handle) and assert it passed.
pub fn scenario_passed(name: &str, mut child: rusty_libc_rs::Child, out: std::io::PipeReader) {
    let reader = std::thread::spawn(move || read_all(out));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if std::time::Instant::now() > deadline {
            child.send_signal(rusty_libc_rs::Signal::KILL).ok();
            break child.wait().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let text = reader.join().unwrap();
    assert!(status.success() && text.contains("1 passed"), "scenario {name} failed: {status:?}\n{text}");
}

/// Is this a scenario run (`RLRS_SCENARIO` = `name`)?
pub fn in_scenario(name: &str) -> bool {
    std::env::var("RLRS_SCENARIO").as_deref() == Ok(name)
}
