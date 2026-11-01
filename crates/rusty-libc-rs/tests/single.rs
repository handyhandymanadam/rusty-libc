//! FIXLIST #127 stage 4, single-threaded checks (harness = false: libtest always runs tests on a second thread, so the
//! safe environment setters and exec with a descriptor above 2 would refuse there). `main` runs the in-process checks,
//! then starts itself again for each exec scenario (RLRS_SCENARIO) and checks what the exec'd program printed. Prints
//! a libtest-style "test result:" line for tools/rusty-libc-rs-tests.sh. Arguments (libtest options) are ignored.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

use rusty_libc_rs::*;
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

fn self_command(scenario: &str) -> std::process::Command {
    let exe = std::env::var_os("RLRS_TEST_EXE").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_exe().unwrap());
    let mut c = match std::env::var_os("RLRS_LOADER") {
        Some(ld) => {
            let mut c = std::process::Command::new(ld);
            c.arg("--library-path").arg(std::env::var_os("RLRS_LIBPATH").unwrap()).arg(exe);
            c
        }
        None => std::process::Command::new(exe),
    };
    c.env("RLRS_SCENARIO", scenario);
    c
}

fn run_scenario(name: &str) -> (String, i32) {
    let out = self_command(name).stdin(std::process::Stdio::null()).output().unwrap();
    (String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr), out.status.code().unwrap_or(-1))
}

/// A process started with an environment std cannot build (entries without '=', with an empty name, empty), through the
/// host C library's posix_spawn.
fn odd_env_scenario() -> (String, i32) {
    let exe = std::env::var_os("RLRS_TEST_EXE").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_exe().unwrap());
    let mut argv: Vec<CString> = Vec::new();
    if let Some(ld) = std::env::var_os("RLRS_LOADER") {
        argv.push(CString::new(ld.as_bytes()).unwrap());
        argv.push(CString::new("--library-path").unwrap());
        argv.push(CString::new(std::env::var_os("RLRS_LIBPATH").unwrap().as_bytes()).unwrap());
    }
    argv.push(CString::new(exe.as_os_str().as_bytes()).unwrap());
    let envs: Vec<CString> = ["RLRS_SCENARIO=odd_env", "NOEQUALS", "=x=1", "", "A=1", "A=2", "PATH=/usr/bin:/bin"].iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut av: Vec<*mut libc::c_char> = argv.iter().map(|c| c.as_ptr() as *mut _).collect();
    av.push(std::ptr::null_mut());
    let mut ev: Vec<*mut libc::c_char> = envs.iter().map(|c| c.as_ptr() as *mut _).collect();
    ev.push(std::ptr::null_mut());
    let (r, w) = std::io::pipe().unwrap();
    let mut fa: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::posix_spawn_file_actions_init(&mut fa);
        libc::posix_spawn_file_actions_adddup2(&mut fa, std::os::fd::AsRawFd::as_raw_fd(&w), 1);
        libc::posix_spawn_file_actions_adddup2(&mut fa, std::os::fd::AsRawFd::as_raw_fd(&w), 2);
    }
    let mut pid = 0;
    assert_eq!(unsafe { libc::posix_spawn(&mut pid, av[0], &fa, std::ptr::null(), av.as_ptr(), ev.as_ptr()) }, 0);
    drop(w);
    let mut s = String::new();
    std::io::Read::read_to_string(&mut std::fs::File::from(std::os::fd::OwnedFd::from(r)), &mut s).unwrap();
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    (s, if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 })
}

fn scenario(name: &str) {
    match name {
        "odd_env" => {
            // the raw view keeps every entry; std's drops the odd ones
            let raw: Vec<OsString> = env::vars_raw();
            let want: Vec<OsString> = ["RLRS_SCENARIO=odd_env", "NOEQUALS", "=x=1", "", "A=1", "A=2", "PATH=/usr/bin:/bin"].iter().map(OsString::from).collect();
            assert_eq!(raw, want);
            // exec with no environment change passes environ exactly: `env` prints it (NUL-separated)
            let e = Command::new("env").arg("-0").exec();
            panic!("exec returned: {e}");
        }
        "exec_fds" => {
            // map a pipe's write end to fd 5 and stdout to fd 1 in place, change argv[0], directory, env, then exec sh
            let (r, w) = std::io::pipe().unwrap();
            let e = Command::new("sh")
                .arg0("rlrs-sh")
                .args(["-c", "echo $0 $RLRS_X $(pwd) >&5; read l <&6; echo got $l"])
                .fd(5, Stdio::Owned(w.into()))
                .fd(6, Stdio::Owned(r.into()))
                .env("RLRS_X", "x1")
                .current_dir("/")
                .exec();
            panic!("exec returned: {e}");
        }
        "exec_ignored_reset" => {
            // SIGINT ignored here; reset_signal gives the program the default; SIGQUIT stays ignored; SIGPIPE default
            signal::set_signal(Signal::INT, Action::Ignore).unwrap();
            signal::set_signal(Signal::QUIT, Action::Ignore).unwrap();
            let e = Command::new("sh").args(["-c", "grep -E '^Sig(Ign|Blk)' /proc/self/status"]).reset_signal(Signal::INT).signal_mask(SigSet::empty().with(Signal::USR2)).exec();
            panic!("exec returned: {e}");
        }
        "exec_high_fd_restore" => {
            // single-threaded: a target above 2 is allowed; after a failed exec fd 9 is what it was (closed) and fd 8
            // still refers to its original file. Descriptors 3..=9 the runner left open (tools/heavy, unshare) are
            // adopted and closed first, so the numbers below are the ones the test means.
            for n in 3..=9 {
                drop(rusty_libc_rs::fd::take_inherited(n));
            }
            let f = std::fs::File::open("/etc/hostname").unwrap();
            let fd8 = rusty_libc_rs::io::fcntl_dupfd_cloexec(&f, 8).unwrap();
            assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&fd8), 8);
            let ino = |fd: i32| {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                (unsafe { libc::fstat(fd, &mut st) }, st.st_ino)
            };
            let before8 = ino(8);
            // an OwnedFd the caller holds at 5 (a pipe's read end), mapped over by the exec that fails
            let (r0, w0) = std::io::pipe().unwrap();
            // move both ends above 5, then put the read end at the lowest free number from 5 up (5 itself)
            let mut w = std::fs::File::from(rusty_libc_rs::io::fcntl_dupfd_cloexec(&w0, 20).unwrap());
            let r = rusty_libc_rs::io::fcntl_dupfd_cloexec(&r0, 20).unwrap();
            drop((r0, w0));
            let r5 = rusty_libc_rs::io::fcntl_dupfd_cloexec(&r, 5).unwrap();
            drop(r);
            assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&r5), 5);
            let before5 = ino(5);
            let e = Command::new("no-such-program-rlrs").fd(5, Stdio::Null).fd(8, Stdio::Null).fd(9, Stdio::Null).exec_detailed();
            assert_eq!(e.exit_code(), 127);
            assert_eq!(ino(5), before5);
            std::io::Write::write_all(&mut w, b"still the pipe").unwrap();
            drop(w);
            let mut got = String::new();
            std::io::Read::read_to_string(&mut std::fs::File::from(r5), &mut got).unwrap();
            assert_eq!(got, "still the pipe");
            assert_eq!(ino(8), before8);
            assert_eq!(unsafe { libc::fcntl(8, libc::F_GETFD) }, libc::FD_CLOEXEC);
            assert_eq!(unsafe { libc::fcntl(9, libc::F_GETFD) }, -1);
            println!("restore ok");
        }
        "default_path" => {
            // started without PATH: a bare name is searched in confstr(_CS_PATH), by spawn (execvp's rules), by spawn
            // without the shell fallback (posix_spawnp's) and by exec; the parent reads the execve paths with strace
            assert!(std::env::var_os("PATH").is_none());
            let e = Command::new("rl-no-such-prog-r1").spawn_detailed().unwrap_err();
            println!("spawn {:?}", e.error.raw_os_error());
            let e = Command::new("rl-no-such-prog-r2").shell_fallback(false).spawn_detailed().unwrap_err();
            println!("spawn-no-shell {:?}", e.error.raw_os_error());
            let e = Command::new("rl-no-such-prog-r3").exec_detailed();
            println!("exec {:?}", e.error.raw_os_error());
        }
        _ => panic!("unknown scenario {name}"),
    }
}

fn main() {
    if let Ok(name) = std::env::var("RLRS_SCENARIO") {
        scenario(&name);
        return;
    }
    let mut passed = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        if ok {
            passed += 1;
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED\n{detail}");
            println!("test result: FAILED. {passed} passed; 1 failed");
            std::process::exit(101);
        }
    };

    // environment changes: allowed with one thread, visible to std and to the C library's getenv
    check("single_threaded", env::is_single_threaded().unwrap(), String::new());
    let mask = signal::blocked_signals();
    env::set_var("RLRS_SINGLE", "v=1").unwrap();
    check("mask restored after set_var", signal::blocked_signals() == mask, String::new());
    let c = unsafe { libc::getenv(c"RLRS_SINGLE".as_ptr()) };
    let via_c = (!c.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(c) }.to_bytes().to_vec());
    check("set_var", std::env::var("RLRS_SINGLE").as_deref() == Ok("v=1") && via_c.as_deref() == Some(&b"v=1"[..]), format!("{via_c:?}"));
    check("vars_raw sees it", env::vars_raw().contains(&OsString::from("RLRS_SINGLE=v=1")), String::new());
    env::remove_var("RLRS_SINGLE").unwrap();
    check("remove_var", std::env::var_os("RLRS_SINGLE").is_none() && unsafe { libc::getenv(c"RLRS_SINGLE".as_ptr()) }.is_null(), String::new());
    check("bad names", env::set_var("", "1").is_err() && env::set_var("A=B", "1").is_err() && env::set_var("A", OsStr::from_bytes(b"\0")).is_err(), String::new());
    // a thread makes it refuse
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let h = std::thread::spawn(move || {
        rx.recv().ok();
    });
    let r = env::set_var("RLRS_SINGLE", "2");
    tx.send(()).unwrap();
    h.join().unwrap();
    check("refused with a thread", r == Err(Errno::BUSY), format!("{r:?}"));

    let (out, code) = odd_env_scenario();
    let want = "RLRS_SCENARIO=odd_env\0NOEQUALS\0=x=1\0\0A=1\0A=2\0PATH=/usr/bin:/bin\0";
    check("odd environment kept by vars_raw and exec", code == 0 && out == want, format!("code {code}: {out:?}"));

    let (out, code) = run_scenario("exec_fds");
    check("exec with fd 5/6 mapping, argv0, env, cwd", code == 0 && out == "got rlrs-sh x1 /\n", format!("code {code}: {out:?}"));

    let (out, code) = run_scenario("exec_ignored_reset");
    // signals the runner already ignores (nohup: SIGHUP) stay ignored across exec; SIGINT is reset by the scenario and SIGPIPE (ignored by Rust's runtime here) by Command
    let inherited = std::fs::read_to_string("/proc/self/status").ok().and_then(|t| t.lines().find_map(|l| l.strip_prefix("SigIgn:\t").map(str::to_owned))).and_then(|h| u64::from_str_radix(h.trim(), 16).ok()).unwrap_or(0);
    let ign = (inherited & !(1u64 << (libc::SIGINT - 1)) & !(1u64 << (libc::SIGPIPE - 1))) | (1u64 << (libc::SIGQUIT - 1));
    let blk = 1u64 << (libc::SIGUSR2 - 1);
    check("exec signal defaults and mask", code == 0 && out == format!("SigBlk:\t{blk:016x}\nSigIgn:\t{ign:016x}\n"), format!("code {code}: {out:?}"));

    let (out, code) = run_scenario("exec_high_fd_restore");
    check("exec high fd restore after failure", code == 0 && out.contains("restore ok"), format!("code {code}: {out}"));

    // PATH unset: the directories of confstr(_CS_PATH) as the host's (glibc's) execvp and posix_spawnp search them, seen
    // with strace; host reference `getconf PATH`
    let host_cs_path = std::process::Command::new("getconf").arg("PATH").output().ok().filter(|o| o.status.success());
    let have_strace = std::process::Command::new("strace").arg("-V").output().is_ok_and(|o| o.status.success());
    match host_cs_path {
        Some(cs) if have_strace => {
            let log = std::env::temp_dir().join(format!("rlrs-default-path-{}.strace", std::process::id()));
            let inner = self_command("default_path");
            let mut c = std::process::Command::new("strace");
            c.args(["-f", "-qq", "-e", "trace=execve", "-e", "signal=none", "-o"]).arg(&log).arg(inner.get_program()).args(inner.get_args());
            c.env("RLRS_SCENARIO", "default_path").env_remove("PATH").stdin(std::process::Stdio::null());
            let out = c.output().unwrap();
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let _ = std::fs::remove_file(&log);
            let seen: Vec<String> = text.lines().filter_map(|l| l.split("execve(\"").nth(1)).filter_map(|r| r.split('"').next()).filter(|p| p.contains("rl-no-such-prog-r")).map(String::from).collect();
            let cs = String::from_utf8_lossy(&cs.stdout).trim_end().to_string();
            let want: Vec<String> = (1..=3).flat_map(|i| cs.split(':').map(move |d| format!("{}/rl-no-such-prog-r{i}", if d.is_empty() { "." } else { d }))).collect();
            let printed = String::from_utf8_lossy(&out.stdout).into_owned();
            let enoent = format!("Some({})", libc::ENOENT);
            let want_out = format!("spawn {enoent}\nspawn-no-shell {enoent}\nexec {enoent}\n");
            check("PATH unset: confstr(_CS_PATH) as the host's", out.status.success() && seen == want && printed == want_out, format!("getconf PATH {cs}; execve {seen:?}; printed {printed:?} {}", String::from_utf8_lossy(&out.stderr)));
        }
        _ => println!("test PATH unset ... skipped (no strace or getconf)"),
    }

    println!("test result: ok. {passed} passed; 0 failed");
}
