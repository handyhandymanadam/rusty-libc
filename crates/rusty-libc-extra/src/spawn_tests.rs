//! Host tests for spawn.rs: the same spawn is made with our functions and with the host glibc's, and
//! the return value, the child's exit status and everything it printed must be equal.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::spawn::{self, FileActions, SpawnAttr};
use std::ffi::{CStr, CString};
use std::sync::Mutex;

// Spawning changes process-wide state (signal mask during the call, the descriptors of the test
// process): run the tests one at a time.
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug)]
enum Act {
    /// the pipe's write end onto descriptors 1 and 2
    PipeOut,
    Close(i32),
    Dup2(i32, i32),
    Open(i32, &'static str, i32, u32),
    Chdir(&'static str),
    Fchdir(i32),
    Closefrom(i32),
}

#[derive(Clone, Debug)]
struct Case {
    path: &'static str,
    use_path: bool,
    argv: Vec<&'static str>,
    env: Option<Vec<&'static str>>,
    acts: Vec<Act>,
    flags: i32,
    pgrp: i32,
    sigmask: u64,
    sigdef: u64,
    attr: bool,
}

impl Case {
    fn new(path: &'static str, argv: &[&'static str]) -> Case {
        Case { path, use_path: false, argv: argv.to_vec(), env: None, acts: vec![Act::PipeOut], flags: 0, pgrp: 0, sigmask: 0, sigdef: 0, attr: false }
    }
    fn sh(script: &'static str) -> Case {
        Case::new("/bin/sh", &["sh", "-c", script])
    }
    fn acts(mut self, a: &[Act]) -> Case {
        self.acts.extend_from_slice(a);
        self
    }
    fn attr(mut self, flags: i32) -> Case {
        self.attr = true;
        self.flags = flags;
        self
    }
}

#[derive(Debug, PartialEq)]
struct Outcome {
    rc: i32,
    pid_set: bool,
    status: Option<i32>,
    output: String,
}

fn cstrings(v: &[&str]) -> Vec<CString> {
    v.iter().map(|s| CString::new(*s).unwrap()).collect()
}

fn ptr_array(v: &[CString]) -> Vec<*mut libc::c_char> {
    let mut p: Vec<*mut libc::c_char> = v.iter().map(|s| s.as_ptr() as *mut libc::c_char).collect();
    p.push(std::ptr::null_mut());
    p
}

fn collect(case_rc: i32, pid: i32, r: i32, w: i32) -> Outcome {
    unsafe {
        libc::close(w);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(r, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(r);
        let mut status = None;
        if case_rc == 0 {
            let mut st = 0;
            assert_eq!(libc::waitpid(pid, &mut st, 0), pid);
            status = Some(st);
        }
        Outcome { rc: case_rc, pid_set: pid != -7, status, output: String::from_utf8_lossy(&out).into_owned() }
    }
}

/// Run `case` through the functions of module `$m` (ours or the `libc` crate's).
macro_rules! runner {
    ($name:ident, $m:path, $fa_t:ty, $attr_t:ty, $set:expr) => {
        fn $name(case: &Case) -> Outcome {
            use $m as m;
            unsafe {
                let mut fds = [0i32; 2];
                assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
                let mut fa: $fa_t = std::mem::zeroed();
                m::posix_spawn_file_actions_init(&mut fa);
                let keep: Vec<CString> = case
                    .acts
                    .iter()
                    .filter_map(|a| match a {
                        Act::Open(_, p, _, _) | Act::Chdir(p) => Some(CString::new(*p).unwrap()),
                        _ => None,
                    })
                    .collect();
                let mut ki = 0;
                for a in &case.acts {
                    let rc = match a {
                        Act::PipeOut => {
                            m::posix_spawn_file_actions_adddup2(&mut fa, fds[1], 1);
                            m::posix_spawn_file_actions_adddup2(&mut fa, fds[1], 2)
                        }
                        Act::Close(fd) => m::posix_spawn_file_actions_addclose(&mut fa, *fd),
                        Act::Dup2(a, b) => m::posix_spawn_file_actions_adddup2(&mut fa, *a, *b),
                        Act::Open(fd, _, fl, mode) => {
                            ki += 1;
                            m::posix_spawn_file_actions_addopen(&mut fa, *fd, keep[ki - 1].as_ptr(), *fl, *mode)
                        }
                        Act::Chdir(_) => {
                            ki += 1;
                            m::posix_spawn_file_actions_addchdir_np(&mut fa, keep[ki - 1].as_ptr())
                        }
                        Act::Fchdir(fd) => m::posix_spawn_file_actions_addfchdir_np(&mut fa, *fd),
                        Act::Closefrom(fd) => m::posix_spawn_file_actions_addclosefrom_np(&mut fa, *fd),
                    };
                    assert_eq!(rc, 0, "adding {a:?}");
                }
                let mut at: $attr_t = std::mem::zeroed();
                m::posix_spawnattr_init(&mut at);
                if case.attr {
                    assert_eq!(m::posix_spawnattr_setflags(&mut at, case.flags as i16), 0);
                    m::posix_spawnattr_setpgroup(&mut at, case.pgrp);
                    let ss = $set(case.sigmask);
                    m::posix_spawnattr_setsigmask(&mut at, &ss);
                    let sd = $set(case.sigdef);
                    m::posix_spawnattr_setsigdefault(&mut at, &sd);
                }
                let path = CString::new(case.path).unwrap();
                let argv_c = cstrings(&case.argv);
                let argv = ptr_array(&argv_c);
                let env_c = case.env.as_ref().map(|e| cstrings(e));
                let env = env_c.as_ref().map(|e| ptr_array(e));
                let mut pid: i32 = -7;
                let envp = env.as_ref().map_or(libc::environ as *const *mut libc::c_char, |e| e.as_ptr());
                let atp = if case.attr { &at as *const $attr_t } else { std::ptr::null() };
                let rc = if case.use_path {
                    m::posix_spawnp(&mut pid, path.as_ptr(), &fa, atp, argv.as_ptr(), envp)
                } else {
                    m::posix_spawn(&mut pid, path.as_ptr(), &fa, atp, argv.as_ptr(), envp)
                };
                m::posix_spawn_file_actions_destroy(&mut fa);
                m::posix_spawnattr_destroy(&mut at);
                collect(rc, pid, fds[0], fds[1])
            }
        }
    };
}

fn host_set(mask: u64) -> libc::sigset_t {
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for sig in 1..=64 {
            if mask & (1 << (sig - 1)) != 0 {
                libc::sigaddset(&mut s, sig);
            }
        }
        s
    }
}

fn our_set(mask: u64) -> spawn::SigsetT {
    let mut s = spawn::SigsetT { val: [0; 16] };
    s.val[0] = mask;
    s
}

runner!(run_host, libc, libc::posix_spawn_file_actions_t, libc::posix_spawnattr_t, host_set);
runner!(run_ours, crate::spawn, spawn::PosixSpawnFileActions, spawn::PosixSpawnattr, our_set);

fn compare(name: &str, case: Case) {
    // Tests of other modules run on other threads and may hold a descriptor without close-on-exec for a
    // moment, which shows in a child's descriptor listing: a case counts as failed only when it differs
    // on every one of 13 tries.
    for _ in 0..12 {
        if run_host(&case) == run_ours(&case) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let want = run_host(&case);
    let got = run_ours(&case);
    assert_eq!(got, want, "case {name}: {case:?}");
}

/// Like `compare`, for the plain-clone path: glibc's own fallback (kernels without clone3) ignores the
/// two internal signals 32 and 33, which clone3's CLONE_CLEAR_SIGHAND does not; take those bits out of
/// the SigIgn line before comparing.
fn compare_fallback(name: &str, case: Case) {
    let want = run_host(&case);
    let mut got = run_ours(&case);
    if let Some(i) = got.output.find("SigIgn: ") {
        let hex = &got.output[i + 8..i + 24];
        let v = u64::from_str_radix(hex, 16).unwrap() & !0x1_8000_0000;
        got.output = format!("{}{:016x}{}", &got.output[..i + 8], v, &got.output[i + 24..]);
    }
    assert_eq!(got, want, "case {name}: {case:?}");
}

#[test]
fn layouts() {
    assert_eq!(size_of::<spawn::PosixSpawnattr>(), size_of::<libc::posix_spawnattr_t>());
    assert_eq!(size_of::<spawn::PosixSpawnattr>(), 336);
    assert_eq!(size_of::<spawn::PosixSpawnFileActions>(), size_of::<libc::posix_spawn_file_actions_t>());
    assert_eq!(size_of::<spawn::PosixSpawnFileActions>(), 80);
    assert_eq!(align_of::<spawn::PosixSpawnattr>(), align_of::<libc::posix_spawnattr_t>());
    assert_eq!(spawn::POSIX_SPAWN_SETSIGMASK, libc::POSIX_SPAWN_SETSIGMASK);
    assert_eq!(spawn::POSIX_SPAWN_SETSID, 0x80);
    assert_eq!(spawn::POSIX_SPAWN_SETCGROUP, 0x100);
}

#[test]
fn basic_spawns() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    compare("true", Case::new("/bin/true", &["true"]));
    compare("false", Case::new("/bin/false", &["false"]));
    compare("echo", Case::new("/bin/sh", &["sh", "-c", "echo $0", "hello"]));
    compare("exit7", Case::sh("exit 7"));
    compare("killed", Case::sh("kill -9 $$"));
    let mut c = Case::new("/usr/bin/env", &["env"]);
    c.env = Some(vec!["A=1", "B=two"]);
    compare("env", c);
    compare("empty argv", Case::new("/bin/true", &[]));
}

#[test]
fn errors() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    compare("enoent", Case::new("/nonexistent/cmd", &["x"]));
    compare("eacces file", Case::new("/etc/passwd", &["x"]));
    compare("eacces dir", Case::new("/tmp", &["x"]));
    compare("enotdir", Case::new("/etc/passwd/x", &["x"]));
    compare("empty", Case::new("", &["x"]));
    let long = format!("/{}", "a".repeat(5000)).leak();
    compare("toolong", Case::new(long, &["x"]));
    // scripts in a temp directory
    let dir = std::env::temp_dir().join(format!("extra-spawn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let make = |name: &str, body: &str, mode: u32| -> &'static str {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p.to_str().unwrap().to_owned().leak()
    };
    compare("no shebang", Case::new(make("noshebang", "echo ran\n", 0o755), &["x"]));
    compare("empty exe", Case::new(make("empty", "", 0o755), &["x"]));
    compare("shebang", Case::new(make("shebang", "#!/bin/sh\necho shebang $1\n", 0o755), &["x", "a1"]));
    compare("bad interp", Case::new(make("badinterp", "#!/nonexistent/i\n", 0o755), &["x"]));
    compare("not executable", Case::new(make("noexec", "#!/bin/sh\n", 0o644), &["x"]));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn path_search() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let old = std::env::var_os("PATH");
        let mut p = Case::new("true", &["true"]);
        p.use_path = true;
        compare("p true", p.clone());
        let mut q = Case::new("no-such-command-xyz", &["x"]);
        q.use_path = true;
        compare("p missing", q);
        let mut e = Case::new("", &["x"]);
        e.use_path = true;
        compare("p empty", e);
        let mut s = Case::new("/bin/true", &["x"]);
        s.use_path = true;
        compare("p slash", s);
        for path in ["/nonexistent:/usr/bin:/bin", "", "/nonexistent::/usr/bin", "/tmp:/etc", ":/usr/bin"] {
            std::env::set_var("PATH", path);
            compare(&format!("p PATH={path}"), p.clone());
        }
        // the dir with a non-executable file first, then the real one
        let dir = std::env::temp_dir().join(format!("extra-spawn-p-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("true"), "#!/bin/sh\n").unwrap();
        std::env::set_var("PATH", format!("{}:/usr/bin", dir.display()));
        compare("p eacces then found", p.clone());
        std::env::set_var("PATH", dir.to_str().unwrap());
        compare("p eacces only", p.clone());
        std::fs::remove_dir_all(&dir).unwrap();
        std::env::remove_var("PATH");
        compare("p PATH unset", p.clone());
        if let Some(o) = old {
            std::env::set_var("PATH", o);
        }
    }
}

#[test]
fn file_actions() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pwd = Case::sh("pwd");
    compare("chdir", pwd.clone().acts(&[Act::Chdir("/usr")]));
    compare("chdir bad", pwd.clone().acts(&[Act::Chdir("/nonexistent-dir")]));
    compare("fchdir bad", pwd.clone().acts(&[Act::Fchdir(999)]));
    let usr = unsafe { libc::open(c"/usr".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    compare("fchdir", pwd.acts(&[Act::Fchdir(usr)]));
    unsafe { libc::close(usr) };
    // descriptor listings: our own pipe ends are close-on-exec so only 0 1 2 and ls's directory fd show
    let ls = || Case::sh("ls /proc/self/fd | tr '\\n' ' '");
    compare("fds", ls());
    compare("close 0", ls().acts(&[Act::Close(0)]));
    compare("close unopen", ls().acts(&[Act::Close(9)]));
    compare("close high", ls().acts(&[Act::Close(900)]));
    compare("open twice", ls().acts(&[Act::Open(7, "/dev/null", libc::O_RDONLY, 0), Act::Open(7, "/dev/null", libc::O_RDONLY, 0)]));
    compare("dup order", ls().acts(&[Act::Dup2(1, 4), Act::Dup2(4, 5), Act::Close(4)]));
    compare("dup bad", ls().acts(&[Act::Dup2(998, 5)]));
    compare("dup same bad", ls().acts(&[Act::Dup2(997, 997)]));
    compare("open bad", ls().acts(&[Act::Open(5, "/nonexistent-file", libc::O_RDONLY, 0)]));
    compare("closefrom 3", ls().acts(&[Act::Dup2(1, 12), Act::Closefrom(3)]));
    compare("closefrom keep", ls().acts(&[Act::Dup2(1, 20), Act::Dup2(1, 30), Act::Closefrom(21)]));
    compare("open onto 0", Case::sh("head -c 5 /proc/self/fd/0").acts(&[Act::Open(0, "/etc/hostname", libc::O_RDONLY, 0)]));
}

#[test]
fn attributes() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // parent state: SIGUSR1 blocked, SIGUSR2 and SIGPIPE ignored
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        let oldu2 = libc::signal(libc::SIGUSR2, libc::SIG_IGN);
        let oldpipe = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let status = || Case::sh("grep -E '^(SigBlk|SigIgn)' /proc/self/status | tr '\\t\\n' '  '");
        let bit = |s: i32| 1u64 << (s - 1);
        compare("inherit", status());
        compare("attr no flags", status().attr(0));
        let mut c = status().attr(spawn::POSIX_SPAWN_SETSIGMASK);
        c.sigmask = bit(libc::SIGUSR2) | bit(libc::SIGINT);
        compare("setsigmask", c.clone());
        c.sigmask = 0;
        compare("setsigmask empty", c);
        let mut c = status().attr(spawn::POSIX_SPAWN_SETSIGDEF);
        c.sigdef = bit(libc::SIGUSR2) | bit(libc::SIGPIPE) | bit(libc::SIGTERM);
        compare("setsigdefault", c.clone());
        c.flags |= spawn::POSIX_SPAWN_SETSIGMASK;
        compare("setsigdefault+mask", c);
        // errors from the child's setup
        compare("sched param on OTHER", status().attr(spawn::POSIX_SPAWN_SETSCHEDPARAM));
        compare("setscheduler", Case::new("/bin/true", &["true"]).attr(spawn::POSIX_SPAWN_SETSCHEDULER));
        compare("setpgroup bogus", Case::new("/bin/true", &["true"]).attr(spawn::POSIX_SPAWN_SETPGROUP));
        let mut c = Case::new("/bin/true", &["true"]).attr(spawn::POSIX_SPAWN_SETPGROUP);
        c.pgrp = 1;
        compare("setpgroup 1", c);
        compare("resetids", Case::new("/bin/true", &["true"]).attr(spawn::POSIX_SPAWN_RESETIDS | spawn::POSIX_SPAWN_USEVFORK));
        compare("setcgroup bad fd", Case::new("/bin/true", &["true"]).attr(spawn::POSIX_SPAWN_SETCGROUP));
        libc::signal(libc::SIGUSR2, oldu2);
        libc::signal(libc::SIGPIPE, oldpipe);
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
}

#[test]
fn setters() {
    unsafe {
        let mut a: spawn::PosixSpawnattr = std::mem::zeroed();
        let mut h: libc::posix_spawnattr_t = std::mem::zeroed();
        spawn::posix_spawnattr_init(&mut a);
        libc::posix_spawnattr_init(&mut h);
        for flags in [0i16, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x1ff, 0x200, 0x3ff, 0x400, 0x4000, -1] {
            assert_eq!(spawn::posix_spawnattr_setflags(&mut a, flags), libc::posix_spawnattr_setflags(&mut h, flags), "{flags:#x}");
            let (mut x, mut y) = (-5i16, -5i16);
            spawn::posix_spawnattr_getflags(&a, &mut x);
            libc::posix_spawnattr_getflags(&h, &mut y);
            assert_eq!(x, y);
        }
        for pol in [0, 1, 2, 3, 4, 5, 6, 7, 99, -1] {
            assert_eq!(spawn::posix_spawnattr_setschedpolicy(&mut a, pol), libc::posix_spawnattr_setschedpolicy(&mut h, pol), "{pol}");
        }
        spawn::posix_spawnattr_setpgroup(&mut a, 77);
        libc::posix_spawnattr_setpgroup(&mut h, 77);
        spawn::posix_spawnattr_setcgroup_np(&mut a, 9);
        // the structures are byte-equal except for fields glibc keeps in the padding (cgroup is ours: set the same on the host)
        let hb = std::slice::from_raw_parts((&h as *const libc::posix_spawnattr_t).cast::<u8>(), 336);
        let ab = std::slice::from_raw_parts((&a as *const spawn::PosixSpawnattr).cast::<u8>(), 336);
        assert_eq!(&hb[..8], &ab[..8]);
        assert_eq!(&hb[264..272], &ab[264..272]);
    }
}

#[test]
fn action_validation() {
    unsafe {
        let mut a: spawn::PosixSpawnFileActions = std::mem::zeroed();
        let mut h: libc::posix_spawn_file_actions_t = std::mem::zeroed();
        spawn::posix_spawn_file_actions_init(&mut a);
        libc::posix_spawn_file_actions_init(&mut h);
        for fd in [0, 1, 5, 100, 900000, 1 << 20, 1 << 30, 0x7fffffff, -1, -100] {
            assert_eq!(spawn::posix_spawn_file_actions_addclose(&mut a, fd), libc::posix_spawn_file_actions_addclose(&mut h, fd), "close {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_adddup2(&mut a, fd, 2), libc::posix_spawn_file_actions_adddup2(&mut h, fd, 2), "dup2 {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_adddup2(&mut a, 2, fd), libc::posix_spawn_file_actions_adddup2(&mut h, 2, fd), "dup2 to {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_addopen(&mut a, fd, c"/dev/null".as_ptr(), 0, 0), libc::posix_spawn_file_actions_addopen(&mut h, fd, c"/dev/null".as_ptr(), 0, 0), "open {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_addclosefrom_np(&mut a, fd), libc::posix_spawn_file_actions_addclosefrom_np(&mut h, fd), "closefrom {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_addtcsetpgrp_np(&mut a, fd), libc::posix_spawn_file_actions_addtcsetpgrp_np(&mut h, fd), "tcsetpgrp {fd}");
            assert_eq!(spawn::posix_spawn_file_actions_addfchdir_np(&mut a, fd), libc::posix_spawn_file_actions_addfchdir_np(&mut h, fd), "fchdir {fd}");
        }
        let hw = &h as *const libc::posix_spawn_file_actions_t as *const i32;
        assert_eq!((a.allocated, a.used), (*hw, *hw.add(1)));
        spawn::posix_spawn_file_actions_destroy(&mut a);
        libc::posix_spawn_file_actions_destroy(&mut h);
    }
}

/// With clone3 refused the child is made with the plain clone call and resets handlers itself.
#[test]
fn clone_fallback() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            spawn::FORCE_CLONE_FALLBACK.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let _reset = Reset;
    spawn::FORCE_CLONE_FALLBACK.store(true, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        // a handler installed in the parent must not survive in the child (it ignores or defaults)
        extern "C" fn handler(_: i32) {}
        let old = libc::signal(libc::SIGUSR1, handler as *const () as usize);
        let status = || Case::sh("grep -E '^(SigBlk|SigIgn|SigCgt)' /proc/self/status | tr '\\t\\n' '  '");
        compare_fallback("fallback status", status());
        compare_fallback("fallback true", Case::new("/bin/true", &["true"]));
        compare_fallback("fallback enoent", Case::new("/nonexistent", &["x"]));
        compare_fallback("fallback chdir", Case::sh("pwd").acts(&[Act::PipeOut, Act::Chdir("/usr")]));
        let mut c = status().attr(spawn::POSIX_SPAWN_SETSIGDEF);
        c.sigdef = 1 << (libc::SIGUSR1 - 1);
        compare_fallback("fallback sigdef", c);
        libc::signal(libc::SIGUSR1, old);
    }
}

#[test]
fn threaded() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let handles: Vec<_> = (0..6)
        .map(|id| {
            std::thread::spawn(move || {
                let mut ok = 0;
                for i in 0..10 {
                    let code = (id + i) % 5;
                    let script = CString::new(format!("exit {code}")).unwrap();
                    let argv: [&CStr; 3] = [c"sh", c"-c", &script];
                    let env: [&CStr; 0] = [];
                    let pid = spawn::spawn(c"/bin/sh", &argv, &env, None, None).unwrap();
                    let st = spawn::wait(pid).unwrap();
                    if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == code {
                        ok += 1;
                    }
                }
                ok
            })
        })
        .collect();
    let total: i32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 60);
}

#[test]
fn rust_api() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0i32; 2];
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    let mut fa = FileActions::new();
    fa.add_dup2(fds[1], 1).unwrap();
    fa.add_chdir(c"/usr").unwrap();
    assert_eq!(fa.add_close(-1), Err(libc::EBADF));
    let mut at = SpawnAttr::new();
    at.flags(spawn::POSIX_SPAWN_SETSIGMASK).unwrap().sigmask(0);
    let args: [&CStr; 3] = [c"sh", c"-c", c"echo $FOO; pwd"];
    let pid = spawn::spawn(c"/bin/sh", &args, &[c"FOO=bar"], Some(&fa), Some(&at)).unwrap();
    unsafe { libc::close(fds[1]) };
    let mut got = Vec::new();
    loop {
        let mut buf = [0u8; 100];
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), 100) };
        if n <= 0 {
            break;
        }
        got.extend_from_slice(&buf[..n as usize]);
    }
    assert_eq!(got, b"bar\n/usr\n");
    assert_eq!(spawn::wait(pid).unwrap(), 0);
    assert_eq!(spawn::spawn(c"/nonexistent", &[c"x"], &[], None, None), Err(libc::ENOENT));
    assert_eq!(spawn::spawnp(c"nonexistent-cmd-zzz", &[c"x"], &[], None, None), Err(libc::ENOENT));
    let pid = spawn::spawnp(c"true", &[c"true"], &[], None, None).unwrap();
    assert_eq!(spawn::wait(pid).unwrap(), 0);
    assert_eq!(at.flags(0x7777).err(), Some(libc::EINVAL));
    unsafe { libc::close(fds[0]) };
}

#[test]
fn pidfd() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let argv = [c"true".as_ptr() as *mut libc::c_char, std::ptr::null_mut()];
        let mut fd = -1;
        let rc = spawn::pidfd_spawn(&mut fd, c"/bin/true".as_ptr(), std::ptr::null(), std::ptr::null(), argv.as_ptr(), libc::environ as *const *mut libc::c_char);
        assert_eq!(rc, 0);
        assert!(fd >= 0);
        let mut info: libc::siginfo_t = std::mem::zeroed();
        assert_eq!(libc::waitid(libc::P_PIDFD, fd as u32, &mut info, libc::WEXITED), 0);
        assert_eq!(info.si_code, libc::CLD_EXITED);
        libc::close(fd);
        let mut fd2 = -1;
        let rc = spawn::pidfd_spawn(&mut fd2, c"/nonexistent".as_ptr(), std::ptr::null(), std::ptr::null(), argv.as_ptr(), libc::environ as *const *mut libc::c_char);
        assert_eq!(rc, libc::ENOENT);
        assert_eq!(fd2, -1);
    }
}
