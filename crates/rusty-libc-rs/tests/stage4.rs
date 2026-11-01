//! FIXLIST #127 stage 4: the thread mask, every signal's state, sigwait*, POSIX and interval timers, utmp/wtmp, the raw
//! environment, get-only umask, getloadavg, gethostid, sysconf, scheduling policy, exec without fork (failure side;
//! the success side needs a single-threaded process: tests/single.rs).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]

mod common;
use common::*;
use rusty_libc_rs::signal::*;
use rusty_libc_rs::time::{ClockId, Itimer, Timer, TimerNotify, TimerSpec, getitimer, setitimer};
use rusty_libc_rs::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::time::Duration;

fn status_field(k: &str) -> String {
    let s = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    s.lines().find_map(|l| l.strip_prefix(k)).unwrap().trim().to_string()
}

fn proc_mask() -> u64 {
    u64::from_str_radix(&status_field("SigBlk:"), 16).unwrap()
}

// ------------------------------------------------------------------------------------------------ masks and states

#[test]
fn thread_mask_through_libc() {
    let before = thread_mask();
    assert_eq!(before, blocked_signals());
    assert_eq!(before.bits(), proc_mask());
    let set = SigSet::empty().with(Signal::USR1).with(SigNum::rt(4).unwrap()).with(SigNum::new(32).unwrap()).with(SigNum::new(33).unwrap());
    assert_eq!(block_signals(set).unwrap(), before);
    let now = thread_mask();
    assert!(now.contains(Signal::USR1) && now.contains(SigNum::rt(4).unwrap()));
    assert!(!now.contains(SigNum::new(32).unwrap()) && !now.contains(SigNum::new(33).unwrap()), "32/33 never blocked");
    assert_eq!(now.bits(), proc_mask());
    unblock_signals(SigSet::empty().with(Signal::USR1)).unwrap();
    assert!(!thread_mask().contains(Signal::USR1));
    assert_eq!(set_thread_mask(MaskHow::SetMask, before).unwrap().bits(), before.bits() | SigSet::empty().with(SigNum::rt(4).unwrap()).bits());
    assert_eq!(thread_mask(), before);
    // the same through the host/running C library's own pthread_sigmask
    let mut cur: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut cur) }, 0);
    assert_eq!(unsafe { *(&cur as *const libc::sigset_t as *const u64) }, before.bits());
}

/// `env --list-signal-handling` lines for our view of the signals.
fn env_lines(states: &[SignalState]) -> String {
    let mut out = String::new();
    for s in states.iter().filter(|s| s.blocked || s.disposition == Disposition::Ignore) {
        let ign = s.disposition == Disposition::Ignore;
        out += &format!(
            "{:<10} ({:2}): {}{}{}\n",
            &s.signal.name().unwrap()[3..],
            s.signal.as_raw(),
            if s.blocked { "BLOCK" } else { "" },
            if ign && s.blocked { "," } else { "" },
            if ign { "IGNORE" } else { "" }
        );
    }
    out
}

#[test]
fn signal_states_match_env_list() {
    isolated("signal_states_match_env_list", || {
        set_signal(Signal::USR1, Action::Ignore).unwrap();
        set_signal(Signal::HUP, Action::Ignore).unwrap();
        block_signals(SigSet::empty().with(Signal::USR2).with(Signal::HUP).with(SigNum::rt(2).unwrap()).with(SigNum::RTMAX)).unwrap();
        let st = signal_states();
        assert_eq!(st.len(), 62);
        // vs /proc
        let ign = u64::from_str_radix(&status_field("SigIgn:"), 16).unwrap();
        for s in &st {
            assert_eq!(s.disposition == Disposition::Ignore, ign & (1 << (s.signal.as_raw() - 1)) != 0, "{:?}", s.signal);
            assert_eq!(s.blocked, proc_mask() & (1 << (s.signal.as_raw() - 1)) != 0, "{:?}", s.signal);
        }
        assert_eq!(query_signal(Signal::KILL).unwrap(), Disposition::Default);
        assert_eq!(query_signal(SigNum::new(32).unwrap()).unwrap_err(), en(libc::EINVAL));
        // vs coreutils env, which inherits the ignored signals and this thread's mask (SIGPIPE: Rust ignores it, the
        // child gets the default, so leave it out of our list)
        let (r, w) = std::io::pipe().unwrap();
        let mut c = Command::new("env").args(["--list-signal-handling", "true"]).stderr(w).spawn().unwrap();
        let text = read_all(r);
        assert!(c.wait().unwrap().success());
        let ours: Vec<SignalState> = st.into_iter().filter(|s| s.signal != Signal::PIPE).collect();
        assert_eq!(text, env_lines(&ours));
        assert!(text.contains("HUP        ( 1): BLOCK,IGNORE\n") && text.contains("RTMAX      (64): BLOCK\n"), "{text}");
    });
}

// ------------------------------------------------------------------------------------------------ sigwait

/// rt_tgsigqueueinfo to this thread with SI_QUEUE and `value`.
fn queue_to_self(sig: i32, value: usize) {
    let mut info = [0i32; 32];
    info[0] = sig;
    info[2] = -1; // SI_QUEUE
    info[4] = unsafe { libc::getpid() };
    info[5] = unsafe { libc::getuid() } as i32;
    info[6] = value as i32;
    info[7] = (value as u64 >> 32) as i32;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    assert_eq!(unsafe { libc::syscall(libc::SYS_rt_tgsigqueueinfo, libc::getpid(), tid, sig, info.as_ptr()) }, 0);
}

#[test]
fn sigwait_family() {
    let s = SigNum::rt(6).unwrap();
    let set = SigSet::empty().with(s);
    let old = block_signals(set).unwrap();
    assert_eq!(sigtimedwait(set, Duration::ZERO).unwrap(), None);
    queue_to_self(s.as_raw(), 0x1234_5678_9abc);
    let i = sigtimedwait(set, Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!(i.signal, s);
    assert_eq!(i.source, SigSource::Queue { pid: unsafe { libc::getpid() }, uid: unsafe { libc::getuid() }, value: 0x1234_5678_9abc, mesgq: false });
    // real-time signals queue: two sent, two taken in order
    queue_to_self(s.as_raw(), 1);
    queue_to_self(s.as_raw(), 2);
    assert_eq!(sigwaitinfo(set).unwrap().source, SigSource::Queue { pid: unsafe { libc::getpid() }, uid: unsafe { libc::getuid() }, value: 1, mesgq: false });
    assert_eq!(sigwait(set).unwrap(), s);
    // 32/33 only: an empty set
    assert_eq!(sigwait(SigSet::empty().with(SigNum::new(32).unwrap())).unwrap_err(), en(libc::EINVAL));
    set_thread_mask(MaskHow::SetMask, old).unwrap();
}

// ------------------------------------------------------------------------------------------------ timers

#[test]
fn timer_thread_signal_and_overrun() {
    let s = SigNum::rt(7).unwrap();
    let set = SigSet::empty().with(s);
    let old = block_signals(set).unwrap();
    let tid = rusty_libc_rs::thread::gettid();
    let t = Timer::new(ClockId::Monotonic, TimerNotify::ThreadSignal { signal: s, tid, value: 77 }).unwrap();
    assert_eq!(t.get().unwrap(), TimerSpec::default());
    t.set(TimerSpec::repeating(Duration::from_millis(1), Duration::from_millis(1))).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    let i = sigtimedwait(set, Duration::from_secs(5)).unwrap().unwrap();
    let SigSource::Timer { timer, overrun, value } = i.source else { panic!("{:?}", i.source) };
    assert_eq!((timer, value), (t.id(), 77));
    assert!(overrun >= 10, "overrun {overrun}");
    assert_eq!(t.overrun().unwrap(), overrun);
    let g = t.disarm().unwrap();
    assert_eq!(g.interval, Duration::from_millis(1));
    assert_eq!(t.get().unwrap(), TimerSpec::default());
    drop(t);
    while sigtimedwait(set, Duration::ZERO).unwrap().is_some() {}
    set_thread_mask(MaskHow::SetMask, old).unwrap();
    assert_eq!(Timer::new(ClockId::Monotonic, TimerNotify::Signal { signal: SigNum::new(33).unwrap(), value: 0 }).unwrap_err(), en(libc::EINVAL));
}

#[test]
fn timer_process_signal_to_counter() {
    isolated("timer_process_signal_to_counter", || {
        let s = SigNum::rt(8).unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let _reg = register_counter(s, Arc::clone(&n)).unwrap();
        let t = Timer::new(ClockId::Realtime, TimerNotify::Signal { signal: s, value: 0 }).unwrap();
        // absolute: 20 ms from now on CLOCK_REALTIME
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        t.set_absolute(TimerSpec::once(now + Duration::from_millis(20))).unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while n.load(SeqCst) == 0 && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(n.load(SeqCst), 1);
    });
}

#[test]
fn itimer_real_sigalrm() {
    isolated("itimer_real_sigalrm", || {
        let flag = Arc::new(AtomicBool::new(false));
        let _reg = register_flag(Signal::ALARM, Arc::clone(&flag)).unwrap();
        assert_eq!(getitimer(Itimer::Real).unwrap(), TimerSpec::default());
        // 1 ns rounds up to 1 us (never 0, which would disarm)
        assert_eq!(setitimer(Itimer::Real, TimerSpec::once(Duration::from_nanos(1))).unwrap(), TimerSpec::default());
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while !flag.load(SeqCst) && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(flag.load(SeqCst));
        setitimer(Itimer::Virtual, TimerSpec::repeating(Duration::from_secs(100), Duration::from_millis(1500))).unwrap();
        let g = getitimer(Itimer::Virtual).unwrap();
        assert_eq!(g.interval, Duration::from_millis(1500));
        assert!(g.value <= Duration::from_millis(100_010) && g.value > Duration::from_secs(99), "{g:?}");
        // the same through the C library
        let mut v: libc::itimerval = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getitimer(libc::ITIMER_VIRTUAL, &mut v) }, 0);
        assert_eq!((v.it_interval.tv_sec, v.it_interval.tv_usec), (1, 500_000));
        setitimer(Itimer::Virtual, TimerSpec::default()).unwrap();
    });
}

// ------------------------------------------------------------------------------------------------ utmp

/// (type, pid, id, user, line, host) of one login record.
type Rec = (i16, i32, String, String, String, String);

/// utmpdump's records.
fn utmpdump(path: &str) -> Option<Vec<Rec>> {
    let out = std::process::Command::new("utmpdump").arg(path).stderr(std::process::Stdio::null()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(
        text.lines()
            .map(|l| {
                let f: Vec<&str> = l.trim_start_matches('[').trim_end_matches(']').split("] [").collect();
                (f[0].parse().unwrap(), f[1].trim().parse().unwrap(), f[2].trim_end().to_string(), f[3].trim_end().to_string(), f[4].trim_end().to_string(), f[5].trim_end().to_string())
            })
            .collect(),
    )
}

fn ours(v: &[utmp::UtmpEntry]) -> Vec<Rec> {
    v.iter()
        .map(|e| {
            let s = |o: &std::ffi::OsString| o.to_string_lossy().into_owned();
            (e.raw.ut_type, e.pid, s(&e.id), s(&e.user), s(&e.line), s(&e.host))
        })
        .collect()
}

#[test]
fn utmp_and_wtmp_match_utmpdump() {
    let Some(want) = utmpdump(utmp::PATH_UTMP) else {
        eprintln!("SKIP: no utmpdump");
        return;
    };
    let got = utmp::utmp_entries().unwrap();
    // utmpdump prints the id field as 4 characters, empty ones as spaces; trailing spaces trimmed on both sides
    let norm = |v: Vec<Rec>| v.into_iter().map(|(t, p, i, u, l, h)| (t, p, i.trim_end().to_string(), u, l, h)).collect::<Vec<_>>();
    assert_eq!(norm(ours(&got)), norm(want));
    let boot = got.iter().filter(|e| e.kind == utmp::UtmpKind::BootTime).count();
    assert!(boot <= 1);
    let wtmp = utmp::utmp_entries_from(utmp::PATH_WTMP).unwrap();
    assert_eq!(norm(ours(&wtmp)), norm(utmpdump(utmp::PATH_WTMP).unwrap()));
    // the library's default file is back: same list again
    assert_eq!(utmp::utmp_entries().unwrap(), got);
    assert_eq!(utmp::utmp_entries_from("/nonexistent-rlrs/wtmp").unwrap(), vec![]);
    // `last` lists the user logins of wtmp (one line per USER_PROCESS record with a user name)
    if let Ok(out) = std::process::Command::new("last").args(["-w", "--time-format", "notime"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        let n_last = text.lines().filter(|l| !l.is_empty() && !l.starts_with("reboot") && !l.starts_with("wtmp begins") && !l.starts_with("shutdown")).count();
        let n_ours = wtmp.iter().filter(|e| e.kind == utmp::UtmpKind::UserProcess && !e.user.is_empty()).count();
        assert_eq!(n_last, n_ours, "{text}");
    }
}

// ------------------------------------------------------------------------------------------------ environment

#[test]
fn vars_raw_and_refusal_with_threads() {
    let raw = env::vars_raw();
    let std_view: Vec<String> = std::env::vars_os().map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy())).collect();
    let ours: Vec<String> = raw.iter().map(|e| e.to_string_lossy().into_owned()).filter(|e| e.len() > 1 && e[1..].contains('=')).collect();
    assert_eq!(ours, std_view);
    // the test harness has threads
    assert!(!env::is_single_threaded().unwrap());
    assert_eq!(env::set_var("RLRS_STAGE4", "1").unwrap_err(), en(libc::EBUSY));
    assert_eq!(env::remove_var("PATH").unwrap_err(), en(libc::EBUSY));
    assert_eq!(env::set_var("A=B", "1").unwrap_err(), en(libc::EINVAL));
}

// ------------------------------------------------------------------------------------------------ umask, load, hostid, sysconf, sched

#[test]
fn get_umask_matches_set() {
    isolated("get_umask_matches_set", || {
        let m = rusty_libc_rs::process::get_umask().unwrap();
        let old = rusty_libc_rs::process::umask(rusty_libc_rs::fs::Mode::from_raw_mode(0o027));
        assert_eq!(m, old);
        assert_eq!(rusty_libc_rs::process::get_umask().unwrap().as_raw_mode(), 0o027);
    });
}

#[test]
fn loadavg_matches_proc() {
    let mut ok = false;
    for _ in 0..5 {
        let a = rusty_libc_rs::system::getloadavg();
        let text = std::fs::read_to_string("/proc/loadavg").unwrap();
        let p: Vec<f64> = text.split_whitespace().take(3).map(|v| v.parse().unwrap()).collect();
        // /proc/loadavg rounds to two decimals
        if (0..3).all(|i| (a[i] - p[i]).abs() <= 0.0051) {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200)); // a 5 s update fell between the two reads
    }
    assert!(ok);
    let mut c = [0f64; 3];
    assert_eq!(unsafe { libc::getloadavg(c.as_mut_ptr(), 3) }, 3);
}

#[test]
fn hostid_matches_coreutils() {
    let out = std::process::Command::new("hostid").output().unwrap();
    let want = String::from_utf8(out.stdout).unwrap();
    assert_eq!(format!("{:08x}\n", rusty_libc_rs::system::gethostid() as u32), want);
}

#[test]
fn sysconf_matches_getconf() {
    for (name, var) in [
        ("ARG_MAX", Sysconf::ArgMax),
        ("CLK_TCK", Sysconf::ClkTck),
        ("OPEN_MAX", Sysconf::OpenMax),
        ("PAGESIZE", Sysconf::PageSize),
        ("_NPROCESSORS_CONF", Sysconf::NprocessorsConf),
        ("_NPROCESSORS_ONLN", Sysconf::NprocessorsOnln),
    ] {
        let out = std::process::Command::new("getconf").arg(name).output().unwrap();
        let want: i64 = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
        assert_eq!(sysconf(var), Some(want), "{name}");
    }
    assert_eq!(sysconf(Sysconf::GetpwRSizeMax), Some(unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) }));
    assert_eq!(sysconf(Sysconf::NprocessorsOnln), Some(unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }));
}

#[test]
fn sysconf_rlimit_dependent() {
    isolated("sysconf_rlimit_dependent", || {
        use rusty_libc_rs::process::{Resource, Rlimit, setrlimit};
        setrlimit(Resource::Nofile, Rlimit { current: Some(77), maximum: rusty_libc_rs::process::getrlimit(Resource::Nofile).maximum }).unwrap();
        assert_eq!(sysconf(Sysconf::OpenMax), Some(77));
        for stack in [Some(64 * 1024), Some(16 << 20), Some(100 << 20), None] {
            setrlimit(Resource::Stack, Rlimit { current: stack, maximum: rusty_libc_rs::process::getrlimit(Resource::Stack).maximum }).unwrap();
            assert_eq!(sysconf(Sysconf::ArgMax), Some(unsafe { libc::sysconf(libc::_SC_ARG_MAX) }), "{stack:?}");
        }
    });
}

#[test]
fn sched_policy_matches_libc() {
    use rusty_libc_rs::thread::{SchedPolicy, sched_getparam, sched_getscheduler};
    let p = unsafe { libc::sched_getscheduler(0) };
    let (ours, reset) = sched_getscheduler(None).unwrap();
    assert_eq!(ours, match p & !0x4000_0000 { 0 => SchedPolicy::Other, 3 => SchedPolicy::Batch, 5 => SchedPolicy::Idle, n => SchedPolicy::Unknown(n) });
    assert_eq!(reset, p & 0x4000_0000 != 0);
    let mut sp: libc::sched_param = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sched_getparam(0, &mut sp) }, 0);
    assert_eq!(sched_getparam(None).unwrap(), sp.sched_priority);
    let me = rusty_libc_rs::process::getpid();
    assert_eq!(sched_getscheduler(Some(me)).unwrap().0, ours);
    assert_eq!(sched_getscheduler(Some(pid(0x3fff_fff0))).unwrap_err(), en(libc::ESRCH));
    // chrt's view
    if let Ok(out) = std::process::Command::new("chrt").args(["-p", &raw(me).to_string()]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        let want = match ours { SchedPolicy::Other => "SCHED_OTHER", SchedPolicy::Batch => "SCHED_BATCH", SchedPolicy::Idle => "SCHED_IDLE", _ => "?" };
        assert!(text.contains(want), "{text}");
    }
}

// ------------------------------------------------------------------------------------------------ exec (failures)

#[test]
fn exec_failures_and_exit_codes() {
    isolated("exec_failures_and_exit_codes", || {
        let ino = |fd: i32| {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
            (st.st_dev, st.st_ino)
        };
        let before = (ino(0), ino(1), ino(2));
        let cwd = std::env::current_dir().unwrap();
        let ign_before = get_signal(Signal::USR1).unwrap();
        set_signal(Signal::USR1, Action::Ignore).unwrap();
        let mask = thread_mask();
        // not found: 127; the stdio mapping, cwd, the reset signal and the mask are put back
        let e = Command::new("no-such-program-rlrs")
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .current_dir("/")
            .reset_signal(Signal::USR1)
            .signal_mask(SigSet::full())
            .exec_detailed();
        assert_eq!((e.stage, e.error.raw_os_error(), e.exit_code()), (Stage::Exec, Some(libc::ENOENT), 127));
        assert_eq!((ino(0), ino(1), ino(2)), before);
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        assert_eq!(get_signal(Signal::USR1).unwrap(), Disposition::Ignore);
        assert_eq!(thread_mask(), mask);
        // found but not executable: 126
        let e = Command::new("/etc/passwd").exec_detailed();
        assert_eq!((e.stage, e.error.raw_os_error(), e.exit_code()), (Stage::Exec, Some(libc::EACCES), 126));
        // a failing chdir: 125
        let e = Command::new("true").current_dir("/nonexistent-rlrs").exec_detailed();
        assert_eq!((e.stage, e.exit_code()), (Stage::Chdir, 125));
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        // a target above 2 in a threaded process (libtest runs this on a thread): refused before any change
        let e = Command::new("true").fd(7, Stdio::Null).exec_detailed();
        assert_eq!((e.stage, e.error.raw_os_error(), e.exit_code()), (Stage::Prepare, Some(libc::EBUSY), 125));
        assert_eq!(unsafe { libc::fcntl(7, libc::F_GETFD) }, -1);
        assert_eq!(spawn::exit_code_for(Stage::Exec, &std::io::Error::from_raw_os_error(libc::ENOEXEC)), 126);
        let _ = ign_before;
    });
}
