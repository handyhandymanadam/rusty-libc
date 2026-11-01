//! FIXLIST #127 stage 3: kill(-1), the signal list, getrusage, users and groups, signal handlers, inherited descriptors.
#![allow(clippy::undocumented_unsafe_blocks)]

mod common;
use common::*;
use rusty_libc_rs::process::{Rusage, RusageWho, getrusage};
use rusty_libc_rs::signal::kill_all;
use rusty_libc_rs::*;

/// The "N) SIGNAME" pairs of bash's `kill -l` / `trap -l` table.
fn bash_list(builtin: &str) -> Vec<(i32, String)> {
    let out = std::process::Command::new("bash").args(["-c", builtin]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let words: Vec<&str> = text.split_whitespace().collect();
    words.chunks(2).map(|p| (p[0].trim_end_matches(')').parse().unwrap(), p[1].to_string())).collect()
}

#[test]
fn signal_list_matches_bash() {
    let ours: Vec<(i32, String)> = SigNum::all().map(|s| (s.as_raw(), s.name().unwrap().into_owned())).collect();
    assert_eq!(ours.len(), 62);
    assert_eq!(ours, bash_list("kill -l"));
    assert_eq!(ours, bash_list("trap -l"));
    assert_eq!(SigNum::all().collect::<Vec<_>>(), SigNum::ALL.to_vec());
    assert_eq!(SigNum::all().len(), 62);
    for s in SigNum::all() {
        assert_eq!(SigNum::from_name(&s.name().unwrap()), Some(s));
    }
}

#[test]
fn kill_all_in_own_pid_namespace() {
    const NAME: &str = "kill_all_in_own_pid_namespace";
    if in_scenario(NAME) {
        // Guard: kill(-1) reaches every process the caller may signal. Only ever call it as process 1 of a fresh PID
        // namespace, where "every process" means this process's own descendants (CLAUDE.md, 2026-10-10 incident).
        assert_eq!(std::process::id(), 1, "kill_all test must run as pid 1 of its own PID namespace");
        assert_eq!(kill_all(SigNum::new(32).unwrap()).unwrap_err(), en(libc::EINVAL));
        assert_eq!(kill_all(SigNum::new(33).unwrap()).unwrap_err(), en(libc::EINVAL));
        // no other process in the namespace yet: ESRCH
        assert_eq!(kill_all(Signal::TERM).unwrap_err(), en(libc::ESRCH));
        let mut a = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let mut b = Command::new("/bin/sleep").arg("30").process_group(None).spawn().unwrap();
        kill_all(SigNum::rt(1).unwrap()).unwrap();
        for c in [&mut a, &mut b] {
            let i = rusty_libc_rs::process::waitid(rusty_libc_rs::process::WaitId::Pid(c.pid()), rusty_libc_rs::process::WaitIdOptions::EXITED)
                .unwrap()
                .unwrap();
            assert_eq!(i.code, rusty_libc_rs::process::WaitCode::Killed(SigNum::rt(1).unwrap()));
        }
        return;
    }
    let (mut c, out) = scenario_command(NAME, &["unshare", "-r", "-p", "-f", "--kill-child"]);
    let child = c.spawn().unwrap();
    drop(c);
    scenario_passed(NAME, child, out);
}

fn host_rusage(who: i32) -> libc::rusage {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(who, &mut r) }, 0);
    r
}

fn tv(t: libc::timeval) -> std::time::Duration {
    std::time::Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000)
}

#[test]
fn getrusage_matches_host() {
    // children: fixed once they are waited for, so ours and the host's must be equal
    let mut c = Command::new("/bin/sh").args(["-c", "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done"]).spawn().unwrap();
    assert!(c.wait().unwrap().success());
    let h = host_rusage(libc::RUSAGE_CHILDREN);
    let o: Rusage = getrusage(RusageWho::Children).unwrap();
    assert_eq!(o.user_time, tv(h.ru_utime));
    assert_eq!(o.system_time, tv(h.ru_stime));
    assert_eq!(o.max_rss_kib, h.ru_maxrss as u64);
    assert_eq!((o.minor_faults, o.major_faults), (h.ru_minflt as u64, h.ru_majflt as u64));
    assert_eq!((o.block_inputs, o.block_outputs), (h.ru_inblock as u64, h.ru_oublock as u64));
    assert_eq!((o.voluntary_switches, o.involuntary_switches), (h.ru_nvcsw as u64, h.ru_nivcsw as u64));
    assert!(o.max_rss_kib > 0 && o.minor_faults > 0);
    // self and thread: between two host readings
    for (who, hw) in [(RusageWho::Process, libc::RUSAGE_SELF), (RusageWho::Thread, libc::RUSAGE_THREAD)] {
        let before = host_rusage(hw);
        let o = getrusage(who).unwrap();
        let after = host_rusage(hw);
        assert!(tv(before.ru_utime) <= o.user_time && o.user_time <= tv(after.ru_utime), "{who:?}");
        assert!(tv(before.ru_stime) <= o.system_time && o.system_time <= tv(after.ru_stime), "{who:?}");
        assert!(before.ru_minflt as u64 <= o.minor_faults && o.minor_faults <= after.ru_minflt as u64, "{who:?}");
        assert!(o.max_rss_kib >= before.ru_maxrss as u64 && o.max_rss_kib <= after.ru_maxrss as u64, "{who:?}");
    }
}

fn run(cmd: &str, args: &[&str]) -> String {
    let out = std::process::Command::new(cmd).args(args).output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn users_match_getent() {
    use rusty_libc_rs::users::*;
    use std::os::unix::ffi::OsStrExt;
    let text = run("getent", &["passwd"]);
    let lines: Vec<&str> = text.lines().take(300).collect();
    assert!(lines.iter().any(|l| l.starts_with("root:")));
    for line in &lines {
        let f: Vec<&str> = line.split(':').collect();
        let u = user_by_name(f[0]).unwrap().unwrap_or_else(|| panic!("{line}"));
        assert_eq!(u.name.as_bytes(), f[0].as_bytes());
        assert_eq!(u.uid.as_raw().to_string(), f[2], "{line}");
        assert_eq!(u.gid.as_raw().to_string(), f[3], "{line}");
        assert_eq!(u.gecos.as_bytes(), f[4].as_bytes(), "{line}");
        assert_eq!(u.home.as_os_str().as_bytes(), f[5].as_bytes(), "{line}");
        assert_eq!(u.shell.as_os_str().as_bytes(), f[6].as_bytes(), "{line}");
        // by uid: the first entry with that uid, as getent's own lookup
        let by_uid = user_by_uid(u.uid).unwrap().unwrap();
        assert_eq!(by_uid.name.as_bytes(), run("getent", &["passwd", f[2]]).split(':').next().unwrap().as_bytes());
    }
    assert_eq!(user_by_name("no-such-user-rlrs").unwrap(), None);
    assert_eq!(user_by_name("ro\0ot").unwrap(), None);
    assert_eq!(user_by_uid(Uid::from_raw(4_000_000_123)).unwrap(), None);
    // current user: the real uid's name (getent passwd $(id -ru)), or None when the uid has no entry
    let me = run("getent", &["passwd", run("id", &["-ru"]).trim()]);
    let me = me.split(':').next().filter(|s| !s.is_empty());
    assert_eq!(current_user_name().unwrap().as_deref().map(|s| s.as_bytes()), me.map(str::as_bytes));
}

#[test]
fn groups_match_getent_and_id() {
    use rusty_libc_rs::users::*;
    use std::os::unix::ffi::OsStrExt;
    let text = run("getent", &["group"]);
    for line in text.lines().take(300) {
        let f: Vec<&str> = line.split(':').collect();
        let g = group_by_name(f[0]).unwrap().unwrap_or_else(|| panic!("{line}"));
        assert_eq!(g.name.as_bytes(), f[0].as_bytes());
        assert_eq!(g.gid.as_raw().to_string(), f[2], "{line}");
        let members: Vec<&[u8]> = g.members.iter().map(|m| m.as_bytes()).collect();
        let want: Vec<&[u8]> = f[3].split(',').filter(|s| !s.is_empty()).map(str::as_bytes).collect();
        assert_eq!(members, want, "{line}");
        let by_gid = group_by_gid(g.gid).unwrap().unwrap();
        assert_eq!(by_gid.name.as_bytes(), run("getent", &["group", f[2]]).split(':').next().unwrap().as_bytes());
    }
    assert_eq!(group_by_name("no-such-group-rlrs").unwrap(), None);
    assert_eq!(group_by_gid(Gid::from_raw(4_000_000_123)).unwrap(), None);
    // getgrouplist vs `id -G user` (which prints the user's gid, then getgrouplist's other groups)
    let users = run("getent", &["passwd"]);
    let mut checked = 0;
    for line in users.lines().take(40) {
        let f: Vec<&str> = line.split(':').collect();
        let mut want: Vec<u32> = run("id", &["-G", f[0]]).split_whitespace().map(|s| s.parse().unwrap()).collect();
        let primary = Gid::from_raw(f[3].parse().unwrap());
        let got = group_list(f[0], primary).unwrap();
        assert_eq!(got[0], primary, "{line}");
        let mut got: Vec<u32> = got.iter().map(|g| g.as_raw()).collect();
        got.sort_unstable();
        got.dedup();
        want.sort_unstable();
        want.dedup();
        assert_eq!(got, want, "{line}");
        checked += 1;
    }
    assert!(checked > 0);
    assert_eq!(group_list("no-such-user-rlrs", Gid::from_raw(1234)).unwrap(), vec![Gid::from_raw(1234)]);
    assert_eq!(group_list("a\0b", Gid::ROOT).unwrap_err(), en(libc::EINVAL));
}

mod handlers {
    use super::*;
    use rusty_libc_rs::signal::{Registration, get_signal, kill_process, register_counter, register_flag, set_signal};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    fn me() -> Pid {
        rusty_libc_rs::process::getpid()
    }

    /// SigCgt (caught) bit of `sig` in /proc/self/status.
    fn caught(sig: i32) -> bool {
        let (_, _, cgt) = sig_masks(&std::fs::read_to_string("/proc/self/status").unwrap());
        cgt & (1u64 << (sig - 1)) != 0
    }

    fn wait_until(what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    static C_HITS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn c_handler(_: i32) {
        C_HITS.fetch_add(1, SeqCst);
    }

    #[test]
    fn flag_counter_and_restore() {
        isolated("handlers::flag_counter_and_restore", || {
            let usr1 = Signal::USR1;
            assert_eq!(get_signal(usr1).unwrap(), Disposition::Default);
            let flag = Arc::new(AtomicBool::new(false));
            let reg = register_flag(usr1, Arc::clone(&flag)).unwrap();
            assert_eq!(reg.signal(), usr1.as_raw());
            assert!(caught(10));
            assert_eq!(get_signal(usr1).unwrap(), Disposition::Handler);
            kill_process(me(), usr1).unwrap();
            wait_until("flag", || flag.load(SeqCst));
            // a counter on the same signal, and a second flag; drop the first flag: the others still fire
            let n = Arc::new(AtomicUsize::new(0));
            let creg = register_counter(usr1, Arc::clone(&n)).unwrap();
            let flag2 = Arc::new(AtomicBool::new(false));
            let reg2 = register_flag(usr1, Arc::clone(&flag2)).unwrap();
            drop(reg);
            assert_eq!(Arc::strong_count(&flag), 1, "the table released its count");
            flag.store(false, SeqCst);
            for i in 1..=3 {
                kill_process(me(), usr1).unwrap();
                wait_until("counter", || n.load(SeqCst) == i);
            }
            assert!(flag2.load(SeqCst) && !flag.load(SeqCst));
            drop(creg);
            drop(reg2);
            assert!(!caught(10));
            assert_eq!(get_signal(usr1).unwrap(), Disposition::Default);
            assert_eq!((Arc::strong_count(&n), Arc::strong_count(&flag2)), (1, 1));
            // real-time signals are queued: every one is counted
            let rt = SigNum::rt(3).unwrap();
            let n = Arc::new(AtomicUsize::new(0));
            let creg = register_counter(rt, Arc::clone(&n)).unwrap();
            let mask = blocked_signals_set(rt);
            for _ in 0..5 {
                kill_process(me(), rt).unwrap();
            }
            restore_mask(mask);
            wait_until("rt counter", || n.load(SeqCst) == 5);
            drop(creg);
            // previous ignore comes back
            set_signal(usr1, Action::Ignore).unwrap();
            let r = register_flag(usr1, Arc::new(AtomicBool::new(false))).unwrap();
            assert_eq!(get_signal(usr1).unwrap(), Disposition::Handler);
            drop(r);
            assert_eq!(get_signal(usr1).unwrap(), Disposition::Ignore);
            // keep(): stays registered
            let f = Arc::new(AtomicBool::new(false));
            register_flag(Signal::USR2, Arc::clone(&f)).unwrap().keep();
            kill_process(me(), Signal::USR2).unwrap();
            wait_until("kept flag", || f.load(SeqCst));
            assert_eq!(Arc::strong_count(&f), 2);
        });
    }

    /// Block `sig` in this thread (so several are queued before delivery); returns the old mask.
    fn blocked_signals_set(sig: SigNum) -> libc::sigset_t {
        unsafe {
            let mut s: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut s);
            libc::sigaddset(&mut s, sig.as_raw());
            // block it process-wide in practice: this test's process has the harness threads too, so block in every
            // thread is not possible; a blocked signal sent to the process waits for any unblocked thread, so sending
            // while blocked here only delays delivery
            libc::pthread_sigmask(libc::SIG_BLOCK, &s, &mut old);
            old
        }
    }

    fn restore_mask(old: libc::sigset_t) {
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    }

    #[test]
    fn chains_and_restores_previous_handler() {
        isolated("handlers::chains_and_restores_previous_handler", || unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = c_handler as *const () as usize;
            libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
            let flag = Arc::new(AtomicBool::new(false));
            let reg = register_flag(Signal::USR2, Arc::clone(&flag)).unwrap();
            kill_process(me(), Signal::USR2).unwrap();
            wait_until("flag and chained C handler", || flag.load(SeqCst) && C_HITS.load(SeqCst) == 1);
            drop(reg);
            let mut cur: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut cur);
            assert_eq!(cur.sa_sigaction, c_handler as *const () as usize, "previous handler restored");
            kill_process(me(), Signal::USR2).unwrap();
            wait_until("C handler alone", || C_HITS.load(SeqCst) == 2);
        });
    }

    #[test]
    fn refused_and_full() {
        isolated("handlers::refused_and_full", || {
            for n in [4, 7, 8, 9, 11, 19, 32, 33] {
                let s = SigNum::new(n).unwrap();
                assert_eq!(register_flag(s, Arc::new(AtomicBool::new(false))).unwrap_err(), en(libc::EINVAL), "{n}");
                assert_eq!(register_counter(s, Arc::new(AtomicUsize::new(0))).unwrap_err(), en(libc::EINVAL), "{n}");
            }
            let f = Arc::new(AtomicBool::new(false));
            let regs: Vec<Registration> = (0..rusty_libc_rs::signal::SLOTS).map(|_| register_flag(Signal::WINCH, Arc::clone(&f)).unwrap()).collect();
            assert_eq!(register_flag(Signal::WINCH, Arc::clone(&f)).unwrap_err(), en(libc::ENOSPC));
            assert_eq!(Arc::strong_count(&f), 1 + rusty_libc_rs::signal::SLOTS, "refused registration released its Arc");
            drop(regs);
            assert_eq!(Arc::strong_count(&f), 1);
            assert!(!caught(28));
        });
    }

    #[test]
    fn register_unregister_under_signal_storm() {
        isolated("handlers::register_unregister_under_signal_storm", || {
            use std::time::{Duration, Instant};
            // keep one registration alive so the handler stays installed (SIGURG's default is ignore anyway); it is
            // registered before the sender starts, so every signal sent from then on is counted (or merged with one
            // still pending: standard signals coalesce, so `base` may be below `sent`, never 0 once one arrived)
            let base = Arc::new(AtomicUsize::new(0));
            let keep = register_counter(Signal::URG, Arc::clone(&base)).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let sent = Arc::new(AtomicUsize::new(0));
            let pid = me();
            let sender = {
                let (stop, sent) = (Arc::clone(&stop), Arc::clone(&sent));
                std::thread::spawn(move || {
                    while !stop.load(SeqCst) {
                        kill_process(pid, Signal::URG).unwrap();
                        sent.fetch_add(1, SeqCst);
                    }
                })
            };
            // The storm must be running before the loop starts and while it runs. (Before 2026-10-14 the loop started
            // at once: with the sender thread not yet scheduled, e.g. on a loaded machine or one CPU, the 20000
            // iterations could finish before it sent anything, and the final check saw "sent 0, counted 0".)
            let deadline = Instant::now() + Duration::from_secs(20);
            while base.load(SeqCst) == 0 {
                assert!(Instant::now() < deadline, "no signal arrived (sent {})", sent.load(SeqCst));
                std::thread::yield_now();
            }
            let sent_before = sent.load(SeqCst);
            let mut iterations = 0u64;
            let mut raced = 0u64;
            // at least 20000 register/unregister rounds and at least 2000 signals sent during them
            while iterations < 20000 || sent.load(SeqCst) - sent_before < 2000 {
                assert!(Instant::now() < deadline, "storm too slow: {iterations} rounds, {} signals", sent.load(SeqCst) - sent_before);
                let n = Arc::new(AtomicUsize::new(0));
                let r = register_counter(Signal::URG, Arc::clone(&n)).unwrap();
                if iterations.is_multiple_of(64) {
                    std::thread::yield_now(); // give the sender (and the handler) a chance to land inside a registration
                }
                drop(r);
                // the slot's strong count was released, after any handler that could still see it finished
                assert_eq!(Arc::strong_count(&n), 1);
                raced += (n.load(SeqCst) > 0) as u64;
                iterations += 1;
            }
            stop.store(true, SeqCst);
            sender.join().unwrap();
            drop(keep);
            let (total, counted) = (sent.load(SeqCst), base.load(SeqCst));
            assert!(counted > 0 && counted <= total, "sent {total}, counted {counted}");
            eprintln!("storm: {iterations} rounds, {} signals during them, {raced} rounds counted a signal", total - sent_before);
        });
    }
}

mod inherited {
    use super::*;
    use rusty_libc_rs::fd::{inherited_snapshot_taken, reopen_fd, take_inherited, was_inherited};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    const NAME: &str = "inherited::socket_pipe_and_replaced";

    #[test]
    fn socket_pipe_and_replaced() {
        if in_scenario(NAME) {
            assert!(inherited_snapshot_taken(), "the .init_array snapshot ran");
            assert!(was_inherited(3) && was_inherited(4) && was_inherited(5));
            for n in [0, 1, 2, -1, 1024, 5000] {
                assert!(take_inherited(n).is_none(), "{n}");
            }
            // fd 3: a socket (reopen through /proc cannot open sockets; adoption can)
            assert!(reopen_fd(3).is_err());
            let s: OwnedFd = take_inherited(3).expect("fd 3");
            assert!(take_inherited(3).is_none(), "second take");
            let mut s = UnixStream::from(s);
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            s.write_all(b"pong").unwrap();
            // fd 4: the read end of a pipe
            let p = take_inherited(4).expect("fd 4");
            assert!(take_inherited(4).is_none());
            let mut text = String::new();
            std::fs::File::from(p).read_to_string(&mut text).unwrap();
            assert_eq!(text, "pipe-data");
            // fd 5: inherited, then replaced by another file (through unsafe code: the documented assumption's case)
            let other = std::fs::File::open("/proc/self/status").unwrap();
            assert_eq!(unsafe { libc::dup2(other.as_raw_fd(), 5) }, 5);
            assert!(take_inherited(5).is_none(), "different file at the number");
            assert!(take_inherited(5).is_none());
            // a descriptor opened after start
            let f = std::fs::File::open("/dev/null").unwrap();
            assert!(!was_inherited(f.as_raw_fd()) || f.as_raw_fd() < 3);
            assert!(take_inherited(f.as_raw_fd()).is_none());
            // dropping the taken socket closed it: the number is not adoptable again
            drop(s);
            assert!(take_inherited(3).is_none());
            return;
        }
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"ping").unwrap();
        let (r, mut w) = std::io::pipe().unwrap();
        w.write_all(b"pipe-data").unwrap();
        drop(w);
        let (mut c, out) = scenario_command(NAME, &[]);
        c.fd(3, OwnedFd::from(b)).fd(4, r).fd(5, std::fs::File::open("/dev/null").unwrap());
        let child = c.spawn().unwrap();
        drop(c);
        scenario_passed(NAME, child, out);
        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    fn not_for_descriptors_opened_later() {
        assert!(inherited_snapshot_taken());
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(take_inherited(f.as_raw_fd()).is_none());
        assert!(take_inherited(0).is_none() && take_inherited(2).is_none());
    }
}
