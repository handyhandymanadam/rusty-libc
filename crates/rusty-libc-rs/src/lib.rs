//! The one library Rust ports of rusty-libc use for operating-system access (FIXLIST #127, Adam: "integrate rustix into
//! ours then. I don't want two seperate libraries."): rustix's safe system-call API, re-exported, plus what rustix leaves
//! out (a spawn builder without `pre_exec`, signal dispositions, waitid that says which child, the controlling terminal
//! with `steal`, confstr, reopening a descriptor by number). Ports name only `rusty_libc_rs`. Safe Rust, std, stable,
//! `#![forbid(unsafe_code)]`: this crate's own system calls live in rusty-libc-rs-core (no_std, every unsafe block
//! documented); rustix (linux_raw backend: raw system calls, no C library calls) is a crates.io dependency with its own
//! audited unsafe. Both behave the same in a glibc-hosted and in a rusty-libc-hosted process.
//!
//! # Layout
//!
//! rustix's API modules appear under their rustix names, each one rustix's module plus (where the area is the same) this
//! crate's additions, so one path per area (Rust Programming Language ch. 14.2, p. 390: `pub use` gives users a public
//! structure different from the private one):
//!
//! | module | contents |
//! |---|---|
//! | [`process`] | `rustix::process::*` (ids, `Pid`, `Uid`, `Signal`, `kill_process`, `waitpid`, `WaitStatus`, `setsid`, `setpgid`, `getrlimit`, `umask`, pidfd...), with **this crate's [`waitid`](process::waitid)** in place of rustix's (rustix's `WaitIdStatus` has no pid/uid) and [`WaitInfo`](process::WaitInfo), [`WaitCode`](process::WaitCode), and **this crate's [`getpgrp`](process::getpgrp), [`getpgid`](process::getpgid), [`getsid`](process::getsid) returning `Option<Pid>`** in place of rustix's (see below) |
//! | [`termios`] | `rustix::termios::*` (`tcgetattr`/`tcsetattr`, `tcsetpgrp`, `ttyname`, `isatty`...) plus [`set_controlling_terminal`](termios::set_controlling_terminal) (TIOCSCTTY with `steal`) and **this crate's [`tcgetpgrp`](termios::tcgetpgrp), [`tcgetsid`](termios::tcgetsid) returning `Option<Pid>`** |
//! | [`fd`] | `rustix::fd::*` (std's `OwnedFd`, `BorrowedFd`, `AsFd`, ...) plus [`reopen_fd`](fd::reopen_fd) and [`take_inherited`](fd::take_inherited) (adopt a descriptor inherited at exec, once) |
//! | [`io`] | `rustix::io::*` (`Errno`, `Result`, `read`, `write`, `dup`, `dup2`, `fcntl_dupfd_cloexec`, ...) |
//! | [`net`] | `rustix::net::*` with **this crate's [`socket_peercred`](net::sockopt::socket_peercred)** (returns [`PeerCred`](net::PeerCred)) and **this crate's [`recvmsg`](net::recvmsg)/[`sendmsg`](net::sendmsg)** (descriptors as `OwnedFd`, [`Credentials`](net::Credentials) with `Option<Pid>`, MSG_CTRUNC closes what arrived; see Soundness) |
//! | [`event`], [`fs`], [`mm`], [`param`], [`pipe`], [`pty`], [`rand`], [`stdio`], [`system`], [`thread`], [`time`] | rustix's module of that name, unchanged |
//! | [`signal`] | this crate: [`SigNum`](signal::SigNum) (standard and real-time signals; rustix's `Signal` converts into it), [`SigSet`](signal::SigSet), [`get_signal`](signal::get_signal)/[`set_signal`](signal::set_signal) (ignore/default), [`blocked_signals`](signal::blocked_signals), [`kill_process`](signal::kill_process)/[`kill_process_group`](signal::kill_process_group) for any signal incl. real-time, signal names ([`SigNum::name`](signal::SigNum::name), [`SigNum::from_name`](signal::SigNum::from_name)), the ordered list [`SigNum::ALL`](signal::SigNum::ALL) (bash's `kill -l`), [`kill_all`](signal::kill_all) (kill -1), flag/counter handlers [`register_flag`](signal::register_flag)/[`register_counter`](signal::register_counter); the thread mask through the C library ([`thread_mask`](signal::thread_mask), [`set_thread_mask`](signal::set_thread_mask), [`block_signals`](signal::block_signals), [`unblock_signals`](signal::unblock_signals)); [`signal_states`](signal::signal_states) (every signal's disposition and blocked state); [`sigwait`](signal::sigwait)/[`sigwaitinfo`](signal::sigwaitinfo)/[`sigtimedwait`](signal::sigtimedwait) with a decoded [`SigInfo`](signal::SigInfo); `Signal` re-exported |
//! | [`spawn`] | this crate: [`Command`], [`Child`], [`Stdio`] (session, process group, controlling terminal, foreground, signals, fd mappings); [`Command::exec`] (exec without fork) and coreutils' 125/126/127 exit codes ([`SpawnError::exit_code`]) |
//! | [`users`] | this crate: users and groups through the running C library's NSS ([`user_by_name`](users::user_by_name), [`user_by_uid`](users::user_by_uid), [`current_user_name`](users::current_user_name), [`group_by_name`](users::group_by_name), [`group_by_gid`](users::group_by_gid), [`group_list`](users::group_list)) |
//! | [`confstr`](mod@confstr) | this crate: confstr(3) values (glibc 2.43's table) |
//! | [`sysconf`](mod@sysconf) | this crate: the sysconf(3) values the ports use, as glibc 2.43 computes them |
//! | [`env`] | this crate: the C library's environ raw ([`vars_raw`](env::vars_raw)); [`set_var`](env::set_var)/[`remove_var`](env::remove_var) only in a single-threaded process (safe, checked) |
//! | [`utmp`] | this crate: login records (utmp/wtmp) through the running C library ([`utmp_entries`](utmp::utmp_entries), [`utmp_entries_from`](utmp::utmp_entries_from)) |
//! | [`time`] additions | [`Timer`](time::Timer) (timer_create with a signal; Drop deletes), [`setitimer`](time::setitimer)/[`getitimer`](time::getitimer) |
//! | [`system`] / [`thread`] / [`process`] additions | [`getloadavg`](system::getloadavg), [`gethostid`](system::gethostid); [`sched_getscheduler`](thread::sched_getscheduler), [`sched_getparam`](thread::sched_getparam); [`get_umask`](process::get_umask) (read-only, from /proc) |
//!
//! Errors: the system-call functions (rustix's and ours) return [`io::Result`] (`Result<T, Errno>`; `Errno` converts
//! into `std::io::Error` with `?`). The std-shaped pieces (`Command::spawn`, `Child::wait`, `reopen_fd`) return
//! `std::io::Result` like their std counterparts.
//!
//! Where rustix and this crate had the same call, rustix's is the one exported (getpid/getppid/uid/gid getters, setpgid,
//! setsid, tcsetpgrp, dup_cloexec = `io::fcntl_dupfd_cloexec`, kill = `process::kill_process`); this crate keeps a call
//! only where it does more: `waitid` (pid/uid), TIOCSCTTY (`steal`), and the calls whose answer can be pid 0 (see
//! Soundness below).
//!
//! # Soundness: rustix calls that are replaced or hidden
//!
//! rustix 1.1.5 builds its `Pid` (a non-zero integer) from kernel values without a check in a few places where Linux can
//! report 0: a process group, session or foreground group outside the caller's PID namespace, a socket without a peer,
//! a credentials message from outside the namespace. In a release build that is an invalid value (undefined behaviour)
//! reached from safe code. Through this crate those calls are either replaced by versions returning `Option<Pid>`
//! (`process::{getpgrp, getpgid, getsid}`, `termios::{tcgetpgrp, tcgetsid}`, `net::sockopt::socket_peercred`,
//! `net::recvmsg` with [`net::RecvMsg`] and [`net::Credentials`], `process::fcntl_getlk` with
//! [`process::LockConflict`], whose owner is -1 for an open-file-description lock) or hidden (rustix's receive-side
//! ancillary types `RecvAncillaryBuffer`, `RecvAncillaryMessage`, `AncillaryDrain`). The rustix crate itself is not re-exported, so a port cannot
//! reach the unchecked versions through `rusty_libc_rs`:
//!
//! ```compile_fail
//! use rusty_libc_rs::net::AncillaryDrain;
//! ```
//! ```compile_fail
//! use rusty_libc_rs::net::RecvAncillaryMessage;
//! ```
//! ```compile_fail
//! use rusty_libc_rs::net::RecvAncillaryBuffer;
//! ```
//! ```compile_fail
//! // rustix's fcntl_getlk returned Option<Flock>; ours returns Option<LockConflict>
//! let f = std::fs::File::open("/dev/null").unwrap();
//! let _: Option<rusty_libc_rs::process::Flock> =
//!     rusty_libc_rs::process::fcntl_getlk(&f, &rusty_libc_rs::process::FlockType::ReadLock.into()).unwrap();
//! ```
//! ```compile_fail
//! use rusty_libc_rs::rustix;
//! ```
//! ```
//! // the replacements have the checked types
//! let p: Option<rusty_libc_rs::Pid> = rusty_libc_rs::process::getpgrp();
//! let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! let c: rusty_libc_rs::net::PeerCred = rusty_libc_rs::net::sockopt::socket_peercred(&s).unwrap();
//! assert_eq!((c.pid, c.uid), (None, None)); // no peer: the kernel says pid 0, uid -1
//! # let _ = p;
//! // recvmsg: credentials with Option<Pid>, descriptors as OwnedFd
//! use rusty_libc_rs::net::{Credentials, RecvFlags, SendFlags, ancillary_space, recvmsg, sendmsg};
//! use std::io::{IoSlice, IoSliceMut};
//! use std::os::fd::AsFd;
//! let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
//! rusty_libc_rs::net::sockopt::set_socket_passcred(&b, true).unwrap(); // a stream socket passes credentials only then
//! let me = Credentials::current();
//! sendmsg(&a, &[IoSlice::new(b"x")], &[a.as_fd()], Some(&me), SendFlags::empty()).unwrap();
//! let (mut data, mut control) = ([0u8; 1], vec![0u8; ancillary_space(1, true)]);
//! let m = recvmsg(&b, &mut [IoSliceMut::new(&mut data)], &mut control, RecvFlags::empty()).unwrap();
//! let pid: Option<rusty_libc_rs::Pid> = m.credentials.unwrap().pid;
//! let fds: Vec<std::os::fd::OwnedFd> = m.fds;
//! assert_eq!((pid, fds.len()), (me.pid, 1));
//! // fcntl_getlk: the owner as Option<Pid>
//! let f = std::fs::File::open("/dev/null").unwrap();
//! let c: Option<rusty_libc_rs::process::LockConflict> =
//!     rusty_libc_rs::process::fcntl_getlk(&f, &rusty_libc_rs::process::FlockType::ReadLock.into()).unwrap();
//! assert!(c.is_none());
//! ```
//!
//! Stateful services (users and groups, signal handlers, the inherited-descriptor snapshot) go through the C library the
//! process runs on, by its C ABI (rusty-libc-rs-core feature `libc-services`), so the process never holds two copies of
//! that state; everything else is a direct system call.
//!
//! x86-64 Linux only (as rusty-libc).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("rusty-libc-rs supports x86-64 Linux only");

pub mod confstr;
pub mod env;
pub mod signal;
pub mod spawn;
pub mod sysconf;
pub mod users;
pub mod utmp;

mod ids;
mod inherit;
mod lock;
mod msg;
mod reopen;
mod rusage;
mod sysinfo;
mod term;
mod timer;
mod wait;

/// Processes: `rustix::process` plus this crate's `getrusage` (`Rusage`, `RusageWho`), `waitid` (which replaces
/// rustix's: it also reports the child's pid and uid), `WaitInfo` and `WaitCode`, and `getpgrp`/`getpgid`/`getsid` returning `Option<Pid>` (which replace
/// rustix's: the id is 0 when it lies outside the caller's PID namespace), and `fcntl_getlk`/`fcntl_ofd_getlk` returning
/// `LockConflict` with `Option<Pid>` (rustix's `fcntl_getlk` is replaced: l_pid is -1 for an open-file-description lock).
pub mod process {
    pub use crate::ids::{getpgid, getpgrp, getsid};
    pub use crate::lock::{LockConflict, fcntl_getlk, fcntl_ofd_getlk};
    pub use crate::rusage::{Rusage, RusageWho, getrusage};
    pub use crate::sysinfo::get_umask;
    pub use crate::wait::{WaitCode, WaitInfo, waitid};
    pub use rustix::process::*;
}

/// Terminals: `rustix::termios` plus this crate's `set_controlling_terminal` (TIOCSCTTY with `steal`) and
/// `tcgetpgrp`/`tcgetsid` returning `Option<Pid>` (which replace rustix's, see `process`).
pub mod termios {
    pub use crate::ids::{tcgetpgrp, tcgetsid};
    pub use crate::term::set_controlling_terminal;
    pub use rustix::termios::*;
}

/// Descriptor types and traits (`rustix::fd`: std's `OwnedFd`, `BorrowedFd`, `AsFd`, ...) plus this crate's `reopen_fd`
/// and `take_inherited` (adopt a descriptor inherited at exec, claim-once).
pub mod fd {
    pub use crate::inherit::{INHERITED_FD_LIMIT, inherited_snapshot_taken, take_inherited, was_inherited};
    pub use crate::reopen::reopen_fd;
    pub use rustix::fd::*;
}

/// `rustix::io`: `Errno`, `Result`, read/write, dup, fcntl.
pub mod io {
    pub use rustix::io::*;
}

/// `rustix::event`: poll, epoll, eventfd, select.
pub mod event {
    pub use rustix::event::*;
}

/// `rustix::fs`: open, stat, access, directories, `Mode`, ...
pub mod fs {
    pub use rustix::fs::*;
}

/// `rustix::mm`: mmap, mprotect, madvise, ...
pub mod mm {
    pub use rustix::mm::*;
}

/// `rustix::net`: sockets, with this crate's `sockopt::socket_peercred` (returns `PeerCred` with `Option<Pid>`) and
/// `recvmsg`/`sendmsg` (descriptors as `OwnedFd`, `Credentials` with `Option<Pid>`, MSG_CTRUNC handled) in place of
/// rustix's. rustix's receive-side ancillary types are hidden: rustix 1.1.5 decodes an SCM_CREDENTIALS message into
/// `UCred`, whose non-zero `Pid` the kernel can fill with 0 (a sender outside the caller's PID namespace), which is
/// undefined behaviour. rustix's `sendmsg_addr`, `sendmmsg` and the send-side types are kept.
pub mod net {
    pub use crate::ids::PeerCred;
    pub use crate::msg::{Credentials, MAX_FDS, RecvMsg, ancillary_space, recvmsg, sendmsg};
    pub use rustix::net::*;

    /// `rustix::net::sockopt` with this crate's `socket_peercred` in place of rustix's.
    pub mod sockopt {
        pub use crate::ids::socket_peercred;
        pub use rustix::net::sockopt::*;
    }

    // Hidden: private items shadow rustix's (see the module documentation).
    #[allow(dead_code, hidden_glob_reexports)]
    struct RecvAncillaryBuffer;
    #[allow(dead_code, hidden_glob_reexports)]
    struct RecvAncillaryMessage;
    #[allow(dead_code, hidden_glob_reexports)]
    struct AncillaryDrain;
}

/// `rustix::param`: page size, clock ticks, ...
pub mod param {
    pub use rustix::param::*;
}

/// `rustix::pipe`: pipe, pipe_with, splice, tee.
pub mod pipe {
    pub use rustix::pipe::*;
}

/// `rustix::pty`: openpt, grantpt, unlockpt, ptsname.
pub mod pty {
    pub use rustix::pty::*;
}

/// `rustix::rand`: getrandom.
pub mod rand {
    pub use rustix::rand::*;
}

/// `rustix::stdio`: the standard descriptors.
pub mod stdio {
    pub use rustix::stdio::*;
}

/// `rustix::system` (uname, sysinfo, hostname) plus this crate's `getloadavg` and `gethostid` (glibc 2.43's rules).
pub mod system {
    pub use crate::sysinfo::{gethostid, getloadavg};
    pub use rustix::system::*;
}

/// `rustix::thread` (gettid, futex, thread names, sched_getaffinity, ...) plus this crate's `sched_getscheduler`,
/// `sched_getparam` and `SchedPolicy`.
pub mod thread {
    pub use crate::sysinfo::{SchedPolicy, sched_getparam, sched_getscheduler};
    pub use rustix::thread::*;
}

/// `rustix::time` (clocks and timerfd) plus this crate's POSIX timers (`Timer`, `TimerNotify`, `TimerSpec`) and
/// interval timers (`setitimer`, `getitimer`, `Itimer`).
pub mod time {
    pub use crate::timer::{Itimer, Timer, TimerNotify, TimerSpec, getitimer, setitimer};
    pub use rustix::time::*;
}

pub use confstr::{CS_PATH, confstr, confstr_os};
pub use rustix::io::Errno;
pub use rustix::process::{Gid, Pid, Signal, Uid};
pub use signal::{Action, Disposition, SigNum, SigSet};
pub use spawn::{Child, Command, SpawnError, Stage, Stdio};
pub use sysconf::{Sysconf, sysconf};

/// rusty-libc-rs-core's error number as rustix's.
pub(crate) fn errno(e: rusty_libc_rs_core::errno::Errno) -> rustix::io::Errno {
    rustix::io::Errno::from_raw_os_error(e.0)
}
