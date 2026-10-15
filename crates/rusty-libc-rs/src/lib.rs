#![forbid(unsafe_code)]

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

pub mod process {
    pub use crate::ids::{getpgid, getpgrp, getsid};
    pub use crate::lock::{LockConflict, fcntl_getlk, fcntl_ofd_getlk};
    pub use crate::rusage::{Rusage, RusageWho, getrusage};
    pub use crate::sysinfo::get_umask;
    pub use crate::wait::{WaitCode, WaitInfo, waitid};
    pub use rustix::process::*;
}

pub mod termios {
    pub use crate::ids::{tcgetpgrp, tcgetsid};
    pub use crate::term::set_controlling_terminal;
    pub use rustix::termios::*;
}

pub mod fd {
    pub use crate::inherit::{INHERITED_FD_LIMIT, inherited_snapshot_taken, take_inherited, was_inherited};
    pub use crate::reopen::reopen_fd;
    pub use rustix::fd::*;
}

pub mod io {
    pub use rustix::io::*;
}

pub mod event {
    pub use rustix::event::*;
}

pub mod fs {
    pub use rustix::fs::*;
}

pub mod mm {
    pub use rustix::mm::*;
}

pub mod net {
    pub use crate::ids::PeerCred;
    pub use crate::msg::{Credentials, MAX_FDS, RecvMsg, ancillary_space, recvmsg, sendmsg};
    pub use rustix::net::*;

    pub mod sockopt {
        pub use crate::ids::socket_peercred;
        pub use rustix::net::sockopt::*;
    }

    #[allow(dead_code, hidden_glob_reexports)]
    struct RecvAncillaryBuffer;
    #[allow(dead_code, hidden_glob_reexports)]
    struct RecvAncillaryMessage;
    #[allow(dead_code, hidden_glob_reexports)]
    struct AncillaryDrain;
}

pub mod param {
    pub use rustix::param::*;
}

pub mod pipe {
    pub use rustix::pipe::*;
}

pub mod pty {
    pub use rustix::pty::*;
}

pub mod rand {
    pub use rustix::rand::*;
}

pub mod stdio {
    pub use rustix::stdio::*;
}

pub mod system {
    pub use crate::sysinfo::{gethostid, getloadavg};
    pub use rustix::system::*;
}

pub mod thread {
    pub use crate::sysinfo::{SchedPolicy, sched_getparam, sched_getscheduler};
    pub use rustix::thread::*;
}

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

pub(crate) fn errno(e: rusty_libc_rs_core::errno::Errno) -> rustix::io::Errno {
    rustix::io::Errno::from_raw_os_error(e.0)
}
