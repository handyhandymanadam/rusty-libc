use crate::errno::{Errno, cvt};
use crate::fd::OwnedRawFd;
use crate::signal::{self, Action, INTERNAL, KSigaction, SIG_IGN, bit};
use crate::spawn::{SpawnPlan, Stage};
use crate::syscall::{nr, syscall3, syscall6};
use crate::term::TIOCSCTTY;
use std::vec::Vec;

const F_DUPFD_CLOEXEC: usize = 1030;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const AT_FDCWD: isize = -100;
const O_PATH_DIR_CLOEXEC: usize = 0o10000000 | 0o200000 | 0o2000000;

struct Undo {
    fds: Vec<(i32, Option<(OwnedRawFd, usize)>)>,
    cwd: Option<OwnedRawFd>,
    ignored: Vec<i32>,
    mask: u64,
}

impl Undo {
    fn run(self) {
        for sig in self.ignored {
            let _ = signal::set_action_raw(sig, Action::Ignore);
        }
        for (target, saved) in self.fds.into_iter().rev() {
            match saved {
                Some((s, flags)) => {
                    let _ = unsafe { syscall3(nr::DUP2, s.as_raw() as usize, target as usize, 0) };
                    let _ = unsafe { syscall3(nr::FCNTL, target as usize, F_SETFD, flags) };
                }
                None => {
                    let _ = unsafe { syscall3(nr::CLOSE, target as usize, 0, 0) };
                }
            }
        }
        if let Some(d) = self.cwd {
            let _ = plain!(nr::FCHDIR, d.as_raw());
        }
        signal::set_mask(self.mask);
    }
}

pub fn exec_in_place(plan: &SpawnPlan<'_>) -> (Stage, Errno) {
    if plan.fds.iter().any(|&(_, t)| t > 2) {
        match crate::threads::single_threaded() {
            Ok(true) => {}
            Ok(false) => return (Stage::Prepare, Errno(16)),
            Err(e) => return (Stage::Prepare, e),
        }
    }
    let min_fd = plan.fds.iter().map(|&(s, t)| s.as_raw().max(t)).max().unwrap_or(2).max(2) + 1;
    let old_mask = signal::set_mask(!INTERNAL);
    let mut undo = Undo { fds: Vec::with_capacity(plan.fds.len()), cwd: None, ignored: Vec::new(), mask: old_mask };
    match steps(plan, min_fd, &mut undo) {
        Ok(()) => {
            let want = plan.mask.map_or(old_mask, |m| m.0);
            signal::set_mask((want & !INTERNAL) | (old_mask & INTERNAL));
            let e = plan.exec();
            undo.run();
            (Stage::Exec, e)
        }
        Err((stage, e)) => {
            undo.run();
            (stage, e)
        }
    }
}

fn steps(plan: &SpawnPlan<'_>, min_fd: i32, undo: &mut Undo) -> Result<(), (Stage, Errno)> {
    for &(src, dst) in plan.fds {
        let r = unsafe { syscall3(nr::FCNTL, dst as usize, F_DUPFD_CLOEXEC, min_fd as usize) };
        let saved = match cvt(r) {
            Ok(fd) => {
                let copy = unsafe { OwnedRawFd::from_raw(fd as i32) };
                let flags = cvt(unsafe { syscall3(nr::FCNTL, dst as usize, F_GETFD, 0) }).unwrap_or(0);
                Some((copy, flags))
            }
            Err(Errno::EBADF) => None,
            Err(e) => return Err((Stage::Fds, e)),
        };
        if src.as_raw() == dst {
            if let Err(e) = cvt(unsafe { syscall3(nr::FCNTL, dst as usize, F_SETFD, 0) }) {
                return Err((Stage::Fds, e));
            }
            continue;
        }
        undo.fds.push((dst, saved));
        if let Err(e) = cvt(unsafe { syscall3(nr::DUP2, src.as_raw() as usize, dst as usize, 0) }) {
            return Err((Stage::Fds, e));
        }
    }
    if let Some(dir) = plan.cwd {
        let r = unsafe { syscall6(nr::OPENAT, AT_FDCWD as usize, c".".as_ptr() as usize, O_PATH_DIR_CLOEXEC, 0, 0, 0) };
        undo.cwd = cvt(r).ok().map(|fd| unsafe { OwnedRawFd::from_raw(fd as i32) });
        cvt(unsafe { syscall3(nr::CHDIR, dir.as_ptr() as usize, 0, 0) }).map_err(|e| (Stage::Chdir, e))?;
    }
    if plan.setsid {
        crate::process::setsid().map_err(|e| (Stage::Setsid, e))?;
    }
    if let Some(pg) = plan.pgroup
        && !(plan.setsid && pg == 0)
    {
        crate::process::setpgid(0, pg).map_err(|e| (Stage::Setpgid, e))?;
    }
    if let Some((fd, steal)) = plan.ctty {
        cvt(unsafe { syscall3(nr::IOCTL, fd as usize, TIOCSCTTY, steal as usize) }).map_err(|e| (Stage::ControllingTerminal, e))?;
    }
    if let Some((fd, required)) = plan.foreground {
        let r = unsafe { crate::spawn::child_tcsetpgrp(fd, None) };
        if let Err(e) = r
            && required
        {
            return Err((Stage::Foreground, e));
        }
    }
    for sig in 1..=64 {
        if plan.sig_default.0 & bit(sig) == 0 || bit(sig) & INTERNAL != 0 {
            continue;
        }
        let mut old = KSigaction::DEFAULT;
        if cvt(signal::rt_sigaction(sig, None, Some(&mut old))).is_ok() && old.handler == SIG_IGN {
            signal::set_action_raw(sig, Action::Default).map_err(|e| (Stage::Signals, e))?;
            undo.ignored.push(sig);
        }
    }
    Ok(())
}
