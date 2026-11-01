//! exec without fork: the steps of a spawn child (descriptors, chdir, session, process group, controlling terminal,
//! foreground, signal defaults, mask) done in the calling process, then execve with the PATH search (feature `std`).
//! The std layer's `Command::exec` fills in the same [`SpawnPlan`] as for `spawn`.
//!
//! # Soundness of the descriptor steps
//!
//! A spawn child dup2()s onto its own copy of the descriptor table. Here the table is the caller's, and a target number
//! may be owned by other code of the program (an `OwnedFd`), so:
//! - targets 0, 1 and 2 are always allowed: the standard streams belong to the process as a whole, and std's own safe
//!   `CommandExt::exec` dup2()s over them the same way;
//! - a target of 3 or more is allowed only when the process is single-threaded at the call
//!   ([`crate::threads::single_threaded`]): then no other thread can use, close or reopen that number while it is
//!   replaced, and
//! - if any step fails, every replaced descriptor is put back: the old open file description is dup2()ed back from a
//!   saved close-on-exec copy (or the number is closed again if it was not open), so after a failed exec every number
//!   refers to what it referred to before. The working directory (saved as an O_PATH descriptor), the signals set
//!   from "ignore" to "default" and the signal mask are put back too.
//!
//! Not put back after a failure (the kernel has no undo; the program usually exits next): setsid, setpgid, TIOCSCTTY,
//! tcsetpgrp. All signals except glibc's internal 32/33 are blocked from the first step to the execve, so tcsetpgrp
//! cannot raise SIGTTOU and no handler runs in between (as in the spawn child).
//!
//! Signal "defaults": execve itself resets every caught signal to SIG_DFL, so only signals that are ignored are changed
//! (no handler installed through the C library is ever touched).

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

/// What a failed exec puts back.
struct Undo {
    /// (target, saved copy of what was there and its FD_CLOEXEC flag, or None if it was closed)
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
                    // SAFETY: `target` is a number this exec replaced (allowed by the rules in the module
                    // documentation); putting the saved description back restores what its owner had.
                    let _ = unsafe { syscall3(nr::DUP2, s.as_raw() as usize, target as usize, 0) };
                    // SAFETY: F_SETFD with an integer on the number just restored.
                    let _ = unsafe { syscall3(nr::FCNTL, target as usize, F_SETFD, flags) };
                }
                None => {
                    // SAFETY: `target` was not open before; the descriptor there now is the one this exec put there.
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

/// Run `plan`'s steps in the calling process and execve the program. Returns only on failure: the failing step and
/// its errno, after undoing what can be undone (see the module documentation). `(Stage::Prepare, EBUSY)`: a descriptor
/// target of 3 or more in a process with other threads (nothing changed).
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
        // save what is at `dst` (EBADF: nothing)
        // SAFETY: F_DUPFD_CLOEXEC makes a new descriptor and changes nothing at `dst`; `dst` is 0..=2 or the process is
        // single-threaded (checked by the caller), so the number cannot be closed or reused meanwhile.
        let r = unsafe { syscall3(nr::FCNTL, dst as usize, F_DUPFD_CLOEXEC, min_fd as usize) };
        let saved = match cvt(r) {
            Ok(fd) => {
                // SAFETY: the kernel just created this descriptor for us.
                let copy = unsafe { OwnedRawFd::from_raw(fd as i32) };
                // SAFETY: F_GETFD reads the flags of `dst` (open, see above); nothing changes.
                let flags = cvt(unsafe { syscall3(nr::FCNTL, dst as usize, F_GETFD, 0) }).unwrap_or(0);
                Some((copy, flags))
            }
            Err(Errno::EBADF) => None,
            Err(e) => return Err((Stage::Fds, e)),
        };
        if src.as_raw() == dst {
            // dup2 onto itself would keep FD_CLOEXEC: clear it as the spawn child's dup2 of a copy does
            // SAFETY: F_SETFD 0 on a descriptor the caller lent us.
            if let Err(e) = cvt(unsafe { syscall3(nr::FCNTL, dst as usize, F_SETFD, 0) }) {
                return Err((Stage::Fds, e));
            }
            continue;
        }
        undo.fds.push((dst, saved));
        // SAFETY: `src` is borrowed for the call; `dst` may be replaced under the rules in the module documentation
        // (0..=2, or a single-threaded process), and what was there is saved above for the undo.
        if let Err(e) = cvt(unsafe { syscall3(nr::DUP2, src.as_raw() as usize, dst as usize, 0) }) {
            return Err((Stage::Fds, e));
        }
    }
    if let Some(dir) = plan.cwd {
        // SAFETY: the kernel reads the NUL-terminated name "."; the result is a new descriptor we own.
        let r = unsafe { syscall6(nr::OPENAT, AT_FDCWD as usize, c".".as_ptr() as usize, O_PATH_DIR_CLOEXEC, 0, 0, 0) };
        // SAFETY: a descriptor the kernel just created.
        undo.cwd = cvt(r).ok().map(|fd| unsafe { OwnedRawFd::from_raw(fd as i32) });
        // SAFETY: the kernel reads the NUL-terminated directory name.
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
        // SAFETY: TIOCSCTTY takes an integer; `fd` is a descriptor of the caller's table the caller named (the
        // controlling terminal is process state, no memory is involved).
        cvt(unsafe { syscall3(nr::IOCTL, fd as usize, TIOCSCTTY, steal as usize) }).map_err(|e| (Stage::ControllingTerminal, e))?;
    }
    if let Some((fd, required)) = plan.foreground {
        // SAFETY: TIOCSPGRP on a descriptor of the caller's table, reading a local pid.
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
