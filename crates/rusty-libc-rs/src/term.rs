//! The controlling terminal (TIOCSCTTY) with the `steal` argument. rustix's `process::ioctl_tiocsctty` is the same call
//! without `steal` (it always passes 0) and its generic ioctl is `unsafe`, so this one stays on rusty-libc-rs-core's
//! `term` module. Everything else of terminal job control is rustix's (`rusty_libc_rs::termios::{tcgetpgrp, tcsetpgrp,
//! tcgetsid, tcgetattr, tcsetattr, ttyname, isatty}`).
//!
//! A process in a background process group that calls `tcsetpgrp` on its controlling terminal gets SIGTTOU unless it
//! blocks or ignores that signal (POSIX tcsetpgrp, SUSv5 2024; GNU C Library manual ch. 29 "Job Control", p. 847: the shell
//! takes the terminal back with tcsetpgrp after the job stops or ends). A shell therefore ignores SIGTTOU
//! (`signal::set_signal(Signal::TTOU, Action::Ignore)`) before taking the terminal back.

use rustix::fd::AsFd;
use rustix::io;

/// ioctl(fd, TIOCSCTTY, steal): make the terminal `fd` the controlling terminal of the caller's session. The caller must
/// be a session leader without a controlling terminal (TLPI 34.4, p. 707). `steal`: take the terminal even when it is
/// another session's controlling terminal (needs CAP_SYS_ADMIN); without it that case fails with EPERM.
pub fn set_controlling_terminal<Fd: AsFd>(fd: Fd, steal: bool) -> io::Result<()> {
    rusty_libc_rs_core::term::set_controlling_terminal(fd.as_fd().into(), steal).map_err(crate::errno)
}
