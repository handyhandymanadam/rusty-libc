//! A process builder that needs no `pre_exec`: new session, process group, controlling terminal, terminal foreground,
//! signal dispositions and mask, descriptor mappings, argv[0], environment and working directory are all done by this
//! crate's own child code, so the caller writes no unsafe.
//!
//! How the child is made (the method of glibc's `posix_spawn` and of rusty-libc's `core::spawn`, sharing its PATH search
//! and clone trampoline: rusty-libc-rs-core's `spawn` module, which holds the child code and all of its `unsafe`): this
//! layer prepares everything that allocates (C strings, argument and environment vectors, the PATH value, descriptor
//! copies above every target number); rusty-libc-rs-core then blocks all signals and creates the
//! child with clone3(CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND | CLONE_PIDFD) on a separate small stack (plain
//! clone(CLONE_VM | CLONE_VFORK) when clone3 is refused). The child shares the parent's memory while the parent's thread
//! is suspended (vfork semantics), so it runs only raw system calls: no allocation, no locks, no C library call, no
//! thread-local data, no unwinding; it never returns from the function that cloned it (it ends in execve or exit_group)
//! (Kerrisk, TLPI 24.3 p. 523: the vfork child must not modify the parent's data or return from the calling function;
//! only descriptor operations are harmless, since the descriptor table is copied). Signals stay blocked in the child
//! until its handlers are reset (otherwise a parent handler could run on the child's stack in shared memory). A failure
//! in the child (chdir, exec, ...) is written into the parent's memory before the child exits with status 127, and
//! comes back from `spawn` as an `io::Error` with the child's errno (no close-on-exec pipe is needed: with CLONE_VFORK
//! the parent resumes only after the exec or the exit, as in glibc).
//!
//! Job control order in the child (GNU C Library manual ch. 29.6.3, p. 844): descriptors, chdir, setsid, setpgid,
//! TIOCSCTTY, tcsetpgrp, signal defaults, signal mask, exec. The tcsetpgrp happens with all signals blocked, so it never
//! raises SIGTTOU (POSIX tcsetpgrp: a blocked SIGTTOU lets the call proceed), as bash's child blocks it around
//! `give_terminal_to`. With CLONE_VFORK the parent resumes only after the child's exec, so the parent's own setpgid that
//! the manual recommends against the fork race is not needed (the child's has already happened).

use crate::signal::{SigNum, SigSet};
use crate::wait::waitid;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use rusty_libc_rs_core::spawn::{self as raw, CVec, SpawnPlan, shell_argv_len};
use rusty_libc_rs_core::BorrowedRawFd;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString, c_char};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};

/// Where a child's standard stream or mapped descriptor comes from.
#[derive(Debug)]
pub enum Stdio<'a> {
    /// The child keeps the parent's descriptor of that number (as it is at spawn time).
    Inherit,
    /// /dev/null, opened read-write.
    Null,
    /// A descriptor the caller lends for the spawn (the child gets its own copy).
    Fd(BorrowedFd<'a>),
    /// A descriptor the builder keeps (closed in the parent when the `Command` is dropped).
    Owned(OwnedFd),
}

impl From<OwnedFd> for Stdio<'_> {
    fn from(fd: OwnedFd) -> Self {
        Stdio::Owned(fd)
    }
}

impl From<File> for Stdio<'_> {
    fn from(f: File) -> Self {
        Stdio::Owned(f.into())
    }
}

impl From<io::PipeReader> for Stdio<'_> {
    fn from(p: io::PipeReader) -> Self {
        Stdio::Owned(p.into())
    }
}

impl From<io::PipeWriter> for Stdio<'_> {
    fn from(p: io::PipeWriter) -> Self {
        Stdio::Owned(p.into())
    }
}

impl<'a> From<BorrowedFd<'a>> for Stdio<'a> {
    fn from(fd: BorrowedFd<'a>) -> Self {
        Stdio::Fd(fd)
    }
}

pub use rusty_libc_rs_core::spawn::Stage;

/// A failed spawn: the step and the error (the child's errno for child-side steps).
#[derive(Debug)]
pub struct SpawnError {
    /// Which step failed.
    pub stage: Stage,
    /// The error, with the system's errno where there is one (`raw_os_error`).
    pub error: io::Error,
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spawn failed at {:?}: {}", self.stage, self.error)
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// coreutils' exit status when its child program could not be started (env, nice, nohup, timeout, chroot, stdbuf):
/// the utility itself failed before the exec (bad option, chdir failed, ...).
pub const EXIT_CANCELED: i32 = 125;
/// The program was found but could not be run (EACCES, ENOEXEC, ...).
pub const EXIT_CANNOT_INVOKE: i32 = 126;
/// The program was not found (ENOENT).
pub const EXIT_ENOENT: i32 = 127;

impl SpawnError {
    /// The exit status coreutils uses for this failure: [`EXIT_ENOENT`] (127) when the exec step failed with ENOENT,
    /// [`EXIT_CANNOT_INVOKE`] (126) for any other exec failure, [`EXIT_CANCELED`] (125) when an earlier step failed
    /// (descriptors, chdir, session, signals, preparing the arguments).
    pub fn exit_code(&self) -> i32 {
        exit_code_for(self.stage, &self.error)
    }
}

/// coreutils' 125/126/127 convention for an exec failure at `stage` with `error` (see [`SpawnError::exit_code`]).
pub fn exit_code_for(stage: Stage, error: &io::Error) -> i32 {
    match stage {
        Stage::Exec if error.raw_os_error() == Some(2) => EXIT_ENOENT,
        Stage::Exec => EXIT_CANNOT_INVOKE,
        _ => EXIT_CANCELED,
    }
}

impl From<SpawnError> for io::Error {
    fn from(e: SpawnError) -> io::Error {
        e.error
    }
}

fn prep_err(msg: &'static str) -> SpawnError {
    SpawnError { stage: Stage::Prepare, error: io::Error::new(io::ErrorKind::InvalidInput, msg) }
}

fn prep_io(e: io::Error) -> SpawnError {
    SpawnError { stage: Stage::Prepare, error: e }
}

/// A process to start. Built like `std::process::Command`; `spawn` takes `&mut self`, so one builder can start several
/// children.
#[derive(Debug)]
pub struct Command<'a> {
    program: OsString,
    argv0: Option<OsString>,
    args: Vec<OsString>,
    env_clear: bool,
    env: BTreeMap<OsString, Option<OsString>>,
    cwd: Option<OsString>,
    stdio: [Stdio<'a>; 3],
    fds: Vec<(RawFd, Stdio<'a>)>,
    setsid: bool,
    pgroup: Option<i32>,
    ctty: Option<(RawFd, bool)>,
    foreground: Option<(RawFd, bool)>,
    sig_default: SigSet,
    sigmask: Option<SigSet>,
    shell_fallback: bool,
}

impl<'a> Command<'a> {
    /// A builder for `program`: a path (with a '/') is run as it is; a bare name is searched in PATH (the child's
    /// PATH when the builder sets or clears the environment and gives one, else the parent's, else confstr(_CS_PATH),
    /// "/usr/bin", which Fedora's glibc 2.43 execvp and posix_spawnp both use; upstream glibc's is "/bin:/usr/bin"),
    /// with execvp's rules (EACCES remembered, ENOENT/ENOTDIR/... go on to the next directory, other errors stop). A file
    /// the kernel cannot run (ENOEXEC: no `#!` line, no ELF header) is run with /bin/sh as glibc's execvp does
    /// (`/bin/sh FILE ARGS...`, argv[0] dropped); [`shell_fallback(false)`](Command::shell_fallback) turns that off
    /// (posix_spawnp's behaviour: the spawn fails with ENOEXEC).
    ///
    /// Defaults (as `std::process::Command`): argv[0] is `program`, the environment, working directory and descriptors
    /// are inherited, the signal mask is the parent thread's, signal handlers become SIG_DFL (ignored signals stay
    /// ignored, as across exec), and SIGPIPE is reset to SIG_DFL (Rust programs ignore it; `keep_signal(SIGPIPE)` keeps
    /// it ignored).
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Command {
            program: program.as_ref().to_owned(),
            argv0: None,
            args: Vec::new(),
            env_clear: false,
            env: BTreeMap::new(),
            cwd: None,
            stdio: [Stdio::Inherit, Stdio::Inherit, Stdio::Inherit],
            fds: Vec::new(),
            setsid: false,
            pgroup: None,
            ctty: None,
            foreground: None,
            sig_default: SigSet::empty().with(Signal::PIPE),
            sigmask: None,
            shell_fallback: true,
        }
    }

    /// Run a file the kernel refuses with ENOEXEC (a script without `#!`) with /bin/sh, as execvp(3) does (default
    /// true). `false` gives posix_spawnp's behaviour: the spawn or exec fails with ENOEXEC (a shell that runs such files
    /// itself, as bash does, wants that).
    pub fn shell_fallback(&mut self, on: bool) -> &mut Self {
        self.shell_fallback = on;
        self
    }

    /// Set argv[0] (default: the program as given).
    pub fn arg0(&mut self, arg0: impl AsRef<OsStr>) -> &mut Self {
        self.argv0 = Some(arg0.as_ref().to_owned());
        self
    }

    /// Add one argument.
    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Add arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Set an environment variable for the child.
    pub fn env(&mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(key.as_ref().to_owned(), Some(val.as_ref().to_owned()));
        self
    }

    /// Set several environment variables.
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (k, v) in vars {
            self.env(k, v);
        }
        self
    }

    /// Remove an environment variable from the child's environment.
    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(key.as_ref().to_owned(), None);
        self
    }

    /// Start the child with an empty environment (plus what `env` adds afterwards or added before).
    pub fn env_clear(&mut self) -> &mut Self {
        self.env_clear = true;
        self.env.retain(|_, v| v.is_some());
        self
    }

    /// The child's working directory (relative to the parent's; a relative program path is then relative to it).
    pub fn current_dir(&mut self, dir: impl AsRef<std::path::Path>) -> &mut Self {
        self.cwd = Some(dir.as_ref().as_os_str().to_owned());
        self
    }

    /// The child's standard input.
    pub fn stdin(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[0] = s.into();
        self
    }

    /// The child's standard output.
    pub fn stdout(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[1] = s.into();
        self
    }

    /// The child's standard error.
    pub fn stderr(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[2] = s.into();
        self
    }

    /// Give the child descriptor number `child_fd` from `src` (any number, also 0-2, where it overrides
    /// stdin/stdout/stderr; a later mapping of the same number replaces an earlier one). Collisions between source and
    /// target numbers are handled (the sources are first copied above every target number). Descriptors the parent has
    /// without FD_CLOEXEC are inherited as usual; mapped ones are made inheritable in the child only.
    pub fn fd(&mut self, child_fd: RawFd, src: impl Into<Stdio<'a>>) -> &mut Self {
        self.fds.retain(|(n, _)| *n != child_fd);
        self.fds.push((child_fd, src.into()));
        self
    }

    /// Make the child the leader of a new session (setsid; it then also leads a new process group).
    pub fn setsid(&mut self, on: bool) -> &mut Self {
        self.setsid = on;
        self
    }

    /// setpgid(0, pgid) in the child: `None` makes a new process group led by the child (setpgid(0, 0)), `Some(pgid)`
    /// joins that group (of the same session). With `setsid`, only `None` is allowed (a session leader already leads its
    /// own group).
    pub fn process_group(&mut self, pgid: Option<Pid>) -> &mut Self {
        self.pgroup = Some(pgid.map_or(0, |p| p.as_raw_nonzero().get()));
        self
    }

    /// ioctl(child_fd, TIOCSCTTY, steal) in the child, after `setsid` and the descriptor mappings: make the terminal on the
    /// child's descriptor `child_fd` its controlling terminal (needs `setsid(true)`).
    pub fn controlling_terminal(&mut self, child_fd: RawFd, steal: bool) -> &mut Self {
        self.ctty = Some((child_fd, steal));
        self
    }

    /// tcsetpgrp(child_fd, the child's process group) in the child, after setsid/setpgid/TIOCSCTTY: the new group takes
    /// the terminal's foreground (done with all signals blocked, so no SIGTTOU). `required` false ignores a failure (not a
    /// terminal, not the controlling terminal), which is what a shell does when stdin is not its terminal.
    pub fn foreground(&mut self, child_fd: RawFd, required: bool) -> &mut Self {
        self.foreground = Some((child_fd, required));
        self
    }

    /// Reset signal `sig` to SIG_DFL in the child (e.g. the SIGTTOU/SIGTSTP/SIGINT a shell ignores itself; a rustix
    /// `Signal` or a `SigNum`). SIGKILL, SIGSTOP and glibc's internal 32/33 are refused at spawn time (InvalidInput).
    pub fn reset_signal(&mut self, sig: impl Into<SigNum>) -> &mut Self {
        self.sig_default = self.sig_default.with(sig);
        self
    }

    /// Do not reset `sig` (only meaningful for the SIGPIPE default).
    pub fn keep_signal(&mut self, sig: impl Into<SigNum>) -> &mut Self {
        self.sig_default = self.sig_default.without(sig);
        self
    }

    /// The child's signal mask (default: the parent thread's mask at spawn time). glibc's internal 32/33 are left out.
    pub fn signal_mask(&mut self, mask: SigSet) -> &mut Self {
        self.sigmask = Some(mask);
        self
    }

    /// Start the child; the error is the failing step's `io::Error` (see `spawn_detailed` for the step).
    pub fn spawn(&mut self) -> io::Result<Child> {
        self.spawn_detailed().map_err(io::Error::from)
    }

    /// Start the child; a failure says which step failed.
    pub fn spawn_detailed(&mut self) -> Result<Child, SpawnError> {
        let result = self.with_plan(false, raw::spawn)?;
        match result {
            Ok(c) => {
                let pidfd = c.pidfd.map(OwnedFd::from);
                // a started child has a pid > 0 (clone returned it)
                let pid = Pid::from_raw(c.pid).ok_or_else(|| SpawnError { stage: Stage::Clone, error: io::Error::other("clone returned no pid") })?;
                Ok(Child { pid, pidfd, status: None })
            }
            Err((stage, e)) => Err(SpawnError { stage, error: e.into() }),
        }
    }

    /// Replace the calling process with the program (exec without fork), after the same steps a spawned child takes:
    /// descriptor mappings, working directory, session, process group, controlling terminal, foreground, signal
    /// defaults (SIGPIPE back to SIG_DFL unless kept), signal mask, argv[0], environment, PATH search. Returns only on
    /// failure, with the failing step's error (see [`Command::exec_detailed`] for the step and the 125/126/127 exit
    /// convention).
    ///
    /// Differences from `spawn`, all because the calling process itself changes:
    /// - Descriptor mappings to numbers 0..=2 always work (as std's `CommandExt::exec`); a mapping to a number of 3 or
    ///   more needs a single-threaded process (another thread could own that number): EBUSY otherwise, before any
    ///   change.
    /// - If a step or the exec fails, the descriptors, the working directory, the signals changed from "ignore" to
    ///   "default" and the mask are put back; setsid, setpgid, the controlling terminal and the foreground group are
    ///   not (no undo exists). Programs normally exit right after a failed exec.
    /// - With no environment changes the program gets the C library's `environ` exactly (entries std's `vars_os`
    ///   skips included), as execvp would give it.
    /// - A file without a `#!` line and ELF header (ENOEXEC) runs with /bin/sh, as with `spawn` and glibc's execvp
    ///   (off with [`shell_fallback(false)`](Command::shell_fallback)).
    /// - Unwritten data in Rust's stdout buffer is lost (as with any exec): flush first.
    pub fn exec(&mut self) -> io::Error {
        self.exec_detailed().into()
    }

    /// [`Command::exec`] with the failing step; [`SpawnError::exit_code`] maps it to coreutils' convention.
    pub fn exec_detailed(&mut self) -> SpawnError {
        match self.with_plan(true, rusty_libc_rs_core::exec::exec_in_place) {
            Ok((stage, e)) => SpawnError { stage, error: e.into() },
            Err(e) => e,
        }
    }

    /// Prepare everything that allocates and run `f` on the finished plan. `raw_env`: with no environment changes,
    /// pass the C library's environ as it is (exec) instead of std's view of it (spawn).
    fn with_plan<R>(&mut self, raw_env: bool, f: impl FnOnce(&SpawnPlan<'_>) -> R) -> Result<R, SpawnError> {
        // ---- checks
        if self.setsid && matches!(self.pgroup, Some(p) if p != 0) {
            return Err(prep_err("setsid with process_group other than None (a session leader cannot change its group)"));
        }
        if (1..=64).filter_map(SigNum::new).any(|s| s.is_fixed() && self.sig_default.contains(s)) {
            return Err(prep_err("reset_signal: signal that cannot be reset"));
        }
        if self.fds.iter().any(|(n, _)| *n < 0) || matches!(self.ctty, Some((n, _)) if n < 0) || matches!(self.foreground, Some((n, _)) if n < 0) {
            return Err(prep_err("negative descriptor number"));
        }

        // ---- strings and vectors (allocations happen here, in the parent)
        let argv0 = self.argv0.as_ref().unwrap_or(&self.program);
        let mut argv_c: Vec<CString> = Vec::with_capacity(self.args.len() + 1);
        argv_c.push(cstring(argv0)?);
        for a in &self.args {
            argv_c.push(cstring(a)?);
        }

        let env_list: Vec<(OsString, OsString)> = if !self.env_clear && self.env.is_empty() {
            std::env::vars_os().collect()
        } else {
            let mut map: BTreeMap<OsString, OsString> = if self.env_clear { BTreeMap::new() } else { std::env::vars_os().collect() };
            for (k, v) in &self.env {
                match v {
                    Some(v) => {
                        map.insert(k.clone(), v.clone());
                    }
                    None => {
                        map.remove(k);
                    }
                }
            }
            map.into_iter().collect()
        };
        let mut env_c = Vec::with_capacity(env_list.len());
        let unchanged = !self.env_clear && self.env.is_empty();
        if raw_env && unchanged {
            for e in crate::env::vars_raw() {
                env_c.push(CString::new(e.into_vec()).map_err(|_| prep_err("NUL byte in an environment variable"))?);
            }
        }
        for (k, v) in env_list.iter().filter(|_| !(raw_env && unchanged)) {
            if k.as_bytes().contains(&b'=') || k.is_empty() {
                return Err(prep_err("environment variable name empty or containing '='"));
            }
            let mut kv = Vec::with_capacity(k.len() + v.len() + 1);
            kv.extend_from_slice(k.as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(v.as_bytes());
            env_c.push(CString::new(kv).map_err(|_| prep_err("NUL byte in an environment variable"))?);
        }

        let program = cstring(&self.program)?;
        let path = self.search_path(&env_list);
        let cwd = match &self.cwd {
            Some(d) => Some(cstring(d)?),
            None => None,
        };

        // ---- descriptors: every source copied (FD_CLOEXEC) above every target number, so the child's dup2 calls can
        // run in any order without one overwriting another's source.
        let mut targets: Vec<(RawFd, &Stdio<'a>)> = Vec::new();
        for (i, s) in self.stdio.iter().enumerate() {
            targets.push((i as RawFd, s));
        }
        for (n, s) in &self.fds {
            targets.retain(|(t, _)| t != n);
            targets.push((*n, s));
        }
        targets.retain(|(_, s)| !matches!(s, Stdio::Inherit));
        let min_fd = targets.iter().map(|(t, _)| *t).max().unwrap_or(2).max(2).checked_add(1).ok_or_else(|| prep_err("descriptor number too large"))?;
        let mut held: Vec<OwnedFd> = Vec::with_capacity(targets.len());
        let mut fd_targets: Vec<RawFd> = Vec::with_capacity(targets.len());
        let mut null: Option<File> = None;
        for (t, s) in &targets {
            let copy = match s {
                Stdio::Inherit => continue,
                Stdio::Null => {
                    if null.is_none() {
                        null = Some(std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").map_err(prep_io)?);
                    }
                    let Some(f) = null.as_ref() else { continue };
                    rustix::io::fcntl_dupfd_cloexec(f, min_fd)
                }
                Stdio::Fd(b) => rustix::io::fcntl_dupfd_cloexec(b, min_fd),
                Stdio::Owned(o) => rustix::io::fcntl_dupfd_cloexec(o, min_fd),
            }
            .map_err(|e| prep_io(e.into()))?;
            fd_targets.push(*t);
            held.push(copy);
        }

        let fds: Vec<(BorrowedRawFd<'_>, RawFd)> = held.iter().zip(&fd_targets).map(|(h, &t)| (BorrowedRawFd::from(h.as_fd()), t)).collect();
        let mut argv_buf = vec![std::ptr::null::<c_char>(); argv_c.len() + 1];
        let mut envp_buf = vec![std::ptr::null::<c_char>(); env_c.len() + 1];
        let (Some(argv), Some(envp)) = (CVec::new(&argv_c, &mut argv_buf), CVec::new(&env_c, &mut envp_buf)) else {
            return Err(prep_err("argument vector")); // not reached: the buffers are one longer than the lists
        };
        // room for the /bin/sh argv of the ENOEXEC fallback, written by the child (or by exec in this process)
        let shell_buf: Vec<Cell<*const c_char>> = if self.shell_fallback { vec![Cell::new(std::ptr::null()); shell_argv_len(argv_c.len())] } else { Vec::new() };
        let plan = SpawnPlan {
            program: &program,
            path: &path,
            argv,
            envp,
            shell: self.shell_fallback.then_some(&shell_buf[..]),
            fds: &fds,
            cwd: cwd.as_deref(),
            setsid: self.setsid,
            pgroup: self.pgroup,
            ctty: self.ctty,
            foreground: self.foreground,
            sig_default: self.sig_default.into(),
            mask: self.sigmask.map(Into::into),
            legacy_clone: FORCE_LEGACY_CLONE.load(Ordering::Relaxed),
        };
        let result = f(&plan);
        drop(fds);
        drop(held);
        Ok(result)
    }

    /// The directory list a bare program name is searched in: the child's PATH when the builder sets or clears the
    /// environment and gives one, else the parent's, else confstr(_CS_PATH) as glibc's execvp and posix_spawnp (both use
    /// CS_PATH; it is "/usr/bin" in Fedora's glibc 2.43, the C face's value too).
    fn search_path(&self, child_env: &[(OsString, OsString)]) -> Vec<u8> {
        let from_child = if self.env_clear || !self.env.is_empty() { child_env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.clone()) } else { None };
        from_child.or_else(|| std::env::var_os("PATH")).or_else(|| crate::confstr::confstr_os(crate::confstr::CS_PATH)).unwrap_or_default().into_vec()
    }
}

fn cstring(s: &OsStr) -> Result<CString, SpawnError> {
    CString::new(s.as_bytes()).map_err(|_| prep_err("NUL byte in the program, an argument or the directory"))
}


/// Test hook: treat clone3 as unavailable, so the plain clone fallback runs.
static FORCE_LEGACY_CLONE: AtomicBool = AtomicBool::new(false);

/// Test hook (not part of the API): force the plain clone(2) fallback instead of clone3.
#[doc(hidden)]
pub fn set_force_legacy_clone(on: bool) {
    FORCE_LEGACY_CLONE.store(on, Ordering::Relaxed);
}

// ------------------------------------------------------------------------------------------------ Child

/// A started child process. Dropping it neither waits nor kills (as `std::process::Child`).
#[derive(Debug)]
pub struct Child {
    pid: Pid,
    pidfd: Option<OwnedFd>,
    status: Option<ExitStatus>,
}

impl Child {
    /// The child's process id.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// The child's process id as `u32` (as `std::process::Child::id`).
    pub fn id(&self) -> u32 {
        self.pid.as_raw_nonzero().get() as u32
    }

    /// The child's pidfd (made by clone3; `None` after the plain clone fallback or `take_pidfd`). It becomes readable
    /// when the child ends, so an async runtime can wait on it (e.g. tokio's `AsyncFd`) and then call `try_wait`.
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(|f| f.as_fd())
    }

    /// Take the pidfd out (the `Child` then waits and signals by pid).
    pub fn take_pidfd(&mut self) -> Option<OwnedFd> {
        self.pidfd.take()
    }

    /// The `WaitId` that selects this child for `process::waitid` (its pidfd when there is one).
    pub fn wait_id(&self) -> WaitId<'_> {
        match &self.pidfd {
            Some(f) => WaitId::PidFd(f.as_fd()),
            None => WaitId::Pid(self.pid),
        }
    }

    /// Wait for the child to end and reap it (EINTR is retried). A later call returns the same status.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(s) = self.status {
            return Ok(s);
        }
        loop {
            match waitid(self.wait_id(), WaitIdOptions::EXITED) {
                Ok(Some(info)) => {
                    let s = info.exit_status();
                    self.status = Some(s);
                    return Ok(s);
                }
                Ok(None) => continue,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Reap the child if it has ended (`None` while it runs).
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        match waitid(self.wait_id(), WaitIdOptions::EXITED | WaitIdOptions::NOHANG)? {
            Some(info) => {
                let s = info.exit_status();
                self.status = Some(s);
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    /// Send signal `sig` (a rustix `Signal` or a `SigNum`, real-time signals included) to the child (pidfd_send_signal
    /// when there is a pidfd: never reaches a recycled pid; else kill(pid)). Refused once the child has been reaped
    /// through this `Child`, and for glibc's internal 32/33 (EINVAL).
    pub fn send_signal(&self, sig: impl Into<SigNum>) -> io::Result<()> {
        let sig = sig.into();
        if self.status.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "child already reaped"));
        }
        if matches!(sig.as_raw(), 32 | 33) {
            return Err(io::Error::from(rustix::io::Errno::INVAL));
        }
        match &self.pidfd {
            Some(f) => Ok(raw::pidfd_send_signal(f.as_fd().into(), sig.as_raw())?),
            None => Ok(rusty_libc_rs_core::process::kill(self.pid.as_raw_nonzero().get(), sig.as_raw())?),
        }
    }
}
