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

#[derive(Debug)]
pub enum Stdio<'a> {
    Inherit,
    Null,
    Fd(BorrowedFd<'a>),
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

#[derive(Debug)]
pub struct SpawnError {
    pub stage: Stage,
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

pub const EXIT_CANCELED: i32 = 125;
pub const EXIT_CANNOT_INVOKE: i32 = 126;
pub const EXIT_ENOENT: i32 = 127;

impl SpawnError {
    pub fn exit_code(&self) -> i32 {
        exit_code_for(self.stage, &self.error)
    }
}

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

    pub fn shell_fallback(&mut self, on: bool) -> &mut Self {
        self.shell_fallback = on;
        self
    }

    pub fn arg0(&mut self, arg0: impl AsRef<OsStr>) -> &mut Self {
        self.argv0 = Some(arg0.as_ref().to_owned());
        self
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(key.as_ref().to_owned(), Some(val.as_ref().to_owned()));
        self
    }

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

    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(key.as_ref().to_owned(), None);
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.env_clear = true;
        self.env.retain(|_, v| v.is_some());
        self
    }

    pub fn current_dir(&mut self, dir: impl AsRef<std::path::Path>) -> &mut Self {
        self.cwd = Some(dir.as_ref().as_os_str().to_owned());
        self
    }

    pub fn stdin(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[0] = s.into();
        self
    }

    pub fn stdout(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[1] = s.into();
        self
    }

    pub fn stderr(&mut self, s: impl Into<Stdio<'a>>) -> &mut Self {
        self.stdio[2] = s.into();
        self
    }

    pub fn fd(&mut self, child_fd: RawFd, src: impl Into<Stdio<'a>>) -> &mut Self {
        self.fds.retain(|(n, _)| *n != child_fd);
        self.fds.push((child_fd, src.into()));
        self
    }

    pub fn setsid(&mut self, on: bool) -> &mut Self {
        self.setsid = on;
        self
    }

    pub fn process_group(&mut self, pgid: Option<Pid>) -> &mut Self {
        self.pgroup = Some(pgid.map_or(0, |p| p.as_raw_nonzero().get()));
        self
    }

    pub fn controlling_terminal(&mut self, child_fd: RawFd, steal: bool) -> &mut Self {
        self.ctty = Some((child_fd, steal));
        self
    }

    pub fn foreground(&mut self, child_fd: RawFd, required: bool) -> &mut Self {
        self.foreground = Some((child_fd, required));
        self
    }

    pub fn reset_signal(&mut self, sig: impl Into<SigNum>) -> &mut Self {
        self.sig_default = self.sig_default.with(sig);
        self
    }

    pub fn keep_signal(&mut self, sig: impl Into<SigNum>) -> &mut Self {
        self.sig_default = self.sig_default.without(sig);
        self
    }

    pub fn signal_mask(&mut self, mask: SigSet) -> &mut Self {
        self.sigmask = Some(mask);
        self
    }

    pub fn spawn(&mut self) -> io::Result<Child> {
        self.spawn_detailed().map_err(io::Error::from)
    }

    pub fn spawn_detailed(&mut self) -> Result<Child, SpawnError> {
        let result = self.with_plan(false, raw::spawn)?;
        match result {
            Ok(c) => {
                let pidfd = c.pidfd.map(OwnedFd::from);
                let pid = Pid::from_raw(c.pid).ok_or_else(|| SpawnError { stage: Stage::Clone, error: io::Error::other("clone returned no pid") })?;
                Ok(Child { pid, pidfd, status: None })
            }
            Err((stage, e)) => Err(SpawnError { stage, error: e.into() }),
        }
    }

    pub fn exec(&mut self) -> io::Error {
        self.exec_detailed().into()
    }

    pub fn exec_detailed(&mut self) -> SpawnError {
        match self.with_plan(true, rusty_libc_rs_core::exec::exec_in_place) {
            Ok((stage, e)) => SpawnError { stage, error: e.into() },
            Err(e) => e,
        }
    }

    fn with_plan<R>(&mut self, raw_env: bool, f: impl FnOnce(&SpawnPlan<'_>) -> R) -> Result<R, SpawnError> {
        if self.setsid && matches!(self.pgroup, Some(p) if p != 0) {
            return Err(prep_err("setsid with process_group other than None (a session leader cannot change its group)"));
        }
        if (1..=64).filter_map(SigNum::new).any(|s| s.is_fixed() && self.sig_default.contains(s)) {
            return Err(prep_err("reset_signal: signal that cannot be reset"));
        }
        if self.fds.iter().any(|(n, _)| *n < 0) || matches!(self.ctty, Some((n, _)) if n < 0) || matches!(self.foreground, Some((n, _)) if n < 0) {
            return Err(prep_err("negative descriptor number"));
        }

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
            return Err(prep_err("argument vector"));
        };
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

    fn search_path(&self, child_env: &[(OsString, OsString)]) -> Vec<u8> {
        let from_child = if self.env_clear || !self.env.is_empty() { child_env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.clone()) } else { None };
        from_child.or_else(|| std::env::var_os("PATH")).or_else(|| crate::confstr::confstr_os(crate::confstr::CS_PATH)).unwrap_or_default().into_vec()
    }
}

fn cstring(s: &OsStr) -> Result<CString, SpawnError> {
    CString::new(s.as_bytes()).map_err(|_| prep_err("NUL byte in the program, an argument or the directory"))
}


static FORCE_LEGACY_CLONE: AtomicBool = AtomicBool::new(false);

pub fn set_force_legacy_clone(on: bool) {
    FORCE_LEGACY_CLONE.store(on, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct Child {
    pid: Pid,
    pidfd: Option<OwnedFd>,
    status: Option<ExitStatus>,
}

impl Child {
    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn id(&self) -> u32 {
        self.pid.as_raw_nonzero().get() as u32
    }

    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(|f| f.as_fd())
    }

    pub fn take_pidfd(&mut self) -> Option<OwnedFd> {
        self.pidfd.take()
    }

    pub fn wait_id(&self) -> WaitId<'_> {
        match &self.pidfd {
            Some(f) => WaitId::PidFd(f.as_fd()),
            None => WaitId::Pid(self.pid),
        }
    }

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
