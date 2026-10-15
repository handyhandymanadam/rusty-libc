use crate::errno::{Errno, cvt};
use crate::fd::{BorrowedRawFd, OwnedRawFd};
use crate::process::{self, Pid};
use crate::signal::{self, Action, INTERNAL, SigSet, bit};
use crate::syscall::{nr, syscall3, syscall6};
use crate::term::{TIOCSCTTY, TIOCSPGRP};
use crate::wait::{WaitFlags, WaitId};
use core::cell::Cell;
use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[derive(Clone, Copy, Debug)]
pub struct CVec<'a> {
    ptr: *const *const c_char,
    _strings: PhantomData<&'a CStr>,
}

impl<'a> CVec<'a> {
    pub fn new<T: AsRef<CStr>>(strings: &'a [T], buf: &'a mut [*const c_char]) -> Option<CVec<'a>> {
        if buf.len() <= strings.len() {
            return None;
        }
        for (slot, s) in buf.iter_mut().zip(strings) {
            *slot = s.as_ref().as_ptr();
        }
        buf[strings.len()] = core::ptr::null();
        Some(CVec { ptr: buf.as_ptr(), _strings: PhantomData })
    }

    #[inline]
    pub const unsafe fn from_raw(ptr: *const *const c_char) -> CVec<'a> {
        CVec { ptr, _strings: PhantomData }
    }

    #[inline]
    pub const fn as_ptr(self) -> *const *const c_char {
        self.ptr
    }

    pub fn len(self) -> usize {
        if self.ptr.is_null() {
            return 0;
        }
        let mut n = 0;
        while !unsafe { self.ptr.wrapping_add(n).read() }.is_null() {
            n += 1;
        }
        n
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    fn get(self, i: usize) -> *const c_char {
        unsafe { self.ptr.wrapping_add(i).read() }
    }
}

#[inline]
pub fn execve(path: &CStr, argv: CVec<'_>, envp: CVec<'_>) -> Errno {
    let r = unsafe { syscall3(nr::EXECVE, path.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize) };
    Errno::of(r).unwrap_or(Errno::ECHILD)
}

const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

#[inline]
pub fn exec_search(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>) -> Errno {
    search(file, path, argv, envp, None::<fn(&CStr) -> Errno>)
}

#[inline]
pub fn exec_search_script(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>, shell: &[Cell<*const c_char>]) -> Errno {
    search(file, path, argv, envp, Some(|script: &CStr| exec_shell(script, argv, envp, shell)))
}

#[inline]
pub fn exec_search_with(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>, on_noexec: impl FnMut(&CStr) -> Errno) -> Errno {
    search(file, path, argv, envp, Some(on_noexec))
}

pub const fn shell_argv_len(argc: usize) -> usize {
    if argc > 1 { argc + 2 } else { 3 }
}

pub fn exec_shell(script: &CStr, argv: CVec<'_>, envp: CVec<'_>, buf: &[Cell<*const c_char>]) -> Errno {
    let argc = argv.len();
    if argc >= i32::MAX as usize - 1 || buf.len() < shell_argv_len(argc) {
        return Errno::E2BIG;
    }
    buf[0].set(SHELL.as_ptr());
    buf[1].set(script.as_ptr());
    let mut n = 2;
    for i in 1..argc {
        buf[n].set(argv.get(i));
        n += 1;
    }
    buf[n].set(core::ptr::null());
    let new = unsafe { CVec::from_raw(buf.as_ptr() as *const *const c_char) };
    execve(SHELL, new, envp)
}

const SHELL: &CStr = c"/bin/sh";

#[inline(always)]
fn search<F: FnMut(&CStr) -> Errno>(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>, mut on_noexec: Option<F>) -> Errno {
    let f = file.to_bytes();
    if f.is_empty() {
        return Errno::ENOENT;
    }
    if f.contains(&b'/') {
        let e = execve(file, argv, envp);
        return match on_noexec.as_mut() {
            Some(run) if e == Errno::ENOEXEC => run(file),
            _ => e,
        };
    }
    let file_len = f.len().min(NAME_MAX) + 1;
    let path_len = path.len().min(PATH_MAX - 1) + 1;
    if f.len() > NAME_MAX || path_len + file_len + 1 > PATH_MAX + NAME_MAX + 3 {
        return Errno::ENAMETOOLONG;
    }
    let mut buffer = [0u8; PATH_MAX + NAME_MAX + 3];
    let mut got_eacces = false;
    let mut last = Errno::ENOENT;
    let mut pp = 0;
    loop {
        let subp = pp + path[pp..].iter().position(|&c| c == b':').unwrap_or(path.len() - pp);
        let seg = subp - pp;
        if seg >= path_len {
            if subp == path.len() {
                break;
            }
            pp = subp;
            continue;
        }
        buffer[..seg].copy_from_slice(&path[pp..subp]);
        buffer[seg] = b'/';
        let at = seg + (seg > 0) as usize;
        buffer[at..at + f.len()].copy_from_slice(f);
        buffer[at + f.len()] = 0;
        let r = unsafe { syscall3(nr::EXECVE, buffer.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize) };
        let mut e = Errno::of(r).unwrap_or(Errno::ECHILD);
        if e == Errno::ENOEXEC
            && let Some(run) = on_noexec.as_mut()
            && let Ok(candidate) = CStr::from_bytes_until_nul(&buffer)
        {
            e = run(candidate);
        }
        last = e;
        match e {
            Errno::EACCES => got_eacces = true,
            Errno::ENOENT | Errno::ESTALE | Errno::ENOTDIR | Errno::ENODEV | Errno::ETIMEDOUT => {}
            _ => return e,
        }
        if subp == path.len() {
            break;
        }
        pp = subp + 1;
    }
    if got_eacces { Errno::EACCES } else { last }
}

#[inline]
pub fn exit_group(status: i32) -> ! {
    plain!(nr::EXIT_GROUP, status);
    loop {
        plain!(nr::EXIT, status);
    }
}

#[inline]
pub unsafe fn child_tcsetpgrp(fd: i32, pgrp: Option<Pid>) -> Result<(), Errno> {
    let pg: i32 = match pgrp {
        Some(p) => p,
        None => plain!(nr::GETPGID, 0) as i32,
    };
    cvt(unsafe { syscall3(nr::IOCTL, fd as usize, TIOCSPGRP, &raw const pg as usize) }).map(drop)
}

macro_rules! child_plain {
    ($n:expr, $a:expr, $b:expr, $c:expr) => {{
        unsafe { syscall3($n, $a as usize, $b as usize, $c as usize) }
    }};
}

#[derive(Debug)]
pub struct Stack {
    base: usize,
    len: usize,
    guard: usize,
}

impl Stack {
    #[inline]
    pub fn new(size: usize, guard: usize) -> Result<Stack, Errno> {
        const MAP_PRIVATE_ANON_STACK: usize = 0x02 | 0x20 | 0x20000;
        const MAP_NORESERVE: usize = 0x4000;
        let len = size + guard;
        if guard == 0 {
            let base = cvt(unsafe { syscall6(nr::MMAP, 0, len, 3, MAP_PRIVATE_ANON_STACK, usize::MAX, 0) })?;
            return Ok(Stack { base, len, guard });
        }
        let base = cvt(unsafe { syscall6(nr::MMAP, 0, len, 0, MAP_PRIVATE_ANON_STACK | MAP_NORESERVE, usize::MAX, 0) })?;
        let stack = Stack { base, len, guard };
        cvt(unsafe { syscall6(nr::MPROTECT, base + guard, size, 3, 0, 0, 0) })?;
        Ok(stack)
    }

    pub const fn low(&self) -> usize {
        self.base + self.guard
    }

    pub const fn size(&self) -> usize {
        self.len - self.guard
    }

    pub const fn top(&self) -> usize {
        (self.base + self.len) & !15
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        unsafe { syscall6(nr::MUNMAP, self.base, self.len, 0, 0, 0, 0) };
    }
}

#[repr(C)]
#[derive(Default, Debug)]
#[allow(missing_docs)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

#[allow(missing_docs)]
pub mod flags {
    pub const CLONE_VM: u64 = 0x100;
    pub const CLONE_PIDFD: u64 = 0x1000;
    pub const CLONE_VFORK: u64 = 0x4000;
    pub const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
    pub const CLONE_INTO_CGROUP: u64 = 1 << 33;
    pub const SIGCHLD: u64 = 17;
}
use flags::*;

#[derive(Debug)]
pub enum CloneCall<'a> {
    Clone3(&'a CloneArgs),
    Clone {
        flags: u64,
        stack_top: usize,
    },
}

pub unsafe fn clone_vfork(call: CloneCall<'_>, entry: unsafe extern "C" fn(*mut c_void) -> !, arg: *mut c_void) -> isize {
    let f = entry as usize;
    let ret: isize;
    match call {
        CloneCall::Clone3(args) => {
            unsafe {
                core::arch::asm!(
                    "syscall",
                    "test rax, rax",
                    "jnz 2f",
                    "xor ebp, ebp",
                    "mov rdi, r12",
                    "call r9",
                    "ud2",
                    "2:",
                    inlateout("rax") nr::CLONE3 as isize => ret,
                    in("rdi") args as *const CloneArgs as usize,
                    in("rsi") core::mem::size_of::<CloneArgs>(),
                    in("r9") f,
                    in("r12") arg as usize,
                    lateout("rcx") _, lateout("r11") _,
                );
            }
        }
        CloneCall::Clone { flags, stack_top } => {
            unsafe {
                core::arch::asm!(
                    "syscall",
                    "test rax, rax",
                    "jnz 2f",
                    "xor ebp, ebp",
                    "mov rdi, r12",
                    "call r9",
                    "ud2",
                    "2:",
                    inlateout("rax") nr::CLONE as isize => ret,
                    in("rdi") flags as usize,
                    in("rsi") stack_top & !15,
                    in("rdx") 0usize,
                    in("r10") 0usize,
                    in("r8") 0usize,
                    in("r9") f,
                    in("r12") arg as usize,
                    lateout("rcx") _, lateout("r11") _,
                );
            }
        }
    }
    ret
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Prepare,
    Clone,
    Fds,
    Chdir,
    Setsid,
    Setpgid,
    ControllingTerminal,
    Foreground,
    Signals,
    Exec,
}

impl Stage {
    const ALL: [Stage; 10] = [Stage::Prepare, Stage::Clone, Stage::Fds, Stage::Chdir, Stage::Setsid, Stage::Setpgid, Stage::ControllingTerminal, Stage::Foreground, Stage::Signals, Stage::Exec];
}

#[derive(Debug)]
pub struct SpawnPlan<'a> {
    pub program: &'a CStr,
    pub path: &'a [u8],
    pub argv: CVec<'a>,
    pub envp: CVec<'a>,
    pub shell: Option<&'a [Cell<*const c_char>]>,
    pub fds: &'a [(BorrowedRawFd<'a>, i32)],
    pub cwd: Option<&'a CStr>,
    pub setsid: bool,
    pub pgroup: Option<Pid>,
    pub ctty: Option<(i32, bool)>,
    pub foreground: Option<(i32, bool)>,
    pub sig_default: SigSet,
    pub mask: Option<SigSet>,
    pub legacy_clone: bool,
}

impl SpawnPlan<'_> {
    pub fn exec(&self) -> Errno {
        match self.shell {
            Some(buf) => exec_search_script(self.program, self.path, self.argv, self.envp, buf),
            None => exec_search(self.program, self.path, self.argv, self.envp),
        }
    }
}

#[derive(Debug)]
pub struct Spawned {
    pub pid: Pid,
    pub pidfd: Option<OwnedRawFd>,
}

struct Shared<'p, 'a> {
    plan: &'p SpawnPlan<'a>,
    err: AtomicI32,
    stage: AtomicI32,
    use_clone3: AtomicBool,
    mask: u64,
}

fn child_run(s: &Shared<'_, '_>) -> (Stage, Errno) {
    let p = s.plan;
    if !s.use_clone3.load(Ordering::Relaxed) {
        for sig in 1..=64 {
            if sig != signal::sig::SIGKILL && sig != signal::sig::SIGSTOP {
                signal::clear_handler(sig);
            }
        }
    }
    for &(src, dst) in p.fds {
        if let Some(e) = Errno::of(child_plain!(nr::DUP2, src.as_raw(), dst, 0)) {
            return (Stage::Fds, e);
        }
    }
    if let Some(dir) = p.cwd {
        if let Some(e) = Errno::of(unsafe { syscall3(nr::CHDIR, dir.as_ptr() as usize, 0, 0) }) {
            return (Stage::Chdir, e);
        }
    }
    if p.setsid
        && let Err(e) = process::setsid()
    {
        return (Stage::Setsid, e);
    }
    if let Some(pg) = p.pgroup
        && !(p.setsid && pg == 0)
        && let Err(e) = process::setpgid(0, pg)
    {
        return (Stage::Setpgid, e);
    }
    if let Some((fd, steal)) = p.ctty
        && let Some(e) = Errno::of(child_plain!(nr::IOCTL, fd, TIOCSCTTY, steal as usize))
    {
        return (Stage::ControllingTerminal, e);
    }
    if let Some((fd, required)) = p.foreground
        && let Err(e) = unsafe { child_tcsetpgrp(fd, None) }
        && required
    {
        return (Stage::Foreground, e);
    }
    if p.sig_default.0 != 0 {
        for sig in 1..=64 {
            if p.sig_default.0 & bit(sig) != 0
                && let Err(e) = signal::set_action_raw(sig, Action::Default)
            {
                return (Stage::Signals, e);
            }
        }
    }
    signal::set_mask(s.mask);
    (Stage::Exec, p.exec())
}

unsafe extern "C" fn child_entry(arg: *mut c_void) -> ! {
    let s = unsafe { &*(arg as *const Shared<'_, '_>) };
    let (stage, e) = child_run(s);
    s.stage.store(stage as i32, Ordering::Relaxed);
    s.err.store(if e.0 == 0 { Errno::EINVAL.0 } else { e.0 }, Ordering::Release);
    exit_group(127)
}

pub fn spawn(plan: &SpawnPlan<'_>) -> Result<Spawned, (Stage, Errno)> {
    const GUARD: usize = 4096;
    const STACK_SIZE: usize = 64 * 1024;
    let stack = Stack::new(STACK_SIZE, GUARD).map_err(|e| (Stage::Clone, e))?;
    let mut pidfd: i32 = -1;
    let old = signal::set_mask(u64::MAX);
    let shared = Shared { plan, err: AtomicI32::new(0), stage: AtomicI32::new(0), use_clone3: AtomicBool::new(true), mask: plan.mask.map_or(old, |m| m.0 & !INTERNAL) };
    let arg = &raw const shared as *mut c_void;
    let mut legacy = plan.legacy_clone;
    let mut ret = -(Errno::ENOSYS.0 as isize);
    if !legacy {
        let args = CloneArgs {
            flags: CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND | CLONE_PIDFD,
            pidfd: &raw mut pidfd as u64,
            exit_signal: SIGCHLD,
            stack: stack.low() as u64,
            stack_size: stack.size() as u64,
            ..CloneArgs::default()
        };
        ret = unsafe { clone_vfork(CloneCall::Clone3(&args), child_entry, arg) };
        legacy = matches!(Errno::of(ret), Some(Errno::ENOSYS | Errno::EINVAL | Errno::EPERM));
    }
    if legacy {
        pidfd = -1;
        shared.use_clone3.store(false, Ordering::Relaxed);
        ret = unsafe { clone_vfork(CloneCall::Clone { flags: CLONE_VM | CLONE_VFORK | SIGCHLD, stack_top: stack.top() }, child_entry, arg) };
    }
    signal::set_mask(old);
    drop(stack);
    if let Some(e) = Errno::of(ret) {
        return Err((Stage::Clone, e));
    }
    let pid = ret as Pid;
    let pidfd = (pidfd >= 0).then(|| {
        unsafe { OwnedRawFd::from_raw(pidfd) }
    });
    let err = shared.err.load(Ordering::Acquire);
    if err != 0 {
        let stage = Stage::ALL.get(shared.stage.load(Ordering::Relaxed) as usize).copied().unwrap_or(Stage::Exec);
        while let Err(Errno::EINTR) = crate::wait::waitid(WaitId::Pid(pid), WaitFlags::WEXITED) {}
        return Err((stage, Errno(err)));
    }
    Ok(Spawned { pid, pidfd })
}

pub fn pidfd_send_signal(pidfd: BorrowedRawFd<'_>, sig: i32) -> Result<(), Errno> {
    cvt(unsafe { syscall6(nr::PIDFD_SEND_SIGNAL, pidfd.as_raw() as usize, sig as usize, 0, 0, 0, 0) }).map(drop)
}

