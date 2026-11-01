//! The vfork-style child: what both faces' process creation share, and the Rust face's whole child.
//!
//! Method (glibc's `posix_spawn`, rusty-libc-core's `spawn`, and the Rust face's builder): the parent prepares
//! everything that allocates, blocks all signals, and creates the child with clone3(CLONE_VM | CLONE_VFORK |
//! CLONE_CLEAR_SIGHAND [| CLONE_PIDFD]) on a separate small stack (plain clone(CLONE_VM | CLONE_VFORK) when clone3 is
//! refused). The child shares the parent's memory while the parent's thread is suspended, so it runs only raw system
//! calls: no allocation, no locks, no C library call, no thread-local data, no unwinding, no panic; it never returns from
//! the function that cloned it, it ends in execve or exit_group (TLPI 24.3 p. 523: a vfork child must not modify the
//! parent's data or return from the calling function; descriptor operations are harmless, the descriptor table is the
//! child's own copy). A failure in the child is written into the parent's memory (atomics) before it exits with 127.
//!
//! Shared by both faces: [`clone_vfork`] (the trampoline), [`Stack`], [`CloneArgs`], [`exec_search`] / [`execve`]
//! (execvp's PATH rules, glibc's `__execvpex`), [`child_tcsetpgrp`], and `signal::clear_handler`. The step order and
//! policies differ by design: the C face follows posix_spawn's attributes and file actions (rusty-libc-core `spawn`), the
//! Rust face the builder's settings ([`spawn`] below, with [`SpawnPlan`]).
//!
//! Job control order in the Rust face's child (GNU C Library manual ch. 29.6.3, p. 844): descriptors, chdir, setsid,
//! setpgid, TIOCSCTTY, tcsetpgrp, signal defaults, signal mask, exec. The tcsetpgrp happens with all signals blocked, so it
//! never raises SIGTTOU (POSIX tcsetpgrp: a blocked SIGTTOU lets the call proceed).

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

// ------------------------------------------------------------------------------------------------ argument vectors

/// A NULL-terminated vector of pointers to NUL-terminated strings (execve's `argv` / `envp`), valid for `'a`.
#[derive(Clone, Copy, Debug)]
pub struct CVec<'a> {
    ptr: *const *const c_char,
    _strings: PhantomData<&'a CStr>,
}

impl<'a> CVec<'a> {
    /// Fill `buf` with pointers to `strings` and a final NULL; `None` when `buf` is shorter than `strings.len() + 1`.
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

    /// Wrap a C caller's vector.
    ///
    /// # Safety
    /// `ptr` points to a NULL-terminated array of pointers to NUL-terminated strings, all valid and unchanged for `'a`.
    #[inline]
    pub const unsafe fn from_raw(ptr: *const *const c_char) -> CVec<'a> {
        CVec { ptr, _strings: PhantomData }
    }

    /// The pointer execve takes.
    #[inline]
    pub const fn as_ptr(self) -> *const *const c_char {
        self.ptr
    }

    /// The number of strings before the NULL (0 for a NULL vector, which the kernel also takes as empty).
    pub fn len(self) -> usize {
        if self.ptr.is_null() {
            return 0;
        }
        let mut n = 0;
        // SAFETY: a non-NULL CVec points to a NULL-terminated array valid for 'a (type invariant): every element up to
        // and including the NULL is readable.
        while !unsafe { self.ptr.wrapping_add(n).read() }.is_null() {
            n += 1;
        }
        n
    }

    /// Is the vector empty (no string before the NULL, or a NULL vector)?
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// The `i`-th string pointer (i < len()).
    fn get(self, i: usize) -> *const c_char {
        // SAFETY: callers pass i < len(), so the element lies before the terminating NULL of the array (type invariant).
        unsafe { self.ptr.wrapping_add(i).read() }
    }
}

// ------------------------------------------------------------------------------------------------ exec

/// execve(2): the error number when it returns (on success it does not).
#[inline]
pub fn execve(path: &CStr, argv: CVec<'_>, envp: CVec<'_>) -> Errno {
    // SAFETY: a NUL-terminated path and two NULL-terminated vectors valid for the call (CVec's invariant). On success the
    // process image is replaced; nothing of this program runs afterwards.
    let r = unsafe { syscall3(nr::EXECVE, path.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize) };
    Errno::of(r).unwrap_or(Errno::ECHILD)
}

const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

/// execvp's search without the shell fallback for scripts (glibc's `__execvpex`), as posix_spawnp does: a `file` with a
/// '/' is run as it is; otherwise each element of `path` (':'-separated; an empty one is the current directory) is tried
/// in order: EACCES is remembered, ENOENT/ESTALE/ENOTDIR/ENODEV/ETIMEDOUT go on to the next element, any other error
/// stops. Returns the error number (only returns on failure). ENOENT for an empty `file`; ENAMETOOLONG when `file` is
/// longer than NAME_MAX; an element too long to form a path is skipped. No allocation: the path is built in a
/// 4354-byte stack buffer.
#[inline]
pub fn exec_search(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>) -> Errno {
    search(file, path, argv, envp, None::<fn(&CStr) -> Errno>)
}

/// execvp's search with the shell fallback for scripts (glibc 2.43's `__execvpe`, posix/execvpe.c): as [`exec_search`],
/// and when execve of a candidate fails with ENOEXEC (a file the kernel cannot run: no `#!` line and no ELF header),
/// [`exec_shell`] runs it with /bin/sh using `shell` (at least [`shell_argv_len`] entries) for the new argv; the error of
/// that attempt (e.g. /bin/sh's own ENOENT) then decides, under the same rules, whether the search goes on. No
/// allocation: usable in a vfork-style child.
#[inline]
pub fn exec_search_script(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>, shell: &[Cell<*const c_char>]) -> Errno {
    search(file, path, argv, envp, Some(|script: &CStr| exec_shell(script, argv, envp, shell)))
}

/// As [`exec_search_script`] with the ENOEXEC step supplied by the caller: `on_noexec(candidate)` runs the candidate
/// some other way and returns the error number when it returns (the C face's execvpe builds glibc's new argv with
/// malloc there, only when it is needed, and then calls [`exec_shell`]).
#[inline]
pub fn exec_search_with(file: &CStr, path: &[u8], argv: CVec<'_>, envp: CVec<'_>, on_noexec: impl FnMut(&CStr) -> Errno) -> Errno {
    search(file, path, argv, envp, Some(on_noexec))
}

/// The entries the argv of [`exec_shell`] needs for an `argc`-string argv: glibc's `argc > 1 ? 2 + argc : 3`
/// ("/bin/sh", the script, argv[1..], NULL).
pub const fn shell_argv_len(argc: usize) -> usize {
    if argc > 1 { argc + 2 } else { 3 }
}

/// glibc's `maybe_script_execute`: execve("/bin/sh", {"/bin/sh", script, argv[1], ..., NULL}, envp), the new argv built
/// in `buf` (argv[0] is dropped: the shell sets $0 to the script). Returns the error number when it returns: E2BIG for
/// an argv of INT_MAX - 1 strings or more (glibc's limit) or a `buf` shorter than [`shell_argv_len`]`(argv.len())`,
/// else execve's error.
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
    // SAFETY: `buf` (Cell<T> has T's layout) now holds pointers to NUL-terminated strings that outlive this call (the
    // literal, `script`, the strings of `argv`) followed by a NULL; nothing changes it during the execve below.
    let new = unsafe { CVec::from_raw(buf.as_ptr() as *const *const c_char) };
    execve(SHELL, new, envp)
}

/// _PATH_BSHELL.
const SHELL: &CStr = c"/bin/sh";

/// The search of [`exec_search`] / [`exec_search_script`]: `on_noexec` None for posix_spawnp's form (and then the same
/// machine code as before the script form existed).
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
    // `pp`: where the element starts; `subp`: the ':' or the end that closes it (glibc's pointers, as indices)
    let mut pp = 0;
    loop {
        let subp = pp + path[pp..].iter().position(|&c| c == b':').unwrap_or(path.len() - pp);
        let seg = subp - pp;
        if seg >= path_len {
            // an element too long to be a path: skipped (glibc continues with the ':' itself)
            if subp == path.len() {
                break;
            }
            pp = subp;
            continue;
        }
        buffer[..seg].copy_from_slice(&path[pp..subp]);
        buffer[seg] = b'/';
        // an empty element means the current directory: just the file name
        let at = seg + (seg > 0) as usize;
        buffer[at..at + f.len()].copy_from_slice(f);
        buffer[at + f.len()] = 0;
        // (a raw pointer, not a `CStr`: building one would scan the buffer for its NUL on every element, which costs the
        // C face's posix_spawnp about 1.35x the instructions of its old loop; a NUL inside a PATH element only shortens
        // the path the kernel sees)
        // SAFETY: `buffer` holds a NUL at `at + f.len()` (written just above), so the kernel's read of the path stays in
        // it; the vectors are valid for the call (CVec's invariant). On success the process image is replaced.
        let r = unsafe { syscall3(nr::EXECVE, buffer.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize) };
        let mut e = Errno::of(r).unwrap_or(Errno::ECHILD);
        if e == Errno::ENOEXEC
            && let Some(run) = on_noexec.as_mut()
            // (only here is the CStr built: the path as the kernel saw it, up to the first NUL)
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

/// exit_group(2): end the calling process with `status`.
#[inline]
pub fn exit_group(status: i32) -> ! {
    plain!(nr::EXIT_GROUP, status);
    loop {
        // not reached; exit(2) of this thread as a last resort
        plain!(nr::EXIT, status);
    }
}

// ------------------------------------------------------------------------------------------------ child-only steps

/// ioctl(fd, TIOCSPGRP, pgrp) with `pgrp` (None: the caller's own group, getpgid(0)): the tcsetpgrp step of a spawn child.
///
/// # Safety
/// Called in a spawn child on its own descriptor table (no CLONE_FILES), where `fd` is a number the child set up or
/// inherited, or with `fd` borrowed by the caller.
#[inline]
pub unsafe fn child_tcsetpgrp(fd: i32, pgrp: Option<Pid>) -> Result<(), Errno> {
    let pg: i32 = match pgrp {
        Some(p) => p,
        None => plain!(nr::GETPGID, 0) as i32,
    };
    // SAFETY: TIOCSPGRP reads one pid_t from the local `pg`; the descriptor is the caller's (contract).
    cvt(unsafe { syscall3(nr::IOCTL, fd as usize, TIOCSPGRP, &raw const pg as usize) }).map(drop)
}

/// A system call with plain integer arguments that, in the spawn child, changes only the child's own descriptor table
/// or terminal (dup2, ioctl with an integer).
macro_rules! child_plain {
    ($n:expr, $a:expr, $b:expr, $c:expr) => {{
        // SAFETY: plain integer arguments; run only in the child (`child_run`), where the descriptor table is the child's
        // own copy (CLONE_VM shares memory, not the descriptor table: no CLONE_FILES).
        unsafe { syscall3($n, $a as usize, $b as usize, $c as usize) }
    }};
}

// ------------------------------------------------------------------------------------------------ stack and clone

/// A child stack: an anonymous private mapping, optionally with a PROT_NONE guard page at its low end (an overflow
/// faults instead of writing into a neighbouring mapping); unmapped on drop.
#[derive(Debug)]
pub struct Stack {
    base: usize,
    len: usize,
    guard: usize,
}

impl Stack {
    /// `size` usable bytes above `guard` guard bytes (both multiples of the page size). `guard` 0: one mapping, readable
    /// and writable (mmap MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK); otherwise PROT_NONE + MAP_NORESERVE, then the usable
    /// part made readable and writable (mprotect).
    #[inline]
    pub fn new(size: usize, guard: usize) -> Result<Stack, Errno> {
        const MAP_PRIVATE_ANON_STACK: usize = 0x02 | 0x20 | 0x20000;
        const MAP_NORESERVE: usize = 0x4000;
        let len = size + guard;
        if guard == 0 {
            // SAFETY: a new anonymous mapping at an address the kernel picks: no existing memory is affected.
            let base = cvt(unsafe { syscall6(nr::MMAP, 0, len, 3, MAP_PRIVATE_ANON_STACK, usize::MAX, 0) })?;
            return Ok(Stack { base, len, guard });
        }
        // SAFETY: as above, with no access.
        let base = cvt(unsafe { syscall6(nr::MMAP, 0, len, 0, MAP_PRIVATE_ANON_STACK | MAP_NORESERVE, usize::MAX, 0) })?;
        let stack = Stack { base, len, guard };
        // SAFETY: changes the protection of the upper part of the mapping made just above, which nothing uses yet.
        cvt(unsafe { syscall6(nr::MPROTECT, base + guard, size, 3, 0, 0, 0) })?;
        Ok(stack)
    }

    /// The low end of the usable part (clone3's `stack`).
    pub const fn low(&self) -> usize {
        self.base + self.guard
    }

    /// The usable size (clone3's `stack_size`).
    pub const fn size(&self) -> usize {
        self.len - self.guard
    }

    /// The top (16-byte aligned; clone's stack pointer).
    pub const fn top(&self) -> usize {
        (self.base + self.len) & !15
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // SAFETY: our own mapping. A child that ran on it has executed or ended (CLONE_VFORK: the parent continues only
        // then), and the only way to give the stack to a child is `clone_vfork`, whose contract requires CLONE_VFORK.
        unsafe { syscall6(nr::MUNMAP, self.base, self.len, 0, 0, 0, 0) };
    }
}

/// `struct clone_args` of clone3(2) (kernel 5.7 layout with cgroup).
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

/// How `clone_vfork` creates the child.
#[derive(Debug)]
pub enum CloneCall<'a> {
    /// clone3(args, sizeof args): the child starts on `args.stack`..`+stack_size`.
    Clone3(&'a CloneArgs),
    /// clone(flags, stack_top, NULL, NULL, 0): the child starts with the stack pointer at `stack_top` (16-byte aligned).
    Clone {
        /// clone's flags (with the exit signal in the low byte).
        flags: u64,
        /// The child's initial stack pointer.
        stack_top: usize,
    },
}

/// Create a child that runs `entry(arg)` on its own stack; returns the child's pid (or the negative errno) in the parent.
///
/// The child starts with the kernel-set stack pointer and the parent's other registers: r9 (`entry`) and r12 (`arg`)
/// survive the system call. `call` leaves the stack aligned as the ABI wants at a function entry; rbp is cleared (the
/// outermost frame for unwinders and debuggers, as glibc's clone does); the child never comes back into this function.
///
/// # Safety
/// The flags include CLONE_VM and CLONE_VFORK (the calling thread is suspended until the child executes or exits); the
/// stack is mapped memory nothing else uses (e.g. a live [`Stack`]); `entry` never returns and only does what a vfork
/// child may (raw system calls, writes to memory the parent expects it to write, no unwinding); `arg` is valid for what
/// `entry` does with it until this returns.
pub unsafe fn clone_vfork(call: CloneCall<'_>, entry: unsafe extern "C" fn(*mut c_void) -> !, arg: *mut c_void) -> isize {
    let f = entry as usize;
    let ret: isize;
    match call {
        CloneCall::Clone3(args) => {
            // SAFETY: the caller's contract; in the parent only rax, rcx and r11 change.
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
            // SAFETY: as above.
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

// ------------------------------------------------------------------------------------------------ the Rust face's spawn

/// The step of a spawn that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Checking the builder's settings or preparing in the parent (strings with NUL, bad descriptor numbers, ...).
    Prepare,
    /// Creating the child (clone3/clone: EAGAIN at the process limit, ENOMEM; mapping its stack).
    Clone,
    /// Setting up the child's descriptors (dup2).
    Fds,
    /// Changing to the working directory.
    Chdir,
    /// setsid.
    Setsid,
    /// setpgid.
    Setpgid,
    /// TIOCSCTTY.
    ControllingTerminal,
    /// tcsetpgrp (only when the foreground was required).
    Foreground,
    /// Resetting signal dispositions or the mask.
    Signals,
    /// execve (for every PATH candidate).
    Exec,
}

impl Stage {
    const ALL: [Stage; 10] = [Stage::Prepare, Stage::Clone, Stage::Fds, Stage::Chdir, Stage::Setsid, Stage::Setpgid, Stage::ControllingTerminal, Stage::Foreground, Stage::Signals, Stage::Exec];
}

/// Everything the child does, prepared by the parent (the Rust face's builder fills it in).
#[derive(Debug)]
pub struct SpawnPlan<'a> {
    /// The program: run as it is when it contains a '/', else searched in `path` ([`exec_search`]).
    pub program: &'a CStr,
    /// The ':'-separated directory list for a bare program name.
    pub path: &'a [u8],
    /// argv (argv[0] first).
    pub argv: CVec<'a>,
    /// The environment.
    pub envp: CVec<'a>,
    /// Room for the /bin/sh argv of the ENOEXEC fallback ([`exec_search_script`], at least [`shell_argv_len`] of argv's
    /// length); None: no fallback (posix_spawnp's behaviour).
    pub shell: Option<&'a [Cell<*const c_char>]>,
    /// dup2(source, target) in order; the sources are the caller's (borrowed for the spawn), the targets the child's
    /// numbers. The caller makes sure no target overwrites a later source (copy the sources above every target first).
    pub fds: &'a [(BorrowedRawFd<'a>, i32)],
    /// chdir in the child.
    pub cwd: Option<&'a CStr>,
    /// setsid in the child.
    pub setsid: bool,
    /// setpgid(0, pgid) in the child (with `setsid`, 0 is a no-op: a session leader leads its own group).
    pub pgroup: Option<Pid>,
    /// ioctl(fd, TIOCSCTTY, steal) on the child's descriptor `fd`.
    pub ctty: Option<(i32, bool)>,
    /// tcsetpgrp(fd, the child's group) on the child's descriptor `fd`; `required` false ignores a failure.
    pub foreground: Option<(i32, bool)>,
    /// Signals set to SIG_DFL in the child.
    pub sig_default: SigSet,
    /// The child's signal mask (None: the parent thread's mask at spawn time); glibc's internal 32/33 are left out.
    pub mask: Option<SigSet>,
    /// Use plain clone(2) instead of clone3 (test hook; also chosen automatically when clone3 is refused).
    pub legacy_clone: bool,
}

impl SpawnPlan<'_> {
    /// The plan's exec step: [`exec_search_script`] with `shell`, else [`exec_search`]. Returns the error number.
    pub fn exec(&self) -> Errno {
        match self.shell {
            Some(buf) => exec_search_script(self.program, self.path, self.argv, self.envp, buf),
            None => exec_search(self.program, self.path, self.argv, self.envp),
        }
    }
}

/// A started child: its pid and, after clone3, its pidfd.
#[derive(Debug)]
pub struct Spawned {
    /// The child's process id.
    pub pid: Pid,
    /// The pidfd clone3 made (None after the plain clone fallback).
    pub pidfd: Option<OwnedRawFd>,
}

/// What the child reads (by shared reference, the parent suspended) and the two results it writes.
struct Shared<'p, 'a> {
    plan: &'p SpawnPlan<'a>,
    err: AtomicI32,
    stage: AtomicI32,
    /// false: the plain clone fallback ran, so the child resets inherited handlers itself (no CLONE_CLEAR_SIGHAND)
    use_clone3: AtomicBool,
    mask: u64,
}

/// The child's work after the clone; returns only on failure (step, errno).
fn child_run(s: &Shared<'_, '_>) -> (Stage, Errno) {
    let p = s.plan;
    // Handlers of the parent would run on this stack in shared memory: reset them (clone3's CLONE_CLEAR_SIGHAND already
    // did). Unlike the C face (glibc's posix_spawn sets 32/33 to SIG_IGN here) they are treated like the others, so the new
    // program sees the same dispositions after either clone path and after std's fork-based spawn.
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
        // SAFETY: the kernel reads the NUL-terminated directory name (borrowed from the suspended parent).
        if let Some(e) = Errno::of(unsafe { syscall3(nr::CHDIR, dir.as_ptr() as usize, 0, 0) }) {
            return (Stage::Chdir, e);
        }
    }
    if p.setsid
        && let Err(e) = process::setsid()
    {
        return (Stage::Setsid, e);
    }
    // after setsid the child already leads its own group (setpgid would say EPERM for a session leader)
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
        // SAFETY: in the child, on its own descriptor table.
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

/// The child's entry on its new stack (called from the clone trampoline). Never returns.
///
/// # Safety
/// `arg` is the parent's `&Shared`, alive while the parent's thread is suspended (CLONE_VFORK).
unsafe extern "C" fn child_entry(arg: *mut c_void) -> ! {
    // SAFETY: caller's contract: a live `Shared` that nothing else writes while the child runs (the parent waits).
    let s = unsafe { &*(arg as *const Shared<'_, '_>) };
    let (stage, e) = child_run(s);
    s.stage.store(stage as i32, Ordering::Relaxed);
    s.err.store(if e.0 == 0 { Errno::EINVAL.0 } else { e.0 }, Ordering::Release);
    exit_group(127)
}

/// Start the child the plan describes. On failure: the step and the errno (a child that failed before exec has been
/// reaped).
pub fn spawn(plan: &SpawnPlan<'_>) -> Result<Spawned, (Stage, Errno)> {
    const GUARD: usize = 4096;
    const STACK_SIZE: usize = 64 * 1024;
    let stack = Stack::new(STACK_SIZE, GUARD).map_err(|e| (Stage::Clone, e))?;
    let mut pidfd: i32 = -1;
    // block everything, glibc's internal signals too, as glibc's posix_spawn does (a raw call: glibc's sigprocmask
    // would leave 32/33 unblocked)
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
        // SAFETY: CLONE_VM | CLONE_VFORK on our unused stack; `child_entry` only runs `child_run` (raw system calls, the
        // two atomics) and exits; `shared` lives in this frame until after the call, and this thread is suspended while
        // the child runs.
        ret = unsafe { clone_vfork(CloneCall::Clone3(&args), child_entry, arg) };
        // ENOSYS: kernel before 5.3; EINVAL: before 5.5 (no CLONE_CLEAR_SIGHAND); EPERM: a seccomp filter refusing clone3
        legacy = matches!(Errno::of(ret), Some(Errno::ENOSYS | Errno::EINVAL | Errno::EPERM));
    }
    if legacy {
        pidfd = -1;
        shared.use_clone3.store(false, Ordering::Relaxed);
        // SAFETY: as above, with plain clone and the top of the same stack.
        ret = unsafe { clone_vfork(CloneCall::Clone { flags: CLONE_VM | CLONE_VFORK | SIGCHLD, stack_top: stack.top() }, child_entry, arg) };
    }
    signal::set_mask(old);
    drop(stack);
    if let Some(e) = Errno::of(ret) {
        return Err((Stage::Clone, e));
    }
    let pid = ret as Pid;
    let pidfd = (pidfd >= 0).then(|| {
        // SAFETY: the kernel created this pidfd for this clone call (CLONE_PIDFD); nothing else has it.
        unsafe { OwnedRawFd::from_raw(pidfd) }
    });
    let err = shared.err.load(Ordering::Acquire);
    if err != 0 {
        // the child failed before exec and has exited: reap it and report its step and errno
        let stage = Stage::ALL.get(shared.stage.load(Ordering::Relaxed) as usize).copied().unwrap_or(Stage::Exec);
        while let Err(Errno::EINTR) = crate::wait::waitid(WaitId::Pid(pid), WaitFlags::WEXITED) {}
        return Err((stage, Errno(err)));
    }
    Ok(Spawned { pid, pidfd })
}

/// pidfd_send_signal(pidfd, sig, NULL, 0).
pub fn pidfd_send_signal(pidfd: BorrowedRawFd<'_>, sig: i32) -> Result<(), Errno> {
    // SAFETY: no pointer (NULL info); the pidfd is borrowed.
    cvt(unsafe { syscall6(nr::PIDFD_SEND_SIGNAL, pidfd.as_raw() as usize, sig as usize, 0, 0, 0, 0) }).map(drop)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn cvec_layout() {
        let strs = [c"a", c"bc"];
        let mut buf = [core::ptr::null(); 3];
        let v = CVec::new(&strs, &mut buf).unwrap();
        // SAFETY: the vector just built: 2 pointers and a NULL.
        let p0 = unsafe { *v.as_ptr() };
        // SAFETY: as above, index 2 is the NULL.
        let p2 = unsafe { *v.as_ptr().wrapping_add(2) };
        assert_eq!(p0, c"a".as_ptr());
        assert!(p2.is_null());
        let mut short = [core::ptr::null(); 2];
        assert!(CVec::new(&strs, &mut short).is_none());
    }

    #[test]
    fn exec_search_errors() {
        let argv_s = [c"x"];
        let mut b1 = [core::ptr::null(); 2];
        let argv = CVec::new(&argv_s, &mut b1).unwrap();
        let env_s: [&CStr; 0] = [];
        let mut b2 = [core::ptr::null(); 1];
        let envp = CVec::new(&env_s, &mut b2).unwrap();
        // none of these can succeed, so the test process is never replaced
        assert_eq!(exec_search(c"", b"/bin", argv, envp), Errno::ENOENT);
        assert_eq!(exec_search(c"rusty-libc-no-such-program", b"/nonexistent:/also-not", argv, envp), Errno::ENOENT);
        assert_eq!(exec_search(c"/nonexistent/x", b"", argv, envp), Errno::ENOENT);
        assert_eq!(exec_search(c"passwd", b"/etc", argv, envp), Errno::EACCES); // a file without x permission
        let long = std::ffi::CString::new(std::vec![b'a'; 256]).unwrap();
        assert_eq!(exec_search(&long, b"/bin", argv, envp), Errno::ENAMETOOLONG);
    }

    #[test]
    fn shell_argv_rules() {
        assert_eq!((shell_argv_len(0), shell_argv_len(1), shell_argv_len(2), shell_argv_len(5)), (3, 3, 4, 7));
        let argv_s = [c"a", c"b", c"c"];
        let mut b1 = [core::ptr::null(); 4];
        let argv = CVec::new(&argv_s, &mut b1).unwrap();
        assert_eq!(argv.len(), 3);
        // SAFETY: a NULL vector (the kernel takes it as empty).
        assert!(unsafe { CVec::from_raw(core::ptr::null()) }.is_empty());
        let env_s: [&CStr; 0] = [];
        let mut b2 = [core::ptr::null(); 1];
        let envp = CVec::new(&env_s, &mut b2).unwrap();
        // a buffer one short: E2BIG, nothing executed
        let short: [Cell<*const c_char>; 4] = Default::default();
        assert_eq!(exec_shell(c"/nonexistent", argv, envp, &short), Errno::E2BIG);
        // the posix_spawnp form never runs the shell: a file without x permission stays EACCES, and the script form with
        // a candidate that does not exist never reaches it
        let buf: [Cell<*const c_char>; 5] = Default::default();
        assert_eq!(exec_search_script(c"rusty-libc-no-such", b"/nonexistent", argv, envp, &buf), Errno::ENOENT);
        assert!(buf[0].get().is_null());
        let mut called = 0;
        let e = exec_search_with(c"/nonexistent/x", b"", argv, envp, |_| {
            called += 1;
            Errno::EPERM
        });
        assert_eq!((e, called), (Errno::ENOENT, 0));
    }

    #[test]
    fn stack_shapes() {
        let s = Stack::new(64 * 1024, 4096).unwrap();
        assert_eq!(s.size(), 64 * 1024);
        assert_eq!(s.low() % 4096, 0);
        assert_eq!(s.top(), s.low() + s.size());
        let t = Stack::new(96 * 1024, 0).unwrap();
        assert_eq!(t.top() - t.low(), 96 * 1024);
    }
}
