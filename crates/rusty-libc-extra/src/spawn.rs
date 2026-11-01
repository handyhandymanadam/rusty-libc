//! spawn.h: posix_spawn, posix_spawnp, the posix_spawnattr_* and posix_spawn_file_actions_* families.
//!
//! The structures have glibc's x86-64 layout (`posix_spawnattr_t` 336 bytes, `posix_spawn_file_actions_t`
//! 80 bytes) so C code that sets them up with the header's functions or inspects them by size works
//! unchanged. The process itself is made by `rusty_libc_core::spawn` (clone3 with CLONE_VM | CLONE_VFORK, as
//! glibc), which system and popen use too; this module holds the C interface and the Rust API.
//!
//! Rust API: [`FileActions`], [`SpawnAttr`], [`spawn`] and [`spawnp`].
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_short, c_uint};
use core::ptr::{null, null_mut};
use rusty_libc_core::syscall::{self, syscall4};

pub use rusty_libc_core::spawn::*;

// ------------------------------------------------------------------ the attribute functions

/// The caller's attribute object to read.
///
/// # Safety
/// `attr` points to a valid `posix_spawnattr_t` for the call.
unsafe fn attr_ref<'a>(attr: *const PosixSpawnattr) -> &'a PosixSpawnattr {
    // SAFETY: forwarded contract.
    unsafe { &*attr }
}

/// The caller's attribute object to change.
///
/// # Safety
/// `attr` points to a valid `posix_spawnattr_t`, not accessed elsewhere during the call.
unsafe fn attr_mut<'a>(attr: *mut PosixSpawnattr) -> &'a mut PosixSpawnattr {
    // SAFETY: forwarded contract.
    unsafe { &mut *attr }
}

/// posix_spawnattr_init: everything zero.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_init(attr: *mut PosixSpawnattr) -> c_int {
    // SAFETY: `attr` is writable (caller's contract).
    unsafe { attr.write(ZERO_ATTR) };
    0
}

/// posix_spawnattr_destroy: nothing to release.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut PosixSpawnattr) -> c_int {
    0
}

/// posix_spawnattr_getsigdefault.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(attr: *const PosixSpawnattr, sigdefault: *mut SigsetT) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.sd;
    // SAFETY: `sigdefault` is writable (caller's contract).
    unsafe { sigdefault.write(v) };
    0
}

/// posix_spawnattr_setsigdefault.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(attr: *mut PosixSpawnattr, sigdefault: *const SigsetT) -> c_int {
    // SAFETY: a readable signal set (caller's contract).
    let v = unsafe { sigdefault.read() };
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.sd = v;
    0
}

/// posix_spawnattr_getsigmask.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(attr: *const PosixSpawnattr, sigmask: *mut SigsetT) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.ss;
    // SAFETY: `sigmask` is writable (caller's contract).
    unsafe { sigmask.write(v) };
    0
}

/// posix_spawnattr_setsigmask.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(attr: *mut PosixSpawnattr, sigmask: *const SigsetT) -> c_int {
    // SAFETY: a readable signal set (caller's contract).
    let v = unsafe { sigmask.read() };
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.ss = v;
    0
}

/// posix_spawnattr_getflags.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getflags(attr: *const PosixSpawnattr, flags: *mut c_short) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.flags;
    // SAFETY: `flags` is writable (caller's contract).
    unsafe { flags.write(v) };
    0
}

/// posix_spawnattr_setflags: EINVAL when a bit outside the nine known flags is set.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setflags(attr: *mut PosixSpawnattr, flags: c_short) -> c_int {
    if (flags as c_int) & !ALL_FLAGS != 0 {
        return EINVAL;
    }
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.flags = flags;
    0
}

/// posix_spawnattr_getpgroup.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(attr: *const PosixSpawnattr, pgroup: *mut c_int) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.pgrp;
    // SAFETY: `pgroup` is writable (caller's contract).
    unsafe { pgroup.write(v) };
    0
}

/// posix_spawnattr_setpgroup.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(attr: *mut PosixSpawnattr, pgroup: c_int) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.pgrp = pgroup;
    0
}

/// posix_spawnattr_getschedpolicy.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(attr: *const PosixSpawnattr, schedpolicy: *mut c_int) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.policy;
    // SAFETY: `schedpolicy` is writable (caller's contract).
    unsafe { schedpolicy.write(v) };
    0
}

/// posix_spawnattr_setschedpolicy: only SCHED_OTHER, SCHED_FIFO and SCHED_RR (EINVAL otherwise).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(attr: *mut PosixSpawnattr, schedpolicy: c_int) -> c_int {
    if schedpolicy != SCHED_OTHER && schedpolicy != SCHED_FIFO && schedpolicy != SCHED_RR {
        return EINVAL;
    }
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.policy = schedpolicy;
    0
}

/// posix_spawnattr_getschedparam.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(attr: *const PosixSpawnattr, schedparam: *mut SchedParam) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.sp;
    // SAFETY: `schedparam` is writable (caller's contract).
    unsafe { schedparam.write(v) };
    0
}

/// posix_spawnattr_setschedparam.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(attr: *mut PosixSpawnattr, schedparam: *const SchedParam) -> c_int {
    // SAFETY: a readable `struct sched_param` (caller's contract).
    let v = unsafe { schedparam.read() };
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.sp = v;
    0
}

/// posix_spawnattr_getcgroup_np (glibc 2.39): the cgroup directory descriptor used by POSIX_SPAWN_SETCGROUP.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(attr: *const PosixSpawnattr, cgroup: *mut c_int) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    let v = unsafe { attr_ref(attr) }.cgroup;
    // SAFETY: `cgroup` is writable (caller's contract).
    unsafe { cgroup.write(v) };
    0
}

/// posix_spawnattr_setcgroup_np.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(attr: *mut PosixSpawnattr, cgroup: c_int) -> c_int {
    // SAFETY: a valid attribute object (caller's contract).
    unsafe { attr_mut(attr) }.cgroup = cgroup;
    0
}

// ------------------------------------------------------------------ the file actions

/// posix_spawn_file_actions_init: everything zero.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_init(fa: *mut PosixSpawnFileActions) -> c_int {
    // SAFETY: `fa` is writable (caller's contract).
    unsafe { fa.write(EMPTY_ACTIONS) };
    0
}

const EMPTY_ACTIONS: PosixSpawnFileActions = PosixSpawnFileActions { allocated: 0, used: 0, actions: null_mut(), pad: [0; 16] };

/// The caller's initialised file-actions object, as the safe [`FileActions`] view.
///
/// # Safety
/// `fa` points to a `posix_spawn_file_actions_t` set up by `posix_spawn_file_actions_init` (and only changed by these
/// functions since), not accessed elsewhere during the call.
unsafe fn actions<'a>(fa: *mut PosixSpawnFileActions) -> &'a mut FileActions {
    // SAFETY: `FileActions` is a transparent wrapper of the structure; its invariant (an initialised object) is the
    // caller's contract.
    unsafe { &mut *fa.cast::<FileActions>() }
}

/// posix_spawn_file_actions_destroy: frees the copied paths and the array. The structure must not be
/// used again until it is initialised.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(fa: *mut PosixSpawnFileActions) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    unsafe { actions(fa) }.release();
    0
}

fn valid_fd(fd: c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let m = open_max();
    m < 0 || (fd as i64) < m
}

const NOACT: SpawnAction = SpawnAction { tag: 0, fd: 0, arg: 0, mode: 0, path: null_mut() };

/// A malloc'd copy of the path argument, or ENOMEM.
///
/// # Safety
/// `path` is a C string.
unsafe fn copy_path(path: *const c_char) -> Result<*mut c_char, c_int> {
    // SAFETY: forwarded contract.
    let copy = unsafe { rusty_libc_malloc::strdup(path) };
    if copy.is_null() { Err(ENOMEM) } else { Ok(copy) }
}

/// posix_spawn_file_actions_addopen: EBADF for a bad descriptor number, ENOMEM when the path copy fails.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(fa: *mut PosixSpawnFileActions, fd: c_int, path: *const c_char, oflag: c_int, mode: c_uint) -> c_int {
    if !valid_fd(fd) {
        return EBADF;
    }
    // SAFETY: `path` is a C string (caller's contract).
    let copy = match unsafe { copy_path(path) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: an initialised object (caller's contract).
    unsafe { actions(fa) }.add_owned(SpawnAction { tag: A_OPEN, fd, arg: oflag, mode: mode as c_int, path: copy })
}

/// posix_spawn_file_actions_addclose.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    err(unsafe { actions(fa) }.add_close(fd))
}

/// posix_spawn_file_actions_adddup2.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(fa: *mut PosixSpawnFileActions, fd: c_int, newfd: c_int) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    err(unsafe { actions(fa) }.add_dup2(fd, newfd))
}

/// posix_spawn_file_actions_addchdir_np (glibc 2.29).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    // SAFETY: `path` is a C string (caller's contract).
    let copy = match unsafe { copy_path(path) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    // SAFETY: an initialised object (caller's contract).
    unsafe { actions(fa) }.add_owned(SpawnAction { tag: A_CHDIR, path: copy, ..NOACT })
}

/// posix_spawn_file_actions_addchdir (POSIX.1-2024 name of the _np function; glibc 2.43 does not export it yet,
/// the shared build adds it as a GLIBC_2.43 extra).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { posix_spawn_file_actions_addchdir_np(fa, path) }
}

/// posix_spawn_file_actions_addfchdir_np: the descriptor is not checked (it only has to be open when
/// the action runs).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    err(unsafe { actions(fa) }.add_fchdir(fd))
}

/// posix_spawn_file_actions_addclosefrom_np (glibc 2.34): close every descriptor >= `from`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(fa: *mut PosixSpawnFileActions, from: c_int) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    err(unsafe { actions(fa) }.add_closefrom(from))
}

/// posix_spawn_file_actions_addtcsetpgrp_np (glibc 2.35): make the child's process group the
/// foreground group of the terminal `tcfd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(fa: *mut PosixSpawnFileActions, tcfd: c_int) -> c_int {
    // SAFETY: an initialised object (caller's contract).
    err(unsafe { actions(fa) }.add_tcsetpgrp(tcfd))
}

/// posix_spawn: run `path` in a new process; the return value is 0 or an error number.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn(pid: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix(pid, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, false) }
}

/// `posix_spawn@GLIBC_2.2.5`: a file that is not a program (a script without `#!`) is run by `/bin/sh`.
///
/// # Safety
/// As `posix_spawn`.
pub unsafe fn posix_spawn_compat(pid: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix_x(pid, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, false, true) }
}

/// `posix_spawnp@GLIBC_2.2.5`.
///
/// # Safety
/// As `posix_spawnp`.
pub unsafe fn posix_spawnp_compat(pid: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix_x(pid, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, false, true) }
}

/// posix_spawnp: like posix_spawn, searching `PATH` of the calling process when `file` has no slash.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnp(pid: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix(pid, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, false) }
}

/// pidfd_spawn (glibc 2.39): like posix_spawn, but returns a process file descriptor instead of a pid
/// (ENOSYS when the kernel has no clone3).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawn(pidfd: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix(pidfd, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, true) }
}

/// pidfd_spawnp: pidfd_spawn with a PATH search.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawnp(pidfd: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    // SAFETY: forwarded contract (the C arguments of posix_spawn).
    unsafe { spawnix(pidfd, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, true) }
}

// ------------------------------------------------------------------ the Rust API

/// Owned list of file actions for [`spawn`] (the C structure, kept initialised: `actions` is NULL or a malloc array of
/// `allocated` slots whose first `used` hold actions; open and chdir actions own their malloc'd path).
#[repr(transparent)]
pub struct FileActions(PosixSpawnFileActions);

impl Default for FileActions {
    fn default() -> Self {
        Self::new()
    }
}

fn check(rc: c_int) -> Result<(), c_int> {
    if rc == 0 { Ok(()) } else { Err(rc) }
}

fn err(r: Result<(), c_int>) -> c_int {
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

impl FileActions {
    pub fn new() -> FileActions {
        FileActions(EMPTY_ACTIONS)
    }

    /// The array's slots.
    fn slots(&mut self) -> &mut [SpawnAction] {
        // SAFETY: the invariant: `actions` is NULL with `allocated == 0`, or a malloc array of `allocated` initialised
        // slots (slots past `used` hold older or written values: plain data), reached only through `self`.
        unsafe { rusty_libc_core::ffi::slice_mut(self.0.actions, self.0.allocated.max(0) as usize) }
    }

    /// Append an action (the array grows 8 slots at a time, like glibc), or ENOMEM.
    fn push(&mut self, a: SpawnAction) -> Result<(), c_int> {
        if self.0.used == self.0.allocated {
            let newalloc = self.0.allocated + 8;
            // SAFETY: `actions` is NULL or this object's malloc array.
            let mem = unsafe { rusty_libc_malloc::realloc(self.0.actions.cast(), newalloc as usize * size_of::<SpawnAction>()) };
            if mem.is_null() {
                return Err(ENOMEM);
            }
            let mem = mem.cast::<SpawnAction>();
            // the new slots get a value before the array is viewed as a slice
            for i in self.0.allocated as usize..newalloc as usize {
                // SAFETY: slot `i` is inside the new block of `newalloc` slots.
                unsafe { mem.wrapping_add(i).write(NOACT) };
            }
            self.0.actions = mem;
            self.0.allocated = newalloc;
        }
        let used = self.0.used as usize;
        self.slots()[used] = a;
        self.0.used += 1;
        Ok(())
    }

    /// Append an action that owns `a.path` (a malloc'd copy, freed when the action cannot be added). 0 or ENOMEM.
    fn add_owned(&mut self, a: SpawnAction) -> c_int {
        let path = a.path;
        match self.push(a) {
            Ok(()) => 0,
            Err(e) => {
                // SAFETY: the copy was not stored; it is this call's own malloc'd string.
                unsafe { rusty_libc_malloc::free(path.cast()) };
                e
            }
        }
    }

    /// Free the paths and the array (glibc's destroy; the object holds dangling values until it is initialised again).
    fn release(&mut self) {
        let used = self.0.used.max(0) as usize;
        for a in &self.slots()[..used] {
            if a.tag == A_OPEN || a.tag == A_CHDIR {
                // SAFETY: an open or chdir action owns its malloc'd path; freed once (the object is not used afterwards).
                unsafe { rusty_libc_malloc::free(a.path.cast()) };
            }
        }
        // SAFETY: NULL or this object's malloc array; freed once.
        unsafe { rusty_libc_malloc::free(self.0.actions.cast()) };
    }

    /// Open `path` onto descriptor `fd` in the child.
    pub fn add_open(&mut self, fd: c_int, path: &CStr, oflag: c_int, mode: u32) -> Result<(), c_int> {
        // SAFETY: `self` is initialised; `path` is a C string.
        check(unsafe { posix_spawn_file_actions_addopen(&mut self.0, fd, path.as_ptr(), oflag, mode) })
    }
    pub fn add_close(&mut self, fd: c_int) -> Result<(), c_int> {
        if !valid_fd(fd) {
            return Err(EBADF);
        }
        self.push(SpawnAction { tag: A_CLOSE, fd, ..NOACT })
    }
    pub fn add_dup2(&mut self, fd: c_int, newfd: c_int) -> Result<(), c_int> {
        if !valid_fd(fd) || !valid_fd(newfd) {
            return Err(EBADF);
        }
        self.push(SpawnAction { tag: A_DUP2, fd, arg: newfd, ..NOACT })
    }
    pub fn add_chdir(&mut self, path: &CStr) -> Result<(), c_int> {
        // SAFETY: `self` is initialised; `path` is a C string.
        check(unsafe { posix_spawn_file_actions_addchdir_np(&mut self.0, path.as_ptr()) })
    }
    pub fn add_fchdir(&mut self, fd: c_int) -> Result<(), c_int> {
        self.push(SpawnAction { tag: A_FCHDIR, fd, ..NOACT })
    }
    pub fn add_closefrom(&mut self, from: c_int) -> Result<(), c_int> {
        if !valid_fd(from) {
            return Err(EBADF);
        }
        self.push(SpawnAction { tag: A_CLOSEFROM, fd: from, ..NOACT })
    }
    pub fn add_tcsetpgrp(&mut self, fd: c_int) -> Result<(), c_int> {
        if !valid_fd(fd) {
            return Err(EBADF);
        }
        self.push(SpawnAction { tag: A_TCSETPGRP, fd, ..NOACT })
    }
    /// The raw structure, for the C functions.
    pub fn as_ptr(&self) -> *const PosixSpawnFileActions {
        &self.0
    }
}

impl Drop for FileActions {
    fn drop(&mut self) {
        self.release();
    }
}

/// Spawn attributes for [`spawn`].
#[derive(Clone, Copy)]
pub struct SpawnAttr(pub PosixSpawnattr);

impl Default for SpawnAttr {
    fn default() -> Self {
        SpawnAttr(ZERO_ATTR)
    }
}

impl SpawnAttr {
    pub fn new() -> SpawnAttr {
        SpawnAttr(ZERO_ATTR)
    }
    /// POSIX_SPAWN_* flags (EINVAL for unknown bits).
    pub fn flags(&mut self, flags: c_int) -> Result<&mut Self, c_int> {
        if (flags as c_short as c_int) & !ALL_FLAGS != 0 {
            return Err(EINVAL);
        }
        self.0.flags = flags as c_short;
        Ok(self)
    }
    pub fn pgroup(&mut self, pgid: c_int) -> &mut Self {
        self.0.pgrp = pgid;
        self
    }
    /// Signals (1..=64 as bits of `mask`) the child resets to the default action.
    pub fn sigdefault(&mut self, mask: u64) -> &mut Self {
        self.0.sd.val[0] = mask;
        self
    }
    /// The child's initial signal mask.
    pub fn sigmask(&mut self, mask: u64) -> &mut Self {
        self.0.ss.val[0] = mask;
        self
    }
}

/// A NULL-terminated array of pointers for execve, built in malloc memory.
struct PtrArray(*mut *const c_char);

impl PtrArray {
    fn new(items: &[&CStr]) -> Option<PtrArray> {
        let p = crate::mntent::malloc((items.len() + 1) * size_of::<*const c_char>()).cast::<*const c_char>();
        if p.is_null() {
            return None;
        }
        for (i, s) in items.iter().enumerate() {
            // SAFETY: slot `i` < items.len() + 1 of the fresh block (malloc alignment suits pointers).
            unsafe { p.wrapping_add(i).write(s.as_ptr()) };
        }
        // SAFETY: the last slot of the block.
        unsafe { p.wrapping_add(items.len()).write(null()) };
        Some(PtrArray(p))
    }
}

impl Drop for PtrArray {
    fn drop(&mut self) {
        // SAFETY: the array's own malloc block; freed once.
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

fn spawn_common(path: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>, use_path: bool) -> Result<c_int, c_int> {
    let argv = PtrArray::new(args).ok_or(ENOMEM)?;
    let envp = PtrArray::new(env).ok_or(ENOMEM)?;
    let mut pid: c_int = 0;
    let fa = actions.map_or(null(), |a| a.as_ptr());
    let at = attr.map_or(null(), |a| &a.0 as *const PosixSpawnattr);
    // SAFETY: C strings, NULL-terminated arrays of C strings that outlive the call, initialised actions and attributes (or
    // NULL), and a local for the pid.
    let rc = unsafe { spawnix(&mut pid, path.as_ptr(), fa, at, argv.0, envp.0, use_path, false) };
    if rc == 0 { Ok(pid) } else { Err(rc) }
}

/// Start `path` with `args` (argv, including argv[0]) and `env` (`NAME=value` strings); returns the
/// pid or the error number the child reported (ENOENT, EACCES, ENOEXEC, ...).
pub fn spawn(path: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>) -> Result<c_int, c_int> {
    spawn_common(path, args, env, actions, attr, false)
}

/// Like [`spawn`], searching the `PATH` of this process for a name without a slash.
pub fn spawnp(file: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>) -> Result<c_int, c_int> {
    spawn_common(file, args, env, actions, attr, true)
}

/// Wait for `pid`; returns the raw wait status.
pub fn wait(pid: c_int) -> Result<c_int, c_int> {
    let mut status: c_int = 0;
    loop {
        // SAFETY: wait4 writes the status into the local; no rusage pointer. (Plain wait4, not a cancellation point.)
        let r = unsafe { syscall4(syscall::SYS_WAIT4, pid as usize, &mut status as *mut c_int as usize, 0, 0) };
        match sys_err(r) {
            0 => return Ok(status),
            EINTR => continue,
            e => return Err(e),
        }
    }
}
