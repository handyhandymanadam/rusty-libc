#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_short, c_uint};
use core::ptr::{null, null_mut};
use rusty_libc_core::syscall::{self, syscall4};

pub use rusty_libc_core::spawn::*;

unsafe fn attr_ref<'a>(attr: *const PosixSpawnattr) -> &'a PosixSpawnattr {
    unsafe { &*attr }
}

unsafe fn attr_mut<'a>(attr: *mut PosixSpawnattr) -> &'a mut PosixSpawnattr {
    unsafe { &mut *attr }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_init(attr: *mut PosixSpawnattr) -> c_int {
    unsafe { attr.write(ZERO_ATTR) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut PosixSpawnattr) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(attr: *const PosixSpawnattr, sigdefault: *mut SigsetT) -> c_int {
    let v = unsafe { attr_ref(attr) }.sd;
    unsafe { sigdefault.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(attr: *mut PosixSpawnattr, sigdefault: *const SigsetT) -> c_int {
    let v = unsafe { sigdefault.read() };
    unsafe { attr_mut(attr) }.sd = v;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(attr: *const PosixSpawnattr, sigmask: *mut SigsetT) -> c_int {
    let v = unsafe { attr_ref(attr) }.ss;
    unsafe { sigmask.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(attr: *mut PosixSpawnattr, sigmask: *const SigsetT) -> c_int {
    let v = unsafe { sigmask.read() };
    unsafe { attr_mut(attr) }.ss = v;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getflags(attr: *const PosixSpawnattr, flags: *mut c_short) -> c_int {
    let v = unsafe { attr_ref(attr) }.flags;
    unsafe { flags.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setflags(attr: *mut PosixSpawnattr, flags: c_short) -> c_int {
    if (flags as c_int) & !ALL_FLAGS != 0 {
        return EINVAL;
    }
    unsafe { attr_mut(attr) }.flags = flags;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(attr: *const PosixSpawnattr, pgroup: *mut c_int) -> c_int {
    let v = unsafe { attr_ref(attr) }.pgrp;
    unsafe { pgroup.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(attr: *mut PosixSpawnattr, pgroup: c_int) -> c_int {
    unsafe { attr_mut(attr) }.pgrp = pgroup;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(attr: *const PosixSpawnattr, schedpolicy: *mut c_int) -> c_int {
    let v = unsafe { attr_ref(attr) }.policy;
    unsafe { schedpolicy.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(attr: *mut PosixSpawnattr, schedpolicy: c_int) -> c_int {
    if schedpolicy != SCHED_OTHER && schedpolicy != SCHED_FIFO && schedpolicy != SCHED_RR {
        return EINVAL;
    }
    unsafe { attr_mut(attr) }.policy = schedpolicy;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(attr: *const PosixSpawnattr, schedparam: *mut SchedParam) -> c_int {
    let v = unsafe { attr_ref(attr) }.sp;
    unsafe { schedparam.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(attr: *mut PosixSpawnattr, schedparam: *const SchedParam) -> c_int {
    let v = unsafe { schedparam.read() };
    unsafe { attr_mut(attr) }.sp = v;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(attr: *const PosixSpawnattr, cgroup: *mut c_int) -> c_int {
    let v = unsafe { attr_ref(attr) }.cgroup;
    unsafe { cgroup.write(v) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(attr: *mut PosixSpawnattr, cgroup: c_int) -> c_int {
    unsafe { attr_mut(attr) }.cgroup = cgroup;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_init(fa: *mut PosixSpawnFileActions) -> c_int {
    unsafe { fa.write(EMPTY_ACTIONS) };
    0
}

const EMPTY_ACTIONS: PosixSpawnFileActions = PosixSpawnFileActions { allocated: 0, used: 0, actions: null_mut(), pad: [0; 16] };

unsafe fn actions<'a>(fa: *mut PosixSpawnFileActions) -> &'a mut FileActions {
    unsafe { &mut *fa.cast::<FileActions>() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(fa: *mut PosixSpawnFileActions) -> c_int {
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

unsafe fn copy_path(path: *const c_char) -> Result<*mut c_char, c_int> {
    let copy = unsafe { rusty_libc_malloc::strdup(path) };
    if copy.is_null() { Err(ENOMEM) } else { Ok(copy) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(fa: *mut PosixSpawnFileActions, fd: c_int, path: *const c_char, oflag: c_int, mode: c_uint) -> c_int {
    if !valid_fd(fd) {
        return EBADF;
    }
    let copy = match unsafe { copy_path(path) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    unsafe { actions(fa) }.add_owned(SpawnAction { tag: A_OPEN, fd, arg: oflag, mode: mode as c_int, path: copy })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    err(unsafe { actions(fa) }.add_close(fd))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(fa: *mut PosixSpawnFileActions, fd: c_int, newfd: c_int) -> c_int {
    err(unsafe { actions(fa) }.add_dup2(fd, newfd))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    let copy = match unsafe { copy_path(path) } {
        Ok(c) => c,
        Err(e) => return e,
    };
    unsafe { actions(fa) }.add_owned(SpawnAction { tag: A_CHDIR, path: copy, ..NOACT })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    unsafe { posix_spawn_file_actions_addchdir_np(fa, path) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    err(unsafe { actions(fa) }.add_fchdir(fd))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(fa: *mut PosixSpawnFileActions, from: c_int) -> c_int {
    err(unsafe { actions(fa) }.add_closefrom(from))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(fa: *mut PosixSpawnFileActions, tcfd: c_int) -> c_int {
    err(unsafe { actions(fa) }.add_tcsetpgrp(tcfd))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn(pid: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix(pid, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, false) }
}

pub unsafe fn posix_spawn_compat(pid: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix_x(pid, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, false, true) }
}

pub unsafe fn posix_spawnp_compat(pid: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix_x(pid, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, false, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnp(pid: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix(pid, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawn(pidfd: *mut c_int, path: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix(pidfd, path, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, false, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawnp(pidfd: *mut c_int, file: *const c_char, file_actions: *const PosixSpawnFileActions, attrp: *const PosixSpawnattr, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int {
    unsafe { spawnix(pidfd, file, file_actions, attrp, argv as *const *const c_char, envp as *const *const c_char, true, true) }
}

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

    fn slots(&mut self) -> &mut [SpawnAction] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.0.actions, self.0.allocated.max(0) as usize) }
    }

    fn push(&mut self, a: SpawnAction) -> Result<(), c_int> {
        if self.0.used == self.0.allocated {
            let newalloc = self.0.allocated + 8;
            let mem = unsafe { rusty_libc_malloc::realloc(self.0.actions.cast(), newalloc as usize * size_of::<SpawnAction>()) };
            if mem.is_null() {
                return Err(ENOMEM);
            }
            let mem = mem.cast::<SpawnAction>();
            for i in self.0.allocated as usize..newalloc as usize {
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

    fn add_owned(&mut self, a: SpawnAction) -> c_int {
        let path = a.path;
        match self.push(a) {
            Ok(()) => 0,
            Err(e) => {
                unsafe { rusty_libc_malloc::free(path.cast()) };
                e
            }
        }
    }

    fn release(&mut self) {
        let used = self.0.used.max(0) as usize;
        for a in &self.slots()[..used] {
            if a.tag == A_OPEN || a.tag == A_CHDIR {
                unsafe { rusty_libc_malloc::free(a.path.cast()) };
            }
        }
        unsafe { rusty_libc_malloc::free(self.0.actions.cast()) };
    }

    pub fn add_open(&mut self, fd: c_int, path: &CStr, oflag: c_int, mode: u32) -> Result<(), c_int> {
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
    pub fn as_ptr(&self) -> *const PosixSpawnFileActions {
        &self.0
    }
}

impl Drop for FileActions {
    fn drop(&mut self) {
        self.release();
    }
}

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
    pub fn sigdefault(&mut self, mask: u64) -> &mut Self {
        self.0.sd.val[0] = mask;
        self
    }
    pub fn sigmask(&mut self, mask: u64) -> &mut Self {
        self.0.ss.val[0] = mask;
        self
    }
}

struct PtrArray(*mut *const c_char);

impl PtrArray {
    fn new(items: &[&CStr]) -> Option<PtrArray> {
        let p = crate::mntent::malloc((items.len() + 1) * size_of::<*const c_char>()).cast::<*const c_char>();
        if p.is_null() {
            return None;
        }
        for (i, s) in items.iter().enumerate() {
            unsafe { p.wrapping_add(i).write(s.as_ptr()) };
        }
        unsafe { p.wrapping_add(items.len()).write(null()) };
        Some(PtrArray(p))
    }
}

impl Drop for PtrArray {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.0.cast()) };
    }
}

fn spawn_common(path: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>, use_path: bool) -> Result<c_int, c_int> {
    let argv = PtrArray::new(args).ok_or(ENOMEM)?;
    let envp = PtrArray::new(env).ok_or(ENOMEM)?;
    let mut pid: c_int = 0;
    let fa = actions.map_or(null(), |a| a.as_ptr());
    let at = attr.map_or(null(), |a| &a.0 as *const PosixSpawnattr);
    let rc = unsafe { spawnix(&mut pid, path.as_ptr(), fa, at, argv.0, envp.0, use_path, false) };
    if rc == 0 { Ok(pid) } else { Err(rc) }
}

pub fn spawn(path: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>) -> Result<c_int, c_int> {
    spawn_common(path, args, env, actions, attr, false)
}

pub fn spawnp(file: &CStr, args: &[&CStr], env: &[&CStr], actions: Option<&FileActions>, attr: Option<&SpawnAttr>) -> Result<c_int, c_int> {
    spawn_common(file, args, env, actions, attr, true)
}

pub fn wait(pid: c_int) -> Result<c_int, c_int> {
    let mut status: c_int = 0;
    loop {
        let r = unsafe { syscall4(syscall::SYS_WAIT4, pid as usize, &mut status as *mut c_int as usize, 0, 0) };
        match sys_err(r) {
            0 => return Ok(status),
            EINTR => continue,
            e => return Err(e),
        }
    }
}
