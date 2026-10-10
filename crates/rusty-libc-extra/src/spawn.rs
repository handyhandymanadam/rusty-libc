use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_short, c_uint};
use core::ptr::{null, null_mut};
use rusty_libc_core::syscall::{self, syscall4};

pub use rusty_libc_core::spawn::*;

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
    unsafe { *sigdefault = (*attr).sd };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(attr: *mut PosixSpawnattr, sigdefault: *const SigsetT) -> c_int {
    unsafe { (*attr).sd = *sigdefault };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(attr: *const PosixSpawnattr, sigmask: *mut SigsetT) -> c_int {
    unsafe { *sigmask = (*attr).ss };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(attr: *mut PosixSpawnattr, sigmask: *const SigsetT) -> c_int {
    unsafe { (*attr).ss = *sigmask };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getflags(attr: *const PosixSpawnattr, flags: *mut c_short) -> c_int {
    unsafe { *flags = (*attr).flags };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setflags(attr: *mut PosixSpawnattr, flags: c_short) -> c_int {
    if (flags as c_int) & !ALL_FLAGS != 0 {
        return EINVAL;
    }
    unsafe { (*attr).flags = flags };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(attr: *const PosixSpawnattr, pgroup: *mut c_int) -> c_int {
    unsafe { *pgroup = (*attr).pgrp };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(attr: *mut PosixSpawnattr, pgroup: c_int) -> c_int {
    unsafe { (*attr).pgrp = pgroup };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(attr: *const PosixSpawnattr, schedpolicy: *mut c_int) -> c_int {
    unsafe { *schedpolicy = (*attr).policy };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(attr: *mut PosixSpawnattr, schedpolicy: c_int) -> c_int {
    if schedpolicy != SCHED_OTHER && schedpolicy != SCHED_FIFO && schedpolicy != SCHED_RR {
        return EINVAL;
    }
    unsafe { (*attr).policy = schedpolicy };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(attr: *const PosixSpawnattr, schedparam: *mut SchedParam) -> c_int {
    unsafe { *schedparam = (*attr).sp };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(attr: *mut PosixSpawnattr, schedparam: *const SchedParam) -> c_int {
    unsafe { (*attr).sp = *schedparam };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(attr: *const PosixSpawnattr, cgroup: *mut c_int) -> c_int {
    unsafe { *cgroup = (*attr).cgroup };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(attr: *mut PosixSpawnattr, cgroup: c_int) -> c_int {
    unsafe { (*attr).cgroup = cgroup };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_init(fa: *mut PosixSpawnFileActions) -> c_int {
    unsafe { fa.write(PosixSpawnFileActions { allocated: 0, used: 0, actions: null_mut(), pad: [0; 16] }) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(fa: *mut PosixSpawnFileActions) -> c_int {
    unsafe {
        let f = &mut *fa;
        for i in 0..f.used.max(0) as usize {
            let a = &*f.actions.add(i);
            if a.tag == A_OPEN || a.tag == A_CHDIR {
                rusty_libc_malloc::free(a.path.cast());
            }
        }
        rusty_libc_malloc::free(f.actions.cast());
    }
    0
}


fn valid_fd(fd: c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let m = open_max();
    m < 0 || (fd as i64) < m
}

unsafe fn next_slot(fa: *mut PosixSpawnFileActions) -> Result<*mut SpawnAction, c_int> {
    unsafe {
        let f = &mut *fa;
        if f.used == f.allocated {
            let newalloc = f.allocated + 8;
            let mem = rusty_libc_malloc::realloc(f.actions.cast(), newalloc as usize * size_of::<SpawnAction>());
            if mem.is_null() {
                return Err(ENOMEM);
            }
            f.actions = mem.cast();
            f.allocated = newalloc;
        }
        let slot = f.actions.add(f.used as usize);
        f.used += 1;
        Ok(slot)
    }
}

unsafe fn add(fa: *mut PosixSpawnFileActions, a: SpawnAction) -> c_int {
    unsafe {
        match next_slot(fa) {
            Ok(slot) => {
                slot.write(a);
                0
            }
            Err(e) => e,
        }
    }
}

const NOACT: SpawnAction = SpawnAction { tag: 0, fd: 0, arg: 0, mode: 0, path: null_mut() };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(fa: *mut PosixSpawnFileActions, fd: c_int, path: *const c_char, oflag: c_int, mode: c_uint) -> c_int {
    unsafe {
        if !valid_fd(fd) {
            return EBADF;
        }
        let copy = rusty_libc_malloc::strdup(path);
        if copy.is_null() {
            return ENOMEM;
        }
        let e = add(fa, SpawnAction { tag: A_OPEN, fd, arg: oflag, mode: mode as c_int, path: copy });
        if e != 0 {
            rusty_libc_malloc::free(copy.cast());
        }
        e
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    if !valid_fd(fd) {
        return EBADF;
    }
    unsafe { add(fa, SpawnAction { tag: A_CLOSE, fd, ..NOACT }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(fa: *mut PosixSpawnFileActions, fd: c_int, newfd: c_int) -> c_int {
    if !valid_fd(fd) || !valid_fd(newfd) {
        return EBADF;
    }
    unsafe { add(fa, SpawnAction { tag: A_DUP2, fd, arg: newfd, ..NOACT }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    unsafe {
        let copy = rusty_libc_malloc::strdup(path);
        if copy.is_null() {
            return ENOMEM;
        }
        let e = add(fa, SpawnAction { tag: A_CHDIR, path: copy, ..NOACT });
        if e != 0 {
            rusty_libc_malloc::free(copy.cast());
        }
        e
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir(fa: *mut PosixSpawnFileActions, path: *const c_char) -> c_int {
    unsafe { posix_spawn_file_actions_addchdir_np(fa, path) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(fa: *mut PosixSpawnFileActions, fd: c_int) -> c_int {
    unsafe { add(fa, SpawnAction { tag: A_FCHDIR, fd, ..NOACT }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(fa: *mut PosixSpawnFileActions, from: c_int) -> c_int {
    if !valid_fd(from) {
        return EBADF;
    }
    unsafe { add(fa, SpawnAction { tag: A_CLOSEFROM, fd: from, ..NOACT }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(fa: *mut PosixSpawnFileActions, tcfd: c_int) -> c_int {
    if !valid_fd(tcfd) {
        return EBADF;
    }
    unsafe { add(fa, SpawnAction { tag: A_TCSETPGRP, fd: tcfd, ..NOACT }) }
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

pub struct FileActions(PosixSpawnFileActions);

impl Default for FileActions {
    fn default() -> Self {
        Self::new()
    }
}

fn check(rc: c_int) -> Result<(), c_int> {
    if rc == 0 { Ok(()) } else { Err(rc) }
}

impl FileActions {
    pub fn new() -> FileActions {
        let mut fa = PosixSpawnFileActions { allocated: 0, used: 0, actions: null_mut(), pad: [0; 16] };
        unsafe { posix_spawn_file_actions_init(&mut fa) };
        FileActions(fa)
    }
    pub fn add_open(&mut self, fd: c_int, path: &CStr, oflag: c_int, mode: u32) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addopen(&mut self.0, fd, path.as_ptr(), oflag, mode) })
    }
    pub fn add_close(&mut self, fd: c_int) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addclose(&mut self.0, fd) })
    }
    pub fn add_dup2(&mut self, fd: c_int, newfd: c_int) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_adddup2(&mut self.0, fd, newfd) })
    }
    pub fn add_chdir(&mut self, path: &CStr) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addchdir_np(&mut self.0, path.as_ptr()) })
    }
    pub fn add_fchdir(&mut self, fd: c_int) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addfchdir_np(&mut self.0, fd) })
    }
    pub fn add_closefrom(&mut self, from: c_int) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addclosefrom_np(&mut self.0, from) })
    }
    pub fn add_tcsetpgrp(&mut self, fd: c_int) -> Result<(), c_int> {
        check(unsafe { posix_spawn_file_actions_addtcsetpgrp_np(&mut self.0, fd) })
    }
    pub fn as_ptr(&self) -> *const PosixSpawnFileActions {
        &self.0
    }
}

impl Drop for FileActions {
    fn drop(&mut self) {
        unsafe { posix_spawn_file_actions_destroy(&mut self.0) };
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
        check(unsafe { posix_spawnattr_setflags(&mut self.0, flags as c_short) })?;
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
        unsafe {
            let p = rusty_libc_malloc::malloc((items.len() + 1) * size_of::<*const c_char>()) as *mut *const c_char;
            if p.is_null() {
                return None;
            }
            for (i, s) in items.iter().enumerate() {
                *p.add(i) = s.as_ptr();
            }
            *p.add(items.len()) = null();
            Some(PtrArray(p))
        }
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
