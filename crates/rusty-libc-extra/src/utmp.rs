use crate::consts::*;
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3, syscall4};

pub const UT_LINESIZE: usize = 32;
pub const UT_NAMESIZE: usize = 32;
pub const UT_HOSTSIZE: usize = 256;

pub const EMPTY: i16 = 0;
pub const RUN_LVL: i16 = 1;
pub const BOOT_TIME: i16 = 2;
pub const NEW_TIME: i16 = 3;
pub const OLD_TIME: i16 = 4;
pub const INIT_PROCESS: i16 = 5;
pub const LOGIN_PROCESS: i16 = 6;
pub const USER_PROCESS: i16 = 7;
pub const DEAD_PROCESS: i16 = 8;
pub const ACCOUNTING: i16 = 9;

pub const PATH_UTMP: &CStr = c"/var/run/utmp";
pub const PATH_WTMP: &CStr = c"/var/log/wtmp";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Utmp {
    pub ut_type: i16,
    pub ut_pid: i32,
    pub ut_line: [u8; UT_LINESIZE],
    pub ut_id: [u8; 4],
    pub ut_user: [u8; UT_NAMESIZE],
    pub ut_host: [u8; UT_HOSTSIZE],
    pub e_termination: i16,
    pub e_exit: i16,
    pub ut_session: i32,
    pub tv_sec: u32,
    pub tv_usec: i32,
    pub ut_addr_v6: [i32; 4],
    pub reserved: [u8; 20],
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Utmpx(pub Utmp);

const _: () = assert!(size_of::<Utmp>() == 384);
const _: () = assert!(align_of::<Utmp>() == 4);
const _: () = assert!(core::mem::offset_of!(Utmp, ut_user) == 44);
const _: () = assert!(core::mem::offset_of!(Utmp, ut_host) == 76);
const _: () = assert!(core::mem::offset_of!(Utmp, tv_sec) == 340);

impl Utmp {
    pub const ZERO: Utmp = Utmp { ut_type: 0, ut_pid: 0, ut_line: [0; 32], ut_id: [0; 4], ut_user: [0; 32], ut_host: [0; 256], e_termination: 0, e_exit: 0, ut_session: 0, tv_sec: 0, tv_usec: 0, ut_addr_v6: [0; 4], reserved: [0; 20] };
}

fn bytes_of(u: &Utmp) -> &[u8; 384] {
    unsafe { &*(u as *const Utmp as *const [u8; 384]) }
}

fn strneq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len().min(b.len()) {
        if a[i] != b[i] {
            return false;
        }
        if a[i] == 0 {
            return true;
        }
    }
    true
}

fn utmp_equal(entry: &Utmp, m: &Utmp) -> bool {
    let process = |t: i16| t == INIT_PROCESS || t == LOGIN_PROCESS || t == USER_PROCESS || t == DEAD_PROCESS;
    process(entry.ut_type) && process(m.ut_type) && if entry.ut_id[0] != 0 && m.ut_id[0] != 0 { strneq(&entry.ut_id, &m.ut_id) } else { strneq(&entry.ut_line, &m.ut_line) }
}

const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const F_SETLKW: usize = 7;
const O_RDONLY: usize = 0;
const O_RDWR: usize = 2;
const O_WRONLY: usize = 1;
const O_CLOEXEC: usize = 0o2000000;
const SIGALRM: i32 = 14;
const SYS_PREAD64: usize = 17;
const SYS_ALARM: usize = 37;
const SYS_ACCESS_NR: usize = 21;

pub static LOCK_TIMEOUT: AtomicU32 = AtomicU32::new(10);

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

extern "C" fn timeout_handler(_sig: c_int) {}

fn try_file_lock(fd: c_int, ty: i16) -> bool {
    use rusty_libc_signal::action::sigaction_rs;
    use rusty_libc_signal::types::{Sigaction, Sigset};
    unsafe {
        let old_timeout = syscall1(SYS_ALARM, 0);
        let act = Sigaction { sa_handler: timeout_handler as extern "C" fn(c_int) as usize, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
        let old_action = sigaction_rs(SIGALRM, Some(&act));
        syscall1(SYS_ALARM, LOCK_TIMEOUT.load(Ordering::Relaxed) as usize);
        let fl = Flock { l_type: ty, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
        let r = syscall3(syscall::SYS_FCNTL, fd as usize, F_SETLKW, &fl as *const Flock as usize);
        let failed = sys_err(r) != 0;
        let saved = errno::get();
        let e = sys_err(r);
        syscall1(SYS_ALARM, 0);
        if let Ok(old) = old_action {
            let _ = sigaction_rs(SIGALRM, Some(&old));
        }
        if old_timeout != 0 {
            syscall1(SYS_ALARM, old_timeout);
        }
        errno::set(if failed { e } else { saved });
        failed
    }
}

fn file_unlock(fd: c_int) {
    let fl = Flock { l_type: F_UNLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
    unsafe { syscall3(syscall::SYS_FCNTL, fd as usize, F_SETLKW, &fl as *const Flock as usize) };
}

fn access_ok(path: &CStr) -> bool {
    let e = unsafe { sys_err(syscall2(SYS_ACCESS_NR, path.as_ptr() as usize, 0)) };
    if e != 0 {
        errno::set(e);
    }
    e == 0
}

fn transform(name: &CStr) -> &CStr {
    const UTMP: &CStr = c"/var/run/utmp";
    const UTMPX: &CStr = c"/var/run/utmpx";
    const WTMP: &CStr = c"/var/log/wtmp";
    const WTMPX: &CStr = c"/var/log/wtmpx";
    if name == UTMP && access_ok(UTMPX) {
        UTMPX
    } else if name == WTMP && access_ok(WTMPX) {
        WTMPX
    } else if name == UTMPX && !access_ok(UTMPX) {
        UTMP
    } else if name == WTMPX && !access_ok(WTMPX) {
        WTMP
    } else {
        name
    }
}

unsafe fn pwrite_all_at(fd: c_int, data: &[u8], off: i64) -> isize {
    unsafe {
        let r = syscall3(syscall::SYS_LSEEK, fd as usize, off as usize, 0);
        if sys_err(r) != 0 {
            return -1;
        }
        let w = syscall3(syscall::SYS_WRITE, fd as usize, data.as_ptr() as usize, data.len());
        if sys_err(w) != 0 { -1 } else { w as isize }
    }
}

pub struct UtmpDb {
    fd: c_int,
    writable: bool,
    offset: i64,
    last: Utmp,
    name: *mut c_char,
}

unsafe impl Send for UtmpDb {}

impl Default for UtmpDb {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UtmpDb {
    fn drop(&mut self) {
        self.endutent();
        unsafe { rusty_libc_malloc::free(self.name.cast()) };
    }
}

impl UtmpDb {
    pub const fn new() -> UtmpDb {
        UtmpDb { fd: -1, writable: false, offset: 0, last: Utmp::ZERO, name: null_mut() }
    }

    fn file_name(&self) -> &CStr {
        if self.name.is_null() { PATH_UTMP } else { unsafe { CStr::from_ptr(self.name) } }
    }

    pub fn set_name(&mut self, file: &CStr) -> bool {
        self.endutent();
        if file != self.file_name() {
            if file == PATH_UTMP {
                unsafe { rusty_libc_malloc::free(self.name.cast()) };
                self.name = null_mut();
            } else {
                let copy = unsafe { rusty_libc_malloc::strdup(file.as_ptr()) };
                if copy.is_null() {
                    return false;
                }
                unsafe { rusty_libc_malloc::free(self.name.cast()) };
                self.name = copy;
            }
        }
        true
    }

    pub fn setutent(&mut self) -> bool {
        if self.fd < 0 {
            self.writable = false;
            let name = transform(self.file_name());
            let r = unsafe { syscall3(syscall::SYS_OPEN, name.as_ptr() as usize, O_RDONLY | O_CLOEXEC, 0) };
            let e = sys_err(r);
            if e != 0 {
                errno::set(e);
                return false;
            }
            self.fd = r as c_int;
        }
        unsafe { syscall3(syscall::SYS_LSEEK, self.fd as usize, 0, 0) };
        self.offset = 0;
        true
    }

    fn maybe_setutent(&mut self) -> bool {
        self.fd >= 0 || self.setutent()
    }

    fn read_last_entry(&mut self) -> isize {
        let mut buf = Utmp::ZERO;
        let r = unsafe { syscall4(SYS_PREAD64, self.fd as usize, &mut buf as *mut Utmp as usize, 384, self.offset as usize) };
        let e = sys_err(r);
        if e != 0 {
            errno::set(e);
            -1
        } else if r != 384 {
            0
        } else {
            self.last = buf;
            self.offset += 384;
            1
        }
    }

    fn matches_last_entry(&self, data: &Utmp) -> bool {
        if self.offset <= 0 {
            return false;
        }
        let t = data.ut_type;
        if t == RUN_LVL || t == BOOT_TIME || t == OLD_TIME || t == NEW_TIME { t == self.last.ut_type } else { utmp_equal(&self.last, data) }
    }

    pub fn getutent(&mut self) -> Result<Option<Utmp>, i32> {
        let saved = errno::get();
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        let n = self.read_last_entry();
        file_unlock(self.fd);
        match n {
            1 => Ok(Some(self.last)),
            0 => {
                errno::set(saved);
                Ok(None)
            }
            _ => Err(errno::get()),
        }
    }

    fn getut_nolock(&mut self, id: &Utmp) -> bool {
        loop {
            match self.read_last_entry() {
                n if n < 0 => return false,
                0 => {
                    errno::set(ESRCH);
                    return false;
                }
                _ => {
                    if self.matches_last_entry(id) {
                        return true;
                    }
                }
            }
        }
    }

    pub fn getutid(&mut self, id: &Utmp) -> Result<Utmp, i32> {
        let t = id.ut_type;
        if !matches!(t, RUN_LVL | BOOT_TIME | OLD_TIME | NEW_TIME | INIT_PROCESS | LOGIN_PROCESS | USER_PROCESS | DEAD_PROCESS) {
            errno::set(EINVAL);
            return Err(errno::get());
        }
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        let found = self.getut_nolock(id);
        file_unlock(self.fd);
        if found { Ok(self.last) } else { Err(errno::get()) }
    }

    pub fn getutline(&mut self, line: &Utmp) -> Result<Utmp, i32> {
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        loop {
            let n = self.read_last_entry();
            if n < 0 {
                file_unlock(self.fd);
                return Err(errno::get());
            }
            if n == 0 {
                file_unlock(self.fd);
                errno::set(ESRCH);
                return Err(errno::get());
            }
            if (self.last.ut_type == USER_PROCESS || self.last.ut_type == LOGIN_PROCESS) && strneq(&line.ut_line, &self.last.ut_line) {
                break;
            }
        }
        file_unlock(self.fd);
        Ok(self.last)
    }

    pub fn pututline(&mut self, data: &Utmp) -> bool {
        if !self.maybe_setutent() {
            return false;
        }
        if !self.writable {
            let name = transform(self.file_name());
            let r = unsafe { syscall3(syscall::SYS_OPEN, name.as_ptr() as usize, O_RDWR | O_CLOEXEC, 0) };
            let e = sys_err(r);
            if e != 0 {
                errno::set(e);
                return false;
            }
            let new_fd = r as c_int;
            let d = unsafe { syscall2(syscall::SYS_DUP2, new_fd as usize, self.fd as usize) };
            let e = sys_err(d);
            if e != 0 {
                unsafe { syscall1(syscall::SYS_CLOSE, new_fd as usize) };
                errno::set(e);
                return false;
            }
            unsafe { syscall1(syscall::SYS_CLOSE, new_fd as usize) };
            self.writable = true;
        }
        if try_file_lock(self.fd, F_WRLCK) {
            return false;
        }
        let mut found = false;
        if self.matches_last_entry(data) {
            self.offset -= 384;
            let n = self.read_last_entry();
            if n < 0 {
                file_unlock(self.fd);
                return false;
            }
            found = n != 0 && self.matches_last_entry(data);
        }
        if !found {
            found = self.getut_nolock(data);
        }
        let write_offset = if !found {
            let end = unsafe { syscall3(syscall::SYS_LSEEK, self.fd as usize, 0, 2) } as i64;
            end / 384 * 384
        } else {
            self.offset - 384
        };
        let w = unsafe { pwrite_all_at(self.fd, bytes_of(data), write_offset) };
        if w < 0 {
            file_unlock(self.fd);
            return false;
        }
        if w != 384 {
            if !found {
                unsafe { syscall2(syscall::SYS_FTRUNCATE, self.fd as usize, write_offset as usize) };
            }
            file_unlock(self.fd);
            errno::set(ENOSPC);
            return false;
        }
        file_unlock(self.fd);
        self.offset = write_offset + 384;
        true
    }

    pub fn endutent(&mut self) {
        if self.fd >= 0 {
            unsafe { syscall1(syscall::SYS_CLOSE, self.fd as usize) };
            self.fd = -1;
        }
    }
}

const ENOSPC: i32 = 28;

pub fn updwtmp_file(file: &CStr, utmp: &Utmp) -> c_int {
    unsafe {
        let name = transform(file);
        let r = syscall3(syscall::SYS_OPEN, name.as_ptr() as usize, O_WRONLY | O_CLOEXEC, 0);
        let e = sys_err(r);
        if e != 0 {
            errno::set(e);
            return -1;
        }
        let fd = r as c_int;
        if try_file_lock(fd, F_WRLCK) {
            syscall1(syscall::SYS_CLOSE, fd as usize);
            return -1;
        }
        let mut result = -1;
        let mut offset = syscall3(syscall::SYS_LSEEK, fd as usize, 0, 2) as i64;
        let mut ok = true;
        if offset % 384 != 0 {
            offset -= offset % 384;
            syscall2(syscall::SYS_FTRUNCATE, fd as usize, offset as usize);
            if sys_err(syscall3(syscall::SYS_LSEEK, fd as usize, 0, 2)) != 0 {
                ok = false;
            }
        }
        if ok {
            let w = syscall3(syscall::SYS_WRITE, fd as usize, bytes_of(utmp).as_ptr() as usize, 384);
            if w != 384 {
                syscall2(syscall::SYS_FTRUNCATE, fd as usize, offset as usize);
            } else {
                result = 0;
            }
        }
        file_unlock(fd);
        syscall1(syscall::SYS_CLOSE, fd as usize);
        result
    }
}

fn copy_name(dst: &mut [u8], src: &CStr) {
    let b = src.to_bytes();
    for (i, d) in dst.iter_mut().enumerate() {
        *d = if i < b.len() { b[i] } else { 0 };
    }
}

fn now() -> (u32, i32) {
    let mut ts = [0i64; 2];
    unsafe { syscall2(SYS_CLOCK_GETTIME_NR, 0, ts.as_mut_ptr() as usize) };
    (ts[0] as u32, (ts[1] / 1000) as i32)
}

fn getpid() -> i32 {
    unsafe { syscall::syscall0(syscall::SYS_GETPID) as i32 }
}

pub fn logwtmp_to(wtmp_file: &CStr, line: &CStr, name: &CStr, host: &CStr) {
    let mut ut = Utmp::ZERO;
    ut.ut_pid = getpid();
    ut.ut_type = if name.to_bytes().first().copied().unwrap_or(0) != 0 { USER_PROCESS } else { DEAD_PROCESS };
    copy_name(&mut ut.ut_line, line);
    copy_name(&mut ut.ut_user, name);
    copy_name(&mut ut.ut_host, host);
    let (s, us) = now();
    ut.tv_sec = s;
    ut.tv_usec = us;
    updwtmp_file(wtmp_file, &ut);
}

fn tty_name(fd: c_int) -> Option<[u8; 4352]> {
    let mut buf = [0u8; 4352];
    let rc = unsafe { rusty_libc_sys::unistd::ttyname_r(fd, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if rc == 0 { Some(buf) } else { None }
}

fn login_line() -> [u8; UT_LINESIZE] {
    let mut line = [0u8; UT_LINESIZE];
    if let Some(buf) = tty_name(0) {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let tty = &buf[..len];
        let name: &[u8] = if tty.starts_with(b"/dev/") { &tty[5..] } else { tty.rsplit(|&c| c == b'/').next().unwrap_or(tty) };
        for (i, d) in line.iter_mut().enumerate() {
            *d = name.get(i).copied().unwrap_or(0);
        }
    }
    line
}

pub fn login_to(utmp_path: &CStr, wtmp_path: &CStr, ut: &Utmp) {
    let mut copy = *ut;
    copy.ut_type = USER_PROCESS;
    copy.ut_pid = getpid();
    copy.ut_line = login_line();
    let mut db = UtmpDb::new();
    if db.set_name(utmp_path) {
        db.setutent();
        db.pututline(&copy);
        db.endutent();
    }
    updwtmp_file(wtmp_path, &copy);
}

pub fn logout_in(utmp_path: &CStr, line: &CStr) -> bool {
    let mut db = UtmpDb::new();
    if !db.set_name(utmp_path) {
        return false;
    }
    db.setutent();
    let mut tmp = Utmp::ZERO;
    tmp.ut_type = USER_PROCESS;
    copy_name(&mut tmp.ut_line, line);
    let mut result = false;
    if let Ok(mut ut) = db.getutline(&tmp) {
        ut.ut_user = [0; UT_NAMESIZE];
        ut.ut_host = [0; UT_HOSTSIZE];
        let (s, us) = now();
        ut.tv_sec = s;
        ut.tv_usec = us;
        ut.ut_type = DEAD_PROCESS;
        result = db.pututline(&ut);
    }
    db.endutent();
    result
}

static GLOBAL: Locked<UtmpDb> = Locked::new(UtmpDb::new());

static BUF_ENT: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());
static BUF_ID: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());
static BUF_LINE: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());

unsafe fn static_buffer(slot: &AtomicPtr<Utmp>) -> *mut Utmp {
    let b = slot.load(Ordering::Acquire);
    if !b.is_null() {
        return b;
    }
    let n = unsafe { rusty_libc_malloc::malloc(size_of::<Utmp>()) } as *mut Utmp;
    if n.is_null() {
        return n;
    }
    match slot.compare_exchange(null_mut(), n, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => n,
        Err(cur) => {
            unsafe { rusty_libc_malloc::free(n.cast()) };
            cur
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utmpname(file: *const c_char) -> c_int {
    GLOBAL.with(|db| if db.set_name(unsafe { CStr::from_ptr(file) }) { 0 } else { -1 })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setutent() {
    GLOBAL.with(|db| {
        db.setutent();
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endutent() {
    GLOBAL.with(|db| db.endutent());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutent_r(buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    unsafe {
        match GLOBAL.with(|db| db.getutent()) {
            Ok(Some(u)) => {
                *buffer = u;
                *result = buffer;
                0
            }
            _ => {
                *result = null_mut();
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutid_r(id: *const Utmp, buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    unsafe {
        match GLOBAL.with(|db| db.getutid(&*id)) {
            Ok(u) => {
                *buffer = u;
                *result = buffer;
                0
            }
            Err(_) => {
                *result = null_mut();
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutline_r(line: *const Utmp, buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    unsafe {
        match GLOBAL.with(|db| db.getutline(&*line)) {
            Ok(u) => {
                *buffer = u;
                *result = buffer;
                0
            }
            Err(_) => {
                *result = null_mut();
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutent() -> *mut Utmp {
    unsafe {
        let b = static_buffer(&BUF_ENT);
        if b.is_null() {
            return b;
        }
        let mut r = null_mut();
        if getutent_r(b, &mut r) < 0 { null_mut() } else { r }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutid(id: *const Utmp) -> *mut Utmp {
    unsafe {
        let b = static_buffer(&BUF_ID);
        if b.is_null() {
            return b;
        }
        let mut r = null_mut();
        if getutid_r(id, b, &mut r) < 0 { null_mut() } else { r }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutline(line: *const Utmp) -> *mut Utmp {
    unsafe {
        let b = static_buffer(&BUF_LINE);
        if b.is_null() {
            return b;
        }
        let mut r = null_mut();
        if getutline_r(line, b, &mut r) < 0 { null_mut() } else { r }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pututline(utmp_ptr: *const Utmp) -> *mut Utmp {
    unsafe { if GLOBAL.with(|db| db.pututline(&*utmp_ptr)) { utmp_ptr as *mut Utmp } else { null_mut() } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmp(wtmp_file: *const c_char, utmp: *const Utmp) {
    unsafe {
        updwtmp_file(CStr::from_ptr(wtmp_file), &*utmp);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn logwtmp(line: *const c_char, name: *const c_char, host: *const c_char) {
    unsafe { logwtmp_to(PATH_WTMP, CStr::from_ptr(line), CStr::from_ptr(name), CStr::from_ptr(host)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn login(entry: *const Utmp) {
    unsafe {
        let mut copy = *entry;
        copy.ut_type = USER_PROCESS;
        copy.ut_pid = getpid();
        copy.ut_line = login_line();
        if utmpname(PATH_UTMP.as_ptr()) == 0 {
            setutent();
            pututline(&copy);
            endutent();
        }
        updwtmp_file(PATH_WTMP, &copy);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn logout(ut_line: *const c_char) -> c_int {
    unsafe {
        if utmpname(PATH_UTMP.as_ptr()) == -1 {
            return 0;
        }
        setutent();
        let mut tmp = Utmp::ZERO;
        tmp.ut_type = USER_PROCESS;
        copy_name(&mut tmp.ut_line, CStr::from_ptr(ut_line));
        let mut result = 0;
        let mut buf = Utmp::ZERO;
        let mut r = null_mut();
        if getutline_r(&tmp, &mut buf, &mut r) >= 0 {
            buf.ut_user = [0; UT_NAMESIZE];
            buf.ut_host = [0; UT_HOSTSIZE];
            let (s, us) = now();
            buf.tv_sec = s;
            buf.tv_usec = us;
            buf.ut_type = DEAD_PROCESS;
            if !pututline(&buf).is_null() {
                result = 1;
            }
        }
        endutent();
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setutxent() {
    setutent()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endutxent() {
    endutent()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxent() -> *mut Utmpx {
    unsafe { getutent() as *mut Utmpx }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxid(id: *const Utmpx) -> *mut Utmpx {
    unsafe { getutid(id as *const Utmp) as *mut Utmpx }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxline(line: *const Utmpx) -> *mut Utmpx {
    unsafe { getutline(line as *const Utmp) as *mut Utmpx }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pututxline(utmpx: *const Utmpx) -> *mut Utmpx {
    unsafe { pututline(utmpx as *const Utmp) as *mut Utmpx }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utmpxname(file: *const c_char) -> c_int {
    unsafe { utmpname(file) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmpx(wtmpx_file: *const c_char, utmpx: *const Utmpx) {
    unsafe { updwtmp(wtmpx_file, utmpx as *const Utmp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutmp(utmpx: *const Utmpx, utmp: *mut Utmp) {
    unsafe { *utmp = (*utmpx).0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutmpx(utmp: *const Utmp, utmpx: *mut Utmpx) {
    unsafe { (*utmpx).0 = *utmp }
}
