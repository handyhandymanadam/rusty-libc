use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, process, signal, syscall, unistd};

const EINTR: i32 = 4;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ERANGE: i32 = 34;
const ENAMETOOLONG: i32 = 36;
const ELOOP: i32 = 40;
const ENOENT: i32 = 2;

const O_ACCMODE: i32 = 3;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const PATH_MAX: usize = 4096;
const MAXSYMLINKS: u32 = 40;

const SYS_MKDIR: usize = 83;
const SYS_READLINK: usize = 89;
const SYS_GETCWD: usize = 79;
const SYS_SYSINFO: usize = 99;
const GRND_NONBLOCK: usize = 1;
const TIOCGPTN: usize = 0x8004_5430;
const TIOCSPTLCK: usize = 0x4004_5431;

unsafe fn strlen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s.cast()) }
}

unsafe fn cstr<'a>(s: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(s.cast(), strlen(s)) }
}

fn fail(e: i32) -> i32 {
    errno::set(e);
    -1
}

fn raw_err(ret: usize) -> Option<i32> {
    if ret > usize::MAX - 4095 { Some((ret as isize).wrapping_neg() as i32) } else { None }
}

struct Buf {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl Buf {
    const fn new() -> Buf {
        Buf { p: null_mut(), len: 0, cap: 0 }
    }
    fn reserve(&mut self, extra: usize) -> bool {
        let need = match self.len.checked_add(extra).and_then(|n| n.checked_add(1)) {
            Some(n) => n,
            None => return false,
        };
        if need <= self.cap {
            return true;
        }
        let cap = need.max(self.cap * 2).max(64);
        let np: *mut u8 = unsafe { rusty_libc_malloc::realloc(self.p.cast(), cap).cast() };
        if np.is_null() {
            return false;
        }
        self.p = np;
        self.cap = cap;
        true
    }
    fn push(&mut self, b: &[u8]) -> bool {
        if !self.reserve(b.len()) {
            return false;
        }
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.p.add(self.len), b.len()) };
        self.len += b.len();
        true
    }
    fn slice(&self) -> &[u8] {
        if self.p.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.p, self.len) } }
    }
    fn cstr(&mut self) -> *const c_char {
        if !self.reserve(0) {
            return core::ptr::null();
        }
        unsafe { *self.p.add(self.len) = 0 };
        self.p.cast()
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe { rusty_libc_malloc::free(self.p.cast()) };
        }
    }
}

struct SystemState {
    refs: i32,
    intr: signal::KSigaction,
    quit: signal::KSigaction,
}

static SYSTEM_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();
static mut SYSTEM: SystemState = SystemState { refs: 0, intr: signal::KSigaction::DEFAULT, quit: signal::KSigaction::DEFAULT };

unsafe fn system_release() {
    unsafe {
        let st = &mut *core::ptr::addr_of_mut!(SYSTEM);
        let t = SYSTEM_LOCK.lock();
        st.refs -= 1;
        if st.refs == 0 {
            let _ = signal::sigaction(signal::SIGINT, Some(&st.intr));
            let _ = signal::sigaction(signal::SIGQUIT, Some(&st.quit));
        }
        SYSTEM_LOCK.unlock(t);
    }
}

unsafe extern "C" fn system_cancelled(arg: *mut c_void) {
    unsafe {
        let pid = arg as isize as i32;
        syscall::syscall2(62, pid as usize, 9);
        while let Err(Errno(EINTR)) = unistd::waitpid(pid, 0) {}
        system_release();
    }
}

pub unsafe fn run_shell(cmd: *const c_char) -> Result<i32, Errno> {
    unsafe {
        let st = &mut *core::ptr::addr_of_mut!(SYSTEM);
        let ign = signal::KSigaction::IGNORE;
        {
            let t = SYSTEM_LOCK.lock();
            if st.refs == 0 {
                st.intr = signal::sigaction(signal::SIGINT, Some(&ign)).unwrap_or(signal::KSigaction::DEFAULT);
                st.quit = signal::sigaction(signal::SIGQUIT, Some(&ign)).unwrap_or(signal::KSigaction::DEFAULT);
            }
            st.refs += 1;
            SYSTEM_LOCK.unlock(t);
        }
        let (intr_handler, quit_handler) = {
            let t = SYSTEM_LOCK.lock();
            let r = (st.intr.handler, st.quit.handler);
            SYSTEM_LOCK.unlock(t);
            r
        };
        let omask = signal::sigprocmask(signal::SIG_BLOCK, Some(signal::bit(signal::SIGCHLD))).unwrap_or(0);

        let sh = c"/bin/sh".as_ptr();
        let argv: [*const c_char; 5] = [c"sh".as_ptr(), c"-c".as_ptr(), c"--".as_ptr(), cmd, core::ptr::null()];
        let envp = rusty_libc_core::env::block() as *const *const c_char;

        let result = match unistd::fork() {
            Ok(0) => {
                let _ = signal::sigprocmask(signal::SIG_SETMASK, Some(omask));
                if intr_handler != signal::SIG_IGN {
                    let _ = signal::sigaction(signal::SIGINT, Some(&signal::KSigaction::DEFAULT));
                }
                if quit_handler != signal::SIG_IGN {
                    let _ = signal::sigaction(signal::SIGQUIT, Some(&signal::KSigaction::DEFAULT));
                }
                let _ = unistd::execve(sh, argv.as_ptr(), envp);
                process::exit_now(127)
            }
            Ok(pid) => rusty_libc_core::cleanup::with(system_cancelled, pid as isize as *mut c_void, || loop {
                match unistd::waitpid(pid, 0) {
                    Ok((p, status)) if p == pid => break Ok(status),
                    Ok(_) => break Err(Errno(EINVAL)),
                    Err(Errno(EINTR)) => continue,
                    Err(e) => break Err(e),
                }
            }),
            Err(e) => Err(e),
        };

        system_release();
        let _ = signal::sigprocmask(signal::SIG_SETMASK, Some(omask));
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn system(cmd: *const c_char) -> c_int {
    unsafe {
        let line = if cmd.is_null() { c"exit 0".as_ptr() } else { cmd };
        match run_shell(line) {
            Ok(st) => {
                if cmd.is_null() {
                    (st == 0) as c_int
                } else {
                    st
                }
            }
            Err(Errno(e)) => {
                errno::set(e);
                if cmd.is_null() { 0 } else { -1 }
            }
        }
    }
}

fn rand64() -> u64 {
    let mut v = 0u64;
    let r = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, &mut v as *mut u64 as usize, 8, GRND_NONBLOCK) };
    if r == 8 {
        return v;
    }
    let t = unsafe { core::arch::x86_64::_rdtsc() };
    let pid = unsafe { syscall::syscall0(syscall::SYS_GETPID) } as u64;
    let mut x = t ^ pid.rotate_left(32) ^ 0x9e37_79b9_7f4a_7c15;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x
}

const NAME_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    File,
    Dir,
    NoCreate,
}

unsafe fn gen_tempname(tmpl: *mut c_char, suffix: usize, flags: c_int, kind: Kind) -> c_int {
    unsafe {
        if tmpl.is_null() {
            return fail(EINVAL);
        }
        let len = strlen(tmpl);
        if len < 6 + suffix {
            return fail(EINVAL);
        }
        let xs = (tmpl as *mut u8).add(len - 6 - suffix);
        if core::slice::from_raw_parts(xs, 6) != b"XXXXXX" {
            return fail(EINVAL);
        }
        for _ in 0..238_328 {
            let mut v = rand64();
            for i in 0..6 {
                *xs.add(i) = NAME_CHARS[(v % 62) as usize];
                v /= 62;
            }
            match kind {
                Kind::File => {
                    let fl = (flags & !O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL;
                    match unistd::open(tmpl, fl, 0o600) {
                        Ok(fd) => return fd,
                        Err(Errno(EEXIST)) => {}
                        Err(Errno(e)) => return fail(e),
                    }
                }
                Kind::Dir => {
                    let r = syscall::syscall2(SYS_MKDIR, tmpl as usize, 0o700);
                    match raw_err(r) {
                        None => return 0,
                        Some(EEXIST) => {}
                        Some(e) => return fail(e),
                    }
                }
                Kind::NoCreate => {
                    let mut st = [0u64; 18];
                    let r = syscall::syscall2(syscall::SYS_LSTAT, tmpl as usize, st.as_mut_ptr() as usize);
                    match raw_err(r) {
                        Some(ENOENT) => return 0,
                        Some(e) if e != EEXIST => return fail(e),
                        _ => {}
                    }
                }
            }
        }
        fail(EEXIST)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    unsafe { gen_tempname(template, 0, 0, Kind::File) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { gen_tempname(template, 0, flags, Kind::File) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int {
    unsafe {
        if suffixlen < 0 {
            return fail(EINVAL);
        }
        gen_tempname(template, suffixlen as usize, 0, Kind::File)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    unsafe {
        if suffixlen < 0 {
            return fail(EINVAL);
        }
        gen_tempname(template, suffixlen as usize, flags, Kind::File)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp64(template: *mut c_char) -> c_int {
    unsafe { mkstemp(template) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp64(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { mkostemp(template, flags) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps64(template: *mut c_char, suffixlen: c_int) -> c_int {
    unsafe { mkstemps(template, suffixlen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps64(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    unsafe { mkostemps(template, suffixlen, flags) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    unsafe { if gen_tempname(template, 0, 0, Kind::Dir) < 0 { null_mut() } else { template } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    unsafe {
        if gen_tempname(template, 0, 0, Kind::NoCreate) < 0 && !template.is_null() {
            *template = 0;
        }
        template
    }
}

fn pop_component(b: &mut Buf) {
    let s = b.slice();
    let mut i = s.len();
    while i > 1 && s[i - 1] != b'/' {
        i -= 1;
    }
    b.len = if i > 1 { i - 1 } else { s.len().min(1) };
}

unsafe fn resolve(path: &[u8], rpath: &mut Buf) -> Result<(), i32> {
    unsafe {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut work = Buf::new();
        if !work.push(path) {
            return Err(ENOMEM);
        }
        let mut pos = 0usize;
        if path[0] == b'/' {
            if !rpath.push(b"/") {
                return Err(ENOMEM);
            }
        } else {
            let mut cwd = [0u8; PATH_MAX];
            let r = syscall::syscall2(SYS_GETCWD, cwd.as_mut_ptr() as usize, PATH_MAX);
            if let Some(e) = raw_err(r) {
                return Err(e);
            }
            if r == 0 || cwd[0] != b'/' {
                return Err(ENOENT);
            }
            if !rpath.push(&cwd[..r - 1]) {
                return Err(ENOMEM);
            }
        }
        let mut links = 0u32;
        loop {
            let w = work.slice();
            while pos < w.len() && w[pos] == b'/' {
                pos += 1;
            }
            if pos >= w.len() {
                break;
            }
            let start = pos;
            while pos < w.len() && w[pos] != b'/' {
                pos += 1;
            }
            let name = &w[start..pos];
            if name == b"." {
                continue;
            }
            if name == b".." {
                pop_component(rpath);
                continue;
            }
            if rpath.len > 1 && !rpath.push(b"/") {
                return Err(ENOMEM);
            }
            let name_start = rpath.len;
            if !rpath.push(name) {
                return Err(ENOMEM);
            }
            let cp = rpath.cstr();
            if cp.is_null() {
                return Err(ENOMEM);
            }
            let mut lb = Buf::new();
            let mut size = 256usize;
            let linklen = loop {
                if !lb.reserve(size) {
                    return Err(ENOMEM);
                }
                let r = syscall::syscall3(SYS_READLINK, cp as usize, lb.p as usize, size);
                match raw_err(r) {
                    Some(e) => break Err(e),
                    None if r < size => break Ok(r),
                    None => size *= 2,
                }
            };
            match linklen {
                Ok(n) => {
                    links += 1;
                    if links > MAXSYMLINKS {
                        return Err(ELOOP);
                    }
                    lb.len = n;
                    let mut nw = Buf::new();
                    if !nw.push(lb.slice()) || !nw.push(&work.slice()[pos..]) {
                        return Err(ENOMEM);
                    }
                    if lb.slice().first() == Some(&b'/') {
                        rpath.len = 0;
                        if !rpath.push(b"/") {
                            return Err(ENOMEM);
                        }
                    } else {
                        rpath.len = name_start;
                        if rpath.len > 1 {
                            rpath.len -= 1;
                        }
                    }
                    work = nw;
                    pos = 0;
                }
                Err(EINVAL) => {
                    if pos < work.len {
                        let mut st = [0u64; 18];
                        let r = syscall::syscall2(syscall::SYS_STAT, cp as usize, st.as_mut_ptr() as usize);
                        if let Some(e) = raw_err(r) {
                            return Err(e);
                        }
                        if (st[3] & 0xffff_ffff) as u32 & 0o170000 != 0o040000 {
                            return Err(ENOTDIR);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if rpath.len == 0 {
            rpath.push(b"/");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    unsafe {
        if path.is_null() {
            errno::set(EINVAL);
            return null_mut();
        }
        if *path == 0 {
            errno::set(ENOENT);
            return null_mut();
        }
        let mut rpath = Buf::new();
        let e = match resolve(cstr(path), &mut rpath) {
            Ok(()) if !resolved.is_null() && rpath.len >= PATH_MAX => ENAMETOOLONG,
            Ok(()) => 0,
            Err(e) => e,
        };
        if e != 0 {
            if !resolved.is_null() && (e == ENOENT || e == EACCES) && rpath.len < PATH_MAX {
                rusty_libc_mem::memcpy(resolved.cast(), rpath.slice().as_ptr().cast(), rpath.len);
                *resolved.add(rpath.len) = 0;
            }
            errno::set(e);
            return null_mut();
        }
        let out: *mut u8 = if resolved.is_null() { rusty_libc_malloc::malloc(rpath.len + 1).cast() } else { resolved.cast() };
        if out.is_null() {
            errno::set(ENOMEM);
            return null_mut();
        }
        rusty_libc_mem::memcpy(out.cast(), rpath.slice().as_ptr().cast(), rpath.len);
        *out.add(rpath.len) = 0;
        out.cast()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    unsafe { realpath(path, null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getloadavg(loadavg: *mut f64, nelem: c_int) -> c_int {
    unsafe {
        let mut info = [0u64; 14];
        let r = syscall::syscall1(SYS_SYSINFO, info.as_mut_ptr() as usize);
        if let Some(e) = raw_err(r) {
            return fail(e);
        }
        let n = nelem.clamp(0, 3);
        for i in 0..n as usize {
            *loadavg.add(i) = info[1 + i] as f64 / 65536.0;
        }
        n
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_openpt(flags: c_int) -> c_int {
    match unsafe { unistd::open(c"/dev/ptmx".as_ptr(), flags, 0) } {
        Ok(fd) => fd,
        Err(Errno(e)) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpt() -> c_int {
    posix_openpt(O_RDWR)
}

fn pty_number(fd: c_int) -> Result<u32, i32> {
    let mut n = 0u32;
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, TIOCGPTN, &mut n as *mut u32 as usize) };
    match raw_err(r) {
        None => Ok(n),
        Some(e) => Err(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn grantpt(fd: c_int) -> c_int {
    match pty_number(fd) {
        Ok(_) => 0,
        Err(ENOTTY) => fail(EINVAL),
        Err(e) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn unlockpt(fd: c_int) -> c_int {
    let zero = 0i32;
    let r = unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, TIOCSPTLCK, &zero as *const i32 as usize) };
    match raw_err(r) {
        None => 0,
        Some(ENOTTY) => fail(EINVAL),
        Some(e) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let n = match pty_number(fd) {
            Ok(n) => n,
            Err(e) => {
                errno::set(e);
                return e;
            }
        };
        let mut digits = [0u8; 10];
        let mut i = digits.len();
        let mut v = n;
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let prefix = b"/dev/pts/";
        let nd = digits.len() - i;
        if buflen < prefix.len() + nd + 1 {
            errno::set(ERANGE);
            return ERANGE;
        }
        let out = buf as *mut u8;
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), out, prefix.len());
        core::ptr::copy_nonoverlapping(digits.as_ptr().add(i), out.add(prefix.len()), nd);
        *out.add(prefix.len() + nd) = 0;
        0
    }
}

static mut PTSNAME_BUF: [u8; 32] = [0; 32];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    unsafe {
        let b = core::ptr::addr_of_mut!(PTSNAME_BUF) as *mut c_char;
        if ptsname_r(fd, b, 32) != 0 {
            return null_mut();
        }
        b
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsubopt(optionp: *mut *mut c_char, tokens: *const *mut c_char, valuep: *mut *mut c_char) -> c_int {
    unsafe {
        let start = *optionp as *mut u8;
        if *start == 0 {
            return -1;
        }
        let mut endp = start;
        while *endp != 0 && *endp != b',' {
            endp = endp.add(1);
        }
        let mut vstart = start;
        while vstart < endp && *vstart != b'=' {
            vstart = vstart.add(1);
        }
        let namelen = vstart as usize - start as usize;
        let mut cnt = 0;
        let mut found = -1;
        loop {
            let t = *tokens.add(cnt);
            if t.is_null() {
                break;
            }
            let tb = cstr(t);
            if tb.len() == namelen && core::slice::from_raw_parts(start, namelen) == tb {
                found = cnt as c_int;
                break;
            }
            cnt += 1;
        }
        *valuep = if found < 0 {
            start.cast()
        } else if vstart != endp {
            vstart.add(1).cast()
        } else {
            null_mut()
        };
        let mut next = endp;
        if *next != 0 {
            *next = 0;
            next = next.add(1);
        }
        *optionp = next.cast();
        found
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rpmatch(response: *const c_char) -> c_int {
    unsafe {
        match *response as u8 {
            b'y' | b'Y' => 1,
            b'n' | b'N' => 0,
            _ => -1,
        }
    }
}

const A64_DIGITS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn a64_value(c: u8) -> Option<u32> {
    A64_DIGITS.iter().position(|&d| d == c).map(|p| p as u32)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    unsafe {
        let mut result = 0u32;
        let mut shift = 0u32;
        for i in 0..6 {
            match a64_value(*s.add(i) as u8) {
                Some(v) => {
                    result |= v << shift;
                    shift += 6;
                }
                None => break,
            }
        }
        result as c_long
    }
}

static mut L64A_BUF: [u8; 7] = [0; 7];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn l64a(n: c_long) -> *mut c_char {
    unsafe {
        let mut m = (n as u64 & 0xffff_ffff) as u32;
        let b = core::ptr::addr_of_mut!(L64A_BUF) as *mut u8;
        let mut i = 0;
        while m > 0 {
            *b.add(i) = A64_DIGITS[(m & 63) as usize];
            m >>= 6;
            i += 1;
        }
        *b.add(i) = 0;
        b.cast()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ttyslot() -> c_int {
    unsafe {
        for fd in 0..3u8 {
            if !unistd::isatty(fd as i32) {
                continue;
            }
            let link = *b"/proc/self/fd/0\0";
            let mut link = link;
            link[13] = b'0' + fd;
            let mut name = [0u8; 256];
            let r = syscall::syscall3(SYS_READLINK, link.as_ptr() as usize, name.as_mut_ptr() as usize, name.len());
            if raw_err(r).is_some() {
                return 0;
            }
            let full = &name[..r];
            let last = match full.iter().rposition(|&c| c == b'/') {
                Some(i) => &full[i + 1..],
                None => full,
            };
            let Ok(f) = unistd::open(c"/etc/ttys".as_ptr(), 0, 0) else { return 0 };
            let mut data = Buf::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = unistd::read(f, &mut chunk) {
                if n == 0 || !data.push(&chunk[..n]) {
                    break;
                }
            }
            let _ = unistd::close(f);
            let mut slot = 0;
            for line in data.slice().split(|&c| c == b'\n') {
                let t = line.trim_ascii_start();
                if t.is_empty() || t[0] == b'#' {
                    continue;
                }
                slot += 1;
                let end = t.iter().position(|c| c.is_ascii_whitespace()).unwrap_or(t.len());
                if &t[..end] == last {
                    return slot;
                }
            }
            return 0;
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn on_exit(func: Option<unsafe extern "C" fn(c_int, *mut c_void)>, arg: *mut c_void) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::OnExit(func, arg)) { 0 } else { fail(ENOMEM) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn at_quick_exit(func: Option<extern "C" fn()>) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::Quick(func)) { 0 } else { fail(ENOMEM) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn quick_exit(status: c_int) -> ! {
    process::exit_lock();
    rusty_libc_core::tls::run_thread_dtors();
    process::finalize_quick();
    process::exit_now(status)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn memalignment(p: *const c_void) -> usize {
    let a = p as usize;
    if a == 0 { 0 } else { 1usize << a.trailing_zeros() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn free_sized(ptr: *mut c_void, _size: usize) {
    unsafe { rusty_libc_malloc::free(ptr) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn free_aligned_sized(ptr: *mut c_void, _alignment: usize, _size: usize) {
    unsafe { rusty_libc_malloc::free(ptr) }
}

