use crate::cmem::CVec;
use crate::zstr::ZStr;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, process, signal, spawn, unistd};

const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ERANGE: i32 = 34;
const ENAMETOOLONG: i32 = 36;
const ELOOP: i32 = 40;
const ENOENT: i32 = 2;
const ENOSYS: i32 = 38;

const O_ACCMODE: i32 = 3;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const PATH_MAX: usize = 4096;
const MAXSYMLINKS: u32 = 40;

const GRND_NONBLOCK: usize = 1;
const TIOCGPTN: usize = 0x8004_5430;
const TIOCSPTLCK: usize = 0x4004_5431;
const AT_EACCESS: usize = 0x200;

fn fail(e: i32) -> i32 {
    errno::set(e);
    -1
}

fn raw_err(ret: usize) -> Option<i32> {
    if ret > usize::MAX - 4095 { Some((ret as isize).wrapping_neg() as i32) } else { None }
}

struct Buf(CVec<u8>);

impl Buf {
    const fn new() -> Buf {
        Buf(CVec::new())
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn reserve(&mut self, extra: usize) -> bool {
        let Some(need) = self.len().checked_add(extra).and_then(|n| n.checked_add(1)) else { return false };
        if need <= self.0.capacity() {
            return true;
        }
        self.0.reserve_total(need.max(self.0.capacity() * 2).max(64))
    }
    fn push(&mut self, b: &[u8]) -> bool {
        !b.contains(&0) && self.reserve(b.len()) && self.0.extend_with(b, |n, _| n)
    }
    fn slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    fn truncate(&mut self, n: usize) {
        self.0.truncate(n);
    }
    fn spare_mut(&mut self) -> &mut [u8] {
        self.0.spare_mut()
    }
    fn set_len(&mut self, n: usize) {
        let old = self.len();
        self.0.set_len_written(n);
        if let Some(i) = self.0.as_slice().get(old..).and_then(|new| new.iter().position(|&c| c == 0)) {
            self.0.truncate(old + i);
        }
    }
    fn cstr(&mut self) -> Option<&CStr> {
        if !self.reserve(0) {
            return None;
        }
        let b = self.0.with_nul()?;
        Some(unsafe { CStr::from_bytes_with_nul_unchecked(b) })
    }
}

struct SystemState {
    refs: i32,
    intr: signal::KSigaction,
    quit: signal::KSigaction,
}

static SYSTEM: rusty_libc_core::lock::Locked<SystemState> =
    rusty_libc_core::lock::Locked::new(SystemState { refs: 0, intr: signal::KSigaction::DEFAULT, quit: signal::KSigaction::DEFAULT });

fn system_release() {
    SYSTEM.with(|st| {
        st.refs -= 1;
        if st.refs == 0 {
            let _ = signal::sigaction(signal::SIGINT, Some(&st.intr));
            let _ = signal::sigaction(signal::SIGQUIT, Some(&st.quit));
        }
    });
}

extern "C" fn system_cancelled(arg: *mut c_void) {
    let pid = arg as isize as i32;
    crate::sys::kill(pid, 9);
    while let Err(Errno(EINTR)) = unistd::waitpid(pid, 0) {}
    system_release();
}

pub fn run_shell(cmd: &CStr) -> Result<i32, Errno> {
    let ign = signal::KSigaction::IGNORE;
    SYSTEM.with(|st| {
        if st.refs == 0 {
            st.intr = signal::sigaction(signal::SIGINT, Some(&ign)).unwrap_or(signal::KSigaction::DEFAULT);
            st.quit = signal::sigaction(signal::SIGQUIT, Some(&ign)).unwrap_or(signal::KSigaction::DEFAULT);
        }
        st.refs += 1;
    });
    let (intr_handler, quit_handler) = SYSTEM.with(|st| (st.intr.handler, st.quit.handler));
    let omask = signal::sigprocmask(signal::SIG_BLOCK, Some(signal::bit(signal::SIGCHLD))).unwrap_or(0);

    let mut attr = spawn::ZERO_ATTR;
    attr.flags = (spawn::POSIX_SPAWN_SETSIGDEF | spawn::POSIX_SPAWN_SETSIGMASK) as core::ffi::c_short;
    attr.ss.val[0] = omask;
    if intr_handler != signal::SIG_IGN {
        attr.sd.val[0] |= signal::bit(signal::SIGINT);
    }
    if quit_handler != signal::SIG_IGN {
        attr.sd.val[0] |= signal::bit(signal::SIGQUIT);
    }
    let sh = c"/bin/sh".as_ptr();
    let argv: [*const c_char; 5] = [c"sh".as_ptr(), c"-c".as_ptr(), c"--".as_ptr(), cmd.as_ptr(), core::ptr::null()];
    let envp = unsafe { rusty_libc_core::env::block() } as *const *const c_char;

    let mut pid: c_int = 0;
    let ret = unsafe { spawn::spawnix(&mut pid, sh, core::ptr::null(), &attr, argv.as_ptr(), envp, false, false) };
    let result = if ret == 0 {
        unsafe {
            rusty_libc_core::cleanup::with(system_cancelled, pid as isize as *mut c_void, || loop {
                match unistd::waitpid(pid, 0) {
                    Ok((p, status)) if p == pid => break Ok(status),
                    Ok(_) => break Err(Errno(EINVAL)),
                    Err(Errno(EINTR)) => continue,
                    Err(e) => break Err(e),
                }
            })
        }
    } else if ret == EAGAIN || ret == ENOMEM {
        Err(Errno(ret))
    } else {
        Ok(127 << 8)
    };

    system_release();
    let _ = signal::sigprocmask(signal::SIG_SETMASK, Some(omask));
    if ret != 0 {
        errno::set(ret);
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn system(cmd: *const c_char) -> c_int {
    let cmd = unsafe { rusty_libc_core::ffi::cstr(cmd) };
    match run_shell(cmd.unwrap_or(c"exit 0")) {
        Ok(st) => {
            if cmd.is_none() {
                (st == 0) as c_int
            } else {
                st
            }
        }
        Err(Errno(e)) => {
            errno::set(e);
            if cmd.is_none() { 0 } else { -1 }
        }
    }
}

fn rand64() -> u64 {
    let mut v = [0u8; 8];
    if crate::sys::getrandom(&mut v, GRND_NONBLOCK) == 8 {
        return u64::from_ne_bytes(v);
    }
    let t = crate::sys::rdtsc();
    let pid = unistd::getpid() as u64;
    let mut x = t ^ pid.rotate_left(32) ^ 0x9e37_79b9_7f4a_7c15;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x
}

const NAME_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    File,
    Dir,
    NoCreate,
}

pub struct Template<'a>(&'a mut [u8]);

impl<'a> Template<'a> {
    pub fn new(b: &'a mut [u8]) -> Option<Template<'a>> {
        let (&last, rest) = b.split_last()?;
        (last == 0 && !rest.contains(&0)).then_some(Template(b))
    }

    unsafe fn from_c(p: *mut u8, len: usize) -> Template<'a> {
        Template(unsafe { rusty_libc_core::ffi::bytes_mut(p, len + 1) })
    }

    fn bytes(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }

    fn as_cstr(&self) -> &CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(self.0) }
    }
}

pub fn gen_tempname(tmpl: &mut Template<'_>, suffix: usize, flags: c_int, kind: Kind) -> Result<c_int, Errno> {
    let len = tmpl.bytes().len();
    if len < 6 + suffix {
        return Err(Errno(EINVAL));
    }
    let xs = len - 6 - suffix;
    if &tmpl.bytes()[xs..xs + 6] != b"XXXXXX" {
        return Err(Errno(EINVAL));
    }
    for _ in 0..238_328 {
        let mut v = rand64();
        for c in &mut tmpl.0[xs..xs + 6] {
            *c = NAME_CHARS[(v % 62) as usize];
            v /= 62;
        }
        let path = tmpl.as_cstr();
        match kind {
            Kind::File => {
                let fl = (flags & !O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL;
                match crate::sys::open(path, fl, 0o600) {
                    Ok(fd) => return Ok(fd),
                    Err(Errno(EEXIST)) => {}
                    Err(e) => return Err(e),
                }
            }
            Kind::Dir => match raw_err(crate::sys::mkdir(path, 0o700)) {
                None => return Ok(0),
                Some(EEXIST) => {}
                Some(e) => return Err(Errno(e)),
            },
            Kind::NoCreate => {
                let mut st = [0u64; 18];
                match raw_err(crate::sys::lstat(path, &mut st)) {
                    Some(ENOENT) => return Ok(0),
                    Some(e) if e != EEXIST => return Err(Errno(e)),
                    _ => {}
                }
            }
        }
    }
    Err(Errno(EEXIST))
}

unsafe fn tempname_c(tmpl: *mut c_char, suffix: usize, flags: c_int, kind: Kind) -> c_int {
    if tmpl.is_null() {
        return fail(EINVAL);
    }
    let len = unsafe { rusty_libc_core::ffi::cstr_len(tmpl) };
    let mut t = unsafe { Template::from_c(tmpl.cast(), len) };
    match gen_tempname(&mut t, suffix, flags, kind) {
        Ok(v) => v,
        Err(Errno(e)) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    unsafe { tempname_c(template, 0, 0, Kind::File) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { tempname_c(template, 0, flags, Kind::File) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int {
    if suffixlen < 0 {
        return fail(EINVAL);
    }
    unsafe { tempname_c(template, suffixlen as usize, 0, Kind::File) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    if suffixlen < 0 {
        return fail(EINVAL);
    }
    unsafe { tempname_c(template, suffixlen as usize, flags, Kind::File) }
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
    if unsafe { tempname_c(template, 0, 0, Kind::Dir) } < 0 { null_mut() } else { template }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    if unsafe { tempname_c(template, 0, 0, Kind::NoCreate) } < 0 && !template.is_null() {
        unsafe { template.write(0) };
    }
    template
}

fn pop_component(b: &mut Buf) {
    let s = b.slice();
    let mut i = s.len();
    while i > 1 && s[i - 1] != b'/' {
        i -= 1;
    }
    let n = if i > 1 { i - 1 } else { s.len().min(1) };
    b.truncate(n);
}

#[derive(Clone, Copy)]
enum Src {
    Path,
    Target(usize),
}

#[derive(Clone, Copy)]
struct Seg {
    src: Src,
    len: usize,
    pos: usize,
}

fn next_is_plain_name(w: &[u8], pos: usize) -> bool {
    let mut i = pos;
    while i < w.len() && w[i] == b'/' {
        i += 1;
    }
    let start = i;
    while i < w.len() && w[i] != b'/' {
        i += 1;
    }
    let name = &w[start..i];
    !name.is_empty() && name != b"." && name != b".." && name.len() < PATH_MAX
}

fn resolve(path: &[u8], rpath: &mut Buf) -> Result<(), i32> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let mut segs = [Seg { src: Src::Path, len: path.len(), pos: 0 }; MAXSYMLINKS as usize + 2];
    let mut nseg = 1usize;
    let mut targets = [const { Buf::new() }; MAXSYMLINKS as usize + 1];
    if path[0] == b'/' {
        if !rpath.push(b"/") {
            return Err(ENOMEM);
        }
    } else {
        if !rpath.reserve(PATH_MAX) {
            return Err(ENOMEM);
        }
        let room = rpath.spare_mut();
        let r = crate::sys::getcwd(&mut room[..PATH_MAX]);
        if let Some(e) = raw_err(r) {
            return Err(e);
        }
        if r == 0 || room[0] != b'/' {
            return Err(ENOENT);
        }
        rpath.set_len(r - 1);
    }
    let mut links = 0u32;
    loop {
        let top = &mut segs[nseg - 1];
        let w = match top.src {
            Src::Path => path,
            Src::Target(k) => &targets[k].slice()[..top.len],
        };
        while top.pos < w.len() && w[top.pos] == b'/' {
            top.pos += 1;
        }
        if top.pos >= w.len() {
            nseg -= 1;
            if nseg == 0 {
                break;
            }
            continue;
        }
        let start = top.pos;
        while top.pos < w.len() && w[top.pos] != b'/' {
            top.pos += 1;
        }
        let name = &w[start..top.pos];
        if name == b"." {
            continue;
        }
        if name == b".." {
            pop_component(rpath);
            continue;
        }
        if name.len() >= PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        if rpath.len() > 1 && !rpath.push(b"/") {
            return Err(ENOMEM);
        }
        let name_start = rpath.len();
        if !rpath.push(name) {
            return Err(ENOMEM);
        }
        let Some(cp) = rpath.cstr() else { return Err(ENOMEM) };
        let mut lb = Buf::new();
        let mut sb = [0u8; 256];
        let r = crate::sys::readlink(cp, &mut sb);
        let linklen = match raw_err(r) {
            Some(e) => Err(e),
            None if r < sb.len() => {
                if !lb.push(&sb[..r]) {
                    return Err(ENOMEM);
                }
                Ok(r)
            }
            None => {
                let mut size = 512usize;
                loop {
                    if !lb.reserve(size) {
                        return Err(ENOMEM);
                    }
                    let r = crate::sys::readlink(cp, &mut lb.spare_mut()[..size]);
                    match raw_err(r) {
                        Some(e) => break Err(e),
                        None if r < size => break Ok(r),
                        None => size *= 2,
                    }
                }
            }
        };
        match linklen {
            Ok(n) => {
                links += 1;
                if links > MAXSYMLINKS {
                    return Err(ELOOP);
                }
                lb.set_len(n);
                let absolute = lb.slice().first() == Some(&b'/');
                segs[nseg] = Seg { src: Src::Target(links as usize - 1), len: n, pos: 0 };
                nseg += 1;
                targets[links as usize - 1] = lb;
                if absolute {
                    rpath.truncate(0);
                    if !rpath.push(b"/") {
                        return Err(ENOMEM);
                    }
                } else {
                    rpath.truncate(name_start);
                    if rpath.len() > 1 {
                        rpath.truncate(rpath.len() - 1);
                    }
                }
            }
            Err(EINVAL) => {
                let more = segs[..nseg].iter().any(|g| g.pos < g.len);
                let top = segs[nseg - 1];
                let w = match top.src {
                    Src::Path => path,
                    Src::Target(k) => &targets[k].slice()[..top.len],
                };
                if more && !next_is_plain_name(w, top.pos) {
                    if !rpath.push(b"/") {
                        return Err(ENOMEM);
                    }
                    let r = match rpath.cstr() {
                        None => return Err(ENOMEM),
                        Some(cp) => {
                            let mut r = crate::sys::faccessat2(cp, 0, AT_EACCESS);
                            if raw_err(r) == Some(ENOSYS) {
                                r = if rusty_libc_core::lock::secure() {
                                    let mut st = [0u64; 18];
                                    crate::sys::stat_at(cp, &mut st)
                                } else {
                                    crate::sys::faccessat(cp, 0)
                                };
                            }
                            r
                        }
                    };
                    rpath.truncate(rpath.len() - 1);
                    if let Some(e) = raw_err(r) {
                        return Err(e);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    if rpath.len() == 0 {
        rpath.push(b"/");
    }
    Ok(())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    let Some(path) = (unsafe { rusty_libc_core::ffi::cstr(path) }) else {
        errno::set(EINVAL);
        return null_mut();
    };
    let path = path.to_bytes();
    if path.is_empty() {
        errno::set(ENOENT);
        return null_mut();
    }
    let mut rpath = Buf::new();
    let e = match resolve(path, &mut rpath) {
        Ok(()) if !resolved.is_null() && rpath.len() >= PATH_MAX => ENAMETOOLONG,
        Ok(()) => 0,
        Err(e) => e,
    };
    let n = rpath.len();
    if e != 0 {
        if !resolved.is_null() && (e == ENOENT || e == EACCES) && n < PATH_MAX {
            let out = unsafe { rusty_libc_core::ffi::bytes_mut(resolved.cast(), n + 1) };
            out[..n].copy_from_slice(rpath.slice());
            out[n] = 0;
        }
        errno::set(e);
        return null_mut();
    }
    let out: *mut u8 = if resolved.is_null() { crate::cmem::malloc(n + 1) } else { resolved.cast() };
    if out.is_null() {
        errno::set(ENOMEM);
        return null_mut();
    }
    let o = unsafe { rusty_libc_core::ffi::bytes_mut(out, n + 1) };
    o[..n].copy_from_slice(rpath.slice());
    o[n] = 0;
    out.cast()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    unsafe { realpath(path, null_mut()) }
}

pub fn loadavg(out: &mut [f64]) -> Result<usize, Errno> {
    let mut info = [0u64; 14];
    if let Some(e) = raw_err(crate::sys::sysinfo(&mut info)) {
        return Err(Errno(e));
    }
    let n = out.len().min(3);
    for (o, &l) in out[..n].iter_mut().zip(&info[1..4]) {
        *o = l as f64 / 65536.0;
    }
    Ok(n)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getloadavg(loadavg: *mut f64, nelem: c_int) -> c_int {
    let n = nelem.clamp(0, 3) as usize;
    let mut tmp = [0f64; 3];
    match self::loadavg(&mut tmp[..n]) {
        Ok(k) => {
            unsafe { rusty_libc_core::ffi::slice_mut(loadavg, k) }.copy_from_slice(&tmp[..k]);
            k as c_int
        }
        Err(Errno(e)) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_openpt(flags: c_int) -> c_int {
    match crate::sys::open(c"/dev/ptmx", flags, 0) {
        Ok(fd) => fd,
        Err(Errno(e)) => fail(e),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpt() -> c_int {
    posix_openpt(O_RDWR)
}

fn pty_number(fd: c_int) -> Result<u32, i32> {
    let mut n = 0i32;
    match raw_err(crate::sys::ioctl_int(fd, TIOCGPTN, &mut n)) {
        None => Ok(n as u32),
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
    let mut zero = 0i32;
    match raw_err(crate::sys::ioctl_int(fd, TIOCSPTLCK, &mut zero)) {
        None => 0,
        Some(ENOTTY) => fail(EINVAL),
        Some(e) => fail(e),
    }
}

pub fn pts_name(fd: c_int) -> Result<([u8; 20], usize), c_int> {
    let n = match pty_number(fd) {
        Ok(n) => n,
        Err(e) => {
            errno::set(e);
            return Err(e);
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
    let mut out = [0u8; 20];
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..prefix.len() + nd].copy_from_slice(&digits[i..]);
    Ok((out, prefix.len() + nd + 1))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let (name, n) = match pts_name(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if buflen < n {
        errno::set(ERANGE);
        return ERANGE;
    }
    unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast(), n) }.copy_from_slice(&name[..n]);
    0
}

static PTSNAME_BUF: rusty_libc_core::SyncCell<[u8; 32]> = rusty_libc_core::SyncCell::new([0; 32]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let Ok((name, n)) = pts_name(fd) else { return null_mut() };
    unsafe { PTSNAME_BUF.with_unsync(|b| b[..n].copy_from_slice(&name[..n])) };
    PTSNAME_BUF.as_ptr().cast()
}

pub struct SubOpt {
    pub found: c_int,
    pub value_at: Option<usize>,
    pub end: usize,
    pub comma: bool,
}

pub fn find_subopt<'t>(z: ZStr<'_>, mut token: impl FnMut(usize) -> Option<&'t [u8]>) -> SubOpt {
    let mut e = z;
    while !e.at_end() && e.cur() != b',' {
        e.bump();
    }
    let text = e.scanned();
    let namelen = text.iter().position(|&c| c == b'=').unwrap_or(text.len());
    let name = &text[..namelen];
    let mut cnt = 0;
    let mut found = -1;
    while let Some(t) = token(cnt) {
        if t == name {
            found = cnt as c_int;
            break;
        }
        cnt += 1;
    }
    let value_at = if found >= 0 && namelen != text.len() { Some(namelen + 1) } else { None };
    SubOpt { found, value_at, end: text.len(), comma: !e.at_end() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsubopt(optionp: *mut *mut c_char, tokens: *const *mut c_char, valuep: *mut *mut c_char) -> c_int {
    let start = unsafe { optionp.read() };
    let z = unsafe { ZStr::new(start.cast::<u8>()) };
    if z.at_end() {
        return -1;
    }
    let r = find_subopt(z, |i| {
        let t = unsafe { tokens.wrapping_add(i).read() };
        unsafe { rusty_libc_core::ffi::cstr(t) }.map(CStr::to_bytes)
    });
    let value = if r.found < 0 {
        start
    } else {
        r.value_at.map_or(null_mut(), |v| start.wrapping_add(v))
    };
    unsafe { valuep.write(value) };
    let mut next = start.wrapping_add(r.end);
    if r.comma {
        unsafe { next.write(0) };
        next = next.wrapping_add(1);
    }
    unsafe { optionp.write(next) };
    r.found
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rpmatch(response: *const c_char) -> c_int {
    match unsafe { ZStr::new(response.cast::<u8>()) }.cur() {
        b'y' | b'Y' => 1,
        b'n' | b'N' => 0,
        _ => -1,
    }
}

const A64_DIGITS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[inline(always)]
fn a64_value(c: u8) -> Option<u32> {
    match c {
        b'.' | b'/' | b'0'..=b'9' => Some(u32::from(c - b'.')),
        b'A'..=b'Z' => Some(u32::from(c - b'A') + 12),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 38),
        _ => None,
    }
}

pub fn a64l_z(mut z: ZStr<'_>) -> c_long {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..6 {
        match a64_value(z.cur()) {
            Some(v) => {
                result |= v << shift;
                shift += 6;
                z.bump();
            }
            None => break,
        }
    }
    result as c_long
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    a64l_z(unsafe { ZStr::new(s.cast::<u8>()) })
}

static L64A_BUF: rusty_libc_core::SyncCell<[u8; 7]> = rusty_libc_core::SyncCell::new([0; 7]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn l64a(n: c_long) -> *mut c_char {
    let mut m = (n as u64 & 0xffff_ffff) as u32;
    unsafe {
        L64A_BUF.with_unsync(|b| {
            let mut i = 0;
            while m > 0 {
                b[i] = A64_DIGITS[(m & 63) as usize];
                m >>= 6;
                i += 1;
            }
            b[i] = 0;
        })
    };
    L64A_BUF.as_ptr().cast()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ttyslot() -> c_int {
    for fd in 0..3u8 {
        if !unistd::isatty(fd as i32) {
            continue;
        }
        let mut link = *b"/proc/self/fd/0\0";
        link[13] = b'0' + fd;
        let Ok(link) = CStr::from_bytes_with_nul(&link) else { return 0 };
        let mut name = [0u8; 256];
        let r = crate::sys::readlink(link, &mut name);
        if raw_err(r).is_some() {
            return 0;
        }
        let full = &name[..r];
        let last = match full.iter().rposition(|&c| c == b'/') {
            Some(i) => &full[i + 1..],
            None => full,
        };
        let Ok(f) = crate::sys::open(c"/etc/ttys", 0, 0) else { return 0 };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn on_exit(func: Option<unsafe extern "C" fn(c_int, *mut c_void)>, arg: *mut c_void) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::OnExit(func, arg)) { 0 } else { fail(ENOMEM) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn at_quick_exit(func: Option<extern "C" fn()>) -> c_int {
    at_quick_exit_dso(func, 0)
}

pub fn at_quick_exit_dso(func: Option<extern "C" fn()>, dso: usize) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::Quick(func, dso)) { 0 } else { fail(ENOMEM) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn quick_exit(status: c_int) -> ! {
    process::exit_lock();
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

