//! stdlib.h: running commands (system), temporary files and directories, realpath, load average,
//! pseudo-terminals, getsubopt, rpmatch, a64l/l64a, ttyslot, exit handlers with arguments,
//! quick_exit and the C23 allocation helpers.
//!
//! Shape (BRIEF-UNSAFE U2): each C function converts its pointer arguments once (C strings to `&CStr`/[`ZStr`], buffers to
//! slices, out-parameters to references) and the work is safe code: path resolution on byte slices and an owned
//! [`Buf`], temporary names on the template's bytes, system calls through [`crate::sys`]. `system`'s shared signal
//! dispositions sit in a `Locked`; `ptsname`'s buffer in a `SyncCell` (POSIX lets it be non-thread-safe, as `l64a`).
//! Still unsafe: the pointer conversions, `posix_spawn` with its C argument vector, the cancellation cleanup
//! registration, the environment block, and `free`.
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

// ---------------------------------------------------------------- growable byte buffer

/// A byte buffer on the malloc heap (this crate has no `alloc`) whose contents never hold a NUL (every way in checks the
/// bytes it adds), so they can always be handed to the kernel as a C string.
struct Buf(CVec<u8>);

impl Buf {
    const fn new() -> Buf {
        Buf(CVec::new())
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    /// Room for `extra` more bytes plus a NUL.
    fn reserve(&mut self, extra: usize) -> bool {
        let Some(need) = self.len().checked_add(extra).and_then(|n| n.checked_add(1)) else { return false };
        if need <= self.0.capacity() {
            return true;
        }
        self.0.reserve_total(need.max(self.0.capacity() * 2).max(64))
    }
    /// Append `b` (false when out of memory, or when `b` holds a NUL, which no path or link target does).
    fn push(&mut self, b: &[u8]) -> bool {
        !b.contains(&0) && self.reserve(b.len()) && self.0.extend_with(b, |n, _| n)
    }
    fn slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    fn truncate(&mut self, n: usize) {
        self.0.truncate(n);
    }
    /// The free room after the contents, for a system call to write into.
    fn spare_mut(&mut self) -> &mut [u8] {
        self.0.spare_mut()
    }
    /// Make the first `n` bytes the contents after a system call wrote the new ones through `spare_mut` (cut at a NUL
    /// among them, which the kernel never writes there: the contents stay NUL-free).
    fn set_len(&mut self, n: usize) {
        let old = self.len();
        self.0.set_len_written(n);
        if let Some(i) = self.0.as_slice().get(old..).and_then(|new| new.iter().position(|&c| c == 0)) {
            self.0.truncate(old + i);
        }
    }
    /// The contents as a C string (NUL written after the end); None when out of memory.
    fn cstr(&mut self) -> Option<&CStr> {
        if !self.reserve(0) {
            return None;
        }
        let b = self.0.with_nul()?;
        // SAFETY: the contents hold no NUL (the type's invariant) and `with_nul` put one right after them.
        Some(unsafe { CStr::from_bytes_with_nul_unchecked(b) })
    }
}

// ---------------------------------------------------------------- system

/// The signal dispositions system() found, shared by the threads that run it at the same time (glibc's
/// `intr`, `quit`, `sa_refcntr` and `lock`): the first caller ignores SIGINT and SIGQUIT and the last
/// one to finish puts them back, whichever thread that is.
struct SystemState {
    refs: i32,
    intr: signal::KSigaction,
    quit: signal::KSigaction,
}

static SYSTEM: rusty_libc_core::lock::Locked<SystemState> =
    rusty_libc_core::lock::Locked::new(SystemState { refs: 0, intr: signal::KSigaction::DEFAULT, quit: signal::KSigaction::DEFAULT });

/// The last user of the shared dispositions puts them back.
fn system_release() {
    SYSTEM.with(|st| {
        st.refs -= 1;
        if st.refs == 0 {
            let _ = signal::sigaction(signal::SIGINT, Some(&st.intr));
            let _ = signal::sigaction(signal::SIGQUIT, Some(&st.quit));
        }
    });
}

/// Cancellation inside `system` (glibc's `cancel_handler`): the child is killed and collected and the
/// signal dispositions are given back, so a cancelled `system` leaves no shell running behind it.
extern "C" fn system_cancelled(arg: *mut c_void) {
    let pid = arg as isize as i32;
    crate::sys::kill(pid, 9);
    // (this thread is ending: the wait is no longer a cancellation point)
    while let Err(Errno(EINTR)) = unistd::waitpid(pid, 0) {}
    system_release();
}

/// system(3) core: run `/bin/sh -c -- cmd` and wait for it; returns the wait status, or Err(errno) when no child
/// could be made or waited for. As glibc 2.43's do_system: the shell is started with posix_spawn (clone3 with
/// CLONE_VM | CLONE_VFORK: nothing of the caller is copied, so a large caller costs no more than a small one, where fork
/// copied its page tables); SIGCHLD is blocked and SIGINT/SIGQUIT are ignored in the caller meanwhile; the child gets
/// the caller's signal mask back (spawn attribute) and SIGINT/SIGQUIT at their default action unless the caller already
/// ignored them (sigdefault). When the shell cannot be run the status is "exited with 127" and errno is the reason
/// (EAGAIN/ENOMEM: no child, Err). A thread cancelled while it waits kills the child (see `system_cancelled`).
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
    // SAFETY: reading the environment block pointer (the child gets it as its envp).
    let envp = unsafe { rusty_libc_core::env::block() } as *const *const c_char;

    let mut pid: c_int = 0;
    // SAFETY: `pid`, `attr` and the NULL-terminated `argv` of C strings are ours and live through the call; `envp` is the
    // process environment (NULL or a NULL-terminated array, the C contract); no file actions.
    let ret = unsafe { spawn::spawnix(&mut pid, sh, core::ptr::null(), &attr, argv.as_ptr(), envp, false, false) };
    let result = if ret == 0 {
        // SAFETY: system_cancelled may run at the waitpid cancellation point: it only needs the pid, carried in `arg`.
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
        // POSIX: no child process could be made
        Err(Errno(ret))
    } else {
        // POSIX: the shell could not be run, as if it had exited with 127
        Ok(127 << 8)
    };

    system_release();
    let _ = signal::sigprocmask(signal::SIG_SETMASK, Some(omask));
    if ret != 0 {
        // (glibc sets errno to the spawn error in both failure cases)
        errno::set(ret);
    }
    result
}

/// system(3). With a NULL command: nonzero if a shell is available (it runs `exit 0` to find out,
/// as glibc does).
///
/// # Safety
/// `cmd` is NULL or a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn system(cmd: *const c_char) -> c_int {
    // SAFETY: NULL or a C string (the caller's contract).
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

// ---------------------------------------------------------------- temporary names

/// 64 random bits (getrandom without blocking; if that fails, a mix of the cycle counter and the
/// pid, which is enough to vary names between attempts).
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

/// What `gen_tempname` makes.
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    File,
    Dir,
    NoCreate,
}

/// A writable template: the bytes of a C string and its NUL, with no other NUL (so it is always a valid C string; only
/// letters and digits are written into it).
pub struct Template<'a>(&'a mut [u8]);

impl<'a> Template<'a> {
    /// `b` as a template: it must end with its only NUL.
    pub fn new(b: &'a mut [u8]) -> Option<Template<'a>> {
        let (&last, rest) = b.split_last()?;
        (last == 0 && !rest.contains(&0)).then_some(Template(b))
    }

    /// The template at a C string whose length is known.
    ///
    /// # Safety
    /// `p` points to `len` writable bytes that are not NUL followed by a NUL, valid and not otherwise used for `'a`.
    unsafe fn from_c(p: *mut u8, len: usize) -> Template<'a> {
        // SAFETY: forwarded contract.
        Template(unsafe { rusty_libc_core::ffi::bytes_mut(p, len + 1) })
    }

    /// The template without its NUL.
    fn bytes(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }

    fn as_cstr(&self) -> &CStr {
        // SAFETY: the bytes end with their only NUL (the type's invariant: checked or vouched for when made, and only
        // non-NUL bytes are written).
        unsafe { CStr::from_bytes_with_nul_unchecked(self.0) }
    }
}

/// Fill the six X's of the template `tmpl` (the X's are followed by `suffix` more bytes) until the system accepts a
/// name. Returns the fd for `File`, 0 otherwise, or Err(errno).
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
            *c = NAME_CHARS[(v % 62) as usize]; // never NUL: the template stays a C string
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
                    _ => {} // the name exists: try another
                }
            }
        }
    }
    Err(Errno(EEXIST))
}

/// The C side of the mkstemp family: the template made once, then `gen_tempname`.
///
/// # Safety
/// `tmpl` is NULL (EINVAL) or a writable C string.
unsafe fn tempname_c(tmpl: *mut c_char, suffix: usize, flags: c_int, kind: Kind) -> c_int {
    if tmpl.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: a C string (the caller's contract), not NULL.
    let len = unsafe { rusty_libc_core::ffi::cstr_len(tmpl) };
    // SAFETY: the `len` bytes before the NUL are not NUL (strlen) and are writable and ours for the call (the caller's
    // contract).
    let mut t = unsafe { Template::from_c(tmpl.cast(), len) };
    match gen_tempname(&mut t, suffix, flags, kind) {
        Ok(v) => v,
        Err(Errno(e)) => fail(e),
    }
}

/// mkstemp(3): replace the trailing XXXXXX of `template` and create the file (mode 0600, O_EXCL).
///
/// # Safety
/// `template` is a writable C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { tempname_c(template, 0, 0, Kind::File) }
}

/// mkostemp(3): like `mkstemp` with extra open flags (O_CLOEXEC, O_APPEND, O_SYNC, ...).
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { tempname_c(template, 0, flags, Kind::File) }
}

/// mkstemps(3): the six X's are followed by `suffixlen` fixed bytes.
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int {
    if suffixlen < 0 {
        return fail(EINVAL);
    }
    // SAFETY: the caller's contract.
    unsafe { tempname_c(template, suffixlen as usize, 0, Kind::File) }
}

/// mkostemps(3).
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    if suffixlen < 0 {
        return fail(EINVAL);
    }
    // SAFETY: the caller's contract.
    unsafe { tempname_c(template, suffixlen as usize, flags, Kind::File) }
}

/// The 64-bit names are the same functions (file offsets are 64-bit already).
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp64(template: *mut c_char) -> c_int {
    // SAFETY: the same contract.
    unsafe { mkstemp(template) }
}

/// # Safety
/// As `mkostemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp64(template: *mut c_char, flags: c_int) -> c_int {
    // SAFETY: the same contract.
    unsafe { mkostemp(template, flags) }
}

/// # Safety
/// As `mkstemps`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps64(template: *mut c_char, suffixlen: c_int) -> c_int {
    // SAFETY: the same contract.
    unsafe { mkstemps(template, suffixlen) }
}

/// # Safety
/// As `mkostemps`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps64(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    // SAFETY: the same contract.
    unsafe { mkostemps(template, suffixlen, flags) }
}

/// mkdtemp(3): create a directory (mode 0700); returns `template` or NULL.
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    // SAFETY: the caller's contract.
    if unsafe { tempname_c(template, 0, 0, Kind::Dir) } < 0 { null_mut() } else { template }
}

/// mktemp(3) (unsafe by design: the name is free when returned, not reserved). On failure the
/// template becomes the empty string.
///
/// # Safety
/// As `mkstemp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    // SAFETY: the caller's contract.
    if unsafe { tempname_c(template, 0, 0, Kind::NoCreate) } < 0 && !template.is_null() {
        // SAFETY: a writable C string (the caller's contract), not NULL.
        unsafe { template.write(0) };
    }
    template
}

// ---------------------------------------------------------------- realpath

/// Drop the last component of an absolute path in `b` (never past the root).
fn pop_component(b: &mut Buf) {
    let s = b.slice();
    let mut i = s.len();
    while i > 1 && s[i - 1] != b'/' {
        i -= 1;
    }
    let n = if i > 1 { i - 1 } else { s.len().min(1) };
    b.truncate(n);
}

/// Where a stretch of text that `resolve` still has to walk lives: the argument, or the target of the n-th symlink.
#[derive(Clone, Copy)]
enum Src {
    Path,
    Target(usize),
}

/// A stretch of text that `resolve` still has to walk (see there).
#[derive(Clone, Copy)]
struct Seg {
    src: Src,
    len: usize,
    pos: usize,
}

/// Does the text still to resolve in `w` from `pos` continue with an ordinary component (not `.`, `..` or only slashes)?
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

/// Resolve `path` into `rpath` (symlinks, `.` and `..`); on error `rpath` holds the part resolved
/// so far (including the component that failed), as glibc leaves it in a caller's buffer. The working directory of a relative
/// path is read straight into `rpath`: a PATH_MAX buffer on the stack would sit in realpath's frame for every path (glibc's
/// stdlib/tst-canon-bz26341 leaves realpath about 9 KiB of stack in a thread).
fn resolve(path: &[u8], rpath: &mut Buf) -> Result<(), i32> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    // The text still to resolve: the argument itself (not copied: it can be gigabytes long), then, innermost last, the target of
    // each symlink met on the way. A target is followed by what was left of the text it replaced, which is that segment below
    // it: a component never spans two segments (the left-over text starts at a '/' or is empty).
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
        // no file name has PATH_MAX bytes: do not copy it (glibc's readlink answers the same)
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
        // read the link, growing the buffer until it fits
        // (first into a stack buffer: most components are not links, and a link is usually short)
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
                // the target is resolved next, then the rest of the path
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
                        rpath.truncate(rpath.len() - 1); // drop the slash we added
                    }
                }
            }
            Err(EINVAL) => {
                // not a symlink; if more path follows it must be a directory
                // (when a plain name follows, the next readlink answers ENOTDIR itself: no stat)
                let more = segs[..nseg].iter().any(|g| g.pos < g.len);
                let top = segs[nseg - 1];
                let w = match top.src {
                    Src::Path => path,
                    Src::Target(k) => &targets[k].slice()[..top.len],
                };
                if more && !next_is_plain_name(w, top.pos) {
                    // "name/" accessible answers like stat plus a directory test (ENOENT, EACCES, and ENOTDIR for a
                    // non-directory) without filling in a stat buffer. The call glibc's dir_check makes:
                    // faccessat2(AT_FDCWD, "name/", F_OK, AT_EACCESS), then (ENOSYS) faccessat, or fstatat in a
                    // secure program (its __faccessat): a seccomp allowlist made from glibc's calls has no access
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

/// realpath(3). With a NULL `resolved` the result is malloc'd (any length); otherwise `resolved`
/// must hold PATH_MAX bytes, and a longer result is ENAMETOOLONG. On failure with a buffer, the
/// buffer holds the part of the path resolved so far (ENOENT and EACCES only, as in glibc).
///
/// # Safety
/// `path` is a C string; `resolved` is NULL or a PATH_MAX buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    // SAFETY: NULL or a C string (the caller's contract).
    let Some(path) = (unsafe { rusty_libc_core::ffi::cstr(path) }) else {
        errno::set(EINVAL);
        return null_mut();
    };
    let path = path.to_bytes();
    if path.is_empty() {
        errno::set(ENOENT); // the buffer is left alone
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
        // like glibc, a caller's buffer gets the partial path only for ENOENT and EACCES
        if !resolved.is_null() && (e == ENOENT || e == EACCES) && n < PATH_MAX {
            // SAFETY: `resolved` holds PATH_MAX bytes (the caller's contract) and n + 1 <= PATH_MAX.
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
    // SAFETY: a fresh block of n + 1 bytes, or the caller's PATH_MAX buffer with n < PATH_MAX.
    let o = unsafe { rusty_libc_core::ffi::bytes_mut(out, n + 1) };
    o[..n].copy_from_slice(rpath.slice());
    o[n] = 0;
    out.cast()
}

/// canonicalize_file_name(3): `realpath(path, NULL)`.
///
/// # Safety
/// `path` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    // SAFETY: the same contract.
    unsafe { realpath(path, null_mut()) }
}

// ---------------------------------------------------------------- load average

/// The 1, 5 and 15 minute load averages (from sysinfo(2), as glibc does) into `out` (at most 3 are written); how many.
pub fn loadavg(out: &mut [f64]) -> Result<usize, Errno> {
    let mut info = [0u64; 14]; // struct sysinfo: uptime, loads[3], ... (112 bytes)
    if let Some(e) = raw_err(crate::sys::sysinfo(&mut info)) {
        return Err(Errno(e));
    }
    let n = out.len().min(3);
    for (o, &l) in out[..n].iter_mut().zip(&info[1..4]) {
        *o = l as f64 / 65536.0;
    }
    Ok(n)
}

/// The 1, 5 and 15 minute load averages, at most `nelem` of them. Returns how many were stored, or -1.
///
/// # Safety
/// `loadavg` has room for `nelem` (at most 3 are written) doubles.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getloadavg(loadavg: *mut f64, nelem: c_int) -> c_int {
    let n = nelem.clamp(0, 3) as usize;
    let mut tmp = [0f64; 3];
    match self::loadavg(&mut tmp[..n]) {
        Ok(k) => {
            // SAFETY: `loadavg` has room for `nelem >= k` doubles (the caller's contract); written only after sysinfo
            // succeeded, as before.
            unsafe { rusty_libc_core::ffi::slice_mut(loadavg, k) }.copy_from_slice(&tmp[..k]);
            k as c_int
        }
        Err(Errno(e)) => fail(e),
    }
}

// ---------------------------------------------------------------- pseudo-terminals

/// posix_openpt(3): open a new pseudo-terminal master (/dev/ptmx).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_openpt(flags: c_int) -> c_int {
    match crate::sys::open(c"/dev/ptmx", flags, 0) {
        Ok(fd) => fd,
        Err(Errno(e)) => fail(e),
    }
}

/// getpt(3): `posix_openpt(O_RDWR)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpt() -> c_int {
    posix_openpt(O_RDWR)
}

/// The kernel-side check shared by grantpt and ptsname: the slave number of a master fd.
fn pty_number(fd: c_int) -> Result<u32, i32> {
    let mut n = 0i32;
    match raw_err(crate::sys::ioctl_int(fd, TIOCGPTN, &mut n)) {
        None => Ok(n as u32),
        Some(e) => Err(e),
    }
}

/// grantpt(3): the kernel gives the slave the right owner and mode when it is created, so this
/// only checks that `fd` is a pty master (errors as POSIX: EINVAL instead of ENOTTY).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn grantpt(fd: c_int) -> c_int {
    match pty_number(fd) {
        Ok(_) => 0,
        Err(ENOTTY) => fail(EINVAL),
        Err(e) => fail(e),
    }
}

/// unlockpt(3): clear the lock on the slave side.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn unlockpt(fd: c_int) -> c_int {
    let mut zero = 0i32;
    match raw_err(crate::sys::ioctl_int(fd, TIOCSPTLCK, &mut zero)) {
        None => 0,
        Some(ENOTTY) => fail(EINVAL),
        Some(e) => fail(e),
    }
}

/// "/dev/pts/N" with its NUL for the master `fd`, and its length (with the NUL); on error errno is set and returned
/// (glibc leaves the failed ioctl's error in errno as well as returning it).
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

/// ptsname_r(3): "/dev/pts/N" into `buf`; returns 0 or an error number (also ERANGE when `buflen`
/// is too small, which is the only case where errno is set).
///
/// # Safety
/// `buf` has room for `buflen` bytes.
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
    // SAFETY: `buf` has room for `buflen >= n` bytes (the caller's contract).
    unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast(), n) }.copy_from_slice(&name[..n]);
    0
}

/// ptsname's result buffer: only ptsname touches it, and ptsname need not be thread-safe (POSIX), as l64a.
static PTSNAME_BUF: rusty_libc_core::SyncCell<[u8; 32]> = rusty_libc_core::SyncCell::new([0; 32]);

/// ptsname(3): like `ptsname_r` into a static buffer; NULL on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let Ok((name, n)) = pts_name(fd) else { return null_mut() };
    // SAFETY: only ptsname touches the buffer; two threads calling it at once race on the shared result, which is the C
    // caller's to avoid (POSIX: not thread-safe), as in glibc; the closure does not come back here.
    unsafe { PTSNAME_BUF.with_unsync(|b| b[..n].copy_from_slice(&name[..n])) };
    PTSNAME_BUF.as_ptr().cast()
}

// ---------------------------------------------------------------- getsubopt

/// What getsubopt found in the suboption at the start of a string (see [`getsubopt`]).
pub struct SubOpt {
    /// The index in `tokens`, or -1.
    pub found: c_int,
    /// Where the value starts (after `=`), when there is one and the name was found.
    pub value_at: Option<usize>,
    /// Where the suboption ends (a `,` or the NUL).
    pub end: usize,
    /// Whether it ends at a `,` (which the caller cuts to a NUL).
    pub comma: bool,
}

/// getsubopt on a cursor: look at the suboption `name[=value]` at the start of `z` (not empty) and find `name` among the
/// tokens (`token(i)` is the i-th token, None after the last).
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

/// getsubopt(3): take the next `name[=value]` out of the comma-separated `*optionp` (cutting the
/// string in place), return its index in `tokens`, and set `*valuep` to the value or NULL. An
/// unknown name gives -1 with `*valuep` pointing at the whole unknown suboption. `*optionp` moves
/// past the comma.
///
/// # Safety
/// `*optionp` is a writable C string; `tokens` is a NULL-terminated array of C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsubopt(optionp: *mut *mut c_char, tokens: *const *mut c_char, valuep: *mut *mut c_char) -> c_int {
    // SAFETY: `optionp` points to the pointer to a writable C string (the caller's contract).
    let start = unsafe { optionp.read() };
    // SAFETY: as above.
    let z = unsafe { ZStr::new(start.cast::<u8>()) };
    if z.at_end() {
        return -1;
    }
    let r = find_subopt(z, |i| {
        // SAFETY: `tokens` is a NULL-terminated array (the caller's contract) and slot `i` is read only after slots
        // 0..i were seen not NULL.
        let t = unsafe { tokens.wrapping_add(i).read() };
        // SAFETY: NULL or a C string (the caller's contract).
        unsafe { rusty_libc_core::ffi::cstr(t) }.map(CStr::to_bytes)
    });
    let value = if r.found < 0 {
        start
    } else {
        r.value_at.map_or(null_mut(), |v| start.wrapping_add(v))
    };
    // SAFETY: `valuep` is writable (the caller's contract).
    unsafe { valuep.write(value) };
    let mut next = start.wrapping_add(r.end);
    if r.comma {
        // SAFETY: the `,` at `end` is a byte of the writable string (the caller's contract).
        unsafe { next.write(0) };
        next = next.wrapping_add(1);
    }
    // SAFETY: as for the first read.
    unsafe { optionp.write(next) };
    r.found
}

// ---------------------------------------------------------------- small functions

/// rpmatch(3) in the C locale (yes pattern `^[yY]`, no pattern `^[nN]`): 1, 0, or -1. Locale
/// support does not exist yet, so other locales' answers (like "oui") are not recognised.
///
/// # Safety
/// `response` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rpmatch(response: *const c_char) -> c_int {
    // SAFETY: a C string (the caller's contract).
    match unsafe { ZStr::new(response.cast::<u8>()) }.cur() {
        b'y' | b'Y' => 1,
        b'n' | b'N' => 0,
        _ => -1,
    }
}

// The a64l digit set is fixed by POSIX: "./0-9A-Za-z", value 0 to 63.
const A64_DIGITS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[inline(always)]
fn a64_value(c: u8) -> Option<u32> {
    // (the position in A64_DIGITS, by ranges instead of a search)
    match c {
        b'.' | b'/' | b'0'..=b'9' => Some(u32::from(c - b'.')),
        b'A'..=b'Z' => Some(u32::from(c - b'A') + 12),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 38),
        _ => None,
    }
}

/// a64l on a cursor: up to six base-64 digits (least significant first) to a 32-bit value.
pub fn a64l_z(mut z: ZStr<'_>) -> c_long {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..6 {
        match a64_value(z.cur()) {
            Some(v) => {
                result |= v << shift; // bits past 32 are dropped, as in glibc
                shift += 6;
                z.bump();
            }
            None => break,
        }
    }
    result as c_long
}

/// a64l(3): up to six base-64 digits (`./0-9A-Za-z`, least significant first) to a 32-bit value.
///
/// # Safety
/// `s` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    // SAFETY: a C string (the caller's contract).
    a64l_z(unsafe { ZStr::new(s.cast::<u8>()) })
}

/// l64a's result buffer (a `SyncCell`, U1 demonstration: the rule is l64a's own, see below).
static L64A_BUF: rusty_libc_core::SyncCell<[u8; 7]> = rusty_libc_core::SyncCell::new([0; 7]);

/// l64a(3): the low 32 bits of `n` as base-64 digits, in a static buffer ("" for 0).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn l64a(n: c_long) -> *mut c_char {
    let mut m = (n as u64 & 0xffff_ffff) as u32;
    // SAFETY: only l64a touches the buffer, and l64a need not be thread-safe (POSIX): as in glibc, two threads calling it
    // at once race on the shared result, which is the C caller's to avoid; the closure does not call l64a again.
    unsafe {
        L64A_BUF.with_unsync(|b| {
            // at most 6 digits for 32 bits, then the NUL: indices 0..=6
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

/// ttyslot(3): the line number in /etc/ttys of the terminal on stdin, stdout or stderr (the first
/// of them that is a terminal), or 0 (also when /etc/ttys does not exist, which is usual on Linux).
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

// ---------------------------------------------------------------- exit handlers

/// on_exit(3): register `func(status, arg)` to run at exit, in order with `atexit` handlers (last
/// registered runs first); `status` is the one `exit` was called with. Returns 0, or -1 if the
/// table is full.
///
/// # Safety
/// `func` must be callable with `arg`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn on_exit(func: Option<unsafe extern "C" fn(c_int, *mut c_void)>, arg: *mut c_void) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::OnExit(func, arg)) { 0 } else { fail(ENOMEM) }
}

/// at_quick_exit(C11): register a function for `quick_exit`. 0, or nonzero if the table is full.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn at_quick_exit(func: Option<extern "C" fn()>) -> c_int {
    at_quick_exit_dso(func, 0)
}

/// `__cxa_at_quick_exit(func, dso)`'s work: as `at_quick_exit`, with the handle of the object that registers (`__cxa_finalize`
/// of that object drops the handler without running it, so `quick_exit` never calls into an unloaded library).
pub fn at_quick_exit_dso(func: Option<extern "C" fn()>, dso: usize) -> c_int {
    let Some(func) = func else { process::exit_func_is_null() };
    if process::register(process::ExitFn::Quick(func, dso)) { 0 } else { fail(ENOMEM) }
}

/// quick_exit(C11): run the `at_quick_exit` functions (last registered first; one registered while they run is run next), then
/// end the process at once; no atexit handlers, no stdio flush, and (since glibc 2.24) no thread-local destructors: the old
/// quick_exit@GLIBC_2.10 runs those first (rusty-libc-cabi compat_shims). A second thread that calls it (or `exit`) waits.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn quick_exit(status: c_int) -> ! {
    process::exit_lock();
    process::finalize_quick();
    process::exit_now(status)
}

// ---------------------------------------------------------------- C23 allocation helpers

/// memalignment(C23): the largest power of two that divides the address (0 for NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn memalignment(p: *const c_void) -> usize {
    let a = p as usize;
    if a == 0 { 0 } else { 1usize << a.trailing_zeros() }
}

/// free_sized(C23): `free`; the size is only a hint.
///
/// # Safety
/// As `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn free_sized(ptr: *mut c_void, _size: usize) {
    // SAFETY: the caller's contract is free's.
    unsafe { rusty_libc_malloc::free(ptr) }
}

/// free_aligned_sized(C23): `free`; size and alignment are only hints.
///
/// # Safety
/// As `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn free_aligned_sized(ptr: *mut c_void, _alignment: usize, _size: usize) {
    // SAFETY: the caller's contract is free's.
    unsafe { rusty_libc_malloc::free(ptr) }
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::deref_addrof)]
mod tests {
    use super::*;
    use crate::env::test_lock;
    use std::ffi::{CStr, CString};
    use std::os::unix::fs::PermissionsExt;

    mod host {
        use core::ffi::{c_char, c_int, c_long, c_void};
        unsafe extern "C" {
            pub fn realpath(p: *const c_char, r: *mut c_char) -> *mut c_char;
            pub fn canonicalize_file_name(p: *const c_char) -> *mut c_char;
            pub fn getloadavg(a: *mut f64, n: c_int) -> c_int;
            pub fn ptsname_r(fd: c_int, buf: *mut c_char, n: usize) -> c_int;
            pub fn ptsname(fd: c_int) -> *mut c_char;
            pub fn grantpt(fd: c_int) -> c_int;
            pub fn unlockpt(fd: c_int) -> c_int;
            pub fn posix_openpt(f: c_int) -> c_int;
            pub fn getpt() -> c_int;
            pub fn getsubopt(o: *mut *mut c_char, t: *const *mut c_char, v: *mut *mut c_char) -> c_int;
            pub fn rpmatch(s: *const c_char) -> c_int;
            pub fn a64l(s: *const c_char) -> c_long;
            pub fn l64a(n: c_long) -> *mut c_char;
            pub fn ttyslot() -> c_int;
            pub fn mktemp(t: *mut c_char) -> *mut c_char;
            pub fn mkstemp(t: *mut c_char) -> c_int;
            pub fn mkstemps(t: *mut c_char, s: c_int) -> c_int;
            pub fn mkdtemp(t: *mut c_char) -> *mut c_char;
            pub fn system(c: *const c_char) -> c_int;
            pub fn free(p: *mut c_void);
            pub fn __errno_location() -> *mut c_int;
        }
    }

    fn herrno() -> i32 {
        unsafe { *host::__errno_location() }
    }
    fn hset(v: i32) {
        unsafe { *host::__errno_location() = v }
    }

    fn tmpdir(name: &str) -> String {
        let d = format!("/tmp/rusty-libc-stdlib-test-{}-{}", std::process::id(), name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    // ---------------------------------------------------------------- temporary names

    fn check_shape(name: &[u8], prefix: &[u8], suffix: &[u8]) {
        assert!(name.starts_with(prefix) && name.ends_with(suffix), "{:?}", String::from_utf8_lossy(name));
        assert_eq!(name.len(), prefix.len() + 6 + suffix.len());
        let mid = &name[prefix.len()..prefix.len() + 6];
        assert!(mid.iter().all(|c| c.is_ascii_alphanumeric()), "{mid:?}");
        assert_ne!(mid, b"XXXXXX");
    }

    fn cbuf(s: &str) -> Vec<u8> {
        CString::new(s).unwrap().into_bytes_with_nul()
    }

    fn text(b: &[u8]) -> &[u8] {
        &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
    }

    #[test]
    fn mkstemp_family_creates_files() {
        let _g = test_lock();
        let d = tmpdir("mk");
        unsafe {
            // plain mkstemp: shape, mode 0600, exists, open read-write
            let mut t = cbuf(&format!("{d}/fooXXXXXX"));
            let fd = mkstemp(t.as_mut_ptr().cast());
            assert!(fd >= 0);
            let name = String::from_utf8(text(&t).to_vec()).unwrap();
            check_shape(name.as_bytes(), format!("{d}/foo").as_bytes(), b"");
            let md = std::fs::metadata(&name).unwrap();
            assert!(md.is_file());
            assert_eq!(md.permissions().mode() & 0o7777, 0o600);
            assert_eq!(libc::write(fd, b"hi".as_ptr().cast(), 2), 2);
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
            let mut b = [0u8; 2];
            assert_eq!(libc::read(fd, b.as_mut_ptr().cast(), 2), 2);
            assert_eq!(&b, b"hi");
            libc::close(fd);

            // suffix variants
            let mut t = cbuf(&format!("{d}/aXXXXXX.txt"));
            let fd = mkstemps(t.as_mut_ptr().cast(), 4);
            assert!(fd >= 0);
            check_shape(text(&t), format!("{d}/a").as_bytes(), b".txt");
            assert!(std::path::Path::new(std::str::from_utf8(text(&t)).unwrap()).exists());
            libc::close(fd);

            // flags: close-on-exec and append are passed through
            let mut t = cbuf(&format!("{d}/fXXXXXX"));
            let fd = mkostemp(t.as_mut_ptr().cast(), libc::O_CLOEXEC | libc::O_APPEND);
            assert!(fd >= 0);
            assert_ne!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            assert_ne!(libc::fcntl(fd, libc::F_GETFL) & libc::O_APPEND, 0);
            libc::close(fd);
            let mut t = cbuf(&format!("{d}/gXXXXXXyz"));
            let fd = mkostemps(t.as_mut_ptr().cast(), 2, libc::O_CLOEXEC);
            assert!(fd >= 0);
            assert_ne!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            check_shape(text(&t), format!("{d}/g").as_bytes(), b"yz");
            libc::close(fd);

            // the 64-bit names
            let mut t = cbuf(&format!("{d}/s64XXXXXX"));
            let fd = mkstemp64(t.as_mut_ptr().cast());
            assert!(fd >= 0);
            libc::close(fd);
            let mut t = cbuf(&format!("{d}/o64XXXXXX"));
            let fd = mkostemp64(t.as_mut_ptr().cast(), 0);
            assert!(fd >= 0);
            libc::close(fd);
            let mut t = cbuf(&format!("{d}/p64XXXXXX.c"));
            let fd = mkstemps64(t.as_mut_ptr().cast(), 2);
            assert!(fd >= 0);
            libc::close(fd);
            let mut t = cbuf(&format!("{d}/q64XXXXXX.c"));
            let fd = mkostemps64(t.as_mut_ptr().cast(), 2, 0);
            assert!(fd >= 0);
            libc::close(fd);

            // names do not repeat
            let mut seen = std::collections::HashSet::new();
            for _ in 0..300 {
                let mut t = cbuf(&format!("{d}/uXXXXXX"));
                let fd = mkstemp(t.as_mut_ptr().cast());
                assert!(fd >= 0);
                libc::close(fd);
                assert!(seen.insert(text(&t).to_vec()));
            }
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn mkstemp_errors_match_glibc() {
        let _g = test_lock();
        let d = tmpdir("mke");
        std::fs::write(format!("{d}/afile"), b"x").unwrap();
        let cases: Vec<(String, i32)> = vec![
            ("".into(), 0),
            ("XXXXX".into(), 0),
            ("fooXXXXX".into(), 0),
            ("fooXXXXXX.txt".into(), 0),
            ("fooXXXXXXx".into(), 0),
            (format!("{d}/nonexistent/XXXXXX"), 0),
            (format!("{d}/afile/XXXXXX"), 0),
            (format!("{d}/XXXXXX"), -1),
            (format!("{d}/XXXXXX"), 100),
            (format!("{d}/aXXXXXX.txt"), 3),
            (format!("{d}/aXXXXXX.txt"), 5),
        ];
        unsafe {
            for (tmpl, suffix) in cases {
                let mut a = cbuf(&tmpl);
                let mut b = cbuf(&tmpl);
                errno::set(0);
                hset(0);
                let ra = mkstemps(a.as_mut_ptr().cast(), suffix);
                let rb = host::mkstemps(b.as_mut_ptr().cast(), suffix);
                assert_eq!(ra < 0, rb < 0, "{tmpl} {suffix}");
                if ra < 0 {
                    assert_eq!(errno::get(), herrno(), "errno for {tmpl:?} suffix {suffix}");
                    if errno::get() == EINVAL {
                        assert_eq!(a, b, "template changed for {tmpl:?}");
                    }
                } else {
                    libc::close(ra);
                    libc::close(rb);
                }
            }
            // mkstemp / mkostemp reject the same way
            for tmpl in ["abc", "XXXXXX.c", "ab"] {
                let (mut a, mut b) = (cbuf(tmpl), cbuf(tmpl));
                errno::set(0);
                hset(0);
                assert_eq!(mkstemp(a.as_mut_ptr().cast()), -1);
                assert_eq!(host::mkstemp(b.as_mut_ptr().cast()), -1);
                assert_eq!(errno::get(), herrno());
                assert_eq!(mkostemp(a.as_mut_ptr().cast(), 0), -1);
                assert_eq!(errno::get(), EINVAL);
            }
            // NULL template: EINVAL
            errno::set(0);
            assert_eq!(mkstemp(null_mut()), -1);
            assert_eq!(errno::get(), EINVAL);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn mkdtemp_and_mktemp() {
        let _g = test_lock();
        let d = tmpdir("mkd");
        unsafe {
            let mut t = cbuf(&format!("{d}/dirXXXXXX"));
            let r = mkdtemp(t.as_mut_ptr().cast());
            assert_eq!(r as *const u8, t.as_ptr());
            let name = std::str::from_utf8(text(&t)).unwrap().to_string();
            check_shape(name.as_bytes(), format!("{d}/dir").as_bytes(), b"");
            let md = std::fs::metadata(&name).unwrap();
            assert!(md.is_dir());
            assert_eq!(md.permissions().mode() & 0o7777, 0o700);

            for tmpl in ["abc", "XXXXX", &format!("{d}/nodir/XXXXXX"), &format!("{d}/dirXXXXXX.x")] {
                let (mut a, mut b) = (cbuf(tmpl), cbuf(tmpl));
                errno::set(0);
                hset(0);
                assert!(mkdtemp(a.as_mut_ptr().cast()).is_null());
                assert!(host::mkdtemp(b.as_mut_ptr().cast()).is_null());
                assert_eq!(errno::get(), herrno(), "{tmpl}");
            }

            // mktemp: a name that does not exist, nothing created
            let mut t = cbuf(&format!("{d}/mXXXXXX"));
            let r = mktemp(t.as_mut_ptr().cast());
            assert_eq!(r as *const u8, t.as_ptr());
            check_shape(text(&t), format!("{d}/m").as_bytes(), b"");
            assert!(!std::path::Path::new(std::str::from_utf8(text(&t)).unwrap()).exists());
            // failure empties the template, like glibc
            for tmpl in ["abc", "XXXXX", "fooXXXXXX.c"] {
                let (mut a, mut b) = (cbuf(tmpl), cbuf(tmpl));
                errno::set(0);
                hset(0);
                mktemp(a.as_mut_ptr().cast());
                host::mktemp(b.as_mut_ptr().cast());
                assert_eq!(text(&a), b"");
                assert_eq!(text(&b), b"");
                assert_eq!(errno::get(), herrno());
            }
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    // ---------------------------------------------------------------- realpath

    fn rp_ours(path: &CStr, buf: bool) -> (Option<Vec<u8>>, i32, Vec<u8>) {
        unsafe {
            let mut b = vec![0xAAu8; PATH_MAX];
            errno::set(0);
            let r = realpath(path.as_ptr(), if buf { b.as_mut_ptr().cast() } else { null_mut() });
            let e = errno::get();
            if r.is_null() {
                return (None, e, if buf { text(&b).to_vec() } else { vec![] });
            }
            let s = CStr::from_ptr(r).to_bytes().to_vec();
            if !buf {
                rusty_libc_malloc::free(r.cast());
            }
            (Some(s), 0, vec![])
        }
    }

    fn rp_host(path: &CStr, buf: bool) -> (Option<Vec<u8>>, i32, Vec<u8>) {
        unsafe {
            let mut b = vec![0xAAu8; PATH_MAX];
            hset(0);
            let r = host::realpath(path.as_ptr(), if buf { b.as_mut_ptr().cast() } else { null_mut() });
            let e = herrno();
            if r.is_null() {
                return (None, e, if buf { text(&b).to_vec() } else { vec![] });
            }
            let s = CStr::from_ptr(r).to_bytes().to_vec();
            if !buf {
                host::free(r.cast());
            }
            (Some(s), 0, vec![])
        }
    }

    fn compare_realpath(path: &str) {
        let c = CString::new(path).unwrap();
        for buf in [false, true] {
            let a = rp_ours(&c, buf);
            let b = rp_host(&c, buf);
            assert_eq!(a, b, "realpath({path:?}) buffer={buf}");
        }
    }

    fn make_tree(d: &str) {
        use std::os::unix::fs::symlink;
        std::fs::create_dir_all(format!("{d}/a/b/sub")).unwrap();
        std::fs::create_dir_all(format!("{d}/dir with space")).unwrap();
        std::fs::write(format!("{d}/a/b/file"), b"x").unwrap();
        symlink("a/b", format!("{d}/l1")).unwrap();
        symlink("a/../a/b", format!("{d}/l2")).unwrap();
        symlink(format!("{d}/a"), format!("{d}/abs")).unwrap();
        symlink("../l1", format!("{d}/a/up")).unwrap();
        symlink("loop2", format!("{d}/loop1")).unwrap();
        symlink("loop1", format!("{d}/loop2")).unwrap();
        symlink("self", format!("{d}/self")).unwrap();
        symlink("nowhere/x", format!("{d}/dangling")).unwrap();
        symlink("a/b/file", format!("{d}/tofile")).unwrap();
        symlink("./file", format!("{d}/a/b/rel")).unwrap();
        symlink("chain2", format!("{d}/chain1")).unwrap();
        symlink("chain3", format!("{d}/chain2")).unwrap();
        symlink("a", format!("{d}/chain3")).unwrap();
        symlink("/", format!("{d}/toroot")).unwrap();
        symlink("dir with space/..", format!("{d}/spacedot")).unwrap();
        // 30 links in a row resolve; 45 do not (the limit is 40)
        for i in 0..30 {
            symlink(format!("ok{}", i + 1), format!("{d}/ok{i}")).unwrap();
        }
        symlink("a", format!("{d}/ok30")).unwrap();
        for i in 0..45 {
            symlink(format!("far{}", i + 1), format!("{d}/far{i}")).unwrap();
        }
        symlink("a", format!("{d}/far45")).unwrap();
    }

    #[test]
    fn realpath_matches_glibc() {
        let _g = test_lock();
        let d = tmpdir("rp");
        let d = std::fs::canonicalize(&d).unwrap().to_string_lossy().into_owned();
        make_tree(&d);
        let rel: Vec<String> = vec![
            "a", "a/", "a/b/file", "a/b/file/", "a/b/file/..", "a/b/file/.", "a//b///./sub/..", "a/b/../..", "l1", "l1/", "l1/..",
            "l1/file", "l2", "l2/sub", "abs", "abs/b", "a/up", "a/up/file", "loop1", "loop1/x", "loop2", "self", "dangling", "dangling/x",
            "tofile", "tofile/", "tofile/x", "a/b/rel", "chain1", "chain1/b", "toroot", "toroot/tmp/..", "spacedot", "dir with space",
            "dir with space/", "nothere", "nothere/..", "nothere/x/y", "a/nothere", "a/b/../nothere", "ok0", "ok0/b/file", "far0", "far0/b",
            "far10", "far10/b", "far5", "far44", "far44/b", "ok29", ".", "..", "./a/./b/.", "a/b/sub/../../../a",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        for r in &rel {
            compare_realpath(&format!("{d}/{r}"));
        }
        for p in ["/", "//", "///", "/..", "/../..", "/tmp/../tmp", "/tmp//", "/proc/self/cwd", "", "/nonexistent", "/nonexistent/..", "/proc/self/exe"] {
            if p == "/proc/self/cwd" || p == "/proc/self/exe" {
                // same process, same answer
            }
            compare_realpath(p);
        }
        // a component longer than NAME_MAX
        compare_realpath(&format!("{d}/{}", "x".repeat(300)));
        compare_realpath(&format!("{d}/a/{}/..", "y".repeat(256)));
        // a very long input path whose result is short
        let long = format!("{d}/{}", "a/../".repeat(1500));
        compare_realpath(&long);
        let long = format!("{d}/{}b", "a/../".repeat(1500));
        compare_realpath(&long);
        // NULL path
        unsafe {
            errno::set(0);
            assert!(realpath(core::ptr::null(), null_mut()).is_null());
            assert_eq!(errno::get(), EINVAL);
            hset(0);
            assert!(host::realpath(core::ptr::null(), null_mut()).is_null());
            assert_eq!(herrno(), EINVAL);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn realpath_relative_paths_and_canonicalize() {
        let _g = test_lock();
        let d = tmpdir("rprel");
        let d = std::fs::canonicalize(&d).unwrap().to_string_lossy().into_owned();
        make_tree(&d);
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(format!("{d}/a")).unwrap();
        for p in ["b/file", "../l1", ".", "..", "b/../b/sub", "nothere", "up/file", "./b/", "../loop1", "../far0", "../ok0", "b/file/x"] {
            compare_realpath(p);
        }
        // canonicalize_file_name is realpath(path, NULL)
        unsafe {
            for p in [c"b/file", c"../l1", c"nothere", c""] {
                errno::set(0);
                let r = canonicalize_file_name(p.as_ptr());
                let e = errno::get();
                hset(0);
                let h = host::canonicalize_file_name(p.as_ptr());
                assert_eq!(r.is_null(), h.is_null());
                if r.is_null() {
                    assert_eq!(e, herrno());
                } else {
                    assert_eq!(CStr::from_ptr(r), CStr::from_ptr(h));
                    rusty_libc_malloc::free(r.cast());
                    host::free(h.cast());
                }
            }
        }
        std::env::set_current_dir(saved).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    // ---------------------------------------------------------------- load average

    #[test]
    fn getloadavg_matches_glibc() {
        let _g = test_lock();
        unsafe {
            for n in [-1, 0, 1, 2, 3, 4, 10] {
                let mut a = [-1.0f64; 5];
                let mut b = [-1.0f64; 5];
                let ra = getloadavg(a.as_mut_ptr(), n);
                let rb = host::getloadavg(b.as_mut_ptr(), n);
                assert_eq!(ra, rb, "count for nelem {n}");
                for i in 0..5 {
                    if (i as i32) < ra {
                        assert!(a[i] >= 0.0 && (a[i] - b[i]).abs() < 1.0, "{a:?} {b:?}");
                    } else {
                        assert_eq!(a[i], -1.0, "element past the count must stay untouched");
                    }
                }
            }
            // the values agree with /proc/loadavg (two decimals)
            let s = std::fs::read_to_string("/proc/loadavg").unwrap();
            let first: f64 = s.split_whitespace().next().unwrap().parse().unwrap();
            let mut a = [0.0f64; 3];
            assert_eq!(getloadavg(a.as_mut_ptr(), 3), 3);
            assert!((a[0] - first).abs() < 0.5, "{a:?} vs {first}");
        }
    }

    // ---------------------------------------------------------------- pty

    #[test]
    fn pty_master_slave_roundtrip() {
        let _g = test_lock();
        unsafe {
            let m = posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(m >= 0);
            assert_eq!(grantpt(m), 0);
            assert_eq!(unlockpt(m), 0);
            let name = ptsname(m);
            assert!(!name.is_null());
            let mut hb = [0 as c_char; 64];
            assert_eq!(host::ptsname_r(m, hb.as_mut_ptr(), 64), 0);
            assert_eq!(CStr::from_ptr(name), CStr::from_ptr(hb.as_ptr()));
            assert_eq!(host::grantpt(m), 0);
            let n = CStr::from_ptr(name).to_str().unwrap().to_string();
            assert!(n.starts_with("/dev/pts/"));

            // data written to the slave arrives at the master
            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(s >= 0, "open slave {n}");
            assert_eq!(libc::write(s, b"ab".as_ptr().cast(), 2), 2);
            let mut buf = [0u8; 2];
            assert_eq!(libc::read(m, buf.as_mut_ptr().cast(), 2), 2);
            assert_eq!(&buf, b"ab");
            libc::close(s);

            // ptsname_r buffer sizes: exact fit works, one byte short is ERANGE (as in glibc)
            let need = n.len() + 1;
            let mut b = vec![0 as c_char; need];
            assert_eq!(ptsname_r(m, b.as_mut_ptr(), need), 0);
            assert_eq!(CStr::from_ptr(b.as_ptr()).to_str().unwrap(), n);
            for short in [0, 1, need - 1] {
                errno::set(0);
                hset(0);
                let r = ptsname_r(m, b.as_mut_ptr(), short);
                let h = host::ptsname_r(m, hb.as_mut_ptr(), short);
                assert_eq!((r, errno::get()), (h, herrno()));
                assert_eq!(r, ERANGE);
            }
            libc::close(m);

            // getpt gives a master too
            let g = getpt();
            assert!(g >= 0);
            assert_eq!(unlockpt(g), 0);
            assert!(!ptsname(g).is_null());
            libc::close(g);
            let hg = host::getpt();
            assert!(hg >= 0);
            libc::close(hg);
            let hm = host::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(hm >= 0);
            libc::close(hm);
        }
    }

    #[test]
    fn pty_calls_on_wrong_descriptors_match_glibc() {
        let _g = test_lock();
        unsafe {
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            for fd in [null, 987_654] {
                errno::set(0);
                hset(0);
                assert_eq!(grantpt(fd), -1);
                assert_eq!(host::grantpt(fd), -1);
                assert_eq!(errno::get(), herrno(), "grantpt({fd})");
                errno::set(0);
                hset(0);
                assert_eq!(unlockpt(fd), -1);
                assert_eq!(host::unlockpt(fd), -1);
                assert_eq!(errno::get(), herrno(), "unlockpt({fd})");
                let mut a = [0 as c_char; 64];
                let mut b = [0 as c_char; 64];
                assert_eq!(ptsname_r(fd, a.as_mut_ptr(), 64), host::ptsname_r(fd, b.as_mut_ptr(), 64));
                errno::set(0);
                hset(0);
                assert!(ptsname(fd).is_null());
                assert!(host::ptsname(fd).is_null());
                assert_eq!(errno::get(), herrno(), "ptsname({fd})");
            }
            libc::close(null);
        }
    }

    // ---------------------------------------------------------------- getsubopt

    #[test]
    fn getsubopt_matches_glibc() {
        let _g = test_lock();
        let toks = ["ro", "rw", "name", "size"];
        let inputs = [
            "ro,rw=5,name=bob,size=",
            "unknown,ro",
            "x=y=z,rw",
            "ro,,rw",
            ",ro",
            "rw=",
            "name=a,b",
            "",
            "ro,",
            "=v,ro",
            "rwx,rw",
            "r,ro,rw=1=2,size=3,tail",
            "name,name=,name=x",
        ];
        for input in inputs {
            let ta: Vec<CString> = toks.iter().map(|t| CString::new(*t).unwrap()).collect();
            let tb = ta.clone();
            let mut pa: Vec<*mut c_char> = ta.iter().map(|c| c.as_ptr() as *mut c_char).collect();
            pa.push(null_mut());
            let mut pb: Vec<*mut c_char> = tb.iter().map(|c| c.as_ptr() as *mut c_char).collect();
            pb.push(null_mut());
            let mut sa = cbuf(input);
            let mut sb = cbuf(input);
            let (basea, baseb) = (sa.as_mut_ptr() as usize, sb.as_mut_ptr() as usize);
            let (mut oa, mut ob) = (sa.as_mut_ptr().cast::<c_char>(), sb.as_mut_ptr().cast::<c_char>());
            for step in 0..input.len() + 3 {
                let sentinel = core::ptr::dangling_mut::<c_char>();
                let (mut va, mut vb) = (sentinel, sentinel);
                let ra = unsafe { getsubopt(&mut oa, pa.as_ptr(), &mut va) };
                let rb = unsafe { host::getsubopt(&mut ob, pb.as_ptr(), &mut vb) };
                let offs = |v: *mut c_char, base: usize| if v.is_null() { None } else if v == sentinel { Some(usize::MAX) } else { Some(v as usize - base) };
                assert_eq!(ra, rb, "{input:?} step {step}");
                assert_eq!(offs(va, basea), offs(vb, baseb), "{input:?} step {step} value");
                assert_eq!(oa as usize - basea, ob as usize - baseb, "{input:?} step {step} next");
                assert_eq!(sa, sb, "{input:?} step {step} bytes");
            }
        }
    }

    // ---------------------------------------------------------------- small functions

    #[test]
    fn rpmatch_matches_glibc_c_locale() {
        let _g = test_lock();
        for s in ["y", "Y", "yes", "Yes", "YES", "n", "N", "no", "NO", "nO", "", "maybe", "x", "1", " y", "oui", "ja"] {
            let c = CString::new(s).unwrap();
            unsafe { assert_eq!(rpmatch(c.as_ptr()), host::rpmatch(c.as_ptr()), "{s:?}") };
        }
        unsafe {
            assert_eq!(rpmatch(c"yes".as_ptr()), 1);
            assert_eq!(rpmatch(c"No".as_ptr()), 0);
            assert_eq!(rpmatch(c"".as_ptr()), -1);
        }
    }

    #[test]
    fn a64_value_is_the_digit_position() {
        for c in 0..=255u8 {
            assert_eq!(a64_value(c), A64_DIGITS.iter().position(|&d| d == c).map(|p| p as u32), "byte {c}");
        }
    }

    #[test]
    fn a64l_and_l64a_match_glibc() {
        let _g = test_lock();
        let digits = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut r = Rng(12345);
        unsafe {
            for _ in 0..5000 {
                let len = r.below(9);
                let mut s: Vec<u8> = (0..len).map(|_| if r.below(12) == 0 { b" -+:@`{"[r.below(7)] } else { digits[r.below(64)] }).collect();
                s.extend([0u8]);
                assert_eq!(a64l(s.as_ptr().cast()), host::a64l(s.as_ptr().cast()), "{:?}", String::from_utf8_lossy(&s));
            }
            for _ in 0..5000 {
                let v = r.next() as i64;
                let a = CStr::from_ptr(l64a(v));
                let b = CStr::from_ptr(host::l64a(v));
                assert_eq!(a, b, "l64a({v})");
            }
            for v in [0i64, 1, 63, 64, -1, 0xffff_ffff, 0x1_0000_0000, i64::MIN, i64::MAX] {
                assert_eq!(CStr::from_ptr(l64a(v)), CStr::from_ptr(host::l64a(v)), "l64a({v})");
            }
            // round trip through both functions, and against glibc in either direction
            for _ in 0..5000 {
                let v = r.next() as u32;
                let s = l64a(v as c_long);
                assert_eq!(a64l(s) as u32, v);
                assert_eq!(host::a64l(s) as u32, v);
            }
            assert_eq!(CStr::from_ptr(l64a(0)).to_bytes(), b"");
            assert_eq!(a64l(c"".as_ptr()), 0);
            assert_eq!(a64l(c"./".as_ptr()), 64);
        }
    }

    #[test]
    fn ttyslot_matches_glibc() {
        let _g = test_lock();
        unsafe { assert_eq!(ttyslot(), host::ttyslot()) };
    }

    #[test]
    fn memalignment_and_sized_free() {
        let _g = test_lock();
        assert_eq!(memalignment(core::ptr::null()), 0);
        assert_eq!(memalignment(8 as *const c_void), 8);
        assert_eq!(memalignment(24 as *const c_void), 8);
        assert_eq!(memalignment(0x1000 as *const c_void), 4096);
        assert_eq!(memalignment(7 as *const c_void), 1);
        unsafe {
            let p = rusty_libc_malloc::malloc(100);
            assert!(memalignment(p) >= 16);
            free_sized(p, 100);
            let p = rusty_libc_malloc::aligned_alloc(64, 128);
            assert_eq!(memalignment(p) % 64, 0);
            free_aligned_sized(p, 64, 128);
            free_sized(null_mut(), 0);
        }
    }

    // ---------------------------------------------------------------- system

    fn sys_both(cmd: &str) -> (i32, i32) {
        let c = CString::new(cmd).unwrap();
        unsafe { (system(c.as_ptr()), host::system(c.as_ptr())) }
    }

    #[test]
    fn system_status_matches_glibc() {
        let _g = test_lock();
        for cmd in ["exit 0", "exit 1", "exit 3", "exit 255", "true", "false", "kill -9 $$", "kill -15 $$", "nonexistent_cmd_xyz_123", "exit 300", "( exit 4 )"] {
            let (a, b) = sys_both(cmd);
            assert_eq!(a, b, "{cmd}");
        }
        assert_eq!(sys_both("exit 3").0, 3 << 8);
        assert_eq!(sys_both("kill -9 $$").0, 9);
        assert_eq!(sys_both("nonexistent_cmd_xyz_123").0, 127 << 8);
        unsafe {
            assert_ne!(system(core::ptr::null()), 0);
            assert_eq!(system(core::ptr::null()), host::system(core::ptr::null()));
        }
    }

    #[test]
    fn system_output_and_environment() {
        let _g = test_lock();
        let d = tmpdir("sys");
        let out = format!("{d}/out");
        assert_eq!(sys_both(&format!("echo hello > '{out}'")).0, 0);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello\n");
        // arguments reach the shell as one string; "--" keeps a command starting with '-' working
        assert_eq!(sys_both(&format!("printf '%s' \"a b\" > '{out}'; exit 2")).0, 2 << 8);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "a b");
        // the child sees our environment
        unsafe {
            assert_eq!(crate::env::setenv(c"LIBC_PORT_SYS_T".as_ptr(), c"bar".as_ptr(), 1), 0);
            let c = c"[ \"$LIBC_PORT_SYS_T\" = bar ] || exit 7";
            assert_eq!(system(c.as_ptr()), 0);
            assert_eq!(crate::env::unsetenv(c"LIBC_PORT_SYS_T".as_ptr()), 0);
            assert_eq!(system(c.as_ptr()), 7 << 8);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    static CHLD_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    extern "C" fn on_chld(_: c_int) {
        CHLD_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn system_signal_handling() {
        let _g = test_lock();
        let mask_before = signal::sigprocmask(signal::SIG_BLOCK, Some(0)).unwrap();
        let int_before = signal::sigaction(signal::SIGINT, None).unwrap();
        let quit_before = signal::sigaction(signal::SIGQUIT, None).unwrap();

        // SIGINT and SIGQUIT sent to us while we wait are ignored; SIGCHLD stays blocked until system returns
        let (a, b) = sys_both("kill -INT $PPID; kill -QUIT $PPID; exit 5");
        assert_eq!((a, b), (5 << 8, 5 << 8));
        assert_eq!(signal::sigprocmask(signal::SIG_BLOCK, Some(0)).unwrap(), mask_before);
        assert_eq!(signal::sigaction(signal::SIGINT, None).unwrap(), int_before);
        assert_eq!(signal::sigaction(signal::SIGQUIT, None).unwrap(), quit_before);

        // a SIGCHLD handler runs only after system has returned (once), like glibc
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = on_chld as *const () as usize;
            let mut old: libc::sigaction = core::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGCHLD, &sa, &mut old), 0);
            for ours in [true, false] {
                CHLD_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
                let c = c"exit 0";
                let r = if ours { system(c.as_ptr()) } else { host::system(c.as_ptr()) };
                assert_eq!(r, 0);
                // another thread may take the signal while it is blocked here, so wait a moment
                for _ in 0..200 {
                    if CHLD_COUNT.load(core::sync::atomic::Ordering::SeqCst) > 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
                assert_eq!(CHLD_COUNT.load(core::sync::atomic::Ordering::SeqCst), 1, "ours={ours}");
            }
            assert_eq!(libc::sigaction(libc::SIGCHLD, &old, core::ptr::null_mut()), 0);
        }

        // what the child sees: SIGINT/SIGQUIT are at default unless we ignored them first
        let d = tmpdir("sysig");
        let f = format!("{d}/ign");
        let read_ign = || {
            let s = std::fs::read_to_string(&f).unwrap();
            let hex = s.split_whitespace().nth(1).unwrap().to_string();
            u64::from_str_radix(&hex, 16).unwrap() & 0b110
        };
        let cmd = format!("grep SigIgn /proc/self/status > '{f}'");
        for parent_ignores in [false, true] {
            if parent_ignores {
                signal::sigaction(signal::SIGINT, Some(&signal::KSigaction::IGNORE)).unwrap();
                signal::sigaction(signal::SIGQUIT, Some(&signal::KSigaction::IGNORE)).unwrap();
            }
            let (ra, rb) = sys_both(&cmd);
            assert_eq!((ra, rb), (0, 0));
            let _ = ra;
            // run ours again to read its result (sys_both ran both; run each alone)
            let c = CString::new(cmd.clone()).unwrap();
            unsafe { system(c.as_ptr()) };
            let ours = read_ign();
            unsafe { host::system(c.as_ptr()) };
            let theirs = read_ign();
            assert_eq!(ours, theirs, "parent_ignores={parent_ignores}");
            assert_eq!(ours, if parent_ignores { 0b110 } else { 0 });
        }
        signal::sigaction(signal::SIGINT, Some(&int_before)).unwrap();
        signal::sigaction(signal::SIGQUIT, Some(&quit_before)).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    // ---------------------------------------------------------------- exit handlers (in a forked child)

    static OUT_FD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);

    fn emit(b: u8) {
        let fd = OUT_FD.load(core::sync::atomic::Ordering::SeqCst);
        unsafe { libc::write(fd, (&b as *const u8).cast(), 1) };
    }
    unsafe extern "C" fn h_arg(_status: c_int, arg: *mut c_void) {
        emit(arg as usize as u8);
    }
    extern "C" fn h_plain() {
        emit(b'P');
    }
    extern "C" fn q1() {
        emit(b'1');
    }
    extern "C" fn q2() {
        emit(b'2');
    }

    /// Run `child` in a forked process; returns (wait status, bytes the child emitted).
    fn in_child(name: &str, child: fn()) -> (i32, Vec<u8>) {
        let d = tmpdir(name);
        let path = CString::new(format!("{d}/log")).unwrap();
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600);
            OUT_FD.store(fd, core::sync::atomic::Ordering::SeqCst);
            let pid = libc::fork();
            if pid == 0 {
                child();
                libc::_exit(99);
            }
            let mut st = 0;
            assert_eq!(libc::waitpid(pid, &mut st, 0), pid);
            libc::close(fd);
            let out = std::fs::read(format!("{d}/log")).unwrap();
            std::fs::remove_dir_all(&d).unwrap();
            (st, out)
        }
    }

    #[test]
    fn on_exit_runs_in_reverse_order_with_atexit() {
        let _g = test_lock();
        let (st, out) = in_child("onexit", || unsafe {
            on_exit(Some(h_arg), b'1' as usize as *mut c_void);
            process::atexit(h_plain);
            on_exit(Some(h_arg), b'2' as usize as *mut c_void);
            process::exit(7);
        });
        assert!(libc::WIFEXITED(st));
        assert_eq!(libc::WEXITSTATUS(st), 7);
        assert_eq!(out, b"2P1");
    }

    #[test]
    fn quick_exit_runs_only_quick_handlers() {
        let _g = test_lock();
        let (st, out) = in_child("quick", || {
            process::atexit(h_plain);
            at_quick_exit(Some(q1));
            at_quick_exit(Some(q2));
            quick_exit(9);
        });
        assert!(libc::WIFEXITED(st));
        assert_eq!(libc::WEXITSTATUS(st), 9);
        assert_eq!(out, b"21");
    }
}
