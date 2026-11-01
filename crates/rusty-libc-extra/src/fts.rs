//! fts.h: walking file trees (the 4.4BSD `fts` interface): fts_open, fts_read, fts_children, fts_set,
//! fts_close, and the `fts64_*` names (the same functions: on x86-64 the 64-bit structures are the plain
//! ones).
//!
//! The behaviour is glibc's: a walk visits a directory before (FTS_D) and after (FTS_DP) its contents,
//! reading entries in directory order (or sorted by the comparison function), changes the working
//! directory into each directory it walks unless FTS_NOCHDIR is set (so `fts_accpath` is relative to it),
//! detects directory cycles by comparing device and inode with the ancestors, and keeps `fts_path` as one
//! growing buffer shared by all the entries (a path longer than 65535 bytes ends the walk with
//! ENAMETOOLONG). The layouts of [`Fts`] (72 bytes) and [`Ftsent`] (120 bytes with the one-byte name) are
//! glibc's.
//!
//! Rust API: [`Walk`], an iterator-like wrapper over `fts_open`/`fts_read`/`fts_close`.
//!
//! Unsafe in this module (BRIEF-UNSAFE.md U2). The entries are C-layout blocks linked by raw pointers that the C caller
//! also holds and writes (`fts_number`, `fts_pointer`, `fts_instr`), so the tree stays a raw-pointer tree. Every access to
//! an entry goes through [`Ent`], a handle whose unsafe constructor states the invariant (a live entry of a stream); its
//! field accessors are safe and do one raw read or write each, and the links it hands out are live by the stream's own
//! bookkeeping (an entry is freed only after it is unlinked from everything the walk follows again). The path buffer is
//! written through [`with_path`]; paths handed to the kernel are [`CPath`]s (NUL-terminated by construction). What stays
//! unsafe: the C caller's stream pointer and argv (converted once per entry point), malloc/realloc/free of the blocks, the
//! system calls on C paths, the directory stream calls of rusty-libc-sys and the qsort call with the user's comparison
//! function. `Ent` and `CPath` are private, so the invariants are checked in this module only (Rust for Rustaceans p.233).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::{NonNull, null_mut};
use rusty_libc_core::errno;
use rusty_libc_core::syscall::{syscall1, syscall2};
use rusty_libc_sys::dirent::{DIR, closedir, dirent, dirfd, opendir, readdir};
use rusty_libc_sys::stat::Stat;

pub const FTS_COMFOLLOW: c_int = 0x0001;
pub const FTS_LOGICAL: c_int = 0x0002;
pub const FTS_NOCHDIR: c_int = 0x0004;
pub const FTS_NOSTAT: c_int = 0x0008;
pub const FTS_PHYSICAL: c_int = 0x0010;
pub const FTS_SEEDOT: c_int = 0x0020;
pub const FTS_XDEV: c_int = 0x0040;
pub const FTS_WHITEOUT: c_int = 0x0080;
pub const FTS_OPTIONMASK: c_int = 0x00ff;
pub const FTS_NAMEONLY: c_int = 0x0100;
pub const FTS_STOP: c_int = 0x0200;

pub const FTS_ROOTPARENTLEVEL: i16 = -1;
pub const FTS_ROOTLEVEL: i16 = 0;

pub const FTS_D: u16 = 1;
pub const FTS_DC: u16 = 2;
pub const FTS_DEFAULT: u16 = 3;
pub const FTS_DNR: u16 = 4;
pub const FTS_DOT: u16 = 5;
pub const FTS_DP: u16 = 6;
pub const FTS_ERR: u16 = 7;
pub const FTS_F: u16 = 8;
pub const FTS_INIT: u16 = 9;
pub const FTS_NS: u16 = 10;
pub const FTS_NSOK: u16 = 11;
pub const FTS_SL: u16 = 12;
pub const FTS_SLNONE: u16 = 13;
pub const FTS_W: u16 = 14;

pub const FTS_DONTCHDIR: u16 = 0x01;
pub const FTS_SYMFOLLOW: u16 = 0x02;

pub const FTS_AGAIN: c_int = 1;
pub const FTS_FOLLOW: c_int = 2;
pub const FTS_NOINSTR: c_int = 3;
pub const FTS_SKIP: c_int = 4;

/// What `fts_compar` is: a function of two `FTSENT **`.
pub type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// `FTS`, the stream (72 bytes).
#[repr(C)]
pub struct Fts {
    pub fts_cur: *mut Ftsent,
    pub fts_child: *mut Ftsent,
    pub fts_array: *mut *mut Ftsent,
    pub fts_dev: u64,
    pub fts_path: *mut c_char,
    pub fts_rfd: c_int,
    pub fts_pathlen: c_int,
    pub fts_nitems: c_int,
    pub fts_compar: Option<Compar>,
    pub fts_options: c_int,
}

/// `FTSENT`, one file of the walk (120 bytes with the one byte name; the real name continues past it).
#[repr(C)]
pub struct Ftsent {
    pub fts_cycle: *mut Ftsent,
    pub fts_parent: *mut Ftsent,
    pub fts_link: *mut Ftsent,
    pub fts_number: c_long,
    pub fts_pointer: *mut c_void,
    pub fts_accpath: *mut c_char,
    pub fts_path: *mut c_char,
    pub fts_errno: c_int,
    pub fts_symfd: c_int,
    pub fts_pathlen: u16,
    pub fts_namelen: u16,
    pub fts_ino: u64,
    pub fts_dev: u64,
    pub fts_nlink: u64,
    pub fts_level: i16,
    pub fts_info: u16,
    pub fts_flags: u16,
    pub fts_instr: u16,
    pub fts_statp: *mut Stat,
    pub fts_name: [c_char; 1],
}

const _: () = assert!(size_of::<Fts>() == 72);
const _: () = assert!(size_of::<Ftsent>() == 120);
const _: () = assert!(core::mem::offset_of!(Ftsent, fts_pathlen) == 64);
const _: () = assert!(core::mem::offset_of!(Ftsent, fts_level) == 96);
const _: () = assert!(core::mem::offset_of!(Ftsent, fts_statp) == 104);
const _: () = assert!(core::mem::offset_of!(Ftsent, fts_name) == 112);


const USHRT_MAX: usize = 65535;
const ALIGNBYTES: usize = 15;
// glibc's <sys/param.h> value (PATH_MAX), which its source uses, not the 1024 of the fallback definition
const MAXPATHLEN: usize = 4096;
const SYS_FSTAT_NR: usize = 5;
const SYS_FCHDIR_NR: usize = 81;
const O_RDONLY: usize = 0;
const DT_DIR: u8 = 4;
const DT_UNKNOWN: u8 = 0;

const BCHILD: c_int = 1;
const BNAMES: c_int = 2;
const BREAD: c_int = 3;

// ------------------------------------------------------------------ entries, paths, system calls

/// A handle to one entry of a stream.
///
/// Invariant: the pointer is a live entry made by [`fts_alloc`] (a malloc block of an `Ftsent`, its NUL-terminated name
/// of `fts_namelen` bytes and, without FTS_NOSTAT, room for a `Stat`), not yet freed; nothing else uses it while the walk
/// code runs (the C caller is not inside the library for this stream at the same time, as fts requires). Its
/// `fts_accpath` points to a NUL-terminated string (its own name or the stream's path buffer) whenever it is used as a
/// path. Links read from a live entry (`fts_link`, `fts_parent`, `fts_cycle`) are NULL or live entries whenever the
/// walk follows them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Ent(NonNull<Ftsent>);

macro_rules! fields {
    ($($get:ident, $set:ident: $f:ident: $t:ty;)*) => {
        $(
            #[inline(always)]
            #[allow(dead_code)]
            fn $get(self) -> $t {
                // SAFETY: a live entry (type invariant); one plain field read through the raw pointer.
                unsafe { (*self.0.as_ptr()).$f }
            }
            #[inline(always)]
            #[allow(dead_code)]
            fn $set(self, v: $t) {
                // SAFETY: a live entry (type invariant) that nothing else uses meanwhile; one plain field write.
                unsafe { (*self.0.as_ptr()).$f = v }
            }
        )*
    };
}

impl Ent {
    /// The handle of `p`, or None for NULL.
    ///
    /// # Safety
    /// `p` is NULL or a live entry (see the type's invariant).
    #[inline(always)]
    unsafe fn from_raw(p: *mut Ftsent) -> Option<Ent> {
        NonNull::new(p).map(Ent)
    }

    #[inline(always)]
    fn as_ptr(self) -> *mut Ftsent {
        self.0.as_ptr()
    }

    fields! {
        level, set_level: fts_level: i16;
        info, set_info: fts_info: u16;
        flags, set_flags: fts_flags: u16;
        instr, set_instr: fts_instr: u16;
        errno, set_errno: fts_errno: c_int;
        symfd, set_symfd: fts_symfd: c_int;
        pathlen, set_pathlen: fts_pathlen: u16;
        namelen, set_namelen: fts_namelen: u16;
        ino, set_ino: fts_ino: u64;
        dev, set_dev: fts_dev: u64;
        nlink, set_nlink: fts_nlink: u64;
        accpath, set_accpath: fts_accpath: *mut c_char;
        path_ptr, set_path_ptr: fts_path: *mut c_char;
        link_raw, set_link_raw: fts_link: *mut Ftsent;
        parent_raw, set_parent_raw: fts_parent: *mut Ftsent;
        cycle_raw, set_cycle_raw: fts_cycle: *mut Ftsent;
        statp, set_statp: fts_statp: *mut Stat;
        number, set_number: fts_number: c_long;
        pointer, set_pointer: fts_pointer: *mut c_void;
    }

    /// The next entry of the level (`fts_link`).
    #[inline(always)]
    fn link(self) -> Option<Ent> {
        // SAFETY: links of a live entry are NULL or live (type invariant).
        unsafe { Ent::from_raw(self.link_raw()) }
    }

    #[inline(always)]
    fn set_link(self, l: Option<Ent>) {
        self.set_link_raw(l.map_or(null_mut(), Ent::as_ptr));
    }

    /// The parent (`fts_parent`).
    #[inline(always)]
    fn parent(self) -> Option<Ent> {
        // SAFETY: as `link`.
        unsafe { Ent::from_raw(self.parent_raw()) }
    }

    /// The first byte of the name (`fts_name`, which continues past the one-byte array).
    #[inline(always)]
    fn name_ptr(self) -> *mut c_char {
        // pointer arithmetic only, inside the entry's own block
        self.as_ptr().cast::<c_char>().wrapping_add(core::mem::offset_of!(Ftsent, fts_name))
    }

    /// Run `f` on the name area: the `fts_namelen` bytes of the name and its NUL.
    #[inline(always)]
    fn with_name<R>(self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        let n = self.namelen() as usize + 1;
        // SAFETY: the name and its NUL are inside the entry's block (fts_alloc made room for the name it was given;
        // fts_namelen only ever shrinks), nothing else uses them meanwhile, and the slice does not outlive `f`.
        f(unsafe { rusty_libc_core::ffi::bytes_mut(self.name_ptr().cast(), n) })
    }

    /// Whether the name is "." or "..".
    fn is_dot(self) -> bool {
        self.with_name(|n| is_dot(&n[..n.len() - 1]))
    }

    /// `fts_accpath` as a path for the kernel.
    #[inline(always)]
    fn acc(self) -> CPath {
        CPath(self.accpath())
    }

    /// Free the entry's block; the handle must not be used afterwards.
    #[inline(always)]
    fn free(self) {
        // SAFETY: the block came from malloc (fts_alloc) and is not used again (the caller unlinked it).
        unsafe { rusty_libc_malloc::free(self.as_ptr().cast()) };
    }
}

/// A NUL-terminated path for the kernel: a literal, or the access path of a live entry (see [`Ent`]'s invariant).
#[derive(Clone, Copy)]
struct CPath(*const c_char);

impl CPath {
    const fn lit(s: &'static CStr) -> CPath {
        CPath(s.as_ptr())
    }
}

/// Run `f` on the stream's path buffer (`fts_pathlen` bytes).
#[inline(always)]
fn with_path<R>(sp: &Fts, f: impl FnOnce(&mut [u8]) -> R) -> R {
    // SAFETY: fts_path is the stream's malloc buffer of fts_pathlen bytes (fts_palloc keeps the two in step); it is
    // separate from the `Fts` itself, nothing else uses it while the walk code runs, and the slice does not outlive `f`.
    f(unsafe { rusty_libc_core::ffi::bytes_mut(sp.fts_path.cast(), sp.fts_pathlen as usize) })
}

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

/// A system call that returns 0 or -1 with errno set (like the C wrappers).
fn check_sys(r: usize) -> c_int {
    let e = sys_err(r);
    if e != 0 {
        errno::set(e);
        -1
    } else {
        r as c_int
    }
}

fn sys_open(path: CPath, flags: usize) -> c_int {
    // SAFETY: a NUL-terminated path (CPath).
    check_sys(unsafe { rusty_libc_core::syscall::sys_open(path.0 as usize, flags, 0) })
}

fn sys_close(fd: c_int) -> c_int {
    match rusty_libc_core::unistd::close(fd) {
        Ok(()) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

fn sys_fchdir(fd: c_int) -> c_int {
    // SAFETY: plain values only.
    check_sys(unsafe { syscall1(SYS_FCHDIR_NR, fd as usize) })
}

fn sys_stat(path: CPath, sb: &mut Stat) -> c_int {
    // SAFETY: a NUL-terminated path (CPath); `sb` is a whole `Stat`, the kernel's struct stat.
    check_sys(unsafe { rusty_libc_core::syscall::sys_stat(path.0 as usize, sb as *mut Stat as usize) })
}

fn sys_lstat(path: CPath, sb: &mut Stat) -> c_int {
    // SAFETY: as `sys_stat`.
    check_sys(unsafe { rusty_libc_core::syscall::sys_lstat(path.0 as usize, sb as *mut Stat as usize) })
}

fn sys_fstat(fd: c_int, sb: &mut Stat) -> c_int {
    // SAFETY: `sb` is a whole `Stat`, the kernel's struct stat.
    check_sys(unsafe { syscall2(SYS_FSTAT_NR, fd as usize, sb as *mut Stat as usize) })
}

fn is_set(sp: &Fts, opt: c_int) -> bool {
    sp.fts_options & opt != 0
}

/// "." or ".." (the name without its NUL).
fn is_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// The length of the path of `p` without a trailing slash (so a slash is not appended twice).
fn nappend(sp: &Fts, p: Ent) -> usize {
    let n = p.pathlen() as usize;
    // (the entry's fts_path is the stream's path buffer: fts_alloc, fts_load and fts_padjust keep it so)
    if with_path(sp, |b| b[n - 1]) == b'/' { n - 1 } else { n }
}

/// The handle of the stream's current entry.
#[inline(always)]
fn cur(sp: &Fts) -> Option<Ent> {
    // SAFETY: fts_cur is NULL or a live entry of the stream.
    unsafe { Ent::from_raw(sp.fts_cur) }
}

/// The handle of the stream's child list.
#[inline(always)]
fn child(sp: &Fts) -> Option<Ent> {
    // SAFETY: fts_child is NULL or a live entry of the stream.
    unsafe { Ent::from_raw(sp.fts_child) }
}

fn malloc(n: usize) -> *mut u8 {
    // SAFETY: a plain size.
    unsafe { rusty_libc_malloc::malloc(n) as *mut u8 }
}

/// free(3) of a block this module allocated (or NULL).
fn free<T>(p: *mut T) {
    // SAFETY: `p` is NULL or a block from malloc/realloc that the caller no longer uses.
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

// ------------------------------------------------------------------ open and close

/// fts_open: start walking the trees rooted at the NULL-terminated `argv`. `compar` sorts the entries of
/// every directory (and the roots); FTS_PHYSICAL or FTS_LOGICAL has to be among the options.
///
/// # Safety
/// `argv` is a NULL-terminated array of C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts {
    let mut n = 0;
    // SAFETY: the array is NULL-terminated (caller's contract), so every element up to the NULL is readable.
    while !unsafe { *argv.wrapping_add(n) }.is_null() {
        n += 1;
    }
    // SAFETY: the `n` pointers before the NULL (caller's contract).
    let args = unsafe { rusty_libc_core::ffi::slice(argv, n) };
    // SAFETY: each element is a C string (caller's contract), alive for the call.
    let roots = args.iter().map(|&a| unsafe { rusty_libc_core::ffi::cstr_bytes(a) });
    // SAFETY: the two function pointer types differ only in how the pointer arguments are spelled.
    let compar = unsafe { core::mem::transmute::<Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>, Option<Compar>>(compar) };
    open_roots(roots, options, compar)
}

/// fts_open over the root paths (without their NULs).
fn open_roots<'a>(roots: impl Iterator<Item = &'a [u8]> + Clone, options: c_int, compar: Option<Compar>) -> *mut Fts {
    // options check
    if options & !FTS_OPTIONMASK != 0 {
        errno::set(EINVAL);
        return null_mut();
    }
    // allocate and initialise the stream
    let sp = malloc(size_of::<Fts>()) as *mut Fts;
    if sp.is_null() {
        return null_mut();
    }
    // SAFETY: a new block of `size_of::<Fts>()` bytes; an all-zero `Fts` is valid (NULL pointers, None, zeros).
    unsafe { core::ptr::write_bytes(sp, 0, 1) };
    // SAFETY: the block is initialised and ours alone until it is returned.
    let s = unsafe { &mut *sp };
    s.fts_compar = compar;
    s.fts_options = options;
    // a logical walk turns on NOCHDIR: symbolic links are too hard
    if is_set(s, FTS_LOGICAL) {
        s.fts_options |= FTS_NOCHDIR;
    }
    // path space: 1K to start with, and at least what the user's paths need
    let maxarglen = roots.clone().map(<[u8]>::len).max().unwrap_or(0) + 1;
    if fts_palloc(s, maxarglen.max(MAXPATHLEN)) != 0 {
        free(sp);
        return null_mut();
    }
    // the parent of the roots
    let mut parent: Option<Ent> = None;
    if roots.clone().next().is_some() {
        parent = fts_alloc(s, b"");
        let Some(par) = parent else {
            free(s.fts_path);
            free(sp);
            return null_mut();
        };
        par.set_level(FTS_ROOTPARENTLEVEL);
    }
    // the roots
    let mut root: Option<Ent> = None;
    let mut tmp: Option<Ent> = None;
    let mut nitems = 0;
    for a in roots {
        // no zero-length paths
        if a.is_empty() {
            errno::set(ENOENT);
            fts_lfree(root);
            free(parent.map_or(null_mut(), Ent::as_ptr));
            free(s.fts_path);
            free(sp);
            return null_mut();
        }
        // (an allocation failure here is not checked, as before: the entry is used at once)
        let p = fts_alloc(s, a).expect("fts_open: out of memory");
        p.set_level(FTS_ROOTLEVEL);
        p.set_parent_raw(parent.map_or(null_mut(), Ent::as_ptr));
        p.set_accpath(p.name_ptr());
        let comfollow = is_set(s, FTS_COMFOLLOW);
        p.set_info(fts_stat(s, p, comfollow));
        // "." and ".." on the command line are real directories
        if p.info() == FTS_DOT {
            p.set_info(FTS_D);
        }
        // with a comparison function the roots are collected back to front and sorted below
        if compar.is_some() {
            p.set_link(root);
            root = Some(p);
        } else {
            p.set_link(None);
            match tmp {
                None => {
                    root = Some(p);
                    tmp = Some(p);
                }
                Some(t) => {
                    t.set_link(Some(p));
                    tmp = Some(p);
                }
            }
        }
        nitems += 1;
    }
    if compar.is_some() && nitems > 1 {
        root = fts_sort(s, root, nitems);
    }
    // a dummy node that makes fts_read think it has just finished the node before the root(s)
    let Some(dummy) = fts_alloc(s, b"") else {
        s.fts_cur = null_mut();
        fts_lfree(root);
        free(parent.map_or(null_mut(), Ent::as_ptr));
        free(s.fts_path);
        free(sp);
        return null_mut();
    };
    s.fts_cur = dummy.as_ptr();
    dummy.set_link(root);
    dummy.set_info(FTS_INIT);
    // with chdir: a descriptor of "." to get back to; without one run anyway, with NOCHDIR
    if !is_set(s, FTS_NOCHDIR) {
        s.fts_rfd = sys_open(CPath::lit(c"."), O_RDONLY);
        if s.fts_rfd < 0 {
            s.fts_options |= FTS_NOCHDIR;
        }
    }
    sp
}

/// Load the stream for the walk of the next root: the path buffer holds its name, and the entry keeps
/// only the last component as its name.
fn fts_load(sp: &mut Fts, p: Ent) {
    let len = p.namelen() as usize;
    p.set_pathlen(len as u16);
    p.with_name(|name| with_path(sp, |path| path[..len + 1].copy_from_slice(name)));
    p.with_name(|name| {
        let cp = name[..len].iter().rposition(|&c| c == b'/');
        if let Some(cp) = cp
            && (cp != 0 || name[cp + 1] != 0)
        {
            let l = len - (cp + 1);
            name.copy_within(cp + 1..len + 1, 0);
            p.set_namelen(l as u16);
        }
    });
    p.set_accpath(sp.fts_path);
    p.set_path_ptr(sp.fts_path);
    sp.fts_dev = p.dev();
}

/// fts_close: free the stream and return to the directory the walk started in (the error of that, if any,
/// is the return value).
///
/// # Safety
/// `sp` is a stream from fts_open.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_close(sp: *mut Fts) -> c_int {
    // SAFETY: a stream from fts_open (caller's contract), not used elsewhere during the call.
    let e = close_stream(unsafe { &mut *sp });
    free(sp);
    if e != 0 {
        errno::set(e);
        return -1;
    }
    0
}

/// fts_close up to the final free of the stream block: the errno of a failed return to the start directory, or 0.
fn close_stream(s: &mut Fts) -> c_int {
    // the dummy node points to the root list: step to the end of it (the node with a valid parent)
    if let Some(mut p) = cur(s) {
        // (a stream opened without roots has no parent to end on: stop at NULL, which glibc does not)
        let mut last = Some(p);
        while p.level() >= FTS_ROOTLEVEL {
            let freep = p;
            let next = if p.link().is_some() { p.link() } else { p.parent() };
            freep.free();
            last = next;
            match next {
                Some(n) => p = n,
                None => break,
            }
        }
        free(last.map_or(null_mut(), Ent::as_ptr));
    }
    // the child list, the sort array, the path buffer
    if child(s).is_some() {
        fts_lfree(child(s));
    }
    free(s.fts_array);
    free(s.fts_path);
    // back to the original directory
    if !is_set(s, FTS_NOCHDIR) {
        let saved_errno = if sys_fchdir(s.fts_rfd) != 0 { errno::get() } else { 0 };
        sys_close(s.fts_rfd);
        return saved_errno;
    }
    0
}

// ------------------------------------------------------------------ reading

/// fts_read: the next entry of the walk, or NULL at the end (errno 0) or after an error (errno set).
///
/// # Safety
/// `sp` is a stream from fts_open.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_read(sp: *mut Fts) -> *mut Ftsent {
    // SAFETY: a stream from fts_open (caller's contract), not used elsewhere during the call.
    read_entry(unsafe { &mut *sp }).map_or(null_mut(), Ent::as_ptr)
}

/// After FTS_FOLLOW on `p`: stat it following links, and for a directory keep a descriptor to come back by.
fn follow(s: &mut Fts, p: Ent) {
    p.set_info(fts_stat(s, p, true));
    if p.info() == FTS_D && !is_set(s, FTS_NOCHDIR) {
        p.set_symfd(sys_open(CPath::lit(c"."), O_RDONLY));
        if p.symfd() < 0 {
            p.set_errno(errno::get());
            p.set_info(FTS_ERR);
        } else {
            p.set_flags(p.flags() | FTS_SYMFOLLOW);
        }
    }
}

/// fts_read on the stream.
fn read_entry(s: &mut Fts) -> Option<Ent> {
    // finished or unrecoverable error
    let mut p = cur(s)?;
    if is_set(s, FTS_STOP) {
        return None;
    }
    // save and clear the user's instruction
    let instr = p.instr() as c_int;
    p.set_instr(FTS_NOINSTR as u16);
    // any kind of file may be visited again
    if instr == FTS_AGAIN {
        p.set_info(fts_stat(s, p, false));
        return Some(p);
    }
    // following a symlink (a dangling one may be followed too: the application sees SLNONE and recovers)
    if instr == FTS_FOLLOW && (p.info() == FTS_SL || p.info() == FTS_SLNONE) {
        follow(s, p);
        return Some(p);
    }
    // a directory in pre-order
    if p.info() == FTS_D {
        // skipped, or crossed a mount point: the post-order visit comes at once
        if instr == FTS_SKIP || (is_set(s, FTS_XDEV) && p.dev() != s.fts_dev) {
            if p.flags() & FTS_SYMFOLLOW != 0 {
                sys_close(p.symfd());
            }
            if child(s).is_some() {
                fts_lfree(child(s));
                s.fts_child = null_mut();
            }
            p.set_info(FTS_DP);
            return Some(p);
        }
        // only the names were read and now the walk goes on: read again
        if child(s).is_some() && is_set(s, FTS_NAMEONLY) {
            s.fts_options &= !FTS_NAMEONLY;
            fts_lfree(child(s));
            s.fts_child = null_mut();
        }
        // go into the subdirectory; when the children were read already and the chdir fails, their
        // access paths become the parent's and the parent gets the error
        if child(s).is_some() {
            if fts_safe_changedir(s, p, -1, p.acc()) != 0 {
                p.set_errno(errno::get());
                p.set_flags(p.flags() | FTS_DONTCHDIR);
                let mut c = child(s);
                while let Some(e) = c {
                    e.set_accpath(e.parent().expect("fts: child without parent").accpath());
                    c = e.link();
                }
            }
        } else {
            let built = fts_build(s, BREAD);
            s.fts_child = built.map_or(null_mut(), Ent::as_ptr);
            if built.is_none() {
                if is_set(s, FTS_STOP) {
                    return None;
                }
                return Some(p);
            }
        }
        let first = child(s).expect("fts: child list");
        s.fts_child = null_mut();
        s.fts_cur = first.as_ptr();
        return Some(name_path(s, first));
    }
    // the next node on this level
    let mut tmp = p;
    if let Some(next) = p.link() {
        p = next;
        s.fts_cur = p.as_ptr();
        tmp.free();
        // reached the top: back to the original directory and load the next root
        if p.level() == FTS_ROOTLEVEL {
            if !is_set(s, FTS_NOCHDIR) && sys_fchdir(s.fts_rfd) != 0 {
                s.fts_options |= FTS_STOP;
                return None;
            }
            fts_load(s, p);
            return Some(p);
        }
        // the user may have called fts_set on the node: skipped, ignore it; followed, get a descriptor to
        // come back by
        while p.instr() as c_int == FTS_SKIP {
            // goto next: move on again from here
            tmp = p;
            let Some(next) = p.link() else { return fts_up(s, tmp) };
            p = next;
            s.fts_cur = p.as_ptr();
            tmp.free();
            if p.level() == FTS_ROOTLEVEL {
                if !is_set(s, FTS_NOCHDIR) && sys_fchdir(s.fts_rfd) != 0 {
                    s.fts_options |= FTS_STOP;
                    return None;
                }
                fts_load(s, p);
                return Some(p);
            }
        }
        if p.instr() as c_int == FTS_FOLLOW {
            follow(s, p);
            p.set_instr(FTS_NOINSTR as u16);
        }
        return Some(name_path(s, p));
    }
    fts_up(s, tmp)
}

/// Write `/name` of `p` after its parent's path into the shared path buffer and return `p`.
fn name_path(sp: &mut Fts, p: Ent) -> Ent {
    let at = nappend(sp, p.parent().expect("fts: entry without parent"));
    p.with_name(|name| {
        with_path(sp, |path| {
            path[at] = b'/';
            path[at + 1..at + 1 + name.len()].copy_from_slice(name);
        })
    });
    p
}

/// Move up to the parent after the last node of a level (`tmp`): the end of the walk, or the post-order
/// visit of the parent.
fn fts_up(sp: &mut Fts, tmp: Ent) -> Option<Ent> {
    let p = tmp.parent().expect("fts: entry without parent");
    sp.fts_cur = p.as_ptr();
    tmp.free();
    if p.level() == FTS_ROOTPARENTLEVEL {
        // done: everything is freed and errno is 0, so the caller can tell the end from an error
        p.free();
        errno::set(0);
        sp.fts_cur = null_mut();
        return None;
    }
    // end the path name
    let at = p.pathlen() as usize;
    with_path(sp, |path| path[at] = 0);
    // return to the parent directory: through the root descriptor at a root, through the symlink
    // descriptor after a followed link, otherwise by ".."
    if p.level() == FTS_ROOTLEVEL {
        if !is_set(sp, FTS_NOCHDIR) && sys_fchdir(sp.fts_rfd) != 0 {
            sp.fts_options |= FTS_STOP;
            return None;
        }
    } else if p.flags() & FTS_SYMFOLLOW != 0 {
        if !is_set(sp, FTS_NOCHDIR) && sys_fchdir(p.symfd()) != 0 {
            let saved = errno::get();
            sys_close(p.symfd());
            errno::set(saved);
            sp.fts_options |= FTS_STOP;
            return None;
        }
        sys_close(p.symfd());
    } else if p.flags() & FTS_DONTCHDIR == 0 && fts_safe_changedir(sp, p.parent().expect("fts: entry without parent"), -1, CPath::lit(c"..")) != 0 {
        sp.fts_options |= FTS_STOP;
        return None;
    }
    p.set_info(if p.errno() != 0 { FTS_ERR } else { FTS_DP });
    Some(p)
}

/// fts_set: attach an instruction (FTS_AGAIN, FTS_FOLLOW, FTS_NOINSTR, FTS_SKIP or 0) to a node. 1 and EINVAL
/// for anything else.
///
/// # Safety
/// `p` is an entry of the stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_set(_sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int {
    if instr != 0 && instr != FTS_AGAIN && instr != FTS_FOLLOW && instr != FTS_NOINSTR && instr != FTS_SKIP {
        errno::set(EINVAL);
        return 1;
    }
    // SAFETY: an entry of the stream (caller's contract); NULL faults in the write below, as in glibc.
    let p = unsafe { Ent::from_raw(p) }.expect("fts_set: NULL entry");
    p.set_instr(instr as u16);
    0
}

/// fts_children: the entries of the current directory as a list (`fts_link`), read now; with FTS_NAMEONLY
/// just the names. NULL with errno 0 for an empty directory, NULL with errno set on an error.
///
/// # Safety
/// `sp` is a stream from fts_open.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    // SAFETY: a stream from fts_open (caller's contract), not used elsewhere during the call.
    children(unsafe { &mut *sp }, instr).map_or(null_mut(), Ent::as_ptr)
}

/// fts_children on the stream.
fn children(s: &mut Fts, instr: c_int) -> Option<Ent> {
    if instr != 0 && instr != FTS_NAMEONLY {
        errno::set(EINVAL);
        return None;
    }
    // errno is 0 so the caller can tell an empty directory from an error
    errno::set(0);
    // fatal errors stop here
    if is_set(s, FTS_STOP) {
        return None;
    }
    let p = cur(s).expect("fts_children: finished stream");
    // the logical hierarchy of the user's arguments
    if p.info() == FTS_INIT {
        return p.link();
    }
    // not a directory being visited in pre-order: stop here
    if p.info() != FTS_D {
        return None;
    }
    // free any previous child list
    if child(s).is_some() {
        fts_lfree(child(s));
    }
    let kind = if instr == FTS_NAMEONLY {
        s.fts_options |= FTS_NAMEONLY;
        BNAMES
    } else {
        BCHILD
    };
    // with chdir on a relative path before fts_read has changed to the root of the walk, the current
    // directory is unknown: remember it and come back
    // SAFETY: the access path of a live entry is a NUL-terminated string (Ent's invariant); its first byte is readable.
    let absolute = unsafe { *p.accpath() } == b'/' as c_char;
    if p.level() != FTS_ROOTLEVEL || absolute || is_set(s, FTS_NOCHDIR) {
        s.fts_child = fts_build(s, kind).map_or(null_mut(), Ent::as_ptr);
        return child(s);
    }
    let fd = sys_open(CPath::lit(c"."), O_RDONLY);
    if fd < 0 {
        return None;
    }
    s.fts_child = fts_build(s, kind).map_or(null_mut(), Ent::as_ptr);
    if sys_fchdir(fd) != 0 {
        return None;
    }
    sys_close(fd);
    child(s)
}

/// Read the directory of the current node into a linked list (for fts_children and fts_read). The node
/// is `fts_cur`; `type_` says who asked (BREAD: fts_read, which also gets the error reported in the node).
fn fts_build(sp: &mut Fts, type_: c_int) -> Option<Ent> {
    let cur = cur(sp).expect("fts_build: no current entry");
    // open the directory; if that fails there is nothing to do, and fts_read's node tells why
    // SAFETY: a NUL-terminated path (Ent's invariant).
    let mut dirp: *mut DIR = unsafe { opendir(cur.acc().0) };
    if dirp.is_null() {
        if type_ == BREAD {
            cur.set_info(FTS_DNR);
            cur.set_errno(errno::get());
        }
        return None;
    }
    // nlinks: the number of directories that can be among the entries when stat calls are skipped,
    // 0 for no stat calls at all, -1 for stat on everything
    let mut nlinks: i64;
    let mut nostat = false;
    if type_ == BNAMES {
        nlinks = 0;
    } else if is_set(sp, FTS_NOSTAT) && is_set(sp, FTS_PHYSICAL) {
        nlinks = cur.nlink() as i64 - if is_set(sp, FTS_SEEDOT) { 0 } else { 2 };
        nostat = true;
    } else {
        nlinks = -1;
    }
    // chdir when stat calls are needed or the walk will descend; a failure is kept going with, but the
    // directory is marked so no chdir back happens
    let mut descend = false;
    if nlinks != 0 || type_ == BREAD {
        // SAFETY: `dirp` is the open directory stream from opendir above.
        let dfd = unsafe { dirfd(dirp) };
        if fts_safe_changedir_fd(sp, cur, dfd) != 0 {
            if nlinks != 0 && type_ == BREAD {
                cur.set_errno(errno::get());
            }
            cur.set_flags(cur.flags() | FTS_DONTCHDIR);
            descend = false;
            // SAFETY: `dirp` is open and not used again.
            unsafe { closedir(dirp) };
            dirp = null_mut();
        } else {
            descend = true;
        }
    }
    // the longest name that fits in the path buffer; without chdir the names are appended in place
    let mut len = nappend(sp, cur);
    // (the offset of `cp` in the path buffer, when it is used: without chdir)
    let mut cp = 0usize;
    if is_set(sp, FTS_NOCHDIR) {
        cp = len;
        with_path(sp, |path| path[cp] = b'/');
        cp += 1;
    }
    len += 1;
    let mut maxlen = sp.fts_pathlen as usize - len;
    let level = cur.level() + 1;
    // read the directory, linking the entries in directory order
    let mut doadjust = false;
    let mut head: Option<Ent> = None;
    let mut tail: Option<Ent> = None;
    let mut nitems = 0;
    while !dirp.is_null() {
        // SAFETY: `dirp` is an open directory stream.
        let dp: *mut dirent = unsafe { readdir(dirp) };
        if dp.is_null() {
            break;
        }
        // SAFETY: a record readdir just returned: d_name is its NUL-terminated name, valid until the next readdir.
        let dname = unsafe { rusty_libc_core::ffi::cstr_bytes(dp.cast::<u8>().wrapping_add(core::mem::offset_of!(dirent, d_name))) };
        if !is_set(sp, FTS_SEEDOT) && is_dot(dname) {
            continue;
        }
        let namlen = dname.len();
        let Some(p) = fts_alloc(sp, dname) else {
            let e = errno::get();
            return build_fail(sp, cur, head, dirp, e);
        };
        if namlen >= maxlen {
            // include space for the NUL
            let oldaddr = sp.fts_path;
            if fts_palloc(sp, namlen + len + 1) != 0 {
                // no more memory for the path, or too long: free what was made and stop the walk
                let saved = errno::get();
                p.free();
                return build_fail(sp, cur, head, dirp, saved);
            }
            // did realloc change the pointer?
            if oldaddr != sp.fts_path {
                doadjust = true;
                if is_set(sp, FTS_NOCHDIR) {
                    cp = len;
                }
            }
            maxlen = sp.fts_pathlen as usize - len;
        }
        if len + namlen >= USHRT_MAX {
            // fts_pathlen of an entry is a u_short: it would wrap around
            p.free();
            return build_fail(sp, cur, head, dirp, ENAMETOOLONG);
        }
        p.set_level(level);
        p.set_parent_raw(sp.fts_cur);
        p.set_pathlen((len + namlen) as u16);
        // SAFETY: a record readdir just returned (see above); d_type is a plain byte of it.
        let d_type = unsafe { (*dp).d_type };
        if nlinks == 0 || (nostat && d_type != DT_DIR && d_type != DT_UNKNOWN) {
            p.set_accpath(if is_set(sp, FTS_NOCHDIR) { p.path_ptr() } else { p.name_ptr() });
            p.set_info(FTS_NSOK);
        } else {
            // a file name for fts_stat to stat
            if is_set(sp, FTS_NOCHDIR) {
                p.set_accpath(p.path_ptr());
                p.with_name(|name| with_path(sp, |path| path[cp..cp + name.len()].copy_from_slice(name)));
            } else {
                p.set_accpath(p.name_ptr());
            }
            // stat it
            p.set_info(fts_stat(sp, p, false));
            // one directory fewer to find
            if nlinks > 0 && (p.info() == FTS_D || p.info() == FTS_DC || p.info() == FTS_DOT) {
                nlinks -= 1;
            }
        }
        // directory order, so that "ls -f" is not upset
        p.set_link(None);
        match tail {
            None => {
                head = Some(p);
                tail = Some(p);
            }
            Some(t) => {
                t.set_link(Some(p));
                tail = Some(p);
            }
        }
        nitems += 1;
    }
    if !dirp.is_null() {
        // SAFETY: `dirp` is open and not used again.
        unsafe { closedir(dirp) };
    }
    // if the path buffer moved, fix the addresses in the rest of the tree and in this list
    if doadjust {
        fts_padjust(sp, head);
    }
    // without chdir, put the path back as it was
    if is_set(sp, FTS_NOCHDIR) {
        if len == sp.fts_pathlen as usize || nitems == 0 {
            cp -= 1;
        }
        with_path(sp, |path| path[cp] = 0);
    }
    // descended for fts_children, or for fts_read and nothing was found: get back; at the root level
    // through the saved descriptor
    if descend && (type_ == BCHILD || nitems == 0) {
        let failed = if cur.level() == FTS_ROOTLEVEL {
            !is_set(sp, FTS_NOCHDIR) && sys_fchdir(sp.fts_rfd) != 0
        } else {
            fts_safe_changedir(sp, cur.parent().expect("fts: entry without parent"), -1, CPath::lit(c"..")) != 0
        };
        if failed {
            cur.set_info(FTS_ERR);
            sp.fts_options |= FTS_STOP;
            fts_lfree(head);
            return None;
        }
    }
    // nothing found
    if nitems == 0 {
        if type_ == BREAD {
            cur.set_info(FTS_DP);
        }
        fts_lfree(head);
        return None;
    }
    // sort the entries
    if sp.fts_compar.is_some() && nitems > 1 {
        head = fts_sort(sp, head, nitems);
    }
    head
}

/// The error exit of fts_build after allocation trouble: free the list, mark the stream, set errno.
fn build_fail(sp: &mut Fts, cur: Ent, head: Option<Ent>, dirp: *mut DIR, err: c_int) -> Option<Ent> {
    fts_lfree(head);
    // SAFETY: `dirp` is fts_build's open directory stream (build_fail is reached only from its read loop), not used again.
    unsafe { closedir(dirp) };
    cur.set_info(FTS_ERR);
    sp.fts_options |= FTS_STOP;
    errno::set(err);
    None
}

/// Find out what `p` is: stat (or lstat) it into its stat buffer and classify; detects directory cycles
/// by comparing with the ancestors.
fn fts_stat(sp: &mut Fts, p: Ent, follow: bool) -> u16 {
    let mut local = Stat::zeroed();
    // when the user wants stat information the buffer was allocated with the entry
    let sbp: &mut Stat = if is_set(sp, FTS_NOSTAT) {
        &mut local
    } else {
        // SAFETY: without FTS_NOSTAT fts_alloc pointed fts_statp at the aligned `Stat` room of the entry's own block,
        // which nothing else uses during the call.
        unsafe { &mut *p.statp() }
    };
    // a logical walk, or an application asking to follow: stat; if that fails look for a dangling link
    let mut failed = false;
    if is_set(sp, FTS_LOGICAL) || follow {
        if sys_stat(p.acc(), sbp) != 0 {
            let saved = errno::get();
            if sys_lstat(p.acc(), sbp) == 0 {
                errno::set(0);
                return FTS_SLNONE;
            }
            p.set_errno(saved);
            failed = true;
        }
    } else if sys_lstat(p.acc(), sbp) != 0 {
        p.set_errno(errno::get());
        failed = true;
    }
    if failed {
        *sbp = Stat::zeroed();
        return FTS_NS;
    }
    let mode = sbp.st_mode;
    if mode & 0o170000 == 0o040000 {
        // device, inode and link count: for cycle checks, mount point crossings and fts_build's savings
        let dev = sbp.st_dev;
        let ino = sbp.st_ino;
        p.set_dev(dev);
        p.set_ino(ino);
        p.set_nlink(sbp.st_nlink);
        if p.is_dot() {
            return FTS_DOT;
        }
        // cycles, by brute force on first sight
        let mut t = p.parent().expect("fts: entry without parent");
        while t.level() >= FTS_ROOTLEVEL {
            if ino == t.ino() && dev == t.dev() {
                p.set_cycle_raw(t.as_ptr());
                return FTS_DC;
            }
            t = t.parent().expect("fts: entry without parent");
        }
        return FTS_D;
    }
    if mode & 0o170000 == 0o120000 {
        return FTS_SL;
    }
    if mode & 0o170000 == 0o100000 {
        return FTS_F;
    }
    FTS_DEFAULT
}

/// Sort the list with the comparison function through an array of pointers (qsort, like glibc: same order
/// of equal entries).
fn fts_sort(sp: &mut Fts, head: Option<Ent>, nitems: c_int) -> Option<Ent> {
    // an array big enough for the current needs plus 40
    if nitems > sp.fts_nitems {
        sp.fts_nitems = nitems + 40;
        // SAFETY: fts_array is NULL or the stream's own malloc block.
        let a = unsafe { rusty_libc_malloc::realloc(sp.fts_array.cast(), sp.fts_nitems as usize * size_of::<*mut Ftsent>()) } as *mut *mut Ftsent;
        if a.is_null() {
            free(sp.fts_array);
            sp.fts_array = null_mut();
            sp.fts_nitems = 0;
            return head;
        }
        sp.fts_array = a;
    }
    let n = nitems as usize;
    {
        // SAFETY: fts_array holds fts_nitems >= nitems pointers, is the stream's alone, and the slice ends before qsort.
        let arr = unsafe { rusty_libc_core::ffi::slice_mut(sp.fts_array, n) };
        let mut p = head;
        for slot in arr.iter_mut() {
            let e = p.expect("fts_sort: short list");
            *slot = e.as_ptr();
            p = e.link();
        }
    }
    // SAFETY: the array holds `n` entry pointers; the comparison function is the user's, called with pointers into the
    // array as glibc calls it.
    unsafe { rusty_libc_stdlib::sort::qsort(sp.fts_array.cast(), n, size_of::<*mut Ftsent>(), sp.fts_compar.expect("fts_sort: no comparison function")) };
    // SAFETY: as above (qsort has returned; the array still holds the `n` pointers, permuted).
    let arr = unsafe { rusty_libc_core::ffi::slice(sp.fts_array, n) };
    // SAFETY: every element is one of the list's live entries (only permuted by qsort).
    let ent = |i: usize| unsafe { Ent::from_raw(arr[i]) }.expect("fts_sort: NULL entry");
    for i in 0..n - 1 {
        ent(i).set_link(Some(ent(i + 1)));
    }
    ent(n - 1).set_link(None);
    Some(ent(0))
}

/// An entry: the structure, the name, and (unless FTS_NOSTAT) room for the stat buffer, in one block.
fn fts_alloc(sp: &mut Fts, name: &[u8]) -> Option<Ent> {
    let namelen = name.len();
    let mut len = size_of::<Ftsent>() + namelen;
    if !is_set(sp, FTS_NOSTAT) {
        len += size_of::<Stat>() + ALIGNBYTES;
    }
    let p = malloc(len) as *mut Ftsent;
    if p.is_null() {
        return None;
    }
    // everything starts as zero (glibc leaves some fields uninitialised until they are set)
    // SAFETY: a new block of at least `size_of::<Ftsent>()` bytes; all-zero is a valid `Ftsent`.
    unsafe { core::ptr::write_bytes(p as *mut u8, 0, size_of::<Ftsent>()) };
    // SAFETY: the block is initialised (above), freshly allocated, so it is a live entry of this stream from now on.
    let e = unsafe { Ent::from_raw(p) }.expect("non-NULL");
    let nm = e.name_ptr();
    {
        // SAFETY: the block has room for the name and its NUL after the fixed part (`size_of::<Ftsent>()` includes one
        // name byte), and nothing else uses it yet.
        let dst = unsafe { rusty_libc_core::ffi::bytes_mut(nm.cast(), namelen + 1) };
        dst[..namelen].copy_from_slice(name);
        dst[namelen] = 0;
    }
    if !is_set(sp, FTS_NOSTAT) {
        // the stat room: the first 16-byte aligned address 2 bytes past the name (pointer arithmetic in the block)
        let q = nm.wrapping_add(namelen + 2);
        e.set_statp(q.wrapping_add((q as usize).wrapping_neg() & ALIGNBYTES).cast());
    }
    e.set_namelen(namelen as u16);
    e.set_path_ptr(sp.fts_path);
    e.set_errno(0);
    e.set_flags(0);
    e.set_instr(FTS_NOINSTR as u16);
    e.set_number(0);
    e.set_pointer(null_mut());
    Some(e)
}

fn fts_lfree(head: Option<Ent>) {
    let mut p = head;
    while let Some(e) = p {
        let next = e.link();
        e.free();
        p = next;
    }
}

/// Grow the path buffer: by `more` plus 256 (so it does not grow two bytes at a time). 1 on failure
/// (ENAMETOOLONG when it would pass 65535 bytes).
fn fts_palloc(sp: &mut Fts, more: usize) -> c_int {
    sp.fts_pathlen = sp.fts_pathlen.wrapping_add((more + 256) as c_int);
    if sp.fts_pathlen < 0 || sp.fts_pathlen as usize >= USHRT_MAX {
        free(sp.fts_path);
        sp.fts_path = null_mut();
        errno::set(ENAMETOOLONG);
        return 1;
    }
    // SAFETY: fts_path is NULL or the stream's own malloc block.
    let p = unsafe { rusty_libc_malloc::realloc(sp.fts_path.cast(), sp.fts_pathlen as usize) } as *mut c_char;
    if p.is_null() {
        free(sp.fts_path);
        sp.fts_path = null_mut();
        return 1;
    }
    sp.fts_path = p;
    0
}

/// After the path buffer moved: fix the pointers of the entries already handed out.
fn fts_padjust(sp: &mut Fts, head: Option<Ent>) {
    let addr = sp.fts_path;
    let adjust = |p: Ent| {
        if p.accpath() != p.name_ptr() {
            // the same offset into the new buffer (addresses only: the old buffer is gone)
            let off = (p.accpath() as usize).wrapping_sub(p.path_ptr() as usize);
            p.set_accpath(addr.wrapping_add(off));
        }
        p.set_path_ptr(addr);
    };
    // the current children
    let mut p = child(sp);
    while let Some(e) = p {
        adjust(e);
        p = e.link();
    }
    // the rest of the tree, including the current level
    let mut p = head.expect("fts_padjust: empty list");
    while p.level() >= FTS_ROOTLEVEL {
        adjust(p);
        p = if p.link().is_some() { p.link() } else { p.parent() }.expect("fts: entry without parent");
    }
}

/// Change into the directory given by `fd` or by `path`, after checking that it is the one `p` stands for
/// (device and inode), so nothing swapped under the walk goes unnoticed (ENOENT then).
fn fts_safe_changedir(sp: &mut Fts, p: Ent, fd: c_int, path: CPath) -> c_int {
    safe_changedir(sp, p, fd, Some(path))
}

/// [`fts_safe_changedir`] with a descriptor (no path).
fn fts_safe_changedir_fd(sp: &mut Fts, p: Ent, fd: c_int) -> c_int {
    safe_changedir(sp, p, fd, None)
}

fn safe_changedir(sp: &mut Fts, p: Ent, fd: c_int, path: Option<CPath>) -> c_int {
    if is_set(sp, FTS_NOCHDIR) {
        return 0;
    }
    let mut newfd = fd;
    if fd < 0 {
        newfd = sys_open(path.expect("fts: chdir without a descriptor or a path"), O_RDONLY);
        if newfd < 0 {
            return -1;
        }
    }
    let mut sb = Stat::zeroed();
    let mut ret;
    if sys_fstat(newfd, &mut sb) != 0 {
        ret = -1;
    } else if p.dev() != sb.st_dev || p.ino() != sb.st_ino {
        errno::set(ENOENT); // disinformation
        ret = -1;
    } else {
        ret = sys_fchdir(newfd);
    }
    let oerrno = errno::get();
    if fd < 0 {
        sys_close(newfd);
    }
    errno::set(oerrno);
    if ret != 0 {
        ret = -1;
    }
    ret
}

// ------------------------------------------------------------------ the 64-bit names

/// fts64_open: the same function (the 64-bit structures equal the plain ones on x86-64).
///
/// # Safety
/// As `fts_open`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts {
    // SAFETY: forwarded contract.
    unsafe { fts_open(argv, options, compar) }
}

/// fts64_close.
///
/// # Safety
/// As `fts_close`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_close(sp: *mut Fts) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { fts_close(sp) }
}

/// fts64_read.
///
/// # Safety
/// As `fts_read`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_read(sp: *mut Fts) -> *mut Ftsent {
    // SAFETY: forwarded contract.
    unsafe { fts_read(sp) }
}

/// fts64_children.
///
/// # Safety
/// As `fts_children`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    // SAFETY: forwarded contract.
    unsafe { fts_children(sp, instr) }
}

/// fts64_set.
///
/// # Safety
/// As `fts_set`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_set(sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { fts_set(sp, p, instr) }
}

// ------------------------------------------------------------------ the Rust API

/// A walk over file trees: [`Walk::open`], then [`Walk::next_entry`] until it returns `None`; dropping it
/// closes the stream (and returns to the original directory).
pub struct Walk {
    fts: NonNull<Fts>,
}

impl Walk {
    /// Start a walk of `roots` (each a path) with the `FTS_*` options.
    pub fn open(roots: &[&CStr], options: c_int) -> Result<Walk, c_int> {
        let fts = open_roots(roots.iter().map(|r| r.to_bytes()), options, None);
        NonNull::new(fts).map(|fts| Walk { fts }).ok_or_else(errno::get)
    }

    /// The stream: a stream from `open_roots`, owned by this walk until it is dropped.
    fn stream(&mut self) -> &mut Fts {
        // SAFETY: the stream stays allocated until `drop`, and `&mut self` makes this the only access.
        unsafe { self.fts.as_mut() }
    }

    /// The next entry (valid until the following call), or `None` at the end or after an error (then
    /// [`Walk::error`] is not 0).
    pub fn next_entry(&mut self) -> Option<&Ftsent> {
        let p = read_entry(self.stream())?;
        // SAFETY: the entry stays alive until the next call on the walk, which the borrow of `self` rules out.
        Some(unsafe { &*p.as_ptr() })
    }

    /// The instruction FTS_SKIP, FTS_FOLLOW or FTS_AGAIN for the entry just returned.
    pub fn set(&mut self, instr: c_int) -> bool {
        match cur(self.stream()) {
            Some(cur) => {
                if instr != 0 && instr != FTS_AGAIN && instr != FTS_FOLLOW && instr != FTS_NOINSTR && instr != FTS_SKIP {
                    errno::set(EINVAL);
                    return false;
                }
                cur.set_instr(instr as u16);
                true
            }
            None => false,
        }
    }

    /// The error number after the last `next_entry` returned `None` (0 for a normal end).
    pub fn error(&self) -> c_int {
        errno::get()
    }

    /// The raw stream, for the C functions.
    pub fn as_ptr(&self) -> *mut Fts {
        self.fts.as_ptr()
    }
}

impl Drop for Walk {
    fn drop(&mut self) {
        // SAFETY: the stream came from `open_roots` and is not used after this.
        unsafe { fts_close(self.fts.as_ptr()) };
    }
}

impl Ftsent {
    /// The name of the file (without directories).
    pub fn name(&self) -> &[u8] {
        // SAFETY: an entry of a walk carries its name of fts_namelen bytes in its own block, after the fixed part.
        unsafe { rusty_libc_core::ffi::bytes(self.fts_name.as_ptr() as *const u8, self.fts_namelen as usize) }
    }

    /// The path of the file as the walk found it.
    pub fn path(&self) -> &[u8] {
        // SAFETY: fts_path of an entry of a walk is the stream's path buffer, holding at least fts_pathlen bytes.
        unsafe { rusty_libc_core::ffi::bytes(self.fts_path as *const u8, self.fts_pathlen as usize) }
    }
}
