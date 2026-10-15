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

pub type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

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
const MAXPATHLEN: usize = 4096;
const SYS_FSTAT_NR: usize = 5;
const SYS_FCHDIR_NR: usize = 81;
const O_RDONLY: usize = 0;
const DT_DIR: u8 = 4;
const DT_UNKNOWN: u8 = 0;

const BCHILD: c_int = 1;
const BNAMES: c_int = 2;
const BREAD: c_int = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Ent(NonNull<Ftsent>);

macro_rules! fields {
    ($($get:ident, $set:ident: $f:ident: $t:ty;)*) => {
        $(
            #[inline(always)]
            #[allow(dead_code)]
            fn $get(self) -> $t {
                unsafe { (*self.0.as_ptr()).$f }
            }
            #[inline(always)]
            #[allow(dead_code)]
            fn $set(self, v: $t) {
                unsafe { (*self.0.as_ptr()).$f = v }
            }
        )*
    };
}

impl Ent {
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

    #[inline(always)]
    fn link(self) -> Option<Ent> {
        unsafe { Ent::from_raw(self.link_raw()) }
    }

    #[inline(always)]
    fn set_link(self, l: Option<Ent>) {
        self.set_link_raw(l.map_or(null_mut(), Ent::as_ptr));
    }

    #[inline(always)]
    fn parent(self) -> Option<Ent> {
        unsafe { Ent::from_raw(self.parent_raw()) }
    }

    #[inline(always)]
    fn name_ptr(self) -> *mut c_char {
        self.as_ptr().cast::<c_char>().wrapping_add(core::mem::offset_of!(Ftsent, fts_name))
    }

    #[inline(always)]
    fn with_name<R>(self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        let n = self.namelen() as usize + 1;
        f(unsafe { rusty_libc_core::ffi::bytes_mut(self.name_ptr().cast(), n) })
    }

    fn is_dot(self) -> bool {
        self.with_name(|n| is_dot(&n[..n.len() - 1]))
    }

    #[inline(always)]
    fn acc(self) -> CPath {
        CPath(self.accpath())
    }

    #[inline(always)]
    fn free(self) {
        unsafe { rusty_libc_malloc::free(self.as_ptr().cast()) };
    }
}

#[derive(Clone, Copy)]
struct CPath(*const c_char);

impl CPath {
    const fn lit(s: &'static CStr) -> CPath {
        CPath(s.as_ptr())
    }
}

#[inline(always)]
fn with_path<R>(sp: &Fts, f: impl FnOnce(&mut [u8]) -> R) -> R {
    f(unsafe { rusty_libc_core::ffi::bytes_mut(sp.fts_path.cast(), sp.fts_pathlen as usize) })
}

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

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
    check_sys(unsafe { syscall1(SYS_FCHDIR_NR, fd as usize) })
}

fn sys_stat(path: CPath, sb: &mut Stat) -> c_int {
    check_sys(unsafe { rusty_libc_core::syscall::sys_stat(path.0 as usize, sb as *mut Stat as usize) })
}

fn sys_lstat(path: CPath, sb: &mut Stat) -> c_int {
    check_sys(unsafe { rusty_libc_core::syscall::sys_lstat(path.0 as usize, sb as *mut Stat as usize) })
}

fn sys_fstat(fd: c_int, sb: &mut Stat) -> c_int {
    check_sys(unsafe { syscall2(SYS_FSTAT_NR, fd as usize, sb as *mut Stat as usize) })
}

fn is_set(sp: &Fts, opt: c_int) -> bool {
    sp.fts_options & opt != 0
}

fn is_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

fn nappend(sp: &Fts, p: Ent) -> usize {
    let n = p.pathlen() as usize;
    if with_path(sp, |b| b[n - 1]) == b'/' { n - 1 } else { n }
}

#[inline(always)]
fn cur(sp: &Fts) -> Option<Ent> {
    unsafe { Ent::from_raw(sp.fts_cur) }
}

#[inline(always)]
fn child(sp: &Fts) -> Option<Ent> {
    unsafe { Ent::from_raw(sp.fts_child) }
}

fn malloc(n: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::malloc(n) as *mut u8 }
}

fn free<T>(p: *mut T) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts {
    let mut n = 0;
    while !unsafe { *argv.wrapping_add(n) }.is_null() {
        n += 1;
    }
    let args = unsafe { rusty_libc_core::ffi::slice(argv, n) };
    let roots = args.iter().map(|&a| unsafe { rusty_libc_core::ffi::cstr_bytes(a) });
    let compar = unsafe { core::mem::transmute::<Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>, Option<Compar>>(compar) };
    open_roots(roots, options, compar)
}

fn open_roots<'a>(roots: impl Iterator<Item = &'a [u8]> + Clone, options: c_int, compar: Option<Compar>) -> *mut Fts {
    if options & !FTS_OPTIONMASK != 0 {
        errno::set(EINVAL);
        return null_mut();
    }
    let sp = malloc(size_of::<Fts>()) as *mut Fts;
    if sp.is_null() {
        return null_mut();
    }
    unsafe { core::ptr::write_bytes(sp, 0, 1) };
    let s = unsafe { &mut *sp };
    s.fts_compar = compar;
    s.fts_options = options;
    if is_set(s, FTS_LOGICAL) {
        s.fts_options |= FTS_NOCHDIR;
    }
    let maxarglen = roots.clone().map(<[u8]>::len).max().unwrap_or(0) + 1;
    if fts_palloc(s, maxarglen.max(MAXPATHLEN)) != 0 {
        free(sp);
        return null_mut();
    }
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
    let mut root: Option<Ent> = None;
    let mut tmp: Option<Ent> = None;
    let mut nitems = 0;
    for a in roots {
        if a.is_empty() {
            errno::set(ENOENT);
            fts_lfree(root);
            free(parent.map_or(null_mut(), Ent::as_ptr));
            free(s.fts_path);
            free(sp);
            return null_mut();
        }
        let p = fts_alloc(s, a).expect("fts_open: out of memory");
        p.set_level(FTS_ROOTLEVEL);
        p.set_parent_raw(parent.map_or(null_mut(), Ent::as_ptr));
        p.set_accpath(p.name_ptr());
        let comfollow = is_set(s, FTS_COMFOLLOW);
        p.set_info(fts_stat(s, p, comfollow));
        if p.info() == FTS_DOT {
            p.set_info(FTS_D);
        }
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
    if !is_set(s, FTS_NOCHDIR) {
        s.fts_rfd = sys_open(CPath::lit(c"."), O_RDONLY);
        if s.fts_rfd < 0 {
            s.fts_options |= FTS_NOCHDIR;
        }
    }
    sp
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_close(sp: *mut Fts) -> c_int {
    let e = close_stream(unsafe { &mut *sp });
    free(sp);
    if e != 0 {
        errno::set(e);
        return -1;
    }
    0
}

fn close_stream(s: &mut Fts) -> c_int {
    if let Some(mut p) = cur(s) {
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
    if child(s).is_some() {
        fts_lfree(child(s));
    }
    free(s.fts_array);
    free(s.fts_path);
    if !is_set(s, FTS_NOCHDIR) {
        let saved_errno = if sys_fchdir(s.fts_rfd) != 0 { errno::get() } else { 0 };
        sys_close(s.fts_rfd);
        return saved_errno;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_read(sp: *mut Fts) -> *mut Ftsent {
    read_entry(unsafe { &mut *sp }).map_or(null_mut(), Ent::as_ptr)
}

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

fn read_entry(s: &mut Fts) -> Option<Ent> {
    let mut p = cur(s)?;
    if is_set(s, FTS_STOP) {
        return None;
    }
    let instr = p.instr() as c_int;
    p.set_instr(FTS_NOINSTR as u16);
    if instr == FTS_AGAIN {
        p.set_info(fts_stat(s, p, false));
        return Some(p);
    }
    if instr == FTS_FOLLOW && (p.info() == FTS_SL || p.info() == FTS_SLNONE) {
        follow(s, p);
        return Some(p);
    }
    if p.info() == FTS_D {
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
        if child(s).is_some() && is_set(s, FTS_NAMEONLY) {
            s.fts_options &= !FTS_NAMEONLY;
            fts_lfree(child(s));
            s.fts_child = null_mut();
        }
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
    let mut tmp = p;
    if let Some(next) = p.link() {
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
        while p.instr() as c_int == FTS_SKIP {
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

fn fts_up(sp: &mut Fts, tmp: Ent) -> Option<Ent> {
    let p = tmp.parent().expect("fts: entry without parent");
    sp.fts_cur = p.as_ptr();
    tmp.free();
    if p.level() == FTS_ROOTPARENTLEVEL {
        p.free();
        errno::set(0);
        sp.fts_cur = null_mut();
        return None;
    }
    let at = p.pathlen() as usize;
    with_path(sp, |path| path[at] = 0);
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_set(_sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int {
    if instr != 0 && instr != FTS_AGAIN && instr != FTS_FOLLOW && instr != FTS_NOINSTR && instr != FTS_SKIP {
        errno::set(EINVAL);
        return 1;
    }
    let p = unsafe { Ent::from_raw(p) }.expect("fts_set: NULL entry");
    p.set_instr(instr as u16);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    children(unsafe { &mut *sp }, instr).map_or(null_mut(), Ent::as_ptr)
}

fn children(s: &mut Fts, instr: c_int) -> Option<Ent> {
    if instr != 0 && instr != FTS_NAMEONLY {
        errno::set(EINVAL);
        return None;
    }
    errno::set(0);
    if is_set(s, FTS_STOP) {
        return None;
    }
    let p = cur(s).expect("fts_children: finished stream");
    if p.info() == FTS_INIT {
        return p.link();
    }
    if p.info() != FTS_D {
        return None;
    }
    if child(s).is_some() {
        fts_lfree(child(s));
    }
    let kind = if instr == FTS_NAMEONLY {
        s.fts_options |= FTS_NAMEONLY;
        BNAMES
    } else {
        BCHILD
    };
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

fn fts_build(sp: &mut Fts, type_: c_int) -> Option<Ent> {
    let cur = cur(sp).expect("fts_build: no current entry");
    let mut dirp: *mut DIR = unsafe { opendir(cur.acc().0) };
    if dirp.is_null() {
        if type_ == BREAD {
            cur.set_info(FTS_DNR);
            cur.set_errno(errno::get());
        }
        return None;
    }
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
    let mut descend = false;
    if nlinks != 0 || type_ == BREAD {
        let dfd = unsafe { dirfd(dirp) };
        if fts_safe_changedir_fd(sp, cur, dfd) != 0 {
            if nlinks != 0 && type_ == BREAD {
                cur.set_errno(errno::get());
            }
            cur.set_flags(cur.flags() | FTS_DONTCHDIR);
            descend = false;
            unsafe { closedir(dirp) };
            dirp = null_mut();
        } else {
            descend = true;
        }
    }
    let mut len = nappend(sp, cur);
    let mut cp = 0usize;
    if is_set(sp, FTS_NOCHDIR) {
        cp = len;
        with_path(sp, |path| path[cp] = b'/');
        cp += 1;
    }
    len += 1;
    let mut maxlen = sp.fts_pathlen as usize - len;
    let level = cur.level() + 1;
    let mut doadjust = false;
    let mut head: Option<Ent> = None;
    let mut tail: Option<Ent> = None;
    let mut nitems = 0;
    while !dirp.is_null() {
        let dp: *mut dirent = unsafe { readdir(dirp) };
        if dp.is_null() {
            break;
        }
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
            let oldaddr = sp.fts_path;
            if fts_palloc(sp, namlen + len + 1) != 0 {
                let saved = errno::get();
                p.free();
                return build_fail(sp, cur, head, dirp, saved);
            }
            if oldaddr != sp.fts_path {
                doadjust = true;
                if is_set(sp, FTS_NOCHDIR) {
                    cp = len;
                }
            }
            maxlen = sp.fts_pathlen as usize - len;
        }
        if len + namlen >= USHRT_MAX {
            p.free();
            return build_fail(sp, cur, head, dirp, ENAMETOOLONG);
        }
        p.set_level(level);
        p.set_parent_raw(sp.fts_cur);
        p.set_pathlen((len + namlen) as u16);
        let d_type = unsafe { (*dp).d_type };
        if nlinks == 0 || (nostat && d_type != DT_DIR && d_type != DT_UNKNOWN) {
            p.set_accpath(if is_set(sp, FTS_NOCHDIR) { p.path_ptr() } else { p.name_ptr() });
            p.set_info(FTS_NSOK);
        } else {
            if is_set(sp, FTS_NOCHDIR) {
                p.set_accpath(p.path_ptr());
                p.with_name(|name| with_path(sp, |path| path[cp..cp + name.len()].copy_from_slice(name)));
            } else {
                p.set_accpath(p.name_ptr());
            }
            p.set_info(fts_stat(sp, p, false));
            if nlinks > 0 && (p.info() == FTS_D || p.info() == FTS_DC || p.info() == FTS_DOT) {
                nlinks -= 1;
            }
        }
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
        unsafe { closedir(dirp) };
    }
    if doadjust {
        fts_padjust(sp, head);
    }
    if is_set(sp, FTS_NOCHDIR) {
        if len == sp.fts_pathlen as usize || nitems == 0 {
            cp -= 1;
        }
        with_path(sp, |path| path[cp] = 0);
    }
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
    if nitems == 0 {
        if type_ == BREAD {
            cur.set_info(FTS_DP);
        }
        fts_lfree(head);
        return None;
    }
    if sp.fts_compar.is_some() && nitems > 1 {
        head = fts_sort(sp, head, nitems);
    }
    head
}

fn build_fail(sp: &mut Fts, cur: Ent, head: Option<Ent>, dirp: *mut DIR, err: c_int) -> Option<Ent> {
    fts_lfree(head);
    unsafe { closedir(dirp) };
    cur.set_info(FTS_ERR);
    sp.fts_options |= FTS_STOP;
    errno::set(err);
    None
}

fn fts_stat(sp: &mut Fts, p: Ent, follow: bool) -> u16 {
    let mut local = Stat::zeroed();
    let sbp: &mut Stat = if is_set(sp, FTS_NOSTAT) {
        &mut local
    } else {
        unsafe { &mut *p.statp() }
    };
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
        let dev = sbp.st_dev;
        let ino = sbp.st_ino;
        p.set_dev(dev);
        p.set_ino(ino);
        p.set_nlink(sbp.st_nlink);
        if p.is_dot() {
            return FTS_DOT;
        }
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

fn fts_sort(sp: &mut Fts, head: Option<Ent>, nitems: c_int) -> Option<Ent> {
    if nitems > sp.fts_nitems {
        sp.fts_nitems = nitems + 40;
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
        let arr = unsafe { rusty_libc_core::ffi::slice_mut(sp.fts_array, n) };
        let mut p = head;
        for slot in arr.iter_mut() {
            let e = p.expect("fts_sort: short list");
            *slot = e.as_ptr();
            p = e.link();
        }
    }
    unsafe { rusty_libc_stdlib::sort::qsort(sp.fts_array.cast(), n, size_of::<*mut Ftsent>(), sp.fts_compar.expect("fts_sort: no comparison function")) };
    let arr = unsafe { rusty_libc_core::ffi::slice(sp.fts_array, n) };
    let ent = |i: usize| unsafe { Ent::from_raw(arr[i]) }.expect("fts_sort: NULL entry");
    for i in 0..n - 1 {
        ent(i).set_link(Some(ent(i + 1)));
    }
    ent(n - 1).set_link(None);
    Some(ent(0))
}

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
    unsafe { core::ptr::write_bytes(p as *mut u8, 0, size_of::<Ftsent>()) };
    let e = unsafe { Ent::from_raw(p) }.expect("non-NULL");
    let nm = e.name_ptr();
    {
        let dst = unsafe { rusty_libc_core::ffi::bytes_mut(nm.cast(), namelen + 1) };
        dst[..namelen].copy_from_slice(name);
        dst[namelen] = 0;
    }
    if !is_set(sp, FTS_NOSTAT) {
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

fn fts_palloc(sp: &mut Fts, more: usize) -> c_int {
    sp.fts_pathlen = sp.fts_pathlen.wrapping_add((more + 256) as c_int);
    if sp.fts_pathlen < 0 || sp.fts_pathlen as usize >= USHRT_MAX {
        free(sp.fts_path);
        sp.fts_path = null_mut();
        errno::set(ENAMETOOLONG);
        return 1;
    }
    let p = unsafe { rusty_libc_malloc::realloc(sp.fts_path.cast(), sp.fts_pathlen as usize) } as *mut c_char;
    if p.is_null() {
        free(sp.fts_path);
        sp.fts_path = null_mut();
        return 1;
    }
    sp.fts_path = p;
    0
}

fn fts_padjust(sp: &mut Fts, head: Option<Ent>) {
    let addr = sp.fts_path;
    let adjust = |p: Ent| {
        if p.accpath() != p.name_ptr() {
            let off = (p.accpath() as usize).wrapping_sub(p.path_ptr() as usize);
            p.set_accpath(addr.wrapping_add(off));
        }
        p.set_path_ptr(addr);
    };
    let mut p = child(sp);
    while let Some(e) = p {
        adjust(e);
        p = e.link();
    }
    let mut p = head.expect("fts_padjust: empty list");
    while p.level() >= FTS_ROOTLEVEL {
        adjust(p);
        p = if p.link().is_some() { p.link() } else { p.parent() }.expect("fts: entry without parent");
    }
}

fn fts_safe_changedir(sp: &mut Fts, p: Ent, fd: c_int, path: CPath) -> c_int {
    safe_changedir(sp, p, fd, Some(path))
}

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
        errno::set(ENOENT);
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts {
    unsafe { fts_open(argv, options, compar) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_close(sp: *mut Fts) -> c_int {
    unsafe { fts_close(sp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_read(sp: *mut Fts) -> *mut Ftsent {
    unsafe { fts_read(sp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    unsafe { fts_children(sp, instr) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_set(sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int {
    unsafe { fts_set(sp, p, instr) }
}

pub struct Walk {
    fts: NonNull<Fts>,
}

impl Walk {
    pub fn open(roots: &[&CStr], options: c_int) -> Result<Walk, c_int> {
        let fts = open_roots(roots.iter().map(|r| r.to_bytes()), options, None);
        NonNull::new(fts).map(|fts| Walk { fts }).ok_or_else(errno::get)
    }

    fn stream(&mut self) -> &mut Fts {
        unsafe { self.fts.as_mut() }
    }

    pub fn next_entry(&mut self) -> Option<&Ftsent> {
        let p = read_entry(self.stream())?;
        Some(unsafe { &*p.as_ptr() })
    }

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

    pub fn error(&self) -> c_int {
        errno::get()
    }

    pub fn as_ptr(&self) -> *mut Fts {
        self.fts.as_ptr()
    }
}

impl Drop for Walk {
    fn drop(&mut self) {
        unsafe { fts_close(self.fts.as_ptr()) };
    }
}

impl Ftsent {
    pub fn name(&self) -> &[u8] {
        unsafe { rusty_libc_core::ffi::bytes(self.fts_name.as_ptr() as *const u8, self.fts_namelen as usize) }
    }

    pub fn path(&self) -> &[u8] {
        unsafe { rusty_libc_core::ffi::bytes(self.fts_path as *const u8, self.fts_pathlen as usize) }
    }
}
