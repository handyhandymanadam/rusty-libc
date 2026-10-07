use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3};
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
const SYS_STAT_NR: usize = 4;
const SYS_FSTAT_NR: usize = 5;
const SYS_LSTAT_NR: usize = 6;
const SYS_FCHDIR_NR: usize = 81;
const O_RDONLY: usize = 0;
const DT_DIR: u8 = 4;
const DT_UNKNOWN: u8 = 0;

const BCHILD: c_int = 1;
const BNAMES: c_int = 2;
const BREAD: c_int = 3;

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

unsafe fn sys_open(path: *const c_char, flags: usize) -> c_int {
    check_sys(unsafe { syscall3(syscall::SYS_OPEN, path as usize, flags, 0) })
}

fn sys_close(fd: c_int) -> c_int {
    check_sys(unsafe { syscall1(syscall::SYS_CLOSE, fd as usize) })
}

fn sys_fchdir(fd: c_int) -> c_int {
    check_sys(unsafe { syscall1(SYS_FCHDIR_NR, fd as usize) })
}

unsafe fn sys_stat(path: *const c_char, sb: *mut Stat) -> c_int {
    check_sys(unsafe { syscall2(SYS_STAT_NR, path as usize, sb as usize) })
}

unsafe fn sys_lstat(path: *const c_char, sb: *mut Stat) -> c_int {
    check_sys(unsafe { syscall2(SYS_LSTAT_NR, path as usize, sb as usize) })
}

unsafe fn sys_fstat(fd: c_int, sb: *mut Stat) -> c_int {
    check_sys(unsafe { syscall2(SYS_FSTAT_NR, fd as usize, sb as usize) })
}

fn is_set(sp: &Fts, opt: c_int) -> bool {
    sp.fts_options & opt != 0
}

unsafe fn is_dot(name: *const c_char) -> bool {
    unsafe { *name == b'.' as c_char && (*name.add(1) == 0 || (*name.add(1) == b'.' as c_char && *name.add(2) == 0)) }
}

unsafe fn slen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s) }
}

unsafe fn nappend(p: &Ftsent) -> usize {
    unsafe {
        let n = p.fts_pathlen as usize;
        if *p.fts_path.add(n - 1) == b'/' as c_char { n - 1 } else { n }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts {
    unsafe {
        if options & !FTS_OPTIONMASK != 0 {
            errno::set(EINVAL);
            return null_mut();
        }
        let sp = rusty_libc_malloc::malloc(size_of::<Fts>()) as *mut Fts;
        if sp.is_null() {
            return null_mut();
        }
        core::ptr::write_bytes(sp, 0, 1);
        let s = &mut *sp;
        s.fts_compar = core::mem::transmute::<Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>, Option<Compar>>(compar);
        s.fts_options = options;
        if is_set(s, FTS_LOGICAL) {
            s.fts_options |= FTS_NOCHDIR;
        }
        let maxarglen = maxarglen(argv);
        if fts_palloc(s, maxarglen.max(MAXPATHLEN)) != 0 {
            rusty_libc_malloc::free(sp.cast());
            return null_mut();
        }
        let mut parent: *mut Ftsent = null_mut();
        if !(*argv).is_null() {
            parent = fts_alloc(s, c"".as_ptr(), 0);
            if parent.is_null() {
                rusty_libc_malloc::free(s.fts_path.cast());
                rusty_libc_malloc::free(sp.cast());
                return null_mut();
            }
            (*parent).fts_level = FTS_ROOTPARENTLEVEL;
        }
        let mut root: *mut Ftsent = null_mut();
        let mut tmp: *mut Ftsent = null_mut();
        let mut nitems = 0;
        let mut a = argv;
        while !(*a).is_null() {
            let len = slen(*a);
            if len == 0 {
                errno::set(ENOENT);
                fts_lfree(root);
                rusty_libc_malloc::free(parent.cast());
                rusty_libc_malloc::free(s.fts_path.cast());
                rusty_libc_malloc::free(sp.cast());
                return null_mut();
            }
            let p = fts_alloc(s, *a, len);
            (*p).fts_level = FTS_ROOTLEVEL;
            (*p).fts_parent = parent;
            (*p).fts_accpath = (*p).fts_name.as_mut_ptr();
            (*p).fts_info = fts_stat(s, p, is_set(s, FTS_COMFOLLOW));
            if (*p).fts_info == FTS_DOT {
                (*p).fts_info = FTS_D;
            }
            if compar.is_some() {
                (*p).fts_link = root;
                root = p;
            } else {
                (*p).fts_link = null_mut();
                if root.is_null() {
                    root = p;
                    tmp = p;
                } else {
                    (*tmp).fts_link = p;
                    tmp = p;
                }
            }
            a = a.add(1);
            nitems += 1;
        }
        if compar.is_some() && nitems > 1 {
            root = fts_sort(s, root, nitems);
        }
        s.fts_cur = fts_alloc(s, c"".as_ptr(), 0);
        if s.fts_cur.is_null() {
            fts_lfree(root);
            rusty_libc_malloc::free(parent.cast());
            rusty_libc_malloc::free(s.fts_path.cast());
            rusty_libc_malloc::free(sp.cast());
            return null_mut();
        }
        (*s.fts_cur).fts_link = root;
        (*s.fts_cur).fts_info = FTS_INIT;
        if !is_set(s, FTS_NOCHDIR) {
            s.fts_rfd = sys_open(c".".as_ptr(), O_RDONLY);
            if s.fts_rfd < 0 {
                s.fts_options |= FTS_NOCHDIR;
            }
        }
        sp
    }
}

unsafe fn fts_load(sp: &mut Fts, p: *mut Ftsent) {
    unsafe {
        let pe = &mut *p;
        let len = pe.fts_namelen as usize;
        pe.fts_pathlen = len as u16;
        core::ptr::copy(pe.fts_name.as_ptr(), sp.fts_path, len + 1);
        let cp = rusty_libc_mem::strrchr(pe.fts_name.as_ptr(), b'/' as c_int);
        if !cp.is_null() && (!core::ptr::eq(cp as *const c_char, pe.fts_name.as_ptr()) || *cp.add(1) != 0) {
            let cp = cp.add(1);
            let l = slen(cp);
            core::ptr::copy(cp, pe.fts_name.as_mut_ptr(), l + 1);
            pe.fts_namelen = l as u16;
        }
        pe.fts_accpath = sp.fts_path;
        pe.fts_path = sp.fts_path;
        sp.fts_dev = pe.fts_dev;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_close(sp: *mut Fts) -> c_int {
    unsafe {
        let s = &mut *sp;
        if !s.fts_cur.is_null() {
            let mut p = s.fts_cur;
            while !p.is_null() && (*p).fts_level >= FTS_ROOTLEVEL {
                let freep = p;
                p = if !(*p).fts_link.is_null() { (*p).fts_link } else { (*p).fts_parent };
                rusty_libc_malloc::free(freep.cast());
            }
            rusty_libc_malloc::free(p.cast());
        }
        if !s.fts_child.is_null() {
            fts_lfree(s.fts_child);
        }
        rusty_libc_malloc::free(s.fts_array.cast());
        rusty_libc_malloc::free(s.fts_path.cast());
        if !is_set(s, FTS_NOCHDIR) {
            let saved_errno = if sys_fchdir(s.fts_rfd) != 0 { errno::get() } else { 0 };
            sys_close(s.fts_rfd);
            if saved_errno != 0 {
                rusty_libc_malloc::free(sp.cast());
                errno::set(saved_errno);
                return -1;
            }
        }
        rusty_libc_malloc::free(sp.cast());
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_read(sp: *mut Fts) -> *mut Ftsent {
    unsafe {
        let s = &mut *sp;
        if s.fts_cur.is_null() || is_set(s, FTS_STOP) {
            return null_mut();
        }
        let mut p = s.fts_cur;
        let instr = (*p).fts_instr as c_int;
        (*p).fts_instr = FTS_NOINSTR as u16;
        if instr == FTS_AGAIN {
            (*p).fts_info = fts_stat(s, p, false);
            return p;
        }
        if instr == FTS_FOLLOW && ((*p).fts_info == FTS_SL || (*p).fts_info == FTS_SLNONE) {
            (*p).fts_info = fts_stat(s, p, true);
            if (*p).fts_info == FTS_D && !is_set(s, FTS_NOCHDIR) {
                (*p).fts_symfd = sys_open(c".".as_ptr(), O_RDONLY);
                if (*p).fts_symfd < 0 {
                    (*p).fts_errno = errno::get();
                    (*p).fts_info = FTS_ERR;
                } else {
                    (*p).fts_flags |= FTS_SYMFOLLOW;
                }
            }
            return p;
        }
        if (*p).fts_info == FTS_D {
            if instr == FTS_SKIP || (is_set(s, FTS_XDEV) && (*p).fts_dev != s.fts_dev) {
                if (*p).fts_flags & FTS_SYMFOLLOW != 0 {
                    sys_close((*p).fts_symfd);
                }
                if !s.fts_child.is_null() {
                    fts_lfree(s.fts_child);
                    s.fts_child = null_mut();
                }
                (*p).fts_info = FTS_DP;
                return p;
            }
            if !s.fts_child.is_null() && is_set(s, FTS_NAMEONLY) {
                s.fts_options &= !FTS_NAMEONLY;
                fts_lfree(s.fts_child);
                s.fts_child = null_mut();
            }
            if !s.fts_child.is_null() {
                if fts_safe_changedir(s, p, -1, (*p).fts_accpath) != 0 {
                    (*p).fts_errno = errno::get();
                    (*p).fts_flags |= FTS_DONTCHDIR;
                    let mut c = s.fts_child;
                    while !c.is_null() {
                        (*c).fts_accpath = (*(*c).fts_parent).fts_accpath;
                        c = (*c).fts_link;
                    }
                }
            } else {
                s.fts_child = fts_build(s, BREAD);
                if s.fts_child.is_null() {
                    if is_set(s, FTS_STOP) {
                        return null_mut();
                    }
                    return p;
                }
            }
            p = s.fts_child;
            s.fts_child = null_mut();
            s.fts_cur = p;
            return name_path(s, p);
        }
        let mut tmp = p;
        p = (*p).fts_link;
        if !p.is_null() {
            s.fts_cur = p;
            rusty_libc_malloc::free(tmp.cast());
            if (*p).fts_level == FTS_ROOTLEVEL {
                if !is_set(s, FTS_NOCHDIR) && sys_fchdir(s.fts_rfd) != 0 {
                    s.fts_options |= FTS_STOP;
                    return null_mut();
                }
                fts_load(s, p);
                return p;
            }
            loop {
                if (*p).fts_instr as c_int == FTS_SKIP {
                    tmp = p;
                    p = (*p).fts_link;
                    if !p.is_null() {
                        s.fts_cur = p;
                        rusty_libc_malloc::free(tmp.cast());
                        if (*p).fts_level == FTS_ROOTLEVEL {
                            if !is_set(s, FTS_NOCHDIR) && sys_fchdir(s.fts_rfd) != 0 {
                                s.fts_options |= FTS_STOP;
                                return null_mut();
                            }
                            fts_load(s, p);
                            return p;
                        }
                        continue;
                    }
                    return fts_up(s, tmp);
                }
                break;
            }
            if (*p).fts_instr as c_int == FTS_FOLLOW {
                (*p).fts_info = fts_stat(s, p, true);
                if (*p).fts_info == FTS_D && !is_set(s, FTS_NOCHDIR) {
                    (*p).fts_symfd = sys_open(c".".as_ptr(), O_RDONLY);
                    if (*p).fts_symfd < 0 {
                        (*p).fts_errno = errno::get();
                        (*p).fts_info = FTS_ERR;
                    } else {
                        (*p).fts_flags |= FTS_SYMFOLLOW;
                    }
                }
                (*p).fts_instr = FTS_NOINSTR as u16;
            }
            return name_path(s, p);
        }
        fts_up(s, tmp)
    }
}

unsafe fn name_path(sp: &mut Fts, p: *mut Ftsent) -> *mut Ftsent {
    unsafe {
        let mut t = sp.fts_path.add(nappend(&*(*p).fts_parent));
        *t = b'/' as c_char;
        t = t.add(1);
        core::ptr::copy((*p).fts_name.as_ptr(), t, (*p).fts_namelen as usize + 1);
        p
    }
}

unsafe fn fts_up(sp: &mut Fts, tmp: *mut Ftsent) -> *mut Ftsent {
    unsafe {
        let p = (*tmp).fts_parent;
        sp.fts_cur = p;
        rusty_libc_malloc::free(tmp.cast());
        if (*p).fts_level == FTS_ROOTPARENTLEVEL {
            rusty_libc_malloc::free(p.cast());
            errno::set(0);
            sp.fts_cur = null_mut();
            return null_mut();
        }
        *sp.fts_path.add((*p).fts_pathlen as usize) = 0;
        if (*p).fts_level == FTS_ROOTLEVEL {
            if !is_set(sp, FTS_NOCHDIR) && sys_fchdir(sp.fts_rfd) != 0 {
                sp.fts_options |= FTS_STOP;
                return null_mut();
            }
        } else if (*p).fts_flags & FTS_SYMFOLLOW != 0 {
            if !is_set(sp, FTS_NOCHDIR) && sys_fchdir((*p).fts_symfd) != 0 {
                let saved = errno::get();
                sys_close((*p).fts_symfd);
                errno::set(saved);
                sp.fts_options |= FTS_STOP;
                return null_mut();
            }
            sys_close((*p).fts_symfd);
        } else if (*p).fts_flags & FTS_DONTCHDIR == 0 && fts_safe_changedir(sp, (*p).fts_parent, -1, c"..".as_ptr()) != 0 {
            sp.fts_options |= FTS_STOP;
            return null_mut();
        }
        (*p).fts_info = if (*p).fts_errno != 0 { FTS_ERR } else { FTS_DP };
        p
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_set(_sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int {
    unsafe {
        if instr != 0 && instr != FTS_AGAIN && instr != FTS_FOLLOW && instr != FTS_NOINSTR && instr != FTS_SKIP {
            errno::set(EINVAL);
            return 1;
        }
        (*p).fts_instr = instr as u16;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fts_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent {
    unsafe {
        let s = &mut *sp;
        if instr != 0 && instr != FTS_NAMEONLY {
            errno::set(EINVAL);
            return null_mut();
        }
        let p = s.fts_cur;
        errno::set(0);
        if is_set(s, FTS_STOP) {
            return null_mut();
        }
        if (*p).fts_info == FTS_INIT {
            return (*p).fts_link;
        }
        if (*p).fts_info != FTS_D {
            return null_mut();
        }
        if !s.fts_child.is_null() {
            fts_lfree(s.fts_child);
        }
        let kind = if instr == FTS_NAMEONLY {
            s.fts_options |= FTS_NAMEONLY;
            BNAMES
        } else {
            BCHILD
        };
        if (*p).fts_level != FTS_ROOTLEVEL || *(*p).fts_accpath == b'/' as c_char || is_set(s, FTS_NOCHDIR) {
            s.fts_child = fts_build(s, kind);
            return s.fts_child;
        }
        let fd = sys_open(c".".as_ptr(), O_RDONLY);
        if fd < 0 {
            return null_mut();
        }
        s.fts_child = fts_build(s, kind);
        if sys_fchdir(fd) != 0 {
            return null_mut();
        }
        sys_close(fd);
        s.fts_child
    }
}

unsafe fn fts_build(sp: &mut Fts, type_: c_int) -> *mut Ftsent {
    unsafe {
        let cur = sp.fts_cur;
        let dirp: *mut DIR = opendir((*cur).fts_accpath);
        let mut dirp = dirp;
        if dirp.is_null() {
            if type_ == BREAD {
                (*cur).fts_info = FTS_DNR;
                (*cur).fts_errno = errno::get();
            }
            return null_mut();
        }
        let mut nlinks: i64;
        let mut nostat = false;
        if type_ == BNAMES {
            nlinks = 0;
        } else if is_set(sp, FTS_NOSTAT) && is_set(sp, FTS_PHYSICAL) {
            nlinks = (*cur).fts_nlink as i64 - if is_set(sp, FTS_SEEDOT) { 0 } else { 2 };
            nostat = true;
        } else {
            nlinks = -1;
        }
        let mut descend = false;
        if nlinks != 0 || type_ == BREAD {
            if fts_safe_changedir(sp, cur, dirfd(dirp), core::ptr::null()) != 0 {
                if nlinks != 0 && type_ == BREAD {
                    (*cur).fts_errno = errno::get();
                }
                (*cur).fts_flags |= FTS_DONTCHDIR;
                descend = false;
                closedir(dirp);
                dirp = null_mut();
            } else {
                descend = true;
            }
        }
        let mut len = nappend(&*cur);
        let mut cp: *mut c_char = null_mut();
        if is_set(sp, FTS_NOCHDIR) {
            cp = sp.fts_path.add(len);
            *cp = b'/' as c_char;
            cp = cp.add(1);
        }
        len += 1;
        let mut maxlen = sp.fts_pathlen as usize - len;
        let level = (*cur).fts_level + 1;
        let mut doadjust = false;
        let mut head: *mut Ftsent = null_mut();
        let mut tail: *mut Ftsent = null_mut();
        let mut nitems = 0;
        while !dirp.is_null() {
            let dp: *mut dirent = readdir(dirp);
            if dp.is_null() {
                break;
            }
            let dname = (*dp).d_name.as_ptr();
            if !is_set(sp, FTS_SEEDOT) && is_dot(dname) {
                continue;
            }
            let namlen = slen(dname);
            let p = fts_alloc(sp, dname, namlen);
            if p.is_null() {
                return build_fail(sp, cur, head, dirp, errno::get());
            }
            if namlen >= maxlen {
                let oldaddr = sp.fts_path;
                if fts_palloc(sp, namlen + len + 1) != 0 {
                    let saved = errno::get();
                    rusty_libc_malloc::free(p.cast());
                    return build_fail(sp, cur, head, dirp, saved);
                }
                if oldaddr != sp.fts_path {
                    doadjust = true;
                    if is_set(sp, FTS_NOCHDIR) {
                        cp = sp.fts_path.add(len);
                    }
                }
                maxlen = sp.fts_pathlen as usize - len;
            }
            if len + namlen >= USHRT_MAX {
                rusty_libc_malloc::free(p.cast());
                return build_fail(sp, cur, head, dirp, ENAMETOOLONG);
            }
            (*p).fts_level = level;
            (*p).fts_parent = sp.fts_cur;
            (*p).fts_pathlen = (len + namlen) as u16;
            if nlinks == 0 || (nostat && dirent_not_directory(&*dp)) {
                (*p).fts_accpath = if is_set(sp, FTS_NOCHDIR) { (*p).fts_path } else { (*p).fts_name.as_mut_ptr() };
                (*p).fts_info = FTS_NSOK;
            } else {
                if is_set(sp, FTS_NOCHDIR) {
                    (*p).fts_accpath = (*p).fts_path;
                    core::ptr::copy((*p).fts_name.as_ptr(), cp, (*p).fts_namelen as usize + 1);
                } else {
                    (*p).fts_accpath = (*p).fts_name.as_mut_ptr();
                }
                (*p).fts_info = fts_stat(sp, p, false);
                if nlinks > 0 && ((*p).fts_info == FTS_D || (*p).fts_info == FTS_DC || (*p).fts_info == FTS_DOT) {
                    nlinks -= 1;
                }
            }
            (*p).fts_link = null_mut();
            if head.is_null() {
                head = p;
                tail = p;
            } else {
                (*tail).fts_link = p;
                tail = p;
            }
            nitems += 1;
        }
        if !dirp.is_null() {
            closedir(dirp);
        }
        if doadjust {
            fts_padjust(sp, head);
        }
        if is_set(sp, FTS_NOCHDIR) {
            if len == sp.fts_pathlen as usize || nitems == 0 {
                cp = cp.sub(1);
            }
            *cp = 0;
        }
        if descend && (type_ == BCHILD || nitems == 0) {
            let failed = if (*cur).fts_level == FTS_ROOTLEVEL { !is_set(sp, FTS_NOCHDIR) && sys_fchdir(sp.fts_rfd) != 0 } else { fts_safe_changedir(sp, (*cur).fts_parent, -1, c"..".as_ptr()) != 0 };
            if failed {
                (*cur).fts_info = FTS_ERR;
                sp.fts_options |= FTS_STOP;
                fts_lfree(head);
                return null_mut();
            }
        }
        if nitems == 0 {
            if type_ == BREAD {
                (*cur).fts_info = FTS_DP;
            }
            fts_lfree(head);
            return null_mut();
        }
        if sp.fts_compar.is_some() && nitems > 1 {
            head = fts_sort(sp, head, nitems);
        }
        head
    }
}

unsafe fn build_fail(sp: &mut Fts, cur: *mut Ftsent, head: *mut Ftsent, dirp: *mut DIR, err: c_int) -> *mut Ftsent {
    unsafe {
        fts_lfree(head);
        closedir(dirp);
        (*cur).fts_info = FTS_ERR;
        sp.fts_options |= FTS_STOP;
        errno::set(err);
        null_mut()
    }
}

fn dirent_not_directory(dp: &dirent) -> bool {
    dp.d_type != DT_DIR && dp.d_type != DT_UNKNOWN
}

unsafe fn fts_stat(sp: &mut Fts, p: *mut Ftsent, follow: bool) -> u16 {
    unsafe {
        let mut local = Stat::zeroed();
        let sbp: *mut Stat = if is_set(sp, FTS_NOSTAT) { &mut local } else { (*p).fts_statp };
        let mut failed = false;
        if is_set(sp, FTS_LOGICAL) || follow {
            if sys_stat((*p).fts_accpath, sbp) != 0 {
                let saved = errno::get();
                if sys_lstat((*p).fts_accpath, sbp) == 0 {
                    errno::set(0);
                    return FTS_SLNONE;
                }
                (*p).fts_errno = saved;
                failed = true;
            }
        } else if sys_lstat((*p).fts_accpath, sbp) != 0 {
            (*p).fts_errno = errno::get();
            failed = true;
        }
        if failed {
            core::ptr::write_bytes(sbp, 0, 1);
            return FTS_NS;
        }
        let mode = (*sbp).st_mode;
        if mode & 0o170000 == 0o040000 {
            let dev = (*sbp).st_dev;
            let ino = (*sbp).st_ino;
            (*p).fts_dev = dev;
            (*p).fts_ino = ino;
            (*p).fts_nlink = (*sbp).st_nlink;
            if is_dot((*p).fts_name.as_ptr()) {
                return FTS_DOT;
            }
            let mut t = (*p).fts_parent;
            while (*t).fts_level >= FTS_ROOTLEVEL {
                if ino == (*t).fts_ino && dev == (*t).fts_dev {
                    (*p).fts_cycle = t;
                    return FTS_DC;
                }
                t = (*t).fts_parent;
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
}

unsafe fn fts_sort(sp: &mut Fts, head: *mut Ftsent, nitems: c_int) -> *mut Ftsent {
    unsafe {
        if nitems > sp.fts_nitems {
            sp.fts_nitems = nitems + 40;
            let a = rusty_libc_malloc::realloc(sp.fts_array.cast(), sp.fts_nitems as usize * size_of::<*mut Ftsent>()) as *mut *mut Ftsent;
            if a.is_null() {
                rusty_libc_malloc::free(sp.fts_array.cast());
                sp.fts_array = null_mut();
                sp.fts_nitems = 0;
                return head;
            }
            sp.fts_array = a;
        }
        let mut ap = sp.fts_array;
        let mut p = head;
        while !p.is_null() {
            *ap = p;
            ap = ap.add(1);
            p = (*p).fts_link;
        }
        rusty_libc_stdlib::sort::qsort(sp.fts_array.cast(), nitems as usize, size_of::<*mut Ftsent>(), sp.fts_compar.unwrap());
        let mut ap = sp.fts_array;
        let head = *ap;
        for _ in 1..nitems {
            (**ap).fts_link = *ap.add(1);
            ap = ap.add(1);
        }
        (**ap).fts_link = null_mut();
        head
    }
}

unsafe fn fts_alloc(sp: &mut Fts, name: *const c_char, namelen: usize) -> *mut Ftsent {
    unsafe {
        let mut len = size_of::<Ftsent>() + namelen;
        if !is_set(sp, FTS_NOSTAT) {
            len += size_of::<Stat>() + ALIGNBYTES;
        }
        let p = rusty_libc_malloc::malloc(len) as *mut Ftsent;
        if p.is_null() {
            return null_mut();
        }
        core::ptr::write_bytes(p as *mut u8, 0, size_of::<Ftsent>());
        let nm = (*p).fts_name.as_mut_ptr();
        core::ptr::copy(name, nm, namelen);
        *nm.add(namelen) = 0;
        if !is_set(sp, FTS_NOSTAT) {
            (*p).fts_statp = ((nm.add(namelen + 2) as usize + ALIGNBYTES) & !ALIGNBYTES) as *mut Stat;
        }
        (*p).fts_namelen = namelen as u16;
        (*p).fts_path = sp.fts_path;
        (*p).fts_errno = 0;
        (*p).fts_flags = 0;
        (*p).fts_instr = FTS_NOINSTR as u16;
        (*p).fts_number = 0;
        (*p).fts_pointer = null_mut();
        p
    }
}

unsafe fn fts_lfree(head: *mut Ftsent) {
    unsafe {
        let mut p = head;
        while !p.is_null() {
            let next = (*p).fts_link;
            rusty_libc_malloc::free(p.cast());
            p = next;
        }
    }
}

unsafe fn fts_palloc(sp: &mut Fts, more: usize) -> c_int {
    unsafe {
        sp.fts_pathlen = sp.fts_pathlen.wrapping_add((more + 256) as c_int);
        if sp.fts_pathlen < 0 || sp.fts_pathlen as usize >= USHRT_MAX {
            rusty_libc_malloc::free(sp.fts_path.cast());
            sp.fts_path = null_mut();
            errno::set(ENAMETOOLONG);
            return 1;
        }
        let p = rusty_libc_malloc::realloc(sp.fts_path.cast(), sp.fts_pathlen as usize) as *mut c_char;
        if p.is_null() {
            rusty_libc_malloc::free(sp.fts_path.cast());
            sp.fts_path = null_mut();
            return 1;
        }
        sp.fts_path = p;
        0
    }
}

unsafe fn fts_padjust(sp: &mut Fts, head: *mut Ftsent) {
    unsafe {
        let addr = sp.fts_path;
        let adjust = |p: *mut Ftsent| {
            if (*p).fts_accpath != (*p).fts_name.as_mut_ptr() {
                (*p).fts_accpath = addr.offset((*p).fts_accpath.offset_from((*p).fts_path));
            }
            (*p).fts_path = addr;
        };
        let mut p = sp.fts_child;
        while !p.is_null() {
            adjust(p);
            p = (*p).fts_link;
        }
        let mut p = head;
        while (*p).fts_level >= FTS_ROOTLEVEL {
            adjust(p);
            p = if !(*p).fts_link.is_null() { (*p).fts_link } else { (*p).fts_parent };
        }
    }
}

unsafe fn maxarglen(argv: *const *mut c_char) -> usize {
    unsafe {
        let mut max = 0;
        let mut a = argv;
        while !(*a).is_null() {
            max = max.max(slen(*a));
            a = a.add(1);
        }
        max + 1
    }
}

unsafe fn fts_safe_changedir(sp: &mut Fts, p: *mut Ftsent, fd: c_int, path: *const c_char) -> c_int {
    unsafe {
        if is_set(sp, FTS_NOCHDIR) {
            return 0;
        }
        let mut newfd = fd;
        if fd < 0 {
            newfd = sys_open(path, O_RDONLY);
            if newfd < 0 {
                return -1;
            }
        }
        let mut sb = Stat::zeroed();
        let mut ret;
        if sys_fstat(newfd, &mut sb) != 0 {
            ret = -1;
        } else if (*p).fts_dev != sb.st_dev || (*p).fts_ino != sb.st_ino {
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
    fts: *mut Fts,
}

impl Walk {
    pub fn open(roots: &[&CStr], options: c_int) -> Result<Walk, c_int> {
        unsafe {
            let array = rusty_libc_malloc::malloc((roots.len() + 1) * size_of::<*mut c_char>()) as *mut *mut c_char;
            if array.is_null() {
                return Err(ENOMEM);
            }
            for (i, r) in roots.iter().enumerate() {
                *array.add(i) = r.as_ptr() as *mut c_char;
            }
            *array.add(roots.len()) = null_mut();
            let fts = fts_open(array, options, None);
            let err = errno::get();
            rusty_libc_malloc::free(array.cast());
            if fts.is_null() { Err(err) } else { Ok(Walk { fts }) }
        }
    }

    pub fn next_entry(&mut self) -> Option<&Ftsent> {
        let p = unsafe { fts_read(self.fts) };
        if p.is_null() { None } else { Some(unsafe { &*p }) }
    }

    pub fn set(&mut self, instr: c_int) -> bool {
        unsafe {
            let cur = (*self.fts).fts_cur;
            !cur.is_null() && fts_set(self.fts, cur, instr) == 0
        }
    }

    pub fn error(&self) -> c_int {
        errno::get()
    }

    pub fn as_ptr(&self) -> *mut Fts {
        self.fts
    }
}

impl Drop for Walk {
    fn drop(&mut self) {
        unsafe { fts_close(self.fts) };
    }
}

impl Ftsent {
    pub fn name(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.fts_name.as_ptr() as *const u8, self.fts_namelen as usize) }
    }

    pub fn path(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.fts_path as *const u8, self.fts_pathlen as usize) }
    }
}
