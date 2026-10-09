use crate::flock::FLock;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rusty_libc_core::lock::{RawMutex, multithreaded};
use rusty_libc_core::{errno, syscall, unistd};

pub const BUFSIZ: usize = 8192;
pub const EOF: c_int = -1;

pub const F_USERBUF: u32 = 0x1;
pub const F_UNBUF: u32 = 0x2;
pub const F_NOREAD: u32 = 0x4;
pub const F_NOWRITE: u32 = 0x8;
pub const F_EOF: u32 = 0x10;
pub const F_ERR: u32 = 0x20;
pub const F_UNGOT: u32 = 0x100;
pub const F_LBF: u32 = 0x200;
pub const F_PUTTING: u32 = 0x800;
pub const F_APPEND: u32 = 0x1000;
pub const F_READ: u32 = 1 << 16;
pub const F_WRITE: u32 = 1 << 17;
pub const F_DECIDED: u32 = 1 << 18;
pub const F_STATIC: u32 = 1 << 19;
pub const F_RDMODE: u32 = 1 << 20;
pub const F_WRMODE: u32 = 1 << 21;
pub const F_NOSEEK: u32 = 1 << 22;
pub const F_MEM: u32 = 1 << 23;
pub const F_NOCACHE: u32 = 1 << 24;
pub const F_WIDE: u32 = 1 << 25;
pub const F_BYTE: u32 = 1 << 26;
pub const F_OLDMEM: u32 = 1 << 27;
pub const F_W32: u32 = 1 << 28;
pub const F_NOCANCEL: u32 = 1 << 29;
pub const F_SEEKED: u32 = 1 << 30;
pub const F_NOEOF: u32 = 1 << 31;

pub const fn with_access_bits(flags: u32) -> u32 {
    let f = flags & !(F_NOREAD | F_NOWRITE);
    f | if f & F_READ == 0 { F_NOREAD } else { 0 } | if f & F_WRITE == 0 { F_NOWRITE } else { 0 }
}

#[derive(Clone, Copy)]
pub struct CookieIo {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub sync: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct File {
    pub flags: u32,
    pub fd: c_int,
    pub rptr: *mut u8,
    pub rend_p: *mut u8,
    pub rbase: *mut u8,
    pub wbase: *mut u8,
    pub wptr: *mut u8,
    pub wend: *mut u8,
    pub buf: *mut u8,
    pub bufsize: usize,
    pub save_base: *mut u8,
    pub backup_base: *mut u8,
    pub save_end: *mut u8,
    pub unget: [u8; 16],
    pub ubuf: *mut u8,
    pub ucap: usize,
    pub shortbuf: [u8; 8],
    pub next: *mut File,
    pub cookie_pos: i64,
    pub prev: *mut File,
    pub cookie: *mut c_void,
    pub io: CookieIo,
    pub pid: c_int,
    pub wide: *mut crate::wfile::WideInfo,
    pub lock: FLock,
    pub pins: AtomicU32,
    pub linked: AtomicBool,
    pub nolock: bool,
    pub fork_held: u8,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(File, flags) == 0);
    assert!(offset_of!(File, rptr) == 8);
    assert!(offset_of!(File, rend_p) == 16);
    assert!(offset_of!(File, rbase) == 24);
    assert!(offset_of!(File, wbase) == 32);
    assert!(offset_of!(File, wptr) == 40);
    assert!(offset_of!(File, wend) == 48);
    assert!(offset_of!(File, buf) == 56);
    assert!(offset_of!(File, save_base) == 72);
    assert!(offset_of!(File, save_end) == 88);
    assert!(offset_of!(File, cookie_pos) == 144);
};

impl File {
    pub const fn blank(flags: u32, fd: c_int) -> File {
        File {
            flags: with_access_bits(flags),
            fd,
            rptr: null_mut(),
            rend_p: null_mut(),
            rbase: null_mut(),
            wbase: null_mut(),
            wptr: null_mut(),
            wend: null_mut(),
            buf: null_mut(),
            bufsize: 0,
            save_base: null_mut(),
            backup_base: null_mut(),
            save_end: null_mut(),
            unget: [0; 16],
            ubuf: null_mut(),
            ucap: 1,
            shortbuf: [0; 8],
            next: null_mut(),
            cookie_pos: -1,
            prev: null_mut(),
            cookie: null_mut(),
            io: CookieIo { read: None, write: None, seek: None, close: None, sync: None },
            pid: 0,
            wide: null_mut(),
            lock: FLock::new(),
            pins: AtomicU32::new(0),
            linked: AtomicBool::new(false),
            nolock: false,
            fork_held: 0,
        }
    }

    pub fn reset(&mut self, flags: u32, fd: c_int) {
        self.flags = with_access_bits(flags) & !(F_UNGOT | F_PUTTING);
        self.fd = fd;
        self.buf = null_mut();
        self.bufsize = 0;
        self.rptr = null_mut();
        self.rend_p = null_mut();
        self.rbase = null_mut();
        self.wbase = null_mut();
        self.wptr = null_mut();
        self.wend = null_mut();
        self.save_base = null_mut();
        self.save_end = null_mut();
        self.unget = [0; 16];
        self.ubuf = null_mut();
        self.ucap = 1;
        self.cookie = null_mut();
        self.io = CookieIo { read: None, write: None, seek: None, close: None, sync: None };
        self.pid = 0;
        self.cookie_pos = -1;
        self.wide = null_mut();
    }

    #[inline(always)]
    pub fn rpos(&self) -> usize {
        (if self.flags & F_UNGOT != 0 { self.save_base } else { self.rptr }) as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn rend(&self) -> usize {
        (if self.flags & F_UNGOT != 0 { self.save_end } else { self.rend_p }) as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn set_rpos(&mut self, n: usize) {
        let p = self.buf.wrapping_add(n);
        if self.flags & F_UNGOT != 0 { self.save_base = p } else { self.rptr = p }
    }
    #[inline(always)]
    pub fn set_read(&mut self, pos: usize, end: usize) {
        let (p, e) = (self.buf.wrapping_add(pos), self.buf.wrapping_add(end));
        if self.flags & F_UNGOT != 0 {
            self.save_base = p;
            self.save_end = e;
        } else {
            self.rptr = p;
            self.rend_p = e;
            self.rbase = self.buf;
        }
    }
    #[inline(always)]
    pub fn nunget(&self) -> usize {
        if self.flags & F_UNGOT != 0 { self.rend_p as usize - self.rptr as usize } else { 0 }
    }
    #[inline(always)]
    pub fn wpos(&self) -> usize {
        self.wptr as usize - self.wbase as usize
    }
    #[inline(always)]
    pub fn set_wpos(&mut self, n: usize) {
        self.wbase = self.buf;
        self.wptr = self.buf.wrapping_add(n);
        self.wend = if self.flags & (F_WRMODE | F_UNBUF | F_LBF | F_WIDE) == F_WRMODE && !self.buf.is_null() {
            self.buf.wrapping_add(self.bufsize)
        } else {
            self.buf
        };
    }
    pub fn set_buffer(&mut self, b: *mut u8, size: usize) {
        self.buf = b;
        self.bufsize = size;
        self.set_read(0, 0);
        self.set_wpos(0);
    }
}

pub static mut STDIN_FILE: File = File::blank(F_READ | F_STATIC, 0);
pub static mut STDOUT_FILE: File = File::blank(F_WRITE | F_STATIC, 1);
pub static mut STDERR_FILE: File = File::blank(F_WRITE | F_STATIC | F_UNBUF | F_DECIDED, 2);

static mut OPEN_HEAD: *mut File = null_mut();
static STD_LINKED: AtomicBool = AtomicBool::new(false);
static LIST: RawMutex = RawMutex::new();

pub unsafe fn stdin_ptr() -> *mut File {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(crate::file_api::stdin)) }
}
pub unsafe fn stdout_ptr() -> *mut File {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(crate::file_api::stdout)) }
}
pub unsafe fn stderr_ptr() -> *mut File {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(crate::file_api::stderr)) }
}

unsafe fn link_standard() {
    unsafe {
        if STD_LINKED.load(Ordering::Acquire) {
            return;
        }
        let t = LIST.lock();
        if !STD_LINKED.load(Ordering::Relaxed) {
            link_locked(core::ptr::addr_of_mut!(STDIN_FILE));
            link_locked(core::ptr::addr_of_mut!(STDOUT_FILE));
            link_locked(core::ptr::addr_of_mut!(STDERR_FILE));
            STD_LINKED.store(true, Ordering::Release);
        }
        LIST.unlock(t);
    }
}

unsafe fn link_locked(f: *mut File) {
    unsafe {
        (*f).next = OPEN_HEAD;
        (*f).prev = null_mut();
        if !OPEN_HEAD.is_null() {
            (*OPEN_HEAD).prev = f;
        }
        OPEN_HEAD = f;
        (*f).linked.store(true, Ordering::Relaxed);
    }
}

pub unsafe fn link(f: *mut File) {
    unsafe {
        let t = LIST.lock();
        link_locked(f);
        LIST.unlock(t);
    }
}

pub unsafe fn unlink(f: *mut File) {
    unsafe {
        let t = LIST.lock();
        if !(*f).prev.is_null() {
            (*(*f).prev).next = (*f).next;
        } else if OPEN_HEAD == f {
            OPEN_HEAD = (*f).next;
        }
        if !(*f).next.is_null() {
            (*(*f).next).prev = (*f).prev;
        }
        (*f).next = null_mut();
        (*f).prev = null_mut();
        (*f).linked.store(false, Ordering::Relaxed);
        LIST.unlock(t);
    }
}

unsafe fn walk_pinned(mut visit: impl FnMut(*mut File)) {
    unsafe {
        link_standard();
        LIST.lock_always();
        let mut p = OPEN_HEAD;
        if !p.is_null() {
            (*p).pins.fetch_add(1, Ordering::AcqRel);
        }
        LIST.unlock_always();
        while !p.is_null() {
            visit(p);
            LIST.lock_always();
            let next = if (*p).linked.load(Ordering::Relaxed) { (*p).next } else { OPEN_HEAD };
            if !next.is_null() {
                (*next).pins.fetch_add(1, Ordering::AcqRel);
            }
            LIST.unlock_always();
            (*p).pins.fetch_sub(1, Ordering::AcqRel);
            p = next;
        }
    }
}

fn note_used() {
    static FORK_REGISTERED: AtomicBool = AtomicBool::new(false);
    rusty_libc_core::process::set_stdio_flush(flush_at_exit);
    if !FORK_REGISTERED.load(Ordering::Relaxed) && !FORK_REGISTERED.swap(true, Ordering::AcqRel) {
        rusty_libc_core::process::register_fork_handlers(atfork_prepare, atfork_parent, atfork_child);
    }
}

unsafe fn raw_read(f: *mut File, dst: *mut u8, n: usize) -> isize {
    unsafe {
        if (*f).flags & F_MEM != 0 {
            return match (*f).io.read {
                Some(r) => {
                    let got = r((*f).cookie, dst.cast(), n);
                    if got > 0 {
                        (*f).cookie_pos += got as i64;
                    }
                    got
                }
                None => {
                    errno::set(9);
                    -1
                }
            };
        }
        let buf = core::slice::from_raw_parts_mut(dst, n);
        let r = if (*f).flags & F_NOCANCEL != 0 { unistd::read_nocancel((*f).fd, buf) } else { unistd::read((*f).fd, buf) };
        match r {
            Ok(k) => {
                if (*f).cookie_pos >= 0 {
                    (*f).cookie_pos += k as i64;
                }
                k as isize
            }
            Err(e) => {
                errno::set(e.0);
                -1
            }
        }
    }
}

unsafe fn raw_write(f: *mut File, src: *const u8, n: usize) -> isize {
    unsafe {
        if (*f).flags & F_MEM != 0 {
            return match (*f).io.write {
                Some(w) => {
                    let put = w((*f).cookie, src.cast(), n);
                    if (*f).flags & F_APPEND != 0 {
                        (*f).cookie_pos = -1;
                    } else if put > 0 {
                        (*f).cookie_pos += put as i64;
                    }
                    if put == 0 && n > 0 {
                        return -1;
                    }
                    put
                }
                None => {
                    errno::set(9);
                    -1
                }
            };
        }
        let buf = core::slice::from_raw_parts(src, n);
        let r = if (*f).flags & F_NOCANCEL != 0 { unistd::write_nocancel((*f).fd, buf) } else { unistd::write((*f).fd, buf) };
        match r {
            Ok(k) => {
                if (*f).flags & F_APPEND != 0 {
                    (*f).cookie_pos = -1;
                } else if (*f).cookie_pos >= 0 {
                    (*f).cookie_pos += k as i64;
                }
                k as isize
            }
            Err(e) => {
                errno::set(e.0);
                -1
            }
        }
    }
}

unsafe fn raw_seek(f: *mut File, off: i64, whence: c_int) -> Result<i64, i32> {
    unsafe {
        if (*f).flags & F_MEM != 0 {
            return match (*f).io.seek {
                Some(s) => {
                    let mut pos = off;
                    if s((*f).cookie, &mut pos, whence) != 0 {
                        Err(errno::get())
                    } else {
                        (*f).cookie_pos = pos;
                        Ok(pos)
                    }
                }
                None => Err(29),
            };
        }
        match unistd::lseek((*f).fd, off, whence) {
            Ok(p) => {
                (*f).cookie_pos = p;
                Ok(p)
            }
            Err(e) => Err(e.0),
        }
    }
}

unsafe fn offset(f: *mut File) -> Result<i64, i32> {
    unsafe {
        let active = (*f).flags & (F_WRMODE | F_SEEKED) != 0 || (*f).flags & F_RDMODE != 0 && ((*f).rpos() < (*f).rend() || (*f).nunget() > 0);
        if (*f).cookie_pos >= 0 && (*f).flags & F_NOCACHE == 0 && (active || (*f).flags & F_MEM != 0) {
            Ok((*f).cookie_pos)
        } else {
            raw_seek(f, 0, 1)
        }
    }
}

unsafe fn decide(f: *mut File) {
    unsafe {
        if (*f).flags & F_DECIDED != 0 {
            return;
        }
        note_used();
        (*f).flags |= F_DECIDED;
        if (*f).flags & F_UNBUF != 0 {
            return;
        }
        let mut size = BUFSIZ;
        if (*f).flags & F_MEM == 0
            && (*f).fd >= 0
            && let Ok((mode, blksize, _)) = unistd::fstat_basic((*f).fd)
        {
            if mode & 0o170000 == 0o020000 && unistd::isatty((*f).fd) {
                (*f).flags |= F_LBF;
            }
            if blksize > 0 && (blksize as usize) < BUFSIZ {
                size = blksize as usize;
            }
        }
        if (*f).buf.is_null() {
            let b = rusty_libc_malloc::malloc(size) as *mut u8;
            if b.is_null() {
                (*f).flags |= F_UNBUF;
                return;
            }
            (*f).set_buffer(b, size);
        }
    }
}

unsafe fn prepare(f: *mut File) {
    unsafe {
        if (*f).flags & F_DECIDED == 0 {
            decide(f);
        } else if (*f).buf.is_null() && (*f).flags & F_UNBUF == 0 {
            let size = if (*f).bufsize != 0 { (*f).bufsize } else { BUFSIZ };
            let b = rusty_libc_malloc::malloc(size) as *mut u8;
            if b.is_null() {
                (*f).flags |= F_UNBUF;
            } else {
                (*f).set_buffer(b, size);
            }
        }
    }
}

pub unsafe fn flush_write(f: *mut File) -> bool {
    unsafe {
        if (*f).flags & F_WRMODE == 0 || (*f).wpos() == 0 {
            (*f).flags &= !F_WRMODE;
            (*f).set_wpos(0);
            reset_wextra(f);
            return true;
        }
        let mut off = 0;
        let n = (*f).wpos();
        while off < n {
            let k = raw_write(f, (*f).buf.add(off), n - off);
            if k < 0 {
                if errno::get() == 4 {
                    continue;
                }
                (*f).flags |= F_ERR;
                (*f).flags &= !F_WRMODE;
                (*f).set_wpos(0);
                reset_wextra(f);
                return false;
            }
            off += k as usize;
            if (*f).flags & F_MEM != 0 && off < n {
                (*f).flags |= F_ERR;
                (*f).flags &= !F_WRMODE;
                (*f).set_wpos(0);
                reset_wextra(f);
                return false;
            }
        }
        (*f).flags &= !F_WRMODE;
        (*f).set_wpos(0);
        reset_wextra(f);
        true
    }
}

unsafe fn flush_line_buffered() {
    unsafe { flush_lbf(false) }
}

unsafe fn flush_lbf(blocking: bool) {
    unsafe {
        link_standard();
        if !multithreaded() {
            let mut p = OPEN_HEAD;
            while !p.is_null() {
                if (*p).flags & F_LBF != 0 && (*p).flags & F_WRMODE != 0 {
                    flush_write(p);
                }
                p = (*p).next;
            }
            return;
        }
        walk_pinned(|p| {
            if (*p).flags & F_LBF != 0 && (*p).flags & F_WRMODE != 0 {
                if blocking {
                    (*p).lock.lock();
                } else if !(*p).lock.try_lock() {
                    return;
                }
                let mut cg = crate::flock::LockCleanup::idle();
                cg.arm(p);
                if (*p).linked.load(Ordering::Relaxed) && (*p).flags & F_WRMODE != 0 {
                    flush_write(p);
                }
                cg.disarm();
                (*p).lock.unlock();
            }
        });
    }
}

pub(crate) unsafe fn close_all() {
    unsafe {
        link_standard();
        if !multithreaded() {
            while !OPEN_HEAD.is_null() {
                fclose(OPEN_HEAD);
            }
            return;
        }
        loop {
            LIST.lock_always();
            let p = OPEN_HEAD;
            if p.is_null() {
                LIST.unlock_always();
                return;
            }
            (*p).pins.fetch_add(1, Ordering::AcqRel);
            LIST.unlock_always();
            close_stream(p, true);
        }
    }
}

pub(crate) unsafe fn fork_list_lock() -> bool {
    if multithreaded() {
        LIST.lock_always();
        true
    } else {
        false
    }
}

pub(crate) unsafe fn fork_list_unlock(taken: bool) {
    if taken {
        LIST.unlock_always();
    }
}

pub(crate) unsafe fn close_popen_fds(keep: c_int) {
    unsafe {
        let mut p = OPEN_HEAD;
        while !p.is_null() {
            if (*p).pid > 0 && (*p).fd >= 0 && (*p).fd != keep {
                let _ = unistd::close((*p).fd);
            }
            p = (*p).next;
        }
    }
}

pub(crate) unsafe fn purge(f: *mut File) {
    unsafe {
        reset_wextra(f);
        drop_unget(f);
        drop_wpush(f);
        (*f).flags &= !(F_RDMODE | F_WRMODE);
        (*f).set_read(0, 0);
        (*f).set_wpos(0);
    }
}

pub(crate) unsafe fn flush_line_buffered_pub() {
    unsafe { flush_lbf(true) }
}

pub fn note_locking() {
    note_used();
}

#[inline]
unsafe fn sync_mem(f: *mut File) {
    unsafe {
        if (*f).flags & F_MEM != 0
            && let Some(sy) = (*f).io.sync
        {
            sy((*f).cookie);
        }
    }
}

#[inline]
unsafe fn needs_flush(p: *mut File) -> bool {
    unsafe { (*p).flags & F_WRMODE != 0 || ((*p).flags & F_MEM != 0 && (*p).io.sync.is_some()) || has_unread_fd_input(p) }
}

#[inline]
unsafe fn has_unread_fd_input(p: *mut File) -> bool {
    unsafe { (*p).flags & (F_RDMODE | F_MEM) == F_RDMODE && (*p).fd >= 0 && ((*p).rend() > (*p).rpos() || (*p).nunget() > 0) }
}

pub unsafe fn freeres() {
    unsafe {
        flush_all();
        let t = LIST.lock();
        let mut p = OPEN_HEAD;
        while !p.is_null() {
            drop_unget(p);
            if !(*p).buf.is_null() && (*p).flags & F_USERBUF == 0 && (*p).rpos() >= (*p).rend() {
                rusty_libc_malloc::free((*p).buf.cast());
                (*p).set_buffer(null_mut(), 0);
            }
            p = (*p).next;
        }
        LIST.unlock(t);
    }
}

pub unsafe fn flush_all() -> bool {
    unsafe {
        link_standard();
        let mut ok = true;
        if !multithreaded() {
            let mut p = OPEN_HEAD;
            while !p.is_null() {
                sync_mem(p);
                if (*p).flags & F_WRMODE != 0 && !flush_write(p) {
                    ok = false;
                }
                if has_unread_fd_input(p) && !sync_input(p) {
                    ok = false;
                }
                p = (*p).next;
            }
            return ok;
        }
        walk_pinned(|p| {
            if !needs_flush(p) {
                return;
            }
            (*p).lock.lock();
            let mut cg = crate::flock::LockCleanup::idle();
            cg.arm(p);
            if (*p).linked.load(Ordering::Relaxed) {
                sync_mem(p);
                if (*p).flags & F_WRMODE != 0 && !flush_write(p) {
                    ok = false;
                }
                if has_unread_fd_input(p) && !sync_input(p) {
                    ok = false;
                }
            }
            cg.disarm();
            (*p).lock.unlock();
        });
        ok
    }
}

const EXIT_LOCK_WAIT: u64 = 10_000_000;

extern "C" fn flush_at_exit() {
    unsafe {
        if !multithreaded() {
            flush_all();
            return;
        }
        walk_pinned(|p| {
            if !needs_flush(p) {
                return;
            }
            let got = (*p).lock.lock_timeout(EXIT_LOCK_WAIT);
            if (*p).linked.load(Ordering::Relaxed) {
                sync_mem(p);
                if (*p).flags & F_WRMODE != 0 {
                    flush_write(p);
                }
                if has_unread_fd_input(p) {
                    sync_input(p);
                }
            }
            if got {
                (*p).lock.unlock();
            }
        });
    }
}

const FORK_LOCK_WAIT: u64 = 150_000_000;
static FORK_LOCK: RawMutex = RawMutex::new();
static FORK_REAL: AtomicBool = AtomicBool::new(false);

pub(crate) unsafe fn fork_grab(p: *mut File) {
    unsafe {
        if (*p).fork_held != 0 {
            return;
        }
        if (*p).lock.lock_timeout(FORK_LOCK_WAIT) {
            if (*p).linked.load(Ordering::Relaxed) {
                (*p).fork_held = 1;
            } else {
                (*p).lock.unlock();
            }
        } else {
            (*p).fork_held = 2;
        }
    }
}

unsafe extern "C" fn atfork_prepare() {
    unsafe {
        if !multithreaded() {
            FORK_REAL.store(false, Ordering::Relaxed);
            return;
        }
        FORK_LOCK.lock_always();
        FORK_REAL.store(true, Ordering::Relaxed);
        walk_pinned(|p| fork_grab(p));
        loop {
            LIST.lock_always();
            let mut q = OPEN_HEAD;
            let mut missing: *mut File = null_mut();
            while !q.is_null() {
                if (*q).fork_held == 0 {
                    if (*q).lock.try_lock() {
                        (*q).fork_held = 1;
                    } else {
                        missing = q;
                        break;
                    }
                }
                q = (*q).next;
            }
            if missing.is_null() {
                return;
            }
            (*missing).pins.fetch_add(1, Ordering::AcqRel);
            LIST.unlock_always();
            fork_grab(missing);
            (*missing).pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

unsafe fn atfork_release(child: bool) {
    unsafe {
        let mut q = OPEN_HEAD;
        while !q.is_null() {
            match (*q).fork_held {
                1 => {
                    (*q).lock.unlock();
                }
                2 if child => (*q).lock.reset(),
                _ => {}
            }
            (*q).fork_held = 0;
            if child {
                (*q).pins.store(0, Ordering::Relaxed);
            }
            q = (*q).next;
        }
        LIST.unlock_always();
        FORK_LOCK.unlock_always();
    }
}

unsafe extern "C" fn atfork_parent() {
    unsafe {
        if FORK_REAL.load(Ordering::Relaxed) {
            atfork_release(false);
        }
    }
}

unsafe extern "C" fn atfork_child() {
    unsafe {
        if FORK_REAL.load(Ordering::Relaxed) {
            atfork_release(true);
        }
    }
}

pub(crate) unsafe fn discard_input(f: *mut File, sync: bool) {
    unsafe {
        let mut unread = ((*f).rend() - (*f).rpos()) + (*f).nunget();
        if !(*f).wide.is_null() {
            unread += (*(*f).wide).tshift;
        }
        if sync && unread > 0 && (*f).flags & F_NOSEEK == 0 {
            let _ = raw_seek(f, -(unread as i64), 1);
        }
        drop_unget(f);
        (*f).set_read(0, 0);
        drop_wpush(f);
        (*f).flags &= !F_RDMODE;
    }
}

unsafe fn start_write(f: *mut File) -> bool {
    unsafe {
        if (*f).flags & F_WRITE == 0 {
            (*f).flags |= F_ERR;
            errno::set(9);
            return false;
        }
        if (*f).flags & F_RDMODE != 0 {
            let unread = ((*f).rend() - (*f).rpos()) + (*f).nunget().min((*f).rpos());
            let keep_ahead = (*f).flags & F_WIDE != 0 && !(*f).wide.is_null() && !(*(*f).wide).wbuf && (*(*f).wide).ahead;
            if unread > 0 && (*f).flags & F_NOSEEK == 0 && !keep_ahead {
                let _ = raw_seek(f, -(unread as i64), 1);
            }
            drop_unget(f);
            (*f).set_read(0, 0);
            drop_wpush(f);
            (*f).flags &= !F_RDMODE;
        }
        prepare(f);
        (*f).flags |= F_WRMODE | F_PUTTING;
        (*f).set_wpos(0);
        true
    }
}

unsafe fn underflow(f: *mut File) -> bool {
    unsafe { underflow_keep(f, 0) }
}

pub(crate) unsafe fn underflow_keep(f: *mut File, keep: usize) -> bool {
    unsafe {
        if (*f).flags & F_READ == 0 {
            (*f).flags |= F_ERR;
            errno::set(9);
            return false;
        }
        if (*f).flags & F_WRMODE != 0 && !flush_write(f) {
            return false;
        }
        if (*f).flags & F_EOF != 0 {
            return false;
        }
        drop_unget(f);
        prepare(f);
        if (*f).flags & (F_LBF | F_UNBUF) != 0 {
            flush_line_buffered();
        }
        if (*f).flags & F_UNBUF != 0 || (*f).buf.is_null() {
            if (*f).buf.is_null() {
                let size = if keep > 0 { 8 } else { 1 };
                let b = rusty_libc_malloc::malloc(size) as *mut u8;
                if b.is_null() {
                    (*f).set_buffer((*f).shortbuf.as_mut_ptr(), size);
                    (*f).flags |= F_USERBUF;
                } else {
                    (*f).set_buffer(b, size);
                }
            }
            if keep > 0 {
                core::ptr::copy((*f).buf.add((*f).rpos()), (*f).buf, keep);
            }
            (*f).set_read(0, keep);
            let k = raw_read(f, (*f).buf.add(keep), 1);
            return finish_read(f, k, keep);
        }
        if keep > 0 {
            core::ptr::copy((*f).buf.add((*f).rpos()), (*f).buf, keep);
        }
        (*f).set_read(0, keep);
        let k = raw_read(f, (*f).buf.add(keep), (*f).bufsize - keep);
        finish_read(f, k, keep)
    }
}

unsafe fn finish_read(f: *mut File, k: isize, keep: usize) -> bool {
    unsafe {
        if k > 0 {
            (*f).set_read(0, keep + k as usize);
            (*f).flags = ((*f).flags | F_RDMODE) & !F_PUTTING;
            true
        } else if k == 0 {
            if (*f).flags & F_NOEOF == 0 {
                (*f).flags |= F_EOF;
            }
            (*f).flags &= !F_SEEKED;
            false
        } else {
            (*f).flags |= F_ERR;
            false
        }
    }
}

#[inline]
pub(crate) unsafe fn narrow_ok(f: *mut File) -> bool {
    unsafe {
        let fl = (*f).flags;
        if fl & F_WIDE != 0 {
            return false;
        }
        if fl & F_BYTE == 0 {
            (*f).flags = fl | F_BYTE;
        }
        true
    }
}

#[inline]
unsafe fn pending_out(f: *mut File) -> i64 {
    unsafe {
        let extra = if (*f).wide.is_null() { 0 } else { (*(*f).wide).extra };
        ((*f).wpos() as i64 - extra as i64).max(0)
    }
}

#[inline]
unsafe fn reset_wextra(f: *mut File) {
    unsafe {
        if !(*f).wide.is_null() {
            (*(*f).wide).extra = 0;
            (*(*f).wide).pchars = 0;
            (*(*f).wide).raw = 0;
        }
    }
}

#[inline]
pub(crate) unsafe fn drop_wpush(f: *mut File) {
    unsafe {
        if !(*f).wide.is_null() {
            (*(*f).wide).npush = 0;
            (*(*f).wide).tshift = 0;
        }
    }
}

pub fn parse_mode(mode: &[u8]) -> Option<(u32, c_int)> {
    let (base, plus) = match mode.first()? {
        b'r' => (0, false),
        b'w' => (1, false),
        b'a' => (2, false),
        _ => return None,
    };
    let mut plus = plus;
    let mut cloexec = false;
    let mut excl = false;
    let mut nocancel = false;
    for &c in &mode[1..] {
        match c {
            b'+' => plus = true,
            b'b' => {}
            b'e' => cloexec = true,
            b'x' => excl = true,
            b'c' => nocancel = true,
            b'm' | b'n' => {}
            b',' => break,
            _ => break,
        }
    }
    let (mut fl, mut of) = match (base, plus) {
        (0, false) => (F_READ, 0),
        (0, true) => (F_READ | F_WRITE, 2),
        (1, false) => (F_WRITE, 1 | 0o100 | 0o1000),
        (1, true) => (F_READ | F_WRITE, 2 | 0o100 | 0o1000),
        (2, false) => (F_WRITE | F_APPEND, 1 | 0o100 | 0o2000),
        _ => (F_READ | F_WRITE | F_APPEND, 2 | 0o100 | 0o2000),
    };
    if cloexec {
        of |= 0o2000000;
    }
    if excl {
        of |= 0o200;
    }
    if nocancel {
        fl |= F_NOCANCEL;
    }
    Some((fl, of))
}

pub fn mode_ccs(mode: &[u8]) -> Option<&[u8]> {
    let comma = mode.iter().position(|&c| c == b',')?;
    let rest = &mode[comma + 1..];
    if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(b"ccs=") {
        let name = &rest[4..];
        let end = name.iter().position(|&c| c == b',' || c == b' ').unwrap_or(name.len());
        Some(&name[..end])
    } else {
        None
    }
}

pub unsafe fn alloc_file(flags: u32, fd: c_int) -> *mut File {
    unsafe {
        let p = rusty_libc_malloc::malloc(core::mem::size_of::<File>()) as *mut File;
        if p.is_null() {
            return p;
        }
        p.write(File::blank(flags, fd));
        note_used();
        link_standard();
        link(p);
        p
    }
}

pub unsafe fn fopen(path: *const c_char, mode: *const c_char) -> *mut File {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        let Some((flags, oflags)) = parse_mode(m) else {
            errno::set(22);
            return null_mut();
        };
        let fd = match unistd::open(path, oflags, 0o666) {
            Ok(fd) => fd,
            Err(e) => {
                errno::set(e.0);
                return null_mut();
            }
        };
        let mut start = -1i64;
        if flags & F_APPEND != 0 && flags & F_READ == 0 {
            start = unistd::lseek(fd, 0, 2).unwrap_or(-1);
        }
        let f = alloc_file(flags, fd);
        if f.is_null() {
            let _ = unistd::close(fd);
            errno::set(12);
        } else {
            (*f).cookie_pos = start;
            if let Some(name) = mode_ccs(m)
                && !crate::wfile::set_ccs(f, name)
            {
                let e = errno::get();
                crate::file_api::fclose(f);
                errno::set(e);
                return null_mut();
            }
        }
        f
    }
}

pub unsafe fn fdopen(fd: c_int, mode: *const c_char) -> *mut File {
    unsafe {
        let m = core::slice::from_raw_parts(mode as *const u8, rusty_libc_mem::strlen(mode));
        let Some((flags, _)) = parse_mode(m) else {
            errno::set(22);
            return null_mut();
        };
        let r = syscall::syscall3(syscall::SYS_FCNTL, fd as usize, 3 , 0);
        if r > usize::MAX - 4095 {
            errno::set((r as isize).wrapping_neg() as i32);
            return null_mut();
        }
        let acc = r & 3;
        if (flags & F_READ != 0 && acc == 1) || (flags & F_WRITE != 0 && acc == 0) {
            errno::set(22);
            return null_mut();
        }
        let mut flags = flags;
        let mut added_append = false;
        if flags & F_APPEND != 0 && r & 0o2000 == 0 {
            syscall::syscall3(syscall::SYS_FCNTL, fd as usize, 4 , r | 0o2000);
            added_append = true;
        }
        if flags & F_WRITE != 0 && r & 0o2000 != 0 {
            flags |= F_APPEND;
        }
        if added_append && flags & F_READ == 0 {
            if let Err(e) = unistd::lseek(fd, 0, 2)
                && e.0 != 29
            {
                errno::set(e.0);
                return null_mut();
            }
        }
        let f = alloc_file(flags, fd);
        if f.is_null() {
            errno::set(12);
        }
        f
    }
}

pub(crate) unsafe fn close_keep(f: *mut File) -> c_int {
    unsafe {
        let mut result = 0;
        crate::wfile::free_wide(f);
        if (*f).flags & F_WRMODE != 0 && !flush_write(f) {
            result = EOF;
        }
        if (*f).flags & F_RDMODE != 0 {
            discard_input(f, true);
        }
        if (*f).flags & F_MEM != 0 {
            if let Some(c) = (*f).io.close
                && c((*f).cookie) != 0
            {
                result = EOF;
            }
        } else if (*f).fd >= 0 && unistd::close((*f).fd).is_err() {
            result = EOF;
        }
        if (*f).flags & F_MEM != 0 {
            (*f).flags &= !F_MEM;
            (*f).cookie = null_mut();
            (*f).io = CookieIo { read: None, write: None, seek: None, close: None, sync: None };
        }
        if !(*f).buf.is_null() && (*f).flags & F_USERBUF == 0 {
            rusty_libc_malloc::free((*f).buf.cast());
        }
        drop_unget(f);
        (*f).flags &= !(F_RDMODE | F_WRMODE);
        (*f).set_buffer(null_mut(), 0);
        drop_wpush(f);
        (*f).fd = -1;
        result
    }
}

pub(crate) unsafe fn reopen_as(f: *mut File, flags: u32, fd: c_int, pos: i64) {
    unsafe {
        let keep = (*f).flags & F_STATIC;
        (*f).reset(flags | keep, fd);
        (*f).cookie_pos = pos;
    }
}

pub unsafe fn fclose(f: *mut File) -> c_int {
    unsafe { close_stream(f, false) }
}

unsafe fn close_stream(f: *mut File, pinned: bool) -> c_int {
    unsafe {
        if (*f).flags & (F_STATIC | F_MEM) == F_STATIC && (*f).fd < 0 && (*f).flags & F_ERR != 0 {
            if pinned {
                (*f).pins.fetch_sub(1, Ordering::AcqRel);
            }
            errno::set(9);
            return EOF;
        }
        let real = multithreaded() && !(*f).nolock;
        let mut cg = crate::flock::LockCleanup::idle();
        if real {
            (*f).lock.lock();
            cg.arm(f);
        }
        if pinned && !(*f).linked.load(Ordering::Relaxed) {
            if real {
                cg.disarm();
                (*f).lock.unlock();
            }
            (*f).pins.fetch_sub(1, Ordering::AcqRel);
            return EOF;
        }
        let mut result = 0;
        let mut close_errno = 0;
        crate::wfile::free_wide(f);
        if (*f).flags & F_WRMODE != 0 && !flush_write(f) {
            result = EOF;
        }
        if (*f).flags & F_RDMODE != 0 {
            discard_input(f, true);
        }
        unlink(f);
        if (*f).flags & F_MEM != 0 {
            if let Some(c) = (*f).io.close
                && c((*f).cookie) != 0
            {
                result = EOF;
            }
        } else if (*f).fd >= 0
            && let Err(e) = unistd::close((*f).fd)
        {
            result = EOF;
            close_errno = e.0;
        }
        if (*f).pid > 0 {
            loop {
                match unistd::waitpid((*f).pid, 0) {
                    Ok((_, status)) => {
                        result = status;
                        break;
                    }
                    Err(e) if e.0 == 4 => continue,
                    Err(e) => {
                        errno::set(e.0);
                        result = -1;
                        break;
                    }
                }
            }
        }
        if !(*f).buf.is_null() && (*f).flags & F_USERBUF == 0 {
            rusty_libc_malloc::free((*f).buf.cast());
        }
        let is_static = (*f).flags & F_STATIC != 0;
        if is_static {
            (*f).buf = null_mut();
            (*f).flags = F_STATIC | F_ERR;
            (*f).fd = -1;
        }
        if real {
            cg.disarm();
            (*f).lock.unlock();
        }
        if pinned {
            (*f).pins.fetch_sub(1, Ordering::AcqRel);
        }
        if !is_static {
            while (*f).pins.load(Ordering::Acquire) != 0 {
                syscall::syscall0(24);
            }
            rusty_libc_malloc::free(f.cast());
        }
        if close_errno != 0 && result == EOF {
            errno::set(close_errno);
        }
        result
    }
}

#[inline]
pub(crate) unsafe fn drop_unget(f: *mut File) {
    unsafe {
        if (*f).flags & F_UNGOT != 0 {
            (*f).flags &= !F_UNGOT;
            (*f).rptr = (*f).save_base;
            (*f).rend_p = (*f).save_end;
            (*f).rbase = (*f).buf;
            (*f).save_base = null_mut();
            (*f).save_end = null_mut();
        }
        if !(*f).ubuf.is_null() {
            rusty_libc_malloc::free((*f).ubuf.cast());
            (*f).ubuf = null_mut();
        }
        (*f).ucap = 1;
    }
}

#[inline(always)]
unsafe fn unget_done(f: *mut File) {
    unsafe {
        if (*f).flags & F_UNGOT != 0 && (*f).rptr >= (*f).rend_p {
            drop_unget(f);
        }
    }
}

unsafe fn push_byte(f: *mut File, c: u8) -> bool {
    unsafe {
        if (*f).flags & F_UNGOT == 0 {
            let area = (*f).unget.as_mut_ptr();
            (*f).save_base = (*f).rptr;
            (*f).save_end = (*f).rend_p;
            (*f).rbase = area;
            (*f).rend_p = area.add((*f).ucap);
            (*f).rptr = (*f).rend_p;
            (*f).flags |= F_UNGOT;
        }
        if (*f).rptr <= (*f).rbase {
            let n = (*f).nunget();
            let newcap = (*f).ucap * 2;
            let p = rusty_libc_malloc::malloc(newcap) as *mut u8;
            if p.is_null() {
                return false;
            }
            core::ptr::copy_nonoverlapping((*f).rptr, p.add(newcap - n), n);
            if !(*f).ubuf.is_null() {
                rusty_libc_malloc::free((*f).ubuf.cast());
            }
            (*f).ubuf = p;
            (*f).ucap = newcap;
            (*f).rbase = p;
            (*f).rend_p = p.add(newcap);
            (*f).rptr = p.add(newcap - n);
        }
        (*f).rptr = (*f).rptr.sub(1);
        *(*f).rptr = c;
        true
    }
}

#[inline]
pub unsafe fn getc(f: *mut File) -> c_int {
    unsafe {
        if (*f).flags & F_WIDE == 0 && (*f).rptr < (*f).rend_p {
            let c = *(*f).rptr;
            (*f).rptr = (*f).rptr.add(1);
            return c_int::from(c);
        }
        getc_slow(f)
    }
}

#[inline(never)]
unsafe fn getc_slow(f: *mut File) -> c_int {
    unsafe {
        if !narrow_ok(f) {
            return EOF;
        }
        unget_done(f);
        if (*f).rptr >= (*f).rend_p && !underflow(f) {
            return EOF;
        }
        let c = *(*f).rptr;
        (*f).rptr = (*f).rptr.add(1);
        unget_done(f);
        c_int::from(c)
    }
}

pub unsafe fn peekc(f: *mut File) -> c_int {
    unsafe {
        if !narrow_ok(f) {
            return EOF;
        }
        unget_done(f);
        if (*f).rptr >= (*f).rend_p && !underflow(f) {
            return EOF;
        }
        c_int::from(*(*f).rptr)
    }
}

#[inline]
pub unsafe fn fill_buf(f: *mut File) -> Option<(*const u8, usize)> {
    unsafe {
        if (*f).flags & (F_WIDE | F_BYTE) == F_BYTE && (*f).rptr < (*f).rend_p {
            return Some(((*f).rptr, (*f).rend_p as usize - (*f).rptr as usize));
        }
        fill_buf_slow(f)
    }
}

#[inline(never)]
unsafe fn fill_buf_slow(f: *mut File) -> Option<(*const u8, usize)> {
    unsafe {
        if !narrow_ok(f) {
            return None;
        }
        unget_done(f);
        if (*f).rptr >= (*f).rend_p && !underflow(f) {
            return None;
        }
        Some(((*f).rptr, (*f).rend_p as usize - (*f).rptr as usize))
    }
}

#[inline]
pub unsafe fn consume(f: *mut File, n: usize) {
    unsafe { (*f).rptr = (*f).rptr.add(n) };
}

pub unsafe fn ungetc(c: c_int, f: *mut File) -> c_int {
    unsafe {
        if c == EOF || (*f).flags & F_READ == 0 {
            return EOF;
        }
        if (*f).flags & F_WIDE != 0 {
            let r = crate::wfile::ungetwc_raw(rusty_libc_wchar::wint_t::from(c as u8), f);
            return if r == rusty_libc_wchar::WEOF { EOF } else { c_int::from(c as u8) };
        }
        ungetc_force(c, f)
    }
}

pub(crate) unsafe fn ungetc_force(c: c_int, f: *mut File) -> c_int {
    unsafe {
        if (*f).flags & F_WRMODE != 0 && !flush_write(f) {
            return EOF;
        }
        unget_done(f);
        if (*f).flags & F_RDMODE == 0 {
            (*f).set_read(0, 0);
            (*f).flags |= F_RDMODE;
        }
        (*f).flags &= !F_PUTTING;
        if (*f).flags & F_UNGOT == 0 && (*f).rptr > (*f).buf && (*f).rptr <= (*f).buf.wrapping_add((*f).bufsize) && *(*f).rptr.sub(1) == c as u8 {
            (*f).rptr = (*f).rptr.sub(1);
        } else if !push_byte(f, c as u8) {
            return EOF;
        }
        (*f).flags &= !F_EOF;
        c_int::from(c as u8)
    }
}

pub unsafe fn read_bytes(f: *mut File, dst: *mut u8, n: usize) -> usize {
    unsafe {
        if !narrow_ok(f) {
            return 0;
        }
        let mut got = 0;
        while got < n {
            unget_done(f);
            if (*f).rptr < (*f).rend_p {
                let k = ((*f).rend_p as usize - (*f).rptr as usize).min(n - got);
                rusty_libc_mem::memcpy(dst.add(got).cast(), (*f).rptr.cast(), k);
                (*f).rptr = (*f).rptr.add(k);
                got += k;
                continue;
            }
            let want = n - got;
            prepare(f);
            let block = (*f).bufsize;
            if (*f).flags & F_WRITE != 0 && (*f).flags & F_WRMODE != 0 && !flush_write(f) {
                break;
            }
            if (*f).flags & F_READ == 0 {
                (*f).flags |= F_ERR;
                errno::set(9);
                break;
            }
            if (*f).flags & F_EOF != 0 {
                break;
            }
            if (*f).buf.is_null() || want < block || (*f).flags & F_UNBUF != 0 {
                if !underflow(f) {
                    break;
                }
            } else {
                if (*f).flags & (F_LBF | F_UNBUF) != 0 {
                    flush_line_buffered();
                }
                let count = if block >= 128 { want - want % block } else { want };
                (*f).set_read(0, 0);
                let k = raw_read(f, dst.add(got), count);
                if k > 0 {
                    got += k as usize;
                } else {
                    if k == 0 {
                        if (*f).flags & F_NOEOF == 0 {
                            (*f).flags |= F_EOF;
                        }
                        (*f).flags &= !F_SEEKED;
                    } else {
                        (*f).flags |= F_ERR;
                    }
                    break;
                }
            }
        }
        got
    }
}

#[inline]
pub unsafe fn putc(c: c_int, f: *mut File) -> c_int {
    unsafe {
        let b = c as u8;
        if (*f).wptr < (*f).wend {
            *(*f).wptr = b;
            (*f).wptr = (*f).wptr.add(1);
            return c_int::from(b);
        }
        putc_slow(b, f)
    }
}

#[inline(never)]
unsafe fn putc_slow(b: u8, f: *mut File) -> c_int {
    unsafe {
        if (*f).flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE | F_LBF && b != b'\n' && (*f).wpos() < (*f).bufsize {
            *(*f).wptr = b;
            (*f).wptr = (*f).wptr.add(1);
            return c_int::from(b);
        }
        if (*f).flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE && !(*f).buf.is_null() && (*f).wpos() >= (*f).bufsize {
            if !flush_write(f) {
                return EOF;
            }
            (*f).flags |= F_WRMODE;
            (*f).set_wpos(1);
            *(*f).buf = b;
            return c_int::from(b);
        }
        if (*f).flags & F_WIDE != 0 {
            let w = (*f).wide;
            if !(*w).putting || (*f).flags & F_W32 != 0 {
                return if crate::wfile::putwc_raw(f, rusty_libc_wchar::wint_t::from(b)) == rusty_libc_wchar::WEOF { EOF } else { c_int::from(b) };
            }
            if write_bytes_raw(f, &b, 1) != 1 {
                return EOF;
            }
            let wpos = (*f).wpos();
            if wpos == 0 {
                (*w).raw = 0;
            } else {
                let at = (*w).raw.min(wpos - 1);
                core::slice::from_raw_parts_mut((*f).buf.add(at), wpos - at).rotate_right(1);
                (*w).raw = at + 1;
            }
            return c_int::from(b);
        }
        if !write_bytes_ok(f, &b, 1) {
            return EOF;
        }
        c_int::from(b)
    }
}

unsafe fn write_bytes_ok(f: *mut File, src: *const u8, n: usize) -> bool {
    unsafe { write_bytes(f, src, n) == n }
}

pub unsafe fn write_bytes(f: *mut File, src: *const u8, n: usize) -> usize {
    unsafe {
        if !narrow_ok(f) {
            return 0;
        }
        write_bytes_raw(f, src, n)
    }
}

pub(crate) unsafe fn write_bytes_raw(f: *mut File, src: *const u8, n: usize) -> usize {
    unsafe {
        if n == 0 {
            return 0;
        }
        if (*f).flags & F_WRMODE == 0 && !start_write(f) {
            return 0;
        }
        if (*f).flags & F_APPEND != 0 && (*f).flags & F_MEM == 0 {
        }
        if (*f).flags & F_UNBUF != 0 || (*f).buf.is_null() {
            let mut off = 0;
            while off < n {
                let k = raw_write(f, src.add(off), n - off);
                if k < 0 {
                    if errno::get() == 4 {
                        continue;
                    }
                    (*f).flags |= F_ERR;
                    return off;
                }
                off += k as usize;
                if (*f).flags & F_MEM != 0 && off < n {
                    (*f).flags |= F_ERR;
                    return off;
                }
            }
            return n;
        }
        let lbf = (*f).flags & F_LBF != 0;
        let mut flush_upto = 0usize;
        if lbf {
            let mut i = n;
            while i > 0 {
                i -= 1;
                if *src.add(i) == b'\n' {
                    flush_upto = i + 1;
                    break;
                }
            }
        }
        let mut done = 0usize;
        let space = (*f).bufsize - (*f).wpos();
        let k = space.min(n);
        rusty_libc_mem::memcpy((*f).wptr.cast(), src.cast(), k);
        (*f).wptr = (*f).wptr.add(k);
        done += k;
        if done == n {
            if lbf && flush_upto > 0 {
                return if flush_write(f) { n } else { 0 };
            }
            return n;
        }
        if !flush_write(f) {
            return done;
        }
        (*f).flags |= F_WRMODE;
        (*f).set_wpos(0);
        let rest = n - done;
        let block = (*f).bufsize;
        let direct = if block >= 128 { rest - rest % block } else { rest };
        let mut off = 0;
        while off < direct {
            let w = raw_write(f, src.add(done + off), direct - off);
            if w < 0 {
                if errno::get() == 4 {
                    continue;
                }
                (*f).flags |= F_ERR;
                (*f).flags &= !F_WRMODE;
                return done + off;
            }
            off += w as usize;
            if (*f).flags & F_MEM != 0 && off < direct {
                (*f).flags |= F_ERR;
                (*f).flags &= !F_WRMODE;
                return done + off;
            }
        }
        done += direct;
        let rem = n - done;
        if rem > 0 {
            rusty_libc_mem::memcpy((*f).buf.cast(), src.add(done).cast(), rem);
            (*f).set_wpos(rem);
            done += rem;
        }
        if lbf && flush_upto > 0 && !flush_write(f) {
            return 0;
        }
        done
    }
}

pub unsafe fn tell(f: *mut File) -> i64 {
    unsafe {
        if !(*f).wide.is_null() && (*(*f).wide).npush > 0 {
            errno::set(22);
            return -1;
        }
        if !(*f).wide.is_null()
            && (*(*f).wide).cs == crate::wfile::WCs::Utf8
            && (*f).flags & F_WRMODE != 0
            && (*f).wpos() > 4 * (*(*f).wide).pchars
        {
            return 4_294_967_295;
        }
        let mut p = tell_bytes(f);
        if p > 0 && !(*f).wide.is_null() {
            p -= (*(*f).wide).tshift as i64;
        }
        if p > 0 && (*f).flags & F_W32 != 0 { p / 4 } else { p }
    }
}

unsafe fn tell_bytes(f: *mut File) -> i64 {
    unsafe {
        if (*f).flags & F_NOSEEK != 0 {
            errno::set(29);
            return -1;
        }
        let base = match offset(f) {
            Ok(p) => p,
            Err(e) => {
                if e == 29 {
                    (*f).flags |= F_NOSEEK;
                }
                errno::set(e);
                return -1;
            }
        };
        if (*f).flags & F_WRMODE != 0 {
            if (*f).flags & F_APPEND != 0 && (*f).flags & F_OLDMEM != 0 {
                if !flush_write(f) {
                    return -1;
                }
                return match raw_seek(f, 0, 1) {
                    Ok(p) => p,
                    Err(e) => {
                        errno::set(e);
                        -1
                    }
                };
            }
            if (*f).flags & F_APPEND != 0 {
                return match raw_seek(f, 0, 2) {
                    Ok(end) => end + pending_out(f),
                    Err(e) => {
                        errno::set(e);
                        -1
                    }
                };
            }
            base + pending_out(f)
        } else if (*f).flags & F_RDMODE != 0 {
            let p = base - (((*f).rend() - (*f).rpos()) + (*f).nunget()) as i64;
            if p < 0 {
                errno::set(29);
                return -1;
            }
            p
        } else {
            base
        }
    }
}

pub unsafe fn seek(f: *mut File, off: i64, whence: c_int) -> c_int {
    unsafe {
        let off = if (*f).flags & F_W32 != 0 { off.saturating_mul(4) } else { off };
        if !(*f).wide.is_null() {
            (*(*f).wide).putting = false;
            (*(*f).wide).ahead = false;
        }
        seek_bytes(f, off, whence)
    }
}

unsafe fn seek_bytes(f: *mut File, off: i64, whence: c_int) -> c_int {
    unsafe {
        if !(0..=2).contains(&whence) {
            errno::set(22);
            return -1;
        }
        if (*f).flags & F_WRMODE != 0 && !flush_write(f) {
            return -1;
        }
        let mut off = off;
        let reading = (*f).flags & F_RDMODE != 0;
        if reading && whence == 1 {
            off -= (((*f).rend() - (*f).rpos()) + (*f).nunget()) as i64;
        }
        if reading && whence != 2 && (*f).cookie_pos >= 0 && (*f).flags & F_NOSEEK == 0 {
            let here = (*f).cookie_pos;
            let target = if whence == 0 { off } else { here + off };
            let start = here - (*f).rend() as i64;
            if target >= start && target < here {
                drop_unget(f);
                (*f).set_rpos((target - start) as usize);
                drop_wpush(f);
                (*f).flags &= !(F_EOF | F_PUTTING);
                return 0;
            }
        }
        match raw_seek(f, off, whence) {
            Ok(_) => {
                if reading {
                    drop_unget(f);
                    (*f).set_read(0, 0);
                    drop_wpush(f);
                    (*f).flags &= !F_RDMODE;
                }
                (*f).flags &= !(F_EOF | F_PUTTING);
                (*f).flags |= F_SEEKED;
                0
            }
            Err(e) => {
                drop_unget(f);
                drop_wpush(f);
                errno::set(e);
                -1
            }
        }
    }
}

pub unsafe fn fflush(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            return if flush_all() { 0 } else { EOF };
        }
        sync_mem(f);
        if (*f).flags & F_WRMODE != 0 {
            return if flush_write(f) { 0 } else { EOF };
        }
        if (*f).flags & F_RDMODE != 0 && !sync_input(f) {
            return EOF;
        }
        0
    }
}

unsafe fn sync_input(f: *mut File) -> bool {
    unsafe {
        let mut unread = ((*f).rend() - (*f).rpos()) + (*f).nunget();
        if !(*f).wide.is_null() {
            unread += (*(*f).wide).tshift;
        }
        if unread > 0 {
            let r = if (*f).flags & F_NOSEEK != 0 { Err(29) } else { raw_seek(f, -(unread as i64), 1) };
            if let Err(e) = r {
                if (*f).wide.is_null() {
                    drop_unget(f);
                }
                errno::set(e);
                return e == 29;
            }
        }
        drop_unget(f);
        (*f).set_read(0, 0);
        drop_wpush(f);
        (*f).flags &= !F_RDMODE;
        true
    }
}

pub unsafe fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    unsafe {
        if !(0..=2).contains(&mode) {
            errno::set(22);
            return EOF;
        }
        if (*f).flags & F_WRMODE != 0 {
            flush_write(f);
        }
        if (*f).flags & F_RDMODE != 0 {
            discard_input(f, true);
        }
        if !(*f).buf.is_null() && (*f).flags & F_USERBUF == 0 {
            rusty_libc_malloc::free((*f).buf.cast());
        }
        (*f).flags &= !(F_LBF | F_UNBUF | F_USERBUF | F_RDMODE | F_WRMODE);
        drop_unget(f);
        (*f).set_buffer(null_mut(), 0);
        note_used();
        (*f).flags |= F_DECIDED;
        match mode {
            2 => (*f).flags |= F_UNBUF,
            1 => (*f).flags |= F_LBF,
            _ => {}
        }
        if mode != 2 {
            if !buf.is_null() && size > 0 {
                (*f).set_buffer(buf.cast(), size);
                (*f).flags |= F_USERBUF;
            } else if size > 0 {
                (*f).bufsize = size;
            }
        }
        0
    }
}

