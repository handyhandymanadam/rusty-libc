use crate::flock::FLock;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, Ordering};
use rusty_libc_core::lock::{RawMutex, multithreaded};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, unistd};

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

#[inline(always)]
pub(crate) fn alloc(n: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::malloc(n) }.cast()
}

#[inline(always)]
pub(crate) unsafe fn free(p: *mut u8) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

#[inline(always)]
pub(crate) fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() == src.len());
    unsafe { rusty_libc_mem::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
}

#[inline(always)]
pub(crate) unsafe fn copy_raw(dst: *mut u8, src: *const u8, n: usize) {
    unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), n) };
}

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
    pub rptr: *mut u8,
    pub rend_p: *mut u8,
    pub rbase: *mut u8,
    pub wbase: *mut u8,
    pub wptr: *mut u8,
    pub wend: *mut u8,
    pub buf: *mut u8,
    pub buf_end: *mut u8,
    pub save_base: *mut u8,
    pub backup_base: *mut u8,
    pub save_end: *mut u8,
    pub markers: *mut u8,
    pub chain: *mut File,
    pub fd: c_int,
    pub flags2: c_int,
    pub shortbuf: [u8; 8],
    pub ucap: u32,
    pub pid: c_int,
    pub ubuf: *mut u8,
    pub cookie_pos: i64,
    pub io: CookieIo,
    pub mode: c_int,
    pub unget: [u8; 4],
    shared: *const Shared,
    pub cookie: *mut c_void,
    pub wide: *mut crate::wfile::WideInfo,
}

#[repr(C)]
pub struct Shared {
    pub lock: FLock,
    pins: AtomicU32,
    linked: AtomicBool,
    pub(crate) nolock: AtomicBool,
    fork_held: AtomicU8,
    hint: AtomicU8,
    next: AtomicPtr<File>,
    prev: AtomicPtr<File>,
}

pub const H_FLUSH: u8 = 1;
pub const H_LBF_OUT: u8 = 2;
pub const H_ALL: u8 = H_FLUSH | H_LBF_OUT;

impl Shared {
    pub const fn with_hint(hint: u8) -> Shared {
        let mut s = Shared::new();
        s.hint = AtomicU8::new(hint);
        s
    }

    pub const fn new() -> Shared {
        Shared {
            lock: FLock::new(),
            pins: AtomicU32::new(0),
            linked: AtomicBool::new(false),
            nolock: AtomicBool::new(false),
            fork_held: AtomicU8::new(0),
            hint: AtomicU8::new(0),
            next: AtomicPtr::new(null_mut()),
            prev: AtomicPtr::new(null_mut()),
        }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct Stream {
    pub file: File,
    pub shared: Shared,
}

impl Stream {
    const fn new(flags: u32, fd: c_int, shared: *const Shared, hint: u8) -> Stream {
        let mut file = File::blank(flags, fd);
        file.shared = shared;
        Stream { file, shared: Shared::with_hint(hint) }
    }
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
    assert!(offset_of!(File, buf_end) == 64);
    assert!(offset_of!(File, save_base) == 72);
    assert!(offset_of!(File, backup_base) == 80);
    assert!(offset_of!(File, save_end) == 88);
    assert!(offset_of!(File, markers) == 96);
    assert!(offset_of!(File, chain) == 104);
    assert!(offset_of!(File, fd) == 112);
    assert!(offset_of!(File, flags2) == 116);
    assert!(offset_of!(File, cookie_pos) == 144);
    assert!(offset_of!(File, mode) == 192);
    assert!(offset_of!(File, shortbuf) == 120);
    assert!(offset_of!(File, ucap) == 128);
    assert!(offset_of!(File, pid) == 132);
    assert!(offset_of!(File, ubuf) == 136);
    assert!(offset_of!(File, io) == 152);
    assert!(offset_of!(File, unget) == 196);
    assert!(offset_of!(File, shared) == 200);
    assert!(offset_of!(File, cookie) == 208);
    assert!(offset_of!(File, wide) == 216);
    assert!(core::mem::size_of::<File>() >= 216);
    assert!(core::mem::size_of::<File>() == 224);
    assert!(core::mem::size_of::<Stream>() == 264);
    assert!(offset_of!(Stream, file) == 0);
};

impl File {
    pub const fn blank(flags: u32, fd: c_int) -> File {
        File {
            flags: with_access_bits(flags),
            rptr: null_mut(),
            rend_p: null_mut(),
            rbase: null_mut(),
            wbase: null_mut(),
            wptr: null_mut(),
            wend: null_mut(),
            buf: null_mut(),
            buf_end: null_mut(),
            save_base: null_mut(),
            backup_base: null_mut(),
            save_end: null_mut(),
            markers: null_mut(),
            chain: null_mut(),
            fd,
            flags2: 0,
            shortbuf: [0; 8],
            ucap: 1,
            pid: 0,
            ubuf: null_mut(),
            cookie_pos: -1,
            io: CookieIo { read: None, write: None, seek: None, close: None, sync: None },
            mode: 0,
            unget: [0; 4],
            shared: core::ptr::null(),
            cookie: null_mut(),
            wide: null_mut(),
        }
    }

    pub fn reset(&mut self, flags: u32, fd: c_int) {
        self.flags = with_access_bits(flags) & !(F_UNGOT | F_PUTTING);
        self.fd = fd;
        self.buf = null_mut();
        self.buf_end = null_mut();
        self.rptr = null_mut();
        self.rend_p = null_mut();
        self.rbase = null_mut();
        self.wbase = null_mut();
        self.wptr = null_mut();
        self.wend = null_mut();
        self.save_base = null_mut();
        self.save_end = null_mut();
        self.unget = [0; 4];
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
        (if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_base } else { self.rptr }) as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn rend(&self) -> usize {
        (if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_end } else { self.rend_p }) as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn set_rpos(&mut self, n: usize) {
        let p = self.buf.wrapping_add(n);
        if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_base = p } else { self.rptr = p }
    }
    #[inline(always)]
    pub fn set_read(&mut self, pos: usize, end: usize) {
        let (p, e) = (self.buf.wrapping_add(pos), self.buf.wrapping_add(end));
        if self.flags & (F_UNGOT | F_WIDE) != 0 {
            self.save_base = p;
            self.save_end = e;
        } else {
            self.rptr = p;
            self.rend_p = e;
            self.rbase = self.buf;
        }
    }
    pub fn hide_read_window(&mut self) {
        if self.flags & (F_UNGOT | F_WIDE) == 0 {
            self.save_base = self.rptr;
            self.save_end = self.rend_p;
            self.rptr = self.rend_p;
        }
    }
    #[inline(always)]
    pub fn nunget(&self) -> usize {
        if self.flags & F_UNGOT != 0 { self.rend_p as usize - self.rptr as usize } else { 0 }
    }
    #[inline(always)]
    pub fn writing(&mut self) -> bool {
        self.flags & F_WRMODE != 0 || (self.wptr > self.wbase && self.adopt_output())
    }
    #[cold]
    #[inline(never)]
    fn adopt_output(&mut self) -> bool {
        if self.flags & F_RDMODE == 0 && !self.wbase.is_null() {
            self.flags |= F_WRMODE;
            self.set_wpos(self.wpos());
            self.hint_output();
            return true;
        }
        false
    }
    #[inline(always)]
    pub fn bufsize(&self) -> usize {
        self.buf_end as usize - self.buf as usize
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
            self.buf_end
        } else {
            self.buf
        };
    }
    pub fn set_buffer(&mut self, b: *mut u8, size: usize) {
        self.buf = b;
        self.buf_end = b.wrapping_add(size);
        self.set_read(0, 0);
        self.set_wpos(0);
    }

    #[inline(always)]
    pub unsafe fn buf_slice<'b>(&self, from: usize, n: usize) -> &'b [u8] {
        debug_assert!(from + n <= self.bufsize());
        unsafe { core::slice::from_raw_parts(self.buf.wrapping_add(from), n) }
    }

    #[inline(always)]
    pub unsafe fn buf_slice_mut<'b>(&self, from: usize, n: usize) -> &'b mut [u8] {
        debug_assert!(from + n <= self.bufsize());
        unsafe { core::slice::from_raw_parts_mut(self.buf.wrapping_add(from), n) }
    }

    #[inline(always)]
    pub fn window(&self) -> &[u8] {
        let (r, e) = (self.rptr as usize, self.rend_p as usize);
        if r >= e {
            return &[];
        }
        unsafe { core::slice::from_raw_parts(self.rptr, e - r) }
    }

    #[inline(always)]
    fn byte_before(&self) -> u8 {
        unsafe { *self.rptr.wrapping_sub(1) }
    }

    #[inline(always)]
    fn take_byte(&mut self) -> u8 {
        let p = self.rptr;
        debug_assert!(p < self.rend_p);
        let c = unsafe { *p };
        self.rptr = p.wrapping_add(1);
        c
    }

    #[inline(always)]
    pub fn wide_ref(&self) -> Option<&crate::wfile::WideInfo> {
        unsafe { self.wide.as_ref() }
    }

    #[inline(always)]
    pub fn wide_mut(&mut self) -> Option<&mut crate::wfile::WideInfo> {
        unsafe { self.wide.as_mut() }
    }

    #[inline(always)]
    pub(crate) fn shared(&self) -> Option<&Shared> {
        unsafe { self.shared.as_ref() }
    }

    #[inline]
    fn hint_now(&self) -> u8 {
        let fl = self.flags;
        let flush = fl & F_WRMODE != 0 || (fl & F_MEM != 0 && self.io.sync.is_some()) || has_unread_fd_input(self);
        (if flush { H_FLUSH } else { 0 }) | if fl & (F_LBF | F_WRMODE) == F_LBF | F_WRMODE { H_LBF_OUT } else { 0 }
    }

    #[inline(never)]
    pub(crate) fn publish_hint(&self) {
        if let Some(sh) = self.shared() {
            sh.hint.store(self.hint_now(), Ordering::Relaxed);
        }
    }

    #[inline(always)]
    fn publish_hint_mt(&self) {
        if multithreaded() {
            self.publish_hint();
        }
    }

    #[inline(always)]
    fn hint_add(&self, bits: u8) {
        if !multithreaded() {
            return;
        }
        if let Some(sh) = self.shared() {
            let h = sh.hint.load(Ordering::Relaxed);
            if h & bits != bits {
                sh.hint.store(h | bits, Ordering::Relaxed);
            }
        }
    }

    #[inline(always)]
    fn hint_output(&self) {
        self.hint_add(if self.flags & F_LBF != 0 { H_FLUSH | H_LBF_OUT } else { H_FLUSH });
    }
}

#[inline(always)]
pub unsafe fn stream<'a>(f: *mut File) -> &'a mut File {
    unsafe { &mut *f }
}

pub static STDIN_FILE: SyncCell<Stream> =
    SyncCell::new(Stream::new(F_READ | F_STATIC, 0, shared_part((&raw const STDIN_FILE).cast()), H_ALL));
pub static STDOUT_FILE: SyncCell<Stream> =
    SyncCell::new(Stream::new(F_WRITE | F_STATIC, 1, shared_part((&raw const STDOUT_FILE).cast()), H_ALL));
pub static STDERR_FILE: SyncCell<Stream> = SyncCell::new(Stream::new(
    F_WRITE | F_STATIC | F_UNBUF | F_DECIDED,
    2,
    shared_part((&raw const STDERR_FILE).cast()),
    H_ALL,
));

const fn shared_part(s: *const Stream) -> *const Shared {
    s.cast::<u8>().wrapping_add(core::mem::offset_of!(Stream, shared)).cast()
}

#[inline(always)]
pub const fn static_file(s: &'static SyncCell<Stream>) -> *mut File {
    s.as_ptr().cast()
}

static OPEN_HEAD: SyncCell<*mut File> = SyncCell::new(null_mut());
static STD_LINKED: AtomicBool = AtomicBool::new(false);
static LIST: RawMutex = RawMutex::new();

#[inline(always)]
unsafe fn head() -> *mut File {
    unsafe { OPEN_HEAD.read() }
}

#[inline(always)]
unsafe fn set_head(p: *mut File) {
    unsafe { OPEN_HEAD.write(p) }
}

#[inline(always)]
pub(crate) unsafe fn shared_of<'a>(p: *mut File) -> &'a Shared {
    unsafe { &(*p.cast::<Stream>()).shared }
}

#[inline(always)]
pub(crate) unsafe fn lock_of<'a>(p: *mut File) -> &'a FLock {
    &unsafe { shared_of(p) }.lock
}



#[inline(always)]
unsafe fn next_of(p: *mut File) -> *mut File {
    unsafe { shared_of(p) }.next.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn stdin_ptr() -> *mut File {
    unsafe { crate::file_api::stdin.as_ptr().read_volatile() }
}
#[inline(always)]
pub fn stdout_ptr() -> *mut File {
    unsafe { crate::file_api::stdout.as_ptr().read_volatile() }
}
#[inline(always)]
pub fn stderr_ptr() -> *mut File {
    unsafe { crate::file_api::stderr.as_ptr().read_volatile() }
}

fn link_standard() {
    if STD_LINKED.load(Ordering::Acquire) {
        return;
    }
    let t = LIST.lock();
    if !STD_LINKED.load(Ordering::Relaxed) {
        unsafe { link_locked(static_file(&STDIN_FILE)) };
        unsafe { link_locked(static_file(&STDOUT_FILE)) };
        unsafe { link_locked(static_file(&STDERR_FILE)) };
        STD_LINKED.store(true, Ordering::Release);
    }
    LIST.unlock(t);
}

unsafe fn link_locked(f: *mut File) {
    let old = unsafe { head() };
    let sf = unsafe { shared_of(f) };
    sf.next.store(old, Ordering::Relaxed);
    sf.prev.store(null_mut(), Ordering::Relaxed);
    if !old.is_null() {
        unsafe { shared_of(old) }.prev.store(f, Ordering::Relaxed);
    }
    unsafe { set_head(f) };
    sf.linked.store(true, Ordering::Relaxed);
}

pub unsafe fn link(f: *mut File) {
    let t = LIST.lock();
    unsafe { link_locked(f) };
    LIST.unlock(t);
}

pub unsafe fn unlink(f: *mut File) {
    let t = LIST.lock();
    let sf = unsafe { shared_of(f) };
    let prev = sf.prev.load(Ordering::Relaxed);
    let next = sf.next.load(Ordering::Relaxed);
    if !prev.is_null() {
        unsafe { shared_of(prev) }.next.store(next, Ordering::Relaxed);
    } else if unsafe { head() } == f {
        unsafe { set_head(next) };
    }
    if !next.is_null() {
        unsafe { shared_of(next) }.prev.store(prev, Ordering::Relaxed);
    }
    sf.next.store(null_mut(), Ordering::Relaxed);
    sf.prev.store(null_mut(), Ordering::Relaxed);
    sf.linked.store(false, Ordering::Relaxed);
    LIST.unlock(t);
}

fn walk_pinned(mut visit: impl FnMut(*mut File)) {
    link_standard();
    LIST.lock_always();
    let mut p = unsafe { head() };
    if !p.is_null() {
        unsafe { shared_of(p) }.pins.fetch_add(1, Ordering::AcqRel);
    }
    LIST.unlock_always();
    while !p.is_null() {
        visit(p);
        LIST.lock_always();
        let sp = unsafe { shared_of(p) };
        let next = if sp.linked.load(Ordering::Relaxed) { unsafe { next_of(p) } } else { unsafe { head() } };
        if !next.is_null() {
            unsafe { shared_of(next) }.pins.fetch_add(1, Ordering::AcqRel);
        }
        LIST.unlock_always();
        unsafe { shared_of(p) }.pins.fetch_sub(1, Ordering::AcqRel);
        p = next;
    }
}

static FORK_REGISTERED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn note_used() {
    if !FORK_REGISTERED.load(Ordering::Relaxed) {
        note_used_first();
    }
}

#[cold]
#[inline(never)]
fn note_used_first() {
    rusty_libc_core::process::set_stdio_flush(flush_at_exit);
    if !FORK_REGISTERED.swap(true, Ordering::AcqRel) {
        rusty_libc_core::process::register_fork_handlers(atfork_prepare, atfork_parent, atfork_child);
    }
}

fn raw_read(f: &mut File, dst: &mut [u8]) -> isize {
    f.publish_hint_mt();
    if f.flags & F_MEM != 0 {
        return match f.io.read {
            Some(r) => {
                let got = unsafe { r(f.cookie, dst.as_mut_ptr().cast(), dst.len()) };
                if got > 0 {
                    f.cookie_pos += got as i64;
                }
                got
            }
            None => {
                errno::set(9);
                -1
            }
        };
    }
    let r = if f.flags & F_NOCANCEL != 0 { unistd::read_nocancel(f.fd, dst) } else { unistd::read(f.fd, dst) };
    match r {
        Ok(k) => {
            if f.cookie_pos >= 0 {
                f.cookie_pos += k as i64;
            }
            if k > 0 {
                f.hint_add(H_FLUSH);
            }
            k as isize
        }
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

fn raw_write(f: &mut File, src: &[u8]) -> isize {
    let n = src.len();
    if f.flags & F_MEM != 0 {
        return match f.io.write {
            Some(w) => {
                let put = unsafe { w(f.cookie, src.as_ptr().cast(), n) };
                if f.flags & F_APPEND != 0 {
                    f.cookie_pos = -1;
                } else if put > 0 {
                    f.cookie_pos += put as i64;
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
    let r = if f.flags & F_NOCANCEL != 0 { unistd::write_nocancel(f.fd, src) } else { unistd::write(f.fd, src) };
    match r {
        Ok(k) => {
            if f.flags & F_APPEND != 0 {
                f.cookie_pos = -1;
            } else if f.cookie_pos >= 0 {
                f.cookie_pos += k as i64;
            }
            k as isize
        }
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

fn raw_seek(f: &mut File, off: i64, whence: c_int) -> Result<i64, i32> {
    if f.flags & F_MEM != 0 {
        return match f.io.seek {
            Some(s) => {
                let mut pos = off;
                if unsafe { s(f.cookie, &mut pos, whence) } != 0 {
                    Err(errno::get())
                } else {
                    f.cookie_pos = pos;
                    Ok(pos)
                }
            }
            None => Err(29),
        };
    }
    match unistd::lseek(f.fd, off, whence) {
        Ok(p) => {
            f.cookie_pos = p;
            Ok(p)
        }
        Err(e) => Err(e.0),
    }
}

fn offset(f: &mut File) -> Result<i64, i32> {
    let active = f.flags & (F_WRMODE | F_SEEKED) != 0 || f.flags & F_RDMODE != 0 && (f.rpos() < f.rend() || f.nunget() > 0);
    if f.cookie_pos >= 0 && f.flags & F_NOCACHE == 0 && (active || f.flags & F_MEM != 0) {
        Ok(f.cookie_pos)
    } else {
        raw_seek(f, 0, 1)
    }
}

fn decide(f: &mut File) {
    if f.flags & F_DECIDED != 0 {
        return;
    }
    note_used();
    f.flags |= F_DECIDED;
    if f.flags & F_UNBUF != 0 {
        return;
    }
    if f.buf.is_null() {
        alloc_default(f);
    }
}

fn alloc_default(f: &mut File) {
    let mut size = BUFSIZ;
    if f.flags & F_MEM == 0
        && f.fd >= 0
        && let Ok((mode, blksize, _)) = unistd::fstat_basic(f.fd)
    {
        if mode & 0o170000 == 0o020000 && unistd::isatty(f.fd) {
            f.flags |= F_LBF;
        }
        if blksize > 0 && (blksize as usize) < BUFSIZ {
            size = blksize as usize;
        }
    }
    let b = alloc(size);
    if b.is_null() {
        f.flags |= F_UNBUF;
        return;
    }
    f.set_buffer(b, size);
}

fn prepare(f: &mut File) {
    if f.flags & F_DECIDED == 0 {
        decide(f);
    } else if f.buf.is_null() && f.flags & F_UNBUF == 0 {
        alloc_default(f);
    }
}

pub fn flush_write(f: &mut File) -> bool {
    if !f.writing() || f.wpos() == 0 {
        let was_writing = f.flags & F_WRMODE != 0;
        f.flags &= !F_WRMODE;
        f.set_wpos(0);
        reset_wextra(f);
        if was_writing {
            f.publish_hint_mt();
        }
        return true;
    }
    let mut off = 0;
    let n = f.wpos();
    while off < n {
        let src = unsafe { f.buf_slice(off, n - off) };
        let k = raw_write(f, src);
        if k < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            f.set_wpos(0);
            reset_wextra(f);
            return false;
        }
        off += k as usize;
        if f.flags & F_MEM != 0 && off < n {
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            f.set_wpos(0);
            reset_wextra(f);
            return false;
        }
    }
    f.flags &= !F_WRMODE;
    f.set_wpos(0);
    reset_wextra(f);
    f.publish_hint_mt();
    true
}

fn flush_line_buffered() {
    flush_lbf(false)
}

#[inline(always)]
unsafe fn peek_hint(p: *mut File) -> u8 {
    unsafe { shared_of(p) }.hint.load(Ordering::Relaxed)
}

fn flush_lbf(blocking: bool) {
    link_standard();
    if !multithreaded() {
        let mut p = unsafe { head() };
        while !p.is_null() {
            let s = unsafe { stream(p) };
            if s.flags & F_LBF != 0 && s.flags & F_WRMODE != 0 {
                flush_write(s);
            }
            p = unsafe { next_of(p) };
        }
        return;
    }
    walk_pinned(|p| {
        if unsafe { peek_hint(p) } & H_LBF_OUT != 0 {
            let l = unsafe { lock_of(p) };
            if blocking {
                l.lock();
            } else if !l.try_lock() {
                return;
            }
            let mut cg = crate::flock::LockCleanup::idle();
            unsafe { cg.arm(p) };
            let s = unsafe { stream(p) };
            if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) && s.writing() {
                flush_write(s);
            }
            s.publish_hint();
            cg.disarm();
            l.unlock();
        }
    });
}

pub(crate) fn close_all() {
    link_standard();
    if !multithreaded() {
        loop {
            let p = unsafe { head() };
            if p.is_null() {
                return;
            }
            unsafe { fclose(p) };
        }
    }
    loop {
        LIST.lock_always();
        let p = unsafe { head() };
        if p.is_null() {
            LIST.unlock_always();
            return;
        }
        unsafe { shared_of(p) }.pins.fetch_add(1, Ordering::AcqRel);
        LIST.unlock_always();
        unsafe { close_stream(p, true) };
    }
}

pub(crate) unsafe fn popen_spawn(f: &mut File, command: *const c_char, child_end: c_int, target: c_int, parent_end: c_int, cloexec: bool) -> c_int {
    use rusty_libc_core::spawn::{A_CLOSE, A_DUP2, PosixSpawnFileActions, SpawnAction, spawnix};
    let act = |tag, fd, arg| SpawnAction { tag, fd, arg, mode: 0, path: null_mut() };
    let t = LIST.lock();
    let mut fds = PopenFds { p: null_mut() };
    fds.p = unsafe { head() };
    let n = 1 + PopenFds { p: fds.p }.count();
    let mut local = [act(0, 0, 0); 16];
    let mut heap: *mut SpawnAction = null_mut();
    if n > local.len() {
        heap = alloc(n * size_of::<SpawnAction>()).cast();
        if heap.is_null() {
            LIST.unlock(t);
            return 12;
        }
    }
    let acts: &mut [SpawnAction] = if heap.is_null() {
        &mut local
    } else {
        let raw = unsafe { core::slice::from_raw_parts_mut(heap.cast::<core::mem::MaybeUninit<SpawnAction>>(), n) };
        for a in raw.iter_mut() {
            a.write(act(0, 0, 0));
        }
        unsafe { &mut *(raw as *mut [core::mem::MaybeUninit<SpawnAction>] as *mut [SpawnAction]) }
    };
    acts[0] = act(A_DUP2, child_end, target);
    let mut used = 1usize;
    for fd in fds {
        if fd != target {
            acts[used] = act(A_CLOSE, fd, 0);
            used += 1;
        }
    }
    let fa = PosixSpawnFileActions { allocated: used as c_int, used: used as c_int, actions: acts.as_mut_ptr(), pad: [0; 16] };
    let argv: [*const c_char; 5] = [c"sh".as_ptr(), c"-c".as_ptr(), c"--".as_ptr(), command, core::ptr::null()];
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    let mut pid: c_int = 0;
    let err = unsafe { spawnix(&mut pid, c"/bin/sh".as_ptr(), &fa, core::ptr::null(), argv.as_ptr(), env, false, false) };
    if err == 0 {
        let _ = unistd::close(child_end);
        if !cloexec {
            let _ = unistd::fcntl_int(parent_end, 2 , 0);
        }
        f.pid = pid;
    }
    LIST.unlock(t);
    if !heap.is_null() {
        unsafe { free(heap.cast()) };
    }
    err
}

struct PopenFds {
    p: *mut File,
}

impl Iterator for PopenFds {
    type Item = c_int;
    fn next(&mut self) -> Option<c_int> {
        while !self.p.is_null() {
            let pid = unsafe { (*self.p).pid };
            let fd = unsafe { (*self.p).fd };
            let next = unsafe { next_of(self.p) };
            self.p = next;
            if pid > 0 && fd >= 0 {
                return Some(fd);
            }
        }
        None
    }
}

pub(crate) fn purge(f: &mut File) {
    reset_wextra(f);
    drop_unget(f);
    drop_wpush(f);
    f.flags &= !(F_RDMODE | F_WRMODE);
    f.set_read(0, 0);
    f.set_wpos(0);
}

pub(crate) fn flush_line_buffered_pub() {
    flush_lbf(true)
}

#[inline]
pub fn note_locking() {
    note_used();
}

#[inline]
fn sync_mem(f: &mut File) {
    if f.flags & F_MEM != 0
        && let Some(sy) = f.io.sync
    {
        unsafe { sy(f.cookie) };
    }
}

#[inline]
unsafe fn needs_flush(p: *mut File) -> bool {
    (unsafe { peek_hint(p) }) & H_FLUSH != 0
}

#[inline]
fn has_unread_fd_input(p: &File) -> bool {
    p.flags & (F_RDMODE | F_MEM) == F_RDMODE && p.fd >= 0 && (p.rend() > p.rpos() || p.nunget() > 0)
}

pub fn freeres() {
    flush_all();
    let t = LIST.lock();
    let mut p = unsafe { head() };
    while !p.is_null() {
        let s = unsafe { stream(p) };
        drop_unget(s);
        if !s.buf.is_null() && s.flags & F_USERBUF == 0 && s.rpos() >= s.rend() {
            unsafe { free(s.buf) };
            s.set_buffer(null_mut(), 0);
        }
        p = unsafe { next_of(p) };
    }
    LIST.unlock(t);
}

fn flush_one(s: &mut File) -> bool {
    let mut ok = true;
    sync_mem(s);
    if s.writing() && !flush_write(s) {
        ok = false;
    }
    if has_unread_fd_input(s) && !sync_input(s) {
        ok = false;
    }
    ok
}

pub fn flush_all() -> bool {
    link_standard();
    let mut ok = true;
    if !multithreaded() {
        let mut p = unsafe { head() };
        while !p.is_null() {
            let s = unsafe { stream(p) };
            ok &= flush_one(s);
            p = unsafe { next_of(p) };
        }
        return ok;
    }
    walk_pinned(|p| {
        if !unsafe { needs_flush(p) } {
            return;
        }
        let l = unsafe { lock_of(p) };
        l.lock();
        let mut cg = crate::flock::LockCleanup::idle();
        unsafe { cg.arm(p) };
        let s = unsafe { stream(p) };
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            ok &= flush_one(s);
        }
        s.publish_hint();
        cg.disarm();
        l.unlock();
    });
    ok
}

const EXIT_LOCK_WAIT: u64 = 10_000_000;

extern "C" fn flush_at_exit() {
    if !multithreaded() {
        flush_all();
        return;
    }
    walk_pinned(|p| {
        if !unsafe { needs_flush(p) } {
            return;
        }
        let l = unsafe { lock_of(p) };
        let got = l.lock_timeout(EXIT_LOCK_WAIT);
        let s = unsafe { stream(p) };
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            flush_one(s);
        }
        if got {
            s.publish_hint();
            l.unlock();
        }
    });
}

const FORK_LOCK_WAIT: u64 = 150_000_000;
static FORK_LOCK: RawMutex = RawMutex::new();
static FORK_REAL: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn fork_mark<'a>(p: *mut File) -> &'a AtomicU8 {
    &unsafe { shared_of(p) }.fork_held
}

pub(crate) unsafe fn fork_grab(p: *mut File) {
    let mark = unsafe { fork_mark(p) };
    if mark.load(Ordering::Relaxed) != 0 {
        return;
    }
    let l = unsafe { lock_of(p) };
    if l.lock_timeout(FORK_LOCK_WAIT) {
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            mark.store(1, Ordering::Relaxed);
        } else {
            l.unlock();
        }
    } else {
        mark.store(2, Ordering::Relaxed);
    }
}

extern "C" fn atfork_prepare() {
    if !multithreaded() {
        FORK_REAL.store(false, Ordering::Relaxed);
        return;
    }
    FORK_LOCK.lock_always();
    FORK_REAL.store(true, Ordering::Relaxed);
    walk_pinned(|p| unsafe { fork_grab(p) });
    loop {
        LIST.lock_always();
        let mut q = unsafe { head() };
        let mut missing: *mut File = null_mut();
        while !q.is_null() {
            let mark = unsafe { fork_mark(q) };
            if mark.load(Ordering::Relaxed) == 0 {
                if unsafe { lock_of(q) }.try_lock() {
                    mark.store(1, Ordering::Relaxed);
                } else {
                    missing = q;
                    break;
                }
            }
            q = unsafe { next_of(q) };
        }
        if missing.is_null() {
            return;
        }
        let pins = &unsafe { shared_of(missing) }.pins;
        pins.fetch_add(1, Ordering::AcqRel);
        LIST.unlock_always();
        unsafe { fork_grab(missing) };
        pins.fetch_sub(1, Ordering::AcqRel);
    }
}

fn atfork_release(child: bool) {
    let mut q = unsafe { head() };
    while !q.is_null() {
        let mark = unsafe { fork_mark(q) };
        let l = unsafe { lock_of(q) };
        match mark.load(Ordering::Relaxed) {
            1 => {
                l.unlock();
            }
            2 if child => unsafe { l.reset() },
            _ => {}
        }
        mark.store(0, Ordering::Relaxed);
        if child {
            unsafe { shared_of(q) }.pins.store(0, Ordering::Relaxed);
        }
        q = unsafe { next_of(q) };
    }
    LIST.unlock_always();
    FORK_LOCK.unlock_always();
}

extern "C" fn atfork_parent() {
    if FORK_REAL.load(Ordering::Relaxed) {
        atfork_release(false);
    }
}

extern "C" fn atfork_child() {
    if FORK_REAL.load(Ordering::Relaxed) {
        atfork_release(true);
    }
}

pub(crate) fn discard_input(f: &mut File, sync: bool) {
    let mut unread = (f.rend() - f.rpos()) + f.nunget();
    if let Some(w) = f.wide_ref() {
        unread += w.tshift;
    }
    if sync && unread > 0 && f.flags & F_NOSEEK == 0 {
        let _ = raw_seek(f, -(unread as i64), 1);
    }
    drop_unget(f);
    f.set_read(0, 0);
    drop_wpush(f);
    f.flags &= !F_RDMODE;
}

fn start_write(f: &mut File) -> bool {
    if f.flags & F_WRITE == 0 {
        f.flags |= F_ERR;
        errno::set(9);
        return false;
    }
    if f.flags & F_RDMODE != 0 {
        let unread = (f.rend() - f.rpos()) + f.nunget().min(f.rpos());
        let keep_ahead = f.flags & F_WIDE != 0 && f.wide_ref().is_some_and(|w| !w.wbuf && w.ahead);
        if unread > 0 && f.flags & F_NOSEEK == 0 && !keep_ahead {
            let _ = raw_seek(f, -(unread as i64), 1);
        }
        drop_unget(f);
        f.set_read(0, 0);
        drop_wpush(f);
        f.flags &= !F_RDMODE;
    }
    if f.writing() {
        f.flags |= F_PUTTING;
        return true;
    }
    prepare(f);
    f.flags |= F_WRMODE | F_PUTTING;
    f.set_wpos(0);
    f.hint_output();
    true
}

fn underflow(f: &mut File) -> bool {
    underflow_keep(f, 0)
}

pub(crate) fn underflow_keep(f: &mut File, keep: usize) -> bool {
    if f.flags & F_READ == 0 {
        f.flags |= F_ERR;
        errno::set(9);
        return false;
    }
    if f.writing() && !flush_write(f) {
        return false;
    }
    if f.flags & F_EOF != 0 {
        return false;
    }
    drop_unget(f);
    prepare(f);
    if f.flags & (F_LBF | F_UNBUF) != 0 {
        flush_line_buffered();
    }
    if f.flags & F_UNBUF != 0 || f.buf.is_null() {
        if f.buf.is_null() {
            let size = if keep > 0 { 8 } else { 1 };
            let b = alloc(size);
            if b.is_null() {
                let sb = f.shortbuf.as_mut_ptr();
                f.set_buffer(sb, size);
                f.flags |= F_USERBUF;
            } else {
                f.set_buffer(b, size);
            }
        }
        keep_front(f, keep);
        let dst = unsafe { f.buf_slice_mut(keep, 1) };
        let k = raw_read(f, dst);
        return finish_read(f, k, keep);
    }
    keep_front(f, keep);
    let dst = unsafe { f.buf_slice_mut(keep, f.bufsize() - keep) };
    let k = raw_read(f, dst);
    finish_read(f, k, keep)
}

fn keep_front(f: &mut File, keep: usize) {
    if keep > 0 {
        let from = f.rpos();
        unsafe { f.buf_slice_mut(0, from + keep) }.copy_within(from.., 0);
    }
    f.set_read(0, keep);
}

fn finish_read(f: &mut File, k: isize, keep: usize) -> bool {
    if k > 0 {
        f.set_read(0, keep + k as usize);
        f.flags = (f.flags | F_RDMODE) & !F_PUTTING;
        true
    } else if k == 0 {
        if f.flags & F_NOEOF == 0 {
            f.flags |= F_EOF;
        }
        f.flags &= !F_SEEKED;
        false
    } else {
        f.flags |= F_ERR;
        false
    }
}

#[inline]
pub(crate) fn narrow_ok(f: &mut File) -> bool {
    let fl = f.flags;
    if fl & F_WIDE != 0 {
        return false;
    }
    if fl & F_BYTE == 0 {
        f.flags = fl | F_BYTE;
    }
    true
}

#[inline]
fn pending_out(f: &mut File) -> i64 {
    let extra = f.wide_ref().map_or(0, |w| w.extra);
    (f.wpos() as i64 - extra as i64).max(0)
}

#[inline]
fn reset_wextra(f: &mut File) {
    if let Some(w) = f.wide_mut() {
        w.extra = 0;
        w.pchars = 0;
        w.raw = 0;
    }
}

#[inline]
pub(crate) fn drop_wpush(f: &mut File) {
    if let Some(w) = f.wide_mut() {
        w.npush = 0;
        w.tshift = 0;
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
    let mut last = 0;
    for (i, &c) in mode.iter().enumerate().take(7).skip(1) {
        match c {
            b',' | 0 => break,
            b'+' | b'x' | b'b' => last = i,
            _ => {}
        }
    }
    let rest = mode.get(last + 1..)?;
    let at = rest.windows(5).position(|w| w == b",ccs=")?;
    let name = &rest[at + 5..];
    let end = name.iter().position(|&c| c == b',').unwrap_or(name.len());
    Some(&name[..end])
}

pub fn alloc_file(flags: u32, fd: c_int) -> *mut File {
    let s: *mut Stream = alloc(core::mem::size_of::<Stream>()).cast();
    if s.is_null() {
        return s.cast();
    }
    let hint = if !multithreaded() { H_ALL } else if flags & F_MEM != 0 { H_FLUSH } else { 0 };
    unsafe { s.write(Stream::new(flags, fd, shared_part(s), hint)) };
    let p: *mut File = s.cast();
    note_used();
    link_standard();
    unsafe { link(p) };
    p
}

pub fn fopen(path: Option<&core::ffi::CStr>, mode: &[u8]) -> *mut File {
    let Some((flags, oflags)) = parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    let fd = match unsafe { unistd::open(path.map_or(core::ptr::null(), |p| p.as_ptr()), oflags, 0o666) } {
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
        let s = unsafe { stream(f) };
        s.cookie_pos = start;
        if let Some(name) = mode_ccs(mode)
            && !crate::wfile::set_ccs(s, name)
        {
            let e = errno::get();
            unsafe { crate::file_api::fclose(f) };
            errno::set(e);
            return null_mut();
        }
    }
    f
}

pub fn fdopen(fd: c_int, mode: &[u8]) -> *mut File {
    let Some((flags, _)) = parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    let r = match unistd::fcntl_int(fd, 3 , 0) {
        Ok(r) => r as usize,
        Err(e) => {
            errno::set(e.0);
            return null_mut();
        }
    };
    let acc = r & 3;
    if (flags & F_READ != 0 && acc == 1) || (flags & F_WRITE != 0 && acc == 0) {
        errno::set(22);
        return null_mut();
    }
    let mut flags = flags;
    let mut added_append = false;
    if flags & F_APPEND != 0 && r & 0o2000 == 0 {
        let _ = unistd::fcntl_int(fd, 4 , (r | 0o2000) as c_int);
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

pub(crate) fn close_keep(f: &mut File) -> c_int {
    let mut result = 0;
    crate::wfile::free_wide(f);
    if f.writing() && !flush_write(f) {
        result = EOF;
    }
    if f.flags & F_RDMODE != 0 {
        discard_input(f, true);
    }
    if f.flags & F_MEM != 0 {
        if let Some(c) = f.io.close
            && unsafe { c(f.cookie) } != 0
        {
            result = EOF;
        }
    } else if f.fd >= 0 && unistd::close(f.fd).is_err() {
        result = EOF;
    }
    if f.flags & F_MEM != 0 {
        f.flags &= !F_MEM;
        f.cookie = null_mut();
        f.io = CookieIo { read: None, write: None, seek: None, close: None, sync: None };
    }
    if !f.buf.is_null() && f.flags & F_USERBUF == 0 {
        unsafe { free(f.buf) };
    }
    drop_unget(f);
    f.flags &= !(F_RDMODE | F_WRMODE);
    f.set_buffer(null_mut(), 0);
    drop_wpush(f);
    f.fd = -1;
    result
}

pub(crate) fn reopen_as(f: &mut File, flags: u32, fd: c_int, pos: i64) {
    let keep = f.flags & F_STATIC;
    f.reset(flags | keep, fd);
    f.cookie_pos = pos;
}

pub unsafe fn fclose(f: *mut File) -> c_int {
    unsafe { close_stream(f, false) }
}

unsafe fn close_stream(f: *mut File, pinned: bool) -> c_int {
    let pins = &unsafe { shared_of(f) }.pins;
    let l = unsafe { lock_of(f) };
    let real = multithreaded() && !unsafe { shared_of(f) }.nolock.load(Ordering::Relaxed);
    let mut cg = crate::flock::LockCleanup::idle();
    if real {
        l.lock();
        unsafe { cg.arm(f) };
    }
    if pinned && !unsafe { shared_of(f) }.linked.load(Ordering::Relaxed) {
        if real {
            cg.disarm();
            l.unlock();
        }
        pins.fetch_sub(1, Ordering::AcqRel);
        return EOF;
    }
    let s = unsafe { stream(f) };
    if s.flags & (F_STATIC | F_MEM | F_ERR) == F_STATIC | F_ERR && s.fd < 0 {
        if real {
            cg.disarm();
            l.unlock();
        }
        if pinned {
            pins.fetch_sub(1, Ordering::AcqRel);
        }
        errno::set(9);
        return EOF;
    }
    let mut result = 0;
    let mut close_errno = 0;
    crate::wfile::free_wide(s);
    if s.writing() && !flush_write(s) {
        result = EOF;
    }
    if s.flags & F_RDMODE != 0 {
        discard_input(s, true);
    }
    unsafe { unlink(f) };
    if s.flags & F_MEM != 0 {
        if let Some(c) = s.io.close
            && unsafe { c(s.cookie) } != 0
        {
            result = EOF;
        }
    } else if s.fd >= 0
        && let Err(e) = unistd::close(s.fd)
    {
        result = EOF;
        close_errno = e.0;
    }
    if s.pid > 0 {
        loop {
            match unistd::waitpid(s.pid, 0) {
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
    if !s.buf.is_null() && s.flags & F_USERBUF == 0 {
        unsafe { free(s.buf) };
    }
    let is_static = s.flags & F_STATIC != 0;
    if is_static {
        s.buf = null_mut();
        s.flags = F_STATIC | F_ERR;
        s.fd = -1;
    }
    if real {
        cg.disarm();
        l.unlock();
    }
    if pinned {
        pins.fetch_sub(1, Ordering::AcqRel);
    }
    if !is_static {
        loop {
            let p = pins.load(Ordering::Acquire);
            if p == 0 {
                break;
            }
            rusty_libc_core::lock::futex_wait_timeout(pins, p, 200_000);
        }
        unsafe { free(f.cast()) };
    }
    if close_errno != 0 && result == EOF {
        errno::set(close_errno);
    }
    result
}

#[inline]
pub(crate) fn drop_unget(f: &mut File) {
    if f.flags & F_UNGOT != 0 {
        f.flags &= !F_UNGOT;
        f.rptr = f.save_base;
        f.rend_p = f.save_end;
        f.rbase = f.buf;
        f.save_base = null_mut();
        f.save_end = null_mut();
    }
    if !f.ubuf.is_null() {
        unsafe { free(f.ubuf) };
        f.ubuf = null_mut();
    }
    f.ucap = 1;
}

#[inline(always)]
fn unget_done(f: &mut File) {
    if f.flags & F_UNGOT != 0 && f.rptr >= f.rend_p {
        drop_unget(f);
    }
}

fn push_byte(f: &mut File, c: u8) -> bool {
    if f.flags & F_UNGOT == 0 {
        let area = f.unget.as_mut_ptr();
        f.save_base = f.rptr;
        f.save_end = f.rend_p;
        f.rbase = area;
        f.rend_p = area.wrapping_add(f.ucap as usize);
        f.rptr = f.rend_p;
        f.flags |= F_UNGOT;
    }
    if f.rptr <= f.rbase {
        let n = f.nunget();
        let Some(newcap32) = f.ucap.checked_mul(2) else {
            return false;
        };
        let newcap = newcap32 as usize;
        let p = alloc(newcap);
        if p.is_null() {
            return false;
        }
        let fresh = unsafe { core::slice::from_raw_parts_mut(p, newcap) };
        copy_bytes(&mut fresh[newcap - n..], f.window());
        if !f.ubuf.is_null() {
            unsafe { free(f.ubuf) };
        }
        f.ubuf = p;
        f.ucap = newcap32;
        f.rbase = p;
        f.rend_p = p.wrapping_add(newcap);
        f.rptr = p.wrapping_add(newcap - n);
    }
    f.rptr = f.rptr.wrapping_sub(1);
    unsafe { *f.rptr = c };
    f.hint_add(H_FLUSH);
    true
}

#[inline]
pub fn getc(f: &mut File) -> c_int {
    if f.rptr < f.rend_p {
        return c_int::from(f.take_byte());
    }
    getc_slow(f)
}

#[inline(never)]
fn getc_slow(f: &mut File) -> c_int {
    if !narrow_ok(f) {
        return EOF;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return EOF;
    }
    let c = f.take_byte();
    unget_done(f);
    c_int::from(c)
}

pub fn peekc(f: &mut File) -> c_int {
    if !narrow_ok(f) {
        return EOF;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return EOF;
    }
    c_int::from(f.window()[0])
}

#[inline]
pub fn fill_buf(f: &mut File) -> Option<&[u8]> {
    if window_ready(f) {
        return Some(f.window());
    }
    fill_buf_slow(f)
}

#[inline(always)]
pub fn window_ready(f: &File) -> bool {
    f.flags & (F_WIDE | F_BYTE) == F_BYTE && (f.rptr as usize) < (f.rend_p as usize)
}

#[inline(never)]
pub fn fill_buf_slow(f: &mut File) -> Option<&[u8]> {
    if !narrow_ok(f) {
        return None;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return None;
    }
    Some(f.window())
}

#[inline]
pub fn consume(f: &mut File, n: usize) {
    debug_assert!(n <= f.window().len());
    f.rptr = f.rptr.wrapping_add(n);
}

pub fn ungetc(c: c_int, f: &mut File) -> c_int {
    if c == EOF || f.flags & F_READ == 0 {
        return EOF;
    }
    if f.flags & F_WIDE != 0 {
        let r = crate::wfile::ungetwc_raw(rusty_libc_wchar::wint_t::from(c as u8), f);
        return if r == rusty_libc_wchar::WEOF { EOF } else { c_int::from(c as u8) };
    }
    ungetc_force(c, f)
}

pub(crate) fn ungetc_force(c: c_int, f: &mut File) -> c_int {
    if f.flags & F_WRMODE != 0 && !flush_write(f) {
        return EOF;
    }
    if f.flags & (F_UNGOT | F_RDMODE) == F_UNGOT | F_RDMODE && f.rptr > f.rbase && f.byte_before() == c as u8 {
        f.rptr = f.rptr.wrapping_sub(1);
        f.flags &= !(F_PUTTING | F_EOF);
        return c_int::from(c as u8);
    }
    unget_done(f);
    if f.flags & F_RDMODE == 0 {
        f.set_read(0, 0);
        f.flags |= F_RDMODE;
    }
    f.flags &= !F_PUTTING;
    if f.flags & F_UNGOT == 0 && f.rptr > f.buf && f.rptr <= f.buf_end && f.byte_before() == c as u8 {
        f.rptr = f.rptr.wrapping_sub(1);
    } else if !push_byte(f, c as u8) {
        return EOF;
    }
    f.flags &= !F_EOF;
    c_int::from(c as u8)
}

pub fn read_bytes(f: &mut File, dst: &mut [u8]) -> usize {
    if !narrow_ok(f) {
        return 0;
    }
    let n = dst.len();
    let mut got = 0;
    while got < n {
        unget_done(f);
        if f.rptr < f.rend_p {
            let k = (f.rend_p as usize - f.rptr as usize).min(n - got);
            unsafe { copy_raw(dst.as_mut_ptr().wrapping_add(got), f.rptr, k) };
            f.rptr = f.rptr.wrapping_add(k);
            got += k;
            continue;
        }
        let want = n - got;
        prepare(f);
        let block = f.bufsize();
        if f.flags & F_WRITE != 0 && f.writing() && !flush_write(f) {
            break;
        }
        if f.flags & F_READ == 0 {
            f.flags |= F_ERR;
            errno::set(9);
            break;
        }
        if f.flags & F_EOF != 0 {
            break;
        }
        if f.buf.is_null() || want < block || f.flags & F_UNBUF != 0 {
            if !underflow(f) {
                break;
            }
        } else {
            if f.flags & (F_LBF | F_UNBUF) != 0 {
                flush_line_buffered();
            }
            let count = if block >= 128 { want - want % block } else { want };
            f.set_read(0, 0);
            let k = raw_read(f, &mut dst[got..got + count]);
            if k > 0 {
                got += k as usize;
            } else {
                if k == 0 {
                    if f.flags & F_NOEOF == 0 {
                        f.flags |= F_EOF;
                    }
                    f.flags &= !F_SEEKED;
                } else {
                    f.flags |= F_ERR;
                }
                break;
            }
        }
    }
    got
}

#[inline]
pub fn putc(c: c_int, f: &mut File) -> c_int {
    let b = c as u8;
    let p = f.wptr;
    if p < f.wend {
        unsafe { *p = b };
        f.wptr = p.wrapping_add(1);
        return c_int::from(b);
    }
    putc_slow(b, f)
}

#[inline(never)]
fn putc_slow(b: u8, f: &mut File) -> c_int {
    if f.flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE | F_LBF && b != b'\n' && f.wpos() < f.bufsize() {
        let p = f.wptr;
        unsafe { *p = b };
        f.wptr = p.wrapping_add(1);
        return c_int::from(b);
    }
    if f.flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE && !f.buf.is_null() && f.wpos() >= f.bufsize() {
        if !flush_write(f) {
            return EOF;
        }
        f.flags |= F_WRMODE;
        f.hint_output();
        f.set_wpos(1);
        unsafe { *f.buf = b };
        return c_int::from(b);
    }
    if f.flags & F_WIDE != 0 {
        let wide_putting = f.wide_ref().is_some_and(|w| w.putting);
        if !wide_putting || f.flags & F_W32 != 0 {
            return if crate::wfile::putwc_raw(f, rusty_libc_wchar::wint_t::from(b)) == rusty_libc_wchar::WEOF { EOF } else { c_int::from(b) };
        }
        if write_bytes_raw(f, &[b]) != 1 {
            return EOF;
        }
        let wpos = f.wpos();
        let raw = f.wide_ref().map_or(0, |w| w.raw);
        let raw = if wpos == 0 {
            0
        } else {
            let at = raw.min(wpos - 1);
            unsafe { f.buf_slice_mut(at, wpos - at) }.rotate_right(1);
            at + 1
        };
        if let Some(w) = f.wide_mut() {
            w.raw = raw;
        }
        return c_int::from(b);
    }
    if !narrow_ok(f) || put_bytes(f, &[b], false) != 1 {
        return EOF;
    }
    c_int::from(b)
}

pub fn write_bytes(f: &mut File, src: &[u8]) -> usize {
    if !narrow_ok(f) {
        return 0;
    }
    put_bytes(f, src, true)
}

pub(crate) fn write_bytes_raw(f: &mut File, src: &[u8]) -> usize {
    put_bytes(f, src, false)
}

fn put_bytes(f: &mut File, src: &[u8], xsputn: bool) -> usize {
    let n = src.len();
    if n == 0 {
        return 0;
    }
    let fl = f.flags;
    if fl & (F_WRMODE | F_UNBUF | F_LBF) == F_WRMODE {
        if (!xsputn || fl & F_PUTTING != 0) && !f.buf.is_null() && n <= f.bufsize() - f.wpos() {
            unsafe { copy_raw(f.wptr, src.as_ptr(), n) };
            f.wptr = f.wptr.wrapping_add(n);
            return n;
        }
    } else if fl & (F_UNBUF | F_WRMODE) == F_UNBUF | F_WRMODE {
        return put_unbuffered(f, src);
    }
    if f.flags & F_WRMODE == 0 && !start_write(f) {
        return 0;
    }
    if f.flags & F_APPEND != 0 && f.flags & F_MEM == 0 {
    }
    if f.flags & F_UNBUF != 0 || f.buf.is_null() {
        return put_unbuffered(f, src);
    }
    let putting = !xsputn || fl & F_PUTTING != 0;
    let lbf = f.flags & F_LBF != 0;
    let space = f.bufsize() - f.wpos();
    let mut count = if putting { space } else { 0 };
    let mut must_flush = false;
    if lbf
        && putting
        && count >= n
        && let Some(i) = src.iter().rposition(|&c| c == b'\n')
    {
        count = i + 1;
        must_flush = true;
    }
    let k = count.min(n);
    unsafe { copy_raw(f.wptr, src.as_ptr(), k) };
    f.wptr = f.wptr.wrapping_add(k);
    let mut done = k;
    if done == n && !must_flush {
        return n;
    }
    if !flush_write(f) {
        return if done == n { 0 } else { done };
    }
    f.flags |= F_WRMODE;
    f.hint_output();
    f.set_wpos(0);
    let rest = n - done;
    let block = f.bufsize();
    let direct = if block >= 128 { rest - rest % block } else { rest };
    let mut off = 0;
    while off < direct {
        let w = raw_write(f, &src[done + off..done + direct]);
        if w < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            return done + off;
        }
        off += w as usize;
        if f.flags & F_MEM != 0 && off < direct {
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            return done + off;
        }
    }
    done += direct;
    let rem = n - done;
    if rem > 0 {
        let nl = if lbf { src[done..].iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1) } else { 0 };
        if nl > 0 {
            copy_bytes(unsafe { f.buf_slice_mut(0, nl) }, &src[done..done + nl]);
            f.set_wpos(nl);
            if !flush_write(f) {
                return done + src[done..done + nl].iter().position(|&c| c == b'\n').unwrap_or(0);
            }
            f.flags |= F_WRMODE;
            f.hint_output();
            f.set_wpos(0);
            done += nl;
        }
        let tail = n - done;
        copy_bytes(unsafe { f.buf_slice_mut(0, tail) }, &src[done..]);
        f.set_wpos(tail);
        done += tail;
    }
    done
}

#[inline]
fn put_unbuffered(f: &mut File, src: &[u8]) -> usize {
    let n = src.len();
    let mut off = 0;
    while off < n {
        let k = raw_write(f, &src[off..]);
        if k < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            return off;
        }
        off += k as usize;
        if f.flags & F_MEM != 0 && off < n {
            f.flags |= F_ERR;
            return off;
        }
    }
    n
}

pub fn tell(f: &mut File) -> i64 {
    if f.wide_ref().is_some_and(|w| w.npush > 0) {
        errno::set(22);
        return -1;
    }
    let utf8_pchars = f.wide_ref().and_then(|w| (w.cs == crate::wfile::WCs::Utf8).then_some(w.pchars));
    if let Some(pchars) = utf8_pchars
        && f.writing()
        && f.wpos() > 4 * pchars
    {
        return 4_294_967_295;
    }
    let mut p = tell_bytes(f);
    if p > 0 && let Some(w) = f.wide_ref() {
        p -= w.tshift as i64;
    }
    if p > 0 && f.flags & F_W32 != 0 { p / 4 } else { p }
}

fn tell_bytes(f: &mut File) -> i64 {
    if f.flags & F_NOSEEK != 0 {
        errno::set(29);
        return -1;
    }
    let base = match offset(f) {
        Ok(p) => p,
        Err(e) => {
            if e == 29 {
                f.flags |= F_NOSEEK;
            }
            errno::set(e);
            return -1;
        }
    };
    if f.writing() {
        if f.flags & F_APPEND != 0 && f.flags & F_OLDMEM != 0 {
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
        if f.flags & F_APPEND != 0 {
            return match raw_seek(f, 0, 2) {
                Ok(end) => end + pending_out(f),
                Err(e) => {
                    errno::set(e);
                    -1
                }
            };
        }
        base + pending_out(f)
    } else if f.flags & F_RDMODE != 0 {
        let p = base - ((f.rend() - f.rpos()) + f.nunget()) as i64;
        if p < 0 {
            errno::set(29);
            return -1;
        }
        p
    } else {
        base
    }
}

pub fn seek(f: &mut File, off: i64, whence: c_int) -> c_int {
    let off = if f.flags & F_W32 != 0 { off.saturating_mul(4) } else { off };
    if let Some(w) = f.wide_mut() {
        w.putting = false;
        w.ahead = false;
    }
    seek_bytes(f, off, whence)
}

fn seek_bytes(f: &mut File, off: i64, whence: c_int) -> c_int {
    if !(0..=2).contains(&whence) {
        errno::set(22);
        return -1;
    }
    let exact = f.wpos() == 0 && if f.flags & F_UNGOT != 0 { f.save_base == f.save_end } else { f.rend() == 0 };
    if f.writing() && !flush_write(f) {
        return -1;
    }
    let mut off = off;
    let reading = f.flags & F_RDMODE != 0;
    if reading && whence == 1 {
        off -= ((f.rend() - f.rpos()) + f.nunget()) as i64;
    }
    if reading && whence != 2 && f.cookie_pos >= 0 && f.flags & F_NOSEEK == 0 {
        let here = f.cookie_pos;
        let target = if whence == 0 { off } else { here + off };
        let start = here - f.rend() as i64;
        if target >= start && target < here {
            drop_unget(f);
            f.set_rpos((target - start) as usize);
            drop_wpush(f);
            f.flags &= !(F_EOF | F_PUTTING);
            return 0;
        }
    }
    if let Some(r) = block_seek(f, off, whence, exact) {
        return r;
    }
    match raw_seek(f, off, whence) {
        Ok(_) => {
            if reading {
                drop_unget(f);
                f.set_read(0, 0);
                drop_wpush(f);
                f.flags &= !F_RDMODE;
            }
            f.flags &= !(F_EOF | F_PUTTING);
            f.flags |= F_SEEKED;
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

fn block_seek(f: &mut File, off: i64, whence: c_int, exact: bool) -> Option<c_int> {
    if f.flags & (F_MEM | F_UNBUF | F_NOSEEK) != 0 || f.flags & F_READ == 0 || !f.wide.is_null() {
        return None;
    }
    prepare(f);
    if f.buf.is_null() {
        return None;
    }
    let target = match whence {
        0 => off,
        1 if f.cookie_pos >= 0 => f.cookie_pos + off,
        2 => match unistd::fstat_basic(f.fd) {
            Ok((mode, _, size)) if mode & 0o170000 == 0o100000 => size + off,
            _ => return None,
        },
        _ => return None,
    };
    let size = f.bufsize() as i64;
    let base = target & !(size - 1);
    let delta = target - base;
    if target < 0 || delta == 0 || delta > size {
        return None;
    }
    if raw_seek(f, base, 0).is_err() {
        return None;
    }
    drop_unget(f);
    drop_wpush(f);
    f.set_read(0, 0);
    f.flags &= !(F_RDMODE | F_EOF | F_PUTTING);
    f.flags |= F_SEEKED;
    let dst = unsafe { f.buf_slice_mut(0, if exact { delta as usize } else { f.bufsize() }) };
    let count = raw_read(f, dst);
    if count < delta as isize {
        let rest = if count < 0 { delta } else { delta - count as i64 };
        if let Err(e) = raw_seek(f, rest, 1) {
            errno::set(e);
            return Some(-1);
        }
        return Some(0);
    }
    f.set_read(delta as usize, count as usize);
    f.flags |= F_RDMODE;
    Some(0)
}

pub fn fflush(f: &mut File) -> c_int {
    sync_mem(f);
    if f.writing() {
        return if flush_write(f) { 0 } else { EOF };
    }
    if f.flags & F_RDMODE != 0 && !sync_input(f) {
        return EOF;
    }
    0
}

fn sync_input(f: &mut File) -> bool {
    let mut unread = (f.rend() - f.rpos()) + f.nunget();
    if let Some(w) = f.wide_ref() {
        unread += w.tshift;
    }
    if unread > 0 {
        let r = if f.flags & F_NOSEEK != 0 { Err(29) } else { raw_seek(f, -(unread as i64), 1) };
        if let Err(e) = r {
            if f.wide.is_null() {
                drop_unget(f);
            }
            errno::set(e);
            return e == 29;
        }
    }
    drop_unget(f);
    f.set_read(0, 0);
    drop_wpush(f);
    f.flags &= !F_RDMODE;
    true
}

pub unsafe fn setvbuf(f: &mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    if !(0..=2).contains(&mode) {
        errno::set(22);
        return EOF;
    }
    if mode != 2 && buf.is_null() && f.flags & F_UNBUF == 0 {
        if mode == 0 && f.buf.is_null() {
            note_used();
            f.flags |= F_DECIDED;
            alloc_default(f);
            if f.flags & F_UNBUF != 0 {
                return EOF;
            }
        }
        f.flags &= !F_LBF;
        if mode == 1 {
            f.flags |= F_LBF;
        }
        return 0;
    }
    if f.writing() {
        flush_write(f);
    }
    if f.flags & F_RDMODE != 0 {
        discard_input(f, true);
    }
    if !f.buf.is_null() && f.flags & F_USERBUF == 0 {
        unsafe { free(f.buf) };
    }
    f.flags &= !(F_LBF | F_UNBUF | F_USERBUF | F_RDMODE | F_WRMODE);
    drop_unget(f);
    f.set_buffer(null_mut(), 0);
    note_used();
    f.flags |= F_DECIDED;
    match mode {
        2 => f.flags |= F_UNBUF,
        1 => f.flags |= F_LBF,
        _ => {}
    }
    if mode != 2 && !buf.is_null() && size > 0 {
        f.set_buffer(buf.cast(), size);
        f.flags |= F_USERBUF;
    }
    0
}

