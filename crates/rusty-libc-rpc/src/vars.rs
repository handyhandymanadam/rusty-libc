use crate::types::*;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;

pub const EINTR: c_int = 4;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EMFILE: c_int = 24;
pub const ERANGE: c_int = 34;
pub const EIO: c_int = 5;
pub const ETIMEDOUT: c_int = 110;
pub const ECONNRESET: c_int = 104;
pub const EAFNOSUPPORT: c_int = 97;
pub const EPFNOSUPPORT: c_int = 96;
pub const ENAMETOOLONG: c_int = 36;
pub const EPROTOTYPE: c_int = 91;
pub const ENOSYS: c_int = 38;

#[inline]
pub unsafe fn mem_alloc(n: usize) -> *mut c_void {
    rusty_libc_malloc::malloc(n)
}

#[inline]
pub unsafe fn mem_free(p: *mut c_void) {
    rusty_libc_malloc::free(p)
}

#[inline]
pub unsafe fn calloc(n: usize, size: usize) -> *mut c_void {
    rusty_libc_malloc::calloc(n, size)
}

pub struct Racy<T>(pub UnsafeCell<T>);
unsafe impl<T> Sync for Racy<T> {}
impl<T> Racy<T> {
    pub const fn new(v: T) -> Racy<T> {
        Racy(UnsafeCell::new(v))
    }
    #[inline]
    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

pub struct RpcVars {
    pub clnt_perr_buf: *mut c_char,
    pub clntraw_private: *mut c_void,
    pub svcraw_private: *mut c_void,
    pub authdes_cache: *mut c_void,
    pub authdes_lru: *mut c_int,
    pub svc_xports: *mut *mut SVCXPRT,
    pub svc_head: *mut crate::svc::SvcCallout,
    pub svcsimple_proglst: *mut c_void,
    pub svcsimple_transp: *mut SVCXPRT,
    pub callrpc_private: *mut c_void,
    pub key_call_private: *mut c_void,
    pub svc_fdset_s: fd_set,
    pub rpc_createerr_s: rpc_createerr,
    pub svc_pollfd_s: *mut pollfd,
    pub svc_max_pollfd_s: c_int,
}

static MEM: Racy<core::mem::MaybeUninit<RpcVars>> = Racy::new(core::mem::MaybeUninit::zeroed());
static MEM_TAKEN: AtomicBool = AtomicBool::new(false);

#[thread_local]
static mut TVP: *mut RpcVars = core::ptr::null_mut();

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut svc_fdset: fd_set = fd_set::ZERO;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut rpc_createerr: rpc_createerr = rpc_createerr { cf_stat: 0, cf_error: rpc_err::zeroed() };
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut svc_pollfd: *mut pollfd = core::ptr::null_mut();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut svc_max_pollfd: c_int = 0;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut _null_auth: opaque_auth = opaque_auth::null();

#[inline]
fn mem_ptr() -> *mut RpcVars {
    MEM.get().cast()
}

pub unsafe fn thread_vars() -> *mut RpcVars {
    let mut tvp = *(&raw const TVP);
    if tvp.is_null() {
        if MEM_TAKEN.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            *(&raw mut TVP) = mem_ptr();
            register_exit_cleanup();
        }
        tvp = *(&raw const TVP);
        if tvp.is_null() {
            tvp = rusty_libc_malloc::calloc(1, core::mem::size_of::<RpcVars>()) as *mut RpcVars;
            if tvp.is_null() {
                tvp = mem_ptr();
            } else {
                *(&raw mut TVP) = tvp;
                register_exit_cleanup();
            }
        }
    }
    tvp
}

unsafe extern "C" fn thread_exit(_arg: *mut c_void) {
    crate::pmap::thread_destroy();
    let tvp = *(&raw const TVP);
    if !tvp.is_null() && tvp != mem_ptr() {
        rusty_libc_malloc::free(tvp.cast());
    }
    *(&raw mut TVP) = core::ptr::null_mut();
}

fn register_exit_cleanup() {
    let tid = unsafe { rusty_libc_core::syscall::syscall0(rusty_libc_core::syscall::SYS_GETTID) } as i32;
    if tid != getpid() {
        rusty_libc_core::tls::register_thread_dtor(thread_exit, core::ptr::null_mut());
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_fdset() -> *mut fd_set {
    let tvp = thread_vars();
    if tvp == mem_ptr() { &raw mut svc_fdset } else { &raw mut (*tvp).svc_fdset_s }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_createerr() -> *mut rpc_createerr {
    let tvp = thread_vars();
    if tvp == mem_ptr() { &raw mut rpc_createerr } else { &raw mut (*tvp).rpc_createerr_s }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_pollfd() -> *mut *mut pollfd {
    let tvp = thread_vars();
    if tvp == mem_ptr() { &raw mut svc_pollfd } else { &raw mut (*tvp).svc_pollfd_s }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_max_pollfd() -> *mut c_int {
    let tvp = thread_vars();
    if tvp == mem_ptr() { &raw mut svc_max_pollfd } else { &raw mut (*tvp).svc_max_pollfd_s }
}

pub unsafe fn createerr() -> *mut rpc_createerr {
    __rpc_thread_createerr()
}

pub unsafe fn set_createerr(stat: c_int, errno_val: c_int) {
    let ce = createerr();
    (*ce).cf_stat = stat;
    (*ce).cf_error.ru.RE_errno = errno_val;
}

static DTABLE: AtomicI32 = AtomicI32::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _rpc_dtablesize() -> c_int {
    let mut s = DTABLE.load(Ordering::Relaxed);
    if s == 0 {
        s = rusty_libc_sys::unistd::getdtablesize();
        DTABLE.store(s, Ordering::Relaxed);
    }
    s
}

static XID_LOCK: RawMutex = RawMutex::new();
static XID_PID: Racy<i32> = Racy::new(0);
static XID_STATE: Racy<rusty_libc_stdlib::rand::Drand48Data> =
    Racy::new(rusty_libc_stdlib::rand::Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 });

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _create_xid() -> c_ulong_t {
    let _g = XID_LOCK.guard();
    let pid = rusty_libc_sys::unistd::getpid();
    if *XID_PID.get() != pid {
        let mut now = rusty_libc_time::clock::Timespec::default();
        rusty_libc_time::clock::clock_gettime(0, &mut now);
        rusty_libc_stdlib::rand::srand48_r(now.tv_sec ^ now.tv_nsec ^ pid as i64, XID_STATE.get());
        *XID_PID.get() = pid;
    }
    let mut res: c_long = 0;
    rusty_libc_stdlib::rand::lrand48_r(XID_STATE.get(), &mut res);
    res as c_ulong_t
}

pub type c_ulong_t = core::ffi::c_ulong;

#[derive(Clone, Copy)]
pub struct Deadline {
    pub sec: i64,
    pub nsec: i64,
}

pub const INFINITE_DEADLINE: Deadline = Deadline { sec: -1, nsec: -1 };

impl Deadline {
    pub fn is_infinite(&self) -> bool {
        self.sec == -1 && self.nsec == -1
    }
}

pub fn deadline_current_time() -> (i64, i64) {
    let mut ts = rusty_libc_time::clock::Timespec::default();
    unsafe {
        if rusty_libc_time::clock::clock_gettime(1, &mut ts) != 0 {
            rusty_libc_time::clock::clock_gettime(0, &mut ts);
        }
    }
    (ts.tv_sec, ts.tv_nsec)
}

pub fn is_timeval_valid_timeout(tv: &timeval) -> bool {
    tv.tv_sec >= 0 && tv.tv_usec >= 0 && tv.tv_usec < 1_000_000
}

pub fn deadline_from_timeval(cur: (i64, i64), tv: &timeval) -> Deadline {
    let mut sec = cur.0 as u64;
    sec = sec.wrapping_add(tv.tv_sec as u64);
    if sec < tv.tv_sec as u64 {
        return INFINITE_DEADLINE;
    }
    let mut nsec = cur.1 as i32 + (tv.tv_usec as i32) * 1000;
    if nsec >= 1_000_000_000 {
        nsec -= 1_000_000_000;
        if sec.wrapping_add(1) < sec {
            return INFINITE_DEADLINE;
        }
        sec += 1;
    }
    if (sec as i64) < 0 {
        return INFINITE_DEADLINE;
    }
    Deadline { sec: sec as i64, nsec: nsec as i64 }
}

pub fn deadline_to_ms(cur: (i64, i64), d: Deadline) -> c_int {
    if d.is_infinite() {
        return c_int::MAX;
    }
    if cur.0 > d.sec || (cur.0 == d.sec && cur.1 >= d.nsec) {
        return 0;
    }
    let mut sec = d.sec - cur.0;
    if sec >= c_int::MAX as i64 {
        return c_int::MAX;
    }
    let mut nsec = (d.nsec - cur.1) as i32;
    if nsec < 0 {
        sec -= 1;
        nsec += 1_000_000_000;
    }
    nsec += 999_999;
    if nsec > 1_000_000_000 {
        sec += 1;
        nsec -= 1_000_000_000;
    }
    let mut msec = (nsec / 1_000_000) as u32;
    if sec > (c_int::MAX / 1000) as i64 {
        return c_int::MAX;
    }
    msec += (sec * 1000) as u32;
    if msec > c_int::MAX as u32 {
        return c_int::MAX;
    }
    msec as c_int
}

pub fn deadline_elapsed(cur: (i64, i64), d: Deadline) -> bool {
    deadline_to_ms(cur, d) == 0
}

pub fn deadline_first(a: Deadline, b: Deadline) -> Deadline {
    if a.is_infinite() {
        return b;
    }
    if b.is_infinite() {
        return a;
    }
    if a.sec < b.sec || (a.sec == b.sec && a.nsec < b.nsec) { a } else { b }
}

#[inline]
pub fn sc_isize(ret: usize) -> isize {
    if ret > usize::MAX - 4095 {
        errno::set((ret as isize).wrapping_neg() as i32);
        -1
    } else {
        ret as isize
    }
}

pub unsafe fn sys_write(fd: c_int, buf: *const u8, n: usize) -> isize {
    sc_isize(rusty_libc_core::tls::syscall_cp(1, fd as usize, buf as usize, n, 0, 0, 0))
}

pub unsafe fn sys_read(fd: c_int, buf: *mut u8, n: usize) -> isize {
    rusty_libc_sys::unistd::read(fd, buf.cast(), n)
}

pub fn sys_close(fd: c_int) -> c_int {
    rusty_libc_sys::unistd::close(fd)
}

pub unsafe fn sys_poll(fds: *mut pollfd, n: usize, ms: c_int) -> c_int {
    rusty_libc_sys::poll::poll(fds.cast(), n as core::ffi::c_ulong, ms)
}

pub fn get_errno() -> c_int {
    errno::get()
}

pub fn set_errno(e: c_int) {
    errno::set(e)
}

pub fn getpid() -> c_int {
    rusty_libc_sys::unistd::getpid()
}

pub fn geteuid() -> u32 {
    rusty_libc_sys::unistd::geteuid()
}

pub fn getegid() -> u32 {
    rusty_libc_sys::unistd::getegid()
}

pub fn htons(x: u16) -> u16 {
    x.to_be()
}

pub fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

pub fn htonl(x: u32) -> u32 {
    x.to_be()
}

pub fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

pub unsafe fn strlen(s: *const c_char) -> usize {
    rusty_libc_mem::strlen(s)
}

pub fn eprint(text: &[u8]) {
    unsafe {
        let e = rusty_libc_stdio::file::stderr_ptr();
        rusty_libc_stdio::file::write_bytes(e, text.as_ptr(), text.len());
    }
}

pub fn oom(func: &str) {
    let mut b = StackBuf::<128>::new();
    b.push(func.as_bytes());
    b.push(b": out of memory\n");
    eprint(b.as_bytes());
}

pub unsafe fn perror(msg: &str) {
    let mut b = StackBuf::<256>::new();
    b.push(msg.as_bytes());
    b.push(&[0]);
    rusty_libc_stdio::file_api::perror(b.buf.as_ptr().cast());
}

pub struct StackBuf<const N: usize> {
    pub buf: [u8; N],
    pub len: usize,
}

impl<const N: usize> StackBuf<N> {
    pub const fn new() -> Self {
        StackBuf { buf: [0; N], len: 0 }
    }
    pub fn push(&mut self, s: &[u8]) {
        let k = s.len().min(N - self.len);
        self.buf[self.len..self.len + k].copy_from_slice(&s[..k]);
        self.len += k;
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> Default for StackBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Write for StackBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

pub struct CBuf {
    ptr: *mut u8,
    len: usize,
    cap: usize,
    failed: bool,
}

impl CBuf {
    pub fn new() -> CBuf {
        CBuf { ptr: core::ptr::null_mut(), len: 0, cap: 0, failed: false }
    }
    pub fn push(&mut self, s: &[u8]) {
        if self.failed {
            return;
        }
        let need = self.len + s.len() + 1;
        if need > self.cap {
            let ncap = need.max(self.cap * 2).max(64);
            let np = unsafe { rusty_libc_malloc::realloc(self.ptr.cast(), ncap) } as *mut u8;
            if np.is_null() {
                self.failed = true;
                return;
            }
            self.ptr = np;
            self.cap = ncap;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr.add(self.len), s.len());
        }
        self.len += s.len();
        unsafe { *self.ptr.add(self.len) = 0 };
    }
    pub fn finish(self) -> *mut c_char {
        if self.failed {
            unsafe { rusty_libc_malloc::free(self.ptr.cast()) };
            return core::ptr::null_mut();
        }
        if self.ptr.is_null() {
            let p = unsafe { rusty_libc_malloc::malloc(1) } as *mut u8;
            if !p.is_null() {
                unsafe { *p = 0 };
            }
            return p.cast();
        }
        self.ptr.cast()
    }
}

impl Default for CBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Write for CBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

pub fn strerror_into(code: c_int, out: &mut CBuf) {
    if let Some(m) = rusty_libc_core::messages::error_message(code) {
        out.push(m.to_bytes());
        return;
    }
    use core::fmt::Write;
    let _ = write!(out, "Unknown error {}", code);
}

pub unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    core::slice::from_raw_parts(p.cast(), strlen(p))
}
