use crate::types::*;
use core::cell::Cell;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::Locked;
pub use rusty_libc_core::sync_cell::SyncCell;

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
pub unsafe fn mem_free(p: *mut c_void) {
    unsafe { rusty_libc_malloc::free(p) }
}

#[inline]
pub fn alloc(n: usize) -> *mut c_void {
    unsafe { rusty_libc_malloc::malloc(n) }
}

#[inline]
pub fn alloc_zeroed(n: usize, size: usize) -> *mut c_void {
    unsafe { rusty_libc_malloc::calloc(n, size) }
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

static MEM: SyncCell<core::mem::MaybeUninit<RpcVars>> = SyncCell::new(core::mem::MaybeUninit::zeroed());
static MEM_TAKEN: AtomicBool = AtomicBool::new(false);

#[thread_local]
static TVP: Cell<*mut RpcVars> = Cell::new(core::ptr::null_mut());

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static svc_fdset: SyncCell<fd_set> = SyncCell::new(fd_set::ZERO);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static rpc_createerr: SyncCell<rpc_createerr> = SyncCell::new(rpc_createerr { cf_stat: 0, cf_error: rpc_err::zeroed() });
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static svc_pollfd: SyncCell<*mut pollfd> = SyncCell::new(core::ptr::null_mut());
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static svc_max_pollfd: SyncCell<c_int> = SyncCell::new(0);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _null_auth: SyncCell<opaque_auth> = SyncCell::new(opaque_auth::null());

#[inline]
pub fn null_auth() -> opaque_auth {
    unsafe { _null_auth.read() }
}

#[inline]
fn mem_ptr() -> *mut RpcVars {
    MEM.as_ptr().cast()
}

pub fn tv() -> *mut RpcVars {
    let mut tvp = TVP.get();
    if tvp.is_null() {
        if MEM_TAKEN.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            TVP.set(mem_ptr());
            register_exit_cleanup();
        }
        tvp = TVP.get();
        if tvp.is_null() {
            tvp = alloc_zeroed(1, core::mem::size_of::<RpcVars>()) as *mut RpcVars;
            if tvp.is_null() {
                tvp = mem_ptr();
            } else {
                TVP.set(tvp);
                register_exit_cleanup();
            }
        }
    }
    tvp
}

macro_rules! tv_field {
    ($( $f:ident : $t:ty => $get:ident, $set:ident; )*) => {
        $(
            #[inline]
            pub fn $get() -> $t {
                let p = tv();
                unsafe { (*p).$f }
            }
            #[inline]
            pub fn $set(v: $t) {
                let p = tv();
                unsafe { (*p).$f = v }
            }
        )*
    };
}

tv_field! {
    clnt_perr_buf: *mut c_char => tv_clnt_perr_buf, set_tv_clnt_perr_buf;
    clntraw_private: *mut c_void => tv_clntraw_private, set_tv_clntraw_private;
    svcraw_private: *mut c_void => tv_svcraw_private, set_tv_svcraw_private;
    authdes_cache: *mut c_void => tv_authdes_cache, set_tv_authdes_cache;
    authdes_lru: *mut c_int => tv_authdes_lru, set_tv_authdes_lru;
    svc_xports: *mut *mut SVCXPRT => tv_svc_xports, set_tv_svc_xports;
    svc_head: *mut crate::svc::SvcCallout => tv_svc_head, set_tv_svc_head;
    svcsimple_proglst: *mut c_void => tv_svcsimple_proglst, set_tv_svcsimple_proglst;
    svcsimple_transp: *mut SVCXPRT => tv_svcsimple_transp, set_tv_svcsimple_transp;
    callrpc_private: *mut c_void => tv_callrpc_private, set_tv_callrpc_private;
    key_call_private: *mut c_void => tv_key_call_private, set_tv_key_call_private;
}

unsafe extern "C" fn thread_exit(_arg: *mut c_void) {
    crate::pmap::thread_destroy();
    let tvp = TVP.get();
    if !tvp.is_null() && tvp != mem_ptr() {
        unsafe { rusty_libc_malloc::free(tvp.cast()) };
    }
    TVP.set(core::ptr::null_mut());
}

fn register_exit_cleanup() {
    if !rusty_libc_core::tls::is_initial_thread() {
        rusty_libc_core::tls::register_thread_dtor(thread_exit, core::ptr::null_mut(), 0);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __rpc_thread_svc_fdset() -> *mut fd_set {
    let tvp = tv();
    if tvp == mem_ptr() { svc_fdset.as_ptr() } else { unsafe { &raw mut (*tvp).svc_fdset_s } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __rpc_thread_createerr() -> *mut rpc_createerr {
    let tvp = tv();
    if tvp == mem_ptr() { rpc_createerr.as_ptr() } else { unsafe { &raw mut (*tvp).rpc_createerr_s } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __rpc_thread_svc_pollfd() -> *mut *mut pollfd {
    let tvp = tv();
    if tvp == mem_ptr() { svc_pollfd.as_ptr() } else { unsafe { &raw mut (*tvp).svc_pollfd_s } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __rpc_thread_svc_max_pollfd() -> *mut c_int {
    let tvp = tv();
    if tvp == mem_ptr() { svc_max_pollfd.as_ptr() } else { unsafe { &raw mut (*tvp).svc_max_pollfd_s } }
}

#[inline]
pub fn get_createerr() -> rpc_createerr {
    let p = __rpc_thread_createerr();
    unsafe { *p }
}

#[inline]
pub fn set_createerr_stat(stat: c_int) {
    let p = __rpc_thread_createerr();
    unsafe { (*p).cf_stat = stat };
}

#[inline]
pub fn set_createerr(stat: c_int, errno_val: c_int) {
    let p = __rpc_thread_createerr();
    let mut ce = unsafe { *p };
    ce.cf_stat = stat;
    ce.cf_error.ru.RE_errno = errno_val;
    unsafe { *p = ce };
}

#[inline]
pub fn set_createerr_full(stat: c_int, err: rpc_err) {
    let p = __rpc_thread_createerr();
    unsafe { *p = rpc_createerr { cf_stat: stat, cf_error: err } };
}

#[inline]
pub fn set_createerr_error_status(status: c_int) {
    let p = __rpc_thread_createerr();
    unsafe { (*p).cf_error.re_status = status };
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

struct XidState {
    pid: i32,
    rand: rusty_libc_stdlib::rand::Drand48Data,
}

static XID: Locked<XidState> = Locked::new(XidState { pid: 0, rand: rusty_libc_stdlib::rand::Drand48Data { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 } });

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _create_xid() -> c_ulong_t {
    XID.with(|st| {
        let pid = rusty_libc_sys::unistd::getpid();
        if st.pid != pid {
            let (_, now) = gettime(0);
            unsafe { rusty_libc_stdlib::rand::srand48_r(now.tv_sec ^ now.tv_nsec ^ pid as i64, &mut st.rand) };
            st.pid = pid;
        }
        let mut res: c_long = 0;
        unsafe { rusty_libc_stdlib::rand::lrand48_r(&mut st.rand, &mut res) };
        res as c_ulong_t
    })
}

pub fn gettime(clock: c_int) -> (c_int, rusty_libc_time::clock::Timespec) {
    let mut ts = rusty_libc_time::clock::Timespec::default();
    let r = unsafe { rusty_libc_time::clock::clock_gettime(clock, &mut ts) };
    (r, ts)
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
    let (r, mut ts) = gettime(1);
    if r != 0 {
        ts = gettime(0).1;
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

pub fn write_fd(fd: c_int, buf: &[u8]) -> isize {
    sc_isize(unsafe { rusty_libc_core::tls::syscall_cp(1, fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0) })
}

pub fn read_fd(fd: c_int, buf: &mut [u8]) -> isize {
    unsafe { rusty_libc_sys::unistd::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

pub fn sys_close(fd: c_int) -> c_int {
    rusty_libc_sys::unistd::close(fd)
}

pub fn poll_fds(fds: &mut [pollfd], ms: c_int) -> c_int {
    unsafe { rusty_libc_sys::poll::poll(fds.as_mut_ptr().cast(), fds.len() as core::ffi::c_ulong, ms) }
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

pub use rusty_libc_core::ffi::cstr_len as strlen;

pub fn eprint(text: &[u8]) {
    let e = rusty_libc_stdio::file::stderr_ptr();
    rusty_libc_stdio::file::write_bytes(unsafe { rusty_libc_stdio::file::stream(e) }, text);
}

pub fn oom(func: &str) {
    let mut b = StackBuf::<128>::new();
    b.push(func.as_bytes());
    b.push(b": out of memory\n");
    eprint(b.as_bytes());
}

pub fn perror_msg(msg: &str) {
    let mut b = StackBuf::<256>::new();
    b.push(msg.as_bytes());
    b.push(&[0]);
    b.buf[255] = 0;
    unsafe { rusty_libc_stdio::file_api::perror(b.buf.as_ptr().cast()) };
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
        let buf = unsafe { rusty_libc_core::ffi::bytes_mut(self.ptr, self.cap) };
        buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        buf[self.len] = 0;
    }
    pub fn finish(self) -> *mut c_char {
        if self.failed {
            unsafe { rusty_libc_malloc::free(self.ptr.cast()) };
            return core::ptr::null_mut();
        }
        if self.ptr.is_null() {
            let p = alloc(1) as *mut u8;
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
    if let Some(m) = rusty_libc_core::messages::error_message_tr(code) {
        out.push(m.to_bytes());
        return;
    }
    use core::fmt::Write;
    let _ = write!(out, "{}{}", core::str::from_utf8(rusty_libc_core::i18n::tr(c"Unknown error ").to_bytes()).unwrap_or("Unknown error "), code);
}

pub use rusty_libc_core::ffi::cstr_bytes as cstr;
