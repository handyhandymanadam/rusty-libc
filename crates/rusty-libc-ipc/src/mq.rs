//! POSIX message queues (mqueue.h): thin wrappers over the kernel's mq_* system calls, like glibc's.
//! Names must begin with a slash (EINVAL otherwise); the kernel gets the name without it.
//! mq_send, mq_receive and the timed forms are cancellation points; mq_close is a plain close.
//!
//! mq_notify with SIGEV_THREAD: the kernel cannot start threads, so (as glibc does) a helper thread
//! waits on a netlink socket; the kernel writes a 32-byte cookie to it when a message arrives on the
//! empty queue and the helper starts a thread running the user's function. SIGEV_SIGNAL, SIGEV_NONE
//! and SIGEV_THREAD_ID go straight to the kernel.
use crate::kernel;
use crate::notify::*;
use crate::util::{EACCES, EINVAL, ENOSYS, fail, heap_box, heap_free, heap_take, res, sc, sci};
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use rusty_libc_core::Errno;
use rusty_libc_core::syscall::{syscall1, syscall2, syscall3, syscall4};
use rusty_libc_core::tls::syscall_cp;

pub const SYS_MQ_OPEN: usize = 240;
pub const SYS_MQ_UNLINK: usize = 241;
pub const SYS_MQ_TIMEDSEND: usize = 242;
pub const SYS_MQ_TIMEDRECEIVE: usize = 243;
pub const SYS_MQ_NOTIFY: usize = 244;
pub const SYS_MQ_GETSETATTR: usize = 245;
const SYS_RECVFROM: usize = 45;

pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 1;
pub const O_RDWR: c_int = 2;
pub const O_CLOEXEC: c_int = 0o2000000;
/// Highest message priority plus one (the kernel's MQ_PRIO_MAX).
pub const MQ_PRIO_MAX: u32 = 32768;

#[allow(non_camel_case_types)]
pub type mqd_t = c_int;
#[allow(non_camel_case_types)]
pub type ssize_t = isize;

/// `struct mq_attr` (64 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MqAttr {
    pub flags: c_long,
    pub maxmsg: c_long,
    pub msgsize: c_long,
    pub curmsgs: c_long,
    pub reserved: [c_long; 4],
}

const _: () = assert!(core::mem::size_of::<MqAttr>() == 64);

pub use crate::sysv::Timespec;

/// The name the kernel gets for queue `name`: the bytes after the leading slash, or EINVAL when there is none (glibc
/// checks only the first byte).
pub fn kernel_name(name: &[u8]) -> Result<&[u8], c_int> {
    match name.split_first() {
        Some((b'/', rest)) => Ok(rest),
        _ => Err(EINVAL),
    }
}

/// The pointer the kernel gets for the C name `name` whose first byte is `first`: the byte after the slash, or EINVAL (the
/// check of [`kernel_name`], without reading further; glibc reads `name[0]` too, so NULL faults there as in glibc).
fn kernel_name_ptr(name: *const c_char, first: c_char) -> Result<*const c_char, c_int> {
    if first != b'/' as c_char {
        return Err(EINVAL);
    }
    // the rest of the string: in bounds because the first byte was not the NUL
    Ok(name.wrapping_add(1))
}

/// mq_unlink's error number from unlink's: unlink can give EPERM or EACCES; mq_unlink gives just EACCES.
pub fn unlink_errno(e: c_int) -> c_int {
    if e == 1 { EACCES } else { e }
}

/// mq_open(name, oflag [, mode, attr]): `mode` and `attr` are read only when `oflag` has O_CREAT.
///
/// # Safety
/// `name` is a NUL-terminated string; with O_CREAT the variadic arguments are a `mode_t` and a
/// `struct mq_attr *` (may be null).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_open(name: *const c_char, oflag: c_int, mut args: ...) -> mqd_t {
    // SAFETY: `name` is a C string (the caller's contract), so its first byte is readable.
    let kname = match kernel_name_ptr(name, unsafe { *name }) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    let (mode, attr) = if oflag & O_CREAT != 0 {
        // SAFETY: with O_CREAT the caller passed a mode_t (promoted to unsigned int) ...
        let m = unsafe { args.next_arg::<c_uint>() };
        // SAFETY: ... and then a `struct mq_attr *` (its contract).
        let a = unsafe { args.next_arg::<*mut MqAttr>() };
        (m, a)
    } else {
        (0, core::ptr::null_mut())
    };
    // SAFETY: the caller's name and attributes go to the kernel untouched (the kernel copies them, EFAULT if bad).
    sci(unsafe { syscall4(SYS_MQ_OPEN, kname as usize, oflag as usize, mode as usize, attr as usize) })
}

/// The fortified two-argument form (`-D_FORTIFY_SOURCE` calls it when `mq_open` has no mode and
/// attribute arguments): O_CREAT here is a programming error and aborts like glibc's.
///
/// # Safety
/// `name` is a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mq_open_2(name: *const c_char, oflag: c_int) -> mqd_t {
    if oflag & O_CREAT != 0 {
        crate::util::fortify_fail(b"invalid mq_open call: O_CREAT without mode and attr");
    }
    // SAFETY: the caller's contract; without O_CREAT no variadic argument is read.
    unsafe { mq_open(name, oflag) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mq_close(mqdes: mqd_t) -> c_int {
    sci(kernel::close(mqdes as usize))
}

/// # Safety
/// `name` is a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    // SAFETY: `name` is a C string (the caller's contract), so its first byte is readable.
    let kname = match kernel_name_ptr(name, unsafe { *name }) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    // SAFETY: the caller's name goes to the kernel untouched.
    match res(unsafe { syscall1(SYS_MQ_UNLINK, kname as usize) }) {
        Ok(r) => r as c_int,
        Err(Errno(e)) => fail(unlink_errno(e)),
    }
}

/// # Safety
/// `mqstat` points to a `struct mq_attr`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_getattr(mqdes: mqd_t, mqstat: *mut MqAttr) -> c_int {
    // SAFETY: the kernel writes the caller's structure (its contract).
    sci(unsafe { syscall3(SYS_MQ_GETSETATTR, mqdes as usize, 0, mqstat as usize) })
}

/// Only `mq_flags` (O_NONBLOCK) of `mqstat` is used. A null `mqstat` just reads the attributes into
/// `omqstat`, as in glibc (whose mq_getattr is the same call).
///
/// # Safety
/// `mqstat` and `omqstat` are null or point to a `struct mq_attr`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_setattr(mqdes: mqd_t, mqstat: *const MqAttr, omqstat: *mut MqAttr) -> c_int {
    // SAFETY: the caller's structures go to the kernel untouched (its contract).
    sci(unsafe { syscall3(SYS_MQ_GETSETATTR, mqdes as usize, mqstat as usize, omqstat as usize) })
}

/// Cancellation point.
///
/// # Safety
/// `msg` points to `len` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_send(mqdes: mqd_t, msg: *const c_char, len: usize, prio: c_uint) -> c_int {
    // SAFETY: the caller's message goes to the kernel untouched (its contract).
    sci(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, mqdes as usize, msg as usize, len, prio as usize, 0, 0) })
}

/// Cancellation point.
///
/// # Safety
/// `msg` points to `len` readable bytes; `abs_timeout` is a timespec.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedsend(mqdes: mqd_t, msg: *const c_char, len: usize, prio: c_uint, abs_timeout: *const Timespec) -> c_int {
    // SAFETY: the caller's message and timeout go to the kernel untouched (its contract).
    sci(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, mqdes as usize, msg as usize, len, prio as usize, abs_timeout as usize, 0) })
}

/// Cancellation point.
///
/// # Safety
/// `msg` has room for `len` bytes (at least the queue's `mq_msgsize`); `prio` is null or an int.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_receive(mqdes: mqd_t, msg: *mut c_char, len: usize, prio: *mut c_uint) -> ssize_t {
    // SAFETY: the kernel writes the caller's buffer and priority (its contract).
    sc(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, mqdes as usize, msg as usize, len, prio as usize, 0, 0) })
}

/// Cancellation point.
///
/// # Safety
/// As [`mq_receive`]; `abs_timeout` is a timespec.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedreceive(mqdes: mqd_t, msg: *mut c_char, len: usize, prio: *mut c_uint, abs_timeout: *const Timespec) -> ssize_t {
    // SAFETY: the kernel writes the caller's buffer and priority and reads the timeout (its contract).
    sc(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, mqdes as usize, msg as usize, len, prio as usize, abs_timeout as usize, 0) })
}

// ---- mq_notify ----

const NOTIFY_COOKIE_LEN: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;

/// The cookie the kernel hands back (32 bytes; its last byte carries the status). It is built through `f` (writing a
/// union field is safe) and read back from the received bytes with [`NotifyFields::from_cookie`].
#[repr(C)]
#[derive(Clone, Copy)]
union NotifyData {
    f: NotifyFields,
    raw: [u8; NOTIFY_COOKIE_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NotifyFields {
    fct: Option<unsafe extern "C" fn(SigVal)>,
    param: SigVal,
    attr: *mut c_void,
}

impl NotifyFields {
    /// The fields of a cookie the kernel sent back.
    fn from_cookie(raw: &[u8; NOTIFY_COOKIE_LEN]) -> NotifyFields {
        // SAFETY: the 32 bytes are the cookie `mq_notify` registered (the kernel returns it unchanged apart from the
        // status byte, which is past these 24): a valid `NotifyFields` (any bit pattern is a valid `Option<fn>`, union and
        // raw pointer); `read_unaligned` needs no alignment.
        unsafe { raw.as_ptr().cast::<NotifyFields>().read_unaligned() }
    }
}

const _: () = assert!(core::mem::size_of::<NotifyData>() == NOTIFY_COOKIE_LEN);
const _: () = assert!(core::mem::size_of::<NotifyFields>() < NOTIFY_COOKIE_LEN);

static NETLINK: AtomicI32 = AtomicI32::new(-1);
/// 0 = not started, 1 = starting, 2 = ready (or failed: NETLINK stays -1)
static STATE: AtomicU32 = AtomicU32::new(0);

/// What the helper hands a new notification thread (the cookie lives on the helper's stack).
struct Job {
    fct: Option<unsafe extern "C" fn(SigVal)>,
    param: SigVal,
}

unsafe extern "C" fn notification_function(arg: *mut c_void) -> *mut c_void {
    // SAFETY: the helper made `arg` with heap_box(Job) and gave it to this thread alone.
    let j = unsafe { heap_take(arg.cast::<Job>()) };
    detach_self();
    unblock_all();
    if let Some(f) = j.fct {
        // SAFETY: the function and value the program registered with mq_notify; calling it is the contract of SIGEV_THREAD.
        unsafe { f(j.param) };
    }
    core::ptr::null_mut()
}

/// Wait for one cookie from the netlink socket (recv with MSG_NOSIGNAL | MSG_WAITALL; a cancellation point).
fn recv_cookie(raw: &mut [u8; NOTIFY_COOKIE_LEN]) -> usize {
    // SAFETY: the kernel writes at most 32 bytes into the borrowed buffer.
    unsafe { syscall_cp(SYS_RECVFROM, NETLINK.load(Ordering::Relaxed) as usize, raw.as_mut_ptr() as usize, NOTIFY_COOKIE_LEN, 0x4000 | 0x100, 0, 0) }
}

unsafe extern "C" fn helper_thread(_arg: *mut c_void) -> *mut c_void {
    loop {
        let mut raw = [0u8; NOTIFY_COOKIE_LEN];
        let n = recv_cookie(&mut raw);
        if !(NOTIFY_COOKIE_LEN..=usize::MAX - 4095).contains(&n) {
            if n > usize::MAX - 4095 && (n as isize) != -4 {
                // a closed or broken socket: avoid spinning (sched_yield, through the cancellation hook as before)
                // SAFETY: sched_yield takes no arguments.
                unsafe { syscall_cp(24, 0, 0, 0, 0, 0, 0) };
            }
            continue;
        }
        let status = raw[NOTIFY_COOKIE_LEN - 1];
        let f = NotifyFields::from_cookie(&raw);
        if status == NOTIFY_WOKENUP {
            let j = heap_box(Job { fct: f.fct, param: f.param });
            if j.is_null() {
                continue;
            }
            // SAFETY: `f.attr` is null or the attribute copy mq_notify made with attr_clone (alive until NOTIFY_REMOVED).
            if unsafe { spawn(notification_function, j.cast(), f.attr, 0) } != 0 {
                // SAFETY: the thread was not created, so `j` is still ours.
                unsafe { heap_free(j) };
            }
        } else if status == NOTIFY_REMOVED && !f.attr.is_null() {
            // SAFETY: the copy made by attr_clone; the kernel removed the registration, so nothing uses it again.
            unsafe { attr_free(f.attr) };
        }
    }
}

unsafe extern "C" fn mq_fork_child() {
    // the helper thread is gone in the child; the socket descriptor is inherited and reused
    STATE.store(0, Ordering::Release);
}

unsafe extern "C" fn nop() {}

/// Start the netlink helper once. Returns false if it cannot run (no netlink socket or thread).
fn init_netlink() -> bool {
    loop {
        match STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(2) => return NETLINK.load(Ordering::Relaxed) != -1,
            Err(_) => core::hint::spin_loop(),
        }
    }
    static HOOKED: AtomicU32 = AtomicU32::new(0);
    if HOOKED.swap(1, Ordering::AcqRel) == 0 {
        rusty_libc_core::process::register_fork_handlers(nop, nop, mq_fork_child);
    }
    if NETLINK.load(Ordering::Relaxed) == -1 {
        // a plain netlink socket, not bound: AF_NETLINK (16), SOCK_RAW | SOCK_CLOEXEC, protocol 0
        let fd = kernel::socket(16, 3 | 0o2000000, 0);
        if fd > usize::MAX - 4095 {
            STATE.store(2, Ordering::Release);
            return false;
        }
        NETLINK.store(fd as c_int, Ordering::Relaxed);
    }
    // SAFETY: no attribute (null): a detached thread with a 128 KiB stack running our helper.
    let r = with_signals_blocked(|| unsafe { spawn(helper_thread, core::ptr::null_mut(), core::ptr::null(), 128 * 1024) });
    if r != 0 {
        kernel::close(NETLINK.swap(-1, Ordering::Relaxed) as usize);
    }
    STATE.store(2, Ordering::Release);
    r == 0
}

/// Register (or, with null, remove) the notification for a message arriving on the empty queue.
///
/// # Safety
/// `notification` is null or a `struct sigevent`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_notify(mqdes: mqd_t, notification: *const SigEvent) -> c_int {
    // SAFETY: null or a `struct sigevent` (the caller's contract).
    let n = match unsafe { notification.as_ref() } {
        Some(n) if n.sigev_notify == SIGEV_THREAD => n,
        // SAFETY: the caller's structure (or null) goes to the kernel untouched.
        _ => return sci(unsafe { syscall2(SYS_MQ_NOTIFY, mqdes as usize, notification as usize) }),
    };
    if !init_netlink() {
        return fail(ENOSYS);
    }
    // SAFETY: `sigev_notify_attributes` is null or an initialised attribute object (the SIGEV_THREAD contract).
    let attr = match unsafe { attr_clone(n.sigev_notify_attributes) } {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    let mut data = NotifyData { raw: [0; NOTIFY_COOKIE_LEN] };
    data.f = NotifyFields { fct: n.sigev_notify_function, param: n.sigev_value, attr };
    let mut se = SigEvent::none();
    se.sigev_notify = SIGEV_THREAD;
    se.sigev_signo = NETLINK.load(Ordering::Relaxed);
    se.sigev_value = SigVal { sival_ptr: (&raw mut data).cast() };
    // SAFETY: the kernel reads the local `se` and copies the 32-byte cookie it points to (the local `data`).
    let r = sci(unsafe { syscall2(SYS_MQ_NOTIFY, mqdes as usize, &raw const se as usize) });
    if r != 0 && !attr.is_null() {
        let e = rusty_libc_core::errno::get();
        // SAFETY: our own copy; the registration failed, so nothing else holds it.
        unsafe { attr_free(attr) };
        rusty_libc_core::errno::set(e);
    }
    r
}

// ---- Rust API ----

/// A POSIX message queue descriptor: closed on drop.
pub struct Queue {
    fd: mqd_t,
}

/// Queue attributes: `flags` (O_NONBLOCK), `maxmsg`, `msgsize`, and `curmsgs` (read only).
pub type Attr = MqAttr;

impl Queue {
    /// Open an existing queue `name` (with the leading slash) with `oflag` (O_RDONLY, O_WRONLY,
    /// O_RDWR, O_NONBLOCK, O_CLOEXEC).
    pub fn open(name: &core::ffi::CStr, oflag: c_int) -> Result<Queue, Errno> {
        Self::open_raw(name, oflag, 0, None)
    }
    /// Create (O_CREAT, add O_EXCL to fail if it exists) queue `name` with permission bits `mode` and
    /// attributes `attr` (None: the system defaults).
    pub fn create(name: &core::ffi::CStr, oflag: c_int, mode: u32, attr: Option<&Attr>) -> Result<Queue, Errno> {
        Self::open_raw(name, oflag | O_CREAT, mode, attr)
    }
    fn open_raw(name: &core::ffi::CStr, oflag: c_int, mode: u32, attr: Option<&Attr>) -> Result<Queue, Errno> {
        let kname = kernel_name(name.to_bytes_with_nul()).map_err(Errno)?;
        let ap = attr.map_or(0, |a| a as *const Attr as usize);
        // SAFETY: `kname` is the rest of the borrowed C string (NUL-terminated); `ap` is null or a borrowed `mq_attr`.
        res(unsafe { syscall4(SYS_MQ_OPEN, kname.as_ptr() as usize, oflag as usize, mode as usize, ap) }).map(|fd| Queue { fd: fd as mqd_t })
    }
    /// Remove the name `name` (leading slash); open descriptors keep working.
    pub fn unlink(name: &core::ffi::CStr) -> Result<(), Errno> {
        let kname = kernel_name(name.to_bytes_with_nul()).map_err(Errno)?;
        // SAFETY: `kname` is the rest of the borrowed C string (NUL-terminated).
        match res(unsafe { syscall1(SYS_MQ_UNLINK, kname.as_ptr() as usize) }) {
            Ok(_) => Ok(()),
            Err(Errno(e)) => Err(Errno(unlink_errno(e))),
        }
    }
    pub fn fd(&self) -> mqd_t {
        self.fd
    }
    /// Queue a message with `priority` (below [`MQ_PRIO_MAX`]; higher is received first). Waits when
    /// the queue is full unless it is non-blocking (EAGAIN). Cancellation point.
    pub fn send(&self, msg: &[u8], priority: u32) -> Result<(), Errno> {
        self.timedsend(msg, priority, None)
    }
    /// As [`Queue::send`], giving up with ETIMEDOUT at the absolute CLOCK_REALTIME time `abs`.
    pub fn send_timed(&self, msg: &[u8], priority: u32, abs: &Timespec) -> Result<(), Errno> {
        self.timedsend(msg, priority, Some(abs))
    }
    fn timedsend(&self, msg: &[u8], priority: u32, abs: Option<&Timespec>) -> Result<(), Errno> {
        let tp = abs.map_or(0, |a| a as *const Timespec as usize);
        // SAFETY: the kernel reads `msg.len()` bytes from the borrowed slice and the borrowed timeout (or none).
        res(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, self.fd as usize, msg.as_ptr() as usize, msg.len(), priority as usize, tp, 0) }).map(|_| ())
    }
    /// Take the oldest message of the highest priority into `buf` (at least the queue's `msgsize`
    /// bytes, else EMSGSIZE). Returns its length and priority. Cancellation point.
    pub fn receive(&self, buf: &mut [u8]) -> Result<(usize, u32), Errno> {
        self.timedreceive(buf, None)
    }
    /// As [`Queue::receive`], giving up with ETIMEDOUT at the absolute CLOCK_REALTIME time `abs`.
    pub fn receive_timed(&self, buf: &mut [u8], abs: &Timespec) -> Result<(usize, u32), Errno> {
        self.timedreceive(buf, Some(abs))
    }
    fn timedreceive(&self, buf: &mut [u8], abs: Option<&Timespec>) -> Result<(usize, u32), Errno> {
        let mut prio = 0u32;
        let tp = abs.map_or(0, |a| a as *const Timespec as usize);
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf` and the priority into the local `prio`, and reads
        // the borrowed timeout (or none).
        let n = res(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, self.fd as usize, buf.as_mut_ptr() as usize, buf.len(), &raw mut prio as usize, tp, 0) })?;
        Ok((n, prio))
    }
    pub fn attr(&self) -> Result<Attr, Errno> {
        self.getsetattr(None)
    }
    /// Set or clear O_NONBLOCK (the only attribute that can be changed); returns the old attributes.
    pub fn set_nonblocking(&self, on: bool) -> Result<Attr, Errno> {
        self.getsetattr(Some(&Attr { flags: if on { O_NONBLOCK as c_long } else { 0 }, ..Attr::default() }))
    }
    /// mq_getsetattr: set `new` (if any), return the attributes before.
    fn getsetattr(&self, new: Option<&Attr>) -> Result<Attr, Errno> {
        let mut old = Attr::default();
        let np = new.map_or(0, |a| a as *const Attr as usize);
        // SAFETY: the kernel reads the borrowed `new` (or none) and writes one `mq_attr` into the local `old`.
        res(unsafe { syscall3(SYS_MQ_GETSETATTR, self.fd as usize, np, &raw mut old as usize) })?;
        Ok(old)
    }
    /// Ask for a signal (SIGEV_SIGNAL) or nothing (SIGEV_NONE, which only makes a blocked receiver
    /// the only one woken) when a message arrives on the empty queue; `None` removes the request.
    /// SIGEV_THREAD needs a function, so use [`mq_notify`] for it.
    pub fn notify(&self, ev: Option<&SigEvent>) -> Result<(), Errno> {
        // SAFETY: the kernel reads the borrowed sigevent (or gets NULL).
        res(unsafe { syscall2(SYS_MQ_NOTIFY, self.fd as usize, ev.map_or(0, |e| e as *const SigEvent as usize)) }).map(|_| ())
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        let _ = rusty_libc_core::unistd::close(self.fd);
    }
}
