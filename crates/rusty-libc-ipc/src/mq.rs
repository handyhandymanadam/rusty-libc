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
pub const MQ_PRIO_MAX: u32 = 32768;

#[allow(non_camel_case_types)]
pub type mqd_t = c_int;
#[allow(non_camel_case_types)]
pub type ssize_t = isize;

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

pub fn kernel_name(name: &[u8]) -> Result<&[u8], c_int> {
    match name.split_first() {
        Some((b'/', rest)) => Ok(rest),
        _ => Err(EINVAL),
    }
}

fn kernel_name_ptr(name: *const c_char, first: c_char) -> Result<*const c_char, c_int> {
    if first != b'/' as c_char {
        return Err(EINVAL);
    }
    Ok(name.wrapping_add(1))
}

pub fn unlink_errno(e: c_int) -> c_int {
    if e == 1 { EACCES } else { e }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_open(name: *const c_char, oflag: c_int, mut args: ...) -> mqd_t {
    let kname = match kernel_name_ptr(name, unsafe { *name }) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    let (mode, attr) = if oflag & O_CREAT != 0 {
        let m = unsafe { args.next_arg::<c_uint>() };
        let a = unsafe { args.next_arg::<*mut MqAttr>() };
        (m, a)
    } else {
        (0, core::ptr::null_mut())
    };
    sci(unsafe { syscall4(SYS_MQ_OPEN, kname as usize, oflag as usize, mode as usize, attr as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mq_open_2(name: *const c_char, oflag: c_int) -> mqd_t {
    if oflag & O_CREAT != 0 {
        crate::util::fortify_fail(b"invalid mq_open call: O_CREAT without mode and attr");
    }
    unsafe { mq_open(name, oflag) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mq_close(mqdes: mqd_t) -> c_int {
    sci(kernel::close(mqdes as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    let kname = match kernel_name_ptr(name, unsafe { *name }) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    match res(unsafe { syscall1(SYS_MQ_UNLINK, kname as usize) }) {
        Ok(r) => r as c_int,
        Err(Errno(e)) => fail(unlink_errno(e)),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_getattr(mqdes: mqd_t, mqstat: *mut MqAttr) -> c_int {
    sci(unsafe { syscall3(SYS_MQ_GETSETATTR, mqdes as usize, 0, mqstat as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_setattr(mqdes: mqd_t, mqstat: *const MqAttr, omqstat: *mut MqAttr) -> c_int {
    sci(unsafe { syscall3(SYS_MQ_GETSETATTR, mqdes as usize, mqstat as usize, omqstat as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_send(mqdes: mqd_t, msg: *const c_char, len: usize, prio: c_uint) -> c_int {
    sci(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, mqdes as usize, msg as usize, len, prio as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedsend(mqdes: mqd_t, msg: *const c_char, len: usize, prio: c_uint, abs_timeout: *const Timespec) -> c_int {
    sci(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, mqdes as usize, msg as usize, len, prio as usize, abs_timeout as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_receive(mqdes: mqd_t, msg: *mut c_char, len: usize, prio: *mut c_uint) -> ssize_t {
    sc(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, mqdes as usize, msg as usize, len, prio as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedreceive(mqdes: mqd_t, msg: *mut c_char, len: usize, prio: *mut c_uint, abs_timeout: *const Timespec) -> ssize_t {
    sc(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, mqdes as usize, msg as usize, len, prio as usize, abs_timeout as usize, 0) })
}

const NOTIFY_COOKIE_LEN: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;

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
    fn from_cookie(raw: &[u8; NOTIFY_COOKIE_LEN]) -> NotifyFields {
        unsafe { raw.as_ptr().cast::<NotifyFields>().read_unaligned() }
    }
}

const _: () = assert!(core::mem::size_of::<NotifyData>() == NOTIFY_COOKIE_LEN);
const _: () = assert!(core::mem::size_of::<NotifyFields>() < NOTIFY_COOKIE_LEN);

static NETLINK: AtomicI32 = AtomicI32::new(-1);
static STATE: AtomicU32 = AtomicU32::new(0);

struct Job {
    fct: Option<unsafe extern "C" fn(SigVal)>,
    param: SigVal,
}

unsafe extern "C" fn notification_function(arg: *mut c_void) -> *mut c_void {
    let j = unsafe { heap_take(arg.cast::<Job>()) };
    detach_self();
    unblock_all();
    if let Some(f) = j.fct {
        unsafe { f(j.param) };
    }
    core::ptr::null_mut()
}

fn recv_cookie(raw: &mut [u8; NOTIFY_COOKIE_LEN]) -> usize {
    unsafe { syscall_cp(SYS_RECVFROM, NETLINK.load(Ordering::Relaxed) as usize, raw.as_mut_ptr() as usize, NOTIFY_COOKIE_LEN, 0x4000 | 0x100, 0, 0) }
}

unsafe extern "C" fn helper_thread(_arg: *mut c_void) -> *mut c_void {
    loop {
        let mut raw = [0u8; NOTIFY_COOKIE_LEN];
        let n = recv_cookie(&mut raw);
        if !(NOTIFY_COOKIE_LEN..=usize::MAX - 4095).contains(&n) {
            if n > usize::MAX - 4095 && (n as isize) != -4 {
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
            if unsafe { spawn(notification_function, j.cast(), f.attr, 0) } != 0 {
                unsafe { heap_free(j) };
            }
        } else if status == NOTIFY_REMOVED && !f.attr.is_null() {
            unsafe { attr_free(f.attr) };
        }
    }
}

unsafe extern "C" fn mq_fork_child() {
    STATE.store(0, Ordering::Release);
}

unsafe extern "C" fn nop() {}

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
        let fd = kernel::socket(16, 3 | 0o2000000, 0);
        if fd > usize::MAX - 4095 {
            STATE.store(2, Ordering::Release);
            return false;
        }
        NETLINK.store(fd as c_int, Ordering::Relaxed);
    }
    let r = with_signals_blocked(|| unsafe { spawn(helper_thread, core::ptr::null_mut(), core::ptr::null(), 128 * 1024) });
    if r != 0 {
        kernel::close(NETLINK.swap(-1, Ordering::Relaxed) as usize);
    }
    STATE.store(2, Ordering::Release);
    r == 0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_notify(mqdes: mqd_t, notification: *const SigEvent) -> c_int {
    let n = match unsafe { notification.as_ref() } {
        Some(n) if n.sigev_notify == SIGEV_THREAD => n,
        _ => return sci(unsafe { syscall2(SYS_MQ_NOTIFY, mqdes as usize, notification as usize) }),
    };
    if !init_netlink() {
        return fail(ENOSYS);
    }
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
    let r = sci(unsafe { syscall2(SYS_MQ_NOTIFY, mqdes as usize, &raw const se as usize) });
    if r != 0 && !attr.is_null() {
        let e = rusty_libc_core::errno::get();
        unsafe { attr_free(attr) };
        rusty_libc_core::errno::set(e);
    }
    r
}

pub struct Queue {
    fd: mqd_t,
}

pub type Attr = MqAttr;

impl Queue {
    pub fn open(name: &core::ffi::CStr, oflag: c_int) -> Result<Queue, Errno> {
        Self::open_raw(name, oflag, 0, None)
    }
    pub fn create(name: &core::ffi::CStr, oflag: c_int, mode: u32, attr: Option<&Attr>) -> Result<Queue, Errno> {
        Self::open_raw(name, oflag | O_CREAT, mode, attr)
    }
    fn open_raw(name: &core::ffi::CStr, oflag: c_int, mode: u32, attr: Option<&Attr>) -> Result<Queue, Errno> {
        let kname = kernel_name(name.to_bytes_with_nul()).map_err(Errno)?;
        let ap = attr.map_or(0, |a| a as *const Attr as usize);
        res(unsafe { syscall4(SYS_MQ_OPEN, kname.as_ptr() as usize, oflag as usize, mode as usize, ap) }).map(|fd| Queue { fd: fd as mqd_t })
    }
    pub fn unlink(name: &core::ffi::CStr) -> Result<(), Errno> {
        let kname = kernel_name(name.to_bytes_with_nul()).map_err(Errno)?;
        match res(unsafe { syscall1(SYS_MQ_UNLINK, kname.as_ptr() as usize) }) {
            Ok(_) => Ok(()),
            Err(Errno(e)) => Err(Errno(unlink_errno(e))),
        }
    }
    pub fn fd(&self) -> mqd_t {
        self.fd
    }
    pub fn send(&self, msg: &[u8], priority: u32) -> Result<(), Errno> {
        self.timedsend(msg, priority, None)
    }
    pub fn send_timed(&self, msg: &[u8], priority: u32, abs: &Timespec) -> Result<(), Errno> {
        self.timedsend(msg, priority, Some(abs))
    }
    fn timedsend(&self, msg: &[u8], priority: u32, abs: Option<&Timespec>) -> Result<(), Errno> {
        let tp = abs.map_or(0, |a| a as *const Timespec as usize);
        res(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, self.fd as usize, msg.as_ptr() as usize, msg.len(), priority as usize, tp, 0) }).map(|_| ())
    }
    pub fn receive(&self, buf: &mut [u8]) -> Result<(usize, u32), Errno> {
        self.timedreceive(buf, None)
    }
    pub fn receive_timed(&self, buf: &mut [u8], abs: &Timespec) -> Result<(usize, u32), Errno> {
        self.timedreceive(buf, Some(abs))
    }
    fn timedreceive(&self, buf: &mut [u8], abs: Option<&Timespec>) -> Result<(usize, u32), Errno> {
        let mut prio = 0u32;
        let tp = abs.map_or(0, |a| a as *const Timespec as usize);
        let n = res(unsafe { syscall_cp(SYS_MQ_TIMEDRECEIVE, self.fd as usize, buf.as_mut_ptr() as usize, buf.len(), &raw mut prio as usize, tp, 0) })?;
        Ok((n, prio))
    }
    pub fn attr(&self) -> Result<Attr, Errno> {
        self.getsetattr(None)
    }
    pub fn set_nonblocking(&self, on: bool) -> Result<Attr, Errno> {
        self.getsetattr(Some(&Attr { flags: if on { O_NONBLOCK as c_long } else { 0 }, ..Attr::default() }))
    }
    fn getsetattr(&self, new: Option<&Attr>) -> Result<Attr, Errno> {
        let mut old = Attr::default();
        let np = new.map_or(0, |a| a as *const Attr as usize);
        res(unsafe { syscall3(SYS_MQ_GETSETATTR, self.fd as usize, np, &raw mut old as usize) })?;
        Ok(old)
    }
    pub fn notify(&self, ev: Option<&SigEvent>) -> Result<(), Errno> {
        res(unsafe { syscall2(SYS_MQ_NOTIFY, self.fd as usize, ev.map_or(0, |e| e as *const SigEvent as usize)) }).map(|_| ())
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        let _ = rusty_libc_core::unistd::close(self.fd);
    }
}
