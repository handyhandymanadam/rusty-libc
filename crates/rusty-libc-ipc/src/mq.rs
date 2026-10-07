use crate::notify::*;
use crate::util::{EACCES, EINVAL, ENOSYS, fail, res, sc, sci};
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
const SYS_CLOSE: usize = 3;
const SYS_SOCKET: usize = 41;
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_open(name: *const c_char, oflag: c_int, mut args: ...) -> mqd_t {
    unsafe {
        if *name != b'/' as c_char {
            return fail(EINVAL);
        }
        let (mode, attr) = if oflag & O_CREAT != 0 {
            let m = args.next_arg::<c_uint>();
            let a = args.next_arg::<*mut MqAttr>();
            (m, a)
        } else {
            (0, core::ptr::null_mut())
        };
        sci(syscall4(SYS_MQ_OPEN, name.add(1) as usize, oflag as usize, mode as usize, attr as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mq_open_2(name: *const c_char, oflag: c_int) -> mqd_t {
    unsafe {
        if oflag & O_CREAT != 0 {
            crate::util::fortify_fail(b"invalid mq_open call: O_CREAT without mode and attr");
        }
        mq_open(name, oflag)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mq_close(mqdes: mqd_t) -> c_int {
    sci(unsafe { syscall1(SYS_CLOSE, mqdes as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    unsafe {
        if *name != b'/' as c_char {
            return fail(EINVAL);
        }
        let r = syscall1(SYS_MQ_UNLINK, name.add(1) as usize);
        if r > usize::MAX - 4095 {
            let e = (r as isize).wrapping_neg() as c_int;
            return fail(if e == 1 { EACCES } else { e });
        }
        r as c_int
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

const _: () = assert!(core::mem::size_of::<NotifyData>() == NOTIFY_COOKIE_LEN);

static NETLINK: AtomicI32 = AtomicI32::new(-1);
static STATE: AtomicU32 = AtomicU32::new(0);

struct Job {
    fct: Option<unsafe extern "C" fn(SigVal)>,
    param: SigVal,
}

unsafe extern "C" fn notification_function(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let j = arg as *mut Job;
        let fct = (*j).fct;
        let param = (*j).param;
        rusty_libc_malloc::free(arg);
        detach_self();
        unblock_all();
        if let Some(f) = fct {
            f(param);
        }
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn helper_thread(_arg: *mut c_void) -> *mut c_void {
    unsafe {
        loop {
            let mut data = NotifyData { raw: [0; NOTIFY_COOKIE_LEN] };
            let n = syscall_cp(SYS_RECVFROM, NETLINK.load(Ordering::Relaxed) as usize, &mut data as *mut NotifyData as usize, NOTIFY_COOKIE_LEN, 0x4000 | 0x100, 0, 0);
            if !(NOTIFY_COOKIE_LEN..=usize::MAX - 4095).contains(&n) {
                if n > usize::MAX - 4095 && (n as isize) != -4 {
                    syscall_cp(24, 0, 0, 0, 0, 0, 0);
                }
                continue;
            }
            let status = data.raw[NOTIFY_COOKIE_LEN - 1];
            if status == NOTIFY_WOKENUP {
                let j = rusty_libc_malloc::malloc(core::mem::size_of::<Job>()) as *mut Job;
                if j.is_null() {
                    continue;
                }
                (*j).fct = data.f.fct;
                (*j).param = data.f.param;
                if spawn(notification_function, j as *mut c_void, data.f.attr, 0) != 0 {
                    rusty_libc_malloc::free(j as *mut c_void);
                }
            } else if status == NOTIFY_REMOVED && !data.f.attr.is_null() {
                attr_free(data.f.attr);
            }
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
    unsafe {
        if NETLINK.load(Ordering::Relaxed) == -1 {
            let fd = syscall3(SYS_SOCKET, 16, 3 | 0o2000000, 0);
            if fd > usize::MAX - 4095 {
                STATE.store(2, Ordering::Release);
                return false;
            }
            NETLINK.store(fd as c_int, Ordering::Relaxed);
        }
        let r = with_signals_blocked(|| spawn(helper_thread, core::ptr::null_mut(), core::ptr::null(), 128 * 1024));
        if r != 0 {
            syscall1(SYS_CLOSE, NETLINK.swap(-1, Ordering::Relaxed) as usize);
        }
        STATE.store(2, Ordering::Release);
        r == 0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mq_notify(mqdes: mqd_t, notification: *const SigEvent) -> c_int {
    unsafe {
        if notification.is_null() || (*notification).sigev_notify != SIGEV_THREAD {
            return sci(syscall2(SYS_MQ_NOTIFY, mqdes as usize, notification as usize));
        }
        if !init_netlink() {
            return fail(ENOSYS);
        }
        let n = &*notification;
        let attr = match attr_clone(n.sigev_notify_attributes) {
            Ok(a) => a,
            Err(e) => return fail(e),
        };
        let mut data = NotifyData { raw: [0; NOTIFY_COOKIE_LEN] };
        data.f = NotifyFields { fct: n.sigev_notify_function, param: n.sigev_value, attr };
        let mut se = SigEvent::none();
        se.sigev_notify = SIGEV_THREAD;
        se.sigev_signo = NETLINK.load(Ordering::Relaxed);
        se.sigev_value = SigVal { sival_ptr: &mut data as *mut NotifyData as *mut c_void };
        let r = sci(syscall2(SYS_MQ_NOTIFY, mqdes as usize, &se as *const SigEvent as usize));
        if r != 0 && !attr.is_null() {
            let e = rusty_libc_core::errno::get();
            attr_free(attr);
            rusty_libc_core::errno::set(e);
        }
        r
    }
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
        let p = name.to_bytes_with_nul();
        if p[0] != b'/' {
            return Err(Errno(EINVAL));
        }
        let ap = attr.map_or(0, |a| a as *const Attr as usize);
        res(unsafe { syscall4(SYS_MQ_OPEN, p.as_ptr().add(1) as usize, oflag as usize, mode as usize, ap) }).map(|fd| Queue { fd: fd as mqd_t })
    }
    pub fn unlink(name: &core::ffi::CStr) -> Result<(), Errno> {
        let p = name.to_bytes_with_nul();
        if p[0] != b'/' {
            return Err(Errno(EINVAL));
        }
        match res(unsafe { syscall1(SYS_MQ_UNLINK, p.as_ptr().add(1) as usize) }) {
            Ok(_) => Ok(()),
            Err(Errno(1)) => Err(Errno(EACCES)),
            Err(e) => Err(e),
        }
    }
    pub fn fd(&self) -> mqd_t {
        self.fd
    }
    pub fn send(&self, msg: &[u8], priority: u32) -> Result<(), Errno> {
        res(unsafe { syscall_cp(SYS_MQ_TIMEDSEND, self.fd as usize, msg.as_ptr() as usize, msg.len(), priority as usize, 0, 0) }).map(|_| ())
    }
    pub fn send_timed(&self, msg: &[u8], priority: u32, abs: &Timespec) -> Result<(), Errno> {
        res(unsafe {
            syscall_cp(SYS_MQ_TIMEDSEND, self.fd as usize, msg.as_ptr() as usize, msg.len(), priority as usize, abs as *const Timespec as usize, 0)
        })
        .map(|_| ())
    }
    pub fn receive(&self, buf: &mut [u8]) -> Result<(usize, u32), Errno> {
        let mut prio = 0u32;
        let n = res(unsafe {
            syscall_cp(SYS_MQ_TIMEDRECEIVE, self.fd as usize, buf.as_mut_ptr() as usize, buf.len(), &mut prio as *mut u32 as usize, 0, 0)
        })?;
        Ok((n, prio))
    }
    pub fn receive_timed(&self, buf: &mut [u8], abs: &Timespec) -> Result<(usize, u32), Errno> {
        let mut prio = 0u32;
        let n = res(unsafe {
            syscall_cp(
                SYS_MQ_TIMEDRECEIVE,
                self.fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                &mut prio as *mut u32 as usize,
                abs as *const Timespec as usize,
                0,
            )
        })?;
        Ok((n, prio))
    }
    pub fn attr(&self) -> Result<Attr, Errno> {
        let mut a = Attr::default();
        res(unsafe { syscall3(SYS_MQ_GETSETATTR, self.fd as usize, 0, &mut a as *mut Attr as usize) })?;
        Ok(a)
    }
    pub fn set_nonblocking(&self, on: bool) -> Result<Attr, Errno> {
        let a = Attr { flags: if on { O_NONBLOCK as c_long } else { 0 }, ..Attr::default() };
        let mut old = Attr::default();
        res(unsafe { syscall3(SYS_MQ_GETSETATTR, self.fd as usize, &a as *const Attr as usize, &mut old as *mut Attr as usize) })?;
        Ok(old)
    }
    pub fn notify(&self, ev: Option<&SigEvent>) -> Result<(), Errno> {
        res(unsafe { syscall2(SYS_MQ_NOTIFY, self.fd as usize, ev.map_or(0, |e| e as *const SigEvent as usize)) }).map(|_| ())
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe { syscall1(SYS_CLOSE, self.fd as usize) };
    }
}
