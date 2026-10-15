use crate::errno::Errno;
use core::ffi::{c_char, c_int};
use std::ffi::CStr;
use std::sync::Mutex;
use std::vec::Vec;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utmpx {
    pub ut_type: i16,
    _pad: i16,
    pub ut_pid: i32,
    pub ut_line: [u8; 32],
    pub ut_id: [u8; 4],
    pub ut_user: [u8; 32],
    pub ut_host: [u8; 256],
    pub e_termination: i16,
    pub e_exit: i16,
    pub ut_session: i32,
    pub tv_sec: i32,
    pub tv_usec: i32,
    pub ut_addr_v6: [u32; 4],
    _reserved: [u8; 20],
}

const _: () = assert!(core::mem::size_of::<Utmpx>() == 384);

impl Utmpx {
    const ZERO: Utmpx = Utmpx {
        ut_type: 0,
        _pad: 0,
        ut_pid: 0,
        ut_line: [0; 32],
        ut_id: [0; 4],
        ut_user: [0; 32],
        ut_host: [0; 256],
        e_termination: 0,
        e_exit: 0,
        ut_session: 0,
        tv_sec: 0,
        tv_usec: 0,
        ut_addr_v6: [0; 4],
        _reserved: [0; 20],
    };
}

unsafe extern "C" {
    fn utmpname(file: *const c_char) -> c_int;
    fn setutent();
    fn endutent();
    fn getutent_r(buffer: *mut Utmpx, result: *mut *mut Utmpx) -> c_int;
    fn __errno_location() -> *mut c_int;
}

pub const PATH_UTMP: &CStr = c"/var/run/utmp";
pub const PATH_WTMP: &CStr = c"/var/log/wtmp";

static LOCK: Mutex<()> = Mutex::new(());

fn set_errno(v: c_int) {
    let p = unsafe { __errno_location() };
    unsafe { *p = v };
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn read(file: Option<&CStr>) -> Result<Vec<Utmpx>, Errno> {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(f) = file {
        if unsafe { utmpname(f.as_ptr()) } != 0 {
            return Err(Errno(errno()));
        }
    }
    let mut out = Vec::new();
    unsafe { setutent() };
    let err = loop {
        let mut rec = Utmpx::ZERO;
        let mut res: *mut Utmpx = core::ptr::null_mut();
        set_errno(0);
        let r = unsafe { getutent_r(&mut rec, &mut res) };
        if r != 0 || res.is_null() {
            break errno();
        }
        out.push(rec);
    };
    unsafe { endutent() };
    if file.is_some() {
        unsafe { utmpname(PATH_UTMP.as_ptr()) };
    }
    match err {
        0 | 2 => Ok(out),
        e => Err(Errno(e)),
    }
}

