use crate::mntent::{Mntent, endmntent, getmntent_r, hasmntopt, setmntent};
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::rewind;

#[repr(C)]
pub struct Fstab {
    pub fs_spec: *mut c_char,
    pub fs_file: *mut c_char,
    pub fs_vfstype: *mut c_char,
    pub fs_mntops: *mut c_char,
    pub fs_type: *const c_char,
    pub fs_freq: c_int,
    pub fs_passno: c_int,
}

const BUFFER_SIZE: usize = 0x1fc0;

static mut FP: *mut FILE = null_mut();
static mut BUFFER: *mut c_char = null_mut();
static mut MNTRES: Mntent = Mntent { mnt_fsname: null_mut(), mnt_dir: null_mut(), mnt_type: null_mut(), mnt_opts: null_mut(), mnt_freq: 0, mnt_passno: 0 };
static mut RET: Fstab = Fstab { fs_spec: null_mut(), fs_file: null_mut(), fs_vfstype: null_mut(), fs_mntops: null_mut(), fs_type: core::ptr::null(), fs_freq: 0, fs_passno: 0 };
static mut PATH: *const c_char = c"/etc/fstab".as_ptr();

pub unsafe fn set_path(path: *const c_char) {
    unsafe { PATH = if path.is_null() { c"/etc/fstab".as_ptr() } else { path } };
}

unsafe fn init(opt_rewind: bool) -> bool {
    unsafe {
        if BUFFER.is_null() {
            BUFFER = rusty_libc_malloc::malloc(BUFFER_SIZE) as *mut c_char;
            if BUFFER.is_null() {
                return false;
            }
        }
        if !FP.is_null() {
            if opt_rewind {
                rewind(FP);
            }
        } else {
            FP = setmntent(PATH, c"r".as_ptr());
            if FP.is_null() {
                return false;
            }
        }
        true
    }
}

unsafe fn fetch() -> *mut Mntent {
    unsafe { getmntent_r(FP, &raw mut MNTRES, BUFFER, BUFFER_SIZE as c_int) }
}

unsafe fn convert() -> *mut Fstab {
    unsafe {
        let m = &raw mut MNTRES;
        let f = &raw mut RET;
        (*f).fs_spec = (*m).mnt_fsname;
        (*f).fs_file = (*m).mnt_dir;
        (*f).fs_vfstype = (*m).mnt_type;
        (*f).fs_mntops = (*m).mnt_opts;
        (*f).fs_type = if !hasmntopt(m, c"rw".as_ptr()).is_null() {
            c"rw".as_ptr()
        } else if !hasmntopt(m, c"rq".as_ptr()).is_null() {
            c"rq".as_ptr()
        } else if !hasmntopt(m, c"ro".as_ptr()).is_null() {
            c"ro".as_ptr()
        } else if !hasmntopt(m, c"sw".as_ptr()).is_null() {
            c"sw".as_ptr()
        } else if !hasmntopt(m, c"xx".as_ptr()).is_null() {
            c"xx".as_ptr()
        } else {
            c"??".as_ptr()
        };
        (*f).fs_freq = (*m).mnt_freq;
        (*f).fs_passno = (*m).mnt_passno;
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setfsent() -> c_int {
    unsafe { init(true) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsent() -> *mut Fstab {
    unsafe {
        if !init(false) || fetch().is_null() {
            return null_mut();
        }
        convert()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsspec(name: *const c_char) -> *mut Fstab {
    unsafe {
        if !init(true) {
            return null_mut();
        }
        while !fetch().is_null() {
            if rusty_libc_mem::strcmp((*(&raw const MNTRES)).mnt_fsname, name) == 0 {
                return convert();
            }
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsfile(name: *const c_char) -> *mut Fstab {
    unsafe {
        if !init(true) {
            return null_mut();
        }
        while !fetch().is_null() {
            if rusty_libc_mem::strcmp((*(&raw const MNTRES)).mnt_dir, name) == 0 {
                return convert();
            }
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endfsent() {
    unsafe {
        if !FP.is_null() {
            endmntent(FP);
            FP = null_mut();
        }
    }
}
