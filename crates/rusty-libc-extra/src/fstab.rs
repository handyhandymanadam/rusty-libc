#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::mntent::{Mntent, Stream, endmntent, getmntent_into, has_opt, setmntent};
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::ffi::cstr_bytes;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file::File as FILE;

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

struct State {
    fp: *mut FILE,
    buffer: *mut u8,
    mntres: Mntent,
    ret: Fstab,
    path: *const c_char,
}

static STATE: SyncCell<State> = SyncCell::new(State {
    fp: null_mut(),
    buffer: null_mut(),
    mntres: Mntent { mnt_fsname: null_mut(), mnt_dir: null_mut(), mnt_type: null_mut(), mnt_opts: null_mut(), mnt_freq: 0, mnt_passno: 0 },
    ret: Fstab { fs_spec: null_mut(), fs_file: null_mut(), fs_vfstype: null_mut(), fs_mntops: null_mut(), fs_type: core::ptr::null(), fs_freq: 0, fs_passno: 0 },
    path: c"/etc/fstab".as_ptr(),
});

unsafe fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    unsafe { STATE.with_unsync(f) }
}

fn ret_ptr() -> *mut Fstab {
    STATE.as_ptr().cast::<u8>().wrapping_add(core::mem::offset_of!(State, ret)).cast::<Fstab>()
}

pub unsafe fn set_path(path: *const c_char) {
    unsafe { with_state(|st| st.path = if path.is_null() { c"/etc/fstab".as_ptr() } else { path }) };
}

impl State {
    fn stream(&self) -> Stream {
        debug_assert!(!self.fp.is_null());
        unsafe { Stream::new(self.fp) }
    }

    fn init(&mut self, opt_rewind: bool) -> bool {
        if self.buffer.is_null() {
            self.buffer = crate::mntent::malloc(BUFFER_SIZE);
            if self.buffer.is_null() {
                return false;
            }
        }
        if !self.fp.is_null() {
            if opt_rewind {
                self.stream().rewind();
            }
        } else {
            self.fp = unsafe { setmntent(self.path, c"r".as_ptr()) };
            if self.fp.is_null() {
                return false;
            }
        }
        true
    }

    fn fetch(&mut self) -> bool {
        let stream = self.stream();
        let buf = unsafe { rusty_libc_core::ffi::bytes_mut(self.buffer, BUFFER_SIZE) };
        getmntent_into(&stream, &mut self.mntres, buf, BUFFER_SIZE as c_int)
    }

    unsafe fn field<'a>(p: *const c_char) -> &'a [u8] {
        unsafe { cstr_bytes(p) }
    }

    fn convert(&mut self) -> *mut Fstab {
        let m = &self.mntres;
        let opts = unsafe { State::field(m.mnt_opts) };
        let ty = [c"rw", c"rq", c"ro", c"sw", c"xx"].into_iter().find(|t| has_opt(opts, t.to_bytes()).is_some()).unwrap_or(c"??");
        self.ret = Fstab {
            fs_spec: m.mnt_fsname,
            fs_file: m.mnt_dir,
            fs_vfstype: m.mnt_type,
            fs_mntops: m.mnt_opts,
            fs_type: ty.as_ptr(),
            fs_freq: m.mnt_freq,
            fs_passno: m.mnt_passno,
        };
        ret_ptr()
    }

    fn find(&mut self, name: &[u8], pick: fn(&Mntent) -> *mut c_char) -> *mut Fstab {
        if !self.init(true) {
            return null_mut();
        }
        while self.fetch() {
            if unsafe { State::field(pick(&self.mntres)) } == name {
                return self.convert();
            }
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setfsent() -> c_int {
    unsafe { with_state(|st| st.init(true) as c_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsent() -> *mut Fstab {
    unsafe { with_state(|st| if !st.init(false) || !st.fetch() { null_mut() } else { st.convert() }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsspec(name: *const c_char) -> *mut Fstab {
    let name = unsafe { cstr_bytes(name) };
    unsafe { with_state(|st| st.find(name, |m| m.mnt_fsname)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsfile(name: *const c_char) -> *mut Fstab {
    let name = unsafe { cstr_bytes(name) };
    unsafe { with_state(|st| st.find(name, |m| m.mnt_dir)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endfsent() {
    let close = |st: &mut State| {
        if !st.fp.is_null() {
            unsafe { endmntent(st.fp) };
            st.fp = null_mut();
        }
    };
    unsafe { with_state(close) }
}
