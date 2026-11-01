//! fstab.h: `getfsent`, `getfsspec`, `getfsfile`, `setfsent`, `endfsent` on `/etc/fstab`, built on the
//! mntent parser (one static `mntent`, one 8128 byte buffer, one static `fstab`). `fs_type` is the first of
//! "rw", "rq", "ro", "sw", "xx" found among the mount options, "??" when none is. The structure follows
//! glibc 2.43 misc/fstab.c, written in Rust.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::mntent::{Mntent, Stream, endmntent, getmntent_into, has_opt, setmntent};
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::ffi::cstr_bytes;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file::File as FILE;

/// `struct fstab`.
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

/// glibc's static fstab state: the open stream (NULL: closed; otherwise open and owned here), the line buffer (malloc,
/// BUFFER_SIZE bytes, kept for the process), the parsed entry and the returned `struct fstab`.
struct State {
    fp: *mut FILE,
    buffer: *mut u8,
    mntres: Mntent,
    ret: Fstab,
    path: *const c_char,
}

/// Rule: the fstab functions are MT-Unsafe in glibc (race:fsent): callers do not run them concurrently. Each exported
/// function holds the state only for its own duration.
static STATE: SyncCell<State> = SyncCell::new(State {
    fp: null_mut(),
    buffer: null_mut(),
    mntres: Mntent { mnt_fsname: null_mut(), mnt_dir: null_mut(), mnt_type: null_mut(), mnt_opts: null_mut(), mnt_freq: 0, mnt_passno: 0 },
    ret: Fstab { fs_spec: null_mut(), fs_file: null_mut(), fs_vfstype: null_mut(), fs_mntops: null_mut(), fs_type: core::ptr::null(), fs_freq: 0, fs_passno: 0 },
    path: c"/etc/fstab".as_ptr(),
});

/// Run `f` on the state.
///
/// # Safety
/// The fsent rule: no other fstab function runs at the same time; `f` does not call back into this module's exported
/// functions.
unsafe fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    // SAFETY: exclusive by the fsent rule (forwarded contract); `f` does not reach STATE again.
    unsafe { STATE.with_unsync(f) }
}

/// The returned `struct fstab` (a pointer to the static, as glibc returns).
fn ret_ptr() -> *mut Fstab {
    STATE.as_ptr().cast::<u8>().wrapping_add(core::mem::offset_of!(State, ret)).cast::<Fstab>()
}

/// Read another file than `/etc/fstab` from the next open on (tests; the C interface has no such call).
///
/// # Safety
/// `path` stays valid while the stream is in use; it is not copied.
pub unsafe fn set_path(path: *const c_char) {
    // SAFETY: fsent rule (set_path is used like the exported functions, never concurrently with them).
    unsafe { with_state(|st| st.path = if path.is_null() { c"/etc/fstab".as_ptr() } else { path }) };
}

impl State {
    /// The open stream (called only after a successful `init`, which leaves `fp` non-NULL).
    fn stream(&self) -> Stream {
        debug_assert!(!self.fp.is_null());
        // SAFETY: a non-NULL `fp` is the stream setmntent opened, open until endfsent (which clears `fp`).
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
            // SAFETY: `path` is a C string (the default, or one set_path's caller keeps valid); the mode is a literal.
            self.fp = unsafe { setmntent(self.path, c"r".as_ptr()) };
            if self.fp.is_null() {
                return false;
            }
        }
        true
    }

    /// The next entry into `mntres` (after a successful `init`).
    fn fetch(&mut self) -> bool {
        let stream = self.stream();
        // SAFETY: `buffer` is this state's malloc block of BUFFER_SIZE bytes (init allocated it), reached only here.
        let buf = unsafe { rusty_libc_core::ffi::bytes_mut(self.buffer, BUFFER_SIZE) };
        getmntent_into(&stream, &mut self.mntres, buf, BUFFER_SIZE as c_int)
    }

    /// A text field of the entry a successful `fetch` just read.
    ///
    /// # Safety
    /// `p` is one of `mntres`'s text fields after a successful `fetch` (a C string in the state's buffer or the static
    /// empty string); the slice is dropped before the next fetch rewrites the buffer.
    unsafe fn field<'a>(p: *const c_char) -> &'a [u8] {
        // SAFETY: forwarded contract.
        unsafe { cstr_bytes(p) }
    }

    /// The `struct fstab` of the entry just fetched (called only after a successful `fetch`).
    fn convert(&mut self) -> *mut Fstab {
        let m = &self.mntres;
        // SAFETY: called after a successful fetch (both callers), so mnt_opts is that entry's option string.
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

    /// The first entry from the start of the file whose field (`pick`) is `name`.
    fn find(&mut self, name: &[u8], pick: fn(&Mntent) -> *mut c_char) -> *mut Fstab {
        if !self.init(true) {
            return null_mut();
        }
        while self.fetch() {
            // SAFETY: the fetch just succeeded; `pick` returns one of the entry's text fields.
            if unsafe { State::field(pick(&self.mntres)) } == name {
                return self.convert();
            }
        }
        null_mut()
    }
}

/// `setfsent ()`: open (or rewind) the file; 1 on success, 0 when it cannot be opened.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setfsent() -> c_int {
    // SAFETY: fsent rule (the exported fstab functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(|st| st.init(true) as c_int) }
}

/// `getfsent ()`: the next entry (the file is opened on the first call), NULL at the end.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsent() -> *mut Fstab {
    // SAFETY: fsent rule (the exported fstab functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(|st| if !st.init(false) || !st.fetch() { null_mut() } else { st.convert() }) }
}

/// `getfsspec (name)`: the first entry whose device is `name` (searching from the start of the file).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsspec(name: *const c_char) -> *mut Fstab {
    // SAFETY: `name` is a C string (caller's contract).
    let name = unsafe { cstr_bytes(name) };
    // SAFETY: fsent rule (the exported fstab functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(|st| st.find(name, |m| m.mnt_fsname)) }
}

/// `getfsfile (name)`: the first entry whose mount point is `name`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getfsfile(name: *const c_char) -> *mut Fstab {
    // SAFETY: `name` is a C string (caller's contract).
    let name = unsafe { cstr_bytes(name) };
    // SAFETY: fsent rule (the exported fstab functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(|st| st.find(name, |m| m.mnt_dir)) }
}

/// `endfsent ()`: close the file.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endfsent() {
    let close = |st: &mut State| {
        if !st.fp.is_null() {
            // SAFETY: `fp` is the open stream this state owns; it is cleared right after.
            unsafe { endmntent(st.fp) };
            st.fp = null_mut();
        }
    };
    // SAFETY: fsent rule (the exported fstab functions are MT-Unsafe; callers do not overlap them).
    unsafe { with_state(close) }
}
