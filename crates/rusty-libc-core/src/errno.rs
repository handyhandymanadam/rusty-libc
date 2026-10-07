use core::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub i32);

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export-errno", unsafe(no_mangle))]
#[thread_local]
pub static errno: Cell<i32> = Cell::new(0);

pub fn get() -> i32 {
    errno.get()
}

pub fn set(value: i32) {
    errno.set(value);
}

pub fn location() -> *mut i32 {
    errno.as_ptr()
}
