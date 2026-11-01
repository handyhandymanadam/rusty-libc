//! Error numbers. The C-visible `errno` is per thread (a `#[thread_local]` static).
use core::cell::Cell;

/// An error number as returned by the kernel (positive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub i32);

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;

// one per thread: lives in the thread's TLS block (set up by `tls::init_main` or thread creation).
// With the `export-errno` feature it is the TLS symbol `errno` that glibc exports (GLIBC_PRIVATE).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export-errno", unsafe(no_mangle))]
#[thread_local]
pub static errno: Cell<i32> = Cell::new(0);

/// Current value of the C `errno`.
pub fn get() -> i32 {
    errno.get()
}

/// Set the C `errno`.
pub fn set(value: i32) {
    errno.set(value);
}

/// Pointer to the C-visible `errno` storage.
pub fn location() -> *mut i32 {
    errno.as_ptr()
}
