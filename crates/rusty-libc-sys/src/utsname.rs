//! sys/utsname.h: uname.
use crate::unistd::{nr, rc};
use core::ffi::{c_char, c_int};
use rusty_libc_core::{Errno, syscall};

/// `struct utsname` (Linux/glibc: six fields of 65 bytes, including `domainname`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Utsname {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

impl Utsname {
    pub const fn zeroed() -> Utsname {
        Utsname { sysname: [0; 65], nodename: [0; 65], release: [0; 65], version: [0; 65], machine: [0; 65], domainname: [0; 65] }
    }
}

/// A NUL-terminated field as bytes without the NUL.
pub fn field(f: &[c_char; 65]) -> &[u8] {
    // SAFETY: `c_char` (i8) and `u8` have the same size, alignment and valid values; the borrow is shared and as long as `f`.
    let b: &[u8; 65] = unsafe { &*(f as *const [c_char; 65] as *const [u8; 65]) };
    let n = b.iter().position(|&c| c == 0).unwrap_or(65);
    &b[..n]
}

/// uname(2).
///
/// # Safety
/// `buf` must be valid for a `struct utsname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uname(buf: *mut Utsname) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::UNAME, buf as usize) })
}

/// The same call returning a value.
pub mod rs {
    use super::*;

    pub fn uname() -> Result<Utsname, Errno> {
        let mut u = Utsname::zeroed();
        // SAFETY: the kernel writes one `struct utsname` into the local `u`.
        crate::unistd::unit(unsafe { syscall::syscall1(nr::UNAME, &mut u as *mut Utsname as usize) })?;
        Ok(u)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use core::ptr::null_mut;

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<Utsname>(), 390);
        assert_eq!(core::mem::size_of::<Utsname>(), core::mem::size_of::<libc::utsname>());
        assert_eq!(core::mem::offset_of!(Utsname, domainname), 325);
    }

    #[test]
    fn matches_the_host() {
        let _g = lock();
        unsafe {
            let mut a = Utsname::zeroed();
            let mut b: libc::utsname = core::mem::zeroed();
            assert_eq!(uname(&mut a), 0);
            assert_eq!(libc::uname(&mut b), 0);
            let bytes = |p: *const u8| core::slice::from_raw_parts(p, 390).to_vec();
            assert_eq!(bytes(&a as *const Utsname as *const u8), bytes(&b as *const libc::utsname as *const u8));
            assert_eq!(field(&a.sysname), b"Linux");
            assert_eq!(field(&a.machine), b"x86_64");
            assert!(!field(&a.release).is_empty());
            let r = rs::uname().unwrap();
            assert_eq!(field(&r.release), field(&a.release));
            assert_eq!(field(&r.nodename), field(&a.nodename));
            // a bad pointer is EFAULT like the host
            same("uname(NULL)", || uname(null_mut()) as i64, || libc::uname(core::ptr::null_mut()) as i64);
            assert_eq!(rusty_libc_core::errno::get(), 14);
            same("uname(bad ptr)", || uname(8 as *mut Utsname) as i64, || libc::uname(8 as *mut libc::utsname) as i64);
        }
    }
}
