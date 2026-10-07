use crate::unistd::{nr, rc};
use core::ffi::{c_char, c_int};
use rusty_libc_core::{Errno, syscall};

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

pub fn field(f: &[c_char; 65]) -> &[u8] {
    let b: &[u8; 65] = unsafe { &*(f as *const [c_char; 65] as *const [u8; 65]) };
    let n = b.iter().position(|&c| c == 0).unwrap_or(65);
    &b[..n]
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uname(buf: *mut Utsname) -> c_int {
    rc(unsafe { syscall::syscall1(nr::UNAME, buf as usize) })
}

pub mod rs {
    use super::*;

    pub fn uname() -> Result<Utsname, Errno> {
        let mut u = Utsname::zeroed();
        crate::unistd::unit(unsafe { syscall::syscall1(nr::UNAME, &mut u as *mut Utsname as usize) })?;
        Ok(u)
    }
}

