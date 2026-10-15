use crate::misc::sc;
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use rusty_libc_core::syscall::{check, syscall4, syscall6};
use rusty_libc_core::Errno;
use crate::kernel::{plain, plain_cp};

const SYS_PREAD64: usize = 17;
const SYS_PWRITE64: usize = 18;
const SYS_READV: usize = 19;
const SYS_WRITEV: usize = 20;
const SYS_SENDFILE: usize = 40;
const SYS_READAHEAD: usize = 187;
const SYS_SPLICE: usize = 275;
const SYS_TEE: usize = 276;
const SYS_VMSPLICE: usize = 278;
const SYS_PREADV: usize = 295;
const SYS_PWRITEV: usize = 296;
const SYS_PROCESS_VM_READV: usize = 310;
const SYS_PROCESS_VM_WRITEV: usize = 311;
const SYS_COPY_FILE_RANGE: usize = 326;
const SYS_PREADV2: usize = 327;
const SYS_PWRITEV2: usize = 328;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

pub fn pread_r(fd: i32, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), off as usize, 0, 0)) }
}

pub fn pwrite_r(fd: i32, buf: &[u8], off: i64) -> Result<usize, Errno> {
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_PWRITE64, fd as usize, buf.as_ptr() as usize, buf.len(), off as usize, 0, 0)) }
}

pub unsafe fn readv_r(fd: i32, bufs: &mut [iovec]) -> Result<usize, Errno> {
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_READV, fd as usize, bufs.as_mut_ptr() as usize, bufs.len(), 0, 0, 0)) }
}

pub unsafe fn writev_r(fd: i32, bufs: &[iovec]) -> Result<usize, Errno> {
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_WRITEV, fd as usize, bufs.as_ptr() as usize, bufs.len(), 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const iovec, n: c_int) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_READV, fd as usize, iov as usize, n as isize as usize, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn writev(fd: c_int, iov: *const iovec, n: c_int) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_WRITEV, fd as usize, iov as usize, n as isize as usize, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn preadv(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREADV, fd as usize, iov as usize, n as isize as usize, off as usize, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITEV, fd as usize, iov as usize, n as isize as usize, off as usize, 0, 0)) }
}

crate::unistd::alias!(
    preadv64 => preadv(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize
);

crate::unistd::alias!(
    pwritev64 => pwritev(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn preadv2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREADV2, fd as usize, iov as usize, n as isize as usize, off as usize, 0, flags as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITEV2, fd as usize, iov as usize, n as isize as usize, off as usize, 0, flags as isize as usize)) }
}

crate::unistd::alias!(
    preadv64v2 => preadv2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize
);

crate::unistd::alias!(
    pwritev64v2 => pwritev2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_readv(
    pid: c_int,
    local: *const iovec,
    liovcnt: c_ulong,
    remote: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    unsafe {
        sc(syscall6(SYS_PROCESS_VM_READV, pid as usize, local as usize, liovcnt as usize, remote as usize, riovcnt as usize, flags as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_writev(
    pid: c_int,
    local: *const iovec,
    liovcnt: c_ulong,
    remote: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    unsafe {
        sc(syscall6(SYS_PROCESS_VM_WRITEV, pid as usize, local as usize, liovcnt as usize, remote as usize, riovcnt as usize, flags as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, n: usize, off: i64) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREAD64, fd as usize, buf as usize, n, off as usize, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, n: usize, off: i64) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITE64, fd as usize, buf as usize, n, off as usize, 0, 0)) }
}

crate::unistd::alias!(
    pread64 => pread(fd: c_int, buf: *mut c_void, n: usize, off: i64) -> isize
);

crate::unistd::alias!(
    pwrite64 => pwrite(fd: c_int, buf: *const c_void, n: usize, off: i64) -> isize
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: usize) -> isize {
    unsafe { sc(syscall4(SYS_SENDFILE, out_fd as usize, in_fd as usize, offset as usize, count)) }
}

crate::unistd::alias!(
    sendfile64 => sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: usize) -> isize
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn splice(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_SPLICE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tee(fd_in: c_int, fd_out: c_int, len: usize, flags: c_uint) -> isize {
    sc(plain_cp!(SYS_TEE, fd_in as usize, fd_out as usize, len, flags as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vmsplice(fd: c_int, iov: *const iovec, n: usize, flags: c_uint) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_VMSPLICE, fd as usize, iov as usize, n, flags as usize, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn copy_file_range(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn readahead(fd: c_int, off: i64, count: usize) -> isize {
    sc(plain!(SYS_READAHEAD, fd as usize, off as usize, count))
}

