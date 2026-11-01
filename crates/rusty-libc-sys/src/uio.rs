//! sys/uio.h and the positioned and zero-copy I/O calls: readv, writev, preadv, pwritev (and the
//! v2 and 64 forms), process_vm_readv/writev, pread, pwrite, sendfile, splice, tee, vmsplice,
//! copy_file_range, readahead.
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

/// `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

// ---------------------------------------------------------------- Rust API

/// pread(2) into a slice.
pub fn pread_r(fd: i32, buf: &mut [u8], off: i64) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), off as usize, 0, 0)) }
}

/// pwrite(2) from a slice.
pub fn pwrite_r(fd: i32, buf: &[u8], off: i64) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `buf.len()` bytes of `buf`.
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_PWRITE64, fd as usize, buf.as_ptr() as usize, buf.len(), off as usize, 0, 0)) }
}

/// readv(2) into several slices.
///
/// # Safety
/// Each `iovec` describes `iov_len` writable bytes at `iov_base` that nothing else uses during the call (the kernel writes
/// them; an `iovec` holds raw pointers, so this cannot be checked here).
pub unsafe fn readv_r(fd: i32, bufs: &mut [iovec]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads the `bufs.len()` iovecs and writes the buffers they describe (caller's contract).
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_READV, fd as usize, bufs.as_mut_ptr() as usize, bufs.len(), 0, 0, 0)) }
}

/// writev(2) from several slices.
///
/// # Safety
/// Each `iovec` describes `iov_len` readable bytes at `iov_base`.
pub unsafe fn writev_r(fd: i32, bufs: &[iovec]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads the `bufs.len()` iovecs and the buffers they describe (caller's contract).
    unsafe { check(rusty_libc_core::tls::syscall_cp(SYS_WRITEV, fd as usize, bufs.as_ptr() as usize, bufs.len(), 0, 0, 0)) }
}

// ---------------------------------------------------------------- vectors

/// # Safety
/// `iov` points to `n` iovecs with writable buffers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const iovec, n: c_int) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_READV, fd as usize, iov as usize, n as isize as usize, 0, 0, 0)) }
}

/// # Safety
/// `iov` points to `n` iovecs with readable buffers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn writev(fd: c_int, iov: *const iovec, n: c_int) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_WRITEV, fd as usize, iov as usize, n as isize as usize, 0, 0, 0)) }
}

/// # Safety
/// As [`readv`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn preadv(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREADV, fd as usize, iov as usize, n as isize as usize, off as usize, 0, 0)) }
}

/// # Safety
/// As [`writev`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITEV, fd as usize, iov as usize, n as isize as usize, off as usize, 0, 0)) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`readv`].
    preadv64 => preadv(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize
);

crate::unistd::alias!(
    /// # Safety
    /// As [`writev`].
    pwritev64 => pwritev(fd: c_int, iov: *const iovec, n: c_int, off: i64) -> isize
);

/// # Safety
/// As [`readv`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn preadv2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREADV2, fd as usize, iov as usize, n as isize as usize, off as usize, 0, flags as isize as usize)) }
}

/// # Safety
/// As [`writev`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITEV2, fd as usize, iov as usize, n as isize as usize, off as usize, 0, flags as isize as usize)) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`readv`].
    preadv64v2 => preadv2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize
);

crate::unistd::alias!(
    /// # Safety
    /// As [`writev`].
    pwritev64v2 => pwritev2(fd: c_int, iov: *const iovec, n: c_int, off: i64, flags: c_int) -> isize
);

/// # Safety
/// Both vectors are valid for their counts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_readv(
    pid: c_int,
    local: *const iovec,
    liovcnt: c_ulong,
    remote: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    // SAFETY: the caller's iovecs go to the kernel untouched; it checks them and the buffers they describe (EFAULT).
    unsafe {
        sc(syscall6(SYS_PROCESS_VM_READV, pid as usize, local as usize, liovcnt as usize, remote as usize, riovcnt as usize, flags as usize))
    }
}

/// # Safety
/// Both vectors are valid for their counts.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_writev(
    pid: c_int,
    local: *const iovec,
    liovcnt: c_ulong,
    remote: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    // SAFETY: the caller's iovecs go to the kernel untouched; it checks them and the buffers they describe (EFAULT).
    unsafe {
        sc(syscall6(SYS_PROCESS_VM_WRITEV, pid as usize, local as usize, liovcnt as usize, remote as usize, riovcnt as usize, flags as usize))
    }
}

// ---------------------------------------------------------------- positioned and zero-copy

/// # Safety
/// `buf` has `n` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, n: usize, off: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PREAD64, fd as usize, buf as usize, n, off as usize, 0, 0)) }
}

/// # Safety
/// `buf` has `n` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, n: usize, off: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_PWRITE64, fd as usize, buf as usize, n, off as usize, 0, 0)) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`pread`].
    pread64 => pread(fd: c_int, buf: *mut c_void, n: usize, off: i64) -> isize
);

crate::unistd::alias!(
    /// # Safety
    /// As [`pwrite`].
    pwrite64 => pwrite(fd: c_int, buf: *const c_void, n: usize, off: i64) -> isize
);

/// # Safety
/// `offset` is NULL or points to the file offset.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall4(SYS_SENDFILE, out_fd as usize, in_fd as usize, offset as usize, count)) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`sendfile`].
    sendfile64 => sendfile(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: usize) -> isize
);

/// # Safety
/// The offsets are NULL or point to file offsets.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn splice(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    // a cancellation point (glibc)
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_SPLICE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tee(fd_in: c_int, fd_out: c_int, len: usize, flags: c_uint) -> isize {
    // a cancellation point (glibc)
    sc(plain_cp!(SYS_TEE, fd_in as usize, fd_out as usize, len, flags as usize))
}

/// # Safety
/// `iov` points to `n` iovecs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vmsplice(fd: c_int, iov: *const iovec, n: usize, flags: c_uint) -> isize {
    // a cancellation point (glibc)
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_VMSPLICE, fd as usize, iov as usize, n, flags as usize, 0, 0)) }
}

/// # Safety
/// The offsets are NULL or point to file offsets.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn copy_file_range(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    // a cancellation point (glibc)
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(rusty_libc_core::tls::syscall_cp(SYS_COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn readahead(fd: c_int, off: i64, count: usize) -> isize {
    sc(plain!(SYS_READAHEAD, fd as usize, off as usize, count))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;
    use rusty_libc_core::errno;
    use std::os::fd::AsRawFd;

    fn temp(tag: &str) -> (std::fs::File, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!("libc-sys-uio-{}-{}", tag, std::process::id()));
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        (f, p)
    }

    fn iov(b: &mut [u8]) -> iovec {
        iovec { iov_base: b.as_mut_ptr().cast(), iov_len: b.len() }
    }

    #[test]
    fn iovec_layout() {
        assert_eq!(core::mem::size_of::<iovec>(), core::mem::size_of::<libc::iovec>());
        assert_eq!(core::mem::size_of::<iovec>(), 16);
    }

    #[test]
    fn readv_writev_pread_pwrite() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (f, path) = temp("rw");
        let fd = f.as_raw_fd();
        unsafe {
            let (mut a, mut b, mut c) = (*b"hello ", *b"vectored ", *b"world");
            let v = [iov(&mut a), iov(&mut b), iov(&mut c)];
            assert_eq!(writev(fd, v.as_ptr(), 3), 20);
            assert_eq!(std::fs::read(&path).unwrap(), b"hello vectored world");
            // the descriptor's offset advanced by the write
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 20);
            libc::lseek(fd, 0, libc::SEEK_SET);
            let (mut x, mut y) = ([0u8; 7], [0u8; 20]);
            let v = [iov(&mut x), iov(&mut y)];
            assert_eq!(readv(fd, v.as_ptr(), 2), 20);
            assert_eq!(&x, b"hello v");
            assert_eq!(&y[..13], b"ectored world");
            // end of file
            assert_eq!(readv(fd, v.as_ptr(), 2), 0);
            // positioned: the offset does not move
            libc::lseek(fd, 3, libc::SEEK_SET);
            let mut buf = [0u8; 5];
            assert_eq!(pread(fd, buf.as_mut_ptr().cast(), 5, 6), 5);
            assert_eq!(&buf, b"vecto");
            assert_eq!(pread64(fd, buf.as_mut_ptr().cast(), 5, 15), 5);
            assert_eq!(&buf, b"world");
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 3);
            assert_eq!(pwrite(fd, b"HELLO".as_ptr().cast(), 5, 0), 5);
            assert_eq!(pwrite64(fd, b"!".as_ptr().cast(), 1, 25), 1); // past the end: a hole
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 3);
            let all = std::fs::read(&path).unwrap();
            assert_eq!(&all[..20], b"HELLO vectored world");
            assert_eq!(&all[20..25], &[0; 5]);
            assert_eq!(all[25], b'!');
            // preadv / pwritev (and the 64 and v2 forms)
            let (mut p, mut q) = (*b"ab", *b"cd");
            let wv = [iov(&mut p), iov(&mut q)];
            assert_eq!(pwritev(fd, wv.as_ptr(), 2, 1), 4);
            assert_eq!(pwritev64(fd, wv.as_ptr(), 2, 6), 4);
            assert_eq!(pwritev2(fd, wv.as_ptr(), 2, 11, 0), 4);
            assert_eq!(pwritev64v2(fd, wv.as_ptr(), 2, 16, 0), 4);
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 3);
            let (mut r1, mut r2) = ([0u8; 3], [0u8; 2]);
            let rv = [iov(&mut r1), iov(&mut r2)];
            assert_eq!(preadv(fd, rv.as_ptr(), 2, 0), 5);
            assert_eq!((&r1, &r2), (b"Hab", b"cd"));
            assert_eq!(preadv64(fd, rv.as_ptr(), 2, 1), 5);
            assert_eq!((&r1, &r2), (b"abc", b"d "));
            assert_eq!(preadv2(fd, rv.as_ptr(), 2, 6, 0), 5);
            assert_eq!((&r1, &r2), (b"abc", b"do"));
            assert_eq!(preadv64v2(fd, rv.as_ptr(), 2, 11, 0), 5);
            assert_eq!((&r1, &r2), (b"abc", b"dw"));
            // offset -1 with preadv2 uses and moves the current offset (flags 0)
            libc::lseek(fd, 0, libc::SEEK_SET);
            assert_eq!(preadv2(fd, rv.as_ptr(), 2, -1, 0), 5);
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 5);
            // error cases against the host
            for bad in [-1, 9999] {
                assert_eq!(pread(bad, buf.as_mut_ptr().cast(), 1, 0), -1);
                let e = errno::get();
                assert_eq!(libc::pread(bad, buf.as_mut_ptr().cast(), 1, 0), -1);
                assert_eq!(e, *libc::__errno_location());
                assert_eq!(writev(bad, wv.as_ptr(), 2), -1);
                assert_eq!(errno::get(), libc::EBADF);
            }
            assert_eq!(pread(fd, buf.as_mut_ptr().cast(), 1, -5), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(readv(fd, rv.as_ptr(), -1), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // a pipe cannot be pread
            let mut pf = [0; 2];
            libc::pipe(pf.as_mut_ptr());
            assert_eq!(pread(pf[0], buf.as_mut_ptr().cast(), 1, 0), -1);
            assert_eq!(errno::get(), libc::ESPIPE);
            libc::close(pf[0]);
            libc::close(pf[1]);
        }
        // Rust API
        assert_eq!(pwrite_r(fd, b"zz", 0), Ok(2));
        let mut two = [0u8; 2];
        assert_eq!(pread_r(fd, &mut two, 0), Ok(2));
        assert_eq!(&two, b"zz");
        let mut ba = *b"12";
        let mut bb = *b"34";
        assert_eq!(unsafe { writev_r(fd, &[iov(&mut ba), iov(&mut bb)]) }, Ok(4));
        drop(f);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sendfile_splice_copy_tee_readahead() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut src, sp) = temp("src");
        let (dst, dp) = temp("dst");
        use std::io::Write;
        let data: Vec<u8> = (0..10000u32).map(|i| (i % 253) as u8).collect();
        src.write_all(&data).unwrap();
        let (sfd, dfd) = (src.as_raw_fd(), dst.as_raw_fd());
        unsafe {
            // sendfile with an explicit offset leaves the file offset alone
            let mut off: i64 = 100;
            assert_eq!(sendfile(dfd, sfd, &mut off, 1000), 1000);
            assert_eq!(off, 1100);
            assert_eq!(&std::fs::read(&dp).unwrap()[..], &data[100..1100]);
            let mut off2: i64 = 0;
            assert_eq!(sendfile64(dfd, sfd, &mut off2, 10), 10);
            // copy_file_range
            let (mut oi, mut oo) = (2000i64, 0i64);
            let n = copy_file_range(sfd, &mut oi, dfd, &mut oo, 500, 0);
            assert_eq!(n, 500);
            assert_eq!((oi, oo), (2500, 500));
            let got = std::fs::read(&dp).unwrap();
            assert_eq!(&got[..500], &data[2000..2500]);
            // errors against host
            assert_eq!(sendfile(-1, sfd, core::ptr::null_mut(), 1), -1);
            let e = errno::get();
            assert_eq!(libc::sendfile(-1, sfd, core::ptr::null_mut(), 1), -1);
            assert_eq!(e, *libc::__errno_location());
            assert_eq!(copy_file_range(sfd, core::ptr::null_mut(), dfd, core::ptr::null_mut(), 1, 7), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // splice file -> pipe -> file, tee between two pipes, vmsplice into a pipe
            let mut p1 = [0; 2];
            let mut p2 = [0; 2];
            libc::pipe(p1.as_mut_ptr());
            libc::pipe(p2.as_mut_ptr());
            let mut so: i64 = 50;
            assert_eq!(splice(sfd, &mut so, p1[1], core::ptr::null_mut(), 300, 0), 300);
            assert_eq!(so, 350);
            assert_eq!(tee(p1[0], p2[1], 300, 0), 300);
            let mut b1 = [0u8; 300];
            let mut b2 = [0u8; 300];
            assert_eq!(libc::read(p1[0], b1.as_mut_ptr().cast(), 300), 300);
            assert_eq!(libc::read(p2[0], b2.as_mut_ptr().cast(), 300), 300);
            assert_eq!(&b1[..], &data[50..350]);
            assert_eq!(b1, b2);
            let mut chunk = *b"vmsplice!";
            let v = [iov(&mut chunk)];
            assert_eq!(vmsplice(p1[1], v.as_ptr(), 1, 0), 9);
            let mut b3 = [0u8; 9];
            assert_eq!(libc::read(p1[0], b3.as_mut_ptr().cast(), 9), 9);
            assert_eq!(&b3, b"vmsplice!");
            assert_eq!(tee(sfd, p2[1], 1, 0), -1); // a regular file is not a pipe
            assert_eq!(errno::get(), libc::EINVAL);
            for fd in [p1[0], p1[1], p2[0], p2[1]] {
                libc::close(fd);
            }
            assert_eq!(readahead(sfd, 0, 4096), 0);
            assert_eq!(readahead(-1, 0, 1), -1);
            assert_eq!(errno::get(), libc::EBADF);
        }
        drop((src, dst));
        let _ = std::fs::remove_file(&sp);
        let _ = std::fs::remove_file(&dp);
    }

    #[test]
    fn process_vm_readv_writev_own_memory() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let source = *b"remote bytes";
        let mut dest = [0u8; 12];
        let local = [iovec { iov_base: dest.as_mut_ptr().cast(), iov_len: 12 }];
        let remote = [iovec { iov_base: source.as_ptr() as *mut c_void, iov_len: 12 }];
        let pid = unsafe { libc::getpid() };
        unsafe {
            let n = process_vm_readv(pid, local.as_ptr(), 1, remote.as_ptr(), 1, 0);
            let en = errno::get();
            let hn = libc::process_vm_readv(pid, local.as_ptr().cast(), 1, remote.as_ptr().cast(), 1, 0);
            assert_eq!(n, hn);
            if n == 12 {
                assert_eq!(&dest, b"remote bytes");
                let mut target = [0u8; 12];
                let wl = [iovec { iov_base: b"written!!!!!".as_ptr() as *mut c_void, iov_len: 12 }];
                let wr = [iovec { iov_base: target.as_mut_ptr().cast(), iov_len: 12 }];
                assert_eq!(process_vm_writev(pid, wl.as_ptr(), 1, wr.as_ptr(), 1, 0), 12);
                assert_eq!(&target, b"written!!!!!");
            } else {
                assert_eq!(en, *libc::__errno_location());
            }
            // bad pid
            assert_eq!(process_vm_readv(-5, local.as_ptr(), 1, remote.as_ptr(), 1, 0), -1);
            assert_eq!(errno::get(), libc::ESRCH);
        }
    }
}
