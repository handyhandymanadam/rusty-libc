//! sys/mman.h: memory mappings, locking, advice, memfd, protection keys and POSIX shared memory.
//!
//! Return values follow glibc 2.43 on x86_64: `-1` with errno set (`MAP_FAILED` for the pointer
//! functions), except `posix_madvise`, which returns the error number itself.
use crate::misc::{sc, sci};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::syscall::{check, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use rusty_libc_core::{Errno, errno};
use crate::kernel::plain;

const SYS_REMAP_FILE_PAGES: usize = 216;
const SYS_MSYNC: usize = 26;
const SYS_MINCORE: usize = 27;
const SYS_MLOCK: usize = 149;
const SYS_MUNLOCK: usize = 150;
const SYS_MLOCKALL: usize = 151;
const SYS_MUNLOCKALL: usize = 152;
const SYS_UNLINK: usize = 87;
const SYS_PKEY_MPROTECT: usize = 329;
const SYS_MEMFD_CREATE: usize = 319;
const SYS_PKEY_ALLOC: usize = 330;
const SYS_PKEY_FREE: usize = 331;
const SYS_MLOCK2: usize = 325;
const SYS_PROCESS_MADVISE: usize = 440;
const SYS_PROCESS_MRELEASE: usize = 448;

pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;
pub const MREMAP_FIXED: c_int = 2;
pub const POSIX_MADV_DONTNEED: c_int = 4;

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const EISDIR: i32 = 21;
const ENAMETOOLONG: i32 = 36;
const O_NOFOLLOW: c_int = 0o400000;
const O_CLOEXEC: c_int = 0o2000000;

// ---------------------------------------------------------------- Rust API

/// Map memory; the result is the address.
///
/// # Safety
/// Same contract as mmap(2): a mapping at a fixed address replaces what is there.
pub unsafe fn mmap_r(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> Result<*mut u8, Errno> {
    // SAFETY: the caller's contract is mmap(2)'s.
    unsafe {
        check(syscall6(rusty_libc_core::syscall::SYS_MMAP, addr as usize, len, prot as usize, flags as usize, fd as usize, off as usize))
            .map(|p| p as *mut u8)
    }
}

/// # Safety
/// The range must not be in use.
pub unsafe fn munmap_r(addr: *mut u8, len: usize) -> Result<(), Errno> {
    // SAFETY: the caller's contract: nothing uses the range any more.
    unsafe { check(syscall2(rusty_libc_core::syscall::SYS_MUNMAP, addr as usize, len)).map(|_| ()) }
}

/// # Safety
/// The protection change must be sound for every user of the range.
pub unsafe fn mprotect_r(addr: *mut u8, len: usize, prot: i32) -> Result<(), Errno> {
    // SAFETY: the caller's contract: the new protection is sound for every user of the range.
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_MPROTECT, addr as usize, len, prot as usize)).map(|_| ()) }
}

/// # Safety
/// As mremap(2).
pub unsafe fn mremap_r(addr: *mut u8, old: usize, new: usize, flags: i32, new_addr: *mut u8) -> Result<*mut u8, Errno> {
    // SAFETY: the caller's contract is mremap(2)'s.
    unsafe {
        check(syscall5(rusty_libc_core::syscall::SYS_MREMAP, addr as usize, old, new, flags as usize, new_addr as usize))
            .map(|p| p as *mut u8)
    }
}

/// # Safety
/// As madvise(2): some advice (MADV_DONTNEED, MADV_FREE) discards data.
pub unsafe fn madvise_r(addr: *mut u8, len: usize, advice: i32) -> Result<(), Errno> {
    // SAFETY: the caller's contract is madvise(2)'s (discarding advice only on memory nobody needs).
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize)).map(|_| ()) }
}

// ---------------------------------------------------------------- C ABI

/// # Safety
/// As mmap(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void {
    // SAFETY: the caller's contract is mmap(2)'s (a MAP_FIXED mapping replaces what is there).
    let r = unsafe { syscall6(rusty_libc_core::syscall::SYS_MMAP, addr as usize, len, prot as usize, flags as usize, fd as usize, off as usize) };
    match check(r) {
        Ok(p) => p as *mut c_void,
        Err(Errno(e)) => {
            errno::set(e);
            MAP_FAILED
        }
    }
}

crate::unistd::alias!(
    /// # Safety
    /// As mmap(2).
    mmap64 => mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void
);

/// # Safety
/// As munmap(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(rusty_libc_core::syscall::SYS_MUNMAP, addr as usize, len)) }
}

/// # Safety
/// As mprotect(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(rusty_libc_core::syscall::SYS_MPROTECT, addr as usize, len, prot as usize)) }
}

/// `mremap(old, old_len, new_len, flags, ...)`: the fifth argument (new address) is read only
/// with MREMAP_FIXED, as in glibc.
///
/// # Safety
/// As mremap(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mremap(addr: *mut c_void, old: usize, new: usize, flags: c_int, mut args: ...) -> *mut c_void {
    // glibc: unknown flag bits fail at once; the fifth argument is read with MREMAP_FIXED or MREMAP_DONTUNMAP
    if flags & !(1 | MREMAP_FIXED | 4) != 0 {
        errno::set(22);
        return MAP_FAILED;
    }
    let new_addr = if flags & (MREMAP_FIXED | 4) != 0 {
        // SAFETY: with these flags the caller passes the new address as a fifth argument (contract).
        unsafe { args.next_arg::<*mut c_void>() }
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: the caller's contract is mremap(2)'s.
    let r = unsafe { syscall5(rusty_libc_core::syscall::SYS_MREMAP, addr as usize, old, new, flags as usize, new_addr as usize) };
    match check(r) {
        Ok(p) => p as *mut c_void,
        Err(Errno(e)) => {
            errno::set(e);
            MAP_FAILED
        }
    }
}

/// # Safety
/// As madvise(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize)) }
}

/// Returns the error number (0 on success), never sets errno. POSIX_MADV_DONTNEED is ignored,
/// like glibc (the kernel's MADV_DONTNEED would discard data).
///
/// # Safety
/// As madvise(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    if advice == POSIX_MADV_DONTNEED {
        return 0;
    }
    // SAFETY: the caller's contract is madvise(2)'s (POSIX_MADV_DONTNEED, the one that would discard data, was taken out).
    match check(unsafe { syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize) }) {
        Ok(_) => 0,
        Err(Errno(e)) => e,
    }
}

/// # Safety
/// As mlock(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mlock(addr: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_MLOCK, addr as usize, len)) }
}

/// mseal(2): make a mapping immutable (Linux 6.10 and later; ENOSYS before).
///
/// # Safety
/// As mseal(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mseal(addr: *mut c_void, len: usize, flags: core::ffi::c_ulong) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(462, addr as usize, len, flags as usize)) }
}

/// # Safety
/// As mlock2(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mlock2(addr: *const c_void, len: usize, flags: c_uint) -> c_int {
    // as glibc 2.43 (sysdeps/unix/sysv/linux/mlock2.c, kernel 4.4 not assumed): no flags is the mlock call; with flags,
    // mlock2, and a kernel without it reports EINVAL (an unsupported flag)
    if flags == 0 {
        // SAFETY: locking pages changes no memory; the kernel checks the range (ENOMEM).
        return sci(unsafe { syscall2(SYS_MLOCK, addr as usize, len) });
    }
    // SAFETY: as above.
    let r = unsafe { syscall3(SYS_MLOCK2, addr as usize, len, flags as usize) };
    if r == (-38isize) as usize {
        return sci((-22isize) as usize);
    }
    sci(r)
}

/// # Safety
/// As munlock(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn munlock(addr: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_MUNLOCK, addr as usize, len)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mlockall(flags: c_int) -> c_int {
    sci(plain!(SYS_MLOCKALL, flags as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn munlockall() -> c_int {
    sci(plain!(SYS_MUNLOCKALL))
}

/// # Safety
/// As msync(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn msync(addr: *mut c_void, len: usize, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_MSYNC, addr as usize, len, flags as usize, 0, 0, 0)) }
}

/// # Safety
/// `vec` must have one byte per page of the range.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall3(SYS_MINCORE, addr as usize, len, vec as usize)) }
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall2(SYS_MEMFD_CREATE, name as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_alloc(flags: c_uint, access_restrictions: c_uint) -> c_int {
    sci(plain!(SYS_PKEY_ALLOC, flags as usize, access_restrictions as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_free(key: c_int) -> c_int {
    sci(plain!(SYS_PKEY_FREE, key as usize))
}

/// # Safety
/// As pkey_mprotect(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_mprotect(addr: *mut c_void, len: usize, prot: c_int, key: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall4(SYS_PKEY_MPROTECT, addr as usize, len, prot as usize, key as usize)) }
}

#[inline]
fn rdpkru() -> u32 {
    let r: u32;
    // SAFETY: RDPKRU (with ECX = 0) only reads the PKRU register; the caller's CPU has protection keys (as for glibc's
    // pkey_get, an invalid-opcode fault otherwise).
    unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xee", inlateout("eax") 0u32 => r, in("ecx") 0u32, out("edx") _, options(nomem, nostack)) };
    r
}

#[inline]
unsafe fn wrpkru(v: u32) {
    // SAFETY: WRPKRU with ECX = EDX = 0 writes the PKRU register; the caller vouches that the new access rights do not take
    // away memory the program still uses.
    unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xef", in("eax") v, in("ecx") 0u32, in("edx") 0u32, options(nomem, nostack)) };
}

/// Reads the PKRU register (the CPU must have protection keys, as for glibc).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_get(key: c_int) -> c_int {
    if !(0..=15).contains(&key) {
        errno::set(EINVAL);
        return -1;
    }
    ((rdpkru() >> (2 * key)) & 3) as c_int
}

/// Writes the PKRU register.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_set(key: c_int, rights: c_uint) -> c_int {
    if !(0..=15).contains(&key) || rights > 3 {
        errno::set(EINVAL);
        return -1;
    }
    let mask = 3u32 << (2 * key);
    // SAFETY: what the program asked for, as glibc's pkey_set: the rights of one key change, the others stay.
    unsafe { wrpkru((rdpkru() & !mask) | (rights << (2 * key))) };
    0
}

/// # Safety
/// `iov` points to `n` iovecs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_madvise(pidfd: c_int, iov: *const crate::uio::iovec, n: usize, advice: c_int, flags: c_uint) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sc(syscall5(SYS_PROCESS_MADVISE, pidfd as usize, iov as usize, n, advice as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn process_mrelease(pidfd: c_int, flags: c_uint) -> c_int {
    // SAFETY: values only; the kernel reclaims memory of a process that is already being killed (never the caller: it is
    // running), so no memory of ours goes away.
    unsafe { sci(syscall2(SYS_PROCESS_MRELEASE, pidfd as usize, flags as usize)) }
}

/// # Safety
/// As remap_file_pages(2) (the kernel emulates it).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remap_file_pages(addr: *mut c_void, size: usize, prot: c_int, pgoff: usize, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    unsafe { sci(syscall5(SYS_REMAP_FILE_PAGES, addr as usize, size, prot as usize, pgoff, flags as usize)) }
}

// ---------------------------------------------------------------- POSIX shared memory

const SHMDIR: &[u8] = b"/dev/shm/";
const NAME_MAX: usize = 255;

/// Build "/dev/shm/<name>" (leading slashes of `name` dropped). EINVAL for an empty name or a
/// slash inside, ENAMETOOLONG above NAME_MAX, as glibc does.
fn shm_path(name: &[u8], out: &mut [u8; 9 + NAME_MAX + 1]) -> Result<(), i32> {
    let mut s = name;
    while let [b'/', rest @ ..] = s {
        s = rest;
    }
    let n = s.len();
    out[..9].copy_from_slice(SHMDIR);
    if n == 0 || s.contains(&b'/') {
        return Err(EINVAL);
    }
    if n > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    out[9..9 + n].copy_from_slice(s);
    out[9 + n] = 0;
    Ok(())
}

/// Open a POSIX shared memory object (a file in /dev/shm, close-on-exec, no symlink following).
///
/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int {
    let mut buf = [0u8; 9 + NAME_MAX + 1];
    // SAFETY: `name` is a C string (contract).
    if let Err(e) = shm_path(unsafe { rusty_libc_core::ffi::cstr_bytes(name) }, &mut buf) {
        errno::set(e);
        return -1;
    }
    // SAFETY: shm_path stored a NUL-terminated path in the local `buf`, which the kernel only reads.
    let r = sci(unsafe { rusty_libc_core::syscall::sys_open(buf.as_ptr() as usize, (oflag | O_NOFOLLOW | O_CLOEXEC) as usize, mode as usize) });
    if r == -1 && errno::get() == EISDIR {
        errno::set(EINVAL);
    }
    r
}

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    let mut buf = [0u8; 9 + NAME_MAX + 1];
    // SAFETY: `name` is a C string (contract).
    if shm_path(unsafe { rusty_libc_core::ffi::cstr_bytes(name) }, &mut buf).is_err() {
        errno::set(ENOENT);
        return -1;
    }
    // SAFETY: shm_path stored a NUL-terminated path in the local `buf`, which the kernel only reads.
    let r = sci(unsafe { syscall1(SYS_UNLINK, buf.as_ptr() as usize) });
    if r < 0 && errno::get() == EPERM {
        errno::set(EACCES);
    }
    r
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;
    use std::ffi::CString;
    use std::io::Write;

    const PROT_READ: c_int = 1;
    const PROT_WRITE: c_int = 2;
    const PROT_NONE: c_int = 0;
    const MAP_SHARED: c_int = 1;
    const MAP_PRIVATE: c_int = 2;
    const MAP_ANONYMOUS: c_int = 0x20;
    const MREMAP_MAYMOVE: c_int = 1;
    const MS_SYNC: c_int = 4;
    const MADV_DONTNEED: c_int = 4;
    const MADV_NORMAL: c_int = 0;
    const POSIX_MADV_WILLNEED: c_int = 3;
    const PAGE: usize = 4096;

    fn last_errno() -> i32 {
        errno::get()
    }

    #[test]
    fn anon_map_protect_unmap() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let p = mmap(core::ptr::null_mut(), 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert_ne!(p, MAP_FAILED);
            let b = p as *mut u8;
            for i in 0..3 * PAGE {
                assert_eq!(*b.add(i), 0);
            }
            *b = 7;
            assert_eq!(mprotect(p, PAGE, PROT_READ), 0);
            assert_eq!(*b, 7);
            assert_eq!(mprotect(p, PAGE, PROT_NONE), 0);
            assert_eq!(mprotect(p, PAGE, PROT_READ | PROT_WRITE), 0);
            // unaligned address: EINVAL like the host
            assert_eq!(mprotect(b.add(1).cast(), PAGE, PROT_READ), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            assert_eq!(libc::mprotect(b.add(1).cast(), PAGE, PROT_READ), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
            // madvise: DONTNEED zeroes an anonymous private page
            assert_eq!(madvise(p, PAGE, MADV_DONTNEED), 0);
            assert_eq!(*b, 0);
            assert_eq!(madvise(p, PAGE, 9999), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            // posix_madvise returns the error number and leaves errno alone
            errno::set(0);
            assert_eq!(posix_madvise(p, PAGE, POSIX_MADV_WILLNEED), 0);
            assert_eq!(posix_madvise(p, PAGE, 9999), libc::EINVAL);
            assert_eq!(last_errno(), 0);
            assert_eq!(posix_madvise(core::ptr::null_mut(), 1, POSIX_MADV_DONTNEED), 0);
            assert_eq!(madvise(p, PAGE, MADV_NORMAL), 0);
            assert_eq!(munmap(p, 3 * PAGE), 0);
            assert_eq!(munmap(b.add(1).cast(), PAGE), -1);
            assert_eq!(last_errno(), libc::EINVAL);
        }
    }

    #[test]
    fn mmap_errors_match_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            // length 0
            let a = mmap(core::ptr::null_mut(), 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            let ea = last_errno();
            let h = libc::mmap(core::ptr::null_mut(), 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert_eq!(a, MAP_FAILED);
            assert_eq!(h, libc::MAP_FAILED);
            assert_eq!(ea, *libc::__errno_location());
            // bad fd
            let a = mmap(core::ptr::null_mut(), PAGE, PROT_READ, MAP_PRIVATE, 9999, 0);
            let ea = last_errno();
            let h = libc::mmap(core::ptr::null_mut(), PAGE, PROT_READ, MAP_PRIVATE, 9999, 0);
            assert_eq!((a, ea), (MAP_FAILED, *libc::__errno_location()));
            assert_eq!(h, libc::MAP_FAILED);
            // unaligned file offset
            let a = mmap(core::ptr::null_mut(), PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 5);
            assert_eq!(a, MAP_FAILED);
            assert_eq!(last_errno(), libc::EINVAL);
            // Rust API
            let e = mmap_r(core::ptr::null_mut(), 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert_eq!(e, Err(Errno(libc::EINVAL)));
        }
    }

    #[test]
    fn file_map_msync_mincore() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut path = std::env::temp_dir();
        path.push(format!("libc-sys-mman-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let data: Vec<u8> = (0..2 * PAGE).map(|i| (i % 251) as u8).collect();
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();
        unsafe {
            let p = mmap64(core::ptr::null_mut(), 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            assert_ne!(p, MAP_FAILED);
            let s = core::slice::from_raw_parts_mut(p as *mut u8, 2 * PAGE);
            assert_eq!(&s[..], &data[..]);
            // resident pages: both pages were just written, so they are in the page cache
            let mut vec = [0u8; 2];
            assert_eq!(mincore(p, 2 * PAGE, vec.as_mut_ptr()), 0);
            let mut hv = [0u8; 2];
            assert_eq!(libc::mincore(p, 2 * PAGE, hv.as_mut_ptr().cast()), 0);
            assert_eq!(vec[0] & 1, 1);
            assert_eq!(vec[0] & 1, hv[0] & 1);
            // write through the map, sync, read back through the file
            s[10] = 0xAB;
            assert_eq!(msync(p, 2 * PAGE, MS_SYNC), 0);
            let back = std::fs::read(&path).unwrap();
            assert_eq!(back[10], 0xAB);
            // mlock/munlock may fail under a low RLIMIT_MEMLOCK: the host must agree
            let ml = mlock(p, PAGE);
            let hl = libc::mlock(p, PAGE);
            assert_eq!(ml == 0, hl == 0);
            if ml == 0 {
                assert_eq!(munlock(p, PAGE), 0);
                libc::munlock(p, PAGE);
            }
            // msync with conflicting flags: EINVAL
            assert_eq!(msync(p, PAGE, 1 | 4), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            // grow the mapping with mremap (variadic: no fifth argument without MREMAP_FIXED)
            let q = mremap(p, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE);
            assert_ne!(q, MAP_FAILED);
            assert_eq!(*(q as *const u8).add(10), 0xAB);
            // shrink and check the data stays
            let r = mremap(q, 4 * PAGE, PAGE, 0);
            assert_eq!(r, q);
            assert_eq!(*(r as *const u8).add(10), 0xAB);
            assert_eq!(munmap(r, PAGE), 0);
            // MREMAP_FIXED reads the fifth argument
            let a1 = mmap(core::ptr::null_mut(), PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            let target = mmap(core::ptr::null_mut(), PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            *(a1 as *mut u8) = 42;
            let moved = mremap(a1, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, target);
            assert_eq!(moved, target);
            assert_eq!(*(moved as *const u8), 42);
            assert_eq!(munmap(moved, PAGE), 0);
            // bad old address
            assert_eq!(mremap(b"x".as_ptr() as *mut c_void, PAGE, PAGE, 0), MAP_FAILED);
            assert_eq!(last_errno(), libc::EINVAL);
        }
        drop(f);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn memfd_and_pkeys() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let name = CString::new("libc-sys-test").unwrap();
            let fd = memfd_create(name.as_ptr(), 0);
            assert!(fd >= 0);
            assert_eq!(libc::write(fd, b"abc".as_ptr().cast(), 3), 3);
            let mut st: libc::stat = core::mem::zeroed();
            assert_eq!(libc::fstat(fd, &mut st), 0);
            assert_eq!(st.st_size, 3);
            libc::close(fd);
            assert_eq!(memfd_create(name.as_ptr(), 0xffff_ffff), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            // protection keys: only the argument checks and the syscalls (the PKRU register
            // instructions fault on CPUs without the feature)
            assert_eq!(pkey_get(16), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            assert_eq!(pkey_set(-1, 0), -1);
            assert_eq!(pkey_set(0, 4), -1);
            assert_eq!(pkey_free(99), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            let k = pkey_alloc(0, 0);
            let hk = libc::syscall(330, 0, 0) as c_int;
            assert_eq!(k >= 0, hk >= 0);
            if k >= 0 {
                assert_eq!(pkey_free(k), 0);
                libc::syscall(331, hk);
            }
            let p = mmap(core::ptr::null_mut(), PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert_eq!(pkey_mprotect(p, PAGE, PROT_READ, 99), -1);
            munmap(p, PAGE);
            assert_eq!(mlockall(0), -1);
            assert_eq!(last_errno(), libc::EINVAL);
            assert_eq!(process_mrelease(-1, 0), -1);
            assert_eq!(remap_file_pages(core::ptr::null_mut(), 0, 0, 0, 0), -1);
        }
    }

    #[test]
    fn shm_open_unlink_like_glibc() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !std::path::Path::new("/dev/shm").is_dir() {
            return;
        }
        unsafe {
            let n = CString::new(format!("/libc-sys-shm-{}", std::process::id())).unwrap();
            let fd = shm_open(n.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600);
            assert!(fd >= 0, "errno {}", last_errno());
            // the object is the file /dev/shm/<name>, opened close-on-exec
            let fl = libc::fcntl(fd, libc::F_GETFD);
            assert_eq!(fl & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
            assert!(std::path::Path::new(&format!("/dev/shm/libc-sys-shm-{}", std::process::id())).exists());
            // the host sees it too
            let hfd = libc::shm_open(n.as_ptr(), libc::O_RDONLY, 0);
            assert!(hfd >= 0);
            libc::close(hfd);
            // O_EXCL again: EEXIST
            assert_eq!(shm_open(n.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600), -1);
            assert_eq!(last_errno(), libc::EEXIST);
            libc::close(fd);
            assert_eq!(shm_unlink(n.as_ptr()), 0);
            assert_eq!(shm_unlink(n.as_ptr()), -1);
            assert_eq!(last_errno(), libc::ENOENT);
            // empty name, only slashes, slash inside, "." and ".." (a directory opened for writing gives EINVAL)
            for name in ["", "/", "a/b", ".", ".."] {
                let c = CString::new(name).unwrap();
                errno::set(0);
                assert_eq!(shm_open(c.as_ptr(), libc::O_RDWR, 0), -1, "{name:?}");
                let ours = last_errno();
                assert_eq!(libc::shm_open(c.as_ptr(), libc::O_RDWR, 0), -1);
                assert_eq!(ours, *libc::__errno_location(), "errno for {name:?}");
                assert_eq!(ours, libc::EINVAL, "{name:?}");
            }
            let long = CString::new("x".repeat(300)).unwrap();
            assert_eq!(shm_open(long.as_ptr(), libc::O_RDONLY, 0), -1);
            assert_eq!(last_errno(), libc::ENAMETOOLONG);
            assert_eq!(libc::shm_open(long.as_ptr(), libc::O_RDONLY, 0), -1);
            assert_eq!(*libc::__errno_location(), libc::ENAMETOOLONG);
            // shm_unlink of a bad name is ENOENT
            let c = CString::new("a/b").unwrap();
            assert_eq!(shm_unlink(c.as_ptr()), -1);
            assert_eq!(last_errno(), libc::ENOENT);
        }
    }
}
