use crate::misc::{sc, sci};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::syscall::{check, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6};
use rusty_libc_core::{Errno, errno};

const SYS_REMAP_FILE_PAGES: usize = 216;
const SYS_MSYNC: usize = 26;
const SYS_MINCORE: usize = 27;
const SYS_MLOCK: usize = 149;
const SYS_MUNLOCK: usize = 150;
const SYS_MLOCKALL: usize = 151;
const SYS_MUNLOCKALL: usize = 152;
const SYS_OPEN: usize = 2;
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

pub unsafe fn mmap_r(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> Result<*mut u8, Errno> {
    unsafe {
        check(syscall6(rusty_libc_core::syscall::SYS_MMAP, addr as usize, len, prot as usize, flags as usize, fd as usize, off as usize))
            .map(|p| p as *mut u8)
    }
}

pub unsafe fn munmap_r(addr: *mut u8, len: usize) -> Result<(), Errno> {
    unsafe { check(syscall2(rusty_libc_core::syscall::SYS_MUNMAP, addr as usize, len)).map(|_| ()) }
}

pub unsafe fn mprotect_r(addr: *mut u8, len: usize, prot: i32) -> Result<(), Errno> {
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_MPROTECT, addr as usize, len, prot as usize)).map(|_| ()) }
}

pub unsafe fn mremap_r(addr: *mut u8, old: usize, new: usize, flags: i32, new_addr: *mut u8) -> Result<*mut u8, Errno> {
    unsafe {
        check(syscall5(rusty_libc_core::syscall::SYS_MREMAP, addr as usize, old, new, flags as usize, new_addr as usize))
            .map(|p| p as *mut u8)
    }
}

pub unsafe fn madvise_r(addr: *mut u8, len: usize, advice: i32) -> Result<(), Errno> {
    unsafe { check(syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize)).map(|_| ()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void {
    unsafe {
        let r = syscall6(rusty_libc_core::syscall::SYS_MMAP, addr as usize, len, prot as usize, flags as usize, fd as usize, off as usize);
        match check(r) {
            Ok(p) => p as *mut c_void,
            Err(Errno(e)) => {
                errno::set(e);
                MAP_FAILED
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mmap64(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void {
    unsafe { mmap(addr, len, prot, flags, fd, off) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    unsafe { sci(syscall2(rusty_libc_core::syscall::SYS_MUNMAP, addr as usize, len)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    unsafe { sci(syscall3(rusty_libc_core::syscall::SYS_MPROTECT, addr as usize, len, prot as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mremap(addr: *mut c_void, old: usize, new: usize, flags: c_int, mut args: ...) -> *mut c_void {
    unsafe {
        if flags & !(1 | MREMAP_FIXED | 4) != 0 {
            errno::set(22);
            return MAP_FAILED;
        }
        let new_addr = if flags & (MREMAP_FIXED | 4) != 0 { args.next_arg::<*mut c_void>() } else { core::ptr::null_mut() };
        let r = syscall5(rusty_libc_core::syscall::SYS_MREMAP, addr as usize, old, new, flags as usize, new_addr as usize);
        match check(r) {
            Ok(p) => p as *mut c_void,
            Err(Errno(e)) => {
                errno::set(e);
                MAP_FAILED
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    unsafe { sci(syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn posix_madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    unsafe {
        if advice == POSIX_MADV_DONTNEED {
            return 0;
        }
        match check(syscall3(rusty_libc_core::syscall::SYS_MADVISE, addr as usize, len, advice as usize)) {
            Ok(_) => 0,
            Err(Errno(e)) => e,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mlock(addr: *const c_void, len: usize) -> c_int {
    unsafe { sci(syscall2(SYS_MLOCK, addr as usize, len)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mseal(addr: *mut c_void, len: usize, flags: core::ffi::c_ulong) -> c_int {
    unsafe { sci(syscall3(462, addr as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mlock2(addr: *const c_void, len: usize, flags: c_uint) -> c_int {
    unsafe { sci(syscall3(SYS_MLOCK2, addr as usize, len, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn munlock(addr: *const c_void, len: usize) -> c_int {
    unsafe { sci(syscall2(SYS_MUNLOCK, addr as usize, len)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mlockall(flags: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_MLOCKALL, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn munlockall() -> c_int {
    unsafe { sci(rusty_libc_core::syscall::syscall0(SYS_MUNLOCKALL)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn msync(addr: *mut c_void, len: usize, flags: c_int) -> c_int {
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_MSYNC, addr as usize, len, flags as usize, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> c_int {
    unsafe { sci(syscall3(SYS_MINCORE, addr as usize, len, vec as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_MEMFD_CREATE, name as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_alloc(flags: c_uint, access_restrictions: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_PKEY_ALLOC, flags as usize, access_restrictions as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_free(key: c_int) -> c_int {
    unsafe { sci(syscall1(SYS_PKEY_FREE, key as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_mprotect(addr: *mut c_void, len: usize, prot: c_int, key: c_int) -> c_int {
    unsafe { sci(syscall4(SYS_PKEY_MPROTECT, addr as usize, len, prot as usize, key as usize)) }
}

#[inline]
unsafe fn rdpkru() -> u32 {
    let r: u32;
    unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xee", inlateout("eax") 0u32 => r, in("ecx") 0u32, out("edx") _, options(nomem, nostack)) };
    r
}

#[inline]
unsafe fn wrpkru(v: u32) {
    unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xef", in("eax") v, in("ecx") 0u32, in("edx") 0u32, options(nomem, nostack)) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_get(key: c_int) -> c_int {
    if !(0..=15).contains(&key) {
        errno::set(EINVAL);
        return -1;
    }
    unsafe { ((rdpkru() >> (2 * key)) & 3) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pkey_set(key: c_int, rights: c_uint) -> c_int {
    if !(0..=15).contains(&key) || rights > 3 {
        errno::set(EINVAL);
        return -1;
    }
    unsafe {
        let mask = 3u32 << (2 * key);
        wrpkru((rdpkru() & !mask) | (rights << (2 * key)));
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn process_madvise(pidfd: c_int, iov: *const crate::uio::iovec, n: usize, advice: c_int, flags: c_uint) -> isize {
    unsafe { sc(syscall5(SYS_PROCESS_MADVISE, pidfd as usize, iov as usize, n, advice as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn process_mrelease(pidfd: c_int, flags: c_uint) -> c_int {
    unsafe { sci(syscall2(SYS_PROCESS_MRELEASE, pidfd as usize, flags as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remap_file_pages(addr: *mut c_void, size: usize, prot: c_int, pgoff: usize, flags: c_int) -> c_int {
    unsafe { sci(syscall5(SYS_REMAP_FILE_PAGES, addr as usize, size, prot as usize, pgoff, flags as usize)) }
}

const SHMDIR: &[u8] = b"/dev/shm/";
const NAME_MAX: usize = 255;

unsafe fn shm_path(name: *const c_char, out: &mut [u8; 9 + NAME_MAX + 1]) -> Result<(), i32> {
    unsafe {
        let mut p = name as *const u8;
        while *p == b'/' {
            p = p.add(1);
        }
        let n = rusty_libc_mem::strlen(p.cast());
        out[..9].copy_from_slice(SHMDIR);
        let s = core::slice::from_raw_parts(p, n);
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
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int {
    unsafe {
        let mut buf = [0u8; 9 + NAME_MAX + 1];
        if let Err(e) = shm_path(name, &mut buf) {
            errno::set(e);
            return -1;
        }
        let r = sci(syscall3(SYS_OPEN, buf.as_ptr() as usize, (oflag | O_NOFOLLOW | O_CLOEXEC) as usize, mode as usize));
        if r == -1 && errno::get() == EISDIR {
            errno::set(EINVAL);
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    unsafe {
        let mut buf = [0u8; 9 + NAME_MAX + 1];
        if shm_path(name, &mut buf).is_err() {
            errno::set(ENOENT);
            return -1;
        }
        let r = sci(syscall1(SYS_UNLINK, buf.as_ptr() as usize));
        if r < 0 && errno::get() == EPERM {
            errno::set(EACCES);
        }
        r
    }
}

