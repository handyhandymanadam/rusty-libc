#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::arch::asm;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicUsize;

pub const SYS_READ: usize = 0;
pub const SYS_WRITEV: usize = 20;
pub const SYS_CLOSE: usize = 3;
pub const SYS_FSTAT: usize = 5;
pub const SYS_FCNTL: usize = 72;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_MADVISE: usize = 28;
pub const SYS_PREAD64: usize = 17;
pub const SYS_ACCESS: usize = 21;
pub const SYS_GETPID: usize = 39;
pub const SYS_READLINKAT: usize = 267;
pub const SYS_SET_TID_ADDRESS: usize = 218;
pub const SYS_SET_ROBUST_LIST: usize = 273;
pub const SYS_ARCH_PRCTL: usize = 158;
pub const SYS_GETTID: usize = 186;
pub const SYS_FUTEX: usize = 202;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_OPENAT: usize = 257;
pub const SYS_FTRUNCATE: usize = 77;

pub const PROT_NONE: usize = 0;
pub const PROT_READ: usize = 1;
pub const PROT_WRITE: usize = 2;
pub const PROT_EXEC: usize = 4;
pub const MAP_PRIVATE: usize = 2;
pub const MAP_FIXED: usize = 0x10;
pub const MAP_ANONYMOUS: usize = 0x20;
pub const MAP_FIXED_NOREPLACE: usize = 0x100000;
pub const AT_FDCWD: isize = -100;
pub const O_RDONLY: usize = 0;
pub const O_CLOEXEC: usize = 0o2000000;
pub const ARCH_SET_FS: usize = 0x1002;
pub const PAGE: usize = 4096;

#[inline(always)]
pub unsafe fn syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", inlateout("rax") nr as isize => ret, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    unsafe { syscall6(nr, a1, a2, a3, 0, 0, 0) }
}

pub fn exit(code: i32) -> ! {
    loop {
        unsafe { syscall3(SYS_EXIT_GROUP, code as usize, 0, 0) };
    }
}

pub fn getpid() -> isize {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) }
}

pub fn write(fd: i32, buf: &[u8]) -> isize {
    let iov = [buf.as_ptr() as usize, buf.len()];
    unsafe { syscall3(SYS_WRITEV, fd as usize, iov.as_ptr() as usize, 1) }
}

pub fn open(path: &CStr) -> isize {
    openat(path, O_RDONLY | O_CLOEXEC, 0)
}

pub fn openat(path: &CStr, flags: usize, mode: usize) -> isize {
    unsafe { syscall6(SYS_OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, flags, mode, 0, 0) }
}

pub fn close(fd: isize) {
    unsafe { syscall3(SYS_CLOSE, fd as usize, 0, 0) };
}

pub fn pread(fd: isize, buf: &mut [MaybeUninit<u8>], off: usize) -> isize {
    unsafe { syscall6(SYS_PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), off, 0, 0) }
}

pub fn ftruncate(fd: isize, len: usize) -> isize {
    unsafe { syscall3(SYS_FTRUNCATE, fd as usize, len, 0) }
}

pub fn mmap_new(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, off: usize) -> isize {
    if flags & MAP_FIXED != 0 {
        return -22;
    }
    unsafe { syscall6(SYS_MMAP, addr, len, prot, flags, fd as usize, off) }
}

pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, off: usize) -> isize {
    unsafe { syscall6(SYS_MMAP, addr, len, prot, flags, fd as usize, off) }
}

pub unsafe fn munmap(addr: usize, len: usize) -> isize {
    unsafe { syscall3(SYS_MUNMAP, addr, len, 0) }
}

pub unsafe fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    unsafe { syscall3(SYS_MPROTECT, addr, len, prot) }
}

fn fcntl_getfd(fd: usize) -> isize {
    unsafe { syscall3(SYS_FCNTL, fd, 1 , 0) }
}

pub fn fstat(fd: isize, st: &mut [u64; 18]) -> isize {
    unsafe { syscall3(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize, 0) }
}

pub fn check_standard_fds() {
    const EBADF: isize = 9;
    const O_WRONLY: usize = 1;
    const O_NOFOLLOW: usize = 0o400000;
    let fds: [(usize, &CStr, usize, u64); 3] = [
        (0, c"/dev/full", O_WRONLY | O_NOFOLLOW, (1 << 8) | 7),
        (1, c"/dev/null", O_RDONLY | O_NOFOLLOW, (1 << 8) | 3),
        (2, c"/dev/null", O_RDONLY | O_NOFOLLOW, (1 << 8) | 3),
    ];
    for (fd, path, mode, dev) in fds {
        if fcntl_getfd(fd) != -EBADF {
            continue;
        }
        let got = openat(path, mode, 0);
        let mut st = [0u64; 18];
        let ok = got == fd as isize && fstat(fd as isize, &mut st) == 0 && (st[3] as u32) & 0o170000 == 0o020000 && st[5] == dev;
        if !ok {
            loop {
                unsafe { asm!("hlt", options(nomem, nostack)) };
            }
        }
    }
}

pub fn fstat_mode(fd: isize) -> u32 {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return 0;
    }
    st[3] as u32
}

pub fn fstat_id(fd: isize) -> (u64, u64) {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return (0, 0);
    }
    (st[0], st[1])
}

pub fn fstat_size(fd: isize) -> usize {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return 0;
    }
    st[6] as usize
}

pub fn readlink(path: &CStr, buf: &mut [MaybeUninit<u8>]) -> isize {
    unsafe { syscall6(SYS_READLINKAT, AT_FDCWD as usize, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0) }
}

pub fn access_read(path: &CStr) -> isize {
    unsafe { syscall3(SYS_ACCESS, path.as_ptr() as usize, 4 , 0) }
}

pub fn futex_wait(word: &AtomicUsize, val: u32) {
    unsafe { syscall6(SYS_FUTEX, word.as_ptr() as usize, 128, val as usize, 0, 0, 0) };
}

pub fn futex_wake(word: &AtomicUsize, n: usize) {
    unsafe { syscall6(SYS_FUTEX, word.as_ptr() as usize, 129, n, 0, 0, 0) };
}

pub unsafe fn set_tid_address(tidptr: usize) -> i32 {
    unsafe { syscall3(SYS_SET_TID_ADDRESS, tidptr, 0, 0) as i32 }
}

pub unsafe fn robust_register(tp: usize) {
    let head = tp + 0x2e0;
    unsafe { *((tp + 0x2d8) as *mut usize) = head };
    unsafe { *(head as *mut usize) = head };
    unsafe { *((head + 8) as *mut isize) = -32 };
    unsafe { *((head + 16) as *mut usize) = 0 };
    unsafe { syscall3(SYS_SET_ROBUST_LIST, head, 24, 0) };
}

pub unsafe fn set_fs(tp: usize) -> isize {
    unsafe { syscall3(SYS_ARCH_PRCTL, ARCH_SET_FS, tp, 0) }
}

#[inline(always)]
pub fn thread_pointer() -> usize {
    let p: usize;
    unsafe { asm!("mov {}, fs:0", out(reg) p, options(nostack, readonly, preserves_flags)) };
    p
}
