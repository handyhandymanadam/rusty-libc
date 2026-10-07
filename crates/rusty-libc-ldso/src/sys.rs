use core::arch::asm;

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_CLOSE: usize = 3;
pub const SYS_FSTAT: usize = 5;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_MADVISE: usize = 28;
pub const SYS_PREAD64: usize = 17;
pub const SYS_ACCESS: usize = 21;
pub const SYS_GETPID: usize = 39;
pub const SYS_READLINK: usize = 89;
pub const SYS_ARCH_PRCTL: usize = 158;
pub const SYS_GETTID: usize = 186;
pub const SYS_FUTEX: usize = 202;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_OPENAT: usize = 257;

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

pub fn write(fd: i32, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) }
}

pub unsafe fn open(path: *const u8) -> isize {
    unsafe { syscall6(SYS_OPENAT, AT_FDCWD as usize, path as usize, O_RDONLY | O_CLOEXEC, 0, 0, 0) }
}

pub fn close(fd: isize) {
    unsafe { syscall3(SYS_CLOSE, fd as usize, 0, 0) };
}

pub unsafe fn pread(fd: isize, buf: *mut u8, len: usize, off: usize) -> isize {
    unsafe { syscall6(SYS_PREAD64, fd as usize, buf as usize, len, off, 0, 0) }
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

pub unsafe fn fstat_id(fd: isize) -> (u64, u64) {
    let mut st = [0u64; 18];
    unsafe {
        if syscall3(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize, 0) < 0 {
            return (0, 0);
        }
    }
    (st[0], st[1])
}

pub unsafe fn fstat_size(fd: isize) -> usize {
    let mut st = [0u64; 18];
    unsafe {
        if syscall3(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize, 0) < 0 {
            return 0;
        }
    }
    st[6] as usize
}

pub unsafe fn readlink(path: *const u8, buf: *mut u8, len: usize) -> isize {
    unsafe { syscall3(SYS_READLINK, path as usize, buf as usize, len) }
}

pub fn gettid() -> i32 {
    unsafe { syscall3(SYS_GETTID, 0, 0, 0) as i32 }
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
