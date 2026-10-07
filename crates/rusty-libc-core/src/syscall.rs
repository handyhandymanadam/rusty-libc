use core::arch::asm;

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_FSTAT: usize = 5;
pub const SYS_LSEEK: usize = 8;
pub const SYS_IOCTL: usize = 16;
pub const SYS_PIPE2: usize = 293;
pub const SYS_DUP: usize = 32;
pub const SYS_DUP3: usize = 292;
pub const SYS_ACCESS: usize = 21;
pub const SYS_STAT: usize = 4;
pub const SYS_LSTAT: usize = 6;
pub const SYS_RENAMEAT: usize = 264;
pub const SYS_RENAMEAT2: usize = 316;
pub const SYS_GETPPID: usize = 110;
pub const SYS_GETUID: usize = 102;
pub const SYS_GETEUID: usize = 107;
pub const SYS_RENAME: usize = 82;
pub const SYS_UNLINK: usize = 87;
pub const SYS_RMDIR: usize = 84;
pub const SYS_FTRUNCATE: usize = 77;
pub const SYS_FCNTL: usize = 72;
pub const SYS_DUP2: usize = 33;
pub const SYS_OPENAT: usize = 257;
pub const SYS_FORK: usize = 57;
pub const SYS_EXECVE: usize = 59;
pub const SYS_WAIT4: usize = 61;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_BRK: usize = 12;
pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGPROCMASK: usize = 14;
pub const SYS_MREMAP: usize = 25;
pub const SYS_MADVISE: usize = 28;
pub const SYS_GETPID: usize = 39;
pub const SYS_GETTID: usize = 186;
pub const SYS_TGKILL: usize = 234;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_GETRANDOM: usize = 318;

pub fn check(ret: usize) -> Result<usize, crate::Errno> {
    if ret > usize::MAX - 4095 {
        Err(crate::Errno((ret as isize).wrapping_neg() as i32))
    } else {
        Ok(ret)
    }
}

pub unsafe fn syscall0(n: usize) -> usize {
    let ret;
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall1(n: usize, a: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall3(n: usize, a: usize, b: usize, c: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall2(n: usize, a: usize, b: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall4(n: usize, a: usize, b: usize, c: usize, d: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall5(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

pub unsafe fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e, in("r9") f,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}
