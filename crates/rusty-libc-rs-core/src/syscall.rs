//! Raw x86-64 Linux system calls: the system call numbers, the `syscall` instruction, and the `plain!` helper for calls
//! that take only integers. Raw calls (not a C library) so the face behaves the same in a glibc-hosted and in a
//! rusty-libc-hosted process; none of the calls made through here has state in the C library.

/// x86-64 system call numbers.
pub(crate) mod nr {
    pub const READ: usize = 0;
    #[cfg(feature = "libc-services")]
    pub const FSTAT: usize = 5;
    #[cfg(feature = "libc-services")]
    pub const POLL: usize = 7;
    pub const MMAP: usize = 9;
    pub const MPROTECT: usize = 10;
    pub const MUNMAP: usize = 11;
    pub const RT_SIGACTION: usize = 13;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const IOCTL: usize = 16;
    #[cfg(feature = "libc-services")]
    pub const SCHED_YIELD: usize = 24;
    pub const DUP2: usize = 33;
    pub const GETPID: usize = 39;
    #[cfg(feature = "std")]
    pub const SENDMSG: usize = 46;
    #[cfg(feature = "std")]
    pub const RECVMSG: usize = 47;
    #[cfg(test)]
    #[cfg(feature = "std")]
    pub const SETSOCKOPT: usize = 54;
    pub const GETSOCKOPT: usize = 55;
    pub const CLONE: usize = 56;
    pub const EXECVE: usize = 59;
    pub const EXIT: usize = 60;
    pub const KILL: usize = 62;
    pub const FCNTL: usize = 72;
    pub const CHDIR: usize = 80;
    pub const GETRUSAGE: usize = 98;
    pub const GETUID: usize = 102;
    pub const GETGID: usize = 104;
    pub const GETEUID: usize = 107;
    pub const GETEGID: usize = 108;
    pub const SETPGID: usize = 109;
    pub const GETPPID: usize = 110;
    pub const GETPGRP: usize = 111;
    pub const SETSID: usize = 112;
    pub const GETPGID: usize = 121;
    pub const GETSID: usize = 124;
    pub const EXIT_GROUP: usize = 231;
    pub const WAITID: usize = 247;
    pub const PIDFD_SEND_SIGNAL: usize = 424;
    pub const CLONE3: usize = 435;
    pub const CLOSE: usize = 3;
    pub const GETITIMER: usize = 36;
    pub const SETITIMER: usize = 38;
    pub const RT_SIGTIMEDWAIT: usize = 128;
    #[cfg(feature = "std")]
    pub const FSTATFS: usize = 138;
    pub const SCHED_GETPARAM: usize = 143;
    pub const SCHED_GETSCHEDULER: usize = 145;
    pub const GETTID: usize = 186;
    pub const SCHED_GETAFFINITY: usize = 204;
    pub const TIMER_CREATE: usize = 222;
    pub const TIMER_SETTIME: usize = 223;
    pub const TIMER_GETTIME: usize = 224;
    pub const TIMER_GETOVERRUN: usize = 225;
    pub const TIMER_DELETE: usize = 226;
    #[cfg(test)]
    pub const TGKILL: usize = 234;
    pub const OPENAT: usize = 257;
    #[cfg(feature = "std")]
    pub const FCHDIR: usize = 81;
}

/// One system call with up to six arguments; returns the raw kernel value (negative errno on failure).
///
/// # Safety
/// The call `n` with these arguments must not break memory or I/O safety: every pointer argument is valid for what the
/// kernel reads or writes through it, and descriptors it acts on are owned or borrowed by the caller.
#[inline(always)]
pub(crate) unsafe fn syscall6(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let ret: isize;
    // SAFETY: the caller's contract covers the call's effects; the `syscall` instruction itself only writes rax (the
    // result), rcx and r11 (declared), uses no stack and restores the flags from r11.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

/// `syscall6` with the unused arguments 0.
///
/// # Safety
/// As `syscall6`.
#[inline(always)]
pub(crate) unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    // SAFETY: forwarded contract; the extra zero arguments are ignored by every call made with this helper.
    unsafe { syscall6(n, a1, a2, a3, 0, 0, 0) }
}

/// Is `r` a kernel error return (-4095..=-1)?
#[inline(always)]
pub(crate) const fn is_err(r: isize) -> bool {
    r < 0 && r >= -4095
}

/// A system call that takes no pointer and acts on no descriptor (ids, process groups, sessions, exit): `plain!(nr::X, a, b)`.
/// Only for calls whose arguments are all plain integers; the call number is spelled at the call site.
macro_rules! plain {
    ($n:expr $(, $a:expr)*) => {{
        let args: [usize; 3] = plain!(@pad $($a),*);
        // SAFETY: the call takes only plain integer arguments (no pointers, no descriptors), so it cannot touch the
        // caller's memory or descriptors.
        unsafe { $crate::syscall::syscall3($n, args[0], args[1], args[2]) }
    }};
    (@pad) => { [0, 0, 0] };
    (@pad $a:expr) => { [$a as usize, 0, 0] };
    (@pad $a:expr, $b:expr) => { [$a as usize, $b as usize, 0] };
    (@pad $a:expr, $b:expr, $c:expr) => { [$a as usize, $b as usize, $c as usize] };
}
