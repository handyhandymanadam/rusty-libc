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
    pub const OPENAT: usize = 257;
    #[cfg(feature = "std")]
    pub const FCHDIR: usize = 81;
}

#[inline(always)]
pub(crate) unsafe fn syscall6(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let ret: isize;
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

#[inline(always)]
pub(crate) unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    unsafe { syscall6(n, a1, a2, a3, 0, 0, 0) }
}

#[inline(always)]
pub(crate) const fn is_err(r: isize) -> bool {
    r < 0 && r >= -4095
}

macro_rules! plain {
    ($n:expr $(, $a:expr)*) => {{
        let args: [usize; 3] = plain!(@pad $($a),*);
        unsafe { $crate::syscall::syscall3($n, args[0], args[1], args[2]) }
    }};
    (@pad) => { [0, 0, 0] };
    (@pad $a:expr) => { [$a as usize, 0, 0] };
    (@pad $a:expr, $b:expr) => { [$a as usize, $b as usize, 0] };
    (@pad $a:expr, $b:expr, $c:expr) => { [$a as usize, $b as usize, $c as usize] };
}
