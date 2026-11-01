//! Raw Linux x86-64 system calls and the few wrappers the loader needs. No libc, no errno, no TLS.
//!
//! The wrappers whose arguments are plain values, buffers the kernel only reads or writes (slices) or paths (`&CStr`) are
//! safe functions; each holds its one `syscall` in an audited unsafe block. Calls that change the address space (`mmap` with
//! `MAP_FIXED`, `munmap`, `mprotect`), install the thread pointer or hand the kernel an address it keeps (`set_tid_address`,
//! the robust list) stay `unsafe fn`: their callers vouch for the memory involved.
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

/// One raw system call with six arguments; the negative errno on failure.
///
/// # Safety
/// The call with these arguments must not break memory safety: every pointer argument is valid for what the kernel does
/// with it, and the call does not unmap, remap or change the protection of memory Rust code still uses.
#[inline(always)]
pub unsafe fn syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let ret: isize;
    // SAFETY: the `syscall` instruction clobbers only rax (the result), rcx and r11, which are declared; what the kernel does
    // with the arguments is the caller's contract.
    unsafe {
        asm!("syscall", inlateout("rax") nr as isize => ret, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

/// [`syscall6`] with three arguments.
///
/// # Safety
/// As [`syscall6`].
#[inline(always)]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    // SAFETY: forwarded contract.
    unsafe { syscall6(nr, a1, a2, a3, 0, 0, 0) }
}

/// exit_group(code).
pub fn exit(code: i32) -> ! {
    loop {
        // SAFETY: exit_group takes a plain value and does not return.
        unsafe { syscall3(SYS_EXIT_GROUP, code as usize, 0, 0) };
    }
}

/// getpid().
pub fn getpid() -> isize {
    // SAFETY: no arguments.
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) }
}

/// Messages go out with writev as glibc's loader writes them (`_dl_writev` behind `_dl_printf`, `_dl_error_printf`,
/// `_dl_debug_printf`): a seccomp allowlist made from glibc's calls may have writev and not write.
pub fn write(fd: i32, buf: &[u8]) -> isize {
    let iov = [buf.as_ptr() as usize, buf.len()];
    // SAFETY: one iovec describing `buf`, which the kernel only reads; both live across the call.
    unsafe { syscall3(SYS_WRITEV, fd as usize, iov.as_ptr() as usize, 1) }
}

/// open(2) a path read-only (close-on-exec); negative errno on failure.
pub fn open(path: &CStr) -> isize {
    openat(path, O_RDONLY | O_CLOEXEC, 0)
}

/// openat(AT_FDCWD, path, flags, mode); negative errno on failure.
pub fn openat(path: &CStr, flags: usize, mode: usize) -> isize {
    // SAFETY: `path` is a NUL-terminated string the kernel only reads; the other arguments are plain values.
    unsafe { syscall6(SYS_OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, flags, mode, 0, 0) }
}

pub fn close(fd: isize) {
    // SAFETY: a plain value (closing a descriptor touches no memory).
    unsafe { syscall3(SYS_CLOSE, fd as usize, 0, 0) };
}

/// pread64 into a buffer that need not be initialised (the kernel writes at most `buf.len()` bytes); the count or a
/// negative errno.
pub fn pread(fd: isize, buf: &mut [MaybeUninit<u8>], off: usize) -> isize {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`, which is exclusively borrowed for the call.
    unsafe { syscall6(SYS_PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), off, 0, 0) }
}

/// ftruncate(fd, len).
pub fn ftruncate(fd: isize, len: usize) -> isize {
    // SAFETY: plain values.
    unsafe { syscall3(SYS_FTRUNCATE, fd as usize, len, 0) }
}

/// A new mapping that replaces nothing: without `MAP_FIXED` the address is a hint (or, with `MAP_FIXED_NOREPLACE`, a demand
/// the kernel refuses when the range is in use); the address or a negative errno. Returns -EINVAL for a `MAP_FIXED` request
/// (those go through [`mmap`]).
pub fn mmap_new(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, off: usize) -> isize {
    if flags & MAP_FIXED != 0 {
        return -22;
    }
    // SAFETY: no MAP_FIXED: the kernel puts the mapping where no existing mapping is, so no memory in use changes.
    unsafe { syscall6(SYS_MMAP, addr, len, prot, flags, fd as usize, off) }
}

/// mmap(2), any flags.
///
/// # Safety
/// With `MAP_FIXED`, the range `addr..addr+len` holds nothing Rust code still uses (it is replaced).
pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, off: usize) -> isize {
    // SAFETY: forwarded contract.
    unsafe { syscall6(SYS_MMAP, addr, len, prot, flags, fd as usize, off) }
}

/// munmap(2).
///
/// # Safety
/// Nothing in `addr..addr+len` is used after the call.
pub unsafe fn munmap(addr: usize, len: usize) -> isize {
    // SAFETY: forwarded contract.
    unsafe { syscall3(SYS_MUNMAP, addr, len, 0) }
}

/// mprotect(2).
///
/// # Safety
/// No code reads, writes or runs memory in the range in a way the new protection forbids.
pub unsafe fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    // SAFETY: forwarded contract.
    unsafe { syscall3(SYS_MPROTECT, addr, len, prot) }
}

/// fcntl(fd, F_GETFD).
fn fcntl_getfd(fd: usize) -> isize {
    // SAFETY: plain values.
    unsafe { syscall3(SYS_FCNTL, fd, 1 /* F_GETFD */, 0) }
}

/// fstat(fd) into `st` (the kernel's `struct stat`, 144 bytes); 0 or a negative errno.
pub fn fstat(fd: isize, st: &mut [u64; 18]) -> isize {
    // SAFETY: the kernel writes one `struct stat` (144 bytes, the size of `st`) into `st`, exclusively borrowed.
    unsafe { syscall3(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize, 0) }
}

/// glibc's `__libc_check_standard_fds`, run for a secure (set-user-ID) program before anything else is opened: a closed
/// descriptor 0, 1 or 2 is filled so that the program cannot write its output into a file it opens next. Descriptor 0 gets
/// /dev/full opened write-only, 1 and 2 /dev/null read-only (O_NOFOLLOW); if the result is not that device at that number,
/// the program stops at a privileged instruction (glibc's ABORT_INSTRUCTION), as nothing can be reported.
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
                // SAFETY: `hlt` touches no memory; in user mode it faults (SIGSEGV), which ends the process.
                unsafe { asm!("hlt", options(nomem, nostack)) };
            }
        }
    }
}

/// The st_mode of an open file (0 when fstat fails).
pub fn fstat_mode(fd: isize) -> u32 {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return 0;
    }
    st[3] as u32
}

/// The identity of an open file: (device, inode), used to recognise a library that is already loaded.
pub fn fstat_id(fd: isize) -> (u64, u64) {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return (0, 0);
    }
    (st[0], st[1])
}

/// Size of an open file (st_size).
pub fn fstat_size(fd: isize) -> usize {
    let mut st = [0u64; 18];
    if fstat(fd, &mut st) < 0 {
        return 0;
    }
    st[6] as usize
}

/// readlink as glibc's loader makes it (readlinkat with AT_FDCWD: _dl_get_origin, _dl_canonicalize), into a buffer that need
/// not be initialised; the length or a negative errno.
pub fn readlink(path: &CStr, buf: &mut [MaybeUninit<u8>]) -> isize {
    // SAFETY: `path` is NUL-terminated and only read; the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { syscall6(SYS_READLINKAT, AT_FDCWD as usize, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0) }
}

/// access(path, R_OK): 0 when readable.
pub fn access_read(path: &CStr) -> isize {
    // SAFETY: `path` is NUL-terminated and only read.
    unsafe { syscall3(SYS_ACCESS, path.as_ptr() as usize, 4 /* R_OK */, 0) }
}

/// futex(FUTEX_WAIT_PRIVATE) on the low 32 bits of `word` while they equal `val`.
pub fn futex_wait(word: &AtomicUsize, val: u32) {
    // SAFETY: the kernel only reads the aligned word, which lives across the call (x86-64 is little-endian: the futex is
    // its low half).
    unsafe { syscall6(SYS_FUTEX, word.as_ptr() as usize, 128, val as usize, 0, 0, 0) };
}

/// futex(FUTEX_WAKE_PRIVATE): wake up to `n` waiters on `word`.
pub fn futex_wake(word: &AtomicUsize, n: usize) {
    // SAFETY: a wake reads no memory; the address only names the queue.
    unsafe { syscall6(SYS_FUTEX, word.as_ptr() as usize, 129, n, 0, 0, 0) };
}

/// set_tid_address(tidptr): the kernel clears `*tidptr` and wakes it when the thread ends; returns the caller's thread id
/// (glibc's __tls_init_tp takes the main thread's id from it, no gettid).
///
/// # Safety
/// `tidptr` is a 4-byte word that stays valid (and is not reused for anything else) as long as the thread runs.
pub unsafe fn set_tid_address(tidptr: usize) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { syscall3(SYS_SET_TID_ADDRESS, tidptr, 0, 0) as i32 }
}

/// Start the robust mutex list of the thread whose TCB is at `tp` empty and register it with the kernel, as glibc's
/// __tls_init_tp does for the main thread. The head sits at glibc's struct pthread offsets (rusty-libc-core `Tcb`):
/// robust_prev at 0x2d8, robust_head { list, futex_offset, list_op_pending } at 0x2e0.
///
/// # Safety
/// `tp` is the thread pointer of the calling thread's TCB (writable, as long as the thread runs).
pub unsafe fn robust_register(tp: usize) {
    let head = tp + 0x2e0;
    // SAFETY: robust_prev lies inside the TCB (caller's contract), aligned.
    unsafe { *((tp + 0x2d8) as *mut usize) = head };
    // SAFETY: the list head word, inside the TCB.
    unsafe { *(head as *mut usize) = head };
    // SAFETY: futex_offset, inside the TCB.
    unsafe { *((head + 8) as *mut isize) = -32 };
    // SAFETY: list_op_pending, inside the TCB.
    unsafe { *((head + 16) as *mut usize) = 0 };
    // SAFETY: the kernel keeps the head's address; it lives as long as the thread (caller's contract).
    unsafe { syscall3(SYS_SET_ROBUST_LIST, head, 24, 0) };
}

/// arch_prctl(ARCH_SET_FS, tp): make `tp` the thread pointer.
///
/// # Safety
/// `tp` points to a TCB set up for this thread (its self pointer at 0 and the stack guard); code reading `%fs` relies on it.
pub unsafe fn set_fs(tp: usize) -> isize {
    // SAFETY: forwarded contract.
    unsafe { syscall3(SYS_ARCH_PRCTL, ARCH_SET_FS, tp, 0) }
}

/// The thread pointer (`%fs:0`). Only after `tls::setup_main_thread` (callers check `tls::ready()`).
#[inline(always)]
pub fn thread_pointer() -> usize {
    let p: usize;
    // SAFETY: reads the TCB's self pointer at %fs:0, a word of the calling thread's TCB. Before the loader installs a thread
    // pointer the %fs base is 0 and the read faults at address 0 (page 0 is never mapped: vm.mmap_min_addr), which ends the
    // process without reading any memory.
    unsafe { asm!("mov {}, fs:0", out(reg) p, options(nostack, readonly, preserves_flags)) };
    p
}
