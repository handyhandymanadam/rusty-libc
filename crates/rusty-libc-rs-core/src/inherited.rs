//! Adopting descriptors the process inherited at exec (feature `libc-services`): a startup snapshot and a claim-once
//! [`take_inherited`]. For a shell's `3>file` / `--inherit-fd N` style use: the program gets an `OwnedRawFd` for a number
//! its parent left open, without opening a new file description (so sockets work and the offset stays shared, which
//! `/proc/self/fd/N` reopening cannot give).
//!
//! # The snapshot
//!
//! An `.init_array` entry of this crate runs before `main` (after the C library's start-up and the constructors of the
//! shared libraries loaded at start). It records, for every descriptor number below [`LIMIT`] that is open at that
//! moment, the file's identity (fstat `st_dev`, `st_ino`). It runs only when this crate is part of the main program
//! (its own address lies in a PT_LOAD segment of the executable that the C library's `getauxval(AT_PHDR)` describes):
//! in a library loaded later with dlopen, or a program without PT_PHDR, no snapshot is taken and every
//! [`take_inherited`] returns `None` (the program's own descriptors are open by then and owned by its code).
//! Open descriptors are found with poll(2) (POLLNVAL marks closed numbers; 128 per call), with fcntl(F_GETFD) per
//! number as the fallback when poll refuses (RLIMIT_NOFILE below 128).

use crate::fd::OwnedRawFd;
use crate::syscall::{nr, syscall3};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};

/// Descriptor numbers at or above this are never adopted (`take_inherited` returns `None`).
pub const LIMIT: usize = 1024;
const WORDS: usize = LIMIT / 64;

/// Bit `fd % 64` of word `fd / 64`: open when the snapshot was taken.
static OPEN: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
/// Bit set once a `take_inherited` for that number has started (successful or not): never again.
static TAKEN: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
/// fstat identity at snapshot time.
static DEV: [AtomicU64; LIMIT] = [const { AtomicU64::new(0) }; LIMIT];
static INO: [AtomicU64; LIMIT] = [const { AtomicU64::new(0) }; LIMIT];
static SNAPSHOT: AtomicBool = AtomicBool::new(false);

#[used]
// SAFETY: a function pointer in .init_array is called once by the C library's start-up code (glibc and rusty-libc
// pass argc, argv, envp, which an `extern "C" fn()` ignores); `snapshot` needs nothing initialised but the C library.
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = snapshot;

unsafe extern "C" {
    fn getauxval(kind: u64) -> u64;
}

/// ELF64 program header.
#[repr(C)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;

/// Is this crate's code part of the main executable?
fn in_main_executable() -> bool {
    // SAFETY: getauxval only reads the auxiliary vector the C library keeps (0 when the entry is missing).
    let phdr = unsafe { getauxval(AT_PHDR) } as usize;
    // SAFETY: as above.
    let phnum = unsafe { getauxval(AT_PHNUM) } as usize;
    if phdr == 0 || phnum == 0 || phnum > 4096 || !phdr.is_multiple_of(core::mem::align_of::<Phdr>()) {
        return false;
    }
    // SAFETY: AT_PHDR/AT_PHNUM describe the main program's program header table, which is part of its loaded image
    // (mapped read-only for the life of the process; the C library adjusts them when ld.so was run as a command).
    let phdrs = unsafe { core::slice::from_raw_parts(phdr as *const Phdr, phnum) };
    let Some(pt_phdr) = phdrs.iter().find(|p| p.p_type == PT_PHDR) else { return false };
    let bias = (phdr as u64).wrapping_sub(pt_phdr.p_vaddr);
    let me = &raw const OPEN as u64;
    phdrs.iter().any(|p| p.p_type == PT_LOAD && me.wrapping_sub(bias.wrapping_add(p.p_vaddr)) < p.p_memsz)
}

/// fstat(fd): (st_dev, st_ino), or None when `fd` is not open.
fn identity(fd: usize) -> Option<(u64, u64)> {
    let mut st = [0u64; 18]; // struct stat (144 bytes): st_dev at 0, st_ino at 8
    // SAFETY: fstat writes one 144-byte `struct stat` into the local buffer; it only reads the descriptor's metadata,
    // whoever owns the number.
    let r = unsafe { syscall3(nr::FSTAT, fd, st.as_mut_ptr() as usize, 0) };
    if crate::syscall::is_err(r) { None } else { Some((st[0], st[1])) }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const POLLNVAL: i16 = 0x20;
const CHUNK: usize = 128;

extern "C" fn snapshot() {
    if !in_main_executable() {
        return;
    }
    for base in (0..LIMIT).step_by(CHUNK) {
        let mut fds = [PollFd { fd: 0, events: 0, revents: 0 }; CHUNK];
        for (i, p) in fds.iter_mut().enumerate() {
            p.fd = (base + i) as i32;
        }
        // SAFETY: poll reads and writes `CHUNK` pollfd entries of the local array, timeout 0 (no wait); events = 0
        // asks for nothing, so it has no effect on the files.
        let r = unsafe { syscall3(nr::POLL, fds.as_mut_ptr() as *mut c_void as usize, CHUNK, 0) };
        for (i, p) in fds.iter().enumerate() {
            let fd = base + i;
            let open = if crate::syscall::is_err(r) {
                // F_GETFD: EBADF when closed (plain integer call)
                !crate::syscall::is_err(plain!(nr::FCNTL, fd, 1))
            } else {
                p.revents & POLLNVAL == 0
            };
            if open && let Some((dev, ino)) = identity(fd) {
                DEV[fd].store(dev, Relaxed);
                INO[fd].store(ino, Relaxed);
                OPEN[fd / 64].fetch_or(1 << (fd % 64), Relaxed);
            }
        }
    }
    // (runs before main, before any thread of the program exists; threads started later synchronise with it)
    SNAPSHOT.store(true, SeqCst);
}

/// Was the startup snapshot taken (this crate is in the main executable and its `.init_array` entry ran)?
pub fn snapshot_taken() -> bool {
    SNAPSHOT.load(SeqCst)
}

/// Was `fd` open when the snapshot was taken (whether or not it has been taken since)?
pub fn was_inherited(fd: i32) -> bool {
    usize::try_from(fd).is_ok_and(|n| n < LIMIT && OPEN[n / 64].load(Relaxed) & (1 << (n % 64)) != 0)
}

/// Take ownership of descriptor `fd` that the process inherited (open before `main`). `None` unless all of these
/// hold: `fd` is 3..[`LIMIT`], it was open when the startup snapshot was taken, no `take_inherited(fd)` was made
/// before (the first call for a number is the only one that can succeed), and `fd` still refers to the same file
/// (fstat `st_dev`/`st_ino` as in the snapshot).
///
/// # Soundness: why safe code cannot get two owners of one descriptor this way
///
/// Rust's I/O safety (std::io "I/O Safety"; RFC 3128) requires that an open descriptor have at most one owner, and
/// that a number be turned into an owner only by code that knows nothing else owns it. A descriptor that was open
/// before `main` and that no code has claimed is owned by nobody in Rust's sense; the first claim is legitimate.
/// - One claim per number: the `TAKEN` bit is set with an atomic `fetch_or` before anything else, so of any number
///   of threads calling `take_inherited(fd)` exactly one sees the bit clear; every later call returns `None`, also
///   after that owner closed the descriptor and the number was reused.
/// - Only numbers open before `main`: a descriptor opened by the program (a `File`, a socket, rustix, std) after the
///   snapshot has a number that was either closed at snapshot time (not in `OPEN`: `None`) or that was in the
///   snapshot, then closed by its owner (case below), then reused.
/// - Same file as in the snapshot: if the inherited descriptor was closed (only possible through its owner, i.e. a
///   claim by other code, see the assumption) and the number reused for another file, `st_dev`/`st_ino` differ and
///   the call returns `None` (and the number is burnt).
/// - 0, 1 and 2 are refused: std's `Stdin`/`Stdout`/`Stderr` and rustix's safe `stdio::stdin()` (a
///   `BorrowedFd<'static>`) act on those numbers as always open; an owner that closes them would break that.
/// - Only a snapshot of the main program counts (see the module documentation): in a dlopen'ed library the
///   program's own descriptors would look inherited.
///
/// The remaining assumption: no other code in the process claims the same inherited number by unsafe means
/// (`OwnedFd::from_raw_fd`, `File::from_raw_fd`, `BorrowedFd::borrow_raw` for a lifetime past the take, `close`), or
/// keeps a descriptor it opened in a constructor that runs before the snapshot (an LD_PRELOAD library, a C++ static
/// initialiser, a shared library's constructor): such a descriptor looks inherited, and that code's ownership of it
/// is the same kind of claim. Such code would be making its own unchecked claim that it owns the number; two
/// claims on one number cannot both be right, and the `unsafe` one is where the fault lies. Within safe Rust (std,
/// rustix, this crate) there is no way to make such a claim, which is why this function can be safe.
pub fn take_inherited(fd: i32) -> Option<OwnedRawFd> {
    let n = usize::try_from(fd).ok().filter(|&n| (3..LIMIT).contains(&n))?;
    if !was_inherited(fd) {
        return None;
    }
    let bit = 1u64 << (n % 64);
    if TAKEN[n / 64].fetch_or(bit, SeqCst) & bit != 0 {
        return None;
    }
    let (dev, ino) = identity(n)?;
    if (dev, ino) != (DEV[n].load(Relaxed), INO[n].load(Relaxed)) {
        return None;
    }
    // SAFETY: `fd` is open (fstat just succeeded), was open before main with this identity, and this is the one call
    // allowed to claim it (TAKEN bit); under the documented assumption nothing else owns it. Not -1 (n >= 3).
    Some(unsafe { OwnedRawFd::from_raw(fd) })
}
