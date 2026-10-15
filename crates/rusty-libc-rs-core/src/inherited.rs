use crate::fd::OwnedRawFd;
use crate::syscall::{nr, syscall3};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};

pub const LIMIT: usize = 1024;
const WORDS: usize = LIMIT / 64;

static OPEN: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
static TAKEN: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
static DEV: [AtomicU64; LIMIT] = [const { AtomicU64::new(0) }; LIMIT];
static INO: [AtomicU64; LIMIT] = [const { AtomicU64::new(0) }; LIMIT];
static SNAPSHOT: AtomicBool = AtomicBool::new(false);

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = snapshot;

unsafe extern "C" {
    fn getauxval(kind: u64) -> u64;
}

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

fn in_main_executable() -> bool {
    let phdr = unsafe { getauxval(AT_PHDR) } as usize;
    let phnum = unsafe { getauxval(AT_PHNUM) } as usize;
    if phdr == 0 || phnum == 0 || phnum > 4096 || !phdr.is_multiple_of(core::mem::align_of::<Phdr>()) {
        return false;
    }
    let phdrs = unsafe { core::slice::from_raw_parts(phdr as *const Phdr, phnum) };
    let Some(pt_phdr) = phdrs.iter().find(|p| p.p_type == PT_PHDR) else { return false };
    let bias = (phdr as u64).wrapping_sub(pt_phdr.p_vaddr);
    let me = &raw const OPEN as u64;
    phdrs.iter().any(|p| p.p_type == PT_LOAD && me.wrapping_sub(bias.wrapping_add(p.p_vaddr)) < p.p_memsz)
}

fn identity(fd: usize) -> Option<(u64, u64)> {
    let mut st = [0u64; 18];
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
        let r = unsafe { syscall3(nr::POLL, fds.as_mut_ptr() as *mut c_void as usize, CHUNK, 0) };
        for (i, p) in fds.iter().enumerate() {
            let fd = base + i;
            let open = if crate::syscall::is_err(r) {
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
    SNAPSHOT.store(true, SeqCst);
}

pub fn snapshot_taken() -> bool {
    SNAPSHOT.load(SeqCst)
}

pub fn was_inherited(fd: i32) -> bool {
    usize::try_from(fd).is_ok_and(|n| n < LIMIT && OPEN[n / 64].load(Relaxed) & (1 << (n % 64)) != 0)
}

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
    Some(unsafe { OwnedRawFd::from_raw(fd) })
}
