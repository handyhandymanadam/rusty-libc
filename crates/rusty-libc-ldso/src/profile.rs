use crate::map::*;
use crate::sys;
use crate::util::*;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

const HISTFRACTION: usize = 2;
const HASHFRACTION: usize = 2;
const ARCDENSITY: usize = 3;
const MINARCS: usize = 50;
const MAXARCS: usize = 1 << 20;
const GMON_SHOBJ_VERSION: i32 = 0x1ffff;
const HEADER: usize = 20;
const HIST_HDR: usize = 40;
const ARC: usize = 20;
const PROFILE_HZ: usize = 100;
const HASH_SHIFT: u32 = 5;

#[repr(C, packed)]
struct Arc {
    from_pc: usize,
    self_pc: usize,
    count: u32,
}

#[repr(C)]
struct From {
    here: *mut Arc,
    link: u32,
}

struct Prof {
    name: *const u8,
    output: *const u8,
    map: *mut LinkMap,
    started: bool,
    running: bool,
    lowpc: usize,
    textsize: usize,
    narcsp: *mut u32,
    narcs: AtomicU32,
    data: *mut Arc,
    tos: *mut u32,
    froms: *mut From,
    fromlimit: u32,
    fromidx: AtomicU32,
    samples: *mut u16,
    nsamples: usize,
    scale: usize,
}

static mut P: Prof = Prof {
    name: null(),
    output: null(),
    map: null_mut(),
    started: false,
    running: false,
    lowpc: 0,
    textsize: 0,
    narcsp: null_mut(),
    narcs: AtomicU32::new(0),
    data: null_mut(),
    tos: null_mut(),
    froms: null_mut(),
    fromlimit: 0,
    fromidx: AtomicU32::new(0),
    samples: null_mut(),
    nsamples: 0,
    scale: 0,
};

#[inline(always)]
fn p() -> &'static mut Prof {
    unsafe { &mut *(&raw mut P) }
}

#[inline(always)]
pub fn enabled() -> bool {
    !p().name.is_null()
}

pub unsafe fn configure(name: *const u8, output: *const u8) {
    if name.is_null() {
        return;
    }
    if output.is_null() {
        crate::eprint!("warning: LD_PROFILE ignored because LD_PROFILE_OUTPUT not specified\n");
        return;
    }
    let s = p();
    s.name = name;
    s.output = output;
}

unsafe fn name_matches(name: &[u8], m: *mut LinkMap) -> bool {
    if cstr((*m).l_name) == name || (!(*m).soname.is_null() && cstr((*m).soname) == name) {
        return true;
    }
    let mut x = st().head;
    while !x.is_null() {
        let mut k = 0usize;
        let mut hit = false;
        needed_names(x, |n| {
            if k < (*x).nneeded && n == name && *(*x).needed.add(k) == m {
                hit = true;
            }
            k += 1;
        });
        if hit {
            return true;
        }
        x = (*x).l_next;
    }
    false
}

pub unsafe fn note_map(m: *mut LinkMap) {
    let s = p();
    if s.map.is_null() && name_matches(cstr(s.name), m) {
        s.map = m;
    }
}

fn strerror(e: isize) -> &'static str {
    match e {
        1 => "Operation not permitted",
        2 => "No such file or directory",
        12 => "Cannot allocate memory",
        13 => "Permission denied",
        17 => "File exists",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        24 => "Too many open files",
        28 => "No space left on device",
        30 => "Read-only file system",
        40 => "Too many levels of symbolic links",
        _ => "Unknown error",
    }
}

const SYS_FSTAT: usize = 5;
const SYS_FTRUNCATE: usize = 77;
const SYS_RT_SIGACTION: usize = 13;
const SYS_SETITIMER: usize = 38;

pub unsafe fn start() {
    let s = p();
    let m = s.map;
    if m.is_null() || s.started {
        return;
    }
    s.started = true;
    (*m).nodelete = true;
    let pagesz = sys::PAGE;
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for i in 0..(*m).phnum {
        let ph = &*(*m).phdr.add(i);
        if ph.typ == crate::elf::PT_LOAD && ph.flags & crate::elf::PF_X != 0 {
            lo = lo.min(ph.vaddr as usize & !(pagesz - 1));
            hi = hi.max((ph.vaddr as usize + ph.memsz as usize + pagesz - 1) & !(pagesz - 1));
        }
    }
    if lo > hi {
        return;
    }
    let lowpc = ((*m).l_addr + lo) & !(HISTFRACTION * 2 - 1);
    let highpc = ((*m).l_addr + hi + HISTFRACTION * 2 - 1) & !(HISTFRACTION * 2 - 1);
    let textsize = highpc - lowpc;
    let kcountsize = textsize / HISTFRACTION;
    let tossize = textsize / HASHFRACTION;
    let fromlimit = (textsize * ARCDENSITY / 100).clamp(MINARCS, MAXARCS);
    let expected = HEADER + 4 + HIST_HDR + kcountsize + 4 + 4 + fromlimit * 16 * ARC;

    let mut fname = [0u8; 4352];
    let out = cstr(s.output);
    let nm = cstr(s.name);
    let suffix = b".profile";
    let need = out.len() + 1 + nm.len() + suffix.len() + 1;
    if need > fname.len() {
        crate::eprint!("{}/{}.profile: cannot open file: File name too long\n", Bytes(out), Bytes(nm));
        return;
    }
    let mut n = 0;
    for part in [out, b"/", nm, suffix] {
        fname[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    let shown = &fname[..n];
    let fd = sys::syscall6(sys::SYS_OPENAT, sys::AT_FDCWD as usize, fname.as_ptr() as usize, 2 | 0o100 | 0o400000 | sys::O_CLOEXEC, 0o666, 0, 0);
    if fd < 0 {
        crate::eprint!("{}: cannot open file: {}\n", Bytes(shown), strerror(-fd));
        return;
    }
    let mut stbuf = [0u64; 18];
    if sys::syscall3(SYS_FSTAT, fd as usize, stbuf.as_mut_ptr() as usize, 0) < 0 || (stbuf[3] & 0xffff_ffff) as u32 & 0o170000 != 0o100000 {
        crate::eprint!("{}: cannot stat file: {}\n", Bytes(shown), strerror(22));
        sys::close(fd);
        return;
    }
    let size = stbuf[6] as usize;
    let fresh = size == 0;
    if fresh {
        let r = sys::syscall3(SYS_FTRUNCATE, fd as usize, expected, 0);
        if r < 0 {
            crate::eprint!("{}: cannot create file: {}\n", Bytes(shown), strerror(-r));
            sys::close(fd);
            return;
        }
    } else if size != expected {
        sys::close(fd);
        crate::eprint!("{}: file is no correct profile data file for `{}'\n", Bytes(shown), Bytes(nm));
        return;
    }
    let addr = sys::mmap(0, expected, sys::PROT_READ | sys::PROT_WRITE, 1 , fd, 0);
    sys::close(fd);
    if addr < 0 && addr > -4096 {
        crate::eprint!("{}: cannot map file: {}\n", Bytes(shown), strerror(-addr));
        return;
    }
    let base = addr as usize as *mut u8;
    let mut hdr = [0u8; HEADER + 4 + HIST_HDR];
    hdr[0..4].copy_from_slice(b"gmon");
    hdr[4..8].copy_from_slice(&GMON_SHOBJ_VERSION.to_ne_bytes());
    let h = HEADER + 4;
    hdr[h..h + 8].copy_from_slice(&(lo as u64).to_ne_bytes());
    hdr[h + 8..h + 16].copy_from_slice(&(hi as u64).to_ne_bytes());
    hdr[h + 16..h + 20].copy_from_slice(&((kcountsize / 2) as i32).to_ne_bytes());
    hdr[h + 20..h + 24].copy_from_slice(&(PROFILE_HZ as i32).to_ne_bytes());
    hdr[h + 24..h + 31].copy_from_slice(b"seconds");
    hdr[h + 39] = b's';
    let kcount = base.add(HEADER + 4 + HIST_HDR) as *mut u16;
    let narcsp = (kcount as *mut u8).add(kcountsize + 4) as *mut u32;
    let blank = fresh || core::slice::from_raw_parts(base, hdr.len()).iter().all(|&b| b == 0) && *narcsp.sub(1) == 0;
    if blank {
        core::ptr::copy_nonoverlapping(hdr.as_ptr(), base, hdr.len());
        *(narcsp.sub(1)) = 1;
    } else {
        let tag_ok = *narcsp.sub(1) == 1;
        let same = core::slice::from_raw_parts(base, hdr.len()) == &hdr[..];
        if !same || !tag_ok {
            sys::munmap(base as usize, expected);
            crate::eprint!("{}: file is no correct profile data file for `{}'\n", Bytes(shown), Bytes(nm));
            return;
        }
    }
    let data = narcsp.add(1) as *mut Arc;
    let tos_bytes = (tossize / 2 + 1) * 4;
    let froms_bytes = (fromlimit + 2) * core::mem::size_of::<From>();
    let mem = sys::mmap(0, tos_bytes + froms_bytes, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
    if mem < 0 && mem > -4096 {
        sys::munmap(base as usize, expected);
        crate::eprint!("Out of memory while initializing profiler\n");
        sys::exit(127);
    }
    s.tos = mem as usize as *mut u32;
    s.froms = (mem as usize + tos_bytes) as *mut From;
    s.fromlimit = fromlimit as u32;
    s.fromidx.store(0, Relaxed);
    s.lowpc = lowpc;
    s.textsize = textsize;
    s.narcsp = narcsp;
    s.data = data;
    let have = (*AtomicU32::from_ptr(narcsp)).load(Relaxed).min(fromlimit as u32) as usize;
    s.narcs.store(have as u32, Relaxed);
    let mut idx = have;
    while idx > 0 {
        idx -= 1;
        let a = data.add(idx);
        let to = core::ptr::read_unaligned(&raw const (*a).self_pc) >> HASH_SHIFT;
        if to <= textsize >> HASH_SHIFT {
            let slot = s.fromidx.fetch_add(1, Relaxed) + 1;
            let f = s.froms.add(slot as usize);
            (*f).here = a;
            (*f).link = *s.tos.add(to);
            *s.tos.add(to) = slot;
        }
    }
    let range = highpc - lowpc;
    let scale: usize = if kcountsize < range {
        let quot = range / kcountsize;
        if quot >= 0x10000 {
            1
        } else if quot >= 0x10000 / 256 {
            0x10000 / quot
        } else {
            (0x10000 * 256) / ((range * 256) / kcountsize)
        }
    } else {
        0x10000
    };
    s.samples = kcount;
    s.nsamples = kcountsize / 2;
    s.scale = scale;
    install_timer();
    s.running = true;
}

core::arch::global_asm!(
    ".text",
    ".globl __rtld_profil_restorer",
    ".hidden __rtld_profil_restorer",
    ".type __rtld_profil_restorer, @function",
    "__rtld_profil_restorer:",
    "mov eax, 15",
    "syscall",
    ".size __rtld_profil_restorer, .-__rtld_profil_restorer",
);

unsafe extern "C" {
    fn __rtld_profil_restorer();
}

#[repr(C)]
struct KSigaction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
}

unsafe extern "C" fn sample(_sig: i32, _info: usize, uc: *const u8) {
    let s = p();
    let pc = *(uc.add(168) as *const usize);
    if s.samples.is_null() {
        return;
    }
    let off = pc.wrapping_sub(s.lowpc);
    let i = off / 2;
    let i = ((i as u128 * s.scale as u128) / 65536) as usize;
    if pc >= s.lowpc && i < s.nsamples {
        let c = s.samples.add(i);
        core::ptr::write_volatile(c, core::ptr::read_volatile(c).wrapping_add(1));
    }
}

unsafe fn install_timer() {
    const SA_SIGINFO: u64 = 4;
    const SA_RESTORER: u64 = 0x0400_0000;
    const SA_RESTART: u64 = 0x1000_0000;
    const SIGPROF: usize = 27;
    let act = KSigaction { handler: sample as usize, flags: SA_SIGINFO | SA_RESTART | SA_RESTORER, restorer: __rtld_profil_restorer as usize, mask: !0 };
    if sys::syscall6(SYS_RT_SIGACTION, SIGPROF, &act as *const _ as usize, 0, 8, 0, 0) < 0 {
        return;
    }
    let usec = 1_000_000 / PROFILE_HZ;
    let timer: [usize; 4] = [0, usec, 0, usec];
    sys::syscall3(SYS_SETITIMER, 2 , timer.as_ptr() as usize, 0);
}

pub unsafe fn mcount(frompc: usize, selfpc: usize) {
    let s = p();
    if !s.running {
        return;
    }
    let mut frompc = frompc.wrapping_sub(s.lowpc);
    if frompc >= s.textsize {
        frompc = 0;
    }
    let selfpc = selfpc.wrapping_sub(s.lowpc);
    if selfpc >= s.textsize {
        return;
    }
    let mut top: *mut u32 = s.tos.add(selfpc >> HASH_SHIFT);
    let first = *top;
    let mut fromp: *mut From = null_mut();
    let mut new_entry = first == 0;
    if !new_entry {
        fromp = s.froms.add(first as usize);
    }
    let fp = |f: *mut From| core::ptr::read_unaligned(&raw const (*(*f).here).from_pc);
    loop {
        if !new_entry {
            let mut found = false;
            loop {
                if fp(fromp) == frompc {
                    found = true;
                    break;
                }
                if (*fromp).link == 0 {
                    break;
                }
                fromp = s.froms.add((*fromp).link as usize);
            }
            if found {
                break;
            }
            top = &raw mut (*fromp).link;
        }
        let narcsp = AtomicU32::from_ptr(s.narcsp);
        while s.narcs.load(Relaxed) != narcsp.load(Relaxed) && s.narcs.load(Relaxed) < s.fromlimit {
            let n = s.narcs.load(Relaxed) as usize;
            let a = s.data.add(n);
            let to = core::ptr::read_unaligned(&raw const (*a).self_pc) >> HASH_SHIFT;
            if to <= s.textsize >> HASH_SHIFT {
                let slot = s.fromidx.fetch_add(1, Relaxed) + 1;
                let f = s.froms.add(slot as usize);
                (*f).here = a;
                (*f).link = *s.tos.add(to);
                *s.tos.add(to) = slot;
            }
            s.narcs.fetch_add(1, Relaxed);
        }
        if *top == 0 {
            let newarc = narcsp.fetch_add(1, Relaxed);
            if newarc >= s.fromlimit {
                return;
            }
            let slot = s.fromidx.fetch_add(1, Relaxed) + 1;
            *top = slot;
            fromp = s.froms.add(slot as usize);
            let a = s.data.add(newarc as usize);
            (*fromp).here = a;
            core::ptr::write_unaligned(&raw mut (*a).from_pc, frompc);
            core::ptr::write_unaligned(&raw mut (*a).self_pc, selfpc);
            core::ptr::write_unaligned(&raw mut (*a).count, 0);
            (*fromp).link = 0;
            s.narcs.fetch_add(1, Relaxed);
            break;
        }
        fromp = s.froms.add(*top as usize);
        new_entry = false;
    }
    let c = AtomicU32::from_ptr((&raw mut (*(*fromp).here).count) as *mut u32);
    c.fetch_add(1, Relaxed);
}

