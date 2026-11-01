//! Shared-object profiling: `LD_PROFILE=libname LD_PROFILE_OUTPUT=dir` (the data file `dir/libname.profile` that
//! glibc's `sprof` reads) and the `dlopen(..., __RTLD_SPROF)` handle `sprof` itself takes.
//!
//! Written from the file format and behaviour described in glibc's elf/dl-profile.c comment, sprof.c and the
//! x86-64 profiling PLT (no code copied):
//!
//! * While `LD_PROFILE` is set every object's lazy PLT goes through `_dl_runtime_profile` (plt.rs), which looks the target up
//!   (once per slot), records the arc (return address -> target) when the target lies in the profiled library, and
//!   jumps to the target. PLT slots are never patched, so every later call is counted too.
//! * The data file is mapped `MAP_SHARED`, so concurrent processes add to the same counters; the PC histogram is
//!   filled by a `SIGPROF` handler driven by `setitimer(ITIMER_PROF)` at 100 Hz (what `profil(3)` does).
//! * File layout (little endian, 64-bit): `gmon_hdr` (20 bytes: "gmon", version 0x1ffff, 12 spare) | tag 0 | hist
//!   header (low pc, high pc, hist size, rate, "seconds", 's'; 40 bytes) | u16 counters | tag 1 | arc count | packed
//!   arcs (from pc u64, self pc u64, count u32; 20 bytes each).
//!
//! Differences from glibc's loader, on purpose: the lookup tables of arcs use one hash shift both when a file is
//! read and when an arc is added (glibc computes the two differently, so arcs read from an earlier run are not found
//! again), and slot numbers start at 1. The 32-byte buckets of glibc (functions less than 32 bytes apart share their
//! arcs, so sprof shows them as one) are kept: the counts are glibc's.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::util::*;
use core::ptr::null_mut;
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
/// glibc hashes the target address with `log2(HASHFRACTION * sizeof(struct here_fromstruct))` = 5 (32-byte buckets) and keeps
/// one chain of callers per bucket: two functions less than 32 bytes apart share their arcs. Kept, so the counts are glibc's.
const HASH_SHIFT: u32 = 5;

#[repr(C, packed)]
struct Arc {
    from_pc: usize,
    self_pc: usize,
    count: u32,
}

/// The address of a field of an arc of the file (packed: possibly unaligned).
fn arc_field<T>(a: *mut Arc, off: usize) -> *mut T {
    (a as *mut u8).wrapping_add(off) as *mut T
}

#[repr(C)]
struct From {
    here: *mut Arc,
    link: u32,
}

struct Prof {
    /// LD_PROFILE / LD_PROFILE_OUTPUT (None: profiling off).
    name: Option<&'static [u8]>,
    output: Option<&'static [u8]>,
    /// The object being profiled (its lazy PLT was seen).
    map: Option<Map>,
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
    // sampling
    samples: *mut u16,
    nsamples: usize,
    scale: usize,
}

static P: SyncCell<Prof> = SyncCell::new(Prof {
    name: None,
    output: None,
    map: None,
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
});

/// The profiler's state. Rule: configured at start-up and set up by `start` (start-up or under the loader lock, before
/// `running` is set); afterwards `mcount` and the SIGPROF handler only read the fields and update the counters and tables
/// (with atomics or benign races, as glibc's profiler does).
#[inline(always)]
fn p() -> &'static mut Prof {
    // SAFETY: P is a static (lives for ever); the rule above keeps writers apart.
    unsafe { &mut *P.as_ptr() }
}

/// Profiling was asked for (`LD_PROFILE` with an output directory).
#[inline(always)]
pub fn enabled() -> bool {
    p().name.is_some()
}

/// Remember `LD_PROFILE` and `LD_PROFILE_OUTPUT` (already copied). glibc warns and ignores `LD_PROFILE` when
/// there is no output directory (there is no safe default).
pub fn configure(name: Option<&'static [u8]>, output: Option<&'static [u8]>) {
    let Some(name) = name else { return };
    let Some(output) = output else {
        crate::eprint!("warning: LD_PROFILE ignored because LD_PROFILE_OUTPUT not specified\n");
        return;
    };
    let s = p();
    s.name = Some(name);
    s.output = Some(output);
}

/// Does the library `name` (as LD_PROFILE gives it) name this map? Its path, its soname, or a DT_NEEDED string of
/// some map that this one satisfies.
fn name_matches(name: &[u8], m: Map) -> bool {
    if m.name() == name || m.soname() == Some(name) {
        return true;
    }
    for x in ns(0).maps() {
        let needed = x.needed();
        if x.needed_names().enumerate().any(|(k, n)| k < needed.len() && n == name && needed[k] == m) {
            return true;
        }
    }
    false
}

/// A map's lazy PLT is being set up for profiling: is it the library to profile?
pub fn note_map(m: Map) {
    let s = p();
    if let (None, Some(name)) = (s.map, s.name)
        && name_matches(name, m)
    {
        s.map = Some(m);
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

const SYS_RT_SIGACTION: usize = 13;
const SYS_SETITIMER: usize = 38;

/// Called once the profiled library is relocated: open or create the data file, map it and start sampling.
pub fn start() {
    let s = p();
    let Some(m) = s.map else { return };
    if s.started {
        return;
    }
    s.started = true;
    start_profiling(s, m);
}

/// The work of [`start`], out of line: its 4 KB file-name buffer was reserved (and probed) in the frame of every dlopen that
/// called `start`, also without LD_PROFILE, on a thread with a small stack too (FIXLIST #79).
#[cold]
#[inline(never)]
fn start_profiling(s: &mut Prof, m: Map) {
    // the library cannot be unloaded while its counters are live
    m.set_nodelete(true);
    let pagesz = sys::PAGE;
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for ph in m.phdrs() {
        if ph.typ == crate::elf::PT_LOAD && ph.flags & crate::elf::PF_X != 0 {
            lo = lo.min(ph.vaddr as usize & !(pagesz - 1));
            hi = hi.max((ph.vaddr as usize + ph.memsz as usize + pagesz - 1) & !(pagesz - 1));
        }
    }
    if lo > hi {
        return;
    }
    let lowpc = (m.l_addr() + lo) & !(HISTFRACTION * 2 - 1);
    let highpc = (m.l_addr() + hi + HISTFRACTION * 2 - 1) & !(HISTFRACTION * 2 - 1);
    let textsize = highpc - lowpc;
    let kcountsize = textsize / HISTFRACTION;
    let tossize = textsize / HASHFRACTION;
    let fromlimit = (textsize * ARCDENSITY / 100).clamp(MINARCS, MAXARCS);
    let expected = HEADER + 4 + HIST_HDR + kcountsize + 4 + 4 + fromlimit * 16 * ARC;
    // glibc sizes the arc table by the size of its in-memory records (16 bytes each): keep that, sprof checks the size

    let (Some(out), Some(nm)) = (s.output, s.name) else { return };
    let suffix = b".profile";
    let need = out.len() + 1 + nm.len() + suffix.len() + 1;
    // the file name in a scratch mapping, not 4 KB of the stack of the thread whose dlopen gets here
    let Some(mut scratch) = crate::util::Scratch::new(4352) else {
        crate::eprint!("{}/{}.profile: cannot open file: {}\n", Bytes(out), Bytes(nm), strerror(12));
        return;
    };
    let fname = &mut scratch.bytes()[..4352];
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
    // O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode 0666
    let path = core::ffi::CStr::from_bytes_until_nul(&fname[..n + 1]).unwrap_or(c"");
    let fd = sys::openat(path, 2 | 0o100 | 0o400000 | sys::O_CLOEXEC, 0o666);
    if fd < 0 {
        crate::eprint!("{}: cannot open file: {}\n", Bytes(shown), strerror(-fd));
        return;
    }
    let mut stbuf = [0u64; 18];
    if sys::fstat(fd, &mut stbuf) < 0 || (stbuf[3] & 0xffff_ffff) as u32 & 0o170000 != 0o100000 {
        crate::eprint!("{}: cannot stat file: {}\n", Bytes(shown), strerror(22));
        sys::close(fd);
        return;
    }
    let size = stbuf[6] as usize;
    let fresh = size == 0;
    if fresh {
        let r = sys::ftruncate(fd, expected);
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
    let addr = sys::mmap_new(0, expected, sys::PROT_READ | sys::PROT_WRITE, 1 /* MAP_SHARED */, fd, 0);
    sys::close(fd);
    if addr < 0 && addr > -4096 {
        crate::eprint!("{}: cannot map file: {}\n", Bytes(shown), strerror(-addr));
        return;
    }
    let base = addr as usize as *mut u8;
    // the header the file has to carry (the same bytes sprof compares against)
    let mut hdr = [0u8; HEADER + 4 + HIST_HDR];
    hdr[0..4].copy_from_slice(b"gmon");
    hdr[4..8].copy_from_slice(&GMON_SHOBJ_VERSION.to_ne_bytes());
    // tag 0 (GMON_TAG_TIME_HIST)
    let h = HEADER + 4;
    hdr[h..h + 8].copy_from_slice(&(lo as u64).to_ne_bytes());
    hdr[h + 8..h + 16].copy_from_slice(&(hi as u64).to_ne_bytes());
    hdr[h + 16..h + 20].copy_from_slice(&((kcountsize / 2) as i32).to_ne_bytes());
    hdr[h + 20..h + 24].copy_from_slice(&(PROFILE_HZ as i32).to_ne_bytes());
    hdr[h + 24..h + 31].copy_from_slice(b"seconds");
    hdr[h + 39] = b's';
    let kcount = base.wrapping_add(HEADER + 4 + HIST_HDR) as *mut u16;
    let narcsp = (kcount as *mut u8).wrapping_add(kcountsize + 4) as *mut u32;
    // The file is shared with other processes profiling the same library: its words are read and written atomically
    // where they race (the counters), and the header is compared or written as bytes.
    // SAFETY: the tag word before the arc count, inside the `expected` bytes just mapped (shared, writable), 4-aligned;
    // other processes write it only with the same value.
    let tag = unsafe { AtomicU32::from_ptr(narcsp.wrapping_sub(1)) };
    // a file another process created a moment ago and has not written its header into yet is ours to initialise (the bytes
    // are the same for everybody)
    {
        // SAFETY: the header bytes at the start of the mapping (at least `hdr.len()` of the `expected` bytes); other
        // processes may write the same bytes into it (the race glibc's profiler has too).
        let head = unsafe { crate::ffi::slice_mut(base, hdr.len()) };
        let blank = fresh || head.iter().all(|&b| b == 0) && tag.load(Relaxed) == 0;
        if blank {
            head.copy_from_slice(&hdr);
            tag.store(1, Relaxed); // GMON_TAG_CG_ARC
        } else {
            let tag_ok = tag.load(Relaxed) == 1;
            let same = head == &hdr[..];
            if !same || !tag_ok {
                // SAFETY: our own mapping of the file, not published anywhere.
                unsafe { sys::munmap(base as usize, expected) };
                crate::eprint!("{}: file is no correct profile data file for `{}'\n", Bytes(shown), Bytes(nm));
                return;
            }
        }
    }
    let data = narcsp.wrapping_add(1) as *mut Arc;
    // in-memory tables: chain heads per hash bucket, one record per arc (slot 0 is unused: 0 ends a chain)
    let tos_bytes = (tossize / 2 + 1) * 4;
    let froms_bytes = (fromlimit + 2) * core::mem::size_of::<From>();
    let mem = sys::mmap_new(0, tos_bytes + froms_bytes, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
    if mem < 0 && mem > -4096 {
        // SAFETY: our own mapping of the file, not published anywhere.
        unsafe { sys::munmap(base as usize, expected) };
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
    // arcs an earlier run left in the file; newest first so the common ones end up at the head of their chains
    // SAFETY: the arc count word of the mapped file (4-aligned), shared with other processes: only accessed atomically.
    let have = unsafe { AtomicU32::from_ptr(narcsp) }.load(Relaxed).min(fromlimit as u32) as usize;
    s.narcs.store(have as u32, Relaxed);
    let mut idx = have;
    while idx > 0 {
        idx -= 1;
        // SAFETY: arc `idx` < fromlimit of the file's arc table (inside the mapping).
        unsafe { add_known_arc(s, idx) };
    }
    // the PC histogram scale, as in monstartup
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

/// Enter arc `n` of the file's table (written by an earlier run or another process) into the in-memory chains.
///
/// # Safety
/// `n` < `fromlimit` (the arc lies inside the mapped table); `s.tos` and `s.froms` are the tables `start` made.
unsafe fn add_known_arc(s: &Prof, n: usize) {
    let a = s.data.wrapping_add(n);
    // SAFETY: arc `n` lies in the mapped table (caller's contract); a packed field, read unaligned.
    let to = unsafe { core::ptr::read_unaligned(arc_field::<usize>(a, core::mem::offset_of!(Arc, self_pc))) } >> HASH_SHIFT;
    if to <= s.textsize >> HASH_SHIFT {
        let slot = s.fromidx.fetch_add(1, Relaxed) + 1;
        let f = s.froms.wrapping_add(slot as usize);
        let head = s.tos.wrapping_add(to);
        // SAFETY: `to` <= textsize >> 5 indexes the chain heads (tossize / 2 + 1 words); `slot` <= fromlimit + 1 indexes
        // the records (fromlimit + 2), as glibc sizes them; the tables are private to the process.
        let link = unsafe { *head };
        // SAFETY: as above.
        unsafe { f.write(From { here: a, link }) };
        // SAFETY: as above.
        unsafe { *head = slot };
    }
}

// ---- the SIGPROF sampler ----

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

/// SIGPROF handler: count the interrupted PC (`ucontext.uc_mcontext.gregs[REG_RIP]`).
///
/// # Safety
/// Called by the kernel as an SA_SIGINFO handler: `uc` is the interrupted context.
unsafe extern "C" fn sample(_sig: i32, _info: usize, uc: *const u8) {
    let s = p();
    // SAFETY: gregs[REG_RIP] of the x86-64 ucontext the kernel passed (offset 168).
    let pc = unsafe { *(uc.wrapping_add(168) as *const usize) };
    if s.samples.is_null() {
        return;
    }
    let off = pc.wrapping_sub(s.lowpc);
    let i = off / 2;
    let i = ((i as u128 * s.scale as u128) / 65536) as usize;
    if pc >= s.lowpc && i < s.nsamples {
        let c = s.samples.wrapping_add(i);
        // SAFETY: counter `i` < nsamples of the histogram in the mapped file.
        let v = unsafe { core::ptr::read_volatile(c) };
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(c, v.wrapping_add(1)) };
    }
}

fn install_timer() {
    const SA_SIGINFO: u64 = 4;
    const SA_RESTORER: u64 = 0x0400_0000;
    const SA_RESTART: u64 = 0x1000_0000;
    const SIGPROF: usize = 27;
    let act = KSigaction { handler: sample as *const () as usize, flags: SA_SIGINFO | SA_RESTART | SA_RESTORER, restorer: __rtld_profil_restorer as *const () as usize, mask: !0 };
    // SAFETY: installs `sample` (which only reads the profiler's set-up fields and counts in its histogram) with all signals
    // blocked while it runs and the rt_sigreturn restorer; the structure is read by the kernel during the call.
    if unsafe { sys::syscall6(SYS_RT_SIGACTION, SIGPROF, &act as *const _ as usize, 0, 8, 0, 0) } < 0 {
        return;
    }
    let usec = 1_000_000 / PROFILE_HZ;
    let timer: [usize; 4] = [0, usec, 0, usec]; // it_interval, it_value
    // SAFETY: the kernel reads the itimerval during the call.
    unsafe { sys::syscall3(SYS_SETITIMER, 2 /* ITIMER_PROF */, timer.as_ptr() as usize, 0) };
}

// ---- recording arcs ----

/// Count one call of `selfpc` from `frompc` (a return address). Addresses outside the profiled library count as
/// calls from `<external>` (from pc 0); targets outside it are not recorded at all.
pub fn mcount(frompc: usize, selfpc: usize) {
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
    // SAFETY (every access to the tables below): `start` made them before setting `running`: the chain heads (`tos`, one per
    // 32-byte bucket of the text: selfpc < textsize keeps the index in range), the records (`froms`, indices up to
    // fromlimit + 1, which `fromidx` never passes: a new arc is refused at fromlimit) and the file's arc table (`data`,
    // fromlimit arcs; `narcsp` its shared count). Concurrent calls race on the chains the way glibc's do (a lost update
    // loses one arc, never memory).
    let mut top: *mut u32 = s.tos.wrapping_add(selfpc >> HASH_SHIFT);
    // SAFETY: see above.
    let first = unsafe { *top };
    let mut fromp: *mut From = null_mut();
    let mut new_entry = first == 0;
    if !new_entry {
        fromp = s.froms.wrapping_add(first as usize);
    }
    let fp = |f: *mut From| {
        // SAFETY: see above (a record in use).
        let here = unsafe { (*f).here };
        // SAFETY: see above (the record's arc lies in the file; its packed field is read unaligned).
        unsafe { core::ptr::read_unaligned(arc_field::<usize>(here, core::mem::offset_of!(Arc, from_pc))) }
    };
    // SAFETY: the arc count of the mapped file (4-aligned), only accessed atomically.
    let narcsp = unsafe { AtomicU32::from_ptr(s.narcsp) };
    loop {
        if !new_entry {
            let mut found = false;
            loop {
                if fp(fromp) == frompc {
                    found = true;
                    break;
                }
                // SAFETY: see above.
                let link = unsafe { (*fromp).link };
                if link == 0 {
                    break;
                }
                fromp = s.froms.wrapping_add(link as usize);
            }
            if found {
                break;
            }
            // SAFETY: see above (the address of the record's link word).
            top = unsafe { &raw mut (*fromp).link };
        }
        // arcs another process added to the file since we last looked
        while s.narcs.load(Relaxed) != narcsp.load(Relaxed) && s.narcs.load(Relaxed) < s.fromlimit {
            let n = s.narcs.load(Relaxed) as usize;
            // SAFETY: n < fromlimit.
            unsafe { add_known_arc(s, n) };
            s.narcs.fetch_add(1, Relaxed);
        }
        // SAFETY: see above.
        if unsafe { *top } == 0 {
            let newarc = narcsp.fetch_add(1, Relaxed);
            if newarc >= s.fromlimit {
                return;
            }
            let slot = s.fromidx.fetch_add(1, Relaxed) + 1;
            // SAFETY: see above.
            unsafe { *top = slot };
            fromp = s.froms.wrapping_add(slot as usize);
            let a = s.data.wrapping_add(newarc as usize);
            // SAFETY: arc `newarc` < fromlimit of the file's table, claimed by the fetch_add above (packed: written whole,
            // unaligned).
            unsafe { a.write_unaligned(Arc { from_pc: frompc, self_pc: selfpc, count: 0 }) };
            // SAFETY: see above (record `slot`).
            unsafe { fromp.write(From { here: a, link: 0 }) };
            s.narcs.fetch_add(1, Relaxed);
            break;
        }
        // SAFETY: see above.
        fromp = s.froms.wrapping_add(unsafe { *top } as usize);
        new_entry = false;
    }
    // SAFETY: see above (a record in use).
    let here = unsafe { (*fromp).here };
    // SAFETY: see above: the record's arc lies in the mapped file; its count (4 bytes at offset 16 of the 20-byte packed arc,
    // 4-aligned because the table starts 4-aligned and arcs are 20 bytes) is shared between processes, so atomic.
    let c = unsafe { AtomicU32::from_ptr(arc_field::<u32>(here, core::mem::offset_of!(Arc, count))) };
    c.fetch_add(1, Relaxed);
}
