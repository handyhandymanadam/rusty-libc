#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_int, c_long, c_ulong, c_void};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::syscall::{syscall3, syscall4};
use rusty_libc_signal::consts::{SA_RESTART, SA_SIGINFO, SIGPROF};
use rusty_libc_signal::types::{Sigaction, Sigset};
use rusty_libc_time::clock::{Itimerval, setitimer};

const GMON_PROF_ON: i64 = 0;
const GMON_PROF_BUSY: i64 = 1;
const GMON_PROF_ERROR: i64 = 2;
const GMON_PROF_OFF: i64 = 3;

const HISTFRACTION: u64 = 2;
const HASHFRACTION: u64 = 2;
const ARCDENSITY: u64 = 3;
const MINARCS: i64 = 50;
const MAXARCS: i64 = 1 << 20;
const SCALE_1_TO_1: i32 = 0x10000;
type HistCounter = u16;
type ArcIndex = u64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ToStruct {
    pub selfpc: u64,
    pub count: i64,
    pub link: u16,
    pub pad: u16,
}

#[repr(C)]
pub struct GmonParam {
    pub state: AtomicI64,
    pub kcount: *mut u16,
    pub kcountsize: usize,
    pub froms: *mut ArcIndex,
    pub fromssize: usize,
    pub tos: *mut ToStruct,
    pub tossize: usize,
    pub tolimit: c_long,
    pub lowpc: c_ulong,
    pub highpc: c_ulong,
    pub textsize: c_ulong,
    pub hashfraction: c_ulong,
    pub log_hashfraction: c_long,
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static _gmonparam: SyncCell<GmonParam> = SyncCell::new(GmonParam {
    state: AtomicI64::new(GMON_PROF_OFF),
    kcount: core::ptr::null_mut(),
    kcountsize: 0,
    froms: core::ptr::null_mut(),
    fromssize: 0,
    tos: core::ptr::null_mut(),
    tossize: 0,
    tolimit: 0,
    lowpc: 0,
    highpc: 0,
    textsize: 0,
    hashfraction: 0,
    log_hashfraction: 0,
});

static S_SCALE: AtomicI32 = AtomicI32::new(0);

fn params() -> &'static GmonParam {
    unsafe { &*_gmonparam.as_ptr() }
}

fn with_params_mut<R>(f: impl FnOnce(&mut GmonParam) -> R) -> R {
    unsafe { _gmonparam.with_unsync(f) }
}

fn state_cell() -> &'static AtomicI64 {
    &params().state
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __profile_frequency() -> c_int {
    100
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn moncontrol(mode: c_int) {
    let p = params();
    if p.state.load(Ordering::Relaxed) == GMON_PROF_ERROR {
        return;
    }
    if mode != 0 {
        unsafe { profil(p.kcount, p.kcountsize, p.lowpc as usize, S_SCALE.load(Ordering::Relaxed) as u32) };
        p.state.store(GMON_PROF_ON, Ordering::Relaxed);
    } else {
        unsafe { profil(core::ptr::null_mut(), 0, 0, 0) };
        p.state.store(GMON_PROF_OFF, Ordering::Relaxed);
    }
}

fn err_out(msg: &[u8]) {
    let _ = rusty_libc_core::unistd::write_nocancel(2, msg);
}

const fn round_down(x: u64, to: u64) -> u64 {
    x / to * to
}
const fn round_up(x: u64, to: u64) -> u64 {
    x.div_ceil(to) * to
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __monstartup(lowpc: c_ulong, highpc: c_ulong) {
    let started = with_params_mut(|p| {
        if !p.tos.is_null() {
            return false;
        }
        p.lowpc = round_down(lowpc, HISTFRACTION * size_of::<HistCounter>() as u64);
        p.highpc = round_up(highpc, HISTFRACTION * size_of::<HistCounter>() as u64);
        p.textsize = p.highpc - p.lowpc;
        p.kcountsize = round_up(p.textsize / HISTFRACTION, size_of::<ArcIndex>() as u64) as usize;
        p.hashfraction = HASHFRACTION;
        p.log_hashfraction = -1;
        p.log_hashfraction = ((HASHFRACTION * size_of::<ArcIndex>() as u64).trailing_zeros()) as c_long;
        p.fromssize = (p.textsize / HASHFRACTION) as usize;
        let tolimit = ((p.textsize * ARCDENSITY / 100) as i64).clamp(MINARCS, MAXARCS);
        p.tolimit = tolimit;
        p.tossize = tolimit as usize * size_of::<ToStruct>();
        let total = p.kcountsize + p.fromssize + p.tossize;
        let cp = unsafe { rusty_libc_malloc::calloc(total, 1) }.cast::<u8>();
        if cp.is_null() {
            err_out(b"monstartup: out of memory\n");
            p.tos = core::ptr::null_mut();
            p.state.store(GMON_PROF_ERROR, Ordering::Relaxed);
            return false;
        }
        p.tos = cp.cast::<ToStruct>();
        let q = cp.wrapping_add(p.tossize);
        p.kcount = q.cast::<u16>();
        p.froms = q.wrapping_add(p.kcountsize).cast::<ArcIndex>();
        let o = (p.highpc - p.lowpc) as i32;
        let scale = if p.kcountsize < o as usize { (p.kcountsize as f32 / o as f32 * SCALE_1_TO_1 as f32) as i32 } else { SCALE_1_TO_1 };
        S_SCALE.store(scale, Ordering::Relaxed);
        true
    });
    if started {
        moncontrol(1);
    }
}

#[cfg(feature = "export")]
core::arch::global_asm!(".weak monstartup", ".set monstartup, __monstartup");

fn count_arc(p: &GmonParam, froms: &mut [ArcIndex], tos: &mut [ToStruct], frompc: c_ulong, selfpc: c_ulong) -> i64 {
    let i = (frompc >> p.log_hashfraction) as usize;
    let Some(&first) = froms.get(i) else { return GMON_PROF_ON };
    let mut toindex = first;
    if toindex == 0 {
        tos[0].link = tos[0].link.wrapping_add(1);
        toindex = tos[0].link as u64;
        if toindex as i64 >= p.tolimit {
            return GMON_PROF_ERROR;
        }
        froms[i] = toindex;
        let top = &mut tos[toindex as usize];
        top.selfpc = selfpc;
        top.count = 1;
        top.link = 0;
        return GMON_PROF_ON;
    }
    let mut top = toindex as usize;
    if tos[top].selfpc == selfpc {
        tos[top].count += 1;
        return GMON_PROF_ON;
    }
    loop {
        if tos[top].link == 0 {
            tos[0].link = tos[0].link.wrapping_add(1);
            toindex = tos[0].link as u64;
            if toindex as i64 >= p.tolimit {
                return GMON_PROF_ERROR;
            }
            let t = &mut tos[toindex as usize];
            t.selfpc = selfpc;
            t.count = 1;
            t.link = froms[i] as u16;
            froms[i] = toindex;
            return GMON_PROF_ON;
        }
        let prevtop = top;
        top = tos[top].link as usize;
        if tos[top].selfpc == selfpc {
            tos[top].count += 1;
            toindex = tos[prevtop].link as u64;
            tos[prevtop].link = tos[top].link;
            tos[top].link = froms[i] as u16;
            froms[i] = toindex;
            return GMON_PROF_ON;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rl_mcount_internal(frompc: c_ulong, selfpc: c_ulong) {
    let state = state_cell();
    if state.compare_exchange(GMON_PROF_ON, GMON_PROF_BUSY, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return;
    }
    let p = params();
    let frompc = frompc.wrapping_sub(p.lowpc);
    if frompc > p.textsize {
        state.store(GMON_PROF_ON, Ordering::Release);
        return;
    }
    let froms = unsafe { ffi::slice_mut(p.froms, p.fromssize / size_of::<ArcIndex>()) };
    let tos = unsafe { ffi::slice_mut(p.tos, p.tolimit as usize) };
    let next = count_arc(p, froms, tos, frompc, selfpc);
    state.store(next, Ordering::Release);
}

core::arch::global_asm!(
    ".text",
    ".globl _mcount",
    ".type _mcount, @function",
    "_mcount:",
    ".globl rl_mcount_entry",
    "rl_mcount_entry:",
    "sub rsp, 184",
    "mov qword ptr [rsp], rax",
    "mov qword ptr [rsp + 8], rcx",
    "mov qword ptr [rsp + 16], rdx",
    "mov qword ptr [rsp + 24], rsi",
    "mov qword ptr [rsp + 32], rdi",
    "mov qword ptr [rsp + 40], r8",
    "mov qword ptr [rsp + 48], r9",
    "movups xmmword ptr [rsp + 56], xmm0",
    "movups xmmword ptr [rsp + 72], xmm1",
    "movups xmmword ptr [rsp + 88], xmm2",
    "movups xmmword ptr [rsp + 104], xmm3",
    "movups xmmword ptr [rsp + 120], xmm4",
    "movups xmmword ptr [rsp + 136], xmm5",
    "movups xmmword ptr [rsp + 152], xmm6",
    "movups xmmword ptr [rsp + 168], xmm7",
    "mov rsi, qword ptr [rsp + 184]",
    "mov rdi, qword ptr [rbp + 8]",
    "call rl_mcount_internal",
    "jmp 2f",
    ".size _mcount, . - _mcount",
    ".globl __fentry__",
    ".type __fentry__, @function",
    "__fentry__:",
    "sub rsp, 184",
    "mov qword ptr [rsp], rax",
    "mov qword ptr [rsp + 8], rcx",
    "mov qword ptr [rsp + 16], rdx",
    "mov qword ptr [rsp + 24], rsi",
    "mov qword ptr [rsp + 32], rdi",
    "mov qword ptr [rsp + 40], r8",
    "mov qword ptr [rsp + 48], r9",
    "movups xmmword ptr [rsp + 56], xmm0",
    "movups xmmword ptr [rsp + 72], xmm1",
    "movups xmmword ptr [rsp + 88], xmm2",
    "movups xmmword ptr [rsp + 104], xmm3",
    "movups xmmword ptr [rsp + 120], xmm4",
    "movups xmmword ptr [rsp + 136], xmm5",
    "movups xmmword ptr [rsp + 152], xmm6",
    "movups xmmword ptr [rsp + 168], xmm7",
    "mov rsi, qword ptr [rsp + 184]",
    "mov rdi, qword ptr [rsp + 192]",
    "call rl_mcount_internal",
    "2:",
    "mov rax, qword ptr [rsp]",
    "mov rcx, qword ptr [rsp + 8]",
    "mov rdx, qword ptr [rsp + 16]",
    "mov rsi, qword ptr [rsp + 24]",
    "mov rdi, qword ptr [rsp + 32]",
    "mov r8, qword ptr [rsp + 40]",
    "mov r9, qword ptr [rsp + 48]",
    "movups xmm0, xmmword ptr [rsp + 56]",
    "movups xmm1, xmmword ptr [rsp + 72]",
    "movups xmm2, xmmword ptr [rsp + 88]",
    "movups xmm3, xmmword ptr [rsp + 104]",
    "movups xmm4, xmmword ptr [rsp + 120]",
    "movups xmm5, xmmword ptr [rsp + 136]",
    "movups xmm6, xmmword ptr [rsp + 152]",
    "movups xmm7, xmmword ptr [rsp + 168]",
    "add rsp, 184",
    "ret",
    ".size __fentry__, . - __fentry__",
    ".globl _dl_mcount_wrapper",
    ".type _dl_mcount_wrapper, @function",
    "_dl_mcount_wrapper:",
    "mov rsi, rdi",
    "mov rdi, qword ptr [rsp]",
    "jmp rl_mcount_internal",
    ".size _dl_mcount_wrapper, . - _dl_mcount_wrapper",
);

#[cfg(feature = "export")]
core::arch::global_asm!(".weak mcount", ".set mcount, _mcount");

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _dl_mcount_wrapper_check(_selfpc: *mut c_void) {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __cyg_profile_func_enter(_this_fn: *mut c_void, _call_site: *mut c_void) {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __cyg_profile_func_exit(_this_fn: *mut c_void, _call_site: *mut c_void) {}

const GMON_TAG_TIME_HIST: u8 = 0;
const GMON_TAG_CG_ARC: u8 = 1;

fn writev_all(fd: c_int, iov: &[(usize, usize)]) {
    unsafe { syscall3(20, fd as usize, iov.as_ptr() as usize, iov.len()) };
}

fn write_hist(fd: c_int) {
    let p = params();
    if p.kcountsize > 0 {
        let tag: u8 = GMON_TAG_TIME_HIST;
        let mut thdr = [0u8; 40];
        thdr[0..8].copy_from_slice(&p.lowpc.to_ne_bytes());
        thdr[8..16].copy_from_slice(&p.highpc.to_ne_bytes());
        thdr[16..20].copy_from_slice(&(((p.kcountsize / size_of::<HistCounter>()) as i32).to_ne_bytes()));
        thdr[20..24].copy_from_slice(&__profile_frequency().to_ne_bytes());
        thdr[24..31].copy_from_slice(b"seconds");
        thdr[39] = b's';
        writev_all(fd, &[(&tag as *const u8 as usize, 1), (thdr.as_ptr() as usize, 40), (p.kcount as usize, p.kcountsize)]);
    }
}

fn write_call_graph(fd: c_int) {
    const NARCS_PER_WRITEV: usize = 32;
    let p = params();
    let tag: u8 = GMON_TAG_CG_ARC;
    let mut raw = [[0u8; 20]; NARCS_PER_WRITEV];
    let mut nfilled = 0usize;
    let flush = |raw: &[[u8; 20]; NARCS_PER_WRITEV], n: usize| {
        let mut iov = [(0usize, 0usize); 2 * NARCS_PER_WRITEV];
        for k in 0..n {
            iov[2 * k] = (&tag as *const u8 as usize, 1);
            iov[2 * k + 1] = (raw[k].as_ptr() as usize, 20);
        }
        writev_all(fd, &iov[..2 * n]);
    };
    let froms = unsafe { ffi::slice(p.froms, p.fromssize / size_of::<ArcIndex>()) };
    let tos = unsafe { ffi::slice(p.tos, if p.tos.is_null() { 0 } else { p.tolimit as usize }) };
    for (from_index, &first) in froms.iter().enumerate() {
        if first == 0 {
            continue;
        }
        let frompc = p.lowpc + (from_index as u64 * p.hashfraction * size_of::<ArcIndex>() as u64);
        let mut to_index = first;
        while to_index != 0 {
            let t = &tos[to_index as usize];
            raw[nfilled][0..8].copy_from_slice(&frompc.to_ne_bytes());
            raw[nfilled][8..16].copy_from_slice(&t.selfpc.to_ne_bytes());
            raw[nfilled][16..20].copy_from_slice(&(t.count as i32).to_ne_bytes());
            nfilled += 1;
            if nfilled == NARCS_PER_WRITEV {
                flush(&raw, nfilled);
                nfilled = 0;
            }
            to_index = t.link as u64;
        }
    }
    if nfilled > 0 {
        flush(&raw, nfilled);
    }
}

fn prefixed_name<'a>(prefix: &[u8], name: &'a mut [u8; 512]) -> &'a [u8] {
    let pid = rusty_libc_core::unistd::getpid() as u32;
    let mut n = 0usize;
    let take = prefix.len().min(name.len() - 24);
    name[..take].copy_from_slice(&prefix[..take]);
    n += take;
    name[n] = b'.';
    n += 1;
    let mut digits = [0u8; 10];
    let mut k = digits.len();
    let mut v = pid;
    loop {
        k -= 1;
        digits[k] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    name[n..n + digits.len() - k].copy_from_slice(&digits[k..]);
    n += digits.len() - k;
    name[n] = 0;
    &name[..=n]
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _mcleanup() {
    moncontrol(0);
    if params().state.load(Ordering::Relaxed) != GMON_PROF_ERROR {
        const O_WRONLY: usize = 1;
        const O_CREAT: usize = 0o100;
        const O_TRUNC: usize = 0o1000;
        const O_NOFOLLOW: usize = 0o400000;
        const O_CLOEXEC: usize = 0o2000000;
        const AT_FDCWD: usize = -100isize as usize;
        let flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC;
        let env = unsafe { rusty_libc_core::env::getenv(b"GMON_OUT_PREFIX") };
        let secure = rusty_libc_core::lock::secure();
        let mut buf = [0u8; 512];
        let name: &[u8] = match unsafe { ffi::cstr(env) } {
            Some(prefix) if !secure => prefixed_name(prefix.to_bytes(), &mut buf),
            _ => b"gmon.out\0",
        };
        let fd = unsafe { syscall4(257, AT_FDCWD, name.as_ptr() as usize, flags, 0o666) };
        match rusty_libc_core::syscall::check(fd) {
            Err(e) => {
                let mut ebuf = [0u8; 128];
                let text = rusty_libc_core::messages::strerror_r_text(e.0, &mut ebuf);
                let mut msg = [0u8; 160];
                let head = b"_mcleanup: gmon.out: ";
                msg[..head.len()].copy_from_slice(head);
                let tl = text.len().min(msg.len() - head.len() - 1);
                msg[head.len()..head.len() + tl].copy_from_slice(&text[..tl]);
                msg[head.len() + tl] = b'\n';
                err_out(&msg[..head.len() + tl + 1]);
            }
            Ok(fd) => {
                let fd = fd as c_int;
                let mut ghdr = [0u8; 20];
                ghdr[0..4].copy_from_slice(b"gmon");
                ghdr[4..8].copy_from_slice(&1i32.to_ne_bytes());
                let _ = rusty_libc_core::unistd::write_nocancel(fd, &ghdr);
                write_hist(fd);
                write_call_graph(fd);
                let _ = rusty_libc_core::unistd::close(fd);
            }
        }
    }
    with_params_mut(|p| {
        unsafe { rusty_libc_malloc::free(p.tos.cast()) };
        p.tos = core::ptr::null_mut();
    });
}

#[repr(C)]
pub struct Prof {
    pub pr_base: *mut c_void,
    pub pr_size: usize,
    pub pr_off: usize,
    pub pr_scale: c_ulong,
}

const PROF_UINT: c_int = 1;

#[derive(Clone, Copy)]
struct Region {
    start: usize,
    end: usize,
    base: *mut u8,
    nctr: usize,
    scale: u64,
}

#[derive(Clone, Copy)]
struct Sampling {
    regions: *mut Region,
    nregions: usize,
    overflow: *mut u8,
    uint_counters: bool,
}

static SAMPLING: SyncCell<Sampling> = SyncCell::new(Sampling { regions: core::ptr::null_mut(), nregions: 0, overflow: core::ptr::null_mut(), uint_counters: false });

static RUNNING: AtomicBool = AtomicBool::new(false);

static OLD_ACTION: SyncCell<Sigaction> = SyncCell::new(Sigaction { sa_handler: 0, sa_mask: Sigset { val: [0; 16] }, sa_flags: 0, sa_restorer: 0 });
static OLD_TIMER: SyncCell<Itimerval> = SyncCell::new(Itimerval {
    it_interval: rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: 0 },
    it_value: rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: 0 },
});

fn running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

fn set_running(v: bool) {
    RUNNING.store(v, Ordering::Relaxed);
}

fn set_sampling(v: Sampling) {
    unsafe { SAMPLING.write(v) };
}

unsafe fn bump(base: *mut u8, idx: usize, uint: bool) {
    if uint {
        let c = base.cast::<u32>().wrapping_add(idx);
        let v = unsafe { c.read_unaligned() };
        unsafe { c.write_unaligned(v.wrapping_add(1)) };
    } else {
        let c = base.cast::<u16>().wrapping_add(idx);
        let v = unsafe { c.read_unaligned() };
        unsafe { c.write_unaligned(v.wrapping_add(1)) };
    }
}

fn count_sample(pc: usize) {
    let s = unsafe { SAMPLING.read() };
    let regions = unsafe { ffi::slice(s.regions, s.nregions) };
    let csize: usize = if s.uint_counters { 4 } else { 2 };
    for r in regions {
        if pc >= r.start && pc < r.end {
            let idx = (((pc - r.start) / csize) as u128 * r.scale as u128) >> 16;
            if idx < r.nctr as u128 {
                unsafe { bump(r.base, idx as usize, s.uint_counters) };
            }
            return;
        }
    }
    if !s.overflow.is_null() {
        unsafe { bump(s.overflow, 0, s.uint_counters) };
    }
}

extern "C" fn profil_handler(_sig: c_int, _info: *mut c_void, uc: *mut c_void) {
    let pc = unsafe { (uc as *const u8).wrapping_add(40 + 16 * 8).cast::<u64>().read() } as usize;
    count_sample(pc);
}

fn stop_profiling() -> c_int {
    if !running() {
        return 0;
    }
    let r1 = unsafe { setitimer(2, OLD_TIMER.as_ptr(), core::ptr::null_mut()) };
    set_running(false);
    let r2 = if r1 < 0 { -1 } else { unsafe { rusty_libc_signal::action::sigaction(SIGPROF, OLD_ACTION.as_ptr(), core::ptr::null_mut()) } };
    let old = unsafe { SAMPLING.read() };
    set_sampling(Sampling { regions: core::ptr::null_mut(), nregions: 0, overflow: core::ptr::null_mut(), uint_counters: old.uint_counters });
    unsafe { rusty_libc_malloc::free(old.regions.cast()) };
    if r2 < 0 { -1 } else { 0 }
}

fn start_profiling(interval_usec: i64) -> c_int {
    let mut act = Sigaction { sa_handler: profil_handler as *const () as usize, sa_mask: Sigset { val: [0; 16] }, sa_flags: SA_SIGINFO | SA_RESTART, sa_restorer: 0 };
    unsafe { rusty_libc_signal::sigset::sigfillset(&mut act.sa_mask) };
    if unsafe { rusty_libc_signal::action::sigaction(SIGPROF, &act, OLD_ACTION.as_ptr()) } < 0 {
        return -1;
    }
    let tv = rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: interval_usec };
    let timer = Itimerval { it_interval: tv, it_value: tv };
    set_running(true);
    unsafe { setitimer(2, &timer, OLD_TIMER.as_ptr()) }
}

fn alloc_regions(n: usize) -> Option<*mut Region> {
    let reg = unsafe { rusty_libc_malloc::malloc(size_of::<Region>() * n) }.cast::<Region>();
    if reg.is_null() {
        rusty_libc_core::errno::set(12);
        return None;
    }
    Some(reg)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn profil(buffer: *mut u16, size: usize, offset: usize, scale: u32) -> c_int {
    if buffer.is_null() {
        return stop_profiling();
    }
    if running() && stop_profiling() < 0 {
        return -1;
    }
    let nctr = size / 2;
    let end = if scale == 0 { offset } else { offset + (((nctr as u128) << 16).div_ceil(scale as u128) as usize) * 2 };
    let Some(reg) = alloc_regions(1) else { return -1 };
    unsafe { reg.write(Region { start: offset, end, base: buffer.cast(), nctr, scale: scale as u64 }) };
    set_sampling(Sampling { regions: reg, nregions: 1, overflow: core::ptr::null_mut(), uint_counters: false });
    start_profiling(1_000_000 / __profile_frequency() as i64)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sprofil(profp: *mut Prof, profcnt: c_int, tvp: *mut rusty_libc_time::clock::Timeval, flags: u32) -> c_int {
    if profp.is_null() || profcnt <= 0 {
        return stop_profiling();
    }
    if running() && stop_profiling() < 0 {
        return -1;
    }
    let uint = flags & PROF_UINT as u32 != 0;
    let csize: usize = if uint { 4 } else { 2 };
    let Some(reg) = alloc_regions(profcnt as usize) else { return -1 };
    let profs = unsafe { ffi::slice(profp.cast_const(), profcnt as usize) };
    let mut n = 0usize;
    let mut overflow: *mut u8 = core::ptr::null_mut();
    for pr in profs {
        if pr.pr_off == 0 && pr.pr_scale == 2 {
            overflow = pr.pr_base.cast();
            continue;
        }
        let nctr = pr.pr_size / csize;
        let scale = pr.pr_scale;
        let end = if scale == 0 { pr.pr_off } else { pr.pr_off.wrapping_add((((nctr as u128) << 16).div_ceil(scale as u128) as usize) * csize) };
        unsafe { reg.wrapping_add(n).write(Region { start: pr.pr_off, end, base: pr.pr_base.cast(), nctr, scale }) };
        n += 1;
    }
    set_sampling(Sampling { regions: reg, nregions: n, overflow, uint_counters: uint });
    if let Some(tv) = unsafe { ffi::out(tvp) } {
        tv.tv_sec = 0;
        tv.tv_usec = 1_000_000 / __profile_frequency() as i64;
    }
    start_profiling(1)
}

