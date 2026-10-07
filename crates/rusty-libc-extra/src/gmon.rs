use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::sync::atomic::{AtomicI64, Ordering};
use rusty_libc_core::syscall::{syscall0, syscall1, syscall3, syscall4};
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
    pub state: c_long,
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
pub static mut _gmonparam: GmonParam = GmonParam {
    state: GMON_PROF_OFF,
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
};

static mut S_SCALE: i32 = 0;

fn params() -> *mut GmonParam {
    &raw mut _gmonparam
}

fn state_cell() -> &'static AtomicI64 {
    unsafe { AtomicI64::from_ptr(&raw mut (*params()).state) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __profile_frequency() -> c_int {
    100
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn moncontrol(mode: c_int) {
    unsafe {
        let p = params();
        if (*p).state == GMON_PROF_ERROR {
            return;
        }
        if mode != 0 {
            profil((*p).kcount, (*p).kcountsize, (*p).lowpc as usize, S_SCALE as u32);
            (*p).state = GMON_PROF_ON;
        } else {
            profil(core::ptr::null_mut(), 0, 0, 0);
            (*p).state = GMON_PROF_OFF;
        }
    }
}

fn err_out(msg: &[u8]) {
    unsafe { syscall3(1, 2, msg.as_ptr() as usize, msg.len()) };
}

const fn round_down(x: u64, to: u64) -> u64 {
    x / to * to
}
const fn round_up(x: u64, to: u64) -> u64 {
    x.div_ceil(to) * to
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __monstartup(lowpc: c_ulong, highpc: c_ulong) {
    unsafe {
        let p = params();
        if !(*p).tos.is_null() {
            return;
        }
        (*p).lowpc = round_down(lowpc, HISTFRACTION * size_of::<HistCounter>() as u64);
        (*p).highpc = round_up(highpc, HISTFRACTION * size_of::<HistCounter>() as u64);
        (*p).textsize = (*p).highpc - (*p).lowpc;
        (*p).kcountsize = round_up((*p).textsize / HISTFRACTION, size_of::<ArcIndex>() as u64) as usize;
        (*p).hashfraction = HASHFRACTION;
        (*p).log_hashfraction = -1;
        (*p).log_hashfraction = ((HASHFRACTION * size_of::<ArcIndex>() as u64).trailing_zeros()) as c_long;
        (*p).fromssize = ((*p).textsize / HASHFRACTION) as usize;
        let tolimit = (((*p).textsize * ARCDENSITY / 100) as i64).clamp(MINARCS, MAXARCS);
        (*p).tolimit = tolimit;
        (*p).tossize = tolimit as usize * size_of::<ToStruct>();
        let total = (*p).kcountsize + (*p).fromssize + (*p).tossize;
        let cp = rusty_libc_malloc::calloc(total, 1) as *mut u8;
        if cp.is_null() {
            err_out(b"monstartup: out of memory\n");
            (*p).tos = core::ptr::null_mut();
            (*p).state = GMON_PROF_ERROR;
            return;
        }
        (*p).tos = cp as *mut ToStruct;
        let mut q = cp.add((*p).tossize);
        (*p).kcount = q as *mut u16;
        q = q.add((*p).kcountsize);
        (*p).froms = q as *mut ArcIndex;
        (*(*p).tos).link = 0;
        let o = ((*p).highpc - (*p).lowpc) as i32;
        S_SCALE = if (*p).kcountsize < o as usize { ((*p).kcountsize as f32 / o as f32 * SCALE_1_TO_1 as f32) as i32 } else { SCALE_1_TO_1 };
        moncontrol(1);
    }
}

#[cfg(feature = "export")]
core::arch::global_asm!(".weak monstartup", ".set monstartup, __monstartup");

#[unsafe(no_mangle)]
pub extern "C" fn rl_mcount_internal(frompc: c_ulong, selfpc: c_ulong) {
    unsafe {
        let p = params();
        if state_cell().compare_exchange(GMON_PROF_ON, GMON_PROF_BUSY, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return;
        }
        let frompc = frompc.wrapping_sub((*p).lowpc);
        if frompc > (*p).textsize {
            state_cell().store(GMON_PROF_ON, Ordering::Release);
            return;
        }
        let i = (frompc >> (*p).log_hashfraction) as usize;
        let frompcindex = (*p).froms.add(i);
        let tos = (*p).tos;
        let mut toindex = *frompcindex;
        let overflow = |p: *mut GmonParam| {
            state_cell().store(GMON_PROF_ERROR, Ordering::Release);
            let _ = p;
        };
        if toindex == 0 {
            (*tos).link = (*tos).link.wrapping_add(1);
            toindex = (*tos).link as u64;
            if toindex as i64 >= (*p).tolimit {
                overflow(p);
                return;
            }
            *frompcindex = toindex;
            let top = tos.add(toindex as usize);
            (*top).selfpc = selfpc;
            (*top).count = 1;
            (*top).link = 0;
            state_cell().store(GMON_PROF_ON, Ordering::Release);
            return;
        }
        let mut top = tos.add(toindex as usize);
        if (*top).selfpc == selfpc {
            (*top).count += 1;
            state_cell().store(GMON_PROF_ON, Ordering::Release);
            return;
        }
        loop {
            if (*top).link == 0 {
                (*tos).link = (*tos).link.wrapping_add(1);
                toindex = (*tos).link as u64;
                if toindex as i64 >= (*p).tolimit {
                    overflow(p);
                    return;
                }
                top = tos.add(toindex as usize);
                (*top).selfpc = selfpc;
                (*top).count = 1;
                (*top).link = *frompcindex as u16;
                *frompcindex = toindex;
                break;
            }
            let prevtop = top;
            top = tos.add((*top).link as usize);
            if (*top).selfpc == selfpc {
                (*top).count += 1;
                toindex = (*prevtop).link as u64;
                (*prevtop).link = (*top).link;
                (*top).link = *frompcindex as u16;
                *frompcindex = toindex;
                break;
            }
        }
        state_cell().store(GMON_PROF_ON, Ordering::Release);
    }
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
    unsafe {
        syscall3(20, fd as usize, iov.as_ptr() as usize, iov.len());
    }
}

unsafe fn write_hist(fd: c_int) {
    unsafe {
        let p = params();
        if (*p).kcountsize > 0 {
            let tag: u8 = GMON_TAG_TIME_HIST;
            let mut thdr = [0u8; 40];
            thdr[0..8].copy_from_slice(&(*p).lowpc.to_ne_bytes());
            thdr[8..16].copy_from_slice(&(*p).highpc.to_ne_bytes());
            thdr[16..20].copy_from_slice(&((((*p).kcountsize / size_of::<HistCounter>()) as i32).to_ne_bytes()));
            thdr[20..24].copy_from_slice(&__profile_frequency().to_ne_bytes());
            thdr[24..31].copy_from_slice(b"seconds");
            thdr[39] = b's';
            writev_all(fd, &[(&tag as *const u8 as usize, 1), (thdr.as_ptr() as usize, 40), ((*p).kcount as usize, (*p).kcountsize)]);
        }
    }
}

unsafe fn write_call_graph(fd: c_int) {
    unsafe {
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
        let from_len = (*p).fromssize / size_of::<ArcIndex>();
        for from_index in 0..from_len {
            if *(*p).froms.add(from_index) == 0 {
                continue;
            }
            let frompc = (*p).lowpc + (from_index as u64 * (*p).hashfraction * size_of::<ArcIndex>() as u64);
            let mut to_index = *(*p).froms.add(from_index);
            while to_index != 0 {
                let t = (*p).tos.add(to_index as usize);
                raw[nfilled][0..8].copy_from_slice(&frompc.to_ne_bytes());
                raw[nfilled][8..16].copy_from_slice(&(*t).selfpc.to_ne_bytes());
                raw[nfilled][16..20].copy_from_slice(&((*t).count as i32).to_ne_bytes());
                nfilled += 1;
                if nfilled == NARCS_PER_WRITEV {
                    flush(&raw, nfilled);
                    nfilled = 0;
                }
                to_index = (*t).link as u64;
            }
        }
        if nfilled > 0 {
            flush(&raw, nfilled);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _mcleanup() {
    unsafe {
        moncontrol(0);
        let p = params();
        if (*p).state != GMON_PROF_ERROR {
            const O_WRONLY: usize = 1;
            const O_CREAT: usize = 0o100;
            const O_TRUNC: usize = 0o1000;
            const O_NOFOLLOW: usize = 0o400000;
            const O_CLOEXEC: usize = 0o2000000;
            const AT_FDCWD: usize = -100isize as usize;
            let flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC;
            let env = rusty_libc_core::env::getenv(b"GMON_OUT_PREFIX");
            let secure = syscall0(102) != syscall0(107) || syscall0(104) != syscall0(108);
            let fd: isize;
            if !env.is_null() && !secure {
                let prefix = core::ffi::CStr::from_ptr(env).to_bytes();
                let pid = syscall0(39) as u32;
                let mut name = [0u8; 512];
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
                fd = syscall4(257, AT_FDCWD, name.as_ptr() as usize, flags, 0o666) as isize;
            } else {
                fd = syscall4(257, AT_FDCWD, c"gmon.out".as_ptr() as usize, flags, 0o666) as isize;
            }
            if fd < 0 && fd > -4096 {
                let msg_err = (-fd) as i32;
                let text = rusty_libc_core::messages::error_message(msg_err).map(|c| c.to_bytes()).unwrap_or(b"Unknown error");
                let mut msg = [0u8; 160];
                let head = b"_mcleanup: gmon.out: ";
                msg[..head.len()].copy_from_slice(head);
                let tl = text.len().min(msg.len() - head.len() - 1);
                msg[head.len()..head.len() + tl].copy_from_slice(&text[..tl]);
                msg[head.len() + tl] = b'\n';
                err_out(&msg[..head.len() + tl + 1]);
            } else {
                let fd = fd as c_int;
                let mut ghdr = [0u8; 20];
                ghdr[0..4].copy_from_slice(b"gmon");
                ghdr[4..8].copy_from_slice(&1i32.to_ne_bytes());
                syscall3(1, fd as usize, ghdr.as_ptr() as usize, 20);
                write_hist(fd);
                write_call_graph(fd);
                syscall1(3, fd as usize);
            }
        }
        rusty_libc_malloc::free((*p).tos.cast());
        (*p).tos = core::ptr::null_mut();
    }
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

static mut REGIONS: *mut Region = core::ptr::null_mut();
static mut NREGIONS: usize = 0;
static mut OVERFLOW_CTR: *mut u8 = core::ptr::null_mut();
static mut UINT_COUNTERS: bool = false;
static mut RUNNING: bool = false;
static mut OLD_ACTION: Sigaction = Sigaction { sa_handler: 0, sa_mask: Sigset { val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
static mut OLD_TIMER: Itimerval = Itimerval { it_interval: rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: 0 }, it_value: rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: 0 } };

unsafe fn bump(base: *mut u8, idx: usize) {
    unsafe {
        if UINT_COUNTERS {
            let c = (base as *mut u32).add(idx);
            c.write_unaligned(c.read_unaligned().wrapping_add(1));
        } else {
            let c = (base as *mut u16).add(idx);
            c.write_unaligned(c.read_unaligned().wrapping_add(1));
        }
    }
}

unsafe fn count_sample(pc: usize) {
    unsafe {
        let csize: usize = if UINT_COUNTERS { 4 } else { 2 };
        for i in 0..NREGIONS {
            let r = *REGIONS.add(i);
            if pc >= r.start && pc < r.end {
                let idx = (((pc - r.start) / csize) as u128 * r.scale as u128) >> 16;
                if idx < r.nctr as u128 {
                    bump(r.base, idx as usize);
                }
                return;
            }
        }
        if !OVERFLOW_CTR.is_null() {
            bump(OVERFLOW_CTR, 0);
        }
    }
}

extern "C" fn profil_handler(_sig: c_int, _info: *mut c_void, uc: *mut c_void) {
    let pc = unsafe { *((uc as *const u8).add(40 + 16 * 8) as *const u64) } as usize;
    unsafe { count_sample(pc) };
}

unsafe fn stop_profiling() -> c_int {
    unsafe {
        if !RUNNING {
            return 0;
        }
        let r1 = setitimer(2, &raw const OLD_TIMER, core::ptr::null_mut());
        RUNNING = false;
        let r2 = if r1 < 0 { -1 } else { rusty_libc_signal::action::sigaction(SIGPROF, &raw const OLD_ACTION, core::ptr::null_mut()) };
        rusty_libc_malloc::free(REGIONS.cast());
        REGIONS = core::ptr::null_mut();
        NREGIONS = 0;
        OVERFLOW_CTR = core::ptr::null_mut();
        if r2 < 0 { -1 } else { 0 }
    }
}

unsafe fn start_profiling(interval_usec: i64) -> c_int {
    unsafe {
        let mut act = Sigaction { sa_handler: profil_handler as *const () as usize, sa_mask: Sigset { val: [0; 16] }, sa_flags: SA_SIGINFO | SA_RESTART, sa_restorer: 0 };
        rusty_libc_signal::sigset::sigfillset(&mut act.sa_mask);
        if rusty_libc_signal::action::sigaction(SIGPROF, &act, &raw mut OLD_ACTION) < 0 {
            return -1;
        }
        let tv = rusty_libc_time::clock::Timeval { tv_sec: 0, tv_usec: interval_usec };
        let timer = Itimerval { it_interval: tv, it_value: tv };
        RUNNING = true;
        setitimer(2, &timer, &raw mut OLD_TIMER)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn profil(buffer: *mut u16, size: usize, offset: usize, scale: u32) -> c_int {
    unsafe {
        if buffer.is_null() {
            return stop_profiling();
        }
        if RUNNING && stop_profiling() < 0 {
            return -1;
        }
        let nctr = size / 2;
        let end = if scale == 0 { offset } else { offset + (((nctr as u128) << 16).div_ceil(scale as u128) as usize) * 2 };
        let reg = rusty_libc_malloc::malloc(size_of::<Region>()) as *mut Region;
        if reg.is_null() {
            rusty_libc_core::errno::set(12);
            return -1;
        }
        reg.write(Region { start: offset, end, base: buffer.cast(), nctr, scale: scale as u64 });
        REGIONS = reg;
        NREGIONS = 1;
        OVERFLOW_CTR = core::ptr::null_mut();
        UINT_COUNTERS = false;
        start_profiling(1_000_000 / __profile_frequency() as i64)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sprofil(profp: *mut Prof, profcnt: c_int, tvp: *mut rusty_libc_time::clock::Timeval, flags: u32) -> c_int {
    unsafe {
        if profp.is_null() || profcnt <= 0 {
            return stop_profiling();
        }
        if RUNNING && stop_profiling() < 0 {
            return -1;
        }
        let uint = flags & PROF_UINT as u32 != 0;
        let csize: usize = if uint { 4 } else { 2 };
        let reg = rusty_libc_malloc::malloc(size_of::<Region>() * profcnt as usize) as *mut Region;
        if reg.is_null() {
            rusty_libc_core::errno::set(12);
            return -1;
        }
        let mut n = 0usize;
        let mut overflow: *mut u8 = core::ptr::null_mut();
        for i in 0..profcnt as usize {
            let pr = &*profp.add(i);
            if pr.pr_off == 0 && pr.pr_scale == 2 {
                overflow = pr.pr_base.cast();
                continue;
            }
            let nctr = pr.pr_size / csize;
            let scale = pr.pr_scale;
            let end = if scale == 0 { pr.pr_off } else { pr.pr_off.wrapping_add((((nctr as u128) << 16).div_ceil(scale as u128) as usize) * csize) };
            reg.add(n).write(Region { start: pr.pr_off, end, base: pr.pr_base.cast(), nctr, scale });
            n += 1;
        }
        REGIONS = reg;
        NREGIONS = n;
        OVERFLOW_CTR = overflow;
        UINT_COUNTERS = uint;
        if !tvp.is_null() {
            (*tvp).tv_sec = 0;
            (*tvp).tv_usec = 1_000_000 / __profile_frequency() as i64;
        }
        start_profiling(1)
    }
}

#[allow(dead_code)]
fn _unused(_: *const c_char) {}

