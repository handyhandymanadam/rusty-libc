use crate::attr::*;
use crate::cancel;
use crate::key::KeyData;
use crate::sys::*;
use core::arch::global_asm;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::syscall::{syscall2, syscall3, syscall4};
use rusty_libc_core::tls::{self, DebugArg, TCB_SIZE, Tcb};

pub type StartFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

pub const JOINABLE: u32 = 0;
pub const DETACHED: u32 = 1;
pub const JOINING: u32 = 2;
pub const EXITED: u32 = 3;

pub const FLAG_USER_STACK: u32 = 1;

const CLONE_FLAGS: usize = 0x100  | 0x200  | 0x400  | 0x800  | 0x10000
    | 0x40000  | 0x80000  | 0x100000  | 0x200000 ;

pub use rusty_libc_core::tls::RobustHead;

#[repr(C)]
pub struct Thread {
    pub tcb: Tcb,
    pub joinstate: AtomicU32,
    pub flags: u32,
    pub result: *mut c_void,
    pub start: Option<StartFn>,
    pub arg: *mut c_void,
    pub mapping: *mut u8,
    pub mapping_size: usize,
    pub guard_size: usize,
    pub stack_lo: *mut u8,
    pub stack_size: usize,
    pub unwind: *mut cancel::UnwindBuf,
    pub exit_value: *mut c_void,
    pub exc: cancel::UnwindException,
    pub gate: AtomicU32,
    pub start_mask: u64,
    pub list_next: *mut Thread,
    pub list_prev: *mut Thread,
    pub block_base: *mut u8,
    pub block_size: usize,
    pub attr_flags: i32,
    pub sched: Sched,
    pub tpp: *mut crate::tpp::Tpp,
    pub specific_1st: [KeyData; 32],
    pub specific_2nd: *mut KeyData,
    pub dtv_block: usize,
    pub lock: RawMutex,
    pub xid: AtomicU32,
    pub setxid_futex: AtomicU32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sched {
    pub policy: i32,
    pub prio: i32,
    pub flags: i32,
}

impl Sched {
    pub fn fill(&mut self, tid: i32) -> c_int {
        let mut result = 0;
        if self.flags & ATTR_FLAG_SCHED_SET == 0 {
            let mut sp = SchedParam::default();
            let e = errno_of(unsafe { syscall2(SYS_SCHED_GETPARAM, tid as usize, &mut sp as *mut SchedParam as usize) });
            if e != 0 {
                result = e;
            } else {
                self.prio = sp.sched_priority;
                self.flags |= ATTR_FLAG_SCHED_SET;
            }
        }
        if self.flags & ATTR_FLAG_POLICY_SET == 0 {
            let r = syscall_getscheduler(tid);
            let e = errno_of(r as isize as usize);
            if e != 0 {
                self.policy = -1;
                result = e;
            } else {
                self.policy = r;
                self.flags |= ATTR_FLAG_POLICY_SET;
            }
        }
        result
    }
}

pub unsafe fn with_sched_locked<R>(t: *mut Thread, f: impl FnOnce(&mut Sched) -> R) -> R {
    let lock = unsafe { shared_field(field_of!(t, lock: RawMutex)) };
    lock.lock_always();
    let r = f(unsafe { &mut *field_of!(t, sched: Sched) });
    lock.unlock_always();
    r
}

const _: () = assert!(core::mem::size_of::<Thread>() <= TCB_SIZE);
const _: () = assert!(core::mem::offset_of!(Thread, tcb) == 0);

#[inline(always)]
pub fn current_thread() -> *mut Thread {
    tls::current() as *mut Thread
}

macro_rules! field_of {
    ($t:expr, $($f:ident).+ : $ty:ty) => {
        ($t).cast::<u8>().wrapping_add(core::mem::offset_of!(crate::thread::Thread, $($f).+)).cast::<$ty>()
    };
}
pub(crate) use field_of;

#[inline(always)]
pub unsafe fn tid_word<'a>(t: *mut Thread) -> &'a core::sync::atomic::AtomicI32 {
    unsafe { &*field_of!(t, tcb.tid: core::sync::atomic::AtomicI32) }
}

#[inline(always)]
pub unsafe fn shared_field<'a, T>(p: *mut T) -> &'a T {
    unsafe { &*p }
}

static LIST_LOCK: RawMutex = RawMutex::new();
static MAIN_TD: core::sync::atomic::AtomicPtr<Thread> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static MAIN_GONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct Lists {
    all: *mut Thread,
    free: *mut Thread,
}

static LISTS: SyncCell<Lists> = SyncCell::new(Lists { all: core::ptr::null_mut(), free: core::ptr::null_mut() });

fn with_lists<R>(f: impl FnOnce(&mut Lists) -> R) -> R {
    LIST_LOCK.lock_always();
    let r = unsafe { LISTS.with_unsync(f) };
    LIST_LOCK.unlock_always();
    r
}

#[cfg_attr(feature = "export", unsafe(export_name = "__nptl_nthreads"))]
static THREAD_COUNT: AtomicUsize = AtomicUsize::new(1);
const CACHE_MAX: usize = 32;

static DEFAULT_LOCK: RawMutex = RawMutex::new();
static DEFAULT_ATTR: SyncCell<PthreadAttr> = SyncCell::new(PthreadAttr::new());

fn with_default<R>(f: impl FnOnce(&mut PthreadAttr) -> R) -> R {
    DEFAULT_LOCK.lock_always();
    let r = unsafe { DEFAULT_ATTR.with_unsync(f) };
    DEFAULT_LOCK.unlock_always();
    r
}

macro_rules! fixed {
    ($t:expr, $($f:ident).+ : $ty:ty) => {{
        unsafe { *field_of!($t, $($f).+ : $ty) }
    }};
}

fn rlimit_stack() -> usize {
    let mut lim = [0u64; 2];
    let r = unsafe { syscall4(SYS_PRLIMIT64, 0, 3, 0, lim.as_mut_ptr() as usize) };
    let cur = if errno_of(r) == 0 { lim[0] } else { 8 << 20 };
    if cur == u64::MAX {
        2 << 20
    } else {
        align_up((cur as usize).max(PTHREAD_STACK_MIN), PAGE)
    }
}

pub fn default_stacksize() -> usize {
    with_default(|d| {
        if d.stacksize == 0 {
            d.stacksize = rlimit_stack();
        }
        d.stacksize
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_default_np(attr: *mut PthreadAttr) -> c_int {
    default_stacksize();
    let (copy, r) = with_default(|d| match d.duplicate() {
        Ok(c) => (c, 0),
        Err((c, e)) => (c, e),
    });
    unsafe { write_attr(attr, copy) };
    r
}

pub fn setattr_default(a: &PthreadAttr) -> c_int {
    if !(SCHED_OTHER..=SCHED_RR).contains(&a.schedpolicy) {
        return EINVAL;
    }
    if a.schedparam.sched_priority > 0 {
        let mut tmp = PthreadAttr::new();
        tmp.schedpolicy = a.schedpolicy;
        let r = tmp.set_schedparam(&a.schedparam);
        if r != 0 {
            return r;
        }
    }
    if a.stacksize != 0 && a.stacksize < PTHREAD_STACK_MIN {
        return EINVAL;
    }
    if a.flags & ATTR_FLAG_STACKADDR != 0 {
        return EINVAL;
    }
    let mut tmp = match a.duplicate() {
        Ok(t) => t,
        Err((_, e)) => return e,
    };
    let keep = default_stacksize();
    with_default(|d| {
        if tmp.stacksize == 0 {
            tmp.stacksize = keep;
        }
        d.destroy();
        *d = tmp;
    });
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const PthreadAttr) -> c_int {
    setattr_default(unsafe { arg(attr) })
}

global_asm!(
    ".text",
    ".globl rl_clone",
    ".type rl_clone, @function",
    "rl_clone:",
    "mov r11, qword ptr [rsp + 8]",
    "and rsi, -16",
    "sub rsi, 16",
    "mov qword ptr [rsi], r9",
    "mov qword ptr [rsi + 8], r11",
    "mov r10, rcx",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jnz 1f",
    "xor ebp, ebp",
    "pop rax",
    "pop rdi",
    "call rax",
    "ud2",
    "1:",
    "ret",
    ".size rl_clone, . - rl_clone",
);

global_asm!(
    ".text",
    ".globl rl_clone3",
    ".type rl_clone3, @function",
    "rl_clone3:",
    "mov r8, rcx",
    "mov r9, rdx",
    "mov eax, 435",
    "syscall",
    "test rax, rax",
    "jnz 1f",
    "xor ebp, ebp",
    "mov rdi, r8",
    "call r9",
    "ud2",
    "1:",
    "ret",
    ".size rl_clone3, . - rl_clone3",
);

unsafe extern "C" {
    fn rl_clone(flags: usize, stack: *mut u8, ptid: *mut i32, ctid: *mut i32, tls: *mut Tcb, f: unsafe extern "C" fn(*mut Thread) -> !, arg: *mut Thread) -> isize;
    fn rl_clone3(args: *mut CloneArgs, size: usize, f: unsafe extern "C" fn(*mut Thread) -> !, arg: *mut Thread) -> isize;
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

static CLONE3_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);

unsafe fn spawn_kernel_thread(t: *mut Thread) -> isize {
    let tidp = field_of!(t, tcb.tid: i32);
    let base = fixed!(t, block_base: *mut u8);
    let top = (base as usize) & !15;
    if CLONE3_OK.load(Ordering::Relaxed) == 1 {
        let lo = fixed!(t, stack_lo: *mut u8) as usize;
        let mut args = CloneArgs {
            flags: CLONE_FLAGS as u64,
            pidfd: 0,
            child_tid: tidp as u64,
            parent_tid: tidp as u64,
            exit_signal: 0,
            stack: lo as u64,
            stack_size: (top - lo) as u64,
            tls: t as u64,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        let r = unsafe { rl_clone3(&mut args, core::mem::size_of::<CloneArgs>(), thread_entry, t) };
        if r != -38 {
            return r;
        }
        CLONE3_OK.store(0, Ordering::Relaxed);
    }
    unsafe { rl_clone(CLONE_FLAGS, base, tidp, tidp, t as *mut Tcb, thread_entry, t) }
}

unsafe fn list_insert_all(l: &mut Lists, t: *mut Thread) {
    unsafe { list_insert_all_only(l, t) };
    unsafe { rusty_libc_core::thread_db::add(t as *mut Tcb) };
}

unsafe fn list_insert_all_only(l: &mut Lists, t: *mut Thread) {
    unsafe { *field_of!(t, list_prev: *mut Thread) = core::ptr::null_mut() };
    unsafe { *field_of!(t, list_next: *mut Thread) = l.all };
    if !l.all.is_null() {
        unsafe { *field_of!(l.all, list_prev: *mut Thread) = t };
    }
    l.all = t;
}

unsafe fn list_remove_all(l: &mut Lists, t: *mut Thread) {
    let p = unsafe { *field_of!(t, list_prev: *mut Thread) };
    let n = unsafe { *field_of!(t, list_next: *mut Thread) };
    if p.is_null() {
        if l.all == t {
            l.all = n;
        }
    } else {
        unsafe { *field_of!(p, list_next: *mut Thread) = n };
    }
    if !n.is_null() {
        unsafe { *field_of!(n, list_prev: *mut Thread) = p };
    }
    unsafe { *field_of!(t, list_next: *mut Thread) = core::ptr::null_mut() };
    unsafe { *field_of!(t, list_prev: *mut Thread) = core::ptr::null_mut() };
    unsafe { rusty_libc_core::thread_db::remove(t as *mut Tcb) };
}

#[inline]
unsafe fn next_of(t: *mut Thread) -> *mut Thread {
    unsafe { *field_of!(t, list_next: *mut Thread) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_walk_threads(cb: unsafe extern "C" fn(usize, usize), arg: usize) {
    let main = if rusty_libc_core::lock::libc_initial() { tls::main_thread_pointer() } else { 0 };
    if main != 0 {
        unsafe { cb(main, arg) };
    }
    with_lists(|l| {
        let mut cur = l.all;
        while !cur.is_null() {
            if unsafe { tid_of(cur) } > 0 && cur as usize != main {
                unsafe { cb(cur as usize, arg) };
            }
            cur = unsafe { next_of(cur) };
        }
    })
}

pub type Walker<'a> = &'a dyn Fn(&mut dyn FnMut(*mut Thread));

pub fn with_thread_list<R>(f: impl FnOnce(Walker<'_>) -> R) -> R {
    let me = current_thread();
    with_lists(|l| {
        let all = l.all;
        let walk = |g: &mut dyn FnMut(*mut Thread)| {
            let mut cur = all;
            while !cur.is_null() {
                let next = unsafe { next_of(cur) };
                if cur != me {
                    g(cur);
                }
                cur = next;
            }
            let main = MAIN_TD.load(Ordering::Relaxed);
            if !main.is_null() && main != me {
                g(main);
            }
        };
        f(&walk)
    })
}

unsafe fn release(t: *mut Thread) {
    unsafe { crate::tpp::free_table(t) };
    with_lists(|l| {
        unsafe { list_remove_all(l, t) };
        if fixed!(t, flags: u32) & FLAG_USER_STACK == 0 && !fixed!(t, mapping: *mut u8).is_null() {
            if tls::debug_tls_on() {
                let tid = unsafe { tid_of(t) };
                tls::debug_tls(&[DebugArg::S(b"TCB deallocated into cache: TID="), DebugArg::D(tid.max(0) as i64), DebugArg::S(b", TCB="), DebugArg::X(t as usize)]);
            }
            unsafe { *field_of!(t, list_next: *mut Thread) = l.free };
            l.free = t;
        }
    })
}

#[inline]
unsafe fn tid_of(t: *mut Thread) -> i32 {
    unsafe { tid_word(t) }.load(Ordering::Acquire)
}

fn reap_and_find(l: &mut Lists, total: usize, guard: usize) -> *mut Thread {
    let mut cached = 0usize;
    let mut found: *mut Thread = core::ptr::null_mut();
    let mut prev: *mut Thread = core::ptr::null_mut();
    let mut cur = l.free;
    while !cur.is_null() {
        let next = unsafe { next_of(cur) };
        let tid = unsafe { tid_of(cur) };
        let dead = tid <= 0;
        let mut remove = false;
        if dead {
            let (msize, gsize) = (fixed!(cur, mapping_size: usize), fixed!(cur, guard_size: usize));
            if found.is_null() && msize == total && gsize == guard {
                unsafe { tls::release_block(cur as *mut Tcb) };
                found = cur;
                remove = true;
            } else if cached >= CACHE_MAX || msize > (64 << 20) {
                let m = fixed!(cur, mapping: *mut u8);
                if tls::debug_tls_on() {
                    tls::debug_tls(&[DebugArg::S(b"TCB cache full, deallocating: TID="), DebugArg::D(tid.max(0) as i64), DebugArg::S(b", TCB="), DebugArg::X(cur as usize)]);
                    tls::debug_tls(&[DebugArg::S(b"TCB deallocating: "), DebugArg::X(cur as usize), DebugArg::S(b" (dealloc_tcb=0)")]);
                }
                unsafe { tls::release_block(cur as *mut Tcb) };
                if prev.is_null() {
                    l.free = next;
                } else {
                    unsafe { *field_of!(prev, list_next: *mut Thread) = next };
                }
                unsafe { munmap(m, msize) };
                cur = next;
                continue;
            } else {
                cached += 1;
            }
        }
        if remove {
            if prev.is_null() {
                l.free = next;
            } else {
                unsafe { *field_of!(prev, list_next: *mut Thread) = next };
            }
        } else {
            prev = cur;
        }
        cur = next;
    }
    found
}

struct Params<'a> {
    stacksize: usize,
    guardsize: usize,
    user_top: *mut u8,
    detached: bool,
    explicit_sched: bool,
    policy: c_int,
    param: SchedParam,
    affinity: Option<&'a [u8]>,
    sigmask: Option<u64>,
    attr_flags: i32,
}

fn resolve(attr: Option<&PthreadAttr>) -> Params<'_> {
    let defsize = default_stacksize();
    let copy;
    let mut default_mask: Option<u64> = None;
    let a: &PthreadAttr = match attr {
        None => {
            copy = with_default(|d| {
                default_mask = d.sigmask();
                PthreadAttr { extension: core::ptr::null_mut(), ..*d }
            });
            &copy
        }
        Some(a) => a,
    };
    Params {
        stacksize: if a.stacksize != 0 { a.stacksize } else { defsize },
        guardsize: a.guardsize,
        user_top: if a.flags & ATTR_FLAG_STACKADDR != 0 { a.stackaddr as *mut u8 } else { core::ptr::null_mut() },
        detached: a.flags & ATTR_FLAG_DETACHSTATE != 0,
        explicit_sched: a.flags & ATTR_FLAG_NOTINHERITSCHED != 0 && a.flags & (ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET) != 0,
        policy: if a.flags & ATTR_FLAG_POLICY_SET != 0 { a.schedpolicy } else { -1 },
        param: if a.flags & ATTR_FLAG_SCHED_SET != 0 { a.schedparam } else { SchedParam { sched_priority: -1 } },
        affinity: attr.and_then(PthreadAttr::ext).map(AttrExt::cpuset).filter(|c| !c.is_empty()),
        attr_flags: a.flags & ATTR_FLAG_NOTINHERITSCHED,
        sigmask: a.sigmask().or(default_mask),
    }
}

macro_rules! own {
    ($t:expr, $($f:ident).+ : $ty:ty) => {{
        unsafe { *field_of!($t, $($f).+ : $ty) }
    }};
}

unsafe extern "C" fn thread_entry(t: *mut Thread) -> ! {
    unsafe { crate::setxid::thread_started(t) };
    unsafe { tls::robust_register(t as *mut Tcb) };
    sigprocmask_set(2, own!(t, start_mask: u64));
    if tls::debug_tls_on() {
        tls::debug_tls(&[DebugArg::S(b"Thread starting: TID="), DebugArg::D(raw_gettid() as i64), DebugArg::S(b", TCB="), DebugArg::X(t as usize)]);
    }
    unsafe { tls::sync_new_thread(t as *mut Tcb) };
    let gate = unsafe { shared_field(field_of!(t, gate: AtomicU32)) };
    loop {
        let g = gate.load(Ordering::Acquire);
        if g != 1 {
            if g == 3 {
                unsafe { crate::setxid::set_exiting(t) };
                unsafe { crate::setxid::exit_wait(t) };
                exit_thread();
            }
            break;
        }
        futex_wait(gate, 1, true);
    }
    let start = own!(t, start: Option<StartFn>);
    let f = unsafe { start.unwrap_unchecked() };
    let a = own!(t, arg: *mut c_void);
    let r = unsafe { f(a) };
    thread_exit(r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_create(newthread: *mut PthreadT, attr: *const PthreadAttr, start: unsafe extern "C" fn(*mut c_void) -> *mut c_void, arg: *mut c_void) -> c_int {
    crate::atfork::install_fork_hook();
    rusty_libc_core::lock::note_multithreaded();
    cancel::ensure_init();
    let me = current_thread();
    if MAIN_TD.load(Ordering::Relaxed).is_null() && unsafe { is_main_thread(me) } && !MAIN_GONE.load(Ordering::Relaxed) {
        MAIN_TD.store(me, Ordering::Relaxed);
    }
    crate::setxid::init();
    let p = resolve(unsafe { attr.as_ref() });
    match unsafe { create(&p, start, arg) } {
        Ok(t) => {
            unsafe { *newthread = t as PthreadT };
            0
        }
        Err(e) => e,
    }
}

unsafe fn create(p: &Params<'_>, start: StartFn, arg: *mut c_void) -> Result<*mut Thread, c_int> {
    let me = current_thread();
    let tpl = tls::template();
    let (block_size, _tp_off) = tls::block_layout(&tpl);
    let align = tpl.align.max(64);
    let (canary, pguard) = (own!(me, tcb.stack_guard: usize), own!(me, tcb.pointer_guard: usize));
    let (t, mapping);
    if !p.user_top.is_null() {
        if p.stacksize < block_size + 2048 {
            return Err(EINVAL);
        }
        let base = ((p.user_top as usize - block_size) & !(align - 1)) as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, block_size) };
        let tp = unsafe { tls::setup_block(base, &tpl, canary, pguard) } as *mut Thread;
        let td = unsafe { &mut *tp };
        td.dtv_block = unsafe { tls::dtv_allocation(tp as *mut Tcb) };
        t = tp;
        mapping = core::ptr::null_mut();
        td.flags = FLAG_USER_STACK;
        td.stack_lo = p.user_top.wrapping_sub(p.stacksize);
        td.stack_size = p.stacksize;
        td.block_base = base;
        if tls::debug_tls_on() {
            tls::debug_tls(&[
                DebugArg::S(b"TCB for user-supplied stack created: "),
                DebugArg::X(t as usize),
                DebugArg::S(b", stack="),
                DebugArg::X(td.stack_lo as usize),
                DebugArg::S(b", size="),
                DebugArg::D(p.stacksize as i64),
            ]);
        }
    } else {
        let guard = align_up(p.guardsize, PAGE);
        let size = align_up(p.stacksize, PAGE);
        if size < align_up(guard + block_size + 2048, PAGE) {
            return Err(EINVAL);
        }
        let extra = if size < 65536 { PAGE } else { 0 };
        let total = size + guard + extra;
        let reuse = with_lists(|l| reap_and_find(l, total, guard));
        let map;
        if reuse.is_null() {
            map = match mmap(total, 3) {
                Ok(m) => m,
                Err(_) => return Err(EAGAIN),
            };
            if guard != 0 && unsafe { mprotect(map, guard, 0) } != 0 {
                unsafe { munmap(map, total) };
                return Err(EAGAIN);
            }
        } else {
            map = fixed!(reuse, mapping: *mut u8);
        }
        mapping = map;
        let mapping_size = total;
        let base = (((map as usize + total) - block_size) & !(align - 1)) as *mut u8;
        if !reuse.is_null() {
            unsafe { core::ptr::write_bytes(base, 0, block_size) };
        }
        let tp = unsafe { tls::setup_block(base, &tpl, canary, pguard) } as *mut Thread;
        t = tp;
        let td = unsafe { &mut *tp };
        td.dtv_block = unsafe { tls::dtv_allocation(tp as *mut Tcb) };
        if tls::debug_tls_on() {
            if reuse.is_null() {
                tls::debug_tls(&[DebugArg::S(b"TCB for new stack allocated: "), DebugArg::X(t as usize)]);
            } else {
                tls::debug_tls(&[DebugArg::S(b"TLS TCB reused from cache: "), DebugArg::X(t as usize)]);
            }
        }
        td.flags = 0;
        td.mapping = mapping;
        td.mapping_size = mapping_size;
        td.guard_size = guard;
        td.stack_lo = map.wrapping_add(guard);
        td.stack_size = total - guard;
        td.block_base = base;
    }
    let gated = p.explicit_sched || p.affinity.is_some();
    {
        let td = unsafe { &mut *t };
        td.block_size = block_size;
        td.attr_flags = p.attr_flags;
        td.sched = own!(me, sched: Sched);
        td.tpp = core::ptr::null_mut();
        td.tcb.multiple_threads = 1;
        td.tcb.tid = 0;
        td.start = Some(start);
        td.tcb.db_start = start as usize;
        td.arg = arg;
        td.joinstate.store(if p.detached { DETACHED } else { JOINABLE }, Ordering::Relaxed);
        td.xid.store(0, Ordering::Relaxed);
        td.setxid_futex.store(crate::setxid::FUTEX_NOT_STARTED, Ordering::Relaxed);
        td.gate.store(if gated { 1 } else { 0 }, Ordering::Relaxed);
    }

    unsafe { *field_of!(me, tcb.multiple_threads: i32) = 1 };

    THREAD_COUNT.fetch_add(1, Ordering::AcqRel);
    with_lists(|l| unsafe { list_insert_all(l, t) });

    let all = sigprocmask_set(2, u64::MAX);
    unsafe { *field_of!(t, start_mask: u64) = p.sigmask.unwrap_or(all) };

    let r = unsafe { spawn_kernel_thread(t) };
    sigprocmask_set(2, all);
    let tid = unsafe { tid_word(t) };
    if r < 0 {
        unsafe { crate::setxid::thread_started(t) };
        THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
        with_lists(|l| unsafe { list_remove_all(l, t) });
        tid.store(-1, Ordering::Relaxed);
        if !mapping.is_null() {
            with_lists(|l| {
                unsafe { *field_of!(t, list_next: *mut Thread) = l.free };
                l.free = t;
            });
        }
        return Err((-r) as c_int);
    }
    if gated {
        let mut err = 0;
        let ktid = tid.load(Ordering::Relaxed);
        if p.explicit_sched {
            let policy = if p.policy >= 0 { p.policy } else { syscall_getscheduler(0) };
            let mut param = SchedParam { sched_priority: 0 };
            if p.param.sched_priority >= 0 {
                param = p.param;
            } else {
                unsafe { syscall2(SYS_SCHED_GETPARAM, 0, &mut param as *mut SchedParam as usize) };
            }
            err = sched_setscheduler(ktid, policy, &param);
            if err == 0 {
                unsafe { *field_of!(t, sched: Sched) = Sched { policy, prio: param.sched_priority, flags: ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET } };
            }
        }
        if err == 0 {
            if let Some(set) = p.affinity {
                err = sched_setaffinity(ktid, set);
            }
        }
        let gate = unsafe { shared_field(field_of!(t, gate: AtomicU32)) };
        if err != 0 {
            gate.store(3, Ordering::Release);
            futex_wake(gate, 1, true);
            loop {
                let v = unsafe { tid_of(t) };
                if v == 0 {
                    break;
                }
                futex_wait(unsafe { shared_field(field_of!(t, tcb.tid: AtomicU32)) }, v as u32, false);
            }
            THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
            tid.store(-1, Ordering::Relaxed);
            unsafe { release(t) };
            return Err(err);
        }
        gate.store(2, Ordering::Release);
        futex_wake(gate, 1, true);
    }
    Ok(t)
}

fn syscall_getscheduler(tid: i32) -> c_int {
    unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GETSCHEDULER, tid as usize) as c_int }
}

pub fn thread_exit(retval: *mut c_void) -> ! {
    let t = current_thread();
    unsafe { cancel::word_of(t) }.fetch_or(cancel::EXITING_BIT | cancel::DISABLE_BIT, Ordering::AcqRel);
    unsafe { *field_of!(t, result: *mut c_void) = retval };
    rusty_libc_core::tls::run_thread_dtors();
    unsafe { crate::key::run_destructors(t) };
    unsafe { crate::key::free_second_level(t) };
    unsafe { rusty_libc_malloc::thread_shutdown() };
    unsafe { crate::setxid::set_exiting(t) };
    let is_main = unsafe { is_main_thread(t) };
    let left = THREAD_COUNT.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        rusty_libc_core::process::exit(0);
    }
    if is_main {
        unsafe { crate::setxid::exit_wait(t) };
        exit_thread();
    }
    block_signals_for_exit();
    if fixed!(t, flags: u32) & FLAG_USER_STACK == 0 {
        let mapping = fixed!(t, mapping: *mut u8);
        unsafe { advise_stack_range(mapping) };
    }
    unsafe { crate::setxid::exit_wait(t) };
    let js = unsafe { shared_field(field_of!(t, joinstate: AtomicU32)) };
    loop {
        let s = js.load(Ordering::Acquire);
        match s {
            JOINABLE => {
                if js.compare_exchange(JOINABLE, EXITED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    break;
                }
            }
            DETACHED => {
                unsafe { release(t) };
                break;
            }
            _ => break,
        }
    }
    exit_thread();
}

#[inline]
fn block_signals_for_exit() {
    let set: u64 = !(1u64 << (cancel::SIGSETXID - 1));
    unsafe { syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 0, &set as *const u64 as usize, 0, 8) };
}

#[inline(never)]
unsafe fn advise_stack_range(mem: *mut u8) {
    const SYS_MADVISE: usize = 28;
    const MADV_DONTNEED: usize = 4;
    let marker = 0u8;
    let sp = core::hint::black_box(&raw const marker) as usize;
    let freesize = (sp - mem as usize) & !(PAGE - 1);
    if freesize > PTHREAD_STACK_MIN {
        unsafe { syscall3(SYS_MADVISE, mem as usize, freesize - PTHREAD_STACK_MIN, MADV_DONTNEED) };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    cancel::ensure_init();
    let t = current_thread();
    let w = unsafe { cancel::word_of(t) };
    w.fetch_or(cancel::EXITING_BIT | cancel::DISABLE_BIT, Ordering::AcqRel);
    w.fetch_and(!cancel::ASYNC_BIT, Ordering::AcqRel);
    unsafe { crate::setxid::set_exiting(t) };
    unsafe { *field_of!(t, exit_value: *mut c_void) = retval };
    unsafe { cancel::unwind_continue() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pthread_self() -> PthreadT {
    current_thread() as PthreadT
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_gettid_np(th: PthreadT) -> c_int {
    let tid = unsafe { tid_of(th as *mut Thread) };
    if tid > 0 { tid } else { -1 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pthread_equal(a: PthreadT, b: PthreadT) -> c_int {
    (a == b) as c_int
}

unsafe extern "C" fn join_cleanup(arg: *mut c_void) {
    unsafe { shared_field(field_of!(arg as *mut Thread, joinstate: AtomicU32)) }.store(JOINABLE, Ordering::Release);
}

pub unsafe fn join_common(th: PthreadT, retval: Option<&mut *mut c_void>, clock: c_int, abs: Option<&Timespec>, block: bool) -> c_int {
    let t = th as *mut Thread;
    if unsafe { tid_of(t) } < 0 {
        return ESRCH;
    }
    if t == current_thread() {
        return EDEADLK;
    }
    let js = unsafe { shared_field(field_of!(t, joinstate: AtomicU32)) };
    loop {
        let s = js.load(Ordering::Acquire);
        if s == DETACHED || s == JOINING {
            return EINVAL;
        }
        if js.compare_exchange(s, JOINING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            break;
        }
    }
    let mut result = 0;
    let tid_futex = unsafe { shared_field(field_of!(t, tcb.tid: AtomicU32)) };
    let body = || loop {
        if block {
            cancel::testcancel();
        }
        let tid = unsafe { tid_of(t) };
        if tid == 0 {
            return true;
        }
        if !block {
            result = EBUSY;
            return false;
        }
        let e = futex_wait_abs_cp(tid_futex, tid as u32, clock, abs, false);
        if e == ETIMEDOUT || e == EINVAL || e == EOVERFLOW {
            result = e;
            return false;
        }
    };
    let waited = unsafe { cancel::with_cleanup(join_cleanup, t as *mut c_void, body) };
    if !waited {
        js.store(JOINABLE, Ordering::Release);
        return result;
    }
    if let Some(r) = retval {
        *r = unsafe { *field_of!(t, result: *mut c_void) };
    }
    unsafe { tid_word(t) }.store(-1, Ordering::Relaxed);
    unsafe { release(t) };
    0
}

macro_rules! retval {
    ($p:expr) => {{
        unsafe { $p.as_mut() }
    }};
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(th: PthreadT, retval: *mut *mut c_void) -> c_int {
    let retval = retval!(retval);
    unsafe { join_common(th, retval, CLOCK_REALTIME, None, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_tryjoin_np(th: PthreadT, retval: *mut *mut c_void) -> c_int {
    let retval = retval!(retval);
    unsafe { join_common(th, retval, CLOCK_REALTIME, None, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_timedjoin_np(th: PthreadT, retval: *mut *mut c_void, abstime: *const Timespec) -> c_int {
    let abs = unsafe { abstime.as_ref() };
    let retval = retval!(retval);
    unsafe { join_common(th, retval, CLOCK_REALTIME, abs, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_clockjoin_np(th: PthreadT, retval: *mut *mut c_void, clockid: c_int, abstime: *const Timespec) -> c_int {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }
    let abs = unsafe { abstime.as_ref() };
    let retval = retval!(retval);
    unsafe { join_common(th, retval, clockid, abs, true) }
}

pub unsafe fn detach(th: PthreadT) -> c_int {
    let t = th as *mut Thread;
    if unsafe { tid_of(t) } < 0 {
        return ESRCH;
    }
    let js = unsafe { shared_field(field_of!(t, joinstate: AtomicU32)) };
    loop {
        let s = js.load(Ordering::Acquire);
        match s {
            JOINABLE => {
                if js.compare_exchange(JOINABLE, DETACHED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    return 0;
                }
            }
            EXITED => {
                if js.compare_exchange(EXITED, DETACHED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    unsafe { release(t) };
                    return 0;
                }
            }
            _ => return EINVAL,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(th: PthreadT) -> c_int {
    unsafe { detach(th) }
}

pub fn thread_count() -> usize {
    THREAD_COUNT.load(Ordering::Acquire)
}

pub unsafe fn is_main_thread(t: *mut Thread) -> bool {
    fixed!(t, mapping: *mut u8).is_null() && fixed!(t, flags: u32) & FLAG_USER_STACK == 0
}

pub unsafe fn after_fork_child() {
    let me = current_thread();
    unsafe { core::ptr::write(&raw const LIST_LOCK as *mut RawMutex, RawMutex::new()) };
    unsafe { core::ptr::write(&raw const DEFAULT_LOCK as *mut RawMutex, RawMutex::new()) };
    let unmap_others = |l: &mut Lists| {
        let mut cur = l.all;
        while !cur.is_null() {
            let next = unsafe { next_of(cur) };
            if cur != me && fixed!(cur, flags: u32) & FLAG_USER_STACK == 0 && !fixed!(cur, mapping: *mut u8).is_null() {
                let (m, n) = (fixed!(cur, mapping: *mut u8), fixed!(cur, mapping_size: usize));
                unsafe { munmap(m, n) };
            }
            cur = next;
        }
        let mut cur = l.free;
        while !cur.is_null() {
            let next = unsafe { next_of(cur) };
            let (m, n) = (fixed!(cur, mapping: *mut u8), fixed!(cur, mapping_size: usize));
            unsafe { munmap(m, n) };
            cur = next;
        }
        l.free = core::ptr::null_mut();
        l.all = core::ptr::null_mut();
    };
    unsafe { LISTS.with_unsync(unmap_others) };
    if MAIN_TD.load(Ordering::Relaxed) != me {
        MAIN_TD.store(core::ptr::null_mut(), Ordering::Relaxed);
        MAIN_GONE.store(true, Ordering::Relaxed);
    }
    unsafe { shared_field(field_of!(me, xid: AtomicU32)) }.store(0, Ordering::Relaxed);
    unsafe { shared_field(field_of!(me, setxid_futex: AtomicU32)) }.store(0, Ordering::Relaxed);
    if !unsafe { is_main_thread(me) } {
        let insert = |l: &mut Lists| {
            unsafe { list_insert_all_only(l, me) }
        };
        unsafe { LISTS.with_unsync(insert) };
    }
    unsafe { rusty_libc_core::thread_db::after_fork(me as *mut Tcb) };
    THREAD_COUNT.store(1, Ordering::Release);
    unsafe { cancel::word_of(me) }.fetch_and(!cancel::CANCELED_BIT, Ordering::AcqRel);
}

fn parse_hex(s: &[u8]) -> usize {
    let mut v = 0usize;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => break,
        };
        v = (v << 4) | d as usize;
    }
    v
}

fn find_mapping(addr: usize) -> Result<(usize, usize), c_int> {
    let fd = unsafe { rusty_libc_core::syscall::sys_open(c"/proc/self/maps".as_ptr() as usize, 0x80000, 0) };
    let e = errno_of(fd);
    if e != 0 {
        return Err(e);
    }
    let mut buf = [0u8; 4096];
    let mut have = 0usize;
    let mut result = Err(ENOENT);
    let mut last_to = 0usize;
    'outer: loop {
        let n = unsafe { syscall3(rusty_libc_core::syscall::SYS_READ, fd, buf[have..].as_mut_ptr() as usize, buf.len() - have) };
        if errno_of(n) != 0 || n == 0 {
            break;
        }
        have += n;
        let mut start = 0;
        while let Some(nl) = buf[start..have].iter().position(|&c| c == b'\n') {
            let line = &buf[start..start + nl];
            if let Some(dash) = line.iter().position(|&c| c == b'-') {
                let lo = parse_hex(&line[..dash]);
                let hi = parse_hex(&line[dash + 1..]);
                if lo <= addr && addr < hi {
                    result = Ok((last_to, hi));
                    break 'outer;
                }
                last_to = hi;
            }
            start += nl + 1;
        }
        buf.copy_within(start..have, 0);
        have -= start;
        if have == buf.len() {
            have = 0;
        }
    }
    let _ = rusty_libc_core::unistd::close(fd as i32);
    result
}

fn main_stack() -> Result<(usize, usize), c_int> {
    let mut end = tls::stack_end();
    if end == 0 {
        end = &raw const end as usize;
    }
    let (last_to, to) = find_mapping(end)?;
    let mut lim = [0u64; 2];
    let r = unsafe { syscall4(SYS_PRLIMIT64, 0, 3, 0, lim.as_mut_ptr() as usize) };
    let e = errno_of(r);
    if e != 0 {
        return Err(e);
    }
    let addr = (end & !(PAGE - 1)) + PAGE;
    let mut size = (lim[0] as usize).wrapping_sub(to - addr) & !(PAGE - 1);
    if size > addr - last_to {
        size = addr - last_to;
    }
    Ok((addr, size))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_np(th: PthreadT, attr: *mut PthreadAttr) -> c_int {
    unsafe { write_attr(attr, PthreadAttr::new()) };
    let a = unsafe { arg_mut(attr) };
    let t = th as *mut Thread;
    let body = |sched: &mut Sched| {
        unsafe { getattr_locked(t, a, *sched) }
    };
    let r = unsafe { with_sched_locked(t, body) };
    if r != 0 {
        a.destroy();
    }
    r
}

unsafe fn getattr_locked(t: *mut Thread, a: &mut PthreadAttr, sched: Sched) -> c_int {
    if unsafe { shared_field(field_of!(t, joinstate: AtomicU32)) }.load(Ordering::Acquire) == DETACHED {
        a.flags |= ATTR_FLAG_DETACHSTATE;
    }
    let tid = if t == current_thread() { gettid() } else { unsafe { tid_word(t) }.load(Ordering::Relaxed) };
    a.schedpolicy = sched.policy;
    a.schedparam = SchedParam { sched_priority: sched.prio };
    a.flags |= fixed!(t, attr_flags: i32) | sched.flags;
    if unsafe { is_main_thread(t) } {
        a.guardsize = 0;
        a.flags |= ATTR_FLAG_STACKADDR;
        match main_stack() {
            Ok((addr, size)) => {
                a.stackaddr = addr as *mut c_void;
                a.stacksize = size;
            }
            Err(e) => {
                return e;
            }
        }
    } else {
        let (mapping, mapping_size) = (fixed!(t, mapping: *mut u8), fixed!(t, mapping_size: usize));
        a.stackaddr = (mapping as usize + mapping_size) as *mut c_void;
        if fixed!(t, flags: u32) & FLAG_USER_STACK != 0 {
            let (lo, size) = (fixed!(t, stack_lo: *mut u8), fixed!(t, stack_size: usize));
            a.stackaddr = lo.wrapping_add(size) as *mut c_void;
            a.stacksize = size;
            a.guardsize = 0;
        } else {
            let guard = fixed!(t, guard_size: usize);
            a.stacksize = mapping_size - guard;
            a.guardsize = guard;
        }
        a.flags |= ATTR_FLAG_STACKADDR;
    }
    let ks = kernel_cpumask_size();
    let Ok(e) = a.ext_alloc(ks) else { return ENOMEM };
    let r = sched_getaffinity(tid, e.room_mut(ks));
    if r > 0 {
        e.cpusetsize = r as usize;
    }
    0
}

