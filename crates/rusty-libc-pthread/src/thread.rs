use crate::attr::*;
use crate::cancel;
use crate::key::KeyData;
use crate::sys::*;
use core::arch::global_asm;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::syscall::{syscall2, syscall3, syscall4};
use rusty_libc_core::tls::{self, TCB_SIZE, Tcb};

pub type StartFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

pub const JOINABLE: u32 = 0;
pub const DETACHED: u32 = 1;
pub const JOINING: u32 = 2;
pub const EXITED: u32 = 3;

pub const FLAG_USER_STACK: u32 = 1;

const CLONE_FLAGS: usize = 0x100  | 0x200  | 0x400  | 0x800  | 0x10000
    | 0x40000  | 0x80000  | 0x100000  | 0x200000 ;

#[repr(C)]
pub struct RobustHead {
    pub list: *mut u8,
    pub futex_offset: isize,
    pub list_op_pending: *mut u8,
}

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
    pub robust_prev: *mut u8,
    pub robust: RobustHead,
    pub robust_registered: u32,
    pub gate: AtomicU32,
    pub start_mask: u64,
    pub list_next: *mut Thread,
    pub list_prev: *mut Thread,
    pub block_base: *mut u8,
    pub block_size: usize,
    pub attr_flags: i32,
    pub specific_1st: [KeyData; 32],
    pub specific_2nd: *mut KeyData,
}

const _: () = assert!(core::mem::size_of::<Thread>() <= TCB_SIZE);
const _: () = assert!(core::mem::offset_of!(Thread, tcb) == 0);

#[inline(always)]
pub fn current_thread() -> *mut Thread {
    tls::current() as *mut Thread
}

static LIST_LOCK: RawMutex = RawMutex::new();
static mut ALL_HEAD: *mut Thread = core::ptr::null_mut();
static mut FREE_HEAD: *mut Thread = core::ptr::null_mut();
static THREAD_COUNT: AtomicUsize = AtomicUsize::new(1);
const CACHE_MAX: usize = 32;

static DEFAULT_LOCK: RawMutex = RawMutex::new();
static mut DEFAULT_ATTR: PthreadAttr =
    PthreadAttr { schedparam: SchedParam { sched_priority: 0 }, schedpolicy: 0, flags: 0, guardsize: PAGE, stackaddr: core::ptr::null_mut(), stacksize: 0, extension: core::ptr::null_mut(), unused: core::ptr::null_mut() };

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
    DEFAULT_LOCK.lock_always();
    let mut s = unsafe { (*(&raw mut DEFAULT_ATTR)).stacksize };
    if s == 0 {
        s = rlimit_stack();
        unsafe { (*(&raw mut DEFAULT_ATTR)).stacksize = s };
    }
    DEFAULT_LOCK.unlock_always();
    s
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_default_np(attr: *mut PthreadAttr) -> c_int {
    default_stacksize();
    DEFAULT_LOCK.lock_always();
    let r = unsafe { attr_copy(attr, &raw const DEFAULT_ATTR) };
    DEFAULT_LOCK.unlock_always();
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const PthreadAttr) -> c_int {
    unsafe {
        let a = &*attr;
        if !(SCHED_OTHER..=SCHED_RR).contains(&a.schedpolicy) {
            return EINVAL;
        }
        if a.schedparam.sched_priority > 0 {
            let mut tmp = core::mem::MaybeUninit::<PthreadAttr>::zeroed().assume_init();
            tmp.schedpolicy = a.schedpolicy;
            let r = pthread_attr_setschedparam(&mut tmp, &a.schedparam);
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
        let mut tmp = core::mem::MaybeUninit::<PthreadAttr>::zeroed().assume_init();
        let r = attr_copy(&mut tmp, attr);
        if r != 0 {
            return r;
        }
        let keep = default_stacksize();
        DEFAULT_LOCK.lock_always();
        if tmp.stacksize == 0 {
            tmp.stacksize = keep;
        }
        pthread_attr_destroy(&raw mut DEFAULT_ATTR);
        core::ptr::write(&raw mut DEFAULT_ATTR, tmp);
        DEFAULT_LOCK.unlock_always();
        0
    }
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

unsafe extern "C" {
    fn rl_clone(flags: usize, stack: *mut u8, ptid: *mut i32, ctid: *mut i32, tls: *mut Tcb, f: unsafe extern "C" fn(*mut Thread) -> !, arg: *mut Thread) -> isize;
}

unsafe fn list_insert_all(t: *mut Thread) {
    unsafe {
        (*t).list_prev = core::ptr::null_mut();
        (*t).list_next = ALL_HEAD;
        if !ALL_HEAD.is_null() {
            (*ALL_HEAD).list_prev = t;
        }
        ALL_HEAD = t;
    }
}

unsafe fn list_remove_all(t: *mut Thread) {
    unsafe {
        let (p, n) = ((*t).list_prev, (*t).list_next);
        if p.is_null() {
            if ALL_HEAD == t {
                ALL_HEAD = n;
            }
        } else {
            (*p).list_next = n;
        }
        if !n.is_null() {
            (*n).list_prev = p;
        }
        (*t).list_next = core::ptr::null_mut();
        (*t).list_prev = core::ptr::null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_walk_threads(cb: unsafe extern "C" fn(usize, usize), arg: usize) {
    unsafe {
        let main = tls::main_thread_pointer();
        if main != 0 {
            cb(main, arg);
        }
        LIST_LOCK.lock_always();
        let mut cur = ALL_HEAD;
        while !cur.is_null() {
            if tid_of(cur) > 0 && cur as usize != main {
                cb(cur as usize, arg);
            }
            cur = (*cur).list_next;
        }
        LIST_LOCK.unlock_always();
    }
}

unsafe fn release(t: *mut Thread) {
    unsafe {
        LIST_LOCK.lock_always();
        list_remove_all(t);
        if (*t).flags & FLAG_USER_STACK == 0 && !(*t).mapping.is_null() {
            (*t).list_next = FREE_HEAD;
            FREE_HEAD = t;
        }
        LIST_LOCK.unlock_always();
    }
}

#[inline]
unsafe fn tid_of(t: *mut Thread) -> i32 {
    unsafe { (*(&raw const (*t).tcb.tid as *const core::sync::atomic::AtomicI32)).load(Ordering::Acquire) }
}

unsafe fn reap_and_find(total: usize, guard: usize) -> *mut Thread {
    unsafe {
        let mut cached = 0usize;
        let mut found: *mut Thread = core::ptr::null_mut();
        let mut prev: *mut Thread = core::ptr::null_mut();
        let mut cur = FREE_HEAD;
        while !cur.is_null() {
            let next = (*cur).list_next;
            let dead = tid_of(cur) <= 0;
            let mut remove = false;
            if dead {
                if found.is_null() && (*cur).mapping_size == total && (*cur).guard_size == guard {
                    tls::release_block(cur as *mut Tcb);
                    found = cur;
                    remove = true;
                } else if cached >= CACHE_MAX || (*cur).mapping_size > (64 << 20) {
                    let (m, s) = ((*cur).mapping, (*cur).mapping_size);
                    tls::release_block(cur as *mut Tcb);
                    if prev.is_null() {
                        FREE_HEAD = next;
                    } else {
                        (*prev).list_next = next;
                    }
                    munmap(m, s);
                    cur = next;
                    continue;
                } else {
                    cached += 1;
                }
            }
            if remove {
                if prev.is_null() {
                    FREE_HEAD = next;
                } else {
                    (*prev).list_next = next;
                }
            } else {
                prev = cur;
            }
            cur = next;
        }
        found
    }
}

struct Params {
    stacksize: usize,
    guardsize: usize,
    user_top: *mut u8,
    detached: bool,
    explicit_sched: bool,
    policy: c_int,
    param: SchedParam,
    ext: *mut AttrExt,
    sigmask: Option<u64>,
    attr_flags: i32,
}

unsafe fn resolve(attr: *const PthreadAttr) -> Params {
    unsafe {
        let defsize = default_stacksize();
        let mut copy;
        let mut default_mask: Option<u64> = None;
        let a: &PthreadAttr = if attr.is_null() {
            DEFAULT_LOCK.lock_always();
            copy = core::ptr::read(&raw const DEFAULT_ATTR);
            let de = copy.extension;
            if !de.is_null() && (*de).sigmask_set != 0 {
                default_mask = Some((*de).sigmask);
            }
            copy.extension = core::ptr::null_mut();
            DEFAULT_LOCK.unlock_always();
            &copy
        } else {
            &*attr
        };
        Params {
            stacksize: if a.stacksize != 0 { a.stacksize } else { defsize },
            guardsize: a.guardsize,
            user_top: if a.flags & ATTR_FLAG_STACKADDR != 0 { a.stackaddr as *mut u8 } else { core::ptr::null_mut() },
            detached: a.flags & ATTR_FLAG_DETACHSTATE != 0,
            explicit_sched: a.flags & ATTR_FLAG_NOTINHERITSCHED != 0 && a.flags & (ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET) != 0,
            policy: if a.flags & ATTR_FLAG_POLICY_SET != 0 { a.schedpolicy } else { -1 },
            param: if a.flags & ATTR_FLAG_SCHED_SET != 0 { a.schedparam } else { SchedParam { sched_priority: -1 } },
            ext: a.extension,
            attr_flags: a.flags & ATTR_FLAG_NOTINHERITSCHED,
            sigmask: if !a.extension.is_null() && (*a.extension).sigmask_set != 0 { Some((*a.extension).sigmask) } else { default_mask },
        }
    }
}

unsafe extern "C" fn thread_entry(t: *mut Thread) -> ! {
    unsafe {
        sigprocmask_set(2, (*t).start_mask);
        tls::sync_new_thread(t as *mut Tcb);
        loop {
            let g = (*t).gate.load(Ordering::Acquire);
            if g != 1 {
                if g == 3 {
                    exit_thread();
                }
                break;
            }
            futex_wait(&(*t).gate, 1, true);
        }
        let f = (*t).start.unwrap_unchecked();
        let r = f((*t).arg);
        thread_exit(r)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_create(newthread: *mut PthreadT, attr: *const PthreadAttr, start: unsafe extern "C" fn(*mut c_void) -> *mut c_void, arg: *mut c_void) -> c_int {
    crate::atfork::install_fork_hook();
    rusty_libc_core::lock::note_multithreaded();
    unsafe {
        cancel::ensure_init();
        let me = current_thread();
        if THREAD_COUNT.load(Ordering::Acquire) <= 1 {
            (*me).tcb.tid = raw_gettid();
        }
        let p = resolve(attr);
        let tpl = tls::template();
        let (block_size, _tp_off) = tls::block_layout(&tpl);
        let align = tpl.align.max(64);
        let (t, mapping);
        if !p.user_top.is_null() {
            if p.stacksize < block_size + 2048 {
                return EINVAL;
            }
            let base = ((p.user_top as usize - block_size) & !(align - 1)) as *mut u8;
            core::ptr::write_bytes(base, 0, block_size);
            let tp = tls::setup_block(base, &tpl, (*me).tcb.stack_guard, (*me).tcb.pointer_guard) as *mut Thread;
            t = tp;
            mapping = core::ptr::null_mut();
            (*t).flags = FLAG_USER_STACK;
            (*t).stack_lo = p.user_top.sub(p.stacksize);
            (*t).stack_size = p.stacksize;
            (*t).block_base = base;
        } else {
            let guard = align_up(p.guardsize, PAGE);
            let size = align_up(p.stacksize, PAGE);
            if size < align_up(guard + block_size + 2048, PAGE) {
                return EINVAL;
            }
            let extra = if size < 65536 { PAGE } else { 0 };
            let total = size + guard + extra;
            LIST_LOCK.lock_always();
            let reuse = reap_and_find(total, guard);
            LIST_LOCK.unlock_always();
            let map;
            if reuse.is_null() {
                map = match mmap(total, 3) {
                    Ok(m) => m,
                    Err(_) => return EAGAIN,
                };
                if guard != 0 && mprotect(map, guard, 0) != 0 {
                    munmap(map, total);
                    return EAGAIN;
                }
            } else {
                map = (*reuse).mapping;
            }
            mapping = map;
            let mapping_size = total;
            let base = (((map as usize + total) - block_size) & !(align - 1)) as *mut u8;
            if !reuse.is_null() {
                core::ptr::write_bytes(base, 0, block_size);
            }
            t = tls::setup_block(base, &tpl, (*me).tcb.stack_guard, (*me).tcb.pointer_guard) as *mut Thread;
            (*t).flags = 0;
            (*t).mapping = mapping;
            (*t).mapping_size = mapping_size;
            (*t).guard_size = guard;
            (*t).stack_lo = map.add(guard);
            (*t).stack_size = total - guard;
            (*t).block_base = base;
        }
        (*t).block_size = block_size;
        (*t).attr_flags = p.attr_flags;
        (*t).tcb.multiple_threads = 1;
        (*t).tcb.tid = 0;
        (*t).start = Some(start);
        (*t).arg = arg;
        (*t).joinstate.store(if p.detached { DETACHED } else { JOINABLE }, Ordering::Relaxed);
        (*t).robust.list = &raw mut (*t).robust as *mut u8;
        (*t).robust.futex_offset = -32;
        (*t).robust.list_op_pending = core::ptr::null_mut();

        let gated = p.explicit_sched || (!p.ext.is_null() && (*p.ext).cpusetsize != 0);
        (*t).gate.store(if gated { 1 } else { 0 }, Ordering::Relaxed);

        (*me).tcb.multiple_threads = 1;

        let all = sigprocmask_set(2, u64::MAX);
        (*t).start_mask = p.sigmask.unwrap_or(all);

        THREAD_COUNT.fetch_add(1, Ordering::AcqRel);
        LIST_LOCK.lock_always();
        list_insert_all(t);
        LIST_LOCK.unlock_always();

        let tidp = &raw mut (*t).tcb.tid;
        let r = rl_clone(CLONE_FLAGS, base_of_stack(t), tidp, tidp, t as *mut Tcb, thread_entry, t);
        sigprocmask_set(2, all);
        if r < 0 {
            THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
            LIST_LOCK.lock_always();
            list_remove_all(t);
            LIST_LOCK.unlock_always();
            (*t).tcb.tid = -1;
            if !mapping.is_null() {
                LIST_LOCK.lock_always();
                (*t).list_next = FREE_HEAD;
                FREE_HEAD = t;
                LIST_LOCK.unlock_always();
            }
            return (-r) as c_int;
        }
        if gated {
            let mut err = 0;
            let tid = (*t).tcb.tid;
            if p.explicit_sched {
                let policy = if p.policy >= 0 { p.policy } else { syscall_getscheduler(0) };
                let mut param = SchedParam { sched_priority: 0 };
                if p.param.sched_priority >= 0 {
                    param = p.param;
                } else {
                    syscall2(SYS_SCHED_GETPARAM, 0, &mut param as *mut SchedParam as usize);
                }
                err = sched_setscheduler(tid, policy, &param);
            }
            if err == 0 && !p.ext.is_null() && (*p.ext).cpusetsize != 0 {
                err = sched_setaffinity(tid, (*p.ext).cpusetsize, (*p.ext).cpuset());
            }
            if err != 0 {
                (*t).gate.store(3, Ordering::Release);
                futex_wake(&(*t).gate, 1, true);
                loop {
                    let tid = tid_of(t);
                    if tid == 0 {
                        break;
                    }
                    futex_wait(&raw const (*t).tcb.tid as *const AtomicU32, tid as u32, false);
                }
                THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
                (*t).tcb.tid = -1;
                release(t);
                return err;
            }
            (*t).gate.store(2, Ordering::Release);
            futex_wake(&(*t).gate, 1, true);
        }
        *newthread = t as PthreadT;
        0
    }
}

fn syscall_getscheduler(tid: i32) -> c_int {
    unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GETSCHEDULER, tid as usize) as c_int }
}

unsafe fn base_of_stack(t: *mut Thread) -> *mut u8 {
    unsafe { (*t).block_base }
}

pub fn thread_exit(retval: *mut c_void) -> ! {
    unsafe {
        let t = current_thread();
        (&*(&raw const (*t).tcb.cancelhandling as *const AtomicU32)).fetch_or(cancel::EXITING_BIT | cancel::DISABLE_BIT, Ordering::AcqRel);
        (*t).result = retval;
        rusty_libc_core::tls::run_thread_dtors();
        crate::key::run_destructors(t);
        crate::key::free_second_level(t);
        let is_main = (*t).mapping.is_null() && (*t).flags & FLAG_USER_STACK == 0;
        let left = THREAD_COUNT.fetch_sub(1, Ordering::AcqRel) - 1;
        if left == 0 {
            rusty_libc_core::process::exit(0);
        }
        if is_main {
            exit_thread();
        }
        loop {
            let s = (*t).joinstate.load(Ordering::Acquire);
            match s {
                JOINABLE => {
                    if (*t).joinstate.compare_exchange(JOINABLE, EXITED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        break;
                    }
                }
                DETACHED => {
                    release(t);
                    break;
                }
                _ => break,
            }
        }
        exit_thread();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    unsafe {
        cancel::ensure_init();
        let t = current_thread();
        let w = &*(&raw const (*t).tcb.cancelhandling as *const AtomicU32);
        w.fetch_or(cancel::EXITING_BIT | cancel::DISABLE_BIT, Ordering::AcqRel);
        w.fetch_and(!cancel::ASYNC_BIT, Ordering::AcqRel);
        (*t).exit_value = retval;
        cancel::unwind_continue()
    }
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
    unsafe {
        let t = arg as *mut Thread;
        (*t).joinstate.store(JOINABLE, Ordering::Release);
    }
}

pub unsafe fn join_common(th: PthreadT, retval: *mut *mut c_void, clock: c_int, abs: *const Timespec, block: bool) -> c_int {
    unsafe {
        let t = th as *mut Thread;
        if tid_of(t) < 0 {
            return ESRCH;
        }
        if t == current_thread() {
            return EDEADLK;
        }
        loop {
            let s = (*t).joinstate.load(Ordering::Acquire);
            if s == DETACHED || s == JOINING {
                return EINVAL;
            }
            if (*t).joinstate.compare_exchange(s, JOINING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                break;
            }
        }
        let mut result = 0;
        let waited = cancel::with_cleanup(join_cleanup, t as *mut c_void, || loop {
            if block {
                cancel::testcancel();
            }
            let tid = tid_of(t);
            if tid == 0 {
                return true;
            }
            if !block {
                result = EBUSY;
                return false;
            }
            let e = futex_wait_abs_cp(&raw const (*t).tcb.tid as *const AtomicU32, tid as u32, clock, abs, false);
            if e == ETIMEDOUT || e == EINVAL || e == EOVERFLOW {
                result = e;
                return false;
            }
        });
        if !waited {
            (*t).joinstate.store(JOINABLE, Ordering::Release);
            return result;
        }
        if !retval.is_null() {
            *retval = (*t).result;
        }
        (*t).tcb.tid = -1;
        release(t);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(th: PthreadT, retval: *mut *mut c_void) -> c_int {
    unsafe { join_common(th, retval, CLOCK_REALTIME, core::ptr::null(), true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_tryjoin_np(th: PthreadT, retval: *mut *mut c_void) -> c_int {
    unsafe { join_common(th, retval, CLOCK_REALTIME, core::ptr::null(), false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_timedjoin_np(th: PthreadT, retval: *mut *mut c_void, abstime: *const Timespec) -> c_int {
    unsafe { join_common(th, retval, CLOCK_REALTIME, abstime, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_clockjoin_np(th: PthreadT, retval: *mut *mut c_void, clockid: c_int, abstime: *const Timespec) -> c_int {
    unsafe {
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }
        join_common(th, retval, clockid, abstime, true)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(th: PthreadT) -> c_int {
    unsafe {
        let t = th as *mut Thread;
        if tid_of(t) < 0 {
            return ESRCH;
        }
        loop {
            let s = (*t).joinstate.load(Ordering::Acquire);
            match s {
                JOINABLE => {
                    if (*t).joinstate.compare_exchange(JOINABLE, DETACHED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        return 0;
                    }
                }
                EXITED => {
                    if (*t).joinstate.compare_exchange(EXITED, DETACHED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        release(t);
                        return 0;
                    }
                }
                _ => return EINVAL,
            }
        }
    }
}

pub fn thread_count() -> usize {
    THREAD_COUNT.load(Ordering::Acquire)
}

pub unsafe fn is_main_thread(t: *mut Thread) -> bool {
    unsafe { (*t).mapping.is_null() && (*t).flags & FLAG_USER_STACK == 0 }
}

pub unsafe fn after_fork_child() {
    unsafe {
        let me = current_thread();
        (*me).tcb.tid = raw_gettid();
        core::ptr::write(&raw const LIST_LOCK as *mut RawMutex, RawMutex::new());
        core::ptr::write(&raw const DEFAULT_LOCK as *mut RawMutex, RawMutex::new());
        let mut cur = ALL_HEAD;
        while !cur.is_null() {
            let next = (*cur).list_next;
            if cur != me && (*cur).flags & FLAG_USER_STACK == 0 && !(*cur).mapping.is_null() {
                munmap((*cur).mapping, (*cur).mapping_size);
            }
            cur = next;
        }
        let mut cur = FREE_HEAD;
        while !cur.is_null() {
            let next = (*cur).list_next;
            munmap((*cur).mapping, (*cur).mapping_size);
            cur = next;
        }
        FREE_HEAD = core::ptr::null_mut();
        ALL_HEAD = core::ptr::null_mut();
        if !is_main_thread(me) {
            (*me).list_next = core::ptr::null_mut();
            (*me).list_prev = core::ptr::null_mut();
            list_insert_all(me);
        }
        THREAD_COUNT.store(1, Ordering::Release);
        if (*me).robust_registered != 0 {
            (*me).robust.list = &raw mut (*me).robust as *mut u8;
            (*me).robust.list_op_pending = core::ptr::null_mut();
            syscall2(SYS_SET_ROBUST_LIST, &raw mut (*me).robust as usize, 24);
        }
        (&*(&raw const (*me).tcb.cancelhandling as *const AtomicU32)).fetch_and(!cancel::CANCELED_BIT, Ordering::AcqRel);
    }
}

pub unsafe fn ensure_robust_registered(t: *mut Thread) {
    unsafe {
        if (*t).robust_registered == 0 {
            crate::atfork::install_fork_hook();
            (*t).robust.list = &raw mut (*t).robust as *mut u8;
            (*t).robust.futex_offset = -32;
            syscall2(SYS_SET_ROBUST_LIST, &raw mut (*t).robust as usize, 24);
            (*t).robust_registered = 1;
        }
    }
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

fn find_mapping(addr: usize) -> Option<(usize, usize)> {
    let fd = unsafe { syscall3(rusty_libc_core::syscall::SYS_OPEN, c"/proc/self/maps".as_ptr() as usize, 0x80000, 0) };
    if errno_of(fd) != 0 {
        return None;
    }
    let mut buf = [0u8; 4096];
    let mut have = 0usize;
    let mut result = None;
    'outer: loop {
        let n = unsafe { syscall3(rusty_libc_core::syscall::SYS_READ, fd, buf.as_mut_ptr().add(have) as usize, buf.len() - have) };
        if errno_of(n) != 0 || n == 0 {
            break;
        }
        have += n;
        let mut start = 0;
        while let Some(nl) = buf[start..have].iter().position(|&c| c == b'\n') {
            let line = &buf[start..start + nl];
            if let Some(dash) = line.iter().position(|&c| c == b'-') {
                let lo = parse_hex(&line[..dash]);
                let rest = &line[dash + 1..];
                let hi = parse_hex(rest);
                if addr >= lo && addr < hi {
                    result = Some((lo, hi));
                    break 'outer;
                }
            }
            start += nl + 1;
        }
        buf.copy_within(start..have, 0);
        have -= start;
        if have == buf.len() {
            have = 0;
        }
    }
    unsafe { rusty_libc_core::syscall::syscall1(rusty_libc_core::syscall::SYS_CLOSE, fd) };
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_np(th: PthreadT, attr: *mut PthreadAttr) -> c_int {
    unsafe {
        let t = th as *mut Thread;
        pthread_attr_init(attr);
        let a = &mut *attr;
        if (*t).joinstate.load(Ordering::Acquire) == DETACHED {
            a.flags |= ATTR_FLAG_DETACHSTATE;
        }
        let tid = if t == current_thread() { gettid() } else { (*t).tcb.tid };
        let pol = syscall_getscheduler(tid);
        if errno_of(pol as usize) == 0 {
            a.schedpolicy = pol & 0xff;
            let mut sp = SchedParam { sched_priority: 0 };
            syscall2(SYS_SCHED_GETPARAM, tid as usize, &mut sp as *mut SchedParam as usize);
            a.schedparam = sp;
        }
        a.flags |= (*t).attr_flags;
        if is_main_thread(t) {
            let sp_addr = &raw const a as usize;
            let lim = rlimit_stack();
            let mut lo = 0usize;
            let mut hi = 0usize;
            if let Some((l, h)) = find_mapping(sp_addr) {
                lo = l;
                hi = h;
            }
            let mut size = lim;
            if hi != 0 && hi - lo < size {
                size = lim;
            }
            a.stackaddr = hi as *mut c_void;
            a.stacksize = size;
            a.guardsize = 0;
            a.flags |= ATTR_FLAG_STACKADDR;
            let _ = lo;
        } else {
            a.stackaddr = ((*t).mapping as usize + (*t).mapping_size) as *mut c_void;
            if (*t).flags & FLAG_USER_STACK != 0 {
                a.stackaddr = (*t).stack_lo.add((*t).stack_size) as *mut c_void;
                a.stacksize = (*t).stack_size;
                a.guardsize = 0;
            } else {
                a.stacksize = (*t).mapping_size - (*t).guard_size;
                a.guardsize = (*t).guard_size;
            }
            a.flags |= ATTR_FLAG_STACKADDR;
        }
        let ks = kernel_cpumask_size();
        let Ok(e) = ext_alloc(a, ks) else { return ENOMEM };
        let r = sched_getaffinity(tid, ks, e.add(1) as *mut u8);
        if r > 0 {
            (*e).cpusetsize = r as usize;
        }
        0
    }
}

unsafe fn ext_alloc(a: *mut PthreadAttr, size: usize) -> Result<*mut AttrExt, c_int> {
    unsafe {
        let len = align_up(core::mem::size_of::<AttrExt>() + size, PAGE);
        let p = mmap(len, 3).map_err(|_| ENOMEM)? as *mut AttrExt;
        (*p).map_size = len;
        (*a).extension = p;
        Ok(p)
    }
}
