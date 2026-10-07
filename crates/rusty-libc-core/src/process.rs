use crate::syscall;

pub fn exit_now(status: i32) -> ! {
    loop {
        unsafe { syscall::syscall1(syscall::SYS_EXIT_GROUP, status as usize) };
    }
}

pub fn abort() -> ! {
    const SIGABRT: usize = 6;
    unsafe {
        let pid = syscall::syscall1(syscall::SYS_GETPID, 0);
        let tid = syscall::syscall1(syscall::SYS_GETTID, 0);
        syscall::syscall3(syscall::SYS_TGKILL, pid, tid, SIGABRT);
        let act = [0usize, 0, 0, !0usize];
        syscall::syscall4(syscall::SYS_RT_SIGACTION, SIGABRT, act.as_ptr() as usize, 0, 8);
        syscall::syscall3(syscall::SYS_TGKILL, pid, tid, SIGABRT);
        let set: u64 = 1 << (SIGABRT - 1);
        syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, 1 , &set as *const u64 as usize, 0, 8);
        core::arch::asm!("hlt", options(noreturn, nostack));
    }
}


pub fn exit_func_is_null() -> ! {
    let msg = b"Fatal glibc error: cxa_atexit.c:81 (__internal_atexit): assertion failed: func != NULL\n";
    let _ = crate::unistd::write(2, msg);
    abort()
}

const MAX_ATEXIT: usize = 1024;

#[derive(Clone, Copy)]
pub enum ExitFn {
    Plain(extern "C" fn()),
    Cxa(unsafe extern "C" fn(*mut core::ffi::c_void), *mut core::ffi::c_void, usize),
    OnExit(unsafe extern "C" fn(i32, *mut core::ffi::c_void), *mut core::ffi::c_void),
    Quick(extern "C" fn()),
}

static ATEXIT_LOCK: crate::lock::RawMutex = crate::lock::RawMutex::new();
static mut ATEXIT: [Option<ExitFn>; MAX_ATEXIT] = [None; MAX_ATEXIT];
static mut ATEXIT_N: usize = 0;
static EXIT_STATUS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
pub static FORK_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
pub static ATFORK_UNREGISTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

static STDIO_FLUSH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn register(f: ExitFn) -> bool {
    let g = ATEXIT_LOCK.guard();
    let _ = &g;
    unsafe {
        let n = ATEXIT_N;
        if n >= MAX_ATEXIT {
            return false;
        }
        (core::ptr::addr_of_mut!(ATEXIT) as *mut Option<ExitFn>).add(n).write(Some(f));
        ATEXIT_N = n + 1;
        true
    }
}

pub fn atexit(f: extern "C" fn()) -> bool {
    register(ExitFn::Plain(f))
}

pub fn finalize(dso: usize) {
    run_handlers(dso, false);
    if dso != 0 {
        let h = ATFORK_UNREGISTER.load(core::sync::atomic::Ordering::Relaxed);
        if h != 0 {
            let f: unsafe extern "C" fn(usize) = unsafe { core::mem::transmute(h) };
            unsafe { f(dso) };
        }
    }
}

pub fn finalize_quick() {
    run_handlers(0, true);
}

fn run_handlers(dso: usize, quick: bool) {
    loop {
        let taken = {
            let g = ATEXIT_LOCK.guard();
            let _ = &g;
            unsafe {
                let mut i = ATEXIT_N;
                let tbl = core::ptr::addr_of_mut!(ATEXIT) as *mut Option<ExitFn>;
                let mut found = None;
                while i > 0 {
                    i -= 1;
                    let slot = tbl.add(i);
                    let take = match *slot {
                        Some(ExitFn::Quick(_)) => quick,
                        Some(ExitFn::Cxa(_, _, d)) => !quick && (dso == 0 || d == dso),
                        Some(_) => !quick && dso == 0,
                        None => false,
                    };
                    if take {
                        found = (*slot).take();
                        while ATEXIT_N > 0 && (*tbl.add(ATEXIT_N - 1)).is_none() {
                            ATEXIT_N -= 1;
                        }
                        break;
                    }
                }
                found
            }
        };
        match taken {
            None => return,
            Some(ExitFn::Plain(f)) => f(),
            Some(ExitFn::Cxa(f, arg, _)) => unsafe { f(arg) },
            Some(ExitFn::OnExit(f, arg)) => unsafe { f(exit_status(), arg) },
            Some(ExitFn::Quick(f)) => f(),
        }
    }
}

pub fn set_stdio_flush(f: extern "C" fn()) {
    STDIO_FLUSH.store(f as usize, core::sync::atomic::Ordering::Relaxed);
}

pub type ForkHandler = unsafe extern "C" fn();

pub const MAX_FORK_LAYERS: usize = 8;

struct ForkLayers {
    prepare: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    parent: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    child: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    n: core::sync::atomic::AtomicUsize,
}

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_WORD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FORK_LAYERS: ForkLayers =
    ForkLayers { prepare: [ZERO_WORD; MAX_FORK_LAYERS], parent: [ZERO_WORD; MAX_FORK_LAYERS], child: [ZERO_WORD; MAX_FORK_LAYERS], n: ZERO_WORD };

pub fn register_fork_handlers(prepare: ForkHandler, parent: ForkHandler, child: ForkHandler) -> bool {
    use core::sync::atomic::Ordering::*;
    let i = FORK_LAYERS.n.fetch_add(1, AcqRel);
    if i >= MAX_FORK_LAYERS {
        FORK_LAYERS.n.store(MAX_FORK_LAYERS, Relaxed);
        return false;
    }
    FORK_LAYERS.parent[i].store(parent as usize, Relaxed);
    FORK_LAYERS.child[i].store(child as usize, Relaxed);
    FORK_LAYERS.prepare[i].store(prepare as usize, Release);
    true
}

fn fork_layer(words: &[core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS], i: usize) -> Option<ForkHandler> {
    use core::sync::atomic::Ordering::*;
    if FORK_LAYERS.prepare[i].load(Acquire) == 0 {
        return None;
    }
    let w = words[i].load(Relaxed);
    if w == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ForkHandler>(w) }) }
}

fn fork_layer_count() -> usize {
    FORK_LAYERS.n.load(core::sync::atomic::Ordering::Acquire).min(MAX_FORK_LAYERS)
}

pub unsafe fn run_fork_prepare() {
    for i in (0..fork_layer_count()).rev() {
        if let Some(f) = fork_layer(&FORK_LAYERS.prepare, i) {
            unsafe { f() };
        }
    }
}

pub unsafe fn run_fork_parent() {
    for i in 0..fork_layer_count() {
        if let Some(f) = fork_layer(&FORK_LAYERS.parent, i) {
            unsafe { f() };
        }
    }
}

pub unsafe fn run_fork_child() {
    for i in 0..fork_layer_count() {
        if let Some(f) = fork_layer(&FORK_LAYERS.child, i) {
            unsafe { f() };
        }
    }
}

pub fn exit_status() -> i32 {
    EXIT_STATUS.load(core::sync::atomic::Ordering::Relaxed)
}

static EXIT_OWNER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static EXIT_DEPTH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static EXIT_PARK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn exit_lock() {
    use core::sync::atomic::Ordering::*;
    let me = crate::tls::current() as usize;
    if EXIT_OWNER.load(Acquire) == me {
        EXIT_DEPTH.fetch_add(1, Relaxed);
        return;
    }
    loop {
        if EXIT_OWNER.compare_exchange(0, me, Acquire, Relaxed).is_ok() {
            EXIT_DEPTH.store(1, Relaxed);
            return;
        }
        unsafe { syscall::syscall4(202, EXIT_PARK.as_ptr() as usize, 128, 0, 0) };
    }
}

pub fn exit(status: i32) -> ! {
    exit_lock();
    EXIT_STATUS.store(status, core::sync::atomic::Ordering::Relaxed);
    crate::tls::run_thread_dtors();
    finalize(0);
    let hook = STDIO_FLUSH.load(core::sync::atomic::Ordering::Relaxed);
    if hook != 0 {
        let f: extern "C" fn() = unsafe { core::mem::transmute(hook) };
        f();
    }
    exit_now(status)
}
