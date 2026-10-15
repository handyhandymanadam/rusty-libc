#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::SyncCell;
use crate::syscall;

pub fn exit_now(status: i32) -> ! {
    loop {
        unsafe { syscall::syscall1(syscall::SYS_EXIT_GROUP, status as usize) };
    }
}

pub fn abort() -> ! {
    const SIGABRT: i32 = 6;
    let pid = crate::unistd::getpid();
    let tid = crate::unistd::gettid();
    let _ = crate::signal::tgkill(pid, tid, SIGABRT);
    let act = [0usize, 0, 0, !0usize];
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGACTION, SIGABRT as usize, act.as_ptr() as usize, 0, 8) };
    let _ = crate::signal::tgkill(pid, tid, SIGABRT);
    let set: u64 = 1 << (SIGABRT - 1);
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, 1 , &set as *const u64 as usize, 0, 8) };
    unsafe { core::arch::asm!("hlt", options(noreturn, nostack)) }
}


pub fn exit_func_is_null() -> ! {
    let msg = b"Fatal glibc error: cxa_atexit.c:81 (__internal_atexit): assertion failed: func != NULL\n";
    let _ = crate::unistd::write(2, msg);
    abort()
}

const INLINE_ATEXIT: usize = 1024;

#[derive(Clone, Copy)]
pub enum ExitFn {
    Plain(extern "C" fn()),
    Cxa(unsafe extern "C" fn(*mut core::ffi::c_void), *mut core::ffi::c_void, usize),
    OnExit(unsafe extern "C" fn(i32, *mut core::ffi::c_void), *mut core::ffi::c_void),
    Quick(extern "C" fn(), usize),
}

struct ExitTable {
    inline: [Option<ExitFn>; INLINE_ATEXIT],
    more: crate::pages::PageVec<Option<ExitFn>>,
    n: usize,
}

impl ExitTable {
    fn slot(&mut self, i: usize) -> &mut Option<ExitFn> {
        match i.checked_sub(INLINE_ATEXIT) {
            None => &mut self.inline[i],
            Some(j) => &mut self.more.as_mut_slice()[j],
        }
    }

    fn push(&mut self, f: ExitFn) -> bool {
        let n = self.n;
        if n >= INLINE_ATEXIT && !self.more.grow(n - INLINE_ATEXIT + 1, None) {
            return false;
        }
        *self.slot(n) = Some(f);
        self.n = n + 1;
        true
    }

    fn take_next(&mut self, pass: Pass) -> Option<ExitFn> {
        let mut found = None;
        for i in (0..self.n).rev() {
            let take = match (*self.slot(i), pass) {
                (None, _) => false,
                (Some(ExitFn::Quick(..)), p) => p == Pass::Quick,
                (Some(_), Pass::Exit) => true,
                (Some(ExitFn::Plain(_) | ExitFn::Cxa(..)), Pass::AllCxa) => true,
                (Some(ExitFn::Cxa(_, _, d)), Pass::Dso(dso)) => d == dso,
                (Some(_), _) => false,
            };
            if take {
                found = self.slot(i).take();
                break;
            }
        }
        if found.is_none() {
            let dso = match pass {
                Pass::AllCxa => Some(0),
                Pass::Dso(d) => Some(d),
                _ => None,
            };
            if let Some(dso) = dso {
                for i in 0..self.n {
                    let s = self.slot(i);
                    if matches!(*s, Some(ExitFn::Quick(_, d)) if dso == 0 || d == dso) {
                        *s = None;
                    }
                }
            }
        }
        while self.n > 0 && self.slot(self.n - 1).is_none() {
            self.n -= 1;
        }
        found
    }
}

static ATEXIT_LOCK: crate::lock::RawMutex = crate::lock::RawMutex::new();
static ATEXIT: SyncCell<ExitTable> = SyncCell::new(ExitTable { inline: [None; INLINE_ATEXIT], more: crate::pages::PageVec::new(), n: 0 });
static EXIT_STATUS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
pub static FORK_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
pub static ATFORK_UNREGISTER: crate::lock::Locked<Option<extern "C" fn(usize)>> = crate::lock::Locked::new(None);

static STDIO_FLUSH: crate::lock::Locked<Option<extern "C" fn()>> = crate::lock::Locked::new(None);

pub fn register(f: ExitFn) -> bool {
    let g = ATEXIT_LOCK.guard();
    let _ = &g;
    unsafe { ATEXIT.with_unsync(|t| t.push(f)) }
}

pub fn atexit(f: extern "C" fn()) -> bool {
    register(ExitFn::Plain(f))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    Exit,
    AllCxa,
    Dso(usize),
    Quick,
}

pub fn finalize(dso: usize) {
    run_handlers(if dso == 0 { Pass::AllCxa } else { Pass::Dso(dso) }, 0);
    if dso != 0
        && let Some(f) = ATFORK_UNREGISTER.with(|h| *h)
    {
        f(dso);
    }
}

pub fn finalize_exit() {
    run_handlers(Pass::Exit, exit_status());
}

pub fn finalize_quick() {
    run_handlers(Pass::Quick, exit_status());
}

fn run_handlers(pass: Pass, status: i32) {
    loop {
        let taken = {
            let g = ATEXIT_LOCK.guard();
            let _ = &g;
            unsafe { ATEXIT.with_unsync(|t| t.take_next(pass)) }
        };
        match taken {
            None => return,
            Some(ExitFn::Plain(f)) => f(),
            Some(ExitFn::Cxa(f, arg, _)) => {
                let f = unsafe { core::mem::transmute::<unsafe extern "C" fn(*mut core::ffi::c_void), unsafe extern "C" fn(*mut core::ffi::c_void, i32)>(f) };
                unsafe { f(arg, status) }
            }
            Some(ExitFn::OnExit(f, arg)) => unsafe { f(exit_status(), arg) },
            Some(ExitFn::Quick(f, _)) => f(),
        }
    }
}

pub fn set_stdio_flush(f: extern "C" fn()) {
    STDIO_FLUSH.with(|h| *h = Some(f));
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
    finalize_exit();
    let flush = STDIO_FLUSH.with(|h| *h);
    if let Some(f) = flush {
        f();
    }
    exit_now(status)
}
