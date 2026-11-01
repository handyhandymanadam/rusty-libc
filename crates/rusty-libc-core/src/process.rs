//! Process control, Rust side.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::SyncCell;
use crate::syscall;

/// Terminate the process at once with `status` (no cleanup handlers run).
pub fn exit_now(status: i32) -> ! {
    loop {
        // SAFETY: exit_group with a plain value.
        unsafe { syscall::syscall1(syscall::SYS_EXIT_GROUP, status as usize) };
    }
}

/// abort(3), glibc 2.43's sequence: raise SIGABRT as the process stands (a blocked SIGABRT stays
/// pending, so a user handler does not run); if that returns, reset the action to the default with
/// every signal blocked while it is changed, raise again, unblock SIGABRT (so the pending signal
/// kills the process) and, if even that fails, execute `hlt` (a crash).
pub fn abort() -> ! {
    const SIGABRT: i32 = 6;
    let pid = crate::unistd::getpid();
    let tid = crate::unistd::gettid();
    let _ = crate::signal::tgkill(pid, tid, SIGABRT);
    // Still here: a handler returned, or SIGABRT is blocked or ignored. Back to the default action.
    let act = [0usize, 0, 0, !0usize]; // sa_handler = SIG_DFL, flags 0, restorer 0, mask = all signals
    // the raw calls below (not signal::sigaction/sigprocmask): no old-value pointer, as glibc makes them
    // SAFETY: the kernel reads the local kernel sigaction `act` (handler, flags, restorer, mask); no old-value pointer.
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGACTION, SIGABRT as usize, act.as_ptr() as usize, 0, 8) };
    let _ = crate::signal::tgkill(pid, tid, SIGABRT);
    let set: u64 = 1 << (SIGABRT - 1);
    // SAFETY: the kernel reads the local 8-byte set; no old-value pointer.
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, 1 /* SIG_UNBLOCK */, &set as *const u64 as usize, 0, 8) };
    // SAFETY: `hlt` faults in user mode (SIGSEGV): the process ends here, as glibc's ABORT_INSTRUCTION; never falls through.
    unsafe { core::arch::asm!("hlt", options(noreturn, nostack)) }
}


/// glibc asserts that the function given to atexit, on_exit, at_quick_exit, __cxa_atexit and __cxa_at_quick_exit is not NULL:
/// a message on standard error and SIGABRT (glibc's tst-bz20544 looks for the text).
pub fn exit_func_is_null() -> ! {
    let msg = b"Fatal glibc error: cxa_atexit.c:81 (__internal_atexit): assertion failed: func != NULL\n";
    let _ = crate::unistd::write(2, msg);
    abort()
}

/// Handlers kept in the static table; more go into a growing mapping (glibc's list has no limit: a static block of 32,
/// then malloc'd blocks; clang-scan-deps registers 2,780, FIXLIST #131).
const INLINE_ATEXIT: usize = 1024;

/// One registered exit handler.
#[derive(Clone, Copy)]
pub enum ExitFn {
    /// `atexit(f)` (glibc's `atexit@GLIBC_2.2.5` registers it as `__cxa_atexit(f, NULL, NULL)`: `__cxa_finalize(NULL)` runs it)
    Plain(extern "C" fn()),
    /// `__cxa_atexit(f, arg, dso)`: `dso` is the shared-object handle (0 for none). glibc calls `f(arg, status)`: the exit
    /// status, or 0 from `__cxa_finalize`.
    Cxa(unsafe extern "C" fn(*mut core::ffi::c_void), *mut core::ffi::c_void, usize),
    /// `on_exit(f, arg)`: `f` gets the status `exit` was called with
    OnExit(unsafe extern "C" fn(i32, *mut core::ffi::c_void), *mut core::ffi::c_void),
    /// `at_quick_exit(f)` / `__cxa_at_quick_exit(f, dso)`: run by `quick_exit` only (they share the table, so a handler
    /// registered while they run is found); `__cxa_finalize(dso)` drops those of `dso` without running them
    Quick(extern "C" fn(), usize),
}

/// The registered handlers: slots `0..n` (a taken one is `None`), newest last; slot `i` is `inline[i]` below
/// `INLINE_ATEXIT`, `more[i - INLINE_ATEXIT]` above. The count comes first, next to the first slots: every process writes
/// both at start-up (the loader's `_dl_fini`), and with the count after the 32 KB of slots (Rust's field order) that was
/// one more page of .data read and copied by every start.
#[repr(C)]
struct ExitTable {
    n: usize,
    more: crate::pages::PageVec<Option<ExitFn>>,
    inline: [Option<ExitFn>; INLINE_ATEXIT],
}

impl ExitTable {
    fn slot(&mut self, i: usize) -> &mut Option<ExitFn> {
        match i.checked_sub(INLINE_ATEXIT) {
            None => &mut self.inline[i],
            Some(j) => &mut self.more.as_mut_slice()[j],
        }
    }

    /// Append `f`; false if the table cannot grow.
    fn push(&mut self, f: ExitFn) -> bool {
        let n = self.n;
        if n >= INLINE_ATEXIT && !self.more.grow(n - INLINE_ATEXIT + 1, None) {
            return false;
        }
        *self.slot(n) = Some(f);
        self.n = n + 1;
        true
    }

    /// Remove and return the newest handler `pass` selects. Every pass starts at the top again: a handler that registers
    /// another one (fn3 in glibc's tst-atexit registers fn2 and fn0) has it run next, before the older handlers, as in glibc.
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
            // the last pass of `__cxa_finalize`: drop the `at_quick_exit` handlers of the object (all of them for NULL)
            // without running them, after its other handlers ran (glibc's order)
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
        // compact the top of the table so exit-time registration order stays intact
        while self.n > 0 && self.slot(self.n - 1).is_none() {
            self.n -= 1;
        }
        found
    }
}

static ATEXIT_LOCK: crate::lock::RawMutex = crate::lock::RawMutex::new();
/// Touched only with `ATEXIT_LOCK` held (its `guard`, which takes the lock once the process is multi-threaded; before that
/// there is one thread), never while a handler runs.
static ATEXIT: SyncCell<ExitTable> = SyncCell::new(ExitTable { n: 0, more: crate::pages::PageVec::new(), inline: [None; INLINE_ATEXIT] });
static EXIT_STATUS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// Hook that makes the C `fork` honour atfork handlers and reset thread state in the child: rusty-libc-pthread
/// stores a `unsafe extern "C" fn() -> i32` here (0 = none) when threads or handlers exist; rusty-libc-sys's
/// `fork` calls it instead of the raw system call.
pub static FORK_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Hook rusty-libc-pthread sets: `unsafe extern "C" fn(dso: usize)` drops the fork handlers a shared object registered (called
/// by `finalize` for the handlers of an unloaded object, like glibc's `__cxa_finalize` calls `__unregister_atfork`).
pub static ATFORK_UNREGISTER: crate::lock::Locked<Option<extern "C" fn(usize)>> = crate::lock::Locked::new(None);

static STDIO_FLUSH: crate::lock::Locked<Option<extern "C" fn()>> = crate::lock::Locked::new(None);

/// Register an exit handler. False only if no memory is left for the table (glibc: calloc fails).
pub fn register(f: ExitFn) -> bool {
    let g = ATEXIT_LOCK.guard();
    let _ = &g;
    // SAFETY: ATEXIT_LOCK is held (or the process has one thread): the rule of `ATEXIT`.
    unsafe { ATEXIT.with_unsync(|t| t.push(f)) }
}

/// Register a function to run at exit (atexit(3)). False if no memory is left for the table.
pub fn atexit(f: extern "C" fn()) -> bool {
    register(ExitFn::Plain(f))
}

/// Which handlers a pass runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// `exit`: every handler but the `at_quick_exit` ones
    Exit,
    /// `__cxa_finalize(NULL)`: the `atexit` and `__cxa_atexit` ones (not `on_exit`); every `at_quick_exit` one is dropped
    AllCxa,
    /// `__cxa_finalize(dso)`: the `__cxa_atexit` ones of `dso`; its `at_quick_exit` ones are dropped
    Dso(usize),
    /// `quick_exit`
    Quick,
}

/// `__cxa_finalize(dso)` as glibc 2.43 does it: run and remove the `__cxa_atexit` handlers registered with `dso` (with
/// `dso == 0`, every `atexit` and `__cxa_atexit` handler), newest first, with status 0; drop the `at_quick_exit` handlers of
/// `dso` (all of them for 0) without running them; drop the fork handlers of `dso`.
pub fn finalize(dso: usize) {
    run_handlers(if dso == 0 { Pass::AllCxa } else { Pass::Dso(dso) }, 0);
    if dso != 0
        && let Some(f) = ATFORK_UNREGISTER.with(|h| *h)
    {
        f(dso);
    }
}

/// `exit`'s pass: every registered handler but the `at_quick_exit` ones, last registered first.
pub fn finalize_exit() {
    run_handlers(Pass::Exit, exit_status());
}

/// `quick_exit`'s handlers (`at_quick_exit`), last registered first.
pub fn finalize_quick() {
    run_handlers(Pass::Quick, exit_status());
}

/// Run and remove the handlers `pass` selects, last registered first; `status` is what `__cxa_atexit` handlers get.
/// A handler may register further handlers or call `exit` again: they are popped one at a time with the lock released
/// while a handler runs.
fn run_handlers(pass: Pass, status: i32) {
    loop {
        let taken = {
            let g = ATEXIT_LOCK.guard();
            let _ = &g;
            // SAFETY: ATEXIT_LOCK is held (or one thread): the rule of `ATEXIT`; the handler runs after the lock is released.
            unsafe { ATEXIT.with_unsync(|t| t.take_next(pass)) }
        };
        match taken {
            None => return,
            Some(ExitFn::Plain(f)) => f(),
            Some(ExitFn::Cxa(f, arg, _)) => {
                // glibc calls `f(arg, status)`; a handler declared with one parameter ignores the second register
                // SAFETY: only the type changes (one more integer argument, which the SysV ABI passes in a register).
                let f = unsafe { core::mem::transmute::<unsafe extern "C" fn(*mut core::ffi::c_void), unsafe extern "C" fn(*mut core::ffi::c_void, i32)>(f) };
                // SAFETY: registered by `__cxa_atexit(f, arg, dso)`, whose contract is that `f(arg)` may run at exit.
                unsafe { f(arg, status) }
            }
            // SAFETY: registered by `on_exit(f, arg)`: `f(status, arg)` at exit.
            Some(ExitFn::OnExit(f, arg)) => unsafe { f(exit_status(), arg) },
            Some(ExitFn::Quick(f, _)) => f(),
        }
    }
}

/// The stdio layer registers its "flush every open stream" function here.
pub fn set_stdio_flush(f: extern "C" fn()) {
    STDIO_FLUSH.with(|h| *h = Some(f));
}

// ---- fork handlers of the runtime's own layers (stdio, ...) ----

/// A fork handler of a runtime layer (not a `pthread_atfork` one: these run innermost, around the
/// allocator's own handlers, and cost nothing when unused).
pub type ForkHandler = unsafe extern "C" fn();

/// Most layers that can register (stdio is the first user).
pub const MAX_FORK_LAYERS: usize = 8;

struct ForkLayers {
    prepare: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    parent: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    child: [core::sync::atomic::AtomicUsize; MAX_FORK_LAYERS],
    /// Slots handed out; a slot counts once its `prepare` word is nonzero (stored last).
    n: core::sync::atomic::AtomicUsize,
}

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_WORD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FORK_LAYERS: ForkLayers =
    ForkLayers { prepare: [ZERO_WORD; MAX_FORK_LAYERS], parent: [ZERO_WORD; MAX_FORK_LAYERS], child: [ZERO_WORD; MAX_FORK_LAYERS], n: ZERO_WORD };

/// Register a layer's fork handlers: `prepare` runs in the forking thread before the system call
/// (after `pthread_atfork` prepare handlers, before the allocator's lock is taken), `parent` and
/// `child` after it (after the allocator's state is restored, before `pthread_atfork` parent and
/// child handlers). Prepare handlers run in reverse registration order, the others in registration
/// order. False if the table is full. rusty-libc-pthread's `fork_with_handlers` calls `run_fork_*`.
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
    // a slot whose prepare word is still 0 is being registered: skip it
    if FORK_LAYERS.prepare[i].load(Acquire) == 0 {
        return None;
    }
    let w = words[i].load(Relaxed);
    // SAFETY: the word was stored from a `ForkHandler`.
    if w == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ForkHandler>(w) }) }
}

fn fork_layer_count() -> usize {
    FORK_LAYERS.n.load(core::sync::atomic::Ordering::Acquire).min(MAX_FORK_LAYERS)
}

/// Run the layers' prepare handlers (last registered first).
///
/// # Safety
/// Only from a fork wrapper, in the forking thread, paired with `run_fork_parent` or `run_fork_child`.
pub unsafe fn run_fork_prepare() {
    for i in (0..fork_layer_count()).rev() {
        if let Some(f) = fork_layer(&FORK_LAYERS.prepare, i) {
            // SAFETY: a layer's prepare handler, run where it was registered to run (caller's contract: a fork wrapper).
            unsafe { f() };
        }
    }
}

/// Run the layers' parent handlers (registration order), in the parent after the fork.
///
/// # Safety
/// See `run_fork_prepare`.
pub unsafe fn run_fork_parent() {
    for i in 0..fork_layer_count() {
        if let Some(f) = fork_layer(&FORK_LAYERS.parent, i) {
            // SAFETY: a layer's parent handler, in the parent after the fork (caller's contract).
            unsafe { f() };
        }
    }
}

/// Run the layers' child handlers (registration order), in the child after the fork.
///
/// # Safety
/// See `run_fork_prepare`.
pub unsafe fn run_fork_child() {
    for i in 0..fork_layer_count() {
        if let Some(f) = fork_layer(&FORK_LAYERS.child, i) {
            // SAFETY: a layer's child handler, in the child after the fork (caller's contract).
            unsafe { f() };
        }
    }
}

/// exit(3): run the atexit handlers in reverse order, flush stdio, then terminate.
/// The status `exit` was called with (what `on_exit` handlers are given).
pub fn exit_status() -> i32 {
    EXIT_STATUS.load(core::sync::atomic::Ordering::Relaxed)
}

static EXIT_OWNER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static EXIT_DEPTH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static EXIT_PARK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// glibc's `__exit_lock`, a recursive lock that `exit` and `quick_exit` hold until the process ends: a second thread that calls
/// `exit` waits (for good: the first one ends the process), and an exit handler that calls `exit` itself carries on (its
/// handlers resume where the first call stopped).
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
        // FUTEX_WAIT on a word nobody changes
        // SAFETY: the kernel only reads our own static word; no timeout pointer.
        unsafe { syscall::syscall4(202, EXIT_PARK.as_ptr() as usize, 128, 0, 0) };
    }
}

pub fn exit(status: i32) -> ! {
    exit_lock();
    EXIT_STATUS.store(status, core::sync::atomic::Ordering::Relaxed);
    // C++ thread_local destructors of the exiting thread first, then the registered handlers
    crate::tls::run_thread_dtors();
    finalize_exit();
    let flush = STDIO_FLUSH.with(|h| *h);
    if let Some(f) = flush {
        f();
    }
    exit_now(status)
}
