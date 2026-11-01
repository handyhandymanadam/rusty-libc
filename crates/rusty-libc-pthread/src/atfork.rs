//! pthread_atfork and the fork wrapper that runs the handlers.
//!
//! rusty-libc-core's `unistd::fork` (and rusty-libc-sys's `fork`) are the raw system call. A `fork` that honours
//! atfork handlers calls `fork_with_handlers`: prepare handlers run in reverse registration order in
//! the parent; after the system call the parent runs the parent handlers and the child (which has
//! only the calling thread) resets the thread library's state and runs the child handlers, both in
//! registration order.
//!
//! Safe core: the handler table is a `SyncCell` used only under its lock. Unsafe left: calling the program's handlers, the
//! runtime's fork hooks, the lock reset in the child.
use crate::sys::*;
use crate::thread;
use core::ffi::{c_int, c_void};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::sync_cell::SyncCell;

type Handler = Option<unsafe extern "C" fn()>;

#[derive(Clone, Copy)]
struct Entry {
    prepare: Handler,
    parent: Handler,
    child: Handler,
    /// The shared object that registered the handlers (its `__dso_handle`), 0 for the program: dlclose removes them.
    dso: usize,
}

/// Most handlers one process can register (glibc has no fixed limit; this is a documented limit).
pub const MAX_HANDLERS: usize = 512;

static LOCK: RawMutex = RawMutex::new();

struct Table {
    entries: [Entry; MAX_HANDLERS],
    count: usize,
}

/// The registered handlers; touched only with LOCK held (`with_table`), or by the only thread of a forked child.
static TABLE: SyncCell<Table> = SyncCell::new(Table { entries: [Entry { prepare: None, parent: None, child: None, dso: 0 }; MAX_HANDLERS], count: 0 });
/// Forks running their handlers: while one is, a removed handler's slot stays (its handlers cleared) so that the running fork's
/// indexes stay valid; the slots are squeezed out at the next registration when none is running.
static FORKING: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Run `f` on the table with LOCK held (taken for sure, also in a single-threaded process). `f` must not take LOCK.
fn with_table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    LOCK.lock_always();
    // SAFETY: TABLE is touched only with LOCK held, which this thread now holds; `f` does not reach TABLE again.
    let r = unsafe { TABLE.with_unsync(f) };
    LOCK.unlock_always();
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>) -> c_int {
    register(prepare, parent, child, 0)
}

/// Register a set of fork handlers (`dso`: the registering object's handle, 0 for the program): 0 or ENOMEM.
pub fn register(prepare: Handler, parent: Handler, child: Handler, dso: usize) -> c_int {
    install_fork_hook();
    with_table(|t| {
        if t.count >= MAX_HANDLERS && FORKING.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            squeeze(t);
        }
        let n = t.count;
        if n >= MAX_HANDLERS {
            return ENOMEM;
        }
        t.entries[n] = Entry { prepare, parent, child, dso };
        t.count = n + 1;
        0
    })
}

/// `__register_atfork`, the name glibc's shared libraries use: the handlers go with the registering object (`dso`, its
/// `__dso_handle`) and are dropped when it is unloaded.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __register_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>, dso: *mut c_void) -> c_int {
    register(prepare, parent, child, dso as usize)
}

/// Drop the fork handlers that the shared object `dso` registered (`finalize` calls this through `process::ATFORK_UNREGISTER` when
/// the object is unloaded: glibc's `__cxa_finalize` calls `__unregister_atfork`).
extern "C" fn unregister_dso(dso: usize) {
    if dso == 0 {
        return;
    }
    with_table(|t| {
        let n = t.count;
        for e in t.entries.iter_mut().take(n) {
            if e.dso == dso {
                *e = Entry { prepare: None, parent: None, child: None, dso: 0 };
            }
        }
    })
}

/// Remove the slots whose handlers are all gone (the lock is held and no fork is running).
fn squeeze(t: &mut Table) {
    let mut keep = 0;
    for i in 0..t.count {
        let e = t.entries[i];
        if e.prepare.is_some() || e.parent.is_some() || e.child.is_some() {
            t.entries[keep] = e;
            keep += 1;
        }
    }
    t.count = keep;
}

fn entry(i: usize) -> Entry {
    with_table(|t| t.entries[i])
}

fn count() -> usize {
    with_table(|t| t.count)
}

/// Call a fork handler, if there is one.
///
/// # Safety
/// `h` is a handler the program registered (it may be called).
unsafe fn call(h: Handler) {
    if let Some(f) = h {
        // SAFETY: forwarded contract.
        unsafe { f() };
    }
}

/// fork with atfork handlers. `raw` performs the system call and returns what `fork` returns (the
/// child's pid in the parent, 0 in the child, -1 with errno set on failure).
///
/// # Safety
/// `raw` makes the fork system call (or fails); the registered handlers may be called.
pub unsafe fn fork_with_handlers(raw: impl FnOnce() -> c_int) -> c_int {
    FORKING.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    let n = count();
    for i in (0..n).rev() {
        // SAFETY: a handler the program registered (forwarded contract).
        unsafe { call(entry(i).prepare) };
    }
    // the runtime's own layers (stdio: every stream lock), then the allocator's lock, which is
    // held across the fork, last in and first out
    // SAFETY: the runtime's prepare hooks, before the fork as they expect.
    unsafe { rusty_libc_core::process::run_fork_prepare() };
    rusty_libc_malloc::atfork_prepare();
    // no signal handler may run between the system call and the child's state reset
    let old = sigprocmask_set(2, u64::MAX);
    let pid = raw();
    if pid == 0 {
        // SAFETY: in the child, right after the fork, with only this thread and signals blocked (the reset hooks' contract).
        unsafe { rusty_libc_core::tls::loader_fork_child() };
        rusty_libc_malloc::atfork_child();
        // SAFETY: as above.
        unsafe { thread::after_fork_child() };
        crate::sync::once_fork_child();
        // SAFETY: as above: the child has one thread, so nothing uses LOCK while it is reset (a plain atomic word).
        unsafe { core::ptr::write(&raw const LOCK as *mut RawMutex, RawMutex::new()) };
        // SAFETY: as above.
        unsafe { rusty_libc_core::process::run_fork_child() };
        sigprocmask_set(2, old);
        for i in 0..n {
            // SAFETY: a handler the program registered.
            unsafe { call(entry(i).child) };
        }
    } else {
        rusty_libc_malloc::atfork_parent();
        // SAFETY: the runtime's parent hooks, after the fork as they expect.
        unsafe { rusty_libc_core::process::run_fork_parent() };
        sigprocmask_set(2, old);
        for i in 0..n {
            // SAFETY: a handler the program registered.
            unsafe { call(entry(i).parent) };
        }
    }
    FORKING.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    pid
}

/// Make rusty-libc-sys's `fork` run the atfork handlers and reset thread state in the child (called when the
/// first handler is registered or the first thread is created).
pub fn install_fork_hook() {
    rusty_libc_core::process::FORK_HOOK.store(__rlibc_fork as unsafe extern "C" fn() -> c_int as usize, core::sync::atomic::Ordering::Relaxed);
    rusty_libc_core::process::ATFORK_UNREGISTER.with(|h| *h = Some(unregister_dso));
}

/// C entry for fork with atfork handlers (`fork` itself is rusty-libc-sys's raw call until it is wired to
/// `fork_with_handlers`; the C test calls this one).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rlibc_fork() -> c_int {
    // SAFETY: the program's registered handlers may be called (C contract of fork).
    unsafe { fork() }
}

/// fork with handlers, using rusty-libc-core's raw system call (errno set on failure).
///
/// # Safety
/// The registered handlers may be called.
pub unsafe fn fork() -> c_int {
    let raw = || {
        // SAFETY: the fork system call; the child's state is reset by fork_with_handlers right after.
        match unsafe { rusty_libc_core::unistd::fork() } {
            Ok(pid) => pid,
            Err(e) => {
                rusty_libc_core::errno::set(e.0);
                -1
            }
        }
    };
    // SAFETY: forwarded contract.
    unsafe { fork_with_handlers(raw) }
}
