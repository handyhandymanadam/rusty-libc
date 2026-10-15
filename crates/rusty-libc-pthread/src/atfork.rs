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
    dso: usize,
}

pub const MAX_HANDLERS: usize = 512;

static LOCK: RawMutex = RawMutex::new();

struct Table {
    entries: [Entry; MAX_HANDLERS],
    count: usize,
}

static TABLE: SyncCell<Table> = SyncCell::new(Table { entries: [Entry { prepare: None, parent: None, child: None, dso: 0 }; MAX_HANDLERS], count: 0 });
static FORKING: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn with_table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    LOCK.lock_always();
    let r = unsafe { TABLE.with_unsync(f) };
    LOCK.unlock_always();
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>) -> c_int {
    register(prepare, parent, child, 0)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __register_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>, dso: *mut c_void) -> c_int {
    register(prepare, parent, child, dso as usize)
}

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

unsafe fn call(h: Handler) {
    if let Some(f) = h {
        unsafe { f() };
    }
}

pub unsafe fn fork_with_handlers(raw: impl FnOnce() -> c_int) -> c_int {
    FORKING.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    let n = count();
    for i in (0..n).rev() {
        unsafe { call(entry(i).prepare) };
    }
    unsafe { rusty_libc_core::process::run_fork_prepare() };
    rusty_libc_malloc::atfork_prepare();
    let old = sigprocmask_set(2, u64::MAX);
    let pid = raw();
    if pid == 0 {
        unsafe { rusty_libc_core::tls::loader_fork_child() };
        rusty_libc_malloc::atfork_child();
        unsafe { thread::after_fork_child() };
        crate::sync::once_fork_child();
        unsafe { core::ptr::write(&raw const LOCK as *mut RawMutex, RawMutex::new()) };
        unsafe { rusty_libc_core::process::run_fork_child() };
        sigprocmask_set(2, old);
        for i in 0..n {
            unsafe { call(entry(i).child) };
        }
    } else {
        rusty_libc_malloc::atfork_parent();
        unsafe { rusty_libc_core::process::run_fork_parent() };
        sigprocmask_set(2, old);
        for i in 0..n {
            unsafe { call(entry(i).parent) };
        }
    }
    FORKING.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    pid
}

pub fn install_fork_hook() {
    rusty_libc_core::process::FORK_HOOK.store(__rlibc_fork as unsafe extern "C" fn() -> c_int as usize, core::sync::atomic::Ordering::Relaxed);
    rusty_libc_core::process::ATFORK_UNREGISTER.with(|h| *h = Some(unregister_dso));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rlibc_fork() -> c_int {
    unsafe { fork() }
}

pub unsafe fn fork() -> c_int {
    let raw = || {
        match unsafe { rusty_libc_core::unistd::fork() } {
            Ok(pid) => pid,
            Err(e) => {
                rusty_libc_core::errno::set(e.0);
                -1
            }
        }
    };
    unsafe { fork_with_handlers(raw) }
}
