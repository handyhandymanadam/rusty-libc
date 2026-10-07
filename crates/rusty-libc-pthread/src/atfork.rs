use crate::sys::*;
use crate::thread;
use core::ffi::{c_int, c_void};
use rusty_libc_core::lock::RawMutex;

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
static mut TABLE: [Entry; MAX_HANDLERS] = [Entry { prepare: None, parent: None, child: None, dso: 0 }; MAX_HANDLERS];
static mut COUNT: usize = 0;
static FORKING: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>) -> c_int {
    unsafe { register(prepare, parent, child, 0) }
}

unsafe fn register(prepare: Handler, parent: Handler, child: Handler, dso: usize) -> c_int {
    unsafe {
        install_fork_hook();
        LOCK.lock_always();
        if COUNT >= MAX_HANDLERS && FORKING.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            squeeze();
        }
        let n = COUNT;
        if n >= MAX_HANDLERS {
            LOCK.unlock_always();
            return ENOMEM;
        }
        (*(&raw mut TABLE))[n] = Entry { prepare, parent, child, dso };
        COUNT = n + 1;
        LOCK.unlock_always();
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __register_atfork(prepare: Option<unsafe extern "C" fn()>, parent: Option<unsafe extern "C" fn()>, child: Option<unsafe extern "C" fn()>, dso: *mut c_void) -> c_int {
    unsafe { register(prepare, parent, child, dso as usize) }
}

unsafe extern "C" fn unregister_dso(dso: usize) {
    unsafe {
        if dso == 0 {
            return;
        }
        LOCK.lock_always();
        let t = &mut *(&raw mut TABLE);
        for e in t.iter_mut().take(COUNT) {
            if e.dso == dso {
                *e = Entry { prepare: None, parent: None, child: None, dso: 0 };
            }
        }
        LOCK.unlock_always();
    }
}

unsafe fn squeeze() {
    unsafe {
        let t = &mut *(&raw mut TABLE);
        let mut keep = 0;
        for i in 0..COUNT {
            if t[i].prepare.is_some() || t[i].parent.is_some() || t[i].child.is_some() {
                t[keep] = t[i];
                keep += 1;
            }
        }
        COUNT = keep;
    }
}

unsafe fn entry(i: usize) -> Entry {
    unsafe {
        LOCK.lock_always();
        let e = (*(&raw const TABLE))[i];
        LOCK.unlock_always();
        e
    }
}

unsafe fn count() -> usize {
    unsafe {
        LOCK.lock_always();
        let n = COUNT;
        LOCK.unlock_always();
        n
    }
}

pub unsafe fn fork_with_handlers(raw: impl FnOnce() -> c_int) -> c_int {
    unsafe {
        FORKING.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        let n = count();
        for i in (0..n).rev() {
            if let Some(f) = entry(i).prepare {
                f();
            }
        }
        rusty_libc_core::process::run_fork_prepare();
        rusty_libc_malloc::atfork_prepare();
        let old = sigprocmask_set(2, u64::MAX);
        let pid = raw();
        if pid == 0 {
            rusty_libc_malloc::atfork_child();
            thread::after_fork_child();
            crate::sync::once_fork_child();
            core::ptr::write(&raw const LOCK as *mut RawMutex, RawMutex::new());
            rusty_libc_core::process::run_fork_child();
            sigprocmask_set(2, old);
            for i in 0..n {
                if let Some(f) = entry(i).child {
                    f();
                }
            }
        } else {
            rusty_libc_malloc::atfork_parent();
            rusty_libc_core::process::run_fork_parent();
            sigprocmask_set(2, old);
            for i in 0..n {
                if let Some(f) = entry(i).parent {
                    f();
                }
            }
        }
        FORKING.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
        pid
    }
}

pub fn install_fork_hook() {
    rusty_libc_core::process::FORK_HOOK.store(__rlibc_fork as unsafe extern "C" fn() -> c_int as usize, core::sync::atomic::Ordering::Relaxed);
    rusty_libc_core::process::ATFORK_UNREGISTER.store(unregister_dso as unsafe extern "C" fn(usize) as usize, core::sync::atomic::Ordering::Relaxed);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rlibc_fork() -> c_int {
    unsafe { fork() }
}

pub unsafe fn fork() -> c_int {
    unsafe {
        fork_with_handlers(|| match rusty_libc_core::unistd::fork() {
            Ok(pid) => pid,
            Err(e) => {
                rusty_libc_core::errno::set(e.0);
                -1
            }
        })
    }
}
