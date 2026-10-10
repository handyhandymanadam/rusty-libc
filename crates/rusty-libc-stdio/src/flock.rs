use crate::file::File;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use rusty_libc_core::cleanup::CleanupBuf;
use core::sync::atomic::{AtomicUsize, Ordering};
use rusty_libc_core::lock::{RawMutex, multithreaded};

pub struct FLock {
    m: RawMutex,
    owner: AtomicUsize,
    count: UnsafeCell<u32>,
}

unsafe impl Sync for FLock {}

impl Default for FLock {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn me() -> usize {
    rusty_libc_core::tls::current() as usize
}

impl FLock {
    pub const fn new() -> FLock {
        FLock { m: RawMutex::new(), owner: AtomicUsize::new(0), count: UnsafeCell::new(0) }
    }

    #[inline]
    pub fn lock(&self) {
        let me = me();
        if self.owner.load(Ordering::Relaxed) == me {
            unsafe { *self.count.get() += 1 };
            return;
        }
        if !multithreaded() && unsafe { self.m.take_single_thread() } {
            self.owner.store(me, Ordering::Relaxed);
            unsafe { *self.count.get() = 1 };
            return;
        }
        self.lock_first(me);
    }

    #[inline(never)]
    fn lock_first(&self, me: usize) {
        self.m.lock_fast();
        self.owner.store(me, Ordering::Relaxed);
        unsafe { *self.count.get() = 1 };
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        let me = me();
        if self.owner.load(Ordering::Relaxed) == me {
            unsafe { *self.count.get() += 1 };
            return true;
        }
        if !self.m.try_lock_fast() {
            return false;
        }
        self.owner.store(me, Ordering::Relaxed);
        unsafe { *self.count.get() = 1 };
        true
    }

    pub fn lock_timeout(&self, cycles: u64) -> bool {
        if self.try_lock() {
            return true;
        }
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        loop {
            unsafe { rusty_libc_core::syscall::syscall0(24) };
            if self.try_lock() {
                return true;
            }
            if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) > cycles {
                return false;
            }
        }
    }

    #[inline]
    pub fn unlock(&self) -> bool {
        if self.owner.load(Ordering::Relaxed) != me() {
            return false;
        }
        let c = unsafe {
            let c = *self.count.get() - 1;
            *self.count.get() = c;
            c
        };
        if c == 0 {
            self.owner.store(0, Ordering::Relaxed);
            self.m.unlock_fast();
        }
        true
    }

    pub fn held_by_me(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == me()
    }

    pub unsafe fn reset(&self) {
        unsafe {
            core::ptr::write(&self.m as *const RawMutex as *mut RawMutex, RawMutex::new());
            *self.count.get() = 0;
        }
        self.owner.store(0, Ordering::Relaxed);
    }
}

macro_rules! locked {
    ($f:expr, move || $body:expr) => {{
        let stream: *mut $crate::file::File = $f;
        if !rusty_libc_core::lock::multithreaded() { $body } else { $crate::flock::locked_mt(stream, move || $body) }
    }};
}
pub(crate) use locked;

unsafe extern "C" fn unlock_on_cancel(arg: *mut c_void) {
    unsafe {
        (*(arg as *mut File)).lock.unlock();
    }
}

pub struct LockCleanup {
    buf: MaybeUninit<CleanupBuf>,
    armed: bool,
}

impl LockCleanup {
    #[inline(always)]
    pub const fn idle() -> LockCleanup {
        LockCleanup { buf: MaybeUninit::uninit(), armed: false }
    }

    #[inline(always)]
    pub unsafe fn arm(&mut self, f: *mut File) {
        unsafe { rusty_libc_core::cleanup::push(self.buf.as_mut_ptr(), unlock_on_cancel, f.cast()) };
        self.armed = true;
    }

    #[inline(always)]
    pub fn disarm(&mut self) {
        if self.armed {
            unsafe { rusty_libc_core::cleanup::pop(self.buf.as_mut_ptr()) };
            self.armed = false;
        }
    }
}

impl Drop for LockCleanup {
    #[inline(always)]
    fn drop(&mut self) {
        self.disarm();
    }
}

#[inline(never)]
#[cold]
pub unsafe fn locked_mt<R, F: FnOnce() -> R>(f: *mut File, op: F) -> R {
    unsafe {
        let real = !(*f).nolock;
        let mut cg = LockCleanup::idle();
        if real {
            (*f).lock.lock();
            cg.arm(f);
        }
        let r = op();
        if real {
            cg.disarm();
            (*f).lock.unlock();
        }
        r
    }
}

#[inline(always)]
pub unsafe fn lock_file(f: *mut File) -> bool {
    if !multithreaded() {
        return false;
    }
    unsafe {
        if (*f).nolock {
            return false;
        }
        (*f).lock.lock();
    }
    true
}

#[inline(always)]
pub unsafe fn unlock_file(f: *mut File, token: bool) {
    if token {
        unsafe { (*f).lock.unlock() };
    }
}

pub struct StreamGuard {
    f: *mut File,
    token: bool,
    cleanup: LockCleanup,
}

impl StreamGuard {
    #[inline(always)]
    pub const fn idle() -> StreamGuard {
        StreamGuard { f: core::ptr::null_mut(), token: false, cleanup: LockCleanup::idle() }
    }

    #[inline(always)]
    pub unsafe fn lock(&mut self, f: *mut File) {
        self.f = f;
        unsafe {
            self.token = lock_file(f);
            if self.token {
                self.cleanup.arm(f);
            }
        }
    }
}

impl Drop for StreamGuard {
    #[inline(always)]
    fn drop(&mut self) {
        self.cleanup.disarm();
        unsafe { unlock_file(self.f, self.token) };
    }
}
