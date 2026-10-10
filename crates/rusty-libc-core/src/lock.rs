use crate::syscall::syscall4;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

const SYS_FUTEX: usize = 202;
const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;

#[cfg_attr(feature = "export-mem", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut __libc_single_threaded: u8 = 1;

#[cfg_attr(feature = "export-mem", unsafe(no_mangle))]
pub extern "C" fn __libc_early_init(initial: bool) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(__libc_single_threaded), initial as u8);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(LIBC_INITIAL), initial as u8);
    }
}

static mut LIBC_INITIAL: u8 = 1;

pub fn libc_initial() -> bool {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LIBC_INITIAL)) != 0 }
}

static AT_SECURE: AtomicU8 = AtomicU8::new(2);

pub fn set_at_secure(v: bool) {
    AT_SECURE.store(v as u8, Ordering::Relaxed);
}

pub fn at_secure() -> Option<bool> {
    match AT_SECURE.load(Ordering::Relaxed) {
        2 => None,
        v => Some(v != 0),
    }
}

pub fn note_multithreaded() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(__libc_single_threaded), 0) };
}

#[inline(always)]
pub fn multithreaded() -> bool {
    let v: i32;
    unsafe { core::arch::asm!("mov {0:e}, fs:[0x18]", out(reg) v, options(nostack, readonly, preserves_flags)) };
    v != 0
}

#[inline]
pub fn futex_wait(word: &AtomicU32, expected: u32) {
    unsafe { syscall4(SYS_FUTEX, word as *const AtomicU32 as usize, FUTEX_WAIT_PRIVATE, expected as usize, 0) };
}

#[inline]
pub fn futex_wake(word: &AtomicU32, n: u32) {
    unsafe { syscall4(SYS_FUTEX, word as *const AtomicU32 as usize, FUTEX_WAKE_PRIVATE, n as usize, 0) };
}

#[inline(always)]
pub unsafe fn take01_single_thread(w: &AtomicU32) -> bool {
    if w.load(Ordering::Relaxed) != 0 {
        return false;
    }
    w.store(1, Ordering::Relaxed);
    true
}

#[inline(always)]
pub unsafe fn release_single_thread(w: &AtomicU32) -> u32 {
    let s = w.load(Ordering::Relaxed);
    w.store(0, Ordering::Release);
    s
}

pub struct RawMutex {
    state: AtomicU32,
}

impl Default for RawMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl RawMutex {
    pub const fn new() -> RawMutex {
        RawMutex { state: AtomicU32::new(0) }
    }

    #[inline]
    pub fn lock_always(&self) {
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            self.lock_slow();
        }
    }

    #[cold]
    fn lock_slow(&self) {
        let mut spins = 0;
        while spins < 50 {
            if self.state.load(Ordering::Relaxed) == 0 && self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                return;
            }
            core::hint::spin_loop();
            spins += 1;
        }
        while self.state.swap(2, Ordering::Acquire) != 0 {
            futex_wait(&self.state, 2);
        }
    }

    #[inline]
    pub fn try_lock_always(&self) -> bool {
        self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    #[inline]
    pub fn unlock_always(&self) {
        if self.state.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.state, 1);
        }
    }

    #[inline(always)]
    pub fn lock_fast(&self) {
        if !multithreaded() && unsafe { take01_single_thread(&self.state) } {
            return;
        }
        self.lock_always();
    }

    #[inline(always)]
    pub unsafe fn take_single_thread(&self) -> bool {
        unsafe { take01_single_thread(&self.state) }
    }

    #[inline(always)]
    pub fn try_lock_fast(&self) -> bool {
        if !multithreaded() {
            return unsafe { take01_single_thread(&self.state) };
        }
        self.try_lock_always()
    }

    #[inline(always)]
    pub fn unlock_fast(&self) {
        if !multithreaded() {
            if unsafe { release_single_thread(&self.state) } == 2 {
                futex_wake(&self.state, 1);
            }
            return;
        }
        self.unlock_always();
    }

    #[inline(always)]
    pub fn lock(&self) -> bool {
        if !multithreaded() {
            return false;
        }
        self.lock_always();
        true
    }

    #[inline(always)]
    pub fn unlock(&self, taken: bool) {
        if taken {
            self.unlock_always();
        }
    }

    #[inline]
    pub unsafe fn with_cancel_unlock<R>(&'static self, body: impl FnOnce() -> R) -> R {
        unsafe extern "C" fn release(arg: *mut core::ffi::c_void) {
            unsafe { (*(arg as *const RawMutex)).unlock_always() };
        }
        let taken = self.lock();
        let r = if taken { unsafe { crate::cleanup::with(release, self as *const RawMutex as *mut core::ffi::c_void, body) } } else { body() };
        self.unlock(taken);
        r
    }

    #[inline(always)]
    pub fn guard(&self) -> Guard<'_> {
        Guard { m: self, taken: self.lock() }
    }
}

pub struct Guard<'a> {
    m: &'a RawMutex,
    taken: bool,
}

impl Drop for Guard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.m.unlock(self.taken);
    }
}

pub struct Locked<T> {
    lock: RawMutex,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Locked<T> {}

impl<T> Locked<T> {
    pub const fn new(value: T) -> Locked<T> {
        Locked { lock: RawMutex::new(), value: UnsafeCell::new(value) }
    }

    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let _g = self.lock.guard();
        f(unsafe { &mut *self.value.get() })
    }
}

