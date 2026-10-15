use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::sync_cell::SyncCell;

pub struct Spin<T> {
    lock: AtomicBool,
    value: SyncCell<T>,
}

impl<T: Send> Spin<T> {
    pub const fn new(value: T) -> Spin<T> {
        Spin { lock: AtomicBool::new(false), value: SyncCell::new(value) }
    }

    #[inline(always)]
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let r = unsafe { self.value.with_unsync(f) };
        self.lock.store(false, Ordering::Release);
        r
    }

}
