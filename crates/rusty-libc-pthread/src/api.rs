use crate::sys::*;
use crate::*;
#[allow(unused_imports)]
use crate::{cond, key, rwlock};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct Mutex<T> {
    raw: UnsafeCell<pthread_mutex_t>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex {
            raw: UnsafeCell::new(pthread_mutex_t { lock: AtomicU32::new(0), count: 0, owner: 0, nusers: 0, kind: 0, spins: 0, unused: 0, list_prev: core::ptr::null_mut(), list_next: core::ptr::null_mut() }),
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        let r = unsafe { pthread_mutex_lock(self.raw.get()) };
        assert!(r == 0, "mutex lock failed");
        MutexGuard { m: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if unsafe { pthread_mutex_trylock(self.raw.get()) } == 0 { Some(MutexGuard { m: self }) } else { None }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { pthread_mutex_unlock(self.m.raw.get()) };
    }
}

pub struct Condvar {
    raw: pthread_cond_t,
}

impl Condvar {
    pub const fn new() -> Condvar {
        Condvar { raw: cond::Cond::with_attr(0) }
    }

    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        unsafe { cond::wait_common(&self.raw, guard.m.raw.get(), 0, None) };
        guard
    }

    pub fn wait_timeout<'a, T>(&self, guard: MutexGuard<'a, T>, ns: i64) -> (MutexGuard<'a, T>, bool) {
        let mut abs = Timespec::default();
        clock_gettime(CLOCK_REALTIME, &mut abs);
        timespec_add_ns(&mut abs, ns);
        let r = unsafe { cond::wait_common(&self.raw, guard.m.raw.get(), CLOCK_REALTIME, Some(&abs)) };
        (guard, r == ETIMEDOUT)
    }

    pub fn notify_one(&self) {
        cond::signal(&self.raw);
    }

    pub fn notify_all(&self) {
        cond::broadcast(&self.raw);
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RwLock<T> {
    raw: pthread_rwlock_t,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

pub struct ReadGuard<'a, T> {
    l: &'a RwLock<T>,
}
pub struct WriteGuard<'a, T> {
    l: &'a RwLock<T>,
}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> RwLock<T> {
        RwLock { raw: rwlock::RwLock::with_kind(0, false), data: UnsafeCell::new(value) }
    }

    pub fn read(&self) -> ReadGuard<'_, T> {
        let r = rwlock::rdlock_full(&self.raw, 0, None);
        assert!(r == 0, "rwlock read lock failed");
        ReadGuard { l: self }
    }

    pub fn write(&self) -> WriteGuard<'_, T> {
        let r = rwlock::wrlock_full(&self.raw, 0, None);
        assert!(r == 0, "rwlock write lock failed");
        WriteGuard { l: self }
    }

    pub fn try_read(&self) -> Option<ReadGuard<'_, T>> {
        if rwlock::tryrdlock(&self.raw) == 0 { Some(ReadGuard { l: self }) } else { None }
    }

    pub fn try_write(&self) -> Option<WriteGuard<'_, T>> {
        if rwlock::trywrlock(&self.raw) == 0 { Some(WriteGuard { l: self }) } else { None }
    }
}

impl<T> Deref for ReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}
impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.l.data.get() }
    }
}
impl<T> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.l.data.get() }
    }
}
impl<T> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        rwlock::unlock(&self.l.raw);
    }
}
impl<T> Drop for WriteGuard<'_, T> {
    fn drop(&mut self) {
        rwlock::unlock(&self.l.raw);
    }
}

pub struct Once {
    state: AtomicU32,
}

impl Once {
    pub const fn new() -> Once {
        Once { state: AtomicU32::new(0) }
    }

    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }

    pub fn call_once(&self, f: impl FnOnce()) {
        if self.is_completed() {
            return;
        }
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire).is_ok() {
            f();
            self.state.store(2, Ordering::Release);
            futex_wake(&self.state, i32::MAX, true);
            return;
        }
        while self.state.load(Ordering::Acquire) != 2 {
            futex_wait(&self.state, 1, true);
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Key {
    key: AtomicU32,
    once: Once,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Key {
    pub const fn new(dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> Key {
        Key { key: AtomicU32::new(0), once: Once::new(), dtor }
    }

    fn id(&self) -> u32 {
        self.once.call_once(|| {
            let k = key::key_create(self.dtor);
            assert!(k.is_ok(), "no thread-specific data keys left");
            self.key.store(k.unwrap_or(0), Ordering::Relaxed);
        });
        self.key.load(Ordering::Relaxed)
    }

    pub fn get(&self) -> *mut c_void {
        key::getspecific(self.id())
    }

    pub fn set(&self, value: *mut c_void) {
        key::setspecific(self.id(), value);
    }
}

pub fn yield_now() {
    sched_yield();
}

pub fn current() -> pthread_t {
    pthread_self()
}

pub fn sleep_ns(ns: u64) {
    let ts = Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
    let mut rem = ts;
    let mut req = ts;
    loop {
        let r = unsafe { thrd_sleep(&req, &mut rem) };
        if r != -1 {
            return;
        }
        req = rem;
    }
}

#[cfg(feature = "alloc")]
mod spawn {
    use super::*;
    use alloc::boxed::Box;

    struct Packet<F, T> {
        refs: AtomicU32,
        f: UnsafeCell<Option<F>>,
        result: UnsafeCell<Option<T>>,
    }

    unsafe fn release<F, T>(p: *mut Packet<F, T>) {
        if unsafe { &(*p).refs }.fetch_sub(1, Ordering::AcqRel) == 1 {
            drop(unsafe { Box::from_raw(p) });
        }
    }

    unsafe extern "C" fn tramp<F: FnOnce() -> T, T>(arg: *mut c_void) -> *mut c_void {
        let p = arg as *mut Packet<F, T>;
        let packet = unsafe { &*p };
        let f = unsafe { (*packet.f.get()).take() }.unwrap();
        let r = f();
        unsafe { *packet.result.get() = Some(r) };
        unsafe { release(p) };
        core::ptr::null_mut()
    }

    pub struct JoinHandle<T> {
        th: pthread_t,
        packet: *mut c_void,
        take: unsafe fn(*mut c_void) -> Option<T>,
        free: unsafe fn(*mut c_void),
    }

    unsafe impl<T: Send> Send for JoinHandle<T> {}

    unsafe fn take_result<F, T>(p: *mut c_void) -> Option<T> {
        let p = p as *mut Packet<F, T>;
        let packet = unsafe { &*p };
        let r = unsafe { (*packet.result.get()).take() };
        unsafe { release(p) };
        r
    }

    unsafe fn free_packet<F, T>(p: *mut c_void) {
        unsafe { release(p as *mut Packet<F, T>) }
    }

    impl<T> JoinHandle<T> {
        pub fn join(self) -> T {
            let r = unsafe { crate::thread::join_common(self.th, None, CLOCK_REALTIME, None, true) };
            assert!(r == 0, "pthread_join failed");
            unsafe { (self.take)(self.packet) }.expect("thread produced no result")
        }

        pub fn detach(self) {
            unsafe { crate::thread::detach(self.th) };
            unsafe { (self.free)(self.packet) };
        }

        pub fn thread_id(&self) -> pthread_t {
            self.th
        }
    }

    pub fn spawn<F, T>(f: F) -> Result<JoinHandle<T>, i32>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        unsafe { spawn_with(None, f) }
    }

    pub unsafe fn spawn_with<F, T>(attr: Option<&pthread_attr_t>, f: F) -> Result<JoinHandle<T>, i32>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let p = Box::into_raw(Box::new(Packet::<F, T> { refs: AtomicU32::new(2), f: UnsafeCell::new(Some(f)), result: UnsafeCell::new(None) }));
        let mut th: pthread_t = 0;
        let attr = attr.map_or(core::ptr::null(), |a| a as *const pthread_attr_t);
        let r = unsafe { pthread_create(&mut th, attr, tramp::<F, T>, p as *mut c_void) };
        if r != 0 {
            drop(unsafe { Box::from_raw(p) });
            return Err(r);
        }
        Ok(JoinHandle { th, packet: p as *mut c_void, take: take_result::<F, T>, free: free_packet::<F, T> })
    }
}

#[cfg(feature = "alloc")]
pub use spawn::{JoinHandle, spawn, spawn_with};
