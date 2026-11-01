//! The Rust API over the pthread layer, for programs that run on this libc without `std`:
//! `Mutex<T>`, `Condvar`, `RwLock<T>`, `Once`, thread-local `Key`s, and (with the `alloc` feature,
//! which needs a global allocator in the program) `spawn` and `JoinHandle`.
//! Every constructor is `const`, so these work in statics. Panics abort (the runtime is built with
//! panic = "abort").
//!
//! Condvar, RwLock locking, Once and Key use the safe cores of cond.rs, rwlock.rs and key.rs; unsafe is left for the
//! pthread mutex (raw), the guarded values and the spawned thread's packet.
use crate::sys::*;
use crate::*;
#[allow(unused_imports)]
use crate::{cond, key, rwlock};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

/// A mutual-exclusion lock around a value (a normal pthread mutex).
pub struct Mutex<T> {
    raw: UnsafeCell<pthread_mutex_t>,
    data: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a guard, which exists only while the pthread mutex is held, so moving the
// Mutex to another thread or sharing it gives at most one thread access to `T` at a time (as std's Mutex: `T: Send`).
unsafe impl<T: Send> Send for Mutex<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Sync for Mutex<T> {}

pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex {
            // all zero is PTHREAD_MUTEX_INITIALIZER
            raw: UnsafeCell::new(pthread_mutex_t { lock: AtomicU32::new(0), count: 0, owner: 0, nusers: 0, kind: 0, spins: 0, unused: 0, list_prev: core::ptr::null_mut(), list_next: core::ptr::null_mut() }),
            data: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        // SAFETY: our own initialised mutex, which lives as long as `self`.
        let r = unsafe { pthread_mutex_lock(self.raw.get()) };
        assert!(r == 0, "mutex lock failed");
        MutexGuard { m: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        // SAFETY: as in `lock`.
        if unsafe { pthread_mutex_trylock(self.raw.get()) } == 0 { Some(MutexGuard { m: self }) } else { None }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the mutex: no other thread reaches the value; the borrow is tied to the guard.
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, exclusively borrowed with the guard.
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the guard's mutex, held by this thread.
        unsafe { pthread_mutex_unlock(self.m.raw.get()) };
    }
}

/// A condition variable (default clock CLOCK_REALTIME for timed waits).
pub struct Condvar {
    raw: pthread_cond_t,
}

impl Condvar {
    pub const fn new() -> Condvar {
        Condvar { raw: cond::Cond::with_attr(0) }
    }

    /// Block until notified (spurious wake-ups happen: check the condition in a loop).
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        // SAFETY: the guard's mutex is held by this thread and lives as long as the guard.
        unsafe { cond::wait_common(&self.raw, guard.m.raw.get(), 0, None) };
        guard
    }

    /// Wait at most `ns` nanoseconds; the flag is true when the wait timed out.
    pub fn wait_timeout<'a, T>(&self, guard: MutexGuard<'a, T>, ns: i64) -> (MutexGuard<'a, T>, bool) {
        let mut abs = Timespec::default();
        clock_gettime(CLOCK_REALTIME, &mut abs);
        timespec_add_ns(&mut abs, ns);
        // SAFETY: as in `wait`.
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

/// A reader-writer lock around a value.
pub struct RwLock<T> {
    raw: pthread_rwlock_t,
    data: UnsafeCell<T>,
}

// SAFETY: the value is reached only through the guards, which exist only while the rwlock is held (shared for readers,
// exclusive for a writer), as std's RwLock: moving needs `T: Send`.
unsafe impl<T: Send> Send for RwLock<T> {}
// SAFETY: as above: readers share `&T` across threads (`T: Sync`), a writer gets `&mut T` (`T: Send`).
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
        // SAFETY: a read lock is held: no writer has `&mut T` meanwhile; the borrow is tied to the guard.
        unsafe { &*self.l.data.get() }
    }
}
impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the write lock is held: no other reference to the value exists.
        unsafe { &*self.l.data.get() }
    }
}
impl<T> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, exclusively borrowed with the guard.
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

/// Run an initialiser once. Threads that arrive while it runs wait for it.
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

/// A thread-local slot holding one pointer per thread (a pthread key). The destructor runs at thread
/// exit for every thread whose value is not null.
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

/// Give up the processor.
pub fn yield_now() {
    sched_yield();
}

/// The calling thread's id (a pthread_t).
pub fn current() -> pthread_t {
    pthread_self()
}

/// Sleep for `ns` nanoseconds (a cancellation point).
pub fn sleep_ns(ns: u64) {
    let ts = Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
    let mut rem = ts;
    let mut req = ts;
    loop {
        // SAFETY: both timespecs are locals borrowed for the call.
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

    /// Drop one of the packet's two references (the thread's or the handle's); the last one frees it.
    ///
    /// # Safety
    /// `p` is a packet made by `spawn_with` whose reference the caller owns and gives up.
    unsafe fn release<F, T>(p: *mut Packet<F, T>) {
        // SAFETY: the packet lives until its last reference is dropped (forwarded contract).
        if unsafe { &(*p).refs }.fetch_sub(1, Ordering::AcqRel) == 1 {
            // SAFETY: the last reference: nothing uses the box any more; it came from Box::into_raw.
            drop(unsafe { Box::from_raw(p) });
        }
    }

    unsafe extern "C" fn tramp<F: FnOnce() -> T, T>(arg: *mut c_void) -> *mut c_void {
        let p = arg as *mut Packet<F, T>;
        // SAFETY: `arg` is the packet spawn_with passed, alive while the thread holds its reference.
        let packet = unsafe { &*p };
        // SAFETY: the closure slot is touched only here, once.
        let f = unsafe { (*packet.f.get()).take() }.unwrap();
        let r = f();
        // SAFETY: the result slot is written only here and read by the joiner only after the thread has ended.
        unsafe { *packet.result.get() = Some(r) };
        // SAFETY: the thread's reference, given up.
        unsafe { release(p) };
        core::ptr::null_mut()
    }

    /// Owns the right to join (or detach) a spawned thread.
    pub struct JoinHandle<T> {
        th: pthread_t,
        packet: *mut c_void,
        take: unsafe fn(*mut c_void) -> Option<T>,
        free: unsafe fn(*mut c_void),
    }

    // SAFETY: the handle only carries the thread id and the packet reference; the result `T` crosses to the joining thread,
    // so `T: Send` (as std's JoinHandle).
    unsafe impl<T: Send> Send for JoinHandle<T> {}

    /// # Safety
    /// `p` is the handle's packet, after the thread has ended (joined).
    unsafe fn take_result<F, T>(p: *mut c_void) -> Option<T> {
        let p = p as *mut Packet<F, T>;
        // SAFETY: the packet is alive while the handle holds its reference (forwarded contract).
        let packet = unsafe { &*p };
        // SAFETY: the thread has ended, so the result slot is no longer written (forwarded contract).
        let r = unsafe { (*packet.result.get()).take() };
        // SAFETY: the handle's reference, given up.
        unsafe { release(p) };
        r
    }

    /// # Safety
    /// `p` is the handle's packet.
    unsafe fn free_packet<F, T>(p: *mut c_void) {
        // SAFETY: forwarded contract.
        unsafe { release(p as *mut Packet<F, T>) }
    }

    impl<T> JoinHandle<T> {
        /// Wait for the thread and return its result.
        pub fn join(self) -> T {
            // SAFETY: our own thread, not joined or detached before (the handle is consumed).
            let r = unsafe { crate::thread::join_common(self.th, None, CLOCK_REALTIME, None, true) };
            assert!(r == 0, "pthread_join failed");
            // SAFETY: the thread has ended; this is the handle's packet.
            unsafe { (self.take)(self.packet) }.expect("thread produced no result")
        }

        /// Let the thread run on its own; its result is dropped.
        pub fn detach(self) {
            // SAFETY: our own thread, not joined or detached before.
            unsafe { crate::thread::detach(self.th) };
            // SAFETY: the handle's packet.
            unsafe { (self.free)(self.packet) };
        }

        pub fn thread_id(&self) -> pthread_t {
            self.th
        }
    }

    /// Run `f` on a new thread with the default attributes (error: the errno of pthread_create).
    pub fn spawn<F, T>(f: F) -> Result<JoinHandle<T>, i32>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // SAFETY: the default attributes (no user stack).
        unsafe { spawn_with(None, f) }
    }

    /// As `spawn`, with a pthread attribute (stack size, detach state, ...).
    ///
    /// # Safety
    /// A user stack set in `attr` (pthread_attr_setstack) must be memory the new thread may use as its stack.
    pub unsafe fn spawn_with<F, T>(attr: Option<&pthread_attr_t>, f: F) -> Result<JoinHandle<T>, i32>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let p = Box::into_raw(Box::new(Packet::<F, T> { refs: AtomicU32::new(2), f: UnsafeCell::new(Some(f)), result: UnsafeCell::new(None) }));
        let mut th: pthread_t = 0;
        let attr = attr.map_or(core::ptr::null(), |a| a as *const pthread_attr_t);
        // SAFETY: `attr` is NULL or an initialised attribute whose user stack is usable (spawn_with's contract); the packet
        // outlives the thread's use.
        let r = unsafe { pthread_create(&mut th, attr, tramp::<F, T>, p as *mut c_void) };
        if r != 0 {
            // SAFETY: the thread was not made: the box is ours alone.
            drop(unsafe { Box::from_raw(p) });
            return Err(r);
        }
        Ok(JoinHandle { th, packet: p as *mut c_void, take: take_result::<F, T>, free: free_packet::<F, T> })
    }
}

#[cfg(feature = "alloc")]
pub use spawn::{JoinHandle, spawn, spawn_with};
