//! Priority protection (PTHREAD_PRIO_PROTECT mutexes): the per-thread table of the ceilings the thread holds and the
//! priority boost, as glibc 2.43 keeps them (nptl/tpp.c, behaviour reference only; own code).
//!
//! Each thread that ever locks a PP mutex gets a table (from calloc, on first use) with one counter per SCHED_FIFO priority
//! and `priomax`, the highest ceiling counted. Raising `priomax` above the thread's base priority (the cached
//! `sched_prio`, which pthread_getschedparam reports) sets the kernel priority to `priomax` with sched_setscheduler under the
//! cached policy; lowering it sets the kernel priority back. glibc's quirks are kept on purpose: the counter and `priomax`
//! stay raised when that sched_setscheduler fails (an ordinary SCHED_OTHER thread: EINVAL), so the next lock of the same
//! ceiling needs no system call and succeeds; a PP timedlock that times out keeps its boost. pthread_setschedparam and
//! pthread_setschedprio never set the kernel priority below `priomax`.
//!
//! Unsafe left: the table (a calloc block with a counter per priority after its header) is reached through the
//! descriptor's raw `tpp` pointer; the counters are touched only by the owning thread, `priomax` also by others under the
//! thread's lock.
use crate::attr::{ATTR_FLAG_POLICY_SET, ATTR_FLAG_SCHED_SET, sched_setscheduler};
use crate::sys::*;
use crate::thread::{Sched, Thread, field_of, with_sched_locked};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
const SCHED_FIFO: usize = 1;

/// SCHED_FIFO's priority range, asked once (glibc's __sched_fifo_min_prio / __sched_fifo_max_prio); -1 until known.
static FIFO_MIN: AtomicI32 = AtomicI32::new(-1);
static FIFO_MAX: AtomicI32 = AtomicI32::new(-1);

/// Ask the kernel for SCHED_FIFO's range (maximum first, as glibc).
pub fn init_fifo_prio() {
    // SAFETY: plain-value system call.
    FIFO_MAX.store(unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MAX, SCHED_FIFO) } as c_int, Ordering::Relaxed);
    // SAFETY: plain-value system call.
    FIFO_MIN.store(unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MIN, SCHED_FIFO) } as c_int, Ordering::Relaxed);
}

/// The SCHED_FIFO minimum, asking the kernel if it is not known yet (only the minimum is checked, as glibc does where it
/// needs only that one).
pub fn fifo_min() -> c_int {
    if FIFO_MIN.load(Ordering::Relaxed) == -1 {
        init_fifo_prio();
    }
    FIFO_MIN.load(Ordering::Relaxed)
}

/// (minimum, maximum) of SCHED_FIFO, asking the kernel if either is unknown.
pub fn fifo_range() -> (c_int, c_int) {
    if FIFO_MIN.load(Ordering::Relaxed) == -1 || FIFO_MAX.load(Ordering::Relaxed) == -1 {
        init_fifo_prio();
    }
    (FIFO_MIN.load(Ordering::Relaxed), FIFO_MAX.load(Ordering::Relaxed))
}

/// glibc's struct priority_protection_data: `priomax`, then one counter per priority from the SCHED_FIFO minimum.
#[repr(C)]
pub struct Tpp {
    pub priomax: c_int,
    priomap: [u32; 0],
}

impl Tpp {
    /// The address of counter `i` (pointer arithmetic only).
    #[inline]
    fn slot(this: *mut Tpp, i: c_int) -> *mut u32 {
        this.cast::<u8>().wrapping_add(core::mem::offset_of!(Tpp, priomap)).cast::<u32>().wrapping_add(i as usize)
    }
}

#[cfg(not(test))]
#[inline]
fn me() -> *mut Thread {
    crate::thread::current_thread()
}

// Host unit tests: the thread pointer belongs to the host libc, so each test thread gets a zeroed descriptor of its own.
#[cfg(test)]
fn me() -> *mut Thread {
    thread_local! {
        static FAKE: core::cell::Cell<*mut Thread> = const { core::cell::Cell::new(core::ptr::null_mut()) };
    }
    FAKE.with(|c| {
        if c.get().is_null() {
            // SAFETY: a zeroed descriptor is a valid Thread for these tests (it is never freed: one per test thread).
            let p = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<Thread>()) } as *mut Thread;
            // SAFETY: `p` is the fresh block above.
            unsafe { *field_of!(p, tcb.tid: i32) = gettid() };
            c.set(p);
        }
        c.get()
    })
}

/// The calling thread's kernel thread id as its descriptor records it.
fn my_tid(t: *mut Thread) -> i32 {
    // SAFETY: `t` is the calling thread's own live descriptor (me()).
    unsafe { *field_of!(t, tcb.tid: i32) }
}

/// The calling thread's base priority (glibc's __pthread_current_priority): the cached value, asking the kernel for what
/// is not cached yet; -1 if that fails.
pub fn current_priority() -> c_int {
    let t = me();
    // (read without the lock first, as glibc: only this thread and lock holders change it)
    // SAFETY: the calling thread's own live descriptor.
    let cached: Sched = unsafe { *field_of!(t, sched: Sched) };
    if cached.flags & (ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET) == ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET {
        return cached.prio;
    }
    let tid = my_tid(t);
    // SAFETY: the calling thread's own live descriptor; the closure does not take its lock.
    unsafe { with_sched_locked(t, |s| if s.fill(tid) != 0 { -1 } else { s.prio }) }
}

/// The calling thread stops counting ceiling `previous` (-1: none) and starts counting `new` (-1: none); when the highest
/// counted ceiling changes, the kernel priority follows (glibc's __pthread_tpp_change_priority). 0, ENOMEM, EAGAIN or the
/// errno of the scheduling call.
pub fn change_priority(previous: c_int, new: c_int) -> c_int {
    let t = me();
    let tpp_field = field_of!(t, tpp: *mut Tpp);
    // SAFETY: the calling thread's own live descriptor; only this thread sets its `tpp`.
    let mut tpp = unsafe { *tpp_field };
    let (min, max) = if tpp.is_null() {
        let (min, max) = fifo_range();
        let size = core::mem::size_of::<Tpp>() + (max - min + 1) as usize * core::mem::size_of::<u32>();
        // SAFETY: plain allocation call.
        tpp = unsafe { rusty_libc_malloc::calloc(size, 1) }.cast::<Tpp>();
        if tpp.is_null() {
            return ENOMEM;
        }
        // SAFETY: the fresh zeroed block (calloc aligns for any type), not yet visible to other threads.
        unsafe { (*tpp).priomax = min - 1 };
        // SAFETY: as above (own descriptor).
        unsafe { *tpp_field = tpp };
        (min, max)
    } else {
        (FIFO_MIN.load(Ordering::Relaxed), FIFO_MAX.load(Ordering::Relaxed))
    };
    // glibc asserts both are -1 or within the SCHED_FIFO range (a hand-made mutex word with ceiling 0 aborts there)
    if (new != -1 && (new < min || new > max)) || (previous != -1 && (previous < min || previous > max)) {
        rusty_libc_core::process::abort();
    }
    // SAFETY: the table is this thread's (made above or earlier); `priomax` changes only under this thread's lock, which
    // only this thread takes to change it, so reading it here without the lock sees its own last value.
    let priomax = unsafe { (*tpp).priomax };
    let mut newpriomax = priomax;
    if new != -1 {
        let s = Tpp::slot(tpp, new - min);
        // SAFETY: `new - min` is within the table's max - min + 1 counters (checked above); only this thread touches them.
        let c = unsafe { &mut *s };
        if c.wrapping_add(1) == 0 {
            return EAGAIN;
        }
        *c += 1;
        if new > priomax {
            newpriomax = new;
        }
    }
    if previous != -1 {
        let s = Tpp::slot(tpp, previous - min);
        // SAFETY: as above, for `previous`.
        let c = unsafe { &mut *s };
        *c = c.wrapping_sub(1);
        if *c == 0 && priomax == previous && previous > new {
            let mut i = previous - 1;
            while i >= min {
                // SAFETY: min <= i < previous <= max: a counter of the table.
                if unsafe { *Tpp::slot(tpp, i - min) } != 0 {
                    break;
                }
                i -= 1;
            }
            newpriomax = i;
        }
    }
    if priomax == newpriomax {
        return 0;
    }
    let tid = my_tid(t);
    // as glibc: the thread's own lock, so a pthread_setschedparam / setschedprio from another thread sees the new
    // priomax and the kernel priority together
    let body = |s: &mut Sched| {
        // SAFETY: the table is this thread's and its lock is held (boosted reads priomax under it).
        unsafe { (*tpp).priomax = newpriomax };
        let mut result = s.fill(tid);
        if result == 0 {
            let base = s.prio;
            if base < newpriomax || base < priomax {
                let sp = SchedParam { sched_priority: if base < newpriomax { newpriomax } else { base } };
                result = sched_setscheduler(tid, s.policy, &sp);
            }
        }
        result
    };
    // SAFETY: the calling thread's own descriptor; the closure does not take its lock.
    unsafe { with_sched_locked(t, body) }
}

/// The priority pthread_setschedparam / pthread_setschedprio give the kernel for thread `t`: never below the highest
/// ceiling it holds.
///
/// # Safety
/// `t` is a live thread descriptor whose `lock` the caller holds.
#[inline]
pub unsafe fn boosted(t: *mut Thread, prio: c_int) -> c_int {
    // SAFETY: `t` is live (caller's contract); `tpp` changes only while the thread runs, under the held lock or before it
    // becomes visible.
    let tpp = unsafe { *field_of!(t, tpp: *mut Tpp) };
    if tpp.is_null() {
        return prio;
    }
    // SAFETY: a non-NULL `tpp` is the thread's table; `priomax` changes only under the lock the caller holds.
    let priomax = unsafe { (*tpp).priomax };
    if priomax > prio { priomax } else { prio }
}

/// Free thread `t`'s table when its descriptor is reclaimed (a join, pthread_detach of an ended thread, the end of a
/// detached thread), as glibc's __nptl_free_tcb: until then an ended but unjoined thread keeps its ceilings, which
/// pthread_setschedparam and pthread_setschedprio on it still apply.
///
/// # Safety
/// `t` is a thread descriptor that no other thread changes concurrently (it has ended, or is ending and detached).
pub unsafe fn free_table(t: *mut Thread) {
    let field = field_of!(t, tpp: *mut Tpp);
    // SAFETY: `t` is valid and not changed concurrently (caller's contract).
    let tpp = unsafe { *field };
    if !tpp.is_null() {
        // SAFETY: as above.
        unsafe { *field = core::ptr::null_mut() };
        // SAFETY: the table came from calloc (change_priority) and nothing uses it any more.
        unsafe { rusty_libc_malloc::free(tpp.cast()) };
    }
}
