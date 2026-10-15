use crate::attr::{ATTR_FLAG_POLICY_SET, ATTR_FLAG_SCHED_SET, sched_setscheduler};
use crate::sys::*;
use crate::thread::{Sched, Thread, field_of, with_sched_locked};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
const SCHED_FIFO: usize = 1;

static FIFO_MIN: AtomicI32 = AtomicI32::new(-1);
static FIFO_MAX: AtomicI32 = AtomicI32::new(-1);

pub fn init_fifo_prio() {
    FIFO_MAX.store(unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MAX, SCHED_FIFO) } as c_int, Ordering::Relaxed);
    FIFO_MIN.store(unsafe { rusty_libc_core::syscall::syscall1(SYS_SCHED_GET_PRIORITY_MIN, SCHED_FIFO) } as c_int, Ordering::Relaxed);
}

pub fn fifo_min() -> c_int {
    if FIFO_MIN.load(Ordering::Relaxed) == -1 {
        init_fifo_prio();
    }
    FIFO_MIN.load(Ordering::Relaxed)
}

pub fn fifo_range() -> (c_int, c_int) {
    if FIFO_MIN.load(Ordering::Relaxed) == -1 || FIFO_MAX.load(Ordering::Relaxed) == -1 {
        init_fifo_prio();
    }
    (FIFO_MIN.load(Ordering::Relaxed), FIFO_MAX.load(Ordering::Relaxed))
}

#[repr(C)]
pub struct Tpp {
    pub priomax: c_int,
    priomap: [u32; 0],
}

impl Tpp {
    #[inline]
    fn slot(this: *mut Tpp, i: c_int) -> *mut u32 {
        this.cast::<u8>().wrapping_add(core::mem::offset_of!(Tpp, priomap)).cast::<u32>().wrapping_add(i as usize)
    }
}

#[inline]
fn me() -> *mut Thread {
    crate::thread::current_thread()
}

fn my_tid(t: *mut Thread) -> i32 {
    unsafe { *field_of!(t, tcb.tid: i32) }
}

pub fn current_priority() -> c_int {
    let t = me();
    let cached: Sched = unsafe { *field_of!(t, sched: Sched) };
    if cached.flags & (ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET) == ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET {
        return cached.prio;
    }
    let tid = my_tid(t);
    unsafe { with_sched_locked(t, |s| if s.fill(tid) != 0 { -1 } else { s.prio }) }
}

pub fn change_priority(previous: c_int, new: c_int) -> c_int {
    let t = me();
    let tpp_field = field_of!(t, tpp: *mut Tpp);
    let mut tpp = unsafe { *tpp_field };
    let (min, max) = if tpp.is_null() {
        let (min, max) = fifo_range();
        let size = core::mem::size_of::<Tpp>() + (max - min + 1) as usize * core::mem::size_of::<u32>();
        tpp = unsafe { rusty_libc_malloc::calloc(size, 1) }.cast::<Tpp>();
        if tpp.is_null() {
            return ENOMEM;
        }
        unsafe { (*tpp).priomax = min - 1 };
        unsafe { *tpp_field = tpp };
        (min, max)
    } else {
        (FIFO_MIN.load(Ordering::Relaxed), FIFO_MAX.load(Ordering::Relaxed))
    };
    if (new != -1 && (new < min || new > max)) || (previous != -1 && (previous < min || previous > max)) {
        rusty_libc_core::process::abort();
    }
    let priomax = unsafe { (*tpp).priomax };
    let mut newpriomax = priomax;
    if new != -1 {
        let s = Tpp::slot(tpp, new - min);
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
        let c = unsafe { &mut *s };
        *c = c.wrapping_sub(1);
        if *c == 0 && priomax == previous && previous > new {
            let mut i = previous - 1;
            while i >= min {
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
    let body = |s: &mut Sched| {
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
    unsafe { with_sched_locked(t, body) }
}

#[inline]
pub unsafe fn boosted(t: *mut Thread, prio: c_int) -> c_int {
    let tpp = unsafe { *field_of!(t, tpp: *mut Tpp) };
    if tpp.is_null() {
        return prio;
    }
    let priomax = unsafe { (*tpp).priomax };
    if priomax > prio { priomax } else { prio }
}

pub unsafe fn free_table(t: *mut Thread) {
    let field = field_of!(t, tpp: *mut Tpp);
    let tpp = unsafe { *field };
    if !tpp.is_null() {
        unsafe { *field = core::ptr::null_mut() };
        unsafe { rusty_libc_malloc::free(tpp.cast()) };
    }
}
