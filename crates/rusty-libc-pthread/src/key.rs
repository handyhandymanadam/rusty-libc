use crate::sys::*;
use crate::thread::{Thread, current_thread};
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

pub const PTHREAD_KEYS_MAX: usize = 1024;
pub const PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4;
const FIRST_LEVEL: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyData {
    pub seq: usize,
    pub data: *mut c_void,
}

struct KeySlot {
    seq: AtomicUsize,
    destr: AtomicUsize,
}

#[allow(clippy::declare_interior_mutable_const)]
const SLOT: KeySlot = KeySlot { seq: AtomicUsize::new(0), destr: AtomicUsize::new(0) };
static KEYS: [KeySlot; PTHREAD_KEYS_MAX] = [SLOT; PTHREAD_KEYS_MAX];

const SECOND_BYTES: usize = (PTHREAD_KEYS_MAX - FIRST_LEVEL) * core::mem::size_of::<KeyData>();

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(key: *mut u32, destr: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    for (i, k) in KEYS.iter().enumerate() {
        let seq = k.seq.load(Ordering::Acquire);
        if seq & 1 == 0 && k.seq.compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            k.destr.store(destr.map_or(0, |f| f as usize), Ordering::Release);
            unsafe { *key = i as u32 };
            return 0;
        }
    }
    EAGAIN
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_delete(key: u32) -> c_int {
    if key as usize >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    let k = &KEYS[key as usize];
    let seq = k.seq.load(Ordering::Acquire);
    if seq & 1 != 0 && k.seq.compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        return 0;
    }
    EINVAL
}

unsafe fn slot_of(t: *mut Thread, key: usize, alloc: bool) -> *mut KeyData {
    unsafe {
        if key < FIRST_LEVEL {
            return &raw mut (*t).specific_1st[key];
        }
        if (*t).specific_2nd.is_null() {
            if !alloc {
                return core::ptr::null_mut();
            }
            match mmap(SECOND_BYTES.next_multiple_of(PAGE), 3) {
                Ok(p) => (*t).specific_2nd = p as *mut KeyData,
                Err(_) => return core::ptr::null_mut(),
            }
        }
        (*t).specific_2nd.add(key - FIRST_LEVEL)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(key: u32, value: *const c_void) -> c_int {
    unsafe {
        let key = key as usize;
        if key >= PTHREAD_KEYS_MAX {
            return EINVAL;
        }
        let seq = KEYS[key].seq.load(Ordering::Acquire);
        if seq & 1 == 0 {
            return EINVAL;
        }
        let t = current_thread();
        let s = slot_of(t, key, !value.is_null());
        if s.is_null() {
            return if value.is_null() { 0 } else { ENOMEM };
        }
        (*s).seq = seq;
        (*s).data = value as *mut c_void;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: u32) -> *mut c_void {
    unsafe {
        let key = key as usize;
        if key >= PTHREAD_KEYS_MAX {
            return core::ptr::null_mut();
        }
        let t = current_thread();
        let s = slot_of(t, key, false);
        if s.is_null() {
            return core::ptr::null_mut();
        }
        let data = (*s).data;
        if data.is_null() {
            return data;
        }
        if (*s).seq != KEYS[key].seq.load(Ordering::Acquire) {
            (*s).data = core::ptr::null_mut();
            return core::ptr::null_mut();
        }
        data
    }
}

pub unsafe fn run_destructors(t: *mut Thread) {
    unsafe {
        for _round in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
            let mut found = false;
            for key in 0..PTHREAD_KEYS_MAX {
                let s = slot_of(t, key, false);
                if s.is_null() {
                    break;
                }
                let data = (*s).data;
                if data.is_null() {
                    continue;
                }
                (*s).data = core::ptr::null_mut();
                let k = &KEYS[key];
                let destr = k.destr.load(Ordering::Acquire);
                if k.seq.load(Ordering::Acquire) == (*s).seq && destr != 0 {
                    let f: unsafe extern "C" fn(*mut c_void) = core::mem::transmute(destr);
                    f(data);
                    found = true;
                }
            }
            if !found {
                break;
            }
        }
    }
}

pub unsafe fn free_second_level(t: *mut Thread) {
    unsafe {
        if !(*t).specific_2nd.is_null() {
            munmap((*t).specific_2nd as *mut u8, SECOND_BYTES.next_multiple_of(PAGE));
            (*t).specific_2nd = core::ptr::null_mut();
        }
    }
}
