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

type Destructor = unsafe extern "C" fn(*mut c_void);

pub fn key_create(destr: Option<Destructor>) -> Result<u32, c_int> {
    for (i, k) in KEYS.iter().enumerate() {
        let seq = k.seq.load(Ordering::Acquire);
        if seq & 1 == 0 && k.seq.compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            k.destr.store(destr.map_or(0, |f| f as usize), Ordering::Release);
            return Ok(i as u32);
        }
    }
    Err(EAGAIN)
}

pub fn key_delete(key: u32) -> c_int {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(key: *mut u32, destr: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    match key_create(destr) {
        Ok(k) => {
            unsafe { *key = k };
            0
        }
        Err(e) => e,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_delete(key: u32) -> c_int {
    key_delete(key)
}

#[inline(always)]
fn slot_1st(t: *mut Thread, key: usize) -> *mut KeyData {
    debug_assert!(key < FIRST_LEVEL);
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(Thread, specific_1st)).cast::<KeyData>().wrapping_add(key)
}

#[inline(always)]
fn second_field(t: *mut Thread) -> *mut *mut KeyData {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(Thread, specific_2nd)).cast()
}

unsafe fn slot_of(t: *mut Thread, key: usize, alloc: bool) -> *mut KeyData {
    if key < FIRST_LEVEL {
        return slot_1st(t, key);
    }
    let field = second_field(t);
    let mut second = unsafe { *field };
    if second.is_null() {
        if !alloc {
            return core::ptr::null_mut();
        }
        match mmap(SECOND_BYTES.next_multiple_of(PAGE), 3) {
            Ok(p) => {
                second = p.cast::<KeyData>();
                unsafe { *field = second };
            }
            Err(_) => return core::ptr::null_mut(),
        }
    }
    second.wrapping_add(key - FIRST_LEVEL)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(key: u32, value: *const c_void) -> c_int {
    setspecific(key, value)
}

#[inline(always)]
pub fn setspecific(key: u32, value: *const c_void) -> c_int {
    let key = key as usize;
    if key < FIRST_LEVEL {
        let seq = KEYS[key].seq.load(Ordering::Acquire);
        if seq & 1 == 0 {
            return EINVAL;
        }
        let s = slot_1st(current_thread(), key);
        unsafe { *s = KeyData { seq, data: value as *mut c_void } };
        return 0;
    }
    setspecific_2nd(key, value)
}

#[inline(never)]
fn setspecific_2nd(key: usize, value: *const c_void) -> c_int {
    if key >= PTHREAD_KEYS_MAX {
        return EINVAL;
    }
    let seq = KEYS[key].seq.load(Ordering::Acquire);
    if seq & 1 == 0 {
        return EINVAL;
    }
    let s = unsafe { slot_of(current_thread(), key, !value.is_null()) };
    if s.is_null() {
        return if value.is_null() { 0 } else { ENOMEM };
    }
    unsafe { *s = KeyData { seq, data: value as *mut c_void } };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: u32) -> *mut c_void {
    getspecific(key)
}

#[inline(always)]
pub fn getspecific(key: u32) -> *mut c_void {
    let key = key as usize;
    if key >= PTHREAD_KEYS_MAX {
        return core::ptr::null_mut();
    }
    let s = unsafe { slot_of(current_thread(), key, false) };
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let slot = unsafe { &mut *s };
    let data = slot.data;
    if data.is_null() {
        return data;
    }
    if slot.seq != KEYS[key].seq.load(Ordering::Acquire) {
        slot.data = core::ptr::null_mut();
        return core::ptr::null_mut();
    }
    data
}

pub unsafe fn run_destructors(t: *mut Thread) {
    for _round in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut found = false;
        for key in 0..PTHREAD_KEYS_MAX {
            let s = unsafe { slot_of(t, key, false) };
            if s.is_null() {
                break;
            }
            let slot = unsafe { &mut *s };
            let (data, seq) = (slot.data, slot.seq);
            if data.is_null() {
                continue;
            }
            slot.data = core::ptr::null_mut();
            let k = &KEYS[key];
            let destr = k.destr.load(Ordering::Acquire);
            if k.seq.load(Ordering::Acquire) == seq && destr != 0 {
                let f: Destructor = unsafe { core::mem::transmute::<usize, Destructor>(destr) };
                unsafe { f(data) };
                found = true;
            }
        }
        if !found {
            break;
        }
    }
}

pub unsafe fn free_second_level(t: *mut Thread) {
    let field = second_field(t);
    let second = unsafe { *field };
    if !second.is_null() {
        unsafe { munmap(second.cast::<u8>(), SECOND_BYTES.next_multiple_of(PAGE)) };
        unsafe { *field = core::ptr::null_mut() };
    }
}
