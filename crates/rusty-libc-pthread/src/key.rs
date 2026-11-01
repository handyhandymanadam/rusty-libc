//! Thread-specific data: pthread_key_create/delete, getspecific/setspecific, destructors at thread
//! exit. 1024 keys; the first 32 values of a thread live in its descriptor, the rest in a 16 KiB
//! mapping made on first use. A key has a sequence number (odd while in use); a stored value is only
//! valid while its sequence number equals the key's, so deleting a key invalidates every thread's
//! value for it without visiting the threads (the same scheme as glibc; the generation-counter design of the NPTL paper,
//! Drepper and Molnar, "The Native POSIX Thread Library for Linux", section 5.4).
//!
//! Unsafe left here: the slots live in the thread descriptor and its second-level mapping, touched through raw pointers
//! (only the owning thread touches them); the destructor call.
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

/// A free key with `destr` as its destructor (the lowest free number), or EAGAIN when all 1024 are in use.
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

/// `pthread_key_delete`: every thread's value for the key becomes invalid (its sequence number moves on).
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
            // SAFETY: `key` is a writable pthread_key_t (C contract; written without a NULL check, as glibc).
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

/// The address of thread `t`'s first-level slot `key` (< 32): pointer arithmetic only, nothing is read.
#[inline(always)]
fn slot_1st(t: *mut Thread, key: usize) -> *mut KeyData {
    debug_assert!(key < FIRST_LEVEL);
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(Thread, specific_1st)).cast::<KeyData>().wrapping_add(key)
}

/// The address of thread `t`'s `specific_2nd` field.
#[inline(always)]
fn second_field(t: *mut Thread) -> *mut *mut KeyData {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(Thread, specific_2nd)).cast()
}

/// The slot of `key` in thread `t`'s storage, making the second-level block if `alloc` (NULL: no block, or no memory).
///
/// # Safety
/// `t` is a live thread descriptor whose thread-specific data only the calling thread touches (its own, or one it is
/// tearing down).
unsafe fn slot_of(t: *mut Thread, key: usize, alloc: bool) -> *mut KeyData {
    if key < FIRST_LEVEL {
        return slot_1st(t, key);
    }
    let field = second_field(t);
    // SAFETY: `t` is live and its TSD fields are ours (caller's contract).
    let mut second = unsafe { *field };
    if second.is_null() {
        if !alloc {
            return core::ptr::null_mut();
        }
        match mmap(SECOND_BYTES.next_multiple_of(PAGE), 3) {
            Ok(p) => {
                second = p.cast::<KeyData>();
                // SAFETY: as above.
                unsafe { *field = second };
            }
            Err(_) => return core::ptr::null_mut(),
        }
    }
    // (inside the block: key - 32 < 992 entries)
    second.wrapping_add(key - FIRST_LEVEL)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(key: u32, value: *const c_void) -> c_int {
    setspecific(key, value)
}

/// `pthread_setspecific` (the calling thread's storage only: safe).
#[inline(always)]
pub fn setspecific(key: u32, value: *const c_void) -> c_int {
    let key = key as usize;
    // the first 32 keys: a slot in the descriptor, no registers saved (the second level lives out of line)
    if key < FIRST_LEVEL {
        let seq = KEYS[key].seq.load(Ordering::Acquire);
        if seq & 1 == 0 {
            return EINVAL;
        }
        let s = slot_1st(current_thread(), key);
        // SAFETY: the calling thread's own slot in its live descriptor; only this thread touches it.
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
    // storing NULL where nothing is stored needs no memory
    // SAFETY: the calling thread's own descriptor.
    let s = unsafe { slot_of(current_thread(), key, !value.is_null()) };
    if s.is_null() {
        return if value.is_null() { 0 } else { ENOMEM };
    }
    // SAFETY: `s` is a slot of the calling thread's storage (slot_of), touched only by this thread.
    unsafe { *s = KeyData { seq, data: value as *mut c_void } };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: u32) -> *mut c_void {
    getspecific(key)
}

/// `pthread_getspecific` (the calling thread's storage only: safe).
#[inline(always)]
pub fn getspecific(key: u32) -> *mut c_void {
    let key = key as usize;
    if key >= PTHREAD_KEYS_MAX {
        return core::ptr::null_mut();
    }
    // SAFETY: the calling thread's own descriptor.
    let s = unsafe { slot_of(current_thread(), key, false) };
    if s.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `s` is a slot of the calling thread's storage, touched only by this thread.
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

/// Call the destructors of the thread's non-null values: up to 4 rounds, because a destructor may
/// store new values.
///
/// # Safety
/// `t` is the calling thread's descriptor.
pub unsafe fn run_destructors(t: *mut Thread) {
    for _round in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut found = false;
        for key in 0..PTHREAD_KEYS_MAX {
            // SAFETY: `t` is the calling thread's descriptor (caller's contract).
            let s = unsafe { slot_of(t, key, false) };
            if s.is_null() {
                // no second-level block: keys from 32 on have no values
                break;
            }
            // SAFETY: a slot of the calling thread's storage. The copy is taken and the slot cleared before the destructor
            // runs (it may store into the same slot).
            let slot = unsafe { &mut *s };
            let (data, seq) = (slot.data, slot.seq);
            if data.is_null() {
                continue;
            }
            slot.data = core::ptr::null_mut();
            let k = &KEYS[key];
            let destr = k.destr.load(Ordering::Acquire);
            if k.seq.load(Ordering::Acquire) == seq && destr != 0 {
                // SAFETY: a non-zero `destr` was stored from a `Destructor` by key_create.
                let f: Destructor = unsafe { core::mem::transmute::<usize, Destructor>(destr) };
                // SAFETY: the program's destructor, called with the value it stored, as POSIX describes.
                unsafe { f(data) };
                found = true;
            }
        }
        if !found {
            break;
        }
    }
}

/// Unmap the thread's second-level block.
///
/// # Safety
/// `t` is the calling thread's descriptor, after its destructors ran.
pub unsafe fn free_second_level(t: *mut Thread) {
    let field = second_field(t);
    // SAFETY: the calling thread's own descriptor (caller's contract).
    let second = unsafe { *field };
    if !second.is_null() {
        // SAFETY: the block was made by slot_of with this size; no value in it is used after the destructors.
        unsafe { munmap(second.cast::<u8>(), SECOND_BYTES.next_multiple_of(PAGE)) };
        // SAFETY: as above.
        unsafe { *field = core::ptr::null_mut() };
    }
}
