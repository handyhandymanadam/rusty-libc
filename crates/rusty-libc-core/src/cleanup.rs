//! The cancellation cleanup stack: a per-thread linked list of handlers, innermost first. There is no
//! stack unwinding here, so everything that must be undone when a thread is cancelled or calls
//! `pthread_exit` registers itself in this list: `pthread_cleanup_push` of the program, and the
//! library's own critical sections that contain a cancellation point (a stdio stream lock held across
//! a `read`, the mutex a condition wait re-acquires, ...). Cancelling runs the handlers newest first
//! (rusty-libc-pthread), glibc runs the same handlers from its unwinder.
//!
//! A buffer lives on the stack of the registering function and is popped in the same function; the
//! list head is a `#[thread_local]` so that it works in host unit tests too.
//!
//! The list is intrusive (the nodes are the callers' stack buffers), so it is raw pointers by nature (The Rust Reference
//! p.628: a structure invariant discharges the unsafe blocks). Invariant: every node reachable from `HEAD` was pushed by
//! this thread and is still live (its owner pops it before its frame ends); only this thread reads or writes the list.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::cell::Cell;
use core::ffi::{c_int, c_void};

/// glibc's `struct _pthread_cleanup_buffer` (what the C macros place on the caller's stack).
#[repr(C)]
pub struct CleanupBuf {
    pub routine: unsafe extern "C" fn(*mut c_void),
    pub arg: *mut c_void,
    pub canceltype: c_int,
    pub prev: *mut CleanupBuf,
}

#[thread_local]
static HEAD: Cell<*mut CleanupBuf> = Cell::new(core::ptr::null_mut());

/// The innermost registered buffer of the calling thread (null if none).
#[inline]
pub fn head() -> *mut CleanupBuf {
    HEAD.get()
}

/// Replace the head (used by the code that runs the handlers while a thread ends).
#[inline]
pub fn set_head(p: *mut CleanupBuf) {
    HEAD.set(p);
}

/// Register `routine(arg)` as the innermost handler of the calling thread.
///
/// # Safety
/// `buf` must stay valid until `pop(buf)` (or the thread ends), and `pop` must come before any older
/// buffer is popped.
#[inline]
pub unsafe fn push(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    // The buffer may be uninitialised (a `MaybeUninit` on the caller's stack), so no reference to it is made: each field
    // is written through the raw pointer (plain Copy values, nothing is dropped); `canceltype` is the caller's.
    // SAFETY: `buf` is valid and writable (caller's promise).
    unsafe { (*buf).routine = routine };
    // SAFETY: as above.
    unsafe { (*buf).arg = arg };
    // SAFETY: as above.
    unsafe { (*buf).prev = HEAD.get() };
    HEAD.set(buf);
}

/// Take `buf` (the innermost buffer) off the list without running it.
///
/// # Safety
/// `buf` was pushed by this thread.
#[inline]
pub unsafe fn pop(buf: *mut CleanupBuf) {
    // SAFETY: `buf` was pushed by this thread and is still live (caller's promise).
    HEAD.set(unsafe { (*buf).prev });
}

/// Take `buf` off the list wherever it is (for registrations that are released in no fixed order).
///
/// # Safety
/// `buf` was pushed by this thread and not popped.
pub unsafe fn remove(buf: *mut CleanupBuf) {
    // SAFETY: `buf` was pushed by this thread and not popped (caller's promise), so it is live.
    let next = unsafe { (*buf).prev };
    if HEAD.get() == buf {
        HEAD.set(next);
        return;
    }
    let mut p = HEAD.get();
    while !p.is_null() {
        // (raw accesses, no reference: the node's owner keeps its own pointer to it)
        // SAFETY: `p` is reachable from HEAD, so live and only touched by this thread (module invariant).
        let prev = unsafe { (*p).prev };
        if prev == buf {
            // SAFETY: as above.
            unsafe { (*p).prev = next };
            return;
        }
        p = prev;
    }
}

/// Run `body` with `routine(arg)` registered (popped, not run, when `body` returns normally).
///
/// # Safety
/// `routine` must be safe to call with `arg` at any cancellation point inside `body`.
#[inline]
pub unsafe fn with<R>(routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void, body: impl FnOnce() -> R) -> R {
    let mut buf = core::mem::MaybeUninit::<CleanupBuf>::uninit();
    // SAFETY: `buf` lives in this frame, which outlives the registration (popped below before it ends); `routine(arg)`
    // may run at a cancellation point in `body` (caller's promise).
    unsafe { push(buf.as_mut_ptr(), routine, arg) };
    let r = body();
    // SAFETY: `buf` is the innermost buffer again: `body` pops whatever it pushes.
    unsafe { pop(buf.as_mut_ptr()) };
    r
}
