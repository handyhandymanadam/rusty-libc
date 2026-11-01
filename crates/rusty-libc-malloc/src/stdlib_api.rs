//! stdlib.h: the standard allocation functions.
use crate::heap;
use core::ffi::{c_int, c_void};
use rusty_libc_core::errno;

const EINVAL: i32 = 22;

/// # Safety
/// The returned block must be released with `free` or `realloc` only.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    heap::malloc(size).cast()
}

/// # Safety
/// `ptr` must be NULL or a live block from this allocator.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    // SAFETY: `ptr` is NULL or a live block (contract).
    unsafe { heap::free(ptr.cast()) }
}

/// `cfree (ptr)`: the old SunOS name of `free`.
///
/// # Safety
/// As `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn cfree(ptr: *mut c_void) {
    // SAFETY: as `free`.
    unsafe { free(ptr) }
}

/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    heap::calloc(nmemb, size).cast()
}

/// # Safety
/// `ptr` must be NULL or a live block from this allocator.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: `ptr` is NULL or a live block (contract).
    unsafe { heap::realloc(ptr.cast(), size).cast() }
}

/// # Safety
/// As `realloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    match nmemb.checked_mul(size) {
        // through the public `realloc`, like glibc: a program that replaces malloc/free/realloc must see this allocation
        // SAFETY: as `realloc`.
        Some(total) => unsafe { realloc(ptr, total) },
        None => {
            errno::set(12);
            core::ptr::null_mut()
        }
    }
}

/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    if !alignment.is_power_of_two() {
        errno::set(EINVAL);
        return core::ptr::null_mut();
    }
    heap::memalign(alignment, size).cast()
}

/// Returns an error number instead of setting `errno`.
///
/// # Safety
/// `memptr` must be valid for writing a pointer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int {
    if !alignment.is_power_of_two() || !alignment.is_multiple_of(core::mem::size_of::<*mut c_void>()) {
        return EINVAL;
    }
    let saved = errno::get();
    let p = heap::memalign(alignment, size);
    if p.is_null() {
        // glibc's allocation failure path leaves errno at ENOMEM here too (tst-malloc-thread-fail reads it)
        errno::set(12);
        return 12;
    }
    errno::set(saved);
    // SAFETY: `memptr` is writable (contract; glibc writes it the same way, without a NULL check).
    unsafe { *memptr = p.cast() };
    0
}

// ---- the allocator under its glibc-internal names ----
// `__libc_malloc` and its kin are glibc's own allocator, as opposed to `malloc`, which a program or a preloaded library may
// replace. Allocator shims written for glibc (Chromium's and Edge's PartitionAlloc, jemalloc and tcmalloc builds) define
// `malloc` themselves and forward to `__libc_malloc` as their fallback: these must reach the heap directly, never through the
// (interposable) public name, or the shim would call itself. Old programs import them too.

/// glibc's own `malloc`, whatever `malloc` is bound to.
///
/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_malloc(size: usize) -> *mut c_void {
    heap::malloc(size).cast()
}

/// glibc's own `free`.
///
/// # Safety
/// As `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_free(ptr: *mut c_void) {
    // SAFETY: `ptr` is NULL or a live block (contract).
    unsafe { heap::free(ptr.cast()) }
}

/// glibc's own `calloc`.
///
/// # Safety
/// As `calloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_calloc(nmemb: usize, size: usize) -> *mut c_void {
    heap::calloc(nmemb, size).cast()
}

/// glibc's own `realloc`.
///
/// # Safety
/// As `realloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: `ptr` is NULL or a live block (contract).
    unsafe { heap::realloc(ptr.cast(), size).cast() }
}
