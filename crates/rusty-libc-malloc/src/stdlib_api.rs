use crate::heap;
use core::ffi::{c_int, c_void};
use rusty_libc_core::errno;

const EINVAL: i32 = 22;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    unsafe { heap::malloc(size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    unsafe { heap::free(ptr.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn cfree(ptr: *mut c_void) {
    unsafe { free(ptr) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { heap::calloc(nmemb, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { heap::realloc(ptr.cast(), size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    match nmemb.checked_mul(size) {
        Some(total) => unsafe { realloc(ptr, total) },
        None => {
            errno::set(12);
            core::ptr::null_mut()
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    if !alignment.is_power_of_two() {
        errno::set(EINVAL);
        return core::ptr::null_mut();
    }
    unsafe { heap::memalign(alignment, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int {
    if !alignment.is_power_of_two() || !alignment.is_multiple_of(core::mem::size_of::<*mut c_void>()) {
        return EINVAL;
    }
    let saved = errno::get();
    let p = unsafe { heap::memalign(alignment, size) };
    if p.is_null() {
        errno::set(12);
        return 12;
    }
    errno::set(saved);
    unsafe { *memptr = p.cast() };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_malloc(size: usize) -> *mut c_void {
    unsafe { heap::malloc(size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_free(ptr: *mut c_void) {
    unsafe { heap::free(ptr.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_calloc(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { heap::calloc(nmemb, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { heap::realloc(ptr.cast(), size).cast() }
}
