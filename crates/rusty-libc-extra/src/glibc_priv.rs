//! glibc's internal helper API that its own programs (getent, gencat, pldd, the NSS modules) import from libc.so.6 under the
//! GLIBC_PRIVATE version: `struct scratch_buffer` growth, the `dynarray` resizing routines and the `struct alloc_buffer` helpers. Written from the documented
//! behaviour of glibc's malloc/scratch_buffer_*.c, malloc/dynarray_*.c and malloc/alloc_buffer_*.c headers (data structure layouts and the errno
//! and failure conventions), not from its text.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_void};
use rusty_libc_core::errno;

const ENOMEM: i32 = 12;
const SPACE: usize = 1024;

fn malloc(n: usize) -> *mut c_void {
    crate::mntent::malloc(n).cast()
}

/// `free(p)` of a block this module's callers got from malloc/realloc.
///
/// # Safety
/// `p` is NULL or a live malloc block, freed once.
unsafe fn free(p: *mut c_void) {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_malloc::free(p) }
}

/// `realloc(p, n)`.
///
/// # Safety
/// `p` is NULL or a live malloc block (it is gone when the result is not NULL).
unsafe fn realloc(p: *mut c_void, n: usize) -> *mut c_void {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_malloc::realloc(p, n) }
}

/// Copy `n` bytes between two distinct blocks.
///
/// # Safety
/// `src` is readable and `dst` writable for `n` bytes; they do not overlap.
unsafe fn copy(src: *const c_void, dst: *mut c_void, n: usize) {
    // SAFETY: forwarded contract.
    unsafe { core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), n) }
}

/// `struct scratch_buffer`: `data` points at `space` or at a heap block of `length` bytes.
#[repr(C)]
pub struct ScratchBuffer {
    pub data: *mut c_void,
    pub length: usize,
    pub space: [u128; SPACE / 16],
}

impl ScratchBuffer {
    fn space_ptr(&mut self) -> *mut c_void {
        (&raw mut self.space).cast()
    }

    fn init(&mut self) {
        self.data = self.space_ptr();
        self.length = SPACE;
    }

    /// Free the heap block, if any (the buffer is invalid until `init` or a new `data`).
    ///
    /// # Safety
    /// `self` is an initialised scratch buffer: `data` is its inline space or a heap block of `length` bytes it owns.
    unsafe fn release(&mut self) {
        if self.data != self.space_ptr() {
            // SAFETY: a scratch buffer whose data is not its inline space owns a heap block (the contract).
            unsafe { free(self.data) };
        }
    }

    /// The core of `__libc_scratch_buffer_grow`.
    ///
    /// # Safety
    /// `self` is an initialised scratch buffer: `data` is its inline space or a heap block of `length` bytes it owns.
    pub unsafe fn grow(&mut self) -> bool {
        let old = self.length;
        let new_length = old.wrapping_mul(2);
        // SAFETY: the contract of this method.
        unsafe { self.release() };
        let p = if new_length >= old {
            malloc(new_length)
        } else {
            errno::set(ENOMEM);
            core::ptr::null_mut()
        };
        if p.is_null() {
            self.init();
            return false;
        }
        self.data = p;
        self.length = new_length;
        true
    }

    /// The core of `__libc_scratch_buffer_grow_preserve`.
    ///
    /// # Safety
    /// `self` is an initialised scratch buffer: `data` is its inline space or a heap block of `length` bytes it owns.
    pub unsafe fn grow_preserve(&mut self) -> bool {
        let old_length = self.length;
        let new_length = old_length.wrapping_mul(2);
        if new_length < old_length {
            errno::set(ENOMEM);
            return false;
        }
        let p;
        if self.data == self.space_ptr() {
            // the contents live in the inline space: a fresh block gets a copy
            p = malloc(new_length);
            if p.is_null() {
                return false;
            }
            // SAFETY: the inline space holds `length` bytes (the contract); `p` is a fresh block of twice that.
            unsafe { copy(self.data, p, old_length) };
        } else {
            // SAFETY: `data` is the buffer's own heap block.
            p = unsafe { realloc(self.data, new_length) };
            if p.is_null() {
                // the old block stays valid
                return false;
            }
        }
        self.data = p;
        self.length = new_length;
        true
    }

    /// The core of `__libc_scratch_buffer_set_array_size`.
    ///
    /// # Safety
    /// `self` is an initialised scratch buffer: `data` is its inline space or a heap block of `length` bytes it owns.
    pub unsafe fn set_array_size(&mut self, nelem: usize, size: usize) -> bool {
        let new_length = nelem.wrapping_mul(size);
        if size != 0 && new_length / size != nelem {
            // as glibc: the old buffer is dropped, and the buffer stays valid to free
            // SAFETY: the contract of this method.
        unsafe { self.release() };
            self.init();
            errno::set(ENOMEM);
            return false;
        }
        if new_length <= self.length {
            return true;
        }
        // SAFETY: the contract of this method.
        unsafe { self.release() };
        let p = malloc(new_length);
        if p.is_null() {
            self.init();
            return false;
        }
        self.data = p;
        self.length = new_length;
        true
    }
}

/// The caller's scratch buffer.
///
/// # Safety
/// `b` points to an initialised scratch buffer, not accessed elsewhere during the call.
unsafe fn scratch<'a>(b: *mut ScratchBuffer) -> &'a mut ScratchBuffer {
    // SAFETY: forwarded contract.
    unsafe { &mut *b }
}

/// `__libc_scratch_buffer_grow`: double the buffer (the old contents are dropped). False with errno ENOMEM on failure; the
/// buffer is then back to its inline space and still valid to free.
///
/// # Safety
/// `b` is an initialised scratch buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow(b: *mut ScratchBuffer) -> bool {
    // SAFETY: caller's contract.
    let b = unsafe { scratch(b) };
    // SAFETY: `b` is initialised (caller's contract).
    unsafe { b.grow() }
}

/// `__libc_scratch_buffer_grow_preserve`: like the above, keeping the contents.
///
/// # Safety
/// As above.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow_preserve(b: *mut ScratchBuffer) -> bool {
    // SAFETY: caller's contract.
    let b = unsafe { scratch(b) };
    // SAFETY: `b` is initialised (caller's contract).
    unsafe { b.grow_preserve() }
}

/// `__libc_scratch_buffer_set_array_size`: room for `nelem` elements of `size` bytes (contents dropped when it has to grow).
///
/// # Safety
/// As above.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_set_array_size(b: *mut ScratchBuffer, nelem: usize, size: usize) -> bool {
    // SAFETY: caller's contract.
    let b = unsafe { scratch(b) };
    // SAFETY: `b` is initialised (caller's contract).
    unsafe { b.set_array_size(nelem, size) }
}

// ------------------------------------------------------------------------------------------------ dynarray

/// `struct dynarray_header`: `allocated == usize::MAX` marks the error state.
#[repr(C)]
pub struct DynarrayHeader {
    pub used: usize,
    pub allocated: usize,
    pub array: *mut c_void,
}

const ERROR_MARK: usize = usize::MAX;

#[repr(C)]
pub struct DynarrayFinalizeResult {
    pub array: *mut c_void,
    pub length: usize,
}

/// `__libc_dynarray_at_failure`: an index past the end was used; ends the process with glibc's message.
///
/// # Safety
/// Never returns.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_at_failure(size: usize, index: usize) -> ! {
    // "Fatal glibc error: array index %zu not less than array length %zu"
    let mut buf = [0u8; 160];
    let mut n = 0usize;
    let mut put = |s: &[u8]| {
        for &c in s {
            if n < buf.len() {
                buf[n] = c;
                n += 1;
            }
        }
    };
    let num = |mut v: usize, out: &mut [u8; 20]| -> usize {
        let mut k = 20;
        loop {
            k -= 1;
            out[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        k
    };
    let mut d = [0u8; 20];
    put(b"Fatal glibc error: array index ");
    let k = num(index, &mut d);
    put(&d[k..]);
    put(b" not less than array length ");
    let k = num(size, &mut d);
    put(&d[k..]);
    put(b"\n");
    rusty_libc_core::unistd::write(2, &buf[..n]).ok();
    rusty_libc_core::process::abort()
}

impl DynarrayHeader {
    /// A block of `new_size` bytes holding the first `used_bytes` of the array: a fresh copy while the array is the
    /// caller's scratch space (or NULL), a realloc of the heap array otherwise. NULL when the allocation fails (the old
    /// array is then untouched).
    ///
    /// # Safety
    /// `self` is a valid list: `array` is `scratch`, NULL, or a heap block, and holds at least `used_bytes` bytes.
    unsafe fn reallocate(&mut self, scratch: *mut c_void, new_size: usize, used_bytes: usize) -> *mut c_void {
        if self.array == scratch {
            let p = malloc(new_size);
            if !p.is_null() && !self.array.is_null() {
                // SAFETY: the array holds `used_bytes` bytes (contract); `p` is a fresh block of `new_size` >= them.
                unsafe { copy(self.array, p, used_bytes) };
            }
            p
        } else {
            // SAFETY: the array is the list's own heap block (or NULL) (contract).
            unsafe { realloc(self.array, new_size) }
        }
    }

    /// The core of `__libc_dynarray_emplace_enlarge`.
    ///
    /// # Safety
    /// As `reallocate`, with `used * element_size` bytes in the array.
    pub unsafe fn emplace_enlarge(&mut self, scratch: *mut c_void, element_size: usize) -> bool {
        let new_allocated;
        if self.allocated == 0 {
            new_allocated = if element_size < 4 {
                16
            } else if element_size < 8 {
                8
            } else {
                4
            };
        } else {
            new_allocated = self.allocated + self.allocated / 2 + 1;
            if new_allocated <= self.allocated {
                errno::set(ENOMEM);
                return false;
            }
        }
        let Some(new_size) = new_allocated.checked_mul(element_size) else {
            errno::set(ENOMEM);
            return false;
        };
        // SAFETY: the contract of this method.
        let p = unsafe { self.reallocate(scratch, new_size, self.used * element_size) };
        if p.is_null() {
            return false;
        }
        self.array = p;
        self.allocated = new_allocated;
        true
    }

    /// The core of `__libc_dynarray_resize`.
    ///
    /// # Safety
    /// As `emplace_enlarge`.
    pub unsafe fn resize(&mut self, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
        if size <= self.allocated {
            self.used = size;
            return true;
        }
        let Some(new_size_bytes) = size.checked_mul(element_size) else {
            errno::set(ENOMEM);
            return false;
        };
        // SAFETY: the contract of this method.
        let p = unsafe { self.reallocate(scratch, new_size_bytes, self.used * element_size) };
        if p.is_null() {
            return false;
        }
        self.array = p;
        self.allocated = size;
        self.used = size;
        true
    }
}

/// The caller's list header.
///
/// # Safety
/// `list` points to a valid `struct dynarray_header`, not accessed elsewhere during the call.
unsafe fn header<'a>(list: *mut DynarrayHeader) -> &'a mut DynarrayHeader {
    // SAFETY: forwarded contract.
    unsafe { &mut *list }
}

/// `__libc_dynarray_emplace_enlarge`: make room for at least one more element (exponential growth).
///
/// # Safety
/// `list` and `scratch` as the dynarray macros pass them.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_emplace_enlarge(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize) -> bool {
    // SAFETY: caller's contract.
    let l = unsafe { header(list) };
    // SAFETY: the dynarray macros keep the header valid (array is scratch, NULL or the list's heap block of `used` elements).
    unsafe { l.emplace_enlarge(scratch, element_size) }
}

/// `__libc_dynarray_resize`: set the used size, allocating exactly `size` elements when it does not fit.
///
/// # Safety
/// As above.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    // SAFETY: caller's contract.
    let l = unsafe { header(list) };
    // SAFETY: as in `__libc_dynarray_emplace_enlarge`.
    unsafe { l.resize(size, scratch, element_size) }
}

/// `__libc_dynarray_resize_clear`: `__libc_dynarray_resize`, zeroing the elements that were added.
///
/// # Safety
/// As above.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize_clear(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    // SAFETY: caller's contract.
    let l = unsafe { header(list) };
    let old_size = l.used;
    // SAFETY: as in `__libc_dynarray_emplace_enlarge`.
    if !unsafe { l.resize(size, scratch, element_size) } {
        return false;
    }
    if size > old_size {
        let start = l.array.cast::<u8>().wrapping_add(old_size * element_size);
        // SAFETY: after a successful resize the array holds `size` elements; the added ones start at `old_size`.
        unsafe { core::ptr::write_bytes(start, 0, (size - old_size) * element_size) };
    }
    true
}

/// `__libc_dynarray_finalize`: move the elements into an exactly sized heap block (`result.array`, `result.length`); an empty
/// list gives NULL and 0. False (nothing moved) when the list is in the error state or the allocation fails.
///
/// # Safety
/// As above; `result` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_finalize(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize, result: *mut DynarrayFinalizeResult) -> bool {
    // SAFETY: caller's contract.
    let l = unsafe { header(list) };
    if l.allocated == ERROR_MARK {
        return false;
    }
    let used = l.used;
    let out = if used == 0 {
        if l.array != scratch {
            // SAFETY: an array that is not the scratch space is the list's heap block (or NULL); the list is finished.
            unsafe { free(l.array) };
        }
        DynarrayFinalizeResult { array: core::ptr::null_mut(), length: 0 }
    } else {
        let bytes = used * element_size;
        let p = malloc(bytes);
        if p.is_null() {
            return false;
        }
        if !l.array.is_null() {
            // SAFETY: the array holds `used` elements; `p` is a fresh block of that size.
            unsafe { copy(l.array, p, bytes) };
        }
        if l.array != scratch {
            // SAFETY: as above.
            unsafe { free(l.array) };
        }
        DynarrayFinalizeResult { array: p, length: used }
    };
    // SAFETY: `result` is writable (caller's contract).
    unsafe { result.write(out) };
    true
}

/// `__libc_allocate_once_slow(place, allocate, deallocate, closure)`: the slow path of glibc's `allocate_once`. Calls
/// `allocate(closure)`; NULL is returned as is. The result is published into `*place` with a compare-and-swap from NULL; a
/// thread that loses the race releases its own block (`deallocate(closure, ptr)`, or `free` when that is NULL) and returns the
/// winner's. Written from the documented behaviour of glibc's `include/allocate_once.h`.
///
/// # Safety
/// `place` is a valid pointer slot; the callbacks follow the allocate_once contract.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_allocate_once_slow(
    place: *mut *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    deallocate: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    closure: *mut c_void,
) -> *mut c_void {
    use core::sync::atomic::{AtomicPtr, Ordering};
    // SAFETY: the caller's allocate callback with its own closure (allocate_once contract).
    let result = unsafe { allocate(closure) };
    if result.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `place` is a valid, aligned pointer slot that other threads access only atomically (allocate_once's protocol).
    let slot = unsafe { AtomicPtr::from_ptr(place) };
    match slot.compare_exchange(core::ptr::null_mut(), result, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => result,
        Err(other) => {
            match deallocate {
                // SAFETY: the caller's deallocate callback on the block its allocate returned.
                Some(d) => unsafe { d(closure, result) },
                // SAFETY: without a deallocate callback the block is a malloc block (allocate_once's contract).
                None => unsafe { free(result) },
            }
            other
        }
    }
}

/// `__nss_hash(key, len)`: the hash the name service switch's caches use, the sdbm hash (`h = byte + 65599 * h` over the bytes,
/// 32-bit wrap-around; glibc's version unrolls the loop for speed and gives the same values).
///
/// # Safety
/// `key` points at `len` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_hash(key: *const c_void, len: usize) -> u32 {
    // SAFETY: `key` has `len` readable bytes (caller's contract); a length of 0 accepts any pointer.
    nss_hash(unsafe { rusty_libc_core::ffi::bytes(key.cast::<u8>(), len) })
}

/// The safe core of `__nss_hash`.
pub fn nss_hash(bytes: &[u8]) -> u32 {
    let mut h = 0u32;
    for &b in bytes {
        h = u32::from(b).wrapping_add(65599u32.wrapping_mul(h));
    }
    h
}

/// `_libc_intl_domainname`: the text domain of libc's own messages ("libc"), read by glibc's utilities (getconf, getent,
/// iconv, locale, localedef, gencat, pldd, ldconfig) through `bindtextdomain`/`textdomain` calls.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static _libc_intl_domainname: [u8; 5] = *b"libc\0";

// ------------------------------------------------------------------------------------------------ alloc_buffer

/// `struct alloc_buffer`: the write position and the end of a byte region (two `uintptr_t`s, passed and returned in registers
/// like glibc's). `current == 0` marks the buffer as failed (the failed buffer is `{0, 0}`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AllocBuffer {
    pub current: usize,
    pub end: usize,
}

const FAILED_BUFFER: AllocBuffer = AllocBuffer { current: 0, end: 0 };

/// `__libc_alloc_buffer_create_failure`: a region whose end wraps around the address space: print the diagnostic and abort.
///
/// # Safety
/// Never returns.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_create_failure(_start: *mut c_void, size: usize) -> ! {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut n = size;
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let _ = rusty_libc_core::unistd::write(2, b"Fatal glibc error: invalid allocation buffer of size ");
    let _ = rusty_libc_core::unistd::write(2, &digits[i..]);
    let _ = rusty_libc_core::unistd::write(2, b"\n");
    rusty_libc_core::process::abort()
}

/// `__libc_alloc_buffer_allocate`: a buffer over a fresh `malloc` block of `size` bytes; `*pptr` gets the block (NULL, and a failed
/// buffer, when `malloc` fails).
///
/// # Safety
/// `pptr` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_allocate(size: usize, pptr: *mut *mut c_void) -> AllocBuffer {
    let p = malloc(size);
    // SAFETY: `pptr` is writable (caller's contract).
    unsafe { pptr.write(p) };
    if p.is_null() {
        return FAILED_BUFFER;
    }
    let current = p as usize;
    match current.checked_add(size) {
        Some(end) => AllocBuffer { current, end },
        // SAFETY: never returns; no precondition beyond that.
        None => unsafe { __libc_alloc_buffer_create_failure(p, size) },
    }
}

/// `__libc_alloc_buffer_alloc_array`: take `count` objects of `element_size` bytes, aligned to `align` (a power of two), from the
/// buffer. NULL, and the buffer marked failed, when they do not fit (or the sizes overflow).
///
/// # Safety
/// `buf` is valid for reading and writing.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_alloc_array(buf: *mut AllocBuffer, element_size: usize, align: usize, count: usize) -> *mut c_void {
    // SAFETY: `buf` is valid for reading and writing (caller's contract).
    let buf = unsafe { &mut *buf };
    buf.alloc_array(element_size, align, count) as *mut c_void
}

impl AllocBuffer {
    /// The safe core of `__libc_alloc_buffer_alloc_array`: the address of the objects (0, and the buffer failed, when they
    /// do not fit). Only addresses are computed; nothing is read or written.
    pub fn alloc_array(&mut self, element_size: usize, align: usize, count: usize) -> usize {
        let current = self.current;
        let aligned = current.wrapping_add(align.wrapping_sub(1)) & align.wrapping_neg();
        if let Some(size) = element_size.checked_mul(count) {
            let new_current = aligned.wrapping_add(size);
            if aligned >= current && new_current >= size && new_current <= self.end {
                self.current = new_current;
                return aligned;
            }
        }
        *self = FAILED_BUFFER;
        0
    }
}

/// `__libc_alloc_buffer_copy_bytes`: copy `len` bytes from `src` to the buffer's write position and return the advanced buffer
/// (the failed buffer when they do not fit; a failed buffer stays failed).
///
/// # Safety
/// `src` is readable for `len` bytes; the buffer's remaining region is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_bytes(mut buf: AllocBuffer, src: *const c_void, len: usize) -> AllocBuffer {
    if len > buf.end.wrapping_sub(buf.current) {
        return FAILED_BUFFER;
    }
    let dst = buf.current as *mut u8;
    buf.current = buf.current.wrapping_add(len);
    if !dst.is_null() {
        // SAFETY: `src` has `len` readable bytes and the buffer's remaining region (at least `len` bytes, checked above)
        // is writable (caller's contract). The integer address is turned back into the caller's pointer (glibc's layout
        // keeps `uintptr_t`s), with exposed provenance.
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, core::ptr::with_exposed_provenance_mut::<u8>(dst as usize), len) };
    }
    buf
}

/// `__libc_alloc_buffer_copy_string`: like `copy_bytes` for the string at `src`, with its terminating NUL.
///
/// # Safety
/// `src` is a C string; the buffer's remaining region is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_string(buf: AllocBuffer, src: *const c_char) -> AllocBuffer {
    // SAFETY: `src` is a C string (caller's contract).
    let len = unsafe { rusty_libc_core::ffi::cstr_len(src) } + 1;
    // SAFETY: the string and its NUL are `len` readable bytes; the buffer region is the caller's.
    unsafe { __libc_alloc_buffer_copy_bytes(buf, src.cast(), len) }
}

#[cfg(test)]
mod alloc_buffer_tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn layout_is_two_words() {
        assert_eq!(core::mem::size_of::<AllocBuffer>(), 16);
        assert_eq!(core::mem::align_of::<AllocBuffer>(), 8);
    }

    #[test]
    fn allocate_array_copy_and_failure() {
        unsafe {
            let mut heap: *mut c_void = core::ptr::null_mut();
            let mut buf = __libc_alloc_buffer_allocate(64, &mut heap);
            assert!(!heap.is_null());
            assert_eq!(buf.current, heap as usize);
            assert_eq!(buf.end - buf.current, 64);

            // a string, then a 4-byte aligned array behind it
            buf = __libc_alloc_buffer_copy_string(buf, c"abc".as_ptr());
            assert_eq!(buf.current, heap as usize + 4);
            assert_eq!(core::slice::from_raw_parts(heap as *const u8, 4), b"abc\0");
            let arr = __libc_alloc_buffer_alloc_array(&mut buf, 4, 4, 5) as usize;
            assert_eq!(arr, heap as usize + 4);
            assert_eq!(buf.current, heap as usize + 24);
            // an 8-aligned object after 24 bytes needs no padding, after 25 it does
            buf = __libc_alloc_buffer_copy_bytes(buf, b"x".as_ptr().cast(), 1);
            assert_eq!(__libc_alloc_buffer_alloc_array(&mut buf, 8, 8, 1) as usize, heap as usize + 32);

            // too big: NULL and the buffer is failed ({0,0}); it stays failed and later copies do not write
            assert!(__libc_alloc_buffer_alloc_array(&mut buf, 8, 8, 100).is_null());
            assert_eq!((buf.current, buf.end), (0, 0));
            let again = __libc_alloc_buffer_copy_bytes(buf, b"zz".as_ptr().cast(), 2);
            assert_eq!((again.current, again.end), (0, 0));
            assert!(__libc_alloc_buffer_alloc_array(&mut buf, 1, 1, 0).is_null());
            assert_eq!((buf.current, buf.end), (0, 0));
            free(heap);
        }
    }

    #[test]
    fn copy_that_does_not_fit_fails_without_writing() {
        unsafe {
            let mut space = [0xAAu8; 4];
            let p = space.as_mut_ptr() as usize;
            let buf = AllocBuffer { current: p, end: p + 4 };
            let r = __libc_alloc_buffer_copy_bytes(buf, b"12345".as_ptr().cast(), 5);
            assert_eq!((r.current, r.end), (0, 0));
            assert_eq!(space, [0xAA; 4]);
            let r = __libc_alloc_buffer_copy_string(buf, c"abcd".as_ptr());
            assert_eq!((r.current, r.end), (0, 0));
            assert_eq!(space, [0xAA; 4]);
            let r = __libc_alloc_buffer_copy_string(buf, c"abc".as_ptr());
            assert_eq!((r.current, r.end), (p + 4, p + 4));
            assert_eq!(&space, b"abc\0");
        }
    }

    #[test]
    fn array_size_overflow_fails() {
        unsafe {
            let mut space = [0u8; 16];
            let p = space.as_mut_ptr() as usize;
            let mut buf = AllocBuffer { current: p, end: p + 16 };
            assert!(__libc_alloc_buffer_alloc_array(&mut buf, usize::MAX / 2 + 1, 1, 2).is_null());
            assert_eq!((buf.current, buf.end), (0, 0));
            let mut buf = AllocBuffer { current: usize::MAX - 3, end: usize::MAX };
            assert!(__libc_alloc_buffer_alloc_array(&mut buf, 8, 8, 1).is_null());
            assert_eq!((buf.current, buf.end), (0, 0));
        }
    }
}
