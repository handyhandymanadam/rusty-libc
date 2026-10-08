use core::ffi::{c_char, c_void};
use rusty_libc_core::errno;
use rusty_libc_malloc::{free, malloc, realloc};

const ENOMEM: i32 = 12;
const SPACE: usize = 1024;

#[repr(C)]
pub struct ScratchBuffer {
    pub data: *mut c_void,
    pub length: usize,
    pub space: [u128; SPACE / 16],
}

unsafe fn scratch_init(b: *mut ScratchBuffer) {
    unsafe {
        (*b).data = (&raw mut (*b).space).cast();
        (*b).length = SPACE;
    }
}

unsafe fn scratch_free(b: *mut ScratchBuffer) {
    unsafe {
        if (*b).data != (&raw mut (*b).space).cast() {
            free((*b).data);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow(b: *mut ScratchBuffer) -> bool {
    unsafe {
        let old = (*b).length;
        let new_length = old.wrapping_mul(2);
        scratch_free(b);
        let p = if new_length >= old {
            malloc(new_length)
        } else {
            errno::set(ENOMEM);
            core::ptr::null_mut()
        };
        if p.is_null() {
            scratch_init(b);
            return false;
        }
        (*b).data = p;
        (*b).length = new_length;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow_preserve(b: *mut ScratchBuffer) -> bool {
    unsafe {
        let old_length = (*b).length;
        let new_length = old_length.wrapping_mul(2);
        if new_length < old_length {
            errno::set(ENOMEM);
            return false;
        }
        let space: *mut c_void = (&raw mut (*b).space).cast();
        let p;
        if (*b).data == space {
            p = malloc(new_length);
            if p.is_null() {
                return false;
            }
            core::ptr::copy_nonoverlapping((*b).data as *const u8, p as *mut u8, old_length);
        } else {
            p = realloc((*b).data, new_length);
            if p.is_null() {
                return false;
            }
        }
        (*b).data = p;
        (*b).length = new_length;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_set_array_size(b: *mut ScratchBuffer, nelem: usize, size: usize) -> bool {
    unsafe {
        let new_length = nelem.wrapping_mul(size);
        if size != 0 && new_length / size != nelem {
            errno::set(ENOMEM);
            return false;
        }
        if new_length <= (*b).length {
            return true;
        }
        scratch_free(b);
        let p = malloc(new_length);
        if p.is_null() {
            scratch_init(b);
            return false;
        }
        (*b).data = p;
        (*b).length = new_length;
        true
    }
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_at_failure(size: usize, index: usize) -> ! {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_emplace_enlarge(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize) -> bool {
    unsafe {
        let new_allocated;
        if (*list).allocated == 0 {
            new_allocated = if element_size < 4 {
                16
            } else if element_size < 8 {
                8
            } else {
                4
            };
        } else {
            new_allocated = (*list).allocated + (*list).allocated / 2 + 1;
            if new_allocated <= (*list).allocated {
                errno::set(ENOMEM);
                return false;
            }
        }
        let Some(new_size) = new_allocated.checked_mul(element_size) else {
            errno::set(ENOMEM);
            return false;
        };
        let p = if (*list).array == scratch {
            let p = malloc(new_size);
            if !p.is_null() && !(*list).array.is_null() {
                core::ptr::copy_nonoverlapping((*list).array as *const u8, p as *mut u8, (*list).used * element_size);
            }
            p
        } else {
            realloc((*list).array, new_size)
        };
        if p.is_null() {
            return false;
        }
        (*list).array = p;
        (*list).allocated = new_allocated;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    unsafe {
        if size <= (*list).allocated {
            (*list).used = size;
            return true;
        }
        let Some(new_size_bytes) = size.checked_mul(element_size) else {
            errno::set(ENOMEM);
            return false;
        };
        let used_bytes = (*list).used * element_size;
        let p = if (*list).array == scratch {
            let p = malloc(new_size_bytes);
            if !p.is_null() && !(*list).array.is_null() {
                core::ptr::copy_nonoverlapping((*list).array as *const u8, p as *mut u8, used_bytes);
            }
            p
        } else {
            realloc((*list).array, new_size_bytes)
        };
        if p.is_null() {
            return false;
        }
        (*list).array = p;
        (*list).allocated = size;
        (*list).used = size;
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize_clear(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    unsafe {
        let old_size = (*list).used;
        if !__libc_dynarray_resize(list, size, scratch, element_size) {
            return false;
        }
        if size > old_size {
            core::ptr::write_bytes(((*list).array as *mut u8).add(old_size * element_size), 0, (size - old_size) * element_size);
        }
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_finalize(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize, result: *mut DynarrayFinalizeResult) -> bool {
    unsafe {
        if (*list).allocated == ERROR_MARK {
            return false;
        }
        let used = (*list).used;
        if used == 0 {
            if (*list).array != scratch {
                free((*list).array);
            }
            *result = DynarrayFinalizeResult { array: core::ptr::null_mut(), length: 0 };
            return true;
        }
        let bytes = used * element_size;
        let p = malloc(bytes);
        if p.is_null() {
            return false;
        }
        if !(*list).array.is_null() {
            core::ptr::copy_nonoverlapping((*list).array as *const u8, p as *mut u8, bytes);
        }
        if (*list).array != scratch {
            free((*list).array);
        }
        *result = DynarrayFinalizeResult { array: p, length: used };
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_allocate_once_slow(
    place: *mut *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    deallocate: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    closure: *mut c_void,
) -> *mut c_void {
    use core::sync::atomic::{AtomicPtr, Ordering};
    unsafe {
        let result = allocate(closure);
        if result.is_null() {
            return core::ptr::null_mut();
        }
        let slot = &*(place as *const AtomicPtr<c_void>);
        match slot.compare_exchange(core::ptr::null_mut(), result, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => result,
            Err(other) => {
                match deallocate {
                    Some(d) => d(closure, result),
                    None => free(result),
                }
                other
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_hash(key: *const c_void, len: usize) -> u32 {
    let mut h = 0u32;
    if len > 0 {
        let bytes = unsafe { core::slice::from_raw_parts(key.cast::<u8>(), len) };
        for &b in bytes {
            h = u32::from(b).wrapping_add(65599u32.wrapping_mul(h));
        }
    }
    h
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static _libc_intl_domainname: [u8; 5] = *b"libc\0";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AllocBuffer {
    pub current: usize,
    pub end: usize,
}

const FAILED_BUFFER: AllocBuffer = AllocBuffer { current: 0, end: 0 };

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_allocate(size: usize, pptr: *mut *mut c_void) -> AllocBuffer {
    unsafe {
        let p = malloc(size);
        *pptr = p;
        if p.is_null() {
            return FAILED_BUFFER;
        }
        let current = p as usize;
        match current.checked_add(size) {
            Some(end) => AllocBuffer { current, end },
            None => __libc_alloc_buffer_create_failure(p, size),
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_alloc_array(buf: *mut AllocBuffer, element_size: usize, align: usize, count: usize) -> *mut c_void {
    unsafe {
        let current = (*buf).current;
        let aligned = current.wrapping_add(align.wrapping_sub(1)) & align.wrapping_neg();
        if let Some(size) = element_size.checked_mul(count) {
            let new_current = aligned.wrapping_add(size);
            if aligned >= current && new_current >= size && new_current <= (*buf).end {
                (*buf).current = new_current;
                return aligned as *mut c_void;
            }
        }
        *buf = FAILED_BUFFER;
        core::ptr::null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_bytes(mut buf: AllocBuffer, src: *const c_void, len: usize) -> AllocBuffer {
    unsafe {
        if len > buf.end.wrapping_sub(buf.current) {
            return FAILED_BUFFER;
        }
        let dst = buf.current as *mut u8;
        buf.current = buf.current.wrapping_add(len);
        if !dst.is_null() {
            core::ptr::copy_nonoverlapping(src as *const u8, dst, len);
        }
        buf
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_string(buf: AllocBuffer, src: *const c_char) -> AllocBuffer {
    unsafe {
        let len = core::ffi::CStr::from_ptr(src).to_bytes_with_nul().len();
        __libc_alloc_buffer_copy_bytes(buf, src.cast(), len)
    }
}

