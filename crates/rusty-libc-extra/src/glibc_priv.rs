#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_void};
use rusty_libc_core::errno;

const ENOMEM: i32 = 12;
const SPACE: usize = 1024;

fn malloc(n: usize) -> *mut c_void {
    crate::mntent::malloc(n).cast()
}

unsafe fn free(p: *mut c_void) {
    unsafe { rusty_libc_malloc::free(p) }
}

unsafe fn realloc(p: *mut c_void, n: usize) -> *mut c_void {
    unsafe { rusty_libc_malloc::realloc(p, n) }
}

unsafe fn copy(src: *const c_void, dst: *mut c_void, n: usize) {
    unsafe { core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), n) }
}

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

    unsafe fn release(&mut self) {
        if self.data != self.space_ptr() {
            unsafe { free(self.data) };
        }
    }

    pub unsafe fn grow(&mut self) -> bool {
        let old = self.length;
        let new_length = old.wrapping_mul(2);
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

    pub unsafe fn grow_preserve(&mut self) -> bool {
        let old_length = self.length;
        let new_length = old_length.wrapping_mul(2);
        if new_length < old_length {
            errno::set(ENOMEM);
            return false;
        }
        let p;
        if self.data == self.space_ptr() {
            p = malloc(new_length);
            if p.is_null() {
                return false;
            }
            unsafe { copy(self.data, p, old_length) };
        } else {
            p = unsafe { realloc(self.data, new_length) };
            if p.is_null() {
                return false;
            }
        }
        self.data = p;
        self.length = new_length;
        true
    }

    pub unsafe fn set_array_size(&mut self, nelem: usize, size: usize) -> bool {
        let new_length = nelem.wrapping_mul(size);
        if size != 0 && new_length / size != nelem {
        unsafe { self.release() };
            self.init();
            errno::set(ENOMEM);
            return false;
        }
        if new_length <= self.length {
            return true;
        }
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

unsafe fn scratch<'a>(b: *mut ScratchBuffer) -> &'a mut ScratchBuffer {
    unsafe { &mut *b }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow(b: *mut ScratchBuffer) -> bool {
    let b = unsafe { scratch(b) };
    unsafe { b.grow() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow_preserve(b: *mut ScratchBuffer) -> bool {
    let b = unsafe { scratch(b) };
    unsafe { b.grow_preserve() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_set_array_size(b: *mut ScratchBuffer, nelem: usize, size: usize) -> bool {
    let b = unsafe { scratch(b) };
    unsafe { b.set_array_size(nelem, size) }
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

impl DynarrayHeader {
    unsafe fn reallocate(&mut self, scratch: *mut c_void, new_size: usize, used_bytes: usize) -> *mut c_void {
        if self.array == scratch {
            let p = malloc(new_size);
            if !p.is_null() && !self.array.is_null() {
                unsafe { copy(self.array, p, used_bytes) };
            }
            p
        } else {
            unsafe { realloc(self.array, new_size) }
        }
    }

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
        let p = unsafe { self.reallocate(scratch, new_size, self.used * element_size) };
        if p.is_null() {
            return false;
        }
        self.array = p;
        self.allocated = new_allocated;
        true
    }

    pub unsafe fn resize(&mut self, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
        if size <= self.allocated {
            self.used = size;
            return true;
        }
        let Some(new_size_bytes) = size.checked_mul(element_size) else {
            errno::set(ENOMEM);
            return false;
        };
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

unsafe fn header<'a>(list: *mut DynarrayHeader) -> &'a mut DynarrayHeader {
    unsafe { &mut *list }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_emplace_enlarge(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize) -> bool {
    let l = unsafe { header(list) };
    unsafe { l.emplace_enlarge(scratch, element_size) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    let l = unsafe { header(list) };
    unsafe { l.resize(size, scratch, element_size) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize_clear(list: *mut DynarrayHeader, size: usize, scratch: *mut c_void, element_size: usize) -> bool {
    let l = unsafe { header(list) };
    let old_size = l.used;
    if !unsafe { l.resize(size, scratch, element_size) } {
        return false;
    }
    if size > old_size {
        let start = l.array.cast::<u8>().wrapping_add(old_size * element_size);
        unsafe { core::ptr::write_bytes(start, 0, (size - old_size) * element_size) };
    }
    true
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_finalize(list: *mut DynarrayHeader, scratch: *mut c_void, element_size: usize, result: *mut DynarrayFinalizeResult) -> bool {
    let l = unsafe { header(list) };
    if l.allocated == ERROR_MARK {
        return false;
    }
    let used = l.used;
    let out = if used == 0 {
        if l.array != scratch {
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
            unsafe { copy(l.array, p, bytes) };
        }
        if l.array != scratch {
            unsafe { free(l.array) };
        }
        DynarrayFinalizeResult { array: p, length: used }
    };
    unsafe { result.write(out) };
    true
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_allocate_once_slow(
    place: *mut *mut c_void,
    allocate: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    deallocate: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    closure: *mut c_void,
) -> *mut c_void {
    use core::sync::atomic::{AtomicPtr, Ordering};
    let result = unsafe { allocate(closure) };
    if result.is_null() {
        return core::ptr::null_mut();
    }
    let slot = unsafe { AtomicPtr::from_ptr(place) };
    match slot.compare_exchange(core::ptr::null_mut(), result, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => result,
        Err(other) => {
            match deallocate {
                Some(d) => unsafe { d(closure, result) },
                None => unsafe { free(result) },
            }
            other
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_hash(key: *const c_void, len: usize) -> u32 {
    nss_hash(unsafe { rusty_libc_core::ffi::bytes(key.cast::<u8>(), len) })
}

pub fn nss_hash(bytes: &[u8]) -> u32 {
    let mut h = 0u32;
    for &b in bytes {
        h = u32::from(b).wrapping_add(65599u32.wrapping_mul(h));
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
    let p = malloc(size);
    unsafe { pptr.write(p) };
    if p.is_null() {
        return FAILED_BUFFER;
    }
    let current = p as usize;
    match current.checked_add(size) {
        Some(end) => AllocBuffer { current, end },
        None => unsafe { __libc_alloc_buffer_create_failure(p, size) },
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_alloc_array(buf: *mut AllocBuffer, element_size: usize, align: usize, count: usize) -> *mut c_void {
    let buf = unsafe { &mut *buf };
    buf.alloc_array(element_size, align, count) as *mut c_void
}

impl AllocBuffer {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_bytes(mut buf: AllocBuffer, src: *const c_void, len: usize) -> AllocBuffer {
    if len > buf.end.wrapping_sub(buf.current) {
        return FAILED_BUFFER;
    }
    let dst = buf.current as *mut u8;
    buf.current = buf.current.wrapping_add(len);
    if !dst.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, core::ptr::with_exposed_provenance_mut::<u8>(dst as usize), len) };
    }
    buf
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_string(buf: AllocBuffer, src: *const c_char) -> AllocBuffer {
    let len = unsafe { rusty_libc_core::ffi::cstr_len(src) } + 1;
    unsafe { __libc_alloc_buffer_copy_bytes(buf, src.cast(), len) }
}

