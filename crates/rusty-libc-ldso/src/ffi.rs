#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;

#[inline]
pub unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    loop {
        let c = unsafe { *p.wrapping_add(n) };
        if c == 0 {
            return n;
        }
        n += 1;
    }
}

#[inline]
pub unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
    let n = unsafe { cstr_len(p) };
    unsafe { core::slice::from_raw_parts(p, n) }
}

#[inline]
pub unsafe fn cstr_opt<'a>(p: *const u8) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { cstr(p) })
}

#[inline]
pub unsafe fn cstr_nul<'a>(p: *const u8) -> &'a CStr {
    let n = unsafe { cstr_len(p) };
    let with_nul = unsafe { core::slice::from_raw_parts(p, n + 1) };
    unsafe { CStr::from_bytes_with_nul_unchecked(with_nul) }
}

#[inline]
pub unsafe fn cstr_eq(p: *const u8, name: &[u8]) -> bool {
    let mut i = 0;
    while i < name.len() {
        let c = unsafe { *p.wrapping_add(i) };
        if c != name[i] {
            return false;
        }
        i += 1;
    }
    unsafe { *p.wrapping_add(i) == 0 }
}

#[inline]
pub unsafe fn streq(a: *const u8, b: *const u8) -> bool {
    let mut i = 0;
    loop {
        let x = unsafe { *a.wrapping_add(i) };
        let y = unsafe { *b.wrapping_add(i) };
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
        i += 1;
    }
}

#[inline]
pub unsafe fn cstr_gnu_hash<'a>(s: *const u8) -> (&'a [u8], u32) {
    let mut h: u32 = 5381;
    let mut n = 0;
    loop {
        let c = unsafe { *s.wrapping_add(n) };
        if c == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(c as u32);
        n += 1;
    }
    (unsafe { core::slice::from_raw_parts(s, n) }, h)
}

#[inline]
pub unsafe fn slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(p, len) }
}

#[inline]
pub unsafe fn slice_mut<'a, T>(p: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        return &mut [];
    }
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

#[inline]
pub unsafe fn out<'a, T>(p: *mut T) -> Option<&'a mut T> {
    unsafe { p.as_mut() }
}

#[inline]
pub unsafe fn at<'a, T>(p: *const T) -> &'a T {
    unsafe { &*p }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CStrRef(core::ptr::NonNull<u8>);

impl CStrRef {
    #[inline(always)]
    pub unsafe fn new(p: *const u8) -> CStrRef {
        CStrRef(unsafe { core::ptr::NonNull::new_unchecked(p as *mut u8) })
    }
    #[inline(always)]
    pub fn as_ptr(self) -> *const u8 {
        self.0.as_ptr()
    }
    #[inline]
    pub fn bytes(self) -> &'static [u8] {
        unsafe { cstr(self.as_ptr()) }
    }
    #[inline]
    pub fn eq_bytes(self, name: &[u8]) -> bool {
        unsafe { cstr_eq(self.as_ptr(), name) }
    }
    #[inline]
    pub fn eq_str(self, other: CStrRef) -> bool {
        unsafe { streq(self.as_ptr(), other.as_ptr()) }
    }
    #[inline]
    pub fn is_empty(self) -> bool {
        unsafe { *self.as_ptr() == 0 }
    }
}

impl CStrRef {
    #[inline]
    pub fn bytes_gnu_hash(self) -> (&'static [u8], u32) {
        unsafe { cstr_gnu_hash(self.as_ptr()) }
    }
}
