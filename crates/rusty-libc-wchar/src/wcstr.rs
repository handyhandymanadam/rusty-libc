use crate::wchar_t;
use core::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct WStr<'a> {
    p: *const u32,
    _life: PhantomData<&'a [u32]>,
}

impl<'a> WStr<'a> {
    #[inline(always)]
    pub unsafe fn new(p: *const wchar_t) -> WStr<'a> {
        debug_assert!(!p.is_null());
        WStr { p: p.cast(), _life: PhantomData }
    }

    #[inline(always)]
    pub fn as_ptr(self) -> *const wchar_t {
        self.p.cast()
    }

    #[inline(always)]
    pub fn len(self) -> usize {
        unsafe { crate::wstring::wcslen(self.as_ptr()) }
    }

    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.first() == 0
    }

    #[inline(always)]
    pub fn first(self) -> u32 {
        unsafe { *self.p }
    }

    #[inline(always)]
    pub fn to_slice(self) -> &'a [u32] {
        let n = self.len();
        unsafe { rusty_libc_core::ffi::slice(self.p, n) }
    }

    #[inline(always)]
    pub fn to_slice_with_nul(self) -> &'a [u32] {
        let n = self.len() + 1;
        unsafe { rusty_libc_core::ffi::slice(self.p, n) }
    }

    #[inline(always)]
    pub fn to_slice_max(self, n: usize) -> &'a [u32] {
        let l = self.len_max(n);
        unsafe { rusty_libc_core::ffi::slice(self.p, l) }
    }

    #[inline(always)]
    pub fn len_max(self, n: usize) -> usize {
        unsafe { crate::wstring::wcsnlen(self.as_ptr(), n) }
    }

    #[inline(always)]
    pub fn skip(self, i: usize) -> WStr<'a> {
        WStr { p: self.p.wrapping_add(i), _life: PhantomData }
    }

    #[inline(always)]
    pub fn chars(self) -> Chars<'a> {
        Chars { p: self.p, done: false, _life: PhantomData }
    }

}

pub struct Chars<'a> {
    p: *const u32,
    done: bool,
    _life: PhantomData<&'a [u32]>,
}

impl Iterator for Chars<'_> {
    type Item = u32;
    #[inline(always)]
    fn next(&mut self) -> Option<u32> {
        if self.done {
            return None;
        }
        let c = unsafe { *self.p };
        if c == 0 {
            self.done = true;
            return None;
        }
        self.p = self.p.wrapping_add(1);
        Some(c)
    }
}

pub struct CharsN<'a> {
    p: *const u32,
    left: usize,
    _life: PhantomData<&'a [u32]>,
}

impl<'a> CharsN<'a> {
    #[inline(always)]
    pub unsafe fn new(p: *const wchar_t, n: usize) -> CharsN<'a> {
        CharsN { p: p.cast(), left: n, _life: PhantomData }
    }
}

impl Iterator for CharsN<'_> {
    type Item = u32;
    #[inline(always)]
    fn next(&mut self) -> Option<u32> {
        if self.left == 0 {
            return None;
        }
        let c = unsafe { *self.p };
        if c == 0 {
            self.left = 0;
            return None;
        }
        self.left -= 1;
        self.p = self.p.wrapping_add(1);
        Some(c)
    }
}

