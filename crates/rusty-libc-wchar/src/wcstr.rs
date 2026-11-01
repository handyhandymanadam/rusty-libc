//! A NUL-terminated wide string in C memory, seen from safe code (BRIEF-UNSAFE.md U2).
//!
//! The exported functions get `const wchar_t *` arguments whose length nobody knows. Measuring it first (`wcslen`) and
//! taking a slice is right for the functions that read the whole string anyway (wcscpy, wcsdup, wcsstr ...), but wrong for
//! the ones that stop early (wcsspn, wcstol, wcscasecmp ...): they would read a long string to its end for an answer
//! found in the first few characters, which glibc does not do. [`WStr`] covers both: [`WStr::to_slice`] measures,
//! [`WStr::chars`] reads lazily and never past the terminating 0 (the number parsers read through stdlib's `ZStr`
//! cursor).
//!
//! Soundness rests on one invariant, set by the one unsafe constructor: the pointer is a NUL-terminated wide string that
//! stays valid and unchanged for `'a`. Element `i` is then readable whenever every element before it is not 0 (the
//! string goes on), and that is what each read below checks before it reads. Sources: The Rustonomicon p.248 (a safe
//! interface over a C API keeps the unsafe part inside the wrapper), Rust for Rustaceans p.233 (soundness is argued at
//! the module's privacy boundary: the fields are private, so only `new` can make a `WStr`).
use crate::wchar_t;
use core::marker::PhantomData;

/// A NUL-terminated wide string at a C pointer (the 0 not included), valid for `'a`.
#[derive(Clone, Copy)]
pub struct WStr<'a> {
    p: *const u32,
    _life: PhantomData<&'a [u32]>,
}

impl<'a> WStr<'a> {
    /// The wide string at `p`.
    ///
    /// # Safety
    /// `p` is not NULL and points to a NUL-terminated wide string that stays valid and unchanged for `'a`.
    #[inline(always)]
    pub unsafe fn new(p: *const wchar_t) -> WStr<'a> {
        debug_assert!(!p.is_null());
        WStr { p: p.cast(), _life: PhantomData }
    }

    /// The pointer it was made from.
    #[inline(always)]
    pub fn as_ptr(self) -> *const wchar_t {
        self.p.cast()
    }

    /// Number of characters before the 0 (`wcslen`, with its vector kernel).
    #[inline(always)]
    pub fn len(self) -> usize {
        // SAFETY: `p` is a NUL-terminated wide string (the type's invariant).
        unsafe { crate::wstring::wcslen(self.as_ptr()) }
    }

    /// Is the string empty (its first character the 0)?
    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.first() == 0
    }

    /// The first character (0 for the empty string).
    #[inline(always)]
    pub fn first(self) -> u32 {
        // SAFETY: element 0 is always readable: it is the terminator or a character before it.
        unsafe { *self.p }
    }

    /// The characters before the 0.
    #[inline(always)]
    pub fn to_slice(self) -> &'a [u32] {
        let n = self.len();
        // SAFETY: the `n` elements before the 0 are readable and unchanged for `'a` (invariant); `p` is 4-aligned as a
        // `wchar_t *` is.
        unsafe { rusty_libc_core::ffi::slice(self.p, n) }
    }

    /// The characters and the terminating 0.
    #[inline(always)]
    pub fn to_slice_with_nul(self) -> &'a [u32] {
        let n = self.len() + 1;
        // SAFETY: as `to_slice`, one element further: the 0 itself.
        unsafe { rusty_libc_core::ffi::slice(self.p, n) }
    }

    /// The characters before the 0 and at most `n` of them (`wcsnlen`'s count, with its vector kernel).
    #[inline(always)]
    pub fn to_slice_max(self, n: usize) -> &'a [u32] {
        let l = self.len_max(n);
        // SAFETY: the `l` elements counted are before the 0, so readable for `'a`.
        unsafe { rusty_libc_core::ffi::slice(self.p, l) }
    }

    /// Number of characters before the 0, counting no more than `n` (`wcsnlen`, with its vector kernel).
    #[inline(always)]
    pub fn len_max(self, n: usize) -> usize {
        // SAFETY: wcsnlen reads no further than the 0 or the `n`th element; the invariant covers the first.
        unsafe { crate::wstring::wcsnlen(self.as_ptr(), n) }
    }

    /// The string from character `i` on, which must not be past the 0 (`i <= len`): the caller found `i` by reading.
    #[inline(always)]
    pub fn skip(self, i: usize) -> WStr<'a> {
        WStr { p: self.p.wrapping_add(i), _life: PhantomData }
    }

    /// The characters before the 0, read one at a time.
    #[inline(always)]
    pub fn chars(self) -> Chars<'a> {
        Chars { p: self.p, done: false, _life: PhantomData }
    }

}

/// The characters of a [`WStr`] up to (not including) its 0.
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
        // SAFETY: `p` is the start of the string or one past a character that was not 0, so it is readable.
        let c = unsafe { *self.p };
        if c == 0 {
            self.done = true;
            return None;
        }
        self.p = self.p.wrapping_add(1);
        Some(c)
    }
}

/// The characters of a wide string that ends at its 0 or after `n` characters, whichever comes first (the `wcsn*`
/// functions' strings), read one at a time.
pub struct CharsN<'a> {
    p: *const u32,
    left: usize,
    _life: PhantomData<&'a [u32]>,
}

impl<'a> CharsN<'a> {
    /// The characters at `p`, up to its 0 or `n` of them.
    ///
    /// # Safety
    /// `p` is readable up to its 0 or for `n` elements, whichever comes first, and unchanged for `'a`.
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
        // SAFETY: fewer than `n` elements were read and none of them was 0, so this one is readable.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn views() {
        let w: Vec<i32> = "hello".chars().map(|c| c as i32).chain([0, 7, 7]).collect();
        let s = unsafe { WStr::new(w.as_ptr()) };
        assert_eq!(s.len(), 5);
        assert_eq!(s.to_slice(), &[104, 101, 108, 108, 111]);
        assert_eq!(s.to_slice_with_nul().len(), 6);
        assert_eq!(s.to_slice_max(3).len(), 3);
        assert_eq!(s.to_slice_max(9).len(), 5);
        assert_eq!(s.chars().count(), 5);
        assert_eq!(s.skip(5).first(), 0);
        assert!(s.skip(5).is_empty());
    }
}
