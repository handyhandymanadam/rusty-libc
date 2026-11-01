//! `ZStr`: a cursor over a NUL-terminated string whose length is not known (BRIEF-UNSAFE.md U2).
//!
//! The number parsers (strtol, strtod, a64l, ...) read a C string only as far as the number goes. Turning the string into a
//! slice first would cost a `strlen` over the whole rest of the text on every call (a program that walks a big buffer with
//! `strtol(p, &p, 10)` would become quadratic), so they read it through this cursor instead.
//!
//! Invariant (`pos` is the cursor's distance from `base`, kept as the address `p`): the units `base[0..=pos]` are
//! readable for `'a` and `base[0..pos]` holds no NUL. Every step keeps it: the
//! cursor moves past a unit only after reading that unit and seeing it is not NUL, so the next unit is still inside the
//! string (at worst it is the NUL). That makes reading the current unit, stepping, looking ahead (unit by unit, stopping at
//! a NUL) and handing out the scanned prefix `base[0..pos]` safe; only making a cursor from a raw pointer is `unsafe`.
//! Soundness rests on this module alone (the fields are private: Rust for Rustaceans p.233, the privacy boundary).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use core::marker::PhantomData;

/// A unit of a string: a byte, or a wide character (`wchar_t` is `i32` on x86-64).
pub trait Unit: Copy + Eq {
    /// The terminating unit.
    const NUL: Self;
    /// The unit as a code point (a byte's value, or the wide character).
    fn code(self) -> u32;
    /// The unit with code `c` (truncated for bytes).
    fn from_code(c: u32) -> Self;
}

impl Unit for u8 {
    const NUL: u8 = 0;
    #[inline(always)]
    fn code(self) -> u32 {
        u32::from(self)
    }
    #[inline(always)]
    fn from_code(c: u32) -> Self {
        c as u8
    }
}

impl Unit for u32 {
    const NUL: u32 = 0;
    #[inline(always)]
    fn code(self) -> u32 {
        self
    }
    #[inline(always)]
    fn from_code(c: u32) -> Self {
        c
    }
}

impl Unit for i32 {
    const NUL: i32 = 0;
    #[inline(always)]
    fn code(self) -> u32 {
        self as u32
    }
    #[inline(always)]
    fn from_code(c: u32) -> Self {
        c as i32
    }
}

/// A position in a NUL-terminated string (see the module documentation for the invariant).
#[derive(Clone, Copy)]
pub struct ZStr<'a, T: Unit = u8> {
    base: *const T,
    /// `base + pos`: the cursor kept as an address, so that a walk has one moving value (with an index next to the
    /// base, loops carried both a moving address and a count)
    p: *const T,
    _text: PhantomData<&'a [T]>,
}

impl<'a, T: Unit> ZStr<'a, T> {
    /// A cursor at the start of the string at `p`.
    ///
    /// # Safety
    /// `p` is not NULL, is aligned for `T`, and points to a string terminated by `T::NUL` that stays readable and unchanged
    /// for `'a`.
    #[inline(always)]
    pub unsafe fn new(p: *const T) -> Self {
        debug_assert!(!p.is_null());
        ZStr { base: p, p, _text: PhantomData }
    }

    /// A cursor at the start of `s`, which must contain a NUL (`None` otherwise): the string is `s` up to its first NUL.
    #[inline]
    pub fn from_slice(s: &'a [T]) -> Option<Self> {
        if s.contains(&T::NUL) { Some(ZStr { base: s.as_ptr(), p: s.as_ptr(), _text: PhantomData }) } else { None }
    }

    /// A cursor at the start of `s`, whose last unit must be `T::NUL` (`None` otherwise): the string is `s` up to its first
    /// NUL. Unlike [`ZStr::from_slice`] this does not scan `s` (the cursor never steps past a NUL, so the last one bounds
    /// every walk).
    #[inline(always)]
    pub fn from_nul_terminated(s: &'a [T]) -> Option<Self> {
        if s.last() == Some(&T::NUL) { Some(ZStr { base: s.as_ptr(), p: s.as_ptr(), _text: PhantomData }) } else { None }
    }

    /// The unit at the cursor (`T::NUL` at the end of the string).
    #[inline(always)]
    pub fn cur(&self) -> T {
        // SAFETY: `p` is base[pos], readable for 'a (the invariant).
        unsafe { self.p.read() }
    }

    /// Is the cursor at the terminating NUL?
    #[inline(always)]
    pub fn at_end(&self) -> bool {
        self.cur() == T::NUL
    }

    /// Step over the unit at the cursor (no move at the end of the string).
    #[inline(always)]
    pub fn bump(&mut self) {
        if self.at_end() {
            // a call on the NUL path keeps this a branch: as a branchless select the next load would wait for this one
            at_nul();
            return;
        }
        self.step();
    }

    /// Step over the unit at the cursor if it is `c` (not NUL); whether it was.
    #[inline(always)]
    pub fn eat(&mut self, c: T) -> bool {
        let u = self.cur();
        if u == c && u != T::NUL {
            self.step();
            true
        } else {
            false
        }
    }

    /// `f` of the unit at the cursor; when that is `Some`, step over the unit (never over the NUL).
    #[inline(always)]
    pub fn next_map<R>(&mut self, f: impl FnOnce(T) -> Option<R>) -> Option<R> {
        let u = self.cur();
        // `f` first: when it already rejects NUL (digit tests do) the compiler drops the check below
        let r = f(u)?;
        if u == T::NUL {
            return None;
        }
        self.step();
        Some(r)
    }

    /// Step over the units for which `f` holds (never over the NUL); how many.
    #[inline(always)]
    pub fn eat_while(&mut self, mut f: impl FnMut(T) -> bool) -> usize {
        // walked by a count from the cursor (moving the address itself made LLVM carry three induction values and copy
        // them every unit in digit loops)
        let mut n = 0;
        loop {
            let q = self.p.wrapping_add(n);
            // SAFETY: the units p[0..n] were seen not NUL, so q = p[n] is inside the string and readable (the invariant).
            let u = unsafe { q.read() };
            if u == T::NUL || !f(u) {
                break;
            }
            n += 1;
        }
        self.p = self.p.wrapping_add(n);
        n
    }

    /// Step over `n` units (stopping at the end of the string).
    #[inline(always)]
    pub fn bump_n(&mut self, n: usize) {
        let mut k = 0;
        while k < n {
            // units pos .. pos + k were seen not NUL, so this one is inside the string
            if self.at_end() {
                break;
            }
            self.step();
            k += 1;
        }
    }

    /// The unit `k` places after the cursor, or `T::NUL` when the string ends before it.
    #[inline(always)]
    pub fn peek(&self, k: usize) -> T {
        let mut t = *self;
        for _ in 0..k {
            if t.at_end() {
                return T::NUL;
            }
            t.step();
        }
        t.cur()
    }

    /// Do the units at the cursor start with `s` (which holds no NUL)?
    #[inline(always)]
    pub fn starts_with(&self, s: &[T]) -> bool {
        let mut t = *self;
        for &c in s {
            if t.cur() != c || c == T::NUL {
                return false;
            }
            t.step();
        }
        true
    }

    /// How many units the cursor is past the start.
    #[inline(always)]
    pub fn pos(&self) -> usize {
        (self.p.addr() - self.base.addr()) / size_of::<T>()
    }

    /// Move one unit on (the caller saw the unit at the cursor is not NUL, which keeps the invariant).
    #[inline(always)]
    fn step(&mut self) {
        self.p = self.p.wrapping_add(1);
    }

    /// Move back to `pos` (a position not after the cursor; a later one is clamped to the cursor).
    #[inline(always)]
    pub fn rewind(&mut self, pos: usize) {
        self.p = self.base.wrapping_add(pos.min(self.pos()));
    }

    /// The cursor `pos` units from the start, if that is not after this cursor.
    #[inline(always)]
    pub fn at(&self, pos: usize) -> ZStr<'a, T> {
        let mut t = *self;
        t.rewind(pos);
        t
    }

    /// The units before the cursor (all checked, none of them NUL).
    #[inline(always)]
    pub fn scanned(&self) -> &'a [T] {
        // SAFETY: base[0..pos] is readable for 'a and unchanged (the invariant); `base` is not NULL and aligned.
        unsafe { core::slice::from_raw_parts(self.base, self.pos()) }
    }

    /// Move to the end of the string and return everything before it.
    #[inline]
    pub fn rest_to_end(&mut self) -> &'a [T] {
        while !self.at_end() {
            self.step();
        }
        self.scanned()
    }

    /// The address of the unit `i` places from the start (for a C end pointer; never read through here).
    #[inline(always)]
    pub fn ptr_at(&self, i: usize) -> *const T {
        self.base.wrapping_add(i)
    }
}

/// The rare path of [`ZStr::bump`] (see there).
#[cold]
#[inline(never)]
fn at_nul() {
    // not an empty function: the compiler would see that it does nothing, drop the call and make the step branchless again
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl<'a> From<&'a CStr> for ZStr<'a, u8> {
    #[inline(always)]
    fn from(s: &'a CStr) -> Self {
        ZStr { base: s.as_ptr().cast(), p: s.as_ptr().cast(), _text: PhantomData }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_peek_and_scan() {
        let mut z = ZStr::from(c"0x1f");
        assert_eq!(z.cur(), b'0');
        assert_eq!(z.peek(1), b'x');
        assert_eq!(z.peek(4), 0);
        assert_eq!(z.peek(9), 0);
        assert!(z.starts_with(b"0x"));
        assert!(!z.starts_with(b"0x1f0"));
        z.bump_n(3);
        assert_eq!(z.scanned(), b"0x1");
        z.bump_n(10);
        assert!(z.at_end());
        assert_eq!(z.pos(), 4);
        z.bump();
        assert_eq!(z.pos(), 4);
        assert_eq!(z.at(2).scanned(), b"0x");
        assert_eq!(z.at(9).pos(), 4);
        let mut e = ZStr::from(c"");
        assert!(e.at_end());
        assert_eq!(e.rest_to_end(), b"");
        let w = [65i32, 66, 0, 67];
        let mut zw = ZStr::from_slice(&w).unwrap();
        assert_eq!(zw.rest_to_end(), &[65, 66]);
        assert!(ZStr::from_slice(&[1u8, 2]).is_none());
        assert!(ZStr::from_nul_terminated(&[1u8, 2]).is_none());
        assert!(ZStr::<u8>::from_nul_terminated(&[]).is_none());
        let mut zn = ZStr::from_nul_terminated(&[7u32, 0, 9, 0]).unwrap();
        assert_eq!(zn.rest_to_end(), &[7]);
        assert_eq!(ZStr::from(c"abc").ptr_at(2), c"abc".as_ptr().cast::<u8>().wrapping_add(2));
    }
}
