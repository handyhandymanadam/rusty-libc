#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use core::marker::PhantomData;

pub trait Unit: Copy + Eq {
    const NUL: Self;
    fn code(self) -> u32;
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

#[derive(Clone, Copy)]
pub struct ZStr<'a, T: Unit = u8> {
    base: *const T,
    p: *const T,
    _text: PhantomData<&'a [T]>,
}

impl<'a, T: Unit> ZStr<'a, T> {
    #[inline(always)]
    pub unsafe fn new(p: *const T) -> Self {
        debug_assert!(!p.is_null());
        ZStr { base: p, p, _text: PhantomData }
    }

    #[inline]
    pub fn from_slice(s: &'a [T]) -> Option<Self> {
        if s.contains(&T::NUL) { Some(ZStr { base: s.as_ptr(), p: s.as_ptr(), _text: PhantomData }) } else { None }
    }

    #[inline(always)]
    pub fn from_nul_terminated(s: &'a [T]) -> Option<Self> {
        if s.last() == Some(&T::NUL) { Some(ZStr { base: s.as_ptr(), p: s.as_ptr(), _text: PhantomData }) } else { None }
    }

    #[inline(always)]
    pub fn cur(&self) -> T {
        unsafe { self.p.read() }
    }

    #[inline(always)]
    pub fn at_end(&self) -> bool {
        self.cur() == T::NUL
    }

    #[inline(always)]
    pub fn bump(&mut self) {
        if self.at_end() {
            at_nul();
            return;
        }
        self.step();
    }

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

    #[inline(always)]
    pub fn next_map<R>(&mut self, f: impl FnOnce(T) -> Option<R>) -> Option<R> {
        let u = self.cur();
        let r = f(u)?;
        if u == T::NUL {
            return None;
        }
        self.step();
        Some(r)
    }

    #[inline(always)]
    pub fn eat_while(&mut self, mut f: impl FnMut(T) -> bool) -> usize {
        let mut n = 0;
        loop {
            let q = self.p.wrapping_add(n);
            let u = unsafe { q.read() };
            if u == T::NUL || !f(u) {
                break;
            }
            n += 1;
        }
        self.p = self.p.wrapping_add(n);
        n
    }

    #[inline(always)]
    pub fn bump_n(&mut self, n: usize) {
        let mut k = 0;
        while k < n {
            if self.at_end() {
                break;
            }
            self.step();
            k += 1;
        }
    }

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

    #[inline(always)]
    pub fn pos(&self) -> usize {
        (self.p.addr() - self.base.addr()) / size_of::<T>()
    }

    #[inline(always)]
    fn step(&mut self) {
        self.p = self.p.wrapping_add(1);
    }

    #[inline(always)]
    pub fn rewind(&mut self, pos: usize) {
        self.p = self.base.wrapping_add(pos.min(self.pos()));
    }

    #[inline(always)]
    pub fn at(&self, pos: usize) -> ZStr<'a, T> {
        let mut t = *self;
        t.rewind(pos);
        t
    }

    #[inline(always)]
    pub fn scanned(&self) -> &'a [T] {
        unsafe { core::slice::from_raw_parts(self.base, self.pos()) }
    }

    #[inline]
    pub fn rest_to_end(&mut self) -> &'a [T] {
        while !self.at_end() {
            self.step();
        }
        self.scanned()
    }

    #[inline(always)]
    pub fn ptr_at(&self, i: usize) -> *const T {
        self.base.wrapping_add(i)
    }
}

#[cold]
#[inline(never)]
fn at_nul() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl<'a> From<&'a CStr> for ZStr<'a, u8> {
    #[inline(always)]
    fn from(s: &'a CStr) -> Self {
        ZStr { base: s.as_ptr().cast(), p: s.as_ptr().cast(), _text: PhantomData }
    }
}

