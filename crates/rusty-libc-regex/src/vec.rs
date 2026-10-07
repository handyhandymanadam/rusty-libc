use core::ops::{Deref, DerefMut};
use core::ptr::null_mut;

pub struct V<T> {
    ptr: *mut T,
    len: usize,
    cap: usize,
    pub oom: bool,
}

impl<T> V<T> {
    pub const fn new() -> V<T> {
        V { ptr: null_mut(), len: 0, cap: 0, oom: false }
    }

    pub fn with_capacity(n: usize) -> V<T> {
        let mut v = V::new();
        v.reserve(n);
        v
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn reserve(&mut self, extra: usize) {
        if self.oom {
            return;
        }
        let need = match self.len.checked_add(extra) {
            Some(n) => n,
            None => {
                self.oom = true;
                return;
            }
        };
        if need <= self.cap {
            return;
        }
        let mut ncap = if self.cap == 0 { 4 } else { self.cap * 2 };
        if ncap < need {
            ncap = need;
        }
        let bytes = match ncap.checked_mul(core::mem::size_of::<T>()) {
            Some(b) => b,
            None => {
                self.oom = true;
                return;
            }
        };
        let p = unsafe { rusty_libc_malloc::realloc(self.ptr.cast(), bytes) } as *mut T;
        if p.is_null() {
            self.oom = true;
        } else {
            self.ptr = p;
            self.cap = ncap;
        }
    }

    pub fn push(&mut self, v: T) {
        if self.len == self.cap {
            self.reserve(1);
            if self.oom {
                return;
            }
        }
        unsafe { self.ptr.add(self.len).write(v) };
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            Some(unsafe { self.ptr.add(self.len).read() })
        }
    }

    pub fn truncate(&mut self, n: usize) {
        while self.len > n {
            self.len -= 1;
            unsafe { core::ptr::drop_in_place(self.ptr.add(self.len)) };
        }
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }
}

impl<T: Copy> V<T> {
    pub fn resize(&mut self, n: usize, v: T) {
        if n > self.len {
            self.reserve(n - self.len);
            if self.oom {
                return;
            }
            while self.len < n {
                unsafe { self.ptr.add(self.len).write(v) };
                self.len += 1;
            }
        } else {
            self.len = n;
        }
    }

    pub fn from_elem(v: T, n: usize) -> V<T> {
        let mut r = V::new();
        r.resize(n, v);
        r
    }

    pub fn extend_from_slice(&mut self, s: &[T]) {
        self.reserve(s.len());
        if self.oom {
            return;
        }
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr.add(self.len), s.len()) };
        self.len += s.len();
    }

    pub fn duplicate(&self) -> V<T> {
        let mut r = V::with_capacity(self.len);
        r.extend_from_slice(self);
        r.oom |= self.oom;
        r
    }
}

impl<T> Deref for V<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        if self.len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(self.ptr, self.len) } }
    }
}

impl<T> DerefMut for V<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        if self.len == 0 { &mut [] } else { unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) } }
    }
}

impl<T> Drop for V<T> {
    fn drop(&mut self) {
        self.truncate(0);
        if !self.ptr.is_null() {
            unsafe { rusty_libc_malloc::free(self.ptr.cast()) };
        }
    }
}

impl<T> Default for V<T> {
    fn default() -> V<T> {
        V::new()
    }
}
