use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::cleanup::CleanupBuf;
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::errno;

#[inline]
pub(crate) fn sc(ret: usize) -> isize {
    if ret > usize::MAX - 4095 {
        errno::set((ret as isize).wrapping_neg() as i32);
        -1
    } else {
        ret as isize
    }
}

#[inline]
pub(crate) fn sci(ret: usize) -> c_int {
    sc(ret) as c_int
}

pub(crate) struct Spin<T> {
    locked: AtomicBool,
    cleanup: UnsafeCell<core::mem::MaybeUninit<CleanupBuf>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Spin<T> {}

pub(crate) struct SpinGuard<'a, T> {
    lock: &'a Spin<T>,
}

unsafe extern "C" fn spin_release(arg: *mut c_void) {
    unsafe { (*(arg as *const AtomicBool)).store(false, Ordering::Release) };
}


impl<T> Spin<T> {
    pub(crate) const fn new(v: T) -> Spin<T> {
        Spin {
            locked: AtomicBool::new(false),
            cleanup: UnsafeCell::new(core::mem::MaybeUninit::zeroed()),
            data: UnsafeCell::new(v),
        }
    }
    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        unsafe { rusty_libc_core::cleanup::push(self.cleanup.get().cast::<CleanupBuf>(), spin_release, &self.locked as *const AtomicBool as *mut c_void) };
        SpinGuard { lock: self }
    }
}

impl<T> core::ops::Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}
impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}
impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { rusty_libc_core::cleanup::remove(self.lock.cleanup.get().cast::<CleanupBuf>()) };
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[inline]
pub(crate) unsafe fn cstrlen(p: *const c_char) -> usize {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

#[inline]
pub(crate) unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p as *const u8, cstrlen(p)) }
}

pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    if p.is_null() { None } else { Some(unsafe { core::slice::from_raw_parts(p as *const u8, cstrlen(p)) }) }
}

#[derive(Clone, Copy)]
pub struct Buf<const N: usize> {
    pub b: [u8; N],
    pub len: usize,
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Buf { b: [0; N], len: 0 }
    }
    pub fn from(s: &[u8]) -> Option<Self> {
        let mut r = Self::new();
        if s.len() > N {
            return None;
        }
        r.b[..s.len()].copy_from_slice(s);
        r.len = s.len();
        Some(r)
    }
    pub fn push(&mut self, c: u8) -> bool {
        if self.len >= N {
            return false;
        }
        self.b[self.len] = c;
        self.len += 1;
        true
    }
    pub fn push_all(&mut self, s: &[u8]) -> bool {
        if self.len + s.len() > N {
            return false;
        }
        self.b[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        true
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.len]
    }
    pub fn push_u32(&mut self, mut v: u32) -> bool {
        let mut t = [0u8; 10];
        let mut i = 10;
        loop {
            i -= 1;
            t[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push_all(&t[i..])
    }
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn lower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

pub(crate) fn eq_nocase(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| lower(*x) == lower(*y))
}

#[inline]
pub(crate) fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[allow(dead_code)]
pub(crate) fn put_str(dst: &mut [u8], off: &mut usize, s: &[u8]) -> Option<*mut c_char> {
    if *off + s.len() + 1 > dst.len() {
        return None;
    }
    let p = unsafe { dst.as_mut_ptr().add(*off) };
    dst[*off..*off + s.len()].copy_from_slice(s);
    dst[*off + s.len()] = 0;
    *off += s.len() + 1;
    Some(p as *mut c_char)
}

pub(crate) fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}
