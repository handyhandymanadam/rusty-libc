use core::ffi::c_char;
use rusty_libc_core::syscall;

#[inline]
pub(crate) fn malloc(size: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::malloc(size) }.cast()
}

#[inline]
pub(crate) fn calloc(n: usize, size: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::calloc(n, size) }.cast()
}

#[inline]
pub(crate) unsafe fn free<T>(p: *mut T) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

#[inline]
pub(crate) unsafe fn realloc(p: *mut u8, size: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::realloc(p.cast(), size) }.cast()
}

#[inline]
pub(crate) unsafe fn block<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    unsafe { rusty_libc_core::ffi::bytes_mut(p, len) }
}

pub(crate) fn dup_cstr(s: &[u8]) -> *mut u8 {
    let p = malloc(s.len() + 1);
    if p.is_null() {
        return p;
    }
    let buf = unsafe { block(p, s.len() + 1) };
    buf[..s.len()].copy_from_slice(s);
    buf[s.len()] = 0;
    p
}

pub(crate) fn leak_default<T: Copy + Default>(n: usize) -> Option<&'static mut [T]> {
    const { assert!(core::mem::align_of::<T>() <= 16) };
    let p = calloc(n.max(1), core::mem::size_of::<T>()).cast::<core::mem::MaybeUninit<T>>();
    if p.is_null() {
        return None;
    }
    let slots = unsafe { rusty_libc_core::ffi::slice_mut(p, n) };
    for s in slots.iter_mut() {
        s.write(T::default());
    }
    Some(unsafe { rusty_libc_core::ffi::slice_mut(p.cast::<T>(), n) })
}

pub(crate) fn leak<T>(v: T) -> Option<&'static mut T> {
    const { assert!(core::mem::align_of::<T>() <= 16) };
    let p = malloc(core::mem::size_of::<T>().max(1)).cast::<T>();
    if p.is_null() {
        return None;
    }
    let slot = unsafe { &mut *p.cast::<core::mem::MaybeUninit<T>>() };
    Some(slot.write(v))
}

pub(crate) struct Published<T: Sync + 'static>(core::sync::atomic::AtomicPtr<T>);

impl<T: Sync + 'static> Published<T> {
    pub(crate) const fn empty() -> Self {
        Published(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()))
    }

    #[inline(always)]
    pub(crate) fn get(&self) -> Option<&'static T> {
        Self::as_ref(self.0.load(core::sync::atomic::Ordering::Acquire))
    }

    #[inline]
    pub(crate) fn publish(&self, v: &'static T) -> Result<(), &'static T> {
        let p = core::ptr::from_ref(v).cast_mut();
        match self.0.compare_exchange(core::ptr::null_mut(), p, core::sync::atomic::Ordering::Release, core::sync::atomic::Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(other) => Err(Self::as_ref(other).unwrap_or(v)),
        }
    }

    #[inline(always)]
    fn as_ref(p: *mut T) -> Option<&'static T> {
        unsafe { p.as_ref() }
    }
}

const PROT_READ: usize = 1;
const MAP_PRIVATE: usize = 2;
const O_RDONLY: i32 = 0;
const O_CLOEXEC: i32 = 0o2000000;

pub(crate) fn open_ro(path: &[u8]) -> Result<i32, rusty_libc_core::Errno> {
    assert_eq!(path.last(), Some(&0));
    unsafe { rusty_libc_core::unistd::open(path.as_ptr().cast::<c_char>(), O_RDONLY | O_CLOEXEC, 0) }
}

pub(crate) fn mmap_ro(fd: i32, len: usize) -> Result<*const u8, rusty_libc_core::Errno> {
    let r = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, len, PROT_READ, MAP_PRIVATE, fd as usize, 0) };
    syscall::check(r).map(|a| a as *const u8)
}

pub(crate) fn map_forever(fd: i32, len: usize) -> Option<&'static [u8]> {
    let p = mmap_ro(fd, len).ok()?;
    Some(unsafe { rusty_libc_core::ffi::bytes(p, len) })
}

#[inline(always)]
pub(crate) fn rd32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off.wrapping_add(4)) {
        Some(w) => u32::from_ne_bytes([w[0], w[1], w[2], w[3]]),
        None => 0,
    }
}

#[inline]
pub(crate) fn cstr_at(b: &[u8], off: usize) -> &[u8] {
    let s = b.get(off..).unwrap_or(&[]);
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..n]
}
