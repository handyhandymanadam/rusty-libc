//! Small helpers shared by the modules: errno handling, a spin lock, C string access, number text, filling a caller's
//! buffer ([`Carve`]) and a growable array on the library's allocator ([`HeapVec`]).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use rusty_libc_core::cleanup::CleanupBuf;
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::errno;

/// Raw system call result to the C convention: -1 and errno on failure.
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

/// A very small spin lock for the library's static buffers (no threads library below this crate).
/// It is held across blocking calls (a DNS query, a file read): a thread cancelled meanwhile must not
/// leave it locked, so the lock carries its own cancellation-cleanup entry (usable by its holder only,
/// there is one holder at a time) that releases it.
pub(crate) struct Spin<T> {
    locked: AtomicBool,
    /// Not initialised until `lock` pushes it (an initial `routine` pointer would be a load-time relocation in every static
    /// that holds a `Spin`, and the page it sits on would be copied at every program start).
    cleanup: UnsafeCell<core::mem::MaybeUninit<CleanupBuf>>,
    data: UnsafeCell<T>,
}

// SAFETY: the data is reached only through a `SpinGuard`, and at most one guard exists at a time (the `locked` flag is taken
// with Acquire and released with Release), so sharing a `Spin` hands `T` from thread to thread like a mutex does.
unsafe impl<T: Send> Sync for Spin<T> {}

pub(crate) struct SpinGuard<'a, T> {
    lock: &'a Spin<T>,
}

unsafe extern "C" fn spin_release(arg: *mut c_void) {
    // SAFETY: `arg` is the `locked` flag of a spin lock held by the cancelled thread.
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
        // SAFETY: we hold the lock, so the entry is ours; it stays valid as long as the lock does.
        unsafe { rusty_libc_core::cleanup::push(self.cleanup.get().cast::<CleanupBuf>(), spin_release, &self.locked as *const AtomicBool as *mut c_void) };
        SpinGuard { lock: self }
    }
}

impl<T> core::ops::Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard holds the lock, so no other guard (the only other way to the data) exists.
        unsafe { &*self.lock.data.get() }
    }
}
impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` makes this the only borrow through the guard.
        unsafe { &mut *self.lock.data.get() }
    }
}
impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: pushed by `lock` in this thread.
        unsafe { rusty_libc_core::cleanup::remove(self.lock.cleanup.get().cast::<CleanupBuf>()) };
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// Length of a C string; the bytes of a C string (without the NUL).
pub(crate) use rusty_libc_core::ffi::{cstr_bytes as cbytes, cstr_len as cstrlen};

/// The value of an environment variable (valid until the environment changes).
pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: core's getenv is safe against concurrent setenv/unsetenv (see its documentation); the library's callers make
    // no other promise than glibc's getenv does.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    // SAFETY: a non-NULL result points to a NUL-terminated value in the environment, whose strings are never freed.
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
}

/// A fixed-capacity byte string on the stack.
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

/// Case-insensitive equality of two byte strings (ASCII; the C locale).
pub(crate) fn eq_nocase(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| lower(*x) == lower(*y))
}

/// C `isspace` in the C locale.
#[inline]
pub(crate) fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Fills a caller's buffer (the `buf, buflen` pair of the `_r` functions) from the front: strings, raw bytes and pointer
/// arrays, each piece a disjoint part of the buffer (cut off with `split_at_mut`, so the borrow checker sees them apart).
/// The pieces live as long as the buffer (`'a`), so pointers into them may be stored in the result structure the caller
/// gets back. The start is first moved to an 8-byte boundary (the pointer arrays need it; this is where the old per-module
/// fillers began too). After a refused request every later request is refused as well.
pub(crate) struct Carve<'a> {
    rest: &'a mut [u8],
    dead: bool,
}

impl<'a> Carve<'a> {
    /// A filler over `buf`, starting at its first 8-byte boundary (an empty filler when `buf` is shorter than the padding).
    pub(crate) fn new(buf: &'a mut [u8]) -> Carve<'a> {
        let pad = (buf.as_ptr() as usize).wrapping_neg() & 7;
        let rest = if buf.len() < pad { &mut [] } else { &mut buf[pad..] };
        Carve { rest, dead: false }
    }

    /// Bytes not handed out yet.
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> usize {
        if self.dead { 0 } else { self.rest.len() }
    }

    /// The next `n` bytes, or None (and every later request fails) when fewer are left.
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a mut [u8]> {
        if self.dead || n > self.rest.len() {
            self.dead = true;
            return None;
        }
        let (head, tail) = core::mem::take(&mut self.rest).split_at_mut(n);
        self.rest = tail;
        Some(head)
    }

    /// Skip to the next multiple of `a` (a power of two) from the address of the next byte.
    pub(crate) fn align(&mut self, a: usize) -> Option<()> {
        let pad = (self.rest.as_ptr() as usize).wrapping_neg() & (a - 1);
        self.take(pad).map(|_| ())
    }

    /// A copy of `b`; returns a pointer to it.
    pub(crate) fn bytes(&mut self, b: &[u8]) -> Option<*mut u8> {
        let d = self.take(b.len())?;
        d.copy_from_slice(b);
        Some(d.as_mut_ptr())
    }

    /// A copy of `s` followed by a NUL; returns a pointer to it (as C wants it).
    pub(crate) fn string(&mut self, s: &[u8]) -> Option<*mut c_char> {
        let d = self.take(s.len() + 1)?;
        d[..s.len()].copy_from_slice(s);
        d[s.len()] = 0;
        Some(d.as_mut_ptr().cast::<c_char>())
    }

    /// An array of `n` pointers, 8-byte aligned, all NULL to begin with; the caller stores into it.
    pub(crate) fn ptr_array(&mut self, n: usize) -> Option<&'a mut [*mut c_char]> {
        self.align(8)?;
        let d = self.take(n.checked_mul(8)?)?;
        d.fill(0);
        // SAFETY: `d` is `8 * n` bytes, 8-aligned (align above), exclusively borrowed for `'a` and moved into the result, so
        // nothing else reaches it; all-zero bytes are a valid (NULL) `*mut c_char`, so every element is initialised.
        Some(unsafe { core::slice::from_raw_parts_mut(d.as_mut_ptr().cast::<*mut c_char>(), n) })
    }

    /// A pointer array holding a copy of each word of `words`, then a NULL (an alias list).
    pub(crate) fn string_list<'w>(&mut self, words: impl Iterator<Item = &'w [u8]> + Clone) -> Option<*mut *mut c_char> {
        let n = words.clone().count();
        let arr = self.ptr_array(n + 1)?;
        for (slot, w) in arr.iter_mut().zip(words) {
            *slot = self.string(w)?;
        }
        Some(arr.as_mut_ptr())
    }
}

/// A growable array in memory from the library's own allocator (`rusty_libc_malloc`), for results that have no fixed size
/// (the addresses and aliases of a host answer). Nothing is allocated until the first element is pushed. Elements are plain
/// data (`Copy`), so freeing is just giving the block back. A push that cannot get memory is refused (returns false).
pub struct HeapVec<T: Copy> {
    ptr: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> HeapVec<T> {
    pub const fn new() -> Self {
        HeapVec { ptr: core::ptr::null_mut(), len: 0, cap: 0 }
    }

    pub fn push(&mut self, v: T) -> bool {
        if self.len == self.cap && !self.grow(1) {
            return false;
        }
        // SAFETY: `len < cap` now, so slot `len` lies inside the block of `cap` elements that `ptr` owns.
        unsafe { self.ptr.wrapping_add(self.len).write(v) };
        self.len += 1;
        true
    }

    /// Append all of `s`, or nothing.
    pub fn extend_from(&mut self, s: &[T]) -> bool {
        if self.cap - self.len < s.len() && !self.grow(s.len()) {
            return false;
        }
        // SAFETY: `len + s.len() <= cap`, so the destination lies inside the owned block (a fresh `ptr.add(len)` within it);
        // `s` cannot overlap it: the block is ours alone and `s` is borrowed from elsewhere (&self is not borrowed here).
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr.wrapping_add(self.len), s.len()) };
        self.len += s.len();
        true
    }

    fn grow(&mut self, extra: usize) -> bool {
        let want = self.len + extra;
        let mut cap = if self.cap == 0 { 8 } else { self.cap * 2 };
        while cap < want {
            cap *= 2;
        }
        let bytes = match cap.checked_mul(core::mem::size_of::<T>()) {
            Some(b) => b,
            None => return false,
        };
        // SAFETY: `ptr` is NULL or a block this vector got from the same allocator and still owns.
        let p = unsafe { rusty_libc_malloc::realloc(self.ptr as *mut c_void, bytes) } as *mut T;
        if p.is_null() {
            return false;
        }
        self.ptr = p;
        self.cap = cap;
        true
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl HeapVec<u8> {
    pub fn as_bytes(&self) -> &[u8] {
        self
    }

    /// `n` zero bytes (a scratch buffer); None when memory is short.
    pub fn zeroed(n: usize) -> Option<Self> {
        let mut v = HeapVec::new();
        let zeros = [0u8; 256];
        while v.len() < n {
            if !v.extend_from(&zeros[..(n - v.len()).min(zeros.len())]) {
                return None;
            }
        }
        Some(v)
    }
}

impl<T: Copy> core::ops::Deref for HeapVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        // SAFETY: the first `len` elements of the owned block were written by push/extend_from (or are none: then any
        // pointer, NULL included, gives an empty slice).
        unsafe { rusty_libc_core::ffi::slice(self.ptr, self.len) }
    }
}

impl<T: Copy> core::ops::DerefMut for HeapVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as in `deref`, and `&mut self` makes the slice the only access to the block.
        unsafe { rusty_libc_core::ffi::slice_mut(self.ptr, self.len) }
    }
}

impl<T: Copy> HeapVec<T> {
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self
    }
}

impl<T: Copy> Drop for HeapVec<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the block came from the library's allocator and is owned by this vector alone.
            unsafe { rusty_libc_malloc::free(self.ptr as *mut c_void) };
        }
    }
}

impl<T: Copy> Default for HeapVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::Carve;

    #[test]
    fn carve_pieces_are_disjoint_and_aligned() {
        let mut buf = [0xaau8; 64];
        let base = buf.as_ptr() as usize;
        let mut c = Carve::new(&mut buf[1..]);
        let s = c.string(b"abc").unwrap() as usize;
        assert_eq!(s % 8, 0);
        let arr = c.ptr_array(2).unwrap();
        assert_eq!(arr.as_ptr() as usize % 8, 0);
        assert!(arr.iter().all(|p| p.is_null()));
        assert_eq!(arr.as_ptr() as usize, (s + 4 + 7) & !7);
        assert!(c.take(1000).is_none());
        assert!(c.take(0).is_none(), "refused once, refused always");
        assert_eq!(c.remaining(), 0);
        assert_eq!(buf[s - base..s - base + 4], *b"abc\0");
    }

    #[test]
    fn carve_string_list() {
        let mut buf = [0u8; 80];
        let mut c = Carve::new(&mut buf);
        let words: [&[u8]; 2] = [b"x", b"yz"];
        let l = c.string_list(words.iter().copied()).unwrap();
        // SAFETY: `l` points to 3 pointers inside `buf`, written by string_list; the strings are NUL-terminated.
        let v: [*mut core::ffi::c_char; 3] = unsafe { [*l, *l.add(1), *l.add(2)] };
        assert!(v[2].is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(v[1]) }.to_bytes(), b"yz");
        let mut small = [0u8; 16];
        let mut c = Carve::new(&mut small);
        assert!(c.string_list(words.iter().copied()).is_none());
    }
}

/// open(2) of a C string path, not a cancellation point (rusty-libc-core's `open`: openat(AT_FDCWD, ...)).
pub fn open(path: &CStr, flags: c_int, mode: u32) -> Result<c_int, rusty_libc_core::Errno> {
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    unsafe { rusty_libc_core::unistd::open(path.as_ptr(), flags, mode) }
}
