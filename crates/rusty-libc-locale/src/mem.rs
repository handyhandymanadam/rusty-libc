//! Memory the locale crate takes from the system: blocks from the library's malloc and read-only file mappings. Each
//! function here holds one audited unsafe operation (or a few, one per block) so the modules above work on slices and
//! references.
//!
//! Lifetimes. Locale data, catalogs and the lists built from them are never freed or unmapped (glibc keeps them for the
//! life of the process too), so a mapping or a block that is never handed back is given out as `&'static` (Rust for
//! Rustaceans p.30: memory that is deliberately never released can be referenced for `'static`, as `Box::leak` does).
//! Blocks that are freed later (locale names, `locale_t` objects, catgets catalogs) stay raw pointers.
use core::ffi::c_char;
use rusty_libc_core::syscall;

/// The library's malloc: a block of `size` bytes aligned to 16, or null. Safe: getting memory has no preconditions.
#[inline]
pub(crate) fn malloc(size: usize) -> *mut u8 {
    // SAFETY: malloc has no preconditions.
    unsafe { rusty_libc_malloc::malloc(size) }.cast()
}

/// The library's calloc: `n * size` zeroed bytes (null on overflow or when memory is short).
#[inline]
pub(crate) fn calloc(n: usize, size: usize) -> *mut u8 {
    // SAFETY: calloc has no preconditions.
    unsafe { rusty_libc_malloc::calloc(n, size) }.cast()
}

/// Give a block back to malloc.
///
/// # Safety
/// `p` is null or a block from this library's malloc/calloc/realloc that nothing uses afterwards.
#[inline]
pub(crate) unsafe fn free<T>(p: *mut T) {
    // SAFETY: the caller's contract; free(NULL) does nothing.
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

/// The library's realloc.
///
/// # Safety
/// `p` is null or a live block from this library's malloc; on success it is not used again (the result replaces it).
#[inline]
pub(crate) unsafe fn realloc(p: *mut u8, size: usize) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { rusty_libc_malloc::realloc(p.cast(), size) }.cast()
}

/// The `len` bytes of a fresh block as a slice the caller owns for as long as it keeps the block.
///
/// # Safety
/// `p` is a block of at least `len` bytes from this library's malloc that nothing else uses; `'a` ends before it is freed.
#[inline]
pub(crate) unsafe fn block<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    // SAFETY: the caller's contract (`len` bytes, exclusive, alive for `'a`).
    unsafe { rusty_libc_core::ffi::bytes_mut(p, len) }
}

/// A malloc'd copy of `s` with a NUL after it, or null when memory is short. Freed with [`free`] (or kept).
pub(crate) fn dup_cstr(s: &[u8]) -> *mut u8 {
    let p = malloc(s.len() + 1);
    if p.is_null() {
        return p;
    }
    // SAFETY: `p` is a fresh block of `s.len() + 1` bytes, ours alone until it is returned.
    let buf = unsafe { block(p, s.len() + 1) };
    buf[..s.len()].copy_from_slice(s);
    buf[s.len()] = 0;
    p
}

/// An array of `n` default values (from a zeroed calloc block) that is never freed, or None when memory is short.
pub(crate) fn leak_default<T: Copy + Default>(n: usize) -> Option<&'static mut [T]> {
    const { assert!(core::mem::align_of::<T>() <= 16) };
    let p = calloc(n.max(1), core::mem::size_of::<T>()).cast::<core::mem::MaybeUninit<T>>();
    if p.is_null() {
        return None;
    }
    // SAFETY: a fresh block of `n` values, 16-aligned, never freed and ours alone; `MaybeUninit` holds any bytes.
    let slots = unsafe { rusty_libc_core::ffi::slice_mut(p, n) };
    for s in slots.iter_mut() {
        s.write(T::default());
    }
    // SAFETY: every element was initialised just above; `MaybeUninit<T>` has the layout of `T`.
    Some(unsafe { rusty_libc_core::ffi::slice_mut(p.cast::<T>(), n) })
}

/// `v` moved into a malloc'd block that is never freed (list nodes, loaded catalogs), or None when memory is short
/// (`v` is dropped then).
pub(crate) fn leak<T>(v: T) -> Option<&'static mut T> {
    const { assert!(core::mem::align_of::<T>() <= 16) };
    let p = malloc(core::mem::size_of::<T>().max(1)).cast::<T>();
    if p.is_null() {
        return None;
    }
    // SAFETY: a fresh block big and aligned enough for `T`, never freed and ours alone (as uninitialised memory).
    let slot = unsafe { &mut *p.cast::<core::mem::MaybeUninit<T>>() };
    Some(slot.write(v))
}

/// A write-once reference to a value that lives for good: empty until [`Published::publish`] stores a `&'static T` (by one
/// compare-exchange, Release), and never changed or emptied after that. Readers get the reference back (Acquire), so lists
/// and caches of leaked nodes need no unsafe code of their own.
pub(crate) struct Published<T: Sync + 'static>(core::sync::atomic::AtomicPtr<T>);

impl<T: Sync + 'static> Published<T> {
    pub(crate) const fn empty() -> Self {
        Published(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()))
    }

    /// The published reference, None while empty.
    #[inline(always)]
    pub(crate) fn get(&self) -> Option<&'static T> {
        Self::as_ref(self.0.load(core::sync::atomic::Ordering::Acquire))
    }

    /// Publish `v` if still empty: Ok, or Err with the reference published first.
    #[inline]
    pub(crate) fn publish(&self, v: &'static T) -> Result<(), &'static T> {
        let p = core::ptr::from_ref(v).cast_mut();
        match self.0.compare_exchange(core::ptr::null_mut(), p, core::sync::atomic::Ordering::Release, core::sync::atomic::Ordering::Acquire) {
            Ok(_) => Ok(()),
            // (never null: a published value is never removed)
            Err(other) => Err(Self::as_ref(other).unwrap_or(v)),
        }
    }

    #[inline(always)]
    fn as_ref(p: *mut T) -> Option<&'static T> {
        // SAFETY: the word is null or was stored by `publish` from a `&'static T` (valid for the rest of the run, only read
        // through shared references: T is Sync); the Release store pairs with the caller's Acquire load or failed exchange,
        // so the value's initialisation is visible.
        unsafe { p.as_ref() }
    }
}

const PROT_READ: usize = 1;
const MAP_PRIVATE: usize = 2;
const O_RDONLY: i32 = 0;
const O_CLOEXEC: i32 = 0o2000000;

/// open(path, O_RDONLY | O_CLOEXEC). `path` ends with its NUL.
pub(crate) fn open_ro(path: &[u8]) -> Result<i32, rusty_libc_core::Errno> {
    assert_eq!(path.last(), Some(&0));
    // SAFETY: `path` is NUL-terminated (checked above).
    unsafe { rusty_libc_core::unistd::open(path.as_ptr().cast::<c_char>(), O_RDONLY | O_CLOEXEC, 0) }
}

/// mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0): the mapped address, or the error. `len` > 0.
pub(crate) fn mmap_ro(fd: i32, len: usize) -> Result<*const u8, rusty_libc_core::Errno> {
    // SAFETY: a new read-only private mapping chosen by the kernel touches no existing memory.
    let r = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, len, PROT_READ, MAP_PRIVATE, fd as usize, 0) };
    syscall::check(r).map(|a| a as *const u8)
}

/// Map `len` (> 0) bytes of `fd` read-only for the rest of the process: the mapping is never unmapped.
pub(crate) fn map_forever(fd: i32, len: usize) -> Option<&'static [u8]> {
    let p = mmap_ro(fd, len).ok()?;
    // SAFETY: `len` readable bytes at `p` (a fresh private read-only mapping) that stay mapped and unchanged for good:
    // nothing in the library unmaps it or writes to it.
    Some(unsafe { rusty_libc_core::ffi::bytes(p, len) })
}

/// The native-endian `u32` at `off` (any alignment); 0 when it does not fit in `b`.
#[inline(always)]
pub(crate) fn rd32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off.wrapping_add(4)) {
        Some(w) => u32::from_ne_bytes([w[0], w[1], w[2], w[3]]),
        None => 0,
    }
}

/// The NUL-terminated string at `off` of `b` without its NUL (up to the end of `b` if there is none); empty if `off` is
/// past the end.
#[inline]
pub(crate) fn cstr_at(b: &[u8], off: usize) -> &[u8] {
    let s = b.get(off..).unwrap_or(&[]);
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..n]
}
