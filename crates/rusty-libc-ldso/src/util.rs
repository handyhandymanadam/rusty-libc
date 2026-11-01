//! Memory functions the compiler calls, string helpers, message output and the loader's own allocator.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::sync_cell::SyncCell;
use crate::sys;
use core::fmt::Write;
use core::mem::MaybeUninit;

pub use crate::ffi::{cstr, cstr_eq, cstr_gnu_hash, streq};

// ---- mem functions (the crate is `no_builtins`, so these loops are not turned into calls to themselves) ----
// They keep their raw-pointer loops: a slice comparison or copy here would compile to a call of the function itself.

/// # Safety
/// C `memcpy`: `s` readable and `d` writable for `n` bytes, not overlapping.
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    // SAFETY: `rep movsb` copies `n` bytes from `s` to `d` (direction flag clear, as the ABI guarantees), which the caller
    // vouches for; the registers it changes are declared.
    unsafe {
        core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") d => _, inout("rsi") s => _, options(nostack, preserves_flags));
    }
    d
}

/// # Safety
/// C `memmove`: `s` readable and `d` writable for `n` bytes (they may overlap).
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    if (d as usize) <= (s as usize) || (d as usize) >= (s as usize) + n {
        // SAFETY: a forward copy is correct when the destination starts at or before the source, or after its end.
        return unsafe { memcpy(d, s, n) };
    }
    let mut i = n;
    while i > 0 {
        i -= 1;
        // SAFETY: i < n: inside both ranges (caller's contract); copying from the end down is correct for this overlap.
        let c = unsafe { *s.wrapping_add(i) };
        // SAFETY: as above.
        unsafe { *d.wrapping_add(i) = c };
    }
    d
}

/// # Safety
/// C `memset`: `d` writable for `n` bytes.
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: `rep stosb` stores `n` bytes at `d` (direction flag clear), which the caller vouches for.
    unsafe {
        core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") d => _, in("al") c as u8, options(nostack, preserves_flags));
    }
    d
}

/// # Safety
/// C `memcmp`: `a` and `b` readable for `n` bytes.
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: i < n (caller's contract).
        let x = unsafe { *a.wrapping_add(i) };
        // SAFETY: i < n (caller's contract).
        let y = unsafe { *b.wrapping_add(i) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

/// # Safety
/// As [`memcmp`].
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { memcmp(a, b, n) }
}

// ---- C strings ----

// The loader's string functions carry their C names, as glibc's ld.so's do (local symbols of its .symtab): valgrind looks
// strlen, strcmp and index up by name in the object whose soname is ld-linux-x86-64.so.2 and refuses to start without them
// (memcheck replaces them with its own versions; the crate is no_builtins, so these loops are not turned into calls to
// themselves).

/// # Safety
/// `s` points to a NUL-terminated string.
// byte pointers instead of void/char ones: the same C ABI as the runtime symbol core calls
#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    // SAFETY: forwarded contract.
    unsafe { crate::ffi::cstr_len(s) }
}

/// # Safety
/// `a` and `b` point to NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        // SAFETY: bytes 0..i of both strings were equal and not NUL, so byte i of each is readable.
        let x = unsafe { *a.wrapping_add(i) };
        // SAFETY: as above.
        let y = unsafe { *b.wrapping_add(i) };
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
        i += 1;
    }
}

/// # Safety
/// `s` points to a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *const u8 {
    let c = c as u8;
    let mut p = s;
    loop {
        // SAFETY: `p` is at or before the string's NUL (the loop stops there).
        let x = unsafe { *p };
        if x == c {
            return p;
        }
        if x == 0 {
            return core::ptr::null();
        }
        // SAFETY: `x` was not the NUL, so the next byte is still inside the string.
        p = unsafe { p.add(1) };
    }
}

/// # Safety
/// As [`strchr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn index(s: *const u8, c: i32) -> *const u8 {
    // SAFETY: forwarded contract.
    unsafe { strchr(s, c) }
}

/// A file-name buffer that is small and not zero-filled: the loader builds a few dozen bytes of it, and a 4 KB array on the
/// stack (zeroed or not, its start is written) costs a page fault or two. Bytes are appended (`push`, `extend`); only the
/// `len` bytes written are ever read. A name that does not fit the inline part moves to a longer buffer in permanent memory
/// (`reserve`: room for `need` bytes, NUL included, plus 64).
pub struct PathBuf {
    small: MaybeUninit<[u8; 384]>,
    big: *mut u8,
    cap: usize,
    len: usize,
}

impl Default for PathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl PathBuf {
    pub fn new() -> PathBuf {
        PathBuf { small: MaybeUninit::uninit(), big: core::ptr::null_mut(), cap: 384, len: 0 }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn base(&mut self) -> *mut u8 {
        if self.big.is_null() { self.small.as_mut_ptr() as *mut u8 } else { self.big }
    }

    /// The storage, `cap` bytes, of which the first `len` are initialised.
    fn storage(&mut self) -> &mut [MaybeUninit<u8>] {
        let (p, cap) = (self.base() as *mut MaybeUninit<u8>, self.cap);
        // SAFETY: `p` is the inline array (384 bytes) or a permanent block of `cap` bytes, owned by `self` and borrowed
        // exclusively with it; `MaybeUninit` needs no initialisation.
        unsafe { crate::ffi::slice_mut(p, cap) }
    }

    /// Room for `need` bytes (the NUL included), keeping what was written.
    pub fn reserve(&mut self, need: usize) {
        if need > self.cap {
            let nb = alloc_perm(need + 64, 1);
            let len = self.len;
            let old = self.base();
            // SAFETY: `old` holds `len` initialised bytes (len <= cap), `nb` is a fresh block of need + 64 > len bytes.
            unsafe { core::ptr::copy_nonoverlapping(old, nb, len) };
            self.big = nb;
            self.cap = need + 64;
        }
    }

    /// Forget everything after the first `n` bytes.
    pub fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    pub fn push(&mut self, c: u8) {
        if self.len + 1 > self.cap {
            self.reserve(self.len + 1);
        }
        let i = self.len;
        self.storage()[i] = MaybeUninit::new(c);
        self.len += 1;
    }

    pub fn extend(&mut self, s: &[u8]) {
        if self.len + s.len() > self.cap {
            self.reserve(self.len + s.len());
        }
        let i = self.len;
        for (d, &c) in self.storage()[i..i + s.len()].iter_mut().zip(s) {
            *d = MaybeUninit::new(c);
        }
        self.len += s.len();
    }

    /// What was written.
    pub fn bytes(&mut self) -> &[u8] {
        let len = self.len;
        let p = self.base() as *const u8;
        // SAFETY: the first `len` bytes of the storage were written by `push`/`extend`/`readlink`; the borrow of `self` keeps
        // them unchanged.
        unsafe { crate::ffi::slice(p, len) }
    }

    /// The bytes written, as a C string: a NUL is stored after them. A byte 0 among them ends the string there (as the
    /// kernel would read it).
    pub fn as_cstr(&mut self) -> &core::ffi::CStr {
        if self.len + 1 > self.cap {
            self.reserve(self.len + 1);
        }
        let i = self.len;
        self.storage()[i] = MaybeUninit::new(0);
        let len = self.len;
        let p = self.base() as *const u8;
        // SAFETY: bytes 0..=len are initialised (written, then the NUL just stored).
        let with_nul = unsafe { crate::ffi::slice(p, len + 1) };
        core::ffi::CStr::from_bytes_until_nul(with_nul).unwrap_or(c"")
    }

    /// The address of the first byte (what `as_cstr` returns points there).
    pub fn as_ptr(&mut self) -> *const u8 {
        self.base()
    }

    /// readlink(path) into the free room after what was written (all of it but one byte); the bytes the kernel wrote count as
    /// written. The kernel's result (a length or a negative errno).
    pub fn readlink(&mut self, path: &core::ffi::CStr) -> isize {
        let (i, cap) = (self.len, self.cap);
        let n = sys::readlink(path, &mut self.storage()[i..cap - 1]);
        if n > 0 {
            self.len += n as usize;
        }
        n
    }
}

/// A NUL-terminated copy of `s` in permanent memory (a byte 0 inside `s` ends the string there, as C would read it).
pub fn dup(s: &[u8]) -> &'static core::ffi::CStr {
    let d = perm_bytes(s.len() + 1);
    d[..s.len()].copy_from_slice(s);
    d[s.len()] = 0;
    let d: &'static [u8] = d;
    core::ffi::CStr::from_bytes_until_nul(d).unwrap_or(c"")
}

/// `len` zeroed bytes of permanent memory, the caller's alone.
pub fn perm_bytes(len: usize) -> &'static mut [u8] {
    let p = alloc_perm(len, 1);
    // SAFETY: `p` is a fresh, zeroed, exclusively owned block of `len` bytes (`alloc_perm` gives at least one byte), never
    // freed.
    unsafe { crate::ffi::slice_mut(p, len) }
}

/// `n` empty map slots (zeroed = `None`) of permanent memory, the caller's alone: the arrays of a scope, an extra scope or
/// a reldeps list (`Option<Map>` has the layout of a `*mut LinkMap`).
pub fn perm_maps(n: usize) -> &'static mut [Option<crate::map::Map>] {
    let p = alloc_perm(n * core::mem::size_of::<Option<crate::map::Map>>(), 8) as *mut Option<crate::map::Map>;
    // SAFETY: a fresh, zeroed, exclusively owned block of `n` pointer-sized, 8-aligned slots, never freed; all-zero is `None`.
    unsafe { crate::ffi::slice_mut(p, n) }
}

/// A zeroed work area of private anonymous memory, unmapped when dropped: the big arrays of the loader's rare paths (a
/// closure of hundreds of maps, a 4 KB path) live here instead of on the stack of whatever thread reaches them, which may
/// have a small stack (FIXLIST #79). A mapping instead of the loader's heap: no lock is taken (the heap's lock is not held by
/// any of these paths' callers either, but a mapping keeps them independent of it), and the pages go back at once.
pub struct Scratch {
    addr: usize,
    len: usize,
    /// Made for map slots: only `maps` hands it out (so its bytes are always zero or written as `Option<Map>`).
    for_maps: bool,
}

impl Scratch {
    /// `len` zeroed bytes (rounded up to whole pages); None when the kernel has no memory.
    pub fn new(len: usize) -> Option<Scratch> {
        let len = (len.max(1) + sys::PAGE - 1) & !(sys::PAGE - 1);
        let r = sys::mmap_new(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
        if r < 0 && r > -4096 { None } else { Some(Scratch { addr: r as usize, len, for_maps: false }) }
    }

    /// For `n` map slots (all `None`).
    pub fn for_maps(n: usize) -> Option<Scratch> {
        let mut s = Scratch::new(n * core::mem::size_of::<Option<crate::map::Map>>())?;
        s.for_maps = true;
        Some(s)
    }

    /// For `n` map slots, or the loader's "cannot allocate memory" exit (as its heap does when the kernel has none).
    pub fn for_maps_or_die(n: usize) -> Scratch {
        match Scratch::for_maps(n) {
            Some(s) => s,
            None => crate::die(format_args!("cannot allocate memory")),
        }
    }

    /// The whole area as bytes.
    pub fn bytes(&mut self) -> &mut [u8] {
        assert!(!self.for_maps);
        // SAFETY: `len` bytes mapped readable and writable by `new`, owned by this value until drop; the borrow of `self`
        // keeps every other access out while the slice lives.
        unsafe { crate::ffi::slice_mut(self.addr as *mut u8, self.len) }
    }

    /// The first `n` map slots (`None` until the caller sets them; all-zero is `None`). Panics if they do not fit.
    pub fn maps<const N: usize>(&mut self) -> &mut [Option<crate::map::Map>; N] {
        assert!(self.for_maps && N * core::mem::size_of::<Option<crate::map::Map>>() <= self.len);
        // SAFETY: the mapping is page-aligned, holds at least N pointer-sized slots (checked above) whose bytes are zero
        // (`None`) or were written as `Option<Map>` through an earlier borrow of this method (an area made by `for_maps`,
        // which `bytes` refuses), and is owned by this value; the borrow of `self` keeps every other access out.
        unsafe { &mut *(self.addr as *mut [Option<crate::map::Map>; N]) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // SAFETY: the mapping made by `new`; nothing borrows it any more (every slice borrowed `self`).
        unsafe { sys::munmap(self.addr, self.len) };
    }
}

// ---- output ----

/// Formatting into a fixed buffer, written to a file descriptor when full or dropped.
pub struct Out {
    fd: i32,
    buf: [u8; 512],
    len: usize,
}

impl Out {
    pub fn new(fd: i32) -> Out {
        Out { fd, buf: [0; 512], len: 0 }
    }
    pub fn flush(&mut self) {
        if self.len > 0 {
            sys::write(self.fd, &self.buf[..self.len]);
            self.len = 0;
        }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        for &c in b {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = c;
            self.len += 1;
        }
    }
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.bytes(s.as_bytes());
        Ok(())
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.flush();
    }
}

/// `format_args`-style print to standard error.
#[macro_export]
macro_rules! eprint {
    ($($t:tt)*) => {{
        use core::fmt::Write as _;
        let mut o = $crate::util::Out::new(2);
        let _ = write!(o, $($t)*);
    }};
}

/// A `&[u8]` (not necessarily UTF-8) as a Display value.
pub struct Bytes<'a>(pub &'a [u8]);
impl core::fmt::Display for Bytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &c in self.0 {
            f.write_char(if c.is_ascii_graphic() || c == b' ' { c as char } else { '?' })?;
        }
        Ok(())
    }
}

// ---- allocator ----
//
// Permanent allocations (link maps, strings) are bumped out of anonymous mappings and never freed. Blocks that do
// get freed (a thread's dtv, dynamically allocated TLS blocks) come in power-of-two size classes with free lists.

static ALLOC_LOCK: Lock = Lock::new();

/// Called by `tls::__libc_ldso_fork_child` (see there).
pub(crate) fn fork_child_reset() {
    ALLOC_LOCK.reset();
}
const CHUNK: usize = 256 * 1024;
const ARENA: usize = 64 * 1024;

/// The loader's own memory: the permanent bump chunk, the free lists of the freeable blocks by size class, the mappings and
/// arenas those blocks come from (`own`, for `is_own`) and the current arena. Only touched under `ALLOC_LOCK`.
/// (The words every allocation touches come first, the 4 KB `own` table last: one page for a typical program's use.)
#[repr(C)]
struct Heap {
    bump: usize,
    bump_end: usize,
    bbump: usize,
    bend: usize,
    nown: usize,
    free: [usize; 48],
    own: [(usize, usize); 256],
}
static HEAP: SyncCell<Heap> = SyncCell::new(Heap { bump: 0, bump_end: 0, bbump: 0, bend: 0, nown: 0, free: [0; 48], own: [(0, 0); 256] });

/// Run `f` on the heap with `ALLOC_LOCK` held.
fn with_heap<R>(f: impl FnOnce(&mut Heap) -> R) -> R {
    ALLOC_LOCK.lock();
    // SAFETY: every access to HEAP is here, under ALLOC_LOCK; the lock is recursive, but nothing `f` calls (the heap's own
    // methods, `map_anon`, `die`) comes back here, so the `&mut` is the only reference for the call.
    let r = unsafe { HEAP.with_unsync(f) };
    ALLOC_LOCK.unlock();
    r
}

// After relocation the loader allocates the way glibc's does (`__rtld_malloc_init_real`): through the `malloc`, `calloc` and
// `free` the program's global scope binds (an interposed allocator included). The names are looked up when the first such
// allocation happens (a program that never starts a thread or loads a library does not pay for it). Blocks the loader
// keeps for itself (its first thread's, the error buffers) come from its own mappings (`own`); `free_blk` tells them apart
// from the program's by address.
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
static RT_MALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_FREE: AtomicUsize = AtomicUsize::new(0);
static RT_CALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_ARMED: AtomicBool = AtomicBool::new(false);
static RT_TRIED: AtomicBool = AtomicBool::new(false);

/// Relocation is done: from now on allocations go to the program's allocator.
pub fn rtld_malloc_arm() {
    RT_ARMED.store(true, Release);
}

/// The program's `malloc`, `calloc` and `free` (`calloc` is published last: whoever sees it sees the others).
///
/// # Safety
/// The three are the addresses of functions with the C signatures of malloc, calloc and free (callable from any thread from
/// now on).
pub unsafe fn rtld_malloc_init(malloc: usize, calloc: usize, free: usize) {
    RT_MALLOC.store(malloc, Release);
    RT_FREE.store(free, Release);
    RT_CALLOC.store(calloc, Release);
}

fn rt_calloc() -> usize {
    let c = RT_CALLOC.load(Acquire);
    if c != 0 || !RT_ARMED.load(Acquire) || RT_TRIED.swap(true, AcqRel) {
        return c;
    }
    // SAFETY: relocation is done (RT_ARMED), so the global scope's malloc, calloc and free can be looked up and called.
    unsafe { crate::bind_rtld_malloc() };
    RT_CALLOC.load(Acquire)
}

type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut u8;
type MallocFn = unsafe extern "C" fn(usize) -> *mut u8;
type FreeFn = unsafe extern "C" fn(*mut u8);

/// A block from the program's allocator (`rt_calloc()` returned non-zero, so the three functions are published).
fn ext_alloc(size: usize, zero: bool) -> *mut u8 {
    let p = if zero {
        // SAFETY: RT_CALLOC holds the address of the program's calloc (`rtld_malloc_init`'s contract), non-zero here.
        let f: CallocFn = unsafe { core::mem::transmute(RT_CALLOC.load(Acquire)) };
        // SAFETY: calloc takes plain values.
        unsafe { f(1, size) }
    } else {
        // SAFETY: RT_MALLOC holds the address of the program's malloc, published before RT_CALLOC.
        let f: MallocFn = unsafe { core::mem::transmute(RT_MALLOC.load(Acquire)) };
        // SAFETY: malloc takes a plain value.
        unsafe { f(size) }
    };
    if p.is_null() {
        crate::die(format_args!("cannot allocate memory"));
    }
    p
}

/// A block for a thread (its dtv, a dynamic TLS block): the program's `calloc` (`zero`) or `malloc` once the loader is set
/// up, else the loader's own zeroed block. The program's allocator gives 16-byte alignment; a caller that wants more
/// allocates `align` extra and rounds up. Give it back with `free_blk`.
pub fn alloc_ext(size: usize, align: usize, zero: bool) -> *mut u8 {
    if rt_calloc() != 0 { ext_alloc(size, zero) } else { alloc_blk(size, align) }
}

/// Zeroed memory for something that is never freed (a link map): the program's `calloc` once the loader is set up.
pub fn alloc_calloc(size: usize, align: usize) -> *mut u8 {
    if align <= 16 && rt_calloc() != 0 { ext_alloc(size, true) } else { alloc_perm(size, align) }
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

fn map_anon(len: usize) -> usize {
    let r = sys::mmap_new(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
    if r < 0 && r > -4096 {
        crate::die(format_args!("cannot allocate memory"));
    }
    r as usize
}

impl Heap {
    /// A mapping for the loader's own freeable blocks, remembered for `is_own`.
    fn map_own(&mut self, len: usize) -> usize {
        let r = map_anon(len);
        if self.nown == self.own.len() {
            crate::die(format_args!("cannot allocate memory"));
        }
        self.own[self.nown] = (r, len);
        self.nown += 1;
        r
    }

    fn alloc_perm(&mut self, size: usize, align: usize) -> *mut u8 {
        let size = size.max(1);
        let mut p = align_up(self.bump, align);
        if p + size > self.bump_end {
            if size + align > CHUNK / 4 {
                return align_up(map_anon(size + align), align) as *mut u8;
            }
            self.bump = map_anon(CHUNK);
            self.bump_end = self.bump + CHUNK;
            p = align_up(self.bump, align);
        }
        self.bump = p + size;
        p as *mut u8
    }

    fn alloc_blk(&mut self, size: usize, align: usize) -> *mut u8 {
        let c = class_of(size, align);
        let head = self.free[c];
        if head != 0 {
            // SAFETY: `head` is a block of class `c` that `free_blk` put on the list (its first word links the next one);
            // free blocks belong to the heap alone.
            self.free[c] = unsafe { *(head as *const usize) };
            // SAFETY: the block is `1 << c` bytes, now handed out to the caller.
            unsafe { core::ptr::write_bytes(head as *mut u8, 0, 1usize << c) };
            return head as *mut u8;
        }
        let n = 1usize << c;
        if n >= CHUNK / 4 {
            return align_up(self.map_own(n + align), align) as *mut u8;
        }
        let a = n.min(4096).max(align);
        let mut p = align_up(self.bbump, a);
        if p + n > self.bend {
            // an arena cut out of the permanent chunk (no mapping of its own: a system call costs more than a hello program's
            // whole use of it)
            if self.nown == self.own.len() {
                crate::die(format_args!("cannot allocate memory"));
            }
            self.bbump = self.alloc_perm(ARENA, 64) as usize;
            self.bend = self.bbump + ARENA;
            self.own[self.nown] = (self.bbump, ARENA);
            self.nown += 1;
            p = align_up(self.bbump, a);
        }
        self.bbump = p + n;
        p as *mut u8
    }
}

fn is_own(p: usize) -> bool {
    with_heap(|h| (0..h.nown).any(|i| p >= h.own[i].0 && p < h.own[i].0 + h.own[i].1))
}

/// Zeroed permanent memory.
pub fn alloc_perm(size: usize, align: usize) -> *mut u8 {
    with_heap(|h| h.alloc_perm(size, align))
}

fn class_of(size: usize, align: usize) -> usize {
    let n = size.max(align).max(16).next_power_of_two();
    n.trailing_zeros() as usize
}

/// Zeroed memory from the loader's own mappings that can be given back with `free_blk` (same `size` and `align`).
pub fn alloc_blk(size: usize, align: usize) -> *mut u8 {
    with_heap(|h| h.alloc_blk(size, align))
}

/// Give back a block of `alloc_ext` or `alloc_blk` (NULL: nothing).
///
/// # Safety
/// `p` is NULL or came from `alloc_ext`/`alloc_blk` with this `size` and `align`, and is not used afterwards.
pub unsafe fn free_blk(p: *mut u8, size: usize, align: usize) {
    if p.is_null() {
        return;
    }
    let rf = RT_FREE.load(Acquire);
    if rf != 0 && !is_own(p as usize) {
        // SAFETY: RT_FREE holds the address of the program's free (`rtld_malloc_init`'s contract).
        let f: FreeFn = unsafe { core::mem::transmute(rf) };
        // SAFETY: a block of the program's allocator (not one of ours), given back once (caller's contract).
        unsafe { f(p) };
        return;
    }
    let c = class_of(size, align);
    with_heap(|h| {
        // SAFETY: a block of class `c` of our own (caller's contract), at least 16 bytes and 16-aligned: its first word
        // becomes the list link.
        unsafe { *(p as *mut usize) = h.free[c] };
        h.free[c] = p as usize;
    });
}

// ---- the loader lock (recursive; a constructor may call dlopen) ----

pub struct Lock {
    owner: AtomicUsize,
    waiters: core::sync::atomic::AtomicU32,
    /// The holder's nesting depth: only the holder reads or writes it (relaxed accesses suffice).
    depth: AtomicUsize,
}

impl Default for Lock {
    fn default() -> Self {
        Self::new()
    }
}

impl Lock {
    pub const fn new() -> Lock {
        Lock { owner: AtomicUsize::new(0), waiters: core::sync::atomic::AtomicU32::new(0), depth: AtomicUsize::new(0) }
    }
    fn me() -> usize {
        if crate::tls::ready() { sys::thread_pointer() } else { 1 }
    }
    pub fn lock(&self) {
        let me = Self::me();
        if self.owner.load(Relaxed) == me {
            self.depth.store(self.depth.load(Relaxed) + 1, Relaxed);
            return;
        }
        if self.owner.compare_exchange(0, me, Acquire, Relaxed).is_err() {
            self.waiters.fetch_add(1, SeqCst);
            while self.owner.compare_exchange(0, me, Acquire, Relaxed).is_err() {
                // contended: sleep on the owner word (futex wait, private; the low 32 bits are compared)
                let cur = self.owner.load(Relaxed);
                if cur != 0 {
                    sys::futex_wait(&self.owner, cur as u32);
                }
            }
            self.waiters.fetch_sub(1, SeqCst);
        }
        self.depth.store(1, Relaxed);
    }
    /// Forget the holder: in a forked child, where the thread that held the lock does not exist (call it only while no other
    /// thread can use the lock).
    pub fn reset(&self) {
        self.depth.store(0, Relaxed);
        self.owner.store(0, Relaxed);
        self.waiters.store(0, Relaxed);
    }
    pub fn unlock(&self) {
        let d = self.depth.load(Relaxed) - 1;
        self.depth.store(d, Relaxed);
        if d == 0 {
            self.owner.store(0, SeqCst);
            if self.waiters.load(SeqCst) != 0 {
                sys::futex_wake(&self.owner, 1);
            }
        }
    }
}
