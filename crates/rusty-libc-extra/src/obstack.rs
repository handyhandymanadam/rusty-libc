//! obstack.h: stacks of objects that grow in chunks. The macros of `<obstack.h>` work on `struct obstack`
//! directly, so [`Obstack`] has glibc's x86-64 layout (88 bytes, chunks that start with `limit` and
//! `prev` and keep their contents at offset 16); the functions here are what the macros call when a
//! chunk is full: `_obstack_begin`, `_obstack_begin_1`, `_obstack_newchunk`, `obstack_free`,
//! `_obstack_memory_used`, `_obstack_allocated_p`, plus `obstack_printf` and `obstack_vprintf`.
//!
//! A failed chunk allocation calls `obstack_alloc_failed_handler`; the default prints
//! "memory exhausted" to standard error and exits with `obstack_exit_failure`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::fmt::Sink;

/// `struct _obstack_chunk`: the header at the front of every chunk.
#[repr(C)]
pub struct ObstackChunk {
    pub limit: *mut c_char,
    pub prev: *mut ObstackChunk,
    pub contents: [c_char; 4],
}

type ChunkFn = unsafe extern "C" fn(*mut c_void, c_long) -> *mut ObstackChunk;
type FreeFn = unsafe extern "C" fn(*mut c_void, *mut ObstackChunk);

const USE_EXTRA_ARG: c_uint = 1;
const MAYBE_EMPTY_OBJECT: c_uint = 2;
const ALLOC_FAILED: c_uint = 4;

/// `struct obstack` (88 bytes). The three bit-fields share one word: bit 0 `use_extra_arg`, bit 1
/// `maybe_empty_object`, bit 2 `alloc_failed`.
#[repr(C)]
pub struct Obstack {
    pub chunk_size: c_long,
    pub chunk: *mut ObstackChunk,
    pub object_base: *mut c_char,
    pub next_free: *mut c_char,
    pub chunk_limit: *mut c_char,
    /// the `temp` union of the macros (a pointer-sized integer or pointer)
    pub temp: usize,
    pub alignment_mask: c_int,
    pub chunkfun: Option<ChunkFn>,
    pub freefun: Option<FreeFn>,
    pub extra_arg: *mut c_void,
    pub flags: c_uint,
}

const _: () = assert!(size_of::<Obstack>() == 88);
const _: () = assert!(core::mem::offset_of!(Obstack, alignment_mask) == 48);
const _: () = assert!(core::mem::offset_of!(Obstack, chunkfun) == 56);
const _: () = assert!(core::mem::offset_of!(Obstack, flags) == 80);
const _: () = assert!(core::mem::offset_of!(ObstackChunk, contents) == 16);

/// Called when a chunk cannot be allocated; it must not return (exit, abort or longjmp). A C data symbol (`SyncCell` is
/// `repr(transparent)`: the same 8 bytes as glibc's function pointer). Rule (glibc's, a plain global): the program sets it
/// before obstacks are used concurrently; the library only reads it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static obstack_alloc_failed_handler: SyncCell<Option<unsafe extern "C" fn()>> = SyncCell::new(Some(print_and_abort));

/// The exit status of the default handler. Same rule as `obstack_alloc_failed_handler`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static obstack_exit_failure: SyncCell<c_int> = SyncCell::new(1);

/// Old binaries import this variable (it was used by non-GNU-C macros long ago). The library never touches it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static _obstack: SyncCell<*mut Obstack> = SyncCell::new(null_mut());

unsafe extern "C" fn print_and_abort() {
    // glibc: fprintf(stderr, "%s\n", _("memory exhausted"))
    let t = rusty_libc_core::i18n::tr(c"memory exhausted").to_bytes();
    let mut msg = [0u8; 256];
    let k = t.len().min(msg.len() - 1);
    msg[..k].copy_from_slice(&t[..k]);
    msg[k] = b'\n';
    // SAFETY: a write system call from a local buffer of `k + 1` bytes.
    unsafe { rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, 2, msg.as_ptr() as usize, k + 1) };
    // SAFETY: only read; the program sets it before (the variable's rule).
    rusty_libc_core::process::exit(unsafe { obstack_exit_failure.read() })
}

fn alloc_failed() {
    // SAFETY: only read; the program sets it before (the variable's rule).
    if let Some(h) = unsafe { obstack_alloc_failed_handler.read() } {
        // SAFETY: the handler is the program's (or the default) failure function, called with no arguments as glibc does.
        unsafe { h() };
    }
}

const DEFAULT_ALIGNMENT: c_int = 16;
const DEFAULT_ROUNDING: c_int = 16;

/// `p` rounded up to a multiple of `mask + 1` (address arithmetic only; the pointer keeps `p`'s provenance).
fn ptr_align(p: *mut c_char, mask: c_int) -> *mut c_char {
    let a = mask as isize as usize;
    p.wrapping_add(((p as usize).wrapping_add(a) & !a).wrapping_sub(p as usize))
}

/// `b - a` in bytes, computed on the addresses (both point into one chunk: `offset_from` without its precondition).
#[inline(always)]
fn diff(b: *const c_char, a: *const c_char) -> isize {
    (b.addr() as isize).wrapping_sub(a.addr() as isize)
}

/// The address of a chunk's contents.
#[inline(always)]
fn contents(chunk: *mut ObstackChunk) -> *mut c_char {
    chunk.cast::<c_char>().wrapping_add(core::mem::offset_of!(ObstackChunk, contents))
}

/// A chunk header.
///
/// # Safety
/// `chunk` is a live chunk of an obstack (allocated by its chunkfun, at least the 16-byte header), not referenced
/// elsewhere while the result lives.
#[inline(always)]
unsafe fn chunk_mut<'a>(chunk: *mut ObstackChunk) -> &'a mut ObstackChunk {
    // SAFETY: forwarded contract.
    unsafe { &mut *chunk }
}

fn call_chunkfun(h: &Obstack, size: c_long) -> *mut ObstackChunk {
    let f = h.chunkfun.unwrap();
    if h.flags & USE_EXTRA_ARG != 0 {
        // SAFETY: the obstack's allocator, called as `chunkfun(extra_arg, size)` because it was set up with an extra argument.
        unsafe { f(h.extra_arg, size) }
    } else {
        // SAFETY: an obstack begun without an extra argument holds a one-argument allocator in this field (glibc's union).
        let plain: unsafe extern "C" fn(c_long) -> *mut ObstackChunk = unsafe { core::mem::transmute(f) };
        // SAFETY: the obstack's allocator with its own signature.
        unsafe { plain(size) }
    }
}

/// Free a chunk with the obstack's deallocator.
///
/// # Safety
/// `chunk` is a chunk of `h` that is no longer used.
unsafe fn call_freefun(h: &Obstack, chunk: *mut ObstackChunk) {
    let f = h.freefun.unwrap();
    if h.flags & USE_EXTRA_ARG != 0 {
        // SAFETY: the obstack's deallocator on one of its chunks (contract), with the extra argument.
        unsafe { f(h.extra_arg, chunk) }
    } else {
        // SAFETY: an obstack begun without an extra argument holds a one-argument deallocator in this field.
        let plain: unsafe extern "C" fn(*mut ObstackChunk) = unsafe { core::mem::transmute(f) };
        // SAFETY: the obstack's deallocator with its own signature, on one of its chunks (contract).
        unsafe { plain(chunk) }
    }
}

/// The size of the first chunk when none is given: what a 4096-byte malloc block holds.
fn default_size() -> c_int {
    let round = |x: c_int| (x + DEFAULT_ROUNDING - 1) & !(DEFAULT_ROUNDING - 1);
    4096 - round(round(12) + 4)
}

/// The obstack the C caller passed.
///
/// # Safety
/// `h` points to a `struct obstack` not accessed elsewhere during the call.
#[inline(always)]
unsafe fn obstack<'a>(h: *mut Obstack) -> &'a mut Obstack {
    // SAFETY: forwarded contract.
    unsafe { &mut *h }
}

/// Start `o` (both `_obstack_begin` forms).
///
/// # Safety
/// `chunkfun`/`freefun` are functions of the signature that `extra` selects (one or two arguments), or 0 for none.
unsafe fn begin_common(o: &mut Obstack, size: c_int, alignment: c_int, chunkfun: usize, freefun: usize, extra: Option<*mut c_void>) -> c_int {
    let alignment = if alignment == 0 { DEFAULT_ALIGNMENT } else { alignment };
    let size = if size == 0 { default_size() } else { size };
    // SAFETY: a function address (glibc stores either signature in this field; calls go through call_chunkfun).
    o.chunkfun = Some(unsafe { core::mem::transmute::<usize, ChunkFn>(chunkfun) });
    // SAFETY: as above, for the deallocator.
    o.freefun = Some(unsafe { core::mem::transmute::<usize, FreeFn>(freefun) });
    o.chunk_size = size as c_long;
    o.alignment_mask = alignment - 1;
    match extra {
        Some(arg) => {
            o.extra_arg = arg;
            o.flags |= USE_EXTRA_ARG;
        }
        None => o.flags &= !USE_EXTRA_ARG,
    }
    let chunk = call_chunkfun(o, o.chunk_size);
    o.chunk = chunk;
    if chunk.is_null() {
        alloc_failed();
    }
    // the first object starts at the first aligned address inside the contents
    o.object_base = ptr_align(contents(chunk), alignment - 1);
    o.next_free = o.object_base;
    o.chunk_limit = chunk.cast::<c_char>().wrapping_add(o.chunk_size as usize);
    // SAFETY: a fresh chunk of `chunk_size` bytes from the allocator (the failure handler does not return).
    let c = unsafe { chunk_mut(chunk) };
    c.limit = o.chunk_limit;
    c.prev = null_mut();
    // the initial chunk holds no empty object
    o.flags &= !MAYBE_EMPTY_OBJECT;
    o.flags &= !ALLOC_FAILED;
    1
}

/// _obstack_begin: prepare `h` with chunk size `size` (0: about 4 KB), object alignment `alignment`
/// (0: 16) and the chunk allocator and deallocator. Always returns 1 (a failed allocation goes to the
/// failure handler).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    // SAFETY: one-argument functions with `extra` None.
    unsafe { begin_common(o, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), None) }
}

/// _obstack_begin_1: like `_obstack_begin`; the allocator and deallocator also take `arg` first.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin_1(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(*mut c_void, c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>, arg: *mut c_void) -> c_int {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    // SAFETY: two-argument functions with `extra` Some.
    unsafe { begin_common(o, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), Some(arg)) }
}

/// The core of `_obstack_newchunk` (hot: every grow past the end of a chunk lands here; the copy stays one
/// `copy_nonoverlapping`).
///
/// # Safety
/// `o` is a started obstack whose fields describe its current chunk and object.
unsafe fn newchunk(o: &mut Obstack, length: c_int) {
    let old_chunk = o.chunk;
    let obj_size = diff(o.next_free, o.object_base) as c_long;
    let mut new_size = (obj_size + length as c_long) + (obj_size >> 3) + o.alignment_mask as c_long + 100;
    if new_size < o.chunk_size {
        new_size = o.chunk_size;
    }
    let new_chunk = call_chunkfun(o, new_size);
    if new_chunk.is_null() {
        alloc_failed();
    }
    o.chunk = new_chunk;
    o.chunk_limit = new_chunk.cast::<c_char>().wrapping_add(new_size as usize);
    {
        // SAFETY: a fresh chunk of `new_size` bytes from the allocator (the failure handler does not return).
        let c = unsafe { chunk_mut(new_chunk) };
        c.prev = old_chunk;
        c.limit = o.chunk_limit;
    }
    let object_base = ptr_align(contents(new_chunk), o.alignment_mask);
    // SAFETY: the object (`obj_size` bytes at object_base) lies in the old chunk; the new chunk has room for it after the
    // aligned start (new_size covers obj_size + alignment); two different allocations.
    unsafe { core::ptr::copy_nonoverlapping(o.object_base, object_base, obj_size as usize) };
    // if the object just copied was all there was in the old chunk, free that chunk
    // (not when it might hold an empty object)
    if o.flags & MAYBE_EMPTY_OBJECT == 0 && o.object_base == ptr_align(contents(old_chunk), o.alignment_mask) {
        // SAFETY: the old chunk is a live chunk of this obstack.
        let prev = unsafe { chunk_mut(old_chunk) }.prev;
        // SAFETY: the new chunk, as above.
        unsafe { chunk_mut(new_chunk) }.prev = prev;
        // SAFETY: the old chunk held only the object, which was copied out; nothing refers to it any more.
        unsafe { call_freefun(o, old_chunk) };
    }
    o.object_base = object_base;
    o.next_free = o.object_base.wrapping_add(obj_size as usize);
    // the new chunk holds no empty object yet
    o.flags &= !MAYBE_EMPTY_OBJECT;
}

/// _obstack_newchunk: make room for `length` more bytes: a new, bigger chunk takes over the object
/// being built (and the old chunk is freed when that object was all it held).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_newchunk(h: *mut Obstack, length: c_int) {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    // SAFETY: the caller's obstack is started (the macros call this only then).
    unsafe { newchunk(o, length) }
}

/// The chunk of `lp`'s list that holds `obj` (glibc's test: `lp < obj <= limit`), or NULL; `on_skip` sees every chunk
/// passed over (obstack_free frees them).
///
/// # Safety
/// `lp` is NULL or the head of a valid chunk list; `on_skip` may free the chunk it gets (its `prev` is read before).
unsafe fn find_chunk(mut lp: *mut ObstackChunk, obj: *mut c_void, mut on_skip: impl FnMut(*mut ObstackChunk)) -> *mut ObstackChunk {
    loop {
        if lp.is_null() {
            return lp;
        }
        // SAFETY: a non-NULL chunk of the list (contract).
        let c = unsafe { chunk_mut(lp) };
        // >= because an object cannot start exactly at the beginning of a chunk, but an empty one can
        // sit exactly at the end of the neighbouring chunk
        if !(lp as *mut c_void >= obj || (c.limit as *mut c_void) < obj) {
            return lp;
        }
        let plp = c.prev;
        on_skip(lp);
        lp = plp;
    }
}

/// _obstack_allocated_p: whether `obj` was allocated from `h` (a debugging aid).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_allocated_p(h: *mut Obstack, obj: *mut c_void) -> c_int {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    // SAFETY: a started obstack's chunk list.
    (!unsafe { find_chunk(o.chunk, obj, |_| {}) }.is_null()) as c_int
}

/// obstack_free: free `obj` and everything allocated after it; NULL frees everything (the first chunk
/// stays: the obstack remains usable). An object that is in no chunk aborts the program.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_free(h: *mut Obstack, obj: *mut c_void) {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    let mut skipped = false;
    let skip = |c: *mut ObstackChunk| {
        // SAFETY: a chunk above `obj`: everything in it was allocated after `obj`, so it is freed (its `prev` was read).
        unsafe { call_freefun(o, c) };
        skipped = true;
    };
    // SAFETY: a started obstack's chunk list.
    let lp = unsafe { find_chunk(o.chunk, obj, skip) };
    if skipped {
        // after switching chunks it is unknown whether the new current chunk holds an empty object
        o.flags |= MAYBE_EMPTY_OBJECT;
    }
    if !lp.is_null() {
        o.next_free = obj as *mut c_char;
        o.object_base = obj as *mut c_char;
        // SAFETY: `lp` is a live chunk of the list (find_chunk stopped at it).
        o.chunk_limit = unsafe { chunk_mut(lp) }.limit;
        o.chunk = lp;
    } else if !obj.is_null() {
        // obj is not in any of the chunks
        rusty_libc_core::process::abort();
    }
}

/// `_obstack_free`: the same function under its old name.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_free(h: *mut Obstack, obj: *mut c_void) {
    // SAFETY: forwarded contract.
    unsafe { obstack_free(h, obj) }
}

/// _obstack_memory_used: the bytes in all chunks (header included).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_memory_used(h: *mut Obstack) -> c_int {
    // SAFETY: `h` is the caller's obstack.
    let o = unsafe { obstack(h) };
    let mut n: c_int = 0;
    let mut lp = o.chunk;
    while !lp.is_null() {
        // SAFETY: a chunk of a started obstack's list.
        let c = unsafe { chunk_mut(lp) };
        n = n.wrapping_add(diff(c.limit, lp.cast::<c_char>()) as c_int);
        lp = c.prev;
    }
    n
}

// ------------------------------------------------------------------ the Rust API

/// The operations of the `<obstack.h>` macros as methods (the same arithmetic on the same fields, so an
/// obstack can be driven from Rust and from C macros alike).
impl Obstack {
    /// A zeroed structure, to be started with [`Obstack::init`].
    pub const fn zeroed() -> Obstack {
        Obstack { chunk_size: 0, chunk: null_mut(), object_base: null_mut(), next_free: null_mut(), chunk_limit: null_mut(), temp: 0, alignment_mask: 0, chunkfun: None, freefun: None, extra_arg: null_mut(), flags: 0 }
    }

    /// Start the obstack (`obstack_specify_allocation`): chunk size `size` (0: about 4 KB), alignment
    /// (0: 16), the allocator and the deallocator of chunks.
    ///
    /// # Safety
    /// The functions must allocate and free memory properly; the obstack must not move afterwards.
    pub unsafe fn init(&mut self, size: c_int, alignment: c_int, chunkfun: unsafe extern "C" fn(c_long) -> *mut c_void, freefun: unsafe extern "C" fn(*mut c_void)) {
        // SAFETY: one-argument functions with no extra argument (caller's contract on what they do).
        unsafe { begin_common(self, size, alignment, chunkfun as usize, freefun as usize, None) };
    }

    /// Bytes of the object being built.
    pub fn object_size(&self) -> usize {
        diff(self.next_free, self.object_base) as usize
    }

    /// Bytes that fit in the current chunk before it must be replaced.
    pub fn room(&self) -> usize {
        diff(self.chunk_limit, self.next_free) as usize
    }

    /// Add bytes to the object being built (obstack_grow).
    ///
    /// # Safety
    /// The obstack must be started.
    pub unsafe fn grow(&mut self, data: &[u8]) {
        if self.room() < data.len() {
            // SAFETY: started (contract).
            unsafe { newchunk(self, data.len() as c_int) };
        }
        // SAFETY: the current chunk has at least `data.len()` bytes of room at next_free (checked or made above).
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.next_free as *mut u8, data.len()) };
        self.next_free = self.next_free.wrapping_add(data.len());
    }

    /// Add one byte (obstack_1grow).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn grow_byte(&mut self, b: u8) {
        if self.room() < 1 {
            // SAFETY: started (contract).
            unsafe { newchunk(self, 1) };
        }
        // SAFETY: at least one byte of room at next_free.
        unsafe { self.next_free.write(b as c_char) };
        self.next_free = self.next_free.wrapping_add(1);
    }

    /// Add `n` uninitialised bytes (obstack_blank).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn blank(&mut self, n: usize) {
        if self.room() < n {
            // SAFETY: started (contract).
            unsafe { newchunk(self, n as c_int) };
        }
        self.next_free = self.next_free.wrapping_add(n);
    }

    /// Make sure `n` more bytes fit in the current chunk (obstack_make_room).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn make_room(&mut self, n: usize) {
        if self.room() < n {
            // SAFETY: started (contract).
            unsafe { newchunk(self, n as c_int) };
        }
    }

    /// End the object being built: its address (it never moves again), and the next object starts
    /// aligned after it (obstack_finish).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn finish(&mut self) -> *mut u8 {
        let value = self.object_base;
        if self.next_free == value {
            self.flags |= MAYBE_EMPTY_OBJECT;
        }
        self.next_free = ptr_align(self.next_free, self.alignment_mask);
        let chunk = self.chunk.cast::<c_char>();
        if diff(self.next_free, chunk) > diff(self.chunk_limit, chunk) {
            self.next_free = self.chunk_limit;
        }
        self.object_base = self.next_free;
        value as *mut u8
    }

    /// A new object of `n` bytes (obstack_alloc).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn alloc(&mut self, n: usize) -> *mut u8 {
        // SAFETY: started (contract).
        unsafe { self.blank(n) };
        // SAFETY: started (contract).
        unsafe { self.finish() }
    }

    /// A new object holding `data` and a NUL (obstack_copy0).
    ///
    /// # Safety
    /// As [`Obstack::grow`].
    pub unsafe fn copy0(&mut self, data: &[u8]) -> *mut u8 {
        // SAFETY: started (contract).
        unsafe { self.grow(data) };
        // SAFETY: started (contract).
        unsafe { self.grow_byte(0) };
        // SAFETY: started (contract).
        unsafe { self.finish() }
    }

    /// Free `obj` and everything allocated after it (obstack_free); null frees every chunk.
    ///
    /// # Safety
    /// `obj` is an object of this obstack (or null).
    pub unsafe fn free(&mut self, obj: *mut u8) {
        if obj as *mut c_void > self.chunk as *mut c_void && (obj as *mut c_void) < self.chunk_limit as *mut c_void {
            self.next_free = obj as *mut c_char;
            self.object_base = obj as *mut c_char;
        } else {
            // SAFETY: this started obstack and one of its objects (contract).
            unsafe { obstack_free(self, obj.cast()) };
        }
    }
}

// ------------------------------------------------------------------ obstack_printf

/// The output sink of obstack_vprintf: the rest of the current chunk is claimed up front (so the
/// formatter writes straight into it); when it is full one byte goes through obstack_1grow, which opens
/// the next chunk, and the room there is claimed again. When done, the unused part is given back.
struct ObSink {
    o: *mut Obstack,
    ptr: *mut u8,
    end: *mut u8,
    written: usize,
}

impl ObSink {
    fn room(o: &Obstack) -> usize {
        diff(o.chunk_limit, o.next_free) as usize
    }

    /// Claim the rest of the current chunk.
    ///
    /// # Safety
    /// `o` is a started obstack that stays valid, and is not otherwise used, while the sink lives.
    unsafe fn start(o: *mut Obstack) -> ObSink {
        // SAFETY: contract.
        let ob = unsafe { obstack(o) };
        let mut room = Self::room(ob);
        let mut size = diff(ob.next_free, ob.object_base) as usize + room;
        if size == 0 {
            // get more memory
            if diff(ob.chunk_limit, ob.next_free) < 64 {
                // SAFETY: started (contract).
                unsafe { newchunk(ob, 64) };
            }
            room = Self::room(ob);
            size = room;
            debug_assert!(size != 0);
        }
        let ptr = ob.next_free as *mut u8;
        let end = (ob.object_base as *mut u8).wrapping_add(size);
        // claim the rest of the current chunk
        ob.next_free = ob.next_free.wrapping_add(room);
        ObSink { o, ptr, end, written: 0 }
    }

    /// Give back the claimed room that was not written.
    fn finish(&mut self) {
        // SAFETY: the obstack outlives the sink and is used only through it (start's contract).
        let ob = unsafe { obstack(self.o) };
        ob.next_free = ob.next_free.wrapping_offset(diff(self.ptr.cast(), self.end.cast()));
    }
}

impl Sink for ObSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        let mut rest = bytes;
        while !rest.is_empty() {
            let room = diff(self.end.cast(), self.ptr.cast()) as usize;
            if room > 0 {
                let n = room.min(rest.len());
                // SAFETY: `ptr..end` is claimed room of the current chunk; `n` bytes of it are free.
                unsafe { core::ptr::copy_nonoverlapping(rest.as_ptr(), self.ptr, n) };
                self.ptr = self.ptr.wrapping_add(n);
                self.written += n;
                rest = &rest[n..];
                continue;
            }
            // full: one more byte through the obstack grow path (it opens the next chunk) ...
            // SAFETY: the obstack outlives the sink and is used only through it (start's contract).
            let ob = unsafe { obstack(self.o) };
            if ob.next_free.wrapping_add(1) > ob.chunk_limit {
                // SAFETY: started (start's contract).
                unsafe { newchunk(ob, 1) };
            }
            // SAFETY: at least one byte of room at next_free.
            unsafe { ob.next_free.write(rest[0] as c_char) };
            ob.next_free = ob.next_free.wrapping_add(1);
            self.written += 1;
            rest = &rest[1..];
            // ... and the room of the new chunk is claimed again
            let room = ObSink::room(ob);
            self.ptr = ob.next_free as *mut u8;
            self.end = self.ptr.wrapping_add(room);
            ob.next_free = ob.next_free.wrapping_add(room);
        }
        true
    }
}

/// The body of obstack_vprintf; `check` looks at the format first (the `_chk` forms' protection).
///
/// # Safety
/// As `vprintf`; `h` is an initialised obstack.
pub unsafe fn obstack_vprintf_checked(h: *mut Obstack, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) -> c_int {
    if let Some(c) = check {
        // SAFETY: the checker takes the caller's format string.
        unsafe { c(fmt) };
    }
    // SAFETY: `h` is a started obstack (contract), used only through the sink until `finish`.
    let mut sink = unsafe { ObSink::start(h) };
    // SAFETY: `fmt` and `ap` as vprintf's (contract).
    let n = unsafe { rusty_libc_stdio::printf_api::run(&mut sink, fmt, ap) };
    sink.finish();
    if n < 0 { n } else { sink.written as c_int }
}

/// obstack_vprintf: append formatted text to the object being built (it is not finished).
///
/// # Safety
/// As `vprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_vprintf(h: *mut Obstack, fmt: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { obstack_vprintf_checked(h, fmt, &mut ap, None) }
}

/// obstack_printf.
///
/// # Safety
/// As `printf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_printf(h: *mut Obstack, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { obstack_vprintf_checked(h, fmt, &mut args, None) }
}
