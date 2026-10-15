#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::fmt::Sink;

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

#[repr(C)]
pub struct Obstack {
    pub chunk_size: c_long,
    pub chunk: *mut ObstackChunk,
    pub object_base: *mut c_char,
    pub next_free: *mut c_char,
    pub chunk_limit: *mut c_char,
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static obstack_alloc_failed_handler: SyncCell<Option<unsafe extern "C" fn()>> = SyncCell::new(Some(print_and_abort));

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static obstack_exit_failure: SyncCell<c_int> = SyncCell::new(1);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static _obstack: SyncCell<*mut Obstack> = SyncCell::new(null_mut());

unsafe extern "C" fn print_and_abort() {
    let t = rusty_libc_core::i18n::tr(c"memory exhausted").to_bytes();
    let mut msg = [0u8; 256];
    let k = t.len().min(msg.len() - 1);
    msg[..k].copy_from_slice(&t[..k]);
    msg[k] = b'\n';
    unsafe { rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, 2, msg.as_ptr() as usize, k + 1) };
    rusty_libc_core::process::exit(unsafe { obstack_exit_failure.read() })
}

fn alloc_failed() {
    if let Some(h) = unsafe { obstack_alloc_failed_handler.read() } {
        unsafe { h() };
    }
}

const DEFAULT_ALIGNMENT: c_int = 16;
const DEFAULT_ROUNDING: c_int = 16;

fn ptr_align(p: *mut c_char, mask: c_int) -> *mut c_char {
    let a = mask as isize as usize;
    p.wrapping_add(((p as usize).wrapping_add(a) & !a).wrapping_sub(p as usize))
}

#[inline(always)]
fn diff(b: *const c_char, a: *const c_char) -> isize {
    (b.addr() as isize).wrapping_sub(a.addr() as isize)
}

#[inline(always)]
fn contents(chunk: *mut ObstackChunk) -> *mut c_char {
    chunk.cast::<c_char>().wrapping_add(core::mem::offset_of!(ObstackChunk, contents))
}

#[inline(always)]
unsafe fn chunk_mut<'a>(chunk: *mut ObstackChunk) -> &'a mut ObstackChunk {
    unsafe { &mut *chunk }
}

fn call_chunkfun(h: &Obstack, size: c_long) -> *mut ObstackChunk {
    let f = h.chunkfun.unwrap();
    if h.flags & USE_EXTRA_ARG != 0 {
        unsafe { f(h.extra_arg, size) }
    } else {
        let plain: unsafe extern "C" fn(c_long) -> *mut ObstackChunk = unsafe { core::mem::transmute(f) };
        unsafe { plain(size) }
    }
}

unsafe fn call_freefun(h: &Obstack, chunk: *mut ObstackChunk) {
    let f = h.freefun.unwrap();
    if h.flags & USE_EXTRA_ARG != 0 {
        unsafe { f(h.extra_arg, chunk) }
    } else {
        let plain: unsafe extern "C" fn(*mut ObstackChunk) = unsafe { core::mem::transmute(f) };
        unsafe { plain(chunk) }
    }
}

fn default_size() -> c_int {
    let round = |x: c_int| (x + DEFAULT_ROUNDING - 1) & !(DEFAULT_ROUNDING - 1);
    4096 - round(round(12) + 4)
}

#[inline(always)]
unsafe fn obstack<'a>(h: *mut Obstack) -> &'a mut Obstack {
    unsafe { &mut *h }
}

unsafe fn begin_common(o: &mut Obstack, size: c_int, alignment: c_int, chunkfun: usize, freefun: usize, extra: Option<*mut c_void>) -> c_int {
    let alignment = if alignment == 0 { DEFAULT_ALIGNMENT } else { alignment };
    let size = if size == 0 { default_size() } else { size };
    o.chunkfun = Some(unsafe { core::mem::transmute::<usize, ChunkFn>(chunkfun) });
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
    o.object_base = ptr_align(contents(chunk), alignment - 1);
    o.next_free = o.object_base;
    o.chunk_limit = chunk.cast::<c_char>().wrapping_add(o.chunk_size as usize);
    let c = unsafe { chunk_mut(chunk) };
    c.limit = o.chunk_limit;
    c.prev = null_mut();
    o.flags &= !MAYBE_EMPTY_OBJECT;
    o.flags &= !ALLOC_FAILED;
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    let o = unsafe { obstack(h) };
    unsafe { begin_common(o, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin_1(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(*mut c_void, c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>, arg: *mut c_void) -> c_int {
    let o = unsafe { obstack(h) };
    unsafe { begin_common(o, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), Some(arg)) }
}

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
        let c = unsafe { chunk_mut(new_chunk) };
        c.prev = old_chunk;
        c.limit = o.chunk_limit;
    }
    let object_base = ptr_align(contents(new_chunk), o.alignment_mask);
    unsafe { core::ptr::copy_nonoverlapping(o.object_base, object_base, obj_size as usize) };
    if o.flags & MAYBE_EMPTY_OBJECT == 0 && o.object_base == ptr_align(contents(old_chunk), o.alignment_mask) {
        let prev = unsafe { chunk_mut(old_chunk) }.prev;
        unsafe { chunk_mut(new_chunk) }.prev = prev;
        unsafe { call_freefun(o, old_chunk) };
    }
    o.object_base = object_base;
    o.next_free = o.object_base.wrapping_add(obj_size as usize);
    o.flags &= !MAYBE_EMPTY_OBJECT;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_newchunk(h: *mut Obstack, length: c_int) {
    let o = unsafe { obstack(h) };
    unsafe { newchunk(o, length) }
}

unsafe fn find_chunk(mut lp: *mut ObstackChunk, obj: *mut c_void, mut on_skip: impl FnMut(*mut ObstackChunk)) -> *mut ObstackChunk {
    loop {
        if lp.is_null() {
            return lp;
        }
        let c = unsafe { chunk_mut(lp) };
        if !(lp as *mut c_void >= obj || (c.limit as *mut c_void) < obj) {
            return lp;
        }
        let plp = c.prev;
        on_skip(lp);
        lp = plp;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_allocated_p(h: *mut Obstack, obj: *mut c_void) -> c_int {
    let o = unsafe { obstack(h) };
    (!unsafe { find_chunk(o.chunk, obj, |_| {}) }.is_null()) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_free(h: *mut Obstack, obj: *mut c_void) {
    let o = unsafe { obstack(h) };
    let mut skipped = false;
    let skip = |c: *mut ObstackChunk| {
        unsafe { call_freefun(o, c) };
        skipped = true;
    };
    let lp = unsafe { find_chunk(o.chunk, obj, skip) };
    if skipped {
        o.flags |= MAYBE_EMPTY_OBJECT;
    }
    if !lp.is_null() {
        o.next_free = obj as *mut c_char;
        o.object_base = obj as *mut c_char;
        o.chunk_limit = unsafe { chunk_mut(lp) }.limit;
        o.chunk = lp;
    } else if !obj.is_null() {
        rusty_libc_core::process::abort();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_free(h: *mut Obstack, obj: *mut c_void) {
    unsafe { obstack_free(h, obj) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_memory_used(h: *mut Obstack) -> c_int {
    let o = unsafe { obstack(h) };
    let mut n: c_int = 0;
    let mut lp = o.chunk;
    while !lp.is_null() {
        let c = unsafe { chunk_mut(lp) };
        n = n.wrapping_add(diff(c.limit, lp.cast::<c_char>()) as c_int);
        lp = c.prev;
    }
    n
}

impl Obstack {
    pub const fn zeroed() -> Obstack {
        Obstack { chunk_size: 0, chunk: null_mut(), object_base: null_mut(), next_free: null_mut(), chunk_limit: null_mut(), temp: 0, alignment_mask: 0, chunkfun: None, freefun: None, extra_arg: null_mut(), flags: 0 }
    }

    pub unsafe fn init(&mut self, size: c_int, alignment: c_int, chunkfun: unsafe extern "C" fn(c_long) -> *mut c_void, freefun: unsafe extern "C" fn(*mut c_void)) {
        unsafe { begin_common(self, size, alignment, chunkfun as usize, freefun as usize, None) };
    }

    pub fn object_size(&self) -> usize {
        diff(self.next_free, self.object_base) as usize
    }

    pub fn room(&self) -> usize {
        diff(self.chunk_limit, self.next_free) as usize
    }

    pub unsafe fn grow(&mut self, data: &[u8]) {
        if self.room() < data.len() {
            unsafe { newchunk(self, data.len() as c_int) };
        }
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.next_free as *mut u8, data.len()) };
        self.next_free = self.next_free.wrapping_add(data.len());
    }

    pub unsafe fn grow_byte(&mut self, b: u8) {
        if self.room() < 1 {
            unsafe { newchunk(self, 1) };
        }
        unsafe { self.next_free.write(b as c_char) };
        self.next_free = self.next_free.wrapping_add(1);
    }

    pub unsafe fn blank(&mut self, n: usize) {
        if self.room() < n {
            unsafe { newchunk(self, n as c_int) };
        }
        self.next_free = self.next_free.wrapping_add(n);
    }

    pub unsafe fn make_room(&mut self, n: usize) {
        if self.room() < n {
            unsafe { newchunk(self, n as c_int) };
        }
    }

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

    pub unsafe fn alloc(&mut self, n: usize) -> *mut u8 {
        unsafe { self.blank(n) };
        unsafe { self.finish() }
    }

    pub unsafe fn copy0(&mut self, data: &[u8]) -> *mut u8 {
        unsafe { self.grow(data) };
        unsafe { self.grow_byte(0) };
        unsafe { self.finish() }
    }

    pub unsafe fn free(&mut self, obj: *mut u8) {
        if obj as *mut c_void > self.chunk as *mut c_void && (obj as *mut c_void) < self.chunk_limit as *mut c_void {
            self.next_free = obj as *mut c_char;
            self.object_base = obj as *mut c_char;
        } else {
            unsafe { obstack_free(self, obj.cast()) };
        }
    }
}

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

    unsafe fn start(o: *mut Obstack) -> ObSink {
        let ob = unsafe { obstack(o) };
        let mut room = Self::room(ob);
        let mut size = diff(ob.next_free, ob.object_base) as usize + room;
        if size == 0 {
            if diff(ob.chunk_limit, ob.next_free) < 64 {
                unsafe { newchunk(ob, 64) };
            }
            room = Self::room(ob);
            size = room;
            debug_assert!(size != 0);
        }
        let ptr = ob.next_free as *mut u8;
        let end = (ob.object_base as *mut u8).wrapping_add(size);
        ob.next_free = ob.next_free.wrapping_add(room);
        ObSink { o, ptr, end, written: 0 }
    }

    fn finish(&mut self) {
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
                unsafe { core::ptr::copy_nonoverlapping(rest.as_ptr(), self.ptr, n) };
                self.ptr = self.ptr.wrapping_add(n);
                self.written += n;
                rest = &rest[n..];
                continue;
            }
            let ob = unsafe { obstack(self.o) };
            if ob.next_free.wrapping_add(1) > ob.chunk_limit {
                unsafe { newchunk(ob, 1) };
            }
            unsafe { ob.next_free.write(rest[0] as c_char) };
            ob.next_free = ob.next_free.wrapping_add(1);
            self.written += 1;
            rest = &rest[1..];
            let room = ObSink::room(ob);
            self.ptr = ob.next_free as *mut u8;
            self.end = self.ptr.wrapping_add(room);
            ob.next_free = ob.next_free.wrapping_add(room);
        }
        true
    }
}

pub unsafe fn obstack_vprintf_checked(h: *mut Obstack, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) -> c_int {
    if let Some(c) = check {
        unsafe { c(fmt) };
    }
    let mut sink = unsafe { ObSink::start(h) };
    let n = unsafe { rusty_libc_stdio::printf_api::run(&mut sink, fmt, ap) };
    sink.finish();
    if n < 0 { n } else { sink.written as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_vprintf(h: *mut Obstack, fmt: *const c_char, mut ap: VaList) -> c_int {
    unsafe { obstack_vprintf_checked(h, fmt, &mut ap, None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_printf(h: *mut Obstack, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { obstack_vprintf_checked(h, fmt, &mut args, None) }
}
