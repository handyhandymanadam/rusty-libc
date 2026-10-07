use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
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
pub static mut obstack_alloc_failed_handler: Option<unsafe extern "C" fn()> = Some(print_and_abort);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut obstack_exit_failure: c_int = 1;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut _obstack: *mut Obstack = null_mut();

unsafe extern "C" fn print_and_abort() {
    let msg = b"memory exhausted\n";
    unsafe { rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_WRITE, 2, msg.as_ptr() as usize, msg.len()) };
    rusty_libc_core::process::exit(unsafe { obstack_exit_failure })
}

unsafe fn alloc_failed() {
    unsafe {
        if let Some(h) = obstack_alloc_failed_handler {
            h();
        }
    }
}

const DEFAULT_ALIGNMENT: c_int = 16;
const DEFAULT_ROUNDING: c_int = 16;

fn ptr_align(p: *mut c_char, mask: c_int) -> *mut c_char {
    let a = mask as isize as usize;
    ((p as usize).wrapping_add(a) & !a) as *mut c_char
}

unsafe fn call_chunkfun(h: &Obstack, size: c_long) -> *mut ObstackChunk {
    unsafe {
        let f = h.chunkfun.unwrap();
        if h.flags & USE_EXTRA_ARG != 0 {
            f(h.extra_arg, size)
        } else {
            let plain: unsafe extern "C" fn(c_long) -> *mut ObstackChunk = core::mem::transmute(f);
            plain(size)
        }
    }
}

unsafe fn call_freefun(h: &Obstack, chunk: *mut ObstackChunk) {
    unsafe {
        let f = h.freefun.unwrap();
        if h.flags & USE_EXTRA_ARG != 0 {
            f(h.extra_arg, chunk)
        } else {
            let plain: unsafe extern "C" fn(*mut ObstackChunk) = core::mem::transmute(f);
            plain(chunk)
        }
    }
}

fn default_size() -> c_int {
    let round = |x: c_int| (x + DEFAULT_ROUNDING - 1) & !(DEFAULT_ROUNDING - 1);
    4096 - round(round(12) + 4)
}

unsafe fn begin_common(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: usize, freefun: usize, extra: Option<*mut c_void>) -> c_int {
    unsafe {
        let o = &mut *h;
        let alignment = if alignment == 0 { DEFAULT_ALIGNMENT } else { alignment };
        let size = if size == 0 { default_size() } else { size };
        o.chunkfun = Some(core::mem::transmute::<usize, ChunkFn>(chunkfun));
        o.freefun = Some(core::mem::transmute::<usize, FreeFn>(freefun));
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
        o.object_base = ptr_align((&raw mut (*chunk).contents) as *mut c_char, alignment - 1);
        o.next_free = o.object_base;
        o.chunk_limit = (chunk as *mut c_char).add(o.chunk_size as usize);
        (*chunk).limit = o.chunk_limit;
        (*chunk).prev = null_mut();
        o.flags &= !MAYBE_EMPTY_OBJECT;
        o.flags &= !ALLOC_FAILED;
        1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    unsafe { begin_common(h, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_begin_1(h: *mut Obstack, size: c_int, alignment: c_int, chunkfun: Option<unsafe extern "C" fn(*mut c_void, c_long) -> *mut c_void>, freefun: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>, arg: *mut c_void) -> c_int {
    unsafe { begin_common(h, size, alignment, chunkfun.map_or(0, |f| f as usize), freefun.map_or(0, |f| f as usize), Some(arg)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_newchunk(h: *mut Obstack, length: c_int) {
    unsafe {
        let o = &mut *h;
        let old_chunk = o.chunk;
        let obj_size = o.next_free.offset_from(o.object_base) as c_long;
        let mut new_size = (obj_size + length as c_long) + (obj_size >> 3) + o.alignment_mask as c_long + 100;
        if new_size < o.chunk_size {
            new_size = o.chunk_size;
        }
        let new_chunk = call_chunkfun(o, new_size);
        if new_chunk.is_null() {
            alloc_failed();
        }
        o.chunk = new_chunk;
        (*new_chunk).prev = old_chunk;
        o.chunk_limit = (new_chunk as *mut c_char).add(new_size as usize);
        (*new_chunk).limit = o.chunk_limit;
        let object_base = ptr_align((&raw mut (*new_chunk).contents) as *mut c_char, o.alignment_mask);
        core::ptr::copy_nonoverlapping(o.object_base, object_base, obj_size as usize);
        if o.flags & MAYBE_EMPTY_OBJECT == 0 && o.object_base == ptr_align((&raw mut (*old_chunk).contents) as *mut c_char, o.alignment_mask) {
            (*new_chunk).prev = (*old_chunk).prev;
            call_freefun(o, old_chunk);
        }
        o.object_base = object_base;
        o.next_free = o.object_base.add(obj_size as usize);
        o.flags &= !MAYBE_EMPTY_OBJECT;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_allocated_p(h: *mut Obstack, obj: *mut c_void) -> c_int {
    unsafe {
        let mut lp = (*h).chunk;
        while !lp.is_null() && (lp as *mut c_void >= obj || ((*lp).limit as *mut c_void) < obj) {
            lp = (*lp).prev;
        }
        (!lp.is_null()) as c_int
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_free(h: *mut Obstack, obj: *mut c_void) {
    unsafe {
        let o = &mut *h;
        let mut lp = o.chunk;
        while !lp.is_null() && (lp as *mut c_void >= obj || ((*lp).limit as *mut c_void) < obj) {
            let plp = (*lp).prev;
            call_freefun(o, lp);
            lp = plp;
            o.flags |= MAYBE_EMPTY_OBJECT;
        }
        if !lp.is_null() {
            o.next_free = obj as *mut c_char;
            o.object_base = obj as *mut c_char;
            o.chunk_limit = (*lp).limit;
            o.chunk = lp;
        } else if !obj.is_null() {
            rusty_libc_core::process::abort();
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_free(h: *mut Obstack, obj: *mut c_void) {
    unsafe { obstack_free(h, obj) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _obstack_memory_used(h: *mut Obstack) -> c_int {
    unsafe {
        let mut n: c_int = 0;
        let mut lp = (*h).chunk;
        while !lp.is_null() {
            n = n.wrapping_add((*lp).limit.offset_from(lp as *mut c_char) as c_int);
            lp = (*lp).prev;
        }
        n
    }
}

impl Obstack {
    pub const fn zeroed() -> Obstack {
        Obstack { chunk_size: 0, chunk: null_mut(), object_base: null_mut(), next_free: null_mut(), chunk_limit: null_mut(), temp: 0, alignment_mask: 0, chunkfun: None, freefun: None, extra_arg: null_mut(), flags: 0 }
    }

    pub unsafe fn init(&mut self, size: c_int, alignment: c_int, chunkfun: unsafe extern "C" fn(c_long) -> *mut c_void, freefun: unsafe extern "C" fn(*mut c_void)) {
        unsafe { _obstack_begin(self, size, alignment, Some(chunkfun), Some(freefun)) };
    }

    pub fn object_size(&self) -> usize {
        unsafe { self.next_free.offset_from(self.object_base) as usize }
    }

    pub fn room(&self) -> usize {
        unsafe { self.chunk_limit.offset_from(self.next_free) as usize }
    }

    pub unsafe fn grow(&mut self, data: &[u8]) {
        unsafe {
            if self.room() < data.len() {
                _obstack_newchunk(self, data.len() as c_int);
            }
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.next_free as *mut u8, data.len());
            self.next_free = self.next_free.add(data.len());
        }
    }

    pub unsafe fn grow_byte(&mut self, b: u8) {
        unsafe {
            if self.room() < 1 {
                _obstack_newchunk(self, 1);
            }
            *self.next_free = b as c_char;
            self.next_free = self.next_free.add(1);
        }
    }

    pub unsafe fn blank(&mut self, n: usize) {
        unsafe {
            if self.room() < n {
                _obstack_newchunk(self, n as c_int);
            }
            self.next_free = self.next_free.add(n);
        }
    }

    pub unsafe fn make_room(&mut self, n: usize) {
        unsafe {
            if self.room() < n {
                _obstack_newchunk(self, n as c_int);
            }
        }
    }

    pub unsafe fn finish(&mut self) -> *mut u8 {
        unsafe {
            let value = self.object_base;
            if self.next_free == value {
                self.flags |= MAYBE_EMPTY_OBJECT;
            }
            self.next_free = ptr_align(self.next_free, self.alignment_mask);
            if self.next_free.offset_from(self.chunk as *mut c_char) > self.chunk_limit.offset_from(self.chunk as *mut c_char) {
                self.next_free = self.chunk_limit;
            }
            self.object_base = self.next_free;
            value as *mut u8
        }
    }

    pub unsafe fn alloc(&mut self, n: usize) -> *mut u8 {
        unsafe {
            self.blank(n);
            self.finish()
        }
    }

    pub unsafe fn copy0(&mut self, data: &[u8]) -> *mut u8 {
        unsafe {
            self.grow(data);
            self.grow_byte(0);
            self.finish()
        }
    }

    pub unsafe fn free(&mut self, obj: *mut u8) {
        unsafe {
            if obj as *mut c_void > self.chunk as *mut c_void && (obj as *mut c_void) < self.chunk_limit as *mut c_void {
                self.next_free = obj as *mut c_char;
                self.object_base = obj as *mut c_char;
            } else {
                obstack_free(self, obj.cast());
            }
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
    unsafe fn room(o: &Obstack) -> usize {
        unsafe { o.chunk_limit.offset_from(o.next_free) as usize }
    }

    unsafe fn start(o: *mut Obstack) -> ObSink {
        unsafe {
            let ob = &mut *o;
            let mut room = Self::room(ob);
            let mut size = ob.next_free.offset_from(ob.object_base) as usize + room;
            if size == 0 {
                if ob.chunk_limit.offset_from(ob.next_free) < 64 {
                    _obstack_newchunk(o, 64);
                }
                room = Self::room(ob);
                size = room;
                debug_assert!(size != 0);
            }
            let ptr = ob.next_free as *mut u8;
            let end = (ob.object_base as *mut u8).add(size);
            ob.next_free = ob.next_free.add(room);
            ObSink { o, ptr, end, written: 0 }
        }
    }

    unsafe fn finish(&mut self) {
        unsafe {
            let ob = &mut *self.o;
            ob.next_free = ob.next_free.offset(self.ptr.offset_from(self.end));
        }
    }
}

impl Sink for ObSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            let mut rest = bytes;
            while !rest.is_empty() {
                let room = self.end.offset_from(self.ptr) as usize;
                if room > 0 {
                    let n = room.min(rest.len());
                    core::ptr::copy_nonoverlapping(rest.as_ptr(), self.ptr, n);
                    self.ptr = self.ptr.add(n);
                    self.written += n;
                    rest = &rest[n..];
                    continue;
                }
                let ob = &mut *self.o;
                if ob.next_free.add(1) > ob.chunk_limit {
                    _obstack_newchunk(self.o, 1);
                }
                *ob.next_free = rest[0] as c_char;
                ob.next_free = ob.next_free.add(1);
                self.written += 1;
                rest = &rest[1..];
                let room = ObSink::room(ob);
                self.ptr = ob.next_free as *mut u8;
                self.end = self.ptr.add(room);
                ob.next_free = ob.next_free.add(room);
            }
            true
        }
    }
}

pub unsafe fn obstack_vprintf_checked(h: *mut Obstack, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) -> c_int {
    unsafe {
        if let Some(c) = check {
            c(fmt);
        }
        let mut sink = ObSink::start(h);
        let n = rusty_libc_stdio::printf_api::run(&mut sink, fmt, ap);
        sink.finish();
        if n < 0 { n } else { sink.written as c_int }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_vprintf(h: *mut Obstack, fmt: *const c_char, mut ap: VaList) -> c_int {
    unsafe { obstack_vprintf_checked(h, fmt, &mut ap, None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_printf(h: *mut Obstack, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { obstack_vprintf_checked(h, fmt, &mut args, None) }
}
