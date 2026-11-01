//! FILE streams: buffering, reading, writing, positioning.
//!
//! One buffer serves a stream for reading or writing, never both at once (the C rule: switch with
//! a seek or flush). Buffering rules follow glibc: files are fully buffered with a buffer of
//! `min(BUFSIZ, st_blksize)`, terminals are line buffered, stderr is unbuffered; a read from an
//! unbuffered or line-buffered stream first flushes the line-buffered output streams; EOF is sticky
//! until `clearerr` or a seek.
use crate::flock::FLock;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, Ordering};
use rusty_libc_core::lock::{RawMutex, multithreaded};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, unistd};

pub const BUFSIZ: usize = 8192;
pub const EOF: c_int = -1;

// The low bits of `flags` are glibc's `_flags` bits with glibc's meaning, because code compiled against glibc's headers reads
// them: its inline feof_unlocked/ferror_unlocked (0x10, 0x20), and gnulib's freading/fwriting/freadable/fwritable/fbufmode/
// freadahead/fseterr/fseeko/fflush (0x2, 0x4, 0x8, 0x100, 0x200, 0x800; lib/stdio-impl.h and the "GNU libc" branches).
// Our own bits live in the high half, where glibc keeps its magic number (nobody outside libio reads it).
pub const F_USERBUF: u32 = 0x1; // buffer supplied by the caller (setvbuf): never freed (_IO_USER_BUF)
pub const F_UNBUF: u32 = 0x2; // unbuffered (_IO_UNBUFFERED)
pub const F_NOREAD: u32 = 0x4; // not opened for reading (_IO_NO_READS; always the opposite of F_READ)
pub const F_NOWRITE: u32 = 0x8; // not opened for writing (_IO_NO_WRITES; always the opposite of F_WRITE)
pub const F_EOF: u32 = 0x10; // (_IO_EOF_SEEN)
pub const F_ERR: u32 = 0x20; // (_IO_ERR_SEEN)
/// Pushed-back characters are being read (glibc's `_IO_IN_BACKUP`): `rptr`..`rend_p` is the pushback area and the main get
/// area waits in `save_base`..`save_end` (see `File`).
pub const F_UNGOT: u32 = 0x100;
pub const F_LBF: u32 = 0x200; // line buffered (_IO_LINE_BUF)
/// The last operation was a write (glibc's `_IO_CURRENTLY_PUTTING`): set by the switch to writing, cleared only by a switch to
/// reading (a read, ungetc or seek), not by a flush, like glibc. gnulib's freading/fwriting test it.
pub const F_PUTTING: u32 = 0x800;
pub const F_APPEND: u32 = 0x1000; // (_IO_IS_APPENDING)
pub const F_READ: u32 = 1 << 16; // opened for reading
pub const F_WRITE: u32 = 1 << 17; // opened for writing
pub const F_DECIDED: u32 = 1 << 18; // buffering mode has been decided
pub const F_STATIC: u32 = 1 << 19; // not heap allocated (stdin, stdout, stderr)
pub const F_RDMODE: u32 = 1 << 20; // buffer currently holds unread input
pub const F_WRMODE: u32 = 1 << 21; // buffer currently holds unwritten output
pub const F_NOSEEK: u32 = 1 << 22; // known to be unseekable
pub const F_MEM: u32 = 1 << 23; // memory stream or cookie stream: no file descriptor
pub const F_NOCACHE: u32 = 1 << 24; // always ask the cookie for the position (open_memstream: asking has side effects in glibc)
pub const F_WIDE: u32 = 1 << 25; // wide oriented (fixed by the first wide operation or fwide)
pub const F_BYTE: u32 = 1 << 26; // byte oriented
pub const F_OLDMEM: u32 = 1 << 27; // fmemopen@GLIBC_2.2.5 stream: ftell writes pending output out first (matches glibc's old cookie)
pub const F_W32: u32 = 1 << 28; // open_wmemstream: wide characters are stored as raw 32-bit units, positions count them
pub const F_NOCANCEL: u32 = 1 << 29; // opened with the "c" mode flag: its reads and writes are not cancellation points
pub const F_SEEKED: u32 = 1 << 30; // the offset cache is trusted: an fseek succeeded and no read has hit the end since (glibc's _offset != _IO_pos_BAD)
pub const F_NOEOF: u32 = 1 << 31; // reads that hit the end never set the EOF flag (open_memstream, like glibc)

/// `malloc(n)` (the program's malloc when it interposes one, as before): null when there is no memory.
#[inline(always)]
pub(crate) fn alloc(n: usize) -> *mut u8 {
    // SAFETY: malloc has no precondition.
    unsafe { rusty_libc_malloc::malloc(n) }.cast()
}

/// `free(p)`.
///
/// # Safety
/// `p` is null or a live block from `alloc` (malloc) that nothing uses afterwards.
#[inline(always)]
pub(crate) unsafe fn free(p: *mut u8) {
    // SAFETY: the caller's promise.
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

/// `dst.copy_from_slice(src)` through the library's own `memcpy` (the call this code made before it worked on slices: a direct
/// call, never one through the PLT to an interposed `memcpy`).
#[inline(always)]
pub(crate) fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() == src.len());
    // SAFETY: two valid slices of the same length; `&mut` and `&` cannot overlap.
    unsafe { rusty_libc_mem::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
}

/// Copy `n` bytes with the library's `memcpy`, unchecked: the hot copies (fread, fwrite, fgets, getline) keep this raw form,
/// the slice form costs bounds checks on every call (fwrite of 16 bytes 1.10x, fgets 1.11x the time, measured).
///
/// # Safety
/// `dst` is writable and `src` readable for `n` bytes, and they do not overlap.
#[inline(always)]
pub(crate) unsafe fn copy_raw(dst: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller's promise.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), n) };
}

/// `flags` with F_NOREAD and F_NOWRITE matching F_READ and F_WRITE.
pub const fn with_access_bits(flags: u32) -> u32 {
    let f = flags & !(F_NOREAD | F_NOWRITE);
    f | if f & F_READ == 0 { F_NOREAD } else { 0 } | if f & F_WRITE == 0 { F_NOWRITE } else { 0 }
}

/// Cookie I/O functions (fopencookie and memory streams).
#[derive(Clone, Copy)]
pub struct CookieIo {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    /// Called by `fflush` (memory streams publish their buffer and size there).
    pub sync: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// A stream. The first fields have the offsets and the meaning of glibc's `struct _IO_FILE` fields that code compiled against
/// glibc's headers reads or moves directly: `_flags` (0), the six get/put area pointers (8 to 48), `_IO_buf_base` (56),
/// `_IO_save_base` (72), `_IO_save_end` (88), `_fileno` (112) and `_offset` (144). glibc's inline `getc_unlocked`/`putc_unlocked` take bytes
/// at `_IO_read_ptr`/`_IO_write_ptr` while the pointer is below its end, and call `__uflow`/`__overflow` otherwise; gnulib's
/// freadahead, freadptr, freadseek, fpending, fpurge and fseeko (coreutils, tar, gzip, diffutils, m4, ...) read and move the
/// pointers. So the pointers are the stream's only record of its buffer:
///
/// - reading: `rbase` = `buf`, `rptr` = next unread byte, `rend_p` = end of the buffered input.
/// - reading pushed-back bytes (`F_UNGOT`, glibc's backup area): `rbase`..`rend_p` is the pushback area (the inline `unget` bytes
///   or `ubuf`, `ucap` bytes, filled from its end), `rptr` the next pushed-back byte; the main area's position and end wait in
///   `save_base`/`save_end` until the pushed-back bytes are used up (glibc's `_IO_switch_to_backup_area`).
/// - writing: `wbase` = `buf`, `wptr` = end of the pending output, `wend` = end of the buffer, or `wbase` for a line-buffered,
///   unbuffered or wide stream (every inline putc then goes through `__overflow`, which flushes at a newline).
/// - otherwise the read pointers are equal (nothing to read) and the write pointers are equal (nothing to write, no room).
///
/// The rest of the layout is ours.
///
/// Access rule (what the `&mut File` the library's functions take relies on): a thread works on a stream only while it holds
/// the stream's lock, or while the process has one thread, or after `__fsetlocking(BYCALLER)` (the caller locks); the exported
/// functions take the lock and turn the C pointer into `&mut File` once (`locked!`). Other threads never read or write a
/// `File`'s bytes meanwhile: what they use (the lock, the walkers' pins, the open-list links and membership, the locking mode,
/// the fork mark, the walkers' hint) is in `Shared`, after the `File` in the same allocation (`Stream`), so a `&mut File`
/// is unique for all of its bytes under Stacked and Tree Borrows alike (FIXLIST #123, #124). Buffer invariant:
/// `buf..buf_end` is null/empty or memory the stream owns (malloc) or was given (setvbuf, shortbuf), and the six get/put pointers stay inside the current get or put area (glibc's contract for code that
/// moves them). Code that calls back into the program (cookie functions, printf hooks) must not hold a `&mut File` across a
/// callback that may use the same stream: the sinks keep the raw pointer and re-borrow per call.
#[repr(C)]
pub struct File {
    pub flags: u32,
    pub rptr: *mut u8,
    pub rend_p: *mut u8,
    pub rbase: *mut u8,
    pub wbase: *mut u8,
    pub wptr: *mut u8,
    pub wend: *mut u8,
    pub buf: *mut u8,
    /// End of the buffer (glibc's `_IO_buf_end`, offset 64): fmt's `fmt::print(FILE*)` writes straight into
    /// `_IO_write_ptr`..`_IO_buf_end`, so this must be a pointer, not a size.
    pub buf_end: *mut u8,
    pub save_base: *mut u8,
    /// (glibc's `_IO_backup_base`: not used, kept null)
    pub backup_base: *mut u8,
    pub save_end: *mut u8,
    /// (glibc's `_markers`: no stream markers, always null)
    pub markers: *mut u8,
    /// (glibc's `_chain`, which links glibc's open streams: kept null. The open-stream list is in `Shared`, outside the bytes a
    /// `&mut File` covers, because other threads change it while one thread works on this stream; nothing outside libio reads
    /// `_chain`: its head `_IO_list_all` is not exported, gnulib uses only `_flags`, the buffer pointers and `_fileno`.)
    pub chain: *mut File,
    /// The file descriptor, -1 for none (glibc's `_fileno`, offset 112: code compiled against glibc's headers reads
    /// `fp->_fileno` directly).
    pub fd: c_int,
    /// (glibc's `_flags2`: 0)
    pub flags2: c_int,
    /// The buffer of last resort (glibc's `_shortbuf`): an unbuffered stream reads through it when no memory is left.
    pub shortbuf: [u8; 8],
    /// The pushback area's size: 1 (the stream's `unget` room) or the bytes of `ubuf` (32 bits, so that `pid` fits beside it:
    /// FIXLIST #128 keeps a `Stream` at 264 bytes; an area that would pass 2^32 bytes makes ungetc fail).
    pub ucap: u32,
    /// The `popen` child's process id (0 for every other stream).
    pub pid: c_int,
    /// Pushed-back bytes beyond the first live in a heap block (`ucap` bytes, doubled like glibc's backup area when it is
    /// full; null while the first byte's room, `unget[0]`, is enough). A seek or draining the bytes frees it.
    pub ubuf: *mut u8,
    /// Where the descriptor's (or cookie's) offset is, as far as we know: -1 when unknown. Saves a
    /// system call for ftell and for seeks inside the buffer, like glibc's cached offset (`_offset`, at the same place:
    /// gnulib's fseeko sets it after its own lseek on an empty buffer).
    pub cookie_pos: i64,
    /// The cookie functions (fopencookie and the memory streams; all None for a descriptor stream: the bytes at glibc's
    /// `_codecvt` .. `__pad5`, 152 to 192, which nothing outside glibc reads, stay zero there).
    pub io: CookieIo,
    /// (at glibc's `_mode`, offset 192: kept 0. The orientation lives in `flags` (F_WIDE, F_BYTE, decided lazily) and
    /// `fwide` reports it; no code outside glibc is known to read `_mode` since its `_IO_fwide` macro left the public
    /// headers in 2.28, so it only must not hold another field's bytes.)
    pub mode: c_int,
    /// The first pushed-back byte's room (`ucap` is 1 while it is enough; the room is 4 bytes so that it fills the gap
    /// before the pointers that follow).
    pub unget: [u8; 4],
    /// This stream's `Shared` part (null for a `File` that is not part of a `Stream`): where the thread working on the stream
    /// publishes the walkers' hint (`publish_hint`).
    shared: *const Shared,
    pub cookie: *mut c_void,
    /// State of a wide-oriented stream (charset snapshot, pushed-back wide characters); null until the stream becomes wide.
    pub wide: *mut crate::wfile::WideInfo,
}

/// The part of a stream that other threads use while one thread works on the stream through its `&mut File` (see `File`).
/// Everything here is atomic (or the lock), used through shared references only.
#[repr(C)]
pub struct Shared {
    /// The stream's recursive lock (see `flock.rs`).
    pub lock: FLock,
    /// Walkers (fflush(NULL), exit flush, fork) that hold a reference to this stream while they wait
    /// for its lock: `fclose` waits for the count to drop to zero before it frees the stream.
    pins: AtomicU32,
    /// In the list of open streams (changed only under `LIST`).
    linked: AtomicBool,
    /// `__fsetlocking(BYCALLER)`: the caller does the locking, no implicit locks (set by the stream's owner; read by
    /// any thread that calls a function on the stream, before it locks).
    pub(crate) nolock: AtomicBool,
    /// Fork handler mark: 0 not taken, 1 lock taken for the fork, 2 gave up waiting (used only by the forking thread under
    /// `FORK_LOCK`).
    fork_held: AtomicU8,
    /// The walkers' first look at the stream without its lock (`H_FLUSH`, `H_LBF_OUT`): published by the thread working on
    /// the stream (`File::publish_hint`) whenever the answer may turn true and when it unlocks; never a false "clean" for a
    /// stream with pending output, unread descriptor input or a memory stream's sync hook (see `publish_hint`).
    hint: AtomicU8,
    /// The open-stream list (doubly linked, head `OPEN_HEAD`; read and written only under `LIST`).
    next: AtomicPtr<File>,
    prev: AtomicPtr<File>,
}

/// The walkers' hint: fflush(NULL) and the exit flush must look at the stream (pending output, unread input on a descriptor,
/// or a memory stream that publishes its buffer at each flush).
pub const H_FLUSH: u8 = 1;
/// The walkers' hint: a line-buffered stream with pending output (what a read from a terminal-like stream flushes).
pub const H_LBF_OUT: u8 = 2;
/// The hint of a stream made while the process has one thread: look at it (see `File::publish_hint`).
pub const H_ALL: u8 = H_FLUSH | H_LBF_OUT;

impl Shared {
    /// A stream's shared part, with the walkers' hint `hint` (`H_ALL` for a stream made while the process has one
    /// thread; see `File::publish_hint`).
    pub const fn with_hint(hint: u8) -> Shared {
        let mut s = Shared::new();
        s.hint = AtomicU8::new(hint);
        s
    }

    pub const fn new() -> Shared {
        Shared {
            lock: FLock::new(),
            pins: AtomicU32::new(0),
            linked: AtomicBool::new(false),
            nolock: AtomicBool::new(false),
            fork_held: AtomicU8::new(0),
            hint: AtomicU8::new(0),
            next: AtomicPtr::new(null_mut()),
            prev: AtomicPtr::new(null_mut()),
        }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

/// A stream as allocated: the `File` first, so the C `FILE *` is the address of the whole (and of the `File`), then the part
/// other threads use. Every stream is one: the heap streams (`alloc_file`: fopen, fdopen, popen, fmemopen, open_memstream,
/// fopencookie, ...) and the three standard streams.
#[repr(C)]
pub struct Stream {
    pub file: File,
    pub shared: Shared,
}

impl Stream {
    /// A blank stream whose `Shared` part is at `shared` (the address it will have: `Stream`s do not move).
    const fn new(flags: u32, fd: c_int, shared: *const Shared, hint: u8) -> Stream {
        let mut file = File::blank(flags, fd);
        file.shared = shared;
        Stream { file, shared: Shared::with_hint(hint) }
    }
}

// glibc's offsets (bits/types/struct_FILE.h, x86_64)
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(File, flags) == 0);
    assert!(offset_of!(File, rptr) == 8);
    assert!(offset_of!(File, rend_p) == 16);
    assert!(offset_of!(File, rbase) == 24);
    assert!(offset_of!(File, wbase) == 32);
    assert!(offset_of!(File, wptr) == 40);
    assert!(offset_of!(File, wend) == 48);
    assert!(offset_of!(File, buf) == 56);
    assert!(offset_of!(File, buf_end) == 64);
    assert!(offset_of!(File, save_base) == 72);
    assert!(offset_of!(File, backup_base) == 80); // _IO_backup_base
    assert!(offset_of!(File, save_end) == 88);
    assert!(offset_of!(File, markers) == 96); // _markers (null)
    assert!(offset_of!(File, chain) == 104); // _chain (null)
    assert!(offset_of!(File, fd) == 112);
    assert!(offset_of!(File, flags2) == 116); // _flags2 (0)
    assert!(offset_of!(File, cookie_pos) == 144);
    assert!(offset_of!(File, mode) == 192);
    // Every other glibc field holds a private field of ours, as it did before FIXLIST #128 (our own <stdio.h> names
    // these bytes __rlibc_private*; glibc's own code reads them, code compiled against its headers does not):
    // _old_offset (120) the last-resort buffer, _cur_column/_vtable_offset/_shortbuf (128..136) ucap and pid (#128;
    // before: ucap as 8 bytes), _lock (136) the pushback block, _codecvt.._pad5 (152..192) the cookie functions (#128;
    // before: unget room, shared, cookie, wide; all zero for a descriptor stream either way), _unused2 (196..216) the
    // pushback room, shared and cookie (#128; before: pid and cookie functions). Pinned so that any later move is a decision.
    assert!(offset_of!(File, shortbuf) == 120);
    assert!(offset_of!(File, ucap) == 128);
    assert!(offset_of!(File, pid) == 132);
    assert!(offset_of!(File, ubuf) == 136);
    assert!(offset_of!(File, io) == 152);
    assert!(offset_of!(File, unget) == 196);
    assert!(offset_of!(File, shared) == 200);
    assert!(offset_of!(File, cookie) == 208);
    assert!(offset_of!(File, wide) == 216);
    // at least glibc's 216-byte struct _IO_FILE (our header's FILE is 216 bytes)
    assert!(core::mem::size_of::<File>() >= 216);
    // FIXLIST #128: a stream (File + Shared) takes 264 bytes, as before the split of #123 (the three standard streams are
    // libc data: 48 bytes more moved every later variable, which the benchmarks read as slowdowns)
    assert!(core::mem::size_of::<File>() == 224);
    assert!(core::mem::size_of::<Stream>() == 264);
    // the C `FILE *` of a stream is the address of its `Stream` and of its `File`
    assert!(offset_of!(Stream, file) == 0);
};

impl File {
    pub const fn blank(flags: u32, fd: c_int) -> File {
        File {
            flags: with_access_bits(flags),
            rptr: null_mut(),
            rend_p: null_mut(),
            rbase: null_mut(),
            wbase: null_mut(),
            wptr: null_mut(),
            wend: null_mut(),
            buf: null_mut(),
            buf_end: null_mut(),
            save_base: null_mut(),
            backup_base: null_mut(),
            save_end: null_mut(),
            markers: null_mut(),
            chain: null_mut(),
            fd,
            flags2: 0,
            shortbuf: [0; 8],
            ucap: 1,
            pid: 0,
            ubuf: null_mut(),
            cookie_pos: -1,
            io: CookieIo { read: None, write: None, seek: None, close: None, sync: None },
            mode: 0,
            unget: [0; 4],
            shared: core::ptr::null(),
            cookie: null_mut(),
            wide: null_mut(),
        }
    }

    /// Give the stream a fresh state (new flags and descriptor, nothing buffered) but keep what
    /// belongs to the stream's identity: its `Shared` part (lock, pins, list membership, locking mode).
    pub fn reset(&mut self, flags: u32, fd: c_int) {
        self.flags = with_access_bits(flags) & !(F_UNGOT | F_PUTTING);
        self.fd = fd;
        self.buf = null_mut();
        self.buf_end = null_mut();
        self.rptr = null_mut();
        self.rend_p = null_mut();
        self.rbase = null_mut();
        self.wbase = null_mut();
        self.wptr = null_mut();
        self.wend = null_mut();
        self.save_base = null_mut();
        self.save_end = null_mut();
        self.unget = [0; 4];
        self.ubuf = null_mut();
        self.ucap = 1;
        self.cookie = null_mut();
        self.io = CookieIo { read: None, write: None, seek: None, close: None, sync: None };
        self.pid = 0;
        self.cookie_pos = -1;
        self.wide = null_mut();
    }

    /// Read position in the main buffer (an index into `buf`).
    #[inline(always)]
    pub fn rpos(&self) -> usize {
        (if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_base } else { self.rptr }) as usize - self.buf as usize
    }
    /// End of the buffered input in the main buffer.
    #[inline(always)]
    pub fn rend(&self) -> usize {
        (if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_end } else { self.rend_p }) as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn set_rpos(&mut self, n: usize) {
        let p = self.buf.wrapping_add(n);
        if self.flags & (F_UNGOT | F_WIDE) != 0 { self.save_base = p } else { self.rptr = p }
    }
    /// Main get area = `buf[pos..end]`. (Kept in `save_base`/`save_end` while pushed-back bytes are read, and on a wide stream,
    /// whose bytes are the wide functions' own: the visible pointers stay equal, so the inline getc_unlocked of stdio.h and
    /// gnulib's freadahead see no bytes there, as with glibc, whose wide streams convert their bytes into a buffer of their own.)
    #[inline(always)]
    pub fn set_read(&mut self, pos: usize, end: usize) {
        let (p, e) = (self.buf.wrapping_add(pos), self.buf.wrapping_add(end));
        if self.flags & (F_UNGOT | F_WIDE) != 0 {
            self.save_base = p;
            self.save_end = e;
        } else {
            self.rptr = p;
            self.rend_p = e;
            self.rbase = self.buf;
        }
    }
    /// The stream becomes wide oriented (call before setting F_WIDE): its read window moves to `save_base`/`save_end` (see
    /// `set_read`); the visible pointers are left equal.
    pub fn hide_read_window(&mut self) {
        if self.flags & (F_UNGOT | F_WIDE) == 0 {
            self.save_base = self.rptr;
            self.save_end = self.rend_p;
            self.rptr = self.rend_p;
        }
    }
    /// Pushed-back bytes not yet read.
    #[inline(always)]
    pub fn nunget(&self) -> usize {
        if self.flags & F_UNGOT != 0 { self.rend_p as usize - self.rptr as usize } else { 0 }
    }
    /// Bytes of pending output.
    /// True if the buffer holds output to write (`F_WRMODE`). Output written straight into the buffer from outside, as
    /// glibc's pointers allow (fmt's `fmt::print(FILE*)` stores at `_IO_write_ptr` up to `_IO_buf_end` and moves the pointer,
    /// also after an fflush has left the stream out of write mode), counts too: like glibc, whose pending output is
    /// `_IO_write_ptr - _IO_write_base`, the stream is then put back in write mode so the bytes are not dropped.
    #[inline(always)]
    pub fn writing(&mut self) -> bool {
        self.flags & F_WRMODE != 0 || (self.wptr > self.wbase && self.adopt_output())
    }
    #[cold]
    #[inline(never)]
    fn adopt_output(&mut self) -> bool {
        if self.flags & F_RDMODE == 0 && !self.wbase.is_null() {
            self.flags |= F_WRMODE;
            self.set_wpos(self.wpos()); // the room for the inline putc as in write mode
            self.hint_output();
            return true;
        }
        false
    }
    /// Size of the buffer (`_IO_buf_end - _IO_buf_base`).
    #[inline(always)]
    pub fn bufsize(&self) -> usize {
        self.buf_end as usize - self.buf as usize
    }
    #[inline(always)]
    pub fn wpos(&self) -> usize {
        self.wptr as usize - self.wbase as usize
    }
    /// Pending output = `buf[..n]`; the room the inline putc may use follows the buffering mode (see `File`).
    #[inline(always)]
    pub fn set_wpos(&mut self, n: usize) {
        self.wbase = self.buf;
        self.wptr = self.buf.wrapping_add(n);
        self.wend = if self.flags & (F_WRMODE | F_UNBUF | F_LBF | F_WIDE) == F_WRMODE && !self.buf.is_null() {
            self.buf_end
        } else {
            self.buf
        };
    }
    /// A new buffer (or none), nothing buffered in it.
    pub fn set_buffer(&mut self, b: *mut u8, size: usize) {
        self.buf = b;
        self.buf_end = b.wrapping_add(size);
        self.set_read(0, 0);
        self.set_wpos(0);
    }

    /// `buf[from..from + n]`.
    ///
    /// # Safety
    /// The buffer invariant holds (see `File`), `from + n <= bufsize()`, and the slice is not used after the buffer is replaced
    /// or freed, nor alongside another live slice of the same bytes (its lifetime is not tied to `self`, so that it can be
    /// handed to a function that also takes the stream).
    #[inline(always)]
    pub unsafe fn buf_slice<'b>(&self, from: usize, n: usize) -> &'b [u8] {
        debug_assert!(from + n <= self.bufsize());
        // SAFETY: the caller's promise: `buf + from` starts `n` bytes of the stream's buffer.
        unsafe { core::slice::from_raw_parts(self.buf.wrapping_add(from), n) }
    }

    /// `buf[from..from + n]`, writable.
    ///
    /// # Safety
    /// As `buf_slice`.
    #[inline(always)]
    pub unsafe fn buf_slice_mut<'b>(&self, from: usize, n: usize) -> &'b mut [u8] {
        debug_assert!(from + n <= self.bufsize());
        // SAFETY: the caller's promise: `buf + from` starts `n` bytes of the stream's buffer, no other slice of them is live.
        unsafe { core::slice::from_raw_parts_mut(self.buf.wrapping_add(from), n) }
    }

    /// The current get area `rptr..rend_p` (buffered input or pushed-back bytes; empty when `rptr >= rend_p`).
    #[inline(always)]
    pub fn window(&self) -> &[u8] {
        // (compared as addresses, like the length below: a caller's test of the length then folds with this one)
        let (r, e) = (self.rptr as usize, self.rend_p as usize);
        if r >= e {
            return &[];
        }
        // SAFETY: the buffer invariant (see `File`): `rptr..rend_p` lies inside the current get area, which outlives this
        // borrow of the stream (it changes only through `&mut File`).
        unsafe { core::slice::from_raw_parts(self.rptr, e - r) }
    }

    /// The byte just before `rptr`; the caller checked that `rptr` is past the start of its area (`rbase` or `buf`).
    #[inline(always)]
    fn byte_before(&self) -> u8 {
        // SAFETY: the caller checked `rptr > rbase` (pushback area) or `buf < rptr <= buf_end` (buffer): by the buffer
        // invariant the byte before `rptr` belongs to that area.
        unsafe { *self.rptr.wrapping_sub(1) }
    }

    /// The byte at `rptr` and the read position moved past it; the caller checked `rptr < rend_p`.
    #[inline(always)]
    fn take_byte(&mut self) -> u8 {
        let p = self.rptr;
        debug_assert!(p < self.rend_p);
        // SAFETY: the caller checked `rptr < rend_p`: by the buffer invariant `p` is a byte of the current get area.
        let c = unsafe { *p };
        self.rptr = p.wrapping_add(1);
        c
    }

    /// The wide-stream state, if the stream became wide.
    #[inline(always)]
    pub fn wide_ref(&self) -> Option<&crate::wfile::WideInfo> {
        // SAFETY: `wide` is null or the stream's own block, set by `wfile` and freed only by `free_wide` (which nulls it), and
        // reached only under the stream's access rule (see `File`).
        unsafe { self.wide.as_ref() }
    }

    /// The wide-stream state, writable.
    #[inline(always)]
    pub fn wide_mut(&mut self) -> Option<&mut crate::wfile::WideInfo> {
        // SAFETY: as `wide_ref`; `&mut self` makes this the only reference to the block.
        unsafe { self.wide.as_mut() }
    }

    /// This stream's `Shared` part (None for a `File` that is not part of a `Stream`).
    #[inline(always)]
    pub(crate) fn shared(&self) -> Option<&Shared> {
        // SAFETY: `shared` is null or this stream's `Shared` part (set by `Stream::new`), which is outside the `File`'s bytes,
        // lives as long as the `File` (the same allocation) and is used only through shared references (atomics, the lock).
        unsafe { self.shared.as_ref() }
    }

    /// The walkers' hint for the stream as it is now (see `Shared::hint`).
    #[inline]
    fn hint_now(&self) -> u8 {
        let fl = self.flags;
        let flush = fl & F_WRMODE != 0 || (fl & F_MEM != 0 && self.io.sync.is_some()) || has_unread_fd_input(self);
        (if flush { H_FLUSH } else { 0 }) | if fl & (F_LBF | F_WRMODE) == F_LBF | F_WRMODE { H_LBF_OUT } else { 0 }
    }

    /// Publish the walkers' hint for the stream as it is now (see `Shared::hint`): the exact answer, which may clear bits.
    /// Only in a multithreaded process (the walkers of a single-threaded one do not read the hint; a stream made before
    /// the first thread keeps `H_ALL` until then, and a thread blocked in a read began it after the first thread existed):
    /// bits are added (`hint_add`, `hint_output`, cheap) when output becomes pending, when a read brings input and when a
    /// byte is pushed back; the exact answer is published when pending output has been written out, right before a read from the
    /// descriptor or cookie (nothing is buffered then: a reader blocked on a terminal or a pipe does not stall fflush(NULL)),
    /// and by a walker that flushed the stream. So the hint is never "clean" while output is pending, input is buffered or a
    /// memory stream has a sync hook; it can only be stale towards "look at it" (input used up or thrown away by a seek),
    /// which costs a walker a lock and a look, never a skipped flush. Not published at every unlock: that doubled the cost
    /// of a locked clearerr or flockfile/funlockfile pair. The one difference from reading the flags: a thread that keeps a
    /// stream locked (flockfile) after using up its buffered input without reading again makes fflush(NULL) wait for it
    /// (glibc's own fflush(NULL) waits for every locked stream).
    #[inline(never)]
    pub(crate) fn publish_hint(&self) {
        if let Some(sh) = self.shared() {
            sh.hint.store(self.hint_now(), Ordering::Relaxed);
        }
    }

    /// `publish_hint` in a multithreaded process only (see there).
    #[inline(always)]
    fn publish_hint_mt(&self) {
        if multithreaded() {
            self.publish_hint();
        }
    }

    /// Add `bits` to the walkers' hint (see `publish_hint`). Nothing in a single-threaded process, whose streams keep the
    /// hint "look at everything" they were made with (`H_ALL`): a stream starts to keep its hint exact once threads exist.
    #[inline(always)]
    fn hint_add(&self, bits: u8) {
        if !multithreaded() {
            return;
        }
        if let Some(sh) = self.shared() {
            // (only the thread working on the stream writes the hint: a load and a store, no locked instruction; usually
            // the bits are already there and nothing is stored)
            let h = sh.hint.load(Ordering::Relaxed);
            if h & bits != bits {
                sh.hint.store(h | bits, Ordering::Relaxed);
            }
        }
    }

    /// The stream entered write mode: output may now be pending (see `publish_hint`).
    #[inline(always)]
    fn hint_output(&self) {
        self.hint_add(if self.flags & F_LBF != 0 { H_FLUSH | H_LBF_OUT } else { H_FLUSH });
    }
}

/// The stream behind a C `FILE *`.
///
/// # Safety
/// `f` points to an open stream and the calling thread may work on it (the access rule at `File`: lock held, one thread, or
/// caller locking), for the returned lifetime, during which no other `&mut File` to it is used.
#[inline(always)]
pub unsafe fn stream<'a>(f: *mut File) -> &'a mut File {
    // SAFETY: the caller's promise.
    unsafe { &mut *f }
}

// The standard streams live in static storage (C reaches them through `stdin`, `stdout`, `stderr`; the access rule at `File`
// applies to them as to every stream).
pub static STDIN_FILE: SyncCell<Stream> =
    SyncCell::new(Stream::new(F_READ | F_STATIC, 0, shared_part((&raw const STDIN_FILE).cast()), H_ALL));
pub static STDOUT_FILE: SyncCell<Stream> =
    SyncCell::new(Stream::new(F_WRITE | F_STATIC, 1, shared_part((&raw const STDOUT_FILE).cast()), H_ALL));
pub static STDERR_FILE: SyncCell<Stream> = SyncCell::new(Stream::new(
    F_WRITE | F_STATIC | F_UNBUF | F_DECIDED,
    2,
    shared_part((&raw const STDERR_FILE).cast()),
    H_ALL,
));

/// The address of a stream's `Shared` part (for its `File::shared`), computed without a reference or a dereference (a
/// `SyncCell<Stream>` is a `Stream`: `repr(transparent)`).
const fn shared_part(s: *const Stream) -> *const Shared {
    s.cast::<u8>().wrapping_add(core::mem::offset_of!(Stream, shared)).cast()
}

/// The `FILE *` of a static stream.
#[inline(always)]
pub const fn static_file(s: &'static SyncCell<Stream>) -> *mut File {
    s.as_ptr().cast()
}

/// The list of open streams, for fflush(NULL) and exit: its head. Read and written only under `LIST` (or while the process has
/// one thread).
static OPEN_HEAD: SyncCell<*mut File> = SyncCell::new(null_mut());
static STD_LINKED: AtomicBool = AtomicBool::new(false);
/// Protects `OPEN_HEAD`, the `next`/`prev` links and every `linked` flag (in `Shared`). A leaf lock: nothing
/// blocking is acquired while it is held and no user callback runs under it.
static LIST: RawMutex = RawMutex::new();

/// The head of the open-stream list.
///
/// # Safety
/// The caller holds `LIST` or the process has one thread.
#[inline(always)]
unsafe fn head() -> *mut File {
    // SAFETY: the caller's promise: no thread writes the head meanwhile.
    unsafe { OPEN_HEAD.read() }
}

/// # Safety
/// As `head`.
#[inline(always)]
unsafe fn set_head(p: *mut File) {
    // SAFETY: the caller's promise: no other thread reads or writes the head meanwhile.
    unsafe { OPEN_HEAD.write(p) }
}

/// The `Shared` part of a stream in the list or pinned by the caller (a reference to that part only: the thread that holds
/// the lock may be working on the `File` meanwhile).
///
/// # Safety
/// `p` is a stream (a `Stream`: from `alloc_file` or a standard stream, as every `FILE *` the library hands out) in the
/// open-stream list (with `LIST` held) or pinned or otherwise kept alive by the caller for `'a`.
#[inline(always)]
pub(crate) unsafe fn shared_of<'a>(p: *mut File) -> &'a Shared {
    // SAFETY: the caller's promise: `p` is the start of a live `Stream` (its `File` is first); a place projection to the
    // `shared` field, no reference to the `File`; the part is shared by design (atomics, the lock).
    unsafe { &(*p.cast::<Stream>()).shared }
}

/// The lock of a stream (see `shared_of`).
///
/// # Safety
/// As `shared_of`.
#[inline(always)]
pub(crate) unsafe fn lock_of<'a>(p: *mut File) -> &'a FLock {
    // SAFETY: the caller's promise.
    &unsafe { shared_of(p) }.lock
}



/// The next stream in the list.
///
/// # Safety
/// `p` is in the list and the caller holds `LIST` (or the process has one thread).
#[inline(always)]
unsafe fn next_of(p: *mut File) -> *mut File {
    // SAFETY: the caller's promise (`LIST` orders the link's writes and reads).
    unsafe { shared_of(p) }.next.load(Ordering::Relaxed)
}

/// The stream the public variable `stdin` names now. glibc's printf, puts, putchar, scanf, getchar, perror, err, ... use the
/// variable, which a program may assign (`stdout = fopen (...)`, glibc's tst-bz24051 does).
#[inline(always)]
pub fn stdin_ptr() -> *mut File {
    // SAFETY: an aligned pointer-sized static; a program assigns it only before it uses the stream (C's rule for these
    // variables), and the read is volatile so a store by the program is seen.
    unsafe { crate::file_api::stdin.as_ptr().read_volatile() }
}
#[inline(always)]
pub fn stdout_ptr() -> *mut File {
    // SAFETY: as `stdin_ptr`.
    unsafe { crate::file_api::stdout.as_ptr().read_volatile() }
}
#[inline(always)]
pub fn stderr_ptr() -> *mut File {
    // SAFETY: as `stdin_ptr`.
    unsafe { crate::file_api::stderr.as_ptr().read_volatile() }
}

fn link_standard() {
    if STD_LINKED.load(Ordering::Acquire) {
        return;
    }
    let t = LIST.lock();
    if !STD_LINKED.load(Ordering::Relaxed) {
        // SAFETY: `LIST` is held; the standard streams are static.
        unsafe { link_locked(static_file(&STDIN_FILE)) };
        // SAFETY: as above.
        unsafe { link_locked(static_file(&STDOUT_FILE)) };
        // SAFETY: as above.
        unsafe { link_locked(static_file(&STDERR_FILE)) };
        STD_LINKED.store(true, Ordering::Release);
    }
    LIST.unlock(t);
}

/// Put `f` at the head of the list.
///
/// # Safety
/// The caller holds `LIST` (or the process has one thread); `f` is a live stream not in the list.
unsafe fn link_locked(f: *mut File) {
    // SAFETY: the caller's promise (`LIST` held).
    let old = unsafe { head() };
    // SAFETY: `f` is a live stream; its links change only under `LIST`, which is held.
    let sf = unsafe { shared_of(f) };
    sf.next.store(old, Ordering::Relaxed);
    sf.prev.store(null_mut(), Ordering::Relaxed);
    if !old.is_null() {
        // SAFETY: `old` is in the list and `LIST` is held.
        unsafe { shared_of(old) }.prev.store(f, Ordering::Relaxed);
    }
    // SAFETY: `LIST` is held.
    unsafe { set_head(f) };
    sf.linked.store(true, Ordering::Relaxed);
}

/// # Safety
/// `f` is a live stream not in the list.
pub unsafe fn link(f: *mut File) {
    let t = LIST.lock();
    // SAFETY: `LIST` is held; the caller's promise for `f`.
    unsafe { link_locked(f) };
    LIST.unlock(t);
}

/// # Safety
/// `f` is a live stream in the list.
pub unsafe fn unlink(f: *mut File) {
    let t = LIST.lock();
    // SAFETY: the caller's promise; the links change only under `LIST`, which is held.
    let sf = unsafe { shared_of(f) };
    let prev = sf.prev.load(Ordering::Relaxed);
    let next = sf.next.load(Ordering::Relaxed);
    if !prev.is_null() {
        // SAFETY: `prev` is in the list, `LIST` is held.
        unsafe { shared_of(prev) }.next.store(next, Ordering::Relaxed);
    // SAFETY: `LIST` is held.
    } else if unsafe { head() } == f {
        // SAFETY: `LIST` is held.
        unsafe { set_head(next) };
    }
    if !next.is_null() {
        // SAFETY: `next` is in the list, `LIST` is held.
        unsafe { shared_of(next) }.prev.store(prev, Ordering::Relaxed);
    }
    sf.next.store(null_mut(), Ordering::Relaxed);
    sf.prev.store(null_mut(), Ordering::Relaxed);
    sf.linked.store(false, Ordering::Relaxed);
    LIST.unlock(t);
}

/// Visit every open stream with the list lock NOT held while `visit` runs (so it may block on the
/// stream's lock, write, call a cookie function). Each stream is pinned while it is being visited,
/// so `fclose` cannot free it under the visitor; `visit` must check `linked` after taking the
/// stream's lock (a stream closed meanwhile is skipped). If the stream being visited was closed
/// the walk restarts from the head, so a stream can be visited twice: visitors must tolerate that.
/// Only for multithreaded use (callers fall back to a plain walk otherwise). `visit` gets a stream that stays allocated
/// while it runs (pinned) but is not locked.
fn walk_pinned(mut visit: impl FnMut(*mut File)) {
    link_standard();
    LIST.lock_always();
    // SAFETY: `LIST` is held.
    let mut p = unsafe { head() };
    if !p.is_null() {
        // SAFETY: `p` is in the list, `LIST` is held; the pin keeps it alive after the lock is released.
        unsafe { shared_of(p) }.pins.fetch_add(1, Ordering::AcqRel);
    }
    LIST.unlock_always();
    while !p.is_null() {
        visit(p);
        LIST.lock_always();
        // SAFETY: `p` is pinned (not freed); `LIST` is held for its link and for the head.
        let sp = unsafe { shared_of(p) };
        // SAFETY: as above.
        let next = if sp.linked.load(Ordering::Relaxed) { unsafe { next_of(p) } } else { unsafe { head() } };
        if !next.is_null() {
            // SAFETY: `next` is in the list, `LIST` is held.
            unsafe { shared_of(next) }.pins.fetch_add(1, Ordering::AcqRel);
        }
        LIST.unlock_always();
        // SAFETY: our pin kept `p` alive until now.
        unsafe { shared_of(p) }.pins.fetch_sub(1, Ordering::AcqRel);
        p = next;
    }
}

static FORK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register what exit and fork need once any stream is used (flush at exit; fork handlers).
#[inline(always)]
fn note_used() {
    if !FORK_REGISTERED.load(Ordering::Relaxed) {
        note_used_first();
    }
}

#[cold]
#[inline(never)]
fn note_used_first() {
    // the flush hook is set before the flag, and never cleared
    rusty_libc_core::process::set_stdio_flush(flush_at_exit);
    if !FORK_REGISTERED.swap(true, Ordering::AcqRel) {
        rusty_libc_core::process::register_fork_handlers(atfork_prepare, atfork_parent, atfork_child);
    }
}

// ---- raw I/O (file descriptor or cookie) ----

fn raw_read(f: &mut File, dst: &mut [u8]) -> isize {
    // the read may block (a terminal, a pipe, a cookie): walkers must not wait for this stream unless it needs them
    f.publish_hint_mt();
    if f.flags & F_MEM != 0 {
        return match f.io.read {
            Some(r) => {
                // SAFETY: a cookie read function (fopencookie's or a memory stream's) called as its contract says: with the
                // stream's cookie and a buffer of `len` writable bytes.
                let got = unsafe { r(f.cookie, dst.as_mut_ptr().cast(), dst.len()) };
                if got > 0 {
                    f.cookie_pos += got as i64;
                }
                got
            }
            None => {
                errno::set(9);
                -1
            }
        };
    }
    let r = if f.flags & F_NOCANCEL != 0 { unistd::read_nocancel(f.fd, dst) } else { unistd::read(f.fd, dst) };
    match r {
        Ok(k) => {
            if f.cookie_pos >= 0 {
                f.cookie_pos += k as i64;
            }
            if k > 0 {
                f.hint_add(H_FLUSH); // input from the descriptor may now wait in the buffer
            }
            k as isize
        }
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

fn raw_write(f: &mut File, src: &[u8]) -> isize {
    let n = src.len();
    if f.flags & F_MEM != 0 {
        return match f.io.write {
            Some(w) => {
                // SAFETY: a cookie write function called as its contract says: with the stream's cookie and `n` readable bytes.
                let put = unsafe { w(f.cookie, src.as_ptr().cast(), n) };
                // an appending cookie writes at its own end: ask it where we are next time
                if f.flags & F_APPEND != 0 {
                    f.cookie_pos = -1;
                } else if put > 0 {
                    f.cookie_pos += put as i64;
                }
                // a cookie that accepts nothing has failed (glibc sets the error flag, returns -1)
                if put == 0 && n > 0 {
                    return -1;
                }
                put
            }
            None => {
                errno::set(9);
                -1
            }
        };
    }
    let r = if f.flags & F_NOCANCEL != 0 { unistd::write_nocancel(f.fd, src) } else { unistd::write(f.fd, src) };
    match r {
        Ok(k) => {
            // an appending write lands at the end of the file: the offset is no longer known
            if f.flags & F_APPEND != 0 {
                f.cookie_pos = -1;
            } else if f.cookie_pos >= 0 {
                f.cookie_pos += k as i64;
            }
            k as isize
        }
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

/// lseek on the stream's descriptor or cookie; `Err` carries errno.
fn raw_seek(f: &mut File, off: i64, whence: c_int) -> Result<i64, i32> {
    if f.flags & F_MEM != 0 {
        return match f.io.seek {
            Some(s) => {
                let mut pos = off;
                // SAFETY: a cookie seek function called as its contract says: the stream's cookie and a position to update.
                if unsafe { s(f.cookie, &mut pos, whence) } != 0 {
                    Err(errno::get())
                } else {
                    f.cookie_pos = pos;
                    Ok(pos)
                }
            }
            None => Err(29),
        };
    }
    match unistd::lseek(f.fd, off, whence) {
        Ok(p) => {
            f.cookie_pos = p;
            Ok(p)
        }
        Err(e) => Err(e.0),
    }
}

/// The descriptor's (or cookie's) current offset, asking the kernel only when it is not known.
fn offset(f: &mut File) -> Result<i64, i32> {
    // a stream with nothing buffered (no pending output, no unread input, no pushed-back bytes) is not "active": glibc asks
    // the kernel each time, so a write(2) to the descriptor behind its back shows in ftell (tst-ftell-active-handler)
    let active = f.flags & (F_WRMODE | F_SEEKED) != 0 || f.flags & F_RDMODE != 0 && (f.rpos() < f.rend() || f.nunget() > 0);
    if f.cookie_pos >= 0 && f.flags & F_NOCACHE == 0 && (active || f.flags & F_MEM != 0) {
        Ok(f.cookie_pos)
    } else {
        raw_seek(f, 0, 1)
    }
}

// ---- buffer management ----

/// Decide buffering for a stream not yet used: terminals are line buffered, everything else fully
/// buffered with `min(BUFSIZ, st_blksize)`.
fn decide(f: &mut File) {
    if f.flags & F_DECIDED != 0 {
        return;
    }
    // the first use of any stream makes exit flush all of them
    note_used();
    f.flags |= F_DECIDED;
    if f.flags & F_UNBUF != 0 {
        return;
    }
    if f.buf.is_null() {
        alloc_default(f);
    }
}

/// Give the stream its own buffer, as glibc's doallocate: `min(BUFSIZ, st_blksize)` bytes, and line buffering for a
/// terminal. No memory: the stream becomes unbuffered.
fn alloc_default(f: &mut File) {
    let mut size = BUFSIZ;
    if f.flags & F_MEM == 0
        && f.fd >= 0
        && let Ok((mode, blksize, _)) = unistd::fstat_basic(f.fd)
    {
        if mode & 0o170000 == 0o020000 && unistd::isatty(f.fd) {
            f.flags |= F_LBF;
        }
        if blksize > 0 && (blksize as usize) < BUFSIZ {
            size = blksize as usize;
        }
    }
    let b = alloc(size);
    if b.is_null() {
        f.flags |= F_UNBUF;
        return;
    }
    f.set_buffer(b, size);
}

/// Make sure the stream has somewhere to buffer (or is marked unbuffered).
fn prepare(f: &mut File) {
    if f.flags & F_DECIDED == 0 {
        decide(f);
    } else if f.buf.is_null() && f.flags & F_UNBUF == 0 {
        // line buffering was chosen by setvbuf without a buffer: allocate now, glibc's size (its doallocate)
        alloc_default(f);
    }
}

/// Write out pending output. Returns false (with the error flag set) on failure. On a wide stream this is a flush of
/// glibc's wide buffer: it fails without the error flag when the buffer holds a character the stream cannot write
/// (`wfile::drop_flush`).
pub fn flush_write(f: &mut File) -> bool {
    if f.flags & F_WIDE != 0 {
        return flush_write_wide(f);
    }
    flush_write_keep(f)
}

#[inline(never)]
fn flush_write_wide(f: &mut File) -> bool {
    if crate::wfile::dropping(f) {
        return crate::wfile::drop_flush(f);
    }
    if let Some(w) = f.wide_mut() {
        w.gtot = 0;
    }
    flush_write_keep(f)
}

/// `flush_write` of the byte buffer only (a full buffer while writing: glibc's wide buffer is not flushed by it).
/// (Never inlined: inlined into `put_bytes` it made every call of that function pay for a larger frame.)
#[inline(never)]
pub(crate) fn flush_write_keep(f: &mut File) -> bool {
    if !f.writing() || f.wpos() == 0 {
        let was_writing = f.flags & F_WRMODE != 0;
        f.flags &= !F_WRMODE;
        f.set_wpos(0);
        reset_wextra(f);
        if was_writing {
            f.publish_hint_mt(); // nothing pending any more (a holder of flockfile does not make fflush(NULL) wait for it)
        }
        return true;
    }
    let mut off = 0;
    let n = f.wpos();
    while off < n {
        // SAFETY: `off..n` is pending output inside the buffer (`n` = wpos <= bufsize); the slice lives for this write only.
        let src = unsafe { f.buf_slice(off, n - off) };
        let k = raw_write(f, src);
        if k < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            f.set_wpos(0);
            reset_wextra(f);
            return false;
        }
        off += k as usize;
        if f.flags & F_MEM != 0 && off < n {
            // a cookie that took only part of the data has failed: glibc sets the error flag and does not ask again
            // (the rest of the buffer is lost)
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            f.set_wpos(0);
            reset_wextra(f);
            return false;
        }
    }
    f.flags &= !F_WRMODE;
    f.set_wpos(0);
    reset_wextra(f);
    f.publish_hint_mt(); // nothing pending any more (as above)
    true
}

/// Flush every line-buffered output stream (before a read from a terminal-like stream). Called
/// with the lock of the stream being read held, so another stream's lock is only tried: a stream
/// another thread is writing right now is left to that thread (it flushes at its own newline).
fn flush_line_buffered() {
    flush_lbf(false)
}

/// A stream of the list seen without its lock (the walkers' first look, as glibc's unlocked tests in its older
/// `_IO_flush_all`): the hint (`Shared::hint`, never the `File`'s own flags, which the thread working on the stream may be
/// writing) may be stale towards "look at it"; whatever the walker then does to the stream it does under the stream's lock.
///
/// # Safety
/// As `lock_of`.
#[inline(always)]
unsafe fn peek_hint(p: *mut File) -> u8 {
    // SAFETY: the caller's promise keeps `p` alive.
    unsafe { shared_of(p) }.hint.load(Ordering::Relaxed)
}

/// `blocking`: wait for each stream's lock (`_flushlbf`) instead of skipping busy ones.
fn flush_lbf(blocking: bool) {
    link_standard();
    if !multithreaded() {
        // SAFETY: one thread: nothing else reads or writes the list.
        let mut p = unsafe { head() };
        while !p.is_null() {
            // SAFETY: one thread, `p` is in the list: the only reference to the stream.
            let s = unsafe { stream(p) };
            if s.flags & F_LBF != 0 && s.flags & F_WRMODE != 0 {
                flush_write(s);
            }
            // SAFETY: one thread, `p` is in the list.
            p = unsafe { next_of(p) };
        }
        return;
    }
    walk_pinned(|p| {
        // SAFETY: `p` is pinned by the walk.
        if unsafe { peek_hint(p) } & H_LBF_OUT != 0 {
            // SAFETY: as above.
            let l = unsafe { lock_of(p) };
            if blocking {
                l.lock();
            } else if !l.try_lock() {
                return;
            }
            let mut cg = crate::flock::LockCleanup::idle();
            // SAFETY: we hold `p`'s lock; `cg` stays here until it is disarmed.
            unsafe { cg.arm(p) };
            // SAFETY: pinned and locked by us: this thread may work on the stream.
            let s = unsafe { stream(p) };
            // SAFETY: as above.
            if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) && s.writing() {
                flush_write(s);
            }
            s.publish_hint();
            cg.disarm();
            l.unlock();
        }
    });
}

/// Close every open stream (fcloseall).
pub(crate) fn close_all() {
    link_standard();
    if !multithreaded() {
        loop {
            // SAFETY: one thread.
            let p = unsafe { head() };
            if p.is_null() {
                return;
            }
            // SAFETY: `p` is an open stream; with one thread nobody else uses it.
            unsafe { fclose(p) };
        }
    }
    loop {
        LIST.lock_always();
        // SAFETY: `LIST` is held.
        let p = unsafe { head() };
        if p.is_null() {
            LIST.unlock_always();
            return;
        }
        // SAFETY: `p` is in the list and `LIST` is held.
        unsafe { shared_of(p) }.pins.fetch_add(1, Ordering::AcqRel);
        LIST.unlock_always();
        // SAFETY: our pin keeps `p` allocated; `close_stream` with `pinned` drops it.
        unsafe { close_stream(p, true) };
    }
}

/// Start `/bin/sh -c -- command` for popen's stream `f` (glibc's spawn_process, run with the open-stream list locked so no
/// other popen stream can appear or go meanwhile): the child gets `child_end` as descriptor `target` and does not inherit
/// the pipes of the other popen streams (POSIX); then, still under the lock, the parent closes `child_end`, makes
/// `parent_end` inheritable unless `cloexec` ("e"), and records the pid. Returns 0 or the spawn's error number.
///
/// # Safety
/// `command` is a NUL-terminated string.
pub(crate) unsafe fn popen_spawn(f: &mut File, command: *const c_char, child_end: c_int, target: c_int, parent_end: c_int, cloexec: bool) -> c_int {
    use rusty_libc_core::spawn::{A_CLOSE, A_DUP2, PosixSpawnFileActions, SpawnAction, spawnix};
    let act = |tag, fd, arg| SpawnAction { tag, fd, arg, mode: 0, path: null_mut() };
    let t = LIST.lock();
    // the popen streams' descriptors (the list is stable: `LIST` is held; `f` is not in it yet or has pid 0)
    let mut fds = PopenFds { p: null_mut() };
    // SAFETY: `LIST` is held.
    fds.p = unsafe { head() };
    let n = 1 + PopenFds { p: fds.p }.count();
    let mut local = [act(0, 0, 0); 16];
    let mut heap: *mut SpawnAction = null_mut();
    if n > local.len() {
        heap = alloc(n * size_of::<SpawnAction>()).cast();
        if heap.is_null() {
            LIST.unlock(t);
            return 12; // ENOMEM
        }
    }
    let acts: &mut [SpawnAction] = if heap.is_null() {
        &mut local
    } else {
        // SAFETY: a fresh block with room for `n` actions, seen as not yet initialised.
        let raw = unsafe { core::slice::from_raw_parts_mut(heap.cast::<core::mem::MaybeUninit<SpawnAction>>(), n) };
        for a in raw.iter_mut() {
            a.write(act(0, 0, 0));
        }
        // SAFETY: every element was initialised just above.
        unsafe { &mut *(raw as *mut [core::mem::MaybeUninit<SpawnAction>] as *mut [SpawnAction]) }
    };
    acts[0] = act(A_DUP2, child_end, target);
    let mut used = 1usize;
    for fd in fds {
        // (an earlier popen stream whose descriptor is `target` was replaced by the dup already: glibc skips it)
        if fd != target {
            acts[used] = act(A_CLOSE, fd, 0);
            used += 1;
        }
    }
    let fa = PosixSpawnFileActions { allocated: used as c_int, used: used as c_int, actions: acts.as_mut_ptr(), pad: [0; 16] };
    let argv: [*const c_char; 5] = [c"sh".as_ptr(), c"-c".as_ptr(), c"--".as_ptr(), command, core::ptr::null()];
    // SAFETY: the environment block the library keeps (read by the spawn, as glibc's popen passes `environ`).
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    let mut pid: c_int = 0;
    // SAFETY: valid path, file actions (`used` initialised entries), NUL-terminated argv (`command` per the caller) and the
    // environment block.
    let err = unsafe { spawnix(&mut pid, c"/bin/sh".as_ptr(), &fa, core::ptr::null(), argv.as_ptr(), env, false, false) };
    if err == 0 {
        let _ = unistd::close(child_end);
        if !cloexec {
            // undo the O_CLOEXEC of pipe2 on the parent's end (glibc leaves it inheritable unless the mode has "e")
            let _ = unistd::fcntl_int(parent_end, 2 /* F_SETFD */, 0);
        }
        f.pid = pid;
    }
    LIST.unlock(t);
    if !heap.is_null() {
        // SAFETY: allocated above, no longer used.
        unsafe { free(heap.cast()) };
    }
    err
}

/// The descriptors of the popen streams in the open-stream list, from `p` on (`LIST` held by the user).
struct PopenFds {
    p: *mut File,
}

impl Iterator for PopenFds {
    type Item = c_int;
    fn next(&mut self) -> Option<c_int> {
        while !self.p.is_null() {
            // SAFETY: built by `popen_spawn` from the list head with `LIST` held: every stream reached is in the list; `pid`
            // and `fd` of a popen stream are set under `LIST` (popen_spawn) or at its opening.
            let pid = unsafe { (*self.p).pid };
            // SAFETY: as above.
            let fd = unsafe { (*self.p).fd };
            // SAFETY: as above (`LIST` is held).
            let next = unsafe { next_of(self.p) };
            self.p = next;
            if pid > 0 && fd >= 0 {
                return Some(fd);
            }
        }
        None
    }
}

/// Throw away buffered data without writing or reading it (`__fpurge`).
pub(crate) fn purge(f: &mut File) {
    reset_wextra(f);
    drop_unget(f);
    drop_wpush(f);
    f.flags &= !(F_RDMODE | F_WRMODE);
    f.set_read(0, 0);
    f.set_wpos(0);
}

pub(crate) fn flush_line_buffered_pub() {
    flush_lbf(true)
}

/// Make sure exit flushes and the fork handlers exist once the program uses locking explicitly.
#[inline]
pub fn note_locking() {
    note_used();
}

/// A memory stream tells its owner buffer and size at every flush.
#[inline]
fn sync_mem(f: &mut File) {
    if f.flags & F_MEM != 0
        && let Some(sy) = f.io.sync
    {
        // SAFETY: the sync hook of our memory streams, called with the stream's cookie as it expects.
        unsafe { sy(f.cookie) };
    }
}

/// A stream that fflush(NULL) or the exit flush has to look at: pending output, or a memory stream
/// that publishes its buffer at each flush.
///
/// # Safety
/// As `peek_hint` (the walkers' unlocked first look).
#[inline]
unsafe fn needs_flush(p: *mut File) -> bool {
    // SAFETY: the caller's promise; the answer is rechecked under the stream's lock.
    (unsafe { peek_hint(p) }) & H_FLUSH != 0
}

/// A stream on a descriptor that has read ahead of the program: fflush(NULL) and exit move the descriptor's offset back to
/// the logical position (glibc's `_IO_flush_all` syncs such streams; POSIX asks it for stdin at exit).
#[inline]
fn has_unread_fd_input(p: &File) -> bool {
    p.flags & (F_RDMODE | F_MEM) == F_RDMODE && p.fd >= 0 && (p.rend() > p.rpos() || p.nunget() > 0)
}

/// `__libc_freeres`: valgrind calls it at the very end so that the library's own memory does not show as still in use. Every
/// stream is flushed, then the buffers the library allocated (not a program's setvbuf buffer) and the pushback areas are
/// given back; a stream used after this gets a new buffer on its next operation (prepare), as glibc's.
pub fn freeres() {
    flush_all();
    let t = LIST.lock();
    // SAFETY: `LIST` is held.
    let mut p = unsafe { head() };
    while !p.is_null() {
        // SAFETY: valgrind calls this at the very end, with no other thread using a stream; `p` is in the list.
        let s = unsafe { stream(p) };
        drop_unget(s);
        if !s.buf.is_null() && s.flags & F_USERBUF == 0 && s.rpos() >= s.rend() {
            // SAFETY: the stream's own buffer (not F_USERBUF), dropped from the stream right after.
            unsafe { free(s.buf) };
            s.set_buffer(null_mut(), 0);
        }
        // SAFETY: `LIST` is held, `p` is in the list.
        p = unsafe { next_of(p) };
    }
    LIST.unlock(t);
}

/// What fflush(NULL) and the exit flush do to one stream (locked by the caller, or one thread); false if a step failed.
fn flush_one(s: &mut File) -> bool {
    let mut ok = true;
    sync_mem(s);
    if s.writing() && !flush_write(s) {
        ok = false;
    }
    if has_unread_fd_input(s) && !sync_input(s) {
        ok = false;
    }
    ok
}

/// Flush all open output streams (fflush(NULL)), locking each in turn; false if any failed.
pub fn flush_all() -> bool {
    link_standard();
    let mut ok = true;
    if !multithreaded() {
        // SAFETY: one thread.
        let mut p = unsafe { head() };
        while !p.is_null() {
            // SAFETY: one thread, `p` is in the list.
            let s = unsafe { stream(p) };
            ok &= flush_one(s);
            // SAFETY: one thread, `p` is in the list.
            p = unsafe { next_of(p) };
        }
        return ok;
    }
    walk_pinned(|p| {
        // (a clean stream is not locked: a thread blocked in a read must not stall fflush(NULL))
        // SAFETY: `p` is pinned by the walk.
        if !unsafe { needs_flush(p) } {
            return;
        }
        // SAFETY: as above.
        let l = unsafe { lock_of(p) };
        l.lock();
        let mut cg = crate::flock::LockCleanup::idle();
        // SAFETY: we hold `p`'s lock; `cg` stays here until it is disarmed.
        unsafe { cg.arm(p) };
        // SAFETY: pinned and locked by us.
        let s = unsafe { stream(p) };
        // SAFETY: as above.
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            ok &= flush_one(s);
        }
        s.publish_hint();
        cg.disarm();
        l.unlock();
    });
    ok
}

/// How long exit waits for one stream's lock before it flushes the stream anyway (TSC cycles).
const EXIT_LOCK_WAIT: u64 = 10_000_000;

/// The exit-time flush: like fflush(NULL), but a stream whose lock another thread keeps is flushed
/// anyway after a bounded wait (glibc's `_IO_cleanup` takes no locks at all).
extern "C" fn flush_at_exit() {
    if !multithreaded() {
        flush_all();
        return;
    }
    walk_pinned(|p| {
        // SAFETY: `p` is pinned by the walk.
        if !unsafe { needs_flush(p) } {
            return;
        }
        // SAFETY: as above.
        let l = unsafe { lock_of(p) };
        let got = l.lock_timeout(EXIT_LOCK_WAIT);
        // SAFETY: pinned; locked by us, or (after the bounded wait) taken over at exit as glibc's `_IO_cleanup` does with no
        // lock at all: the holder is stuck and the process is ending.
        let s = unsafe { stream(p) };
        // SAFETY: as above.
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            flush_one(s);
        }
        if got {
            s.publish_hint();
            l.unlock();
        }
    });
}

// ---- fork ----

/// How long the fork handler waits for one stream's lock (TSC cycles, roughly 50 ms): a thread blocked
/// in a read holds its stream's lock indefinitely, and fork must not wait for it.
const FORK_LOCK_WAIT: u64 = 150_000_000;
static FORK_LOCK: RawMutex = RawMutex::new();
static FORK_REAL: AtomicBool = AtomicBool::new(false);

/// The fork handler's mark on a stream (`fork_held`). Used only by the forking thread under `FORK_LOCK` (Relaxed).
///
/// # Safety
/// `p` is pinned or in the list with `LIST` held; the caller holds `FORK_LOCK`.
#[inline(always)]
unsafe fn fork_mark<'a>(p: *mut File) -> &'a AtomicU8 {
    // SAFETY: the caller's promise keeps `p` alive.
    &unsafe { shared_of(p) }.fork_held
}

/// # Safety
/// As `fork_mark`.
pub(crate) unsafe fn fork_grab(p: *mut File) {
    // SAFETY: the caller's promise.
    let mark = unsafe { fork_mark(p) };
    // `walk_pinned` restarts from the head when a stream is closed under it, so a stream can come round twice: taking
    // its (recursive) lock again would leave one level held after `atfork_release` and the stream locked for ever
    // (malloc/tst-malloc-fork-deadlock: readers closing their streams while other threads fork)
    if mark.load(Ordering::Relaxed) != 0 {
        return;
    }
    // SAFETY: the caller's promise keeps `p` alive.
    let l = unsafe { lock_of(p) };
    if l.lock_timeout(FORK_LOCK_WAIT) {
        // SAFETY: as above.
        if unsafe { shared_of(p) }.linked.load(Ordering::Relaxed) {
            mark.store(1, Ordering::Relaxed);
        } else {
            l.unlock();
        }
    } else {
        mark.store(2, Ordering::Relaxed);
    }
}

/// Before fork: take the fork lock, every stream's lock (waiting at most `FORK_LOCK_WAIT` for each)
/// and then the list lock, so the child inherits streams in a consistent state and no lock owned by
/// another thread. Does nothing in a single-threaded process.
extern "C" fn atfork_prepare() {
    if !multithreaded() {
        FORK_REAL.store(false, Ordering::Relaxed);
        return;
    }
    FORK_LOCK.lock_always();
    FORK_REAL.store(true, Ordering::Relaxed);
    // pass 1: every stream in the list, never blocking on one thread for long
    // SAFETY: `p` is pinned by the walk; `FORK_LOCK` is held.
    walk_pinned(|p| unsafe { fork_grab(p) });
    // pass 2: with the list lock held, catch streams created meanwhile (keep the list lock when
    // every stream is ours)
    loop {
        LIST.lock_always();
        // SAFETY: `LIST` is held.
        let mut q = unsafe { head() };
        let mut missing: *mut File = null_mut();
        while !q.is_null() {
            // SAFETY: `q` is in the list, `LIST` and `FORK_LOCK` are held.
            let mark = unsafe { fork_mark(q) };
            if mark.load(Ordering::Relaxed) == 0 {
                // SAFETY: `q` is in the list, `LIST` is held.
                if unsafe { lock_of(q) }.try_lock() {
                    mark.store(1, Ordering::Relaxed);
                } else {
                    missing = q;
                    break;
                }
            }
            // SAFETY: `LIST` is held.
            q = unsafe { next_of(q) };
        }
        if missing.is_null() {
            return;
        }
        // SAFETY: `missing` is in the list, `LIST` is held; the pin keeps it alive after the lock is released.
        let pins = &unsafe { shared_of(missing) }.pins;
        pins.fetch_add(1, Ordering::AcqRel);
        LIST.unlock_always();
        // SAFETY: pinned; `FORK_LOCK` is held.
        unsafe { fork_grab(missing) };
        pins.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Undo `atfork_prepare` (list lock held by us): in the parent unlock what we took; in the child the
/// forking thread owns those locks, so it unlocks them the same way, forgets the owners of the streams
/// we gave up on, and clears the pins of walkers that no longer exist.
fn atfork_release(child: bool) {
    // SAFETY: `atfork_prepare` left `LIST` (and `FORK_LOCK`) held by this thread.
    let mut q = unsafe { head() };
    while !q.is_null() {
        // SAFETY: `q` is in the list, `LIST` and `FORK_LOCK` are held.
        let mark = unsafe { fork_mark(q) };
        // SAFETY: as above.
        let l = unsafe { lock_of(q) };
        match mark.load(Ordering::Relaxed) {
            1 => {
                l.unlock();
            }
            // SAFETY: in the child only this thread exists: nobody else can be using the lock.
            2 if child => unsafe { l.reset() },
            _ => {}
        }
        mark.store(0, Ordering::Relaxed);
        if child {
            // SAFETY: `q` is in the list, `LIST` is held.
            unsafe { shared_of(q) }.pins.store(0, Ordering::Relaxed);
        }
        // SAFETY: `LIST` is held.
        q = unsafe { next_of(q) };
    }
    LIST.unlock_always();
    FORK_LOCK.unlock_always();
}

extern "C" fn atfork_parent() {
    if FORK_REAL.load(Ordering::Relaxed) {
        atfork_release(false);
    }
}

extern "C" fn atfork_child() {
    if FORK_REAL.load(Ordering::Relaxed) {
        atfork_release(true);
    }
}

/// Drop unread input, moving the descriptor's offset back to the stream's logical position.
pub(crate) fn discard_input(f: &mut File, sync: bool) {
    let mut unread = (f.rend() - f.rpos()) + f.nunget();
    if let Some(w) = f.wide_ref() {
        // glibc syncs a UTF-8 wide stream to its (shifted) idea of the position
        unread += w.tshift;
    }
    if sync && unread > 0 && f.flags & F_NOSEEK == 0 {
        let _ = raw_seek(f, -(unread as i64), 1);
    }
    drop_unget(f);
    f.set_read(0, 0);
    drop_wpush(f);
    f.flags &= !F_RDMODE;
}

/// Switch the stream to writing. False (error set) if it is not writable.
pub(crate) fn start_write(f: &mut File) -> bool {
    if f.flags & F_WRITE == 0 {
        f.flags |= F_ERR;
        errno::set(9);
        return false;
    }
    if f.flags & F_RDMODE != 0 {
        // writing continues at the logical position of the buffered input; pushed-back
        // characters beyond the buffer do not move it (observed in glibc)
        // (a wide stream that has never been written has decoded everything it read ahead; glibc's first
        // wide write does not go back over it, later ones do)
        // glibc frees the backup area and slides the read base back over as many consumed bytes as there are pushed-back
        // ones (at most the bytes the buffer had consumed): the write starts that much earlier (bug-ungetc2)
        let unread = (f.rend() - f.rpos()) + f.nunget().min(f.rpos());
        let keep_ahead = f.flags & F_WIDE != 0 && f.wide_ref().is_some_and(|w| !w.wbuf && w.ahead);
        if unread > 0 && f.flags & F_NOSEEK == 0 && !keep_ahead {
            let _ = raw_seek(f, -(unread as i64), 1);
        }
        drop_unget(f);
        f.set_read(0, 0);
        drop_wpush(f);
        f.flags &= !F_RDMODE;
    }
    if f.writing() {
        // bytes stored straight into the buffer (see `File::writing`): keep them
        f.flags |= F_PUTTING;
        return true;
    }
    prepare(f);
    f.flags |= F_WRMODE | F_PUTTING;
    f.set_wpos(0);
    f.hint_output();
    true
}

/// Switch the stream to reading and make sure there is input (or EOF). Returns false at EOF/error.
fn underflow(f: &mut File) -> bool {
    underflow_keep(f, 0)
}

/// Refill the buffer. The first `keep` unread bytes (an incomplete multibyte character) stay at the
/// front of the buffer and the new data follows them (`rpos` is 0 afterwards).
pub(crate) fn underflow_keep(f: &mut File, keep: usize) -> bool {
    if f.flags & F_READ == 0 {
        f.flags |= F_ERR;
        errno::set(9);
        return false;
    }
    if f.writing() && !flush_write(f) {
        return false;
    }
    if f.flags & F_EOF != 0 {
        return false;
    }
    drop_unget(f);
    prepare(f);
    if f.flags & (F_LBF | F_UNBUF) != 0 {
        flush_line_buffered();
    }
    if f.flags & F_UNBUF != 0 || f.buf.is_null() {
        // unbuffered: read one byte through a tiny internal buffer
        if f.buf.is_null() {
            let size = if keep > 0 { 8 } else { 1 };
            let b = alloc(size);
            if b.is_null() {
                // no memory: the stream's own small buffer (never freed)
                let sb = f.shortbuf.as_mut_ptr();
                f.set_buffer(sb, size);
                f.flags |= F_USERBUF;
            } else {
                f.set_buffer(b, size);
            }
        }
        keep_front(f, keep);
        // SAFETY: `keep + 1 <= bufsize` (a buffer made here has 8 bytes when `keep > 0`); the slice lives for this read only.
        let dst = unsafe { f.buf_slice_mut(keep, 1) };
        let k = raw_read(f, dst);
        return finish_read(f, k, keep);
    }
    keep_front(f, keep);
    // SAFETY: `keep <= bufsize`; the slice lives for this read only.
    let dst = unsafe { f.buf_slice_mut(keep, f.bufsize() - keep) };
    let k = raw_read(f, dst);
    finish_read(f, k, keep)
}

/// Move the last `keep` unread bytes to the front of the buffer and make them the whole get area.
fn keep_front(f: &mut File, keep: usize) {
    if keep > 0 {
        let from = f.rpos();
        // SAFETY: `from + keep` (the unread bytes) lies inside the buffer; the slice lives for this copy only.
        unsafe { f.buf_slice_mut(0, from + keep) }.copy_within(from.., 0);
    }
    f.set_read(0, keep);
}

fn finish_read(f: &mut File, k: isize, keep: usize) -> bool {
    if k > 0 {
        f.set_read(0, keep + k as usize);
        f.flags = (f.flags | F_RDMODE) & !F_PUTTING;
        true
    } else if k == 0 {
        if f.flags & F_NOEOF == 0 {
            f.flags |= F_EOF;
        }
        f.flags &= !F_SEEKED;
        false
    } else {
        f.flags |= F_ERR;
        false
    }
}

/// A narrow operation on `f`: fixes byte orientation on first use. False (and nothing changes) if the
/// stream is wide: glibc's byte functions then fail quietly (no flag, no errno).
#[inline]
pub(crate) fn narrow_ok(f: &mut File) -> bool {
    let fl = f.flags;
    if fl & F_WIDE != 0 {
        return false;
    }
    if fl & F_BYTE == 0 {
        f.flags = fl | F_BYTE;
    }
    true
}

/// Bytes of pending output as `ftell` counts them: on a wide stream in the C locale glibc counts one
/// byte for each wide character not yet converted, whatever it will become (transliterations
/// included).
#[inline]
fn pending_out(f: &mut File) -> i64 {
    let extra = f.wide_ref().map_or(0, |w| w.extra);
    // (nothing is pending on an unbuffered stream, whatever was written)
    (f.wpos() as i64 - extra as i64).max(0)
}

#[inline]
fn reset_wextra(f: &mut File) {
    if let Some(w) = f.wide_mut() {
        w.extra = 0;
        w.pchars = 0;
        w.raw = 0;
    }
}

/// Forget wide characters pushed back with `ungetwc` (a seek, flush or switch to writing does).
#[inline]
pub(crate) fn drop_wpush(f: &mut File) {
    if let Some(w) = f.wide_mut() {
        w.npush = 0;
        w.tshift = 0;
    }
}

// ---- opening and closing ----

/// Parse an fopen mode into (stream flags, open(2) flags). None if the mode is invalid.
pub fn parse_mode(mode: &[u8]) -> Option<(u32, c_int)> {
    let (base, plus) = match mode.first()? {
        b'r' => (0, false),
        b'w' => (1, false),
        b'a' => (2, false),
        _ => return None,
    };
    let mut plus = plus;
    let mut cloexec = false;
    let mut excl = false;
    let mut nocancel = false;
    for &c in &mode[1..] {
        match c {
            b'+' => plus = true,
            b'b' => {}
            b'e' => cloexec = true,
            b'x' => excl = true,
            b'c' => nocancel = true,
            b'm' | b'n' => {}
            b',' => break,
            _ => break,
        }
    }
    let (mut fl, mut of) = match (base, plus) {
        (0, false) => (F_READ, 0),
        (0, true) => (F_READ | F_WRITE, 2),
        (1, false) => (F_WRITE, 1 | 0o100 | 0o1000),
        (1, true) => (F_READ | F_WRITE, 2 | 0o100 | 0o1000),
        (2, false) => (F_WRITE | F_APPEND, 1 | 0o100 | 0o2000),
        _ => (F_READ | F_WRITE | F_APPEND, 2 | 0o100 | 0o2000),
    };
    if cloexec {
        of |= 0o2000000;
    }
    if excl {
        of |= 0o200;
    }
    if nocancel {
        fl |= F_NOCANCEL;
    }
    Some((fl, of))
}

/// The charset of a `,ccs=NAME` part of a mode string, found as glibc 2.43's `_IO_new_file_fopen` finds it: the first
/// `,ccs=` (lower case) after the last of the mode letters `r w a + x b` it recognised among the first seven bytes (the
/// scan stops at a comma), `NAME` running to the next comma (spaces and other characters stay in it: `ccs_key` drops them).
pub fn mode_ccs(mode: &[u8]) -> Option<&[u8]> {
    let mut last = 0;
    for (i, &c) in mode.iter().enumerate().take(7).skip(1) {
        match c {
            b',' | 0 => break,
            b'+' | b'x' | b'b' => last = i,
            _ => {}
        }
    }
    let rest = mode.get(last + 1..)?;
    let at = rest.windows(5).position(|w| w == b",ccs=")?;
    let name = &rest[at + 5..];
    let end = name.iter().position(|&c| c == b',').unwrap_or(name.len());
    Some(&name[..end])
}

/// A new stream on the heap, in the list of open streams; null when there is no memory.
pub fn alloc_file(flags: u32, fd: c_int) -> *mut File {
    let s: *mut Stream = alloc(core::mem::size_of::<Stream>()).cast();
    if s.is_null() {
        return s.cast();
    }
    // (a memory or cookie stream may have a sync hook, set by the caller: the walkers look at it until it is known)
    let hint = if !multithreaded() { H_ALL } else if flags & F_MEM != 0 { H_FLUSH } else { 0 };
    // SAFETY: a fresh block of `Stream`'s size from malloc (aligned for any type of 16 bytes or less, as `Stream` is).
    unsafe { s.write(Stream::new(flags, fd, shared_part(s), hint)) };
    let p: *mut File = s.cast();
    note_used();
    link_standard();
    // SAFETY: `p` is live and not in the list.
    unsafe { link(p) };
    p
}

/// `fopen`: null with errno set on failure (a missing path fails as the system call does, with EFAULT).
pub fn fopen(path: Option<&core::ffi::CStr>, mode: &[u8]) -> *mut File {
    let Some((flags, oflags)) = parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    // SAFETY: `path` is NUL-terminated or null (the kernel then fails with EFAULT).
    let fd = match unsafe { unistd::open(path.map_or(core::ptr::null(), |p| p.as_ptr()), oflags, 0o666) } {
        Ok(fd) => fd,
        Err(e) => {
            errno::set(e.0);
            return null_mut();
        }
    };
    // glibc does not know a fresh stream's offset until the first ftell or seek asks the kernel (so ftello on a
    // stream whose descriptor was closed behind its back fails with EBADF: gnulib's test-ftello4 checks that)
    let mut start = -1i64;
    if flags & F_APPEND != 0 && flags & F_READ == 0 {
        // a write-only appending stream starts at the end of the file (so ftell reports it at
        // once); "a+" starts reading at the beginning, like glibc
        start = unistd::lseek(fd, 0, 2).unwrap_or(-1);
    }
    let f = alloc_file(flags, fd);
    if f.is_null() {
        let _ = unistd::close(fd);
        errno::set(12);
    } else {
        // SAFETY: a stream we just made, not yet returned to the program: no other reference to it.
        let s = unsafe { stream(f) };
        s.cookie_pos = start;
        if let Some(name) = mode_ccs(mode)
            && !crate::wfile::set_ccs(s, name)
        {
            let e = errno::get();
            // SAFETY: our own stream, open, used by nobody else.
            unsafe { crate::file_api::fclose(f) };
            errno::set(e);
            return null_mut();
        }
    }
    f
}

/// `fdopen`: null with errno set on failure.
pub fn fdopen(fd: c_int, mode: &[u8]) -> *mut File {
    let Some((flags, _)) = parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    // the descriptor's access mode must allow what the mode asks for
    let r = match unistd::fcntl_int(fd, 3 /* F_GETFL */, 0) {
        Ok(r) => r as usize,
        Err(e) => {
            errno::set(e.0);
            return null_mut();
        }
    };
    let acc = r & 3;
    if (flags & F_READ != 0 && acc == 1) || (flags & F_WRITE != 0 && acc == 0) {
        errno::set(22);
        return null_mut();
    }
    let mut flags = flags;
    let mut added_append = false;
    if flags & F_APPEND != 0 && r & 0o2000 == 0 {
        // make the descriptor append-only, as mode "a" asks
        let _ = unistd::fcntl_int(fd, 4 /* F_SETFL */, (r | 0o2000) as c_int);
        added_append = true;
    }
    if flags & F_WRITE != 0 && r & 0o2000 != 0 {
        flags |= F_APPEND;
    }
    if added_append && flags & F_READ == 0 {
        // glibc moves to the end of the file when it added O_APPEND; failing for any reason but ESPIPE fails fdopen
        // (/proc/self/mem is seekable with SEEK_SET only: EINVAL)
        if let Err(e) = unistd::lseek(fd, 0, 2)
            && e.0 != 29
        {
            errno::set(e.0);
            return null_mut();
        }
    }
    let f = alloc_file(flags, fd);
    if f.is_null() {
        errno::set(12);
    }
    f
}

/// Close the stream's descriptor (or cookie) and drop its buffer but keep the `FILE` object and its
/// place in the list of open streams: the first half of `freopen`.
pub(crate) fn close_keep(f: &mut File) -> c_int {
    let mut result = 0;
    // (glibc's wide buffer holding a character the stream cannot write: the flush writes the bytes before it and fails)
    let dropped = crate::wfile::dropping(f);
    crate::wfile::free_wide(f);
    if f.writing() && !flush_write(f) || dropped {
        result = EOF;
    }
    if f.flags & F_RDMODE != 0 {
        discard_input(f, true);
    }
    if f.flags & F_MEM != 0 {
        if let Some(c) = f.io.close
            // SAFETY: the cookie close function, called once with the stream's cookie (forgotten right below).
            && unsafe { c(f.cookie) } != 0
        {
            result = EOF;
        }
    } else if f.fd >= 0 && unistd::close(f.fd).is_err() {
        result = EOF;
    }
    if f.flags & F_MEM != 0 {
        // the cookie is gone: a later fclose of the stream (after a failed freopen) must not close it a second time
        f.flags &= !F_MEM;
        f.cookie = null_mut();
        f.io = CookieIo { read: None, write: None, seek: None, close: None, sync: None };
    }
    if !f.buf.is_null() && f.flags & F_USERBUF == 0 {
        // SAFETY: the stream's own buffer (not F_USERBUF), dropped from the stream right below.
        unsafe { free(f.buf) };
    }
    drop_unget(f);
    f.flags &= !(F_RDMODE | F_WRMODE);
    f.set_buffer(null_mut(), 0);
    drop_wpush(f);
    f.fd = -1;
    result
}

/// Give a closed-by-`close_keep` stream a new descriptor and mode.
pub(crate) fn reopen_as(f: &mut File, flags: u32, fd: c_int, pos: i64) {
    let keep = f.flags & F_STATIC;
    // (the list links, lock, pins and locking mode stay: `reset` leaves them alone)
    f.reset(flags | keep, fd);
    f.cookie_pos = pos;
}

/// Close a stream: lock it, flush, leave the list, close the descriptor (or cookie), wait for the
/// stream's pins to drain, free it. As in glibc, closing a stream another thread is waiting to lock
/// (or is using) is a program error: the waiter would touch freed memory. Our own walkers (fflush(NULL),
/// exit, fork) are safe: they pin the stream and `fclose` waits for them after unlocking.
pub unsafe fn fclose(f: *mut File) -> c_int {
    // SAFETY: the caller's contract: an open stream.
    unsafe { close_stream(f, false) }
}

/// `fclose`; `pinned` says the caller holds one pin on `f` (fcloseall) and that someone else may be
/// closing it at the same time (then this call does nothing).
///
/// # Safety
/// `f` is an open stream (kept allocated by the caller's pin when `pinned`) that no other thread uses except our walkers.
unsafe fn close_stream(f: *mut File, pinned: bool) -> c_int {
    // SAFETY: the caller's promise keeps `f` alive.
    let pins = &unsafe { shared_of(f) }.pins;
    // SAFETY: as above.
    let l = unsafe { lock_of(f) };
    // SAFETY: as above.
    let real = multithreaded() && !unsafe { shared_of(f) }.nolock.load(Ordering::Relaxed);
    // a thread cancelled inside the flush or the close releases the lock (the stream stays open, as in glibc)
    let mut cg = crate::flock::LockCleanup::idle();
    if real {
        l.lock();
        // SAFETY: we hold the lock; `cg` stays here until it is disarmed.
        unsafe { cg.arm(f) };
    }
    // SAFETY: as above.
    if pinned && !unsafe { shared_of(f) }.linked.load(Ordering::Relaxed) {
        if real {
            cg.disarm();
            l.unlock();
        }
        pins.fetch_sub(1, Ordering::AcqRel);
        return EOF;
    }
    // SAFETY: locked by us (or one thread / caller locking): this thread may work on the stream until it unlocks.
    let s = unsafe { stream(f) };
    // a standard stream that fclose already closed stays allocated (it is static): closing it again is an error, as in
    // glibc (a closed stream has no descriptor)
    if s.flags & (F_STATIC | F_MEM | F_ERR) == F_STATIC | F_ERR && s.fd < 0 {
        if real {
            cg.disarm();
            l.unlock();
        }
        if pinned {
            pins.fetch_sub(1, Ordering::AcqRel);
        }
        errno::set(9);
        return EOF;
    }
    let mut result = 0;
    let mut close_errno = 0; // why close(2) failed (EBADF when the descriptor was closed behind our back)
    // (as in close_keep)
    let dropped = crate::wfile::dropping(s);
    crate::wfile::free_wide(s);
    if s.writing() && !flush_write(s) || dropped {
        result = EOF;
    }
    if s.flags & F_RDMODE != 0 {
        discard_input(s, true);
    }
    // SAFETY: `f` is live and in the list.
    unsafe { unlink(f) };
    if s.flags & F_MEM != 0 {
        if let Some(c) = s.io.close
            // SAFETY: the cookie close function, called once with the stream's cookie (the stream is freed below).
            && unsafe { c(s.cookie) } != 0
        {
            result = EOF;
        }
    } else if s.fd >= 0
        && let Err(e) = unistd::close(s.fd)
    {
        result = EOF;
        close_errno = e.0;
    }
    // a popen stream: wait for the child, and its wait status is the result (pclose)
    if s.pid > 0 {
        loop {
            match unistd::waitpid(s.pid, 0) {
                Ok((_, status)) => {
                    result = status;
                    break;
                }
                Err(e) if e.0 == 4 => continue,
                Err(e) => {
                    errno::set(e.0);
                    result = -1;
                    break;
                }
            }
        }
    }
    if !s.buf.is_null() && s.flags & F_USERBUF == 0 {
        // SAFETY: the stream's own buffer (not F_USERBUF); the stream is freed or reset below.
        unsafe { free(s.buf) };
    }
    let is_static = s.flags & F_STATIC != 0;
    if is_static {
        // a closed standard stream is not reusable; reset it so a later call fails cleanly
        s.buf = null_mut();
        s.flags = F_STATIC | F_ERR;
        s.fd = -1;
    }
    if real {
        cg.disarm();
        l.unlock();
    }
    if pinned {
        pins.fetch_sub(1, Ordering::AcqRel);
    }
    if !is_static {
        // walkers that pinned the stream finish with it (they see it unlinked and skip it) first
        loop {
            let p = pins.load(Ordering::Acquire);
            if p == 0 {
                break;
            }
            // sleep briefly on the count (no sched_yield: see core::lock::futex_wait_timeout)
            rusty_libc_core::lock::futex_wait_timeout(pins, p, 200_000);
        }
        // SAFETY: a heap stream from `alloc_file`, out of the list, unpinned and unlocked: nothing refers to it any more.
        unsafe { free(f.cast()) };
    }
    if close_errno != 0 && result == EOF {
        errno::set(close_errno); // fclose returns EOF with the error close(2) reported (glibc), whatever the cleanup did
    }
    result
}

// ---- reading ----

/// Leave the pushback area (its bytes used up or thrown away): the main get area becomes current again (glibc's
/// `_IO_switch_to_main_get_area`) and the area's heap block is freed.
#[inline]
pub(crate) fn drop_unget(f: &mut File) {
    if f.flags & F_UNGOT != 0 {
        f.flags &= !F_UNGOT;
        f.rptr = f.save_base;
        f.rend_p = f.save_end;
        f.rbase = f.buf;
        f.save_base = null_mut();
        f.save_end = null_mut();
    }
    if !f.ubuf.is_null() {
        // SAFETY: the pushback area's own heap block, forgotten right below.
        unsafe { free(f.ubuf) };
        f.ubuf = null_mut();
    }
    f.ucap = 1;
}

/// A pushback area whose bytes were all read (by us or by glibc's inline getc in the program) is left.
#[inline(always)]
fn unget_done(f: &mut File) {
    if f.flags & F_UNGOT != 0 && f.rptr >= f.rend_p {
        drop_unget(f);
    }
}

/// Push `c` back: into the pushback area, which starts at the stream's one-byte room and doubles when it is full (a failing
/// allocation makes ungetc fail). Its bytes sit at its end in reading order, so `rptr`..`rend_p` reads them.
fn push_byte(f: &mut File, c: u8) -> bool {
    if f.flags & F_UNGOT == 0 {
        // glibc's `_IO_switch_to_backup_area`: the main area's position and end wait in the save pointers
        let area = f.unget.as_mut_ptr();
        f.save_base = f.rptr;
        f.save_end = f.rend_p;
        f.rbase = area;
        f.rend_p = area.wrapping_add(f.ucap as usize);
        f.rptr = f.rend_p;
        f.flags |= F_UNGOT;
    }
    if f.rptr <= f.rbase {
        let n = f.nunget();
        let Some(newcap32) = f.ucap.checked_mul(2) else {
            return false; // 2^32 bytes pushed back: as a failing allocation
        };
        let newcap = newcap32 as usize;
        let p = alloc(newcap);
        if p.is_null() {
            return false;
        }
        // SAFETY: a fresh block of `newcap` bytes, `n < newcap`; no other reference to it yet.
        let fresh = unsafe { core::slice::from_raw_parts_mut(p, newcap) };
        copy_bytes(&mut fresh[newcap - n..], f.window());
        if !f.ubuf.is_null() {
            // SAFETY: the old pushback block, just copied out and replaced below.
            unsafe { free(f.ubuf) };
        }
        f.ubuf = p;
        f.ucap = newcap32;
        f.rbase = p;
        f.rend_p = p.wrapping_add(newcap);
        f.rptr = p.wrapping_add(newcap - n);
    }
    f.rptr = f.rptr.wrapping_sub(1);
    // SAFETY: `rbase < rptr` before the step back: `rptr` is a byte of the pushback area (the stream's `unget` room or `ubuf`).
    unsafe { *f.rptr = c };
    // a pushed-back byte is unread input (fflush(NULL) and exit move the descriptor back over it); a byte stepped back onto
    // inside the buffer or the pushback area came with a read or an earlier push, which added the bit
    f.hint_add(H_FLUSH);
    true
}

#[inline]
pub fn getc(f: &mut File) -> c_int {
    // fast path: unread input (buffered or pushed back), as glibc's inline getc_unlocked (no orientation test: a wide
    // stream's byte window is hidden, `hide_read_window`, as the inline getc in our headers relies on too)
    if f.rptr < f.rend_p {
        return c_int::from(f.take_byte());
    }
    getc_slow(f)
}

#[inline(never)]
fn getc_slow(f: &mut File) -> c_int {
    if !narrow_ok(f) {
        return EOF;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return EOF;
    }
    let c = f.take_byte();
    unget_done(f);
    c_int::from(c)
}

/// The next input byte without taking it (glibc's `__underflow`): a pushed-back byte first, then the buffer,
/// refilled when empty; EOF at end of file, on an error or on a wide stream.
pub fn peekc(f: &mut File) -> c_int {
    if !narrow_ok(f) {
        return EOF;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return EOF;
    }
    c_int::from(f.window()[0])
}

/// Unread input, refilling when empty: (start, length), or None at end of file or on an error (the flags say which).
/// Pushed-back bytes come first, alone: `consume` them and call again for the buffer.
#[inline]
pub fn fill_buf(f: &mut File) -> Option<&[u8]> {
    if window_ready(f) {
        return Some(f.window());
    }
    fill_buf_slow(f)
}

/// True when `fill_buf` would hand out the buffered window (`f.window()`, not empty) without more work. Loops that
/// read a window per round test this and call `fill_buf_slow` otherwise: on the fast path no Option is made and
/// tested again (`fill_buf`'s pointer test of its result).
#[inline(always)]
pub fn window_ready(f: &File) -> bool {
    f.flags & (F_WIDE | F_BYTE) == F_BYTE && (f.rptr as usize) < (f.rend_p as usize)
}

/// `fill_buf` past its fast test (`window_ready` false).
#[inline(never)]
pub fn fill_buf_slow(f: &mut File) -> Option<&[u8]> {
    if !narrow_ok(f) {
        return None;
    }
    unget_done(f);
    if f.rptr >= f.rend_p && !underflow(f) {
        return None;
    }
    Some(f.window())
}

/// Mark `n` bytes returned by `fill_buf` as read. (A pushback area read to its end is left by the next read, as after
/// glibc's inline getc.)
#[inline]
pub fn consume(f: &mut File, n: usize) {
    debug_assert!(n <= f.window().len());
    f.rptr = f.rptr.wrapping_add(n);
}

pub fn ungetc(c: c_int, f: &mut File) -> c_int {
    if c == EOF || f.flags & F_READ == 0 {
        return EOF;
    }
    if f.flags & F_WIDE != 0 {
        // glibc: the byte pushback of a wide stream is the wide one (`_IO_wdefault_pbackfail`
        // takes the byte as a wide character): the next fgetwc returns it
        let r = crate::wfile::ungetwc_raw(rusty_libc_wchar::wint_t::from(c as u8), f);
        return if r == rusty_libc_wchar::WEOF { EOF } else { c_int::from(c as u8) };
    }
    ungetc_force(c, f)
}

/// `ungetc` without the checks (`ungetwc` on a byte stream does the same in glibc, even on a stream that is not readable).
pub(crate) fn ungetc_force(c: c_int, f: &mut File) -> c_int {
    if f.flags & F_WRMODE != 0 && !flush_write(f) {
        return EOF;
    }
    // glibc's `_IO_sputbackc` inside a pushback area that is still current (getc read its bytes but nothing has left
    // it yet): the byte before the read position is the same byte, so step back onto it instead of building the area anew
    if f.flags & (F_UNGOT | F_RDMODE) == F_UNGOT | F_RDMODE && f.rptr > f.rbase && f.byte_before() == c as u8 {
        f.rptr = f.rptr.wrapping_sub(1);
        f.flags &= !(F_PUTTING | F_EOF);
        return c_int::from(c as u8);
    }
    unget_done(f);
    if f.flags & F_RDMODE == 0 {
        f.set_read(0, 0);
        f.flags |= F_RDMODE;
    }
    f.flags &= !F_PUTTING;
    // like glibc (`_IO_sputbackc`): step back inside the buffer only when nothing is pushed back and the
    // buffer already holds that byte; any other byte goes to the separate pushback area (which a seek throws away, even a failed one)
    if f.flags & F_UNGOT == 0 && f.rptr > f.buf && f.rptr <= f.buf_end && f.byte_before() == c as u8 {
        f.rptr = f.rptr.wrapping_sub(1);
    } else if !push_byte(f, c as u8) {
        return EOF;
    }
    f.flags &= !F_EOF;
    c_int::from(c as u8)
}

/// Read up to `n` bytes into `dst`; returns how many were read (fewer at EOF or error).
pub fn read_bytes(f: &mut File, dst: &mut [u8]) -> usize {
    if !narrow_ok(f) {
        return 0;
    }
    let n = dst.len();
    let mut got = 0;
    // pushed-back characters first, then the buffer
    while got < n {
        unget_done(f);
        if f.rptr < f.rend_p {
            let k = (f.rend_p as usize - f.rptr as usize).min(n - got);
            // SAFETY: `got + k <= n` = `dst.len()`; `k` bytes of the get area at `rptr` (buffer invariant); the caller's
            // slice and the stream's buffer are different objects.
            unsafe { copy_raw(dst.as_mut_ptr().wrapping_add(got), f.rptr, k) };
            f.rptr = f.rptr.wrapping_add(k);
            got += k;
            continue;
        }
        let want = n - got;
        prepare(f);
        let block = f.bufsize();
        if f.flags & F_WRITE != 0 && f.writing() && !flush_write(f) {
            break;
        }
        if f.flags & F_READ == 0 {
            f.flags |= F_ERR;
            errno::set(9);
            break;
        }
        if f.flags & F_EOF != 0 {
            break;
        }
        if f.buf.is_null() || want < block || f.flags & F_UNBUF != 0 {
            if !underflow(f) {
                break;
            }
        } else {
            // big request: read whole blocks straight into the destination
            if f.flags & (F_LBF | F_UNBUF) != 0 {
                flush_line_buffered();
            }
            let count = if block >= 128 { want - want % block } else { want };
            // the buffer is used up and the file moves past it: forget it, so a later seek
            // cannot land on stale bytes
            f.set_read(0, 0);
            let k = raw_read(f, &mut dst[got..got + count]);
            if k > 0 {
                got += k as usize;
            } else {
                if k == 0 {
                    if f.flags & F_NOEOF == 0 {
                        f.flags |= F_EOF;
                    }
                    f.flags &= !F_SEEKED;
                } else {
                    f.flags |= F_ERR;
                }
                break;
            }
        }
    }
    got
}

// ---- writing ----

#[inline]
pub fn putc(c: c_int, f: &mut File) -> c_int {
    let b = c as u8;
    // fast path: room in a fully buffered stream's output buffer, as glibc's inline putc_unlocked
    // (the pointer is kept in a register: the byte store may alias the FILE, so reloading `wptr` after it would make
    // each call wait for the previous call's store)
    let p = f.wptr;
    if p < f.wend {
        // SAFETY: `wptr < wend`: by the buffer invariant `p` is a byte of the put area (never inside the `File`: the put area
        // is the stream's malloc'd or setvbuf buffer, `wend` = `buf` for the unbuffered streams that use `shortbuf`).
        unsafe { *p = b };
        f.wptr = p.wrapping_add(1);
        return c_int::from(b);
    }
    putc_slow(b, f)
}

#[inline(never)]
fn putc_slow(b: u8, f: &mut File) -> c_int {
    // a line-buffered stream keeps no room for the inline putc (`wend` = `wbase`): every byte comes here, and only a
    // newline needs the full write path
    if f.flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE | F_LBF && b != b'\n' && f.wpos() < f.bufsize() {
        let p = f.wptr;
        // SAFETY: in write mode `wbase` = `buf`, and `wpos < bufsize`: `p` is a byte of the buffer.
        unsafe { *p = b };
        f.wptr = p.wrapping_add(1);
        return c_int::from(b);
    }
    // a full buffer (glibc's `_IO_new_file_overflow`): write it out, then the byte starts the next one (also with a buffer
    // under 128 bytes, where fwrite would write the rest straight through)
    if f.flags & (F_WRMODE | F_UNBUF | F_WIDE | F_LBF) == F_WRMODE && !f.buf.is_null() && f.wpos() >= f.bufsize() {
        if !flush_write(f) {
            return EOF;
        }
        f.flags |= F_WRMODE;
        f.hint_output();
        f.set_wpos(1);
        // SAFETY: the buffer is not null (checked above) and not empty (`wpos >= bufsize` held with a non-null buffer of at
        // least one byte).
        unsafe { *f.buf = b };
        return c_int::from(b);
    }
    if f.flags & F_WIDE != 0 {
        let wide_putting = f.wide_ref().is_some_and(|w| w.putting);
        if !wide_putting || f.flags & F_W32 != 0 {
            // (an open_wmemstream stream is always here: every fputc stores one wchar_t)
            // glibc: no wide write buffer yet, so the byte goes through `__overflow` of the wide stream,
            // which takes it as a wide character (converted like fputwc's)
            return if crate::wfile::putwc_raw(f, rusty_libc_wchar::wint_t::from(b)) == rusty_libc_wchar::WEOF { EOF } else { c_int::from(b) };
        }
        // glibc's putc then stores the raw byte in the byte buffer, ahead of the wide characters
        // still waiting to be converted (they are converted when the buffer is flushed)
        if write_bytes_raw(f, &[b]) != 1 {
            return EOF;
        }
        let wpos = f.wpos();
        let raw = f.wide_ref().map_or(0, |w| w.raw);
        let raw = if wpos == 0 {
            0 // the write went straight out
        } else {
            let at = raw.min(wpos - 1);
            // SAFETY: `at < wpos <= bufsize`: pending output in the buffer; the slice lives for this rotation only.
            unsafe { f.buf_slice_mut(at, wpos - at) }.rotate_right(1);
            at + 1
        };
        if let Some(w) = f.wide_mut() {
            w.raw = raw;
        }
        return c_int::from(b);
    }
    // (glibc's `__overflow`: the byte goes into the buffer even on a stream that was not writing yet)
    if !narrow_ok(f) || put_bytes(f, &[b], false) != 1 {
        return EOF;
    }
    c_int::from(b)
}

/// Write `n` bytes; returns how many were accepted.
pub fn write_bytes(f: &mut File, src: &[u8]) -> usize {
    if !narrow_ok(f) {
        return 0;
    }
    put_bytes(f, src, true)
}

/// `write_bytes` without the orientation check (the wide functions write their encoded bytes here). The bytes go into the
/// buffer whether or not the stream was already writing (glibc's overflow paths: putc and the wide buffer's conversion).
pub(crate) fn write_bytes_raw(f: &mut File, src: &[u8]) -> usize {
    put_bytes(f, src, false)
}

/// The byte writer. `xsputn`: follow glibc's `_IO_new_file_xsputn` (fwrite, fputs, printf output): a stream that is not yet
/// putting has no room in its buffer for this call.
/// When the flush at a newline of the remainder (step 4) fails, the count stops before the first newline there: glibc puts the
/// remainder in byte by byte through `__overflow`, which writes at each newline and does not count the newline whose write
/// failed, so the call comes back short (printf -1, fputs EOF, fwrite short) although the bytes went into the buffer. One
/// write covers every newline here: its failure is the one glibc meets at the first.
fn put_bytes(f: &mut File, src: &[u8], xsputn: bool) -> usize {
    let n = src.len();
    // glibc's `_IO_new_file_xsputn` returns at once for nothing to write: no mode switch, no EBADF on a read-only stream
    if n == 0 {
        return 0;
    }
    // glibc measures the room in the buffer only for a stream that is already putting (_IO_CURRENTLY_PUTTING): the first
    // write after opening, a seek or a read finds none and goes through the flush-and-write-blocks path below
    // the common case first, exactly what step 1 below does for it: a fully buffered stream in write mode whose buffer has
    // room for all of it (no newline to look for, nothing to flush)
    // (the mode test is a branch of its own, and an unbuffered stream in write mode such as stderr goes from its failure
    // straight to the descriptor, as below: with one shared slow path the compiler evaluated every test of the fast path
    // without branching, 15 instructions on each unbuffered write)
    let fl = f.flags;
    if fl & (F_WRMODE | F_UNBUF | F_LBF) == F_WRMODE {
        if (!xsputn || fl & F_PUTTING != 0) && !f.buf.is_null() && n <= f.bufsize() - f.wpos() {
            // SAFETY: `n` bytes of room in the buffer at `wptr` (write mode: `wbase` = `buf`); the caller's slice is not
            // the stream's buffer.
            unsafe { copy_raw(f.wptr, src.as_ptr(), n) };
            f.wptr = f.wptr.wrapping_add(n);
            return n;
        }
    } else if fl & (F_UNBUF | F_WRMODE) == F_UNBUF | F_WRMODE {
        return put_unbuffered(f, src);
    }
    if f.flags & F_WRMODE == 0 && !start_write(f) {
        return 0;
    }
    if f.flags & F_APPEND != 0 && f.flags & F_MEM == 0 {
        // appending streams write at the end whatever the buffer holds; nothing to adjust here
    }
    if f.flags & F_UNBUF != 0 || f.buf.is_null() {
        return put_unbuffered(f, src);
    }
    // (from the flags as they were before start_write; written out twice so the unbuffered paths do not compute it)
    let putting = !xsputn || fl & F_PUTTING != 0;
    // glibc's _IO_new_file_xsputn, step by step:
    // 1. the room to fill: none unless putting; a line-buffered stream whose data fits takes it up to the last newline
    //    and must flush then (the text after that newline stays in the buffer)
    let lbf = f.flags & F_LBF != 0;
    let space = f.bufsize() - f.wpos();
    let mut count = if putting { space } else { 0 };
    let mut must_flush = false;
    if lbf
        && putting
        && count >= n
        && let Some(i) = src.iter().rposition(|&c| c == b'\n')
    {
        count = i + 1;
        must_flush = true;
    }
    let k = count.min(n);
    // SAFETY: `k <= space` = bufsize - wpos: room in the buffer at `wptr` (`wbase` = `buf` in write mode); `k <= n` bytes of
    // the caller's slice, which is not the stream's buffer.
    unsafe { copy_raw(f.wptr, src.as_ptr(), k) };
    f.wptr = f.wptr.wrapping_add(k);
    let mut done = k;
    if done == n && !must_flush {
        // a full buffer is written out at the next write, like glibc
        return n;
    }
    // 2. flush the buffer (what already went into it counts as written, even if the flush fails, like glibc)
    if !flush_write_keep(f) {
        return if done == n { 0 } else { done };
    }
    f.flags |= F_WRMODE;
    f.hint_output();
    f.set_wpos(0);
    // 3. write whole blocks directly (everything when the buffer is smaller than 128 bytes)
    let rest = n - done;
    let block = f.bufsize();
    let direct = if block >= 128 { rest - rest % block } else { rest };
    let mut off = 0;
    while off < direct {
        let w = raw_write(f, &src[done + off..done + direct]);
        if w < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            return done + off;
        }
        off += w as usize;
        if f.flags & F_MEM != 0 && off < direct {
            f.flags |= F_ERR;
            f.flags &= !F_WRMODE;
            return done + off;
        }
    }
    done += direct;
    // 4. the remainder (smaller than the buffer) goes into the buffer; on a line-buffered stream glibc puts it in a byte at
    //    a time and writes the buffer out at each newline: everything up to its last newline reaches the file now
    let rem = n - done;
    if rem > 0 {
        let nl = if lbf { src[done..].iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1) } else { 0 };
        if nl > 0 {
            // SAFETY: `nl <= rem` < bufsize (the remainder is smaller than the buffer); nothing is pending after the flush.
            copy_bytes(unsafe { f.buf_slice_mut(0, nl) }, &src[done..done + nl]);
            f.set_wpos(nl);
            if !flush_write_keep(f) {
                return done + src[done..done + nl].iter().position(|&c| c == b'\n').unwrap_or(0);
            }
            f.flags |= F_WRMODE;
            f.hint_output();
            f.set_wpos(0);
            done += nl;
        }
        let tail = n - done;
        // SAFETY: `tail <= rem` < bufsize; nothing is pending (flushed above).
        copy_bytes(unsafe { f.buf_slice_mut(0, tail) }, &src[done..]);
        f.set_wpos(tail);
        done += tail;
    }
    done
}

/// `put_bytes` on an unbuffered stream (or one without a buffer): straight to the descriptor or cookie. (Not cold: stderr
/// takes this path for every message, and a call here cost ~40 instructions per write.)
#[inline]
fn put_unbuffered(f: &mut File, src: &[u8]) -> usize {
    let n = src.len();
    let mut off = 0;
    while off < n {
        let k = raw_write(f, &src[off..]);
        if k < 0 {
            if errno::get() == 4 {
                continue;
            }
            f.flags |= F_ERR;
            return off;
        }
        off += k as usize;
        if f.flags & F_MEM != 0 && off < n {
            f.flags |= F_ERR; // a short write by a cookie ends the call (see flush_write)
            return off;
        }
    }
    n
}

// ---- positioning ----

/// Current logical position, or -1 (errno set).
pub fn tell(f: &mut File) -> i64 {
    if crate::wfile::dropping(f) {
        let p = tell_bytes(f);
        return crate::wfile::drop_tell(f, p);
    }
    if f.wide_ref().is_some_and(|w| w.npush > 0) && !f.buf.is_null() {
        // glibc (do_ftell_wide): no position while ungetwc'd characters are pending, once the stream has its buffer
        errno::set(22);
        return -1;
    }
    let utf8_pchars = f.wide_ref().and_then(|w| (w.cs == crate::wfile::WCs::Utf8).then_some(w.pchars));
    if let Some(pchars) = utf8_pchars
        && f.writing()
        && f.wpos() > 4 * pchars
    {
        // glibc's estimate of pending UTF-8 output fails when it is more than 4 bytes per character
        return 4_294_967_295;
    }
    let mut p = tell_bytes(f);
    if p > 0 && let Some(w) = f.wide_ref() {
        p -= w.tshift as i64;
    }
    if p > 0 && f.flags & F_W32 != 0 { p / 4 } else { p }
}

fn tell_bytes(f: &mut File) -> i64 {
    if f.flags & F_NOSEEK != 0 {
        errno::set(29);
        return -1;
    }
    let base = match offset(f) {
        Ok(p) => p,
        Err(e) => {
            if e == 29 {
                f.flags |= F_NOSEEK;
            }
            errno::set(e);
            return -1;
        }
    };
    if f.writing() {
        if f.flags & F_APPEND != 0 && f.flags & F_OLDMEM != 0 {
            // the pre-2.22 fmemopen in append mode: glibc writes out what is pending and asks the cookie where it is
            if !flush_write(f) {
                return -1;
            }
            return match raw_seek(f, 0, 1) {
                Ok(p) => p,
                Err(e) => {
                    errno::set(e);
                    -1
                }
            };
        }
        if f.flags & F_APPEND != 0 {
            // appended bytes land at the end of the file
            return match raw_seek(f, 0, 2) {
                Ok(end) => end + pending_out(f),
                Err(e) => {
                    errno::set(e);
                    -1
                }
            };
        }
        base + pending_out(f)
    } else if f.flags & F_RDMODE != 0 {
        if f.flags & F_UNGOT != 0 {
            return tell_in_pushback(f, base);
        }
        let p = base - (f.rend() - f.rpos()) as i64;
        if p < 0 {
            // glibc: /dev/zero and the like do not advance their offset; the position would be negative: not seekable
            errno::set(29);
            return -1;
        }
        p
    } else {
        base
    }
}

/// `tell_bytes` of a byte stream reading its pushback area (out of line: rare, kept out of ftell's common path).
#[cold]
#[inline(never)]
fn tell_in_pushback(f: &mut File, base: i64) -> i64 {
    // glibc (libio/fileops.c do_ftell, then ioftell.c): inside the pushback area do_ftell subtracts only the
    // pushed-back bytes (none while no buffer is allocated) and checks that result; ftell then subtracts the main
    // area's unread bytes without a check, so -2 and below come back as positions and -1 as an error (EIO when errno
    // is 0)
    // (glibc's setvbuf(_IONBF) gives the stream its one-byte buffer at once; ours comes with the first read)
    let has_buf = !f.buf.is_null() || f.flags & F_UNBUF != 0;
    let k = if has_buf { f.nunget() as i64 } else { 0 };
    let unread = if f.buf.is_null() { 0 } else { (f.rend() - f.rpos()) as i64 };
    if base == 0 && k > 0 {
        errno::set(29);
        return -1;
    }
    if base - k < 0 {
        errno::set(22);
        return -1;
    }
    let p = base - k - unread;
    if p == -1 && errno::get() == 0 {
        errno::set(5);
    }
    p
}

pub fn seek(f: &mut File, off: i64, whence: c_int) -> c_int {
    if crate::wfile::dropping(f) {
        return seek_dropping(f);
    }
    let off = if f.flags & F_W32 != 0 { off.saturating_mul(4) } else { off };
    if let Some(w) = f.wide_mut() {
        w.putting = false;
        w.ahead = false;
    }
    seek_bytes(f, off, whence)
}

/// A seek on a wide stream whose buffer holds a character it cannot write: glibc's `_IO_wfile_seekoff` fails in its flush
/// (`_IO_switch_to_wget_mode`) and returns WEOF, which fseek, fseeko, fsetpos and rewind take for success (it is not -1
/// as an `off64_t`): the bytes before the character are written, nothing else moves; pushed-back wide characters were
/// dropped before.
#[cold]
#[inline(never)]
fn seek_dropping(f: &mut File) -> c_int {
    drop_wpush(f);
    crate::wfile::drop_flush(f);
    0
}

fn seek_bytes(f: &mut File, off: i64, whence: c_int) -> c_int {
    if !(0..=2).contains(&whence) {
        errno::set(22);
        return -1;
    }
    // glibc's "must be exact": no input in the main get area (while bytes are pushed back, its start is where the first
    // ungetc left the position: glibc's read base) and no output waiting
    let exact = f.wpos() == 0 && if f.flags & F_UNGOT != 0 { f.save_base == f.save_end } else { f.rend() == 0 };
    if f.writing() && !flush_write(f) {
        return -1;
    }
    let mut off = off;
    let reading = f.flags & F_RDMODE != 0;
    if reading && whence == 1 {
        off -= ((f.rend() - f.rpos()) + f.nunget()) as i64;
    }
    // a seek that lands inside the buffered input only moves the read position (no system call)
    if reading && whence != 2 && f.cookie_pos >= 0 && f.flags & F_NOSEEK == 0 {
        let here = f.cookie_pos; // offset just past the buffered bytes
        let target = if whence == 0 { off } else { here + off };
        let start = here - f.rend() as i64;
        if target >= start && target < here {
            drop_unget(f);
            f.set_rpos((target - start) as usize);
            drop_wpush(f);
            f.flags &= !(F_EOF | F_PUTTING);
            return 0;
        }
    }
    if let Some(r) = block_seek(f, off, whence, exact) {
        return r;
    }
    // seek first; only a successful seek drops the buffered input
    match raw_seek(f, off, whence) {
        Ok(_) => {
            if reading {
                drop_unget(f);
                f.set_read(0, 0);
                drop_wpush(f);
                f.flags &= !F_RDMODE;
            }
            f.flags &= !(F_EOF | F_PUTTING);
            f.flags |= F_SEEKED;
            0
        }
        Err(e) => {
            drop_unget(f);
            drop_wpush(f);
            errno::set(e);
            -1
        }
    }
}

/// glibc's seek outside the buffer (`_IO_new_file_seekoff`): the descriptor goes to the buffer-size boundary below the target
/// and a whole buffer is read, the target inside it (whole pages for the kernel: an unaligned 4 KiB read costs a third more);
/// the descriptor is then left past that buffer, as glibc's is. When the stream must be `exact` (nothing buffered), only the
/// bytes up to the target are read, leaving the descriptor there. `None` when this does not apply (memory, cookie, wide or
/// unbuffered stream, unknown offset, not a regular file for SEEK_END, a target on the boundary): the caller seeks the plain
/// way. `off` is relative to the descriptor's offset for SEEK_CUR (buffered input already taken off).
fn block_seek(f: &mut File, off: i64, whence: c_int, exact: bool) -> Option<c_int> {
    if f.flags & (F_MEM | F_UNBUF | F_NOSEEK) != 0 || f.flags & F_READ == 0 || !f.wide.is_null() {
        return None;
    }
    // a stream not used yet gets its buffer here, as glibc's seek does (_IO_doallocbuf)
    prepare(f);
    if f.buf.is_null() {
        return None;
    }
    let target = match whence {
        0 => off,
        1 if f.cookie_pos >= 0 => f.cookie_pos + off,
        2 => match unistd::fstat_basic(f.fd) {
            Ok((mode, _, size)) if mode & 0o170000 == 0o100000 => size + off,
            _ => return None,
        },
        _ => return None,
    };
    let size = f.bufsize() as i64;
    let base = target & !(size - 1);
    let delta = target - base;
    if target < 0 || delta == 0 || delta > size {
        return None;
    }
    if raw_seek(f, base, 0).is_err() {
        // (the plain seek gets the same error)
        return None;
    }
    drop_unget(f);
    drop_wpush(f);
    f.set_read(0, 0);
    f.flags &= !(F_RDMODE | F_EOF | F_PUTTING);
    f.flags |= F_SEEKED;
    // SAFETY: `delta <= size` = bufsize; nothing is buffered any more (dropped just above); the slice lives for this read only.
    let dst = unsafe { f.buf_slice_mut(0, if exact { delta as usize } else { f.bufsize() }) };
    let count = raw_read(f, dst);
    if count < delta as isize {
        // too little to read: the rest of the way by a seek (glibc's fallback)
        let rest = if count < 0 { delta } else { delta - count as i64 };
        if let Err(e) = raw_seek(f, rest, 1) {
            errno::set(e);
            return Some(-1);
        }
        return Some(0);
    }
    f.set_read(delta as usize, count as usize);
    f.flags |= F_RDMODE;
    Some(0)
}

/// `fflush` of one stream (`flush_all` is `fflush(NULL)`).
pub fn fflush(f: &mut File) -> c_int {
    sync_mem(f);
    if f.writing() {
        return if flush_write(f) { 0 } else { EOF };
    }
    if f.flags & F_RDMODE != 0 && !sync_input(f) {
        return EOF;
    }
    0
}

/// glibc's `_IO_new_file_sync` for an input stream (`fflush`, and `fflush(NULL)` for a stream with unread input): the
/// descriptor's offset goes back to the stream's position and the buffered input is dropped. When that seek fails the pushed-back
/// bytes are dropped but the buffer is kept: on a descriptor that cannot seek (ESPIPE: pipe, socket, tty) the call succeeds and
/// the next read still gets the buffered input (git's `commit --interactive` reads its piped answers through it); any other
/// failure (before offset 0: EINVAL) fails the call. glibc's wide sync does not touch the pushback either.
fn sync_input(f: &mut File) -> bool {
    let mut unread = (f.rend() - f.rpos()) + f.nunget();
    if let Some(w) = f.wide_ref() {
        unread += w.tshift;
    }
    if unread > 0 {
        // (a stream already known to be unseekable fails the same way glibc's lseek would)
        let r = if f.flags & F_NOSEEK != 0 { Err(29) } else { raw_seek(f, -(unread as i64), 1) };
        if let Err(e) = r {
            if f.wide.is_null() {
                drop_unget(f);
            }
            errno::set(e);
            return e == 29;
        }
    }
    drop_unget(f);
    f.set_read(0, 0);
    drop_wpush(f);
    f.flags &= !F_RDMODE;
    true
}

/// Buffering mode change (setvbuf). `mode`: 0 full, 1 line, 2 none.
///
/// # Safety
/// `buf` is null or valid for `size` bytes, readable and writable, for as long as the stream uses it (C's setvbuf contract).
pub unsafe fn setvbuf(f: &mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    if !(0..=2).contains(&mode) {
        errno::set(22);
        return EOF;
    }
    // glibc (iosetvbuf.c): full or line buffering without a buffer of the caller's only changes the mode: nothing is
    // flushed, synced or freed, and the size is not looked at. Full buffering on a stream with no buffer yet gets the
    // stream's own buffer at once, as the first read or write would. The window putc may fill is left as it is, as
    // glibc's: it follows the new mode from the next flush (until then a newline putc stores is not written at once).
    if mode != 2 && buf.is_null() && f.flags & F_UNBUF == 0 {
        if mode == 0 && f.buf.is_null() {
            note_used();
            f.flags |= F_DECIDED;
            alloc_default(f);
            if f.flags & F_UNBUF != 0 {
                return EOF;
            }
        }
        f.flags &= !F_LBF;
        if mode == 1 {
            f.flags |= F_LBF;
        }
        return 0;
    }
    if f.writing() {
        flush_write(f);
    }
    if f.flags & F_RDMODE != 0 {
        // unread input goes back to the file (the descriptor's offset becomes the stream's position), as glibc's setbuf syncs
        // the stream first
        discard_input(f, true);
    }
    if !f.buf.is_null() && f.flags & F_USERBUF == 0 {
        // SAFETY: the stream's own buffer (not F_USERBUF), replaced right below.
        unsafe { free(f.buf) };
    }
    f.flags &= !(F_LBF | F_UNBUF | F_USERBUF | F_RDMODE | F_WRMODE);
    drop_unget(f);
    f.set_buffer(null_mut(), 0);
    // setvbuf counts as the first use: exit must flush this stream (decide() does the same)
    note_used();
    f.flags |= F_DECIDED;
    match mode {
        2 => f.flags |= F_UNBUF,
        1 => f.flags |= F_LBF,
        _ => {}
    }
    if mode != 2 && !buf.is_null() && size > 0 {
        f.set_buffer(buf.cast(), size);
        f.flags |= F_USERBUF;
    }
    0
}

/// The exit-time flush, for the unit tests.
#[cfg(test)]
pub fn flush_at_exit_for_tests() {
    flush_at_exit();
}

/// FIXLIST #123 and #124: the split between a stream's `File` and its `Shared` part, checked by Miri under Stacked Borrows
/// and Tree Borrows (`cargo +nightly miri test -p rusty-libc-stdio --lib stream_split`, with and without
/// `MIRIFLAGS=-Zmiri-tree-borrows`). One thread works on a stream through `&mut File` (as a lock holder does, inside functions
/// that take the reference: protected under Tree Borrows) while another thread does what the other threads of the library do
/// meanwhile: tries the stream's lock, pins it, reads the walkers' hint and the list membership, rewrites its list links (the
/// unlink of a neighbour) and its fork mark. The `old_*` tests model the layout before the split (links, fork mark and a racy
/// flags read inside the `File`) the same way: Miri rejects both under both models (run them with `--ignored`; they are
/// undefined behaviour by design, never run natively).
#[cfg(test)]
mod stream_split {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    /// A pointer handed to the other thread with its provenance (no integer round trip, which would weaken Miri's checks).
    struct Send<T>(T);
    // SAFETY: test-only carrier of raw pointers to streams that outlive both threads.
    unsafe impl<T> core::marker::Send for Send<T> {}

    /// A heap stream as `alloc_file` makes it (Box instead of malloc: Miri runs no system call), never freed.
    fn new_stream(flags: u32, fd: c_int) -> *mut File {
        let s = Box::into_raw(Box::new(core::mem::MaybeUninit::<Stream>::uninit())).cast::<Stream>();
        // SAFETY: a fresh, aligned block of `Stream`'s size.
        unsafe { s.write(Stream::new(flags, fd, shared_part(s), 0)) };
        s.cast()
    }

    /// The handshake: the holder sets 1 once it works on the stream, the other thread sets 2 when it is done (Release/Acquire:
    /// the point is the aliasing models, not the race detector).
    static STEP: AtomicUsize = AtomicUsize::new(0);

    fn wait_for(v: usize) {
        while STEP.load(Ordering::Acquire) != v {
            std::thread::yield_now();
        }
    }

    /// What a lock holder's functions do to the stream; the reference is a protected function argument.
    #[inline(never)]
    fn holder_work(s: &mut File, round: usize) {
        s.flags |= F_WRMODE;
        s.wptr = s.wptr.wrapping_add(round);
        s.cookie_pos += 1;
        s.publish_hint();
        if round == 0 {
            STEP.store(1, Ordering::Release);
            wait_for(2); // the other thread works on the shared part now, while this reference is live and protected
        }
        s.flags &= !F_WRMODE;
        s.publish_hint();
    }

    #[test]
    fn stream_split_aliasing() {
        STEP.store(0, Ordering::Relaxed);
        let (a, b, c) = (new_stream(F_WRITE, 5), new_stream(F_WRITE, 6), new_stream(F_READ, 7));
        // the list b <-> a <-> c, as `link_locked` builds it
        // SAFETY: live streams (never freed while the test runs).
        let sh = |p: *mut File| unsafe { shared_of(p) };
        let (sa, sb, sc) = (sh(a), sh(b), sh(c));
        sb.next.store(a, Ordering::Relaxed);
        sa.prev.store(b, Ordering::Relaxed);
        sa.next.store(c, Ordering::Relaxed);
        sc.prev.store(a, Ordering::Relaxed);
        sa.linked.store(true, Ordering::Relaxed);
        assert!(sa.lock.try_lock());
        let ptrs = Send((a, b, c));
        let other = std::thread::spawn(move || {
            let ptrs = ptrs;
            let (a, b, c) = ptrs.0;
            wait_for(1);
            // SAFETY: `a`, `b` and `c` are live streams (freed after the join); only their `Shared` parts are used.
            let sh = |p: *mut File| unsafe { shared_of(p) };
            let (sa, sb, sc) = (sh(a), sh(b), sh(c));
            assert!(!sa.lock.try_lock()); // the holder has it
            sa.pins.fetch_add(1, Ordering::AcqRel);
            // SAFETY: as above (the walkers' first look).
            assert!(unsafe { needs_flush(a) });
            assert!(sa.linked.load(Ordering::Relaxed));
            // SAFETY: as above (the list is ours in this test).
            assert!(core::ptr::eq(unsafe { next_of(a) }, c));
            // unlink c (a neighbour of the stream the holder works on), then put it back in front of b
            sa.next.store(null_mut(), Ordering::Relaxed);
            sc.prev.store(null_mut(), Ordering::Relaxed);
            sc.next.store(b, Ordering::Relaxed);
            sb.prev.store(c, Ordering::Relaxed);
            // SAFETY: as above (the fork handler gave up waiting for the lock).
            unsafe { fork_mark(a) }.store(2, Ordering::Relaxed);
            sa.pins.fetch_sub(1, Ordering::AcqRel);
            STEP.store(2, Ordering::Release);
        });
        // SAFETY: this thread holds `a`'s lock: it may work on the stream.
        let s = unsafe { stream(a) };
        holder_work(s, 0);
        holder_work(s, 1);
        other.join().unwrap();
        holder_work(s, 2);
        assert_eq!(s.cookie_pos, -1 + 3);
        assert_eq!(s.wptr as usize, 3);
        s.publish_hint();
        assert!(sa.lock.unlock());
        assert_eq!(sa.hint.load(Ordering::Relaxed), 0); // no output pending: the walkers skip it
        assert_eq!(sa.fork_held.load(Ordering::Relaxed), 2);
        assert!(core::ptr::eq(sc.next.load(Ordering::Relaxed), b) && sa.next.load(Ordering::Relaxed).is_null());
        for p in [a, b, c] {
            // SAFETY: from `new_stream`, no longer used by anyone.
            drop(unsafe { Box::from_raw(p.cast::<core::mem::MaybeUninit<Stream>>()) });
        }
    }

    /// The layout before the split, reduced to what matters: the list link and the fork mark inside the stream, and its flags.
    #[repr(C)]
    struct OldFile {
        flags: u32,
        wptr: *mut u8,
        next: *mut OldFile,
        fork_held: u8,
    }

    #[inline(never)]
    fn old_holder_work(s: &mut OldFile, round: usize) {
        s.flags ^= F_WRMODE;
        s.wptr = s.wptr.wrapping_add(round);
        if round == 0 {
            STEP.store(1, Ordering::Release);
            wait_for(2);
        }
        s.flags ^= F_WRMODE;
    }

    fn old_model(other_side: fn(*mut OldFile)) {
        STEP.store(0, Ordering::Relaxed);
        let p = Box::into_raw(Box::new(OldFile { flags: 0, wptr: null_mut(), next: null_mut(), fork_held: 0 }));
        let pp = Send(p);
        let other = std::thread::spawn(move || {
            let pp = pp;
            wait_for(1);
            other_side(pp.0);
            STEP.store(2, Ordering::Release);
        });
        // SAFETY: (the model's holder) the only `&mut`; the other thread uses the raw pointer.
        let s = unsafe { &mut *p };
        old_holder_work(s, 0);
        other.join().unwrap();
        old_holder_work(s, 1);
        // SAFETY: from `Box::into_raw`, no longer used.
        drop(unsafe { Box::from_raw(p) });
    }

    /// FIXLIST #123 before the split: a neighbour's unlink rewrites the link (and the fork handler the mark) inside the
    /// stream while its holder works on it.
    #[test]
    #[ignore = "undefined behaviour by design: run under Miri with --ignored to see it rejected"]
    fn old_layout_links_rejected() {
        old_model(|p| {
            // SAFETY: none: this is the old layout's unsound write.
            unsafe { (*p).next = p };
            // SAFETY: as above.
            unsafe { (*p).fork_held = 2 };
        });
    }

    /// FIXLIST #124 before the split, with the flags read made atomic as first suggested: the walker's first look at the
    /// flags while the holder writes them.
    #[test]
    #[ignore = "undefined behaviour by design: run under Miri with --ignored to see it rejected"]
    fn old_layout_peek_rejected() {
        old_model(|p| {
            // SAFETY: none: this is the old layout's unsound read.
            let at = unsafe { &raw mut (*p).flags };
            // SAFETY: as above.
            let fl = unsafe { AtomicU32::from_ptr(at) }.load(Ordering::Relaxed);
            core::hint::black_box(fl);
        });
    }
}
