//! The allocator proper. See the crate docs for the design.
//!
//! Chunk layout (x86-64): at the chunk address `c` there is `prev_size` (8 bytes, only valid when
//! the previous chunk is free), then `size` (8 bytes, low 3 bits are flags), then the user memory at
//! `c + 16`. The user memory of an in-use chunk extends into the next chunk's `prev_size` field, so
//! `usable = size - 8`. A free chunk keeps `fd` at `c + 16` and `bk` at `c + 24`.
//!
//! # What stays unsafe here, and the invariants the SAFETY comments name
//! The chunk headers and the lists threaded through free chunks are raw memory that C programs share with us: they are
//! read and written through raw pointers only, with `rd`/`wr`/`csize`/`sl_get`/`sl_set` (one audited word access each);
//! pointer arithmetic on chunk addresses is wrapping (`at`, `chunk2mem`, `mem2chunk`) and needs no unsafe. The code
//! around them (bin indexes and bitmaps, sizes, tunables, statistics, the choice of arena) is safe Rust.
//! - **H1 (chunks)**: every chunk the code works on lies in a read-write region of this allocator (the brk heap, an
//!   mmapped region, a non-main heap), starts 16-aligned, and its region reaches at least to the size word of the chunk
//!   after it. Such chunks are: an arena's top; the chunks on its bins (the bin sentinels are 4-word nodes inside
//!   `State`) and per-size lists; the chunks in a thread's cache; their neighbours found through valid size fields
//!   (fences close every region that is left behind, `retire_top`); and the chunk of a pointer handed to free/realloc
//!   (H4). A free chunk on a list keeps its links at `c + 16` and `c + 24`.
//! - **H2 (exclusive use)**: an arena's `State` and the chunks it owns are changed only while the process has one thread
//!   (the paths without a lock) or under the arena's `lock`; a thread's cache only by that thread; the arena list fields
//!   (`next_free`, `attached`) only under `ARENA_LIST`. A `&mut State` is made only under that rule. The fields other
//!   threads touch (the lock word, the ring link, the list fields) are not in `State` but beside it in `ArenaCell`, as
//!   atomics used through shared references, so a `&mut State` never covers memory another thread writes (FIXLIST #99).
//! - **H3 (arenas live for ever)**: the main arena is the static `STATE`; every other arena sits at the start of its first
//!   heap, right after the `HeapInfo`, and heaps that hold an arena are never unmapped. A `HeapInfo` heads every
//!   `HEAP_MAX`-aligned non-main heap, so a NON_MAIN_ARENA chunk finds its arena through it.
//! - **H4 (the caller's pointer)**: free, realloc and malloc_usable_size get NULL or a block this allocator handed out and
//!   that was not freed since (C's contract). Corruption is caught where glibc catches it; anything else is undefined, as
//!   in C.
use core::cell::Cell;
use core::ptr::null_mut;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicUsize};
use rusty_libc_core::{SyncCell, errno, syscall};

pub const SIZE_SZ: usize = 8;
pub const MINSIZE: usize = 32;
const PREV_INUSE: usize = 1;
const IS_MMAPPED: usize = 2;
const FLAGS: usize = 7;
const PAGE: usize = 4096;
/// Chunks up to this size are kept on per-size lists when freed (no coalescing until needed).
const SMALL_MAX: usize = 1040;
const NSMALL: usize = SMALL_MAX / 16 + 1;
const NBINS: usize = 128;
const DEFAULT_MMAP_THRESHOLD: usize = 128 * 1024;
const MMAP_THRESHOLD_MAX: usize = 32 * 1024 * 1024;
const DEFAULT_TOP_PAD: usize = 128 * 1024;
const DEFAULT_TRIM_THRESHOLD: usize = 128 * 1024;
const CONSOLIDATE_THRESHOLD: usize = 64 * 1024;
/// Gather the small-block lists into the bins when they hold more than this many bytes.
const SMALL_BYTES_MAX: usize = 512 * 1024;
const MMAP_MAX_DEFAULT: usize = 65536;
const ENOMEM: i32 = 12;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 2;
const MAP_ANONYMOUS: usize = 0x20;
const MREMAP_MAYMOVE: usize = 1;
const MADV_DONTNEED: usize = 4;

pub struct State {
    /// Set up (bins linked, tunables read); read and set under H2 only (`choose_arena` tests NEXT_TO_USE instead).
    init: bool,
    top: *mut u8,
    top_is_brk: bool,
    brk_start: usize,
    brk_end: usize,
    /// Highest address ever handed out; memory above it is still zero from the kernel.
    high_water: usize,
    last_fresh: bool,
    small: [*mut u8; NSMALL],
    /// Sentinel nodes of the circular bins (prev_size, size, fd, bk).
    bins: [[usize; 4]; NBINS],
    map: [u64; 2],
    /// Extra mmap'd heap regions used when brk is unavailable (main arena).
    foreign_bytes: usize,
    small_bytes: usize,
    /// Set while memalign asks for its over-sized block: grow the heap before merging the quick lists (see alloc_chunk).
    grow_first: bool,
    /// glibc's NON_MAIN_ARENA (4) for every chunk header of this arena; 0 in the main arena.
    abit: usize,
    /// Non-main arena: the heap the top chunk lives in.
    heap: *mut HeapInfo,
    /// Non-main arena: bytes of its heaps that are mapped read-write (glibc's `system_mem`).
    system_mem: usize,
    max_system_mem: usize,
    /// 0 for the main arena, then 1, 2, ... in creation order (malloc_stats and malloc_info number them so).
    id: usize,
}

/// One arena, split by who may touch which part (FIXLIST #99). glibc keeps all of it in one `malloc_state`, and other
/// threads read and write its lock word, ring link and free-list fields while the lock holder works on the rest; in Rust a
/// `&mut` to the whole would forbid that (aliasing UB under both Stacked and Tree Borrows). So:
/// - `state`, the part only the arena's user touches (H2), sits in an `UnsafeCell` (core's `SyncCell`) and is reached
///   as `&mut State` only through `Arena::with`/`Arena::locked` (lock held, or one thread) and `st` (one thread);
/// - the parts other threads touch are atomics, used through `&ArenaCell` only: the lock word, the ring link, and the
///   free-list fields (`next_free`, `attached`: protected by ARENA_LIST, so their accesses are Relaxed; the list lock orders
///   them). A shared reference to the cell covers the `UnsafeCell` and the atomics, which permit mutation through it.
///
/// (Rust Atomics and Locks, ch. 9: a mutex is its atomic state next to an `UnsafeCell<T>`; R. Jung's thesis p. 260: a shared
/// reference allows writes exactly to the bytes inside an `UnsafeCell`.)
pub struct ArenaCell {
    /// Rule (H2): used only while the arena's lock is held or the process has one thread, by one `&mut` at a time.
    state: SyncCell<State>,
    /// The arena's lock (taken on the multithreaded paths; the single-thread path uses the main arena without it).
    lock: rusty_libc_core::lock::RawMutex,
    /// The ring of all arenas, main arena first (glibc's `next`; only ever extended, so read without the list lock).
    next: AtomicPtr<ArenaCell>,
    /// The list of arenas no thread is attached to (under ARENA_LIST).
    next_free: AtomicPtr<ArenaCell>,
    /// Threads using this arena (under ARENA_LIST).
    attached: AtomicUsize,
}

impl ArenaCell {
    const fn new(state: State) -> ArenaCell {
        ArenaCell {
            state: SyncCell::new(state),
            lock: rusty_libc_core::lock::RawMutex::new(),
            next: AtomicPtr::new(null_mut()),
            next_free: AtomicPtr::new(null_mut()),
            attached: AtomicUsize::new(1),
        }
    }
}

/// The tunables of the whole allocator (glibc's `mp_`): set by mallopt and the environment, read by every arena.
pub struct Params {
    pub mmap_threshold: AtomicUsize,
    pub trim_threshold: AtomicUsize,
    pub top_pad: AtomicUsize,
    pub mmap_max: AtomicUsize,
    pub dynamic_thresholds: AtomicBool,
    pub n_mmaps: AtomicUsize,
    pub mmapped_mem: AtomicUsize,
    pub max_mmapped_mem: AtomicUsize,
    pub perturb: AtomicU8,
    pub small_enabled: AtomicBool,
    pub check_action: AtomicI32,
    /// M_ARENA_MAX / M_ARENA_TEST (0: not set).
    pub arena_max: AtomicUsize,
    pub arena_test: AtomicUsize,
    /// Per-thread cache entries per size (glibc's tcache_count).
    pub tcache_count: AtomicUsize,
    /// The largest chunk the per-thread cache keeps (glibc's tcache_max_bytes - 1, at most SMALL_MAX here).
    pub tcache_max: AtomicUsize,
    /// glibc.malloc.hugetlb=1: the transparent huge page size the heap grows to a multiple of (0: off), and whether the
    /// system wants madvise(MADV_HUGEPAGE) for it.
    pub thp_pagesize: AtomicUsize,
    pub thp_madvise: AtomicBool,
    /// The unit the heap top is trimmed in, as a mask: pages, or transparent huge pages with hugetlb=1.
    pub trim_mask: AtomicUsize,
    /// glibc.malloc.hugetlb>=2: the huge page size mmap is asked for first (0: off) and its mmap flags.
    pub hp_pagesize: AtomicUsize,
    pub hp_flags: AtomicUsize,
    key: AtomicUsize,
}

pub static P: Params = Params {
    mmap_threshold: AtomicUsize::new(DEFAULT_MMAP_THRESHOLD),
    trim_threshold: AtomicUsize::new(DEFAULT_TRIM_THRESHOLD),
    top_pad: AtomicUsize::new(DEFAULT_TOP_PAD),
    mmap_max: AtomicUsize::new(MMAP_MAX_DEFAULT),
    dynamic_thresholds: AtomicBool::new(true),
    n_mmaps: AtomicUsize::new(0),
    mmapped_mem: AtomicUsize::new(0),
    max_mmapped_mem: AtomicUsize::new(0),
    perturb: AtomicU8::new(0),
    small_enabled: AtomicBool::new(true),
    check_action: AtomicI32::new(3),
    arena_max: AtomicUsize::new(0),
    arena_test: AtomicUsize::new(8),
    tcache_count: AtomicUsize::new(16),
    tcache_max: AtomicUsize::new(SMALL_MAX),
    thp_pagesize: AtomicUsize::new(0),
    thp_madvise: AtomicBool::new(false),
    trim_mask: AtomicUsize::new(!(PAGE - 1)),
    hp_pagesize: AtomicUsize::new(0),
    hp_flags: AtomicUsize::new(0),
    key: AtomicUsize::new(0),
};

/// Add to a statistics counter: a plain load and store while the process has one thread (no locked instruction), atomic
/// otherwise; returns the new value.
#[inline(always)]
fn count_add(c: &AtomicUsize, v: usize) -> usize {
    if rusty_libc_core::lock::multithreaded() {
        c.fetch_add(v, Relaxed).wrapping_add(v)
    } else {
        let n = c.load(Relaxed).wrapping_add(v);
        c.store(n, Relaxed);
        n
    }
}

#[inline(always)]
fn count_max(c: &AtomicUsize, v: usize) {
    if c.load(Relaxed) < v {
        if rusty_libc_core::lock::multithreaded() {
            c.fetch_max(v, Relaxed);
        } else {
            c.store(v, Relaxed);
        }
    }
}

#[inline(always)]
fn perturb() -> u8 {
    P.perturb.load(Relaxed)
}
#[inline(always)]
fn small_enabled() -> bool {
    P.small_enabled.load(Relaxed)
}
#[inline(always)]
fn key() -> usize {
    P.key.load(Relaxed)
}

/// The header of a non-main arena's heap: at the start of a HEAP_MAX-aligned mapping, so `chunk & !(HEAP_MAX - 1)` finds it
/// (glibc's `heap_info`).
#[repr(C)]
pub struct HeapInfo {
    arena: *mut ArenaCell,
    prev: *mut HeapInfo,
    /// Bytes from the heap start that are read-write.
    committed: usize,
    /// The unit it grows by: a page, or a (transparent) huge page when those were asked for (glibc's heap_info.pagesize).
    pagesize: usize,
}

/// Size and alignment of a non-main heap (glibc: twice the largest mmap threshold).
const HEAP_MAX: usize = 64 << 20;
const NON_MAIN_ARENA: usize = 4;

/// Locks the arena ring's growth, the free list and the attachment counts (glibc's `list_lock`).
static ARENA_LIST: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();
/// Number of arenas (glibc's `narenas`).
static NARENAS: AtomicUsize = AtomicUsize::new(1);
static FREE_ARENAS: AtomicPtr<ArenaCell> = AtomicPtr::new(null_mut());
/// Where the round-robin reuse of an arena starts (glibc's `next_to_use`).
static NEXT_TO_USE: AtomicPtr<ArenaCell> = AtomicPtr::new(null_mut());

/// The main arena. Rule (H2): used without its lock only while the process has one thread, otherwise under its `lock`.
static STATE: ArenaCell = ArenaCell::new(State::empty());

impl State {
    const fn empty() -> State {
        State {
            init: false,
            top: null_mut(),
            // host tests run next to glibc, which also uses brk: keep out of its way and use mmap there
            top_is_brk: !cfg!(any(test, feature = "no-brk")),
            brk_start: 0,
            brk_end: 0,
            high_water: 0,
            last_fresh: false,
            small: [null_mut(); NSMALL],
            bins: [[0; 4]; NBINS],
            map: [0; 2],
            foreign_bytes: 0,
            small_bytes: 0,
            grow_first: false,
            abit: 0,
            heap: null_mut(),
            system_mem: 0,
            max_system_mem: 0,
            id: 0,
        }
    }
}

/// The main arena, as a raw pointer (getting it is safe; its state is used under H2).
#[inline(always)]
fn main_ptr() -> *mut ArenaCell {
    (&raw const STATE).cast_mut()
}

/// The main arena.
///
/// # Safety
/// H2: the process has one thread, or the caller holds the main arena's lock; no other `&mut` to it is live.
#[inline(always)]
pub unsafe fn st() -> &'static mut State {
    // SAFETY: exclusive by the caller's contract (H2); the static lives for ever.
    unsafe { &mut *STATE.state.as_ptr() }
}

/// The address `off` bytes after `c` (wrapping: computing it is safe, only `rd`/`wr` look at what it points to).
#[inline(always)]
fn at(c: *mut u8, off: usize) -> *mut u8 {
    c.wrapping_add(off)
}

/// Read the word `off` bytes into a chunk.
///
/// # Safety
/// `p + off` is an 8-aligned word of a chunk (H1) that the caller may read under H2.
#[inline(always)]
unsafe fn rd(p: *mut u8, off: usize) -> usize {
    // SAFETY: caller's contract.
    unsafe { *(at(p, off) as *mut usize) }
}

/// Write the word `off` bytes into a chunk.
///
/// # Safety
/// `p + off` is an 8-aligned word of a chunk (H1) that the caller may write under H2.
#[inline(always)]
unsafe fn wr(p: *mut u8, off: usize, v: usize) {
    // SAFETY: caller's contract.
    unsafe { *(at(p, off) as *mut usize) = v }
}

/// Safe-linking of the small-block lists (glibc's PROTECT_PTR): the next pointer stored in a free block is XORed with the
/// block's own address shifted right by 12, so a forged or overwritten link is detected as misaligned with probability 15/16.
///
/// # Safety
/// `c` is a free chunk (H1) the caller owns under H2.
#[inline(always)]
unsafe fn sl_set(c: *mut u8, next: *mut u8) {
    // SAFETY: `c + 16` is the first link word of the free chunk `c` (caller's contract).
    unsafe { wr(c, 16, ((c as usize + 16) >> 12) ^ next as usize) }
}

/// The next chunk of a safe-linked list (null at its end); aborts on a link that is not 16-aligned.
///
/// # Safety
/// `c` is a chunk on a per-size list or in a thread's cache (H1) that the caller may read under H2.
#[inline(always)]
unsafe fn sl_get(c: *mut u8) -> *mut u8 {
    // SAFETY: `c + 16` is the link word of the listed chunk `c` (caller's contract).
    let v = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
    if v & 15 != 0 {
        fatal("malloc(): unaligned tcache chunk detected");
    }
    v as *mut u8
}

/// The size of chunk `c` (its size word without the flags).
///
/// # Safety
/// `c` is a chunk (H1) the caller may read under H2.
#[inline(always)]
unsafe fn csize(c: *mut u8) -> usize {
    // SAFETY: `c + 8` is the size word of chunk `c` (caller's contract).
    unsafe { rd(c, 8) & !FLAGS }
}

#[inline(always)]
fn chunk2mem(c: *mut u8) -> *mut u8 {
    c.wrapping_add(16)
}
#[inline(always)]
fn mem2chunk(m: *mut u8) -> *mut u8 {
    m.wrapping_sub(16)
}

/// Write a message to stderr and abort, like glibc's malloc diagnostics.
#[cold]
#[inline(never)]
pub fn fatal(msg: &str) -> ! {
    let _ = rusty_libc_core::unistd::write(2, msg.as_bytes());
    let _ = rusty_libc_core::unistd::write(2, b"\n");
    rusty_libc_core::process::abort()
}

/// Chunk size for a request, or None if the request is too large (above PTRDIFF_MAX minus slack).
#[inline(always)]
pub fn request2size(n: usize) -> Option<usize> {
    if n > isize::MAX as usize - 2 * MINSIZE {
        return None;
    }
    let s = (n + SIZE_SZ + 15) & !15;
    Some(if s < MINSIZE { MINSIZE } else { s })
}

fn bin_index(sz: usize) -> usize {
    if sz < 1024 {
        sz >> 4
    } else {
        let l = 63 - sz.leading_zeros() as usize;
        let sub = (sz >> (l - 2)) & 3;
        let idx = 64 + (l - 10) * 4 + sub;
        if idx > NBINS - 1 { NBINS - 1 } else { idx }
    }
}

impl State {
    #[cold]
    #[inline(never)]
    fn init(&mut self) {
        for i in 0..NBINS {
            // an empty bin: its sentinel's fd and bk (words 2 and 3 of the node) point at the sentinel itself
            let b = self.bin_node(i) as usize;
            self.bins[i][2] = b;
            self.bins[i][3] = b;
        }
        if self.abit != 0 {
            // a non-main arena: its heap and top were set up by `new_arena`
            self.init = true;
            return;
        }
        // The program break belongs to one heap: the copy of libc.so.6 in another dlmopen namespace keeps to mmap (glibc does the
        // same with `__libc_initial`), or two heaps would both extend and shrink the one break and overwrite each other.
        if !rusty_libc_core::lock::libc_initial() {
            self.top_is_brk = false;
        }
        let brk = brk_query();
        let start = (brk + 15) & !15;
        self.brk_start = start;
        self.brk_end = brk;
        // A per-process key for double-free detection (not a security boundary): 8 random bytes from
        // getrandom(GRND_NONBLOCK), as glibc's tcache_key_initialize takes them; the time stamp counter mixed with the
        // break when that fails.
        let k = match random_word() {
            Some(r) => r,
            None => {
                // SAFETY: rdtsc only reads the time stamp counter (the CPU has it: x86-64).
                let t = unsafe { core::arch::x86_64::_rdtsc() } as usize;
                (t ^ (brk >> 4)).rotate_left(17)
            }
        };
        P.key.store(k | 1, Relaxed);
        apply_tunables(self);
        // (only the main arena gets here: `abit` is 0)
        // the thread that sets the main arena up uses it (glibc's ptmalloc_init sets thread_arena so)
        THREAD_ARENA.set(main_ptr());
        self.init = true;
        // (published last: a thread that sees it set skips the main arena's lock in `choose_arena`)
        NEXT_TO_USE.store(main_ptr(), Release);
    }

    /// The sentinel node of bin `i` (a raw borrow: no reference is made, so the links chunks keep to it stay valid).
    #[inline(always)]
    fn bin_node(&mut self, i: usize) -> *mut u8 {
        (&raw mut self.bins[i]).cast::<u8>()
    }

    /// Put free chunk `c` of `size` bytes on its bin.
    ///
    /// # Safety
    /// `c` is a free chunk of this arena (H1, H2) on no list, `size` its size.
    unsafe fn link_bin(&mut self, c: *mut u8, size: usize) {
        let idx = bin_index(size);
        let b = self.bin_node(idx);
        // (in this function every node is the bin's sentinel or a chunk on the bin, H1; `c` by the contract)
        // SAFETY: the sentinel's fd word.
        let mut next = unsafe { rd(b, 16) } as *mut u8; // first chunk
        if idx >= 64 {
            // keep large bins sorted by size, smallest first
            // SAFETY: `next` is a chunk on the bin (the loop stops at the sentinel before reading its size).
            while next != b && unsafe { csize(next) } < size {
                // SAFETY: as above.
                next = unsafe { rd(next, 16) } as *mut u8;
            }
            // SAFETY: `next` is on the bin or the sentinel; its bk word.
            let prev = unsafe { rd(next, 24) } as *mut u8;
            // SAFETY: the links of `c`.
            unsafe { wr(c, 16, next as usize) };
            // SAFETY: as above.
            unsafe { wr(c, 24, prev as usize) };
            // SAFETY: `prev` is on the bin or the sentinel.
            unsafe { wr(prev, 16, c as usize) };
            // SAFETY: `next` is on the bin or the sentinel.
            unsafe { wr(next, 24, c as usize) };
        } else {
            // SAFETY: the links of `c`.
            unsafe { wr(c, 16, next as usize) };
            // SAFETY: as above.
            unsafe { wr(c, 24, b as usize) };
            // SAFETY: `next` is the first chunk of the bin or the sentinel.
            unsafe { wr(next, 24, c as usize) };
            // SAFETY: the sentinel's fd word.
            unsafe { wr(b, 16, c as usize) };
        }
        self.map[idx >> 6] |= 1 << (idx & 63);
    }

    /// Take chunk `c` of `size` bytes off its bin; aborts when its neighbours do not point back at it.
    ///
    /// # Safety
    /// `c` is a chunk on one of this arena's bins (H1, H2), `size` its size.
    unsafe fn unlink(&mut self, c: *mut u8, size: usize) {
        // SAFETY: the links of `c`, a chunk on a bin.
        let fd = unsafe { rd(c, 16) } as *mut u8;
        // SAFETY: as above.
        let bk = unsafe { rd(c, 24) } as *mut u8;
        // SAFETY: `fd` and `bk` are the neighbours of `c` on its bin (chunks or the sentinel, H1).
        if unsafe { rd(fd, 24) } != c as usize || unsafe { rd(bk, 16) } != c as usize {
            fatal("corrupted double-linked list");
        }
        // SAFETY: checked just above: `fd` and `bk` link to `c`, so they are its bin's nodes.
        unsafe { wr(fd, 24, bk as usize) };
        // SAFETY: as above.
        unsafe { wr(bk, 16, fd as usize) };
        let idx = bin_index(size);
        if self.bins[idx][2] == self.bin_node(idx) as usize {
            self.map[idx >> 6] &= !(1 << (idx & 63));
        }
    }

    /// The current top chunk (tests inspect the fence left behind when the heap moves).
    #[cfg(test)]
    pub fn top_ptr(&self) -> *mut u8 {
        self.top
    }

    fn top_size(&self) -> usize {
        // SAFETY: the top is a chunk of this arena (H1), and `&self` is only had under H2.
        if self.top.is_null() { 0 } else { unsafe { csize(self.top) } }
    }

    /// Free chunk `c` (not on any list) and merge it with free neighbours or the top.
    ///
    /// # Safety
    /// `c` is a chunk of this arena (H1, H2) on no list, `size` its size.
    unsafe fn free_merge(&mut self, c: *mut u8, size: usize) {
        let (mut c, mut size) = (c, size);
        // SAFETY: the size word of `c` (contract).
        if unsafe { rd(c, 8) } & PREV_INUSE == 0 {
            // SAFETY: the chunk before is free, so `c`'s prev_size word holds its size (H1).
            let ps = unsafe { rd(c, 0) };
            let p = c.wrapping_sub(ps);
            // SAFETY: `p` is the free chunk before `c` (H1); a corrupted prev_size is caught here as in glibc.
            if unsafe { csize(p) } != ps {
                fatal("corrupted size vs. prev_size");
            }
            c = p;
            size += ps;
            // SAFETY: a free chunk that is not the top is on a bin (the per-size lists keep PREV_INUSE set after them).
            unsafe { self.unlink(c, ps) };
        }
        let next = at(c, size);
        if next == self.top {
            // SAFETY: the top chunk (H1).
            size += unsafe { csize(next) };
            // SAFETY: the size word of `c`.
            unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
            self.top = c;
            return;
        }
        // SAFETY: `next` is the chunk after `c` (H1: the region reaches its size word).
        let nsize = unsafe { csize(next) };
        // SAFETY: the chunk after `next` (fences close each region, H1).
        if unsafe { rd(at(next, nsize), 8) } & PREV_INUSE == 0 {
            // SAFETY: `next` is free and not the top, so it is on a bin.
            unsafe { self.unlink(next, nsize) };
            size += nsize;
        }
        // SAFETY: the size word of `c`.
        unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
        let after = at(c, size);
        // SAFETY: the prev_size word of the chunk after the merged chunk (H1).
        unsafe { wr(after, 0, size) };
        // SAFETY: its size word.
        unsafe { clear_prev_inuse(after) };
        // SAFETY: `c` is now a free chunk of `size` bytes on no list.
        unsafe { self.link_bin(c, size) };
    }

    fn consolidate(&mut self) {
        if self.small_bytes == 0 {
            return;
        }
        self.small_bytes = 0;
        for i in 2..NSMALL {
            let mut c = self.small[i];
            self.small[i] = null_mut();
            while !c.is_null() {
                // SAFETY: `c` is on the arena's per-size list `i` (H1, H2: `&mut self`).
                let next = unsafe { sl_get(c) };
                // SAFETY: as above.
                let size = unsafe { csize(c) };
                // SAFETY: the second link word of the free chunk `c`: no stale double-free key inside merged memory.
                unsafe { wr(c, 24, 0) };
                // SAFETY: `c` is a chunk of this arena, now on no list.
                unsafe { self.free_merge(c, size) };
                c = next;
            }
        }
    }

    /// Return memory at the top of the brk heap to the system when it exceeds the trim threshold.
    fn trim_top(&mut self, threshold: usize, pad: usize) {
        if !self.top_is_brk || self.top.is_null() {
            return;
        }
        let ts = self.top_size();
        if ts < threshold {
            return;
        }
        // glibc's systrim: whole pages (whole transparent huge pages when those are used) above pad, keeping MINSIZE + 1
        let area = ts.saturating_sub(MINSIZE + 1);
        if area <= pad {
            return;
        }
        let extra = (area - pad) & P.trim_mask.load(Relaxed);
        if extra == 0 {
            return;
        }
        let want = self.brk_end - extra;
        // SAFETY: the bytes given back are the end of the top chunk (`extra` < its size), which no block uses.
        let got = unsafe { brk_set(want) };
        if got == want {
            self.brk_end = want;
            // SAFETY: the top's size word (H1), below the new break.
            unsafe { wr(self.top, 8, (ts - extra) | PREV_INUSE | self.abit) };
        }
    }

    /// Cut `size` bytes off the start of free chunk `c` (of `have` bytes); the remainder, if big
    /// enough, goes back to the bins. Returns the chunk with its header set (in use).
    ///
    /// # Safety
    /// `c` is a free chunk of this arena (H1, H2) on no list, `have` its size, `size` <= `have`.
    unsafe fn split(&mut self, c: *mut u8, have: usize, size: usize) -> *mut u8 {
        let rem = have - size;
        if rem >= MINSIZE {
            // SAFETY: the size word of `c`.
            unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
            let r = at(c, size);
            // SAFETY: `r` is inside `c` (`size + MINSIZE <= have`): the remainder's size word.
            unsafe { wr(r, 8, rem | PREV_INUSE | self.abit) };
            let after = at(r, rem);
            // SAFETY: the chunk after `c` (H1): its prev_size word.
            unsafe { wr(after, 0, rem) };
            // SAFETY: its size word.
            unsafe { clear_prev_inuse(after) };
            // SAFETY: the remainder is a free chunk of `rem` bytes on no list.
            unsafe { self.link_bin(r, rem) };
        } else {
            // SAFETY: the size word of `c`.
            unsafe { wr(c, 8, have | PREV_INUSE | self.abit) };
            let next = at(c, have);
            // SAFETY: the chunk after `c` (H1): its size word.
            unsafe { or_head(next, PREV_INUSE | self.abit) };
        }
        c
    }

    fn take_from_bins(&mut self, size: usize) -> *mut u8 {
        let start = bin_index(size);
        let mut word = start >> 6;
        let mut bits = self.map[word] & (!0u64 << (start & 63));
        loop {
            while bits == 0 {
                word += 1;
                if word >= 2 {
                    return null_mut();
                }
                bits = self.map[word];
            }
            let idx = (word << 6) + bits.trailing_zeros() as usize;
            let b = self.bin_node(idx);
            // (every node reached below is bin `idx`'s sentinel or a chunk on it, H1, H2: `&mut self`)
            let mut c = self.bins[idx][2] as *mut u8;
            if idx == start && idx >= 64 {
                // same large bin: first (smallest) chunk that is big enough
                // SAFETY: `c` is a chunk on the bin (the sentinel ends the walk before its size is read).
                while c != b && unsafe { csize(c) } < size {
                    // SAFETY: as above.
                    let cs = unsafe { csize(c) };
                    if cs < MINSIZE || cs & 15 != 0 {
                        fatal("malloc(): invalid size (unsorted)");
                    }
                    // SAFETY: as above: its fd word.
                    c = unsafe { rd(c, 16) } as *mut u8;
                }
                if c == b {
                    bits &= bits - 1;
                    continue;
                }
            }
            // SAFETY: the bin's bit is set, so `c` is a chunk on it, not the sentinel.
            let have = unsafe { csize(c) };
            // a free chunk whose size field was overwritten (heap overflow, write after free) is caught here
            if have < MINSIZE || have & 15 != 0 || bin_index(have) != idx {
                fatal("malloc(): invalid size (unsorted)");
            }
            // SAFETY: `c` is on bin `idx` with size `have`.
            unsafe { self.unlink(c, have) };
            // SAFETY: `c` is now a free chunk on no list, `size` <= `have` (the bin's sizes, or the walk above).
            return unsafe { self.split(c, have, size) };
        }
    }

    fn alloc_from_top(&mut self, size: usize) -> *mut u8 {
        if self.top.is_null() {
            return null_mut();
        }
        let ts = self.top_size();
        if ts < size + MINSIZE {
            return null_mut();
        }
        let c = self.top;
        // SAFETY: the top's size word (H1, H2).
        unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
        let nt = at(c, size);
        // SAFETY: `nt` lies inside the top (`size + MINSIZE <= ts`): the new top's size word.
        unsafe { wr(nt, 8, (ts - size) | PREV_INUSE | self.abit) };
        self.top = nt;
        let end = c as usize + size;
        self.last_fresh = c as usize >= self.high_water;
        if end > self.high_water {
            self.high_water = end;
        }
        c
    }

    /// Make the top chunk at least `size + MINSIZE` bytes. False if the system has no more memory.
    fn grow(&mut self, size: usize) -> bool {
        if self.abit != 0 {
            return self.grow_heap(size);
        }
        let ts = self.top_size();
        let need = size + MINSIZE;
        let top_pad = P.top_pad.load(Relaxed);
        // with transparent huge pages the break is moved to a multiple of their size (glibc's sysmalloc)
        let thp = P.thp_pagesize.load(Relaxed);
        let raw = need.saturating_sub(ts).saturating_add(top_pad);
        let ext = if thp != 0 {
            (self.brk_end.saturating_add(raw).saturating_add(thp - 1) & !(thp - 1)).wrapping_sub(self.brk_end)
        } else {
            raw.saturating_add(PAGE - 1) & !(PAGE - 1)
        };
        if self.top_is_brk {
            let want = self.brk_end + ext;
            if want > self.brk_end {
                // SAFETY: the break only moves up here: nothing in use is unmapped.
                let got = unsafe { brk_set(want) };
                if got == want {
                    madvise_thp(self.brk_end, ext);
                    if self.top.is_null() {
                        let start = (self.brk_end + 15) & !15;
                        self.top = start as *mut u8;
                        // SAFETY: the start of the new read-write break area, the arena's first top chunk.
                        unsafe { wr(self.top, 8, (want - start) | PREV_INUSE | self.abit) };
                        self.brk_start = start;
                    } else {
                        // SAFETY: the top's size word (H1); the top now reaches the new break, which is contiguous with it.
                        unsafe { wr(self.top, 8, (ts + (want - self.brk_end)) | PREV_INUSE | self.abit) };
                    }
                    self.brk_end = want;
                    return true;
                }
            }
        }
        // brk failed (or is not used): take a fresh mapping as the new top, huge pages first when they were asked for,
        // else at least 1 MiB (glibc's sysmalloc_mmap_fallback). The new mapping is not contiguous with the old top, so
        // the new top alone must hold the request.
        let fallback = need.saturating_add(top_pad);
        let hp = P.hp_pagesize.load(Relaxed);
        let mut m = null_mut();
        let mut len = 0;
        if hp > 0
            && let Some(l) = fallback.checked_add(hp - 1)
        {
            len = (l & !(hp - 1)).max(hp);
            m = map_anon_flags(len, P.hp_flags.load(Relaxed));
        }
        if m.is_null() {
            let Some(l) = fallback.max(1 << 20).checked_add(PAGE - 1) else {
                return false;
            };
            len = l & !(PAGE - 1);
            m = map_anon(len);
            if m.is_null() {
                return false;
            }
            madvise_thp(m as usize, len);
        }
        self.retire_top();
        self.top = m;
        self.top_is_brk = false;
        // SAFETY: `m` is a fresh read-write mapping of `len` bytes: the new top chunk's size word.
        unsafe { wr(m, 8, len | PREV_INUSE | self.abit) };
        self.foreign_bytes += len;
        true
    }

    /// The top chunk is left behind for a new region that is not contiguous with it: what can stand alone is freed into the
    /// bins, the rest becomes a fence so that merging never reads past the region.
    fn retire_top(&mut self) {
        if !self.top.is_null() {
            let old = self.top;
            let os = self.top_size();
            self.top = null_mut();
            // (every write below is inside the old top chunk, `os` bytes of its region, H1)
            if os >= MINSIZE + 32 {
                // Close the old region with two fence chunks so merging never reads past it.
                let keep = os - 32;
                // SAFETY: the old top's size word.
                unsafe { wr(old, 8, keep | PREV_INUSE | self.abit) };
                let f1 = at(old, keep);
                // SAFETY: the first fence chunk, 32 bytes before the end of the old top.
                unsafe { wr(f1, 8, 16 | PREV_INUSE | self.abit) };
                // SAFETY: as above.
                unsafe { wr(f1, 16, 0) };
                // SAFETY: the second fence chunk, 16 bytes before the end.
                unsafe { wr(at(f1, 16), 8, PREV_INUSE | self.abit) };
                // SAFETY: the first fence's prev_size word.
                unsafe { wr(f1, 0, 0) };
                // SAFETY: the rest of the old top is a chunk of this arena on no list.
                unsafe { self.free_merge(old, keep) };
            } else if os >= 32 {
                // Too small to free: make all of it the fence (a 16-byte in-use chunk and the
                // header after it) so a free of the chunk before it never reads past the
                // region (this used to segfault, depending on what the next page held).
                // SAFETY: the old top's size word.
                unsafe { wr(old, 8, 16 | PREV_INUSE | self.abit) };
                // SAFETY: 16 bytes into the old top (`os` >= 32).
                unsafe { wr(at(old, 16), 8, PREV_INUSE | self.abit) };
            }
        }
    }

    /// A non-main arena's top is too small: make more of its heap read-write, or start a new heap (glibc's sysmalloc for a
    /// non-main arena: grow_heap, then new_heap).
    fn grow_heap(&mut self, size: usize) -> bool {
        let h = self.heap;
        let ts = self.top_size();
        let need = size + MINSIZE;
        let pad = P.top_pad.load(Relaxed);
        // SAFETY: `h` is the HeapInfo of the heap the top lives in (H3), changed only under the arena's lock (H2).
        let committed = unsafe { (*h).committed };
        // SAFETY: as above.
        let ps = unsafe { (*h).pagesize };
        let up = |n: usize| n.saturating_add(ps - 1) & !(ps - 1);
        // the top always ends where the heap's read-write part ends
        for ext in [up(need.saturating_sub(ts).saturating_add(pad)), up(need.saturating_sub(ts))] {
            // SAFETY: the range is the reserved (PROT_NONE) rest of this arena's own heap, which nothing uses yet.
            if ext <= HEAP_MAX - committed && unsafe { mprotect_rw(h as usize + committed, ext) } {
                // (mprotect keeps MADV_HUGEPAGE of the part before: advise only a heap that was smaller than a huge page)
                if committed < P.thp_pagesize.load(Relaxed) {
                    madvise_thp(h as usize, committed + ext);
                }
                // SAFETY: as above.
                unsafe { (*h).committed += ext };
                self.add_system(ext);
                // SAFETY: the top's size word (H1); the top now reaches the end of the read-write part.
                unsafe { wr(self.top, 8, (ts + ext) | PREV_INUSE | self.abit) };
                return true;
            }
        }
        let hdr = HEAP_HDR;
        let Some(base) = hdr.checked_add(need).filter(|&n| n <= HEAP_MAX) else {
            return false;
        };
        let Some(nh) = new_heap(base, pad) else {
            return false;
        };
        let first = nh.committed;
        // SAFETY: as above; `arena` was set when that heap was made and never changes.
        nh.arena = unsafe { (*h).arena };
        nh.prev = h;
        let nh = nh as *mut HeapInfo;
        self.heap = nh;
        self.add_system(first);
        self.retire_top();
        let m = at(nh.cast(), hdr);
        self.top = m;
        // SAFETY: `m` is the first chunk of the new heap, inside its `first` read-write bytes.
        unsafe { wr(m, 8, (first - hdr) | PREV_INUSE | self.abit) };
        true
    }

    fn add_system(&mut self, n: usize) {
        self.system_mem += n;
        if self.system_mem > self.max_system_mem {
            self.max_system_mem = self.system_mem;
        }
    }
}

// ---- the system calls of the allocator: one audited function each ----

/// The current program break (brk(0) only asks).
fn brk_query() -> usize {
    // SAFETY: brk with 0 changes nothing.
    unsafe { syscall::syscall1(syscall::SYS_BRK, 0) }
}

/// Move the program break to `addr`; returns the break the kernel left (the old one on failure).
///
/// # Safety
/// Memory between the new and the old break is not in use (moving it down unmaps it).
unsafe fn brk_set(addr: usize) -> usize {
    // SAFETY: caller's contract; plain values.
    unsafe { syscall::syscall1(syscall::SYS_BRK, addr) }
}

/// 8 random bytes from getrandom(GRND_NONBLOCK), or None when the call does not give all 8.
fn random_word() -> Option<usize> {
    let mut r = 0usize;
    // SAFETY: the kernel writes at most 8 bytes into the local `r`.
    let got = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, &raw mut r as usize, 8, 1 /* GRND_NONBLOCK */) };
    if got == 8 { Some(r) } else { None }
}

/// Make `len` bytes at `addr` read-write; true on success.
///
/// # Safety
/// The range belongs to this allocator (the reserved part of one of its heaps).
unsafe fn mprotect_rw(addr: usize, len: usize) -> bool {
    // SAFETY: caller's contract; plain values.
    unsafe { syscall::syscall3(syscall::SYS_MPROTECT, addr, len, PROT_READ | PROT_WRITE) == 0 }
}

/// Unmap `len` bytes at `addr`; true on success.
///
/// # Safety
/// The range is a mapping (or the unused part of one) of this allocator that nothing uses any more.
unsafe fn munmap(addr: usize, len: usize) -> bool {
    // SAFETY: caller's contract; plain values.
    unsafe { syscall::syscall2(syscall::SYS_MUNMAP, addr, len) <= usize::MAX - 4095 }
}

/// Give the pages of `len` bytes at `addr` back to the system (MADV_DONTNEED: they read as zero afterwards).
///
/// # Safety
/// No live data is in the range (free chunk bodies only).
unsafe fn madvise_dontneed(addr: usize, len: usize) {
    // SAFETY: caller's contract; plain values.
    unsafe { syscall::syscall3(syscall::SYS_MADVISE, addr, len, MADV_DONTNEED) };
}

/// mremap(MREMAP_MAYMOVE) of a mapped chunk; the new address, or None.
///
/// # Safety
/// `addr`/`old` is a whole mapping of this allocator that the caller owns (an mmapped chunk).
unsafe fn mremap_maymove(addr: usize, old: usize, new: usize) -> Option<*mut u8> {
    // SAFETY: caller's contract; plain values.
    let r = unsafe { syscall::syscall4(syscall::SYS_MREMAP, addr, old, new, MREMAP_MAYMOVE) };
    if r <= usize::MAX - 4095 { Some(r as *mut u8) } else { None }
}

fn map_anon(len: usize) -> *mut u8 {
    map_anon_flags(len, 0)
}

/// A private anonymous read-write mapping with more mmap flags (MAP_HUGETLB and its size); null when there is none.
fn map_anon_flags(len: usize, flags: usize) -> *mut u8 {
    mmap_new(len, PROT_READ | PROT_WRITE, flags)
}

/// A new private anonymous mapping (the kernel picks the address, so nothing in use is replaced); null on failure.
fn mmap_new(len: usize, prot: usize, flags: usize) -> *mut u8 {
    // SAFETY: address 0 without MAP_FIXED: the kernel maps fresh memory and never replaces an existing mapping.
    let r = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | flags, usize::MAX, 0) };
    if r > usize::MAX - 4095 { null_mut() } else { r as *mut u8 }
}

/// mmap a chunk for `size` (a chunk size); returns the user pointer. (Cold: a system call follows anyway, and its code
/// must not sit between the hot blocks of `malloc_slow`, measured 1.07-1.11x on malloc/free of 4096 bytes there.)
#[cold]
fn mmap_chunk(s: &mut State, size: usize) -> *mut u8 {
    if P.n_mmaps.load(Relaxed) >= P.mmap_max.load(Relaxed) {
        return null_mut();
    }
    // huge pages first for a chunk of at least one (glibc's sysmalloc), then ordinary pages
    let hp = P.hp_pagesize.load(Relaxed);
    let mut m = null_mut();
    let mut len = 0;
    if hp > 0
        && size >= hp
        && let Some(l) = size.checked_add(16 + hp - 1)
    {
        len = l & !(hp - 1);
        m = map_anon_flags(len, P.hp_flags.load(Relaxed));
    }
    if m.is_null() {
        len = (size + 8 + PAGE - 1) & !(PAGE - 1);
        m = map_anon(len);
        if m.is_null() {
            return null_mut();
        }
        madvise_thp(m as usize, len);
    }
    // SAFETY: `m` is a fresh read-write mapping of `len` >= 16 bytes: the chunk's prev_size (offset from the mapping) word.
    unsafe { wr(m, 0, 0) };
    // SAFETY: as above: its size word.
    unsafe { wr(m, 8, len | IS_MMAPPED) };
    count_add(&P.n_mmaps, 1);
    let now = count_add(&P.mmapped_mem, len);
    count_max(&P.max_mmapped_mem, now);
    s.last_fresh = true;
    chunk2mem(m)
}

/// Unmap an mmapped chunk.
///
/// # Safety
/// `c` is an mmapped chunk (IS_MMAPPED) whose block the caller frees (H4).
unsafe fn munmap_chunk(c: *mut u8) {
    // SAFETY: the offset word of the mmapped chunk `c` (contract).
    let off = unsafe { rd(c, 0) };
    // SAFETY: as above: its size.
    let len = unsafe { csize(c) };
    let base = c.wrapping_sub(off);
    count_add(&P.n_mmaps, usize::MAX);
    count_add(&P.mmapped_mem, len.wrapping_neg());
    // SAFETY: the chunk's whole mapping, which its block (freed by the caller) was the only user of.
    if !unsafe { munmap(base as usize, len + off) } {
        fatal("munmap_chunk(): invalid pointer");
    }
}

#[inline(never)]
fn set_enomem() {
    errno::set(ENOMEM);
}

/// Take the first chunk of per-size list `i` (chunk size `size`, the list not empty) for the caller: unlinked, its
/// double-free mark cleared, the arena's counters updated.
///
/// # Safety
/// `c` is the first chunk of `s.small[i]` (H1, H2), of `size` bytes.
#[inline(always)]
unsafe fn take_small(s: &mut State, i: usize, c: *mut u8, size: usize) {
    // SAFETY: `c` is on the list (contract).
    s.small[i] = unsafe { sl_get(c) };
    // SAFETY: the second link word of `c`, now the caller's.
    unsafe { wr(c, 24, 0) };
    s.small_bytes = s.small_bytes.wrapping_sub(size);
    s.last_fresh = false;
}

/// Put chunk `c` of `size` bytes (a small size) on the arena's per-size list, marked as freed; merges the lists into the
/// bins when they hold too much.
///
/// # Safety
/// `c` is an in-use small chunk of this arena (H1, H2) being freed (H4), `size` its size.
#[inline(always)]
unsafe fn push_small(s: &mut State, c: *mut u8, size: usize) {
    let i = size >> 4;
    // SAFETY: `c` is the caller's free chunk: its link words.
    unsafe { sl_set(c, s.small[i]) };
    // SAFETY: as above.
    unsafe { wr(c, 24, key()) };
    s.small[i] = c;
    s.small_bytes += size;
    if s.small_bytes > SMALL_BYTES_MAX {
        s.consolidate();
    }
}

#[inline]
fn malloc_nl(s: &mut State, n: usize) -> *mut u8 {
    let Some(size) = request2size(n) else {
        return malloc_toobig();
    };
    if size <= SMALL_MAX && perturb() == 0 {
        // Fast path: reuse a block from the per-size list (a non-empty list implies init).
        let i = size >> 4;
        let c = s.small[i];
        if !c.is_null() {
            // SAFETY: `c` is the first chunk of list `i`, which holds chunks of `size` bytes.
            unsafe { take_small(s, i, c, size) };
            return chunk2mem(c);
        }
    }
    malloc_slow(s, size, n)
}

#[cold]
#[inline(never)]
fn malloc_toobig() -> *mut u8 {
    set_enomem();
    // (opaque: a known null result would turn the caller's tail jump into a call that needs a stack frame)
    core::hint::black_box(null_mut())
}

/// `fill`: the request, the bytes M_PERTURB fills (glibc's alloc_perturb); 0 for none (calloc clears the block itself).
#[inline(never)]
fn malloc_slow(s: &mut State, size: usize, fill: usize) -> *mut u8 {
    if !s.init {
        s.init();
    }
    // (read after the set-up: the tunables may have set it)
    let pert = if fill != 0 { perturb() } else { 0 };
    if size <= SMALL_MAX {
        let i = size >> 4;
        let c = s.small[i];
        if !c.is_null() {
            // SAFETY: `c` is the first chunk of list `i`, which holds chunks of `size` bytes.
            unsafe { take_small(s, i, c, size) };
            // (a chunk the lists keep in place of glibc's tcache comes back as it is, as from glibc's tcache)
            if lists_are_tcache() {
                return chunk2mem(c);
            }
            // SAFETY: the block of `c` has `size - 8` >= `fill` usable bytes (`size` = request2size(fill)).
            return unsafe { perturb_alloc(pert, chunk2mem(c), fill) };
        }
    }
    let c = alloc_chunk(s, size);
    if c.is_null() {
        set_enomem();
        return null_mut();
    }
    // SAFETY: `c` is a new chunk of at least `size` bytes, so its block holds `fill` bytes.
    unsafe { perturb_alloc(pert, chunk2mem(c), fill) }
}

/// Fill `n` bytes at `m` with M_PERTURB's pattern (nothing when `pert` is 0); returns `m`.
///
/// # Safety
/// `m` is a block of at least `n` usable bytes that the caller is handing out.
#[inline(always)]
unsafe fn perturb_alloc(pert: u8, m: *mut u8, n: usize) -> *mut u8 {
    if pert != 0 {
        // SAFETY: caller's contract.
        unsafe { rusty_libc_mem::memset(m.cast(), i32::from(pert ^ 0xff), n) };
    }
    m
}

/// Find or make a chunk of `size` bytes (a chunk size, not a request).
fn alloc_chunk(s: &mut State, size: usize) -> *mut u8 {
    s.last_fresh = false;
    let c = s.take_from_bins(size);
    if !c.is_null() {
        return c;
    }
    let c = s.alloc_from_top(size);
    if !c.is_null() {
        return c;
    }
    if size >= P.mmap_threshold.load(Relaxed) {
        let m = mmap_chunk(s, size);
        if !m.is_null() {
            return mem2chunk(m);
        }
    }
    // memalign hands most of this block straight back: merging the quick lists to find room would glue their blocks onto
    // those pieces and move the block that comes back to the same size of request (glibc extends the heap here too and
    // never merges its tcache).
    if s.grow_first && s.grow(size) {
        let c = s.alloc_from_top(size);
        if !c.is_null() {
            return c;
        }
    }
    // Gather the quickly-reused small chunks into the bins and look again.
    s.consolidate();
    let c = s.take_from_bins(size);
    if !c.is_null() {
        return c;
    }
    let c = s.alloc_from_top(size);
    if !c.is_null() {
        return c;
    }
    if !s.grow(size) {
        return null_mut();
    }
    s.alloc_from_top(size)
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4); `s` is the arena at hand (H2).
#[inline]
unsafe fn free_nl(s: &mut State, p: *mut u8) {
    if p.is_null() {
        return;
    }
    let c = mem2chunk(p);
    // SAFETY: the size word of the caller's block's chunk (H4).
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    // Fast path: an ordinary small block goes onto its per-size list.
    if head & (IS_MMAPPED | NON_MAIN_ARENA) == s.abit
        && (MINSIZE..=SMALL_MAX).contains(&size)
        && size & 15 == 0
        && (p as usize) & 15 == 0
        && perturb() == 0
        && small_enabled()
        // SAFETY: the chunk's second link word (inside its block: every chunk is at least MINSIZE).
        && unsafe { rd(c, 24) } != key()
    {
        // SAFETY: an in-use small chunk of this arena (checked above) being freed.
        unsafe { push_small(s, c, size) };
        return;
    }
    // SAFETY: as for this function.
    unsafe { free_slow(s, p) }
}

/// # Safety
/// As `free_nl`.
#[inline(never)]
unsafe fn free_slow(s: &mut State, p: *mut u8) {
    if p.is_null() {
        return;
    }
    if (p as usize) & 15 != 0 {
        fatal("free(): invalid pointer");
    }
    let c = mem2chunk(p);
    // SAFETY: the size word of the caller's block's chunk (H4).
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED != 0 {
        // SAFETY: an mmapped chunk being freed.
        return unsafe { free_mmapped(c, size) };
    }
    if head & NON_MAIN_ARENA != s.abit {
        // SAFETY: the caller's block, of another arena.
        return unsafe { free_foreign(p) };
    }
    if size < MINSIZE || size & 15 != 0 {
        fatal("free(): invalid size");
    }
    // Read the double-free mark before M_PERTURB overwrites the block (glibc also detects a
    // double free while perturbing).
    // SAFETY: the chunk's second link word (inside its block, `size` >= MINSIZE).
    let marked = unsafe { rd(c, 24) } == key();
    let pert = perturb();
    // SAFETY: an in-use chunk of this arena of `size` bytes, being freed.
    let to_lists = pert == 0 || unsafe { free_perturb(s, p, size, pert) };
    if marked && small_enabled() {
        // Possibly freed twice: look for it on every list (not only the one of its size: an overflow of the block before
        // it can have changed the size in its header, glibc's tst-tcfree4)
        for list in s.small.iter() {
            let mut q = *list;
            while !q.is_null() {
                if q == c {
                    fatal("free(): double free detected in tcache 2");
                }
                // SAFETY: `q` is on one of the arena's per-size lists (H1, H2).
                q = unsafe { sl_get(q) };
            }
        }
    }
    if size <= SMALL_MAX && small_enabled() && to_lists {
        // SAFETY: an in-use small chunk of this arena being freed.
        unsafe { push_small(s, c, size) };
        return;
    }
    let next = at(c, size);
    // SAFETY: the chunk after `c` (H1).
    if next != s.top && unsafe { rd(next, 8) } & PREV_INUSE == 0 {
        fatal("double free or corruption (!prev)");
    }
    // SAFETY: an in-use chunk of this arena being freed: now on no list.
    unsafe { s.free_merge(c, size) };
    if size >= CONSOLIDATE_THRESHOLD {
        s.consolidate();
        s.trim_top(P.trim_threshold.load(Relaxed), P.top_pad.load(Relaxed));
    }
}

/// Free an mmapped chunk of `size` bytes: the dynamic mmap threshold follows it (glibc), then the mapping goes.
///
/// # Safety
/// `c` is an mmapped chunk whose block is being freed (H4).
#[inline(always)]
unsafe fn free_mmapped(c: *mut u8, size: usize) {
    if P.dynamic_thresholds.load(Relaxed) && size > P.mmap_threshold.load(Relaxed) && size <= MMAP_THRESHOLD_MAX {
        P.mmap_threshold.store(size, Relaxed);
        P.trim_threshold.store(2 * size, Relaxed);
    }
    // SAFETY: caller's contract.
    unsafe { munmap_chunk(c) };
}

/// The mmapped-chunk part of `free_slow` for the multithreaded path, which has no arena at hand: the same checks, in
/// the same order (free_slow tests the alignment first).
///
/// # Safety
/// `p` is a block of this allocator whose chunk is mmapped (H4), `size` its chunk size.
#[inline(never)]
unsafe fn free_mmapped_block(p: *mut u8, size: usize) {
    if (p as usize) & 15 != 0 {
        fatal("free(): invalid pointer");
    }
    // SAFETY: caller's contract.
    unsafe { free_mmapped(mem2chunk(p), size) }
}

/// free with M_PERTURB: whether a small chunk may go to the per-size lists. Without a cache of the thread's own the lists
/// stand in for glibc's tcache, which keeps the first tcache_count chunks of each size up to tcache_max as they are; any
/// other chunk is filled and goes to the bins, as in glibc (with a cache, chunks reach these lists from it and are filled
/// as glibc fills its bin chunks). (Out of line: the common free without M_PERTURB pays one test.)
///
/// # Safety
/// `p` is the block of an in-use chunk of `size` bytes of arena `s` being freed (H1, H2, H4).
#[cold]
#[inline(never)]
unsafe fn free_perturb(s: &mut State, p: *mut u8, size: usize, pert: u8) -> bool {
    let tc = lists_are_tcache();
    let as_tcache = tc
        && small_enabled()
        && size <= P.tcache_max.load(Relaxed)
        // SAFETY: the arena's list of this size (H1, H2).
        && unsafe { list_shorter_than(s.small[size >> 4], P.tcache_count.load(Relaxed)) };
    if !as_tcache {
        // (glibc's free_perturb: the chunk less its two header words, so the last 8 usable bytes keep their contents)
        // SAFETY: the block has `size - 8` usable bytes (contract).
        unsafe { rusty_libc_mem::memset(p.cast(), i32::from(pert), size - 2 * SIZE_SZ) };
    }
    !tc || as_tcache
}

/// Whether the calling thread has no cache of its own (one thread, or the cache is off or given back): then the arena's
/// per-size lists are what glibc's tcache is for it.
#[inline]
fn lists_are_tcache() -> bool {
    no_cache(TCACHE.get())
}

/// Whether the list starting at `c` has fewer than `n` chunks.
///
/// # Safety
/// `c` is null or the first chunk of a per-size list or cache list the caller may read (H1, H2).
unsafe fn list_shorter_than(mut c: *mut u8, n: usize) -> bool {
    for _ in 0..n {
        if c.is_null() {
            return true;
        }
        // SAFETY: `c` is on the list (contract).
        c = unsafe { sl_get(c) };
    }
    false
}

/// Usable bytes of an allocated block.
///
/// # Safety
/// `p` is NULL or a block of this allocator (H4).
unsafe fn usable_size_nl(p: *mut u8) -> usize {
    if p.is_null() {
        return 0;
    }
    // SAFETY: the size word of the caller's block's chunk (H4).
    let head = unsafe { rd(mem2chunk(p), 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED != 0 { size - 16 } else { size - SIZE_SZ }
}

/// Clear the first `total` bytes of block `p`, which has at least `total` usable bytes: three words up to 24 (every block
/// has at least 24 usable bytes), overlapping vector stores up to 128, memset above.
///
/// # Safety
/// `p` is a block of at least max(`total`, 24) usable bytes that the caller is handing out.
#[inline(always)]
unsafe fn clear_block(p: *mut u8, total: usize) -> *mut u8 {
    if total <= 24 {
        let w = p as *mut [u64; 3];
        // SAFETY: caller's contract (24 bytes, 16-aligned block).
        unsafe { w.write([0; 3]) };
        return p;
    }
    if total <= 128 {
        // SAFETY: caller's contract.
        return unsafe { clear_small(p, total) };
    }
    // SAFETY: caller's contract.
    unsafe { clear_big(p, total) }
}

/// `calloc` for the common case, with no call and no saved registers on the path: no perturbation, a block of
/// a small size class waiting in its list (the block is never fresh, so it is cleared); everything else
/// (overflow, an empty list, a large size, a fresh top block) goes to `calloc_full`.
#[inline]
fn calloc_nl(s: &mut State, n: usize, m: usize) -> *mut u8 {
    if let Some(total) = n.checked_mul(m)
        && perturb() == 0
        && let Some(size) = request2size(total)
        && size <= SMALL_MAX
    {
        let i = size >> 4;
        let c = s.small[i];
        if !c.is_null() {
            // SAFETY: `c` is the first chunk of list `i`, which holds chunks of `size` bytes.
            unsafe { take_small(s, i, c, size) };
            // SAFETY: the block of `c` has `size - 8` >= `total` usable bytes (and at least 24).
            return unsafe { clear_block(chunk2mem(c), total) };
        }
    }
    calloc_full(s, n, m)
}

/// Clear 25..=128 bytes with overlapping 16-byte stores from both ends (no call through the memset dispatch slot).
///
/// # Safety
/// `p` has at least `total` (25..=128) writable bytes.
#[inline(always)]
unsafe fn clear_small(p: *mut u8, total: usize) -> *mut u8 {
    use core::arch::x86_64::{__m128i, _mm_setzero_si128, _mm_storeu_si128};
    // SAFETY: SSE2 is part of x86-64.
    let z = unsafe { _mm_setzero_si128() };
    // SAFETY: every store covers 16 bytes inside the first `total` bytes of `p` (offsets 0..=total-16).
    let st = |o: usize| unsafe { _mm_storeu_si128(p.wrapping_add(o) as *mut __m128i, z) };
    st(0);
    st(total - 16);
    if total > 32 {
        st(16);
        st(total - 32);
        if total > 64 {
            st(32);
            st(48);
            st(total - 48);
            st(total - 64);
        }
    }
    p
}

/// memset returns its destination, so this is a tail call.
///
/// # Safety
/// `p` has at least `total` writable bytes.
#[inline(always)]
unsafe fn clear_big(p: *mut u8, total: usize) -> *mut u8 {
    // SAFETY: caller's contract.
    unsafe { rusty_libc_mem::memset(p.cast(), 0, total).cast() }
}

fn calloc_full(s: &mut State, n: usize, m: usize) -> *mut u8 {
    let Some(total) = n.checked_mul(m) else {
        set_enomem();
        return null_mut();
    };
    // calloc's block is never perturbed (it is cleared)
    let Some(size) = request2size(total) else {
        return malloc_toobig();
    };
    let p = malloc_slow(s, size, 0);
    if p.is_null() {
        return p;
    }
    if !s.last_fresh {
        // SAFETY: `p` is a new block of at least `total` usable bytes (and at least 24).
        unsafe { clear_block_full(p, total) };
    }
    p
}

/// `clear_block`, with the memset of a large block not as a tail call (calloc_full returns `p` itself).
///
/// # Safety
/// As `clear_block`.
#[inline(always)]
unsafe fn clear_block_full(p: *mut u8, total: usize) {
    if total <= 24 {
        let w = p as *mut [u64; 3];
        // SAFETY: caller's contract.
        unsafe { w.write([0; 3]) };
    } else if total <= 128 {
        // SAFETY: caller's contract.
        unsafe { clear_small(p, total) };
    } else {
        // SAFETY: caller's contract.
        unsafe { rusty_libc_mem::memset(p.cast(), 0, total) };
    }
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4) that belongs to arena `s` or is mmapped; `s` is held under H2.
unsafe fn realloc_nl(s: &mut State, p: *mut u8, n: usize) -> *mut u8 {
    if p.is_null() {
        return malloc_nl(s, n);
    }
    if n == 0 {
        // SAFETY: the caller's block.
        unsafe { free_nl(s, p) };
        return null_mut();
    }
    let Some(size) = request2size(n) else {
        set_enomem();
        return null_mut();
    };
    let c = mem2chunk(p);
    // SAFETY: the size word of the caller's block's chunk (H4).
    let head = unsafe { rd(c, 8) };
    if head & IS_MMAPPED == 0 && head & NON_MAIN_ARENA != s.abit {
        // SAFETY: the caller's block, of another arena.
        return unsafe { realloc_foreign(p, n) };
    }
    let old = head & !FLAGS;
    if (p as usize) & 15 != 0 || old < MINSIZE {
        fatal("realloc(): invalid pointer");
    }
    if head & IS_MMAPPED != 0 {
        // SAFETY: the offset word of the mmapped chunk.
        let off = unsafe { rd(c, 0) };
        if old - 16 >= n && old - 16 < n + 2 * PAGE {
            return p; // keep the mapping when the size barely changes
        }
        let new_len = (size + 8 + PAGE - 1) & !(PAGE - 1);
        if off == 0 {
            // SAFETY: the chunk is its whole mapping (offset 0), owned by the caller's block.
            if let Some(nc) = unsafe { mremap_maymove(c as usize, old, new_len) } {
                let now = count_add(&P.mmapped_mem, new_len.wrapping_sub(old));
                count_max(&P.max_mmapped_mem, now);
                // SAFETY: `nc` is the moved mapping of `new_len` bytes: the chunk's size word.
                unsafe { wr(nc, 8, new_len | IS_MMAPPED) };
                return chunk2mem(nc);
            }
        }
        // SAFETY: the caller's block, `old - 16` usable bytes.
        return unsafe { move_block(s, p, old - 16, n) };
    }
    // Normal chunk.
    if size <= old {
        // shrink in place, giving back a tail that can stand alone
        let rem = old - size;
        if rem >= MINSIZE {
            // SAFETY: the size word of the caller's chunk.
            unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
            let r = at(c, size);
            // SAFETY: `r` is inside the chunk (`size + MINSIZE <= old`): the tail's size word.
            unsafe { wr(r, 8, rem | PREV_INUSE | s.abit) };
            // the tail is an in-use chunk until we free it, so the one after it stays marked
            // SAFETY: the tail is an in-use chunk of this arena, whose block nobody else knows.
            unsafe { free_nl(s, chunk2mem(r)) };
        }
        return p;
    }
    // grow: into the top chunk or a free neighbour
    let next = at(c, old);
    if next == s.top {
        let ts = s.top_size();
        if ts + old >= size + MINSIZE {
            // SAFETY: `c` is followed by the top, which holds enough.
            unsafe { grow_into_top(s, c, old, size, head) };
            return p;
        }
        // the top is too small: make it bigger first, as malloc would for this size (below the mmap threshold, where malloc
        // would map a block of its own), so the block grows where it is: no copy, the new pages not touched (glibc's realloc
        // ends the same way: its new block starts right after the old one and the two are merged). If the heap could not grow
        // in place (a new region), the block moves below.
        if size < P.mmap_threshold.load(Relaxed) && grow_top_for(s, c, old, size) {
            // SAFETY: as above (checked by grow_top_for).
            unsafe { grow_into_top(s, c, old, size, head) };
            return p;
        }
    } else {
        // SAFETY: the chunk after `c` (H1).
        let nsize = unsafe { csize(next) };
        // SAFETY: the chunk after that (H1).
        if unsafe { rd(at(next, nsize), 8) } & PREV_INUSE == 0 && old + nsize >= size {
            // SAFETY: `next` is free and not the top, so it is on a bin.
            unsafe { s.unlink(next, nsize) };
            let total = old + nsize;
            let rem = total - size;
            if rem >= MINSIZE {
                // SAFETY: the size word of the caller's chunk.
                unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
                let r = at(c, size);
                // SAFETY: `r` is inside the merged chunk: the remainder's size word.
                unsafe { wr(r, 8, rem | PREV_INUSE | s.abit) };
                let after = at(r, rem);
                // SAFETY: the chunk after the merged chunk (H1): its prev_size word.
                unsafe { wr(after, 0, rem) };
                // SAFETY: its size word.
                unsafe { clear_prev_inuse(after) };
                // SAFETY: the remainder is a free chunk on no list.
                unsafe { s.link_bin(r, rem) };
            } else {
                // SAFETY: the size word of the caller's chunk.
                unsafe { wr(c, 8, total | (head & PREV_INUSE) | s.abit) };
                // SAFETY: the chunk after the merged chunk (H1).
                unsafe { or_head(at(c, total), PREV_INUSE | s.abit) };
            }
            return p;
        }
    }
    // SAFETY: the caller's block, `old - 8` usable bytes.
    unsafe { move_block(s, p, old - SIZE_SZ, n) }
}

/// Clear PREV_INUSE in the size word of chunk `c`.
///
/// # Safety
/// As `wr` on `c + 8`.
#[inline(always)]
unsafe fn clear_prev_inuse(c: *mut u8) {
    // SAFETY: caller's contract.
    let h = unsafe { rd(c, 8) };
    // SAFETY: caller's contract.
    unsafe { wr(c, 8, h & !PREV_INUSE) };
}

/// Set `bits` in the size word of chunk `c`.
///
/// # Safety
/// As `wr` on `c + 8`.
#[inline(always)]
unsafe fn or_head(c: *mut u8, bits: usize) {
    // SAFETY: caller's contract.
    let h = unsafe { rd(c, 8) };
    // SAFETY: caller's contract.
    unsafe { wr(c, 8, h | bits) };
}

/// Extend chunk `c` (`old` bytes, followed by the top chunk) to `size` bytes out of the top, which holds enough.
///
/// # Safety
/// `c` is an in-use chunk of arena `s` (H1, H2) of `old` bytes followed by the top, and `old + top` >= `size + MINSIZE`.
#[inline(always)]
unsafe fn grow_into_top(s: &mut State, c: *mut u8, old: usize, size: usize, head: usize) {
    let ts = s.top_size();
    let nt = at(c, size);
    // SAFETY: the size word of `c` (contract).
    unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
    // SAFETY: `nt` lies inside the old top (contract): the new top's size word.
    unsafe { wr(nt, 8, (ts + old - size) | PREV_INUSE | s.abit) };
    s.top = nt;
    let end = c as usize + size;
    if end > s.high_water {
        s.high_water = end;
    }
}

/// realloc of chunk `c` followed by a top chunk too small for `size`: grow the heap; true if `c` is still followed by the top and
/// the top now holds enough.
#[cold]
#[inline(never)]
fn grow_top_for(s: &mut State, c: *mut u8, old: usize, size: usize) -> bool {
    s.grow(size - old) && at(c, old) == s.top && s.top_size() + old >= size + MINSIZE
}

/// # Safety
/// `p` is a block of arena `s` or mmapped (H4) with `old_usable` usable bytes.
unsafe fn move_block(s: &mut State, p: *mut u8, old_usable: usize, n: usize) -> *mut u8 {
    let q = malloc_nl(s, n);
    if q.is_null() {
        return q;
    }
    // SAFETY: `q` has at least `n` usable bytes, `p` `old_usable`; they are different blocks.
    unsafe { rusty_libc_mem::memcpy(q.cast(), p.cast(), old_usable.min(n)) };
    // SAFETY: the caller's block.
    unsafe { free_nl(s, p) };
    q
}

/// A just-freed small block of the size for `n` whose address happens to be `align`-aligned, unlinked from the small-block list
/// (the first 16 entries are looked at), or null. Small enough to inline into `memalign`'s single-thread path, so that the common
/// allocate-aligned/free pair saves no registers on the way.
#[inline(always)]
fn small_aligned_take(s: &mut State, align: usize, n: usize) -> *mut u8 {
    if align <= 16 || align > (usize::MAX >> 2) {
        return null_mut();
    }
    let Some(size) = request2size(n) else {
        return null_mut();
    };
    if size > SMALL_MAX || !small_enabled() || !s.init {
        return null_mut();
    }
    let i = size >> 4;
    let mut prev: *mut u8 = null_mut();
    let mut c = s.small[i];
    // (every chunk reached is on the arena's list `i`, H1, H2: `&mut State`)
    for _ in 0..16 {
        if c.is_null() {
            break;
        }
        if (chunk2mem(c) as usize) & (align - 1) == 0 {
            // SAFETY: `c` is on the list.
            let next = unsafe { sl_get(c) };
            if prev.is_null() {
                s.small[i] = next;
            } else {
                // SAFETY: `prev` is on the list.
                unsafe { sl_set(prev, next) };
            }
            // SAFETY: the second link word of `c`, now the caller's.
            unsafe { wr(c, 24, 0) };
            s.small_bytes = s.small_bytes.wrapping_sub(size);
            // (a chunk the lists keep in place of glibc's tcache comes back as it is)
            let pert = perturb();
            if pert == 0 || lists_are_tcache() {
                return chunk2mem(c);
            }
            // SAFETY: the block of `c` has `size - 8` usable bytes.
            return unsafe { perturb_alloc(pert, chunk2mem(c), size - SIZE_SZ) };
        }
        prev = c;
        // SAFETY: `c` is on the list.
        c = unsafe { sl_get(c) };
    }
    null_mut()
}

/// Aligned allocation: `align` must be a power of two.
fn memalign_nl(s: &mut State, align: usize, n: usize) -> *mut u8 {
    if align <= 16 {
        return malloc_nl(s, n);
    }
    if align > (usize::MAX >> 2) {
        // no allocation can be that aligned: glibc reports an alignment up to 2^63 as out of memory (EINVAL only above)
        set_enomem();
        return null_mut();
    }
    let Some(size) = request2size(n) else {
        set_enomem();
        return null_mut();
    };
    // A just-freed small block that happens to be aligned is the cheapest answer.
    let p = small_aligned_take(s, align, n);
    if !p.is_null() {
        return p;
    }
    let Some(req) = n.checked_add(align + MINSIZE) else {
        set_enomem();
        return null_mut();
    };
    s.grow_first = true;
    let m = malloc_nl(s, req);
    s.grow_first = false;
    if m.is_null() {
        return m;
    }
    // (below, `c` and the pieces cut from it are inside the new chunk of at least `req` + 8 bytes, H1, H2)
    let mut c = mem2chunk(m);
    // SAFETY: the new chunk's size word.
    let head = unsafe { rd(c, 8) };
    let mut total = head & !FLAGS;
    if (m as usize) & (align - 1) != 0 {
        let mut am = (m as usize + align - 1) & !(align - 1);
        if (am - m as usize) < MINSIZE {
            am += align;
        }
        let lead = am - m as usize;
        let nc = mem2chunk(am as *mut u8);
        if head & IS_MMAPPED != 0 {
            // SAFETY: the old chunk's offset word.
            let off = unsafe { rd(c, 0) };
            // SAFETY: `nc` is inside the mapping (`lead` < `align` + MINSIZE <= the slack): its offset word.
            unsafe { wr(nc, 0, off + lead) };
            // SAFETY: as above: its size word.
            unsafe { wr(nc, 8, (total - lead) | IS_MMAPPED) };
            return am as *mut u8;
        }
        // Split off the leading piece and free it.
        // SAFETY: the new chunk's size word.
        unsafe { wr(c, 8, lead | (head & PREV_INUSE) | s.abit) };
        // SAFETY: `nc` is inside the new chunk: its size word.
        unsafe { wr(nc, 8, (total - lead) | PREV_INUSE | s.abit) };
        let lead_chunk = c;
        c = nc;
        total -= lead;
        // Merge the piece with its free neighbours now (like glibc): on the quick lists it could never join the block
        // when that is freed, and the block would be too small to serve the same memalign call again.
        // SAFETY: the leading piece is a chunk of this arena on no list.
        unsafe { s.free_merge(lead_chunk, lead) };
    } else if head & IS_MMAPPED != 0 {
        return m;
    }
    // Give back a tail that can stand alone.
    if total - size >= MINSIZE {
        // SAFETY: the aligned chunk's size word.
        let h = unsafe { rd(c, 8) };
        // SAFETY: as above.
        unsafe { wr(c, 8, size | (h & PREV_INUSE) | s.abit) };
        let r = at(c, size);
        // SAFETY: `r` is inside the aligned chunk: the tail's size word.
        unsafe { wr(r, 8, (total - size) | PREV_INUSE | s.abit) };
        // SAFETY: the tail is a chunk of this arena on no list.
        unsafe { s.free_merge(r, total - size) };
    }
    chunk2mem(c)
}

/// Free-block statistics for mallinfo.
pub struct Stats {
    pub arena: usize,
    pub free_chunks: usize,
    pub small_chunks: usize,
    pub small_bytes: usize,
    pub free_bytes: usize,
    pub top: usize,
}

fn stats_nl(s: &mut State) -> Stats {
    if !s.init {
        s.init();
    }
    let mut free_chunks = 0;
    let mut free_bytes = 0;
    for i in 0..NBINS {
        let b = s.bin_node(i);
        let mut c = s.bins[i][2] as *mut u8;
        while c != b {
            free_chunks += 1;
            // SAFETY: `c` is a chunk on bin `i` (H1, H2: `&mut State`).
            free_bytes += unsafe { csize(c) };
            // SAFETY: as above: its fd word.
            c = unsafe { rd(c, 16) } as *mut u8;
        }
    }
    let mut small_chunks = 0;
    let mut small_bytes = 0;
    for &head in s.small.iter() {
        let mut c = head;
        while !c.is_null() {
            small_chunks += 1;
            // SAFETY: `c` is on a per-size list of the arena (H1, H2).
            small_bytes += unsafe { csize(c) };
            // SAFETY: as above.
            c = unsafe { sl_get(c) };
        }
    }
    Stats {
        arena: if s.abit == 0 { (s.brk_end - s.brk_start) + s.foreign_bytes } else { s.system_mem },
        free_chunks,
        small_chunks,
        small_bytes,
        free_bytes,
        top: s.top_size(),
    }
}

/// Release free pages in the middle of the heap back to the system (malloc_trim).
fn trim_nl(s: &mut State, pad: usize) -> i32 {
    if !s.init {
        return 0;
    }
    s.consolidate();
    let mut released = 0;
    for i in 0..NBINS {
        let b = s.bin_node(i);
        let mut c = s.bins[i][2] as *mut u8;
        while c != b {
            // SAFETY: `c` is a chunk on bin `i` (H1, H2: `&mut State`).
            let size = unsafe { csize(c) };
            // whole pages strictly inside the free chunk (keep its header and links)
            let lo = (c as usize + 32 + PAGE - 1) & !(PAGE - 1);
            let hi = (c as usize + size - 8) & !(PAGE - 1);
            if hi > lo && hi - lo >= PAGE {
                // SAFETY: whole pages inside the body of a free chunk, past its links: no live data.
                unsafe { madvise_dontneed(lo, hi - lo) };
                released = 1;
            }
            // SAFETY: as above: its fd word.
            c = unsafe { rd(c, 16) } as *mut u8;
        }
    }
    let before = s.top_size();
    s.trim_top(0, pad);
    if s.top_size() < before {
        released = 1;
    }
    released
}

fn ensure_init_nl(s: &mut State) {
    if !s.init {
        s.init();
    }
}


// ---- arenas (glibc's arena.c): which arena a thread and a chunk belong to ----

/// The arena of the calling thread (null until it first allocates while the process has threads).
#[thread_local]
static THREAD_ARENA: Cell<*mut ArenaCell> = Cell::new(null_mut());
/// The calling thread's cache of free small chunks (glibc's tcache): `EMPTY` when it has none (not made yet, switched off,
/// or given back because the thread is ending: TCACHE_DONE then says not to make one again). Never null, as glibc's
/// (`__tcache_dummy`): the fast paths need no test of the pointer, an empty list or no room sends them to the slow paths.
#[thread_local]
static TCACHE: Cell<*mut TCache> = Cell::new(&raw const EMPTY as *mut TCache);
static EMPTY: TCache = TCache { room: [0; NSMALL], entries: [null_mut(); NSMALL] };
// SAFETY: EMPTY is never written (no room, no entries), and no other TCache is shared between threads.
unsafe impl Sync for TCache {}

#[inline(always)]
fn no_cache(t: *mut TCache) -> bool {
    core::ptr::eq(t, &EMPTY)
}
#[thread_local]
static TCACHE_DONE: Cell<bool> = Cell::new(false);
/// The arena limit of a host test build (feature `no-brk`: this allocator inside a host glibc process, next to its
/// malloc), unless M_ARENA_MAX sets one. The host's threads never run `thread_shutdown` (only our pthread's exit path
/// calls it), so an arena is never given back and every new test thread made a new one, up to 8 per CPU: each a 64 MiB
/// reservation, up to 128 of them on a 16-thread machine: the locale tests peaked at 10.4 GB of address space (2.6 GB
/// with this limit) and failed in most runs under the helpers' 6 GB cap (`prlimit --as`). Past the limit threads share
/// arenas (`reuse_arena`). The shipped library is built without the feature and keeps glibc's limit.
const HOSTED_ARENA_MAX: usize = 8;
/// glibc's `narenas_limit`: worked out once, the first time an arena is chosen after more than arena_test exist.
static NARENAS_LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Bytes at the start of a heap before its first chunk (the HeapInfo, 16-byte aligned).
const HEAP_HDR: usize = (core::mem::size_of::<HeapInfo>() + 15) & !15;

/// The arena chunk `c` belongs to (not for mmapped chunks): the main arena unless NON_MAIN_ARENA is set, then the arena
/// named by the header of its 64 MiB-aligned heap.
///
/// # Safety
/// `c` is a chunk of this allocator that is not mmapped (H1, H4).
#[inline(always)]
unsafe fn arena_for_chunk(c: *mut u8) -> *mut ArenaCell {
    // SAFETY: the chunk's size word (contract); its flags never change while the chunk exists.
    if unsafe { rd(c, 8) } & NON_MAIN_ARENA == 0 {
        main_ptr()
    } else {
        // SAFETY: a NON_MAIN_ARENA chunk lies in a HEAP_MAX-aligned heap headed by its HeapInfo (H3); `arena` is set once
        // when the heap is made.
        unsafe { (*((c as usize & !(HEAP_MAX - 1)) as *mut HeapInfo)).arena }
    }
}

/// glibc's new_heap: a heap for `size` bytes plus `pad`, in huge pages first when glibc.malloc.hugetlb asked for them (then
/// in ordinary pages), its `committed` and `pagesize` set. None when the system has no room.
fn new_heap(size: usize, pad: usize) -> Option<&'static mut HeapInfo> {
    let hp = P.hp_pagesize.load(Relaxed);
    let ps = if hp != 0 { hp } else { P.thp_pagesize.load(Relaxed) };
    if ps != 0 && ps <= HEAP_MAX {
        let h = alloc_new_heap(size, pad, ps, if hp != 0 { P.hp_flags.load(Relaxed) } else { 0 });
        if h.is_some() {
            return h;
        }
    }
    alloc_new_heap(size, pad, PAGE, 0)
}

/// A new heap of HEAP_MAX bytes at a HEAP_MAX-aligned address, its first bytes read-write (`size` plus `pad`, at least
/// glibc's HEAP_MIN_SIZE or one huge page, whole units of `pagesize`), the rest reserved without access (glibc's
/// alloc_new_heap). None when the system has no room. The HeapInfo at its start has `committed` and `pagesize` set, its
/// `arena` and `prev` null.
fn alloc_new_heap(size: usize, pad: usize, pagesize: usize, flags: usize) -> Option<&'static mut HeapInfo> {
    const PROT_NONE: usize = 0;
    const MAP_NORESERVE: usize = 0x4000;
    const HEAP_MIN: usize = 32 << 10;
    let hp = P.hp_pagesize.load(Relaxed);
    let min = if hp == 0 || hp > HEAP_MAX { HEAP_MIN } else { hp };
    let size = if size.saturating_add(pad) < min {
        min
    } else if size.saturating_add(pad) <= HEAP_MAX {
        size + pad
    } else if size > HEAP_MAX {
        return None;
    } else {
        HEAP_MAX
    };
    let first = (size + pagesize - 1) & !(pagesize - 1);
    // (huge pages are mapped without MAP_NORESERVE, as glibc does: with none reserved the mapping fails here instead of
    // faulting later)
    let extra = if flags != 0 { flags } else { MAP_NORESERVE };
    let r = mmap_new(2 * HEAP_MAX, PROT_NONE, extra);
    if r.is_null() {
        return None;
    }
    let r = r as usize;
    let start = (r + HEAP_MAX - 1) & !(HEAP_MAX - 1);
    if start > r {
        // SAFETY: the part of the fresh reservation before the aligned heap, which nothing uses.
        unsafe { munmap(r, start - r) };
    }
    let end = r + 2 * HEAP_MAX;
    if end > start + HEAP_MAX {
        // SAFETY: the part of the fresh reservation after the aligned heap, which nothing uses.
        unsafe { munmap(start + HEAP_MAX, end - (start + HEAP_MAX)) };
    }
    // SAFETY: the start of the fresh reservation, which nothing uses yet.
    if !unsafe { mprotect_rw(start, first) } {
        // SAFETY: the fresh heap, which nothing uses.
        unsafe { munmap(start, HEAP_MAX) };
        return None;
    }
    madvise_thp(start, first);
    let h = start as *mut HeapInfo;
    // SAFETY: `h` is the start of `first` (>= HEAP_MIN) fresh read-write bytes, aligned, used by nobody else; the heap is
    // never unmapped while it holds chunks, and the reference handed out is the only one made from this mapping.
    unsafe { h.write(HeapInfo { arena: null_mut(), prev: null_mut(), committed: first, pagesize }) };
    // SAFETY: as above: initialised just now.
    Some(unsafe { &mut *h })
}

/// A new arena numbered `id` in a heap of its own: the HeapInfo, the arena, then its top chunk (glibc's _int_new_arena).
fn new_arena(id: usize) -> *mut ArenaCell {
    let st_off = HEAP_HDR;
    let top_off = (st_off + core::mem::size_of::<ArenaCell>() + 15) & !15;
    let Some(h) = new_heap(top_off + MINSIZE, P.top_pad.load(Relaxed)) else {
        return null_mut();
    };
    let first = h.committed;
    let hp = h as *mut HeapInfo;
    let a = at(hp.cast(), st_off) as *mut ArenaCell;
    // SAFETY: `a` is inside the heap's fresh read-write part (`top_off + MINSIZE` <= `first`), 16-aligned, used by nobody.
    unsafe { a.write(ArenaCell::new(State::empty())) };
    // SAFETY: just written; the arena lives for ever (H3).
    let cell = unsafe { &*a };
    // SAFETY: no other thread knows this arena yet (H2).
    let s = unsafe { &mut *cell.state.as_ptr() };
    s.abit = NON_MAIN_ARENA;
    s.top_is_brk = false;
    s.heap = hp;
    s.id = id;
    // SAFETY: `hp` is the new heap's HeapInfo (the `&mut` from new_heap is no longer used).
    unsafe { (*hp).arena = a };
    s.add_system(first);
    s.init();
    let top = at(hp.cast(), top_off);
    s.top = top;
    // SAFETY: the new heap's first chunk, inside its read-write part.
    unsafe { wr(top, 8, (first - top_off) | PREV_INUSE | NON_MAIN_ARENA) };
    a
}

/// The malloc tunables (`GLIBC_TUNABLES=glibc.malloc.*` and the `MALLOC_*_` variables that alias them), applied when the
/// main arena is set up, in glibc's order (ptmalloc_init); one the environment did not set changes nothing. Each does what
/// the matching mallopt does in glibc 2.43, without mallopt's bounds: top_pad, mmap_threshold, trim_threshold and mmap_max
/// switch the dynamic thresholds off. `glibc.malloc.check` (it needs glibc's libc_malloc_debug.so), `mxfast` (glibc 2.43 does
/// not read it) and `tcache_unsorted_limit` (no unsorted list here) change nothing.
/// Out of line (cold): its buffers must not sit in its caller's frame, where they take stack from the first malloc of every
/// thread; a thread with a minimum-size stack loads libgcc_s and unwinds on it (glibc's nptl/tst-minstack-exit).
#[cold]
#[inline(never)]
fn apply_tunables(main: &mut State) {
    use rusty_libc_core::tunables as t;
    let get = rusty_libc_core::tunable_set;
    if let Some(v) = get(t::MALLOC_TOP_PAD) {
        P.top_pad.store(v as usize, Relaxed);
        P.dynamic_thresholds.store(false, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_PERTURB) {
        P.perturb.store(v as u8, Relaxed);
    }
    let threshold_set = get(t::MALLOC_MMAP_THRESHOLD);
    if let Some(v) = threshold_set {
        P.mmap_threshold.store(v as usize, Relaxed);
        P.dynamic_thresholds.store(false, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_TRIM_THRESHOLD) {
        P.trim_threshold.store(v as usize, Relaxed);
        P.dynamic_thresholds.store(false, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_MMAP_MAX) {
        P.mmap_max.store(v as usize, Relaxed);
        P.dynamic_thresholds.store(false, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_ARENA_MAX) {
        P.arena_max.store(v as usize, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_ARENA_TEST) {
        P.arena_test.store(v as usize, Relaxed);
    }
    // tcache_max: the cache keeps chunks up to the chunk size of that request (glibc refuses a request past PTRDIFF_MAX and
    // one past its largest cache bin; it can keep chunks larger than SMALL_MAX, this cache cannot)
    if let Some(v) = get(t::MALLOC_TCACHE_MAX)
        && (v as u64) <= isize::MAX as u64
        && let Some(nb) = request2size(v as usize)
        && tcache_bin_exists(nb)
    {
        P.tcache_max.store(nb.min(SMALL_MAX), Relaxed);
    }
    if let Some(v) = get(t::MALLOC_TCACHE_COUNT)
        && (v as u64) <= u16::MAX as u64
    {
        P.tcache_count.store(v as usize, Relaxed);
    }
    if let Some(v) = get(t::MALLOC_HUGETLB) {
        let v = v as u64;
        if v == 1 {
            // transparent huge pages: only where the system has them on (always) or on request (madvise)
            let mut buf = [0u8; 64];
            let n = read_small(c"/sys/kernel/mm/transparent_hugepage/enabled", &mut buf);
            let mode = &buf[..n];
            let madvise = mode == b"always [madvise] never\n";
            if madvise || mode == b"[always] madvise never\n" {
                let n = read_small(c"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", &mut buf);
                let mut r = 0usize;
                for &c in buf[..n].iter().take_while(|&&c| c != b'\n') {
                    r = r.wrapping_mul(10).wrapping_add(c.wrapping_sub(b'0') as usize);
                }
                P.thp_pagesize.store(r, Relaxed);
                P.thp_madvise.store(madvise, Relaxed);
                if r.is_power_of_two() {
                    P.trim_mask.store(!(r - 1), Relaxed);
                }
            }
        } else if v >= 2 {
            let hp = hugepage_size(if v == 2 { 0 } else { v as usize });
            if hp != 0 {
                const MAP_HUGETLB: usize = 0x40000;
                const MAP_HUGE_SHIFT: u32 = 26;
                P.hp_pagesize.store(hp, Relaxed);
                P.hp_flags.store(MAP_HUGETLB | ((hp.trailing_zeros() as usize) << MAP_HUGE_SHIFT), Relaxed);
            }
        }
    }
    // huge pages that fit a heap: the main arena keeps to mmap (where huge pages can be asked for), and big requests are
    // mmapped from one huge page up unless the threshold was set
    let hp = P.hp_pagesize.load(Relaxed);
    if hp > 0 && hp <= HEAP_MAX {
        if threshold_set.is_none() {
            P.mmap_threshold.store(hp, Relaxed);
            P.dynamic_thresholds.store(false, Relaxed);
        }
        main.top_is_brk = false;
    }
}

/// Whether glibc 2.43's cache has a bin for chunks of `nb` bytes (do_set_tcache_max refuses a size without one): its 64
/// small bins up to 1040 bytes, then 12 large bins indexed by the bit length of the size taken as 32 bits (up to 4 MiB).
fn tcache_bin_exists(nb: usize) -> bool {
    const SMALL_BINS: usize = 64;
    let idx = (nb - MINSIZE) / 16;
    idx < SMALL_BINS || SMALL_BINS + 21 - ((nb as u32).leading_zeros() as usize) < SMALL_BINS + 12
}

/// glibc's __malloc_hugepage_config: the system's default huge page size (`Hugepagesize:` of /proc/meminfo) for 0, else
/// `requested` when the system has huge pages of that size (/sys/kernel/mm/hugepages/hugepages-<kB>kB); 0 when not.
/// Out of line (cold): its buffers must not sit in its caller's frame, where they take stack from the first malloc of every
/// thread; a thread with a minimum-size stack loads libgcc_s and unwinds on it (glibc's nptl/tst-minstack-exit).
#[cold]
#[inline(never)]
fn hugepage_size(requested: usize) -> usize {
    if requested == 0 {
        let mut buf = [0u8; 4096];
        let n = read_small(c"/proc/meminfo", &mut buf);
        let s = &buf[..n];
        const TAG: &[u8] = b"Hugepagesize:";
        let Some(at) = s.windows(TAG.len()).position(|w| w == TAG) else { return 0 };
        let mut hp = 0usize;
        for &c in s[at + TAG.len()..].iter().skip(1).take_while(|&&c| c.is_ascii_digit() || c == b' ') {
            if c != b' ' {
                hp = hp.wrapping_mul(10).wrapping_add((c - b'0') as usize);
            }
        }
        return hp.wrapping_mul(1024);
    }
    if !requested.is_multiple_of(1024) {
        return 0;
    }
    let mut path = *b"/sys/kernel/mm/hugepages/hugepages-00000000000000000000kB\0";
    let mut digits = [0u8; 20];
    let (mut k, mut n) = (requested / 1024, 0);
    loop {
        digits[n] = b'0' + (k % 10) as u8;
        n += 1;
        k /= 10;
        if k == 0 {
            break;
        }
    }
    let base = b"/sys/kernel/mm/hugepages/hugepages-".len();
    for i in 0..n {
        path[base + i] = digits[n - 1 - i];
    }
    path[base + n..base + n + 3].copy_from_slice(b"kB\0");
    const O_DIRECTORY: usize = 0o200000;
    let Ok(path) = core::ffi::CStr::from_bytes_until_nul(&path) else { return 0 };
    let Some(fd) = open_cloexec(path, O_DIRECTORY) else { return 0 };
    let _ = rusty_libc_core::unistd::close(fd);
    requested
}

/// glibc's madvise_thp: with transparent huge pages on request, ask for them on a region of at least one huge page (from
/// its first page boundary).
fn madvise_thp(p: usize, size: usize) {
    const MADV_HUGEPAGE: usize = 14;
    let thp = P.thp_pagesize.load(Relaxed);
    if !P.thp_madvise.load(Relaxed) || size < thp {
        return;
    }
    let q = (p + PAGE - 1) & !(PAGE - 1);
    // SAFETY: MADV_HUGEPAGE only changes how the pages are backed, never their contents; plain values.
    unsafe { syscall::syscall3(syscall::SYS_MADVISE, q, size - (q - p), MADV_HUGEPAGE) };
}

/// openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC | `flags`) without a cancellation point; the descriptor, or None.
fn open_cloexec(path: &core::ffi::CStr, flags: usize) -> Option<i32> {
    // SAFETY: `path` is a NUL-terminated string the kernel only reads.
    let fd = unsafe { syscall::syscall4(syscall::SYS_OPENAT, -100isize as usize, path.as_ptr() as usize, flags | 0o2000000, 0) };
    if fd > usize::MAX - 4095 { None } else { Some(fd as i32) }
}

/// Read a small file into `buf` (open O_RDONLY|O_CLOEXEC, read, close: glibc's nocancel calls); the bytes read.
fn read_small(path: &core::ffi::CStr, buf: &mut [u8]) -> usize {
    let Some(fd) = open_cloexec(path, 0) else { return 0 };
    let mut n = 0;
    while n < buf.len() {
        match rusty_libc_core::unistd::read_nocancel(fd, &mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(r) => n += r,
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    n
}

/// The online processors as glibc's `__get_nprocs` counts them for the arena limit: rusty-libc-rs-core's `cpus::online`
/// (the range list in /sys/devices/system/cpu/online, else the cpuN lines of /proc/stat, else the affinity mask, else 2;
/// the same function as get_nprocs). (Not the affinity mask first: that gave a different limit under taskset, and a call a
/// seccomp allowlist made from glibc's calls may not have.)
/// Out of line (cold): its buffers must not sit in its caller's frame, where they take stack from the first malloc of every
/// thread; a thread with a minimum-size stack loads libgcc_s and unwinds on it (glibc's nptl/tst-minstack-exit).
/// rusty-libc-rs-core's steps are out of line too, one at a time (at most 4 KiB of stack each).
#[cold]
#[inline(never)]
fn nprocs() -> usize {
    rusty_libc_rs_core::cpus::online() as usize
}

/// A handle to an arena of the ring. Only this module makes one, and only from the main arena, `new_arena` or the ring
/// links, so it always names an arena that lives for ever (H3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Arena(*mut ArenaCell);

impl Arena {
    #[inline(always)]
    fn main() -> Arena {
        Arena(main_ptr())
    }

    /// The arena's shared part. Shared references are all other threads ever make to it: what they change through it is
    /// atomic (the lock, the links) or inside the `UnsafeCell` that holds the state.
    #[inline(always)]
    fn cell(self) -> &'static ArenaCell {
        // SAFETY: an Arena always names an arena of the ring, which lives for ever (H3).
        unsafe { &*self.0 }
    }

    /// The arena's lock.
    #[inline(always)]
    fn lock(self) -> &'static rusty_libc_core::lock::RawMutex {
        &self.cell().lock
    }

    /// The next arena of the ring (the main arena after the last).
    #[inline]
    fn next(self) -> Arena {
        // (`next` is only ever set to a new arena, H3)
        let n = self.cell().next.load(Acquire);
        if n.is_null() { Arena::main() } else { Arena(n) }
    }

    /// The arena's state, as a raw pointer (dereferenced under H2 only).
    #[inline(always)]
    fn state(self) -> *mut State {
        self.cell().state.as_ptr()
    }

    /// Run `f` with the arena under its lock, taken for sure (also in a process with one thread).
    #[inline(always)]
    fn locked<R>(self, f: impl FnOnce(&mut State) -> R) -> R {
        let l = self.lock();
        l.lock_always();
        // SAFETY: the arena's lock is held (H2), so no other `&mut` to the state is live; the arena lives for ever (H3).
        let r = f(unsafe { &mut *self.state() });
        l.unlock_always();
        r
    }

    /// Run `f` with the arena under its lock, which is skipped while the process has one thread (H2 either way).
    #[inline(always)]
    fn with<R>(self, f: impl FnOnce(&mut State) -> R) -> R {
        let l = self.lock();
        let taken = l.lock();
        // SAFETY: the lock is held, or the process has one thread (H2), so no other `&mut` to the state is live; the arena
        // lives for ever (H3).
        let r = f(unsafe { &mut *self.state() });
        l.unlock(taken);
        r
    }

    #[inline(always)]
    fn is_main(self) -> bool {
        core::ptr::eq(self.0, main_ptr())
    }
}

/// The calling thread's arena, choosing one the first time (glibc's arena_get / arena_get2).
#[inline(always)]
fn thread_arena() -> Arena {
    let a = THREAD_ARENA.get();
    // (THREAD_ARENA only ever holds null or an arena of the ring)
    if !a.is_null() { Arena(a) } else { choose_arena() }
}

#[cold]
#[inline(never)]
fn choose_arena() -> Arena {
    let main = Arena::main();
    // the main arena is set up once NEXT_TO_USE is set (its `init` stores it last, with release)
    if NEXT_TO_USE.load(Acquire).is_null() {
        let made = main.locked(|m| {
            if !m.init {
                m.init();
                true
            } else {
                false
            }
        });
        if made {
            // (init made this thread the main arena's)
            return main;
        }
    }
    ARENA_LIST.lock_always();
    // an arena no thread uses any more
    // (arenas on the free list are arenas of the ring, H3; `next_free` and `attached` are under ARENA_LIST, held here)
    let f = FREE_ARENAS.load(Relaxed);
    if !f.is_null() {
        let fc = Arena(f).cell();
        FREE_ARENAS.store(fc.next_free.load(Relaxed), Relaxed);
        fc.next_free.store(null_mut(), Relaxed);
        fc.attached.store(fc.attached.load(Relaxed) + 1, Relaxed);
        ARENA_LIST.unlock_always();
        THREAD_ARENA.set(f);
        return Arena(f);
    }
    // a new one while under the limit: M_ARENA_MAX, else (host test build) HOSTED_ARENA_MAX, else 8 per CPU once more
    // than M_ARENA_TEST exist
    let n = NARENAS.load(Relaxed);
    let mut limit = NARENAS_LIMIT.load(Relaxed);
    if limit == 0 {
        let max = P.arena_max.load(Relaxed);
        if max != 0 {
            limit = max;
        } else if cfg!(feature = "no-brk") {
            limit = HOSTED_ARENA_MAX;
        } else if n > P.arena_test.load(Relaxed) {
            let c = nprocs();
            limit = 8 * if c >= 1 { c } else { 2 };
        }
        NARENAS_LIMIT.store(limit, Relaxed);
    }
    if limit == 0 || n < limit {
        let a = new_arena(n);
        if !a.is_null() {
            // into the ring right after the main arena (readers walk it without the list lock; the ring is only extended
            // under ARENA_LIST, which is held)
            let after_main = &main.cell().next;
            Arena(a).cell().next.store(after_main.load(Relaxed), Relaxed);
            after_main.store(a, Release);
            NARENAS.store(n + 1, Relaxed);
            ARENA_LIST.unlock_always();
            THREAD_ARENA.set(a);
            return Arena(a);
        }
    }
    ARENA_LIST.unlock_always();
    reuse_arena()
}

/// No new arena allowed: share one, the first of the ring that is not locked right now, from where the last search
/// stopped (glibc's reused_arena).
fn reuse_arena() -> Arena {
    let start = NEXT_TO_USE.load(Relaxed);
    // (NEXT_TO_USE only ever holds null or an arena of the ring)
    let start = if start.is_null() { Arena::main() } else { Arena(start) };
    let mut r = start;
    let mut found = None;
    loop {
        if r.lock().try_lock_always() {
            r.lock().unlock_always();
            found = Some(r);
            break;
        }
        r = r.next();
        if r == start {
            break;
        }
    }
    let found = found.unwrap_or(start);
    NEXT_TO_USE.store(found.next().0, Relaxed);
    ARENA_LIST.lock_always();
    // an arena on the free list is taken off it (`next_free` and `attached` are under ARENA_LIST, held from here on, H2;
    // every arena on the list is of the ring, H3)
    let mut q = FREE_ARENAS.load(Relaxed);
    let mut prev: *mut ArenaCell = null_mut();
    while !q.is_null() {
        let next = Arena(q).cell().next_free.load(Relaxed);
        if q == found.0 {
            if prev.is_null() {
                FREE_ARENAS.store(next, Relaxed);
            } else {
                Arena(prev).cell().next_free.store(next, Relaxed);
            }
            Arena(q).cell().next_free.store(null_mut(), Relaxed);
            break;
        }
        prev = q;
        q = next;
    }
    let fc = found.cell();
    fc.attached.store(fc.attached.load(Relaxed) + 1, Relaxed);
    ARENA_LIST.unlock_always();
    THREAD_ARENA.set(found.0);
    found
}

// ---- the per-thread cache (glibc's tcache): small free chunks a thread keeps for itself, used without any lock ----
// As glibc's, it is used whatever M_PERTURB and M_MXFAST say: blocks are perturbed only on the arena's paths.

#[repr(C)]
struct TCache {
    /// Free places left in each list (glibc's num_slots): the free path tests it against 0, no global limit to load.
    room: [u16; NSMALL],
    entries: [*mut u8; NSMALL],
}

/// The address of list `i`'s head in cache `t` (computing it is safe: wrapping arithmetic from the struct's layout).
#[inline(always)]
fn entry_slot(t: *mut TCache, i: usize) -> *mut *mut u8 {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(TCache, entries)).cast::<*mut u8>().wrapping_add(i)
}

/// The address of list `i`'s free-place count in cache `t`.
#[inline(always)]
fn room_slot(t: *mut TCache, i: usize) -> *mut u16 {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(TCache, room)).cast::<u16>().wrapping_add(i)
}

/// The calling thread's cache, made on first use from its arena; null when there is none to use. (A cache is only ever
/// touched by its own thread, H2.)
#[inline(always)]
fn tcache() -> *mut TCache {
    let t = TCACHE.get();
    if !no_cache(t) {
        t
    } else if TCACHE_DONE.get() {
        null_mut()
    } else {
        tcache_init()
    }
}

#[cold]
#[inline(never)]
fn tcache_init() -> *mut TCache {
    // made once per thread (the allocation below must not use the cache it makes)
    TCACHE_DONE.set(true);
    if P.tcache_count.load(Relaxed) == 0 {
        return null_mut();
    }
    let m = thread_arena().locked(|s| malloc_nl(s, core::mem::size_of::<TCache>()));
    if m.is_null() {
        return null_mut();
    }
    let t = m as *mut TCache;
    let n = P.tcache_count.load(Relaxed).min(u16::MAX as usize) as u16;
    // no room for chunks above tcache_max (list i holds chunks of i * 16 bytes)
    let max = P.tcache_max.load(Relaxed);
    let mut room = [0u16; NSMALL];
    for (i, r) in room.iter_mut().enumerate() {
        *r = if i * 16 <= max { n } else { 0 };
    }
    // SAFETY: `m` is a new block of at least size_of::<TCache>() bytes, 16-aligned, that only this thread knows.
    unsafe { t.write(TCache { room, entries: [null_mut(); NSMALL] }) };
    TCACHE.set(t);
    t
}

/// Free `p` into the arena it belongs to, under that arena's lock.
///
/// # Safety
/// `p` is a block of this allocator that is not mmapped, being freed (H4).
#[inline(never)]
unsafe fn free_to_arena(p: *mut u8) {
    let c = mem2chunk(p);
    // SAFETY: the caller's block's chunk, not mmapped.
    let a = Arena(unsafe { arena_for_chunk(c) });
    a.locked(|s| {
        // what does not stay in a thread's cache goes to glibc's bins, which keep the chunk's size at its end (the next
        // chunk's prev_size); the per-size lists do not need it, but a program reading freed memory sees it as in glibc
        // SAFETY: the chunk's size word (H4), under its arena's lock.
        let head = unsafe { rd(c, 8) };
        let size = head & !FLAGS;
        if head & IS_MMAPPED == 0 && (MINSIZE..=SMALL_MAX).contains(&size) && size & 15 == 0 {
            // SAFETY: the prev_size word of the chunk after it (H1).
            unsafe { wr(at(c, size), 0, size) };
        }
        // SAFETY: the caller's block, of this arena, under its lock.
        unsafe { free_nl(s, p) };
    });
}

/// The calling thread ends: its cached chunks go back to their arenas and it lets go of its arena, which goes on the free
/// list when no thread uses it any more (glibc's tcache_thread_shutdown and __malloc_arena_thread_freeres).
///
/// # Safety
/// Called by the ending thread itself, once it makes no more allocations that should use its cache.
pub unsafe fn thread_shutdown() {
    let t = TCACHE.replace(&raw const EMPTY as *mut TCache);
    TCACHE_DONE.set(true);
    if !no_cache(t) {
        for i in 0..NSMALL {
            // SAFETY: `t` is this thread's own cache (H2), a live block.
            let mut c = unsafe { *entry_slot(t, i) };
            while !c.is_null() {
                // SAFETY: `c` is in this thread's cache (H1).
                let next = unsafe { sl_get(c) };
                // SAFETY: as above: its second link word.
                unsafe { wr(c, 24, 0) };
                // SAFETY: a cached chunk is a free block of an arena, given back now.
                unsafe { free_to_arena(chunk2mem(c)) };
                c = next;
            }
        }
        // SAFETY: the cache is a block from `tcache_init`, no longer used.
        unsafe { free_to_arena(t as *mut u8) };
    }
    let a = THREAD_ARENA.replace(null_mut());
    if !a.is_null() {
        ARENA_LIST.lock_always();
        // (`a` is an arena of the ring, H3; `attached` and `next_free` are under ARENA_LIST, held)
        let ac = Arena(a).cell();
        let left = ac.attached.load(Relaxed) - 1;
        ac.attached.store(left, Relaxed);
        if left == 0 {
            ac.next_free.store(FREE_ARENAS.load(Relaxed), Relaxed);
            FREE_ARENAS.store(a, Relaxed);
        }
        ARENA_LIST.unlock_always();
    }
}

// ---- entry points ----

// While the process has one thread the main arena is used directly, with no lock and no cache (the code below `malloc_nl`
// and friends). Once there are threads every call goes to the `_mt` forms: the thread's cache first, then the lock of the
// thread's arena (for a free: the lock of the arena the chunk belongs to).
// The exported malloc and free keep their common cases free of calls (every rare case is a tail jump to a cold function), so
// they need no stack frame: one thread, a block waiting on the main arena's list; threads, a block in the thread's cache.
#[inline(always)]
pub fn malloc(n: usize) -> *mut u8 {
    // a thread with a cache (only threads of a process with threads have one) goes to the cache; the single-thread case
    // is written first so that it is the straight-line path
    if core::hint::likely(no_cache(TCACHE.get()) && !rusty_libc_core::lock::multithreaded()) {
        if n <= SMALL_MAX - SIZE_SZ && perturb() == 0 {
            // SAFETY: the process has one thread (H2).
            let s = unsafe { st() };
            let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
            let e = s.small.as_mut_ptr().wrapping_add(size >> 4);
            // SAFETY: `size >> 4` <= SMALL_MAX >> 4 < NSMALL: `e` is an element of `s.small`.
            let c = unsafe { *e };
            if !c.is_null() {
                // SAFETY: `c` is the first chunk of the per-size list (H1): its link word.
                let next = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
                if next & 15 != 0 {
                    return bad_list();
                }
                // SAFETY: as above.
                unsafe { *e = next as *mut u8 };
                // SAFETY: `c` is the caller's chunk now: its second link word.
                unsafe { wr(c, 24, 0) };
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                s.last_fresh = false;
                return chunk2mem(c);
            }
        }
        let Some(size) = request2size(n) else {
            return malloc_toobig();
        };
        // SAFETY: the process has one thread (H2).
        return malloc_slow(unsafe { st() }, size, n);
    }
    malloc_mt(n)
}

/// A list link that is not 16-byte aligned (an overwritten free block): glibc's diagnostic. (The optimiser must not see that
/// this never returns: a call to a function that never returns keeps the caller's stack frame, a tail jump needs none.)
#[cold]
#[inline(never)]
fn bad_list() -> *mut u8 {
    if core::hint::black_box(true) {
        fatal("malloc(): unaligned tcache chunk detected");
    }
    core::hint::black_box(null_mut())
}

/// The cache's fast path: a chunk of this size is waiting (no call, nothing saved); everything else goes to `malloc_mt_slow`.
#[inline(always)]
fn malloc_mt(n: usize) -> *mut u8 {
    // (`t` is this thread's cache or EMPTY, whose lists are all empty: only a non-null head is ever written, H2)
    let t = TCACHE.get();
    if n <= SMALL_MAX - SIZE_SZ {
        let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
        let i = size >> 4;
        let e = entry_slot(t, i);
        // SAFETY: `i` < NSMALL: list `i`'s head in the cache.
        let c = unsafe { *e };
        if !c.is_null() {
            // SAFETY: `c` is in the thread's cache (H1): its link word.
            let next = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
            if next & 15 != 0 {
                return bad_list();
            }
            // SAFETY: as above; `t` is a real cache (it had a chunk).
            unsafe { *e = next as *mut u8 };
            // SAFETY: as above.
            unsafe { *room_slot(t, i) += 1 };
            // SAFETY: `c` is the caller's chunk now: its second link word.
            unsafe { wr(c, 24, 0) };
            return chunk2mem(c);
        }
    }
    malloc_mt_slow(n)
}

#[inline(never)]
fn malloc_mt_slow(n: usize) -> *mut u8 {
    if let Some(size) = request2size(n)
        && size <= SMALL_MAX
    {
        let t = tcache();
        if !t.is_null() {
            let i = size >> 4;
            // SAFETY: `t` is this thread's own cache (H2), `i` < NSMALL.
            let c = unsafe { *entry_slot(t, i) };
            if !c.is_null() {
                // SAFETY: `c` is in the cache (H1).
                let next = unsafe { sl_get(c) };
                // SAFETY: as above.
                unsafe { *entry_slot(t, i) = next };
                // SAFETY: as above.
                unsafe { *room_slot(t, i) += 1 };
                // SAFETY: `c` is the caller's chunk now.
                unsafe { wr(c, 24, 0) };
                return chunk2mem(c);
            }
            // SAFETY: `t` is this thread's cache, `i` a list of it.
            return unsafe { malloc_refill(t, i, n) };
        }
    }
    malloc_arena(n)
}

/// The cache has no chunk of this size: take one from the arena, and while its lock is held move more chunks of the size
/// from the arena's list into the cache (glibc stashes them so too), up to half its capacity.
///
/// # Safety
/// `t` is the calling thread's own cache (not EMPTY), `i` < NSMALL.
#[inline(never)]
unsafe fn malloc_refill(t: *mut TCache, i: usize, n: usize) -> *mut u8 {
    let a = thread_arena();
    let p = a.locked(|s| {
        let p = malloc_nl(s, n);
        if !p.is_null() && small_enabled() {
            // up to half full: the frees that follow still find room (the block freed last is the next one handed out)
            let keep_free = P.tcache_count.load(Relaxed).div_ceil(2);
            let size = i << 4;
            let room = room_slot(t, i);
            let head = entry_slot(t, i);
            // SAFETY: the thread's own cache (contract).
            while (unsafe { *room } as usize) > keep_free {
                let c = s.small[i];
                if c.is_null() {
                    break;
                }
                // SAFETY: `c` is on the arena's list `i` (H1), under its lock.
                s.small[i] = unsafe { sl_get(c) };
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                // SAFETY: the cache's head (contract).
                let first = unsafe { *head };
                // SAFETY: `c` moves into the cache: its link words.
                unsafe { sl_set(c, first) };
                // SAFETY: as above.
                unsafe { wr(c, 24, key()) };
                // SAFETY: the cache's head and count (contract).
                unsafe { *head = c };
                // SAFETY: as above.
                unsafe { *room -= 1 };
            }
        }
        p
    });
    if p.is_null() && !a.is_main() {
        return malloc_main(n);
    }
    p
}

#[inline(never)]
fn malloc_arena(n: usize) -> *mut u8 {
    let a = thread_arena();
    let p = a.locked(|s| malloc_nl(s, n));
    // an arena that cannot grow: try the main one (glibc's arena_get_retry)
    if p.is_null() && !a.is_main() {
        return malloc_main(n);
    }
    p
}

#[cold]
fn malloc_main(n: usize) -> *mut u8 {
    Arena::main().locked(|m| malloc_nl(m, n))
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4).
#[inline(always)]
pub unsafe fn free(p: *mut u8) {
    if core::hint::likely(no_cache(TCACHE.get()) && !rusty_libc_core::lock::multithreaded()) {
        if !p.is_null() {
            // SAFETY: the process has one thread (H2).
            let s = unsafe { st() };
            let c = mem2chunk(p);
            // SAFETY: the size word of the caller's block's chunk (H4).
            let head = unsafe { rd(c, 8) };
            let size = head & !FLAGS;
            let k = key();
            // an ordinary small block of the main arena goes onto its per-size list
            if head & (IS_MMAPPED | NON_MAIN_ARENA) == 0
                && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
                && (size | p as usize) & 15 == 0
                // SAFETY: the chunk's second link word (inside its block: `size` >= MINSIZE).
                && unsafe { rd(c, 24) } != k
                && perturb() == 0
                && small_enabled()
            {
                let e = s.small.as_mut_ptr().wrapping_add(size >> 4);
                // SAFETY: `e` is an element of `s.small` (`size >> 4` <= SMALL_MAX >> 4 < NSMALL).
                let first = unsafe { *e };
                // SAFETY: `c` is a small chunk of the main arena being freed (H4): its link words.
                unsafe { sl_set(c, first) };
                // SAFETY: as above.
                unsafe { wr(c, 24, k) };
                // SAFETY: as above.
                unsafe { *e = c };
                s.small_bytes += size;
                if s.small_bytes > SMALL_BYTES_MAX {
                    return consolidate_main();
                }
                return;
            }
        }
        // SAFETY: the process has one thread (H2).
        let s = unsafe { st() };
        // SAFETY: the caller's block (H4).
        return unsafe { free_slow(s, p) };
    }
    // SAFETY: the caller's block (H4).
    unsafe { free_mt(p) }
}

#[cold]
#[inline(never)]
fn consolidate_main() {
    // SAFETY: called from the single-thread path of `free` (H2).
    unsafe { st() }.consolidate()
}

/// The cache's fast path: a small chunk not marked as cached and room in its list (no call, nothing saved); everything
/// else goes to `free_mt_slow`.
///
/// # Safety
/// `p` is NULL or a block of this allocator (H4).
#[inline(always)]
unsafe fn free_mt(p: *mut u8) {
    // (`t` is this thread's cache or EMPTY, whose lists have no room: only a real cache is ever written, H2)
    let t = TCACHE.get();
    if !p.is_null() {
        let c = mem2chunk(p);
        // SAFETY: the size word of the caller's block's chunk (H4).
        let head = unsafe { rd(c, 8) };
        let size = head & !FLAGS;
        let k = key();
        if head & IS_MMAPPED == 0
            && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
            && (size | p as usize) & 15 == 0
            // SAFETY: the chunk's second link word (inside its block).
            && unsafe { rd(c, 24) } != k
        {
            let i = size >> 4;
            let r = room_slot(t, i);
            // SAFETY: `i` < NSMALL: list `i`'s count in the cache.
            if unsafe { *r } != 0 {
                let e = entry_slot(t, i);
                // SAFETY: the cache's list head.
                let first = unsafe { *e };
                // SAFETY: a small chunk being freed (H4) goes into the thread's own (real: it had room) cache.
                unsafe { sl_set(c, first) };
                // SAFETY: as above.
                unsafe { wr(c, 24, k) };
                // SAFETY: as above.
                unsafe { *e = c };
                // SAFETY: as above.
                unsafe { *r -= 1 };
                return;
            }
        }
    }
    // SAFETY: the caller's block (H4).
    unsafe { free_mt_slow(p) }
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4).
#[inline(never)]
unsafe fn free_mt_slow(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let c = mem2chunk(p);
    // SAFETY: the size word of the caller's block's chunk (H4).
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED == 0 && (MINSIZE..=SMALL_MAX).contains(&size) && size & 15 == 0 && (p as usize) & 15 == 0 {
        let t = tcache();
        if !t.is_null() {
            // (`t` is this thread's own cache, H2; `i` < NSMALL)
            let i = size >> 4;
            let k = key();
            // SAFETY: the chunk's second link word (inside its block).
            if unsafe { rd(c, 24) } == k {
                // freed before? (glibc's tcache double-free check: the mark may also be chance data)
                // SAFETY: the cache's list head.
                let mut q = unsafe { *entry_slot(t, i) };
                while !q.is_null() {
                    if q == c {
                        fatal("free(): double free detected in tcache 2");
                    }
                    // SAFETY: `q` is in the cache (H1).
                    q = unsafe { sl_get(q) };
                }
            }
            // SAFETY: the cache's count.
            if unsafe { *room_slot(t, i) } != 0 {
                // SAFETY: the cache's list head.
                let first = unsafe { *entry_slot(t, i) };
                // SAFETY: a small chunk being freed goes into the thread's cache: its links, the head, the count.
                unsafe { sl_set(c, first) };
                // SAFETY: as above.
                unsafe { wr(c, 24, k) };
                // SAFETY: as above.
                unsafe { *entry_slot(t, i) = c };
                // SAFETY: as above.
                unsafe { *room_slot(t, i) -= 1 };
                return;
            }
        }
    }
    if head & IS_MMAPPED != 0 {
        // no arena behind an mmapped chunk: no lock
        // SAFETY: an mmapped block being freed (H4).
        return unsafe { free_mmapped_block(p, size) };
    }
    // SAFETY: the caller's block, not mmapped.
    unsafe { free_to_arena(p) }
}

/// A chunk of another arena reached the single-thread path (a child forked from a multithreaded parent frees what the
/// parent's threads allocated): free it in its own arena.
///
/// # Safety
/// As `free_to_arena`.
#[cold]
#[inline(never)]
unsafe fn free_foreign(p: *mut u8) {
    // SAFETY: caller's contract.
    unsafe { free_to_arena(p) }
}

/// realloc of a chunk of another arena than the one at hand: in its own arena.
///
/// # Safety
/// `p` is a block of this allocator that is not mmapped (H4).
#[cold]
#[inline(never)]
unsafe fn realloc_foreign(p: *mut u8, n: usize) -> *mut u8 {
    // SAFETY: caller's contract.
    let a = Arena(unsafe { arena_for_chunk(mem2chunk(p)) });
    // SAFETY: the block belongs to `a`, whose lock is held.
    a.locked(|s| unsafe { realloc_nl(s, p, n) })
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4).
pub unsafe fn usable_size(p: *mut u8) -> usize {
    // SAFETY: caller's contract.
    unsafe { usable_size_nl(p) }
}

#[inline]
pub fn calloc(n: usize, m: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
        // SAFETY: the process has one thread (H2).
        return calloc_nl(unsafe { st() }, n, m);
    }
    calloc_mt(n, m)
}

#[inline(never)]
fn calloc_mt(n: usize, m: usize) -> *mut u8 {
    let a = thread_arena();
    let p = a.locked(|s| calloc_nl(s, n, m));
    if p.is_null() && !a.is_main() && n.checked_mul(m).is_some() {
        return Arena::main().locked(|s| calloc_nl(s, n, m));
    }
    p
}

/// # Safety
/// `p` is NULL or a block of this allocator (H4).
#[inline]
pub unsafe fn realloc(p: *mut u8, n: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
        // SAFETY: the process has one thread (H2).
        let s = unsafe { st() };
        // SAFETY: the caller's block (H4).
        return unsafe { realloc_nl(s, p, n) };
    }
    // SAFETY: the caller's block (H4).
    unsafe { realloc_mt(p, n) }
}

/// # Safety
/// As `realloc`.
#[inline(never)]
unsafe fn realloc_mt(p: *mut u8, n: usize) -> *mut u8 {
    if p.is_null() {
        return malloc_mt(n);
    }
    if n == 0 {
        // SAFETY: the caller's block.
        unsafe { free_mt(p) };
        return null_mut();
    }
    let c = mem2chunk(p);
    // a chunk is resized in its own arena; an mmapped one (no arena) with the thread's arena for a move
    // SAFETY: the size word of the caller's block's chunk (H4).
    let a = if unsafe { rd(c, 8) } & IS_MMAPPED != 0 {
        thread_arena()
    } else {
        // SAFETY: a block that is not mmapped.
        Arena(unsafe { arena_for_chunk(c) })
    };
    // SAFETY: the block belongs to `a` (or is mmapped), whose lock is held.
    a.locked(|s| unsafe { realloc_nl(s, p, n) })
}

/// Aligned allocation; `align` is a power of two (the block is not aligned otherwise).
#[inline(always)]
pub fn memalign(align: usize, n: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
        // SAFETY: the process has one thread (H2).
        let p = small_aligned_take(unsafe { st() }, align, n);
        if !p.is_null() {
            return p;
        }
        return memalign_st(align, n);
    }
    memalign_mt(align, n)
}

#[inline(never)]
fn memalign_st(align: usize, n: usize) -> *mut u8 {
    // SAFETY: called on the single-thread path (H2).
    memalign_nl(unsafe { st() }, align, n)
}

#[inline(never)]
fn memalign_mt(align: usize, n: usize) -> *mut u8 {
    // a cached chunk of the size that happens to be aligned (glibc's memalign looks in the tcache first too)
    if align > 16
        && let Some(size) = request2size(n)
        && size <= SMALL_MAX
    {
        let t = tcache();
        if !t.is_null() {
            // (`t` is this thread's own cache, H2; every chunk reached is in it, H1)
            let i = size >> 4;
            let head = entry_slot(t, i);
            let mut link: *mut *mut u8 = head;
            // SAFETY: the cache's list head.
            let mut c = unsafe { *link };
            while !c.is_null() {
                // SAFETY: `c` is in the cache.
                let next = unsafe { sl_get(c) };
                if (chunk2mem(c) as usize) & (align - 1) == 0 {
                    // unlink it: the link before it now points past it (safe-linked like every link)
                    if core::ptr::eq(link, head) {
                        // SAFETY: the cache's list head.
                        unsafe { *link = next };
                    } else {
                        // SAFETY: `link` is the link word of the chunk before `c`, 16 bytes into it.
                        unsafe { sl_set(link.cast::<u8>().wrapping_sub(16), next) };
                    }
                    // SAFETY: the cache's count.
                    unsafe { *room_slot(t, i) += 1 };
                    // SAFETY: `c` is the caller's chunk now.
                    unsafe { wr(c, 24, 0) };
                    return chunk2mem(c);
                }
                link = at(c, 16).cast::<*mut u8>();
                c = next;
            }
        }
    }
    thread_arena().locked(|s| memalign_nl(s, align, n))
}

/// Every arena in ring order, main first.
pub fn arenas(mut f: impl FnMut(Arena)) {
    let main = Arena::main();
    let mut a = main;
    loop {
        f(a);
        a = a.next();
        if a == main {
            break;
        }
    }
}

/// The statistics of one arena, taken under its lock.
pub fn arena_stats(a: Arena) -> Stats {
    a.with(stats_nl)
}

/// The statistics of all arenas added up (keepcost: the main arena's top, as glibc).
pub fn stats() -> Stats {
    let mut t = Stats { arena: 0, free_chunks: 0, small_chunks: 0, small_bytes: 0, free_bytes: 0, top: 0 };
    arenas(|a| {
        let (x, id) = a.with(|s| (stats_nl(s), s.id));
        t.arena += x.arena;
        t.free_chunks += x.free_chunks;
        t.small_chunks += x.small_chunks;
        t.small_bytes += x.small_bytes;
        t.free_bytes += x.free_bytes;
        if id == 0 {
            t.top = x.top;
        } else {
            // a non-main arena's top is free memory too (it counts as one free chunk in glibc's ordblks)
            t.free_bytes += x.top;
            t.free_chunks += 1;
        }
    });
    t
}

pub fn trim(pad: usize) -> i32 {
    let mut r = 0;
    arenas(|a| r |= a.with(|s| trim_nl(s, pad)));
    r
}

pub fn ensure_init() {
    Arena::main().with(ensure_init_nl);
}

/// The main arena's lock (mallopt and malloc_stats take it, as glibc).
pub fn main_lock() -> &'static rusty_libc_core::lock::RawMutex {
    Arena::main().lock()
}

/// Number of arenas.
#[cfg(test)]
pub fn narenas() -> usize {
    NARENAS.load(Relaxed)
}

/// Host tests: the main arena's current top chunk (tests inspect the fence left behind when the heap moves).
#[cfg(test)]
pub fn main_top() -> *mut u8 {
    Arena::main().with(|s| s.top_ptr())
}

/// Host tests: make the calling thread use the main arena.
#[cfg(test)]
pub fn bind_main_arena() {
    Arena::main().locked(ensure_init_nl);
    THREAD_ARENA.set(main_ptr());
}

/// What malloc_info prints for one arena (glibc's figures per `<heap>`).
pub struct ArenaInfo {
    pub main: bool,
    /// Free chunks (the top counts as one) and their bytes.
    pub nblocks: usize,
    pub avail: usize,
    pub system: usize,
    pub max_system: usize,
    /// Non-main arenas: the bytes of their heaps in use and read-write, and how many heaps.
    pub aspace: usize,
    pub aspace_mprotect: usize,
    pub subheaps: usize,
}

/// The malloc_info figures of every arena in ring order, each taken under its lock.
pub fn arena_infos(mut f: impl FnMut(&ArenaInfo)) {
    arenas(|a| {
        let x = arena_stats(a);
        let (mut aspace, mut subheaps) = (0, 0);
        let (main, system_mem, max_system_mem) = a.with(|s| {
            if s.abit != 0 {
                let mut h = s.heap;
                while !h.is_null() {
                    // SAFETY: the arena's heaps are chained through `prev` and never unmapped while it exists (H3); their
                    // `committed` changes only under the arena's lock, held here.
                    let committed = unsafe { (*h).committed };
                    // SAFETY: as above.
                    let prev = unsafe { (*h).prev };
                    aspace += committed;
                    subheaps += 1;
                    h = prev;
                }
            }
            (s.abit == 0, s.system_mem, s.max_system_mem)
        });
        let system = if main { x.arena } else { system_mem };
        let max_system = if main { x.arena } else { max_system_mem };
        f(&ArenaInfo {
            main,
            nblocks: x.free_chunks + x.small_chunks + 1,
            avail: x.top + x.free_bytes + x.small_bytes,
            system,
            max_system,
            aspace: if main { system } else { aspace },
            aspace_mprotect: if main { system } else { aspace },
            subheaps,
        });
    });
}

// ---- fork: no arena may be locked by another thread when the child starts ----

/// Take the list lock and every arena's lock before `fork` (so no other thread is inside malloc when the process splits).
pub fn atfork_prepare() {
    ARENA_LIST.lock_always();
    arenas(|a| a.lock().lock_always());
}

/// Release them in the parent after `fork`.
pub fn atfork_parent() {
    arenas(|a| a.lock().unlock_always());
    ARENA_LIST.unlock_always();
}

/// In the child (the forking thread is the only one left, holding every lock): release them, and every arena but the
/// child's own is free for reuse (glibc's ptmalloc_unlock_all2).
pub fn atfork_child() {
    let mine = THREAD_ARENA.get();
    let mut free: *mut ArenaCell = null_mut();
    arenas(|a| {
        a.lock().unlock_always();
        // (the child has one thread, which holds ARENA_LIST)
        let c = a.cell();
        if a.0 == mine {
            c.attached.store(1, Relaxed);
        } else {
            c.attached.store(0, Relaxed);
            c.next_free.store(free, Relaxed);
            free = a.0;
        }
    });
    FREE_ARENAS.store(free, Relaxed);
    ARENA_LIST.unlock_always();
}

/// FIXLIST #99: the split between an arena's shared part and its state, checked by Miri under Stacked Borrows and Tree
/// Borrows (`cargo +nightly miri test -p rusty-libc-malloc state_split`, with and without
/// `MIRIFLAGS=-Zmiri-tree-borrows`). One thread holds the arena's lock and its state as `&mut State` while another walks the
/// ring, tries the lock and updates the list fields, as `reuse_arena` and `thread_shutdown` do (no system call is reached:
/// the lock is never contended in a way that sleeps).
#[cfg(test)]
mod state_split {
    use super::*;

    #[test]
    fn state_split_aliasing() {
        // (arenas live for ever, H3: statics, as the main arena)
        static A: ArenaCell = ArenaCell::new(State::empty());
        static B: ArenaCell = ArenaCell::new(State::empty());
        let (a, b): (&'static ArenaCell, &'static ArenaCell) = (&A, &B);
        a.next.store((b as *const ArenaCell).cast_mut(), Release);
        let arena = Arena((a as *const ArenaCell).cast_mut());
        assert!(arena.lock().try_lock_always());
        // SAFETY: this thread holds the arena's lock (H2).
        let s = unsafe { &mut *arena.state() };
        s.id = 7;
        let other = std::thread::spawn(move || {
            let x = Arena((a as *const ArenaCell).cast_mut());
            for i in 0..50 {
                assert!(!x.lock().try_lock_always());
                let n = x.next();
                assert!(core::ptr::eq(n.0, (b as *const ArenaCell).cast_mut()));
                let c = x.cell();
                c.attached.store(c.attached.load(Relaxed) + i, Relaxed);
                c.next_free.store(n.0, Relaxed);
            }
        });
        for i in 0..50 {
            s.small_bytes += i;
            s.last_fresh = !s.last_fresh;
            core::hint::black_box(&mut *s);
        }
        other.join().unwrap();
        assert_eq!(s.id, 7);
        assert_eq!(s.small_bytes, (0..50).sum::<usize>());
        arena.lock().unlock_always();
        assert_eq!(a.attached.load(Relaxed), 1 + (0..50).sum::<usize>());
        // the lock is free again: the state may be taken by the next holder
        assert!(arena.lock().try_lock_always());
        arena.lock().unlock_always();
    }
}
