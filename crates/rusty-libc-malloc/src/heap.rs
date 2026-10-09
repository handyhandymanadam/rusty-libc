use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicUsize};
use rusty_libc_core::{errno, syscall};

pub const SIZE_SZ: usize = 8;
pub const MINSIZE: usize = 32;
const PREV_INUSE: usize = 1;
const IS_MMAPPED: usize = 2;
const FLAGS: usize = 7;
const PAGE: usize = 4096;
const SMALL_MAX: usize = 1040;
const NSMALL: usize = SMALL_MAX / 16 + 1;
const NBINS: usize = 128;
const DEFAULT_MMAP_THRESHOLD: usize = 128 * 1024;
const MMAP_THRESHOLD_MAX: usize = 32 * 1024 * 1024;
const DEFAULT_TOP_PAD: usize = 128 * 1024;
const DEFAULT_TRIM_THRESHOLD: usize = 128 * 1024;
const CONSOLIDATE_THRESHOLD: usize = 64 * 1024;
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
    init: bool,
    top: *mut u8,
    top_is_brk: bool,
    brk_start: usize,
    brk_end: usize,
    high_water: usize,
    pub last_fresh: bool,
    small: [*mut u8; NSMALL],
    bins: [[usize; 4]; NBINS],
    map: [u64; 2],
    pub foreign_bytes: usize,
    small_bytes: usize,
    grow_first: bool,
    abit: usize,
    pub lock: rusty_libc_core::lock::RawMutex,
    next: AtomicPtr<State>,
    next_free: *mut State,
    attached: usize,
    heap: *mut HeapInfo,
    pub system_mem: usize,
    pub max_system_mem: usize,
    pub id: usize,
}

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
    pub arena_max: AtomicUsize,
    pub arena_test: AtomicUsize,
    pub tcache_count: AtomicUsize,
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
    key: AtomicUsize::new(0),
};

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

#[repr(C)]
pub struct HeapInfo {
    arena: *mut State,
    prev: *mut HeapInfo,
    committed: usize,
}

const HEAP_MAX: usize = 64 << 20;
const NON_MAIN_ARENA: usize = 4;

static ARENA_LIST: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();
static NARENAS: AtomicUsize = AtomicUsize::new(1);
static FREE_ARENAS: AtomicPtr<State> = AtomicPtr::new(null_mut());
static NEXT_TO_USE: AtomicPtr<State> = AtomicPtr::new(null_mut());

struct Global(UnsafeCell<State>);
unsafe impl Sync for Global {}

static STATE: Global = Global(UnsafeCell::new(State::empty()));

impl State {
    const fn empty() -> State {
        State {
            init: false,
            top: null_mut(),
            top_is_brk: !cfg!(feature = "no-brk"),
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
            lock: rusty_libc_core::lock::RawMutex::new(),
            next: AtomicPtr::new(null_mut()),
            next_free: null_mut(),
            attached: 1,
            heap: null_mut(),
            system_mem: 0,
            max_system_mem: 0,
            id: 0,
        }
    }
}

#[inline(always)]
pub fn st() -> &'static mut State {
    unsafe { &mut *STATE.0.get() }
}

#[inline(always)]
unsafe fn rd(p: *mut u8, off: usize) -> usize {
    unsafe { *(p.add(off) as *mut usize) }
}
#[inline(always)]
unsafe fn wr(p: *mut u8, off: usize, v: usize) {
    unsafe { *(p.add(off) as *mut usize) = v }
}
#[inline(always)]
unsafe fn sl_set(c: *mut u8, next: *mut u8) {
    unsafe { wr(c, 16, ((c as usize + 16) >> 12) ^ next as usize) }
}
#[inline(always)]
unsafe fn sl_get(c: *mut u8) -> *mut u8 {
    unsafe {
        let v = rd(c, 16) ^ ((c as usize + 16) >> 12);
        if v & 15 != 0 {
            fatal("malloc(): unaligned tcache chunk detected");
        }
        v as *mut u8
    }
}
#[inline(always)]
unsafe fn csize(c: *mut u8) -> usize {
    unsafe { rd(c, 8) & !FLAGS }
}
#[inline(always)]
fn chunk2mem(c: *mut u8) -> *mut u8 {
    unsafe { c.add(16) }
}
#[inline(always)]
fn mem2chunk(m: *mut u8) -> *mut u8 {
    unsafe { m.sub(16) }
}

#[cold]
#[inline(never)]
pub fn fatal(msg: &str) -> ! {
    let _ = rusty_libc_core::unistd::write(2, msg.as_bytes());
    let _ = rusty_libc_core::unistd::write(2, b"\n");
    rusty_libc_core::process::abort()
}

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
    unsafe fn init(&mut self) {
        for i in 0..NBINS {
            let b = self.bin_node(i);
            unsafe {
                wr(b, 16, b as usize);
                wr(b, 24, b as usize);
            }
        }
        if self.abit != 0 {
            self.init = true;
            return;
        }
        if !rusty_libc_core::lock::libc_initial() {
            self.top_is_brk = false;
        }
        let brk = unsafe { syscall::syscall1(syscall::SYS_BRK, 0) };
        let start = (brk + 15) & !15;
        self.brk_start = start;
        self.brk_end = brk;
        let t = unsafe { core::arch::x86_64::_rdtsc() } as usize;
        P.key.store((t ^ (brk >> 4)).rotate_left(17) | 1, Relaxed);
        unsafe { read_arena_env() };
        unsafe { THREAD_ARENA = self as *mut State };
        NEXT_TO_USE.store(self as *mut State, Relaxed);
        self.init = true;
    }

    #[inline(always)]
    fn bin_node(&mut self, i: usize) -> *mut u8 {
        self.bins[i].as_mut_ptr() as *mut u8
    }

    unsafe fn link_bin(&mut self, c: *mut u8, size: usize) {
        let idx = bin_index(size);
        let b = self.bin_node(idx);
        unsafe {
            let mut at = rd(b, 16) as *mut u8;
            if idx >= 64 {
                while at != b && csize(at) < size {
                    at = rd(at, 16) as *mut u8;
                }
                let prev = rd(at, 24) as *mut u8;
                wr(c, 16, at as usize);
                wr(c, 24, prev as usize);
                wr(prev, 16, c as usize);
                wr(at, 24, c as usize);
            } else {
                wr(c, 16, at as usize);
                wr(c, 24, b as usize);
                wr(at, 24, c as usize);
                wr(b, 16, c as usize);
            }
        }
        self.map[idx >> 6] |= 1 << (idx & 63);
    }

    unsafe fn unlink(&mut self, c: *mut u8, size: usize) {
        unsafe {
            let fd = rd(c, 16) as *mut u8;
            let bk = rd(c, 24) as *mut u8;
            if rd(fd, 24) != c as usize || rd(bk, 16) != c as usize {
                fatal("corrupted double-linked list");
            }
            wr(fd, 24, bk as usize);
            wr(bk, 16, fd as usize);
            let idx = bin_index(size);
            let b = self.bin_node(idx);
            if rd(b, 16) == b as usize {
                self.map[idx >> 6] &= !(1 << (idx & 63));
            }
        }
    }

    unsafe fn top_size(&self) -> usize {
        if self.top.is_null() { 0 } else { unsafe { csize(self.top) } }
    }

    unsafe fn free_merge(&mut self, c: *mut u8, size: usize) {
        unsafe {
            let (mut c, mut size) = (c, size);
            if rd(c, 8) & PREV_INUSE == 0 {
                let ps = rd(c, 0);
                let p = c.sub(ps);
                if csize(p) != ps {
                    fatal("corrupted size vs. prev_size");
                }
                c = p;
                size += ps;
                self.unlink(c, ps);
            }
            let next = c.add(size);
            if next == self.top {
                size += csize(next);
                wr(c, 8, size | PREV_INUSE | self.abit);
                self.top = c;
                return;
            }
            let nsize = csize(next);
            if rd(next.add(nsize), 8) & PREV_INUSE == 0 {
                self.unlink(next, nsize);
                size += nsize;
            }
            wr(c, 8, size | PREV_INUSE | self.abit);
            wr(c.add(size), 0, size);
            let after = c.add(size);
            wr(after, 8, rd(after, 8) & !PREV_INUSE);
            self.link_bin(c, size);
        }
    }

    unsafe fn consolidate(&mut self) {
        unsafe {
            if self.small_bytes == 0 {
                return;
            }
            self.small_bytes = 0;
            for i in 2..NSMALL {
                let mut c = self.small[i];
                self.small[i] = null_mut();
                while !c.is_null() {
                    let next = sl_get(c);
                    let size = csize(c);
                    wr(c, 24, 0);
                    self.free_merge(c, size);
                    c = next;
                }
            }
        }
    }

    unsafe fn trim_top(&mut self, threshold: usize, pad: usize) {
        unsafe {
            if !self.top_is_brk || self.top.is_null() {
                return;
            }
            let ts = csize(self.top);
            if ts < threshold {
                return;
            }
            let extra = (ts.saturating_sub(pad + MINSIZE)) & !(PAGE - 1);
            if extra == 0 {
                return;
            }
            let want = self.brk_end - extra;
            let got = syscall::syscall1(syscall::SYS_BRK, want);
            if got == want {
                self.brk_end = want;
                wr(self.top, 8, (ts - extra) | PREV_INUSE | self.abit);
            }
        }
    }

    unsafe fn split(&mut self, c: *mut u8, have: usize, size: usize) -> *mut u8 {
        unsafe {
            let rem = have - size;
            if rem >= MINSIZE {
                wr(c, 8, size | PREV_INUSE | self.abit);
                let r = c.add(size);
                wr(r, 8, rem | PREV_INUSE | self.abit);
                let after = r.add(rem);
                wr(r.add(rem), 0, rem);
                wr(after, 8, rd(after, 8) & !PREV_INUSE);
                self.link_bin(r, rem);
            } else {
                wr(c, 8, have | PREV_INUSE | self.abit);
                let next = c.add(have);
                wr(next, 8, rd(next, 8) | PREV_INUSE | self.abit);
            }
            c
        }
    }

    unsafe fn take_from_bins(&mut self, size: usize) -> *mut u8 {
        unsafe {
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
                let mut c = rd(b, 16) as *mut u8;
                if idx == start && idx >= 64 {
                    while c != b && csize(c) < size {
                        if csize(c) < MINSIZE || csize(c) & 15 != 0 {
                            fatal("malloc(): invalid size (unsorted)");
                        }
                        c = rd(c, 16) as *mut u8;
                    }
                    if c == b {
                        bits &= bits - 1;
                        continue;
                    }
                }
                let have = csize(c);
                if have < MINSIZE || have & 15 != 0 || bin_index(have) != idx {
                    fatal("malloc(): invalid size (unsorted)");
                }
                self.unlink(c, have);
                return self.split(c, have, size);
            }
        }
    }

    unsafe fn alloc_from_top(&mut self, size: usize) -> *mut u8 {
        unsafe {
            if self.top.is_null() {
                return null_mut();
            }
            let ts = csize(self.top);
            if ts < size + MINSIZE {
                return null_mut();
            }
            let c = self.top;
            wr(c, 8, size | PREV_INUSE | self.abit);
            let nt = c.add(size);
            wr(nt, 8, (ts - size) | PREV_INUSE | self.abit);
            self.top = nt;
            let end = c as usize + size;
            self.last_fresh = c as usize >= self.high_water;
            if end > self.high_water {
                self.high_water = end;
            }
            c
        }
    }

    unsafe fn grow(&mut self, size: usize) -> bool {
        unsafe {
            if self.abit != 0 {
                return self.grow_heap(size);
            }
            let ts = self.top_size();
            let need = size + MINSIZE;
            let top_pad = P.top_pad.load(Relaxed);
            let ext = (need.saturating_sub(ts) + top_pad + PAGE - 1) & !(PAGE - 1);
            if self.top_is_brk {
                let want = self.brk_end + ext;
                if want > self.brk_end {
                    let got = syscall::syscall1(syscall::SYS_BRK, want);
                    if got == want {
                        if self.top.is_null() {
                            let start = (self.brk_end + 15) & !15;
                            self.top = start as *mut u8;
                            wr(self.top, 8, (want - start) | PREV_INUSE | self.abit);
                            self.brk_start = start;
                        } else {
                            wr(self.top, 8, (ts + (want - self.brk_end)) | PREV_INUSE | self.abit);
                        }
                        self.brk_end = want;
                        return true;
                    }
                }
            }
            let Some(len) = need.saturating_add(top_pad).max(ext).max(1 << 20).checked_add(PAGE - 1) else {
                return false;
            };
            let len = len & !(PAGE - 1);
            let m = map_anon(len);
            if m.is_null() {
                return false;
            }
            self.retire_top();
            self.top = m;
            self.top_is_brk = false;
            wr(m, 8, len | PREV_INUSE | self.abit);
            self.foreign_bytes += len;
            true
        }
    }

    unsafe fn retire_top(&mut self) {
        unsafe {
            if !self.top.is_null() {
                let old = self.top;
                let os = csize(old);
                self.top = null_mut();
                if os >= MINSIZE + 32 {
                    let keep = os - 32;
                    wr(old, 8, keep | PREV_INUSE | self.abit);
                    let f1 = old.add(keep);
                    wr(f1, 8, 16 | PREV_INUSE | self.abit);
                    wr(f1, 16, 0);
                    wr(f1.add(16), 8, PREV_INUSE | self.abit);
                    wr(old.add(keep), 0, 0);
                    self.free_merge(old, keep);
                } else if os >= 32 {
                    wr(old, 8, 16 | PREV_INUSE | self.abit);
                    wr(old.add(16), 8, PREV_INUSE | self.abit);
                }
            }
        }
    }

    unsafe fn grow_heap(&mut self, size: usize) -> bool {
        unsafe {
            let h = self.heap;
            let ts = self.top_size();
            let need = size + MINSIZE;
            let pad = P.top_pad.load(Relaxed);
            let committed = (*h).committed;
            for ext in [page_up(need.saturating_sub(ts).saturating_add(pad)), page_up(need.saturating_sub(ts))] {
                if ext <= HEAP_MAX - committed
                    && syscall::syscall3(syscall::SYS_MPROTECT, h as usize + committed, ext, PROT_READ | PROT_WRITE) == 0
                {
                    (*h).committed += ext;
                    self.add_system(ext);
                    wr(self.top, 8, (ts + ext) | PREV_INUSE | self.abit);
                    return true;
                }
            }
            let hdr = HEAP_HDR;
            let Some(first) = hdr.checked_add(need).filter(|&n| n <= HEAP_MAX).map(|n| page_up(n.saturating_add(pad)).min(HEAP_MAX)) else {
                return false;
            };
            let nh = new_heap(first);
            if nh.is_null() {
                return false;
            }
            (*nh).arena = self as *mut State;
            (*nh).prev = h;
            (*nh).committed = first;
            self.heap = nh;
            self.add_system(first);
            self.retire_top();
            let m = (nh as *mut u8).add(hdr);
            self.top = m;
            wr(m, 8, (first - hdr) | PREV_INUSE | self.abit);
            true
        }
    }

    fn add_system(&mut self, n: usize) {
        self.system_mem += n;
        if self.system_mem > self.max_system_mem {
            self.max_system_mem = self.system_mem;
        }
    }
}

unsafe fn map_anon(len: usize) -> *mut u8 {
    unsafe {
        let r = syscall::syscall6(syscall::SYS_MMAP, 0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, usize::MAX, 0);
        if r > usize::MAX - 4095 { null_mut() } else { r as *mut u8 }
    }
}

unsafe fn mmap_chunk(s: &mut State, size: usize) -> *mut u8 {
    unsafe {
        if P.n_mmaps.load(Relaxed) >= P.mmap_max.load(Relaxed) {
            return null_mut();
        }
        let len = (size + 8 + PAGE - 1) & !(PAGE - 1);
        let m = map_anon(len);
        if m.is_null() {
            return null_mut();
        }
        wr(m, 0, 0);
        wr(m, 8, len | IS_MMAPPED);
        count_add(&P.n_mmaps, 1);
        let now = count_add(&P.mmapped_mem, len);
        count_max(&P.max_mmapped_mem, now);
        s.last_fresh = true;
        chunk2mem(m)
    }
}

unsafe fn munmap_chunk(c: *mut u8) {
    unsafe {
        let off = rd(c, 0);
        let len = csize(c);
        let base = c.sub(off);
        count_add(&P.n_mmaps, usize::MAX);
        count_add(&P.mmapped_mem, len.wrapping_neg());
        if syscall::syscall2(syscall::SYS_MUNMAP, base as usize, len + off) > usize::MAX - 4095 {
            fatal("munmap_chunk(): invalid pointer");
        }
    }
}

#[inline(never)]
fn set_enomem() {
    errno::set(ENOMEM);
}

#[inline]
unsafe fn malloc_nl(s: &mut State, n: usize) -> *mut u8 {
    unsafe {
        let Some(size) = request2size(n) else {
            return malloc_toobig();
        };
        if size <= SMALL_MAX && perturb() == 0 {
            let i = size >> 4;
            let c = s.small[i];
            if !c.is_null() {
                s.small[i] = sl_get(c);
                wr(c, 24, 0);
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                s.last_fresh = false;
                return chunk2mem(c);
            }
        }
        malloc_slow(s, size, perturb())
    }
}

#[cold]
#[inline(never)]
fn malloc_toobig() -> *mut u8 {
    set_enomem();
    core::hint::black_box(null_mut())
}

#[inline(never)]
unsafe fn malloc_slow(s: &mut State, size: usize, pert: u8) -> *mut u8 {
    unsafe {
        if !s.init {
            s.init();
        }
        if size <= SMALL_MAX {
            let i = size >> 4;
            let c = s.small[i];
            if !c.is_null() {
                s.small[i] = sl_get(c);
                wr(c, 24, 0);
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                s.last_fresh = false;
                return perturb_alloc(pert, chunk2mem(c), size);
            }
        }
        let c = alloc_chunk(s, size);
        if c.is_null() {
            set_enomem();
            return null_mut();
        }
        perturb_alloc(pert, chunk2mem(c), size)
    }
}

#[inline(always)]
unsafe fn perturb_alloc(pert: u8, m: *mut u8, size: usize) -> *mut u8 {
    unsafe {
        if pert != 0 {
            rusty_libc_mem::memset(m.cast(), i32::from(pert ^ 0xff), size - SIZE_SZ);
        }
        m
    }
}

unsafe fn alloc_chunk(s: &mut State, size: usize) -> *mut u8 {
    unsafe {
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
        if s.grow_first && s.grow(size) {
            let c = s.alloc_from_top(size);
            if !c.is_null() {
                return c;
            }
        }
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
}

#[inline]
unsafe fn free_nl(s: &mut State, p: *mut u8) {
    unsafe {
        if p.is_null() {
            return;
        }
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & (IS_MMAPPED | NON_MAIN_ARENA) == s.abit
            && (MINSIZE..=SMALL_MAX).contains(&size)
            && size & 15 == 0
            && (p as usize) & 15 == 0
            && perturb() == 0
            && small_enabled()
            && rd(c, 24) != key()
        {
            let i = size >> 4;
            sl_set(c, s.small[i]);
            wr(c, 24, key());
            s.small[i] = c;
            s.small_bytes += size;
            if s.small_bytes > SMALL_BYTES_MAX {
                s.consolidate();
            }
            return;
        }
        free_slow(s, p);
    }
}

#[inline(never)]
unsafe fn free_slow(s: &mut State, p: *mut u8) {
    unsafe {
        if p.is_null() {
            return;
        }
        if (p as usize) & 15 != 0 {
            fatal("free(): invalid pointer");
        }
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & IS_MMAPPED != 0 {
            if P.dynamic_thresholds.load(Relaxed) && size > P.mmap_threshold.load(Relaxed) && size <= MMAP_THRESHOLD_MAX {
                P.mmap_threshold.store(size, Relaxed);
                P.trim_threshold.store(2 * size, Relaxed);
            }
            munmap_chunk(c);
            return;
        }
        if head & NON_MAIN_ARENA != s.abit {
            return free_foreign(p);
        }
        if size < MINSIZE || size & 15 != 0 {
            fatal("free(): invalid size");
        }
        let marked = rd(c, 24) == key();
        if perturb() != 0 {
            rusty_libc_mem::memset(p.cast(), i32::from(perturb()), size - SIZE_SZ);
        }
        if marked && small_enabled() {
            for list in s.small.iter() {
                let mut q = *list;
                while !q.is_null() {
                    if q == c {
                        fatal("free(): double free detected in tcache 2");
                    }
                    q = sl_get(q);
                }
            }
        }
        if size <= SMALL_MAX && small_enabled() {
            let i = size >> 4;
            sl_set(c, s.small[i]);
            wr(c, 24, key());
            s.small[i] = c;
            s.small_bytes += size;
            if s.small_bytes > SMALL_BYTES_MAX {
                s.consolidate();
            }
            return;
        }
        let next = c.add(size);
        if next != s.top && rd(next, 8) & PREV_INUSE == 0 {
            fatal("double free or corruption (!prev)");
        }
        s.free_merge(c, size);
        if size >= CONSOLIDATE_THRESHOLD {
            s.consolidate();
            s.trim_top(P.trim_threshold.load(Relaxed), P.top_pad.load(Relaxed));
        }
    }
}

unsafe fn usable_size_nl(p: *mut u8) -> usize {
    unsafe {
        if p.is_null() {
            return 0;
        }
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & IS_MMAPPED != 0 { size - 16 } else { size - SIZE_SZ }
    }
}

#[inline]
unsafe fn calloc_nl(s: &mut State, n: usize, m: usize) -> *mut u8 {
    unsafe {
        if let Some(total) = n.checked_mul(m)
            && perturb() == 0
            && let Some(size) = request2size(total)
            && size <= SMALL_MAX
        {
            {
                let i = size >> 4;
                let c = s.small[i];
                if !c.is_null() {
                    s.small[i] = sl_get(c);
                    wr(c, 24, 0);
                    s.small_bytes = s.small_bytes.wrapping_sub(size);
                    s.last_fresh = false;
                    let p = chunk2mem(c);
                    if total <= 24 {
                        let w = p as *mut u64;
                        w.write(0);
                        w.add(1).write(0);
                        w.add(2).write(0);
                        return p;
                    }
                    if total <= 128 {
                        return clear_small(p, total);
                    }
                    return clear_big(p, total);
                }
            }
        }
        calloc_full(s, n, m)
    }
}

#[inline(always)]
unsafe fn clear_small(p: *mut u8, total: usize) -> *mut u8 {
    unsafe {
        use core::arch::x86_64::{__m128i, _mm_setzero_si128, _mm_storeu_si128};
        let z = _mm_setzero_si128();
        let st = |o: usize| _mm_storeu_si128(p.add(o) as *mut __m128i, z);
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
}

#[inline(always)]
unsafe fn clear_big(p: *mut u8, total: usize) -> *mut u8 {
    unsafe { rusty_libc_mem::memset(p.cast(), 0, total).cast() }
}

unsafe fn calloc_full(s: &mut State, n: usize, m: usize) -> *mut u8 {
    unsafe {
        let Some(total) = n.checked_mul(m) else {
            set_enomem();
            return null_mut();
        };
        let Some(size) = request2size(total) else {
            return malloc_toobig();
        };
        let p = malloc_slow(s, size, 0);
        if p.is_null() {
            return p;
        }
        if !s.last_fresh {
            if total <= 24 {
                let w = p as *mut u64;
                w.write(0);
                w.add(1).write(0);
                w.add(2).write(0);
            } else if total <= 128 {
                clear_small(p, total);
            } else {
                rusty_libc_mem::memset(p.cast(), 0, total);
            }
        }
        p
    }
}

unsafe fn realloc_nl(s: &mut State, p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        if p.is_null() {
            return malloc_nl(s, n);
        }
        if n == 0 {
            free_nl(s, p);
            return null_mut();
        }
        let Some(size) = request2size(n) else {
            set_enomem();
            return null_mut();
        };
        let c = mem2chunk(p);
        let head = rd(c, 8);
        if head & IS_MMAPPED == 0 && head & NON_MAIN_ARENA != s.abit {
            return realloc_foreign(p, n);
        }
        let old = head & !FLAGS;
        if (p as usize) & 15 != 0 || old < MINSIZE {
            fatal("realloc(): invalid pointer");
        }
        if head & IS_MMAPPED != 0 {
            let off = rd(c, 0);
            if old - 16 >= n && old - 16 < n + 2 * PAGE {
                return p;
            }
            let new_len = (size + 8 + PAGE - 1) & !(PAGE - 1);
            if off == 0 {
                let r = syscall::syscall4(syscall::SYS_MREMAP, c as usize, old, new_len, MREMAP_MAYMOVE);
                if r <= usize::MAX - 4095 {
                    let nc = r as *mut u8;
                    let now = count_add(&P.mmapped_mem, new_len.wrapping_sub(old));
                    count_max(&P.max_mmapped_mem, now);
                    wr(nc, 8, new_len | IS_MMAPPED);
                    return chunk2mem(nc);
                }
            }
            return move_block(s, p, old - 16, n);
        }
        if size <= old {
            let rem = old - size;
            if rem >= MINSIZE {
                wr(c, 8, size | (head & PREV_INUSE) | s.abit);
                let r = c.add(size);
                wr(r, 8, rem | PREV_INUSE | s.abit);
                free_nl(s, chunk2mem(r));
            }
            return p;
        }
        let next = c.add(old);
        if next == s.top {
            let ts = csize(next);
            if ts + old >= size + MINSIZE {
                let nt = c.add(size);
                wr(c, 8, size | (head & PREV_INUSE) | s.abit);
                wr(nt, 8, (ts + old - size) | PREV_INUSE | s.abit);
                s.top = nt;
                let end = c as usize + size;
                if end > s.high_water {
                    s.high_water = end;
                }
                return p;
            }
        } else {
            let nsize = csize(next);
            if rd(next.add(nsize), 8) & PREV_INUSE == 0 && old + nsize >= size {
                s.unlink(next, nsize);
                let total = old + nsize;
                let rem = total - size;
                if rem >= MINSIZE {
                    wr(c, 8, size | (head & PREV_INUSE) | s.abit);
                    let r = c.add(size);
                    wr(r, 8, rem | PREV_INUSE | s.abit);
                    wr(r.add(rem), 0, rem);
                    let after = r.add(rem);
                    wr(after, 8, rd(after, 8) & !PREV_INUSE);
                    s.link_bin(r, rem);
                } else {
                    wr(c, 8, total | (head & PREV_INUSE) | s.abit);
                    let after = c.add(total);
                    wr(after, 8, rd(after, 8) | PREV_INUSE | s.abit);
                }
                return p;
            }
        }
        move_block(s, p, old - SIZE_SZ, n)
    }
}

unsafe fn move_block(s: &mut State, p: *mut u8, old_usable: usize, n: usize) -> *mut u8 {
    unsafe {
        let q = malloc_nl(s, n);
        if q.is_null() {
            return q;
        }
        rusty_libc_mem::memcpy(q.cast(), p.cast(), old_usable.min(n));
        free_nl(s, p);
        q
    }
}

unsafe fn memalign_nl(s: &mut State, align: usize, n: usize) -> *mut u8 {
    unsafe {
        if align <= 16 {
            return malloc_nl(s, n);
        }
        if align > (usize::MAX >> 2) {
            set_enomem();
            return null_mut();
        }
        let Some(size) = request2size(n) else {
            set_enomem();
            return null_mut();
        };
        {
            if size <= SMALL_MAX && small_enabled() && s.init {
                let i = size >> 4;
                let mut prev: *mut u8 = null_mut();
                let mut c = s.small[i];
                for _ in 0..16 {
                    if c.is_null() {
                        break;
                    }
                    if (chunk2mem(c) as usize) & (align - 1) == 0 {
                        let next = sl_get(c);
                        if prev.is_null() {
                            s.small[i] = next;
                        } else {
                            sl_set(prev, next);
                        }
                        wr(c, 24, 0);
                        s.small_bytes = s.small_bytes.wrapping_sub(size);
                        return perturb_alloc(perturb(), chunk2mem(c), size);
                    }
                    prev = c;
                    c = sl_get(c);
                }
            }
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
        let mut c = mem2chunk(m);
        let head = rd(c, 8);
        let mut total = head & !FLAGS;
        if (m as usize) & (align - 1) != 0 {
            let mut am = (m as usize + align - 1) & !(align - 1);
            if (am - m as usize) < MINSIZE {
                am += align;
            }
            let lead = am - m as usize;
            let nc = mem2chunk(am as *mut u8);
            if head & IS_MMAPPED != 0 {
                wr(nc, 0, rd(c, 0) + lead);
                wr(nc, 8, (total - lead) | IS_MMAPPED);
                return am as *mut u8;
            }
            wr(c, 8, lead | (head & PREV_INUSE) | s.abit);
            wr(nc, 8, (total - lead) | PREV_INUSE | s.abit);
            let lead_chunk = c;
            c = nc;
            total -= lead;
            s.free_merge(lead_chunk, lead);
        } else if head & IS_MMAPPED != 0 {
            return m;
        }
        if total - size >= MINSIZE {
            let h = rd(c, 8);
            wr(c, 8, size | (h & PREV_INUSE) | s.abit);
            let r = c.add(size);
            wr(r, 8, (total - size) | PREV_INUSE | s.abit);
            s.free_merge(r, total - size);
        }
        chunk2mem(c)
    }
}

pub struct Stats {
    pub arena: usize,
    pub free_chunks: usize,
    pub small_chunks: usize,
    pub small_bytes: usize,
    pub free_bytes: usize,
    pub top: usize,
}

unsafe fn stats_nl(s: &mut State) -> Stats {
    unsafe {
        if !s.init {
            s.init();
        }
        let mut free_chunks = 0;
        let mut free_bytes = 0;
        for i in 0..NBINS {
            let b = s.bin_node(i);
            let mut c = rd(b, 16) as *mut u8;
            while c != b {
                free_chunks += 1;
                free_bytes += csize(c);
                c = rd(c, 16) as *mut u8;
            }
        }
        let mut small_chunks = 0;
        let mut small_bytes = 0;
        for &head in s.small.iter() {
            let mut c = head;
            while !c.is_null() {
                small_chunks += 1;
                small_bytes += csize(c);
                c = sl_get(c);
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
}

unsafe fn trim_nl(s: &mut State, pad: usize) -> i32 {
    unsafe {
        if !s.init {
            return 0;
        }
        s.consolidate();
        let mut released = 0;
        for i in 0..NBINS {
            let b = s.bin_node(i);
            let mut c = rd(b, 16) as *mut u8;
            while c != b {
                let size = csize(c);
                let lo = (c as usize + 32 + PAGE - 1) & !(PAGE - 1);
                let hi = (c as usize + size - 8) & !(PAGE - 1);
                if hi > lo && hi - lo >= PAGE {
                    syscall::syscall3(syscall::SYS_MADVISE, lo, hi - lo, MADV_DONTNEED);
                    released = 1;
                }
                c = rd(c, 16) as *mut u8;
            }
        }
        let before = s.top_size();
        s.trim_top(0, pad);
        if s.top_size() < before {
            released = 1;
        }
        released
    }
}

unsafe fn ensure_init_nl(s: &mut State) {
    unsafe {
        if !s.init {
            s.init();
        }
    }
}


#[thread_local]
static mut THREAD_ARENA: *mut State = null_mut();
#[thread_local]
static mut TCACHE: *mut TCache = &raw const EMPTY as *mut TCache;
static EMPTY: TCache = TCache { room: [0; NSMALL], entries: [null_mut(); NSMALL] };
unsafe impl Sync for TCache {}

#[inline(always)]
fn no_cache(t: *mut TCache) -> bool {
    core::ptr::eq(t, &EMPTY)
}
#[thread_local]
static mut TCACHE_DONE: bool = false;
static NARENAS_LIMIT: AtomicUsize = AtomicUsize::new(0);

const HEAP_HDR: usize = (core::mem::size_of::<HeapInfo>() + 15) & !15;

fn page_up(n: usize) -> usize {
    n.saturating_add(PAGE - 1) & !(PAGE - 1)
}

#[inline(always)]
unsafe fn arena_for_chunk(c: *mut u8) -> *mut State {
    unsafe {
        if rd(c, 8) & NON_MAIN_ARENA == 0 {
            st() as *mut State
        } else {
            (*((c as usize & !(HEAP_MAX - 1)) as *mut HeapInfo)).arena
        }
    }
}

unsafe fn new_heap(first: usize) -> *mut HeapInfo {
    unsafe {
        const PROT_NONE: usize = 0;
        const MAP_NORESERVE: usize = 0x4000;
        let r = syscall::syscall6(syscall::SYS_MMAP, 0, 2 * HEAP_MAX, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, usize::MAX, 0);
        if r > usize::MAX - 4095 {
            return null_mut();
        }
        let start = (r + HEAP_MAX - 1) & !(HEAP_MAX - 1);
        if start > r {
            syscall::syscall2(syscall::SYS_MUNMAP, r, start - r);
        }
        let end = r + 2 * HEAP_MAX;
        if end > start + HEAP_MAX {
            syscall::syscall2(syscall::SYS_MUNMAP, start + HEAP_MAX, end - (start + HEAP_MAX));
        }
        if syscall::syscall3(syscall::SYS_MPROTECT, start, first, PROT_READ | PROT_WRITE) != 0 {
            syscall::syscall2(syscall::SYS_MUNMAP, start, HEAP_MAX);
            return null_mut();
        }
        start as *mut HeapInfo
    }
}

unsafe fn new_arena() -> *mut State {
    unsafe {
        let st_off = HEAP_HDR;
        let top_off = (st_off + core::mem::size_of::<State>() + 15) & !15;
        let first = page_up(top_off + MINSIZE + P.top_pad.load(Relaxed)).min(HEAP_MAX);
        let h = new_heap(first);
        if h.is_null() {
            return null_mut();
        }
        let a = (h as *mut u8).add(st_off) as *mut State;
        core::ptr::write(a, State::empty());
        let s = &mut *a;
        s.abit = NON_MAIN_ARENA;
        s.top_is_brk = false;
        s.heap = h;
        s.attached = 1;
        (*h).arena = a;
        (*h).prev = null_mut();
        (*h).committed = first;
        s.add_system(first);
        s.init();
        let top = (h as *mut u8).add(top_off);
        s.top = top;
        wr(top, 8, (first - top_off) | PREV_INUSE | NON_MAIN_ARENA);
        a
    }
}

unsafe fn read_arena_env() {
    unsafe {
        for (name, cell) in [(&b"MALLOC_ARENA_MAX"[..], &P.arena_max), (&b"MALLOC_ARENA_TEST"[..], &P.arena_test)] {
            let v = rusty_libc_core::env::getenv(name);
            if v.is_null() {
                continue;
            }
            let mut n: usize = 0;
            let mut p = v as *const u8;
            let mut ok = *p != 0;
            while *p != 0 {
                let c = *p;
                if !c.is_ascii_digit() {
                    ok = false;
                    break;
                }
                n = n.saturating_mul(10).saturating_add((c - b'0') as usize);
                p = p.add(1);
            }
            if ok && n > 0 {
                cell.store(n, Relaxed);
            }
        }
    }
}

fn nprocs() -> usize {
    let mut set = [0u64; 16];
    let r = unsafe { syscall::syscall3(204, 0, core::mem::size_of_val(&set), set.as_mut_ptr() as usize) };
    if r > usize::MAX - 4095 {
        return 0;
    }
    set.iter().map(|w| w.count_ones() as usize).sum()
}

#[inline(always)]
unsafe fn thread_arena() -> *mut State {
    unsafe {
        let a = THREAD_ARENA;
        if !a.is_null() { a } else { choose_arena() }
    }
}

#[cold]
#[inline(never)]
unsafe fn choose_arena() -> *mut State {
    unsafe {
        let main = st() as *mut State;
        if !(*main).init {
            (*main).lock.lock_always();
            if !(*main).init {
                (*main).init();
                (*main).lock.unlock_always();
                return main;
            }
            (*main).lock.unlock_always();
        }
        ARENA_LIST.lock_always();
        let f = FREE_ARENAS.load(Relaxed);
        if !f.is_null() {
            FREE_ARENAS.store((*f).next_free, Relaxed);
            (*f).next_free = null_mut();
            (*f).attached += 1;
            ARENA_LIST.unlock_always();
            THREAD_ARENA = f;
            return f;
        }
        let n = NARENAS.load(Relaxed);
        let mut limit = NARENAS_LIMIT.load(Relaxed);
        if limit == 0 {
            let max = P.arena_max.load(Relaxed);
            if max != 0 {
                limit = max;
            } else if n > P.arena_test.load(Relaxed) {
                let c = nprocs();
                limit = 8 * if c >= 1 { c } else { 2 };
            }
            NARENAS_LIMIT.store(limit, Relaxed);
        }
        if limit == 0 || n < limit {
            let a = new_arena();
            if !a.is_null() {
                (*a).id = n;
                (*a).next.store((*main).next.load(Relaxed), Relaxed);
                (*main).next.store(a, Release);
                NARENAS.store(n + 1, Relaxed);
                ARENA_LIST.unlock_always();
                THREAD_ARENA = a;
                return a;
            }
        }
        ARENA_LIST.unlock_always();
        reuse_arena()
    }
}

#[inline]
unsafe fn ring_next(a: *mut State) -> *mut State {
    unsafe {
        let n = (*a).next.load(Acquire);
        if n.is_null() { st() as *mut State } else { n }
    }
}

unsafe fn reuse_arena() -> *mut State {
    unsafe {
        let mut start = NEXT_TO_USE.load(Relaxed);
        if start.is_null() {
            start = st() as *mut State;
        }
        let mut r = start;
        let mut found = null_mut();
        loop {
            if (*r).lock.try_lock_always() {
                (*r).lock.unlock_always();
                found = r;
                break;
            }
            r = ring_next(r);
            if r == start {
                break;
            }
        }
        if found.is_null() {
            found = start;
        }
        NEXT_TO_USE.store(ring_next(found), Relaxed);
        ARENA_LIST.lock_always();
        let mut pp = &raw const FREE_ARENAS as *mut AtomicPtr<State>;
        let mut q = (*pp).load(Relaxed);
        while !q.is_null() {
            if q == found {
                (*pp).store((*q).next_free, Relaxed);
                (*q).next_free = null_mut();
                break;
            }
            pp = (&raw mut (*q).next_free).cast::<AtomicPtr<State>>();
            q = (*pp).load(Relaxed);
        }
        (*found).attached += 1;
        ARENA_LIST.unlock_always();
        THREAD_ARENA = found;
        found
    }
}

#[repr(C)]
struct TCache {
    room: [u16; NSMALL],
    entries: [*mut u8; NSMALL],
}

#[inline(always)]
unsafe fn tcache() -> *mut TCache {
    unsafe {
        let t = TCACHE;
        if !no_cache(t) {
            t
        } else if TCACHE_DONE {
            null_mut()
        } else {
            tcache_init()
        }
    }
}

#[cold]
#[inline(never)]
unsafe fn tcache_init() -> *mut TCache {
    unsafe {
        TCACHE_DONE = true;
        if P.tcache_count.load(Relaxed) == 0 {
            return null_mut();
        }
        let a = thread_arena();
        (*a).lock.lock_always();
        let m = malloc_nl(&mut *a, core::mem::size_of::<TCache>());
        (*a).lock.unlock_always();
        if m.is_null() {
            return null_mut();
        }
        core::ptr::write_bytes(m, 0, core::mem::size_of::<TCache>());
        let t = m as *mut TCache;
        let n = P.tcache_count.load(Relaxed).min(u16::MAX as usize) as u16;
        for r in (*t).room.iter_mut() {
            *r = n;
        }
        TCACHE = t;
        m as *mut TCache
    }
}

#[inline(never)]
unsafe fn free_to_arena(p: *mut u8) {
    unsafe {
        let a = arena_for_chunk(mem2chunk(p));
        (*a).lock.lock_always();
        free_nl(&mut *a, p);
        (*a).lock.unlock_always();
    }
}

pub unsafe fn thread_shutdown() {
    unsafe {
        let t = TCACHE;
        TCACHE = &raw const EMPTY as *mut TCache;
        TCACHE_DONE = true;
        if !no_cache(t) {
            for i in 0..NSMALL {
                let mut c = (*t).entries[i];
                while !c.is_null() {
                    let next = sl_get(c);
                    wr(c, 24, 0);
                    free_to_arena(chunk2mem(c));
                    c = next;
                }
            }
            free_to_arena(t as *mut u8);
        }
        let a = THREAD_ARENA;
        THREAD_ARENA = null_mut();
        if !a.is_null() {
            ARENA_LIST.lock_always();
            (*a).attached -= 1;
            if (*a).attached == 0 {
                (*a).next_free = FREE_ARENAS.load(Relaxed);
                FREE_ARENAS.store(a, Relaxed);
            }
            ARENA_LIST.unlock_always();
        }
    }
}

#[inline(always)]
pub unsafe fn malloc(n: usize) -> *mut u8 {
    unsafe {
        if core::hint::likely(no_cache(TCACHE) && !rusty_libc_core::lock::multithreaded()) {
            if n <= SMALL_MAX - SIZE_SZ && perturb() == 0 {
                let s = st();
                let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
                let e = s.small.as_mut_ptr().add(size >> 4);
                let c = *e;
                if !c.is_null() {
                    let next = rd(c, 16) ^ ((c as usize + 16) >> 12);
                    if next & 15 != 0 {
                        return bad_list();
                    }
                    *e = next as *mut u8;
                    wr(c, 24, 0);
                    s.small_bytes = s.small_bytes.wrapping_sub(size);
                    s.last_fresh = false;
                    return chunk2mem(c);
                }
            }
            let Some(size) = request2size(n) else {
                return malloc_toobig();
            };
            return malloc_slow(st(), size, perturb());
        }
        malloc_mt(n)
    }
}

#[cold]
#[inline(never)]
fn bad_list() -> *mut u8 {
    if core::hint::black_box(true) {
        fatal("malloc(): unaligned tcache chunk detected");
    }
    core::hint::black_box(null_mut())
}

#[inline(always)]
unsafe fn malloc_mt(n: usize) -> *mut u8 {
    unsafe {
        let t = TCACHE;
        if n <= SMALL_MAX - SIZE_SZ {
            let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
            let i = size >> 4;
            let e = (*t).entries.as_mut_ptr().add(i);
            let c = *e;
            if !c.is_null() {
                let next = rd(c, 16) ^ ((c as usize + 16) >> 12);
                if next & 15 != 0 {
                    return bad_list();
                }
                *e = next as *mut u8;
                *(*t).room.as_mut_ptr().add(i) += 1;
                wr(c, 24, 0);
                return chunk2mem(c);
            }
        }
        malloc_mt_slow(n)
    }
}

#[inline(never)]
unsafe fn malloc_mt_slow(n: usize) -> *mut u8 {
    unsafe {
        if let Some(size) = request2size(n)
            && size <= SMALL_MAX
        {
            let t = tcache();
            if !t.is_null() {
                let i = size >> 4;
                let c = (*t).entries[i];
                if !c.is_null() {
                    (*t).entries[i] = sl_get(c);
                    (*t).room[i] += 1;
                    wr(c, 24, 0);
                    return chunk2mem(c);
                }
                return malloc_refill(t, i, n);
            }
        }
        malloc_arena(n)
    }
}

#[inline(never)]
unsafe fn malloc_refill(t: *mut TCache, i: usize, n: usize) -> *mut u8 {
    unsafe {
        let a = thread_arena();
        (*a).lock.lock_always();
        let s = &mut *a;
        let p = malloc_nl(s, n);
        if !p.is_null() && small_enabled() {
            let keep_free = P.tcache_count.load(Relaxed).div_ceil(2);
            let size = i << 4;
            while ((*t).room[i] as usize) > keep_free {
                let c = s.small[i];
                if c.is_null() {
                    break;
                }
                s.small[i] = sl_get(c);
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                sl_set(c, (*t).entries[i]);
                wr(c, 24, key());
                (*t).entries[i] = c;
                (*t).room[i] -= 1;
            }
        }
        (*a).lock.unlock_always();
        if p.is_null() && !core::ptr::eq(a, st()) {
            return malloc_main(n);
        }
        p
    }
}

#[inline(never)]
unsafe fn malloc_arena(n: usize) -> *mut u8 {
    unsafe {
        let a = thread_arena();
        (*a).lock.lock_always();
        let p = malloc_nl(&mut *a, n);
        (*a).lock.unlock_always();
        if p.is_null() && !core::ptr::eq(a, st()) {
            return malloc_main(n);
        }
        p
    }
}

#[cold]
unsafe fn malloc_main(n: usize) -> *mut u8 {
    unsafe {
        let m = st();
        m.lock.lock_always();
        let p = malloc_nl(m, n);
        m.lock.unlock_always();
        p
    }
}

#[inline(always)]
pub unsafe fn free(p: *mut u8) {
    unsafe {
        if core::hint::likely(no_cache(TCACHE) && !rusty_libc_core::lock::multithreaded()) {
            if !p.is_null() {
                let s = st();
                let c = mem2chunk(p);
                let head = rd(c, 8);
                let size = head & !FLAGS;
                let k = key();
                if head & (IS_MMAPPED | NON_MAIN_ARENA) == 0
                    && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
                    && (size | p as usize) & 15 == 0
                    && rd(c, 24) != k
                    && perturb() == 0
                    && small_enabled()
                {
                    let e = s.small.as_mut_ptr().add(size >> 4);
                    sl_set(c, *e);
                    wr(c, 24, k);
                    *e = c;
                    s.small_bytes += size;
                    if s.small_bytes > SMALL_BYTES_MAX {
                        return consolidate_main();
                    }
                    return;
                }
            }
            return free_slow(st(), p);
        }
        free_mt(p)
    }
}

#[cold]
#[inline(never)]
unsafe fn consolidate_main() {
    unsafe { st().consolidate() }
}

#[inline(always)]
unsafe fn free_mt(p: *mut u8) {
    unsafe {
        let t = TCACHE;
        if !p.is_null() {
            let c = mem2chunk(p);
            let head = rd(c, 8);
            let size = head & !FLAGS;
            let k = key();
            if head & IS_MMAPPED == 0
                && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
                && (size | p as usize) & 15 == 0
                && rd(c, 24) != k
            {
                let i = size >> 4;
                let r = (*t).room.as_mut_ptr().add(i);
                if *r != 0 {
                    let e = (*t).entries.as_mut_ptr().add(i);
                    sl_set(c, *e);
                    wr(c, 24, k);
                    *e = c;
                    *r -= 1;
                    return;
                }
            }
        }
        free_mt_slow(p)
    }
}

#[inline(never)]
unsafe fn free_mt_slow(p: *mut u8) {
    unsafe {
        if p.is_null() {
            return;
        }
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & IS_MMAPPED == 0
            && (MINSIZE..=SMALL_MAX).contains(&size)
            && size & 15 == 0
            && (p as usize) & 15 == 0
        {
            let t = tcache();
            if !t.is_null() {
                let i = size >> 4;
                let k = key();
                if rd(c, 24) == k {
                    let mut q = (*t).entries[i];
                    while !q.is_null() {
                        if q == c {
                            fatal("free(): double free detected in tcache 2");
                        }
                        q = sl_get(q);
                    }
                }
                if (*t).room[i] != 0 {
                    sl_set(c, (*t).entries[i]);
                    wr(c, 24, k);
                    (*t).entries[i] = c;
                    (*t).room[i] -= 1;
                    return;
                }
            }
        }
        if head & IS_MMAPPED != 0 {
            return free_slow(st(), p);
        }
        free_to_arena(p)
    }
}

#[cold]
#[inline(never)]
unsafe fn free_foreign(p: *mut u8) {
    unsafe { free_to_arena(p) }
}

#[cold]
#[inline(never)]
unsafe fn realloc_foreign(p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        let a = arena_for_chunk(mem2chunk(p));
        (*a).lock.lock_always();
        let r = realloc_nl(&mut *a, p, n);
        (*a).lock.unlock_always();
        r
    }
}

pub unsafe fn usable_size(p: *mut u8) -> usize {
    unsafe { usable_size_nl(p) }
}

#[inline]
pub unsafe fn calloc(n: usize, m: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return calloc_nl(st(), n, m);
        }
        calloc_mt(n, m)
    }
}

#[inline(never)]
unsafe fn calloc_mt(n: usize, m: usize) -> *mut u8 {
    unsafe {
        let a = thread_arena();
        (*a).lock.lock_always();
        let p = calloc_nl(&mut *a, n, m);
        (*a).lock.unlock_always();
        if p.is_null() && !core::ptr::eq(a, st()) && n.checked_mul(m).is_some() {
            let s = st();
            s.lock.lock_always();
            let p = calloc_nl(s, n, m);
            s.lock.unlock_always();
            return p;
        }
        p
    }
}

#[inline]
pub unsafe fn realloc(p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return realloc_nl(st(), p, n);
        }
        realloc_mt(p, n)
    }
}

#[inline(never)]
unsafe fn realloc_mt(p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        if p.is_null() {
            return malloc_mt(n);
        }
        if n == 0 {
            free_mt(p);
            return null_mut();
        }
        let c = mem2chunk(p);
        let a = if rd(c, 8) & IS_MMAPPED != 0 { thread_arena() } else { arena_for_chunk(c) };
        (*a).lock.lock_always();
        let r = realloc_nl(&mut *a, p, n);
        (*a).lock.unlock_always();
        r
    }
}

pub unsafe fn memalign(align: usize, n: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return memalign_nl(st(), align, n);
        }
        if align > 16
            && let Some(size) = request2size(n)
            && size <= SMALL_MAX
        {
            let t = tcache();
            if !t.is_null() {
                let i = size >> 4;
                let mut link: *mut *mut u8 = &raw mut (*t).entries[i];
                let mut c = *link;
                while !c.is_null() {
                    let next = sl_get(c);
                    if (chunk2mem(c) as usize) & (align - 1) == 0 {
                        if core::ptr::eq(link, &raw mut (*t).entries[i]) {
                            *link = next;
                        } else {
                            sl_set(link.cast::<u8>().sub(16), next);
                        }
                        (*t).room[i] += 1;
                        wr(c, 24, 0);
                        return chunk2mem(c);
                    }
                    link = c.add(16).cast::<*mut u8>();
                    c = next;
                }
            }
        }
        let a = thread_arena();
        (*a).lock.lock_always();
        let p = memalign_nl(&mut *a, align, n);
        (*a).lock.unlock_always();
        p
    }
}

pub fn arenas(mut f: impl FnMut(&mut State)) {
    unsafe {
        let main = st() as *mut State;
        let mut a = main;
        loop {
            f(&mut *a);
            a = ring_next(a);
            if a == main {
                break;
            }
        }
    }
}

pub unsafe fn arena_stats(s: &mut State) -> Stats {
    let taken = s.lock.lock();
    let r = unsafe { stats_nl(s) };
    s.lock.unlock(taken);
    r
}

pub unsafe fn stats() -> Stats {
    let mut t = Stats { arena: 0, free_chunks: 0, small_chunks: 0, small_bytes: 0, free_bytes: 0, top: 0 };
    arenas(|s| {
        let x = unsafe { arena_stats(s) };
        t.arena += x.arena;
        t.free_chunks += x.free_chunks;
        t.small_chunks += x.small_chunks;
        t.small_bytes += x.small_bytes;
        t.free_bytes += x.free_bytes;
        if s.id == 0 {
            t.top = x.top;
        } else {
            t.free_bytes += x.top;
            t.free_chunks += 1;
        }
    });
    t
}

pub unsafe fn trim(pad: usize) -> i32 {
    let mut r = 0;
    arenas(|s| {
        let taken = s.lock.lock();
        r |= unsafe { trim_nl(s, pad) };
        s.lock.unlock(taken);
    });
    r
}

pub unsafe fn ensure_init() {
    let s = st();
    let taken = s.lock.lock();
    unsafe { ensure_init_nl(s) };
    s.lock.unlock(taken);
}

pub fn main_lock() -> &'static rusty_libc_core::lock::RawMutex {
    &st().lock
}

pub struct ArenaInfo {
    pub main: bool,
    pub nblocks: usize,
    pub avail: usize,
    pub system: usize,
    pub max_system: usize,
    pub aspace: usize,
    pub aspace_mprotect: usize,
    pub subheaps: usize,
}

pub fn arena_infos(mut f: impl FnMut(&ArenaInfo)) {
    arenas(|s| unsafe {
        let x = arena_stats(s);
        let main = s.abit == 0;
        let (mut aspace, mut subheaps) = (0, 0);
        if !main {
            let taken = s.lock.lock();
            let mut h = s.heap;
            while !h.is_null() {
                aspace += (*h).committed;
                subheaps += 1;
                h = (*h).prev;
            }
            s.lock.unlock(taken);
        }
        let system = if main { x.arena } else { s.system_mem };
        let max_system = if main { x.arena } else { s.max_system_mem };
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

pub fn atfork_prepare() {
    ARENA_LIST.lock_always();
    arenas(|s| s.lock.lock_always());
}

pub fn atfork_parent() {
    arenas(|s| s.lock.unlock_always());
    ARENA_LIST.unlock_always();
}

pub fn atfork_child() {
    unsafe {
        let mine = THREAD_ARENA;
        let mut free: *mut State = null_mut();
        arenas(|s| {
            s.lock.unlock_always();
            let me = s as *mut State;
            if me == mine {
                s.attached = 1;
            } else {
                s.attached = 0;
                s.next_free = free;
                free = me;
            }
        });
        FREE_ARENAS.store(free, Relaxed);
        ARENA_LIST.unlock_always();
    }
}
