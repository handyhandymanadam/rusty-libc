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
    last_fresh: bool,
    small: [*mut u8; NSMALL],
    bins: [[usize; 4]; NBINS],
    map: [u64; 2],
    foreign_bytes: usize,
    small_bytes: usize,
    grow_first: bool,
    abit: usize,
    heap: *mut HeapInfo,
    system_mem: usize,
    max_system_mem: usize,
    id: usize,
}

pub struct ArenaCell {
    state: SyncCell<State>,
    lock: rusty_libc_core::lock::RawMutex,
    next: AtomicPtr<ArenaCell>,
    next_free: AtomicPtr<ArenaCell>,
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
    pub tcache_max: AtomicUsize,
    pub thp_pagesize: AtomicUsize,
    pub thp_madvise: AtomicBool,
    pub trim_mask: AtomicUsize,
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
    arena: *mut ArenaCell,
    prev: *mut HeapInfo,
    committed: usize,
    pagesize: usize,
}

const HEAP_MAX: usize = 64 << 20;
const NON_MAIN_ARENA: usize = 4;

static ARENA_LIST: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();
static NARENAS: AtomicUsize = AtomicUsize::new(1);
static FREE_ARENAS: AtomicPtr<ArenaCell> = AtomicPtr::new(null_mut());
static NEXT_TO_USE: AtomicPtr<ArenaCell> = AtomicPtr::new(null_mut());

static STATE: ArenaCell = ArenaCell::new(State::empty());

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
            heap: null_mut(),
            system_mem: 0,
            max_system_mem: 0,
            id: 0,
        }
    }
}

#[inline(always)]
fn main_ptr() -> *mut ArenaCell {
    (&raw const STATE).cast_mut()
}

#[inline(always)]
pub unsafe fn st() -> &'static mut State {
    unsafe { &mut *STATE.state.as_ptr() }
}

#[inline(always)]
fn at(c: *mut u8, off: usize) -> *mut u8 {
    c.wrapping_add(off)
}

#[inline(always)]
unsafe fn rd(p: *mut u8, off: usize) -> usize {
    unsafe { *(at(p, off) as *mut usize) }
}

#[inline(always)]
unsafe fn wr(p: *mut u8, off: usize, v: usize) {
    unsafe { *(at(p, off) as *mut usize) = v }
}

#[inline(always)]
unsafe fn sl_set(c: *mut u8, next: *mut u8) {
    unsafe { wr(c, 16, ((c as usize + 16) >> 12) ^ next as usize) }
}

#[inline(always)]
unsafe fn sl_get(c: *mut u8) -> *mut u8 {
    let v = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
    if v & 15 != 0 {
        fatal("malloc(): unaligned tcache chunk detected");
    }
    v as *mut u8
}

#[inline(always)]
unsafe fn csize(c: *mut u8) -> usize {
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
    fn init(&mut self) {
        for i in 0..NBINS {
            let b = self.bin_node(i) as usize;
            self.bins[i][2] = b;
            self.bins[i][3] = b;
        }
        if self.abit != 0 {
            self.init = true;
            return;
        }
        if !rusty_libc_core::lock::libc_initial() {
            self.top_is_brk = false;
        }
        let brk = brk_query();
        let start = (brk + 15) & !15;
        self.brk_start = start;
        self.brk_end = brk;
        let k = match random_word() {
            Some(r) => r,
            None => {
                let t = unsafe { core::arch::x86_64::_rdtsc() } as usize;
                (t ^ (brk >> 4)).rotate_left(17)
            }
        };
        P.key.store(k | 1, Relaxed);
        apply_tunables(self);
        THREAD_ARENA.set(main_ptr());
        self.init = true;
        NEXT_TO_USE.store(main_ptr(), Release);
    }

    #[inline(always)]
    fn bin_node(&mut self, i: usize) -> *mut u8 {
        (&raw mut self.bins[i]).cast::<u8>()
    }

    unsafe fn link_bin(&mut self, c: *mut u8, size: usize) {
        let idx = bin_index(size);
        let b = self.bin_node(idx);
        let mut next = unsafe { rd(b, 16) } as *mut u8;
        if idx >= 64 {
            while next != b && unsafe { csize(next) } < size {
                next = unsafe { rd(next, 16) } as *mut u8;
            }
            let prev = unsafe { rd(next, 24) } as *mut u8;
            unsafe { wr(c, 16, next as usize) };
            unsafe { wr(c, 24, prev as usize) };
            unsafe { wr(prev, 16, c as usize) };
            unsafe { wr(next, 24, c as usize) };
        } else {
            unsafe { wr(c, 16, next as usize) };
            unsafe { wr(c, 24, b as usize) };
            unsafe { wr(next, 24, c as usize) };
            unsafe { wr(b, 16, c as usize) };
        }
        self.map[idx >> 6] |= 1 << (idx & 63);
    }

    unsafe fn unlink(&mut self, c: *mut u8, size: usize) {
        let fd = unsafe { rd(c, 16) } as *mut u8;
        let bk = unsafe { rd(c, 24) } as *mut u8;
        if unsafe { rd(fd, 24) } != c as usize || unsafe { rd(bk, 16) } != c as usize {
            fatal("corrupted double-linked list");
        }
        unsafe { wr(fd, 24, bk as usize) };
        unsafe { wr(bk, 16, fd as usize) };
        let idx = bin_index(size);
        if self.bins[idx][2] == self.bin_node(idx) as usize {
            self.map[idx >> 6] &= !(1 << (idx & 63));
        }
    }

    fn top_size(&self) -> usize {
        if self.top.is_null() { 0 } else { unsafe { csize(self.top) } }
    }

    unsafe fn free_merge(&mut self, c: *mut u8, size: usize) {
        let (mut c, mut size) = (c, size);
        if unsafe { rd(c, 8) } & PREV_INUSE == 0 {
            let ps = unsafe { rd(c, 0) };
            let p = c.wrapping_sub(ps);
            if unsafe { csize(p) } != ps {
                fatal("corrupted size vs. prev_size");
            }
            c = p;
            size += ps;
            unsafe { self.unlink(c, ps) };
        }
        let next = at(c, size);
        if next == self.top {
            size += unsafe { csize(next) };
            unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
            self.top = c;
            return;
        }
        let nsize = unsafe { csize(next) };
        if unsafe { rd(at(next, nsize), 8) } & PREV_INUSE == 0 {
            unsafe { self.unlink(next, nsize) };
            size += nsize;
        }
        unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
        let after = at(c, size);
        unsafe { wr(after, 0, size) };
        unsafe { clear_prev_inuse(after) };
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
                let next = unsafe { sl_get(c) };
                let size = unsafe { csize(c) };
                unsafe { wr(c, 24, 0) };
                unsafe { self.free_merge(c, size) };
                c = next;
            }
        }
    }

    fn trim_top(&mut self, threshold: usize, pad: usize) {
        if !self.top_is_brk || self.top.is_null() {
            return;
        }
        let ts = self.top_size();
        if ts < threshold {
            return;
        }
        let area = ts.saturating_sub(MINSIZE + 1);
        if area <= pad {
            return;
        }
        let extra = (area - pad) & P.trim_mask.load(Relaxed);
        if extra == 0 {
            return;
        }
        let want = self.brk_end - extra;
        let got = unsafe { brk_set(want) };
        if got == want {
            self.brk_end = want;
            unsafe { wr(self.top, 8, (ts - extra) | PREV_INUSE | self.abit) };
        }
    }

    unsafe fn split(&mut self, c: *mut u8, have: usize, size: usize) -> *mut u8 {
        let rem = have - size;
        if rem >= MINSIZE {
            unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
            let r = at(c, size);
            unsafe { wr(r, 8, rem | PREV_INUSE | self.abit) };
            let after = at(r, rem);
            unsafe { wr(after, 0, rem) };
            unsafe { clear_prev_inuse(after) };
            unsafe { self.link_bin(r, rem) };
        } else {
            unsafe { wr(c, 8, have | PREV_INUSE | self.abit) };
            let next = at(c, have);
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
            let mut c = self.bins[idx][2] as *mut u8;
            if idx == start && idx >= 64 {
                while c != b && unsafe { csize(c) } < size {
                    let cs = unsafe { csize(c) };
                    if cs < MINSIZE || cs & 15 != 0 {
                        fatal("malloc(): invalid size (unsorted)");
                    }
                    c = unsafe { rd(c, 16) } as *mut u8;
                }
                if c == b {
                    bits &= bits - 1;
                    continue;
                }
            }
            let have = unsafe { csize(c) };
            if have < MINSIZE || have & 15 != 0 || bin_index(have) != idx {
                fatal("malloc(): invalid size (unsorted)");
            }
            unsafe { self.unlink(c, have) };
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
        unsafe { wr(c, 8, size | PREV_INUSE | self.abit) };
        let nt = at(c, size);
        unsafe { wr(nt, 8, (ts - size) | PREV_INUSE | self.abit) };
        self.top = nt;
        let end = c as usize + size;
        self.last_fresh = c as usize >= self.high_water;
        if end > self.high_water {
            self.high_water = end;
        }
        c
    }

    fn grow(&mut self, size: usize) -> bool {
        if self.abit != 0 {
            return self.grow_heap(size);
        }
        let ts = self.top_size();
        let need = size + MINSIZE;
        let top_pad = P.top_pad.load(Relaxed);
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
                let got = unsafe { brk_set(want) };
                if got == want {
                    madvise_thp(self.brk_end, ext);
                    if self.top.is_null() {
                        let start = (self.brk_end + 15) & !15;
                        self.top = start as *mut u8;
                        unsafe { wr(self.top, 8, (want - start) | PREV_INUSE | self.abit) };
                        self.brk_start = start;
                    } else {
                        unsafe { wr(self.top, 8, (ts + (want - self.brk_end)) | PREV_INUSE | self.abit) };
                    }
                    self.brk_end = want;
                    return true;
                }
            }
        }
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
        unsafe { wr(m, 8, len | PREV_INUSE | self.abit) };
        self.foreign_bytes += len;
        true
    }

    fn retire_top(&mut self) {
        if !self.top.is_null() {
            let old = self.top;
            let os = self.top_size();
            self.top = null_mut();
            if os >= MINSIZE + 32 {
                let keep = os - 32;
                unsafe { wr(old, 8, keep | PREV_INUSE | self.abit) };
                let f1 = at(old, keep);
                unsafe { wr(f1, 8, 16 | PREV_INUSE | self.abit) };
                unsafe { wr(f1, 16, 0) };
                unsafe { wr(at(f1, 16), 8, PREV_INUSE | self.abit) };
                unsafe { wr(f1, 0, 0) };
                unsafe { self.free_merge(old, keep) };
            } else if os >= 32 {
                unsafe { wr(old, 8, 16 | PREV_INUSE | self.abit) };
                unsafe { wr(at(old, 16), 8, PREV_INUSE | self.abit) };
            }
        }
    }

    fn grow_heap(&mut self, size: usize) -> bool {
        let h = self.heap;
        let ts = self.top_size();
        let need = size + MINSIZE;
        let pad = P.top_pad.load(Relaxed);
        let committed = unsafe { (*h).committed };
        let ps = unsafe { (*h).pagesize };
        let up = |n: usize| n.saturating_add(ps - 1) & !(ps - 1);
        for ext in [up(need.saturating_sub(ts).saturating_add(pad)), up(need.saturating_sub(ts))] {
            if ext <= HEAP_MAX - committed && unsafe { mprotect_rw(h as usize + committed, ext) } {
                if committed < P.thp_pagesize.load(Relaxed) {
                    madvise_thp(h as usize, committed + ext);
                }
                unsafe { (*h).committed += ext };
                self.add_system(ext);
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
        nh.arena = unsafe { (*h).arena };
        nh.prev = h;
        let nh = nh as *mut HeapInfo;
        self.heap = nh;
        self.add_system(first);
        self.retire_top();
        let m = at(nh.cast(), hdr);
        self.top = m;
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

fn brk_query() -> usize {
    unsafe { syscall::syscall1(syscall::SYS_BRK, 0) }
}

unsafe fn brk_set(addr: usize) -> usize {
    unsafe { syscall::syscall1(syscall::SYS_BRK, addr) }
}

fn random_word() -> Option<usize> {
    let mut r = 0usize;
    let got = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, &raw mut r as usize, 8, 1 ) };
    if got == 8 { Some(r) } else { None }
}

unsafe fn mprotect_rw(addr: usize, len: usize) -> bool {
    unsafe { syscall::syscall3(syscall::SYS_MPROTECT, addr, len, PROT_READ | PROT_WRITE) == 0 }
}

unsafe fn munmap(addr: usize, len: usize) -> bool {
    unsafe { syscall::syscall2(syscall::SYS_MUNMAP, addr, len) <= usize::MAX - 4095 }
}

unsafe fn madvise_dontneed(addr: usize, len: usize) {
    unsafe { syscall::syscall3(syscall::SYS_MADVISE, addr, len, MADV_DONTNEED) };
}

unsafe fn mremap_maymove(addr: usize, old: usize, new: usize) -> Option<*mut u8> {
    let r = unsafe { syscall::syscall4(syscall::SYS_MREMAP, addr, old, new, MREMAP_MAYMOVE) };
    if r <= usize::MAX - 4095 { Some(r as *mut u8) } else { None }
}

fn map_anon(len: usize) -> *mut u8 {
    map_anon_flags(len, 0)
}

fn map_anon_flags(len: usize, flags: usize) -> *mut u8 {
    mmap_new(len, PROT_READ | PROT_WRITE, flags)
}

fn mmap_new(len: usize, prot: usize, flags: usize) -> *mut u8 {
    let r = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | flags, usize::MAX, 0) };
    if r > usize::MAX - 4095 { null_mut() } else { r as *mut u8 }
}

#[cold]
fn mmap_chunk(s: &mut State, size: usize) -> *mut u8 {
    if P.n_mmaps.load(Relaxed) >= P.mmap_max.load(Relaxed) {
        return null_mut();
    }
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
    unsafe { wr(m, 0, 0) };
    unsafe { wr(m, 8, len | IS_MMAPPED) };
    count_add(&P.n_mmaps, 1);
    let now = count_add(&P.mmapped_mem, len);
    count_max(&P.max_mmapped_mem, now);
    s.last_fresh = true;
    chunk2mem(m)
}

unsafe fn munmap_chunk(c: *mut u8) {
    let off = unsafe { rd(c, 0) };
    let len = unsafe { csize(c) };
    let base = c.wrapping_sub(off);
    count_add(&P.n_mmaps, usize::MAX);
    count_add(&P.mmapped_mem, len.wrapping_neg());
    if !unsafe { munmap(base as usize, len + off) } {
        fatal("munmap_chunk(): invalid pointer");
    }
}

#[inline(never)]
fn set_enomem() {
    errno::set(ENOMEM);
}

#[inline(always)]
unsafe fn take_small(s: &mut State, i: usize, c: *mut u8, size: usize) {
    s.small[i] = unsafe { sl_get(c) };
    unsafe { wr(c, 24, 0) };
    s.small_bytes = s.small_bytes.wrapping_sub(size);
    s.last_fresh = false;
}

#[inline(always)]
unsafe fn push_small(s: &mut State, c: *mut u8, size: usize) {
    let i = size >> 4;
    unsafe { sl_set(c, s.small[i]) };
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
        let i = size >> 4;
        let c = s.small[i];
        if !c.is_null() {
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
    core::hint::black_box(null_mut())
}

#[inline(never)]
fn malloc_slow(s: &mut State, size: usize, fill: usize) -> *mut u8 {
    if !s.init {
        s.init();
    }
    let pert = if fill != 0 { perturb() } else { 0 };
    if size <= SMALL_MAX {
        let i = size >> 4;
        let c = s.small[i];
        if !c.is_null() {
            unsafe { take_small(s, i, c, size) };
            if lists_are_tcache() {
                return chunk2mem(c);
            }
            return unsafe { perturb_alloc(pert, chunk2mem(c), fill) };
        }
    }
    let c = alloc_chunk(s, size);
    if c.is_null() {
        set_enomem();
        return null_mut();
    }
    unsafe { perturb_alloc(pert, chunk2mem(c), fill) }
}

#[inline(always)]
unsafe fn perturb_alloc(pert: u8, m: *mut u8, n: usize) -> *mut u8 {
    if pert != 0 {
        unsafe { rusty_libc_mem::memset(m.cast(), i32::from(pert ^ 0xff), n) };
    }
    m
}

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

#[inline]
unsafe fn free_nl(s: &mut State, p: *mut u8) {
    if p.is_null() {
        return;
    }
    let c = mem2chunk(p);
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    if head & (IS_MMAPPED | NON_MAIN_ARENA) == s.abit
        && (MINSIZE..=SMALL_MAX).contains(&size)
        && size & 15 == 0
        && (p as usize) & 15 == 0
        && perturb() == 0
        && small_enabled()
        && unsafe { rd(c, 24) } != key()
    {
        unsafe { push_small(s, c, size) };
        return;
    }
    unsafe { free_slow(s, p) }
}

#[inline(never)]
unsafe fn free_slow(s: &mut State, p: *mut u8) {
    if p.is_null() {
        return;
    }
    if (p as usize) & 15 != 0 {
        fatal("free(): invalid pointer");
    }
    let c = mem2chunk(p);
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED != 0 {
        return unsafe { free_mmapped(c, size) };
    }
    if head & NON_MAIN_ARENA != s.abit {
        return unsafe { free_foreign(p) };
    }
    if size < MINSIZE || size & 15 != 0 {
        fatal("free(): invalid size");
    }
    let marked = unsafe { rd(c, 24) } == key();
    let pert = perturb();
    let to_lists = pert == 0 || unsafe { free_perturb(s, p, size, pert) };
    if marked && small_enabled() {
        for list in s.small.iter() {
            let mut q = *list;
            while !q.is_null() {
                if q == c {
                    fatal("free(): double free detected in tcache 2");
                }
                q = unsafe { sl_get(q) };
            }
        }
    }
    if size <= SMALL_MAX && small_enabled() && to_lists {
        unsafe { push_small(s, c, size) };
        return;
    }
    let next = at(c, size);
    if next != s.top && unsafe { rd(next, 8) } & PREV_INUSE == 0 {
        fatal("double free or corruption (!prev)");
    }
    unsafe { s.free_merge(c, size) };
    if size >= CONSOLIDATE_THRESHOLD {
        s.consolidate();
        s.trim_top(P.trim_threshold.load(Relaxed), P.top_pad.load(Relaxed));
    }
}

#[inline(always)]
unsafe fn free_mmapped(c: *mut u8, size: usize) {
    if P.dynamic_thresholds.load(Relaxed) && size > P.mmap_threshold.load(Relaxed) && size <= MMAP_THRESHOLD_MAX {
        P.mmap_threshold.store(size, Relaxed);
        P.trim_threshold.store(2 * size, Relaxed);
    }
    unsafe { munmap_chunk(c) };
}

#[inline(never)]
unsafe fn free_mmapped_block(p: *mut u8, size: usize) {
    if (p as usize) & 15 != 0 {
        fatal("free(): invalid pointer");
    }
    unsafe { free_mmapped(mem2chunk(p), size) }
}

#[cold]
#[inline(never)]
unsafe fn free_perturb(s: &mut State, p: *mut u8, size: usize, pert: u8) -> bool {
    let tc = lists_are_tcache();
    let as_tcache = tc
        && small_enabled()
        && size <= P.tcache_max.load(Relaxed)
        && unsafe { list_shorter_than(s.small[size >> 4], P.tcache_count.load(Relaxed)) };
    if !as_tcache {
        unsafe { rusty_libc_mem::memset(p.cast(), i32::from(pert), size - 2 * SIZE_SZ) };
    }
    !tc || as_tcache
}

#[inline]
fn lists_are_tcache() -> bool {
    no_cache(TCACHE.get())
}

unsafe fn list_shorter_than(mut c: *mut u8, n: usize) -> bool {
    for _ in 0..n {
        if c.is_null() {
            return true;
        }
        c = unsafe { sl_get(c) };
    }
    false
}

unsafe fn usable_size_nl(p: *mut u8) -> usize {
    if p.is_null() {
        return 0;
    }
    let head = unsafe { rd(mem2chunk(p), 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED != 0 { size - 16 } else { size - SIZE_SZ }
}

#[inline(always)]
unsafe fn clear_block(p: *mut u8, total: usize) -> *mut u8 {
    if total <= 24 {
        let w = p as *mut [u64; 3];
        unsafe { w.write([0; 3]) };
        return p;
    }
    if total <= 128 {
        return unsafe { clear_small(p, total) };
    }
    unsafe { clear_big(p, total) }
}

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
            unsafe { take_small(s, i, c, size) };
            return unsafe { clear_block(chunk2mem(c), total) };
        }
    }
    calloc_full(s, n, m)
}

#[inline(always)]
unsafe fn clear_small(p: *mut u8, total: usize) -> *mut u8 {
    use core::arch::x86_64::{__m128i, _mm_setzero_si128, _mm_storeu_si128};
    let z = unsafe { _mm_setzero_si128() };
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

#[inline(always)]
unsafe fn clear_big(p: *mut u8, total: usize) -> *mut u8 {
    unsafe { rusty_libc_mem::memset(p.cast(), 0, total).cast() }
}

fn calloc_full(s: &mut State, n: usize, m: usize) -> *mut u8 {
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
        unsafe { clear_block_full(p, total) };
    }
    p
}

#[inline(always)]
unsafe fn clear_block_full(p: *mut u8, total: usize) {
    if total <= 24 {
        let w = p as *mut [u64; 3];
        unsafe { w.write([0; 3]) };
    } else if total <= 128 {
        unsafe { clear_small(p, total) };
    } else {
        unsafe { rusty_libc_mem::memset(p.cast(), 0, total) };
    }
}

unsafe fn realloc_nl(s: &mut State, p: *mut u8, n: usize) -> *mut u8 {
    if p.is_null() {
        return malloc_nl(s, n);
    }
    if n == 0 {
        unsafe { free_nl(s, p) };
        return null_mut();
    }
    let Some(size) = request2size(n) else {
        set_enomem();
        return null_mut();
    };
    let c = mem2chunk(p);
    let head = unsafe { rd(c, 8) };
    if head & IS_MMAPPED == 0 && head & NON_MAIN_ARENA != s.abit {
        return unsafe { realloc_foreign(p, n) };
    }
    let old = head & !FLAGS;
    if (p as usize) & 15 != 0 || old < MINSIZE {
        fatal("realloc(): invalid pointer");
    }
    if head & IS_MMAPPED != 0 {
        let off = unsafe { rd(c, 0) };
        if old - 16 >= n && old - 16 < n + 2 * PAGE {
            return p;
        }
        let new_len = (size + 8 + PAGE - 1) & !(PAGE - 1);
        if off == 0 {
            if let Some(nc) = unsafe { mremap_maymove(c as usize, old, new_len) } {
                let now = count_add(&P.mmapped_mem, new_len.wrapping_sub(old));
                count_max(&P.max_mmapped_mem, now);
                unsafe { wr(nc, 8, new_len | IS_MMAPPED) };
                return chunk2mem(nc);
            }
        }
        return unsafe { move_block(s, p, old - 16, n) };
    }
    if size <= old {
        let rem = old - size;
        if rem >= MINSIZE {
            unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
            let r = at(c, size);
            unsafe { wr(r, 8, rem | PREV_INUSE | s.abit) };
            unsafe { free_nl(s, chunk2mem(r)) };
        }
        return p;
    }
    let next = at(c, old);
    if next == s.top {
        let ts = s.top_size();
        if ts + old >= size + MINSIZE {
            unsafe { grow_into_top(s, c, old, size, head) };
            return p;
        }
        if size < P.mmap_threshold.load(Relaxed) && grow_top_for(s, c, old, size) {
            unsafe { grow_into_top(s, c, old, size, head) };
            return p;
        }
    } else {
        let nsize = unsafe { csize(next) };
        if unsafe { rd(at(next, nsize), 8) } & PREV_INUSE == 0 && old + nsize >= size {
            unsafe { s.unlink(next, nsize) };
            let total = old + nsize;
            let rem = total - size;
            if rem >= MINSIZE {
                unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
                let r = at(c, size);
                unsafe { wr(r, 8, rem | PREV_INUSE | s.abit) };
                let after = at(r, rem);
                unsafe { wr(after, 0, rem) };
                unsafe { clear_prev_inuse(after) };
                unsafe { s.link_bin(r, rem) };
            } else {
                unsafe { wr(c, 8, total | (head & PREV_INUSE) | s.abit) };
                unsafe { or_head(at(c, total), PREV_INUSE | s.abit) };
            }
            return p;
        }
    }
    unsafe { move_block(s, p, old - SIZE_SZ, n) }
}

#[inline(always)]
unsafe fn clear_prev_inuse(c: *mut u8) {
    let h = unsafe { rd(c, 8) };
    unsafe { wr(c, 8, h & !PREV_INUSE) };
}

#[inline(always)]
unsafe fn or_head(c: *mut u8, bits: usize) {
    let h = unsafe { rd(c, 8) };
    unsafe { wr(c, 8, h | bits) };
}

#[inline(always)]
unsafe fn grow_into_top(s: &mut State, c: *mut u8, old: usize, size: usize, head: usize) {
    let ts = s.top_size();
    let nt = at(c, size);
    unsafe { wr(c, 8, size | (head & PREV_INUSE) | s.abit) };
    unsafe { wr(nt, 8, (ts + old - size) | PREV_INUSE | s.abit) };
    s.top = nt;
    let end = c as usize + size;
    if end > s.high_water {
        s.high_water = end;
    }
}

#[cold]
#[inline(never)]
fn grow_top_for(s: &mut State, c: *mut u8, old: usize, size: usize) -> bool {
    s.grow(size - old) && at(c, old) == s.top && s.top_size() + old >= size + MINSIZE
}

unsafe fn move_block(s: &mut State, p: *mut u8, old_usable: usize, n: usize) -> *mut u8 {
    let q = malloc_nl(s, n);
    if q.is_null() {
        return q;
    }
    unsafe { rusty_libc_mem::memcpy(q.cast(), p.cast(), old_usable.min(n)) };
    unsafe { free_nl(s, p) };
    q
}

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
    for _ in 0..16 {
        if c.is_null() {
            break;
        }
        if (chunk2mem(c) as usize) & (align - 1) == 0 {
            let next = unsafe { sl_get(c) };
            if prev.is_null() {
                s.small[i] = next;
            } else {
                unsafe { sl_set(prev, next) };
            }
            unsafe { wr(c, 24, 0) };
            s.small_bytes = s.small_bytes.wrapping_sub(size);
            let pert = perturb();
            if pert == 0 || lists_are_tcache() {
                return chunk2mem(c);
            }
            return unsafe { perturb_alloc(pert, chunk2mem(c), size - SIZE_SZ) };
        }
        prev = c;
        c = unsafe { sl_get(c) };
    }
    null_mut()
}

fn memalign_nl(s: &mut State, align: usize, n: usize) -> *mut u8 {
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
    let mut c = mem2chunk(m);
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
            let off = unsafe { rd(c, 0) };
            unsafe { wr(nc, 0, off + lead) };
            unsafe { wr(nc, 8, (total - lead) | IS_MMAPPED) };
            return am as *mut u8;
        }
        unsafe { wr(c, 8, lead | (head & PREV_INUSE) | s.abit) };
        unsafe { wr(nc, 8, (total - lead) | PREV_INUSE | s.abit) };
        let lead_chunk = c;
        c = nc;
        total -= lead;
        unsafe { s.free_merge(lead_chunk, lead) };
    } else if head & IS_MMAPPED != 0 {
        return m;
    }
    if total - size >= MINSIZE {
        let h = unsafe { rd(c, 8) };
        unsafe { wr(c, 8, size | (h & PREV_INUSE) | s.abit) };
        let r = at(c, size);
        unsafe { wr(r, 8, (total - size) | PREV_INUSE | s.abit) };
        unsafe { s.free_merge(r, total - size) };
    }
    chunk2mem(c)
}

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
            free_bytes += unsafe { csize(c) };
            c = unsafe { rd(c, 16) } as *mut u8;
        }
    }
    let mut small_chunks = 0;
    let mut small_bytes = 0;
    for &head in s.small.iter() {
        let mut c = head;
        while !c.is_null() {
            small_chunks += 1;
            small_bytes += unsafe { csize(c) };
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
            let size = unsafe { csize(c) };
            let lo = (c as usize + 32 + PAGE - 1) & !(PAGE - 1);
            let hi = (c as usize + size - 8) & !(PAGE - 1);
            if hi > lo && hi - lo >= PAGE {
                unsafe { madvise_dontneed(lo, hi - lo) };
                released = 1;
            }
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


#[thread_local]
static THREAD_ARENA: Cell<*mut ArenaCell> = Cell::new(null_mut());
#[thread_local]
static TCACHE: Cell<*mut TCache> = Cell::new(&raw const EMPTY as *mut TCache);
static EMPTY: TCache = TCache { room: [0; NSMALL], entries: [null_mut(); NSMALL] };
unsafe impl Sync for TCache {}

#[inline(always)]
fn no_cache(t: *mut TCache) -> bool {
    core::ptr::eq(t, &EMPTY)
}
#[thread_local]
static TCACHE_DONE: Cell<bool> = Cell::new(false);
static NARENAS_LIMIT: AtomicUsize = AtomicUsize::new(0);

const HEAP_HDR: usize = (core::mem::size_of::<HeapInfo>() + 15) & !15;

#[inline(always)]
unsafe fn arena_for_chunk(c: *mut u8) -> *mut ArenaCell {
    if unsafe { rd(c, 8) } & NON_MAIN_ARENA == 0 {
        main_ptr()
    } else {
        unsafe { (*((c as usize & !(HEAP_MAX - 1)) as *mut HeapInfo)).arena }
    }
}

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
    let extra = if flags != 0 { flags } else { MAP_NORESERVE };
    let r = mmap_new(2 * HEAP_MAX, PROT_NONE, extra);
    if r.is_null() {
        return None;
    }
    let r = r as usize;
    let start = (r + HEAP_MAX - 1) & !(HEAP_MAX - 1);
    if start > r {
        unsafe { munmap(r, start - r) };
    }
    let end = r + 2 * HEAP_MAX;
    if end > start + HEAP_MAX {
        unsafe { munmap(start + HEAP_MAX, end - (start + HEAP_MAX)) };
    }
    if !unsafe { mprotect_rw(start, first) } {
        unsafe { munmap(start, HEAP_MAX) };
        return None;
    }
    madvise_thp(start, first);
    let h = start as *mut HeapInfo;
    unsafe { h.write(HeapInfo { arena: null_mut(), prev: null_mut(), committed: first, pagesize }) };
    Some(unsafe { &mut *h })
}

fn new_arena(id: usize) -> *mut ArenaCell {
    let st_off = HEAP_HDR;
    let top_off = (st_off + core::mem::size_of::<ArenaCell>() + 15) & !15;
    let Some(h) = new_heap(top_off + MINSIZE, P.top_pad.load(Relaxed)) else {
        return null_mut();
    };
    let first = h.committed;
    let hp = h as *mut HeapInfo;
    let a = at(hp.cast(), st_off) as *mut ArenaCell;
    unsafe { a.write(ArenaCell::new(State::empty())) };
    let cell = unsafe { &*a };
    let s = unsafe { &mut *cell.state.as_ptr() };
    s.abit = NON_MAIN_ARENA;
    s.top_is_brk = false;
    s.heap = hp;
    s.id = id;
    unsafe { (*hp).arena = a };
    s.add_system(first);
    s.init();
    let top = at(hp.cast(), top_off);
    s.top = top;
    unsafe { wr(top, 8, (first - top_off) | PREV_INUSE | NON_MAIN_ARENA) };
    a
}

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
    let hp = P.hp_pagesize.load(Relaxed);
    if hp > 0 && hp <= HEAP_MAX {
        if threshold_set.is_none() {
            P.mmap_threshold.store(hp, Relaxed);
            P.dynamic_thresholds.store(false, Relaxed);
        }
        main.top_is_brk = false;
    }
}

fn tcache_bin_exists(nb: usize) -> bool {
    const SMALL_BINS: usize = 64;
    let idx = (nb - MINSIZE) / 16;
    idx < SMALL_BINS || SMALL_BINS + 21 - ((nb as u32).leading_zeros() as usize) < SMALL_BINS + 12
}

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

fn madvise_thp(p: usize, size: usize) {
    const MADV_HUGEPAGE: usize = 14;
    let thp = P.thp_pagesize.load(Relaxed);
    if !P.thp_madvise.load(Relaxed) || size < thp {
        return;
    }
    let q = (p + PAGE - 1) & !(PAGE - 1);
    unsafe { syscall::syscall3(syscall::SYS_MADVISE, q, size - (q - p), MADV_HUGEPAGE) };
}

fn open_cloexec(path: &core::ffi::CStr, flags: usize) -> Option<i32> {
    let fd = unsafe { syscall::syscall4(syscall::SYS_OPENAT, -100isize as usize, path.as_ptr() as usize, flags | 0o2000000, 0) };
    if fd > usize::MAX - 4095 { None } else { Some(fd as i32) }
}

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

#[cold]
#[inline(never)]
fn nprocs() -> usize {
    rusty_libc_rs_core::cpus::online() as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Arena(*mut ArenaCell);

impl Arena {
    #[inline(always)]
    fn main() -> Arena {
        Arena(main_ptr())
    }

    #[inline(always)]
    fn cell(self) -> &'static ArenaCell {
        unsafe { &*self.0 }
    }

    #[inline(always)]
    fn lock(self) -> &'static rusty_libc_core::lock::RawMutex {
        &self.cell().lock
    }

    #[inline]
    fn next(self) -> Arena {
        let n = self.cell().next.load(Acquire);
        if n.is_null() { Arena::main() } else { Arena(n) }
    }

    #[inline(always)]
    fn state(self) -> *mut State {
        self.cell().state.as_ptr()
    }

    #[inline(always)]
    fn locked<R>(self, f: impl FnOnce(&mut State) -> R) -> R {
        let l = self.lock();
        l.lock_always();
        let r = f(unsafe { &mut *self.state() });
        l.unlock_always();
        r
    }

    #[inline(always)]
    fn with<R>(self, f: impl FnOnce(&mut State) -> R) -> R {
        let l = self.lock();
        let taken = l.lock();
        let r = f(unsafe { &mut *self.state() });
        l.unlock(taken);
        r
    }

    #[inline(always)]
    fn is_main(self) -> bool {
        core::ptr::eq(self.0, main_ptr())
    }
}

#[inline(always)]
fn thread_arena() -> Arena {
    let a = THREAD_ARENA.get();
    if !a.is_null() { Arena(a) } else { choose_arena() }
}

#[cold]
#[inline(never)]
fn choose_arena() -> Arena {
    let main = Arena::main();
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
            return main;
        }
    }
    ARENA_LIST.lock_always();
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
        let a = new_arena(n);
        if !a.is_null() {
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

fn reuse_arena() -> Arena {
    let start = NEXT_TO_USE.load(Relaxed);
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

#[repr(C)]
struct TCache {
    room: [u16; NSMALL],
    entries: [*mut u8; NSMALL],
}

#[inline(always)]
fn entry_slot(t: *mut TCache, i: usize) -> *mut *mut u8 {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(TCache, entries)).cast::<*mut u8>().wrapping_add(i)
}

#[inline(always)]
fn room_slot(t: *mut TCache, i: usize) -> *mut u16 {
    t.cast::<u8>().wrapping_add(core::mem::offset_of!(TCache, room)).cast::<u16>().wrapping_add(i)
}

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
    let max = P.tcache_max.load(Relaxed);
    let mut room = [0u16; NSMALL];
    for (i, r) in room.iter_mut().enumerate() {
        *r = if i * 16 <= max { n } else { 0 };
    }
    unsafe { t.write(TCache { room, entries: [null_mut(); NSMALL] }) };
    TCACHE.set(t);
    t
}

#[inline(never)]
unsafe fn free_to_arena(p: *mut u8) {
    let c = mem2chunk(p);
    let a = Arena(unsafe { arena_for_chunk(c) });
    a.locked(|s| {
        let head = unsafe { rd(c, 8) };
        let size = head & !FLAGS;
        if head & IS_MMAPPED == 0 && (MINSIZE..=SMALL_MAX).contains(&size) && size & 15 == 0 {
            unsafe { wr(at(c, size), 0, size) };
        }
        unsafe { free_nl(s, p) };
    });
}

pub unsafe fn thread_shutdown() {
    let t = TCACHE.replace(&raw const EMPTY as *mut TCache);
    TCACHE_DONE.set(true);
    if !no_cache(t) {
        for i in 0..NSMALL {
            let mut c = unsafe { *entry_slot(t, i) };
            while !c.is_null() {
                let next = unsafe { sl_get(c) };
                unsafe { wr(c, 24, 0) };
                unsafe { free_to_arena(chunk2mem(c)) };
                c = next;
            }
        }
        unsafe { free_to_arena(t as *mut u8) };
    }
    let a = THREAD_ARENA.replace(null_mut());
    if !a.is_null() {
        ARENA_LIST.lock_always();
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

#[inline(always)]
pub fn malloc(n: usize) -> *mut u8 {
    if core::hint::likely(no_cache(TCACHE.get()) && !rusty_libc_core::lock::multithreaded()) {
        if n <= SMALL_MAX - SIZE_SZ && perturb() == 0 {
            let s = unsafe { st() };
            let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
            let e = s.small.as_mut_ptr().wrapping_add(size >> 4);
            let c = unsafe { *e };
            if !c.is_null() {
                let next = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
                if next & 15 != 0 {
                    return bad_list();
                }
                unsafe { *e = next as *mut u8 };
                unsafe { wr(c, 24, 0) };
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                s.last_fresh = false;
                return chunk2mem(c);
            }
        }
        let Some(size) = request2size(n) else {
            return malloc_toobig();
        };
        return malloc_slow(unsafe { st() }, size, n);
    }
    malloc_mt(n)
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
fn malloc_mt(n: usize) -> *mut u8 {
    let t = TCACHE.get();
    if n <= SMALL_MAX - SIZE_SZ {
        let size = ((n + SIZE_SZ + 15) & !15).max(MINSIZE);
        let i = size >> 4;
        let e = entry_slot(t, i);
        let c = unsafe { *e };
        if !c.is_null() {
            let next = unsafe { rd(c, 16) } ^ ((c as usize + 16) >> 12);
            if next & 15 != 0 {
                return bad_list();
            }
            unsafe { *e = next as *mut u8 };
            unsafe { *room_slot(t, i) += 1 };
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
            let c = unsafe { *entry_slot(t, i) };
            if !c.is_null() {
                let next = unsafe { sl_get(c) };
                unsafe { *entry_slot(t, i) = next };
                unsafe { *room_slot(t, i) += 1 };
                unsafe { wr(c, 24, 0) };
                return chunk2mem(c);
            }
            return unsafe { malloc_refill(t, i, n) };
        }
    }
    malloc_arena(n)
}

#[inline(never)]
unsafe fn malloc_refill(t: *mut TCache, i: usize, n: usize) -> *mut u8 {
    let a = thread_arena();
    let p = a.locked(|s| {
        let p = malloc_nl(s, n);
        if !p.is_null() && small_enabled() {
            let keep_free = P.tcache_count.load(Relaxed).div_ceil(2);
            let size = i << 4;
            let room = room_slot(t, i);
            let head = entry_slot(t, i);
            while (unsafe { *room } as usize) > keep_free {
                let c = s.small[i];
                if c.is_null() {
                    break;
                }
                s.small[i] = unsafe { sl_get(c) };
                s.small_bytes = s.small_bytes.wrapping_sub(size);
                let first = unsafe { *head };
                unsafe { sl_set(c, first) };
                unsafe { wr(c, 24, key()) };
                unsafe { *head = c };
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
    if p.is_null() && !a.is_main() {
        return malloc_main(n);
    }
    p
}

#[cold]
fn malloc_main(n: usize) -> *mut u8 {
    Arena::main().locked(|m| malloc_nl(m, n))
}

#[inline(always)]
pub unsafe fn free(p: *mut u8) {
    if core::hint::likely(no_cache(TCACHE.get()) && !rusty_libc_core::lock::multithreaded()) {
        if !p.is_null() {
            let s = unsafe { st() };
            let c = mem2chunk(p);
            let head = unsafe { rd(c, 8) };
            let size = head & !FLAGS;
            let k = key();
            if head & (IS_MMAPPED | NON_MAIN_ARENA) == 0
                && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
                && (size | p as usize) & 15 == 0
                && unsafe { rd(c, 24) } != k
                && perturb() == 0
                && small_enabled()
            {
                let e = s.small.as_mut_ptr().wrapping_add(size >> 4);
                let first = unsafe { *e };
                unsafe { sl_set(c, first) };
                unsafe { wr(c, 24, k) };
                unsafe { *e = c };
                s.small_bytes += size;
                if s.small_bytes > SMALL_BYTES_MAX {
                    return consolidate_main();
                }
                return;
            }
        }
        let s = unsafe { st() };
        return unsafe { free_slow(s, p) };
    }
    unsafe { free_mt(p) }
}

#[cold]
#[inline(never)]
fn consolidate_main() {
    unsafe { st() }.consolidate()
}

#[inline(always)]
unsafe fn free_mt(p: *mut u8) {
    let t = TCACHE.get();
    if !p.is_null() {
        let c = mem2chunk(p);
        let head = unsafe { rd(c, 8) };
        let size = head & !FLAGS;
        let k = key();
        if head & IS_MMAPPED == 0
            && size.wrapping_sub(MINSIZE) <= SMALL_MAX - MINSIZE
            && (size | p as usize) & 15 == 0
            && unsafe { rd(c, 24) } != k
        {
            let i = size >> 4;
            let r = room_slot(t, i);
            if unsafe { *r } != 0 {
                let e = entry_slot(t, i);
                let first = unsafe { *e };
                unsafe { sl_set(c, first) };
                unsafe { wr(c, 24, k) };
                unsafe { *e = c };
                unsafe { *r -= 1 };
                return;
            }
        }
    }
    unsafe { free_mt_slow(p) }
}

#[inline(never)]
unsafe fn free_mt_slow(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let c = mem2chunk(p);
    let head = unsafe { rd(c, 8) };
    let size = head & !FLAGS;
    if head & IS_MMAPPED == 0 && (MINSIZE..=SMALL_MAX).contains(&size) && size & 15 == 0 && (p as usize) & 15 == 0 {
        let t = tcache();
        if !t.is_null() {
            let i = size >> 4;
            let k = key();
            if unsafe { rd(c, 24) } == k {
                let mut q = unsafe { *entry_slot(t, i) };
                while !q.is_null() {
                    if q == c {
                        fatal("free(): double free detected in tcache 2");
                    }
                    q = unsafe { sl_get(q) };
                }
            }
            if unsafe { *room_slot(t, i) } != 0 {
                let first = unsafe { *entry_slot(t, i) };
                unsafe { sl_set(c, first) };
                unsafe { wr(c, 24, k) };
                unsafe { *entry_slot(t, i) = c };
                unsafe { *room_slot(t, i) -= 1 };
                return;
            }
        }
    }
    if head & IS_MMAPPED != 0 {
        return unsafe { free_mmapped_block(p, size) };
    }
    unsafe { free_to_arena(p) }
}

#[cold]
#[inline(never)]
unsafe fn free_foreign(p: *mut u8) {
    unsafe { free_to_arena(p) }
}

#[cold]
#[inline(never)]
unsafe fn realloc_foreign(p: *mut u8, n: usize) -> *mut u8 {
    let a = Arena(unsafe { arena_for_chunk(mem2chunk(p)) });
    a.locked(|s| unsafe { realloc_nl(s, p, n) })
}

pub unsafe fn usable_size(p: *mut u8) -> usize {
    unsafe { usable_size_nl(p) }
}

#[inline]
pub fn calloc(n: usize, m: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
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

#[inline]
pub unsafe fn realloc(p: *mut u8, n: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
        let s = unsafe { st() };
        return unsafe { realloc_nl(s, p, n) };
    }
    unsafe { realloc_mt(p, n) }
}

#[inline(never)]
unsafe fn realloc_mt(p: *mut u8, n: usize) -> *mut u8 {
    if p.is_null() {
        return malloc_mt(n);
    }
    if n == 0 {
        unsafe { free_mt(p) };
        return null_mut();
    }
    let c = mem2chunk(p);
    let a = if unsafe { rd(c, 8) } & IS_MMAPPED != 0 {
        thread_arena()
    } else {
        Arena(unsafe { arena_for_chunk(c) })
    };
    a.locked(|s| unsafe { realloc_nl(s, p, n) })
}

#[inline(always)]
pub fn memalign(align: usize, n: usize) -> *mut u8 {
    if !rusty_libc_core::lock::multithreaded() {
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
    memalign_nl(unsafe { st() }, align, n)
}

#[inline(never)]
fn memalign_mt(align: usize, n: usize) -> *mut u8 {
    if align > 16
        && let Some(size) = request2size(n)
        && size <= SMALL_MAX
    {
        let t = tcache();
        if !t.is_null() {
            let i = size >> 4;
            let head = entry_slot(t, i);
            let mut link: *mut *mut u8 = head;
            let mut c = unsafe { *link };
            while !c.is_null() {
                let next = unsafe { sl_get(c) };
                if (chunk2mem(c) as usize) & (align - 1) == 0 {
                    if core::ptr::eq(link, head) {
                        unsafe { *link = next };
                    } else {
                        unsafe { sl_set(link.cast::<u8>().wrapping_sub(16), next) };
                    }
                    unsafe { *room_slot(t, i) += 1 };
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

pub fn arena_stats(a: Arena) -> Stats {
    a.with(stats_nl)
}

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

pub fn main_lock() -> &'static rusty_libc_core::lock::RawMutex {
    Arena::main().lock()
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
    arenas(|a| {
        let x = arena_stats(a);
        let (mut aspace, mut subheaps) = (0, 0);
        let (main, system_mem, max_system_mem) = a.with(|s| {
            if s.abit != 0 {
                let mut h = s.heap;
                while !h.is_null() {
                    let committed = unsafe { (*h).committed };
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

pub fn atfork_prepare() {
    ARENA_LIST.lock_always();
    arenas(|a| a.lock().lock_always());
}

pub fn atfork_parent() {
    arenas(|a| a.lock().unlock_always());
    ARENA_LIST.unlock_always();
}

pub fn atfork_child() {
    let mine = THREAD_ARENA.get();
    let mut free: *mut ArenaCell = null_mut();
    arenas(|a| {
        a.lock().unlock_always();
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

