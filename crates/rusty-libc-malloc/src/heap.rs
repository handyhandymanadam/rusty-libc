use core::cell::UnsafeCell;
use core::ptr::null_mut;
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
    pub mmap_threshold: usize,
    pub trim_threshold: usize,
    pub top_pad: usize,
    pub mmap_max: usize,
    pub dynamic_thresholds: bool,
    pub n_mmaps: usize,
    pub mmapped_mem: usize,
    pub max_mmapped_mem: usize,
    pub perturb: u8,
    pub small_enabled: bool,
    pub check_action: i32,
    pub arena_max: i32,
    pub arena_test: i32,
    key: usize,
    pub foreign_bytes: usize,
    small_bytes: usize,
    grow_first: bool,
}

pub static LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

struct Global(UnsafeCell<State>);
unsafe impl Sync for Global {}

static STATE: Global = Global(UnsafeCell::new(State {
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
    mmap_threshold: DEFAULT_MMAP_THRESHOLD,
    trim_threshold: DEFAULT_TRIM_THRESHOLD,
    top_pad: DEFAULT_TOP_PAD,
    mmap_max: MMAP_MAX_DEFAULT,
    dynamic_thresholds: true,
    n_mmaps: 0,
    mmapped_mem: 0,
    max_mmapped_mem: 0,
    perturb: 0,
    small_enabled: true,
    check_action: 3,
    arena_max: 0,
    arena_test: 8,
    key: 0,
    foreign_bytes: 0,
    small_bytes: 0,
    grow_first: false,
}));

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
        let brk = unsafe { syscall::syscall1(syscall::SYS_BRK, 0) };
        let start = (brk + 15) & !15;
        self.brk_start = start;
        self.brk_end = brk;
        let t = unsafe { core::arch::x86_64::_rdtsc() } as usize;
        self.key = (t ^ (brk >> 4)).rotate_left(17) | 1;
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
                wr(c, 8, size | PREV_INUSE);
                self.top = c;
                return;
            }
            let nsize = csize(next);
            if rd(next.add(nsize), 8) & PREV_INUSE == 0 {
                self.unlink(next, nsize);
                size += nsize;
            }
            wr(c, 8, size | PREV_INUSE);
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

    unsafe fn trim_top(&mut self) {
        unsafe {
            if !self.top_is_brk || self.top.is_null() {
                return;
            }
            let ts = csize(self.top);
            if ts < self.trim_threshold {
                return;
            }
            let extra = (ts.saturating_sub(self.top_pad + MINSIZE)) & !(PAGE - 1);
            if extra == 0 {
                return;
            }
            let want = self.brk_end - extra;
            let got = syscall::syscall1(syscall::SYS_BRK, want);
            if got == want {
                self.brk_end = want;
                wr(self.top, 8, (ts - extra) | PREV_INUSE);
            }
        }
    }

    unsafe fn split(&mut self, c: *mut u8, have: usize, size: usize) -> *mut u8 {
        unsafe {
            let rem = have - size;
            if rem >= MINSIZE {
                wr(c, 8, size | PREV_INUSE);
                let r = c.add(size);
                wr(r, 8, rem | PREV_INUSE);
                let after = r.add(rem);
                wr(r.add(rem), 0, rem);
                wr(after, 8, rd(after, 8) & !PREV_INUSE);
                self.link_bin(r, rem);
            } else {
                wr(c, 8, have | PREV_INUSE);
                let next = c.add(have);
                wr(next, 8, rd(next, 8) | PREV_INUSE);
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
            wr(c, 8, size | PREV_INUSE);
            let nt = c.add(size);
            wr(nt, 8, (ts - size) | PREV_INUSE);
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
            let ts = self.top_size();
            let need = size + MINSIZE;
            let ext = (need.saturating_sub(ts) + self.top_pad + PAGE - 1) & !(PAGE - 1);
            if self.top_is_brk {
                let want = self.brk_end + ext;
                if want > self.brk_end {
                    let got = syscall::syscall1(syscall::SYS_BRK, want);
                    if got == want {
                        if self.top.is_null() {
                            let start = (self.brk_end + 15) & !15;
                            self.top = start as *mut u8;
                            wr(self.top, 8, (want - start) | PREV_INUSE);
                            self.brk_start = start;
                        } else {
                            wr(self.top, 8, (ts + (want - self.brk_end)) | PREV_INUSE);
                        }
                        self.brk_end = want;
                        return true;
                    }
                }
            }
            let Some(len) = need.saturating_add(self.top_pad).max(ext).max(1 << 20).checked_add(PAGE - 1) else {
                return false;
            };
            let len = len & !(PAGE - 1);
            let m = map_anon(len);
            if m.is_null() {
                return false;
            }
            if !self.top.is_null() {
                let old = self.top;
                let os = csize(old);
                self.top = null_mut();
                if os >= MINSIZE + 32 {
                    let keep = os - 32;
                    wr(old, 8, keep | PREV_INUSE);
                    let f1 = old.add(keep);
                    wr(f1, 8, 16 | PREV_INUSE);
                    wr(f1, 16, 0);
                    wr(f1.add(16), 8, PREV_INUSE);
                    wr(old.add(keep), 0, 0);
                    self.free_merge(old, keep);
                } else if os >= 32 {
                    wr(old, 8, 16 | PREV_INUSE);
                    wr(old.add(16), 8, PREV_INUSE);
                }
            }
            self.top = m;
            self.top_is_brk = false;
            wr(m, 8, len | PREV_INUSE);
            self.foreign_bytes += len;
            true
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
        if s.n_mmaps >= s.mmap_max {
            return null_mut();
        }
        let len = (size + 8 + PAGE - 1) & !(PAGE - 1);
        let m = map_anon(len);
        if m.is_null() {
            return null_mut();
        }
        wr(m, 0, 0);
        wr(m, 8, len | IS_MMAPPED);
        s.n_mmaps += 1;
        s.mmapped_mem += len;
        if s.mmapped_mem > s.max_mmapped_mem {
            s.max_mmapped_mem = s.mmapped_mem;
        }
        s.last_fresh = true;
        chunk2mem(m)
    }
}

unsafe fn munmap_chunk(s: &mut State, c: *mut u8) {
    unsafe {
        let off = rd(c, 0);
        let len = csize(c);
        let base = c.sub(off);
        s.n_mmaps -= 1;
        s.mmapped_mem -= len;
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
unsafe fn malloc_nl(n: usize) -> *mut u8 {
    unsafe {
        let Some(size) = request2size(n) else {
            return malloc_toobig();
        };
        let s = st();
        if size <= SMALL_MAX && s.perturb == 0 {
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
        malloc_slow(size)
    }
}

#[cold]
#[inline(never)]
fn malloc_toobig() -> *mut u8 {
    set_enomem();
    null_mut()
}

#[inline(never)]
unsafe fn malloc_slow(size: usize) -> *mut u8 {
    unsafe {
        let s = st();
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
                return perturb_alloc(s, chunk2mem(c), size);
            }
        }
        let c = alloc_chunk(s, size);
        if c.is_null() {
            set_enomem();
            return null_mut();
        }
        perturb_alloc(s, chunk2mem(c), size)
    }
}

#[inline(always)]
unsafe fn perturb_alloc(s: &State, m: *mut u8, size: usize) -> *mut u8 {
    unsafe {
        if s.perturb != 0 {
            rusty_libc_mem::memset(m.cast(), i32::from(s.perturb ^ 0xff), size - SIZE_SZ);
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
        if size >= s.mmap_threshold {
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
unsafe fn free_nl(p: *mut u8) {
    unsafe {
        if p.is_null() {
            return;
        }
        let s = st();
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & IS_MMAPPED == 0
            && (MINSIZE..=SMALL_MAX).contains(&size)
            && size & 15 == 0
            && (p as usize) & 15 == 0
            && s.perturb == 0
            && s.small_enabled
            && rd(c, 24) != s.key
        {
            let i = size >> 4;
            sl_set(c, s.small[i]);
            wr(c, 24, s.key);
            s.small[i] = c;
            s.small_bytes += size;
            if s.small_bytes > SMALL_BYTES_MAX {
                s.consolidate();
            }
            return;
        }
        free_slow(p);
    }
}

#[inline(never)]
unsafe fn free_slow(p: *mut u8) {
    unsafe {
        if p.is_null() {
            return;
        }
        let s = st();
        if (p as usize) & 15 != 0 {
            fatal("free(): invalid pointer");
        }
        let c = mem2chunk(p);
        let head = rd(c, 8);
        let size = head & !FLAGS;
        if head & IS_MMAPPED != 0 {
            if s.dynamic_thresholds && size > s.mmap_threshold && size <= MMAP_THRESHOLD_MAX {
                s.mmap_threshold = size;
                s.trim_threshold = 2 * size;
            }
            munmap_chunk(s, c);
            return;
        }
        if size < MINSIZE || size & 15 != 0 {
            fatal("free(): invalid size");
        }
        let marked = rd(c, 24) == s.key;
        if s.perturb != 0 {
            rusty_libc_mem::memset(p.cast(), i32::from(s.perturb), size - SIZE_SZ);
        }
        if marked && s.small_enabled {
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
        if size <= SMALL_MAX && s.small_enabled {
            let i = size >> 4;
            sl_set(c, s.small[i]);
            wr(c, 24, s.key);
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
            s.trim_top();
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
unsafe fn calloc_nl(n: usize, m: usize) -> *mut u8 {
    unsafe {
        if let Some(total) = n.checked_mul(m) {
            let s = st();
            if s.perturb == 0
                && let Some(size) = request2size(total)
                && size <= SMALL_MAX
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
        calloc_full(n, m)
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

unsafe fn calloc_full(n: usize, m: usize) -> *mut u8 {
    unsafe {
        let Some(total) = n.checked_mul(m) else {
            set_enomem();
            return null_mut();
        };
        let s = st();
        let perturb = s.perturb;
        if perturb != 0 {
            s.perturb = 0;
        }
        let p = malloc_nl(total);
        let s = st();
        if perturb != 0 {
            s.perturb = perturb;
        }
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

unsafe fn realloc_nl(p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        if p.is_null() {
            return malloc_nl(n);
        }
        if n == 0 {
            free_nl(p);
            return null_mut();
        }
        let s = st();
        let Some(size) = request2size(n) else {
            set_enomem();
            return null_mut();
        };
        let c = mem2chunk(p);
        let head = rd(c, 8);
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
                    s.mmapped_mem = s.mmapped_mem - old + new_len;
                    if s.mmapped_mem > s.max_mmapped_mem {
                        s.max_mmapped_mem = s.mmapped_mem;
                    }
                    wr(nc, 8, new_len | IS_MMAPPED);
                    return chunk2mem(nc);
                }
            }
            return move_block(p, old - 16, n);
        }
        if size <= old {
            let rem = old - size;
            if rem >= MINSIZE {
                wr(c, 8, size | (head & PREV_INUSE));
                let r = c.add(size);
                wr(r, 8, rem | PREV_INUSE);
                free_nl(chunk2mem(r));
            }
            return p;
        }
        let next = c.add(old);
        if next == s.top {
            let ts = csize(next);
            if ts + old >= size + MINSIZE {
                let nt = c.add(size);
                wr(c, 8, size | (head & PREV_INUSE));
                wr(nt, 8, (ts + old - size) | PREV_INUSE);
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
                    wr(c, 8, size | (head & PREV_INUSE));
                    let r = c.add(size);
                    wr(r, 8, rem | PREV_INUSE);
                    wr(r.add(rem), 0, rem);
                    let after = r.add(rem);
                    wr(after, 8, rd(after, 8) & !PREV_INUSE);
                    s.link_bin(r, rem);
                } else {
                    wr(c, 8, total | (head & PREV_INUSE));
                    let after = c.add(total);
                    wr(after, 8, rd(after, 8) | PREV_INUSE);
                }
                return p;
            }
        }
        move_block(p, old - SIZE_SZ, n)
    }
}

unsafe fn move_block(p: *mut u8, old_usable: usize, n: usize) -> *mut u8 {
    unsafe {
        let q = malloc_nl(n);
        if q.is_null() {
            return q;
        }
        rusty_libc_mem::memcpy(q.cast(), p.cast(), old_usable.min(n));
        free_nl(p);
        q
    }
}

unsafe fn memalign_nl(align: usize, n: usize) -> *mut u8 {
    unsafe {
        if align <= 16 {
            return malloc_nl(n);
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
            let s = st();
            if size <= SMALL_MAX && s.small_enabled && s.init {
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
                        return perturb_alloc(s, chunk2mem(c), size);
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
        let s = st();
        s.grow_first = true;
        let m = malloc_nl(req);
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
            wr(c, 8, lead | (head & PREV_INUSE));
            wr(nc, 8, (total - lead) | PREV_INUSE);
            let lead_chunk = c;
            c = nc;
            total -= lead;
            s.free_merge(lead_chunk, lead);
        } else if head & IS_MMAPPED != 0 {
            return m;
        }
        if total - size >= MINSIZE {
            let h = rd(c, 8);
            wr(c, 8, size | (h & PREV_INUSE));
            let r = c.add(size);
            wr(r, 8, (total - size) | PREV_INUSE);
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

unsafe fn stats_nl() -> Stats {
    unsafe {
        let s = st();
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
            arena: (s.brk_end - s.brk_start) + s.foreign_bytes,
            free_chunks,
            small_chunks,
            small_bytes,
            free_bytes,
            top: s.top_size(),
        }
    }
}

unsafe fn trim_nl(pad: usize) -> i32 {
    unsafe {
        let s = st();
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
        let saved_pad = s.top_pad;
        s.top_pad = pad;
        let saved_thr = s.trim_threshold;
        s.trim_threshold = 0;
        s.trim_top();
        s.trim_threshold = saved_thr;
        s.top_pad = saved_pad;
        if s.top_size() < before {
            released = 1;
        }
        released
    }
}

unsafe fn ensure_init_nl() {
    unsafe {
        let s = st();
        if !s.init {
            s.init();
        }
    }
}


#[inline]
pub unsafe fn malloc(n: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return malloc_nl(n);
        }
        malloc_mt(n)
    }
}

#[inline(never)]
unsafe fn malloc_mt(n: usize) -> *mut u8 {
    let _g = LOCK.guard();
    unsafe { malloc_nl(n) }
}

#[inline]
pub unsafe fn free(p: *mut u8) {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return free_nl(p);
        }
        free_mt(p)
    }
}

#[inline(never)]
unsafe fn free_mt(p: *mut u8) {
    let _g = LOCK.guard();
    unsafe { free_nl(p) }
}

pub unsafe fn usable_size(p: *mut u8) -> usize {
    let _g = LOCK.guard();
    unsafe { usable_size_nl(p) }
}

#[inline]
pub unsafe fn calloc(n: usize, m: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return calloc_nl(n, m);
        }
        calloc_mt(n, m)
    }
}

#[inline(never)]
unsafe fn calloc_mt(n: usize, m: usize) -> *mut u8 {
    let _g = LOCK.guard();
    unsafe { calloc_nl(n, m) }
}

#[inline]
pub unsafe fn realloc(p: *mut u8, n: usize) -> *mut u8 {
    unsafe {
        if !rusty_libc_core::lock::multithreaded() {
            return realloc_nl(p, n);
        }
        realloc_mt(p, n)
    }
}

#[inline(never)]
unsafe fn realloc_mt(p: *mut u8, n: usize) -> *mut u8 {
    let _g = LOCK.guard();
    unsafe { realloc_nl(p, n) }
}

pub unsafe fn memalign(align: usize, n: usize) -> *mut u8 {
    let _g = LOCK.guard();
    unsafe { memalign_nl(align, n) }
}

pub unsafe fn stats() -> Stats {
    let _g = LOCK.guard();
    unsafe { stats_nl() }
}

pub unsafe fn trim(pad: usize) -> i32 {
    let _g = LOCK.guard();
    unsafe { trim_nl(pad) }
}

pub unsafe fn ensure_init() {
    let _g = LOCK.guard();
    unsafe { ensure_init_nl() }
}

pub fn atfork_prepare() {
    LOCK.lock_always();
}

pub fn atfork_parent() {
    LOCK.unlock_always();
}

pub fn atfork_child() {
    LOCK.unlock_always();
}
