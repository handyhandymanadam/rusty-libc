#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::sync_cell::SyncCell;
use crate::sys;
use core::fmt::Write;
use core::mem::MaybeUninit;

pub use crate::ffi::{cstr, cstr_eq, cstr_gnu_hash, streq};

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") d => _, inout("rsi") s => _, options(nostack, preserves_flags));
    }
    d
}

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    if (d as usize) <= (s as usize) || (d as usize) >= (s as usize) + n {
        return unsafe { memcpy(d, s, n) };
    }
    let mut i = n;
    while i > 0 {
        i -= 1;
        let c = unsafe { *s.wrapping_add(i) };
        unsafe { *d.wrapping_add(i) = c };
    }
    d
}

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") d => _, in("al") c as u8, options(nostack, preserves_flags));
    }
    d
}

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let x = unsafe { *a.wrapping_add(i) };
        let y = unsafe { *b.wrapping_add(i) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { memcmp(a, b, n) }
}

#[allow(suspicious_runtime_symbol_definitions)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    unsafe { crate::ffi::cstr_len(s) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        let x = unsafe { *a.wrapping_add(i) };
        let y = unsafe { *b.wrapping_add(i) };
        if x != y || x == 0 {
            return x as i32 - y as i32;
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *const u8 {
    let c = c as u8;
    let mut p = s;
    loop {
        let x = unsafe { *p };
        if x == c {
            return p;
        }
        if x == 0 {
            return core::ptr::null();
        }
        p = unsafe { p.add(1) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn index(s: *const u8, c: i32) -> *const u8 {
    unsafe { strchr(s, c) }
}

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

    fn storage(&mut self) -> &mut [MaybeUninit<u8>] {
        let (p, cap) = (self.base() as *mut MaybeUninit<u8>, self.cap);
        unsafe { crate::ffi::slice_mut(p, cap) }
    }

    pub fn reserve(&mut self, need: usize) {
        if need > self.cap {
            let nb = alloc_perm(need + 64, 1);
            let len = self.len;
            let old = self.base();
            unsafe { core::ptr::copy_nonoverlapping(old, nb, len) };
            self.big = nb;
            self.cap = need + 64;
        }
    }

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

    pub fn bytes(&mut self) -> &[u8] {
        let len = self.len;
        let p = self.base() as *const u8;
        unsafe { crate::ffi::slice(p, len) }
    }

    pub fn as_cstr(&mut self) -> &core::ffi::CStr {
        if self.len + 1 > self.cap {
            self.reserve(self.len + 1);
        }
        let i = self.len;
        self.storage()[i] = MaybeUninit::new(0);
        let len = self.len;
        let p = self.base() as *const u8;
        let with_nul = unsafe { crate::ffi::slice(p, len + 1) };
        core::ffi::CStr::from_bytes_until_nul(with_nul).unwrap_or(c"")
    }

    pub fn as_ptr(&mut self) -> *const u8 {
        self.base()
    }

    pub fn readlink(&mut self, path: &core::ffi::CStr) -> isize {
        let (i, cap) = (self.len, self.cap);
        let n = sys::readlink(path, &mut self.storage()[i..cap - 1]);
        if n > 0 {
            self.len += n as usize;
        }
        n
    }
}

pub fn dup(s: &[u8]) -> &'static core::ffi::CStr {
    let p = alloc_perm(s.len() + 1, 1);
    let d: &'static mut [u8] = unsafe { crate::ffi::slice_mut(p, s.len() + 1) };
    d[..s.len()].copy_from_slice(s);
    d[s.len()] = 0;
    let d: &'static [u8] = d;
    core::ffi::CStr::from_bytes_until_nul(d).unwrap_or(c"")
}

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

#[macro_export]
macro_rules! eprint {
    ($($t:tt)*) => {{
        use core::fmt::Write as _;
        let mut o = $crate::util::Out::new(2);
        let _ = write!(o, $($t)*);
    }};
}

pub struct Bytes<'a>(pub &'a [u8]);
impl core::fmt::Display for Bytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &c in self.0 {
            f.write_char(if c.is_ascii_graphic() || c == b' ' { c as char } else { '?' })?;
        }
        Ok(())
    }
}

static ALLOC_LOCK: Lock = Lock::new();

pub(crate) fn fork_child_reset() {
    ALLOC_LOCK.reset();
}
const CHUNK: usize = 256 * 1024;
const ARENA: usize = 64 * 1024;

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

fn with_heap<R>(f: impl FnOnce(&mut Heap) -> R) -> R {
    ALLOC_LOCK.lock();
    let r = unsafe { HEAP.with_unsync(f) };
    ALLOC_LOCK.unlock();
    r
}

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
static RT_MALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_FREE: AtomicUsize = AtomicUsize::new(0);
static RT_CALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_ARMED: AtomicBool = AtomicBool::new(false);
static RT_TRIED: AtomicBool = AtomicBool::new(false);

pub fn rtld_malloc_arm() {
    RT_ARMED.store(true, Release);
}

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
    unsafe { crate::bind_rtld_malloc() };
    RT_CALLOC.load(Acquire)
}

type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut u8;
type MallocFn = unsafe extern "C" fn(usize) -> *mut u8;
type FreeFn = unsafe extern "C" fn(*mut u8);

fn ext_alloc(size: usize, zero: bool) -> *mut u8 {
    let p = if zero {
        let f: CallocFn = unsafe { core::mem::transmute(RT_CALLOC.load(Acquire)) };
        unsafe { f(1, size) }
    } else {
        let f: MallocFn = unsafe { core::mem::transmute(RT_MALLOC.load(Acquire)) };
        unsafe { f(size) }
    };
    if p.is_null() {
        crate::die(format_args!("cannot allocate memory"));
    }
    p
}

pub fn alloc_ext(size: usize, align: usize, zero: bool) -> *mut u8 {
    if rt_calloc() != 0 { ext_alloc(size, zero) } else { alloc_blk(size, align) }
}

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
            self.free[c] = unsafe { *(head as *const usize) };
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

pub fn alloc_perm(size: usize, align: usize) -> *mut u8 {
    with_heap(|h| h.alloc_perm(size, align))
}

fn class_of(size: usize, align: usize) -> usize {
    let n = size.max(align).max(16).next_power_of_two();
    n.trailing_zeros() as usize
}

pub fn alloc_blk(size: usize, align: usize) -> *mut u8 {
    with_heap(|h| h.alloc_blk(size, align))
}

pub unsafe fn free_blk(p: *mut u8, size: usize, align: usize) {
    if p.is_null() {
        return;
    }
    let rf = RT_FREE.load(Acquire);
    if rf != 0 && !is_own(p as usize) {
        let f: FreeFn = unsafe { core::mem::transmute(rf) };
        unsafe { f(p) };
        return;
    }
    let c = class_of(size, align);
    with_heap(|h| {
        unsafe { *(p as *mut usize) = h.free[c] };
        h.free[c] = p as usize;
    });
}

pub struct Lock {
    owner: AtomicUsize,
    waiters: core::sync::atomic::AtomicU32,
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
                let cur = self.owner.load(Relaxed);
                if cur != 0 {
                    sys::futex_wait(&self.owner, cur as u32);
                }
            }
            self.waiters.fetch_sub(1, SeqCst);
        }
        self.depth.store(1, Relaxed);
    }
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
