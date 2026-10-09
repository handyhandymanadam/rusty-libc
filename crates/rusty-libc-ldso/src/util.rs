use crate::sys;
use core::fmt::Write;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!("rep movsb", inout("rcx") n => _, inout("rdi") d => _, inout("rsi") s => _, options(nostack, preserves_flags));
    }
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if (d as usize) <= (s as usize) || (d as usize) >= (s as usize) + n {
            return memcpy(d, s, n);
        }
        let mut i = n;
        while i > 0 {
            i -= 1;
            *d.add(i) = *s.add(i);
        }
    }
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!("rep stosb", inout("rcx") n => _, inout("rdi") d => _, in("al") c as u8, options(nostack, preserves_flags));
    }
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe {
        for i in 0..n {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y {
                return x as i32 - y as i32;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { memcmp(a, b, n) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    unsafe {
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y || x == 0 {
                return x as i32 - y as i32;
            }
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *const u8 {
    let c = c as u8;
    let mut p = s;
    unsafe {
        loop {
            if *p == c {
                return p;
            }
            if *p == 0 {
                return core::ptr::null();
            }
            p = p.add(1);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn index(s: *const u8, c: i32) -> *const u8 {
    unsafe { strchr(s, c) }
}

pub unsafe fn cstr<'a>(s: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(s, strlen(s)) }
}

#[inline]
pub unsafe fn cstr_eq(p: *const u8, name: &[u8]) -> bool {
    unsafe {
        let mut i = 0;
        while i < name.len() {
            if *p.add(i) != *name.get_unchecked(i) {
                return false;
            }
            i += 1;
        }
        *p.add(i) == 0
    }
}

pub unsafe fn streq(a: *const u8, b: *const u8) -> bool {
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y {
                return false;
            }
            if x == 0 {
                return true;
            }
            i += 1;
        }
    }
}

pub unsafe fn cstr_gnu_hash<'a>(s: *const u8) -> (&'a [u8], u32) {
    unsafe {
        let mut h: u32 = 5381;
        let mut n = 0;
        loop {
            let c = *s.add(n);
            if c == 0 {
                break;
            }
            h = h.wrapping_mul(33).wrapping_add(c as u32);
            n += 1;
        }
        (core::slice::from_raw_parts(s, n), h)
    }
}

pub struct PathBuf {
    small: core::mem::MaybeUninit<[u8; 384]>,
    big: *mut u8,
    cap: usize,
}

impl PathBuf {
    pub fn new() -> PathBuf {
        PathBuf { small: core::mem::MaybeUninit::uninit(), big: core::ptr::null_mut(), cap: 384 }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn ptr(&mut self) -> *mut u8 {
        if self.big.is_null() { self.small.as_mut_ptr() as *mut u8 } else { self.big }
    }

    pub unsafe fn grow(&mut self, used: usize, need: usize) {
        unsafe {
            if need > self.cap {
                let nb = alloc_perm(need + 64, 1);
                core::ptr::copy_nonoverlapping(self.ptr(), nb, used);
                self.big = nb;
                self.cap = need + 64;
            }
        }
    }
}

pub unsafe fn dup(s: &[u8]) -> *const u8 {
    unsafe {
        let p = alloc_perm(s.len() + 1, 1);
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        *p.add(s.len()) = 0;
        p
    }
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

pub(crate) unsafe fn fork_child_reset() {
    unsafe { ALLOC_LOCK.reset() };
}
const CHUNK: usize = 256 * 1024;
const ARENA: usize = 64 * 1024;
static mut BUMP: usize = 0;
static mut BUMP_END: usize = 0;
static mut FREE: [usize; 48] = [0; 48];

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
static RT_MALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_FREE: AtomicUsize = AtomicUsize::new(0);
static RT_CALLOC: AtomicUsize = AtomicUsize::new(0);
static RT_ARMED: AtomicBool = AtomicBool::new(false);
static RT_TRIED: AtomicBool = AtomicBool::new(false);
static mut OWN: [(usize, usize); 256] = [(0, 0); 256];
static mut NOWN: usize = 0;
static mut BBUMP: usize = 0;
static mut BEND: usize = 0;

pub fn rtld_malloc_arm() {
    RT_ARMED.store(true, Release);
}

pub fn rtld_malloc_init(malloc: usize, calloc: usize, free: usize) {
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

unsafe fn ext_alloc(size: usize, zero: bool) -> *mut u8 {
    unsafe {
        let p = if zero {
            let f: unsafe extern "C" fn(usize, usize) -> *mut u8 = core::mem::transmute(RT_CALLOC.load(Acquire));
            f(1, size)
        } else {
            let f: unsafe extern "C" fn(usize) -> *mut u8 = core::mem::transmute(RT_MALLOC.load(Acquire));
            f(size)
        };
        if p.is_null() {
            crate::die(format_args!("cannot allocate memory"));
        }
        p
    }
}

pub unsafe fn alloc_ext(size: usize, align: usize, zero: bool) -> *mut u8 {
    unsafe {
        if rt_calloc() != 0 { ext_alloc(size, zero) } else { alloc_blk(size, align) }
    }
}

pub unsafe fn alloc_calloc(size: usize, align: usize) -> *mut u8 {
    unsafe {
        if align <= 16 && rt_calloc() != 0 { ext_alloc(size, true) } else { alloc_perm(size, align) }
    }
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

unsafe fn map_anon(len: usize) -> usize {
    let r = unsafe { sys::mmap(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0) };
    if r < 0 && r > -4096 {
        crate::die(format_args!("cannot allocate memory"));
    }
    r as usize
}

unsafe fn map_own(len: usize) -> usize {
    unsafe {
        let r = map_anon(len);
        if NOWN == OWN.len() {
            crate::die(format_args!("cannot allocate memory"));
        }
        OWN[NOWN] = (r, len);
        NOWN += 1;
        r
    }
}

fn is_own(p: usize) -> bool {
    ALLOC_LOCK.lock();
    let r = unsafe { (0..NOWN).any(|i| p >= OWN[i].0 && p < OWN[i].0 + OWN[i].1) };
    ALLOC_LOCK.unlock();
    r
}

pub unsafe fn alloc_perm(size: usize, align: usize) -> *mut u8 {
    ALLOC_LOCK.lock();
    let r = unsafe { alloc_perm_locked(size, align) };
    ALLOC_LOCK.unlock();
    r
}

unsafe fn alloc_perm_locked(size: usize, align: usize) -> *mut u8 {
    unsafe {
        let size = size.max(1);
        let mut p = align_up(BUMP, align);
        if p + size > BUMP_END {
            if size + align > CHUNK / 4 {
                return align_up(map_anon(size + align), align) as *mut u8;
            }
            BUMP = map_anon(CHUNK);
            BUMP_END = BUMP + CHUNK;
            p = align_up(BUMP, align);
        }
        BUMP = p + size;
        p as *mut u8
    }
}

fn class_of(size: usize, align: usize) -> usize {
    let n = size.max(align).max(16).next_power_of_two();
    n.trailing_zeros() as usize
}

pub unsafe fn alloc_blk(size: usize, align: usize) -> *mut u8 {
    ALLOC_LOCK.lock();
    let r = unsafe { alloc_blk_locked(size, align) };
    ALLOC_LOCK.unlock();
    r
}

unsafe fn alloc_blk_locked(size: usize, align: usize) -> *mut u8 {
    unsafe {
        let c = class_of(size, align);
        let head = FREE[c];
        if head != 0 {
            FREE[c] = *(head as *const usize);
            core::ptr::write_bytes(head as *mut u8, 0, 1usize << c);
            return head as *mut u8;
        }
        let n = 1usize << c;
        if n >= CHUNK / 4 {
            return align_up(map_own(n + align), align) as *mut u8;
        }
        let a = n.min(4096).max(align);
        let mut p = align_up(BBUMP, a);
        if p + n > BEND {
            if NOWN == OWN.len() {
                crate::die(format_args!("cannot allocate memory"));
            }
            BBUMP = alloc_perm_locked(ARENA, 64) as usize;
            BEND = BBUMP + ARENA;
            OWN[NOWN] = (BBUMP, ARENA);
            NOWN += 1;
            p = align_up(BBUMP, a);
        }
        BBUMP = p + n;
        p as *mut u8
    }
}

pub unsafe fn free_blk(p: *mut u8, size: usize, align: usize) {
    unsafe {
        if p.is_null() {
            return;
        }
        let rf = RT_FREE.load(Acquire);
        if rf != 0 && !is_own(p as usize) {
            let f: unsafe extern "C" fn(*mut u8) = core::mem::transmute(rf);
            f(p);
            return;
        }
        let c = class_of(size, align);
        ALLOC_LOCK.lock();
        *(p as *mut usize) = FREE[c];
        FREE[c] = p as usize;
        ALLOC_LOCK.unlock();
    }
}

pub struct Lock {
    owner: core::sync::atomic::AtomicUsize,
    waiters: core::sync::atomic::AtomicU32,
    depth: core::cell::UnsafeCell<usize>,
}

unsafe impl Sync for Lock {}

impl Lock {
    pub const fn new() -> Lock {
        Lock { owner: core::sync::atomic::AtomicUsize::new(0), waiters: core::sync::atomic::AtomicU32::new(0), depth: core::cell::UnsafeCell::new(0) }
    }
    fn me() -> usize {
        if crate::tls::ready() { sys::thread_pointer() } else { 1 }
    }
    pub fn lock(&self) {
        use core::sync::atomic::Ordering::*;
        let me = Self::me();
        if self.owner.load(Relaxed) == me {
            unsafe { *self.depth.get() += 1 };
            return;
        }
        if self.owner.compare_exchange(0, me, Acquire, Relaxed).is_err() {
            self.waiters.fetch_add(1, SeqCst);
            while self.owner.compare_exchange(0, me, Acquire, Relaxed).is_err() {
                let cur = self.owner.load(Relaxed);
                if cur != 0 {
                    unsafe { sys::syscall6(sys::SYS_FUTEX, &self.owner as *const _ as usize, 128, cur as u32 as usize, 0, 0, 0) };
                }
            }
            self.waiters.fetch_sub(1, SeqCst);
        }
        unsafe { *self.depth.get() = 1 };
    }
    pub unsafe fn reset(&self) {
        unsafe { *self.depth.get() = 0 };
        self.owner.store(0, core::sync::atomic::Ordering::Relaxed);
        self.waiters.store(0, core::sync::atomic::Ordering::Relaxed);
    }
    pub fn unlock(&self) {
        use core::sync::atomic::Ordering::*;
        unsafe {
            *self.depth.get() -= 1;
            if *self.depth.get() == 0 {
                self.owner.store(0, SeqCst);
                if self.waiters.load(SeqCst) != 0 {
                    sys::syscall6(sys::SYS_FUTEX, &self.owner as *const _ as usize, 129, 1, 0, 0, 0);
                }
            }
        }
    }
}
