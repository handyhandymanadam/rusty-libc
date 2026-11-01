//! malloc.h: glibc extensions to the allocator interface.
use crate::heap;
use core::ffi::{c_int, c_void};
use core::sync::atomic::Ordering::Relaxed;
use rusty_libc_core::errno;

/// Old `mallinfo` result (32-bit fields, which wrap for big heaps; prefer `mallinfo2`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct mallinfo {
    pub arena: c_int,
    pub ordblks: c_int,
    pub smblks: c_int,
    pub hblks: c_int,
    pub hblkhd: c_int,
    pub usmblks: c_int,
    pub fsmblks: c_int,
    pub uordblks: c_int,
    pub fordblks: c_int,
    pub keepcost: c_int,
}

/// `mallinfo2` result: the same fields as `size_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct mallinfo2 {
    pub arena: usize,
    pub ordblks: usize,
    pub smblks: usize,
    pub hblks: usize,
    pub hblkhd: usize,
    pub usmblks: usize,
    pub fsmblks: usize,
    pub uordblks: usize,
    pub fordblks: usize,
    pub keepcost: usize,
}

/// memalign's rule (Rust API): an alignment up to 16 means 16, any other is rounded up to a power of two; EINVAL when
/// there is none.
pub fn memalign_rs(alignment: usize, size: usize) -> *mut u8 {
    memalign_rule(alignment, size)
}

/// pvalloc's rule (Rust API): whole pages, page-aligned; ENOMEM when the size cannot be rounded up.
pub fn pvalloc_rs(size: usize) -> *mut u8 {
    pvalloc_rule(size)
}

// (The C names inline these private forms. A `pub` #[inline] function would make everything it inlines reachable from
// other crates, and the allocator's statics would then be reached through the GOT on its fast paths.)
#[inline(always)]
fn memalign_rule(alignment: usize, size: usize) -> *mut u8 {
    let a = if alignment <= 16 { 16 } else { alignment.checked_next_power_of_two().unwrap_or(0) };
    if a == 0 {
        errno::set(22);
        return core::ptr::null_mut();
    }
    heap::memalign(a, size)
}

#[inline(always)]
fn pvalloc_rule(size: usize) -> *mut u8 {
    match size.checked_add(4095) {
        Some(n) => heap::memalign(4096, n & !4095),
        None => {
            errno::set(12);
            core::ptr::null_mut()
        }
    }
}

/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    memalign_rule(alignment, size).cast()
}

/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    heap::memalign(4096, size).cast()
}

/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    pvalloc_rule(size).cast()
}

/// # Safety
/// `ptr` must be NULL or a live block from this allocator.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    // SAFETY: `ptr` is NULL or a live block (contract).
    unsafe { heap::usable_size(ptr.cast()) }
}

/// The `mallinfo2` figures (Rust API).
pub fn fill_info() -> mallinfo2 {
    let st = heap::stats();
    let avail = st.top + st.free_bytes + st.small_bytes;
    mallinfo2 {
        arena: st.arena,
        ordblks: st.free_chunks + 1,
        smblks: st.small_chunks,
        hblks: heap::P.n_mmaps.load(Relaxed),
        hblkhd: heap::P.mmapped_mem.load(Relaxed),
        usmblks: 0,
        fsmblks: st.small_bytes,
        uordblks: st.arena.saturating_sub(avail),
        fordblks: avail,
        keepcost: st.top,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mallinfo2() -> mallinfo2 {
    fill_info()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mallinfo() -> mallinfo {
    let m = fill_info();
    mallinfo {
        arena: m.arena as c_int,
        ordblks: m.ordblks as c_int,
        smblks: m.smblks as c_int,
        hblks: m.hblks as c_int,
        hblkhd: m.hblkhd as c_int,
        usmblks: m.usmblks as c_int,
        fsmblks: m.fsmblks as c_int,
        uordblks: m.uordblks as c_int,
        fordblks: m.fordblks as c_int,
        keepcost: m.keepcost as c_int,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn malloc_trim(pad: usize) -> c_int {
    heap::trim(pad)
}

pub const M_MXFAST: c_int = 1;
pub const M_TRIM_THRESHOLD: c_int = -1;
pub const M_TOP_PAD: c_int = -2;
pub const M_MMAP_THRESHOLD: c_int = -3;
pub const M_MMAP_MAX: c_int = -4;
pub const M_CHECK_ACTION: c_int = -5;
pub const M_PERTURB: c_int = -6;
pub const M_ARENA_TEST: c_int = -7;
pub const M_ARENA_MAX: c_int = -8;

/// Adjust allocator parameters. Always returns 1, like glibc 2.43.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mallopt(param: c_int, value: c_int) -> c_int {
    heap::ensure_init();
    let lock = heap::main_lock();
    let taken = lock.lock();
    let p = &heap::P;
    let r = match param {
        M_MXFAST => {
            // glibc 2.43 accepts any value here (the fast bins it once controlled are gone); a value
            // of 0 is kept to mean "do not keep small blocks on quick lists".
            p.small_enabled.store(value != 0, Relaxed);
            1
        }
        M_TRIM_THRESHOLD => {
            p.trim_threshold.store(value as usize, Relaxed);
            p.dynamic_thresholds.store(false, Relaxed);
            1
        }
        M_TOP_PAD => {
            p.top_pad.store(value as usize, Relaxed);
            p.dynamic_thresholds.store(false, Relaxed);
            1
        }
        M_MMAP_THRESHOLD => {
            // Out-of-range values are ignored; glibc 2.43 still reports success (checked against it
            // for 16 parameters and 14 values: every call returned 1).
            if (0..=32 * 1024 * 1024).contains(&value) {
                p.mmap_threshold.store(value as usize, Relaxed);
                p.dynamic_thresholds.store(false, Relaxed);
            }
            1
        }
        M_MMAP_MAX => {
            p.mmap_max.store(value as usize, Relaxed);
            p.dynamic_thresholds.store(false, Relaxed);
            1
        }
        M_CHECK_ACTION => {
            p.check_action.store(value, Relaxed);
            1
        }
        M_PERTURB => {
            p.perturb.store(value as u8, Relaxed);
            1
        }
        M_ARENA_TEST => {
            if value > 0 {
                p.arena_test.store(value as usize, Relaxed);
            }
            1
        }
        M_ARENA_MAX => {
            if value > 0 {
                p.arena_max.store(value as usize, Relaxed);
            }
            1
        }
        _ => 1,
    };
    lock.unlock(taken);
    r
}

fn put_num(buf: &mut [u8], at: &mut usize, label: &[u8], v: usize) {
    for &b in label {
        buf[*at] = b;
        *at += 1;
    }
    let mut digits = [b' '; 10];
    let mut n = v;
    let mut i = 10;
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 || i == 0 {
            break;
        }
    }
    for d in digits {
        buf[*at] = d;
        *at += 1;
    }
    buf[*at] = b'\n';
    *at += 1;
}

/// Print allocator statistics to stderr in glibc's format.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn malloc_stats() {
    let mut buf = [0u8; 160];
    let text = |t: &[u8], buf: &mut [u8; 160], at: &mut usize| {
        for &b in t {
            buf[*at] = b;
            *at += 1;
        }
    };
    // not a cancellation point: arena locks are taken in here (and glibc disables cancellation)
    let out = |buf: &[u8]| {
        let _ = rusty_libc_core::unistd::write_nocancel(2, buf);
    };
    let (mut system, mut in_use) = (0usize, 0usize);
    // one block per arena, in the ring's order (glibc's numbering)
    let mut i = 0;
    heap::arenas(|a| {
        let st = heap::arena_stats(a);
        let avail = st.top + st.free_bytes + st.small_bytes;
        let used = st.arena.saturating_sub(avail);
        let mut at = 0;
        text(b"Arena ", &mut buf, &mut at);
        let mut d = [0u8; 20];
        let mut k = d.len();
        let mut v = i;
        loop {
            k -= 1;
            d[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        text(&d[k..], &mut buf, &mut at);
        text(b":\n", &mut buf, &mut at);
        put_num(&mut buf, &mut at, b"system bytes     = ", st.arena);
        put_num(&mut buf, &mut at, b"in use bytes     = ", used);
        out(&buf[..at]);
        system += st.arena;
        in_use += used;
        i += 1;
    });
    let p = &heap::P;
    let mmapped = p.mmapped_mem.load(Relaxed);
    let mut at = 0;
    text(b"Total (incl. mmap):\n", &mut buf, &mut at);
    put_num(&mut buf, &mut at, b"system bytes     = ", system + mmapped);
    put_num(&mut buf, &mut at, b"in use bytes     = ", in_use + mmapped);
    put_num(&mut buf, &mut at, b"max mmap regions = ", p.n_mmaps.load(Relaxed));
    put_num(&mut buf, &mut at, b"max mmap bytes   = ", p.max_mmapped_mem.load(Relaxed));
    out(&buf[..at]);
}

// ---- glibc's own names (see stdlib_api.rs: `__libc_malloc` and its kin do not go through the interposable public names) ----

/// glibc's own `memalign`.
///
/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_memalign(alignment: usize, size: usize) -> *mut c_void {
    memalign_rule(alignment, size).cast()
}

/// glibc's own `valloc`.
///
/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_valloc(size: usize) -> *mut c_void {
    heap::memalign(4096, size).cast()
}

/// glibc's own `pvalloc`.
///
/// # Safety
/// As `malloc`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_pvalloc(size: usize) -> *mut c_void {
    pvalloc_rule(size).cast()
}

/// glibc's own `mallinfo`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_mallinfo() -> mallinfo {
    mallinfo()
}

/// glibc's own `mallopt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_mallopt(param: c_int, value: c_int) -> c_int {
    mallopt(param, value)
}
