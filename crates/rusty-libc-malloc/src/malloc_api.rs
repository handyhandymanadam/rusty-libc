use crate::heap;
use core::ffi::{c_int, c_void};
use core::sync::atomic::Ordering::Relaxed;
use rusty_libc_core::errno;

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    let a = if alignment <= 16 { 16 } else { alignment.checked_next_power_of_two().unwrap_or(0) };
    if a == 0 {
        errno::set(22);
        return core::ptr::null_mut();
    }
    unsafe { heap::memalign(a, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    unsafe { heap::memalign(4096, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    match size.checked_add(4095) {
        Some(n) => unsafe { heap::memalign(4096, n & !4095).cast() },
        None => {
            errno::set(12);
            core::ptr::null_mut()
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    unsafe { heap::usable_size(ptr.cast()) }
}

fn fill_info() -> mallinfo2 {
    let st = unsafe { heap::stats() };
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
pub unsafe extern "C" fn mallinfo2() -> mallinfo2 {
    fill_info()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mallinfo() -> mallinfo {
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
pub unsafe extern "C" fn malloc_trim(pad: usize) -> c_int {
    unsafe { heap::trim(pad) }
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mallopt(param: c_int, value: c_int) -> c_int {
    unsafe { heap::ensure_init() };
    let lock = heap::main_lock();
    let taken = lock.lock();
    let p = &heap::P;
    let r = match param {
        M_MXFAST => {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_stats() {
    let mut buf = [0u8; 160];
    let text = |t: &[u8], buf: &mut [u8; 160], at: &mut usize| {
        for &b in t {
            buf[*at] = b;
            *at += 1;
        }
    };
    let out = |buf: &[u8]| {
        let _ = rusty_libc_core::unistd::write_nocancel(2, buf);
    };
    let (mut system, mut in_use) = (0usize, 0usize);
    let mut i = 0;
    heap::arenas(|a| {
        let st = unsafe { heap::arena_stats(a) };
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

#[allow(dead_code)]
fn unused(_: *mut c_void) {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_memalign(alignment: usize, size: usize) -> *mut c_void {
    let a = if alignment <= 16 { 16 } else { alignment.checked_next_power_of_two().unwrap_or(0) };
    if a == 0 {
        errno::set(22);
        return core::ptr::null_mut();
    }
    unsafe { heap::memalign(a, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_valloc(size: usize) -> *mut c_void {
    unsafe { heap::memalign(4096, size).cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_pvalloc(size: usize) -> *mut c_void {
    match size.checked_add(4095) {
        Some(n) => unsafe { heap::memalign(4096, n & !4095).cast() },
        None => {
            errno::set(12);
            core::ptr::null_mut()
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_mallinfo() -> mallinfo {
    unsafe { mallinfo() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_mallopt(param: c_int, value: c_int) -> c_int {
    unsafe { mallopt(param, value) }
}
