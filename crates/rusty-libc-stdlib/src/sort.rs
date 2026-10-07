#![allow(clippy::deref_addrof)]
use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use rusty_libc_core::errno;

pub type CompareArg = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;
pub type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

const STACK_SIZE: usize = 1024;
const INDIRECT_THRESHOLD: usize = 32;
const PTR: usize = core::mem::size_of::<*mut u8>();

#[derive(Clone, Copy, PartialEq)]
enum Var {
    Words32,
    Words64,
    VoidArg,
    Bytes,
}

struct Param {
    s: usize,
    var: Var,
    cmp: CompareArg,
    arg: *mut c_void,
    t: *mut u8,
}

fn swap_type(base: *mut u8, size: usize) -> Var {
    if size & 3 == 0 && (base as usize) & 3 == 0 {
        if size == 4 {
            return Var::Words32;
        } else if size == 8 && (base as usize) & 7 == 0 {
            return Var::Words64;
        }
    }
    Var::Bytes
}

unsafe fn msort(p: &Param, b: *mut u8, n: usize) {
    if n <= 1 {
        return;
    }
    let mut n1 = n / 2;
    let mut n2 = n - n1;
    let mut b1 = b;
    let mut b2 = unsafe { b.add(n1 * p.s) };
    unsafe {
        msort(p, b1, n1);
        msort(p, b2, n2);
    }
    let mut tmp = p.t;
    let s = p.s;
    let cmp = p.cmp;
    let arg = p.arg;
    unsafe {
        match p.var {
            Var::Words32 => {
                while n1 > 0 && n2 > 0 {
                    if cmp(b1.cast(), b2.cast(), arg) <= 0 {
                        tmp.cast::<u32>().write(b1.cast::<u32>().read());
                        b1 = b1.add(4);
                        n1 -= 1;
                    } else {
                        tmp.cast::<u32>().write(b2.cast::<u32>().read());
                        b2 = b2.add(4);
                        n2 -= 1;
                    }
                    tmp = tmp.add(4);
                }
            }
            Var::Words64 => {
                while n1 > 0 && n2 > 0 {
                    if cmp(b1.cast(), b2.cast(), arg) <= 0 {
                        tmp.cast::<u64>().write(b1.cast::<u64>().read());
                        b1 = b1.add(8);
                        n1 -= 1;
                    } else {
                        tmp.cast::<u64>().write(b2.cast::<u64>().read());
                        b2 = b2.add(8);
                        n2 -= 1;
                    }
                    tmp = tmp.add(8);
                }
            }
            Var::VoidArg => {
                while n1 > 0 && n2 > 0 {
                    if cmp(b1.cast::<*const c_void>().read(), b2.cast::<*const c_void>().read(), arg) <= 0 {
                        tmp.cast::<*mut u8>().write(b1.cast::<*mut u8>().read());
                        b1 = b1.add(PTR);
                        n1 -= 1;
                    } else {
                        tmp.cast::<*mut u8>().write(b2.cast::<*mut u8>().read());
                        b2 = b2.add(PTR);
                        n2 -= 1;
                    }
                    tmp = tmp.add(PTR);
                }
            }
            Var::Bytes => {
                while n1 > 0 && n2 > 0 {
                    if cmp(b1.cast(), b2.cast(), arg) <= 0 {
                        ptr::copy_nonoverlapping(b1, tmp, s);
                        b1 = b1.add(s);
                        n1 -= 1;
                    } else {
                        ptr::copy_nonoverlapping(b2, tmp, s);
                        b2 = b2.add(s);
                        n2 -= 1;
                    }
                    tmp = tmp.add(s);
                }
            }
        }
        if n1 > 0 {
            ptr::copy_nonoverlapping(b1, tmp, n1 * s);
        }
        ptr::copy_nonoverlapping(p.t, b, (n - n2) * s);
    }
}

unsafe fn indirect_msort(p: &Param, b: *mut u8, n: usize, s: usize) {
    unsafe {
        let tp = p.t.add(n * PTR).cast::<*mut u8>();
        let tmp_storage = tp.add(n).cast::<u8>();
        let mut ip = b;
        for i in 0..n {
            tp.add(i).write(ip);
            ip = ip.add(s);
        }
        msort(p, tp.cast(), n);
        let mut ip = b;
        for i in 0..n {
            let mut kp = tp.add(i).read();
            if kp != ip {
                let mut j = i;
                let mut jp = ip;
                ptr::copy_nonoverlapping(ip, tmp_storage, s);
                loop {
                    let k = (kp as usize - b as usize) / s;
                    tp.add(j).write(jp);
                    ptr::copy_nonoverlapping(kp, jp, s);
                    j = k;
                    jp = kp;
                    kp = tp.add(k).read();
                    if kp == ip {
                        break;
                    }
                }
                tp.add(j).write(jp);
                ptr::copy_nonoverlapping(tmp_storage, jp, s);
            }
            ip = ip.add(s);
        }
    }
}

unsafe fn mergesort(base: *mut u8, n: usize, size: usize, cmp: CompareArg, arg: *mut c_void, buf: *mut u8) {
    if size > INDIRECT_THRESHOLD {
        let p = Param { s: PTR, cmp, arg, var: Var::VoidArg, t: buf };
        unsafe { indirect_msort(&p, base, n, size) }
    } else {
        let p = Param { s: size, cmp, arg, var: swap_type(base, size), t: buf };
        unsafe { msort(&p, base, n) }
    }
}

unsafe fn swap(a: *mut u8, b: *mut u8, size: usize) {
    unsafe { ptr::swap_nonoverlapping(a, b, size) }
}

unsafe fn siftdown(base: *mut u8, size: usize, mut k: usize, n: usize, cmp: CompareArg, arg: *mut c_void) {
    unsafe {
        while 2 * k < n {
            let mut j = 2 * k + 1;
            if j < n && cmp(base.add(j * size).cast(), base.add((j + 1) * size).cast(), arg) < 0 {
                j += 1;
            }
            if j == k || cmp(base.add(k * size).cast(), base.add(j * size).cast(), arg) >= 0 {
                break;
            }
            swap(base.add(size * j), base.add(k * size), size);
            k = j;
        }
    }
}

unsafe fn heapsort(base: *mut u8, mut n: usize, size: usize, cmp: CompareArg, arg: *mut c_void) {
    if n == 0 {
        return;
    }
    unsafe {
        let mut k = n / 2;
        loop {
            siftdown(base, size, k, n, cmp, arg);
            if k == 0 {
                break;
            }
            k -= 1;
        }
        loop {
            swap(base, base.add(n * size), size);
            n -= 1;
            if n == 0 {
                break;
            }
            siftdown(base, size, 0, n, cmp, arg);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(base: *mut c_void, nmemb: usize, size: usize, cmp: CompareArg, arg: *mut c_void) {
    if nmemb <= 1 {
        return;
    }
    let base = base.cast::<u8>();
    let total = if size > INDIRECT_THRESHOLD {
        nmemb.checked_mul(2 * PTR).and_then(|v| v.checked_add(size))
    } else {
        nmemb.checked_mul(size)
    };
    match total {
        Some(t) if t <= STACK_SIZE => {
            #[repr(align(8))]
            struct Stack(MaybeUninit<[u8; STACK_SIZE]>);
            let mut stack = Stack(MaybeUninit::uninit());
            unsafe { mergesort(base, nmemb, size, cmp, arg, stack.0.as_mut_ptr().cast()) }
        }
        _ => {
            let buf = match total {
                Some(t) => {
                    let save = errno::get();
                    let b = unsafe { rusty_libc_malloc::stdlib_api::malloc(t) }.cast::<u8>();
                    errno::set(save);
                    b
                }
                None => ptr::null_mut(),
            };
            if buf.is_null() {
                unsafe { heapsort(base, nmemb - 1, size, cmp, arg) }
            } else {
                unsafe {
                    mergesort(base, nmemb, size, cmp, arg, buf);
                    rusty_libc_malloc::stdlib_api::free(buf.cast());
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(base: *mut c_void, nmemb: usize, size: usize, cmp: Compare) {
    let cmp: CompareArg = unsafe { core::mem::transmute::<Compare, CompareArg>(cmp) };
    unsafe { qsort_r(base, nmemb, size, cmp, ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(key: *const c_void, base: *const c_void, mut nmemb: usize, size: usize, cmp: Compare) -> *mut c_void {
    let mut base = base.cast::<u8>();
    while nmemb != 0 {
        let p = unsafe { base.add((nmemb >> 1) * size) };
        let c = unsafe { cmp(key, p.cast()) };
        if c == 0 {
            return p.cast_mut().cast();
        }
        if c > 0 {
            base = unsafe { p.add(size) };
            nmemb -= 1;
        }
        nmemb >>= 1;
    }
    ptr::null_mut()
}

unsafe extern "C" fn trampoline<T, F: FnMut(&T, &T) -> Ordering>(a: *const c_void, b: *const c_void, arg: *mut c_void) -> c_int {
    let f = unsafe { &mut *arg.cast::<F>() };
    match f(unsafe { &*a.cast::<T>() }, unsafe { &*b.cast::<T>() }) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub fn sort_by<T: Copy, F: FnMut(&T, &T) -> Ordering>(v: &mut [T], mut f: F) {
    unsafe {
        qsort_r(v.as_mut_ptr().cast(), v.len(), core::mem::size_of::<T>(), trampoline::<T, F>, (&raw mut f).cast());
    }
}

pub fn sort<T: Copy + Ord>(v: &mut [T]) {
    sort_by(v, |a, b| a.cmp(b));
}

pub fn binary_search_by<T, F: FnMut(&T) -> Ordering>(v: &[T], mut f: F) -> Option<usize> {
    let (mut lo, mut n) = (0usize, v.len());
    while n != 0 {
        let mid = lo + (n >> 1);
        match f(&v[mid]) {
            Ordering::Equal => return Some(mid),
            Ordering::Greater => {
                lo = mid + 1;
                n -= 1;
            }
            Ordering::Less => {}
        }
        n >>= 1;
    }
    None
}

