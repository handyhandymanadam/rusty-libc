use crate::mem::{memchr_impl, memcmp_impl};
use crate::simd::{Vector, jump, pair};
use crate::str::{lower, strlen, strnlen, strnlen_impl};
use crate::{memcmp, strchr};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

unsafe fn twoway(mut h: *const u8, hend: *const u8, n: *const u8, l: usize) -> *const u8 {
    let nb = |i: usize| unsafe { n.add(i).read() };
    let mut byteset = [0u64; 4];
    let mut shift = [0usize; 256];
    for i in 0..l {
        let b = nb(i);
        byteset[(b >> 6) as usize] |= 1 << (b & 63);
        shift[b as usize] = i + 1;
    }

    let (mut ip, mut jp, mut k, mut p) = (usize::MAX, 0usize, 1usize, 1usize);
    while jp + k < l {
        let (a, b) = (nb(ip.wrapping_add(k)), nb(jp + k));
        if a == b {
            if k == p {
                jp += p;
                k = 1;
            } else {
                k += 1;
            }
        } else if a > b {
            jp += k;
            k = 1;
            p = jp.wrapping_sub(ip);
        } else {
            ip = jp;
            jp += 1;
            k = 1;
            p = 1;
        }
    }
    let mut ms = ip;
    let p0 = p;
    ip = usize::MAX;
    jp = 0;
    k = 1;
    p = 1;
    while jp + k < l {
        let (a, b) = (nb(ip.wrapping_add(k)), nb(jp + k));
        if a == b {
            if k == p {
                jp += p;
                k = 1;
            } else {
                k += 1;
            }
        } else if a < b {
            jp += k;
            k = 1;
            p = jp.wrapping_sub(ip);
        } else {
            ip = jp;
            jp += 1;
            k = 1;
            p = 1;
        }
    }
    if ip.wrapping_add(1) > ms.wrapping_add(1) {
        ms = ip;
    } else {
        p = p0;
    }

    let mem0;
    if unsafe { memcmp(n.cast(), n.add(p).cast(), ms.wrapping_add(1)) } != 0 {
        mem0 = 0;
        p = core::cmp::max(ms, l.wrapping_sub(ms).wrapping_sub(1)).wrapping_add(1);
    } else {
        mem0 = l - p;
    }
    let mut mem = 0usize;
    let mut z = h;
    let lazy = hend.is_null();

    loop {
        if lazy {
            if (z as usize) - (h as usize) < l {
                let grow = l | 63;
                let k = unsafe { strnlen(z.cast(), grow) };
                if k < grow {
                    z = unsafe { z.add(k) };
                    if (z as usize) - (h as usize) < l {
                        return core::ptr::null();
                    }
                } else {
                    z = unsafe { z.add(grow) };
                }
            }
        } else if (hend as usize) - (h as usize) < l {
            return core::ptr::null();
        }

        let last = unsafe { h.add(l - 1).read() };
        if byteset[(last >> 6) as usize] >> (last & 63) & 1 != 0 {
            let k = l - shift[last as usize];
            if k != 0 {
                let k = if k < mem { mem } else { k };
                h = unsafe { h.add(k) };
                mem = 0;
                continue;
            }
        } else {
            h = unsafe { h.add(l) };
            mem = 0;
            continue;
        }

        let mut k = core::cmp::max(ms.wrapping_add(1), mem);
        while k < l && nb(k) == unsafe { h.add(k).read() } {
            k += 1;
        }
        if k < l {
            h = unsafe { h.add(k.wrapping_sub(ms)) };
            mem = 0;
            continue;
        }
        let mut k = ms.wrapping_add(1);
        while k > mem && nb(k - 1) == unsafe { h.add(k - 1).read() } {
            k -= 1;
        }
        if k <= mem {
            return h;
        }
        h = unsafe { h.add(p) };
        mem = mem0;
    }
}

#[inline(always)]
unsafe fn find_in<V: Vector>(h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8 {
    unsafe {
        let w = V::W;
        let positions = hl - nl + 1;
        let (first, last) = (n.read(), n.add(nl - 1).read());
        let mid = nl - 2;
        let verify = |p: usize| mid == 0 || memcmp_impl::<V>(h.add(p + 1), n.add(1), mid) == 0;
        if positions < w {
            for p in 0..positions {
                if h.add(p).read() == first && h.add(p + nl - 1).read() == last && verify(p) {
                    return h.add(p);
                }
            }
            return core::ptr::null();
        }
        let (vf, vl) = (V::splat(first), V::splat(last));
        let last_i = positions - w;
        let mut i = 0;
        let mut spent = 0usize;
        loop {
            let hit = V::and(V::eq(V::loadu(h.add(i)), vf), V::eq(V::loadu(h.add(i + nl - 1)), vl));
            let mut m = V::mask(hit);
            while m != 0 {
                let p = i + m.trailing_zeros() as usize;
                if verify(p) {
                    return h.add(p);
                }
                spent += mid + 8;
                m &= m - 1;
            }
            if i == last_i {
                return core::ptr::null();
            }
            i = core::cmp::min(i + w, last_i);
            if spent > 512 + 8 * i {
                return twoway(h.add(i), h.add(hl), n, nl);
            }
        }
    }
}

const WINDOW: usize = 1024;
const MAX_FILTER_NEEDLE: usize = 256;

#[inline(always)]
unsafe fn strstr_slow_impl<V: Vector>(mut p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe {
        loop {
            let len = strnlen_impl::<V>(p, WINDOW);
            if len < WINDOW {
                return if len >= nl { find_in::<V>(p, len, n, nl) } else { core::ptr::null() };
            }
            let r = find_in::<V>(p, WINDOW, n, nl);
            if !r.is_null() {
                return r;
            }
            p = p.add(WINDOW - nl + 1);
        }
    }
}
#[inline(never)]
unsafe extern "C" fn strstr_slow_sse2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_slow_impl::<crate::simd::Sse2>(p, n, nl) }
}
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_slow_avx2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_slow_impl::<crate::simd::Avx2>(p, n, nl) }
}

#[inline(never)]
unsafe extern "C" fn twoway_str(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { twoway(p, core::ptr::null(), n, nl) }
}

#[inline(always)]
unsafe fn mid_eq_impl<V: Vector>(a: *const u8, b: *const u8, len: usize) -> bool {
    unsafe { memcmp_impl::<V>(a, b, len) == 0 }
}
#[inline(never)]
unsafe extern "C" fn mid_eq_sse2(a: *const u8, b: *const u8, len: usize) -> bool {
    unsafe { mid_eq_impl::<crate::simd::Sse2>(a, b, len) }
}
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn mid_eq_avx2(a: *const u8, b: *const u8, len: usize) -> bool {
    unsafe { mid_eq_impl::<crate::simd::Avx2>(a, b, len) }
}

#[inline(always)]
unsafe fn strstr_edge_impl<V: Vector>(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe {
        let len = strnlen_impl::<V>(p, 64);
        if len < 64 {
            return if len >= nl { find_in::<V>(p, len, n, nl) } else { core::ptr::null() };
        }
        let r = find_in::<V>(p, 64, n, nl);
        if r.is_null() { core::ptr::without_provenance(1) } else { r }
    }
}
#[inline(never)]
unsafe extern "C" fn strstr_edge_sse2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_edge_impl::<crate::simd::Sse2>(p, n, nl) }
}
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_edge_avx2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_edge_impl::<crate::simd::Avx2>(p, n, nl) }
}

#[inline(never)]
unsafe extern "C" fn strstr_cont_sse2(h: *const u8, p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_cont_impl::<crate::simd::Sse2>(h, p, n, nl) }
}
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_cont_avx2(h: *const u8, p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe { strstr_cont_impl::<crate::simd::Avx2>(h, p, n, nl) }
}

#[inline(always)]
unsafe fn strstr_cont_impl<V: Vector>(h: *const u8, mut p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    unsafe {
        let first = n.read();
        let avx = V::W == 32;
        let slow = |p: *const u8| if avx { strstr_slow_avx2(p, n, nl) } else { strstr_slow_sse2(p, n, nl) };
        let w = V::W;
        let (vf, vl, vz) = (V::splat(first), V::splat(n.add(nl - 1).read()), V::zero());
        let mid = nl - 2;
        let mut spent = 0usize;
        loop {
            let pe = (p as usize | (crate::simd::PAGE - 1)) + 1;
            while (p as usize) + nl - 1 + 2 * w <= pe {
                let (a0, a1) = (V::loadu(p), V::loadu(p.add(w)));
                let t0 = V::or(V::and(V::eq(a0, vf), V::eq(V::loadu(p.add(nl - 1)), vl)), V::eq(a0, vz));
                let t1 = V::or(V::and(V::eq(a1, vf), V::eq(V::loadu(p.add(w + nl - 1)), vl)), V::eq(a1, vz));
                if V::mask(V::or(t0, t1)) != 0 {
                    break;
                }
                p = p.add(2 * w);
            }
            if (p as usize) + nl - 1 + w <= pe {
                let v0 = V::loadu(p);
                let mz = V::mask(V::eq(v0, vz));
                let mut m = V::mask(V::and(V::eq(v0, vf), V::eq(V::loadu(p.add(nl - 1)), vl)));
                if mz != 0 {
                    let nul = mz.trailing_zeros() as usize;
                    if nul < nl {
                        return core::ptr::null();
                    }
                    m &= crate::simd::low_bits(nul - nl + 1);
                }
                while m != 0 {
                    let q = p.add(m.trailing_zeros() as usize);
                    let ok = mid == 0 || if avx { mid_eq_avx2(q.add(1), n.add(1), mid) } else { mid_eq_sse2(q.add(1), n.add(1), mid) };
                    if ok {
                        return q;
                    }
                    spent += mid + 8;
                    m &= m - 1;
                }
                if mz != 0 {
                    return core::ptr::null();
                }
                p = p.add(w);
                if spent > 512 + 8 * (p as usize - h as usize) {
                    return twoway_str(p, n, nl);
                }
            } else {
                if nl > 32 {
                    break;
                }
                let r = if avx { strstr_edge_avx2(p, n, nl) } else { strstr_edge_sse2(p, n, nl) };
                if r as usize != 1 {
                    return r;
                }
                p = ((p as usize + 64 - nl + 1) & !31) as *const u8;
            }
        }
        slow(p)
    }
}

#[inline(always)]
unsafe fn strstr_full_impl<V: Vector>(h: *const u8, n: *const u8) -> *const u8 {
    unsafe {
        let first = n.read();
        if first == 0 {
            return h;
        }
        if n.add(1).read() == 0 {
            return strchr(h.cast(), c_int::from(first)).cast();
        }
        let nl = if n.add(2).read() == 0 {
            2
        } else {
            let z = if crate::simd::same_page(n, V::W) { V::mask(V::eq(V::loadu(n), V::zero())) } else { 0 };
            if z != 0 {
                z.trailing_zeros() as usize
            } else {
                let z2 = if crate::simd::same_page(n, 2 * V::W) { V::mask(V::eq(V::loadu(n.add(V::W)), V::zero())) } else { 0 };
                if z2 != 0 { V::W + z2.trailing_zeros() as usize } else { strlen(n.cast()) }
            }
        };
        if nl > MAX_FILTER_NEEDLE {
            return twoway(h, core::ptr::null(), n, nl);
        }
        let w = V::W;
        let mut p = h;
        let (vf, vl, vz) = (V::splat(first), V::splat(n.add(nl - 1).read()), V::zero());
        for _ in 0..2 {
            if !(crate::simd::same_page(p, w + nl - 1)) {
                break;
            }
            let v0 = V::loadu(p);
            let mz = V::mask(V::eq(v0, vz));
            let mut m = V::mask(V::and(V::eq(v0, vf), V::eq(V::loadu(p.add(nl - 1)), vl)));
            if mz != 0 {
                let nul = mz.trailing_zeros() as usize;
                if nul < nl {
                    return core::ptr::null();
                }
                m &= crate::simd::low_bits(nul - nl + 1);
            }
            let mid = nl - 2;
            let avx = V::W == 32;
            while m != 0 {
                let q = p.add(m.trailing_zeros() as usize);
                let ok = mid == 0 || if avx { mid_eq_avx2(q.add(1), n.add(1), mid) } else { mid_eq_sse2(q.add(1), n.add(1), mid) };
                if ok {
                    return q;
                }
                m &= m - 1;
            }
            if mz != 0 {
                return core::ptr::null();
            }
            p = p.add(w);
        }
        if V::W == 32 { strstr_cont_avx2(h, p, n, nl) } else { strstr_cont_sse2(h, p, n, nl) }
    }
}

#[inline(never)]
unsafe extern "C" fn strstr_full_sse2(h: *const u8, n: *const u8) -> *const u8 {
    unsafe { strstr_full_impl::<crate::simd::Sse2>(h, n) }
}
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_full_avx2(h: *const u8, n: *const u8) -> *const u8 {
    unsafe { strstr_full_impl::<crate::simd::Avx2>(h, n) }
}

#[inline(always)]
unsafe fn strstr_impl<V: Vector>(h: *const u8, n: *const u8) -> *const u8 {
    unsafe {
        let avx = V::W == 32;
        let first = n.read();
        if first == 0 {
            return h;
        }
        if n.add(1).read() == 0 {
            return strchr(h.cast(), c_int::from(first)).cast();
        }
        let nl = if n.add(2).read() == 0 {
            2
        } else {
            let sp = crate::simd::same_page(n, V::W);
            let z = if sp { V::mask(V::eq(V::loadu(n), V::zero())) } else { 0 };
            let zh = if crate::simd::same_page(h, V::W) { V::mask(V::eq(V::loadu(h), V::zero())) } else { 0 };
            if z != 0 {
                let l = z.trailing_zeros();
                if zh != 0 && zh.trailing_zeros() < l {
                    return core::ptr::null();
                }
                l as usize
            } else {
                if zh != 0 && sp {
                    return core::ptr::null();
                }
                let z2 = if crate::simd::same_page(n, 2 * V::W) { V::mask(V::eq(V::loadu(n.add(V::W)), V::zero())) } else { 0 };
                if z2 == 0 {
                    return if avx { strstr_full_avx2(h, n) } else { strstr_full_sse2(h, n) };
                }
                V::W + z2.trailing_zeros() as usize
            }
        };
        if nl == 2 { strstr_front_blocks::<V, true>(h, n, 2, first) } else { strstr_front_blocks::<V, false>(h, n, nl, first) }
    }
}

#[inline(always)]
unsafe fn strstr_front_blocks<V: Vector, const TWO: bool>(h: *const u8, n: *const u8, nl: usize, first: u8) -> *const u8 {
    unsafe {
        let avx = V::W == 32;
        let w = V::W;
        let mut p = h;
        let (vf, vl, vz) = (V::splat(first), V::splat(n.add(nl - 1).read()), V::zero());
        let (count, checked) = if crate::simd::same_page(h, 8 * w + nl - 1) { (8, false) } else { (2, true) };
        for _ in 0..count {
            if checked && !(crate::simd::same_page(p, w + nl - 1)) {
                break;
            }
            let v0 = V::loadu(p);
            let mz = V::mask(V::eq(v0, vz));
            let m = V::mask(V::and(V::eq(v0, vf), V::eq(V::loadu(p.add(nl - 1)), vl)));
            let live = if mz == 0 { m != 0 } else { m != 0 && m.trailing_zeros() + (nl as u32) <= mz.trailing_zeros() };
            if live {
                if TWO {
                    return p.add(m.trailing_zeros() as usize);
                }
                return if avx { strstr_cont_avx2(h, h, n, nl) } else { strstr_cont_sse2(h, h, n, nl) };
            }
            if mz != 0 {
                return core::ptr::null();
            }
            p = p.add(w);
        }
        if avx { strstr_cont_avx2(h, p, n, nl) } else { strstr_cont_sse2(h, p, n, nl) }
    }
}

#[inline(always)]
unsafe fn memmem_impl<V: Vector>(h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8 {
    unsafe {
        if nl == 0 {
            return h;
        }
        if hl < nl {
            return core::ptr::null();
        }
        if nl == 1 {
            return memchr_impl::<V>(h, c_int::from(n.read()), hl);
        }
        find_in::<V>(h, hl, n, nl)
    }
}

pair!(strstr_sse2, strstr_avx2, strstr_impl, (h: *const u8, n: *const u8) -> *const u8);
pair!(memmem_sse2, memmem_avx2, memmem_impl, (h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char {
    jump!(STRSTR)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void {
    jump!(MEMMEM)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char {
    let at = |p: *const c_char, i: usize| unsafe { lower(p.add(i).cast::<u8>().read()) };
    if at(n, 0) == 0 {
        return h as *mut c_char;
    }
    let mut start = 0;
    while at(h, start) != 0 {
        let mut j = 0;
        while at(n, j) != 0 && at(h, start + j) == at(n, j) {
            j += 1;
        }
        if at(n, j) == 0 {
            return unsafe { h.add(start) } as *mut c_char;
        }
        if at(h, start + j) == 0 {
            return null_mut();
        }
        start += 1;
    }
    null_mut()
}
