use crate::mem::{memcpy_impl, memset_impl};
use crate::simd::{Avx2, PAGE, Sse2, Vector, avx2_front, avx2_front_x, jump, low_bits, pair};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use hooks::ACTIVE as HOOK_ACTIVE;
pub mod hooks {
    use super::*;

    pub type ToLower = fn(c: i32, loc: usize) -> i32;
    pub type Coll = unsafe fn(a: *const u8, b: *const u8, loc: usize) -> c_int;
    pub type Xfrm = unsafe fn(dest: *mut u8, src: *const u8, n: usize, loc: usize) -> usize;

    pub(crate) static ACTIVE: AtomicBool = AtomicBool::new(false);
    static TOLOWER: AtomicUsize = AtomicUsize::new(0);
    static COLL: AtomicUsize = AtomicUsize::new(0);
    static XFRM: AtomicUsize = AtomicUsize::new(0);

    pub fn install(tolower: ToLower, coll: Coll, xfrm: Xfrm) {
        TOLOWER.store(tolower as usize, Ordering::Release);
        COLL.store(coll as usize, Ordering::Release);
        XFRM.store(xfrm as usize, Ordering::Release);
    }

    pub fn activate() {
        crate::slots::init(crate::simd::has_avx2());
        crate::slots::STRCASECMP.store(hooked_strcasecmp as *const () as *mut (), Ordering::Release);
        crate::slots::STRNCASECMP.store(hooked_strncasecmp as *const () as *mut (), Ordering::Release);
        ACTIVE.store(true, Ordering::Release);
    }

    unsafe extern "C" fn hooked_strcasecmp(a: *const u8, b: *const u8) -> c_int {
        unsafe { super::casecmp_hooked(a, b, usize::MAX, 0) }
    }

    unsafe extern "C" fn hooked_strncasecmp(a: *const u8, b: *const u8, n: usize) -> c_int {
        unsafe { super::casecmp_hooked(a, b, n, 0) }
    }

    #[inline(always)]
    pub fn active() -> bool {
        ACTIVE.load(Ordering::Relaxed)
    }

    pub(super) fn tolower(c: u8, loc: usize) -> i32 {
        let f = TOLOWER.load(Ordering::Acquire);
        if f == 0 {
            return i32::from(super::lower(c));
        }
        let f: ToLower = unsafe { core::mem::transmute::<usize, ToLower>(f) };
        f(i32::from(c), loc)
    }

    pub(super) fn coll() -> Option<Coll> {
        let f = COLL.load(Ordering::Acquire);
        if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, Coll>(f) }) }
    }

    pub(super) fn xfrm() -> Option<Xfrm> {
        let f = XFRM.load(Ordering::Acquire);
        if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, Xfrm>(f) }) }
    }
}

unsafe fn casecmp_hooked(a: *const u8, b: *const u8, n: usize, loc: usize) -> c_int {
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (*a.add(i), *b.add(i));
            let (lx, ly) = (hooks::tolower(x, loc), hooks::tolower(y, loc));
            if lx != ly {
                return lx - ly;
            }
            if x == 0 {
                break;
            }
            i += 1;
        }
        0
    }
}

#[inline(always)]
unsafe fn at(p: *const c_char, i: usize) -> u8 {
    unsafe { p.add(i).cast::<u8>().read() }
}

#[inline(always)]
pub(crate) fn lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

#[inline(always)]
unsafe fn first_block<V: Vector>(s: *const u8, test: impl Fn(V) -> V) -> (u32, *const u8) {
    unsafe {
        let base = (s as usize & !(V::W - 1)) as *const u8;
        let skip = s as usize - base as usize;
        (V::mask(test(V::load(base))) >> skip, base)
    }
}

#[inline(always)]
unsafe fn scan_from<V: Vector>(s: *const u8, mut p: *const u8, hit: impl Fn(V) -> V) -> usize {
    unsafe {
        let w = V::W;
        let z = V::zero();
        for _ in 0..4 {
            let m = V::mask(V::eq(hit(V::load(p)), z));
            if m != 0 {
                return p as usize - s as usize + m.trailing_zeros() as usize;
            }
            p = p.add(w);
        }
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
                let (t0, t1, t2, t3) = (hit(V::load(p)), hit(V::load(p.add(w))), hit(V::load(p.add(2 * w))), hit(V::load(p.add(3 * w))));
                if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                    for (k, t) in [t0, t1, t2, t3].into_iter().enumerate() {
                        let m = V::mask(V::eq(t, z));
                        if m != 0 {
                            return p as usize - s as usize + k * w + m.trailing_zeros() as usize;
                        }
                    }
                }
                p = p.add(4 * w);
            } else {
                let m = V::mask(V::eq(hit(V::load(p)), z));
                if m != 0 {
                    return p as usize - s as usize + m.trailing_zeros() as usize;
                }
                p = p.add(w);
            }
        }
    }
}

#[inline(always)]
pub(crate) unsafe fn strlen_impl<V: Vector>(s: *const u8) -> usize {
    unsafe {
        let z = V::zero();
        if crate::simd::same_page(s, V::W) {
            let m = V::mask(V::eq(V::loadu(s), z));
            if m != 0 {
                return m.trailing_zeros() as usize;
            }
            return scan_from::<V>(s, ((s as usize | (V::W - 1)) + 1) as *const u8, |v| v);
        }
        let (m, base) = first_block::<V>(s, |v| V::eq(v, z));
        if m != 0 {
            return m.trailing_zeros() as usize;
        }
        scan_from::<V>(s, base.add(V::W), |v| v)
    }
}

pair!(strlen_sse2, strlen_avx2, strlen_impl, (s: *const u8) -> usize);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    avx2_front!(
        STRLEN,
        "mov eax, edi",
        "mov rdx, rdi",
        "vpxor xmm0, xmm0, xmm0",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "or rdi, 127",
        "inc rdi",
        ".p2align 4",
        "40:",
        "vmovdqa ymm1, [rdi]",
        "vpminub ymm2, ymm1, [rdi + 32]",
        "vmovdqa ymm3, [rdi + 64]",
        "vpminub ymm4, ymm3, [rdi + 96]",
        "vpminub ymm5, ymm2, ymm4",
        "vpcmpeqb ymm5, ymm0, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm1, ymm1, ymm0",
        "vpmovmskb eax, ymm1",
        "sub rdi, rdx",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm2, ymm2, ymm0",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "shl rcx, 32",
        "or rax, rcx",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi + 64]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rax + rdi + 32]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 1]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 33]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 65]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 97]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi - 31]",
        "vpmovmskb eax, ymm1",
        "sarx eax, eax, edx",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "vzeroupper",
        "ret",
    )
}

#[inline(always)]
pub(crate) unsafe fn strnlen_impl<V: Vector>(s: *const u8, n: usize) -> usize {
    unsafe {
        let w = V::W;
        if n == 0 {
            return 0;
        }
        let z = V::zero();
        let mut p;
        if crate::simd::same_page(s, w) {
            let m = V::mask(V::eq(V::loadu(s), z));
            if n <= w {
                return (u64::from(m) | (1u64 << n)).trailing_zeros() as usize;
            }
            if m != 0 {
                return m.trailing_zeros() as usize;
            }
            p = ((s as usize | (w - 1)) + 1) as *const u8;
        } else {
            let (m, base) = first_block::<V>(s, |v| V::eq(v, z));
            if m != 0 {
                return core::cmp::min(m.trailing_zeros() as usize, n);
            }
            p = base.add(w);
        }
        if p as usize - s as usize >= n {
            return n;
        }
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
                let (v0, v1, v2, v3) = (V::load(p), V::load(p.add(w)), V::load(p.add(2 * w)), V::load(p.add(3 * w)));
                if V::mask(V::eq(V::min(V::min(v0, v1), V::min(v2, v3)), z)) != 0 {
                    for (k, v) in [v0, v1, v2, v3].into_iter().enumerate() {
                        let m = V::mask(V::eq(v, z));
                        if m != 0 {
                            return core::cmp::min(p as usize - s as usize + k * w + m.trailing_zeros() as usize, n);
                        }
                    }
                }
                p = p.add(4 * w);
            } else {
                let m = V::mask(V::eq(V::load(p), z));
                if m != 0 {
                    return core::cmp::min(p as usize - s as usize + m.trailing_zeros() as usize, n);
                }
                p = p.add(w);
            }
            if p as usize - s as usize >= n {
                return n;
            }
        }
    }
}

pair!(strnlen_sse2, strnlen_avx2, strnlen_impl, (s: *const u8, n: usize) -> usize);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strnlen(s: *const c_char, n: usize) -> usize {
    avx2_front!(
        STRNLEN,
        "test rsi, rsi",
        "jz 70f",
        "mov eax, edi",
        "vpxor xmm0, xmm0, xmm0",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "mov rdx, rdi",
        "cmp rsi, 128",
        "jbe 24f",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "mov rax, -1",
        "sub rax, rdx",
        "cmp rsi, rax",
        "cmova rsi, rax",
        "lea r8, [rdx + rsi]",
        "jmp 23f",
        "24:",
        "cmp rsi, 32",
        "jbe 72f",
        "mov r8, rdi",
        "add r8, rsi",
        "sbb rax, rax",
        "or r8, rax",
        "or rdi, 31",
        "21:",
        "lea rcx, [rdi + 97]",
        "cmp rcx, r8",
        "jae 22f",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "jmp 23f",
        "22:",
        "lea rcx, [rdi + 1]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "lea rcx, [rdi + 33]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "lea rcx, [rdi + 65]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "lea rcx, [rdi + 97]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "23:",
        "or rdi, 127",
        "inc rdi",
        "lea r9, [r8 - 128]",
        ".p2align 4",
        "40:",
        "cmp rdi, r9",
        "ja 45f",
        "vmovdqa ymm1, [rdi]",
        "vpminub ymm2, ymm1, [rdi + 32]",
        "vmovdqa ymm3, [rdi + 64]",
        "vpminub ymm4, ymm3, [rdi + 96]",
        "vpminub ymm5, ymm2, ymm4",
        "vpcmpeqb ymm5, ymm0, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm1, ymm1, ymm0",
        "vpmovmskb eax, ymm1",
        "sub rdi, rdx",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm2, ymm2, ymm0",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "shl rcx, 32",
        "or rax, rcx",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi + 64]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rax + rdi + 32]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "45:",
        "cmp rdi, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 46f",
        "add rdi, 32",
        "jmp 45b",
        "46:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "add rax, rdi",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 1]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 33]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 65]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 97]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "72:",
        "mov rax, rsi",
        "vzeroupper",
        "ret",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi - 31]",
        "vpmovmskb eax, ymm1",
        "sarx eax, eax, edx",
        "test eax, eax",
        "jz 61f",
        "tzcnt eax, eax",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        "61:",
        "mov rax, -1",
        "sub rax, rdi",
        "cmp rsi, rax",
        "cmova rsi, rax",
        "lea r8, [rdx + rsi]",
        "jmp 21b",
    )
}

#[inline(always)]
unsafe fn stpcpy_impl<V: Vector>(d: *mut u8, s: *const u8) -> *mut u8 {
    unsafe {
        let w = V::W;
        let z = V::zero();
        if !crate::simd::same_page(s, w) {
            let len = strlen_impl::<V>(s);
            memcpy_impl::<V>(d, s, len + 1);
            return d.add(len);
        }
        let v0 = V::loadu(s);
        let m = V::mask(V::eq(v0, z));
        if m != 0 {
            let len = m.trailing_zeros() as usize;
            crate::mem::copy_upto_8w::<V>(d, s, len + 1);
            return d.add(len);
        }
        V::storeu(d, v0);
        let mut p = ((s as usize & !(w - 1)) + w) as *const u8;
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
                let (a, b, c, e) = (V::load(p), V::load(p.add(w)), V::load(p.add(2 * w)), V::load(p.add(3 * w)));
                if V::mask(V::eq(V::min(V::min(a, b), V::min(c, e)), z)) == 0 {
                    let off = p as usize - s as usize;
                    V::storeu(d.add(off), a);
                    V::storeu(d.add(off + w), b);
                    V::storeu(d.add(off + 2 * w), c);
                    V::storeu(d.add(off + 3 * w), e);
                    p = p.add(4 * w);
                    continue;
                }
                for v in [a, b, c, e] {
                    let m = V::mask(V::eq(v, z));
                    let off = p as usize - s as usize;
                    if m != 0 {
                        let len = off + m.trailing_zeros() as usize;
                        V::storeu(d.add(len + 1 - w), V::loadu(s.add(len + 1 - w)));
                        return d.add(len);
                    }
                    V::storeu(d.add(off), v);
                    p = p.add(w);
                }
            } else {
                let v = V::load(p);
                let m = V::mask(V::eq(v, z));
                let off = p as usize - s as usize;
                if m != 0 {
                    let len = off + m.trailing_zeros() as usize;
                    V::storeu(d.add(len + 1 - w), V::loadu(s.add(len + 1 - w)));
                    return d.add(len);
                }
                V::storeu(d.add(off), v);
                p = p.add(w);
            }
        }
    }
}

#[inline(always)]
unsafe fn strcpy_impl<V: Vector>(d: *mut u8, s: *const u8) -> *mut u8 {
    unsafe {
        stpcpy_impl::<V>(d, s);
        d
    }
}

pair!(strcpy_sse2, strcpy_avx2, strcpy_impl, (d: *mut u8, s: *const u8) -> *mut u8);
pair!(stpcpy_sse2, stpcpy_avx2, stpcpy_impl, (d: *mut u8, s: *const u8) -> *mut u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    avx2_front!(
        STPCPY,
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb eax, ymm2",
        "shrx eax, eax, esi",
        "test eax, eax",
        "jz 15b",
        "tzcnt ecx, eax",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "lea rax, [rdi + rcx]",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    avx2_front!(
        STRCPY,
        "mov rax, rdi",
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb r10d, ymm2",
        "shrx r10d, r10d, esi",
        "test r10d, r10d",
        "jz 15b",
        "tzcnt ecx, r10d",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "ret",
    )
}

static ALIVE: [u8; 288] = {
    let mut t = [0u8; 288];
    let mut i = 0;
    while i < 128 {
        t[i] = 0xFF;
        i += 1;
    }
    t
};

static PREFIX_MASK: [u8; 64] = {
    let mut t = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        t[i] = 0xFF;
        i += 1;
    }
    t
};

#[inline(always)]
unsafe fn stpncpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let w = V::W;
        if n <= w && crate::simd::same_page(s, w) {
            let v = V::loadu(s);
            let m = u64::from(V::mask(V::eq(v, V::zero()))) | (1u64 << n);
            let len = m.trailing_zeros() as usize;
            let keep = V::loadu(PREFIX_MASK.as_ptr().add(32 - len));
            let mut tmp = [0u8; 32];
            V::storeu(tmp.as_mut_ptr(), V::and(v, keep));
            crate::mem::copy_upto_8w::<V>(d, tmp.as_ptr(), n);
            return d.add(len);
        }
        let len = strnlen_impl::<V>(s, n);
        memcpy_impl::<V>(d, s, len);
        if len < n {
            memset_impl::<V>(d.add(len), 0, n - len);
        }
        d.add(len)
    }
}

#[inline(always)]
unsafe fn strncpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        stpncpy_impl::<V>(d, s, n);
        d
    }
}

pair!(strncpy_sse2, strncpy_avx2, strncpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);
pair!(stpncpy_sse2, stpncpy_avx2, stpncpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn stpncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    avx2_front_x!(
        STPNCPY,
        [tb = sym ALIVE],
        "test rdx, rdx",
        "jz 70f",
        "mov eax, esi",
        "and eax, 0xfff",
        "vpxor xmm0, xmm0, xmm0",
        "cmp rdx, 32",
        "ja 20f",
        "cmp eax, 0xfe0",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "bts rcx, rdx",
        "tzcnt rcx, rcx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "movzx eax, byte ptr [rsi]",
        "and al, byte ptr [r9]",
        "mov [rdi], al",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm2, [rsi]",
        "vpand xmm2, xmm2, [r9]",
        "vmovdqu xmm3, [rsi + rdx - 16]",
        "vpand xmm3, xmm3, [r9 + rdx - 16]",
        "vmovdqu [rdi], xmm2",
        "vmovdqu [rdi + rdx - 16], xmm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "mov rax, [rsi]",
        "and rax, [r9]",
        "mov r8, [rsi + rdx - 8]",
        "and r8, [r9 + rdx - 8]",
        "mov [rdi], rax",
        "mov [rdi + rdx - 8], r8",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "mov eax, [rsi]",
        "and eax, [r9]",
        "mov r8d, [rsi + rdx - 4]",
        "and r8d, [r9 + rdx - 4]",
        "mov [rdi], eax",
        "mov [rdi + rdx - 4], r8d",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "movzx eax, word ptr [rsi]",
        "and ax, word ptr [r9]",
        "movzx r8d, word ptr [rsi + rdx - 2]",
        "and r8w, word ptr [r9 + rdx - 2]",
        "mov [rdi], ax",
        "mov [rdi + rdx - 2], r8w",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "lea rax, [rdi + rdx]",
        "ret",
        ".p2align 4",
        "20:",
        "cmp eax, 0xf80",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vmovdqu ymm2, [rsi + 32]",
        "cmp rdx, 64",
        "ja 25f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "tzcnt rcx, rcx",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vpand ymm3, ymm3, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "25:",
        "vmovdqu ymm3, [rsi + 64]",
        "vmovdqu ymm4, [rsi + 96]",
        "cmp rdx, 128",
        "ja 40f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpand ymm5, ymm5, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "cmp rdx, 96",
        "jbe 26f",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vmovdqu [rdi + 64], ymm3",
        "26:",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb eax, ymm5",
        "test eax, eax",
        "jz 41f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "lea r9, [rdi + 128]",
        "lea r8, [rdx - 128]",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 95f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 95f",
        "94:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 95f",
        "vmovdqu [r9], ymm0",
        "jmp 94b",
        "95:",
        "vmovdqu [r10], ymm0",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vpand ymm4, ymm4, [r9 + 96]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "41:",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "lea r9, [rsi + rdx]",
        "lea r11, [r9 - 128]",
        "mov r8, rsi",
        "or r8, 127",
        "inc r8",
        "mov r10, rdi",
        "sub r10, rsi",
        ".p2align 6",
        "45:",
        "cmp r8, r11",
        "ja 50f",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 55f",
        "vmovdqu [r8 + r10], ymm1",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vmovdqu [r8 + r10 + 96], ymm4",
        "sub r8, -128",
        "jmp 45b",
        ".p2align 4",
        "50:",
        "cmp r8, r9",
        "jae 60f",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "mov rax, r9",
        "sub rax, r8",
        "cmp rax, 32",
        "jb 51f",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "add r8, 32",
        "jmp 50b",
        "51:",
        "bzhi ecx, ecx, eax",
        "tzcnt ecx, ecx",
        "lea r11, [rip + {tb} + 128]",
        "sub r11, rcx",
        "lea r9, [r8 + r10]",
        "lea rcx, [rcx + r8]",
        "sub rcx, rsi",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "cmp eax, 16",
        "jae 52f",
        "cmp eax, 8",
        "jae 53f",
        "cmp eax, 4",
        "jae 54f",
        "cmp eax, 2",
        "jae 56f",
        "movzx edx, byte ptr [r8]",
        "and dl, byte ptr [r11]",
        "mov [r9], dl",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "52:",
        "vmovdqu xmm2, [r8]",
        "vpand xmm2, xmm2, [r11]",
        "vmovdqu xmm3, [r8 + rax - 16]",
        "vpand xmm3, xmm3, [r11 + rax - 16]",
        "vmovdqu [r9], xmm2",
        "vmovdqu [r9 + rax - 16], xmm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "53:",
        "mov r10, [r8]",
        "and r10, [r11]",
        "mov rdx, [r8 + rax - 8]",
        "and rdx, [r11 + rax - 8]",
        "mov [r9], r10",
        "mov [r9 + rax - 8], rdx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "54:",
        "mov r10d, [r8]",
        "and r10d, [r11]",
        "mov edx, [r8 + rax - 4]",
        "and edx, [r11 + rax - 4]",
        "mov [r9], r10d",
        "mov [r9 + rax - 4], edx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "56:",
        "movzx r10d, word ptr [r8]",
        "and r10w, word ptr [r11]",
        "movzx edx, word ptr [r8 + rax - 2]",
        "and dx, word ptr [r11 + rax - 2]",
        "mov [r9], r10w",
        "mov [r9 + rax - 2], dx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "55:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 57f",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 58f",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "vmovdqa ymm1, ymm4",
        "jmp 80f",
        "58:",
        "add r8, 64",
        "vmovdqa ymm1, ymm3",
        "jmp 80f",
        "57:",
        "add r8, 32",
        "vmovdqa ymm1, ymm2",
        "80:",
        "tzcnt ecx, ecx",
        "lea r11, [r8 + r10]",
        "lea r8, [r8 + 32]",
        "mov rax, r9",
        "sub rax, r8",
        "jz 86f",
        "mov r9, r8",
        "add r9, r10",
        "mov r8, rax",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 85f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 85f",
        "84:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 85f",
        "vmovdqu [r9], ymm0",
        "jmp 84b",
        "85:",
        "vmovdqu [r10], ymm0",
        "86:",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu [r11], ymm1",
        "lea rax, [r11 + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "lea rax, [rdi + rdx]",
        "vzeroupper",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    avx2_front_x!(
        STRNCPY,
        [tb = sym ALIVE],
        "test rdx, rdx",
        "jz 70f",
        "mov eax, esi",
        "and eax, 0xfff",
        "vpxor xmm0, xmm0, xmm0",
        "cmp rdx, 32",
        "ja 20f",
        "cmp eax, 0xfe0",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "bts rcx, rdx",
        "tzcnt rcx, rcx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "movzx eax, byte ptr [rsi]",
        "and al, byte ptr [r9]",
        "mov [rdi], al",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm2, [rsi]",
        "vpand xmm2, xmm2, [r9]",
        "vmovdqu xmm3, [rsi + rdx - 16]",
        "vpand xmm3, xmm3, [r9 + rdx - 16]",
        "vmovdqu [rdi], xmm2",
        "vmovdqu [rdi + rdx - 16], xmm3",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "mov rax, [rsi]",
        "and rax, [r9]",
        "mov r8, [rsi + rdx - 8]",
        "and r8, [r9 + rdx - 8]",
        "mov [rdi], rax",
        "mov [rdi + rdx - 8], r8",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "mov eax, [rsi]",
        "and eax, [r9]",
        "mov r8d, [rsi + rdx - 4]",
        "and r8d, [r9 + rdx - 4]",
        "mov [rdi], eax",
        "mov [rdi + rdx - 4], r8d",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "movzx eax, word ptr [rsi]",
        "and ax, word ptr [r9]",
        "movzx r8d, word ptr [rsi + rdx - 2]",
        "and r8w, word ptr [r9 + rdx - 2]",
        "mov [rdi], ax",
        "mov [rdi + rdx - 2], r8w",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "mov rax, rdi",
        "ret",
        ".p2align 4",
        "20:",
        "cmp eax, 0xf80",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vmovdqu ymm2, [rsi + 32]",
        "cmp rdx, 64",
        "ja 25f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "tzcnt rcx, rcx",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vpand ymm3, ymm3, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "25:",
        "cmp rdx, 96",
        "ja 27f",
        "vmovdqu ymm3, [rsi + 64]",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "tzcnt rcx, rcx",
        "tzcnt r8d, r8d",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpand ymm5, ymm5, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "27:",
        "vmovdqu ymm3, [rsi + 64]",
        "vmovdqu ymm4, [rsi + 96]",
        "cmp rdx, 128",
        "ja 40f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpand ymm5, ymm5, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "cmp rdx, 96",
        "jbe 26f",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vmovdqu [rdi + 64], ymm3",
        "26:",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb eax, ymm5",
        "test eax, eax",
        "jz 41f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "lea r9, [rdi + 128]",
        "lea r8, [rdx - 128]",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 95f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 95f",
        "94:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 95f",
        "vmovdqu [r9], ymm0",
        "jmp 94b",
        "95:",
        "vmovdqu [r10], ymm0",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vpand ymm4, ymm4, [r9 + 96]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "41:",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "lea r9, [rdx - 128]",
        "cmp r9, 32",
        "ja 47f",
        "mov r8d, esi",
        "and r8d, 0xfff",
        "cmp r8d, 0xf60",
        "ja 47f",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpcmpeqb ymm6, ymm5, ymm0",
        "vpmovmskb ecx, ymm6",
        "bts rcx, 32",
        "tzcnt rcx, rcx",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm5, ymm5, [r9]",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        "47:",
        "lea r9, [rsi + rdx]",
        "lea r11, [r9 - 128]",
        "mov r8, rsi",
        "or r8, 127",
        "inc r8",
        "mov r10, rdi",
        "sub r10, rsi",
        ".p2align 6",
        "45:",
        "cmp r8, r11",
        "ja 50f",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 55f",
        "vmovdqu [r8 + r10], ymm1",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vmovdqu [r8 + r10 + 96], ymm4",
        "sub r8, -128",
        "jmp 45b",
        ".p2align 4",
        "50:",
        "cmp r8, r9",
        "jae 60f",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "mov rax, r9",
        "sub rax, r8",
        "cmp rax, 32",
        "jb 51f",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "add r8, 32",
        "jmp 50b",
        "51:",
        "bzhi ecx, ecx, eax",
        "tzcnt ecx, ecx",
        "lea r11, [rip + {tb} + 128]",
        "sub r11, rcx",
        "lea r9, [r8 + r10]",
        "cmp eax, 16",
        "jae 52f",
        "cmp eax, 8",
        "jae 53f",
        "cmp eax, 4",
        "jae 54f",
        "cmp eax, 2",
        "jae 56f",
        "movzx edx, byte ptr [r8]",
        "and dl, byte ptr [r11]",
        "mov [r9], dl",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "52:",
        "vmovdqu xmm2, [r8]",
        "vpand xmm2, xmm2, [r11]",
        "vmovdqu xmm3, [r8 + rax - 16]",
        "vpand xmm3, xmm3, [r11 + rax - 16]",
        "vmovdqu [r9], xmm2",
        "vmovdqu [r9 + rax - 16], xmm3",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "53:",
        "mov r10, [r8]",
        "and r10, [r11]",
        "mov rdx, [r8 + rax - 8]",
        "and rdx, [r11 + rax - 8]",
        "mov [r9], r10",
        "mov [r9 + rax - 8], rdx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "54:",
        "mov r10d, [r8]",
        "and r10d, [r11]",
        "mov edx, [r8 + rax - 4]",
        "and edx, [r11 + rax - 4]",
        "mov [r9], r10d",
        "mov [r9 + rax - 4], edx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "56:",
        "movzx r10d, word ptr [r8]",
        "and r10w, word ptr [r11]",
        "movzx edx, word ptr [r8 + rax - 2]",
        "and dx, word ptr [r11 + rax - 2]",
        "mov [r9], r10w",
        "mov [r9 + rax - 2], dx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "55:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 57f",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 58f",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "vmovdqa ymm1, ymm4",
        "jmp 80f",
        "58:",
        "add r8, 64",
        "vmovdqa ymm1, ymm3",
        "jmp 80f",
        "57:",
        "add r8, 32",
        "vmovdqa ymm1, ymm2",
        "80:",
        "tzcnt ecx, ecx",
        "lea r11, [r8 + r10]",
        "lea r8, [r8 + 32]",
        "mov rax, r9",
        "sub rax, r8",
        "jz 86f",
        "mov r9, r8",
        "add r9, r10",
        "mov r8, rax",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 85f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 85f",
        "84:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 85f",
        "vmovdqu [r9], ymm0",
        "jmp 84b",
        "85:",
        "vmovdqu [r10], ymm0",
        "86:",
        "lea r9, [rip + {tb} + 128]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu [r11], ymm1",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
    )
}

pub(crate) unsafe extern "C" fn strcat_generic(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { stpcpy(dest.add(strlen(dest)), src) };
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    avx2_front_x!(
        STRCAT,
        [strlen = sym strlen],
        "mov rax, rdi",
        "mov edx, edi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 70f",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jz 70f",
        "tzcnt ecx, ecx",
        "add rdi, rcx",
        "jmp 75f",
        ".p2align 4",
        "70:",
        "sub rsp, 24",
        "mov [rsp], rax",
        "mov [rsp + 8], rsi",
        "vzeroupper",
        "call {strlen}",
        "mov rcx, [rsp]",
        "mov rsi, [rsp + 8]",
        "add rsp, 24",
        "lea rdi, [rcx + rax]",
        "mov rax, rcx",
        "75:",
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb r10d, ymm2",
        "shrx r10d, r10d, esi",
        "test r10d, r10d",
        "jz 15b",
        "tzcnt ecx, r10d",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strncat(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    unsafe {
        let d = dest.add(strlen(dest));
        let len = strnlen(src, n);
        super::mem::memcpy(d.cast::<c_void>(), src.cast::<c_void>(), len);
        d.add(len).cast::<u8>().write(0);
    }
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strlcpy(dest: *mut c_char, src: *const c_char, size: usize) -> usize {
    let len = unsafe { strlen(src) };
    if size > 0 {
        let n = if len < size { len } else { size - 1 };
        unsafe {
            super::mem::memcpy(dest.cast::<c_void>(), src.cast::<c_void>(), n);
            dest.add(n).cast::<u8>().write(0);
        }
    }
    len
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strlcat(dest: *mut c_char, src: *const c_char, size: usize) -> usize {
    let dl = unsafe { strnlen(dest, size) };
    let sl = unsafe { strlen(src) };
    if dl == size {
        return size + sl;
    }
    let room = size - dl - 1;
    let n = if sl < room { sl } else { room };
    unsafe {
        super::mem::memcpy(dest.add(dl).cast::<c_void>(), src.cast::<c_void>(), n);
        dest.add(dl + n).cast::<u8>().write(0);
    }
    dl + sl
}

#[inline(always)]
unsafe fn lower_v<V: Vector>(v: V) -> V {
    unsafe {
        let upper = V::and(V::gt(v, V::splat(b'A' - 1)), V::gt(V::splat(b'Z' + 1), v));
        V::add(v, V::and(upper, V::splat(0x20)))
    }
}

#[inline(always)]
unsafe fn cmp_one<V: Vector, const CI: bool>(a: *const u8, b: *const u8, left: usize, z: V) -> Option<c_int> {
    unsafe {
        let w = V::W;
        let a0 = V::loadu(a);
        let b0 = V::loadu(b);
        let mut m = V::mask(V::eq(V::min(V::eq(a0, b0), a0), z));
        if CI && m != 0 {
            m = V::mask(V::eq(V::min(V::eq(lower_v(a0), lower_v(b0)), a0), z));
        }
        if left < w {
            m &= low_bits(left);
        }
        if m != 0 {
            let i = m.trailing_zeros() as usize;
            let (x, y) = (*a.add(i), *b.add(i));
            let (x, y) = if CI { (lower(x), lower(y)) } else { (x, y) };
            return Some(c_int::from(x) - c_int::from(y));
        }
        if left <= w { Some(0) } else { None }
    }
}

#[inline(always)]
unsafe fn cmp_impl<V: Vector, const CI: bool>(mut a: *const u8, mut b: *const u8, n: usize) -> c_int {
    unsafe {
        let w = V::W;
        let z = V::zero();
        let mut left = n;
        let prep = |v: V| if CI { lower_v(v) } else { v };
        let byte = |p: *const u8, i: usize| if CI { lower(*p.add(i)) } else { *p.add(i) };
        if core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1)) <= PAGE - w {
            if let Some(r) = cmp_one::<V, CI>(a, b, left, z) {
                return r;
            }
            a = a.add(w);
            b = b.add(w);
            left -= w;
            for _ in 0..3 {
                if core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1)) > PAGE - w {
                    break;
                }
                if let Some(r) = cmp_one::<V, CI>(a, b, left, z) {
                    return r;
                }
                a = a.add(w);
                b = b.add(w);
                left -= w;
            }
        }
        loop {
            if left == 0 {
                return 0;
            }
            let worst = core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1));
            if left >= 4 * w && worst <= PAGE - 4 * w {
                let a0 = V::loadu(a);
                let a1 = V::loadu(a.add(w));
                let a2 = V::loadu(a.add(2 * w));
                let a3 = V::loadu(a.add(3 * w));
                let t0 = V::min(V::eq(prep(a0), prep(V::loadu(b))), a0);
                let t1 = V::min(V::eq(prep(a1), prep(V::loadu(b.add(w)))), a1);
                let t2 = V::min(V::eq(prep(a2), prep(V::loadu(b.add(2 * w)))), a2);
                let t3 = V::min(V::eq(prep(a3), prep(V::loadu(b.add(3 * w)))), a3);
                if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                    for (k, t) in [t0, t1, t2, t3].into_iter().enumerate() {
                        let m = V::mask(V::eq(t, z));
                        if m != 0 {
                            let i = k * w + m.trailing_zeros() as usize;
                            return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
                        }
                    }
                }
                a = a.add(4 * w);
                b = b.add(4 * w);
                left -= 4 * w;
            } else if left >= w && worst <= PAGE - w {
                let a0 = V::loadu(a);
                let t = V::min(V::eq(prep(a0), prep(V::loadu(b))), a0);
                let m = V::mask(V::eq(t, z));
                if m != 0 {
                    let i = m.trailing_zeros() as usize;
                    return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
                }
                a = a.add(w);
                b = b.add(w);
                left -= w;
            } else if left < w && worst <= PAGE - w {
                let a0 = V::loadu(a);
                let t = V::min(V::eq(prep(a0), prep(V::loadu(b))), a0);
                let m = V::mask(V::eq(t, z)) & low_bits(left);
                if m != 0 {
                    let i = m.trailing_zeros() as usize;
                    return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
                }
                return 0;
            } else {
                let (x, y) = (byte(a, 0), byte(b, 0));
                if x != y || x == 0 {
                    return c_int::from(x) - c_int::from(y);
                }
                a = a.add(1);
                b = b.add(1);
                left -= 1;
            }
        }
    }
}

pub(crate) unsafe extern "C" fn strcmp_sse2(a: *const u8, b: *const u8) -> c_int {
    unsafe { cmp_impl::<Sse2, false>(a, b, usize::MAX) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcmp_avx2(a: *const u8, b: *const u8) -> c_int {
    unsafe { cmp_impl::<Avx2, false>(a, b, usize::MAX) }
}
pub(crate) unsafe extern "C" fn strncmp_sse2(a: *const u8, b: *const u8, n: usize) -> c_int {
    unsafe { cmp_impl::<Sse2, false>(a, b, n) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strncmp_avx2(a: *const u8, b: *const u8, n: usize) -> c_int {
    unsafe { cmp_impl::<Avx2, false>(a, b, n) }
}
pub(crate) unsafe extern "C" fn strcasecmp_sse2(a: *const u8, b: *const u8) -> c_int {
    unsafe { cmp_impl::<Sse2, true>(a, b, usize::MAX) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcasecmp_avx2(a: *const u8, b: *const u8) -> c_int {
    unsafe { cmp_impl::<Avx2, true>(a, b, usize::MAX) }
}
pub(crate) unsafe extern "C" fn strncasecmp_sse2(a: *const u8, b: *const u8, n: usize) -> c_int {
    unsafe { cmp_impl::<Sse2, true>(a, b, n) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strncasecmp_avx2(a: *const u8, b: *const u8, n: usize) -> c_int {
    unsafe { cmp_impl::<Avx2, true>(a, b, n) }
}

macro_rules! strcmp_step_at {
    ($a:literal, $b:literal) => {
        concat!(
            "vmovdqu ymm0, [", $a, "]\n",
            "vpcmpeqb ymm1, ymm0, [", $b, "]\n",
            "vpcmpeqb ymm2, ymm0, ymm15\n",
            "vpandn ymm1, ymm2, ymm1\n",
            "vpmovmskb ecx, ymm1\n",
            "inc ecx"
        )
    };
}

macro_rules! strcmp_step {
    ($off:literal) => {
        concat!(
            "vmovdqu ymm0, [rdi + ", $off, "]\n",
            "vpcmpeqb ymm1, ymm0, [rsi + ", $off, "]\n",
            "vpcmpeqb ymm2, ymm0, ymm15\n",
            "vpandn ymm1, ymm2, ymm1\n",
            "vpmovmskb ecx, ymm1\n",
            "inc ecx"
        )
    };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    avx2_front!(
        STRCMP,
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xf80",
        "ja 99f",
        "vpxor xmm15, xmm15, xmm15",
        strcmp_step!("0"),
        "jz 20f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        strcmp_step!("32"),
        "jnz 81f",
        strcmp_step!("64"),
        "jnz 82f",
        strcmp_step!("96"),
        "jnz 83f",
        "sub rsi, rdi",
        "and rdi, -128",
        "sub rdi, -128",
        "add rsi, rdi",
        "mov eax, esi",
        "and eax, 4095",
        "neg eax",
        "add eax, 4096",
        "sub eax, 128",
        "jb 50f",
        ".p2align 6",
        "41:",
        "vmovdqa ymm0, [rdi]",
        "vmovdqa ymm2, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm6, [rdi + 96]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm3, ymm2, [rsi + 32]",
        "vpcmpeqb ymm5, ymm4, [rsi + 64]",
        "vpcmpeqb ymm7, ymm6, [rsi + 96]",
        "vpand ymm1, ymm1, ymm0",
        "vpand ymm3, ymm3, ymm2",
        "vpand ymm5, ymm5, ymm4",
        "vpand ymm7, ymm7, ymm6",
        "vpminub ymm3, ymm3, ymm1",
        "vpminub ymm7, ymm7, ymm5",
        "vpminub ymm7, ymm7, ymm3",
        "vpcmpeqb ymm7, ymm15, ymm7",
        "vpmovmskb edx, ymm7",
        "test edx, edx",
        "jnz 42f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jae 41b",
        "jmp 50f",
        ".p2align 4",
        "42:",
        "vpcmpeqb ymm1, ymm15, ymm1",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jnz 84f",
        "vpcmpeqb ymm3, ymm15, ymm3",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jnz 85f",
        "vpcmpeqb ymm5, ymm15, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 86f",
        "tzcnt ecx, edx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "50:",
        "add eax, 128",
        "jnz 51f",
        "mov eax, 3968",
        "jmp 41b",
        "51:",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        ".p2align 4",
        "81:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "84:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "85:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "86:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    avx2_front!(
        STRNCMP,
        "test rdx, rdx",
        "jz 70f",
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xf80",
        "ja 99f",
        "vpxor xmm15, xmm15, xmm15",
        "cmp rdx, 32",
        "ja 19f",
        "vmovdqu ymm0, [rdi]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm2, ymm0, ymm15",
        "vpandn ymm1, ymm2, ymm1",
        "vpmovmskb ecx, ymm1",
        "not ecx",
        "bzhi ecx, ecx, edx",
        "jz 71f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "19:",
        strcmp_step!("0"),
        "jz 20f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "cmp rdx, 64",
        "jbe 31f",
        strcmp_step!("32"),
        "jnz 81f",
        "cmp rdx, 128",
        "jbe 32f",
        strcmp_step!("64"),
        "jnz 82f",
        strcmp_step!("96"),
        "jnz 83f",
        "mov rcx, -1",
        "shr rcx, 2",
        "cmp rdx, rcx",
        "cmova rdx, rcx",
        "lea r8, [rdi + rdx]",
        "lea r9, [r8 - 128]",
        "sub rsi, rdi",
        "and rdi, -128",
        "sub rdi, -128",
        "add rsi, rdi",
        "mov eax, esi",
        "and eax, 4095",
        "neg eax",
        "add eax, 4096",
        "sub eax, 128",
        "jb 50f",
        ".p2align 6",
        "41:",
        "cmp rdi, r9",
        "ja 60f",
        "vmovdqa ymm0, [rdi]",
        "vmovdqa ymm2, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm6, [rdi + 96]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm3, ymm2, [rsi + 32]",
        "vpcmpeqb ymm5, ymm4, [rsi + 64]",
        "vpcmpeqb ymm7, ymm6, [rsi + 96]",
        "vpand ymm1, ymm1, ymm0",
        "vpand ymm3, ymm3, ymm2",
        "vpand ymm5, ymm5, ymm4",
        "vpand ymm7, ymm7, ymm6",
        "vpminub ymm3, ymm3, ymm1",
        "vpminub ymm7, ymm7, ymm5",
        "vpminub ymm7, ymm7, ymm3",
        "vpcmpeqb ymm7, ymm15, ymm7",
        "vpmovmskb edx, ymm7",
        "test edx, edx",
        "jnz 42f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jae 41b",
        "50:",
        "mov rdx, r8",
        "sub rdx, rdi",
        "jbe 71f",
        "add eax, 128",
        "jnz 51f",
        "mov eax, 3968",
        "jmp 41b",
        "51:",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        ".p2align 4",
        "42:",
        "vpcmpeqb ymm1, ymm15, ymm1",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jnz 84f",
        "vpcmpeqb ymm3, ymm15, ymm3",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jnz 85f",
        "vpcmpeqb ymm5, ymm15, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 86f",
        "tzcnt ecx, edx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rdx, r8",
        "sub rdx, rdi",
        "jbe 71f",
        "61:",
        "vmovdqa ymm0, [rdi]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm2, ymm0, ymm15",
        "vpandn ymm1, ymm2, ymm1",
        "vpmovmskb ecx, ymm1",
        "not ecx",
        "cmp rdx, 32",
        "jb 62f",
        "test ecx, ecx",
        "jnz 84f",
        "sub rdx, 32",
        "jz 71f",
        "add rdi, 32",
        "add rsi, 32",
        "jmp 61b",
        "62:",
        "bzhi ecx, ecx, edx",
        "jnz 84f",
        "71:",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        strcmp_step_at!("rdi + rdx - 32", "rsi + rdx - 32"),
        "jnz 87f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "32:",
        "cmp rdx, 96",
        "jbe 33f",
        strcmp_step!("64"),
        "jnz 82f",
        "33:",
        strcmp_step_at!("rdi + rdx - 32", "rsi + rdx - 32"),
        "jnz 87f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "81:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "84:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "85:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "86:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "87:",
        "tzcnt ecx, ecx",
        "add rcx, rdx",
        "movzx eax, byte ptr [rdi + rcx - 32]",
        "movzx ecx, byte ptr [rsi + rcx - 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int {
    avx2_front_x!(
        STRCASECMP,
        [hk = sym HOOK_ACTIVE],
        "cmp byte ptr [rip + {hk}], 0",
        "jne 99f",
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xf80",
        "ja 99f",
        "vpxor xmm15, xmm15, xmm15",
        strcmp_step!("0"),
        "jz 20f",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx]",
        "lea r9, [rsi + rcx]",
        "jmp 90f",
        ".p2align 4",
        "20:",
        strcmp_step!("32"),
        "jnz 81f",
        strcmp_step!("64"),
        "jnz 82f",
        strcmp_step!("96"),
        "jnz 83f",
        "sub rsi, rdi",
        "and rdi, -128",
        "sub rdi, -128",
        "add rsi, rdi",
        "mov eax, esi",
        "and eax, 4095",
        "neg eax",
        "add eax, 4096",
        "sub eax, 128",
        "jb 50f",
        ".p2align 6",
        "41:",
        "vmovdqa ymm0, [rdi]",
        "vmovdqa ymm2, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm6, [rdi + 96]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm3, ymm2, [rsi + 32]",
        "vpcmpeqb ymm5, ymm4, [rsi + 64]",
        "vpcmpeqb ymm7, ymm6, [rsi + 96]",
        "vpand ymm1, ymm1, ymm0",
        "vpand ymm3, ymm3, ymm2",
        "vpand ymm5, ymm5, ymm4",
        "vpand ymm7, ymm7, ymm6",
        "vpminub ymm3, ymm3, ymm1",
        "vpminub ymm7, ymm7, ymm5",
        "vpminub ymm7, ymm7, ymm3",
        "vpcmpeqb ymm7, ymm15, ymm7",
        "vpmovmskb edx, ymm7",
        "test edx, edx",
        "jnz 42f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jae 41b",
        "jmp 50f",
        ".p2align 4",
        "42:",
        "vpcmpeqb ymm1, ymm15, ymm1",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jnz 84f",
        "vpcmpeqb ymm3, ymm15, ymm3",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jnz 85f",
        "vpcmpeqb ymm5, ymm15, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 86f",
        "tzcnt ecx, edx",
        "lea r8, [rdi + rcx + 96]",
        "lea r9, [rsi + rcx + 96]",
        "jmp 90f",
        ".p2align 4",
        "50:",
        "add eax, 128",
        "jnz 51f",
        "mov eax, 3968",
        "jmp 41b",
        "51:",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        ".p2align 4",
        "81:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx + 32]",
        "lea r9, [rsi + rcx + 32]",
        "jmp 90f",
        ".p2align 4",
        "82:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx + 64]",
        "lea r9, [rsi + rcx + 64]",
        "jmp 90f",
        ".p2align 4",
        "83:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx + 96]",
        "lea r9, [rsi + rcx + 96]",
        "jmp 90f",
        ".p2align 4",
        "84:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx]",
        "lea r9, [rsi + rcx]",
        "jmp 90f",
        ".p2align 4",
        "85:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx + 32]",
        "lea r9, [rsi + rcx + 32]",
        "jmp 90f",
        ".p2align 4",
        "86:",
        "tzcnt ecx, ecx",
        "lea r8, [rdi + rcx + 64]",
        "lea r9, [rsi + rcx + 64]",
        "jmp 90f",
        ".p2align 4",
        "90:",
        "movzx eax, byte ptr [r8]",
        "movzx ecx, byte ptr [r9]",
        "cmp eax, ecx",
        "je 91f",
        "lea edx, [rax - 65]",
        "cmp dl, 25",
        "ja 92f",
        "add eax, 32",
        "92:",
        "lea edx, [rcx - 65]",
        "cmp dl, 25",
        "ja 93f",
        "add ecx, 32",
        "93:",
        "sub eax, ecx",
        "jnz 94f",
        "lea rdi, [r8 + 1]",
        "lea rsi, [r9 + 1]",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        "91:",
        "xor eax, eax",
        "94:",
        "vzeroupper",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    jump!(STRNCASECMP)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int {
    unsafe {
        if hooks::active() {
            return casecmp_hooked(a.cast(), b.cast(), usize::MAX, loc as usize);
        }
        strcasecmp(a, b)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp_l(a: *const c_char, b: *const c_char, n: usize, loc: *mut c_void) -> c_int {
    unsafe {
        if hooks::active() {
            return casecmp_hooked(a.cast(), b.cast(), n, loc as usize);
        }
        strncasecmp(a, b, n)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll(a: *const c_char, b: *const c_char) -> c_int {
    unsafe {
        if hooks::active()
            && let Some(f) = hooks::coll()
        {
            return f(a.cast(), b.cast(), 0);
        }
        strcmp(a, b)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int {
    unsafe {
        if hooks::active()
            && let Some(f) = hooks::coll()
        {
            return f(a.cast(), b.cast(), loc as usize);
        }
        strcmp(a, b)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    unsafe {
        if hooks::active()
            && let Some(f) = hooks::xfrm()
        {
            return f(dest.cast(), src.cast(), n, 0);
        }
        strxfrm_c(dest, src, n)
    }
}

unsafe fn strxfrm_c(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    let len = unsafe { strlen(src) };
    if n != 0 {
        let count = if len + 1 < n { len + 1 } else { n };
        unsafe { super::mem::memcpy(dest.cast::<c_void>(), src.cast::<c_void>(), count) };
    }
    len
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm_l(dest: *mut c_char, src: *const c_char, n: usize, loc: *mut c_void) -> usize {
    unsafe {
        if hooks::active()
            && let Some(f) = hooks::xfrm()
        {
            return f(dest.cast(), src.cast(), n, loc as usize);
        }
        strxfrm_c(dest, src, n)
    }
}

#[inline(always)]
unsafe fn strchrnul_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    unsafe {
        let c = c as u8;
        let vc = V::splat(c);
        let z = V::zero();
        let hit = |v: V| V::min(v, V::xor(v, vc));
        if crate::simd::same_page(s, V::W) {
            let m = V::mask(V::eq(hit(V::loadu(s)), z));
            if m != 0 {
                return s.add(m.trailing_zeros() as usize);
            }
            return s.add(scan_from::<V>(s, ((s as usize | (V::W - 1)) + 1) as *const u8, hit));
        }
        let (m, base) = first_block::<V>(s, |v| V::eq(hit(v), z));
        if m != 0 {
            return s.add(m.trailing_zeros() as usize);
        }
        s.add(scan_from::<V>(s, base.add(V::W), hit))
    }
}

#[inline(always)]
unsafe fn strchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    unsafe {
        let p = strchrnul_impl::<V>(s, c);
        if p.read() == c as u8 { p } else { core::ptr::null() }
    }
}

pair!(strchrnul_sse2, strchrnul_avx2, strchrnul_impl, (s: *const u8, c: c_int) -> *const u8);
pair!(strchr_sse2, strchr_avx2, strchr_impl, (s: *const u8, c: c_int) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    avx2_front!(
        STRCHRNUL,
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vmovdqa ymm2, [rdi + 1]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 30f",
        "vmovdqa ymm2, [rdi + 33]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 31f",
        "vmovdqa ymm2, [rdi + 65]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 32f",
        "vmovdqa ymm2, [rdi + 97]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 33f",
        "or rdi, 127",
        "inc rdi",
        ".p2align 6",
        "40:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm10, ymm10, ymm11",
        "vpcmpeqb ymm10, ymm10, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm6, ymm6, ymm0",
        "vpmovmskb eax, ymm6",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm7, ymm7, ymm0",
        "vpmovmskb eax, ymm7",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm8, ymm8, ymm0",
        "vpmovmskb eax, ymm8",
        "test eax, eax",
        "jnz 44f",
        "vpcmpeqb ymm9, ymm9, ymm0",
        "vpmovmskb eax, ymm9",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 96]",
        "jmp 49f",
        "44:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 64]",
        "jmp 49f",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 32]",
        "jmp 49f",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49f",
        "30:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 1]",
        "jmp 49f",
        "31:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 33]",
        "jmp 49f",
        "32:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 65]",
        "jmp 49f",
        "33:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 97]",
        "49:",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "and rdx, -32",
        "vmovdqa ymm2, [rdx]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "sarx eax, eax, edi",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49b",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    avx2_front!(
        STRCHR,
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "add rax, rdi",
        "xor ecx, ecx",
        "cmp byte ptr [rax], sil",
        "cmovne rax, rcx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vmovdqa ymm2, [rdi + 1]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 30f",
        "vmovdqa ymm2, [rdi + 33]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 31f",
        "vmovdqa ymm2, [rdi + 65]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 32f",
        "vmovdqa ymm2, [rdi + 97]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 33f",
        "or rdi, 127",
        "inc rdi",
        ".p2align 6",
        "40:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm10, ymm10, ymm11",
        "vpcmpeqb ymm10, ymm10, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm6, ymm6, ymm0",
        "vpmovmskb eax, ymm6",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm7, ymm7, ymm0",
        "vpmovmskb eax, ymm7",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm8, ymm8, ymm0",
        "vpmovmskb eax, ymm8",
        "test eax, eax",
        "jnz 44f",
        "vpcmpeqb ymm9, ymm9, ymm0",
        "vpmovmskb eax, ymm9",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 96]",
        "jmp 49f",
        "44:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 64]",
        "jmp 49f",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 32]",
        "jmp 49f",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49f",
        "30:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 1]",
        "jmp 49f",
        "31:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 33]",
        "jmp 49f",
        "32:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 65]",
        "jmp 49f",
        "33:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 97]",
        "49:",
        "xor ecx, ecx",
        "cmp byte ptr [rax], sil",
        "cmovne rax, rcx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "and rdx, -32",
        "vmovdqa ymm2, [rdx]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "sarx eax, eax, edi",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49b",
    )
}

#[inline(always)]
unsafe fn strrchr_block<V: Vector>(p: *const u8, vc: V, hi: u32, last: &mut (*const u8, u32)) -> Option<*const u8> {
    unsafe {
        let v = V::load(p);
        let mz = V::mask(V::eq(v, V::zero())) & hi;
        let mc = V::mask(V::eq(v, vc)) & hi;
        if mz != 0 {
            let before = mc & (mz.isolate_lowest_one() - 1);
            let (base, m) = if before != 0 { (p, before) } else { *last };
            return Some(if m != 0 { base.add(31 - m.leading_zeros() as usize) } else { core::ptr::null() });
        }
        if mc != 0 {
            *last = (p, mc);
        }
        None
    }
}

#[inline(always)]
unsafe fn strrchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    unsafe {
        let c = c as u8;
        let w = V::W;
        if c == 0 {
            return s.add(strlen_impl::<V>(s));
        }
        let vc = V::splat(c);
        let hit = |v: V| V::min(v, V::xor(v, vc));
        let mut last: (*const u8, u32) = (core::ptr::null(), 0);
        let mut p;
        if crate::simd::same_page(s, w) {
            let v = V::loadu(s);
            let mz = V::mask(V::eq(v, V::zero()));
            let mc = V::mask(V::eq(v, vc));
            if mz != 0 {
                let before = mc & (mz.isolate_lowest_one() - 1);
                return if before != 0 { s.add(31 - before.leading_zeros() as usize) } else { core::ptr::null() };
            }
            if mc != 0 {
                last = (s, mc);
            }
            p = ((s as usize | (w - 1)) + 1) as *const u8;
        } else {
            let base = (s as usize & !(w - 1)) as *const u8;
            let hi = low_bits(w) << (s as usize - base as usize);
            if let Some(r) = strrchr_block::<V>(base, vc, hi, &mut last) {
                return r;
            }
            p = base.add(w);
        }
        for _ in 0..3 {
            if let Some(r) = strrchr_block::<V>(p, vc, low_bits(w), &mut last) {
                return r;
            }
            p = p.add(w);
        }
        let z = V::zero();
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
                let (t0, t1, t2, t3) = (hit(V::load(p)), hit(V::load(p.add(w))), hit(V::load(p.add(2 * w))), hit(V::load(p.add(3 * w))));
                if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                    for k in 0..4 {
                        if let Some(r) = strrchr_block::<V>(p.add(k * w), vc, low_bits(w), &mut last) {
                            return r;
                        }
                    }
                }
                p = p.add(4 * w);
            } else {
                if let Some(r) = strrchr_block::<V>(p, vc, low_bits(w), &mut last) {
                    return r;
                }
                p = p.add(w);
            }
        }
    }
}

pair!(strrchr_sse2, strrchr_avx2, strrchr_impl, (s: *const u8, c: c_int) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    avx2_front_x!(
        STRRCHR,
        [strlen = sym strlen],
        "test sil, sil",
        "jz 80f",
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpcmpeqb ymm3, ymm2, ymm0",
        "vpcmpeqb ymm4, ymm2, ymm1",
        "vpmovmskb ecx, ymm3",
        "vpmovmskb eax, ymm4",
        "test ecx, ecx",
        "jnz 30f",
        "mov r8, rdi",
        "mov r9d, eax",
        "or rdi, 31",
        "inc rdi",
        "40:",
        "test edi, 127",
        "jz 50f",
        "vmovdqa ymm2, [rdi]",
        "vpxor ymm6, ymm2, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpcmpeqb ymm6, ymm6, ymm0",
        "vpmovmskb edx, ymm6",
        "test edx, edx",
        "jnz 42f",
        "add rdi, 32",
        "jmp 40b",
        "42:",
        "vpcmpeqb ymm3, ymm2, ymm0",
        "vpcmpeqb ymm4, ymm2, ymm1",
        "vpmovmskb ecx, ymm3",
        "vpmovmskb eax, ymm4",
        "test ecx, ecx",
        "jnz 31f",
        "mov r8, rdi",
        "mov r9d, eax",
        "add rdi, 32",
        "jmp 40b",
        ".p2align 6",
        "50:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm10, ymm10, ymm11",
        "vpcmpeqb ymm10, ymm10, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 52f",
        "sub rdi, -128",
        "jmp 50b",
        ".p2align 4",
        "52:",
        "vpcmpeqb ymm10, ymm6, ymm0",
        "vpmovmskb edx, ymm10",
        "test edx, edx",
        "jz 90f",
        "vpcmpeqb ymm10, ymm2, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 70f",
        "vpcmpeqb ymm10, ymm2, ymm1",
        "vpmovmskb eax, ymm10",
        "lea r8, [rdi + 0]",
        "mov r9d, eax",
        "90:",
        "vpcmpeqb ymm10, ymm7, ymm0",
        "vpmovmskb edx, ymm10",
        "test edx, edx",
        "jz 91f",
        "vpcmpeqb ymm10, ymm3, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 71f",
        "vpcmpeqb ymm10, ymm3, ymm1",
        "vpmovmskb eax, ymm10",
        "lea r8, [rdi + 32]",
        "mov r9d, eax",
        "91:",
        "vpcmpeqb ymm10, ymm8, ymm0",
        "vpmovmskb edx, ymm10",
        "test edx, edx",
        "jz 92f",
        "vpcmpeqb ymm10, ymm4, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 72f",
        "vpcmpeqb ymm10, ymm4, ymm1",
        "vpmovmskb eax, ymm10",
        "lea r8, [rdi + 64]",
        "mov r9d, eax",
        "92:",
        "vpcmpeqb ymm10, ymm9, ymm0",
        "vpmovmskb edx, ymm10",
        "test edx, edx",
        "jz 93f",
        "vpcmpeqb ymm10, ymm5, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 73f",
        "vpcmpeqb ymm10, ymm5, ymm1",
        "vpmovmskb eax, ymm10",
        "lea r8, [rdi + 96]",
        "mov r9d, eax",
        "93:",
        "sub rdi, -128",
        "jmp 50b",
        "70:",
        "vpcmpeqb ymm10, ymm2, ymm1",
        "vpmovmskb eax, ymm10",
        "add rdi, 0",
        "jmp 31f",
        "71:",
        "vpcmpeqb ymm10, ymm3, ymm1",
        "vpmovmskb eax, ymm10",
        "add rdi, 32",
        "jmp 31f",
        "72:",
        "vpcmpeqb ymm10, ymm4, ymm1",
        "vpmovmskb eax, ymm10",
        "add rdi, 64",
        "jmp 31f",
        "73:",
        "vpcmpeqb ymm10, ymm5, ymm1",
        "vpmovmskb eax, ymm10",
        "add rdi, 96",
        "jmp 31f",
        ".p2align 4",
        "30:",
        "blsmsk ecx, ecx",
        "and eax, ecx",
        "jz 34f",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "blsmsk ecx, ecx",
        "and eax, ecx",
        "jz 33f",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        "33:",
        "test r9d, r9d",
        "jz 34f",
        "lzcnt eax, r9d",
        "neg eax",
        "add eax, 31",
        "add rax, r8",
        "vzeroupper",
        "ret",
        "34:",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov r10, rdi",
        "and r10, -32",
        "vmovdqa ymm2, [r10]",
        "vpcmpeqb ymm3, ymm2, ymm0",
        "vpcmpeqb ymm4, ymm2, ymm1",
        "vpmovmskb ecx, ymm3",
        "vpmovmskb eax, ymm4",
        "shrx ecx, ecx, edi",
        "shrx eax, eax, edi",
        "test ecx, ecx",
        "jnz 30b",
        "mov r8, rdi",
        "mov r9d, eax",
        "or rdi, 31",
        "inc rdi",
        "jmp 40b",
        ".p2align 4",
        "80:",
        "push rdi",
        "call {strlen}",
        "pop rdi",
        "add rax, rdi",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn index(s: *const c_char, c: c_int) -> *mut c_char {
    jump!(STRCHR)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn rindex(s: *const c_char, c: c_int) -> *mut c_char {
    jump!(STRRCHR)
}

#[inline(always)]
unsafe fn span_stop<V: Vector, const ACCEPT: bool, const K: usize>(v: V, sp: &[V; K], z: V) -> u32 {
    unsafe {
        let mut inset = V::eq(v, sp[0]);
        for x in &sp[1..] {
            inset = V::or(inset, V::eq(v, *x));
        }
        if ACCEPT { !V::mask(inset) & low_bits(V::W) } else { V::mask(V::or(inset, V::eq(v, z))) }
    }
}

#[inline(always)]
unsafe fn span_k<V: Vector, const ACCEPT: bool, const K: usize, const N: usize>(s: *const u8, bytes: [u8; N]) -> usize {
    unsafe {
        let w = V::W;
        let z = V::zero();
        let sp: [V; K] = core::array::from_fn(|i| V::splat(bytes[i]));
        let base = (s as usize & !(w - 1)) as *const u8;
        let m = span_stop::<V, ACCEPT, K>(V::load(base), &sp, z) >> (s as usize - base as usize);
        if m != 0 {
            return m.trailing_zeros() as usize;
        }
        let mut p = base.add(w);
        let m = span_stop::<V, ACCEPT, K>(V::load(p), &sp, z);
        if m != 0 {
            return p as usize - s as usize + m.trailing_zeros() as usize;
        }
        p = p.add(w);
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 2 * w {
                let (m0, m1) = (span_stop::<V, ACCEPT, K>(V::load(p), &sp, z), span_stop::<V, ACCEPT, K>(V::load(p.add(w)), &sp, z));
                if m0 | m1 != 0 {
                    let (off, m) = if m0 != 0 { (0, m0) } else { (w, m1) };
                    return p as usize - s as usize + off + m.trailing_zeros() as usize;
                }
                p = p.add(2 * w);
            } else {
                let m = span_stop::<V, ACCEPT, K>(V::load(p), &sp, z);
                if m != 0 {
                    return p as usize - s as usize + m.trailing_zeros() as usize;
                }
                p = p.add(w);
            }
        }
    }
}

#[inline(always)]
unsafe fn span_wide<V: Vector, const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    unsafe {
        let mut bytes = [0u8; 16];
        let mut k = 0;
        while k < 17 {
            let b = *set.add(k);
            if b == 0 {
                break;
            }
            if k < 16 {
                bytes[k] = b;
            }
            k += 1;
        }
        if k > 16 {
            return span_map::<ACCEPT>(s, set);
        }
        let first = bytes[0];
        for slot in bytes.iter_mut().skip(k) {
            *slot = first;
        }
        if k <= 8 { span_k::<V, ACCEPT, 8, 16>(s, bytes) } else { span_k::<V, ACCEPT, 16, 16>(s, bytes) }
    }
}

unsafe fn span_wide_sse2<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    unsafe { span_wide::<Sse2, ACCEPT>(s, set) }
}
#[target_feature(enable = "avx2")]
unsafe fn span_wide_avx2<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    unsafe { span_wide::<Avx2, ACCEPT>(s, set) }
}

#[inline(always)]
unsafe fn span_impl<V: Vector, const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    unsafe {
        let b0 = *set;
        if b0 == 0 {
            return if ACCEPT { 0 } else { strlen_impl::<V>(s) };
        }
        let b1 = *set.add(1);
        if b1 == 0 {
            return span_k::<V, ACCEPT, 1, 4>(s, [b0, b0, b0, b0]);
        }
        let b2 = *set.add(2);
        if b2 == 0 {
            return span_k::<V, ACCEPT, 2, 4>(s, [b0, b1, b0, b0]);
        }
        let b3 = *set.add(3);
        if b3 == 0 {
            return span_k::<V, ACCEPT, 3, 4>(s, [b0, b1, b2, b0]);
        }
        if *set.add(4) == 0 {
            return span_k::<V, ACCEPT, 4, 4>(s, [b0, b1, b2, b3]);
        }
        if V::W == 32 { span_wide_avx2::<ACCEPT>(s, set) } else { span_wide_sse2::<ACCEPT>(s, set) }
    }
}

unsafe fn span_map<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    let map = unsafe { byte_set(set.cast()) };
    let mut i = 0;
    loop {
        let b = unsafe { *s.add(i) };
        if b == 0 || map.has(b) != ACCEPT {
            return i;
        }
        i += 1;
    }
}

pub(crate) unsafe extern "C" fn strspn_sse2(s: *const u8, set: *const u8) -> usize {
    unsafe { span_impl::<Sse2, true>(s, set) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strspn_avx2(s: *const u8, set: *const u8) -> usize {
    unsafe { span_impl::<Avx2, true>(s, set) }
}
pub(crate) unsafe extern "C" fn strcspn_sse2(s: *const u8, set: *const u8) -> usize {
    unsafe { span_impl::<Sse2, false>(s, set) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcspn_avx2(s: *const u8, set: *const u8) -> usize {
    unsafe { span_impl::<Avx2, false>(s, set) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    jump!(STRSPN)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    jump!(STRCSPN)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    let i = unsafe { strcspn(s, accept) };
    if unsafe { at(s, i) } == 0 { null_mut() } else { unsafe { s.add(i) as *mut c_char } }
}

pub(crate) struct ByteSet([u64; 4]);

impl ByteSet {
    #[inline(always)]
    pub(crate) fn has(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] >> (b & 63) & 1 != 0
    }
}

pub(crate) unsafe fn byte_set(s: *const c_char) -> ByteSet {
    let mut set = ByteSet([0; 4]);
    let mut i = 0;
    loop {
        let b = unsafe { at(s, i) };
        if b == 0 {
            return set;
        }
        set.0[(b >> 6) as usize] |= 1 << (b & 63);
        i += 1;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char {
    let s = unsafe { *stringp };
    if s.is_null() {
        return null_mut();
    }
    let i = unsafe { strcspn(s, delim) };
    unsafe {
        if at(s, i) == 0 {
            *stringp = null_mut();
        } else {
            s.add(i).cast::<u8>().write(0);
            *stringp = s.add(i + 1);
        }
    }
    s
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    let mut s = if s.is_null() { unsafe { *saveptr } } else { s };
    if s.is_null() {
        return null_mut();
    }
    if unsafe { at(s, 0) } == 0 {
        unsafe { *saveptr = s };
        return null_mut();
    }
    s = unsafe { s.add(strspn(s, delim)) };
    if unsafe { at(s, 0) } == 0 {
        unsafe { *saveptr = s };
        return null_mut();
    }
    let end = unsafe { s.add(strcspn(s, delim)) };
    unsafe {
        if at(end, 0) == 0 {
            *saveptr = end;
        } else {
            end.cast::<u8>().write(0);
            *saveptr = end.add(1);
        }
    }
    s
}

static STRTOK_SAVE: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    let mut save = STRTOK_SAVE.load(Ordering::Relaxed);
    let r = unsafe { strtok_r(s, delim, &mut save) };
    STRTOK_SAVE.store(save, Ordering::Relaxed);
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn basename(path: *const c_char) -> *mut c_char {
    let p = unsafe { strrchr(path, c_int::from(b'/')) };
    if p.is_null() { path as *mut c_char } else { unsafe { p.add(1) } }
}

#[inline(always)]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strverscmp(s1: *const c_char, s2: *const c_char) -> c_int {
    const S_N: usize = 0;
    const S_I: usize = 3;
    const S_F: usize = 6;
    const S_Z: usize = 9;
    const CMP: i8 = 2;
    const LEN: i8 = 3;
    const NEXT_STATE: [usize; 12] = [S_N, S_I, S_Z, S_N, S_I, S_I, S_N, S_F, S_F, S_N, S_F, S_Z];
    const RESULT_TYPE: [i8; 36] = [
        CMP, CMP, CMP, CMP, LEN, CMP, CMP, CMP, CMP,
        CMP, -1, -1, 1, LEN, LEN, 1, LEN, LEN,
        CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP,
        CMP, 1, 1, -1, CMP, CMP, -1, CMP, CMP,
    ];
    if core::ptr::eq(s1, s2) {
        return 0;
    }
    let mut i = 0;
    let mut c1 = unsafe { at(s1, 0) };
    let mut c2 = unsafe { at(s2, 0) };
    i += 1;
    let mut state = S_N + usize::from(c1 == b'0') + usize::from(is_digit(c1));
    while c1 == c2 {
        if c1 == 0 {
            return 0;
        }
        state = NEXT_STATE[state];
        c1 = unsafe { at(s1, i) };
        c2 = unsafe { at(s2, i) };
        i += 1;
        state += usize::from(c1 == b'0') + usize::from(is_digit(c1));
    }
    let diff = c_int::from(c1) - c_int::from(c2);
    let kind = RESULT_TYPE[state * 3 + usize::from(c2 == b'0') + usize::from(is_digit(c2))];
    match kind {
        CMP => diff,
        LEN => {
            let mut j = i;
            loop {
                if !is_digit(unsafe { at(s1, j) }) {
                    break;
                }
                if !is_digit(unsafe { at(s2, j) }) {
                    return 1;
                }
                j += 1;
            }
            if is_digit(unsafe { at(s2, j) }) { -1 } else { diff }
        }
        other => c_int::from(other),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { stpcpy(dest, src) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    unsafe { stpncpy(dest, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    unsafe { strtok_r(s, delim, saveptr) }
}

