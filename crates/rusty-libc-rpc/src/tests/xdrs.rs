//! XDR: every primitive and composite routine through glibc's and our code, on glibc's and our memory
//! streams, compared byte for byte (also record streams, stdio streams, `xdr_sizeof`, `xdr_free`).
use super::*;
use crate::xdr::{x_getpos, x_inline, x_setpos};

pub(crate) fn mk(api: &Api, op: c_int, buf: &mut [u8]) -> XDR {
    let mut x = XDR::zeroed();
    unsafe { (api.xdrmem_create)(&mut x, buf.as_mut_ptr().cast(), buf.len() as u_int, op) };
    x
}

type Prim<T> = unsafe extern "C" fn(X, *mut T) -> B;

/// Encode `v` into a buffer of `size` bytes (filled with 0xAA): (result, buffer, position).
fn enc<T: Copy>(f: Prim<T>, mem: &Api, size: usize, mut v: T) -> (B, Vec<u8>, u32) {
    let mut buf = vec![0xAAu8; size];
    let mut x = mk(mem, XDR_ENCODE, &mut buf);
    let r = unsafe { f(&mut x, &mut v) };
    let pos = unsafe { x_getpos(&x) };
    (r, buf, pos)
}

fn dec<T: Copy + Default>(f: Prim<T>, mem: &Api, bytes: &[u8]) -> (B, T, u32) {
    let mut buf = bytes.to_vec();
    let mut x = mk(mem, XDR_DECODE, &mut buf);
    let mut v = T::default();
    let r = unsafe { f(&mut x, &mut v) };
    let pos = unsafe { x_getpos(&x) };
    (r, v, pos)
}

/// Run one primitive through the four combinations (routine from ours/glibc on a memory stream
/// from ours/glibc) and require identical results.
fn check_prim<T: Copy + Default + PartialEq + core::fmt::Debug>(name: &str, get: fn(&Api) -> Prim<T>, genv: impl Fn(&mut Rng) -> T, bits: fn(T) -> u64) {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(0x1234_5678_9abc_def1 ^ name.len() as u64);
    for _ in 0..400 {
        let v = genv(&mut rng);
        let size = [0usize, 2, 4, 6, 8, 12, 16][rng.below(7) as usize];
        let mut first: Option<(B, Vec<u8>, u32)> = None;
        for (fname, fa) in apis.iter() {
            for (mname, ma) in apis.iter() {
                let r = enc(get(fa), ma, size, v);
                match &first {
                    None => first = Some(r),
                    Some(f) => assert_eq!(&r, f, "{name} encode {v:?} size {size}: {fname} routine on {mname} stream differs"),
                }
            }
        }
        let (ok, buf, _pos) = first.unwrap();
        // decode what was encoded (when it worked) and short / empty inputs
        let inputs: Vec<Vec<u8>> = if ok != 0 { vec![buf.clone(), buf[..buf.len().min(3)].to_vec(), Vec::new()] } else { vec![buf.clone()] };
        for inp in inputs {
            let mut first: Option<(B, T, u32)> = None;
            for (fname, fa) in apis.iter() {
                for (mname, ma) in apis.iter() {
                    let r = dec(get(fa), ma, &inp);
                    match &first {
                        None => first = Some(r),
                        Some(f) => {
                            assert_eq!((r.0, r.2), (f.0, f.2), "{name} decode {inp:02x?}: {fname} routine on {mname} stream differs");
                            if f.0 != 0 {
                                assert_eq!(bits(r.1), bits(f.1), "{name} decode {inp:02x?}: value differs ({fname} on {mname})");
                            }
                        }
                    }
                }
            }
        }
    }
}

macro_rules! prim_tests {
    ($( $test:ident, $f:ident, $t:ty, $gen:expr, $bits:expr );* $(;)?) => {
        $( #[test] fn $test() { check_prim::<$t>(stringify!($f), |a| a.$f, $gen, $bits); } )*
    };
}

prim_tests! {
    t_int, xdr_int, c_int, |r| r.edge_i64() as c_int, |v| v as u64;
    t_u_int, xdr_u_int, u_int, |r| r.edge_i64() as u_int, |v| v as u64;
    t_long, xdr_long, c_long, |r| r.edge_i64(), |v| v as u64;
    t_u_long, xdr_u_long, u_long, |r| r.edge_i64() as u64, |v| v;
    t_short, xdr_short, i16, |r| r.edge_i64() as i16, |v| v as u64;
    t_u_short, xdr_u_short, u16, |r| r.edge_i64() as u16, |v| v as u64;
    t_char, xdr_char, c_char, |r| r.edge_i64() as c_char, |v| v as u64;
    t_u_char, xdr_u_char, u8, |r| r.edge_i64() as u8, |v| v as u64;
    t_bool, xdr_bool, c_int, |r| r.edge_i64() as c_int, |v| v as u64;
    t_enum, xdr_enum, c_int, |r| r.edge_i64() as c_int, |v| v as u64;
    t_hyper, xdr_hyper, i64, |r| r.edge_i64(), |v| v as u64;
    t_u_hyper, xdr_u_hyper, u64, |r| r.edge_i64() as u64, |v| v;
    t_longlong, xdr_longlong_t, i64, |r| r.edge_i64(), |v| v as u64;
    t_u_longlong, xdr_u_longlong_t, u64, |r| r.edge_i64() as u64, |v| v;
    t_quad, xdr_quad_t, i64, |r| r.edge_i64(), |v| v as u64;
    t_u_quad, xdr_u_quad_t, u64, |r| r.edge_i64() as u64, |v| v;
    t_int8, xdr_int8_t, i8, |r| r.edge_i64() as i8, |v| v as u64;
    t_uint8, xdr_uint8_t, u8, |r| r.edge_i64() as u8, |v| v as u64;
    t_int16, xdr_int16_t, i16, |r| r.edge_i64() as i16, |v| v as u64;
    t_uint16, xdr_uint16_t, u16, |r| r.edge_i64() as u16, |v| v as u64;
    t_int32, xdr_int32_t, i32, |r| r.edge_i64() as i32, |v| v as u64;
    t_uint32, xdr_uint32_t, u32, |r| r.edge_i64() as u32, |v| v as u64;
    t_int64, xdr_int64_t, i64, |r| r.edge_i64(), |v| v as u64;
    t_uint64, xdr_uint64_t, u64, |r| r.edge_i64() as u64, |v| v;
    t_float, xdr_float, f32, |r| match r.below(6) { 0 => f32::NAN, 1 => f32::INFINITY, 2 => -0.0, 3 => f32::MIN_POSITIVE / 4.0, _ => f32::from_bits(r.next() as u32) }, |v| v.to_bits() as u64;
    t_double, xdr_double, f64, |r| match r.below(6) { 0 => f64::NAN, 1 => f64::NEG_INFINITY, 2 => -0.0, 3 => f64::MIN_POSITIVE / 4.0, _ => f64::from_bits(r.next()) }, |v| v.to_bits();
}

/// FREE does nothing and succeeds for all primitives; an invalid operation fails.
#[test]
fn free_and_invalid_operations() {
    let _g = lock();
    for (name, a) in both() {
        for op in [XDR_FREE, 3, 77] {
            let mut buf = [0u8; 16];
            let mut x = mk(&a, op, &mut buf);
            let mut i: c_int = 5;
            let mut l: c_long = 5;
            let mut h: i64 = 5;
            let mut f: f32 = 1.0;
            let mut d: f64 = 1.0;
            let res = unsafe { [(a.xdr_int)(&mut x, &mut i), (a.xdr_long)(&mut x, &mut l), (a.xdr_hyper)(&mut x, &mut h), (a.xdr_float)(&mut x, &mut f), (a.xdr_double)(&mut x, &mut d), (a.xdr_void)()] };
            let want = if op == XDR_FREE { [1, 1, 1, 1, 1, 1] } else { [0, 0, 0, 0, 0, 1] };
            assert_eq!(res, want, "{name} op {op}");
            assert_eq!((i, l, h), (5, 5, 5));
        }
    }
}

#[test]
fn known_encodings() {
    let _g = lock();
    for (name, a) in both() {
        let mut buf = [0u8; 16];
        let mut x = mk(&a, XDR_ENCODE, &mut buf);
        let mut d: f64 = 1.5;
        let mut i: c_int = -2;
        unsafe {
            assert_eq!((a.xdr_double)(&mut x, &mut d), 1);
            assert_eq!((a.xdr_int)(&mut x, &mut i), 1);
        }
        assert_eq!(buf[..12], [0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xfe], "{name}");
    }
}

// ---- composites

type Str = *mut c_char;

fn cstring(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.push(0);
    v
}

fn cstr_at(p: Str) -> Option<Vec<u8>> {
    if p.is_null() { None } else { Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()) }
}

#[test]
fn strings_and_wrapstring() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(99);
    for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 255, 256, 1000] {
        let s: Vec<u8> = (0..len).map(|_| 1 + rng.below(255) as u8).collect();
        let cs = cstring(&s);
        for max in [LASTUNSIGNED, len as u32, (len as u32).wrapping_sub(1), 0, 5] {
            for size in [0usize, 4, 8, 3 + len, 4 + len, 4 + len.div_ceil(4) * 4, 8 + len.div_ceil(4) * 4] {
                let mut results = Vec::new();
                for (fname, fa) in apis.iter() {
                    for (mname, ma) in apis.iter() {
                        let mut buf = vec![0xCCu8; size];
                        let mut x = mk(ma, XDR_ENCODE, &mut buf);
                        let mut p = cs.as_ptr() as Str;
                        let r = unsafe { (fa.xdr_string)(&mut x, &mut p, max) };
                        results.push(((fname, mname), r, buf, unsafe { x_getpos(&x) }));
                    }
                }
                for r in &results[1..] {
                    assert_eq!((r.1, &r.2, r.3), (results[0].1, &results[0].2, results[0].3), "string len {len} max {max} size {size}: {:?} vs {:?}", r.0, results[0].0);
                }
                // decode (allocating and into a given buffer) and free
                if results[0].1 != 0 {
                    let enc_bytes = results[0].2.clone();
                    for (fname, fa) in apis.iter() {
                        let mut b = enc_bytes.clone();
                        let mut x = mk(fa, XDR_DECODE, &mut b);
                        let mut p: Str = core::ptr::null_mut();
                        let r = unsafe { (fa.xdr_string)(&mut x, &mut p, max) };
                        assert_eq!(r, 1, "{fname}");
                        assert_eq!(cstr_at(p).unwrap(), s, "{fname} decoded string");
                        unsafe { (fa.xdr_free)(crate::xproc!(fa.xdr_wrapstring), (&raw mut p).cast()) };
                        assert!(p.is_null(), "{fname}: xdr_free did not clear the pointer");
                        // into a buffer
                        let mut dst = vec![0x55u8; len + 8];
                        let mut b = enc_bytes.clone();
                        let mut x = mk(fa, XDR_DECODE, &mut b);
                        let mut p = dst.as_mut_ptr() as Str;
                        let r = unsafe { (fa.xdr_string)(&mut x, &mut p, max) };
                        assert_eq!(r, 1);
                        assert_eq!(&dst[..len + 1], &cs[..], "{fname} decoded into buffer");
                    }
                }
            }
        }
    }
    // a NULL string cannot be encoded; freeing NULL is fine
    for (name, a) in apis.iter() {
        let mut buf = [0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut p: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_string)(&mut x, &mut p, 100) }, 0, "{name}");
        assert_eq!(unsafe { (a.xdr_wrapstring)(&mut x, &mut p) }, 0, "{name}");
        let mut x = mk(a, XDR_FREE, &mut buf);
        assert_eq!(unsafe { (a.xdr_string)(&mut x, &mut p, 100) }, 1, "{name}");
    }
    // a length that overflows size + 1 is refused
    for (name, a) in apis.iter() {
        let mut b = [0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        let mut x = mk(a, XDR_DECODE, &mut b);
        let mut p: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_string)(&mut x, &mut p, LASTUNSIGNED) }, 0, "{name} huge length");
        assert!(p.is_null());
    }
}

#[test]
fn opaque_and_bytes() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(7);
    for cnt in 0u32..14 {
        let data = rng.bytes(cnt as usize);
        let mut results = Vec::new();
        for (fname, fa) in apis.iter() {
            for (mname, ma) in apis.iter() {
                let mut buf = vec![0xCCu8; 24];
                let mut x = mk(ma, XDR_ENCODE, &mut buf);
                let mut d = data.clone();
                d.push(0);
                let r = unsafe { (fa.xdr_opaque)(&mut x, d.as_mut_ptr().cast(), cnt) };
                results.push(((fname, mname), r, buf, unsafe { x_getpos(&x) }));
            }
        }
        for r in &results[1..] {
            assert_eq!((r.1, &r.2, r.3), (results[0].1, &results[0].2, results[0].3), "opaque {cnt}");
        }
        // padding is zeros
        let padded = (cnt as usize).div_ceil(4) * 4;
        assert!(results[0].2[cnt as usize..padded].iter().all(|&b| b == 0));
        // decode
        for (fname, fa) in apis.iter() {
            let mut dst = vec![0u8; cnt as usize + 4];
            let mut b = results[0].2.clone();
            let mut x = mk(fa, XDR_DECODE, &mut b);
            assert_eq!(unsafe { (fa.xdr_opaque)(&mut x, dst.as_mut_ptr().cast(), cnt) }, 1, "{fname}");
            assert_eq!(&dst[..cnt as usize], &data[..], "{fname}");
            assert_eq!(unsafe { x_getpos(&x) } as usize, padded);
        }
        // bytes: lengths against maxsize
        for max in [LASTUNSIGNED, cnt, cnt.wrapping_sub(1)] {
            let mut results = Vec::new();
            for (fname, fa) in apis.iter() {
                let mut buf = vec![0xCCu8; 4 + padded];
                let mut x = mk(fa, XDR_ENCODE, &mut buf);
                let mut d = data.clone();
                d.push(0);
                let mut p = d.as_mut_ptr() as Str;
                let mut n = cnt;
                let r = unsafe { (fa.xdr_bytes)(&mut x, &mut p, &mut n, max) };
                results.push((fname, r, buf, n));
            }
            assert_eq!((results[0].1, &results[0].2, results[0].3), (results[1].1, &results[1].2, results[1].3), "bytes {cnt} max {max}");
            if results[0].1 != 0 {
                for (fname, fa) in apis.iter() {
                    let mut b = results[0].2.clone();
                    let mut x = mk(fa, XDR_DECODE, &mut b);
                    let mut p: Str = core::ptr::null_mut();
                    let mut n = 0;
                    let r = unsafe { (fa.xdr_bytes)(&mut x, &mut p, &mut n, max) };
                    assert_eq!((r, n), (1, cnt), "{fname}");
                    if cnt != 0 {
                        assert_eq!(unsafe { core::slice::from_raw_parts(p as *const u8, cnt as usize) }, &data[..], "{fname}");
                    } else {
                        assert!(p.is_null(), "{fname}: zero length leaves the pointer alone");
                    }
                    let mut x = mk(fa, XDR_FREE, &mut b);
                    let r = unsafe { (fa.xdr_bytes)(&mut x, &mut p, &mut n, max) };
                    assert_eq!(r, 1);
                    assert!(p.is_null());
                }
            }
        }
    }
}

#[test]
fn netobj_roundtrip() {
    let _g = lock();
    let apis = both();
    let data = [1u8, 2, 3, 4, 5];
    let mut out = Vec::new();
    for (name, a) in apis.iter() {
        let mut buf = vec![0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut n = netobj { n_len: 5, n_bytes: data.as_ptr() as Str };
        assert_eq!(unsafe { (a.xdr_netobj)(&mut x, &mut n) }, 1, "{name}");
        out.push(buf.clone());
        let mut x = mk(a, XDR_DECODE, &mut buf);
        let mut n = netobj { n_len: 0, n_bytes: core::ptr::null_mut() };
        assert_eq!(unsafe { (a.xdr_netobj)(&mut x, &mut n) }, 1);
        assert_eq!(unsafe { core::slice::from_raw_parts(n.n_bytes as *const u8, n.n_len as usize) }, &data);
        let mut x = mk(a, XDR_FREE, &mut buf);
        unsafe { (a.xdr_netobj)(&mut x, &mut n) };
        assert!(n.n_bytes.is_null());
    }
    assert_eq!(out[0], out[1]);
    // longer than MAX_NETOBJ_SZ fails
    for (name, a) in apis.iter() {
        let mut buf = vec![0u8; 4096];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut n = netobj { n_len: 1025, n_bytes: buf.as_mut_ptr().cast() };
        assert_eq!(unsafe { (a.xdr_netobj)(&mut x, &mut n) }, 0, "{name}");
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug)]
struct Pair {
    a: c_int,
    b: c_int,
}

unsafe extern "C" fn xdr_pair(x: X, p: *mut Pair) -> B {
    unsafe { (crate::xdr::xdr_int(x, &raw mut (*p).a) != 0 && crate::xdr::xdr_int(x, &raw mut (*p).b) != 0) as B }
}

fn pair_proc() -> xdrproc_t {
    crate::xproc!(xdr_pair as unsafe extern "C" fn(X, *mut Pair) -> B)
}

fn int_proc(a: &Api) -> xdrproc_t {
    crate::xproc!(a.xdr_int)
}

#[test]
fn arrays_vectors_references_pointers() {
    let _g = lock();
    let apis = both();
    // vector of ints
    for (name, a) in apis.iter() {
        let mut v = [1i32, -2, 3, 40000];
        let mut buf = vec![0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        assert_eq!(unsafe { (a.xdr_vector)(&mut x, v.as_mut_ptr().cast(), 4, 4, int_proc(a)) }, 1, "{name}");
        assert_eq!(&buf[..8], &[0, 0, 0, 1, 0xff, 0xff, 0xff, 0xfe]);
        let mut small = vec![0u8; 12];
        let mut x = mk(a, XDR_ENCODE, &mut small);
        assert_eq!(unsafe { (a.xdr_vector)(&mut x, v.as_mut_ptr().cast(), 4, 4, int_proc(a)) }, 0, "{name} too small");
    }
    // array
    let mut outs = Vec::new();
    for (name, a) in apis.iter() {
        let vals = [10i32, 20, 30];
        let mut p = vals.as_ptr() as Str;
        let mut n = 3u32;
        let mut buf = vec![0u8; 32];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, 10, 4, int_proc(a)) }, 1, "{name}");
        outs.push(buf.clone());
        // too many elements for maxsize
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut n = 3u32;
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, 2, 4, int_proc(a)) }, 0, "{name} maxsize");
        // decode allocating
        let mut x = mk(a, XDR_DECODE, &mut buf);
        let mut p: Str = core::ptr::null_mut();
        let mut n = 0u32;
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, 10, 4, int_proc(a)) }, 1, "{name}");
        assert_eq!(n, 3);
        assert_eq!(unsafe { core::slice::from_raw_parts(p as *const i32, 3) }, &vals);
        let mut x = mk(a, XDR_FREE, &mut buf);
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, 10, 4, int_proc(a)) }, 1);
        assert!(p.is_null(), "{name}: array freed");
        // decode with element count 0: nothing allocated
        let mut z = [0u8; 4];
        let mut x = mk(a, XDR_DECODE, &mut z);
        let mut p: Str = core::ptr::null_mut();
        let mut n = 9u32;
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, 10, 4, int_proc(a)) }, 1);
        assert!(p.is_null() && n == 0);
        // an element size that makes count * size overflow
        let mut big = [0x10u8, 0, 0, 0];
        let mut x = mk(a, XDR_DECODE, &mut big);
        let mut p: Str = core::ptr::null_mut();
        let mut n = 0u32;
        assert_eq!(unsafe { (a.xdr_array)(&mut x, &mut p, &mut n, LASTUNSIGNED, 0x1000_0000, int_proc(a)) }, 0, "{name} overflow");
    }
    assert_eq!(outs[0], outs[1]);
    // reference and pointer
    for (name, a) in apis.iter() {
        let mut pr = Pair { a: 1, b: 2 };
        let mut buf = vec![0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut p = (&mut pr as *mut Pair).cast::<c_char>();
        assert_eq!(unsafe { (a.xdr_reference)(&mut x, &mut p, 8, pair_proc()) }, 1);
        let mut x = mk(a, XDR_DECODE, &mut buf);
        let mut q: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_reference)(&mut x, &mut q, 8, pair_proc()) }, 1);
        assert_eq!(unsafe { *(q as *mut Pair) }, pr, "{name}");
        let mut x = mk(a, XDR_FREE, &mut buf);
        assert_eq!(unsafe { (a.xdr_reference)(&mut x, &mut q, 8, pair_proc()) }, 1);
        assert!(q.is_null());
        // pointer: present and absent
        let mut buf = vec![0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        let mut p = (&mut pr as *mut Pair).cast::<c_char>();
        assert_eq!(unsafe { (a.xdr_pointer)(&mut x, &mut p, 8, pair_proc()) }, 1);
        assert_eq!(unsafe { x_getpos(&x) }, 12);
        let mut nul = [0u8; 8];
        let mut x = mk(a, XDR_ENCODE, &mut nul);
        let mut p: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_pointer)(&mut x, &mut p, 8, pair_proc()) }, 1);
        assert_eq!((unsafe { x_getpos(&x) }, nul[3]), (4, 0));
        let mut x = mk(a, XDR_DECODE, &mut buf);
        let mut q: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_pointer)(&mut x, &mut q, 8, pair_proc()) }, 1);
        assert_eq!(unsafe { *(q as *mut Pair) }, pr);
        let mut x = mk(a, XDR_FREE, &mut buf);
        unsafe { (a.xdr_pointer)(&mut x, &mut q, 8, pair_proc()) };
        assert!(q.is_null());
        // pointer to NULL decoded from a zero flag
        let mut zero = [0u8; 4];
        let mut x = mk(a, XDR_DECODE, &mut zero);
        let mut q: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_pointer)(&mut x, &mut q, 8, pair_proc()) }, 1);
        assert!(q.is_null());
    }
}

#[test]
fn unions() {
    let _g = lock();
    let apis = both();
    for (name, a) in apis.iter() {
        let table = [
            xdr_discrim { value: 1, proc_: int_proc(a) },
            xdr_discrim { value: 2, proc_: pair_proc() },
            xdr_discrim { value: DONTCARE, proc_: None },
        ];
        for (disc, dflt) in [(1, None), (2, None), (3, None), (3, int_proc(a))] {
            let mut u = [0u8; 8];
            u[..4].copy_from_slice(&0x0102_0304i32.to_ne_bytes());
            u[4..].copy_from_slice(&0x0506_0708i32.to_ne_bytes());
            let mut buf = vec![0u8; 16];
            let mut x = mk(a, XDR_ENCODE, &mut buf);
            let mut d = disc;
            let r = unsafe { (a.xdr_union)(&mut x, &mut d, u.as_mut_ptr().cast(), table.as_ptr(), dflt) };
            let want = matches!((disc, dflt.is_some()), (1, _) | (2, _) | (3, true)) as c_int;
            assert_eq!(r, want, "{name} disc {disc}");
            let len = unsafe { x_getpos(&x) };
            assert_eq!(len, match (disc, want) { (1, _) => 8, (2, _) => 12, (3, 1) => 8, _ => 4 }, "{name} disc {disc}");
        }
    }
}

#[test]
fn sizeof() {
    let _g = lock();
    for (name, a) in both() {
        let mut v: c_int = 5;
        assert_eq!(unsafe { (a.xdr_sizeof)(int_proc(&a), (&mut v as *mut c_int).cast()) }, 4, "{name}");
        let mut pr = Pair::default();
        assert_eq!(unsafe { (a.xdr_sizeof)(pair_proc(), (&mut pr as *mut Pair).cast()) }, 8, "{name}");
        let mut s = *b"hello\0";
        let mut p = s.as_mut_ptr() as Str;
        assert_eq!(unsafe { (a.xdr_sizeof)(crate::xproc!(a.xdr_wrapstring), (&raw mut p).cast()) }, 12, "{name}");
        let mut d = 1.0f64;
        assert_eq!(unsafe { (a.xdr_sizeof)(crate::xproc!(a.xdr_double), (&mut d as *mut f64).cast()) }, 8);
        // a failing routine gives 0
        let mut np: Str = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_sizeof)(crate::xproc!(a.xdr_wrapstring), (&raw mut np).cast()) }, 0, "{name}");
    }
}

#[test]
fn memory_stream_positions() {
    let _g = lock();
    for (name, a) in both() {
        let mut buf = vec![0u8; 20];
        let mut x = mk(&a, XDR_ENCODE, &mut buf);
        unsafe {
            assert_eq!(x_getpos(&x), 0, "{name}");
            let mut i = 7;
            (a.xdr_int)(&mut x, &mut i);
            assert_eq!(x_getpos(&x), 4);
            assert_eq!(x_setpos(&mut x, 12), 1, "{name}");
            assert_eq!(x_getpos(&x), 12);
            assert_eq!(x.x_handy, 8);
            assert_eq!(x_setpos(&mut x, 20), 1, "{name}: end of the buffer is a valid position");
            assert_eq!(x_setpos(&mut x, 21), 0, "{name}");
            assert_eq!(x_getpos(&x), 20);
            assert_eq!(x_setpos(&mut x, 0), 1);
            // inline: len fits, then not
            let p = x_inline(&mut x, 8);
            assert_eq!(p as usize, buf.as_ptr() as usize, "{name}");
            assert!(x_inline(&mut x, 13).is_null());
            assert!(!x_inline(&mut x, 12).is_null());
            assert!(x_inline(&mut x, 1).is_null());
        }
    }
}

// ---- xdrstdio

#[test]
fn stdio_streams() {
    use std::ffi::CString;
    let _g = lock();
    let dir = std::env::temp_dir().join(format!("rpc-xdrstdio-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    for (name, a) in both() {
        let path = dir.join(format!("{name}.xdr"));
        let cp = CString::new(path.to_str().unwrap()).unwrap();
        // the FILE comes from the implementation that owns the stream code
        let (f, close): (*mut c_void, Box<dyn Fn(*mut c_void)>) = if name == "glibc" {
            (unsafe { libc::fopen(cp.as_ptr(), c"w+".as_ptr()) as *mut c_void }, Box::new(|f| unsafe { assert_eq!(libc::fclose(f as *mut libc::FILE), 0) }))
        } else {
            (unsafe { rusty_libc_stdio::file_api::fopen(cp.as_ptr(), c"w+".as_ptr()) as *mut c_void }, Box::new(|f| unsafe { assert_eq!(rusty_libc_stdio::file_api::fclose(f.cast()), 0) }))
        };
        assert!(!f.is_null());
        let mut x = XDR::zeroed();
        unsafe { (a.xdrstdio_create)(&mut x, f, XDR_ENCODE) };
        let mut rng = Rng(5);
        unsafe {
            for _ in 0..50 {
                let mut i = rng.edge_i64() as c_int;
                assert_eq!((a.xdr_int)(&mut x, &mut i), 1);
                let mut h = rng.edge_i64();
                assert_eq!((a.xdr_hyper)(&mut x, &mut h), 1);
                let mut d = f64::from_bits(rng.next());
                assert_eq!((a.xdr_double)(&mut x, &mut d), 1);
                let n = rng.below(20) as usize;
                let s = cstring(&rng.bytes(n).iter().map(|b| b | 1).collect::<Vec<_>>());
                let mut p = s.as_ptr() as Str;
                assert_eq!((a.xdr_string)(&mut x, &mut p, LASTUNSIGNED), 1);
            }
            assert_eq!(x_getpos(&x) as usize % 4, 0);
            let pos = x_getpos(&x);
            assert!(pos > 100);
            assert_eq!(x_setpos(&mut x, 8), 1, "{name}");
            assert_eq!(x_getpos(&x), 8);
            assert!(x_inline(&mut x, 4).is_null());
            crate::xdr::x_destroy(&mut x); // fflush
        }
        close(f);
        files.push(std::fs::read(&path).unwrap());
        // read it back through the stream decoder and compare against the file contents
        let (f, close): (*mut c_void, Box<dyn Fn(*mut c_void)>) = if name == "glibc" {
            (unsafe { libc::fopen(cp.as_ptr(), c"r".as_ptr()) as *mut c_void }, Box::new(|f| unsafe { assert_eq!(libc::fclose(f as *mut libc::FILE), 0) }))
        } else {
            (unsafe { rusty_libc_stdio::file_api::fopen(cp.as_ptr(), c"r".as_ptr()) as *mut c_void }, Box::new(|f| unsafe { assert_eq!(rusty_libc_stdio::file_api::fclose(f.cast()), 0) }))
        };
        let mut x = XDR::zeroed();
        unsafe { (a.xdrstdio_create)(&mut x, f, XDR_DECODE) };
        let mut rng = Rng(5);
        unsafe {
            for _ in 0..50 {
                let mut i: c_int = 0;
                assert_eq!((a.xdr_int)(&mut x, &mut i), 1);
                assert_eq!(i, rng.edge_i64() as c_int);
                let mut h = 0i64;
                assert_eq!((a.xdr_hyper)(&mut x, &mut h), 1);
                assert_eq!(h, rng.edge_i64());
                let mut d = 0f64;
                assert_eq!((a.xdr_double)(&mut x, &mut d), 1);
                assert_eq!(d.to_bits(), rng.next());
                let n = rng.below(20) as usize;
                let want = cstring(&rng.bytes(n).iter().map(|b| b | 1).collect::<Vec<_>>());
                let mut p: Str = core::ptr::null_mut();
                assert_eq!((a.xdr_string)(&mut x, &mut p, LASTUNSIGNED), 1);
                assert_eq!(cstr_at(p).unwrap(), &want[..want.len() - 1]);
                (a.xdr_free)(crate::xproc!(a.xdr_wrapstring), (&raw mut p).cast());
            }
            // end of file: the next read fails
            let mut i: c_int = 0;
            assert_eq!((a.xdr_int)(&mut x, &mut i), 0, "{name}");
        }
        close(f);
    }
    assert_eq!(files[0], files[1], "stdio streams write the same bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- record streams

struct Pipe {
    written: Vec<u8>,
    to_read: Vec<u8>,
    pos: usize,
    chunk: usize,
    writes: Vec<usize>,
}

unsafe extern "C" fn rec_write(h: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let p = unsafe { &mut *(h as *mut Pipe) };
    p.written.extend_from_slice(unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) });
    p.writes.push(len as usize);
    len
}

unsafe extern "C" fn rec_read(h: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let p = unsafe { &mut *(h as *mut Pipe) };
    let n = (p.to_read.len() - p.pos).min(len as usize).min(p.chunk);
    if n == 0 {
        return -1;
    }
    unsafe { core::ptr::copy_nonoverlapping(p.to_read.as_ptr().add(p.pos), buf as *mut u8, n) };
    p.pos += n;
    n as c_int
}

fn new_pipe(to_read: Vec<u8>, chunk: usize) -> Box<Pipe> {
    Box::new(Pipe { written: Vec::new(), to_read, pos: 0, chunk, writes: Vec::new() })
}

#[test]
fn record_streams_write() {
    let _g = lock();
    let apis = both();
    for (sendsize, nrec, recbytes) in [(0u32, 3usize, 40usize), (100, 5, 700), (4000, 4, 9000), (0, 2, 12001), (222, 6, 1)] {
        let mut outs = Vec::new();
        for (name, a) in apis.iter() {
            let mut pipe = new_pipe(Vec::new(), 1);
            let mut x = XDR::zeroed();
            unsafe {
                (a.xdrrec_create)(&mut x, sendsize, 0, (&mut *pipe as *mut Pipe).cast(), Some(rec_read), Some(rec_write));
                x.x_op = XDR_ENCODE;
                for r in 0..nrec {
                    for i in 0..(recbytes / 4) as i32 {
                        let mut v = (r as i32) * 100_000 + i;
                        assert_eq!((a.xdr_int)(&mut x, &mut v), 1, "{name}");
                    }
                    let sendnow = r % 2 == 0;
                    assert_eq!((a.xdrrec_endofrecord)(&mut x, sendnow as B), 1, "{name}");
                }
                assert_eq!((a.xdrrec_endofrecord)(&mut x, 1), 1);
                crate::xdr::x_destroy(&mut x);
            }
            outs.push((name, pipe.written.clone(), pipe.writes.clone()));
        }
        assert_eq!(outs[0].1, outs[1].1, "record stream bytes, sendsize {sendsize} records {nrec} x {recbytes}");
        assert_eq!(outs[0].2, outs[1].2, "write call sizes, sendsize {sendsize} records {nrec} x {recbytes}");
    }
}

#[test]
fn record_streams_read() {
    let _g = lock();
    let apis = both();
    // build a stream of records with several fragments by hand
    let mut stream = Vec::new();
    let mut want_records: Vec<Vec<i32>> = Vec::new();
    let mut rng = Rng(2024);
    for _ in 0..6 {
        let nfrag = 1 + rng.below(4);
        let mut rec = Vec::new();
        for f in 0..nfrag {
            let words = 1 + rng.below(30) as usize;
            let hdr = (words * 4) as u32 | if f + 1 == nfrag { 1 << 31 } else { 0 };
            stream.extend_from_slice(&hdr.to_be_bytes());
            for _ in 0..words {
                let v = rng.next() as i32;
                stream.extend_from_slice(&v.to_be_bytes());
                rec.push(v);
            }
        }
        want_records.push(rec);
    }
    for chunk in [1usize, 3, 7, 100, 100000] {
        for (name, a) in apis.iter() {
            let mut pipe = new_pipe(stream.clone(), chunk);
            let mut x = XDR::zeroed();
            unsafe {
                (a.xdrrec_create)(&mut x, 0, 0, (&mut *pipe as *mut Pipe).cast(), Some(rec_read), Some(rec_write));
                x.x_op = XDR_DECODE;
                for (ri, rec) in want_records.iter().enumerate() {
                    assert_eq!((a.xdrrec_skiprecord)(&mut x), 1, "{name} chunk {chunk} record {ri}");
                    // read a prefix of the record, skip the rest on the next skiprecord
                    let take = if ri % 2 == 0 { rec.len() } else { rec.len() / 2 };
                    for (k, w) in rec.iter().take(take).enumerate() {
                        let mut v: c_int = 0;
                        assert_eq!((a.xdr_int)(&mut x, &mut v), 1, "{name} chunk {chunk} record {ri} word {k}");
                        assert_eq!(v, *w);
                    }
                    if ri % 2 == 0 {
                        // past the end of the record
                        let mut v: c_int = 0;
                        assert_eq!((a.xdr_int)(&mut x, &mut v), 0, "{name}: reading past the record end");
                        // the failed read must not be fatal for the next record
                    }
                }
                // the rest of the last record is skipped, then there is no more input
                assert_eq!((a.xdrrec_skiprecord)(&mut x), 1, "{name} chunk {chunk}: skip the rest of the last record");
                assert_eq!((a.xdrrec_skiprecord)(&mut x), 0, "{name} chunk {chunk}: nothing left");
                assert_eq!((a.xdrrec_eof)(&mut x), 1, "{name}");
            }
        }
    }
}
