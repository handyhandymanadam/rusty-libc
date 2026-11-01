//! XDR (RFC 4506): the primitive and composite routines, the memory stream (`xdrmem_create`), `xdr_free`
//! and `xdr_sizeof`. A port of Sun's `xdr.c`, `xdr_mem.c`, `xdr_array.c`, `xdr_ref.c`, `xdr_intXX_t.c`,
//! `xdr_float.c` and `xdr_sizeof.c` as glibc 2.43 ships them (BSD-3-clause licence of Sun's code).
//!
//! Thin C shells: each exported routine turns its raw arguments into an [`XdrStream`] and references once and calls the
//! safe codec in stream.rs. What stays unsafe here is what the C interface makes so: object pointers handed to C
//! `xdrproc_t` callbacks (unions, arrays, references), buffers the caller owns and frees with `free`, and the memory
//! stream's cursor, which lives in the C handle.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use rusty_libc_core::ffi::{bytes, bytes_mut};

// ---- the operations of a stream (the XDR_GETLONG family of macros), for callers that hold a raw handle

/// `XDR_GETPOS` on a handle that is only read.
///
/// # Safety
/// `x` is a live stream.
#[inline]
pub unsafe fn x_getpos(x: *const XDR) -> u_int {
    // SAFETY: `x` points to a live handle (caller's contract).
    let x = unsafe { &*x };
    // SAFETY: a live stream's operations table is valid.
    let ops = unsafe { &*x.x_ops };
    match ops.x_getpostn {
        // SAFETY: the stream contract: the callback reads the handle it gets.
        Some(f) => unsafe { f(x) },
        None => 0,
    }
}

/// `XDR_SETPOS`.
///
/// # Safety
/// `x` is a live stream.
#[inline]
pub unsafe fn x_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    // SAFETY: `x` is a live stream (caller's contract).
    unsafe { XdrStream::from_ptr(x) }.setpos(pos)
}

/// `XDR_INLINE`.
///
/// # Safety
/// `x` is a live stream.
#[inline]
pub unsafe fn x_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    // SAFETY: `x` is a live stream (caller's contract).
    unsafe { XdrStream::from_ptr(x) }.inline_ptr(len)
}

/// `XDR_DESTROY`.
///
/// # Safety
/// `x` is a live stream.
#[inline]
pub unsafe fn x_destroy(x: *mut XDR) {
    // SAFETY: `x` is a live stream (caller's contract).
    unsafe { XdrStream::from_ptr(x) }.destroy()
}

#[inline]
pub fn rndup(x: u_int) -> u_int {
    (x.wrapping_add(BYTES_PER_XDR_UNIT - 1)) & !(BYTES_PER_XDR_UNIT - 1)
}

/// Call an `xdrproc_t` the way Sun's code does: with the extra `LASTUNSIGNED` argument.
///
/// # Safety
/// `x` is a live stream; `p` is NULL or an XDR routine for the object `obj` points to.
#[inline]
pub unsafe fn call_proc(p: xdrproc_t, x: *mut XDR, obj: *mut c_void) -> bool_t {
    match p {
        Some(f) => {
            // glibc passes LASTUNSIGNED as a third argument; the routines declared with `...` may read it, ordinary ones
            // ignore it (the C calling convention allows an extra argument)
            let f = f as *const ();
            // SAFETY: the same function with one more trailing integer argument, which the x86-64 C convention passes in
            // a register the callee does not read unless it declares it.
            let g = unsafe { core::mem::transmute::<*const (), unsafe extern "C" fn(*mut XDR, *mut c_void, u_int) -> bool_t>(f) };
            // SAFETY: the routine fits the object (caller's contract).
            unsafe { g(x, obj, LASTUNSIGNED) }
        }
        None => FALSE,
    }
}

// ---- the C shells of the primitive codecs

/// The shell of a codec that, like glibc's, touches the object only when encoding or decoding (freeing a primitive is a
/// no-op, so `p` may be anything then).
///
/// # Safety
/// `xdrs` is a live stream; when it encodes or decodes, `p` points to a `T`.
#[inline(always)]
unsafe fn prim<'a, T>(xdrs: *mut XDR, p: *mut T, f: impl FnOnce(&mut XdrStream<'a>, &mut T) -> bool_t) -> bool_t {
    // SAFETY: `xdrs` is a live stream (caller's contract).
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    let op = x.op();
    if op != XDR_ENCODE && op != XDR_DECODE {
        return if op == XDR_FREE { TRUE } else { FALSE };
    }
    // SAFETY: when coding, `p` points to the object (caller's contract; glibc dereferences it too).
    f(&mut x, unsafe { &mut *p })
}

/// The shell of a codec that reads the object in every direction (`xdr_char`, `xdr_u_char` as glibc has them).
///
/// # Safety
/// `xdrs` is a live stream and `p` points to a `T`.
#[inline(always)]
unsafe fn always<'a, T>(xdrs: *mut XDR, p: *mut T, f: impl FnOnce(&mut XdrStream<'a>, &mut T) -> bool_t) -> bool_t {
    // SAFETY: `xdrs` is a live stream (caller's contract).
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: `p` points to the object (caller's contract).
    f(&mut x, unsafe { &mut *p })
}

// ---- xdr.c

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn xdr_void() -> bool_t {
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int(xdrs: *mut XDR, ip: *mut c_int) -> bool_t {
    // SAFETY: the C contract of xdr_int.
    unsafe { prim(xdrs, ip, XdrStream::int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_int(xdrs: *mut XDR, up: *mut u_int) -> bool_t {
    // SAFETY: the C contract of xdr_u_int.
    unsafe { prim(xdrs, up, XdrStream::u_int) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_long(xdrs: *mut XDR, lp: *mut c_long) -> bool_t {
    // SAFETY: the C contract of xdr_long.
    unsafe { prim(xdrs, lp, XdrStream::long) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_long(xdrs: *mut XDR, ulp: *mut u_long) -> bool_t {
    // SAFETY: the C contract of xdr_u_long.
    unsafe { prim(xdrs, ulp, XdrStream::u_long) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_hyper(xdrs: *mut XDR, llp: *mut quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_hyper.
    unsafe { prim(xdrs, llp, XdrStream::hyper) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_hyper(xdrs: *mut XDR, ullp: *mut u_quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_u_hyper.
    unsafe { prim(xdrs, ullp, XdrStream::u_hyper) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_longlong_t(xdrs: *mut XDR, llp: *mut quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_longlong_t.
    unsafe { prim(xdrs, llp, XdrStream::hyper) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_longlong_t(xdrs: *mut XDR, ullp: *mut u_quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_u_longlong_t.
    unsafe { prim(xdrs, ullp, XdrStream::u_hyper) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_short(xdrs: *mut XDR, sp: *mut core::ffi::c_short) -> bool_t {
    // SAFETY: the C contract of xdr_short.
    unsafe { prim(xdrs, sp, XdrStream::short) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_short(xdrs: *mut XDR, usp: *mut u_short) -> bool_t {
    // SAFETY: the C contract of xdr_u_short.
    unsafe { prim(xdrs, usp, XdrStream::u_short) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_char(xdrs: *mut XDR, cp: *mut c_char) -> bool_t {
    // SAFETY: the C contract of xdr_char.
    unsafe { always(xdrs, cp, XdrStream::char_) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_char(xdrs: *mut XDR, cp: *mut u_char) -> bool_t {
    // SAFETY: the C contract of xdr_u_char.
    unsafe { always(xdrs, cp, XdrStream::u_char) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bool(xdrs: *mut XDR, bp: *mut bool_t) -> bool_t {
    // SAFETY: the C contract of xdr_bool.
    unsafe { prim(xdrs, bp, XdrStream::bool_) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_enum(xdrs: *mut XDR, ep: *mut enum_t) -> bool_t {
    // SAFETY: the C contract of xdr_enum.
    unsafe { prim(xdrs, ep, XdrStream::enum_) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque(xdrs: *mut XDR, cp: caddr_t, cnt: u_int) -> bool_t {
    if cnt == 0 {
        return TRUE;
    }
    // SAFETY: the C contract of xdr_opaque: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    match x.op() {
        // SAFETY: decoding: `cp` points to `cnt` writable bytes.
        XDR_DECODE => x.opaque_decode(unsafe { bytes_mut(cp.cast(), cnt as usize) }),
        // SAFETY: encoding: `cp` points to `cnt` readable bytes.
        XDR_ENCODE => x.opaque_encode(unsafe { bytes(cp.cast(), cnt as usize) }),
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

/// `xdr_bytes` on a stream already in hand: counted opaque data in a `malloc` buffer (allocated when decoding into a NULL
/// pointer, freed and cleared when freeing).
///
/// # Safety
/// `*cpp` is NULL or points to a buffer of at least `*sizep` bytes (when decoding into an existing buffer: of the size
/// the decoded count will be) that was allocated with `malloc` if the stream frees it.
#[inline]
pub unsafe fn bytes_in(x: &mut XdrStream, cpp: &mut *mut c_char, sizep: &mut u_int, maxsize: u_int) -> bool_t {
    let mut sp = *cpp;
    if x.u_int(sizep) == 0 {
        return FALSE;
    }
    let nodesize = *sizep;
    if nodesize > maxsize && x.op() != XDR_FREE {
        return FALSE;
    }
    match x.op() {
        XDR_DECODE | XDR_ENCODE => {
            if x.op() == XDR_DECODE {
                if nodesize == 0 {
                    return TRUE;
                }
                if sp.is_null() {
                    sp = alloc(nodesize as usize) as *mut c_char;
                    *cpp = sp;
                }
                if sp.is_null() {
                    oom("xdr_bytes");
                    return FALSE;
                }
                // SAFETY: `sp` is our fresh `nodesize`-byte buffer or the caller's buffer of that size (contract).
                x.opaque(unsafe { bytes_mut(sp.cast(), nodesize as usize) })
            } else if nodesize == 0 {
                TRUE
            } else {
                // SAFETY: encoding: `sp` points to `nodesize` bytes (contract).
                x.opaque_encode(unsafe { bytes(sp.cast(), nodesize as usize) })
            }
        }
        XDR_FREE => {
            if !sp.is_null() {
                // SAFETY: a decoded buffer comes from malloc (contract).
                unsafe { mem_free(sp.cast()) };
                *cpp = core::ptr::null_mut();
            }
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bytes(xdrs: *mut XDR, cpp: *mut *mut c_char, sizep: *mut u_int, maxsize: u_int) -> bool_t {
    // SAFETY: the C contract of xdr_bytes: `cpp` points to the data pointer (glibc reads it first).
    let cpp = unsafe { &mut *cpp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: `sizep` points to the count.
    let sizep = unsafe { &mut *sizep };
    // SAFETY: `*cpp` and `*sizep` describe the caller's buffer (the C contract).
    unsafe { bytes_in(&mut x, cpp, sizep, maxsize) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netobj(xdrs: *mut XDR, np: *mut netobj) -> bool_t {
    // SAFETY: the C contract of xdr_netobj: `np` points to a netobj.
    let np = unsafe { &mut *np };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: a netobj's `n_bytes` holds `n_len` bytes.
    unsafe { bytes_in(&mut x, &mut np.n_bytes, &mut np.n_len, MAX_NETOBJ_SZ) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_union(xdrs: *mut XDR, dscmp: *mut enum_t, unp: *mut c_char, choices: *const xdr_discrim, dfault: xdrproc_t) -> bool_t {
    // SAFETY: the C contract of xdr_union: `dscmp` points to the discriminant.
    if unsafe { xdr_enum(xdrs, dscmp) } == 0 {
        return FALSE;
    }
    // SAFETY: as above (glibc reads it after coding it).
    let dscm = unsafe { *dscmp };
    let mut ch = choices;
    loop {
        // SAFETY: `choices` is an array ended by an entry with a NULL routine; `ch` has not passed that entry.
        let c = unsafe { &*ch };
        if c.proc_.is_none() {
            break;
        }
        if c.value == dscm {
            // SAFETY: the arm's routine codes the union member at `unp` (the C contract).
            return unsafe { call_proc(c.proc_, xdrs, unp.cast()) };
        }
        ch = ch.wrapping_add(1);
    }
    // SAFETY: the default routine codes the union member at `unp` (the C contract).
    if dfault.is_none() { FALSE } else { unsafe { call_proc(dfault, xdrs, unp.cast()) } }
}

/// `xdr_string` on a stream already in hand: a NUL-terminated string of at most `maxsize` bytes in a `malloc` buffer
/// (allocated when decoding into a NULL pointer, freed and cleared when freeing).
///
/// # Safety
/// `*cpp` is NULL or a NUL-terminated string (when encoding or freeing), or a buffer big enough for the decoded string
/// and its NUL (when decoding); `malloc` memory if the stream frees it.
#[inline]
pub unsafe fn string_in(x: &mut XdrStream, cpp: &mut *mut c_char, maxsize: u_int) -> bool_t {
    let mut sp = *cpp;
    let mut size: u_int = 0;
    match x.op() {
        XDR_FREE => {
            if sp.is_null() {
                return TRUE;
            }
            // SAFETY: a string to free is NUL-terminated (contract).
            size = unsafe { strlen(sp) } as u_int;
        }
        XDR_ENCODE => {
            if sp.is_null() {
                return FALSE;
            }
            // SAFETY: a string to encode is NUL-terminated (contract).
            size = unsafe { strlen(sp) } as u_int;
        }
        _ => {}
    }
    if x.u_int(&mut size) == 0 {
        return FALSE;
    }
    if size > maxsize {
        return FALSE;
    }
    let nodesize = size.wrapping_add(1);
    if nodesize == 0 {
        return FALSE;
    }
    // encoding first: the common case keeps the straight-line path
    if x.op() == XDR_ENCODE {
        if size == 0 {
            return TRUE;
        }
        // SAFETY: the string has `size` bytes before its NUL (measured above).
        return x.opaque_encode(unsafe { bytes(sp.cast(), size as usize) });
    }
    match x.op() {
        XDR_DECODE => {
            if sp.is_null() {
                sp = alloc(nodesize as usize) as *mut c_char;
                *cpp = sp;
            }
            if sp.is_null() {
                oom("xdr_string");
                return FALSE;
            }
            // SAFETY: `sp` is our fresh `nodesize`-byte buffer or the caller's buffer, big enough (contract).
            let buf = unsafe { bytes_mut(sp.cast(), nodesize as usize) };
            buf[size as usize] = 0;
            x.opaque(&mut buf[..size as usize])
        }
        XDR_FREE => {
            // SAFETY: a decoded string comes from malloc (contract).
            unsafe { mem_free(sp.cast()) };
            *cpp = core::ptr::null_mut();
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_string(xdrs: *mut XDR, cpp: *mut *mut c_char, maxsize: u_int) -> bool_t {
    // SAFETY: the C contract of xdr_string: `cpp` points to the string pointer.
    let cpp = unsafe { &mut *cpp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: `*cpp` is what the C contract says.
    unsafe { string_in(&mut x, cpp, maxsize) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_wrapstring(xdrs: *mut XDR, cpp: *mut *mut c_char) -> bool_t {
    // SAFETY: the C contract of xdr_wrapstring is xdr_string's.
    if unsafe { xdr_string(xdrs, cpp, LASTUNSIGNED) } != 0 { TRUE } else { FALSE }
}

// ---- xdr_intXX_t.c

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int64_t(xdrs: *mut XDR, ip: *mut i64) -> bool_t {
    // SAFETY: the C contract of xdr_int64_t.
    unsafe { prim(xdrs, ip, XdrStream::int64) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_quad_t(xdrs: *mut XDR, ip: *mut quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_quad_t.
    unsafe { prim(xdrs, ip, XdrStream::int64) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint64_t(xdrs: *mut XDR, uip: *mut u64) -> bool_t {
    // SAFETY: the C contract of xdr_uint64_t.
    unsafe { prim(xdrs, uip, XdrStream::uint64) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_quad_t(xdrs: *mut XDR, ip: *mut u_quad_t) -> bool_t {
    // SAFETY: the C contract of xdr_u_quad_t.
    unsafe { prim(xdrs, ip, XdrStream::uint64) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int32_t(xdrs: *mut XDR, lp: *mut i32) -> bool_t {
    // SAFETY: the C contract of xdr_int32_t.
    unsafe { prim(xdrs, lp, XdrStream::int32) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint32_t(xdrs: *mut XDR, ulp: *mut u32) -> bool_t {
    // SAFETY: the C contract of xdr_uint32_t.
    unsafe { prim(xdrs, ulp, XdrStream::uint32) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int16_t(xdrs: *mut XDR, ip: *mut i16) -> bool_t {
    // SAFETY: the C contract of xdr_int16_t.
    unsafe { prim(xdrs, ip, XdrStream::int16) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint16_t(xdrs: *mut XDR, uip: *mut u16) -> bool_t {
    // SAFETY: the C contract of xdr_uint16_t.
    unsafe { prim(xdrs, uip, XdrStream::uint16) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int8_t(xdrs: *mut XDR, ip: *mut i8) -> bool_t {
    // SAFETY: the C contract of xdr_int8_t.
    unsafe { prim(xdrs, ip, XdrStream::int8) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint8_t(xdrs: *mut XDR, uip: *mut u8) -> bool_t {
    // SAFETY: the C contract of xdr_uint8_t.
    unsafe { prim(xdrs, uip, XdrStream::uint8) }
}

// ---- xdr_float.c (IEEE 754 hosts: the bit patterns go over as they are)

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_float(xdrs: *mut XDR, fp: *mut f32) -> bool_t {
    // SAFETY: the C contract of xdr_float.
    unsafe { prim(xdrs, fp, XdrStream::float) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_double(xdrs: *mut XDR, dp: *mut f64) -> bool_t {
    // SAFETY: the C contract of xdr_double.
    unsafe { prim(xdrs, dp, XdrStream::double) }
}

// ---- xdr_array.c, xdr_ref.c

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_array(xdrs: *mut XDR, addrp: *mut caddr_t, sizep: *mut u_int, maxsize: u_int, elsize: u_int, elproc: xdrproc_t) -> bool_t {
    // SAFETY: the C contract of xdr_array: `addrp` points to the array pointer.
    let addrp = unsafe { &mut *addrp };
    let mut target = *addrp;
    // SAFETY: `sizep` points to the element count.
    if unsafe { xdr_u_int(xdrs, sizep) } == 0 {
        return FALSE;
    }
    // SAFETY: as above.
    let c = unsafe { *sizep };
    // SAFETY: `xdrs` is a live stream (read after the count, as glibc does).
    let op = unsafe { (*xdrs).x_op };
    if (c > maxsize || (elsize != 0 && c > u_int::MAX / elsize)) && op != XDR_FREE {
        return FALSE;
    }
    if target.is_null() {
        match op {
            XDR_DECODE => {
                if c == 0 {
                    return TRUE;
                }
                target = alloc_zeroed(c as usize, elsize as usize) as caddr_t;
                *addrp = target;
                if target.is_null() {
                    oom("xdr_array");
                    return FALSE;
                }
            }
            XDR_FREE => return TRUE,
            _ => {}
        }
    }
    let mut stat = TRUE;
    let mut i = 0;
    while i < c && stat != 0 {
        // SAFETY: `target` walks the `c` elements of `elsize` bytes; `elproc` codes one element (the C contract).
        stat = unsafe { call_proc(elproc, xdrs, target.cast()) };
        target = target.wrapping_add(elsize as usize);
        i += 1;
    }
    // SAFETY: `xdrs` is a live stream (the element routines may not change the direction, but glibc reads it again).
    if unsafe { (*xdrs).x_op } == XDR_FREE {
        // SAFETY: a decoded array comes from calloc.
        unsafe { mem_free((*addrp).cast()) };
        *addrp = core::ptr::null_mut();
    }
    stat
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_vector(xdrs: *mut XDR, basep: *mut c_char, nelem: u_int, elemsize: u_int, xdr_elem: xdrproc_t) -> bool_t {
    let mut elptr = basep;
    for _ in 0..nelem {
        // SAFETY: `elptr` walks the `nelem` elements at `basep`; `xdr_elem` codes one element (the C contract).
        if unsafe { call_proc(xdr_elem, xdrs, elptr.cast()) } == 0 {
            return FALSE;
        }
        elptr = elptr.wrapping_add(elemsize as usize);
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_reference(xdrs: *mut XDR, pp: *mut caddr_t, size: u_int, proc_: xdrproc_t) -> bool_t {
    // SAFETY: the C contract of xdr_reference: `pp` points to the object pointer.
    let pp = unsafe { &mut *pp };
    let mut loc = *pp;
    if loc.is_null() {
        // SAFETY: `xdrs` is a live stream.
        match unsafe { (*xdrs).x_op } {
            XDR_FREE => return TRUE,
            XDR_DECODE => {
                loc = alloc_zeroed(1, size as usize) as caddr_t;
                *pp = loc;
                if loc.is_null() {
                    oom("xdr_reference");
                    return FALSE;
                }
            }
            _ => {}
        }
    }
    // SAFETY: `proc_` codes the object at `loc` (the C contract; a fresh one is zeroed `size` bytes).
    let stat = unsafe { call_proc(proc_, xdrs, loc.cast()) };
    // SAFETY: `xdrs` is a live stream.
    if unsafe { (*xdrs).x_op } == XDR_FREE {
        // SAFETY: a decoded object comes from calloc.
        unsafe { mem_free(loc.cast()) };
        *pp = core::ptr::null_mut();
    }
    stat
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pointer(xdrs: *mut XDR, objpp: *mut *mut c_char, obj_size: u_int, xdr_obj: xdrproc_t) -> bool_t {
    // SAFETY: the C contract of xdr_pointer: `objpp` points to the object pointer.
    let mut more_data: bool_t = unsafe { (!(*objpp).is_null()) as bool_t };
    // SAFETY: `xdrs` is a live stream.
    if unsafe { xdr_bool(xdrs, &mut more_data) } == 0 {
        return FALSE;
    }
    if more_data == 0 {
        // SAFETY: as above.
        unsafe { *objpp = core::ptr::null_mut() };
        return TRUE;
    }
    // SAFETY: the C contract of xdr_reference is ours.
    unsafe { xdr_reference(xdrs, objpp, obj_size, xdr_obj) }
}

/// Free what a decode routine allocated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_free(proc_: xdrproc_t, objp: *mut c_char) {
    let mut x = XDR::zeroed();
    x.x_op = XDR_FREE;
    if let Some(f) = proc_ {
        // SAFETY: `proc_` is the routine for the object at `objp` (the C contract); freeing never touches the stream's
        // operations.
        unsafe { f(&mut x, objp.cast()) };
    }
}

// ---- xdr_mem.c

/// A memory stream's state, which lives in its C handle: `x_private` is the cursor, `x_handy` the bytes left after it,
/// `x_base` the start of the buffer.
struct Mem<'a> {
    x: &'a mut XDR,
}

impl<'a> Mem<'a> {
    /// # Safety
    /// `x` is a memory stream (`xdrmem_create` made it, and `x_private` points to `x_handy` bytes of the caller's buffer
    /// that only this stream accesses meanwhile: the C contract of `xdrmem_create`), used by nothing else for `'a`.
    #[inline(always)]
    unsafe fn from_ptr(x: *mut XDR) -> Mem<'a> {
        // SAFETY: caller's contract.
        Mem { x: unsafe { &mut *x } }
    }

    /// The next `n` bytes, consumed; `None` (nothing consumed) when fewer are left.
    #[inline(always)]
    fn take(&mut self, n: u_int) -> Option<&mut [u8]> {
        if self.x.x_handy < n {
            return None;
        }
        let p = self.x.x_private;
        self.x.x_handy -= n;
        self.x.x_private = p.wrapping_add(n as usize);
        // SAFETY: `p` points to at least `n` bytes of the buffer (the invariant: `x_handy` bytes follow the cursor, and
        // `n` <= the old `x_handy`); the cursor has moved past them, so no later `take` hands them out again.
        Some(unsafe { bytes_mut(p.cast(), n as usize) })
    }

    #[inline(always)]
    fn take_word(&mut self) -> Option<&mut [u8; 4]> {
        self.take(4).and_then(|b| b.first_chunk_mut::<4>())
    }
}

unsafe extern "C" fn xdrmem_destroy(_x: *mut XDR) {}

unsafe extern "C" fn xdrmem_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    let Some(w) = m.take_word() else { return FALSE };
    // SAFETY: the stream contract: `lp` points to a long.
    unsafe { *lp = i32::from_be_bytes(*w) as c_long };
    TRUE
}

unsafe extern "C" fn xdrmem_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    if m.x.x_handy < 4 {
        return FALSE;
    }
    // SAFETY: the stream contract: `lp` points to a long.
    let v = (unsafe { *lp } as u32).to_be_bytes();
    let Some(w) = m.take_word() else { return FALSE };
    *w = v;
    TRUE
}

unsafe extern "C" fn xdrmem_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    let Some(src) = m.take(len) else { return FALSE };
    // SAFETY: the stream contract: `addr` points to `len` writable bytes.
    let dst = unsafe { bytes_mut(addr.cast(), len as usize) };
    dst.copy_from_slice(src);
    TRUE
}

unsafe extern "C" fn xdrmem_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    let Some(dst) = m.take(len) else { return FALSE };
    // SAFETY: the stream contract: `addr` points to `len` readable bytes.
    dst.copy_from_slice(unsafe { bytes(addr.cast(), len as usize) });
    TRUE
}

unsafe extern "C" fn xdrmem_getpos(x: *const XDR) -> u_int {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a live handle.
    let x = unsafe { &*x };
    (x.x_private as usize).wrapping_sub(x.x_base as usize) as u_int
}

unsafe extern "C" fn xdrmem_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a live handle (only its fields are touched, as integers).
    let x = unsafe { &mut *x };
    let newaddr = (x.x_base as usize).wrapping_add(pos as usize);
    let lastaddr = (x.x_private as usize).wrapping_add(x.x_handy as usize);
    let handy = lastaddr.wrapping_sub(newaddr);
    if newaddr > lastaddr || newaddr < x.x_base as usize || handy != (handy as u_int) as usize {
        return FALSE;
    }
    // the cursor stays inside [x_base, end of buffer], so the stream's invariant holds
    x.x_private = x.x_base.wrapping_add(pos as usize);
    x.x_handy = handy as u_int;
    TRUE
}

unsafe extern "C" fn xdrmem_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let m = unsafe { Mem::from_ptr(x) };
    // the cursor itself, also for `len` 0 (so no slice is made here)
    if m.x.x_handy < len {
        return core::ptr::null_mut();
    }
    let buf = m.x.x_private;
    m.x.x_handy -= len;
    m.x.x_private = buf.wrapping_add(len as usize);
    buf as *mut i32
}

unsafe extern "C" fn xdrmem_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    let Some(w) = m.take_word() else { return FALSE };
    // SAFETY: the stream contract: `ip` points to an int32.
    unsafe { *ip = i32::from_be_bytes(*w) };
    TRUE
}

unsafe extern "C" fn xdrmem_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    // SAFETY: an operation of XDRMEM_OPS: `x` is a memory stream.
    let mut m = unsafe { Mem::from_ptr(x) };
    if m.x.x_handy < 4 {
        return FALSE;
    }
    // SAFETY: the stream contract: `ip` points to an int32.
    let v = unsafe { *ip }.to_be_bytes();
    let Some(w) = m.take_word() else { return FALSE };
    *w = v;
    TRUE
}

pub static XDRMEM_OPS: xdr_ops = xdr_ops {
    x_getlong: Some(xdrmem_getlong),
    x_putlong: Some(xdrmem_putlong),
    x_getbytes: Some(xdrmem_getbytes),
    x_putbytes: Some(xdrmem_putbytes),
    x_getpostn: Some(xdrmem_getpos),
    x_setpostn: Some(xdrmem_setpos),
    x_inline: Some(xdrmem_inline),
    x_destroy: Some(xdrmem_destroy),
    x_getint32: Some(xdrmem_getint32),
    x_putint32: Some(xdrmem_putint32),
};

/// `xdrmem_create` on a handle in hand. Safe: it only stores the pointer; using the stream later is what needs the buffer
/// to be valid (`XdrStream::from_ptr`'s contract, or `XdrStream::mem`, which borrows the buffer).
#[inline]
pub fn mem_init(x: &mut XDR, addr: caddr_t, size: u_int, op: c_int) {
    x.x_op = op;
    x.x_ops = &XDRMEM_OPS;
    x.x_private = addr;
    x.x_base = addr;
    x.x_handy = size;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrmem_create(xdrs: *mut XDR, addr: caddr_t, size: u_int, op: c_int) {
    // SAFETY: the C contract of xdrmem_create: `xdrs` points to a handle to fill in.
    mem_init(unsafe { &mut *xdrs }, addr, size, op)
}

// ---- xdr_sizeof.c (a stream that only counts; `x_base` holds the size of the scratch buffer, `x_private` the buffer)

/// # Safety
/// `x` is the handle `xdr_sizeof` made (only its fields are touched).
#[inline(always)]
unsafe fn sz_handle<'a>(x: *mut XDR) -> &'a mut XDR {
    // SAFETY: caller's contract.
    unsafe { &mut *x }
}

unsafe extern "C" fn sz_putlong(x: *mut XDR, _lp: *const c_long) -> bool_t {
    // SAFETY: an operation of the sizeof stream.
    unsafe { sz_handle(x) }.x_handy += BYTES_PER_XDR_UNIT;
    TRUE
}

unsafe extern "C" fn sz_putbytes(x: *mut XDR, _bp: *const c_char, len: u_int) -> bool_t {
    // SAFETY: an operation of the sizeof stream.
    let x = unsafe { sz_handle(x) };
    x.x_handy = x.x_handy.wrapping_add(len);
    TRUE
}

unsafe extern "C" fn sz_getpostn(x: *const XDR) -> u_int {
    // SAFETY: an operation of the sizeof stream: `x` is its live handle.
    unsafe { (*x).x_handy }
}

unsafe extern "C" fn sz_setpostn(_x: *mut XDR, _len: u_int) -> bool_t {
    FALSE
}

unsafe extern "C" fn sz_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    // SAFETY: an operation of the sizeof stream.
    let x = unsafe { sz_handle(x) };
    if len == 0 || x.x_op != XDR_ENCODE {
        return core::ptr::null_mut();
    }
    if (len as c_long) < x.x_base as c_long {
        x.x_handy = x.x_handy.wrapping_add(len);
        return x.x_private as *mut i32;
    }
    // SAFETY: the scratch buffer is NULL or came from malloc below.
    unsafe { mem_free(x.x_private.cast()) };
    x.x_private = alloc(len as usize) as caddr_t;
    if x.x_private.is_null() {
        x.x_base = core::ptr::null_mut();
        return core::ptr::null_mut();
    }
    x.x_base = len as c_long as caddr_t;
    x.x_handy = x.x_handy.wrapping_add(len);
    x.x_private as *mut i32
}

// the decoding operations of the sizeof stream: glibc points them at a function that returns 0
unsafe extern "C" fn sz_getlong(_x: *mut XDR, _lp: *mut c_long) -> bool_t {
    0
}

unsafe extern "C" fn sz_getbytes(_x: *mut XDR, _p: caddr_t, _n: u_int) -> bool_t {
    0
}

unsafe extern "C" fn sz_getint32(_x: *mut XDR, _ip: *mut i32) -> bool_t {
    0
}

unsafe extern "C" fn sz_destroy(x: *mut XDR) {
    // SAFETY: an operation of the sizeof stream.
    let x = unsafe { sz_handle(x) };
    x.x_handy = 0;
    x.x_base = core::ptr::null_mut();
    if !x.x_private.is_null() {
        // SAFETY: the scratch buffer came from malloc (sz_inline).
        unsafe { mem_free(x.x_private.cast()) };
        x.x_private = core::ptr::null_mut();
    }
}

unsafe extern "C" fn sz_putint32(x: *mut XDR, _ip: *const i32) -> bool_t {
    // SAFETY: an operation of the sizeof stream.
    unsafe { sz_handle(x) }.x_handy += BYTES_PER_XDR_UNIT;
    TRUE
}

static SIZEOF_OPS: xdr_ops = xdr_ops {
    x_putlong: Some(sz_putlong),
    x_putbytes: Some(sz_putbytes),
    x_inline: Some(sz_inline),
    x_getpostn: Some(sz_getpostn),
    x_setpostn: Some(sz_setpostn),
    x_destroy: Some(sz_destroy),
    x_putint32: Some(sz_putint32),
    x_getlong: Some(sz_getlong),
    x_getbytes: Some(sz_getbytes),
    x_getint32: Some(sz_getint32),
};

/// The number of bytes `func` would encode `data` into (0 if it fails).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_sizeof(func: xdrproc_t, data: *mut c_void) -> c_ulong {
    let mut x = XDR::zeroed();
    x.x_op = XDR_ENCODE;
    x.x_ops = &SIZEOF_OPS;
    x.x_handy = 0;
    x.x_private = core::ptr::null_mut();
    x.x_base = core::ptr::null_mut();
    let stat = match func {
        // SAFETY: `func` is the routine for the object at `data` (the C contract).
        Some(f) => unsafe { f(&mut x, data) },
        None => FALSE,
    };
    // SAFETY: the scratch buffer is NULL or came from malloc (sz_inline).
    unsafe { mem_free(x.x_private.cast()) };
    if stat == TRUE { x.x_handy as c_ulong } else { 0 }
}
