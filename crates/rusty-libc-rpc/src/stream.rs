//! The safe core of XDR: [`XdrStream`], a checked view of a C `XDR` handle, with the primitive codecs of RFC 4506 as
//! methods, and [`Inline`], a cursor over the buffer an `x_inline` call lends out (the `IXDR_*` macros).
//!
//! The exported `xdr_*` routines (xdr.rs) convert their raw arguments once (`XdrStream::from_ptr`, the object pointer to a
//! reference) and call these methods; the rest of the crate and the Rust API (rustapi.rs) use them directly.
//!
//! Soundness rests on one contract, stated at [`XdrStream::from_ptr`]: the handle and its operations table behave as an
//! XDR stream must (each callback touches only the memory its arguments describe). That is the contract every C caller of
//! the `xdr_*` routines already relies on; it is checked here once, at the privacy boundary of this module (Rust for
//! Rustaceans p.233: keep the unsafe code in one module with a safe interface; Comprehensive Rust p.836-838: an unsafe
//! function documents its preconditions, a safe one encapsulates its unsafe blocks completely). The streams this crate
//! builds itself (memory streams over a borrowed buffer) are made with [`XdrStream::mem`], which needs no contract.
//!
//! Every method returns the callback's own `bool_t` (not a normalised bool), so the C routines built on them return
//! exactly what they returned before.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_short};

/// A live XDR stream: the C handle plus the guarantee that its operations table honours the stream contract.
pub struct XdrStream<'a> {
    x: &'a mut XDR,
}

impl<'a> XdrStream<'a> {
    /// View the C handle `x` as a stream.
    ///
    /// # Safety
    /// `x` is non-NULL, aligned and points to an `XDR` that, for `'a`, nothing accesses except through the returned value
    /// and the stream's own callbacks (which receive this pointer). `x_ops` points to an operations table that stays valid
    /// for `'a` and whose callbacks honour the XDR stream contract for this handle: `x_getbytes(x, p, n)` writes at most the
    /// `n` bytes at `p`; `x_putbytes(x, p, n)` only reads the `n` bytes at `p`; `x_getlong`/`x_getint32` write one value
    /// and `x_putlong`/`x_putint32` read one value at the pointer they get; `x_inline(x, n)` returns NULL or a pointer to
    /// `n` bytes owned by the stream that nothing else accesses until the next call on the stream. (This is what every
    /// stream of Sun's design does: memory, record, stdio, sizeof, and the ones C programs write.)
    #[inline(always)]
    pub unsafe fn from_ptr(x: *mut XDR) -> XdrStream<'a> {
        // SAFETY: non-NULL, aligned, exclusive for 'a (the caller's contract).
        XdrStream { x: unsafe { &mut *x } }
    }

    /// A memory stream (`xdrmem_create`) over `buf`, coding in direction `op`. `handle` is the C handle it lives in.
    /// Safe: the buffer and the handle are borrowed for as long as the stream is used, and the operations are this
    /// crate's own memory-stream operations.
    #[inline]
    pub fn mem(handle: &'a mut XDR, buf: &'a mut [u8], op: c_int) -> XdrStream<'a> {
        crate::xdr::mem_init(handle, buf.as_mut_ptr().cast(), buf.len() as u_int, op);
        XdrStream { x: handle }
    }

    /// The raw handle, for passing to a C callback (`xdrproc_t`, `ah_marshal`, ...) or an exported routine.
    #[inline(always)]
    pub fn as_ptr(&mut self) -> *mut XDR {
        self.x
    }

    /// The direction: `XDR_ENCODE`, `XDR_DECODE` or `XDR_FREE` (or any other value a C program stored).
    #[inline(always)]
    pub fn op(&self) -> c_int {
        self.x.x_op
    }

    /// Change the direction (any value: the codecs treat an unknown one as a failure).
    #[inline(always)]
    pub fn set_op(&mut self, op: c_int) {
        self.x.x_op = op;
    }

    #[inline(always)]
    fn ops(&self) -> &xdr_ops {
        // SAFETY: `x_ops` points to a table valid for 'a (from_ptr's contract; `mem` sets our own static table). It is
        // read again on every call, as the C macros do, in case a callback replaced it.
        unsafe { &*self.x.x_ops }
    }

    /// `XDR_GETLONG`: read one unit into `*v` (sign-extended word).
    #[inline(always)]
    pub fn get_long(&mut self, v: &mut c_long) -> bool_t {
        match self.ops().x_getlong {
            // SAFETY: the stream contract: the callback writes one long at the pointer it gets.
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    /// `XDR_PUTLONG`: write the low 32 bits of `v` as one unit.
    #[inline(always)]
    pub fn put_long(&mut self, v: c_long) -> bool_t {
        match self.ops().x_putlong {
            // SAFETY: the stream contract: the callback reads one long at the pointer it gets.
            Some(f) => unsafe { f(self.x, &v) },
            None => FALSE,
        }
    }

    /// `XDR_PUTLONG` of a long the caller holds (its address goes to the callback, as the C macro passes it).
    #[inline(always)]
    pub fn put_long_ref(&mut self, v: &c_long) -> bool_t {
        match self.ops().x_putlong {
            // SAFETY: the stream contract: the callback reads one long at the pointer it gets.
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    /// `XDR_GETINT32`.
    #[inline(always)]
    pub fn get_int32(&mut self, v: &mut i32) -> bool_t {
        match self.ops().x_getint32 {
            // SAFETY: the stream contract: the callback writes one int32 at the pointer it gets.
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    /// `XDR_PUTINT32`.
    #[inline(always)]
    pub fn put_int32(&mut self, v: i32) -> bool_t {
        match self.ops().x_putint32 {
            // SAFETY: the stream contract: the callback reads one int32 at the pointer it gets.
            Some(f) => unsafe { f(self.x, &v) },
            None => FALSE,
        }
    }

    /// `XDR_GETBYTES`: fill `buf` from the stream (no padding).
    #[inline(always)]
    pub fn get_bytes(&mut self, buf: &mut [u8]) -> bool_t {
        debug_assert!(buf.len() <= u_int::MAX as usize);
        match self.ops().x_getbytes {
            // SAFETY: the stream contract: the callback writes at most `buf.len()` bytes at `buf`.
            Some(f) => unsafe { f(self.x, buf.as_mut_ptr().cast(), buf.len() as u_int) },
            None => FALSE,
        }
    }

    /// `XDR_PUTBYTES`: write `buf` to the stream (no padding).
    #[inline(always)]
    pub fn put_bytes(&mut self, buf: &[u8]) -> bool_t {
        debug_assert!(buf.len() <= u_int::MAX as usize);
        match self.ops().x_putbytes {
            // SAFETY: the stream contract: the callback only reads the `buf.len()` bytes at `buf`.
            Some(f) => unsafe { f(self.x, buf.as_ptr().cast(), buf.len() as u_int) },
            None => FALSE,
        }
    }

    /// `XDR_GETPOS`.
    #[inline(always)]
    pub fn getpos(&self) -> u_int {
        match self.ops().x_getpostn {
            // SAFETY: the stream contract: the callback reads the handle it gets.
            Some(f) => unsafe { f(&*self.x) },
            None => 0,
        }
    }

    /// `XDR_SETPOS`.
    #[inline(always)]
    pub fn setpos(&mut self, pos: u_int) -> bool_t {
        match self.ops().x_setpostn {
            // SAFETY: the stream contract.
            Some(f) => unsafe { f(self.x, pos) },
            None => FALSE,
        }
    }

    /// `XDR_INLINE` as a raw pointer (NULL when the stream cannot lend `len` bytes), for code that hands it on to C.
    #[inline(always)]
    pub fn inline_ptr(&mut self, len: u_int) -> *mut i32 {
        match self.ops().x_inline {
            // SAFETY: the stream contract.
            Some(f) => unsafe { f(self.x, len) },
            None => core::ptr::null_mut(),
        }
    }

    /// `XDR_INLINE`: `len` bytes of the stream's own buffer to code straight into, or `None`.
    #[inline(always)]
    pub fn inline(&mut self, len: u_int) -> Option<Inline<'_>> {
        let p = self.inline_ptr(len);
        if p.is_null() {
            return None;
        }
        // SAFETY: the stream contract: a non-NULL result points to `len` bytes owned by the stream and untouched by anyone
        // else until the next call on the stream; the returned cursor borrows the stream, so no call happens meanwhile.
        let buf = unsafe { rusty_libc_core::ffi::bytes_mut(p.cast::<u8>(), len as usize) };
        Some(Inline { buf })
    }

    /// `XDR_DESTROY`.
    #[inline(always)]
    pub fn destroy(&mut self) {
        if let Some(f) = self.ops().x_destroy {
            // SAFETY: the stream contract.
            unsafe { f(self.x) }
        }
    }

    /// Run an XDR routine on the object at `obj`, with the extra `LASTUNSIGNED` argument Sun's code passes.
    ///
    /// # Safety
    /// `proc_` is an XDR routine for the type of object `obj` points to (or NULL), and `obj` is what that routine expects.
    #[inline(always)]
    pub unsafe fn call(&mut self, proc_: xdrproc_t, obj: *mut core::ffi::c_void) -> bool_t {
        // SAFETY: forwarded contract.
        unsafe { crate::xdr::call_proc(proc_, self.x, obj) }
    }

    // ---- the primitive codecs (xdr.c, xdr_intXX_t.c, xdr_float.c)

    /// The shared shape of the `long`-unit codecs: encode `enc(v)`, decode into a long and store `dec(l)`.
    #[inline(always)]
    fn long_unit<T: Copy>(&mut self, v: &mut T, enc: impl FnOnce(T) -> c_long, dec: impl FnOnce(c_long) -> T) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_long(enc(*v)),
            XDR_DECODE => {
                let mut l: c_long = 0;
                if self.get_long(&mut l) == 0 {
                    return FALSE;
                }
                *v = dec(l);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// The shared shape of the `int32`-unit codecs.
    #[inline(always)]
    fn int32_unit<T: Copy>(&mut self, v: &mut T, enc: impl FnOnce(T) -> i32, dec: impl FnOnce(i32) -> T) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_int32(enc(*v)),
            XDR_DECODE => {
                let mut t = 0i32;
                if self.get_int32(&mut t) == 0 {
                    return FALSE;
                }
                *v = dec(t);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_int`.
    #[inline]
    pub fn int(&mut self, v: &mut c_int) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as c_int)
    }

    /// `xdr_u_int`.
    #[inline]
    pub fn u_int(&mut self, v: &mut u_int) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as u_int)
    }

    /// `xdr_short`.
    #[inline]
    pub fn short(&mut self, v: &mut c_short) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as c_short)
    }

    /// `xdr_u_short`.
    #[inline]
    pub fn u_short(&mut self, v: &mut u_short) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as u_short)
    }

    /// `xdr_enum`.
    #[inline]
    pub fn enum_(&mut self, v: &mut enum_t) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as enum_t)
    }

    /// `xdr_bool`: any nonzero value goes out as 1; any nonzero unit comes in as TRUE.
    #[inline]
    pub fn bool_(&mut self, v: &mut bool_t) -> bool_t {
        self.long_unit(v, |b| if b != 0 { 1 } else { 0 }, |l| if l == 0 { FALSE } else { TRUE })
    }

    /// `xdr_long`: encoding fails for a value that does not fit in 32 bits; decoding stores the sign-extended unit
    /// straight from the stream's callback.
    #[inline]
    pub fn long(&mut self, v: &mut c_long) -> bool_t {
        let op = self.op();
        if op == XDR_ENCODE && (*v as i32) as c_long == *v {
            return self.put_long(*v);
        }
        if op == XDR_DECODE {
            return self.get_long(v);
        }
        if op == XDR_FREE {
            return TRUE;
        }
        FALSE
    }

    /// `xdr_u_long`: encoding fails above 2^32-1; decoding zero-extends the unit.
    #[inline]
    pub fn u_long(&mut self, v: &mut u_long) -> bool_t {
        match self.op() {
            XDR_DECODE => {
                let mut tmp: c_long = 0;
                if self.get_long(&mut tmp) == FALSE {
                    return FALSE;
                }
                *v = (tmp as u32) as u_long;
                TRUE
            }
            XDR_ENCODE => {
                if (*v as u32) as u_long != *v {
                    return FALSE;
                }
                self.put_long(*v as c_long)
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_hyper` (two long units, high first).
    #[inline]
    pub fn hyper(&mut self, v: &mut quad_t) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let t = [(*v >> 32) as c_long, *v as c_long];
                (self.put_long_ref(&t[0]) != 0 && self.put_long_ref(&t[1]) != 0) as bool_t
            }
            XDR_DECODE => {
                let (mut t1, mut t2): (c_long, c_long) = (0, 0);
                if self.get_long(&mut t1) == 0 || self.get_long(&mut t2) == 0 {
                    return FALSE;
                }
                *v = ((t1 as quad_t) << 32) | (t2 as u32 as quad_t);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_u_hyper`.
    #[inline]
    pub fn u_hyper(&mut self, v: &mut u_quad_t) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let t = [(*v >> 32) as c_long, *v as c_long];
                (self.put_long_ref(&t[0]) != 0 && self.put_long_ref(&t[1]) != 0) as bool_t
            }
            XDR_DECODE => {
                let (mut t1, mut t2): (c_long, c_long) = (0, 0);
                if self.get_long(&mut t1) == 0 || self.get_long(&mut t2) == 0 {
                    return FALSE;
                }
                *v = ((t1 as u_quad_t) << 32) | (t2 as u32 as u_quad_t);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_char`: through an int, writing back on success (also when freeing, as glibc does).
    #[inline]
    pub fn char_(&mut self, c: &mut c_char) -> bool_t {
        let mut i = *c as c_int;
        if self.int(&mut i) == 0 {
            return FALSE;
        }
        *c = i as c_char;
        TRUE
    }

    /// `xdr_u_char`.
    #[inline]
    pub fn u_char(&mut self, c: &mut u_char) -> bool_t {
        let mut u = *c as u_int;
        if self.u_int(&mut u) == 0 {
            return FALSE;
        }
        *c = u as u_char;
        TRUE
    }

    /// `xdr_int64_t` (two int32 units, high first).
    #[inline]
    pub fn int64(&mut self, v: &mut i64) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let (t1, t2) = ((*v >> 32) as i32, *v as i32);
                (self.put_int32(t1) != 0 && self.put_int32(t2) != 0) as bool_t
            }
            XDR_DECODE => {
                let (mut t1, mut t2) = (0i32, 0i32);
                if self.get_int32(&mut t1) == 0 || self.get_int32(&mut t2) == 0 {
                    return FALSE;
                }
                *v = ((t1 as i64) << 32) | (t2 as u32 as i64);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_uint64_t`.
    #[inline]
    pub fn uint64(&mut self, v: &mut u64) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let (t1, t2) = ((*v >> 32) as u32 as i32, *v as u32 as i32);
                (self.put_int32(t1) != 0 && self.put_int32(t2) != 0) as bool_t
            }
            XDR_DECODE => {
                let (mut t1, mut t2) = (0i32, 0i32);
                if self.get_int32(&mut t1) == 0 || self.get_int32(&mut t2) == 0 {
                    return FALSE;
                }
                *v = ((t1 as u32 as u64) << 32) | (t2 as u32 as u64);
                TRUE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_int32_t`: decoding stores straight from the stream's callback.
    #[inline]
    pub fn int32(&mut self, v: &mut i32) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_int32(*v),
            XDR_DECODE => self.get_int32(v),
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_uint32_t`.
    #[inline]
    pub fn uint32(&mut self, v: &mut u32) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_int32(*v as i32),
            XDR_DECODE => {
                // the callback writes the unit straight into `*v`, as glibc's cast pointer does
                let mut t = *v as i32;
                let r = self.get_int32(&mut t);
                *v = t as u32;
                r
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_int16_t`.
    #[inline]
    pub fn int16(&mut self, v: &mut i16) -> bool_t {
        self.int32_unit(v, |v| v as i32, |t| t as i16)
    }

    /// `xdr_uint16_t`.
    #[inline]
    pub fn uint16(&mut self, v: &mut u16) -> bool_t {
        self.int32_unit(v, |v| v as u32 as i32, |t| t as u16)
    }

    /// `xdr_int8_t`.
    #[inline]
    pub fn int8(&mut self, v: &mut i8) -> bool_t {
        self.int32_unit(v, |v| v as i32, |t| t as i8)
    }

    /// `xdr_uint8_t`.
    #[inline]
    pub fn uint8(&mut self, v: &mut u8) -> bool_t {
        self.int32_unit(v, |v| v as u32 as i32, |t| t as u8)
    }

    /// `xdr_float` (IEEE 754 single: the bit pattern as one unit).
    #[inline]
    pub fn float(&mut self, v: &mut f32) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_long(v.to_bits() as i32 as c_long),
            XDR_DECODE => {
                let mut tmp: c_long = 0;
                if self.get_long(&mut tmp) != 0 {
                    *v = f32::from_bits(tmp as i32 as u32);
                    return TRUE;
                }
                FALSE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_double` (IEEE 754 double: high word first).
    #[inline]
    pub fn double(&mut self, v: &mut f64) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let bits = v.to_bits();
                // both words in memory before the first call, as glibc's code has them
                let tmp = [(bits >> 32) as u32 as i32 as c_long, bits as u32 as i32 as c_long];
                (self.put_long_ref(&tmp[0]) != 0 && self.put_long_ref(&tmp[1]) != 0) as bool_t
            }
            XDR_DECODE => {
                let (mut tmp0, mut tmp1): (c_long, c_long) = (0, 0);
                if self.get_long(&mut tmp1) != 0 && self.get_long(&mut tmp0) != 0 {
                    let hi = tmp1 as u32 as u64;
                    let lo = tmp0 as u32 as u64;
                    *v = f64::from_bits((hi << 32) | lo);
                    return TRUE;
                }
                FALSE
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    /// `xdr_opaque` when decoding: fill `buf`, then skip the padding to a multiple of four bytes.
    #[inline]
    pub fn opaque_decode(&mut self, buf: &mut [u8]) -> bool_t {
        let pad = pad_len(buf.len());
        if self.get_bytes(buf) == 0 {
            return FALSE;
        }
        if pad == 0 {
            return TRUE;
        }
        let mut crud = [0u8; 4];
        self.get_bytes(&mut crud[..pad])
    }

    /// `xdr_opaque` when encoding: write `buf`, then zero bytes up to a multiple of four.
    #[inline]
    pub fn opaque_encode(&mut self, buf: &[u8]) -> bool_t {
        let pad = pad_len(buf.len());
        if self.put_bytes(buf) == 0 {
            return FALSE;
        }
        if pad == 0 {
            return TRUE;
        }
        self.put_bytes(&[0u8; 4][..pad])
    }

    /// `xdr_opaque`: fixed-length opaque data in either direction.
    #[inline]
    pub fn opaque(&mut self, buf: &mut [u8]) -> bool_t {
        if buf.is_empty() {
            return TRUE;
        }
        match self.op() {
            XDR_DECODE => self.opaque_decode(buf),
            XDR_ENCODE => self.opaque_encode(buf),
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }
}

/// Store `v` in network byte order at byte `off` of `b` (an `IXDR_PUT_*` into an array taken from an [`Inline`]).
#[inline(always)]
pub fn put_word<const N: usize>(b: &mut [u8; N], off: usize, v: i32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// The word in network byte order at byte `off` of `b` (`IXDR_GET_INT32`).
#[inline(always)]
pub fn get_word<const N: usize>(b: &[u8; N], off: usize) -> i32 {
    i32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Bytes of padding after `n` bytes of opaque data.
#[inline(always)]
pub fn pad_len(n: usize) -> usize {
    let r = n % BYTES_PER_XDR_UNIT as usize;
    if r > 0 { BYTES_PER_XDR_UNIT as usize - r } else { 0 }
}

/// A cursor over bytes an `x_inline` call lent out: the `IXDR_GET_*` / `IXDR_PUT_*` macros. Reads and writes go in
/// network byte order; running past the end panics (the callers ask for exactly the room they use, as the C code does)
/// except in the `try_*` forms, which report it. The cursor is the not yet used part of the buffer, so each step is one
/// length check, which the compiler folds away when the length asked for is a constant.
pub struct Inline<'b> {
    buf: &'b mut [u8],
}

impl<'b> Inline<'b> {
    /// A cursor over `buf` (for tests and for buffers this crate owns).
    pub fn new(buf: &'b mut [u8]) -> Inline<'b> {
        Inline { buf }
    }

    /// The next `n` bytes, consumed (None, nothing consumed, when fewer are left).
    #[inline(always)]
    fn take(&mut self, n: usize) -> Option<&'b mut [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = core::mem::take(&mut self.buf).split_at_mut(n);
        self.buf = rest;
        Some(head)
    }

    /// The next word, consumed.
    #[inline(always)]
    fn take_word(&mut self) -> Option<&'b mut [u8; 4]> {
        let (head, rest) = core::mem::take(&mut self.buf).split_first_chunk_mut::<4>()?;
        self.buf = rest;
        Some(head)
    }

    /// The next `N` bytes as an array, consumed (one length check for a run of words at constant offsets).
    #[inline(always)]
    pub fn take_array<const N: usize>(&mut self) -> &'b mut [u8; N] {
        let (head, rest) = core::mem::take(&mut self.buf).split_first_chunk_mut::<N>().expect("XDR_INLINE buffer too short");
        self.buf = rest;
        head
    }

    /// `IXDR_PUT_INT32` / `IXDR_PUT_LONG` / `IXDR_PUT_U_INT32` ...
    #[inline(always)]
    pub fn put_i32(&mut self, v: i32) {
        *self.take_word().expect("XDR_INLINE buffer too short") = v.to_be_bytes();
    }

    /// `IXDR_GET_INT32`.
    #[inline(always)]
    pub fn get_i32(&mut self) -> i32 {
        i32::from_be_bytes(*self.take_word().expect("XDR_INLINE buffer too short"))
    }

    /// `IXDR_GET_U_INT32`.
    #[inline(always)]
    pub fn get_u32(&mut self) -> u32 {
        self.get_i32() as u32
    }

    /// `IXDR_GET_LONG`: the unit zero-extended to a long (glibc's macro goes through `u_int32_t`).
    #[inline(always)]
    pub fn get_long(&mut self) -> c_long {
        (self.get_i32() as u32) as c_long
    }

    /// Copy `src` in (no padding: the caller skips it with [`Inline::skip`]).
    #[inline(always)]
    pub fn put_bytes(&mut self, src: &[u8]) {
        self.take(src.len()).expect("XDR_INLINE buffer too short").copy_from_slice(src);
    }

    /// Copy `dst.len()` bytes out.
    #[inline(always)]
    pub fn get_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(self.take(dst.len()).expect("XDR_INLINE buffer too short"));
    }

    /// [`Inline::get_u32`] that reports running out instead of panicking (for input from the network).
    #[inline(always)]
    pub fn try_get_u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(*self.take_word()?))
    }

    /// [`Inline::get_bytes`] that reports running out instead of panicking.
    #[inline(always)]
    pub fn try_get_bytes(&mut self, dst: &mut [u8]) -> Option<()> {
        dst.copy_from_slice(self.take(dst.len())?);
        Some(())
    }

    /// [`Inline::skip`] that reports running out instead of panicking.
    #[inline(always)]
    pub fn try_skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// Move on `n` bytes.
    #[inline(always)]
    pub fn skip(&mut self, n: usize) {
        self.take(n).expect("XDR_INLINE buffer too short");
    }
}
