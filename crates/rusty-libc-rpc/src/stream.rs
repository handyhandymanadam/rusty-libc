#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_short};

pub struct XdrStream<'a> {
    x: &'a mut XDR,
}

impl<'a> XdrStream<'a> {
    #[inline(always)]
    pub unsafe fn from_ptr(x: *mut XDR) -> XdrStream<'a> {
        XdrStream { x: unsafe { &mut *x } }
    }

    #[inline]
    pub fn mem(handle: &'a mut XDR, buf: &'a mut [u8], op: c_int) -> XdrStream<'a> {
        crate::xdr::mem_init(handle, buf.as_mut_ptr().cast(), buf.len() as u_int, op);
        XdrStream { x: handle }
    }

    #[inline(always)]
    pub fn as_ptr(&mut self) -> *mut XDR {
        self.x
    }

    #[inline(always)]
    pub fn op(&self) -> c_int {
        self.x.x_op
    }

    #[inline(always)]
    pub fn set_op(&mut self, op: c_int) {
        self.x.x_op = op;
    }

    #[inline(always)]
    fn ops(&self) -> &xdr_ops {
        unsafe { &*self.x.x_ops }
    }

    #[inline(always)]
    pub fn get_long(&mut self, v: &mut c_long) -> bool_t {
        match self.ops().x_getlong {
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn put_long(&mut self, v: c_long) -> bool_t {
        match self.ops().x_putlong {
            Some(f) => unsafe { f(self.x, &v) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn put_long_ref(&mut self, v: &c_long) -> bool_t {
        match self.ops().x_putlong {
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn get_int32(&mut self, v: &mut i32) -> bool_t {
        match self.ops().x_getint32 {
            Some(f) => unsafe { f(self.x, v) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn put_int32(&mut self, v: i32) -> bool_t {
        match self.ops().x_putint32 {
            Some(f) => unsafe { f(self.x, &v) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn get_bytes(&mut self, buf: &mut [u8]) -> bool_t {
        debug_assert!(buf.len() <= u_int::MAX as usize);
        match self.ops().x_getbytes {
            Some(f) => unsafe { f(self.x, buf.as_mut_ptr().cast(), buf.len() as u_int) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn put_bytes(&mut self, buf: &[u8]) -> bool_t {
        debug_assert!(buf.len() <= u_int::MAX as usize);
        match self.ops().x_putbytes {
            Some(f) => unsafe { f(self.x, buf.as_ptr().cast(), buf.len() as u_int) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn getpos(&self) -> u_int {
        match self.ops().x_getpostn {
            Some(f) => unsafe { f(&*self.x) },
            None => 0,
        }
    }

    #[inline(always)]
    pub fn setpos(&mut self, pos: u_int) -> bool_t {
        match self.ops().x_setpostn {
            Some(f) => unsafe { f(self.x, pos) },
            None => FALSE,
        }
    }

    #[inline(always)]
    pub fn inline_ptr(&mut self, len: u_int) -> *mut i32 {
        match self.ops().x_inline {
            Some(f) => unsafe { f(self.x, len) },
            None => core::ptr::null_mut(),
        }
    }

    #[inline(always)]
    pub fn inline(&mut self, len: u_int) -> Option<Inline<'_>> {
        let p = self.inline_ptr(len);
        if p.is_null() {
            return None;
        }
        let buf = unsafe { rusty_libc_core::ffi::bytes_mut(p.cast::<u8>(), len as usize) };
        Some(Inline { buf })
    }

    #[inline(always)]
    pub fn destroy(&mut self) {
        if let Some(f) = self.ops().x_destroy {
            unsafe { f(self.x) }
        }
    }

    #[inline(always)]
    pub unsafe fn call(&mut self, proc_: xdrproc_t, obj: *mut core::ffi::c_void) -> bool_t {
        unsafe { crate::xdr::call_proc(proc_, self.x, obj) }
    }

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

    #[inline]
    pub fn int(&mut self, v: &mut c_int) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as c_int)
    }

    #[inline]
    pub fn u_int(&mut self, v: &mut u_int) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as u_int)
    }

    #[inline]
    pub fn short(&mut self, v: &mut c_short) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as c_short)
    }

    #[inline]
    pub fn u_short(&mut self, v: &mut u_short) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as u_short)
    }

    #[inline]
    pub fn enum_(&mut self, v: &mut enum_t) -> bool_t {
        self.long_unit(v, |v| v as c_long, |l| l as enum_t)
    }

    #[inline]
    pub fn bool_(&mut self, v: &mut bool_t) -> bool_t {
        self.long_unit(v, |b| if b != 0 { 1 } else { 0 }, |l| if l == 0 { FALSE } else { TRUE })
    }

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

    #[inline]
    pub fn char_(&mut self, c: &mut c_char) -> bool_t {
        let mut i = *c as c_int;
        if self.int(&mut i) == 0 {
            return FALSE;
        }
        *c = i as c_char;
        TRUE
    }

    #[inline]
    pub fn u_char(&mut self, c: &mut u_char) -> bool_t {
        let mut u = *c as u_int;
        if self.u_int(&mut u) == 0 {
            return FALSE;
        }
        *c = u as u_char;
        TRUE
    }

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

    #[inline]
    pub fn int32(&mut self, v: &mut i32) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_int32(*v),
            XDR_DECODE => self.get_int32(v),
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    #[inline]
    pub fn uint32(&mut self, v: &mut u32) -> bool_t {
        match self.op() {
            XDR_ENCODE => self.put_int32(*v as i32),
            XDR_DECODE => {
                let mut t = *v as i32;
                let r = self.get_int32(&mut t);
                *v = t as u32;
                r
            }
            XDR_FREE => TRUE,
            _ => FALSE,
        }
    }

    #[inline]
    pub fn int16(&mut self, v: &mut i16) -> bool_t {
        self.int32_unit(v, |v| v as i32, |t| t as i16)
    }

    #[inline]
    pub fn uint16(&mut self, v: &mut u16) -> bool_t {
        self.int32_unit(v, |v| v as u32 as i32, |t| t as u16)
    }

    #[inline]
    pub fn int8(&mut self, v: &mut i8) -> bool_t {
        self.int32_unit(v, |v| v as i32, |t| t as i8)
    }

    #[inline]
    pub fn uint8(&mut self, v: &mut u8) -> bool_t {
        self.int32_unit(v, |v| v as u32 as i32, |t| t as u8)
    }

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

    #[inline]
    pub fn double(&mut self, v: &mut f64) -> bool_t {
        match self.op() {
            XDR_ENCODE => {
                let bits = v.to_bits();
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

#[inline(always)]
pub fn put_word<const N: usize>(b: &mut [u8; N], off: usize, v: i32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub fn get_word<const N: usize>(b: &[u8; N], off: usize) -> i32 {
    i32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline(always)]
pub fn pad_len(n: usize) -> usize {
    let r = n % BYTES_PER_XDR_UNIT as usize;
    if r > 0 { BYTES_PER_XDR_UNIT as usize - r } else { 0 }
}

pub struct Inline<'b> {
    buf: &'b mut [u8],
}

impl<'b> Inline<'b> {
    pub fn new(buf: &'b mut [u8]) -> Inline<'b> {
        Inline { buf }
    }

    #[inline(always)]
    fn take(&mut self, n: usize) -> Option<&'b mut [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = core::mem::take(&mut self.buf).split_at_mut(n);
        self.buf = rest;
        Some(head)
    }

    #[inline(always)]
    fn take_word(&mut self) -> Option<&'b mut [u8; 4]> {
        let (head, rest) = core::mem::take(&mut self.buf).split_first_chunk_mut::<4>()?;
        self.buf = rest;
        Some(head)
    }

    #[inline(always)]
    pub fn take_array<const N: usize>(&mut self) -> &'b mut [u8; N] {
        let (head, rest) = core::mem::take(&mut self.buf).split_first_chunk_mut::<N>().expect("XDR_INLINE buffer too short");
        self.buf = rest;
        head
    }

    #[inline(always)]
    pub fn put_i32(&mut self, v: i32) {
        *self.take_word().expect("XDR_INLINE buffer too short") = v.to_be_bytes();
    }

    #[inline(always)]
    pub fn get_i32(&mut self) -> i32 {
        i32::from_be_bytes(*self.take_word().expect("XDR_INLINE buffer too short"))
    }

    #[inline(always)]
    pub fn get_u32(&mut self) -> u32 {
        self.get_i32() as u32
    }

    #[inline(always)]
    pub fn get_long(&mut self) -> c_long {
        (self.get_i32() as u32) as c_long
    }

    #[inline(always)]
    pub fn put_bytes(&mut self, src: &[u8]) {
        self.take(src.len()).expect("XDR_INLINE buffer too short").copy_from_slice(src);
    }

    #[inline(always)]
    pub fn get_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(self.take(dst.len()).expect("XDR_INLINE buffer too short"));
    }

    #[inline(always)]
    pub fn try_get_u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(*self.take_word()?))
    }

    #[inline(always)]
    pub fn try_get_bytes(&mut self, dst: &mut [u8]) -> Option<()> {
        dst.copy_from_slice(self.take(dst.len())?);
        Some(())
    }

    #[inline(always)]
    pub fn try_skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    #[inline(always)]
    pub fn skip(&mut self, n: usize) {
        self.take(n).expect("XDR_INLINE buffer too short");
    }
}
