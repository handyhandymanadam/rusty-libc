//! XDR over a stdio `FILE` (`xdrstdio_create`). Port of Sun's `xdr_stdio.c`.
//!
//! Every operation is one stdio call on the handle's `FILE`; the unsafe left is that call (a C `FILE *` and the
//! caller's buffer) and reading the `FILE` out of the handle.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::{fflush, fread, fseek, ftell, fwrite};

/// The `FILE` of a stdio stream.
///
/// # Safety
/// `x` is a live handle made by `xdrstdio_create`.
#[inline(always)]
unsafe fn fp(x: *const XDR) -> *mut FILE {
    // SAFETY: caller's contract.
    unsafe { (*x).x_private as *mut FILE }
}

/// `fread(buf, size, n, FILE of x)`.
///
/// # Safety
/// `x` is a stdio stream whose `FILE` is open, and `buf` has room for `size * n` bytes.
#[inline(always)]
unsafe fn sread(x: *const XDR, buf: *mut c_void, size: usize, n: usize) -> usize {
    // SAFETY: caller's contract.
    let f = unsafe { fp(x) };
    // SAFETY: an open FILE and a buffer of `size * n` bytes (caller's contract).
    unsafe { fread(buf, size, n, f) }
}

/// `fwrite(buf, size, n, FILE of x)`.
///
/// # Safety
/// `x` is a stdio stream whose `FILE` is open, and `buf` holds `size * n` bytes.
#[inline(always)]
unsafe fn swrite(x: *const XDR, buf: *const c_void, size: usize, n: usize) -> usize {
    // SAFETY: caller's contract.
    let f = unsafe { fp(x) };
    // SAFETY: an open FILE and `size * n` readable bytes (caller's contract).
    unsafe { fwrite(buf, size, n, f) }
}

unsafe extern "C" fn xdrstdio_destroy(x: *mut XDR) {
    // SAFETY: an operation of XDRSTDIO_OPS: `x` is a stdio stream.
    let f = unsafe { fp(x) };
    // SAFETY: its FILE is open (the C contract of xdrstdio_create).
    unsafe { fflush(f) };
}

unsafe extern "C" fn xdrstdio_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    let mut b = [0u8; 4];
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; `b` has room for one 4-byte item.
    if unsafe { sread(x, b.as_mut_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    // SAFETY: the stream contract: `lp` points to a long.
    unsafe { *lp = u32::from_be_bytes(b) as c_long };
    TRUE
}

unsafe extern "C" fn xdrstdio_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    // SAFETY: the stream contract: `lp` points to a long.
    let b = (unsafe { *lp } as u32).to_be_bytes();
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; `b` holds one 4-byte item.
    if unsafe { swrite(x, b.as_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; the stream contract: `addr` has room for `len` bytes.
    if len != 0 && unsafe { sread(x, addr.cast(), len as c_int as usize, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; the stream contract: `addr` holds `len` bytes.
    if len != 0 && unsafe { swrite(x, addr.cast(), len as c_int as usize, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getpos(x: *const XDR) -> u_int {
    // SAFETY: an operation of XDRSTDIO_OPS: `x` is a stdio stream.
    let f = unsafe { fp(x) };
    // SAFETY: its FILE is open.
    unsafe { ftell(f) as u_int }
}

unsafe extern "C" fn xdrstdio_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    // SAFETY: an operation of XDRSTDIO_OPS: `x` is a stdio stream.
    let f = unsafe { fp(x) };
    // SAFETY: its FILE is open.
    if unsafe { fseek(f, pos as c_long, 0) } < 0 { FALSE } else { TRUE }
}

unsafe extern "C" fn xdrstdio_inline(_x: *mut XDR, _len: u_int) -> *mut i32 {
    core::ptr::null_mut()
}

unsafe extern "C" fn xdrstdio_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    let mut b = [0u8; 4];
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; `b` has room for one 4-byte item.
    if unsafe { sread(x, b.as_mut_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    // SAFETY: the stream contract: `ip` points to an int32.
    unsafe { *ip = i32::from_be_bytes(b) };
    TRUE
}

unsafe extern "C" fn xdrstdio_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    // SAFETY: the stream contract: `ip` points to an int32.
    let b = unsafe { *ip }.to_be_bytes();
    // SAFETY: an operation of XDRSTDIO_OPS on an open FILE; `b` holds one 4-byte item.
    if unsafe { swrite(x, b.as_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

static XDRSTDIO_OPS: xdr_ops = xdr_ops {
    x_getlong: Some(xdrstdio_getlong),
    x_putlong: Some(xdrstdio_putlong),
    x_getbytes: Some(xdrstdio_getbytes),
    x_putbytes: Some(xdrstdio_putbytes),
    x_getpostn: Some(xdrstdio_getpos),
    x_setpostn: Some(xdrstdio_setpos),
    x_inline: Some(xdrstdio_inline),
    x_destroy: Some(xdrstdio_destroy),
    x_getint32: Some(xdrstdio_getint32),
    x_putint32: Some(xdrstdio_putint32),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrstdio_create(xdrs: *mut XDR, file: *mut FILE, op: c_int) {
    // SAFETY: the C contract: `xdrs` points to a handle to fill in.
    let x = unsafe { &mut *xdrs };
    x.x_op = op;
    x.x_ops = &XDRSTDIO_OPS;
    x.x_private = file as caddr_t;
    x.x_handy = 0;
    x.x_base = core::ptr::null_mut();
}
