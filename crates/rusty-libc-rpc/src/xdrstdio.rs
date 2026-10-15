#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::{fflush, fread, fseek, ftell, fwrite};

#[inline(always)]
unsafe fn fp(x: *const XDR) -> *mut FILE {
    unsafe { (*x).x_private as *mut FILE }
}

#[inline(always)]
unsafe fn sread(x: *const XDR, buf: *mut c_void, size: usize, n: usize) -> usize {
    let f = unsafe { fp(x) };
    unsafe { fread(buf, size, n, f) }
}

#[inline(always)]
unsafe fn swrite(x: *const XDR, buf: *const c_void, size: usize, n: usize) -> usize {
    let f = unsafe { fp(x) };
    unsafe { fwrite(buf, size, n, f) }
}

unsafe extern "C" fn xdrstdio_destroy(x: *mut XDR) {
    let f = unsafe { fp(x) };
    unsafe { fflush(f) };
}

unsafe extern "C" fn xdrstdio_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    let mut b = [0u8; 4];
    if unsafe { sread(x, b.as_mut_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    unsafe { *lp = u32::from_be_bytes(b) as c_long };
    TRUE
}

unsafe extern "C" fn xdrstdio_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    let b = (unsafe { *lp } as u32).to_be_bytes();
    if unsafe { swrite(x, b.as_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    if len != 0 && unsafe { sread(x, addr.cast(), len as c_int as usize, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    if len != 0 && unsafe { swrite(x, addr.cast(), len as c_int as usize, 1) } != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getpos(x: *const XDR) -> u_int {
    let f = unsafe { fp(x) };
    unsafe { ftell(f) as u_int }
}

unsafe extern "C" fn xdrstdio_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    let f = unsafe { fp(x) };
    if unsafe { fseek(f, pos as c_long, 0) } < 0 { FALSE } else { TRUE }
}

unsafe extern "C" fn xdrstdio_inline(_x: *mut XDR, _len: u_int) -> *mut i32 {
    core::ptr::null_mut()
}

unsafe extern "C" fn xdrstdio_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    let mut b = [0u8; 4];
    if unsafe { sread(x, b.as_mut_ptr().cast(), 4, 1) } != 1 {
        return FALSE;
    }
    unsafe { *ip = i32::from_be_bytes(b) };
    TRUE
}

unsafe extern "C" fn xdrstdio_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    let b = unsafe { *ip }.to_be_bytes();
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
    let x = unsafe { &mut *xdrs };
    x.x_op = op;
    x.x_ops = &XDRSTDIO_OPS;
    x.x_private = file as caddr_t;
    x.x_handy = 0;
    x.x_base = core::ptr::null_mut();
}
