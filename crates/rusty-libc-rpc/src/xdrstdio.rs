use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::{fflush, fread, fseek, ftell, fwrite};

#[inline]
unsafe fn fp(x: *mut XDR) -> *mut FILE {
    (*x).x_private as *mut FILE
}

unsafe extern "C" fn xdrstdio_destroy(x: *mut XDR) {
    fflush(fp(x));
}

unsafe extern "C" fn xdrstdio_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    let mut mycopy: u32 = 0;
    if fread((&mut mycopy as *mut u32).cast::<c_void>(), 4, 1, fp(x)) != 1 {
        return FALSE;
    }
    *lp = u32::from_be(mycopy) as c_long;
    TRUE
}

unsafe extern "C" fn xdrstdio_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    let mycopy = (*lp as u32).to_be();
    if fwrite((&mycopy as *const u32).cast::<c_void>(), 4, 1, fp(x)) != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    if len != 0 && fread(addr.cast::<c_void>(), len as c_int as usize, 1, fp(x)) != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    if len != 0 && fwrite(addr.cast::<c_void>(), len as c_int as usize, 1, fp(x)) != 1 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn xdrstdio_getpos(x: *const XDR) -> u_int {
    ftell((*x).x_private as *mut FILE) as u_int
}

unsafe extern "C" fn xdrstdio_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    if fseek(fp(x), pos as c_long, 0) < 0 { FALSE } else { TRUE }
}

unsafe extern "C" fn xdrstdio_inline(_x: *mut XDR, _len: u_int) -> *mut i32 {
    core::ptr::null_mut()
}

unsafe extern "C" fn xdrstdio_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    let mut mycopy: i32 = 0;
    if fread((&mut mycopy as *mut i32).cast::<c_void>(), 4, 1, fp(x)) != 1 {
        return FALSE;
    }
    *ip = i32::from_be(mycopy);
    TRUE
}

unsafe extern "C" fn xdrstdio_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    let mycopy = (*ip).to_be();
    if fwrite((&mycopy as *const i32).cast::<c_void>(), 4, 1, fp(x)) != 1 {
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
    (*xdrs).x_op = op;
    (*xdrs).x_ops = &XDRSTDIO_OPS;
    (*xdrs).x_private = file as caddr_t;
    (*xdrs).x_handy = 0;
    (*xdrs).x_base = core::ptr::null_mut();
}
