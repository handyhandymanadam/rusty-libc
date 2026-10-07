use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_long};

pub type XdrIoFn = Option<unsafe extern "C" fn(*mut c_char, *mut c_char, c_int) -> c_int>;

const LAST_FRAG: u32 = 1 << 31;

#[repr(C)]
struct RecStream {
    tcp_handle: caddr_t,
    the_buffer: caddr_t,
    writeit: XdrIoFn,
    out_base: caddr_t,
    out_finger: caddr_t,
    out_boundry: caddr_t,
    frag_header: *mut u32,
    frag_sent: bool_t,
    readit: XdrIoFn,
    in_size: u_long,
    in_base: caddr_t,
    in_finger: caddr_t,
    in_boundry: caddr_t,
    fbtbc: c_long,
    last_frag: bool_t,
    sendsize: u_int,
    recvsize: u_int,
}

#[inline]
unsafe fn rs(xdrs: *mut XDR) -> *mut RecStream {
    (*xdrs).x_private as *mut RecStream
}

fn fix_buf_size(mut s: u_int) -> u_int {
    if s < 100 {
        s = 4000;
    }
    crate::xdr::rndup(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_create(xdrs: *mut XDR, sendsize: u_int, recvsize: u_int, tcp_handle: caddr_t, readit: XdrIoFn, writeit: XdrIoFn) {
    let rstrm = mem_alloc(core::mem::size_of::<RecStream>()) as *mut RecStream;
    let sendsize = fix_buf_size(sendsize);
    let recvsize = fix_buf_size(recvsize);
    let buf = mem_alloc((sendsize + recvsize + BYTES_PER_XDR_UNIT) as usize) as caddr_t;
    if rstrm.is_null() || buf.is_null() {
        oom("xdrrec_create");
        mem_free(rstrm.cast());
        mem_free(buf.cast());
        return;
    }
    (*rstrm).sendsize = sendsize;
    (*rstrm).recvsize = recvsize;
    (*rstrm).the_buffer = buf;
    let mut tmp = buf;
    if (tmp as usize) % BYTES_PER_XDR_UNIT as usize != 0 {
        tmp = tmp.add(BYTES_PER_XDR_UNIT as usize - (tmp as usize) % BYTES_PER_XDR_UNIT as usize);
    }
    (*rstrm).out_base = tmp;
    (*rstrm).in_base = tmp.add(sendsize as usize);
    (*xdrs).x_ops = &XDRREC_OPS;
    (*xdrs).x_private = rstrm as caddr_t;
    (*rstrm).tcp_handle = tcp_handle;
    (*rstrm).readit = readit;
    (*rstrm).writeit = writeit;
    (*rstrm).out_boundry = (*rstrm).out_base;
    (*rstrm).out_finger = (*rstrm).out_base;
    (*rstrm).frag_header = (*rstrm).out_base as *mut u32;
    (*rstrm).out_finger = (*rstrm).out_finger.add(4);
    (*rstrm).out_boundry = (*rstrm).out_boundry.add(sendsize as usize);
    (*rstrm).frag_sent = FALSE;
    (*rstrm).in_size = recvsize as u_long;
    (*rstrm).in_boundry = (*rstrm).in_base;
    (*rstrm).in_boundry = (*rstrm).in_boundry.add(recvsize as usize);
    (*rstrm).in_finger = (*rstrm).in_boundry;
    (*rstrm).fbtbc = 0;
    (*rstrm).last_frag = TRUE;
}

unsafe extern "C" fn xdrrec_getlong(xdrs: *mut XDR, lp: *mut c_long) -> bool_t {
    let r = rs(xdrs);
    let buflp = (*r).in_finger as *const i32;
    if (*r).fbtbc >= BYTES_PER_XDR_UNIT as c_long && ((*r).in_boundry as isize - buflp as isize) >= BYTES_PER_XDR_UNIT as isize {
        *lp = i32::from_be(core::ptr::read_unaligned(buflp)) as c_long;
        (*r).fbtbc -= BYTES_PER_XDR_UNIT as c_long;
        (*r).in_finger = (*r).in_finger.add(BYTES_PER_XDR_UNIT as usize);
    } else {
        let mut mylong: i32 = 0;
        if xdrrec_getbytes(xdrs, (&mut mylong as *mut i32).cast(), BYTES_PER_XDR_UNIT) == 0 {
            return FALSE;
        }
        *lp = i32::from_be(mylong) as c_long;
    }
    TRUE
}

unsafe extern "C" fn xdrrec_putlong(xdrs: *mut XDR, lp: *const c_long) -> bool_t {
    let r = rs(xdrs);
    let mut dest_lp = (*r).out_finger as *mut i32;
    (*r).out_finger = (*r).out_finger.add(BYTES_PER_XDR_UNIT as usize);
    if (*r).out_finger > (*r).out_boundry {
        (*r).out_finger = (*r).out_finger.sub(BYTES_PER_XDR_UNIT as usize);
        (*r).frag_sent = TRUE;
        if flush_out(r, FALSE) == 0 {
            return FALSE;
        }
        dest_lp = (*r).out_finger as *mut i32;
        (*r).out_finger = (*r).out_finger.add(BYTES_PER_XDR_UNIT as usize);
    }
    core::ptr::write_unaligned(dest_lp, (*lp as i32).to_be());
    TRUE
}

unsafe extern "C" fn xdrrec_getbytes(xdrs: *mut XDR, mut addr: caddr_t, mut len: u_int) -> bool_t {
    let r = rs(xdrs);
    while len > 0 {
        let mut current = (*r).fbtbc as u_int;
        if current == 0 {
            if (*r).last_frag != 0 {
                return FALSE;
            }
            if set_input_fragment(r) == 0 {
                return FALSE;
            }
            continue;
        }
        current = if len < current { len } else { current };
        if get_input_bytes(r, addr, current as c_int) == 0 {
            return FALSE;
        }
        addr = addr.add(current as usize);
        (*r).fbtbc -= current as c_long;
        len -= current;
    }
    TRUE
}

unsafe extern "C" fn xdrrec_putbytes(xdrs: *mut XDR, mut addr: *const c_char, mut len: u_int) -> bool_t {
    let r = rs(xdrs);
    while len > 0 {
        let mut current = ((*r).out_boundry as usize - (*r).out_finger as usize) as u_int;
        current = if len < current { len } else { current };
        core::ptr::copy_nonoverlapping(addr as *const u8, (*r).out_finger as *mut u8, current as usize);
        (*r).out_finger = (*r).out_finger.add(current as usize);
        addr = addr.add(current as usize);
        len -= current;
        if (*r).out_finger == (*r).out_boundry && len > 0 {
            (*r).frag_sent = TRUE;
            if flush_out(r, FALSE) == 0 {
                return FALSE;
            }
        }
    }
    TRUE
}

unsafe extern "C" fn xdrrec_getpos(xdrs: *const XDR) -> u_int {
    let r = (*xdrs).x_private as *mut RecStream;
    let mut pos = rusty_libc_sys::unistd::lseek((*r).tcp_handle as isize as c_int, 0, 1) as c_long;
    if pos != -1 {
        match (*xdrs).x_op {
            XDR_ENCODE => pos += ((*r).out_finger as isize - (*r).out_base as isize) as c_long,
            XDR_DECODE => pos -= ((*r).in_boundry as isize - (*r).in_finger as isize) as c_long,
            _ => pos = u_int::MAX as c_long,
        }
    }
    pos as u_int
}

unsafe extern "C" fn xdrrec_setpos(xdrs: *mut XDR, pos: u_int) -> bool_t {
    let r = rs(xdrs);
    let currpos = xdrrec_getpos(xdrs);
    let delta = currpos.wrapping_sub(pos) as c_int;
    if currpos as c_int != -1 {
        match (*xdrs).x_op {
            XDR_ENCODE => {
                let newpos = ((*r).out_finger as isize - delta as isize) as caddr_t;
                if newpos > (*r).frag_header as caddr_t && newpos < (*r).out_boundry {
                    (*r).out_finger = newpos;
                    return TRUE;
                }
            }
            XDR_DECODE => {
                let newpos = ((*r).in_finger as isize - delta as isize) as caddr_t;
                if (delta as c_long) < (*r).fbtbc && newpos <= (*r).in_boundry && newpos >= (*r).in_base {
                    (*r).in_finger = newpos;
                    (*r).fbtbc -= delta as c_long;
                    return TRUE;
                }
            }
            _ => {}
        }
    }
    FALSE
}

unsafe extern "C" fn xdrrec_inline(xdrs: *mut XDR, len: u_int) -> *mut i32 {
    let r = rs(xdrs);
    let mut buf: *mut i32 = core::ptr::null_mut();
    match (*xdrs).x_op {
        XDR_ENCODE => {
            if (*r).out_finger as usize + len as usize <= (*r).out_boundry as usize {
                buf = (*r).out_finger as *mut i32;
                (*r).out_finger = (*r).out_finger.add(len as usize);
            }
        }
        XDR_DECODE => {
            if (len as c_long) <= (*r).fbtbc && (*r).in_finger as usize + len as usize <= (*r).in_boundry as usize {
                buf = (*r).in_finger as *mut i32;
                (*r).fbtbc -= len as c_long;
                (*r).in_finger = (*r).in_finger.add(len as usize);
            }
        }
        _ => {}
    }
    buf
}

unsafe extern "C" fn xdrrec_destroy(xdrs: *mut XDR) {
    let r = rs(xdrs);
    mem_free((*r).the_buffer.cast());
    mem_free(r.cast());
}

unsafe extern "C" fn xdrrec_getint32(xdrs: *mut XDR, ip: *mut i32) -> bool_t {
    let r = rs(xdrs);
    let bufip = (*r).in_finger as *const i32;
    if (*r).fbtbc >= BYTES_PER_XDR_UNIT as c_long && ((*r).in_boundry as isize - bufip as isize) >= BYTES_PER_XDR_UNIT as isize {
        *ip = i32::from_be(core::ptr::read_unaligned(bufip));
        (*r).fbtbc -= BYTES_PER_XDR_UNIT as c_long;
        (*r).in_finger = (*r).in_finger.add(BYTES_PER_XDR_UNIT as usize);
    } else {
        let mut mylong: i32 = 0;
        if xdrrec_getbytes(xdrs, (&mut mylong as *mut i32).cast(), BYTES_PER_XDR_UNIT) == 0 {
            return FALSE;
        }
        *ip = i32::from_be(mylong);
    }
    TRUE
}

unsafe extern "C" fn xdrrec_putint32(xdrs: *mut XDR, ip: *const i32) -> bool_t {
    let r = rs(xdrs);
    let mut dest_ip = (*r).out_finger as *mut i32;
    (*r).out_finger = (*r).out_finger.add(BYTES_PER_XDR_UNIT as usize);
    if (*r).out_finger > (*r).out_boundry {
        (*r).out_finger = (*r).out_finger.sub(BYTES_PER_XDR_UNIT as usize);
        (*r).frag_sent = TRUE;
        if flush_out(r, FALSE) == 0 {
            return FALSE;
        }
        dest_ip = (*r).out_finger as *mut i32;
        (*r).out_finger = (*r).out_finger.add(BYTES_PER_XDR_UNIT as usize);
    }
    core::ptr::write_unaligned(dest_ip, (*ip).to_be());
    TRUE
}

static XDRREC_OPS: xdr_ops = xdr_ops {
    x_getlong: Some(xdrrec_getlong),
    x_putlong: Some(xdrrec_putlong),
    x_getbytes: Some(xdrrec_getbytes),
    x_putbytes: Some(xdrrec_putbytes),
    x_getpostn: Some(xdrrec_getpos),
    x_setpostn: Some(xdrrec_setpos),
    x_inline: Some(xdrrec_inline),
    x_destroy: Some(xdrrec_destroy),
    x_getint32: Some(xdrrec_getint32),
    x_putint32: Some(xdrrec_putint32),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_skiprecord(xdrs: *mut XDR) -> bool_t {
    let r = rs(xdrs);
    while (*r).fbtbc > 0 || (*r).last_frag == 0 {
        if skip_input_bytes(r, (*r).fbtbc) == 0 {
            return FALSE;
        }
        (*r).fbtbc = 0;
        if (*r).last_frag == 0 && set_input_fragment(r) == 0 {
            return FALSE;
        }
    }
    (*r).last_frag = FALSE;
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_eof(xdrs: *mut XDR) -> bool_t {
    let r = rs(xdrs);
    while (*r).fbtbc > 0 || (*r).last_frag == 0 {
        if skip_input_bytes(r, (*r).fbtbc) == 0 {
            return TRUE;
        }
        (*r).fbtbc = 0;
        if (*r).last_frag == 0 && set_input_fragment(r) == 0 {
            return TRUE;
        }
    }
    if (*r).in_finger == (*r).in_boundry {
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_endofrecord(xdrs: *mut XDR, sendnow: bool_t) -> bool_t {
    let r = rs(xdrs);
    if sendnow != 0 || (*r).frag_sent != 0 || (*r).out_finger as usize + BYTES_PER_XDR_UNIT as usize >= (*r).out_boundry as usize {
        (*r).frag_sent = FALSE;
        return flush_out(r, TRUE);
    }
    let len = ((*r).out_finger as usize - (*r).frag_header as usize - BYTES_PER_XDR_UNIT as usize) as u_long;
    core::ptr::write_unaligned((*r).frag_header, ((len as u32) | LAST_FRAG).to_be());
    (*r).frag_header = (*r).out_finger as *mut u32;
    (*r).out_finger = (*r).out_finger.add(BYTES_PER_XDR_UNIT as usize);
    TRUE
}

unsafe fn flush_out(r: *mut RecStream, eor: bool_t) -> bool_t {
    let eormask: u32 = if eor == TRUE { LAST_FRAG } else { 0 };
    let len = ((*r).out_finger as usize - (*r).frag_header as usize - BYTES_PER_XDR_UNIT as usize) as u32;
    core::ptr::write_unaligned((*r).frag_header, (len | eormask).to_be());
    let len = ((*r).out_finger as usize - (*r).out_base as usize) as c_int;
    let w = match (*r).writeit {
        Some(f) => f((*r).tcp_handle, (*r).out_base, len),
        None => -1,
    };
    if w != len {
        return FALSE;
    }
    (*r).frag_header = (*r).out_base as *mut u32;
    (*r).out_finger = (*r).out_base.add(BYTES_PER_XDR_UNIT as usize);
    TRUE
}

unsafe fn fill_input_buf(r: *mut RecStream) -> bool_t {
    let mut where_ = (*r).in_base;
    let i = ((*r).in_boundry as usize) % BYTES_PER_XDR_UNIT as usize;
    where_ = where_.add(i);
    let len = ((*r).in_size as usize - i) as c_int;
    let len = match (*r).readit {
        Some(f) => f((*r).tcp_handle, where_, len),
        None => -1,
    };
    if len == -1 {
        return FALSE;
    }
    (*r).in_finger = where_;
    where_ = where_.offset(len as isize);
    (*r).in_boundry = where_;
    TRUE
}

unsafe fn get_input_bytes(r: *mut RecStream, mut addr: caddr_t, mut len: c_int) -> bool_t {
    while len > 0 {
        let mut current = ((*r).in_boundry as isize - (*r).in_finger as isize) as c_int;
        if current == 0 {
            if fill_input_buf(r) == 0 {
                return FALSE;
            }
            continue;
        }
        current = if len < current { len } else { current };
        core::ptr::copy_nonoverlapping((*r).in_finger as *const u8, addr as *mut u8, current as usize);
        (*r).in_finger = (*r).in_finger.add(current as usize);
        addr = addr.add(current as usize);
        len -= current;
    }
    TRUE
}

unsafe fn set_input_fragment(r: *mut RecStream) -> bool_t {
    let mut header: u32 = 0;
    if get_input_bytes(r, (&mut header as *mut u32).cast(), BYTES_PER_XDR_UNIT as c_int) == 0 {
        return FALSE;
    }
    header = u32::from_be(header);
    (*r).last_frag = if header & LAST_FRAG == 0 { FALSE } else { TRUE };
    if header == 0 {
        return FALSE;
    }
    (*r).fbtbc = (header & !LAST_FRAG) as c_long;
    TRUE
}

unsafe fn skip_input_bytes(r: *mut RecStream, mut cnt: c_long) -> bool_t {
    while cnt > 0 {
        let mut current = ((*r).in_boundry as isize - (*r).in_finger as isize) as c_int;
        if current == 0 {
            if fill_input_buf(r) == 0 {
                return FALSE;
            }
            continue;
        }
        current = if (cnt as c_int) < current { cnt as c_int } else { current };
        (*r).in_finger = (*r).in_finger.add(current as usize);
        cnt -= current as c_long;
    }
    TRUE
}
