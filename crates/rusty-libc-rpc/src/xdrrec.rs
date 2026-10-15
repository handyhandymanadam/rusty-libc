#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_long};

pub type XdrIoFn = Option<unsafe extern "C" fn(*mut c_char, *mut c_char, c_int) -> c_int>;

const LAST_FRAG: u32 = 1 << 31;
const UNIT: usize = BYTES_PER_XDR_UNIT as usize;

struct RecStream {
    tcp_handle: caddr_t,
    the_buffer: *mut u8,
    buf_len: usize,
    writeit: XdrIoFn,
    out_base: usize,
    out_finger: usize,
    out_boundry: usize,
    frag_header: usize,
    frag_sent: bool_t,
    readit: XdrIoFn,
    in_size: u_long,
    in_base: usize,
    in_finger: usize,
    in_boundry: usize,
    fbtbc: c_long,
    last_frag: bool_t,
}

impl RecStream {
    #[inline(always)]
    fn addr(&self, off: usize) -> *mut c_char {
        self.the_buffer.wrapping_add(off).cast()
    }

    #[inline(always)]
    unsafe fn get_word(&self, off: usize) -> u32 {
        debug_assert!(off + UNIT <= self.buf_len);
        u32::from_be_bytes(unsafe { self.the_buffer.wrapping_add(off).cast::<[u8; UNIT]>().read() })
    }

    #[inline(always)]
    unsafe fn put_word(&mut self, off: usize, v: u32) {
        debug_assert!(off + UNIT <= self.buf_len);
        unsafe { self.the_buffer.wrapping_add(off).cast::<[u8; UNIT]>().write(v.to_be_bytes()) };
    }

    #[inline(always)]
    fn in_avail(&self) -> isize {
        self.in_boundry as isize - self.in_finger as isize
    }

    #[inline(never)]
    unsafe fn getbytes(&mut self, mut addr: *mut u8, mut len: u_int) -> bool_t {
        while len > 0 {
            let mut current = self.fbtbc as u_int;
            if current == 0 {
                if self.last_frag != 0 {
                    return FALSE;
                }
                if self.set_input_fragment() == 0 {
                    return FALSE;
                }
                continue;
            }
            current = if len < current { len } else { current };
            if unsafe { self.get_input_bytes(addr, current as c_int) } == 0 {
                return FALSE;
            }
            addr = addr.wrapping_add(current as usize);
            self.fbtbc -= current as c_long;
            len -= current;
        }
        TRUE
    }

    unsafe fn putbytes(&mut self, mut addr: *const u8, mut len: u_int) -> bool_t {
        while len > 0 {
            let mut current = (self.out_boundry - self.out_finger) as u_int;
            current = if len < current { len } else { current };
            let n = current as usize;
            unsafe { core::ptr::copy_nonoverlapping(addr, self.the_buffer.wrapping_add(self.out_finger), n) };
            self.out_finger += n;
            addr = addr.wrapping_add(n);
            len -= current;
            if self.out_finger == self.out_boundry && len > 0 {
                self.frag_sent = TRUE;
                if self.flush_out(FALSE) == 0 {
                    return FALSE;
                }
            }
        }
        TRUE
    }

    #[inline]
    fn get_unit(&mut self) -> Option<i32> {
        if self.fbtbc >= UNIT as c_long && self.in_avail() >= UNIT as isize {
            let v = unsafe { self.get_word(self.in_finger) } as i32;
            self.fbtbc -= UNIT as c_long;
            self.in_finger += UNIT;
            Some(v)
        } else {
            let mut b = [0u8; UNIT];
            if unsafe { self.getbytes(b.as_mut_ptr(), UNIT as u_int) } == 0 {
                return None;
            }
            Some(i32::from_be_bytes(b))
        }
    }

    #[inline]
    fn put_unit(&mut self, v: i32) -> bool_t {
        let mut dest = self.out_finger;
        self.out_finger += UNIT;
        if self.out_finger > self.out_boundry {
            self.out_finger -= UNIT;
            self.frag_sent = TRUE;
            if self.flush_out(FALSE) == 0 {
                return FALSE;
            }
            dest = self.out_finger;
            self.out_finger += UNIT;
        }
        unsafe { self.put_word(dest, v as u32) };
        TRUE
    }

    #[inline(never)]
    fn flush_out(&mut self, eor: bool_t) -> bool_t {
        let eormask: u32 = if eor == TRUE { LAST_FRAG } else { 0 };
        let len = (self.out_finger - self.frag_header - UNIT) as u32;
        unsafe { self.put_word(self.frag_header, len | eormask) };
        let len = (self.out_finger - self.out_base) as c_int;
        let w = match self.writeit {
            Some(f) => unsafe { f(self.tcp_handle, self.addr(self.out_base), len) },
            None => -1,
        };
        if w != len {
            return FALSE;
        }
        self.frag_header = self.out_base;
        self.out_finger = self.out_base + UNIT;
        TRUE
    }

    #[inline]
    fn fill_input_buf(&mut self) -> bool_t {
        let i = (self.addr(self.in_boundry) as usize) % UNIT;
        let where_ = self.in_base + i;
        let len = (self.in_size as usize - i) as c_int;
        let want = len;
        let len = match self.readit {
            Some(f) => unsafe { f(self.tcp_handle, self.addr(where_), len) },
            None => -1,
        };
        if len == -1 {
            return FALSE;
        }
        if !(0..=want).contains(&len) {
            return FALSE;
        }
        self.in_finger = where_;
        self.in_boundry = (where_ as isize + len as isize) as usize;
        TRUE
    }

    unsafe fn get_input_bytes(&mut self, mut addr: *mut u8, mut len: c_int) -> bool_t {
        while len > 0 {
            let mut current = self.in_avail() as c_int;
            if current == 0 {
                if self.fill_input_buf() == 0 {
                    return FALSE;
                }
                continue;
            }
            current = if len < current { len } else { current };
            let n = current as usize;
            unsafe { core::ptr::copy_nonoverlapping(self.the_buffer.wrapping_add(self.in_finger), addr, n) };
            self.in_finger += n;
            addr = addr.wrapping_add(n);
            len -= current;
        }
        TRUE
    }

    #[inline]
    fn set_input_fragment(&mut self) -> bool_t {
        let mut b = [0u8; UNIT];
        if unsafe { self.get_input_bytes(b.as_mut_ptr(), UNIT as c_int) } == 0 {
            return FALSE;
        }
        let header = u32::from_be_bytes(b);
        self.last_frag = if header & LAST_FRAG == 0 { FALSE } else { TRUE };
        if header == 0 {
            return FALSE;
        }
        self.fbtbc = (header & !LAST_FRAG) as c_long;
        TRUE
    }

    fn skip_input_bytes(&mut self, mut cnt: c_long) -> bool_t {
        while cnt > 0 {
            let mut current = self.in_avail() as c_int;
            if current == 0 {
                if self.fill_input_buf() == 0 {
                    return FALSE;
                }
                continue;
            }
            current = if (cnt as c_int) < current { cnt as c_int } else { current };
            self.in_finger += current as usize;
            cnt -= current as c_long;
        }
        TRUE
    }

    fn skiprecord(&mut self) -> bool_t {
        while self.fbtbc > 0 || self.last_frag == 0 {
            if self.skip_input_bytes(self.fbtbc) == 0 {
                return FALSE;
            }
            self.fbtbc = 0;
            if self.last_frag == 0 && self.set_input_fragment() == 0 {
                return FALSE;
            }
        }
        self.last_frag = FALSE;
        TRUE
    }

    fn eof(&mut self) -> bool_t {
        while self.fbtbc > 0 || self.last_frag == 0 {
            if self.skip_input_bytes(self.fbtbc) == 0 {
                return TRUE;
            }
            self.fbtbc = 0;
            if self.last_frag == 0 && self.set_input_fragment() == 0 {
                return TRUE;
            }
        }
        if self.in_finger == self.in_boundry {
            return TRUE;
        }
        FALSE
    }

    fn endofrecord(&mut self, sendnow: bool_t) -> bool_t {
        if sendnow != 0 || self.frag_sent != 0 || self.out_finger + UNIT >= self.out_boundry {
            self.frag_sent = FALSE;
            return self.flush_out(TRUE);
        }
        let len = (self.out_finger - self.frag_header - UNIT) as u_long;
        unsafe { self.put_word(self.frag_header, (len as u32) | LAST_FRAG) };
        self.frag_header = self.out_finger;
        self.out_finger += UNIT;
        TRUE
    }

    fn getpos(&self, op: c_int) -> u_int {
        let mut pos = rusty_libc_sys::unistd::lseek(self.tcp_handle as isize as c_int, 0, 1) as c_long;
        if pos != -1 {
            match op {
                XDR_ENCODE => pos += (self.out_finger as isize - self.out_base as isize) as c_long,
                XDR_DECODE => pos -= (self.in_boundry as isize - self.in_finger as isize) as c_long,
                _ => pos = u_int::MAX as c_long,
            }
        }
        pos as u_int
    }

    fn setpos(&mut self, op: c_int, pos: u_int) -> bool_t {
        let currpos = self.getpos(op);
        let delta = currpos.wrapping_sub(pos) as c_int;
        if currpos as c_int != -1 {
            match op {
                XDR_ENCODE => {
                    let newpos = self.out_finger as isize - delta as isize;
                    if newpos > self.frag_header as isize && newpos < self.out_boundry as isize {
                        self.out_finger = newpos as usize;
                        return TRUE;
                    }
                }
                XDR_DECODE => {
                    let newpos = self.in_finger as isize - delta as isize;
                    if (delta as c_long) < self.fbtbc && newpos <= self.in_boundry as isize && newpos >= self.in_base as isize {
                        self.in_finger = newpos as usize;
                        self.fbtbc -= delta as c_long;
                        return TRUE;
                    }
                }
                _ => {}
            }
        }
        FALSE
    }

    fn inline(&mut self, op: c_int, len: u_int) -> *mut i32 {
        let mut buf: *mut i32 = core::ptr::null_mut();
        match op {
            XDR_ENCODE => {
                if self.out_finger + len as usize <= self.out_boundry {
                    buf = self.addr(self.out_finger).cast();
                    self.out_finger += len as usize;
                }
            }
            XDR_DECODE => {
                if (len as c_long) <= self.fbtbc && self.in_finger + len as usize <= self.in_boundry {
                    buf = self.addr(self.in_finger).cast();
                    self.fbtbc -= len as c_long;
                    self.in_finger += len as usize;
                }
            }
            _ => {}
        }
        buf
    }
}

#[inline(always)]
unsafe fn rs<'a>(xdrs: *const XDR) -> &'a mut RecStream {
    let p = unsafe { (*xdrs).x_private };
    unsafe { &mut *p.cast::<RecStream>() }
}

#[inline(always)]
unsafe fn op_of(xdrs: *const XDR) -> c_int {
    unsafe { (*xdrs).x_op }
}

fn fix_buf_size(mut s: u_int) -> u_int {
    if s < 100 {
        s = 4000;
    }
    crate::xdr::rndup(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_create(xdrs: *mut XDR, sendsize: u_int, recvsize: u_int, tcp_handle: caddr_t, readit: XdrIoFn, writeit: XdrIoFn) {
    let rstrm = alloc(core::mem::size_of::<RecStream>()) as *mut RecStream;
    let sendsize = fix_buf_size(sendsize);
    let recvsize = fix_buf_size(recvsize);
    let buf_len = (sendsize + recvsize + BYTES_PER_XDR_UNIT) as usize;
    let buf = alloc(buf_len) as *mut u8;
    if rstrm.is_null() || buf.is_null() {
        oom("xdrrec_create");
        unsafe { mem_free(rstrm.cast()) };
        unsafe { mem_free(buf.cast()) };
        return;
    }
    let mis = (buf as usize) % UNIT;
    let out_base = if mis != 0 { UNIT - mis } else { 0 };
    let in_base = out_base + sendsize as usize;
    let state = RecStream {
        tcp_handle,
        the_buffer: buf,
        buf_len,
        writeit,
        out_base,
        out_finger: out_base + UNIT,
        out_boundry: out_base + sendsize as usize,
        frag_header: out_base,
        frag_sent: FALSE,
        readit,
        in_size: recvsize as u_long,
        in_base,
        in_finger: in_base + recvsize as usize,
        in_boundry: in_base + recvsize as usize,
        fbtbc: 0,
        last_frag: TRUE,
    };
    unsafe { rstrm.write(state) };
    let x = unsafe { &mut *xdrs };
    x.x_ops = &XDRREC_OPS;
    x.x_private = rstrm.cast();
}

unsafe extern "C" fn xdrrec_getlong(xdrs: *mut XDR, lp: *mut c_long) -> bool_t {
    let Some(v) = unsafe { rs(xdrs) }.get_unit() else { return FALSE };
    unsafe { *lp = v as c_long };
    TRUE
}

unsafe extern "C" fn xdrrec_putlong(xdrs: *mut XDR, lp: *const c_long) -> bool_t {
    let v = unsafe { *lp } as i32;
    unsafe { rs(xdrs) }.put_unit(v)
}

unsafe extern "C" fn xdrrec_getbytes(xdrs: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    let r = unsafe { rs(xdrs) };
    unsafe { r.getbytes(addr.cast(), len) }
}

unsafe extern "C" fn xdrrec_putbytes(xdrs: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    let r = unsafe { rs(xdrs) };
    unsafe { r.putbytes(addr.cast(), len) }
}

unsafe extern "C" fn xdrrec_getpos(xdrs: *const XDR) -> u_int {
    let op = unsafe { op_of(xdrs) };
    unsafe { rs(xdrs) }.getpos(op)
}

unsafe extern "C" fn xdrrec_setpos(xdrs: *mut XDR, pos: u_int) -> bool_t {
    let op = unsafe { op_of(xdrs) };
    unsafe { rs(xdrs) }.setpos(op, pos)
}

unsafe extern "C" fn xdrrec_inline(xdrs: *mut XDR, len: u_int) -> *mut i32 {
    let op = unsafe { op_of(xdrs) };
    unsafe { rs(xdrs) }.inline(op, len)
}

unsafe extern "C" fn xdrrec_destroy(xdrs: *mut XDR) {
    let r = unsafe { rs(xdrs) };
    let (buf, state) = (r.the_buffer, core::ptr::from_mut(r));
    unsafe { mem_free(buf.cast()) };
    unsafe { mem_free(state.cast()) };
}

unsafe extern "C" fn xdrrec_getint32(xdrs: *mut XDR, ip: *mut i32) -> bool_t {
    let Some(v) = unsafe { rs(xdrs) }.get_unit() else { return FALSE };
    unsafe { *ip = v };
    TRUE
}

unsafe extern "C" fn xdrrec_putint32(xdrs: *mut XDR, ip: *const i32) -> bool_t {
    let v = unsafe { *ip };
    unsafe { rs(xdrs) }.put_unit(v)
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
    unsafe { rs(xdrs) }.skiprecord()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_eof(xdrs: *mut XDR) -> bool_t {
    unsafe { rs(xdrs) }.eof()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_endofrecord(xdrs: *mut XDR, sendnow: bool_t) -> bool_t {
    unsafe { rs(xdrs) }.endofrecord(sendnow)
}
