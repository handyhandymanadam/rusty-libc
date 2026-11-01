//! The record-marking XDR stream (RFC 5531 section 11) used over TCP: `xdrrec_create`,
//! `xdrrec_endofrecord`, `xdrrec_skiprecord`, `xdrrec_eof`. Port of Sun's `xdr_rec.c`.
//!
//! The stream's private state ([`RecStream`], never seen by C) keeps its cursors as offsets into its one `malloc` buffer,
//! so the record logic is offset arithmetic in safe Rust. What stays unsafe: turning the handle's `x_private` back into
//! the state, the C read/write callbacks, the caller's buffers in `x_getbytes`/`x_putbytes`, and four raw buffer
//! accessors at offsets the state's invariant bounds (a hot path; see the `impl RecStream` comment).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_long};

pub type XdrIoFn = Option<unsafe extern "C" fn(*mut c_char, *mut c_char, c_int) -> c_int>;

const LAST_FRAG: u32 = 1 << 31;
const UNIT: usize = BYTES_PER_XDR_UNIT as usize;

/// The private state of a record stream. Offsets count from the start of `the_buffer` (`buf_len` bytes from malloc);
/// the output area is `out_base..out_boundry`, the input area `in_base..in_base + in_size`.
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

/// The offsets keep this order (set by xdrrec_create, kept by every method; a read callback's count is checked before it
/// moves `in_boundry`): `out_base <= frag_header < out_finger <= out_boundry <= in_base` with
/// `frag_header + UNIT <= out_boundry`, and `in_base <= in_finger <= in_boundry <= in_base + in_size <= buf_len`. The accessors below rely on it: the record
/// stream is the TCP and UNIX transports' per-call path, and checked slices cost it about 300 instructions a call
/// (measured with callgrind), so the buffer accesses (words, and the copy loops between it and the caller's raw
/// buffer, as in Sun's code) are raw, at offsets the invariant bounds.
impl RecStream {
    /// The address of offset `off` (for the C callbacks and `x_inline`).
    #[inline(always)]
    fn addr(&self, off: usize) -> *mut c_char {
        self.the_buffer.wrapping_add(off).cast()
    }

    /// The word in network byte order at `off`.
    ///
    /// # Safety
    /// `off + UNIT <= buf_len`.
    #[inline(always)]
    unsafe fn get_word(&self, off: usize) -> u32 {
        debug_assert!(off + UNIT <= self.buf_len);
        // SAFETY: inside our malloc block of `buf_len` bytes (caller's contract); unaligned read of plain bytes.
        u32::from_be_bytes(unsafe { self.the_buffer.wrapping_add(off).cast::<[u8; UNIT]>().read() })
    }

    /// Store a word in network byte order at `off`.
    ///
    /// # Safety
    /// `off + UNIT <= buf_len`.
    #[inline(always)]
    unsafe fn put_word(&mut self, off: usize, v: u32) {
        debug_assert!(off + UNIT <= self.buf_len);
        // SAFETY: inside our malloc block (caller's contract), which only the stream reaches.
        unsafe { self.the_buffer.wrapping_add(off).cast::<[u8; UNIT]>().write(v.to_be_bytes()) };
    }

    /// Bytes left in the input buffer.
    #[inline(always)]
    fn in_avail(&self) -> isize {
        self.in_boundry as isize - self.in_finger as isize
    }

    /// Fill the `len` bytes at `addr` from the current fragment, crossing fragments as needed (Sun's loop, on the
    /// caller's raw buffer: the per-call path of the record stream).
    ///
    /// # Safety
    /// `addr` points to `len` writable bytes that are not inside our buffer.
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
            // SAFETY: `current` <= `len`, so the bytes at `addr` are the caller's (contract).
            if unsafe { self.get_input_bytes(addr, current as c_int) } == 0 {
                return FALSE;
            }
            addr = addr.wrapping_add(current as usize);
            self.fbtbc -= current as c_long;
            len -= current;
        }
        TRUE
    }

    /// Append the `len` bytes at `addr` to the record, sending full fragments as needed.
    ///
    /// # Safety
    /// `addr` points to `len` readable bytes that are not inside our buffer.
    unsafe fn putbytes(&mut self, mut addr: *const u8, mut len: u_int) -> bool_t {
        while len > 0 {
            let mut current = (self.out_boundry - self.out_finger) as u_int;
            current = if len < current { len } else { current };
            let n = current as usize;
            // SAFETY: `n` <= `out_boundry - out_finger` and `out_boundry <= buf_len` (the invariant); the caller's
            // bytes at `addr` (contract) are other memory.
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

    /// One unit from the input, the fast way when the fragment and the buffer both hold it.
    #[inline]
    fn get_unit(&mut self) -> Option<i32> {
        if self.fbtbc >= UNIT as c_long && self.in_avail() >= UNIT as isize {
            // SAFETY: `in_finger + UNIT <= in_boundry <= buf_len` (just checked; the invariant).
            let v = unsafe { self.get_word(self.in_finger) } as i32;
            self.fbtbc -= UNIT as c_long;
            self.in_finger += UNIT;
            Some(v)
        } else {
            let mut b = [0u8; UNIT];
            // SAFETY: a local of UNIT bytes.
            if unsafe { self.getbytes(b.as_mut_ptr(), UNIT as u_int) } == 0 {
                return None;
            }
            Some(i32::from_be_bytes(b))
        }
    }

    /// One unit to the output, sending the fragment first when it is full.
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
        // SAFETY: `dest + UNIT == out_finger <= out_boundry <= buf_len` (checked above; after a flush `out_finger` is
        // `out_base + UNIT`, and the area holds at least 100 bytes).
        unsafe { self.put_word(dest, v as u32) };
        TRUE
    }

    // out of line: rare per call, and inlined its loads would be hoisted into the copy loops
    #[inline(never)]
    fn flush_out(&mut self, eor: bool_t) -> bool_t {
        let eormask: u32 = if eor == TRUE { LAST_FRAG } else { 0 };
        let len = (self.out_finger - self.frag_header - UNIT) as u32;
        // SAFETY: `frag_header + UNIT <= out_boundry <= buf_len`: a fragment header is placed at `out_base` or at an
        // `out_finger` with room for a unit before `out_boundry` (endofrecord).
        unsafe { self.put_word(self.frag_header, len | eormask) };
        let len = (self.out_finger - self.out_base) as c_int;
        let w = match self.writeit {
            // SAFETY: the C contract of xdrrec_create: `writeit` writes `len` bytes from the buffer it gets to the
            // transport behind `tcp_handle`; the bytes `out_base..out_finger` are inside our buffer.
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

    // inlined only into getbytes (itself out of line), as in Sun's code
    #[inline]
    fn fill_input_buf(&mut self) -> bool_t {
        let i = (self.addr(self.in_boundry) as usize) % UNIT;
        let where_ = self.in_base + i;
        let len = (self.in_size as usize - i) as c_int;
        let want = len;
        let len = match self.readit {
            // SAFETY: the C contract of xdrrec_create: `readit` reads at most `len` bytes into the buffer it gets;
            // `where_..where_ + len` is inside the input area of our buffer.
            Some(f) => unsafe { f(self.tcp_handle, self.addr(where_), len) },
            None => -1,
        };
        if len == -1 {
            return FALSE;
        }
        if !(0..=want).contains(&len) {
            // a read callback that claims more than it was given room for (or a negative count other than -1) breaks
            // its contract; glibc would read past the buffer, here the read fails
            return FALSE;
        }
        self.in_finger = where_;
        self.in_boundry = (where_ as isize + len as isize) as usize;
        TRUE
    }

    /// Copy `len` bytes of input to `addr`, refilling the buffer as needed.
    ///
    /// # Safety
    /// `addr` points to `len` writable bytes that are not inside our buffer.
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
            // SAFETY: `n` <= `in_boundry - in_finger` and `in_boundry <= buf_len` (the invariant); the caller's bytes
            // at `addr` (contract) are other memory.
            unsafe { core::ptr::copy_nonoverlapping(self.the_buffer.wrapping_add(self.in_finger), addr, n) };
            self.in_finger += n;
            addr = addr.wrapping_add(n);
            len -= current;
        }
        TRUE
    }

    // inlined only into getbytes (itself out of line), as in Sun's code
    #[inline]
    fn set_input_fragment(&mut self) -> bool_t {
        let mut b = [0u8; UNIT];
        // SAFETY: a local of UNIT bytes.
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
        // SAFETY: `frag_header + UNIT <= out_boundry <= buf_len` (see flush_out).
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

/// The record state behind a record stream's handle.
///
/// # Safety
/// `xdrs` is a live handle that `xdrrec_create` set up (its `x_private` is our state), and nothing else uses that state
/// for `'a`.
#[inline(always)]
unsafe fn rs<'a>(xdrs: *const XDR) -> &'a mut RecStream {
    // SAFETY: `xdrs` is a live handle (caller's contract).
    let p = unsafe { (*xdrs).x_private };
    // SAFETY: `x_private` is the RecStream xdrrec_create allocated (caller's contract).
    unsafe { &mut *p.cast::<RecStream>() }
}

/// The direction of a live handle.
///
/// # Safety
/// `xdrs` is a live handle.
#[inline(always)]
unsafe fn op_of(xdrs: *const XDR) -> c_int {
    // SAFETY: caller's contract.
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
        // SAFETY: each is NULL or our fresh malloc block.
        unsafe { mem_free(rstrm.cast()) };
        // SAFETY: as above.
        unsafe { mem_free(buf.cast()) };
        return;
    }
    // the output area starts at the first unit-aligned address of the buffer
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
    // SAFETY: `rstrm` is our fresh, suitably aligned malloc block for one RecStream.
    unsafe { rstrm.write(state) };
    // SAFETY: the C contract of xdrrec_create: `xdrs` points to a handle to fill in.
    let x = unsafe { &mut *xdrs };
    x.x_ops = &XDRREC_OPS;
    x.x_private = rstrm.cast();
}

unsafe extern "C" fn xdrrec_getlong(xdrs: *mut XDR, lp: *mut c_long) -> bool_t {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let Some(v) = unsafe { rs(xdrs) }.get_unit() else { return FALSE };
    // SAFETY: the stream contract: `lp` points to a long.
    unsafe { *lp = v as c_long };
    TRUE
}

unsafe extern "C" fn xdrrec_putlong(xdrs: *mut XDR, lp: *const c_long) -> bool_t {
    // SAFETY: the stream contract: `lp` points to a long.
    let v = unsafe { *lp } as i32;
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    unsafe { rs(xdrs) }.put_unit(v)
}

unsafe extern "C" fn xdrrec_getbytes(xdrs: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let r = unsafe { rs(xdrs) };
    // SAFETY: the stream contract: `addr` points to `len` writable bytes (the caller's, not the stream's buffer).
    unsafe { r.getbytes(addr.cast(), len) }
}

unsafe extern "C" fn xdrrec_putbytes(xdrs: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let r = unsafe { rs(xdrs) };
    // SAFETY: the stream contract: `addr` points to `len` readable bytes (the caller's, not the stream's buffer).
    unsafe { r.putbytes(addr.cast(), len) }
}

unsafe extern "C" fn xdrrec_getpos(xdrs: *const XDR) -> u_int {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let op = unsafe { op_of(xdrs) };
    // SAFETY: as above.
    unsafe { rs(xdrs) }.getpos(op)
}

unsafe extern "C" fn xdrrec_setpos(xdrs: *mut XDR, pos: u_int) -> bool_t {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let op = unsafe { op_of(xdrs) };
    // SAFETY: as above.
    unsafe { rs(xdrs) }.setpos(op, pos)
}

unsafe extern "C" fn xdrrec_inline(xdrs: *mut XDR, len: u_int) -> *mut i32 {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let op = unsafe { op_of(xdrs) };
    // SAFETY: as above.
    unsafe { rs(xdrs) }.inline(op, len)
}

unsafe extern "C" fn xdrrec_destroy(xdrs: *mut XDR) {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let r = unsafe { rs(xdrs) };
    let (buf, state) = (r.the_buffer, core::ptr::from_mut(r));
    // SAFETY: our malloc buffer; the stream is dead after destroy.
    unsafe { mem_free(buf.cast()) };
    // SAFETY: our malloc'ed state (RecStream has no destructor to run).
    unsafe { mem_free(state.cast()) };
}

unsafe extern "C" fn xdrrec_getint32(xdrs: *mut XDR, ip: *mut i32) -> bool_t {
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
    let Some(v) = unsafe { rs(xdrs) }.get_unit() else { return FALSE };
    // SAFETY: the stream contract: `ip` points to an int32.
    unsafe { *ip = v };
    TRUE
}

unsafe extern "C" fn xdrrec_putint32(xdrs: *mut XDR, ip: *const i32) -> bool_t {
    // SAFETY: the stream contract: `ip` points to an int32.
    let v = unsafe { *ip };
    // SAFETY: an operation of XDRREC_OPS: `xdrs` is a record stream.
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

/// Skip the rest of the current record and make the next one current.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_skiprecord(xdrs: *mut XDR) -> bool_t {
    // SAFETY: the C contract: `xdrs` is a record stream.
    unsafe { rs(xdrs) }.skiprecord()
}

/// TRUE when there is no more input (the rest of the current record is skipped to find out).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_eof(xdrs: *mut XDR) -> bool_t {
    // SAFETY: the C contract: `xdrs` is a record stream.
    unsafe { rs(xdrs) }.eof()
}

/// Mark the end of the record being written; send it now when `sendnow` (or when it already spilled).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_endofrecord(xdrs: *mut XDR, sendnow: bool_t) -> bool_t {
    // SAFETY: the C contract: `xdrs` is a record stream.
    unsafe { rs(xdrs) }.endofrecord(sendnow)
}
