use crate::types::*;
use core::ffi::{c_int, c_void};
use rusty_libc_core::errno;

const HBH: usize = 2;
const IP6OPT_PAD1: u8 = 0;
const IP6OPT_PADN: u8 = 1;
const IPV6_RTHDR_TYPE_0: c_int = 0;

#[inline]
fn a8(x: socklen_t) -> bool {
    x.is_multiple_of(8)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_init(extbuf: *mut c_void, extlen: socklen_t) -> c_int {
    if !extbuf.is_null() {
        if extlen == 0 || !a8(extlen) || extlen > 256 * 8 {
            return -1;
        }
        unsafe { *(extbuf as *mut u8).add(1) = (extlen / 8 - 1) as u8 };
    }
    HBH as c_int
}

unsafe fn add_padding(extbuf: *mut u8, offset: usize, npad: usize) {
    unsafe {
        if npad == 1 {
            *extbuf.add(offset) = IP6OPT_PAD1;
        } else if npad > 0 {
            *extbuf.add(offset) = IP6OPT_PADN;
            *extbuf.add(offset + 1) = (npad - 2) as u8;
            core::ptr::write_bytes(extbuf.add(offset + 2), 0, npad - 2);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_append(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, ty: u8, len: socklen_t, align: u8, databufp: *mut *mut c_void) -> c_int {
    if (offset as usize) < HBH || offset < 0 {
        return -1;
    }
    if ty == IP6OPT_PAD1 || ty == IP6OPT_PADN || len > 255 {
        return -1;
    }
    if align == 0 || align > 8 || (align & (align - 1)) != 0 || align as u32 > len {
        return -1;
    }
    let data_offset = offset as usize + HBH;
    let npad = (align as usize - data_offset % align as usize) & (align as usize - 1);
    let mut offset = offset as usize;
    if !extbuf.is_null() {
        if data_offset + npad + len as usize > extlen as usize {
            return -1;
        }
        let b = extbuf as *mut u8;
        unsafe {
            add_padding(b, offset, npad);
            offset += npad;
            *b.add(offset) = ty;
            *b.add(offset + 1) = len as u8;
            *databufp = b.add(offset + HBH) as *mut c_void;
        }
    } else {
        offset += npad;
    }
    (offset + HBH + len as usize) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_finish(extbuf: *mut c_void, extlen: socklen_t, offset: c_int) -> c_int {
    if (offset as usize) < HBH || offset < 0 {
        return -1;
    }
    let npad = (8 - (offset as usize & 7)) & 7;
    if !extbuf.is_null() {
        if offset as usize + npad > extlen as usize {
            return -1;
        }
        unsafe { add_padding(extbuf as *mut u8, offset as usize, npad) };
    }
    (offset as usize + npad) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_set_val(databuf: *mut c_void, offset: c_int, val: *mut c_void, vallen: socklen_t) -> c_int {
    unsafe { core::ptr::copy_nonoverlapping(val as *const u8, (databuf as *mut u8).offset(offset as isize), vallen as usize) };
    offset + vallen as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_next(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, typep: *mut u8, lenp: *mut socklen_t, databufp: *mut *mut c_void) -> c_int {
    let mut offset = offset as i64;
    if offset == 0 {
        offset = HBH as i64;
    } else if offset < HBH as i64 {
        return -1;
    }
    let b = extbuf as *mut u8;
    while offset < extlen as i64 {
        unsafe {
            let ty = *b.offset(offset as isize);
            if ty == IP6OPT_PAD1 {
                offset += 1;
            } else if ty == IP6OPT_PADN {
                offset += HBH as i64 + *b.offset(offset as isize + 1) as i64;
            } else {
                let l = *b.offset(offset as isize + 1);
                let start = offset;
                offset += HBH as i64 + l as i64;
                if offset > extlen as i64 {
                    return -1;
                }
                *typep = ty;
                *lenp = l as socklen_t;
                *databufp = b.offset(start as isize + HBH as isize) as *mut c_void;
                return offset as c_int;
            }
        }
    }
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_find(extbuf: *mut c_void, extlen: socklen_t, offset: c_int, ty: u8, lenp: *mut socklen_t, databufp: *mut *mut c_void) -> c_int {
    let mut offset = offset as i64;
    if offset == 0 {
        offset = HBH as i64;
    } else if offset < HBH as i64 {
        return -1;
    }
    let b = extbuf as *mut u8;
    while offset < extlen as i64 {
        unsafe {
            let t = *b.offset(offset as isize);
            if t == IP6OPT_PAD1 {
                offset += 1;
                if ty == IP6OPT_PAD1 {
                    *lenp = 0;
                    *databufp = b.offset(offset as isize) as *mut c_void;
                    return offset as c_int;
                }
            } else if t != ty {
                offset += HBH as i64 + *b.offset(offset as isize + 1) as i64;
            } else {
                let l = *b.offset(offset as isize + 1);
                let start = offset;
                offset += HBH as i64 + l as i64;
                if offset > extlen as i64 {
                    return -1;
                }
                *lenp = l as socklen_t;
                *databufp = b.offset(start as isize + HBH as isize) as *mut c_void;
                return offset as c_int;
            }
        }
    }
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_get_val(databuf: *mut c_void, offset: c_int, val: *mut c_void, vallen: socklen_t) -> c_int {
    unsafe { core::ptr::copy_nonoverlapping((databuf as *const u8).offset(offset as isize), val as *mut u8, vallen as usize) };
    offset + vallen as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn inet6_rth_space(ty: c_int, segments: c_int) -> socklen_t {
    if ty == IPV6_RTHDR_TYPE_0 && (0..=127).contains(&segments) { (8 + segments * 16) as socklen_t } else { 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_init(bp: *mut c_void, bp_len: socklen_t, ty: c_int, segments: c_int) -> *mut c_void {
    if ty == IPV6_RTHDR_TYPE_0 && (0..=127).contains(&segments) {
        let len = 8 + segments as usize * 16;
        if len > bp_len as usize {
            return core::ptr::null_mut();
        }
        unsafe {
            core::ptr::write_bytes(bp as *mut u8, 0, len);
            *(bp as *mut u8).add(1) = (segments as usize * 16 / 8) as u8;
            *(bp as *mut u8).add(2) = IPV6_RTHDR_TYPE_0 as u8;
        }
        return bp;
    }
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_add(bp: *mut c_void, addr: *const in6_addr) -> c_int {
    unsafe {
        let b = bp as *mut u8;
        if *b.add(2) as c_int != IPV6_RTHDR_TYPE_0 {
            return -1;
        }
        let len = *b.add(1) as i32;
        let segleft = *b.add(3);
        if len * 8 / 16 - (segleft as i32) < 1 {
            return -1;
        }
        core::ptr::copy_nonoverlapping(addr as *const u8, b.add(8 + segleft as usize * 16), 16);
        *b.add(3) = segleft + 1;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_reverse(in_: *const c_void, out: *mut c_void) -> c_int {
    unsafe {
        let i = in_ as *const u8;
        let o = out as *mut u8;
        if *i.add(2) as c_int != IPV6_RTHDR_TYPE_0 {
            return -1;
        }
        core::ptr::copy(i, o, 8);
        let total = (*i.add(1) as usize) * 8 / 16;
        for k in 0..total / 2 {
            let mut tmp = [0u8; 16];
            core::ptr::copy_nonoverlapping(i.add(8 + k * 16), tmp.as_mut_ptr(), 16);
            core::ptr::copy(i.add(8 + (total - 1 - k) * 16), o.add(8 + k * 16), 16);
            core::ptr::copy_nonoverlapping(tmp.as_ptr(), o.add(8 + (total - 1 - k) * 16), 16);
        }
        if !total.is_multiple_of(2) && !core::ptr::eq(in_, out as *const c_void) {
            core::ptr::copy_nonoverlapping(i.add(8 + (total / 2) * 16), o.add(8 + (total / 2) * 16), 16);
        }
        *o.add(3) = total as u8;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_segments(bp: *const c_void) -> c_int {
    unsafe {
        let b = bp as *const u8;
        if *b.add(2) as c_int == IPV6_RTHDR_TYPE_0 { (*b.add(1) as c_int) * 8 / 16 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_getaddr(bp: *const c_void, index: c_int) -> *mut in6_addr {
    unsafe {
        let b = bp as *mut u8;
        if *b.add(2) as c_int == IPV6_RTHDR_TYPE_0 && index < (*b.add(1) as c_int) * 8 / 16 {
            return b.offset(8 + index as isize * 16) as *mut in6_addr;
        }
        core::ptr::null_mut()
    }
}

static LAST_PORT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport(fd: c_int, sin: *mut sockaddr_in) -> c_int {
    use core::sync::atomic::Ordering;
    const START: u32 = 600;
    const END: u32 = 1023;
    let mut local = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: 0 }, sin_zero: [0; 8] };
    let sin = if sin.is_null() { &mut local as *mut sockaddr_in } else { sin };
    let fam = unsafe { (*sin).sin_family } as c_int;
    if fam != AF_INET && fam != AF_INET6 && fam != AF_UNSPEC {
        errno::set(EPFNOSUPPORT);
        return -1;
    }
    let len: socklen_t = if fam == AF_INET6 { 28 } else { 16 };
    unsafe { (*sin).sin_family = if fam == AF_UNSPEC { AF_INET as u16 } else { fam as u16 } };
    let mut p = LAST_PORT.load(Ordering::Relaxed);
    if !(START..=END).contains(&p) {
        let mut b = [0u8; 2];
        unsafe { rusty_libc_core::syscall::syscall3(318, b.as_mut_ptr() as usize, 2, 0) };
        p = START + (u16::from_ne_bytes(b) as u32) % (END - START + 1);
    }
    let mut tries = 0;
    loop {
        unsafe { (*sin).sin_port = (p as u16).to_be() };
        if unsafe { crate::sock::bind(fd, sin as *const sockaddr, len) } == 0 {
            LAST_PORT.store(p + 1, Ordering::Relaxed);
            return 0;
        }
        let e = errno::get();
        if e != EADDRINUSE {
            return -1;
        }
        p = if p >= END { START } else { p + 1 };
        tries += 1;
        if tries > (END - START + 1) {
            errno::set(EADDRINUSE);
            return -1;
        }
    }
}

const EPFNOSUPPORT: i32 = 96;
