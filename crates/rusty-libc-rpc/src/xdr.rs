use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

#[inline]
pub unsafe fn x_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    match (*(*x).x_ops).x_getlong {
        Some(f) => f(x, lp),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    match (*(*x).x_ops).x_putlong {
        Some(f) => f(x, lp),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    match (*(*x).x_ops).x_getbytes {
        Some(f) => f(x, addr, len),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    match (*(*x).x_ops).x_putbytes {
        Some(f) => f(x, addr, len),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_getpos(x: *const XDR) -> u_int {
    match (*(*x).x_ops).x_getpostn {
        Some(f) => f(x),
        None => 0,
    }
}

#[inline]
pub unsafe fn x_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    match (*(*x).x_ops).x_setpostn {
        Some(f) => f(x, pos),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    match (*(*x).x_ops).x_inline {
        Some(f) => f(x, len),
        None => core::ptr::null_mut(),
    }
}

#[inline]
pub unsafe fn x_destroy(x: *mut XDR) {
    if let Some(f) = (*(*x).x_ops).x_destroy {
        f(x)
    }
}

#[inline]
pub unsafe fn x_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    match (*(*x).x_ops).x_getint32 {
        Some(f) => f(x, ip),
        None => FALSE,
    }
}

#[inline]
pub unsafe fn x_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    match (*(*x).x_ops).x_putint32 {
        Some(f) => f(x, ip),
        None => FALSE,
    }
}

#[inline]
pub fn rndup(x: u_int) -> u_int {
    (x.wrapping_add(BYTES_PER_XDR_UNIT - 1)) & !(BYTES_PER_XDR_UNIT - 1)
}

#[inline]
pub unsafe fn call_proc(p: xdrproc_t, x: *mut XDR, obj: *mut c_void) -> bool_t {
    match p {
        Some(f) => {
            let g: unsafe extern "C" fn(*mut XDR, *mut c_void, u_int) -> bool_t = core::mem::transmute(f);
            g(x, obj, LASTUNSIGNED)
        }
        None => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn xdr_void() -> bool_t {
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int(xdrs: *mut XDR, ip: *mut c_int) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let l = *ip as c_long;
            x_putlong(xdrs, &l)
        }
        XDR_DECODE => {
            let mut l: c_long = 0;
            if x_getlong(xdrs, &mut l) == 0 {
                return FALSE;
            }
            *ip = l as c_int;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_int(xdrs: *mut XDR, up: *mut u_int) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let l = *up as c_long;
            x_putlong(xdrs, &l)
        }
        XDR_DECODE => {
            let mut l: c_long = 0;
            if x_getlong(xdrs, &mut l) == 0 {
                return FALSE;
            }
            *up = l as u_int;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_long(xdrs: *mut XDR, lp: *mut c_long) -> bool_t {
    let op = (*xdrs).x_op;
    if op == XDR_ENCODE && (*lp as i32) as c_long == *lp {
        return x_putlong(xdrs, lp);
    }
    if op == XDR_DECODE {
        return x_getlong(xdrs, lp);
    }
    if op == XDR_FREE {
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_long(xdrs: *mut XDR, ulp: *mut u_long) -> bool_t {
    match (*xdrs).x_op {
        XDR_DECODE => {
            let mut tmp: c_long = 0;
            if x_getlong(xdrs, &mut tmp) == FALSE {
                return FALSE;
            }
            *ulp = (tmp as u32) as u_long;
            TRUE
        }
        XDR_ENCODE => {
            if (*ulp as u32) as u_long != *ulp {
                return FALSE;
            }
            x_putlong(xdrs, ulp as *const c_long)
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_hyper(xdrs: *mut XDR, llp: *mut quad_t) -> bool_t {
    let op = (*xdrs).x_op;
    if op == XDR_ENCODE {
        let t1 = (*llp >> 32) as c_long;
        let t2 = *llp as c_long;
        return (x_putlong(xdrs, &t1) != 0 && x_putlong(xdrs, &t2) != 0) as bool_t;
    }
    if op == XDR_DECODE {
        let (mut t1, mut t2): (c_long, c_long) = (0, 0);
        if x_getlong(xdrs, &mut t1) == 0 || x_getlong(xdrs, &mut t2) == 0 {
            return FALSE;
        }
        *llp = ((t1 as quad_t) << 32) | (t2 as u32 as quad_t);
        return TRUE;
    }
    if op == XDR_FREE {
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_hyper(xdrs: *mut XDR, ullp: *mut u_quad_t) -> bool_t {
    let op = (*xdrs).x_op;
    if op == XDR_ENCODE {
        let t1 = (*ullp >> 32) as c_long;
        let t2 = *ullp as c_long;
        return (x_putlong(xdrs, &t1) != 0 && x_putlong(xdrs, &t2) != 0) as bool_t;
    }
    if op == XDR_DECODE {
        let (mut t1, mut t2): (c_long, c_long) = (0, 0);
        if x_getlong(xdrs, &mut t1) == 0 || x_getlong(xdrs, &mut t2) == 0 {
            return FALSE;
        }
        *ullp = ((t1 as u_quad_t) << 32) | (t2 as u32 as u_quad_t);
        return TRUE;
    }
    if op == XDR_FREE {
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_longlong_t(xdrs: *mut XDR, llp: *mut quad_t) -> bool_t {
    xdr_hyper(xdrs, llp)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_longlong_t(xdrs: *mut XDR, ullp: *mut u_quad_t) -> bool_t {
    xdr_u_hyper(xdrs, ullp)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_short(xdrs: *mut XDR, sp: *mut core::ffi::c_short) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let l = *sp as c_long;
            x_putlong(xdrs, &l)
        }
        XDR_DECODE => {
            let mut l: c_long = 0;
            if x_getlong(xdrs, &mut l) == 0 {
                return FALSE;
            }
            *sp = l as core::ffi::c_short;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_short(xdrs: *mut XDR, usp: *mut u_short) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let l = *usp as c_long;
            x_putlong(xdrs, &l)
        }
        XDR_DECODE => {
            let mut l: c_long = 0;
            if x_getlong(xdrs, &mut l) == 0 {
                return FALSE;
            }
            *usp = l as u_short;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_char(xdrs: *mut XDR, cp: *mut c_char) -> bool_t {
    let mut i = *cp as c_int;
    if xdr_int(xdrs, &mut i) == 0 {
        return FALSE;
    }
    *cp = i as c_char;
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_char(xdrs: *mut XDR, cp: *mut u_char) -> bool_t {
    let mut u = *cp as u_int;
    if xdr_u_int(xdrs, &mut u) == 0 {
        return FALSE;
    }
    *cp = u as u_char;
    TRUE
}

const XDR_FALSE: c_long = 0;
const XDR_TRUE: c_long = 1;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bool(xdrs: *mut XDR, bp: *mut bool_t) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let lb = if *bp != 0 { XDR_TRUE } else { XDR_FALSE };
            x_putlong(xdrs, &lb)
        }
        XDR_DECODE => {
            let mut lb: c_long = 0;
            if x_getlong(xdrs, &mut lb) == 0 {
                return FALSE;
            }
            *bp = if lb == XDR_FALSE { FALSE } else { TRUE };
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_enum(xdrs: *mut XDR, ep: *mut enum_t) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let l = *ep as c_long;
            x_putlong(xdrs, &l)
        }
        XDR_DECODE => {
            let mut l: c_long = 0;
            if x_getlong(xdrs, &mut l) == 0 {
                return FALSE;
            }
            *ep = l as enum_t;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

static XDR_ZERO: [c_char; 4] = [0; 4];
static CRUD: Racy<[c_char; 4]> = Racy::new([0; 4]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque(xdrs: *mut XDR, cp: caddr_t, cnt: u_int) -> bool_t {
    if cnt == 0 {
        return TRUE;
    }
    let mut rndup = cnt % BYTES_PER_XDR_UNIT;
    if rndup > 0 {
        rndup = BYTES_PER_XDR_UNIT - rndup;
    }
    match (*xdrs).x_op {
        XDR_DECODE => {
            if x_getbytes(xdrs, cp, cnt) == 0 {
                return FALSE;
            }
            if rndup == 0 {
                return TRUE;
            }
            x_getbytes(xdrs, CRUD.get().cast(), rndup)
        }
        XDR_ENCODE => {
            if x_putbytes(xdrs, cp, cnt) == 0 {
                return FALSE;
            }
            if rndup == 0 {
                return TRUE;
            }
            x_putbytes(xdrs, XDR_ZERO.as_ptr(), rndup)
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bytes(xdrs: *mut XDR, cpp: *mut *mut c_char, sizep: *mut u_int, maxsize: u_int) -> bool_t {
    let mut sp = *cpp;
    if xdr_u_int(xdrs, sizep) == 0 {
        return FALSE;
    }
    let nodesize = *sizep;
    if nodesize > maxsize && (*xdrs).x_op != XDR_FREE {
        return FALSE;
    }
    match (*xdrs).x_op {
        XDR_DECODE | XDR_ENCODE => {
            if (*xdrs).x_op == XDR_DECODE {
                if nodesize == 0 {
                    return TRUE;
                }
                if sp.is_null() {
                    sp = mem_alloc(nodesize as usize) as *mut c_char;
                    *cpp = sp;
                }
                if sp.is_null() {
                    oom("xdr_bytes");
                    return FALSE;
                }
            }
            xdr_opaque(xdrs, sp, nodesize)
        }
        XDR_FREE => {
            if !sp.is_null() {
                mem_free(sp.cast());
                *cpp = core::ptr::null_mut();
            }
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netobj(xdrs: *mut XDR, np: *mut netobj) -> bool_t {
    xdr_bytes(xdrs, &mut (*np).n_bytes, &mut (*np).n_len, MAX_NETOBJ_SZ)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_union(xdrs: *mut XDR, dscmp: *mut enum_t, unp: *mut c_char, choices: *const xdr_discrim, dfault: xdrproc_t) -> bool_t {
    if xdr_enum(xdrs, dscmp) == 0 {
        return FALSE;
    }
    let dscm = *dscmp;
    let mut ch = choices;
    while (*ch).proc_.is_some() {
        if (*ch).value == dscm {
            return call_proc((*ch).proc_, xdrs, unp.cast());
        }
        ch = ch.add(1);
    }
    if dfault.is_none() { FALSE } else { call_proc(dfault, xdrs, unp.cast()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_string(xdrs: *mut XDR, cpp: *mut *mut c_char, maxsize: u_int) -> bool_t {
    let mut sp = *cpp;
    let mut size: u_int = 0;
    match (*xdrs).x_op {
        XDR_FREE => {
            if sp.is_null() {
                return TRUE;
            }
            size = strlen(sp) as u_int;
        }
        XDR_ENCODE => {
            if sp.is_null() {
                return FALSE;
            }
            size = strlen(sp) as u_int;
        }
        _ => {}
    }
    if xdr_u_int(xdrs, &mut size) == 0 {
        return FALSE;
    }
    if size > maxsize {
        return FALSE;
    }
    let nodesize = size.wrapping_add(1);
    if nodesize == 0 {
        return FALSE;
    }
    match (*xdrs).x_op {
        XDR_DECODE => {
            if sp.is_null() {
                sp = mem_alloc(nodesize as usize) as *mut c_char;
                *cpp = sp;
            }
            if sp.is_null() {
                oom("xdr_string");
                return FALSE;
            }
            *sp.add(size as usize) = 0;
            xdr_opaque(xdrs, sp, size)
        }
        XDR_ENCODE => xdr_opaque(xdrs, sp, size),
        XDR_FREE => {
            mem_free(sp.cast());
            *cpp = core::ptr::null_mut();
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_wrapstring(xdrs: *mut XDR, cpp: *mut *mut c_char) -> bool_t {
    if xdr_string(xdrs, cpp, LASTUNSIGNED) != 0 { TRUE } else { FALSE }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int64_t(xdrs: *mut XDR, ip: *mut i64) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t1 = (*ip >> 32) as i32;
            let t2 = *ip as i32;
            (x_putint32(xdrs, &t1) != 0 && x_putint32(xdrs, &t2) != 0) as bool_t
        }
        XDR_DECODE => {
            let (mut t1, mut t2) = (0i32, 0i32);
            if x_getint32(xdrs, &mut t1) == 0 || x_getint32(xdrs, &mut t2) == 0 {
                return FALSE;
            }
            *ip = ((t1 as i64) << 32) | (t2 as u32 as i64);
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_quad_t(xdrs: *mut XDR, ip: *mut quad_t) -> bool_t {
    xdr_int64_t(xdrs, ip)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint64_t(xdrs: *mut XDR, uip: *mut u64) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t1 = (*uip >> 32) as u32 as i32;
            let t2 = *uip as u32 as i32;
            (x_putint32(xdrs, &t1) != 0 && x_putint32(xdrs, &t2) != 0) as bool_t
        }
        XDR_DECODE => {
            let (mut t1, mut t2) = (0i32, 0i32);
            if x_getint32(xdrs, &mut t1) == 0 || x_getint32(xdrs, &mut t2) == 0 {
                return FALSE;
            }
            *uip = ((t1 as u32 as u64) << 32) | (t2 as u32 as u64);
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_quad_t(xdrs: *mut XDR, ip: *mut u_quad_t) -> bool_t {
    xdr_uint64_t(xdrs, ip)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int32_t(xdrs: *mut XDR, lp: *mut i32) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => x_putint32(xdrs, lp),
        XDR_DECODE => x_getint32(xdrs, lp),
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint32_t(xdrs: *mut XDR, ulp: *mut u32) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => x_putint32(xdrs, ulp as *const i32),
        XDR_DECODE => x_getint32(xdrs, ulp as *mut i32),
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int16_t(xdrs: *mut XDR, ip: *mut i16) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t = *ip as i32;
            x_putint32(xdrs, &t)
        }
        XDR_DECODE => {
            let mut t = 0i32;
            if x_getint32(xdrs, &mut t) == 0 {
                return FALSE;
            }
            *ip = t as i16;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint16_t(xdrs: *mut XDR, uip: *mut u16) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t = *uip as u32 as i32;
            x_putint32(xdrs, &t)
        }
        XDR_DECODE => {
            let mut t = 0i32;
            if x_getint32(xdrs, &mut t) == 0 {
                return FALSE;
            }
            *uip = t as u16;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_int8_t(xdrs: *mut XDR, ip: *mut i8) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t = *ip as i32;
            x_putint32(xdrs, &t)
        }
        XDR_DECODE => {
            let mut t = 0i32;
            if x_getint32(xdrs, &mut t) == 0 {
                return FALSE;
            }
            *ip = t as i8;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_uint8_t(xdrs: *mut XDR, uip: *mut u8) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let t = *uip as u32 as i32;
            x_putint32(xdrs, &t)
        }
        XDR_DECODE => {
            let mut t = 0i32;
            if x_getint32(xdrs, &mut t) == 0 {
                return FALSE;
            }
            *uip = t as u8;
            TRUE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_float(xdrs: *mut XDR, fp: *mut f32) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let tmp = (*fp).to_bits() as i32 as c_long;
            x_putlong(xdrs, &tmp)
        }
        XDR_DECODE => {
            let mut tmp: c_long = 0;
            if x_getlong(xdrs, &mut tmp) != 0 {
                *fp = f32::from_bits(tmp as i32 as u32);
                return TRUE;
            }
            FALSE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_double(xdrs: *mut XDR, dp: *mut f64) -> bool_t {
    match (*xdrs).x_op {
        XDR_ENCODE => {
            let bits = (*dp).to_bits();
            let tmp0 = (bits >> 32) as u32 as i32 as c_long;
            let tmp1 = bits as u32 as i32 as c_long;
            (x_putlong(xdrs, &tmp0) != 0 && x_putlong(xdrs, &tmp1) != 0) as bool_t
        }
        XDR_DECODE => {
            let (mut tmp0, mut tmp1): (c_long, c_long) = (0, 0);
            if x_getlong(xdrs, &mut tmp1) != 0 && x_getlong(xdrs, &mut tmp0) != 0 {
                let hi = tmp1 as u32 as u64;
                let lo = tmp0 as u32 as u64;
                *dp = f64::from_bits((hi << 32) | lo);
                return TRUE;
            }
            FALSE
        }
        XDR_FREE => TRUE,
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_array(xdrs: *mut XDR, addrp: *mut caddr_t, sizep: *mut u_int, maxsize: u_int, elsize: u_int, elproc: xdrproc_t) -> bool_t {
    let mut target = *addrp;
    if xdr_u_int(xdrs, sizep) == 0 {
        return FALSE;
    }
    let c = *sizep;
    if (c > maxsize || (elsize != 0 && c > u_int::MAX / elsize)) && (*xdrs).x_op != XDR_FREE {
        return FALSE;
    }
    if target.is_null() {
        match (*xdrs).x_op {
            XDR_DECODE => {
                if c == 0 {
                    return TRUE;
                }
                target = calloc(c as usize, elsize as usize) as caddr_t;
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
        stat = call_proc(elproc, xdrs, target.cast());
        target = target.add(elsize as usize);
        i += 1;
    }
    if (*xdrs).x_op == XDR_FREE {
        mem_free((*addrp).cast());
        *addrp = core::ptr::null_mut();
    }
    stat
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_vector(xdrs: *mut XDR, basep: *mut c_char, nelem: u_int, elemsize: u_int, xdr_elem: xdrproc_t) -> bool_t {
    let mut elptr = basep;
    for _ in 0..nelem {
        if call_proc(xdr_elem, xdrs, elptr.cast()) == 0 {
            return FALSE;
        }
        elptr = elptr.add(elemsize as usize);
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_reference(xdrs: *mut XDR, pp: *mut caddr_t, size: u_int, proc_: xdrproc_t) -> bool_t {
    let mut loc = *pp;
    if loc.is_null() {
        match (*xdrs).x_op {
            XDR_FREE => return TRUE,
            XDR_DECODE => {
                loc = calloc(1, size as usize) as caddr_t;
                *pp = loc;
                if loc.is_null() {
                    oom("xdr_reference");
                    return FALSE;
                }
            }
            _ => {}
        }
    }
    let stat = call_proc(proc_, xdrs, loc.cast());
    if (*xdrs).x_op == XDR_FREE {
        mem_free(loc.cast());
        *pp = core::ptr::null_mut();
    }
    stat
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pointer(xdrs: *mut XDR, objpp: *mut *mut c_char, obj_size: u_int, xdr_obj: xdrproc_t) -> bool_t {
    let mut more_data: bool_t = (!(*objpp).is_null()) as bool_t;
    if xdr_bool(xdrs, &mut more_data) == 0 {
        return FALSE;
    }
    if more_data == 0 {
        *objpp = core::ptr::null_mut();
        return TRUE;
    }
    xdr_reference(xdrs, objpp, obj_size, xdr_obj)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_free(proc_: xdrproc_t, objp: *mut c_char) {
    let mut x = XDR::zeroed();
    x.x_op = XDR_FREE;
    if let Some(f) = proc_ {
        f(&mut x, objp.cast());
    }
}

unsafe extern "C" fn xdrmem_destroy(_x: *mut XDR) {}

unsafe extern "C" fn xdrmem_getlong(x: *mut XDR, lp: *mut c_long) -> bool_t {
    if (*x).x_handy < 4 {
        return FALSE;
    }
    (*x).x_handy -= 4;
    let v = core::ptr::read_unaligned((*x).x_private as *const u32);
    *lp = u32::from_be(v) as i32 as c_long;
    (*x).x_private = (*x).x_private.add(4);
    TRUE
}

unsafe extern "C" fn xdrmem_putlong(x: *mut XDR, lp: *const c_long) -> bool_t {
    if (*x).x_handy < 4 {
        return FALSE;
    }
    (*x).x_handy -= 4;
    core::ptr::write_unaligned((*x).x_private as *mut u32, (*lp as u32).to_be());
    (*x).x_private = (*x).x_private.add(4);
    TRUE
}

unsafe extern "C" fn xdrmem_getbytes(x: *mut XDR, addr: caddr_t, len: u_int) -> bool_t {
    if (*x).x_handy < len {
        return FALSE;
    }
    (*x).x_handy -= len;
    core::ptr::copy_nonoverlapping((*x).x_private as *const u8, addr as *mut u8, len as usize);
    (*x).x_private = (*x).x_private.add(len as usize);
    TRUE
}

unsafe extern "C" fn xdrmem_putbytes(x: *mut XDR, addr: *const c_char, len: u_int) -> bool_t {
    if (*x).x_handy < len {
        return FALSE;
    }
    (*x).x_handy -= len;
    core::ptr::copy_nonoverlapping(addr as *const u8, (*x).x_private as *mut u8, len as usize);
    (*x).x_private = (*x).x_private.add(len as usize);
    TRUE
}

unsafe extern "C" fn xdrmem_getpos(x: *const XDR) -> u_int {
    ((*x).x_private as usize).wrapping_sub((*x).x_base as usize) as u_int
}

unsafe extern "C" fn xdrmem_setpos(x: *mut XDR, pos: u_int) -> bool_t {
    let newaddr = ((*x).x_base as usize).wrapping_add(pos as usize);
    let lastaddr = ((*x).x_private as usize).wrapping_add((*x).x_handy as usize);
    let handy = lastaddr.wrapping_sub(newaddr);
    if newaddr > lastaddr || newaddr < (*x).x_base as usize || handy != (handy as u_int) as usize {
        return FALSE;
    }
    (*x).x_private = newaddr as caddr_t;
    (*x).x_handy = handy as u_int;
    TRUE
}

unsafe extern "C" fn xdrmem_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    let mut buf: *mut i32 = core::ptr::null_mut();
    if (*x).x_handy >= len {
        (*x).x_handy -= len;
        buf = (*x).x_private as *mut i32;
        (*x).x_private = (*x).x_private.add(len as usize);
    }
    buf
}

unsafe extern "C" fn xdrmem_getint32(x: *mut XDR, ip: *mut i32) -> bool_t {
    if (*x).x_handy < 4 {
        return FALSE;
    }
    (*x).x_handy -= 4;
    *ip = u32::from_be(core::ptr::read_unaligned((*x).x_private as *const u32)) as i32;
    (*x).x_private = (*x).x_private.add(4);
    TRUE
}

unsafe extern "C" fn xdrmem_putint32(x: *mut XDR, ip: *const i32) -> bool_t {
    if (*x).x_handy < 4 {
        return FALSE;
    }
    (*x).x_handy -= 4;
    core::ptr::write_unaligned((*x).x_private as *mut u32, (*ip as u32).to_be());
    (*x).x_private = (*x).x_private.add(4);
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdrmem_create(xdrs: *mut XDR, addr: caddr_t, size: u_int, op: c_int) {
    (*xdrs).x_op = op;
    (*xdrs).x_ops = &XDRMEM_OPS;
    (*xdrs).x_private = addr;
    (*xdrs).x_base = addr;
    (*xdrs).x_handy = size;
}

unsafe extern "C" fn sz_putlong(x: *mut XDR, _lp: *const c_long) -> bool_t {
    (*x).x_handy += BYTES_PER_XDR_UNIT;
    TRUE
}

unsafe extern "C" fn sz_putbytes(x: *mut XDR, _bp: *const c_char, len: u_int) -> bool_t {
    (*x).x_handy = (*x).x_handy.wrapping_add(len);
    TRUE
}

unsafe extern "C" fn sz_getpostn(x: *const XDR) -> u_int {
    (*x).x_handy
}

unsafe extern "C" fn sz_setpostn(_x: *mut XDR, _len: u_int) -> bool_t {
    FALSE
}

unsafe extern "C" fn sz_inline(x: *mut XDR, len: u_int) -> *mut i32 {
    if len == 0 || (*x).x_op != XDR_ENCODE {
        return core::ptr::null_mut();
    }
    if (len as c_long) < (*x).x_base as c_long {
        (*x).x_handy = (*x).x_handy.wrapping_add(len);
        return (*x).x_private as *mut i32;
    }
    mem_free((*x).x_private.cast());
    (*x).x_private = mem_alloc(len as usize) as caddr_t;
    if (*x).x_private.is_null() {
        (*x).x_base = core::ptr::null_mut();
        return core::ptr::null_mut();
    }
    (*x).x_base = len as c_long as caddr_t;
    (*x).x_handy = (*x).x_handy.wrapping_add(len);
    (*x).x_private as *mut i32
}

unsafe extern "C" fn sz_harmless() -> bool_t {
    0
}

unsafe extern "C" fn sz_destroy(x: *mut XDR) {
    (*x).x_handy = 0;
    (*x).x_base = core::ptr::null_mut();
    if !(*x).x_private.is_null() {
        mem_free((*x).x_private.cast());
        (*x).x_private = core::ptr::null_mut();
    }
}

unsafe extern "C" fn sz_putint32(x: *mut XDR, _ip: *const i32) -> bool_t {
    (*x).x_handy += BYTES_PER_XDR_UNIT;
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_sizeof(func: xdrproc_t, data: *mut c_void) -> c_ulong {
    let ops = xdr_ops {
        x_putlong: Some(sz_putlong),
        x_putbytes: Some(sz_putbytes),
        x_inline: Some(sz_inline),
        x_getpostn: Some(sz_getpostn),
        x_setpostn: Some(sz_setpostn),
        x_destroy: Some(sz_destroy),
        x_putint32: Some(sz_putint32),
        x_getlong: Some(core::mem::transmute::<unsafe extern "C" fn() -> bool_t, unsafe extern "C" fn(*mut XDR, *mut c_long) -> bool_t>(sz_harmless)),
        x_getbytes: Some(core::mem::transmute::<unsafe extern "C" fn() -> bool_t, unsafe extern "C" fn(*mut XDR, caddr_t, u_int) -> bool_t>(sz_harmless)),
        x_getint32: Some(core::mem::transmute::<unsafe extern "C" fn() -> bool_t, unsafe extern "C" fn(*mut XDR, *mut i32) -> bool_t>(sz_harmless)),
    };
    let mut x = XDR::zeroed();
    x.x_op = XDR_ENCODE;
    x.x_ops = &ops;
    x.x_handy = 0;
    x.x_private = core::ptr::null_mut();
    x.x_base = core::ptr::null_mut();
    let stat = match func {
        Some(f) => f(&mut x, data),
        None => FALSE,
    };
    mem_free(x.x_private.cast());
    if stat == TRUE { x.x_handy as c_ulong } else { 0 }
}
