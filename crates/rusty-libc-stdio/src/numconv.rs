use crate::rust_api::{Arg, snprintf};
use core::arch::naked_asm;
use core::ffi::{CStr, c_char, c_int};
use rusty_libc_core::errno;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::floatparse::{self, Bits, Target};
use rusty_libc_core::x87::{self, F80};

trait Real: Copy {
    const NDIGIT_MAX: i32;
    const FCVT_MAXDIG: usize;
    const MIN_10_EXP: i32;
    fn min_10_norm() -> Self;
    fn lit(x: f64) -> Self;
    fn finite(self) -> bool;
    fn negative(self) -> bool;
    fn neg(self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn div(self, o: Self) -> Self;
    fn lt(self, o: Self) -> bool;
    fn ge(self, o: Self) -> bool;
    fn is_zero(self) -> bool;
    fn arg(self) -> Arg<'static>;
}

impl Real for f64 {
    const NDIGIT_MAX: i32 = 17;
    const FCVT_MAXDIG: usize = 308 + 20;
    const MIN_10_EXP: i32 = -307;
    fn min_10_norm() -> f64 {
        1.0e-307
    }
    fn lit(x: f64) -> f64 {
        x
    }
    fn finite(self) -> bool {
        f64::is_finite(self)
    }
    fn negative(self) -> bool {
        self.is_sign_negative()
    }
    fn neg(self) -> f64 {
        -self
    }
    fn mul(self, o: f64) -> f64 {
        self * o
    }
    fn div(self, o: f64) -> f64 {
        self / o
    }
    fn lt(self, o: f64) -> bool {
        self < o
    }
    fn ge(self, o: f64) -> bool {
        self >= o
    }
    fn is_zero(self) -> bool {
        self == 0.0
    }
    fn arg(self) -> Arg<'static> {
        Arg::Double(self)
    }
}

impl Real for F80 {
    const NDIGIT_MAX: i32 = 21;
    const FCVT_MAXDIG: usize = 4932 + 33;
    const MIN_10_EXP: i32 = -4931;
    fn min_10_norm() -> F80 {
        match floatparse::convert(b"1.0e-4931", Target::X87) {
            Some(c) => match c.bits {
                Bits::X87(m, se) => F80::from_bits(m, se),
                _ => F80::ZERO,
            },
            None => F80::ZERO,
        }
    }
    fn lit(x: f64) -> F80 {
        F80::from_f64(x)
    }
    fn finite(self) -> bool {
        F80::is_finite(self)
    }
    fn negative(self) -> bool {
        self.is_sign_negative()
    }
    fn neg(self) -> F80 {
        F80::neg(self)
    }
    fn mul(self, o: F80) -> F80 {
        x87::mul(self, o)
    }
    fn div(self, o: F80) -> F80 {
        x87::div(self, o)
    }
    fn lt(self, o: F80) -> bool {
        x87::lt(self, o)
    }
    fn ge(self, o: F80) -> bool {
        x87::ge(self, o)
    }
    fn is_zero(self) -> bool {
        F80::is_zero(self)
    }
    fn arg(self) -> Arg<'static> {
        Arg::LongDouble(self.0)
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn fcvt_r_impl<T: Real>(mut value: T, mut ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, buf: &mut [u8]) -> c_int {
    let mut left = 0;
    if value.finite() {
        *sign = c_int::from(value.negative());
        if *sign != 0 {
            value = value.neg();
        }
        if ndigit < 0 {
            while ndigit < 0 {
                let new_value = value.mul(T::lit(0.1));
                if new_value.lt(T::lit(1.0)) {
                    ndigit = 0;
                    break;
                }
                value = new_value;
                left += 1;
                ndigit += 1;
            }
        }
    } else {
        *sign = 0;
    }
    let len = buf.len();
    let prec = ndigit.min(T::NDIGIT_MAX);
    let mut tmp = [0u8; 5200];
    let full = snprintf(&mut tmp[..len.min(5200)], c"%.*f", &[Arg::Int(i64::from(prec)), value.arg()]);
    let n = full as isize;
    if n < 0 || n as usize >= len {
        return -1;
    }
    let n = n as usize;
    buf[..n + 1].copy_from_slice(&tmp[..n + 1]);
    let mut i = 0usize;
    while i < n && is_digit(buf[i]) {
        i += 1;
    }
    *decpt = i as c_int;
    if i == 0 {
        return 0;
    }
    if i < n {
        loop {
            i += 1;
            if !(i < n && !is_digit(buf[i])) {
                break;
            }
        }
        if *decpt == 1 && buf[0] == b'0' && !value.is_zero() {
            *decpt -= 1;
            while i < n && buf[i] == b'0' {
                *decpt -= 1;
                i += 1;
            }
        }
        let at = (*decpt).max(0) as usize;
        buf.copy_within(i..n, at);
        buf[n - (i - at)] = 0;
    }
    if left != 0 {
        *decpt += left;
        let lim = len - 1;
        let mut n = n;
        if lim > n {
            let mut l = left;
            while l > 0 && n < lim {
                l -= 1;
                buf[n] = b'0';
                n += 1;
            }
            buf[n] = 0;
        }
    }
    0
}

fn ecvt_r_impl<T: Real>(mut value: T, ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, buf: &mut [u8]) -> c_int {
    let mut exponent = 0;
    if value.finite() && !value.is_zero() {
        let mut d = if value.negative() { value.neg() } else { value };
        let mut f = T::lit(1.0);
        if d.lt(T::min_10_norm()) {
            value = value.div(T::min_10_norm());
            d = if value.negative() { value.neg() } else { value };
            exponent += T::MIN_10_EXP;
        }
        if d.lt(T::lit(1.0)) {
            loop {
                f = f.mul(T::lit(10.0));
                exponent -= 1;
                if !d.mul(f).lt(T::lit(1.0)) {
                    break;
                }
            }
            value = value.mul(f);
        } else if d.ge(T::lit(10.0)) {
            loop {
                f = f.mul(T::lit(10.0));
                exponent += 1;
                if !d.ge(f.mul(T::lit(10.0))) {
                    break;
                }
            }
            value = value.div(f);
        }
    }
    if ndigit <= 0 && !buf.is_empty() {
        buf[0] = 0;
        *decpt = 1;
        *sign = if value.finite() { c_int::from(value.negative()) } else { 0 };
    } else if fcvt_r_impl(value, ndigit.min(T::NDIGIT_MAX) - 1, decpt, sign, buf) != 0 {
        return -1;
    }
    *decpt += exponent;
    0
}

static ECVT_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);
static FCVT_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);
static FCVT_PTR: SyncCell<*mut u8> = SyncCell::new(core::ptr::null_mut());
static QECVT_BUF: SyncCell<[u8; 33]> = SyncCell::new([0; 33]);
static QFCVT_BUF: SyncCell<[u8; 33]> = SyncCell::new([0; 33]);
static QFCVT_PTR: SyncCell<*mut u8> = SyncCell::new(core::ptr::null_mut());

unsafe fn fcvt_static<T: Real, const N: usize>(value: T, ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, small: &SyncCell<[u8; N]>, bufptr: &SyncCell<*mut u8>) -> *mut c_char {
    if unsafe { bufptr.read() }.is_null() {
        if unsafe { small.with_unsync(|b| fcvt_r_impl(value, ndigit, decpt, sign, b)) } != -1 {
            return small.as_ptr().cast();
        }
        let p = crate::file::alloc(T::FCVT_MAXDIG);
        unsafe { bufptr.write(p) };
        if p.is_null() {
            return small.as_ptr().cast();
        }
    }
    let p = unsafe { bufptr.read() };
    let _ = fcvt_r_impl(value, ndigit, decpt, sign, unsafe { core::slice::from_raw_parts_mut(p, T::FCVT_MAXDIG) });
    p.cast()
}

#[inline(always)]
unsafe fn outs<'a>(decpt: *mut c_int, sign: *mut c_int) -> (&'a mut c_int, &'a mut c_int) {
    let d = unsafe { &mut *decpt };
    let s = unsafe { &mut *sign };
    (d, s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char {
    let (d, s) = unsafe { outs(decpt, sign) };
    let _ = unsafe { ECVT_BUF.with_unsync(|b| ecvt_r_impl(value, ndigit, d, s, b)) };
    ECVT_BUF.as_ptr().cast()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char {
    let (d, s) = unsafe { outs(decpt, sign) };
    unsafe { fcvt_static(value, ndigit, d, s, &FCVT_BUF, &FCVT_PTR) }
}

unsafe fn put_text(tmp: &[u8], buf: *mut c_char) -> *mut c_char {
    let n = tmp.iter().position(|&b| b == 0).unwrap_or(tmp.len() - 1);
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf as *mut u8, n + 1) };
    buf
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gcvt(value: f64, ndigit: c_int, buf: *mut c_char) -> *mut c_char {
    let mut tmp = [0u8; 64];
    snprintf(&mut tmp, c"%.*g", &[Arg::Int(i64::from(ndigit.min(f64::NDIGIT_MAX))), Arg::Double(value)]);
    unsafe { put_text(&tmp, buf) }
}

unsafe fn r_buf<'a>(buf: *mut c_char, len: usize) -> Option<&'a mut [u8]> {
    if buf.is_null() {
        errno::set(22);
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize) -> c_int {
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    let (d, s) = unsafe { outs(decpt, sign) };
    ecvt_r_impl(value, ndigit, d, s, b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize) -> c_int {
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    let (d, s) = unsafe { outs(decpt, sign) };
    fcvt_r_impl(value, ndigit, d, s, b)
}

unsafe extern "C" fn qecvt_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, v: *const F80) -> *mut c_char {
    let v = unsafe { *v };
    let (d, s) = unsafe { outs(decpt, sign) };
    let _ = unsafe { QECVT_BUF.with_unsync(|b| ecvt_r_impl(v, ndigit, d, s, b)) };
    QECVT_BUF.as_ptr().cast()
}

unsafe extern "C" fn qfcvt_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, v: *const F80) -> *mut c_char {
    let v = unsafe { *v };
    let (d, s) = unsafe { outs(decpt, sign) };
    unsafe { fcvt_static(v, ndigit, d, s, &QFCVT_BUF, &QFCVT_PTR) }
}

unsafe extern "C" fn qgcvt_inner(ndigit: c_int, buf: *mut c_char, v: *const F80) -> *mut c_char {
    let v = unsafe { *v };
    let mut tmp = [0u8; 96];
    snprintf(&mut tmp, c"%.*Lg", &[Arg::Int(i64::from(ndigit.min(F80::NDIGIT_MAX))), Arg::LongDouble(v.0)]);
    unsafe { put_text(&tmp, buf) }
}

unsafe extern "C" fn qecvt_r_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize, v: *const F80) -> c_int {
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    let v = unsafe { *v };
    let (d, s) = unsafe { outs(decpt, sign) };
    ecvt_r_impl(v, ndigit, d, s, b)
}

unsafe extern "C" fn qfcvt_r_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize, v: *const F80) -> c_int {
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    let v = unsafe { *v };
    let (d, s) = unsafe { outs(decpt, sign) };
    fcvt_r_impl(v, ndigit, d, s, b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qecvt() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym qecvt_inner)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qfcvt() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym qfcvt_inner)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qgcvt() {
    naked_asm!("lea rdx, [rsp + 8]", "jmp {i}", i = sym qgcvt_inner)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qecvt_r() {
    naked_asm!("lea r9, [rsp + 8]", "jmp {i}", i = sym qecvt_r_inner)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qfcvt_r() {
    naked_asm!("lea r9, [rsp + 8]", "jmp {i}", i = sym qfcvt_r_inner)
}

unsafe fn strfrom(dest: *mut c_char, size: usize, format: *const c_char, arg: Arg<'static>, long: bool) -> c_int {
    let f = unsafe { rusty_libc_core::ffi::cstr_bytes(format) };
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(dest as *mut u8, size) };
    strfrom_s(out, f, arg, long)
}

fn strfrom_s(out: &mut [u8], f: &[u8], arg: Arg<'static>, long: bool) -> c_int {
    let at = |i: usize| f.get(i).copied().unwrap_or(0);
    if at(0) != b'%' {
        rusty_libc_core::process::abort();
    }
    let mut i = 1;
    let mut precision: Option<i64> = None;
    if at(i) == b'.' {
        i += 1;
        if at(i).is_ascii_digit() {
            let mut v: i64 = 0;
            while at(i).is_ascii_digit() {
                v = (v * 10 + i64::from(at(i) - b'0')).min(i64::from(i32::MAX));
                i += 1;
            }
            precision = Some(v);
        } else {
            precision = Some(0);
        }
    }
    let spec = at(i);
    if !matches!(spec, b'a' | b'A' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G') {
        rusty_libc_core::process::abort();
    }
    let mut fmt = [0u8; 12];
    let mut k = 0;
    fmt[k] = b'%';
    k += 1;
    if precision.is_some() {
        fmt[k] = b'.';
        fmt[k + 1] = b'*';
        k += 2;
    }
    if long {
        fmt[k] = b'L';
        k += 1;
    }
    fmt[k] = spec;
    k += 1;
    fmt[k] = 0;
    let Ok(cfmt) = CStr::from_bytes_until_nul(&fmt) else { unreachable!() };
    match precision {
        Some(p) => snprintf(out, cfmt, &[Arg::Int(p), arg]),
        None => snprintf(out, cfmt, &[arg]),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfromd(dest: *mut c_char, size: usize, format: *const c_char, fp: f64) -> c_int {
    unsafe { strfrom(dest, size, format, Arg::Double(fp), false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf(dest: *mut c_char, size: usize, format: *const c_char, fp: f32) -> c_int {
    unsafe { strfrom(dest, size, format, Arg::Double(f64::from(fp)), false) }
}

unsafe extern "C" fn strfroml_inner(dest: *mut c_char, size: usize, format: *const c_char, v: *const F80) -> c_int {
    let v = unsafe { *v };
    unsafe { strfrom(dest, size, format, Arg::LongDouble(v.0), true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strfroml() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym strfroml_inner)
}

macro_rules! strfrom_alias {
    ($name:ident, $target:ident, $t:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(dest: *mut c_char, size: usize, format: *const c_char, fp: $t) -> c_int {
            unsafe { $target(dest, size, format, fp) }
        }
    };
}
strfrom_alias!(strfromf32, strfromf, f32);
strfrom_alias!(strfromf64, strfromd, f64);
strfrom_alias!(strfromf32x, strfromd, f64);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strfromf64x() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym strfroml_inner)
}

unsafe extern "C" fn strfromf128_inner(dest: *mut c_char, size: usize, format: *const c_char, v: *const u128) -> c_int {
    let v = unsafe { v.read_unaligned() };
    unsafe { strfrom(dest, size, format, Arg::Quad(v), true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strfromf128() {
    naked_asm!(
        "sub rsp, 24",
        "movups xmmword ptr [rsp], xmm0",
        "mov rcx, rsp",
        "call {i}",
        "add rsp, 24",
        "ret",
        i = sym strfromf128_inner,
    )
}
