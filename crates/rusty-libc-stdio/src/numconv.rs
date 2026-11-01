//! stdlib.h number-to-text functions: ecvt, fcvt, gcvt (and the long double q-forms and `_r`
//! forms) and strfromd, strfromf, strfroml. The old ecvt/fcvt family follows glibc's algorithm
//! step by step, including its floating-point scaling (which can differ in the last digit from an
//! exact conversion), so the same inputs give the same digits.
use crate::rust_api::{Arg, snprintf};
use core::arch::naked_asm;
use core::ffi::{CStr, c_char, c_int};
use rusty_libc_core::errno;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::floatparse::{self, Bits, Target};
use rusty_libc_core::x87::{self, F80};

/// The arithmetic the conversion templates need, for double and for the x87 long double.
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
        // 1.0e-4931L, converted exactly like the compiler does
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

/// glibc's `fcvt_r`: `value` rounded to `ndigit` digits after the point, as a digit string without
/// the point; `decpt` says where the point goes. -1 if the buffer is too small.
fn fcvt_r_impl<T: Real>(mut value: T, mut ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, buf: &mut [u8]) -> c_int {
    let mut left = 0;
    if value.finite() {
        *sign = c_int::from(value.negative());
        if *sign != 0 {
            value = value.neg();
        }
        if ndigit < 0 {
            // rounding to the left of the decimal point
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
    // the same text as the C code produced into `buf` (it checks the length first)
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
        return 0; // Inf or NaN
    }
    if i < n {
        loop {
            i += 1;
            if !(i < n && !is_digit(buf[i])) {
                break;
            }
        }
        if *decpt == 1 && buf[0] == b'0' && !value.is_zero() {
            // no leading zeros: strip them and move the decimal point
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
        // `n` is now the length of what is in the buffer
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

/// glibc's `ecvt_r`: `ndigit` significant digits.
fn ecvt_r_impl<T: Real>(mut value: T, ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, buf: &mut [u8]) -> c_int {
    let mut exponent = 0;
    if value.finite() && !value.is_zero() {
        // slow code that does not need libm
        let mut d = if value.negative() { value.neg() } else { value };
        let mut f = T::lit(1.0);
        // denormals: f would overflow in the loop below
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

// ---- the static-buffer forms ----

// The static result buffers of ecvt, fcvt and the q-forms. POSIX does not make these functions thread-safe: concurrent
// callers share (and race on) the buffers, as with glibc. Each is reached through `with_unsync` for one call.
static ECVT_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);
static FCVT_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);
static FCVT_PTR: SyncCell<*mut u8> = SyncCell::new(core::ptr::null_mut());
static QECVT_BUF: SyncCell<[u8; 33]> = SyncCell::new([0; 33]);
static QFCVT_BUF: SyncCell<[u8; 33]> = SyncCell::new([0; 33]);
static QFCVT_PTR: SyncCell<*mut u8> = SyncCell::new(core::ptr::null_mut());

/// fcvt's heap buffer of `FCVT_MAXDIG` bytes (allocated on first need when the static one is too small), or `small`.
///
/// # Safety
/// No other call uses `small` or `bufptr` meanwhile (the functions' non-thread-safe contract).
unsafe fn fcvt_static<T: Real, const N: usize>(value: T, ndigit: c_int, decpt: &mut c_int, sign: &mut c_int, small: &SyncCell<[u8; N]>, bufptr: &SyncCell<*mut u8>) -> *mut c_char {
    // SAFETY: the caller's promise (this read and the uses of `small` and `bufptr` below).
    if unsafe { bufptr.read() }.is_null() {
        // SAFETY: as above.
        if unsafe { small.with_unsync(|b| fcvt_r_impl(value, ndigit, decpt, sign, b)) } != -1 {
            return small.as_ptr().cast();
        }
        let p = crate::file::alloc(T::FCVT_MAXDIG);
        // SAFETY: as above.
        unsafe { bufptr.write(p) };
        if p.is_null() {
            return small.as_ptr().cast();
        }
    }
    // SAFETY: as above.
    let p = unsafe { bufptr.read() };
    // SAFETY: `p` is our block of `FCVT_MAXDIG` bytes, used by this call only (the caller's promise).
    let _ = fcvt_r_impl(value, ndigit, decpt, sign, unsafe { core::slice::from_raw_parts_mut(p, T::FCVT_MAXDIG) });
    p.cast()
}

/// The two out-parameters of the ecvt family.
///
/// # Safety
/// Both are valid for writing (the functions' contract).
#[inline(always)]
unsafe fn outs<'a>(decpt: *mut c_int, sign: *mut c_int) -> (&'a mut c_int, &'a mut c_int) {
    // SAFETY: the caller's promise.
    let d = unsafe { &mut *decpt };
    // SAFETY: as above.
    let s = unsafe { &mut *sign };
    (d, s)
}

/// # Safety
/// `decpt` and `sign` must be valid; the result is a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char {
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    // SAFETY: the function's non-thread-safe contract: no other call uses the buffer meanwhile.
    let _ = unsafe { ECVT_BUF.with_unsync(|b| ecvt_r_impl(value, ndigit, d, s, b)) };
    ECVT_BUF.as_ptr().cast()
}

/// # Safety
/// As `ecvt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char {
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    // SAFETY: the function's non-thread-safe contract.
    unsafe { fcvt_static(value, ndigit, d, s, &FCVT_BUF, &FCVT_PTR) }
}

/// Copy the NUL-terminated text in `tmp` to the caller's `buf` (gcvt's result).
///
/// # Safety
/// `buf` has room for the text and its NUL.
unsafe fn put_text(tmp: &[u8], buf: *mut c_char) -> *mut c_char {
    let n = tmp.iter().position(|&b| b == 0).unwrap_or(tmp.len() - 1);
    // SAFETY: the caller's promise; `tmp` (ours) is not `buf`.
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf as *mut u8, n + 1) };
    buf
}

/// `%.*g` of `value` into `buf` (at most NDIGIT_MAX digits).
///
/// # Safety
/// `buf` must have room for the result (about ndigit + 8 bytes).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gcvt(value: f64, ndigit: c_int, buf: *mut c_char) -> *mut c_char {
    let mut tmp = [0u8; 64];
    snprintf(&mut tmp, c"%.*g", &[Arg::Int(i64::from(ndigit.min(f64::NDIGIT_MAX))), Arg::Double(value)]);
    // SAFETY: the caller's contract.
    unsafe { put_text(&tmp, buf) }
}

/// The `_r` forms' buffer, or EINVAL for a null one.
///
/// # Safety
/// `buf` is null or valid for `len` bytes.
unsafe fn r_buf<'a>(buf: *mut c_char, len: usize) -> Option<&'a mut [u8]> {
    if buf.is_null() {
        errno::set(22);
        return None;
    }
    // SAFETY: the caller's promise.
    Some(unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) })
}

/// # Safety
/// `buf` must be valid for `len` bytes; the others are valid pointers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    ecvt_r_impl(value, ndigit, d, s, b)
}

/// # Safety
/// As `ecvt_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt_r(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    fcvt_r_impl(value, ndigit, d, s, b)
}

// ---- long double forms: the argument is on the stack, so these start in assembly ----

unsafe extern "C" fn qecvt_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, v: *const F80) -> *mut c_char {
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    // SAFETY: the function's non-thread-safe contract: no other call uses the buffer meanwhile.
    let _ = unsafe { QECVT_BUF.with_unsync(|b| ecvt_r_impl(v, ndigit, d, s, b)) };
    QECVT_BUF.as_ptr().cast()
}

unsafe extern "C" fn qfcvt_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, v: *const F80) -> *mut c_char {
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    // SAFETY: the function's non-thread-safe contract.
    unsafe { fcvt_static(v, ndigit, d, s, &QFCVT_BUF, &QFCVT_PTR) }
}

unsafe extern "C" fn qgcvt_inner(ndigit: c_int, buf: *mut c_char, v: *const F80) -> *mut c_char {
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    let mut tmp = [0u8; 96];
    snprintf(&mut tmp, c"%.*Lg", &[Arg::Int(i64::from(ndigit.min(F80::NDIGIT_MAX))), Arg::LongDouble(v.0)]);
    // SAFETY: the caller's contract.
    unsafe { put_text(&tmp, buf) }
}

unsafe extern "C" fn qecvt_r_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize, v: *const F80) -> c_int {
    // SAFETY: the caller's contract.
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    ecvt_r_impl(v, ndigit, d, s, b)
}

unsafe extern "C" fn qfcvt_r_inner(ndigit: c_int, decpt: *mut c_int, sign: *mut c_int, buf: *mut c_char, len: usize, v: *const F80) -> c_int {
    // SAFETY: the caller's contract.
    let Some(b) = (unsafe { r_buf(buf, len) }) else { return -1 };
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    // SAFETY: the caller's contract.
    let (d, s) = unsafe { outs(decpt, sign) };
    fcvt_r_impl(v, ndigit, d, s, b)
}

/// `char *qecvt(long double value, int ndigit, int *decpt, int *sign)`
///
/// # Safety
/// As `ecvt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qecvt() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym qecvt_inner)
}

/// `char *qfcvt(long double value, int ndigit, int *decpt, int *sign)`
///
/// # Safety
/// As `ecvt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qfcvt() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym qfcvt_inner)
}

/// `char *qgcvt(long double value, int ndigit, char *buf)`
///
/// # Safety
/// As `gcvt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qgcvt() {
    naked_asm!("lea rdx, [rsp + 8]", "jmp {i}", i = sym qgcvt_inner)
}

/// `int qecvt_r(long double value, int ndigit, int *decpt, int *sign, char *buf, size_t len)`
///
/// # Safety
/// As `ecvt_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qecvt_r() {
    naked_asm!("lea r9, [rsp + 8]", "jmp {i}", i = sym qecvt_r_inner)
}

/// `int qfcvt_r(long double value, int ndigit, int *decpt, int *sign, char *buf, size_t len)`
///
/// # Safety
/// As `fcvt_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn qfcvt_r() {
    naked_asm!("lea r9, [rsp + 8]", "jmp {i}", i = sym qfcvt_r_inner)
}

// ---- strfromd, strfromf, strfroml ----

/// The shared body: `format` is "%[.precision]{a,A,e,E,f,F,g,G}"; anything else aborts, like glibc.
///
/// # Safety
/// `dest` is valid for `size` bytes; `format` is NUL-terminated.
unsafe fn strfrom(dest: *mut c_char, size: usize, format: *const c_char, arg: Arg<'static>, long: bool) -> c_int {
    // SAFETY: the caller's contract.
    let f = unsafe { rusty_libc_core::ffi::cstr_bytes(format) };
    // SAFETY: the caller's contract (`size` 0: nothing is written, the pointer may be anything).
    let out = unsafe { rusty_libc_core::ffi::bytes_mut(dest as *mut u8, size) };
    strfrom_s(out, f, arg, long)
}

/// The safe core of `strfrom*`: the format's bytes (without its NUL).
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

/// # Safety
/// `dest` must be valid for `size` bytes; `format` a NUL-terminated "%[.N]{aAeEfFgG}".
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfromd(dest: *mut c_char, size: usize, format: *const c_char, fp: f64) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { strfrom(dest, size, format, Arg::Double(fp), false) }
}

/// # Safety
/// As `strfromd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf(dest: *mut c_char, size: usize, format: *const c_char, fp: f32) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { strfrom(dest, size, format, Arg::Double(f64::from(fp)), false) }
}

unsafe extern "C" fn strfroml_inner(dest: *mut c_char, size: usize, format: *const c_char, v: *const F80) -> c_int {
    // SAFETY: the stub passes the address of the long double argument on the stack.
    let v = unsafe { *v };
    // SAFETY: the caller's contract.
    unsafe { strfrom(dest, size, format, Arg::LongDouble(v.0), true) }
}

/// `int strfroml(char *dest, size_t size, const char *format, long double fp)`
///
/// # Safety
/// As `strfromd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strfroml() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym strfroml_inner)
}

/// The `_FloatN` names of the same functions.
macro_rules! strfrom_alias {
    ($name:ident, $target:ident, $t:ty) => {
        /// # Safety
        /// As the function it forwards to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(dest: *mut c_char, size: usize, format: *const c_char, fp: $t) -> c_int {
            // SAFETY: the same contract.
            unsafe { $target(dest, size, format, fp) }
        }
    };
}
strfrom_alias!(strfromf32, strfromf, f32);
strfrom_alias!(strfromf64, strfromd, f64);
strfrom_alias!(strfromf32x, strfromd, f64);

/// `strfromf64x` is the x87 type on x86-64.
///
/// # Safety
/// As `strfroml`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strfromf64x() {
    naked_asm!("lea rcx, [rsp + 8]", "jmp {i}", i = sym strfroml_inner)
}

unsafe extern "C" fn strfromf128_inner(dest: *mut c_char, size: usize, format: *const c_char, v: *const u128) -> c_int {
    // SAFETY: the stub passes the address where it spilled the argument (16 bytes, not necessarily aligned).
    let v = unsafe { v.read_unaligned() };
    // SAFETY: the caller's contract.
    unsafe { strfrom(dest, size, format, Arg::Quad(v), true) }
}

/// `int strfromf128(char *dest, size_t size, const char *format, _Float128 fp)`: the value arrives in
/// xmm0; the stub spills it to the stack and passes its address.
///
/// # Safety
/// As `strfromd`.
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
