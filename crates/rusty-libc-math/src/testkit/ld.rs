//! long double (x87) support for the test kit: calling C functions that take and return
//! `long double` (arguments in memory on the stack, result in st(0)) through inline assembly,
//! random 80-bit inputs, and an MPFR oracle for 64-bit-mantissa arguments and results.
use super::mpfr::{Arg, Func, Mpfr, lookup};
use super::ulp::{Overflow, ulp_error_f80};
use core::arch::asm;

/// A `long double` as it lies in memory (16 bytes, 10 used).
pub type Ld = [u8; 16];

pub fn ld(mant: u64, se: u16) -> Ld {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&mant.to_le_bytes());
    b[8..10].copy_from_slice(&se.to_le_bytes());
    b
}
pub fn mant(x: &Ld) -> u64 {
    u64::from_le_bytes(x[..8].try_into().unwrap())
}
pub fn se(x: &Ld) -> u16 {
    u16::from_le_bytes([x[8], x[9]])
}
pub fn b10(x: &Ld) -> [u8; 10] {
    x[..10].try_into().unwrap()
}
pub fn from_f64(x: f64) -> Ld {
    let mut o = [0u8; 16];
    unsafe { asm!("fld qword ptr [{x}]", "fstp tbyte ptr [{o}]", x = in(reg) &x, o = in(reg) o.as_mut_ptr(), options(nostack)) };
    o
}
/// x87 addition (current rounding mode).
pub fn add(a: &Ld, b: &Ld) -> Ld {
    let mut o = [0u8; 16];
    unsafe {
        asm!("fld tbyte ptr [{a}]", "fld tbyte ptr [{b}]", "faddp st(1), st", "fstp tbyte ptr [{o}]",
            a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), o = in(reg) o.as_mut_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
    }
    o
}
/// Round to binary64 (nearest).
pub fn to_f64(x: &Ld) -> f64 {
    let mut o = 0f64;
    unsafe { asm!("fld tbyte ptr [{x}]", "fstp qword ptr [{o}]", x = in(reg) x.as_ptr(), o = in(reg) &mut o, options(nostack)) };
    o
}
pub fn is_nan(x: &Ld) -> bool {
    se(x) & 0x7fff == 0x7fff && mant(x) << 1 != 0
}
pub fn is_inf(x: &Ld) -> bool {
    se(x) & 0x7fff == 0x7fff && mant(x) << 1 == 0
}
/// Same value for the comparison of two results: NaNs equal when both are NaN with the same sign
/// and quiet bit (payload ignored unless `strict`), everything else bit for bit (10 bytes).
pub fn same(a: &Ld, b: &Ld, strict: bool) -> bool {
    if is_nan(a) && is_nan(b) {
        return if strict { b10(a) == b10(b) } else { se(a) == se(b) && mant(a) >> 62 == mant(b) >> 62 };
    }
    b10(a) == b10(b)
}
/// Monotonic integer of a finite or infinite value (neighbours differ by 1, -0 and +0 coincide).
pub fn ordinal(x: &Ld) -> i128 {
    // exponent field * 2^63 + the 63 fraction bits (the integer bit is implied for normals;
    // subnormals have field 0 and a clear integer bit, so the same formula is contiguous)
    let mag = ((se(x) & 0x7fff) as i128) << 63 | (mant(x) & (u64::MAX >> 1)) as i128;
    if se(x) & 0x8000 != 0 { -mag } else { mag }
}
/// Distance in units of the last place between two non-NaN values.
pub fn ulp_diff(a: &Ld, b: &Ld) -> u128 {
    (ordinal(a) - ordinal(b)).unsigned_abs()
}
pub fn show(x: &Ld) -> String {
    format!("{:04x}:{:016x}", se(x), mant(x))
}

/// `long double f(long double)`.
///
/// # Safety
/// `f` must be a function of that C type.
pub unsafe fn call1(f: usize, x: &Ld) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `long double f(long double, long double)`.
///
/// # Safety
/// `f` must be a function of that C type.
pub unsafe fn call2(f: usize, x: &Ld, y: &Ld) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 32",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r15]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(), in("r15") y.as_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `long double f(long double, long double, long double)`.
///
/// # Safety
/// `f` must be a function of that C type.
pub unsafe fn call3(f: usize, x: &Ld, y: &Ld, z: &Ld) -> Ld {
    let mut out = [0u8; 16];
    let args = [*x, *y, *z];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 48",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "movups xmm0, xmmword ptr [r13 + 32]",
            "movups xmmword ptr [rsp + 32], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") args.as_ptr(), in("r14") out.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `long double f(long double, <integer in rdi>)` (ldexpl, scalbnl, pownl, ...).
///
/// # Safety
/// `f` must be a function of that C type.
pub unsafe fn call_ld_int(f: usize, x: &Ld, n: i64) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(), in("rdi") n,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `long double f(long double, T *p)` (frexpl, modfl, lgammal_r): the pointer goes in rdi.
///
/// # Safety
/// `f` must be a function of that C type and `p` valid for it.
pub unsafe fn call_ld_ptr(f: usize, x: &Ld, p: *mut u8) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(), in("rdi") p,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `long double f(long double, long double, int *p)` (remquol).
///
/// # Safety
/// As above.
pub unsafe fn call2_ptr(f: usize, x: &Ld, y: &Ld, p: *mut u8) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 32",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r15]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(), in("r15") y.as_ptr(), in("rdi") p,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `<integer> f(long double)` (lrintl, ilogbl, fpclassifyl, ...): the result as rax.
///
/// # Safety
/// As above.
pub unsafe fn call_ld_to_int(f: usize, x: &Ld) -> i64 {
    let mut r: i64;
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "mov rsp, r12",
            inout("rax") f => r, in("r13") x.as_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}

/// `<integer> f(long double, long double)` (iseqsigl, ...).
///
/// # Safety
/// As above.
pub unsafe fn call2_to_int(f: usize, x: &Ld, y: &Ld) -> i64 {
    let mut r: i64;
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 32",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r15]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "call rax",
            "mov rsp, r12",
            inout("rax") f => r, in("r13") x.as_ptr(), in("r15") y.as_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}

/// `void f(long double, long double *, long double *)` (sincosl).
///
/// # Safety
/// As above.
pub unsafe fn call_sincos(f: usize, x: &Ld) -> (Ld, Ld) {
    #[repr(align(16))]
    struct A16([u8; 16]);
    let (mut sa, mut ca) = (A16([0u8; 16]), A16([0u8; 16]));
    let (s, c) = (&mut sa.0, &mut ca.0);
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("rdi") s.as_mut_ptr(), in("rsi") c.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    (*s, *c)
}

/// `long double _Complex f(long double _Complex)`: the argument is 32 bytes in memory, the result
/// comes back in st(0) (real) and st(1) (imaginary).
///
/// # Safety
/// As above.
pub unsafe fn call_c1(f: usize, re: &Ld, im: &Ld) -> (Ld, Ld) {
    let mut out = [[0u8; 16]; 2];
    let args = [*re, *im];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 32",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "fstp tbyte ptr [r14 + 16]",
            "mov rsp, r12",
            in("rax") f, in("r13") args.as_ptr(), in("r14") out.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    (out[0], out[1])
}

/// `long double f(long double _Complex)` (cabsl, cargl, creall, cimagl).
///
/// # Safety
/// As above.
pub unsafe fn call_c1_real(f: usize, re: &Ld, im: &Ld) -> Ld {
    let mut r = [0u8; 16];
    let args = [*re, *im];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 32",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") args.as_ptr(), in("r14") r.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}

/// `long double _Complex f(long double _Complex, long double _Complex)` (cpowl).
///
/// # Safety
/// As above.
pub unsafe fn call_c2(f: usize, a: [&Ld; 2], b: [&Ld; 2]) -> (Ld, Ld) {
    let mut out = [[0u8; 16]; 2];
    let args = [*a[0], *a[1], *b[0], *b[1]];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 64",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "movups xmm0, xmmword ptr [r13 + 32]",
            "movups xmmword ptr [rsp + 32], xmm0",
            "movups xmm0, xmmword ptr [r13 + 48]",
            "movups xmmword ptr [rsp + 48], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "fstp tbyte ptr [r14 + 16]",
            "mov rsp, r12",
            in("rax") f, in("r13") args.as_ptr(), in("r14") out.as_mut_ptr(),
            out("r12") _,
            clobber_abi("C"),
        );
    }
    (out[0], out[1])
}

/// Random 80-bit values.
pub struct LdGen {
    pub rng: super::inputs::Rng,
}

impl LdGen {
    pub fn new(seed: u64) -> LdGen {
        LdGen { rng: super::inputs::Rng::new(seed) }
    }
    /// A random finite number with binary exponent uniform in `lo..=hi` (as the exponent of the
    /// leading bit), random sign (unless `positive`) and a full random significand.
    pub fn exp_range(&mut self, lo: i32, hi: i32, positive: bool) -> Ld {
        let e = lo as i64 + self.rng.below((hi - lo + 1) as u64) as i64;
        let m = self.rng.next_u64() | (1 << 63);
        let neg = !positive && self.rng.next_u64() & 1 != 0;
        if e < -16382 {
            // subnormal: shift the significand down
            let sh = (-16382 - e) as u32;
            let m = if sh >= 64 { 0 } else { m >> sh };
            return ld(m, if neg { 0x8000 } else { 0 });
        }
        ld(m, ((e + 16383) as u16) | if neg { 0x8000 } else { 0 })
    }
    /// A random number in [a, b) as an extended value (uniform on the real line, 53 random bits
    /// plus 11 more from a second draw so the low bits of the significand are exercised).
    pub fn uniform(&mut self, a: f64, b: f64) -> Ld {
        // x = a + (b - a) * u, computed in extended precision
        let u1 = self.rng.unit();
        let u2 = self.rng.unit();
        let hi = from_f64(a + (b - a) * u1);
        let tiny = from_f64((b - a) * u2 * 2f64.powi(-53));
        add(&hi, &tiny)
    }
    pub fn bits(&mut self) -> Ld {
        let m = self.rng.next_u64();
        let s = self.rng.next_u64() as u16;
        ld(m | (1 << 63), s & 0x7fff | (s & 0x8000))
    }
}

/// MPFR oracle for long double arguments.
pub struct LdOracle {
    func: &'static Func,
    args: [Mpfr; 3],
    out: Mpfr,
}

impl LdOracle {
    pub fn new(name: &str) -> LdOracle {
        let func = lookup(name).unwrap_or_else(|| panic!("no MPFR function {name}"));
        LdOracle { func, args: [Mpfr::new(64), Mpfr::new(64), Mpfr::new(64)], out: Mpfr::new(200) }
    }
    /// The value of the function at the given arguments, 200 bits.
    pub fn eval(&mut self, args: &[&Ld]) -> &Mpfr {
        for (i, a) in args.iter().enumerate() {
            self.args[i].set_f80_bytes(b10(a));
        }
        let v: Vec<Arg> = self.args.iter().take(args.len()).map(Arg::F).collect();
        self.func.eval_into(&mut self.out, &v);
        &self.out
    }
    /// Ulp error of `y` against the function at `args`.
    pub fn ulp(&mut self, args: &[&Ld], y: &Ld) -> f64 {
        let z = self.eval(args);
        ulp_error_f80(b10(y), z, Overflow::Clamp)
    }
    /// With an integer second argument (jn, yn, pown, rootn, compoundn): `n` is an integer.
    pub fn eval_int(&mut self, x: &Ld, n: i64, int_first: bool) -> &Mpfr {
        self.args[0].set_f80_bytes(b10(x));
        let v = if int_first { vec![Arg::I(n), Arg::F(&self.args[0])] } else { vec![Arg::F(&self.args[0]), Arg::I(n)] };
        self.func.eval_into(&mut self.out, &v);
        &self.out
    }
}

/// `long double f(<pointer in rdi>)` (nanl, getpayloadl).
///
/// # Safety
/// As above.
pub unsafe fn call_ptr_to_ld(f: usize, p: *const u8) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r14") out.as_mut_ptr(), in("rdi") p,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `int f(<pointer in rdi>, long double)` (setpayloadl).
///
/// # Safety
/// As above.
pub unsafe fn call_ptr_ld_to_int(f: usize, p: *mut u8, x: &Ld) -> i32 {
    let r: i64;
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "mov rsp, r12",
            inout("rax") f => r, in("r13") x.as_ptr(), in("rdi") p,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r as i32
}

/// `long double f(long double, int, unsigned)` (fromfpl family): the integers go in rdi and rsi.
///
/// # Safety
/// As above.
pub unsafe fn call_fromfp(f: usize, x: &Ld, round: i32, width: u32) -> Ld {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "call rax",
            "fstp tbyte ptr [r14]",
            "mov rsp, r12",
            in("rax") f, in("r13") x.as_ptr(), in("r14") out.as_mut_ptr(), in("rdi") round as i64, in("rsi") width as u64,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    out
}

/// `double f(long double, ...)` with up to three long double arguments (the daddl family): the
/// result comes back in xmm0.
///
/// # Safety
/// As above.
pub unsafe fn call_n_to_f64(f: usize, args: &[Ld]) -> f64 {
    let mut a = [[0u8; 16]; 3];
    a[..args.len()].copy_from_slice(args);
    let r: f64;
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 48",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "movups xmm0, xmmword ptr [r13 + 32]",
            "movups xmmword ptr [rsp + 32], xmm0",
            "call rax",
            "mov rsp, r12",
            in("rax") f, in("r13") a.as_ptr(),
            lateout("xmm0") r,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}

/// As `call_n_to_f64` for a `float` result.
///
/// # Safety
/// As above.
pub unsafe fn call_n_to_f32(f: usize, args: &[Ld]) -> f32 {
    let mut a = [[0u8; 16]; 3];
    a[..args.len()].copy_from_slice(args);
    let r: f32;
    unsafe {
        asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 48",
            "movups xmm0, xmmword ptr [r13]",
            "movups xmmword ptr [rsp], xmm0",
            "movups xmm0, xmmword ptr [r13 + 16]",
            "movups xmmword ptr [rsp + 16], xmm0",
            "movups xmm0, xmmword ptr [r13 + 32]",
            "movups xmmword ptr [rsp + 32], xmm0",
            "call rax",
            "mov rsp, r12",
            in("rax") f, in("r13") a.as_ptr(),
            lateout("xmm0") r,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}
