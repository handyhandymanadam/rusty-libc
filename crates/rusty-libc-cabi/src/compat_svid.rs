#![allow(missing_docs, clippy::missing_safety_doc)]
use core::cmp::Ordering;
use core::ffi::c_int;
use rusty_libc_core::errno;

unsafe extern "C" {
    fn dlvsym(handle: *mut core::ffi::c_void, name: *const core::ffi::c_char, version: *const core::ffi::c_char) -> *mut core::ffi::c_void;
    static mut __rl_cd__LIB_VERSION_2_2_5: c_int;
}
static mut LV_PTR: *const c_int = core::ptr::null();

const EDOM: c_int = 33;
const ERANGE: c_int = 34;
const FE_INVALID: c_int = 1;
const FE_DIVBYZERO: c_int = 4;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ty {
    D,
    F,
    L,
    Q,
}

pub struct Desc {
    pub stem: &'static str,
    pub ty: Ty,
    pub finite: bool,
    pub shape: u8,
    pub modern_raw: bool,
}

pub struct Raw {
    pub name: &'static str,
    pub ty: Ty,
    pub errno: u8,
    pub nan: u8,
}

#[derive(Clone, Copy)]
pub struct Val {
    pub b: [u8; 16],
    pub ty: Ty,
}

impl Val {
    unsafe fn load(p: *const u8, ty: Ty) -> Val {
        let mut b = [0u8; 16];
        let n = match ty {
            Ty::F => 4,
            Ty::D => 8,
            Ty::L => 10,
            Ty::Q => 16,
        };
        unsafe { core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), n) };
        Val { b, ty }
    }
    unsafe fn store(&self, p: *mut u8) {
        unsafe { core::ptr::copy_nonoverlapping(self.b.as_ptr(), p, 16) };
    }
    fn bits(&self) -> u128 {
        u128::from_le_bytes(self.b)
    }
    fn parts(&self) -> (bool, u32, u128) {
        let v = self.bits();
        match self.ty {
            Ty::F => (v >> 31 & 1 != 0, (v >> 23 & 0xff) as u32, v & 0x7f_ffff),
            Ty::D => (v >> 63 & 1 != 0, (v >> 52 & 0x7ff) as u32, v & ((1 << 52) - 1)),
            Ty::L => (v >> 79 & 1 != 0, (v >> 64 & 0x7fff) as u32, v & ((1u128 << 64) - 1)),
            Ty::Q => (v >> 127 & 1 != 0, (v >> 112 & 0x7fff) as u32, v & ((1u128 << 112) - 1)),
        }
    }
    fn max_exp(&self) -> u32 {
        match self.ty {
            Ty::F => 0xff,
            Ty::D => 0x7ff,
            _ => 0x7fff,
        }
    }
    pub fn neg(&self) -> bool {
        self.parts().0
    }
    pub fn is_nan(&self) -> bool {
        let (_, e, f) = self.parts();
        e == self.max_exp() && if self.ty == Ty::L { f & !(1u128 << 63) != 0 } else { f != 0 }
    }
    pub fn is_inf(&self) -> bool {
        let (_, e, f) = self.parts();
        e == self.max_exp() && if self.ty == Ty::L { f & !(1u128 << 63) == 0 } else { f == 0 }
    }
    pub fn is_finite(&self) -> bool {
        self.parts().1 != self.max_exp()
    }
    pub fn is_zero(&self) -> bool {
        let (_, e, f) = self.parts();
        if self.ty == Ty::L { f == 0 } else { e == 0 && f == 0 }
    }
    fn mant_exp(&self) -> (u128, i32) {
        let (_, e, f) = self.parts();
        match self.ty {
            Ty::F => if e == 0 { (f, -149) } else { (f | 1 << 23, e as i32 - 150) },
            Ty::D => if e == 0 { (f, -1074) } else { (f | 1 << 52, e as i32 - 1075) },
            Ty::L => (f, (if e == 0 { 1 } else { e as i32 }) - 16383 - 63),
            Ty::Q => if e == 0 { (f, -16494) } else { (f | 1 << 112, e as i32 - 16383 - 112) },
        }
    }
    fn cmp_abs_int(&self, k: u64) -> Ordering {
        let (m, e2) = self.mant_exp();
        if m == 0 {
            return 0u64.cmp(&k);
        }
        let k = k as u128;
        if e2 >= 0 {
            let bits = 128 - m.leading_zeros() as i32 + e2;
            if bits > 128 {
                return Ordering::Greater;
            }
            (m << e2).cmp(&k)
        } else if -e2 >= 128 {
            Ordering::Less.then(Ordering::Less)
        } else {
            m.cmp(&(k << (-e2)))
        }
    }
    fn half_is_integer(&self) -> bool {
        let (m, e2) = self.mant_exp();
        e2 - 1 >= 0 || m == 0 || m.trailing_zeros() as i32 >= 1 - e2
    }
    fn is_integer(&self) -> bool {
        let (m, e2) = self.mant_exp();
        e2 >= 0 || m == 0 || m.trailing_zeros() as i32 >= -e2
    }
    pub fn f64(&self) -> f64 {
        match self.ty {
            Ty::F => f32::from_bits(self.bits() as u32) as f64,
            Ty::D => f64::from_bits(self.bits() as u64),
            Ty::L => {
                let mut o = 0f64;
                unsafe {
                    core::arch::asm!("fld tbyte ptr [{p}]", "fstp qword ptr [{o}]", p = in(reg) self.b.as_ptr(), o = in(reg) &mut o, options(nostack));
                }
                o
            }
            Ty::Q => {
                let (s, e, f) = self.parts();
                if e == 0x7fff {
                    return if f == 0 { if s { f64::NEG_INFINITY } else { f64::INFINITY } } else { f64::NAN };
                }
                let (m, e2) = self.mant_exp();
                let v = (m >> 64) as f64 * 18446744073709551616.0 + (m as u64) as f64;
                let r = v * pow2(e2);
                if s { -r } else { r }
            }
        }
    }
    pub fn from_f64(v: f64, ty: Ty) -> Val {
        let mut b = [0u8; 16];
        match ty {
            Ty::F => b[..4].copy_from_slice(&(v as f32).to_bits().to_le_bytes()),
            Ty::D => b[..8].copy_from_slice(&v.to_bits().to_le_bytes()),
            Ty::L => unsafe {
                core::arch::asm!("fld qword ptr [{i}]", "fstp tbyte ptr [{p}]", i = in(reg) &v, p = in(reg) b.as_mut_ptr(), options(nostack));
            },
            Ty::Q => {
                let bits = v.to_bits();
                let s = (bits >> 63) as u128;
                let r: u128 = if v.is_nan() { (s << 127) | (0x7fff << 112) | (1 << 111) } else if v.is_infinite() { (s << 127) | (0x7fff << 112) } else { s << 127 };
                b.copy_from_slice(&r.to_le_bytes());
            }
        }
        Val { b, ty }
    }
    fn with_sign(mut self, neg: bool) -> Val {
        let bit = match self.ty {
            Ty::F => 31,
            Ty::D => 63,
            Ty::L => 79,
            Ty::Q => 127,
        };
        let mut v = self.bits();
        v = (v & !(1u128 << bit)) | ((neg as u128) << bit);
        self.b = v.to_le_bytes();
        self
    }
}

fn pow2(e: i32) -> f64 {
    let mut r = 1.0f64;
    let mut e = e;
    while e > 1000 {
        r *= f64::from_bits((1023u64 + 1000) << 52);
        e -= 1000;
    }
    while e < -1000 {
        r *= f64::from_bits((1023u64 - 1000) << 52);
        e += 1000;
    }
    r * f64::from_bits(((1023 + e) as u64) << 52)
}

fn lib_version() -> c_int {
    unsafe {
        if LV_PTR.is_null() {
            let p = dlvsym(core::ptr::null_mut(), c"_LIB_VERSION".as_ptr(), c"GLIBC_2.2.5".as_ptr()) as *const c_int;
            LV_PTR = if p.is_null() { &raw const __rl_cd__LIB_VERSION_2_2_5 } else { p };
        }
        core::ptr::read_volatile(LV_PTR)
    }
}

const HUGE: f64 = 3.402_823_466_385_288_6e38;
const HUGE_VAL: f64 = f64::INFINITY;
const NAN_POS: f64 = f64::from_bits(0x7ff8_0000_0000_0000);

fn zero() -> f64 {
    core::hint::black_box(0.0f64)
}

fn zdz() -> f64 {
    let z = zero();
    z / z
}

fn write2(s: &[u8]) {
    unsafe { rusty_libc_core::syscall::syscall3(1, 2, s.as_ptr() as usize, s.len()) };
}

fn kernel_standard(x: f64, _y: f64, typ: i32, y_half_int: bool) -> f64 {
    let lv = lib_version();
    let base = typ % 100;
    let svid = lv == 0;
    let big = if svid { HUGE } else { HUGE_VAL };
    let (mut retval, e_posix, e_other, text): (f64, c_int, c_int, &[u8]) = match base {
        1 => (if svid { HUGE } else { NAN_POS }, EDOM, EDOM, b"acos: DOMAIN error\n"),
        2 => (if svid { HUGE } else { NAN_POS }, EDOM, EDOM, b"asin: DOMAIN error\n"),
        3 => (HUGE, EDOM, EDOM, b"atan2: DOMAIN error\n"),
        4 | 5 | 6 => (big, ERANGE, ERANGE, b""),
        7 | 45 | 47 => (0.0, ERANGE, ERANGE, b""),
        8 => (if svid { -HUGE } else { -HUGE_VAL }, ERANGE, EDOM, b"y0: DOMAIN error\n"),
        10 => (if svid { -HUGE } else { -HUGE_VAL }, ERANGE, EDOM, b"y1: DOMAIN error\n"),
        9 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b"y0: DOMAIN error\n"),
        11 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b"y1: DOMAIN error\n"),
        13 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b"yn: DOMAIN error\n"),
        12 => (if svid { -HUGE } else if x < 0.0 && (x as i32) & 1 != 0 { HUGE_VAL } else { -HUGE_VAL }, ERANGE, EDOM, b"yn: DOMAIN error\n"),
        14 => (big, ERANGE, ERANGE, b""),
        21 => (if x < zero() && !y_half_int { -big } else { big }, ERANGE, ERANGE, b""),
        15 => (big, ERANGE, EDOM, b"lgamma: SING error\n"),
        16 => (if svid { -HUGE } else { -HUGE_VAL }, ERANGE, EDOM, b"log: SING error\n"),
        17 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b"log: DOMAIN error\n"),
        18 => (if svid { -HUGE } else { -HUGE_VAL }, ERANGE, EDOM, b"log10: SING error\n"),
        19 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b"log10: DOMAIN error\n"),
        22 => (if x < zero() && !y_half_int { -0.0 } else { 0.0 }, ERANGE, ERANGE, b""),
        23 => (if svid { 0.0 } else { -HUGE_VAL }, ERANGE, EDOM, b"pow(0,neg): DOMAIN error\n"),
        43 => (if svid { 0.0 } else { HUGE_VAL }, ERANGE, EDOM, b"pow(0,neg): DOMAIN error\n"),
        24 => (if svid { 0.0 } else { zdz() }, EDOM, EDOM, b"neg**non-integral: DOMAIN error\n"),
        25 => (if x > zero() { big } else { -big }, ERANGE, ERANGE, b""),
        26 => (if svid { 0.0 } else { zdz() }, EDOM, EDOM, b"sqrt: DOMAIN error\n"),
        27 => (if svid { x } else { zdz() }, EDOM, EDOM, b"fmod:  DOMAIN error\n"),
        28 => (zdz(), EDOM, EDOM, b"remainder: DOMAIN error\n"),
        29 => (zdz(), EDOM, EDOM, b"acosh: DOMAIN error\n"),
        30 => (zdz(), EDOM, EDOM, b"atanh: DOMAIN error\n"),
        31 => (x / zero(), ERANGE, EDOM, b"atanh: SING error\n"),
        32 => (if x > zero() { HUGE_VAL } else { -HUGE_VAL }, ERANGE, ERANGE, b""),
        33 => (copysign(zero(), x), ERANGE, ERANGE, b""),
        34..=39 => (0.0, ERANGE, ERANGE, b"TLOSS"),
        40 => (copysign(HUGE_VAL, x), ERANGE, ERANGE, b""),
        41 => (NAN_POS, EDOM, EDOM, b"tgamma: SING error\n"),
        44 | 46 => (big, ERANGE, ERANGE, b""),
        48 => (if svid { -HUGE } else { -HUGE_VAL }, ERANGE, EDOM, b""),
        49 => (if svid { -HUGE } else { NAN_POS }, EDOM, EDOM, b""),
        50 => (copysign(HUGE_VAL, x), ERANGE, ERANGE, b"tgamma: SING error\n"),
        _ => (0.0, ERANGE, ERANGE, b""),
    };
    if lv == 2 {
        errno::set(e_posix);
    } else {
        if svid && !text.is_empty() {
            if text == b"TLOSS" {
                let nm: &[u8] = match base {
                    34 => b"j0",
                    35 => b"y0",
                    36 => b"j1",
                    37 => b"y1",
                    38 => b"jn",
                    _ => b"yn",
                };
                write2(nm);
                if (100..200).contains(&typ) {
                    write2(b"f");
                }
                write2(b": TLOSS error\n");
            } else {
                write2(text);
            }
        }
        if base == 41 && svid {
            retval = HUGE_VAL;
        }
        errno::set(e_other);
    }
    retval
}

fn copysign(x: f64, s: f64) -> f64 {
    f64::from_bits((x.to_bits() & !(1 << 63)) | (s.to_bits() & (1 << 63)))
}

include!("compat_svid_raw.rs");

fn raw_rule(stem: &str, ty: Ty) -> Option<&'static Raw> {
    let stem = match stem {
        "lgamma" => "lgamma_r",
        "tgamma" => "gamma_r",
        s => s,
    };
    RAW.iter().find(|r| r.name == stem && r.ty == ty)
}

fn nan_make(neg: bool, ty: Ty) -> Val {
    Val::from_f64(NAN_POS, ty).with_sign(neg)
}

struct Args {
    flags_before: c_int,
    x: Val,
    y: Val,
    n: i32,
    ptr: *mut c_int,
}

fn raw_fix(d: &Desc, a: &Args, z: Val, errno_before: c_int) -> Val {
    let Some(r) = raw_rule(d.stem, d.ty) else { return z };
    let xv = if d.shape == b'I' { &a.y } else { &a.x };
    let keep = match d.stem {
        "y1" | "yn" | "jn" if d.ty != Ty::F => xv.is_finite() && !xv.is_zero() && !xv.neg() && (z.is_inf() || z.is_zero()),
        "lgamma" | "lgamma_r" if d.ty == Ty::D => z.is_inf() && xv.is_finite() && xv.is_integer() && le0(xv),
        "lgamma" | "lgamma_r" if d.ty == Ty::Q => z.is_inf() && xv.is_zero(),
        _ => r.errno == b'k',
    };
    if !keep {
        errno::set(errno_before);
    }
    let mut z = z;
    if d.finite && d.ty == Ty::L {
        match d.stem {
            "log" | "log2" | "log10" if a.x.is_nan() => feraise(FE_INVALID),
            "y0" | "y1" if a.x.is_zero() => {
                restore_flags(a.flags_before);
                if a.x.neg() {
                    feraise(FE_INVALID);
                    z = Val { b: [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff, 0, 0, 0, 0, 0, 0], ty: Ty::L };
                } else {
                    z = Val { b: [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xff, 0, 0, 0, 0, 0, 0], ty: Ty::L };
                }
            }
            "scalb" if a.x.is_nan() && a.y.is_inf() && a.y.neg() => {
                z = Val { b: [0, 0, 0, 0, 0, 0, 0, 0xf8, 0xff, 0x7f, 0, 0, 0, 0, 0, 0], ty: Ty::L };
            }
            _ => {}
        }
    }
    if d.stem == "gamma_r" {
        unsafe {
            match d.ty {
                Ty::D => *a.ptr = 0,
                Ty::F => {}
                _ => {
                    let mut sg = 0;
                    if z.is_finite() && !z.is_zero() && xv.neg() && !xv.is_zero() && xv.is_finite() && !xv.is_integer() {
                        sg = if z.neg() { -1 } else { 1 };
                        z = z.with_sign(false);
                    }
                    *a.ptr = sg;
                }
            }
        }
    }
    if z.is_nan() && r.nan != b'k' {
        let ins_nan = a.x.is_nan() || (d.shape == b'2' && a.y.is_nan()) || (d.shape == b'I' && false);
        if !ins_nan {
            z = z.with_sign(r.nan == b'n');
        }
    }
    z
}

static mut KS_TAKEN: bool = false;

fn ks(d: &Desc, code: i32, x: f64, y: f64, yv: Option<&Val>) -> Val {
    unsafe { KS_TAKEN = true };
    let base = match d.ty {
        Ty::D => 0,
        Ty::F => 100,
        _ => 200,
    };
    let half = yv.map(|v| v.is_finite() && v.half_is_integer()).unwrap_or(true);
    Val::from_f64(kernel_standard(x, y, base + code, half), d.ty)
}

fn x_tloss_k(ty: Ty) -> u64 {
    if ty == Ty::F { 1.414_847_550_405_688e16f64 as f32 as u64 } else { 14148475504056880 }
}

fn gt_abs_int(v: &Val, k: u64) -> bool {
    !v.is_nan() && (v.is_inf() || v.cmp_abs_int(k) == Ordering::Greater)
}

fn lt0(v: &Val) -> bool {
    !v.is_nan() && v.neg() && !v.is_zero()
}
fn le0(v: &Val) -> bool {
    !v.is_nan() && (v.neg() || v.is_zero())
}

fn restore_flags(f: c_int) {
    rusty_libc_math::fenv::feclearexcept(0x3d);
    rusty_libc_math::fenv::feraiseexcept(f);
}

fn feraise(e: c_int) {
    rusty_libc_math::fenv::feraiseexcept(e);
}

fn wrapper(d: &Desc, a: &Args, z: Val) -> Val {
    let lv = lib_version();
    let x = &a.x;
    let y = &a.y;
    let (xd, yd) = (x.f64(), if d.shape == b'2' { y.f64() } else { 0.0 });
    let not_ieee = lv != -1;
    let finite_args = x.is_finite() && (d.shape != b'2' || y.is_finite());
    let tl = x_tloss_k(d.ty);
    let sb = x.neg() as i32;
    match d.stem {
        "acos" | "asin" => {
            if gt_abs_int(x, 1) && not_ieee {
                feraise(FE_INVALID);
                return ks(d, if d.stem == "acos" { 1 } else { 2 }, xd, xd, None);
            }
        }
        "acosh" => {
            if lt1(x) && not_ieee {
                return ks(d, 29, xd, xd, None);
            }
        }
        "atan2" => {
            if x.is_zero() && y.is_zero() && lv == 0 {
                return ks(d, 3, xd, yd, None);
            }
            if z.is_zero() && !x.is_zero() && y.is_finite() {
                errno::set(ERANGE);
            }
        }
        "atanh" => {
            if !x.is_nan() && (x.is_inf() || x.cmp_abs_int(1) != Ordering::Less) && not_ieee {
                let gt = x.is_inf() || x.cmp_abs_int(1) == Ordering::Greater;
                return ks(d, if gt { 30 } else { 31 }, xd, xd, None);
            }
        }
        "cosh" => {
            if !z.is_finite() && x.is_finite() && not_ieee {
                return ks(d, 5, xd, xd, None);
            }
        }
        "sinh" => {
            if !z.is_finite() && x.is_finite() && not_ieee {
                return ks(d, 25, xd, xd, None);
            }
        }
        "exp" | "exp2" | "exp10" => {
            if (!z.is_finite() || z.is_zero()) && x.is_finite() && not_ieee {
                let c = match d.stem {
                    "exp" => 6,
                    "exp2" => 44,
                    _ => 46,
                };
                return ks(d, c + sb, xd, xd, None);
            }
        }
        "fmod" => {
            if (x.is_inf() || y.is_zero()) && not_ieee && !y.is_nan() && !x.is_nan() {
                return ks(d, 27, xd, yd, None);
            }
        }
        "remainder" => {
            if ((y.is_zero() && !x.is_nan()) || (x.is_inf() && !y.is_nan())) && not_ieee {
                return ks(d, 28, xd, yd, None);
            }
        }
        "hypot" => {
            if !z.is_finite() && finite_args && not_ieee {
                return ks(d, 4, xd, yd, None);
            }
        }
        "j0" | "j1" => {
            if gt_abs_int(x, tl) && not_ieee && lv != 2 {
                return ks(d, if d.stem == "j0" { 34 } else { 36 }, xd, xd, None);
            }
        }
        "y0" | "y1" => {
            let (c_neg, c_zero, c_tloss) = if d.stem == "y0" { (9, 8, 35) } else { (11, 10, 37) };
            if (le0(x) || (gt_abs_int(x, tl) && !x.neg())) && not_ieee {
                if lt0(x) {
                    feraise(FE_INVALID);
                    return ks(d, c_neg, xd, xd, None);
                } else if x.is_zero() {
                    feraise(FE_DIVBYZERO);
                    return ks(d, c_zero, xd, xd, None);
                } else if lv != 2 {
                    return ks(d, c_tloss, xd, xd, None);
                }
            }
        }
        "jn" => {
            if gt_abs_int(y, tl) && not_ieee && lv != 2 {
                return ks(d, 38, a.n as f64, y.f64(), None);
            }
        }
        "yn" => {
            let xv = y;
            if (le0(xv) || (gt_abs_int(xv, tl) && !xv.neg())) && not_ieee {
                if lt0(xv) {
                    feraise(FE_INVALID);
                    return ks(d, 13, a.n as f64, xv.f64(), None);
                } else if xv.is_zero() {
                    feraise(FE_DIVBYZERO);
                    return ks(d, 12, a.n as f64, xv.f64(), None);
                } else if lv != 2 {
                    return ks(d, 39, a.n as f64, xv.f64(), None);
                }
            }
        }
        "lgamma" | "lgamma_r" => {
            if !z.is_finite() && x.is_finite() && not_ieee {
                let c = if x.is_integer() && le0(x) { 15 } else { 14 };
                return ks(d, c, xd, xd, None);
            }
        }
        "log" | "log10" | "log2" => {
            if le0(x) && not_ieee {
                let (cz, cn) = match d.stem {
                    "log" => (16, 17),
                    "log10" => (18, 19),
                    _ => (48, 49),
                };
                if x.is_zero() {
                    feraise(FE_DIVBYZERO);
                    return ks(d, cz, xd, xd, None);
                } else {
                    feraise(FE_INVALID);
                    return ks(d, cn, xd, xd, None);
                }
            }
        }
        "sqrt" => {
            if lt0(x) && not_ieee {
                return ks(d, 26, xd, xd, None);
            }
        }
        "pow" => {
            if !z.is_finite() {
                if not_ieee && finite_args {
                    if z.is_nan() {
                        return ks(d, 24, xd, yd, Some(y));
                    } else if x.is_zero() && lt0(y) {
                        if x.neg() && z.neg() {
                            return ks(d, 23, xd, yd, Some(y));
                        } else {
                            return ks(d, 43, xd, yd, Some(y));
                        }
                    } else {
                        return ks(d, 21, xd, yd, Some(y));
                    }
                }
            } else if z.is_zero() && finite_args && !x.is_zero() && not_ieee {
                return ks(d, 22, xd, yd, Some(y));
            }
        }
        "scalb" => {
            if lv == 0 {
                if z.is_inf() {
                    if x.is_finite() {
                        return ks(d, 32, xd, yd, None);
                    } else {
                        errno::set(ERANGE);
                    }
                } else if z.is_zero() && !x.is_zero() {
                    return ks(d, 33, xd, yd, None);
                }
            } else if !z.is_finite() || z.is_zero() {
                if z.is_nan() {
                    if !x.is_nan() && !y.is_nan() {
                        errno::set(EDOM);
                    }
                } else if z.is_inf() {
                    if !x.is_inf() && !y.is_inf() {
                        errno::set(ERANGE);
                    }
                } else if !x.is_zero() && !y.is_inf() {
                    errno::set(ERANGE);
                }
            }
        }
        "tgamma" => {
            if (!z.is_finite() || z.is_zero()) && (x.is_finite() || (x.is_inf() && x.neg())) && not_ieee {
                if x.is_zero() {
                    return ks(d, 50, xd, xd, None);
                } else if x.neg() && (x.is_inf() || x.is_integer()) {
                    return ks(d, 41, xd, xd, None);
                } else if z.is_zero() {
                    errno::set(ERANGE);
                } else {
                    return ks(d, 40, xd, xd, None);
                }
            }
        }
        _ => {}
    }
    z
}

fn lt1(x: &Val) -> bool {
    !x.is_nan() && (x.neg() || x.is_zero() || (x.is_finite() && x.cmp_abs_int(1) == Ordering::Less))
}

include!("compat_svid_gen.rs");

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_sv_pre(frame: *mut u8, _id: u32) {
    unsafe {
        *(frame.add(48) as *mut c_int) = errno::get();
        *(frame.add(52) as *mut c_int) = rusty_libc_math::fenv::fetestexcept(0x3d);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_sv_post(frame: *mut u8, id: u32) {
    unsafe {
        let d = &DESCS[id as usize];
        let ty = d.ty;
        let sz = 16usize;
        let _ = sz;
        let x = Val::load(frame, ty);
        let mut a = Args { flags_before: *(frame.add(52) as *const c_int), x, y: x, n: 0, ptr: core::ptr::null_mut() };
        match d.shape {
            b'2' => a.y = Val::load(frame.add(16), ty),
            b'I' => {
                a.n = *(frame.add(16) as *const i64) as i32;
                a.y = a.x;
            }
            b'R' => a.ptr = *(frame.add(16) as *const *mut c_int),
            _ => {}
        }
        let errno_before = *(frame.add(48) as *const c_int);
        let z = Val::load(frame.add(32), ty);
        let mut z = if d.modern_raw { z } else { raw_fix(d, &a, z, errno_before) };
        if !d.finite {
            let precheck = matches!(d.stem, "acos" | "asin" | "acosh" | "atanh" | "atan2" | "fmod" | "remainder" | "j0" | "j1" | "jn" | "y0" | "y1" | "yn" | "log" | "log10" | "log2" | "sqrt");
            let after = rusty_libc_math::fenv::fetestexcept(0x3d);
            if precheck {
                restore_flags(a.flags_before);
            }
            KS_TAKEN = false;
            z = wrapper(d, &a, z);
            if precheck && !KS_TAKEN {
                restore_flags(after);
            }
        }
        z.store(frame.add(32));
    }
}
