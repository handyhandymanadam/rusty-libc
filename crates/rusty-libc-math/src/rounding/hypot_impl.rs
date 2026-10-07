use super::fp::{ERANGE, Fp, fma_ready, has_fma, set_errno};
use crate::export_alias;

const SCALE: f64 = f64::from_bits(0x1a70_0000_0000_0000);
const LARGE_VAL: f64 = f64::from_bits(0x5fe0_0000_0000_0000);
const TINY_VAL: f64 = f64::from_bits(0x2340_0000_0000_0000);
const EPS: f64 = f64::from_bits(0x3c90_0000_0000_0000);

#[inline]
fn add(a: f64, b: f64) -> f64 {
    Fp::add(a, b)
}
#[inline]
fn sub(a: f64, b: f64) -> f64 {
    Fp::sub(a, b)
}
#[inline]
fn mul(a: f64, b: f64) -> f64 {
    Fp::mul(a, b)
}
#[inline]
fn div(a: f64, b: f64) -> f64 {
    Fp::div(a, b)
}

fn kernel(ax: f64, ay: f64) -> f64 {
    let h = Fp::sqrt(add(mul(ax, ax), mul(ay, ay)));
    let (t1, t2);
    if h <= mul(2.0, ay) {
        let delta = sub(h, ay);
        t1 = mul(ax, sub(mul(2.0, delta), ax));
        t2 = mul(sub(delta, mul(2.0, sub(ax, ay))), delta);
    } else {
        let delta = sub(h, ax);
        t1 = mul(mul(2.0, delta), sub(ax, mul(2.0, ay)));
        t2 = add(mul(sub(mul(4.0, delta), ay), ay), mul(delta, delta));
    }
    sub(h, div(add(t1, t2), mul(2.0, h)))
}

#[inline(always)]
fn max_min(a: f64, b: f64) -> (f64, f64) {
    let (mut hi, mut lo) = (a, a);
    unsafe {
        core::arch::asm!(
            "maxsd {hi}, {b}",
            "minsd {lo}, {b}",
            hi = inout(xmm_reg) hi, lo = inout(xmm_reg) lo, b = in(xmm_reg) b,
            options(nomem, nostack, preserves_flags)
        );
    }
    (hi, lo)
}

const SIGN: u64 = 1 << 63;
const LARGE_BITS: u64 = 0x5fe0_0000_0000_0000;
const TINY_BITS: u64 = 0x2340_0000_0000_0000;

#[inline(always)]
fn select_le(x: f64, y: f64, a: f64, b: f64) -> f64 {
    let r: f64;
    unsafe {
        core::arch::asm!(
            "vcmplesd {m}, {x}, {y}",
            "vblendvpd {r}, {b}, {a}, {m}",
            x = in(xmm_reg) x, y = in(xmm_reg) y, a = in(xmm_reg) a, b = in(xmm_reg) b,
            m = out(xmm_reg) _, r = lateout(xmm_reg) r,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    r
}

#[inline(never)]
fn kernel_plain(ax: f64, ay: f64) -> f64 {
    let h = Fp::sqrt(ax * ax + ay * ay);
    let (t1, t2);
    if h <= 2.0 * ay {
        let delta = h - ay;
        t1 = ax * (2.0 * delta - ax);
        t2 = (delta - 2.0 * (ax - ay)) * delta;
    } else {
        let delta = h - ax;
        t1 = 2.0 * delta * (ax - 2.0 * ay);
        t2 = (4.0 * delta - ay) * ay + delta * delta;
    }
    h - (t1 + t2) / (2.0 * h)
}

#[inline(always)]
fn kernel_fma(ax: f64, ay: f64) -> f64 {
    let h = Fp::sqrt(super::cbrt_impl::fmadd(ax, ax, ay * ay));
    use super::cbrt_impl::fmadd as f;
    let u = ax - ay;
    let da = h - ay;
    let sa = f(ax, f(da, 2.0, -ax), f(u, -2.0, da) * da);
    let db = h - ax;
    let sb = f(db + db, f(ay, -2.0, ax), f(f(db, 4.0, -ay), ay, db * db));
    let t = select_le(h, ay + ay, sa, sb);
    h - t / (h + h)
}

#[inline(never)]
fn kernel_slow(ax: f64, ay: f64) -> f64 {
    if has_fma() { kernel_fma(ax, ay) } else { kernel_plain(ax, ay) }
}

fn handle_errno(r: f64) -> f64 {
    if r.is_inf_() {
        set_errno(ERANGE);
    }
    r
}

#[inline(never)]
fn force_underflow_nonneg(x: f64) {
    if x < f64::MIN_POSITIVE {
        core::hint::black_box(Fp::mul(core::hint::black_box(x), core::hint::black_box(x)));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hypot(x: f64, y: f64) -> f64 {
    let (a, b) = (x.abs_(), y.abs_());
    if a <= LARGE_VAL && b <= LARGE_VAL {
        let (hi, lo) = max_min(a, b);
        if lo >= TINY_VAL && lo > mul(hi, EPS) && fma_ready() {
            return kernel_fma(hi, lo);
        }
    }
    hypot_slow(x, y)
}

#[inline(never)]
fn hypot_slow(x: f64, y: f64) -> f64 {
    if !x.is_finite_() || !y.is_finite_() {
        if (x.is_inf_() || y.is_inf_()) && !x.is_signaling_() && !y.is_signaling_() {
            return f64::INFINITY;
        }
        return add(x, y);
    }
    {
        let (bx, by) = (x.to_bits() & !SIGN, y.to_bits() & !SIGN);
        let (hb, lb) = if bx >= by { (bx, by) } else { (by, bx) };
        if hb <= LARGE_BITS && lb >= TINY_BITS && lb > hb - (54u64 << 52) {
            return kernel_slow(f64::from_bits(hb), f64::from_bits(lb));
        }
    }
    let x = x.abs_();
    let y = y.abs_();
    let ax = if x < y { y } else { x };
    let ay = if x < y { x } else { y };
    if ax > LARGE_VAL {
        if ay <= mul(ax, EPS) {
            return handle_errno(add(ax, ay));
        }
        return handle_errno(div(kernel(mul(ax, SCALE), mul(ay, SCALE)), SCALE));
    }
    if ay < TINY_VAL {
        if ax >= div(ay, EPS) {
            return add(ax, ay);
        }
        let r = mul(kernel(div(ax, SCALE), div(ay, SCALE)), SCALE);
        force_underflow_nonneg(r);
        return r;
    }
    if ay <= mul(ax, EPS) {
        return add(ax, ay);
    }
    kernel(ax, ay)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hypotf(x: f32, y: f32) -> f32 {
    if !x.is_finite_() || !y.is_finite_() {
        if (x.is_inf_() || y.is_inf_()) && !x.is_signaling_() && !y.is_signaling_() {
            return f32::INFINITY;
        }
        return Fp::add(x, y);
    }
    let (dx, dy) = (f64::from(x), f64::from(y));
    let s = Fp::sqrt(add(mul(dx, dx), mul(dy, dy)));
    let r = narrow(s);
    if !r.is_finite_() {
        set_errno(ERANGE);
    }
    r
}

#[inline]
fn narrow(x: f64) -> f32 {
    let r: f32;
    unsafe { core::arch::asm!("cvtsd2ss {0}, {1}", out(xmm_reg) r, in(xmm_reg) x, options(nomem, nostack, preserves_flags)) };
    r
}

export_alias!(fn(x: f64, y: f64) -> f64; hypot => hypotf64, hypotf32x);
export_alias!(fn(x: f32, y: f32) -> f32; hypotf => hypotf32);
