//! Audit of the fast paths of the speed work: a kernel returns `(hi, lo)` with a claimed relative
//! error bound `E`; the audit measures the real relative error of `hi + lo` against a 200-bit
//! MPFR value over random inputs of a domain and reports the largest, as a power of two. A kernel
//! passes when the largest error is at most E/4 (two bits of margin over the sample).
use super::inputs::{Domain, Rng};
use super::mpfr::{Mpfr, Oracle};

pub struct Audit {
    /// log2 of the largest relative error seen (-inf when every result was exact).
    pub max_log2: f64,
    pub worst_x: f64,
    pub n: u64,
    /// Inputs where the kernel declined (returned None).
    pub declined: u64,
}

impl core::fmt::Display for Audit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "max rel err 2^{:.2} at {:e} over {} inputs ({} declined)", self.max_log2, self.worst_x, self.n, self.declined)
    }
}

impl Audit {
    /// Is the largest error at most `bound` / 4?
    pub fn within(&self, bound: f64) -> bool {
        self.max_log2 <= bound.log2() - 2.0
    }
}

/// Audit `f` (a kernel on binary64 returning hi, lo) against MPFR function `name` on `dom`.
pub fn audit(name: &str, dom: Domain, n: u64, seed: u64, f: impl Fn(f64) -> Option<(f64, f64)>) -> Audit {
    let mut o = Oracle::new(name);
    let mut rng = Rng::new(seed);
    let mut xs: Vec<f64> = dom.edges::<f64>();
    for _ in 0..n {
        xs.push(dom.sample::<f64>(&mut rng));
    }
    audit_inputs(&mut o, &xs, f)
}

pub fn audit_inputs(o: &mut Oracle, xs: &[f64], f: impl Fn(f64) -> Option<(f64, f64)>) -> Audit {
    let mut a = Audit { max_log2: f64::NEG_INFINITY, worst_x: 0.0, n: 0, declined: 0 };
    let mut v = Mpfr::new(200);
    let mut d = Mpfr::new(200);
    let mut q = Mpfr::new(200);
    let mut t = Mpfr::new(200);
    let mut l = Mpfr::new(200);
    for &x in xs {
        let Some((hi, lo)) = f(x) else {
            a.declined += 1;
            continue;
        };
        a.n += 1;
        let r = o.at_prec(&[x], 200);
        if !r.is_finite_nonzero() {
            continue;
        }
        t.set_f64(hi);
        l.set_f64(lo);
        v.add_from(&t, &l);
        d.sub_from(&v, r);
        q.div_from(&d, r);
        let e = q.to_f64().abs();
        if e > 0.0 {
            let l2 = e.log2();
            if l2 > a.max_log2 {
                a.max_log2 = l2;
                a.worst_x = x;
            }
        }
    }
    a
}
