//! Accuracy harness: run a candidate over random and edge inputs, measure its ulp error against
//! MPFR, report the maximum, the worst input and how many results are above thresholds.
use super::inputs::{Domain, Fp, Rng, hex};
use super::mpfr::{self, Oracle};
use super::ulp::Overflow;
use core::fmt;

/// Error thresholds the report counts (results with error strictly above each).
pub const THRESHOLDS: [f64; 6] = [0.5, 1.0, 2.0, 4.0, 16.0, 1024.0];
/// A result at most this far above a threshold still counts as at it (the 113-bit reference is
/// itself rounded, so a correctly rounded result can measure 0.5 + 2^-60).
const SLACK: f64 = 1e-9;

#[derive(Clone, Debug)]
pub struct Report {
    pub name: String,
    pub fmt: &'static str,
    /// Inputs tested (edge points and random).
    pub n: u64,
    pub max_ulp: f64,
    /// Arguments of the worst case (widened to f64, exact).
    pub worst_args: Vec<f64>,
    pub worst_got: f64,
    /// Correctly rounded result at the worst input.
    pub worst_want: f64,
    /// Counts of results with error above each of THRESHOLDS.
    pub above: [u64; 6],
    /// Results whose error is infinite (NaN where a number is due, overflow in the wrong place...).
    pub infinite: u64,
    /// Mean error over finite-error results.
    pub mean_ulp: f64,
    sum: f64,
}

impl Report {
    pub fn new(name: &str, fmt: &'static str) -> Report {
        Report {
            name: name.to_string(),
            fmt,
            n: 0,
            max_ulp: 0.0,
            worst_args: vec![],
            worst_got: 0.0,
            worst_want: 0.0,
            above: [0; 6],
            infinite: 0,
            mean_ulp: 0.0,
            sum: 0.0,
        }
    }
    fn count(&mut self, err: f64) {
        self.n += 1;
        for (i, t) in THRESHOLDS.iter().enumerate() {
            if err > t + SLACK {
                self.above[i] += 1;
            }
        }
        if err.is_finite() {
            self.sum += err;
        } else {
            self.infinite += 1;
        }
    }
    pub fn merge(&mut self, o: Report) {
        self.n += o.n;
        self.infinite += o.infinite;
        self.sum += o.sum;
        for i in 0..6 {
            self.above[i] += o.above[i];
        }
        if o.max_ulp > self.max_ulp {
            self.max_ulp = o.max_ulp;
            self.worst_args = o.worst_args;
            self.worst_got = o.worst_got;
            self.worst_want = o.worst_want;
        }
    }
    fn finish(&mut self) {
        let finite = self.n - self.infinite;
        self.mean_ulp = if finite > 0 { self.sum / finite as f64 } else { 0.0 };
    }
    /// True when max error is within `bound` ulp (with the reference slack).
    pub fn within(&self, bound: f64) -> bool {
        self.max_ulp <= bound + SLACK
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let args: Vec<String> = self.worst_args.iter().map(|&a| hex(a)).collect();
        write!(
            f,
            "{:<9} {} n={} max {:.4} ulp at ({}) got {} want {} | above 0.5/1/2/4/16/1024: {}/{}/{}/{}/{}/{} inf {} mean {:.4}",
            self.name,
            self.fmt,
            self.n,
            self.max_ulp,
            args.join(", "),
            hex(self.worst_got),
            hex(self.worst_want),
            self.above[0],
            self.above[1],
            self.above[2],
            self.above[3],
            self.above[4],
            self.above[5],
            self.infinite,
            self.mean_ulp
        )
    }
}

#[derive(Clone, Debug)]
pub struct Cfg {
    /// Random inputs (the edge points come on top).
    pub n: u64,
    pub seed: u64,
    pub threads: usize,
    pub edges: bool,
    pub overflow: Overflow,
}

impl Cfg {
    pub fn new(n: u64) -> Cfg {
        let cpus = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(1);
        Cfg { n, seed: 0x005e_ed0f_11b3_a7a1, threads: cpus.min(4), edges: true, overflow: Overflow::Clamp }
    }
    pub fn threads(mut self, t: usize) -> Cfg {
        self.threads = t.max(1);
        self
    }
    pub fn seed(mut self, s: u64) -> Cfg {
        self.seed = s;
        self
    }
}

/// Edge-point tuples: the cross product of each argument's edge points, thinned so that the
/// product stays small (all for one argument, 40 per argument for two, 12 for three).
fn edge_tuples<F: Fp, const N: usize>(doms: &[Domain; N]) -> Vec<[F; N]> {
    let cap = match N {
        1 => usize::MAX,
        2 => 40,
        3 => 12,
        _ => 6,
    };
    let lists: Vec<Vec<F>> = doms
        .iter()
        .map(|d| {
            let e = d.edges::<F>();
            if e.len() <= cap {
                e
            } else {
                (0..cap).map(|i| e[i * e.len() / cap]).collect()
            }
        })
        .collect();
    let mut out = Vec::new();
    if lists.iter().any(|l| l.is_empty()) {
        return out;
    }
    let mut idx = [0usize; N];
    loop {
        let mut t = [lists[0][0]; N];
        for k in 0..N {
            t[k] = lists[k][idx[k]];
        }
        out.push(t);
        let mut k = 0;
        loop {
            if k == N {
                return out;
            }
            idx[k] += 1;
            if idx[k] < lists[k].len() {
                break;
            }
            idx[k] = 0;
            k += 1;
        }
    }
}

fn measure<F: Fp, const N: usize>(
    rep: &mut Report,
    oracle: &mut Oracle,
    f: &impl Fn([F; N]) -> F,
    args: [F; N],
    ov: Overflow,
) {
    let mut a = [0.0f64; N];
    for k in 0..N {
        a[k] = args[k].to_f64();
    }
    let y = f(args);
    let z = oracle.ref113(&a);
    let err = y.ulp_error(z, ov);
    rep.count(err);
    if err > rep.max_ulp || rep.worst_args.is_empty() {
        rep.max_ulp = err.max(rep.max_ulp);
        rep.worst_args = a.to_vec();
        rep.worst_got = y.to_f64();
        rep.worst_want = F::from_mpfr(z).to_f64();
    }
}

/// The general entry point: `name` is the MPFR function (see `mpfr::FUNCS`), `f` the candidate on
/// arrays of N arguments, `doms` where each argument comes from.
pub fn check_with<F: Fp, const N: usize>(
    name: &str,
    f: impl Fn([F; N]) -> F + Sync,
    doms: [Domain; N],
    cfg: &Cfg,
) -> Report {
    assert_eq!(mpfr::lookup(name).map(|x| x.arity), Some(N), "{name}: not an MPFR function of {N} arguments");
    let threads = if mpfr::thread_safe() { cfg.threads.max(1) } else { 1 };
    let edges = if cfg.edges { edge_tuples::<F, N>(&doms) } else { vec![] };
    let mut total = Report::new(name, F::NAME);
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            let (f, edges, doms) = (&f, &edges, &doms);
            handles.push(s.spawn(move || {
                let mut rep = Report::new(name, F::NAME);
                let mut oracle = Oracle::new(name);
                let mut rng = Rng::new(cfg.seed ^ (t as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
                for (i, e) in edges.iter().enumerate() {
                    if i % threads == t {
                        measure(&mut rep, &mut oracle, f, *e, cfg.overflow);
                    }
                }
                let share = cfg.n / threads as u64 + u64::from((t as u64) < cfg.n % threads as u64);
                for _ in 0..share {
                    let mut args = [F::from_f64(0.0); N];
                    for k in 0..N {
                        args[k] = doms[k].sample::<F>(&mut rng);
                    }
                    measure(&mut rep, &mut oracle, f, args, cfg.overflow);
                }
                rep
            }));
        }
        for h in handles {
            total.merge(h.join().unwrap());
        }
    });
    total.finish();
    total
}

/// `check("sin", candidate, Domain::all(), 100_000)`: binary64, one argument.
pub fn check(name: &str, f: fn(f64) -> f64, dom: Domain, n: u64) -> Report {
    check_with::<f64, 1>(name, |[x]| f(x), [dom], &Cfg::new(n))
}

pub fn check_f32(name: &str, f: fn(f32) -> f32, dom: Domain, n: u64) -> Report {
    check_with::<f32, 1>(name, |[x]| f(x), [dom], &Cfg::new(n))
}

pub fn check2(name: &str, f: fn(f64, f64) -> f64, doms: [Domain; 2], n: u64) -> Report {
    check_with::<f64, 2>(name, |[x, y]| f(x, y), doms, &Cfg::new(n))
}

pub fn check2_f32(name: &str, f: fn(f32, f32) -> f32, doms: [Domain; 2], n: u64) -> Report {
    check_with::<f32, 2>(name, |[x, y]| f(x, y), doms, &Cfg::new(n))
}

pub fn check3(name: &str, f: fn(f64, f64, f64) -> f64, doms: [Domain; 3], n: u64) -> Report {
    check_with::<f64, 3>(name, |[x, y, z]| f(x, y, z), doms, &Cfg::new(n))
}

/// Exhaustive (or strided) binary32 check of a one-argument function: every bit pattern
/// `0, stride, 2*stride, ...` below 2^32 that lies in `dom`. `stride` 1 is all 2^32 patterns
/// (hours: about 4 billion MPFR evaluations; split by `threads`).
pub fn check_f32_exhaustive(
    name: &str,
    f: impl Fn(f32) -> f32 + Sync,
    dom: Domain,
    stride: u64,
    threads: usize,
) -> Report {
    assert_eq!(mpfr::lookup(name).map(|x| x.arity), Some(1));
    let stride = stride.max(1);
    let threads = if mpfr::thread_safe() { threads.max(1) } else { 1 };
    let mut total = Report::new(name, "binary32");
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads as u64 {
            let (f, dom) = (&f, &dom);
            handles.push(s.spawn(move || {
                let mut rep = Report::new(name, "binary32");
                let mut oracle = Oracle::new(name);
                let mut b = t * stride;
                while b < (1u64 << 32) {
                    let x = f32::from_bits(b as u32);
                    if dom.contains(x as f64) {
                        measure::<f32, 1>(&mut rep, &mut oracle, &|[v]| f(v), [x], Overflow::Clamp);
                    }
                    b += stride * threads as u64;
                }
                rep
            }));
        }
        for h in handles {
            total.merge(h.join().unwrap());
        }
    });
    total.finish();
    total
}
