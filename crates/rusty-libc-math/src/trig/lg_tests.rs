//! Audit of the log, asinh, acosh and atanh kernels of lg.rs against MPFR.
use super::lg;
use crate::testkit::audit::audit;
use crate::testkit::inputs::Domain;

const NA: u64 = 200_000;
const TINY: f64 = 1.0 / (1u64 << 27) as f64;

#[test]
fn log_kernel_bound() {
    for dom in [Domain::new(1.05, 2.0), Domain::new(1.0, 1e10), Domain::new(0.1, 0.95), Domain::new(1e-300, 1e300), Domain::new(1.06, 1.5)] {
        // valid for z at least 5% away from 1 (the callers use it for z >= 1.5)
        let ok = |x: f64| x > 0.0 && (x - 1.0).abs() >= 0.05;
        let a = audit("log", dom, NA, 31, |x| if ok(x) { Some(lg::log_pair::<true>(x, 0.0, 0)) } else { None });
        println!("log fma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(lg::E_LG), "log {a}");
        let a = audit("log", dom, NA / 4, 32, |x| if ok(x) { Some(lg::log_pair::<false>(x, 0.0, 0)) } else { None });
        println!("log nofma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(lg::E_LG), "log {a}");
    }
}

#[test]
fn inverse_hyperbolic_kernel_bounds() {
    for dom in [Domain::new(2f64.powi(-27), 0.5), Domain::new(0.5, 3.0), Domain::new(3.0, 1e5), Domain::new(1e5, 1e9), Domain::new(1e9, 1e300), Domain::all()] {
        let ok = |x: f64| x.abs() >= TINY;
        for (fma, n) in [(true, NA), (false, NA / 4)] {
            let a = if fma {
                audit("asinh", dom, n, 41, |x| if ok(x) && x > 0.0 { Some(lg::asinh_pos::<true>(x)) } else { None })
            } else {
                audit("asinh", dom, n, 41, |x| if ok(x) && x > 0.0 { Some(lg::asinh_pos::<false>(x)) } else { None })
            };
            println!("asinh fma={fma} {:?}: {a}", (dom.lo, dom.hi));
            assert!(a.within(if dom.hi <= 0.5 { lg::E_ASINH_ROWS } else { lg::E_LOG }), "asinh {a}");
        }
    }
    for dom in [Domain::new(1.0, 2.0), Domain::new(2.0, 3.0), Domain::new(3.0, 1e5), Domain::new(1e5, 1e9), Domain::new(1.0, 1.0001), Domain::new(1e9, 1e300)] {
        let ok = |x: f64| x > 1.0;
        for (fma, n) in [(true, NA), (false, NA / 4)] {
            let a = if fma {
                audit("acosh", dom, n, 42, |x| if ok(x) { Some(lg::acosh_pos::<true>(x)) } else { None })
            } else {
                audit("acosh", dom, n, 42, |x| if ok(x) { Some(lg::acosh_pos::<false>(x)) } else { None })
            };
            println!("acosh fma={fma} {:?}: {a}", (dom.lo, dom.hi));
            assert!(a.within(if dom.hi <= 2.0 { lg::E_ACOSH_ROWS } else { lg::E_LOG }), "acosh {a}");
        }
    }
    for dom in [Domain::new(2f64.powi(-27), 0.5), Domain::new(0.5, 0.85), Domain::new(0.84, 0.85), Domain::new(0.85, 0.95), Domain::new(0.9, 0.999999), Domain::new(0.999999, 1.0)] {
        let ok = |x: f64| x.abs() >= TINY && x > 0.0 && x < 1.0;
        for (fma, n) in [(true, NA), (false, NA / 4)] {
            let a = if fma {
                audit("atanh", dom, n, 43, |x| if ok(x) { Some(lg::atanh_pos::<true>(x)) } else { None })
            } else {
                audit("atanh", dom, n, 43, |x| if ok(x) { Some(lg::atanh_pos::<false>(x)) } else { None })
            };
            println!("atanh fma={fma} {:?}: {a}", (dom.lo, dom.hi));
            assert!(a.within(if dom.hi <= 0.5 { lg::E_ATANH_ROWS } else if dom.hi <= 0.85 { lg::E_ATANH_WIDE } else { lg::E_LOG }), "atanh {a}");
        }
    }
}

#[test]
fn log_hp_kernel_bound() {
    // the high-precision logarithm: relative error below 2^-72 for z >= 1.5
    let bound = 2f64.powi(-72);
    for dom in [Domain::new(1.5, 4.0), Domain::new(1.0, 1e3), Domain::new(16.0, 172.0), Domain::new(1e3, 1e300)] {
        let ok = |x: f64| x >= 1.5;
        for (fma, n) in [(true, 100_000u64), (false, 25_000)] {
            let a = if fma {
                audit("log", dom, n, 51, |x| if ok(x) { Some(lg::log_pair_hp::<true>(x, 0.0, 0)) } else { None })
            } else {
                audit("log", dom, n, 51, |x| if ok(x) { Some(lg::log_pair_hp::<false>(x, 0.0, 0)) } else { None })
            };
            println!("log_hp fma={fma} {:?}: {a}", (dom.lo, dom.hi));
            assert!(a.within(bound), "log_hp {a}");
        }
    }
}

#[test]
#[ignore]
fn atanh_rows_profile() {
    for (lo, hi) in [(1e-3, 0.05), (0.05, 0.1), (0.1, 0.2), (0.2, 0.3), (0.3, 0.4), (0.4, 0.45), (0.45, 0.5)] {
        let a = audit("atanh", Domain::new(lo, hi), NA, 43, |x| Some(lg::atanh_pos::<true>(x)));
        println!("atanh rows {lo}..{hi}: {a}");
    }
}
